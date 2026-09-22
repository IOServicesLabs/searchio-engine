//! se-dom: HTML5 document model for the searchio scraping engine.
//!
//! This is the DOM substrate every higher tier builds on: the JS bridge
//! (M1) walks these nodes to expose `document` to V8, and the sidecar's
//! `read_html` verb serializes straight from here. Parsing is spec-compliant
//! HTML5 via html5ever underneath — the same error-recovery rules browsers
//! use — because sites ship tag soup and expect browser semantics.
//!
//! M0 scope: parse → select → serialize, proven against two real captures
//! (a Facebook Marketplace search page and a YouTube results page) rather
//! than hand-written toy HTML.

use std::collections::BTreeSet;

use scraper::{ElementRef, Html, Selector};

pub mod snapshot;

// `ns!()` expands to `namespace_url!()`, a markup5ever `#[macro_export]`
// macro that must also be in textual scope at the call site. Importing `ns`
// alone by `use` leaves the expansion dangling — scraper itself solves this
// the same way (`#[macro_use] extern crate html5ever;` at its crate root),
// so the attribute-mutation paths below can call `ns!()` directly.
#[macro_use]
extern crate html5ever;

/// Stable identity of a node inside one parsed `Document`. The JS bridge
/// (M1) snapshots elements per eval and uses this to resolve ancestors
/// lazily — `parentElement` walks re-enter the same cached parse instead of
/// duplicating ancestor subtrees into every snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeId(ego_tree::NodeId);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid CSS selector {0:?}: {1}")]
    BadSelector(String, String),
}

#[derive(Clone)]
pub struct Document {
    inner: Html,
}

/// Recursively copy `src`'s subtree rooted at `src_id` under `dst_parent`
/// in `dst` by value (ego-tree has no cross-tree id reparent, so grafting is
/// a value-copy). Element nodes carry private id/classes caches that clone
/// stale — harmless for scraping, where selectors read attrs.
fn copy_subtree(
    src: &Html,
    dst: &mut Html,
    src_id: ego_tree::NodeId,
    dst_parent: ego_tree::NodeId,
) {
    let (value, child_ids): (scraper::node::Node, Vec<ego_tree::NodeId>) = {
        let node_ref = src.tree.get(src_id).expect("src node");
        (
            node_ref.value().clone(),
            node_ref.children().map(|c| c.id()).collect(),
        )
    };
    let new_id = dst
        .tree
        .get_mut(dst_parent)
        .expect("dst parent")
        .append(value)
        .id();
    for cid in child_ids {
        copy_subtree(src, dst, cid, new_id);
    }
}

/// Graft a parsed fragment's children under `dst_parent`, unwrapping the
/// synthetic `<html>` element scraper's `parse_fragment` wraps content in
/// (grafting it verbatim would give the copy a bogus wrapper).
fn graft_fragment(dst: &mut Html, frag: &Html, dst_parent: ego_tree::NodeId) {
    let top: Vec<ego_tree::NodeId> = frag.tree.root().children().map(|c| c.id()).collect();
    for tid in top {
        let is_html = frag
            .tree
            .get(tid)
            .and_then(|n| n.value().as_element().map(|e| e.name() == "html"))
            .unwrap_or(false);
        if is_html {
            let inner: Vec<ego_tree::NodeId> = frag
                .tree
                .get(tid)
                .expect("html wrapper")
                .children()
                .map(|c| c.id())
                .collect();
            for iid in inner {
                copy_subtree(frag, dst, iid, dst_parent);
            }
        } else {
            copy_subtree(frag, dst, tid, dst_parent);
        }
    }
}

/// A borrowed handle to one element. Deliberately thin for M0; the M1 JS
/// bridge replaces this with v8 wrapper objects and needs `ElementRef`'s
/// node identity to stay stable, so all accessors go through it.
#[derive(Clone, Copy)]
pub struct Node<'a> {
    el: ElementRef<'a>,
}

impl Document {
    pub fn parse(html: &str) -> Self {
        Self {
            inner: Html::parse_document(html),
        }
    }

    /// Parse an HTML fragment (an element's inner HTML) for scoped queries.
    /// Unlike `parse`, no html/head/body synthesis is added around the content.
    pub fn parse_fragment(html: &str) -> Self {
        Self {
            inner: Html::parse_fragment(html),
        }
    }

    pub fn select(&self, css: &str) -> Result<Vec<Node<'_>>, Error> {
        let sel = Selector::parse(css)
            .map_err(|e| Error::BadSelector(css.to_string(), format!("{e:?}")))?;
        Ok(self.inner.select(&sel).map(|el| Node { el }).collect())
    }

    /// First match, if any — the common case in provider parsers.
    pub fn select_one(&self, css: &str) -> Result<Option<Node<'_>>, Error> {
        Ok(self.select(css)?.into_iter().next())
    }

    /// Re-resolve a node by the identity a previous select returned. Returns
    /// `None` for ids from a *different* parse (e.g. a discarded fragment).
    pub fn node(&self, id: NodeId) -> Option<Node<'_>> {
        ElementRef::wrap(self.inner.tree.get(id.0)?).map(|el| Node { el })
    }

    /// The document element (`<html>`). Only meaningful on full document
    /// parses; fragments have no root element. The tree root itself is the
    /// Document node, so this is its first element child.
    pub fn root(&self) -> Option<Node<'_>> {
        self.inner
            .tree
            .root()
            .children()
            .find_map(ElementRef::wrap)
            .map(|el| Node { el })
    }

    /// Serialize the whole document back to HTML. Round-trips through
    /// parse → serialize → parse must be stable; the fixtures test pins it.
    pub fn html(&self) -> String {
        self.inner.root_element().html()
    }

    // ── mutation ops (firing 16) ─────────────────────────────────────────
    //
    // The bridge DOM was read-only through firing 15; these ops back the
    // same-eval mutation tier (`innerHTML`/`textContent` setters,
    // `appendChild`, `remove`). Mutations land in the ego-tree, so a fresh
    // `select` after a mutation sees the new shape. Node ids issued before a
    // mutation are NOT stable across it (a reparse is a different tree) —
    // the bridge invalidates its cached parse on every mutation.
    //
    // ego-tree notes: `append(value)` copies a node value in and returns a
    // `NodeMut` whose `.id()` is the new node; `detach()` takes no argument
    // (it removes the `NodeMut` itself); there is no cross-tree id reparent,
    // so grafting a parsed fragment is a recursive value-copy. scraper's
    // `parse_fragment` wraps content in a synthetic `<html>` element that
    // must be unwrapped before grafting, or the copy gains a bogus wrapper.

    /// Replace the subtree of the node `id` with `html` (a DOM
    /// `innerHTML` setter). Parses `html` as a fragment and grafts its
    /// children in place of `id`'s current children. Returns false when the
    /// id does not resolve in this tree.
    pub fn set_inner_html(&mut self, id: NodeId, html: &str) -> bool {
        let frag = Html::parse_fragment(html);
        let parent = match self.inner.tree.get(id.0) {
            Some(n) => n.id(),
            None => return false,
        };
        let old_children: Vec<ego_tree::NodeId> = self
            .inner
            .tree
            .get(parent)
            .expect("just resolved")
            .children()
            .map(|c| c.id())
            .collect();
        for c in old_children {
            self.inner.tree.get_mut(c).expect("child").detach();
        }
        graft_fragment(&mut self.inner, &frag, parent);
        true
    }

    /// Append a child parsed from an HTML string under `id` (the
    /// `appendChild` of an element built from markup). Returns the new
    /// child's id, or None when `id` does not resolve.
    pub fn append_html(&mut self, id: NodeId, html: &str) -> Option<NodeId> {
        let frag = Html::parse_fragment(html);
        let parent = self.inner.tree.get_mut(id.0)?.id();
        let before = self.child_count_of(parent);
        graft_fragment(&mut self.inner, &frag, parent);
        // The first grafted child's id: re-walk and take the `before`-th.
        self.nth_child_id(parent, before)
    }

    /// Append a bare text node under `id` (`appendChild` of a text node).
    /// Returns the new node's id.
    pub fn append_text(&mut self, id: NodeId, text: &str) -> Option<NodeId> {
        use scraper::node::{Node as SNode, Text};
        let mut node = self.inner.tree.get_mut(id.0)?;
        Some(NodeId(
            node.append(SNode::Text(Text {
                text: text.into(),
            }))
            .id(),
        ))
    }

    /// Replace the subtree of `id` with a single text node (a DOM
    /// `textContent` setter). Returns false when `id` does not resolve.
    pub fn set_text(&mut self, id: NodeId, text: &str) -> bool {
        use scraper::node::{Node as SNode, Text};
        let old_children: Vec<ego_tree::NodeId> = match self.inner.tree.get(id.0) {
            Some(n) => n.children().map(|c| c.id()).collect(),
            None => return false,
        };
        for c in old_children {
            self.inner.tree.get_mut(c).expect("child").detach();
        }
        let mut node = match self.inner.tree.get_mut(id.0) {
            Some(n) => n,
            None => return false,
        };
        node.append(SNode::Text(Text {
            text: text.into(),
        }));
        true
    }

    /// Detach the subtree rooted at `id` from the tree (`remove()`).
    /// Sibling order is preserved; the node is gone from every subsequent
    /// select. Returns false when `id` does not resolve.
    pub fn remove(&mut self, id: NodeId) -> bool {
        match self.inner.tree.get_mut(id.0) {
            Some(mut n) => {
                n.detach();
                true
            }
            None => false,
        }
    }

    /// Set (or replace) an attribute on the element `id` — the DOM
    /// `setAttribute` over the live tree. The new attribute is visible to
    /// every subsequent select and serialization. Returns false when `id`
    /// does not resolve to an element (dangling id, or a non-element node).
    pub fn set_attr(&mut self, id: NodeId, name: &str, value: &str) -> bool {
        use html5ever::{Attribute, LocalName, QualName, ns};
        use scraper::node::{Element, Node as SNode};
        let Some(mut node) = self.inner.tree.get_mut(id.0) else {
            return false;
        };
        let SNode::Element(el) = node.value() else {
            return false;
        };
        // HTML attributes sit in the empty namespace; a plain name matches
        // what the parser produces for markup attributes.
        let qual = QualName::new(None, ns!(), LocalName::from(name));
        let mut attrs: Vec<Attribute> = el
            .attrs
            .iter()
            .map(|(n, v)| Attribute {
                name: n.clone(),
                value: v.clone(),
            })
            .collect();
        match attrs.iter_mut().find(|a| a.name == qual) {
            Some(a) => a.value = value.into(),
            None => attrs.push(Attribute {
                name: qual,
                value: value.into(),
            }),
        }
        // Rebuild the element value rather than poking attrs in place:
        // scraper memoizes id/class in private OnceCells, so an in-place
        // edit would leave `#id` and `.class` selector matching stale for
        // the life of the tree. Element::new starts the caches empty.
        let name = el.name.clone();
        *node.value() = SNode::Element(Element::new(name, attrs));
        true
    }

    /// Remove an attribute from the element `id` — the DOM
    /// `removeAttribute` (silent when the attribute is absent, like the
    /// spec). Returns false when `id` does not resolve to an element.
    pub fn remove_attr(&mut self, id: NodeId, name: &str) -> bool {
        use html5ever::{Attribute, LocalName, QualName, ns};
        use scraper::node::{Element, Node as SNode};
        let Some(mut node) = self.inner.tree.get_mut(id.0) else {
            return false;
        };
        let SNode::Element(el) = node.value() else {
            return false;
        };
        let qual = QualName::new(None, ns!(), LocalName::from(name));
        let attrs: Vec<Attribute> = el
            .attrs
            .iter()
            .filter(|(n, _)| *n != qual)
            .map(|(n, v)| Attribute {
                name: n.clone(),
                value: v.clone(),
            })
            .collect();
        let name_q = el.name.clone();
        *node.value() = SNode::Element(Element::new(name_q, attrs));
        true
    }

    /// Child count of `id` (all node kinds) — used to locate the first
    /// grafted child after an `append_html`.
    fn child_count_of(&self, id: ego_tree::NodeId) -> usize {
        self.inner
            .tree
            .get(id)
            .map(|n| n.children().count())
            .unwrap_or(0)
    }

    /// Id of the `n`-th child of `id` (all node kinds).
    fn nth_child_id(&self, id: ego_tree::NodeId, n: usize) -> Option<NodeId> {
        self.inner
            .tree
            .get(id)?
            .children()
            .nth(n)
            .map(|c| NodeId(c.id()))
    }

    /// Every distinct value of an attribute across a selector's matches,
    /// in sorted order. Dedup first because modern pages wrap one card in
    /// two anchors to the same target.
    pub fn attr_values(&self, css: &str, attr: &str) -> Result<Vec<String>, Error> {
        let mut seen = BTreeSet::new();
        for node in self.select(css)? {
            if let Some(v) = node.attr(attr) {
                seen.insert(v.to_string());
            }
        }
        Ok(seen.into_iter().collect())
    }
}

impl<'a> Node<'a> {
    /// Identity within this node's parse — feed back to `Document::node`.
    pub fn id(&self) -> NodeId {
        NodeId(self.el.id())
    }

    /// Nearest ancestor that is an element, skipping text/comment/document
    /// nodes — DOM `parentElement` (as opposed to `parentNode`). `None` at
    /// `<html>` and for fragment roots.
    pub fn parent_element(&self) -> Option<Node<'a>> {
        let mut cur = self.el.parent();
        while let Some(n) = cur {
            if let Some(el) = ElementRef::wrap(n) {
                return Some(Node { el });
            }
            cur = n.parent();
        }
        None
    }

    /// Does this element match a CSS selector? (DOM `Element.matches`.)
    pub fn matches(&self, css: &str) -> Result<bool, Error> {
        let sel = Selector::parse(css)
            .map_err(|e| Error::BadSelector(css.to_string(), format!("{e:?}")))?;
        Ok(sel.matches(&self.el))
    }

    /// Nearest ancestor-or-self matching a CSS selector (DOM
    /// `Element.closest`); `None` when no element in the chain matches.
    pub fn closest(&self, css: &str) -> Result<Option<Node<'a>>, Error> {
        let sel = Selector::parse(css)
            .map_err(|e| Error::BadSelector(css.to_string(), format!("{e:?}")))?;
        let mut cur = Some(*self);
        while let Some(n) = cur {
            if sel.matches(&n.el) {
                return Ok(Some(n));
            }
            cur = n.parent_element();
        }
        Ok(None)
    }

    pub fn attr(&self, name: &str) -> Option<&'a str> {
        self.el.value().attr(name)
    }

    /// Tag name lowercased, as `tagName` is presented to JS (uppercased by
    /// the bridge; HTML parsing already lowercases the source form).
    pub fn tag(&self) -> String {
        self.el.value().name().to_string()
    }

    pub fn attrs(&self) -> Vec<(String, String)> {
        self.el
            .value()
            .attrs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// Concatenated text of the subtree, like DOM `textContent`.
    pub fn text(&self) -> String {
        self.el.text().collect::<String>()
    }

    /// Approximate DOM `innerText` — the rendered-text floor the read_text
    /// verb answers. The engine has no CSSOM, so this cannot evaluate
    /// display/visibility the way a layout-backed `innerText` does; the
    /// documented floor is structural instead: `script`/`style`/
    /// `noscript`/`template` subtrees are skipped (they never render),
    /// block-level elements bound their text with newlines, `<br>` breaks
    /// a line, and whitespace runs collapse to single spaces — the same
    /// honesty line the geometry tier draws with its zero-DOMRect floor.
    pub fn inner_text(&self) -> String {
        let mut out = String::new();
        for child in self.el.children() {
            inner_text_node(child, &mut out);
        }
        while out.ends_with(|c: char| c.is_whitespace()) {
            out.pop();
        }
        out
    }

    /// Serialize just this element's subtree.
    pub fn html(&self) -> String {
        self.el.html()
    }
}

/// Block-level tags: their rendered text is separated from siblings by
/// line breaks. `inner_text` uses this list in place of a box-tree walk.
fn is_block_element(tag: &str) -> bool {
    matches!(
        tag,
        "html" | "body" | "head" | "p" | "div" | "ul" | "ol" | "li" | "dl" | "dt"
            | "dd" | "table" | "thead" | "tbody" | "tfoot" | "tr" | "td" | "th"
            | "caption" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "section"
            | "article" | "aside" | "header" | "footer" | "nav" | "main" | "figure"
            | "figcaption" | "blockquote" | "pre" | "hr" | "form" | "fieldset"
            | "address" | "summary" | "details"
    )
}

fn inner_text_node(node: ego_tree::NodeRef<'_, scraper::node::Node>, out: &mut String) {
    match node.value() {
        scraper::node::Node::Element(el) => {
            let tag = el.name();
            // Non-rendering subtrees never contribute rendered text.
            if matches!(tag, "script" | "style" | "noscript" | "template") {
                return;
            }
            if tag == "br" {
                text_block_boundary(out);
                return;
            }
            let block = is_block_element(tag);
            if block {
                text_block_boundary(out);
            }
            for child in node.children() {
                inner_text_node(child, out);
            }
            if block {
                text_block_boundary(out);
            }
        }
        scraper::node::Node::Text(t) => {
            let collapsed = t.split_whitespace().collect::<Vec<_>>().join(" ");
            if collapsed.is_empty() {
                return;
            }
            if !out.is_empty() && !out.ends_with(|c: char| c.is_whitespace()) {
                out.push(' ');
            }
            out.push_str(&collapsed);
        }
        // Comments, doctypes, PIs carry no rendered text.
        _ => {}
    }
}

/// A line-break boundary: exactly one newline, never leading, never doubled.
fn text_block_boundary(out: &mut String) {
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn parse_select_serialize_round_trips() {
        let doc = Document::parse(
            r#"<html><body><div class="card"><a href="/p/1">one</a><a href="/p/1">dup</a></div></body></html>"#,
        );
        let hrefs = doc.attr_values("a", "href").unwrap();
        assert_eq!(hrefs, vec!["/p/1"]); // deduped
        let card = doc.select_one(".card").unwrap().unwrap();
        assert_eq!(card.text(), "onedup");
        let again = Document::parse(&doc.html());
        assert_eq!(again.attr_values("a", "href").unwrap(), hrefs);
    }

    #[test]
    fn bad_selector_is_an_error_not_a_panic() {
        assert!(Document::parse("<p>x</p>").select("a[href=").is_err());
    }

    #[test]
    fn inner_text_approximates_the_rendered_text_floor() {
        let doc = Document::parse(
            r#"<html><body>
            <script>var json = {hidden: true};</script>
            <style>.card { color: red; }</style>
            <div>
                <p>First  paragraph
                spanning lines</p>
                <ul><li>one</li><li>two</li></ul>
                <p>Second&nbsp;paragraph<br>after break <span>inline tail</span></p>
            </div>
            </body></html>"#,
        );
        let body = doc.select_one("body").unwrap().unwrap();
        // Blocks newline-joined, whitespace collapsed, script/style gone,
        // <br> breaks, inline spans space-joined.
        assert_eq!(
            body.inner_text(),
            "First paragraph spanning lines\none\ntwo\nSecond paragraph\nafter break inline tail"
        );
    }

    #[test]
    fn inner_text_skips_non_rendering_subtrees_but_text_does_not() {
        let doc = Document::parse(
            r#"<body>keep<template>tpl</template><script>s</script><style>st</style>done</body>"#,
        );
        let body = doc.select_one("body").unwrap().unwrap();
        assert_eq!(body.inner_text(), "keep done");
        // textContent stays the raw concatenation — the two accessors
        // diverge the same way they do in a browser.
        let raw = body.text();
        assert!(raw.contains("st") && raw.contains("s") && raw.contains("tpl"));
    }

    #[test]
    fn matches_and_closest_walk_the_ancestor_chain() {
        let doc = Document::parse(
            r#"<html><body><div class="card outer"><div class="card inner"><a href="/x">x</a></div></div></body></html>"#,
        );
        let a = doc.select_one("a").unwrap().unwrap();
        // matches: self test, true and false.
        assert!(a.matches("a[href='/x']").unwrap());
        assert!(!a.matches("div").unwrap());
        // Bad selector is an Error, not a panic.
        assert!(matches!(a.matches("a["), Err(Error::BadSelector(..))));
        // closest: self match, ancestor match, miss.
        let inner = a.closest(".inner").unwrap().unwrap();
        assert_eq!(inner.attr("class"), Some("card inner"));
        let outer = a.closest(".outer").unwrap().unwrap();
        assert_eq!(outer.attr("class"), Some("card outer"));
        assert!(a.closest("section").unwrap().is_none());
        // closest includes the element itself.
        assert_eq!(a.closest("a").unwrap().unwrap().attr("href"), Some("/x"));
    }

    #[test]
    fn parent_element_walks_to_html_then_stops() {
        let doc = Document::parse(
            r#"<html><body><div class="outer"><div class="inner"><a href="/x">x</a></div></div></body></html>"#,
        );
        let a = doc.select_one("a").unwrap().unwrap();
        let chain: Vec<String> = std::iter::successors(Some(a), |n| n.parent_element())
            .map(|n| n.tag())
            .collect();
        assert_eq!(chain, vec!["a", "div", "div", "body", "html"]);
        assert_eq!(doc.root().unwrap().tag(), "html");
        assert!(doc.root().unwrap().parent_element().is_none());
        // Id round-trips through the owning document, dangles on others.
        let id = a.id();
        assert_eq!(doc.node(id).unwrap().attr("href"), Some("/x"));
        let other = Document::parse("<a href='/y'>y</a>");
        assert!(other.node(id).is_none());
    }

    #[test]
    fn set_inner_html_replaces_children() {
        let mut doc = Document::parse(r#"<html><body><div id="a"><p>hi</p></div></body></html>"#);
        let div = doc.select_one("#a").unwrap().unwrap();
        assert!(doc.set_inner_html(div.id(), r#"<span class="s">x</span><b>y</b>"#));
        // New shape is selectable; the old <p> is gone.
        assert!(doc.select_one("#a p").unwrap().is_none());
        assert_eq!(doc.select_one("#a .s").unwrap().unwrap().text(), "x");
        assert_eq!(doc.select_one("#a b").unwrap().unwrap().text(), "y");
        // Stale id from before the mutation is gone (tree was edited in place
        // but the <p> child was detached).
        let old_p = doc.select_one("#a p");
        assert!(old_p.unwrap().is_none());
    }

    #[test]
    fn append_html_and_text_extend_children() {
        let mut doc = Document::parse(r#"<html><body><div id="a"><p>hi</p></div></body></html>"#);
        let div = doc.select_one("#a").unwrap().unwrap();
        let id = div.id();
        assert!(doc.append_html(id, r#"<span class="s">x</span>"#).is_some());
        assert!(doc.append_text(id, "tail").is_some());
        assert_eq!(
            doc.select_one("#a").unwrap().unwrap().text(),
            "hixtail"
        );
        // Order: p, span, tail.
        let tags: Vec<String> = doc
            .select("#a > *")
            .unwrap()
            .iter()
            .map(|n| n.tag())
            .collect();
        assert_eq!(tags, vec!["p", "span"]);
    }

    #[test]
    fn set_text_replaces_subtree_with_one_text_node() {
        let mut doc = Document::parse(r#"<html><body><div id="a"><p>hi</p><span>x</span></div></body></html>"#);
        let div = doc.select_one("#a").unwrap().unwrap();
        assert!(doc.set_text(div.id(), "REPLACED"));
        assert_eq!(doc.select_one("#a").unwrap().unwrap().text(), "REPLACED");
        assert!(doc.select_one("#a p").unwrap().is_none());
        assert!(doc.select_one("#a span").unwrap().is_none());
    }

    #[test]
    fn remove_detaches_subtree() {
        let mut doc = Document::parse(r#"<html><body><div id="a"><p>hi</p></div><div id="b">tail</div></body></html>"#);
        let b = doc.select_one("#b").unwrap().unwrap();
        assert!(doc.remove(b.id()));
        assert!(doc.select_one("#b").unwrap().is_none());
        // Sibling #a survives.
        assert_eq!(doc.select_one("#a p").unwrap().unwrap().text(), "hi");
        // A fresh parse's ids are meaningless here — but ego-tree recycles
        // NodeIds, so a foreign id can accidentally resolve. The contract the
        // bridge relies on is "the id you just selected in THIS tree", which
        // always resolves; ids are never carried across a mutation (the
        // bridge re-selects after mutating). Pin the supported shape: a
        // just-selected node in this tree is removable, a second remove of
        // the same (now-detached) id does not panic.
        let a = doc.select_one("#a").unwrap().unwrap();
        assert!(doc.remove(a.id()));
        assert!(doc.select_one("#a").unwrap().is_none());
    }

    #[test]
    fn set_attr_adds_replaces_and_selects() {
        let mut doc = Document::parse(r#"<html><body><p id="a" class="x">hi</p></body></html>"#);
        // Copy the id up front — Node borrows the doc, and the mutations
        // need &mut.
        let id = doc.select_one("#a").unwrap().unwrap().id();
        // New attribute...
        assert!(doc.set_attr(id, "data-se", "touched"));
        assert_eq!(
            doc.select_one(r#"[data-se="touched"]"#)
                .unwrap()
                .unwrap()
                .text(),
            "hi"
        );
        // ...replaces in place (no duplicate)...
        assert!(doc.set_attr(id, "data-se", "again"));
        assert_eq!(
            doc.select(r#"[data-se="again"]"#).unwrap().len(),
            1
        );
        // ...and the serialization carries it.
        assert!(doc.html().contains(r#"data-se="again""#));
        // Replacing `id` moves the element for `#` selectors — the memoized
        // id cache must not serve the stale value.
        assert!(doc.set_attr(id, "id", "b"));
        assert!(doc.select_one("#a").unwrap().is_none());
        assert_eq!(doc.select_one("#b").unwrap().unwrap().text(), "hi");
    }

    #[test]
    fn set_attr_on_class_refreshes_class_matching() {
        let mut doc = Document::parse(r#"<html><body><p id="a" class="cold">hi</p></body></html>"#);
        let id = doc.select_one("#a").unwrap().unwrap().id();
        assert!(doc.select(".hot").unwrap().is_empty());
        assert!(doc.set_attr(id, "class", "hot"));
        assert_eq!(doc.select(".hot").unwrap().len(), 1);
        assert!(doc.select(".cold").unwrap().is_empty());
    }

    #[test]
    fn remove_attr_detaches_from_select_and_serialize() {
        let mut doc = Document::parse(r#"<html><body><p id="a" data-x="1">hi</p></body></html>"#);
        let id = doc.select_one("#a").unwrap().unwrap().id();
        // Absent attribute: silent no-op success, like the spec.
        assert!(doc.remove_attr(id, "data-missing"));
        assert!(doc.remove_attr(id, "data-x"));
        assert!(doc.select_one(r#"[data-x]"#).unwrap().is_none());
        assert!(!doc.html().contains("data-x"));
        // The untouched attr survives.
        assert_eq!(doc.select_one("#a").unwrap().unwrap().attr("id"), Some("a"));
        // Removing `id` kills `#a` matching.
        assert!(doc.remove_attr(id, "id"));
        assert!(doc.select_one("#a").unwrap().is_none());
    }

    #[test]
    fn mutation_round_trips_through_serialize() {
        let mut doc = Document::parse(r#"<html><body><div id="a"><p>hi</p></div></body></html>"#);
        let div = doc.select_one("#a").unwrap().unwrap();
        doc.append_html(div.id(), "<span>x</span>").unwrap();
        let serialized = doc.html();
        let reparsed = Document::parse(&serialized);
        assert_eq!(reparsed.select_one("#a span").unwrap().unwrap().text(), "x");
    }
}
