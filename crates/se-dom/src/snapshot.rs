//! `read_snapshot` walker — the agent's structural "eyes" (firing 38).
//!
//! An LLM agent asks "what's on the page / what's clickable" far more often
//! than it needs pixels. The snapshot answers with a flat, document-order
//! list of VISIBLE elements: kind, computed role, text (the same structural
//! innerText floor `read_text` answers), interactivity, and the identity
//! attributes an agent acts on (id/href/alt/name/type/aria-label). Honesty
//! line, same as the geometry and innerText tiers: no CSSOM, so visibility
//! is a STRUCTURAL heuristic (hidden attribute, inline display:none/
//! visibility:hidden, type=hidden, aria-hidden=true) — hidden subtrees are
//! pruned, not listed. Geometry is deliberately absent (zero-DOMRect floor);
//! `depth` conveys nesting, not pixels.

use crate::Document;
use scraper::ElementRef;

/// One visible element in the snapshot dump.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SnapEntry {
    /// Nesting depth among listed (visible) elements; 0 = direct child of body.
    pub depth: usize,
    /// Tag name, lowercased.
    pub kind: String,
    /// Computed role: explicit `role` attribute wins; otherwise a small
    /// implicit table (link/button/img/heading landmarks/form controls).
    /// Empty when neither applies.
    pub role: String,
    /// Structural innerText for textual elements; "" for containers (their
    /// text lives on their listed descendants — avoids quadratic duplication).
    pub text: String,
    /// True when the element is agent-actionable: links, buttons, form
    /// controls, labels, summary, or an interactive explicit role.
    pub interactive: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aria_label: Option<String>,
}

/// Elements whose text renders as their own line/name even with inline
/// children — the snapshot carries their innerText; containers carry none.
fn is_textual_element(tag: &str) -> bool {
    matches!(
        tag,
        "a" | "button" | "label" | "span" | "p" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6"
            | "li" | "td" | "th" | "caption" | "option" | "summary" | "strong" | "em"
            | "b" | "i" | "u" | "small" | "code" | "mark" | "abbr" | "time" | "pre"
            | "blockquote"
    )
}

/// Structural visibility heuristic — the no-CSSOM floor. `style` attribute
/// inspection is substring-based on the declaration value (spaces optional),
/// which is the only display/visibility information the engine has.
fn is_structurally_hidden(el: &ElementRef<'_>) -> bool {
    let v = el.value();
    if v.attr("hidden").is_some() || v.attr("aria-hidden") == Some("true") {
        return true;
    }
    if v.name() == "input" && v.attr("type") == Some("hidden") {
        return true;
    }
    if let Some(style) = v.attr("style") {
        let squashed: String = style.chars().filter(|c| !c.is_whitespace()).collect();
        if squashed.contains("display:none")
            || squashed.contains("visibility:hidden")
            || squashed.contains("opacity:0")
        {
            return true;
        }
    }
    false
}

/// Implicit role table — the common cases an agent filters on. Explicit
/// `role` attributes always win over this (ARIA author intent).
fn implicit_role(el: &ElementRef<'_>) -> &'static str {
    let v = el.value();
    let tag = v.name();
    match tag {
        "a" | "area" => {
            if v.attr("href").is_some() {
                "link"
            } else {
                ""
            }
        }
        "button" => "button",
        "img" => "img",
        "select" => "combobox",
        "textarea" => "textbox",
        "nav" => "navigation",
        "main" => "main",
        "header" => "banner",
        "footer" => "contentinfo",
        "aside" => "complementary",
        "form" => "form",
        "ul" | "ol" => "list",
        "li" => "listitem",
        "table" => "table",
        "tr" => "row",
        "td" => "cell",
        "th" => "columnheader",
        "option" => "option",
        "label" => "label",
        "summary" => "button",
        "input" => match v.attr("type").unwrap_or("text") {
            "button" | "submit" | "reset" | "image" => "button",
            "checkbox" => "checkbox",
            "radio" => "radio",
            "range" => "slider",
            t if t.is_empty() => "textbox",
            _ => "textbox",
        },
        t if t.len() == 2 && t.starts_with('h') && t.as_bytes()[1].is_ascii_digit() => {
            "heading"
        }
        _ => "",
    }
}

fn is_interactive(el: &ElementRef<'_>, role: &str) -> bool {
    let v = el.value();
    if matches!(
        role,
        "button" | "link" | "checkbox" | "radio" | "tab" | "switch" | "menuitem" | "option"
            | "combobox" | "slider" | "textbox"
    ) {
        return true;
    }
    matches!(v.name(), "button" | "select" | "textarea" | "label" | "summary")
        || (v.name() == "a" && v.attr("href").is_some())
        || (v.name() == "input" && v.attr("type") != Some("hidden"))
}

/// Non-rendering subtrees never appear in the snapshot.
fn is_non_rendering(tag: &str) -> bool {
    matches!(
        tag,
        "script" | "style" | "noscript" | "template" | "head" | "meta" | "link" | "title"
            | "base" | "svg"
    )
}

fn walk(el: ElementRef<'_>, depth: usize, out: &mut Vec<SnapEntry>) {
    // Prune non-rendering and hidden subtrees entirely.
    if is_non_rendering(el.value().name()) || is_structurally_hidden(&el) {
        return;
    }
    let v = el.value();
    let tag = v.name();
    // html/body are structural noise for an agent — descend without listing.
    let listed = !matches!(tag, "html" | "body");
    let child_depth = if listed { depth + 1 } else { depth };
    if listed {
        let role = v.attr("role").unwrap_or("").to_string();
        let role = if role.is_empty() {
            implicit_role(&el).to_string()
        } else {
            role
        };
        let text = if is_textual_element(tag) {
            crate::Node { el }.inner_text()
        } else {
            String::new()
        };
        let opt = |name: &str| v.attr(name).map(|s| s.to_string());
        out.push(SnapEntry {
            depth,
            kind: tag.to_string(),
            interactive: is_interactive(&el, &role),
            text,
            id: opt("id"),
            href: opt("href"),
            alt: opt("alt"),
            name: opt("name"),
            control_type: if matches!(tag, "input" | "select" | "textarea" | "button") {
                Some(v.attr("type").unwrap_or(tag).to_string())
            } else {
                None
            },
            aria_label: opt("aria-label"),
            role,
        });
    }
    for child in el.children() {
        if let Some(cel) = ElementRef::wrap(child) {
            walk(cel, child_depth, out);
        }
    }
}

/// The snapshot dump: every visible element under `scope` (usually the
/// document root) in document order.
pub fn snapshot(doc: &Document, scope: Option<crate::Node<'_>>) -> Vec<SnapEntry> {
    let mut out = Vec::new();
    match scope {
        Some(node) => walk(node.el, 0, &mut out),
        None => {
            if let Some(root) = doc.root() {
                walk(root.el, 0, &mut out);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(entries: &[SnapEntry]) -> Vec<String> {
        entries.iter().map(|e| e.kind.clone()).collect()
    }

    #[test]
    fn snapshot_lists_visible_elements_in_document_order_with_roles() {
        let doc = Document::parse(
            r#"<html><head><title>t</title><style>.x{}</style></head><body>
               <nav><a href="/a">Alpha</a><a href="/b">Beta</a></nav>
               <main><h1>Title</h1><p>Hello <b>world</b></p>
               <button id="go" aria-label="Go now">Go</button></main>
               </body></html>"#,
        );
        let snap = snapshot(&doc, None);
        // head/style/title pruned; html/body not listed.
        assert_eq!(
            kinds(&snap),
            vec!["nav", "a", "a", "main", "h1", "p", "b", "button"]
        );
        let nav = &snap[0];
        assert_eq!(nav.role, "navigation");
        assert_eq!(nav.depth, 0);
        let a0 = &snap[1];
        assert_eq!(a0.role, "link");
        assert_eq!(a0.text, "Alpha");
        assert_eq!(a0.href.as_deref(), Some("/a"));
        assert!(a0.interactive);
        assert_eq!(a0.depth, 1);
        let h1 = &snap[3 + 1]; // main is index 3, h1 index 4
        assert_eq!(h1.kind, "h1");
        assert_eq!(h1.role, "heading");
        assert_eq!(h1.text, "Title");
        let p = &snap[5];
        assert_eq!(p.text, "Hello world", "textual elements carry their innerText");
        let b = &snap[6];
        assert_eq!(b.text, "world");
        let btn = &snap[7];
        assert_eq!(btn.role, "button");
        assert_eq!(btn.aria_label.as_deref(), Some("Go now"));
        assert!(btn.interactive);
    }

    #[test]
    fn snapshot_prunes_hidden_subtrees_and_form_state() {
        let doc = Document::parse(
            r#"<html><body>
               <div hidden><a href="/x">ghost</a></div>
               <p style="display:none">nope</p>
               <p aria-hidden="true">also nope</p>
               <form action="/go" method="post">
                 <input type="hidden" name="tok" value="t">
                 <input type="text" name="q" value="hello">
                 <input type="checkbox" name="ok" checked>
               </form>
               <div style="opacity:0">transparent</div>
               </body></html>"#,
        );
        let snap = snapshot(&doc, None);
        let ks = kinds(&snap);
        assert!(!ks.contains(&"div".to_string()), "{ks:?}");
        assert!(!snap.iter().any(|e| e.text.contains("nope")), "{snap:?}");
        assert!(!snap.iter().any(|e| e.text.contains("also nope")), "{snap:?}");
        // The hidden input is pruned; the text box and checkbox list with
        // their control types and names.
        let inputs: Vec<_> = snap.iter().filter(|e| e.kind == "input").collect();
        assert_eq!(inputs.len(), 2, "{snap:?}");
        assert_eq!(inputs[0].control_type.as_deref(), Some("text"));
        assert_eq!(inputs[0].name.as_deref(), Some("q"));
        assert_eq!(inputs[0].role, "textbox");
        assert!(inputs[0].interactive);
        assert_eq!(inputs[1].control_type.as_deref(), Some("checkbox"));
        assert_eq!(inputs[1].role, "checkbox");
        let form = snap.iter().find(|e| e.kind == "form").expect("form");
        assert_eq!(form.role, "form");
        assert!(!form.interactive);
    }

    #[test]
    fn snapshot_scopes_to_a_selector_subtree() {
        let doc = Document::parse(
            r#"<html><body><p>outside</p><div id="in"><p>inside</p><span>deep</span></div></body></html>"#,
        );
        let scope = doc.select_one("#in").unwrap().unwrap();
        let snap = snapshot(&doc, Some(scope));
        assert_eq!(
            kinds(&snap),
            vec!["div".to_string(), "p".to_string(), "span".to_string()]
        );
        assert_eq!(snap[1].text, "inside");
        assert_eq!(snap[2].text, "deep");
        assert_eq!(snap[0].depth, 0, "scope root lists at depth 0");
    }

    #[test]
    fn explicit_role_beats_implicit() {
        let doc =
            Document::parse(r#"<html><body><a href="/x" role="menuitem">m</a></body></html>"#);
        let snap = snapshot(&doc, None);
        assert_eq!(snap[0].role, "menuitem");
        assert!(snap[0].interactive);
    }
}
