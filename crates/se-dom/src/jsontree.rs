//! A parsed document or fragment as a compact JSON tree, for the JS-side live
//! DOM (se-serve's `livedom.js`). The page scripts run against a tree of real
//! JS objects; html5ever stays the parser, so tag soup is repaired the way a
//! browser repairs it.
//!
//! Wire shape, one array per node:
//!   element  `[1, "tag", ["name","value",...], [children], ns]`
//!            ns: 0 = HTML, 1 = SVG, 2 = MathML
//!   text     `[3, "data"]`
//!   comment  `[8, "data"]`
//!   doctype  `[10, "name", "public", "system"]`
//! The top level is the array of the document's (or fragment's) children.

use scraper::{Html, Node};

fn push_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// scraper's tree sink discards the contents of `<template>`, so templates
/// are parsed under this name and restored on the way out.
const TEMPLATE_ALIAS: &str = "se-template";

fn starts_with_ci(hay: &[u8], at: usize, needle: &[u8]) -> bool {
    hay.len() >= at + needle.len()
        && hay[at..at + needle.len()].eq_ignore_ascii_case(needle)
}

/// Rename `<template>` tags to the alias, leaving script, style and comment
/// bodies alone (a template tag inside a string literal is not markup).
fn alias_templates(html: &str) -> std::borrow::Cow<'_, str> {
    let b = html.as_bytes();
    if !b.windows(9).any(|w| w.eq_ignore_ascii_case(b"<template")) {
        return std::borrow::Cow::Borrowed(html);
    }
    let mut out = String::with_capacity(html.len() + 64);
    let mut i = 0usize;
    let mut copied = 0usize;
    let find_ci = |from: usize, needle: &[u8]| -> usize {
        let mut j = from;
        while j + needle.len() <= b.len() {
            if b[j..j + needle.len()].eq_ignore_ascii_case(needle) {
                return j;
            }
            j += 1;
        }
        b.len()
    };
    while i < b.len() {
        if b[i] != b'<' {
            i += 1;
            continue;
        }
        if starts_with_ci(b, i, b"<!--") {
            i = (find_ci(i + 4, b"-->") + 3).min(b.len());
        } else if starts_with_ci(b, i, b"<script") {
            i = (find_ci(i + 7, b"</script") + 8).min(b.len());
        } else if starts_with_ci(b, i, b"<style") {
            i = (find_ci(i + 6, b"</style") + 7).min(b.len());
        } else if starts_with_ci(b, i, b"<template")
            && b.get(i + 9).map_or(true, |c| !c.is_ascii_alphanumeric() && *c != b'-')
        {
            out.push_str(&html[copied..i]);
            out.push('<');
            out.push_str(TEMPLATE_ALIAS);
            i += 9;
            copied = i;
        } else if starts_with_ci(b, i, b"</template")
            && b.get(i + 10).map_or(true, |c| !c.is_ascii_alphanumeric() && *c != b'-')
        {
            out.push_str(&html[copied..i]);
            out.push_str("</");
            out.push_str(TEMPLATE_ALIAS);
            i += 10;
            copied = i;
        } else {
            i += 1;
        }
    }
    out.push_str(&html[copied..]);
    std::borrow::Cow::Owned(out)
}

fn write_children(node: ego_tree::NodeRef<'_, Node>, out: &mut String) {
    out.push('[');
    let mut first = true;
    for child in node.children() {
        let mut piece = String::new();
        write_node(child, &mut piece);
        if piece.is_empty() {
            continue;
        }
        if !first {
            out.push(',');
        }
        first = false;
        out.push_str(&piece);
    }
    out.push(']');
}

fn write_node(node: ego_tree::NodeRef<'_, Node>, out: &mut String) {
    match node.value() {
        Node::Element(el) => {
            out.push_str("[1,");
            push_str(out, if el.name() == TEMPLATE_ALIAS { "template" } else { el.name() });
            out.push_str(",[");
            let mut first = true;
            for (name, value) in el.attrs.iter() {
                if !first {
                    out.push(',');
                }
                first = false;
                match &name.prefix {
                    Some(p) if !p.is_empty() => push_str(out, &format!("{}:{}", p, name.local)),
                    _ => push_str(out, &name.local),
                }
                out.push(',');
                push_str(out, value);
            }
            out.push_str("],");
            write_children(node, out);
            let ns: &str = &el.name.ns;
            out.push_str(match ns {
                "http://www.w3.org/2000/svg" => ",1]",
                "http://www.w3.org/1998/Math/MathML" => ",2]",
                _ => ",0]",
            });
        }
        Node::Text(t) => {
            out.push_str("[3,");
            push_str(out, &t.text);
            out.push(']');
        }
        Node::Comment(c) => {
            out.push_str("[8,");
            push_str(out, &c.comment);
            out.push(']');
        }
        Node::Doctype(d) => {
            out.push_str("[10,");
            push_str(out, &d.name);
            out.push(',');
            push_str(out, &d.public_id);
            out.push(',');
            push_str(out, &d.system_id);
            out.push(']');
        }
        _ => {}
    }
}

/// The children of a parsed document: doctype (when present) and `<html>`.
pub fn document_tree(html: &str) -> String {
    let html = &*alias_templates(html);
    let doc = Html::parse_document(html);
    let mut out = String::with_capacity(html.len() + html.len() / 4);
    write_children(doc.tree.root(), &mut out);
    out
}

/// The first start tag's name in a fragment (leading text and comments
/// skipped), lowercased.
fn first_tag(html: &str) -> String {
    let mut rest = html;
    loop {
        let Some(lt) = rest.find('<') else { return String::new() };
        rest = &rest[lt + 1..];
        if let Some(after) = rest.strip_prefix("!--") {
            match after.find("-->") {
                Some(end) => rest = &after[end + 3..],
                None => return String::new(),
            }
            continue;
        }
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_lowercase();
        if !name.is_empty() {
            return name;
        }
    }
}

/// The nodes of an HTML fragment. A body-context parse drops table parts and
/// options that arrive without their container (`<tr>`, `<td>`, `<option>`),
/// which is how every template-based framework ships rows; those fragments
/// are parsed inside the container they need and lifted back out.
pub fn fragment_tree(html: &str) -> String {
    let html = &*alias_templates(html);
    let (open, close, path): (&str, &str, &[&str]) = match first_tag(html).as_str() {
        "tr" => ("<table><tbody>", "</tbody></table>", &["table", "tbody"]),
        "td" | "th" => ("<table><tbody><tr>", "</tr></tbody></table>", &["table", "tbody", "tr"]),
        "tbody" | "thead" | "tfoot" | "colgroup" | "caption" => ("<table>", "</table>", &["table"]),
        "col" => ("<table><colgroup>", "</colgroup></table>", &["table", "colgroup"]),
        "option" | "optgroup" => ("<select>", "</select>", &["select"]),
        _ => ("", "", &[]),
    };
    let doc = if path.is_empty() {
        Html::parse_fragment(html)
    } else {
        Html::parse_fragment(&format!("{open}{html}{close}"))
    };
    let mut out = String::with_capacity(html.len() + html.len() / 4);
    // parse_fragment hangs the content under a synthetic <html> element.
    let mut at = doc
        .tree
        .root()
        .children()
        .find(|n| matches!(n.value(), Node::Element(e) if e.name() == "html"));
    for want in path {
        at = at.and_then(|n| {
            n.children()
                .find(|c| matches!(c.value(), Node::Element(e) if e.name() == *want))
        });
    }
    match at {
        Some(n) => write_children(n, &mut out),
        None => out.push_str("[]"),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_tree_carries_doctype_elements_text_and_comments() {
        let t = document_tree("<!doctype html><html lang=en><head><title>T</title></head><body><!--c--><p id=\"a\" class='x y'>hi &amp; \"bye\"</p></body></html>");
        assert!(t.starts_with("[[10,\"html\",\"\",\"\"],[1,\"html\",[\"lang\",\"en\"],"), "{t}");
        assert!(t.contains("[8,\"c\"]"), "{t}");
        assert!(t.contains("[1,\"p\",[\"class\",\"x y\",\"id\",\"a\"],[[3,\"hi & \\\"bye\\\"\"]],0]"), "{t}");
    }

    #[test]
    fn fragment_tree_keeps_table_parts_and_marks_svg() {
        let t = fragment_tree("<tr><td>1</td></tr>");
        assert_eq!(t, "[[1,\"tr\",[],[[1,\"td\",[],[[3,\"1\"]],0]],0]]");
        let t = fragment_tree("<option value=1>one</option>text");
        assert!(t.starts_with("[[1,\"option\",[\"value\",\"1\"]"), "{t}");
        assert!(t.ends_with("[3,\"text\"]]"), "{t}");
        let t = fragment_tree("<svg viewBox=\"0 0 1 1\"><path d=\"M0\"/></svg>");
        assert!(t.contains("[1,\"path\",[\"d\",\"M0\"],[],1]"), "{t}");
        assert!(t.contains("\"viewBox\""), "{t}");
        assert_eq!(fragment_tree(""), "[]");
        let t = fragment_tree(" <!-- c --><td>a</td><td>b</td>");
        assert!(t.contains("[1,\"td\",[],[[3,\"a\"]],0],[1,\"td\",[],[[3,\"b\"]],0]"), "{t}");
        let t = fragment_tree("plain <b>bold</b> text");
        assert_eq!(t, "[[3,\"plain \"],[1,\"b\",[],[[3,\"bold\"]],0],[3,\" text\"]]");
    }

    #[test]
    fn template_contents_survive_and_script_text_is_untouched() {
        let t = document_tree("<body><template id=t><p>row</p></template><script>var s = '<template>x</template>';</script></body>");
        assert!(t.contains("[1,\"template\",[\"id\",\"t\"],[[1,\"p\",[],[[3,\"row\"]],0]],0]"), "{t}");
        assert!(t.contains("var s = '<template>x</template>';"), "{t}");
        let t = fragment_tree("<TEMPLATE><b>x</b></TEMPLATE><templates>no</templates>");
        assert!(t.starts_with("[[1,\"template\",[],[[1,\"b\""), "{t}");
        assert!(t.contains("[1,\"templates\""), "{t}");
    }

    #[test]
    fn strings_are_valid_json_for_control_and_line_separator_characters() {
        let t = fragment_tree("<p>a\u{2028}b\tc\n</p><script>var s = \"</p>\";</script>");
        assert!(t.contains("a\\u2028b\\tc\\n"), "{t}");
        assert!(t.contains("[1,\"script\""), "{t}");
    }
}
