//! se-js: V8 execution tier for the searchio engine.
//!
//! Owns the JavaScript runtime and, eventually, the DOM bridge that exposes
//! `document` to page scripts. M1 slice 1 scope: a `Runtime` that can eval
//! scripts and hand results back as `serde_json::Value`, plus
//! `extract_object_literal` — the string-aware brace scanner the Python
//! provider proved necessary (a `}` inside a string literal must not end the
//! scan). Acceptance test runs YouTube's real 2MB `ytInitialData` assignment
//! through V8 and gets the same 19-video structure the Python parser sees.

use std::sync::Once;

pub mod bridge;
mod sha256;
pub mod audio;

static INIT: Once = Once::new();

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("script too large for V8's string type")]
    SourceTooLarge,
    #[error("compile error: {0}")]
    Compile(String),
    #[error("execution threw: {0}")]
    Threw(String),
    #[error("result is not JSON-representable: {0}")]
    NotJson(String),
}

/// Initialize the V8 platform once per process, then own one isolate.
/// One `Runtime` per page is the se-serve plan; isolates give pages
/// independent heaps and cheap teardown.
pub struct Runtime {
    isolate: v8::OwnedIsolate,
}

impl Default for Runtime {
    fn default() -> Self {
        Self::new()
    }
}

impl Runtime {
    pub fn new() -> Self {
        INIT.call_once(|| {
            let platform = v8::new_default_platform(0, false).make_shared();
            v8::V8::initialize_platform(platform);
            v8::V8::initialize();
        });
        let i = v8::Isolate::new(v8::CreateParams::default());
        Self { isolate: i }
    }

    /// Eval `source` with no page loaded (about:blank semantics):
    /// `navigator` answers, `document` is empty.
    pub fn eval(&mut self, source: &str) -> Result<serde_json::Value, Error> {
        self.eval_with_page(None, source)
    }

    /// Eval `source` against `page` (URL + HTML), exposing a read-only
    /// `document` to the script. One fresh context per eval — no JS state
    /// leaks between evals; the page's Web Storage maps are shared by Arc
    /// (that persistence is the page's, not the script's).
    ///
    /// Completion values: plain values stringify to JSON; a top-level
    /// Promise (or any script that schedules timers) drives the bridge's
    /// event-loop pump — microtask checkpoint, due timers, repeat — until
    /// the promise settles, no timers remain, or the wall-clock budget trips;
    /// the resolution value is the result; a rejection is `Error::Threw`.
    pub fn eval_with_page(
        &mut self,
        page: Option<&bridge::Page>,
        source: &str,
    ) -> Result<serde_json::Value, Error> {
        self.eval_with_page_with_budget(page, source, bridge::TIMER_BUDGET)
    }

    /// `eval_with_page` with an explicit macrotask-pump ceiling. se-serve's
    /// render mode passes the caller's `settle_ms` here so a page holding
    /// long-interval timers can't pin the single JS worker for the full
    /// default budget.
    pub fn eval_with_page_with_budget(
        &mut self,
        page: Option<&bridge::Page>,
        source: &str,
        budget: std::time::Duration,
    ) -> Result<serde_json::Value, Error> {
        self.eval_inner(page, source, budget).0
    }

    /// `eval_with_page_with_budget` that also reports where page-script
    /// navigation left the page: the bridge's `State.page_url` AFTER the
    /// settle pump (a setTimeout-scheduled location.href= only lands once
    /// the timers run, so the post-settle read is the truth about where a
    /// real browser would be). se-serve's render follow drives off this;
    /// the eval verb drops it (goto parses, eval executes — an eval is not
    /// a navigation surface). `None` when no page was bound.
    pub fn eval_with_page_with_nav(
        &mut self,
        page: Option<&bridge::Page>,
        source: &str,
        budget: std::time::Duration,
    ) -> (Result<serde_json::Value, Error>, Option<String>) {
        self.eval_inner(page, source, budget)
    }

    fn eval_inner(
        &mut self,
        page: Option<&bridge::Page>,
        source: &str,
        budget: std::time::Duration,
    ) -> (Result<serde_json::Value, Error>, Option<String>) {
        let isolate = &mut self.isolate;
        v8::scope!(let scope, isolate);
        let mut state = Box::new(bridge::State::new(page));
        let ptr = bridge::state_ptr(&mut state);
        let ext = v8::External::new(scope, ptr as *mut std::os::raw::c_void);
        let globals = bridge::build_globals(scope, ptr, ext.into());
        let context = v8::Context::new(
            scope,
            v8::ContextOptions {
                global_template: Some(globals),
                global_object: None,
                microtask_queue: None,
            },
        );
        let scope = &mut v8::ContextScope::new(scope, context);
        bridge::finalize_context(scope, &mut state);
        // Wrap the user source in a try/catch that funnels a sync throw into
        // the bridge's `__seThrow` host fn. This is what carries the
        // exception's MESSAGE over the wire (previously "<v8 gave no
        // message>") — and it sidesteps a real v8-152 API constraint:
        // `Script::run` takes `&PinScope` concretely, so a Rust-side
        // TryCatch cannot wrap the run (the try-catch would exclusively
        // borrow the very scope run needs). A JS-level catch sees the same
        // exception. The try STATEMENT preserves the completion value when
        // nothing throws, so the settle/stringify paths are unchanged.
        let wrapped = format!(
            "try {{\n{}\n}} catch (__seThrown) {{ __seThrow(__seThrown); }}",
            source
        );
        let Some(code) = v8::String::new(scope, &wrapped) else {
            return (
                Err(Error::SourceTooLarge),
                page.map(|_| state.page_url().to_string()),
            );
        };
        let script = match v8::Script::compile(scope, code, None) {
            Some(s) => s,
            None => {
                // Syntax error in the user source. The wrapped script can't
                // compile, so run a compile-only probe — `new Function` parses
                // the source without executing it — and let __seThrow carry
                // the SyntaxError's message back. Sources the function grammar
                // accepts but the script grammar rejects (top-level return)
                // keep the honest default.
                let source_json = match serde_json::to_string(source) {
                    Ok(s) => s,
                    Err(e) => {
                        return (
                            Err(Error::Compile(e.to_string())),
                            page.map(|_| state.page_url().to_string()),
                        );
                    }
                };
                let probe = format!(
                    "try {{ new Function({}); }} catch (e) {{ __seThrow(e); }}",
                    source_json
                );
                let _ = v8::String::new(scope, &probe)
                    .and_then(|c| v8::Script::compile(scope, c, None))
                    .and_then(|s| s.run(scope));
                let msg = state.take_thrown().filter(|m| !m.is_empty());
                return (
                    Err(Error::Compile(
                        msg.unwrap_or_else(|| "<v8 gave no message>".into()),
                    )),
                    page.map(|_| state.page_url().to_string()),
                );
            }
        };
        // No `?` between run and the writeback flush: a script that mutates
        // the DOM and then throws (sync or via promise) still leaves a real
        // tab mutated, so the writeback must publish on those paths too.
        let out = match script.run(scope) {
            // Unreachable under the wrapper (a sync throw is caught in JS);
            // kept as the backstop for non-catchable aborts like termination.
            None => Err(Error::Threw("<v8 gave no message>".into())),
            Some(result) => {
                if let Some(msg) = state.take_thrown() {
                    Err(Error::Threw(msg))
                } else {
                    match bridge::settle(scope, result, &mut state, budget) {
                        bridge::Settled::Rejected(reason) => Err(Error::Threw(reason)),
                        bridge::Settled::Resolved(json) => {
                            serde_json::from_str(&json).map_err(|e| Error::NotJson(e.to_string()))
                        }
                        bridge::Settled::Value => {
                            if result.is_undefined() {
                                Ok(serde_json::Value::Null)
                            } else {
                                match v8::json::stringify(scope, result) {
                                    None => Err(Error::NotJson(
                                        "json::stringify returned None".into(),
                                    )),
                                    Some(s) => {
                                        let s = s.to_rust_string_lossy(scope);
                                        serde_json::from_str(&s)
                                            .map_err(|e| Error::NotJson(e.to_string()))
                                    }
                                }
                            }
                        }
                    }
                }
            }
        };
        if let Some(p) = page {
            state.flush_writeback(p);
        }
        let nav = page.map(|_| state.page_url().to_string());
        (out, nav)
    }
}

/// Find `marker` in `src` and return the balanced `{...}` object literal
/// that follows, scanning string-, template-, line-comment-, and
/// block-comment-aware so braces inside string values don't end the scan
/// early. Returns the literal including its braces, or None if unbalanced.
pub fn extract_object_literal<'a>(src: &'a str, marker: &str) -> Option<&'a str> {
    let start = src.find(marker)? + marker.len();
    let bytes = src.as_bytes();
    let mut i = start;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() && bytes[i] != b'{' {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b'{' {
        return None;
    }
    let literal_start = i;
    let mut depth = 0i32;
    let mut in_str: Option<u8> = None;
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    while i < bytes.len() {
        let b = bytes[i];
        let next = bytes.get(i + 1).copied();
        if in_line_comment {
            if b == b'\n' {
                in_line_comment = false;
            }
        } else if in_block_comment {
            if b == b'*' && next == Some(b'/') {
                in_block_comment = false;
                i += 1;
            }
        } else if let Some(q) = in_str {
            if b == b'\\' {
                i += 1; // skip escaped char
            } else if b == q {
                in_str = None;
            }
        } else {
            match b {
                b'"' | b'\'' => in_str = Some(b),
                b'`' => in_str = Some(b), // templates: treat as opaque for M1
                b'/' if next == Some(b'/') => {
                    in_line_comment = true;
                    i += 1;
                }
                b'/' if next == Some(b'*') => {
                    in_block_comment = true;
                    i += 1;
                }
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&src[literal_start..=i]);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod scanner_tests {
    use super::*;

    const MARKER: &str = "var data = ";

    #[test]
    fn brace_in_string_does_not_end_scan() {
        let src = r#"var data = {"title": "a } b", "n": 1};"#;
        let lit = extract_object_literal(src, MARKER).unwrap();
        assert_eq!(lit, r#"{"title": "a } b", "n": 1}"#);
    }

    #[test]
    fn escaped_quote_inside_string() {
        let src = r#"var data = {"t": "she said \"}\" "};"#;
        let lit = extract_object_literal(src, MARKER).unwrap();
        assert!(lit.ends_with('}'));
    }

    #[test]
    fn braces_in_comments_are_ignored() {
        let src = "var data = {\n// } in comment\n\"a\": 1};";
        let lit = extract_object_literal(src, MARKER).unwrap();
        assert_eq!(lit, "{\n// } in comment\n\"a\": 1}");
    }

    #[test]
    fn nested_objects_balance() {
        let src = r#"var data = {"a": {"b": {"c": 1}}};"#;
        let lit = extract_object_literal(src, MARKER).unwrap();
        assert_eq!(lit, r#"{"a": {"b": {"c": 1}}}"#);
    }

    #[test]
    fn unbalanced_returns_none() {
        assert!(extract_object_literal("var data = {\"a\": 1;", MARKER).is_none());
    }

    #[test]
    fn missing_marker_returns_none() {
        assert!(extract_object_literal("x = 1;", MARKER).is_none());
    }
}
