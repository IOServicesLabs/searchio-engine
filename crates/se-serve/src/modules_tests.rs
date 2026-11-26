//! Module scripts and the classic-script code cache, through a real render
//! pass against a local server.

use super::*;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Serve `routes` (path -> body) as JavaScript; count the hits per run.
fn serve(routes: Vec<(&'static str, String)>) -> (String, Arc<AtomicUsize>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits2 = hits.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
            let path = path.split('?').next().unwrap_or("/").to_string();
            hits2.fetch_add(1, Ordering::SeqCst);
            let (status, body) = match routes.iter().find(|(p, _)| *p == path) {
                Some((_, b)) => ("200 OK", b.clone()),
                None => ("404 Not Found", "missing".to_string()),
            };
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 {status}\r\nContent-Type: text/javascript\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            );
        }
    });
    (format!("http://{addr}"), hits)
}

fn render(base: &str, html: &str, opts: JsOpts) -> (RenderStats, String) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let engine = Engine::default();
    engine.tabs.lock().unwrap().insert(
        "default".to_string(),
        Tab::after_navigation(None, &format!("{base}/app/index.html"), String::new(), html.to_string()),
    );
    let stats = rt.block_on(JS_OPTS.scope(
        opts,
        engine.render_tab("default", std::time::Duration::from_millis(4000)),
    ));
    let out = engine.tabs.lock().unwrap().get("default").unwrap().html.clone();
    (stats, out)
}

fn on() -> JsOpts {
    JsOpts { prelude: true, quiesce: 3, modules: true, live_dom: true, ..JsOpts::default() }
}

const SHOW: &str = "function show(id, t) { var p = document.createElement('p'); p.id = id; \
                    p.textContent = t; document.body.appendChild(p); }";

#[test]
fn off_a_module_script_is_skipped_as_before() {
    let (base, hits) = serve(vec![]);
    let html = "<html><body><script type=\"module\">document.body.innerHTML = '<p id=m>ran</p>';</script>\
                <script>document.title = 'classic';</script></body></html>";
    let (stats, out) = render(&base, html, JsOpts { prelude: true, ..JsOpts::default() });
    assert!(!out.contains("id=\"m\""), "{out}");
    assert!(stats.errors.iter().any(|e| e.contains("module scripts unsupported")), "{:?}", stats.errors);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[test]
fn inline_module_loads_its_import_graph_relative_to_each_importer() {
    let (base, hits) = serve(vec![
        ("/app/lib/dep.js", "import { leaf } from '../leaf.js'; export const dep = 'dep+' + leaf;".into()),
        ("/app/leaf.js", "export const leaf = 'leaf'; export default 7;".into()),
    ]);
    let html = format!(
        "<html><body><script>{SHOW}</script>\
         <script type=\"module\">import {{ dep }} from './lib/dep.js'; import seven from './leaf.js';\
         show('m', dep + ':' + seven + ':' + (typeof import.meta));</script></body></html>"
    );
    let (stats, out) = render(&base, &html, on());
    assert!(out.contains("<p id=\"m\">dep+leaf:7:object</p>"), "{out} {:?} {:?}", stats.errors, stats.page_errors);
    // leaf.js is imported twice and fetched once.
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[test]
fn external_module_runs_after_classic_scripts_and_nomodule_is_skipped() {
    let (base, _) = serve(vec![
        ("/app/main.js", "import { n } from './n.js'; show('order', window.__classic + '>' + n);".into()),
        ("/app/n.js", "export const n = 'module';".into()),
        ("/app/legacy.js", "show('legacy', 'ran');".into()),
    ]);
    let html = format!(
        "<html><body><script>{SHOW}</script>\
         <script type=\"module\" src=\"main.js\"></script>\
         <script nomodule src=\"legacy.js\"></script>\
         <script>window.__classic = 'classic';</script></body></html>"
    );
    let (stats, out) = render(&base, &html, on());
    assert!(out.contains("<p id=\"order\">classic&gt;module</p>"), "{out} {:?}", stats.errors);
    assert!(!out.contains("id=\"legacy\""), "{out}");
    assert!(stats.errors.iter().any(|e| e.contains("nomodule")), "{:?}", stats.errors);
}

#[test]
fn dynamic_import_resolves_with_the_namespace_from_modules_and_classic_scripts() {
    let (base, _) = serve(vec![
        ("/app/chunk.js", "export const word = 'lazy'; export default function () { return 'fn'; }".into()),
        ("/app/tla.js", "const v = await Promise.resolve('awaited'); export { v };".into()),
    ]);
    let html = format!(
        "<html><body><script>{SHOW}\
         import('./chunk.js').then(function (m) {{ show('c', m.word + ':' + m.default()); }});\
         import('./nope.js').then(null, function (e) {{ show('e', 'rejected'); }});</script>\
         <script type=\"module\">const m = await import('./tla.js'); show('t', m.v);</script></body></html>"
    );
    let (stats, out) = render(&base, &html, on());
    assert!(out.contains("<p id=\"c\">lazy:fn</p>"), "{out} {:?} {:?}", stats.errors, stats.page_errors);
    assert!(out.contains("<p id=\"e\">rejected</p>"), "{out}");
    assert!(out.contains("<p id=\"t\">awaited</p>"), "{out}");
}

#[test]
fn a_failing_module_is_reported_and_the_page_goes_on() {
    let (base, _) = serve(vec![("/app/bad.js", "export const = ;".into())]);
    let html = format!(
        "<html><body><script>{SHOW}</script>\
         <script type=\"module\">import 'vue'; show('a', 'no');</script>\
         <script type=\"module\">import './bad.js'; show('b', 'no');</script>\
         <script type=\"module\">import './gone.js'; show('c', 'no');</script>\
         <script type=\"module\">throw new Error('boom at top level');</script>\
         <script type=\"module\">show('ok', 'still runs');</script></body></html>"
    );
    let (stats, out) = render(&base, &html, on());
    assert!(out.contains("<p id=\"ok\">still runs</p>"), "{out}");
    for id in ["a", "b", "c"] {
        assert!(!out.contains(&format!("id=\"{id}\"")), "{out}");
    }
    let errs = stats.errors.join(" | ");
    assert!(errs.contains("bare"), "{errs}");
    assert!(errs.contains("SyntaxError") || errs.contains("Unexpected"), "{errs}");
    assert!(errs.contains("HTTP 404"), "{errs}");
    assert!(errs.contains("boom at top level"), "{errs}");
}

#[test]
fn cached_runner_shares_the_global_lexical_scope_and_reports_errors() {
    let (base, _) = serve(vec![]);
    let html = format!(
        "<html><body><script>{SHOW} let shared = 'lexical';</script>\
         <script>show('s', shared + ':' + (typeof show));</script>\
         <script>this is not javascript</script>\
         <script>throw new Error('second boom');</script>\
         <script>show('after', 'ok');</script></body></html>"
    );
    let opts = JsOpts { prelude: true, quiesce: 3, code_cache: true, live_dom: true, ..JsOpts::default() };
    let (stats, out) = render(&base, &html, opts);
    assert!(out.contains("<p id=\"s\">lexical:function</p>"), "{out} {:?}", stats.errors);
    assert!(out.contains("<p id=\"after\">ok</p>"), "{out}");
    let errs = stats.errors.join(" | ");
    assert!(errs.contains("compile script 2"), "{errs}");
    assert!(errs.contains("run script 3") && errs.contains("second boom"), "{errs}");
}

#[test]
fn the_code_cache_is_reused_for_the_same_bundle_and_not_for_changed_content() {
    // A bundle well over the cache floor, with real functions to compile.
    let mut bundle = String::from("var __acc = 0;\n");
    for i in 0..600 {
        bundle.push_str(&format!(
            "function f{i}(a, b) {{ var t = a * {i} + b; for (var k = 0; k < 3; k++) {{ t += k; }} return t; }}\n__acc += f{i}(1, 2);\n"
        ));
    }
    let v1 = format!("{bundle}show('r', 'v1:' + __acc);");
    let v2 = v1.replace("'v1:'", "'v2:'"); // same length, other content
    assert_eq!(v1.len(), v2.len());
    let html = format!(
        "<html><body><script>{SHOW}</script><script src=\"bundle.js\"></script></body></html>"
    );
    let opts = JsOpts { prelude: true, quiesce: 3, code_cache: true, pipeline: true, live_dom: true, ..JsOpts::default() };

    let (base, _) = serve(vec![("/app/bundle.js", v1.clone())]);
    let (h0, m0, ..) = se_js::code_cache_stats();
    let (_, out1) = render(&base, &html, opts);
    let (h1, m1, ..) = se_js::code_cache_stats();
    assert!(out1.contains("v1:"), "{out1}");
    assert!(m1 > m0, "first run stores a cache entry");
    let (_, out2) = render(&base, &html, opts);
    let (h2, ..) = se_js::code_cache_stats();
    assert_eq!(out1, out2);
    assert!(h2 > h1.max(h0), "second run consumes the cache");

    // Other content at a URL of its own: a miss, and the right answer.
    let (base2, _) = serve(vec![("/app/bundle.js", v2)]);
    let (_, out3) = render(&base2, &html, opts);
    assert!(out3.contains("v2:"), "{out3}");
}

// ── quiet window (render option `quiet_ms`) ─────────────────────────────────

const FAR_TIMER: &str = "<html><body><div id=\"app\"></div><script>\
    setTimeout(function () { document.getElementById('app').innerHTML = '<p id=\"one\">first</p>';\
      setTimeout(function () { document.getElementById('app').innerHTML += '<p id=\"two\">second</p>'; }, 250);\
    }, 200);\
    setTimeout(function () { window.__beacon = 1; }, 2500);</script></body></html>";

#[test]
fn without_a_quiet_window_a_far_timer_holds_the_render() {
    let (base, _) = serve(vec![]);
    let t0 = std::time::Instant::now();
    let opts = JsOpts { prelude: true, quiesce: 3, live_dom: true, ..JsOpts::default() };
    let (_, out) = render(&base, FAR_TIMER, opts);
    assert!(out.contains("id=\"two\""), "{out}");
    assert!(t0.elapsed() >= std::time::Duration::from_millis(2400), "{:?}", t0.elapsed());
}

#[test]
fn a_quiet_window_ends_a_still_page_and_keeps_near_timer_chains() {
    let (base, _) = serve(vec![]);
    let t0 = std::time::Instant::now();
    let opts = JsOpts { prelude: true, quiesce: 3, live_dom: true, quiet_ms: 400, ..JsOpts::default() };
    let (_, out) = render(&base, FAR_TIMER, opts);
    let took = t0.elapsed();
    // Both timer-built sections are in: each was due inside the window.
    assert!(out.contains("id=\"one\"") && out.contains("id=\"two\""), "{out}");
    // 450 ms of page work + the 400 ms window, not the 2.5 s beacon.
    assert!(took >= std::time::Duration::from_millis(800), "{took:?}");
    assert!(took < std::time::Duration::from_millis(1800), "{took:?}");
}
