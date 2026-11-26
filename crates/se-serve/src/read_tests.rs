//! The combined `read` verb, snapshot shaping, and reads that do not hold
//! the tab lock while they parse.

use super::*;

const PAGE: &str = r##"<html><head><base href="/shop/"></head><body>
<nav><a href="a">Alpha</a><a href="/b?x=1">Beta</a><a href="#top">Top</a><a href="a">Alpha again</a></nav>
<main id="m"><h1>Title</h1><p>Hello <b>world</b> and <a href="https://other.example/x"><span>Buy</span></a></p>
<p id="keep">Hello <i>world</i></p>
<button aria-label="Go now"><span>Go</span></button>
<p>A long paragraph of text that goes on well past the cap we ask for here.</p></main>
</body></html>"##;

fn engine_with(html: &str) -> Engine {
    let engine = Engine::default();
    engine.tabs.lock().unwrap().insert(
        "default".to_string(),
        Tab::after_navigation(None, "https://site.example/dir/page.html", String::new(), html.to_string()),
    );
    engine
}

fn call(engine: &Engine, verb: &str, params: Value) -> Value {
    tokio::runtime::Runtime::new().unwrap().block_on(dispatch(engine, verb, params)).unwrap()
}

#[test]
fn read_returns_every_included_part_from_one_call() {
    let engine = engine_with(PAGE);
    let r = call(&engine, "read", json!({"include": ["html", "text", "snapshot", "links"]}));
    assert_eq!(r["ok"], json!(true), "{r}");
    assert_eq!(r["url"], json!("https://site.example/dir/page.html"));
    // Each part equals what its own verb returns.
    assert_eq!(r["html"], call(&engine, "read_html", json!({}))["html"]);
    assert_eq!(r["text"], call(&engine, "read_text", json!({}))["text"]);
    assert_eq!(r["snapshot"], call(&engine, "read_snapshot", json!({}))["snapshot"]);
    // Links: absolute, in document order, one row per target, no fragments.
    let links: Vec<(String, String)> = r["links"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| (l["href"].as_str().unwrap().to_string(), l["text"].as_str().unwrap().to_string()))
        .collect();
    assert_eq!(
        links,
        vec![
            ("https://site.example/shop/a".to_string(), "Alpha".to_string()),
            ("https://site.example/b?x=1".to_string(), "Beta".to_string()),
            ("https://other.example/x".to_string(), "Buy".to_string()),
        ]
    );
}

#[test]
fn read_defaults_to_text_scopes_by_selector_and_refuses_unknown_parts() {
    let engine = engine_with(PAGE);
    let r = call(&engine, "read", json!({}));
    assert!(r["text"].as_str().unwrap().contains("Title"), "{r}");
    assert!(r.get("html").is_none() && r.get("snapshot").is_none());
    let r = call(&engine, "read", json!({"include": "text,html", "selector": "#keep"}));
    assert_eq!(r["text"], json!("Hello world"));
    assert_eq!(r["html"], json!("<p id=\"keep\">Hello <i>world</i></p>"));
    let r = call(&engine, "read", json!({"include": ["pixels"]}));
    assert_eq!(r["ok"], json!(false));
    assert!(r["error"].as_str().unwrap().contains("unknown include"), "{r}");
    let r = call(&engine, "read", json!({"selector": "#nope"}));
    assert_eq!(r["ok"], json!(false));
    let r = call(&engine, "read", json!({"tab_id": "ghost"}));
    assert!(r["error"].as_str().unwrap().contains("no tab"), "{r}");
}

#[test]
fn snapshot_shaping_is_opt_in() {
    let engine = engine_with(PAGE);
    let plain = call(&engine, "read_snapshot", json!({}));
    assert!(plain.get("snapshot_total").is_none(), "{plain}");
    let hrefs: Vec<&str> = plain["snapshot"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["href"].as_str())
        .collect();
    assert_eq!(hrefs, vec!["a", "/b?x=1", "#top", "a", "https://other.example/x"]);
}

#[test]
fn snapshot_dedupe_drops_only_entries_that_repeat_a_listed_ancestor() {
    let engine = engine_with(PAGE);
    let plain = call(&engine, "read_snapshot", json!({}));
    let shaped = call(&engine, "read_snapshot", json!({"dedupe": true}));
    let kinds = |v: &Value| -> Vec<String> {
        v["snapshot"].as_array().unwrap().iter().map(|e| e["kind"].as_str().unwrap().to_string()).collect()
    };
    let before = kinds(&plain);
    let after = kinds(&shaped);
    // <b>world</b>, <span>Buy</span>, <i>world</i> and the button's <span>Go</span>.
    assert_eq!(before.len() - after.len(), 4, "{before:?} -> {after:?}");
    assert_eq!(shaped["snapshot_deduped"], json!(4));
    assert_eq!(shaped["snapshot_total"], json!(before.len()));
    for gone in ["b", "i", "span"] {
        assert!(!after.contains(&gone.to_string()), "{after:?}");
    }
    // Interactive and identified entries all stay, with their text.
    let snap = shaped["snapshot"].as_array().unwrap();
    assert_eq!(snap.iter().filter(|e| e["kind"] == "a").count(), 5);
    assert!(snap.iter().any(|e| e["id"] == "keep" && e["text"] == "Hello world"));
    assert!(snap.iter().any(|e| e["kind"] == "button" && e["text"] == "Go"));
    // No text was lost: every dropped text is inside a kept entry's text.
    let kept: String = snap.iter().map(|e| e["text"].as_str().unwrap()).collect::<Vec<_>>().join("\n");
    for e in plain["snapshot"].as_array().unwrap() {
        assert!(kept.contains(e["text"].as_str().unwrap()), "{e}");
    }
}

#[test]
fn snapshot_absolute_hrefs_honour_base_and_caps_truncate() {
    let engine = engine_with(PAGE);
    let all = call(&engine, "read_snapshot", json!({"absolute": true}));
    assert_eq!(all["snapshot_truncated"], json!(false));
    let hrefs: Vec<&str> = all["snapshot"].as_array().unwrap().iter().filter_map(|e| e["href"].as_str()).collect();
    let r = call(&engine, "read_snapshot", json!({"absolute": true, "max_text": 12, "max_entries": 9}));
    let snap = r["snapshot"].as_array().unwrap();
    assert_eq!(
        hrefs,
        vec![
            "https://site.example/shop/a",
            "https://site.example/b?x=1",
            "#top",
            "https://site.example/shop/a",
            "https://other.example/x",
        ]
    );
    assert_eq!(snap.len(), 9);
    assert_eq!(r["snapshot_truncated"], json!(true));
    assert!(snap.iter().all(|e| e["text"].as_str().unwrap().chars().count() <= 13), "{snap:?}");
    // The combined verb takes the same options.
    let c = call(&engine, "read", json!({"include": ["snapshot"], "absolute": true, "max_text": 12, "max_entries": 9}));
    assert_eq!(c["snapshot"], r["snapshot"]);
}

#[test]
fn a_large_parse_does_not_hold_the_tab_lock() {
    // One tab with a document that takes long to parse, one small tab. While
    // the large read runs, the tab map must stay available.
    let mut big = String::from("<html><body>");
    for i in 0..60_000 {
        big.push_str(&format!("<div class=\"r\"><a href=\"/i/{i}\">item {i}</a><span>v{i}</span></div>"));
    }
    big.push_str("</body></html>");
    let engine = std::sync::Arc::new(engine_with(&big));
    let e2 = engine.clone();
    let reader = std::thread::spawn(move || {
        let t0 = std::time::Instant::now();
        let r = call(&e2, "read_snapshot", json!({}));
        assert!(r["snapshot"].as_array().unwrap().len() >= 120_000);
        t0.elapsed()
    });
    std::thread::sleep(std::time::Duration::from_millis(15));
    let mut worst = std::time::Duration::ZERO;
    let mut probes = 0;
    while !reader.is_finished() {
        let t0 = std::time::Instant::now();
        drop(engine.tabs.lock().unwrap());
        worst = worst.max(t0.elapsed());
        probes += 1;
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    let long = reader.join().unwrap();
    assert!(probes >= 3, "the large read was too short to observe ({long:?})");
    assert!(worst < long / 4, "lock held {worst:?} of a {long:?} read");
}

// ── isolate pool ────────────────────────────────────────────────────────────

/// How long a quick eval waits when a 600 ms eval started just before it.
fn quick_eval_wait(isolates: usize) -> (std::time::Duration, Value) {
    let pool = JsPool::with_size(isolates);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let slow_pool = pool.clone();
    let slow = std::thread::spawn(move || {
        tokio::runtime::Runtime::new().unwrap().block_on(slow_pool.eval_with_budget(
            None,
            "new Promise(function (r) { setTimeout(function () { r('slow'); }, 600); })".to_string(),
            std::time::Duration::from_millis(3000),
        ))
    });
    std::thread::sleep(std::time::Duration::from_millis(120));
    let t0 = std::time::Instant::now();
    let quick = rt.block_on(pool.eval(None, "1 + 1".to_string())).unwrap();
    let waited = t0.elapsed();
    assert_eq!(quick, json!(2));
    assert_eq!(slow.join().unwrap().unwrap(), json!("slow"));
    (waited, pool.health())
}

#[test]
fn one_isolate_makes_a_quick_eval_wait_behind_a_slow_one() {
    let (waited, health) = quick_eval_wait(1);
    assert!(waited >= std::time::Duration::from_millis(350), "{waited:?}");
    assert_eq!(health["isolates"], json!(1));
    assert_eq!(health["evals"], json!(2));
}

#[test]
fn a_second_isolate_starts_on_need_and_takes_the_quick_eval() {
    let (waited, health) = quick_eval_wait(3);
    assert!(waited < std::time::Duration::from_millis(350), "{waited:?}");
    // Started on need: two, not the three allowed.
    assert_eq!(health["isolates"], json!(2));
    assert_eq!(health["isolates_max"], json!(3));
    assert_eq!(health["evals"], json!(2));
    assert_eq!(health["alive"], json!(true));
}
