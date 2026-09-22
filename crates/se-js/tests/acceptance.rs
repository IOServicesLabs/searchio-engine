//! Acceptance test for the M1 JS tier: YouTube's real `ytInitialData`
//! assignment — a ~2MB object literal from the live site — must execute in
//! our V8 and yield the same 19-video structure the Python provider parses.

use std::fs;
use std::path::PathBuf;

use se_dom::Document;
use se_js::{bridge::Page, extract_object_literal, Runtime};

fn fixture(name: &str) -> String {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // se-js/
    p.push("se-dom");
    p.push("tests");
    p.push("fixtures");
    p.push(name);
    fs::read_to_string(p).expect("fixture lives in the se-dom crate")
}

#[test]
fn evals_arithmetic_and_objects() {
    let mut rt = Runtime::new();
    assert_eq!(rt.eval("1 + 1").unwrap(), serde_json::json!(2));
    assert_eq!(
        rt.eval("({a: [1, 2, 3], b: 'x', c: null, d: true})").unwrap(),
        serde_json::json!({"a": [1, 2, 3], "b": "x", "c": null, "d": true})
    );
    assert_eq!(rt.eval("undefined").unwrap(), serde_json::Value::Null);
}

#[test]
fn executes_youtube_initial_data() {
    let doc = Document::parse(&fixture("yt_results.html"));
    let script = doc
        .select("script")
        .unwrap()
        .into_iter()
        .map(|s| s.text())
        .find(|t| t.contains("ytInitialData"))
        .expect("ytInitialData script in fixture");

    let literal = extract_object_literal(&script, "var ytInitialData = ")
        .or_else(|| extract_object_literal(&script, "window[\"ytInitialData\"] = "))
        .expect("balanced literal after marker");

    let mut rt = Runtime::new();
    let json_text = rt
        .eval(&format!("var ytInitialData = {literal}; JSON.stringify(ytInitialData)"))
        .unwrap()
        .as_str()
        .expect("JSON.stringify returns a string")
        .to_string();

    let data: serde_json::Value = serde_json::from_str(&json_text).unwrap();
    let s = serde_json::to_string(&data).unwrap();
    let renderers = s.matches("videoRenderer").count();
    assert!(renderers >= 19, "expected >= 19 videoRenderers, got {renderers}");
    let watch_urls = s.matches("watch?v=").count();
    assert!(watch_urls >= 19, "expected >= 19 watch URLs, got {watch_urls}");
}

// ── DOM bridge (M1 slice 2) ──────────────────────────────────────────────────
//
// The same queries searchio's providers run, but through the engine's own
// JS tier: page JS sees `document`, elements, location — not raw strings.

fn fb_page() -> Page {
    Page::new(
        "https://www.facebook.com/marketplace/nyc/search/?query=couch",
        fixture("fb_marketplace.html"),
    )
}

#[test]
fn navigator_answers_at_about_blank() {
    // SidecarClient.user_agent() evals this before any navigation.
    let mut rt = Runtime::new();
    let ua = rt
        .eval("navigator.userAgent")
        .unwrap()
        .as_str()
        .expect("userAgent is a string")
        .to_string();
    assert!(ua.contains("Chrome/145"), "presented UA, got {ua:?}");
    // Real non-automated Chrome has NO webdriver property; a boolean false
    // is itself the automation tell. Assert absence, not value.
    assert_eq!(
        rt.eval("'webdriver' in navigator").unwrap(),
        serde_json::Value::Bool(false)
    );
    assert_eq!(
        rt.eval("typeof navigator.webdriver").unwrap(),
        serde_json::Value::String("undefined".into())
    );
}

#[test]
fn query_selector_all_counts_real_fixture() {
    let page = fb_page();
    let mut rt = Runtime::new();
    let n = rt
        .eval_with_page(
            Some(&page),
            "document.querySelectorAll(\"a[href*='/marketplace/item/']\").length",
        )
        .unwrap();
    // The se-dom fixture pins exactly 11 distinct listing anchors; the DOM
    // has more anchor nodes than distinct ids (wrap cards), so >= 11.
    assert!(
        n.as_i64().expect("numeric count") >= 11,
        "expected >= 11 listing anchors, got {n}"
    );
}

#[test]
fn scoped_queries_text_and_attributes() {
    let page = fb_page();
    let mut rt = Runtime::new();
    let js = r#"
      var card = document.querySelector("a[href*='/marketplace/item/']");
      var out = {
        tag: card.tagName,
        href: card.getAttribute("href"),
        text_len: card.textContent.length,
        classes: card.classList.contains("x1i10hfl"), // FB's real class soup
      };
      out
    "#;
    let out = rt.eval_with_page(Some(&page), js).unwrap();
    assert_eq!(out["tag"], serde_json::json!("A"));
    let href = out["href"].as_str().expect("href attribute");
    assert!(href.starts_with("/marketplace/item/") || href.contains("/marketplace/item/"),);
    assert!(out["text_len"].as_i64().unwrap() > 0, "listing anchor has text");
    // Whether the pinned class is present depends on the capture; the field
    // must exist either way — the call must not throw.
    assert!(out["classes"].is_boolean(), "classList.contains returned bool");
}

#[test]
fn top_level_async_iife_resolves() {
    let page = fb_page();
    let mut rt = Runtime::new();
    // The provider scroll idiom: an async body whose result is the answer.
    // setTimeout resolves synchronously at this tier (see bridge docs).
    let js = r#"
      (async () => {
        await new Promise(r => setTimeout(r, 100));
        var ids = new Set();
        document.querySelectorAll("a[href*='/marketplace/item/']").forEach(a => {
          var m = a.getAttribute("href").match(/\/marketplace\/item\/(\d+)/);
          if (m) ids.add(m[1]);
        });
        return ids.size;
      })()
    "#;
    let n = rt.eval_with_page(Some(&page), js).unwrap();
    assert_eq!(n, serde_json::json!(11), "exactly 11 distinct listings");
}

#[test]
fn location_and_document_metadata_match_page() {
    let page = fb_page();
    let mut rt = Runtime::new();
    let js = r#"
      ({
        href: location.href,
        protocol: location.protocol,
        host: location.host,
        has_query: location.search.indexOf("query=") !== -1,
        ready: document.readyState,
        url_match: document.URL === location.href,
        window_nav: window.navigator.userAgent === navigator.userAgent,
      })
    "#;
    let out = rt.eval_with_page(Some(&page), js).unwrap();
    assert_eq!(
        out["href"],
        serde_json::json!("https://www.facebook.com/marketplace/nyc/search/?query=couch")
    );
    assert_eq!(out["protocol"], serde_json::json!("https:"));
    assert_eq!(out["host"], serde_json::json!("www.facebook.com"));
    assert!(out["has_query"].as_bool().unwrap());
    assert_eq!(out["ready"], serde_json::json!("complete"));
    assert!(out["url_match"].as_bool().unwrap());
    assert!(out["window_nav"].as_bool().unwrap());
}

#[test]
fn promise_rejection_surfaces_as_error() {
    let mut rt = Runtime::new();
    let err = rt.eval("Promise.reject(new Error('boom'))").unwrap_err();
    assert!(err.to_string().contains("boom"), "reason surfaced, got {err}");
}

#[test]
fn fingerprint_surface_is_consistent_with_the_presented_ua() {
    // M3 stealth slice: every JS-observable surface a fingerprint script
    // reads must agree with the Chrome-145-on-Windows identity the wire
    // presents (se-net sends the SAME UA). A contradiction between any two
    // of these is itself the bot signal.
    let mut rt = Runtime::new();
    let js = r#"
      ({
        ua_has_chrome: navigator.userAgent.indexOf('Chrome/145') !== -1,
        ua_has_windows: navigator.userAgent.indexOf('Windows NT 10.0') !== -1,
        appName: navigator.appName,
        appVersion: navigator.appVersion,
        product: navigator.product,
        productSub: navigator.productSub,
        vendor: navigator.vendor,
        vendorSub: navigator.vendorSub,
        platform: navigator.platform,
        language: navigator.language,
        languages: navigator.languages.join(','),
        hardwareConcurrency: navigator.hardwareConcurrency,
        deviceMemory: navigator.deviceMemory,
        maxTouchPoints: navigator.maxTouchPoints,
        onLine: navigator.onLine,
        cookieEnabled: navigator.cookieEnabled,
        pdfViewerEnabled: navigator.pdfViewerEnabled,
        connection: navigator.connection.effectiveType,
        javaEnabled: navigator.javaEnabled(),
        webdriverAbsent: !('webdriver' in navigator),
        webdriverUndefined: typeof navigator.webdriver === 'undefined',
        pluginsLen: navigator.plugins.length,
        pluginNames: Array.prototype.map.call(navigator.plugins, p => p.name).join('|'),
        mimeTypesLen: navigator.mimeTypes.length,
        screen: [screen.width, screen.height, screen.availWidth, screen.availHeight,
                 screen.colorDepth, screen.pixelDepth].join('x'),
        innerConsistent: window.innerWidth <= screen.width && window.innerHeight <= screen.height,
        chromePresent: typeof window.chrome === 'object' && window.chrome !== null,
        chromeRuntime: typeof window.chrome.runtime === 'object',
        uadMobile: navigator.userAgentData.mobile,
        uadPlatform: navigator.userAgentData.platform,
        uadBrands: navigator.userAgentData.brands.map(b => b.brand + '/' + b.version).join('|'),
        hasFocus: document.hasFocus(),
        matchMediaOk: typeof window.matchMedia === 'function'
            && window.matchMedia('(prefers-color-scheme: dark)').matches === false
            && typeof window.matchMedia('(prefers-color-scheme: dark)').addEventListener === 'function',
        notificationPermission: typeof Notification === 'function' ? Notification.permission : 'absent',
      })
    "#;
    let out = rt.eval(js).unwrap();
    assert!(out["ua_has_chrome"].as_bool().unwrap());
    assert!(out["ua_has_windows"].as_bool().unwrap());
    assert_eq!(out["appName"], serde_json::json!("Netscape"));
    assert_eq!(
        out["appVersion"],
        serde_json::json!("5.0 (Windows NT 10.0; Win64; x64)")
    );
    assert_eq!(out["product"], serde_json::json!("Gecko"));
    assert_eq!(out["productSub"], serde_json::json!("20030107"));
    assert_eq!(out["vendor"], serde_json::json!("Google Inc."));
    assert_eq!(out["vendorSub"], serde_json::json!(""));
    assert_eq!(out["platform"], serde_json::json!("Win32"));
    assert_eq!(out["language"], serde_json::json!("en-US"));
    assert_eq!(out["languages"], serde_json::json!("en-US"));
    assert_eq!(out["hardwareConcurrency"], serde_json::json!(8));
    assert_eq!(out["deviceMemory"], serde_json::json!(8));
    assert_eq!(out["maxTouchPoints"], serde_json::json!(0));
    assert_eq!(out["onLine"], serde_json::json!(true));
    assert_eq!(out["cookieEnabled"], serde_json::json!(true));
    assert_eq!(out["pdfViewerEnabled"], serde_json::json!(true));
    assert_eq!(out["connection"], serde_json::json!("4g"));
    assert_eq!(out["javaEnabled"], serde_json::json!(false));
    assert_eq!(out["webdriverAbsent"], serde_json::json!(true));
    assert_eq!(out["webdriverUndefined"], serde_json::json!(true));
    assert_eq!(out["pluginsLen"], serde_json::json!(5));
    assert_eq!(
        out["pluginNames"],
        serde_json::json!(
            "PDF Viewer|Chrome PDF Viewer|Chromium PDF Viewer|Microsoft Edge PDF Viewer|WebKit built-in PDF"
        )
    );
    assert_eq!(out["mimeTypesLen"], serde_json::json!(1));
    assert_eq!(out["screen"], serde_json::json!("1920x1080x1920x1040x24x24"));
    assert_eq!(out["innerConsistent"], serde_json::json!(true));
    assert_eq!(out["chromePresent"], serde_json::json!(true));
    assert_eq!(out["chromeRuntime"], serde_json::json!(true));
    assert_eq!(out["uadMobile"], serde_json::json!(false));
    assert_eq!(out["uadPlatform"], serde_json::json!("Windows"));
    assert_eq!(
        out["uadBrands"],
        serde_json::json!("Chromium/145|Google Chrome/145|Not.A/Brand/99")
    );
    assert_eq!(out["hasFocus"], serde_json::json!(true));
    assert_eq!(out["matchMediaOk"], serde_json::json!(true));
    assert_eq!(out["notificationPermission"], serde_json::json!("default"));
}
