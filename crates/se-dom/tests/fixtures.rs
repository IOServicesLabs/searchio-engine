//! Fixture tests: the two workloads searchio actually serves, captured from
//! the live sites by the reference engine. These pin M0 against reality —
//! if a dependency bump or parser swap changes what we see on these pages,
//! this file fails before any provider in Python does.

use std::fs;
use std::path::PathBuf;

use se_dom::Document;

fn fixture(name: &str) -> String {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p.push(name);
    fs::read_to_string(p).expect("fixture missing — captures live in tests/fixtures/")
}

#[test]
fn facebook_marketplace_lists_every_listing() {
    let doc = Document::parse(&fixture("fb_marketplace.html"));
    let items = doc
        .attr_values("a[href*='/marketplace/item/']", "href")
        .unwrap();
    // Reference count from the live capture (selectolax cross-check).
    assert_eq!(items.len(), 11, "expected 11 distinct listings, got {items:?}");
}

#[test]
fn facebook_marketplace_round_trip_is_stable() {
    let doc = Document::parse(&fixture("fb_marketplace.html"));
    let first = doc.attr_values("a[href*='/marketplace/item/']", "href").unwrap();
    let reparsed = Document::parse(&doc.html());
    let second = reparsed
        .attr_values("a[href*='/marketplace/item/']", "href")
        .unwrap();
    assert_eq!(first, second);
}

#[test]
fn youtube_carries_initial_data_and_video_renderers() {
    let doc = Document::parse(&fixture("yt_results.html"));
    let has_initial = doc
        .select("script")
        .unwrap()
        .iter()
        .any(|s| s.text().contains("ytInitialData"));
    assert!(has_initial, "ytInitialData script must survive parsing");
    let html = doc.html();
    let renderers = html.matches("videoRenderer").count();
    assert!(
        renderers >= 19,
        "expected >= 19 videoRenderer occurrences, got {renderers}"
    );
}

#[test]
fn youtube_watch_urls_live_in_initial_data_json() {
    let doc = Document::parse(&fixture("yt_results.html"));
    // The captured DOM holds only nav anchors — result links exist as URLs
    // inside the ytInitialData JSON (this capture predates full hydration),
    // which is exactly how the searchio provider extracts them.
    let script = doc
        .select("script")
        .unwrap()
        .into_iter()
        .find(|s| s.text().contains("ytInitialData"))
        .expect("ytInitialData script present");
    let watch_urls = script.text().matches("watch?v=").count();
    assert!(
        watch_urls >= 19,
        "ytInitialData JSON must reference >= 19 watch URLs, got {watch_urls}"
    );
}
