//! The DOM bridge: a live `document` plus page-context Web APIs exposed to
//! page-facing JS.
//!
//! Design constraints that shaped this:
//! - v8 152 callbacks must be non-capturing (`UnitType`), so all host state
//!   lives in one [`State`] box; every function template carries it via
//!   `.data()` as a `v8::External` pointer.
//! - Timers are a real macrotask queue: `setTimeout`/`setInterval` schedule,
//!   `clearTimeout`/`clearInterval` cancel, and `settle` runs the pump —
//!   microtask checkpoint, fire due timers, repeat — until the tracked
//!   promise settles, no timers remain, or a wall-clock budget trips.
//!   Macrotask-then-microtask ordering matches the HTML event loop, so
//!   `await new Promise(r => setTimeout(r, n))` and scroll-loop evals return
//!   their counts, the exact contract `SidecarClient.eval_js` documents.
//! - `localStorage`/`sessionStorage` are per-page maps shared across evals
//!   (the se-serve tab holds the Arc; `session_reset` clears them per the
//!   protocol doc). Method API plus a live `length` accessor.
//! - `fetch` is real but blocking: the callback parks the isolate thread on
//!   an mpsc channel until a spawned thread's bare-HTTP answer lands, then
//!   pumps the microtask queue so `await fetch(...)` chains resolve, one
//!   fetch per eval. When the page is session-bound (se-serve wires the live
//!   jar into `Page.cookie_store`), the request presents the session's
//!   cookies — the store's own domain/path rules decide what matches, so a
//!   cross-origin `fetch` can't pull another origin's jar — and response
//!   `Set-Cookie` headers feed back into the jar like a document request
//!   would. The request itself presents the subresource signature a real
//!   XHR carries — client hints, Fetch Metadata (`Sec-Fetch-Dest: empty`,
//!   `Sec-Fetch-Mode: cors`, `Sec-Fetch-Site` from the page origin), the
//!   engine UA, `Accept: */*` — and never the navigation markers
//!   (`Upgrade-Insecure-Requests`, `Sec-Fetch-User`). `fetch`'s `init`
//!   honors `method` (POST body, Content-Length, the spec's
//!   `text/plain;charset=UTF-8` default), `headers` (Headers instance or
//!   plain object — same-name replaces a default, new name appends), and
//!   `body`; GET/HEAD never carry one. Redirects follow the fetch spec
//!   (301/302 rewrite POST→GET, 303 any→GET, 307/308 preserve; cap 20).
//!   The response read side matches browser parity: `headers` answers
//!   `get`/`has`/`forEach`/`entries` (names case-insensitive, snapshot taken
//!   before the methods attach), and `json()` is `text()` + `JSON.parse`
//!   with spec-shaped rejection. `XMLHttpRequest` is a
//!   shim:
//!   open/send/responseText work synchronously enough for
//!   `var x = new XMLHttpRequest(); x.open('GET', u, false); x.send();
//!   x.responseText` (the FB anonymous-listing idiom), and
//!   `getResponseHeader`/`getAllResponseHeaders` read the response head.
//!   `document.cookie` is a live accessor over the same jar: reads show the
//!   page's cookies minus httpOnly ones, writes parse `Path`/`Max-Age`/
//!   `Secure` and land in the store the next request presents.
//! - Scroll/geometry parity for provider scroll loops (`_SCROLL_JS`):
//!   `parentElement` resolves node ids against the eval's cached parse and
//!   wraps ancestors on demand (no eager ancestor snapshots); `getComputedStyle`
//!   answers CSS initial values plus the UA-stylesheet `display` per tag —
//!   the honest no-layout report; elements carry zeroed
//!   `scrollHeight`/`clientHeight`/`scrollTop`/… as writable data props, so
//!   assignments behave like real IDL attributes; `window.scrollBy`/`scrollTo`
//!   keep real `scrollY`/`pageYOffset` bookkeeping (clamped at zero); and
//!   `document.documentElement`/`body` wrap the live root. With no layout,
//!   `overflowY` is always `"visible"`, so the FB pane search falls through
//!   to the `window.scrollBy` branch exactly like the patchright fallback.
//! - Scope is deliberately scraping-shaped: queries, text, attributes,
//!   classList, scoped queries, timers, storage, scroll bookkeeping. No
//!   layout, no mutation API, no events.

use se_dom::{Document, Node};
use std::time::{Duration, Instant};
use v8::{
    External, Function, FunctionCallbackArguments, FunctionTemplate, Local, Name, Object,
    ObjectTemplate, PinScope, Promise, PropertyCallbackArguments, ReturnValue, Value,
};

/// What `canvas.toDataURL()` answers for a canvas the page has drawn to this
/// eval. A fixed 8x8 PNG rendered from a deterministic byte pattern — no real
/// rasterizer exists on this tier (see the module doc's "no layout/paint"
/// line), and for a fingerprint the payload's job is stability, not accuracy:
/// it must be identical across runs, machines, and eval sessions, and
/// different from the pristine-canvas answer below.
const CANVAS_FINGERPRINT: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAYAAADED76LAAAA7klEQVR42mNgYPj/X63o5n+fJ5v/F4X1/p9xIv3/PivH/0/WSP/nkvv6n0HC4/l/gwnn/6fozP5fU9L8f4OA//8TEeb//3xh/i9i8/o/A0gyjGnl/wSF+f/bJlWCJd+dEvz/4wX7f7moh/8ZPG5sB0tWZLT/n7Ah//+DBfJgSQGD9/81Kq7/Z4DpXMMS/P9Sme7/Aw72/59tkvzPo/L5v9G0s/8ZYDqP+Fj/vzNF+f+NDvX/Hy7w/1fJuf3fZsvh/wwgyW1KnnCdIEkxp5f/FRLu/3e7tPM/w4of4WBJmE4Oie9gSYsVx/8HfFj/HwA7+J3hqR7ILwAAAABJRU5ErkJggg==";

/// What `canvas.toDataURL()` answers for a never-drawn canvas: the canonical
/// transparent-pixel PNG a real browser produces for a pristine 300x150
/// canvas (RFC 2397 form).
const CANVAS_EMPTY_PNG: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";

/// One page's rendering input: final URL plus the HTML to expose as
/// `document`, the Web Storage maps the page shares across evals, and —
/// when driven by a session owner like se-serve — the live cookie jar the
/// page-context fetch/XHR tier presents on same-origin requests.
#[derive(Clone, Default)]
pub struct Page {
    pub url: String,
    /// The navigation initiator — the previous page's URL on a followed
    /// navigation, empty on an address-bar load. Surfaces as
    /// `document.referrer` and (in se-serve) the wire `Referer` /
    /// `Sec-Fetch-Site` pair.
    pub referrer: String,
    pub html: String,
    pub local_storage: Storage,
    pub session_storage: Storage,
    /// The browsing-context name (`window.name`) this page's evals share with
    /// the tab — writes survive across evals and navigations.
    pub window_name: WindowName,
    pub cookie_store: Option<std::sync::Arc<se_net::SessionStore>>,
    /// Session network log (firing 32): page-context fetch/XHR hops append
    /// here when wired in — the same opt-in pattern as `cookie_store`.
    pub net_log: Option<std::sync::Arc<se_net::NetLog>>,
    /// Test-tier hook: accept self-signed host certificates on page-context
    /// fetches (the h2-negotiation fixture serves one). The engine's
    /// production path always leaves this false — se-serve never sets it.
    pub danger_accept_invalid_host_certs: bool,
    /// DOM-mutation writeback slot. `mutate()` already re-serializes the
    /// document after every successful mutation; an eval that mutated leaves
    /// the final serialization here, and the session owner (se-serve's tab)
    /// adopts it after the eval — that is what makes page JS mutations
    /// persist across evals and into `read_html`, the way patchright's live
    /// DOM does. `None` after an eval = nothing mutated; same Arc-cell
    /// pattern as `window_name`, with the tab owning the Arc and each eval's
    /// Page cloning it.
    pub writeback: std::sync::Arc<std::sync::Mutex<Option<MutationWriteback>>>,
}

/// One pending DOM-mutation writeback: the document an eval produced, tagged
/// with the document it started from. The tab owner adopts the writeback
/// only while its current document is still `from` — a navigation that
/// raced the eval replaces the document and invalidates the writeback (the
/// fresh navigation always wins).
#[derive(Clone, Debug)]
pub struct MutationWriteback {
    pub from: String,
    pub html: String,
}

impl Page {
    pub fn new(url: impl Into<String>, html: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            html: html.into(),
            ..Self::default()
        }
    }

    /// Test-only: trust the loopback fixture's self-signed certificate.
    pub fn accepting_dev_certs(mut self) -> Self {
        self.danger_accept_invalid_host_certs = true;
        self
    }
}

/// Per-page Web Storage backing shared across evals. The se-serve tab owns
/// the Arc; an eval's [`State`] clones it, so a script's `setItem` lands in
/// the same map the next eval — and `session_reset` — sees. One map per
/// storage area per page: origin namespacing is the tab's job if it ever
/// holds multiple origins.
#[derive(Clone, Default)]
pub struct Storage {
    inner: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, String>>>,
}

impl Storage {
    pub fn get(&self, key: &str) -> Option<String> {
        self.inner.lock().expect("storage lock").get(key).cloned()
    }
    pub fn set(&self, key: String, value: String) {
        self.inner.lock().expect("storage lock").insert(key, value);
    }
    pub fn remove(&self, key: &str) {
        self.inner.lock().expect("storage lock").remove(key);
    }
    pub fn clear(&self) {
        self.inner.lock().expect("storage lock").clear();
    }
    pub fn len(&self) -> usize {
        self.inner.lock().expect("storage lock").len()
    }
    /// `key(i)` — the Web Storage enumeration accessor. The spec leaves
    /// enumeration order implementation-defined, so HashMap's arbitrary
    /// order is compliant; callers that need order use keys they set.
    pub fn key(&self, index: usize) -> Option<String> {
        self.inner
            .lock()
            .expect("storage lock")
            .keys()
            .nth(index)
            .cloned()
    }

    /// Every entry as `(name, value)` pairs sorted by name — the
    /// `storage_state_get` export shape; sorting makes the wire artifact
    /// deterministic where the HashMap's order is not.
    pub fn entries(&self) -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = self
            .inner
            .lock()
            .expect("storage lock")
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        v.sort();
        v
    }
}

/// `window.name`: one string cell per browsing context. The se-serve tab
/// owns the Arc and hands it to every eval on that tab (via [`Page`]), so a
/// script's `window.name = "x"` survives across evals AND navigations — the
/// browsing-context name is not origin-scoped, not storage, and trackers
/// legitimately read it for session correlation. (Named `WindowName`, not
/// `Name`, to keep clear of the `v8::Name` import.)
#[derive(Clone, Default)]
pub struct WindowName {
    inner: std::sync::Arc<std::sync::Mutex<String>>,
}

impl WindowName {
    pub fn get(&self) -> String {
        self.inner.lock().expect("name lock").clone()
    }
    pub fn set(&self, value: String) {
        *self.inner.lock().expect("name lock") = value;
    }
    pub fn clear(&self) {
        *self.inner.lock().expect("name lock") = String::new();
    }
}

/// One scheduled timer. `Global<Function>` because the callback must outlive
/// the script run that scheduled it — the pump fires it from `settle`.
struct Timer {
    id: u32,
    deadline: Instant,
    /// `Some(ms)` for setInterval: refired every ms until cleared.
    interval_ms: Option<u64>,
    /// `requestAnimationFrame` entry: fires once with a DOMHighResTimeStamp
    /// argument (like a display vsync callback), not a plain timer.
    raf: bool,
    callback: v8::Global<Function>,
}

/// One queued observer notification (IntersectionObserver / ResizeObserver).
/// `observe()` pushes an entry and schedules a single pump-drained flush; the
/// flush groups by observer id and invokes each stored callback once with all
/// its targets' entries.
struct ObserverNotification {
    /// The observer instance's id (its JS object carries `_obsId`) —
    /// disconnect/unobserve filter on this, never object identity.
    observer_id: u32,
    /// 0 = IntersectionObserver, 1 = ResizeObserver.
    kind: u8,
    callback: v8::Global<Function>,
    observer: v8::Global<Value>,
    target: v8::Global<Value>,
    /// Element-wrapper index of `target` (`u32::MAX` when the target is not a
    /// bridge element) — lets `unobserve(target)` match without comparing JS
    /// object identity.
    target_index: u32,
}

/// One live MutationObserver registration (firing 24). Unlike IO/RO — whose
/// `observe()` queues a single synthetic notification — an MO registration
/// is a standing filter: every DOM mutation choke point re-evaluates it and
/// queues a record for the matches.
#[derive(Clone)]
struct MutationTarget {
    observer_id: u32,
    /// Observed element-wrapper index, or `u32::MAX` for a document-level
    /// observation (`observe(document, …)`) which matches any mutation.
    target_index: u32,
    child_list: bool,
    attributes: bool,
    character_data: bool,
    /// `subtree: true` also matches mutations at any descendant of the
    /// observed node (ancestor check over the live doc).
    subtree: bool,
    /// `attributeOldValue` / `characterDataOldValue` — records carry the
    /// pre-mutation value only for observers that asked for it.
    attr_old_value: bool,
    character_old_value: bool,
    callback: v8::Global<Function>,
    observer: v8::Global<Value>,
}

/// Mutation record kinds: 0 = childList, 1 = attributes, 2 = characterData.
const MUT_CHILD_LIST: u8 = 0;
const MUT_ATTRIBUTES: u8 = 1;
const MUT_CHARACTER_DATA: u8 = 2;

/// One pending mutation record, queued per (observer, mutation) pair by the
/// choke points and drained by the observer flush — one callback invocation
/// per observer with all its records in a single array (spec delivery shape,
/// same grouping the IO/RO flush uses).
struct MutationRecord {
    observer_id: u32,
    kind: u8,
    /// The mutation target, resolved AT RECORD TIME and re-wrapped at
    /// delivery. Resolving eagerly — not indexing `State.elements` at flush
    /// time — matters for childList-on-remove: the spec target is the
    /// PARENT, which may have no resident wrapper at all (e.g. removing an
    /// `<li>` from a `<ul>` never queried into being).
    target: ElementData,
    attribute_name: Option<String>,
    old_value: Option<String>,
    /// The actual node objects for childList records (Globals so they can
    /// wait in the queue across the pump): appended/moved nodes, then
    /// removed nodes — the same object the script passed, like a real
    /// browser's addedNodes/removedNodes identity. Empty when the choke
    /// point can't name them (an innerHTML wholesale replace — the bridge
    /// re-parses the subtree and doesn't diff nodes).
    added: Vec<v8::Global<Value>>,
    removed: Vec<v8::Global<Value>>,
}

/// Escape text for HTML text-node serialization (`textContent` semantics —
/// markup must NOT be re-parsed as tags when the value rides a graft).
fn escape_text_node(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Default wall-clock ceiling on one eval's macrotask pump. A page that
/// schedules an uncleared interval would otherwise pump forever; the tracked
/// promise is expected to settle long before this trips. Callers that need
/// a different ceiling (se-serve's `settle_ms`) pass an explicit budget to
/// `settle`; this stays the default for plain evals.
pub const TIMER_BUDGET: Duration = Duration::from_secs(5);

/// The UA string this engine presents. It is what
/// `SidecarClient.user_agent()` reads back via eval, and clearance cookies
/// bind to it, so it must be stable for the process lifetime.
pub const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36";

/// Snapshot of one matched element. Exact while the DOM is static per eval;
/// see module docs.
#[derive(Clone)]
struct ElementData {
    tag: String,
    text: String,
    html: String,
    attrs: Vec<(String, String)>,
    /// Identity inside `State.doc`'s cached parse, for lazy ancestor
    /// resolution (`parentElement`). `None` for snapshots taken from a
    /// throwaway fragment parse (element-scope `querySelector`), whose ids
    /// would dangle against the document parse.
    node_id: Option<se_dom::NodeId>,
}

impl ElementData {
    fn from_node(n: &Node) -> Self {
        Self {
            tag: n.tag(),
            text: n.text(),
            html: n.html(),
            attrs: n.attrs(),
            node_id: Some(n.id()),
        }
    }

    fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Serialize as an HTML element (`<tag attrs>html</tag>`) so an
    /// appended child can be re-parsed and grafted into the live tree.
    /// `override_inner` is the `_seHtml` stash a synthetic wrapper's
    /// innerHTML setter wrote (its `html` snapshot is empty); it wins over
    /// the stored subtree. Attribute values are escaped for the
    /// double-quoted form; the inner `html` is already markup. Void elements
    /// serialize without a close tag.
    fn to_outer_html_with(&self, override_inner: Option<&str>) -> String {
        const VOID: &[&str] = &[
            "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
            "param", "source", "track", "wbr",
        ];
        let mut s = format!("<{}", self.tag);
        for (k, v) in &self.attrs {
            let esc = v.replace('&', "&amp;").replace('"', "&quot;");
            s.push_str(&format!(" {}=\"{}\"", k, esc));
        }
        s.push('>');
        if VOID.contains(&self.tag.as_str()) {
            return s;
        }
        s.push_str(override_inner.unwrap_or(&self.html));
        s.push_str(&format!("</{}>", self.tag));
        s
    }

    fn to_outer_html(&self) -> String {
        self.to_outer_html_with(None)
    }
}

/// Host state shared by every bridge callback for one eval. Allocated on the
/// Rust heap per eval and reachable from callbacks through the `External`
/// hung on each function template's `.data()`.
pub struct State {
    html: String,
    page_url: String,
    page_referrer: String,
    doc: Option<Document>,
    elements: Vec<ElementData>,
    el_template: Option<v8::Global<ObjectTemplate>>,
    resolved: Option<String>,
    rejected: Option<String>,
    /// Set by `__seThrow` when the eval wrapper's catch intercepts a sync
    /// throw. Read (and taken) by `Runtime::eval_with_page` after
    /// `script.run`, so a sync throw surfaces as `Error::Threw` with the
    /// exception's message — the same text a promise rejection carries.
    thrown: Option<String>,
    text_template: Option<v8::Global<FunctionTemplate>>,
    /// Bodies the page-context `fetch` resolved, keyed by index. The `text()`
    /// callback carries no per-response capture (v8 callbacks can't), so it
    /// reads `this._body_index` off the response object and takes the matching
    /// entry. Per-`State`, so concurrent fetches in one eval can't cross —
    /// and concurrent *evals* (separate isolates) never share a `State`.
    response_bodies: Vec<String>,
    /// Macrotask queue for the timer shims. Callbacks scheduled mid-script
    /// fire from `settle`'s pump, after the script task ends.
    timers: Vec<Timer>,
    next_timer_id: u32,
    /// Timer ids cancelled while their callback was in flight (a callback
    /// can't see itself in `timers` — it was drained to fire).
    cancelled: std::collections::HashSet<u32>,
    local_storage: Storage,
    session_storage: Storage,
    /// `window.name` cell shared with the owning tab (see [`Page::window_name`]).
    window_name: WindowName,
    /// The session jar this page presents on page-context requests. `None`
    /// (standalone/tests) means cookie-less bare HTTP, the original tier
    /// behavior. The jar's domain/path rules scope what a request may
    /// carry, so wiring the session jar in cannot leak cookies cross-origin.
    cookie_store: Option<std::sync::Arc<se_net::SessionStore>>,
    /// Session network log (firing 32): page-context fetch/XHR hops append
    /// here when wired in — the same opt-in pattern as `cookie_store`, so
    /// standalone evals record nothing.
    net_log: Option<std::sync::Arc<se_net::NetLog>>,
    /// When this eval started — `performance.now()` counts from here.
    started: Instant,
    /// `performance.timeOrigin`: `started` as epoch milliseconds.
    started_epoch_ms: f64,
    /// Mirrors `Page::danger_accept_invalid_host_certs` — see there.
    danger_accept_invalid_host_certs: bool,
    /// Queued IntersectionObserver/ResizeObserver notifications, drained by a
    /// single pump-scheduled flush.
    observer_queue: Vec<ObserverNotification>,
    /// Whether the observer-flush timer is already pending (avoids scheduling
    /// one per observe() call).
    observer_flush_scheduled: bool,
    /// Per-eval observer instance ids (`next_observer_id`).
    next_observer_id: u32,
    /// The hidden `__seFlushObservers` host function, stashed at finalize so
    /// observe() can schedule it onto the timer queue.
    observer_flush_fn: Option<v8::Global<Function>>,
    /// Session history for the SPA tier: the URL stack history.pushState/
    /// back() navigate within (no document load happens at eval time — a
    /// session entry just rewrites location and fires popstate). Starts as
    /// the one current URL, like a freshly loaded tab.
    history_stack: Vec<String>,
    /// Position within `history_stack` (what back()/forward() move).
    history_pos: usize,
    /// Per-entry states passed to pushState/replaceState (`history.state`).
    /// `None` entries report null.
    history_states: Vec<Option<v8::Global<Value>>>,
    /// DOM event listeners registered through addEventListener. dispatchEvent
    /// invokes them synchronously; capture listeners on window fire before the
    /// target's own listeners, non-capture after (the two endpoint phases of a
    /// real propagation — no intermediate bubble walk, the bridge DOM is
    /// read-only).
    listeners: Vec<ListenerEntry>,
    /// Set when `mutate()` succeeds — this eval mutated the document.
    /// `Runtime::eval_with_page` reads it after the script (and its settled
    /// promises / pumped timers) has run to publish the mutated serialization
    /// into the page's writeback slot; the tab owner adopts it post-eval, so
    /// mutations persist across evals instead of dying with the eval's State.
    mutated: bool,
    /// Live MutationObserver registrations and their pending records
    /// (firing 24). Registrations are standing filters evaluated at every
    /// mutation choke point; matched records wait here for the same
    /// pump-drained flush that delivers IO/RO notifications.
    mutation_targets: Vec<MutationTarget>,
    mutation_records: Vec<MutationRecord>,
    /// The original `Function.prototype.toString` intrinsic and the JS
    /// trampoline masks, rooted by finalize_context (firing 25/26, M4) before
    /// the intrinsic is swapped for the dispatching host function: a masked
    /// function answers toString with its native string, every other
    /// function falls through to the original. Each mask carries the name
    /// its native string reports.
    fp_tostring_orig: Option<v8::Global<v8::Function>>,
    fp_masks: Vec<(v8::Global<v8::Object>, String)>,
    /// The hidden `__seIdbError(request, err)` dispatch function, rooted at
    /// finalize time so async IDB request-error delivery can reach it from
    /// make_idb_request (a callback with no direct path to the global's
    /// hidden slot without a context global lookup each call).
    idb_error_fn: Option<v8::Global<v8::Object>>,
}

/// One addEventListener registration (the SPA-tier event system).
struct ListenerEntry {
    /// 0 = window, 1 = document, 2 = element (via `element_index`).
    target_kind: u8,
    /// Element index when `target_kind == 2`; meaningless otherwise.
    element_index: u32,
    type_: String,
    callback: v8::Global<Function>,
    capture: bool,
}

impl State {
    pub fn new(page: Option<&Page>) -> Self {
        let (html, page_url, page_referrer, local_storage, session_storage, window_name, cookie_store, net_log, danger) =
            match page {
                Some(p) => (
                    p.html.clone(),
                    p.url.clone(),
                    p.referrer.clone(),
                    p.local_storage.clone(),
                    p.session_storage.clone(),
                    p.window_name.clone(),
                    p.cookie_store.clone(),
                    p.net_log.clone(),
                    p.danger_accept_invalid_host_certs,
                ),
                None => (
                    String::new(),
                    String::new(),
                    String::new(),
                    Storage::default(),
                    Storage::default(),
                    WindowName::default(),
                    None,
                    None,
                    false,
                ),
            };
        let initial_history = vec![page_url.clone()];
        Self {
            html,
            page_url,
            page_referrer,
            doc: None,
            elements: Vec::new(),
            el_template: None,
            resolved: None,
            rejected: None,
            thrown: None,
            text_template: None,
            response_bodies: Vec::new(),
            timers: Vec::new(),
            next_timer_id: 1,
            cancelled: std::collections::HashSet::new(),
            local_storage,
            session_storage,
            window_name,
            cookie_store,
            net_log,
            started: Instant::now(),
            started_epoch_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as f64)
                .unwrap_or(0.0),
            danger_accept_invalid_host_certs: danger,
            observer_queue: Vec::new(),
            observer_flush_scheduled: false,
            next_observer_id: 1,
            observer_flush_fn: None,
            history_stack: initial_history,
            history_pos: 0,
            history_states: vec![None],
            listeners: Vec::new(),
            mutated: false,
            mutation_targets: Vec::new(),
            mutation_records: Vec::new(),
            fp_tostring_orig: None,
            fp_masks: Vec::new(),
            idb_error_fn: None,
        }
    }

    fn doc(&mut self) -> &Document {
        if self.doc.is_none() {
            self.doc = Some(Document::parse(&self.html));
        }
        self.doc.as_ref().expect("just set")
    }

    fn push(&mut self, data: ElementData) -> usize {
        self.elements.push(data);
        self.elements.len() - 1
    }

    /// Apply a DOM mutation to the cached parse and invalidate it, so the
    /// next `querySelector` re-parses from the mutated serialization. This
    /// is what makes `innerHTML = ...` followed by `querySelector(...)` see
    /// the new node within one eval: the mutation lands in the ego-tree,
    /// `doc` is dropped, and `self.html` is refreshed from the mutated tree
    /// so the reparse reflects it.
    ///
    /// Returns false when the target's node id does not resolve (a
    /// fragment-scoped or synthetic wrapper — off-document, so the mutation
    /// is a silent no-op like a real detached node).
    fn mutate(&mut self, idx: usize, f: impl FnOnce(&mut Document, se_dom::NodeId) -> bool) -> bool {
        let id = match self.elements.get(idx).and_then(|e| e.node_id) {
            Some(id) => id,
            None => return false,
        };
        // Force the lazy parse up front so `doc` is the live tree.
        let mut doc = match self.doc.take() {
            Some(d) => d,
            None => Document::parse(&self.html),
        };
        if !f(&mut doc, id) {
            return false;
        }
        self.html = doc.html();
        self.doc = Some(doc);
        self.mutated = true;
        true
    }

    /// Queue a mutation record for every live MutationObserver whose
    /// registration matches (firing 24). Called by the mutation choke points
    /// AFTER a successful `mutate()`. Matching: the record kind must be one
    /// the observer asked for; the target must be the observed node (exact
    /// wrapper-index match — `None` when the target has no resident wrapper,
    /// e.g. a remove whose parent was never queried), or any descendant of
    /// the observed node when `subtree` is set (ancestor check over the live
    /// doc against `target.node_id`), or anything at all for a document-level
    /// observation (`u32::MAX` sentinel). `old_value` is carried only by
    /// observers that requested old-value reporting.
    fn record_mutation(
        &mut self,
        match_index: Option<usize>,
        target: ElementData,
        kind: u8,
        attribute_name: Option<String>,
        old_value: Option<String>,
        added: Vec<v8::Global<Value>>,
        removed: Vec<v8::Global<Value>>,
    ) {
        if self.mutation_targets.is_empty() {
            return;
        }
        // Snapshot the registrations: subtree matching borrows the live doc.
        let targets = self.mutation_targets.clone();
        for t in &targets {
            let kind_ok = match kind {
                MUT_CHILD_LIST => t.child_list,
                MUT_ATTRIBUTES => t.attributes,
                MUT_CHARACTER_DATA => t.character_data,
                _ => false,
            };
            if !kind_ok {
                continue;
            }
            let matched = if t.target_index == u32::MAX {
                true // document-level observation matches any mutation
            } else if match_index == Some(t.target_index as usize) {
                true
            } else if t.subtree {
                match (
                    target.node_id,
                    self.elements
                        .get(t.target_index as usize)
                        .and_then(|e| e.node_id),
                ) {
                    (Some(node), Some(ancestor)) => doc_contains(self.doc(), ancestor, node),
                    _ => false,
                }
            } else {
                false
            };
            if !matched {
                continue;
            }
            let wants_old = match kind {
                MUT_ATTRIBUTES => t.attr_old_value,
                MUT_CHARACTER_DATA => t.character_old_value,
                _ => false,
            };
            self.mutation_records.push(MutationRecord {
                observer_id: t.observer_id,
                kind,
                target: target.clone(),
                attribute_name: attribute_name.clone(),
                old_value: if wants_old { old_value.clone() } else { None },
                added: added.clone(),
                removed: removed.clone(),
            });
        }
    }

    /// Take a sync-throw message recorded by `__seThrow` (the eval wrapper's
    /// catch), if any. Called by `Runtime::eval_with_page` after
    /// `script.run` so a sync throw surfaces as `Error::Threw` with the
    /// exception's rendered message.
    pub fn take_thrown(&mut self) -> Option<String> {
        self.thrown.take()
    }

    /// The page's URL as the script environment sees it. Page-script
    /// navigation (location.href=/assign/replace, history moves) relocates
    /// this field without any network fetch (bridge.rs:3480 — inert state,
    /// never a dial), so the value read AFTER `settle` is where a real
    /// browser would have navigated: se-serve's render follow reads it
    /// post-pump, because a setTimeout-scheduled navigation only lands once
    /// the timers have run.
    pub fn page_url(&self) -> &str {
        &self.page_url
    }

    /// Publish this eval's DOM mutation into the page's writeback slot —
    /// called by `Runtime::eval_with_page` after the script (and its settled
    /// promises / pumped timers) has run, on every post-compile outcome: a
    /// real tab keeps mutations a script made before throwing. The writeback
    /// is tagged with the document the eval started from so a racing
    /// navigation is never overwritten by a stale mutation.
    pub fn flush_writeback(&self, page: &Page) {
        if !self.mutated {
            return;
        }
        let mut slot = page.writeback.lock().expect("writeback lock");
        *slot = Some(MutationWriteback {
            from: page.html.clone(),
            html: self.html.clone(),        });
    }

    /// Refresh `elements[idx]` from the live tree after a mutation that may
    /// have changed its subtree. `sel` is a document-level selector matching
    /// exactly this element (its `#id`). Re-selecting — not re-resolving the
    /// old node id, which the mutation invalidated — keeps the wrapper's
    /// snapshot in sync with the mutated tree so the accessor getters read
    /// fresh data.
    fn resnapshot_after_mutate(&mut self, idx: usize, sel: &str) {
        let node = self.doc().select_one(sel).ok().flatten();
        if let Some(n) = node {
            self.elements[idx] = ElementData::from_node(&n);
        }
    }

    /// A `#id` selector for this element, when it has an id (used to
    /// re-select it after a mutation). None when id-less.
    fn id_selector(&self, idx: usize) -> Option<String> {
        let id = self.elements.get(idx)?.attr("id")?;
        if id.is_empty() {
            return None;
        }
        Some(format!("#{}", id.replace('\\', "\\\\").replace('"', "\\\"")))
    }
}

/// What [`settle`] found in the completion value.
pub enum Settled {
    /// Not a promise — stringify the value itself.
    Value,
    /// Top-level promise resolved; the JSON payload of its value.
    Resolved(String),
    /// Top-level promise rejected; the stringified reason.
    Rejected(String),
}

// ── scope plumbing ───────────────────────────────────────────────────────────

/// A context-carrying scope derefs to the context-less variant; make that
/// hop explicit so call sites don't depend on coercion chains.
fn nullscope<'a, 's, 'i>(scope: &'a PinScope<'s, 'i>) -> &'a PinScope<'s, 'i, ()> {
    scope
}

fn sv<'s, 'i>(scope: &PinScope<'s, 'i>, v: &str) -> Local<'s, Value> {
    v8::String::new(nullscope(scope), v).expect("string alloc").into()
}

fn nullv<'s, 'i>(scope: &PinScope<'s, 'i>) -> Local<'s, Value> {
    v8::null(scope).into()
}

fn arg_string<'s, 'i>(
    scope: &PinScope<'s, 'i>,
    args: &FunctionCallbackArguments<'_>,
    i: usize,
) -> Option<String> {
    let v = args.get(i as i32);
    if v.is_undefined() || v.is_null() {
        return None;
    }
    v.to_string(scope).map(|s| s.to_rust_string_lossy(scope))
}

/// The host state every template's `.data()` carries.
///
/// Safety contract: the `External` pointer must reference a live `State`
/// box for the whole eval, and callbacks run on the isolate thread only.
/// Both hold by construction in `Runtime::eval_with_page`.
unsafe fn state_of<'a, 'b>(args: &'a FunctionCallbackArguments<'b>) -> &'a mut State {
    let ext = args.data().cast::<External>();
    &mut *(ext.value() as *mut State)
}

/// `this` is an element wrapper iff it carries an internal field (the
/// element index). `document` and the global object have none.
fn this_element_index<'s, 'i>(
    scope: &PinScope<'s, 'i>,
    args: &FunctionCallbackArguments<'_>,
) -> Option<usize> {
    let this = args.this();
    if this.internal_field_count() == 0 {
        return None;
    }
    let field = this.get_internal_field(scope, 0)?;
    Some(field.cast::<v8::Number>().value() as usize)
}

/// Element-wrapper index carried by an arbitrary value's internal field 0
/// (`u32::MAX` when it isn't a bridge element). IntersectionObserver targets
/// are always elements; the index lets `unobserve(target)` match without
/// comparing JS object identity.
fn value_element_index<'s, 'i>(scope: &PinScope<'s, 'i>, v: Local<'_, Value>) -> u32 {
    if !v.is_object() {
        return u32::MAX;
    }
    let o = v.cast::<Object>();
    if o.internal_field_count() == 0 {
        return u32::MAX;
    }
    o.get_internal_field(scope, 0)
        .map(|f| f.cast::<v8::Number>().value() as u32)
        .unwrap_or(u32::MAX)
}

/// Ancestor-or-self check over the live doc: is `ancestor` on the parent
/// chain of `node`? Backs MutationObserver `subtree` matching. Ids that
/// don't resolve (a stale snapshot) simply don't match.
fn doc_contains(doc: &Document, ancestor: se_dom::NodeId, node: se_dom::NodeId) -> bool {
    let mut cur = doc.node(node);
    while let Some(n) = cur {
        if n.id() == ancestor {
            return true;
        }
        cur = n.parent_element();
    }
    false
}

/// Resolve `raw` against the page URL. Absolute URLs pass through; relative
/// ones anchor at the page (RFC 3986 §5), so a page fetched from a loopback
/// test server can `fetch("/api")` without hardcoding a host.
fn absolutize(raw: &str, page_url: &str) -> String {
    match url::Url::parse(raw) {
        Ok(u) => u.to_string(),
        Err(_) => match url::Url::parse(page_url) {
            Ok(base) => base.join(raw).map(|u| u.to_string()).unwrap_or_else(|_| raw.to_string()),
            Err(_) => raw.to_string(),
        },
    }
}

/// The `scheme://host[:port]` prefix, for same-origin checks. `Url::port`
/// reports None for default ports (80/443 — the URL crate normalizes them
/// away), so both sides compare equal whether or not the default was
/// spelled out.
fn origin_of(u: &url::Url) -> String {
    let scheme = u.scheme();
    match (u.host_str(), u.port()) {
        (Some(h), Some(p)) => format!("{scheme}://{h}:{p}"),
        (Some(h), None) => format!("{scheme}://{h}"),
        _ => String::new(),
    }
}

/// The `location` string decomposition. Parsed with `url::Url` so query and
/// fragment never bleed into each other (the old hand-rolled split put
/// `#frag` into `search`). Unparseable URLs (never at about:blank — that
/// parses — but for garbage) report href only, everything else empty.
struct LocationParts {
    href: String,
    protocol: String,
    host: String,
    hostname: String,
    port: String,
    pathname: String,
    search: String,
    hash: String,
    origin: String,
}

impl LocationParts {
    fn parse(url: &str) -> Self {
        match url::Url::parse(url) {
            Ok(u) => {
                let host = match u.host_str() {
                    Some(h) => match u.port() {
                        Some(p) => format!("{h}:{p}"),
                        None => h.to_string(),
                    },
                    None => String::new(),
                };
                let hostname = u.host_str().unwrap_or("").to_string();
                Self {
                    href: url.to_string(),
                    protocol: format!("{}:", u.scheme()),
                    host,
                    hostname,
                    port: u.port().map(|p| p.to_string()).unwrap_or_default(),
                    pathname: u.path().to_string(),
                    search: match u.query() {
                        Some(q) => format!("?{q}"),
                        None => String::new(),
                    },
                    hash: match u.fragment() {
                        Some(f) => format!("#{f}"),
                        None => String::new(),
                    },
                    origin: u.origin().ascii_serialization(),
                }
            }
            Err(_) => Self {
                href: url.to_string(),
                protocol: String::new(),
                host: String::new(),
                hostname: String::new(),
                port: String::new(),
                pathname: String::new(),
                search: String::new(),
                hash: String::new(),
                origin: String::new(),
            },
        }
    }
}

/// Serialize `s` (including lone surrogates) to UTF-8 lossily, the way the
/// eventual `TextDecoder` tier will do it.
fn js_string<'s, 'i>(scope: &mut PinScope<'s, 'i>, s: &str) -> Local<'s, Value> {
    v8::String::new_from_one_byte(scope, s.as_bytes(), v8::NewStringType::Normal)
        .expect("string alloc")
        .into()
}

/// Read a `Local<Object>`'s string property, if present.
fn obj_str<'s, 'i>(
    scope: &PinScope<'s, 'i>,
    obj: Local<'_, Object>,
    key: &str,
) -> Option<String> {
    let v = obj.get(scope, sv(scope, key))?;
    v.to_string(scope).map(|s| s.to_rust_string_lossy(scope))
}

/// Numeric property read, for the `_body_index` marker `text()` uses to find
/// its body in the per-`State` registry.
fn obj_num<'s, 'i>(scope: &PinScope<'s, 'i>, obj: Local<'_, Object>, key: &str) -> Option<f64> {
    let v = obj.get(scope, sv(scope, key))?;
    v.to_number(scope).map(|n| n.value())
}

/// Pump the microtask queue while `blocking_fetch` waits on the network.
/// Runs queued continuations (the `await fetch()` chain) between wait ticks.
/// Microtasks only run at scope checkpoints in v8, so checkpointing the
/// current context's scope is the correct pump.
fn pump_microtasks<'s, 'i>(scope: &mut PinScope<'s, 'i>) {
    scope.perform_microtask_checkpoint();
}

/// A page-context request's particulars — what `fetch(url, init)` and
/// `XMLHttpRequest` carry beyond the URL. Defaults match the GET idiom the
/// bridge has served since the fetch shim landed.
#[derive(Default)]
struct FetchSpec {
    /// Uppercased method; GET when the caller passed none.
    method: String,
    /// Caller headers (fetch `init.headers`, XHR `setRequestHeader`). Same
    /// name (case-insensitive) replaces the subresource default; a new name
    /// appends, exactly as a real request's header list merges.
    headers: Vec<(String, String)>,
    /// Serialized request body. Empty for GET/HEAD regardless of what the
    /// caller passed — that is the fetch spec's behavior too.
    body: String,
}

impl FetchSpec {
    fn get() -> Self {
        Self {
            method: "GET".to_string(),
            ..Self::default()
        }
    }
}

/// Send the page-context request and drive microtasks until the response lands.
///
/// Blocking from inside a V8 callback is safe here: the bridge runs nothing
/// else on the isolate thread concurrently (one eval, one outstanding fetch).
/// `pump` runs queued microtasks between wait ticks so the `await fetch()`
/// chain progresses even though the isolate thread is parked here.
///
/// The request itself runs on a spawned thread, not in the callback: driving
/// a tokio runtime from inside a V8 callback deadlocked on this platform.
/// `http://` hops use the raw blocking HTTP/1.1 writer (loopback fixtures
/// are h1.1); `https://` hops go through se-net's one-shot subresource
/// client, which negotiates ALPN like a real browser — h2 when the origin
/// offers it, h1.1 when it declines — and reports the negotiated version
/// honestly. Redirects (301/302/303/307/308, Location resolved against the
/// request URL, fetch-spec rewrite rules, cap 20) are followed in the same
/// loop for both arms; the result crosses back over an mpsc channel; `pump`
/// after `recv` drains the microtask queue the resolution enqueued.

/// Resolve `host:port` for the shim's raw-TCP branch and vet every answer
/// against the refused address classes (bug 28): ANY refused answer poisons
/// the whole set — a legit name never answers link-local, so one poisoned
/// record is the DNS-rebinding shape and the dial is refused with the
/// contractual token. The caller dials exactly the returned addresses, so a
/// flipped second resolution (TOCTOU) never reaches the wire. The https arm
/// gets the same property from se-net's `GuardedResolver` (bug 27); this is
/// the raw branch's mirror of it.
fn resolve_checked(host: &str, port: u16) -> Result<Vec<std::net::SocketAddr>, String> {
    use std::net::ToSocketAddrs;
    let addrs: Vec<std::net::SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve {host}: {e}"))?
        .collect();
    vet_addrs(host, addrs)
}

/// The vetting half of `resolve_checked`, separated so tests can script the
/// answer set without a DNS dependency.
fn vet_addrs(
    host: &str,
    addrs: Vec<std::net::SocketAddr>,
) -> Result<Vec<std::net::SocketAddr>, String> {
    for addr in &addrs {
        if let Some(why) = se_net::refused_ip(addr.ip()) {
            return Err(format!("target_refused: dns:{host} -> {why}"));
        }
    }
    Ok(addrs)
}

/// Iteration 23: the fetch shim's raw arm reads the wire itself, and the
/// honest-read rules are the same ones the ladder/se-net tiers enforce —
/// bounded head, bounded body (mirroring se-net's subresource cap),
/// framing decoded (chunked), encodings it can't decode refused, and
/// truncation refused rather than served. The body cap and refusal tokens
/// (`too_large:` / `truncated:` / `unsupported_content_encoding:` /
/// `unsupported_transfer_encoding:`) ride the fetch rejection.
const MAX_FETCH_HEAD_BYTES: usize = 64 * 1024;

/// Read the response head through its blank line, bounded. Returns the head
/// bytes and the overhang — body bytes that arrived in the same read()s (a
/// single segment can span the boundary, and dropping it would desync the
/// body readers).
fn read_fetch_head(stream: &mut std::net::TcpStream) -> Result<(Vec<u8>, Vec<u8>), String> {
    use std::io::Read;
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            if i + 4 > MAX_FETCH_HEAD_BYTES {
                return Err(format!(
                    "too_large: response head over {MAX_FETCH_HEAD_BYTES} bytes"
                ));
            }
            let overhang = buf.split_off(i + 4);
            return Ok((buf, overhang));
        }
        if buf.len() > MAX_FETCH_HEAD_BYTES {
            return Err(format!(
                "too_large: response head over {MAX_FETCH_HEAD_BYTES} bytes"
            ));
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Err("truncated: response head closed before the blank line".into()),
            Ok(m) => buf.extend_from_slice(&chunk[..m]),
            Err(e) => return Err(format!("read: {e}")),
        }
    }
}

/// Parse a response head into (status, lowercased name/value headers).
fn parse_fetch_head(head: &[u8]) -> (u16, Vec<(String, String)>) {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.lines();
    let status: u16 = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mut headers = Vec::new();
    for line in lines {
        if let Some(colon) = line.find(':') {
            let name = line[..colon].trim().to_lowercase();
            let value = line[colon + 1..].trim().to_string();
            headers.push((name, value));
        }
    }
    (status, headers)
}

/// Read the response body per its framing: Transfer-Encoding: chunked
/// de-frames (the only transfer coding this shim speaks), Content-Length
/// reads exactly, anything else is close-delimited (the shim sends
/// Connection: close). All three paths are bounded at the subresource cap,
/// and a short read refuses `truncated:` rather than serving a prefix.
fn read_fetch_body(
    stream: &mut std::net::TcpStream,
    overhang: Vec<u8>,
    headers: &[(String, String)],
) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let cap = se_net::MAX_SUBRESOURCE_BYTES as usize;
    // RFC 9112 s6.1: Transfer-Encoding overrides Content-Length.
    if let Some((_, te)) = headers.iter().find(|(n, _)| n == "transfer-encoding") {
        if te.split(',').any(|c| !c.trim().eq_ignore_ascii_case("chunked")) {
            return Err(format!("unsupported_transfer_encoding:{}", te.trim()));
        }
        return read_fetch_chunked(stream, overhang, cap);
    }
    if let Some((_, cl)) = headers.iter().find(|(n, _)| n == "content-length") {
        let declared: u64 = cl
            .trim()
            .parse()
            .map_err(|_| format!("malformed content-length: {}", cl.trim()))?;
        if declared > cap as u64 {
            return Err(format!(
                "too_large: content-length {declared} over {cap} subresource cap"
            ));
        }
        let mut body = overhang;
        let mut chunk = [0u8; 8192];
        while (body.len() as u64) < declared {
            match stream.read(&mut chunk) {
                Ok(0) => {
                    return Err(format!(
                        "truncated: response body under content-length {declared}"
                    ))
                }
                Ok(m) => body.extend_from_slice(&chunk[..m]),
                Err(e) => return Err(format!("read: {e}")),
            }
        }
        // Anything past the declared length on the closing socket is junk.
        body.truncate(declared as usize);
        return Ok(body);
    }
    let mut body = overhang;
    let mut chunk = [0u8; 8192];
    loop {
        if body.len() > cap {
            return Err(format!("too_large: response body over {cap} subresource cap"));
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(body),
            Ok(m) => body.extend_from_slice(&chunk[..m]),
            Err(e) => return Err(format!("read: {e}")),
        }
    }
}

/// Chunked de-framing over the overhang+socket boundary: hex size lines
/// (extensions ignored), CRLF-terminated data, a terminal zero chunk, and a
/// bounded trailer drain. The DECODED total is what the cap measures.
fn read_fetch_chunked(
    stream: &mut std::net::TcpStream,
    overhang: Vec<u8>,
    cap: usize,
) -> Result<Vec<u8>, String> {
    use std::io::Read;
    /// Pulls from the overhang first, then the socket, so frame lines can
    /// span the head/body read boundary.
    struct Cursor<'a> {
        stream: &'a mut std::net::TcpStream,
        buf: Vec<u8>,
        pos: usize,
    }
    impl Cursor<'_> {
        fn take(&mut self, n: usize, out: &mut Vec<u8>) -> Result<(), String> {
            let mut need = n;
            while need > 0 {
                if self.pos == self.buf.len() {
                    self.buf.clear();
                    self.pos = 0;
                    let mut chunk = [0u8; 8192];
                    match self.stream.read(&mut chunk) {
                        Ok(0) => return Err("truncated: chunked body".into()),
                        Ok(m) => self.buf.extend_from_slice(&chunk[..m]),
                        Err(e) => return Err(format!("read: {e}")),
                    }
                }
                let n_take = need.min(self.buf.len() - self.pos);
                out.extend_from_slice(&self.buf[self.pos..self.pos + n_take]);
                self.pos += n_take;
                need -= n_take;
            }
            Ok(())
        }
        fn line(&mut self) -> Result<Vec<u8>, String> {
            let mut out = Vec::new();
            loop {
                if out.len() > 8192 {
                    return Err("malformed: chunk line over 8192 bytes".into());
                }
                let mut byte = Vec::with_capacity(1);
                self.take(1, &mut byte)?;
                if byte[0] == b'\n' {
                    if out.last() == Some(&b'\r') {
                        out.pop();
                    }
                    return Ok(out);
                }
                out.push(byte[0]);
            }
        }
    }
    let mut cur = Cursor {
        stream,
        buf: overhang,
        pos: 0,
    };
    let mut body = Vec::new();
    loop {
        let line = cur.line()?;
        let text = String::from_utf8_lossy(&line);
        let size_text = text.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| format!("malformed chunk size: {size_text}"))?;
        if size == 0 {
            // Trailer section: drained, bounded, ignored.
            let mut trailers = 0;
            loop {
                if cur.line()?.is_empty() {
                    break;
                }
                trailers += 1;
                if trailers > 64 {
                    return Err("malformed: chunk trailers over 64 lines".into());
                }
            }
            return Ok(body);
        }
        if body.len() + size > cap {
            return Err(format!(
                "too_large: chunked response body over {cap} subresource cap"
            ));
        }
        cur.take(size, &mut body)?;
        let mut crlf = Vec::with_capacity(2);
        cur.take(2, &mut crlf)?;
        if crlf != b"\r\n" {
            return Err("malformed chunk: data not CRLF-terminated".into());
        }
    }
}

fn blocking_fetch(
    st: &mut State,
    kind: &str,
    raw: &str,
    spec: &FetchSpec,
    pump: &mut dyn FnMut(),
) -> Result<se_net::Response, String> {
    let url = absolutize(raw, &st.page_url);
    // Subresource presentation: a real Chrome page fetch/XHR carries client
    // hints + Fetch Metadata — and NOT the navigation markers (Upgrade-
    // Insecure-Requests, Sec-Fetch-User: ?1) those stay document-only. The
    // edges that flat-400 a document request missing the navigation
    // signature (Facebook's anonymous tier) apply the same class of check
    // one tier down, so the page-context request presents the same bytes a
    // browser XHR would.
    let fetch_site = match url::Url::parse(&st.page_url) {
        Ok(page) => match url::Url::parse(&url) {
            Ok(u) if origin_of(&u) == origin_of(&page) => "same-origin",
            _ => "cross-site",
        },
        Err(_) => "cross-site",
    };
    let ua = USER_AGENT;
    let chua = se_net::sec_ch_ua();
    let chplatform = se_net::UA_PLATFORM;
    let cookie_store = st.cookie_store.clone();
    let net_log = st.net_log.clone();
    let kind = kind.to_string();
    // The subresource default set; caller headers merge over it below (same
    // name replaces, new name appends — the fetch spec's header merge).
    let mut headers: Vec<(String, String)> = vec![
        ("Connection".into(), "close".into()),
        ("sec-ch-ua".into(), chua.clone()),
        ("sec-ch-ua-mobile".into(), "?0".into()),
        ("sec-ch-ua-platform".into(), format!("\"{chplatform}\"")),
        ("Sec-Fetch-Dest".into(), "empty".into()),
        ("Sec-Fetch-Mode".into(), "cors".into()),
        ("Sec-Fetch-Site".into(), fetch_site.to_string()),
        ("User-Agent".into(), ua.to_string()),
        ("Accept".into(), "*/*".into()),
        ("Accept-Language".into(), "en-US,en;q=0.9".into()),
    ];
    // A body lands its length (and a default content type, the fetch spec's
    // string-body default) unless the caller set their own.
    let sends_body = !matches!(spec.method.as_str(), "GET" | "HEAD") || !spec.body.is_empty();
    if sends_body {
        headers.push(("Content-Type".into(), "text/plain;charset=UTF-8".into()));
        headers.push(("Content-Length".into(), spec.body.len().to_string()));
    }
    for (name, value) in &spec.headers {
        // Page-supplied names/values go on the wire verbatim except CR/LF,
        // which would smash the request shape — the sanitizer a real stack
        // applies is "refuse to send", but dropping the offending bytes
        // keeps the shim total for well-behaved pages and harmless for the
        // rest.
        let name = name.replace(['\r', '\n'], "");
        let value = value.replace(['\r', '\n'], "");
        if name.is_empty() {
            continue;
        }
        if let Some(slot) = headers
            .iter_mut()
            .find(|(n, _)| n.eq_ignore_ascii_case(&name))
        {
            slot.1 = value;
        } else {
            headers.push((name, value));
        }
    }
    let method = spec.method.clone();
    let body = spec.body.clone();
    let danger = st.danger_accept_invalid_host_certs;
    let (tx, rx) = std::sync::mpsc::channel::<Result<se_net::Response, String>>();
    std::thread::spawn(move || {
        use std::io::Write;
        use std::net::TcpStream;
        let result = (|| -> Result<se_net::Response, String> {
            // Redirect-following per the fetch spec: 301/302 rewrite POST to
            // GET (body dropped, entity headers stripped), 303 does the same
            // for any method, 307/308 preserve method+body. Location resolves
            // against the request URL, the jar feeds cookies hop by hop, and
            // the spec's default cap of 20 redirects bounds the loop.
            const MAX_REDIRECTS: u32 = 20;
            let mut redirects: u32 = 0;
            let mut current = url;
            let mut method = method;
            let mut body = body;
            let mut req_headers = headers;
            loop {
                let hop_started = std::time::Instant::now();
                // Bug 28: page-side fetch() is a full network surface -- a
                // script can aim it at a refused target directly or steer it
                // there through a redirect, and this shim's raw-TCP branch
                // carried NO guard (the https branch gets one from
                // se_net::subresource_fetch's entry check). Every hop passes
                // the same target policy the navigation client enforces
                // (bug 25) BEFORE any dial: non-http(s) schemes and
                // link-local/unspecified IP literals never connect.
                if let Some(why) = se_net::refused_target(&current) {
                    return Err(format!("target_refused: {why} ({current})"));
                }
                let u = url::Url::parse(&current).map_err(|e| format!("url parse: {e}"))?;
                // Present the session jar on this request when one is wired
                // in. The store's domain/path rules scope what matches,
                // exactly as they do for the navigation verbs' reqwest
                // client. Recomputed each hop: an earlier hop's Set-Cookie
                // rides to the next origin the way it does through a real
                // redirect cascade.
                let cookie_line = cookie_store
                    .as_ref()
                    .and_then(|s| s.cookie_header(&current));
                let (status, resp_headers, resp_body, resp_bytes, version) =
                    if u.scheme() == "https" {
                        // HTTPS presents the request through the ALPN
                        // stack: h2 when the origin offers it, h1.1 when it
                        // declines — the same fork a real browser takes.
                        let mut hop_headers = req_headers.clone();
                        if let Some(c) = &cookie_line {
                            hop_headers.push(("Cookie".into(), c.clone()));
                        }
                        let resp = se_net::subresource_fetch(
                            &current,
                            &method,
                            &hop_headers,
                            &body,
                            danger,
                        )
                        .map_err(|e| e.to_string())?;
                        let se_net::Response {
                            status,
                            headers,
                            body,
                            body_bytes,
                            version,
                            ..
                        } = resp;
                        // se-net already decoded the text slot per the
                        // charset rules (bug 22); the bytes slot carries
                        // the raw (decompressed) wire bytes.
                        (status, headers, body, body_bytes, version)
                    } else {
                        let host = u.host_str().ok_or("no host")?.to_string();
                        let port = u.port().unwrap_or(80);
                        // Bug 28, resolution leg: this branch dials raw TCP,
                        // OUTSIDE se-net's guarded resolver -- so it resolves
                        // here, vets every answer (ANY refused answer poisons
                        // the set, the rebinding shape), and dials exactly
                        // the checked addresses: a flipped second resolution
                        // (TOCTOU) never reaches the wire.
                        let addrs = resolve_checked(&host, port)?;
                        // Iteration 23: dial each checked address with a
                        // BOUNDED connect -- a SYN-blackhole answer
                        // otherwise parks this thread, and with it
                        // blocking_fetch's rx.recv() (the whole isolate),
                        // on the OS TCP timeout (~21s Windows, ~2m+
                        // Linux). The bug-24 lesson one tier down.
                        let mut stream = None;
                        let mut last_err = format!("connect: no addresses for {host}");
                        for addr in &addrs {
                            match TcpStream::connect_timeout(addr, std::time::Duration::from_secs(5))
                            {
                                Ok(s) => {
                                    stream = Some(s);
                                    break;
                                }
                                Err(e) => {
                                    last_err = if e.kind() == std::io::ErrorKind::TimedOut {
                                        format!("connect: timed out after 5s ({addr})")
                                    } else {
                                        format!("connect: {e}")
                                    };
                                }
                            }
                        }
                        let mut stream = match stream {
                            Some(s) => s,
                            None => return Err(last_err),
                        };
                        let _ =
                            stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                        let path = u.path();
                        // `Url::path` excludes the query — drop nothing:
                        // API-style fetches live in `?q=...`.
                        let path_q = match u.query() {
                            Some(q) => format!("{path}?{q}"),
                            None => path.to_string(),
                        };
                        // Header order follows Chrome's subresource
                        // signature: hints first, then Fetch Metadata, then
                        // UA/Accept, entity headers, Cookie last.
                        let mut head = String::new();
                        for (name, value) in &req_headers {
                            head.push_str(&format!("{name}: {value}\r\n"));
                        }
                        // Iteration 23: the raw arm cannot decode content
                        // codings, so it offers `identity` unless the page
                        // supplied its own (the https arm leaves the header
                        // to reqwest, which decodes gzip/br/zstd itself).
                        if !req_headers
                            .iter()
                            .any(|(n, _)| n.eq_ignore_ascii_case("accept-encoding"))
                        {
                            head.push_str("Accept-Encoding: identity\r\n");
                        }
                        let cookie = cookie_line
                            .map(|c| format!("Cookie: {c}\r\n"))
                            .unwrap_or_default();
                        let req = format!(
                            "{method} {path_q} HTTP/1.1\r\nHost: {host}:{port}\r\n{head}{cookie}\r\n{body}"
                        );
                        stream
                            .write_all(req.as_bytes())
                            .map_err(|e| format!("write: {e}"))?;
                        // Iteration 23: bounded, frame-aware reading (was
                        // read_to_string -- unbounded head+body, chunk
                        // frames served as text, a short body served as if
                        // whole, and invalid-UTF-8 failing by accident).
                        let (head_bytes, overhang) = read_fetch_head(&mut stream)?;
                        let (status, resp_headers) = parse_fetch_head(&head_bytes);
                        // The raw arm offered `identity` (or the page
                        // offered something this arm can't decode either):
                        // a coded body refuses honestly instead of landing
                        // in text() as garbage -- the iteration-15 lesson
                        // one tier down. (The https arm decodes inside
                        // se-net, so it needs no such check.)
                        if let Some((_, ce)) =
                            resp_headers.iter().find(|(n, _)| n == "content-encoding")
                        {
                            let ce = ce.trim();
                            if !ce.eq_ignore_ascii_case("identity") {
                                return Err(format!("unsupported_content_encoding:{ce}"));
                            }
                        }
                        let body_bytes = read_fetch_body(&mut stream, overhang, &resp_headers)?;
                        // The text slot lossy-decodes the wire bytes, the
                        // same fallback se-net's decode_body uses at the
                        // document tier; the bytes slot stays raw.
                        let resp_body = String::from_utf8_lossy(&body_bytes).into_owned();
                        (status, resp_headers, resp_body, body_bytes, "HTTP/1.1".to_string())
                    };
                // A document request feeds response cookies back to the jar,
                // same as the navigation client does.
                if let Some(store) = &cookie_store {
                    for (name, value) in &resp_headers {
                        if name == "set-cookie" {
                            store.store_set_cookie(value, &current);
                        }
                    }
                }
                // One log entry per completed hop — a redirect chain logs each
                // hop with its own url/method/status, the devtools shape.
                // Best-effort: observability must never fail the fetch.
                if let Some(log) = &net_log {
                    log.record(
                        &kind,
                        &method,
                        &current,
                        status,
                        hop_started.elapsed(),
                    );
                }
                let redirect_to = match status {
                    301 | 302 | 303 | 307 | 308 => resp_headers
                        .iter()
                        .find(|(n, _)| n == "location")
                        .map(|(_, v)| v.clone()),
                    _ => None,
                };
                if let Some(loc) = redirect_to {
                    redirects += 1;
                    if redirects > MAX_REDIRECTS {
                        return Err("fetch: too many redirects".into());
                    }
                    let next = url::Url::parse(&current)
                        .and_then(|base| base.join(&loc))
                        .map_err(|e| format!("redirect parse: {e}"))?;
                    let rewrite_to_get = status == 303
                        || (matches!(status, 301 | 302)
                            && !matches!(method.as_str(), "GET" | "HEAD"));
                    if rewrite_to_get {
                        method = "GET".into();
                        body.clear();
                        req_headers.retain(|(n, _)| {
                            !matches!(n.to_ascii_lowercase().as_str(), "content-length" | "content-type")
                        });
                    }
                    current = next.to_string();
                    continue;
                }
                return Ok(se_net::Response {
                    final_url: current,
                    status,
                    version,
                    headers: resp_headers,
                    // The bytes slot carries the raw wire bytes (de-framed,
                    // identity-coded); the text slot is the https arm's
                    // charset-decoded body or the raw arm's lossy decode
                    // of those bytes.
                    body_bytes: resp_bytes,
                    body: resp_body,
                });
            }
        })();
        let _ = tx.send(result);
    });
    let r = rx.recv().map_err(|e| format!("recv: {e}"))?.map_err(|e| e);
    pump();
    r
}

/// Set a value on `obj` with best-effort result checking.
fn set_prop<'s, 'i>(
    scope: &PinScope<'s, 'i>,
    obj: Local<'_, Object>,
    key: &str,
    v: Local<'_, Value>,
) {
    let _ = obj.set(scope, sv(scope, key), v);
}

fn ok_status(status: u16) -> bool {
    (200..300).contains(&status)
}

/// Build the response object handed to `fetch`'s resolver: status, url, a
/// Headers-like wrapper, and a `text()` that resolves with this response's
/// body. The body is pushed into the per-`State` registry and the response
/// records its index; `text()` reads `this._body_index` and takes it (v8
/// callbacks can't capture, so the body travels by index).
fn response_object<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: &FunctionCallbackArguments<'_>,
    resp: &se_net::Response,
) -> Local<'s, Object> {
    let obj = v8::Object::new(scope);
    set_prop(scope, obj, "status", v8::Number::new(scope, resp.status as f64).into());
    set_prop(scope, obj, "url", sv(scope, &resp.final_url));
    set_prop(scope, obj, "ok", v8::Boolean::new(scope, ok_status(resp.status)).into());

    let headers = v8::Object::new(scope);
    for (k, v) in &resp.headers {
        set_prop(scope, headers, k, sv(scope, v));
    }
    set_prop(scope, obj, "headers", headers.into());

    // Stash the body and point `text()` at it by index.
    let body_index = {
        let st = unsafe { state_of(args) };
        st.response_bodies.push(resp.body.clone());
        st.response_bodies.len() - 1
    };
    set_prop(
        scope,
        obj,
        "_body_index",
        v8::Number::new(scope, body_index as f64).into(),
    );
    let text_fn = {
        let st = unsafe { state_of(args) };
        st.text_template
            .as_ref()
            .and_then(|tpl| v8::Local::new(nullscope(scope), tpl).get_function(scope))
    };
    if let Some(f) = text_fn {
        set_prop(scope, obj, "text", f.into());
    }
    obj
}

/// Read the resolver out of a one-element `[resolve, reject]` array.
fn then_callbacks<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    arr: Local<'_, Value>,
) -> Option<(Local<'s, Function>, Local<'s, Function>)> {
    let arr = arr.cast::<v8::Array>();
    let resolve = arr.get_index(scope, 0)?.cast::<Function>();
    let reject = arr.get_index(scope, 1)?.cast::<Function>();
    Some((resolve, reject))
}

fn reject_with<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    reject: Local<'_, Function>,
    msg: &str,
) {
    let reason = js_string(scope, msg);
    let args = &[reason];
    let _ = reject.call(scope, v8::undefined(scope).into(), args);
}

fn cb_fetch<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let raw = arg_string(scope, &args, 0).unwrap_or_default();
    let resolver = v8::PromiseResolver::new(scope).expect("promise resolver");
    let promise = resolver.get_promise(scope);
    let Some((resolve_fn, reject_fn)) = arg_then_functions(scope, &args, 1) else {
        let reason = js_string(scope, "fetch: unsupported call shape");
        resolver.reject(scope, reason);
        rv.set(promise.into());
        return;
    };
    // Keep the callbacks alive across the blocking wait by rooting them.
    let resolve_root = v8::Global::new(scope, resolve_fn);
    let reject_root = v8::Global::new(scope, reject_fn);

    let state_ptr = unsafe { state_of(&args) } as *mut State;
    let raw = raw.clone();
    // init arrives pre-normalized by the fetch trampoline JS: method,
    // headers as a JSON [[name, value], ...] (Headers.forEach already
    // lowercased them), body stringified. Defaults: GET / no headers /
    // no body.
    let mut spec = FetchSpec::get();
    if let Some(method) = arg_string(scope, &args, 2) {
        if !method.is_empty() {
            spec.method = method.to_ascii_uppercase();
        }
    }
    if let Some(headers_json) = arg_string(scope, &args, 3) {
        if let Ok(pairs) = serde_json::from_str::<Vec<Vec<String>>>(&headers_json) {
            spec.headers = pairs
                .into_iter()
                .filter_map(|p| {
                    if p.len() == 2 {
                        Some((p[0].clone(), p[1].clone()))
                    } else {
                        None
                    }
                })
                .collect();
        }
    }
    if let Some(body) = arg_string(scope, &args, 4) {
        spec.body = body;
    }
    // The fetch spec: GET/HEAD never carry a body, whatever the caller passed.
    if matches!(spec.method.as_str(), "GET" | "HEAD") {
        spec.body.clear();
    }
    let mut pump = || pump_microtasks(scope);
    let result = {
        // Park the isolate thread on the fetch; re-borrow state per touch.
        let st = unsafe { &mut *state_ptr };
        blocking_fetch(st, "fetch", &raw, &spec, &mut pump)
    };

    let resolve_fn = v8::Local::new(scope, resolve_root);
    let reject_fn = v8::Local::new(scope, reject_root);
    match result {
        Ok(resp) => {
            let resp_obj = response_object(scope, &args, &resp);
            let call_args = &[resp_obj.into()];
            let _ = resolve_fn.call(scope, v8::undefined(scope).into(), call_args);
        }
        Err(msg) => {
            let reason = format!("TypeError: failed to fetch ({msg})");
            reject_with(scope, reject_fn, &reason);
        }
    }
    resolver.resolve(scope, v8::undefined(scope).into());
    rv.set(promise.into());
}

fn cb_response_text<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    // `text()` resolves with the body `response_object` recorded for this
    // response, found via `this._body_index` in the per-`State` registry. The
    // [resolve, reject] pair is threaded as the first argument (a raw array),
    // the same no-capture contract cb_fetch uses: one fetch per eval, so the
    // single slot stays honest.
    let body = {
        let idx = obj_num(scope, args.this(), "_body_index").unwrap_or(0.0) as usize;
        let st = unsafe { state_of(&args) };
        st.response_bodies.get(idx).cloned().unwrap_or_default()
    };
    let resolver = v8::PromiseResolver::new(scope).expect("promise resolver");
    let promise = resolver.get_promise(scope);
    if let Some((resolve_fn, _)) = arg_then_functions(scope, &args, 0) {
        let call_args = &[js_string(scope, &body)];
        let _ = resolve_fn.call(scope, v8::undefined(scope).into(), call_args);
    }
    resolver.resolve(scope, v8::undefined(scope).into());
    rv.set(promise.into());
}

fn arg_then_functions<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: &FunctionCallbackArguments<'_>,
    i: usize,
) -> Option<(Local<'s, Function>, Local<'s, Function>)> {
    let v = args.get(i as i32);
    if !v.is_array() {
        return None;
    }
    then_callbacks(scope, v)
}

// ── XMLHttpRequest shim ──────────────────────────────────────────────────────
// The FB anonymous-listing idiom is synchronous:
//   var x = new XMLHttpRequest(); x.open('GET', url, false); x.send();
//   var data = JSON.parse(x.responseText);
// `open` records method/url/async; `send(body)` performs the blocking
// request (via the same page-context client as fetch — same subresource
// signature, caller headers merging over the defaults) and populates
// responseText/status so the next statement can read them.
// `setRequestHeader` accumulates on the instance and rides the request.
// Events are stubs.

fn cb_xhr_ctor<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let obj = v8::Object::new(scope);
    set_prop(scope, obj, "readyState", v8::Number::new(scope, 0.0).into());
    set_prop(scope, obj, "status", v8::Number::new(scope, 0.0).into());
    set_prop(scope, obj, "responseText", sv(scope, ""));
    set_prop(scope, obj, "onreadystatechange", v8::null(scope).into());

    // Per-instance methods bound to a JS closure over the host `open`/`send`
    // callbacks. v8 callbacks can't capture, so the host handlers receive the
    // instance via `this` (the closure `.call(obj, ...)`); request state
    // (method/url/headers/body) and the response ride on the object itself.
    // `setRequestHeader` accumulates in plain JS — no host callback needed.
    let shim = r#"
        (function(obj, openFn, sendFn) {
            obj._headers = [];
            obj.open = function(m, u, a) { return openFn.call(obj, m, u, a); };
            obj.setRequestHeader = function(k, v) { obj._headers.push([String(k), String(v)]); };
            obj.send = function(body) {
                return sendFn.call(obj, body == null ? '' : String(body), JSON.stringify(obj._headers));
            };
            // Response-header reads close over the [[name, value], ...] JSON
            // the host stashes on _resp_headers at send() time — wire names
            // arrive lowercased, so the lookup lowercases the ask.
            obj.getResponseHeader = function(name) {
                name = String(name).toLowerCase();
                var hs = JSON.parse(obj._resp_headers || '[]');
                for (var i = 0; i < hs.length; i++) {
                    if (hs[i][0] === name) return hs[i][1];
                }
                return null;
            };
            obj.getAllResponseHeaders = function() {
                var hs = JSON.parse(obj._resp_headers || '[]');
                var out = [];
                for (var i = 0; i < hs.length; i++) out.push(hs[i][0] + ': ' + hs[i][1]);
                return out.join('\r\n');
            };
            return obj;
        })
    "#;
    let code = v8::String::new(scope, shim).expect("string alloc");
    let wrapper = v8::Script::compile(scope, code, None)
        .and_then(|s| s.run(scope))
        .map(|v| v.cast::<Function>());

    let open_fn = v8::FunctionTemplate::builder(cb_xhr_open)
        .data(args.data())
        .build(scope)
        .get_function(scope);
    let send_fn = v8::FunctionTemplate::builder(cb_xhr_send)
        .data(args.data())
        .build(scope)
        .get_function(scope);
    match (wrapper, open_fn, send_fn) {
        (Some(wrapper), Some(open_fn), Some(send_fn)) => {
            let call_args = &[obj.into(), open_fn.into(), send_fn.into()];
            let recv = v8::undefined(scope).into();
            match wrapper.call(scope, recv, call_args) {
                Some(result) => rv.set(result),
                None => rv.set(obj.into()),
            }
        }
        _ => rv.set(obj.into()),
    }
}

fn cb_xhr_open<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    _rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    if !this.is_object() {
        return;
    }
    let obj = this.cast::<Object>();
    let method = arg_string(scope, &args, 0).unwrap_or_else(|| "GET".into());
    let raw = arg_string(scope, &args, 1).unwrap_or_default();
    let url = {
        let st = unsafe { state_of(&args) };
        absolutize(&raw, &st.page_url)
    };
    set_prop(scope, obj, "_method", sv(scope, &method));
    set_prop(scope, obj, "_url", sv(scope, &url));
}

fn cb_xhr_send<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    _rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    if !this.is_object() {
        return;
    }
    let obj = this.cast::<Object>();
    let url = obj_str(scope, obj, "_url").unwrap_or_default();
    if url.is_empty() {
        set_prop(scope, obj, "status", v8::Number::new(scope, 0.0).into());
        set_prop(scope, obj, "responseText", sv(scope, ""));
        return;
    }
    let state_ptr = unsafe { state_of(&args) } as *mut State;
    // send() arrives with the body string and the accumulated headers as
    // JSON (see the ctor shim); open() recorded method + url.
    let mut spec = FetchSpec::get();
    let method = obj_str(scope, obj, "_method").unwrap_or_else(|| "GET".into());
    if !method.is_empty() {
        spec.method = method.to_ascii_uppercase();
    }
    if let Some(headers_json) = arg_string(scope, &args, 1) {
        if let Ok(pairs) = serde_json::from_str::<Vec<Vec<String>>>(&headers_json) {
            spec.headers = pairs
                .into_iter()
                .filter_map(|p| {
                    if p.len() == 2 {
                        Some((p[0].clone(), p[1].clone()))
                    } else {
                        None
                    }
                })
                .collect();
        }
    }
    if let Some(body) = arg_string(scope, &args, 0) {
        spec.body = body;
    }
    if matches!(spec.method.as_str(), "GET" | "HEAD") {
        spec.body.clear();
    }
    let mut pump = || pump_microtasks(scope);
    let result = {
        let st = unsafe { &mut *state_ptr };
        blocking_fetch(st, "xhr", &url, &spec, &mut pump)
    };
    match result {
        Ok(resp) => {
            set_prop(scope, obj, "status", v8::Number::new(scope, resp.status as f64).into());
            set_prop(scope, obj, "responseText", sv(scope, &resp.body));
            // [[name, value], ...] JSON — the ctor shim's getResponseHeader/
            // getAllResponseHeaders close over it.
            let hdrs = serde_json::to_string(&resp.headers).unwrap_or_else(|_| "[]".into());
            set_prop(scope, obj, "_resp_headers", sv(scope, &hdrs));
        }
        Err(_) => {
            set_prop(scope, obj, "status", v8::Number::new(scope, 0.0).into());
            set_prop(scope, obj, "responseText", sv(scope, ""));
            set_prop(scope, obj, "_resp_headers", sv(scope, "[]"));
        }
    }
}

// ── WebSocket (firing 17) ────────────────────────────────────────────────────
//
// A scraping engine never keeps a socket open — the whole point is fetch,
// not push — so WebSocket is a SHAPE stub: constructible with a real state
// machine (readyState/bufferedAmount) so FingerprintJS-style probes and page
// init read a consistent, non-throwing answer. The connection never reaches
// OPEN: there is no wire backend, and faking `open`/`message` would let a
// page hang an eval on a socket that can never carry data. `send` therefore
// accumulates into `bufferedAmount` while CONNECTING (bytes queued for a
// not-yet-open socket, per spec) and throws an InvalidStateError once the
// socket is no longer CONNECTING, exactly what a closed/real-open socket
// does. `close` transitions to CLOSED.

/// Host `send(data)` bound as `obj.send`: returns an error STRING when the
/// send is invalid (non-CONNECTING), else null and accumulates the byte
/// length into `bufferedAmount`. Returning an error string — not throwing —
/// keeps the host callback total; the JS wrapper turns a non-null return
/// into a thrown `InvalidStateError`.
fn cb_ws_send<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    if !this.is_object() {
        rv.set(v8::null(scope).into());
        return;
    }
    let obj = this.cast::<Object>();
    let ready = obj_num(scope, obj, "readyState").unwrap_or(0.0);
    if ready != 0.0 {
        // send() on a socket that is not CONNECTING — InvalidStateError.
        rv.set(sv(scope, "InvalidStateError"));
        return;
    }
    // Accumulate the byte length of a string payload (binary payloads count
    // by their length too — best-effort for the buffered accounting).
    let data = args.get(0);
    let bytes = if data.is_string() {
        data.to_string(scope)
            .map(|s| s.to_rust_string_lossy(scope).len())
            .unwrap_or(0)
    } else {
        0
    } as f64;
    let buffered = obj_num(scope, obj, "bufferedAmount").unwrap_or(0.0) + bytes;
    set_prop(
        scope,
        obj,
        "bufferedAmount",
        v8::Number::new(scope, buffered).into(),
    );
    rv.set(v8::null(scope).into());
}

/// Host `close()`: transition to CLOSED(3) and drop any buffered bytes, the
/// spec's close-on-a-connecting-socket behavior.
fn cb_ws_close<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    _rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    if !this.is_object() {
        return;
    }
    let obj = this.cast::<Object>();
    set_prop(scope, obj, "readyState", v8::Number::new(scope, 3.0).into());
    set_prop(scope, obj, "bufferedAmount", v8::Number::new(scope, 0.0).into());
}

/// `new WebSocket(url)` — the constructor trampoline. Host ctor builds the
/// object; a JS wrapper binds `close`/`send` and seeds the state. Constants
/// (CONNECTING..CLOSED) live on both the constructor and the instance, per
/// spec.
fn cb_ws_ctor<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let url = args
        .get(0)
        .to_string(scope)
        .map(|s| s.to_rust_string_lossy(scope))
        .unwrap_or_default();
    let obj = v8::Object::new(scope);
    set_prop(scope, obj, "url", sv(scope, &url));
    set_prop(scope, obj, "readyState", v8::Number::new(scope, 0.0).into());
    set_prop(scope, obj, "bufferedAmount", v8::Number::new(scope, 0.0).into());
    set_prop(scope, obj, "protocol", sv(scope, ""));
    set_prop(scope, obj, "extensions", sv(scope, ""));
    set_prop(scope, obj, "binaryType", sv(scope, "blob"));
    // Event handlers default null (onopen/onmessage/onerror/onclose).
    for h in ["onopen", "onmessage", "onerror", "onclose"] {
        set_prop(scope, obj, h, v8::null(scope).into());
    }

    // Per-instance methods bound over the host `send`/`close` callbacks; v8
    // callbacks can't capture, so the host handlers receive the instance via
    // `this` (the closure `.call(obj, ...)`).
    let shim = r#"
        (function(obj, sendFn, closeFn) {
            obj.send = function(data) {
                var err = sendFn.call(obj, data);
                if (err !== null) {
                    var e = new Error('WebSocket is not CONNECTING');
                    e.name = err;
                    throw e;
                }
            };
            obj.close = function() { return closeFn.call(obj); };
            return obj;
        })
    "#;
    let code = v8::String::new(scope, shim).expect("string alloc");
    let wrapper = v8::Script::compile(scope, code, None)
        .and_then(|s| s.run(scope))
        .map(|v| v.cast::<Function>());
    let send_fn = v8::FunctionTemplate::builder(cb_ws_send)
        .data(args.data())
        .build(scope)
        .get_function(scope);
    let close_fn = v8::FunctionTemplate::builder(cb_ws_close)
        .data(args.data())
        .build(scope)
        .get_function(scope);
    match (wrapper, send_fn, close_fn) {
        (Some(wrapper), Some(send_fn), Some(close_fn)) => {
            let call_args = &[obj.into(), send_fn.into(), close_fn.into()];
            let recv = v8::undefined(scope).into();
            match wrapper.call(scope, recv, call_args) {
                Some(result) => rv.set(result),
                None => rv.set(obj.into()),
            }
        }
        _ => rv.set(obj.into()),
    }
}

/// `window.name` getter — the shared per-tab cell (see [`Name`]).
fn cb_window_name_get<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let st = unsafe { state_of(&args) };
    let name = st.window_name.get();
    rv.set(sv(scope, &name));
}

/// `window.name` setter — writes land in the shared cell, so the next eval
/// (after however many navigations) reads them back, like a real browsing
/// context.
fn cb_window_name_set<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    _rv: ReturnValue<'s, Value>,
) {
    let st = unsafe { state_of(&args) };
    let name = arg_string(scope, &args, 0).unwrap_or_default();
    st.window_name.set(name);
}

/// `Element.matches(selector)` — does this element match? Bad selectors
/// answer false rather than throwing (the gather precedent: providers send
/// valid selectors, and a host throw would fail the whole eval).
fn cb_el_matches<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let answer = match arg_string(scope, &args, 0) {
        Some(sel) => {
            let st = unsafe { state_of(&args) };
            match this_element_index(scope, &args) {
                Some(idx) => {
                    let id = st.elements.get(idx).and_then(|e| e.node_id);
                    match id.and_then(|id| st.doc().node(id)) {
                        Some(n) => n.matches(&sel).unwrap_or(false),
                        None => false, // synthetic wrapper
                    }
                }
                None => false,
            }
        }
        None => false,
    };
    rv.set(v8::Boolean::new(scope, answer).into());
}

/// `Element.closest(selector)` — nearest ancestor-or-self matching, wrapped;
/// null when nothing matches (or this is a synthetic off-document wrapper).
fn cb_el_closest<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let found = match arg_string(scope, &args, 0) {
        Some(sel) => {
            let st = unsafe { state_of(&args) };
            match this_element_index(scope, &args) {
                Some(idx) => {
                    let id = st.elements.get(idx).and_then(|e| e.node_id);
                    match id.and_then(|id| st.doc().node(id)) {
                        Some(n) => n
                            .closest(&sel)
                            .ok()
                            .flatten()
                            .map(|x| ElementData::from_node(&x)),
                        None => None,
                    }
                }
                None => None,
            }
        }
        None => None,
    };
    match found {
        Some(data) => {
            let obj = wrap_element(scope, &args, data);
            rv.set(obj.into());
        }
        None => rv.set(nullv(scope)),
    }
}

/// `document.activeElement` — a freshly loaded page reports its body (no
/// element has focus until something takes it; the bridge tracks no focus
/// moves, and body is what an unfocused real page answers).
fn cb_document_active_element<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let body = {
        let st = unsafe { state_of(&args) };
        st.doc()
            .select_one("body")
            .ok()
            .flatten()
            .map(|n| ElementData::from_node(&n))
    };
    match body {
        Some(data) => {
            let obj = wrap_element(scope, &args, data);
            rv.set(obj.into());
        }
        None => rv.set(nullv(scope)),
    }
}

/// `navigator.sendBeacon(url, data)` — accepted, payload dropped. A scraping
/// engine sends no analytics; the page's contract is only that the call
/// returns true (queued) instead of throwing.
fn cb_send_beacon<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    rv.set(v8::Boolean::new(scope, true).into());
}

/// `new Worker(url)` — shape only: the feature-detect (`typeof Worker ===
/// 'function'`, constructible) passes, and the instance's methods are inert
/// noops. Running a worker script would need a second script context fed by
/// a network fetch — no page's data path depends on it, so the worker never
/// actually works.
fn cb_worker_ctor<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let obj = v8::Object::new(scope);
    set_prop(scope, obj, "onmessage", v8::null(scope).into());
    set_prop(scope, obj, "onerror", v8::null(scope).into());
    for m in [
        "postMessage",
        "terminate",
        "close",
        "addEventListener",
        "removeEventListener",
        "dispatchEvent",
    ] {
        if let Some(f) = v8::Function::new(scope, cb_noop) {
            set_prop(scope, obj, m, f.into());
        }
    }
    let _ = args; // construction takes no per-instance input
    rv.set(obj.into());
}

/// `new SharedWorker(url)` — shape only, same contract as [`cb_worker_ctor`].
fn cb_shared_worker_ctor<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let obj = v8::Object::new(scope);
    let port = v8::Object::new(scope);
    set_prop(scope, port, "onmessage", v8::null(scope).into());
    set_prop(scope, port, "onmessageerror", v8::null(scope).into());
    if let Some(f) = v8::Function::new(scope, cb_noop) {
        set_prop(scope, port, "postMessage", f.into());
    }
    for m in ["addEventListener", "removeEventListener", "dispatchEvent", "start", "close"] {
        if let Some(f) = v8::Function::new(scope, cb_noop) {
            set_prop(scope, port, m, f.into());
        }
    }
    set_prop(scope, obj, "port", port.into());
    rv.set(obj.into());
}

/// `new Image()` — the tracking-pixel idiom (`new Image().src = url`). Shape
/// only: natural metrics zero, src assignable, load/error handlers null and
/// never fired (no fetch is issued — the beacon contract is "don't throw").
fn cb_image_ctor<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let obj = v8::Object::new(scope);
    set_prop(scope, obj, "width", v8::Number::new(scope, 0.0).into());
    set_prop(scope, obj, "height", v8::Number::new(scope, 0.0).into());
    set_prop(scope, obj, "naturalWidth", v8::Number::new(scope, 0.0).into());
    set_prop(scope, obj, "naturalHeight", v8::Number::new(scope, 0.0).into());
    set_prop(scope, obj, "src", sv(scope, ""));
    set_prop(scope, obj, "onload", v8::null(scope).into());
    set_prop(scope, obj, "onerror", v8::null(scope).into());
    rv.set(obj.into());
}

fn select_snapshots(doc: &Document, sel: &str, limit: usize) -> Vec<ElementData> {
    match doc.select(sel) {
        Ok(nodes) => nodes
            .iter()
            .take(limit)
            .map(|n| ElementData::from_node(&n))
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Run a selector from `this` (element scope) or from the document.
/// Returns snapshots; a bad selector yields empty, matching browser
/// `querySelector` throwing — but providers send valid selectors and a
/// thrown error inside V8 here would surface as an eval failure, so empty
/// is the pragmatic choice.
fn gather<'s, 'i>(
    scope: &PinScope<'s, 'i>,
    args: &FunctionCallbackArguments<'_>,
    sel: &str,
    limit: usize,
) -> Vec<ElementData> {
    let st = unsafe { state_of(args) };
    match this_element_index(scope, args) {
        Some(idx) => {
            // Element scope: re-read this element's CURRENT subtree from the
            // live tree. The wrapper's `html` snapshot goes stale after a
            // mutation (innerHTML/appendChild/remove) — the cached doc is the
            // source of truth, invalidated and reparsed on each mutation.
            let id = st.elements.get(idx).and_then(|e| e.node_id);
            let Some(id) = id else {
                return Vec::new(); // synthetic wrapper: empty fragment scope
            };
            let html = match st.doc().node(id) {
                Some(n) => n.html(),
                None => return Vec::new(),
            };
            let mut snaps = select_snapshots(&Document::parse_fragment(&html), sel, limit);
            // The fragment parse is discarded with this call — its node ids
            // would resolve against the wrong document in `parentElement`.
            for e in &mut snaps {
                e.node_id = None;
            }
            snaps
        }
        None => select_snapshots(st.doc(), sel, limit),
    }
}

/// Wrap one snapshot as a JS element object: index in the internal field,
/// data as own properties.
fn wrap_element<'s, 'i>(
    scope: &PinScope<'s, 'i>,
    args: &FunctionCallbackArguments<'_>,
    data: ElementData,
) -> Local<'s, Object> {
    let (idx, tpl) = {
        let st = unsafe { state_of(args) };
        let idx = st.push(data.clone());
        let tpl = st.el_template.as_ref().expect("element template installed");
        let tpl = v8::Local::new(nullscope(scope), tpl);
        (idx, tpl)
    };
    let obj = tpl.new_instance(scope).expect("element instance");
    let n = v8::Number::new(scope, idx as f64);
    obj.set_internal_field(0, n.into());
    if let Some(cl) = obj
        .get(scope, sv(scope, "classList"))
        .and_then(|v| v.to_object(scope))
    {
        cl.set_internal_field(0, v8::Number::new(scope, idx as f64).into());
    }
    let k_tag = sv(scope, "tagName");
    let v_tag = sv(scope, &data.tag.to_uppercase());
    let _ = obj.set(scope, k_tag, v_tag);
    // innerHTML/textContent/outerHTML are ACCESSOR properties on the template
    // (see build_element_template) — not set here. id/className remain static
    // data props (they don't mutate through the tier; the getters that need
    // liveness read the snapshot).
    let k_id = sv(scope, "id");
    let v_id = sv(scope, data.attr("id").unwrap_or(""));
    let _ = obj.set(scope, k_id, v_id);
    let k_cls = sv(scope, "className");
    let v_cls = sv(scope, data.attr("class").unwrap_or(""));
    let _ = obj.set(scope, k_cls, v_cls);
    // Scroll geometry: this tier has no layout, so every metric is the
    // honest zero and `scrollTop`/`scrollLeft` are plain writable data
    // props (assignment overwrites, like a real element's IDL attribute).
    // Provider scroll loops (`_SCROLL_JS`) read and assign these.
    for k in [
        "scrollHeight",
        "scrollWidth",
        "clientHeight",
        "clientWidth",
        "scrollTop",
        "scrollLeft",
        "offsetHeight",
        "offsetWidth",
    ] {
        let _ = obj.set(scope, sv(scope, k), v8::Number::new(scope, 0.0).into());
    }
    obj
}

// ── callbacks (non-capturing; state via args.data()) ────────────────────────

fn cb_query_selector<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(sel) = arg_string(scope, &args, 0) else {
        rv.set(nullv(scope));
        return;
    };
    let snaps = gather(scope, &args, &sel, 1);
    match snaps.into_iter().next() {
        Some(data) => {
            let obj = wrap_element(scope, &args, data);
            rv.set(obj.into());
        }
        None => rv.set(nullv(scope)),
    }
}

fn cb_query_selector_all<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(sel) = arg_string(scope, &args, 0) else {
        rv.set(v8::Array::new(scope, 0).into());
        return;
    };
    let snaps = gather(scope, &args, &sel, usize::MAX);
    let vals: Vec<Local<Value>> = snaps
        .into_iter()
        .map(|data| wrap_element(scope, &args, data).into())
        .collect();
    rv.set(v8::Array::new_with_elements(scope, &vals).into());
}

fn cb_get_element_by_id<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(id) = arg_string(scope, &args, 0) else {
        rv.set(nullv(scope));
        return;
    };
    let escaped = id.replace('\\', "\\\\").replace('"', "\\\"");
    let sel = format!("[id=\"{escaped}\"]");
    let snaps = gather(scope, &args, &sel, 1);
    match snaps.into_iter().next() {
        Some(data) => {
            let obj = wrap_element(scope, &args, data);
            rv.set(obj.into());
        }
        None => rv.set(nullv(scope)),
    }
}

/// `document.createElement(tag)`: a synthetic off-document element wrapper.
/// The fingerprint-probe idiom is `document.createElement('canvas')` — the
/// canvas never enters the DOM, so there is no parse node to snapshot; the
/// wrapper's `node_id` stays `None` (its queries resolve against the empty
/// fragment, and `parentElement` of an off-DOM node is null, as in a real
/// browser).
fn cb_document_create_element<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(tag) = arg_string(scope, &args, 0) else {
        rv.set(nullv(scope));
        return;
    };
    let tag = tag.trim().to_lowercase();
    if tag.is_empty() {
        rv.set(nullv(scope));
        return;
    }
    let data = ElementData {
        tag,
        text: String::new(),
        html: String::new(),
        attrs: Vec::new(),
        node_id: None,
    };
    let obj = wrap_element(scope, &args, data);
    rv.set(obj.into());
}

/// `document.createTextNode(text)` — a synthetic text node, the `{nodeType:3,
/// textContent}` shape `appendChild` recognizes and grafts as a bare text
/// node. Off-document until appended.
fn cb_document_create_text_node<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let text = arg_string(scope, &args, 0).unwrap_or_default();
    let obj = v8::Object::new(scope);
    set_prop(scope, obj, "nodeType", v8::Number::new(scope, 3.0).into());
    set_prop(scope, obj, "textContent", sv(scope, &text));
    rv.set(obj.into());
}

/// A zero-geometry DOMRect(-like) object. This tier has no layout, so every
/// element reports the honest zero rect — the same policy as the zeroed
/// scroll* metrics. Fields carry both the `x`/`y` and `top`/`left` aliases a
/// real DOMRect exposes. Scraping-side effect: `rect.top < innerHeight` is
/// true for every element, so visibility-gated lazy-loaders treat everything
/// as in-viewport — which is exactly the reveal-everything behavior a scraper
/// wants.
fn rect_object<'s, 'i>(scope: &mut PinScope<'s, 'i>) -> Local<'s, Object> {
    let r = v8::Object::new(scope);
    let zero = v8::Number::new(scope, 0.0);
    for k in [
        "x", "y", "width", "height", "top", "right", "bottom", "left",
    ] {
        set_prop(scope, r, k, zero.into());
    }
    r
}

fn cb_get_bounding_client_rect<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let _ = &args;
    rv.set(rect_object(scope).into());
}

/// `getClientRects()` — a real rendered element reports one rect per line
/// box; with no layout we report the single zero rect, consistent with
/// `getBoundingClientRect`. A plain JS array answers both `length` and
/// indexing, which is all lazy-loaders read.
fn cb_get_client_rects<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let _ = &args;
    let rect = rect_object(scope);
    rv.set(v8::Array::new_with_elements(scope, &[rect.into()]).into());
}

// ── observers (IntersectionObserver / ResizeObserver / MutationObserver) ────
//
// Scraping-grade policy: observers REVEAL rather than gate. With no layout
// every element reports the zero geometry (see rect_object), so a strict
// "is it in the viewport?" answer would report nothing intersecting and
// lazy-loaders would never fetch their content. Instead an observed target
// is delivered one notification reporting it live (intersecting / resized),
// which is what makes infinite-scroll and lazy-load pages actually populate
// under this engine. MutationObserver (firing 24) is LIVE: the firing-16
// mutation tier made the bridge DOM mutable, so every mutation choke point
// queues records for matching registrations and the pump-drained flush
// delivers them — `observe(document.body, {childList:true, subtree:true})`
// followed by an append finally fires its callback.

/// Build one IntersectionObserver/ResizeObserver instance. The constructor
/// callback can't capture the kind, so the two public ctors are thin wrappers
/// over this shared builder. The per-instance JS closures bind the host
/// methods over `obj` (v8 callbacks can't capture); the user's callback is
/// stashed on `_cb`, the instance id on `_obsId`, the kind on `_kind`.
fn build_observer<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
    kind: u8,
) {
    let obj = v8::Object::new(scope);
    // The user callback arrives as the constructor's first argument.
    let user_cb = args.get(0);
    set_prop(scope, obj, "_cb", user_cb);

    let shim = r#"
        (function(obj, observeFn, unobserveFn, disconnectFn, takeRecordsFn, id, kind) {
            obj._obsId = id;
            obj._kind = kind;
            obj.observe = function(t) { return observeFn.call(obj, t); };
            obj.unobserve = function(t) { return unobserveFn.call(obj, t); };
            obj.disconnect = function() { return disconnectFn.call(obj); };
            obj.takeRecords = function() { return takeRecordsFn.call(obj); };
            return obj;
        })
    "#;
    let code = v8::String::new(scope, shim).expect("string alloc");
    let wrapper = v8::Script::compile(scope, code, None)
        .and_then(|s| s.run(scope))
        .map(|v| v.cast::<Function>());

    let observe_fn = v8::FunctionTemplate::builder(cb_observer_observe)
        .data(args.data())
        .build(scope)
        .get_function(scope);
    let unobserve_fn = v8::FunctionTemplate::builder(cb_observer_unobserve)
        .data(args.data())
        .build(scope)
        .get_function(scope);
    let disconnect_fn = v8::FunctionTemplate::builder(cb_observer_disconnect)
        .data(args.data())
        .build(scope)
        .get_function(scope);
    let take_records_fn = v8::FunctionTemplate::builder(cb_observer_take_records)
        .data(args.data())
        .build(scope)
        .get_function(scope);

    let id = {
        let st = unsafe { state_of(&args) };
        let id = st.next_observer_id;
        st.next_observer_id += 1;
        id
    };

    match (wrapper, observe_fn, unobserve_fn, disconnect_fn, take_records_fn) {
        (Some(wrapper), Some(observe_fn), Some(unobserve_fn), Some(disconnect_fn), Some(take_fn)) => {
            let call_args = &[
                obj.into(),
                observe_fn.into(),
                unobserve_fn.into(),
                disconnect_fn.into(),
                take_fn.into(),
                v8::Number::new(scope, id as f64).into(),
                v8::Number::new(scope, kind as f64).into(),
            ];
            let recv = v8::undefined(scope).into();
            match wrapper.call(scope, recv, call_args) {
                Some(result) => rv.set(result),
                None => rv.set(obj.into()),
            }
        }
        _ => rv.set(obj.into()),
    }
}

fn cb_intersection_observer_ctor<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    rv: ReturnValue<'s, Value>,
) {
    build_observer(scope, args, rv, 0);
}

fn cb_resize_observer_ctor<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    rv: ReturnValue<'s, Value>,
) {
    build_observer(scope, args, rv, 1);
}

/// Number property read off an object (`_obsId` / `_kind`).
fn num_prop<'s, 'i>(scope: &mut PinScope<'s, 'i>, obj: Local<'_, Object>, key: &str) -> u32 {
    obj.get(scope, sv(scope, key))
        .and_then(|v| v.to_number(scope))
        .map(|n| n.value() as u32)
        .unwrap_or(0)
}

fn cb_observer_observe<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    let Some(obj) = this.to_object(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let user_cb = obj.get(scope, sv(scope, "_cb"));
    if !user_cb.map(|v| v.is_function()).unwrap_or(false) {
        rv.set(v8::undefined(scope).into());
        return;
    }
    let target = args.get(0);
    let target_index = value_element_index(scope, target);
    let st = unsafe { state_of(&args) };
    st.observer_queue.push(ObserverNotification {
        observer_id: num_prop(scope, obj, "_obsId"),
        kind: num_prop(scope, obj, "_kind") as u8,
        callback: v8::Global::new(scope, user_cb.expect("checked").cast::<Function>()),
        observer: v8::Global::new(scope, this.cast::<Value>()),
        target: v8::Global::new(scope, target),
        target_index,
    });
    schedule_observer_flush(st, scope, &args, &mut rv);
    rv.set(v8::undefined(scope).into());
}

/// Schedule ONE pump-drained flush for the observer queues (IO/RO
/// notifications and/or pending mutation records). The flush fn's Global is
/// built on first use — a live context (required by get_function) only
/// exists inside callbacks, not while build_globals assembles the template.
/// Shared by observe() and every mutation choke point; the
/// `observer_flush_scheduled` flag dedups so a burst of mutations between
/// pump passes costs one 0ms timer, not one per record.
fn schedule_observer_flush<'s, 'i>(
    st: &mut State,
    scope: &mut PinScope<'s, 'i>,
    args: &FunctionCallbackArguments<'s>,
    rv: &mut ReturnValue<'s, Value>,
) {
    if st.observer_flush_scheduled {
        return;
    }
    let f = match st.observer_flush_fn.clone() {
        Some(f) => f,
        None => {
            let built = v8::FunctionTemplate::builder(cb_observer_flush)
                .data(args.data())
                .build(scope)
                .get_function(scope);
            match built {
                Some(f) => {
                    let g = v8::Global::new(scope, f);
                    st.observer_flush_fn = Some(g.clone());
                    g
                }
                None => {
                    rv.set(v8::undefined(scope).into());
                    return;
                }
            }
        }
    };
    let id = st.next_timer_id;
    st.next_timer_id += 1;
    st.timers.push(Timer {
        id,
        deadline: Instant::now(),
        interval_ms: None,
        raf: false,
        callback: f,
    });
    st.observer_flush_scheduled = true;
}

fn cb_observer_unobserve<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    let Some(obj) = this.to_object(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let id = num_prop(scope, obj, "_obsId");
    let target_index = value_element_index(scope, args.get(0));
    let st = unsafe { state_of(&args) };
    st.observer_queue
        .retain(|n| !(n.observer_id == id && n.target_index == target_index));
    rv.set(v8::undefined(scope).into());
}

fn cb_observer_disconnect<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    let Some(obj) = this.to_object(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let id = num_prop(scope, obj, "_obsId");
    let st = unsafe { state_of(&args) };
    st.observer_queue.retain(|n| n.observer_id != id);
    rv.set(v8::undefined(scope).into());
}

/// Build one delivered entry object for a notification.
fn observer_entry<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    n: &ObserverNotification,
    timestamp: f64,
) -> Local<'s, Object> {
    let e = v8::Object::new(scope);
    let target = Local::new(scope, n.target.clone());
    set_prop(scope, e, "target", target.into());
    if n.kind == 0 {
        // IntersectionObserverEntry — reveal-everything: live, fully visible.
        let rect = rect_object(scope);
        set_prop(scope, e, "boundingClientRect", rect.into());
        let rect = rect_object(scope);
        set_prop(scope, e, "intersectionRect", rect.into());
        set_prop(scope, e, "rootBounds", v8::null(scope).into());
        set_prop(scope, e, "intersectionRatio", v8::Number::new(scope, 1.0).into());
        set_prop(scope, e, "isIntersecting", v8::Boolean::new(scope, true).into());
        set_prop(scope, e, "isVisible", v8::Boolean::new(scope, true).into());
        set_prop(scope, e, "time", v8::Number::new(scope, timestamp).into());
    } else {
        // ResizeObserverEntry — the zero content rect (no layout).
        let rect = rect_object(scope);
        set_prop(scope, e, "contentRect", rect.into());
    }
    e
}

/// Drain BOTH observer queues — the IO/RO notification queue and the
/// MutationObserver record queue: one callback invocation per observer, with
/// all its entries in a single array (spec delivery shape). All queue
/// contents are taken up front so no `State` borrow is held across the
/// user-callback invocations — a callback may itself mutate/observe and
/// re-enter through `state_of`.
fn cb_observer_flush<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let st = unsafe { state_of(&args) };
    st.observer_flush_scheduled = false;
    let pending = std::mem::take(&mut st.observer_queue);
    let records = std::mem::take(&mut st.mutation_records);
    if pending.is_empty() && records.is_empty() {
        rv.set(v8::undefined(scope).into());
        return;
    }
    let timestamp = st.started.elapsed().as_millis() as f64;
    // IntersectionObserver / ResizeObserver notifications.
    let mut groups: Vec<(u32, Vec<ObserverNotification>)> = Vec::new();
    for n in pending {
        match groups.iter_mut().find(|(id, _)| *id == n.observer_id) {
            Some((_, v)) => v.push(n),
            None => groups.push((n.observer_id, vec![n])),
        }
    }
    for (_, entries) in groups {
        let Some(first) = entries.first() else { continue };
        let callback = Local::new(scope, first.callback.clone());
        let observer = Local::new(scope, first.observer.clone());
        let vals: Vec<Local<Value>> = entries
            .iter()
            .map(|n| observer_entry(scope, n, timestamp).into())
            .collect();
        let arr = v8::Array::new_with_elements(scope, &vals);
        v8::tc_scope!(tc, scope);
        let _ = callback.call(&mut *tc, observer, &[arr.into(), observer]);
    }
    // MutationObserver records (firing 24): same grouping, one callback per
    // observer with every pending record in one array. Records made BY these
    // callbacks stay queued for the next flush (the choke points scheduled
    // it) — a mutation storm can't re-enter this drain mid-loop.
    let mut mgroups: Vec<(u32, Vec<MutationRecord>)> = Vec::new();
    for r in records {
        match mgroups.iter_mut().find(|(id, _)| *id == r.observer_id) {
            Some((_, v)) => v.push(r),
            None => mgroups.push((r.observer_id, vec![r])),
        }
    }
    for (observer_id, recs) in mgroups {
        // The registration snapshot carries callback + observer object; a
        // disconnected observer's records were drained at disconnect time.
        let reg = {
            let st = unsafe { state_of(&args) };
            st.mutation_targets
                .iter()
                .find(|t| t.observer_id == observer_id)
                .cloned()
        };
        let Some(reg) = reg else { continue };
        let vals: Vec<Local<Value>> = recs
            .iter()
            .map(|r| mutation_record_object(scope, &args, r).into())
            .collect();
        let arr = v8::Array::new_with_elements(scope, &vals);
        let callback = Local::new(scope, reg.callback);
        let observer = Local::new(scope, reg.observer);
        v8::tc_scope!(tc, scope);
        let _ = callback.call(&mut *tc, observer, &[arr.into(), observer]);
    }
    rv.set(v8::undefined(scope).into());
}

/// Build one delivered MutationRecord object: the type string, the target
/// re-wrapped from the record-time snapshot, the held node objects for
/// childList added/removed, attributeName/oldValue when applicable. Sibling
/// pointers are null — the bridge re-parses on mutation and doesn't diff
/// siblings.
fn mutation_record_object<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: &FunctionCallbackArguments<'_>,
    r: &MutationRecord,
) -> Local<'s, Object> {
    let e = v8::Object::new(scope);
    let type_ = match r.kind {
        MUT_CHILD_LIST => "childList",
        MUT_ATTRIBUTES => "attributes",
        _ => "characterData",
    };
    set_prop(scope, e, "type", sv(scope, type_).into());
    let target = wrap_element(scope, args, r.target.clone()).into();
    set_prop(scope, e, "target", target);
    let added: Vec<Local<Value>> = r.added.iter().map(|g| Local::new(scope, g.clone())).collect();
    set_prop(
        scope,
        e,
        "addedNodes",
        v8::Array::new_with_elements(scope, &added).into(),
    );
    let removed: Vec<Local<Value>> = r
        .removed
        .iter()
        .map(|g| Local::new(scope, g.clone()))
        .collect();
    set_prop(
        scope,
        e,
        "removedNodes",
        v8::Array::new_with_elements(scope, &removed).into(),
    );
    match &r.attribute_name {
        Some(n) => set_prop(scope, e, "attributeName", sv(scope, n).into()),
        None => set_prop(scope, e, "attributeName", nullv(scope)),
    }
    match &r.old_value {
        Some(v) => set_prop(scope, e, "oldValue", sv(scope, v).into()),
        None => set_prop(scope, e, "oldValue", nullv(scope)),
    }
    set_prop(scope, e, "nextSibling", nullv(scope));
    set_prop(scope, e, "previousSibling", nullv(scope));
    e
}

/// Pull this observer's still-queued entries (they are NOT delivered by the
/// later flush once taken) and return them as an array.
fn cb_observer_take_records<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    let Some(obj) = this.to_object(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let id = num_prop(scope, obj, "_obsId");
    let st = unsafe { state_of(&args) };
    let taken: Vec<ObserverNotification> = st
        .observer_queue
        .iter()
        .filter(|n| n.observer_id == id)
        .cloned()
        .collect();
    st.observer_queue.retain(|n| n.observer_id != id);
    if taken.is_empty() {
        rv.set(v8::Array::new(scope, 0).into());
        return;
    }
    let timestamp = st.started.elapsed().as_millis() as f64;
    let vals: Vec<Local<Value>> = taken
        .iter()
        .map(|n| observer_entry(scope, n, timestamp).into())
        .collect();
    rv.set(v8::Array::new_with_elements(scope, &vals).into());
}

// ObserverNotification is Clone-only by hand (Global<T> is Clone).
impl Clone for ObserverNotification {
    fn clone(&self) -> Self {
        Self {
            observer_id: self.observer_id,
            kind: self.kind,
            callback: self.callback.clone(),
            observer: self.observer.clone(),
            target: self.target.clone(),
            target_index: self.target_index,
        }
    }
}

/// `MutationObserver` — LIVE as of firing 24: the firing-16 mutation tier
/// made the bridge DOM mutable, so every mutation choke point queues records
/// for matching registrations and the pump-drained observer flush delivers
/// them (one callback per observer with all its records in one array, the
/// spec delivery shape). The JS shim validates observe() options (spec: at
/// least one of childList/attributes/characterData, else TypeError — thrown
/// in JS since v8 152 has no host-side throw) and forwards the booleans;
/// registration state lives host-side in `State::mutation_targets` because
/// matching happens at MUTATION time, before any JS runs. takeRecords()
/// pulls still-queued records (they are not delivered once taken);
/// disconnect() unregisters AND discards pending records, matching browsers.
fn cb_mutation_observer_ctor<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let obj = v8::Object::new(scope);
    // The user callback arrives as the constructor's first argument.
    let user_cb = args.get(0);
    set_prop(scope, obj, "_cb", user_cb);
    let shim = r#"
        (function(obj, observeFn, unobserveFn, disconnectFn, takeRecordsFn, id) {
            obj._obsId = id;
            obj.observe = function(t, options) {
                options = options || {};
                var childList = !!options.childList;
                var attributes = !!options.attributes;
                var characterData = !!options.characterData;
                if (!childList && !attributes && !characterData) {
                    throw new TypeError("Failed to execute 'observe' on 'MutationObserver': parameters 1-2 of MutationObserver.observe are not of type 'MutationObserverInit' — at least one of childList, attributes, or characterData must be true.");
                }
                return observeFn.call(obj, t, childList, attributes, characterData,
                                      !!options.subtree, !!options.attributeOldValue,
                                      !!options.characterDataOldValue);
            };
            obj.unobserve = function(t) { return unobserveFn.call(obj, t); };
            obj.disconnect = function() { return disconnectFn.call(obj); };
            obj.takeRecords = function() { return takeRecordsFn.call(obj); };
            return obj;
        })
    "#;
    let code = v8::String::new(scope, shim).expect("string alloc");
    let wrapper = v8::Script::compile(scope, code, None)
        .and_then(|s| s.run(scope))
        .map(|v| v.cast::<Function>());

    let observe_fn = v8::FunctionTemplate::builder(cb_mo_observe)
        .data(args.data())
        .build(scope)
        .get_function(scope);
    let unobserve_fn = v8::FunctionTemplate::builder(cb_mo_unobserve)
        .data(args.data())
        .build(scope)
        .get_function(scope);
    let disconnect_fn = v8::FunctionTemplate::builder(cb_mo_disconnect)
        .data(args.data())
        .build(scope)
        .get_function(scope);
    let take_records_fn = v8::FunctionTemplate::builder(cb_mo_take_records)
        .data(args.data())
        .build(scope)
        .get_function(scope);

    let id = {
        let st = unsafe { state_of(&args) };
        let id = st.next_observer_id;
        st.next_observer_id += 1;
        id
    };

    match (wrapper, observe_fn, unobserve_fn, disconnect_fn, take_records_fn) {
        (Some(wrapper), Some(observe_fn), Some(unobserve_fn), Some(disconnect_fn), Some(take_fn)) => {
            let call_args = &[
                obj.into(),
                observe_fn.into(),
                unobserve_fn.into(),
                disconnect_fn.into(),
                take_fn.into(),
                v8::Number::new(scope, id as f64).into(),
            ];
            let recv = v8::undefined(scope).into();
            match wrapper.call(scope, recv, call_args) {
                Some(result) => rv.set(result),
                None => rv.set(obj.into()),
            }
        }
        _ => rv.set(obj.into()),
    }
}

fn mo_flag(args: &FunctionCallbackArguments<'_>, i: i32) -> bool {
    args.get(i).is_true()
}

/// `mo.observe(target, options…)` — register a standing mutation filter.
/// The target is an element wrapper (internal field) or, when it has none,
/// a document-level observation that matches any mutation (`u32::MAX`).
fn cb_mo_observe<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    let Some(obj) = this.to_object(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let user_cb = obj.get(scope, sv(scope, "_cb"));
    if !user_cb.map(|v| v.is_function()).unwrap_or(false) {
        rv.set(v8::undefined(scope).into());
        return;
    }
    let target = args.get(0);
    let target_index = value_element_index(scope, target);
    let st = unsafe { state_of(&args) };
    st.mutation_targets.push(MutationTarget {
        observer_id: num_prop(scope, obj, "_obsId"),
        target_index,
        child_list: mo_flag(&args, 1),
        attributes: mo_flag(&args, 2),
        character_data: mo_flag(&args, 3),
        subtree: mo_flag(&args, 4),
        attr_old_value: mo_flag(&args, 5),
        character_old_value: mo_flag(&args, 6),
        callback: v8::Global::new(scope, user_cb.expect("checked").cast::<Function>()),
        observer: v8::Global::new(scope, this.cast::<Value>()),
    });
    rv.set(v8::undefined(scope).into());
}

fn cb_mo_unobserve<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    let Some(obj) = this.to_object(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let id = num_prop(scope, obj, "_obsId");
    let target_index = value_element_index(scope, args.get(0));
    let st = unsafe { state_of(&args) };
    st.mutation_targets
        .retain(|t| !(t.observer_id == id && t.target_index == target_index));
    rv.set(v8::undefined(scope).into());
}

/// `mo.disconnect()` — unregister every target AND discard this observer's
/// still-queued records (what browsers do; takeRecords() after a disconnect
/// is empty).
fn cb_mo_disconnect<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    let Some(obj) = this.to_object(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let id = num_prop(scope, obj, "_obsId");
    let st = unsafe { state_of(&args) };
    st.mutation_targets.retain(|t| t.observer_id != id);
    st.mutation_records.retain(|r| r.observer_id != id);
    rv.set(v8::undefined(scope).into());
}

/// `mo.takeRecords()` — pull this observer's still-queued records out of
/// the delivery queue and return them (records are NOT delivered once
/// taken). Called synchronously, between mutations and the pump flush.
fn cb_mo_take_records<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    let Some(obj) = this.to_object(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let id = num_prop(scope, obj, "_obsId");
    let taken: Vec<MutationRecord> = {
        let st = unsafe { state_of(&args) };
        let (mine, rest): (Vec<_>, Vec<_>) = st
            .mutation_records
            .drain(..)
            .partition(|r| r.observer_id == id);
        st.mutation_records = rest;
        mine
    };
    let vals: Vec<Local<Value>> = taken
        .iter()
        .map(|r| mutation_record_object(scope, &args, r).into())
        .collect();
    rv.set(v8::Array::new_with_elements(scope, &vals).into());
}

// ── SPA runtime tier ─────────────────────────────────────────────────────────
// The surface client-side routers and reactive frameworks observe: session
// history + live location, a working EventTarget registry (replacing the
// addEventListener noops), heuristic matchMedia, and a serviceWorker stub
// that resolves instead of hanging page init. All of it is in-session — no
// document load happens from an eval, so "navigation" rewrites location and
// fires the events a router listens for.

/// Which node an event targets: window, document, or a wrapped element.
#[derive(Clone, Copy, PartialEq)]
enum EvTarget {
    Window,
    Document,
    Element(u32),
}

/// Classify a callback receiver: element wrappers carry an internal field;
/// the global proxy is window; anything else is document-ish (only `document`
/// itself ever registers document listeners).
fn classify_target<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: &FunctionCallbackArguments<'s>,
) -> EvTarget {
    let this = args.this();
    let idx = value_element_index(scope, this.into());
    if idx != u32::MAX {
        return EvTarget::Element(idx);
    }
    let context = scope.get_current_context();
    let global = context.global(nullscope(scope));
    if this.strict_equals(global.into()) {
        return EvTarget::Window;
    }
    EvTarget::Document
}

/// Snapshot the listener callbacks that would fire for `target` and event
/// type `ty`, grouped into phases. Phase bool = is-window-phase (currentTarget
/// reports window); the middle phase is the target's own listeners. Window
/// capture runs before, window non-capture after — but only when the event
/// bubbles, matching real propagation endpoints; there is no intermediate
/// bubble walk on the read-only bridge DOM.
fn event_phases(
    st: &State,
    target: EvTarget,
    ty: &str,
    bubbles: bool,
) -> Vec<(bool, Vec<v8::Global<Function>>)> {
    let pick = |kind: u8, idx: u32, capture: Option<bool>| {
        st.listeners
            .iter()
            .filter(|l| {
                l.target_kind == kind
                    && l.type_ == ty
                    && (kind != 2 || l.element_index == idx)
                    && capture.map_or(true, |c| l.capture == c)
            })
            .map(|l| l.callback.clone())
            .collect::<Vec<_>>()
    };
    match target {
        EvTarget::Window => vec![(true, pick(0, 0, None))],
        EvTarget::Document => {
            let mut v = vec![
                (true, pick(0, 0, Some(true))),
                (false, pick(1, 0, None)),
            ];
            if bubbles {
                v.push((true, pick(0, 0, Some(false))));
            }
            v
        }
        EvTarget::Element(i) => {
            let mut v = vec![
                (true, pick(0, 0, Some(true))),
                (false, pick(2, i, None)),
            ];
            if bubbles {
                v.push((true, pick(0, 0, Some(false))));
            }
            v
        }
    }
}

/// Run the phases snapshot by [`event_phases`]. Takes no State reference: a
/// listener may re-enter host callbacks, and none of them may alias a live
/// borrow of the listeners vector.
fn run_event_phases<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    phases: Vec<(bool, Vec<v8::Global<Function>>)>,
    this_obj: Local<'s, Value>,
    event: Local<'s, Object>,
) {
    if phases.iter().all(|(_, cbs)| cbs.is_empty()) {
        return;
    }
    let context = scope.get_current_context();
    let global = context.global(nullscope(scope)).into();
    for (is_window_phase, cbs) in phases {
        if cbs.is_empty() {
            continue;
        }
        let current = if is_window_phase { global } else { this_obj };
        let _ = event.set(scope, sv(scope, "currentTarget"), current);
        for cb in cbs {
            let f = Local::new(scope, cb);
            {
                v8::tc_scope!(tc, scope);
                let _ = f.call(&mut *tc, current, &[event.into()]);
            }
            let stop_now = event
                .get(scope, sv(scope, "__seStopNow"))
                .map(|v| v.is_true())
                .unwrap_or(false);
            if stop_now {
                return;
            }
        }
        let stop = event
            .get(scope, sv(scope, "__seStop"))
            .map(|v| v.is_true())
            .unwrap_or(false);
        if stop {
            return;
        }
    }
}

/// Truthiness for the capture flag: booleans directly, `{capture: bool}`
/// option objects via their `capture` prop, anything else false.
fn capture_flag<'s, 'i>(scope: &mut PinScope<'s, 'i>, v: Local<'s, Value>) -> bool {
    if v.is_boolean() {
        return v.is_true();
    }
    if v.is_object() && !v.is_function() {
        return v
            .to_object(scope)
            .and_then(|o| o.get(scope, sv(scope, "capture")))
            .map(|c| c.is_true())
            .unwrap_or(false);
    }
    false
}

fn cb_add_event_listener<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let ty = args
        .get(0)
        .to_string(scope)
        .map(|s| s.to_rust_string_lossy(scope))
        .unwrap_or_default();
    let cb = args.get(1);
    if ty.is_empty() || !cb.is_function() {
        rv.set(v8::undefined(scope).into());
        return;
    }
    let capture = capture_flag(scope, args.get(2));
    let target = classify_target(scope, &args);
    let (kind, idx) = match target {
        EvTarget::Window => (0u8, 0u32),
        EvTarget::Document => (1, 0),
        EvTarget::Element(i) => (2, i),
    };
    let st = unsafe { state_of(&args) };
    // addEventListener with the same (target, type, callback, capture) is a
    // no-op per spec — dedup on callback identity.
    let dup = st.listeners.iter().any(|l| {
        l.target_kind == kind
            && l.element_index == idx
            && l.type_ == ty
            && l.capture == capture
            && Local::new(scope, l.callback.clone()).strict_equals(cb)
    });
    if !dup {
        st.listeners.push(ListenerEntry {
            target_kind: kind,
            element_index: idx,
            type_: ty,
            callback: v8::Global::new(scope, cb.cast::<Function>()),
            capture,
        });
    }
    rv.set(v8::undefined(scope).into());
}

fn cb_remove_event_listener<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let ty = args
        .get(0)
        .to_string(scope)
        .map(|s| s.to_rust_string_lossy(scope))
        .unwrap_or_default();
    let cb = args.get(1);
    if ty.is_empty() || !cb.is_function() {
        rv.set(v8::undefined(scope).into());
        return;
    }
    let capture = capture_flag(scope, args.get(2));
    let target = classify_target(scope, &args);
    let (kind, idx) = match target {
        EvTarget::Window => (0u8, 0u32),
        EvTarget::Document => (1, 0),
        EvTarget::Element(i) => (2, i),
    };
    let st = unsafe { state_of(&args) };
    st.listeners.retain(|l| {
        !(l.target_kind == kind
            && l.element_index == idx
            && l.type_ == ty
            && l.capture == capture
            && Local::new(scope, l.callback.clone()).strict_equals(cb))
    });
    rv.set(v8::undefined(scope).into());
}

/// `target.dispatchEvent(event)` — synchronous delivery through the listener
/// registry. Browsers dispatch at-target + bubble-to-window; the bridge DOM
/// is read-only so there is no tree walk, just the registered listeners.
fn cb_dispatch_event<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let event = args.get(0);
    let Some(ev_obj) = event.to_object(scope) else {
        rv.set(v8::Boolean::new(scope, false).into());
        return;
    };
    let ty = ev_obj
        .get(scope, sv(scope, "type"))
        .and_then(|v| v.to_string(scope))
        .map(|s| s.to_rust_string_lossy(scope))
        .unwrap_or_default();
    if ty.is_empty() {
        rv.set(v8::Boolean::new(scope, false).into());
        return;
    }
    let target = classify_target(scope, &args);
    let this_v = args.this().into();
    // event.target defaults to the dispatch target (host-made events start
    // with target null).
    let has_target = ev_obj
        .get(scope, sv(scope, "target"))
        .map(|v| !v.is_null() && !v.is_undefined())
        .unwrap_or(false);
    if !has_target {
        let _ = ev_obj.set(scope, sv(scope, "target"), this_v);
    }
    let bubbles = ev_obj
        .get(scope, sv(scope, "bubbles"))
        .map(|v| v.is_true())
        .unwrap_or(false);
    let phases = {
        let st = unsafe { state_of(&args) };
        event_phases(st, target, &ty, bubbles)
    };
    run_event_phases(scope, phases, this_v, ev_obj);
    rv.set(v8::Boolean::new(scope, true).into());
}

/// Host-built event object for engine-dispatched events (scroll, popstate):
/// the same shape the JS-constructed Event carries, but `isTrusted` — the
/// engine, not page script, fired it.
fn simple_event<'s, 'i>(scope: &mut PinScope<'s, 'i>, ty: &str) -> Local<'s, Object> {
    let e = v8::Object::new(scope);
    set_prop(scope, e, "type", sv(scope, ty));
    set_prop(scope, e, "bubbles", v8::Boolean::new(scope, false).into());
    set_prop(scope, e, "cancelable", v8::Boolean::new(scope, false).into());
    set_prop(scope, e, "composed", v8::Boolean::new(scope, false).into());
    set_prop(scope, e, "defaultPrevented", v8::Boolean::new(scope, false).into());
    set_prop(scope, e, "isTrusted", v8::Boolean::new(scope, true).into());
    set_prop(scope, e, "target", v8::null(scope).into());
    set_prop(scope, e, "currentTarget", v8::null(scope).into());
    set_prop(scope, e, "__seStop", v8::Boolean::new(scope, false).into());
    set_prop(scope, e, "__seStopNow", v8::Boolean::new(scope, false).into());
    set_prop(scope, e, "timeStamp", v8::Number::new(scope, 0.0).into());
    for m in ["preventDefault", "stopPropagation", "stopImmediatePropagation"] {
        if let Some(f) = v8::Function::new(scope, cb_noop) {
            set_prop(scope, e, m, f.into());
        }
    }
    e
}

/// Shared JS trampoline for `new Event(type, opts)` / `new CustomEvent(...)`.
fn build_event_obj<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    ty: Local<'s, Value>,
    opts: Local<'s, Value>,
    detail: Local<'s, Value>,
) -> Local<'s, Value> {
    let shim = r#"
        (function(ty, opts, detail) {
            const e = {};
            opts = opts || {};
            e.type = String(ty);
            e.bubbles = !!opts.bubbles;
            e.cancelable = !!opts.cancelable;
            e.composed = !!opts.composed;
            e.defaultPrevented = false;
            e.isTrusted = false;
            e.target = null;
            e.currentTarget = null;
            e.__seStop = false;
            e.__seStopNow = false;
            e.timeStamp = performance.now();
            e.preventDefault = function() { if (e.cancelable) e.defaultPrevented = true; };
            e.stopPropagation = function() { e.__seStop = true; };
            e.stopImmediatePropagation = function() { e.__seStopNow = true; e.__seStop = true; };
            if (detail !== undefined) e.detail = detail;
            return e;
        })
    "#;
    let code = v8::String::new(scope, shim).expect("string alloc");
    let wrapper = v8::Script::compile(scope, code, None)
        .and_then(|s| s.run(scope))
        .map(|v| v.cast::<Function>());
    let undefined = v8::undefined(scope).into();
    match wrapper {
        Some(wrapper) => {
            let call_args = &[ty, opts, detail];
            let recv = undefined;
            match wrapper.call(scope, recv, call_args) {
                Some(result) => result,
                None => v8::undefined(scope).into(),
            }
        }
        None => v8::undefined(scope).into(),
    }
}

fn cb_event_ctor<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let detail = v8::undefined(scope).into();
    rv.set(build_event_obj(scope, args.get(0), args.get(1), detail));
}

fn cb_custom_event_ctor<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let detail = args
        .get(1)
        .to_object(scope)
        .and_then(|o| o.get(scope, sv(scope, "detail")))
        .unwrap_or_else(|| v8::null(scope).into());
    rv.set(build_event_obj(scope, args.get(0), args.get(1), detail));
}

/// In-session navigation core shared by location.assign/replace, the
/// location href/component setters, window.location=, and
/// history.pushState/replaceState: resolve the target (empty/absent =
/// current page), update the history stack, and move `State.page_url` —
/// the single source of truth every location accessor derives from
/// (iteration 24: location's props were plain data props that went stale
/// on assignment, and window.location= could replace the object with a
/// string, destroying the whole API). A real document load can't suspend
/// an eval — se-serve's `goto` owns loads — and fetch() re-guards
/// whatever URL lands here at entry (bug 28), so a refused target in
/// page_url is inert state, never a dial.
fn navigate_core(
    st: &mut State,
    raw: Option<String>,
    state: Option<v8::Global<Value>>,
    replace: bool,
) {
    let new_url = match raw {
        Some(r) if !r.is_empty() => absolutize(&r, &st.page_url),
        _ => st.page_url.clone(),
    };
    let cur = st.history_pos;
    if replace {
        if cur < st.history_stack.len() {
            st.history_stack[cur] = new_url.clone();
            st.history_states[cur] = state;
        }
    } else {
        st.history_stack.truncate(cur + 1);
        st.history_stack.push(new_url.clone());
        st.history_states.truncate(cur + 1);
        st.history_states.push(state);
        st.history_pos = cur + 1;
    }
    st.page_url = new_url;
}

/// Shared core of history.pushState / history.replaceState (spec: same
/// algorithm, differing only in whether the current entry is replaced).
fn history_push_replace<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
    replace: bool,
) {
    let state_v = args.get(0);
    let url_raw = args
        .get(2)
        .to_string(scope)
        .map(|s| s.to_rust_string_lossy(scope));
    let state_g = if state_v.is_undefined() || state_v.is_null() {
        None
    } else {
        Some(v8::Global::new(scope, state_v))
    };
    let st = unsafe { state_of(&args) };
    navigate_core(st, url_raw, state_g, replace);
    // Per spec, pushState/replaceState do NOT fire popstate.
    rv.set(v8::undefined(scope).into());
}

fn cb_history_push_state<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    rv: ReturnValue<'s, Value>,
) {
    history_push_replace(scope, args, rv, false);
}

fn cb_history_replace_state<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    rv: ReturnValue<'s, Value>,
) {
    history_push_replace(scope, args, rv, true);
}

/// Move within the session history stack; on a real move, move page_url
/// (location's accessors derive everything from it) and fire popstate
/// carrying the restored state. No document load — the eval tier can't
/// suspend for navigation.
fn history_go_to<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: &FunctionCallbackArguments<'s>,
    new_pos: usize,
) {
    let state_g = {
        let st = unsafe { state_of(args) };
        if new_pos == st.history_pos || new_pos >= st.history_stack.len() {
            return;
        }
        st.history_pos = new_pos;
        st.page_url = st.history_stack[new_pos].clone();
        st.history_states.get(new_pos).cloned().flatten()
    };
    let context = scope.get_current_context();
    let global = context.global(nullscope(scope)).into();
    let ev = simple_event(scope, "popstate");
    let _ = ev.set(scope, sv(scope, "target"), global);
    match state_g {
        Some(g) => set_prop(scope, ev, "state", Local::new(scope, g)),
        None => set_prop(scope, ev, "state", v8::null(scope).into()),
    }
    let phases = {
        let st = unsafe { state_of(args) };
        event_phases(st, EvTarget::Window, "popstate", false)
    };
    run_event_phases(scope, phases, global, ev);
}

fn cb_history_back<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let pos = {
        let st = unsafe { state_of(&args) };
        st.history_pos.saturating_sub(1)
    };
    history_go_to(scope, &args, pos);
    rv.set(v8::undefined(scope).into());
}

fn cb_history_forward<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let pos = {
        let st = unsafe { state_of(&args) };
        (st.history_pos + 1).min(st.history_stack.len().saturating_sub(1))
    };
    history_go_to(scope, &args, pos);
    rv.set(v8::undefined(scope).into());
}

fn cb_history_go<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let delta = args
        .get(0)
        .to_number(scope)
        .map(|n| n.value() as i64)
        .unwrap_or(0);
    let pos = {
        let st = unsafe { state_of(&args) };
        (st.history_pos as i64 + delta)
            .clamp(0, st.history_stack.len() as i64 - 1)
            .max(0) as usize
    };
    history_go_to(scope, &args, pos);
    rv.set(v8::undefined(scope).into());
}

fn cb_history_length<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let len = {
        let st = unsafe { state_of(&args) };
        st.history_stack.len()
    };
    rv.set(v8::Number::new(scope, len as f64).into());
}

fn cb_history_state<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let g = {
        let st = unsafe { state_of(&args) };
        st.history_states.get(st.history_pos).cloned().flatten()
    };
    match g {
        Some(g) => rv.set(Local::new(scope, g)),
        None => rv.set(v8::null(scope).into()),
    }
}

/// `location.assign(url)` — in-session navigation: a new history entry and
/// a rewritten location. (A real load can't suspend an eval; se-serve's
/// `goto` is the document-load path.)
fn cb_location_assign<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    rv: ReturnValue<'s, Value>,
) {
    location_navigate(scope, args, rv, false);
}

/// `location.replace(url)` — like assign but swaps the current entry.
fn cb_location_replace<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    rv: ReturnValue<'s, Value>,
) {
    location_navigate(scope, args, rv, true);
}

fn location_navigate<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
    replace: bool,
) {
    let raw = args
        .get(0)
        .to_string(scope)
        .map(|s| s.to_rust_string_lossy(scope));
    let st = unsafe { state_of(&args) };
    navigate_core(st, raw, None, replace);
    rv.set(v8::undefined(scope).into());
}

// ── location accessors ───────────────────────────────────────────────────────
// Every string prop of the location object is an accessor pair deriving
// from `State.page_url` (the single source of truth): getters re-parse per
// read so history moves / href= / component sets are instantly coherent,
// and setters substitute one component into the parsed current URL then run
// the same navigate_core as location.assign — never a hand-maintained prop
// bag that can go stale (iteration 24: assignment rewrote ONE data prop,
// leaving the other eight lying, and relative fetch() resolved against the
// pre-assignment page).

/// Shared getter shape: parse page_url, hand one component to `pick`.
fn loc_part_rv<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: &FunctionCallbackArguments<'s>,
    rv: &mut ReturnValue<'s, Value>,
    pick: impl Fn(&LocationParts) -> &str,
) {
    let st = unsafe { state_of(args) };
    let parts = LocationParts::parse(&st.page_url);
    let v = pick(&parts).to_string();
    rv.set(sv(scope, &v).into());
}

/// Shared setter shape: substitute into the parsed current URL, navigate.
/// A no-op when page_url isn't absolute-parseable (matches the getter
/// fallback where every part but href is empty).
fn loc_set_navigate<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: &FunctionCallbackArguments<'s>,
    subst: impl FnOnce(&mut url::Url, &str),
) {
    let raw = args
        .get(0)
        .to_string(scope)
        .map(|s| s.to_rust_string_lossy(scope))
        .unwrap_or_default();
    let st = unsafe { state_of(args) };
    let Ok(mut u) = url::Url::parse(&st.page_url) else {
        return;
    };
    subst(&mut u, &raw);
    navigate_core(st, Some(u.into()), None, false);
}

macro_rules! loc_getter {
    ($name:ident, $prop:ident) => {
        fn $name<'s, 'i>(
            scope: &mut PinScope<'s, 'i>,
            args: FunctionCallbackArguments<'s>,
            mut rv: ReturnValue<'s, Value>,
        ) {
            loc_part_rv(scope, &args, &mut rv, |p| &p.$prop);
        }
    };
}

loc_getter!(cb_loc_get_href, href);
loc_getter!(cb_loc_get_protocol, protocol);
loc_getter!(cb_loc_get_host, host);
loc_getter!(cb_loc_get_hostname, hostname);
loc_getter!(cb_loc_get_port, port);
loc_getter!(cb_loc_get_pathname, pathname);
loc_getter!(cb_loc_get_search, search);
loc_getter!(cb_loc_get_hash, hash);
loc_getter!(cb_loc_get_origin, origin);

/// `location.href = x` — full navigation, same as assign.
fn cb_loc_set_href<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    _rv: ReturnValue<'s, Value>,
) {
    let raw = args
        .get(0)
        .to_string(scope)
        .map(|s| s.to_rust_string_lossy(scope));
    let st = unsafe { state_of(&args) };
    navigate_core(st, raw, None, false);
}

/// `location.protocol = x` — scheme substitute; no-op when the scheme is
/// unparsable (url's setter reports Err and leaves the URL untouched, and
/// Chrome likewise ignores a bad-scheme set).
fn cb_loc_set_protocol<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    _rv: ReturnValue<'s, Value>,
) {
    loc_set_navigate(scope, &args, |u, v| {
        let _ = u.set_scheme(v.trim_end_matches(':'));
    });
}

/// `location.host = x` — host[:port]; an rsplit on ':' keeps an IPv6
/// literal's inner colons out of the port slot ('[::1]' has no ':' after
/// the bracket close, so the split only fires on a real port suffix).
fn cb_loc_set_host<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    _rv: ReturnValue<'s, Value>,
) {
    loc_set_navigate(scope, &args, |u, v| {
        let (h, p) = match v.rsplit_once(':') {
            Some((h, p)) if !h.ends_with(']') => (h, Some(p)),
            _ => (v, None),
        };
        let _ = u.set_host(Some(h));
        if let Some(p) = p {
            let _ = u.set_port(if p.is_empty() { None } else { p.parse().ok() });
        }
    });
}

fn cb_loc_set_hostname<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    _rv: ReturnValue<'s, Value>,
) {
    loc_set_navigate(scope, &args, |u, v| {
        let _ = u.set_host(Some(v));
    });
}

/// `location.port = x` — empty clears the port (Chrome semantics).
fn cb_loc_set_port<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    _rv: ReturnValue<'s, Value>,
) {
    loc_set_navigate(scope, &args, |u, v| {
        let _ = u.set_port(if v.is_empty() {
            None
        } else {
            v.parse().ok()
        });
    });
}

fn cb_loc_set_pathname<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    _rv: ReturnValue<'s, Value>,
) {
    loc_set_navigate(scope, &args, |u, v| u.set_path(v));
}

/// `location.search = x` — leading '?' tolerated; empty clears.
fn cb_loc_set_search<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    _rv: ReturnValue<'s, Value>,
) {
    loc_set_navigate(scope, &args, |u, v| {
        let v = v.strip_prefix('?').unwrap_or(v);
        u.set_query(if v.is_empty() { None } else { Some(v) });
    });
}

/// `location.hash = x` — leading '#' tolerated; empty clears.
fn cb_loc_set_hash<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    _rv: ReturnValue<'s, Value>,
) {
    loc_set_navigate(scope, &args, |u, v| {
        let v = v.strip_prefix('#').unwrap_or(v);
        u.set_fragment(if v.is_empty() { None } else { Some(v) });
    });
}

/// `window.location` getter — returns the hidden singleton location object
/// so assignment can't destroy the API (iteration 24: `window.location =
/// x` replaced the object with a string under the data-prop shape).
fn cb_window_location_get<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let context = scope.get_current_context();
    let global = context.global(nullscope(scope));
    if let Some(loc) = global.get(scope, sv(scope, "__seLocation")) {
        rv.set(loc);
    }
}

/// `window.location = x` — navigates, exactly like location.href = x
/// (Chrome's Location object is unforgeable + its setter navigates).
fn cb_window_location_set<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    _rv: ReturnValue<'s, Value>,
) {
    let raw = args
        .get(0)
        .to_string(scope)
        .map(|s| s.to_rust_string_lossy(scope));
    let st = unsafe { state_of(&args) };
    navigate_core(st, raw, None, false);
}

/// `window.open` — v1 shape: popups are blocked without a user gesture in
/// a fresh Chrome profile, which returns null. Documented; a real
/// window-manager is a se-serve concern, not the eval tier's.
fn cb_window_open<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    rv.set(v8::null(scope).into());
}

// ── matchMedia heuristics ────────────────────────────────────────────────────
// No layout, but the viewport IS a real constant (innerWidth/innerHeight), so
// the common probe queries evaluate for real against it. Unrecognized
// features conservatively report no-match (the fresh-Chrome default for the
// prefers-* family this engine's profile claims).

fn media_cond_holds(cond: &str, w: f64, h: f64) -> bool {
    let c = cond
        .trim()
        .trim_matches(|ch| ch == '(' || ch == ')')
        .trim();
    let c = c.strip_prefix("only ").unwrap_or(c).trim();
    match c {
        "screen" | "all" => return true,
        "print" => return false,
        _ => {}
    }
    let (name, val) = match c.split_once(':') {
        Some((n, v)) => (n.trim(), v.trim()),
        None => return false,
    };
    let px: Option<f64> = val.trim_end_matches("px").trim().parse().ok();
    match name {
        "min-width" => px.map_or(true, |n| w >= n),
        "max-width" => px.map_or(true, |n| w <= n),
        "width" => px.map_or(true, |n| (w - n).abs() < f64::EPSILON),
        "min-height" => px.map_or(true, |n| h >= n),
        "max-height" => px.map_or(true, |n| h <= n),
        "height" => px.map_or(true, |n| (h - n).abs() < f64::EPSILON),
        "orientation" => match val {
            "landscape" => w >= h,
            "portrait" => h > w,
            _ => true,
        },
        "prefers-color-scheme" => val == "light",
        "prefers-reduced-motion" => val == "no-preference",
        "hover" | "any-hover" => val == "hover",
        "pointer" | "any-pointer" => val == "fine",
        "display-mode" => val == "browser",
        "color-gamut" => val == "srgb",
        "update" => val == "fast",
        "overflow-block" => val == "scroll",
        "overflow-inline" => val == "none",
        _ => false,
    }
}

fn eval_media_query(query: &str, w: f64, h: f64) -> bool {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return true;
    }
    q.split(',').any(|alt| {
        let alt = alt.trim();
        if let Some(rest) = alt.strip_prefix("not ") {
            !rest.trim().split(" and ").all(|c| media_cond_holds(c, w, h))
        } else {
            alt.split(" and ").all(|c| media_cond_holds(c, w, h))
        }
    })
}

// ── serviceWorker stub ───────────────────────────────────────────────────────
// Pages `await navigator.serviceWorker.register/ready` during init; a
// rejecting or never-settling promise breaks those paths. Everything
// resolves with a shaped-but-empty registration; `controller` stays null
// (no worker controls this page — honest, and what a fresh tab reports).

fn sw_registration<'s, 'i>(scope: &mut PinScope<'s, 'i>, scope_url: &str) -> Local<'s, Object> {
    let r = v8::Object::new(scope);
    set_prop(scope, r, "scope", sv(scope, scope_url));
    set_prop(scope, r, "active", v8::null(scope).into());
    set_prop(scope, r, "waiting", v8::null(scope).into());
    set_prop(scope, r, "installing", v8::null(scope).into());
    set_prop(scope, r, "updateViaCache", sv(scope, "imports"));
    let update = v8::FunctionTemplate::builder(cb_sw_update)
        .build(scope)
        .get_function(scope);
    if let Some(f) = update {
        set_prop(scope, r, "update", f.into());
    }
    let unregister = v8::FunctionTemplate::builder(cb_sw_unregister)
        .build(scope)
        .get_function(scope);
    if let Some(f) = unregister {
        set_prop(scope, r, "unregister", f.into());
    }
    for m in ["addEventListener", "removeEventListener", "postMessage"] {
        if let Some(f) = v8::Function::new(scope, cb_noop) {
            set_prop(scope, r, m, f.into());
        }
    }
    r
}

fn cb_sw_update<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    match v8::PromiseResolver::new(scope) {
        Some(resolver) => {
            let _ = resolver.resolve(scope, v8::undefined(scope).into());
            rv.set(resolver.get_promise(scope).into());
        }
        None => rv.set(v8::undefined(scope).into()),
    }
}

fn cb_sw_unregister<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    match v8::PromiseResolver::new(scope) {
        Some(resolver) => {
            let _ = resolver.resolve(scope, v8::Boolean::new(scope, true).into());
            rv.set(resolver.get_promise(scope).into());
        }
        None => rv.set(v8::undefined(scope).into()),
    }
}

/// `navigator.serviceWorker.register(script, opts)` — resolves with a fake
/// registration whose scope is opts.scope (resolved against the page) or
/// the script URL's directory, per spec.
fn cb_sw_register<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let script_raw = args
        .get(0)
        .to_string(scope)
        .map(|s| s.to_rust_string_lossy(scope))
        .unwrap_or_default();
    let opts_scope = args
        .get(1)
        .to_object(scope)
        .and_then(|o| o.get(scope, sv(scope, "scope")))
        .and_then(|v| v.to_string(scope))
        .map(|s| s.to_rust_string_lossy(scope));
    let (script, scope_url) = {
        let st = unsafe { state_of(&args) };
        let script = absolutize(&script_raw, &st.page_url);
        let default_scope = script
            .rsplit_once('/')
            .map(|(d, _)| format!("{d}/"))
            .unwrap_or_else(|| script.clone());
        let scope_url = opts_scope
            .filter(|s| !s.is_empty())
            .map(|s| absolutize(&s, &st.page_url))
            .unwrap_or(default_scope);
        (script, scope_url)
    };
    let _ = script;
    let reg = sw_registration(scope, &scope_url);
    let _ = resolver.resolve(scope, reg.into());
    rv.set(resolver.get_promise(scope).into());
}

fn cb_sw_get_registration<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    match v8::PromiseResolver::new(scope) {
        Some(resolver) => {
            let _ = resolver.resolve(scope, v8::undefined(scope).into());
            rv.set(resolver.get_promise(scope).into());
        }
        None => rv.set(v8::undefined(scope).into()),
    }
}

fn cb_sw_get_registrations<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    match v8::PromiseResolver::new(scope) {
        Some(resolver) => {
            let arr = v8::Array::new(scope, 0);
            let _ = resolver.resolve(scope, arr.into());
            rv.set(resolver.get_promise(scope).into());
        }
        None => rv.set(v8::undefined(scope).into()),
    }
}

/// `navigator.serviceWorker.ready` — an accessor whose getter hands back a
/// fresh already-resolved promise carrying a shaped registration (the
/// identity of successive `ready` reads barely matters to page code).
fn cb_sw_ready<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let scope_url = {
        let st = unsafe { state_of(&args) };
        let base = url::Url::parse(&st.page_url).ok();
        base.map(|u| format!("{}/", u.origin().ascii_serialization()))
            .unwrap_or_else(|| "/".to_string())
    };
    let reg = sw_registration(scope, &scope_url);
    let _ = resolver.resolve(scope, reg.into());
    rv.set(resolver.get_promise(scope).into());
}

/// `el.innerHTML` getter — the subtree's serialized HTML. Live: reads the
/// current tree (re-parses if the cached doc was invalidated by a prior
/// mutation), so it reflects mutations made earlier in this eval.
fn cb_inner_html_get<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let v = {
        let st = unsafe { state_of(&args) };
        match this_element_index(scope, &args).and_then(|i| st.elements.get(i)) {
            Some(el) => el.html.clone(),
            None => String::new(),
        }
    };
    rv.set(sv(scope, &v));
}

/// `el.innerHTML = html` — replace the subtree. Lands in the live tree and
/// invalidates the cached parse, so a subsequent `querySelector` re-parses
/// and sees the new node. Fragment-scoped/synthetic wrappers (no node id)
/// ignore the write, like a real detached node.
fn cb_inner_html_set<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(html) = arg_string(scope, &args, 0) else { return };
    let idx = match this_element_index(scope, &args) {
        Some(i) => i,
        None => return,
    };
    let st = unsafe { state_of(&args) };
    if st.mutate(idx, |doc, id| doc.set_inner_html(id, &html)) {
        // On-tree element: resnapshot from the mutated tree.
        if let Some(sel) = st.id_selector(idx) {
            st.resnapshot_after_mutate(idx, &sel);
        }
        // Live MutationObserver delivery (firing 24): a wholesale subtree
        // replace is a childList record. The bridge re-parses rather than
        // diffs, so added/removed node lists are empty (documented floor);
        // scripts keying on "did the callback fire?" — the common
        // wait-for-node idiom — get what they need. The target rides the
        // freshest snapshot available.
        let target = st.elements.get(idx).cloned();
        if let Some(t) = target {
            st.record_mutation(Some(idx), t, MUT_CHILD_LIST, None, None, Vec::new(), Vec::new());
        }
        schedule_observer_flush(st, scope, &args, &mut rv);
    } else {
        // Synthetic/off-document wrapper (createElement, no node id): a real
        // detached node's innerHTML is settable but changes nothing until
        // appended. Stash the markup on the JS object so appendChild can
        // serialize the child with this content.
        let this = args.this();
        let _ = this.set(scope, sv(scope, "_seHtml"), sv(scope, &html));
    }
}

/// `el.textContent` getter — concatenated subtree text (live read).
fn cb_text_content_get<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let v = {
        let st = unsafe { state_of(&args) };
        match this_element_index(scope, &args).and_then(|i| st.elements.get(i)) {
            Some(el) => el.text.clone(),
            None => String::new(),
        }
    };
    rv.set(sv(scope, &v));
}

/// `el.textContent = text` — replace the subtree with a single text node.
fn cb_text_content_set<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(text) = arg_string(scope, &args, 0) else { return };
    let idx = match this_element_index(scope, &args) {
        Some(i) => i,
        None => return,
    };
    let st = unsafe { state_of(&args) };
    // Pre-mutation text, for observers that requested characterDataOldValue.
    let old_text = st.elements.get(idx).map(|e| e.text.clone());
    if st.mutate(idx, |doc, id| doc.set_text(id, &text)) {
        if let Some(sel) = st.id_selector(idx) {
            st.resnapshot_after_mutate(idx, &sel);
        }
        if let Some(t) = st.elements.get(idx).cloned() {
            st.record_mutation(
                Some(idx),
                t,
                MUT_CHARACTER_DATA,
                None,
                old_text,
                Vec::new(),
                Vec::new(),
            );
        }
        schedule_observer_flush(st, scope, &args, &mut rv);
    } else if let Some(el) = st.elements.get_mut(idx) {
        // Synthetic/off-document wrapper (createElement, no node id): the
        // text can't reach a live tree, but the wrapper's snapshot rides
        // the next graft — stash it pre-escaped (textContent semantics:
        // markup must not re-parse as tags) so `appendChild` serializes
        // the child WITH this content and accessors read it back.
        el.text = text.clone();
        el.html = escape_text_node(&text);
    }
}

/// `el.outerHTML` getter — the element serialized with its own tag. Read-only
/// (the DOM has an outerHTML setter, but the bridge treats it as get-only; no
/// provider sets it and supporting a self-replace complicates node identity).
fn cb_outer_html_get<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let v = {
        let st = unsafe { state_of(&args) };
        match this_element_index(scope, &args).and_then(|i| st.elements.get(i)) {
            Some(el) => el.to_outer_html(),
            None => String::new(),
        }
    };
    rv.set(sv(scope, &v));
}

/// `parent.appendChild(child)` — graft `child` under `parent`. `child` may be
/// an element wrapper (re-parsed and grafted) or a text node (`{nodeType:3,
/// textContent}` — the shape `createTextNode` would produce). Returns the
/// appended child, per DOM. Mutation lands in the live tree; the cached parse
/// is invalidated so later queries re-parse. Appending a child that already
/// has a parent moves it (a detach-then-graft); the bridge re-parses the
/// child, so a fresh node is always grafted.
fn cb_append_child<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let child = args.get(0);
    let parent_idx = match this_element_index(scope, &args) {
        Some(i) => i,
        None => {
            rv.set(nullv(scope));
            return;
        }
    };
    let st = unsafe { state_of(&args) };

    // Text node: `{nodeType:3, textContent}` — append a bare text node.
    let child_obj = child.to_object(scope);
    let is_text = child_obj
        .and_then(|o| obj_num(scope, o, "nodeType"))
        .map(|n| n == 3.0)
        .unwrap_or(false);
    if is_text {
        let text = child_obj.and_then(|o| obj_str(scope, o, "textContent")).unwrap_or_default();
        if st.mutate(parent_idx, |doc, id| doc.append_text(id, &text).is_some()) {
            if let Some(sel) = st.id_selector(parent_idx) {
                st.resnapshot_after_mutate(parent_idx, &sel);
            }
            if let Some(t) = st.elements.get(parent_idx).cloned() {
                st.record_mutation(
                    Some(parent_idx),
                    t,
                    MUT_CHILD_LIST,
                    None,
                    None,
                    Vec::new(),
                    Vec::new(),
                );
            }
            schedule_observer_flush(st, scope, &args, &mut rv);
        }
        rv.set(child);
        return;
    }

    // Element wrapper: serialize and graft. A synthetic wrapper (createElement)
    // carries its innerHTML on the JS object as `_seHtml` (its snapshot is
    // empty); read it back so the graft includes the set content.
    let cidx = value_element_index(scope, child) as usize;
    let stash = child_obj.and_then(|o| obj_str(scope, o, "_seHtml"));
    let html = match st.elements.get(cidx) {
        Some(el) => el.to_outer_html_with(stash.as_deref()),
        None => {
            rv.set(nullv(scope));
            return;
        }
    };
    if st.mutate(parent_idx, |doc, id| doc.append_html(id, &html).is_some()) {
        if let Some(sel) = st.id_selector(parent_idx) {
            st.resnapshot_after_mutate(parent_idx, &sel);
        }
        // The record names the actual appended node object (held as a
        // Global so it survives until the pump-drained flush).
        let child_g = v8::Global::new(scope, child);
        if let Some(t) = st.elements.get(parent_idx).cloned() {
            st.record_mutation(
                Some(parent_idx),
                t,
                MUT_CHILD_LIST,
                None,
                None,
                vec![child_g],
                Vec::new(),
            );
        }
        schedule_observer_flush(st, scope, &args, &mut rv);
    }
    rv.set(child);
}

/// `el.remove()` — detach the subtree. Later queries no longer see it.
fn cb_remove<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let idx = match this_element_index(scope, &args) {
        Some(i) => i,
        None => return,
    };
    let st = unsafe { state_of(&args) };
    // A removal record's spec target is the PARENT. Resolve the parent's
    // wrapper index AND snapshot BEFORE the node detaches — after `remove`
    // the parent may have no resident wrapper at all (removing the only
    // queried `<li>` from a never-queried `<ul>`), and a post-hoc elements
    // lookup could never name it.
    let node_id = st.elements.get(idx).and_then(|e| e.node_id);
    // `doc()` takes &mut self, so each borrow ends before the next use.
    let parent_id = node_id.and_then(|nid| {
        st.doc()
            .node(nid)
            .and_then(|n| n.parent_element())
            .map(|p| p.id())
    });
    let (parent_idx, parent_data) = match parent_id {
        Some(pid) => {
            let pos = st.elements.iter().position(|e| e.node_id == Some(pid));
            let data = st.doc().node(pid).map(|n| ElementData::from_node(&n));
            (pos, data)
        }
        None => (None, None),
    };
    let removed_g = v8::Global::new(scope, args.this().cast::<Value>());
    if st.mutate(idx, |doc, id| doc.remove(id)) {
        if let Some(t) = parent_data {
            st.record_mutation(
                parent_idx,
                t,
                MUT_CHILD_LIST,
                None,
                None,
                Vec::new(),
                vec![removed_g],
            );
        }
        schedule_observer_flush(st, scope, &args, &mut rv);
    }
}

/// `el.click()` — dispatch a bubbling `MouseEvent` through the firing-15
/// event registry so handlers registered with addEventListener run. The
/// bridge has no real layout/hit-testing, so `click` fires the registered
/// handler directly on the element, then bubbles to document and window (the
/// bubble endpoint), matching a real click's listener-observable path.
fn cb_click<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    _rv: ReturnValue<'s, Value>,
) {
    let idx = match this_element_index(scope, &args) {
        Some(i) => i,
        None => return,
    };
    // A trusted click fully bubbles through the bridge's endpoint registry:
    // window capture → the element → document → window (the bubble endpoint).
    // The element and document stops report their own object as currentTarget;
    // window stops report window. Build each phase from the listener registry.
    let (win_cap, el_cbs, doc_cbs, win_bub) = {
        let st = unsafe { state_of(&args) };
        let pick = |kind: u8, capture: Option<bool>| {
            st.listeners
                .iter()
                .filter(|l| {
                    l.target_kind == kind
                        && l.type_ == "click"
                        && capture.map_or(true, |c| l.capture == c)
                })
                .map(|l| l.callback.clone())
                .collect::<Vec<_>>()
        };
        (
            pick(0, Some(true)),
            // element listeners: only those on THIS element index
            st.listeners
                .iter()
                .filter(|l| l.target_kind == 2 && l.type_ == "click" && l.element_index == idx as u32)
                .map(|l| l.callback.clone())
                .collect::<Vec<_>>(),
            pick(1, None),
            pick(0, Some(false)),
        )
    };
    if win_cap.is_empty() && el_cbs.is_empty() && doc_cbs.is_empty() && win_bub.is_empty() {
        return;
    }
    let context = scope.get_current_context();
    let global: Local<'_, Value> = context.global(nullscope(scope)).into();
    let document = global
        .to_object(scope)
        .and_then(|g| g.get(scope, sv(scope, "document")))
        .unwrap_or_else(|| nullv(scope));
    // The clicked element (target / element-phase currentTarget).
    let target = {
        let st = unsafe { state_of(&args) };
        st.elements
            .get(idx)
            .cloned()
            .map(|data| wrap_element(scope, &args, data).into())
            .unwrap_or_else(|| nullv(scope))
    };
    let ev = simple_event(scope, "click");
    set_prop(scope, ev, "bubbles", v8::Boolean::new(scope, true).into());
    set_prop(scope, ev, "cancelable", v8::Boolean::new(scope, true).into());
    set_prop(scope, ev, "button", v8::Number::new(scope, 0.0).into());
    let _ = ev.set(scope, sv(scope, "target"), target);
    for (is_window, current, cbs) in [
        (true, global, win_cap),
        (false, target, el_cbs),
        (false, document, doc_cbs),
        (true, global, win_bub),
    ] {
        if cbs.is_empty() {
            continue;
        }
        run_event_phases(scope, vec![(is_window, cbs)], current, ev);
    }
}

fn cb_get_attribute<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(name) = arg_string(scope, &args, 0) else {
        rv.set(nullv(scope));
        return;
    };
    let value = {
        let st = unsafe { state_of(&args) };
        match this_element_index(scope, &args).and_then(|i| st.elements.get(i)) {
            Some(el) => el.attr(&name).map(|v| v.to_string()),
            None => None,
        }
    };
    match value {
        Some(v) => rv.set(sv(scope, &v)),
        None => rv.set(nullv(scope)),
    }
}

/// `el.setAttribute(name, value)` — the DOM attribute mutator over the live
/// tree. Resident element: `se_dom::Document::set_attr` (which rebuilds the
/// node value so scraper's memoized id/class caches refresh, keeping `#id` /
/// `.class` selector matching honest), then the wrapper snapshot is re-read
/// through the STABLE node id — not `id_selector`, which re-selects by the
/// pre-mutation id and would silently miss when the mutated attribute IS the
/// id. Synthetic wrapper (createElement, not yet grafted): the attribute
/// lands on the snapshot's own list, which `appendChild`'s
/// `to_outer_html_with` serialization reads — so the attribute rides the
/// graft, exactly like a real detached node's attribute rides its append.
fn cb_set_attribute<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(name) = arg_string(scope, &args, 0) else { return };
    let value = arg_string(scope, &args, 1).unwrap_or_default();
    let idx = match this_element_index(scope, &args) {
        Some(i) => i,
        None => return,
    };
    let st = unsafe { state_of(&args) };
    // Pre-mutation value, for observers that requested attributeOldValue.
    let old = st.elements.get(idx).and_then(|e| e.attr(&name).map(|s| s.to_string()));
    let node_id = st.elements.get(idx).and_then(|e| e.node_id);
    if st.mutate(idx, |doc, id| doc.set_attr(id, &name, &value)) {
        let data = node_id
            .and_then(|nid| st.doc().node(nid))
            .map(|n| ElementData::from_node(&n));
        if let Some(d) = data {
            st.elements[idx] = d;
        }
        if let Some(t) = st.elements.get(idx).cloned() {
            st.record_mutation(
                Some(idx),
                t,
                MUT_ATTRIBUTES,
                Some(name),
                old,
                Vec::new(),
                Vec::new(),
            );
        }
        schedule_observer_flush(st, scope, &args, &mut rv);
    } else if let Some(el) = st.elements.get_mut(idx) {
        // No writeback latch: the document serialization is unchanged — only
        // the pending graft's serialization picks the attribute up.
        match el.attrs.iter_mut().find(|(k, _)| k == &name) {
            Some((_, v)) => *v = value,
            None => el.attrs.push((name, value)),
        }
    }
}

/// `el.removeAttribute(name)` — the DOM attribute remover (silent when the
/// attribute is absent, per spec). Same refresh shape as `cb_set_attribute`:
/// live tree via `remove_attr` + stable-node-id snapshot refresh for resident
/// elements, snapshot `retain` for a synthetic wrapper.
fn cb_remove_attribute<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(name) = arg_string(scope, &args, 0) else { return };
    let idx = match this_element_index(scope, &args) {
        Some(i) => i,
        None => return,
    };
    let st = unsafe { state_of(&args) };
    let old = st.elements.get(idx).and_then(|e| e.attr(&name).map(|s| s.to_string()));
    let node_id = st.elements.get(idx).and_then(|e| e.node_id);
    if st.mutate(idx, |doc, id| doc.remove_attr(id, &name)) {
        let data = node_id
            .and_then(|nid| st.doc().node(nid))
            .map(|n| ElementData::from_node(&n));
        if let Some(d) = data {
            st.elements[idx] = d;
        }
        if let Some(t) = st.elements.get(idx).cloned() {
            st.record_mutation(
                Some(idx),
                t,
                MUT_ATTRIBUTES,
                Some(name),
                old,
                Vec::new(),
                Vec::new(),
            );
        }
        schedule_observer_flush(st, scope, &args, &mut rv);
    } else if let Some(el) = st.elements.get_mut(idx) {
        el.attrs.retain(|(k, _)| k != &name);
    }
}

/// `el.hasAttribute(name)` — presence probe over the wrapper snapshot (the
/// same list `getAttribute` reads, so both paths agree within one eval).
fn cb_has_attribute<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let name = arg_string(scope, &args, 0).unwrap_or_default();
    let has = {
        let st = unsafe { state_of(&args) };
        match this_element_index(scope, &args).and_then(|i| st.elements.get(i)) {
            Some(el) => el.attr(&name).is_some(),
            None => false,
        }
    };
    rv.set(v8::Boolean::new(scope, has).into());
}

fn cb_class_list_contains<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let needle = arg_string(scope, &args, 0).unwrap_or_default();
    let found = {
        let st = unsafe { state_of(&args) };
        match this_element_index(scope, &args).and_then(|i| st.elements.get(i)) {
            Some(el) => el
                .attr("class")
                .map(|classes| classes.split_whitespace().any(|c| c == needle))
                .unwrap_or(false),
            None => false,
        }
    };
    rv.set(v8::Boolean::new(scope, found).into());
}

/// `el.parentElement` — resolves the snapshot's node id against the eval's
/// cached document parse and wraps the nearest element ancestor, so provider
/// scroll loops (`_SCROLL_JS`) can walk up from a listing anchor without us
/// ever snapshotting ancestor subtrees eagerly. Fragment-scoped wrappers and
/// the root answer null, matching DOM semantics (`<html>`.parentElement is
/// null).
fn cb_el_parent<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let parent = {
        let st = unsafe { state_of(&args) };
        let id = this_element_index(scope, &args)
            .and_then(|i| st.elements.get(i))
            .and_then(|e| e.node_id);
        id.and_then(|id| st.doc().node(id))
            .and_then(|n| n.parent_element())
            .map(|n| ElementData::from_node(&n))
    };
    match parent {
        Some(data) => {
            let obj = wrap_element(scope, &args, data);
            rv.set(obj.into());
        }
        None => rv.set(nullv(scope)),
    }
}

/// The UA stylesheet's `display` default per tag — what `getComputedStyle`
/// reports without layout. Covers the common tags; unknown tags fall back to
/// the CSS initial `inline`.
fn ua_display(tag: &str) -> &'static str {
    match tag {
        "html" | "body" | "div" | "p" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "ul"
        | "ol" | "dl" | "dt" | "dd" | "form" | "fieldset" | "blockquote" | "pre" | "hr"
        | "header" | "footer" | "nav" | "section" | "article" | "aside" | "main" | "figure"
        | "figcaption" | "canvas" | "video" => "block",
        "li" => "list-item",
        "head" | "meta" | "title" | "link" | "style" | "script" | "base" | "template"
        | "noscript" | "param" | "track" => "none",
        "table" => "table",
        "img" | "input" | "button" | "select" | "textarea" | "iframe" | "object" | "embed" => {
            "inline-block"
        }
        _ => "inline",
    }
}

/// `getComputedStyle(el)` — no layout exists at this tier, so every answer
/// is the CSS initial value except `display`, which the UA stylesheet fixes
/// per tag (deterministic, no geometry needed). The provider surface this
/// exists for is overflow discovery in scroll loops; `overflowY: "visible"`
/// there honestly means "no scrollable pane is knowable here", and the loop
/// falls through to the `window.scrollBy` branch.
fn cb_get_computed_style<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let tag = args
        .get(0)
        .to_object(scope)
        .and_then(|o| o.get(scope, sv(scope, "tagName")))
        .map(|v| {
            v.to_string(scope)
                .map(|s| s.to_rust_string_lossy(scope).to_lowercase())
                .unwrap_or_default()
        })
        .unwrap_or_default();
    let obj = v8::Object::new(scope);
    let props: [(&str, &str); 10] = [
        ("display", ua_display(&tag)),
        ("visibility", "visible"),
        ("position", "static"),
        ("overflow", "visible"),
        ("overflowX", "visible"),
        ("overflowY", "visible"),
        ("opacity", "1"),
        ("pointerEvents", "auto"),
        ("zIndex", "auto"),
        ("cursor", "auto"),
    ];
    for (k, v) in props {
        let _ = obj.set(scope, sv(scope, k), sv(scope, v));
    }
    rv.set(obj.into());
}

/// `window.scrollTo`/`window.scrollBy`. There is no viewport to move, but
/// the scroll position is real bookkeeping providers can observe: `scrollBy`
/// advances `scrollY` (clamped at zero), `scrollTo` sets it. `this` is the
/// global object (window === globals here), so the props ride on it.
fn window_scroll<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: &FunctionCallbackArguments<'s>,
    add: bool,
) {
    let this = args.this();
    let num = |i: i32| -> f64 {
        args.get(i)
            .to_number(scope)
            .map(|n| n.value())
            .unwrap_or(0.0)
    };
    let (dx, dy) = (num(0), num(1));
    for (base, delta) in [("scrollX", dx), ("scrollY", dy)] {
        let cur = this
            .get(scope, sv(scope, base))
            .and_then(|v| v.to_number(scope))
            .map(|n| n.value())
            .unwrap_or(0.0);
        let next = if add { cur + delta } else { delta }.max(0.0);
        let _ = this.set(scope, sv(scope, base), v8::Number::new(scope, next).into());
        let alias = if base == "scrollX" { "pageXOffset" } else { "pageYOffset" };
        let _ = this.set(scope, sv(scope, alias), v8::Number::new(scope, next).into());
    }
    // A real scroll dispatches a 'scroll' event on the window — lazy-loaders
    // hook it, so the engine fires it too (only when someone is listening;
    // building the event object is not free). scroll doesn't bubble, so the
    // window target alone is correct.
    let phases = {
        let st = unsafe { state_of(args) };
        event_phases(st, EvTarget::Window, "scroll", false)
    };
    if phases.iter().any(|(_, cbs)| !cbs.is_empty()) {
        let context = scope.get_current_context();
        let global = context.global(nullscope(scope)).into();
        let ev = simple_event(scope, "scroll");
        let _ = ev.set(scope, sv(scope, "target"), global);
        run_event_phases(scope, phases, global, ev);
    }
}

fn cb_window_scroll_to<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    _rv: ReturnValue<'s, Value>,
) {
    window_scroll(scope, &args, false);
}

fn cb_window_scroll_by<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    _rv: ReturnValue<'s, Value>,
) {
    window_scroll(scope, &args, true);
}

/// `document.documentElement` — the live `<html>` wrapper.
fn cb_document_root<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let root = {
        let st = unsafe { state_of(&args) };
        st.doc().root().map(|n| ElementData::from_node(&n))
    };
    match root {
        Some(data) => {
            let obj = wrap_element(scope, &args, data);
            rv.set(obj.into());
        }
        None => rv.set(nullv(scope)),
    }
}

/// `document.body` — the live `<body>` wrapper.
fn cb_document_body<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let body = {
        let st = unsafe { state_of(&args) };
        st.doc()
            .select_one("body")
            .ok()
            .flatten()
            .map(|n| ElementData::from_node(&n))
    };
    match body {
        Some(data) => {
            let obj = wrap_element(scope, &args, data);
            rv.set(obj.into());
        }
        None => rv.set(nullv(scope)),
    }
}

fn cb_set_timeout<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    rv: ReturnValue<'s, Value>,
) {
    schedule_timer(scope, args, rv, false);
}

fn cb_set_interval<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    rv: ReturnValue<'s, Value>,
) {
    schedule_timer(scope, args, rv, true);
}

fn schedule_timer<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
    repeat: bool,
) {
    let cb = args.get(0);
    if !cb.is_function() {
        rv.set(v8::Number::new(scope, 0.0).into());
        return;
    }
    // Delay coercion: missing/non-finite/negative → 0. No 4ms nesting clamp —
    // scroll loops want their small delays honored.
    let ms_v = args.get(1);
    let n = if ms_v.is_number() {
        ms_v.to_number(scope).map(|x| x.value()).unwrap_or(0.0)
    } else {
        0.0
    };
    let ms = if n.is_finite() && n > 0.0 { n as u64 } else { 0 };
    let st = unsafe { state_of(&args) };
    let id = st.next_timer_id;
    st.next_timer_id += 1;
    st.timers.push(Timer {
        id,
        deadline: Instant::now() + Duration::from_millis(ms),
        interval_ms: repeat.then_some(ms),
        raf: false,
        callback: v8::Global::new(scope, cb.cast::<Function>()),
    });
    rv.set(v8::Number::new(scope, id as f64).into());
}

/// `requestAnimationFrame(cb)` — one-shot frame callback scheduled ~16ms out
/// (a fixed ~60fps interval; there's no vsync on this tier). The callback
/// receives a DOMHighResTimeStamp (the same monotonic clock performance.now()
/// reads), matching a real frame tick. Shares the timer queue so settle()'s
/// pump drives it; cancelAnimationFrame aliases clearTimeout's id space.
fn cb_request_animation_frame<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let cb = args.get(0);
    if !cb.is_function() {
        rv.set(v8::Number::new(scope, 0.0).into());
        return;
    }
    let st = unsafe { state_of(&args) };
    let id = st.next_timer_id;
    st.next_timer_id += 1;
    st.timers.push(Timer {
        id,
        deadline: Instant::now() + Duration::from_millis(16),
        interval_ms: None,
        raf: true,
        callback: v8::Global::new(scope, cb.cast::<Function>()),
    });
    rv.set(v8::Number::new(scope, id as f64).into());
}

fn cb_clear_timer<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let st = unsafe { state_of(&args) };
    let id_v = args.get(0);
    let id = id_v
        .to_number(scope)
        .map(|n| n.value() as u32)
        .unwrap_or(0);
    st.timers.retain(|t| t.id != id);
    st.cancelled.insert(id);
    rv.set(v8::undefined(scope).into());
}

/// Which storage area a callback's `this` carries: internal field 0 —
/// 0 = localStorage, 1 = sessionStorage. Installed per storage object in
/// `finalize_context` (templates default the field to undefined).
fn storage_slot<'s, 'i>(
    scope: &PinScope<'s, 'i>,
    args: &FunctionCallbackArguments<'_>,
) -> u8 {
    let this = args.this();
    if this.internal_field_count() == 0 {
        return 0;
    }
    this.get_internal_field(scope, 0)
        .map(|f| f.cast::<v8::Number>().value() as u8)
        .unwrap_or(0)
}

fn storage_for<'a>(st: &'a State, slot: u8) -> &'a Storage {
    if slot == 0 {
        &st.local_storage
    } else {
        &st.session_storage
    }
}

/// Web Storage string coercion: keys and values are ToString'd, so
/// `setItem('k', undefined)` stores the string "undefined" — unlike the
/// `undefined`-means-absent reading `arg_string` uses elsewhere.
fn coerce_string<'s, 'i>(
    scope: &PinScope<'s, 'i>,
    args: &FunctionCallbackArguments<'_>,
    i: usize,
) -> Option<String> {
    args.get(i as i32)
        .to_string(scope)
        .map(|s| s.to_rust_string_lossy(scope))
}

/// `length` is a real data property kept in sync by every mutating callback
/// (a live getter would need an accessor shim whose data slot the template
/// API doesn't expose; pages only observe the value, never the difference).
fn sync_storage_length<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: &FunctionCallbackArguments<'_>,
    len: usize,
) {
    let this = args.this();
    let _ = this.set(
        scope,
        sv(scope, "length"),
        v8::Number::new(scope, len as f64).into(),
    );
}

fn cb_storage_get<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let slot = storage_slot(scope, &args);
    let st = unsafe { state_of(&args) };
    let key = match coerce_string(scope, &args, 0) {
        Some(k) => k,
        None => {
            rv.set(nullv(scope));
            return;
        }
    };
    match storage_for(st, slot).get(&key) {
        Some(v) => rv.set(js_string(scope, &v)),
        None => rv.set(nullv(scope)),
    }
}

fn cb_storage_set<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let slot = storage_slot(scope, &args);
    let st = unsafe { state_of(&args) };
    let (Some(key), Some(value)) = (coerce_string(scope, &args, 0), coerce_string(scope, &args, 1)) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let store = storage_for(st, slot);
    store.set(key, value);
    let len = store.len();
    sync_storage_length(scope, &args, len);
    rv.set(v8::undefined(scope).into());
}

fn cb_storage_remove<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let slot = storage_slot(scope, &args);
    let st = unsafe { state_of(&args) };
    if let Some(key) = coerce_string(scope, &args, 0) {
        let store = storage_for(st, slot);
        store.remove(&key);
        let len = store.len();
        sync_storage_length(scope, &args, len);
    }
    rv.set(v8::undefined(scope).into());
}

fn cb_storage_clear<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let slot = storage_slot(scope, &args);
    let st = unsafe { state_of(&args) };
    storage_for(st, slot).clear();
    sync_storage_length(scope, &args, 0);
    rv.set(v8::undefined(scope).into());
}

fn cb_storage_key<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let slot = storage_slot(scope, &args);
    let st = unsafe { state_of(&args) };
    let i = args
        .get(0)
        .to_number(scope)
        .map(|n| n.value())
        .unwrap_or(0.0);
    let key = if i >= 0.0 {
        storage_for(st, slot).key(i as usize)
    } else {
        None
    };
    match key {
        Some(k) => rv.set(js_string(scope, &k)),
        None => rv.set(nullv(scope)),
    }
}

fn cb_performance_now<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let st = unsafe { state_of(&args) };
    let elapsed = st.started.elapsed().as_millis() as f64;
    rv.set(v8::Number::new(scope, elapsed).into());
}

fn cb_location_to_string<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let st = unsafe { state_of(&args) };
    let url = st.page_url.clone();
    rv.set(js_string(scope, &url));
}

/// `document.cookie` getter: the session's cookies for this page's origin,
/// httpOnly ones excluded — the visibility contract real jars enforce.
fn cb_document_cookie_get<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let st = unsafe { state_of(&args) };
    let out = match &st.cookie_store {
        Some(store) if !st.page_url.is_empty() => {
            store.document_cookie(&st.page_url).unwrap_or_default()
        }
        _ => String::new(),
    };
    rv.set(js_string(scope, &out));
}

/// `document.cookie` setter: parse the `name=value; Path=...; Max-Age=...;
/// Secure` assignment and land it in the session jar, so the next page
/// request carries it like a browser's would. Defaults follow the spec
/// where it matters for scraping (path `/` rather than the URL's
/// directory — the pragmatic choice, pinned), and the Domain attribute is
/// ignored: a page may only scope cookies to its own host.
fn cb_document_cookie_set<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut _rv: ReturnValue<'s, Value>,
) {
    let raw = arg_string(scope, &args, 0).unwrap_or_default();
    let st = unsafe { state_of(&args) };
    let Some(store) = st.cookie_store.clone() else {
        return;
    };
    if st.page_url.is_empty() {
        return;
    }
    let mut parts = raw.split(';');
    let Some(pair) = parts.next() else { return };
    let Some(eq) = pair.find('=') else { return };
    let name = pair[..eq].trim().to_string();
    let value = pair[eq + 1..].trim().to_string();
    if name.is_empty() {
        return;
    }
    let host = url::Url::parse(&st.page_url)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
        .unwrap_or_default();
    if host.is_empty() {
        return;
    }
    let mut entry = se_net::CookieEntry::new(name, value);
    entry.domain = host;
    entry.path = "/".to_string();
    for attr in parts {
        let attr = attr.trim();
        let (k, v) = match attr.find('=') {
            Some(i) => (&attr[..i], attr[i + 1..].trim()),
            None => (attr, ""),
        };
        match k.trim().to_ascii_lowercase().as_str() {
            "path" if !v.is_empty() => entry.path = v.to_string(),
            "max-age" => {
                if let Ok(secs) = v.parse::<i64>() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    entry.expires = Some(now + secs);
                }
            }
            "secure" => entry.secure = true,
            _ => {}
        }
    }
    store.insert_entry(&entry);
}

fn cb_queue_microtask<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let f = args.get(0);
    if f.is_function() {
        scope.enqueue_microtask(f.cast::<Function>());
    }
    rv.set(v8::undefined(scope).into());
}

fn cb_noop<'s, 'i>(
    _scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    _rv: ReturnValue<'s, Value>,
) {
}

/// `navigator.javaEnabled()` — real Chrome answers false (no Java plugin).
fn cb_java_enabled<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    rv.set(v8::Boolean::new(scope, false).into());
}

// ── M4 se-detect deep tier ────────────────────────────────────────────────
// The fingerprint probes FingerprintJS-class scripts run BEYOND the
// navigator/screen/chrome basics: the Permissions API (consistency-checked
// against Notification.permission), the device enumerators, battery state,
// speech synthesis, and the visual viewport. Every missing entry is a
// headless tell; every answer below mirrors a fresh-profile desktop Chrome.

/// `navigator.permissions.query(desc)` — resolves `{state, onchange: null}`.
/// Fresh-profile Chrome answers 'prompt' for nearly everything;
/// clipboard-write and background-sync are 'granted' (writes and one-shot
/// sync need no user permission). Unknown names reject with a
/// TypeError-shaped reason, per spec.
fn cb_permissions_query<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let name = args
        .get(0)
        .to_object(scope)
        .and_then(|o| o.get(scope, sv(scope, "name")))
        .and_then(|v| v.to_string(scope))
        .map(|s| s.to_rust_string_lossy(scope))
        .unwrap_or_default();
    const KNOWN: &[(&str, &str)] = &[
        ("geolocation", "prompt"),
        ("notifications", "prompt"), // ↔ Notification.permission 'default'
        ("camera", "prompt"),
        ("microphone", "prompt"),
        ("clipboard-read", "prompt"),
        ("clipboard-write", "granted"),
        ("persistent-storage", "prompt"),
        ("push", "prompt"),
        ("midi", "prompt"),
        ("accelerometer", "prompt"),
        ("gyroscope", "prompt"),
        ("magnetometer", "prompt"),
        ("speaker-selection", "prompt"),
        ("background-sync", "granted"),
    ];
    match KNOWN.iter().find(|(n, _)| *n == name) {
        Some((_, state)) => {
            let status = v8::Object::new(scope);
            set_prop(scope, status, "state", sv(scope, state));
            set_prop(scope, status, "onchange", nullv(scope));
            let _ = resolver.resolve(scope, status.into());
        }
        None => {
            let reason = format!(
                "TypeError: Failed to execute 'query' on 'Permissions': The provided value '{name}' is not a valid enum value"
            );
            let reason = js_string(scope, &reason);
            let _ = resolver.reject(scope, reason);
        }
    }
    rv.set(resolver.get_promise(scope).into());
}

/// `navigator.mediaDevices.enumerateDevices()` — the fresh-profile device
/// list: one input each of audio/video plus the default audio output.
/// Labels are EMPTY without getUserMedia permission, exactly like Chrome.
fn cb_enum_devices<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let specs: [(&str, &str); 3] = [
        ("default-audio-input", "audioinput"),
        ("default-video-input", "videoinput"),
        ("default-audio-output", "audiooutput"),
    ];
    let mut devs = Vec::with_capacity(specs.len());
    for (id, kind) in specs {
        let d = v8::Object::new(scope);
        set_prop(scope, d, "deviceId", sv(scope, id));
        set_prop(scope, d, "kind", sv(scope, kind));
        set_prop(scope, d, "label", sv(scope, ""));
        set_prop(scope, d, "groupId", sv(scope, ""));
        devs.push(d.into());
    }
    let arr = v8::Array::new_with_elements(scope, &devs);
    let _ = resolver.resolve(scope, arr.into());
    rv.set(resolver.get_promise(scope).into());
}

/// `navigator.mediaDevices.getUserMedia/getDisplayMedia()` — no permission
/// granted: reject, like Chrome's NotAllowedError path.
fn cb_media_denied<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    match v8::PromiseResolver::new(scope) {
        Some(resolver) => {
            let reason = js_string(
                scope,
                "NotAllowedError: Permission denied by system (navigator.mediaDevices)",
            );
            let _ = resolver.reject(scope, reason);
            rv.set(resolver.get_promise(scope).into());
        }
        None => rv.set(v8::undefined(scope).into()),
    }
}

/// `navigator.getBattery()` — desktop Chrome without a battery manager:
/// charging, full, never discharging.
fn cb_get_battery<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let b = v8::Object::new(scope);
    set_prop(scope, b, "charging", v8::Boolean::new(scope, true).into());
    set_prop(scope, b, "chargingTime", v8::Number::new(scope, 0.0).into());
    set_prop(
        scope,
        b,
        "dischargingTime",
        v8::Number::new(scope, f64::INFINITY).into(),
    );
    set_prop(scope, b, "level", v8::Number::new(scope, 1.0).into());
    for m in ["addEventListener", "removeEventListener", "dispatchEvent"] {
        let f = v8::Function::new(scope, cb_noop).expect("noop fn");
        set_prop(scope, b, m, f.into());
    }
    let _ = resolver.resolve(scope, b.into());
    rv.set(resolver.get_promise(scope).into());
}

/// `speechSynthesis.getVoices()` — an empty voice list (no Speech service
/// voices installed is a plausible fresh-profile state, and an empty list
/// serializes deterministically).
fn cb_get_voices<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let arr = v8::Array::new(scope, 0);
    rv.set(arr.into());
}

/// The `Function.prototype.toString` dispatcher (M4) — see finalize_context.
/// The fetch promisify trampoline is a JS function and the toString
/// intrinsic reflects its SOURCE; the call form fingerprint scripts use,
/// `Function.prototype.toString.call(fetch)`, invokes the intrinsic
/// directly, so an own-property mask can never intercept it. This host
/// replacement dispatches instead: the trampoline (identity check against
/// the rooted Global) answers with the native string, everything else
/// falls through to the ORIGINAL intrinsic — itself rooted at finalize
/// time and reachable only host-side. Being template-born, the dispatcher
/// reads as native under its own toString.
fn cb_fp_tostring<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    let (mask_name, orig) = {
        let st = unsafe { state_of(&args) };
        let mask_name = st.fp_masks.iter().find_map(|(g, name)| {
            let g = v8::Local::new(scope, g.clone());
            this.strict_equals(g.into()).then(|| name.clone())
        });
        (mask_name, st.fp_tostring_orig.clone())
    };
    if let Some(name) = mask_name {
        let native = format!("function {name}() {{ [native code] }}");
        rv.set(sv(scope, &native));
        return;
    }
    const FALLBACK: &str = "function () { [native code] }";
    match orig {
        Some(orig) => {
            let orig = v8::Local::new(scope, orig);
            match orig.call(scope, this.into(), &[]) {
                Some(v) => rv.set(v),
                None => rv.set(sv(scope, FALLBACK)),
            }
        }
        None => rv.set(sv(scope, FALLBACK)),
    }
}

// ---------------------------------------------------------------------
// M4 utility/crypto tier (firing 26). The page-utility surface tracker
// and feature-detect code touches on init: WebCrypto, text codecs,
// CSS.supports, AbortController, performance extras, storage/geolocation
// shapes, indexedDB/customElements/Shadow-DOM shapes. Real work (SHA-256,
// OS randomness, UTF-8) is honest; the shape-only pieces answer like a
// fresh-profile desktop Chrome and are documented as such per callback.
// ---------------------------------------------------------------------

/// Build a `DOMException`-shaped object with the legacy `code` table.
fn dom_exception_obj<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    message: &str,
    name: &str,
) -> Local<'s, Object> {
    let o = v8::Object::new(scope);
    set_prop(scope, o, "message", sv(scope, message));
    set_prop(scope, o, "name", sv(scope, name));
    let code = match name {
        "IndexSizeError" => 1,
        "HierarchyRequestError" => 3,
        "WrongDocumentError" => 4,
        "InvalidCharacterError" => 5,
        "NoModificationAllowedError" => 7,
        "NotFoundError" => 8,
        "NotSupportedError" => 9,
        "InvalidStateError" => 11,
        "SyntaxError" => 12,
        "InvalidModificationError" => 13,
        "NamespaceError" => 14,
        "InvalidAccessError" => 15,
        "TypeMismatchError" => 17,
        "SecurityError" => 18,
        "NetworkError" => 19,
        "AbortError" => 20,
        "URLMismatchError" => 21,
        "QuotaExceededError" => 22,
        "TimeoutError" => 23,
        "InvalidNodeTypeError" => 24,
        "DataCloneError" => 25,
        _ => 0,
    };
    set_prop(scope, o, "code", v8::Number::new(scope, code as f64).into());
    o
}

/// `new DOMException(message, name)` — the object shape pages read
/// (message/name/code); the prototype chain is the plain Object floor.
fn cb_dom_exception_ctor<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let message = arg_string(scope, &args, 0).unwrap_or_default();
    let name = arg_string(scope, &args, 1).unwrap_or_else(|| "Error".to_string());
    rv.set(dom_exception_obj(scope, &message, &name).into());
}

/// Listener storage for the generic per-object event targets (AbortSignal,
/// IDBRequest). Registrations live in a hidden `_listeners` array of
/// `{type, cb, capture}` objects on the target itself — no State entry, so
/// the pattern works for any object without touching the window/document
/// listener registry.
fn target_add_listener<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    target: Local<Object>,
    type_: Local<Value>,
    cb: Local<Value>,
    capture: Local<Value>,
) {
    let entry = v8::Object::new(scope);
    let _ = entry.set(scope, sv(scope, "type"), type_);
    let _ = entry.set(scope, sv(scope, "cb"), cb);
    let _ = entry.set(scope, sv(scope, "capture"), capture);
    let existing = target
        .get(scope, sv(scope, "_listeners"))
        .filter(|v| v.is_array())
        .map(|v| v.cast::<v8::Array>());
    let arr = match existing {
        Some(a) => a,
        None => {
            let a = v8::Array::new(scope, 0);
            let _ = target.set(scope, sv(scope, "_listeners"), a.into());
            a
        }
    };
    let _ = arr.set_index(scope, arr.length(), entry.into());
}

fn target_remove_listener<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    target: Local<Object>,
    type_: Local<Value>,
    cb: Local<Value>,
    capture: Local<Value>,
) {
    let Some(arr) = target
        .get(scope, sv(scope, "_listeners"))
        .filter(|v| v.is_array())
        .map(|v| v.cast::<v8::Array>())
    else {
        return;
    };
    let len = arr.length();
    let mut keep: Vec<Local<Value>> = Vec::new();
    for i in 0..len {
        let Some(entry) = arr.get_index(scope, i).and_then(|e| e.to_object(scope)) else {
            continue;
        };
        let same_type = entry
            .get(scope, sv(scope, "type"))
            .map(|t| t.strict_equals(type_))
            .unwrap_or(false);
        let same_cb = entry
            .get(scope, sv(scope, "cb"))
            .map(|c| c.strict_equals(cb))
            .unwrap_or(false);
        let same_cap = entry
            .get(scope, sv(scope, "capture"))
            .map(|c| c.strict_equals(capture))
            .unwrap_or(false);
        if !(same_type && same_cb && same_cap) {
            keep.push(entry.into());
        }
    }
    let fresh = v8::Array::new(scope, 0);
    for (i, k) in keep.into_iter().enumerate() {
        let _ = fresh.set_index(scope, i as u32, k);
    }
    let _ = target.set(scope, sv(scope, "_listeners"), fresh.into());
}

/// Fire `type_name` on a generic target: the `on<type>` property first
/// (like the registry dispatch), then the `_listeners` entries whose type
/// matches. Listener callbacks are invoked with the event as the sole
/// argument, `this` = the target.
fn target_fire_listeners<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    target: Local<Object>,
    type_name: &str,
    event: Local<Value>,
) {
    let on_key = format!("on{type_name}");
    if let Some(on) = target.get(scope, sv(scope, &on_key)) {
        if on.is_function() {
            let f = on.cast::<Function>();
            let tgt = target.into();
            let _ = f.call(scope, tgt, &[event]);
        }
    }
    let Some(arr) = target
        .get(scope, sv(scope, "_listeners"))
        .filter(|v| v.is_array())
        .map(|v| v.cast::<v8::Array>())
    else {
        return;
    };
    let len = arr.length();
    let mut cbs: Vec<Local<Value>> = Vec::new();
    for i in 0..len {
        let Some(entry) = arr.get_index(scope, i).and_then(|e| e.to_object(scope)) else {
            continue;
        };
        let matches = entry
            .get(scope, sv(scope, "type"))
            .and_then(|t| t.to_string(scope))
            .map(|t| t.to_rust_string_lossy(scope) == type_name)
            .unwrap_or(false);
        if matches {
            if let Some(cb) = entry.get(scope, sv(scope, "cb")) {
                cbs.push(cb);
            }
        }
    }
    let tgt = target.into();
    for cb in cbs {
        if cb.is_function() {
            let f = cb.cast::<Function>();
            let _ = f.call(scope, tgt, &[event]);
        }
    }
}

/// Build an Event-shaped object `{type, target, preventDefault(),
/// stopPropagation(), ...}` for the generic-target delivery. Uses the
/// page-visible `Event` constructor when it exists so `ev instanceof
/// Event` holds; falls back to a plain object with the same fields.
fn make_event_obj<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    type_: &str,
    target: Option<Local<Object>>,
) -> Local<'s, Value> {
    let ctx = scope.get_current_context();
    let global = ctx.global(scope);
    let ev = global
        .get(scope, sv(scope, "Event"))
        .filter(|e| e.is_function())
        .and_then(|ctor| {
            let ty = sv(scope, type_);
            ctor.cast::<Function>()
                .call(scope, global.into(), &[ty])
        })
        .and_then(|e| e.to_object(scope))
        .unwrap_or_else(|| {
            let o = v8::Object::new(scope);
            set_prop(scope, o, "type", sv(scope, type_));
            for m in ["preventDefault", "stopPropagation", "stopImmediatePropagation"] {
                let f = v8::Function::new(scope, cb_noop).expect("noop fn");
                set_prop(scope, o, m, f.into());
            }
            o
        });
    if let Some(t) = target {
        let _ = ev.set(scope, sv(scope, "target"), t.into());
    }
    ev.into()
}

/// Schedule `cb(arg)` on a 0ms one-shot timer. Timer callbacks take no
/// arguments in this engine's queue, so the delivery rides a tiny JS
/// closure built per call (same `(c,a)=>()=>c(a)` factory shape the XHR
/// trampoline uses). Used for the async-callback contracts: geolocation's
/// error position and IDB request errors.
fn schedule_call_timer<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    st: &mut State,
    cb: Local<'s, Value>,
    arg: Local<'s, Value>,
) {
    let src = v8::String::new(scope, "(c,a)=>()=>c(a)").expect("string alloc");
    let closure = v8::Script::compile(scope, src, None)
        .and_then(|s| s.run(scope))
        .and_then(|f| f.cast::<Function>().call(scope, v8::undefined(scope).into(), &[cb, arg]));
    let Some(closure) = closure else {
        return;
    };
    let id = st.next_timer_id;
    st.next_timer_id += 1;
    st.timers.push(Timer {
        id,
        deadline: Instant::now(),
        interval_ms: None,
        raf: false,
        callback: v8::Global::new(scope, closure.cast::<Function>()),
    });
}

/// `crypto.getRandomValues(typedArray)` — OS randomness via getrandom,
/// filled in place; the SAME array is returned (the spec contract).
fn cb_crypto_get_random_values<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let v = args.get(0);
    if !v.is_typed_array() {
        // Spec throws TypeError; the tolerant floor (undefined) keeps an
        // off-contract probe from crashing init code.
        rv.set(v8::undefined(scope).into());
        return;
    }
    let ta = v.cast::<v8::TypedArray>();
    let offset = ta.byte_offset();
    let len = ta.byte_length();
    let Some(buf) = ta.buffer(nullscope(scope)) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let backing = buf.get_backing_store();
    let bytes: &[std::cell::Cell<u8>] = &backing;
    let mut chunk = vec![0u8; len.min(65536)];
    if getrandom::getrandom(&mut chunk).is_err() {
        rv.set(v8::undefined(scope).into());
        return;
    }
    for (i, b) in chunk.iter().enumerate() {
        let idx = offset + i;
        if idx < bytes.len() {
            bytes[idx].set(*b);
        }
    }
    rv.set(v);
}

/// `crypto.randomUUID()` — RFC 4122 version 4, random variant.
fn cb_crypto_random_uuid<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let mut b = [0u8; 16];
    if getrandom::getrandom(&mut b).is_err() {
        rv.set(v8::undefined(scope).into());
        return;
    }
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex: Vec<String> = b.iter().map(|x| format!("{x:02x}")).collect();
    let mut uuid = String::with_capacity(36);
    for (i, h) in hex.iter().enumerate() {
        if i == 4 || i == 6 || i == 8 || i == 10 {
            uuid.push('-');
        }
        uuid.push_str(h);
    }
    rv.set(sv(scope, &uuid));
}

/// Copy the bytes a BufferSource argument points at (ArrayBuffer /
/// TypedArray view / DataView), for `subtle.digest` and `TextDecoder`.
fn buffer_source_bytes<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    v: Local<'s, Value>,
) -> Option<Vec<u8>> {
    if v.is_array_buffer() {
        let ab = v.cast::<v8::ArrayBuffer>();
        let backing = ab.get_backing_store();
        let bytes: &[std::cell::Cell<u8>] = &backing;
        return Some(bytes.iter().map(|c| c.get()).collect());
    }
    if v.is_typed_array() || v.is_data_view() {
        let view = v.cast::<v8::ArrayBufferView>();
        let offset = view.byte_offset();
        let len = view.byte_length();
        let Some(buffer) = view.buffer(nullscope(scope)) else {
            return None;
        };
        let backing = buffer.get_backing_store();
        let bytes: &[std::cell::Cell<u8>] = &backing;
        return Some(
            bytes
                .iter()
                .skip(offset)
                .take(len)
                .map(|c| c.get())
                .collect(),
        );
    }
    // Tolerant floor: a string argument decodes as its UTF-8 bytes.
    v.to_string(scope)
        .map(|s| s.to_rust_string_lossy(scope).into_bytes())
}

/// `crypto.subtle.digest(alg, data)` — SHA-256 is computed honestly
/// (hand-rolled FIPS 180-4 in sha256.rs); other algorithms reject rather
/// than fake a digest. Resolves an ArrayBuffer.
fn cb_subtle_digest<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let alg = arg_string(scope, &args, 0)
        .unwrap_or_default()
        .to_ascii_uppercase();
    if alg != "SHA-256" {
        let err = dom_exception_obj(
            scope,
            &format!("unsupported digest algorithm: {alg}"),
            "NotSupportedError",
        );
        let _ = resolver.reject(scope, err.into());
        rv.set(resolver.get_promise(scope).into());
        return;
    }
    let Some(bytes) = buffer_source_bytes(scope, args.get(1)) else {
        let err = dom_exception_obj(scope, "data is not a BufferSource", "TypeMismatchError");
        let _ = resolver.reject(scope, err.into());
        rv.set(resolver.get_promise(scope).into());
        return;
    };
    let digest = crate::sha256::sha256(&bytes);
    let ab = v8::ArrayBuffer::new(scope, digest.len());
    let backing = ab.get_backing_store();
    let cells: &[std::cell::Cell<u8>] = &backing;
    for (i, b) in digest.iter().enumerate() {
        if i < cells.len() {
            cells[i].set(*b);
        }
    }
    let _ = resolver.resolve(scope, ab.into());
    rv.set(resolver.get_promise(scope).into());
}

/// `TextEncoder.prototype.encode(str)` — real UTF-8; returns a fresh
/// Uint8Array over a fresh ArrayBuffer.
fn cb_text_encoder_encode<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let s = arg_string(scope, &args, 0).unwrap_or_default();
    let bytes = s.into_bytes();
    let ab = v8::ArrayBuffer::new(scope, bytes.len());
    let backing = ab.get_backing_store();
    let cells: &[std::cell::Cell<u8>] = &backing;
    for (i, b) in bytes.iter().enumerate() {
        if i < cells.len() {
            cells[i].set(*b);
        }
    }
    match v8::Uint8Array::new(scope, ab, 0, bytes.len()) {
        Some(ua) => rv.set(ua.into()),
        None => rv.set(v8::undefined(scope).into()),
    }
}

/// `TextDecoder.prototype.decode(data, opts)` — real UTF-8 with BOM
/// stripping and `fatal` support. Fatal errors cannot throw from a host
/// callback (v8 152), so the raw callback returns a `{__seFatal: msg}`
/// signal object and the JS wrapper installed in finalize_context turns
/// it into a TypeError (the WS-trampoline error convention).
fn cb_text_decoder_decode_raw<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    let data = args.get(0);
    let mut bytes = if data.is_undefined() || data.is_null() {
        Vec::new()
    } else {
        match buffer_source_bytes(scope, data) {
            Some(b) => b,
            None => {
                rv.set(v8::undefined(scope).into());
                return;
            }
        }
    };
    let ignore_bom = this
        .to_object(scope)
        .and_then(|o| o.get(scope, sv(scope, "ignoreBOM")))
        .map(|v| v.is_true())
        .unwrap_or(false);
    if !ignore_bom && bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        bytes.drain(0..3);
    }
    match String::from_utf8(bytes) {
        Ok(s) => rv.set(sv(scope, &s)),
        Err(e) => {
            let fatal = this
                .to_object(scope)
                .and_then(|o| o.get(scope, sv(scope, "fatal")))
                .map(|v| v.is_true())
                .unwrap_or(false);
            if fatal {
                let msg = format!("Decoder fatal error: {}", e.utf8_error());
                let sig = v8::Object::new(scope);
                set_prop(scope, sig, "__seFatal", sv(scope, &msg));
                rv.set(sig.into());
            } else {
                rv.set(sv(scope, &String::from_utf8_lossy(e.as_bytes()).into_owned()));
            }
        }
    }
}

/// `new TextEncoder()` — the instance carries `encoding` and a host
/// `encode` (its toString reads native, no mask needed).
fn cb_text_encoder_ctor<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    let Some(obj) = this.to_object(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let ext = args.data();
    let encode = v8::FunctionTemplate::builder(cb_text_encoder_encode)
        .data(ext)
        .build(scope)
        .get_function(scope);
    if let Some(f) = encode {
        set_prop(scope, obj, "encode", f.into());
    }
    set_prop(scope, obj, "encoding", sv(scope, "utf-8"));
    rv.set(this.into());
}

/// `new TextDecoder(label, opts)` — utf-8 only (the label is accepted and
/// ignored, like a browser that has no other codecs built in); the fatal /
/// ignoreBOM flags are stored as instance props the raw decode reads. The
/// instance's `decode` is a JS wrapper around the raw host callback: v8
/// 152 cannot throw from a host callback, so the raw side returns a
/// `{__seFatal}` signal object on fatal+invalid input and the wrapper
/// converts it to a TypeError. The wrapper is pushed into `fp_masks` so
/// `toString` still reports native.
fn cb_text_decoder_ctor<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    let Some(obj) = this.to_object(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let opts = args.get(1).to_object(scope);
    let flag = |key: &str| -> bool {
        opts.and_then(|o| o.get(scope, sv(scope, key)))
            .map(|v| v.is_true())
            .unwrap_or(false)
    };
    set_prop(scope, obj, "encoding", sv(scope, "utf-8"));
    set_prop(scope, obj, "fatal", v8::Boolean::new(scope, flag("fatal")).into());
    set_prop(
        scope,
        obj,
        "ignoreBOM",
        v8::Boolean::new(scope, flag("ignoreBOM")).into(),
    );
    let ext = args.data();
    let raw = v8::FunctionTemplate::builder(cb_text_decoder_decode_raw)
        .data(ext)
        .build(scope)
        .get_function(scope)
        .map(|f| f.cast::<Value>());
    if let Some(raw) = raw {
        let src = v8::String::new(
            scope,
            "(raw)=>function(input,opts){var r=raw.call(this,input,opts);if(r&&typeof r==='object'&&r.__seFatal)throw new TypeError(r.__seFatal);return r;}",
        )
        .expect("string alloc");
        let wrapper = v8::Script::compile(scope, src, None)
            .and_then(|s| s.run(scope))
            .and_then(|f| f.cast::<Function>().call(scope, v8::undefined(scope).into(), &[raw]));
        if let Some(wrapper) = wrapper {
            if let Some(wobj) = wrapper.to_object(scope) {
                let st = unsafe { state_of(&args) };
                st.fp_masks
                    .push((v8::Global::new(scope, wobj), "decode".to_string()));
            }
            let _ = obj.set(scope, sv(scope, "decode"), wrapper);
        }
    }
    rv.set(this.into());
}

/// Curated `CSS.supports(prop, value)` table (firing 26). Per-property
/// either ANY non-empty value parses, an explicit value set, or a token
/// combination (place-items / contain / scroll-snap-type). Unlisted
/// properties answer FALSE — like a browser that doesn't support them;
/// this tier never fakes a success. The global keywords initial/inherit/
/// unset/revert/revert-layer/auto parse for any property.
fn css_supports(prop: &str, value: &str) -> bool {
    let p = prop.trim().to_ascii_lowercase();
    let mut v = value.trim().to_ascii_lowercase();
    if let Some(stripped) = v.strip_suffix("!important") {
        v = stripped.trim().to_string();
    }
    if v.is_empty() {
        return false;
    }
    if matches!(
        v.as_str(),
        "initial" | "inherit" | "unset" | "revert" | "revert-layer" | "auto"
    ) {
        return true;
    }
    const ANY_PROPS: &[&str] = &[
        "color", "background", "background-color", "background-image",
        "background-position", "background-size", "background-repeat",
        "background-attachment", "background-origin", "background-clip",
        "border", "border-color", "border-width", "border-top", "border-right",
        "border-bottom", "border-left", "border-radius", "border-image",
        "border-spacing", "outline", "outline-color", "outline-width",
        "outline-offset", "margin", "margin-top", "margin-right",
        "margin-bottom", "margin-left", "padding", "padding-top",
        "padding-right", "padding-bottom", "padding-left", "width", "height",
        "min-width", "max-width", "min-height", "max-height", "inset", "top",
        "left", "right", "bottom", "font", "font-size", "font-weight",
        "font-family", "font-variant", "line-height", "letter-spacing",
        "word-spacing", "text-indent", "text-decoration", "text-decoration-color",
        "text-shadow", "flex", "flex-grow", "flex-shrink", "flex-basis",
        "order", "grid-area", "grid-column", "grid-row", "grid-auto-columns",
        "grid-auto-rows", "grid-template", "grid-template-areas",
        "grid-template-columns", "grid-template-rows", "gap", "row-gap",
        "column-gap", "transform", "transform-origin", "perspective",
        "perspective-origin", "filter", "backdrop-filter", "opacity",
        "z-index", "box-shadow", "clip", "clip-path", "mask", "mask-image",
        "mask-size", "mask-position", "object-position", "transition",
        "transition-property", "transition-duration",
        "transition-timing-function", "transition-delay", "animation",
        "animation-name", "animation-duration", "animation-timing-function",
        "animation-delay", "animation-iteration-count", "animation-direction",
        "animation-fill-mode", "animation-play-state", "caret-color",
        "accent-color", "scroll-margin", "scroll-padding", "aspect-ratio",
        "quotes", "counter-increment", "counter-reset", "counter-set",
        "content", "columns", "column-count", "column-width", "column-rule",
        "orphans", "widows", "fill", "stroke", "stroke-width", "all", "zoom",
        "list-style", "list-style-image",
    ];
    const VALUE_PROPS: &[(&str, &[&str])] = &[
        ("display", &["block", "inline", "inline-block", "none", "flex", "inline-flex", "grid", "inline-grid", "contents", "flow-root", "table", "inline-table", "table-row", "table-cell", "table-row-group", "table-header-group", "table-footer-group", "table-caption", "table-column", "table-column-group", "list-item"]),
        ("position", &["static", "relative", "absolute", "fixed", "sticky"]),
        ("overflow", &["visible", "hidden", "scroll", "auto", "clip"]),
        ("overflow-x", &["visible", "hidden", "scroll", "auto", "clip"]),
        ("overflow-y", &["visible", "hidden", "scroll", "auto", "clip"]),
        ("text-overflow", &["clip", "ellipsis"]),
        ("white-space", &["normal", "nowrap", "pre", "pre-wrap", "pre-line", "break-spaces"]),
        ("word-break", &["normal", "break-all", "keep-all"]),
        ("overflow-wrap", &["normal", "break-word", "anywhere"]),
        ("hyphens", &["none", "manual", "auto"]),
        ("text-transform", &["none", "capitalize", "uppercase", "lowercase", "full-width", "full-size-kana"]),
        ("text-align", &["left", "right", "center", "justify", "start", "end", "match-parent"]),
        ("text-decoration-line", &["none", "underline", "overline", "line-through", "blink"]),
        ("text-decoration-style", &["solid", "double", "dotted", "dashed", "wavy"]),
        ("font-style", &["normal", "italic", "oblique"]),
        ("font-variant-caps", &["normal", "small-caps", "all-small-caps", "petite-caps", "all-petite-caps", "unicase", "titling-caps"]),
        ("writing-mode", &["horizontal-tb", "vertical-rl", "vertical-lr", "sideways-rl", "sideways-lr"]),
        ("direction", &["ltr", "rtl"]),
        ("unicode-bidi", &["normal", "embed", "bidi-override", "isolate", "isolate-override", "plaintext"]),
        ("vertical-align", &["baseline", "sub", "super", "top", "text-top", "middle", "bottom", "text-bottom"]),
        ("flex-direction", &["row", "row-reverse", "column", "column-reverse"]),
        ("flex-wrap", &["nowrap", "wrap", "wrap-reverse"]),
        ("transform-style", &["flat", "preserve-3d"]),
        ("backface-visibility", &["visible", "hidden"]),
        ("visibility", &["visible", "hidden", "collapse"]),
        ("box-sizing", &["content-box", "border-box"]),
        ("object-fit", &["fill", "contain", "cover", "none", "scale-down"]),
        ("resize", &["none", "both", "horizontal", "vertical", "block", "inline"]),
        ("pointer-events", &["auto", "none", "visiblepainted", "visiblefill", "visiblestroke", "visible", "painted", "fill", "stroke", "all"]),
        ("touch-action", &["auto", "none", "pan-x", "pan-y", "pan-left", "pan-right", "pan-up", "pan-down", "pinch-zoom", "manipulation"]),
        ("user-select", &["auto", "none", "text", "all", "contain"]),
        ("appearance", &["none", "auto", "textfield", "button", "button-bevel", "checkbox", "listbox", "menulist", "menulist-button", "meter", "number-field", "progress-bar", "push-button", "radio", "searchfield", "slider-horizontal", "square-button", "textarea"]),
        ("-webkit-appearance", &["none", "auto", "textfield", "button", "button-bevel", "checkbox", "listbox", "menulist", "menulist-button", "meter", "number-field", "progress-bar", "push-button", "radio", "searchfield", "slider-horizontal", "square-button", "textarea"]),
        ("will-change", &["auto", "scroll-position", "contents", "transform", "opacity", "left", "top", "right", "bottom"]),
        ("isolation", &["auto", "isolate"]),
        ("mix-blend-mode", &["normal", "multiply", "screen", "overlay", "darken", "lighten", "color-dodge", "color-burn", "hard-light", "soft-light", "difference", "exclusion", "hue", "saturation", "color", "luminosity", "plus-lighter", "plus-darker"]),
        ("background-blend-mode", &["normal", "multiply", "screen", "overlay", "darken", "lighten", "color-dodge", "color-burn", "hard-light", "soft-light", "difference", "exclusion", "hue", "saturation", "color", "luminosity"]),
        ("justify-content", &["normal", "flex-start", "flex-end", "center", "space-between", "space-around", "space-evenly", "start", "end", "left", "right", "stretch", "baseline", "first-baseline", "last-baseline", "safe center", "unsafe center"]),
        ("align-items", &["normal", "stretch", "center", "flex-start", "flex-end", "start", "end", "baseline", "first-baseline", "last-baseline"]),
        ("align-content", &["normal", "flex-start", "flex-end", "center", "space-between", "space-around", "space-evenly", "start", "end", "stretch", "baseline", "first-baseline", "last-baseline"]),
        ("align-self", &["auto", "normal", "stretch", "center", "flex-start", "flex-end", "start", "end", "baseline", "first-baseline", "last-baseline"]),
        ("justify-items", &["stretch", "center", "start", "end", "flex-start", "flex-end", "left", "right", "baseline", "legacy"]),
        ("justify-self", &["auto", "stretch", "center", "start", "end", "flex-start", "flex-end", "left", "right", "baseline"]),
        ("scroll-behavior", &["auto", "smooth"]),
        ("overscroll-behavior", &["auto", "contain", "none"]),
        ("overscroll-behavior-x", &["auto", "contain", "none"]),
        ("overscroll-behavior-y", &["auto", "contain", "none"]),
        ("scroll-snap-align", &["none", "start", "end", "center"]),
        ("scroll-snap-stop", &["normal", "always"]),
        ("image-rendering", &["auto", "smooth", "high-quality", "crisp-edges", "pixelated"]),
        ("list-style-type", &["disc", "circle", "square", "decimal", "decimal-leading-zero", "none", "lower-roman", "upper-roman", "lower-alpha", "upper-alpha", "lower-greek", "georgian", "armenian", "hebrew", "cjk-ideographic", "hiragana", "katakana"]),
        ("list-style-position", &["inside", "outside"]),
        ("caption-side", &["top", "bottom", "block-start", "block-end", "left", "right"]),
        ("border-collapse", &["collapse", "separate"]),
        ("empty-cells", &["show", "hide"]),
        ("table-layout", &["auto", "fixed"]),
        ("break-inside", &["auto", "avoid", "avoid-page", "avoid-column", "avoid-region"]),
        ("border-style", &["none", "hidden", "dotted", "dashed", "solid", "double", "groove", "ridge", "inset", "outset"]),
        ("outline-style", &["none", "auto", "dotted", "dashed", "solid", "double", "groove", "ridge", "inset", "outset"]),
        ("color-scheme", &["normal", "light", "dark"]),
        ("clear", &["none", "left", "right", "both", "inline-start", "inline-end"]),
        ("float", &["none", "left", "right", "inline-start", "inline-end"]),
    ];
    if ANY_PROPS.contains(&p.as_str()) {
        return true;
    }
    for (vp, values) in VALUE_PROPS {
        if *vp == p {
            return values.contains(&v.as_str());
        }
    }
    // Token-combination properties: every whitespace token must come from
    // the allowed set (order-free; "pan-x pan-y", "size layout", ...).
    let tokens_ok = |allowed: &[&str]| -> bool {
        v.split_whitespace().all(|t| allowed.contains(&t))
    };
    match p.as_str() {
        "contain" => tokens_ok(&["none", "strict", "content", "size", "layout", "style", "paint"]),
        "scroll-snap-type" => {
            tokens_ok(&["none", "x", "y", "both", "block", "inline", "mandatory", "proximity"])
        }
        "place-items" => {
            let align = ["normal", "stretch", "center", "flex-start", "flex-end", "start", "end", "baseline", "first-baseline", "last-baseline"];
            let justify = ["normal", "stretch", "center", "flex-start", "flex-end", "start", "end", "left", "right", "baseline"];
            let toks: Vec<&str> = v.split_whitespace().collect();
            !toks.is_empty()
                && toks
                    .iter()
                    .all(|t| align.contains(t) || justify.contains(t))
        }
        "place-content" => {
            let allowed = ["normal", "flex-start", "flex-end", "center", "space-between", "space-around", "space-evenly", "start", "end", "stretch", "baseline", "first-baseline", "last-baseline"];
            tokens_ok(&allowed)
        }
        _ => false,
    }
}

/// `CSS.supports(prop, value)` / `CSS.supports(conditionText)`.
fn cb_css_supports<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let a0 = arg_string(scope, &args, 0).unwrap_or_default();
    let supported = if let Some(b) = arg_string(scope, &args, 1) {
        css_supports(&a0, &b)
    } else {
        // Single-argument condition form: "(prop: value)" or "prop: value".
        let cond = a0.trim();
        let cond = cond
            .strip_prefix('(')
            .and_then(|c| c.strip_suffix(')'))
            .unwrap_or(cond)
            .trim();
        match cond.split_once(':') {
            Some((p, v)) => css_supports(p, v),
            None => false,
        }
    };
    rv.set(v8::Boolean::new(scope, supported).into());
}

/// `new AbortController()` — the signal is a generic per-object event
/// target whose `aborted`/`reason` the controller's abort() flips.
fn cb_abort_controller_ctor<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    let Some(obj) = this.to_object(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let signal = v8::Object::new(scope);
    set_prop(scope, signal, "aborted", v8::Boolean::new(scope, false).into());
    set_prop(scope, signal, "reason", v8::undefined(scope).into());
    set_prop(scope, signal, "onabort", nullv(scope));
    let add = v8::Function::new(scope, cb_target_add_event_listener).expect("fn alloc");
    let remove = v8::Function::new(scope, cb_target_remove_event_listener).expect("fn alloc");
    set_prop(scope, signal, "addEventListener", add.into());
    set_prop(scope, signal, "removeEventListener", remove.into());
    let dispatch = v8::Function::new(scope, cb_noop).expect("fn alloc");
    set_prop(scope, signal, "dispatchEvent", dispatch.into());
    set_prop(scope, obj, "signal", signal.into());
    let abort = v8::FunctionTemplate::builder(cb_abort_controller_abort)
        .data(args.data())
        .build(scope)
        .get_function(scope);
    if let Some(abort) = abort {
        set_prop(scope, obj, "abort", abort.into());
    }
    rv.set(this.into());
}

fn cb_target_add_event_listener<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    if let Some(obj) = this.to_object(scope) {
        let capture = args.get(2);
        let capture = if capture.is_boolean() {
            capture
        } else {
            v8::Boolean::new(scope, false).into()
        };
        target_add_listener(scope, obj, args.get(0), args.get(1), capture);
    }
    rv.set(v8::undefined(scope).into());
}

fn cb_target_remove_event_listener<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    if let Some(obj) = this.to_object(scope) {
        let capture = args.get(2);
        let capture = if capture.is_boolean() {
            capture
        } else {
            v8::Boolean::new(scope, false).into()
        };
        target_remove_listener(scope, obj, args.get(0), args.get(1), capture);
    }
    rv.set(v8::undefined(scope).into());
}

/// `AbortController.prototype.abort(reason)` — flips `signal.aborted`,
/// fills `signal.reason` (argument, else a fresh AbortError DOMException),
/// and fires the signal's `abort` listeners synchronously (the spec's
/// order: flag, reason, then dispatch).
fn cb_abort_controller_abort<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    let Some(ctrl) = this.to_object(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let Some(signal) = ctrl
        .get(scope, sv(scope, "signal"))
        .and_then(|s| s.to_object(scope))
    else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let already = signal
        .get(scope, sv(scope, "aborted"))
        .map(|v| v.is_true())
        .unwrap_or(false);
    if already {
        rv.set(v8::undefined(scope).into());
        return;
    }
    set_prop(scope, signal, "aborted", v8::Boolean::new(scope, true).into());
    let reason = args.get(0);
    let reason = if reason.is_undefined() {
        dom_exception_obj(scope, "The operation was aborted.", "AbortError").into()
    } else {
        reason
    };
    let _ = signal.set(scope, sv(scope, "reason"), reason);
    let ev = make_event_obj(scope, "abort", Some(signal));
    target_fire_listeners(scope, signal, "abort", ev);
    rv.set(v8::undefined(scope).into());
}

/// Deep-clone the JSON-type subset for `structuredClone`: primitives pass
/// through; Array / plain Object recurse (own enumerable string keys);
/// ArrayBuffer and TypedArray views copy bytes; Date copies its epoch ms.
/// Cycles resolve to the already-built clone. Anything else (functions,
/// Map/Set, Error, ...) reports `could not be cloned` — the JS wrapper
/// turns that into a DataCloneError DOMException (documented floor: the
/// structuredClone-only types beyond this subset are rejected, not faked).
fn deep_clone_json<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    v: Local<'s, Value>,
    seen: &mut Vec<(v8::Global<Value>, Local<'s, Object>)>,
) -> Result<Local<'s, Value>, String> {
    if !v.is_object() {
        return Ok(v);
    }
    for (src, out) in seen.iter() {
        let src = v8::Local::new(scope, src.clone());
        if v.strict_equals(src) {
            return Ok((*out).into());
        }
    }
    if v.is_array() {
        let arr = v.cast::<v8::Array>();
        let len = arr.length();
        let out = v8::Array::new(scope, len as i32);
        seen.push((v8::Global::new(scope, v), out.into()));
        for i in 0..len {
            let Some(el) = arr.get_index(scope, i) else {
                continue;
            };
            let cloned = deep_clone_json(scope, el, seen)?;
            let _ = out.set_index(scope, i, cloned);
        }
        return Ok(out.into());
    }
    if v.is_array_buffer() {
        let ab = v.cast::<v8::ArrayBuffer>();
        let backing = ab.get_backing_store();
        let cells: &[std::cell::Cell<u8>] = &backing;
        let bytes: Vec<u8> = cells.iter().map(|c| c.get()).collect();
        let out = v8::ArrayBuffer::new(scope, bytes.len());
        let obacking = out.get_backing_store();
        let ocells: &[std::cell::Cell<u8>] = &obacking;
        for (i, b) in bytes.iter().enumerate() {
            if i < ocells.len() {
                ocells[i].set(*b);
            }
        }
        return Ok(out.into());
    }
    if v.is_date() {
        let ms = v.cast::<v8::Date>().value_of();
        return match v8::Date::new(scope, ms) {
            Some(d) => Ok(d.into()),
            None => Err("Date could not be cloned".to_string()),
        };
    }
    if v.is_typed_array() || v.is_data_view() {
        let view = v.cast::<v8::ArrayBufferView>();
        let offset = view.byte_offset();
        let len = view.byte_length();
        let Some(buffer) = view.buffer(nullscope(scope)) else {
            return Err("ArrayBufferView buffer unavailable".to_string());
        };
        let backing = buffer.get_backing_store();
        let cells: &[std::cell::Cell<u8>] = &backing;
        let bytes: Vec<u8> = cells
            .iter()
            .skip(offset)
            .take(len)
            .map(|c| c.get())
            .collect();
        let ab = v8::ArrayBuffer::new(scope, bytes.len());
        let obacking = ab.get_backing_store();
        let ocells: &[std::cell::Cell<u8>] = &obacking;
        for (i, b) in bytes.iter().enumerate() {
            if i < ocells.len() {
                ocells[i].set(*b);
            }
        }
        // The clone lands on a Uint8Array view regardless of the source
        // view's class this slice (documented floor).
        return match v8::Uint8Array::new(scope, ab, 0, bytes.len()) {
            Some(ua) => Ok(ua.into()),
            None => Err("ArrayBufferView could not be cloned".to_string()),
        };
    }
    if v.is_function() {
        return Err("function could not be cloned".to_string());
    }
    if let Some(obj) = v.to_object(scope) {
        // Reject the host-built shapes (Map/Set/Error/Promise and the
        // engine's own wrappers) rather than copying their internals —
        // those types are outside the JSON subset.
        if v.is_map() || v.is_set() || v.is_promise() || v.is_reg_exp() || v.is_native_error() {
            return Err("object could not be cloned".to_string());
        }
        let out = v8::Object::new(scope);
        seen.push((v8::Global::new(scope, v), out));
        let names = obj.get_own_property_names(
            scope,
            v8::GetPropertyNamesArgsBuilder::new()
                .mode(v8::KeyCollectionMode::OwnOnly)
                .build(),
        );
        if let Some(names) = names {
            for i in 0..names.length() {
                let Some(name) = names.get_index(scope, i) else {
                    continue;
                };
                let Some(val) = obj.get(scope, name) else {
                    continue;
                };
                let cloned = deep_clone_json(scope, val, seen)?;
                let _ = out.set(scope, name, cloned);
            }
        }
        return Ok(out.into());
    }
    Err("value could not be cloned".to_string())
}

/// `structuredClone(value)` — raw host side. The result is wrapped as
/// `{__seOk, value|err}` so the JS trampoline in finalize_context can tell
/// success from DataCloneError without a sentinel collision (a page
/// cloning `{__seOk: 1}` still round-trips correctly: the wrapper reads
/// the WRAPPER's field, not the clone's).
fn cb_structured_clone<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let mut seen = Vec::new();
    let out = v8::Object::new(scope);
    match deep_clone_json(scope, args.get(0), &mut seen) {
        Ok(v) => {
            set_prop(scope, out, "__seOk", v8::Boolean::new(scope, true).into());
            let _ = out.set(scope, sv(scope, "value"), v);
        }
        Err(e) => {
            set_prop(scope, out, "__seOk", v8::Boolean::new(scope, false).into());
            set_prop(scope, out, "err", sv(scope, &e));
        }
    }
    rv.set(out.into());
}

/// Performance-timeline shape: `getEntriesByType` / `getEntries` /
/// `getEntriesByName` return empty arrays (this engine records no
/// subresource timeline; an empty list is the honest report).
fn cb_empty_array<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    rv.set(v8::Array::new(scope, 0).into());
}

/// A function that resolves its returned promise with undefined —
/// `requestFullscreen` / `exitFullscreen` contract.
fn cb_promise_resolve_undefined<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let _ = resolver.resolve(scope, v8::undefined(scope).into());
    rv.set(resolver.get_promise(scope).into());
}

/// `navigator.geolocation.getCurrentPosition(success, error, opts)` —
/// this engine has no location source and no permission prompt; like a
/// fresh profile where the prompt is unanswered/denied, the ERROR
/// callback fires asynchronously with PERMISSION_DENIED (code 1).
fn cb_geo_get_current<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let err_cb = args.get(1);
    if err_cb.is_function() {
        let e = v8::Object::new(scope);
        set_prop(scope, e, "code", v8::Number::new(scope, 1.0).into());
        set_prop(
            scope,
            e,
            "message",
            sv(scope, "User denied Geolocation"),
        );
        for (k, n) in [
            ("PERMISSION_DENIED", 1.0),
            ("POSITION_UNAVAILABLE", 2.0),
            ("TIMEOUT", 3.0),
        ] {
            set_prop(scope, e, k, v8::Number::new(scope, n).into());
        }
        let st = unsafe { state_of(&args) };
        schedule_call_timer(scope, st, err_cb, e.into());
    }
    rv.set(v8::undefined(scope).into());
}

/// `navigator.geolocation.watchPosition(...)` — same denial contract as
/// getCurrentPosition; returns watch id 0 (clearWatch is a noop).
fn cb_geo_watch<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let err_cb = args.get(1);
    if err_cb.is_function() {
        let e = v8::Object::new(scope);
        set_prop(scope, e, "code", v8::Number::new(scope, 1.0).into());
        set_prop(
            scope,
            e,
            "message",
            sv(scope, "User denied Geolocation"),
        );
        let st = unsafe { state_of(&args) };
        schedule_call_timer(scope, st, err_cb, e.into());
    }
    rv.set(v8::Number::new(scope, 0.0).into());
}

/// `navigator.storage.estimate()` — resolves a plausible fresh-profile
/// quota with zero usage (no persisted origin data on this tier).
fn cb_storage_estimate<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let est = v8::Object::new(scope);
    set_prop(
        scope,
        est,
        "quota",
        v8::Number::new(scope, 60_000_000_000.0).into(),
    );
    set_prop(scope, est, "usage", v8::Number::new(scope, 0.0).into());
    let details = v8::Object::new(scope);
    set_prop(scope, est, "usageDetails", details.into());
    let _ = resolver.resolve(scope, est.into());
    rv.set(resolver.get_promise(scope).into());
}

/// `navigator.storage.persist()` / `persisted()` — the origin has not
/// asked for persistence (and a scraping profile wouldn't grant it).
fn cb_storage_bool<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let _ = resolver.resolve(scope, v8::Boolean::new(scope, false).into());
    rv.set(resolver.get_promise(scope).into());
}

/// `navigator.vibrate(...)` — desktop Chrome: present but ineffective.
fn cb_returns_false<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    rv.set(v8::Boolean::new(scope, false).into());
}

/// `indexedDB.open(name, version?)` — there is no IDB backend on this
/// tier; the request fires its `error` event asynchronously (like a
/// denied/quota-failed open) rather than hanging the page. `cmp` is real
/// for numbers and strings.
fn make_idb_request<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    st: &mut State,
    kind: &str,
) -> Local<'s, Object> {
    let req = v8::Object::new(scope);
    set_prop(scope, req, "readyState", sv(scope, "pending"));
    set_prop(scope, req, "result", v8::undefined(scope).into());
    set_prop(scope, req, "error", nullv(scope));
    set_prop(scope, req, "transaction", nullv(scope));
    set_prop(scope, req, "source", nullv(scope));
    for k in [
        "onsuccess",
        "onerror",
        "onupgradeneeded",
        "onblocked",
        "oncomplete",
        "onabort",
    ] {
        set_prop(scope, req, k, nullv(scope));
    }
    let add = v8::Function::new(scope, cb_target_add_event_listener).expect("fn alloc");
    let remove = v8::Function::new(scope, cb_target_remove_event_listener).expect("fn alloc");
    set_prop(scope, req, "addEventListener", add.into());
    set_prop(scope, req, "removeEventListener", remove.into());
    let err = dom_exception_obj(
        scope,
        &format!("IndexedDB is not available in this engine build ({kind})"),
        "InvalidStateError",
    );
    // Delivery closure: () => __seIdbError(req, err).
    let dispatch = st
        .idb_error_fn
        .as_ref()
        .map(|g| v8::Local::new(scope, g.clone()).into());
    if let Some(dispatch) = dispatch {
        let dispatch: Local<Value> = dispatch;
        let src = v8::String::new(scope, "(d,r,e)=>()=>d(r,e)").expect("string alloc");
        let closure = v8::Script::compile(scope, src, None)
            .and_then(|s| s.run(scope))
            .and_then(|f| {
                f.cast::<Function>().call(
                    scope,
                    v8::undefined(scope).into(),
                    &[dispatch, req.into(), err.into()],
                )
            });
        if let Some(closure) = closure {
            let id = st.next_timer_id;
            st.next_timer_id += 1;
            st.timers.push(Timer {
                id,
                deadline: Instant::now(),
                interval_ms: None,
                raf: false,
                callback: v8::Global::new(scope, closure.cast::<Function>()),
            });
        }
    }
    req
}

/// `__seIdbError(request, err)` — the async half of an IDB request error:
/// flips readyState, fills request.error, fires `onerror` + listeners.
fn cb_idb_error<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(req) = args.get(0).to_object(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let err = args.get(1);
    set_prop(scope, req, "readyState", sv(scope, "done"));
    let _ = req.set(scope, sv(scope, "error"), err);
    let ev = make_event_obj(scope, "error", Some(req));
    target_fire_listeners(scope, req, "error", ev);
    rv.set(v8::undefined(scope).into());
}

fn cb_idb_open<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let st = unsafe { state_of(&args) };
    let req = make_idb_request(scope, st, "open");
    rv.set(req.into());
}

fn cb_idb_delete<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let st = unsafe { state_of(&args) };
    let req = make_idb_request(scope, st, "deleteDatabase");
    rv.set(req.into());
}

/// `indexedDB.cmp(a, b)` — real ordering for numbers and strings.
fn cb_idb_cmp<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let a = args.get(0);
    let b = args.get(1);
    let ord = if a.is_number() && b.is_number() {
        let x = a.number_value(scope).unwrap_or(f64::NAN);
        let y = b.number_value(scope).unwrap_or(f64::NAN);
        if x < y {
            -1.0
        } else if x > y {
            1.0
        } else {
            0.0
        }
    } else if let (Some(x), Some(y)) = (
        a.to_string(scope).map(|s| s.to_rust_string_lossy(scope)),
        b.to_string(scope).map(|s| s.to_rust_string_lossy(scope)),
    ) {
        match x.cmp(&y) {
            std::cmp::Ordering::Less => -1.0,
            std::cmp::Ordering::Equal => 0.0,
            std::cmp::Ordering::Greater => 1.0,
        }
    } else {
        0.0
    };
    rv.set(v8::Number::new(scope, ord).into());
}

/// `customElements.define(name, ctor, opts)` — the registry is recorded
/// (get/whenDefined answer consistently) but upgrade is a noop: custom
/// element REACTIONS (attribute/insertion callbacks driving page-defined
/// classes) are a documented floor of this tier.
fn cb_custom_elements_define<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let name = arg_string(scope, &args, 0).unwrap_or_default();
    let ctor = args.get(1);
    if !name.contains('-') {
        // Spec: SyntaxError. Host can't throw (v8 152) — report via the
        // console-report floor; the define itself is a noop.
        rv.set(v8::undefined(scope).into());
        return;
    }
    let ctx = scope.get_current_context();
    let global = ctx.global(scope);
    if let Some(reg) = global
        .get(scope, sv(scope, "__seCustomRegistry"))
        .and_then(|v| v.to_object(scope))
    {
        let _ = reg.set(scope, sv(scope, &name), ctor);
    }
    rv.set(v8::undefined(scope).into());
}

fn cb_custom_elements_get<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let name = arg_string(scope, &args, 0).unwrap_or_default();
    let ctx = scope.get_current_context();
    let global = ctx.global(scope);
    let hit = global
        .get(scope, sv(scope, "__seCustomRegistry"))
        .and_then(|v| v.to_object(scope))
        .and_then(|reg| reg.get(scope, sv(scope, &name)))
        .filter(|v| !v.is_undefined());
    match hit {
        Some(v) => rv.set(v),
        None => rv.set(v8::undefined(scope).into()),
    }
}

/// `customElements.whenDefined(name)` — resolves when defined; for names
/// never defined the promise stays pending (the spec contract).
fn cb_custom_elements_when_defined<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let name = arg_string(scope, &args, 0).unwrap_or_default();
    let ctx = scope.get_current_context();
    let global = ctx.global(scope);
    let hit = global
        .get(scope, sv(scope, "__seCustomRegistry"))
        .and_then(|v| v.to_object(scope))
        .and_then(|reg| reg.get(scope, sv(scope, &name)))
        .filter(|v| !v.is_undefined());
    if let Some(v) = hit {
        let _ = resolver.resolve(scope, v);
    }
    rv.set(resolver.get_promise(scope).into());
}

/// `Element.prototype.attachShadow(init)` — returns a ShadowRoot-shaped
/// object; `open` mode also fills `el.shadowRoot` (spec contract).
/// No shadow-tree rendering/querying: the shadow root is an inert data
/// holder (documented floor).
fn cb_attach_shadow<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    let Some(el) = this.to_object(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let mode = args
        .get(0)
        .to_object(scope)
        .and_then(|o| o.get(scope, sv(scope, "mode")))
        .and_then(|m| m.to_string(scope))
        .map(|m| m.to_rust_string_lossy(scope))
        .unwrap_or_else(|| "open".to_string());
    let root = v8::Object::new(scope);
    set_prop(scope, root, "mode", sv(scope, &mode));
    set_prop(scope, root, "host", this.into());
    set_prop(scope, root, "innerHTML", sv(scope, ""));
    let delegates = v8::Function::new(scope, cb_noop).expect("fn alloc");
    set_prop(scope, root, "addEventListener", delegates.into());
    set_prop(scope, root, "removeEventListener", delegates.into());
    if mode == "open" {
        let _ = el.set(scope, sv(scope, "shadowRoot"), root.into());
    }
    rv.set(root.into());
}

// ---------------------------------------------------------------------
// M4 audio fingerprint tier (firing 27). The engine has no audio output
// device, but OfflineAudioContext rendering must not be a constant:
// fingerprint scripts sum `getChannelData()` output and compare configs
// (frequencies, waveform types, compressor on/off) to catch stubbed audio.
// The DSP lives in se-js/src/audio.rs (real oscillator waveforms + the Web
// Audio soft-knee compressor); this layer captures the JS graph via hidden
// props on the context/node objects (_nodes, _downstream, _toDest, _dest,
// _started) and renders started source chains at startRendering() time.
// Everything is STATELESS — the wall clock for `currentTime` is read from
// std::time, so no callback needs the State external.
// Floors (documented): branchy graphs render the first downstream chain
// only, signal routed THROUGH an AudioParam doesn't carry, unmodelled
// node kinds (biquad/delay/waveshaper/merger/splitter/scriptProcessor/
// mediaElementSource) pass signal through unchanged, decodeAudioData
// rejects (no decoder), analyser fills report deterministic silence.
// ---------------------------------------------------------------------

/// Wall-clock epoch milliseconds (the currentTime clock; no State needed).
fn now_ms() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as f64)
        .unwrap_or(0.0)
}

/// Define a non-enumerable own property — the hidden graph fields must not
/// show up when a page JSON-stringifies a returned AudioBuffer (44100
/// samples would otherwise serialize into the eval result).
fn hide_prop<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    obj: Local<'_, Object>,
    key: &str,
    value: Local<'s, Value>,
) {
    let name = v8::String::new(nullscope(scope), key)
        .expect("string alloc")
        .cast::<v8::Name>();
    let _ = obj.define_own_property(scope, name, value, v8::PropertyAttribute::DONT_ENUM);
}

fn audio_num_arg<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: &FunctionCallbackArguments<'_>,
    i: usize,
    default: f64,
) -> f64 {
    args.get(i as i32)
        .to_number(scope)
        .map(|n| n.value())
        .unwrap_or(default)
}

/// Numeric data property read with a default.
fn audio_prop_f64<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    node: Local<'_, Object>,
    key: &str,
    default: f64,
) -> f64 {
    node.get(scope, sv(scope, key))
        .and_then(|v| v.to_number(scope))
        .map(|n| n.value())
        .unwrap_or(default)
}

fn audio_prop_bool<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    node: Local<'_, Object>,
    key: &str,
    default: bool,
) -> bool {
    node.get(scope, sv(scope, key))
        .map(|v| v.is_true())
        .unwrap_or(default)
}

fn audio_prop_string<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    node: Local<'_, Object>,
    key: &str,
    default: &str,
) -> String {
    node.get(scope, sv(scope, key))
        .and_then(|v| v.to_string(scope))
        .map(|s| s.to_rust_string_lossy(scope))
        .unwrap_or_else(|| default.to_string())
}

/// Read a live AudioParam's `value` off a node (`node.<name>.value`),
/// falling back to `default`. Both mutation paths converge here: direct
/// assignment (`osc.frequency.value = 10000`) writes the param object's
/// data prop, and the automation setters update that same prop.
fn audio_param_value<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    node: Local<'_, Object>,
    name: &str,
    default: f64,
) -> f64 {
    node.get(scope, sv(scope, name))
        .and_then(|p| p.to_object(scope))
        .and_then(|p| p.get(scope, sv(scope, "value")))
        .and_then(|v| v.to_number(scope))
        .map(|n| n.value())
        .unwrap_or(default)
}

/// `AudioParam` shape: value/defaultValue/minValue/maxValue plus the
/// chainable automation methods (each sets `value` and returns `this`).
fn audio_param_obj<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    value: f64,
    default: f64,
    min: f64,
    max: f64,
) -> Local<'s, Object> {
    let p = v8::Object::new(scope);
    set_prop(scope, p, "value", v8::Number::new(scope, value).into());
    set_prop(scope, p, "defaultValue", v8::Number::new(scope, default).into());
    set_prop(scope, p, "minValue", v8::Number::new(scope, min).into());
    set_prop(scope, p, "maxValue", v8::Number::new(scope, max).into());
    for m in [
        "setValueAtTime",
        "linearRampToValueAtTime",
        "exponentialRampToValueAtTime",
        "setTargetAtTime",
    ] {
        let f = v8::Function::new(scope, cb_audio_param_set).expect("fn alloc");
        set_prop(scope, p, m, f.into());
    }
    let c = v8::Function::new(scope, cb_audio_param_return_this).expect("fn alloc");
    set_prop(scope, p, "cancelScheduledValues", c.into());
    p
}

/// Automation setter: `this.value = Number(arg0); return this`.
fn cb_audio_param_set<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    if let Some(p) = this.to_object(scope) {
        let v = args.get(0);
        if v.is_undefined() {
            let _ = p.set(scope, sv(scope, "value"), v8::Number::new(scope, 0.0).into());
        } else {
            let _ = p.set(scope, sv(scope, "value"), v);
        }
    }
    rv.set(this.into());
}

fn cb_audio_param_return_this<'s, 'i>(
    _scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    rv.set(args.this().into());
}

/// Materialize a Float32Array's element values (little-endian read through
/// the shared backing store).
fn typed_array_f32<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    v: Local<'_, Value>,
) -> Vec<f32> {
    if !v.is_typed_array() {
        return Vec::new();
    }
    let ta = v.cast::<v8::TypedArray>();
    let offset = ta.byte_offset();
    let count = ta.length();
    let Some(buf) = ta.buffer(nullscope(scope)) else {
        return Vec::new();
    };
    let backing = buf.get_backing_store();
    let bytes: &[std::cell::Cell<u8>] = &backing;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let base = offset + i * 4;
        if base + 4 <= bytes.len() {
            out.push(f32::from_le_bytes([
                bytes[base].get(),
                bytes[base + 1].get(),
                bytes[base + 2].get(),
                bytes[base + 3].get(),
            ]));
        } else {
            out.push(0.0);
        }
    }
    out
}

/// Typed-array OR plain-array numeric fill, used by the analyser methods.
fn fill_num_array<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    v: Local<'s, Value>,
    f: impl Fn(usize) -> f64,
) {
    if v.is_typed_array() {
        let ta = v.cast::<v8::TypedArray>();
        let count = ta.length();
        let elem = if count > 0 {
            (ta.byte_length() / count).max(1)
        } else {
            4
        };
        let Some(buf) = ta.buffer(nullscope(scope)) else {
            return;
        };
        let backing = buf.get_backing_store();
        let cells: &[std::cell::Cell<u8>] = &backing;
        let offset = ta.byte_offset();
        for i in 0..count {
            let val = f(i);
            if elem == 1 {
                let p = offset + i;
                if p < cells.len() {
                    cells[p].set((val as i32).clamp(0, 255) as u8);
                }
            } else {
                let base = offset + i * elem;
                let b = (val as f32).to_le_bytes();
                for (j, byte) in b.iter().enumerate() {
                    if base + j < cells.len() {
                        cells[base + j].set(*byte);
                    }
                }
            }
        }
        return;
    }
    if v.is_array() {
        let arr = v.cast::<v8::Array>();
        for i in 0..arr.length() {
            let _ = arr.set_index(scope, i, v8::Number::new(scope, f(i as usize)).into());
        }
    }
}

/// Build an `AudioBuffer`: one ArrayBuffer backing all channels, each
/// channel a Float32Array view at its offset (spec layout), with
/// getChannelData/copyToChannel/copyFromChannel.
fn make_audio_buffer<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    channels: &[Vec<f32>],
    sample_rate: f64,
) -> Local<'s, Object> {
    let nch = channels.len();
    let len = channels.first().map(|c| c.len()).unwrap_or(0);
    let total = len.saturating_mul(nch).saturating_mul(4);
    let ab = v8::ArrayBuffer::new(scope, total);
    {
        let backing = ab.get_backing_store();
        let cells: &[std::cell::Cell<u8>] = &backing;
        for (ch, data) in channels.iter().enumerate() {
            for (i, s) in data.iter().enumerate() {
                let base = (ch * len + i) * 4;
                if base + 4 <= cells.len() {
                    let b = s.to_le_bytes();
                    cells[base].set(b[0]);
                    cells[base + 1].set(b[1]);
                    cells[base + 2].set(b[2]);
                    cells[base + 3].set(b[3]);
                }
            }
        }
    }
    let buf = v8::Object::new(scope);
    let chans_arr = v8::Array::new(scope, nch as i32);
    for ch in 0..nch {
        if let Some(view) = v8::Float32Array::new(scope, ab, ch * len * 4, len) {
            let _ = chans_arr.set_index(scope, ch as u32, view.into());
        }
    }
    hide_prop(scope, buf, "_chans", chans_arr.into());
    set_prop(scope, buf, "length", v8::Number::new(scope, len as f64).into());
    set_prop(
        scope,
        buf,
        "duration",
        v8::Number::new(
            scope,
            if sample_rate > 0.0 {
                len as f64 / sample_rate
            } else {
                0.0
            },
        )
        .into(),
    );
    set_prop(scope, buf, "numberOfChannels", v8::Number::new(scope, nch as f64).into());
    set_prop(scope, buf, "sampleRate", v8::Number::new(scope, sample_rate).into());
    let get_ch = v8::Function::new(scope, cb_get_channel_data).expect("fn alloc");
    set_prop(scope, buf, "getChannelData", get_ch.into());
    let ctc = v8::Function::new(scope, cb_copy_to_channel).expect("fn alloc");
    set_prop(scope, buf, "copyToChannel", ctc.into());
    let cfc = v8::Function::new(scope, cb_copy_from_channel).expect("fn alloc");
    set_prop(scope, buf, "copyFromChannel", cfc.into());
    buf
}

fn cb_get_channel_data<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    let idx = args
        .get(0)
        .to_number(scope)
        .map(|n| n.value() as i64)
        .unwrap_or(0);
    let out = this
        .to_object(scope)
        .and_then(|o| o.get(scope, sv(scope, "_chans")))
        .filter(|v| v.is_array())
        .map(|v| v.cast::<v8::Array>())
        .and_then(|a| {
            if idx >= 0 && (idx as u32) < a.length() {
                a.get_index(scope, idx as u32)
            } else {
                None
            }
        });
    match out {
        Some(v) => rv.set(v),
        None => rv.set(v8::undefined(scope).into()),
    }
}

/// `copyToChannel(src, channel, start)` — copy src values into the
/// channel's Float32Array at `start` (typed-array or plain-array src).
fn cb_copy_to_channel<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    let Some(o) = this.to_object(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let idx = args
        .get(1)
        .to_number(scope)
        .map(|n| n.value() as i64)
        .unwrap_or(0);
    let start = args
        .get(2)
        .to_number(scope)
        .map(|n| n.value() as i64)
        .unwrap_or(0)
        .max(0) as usize;
    let Some(chans) = o
        .get(scope, sv(scope, "_chans"))
        .filter(|v| v.is_array())
        .map(|v| v.cast::<v8::Array>())
    else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    if idx < 0 || (idx as u32) >= chans.length() {
        rv.set(v8::undefined(scope).into());
        return;
    }
    let Some(dest) = chans.get_index(scope, idx as u32) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    if !dest.is_typed_array() {
        rv.set(v8::undefined(scope).into());
        return;
    }
    let src = args.get(0);
    let vals = if src.is_typed_array() {
        typed_array_f32(scope, src)
    } else if src.is_array() {
        let a = src.cast::<v8::Array>();
        let mut v = Vec::with_capacity(a.length() as usize);
        for i in 0..a.length() {
            v.push(
                a.get_index(scope, i)
                    .and_then(|e| e.to_number(scope))
                    .map(|n| n.value() as f32)
                    .unwrap_or(0.0),
            );
        }
        v
    } else {
        Vec::new()
    };
    let ta = dest.cast::<v8::TypedArray>();
    let Some(buf) = ta.buffer(nullscope(scope)) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let backing = buf.get_backing_store();
    let cells: &[std::cell::Cell<u8>] = &backing;
    let offset = ta.byte_offset();
    for (k, val) in vals.iter().enumerate() {
        let base = offset + (start + k) * 4;
        if base + 4 <= cells.len() {
            let b = (*val as f32).to_le_bytes();
            cells[base].set(b[0]);
            cells[base + 1].set(b[1]);
            cells[base + 2].set(b[2]);
            cells[base + 3].set(b[3]);
        }
    }
    rv.set(v8::undefined(scope).into());
}

fn cb_copy_from_channel<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    let Some(o) = this.to_object(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let idx = args
        .get(1)
        .to_number(scope)
        .map(|n| n.value() as i64)
        .unwrap_or(0);
    let start = args
        .get(2)
        .to_number(scope)
        .map(|n| n.value() as i64)
        .unwrap_or(0)
        .max(0) as usize;
    let Some(chans) = o
        .get(scope, sv(scope, "_chans"))
        .filter(|v| v.is_array())
        .map(|v| v.cast::<v8::Array>())
    else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    if idx < 0 || (idx as u32) >= chans.length() {
        rv.set(v8::undefined(scope).into());
        return;
    }
    let Some(src) = chans.get_index(scope, idx as u32) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let vals = typed_array_f32(scope, src);
    let dest = args.get(0);
    if dest.is_typed_array() {
        let ta = dest.cast::<v8::TypedArray>();
        let Some(buf) = ta.buffer(nullscope(scope)) else {
            rv.set(v8::undefined(scope).into());
            return;
        };
        let backing = buf.get_backing_store();
        let cells: &[std::cell::Cell<u8>] = &backing;
        let offset = ta.byte_offset();
        let count = ta.length();
        for k in 0..count {
            let val = vals.get(start + k).copied().unwrap_or(0.0);
            let base = offset + k * 4;
            if base + 4 <= cells.len() {
                let b = val.to_le_bytes();
                cells[base].set(b[0]);
                cells[base + 1].set(b[1]);
                cells[base + 2].set(b[2]);
                cells[base + 3].set(b[3]);
            }
        }
    } else if dest.is_array() {
        let a = dest.cast::<v8::Array>();
        for k in 0..a.length() {
            let val = vals.get(start + k as usize).copied().unwrap_or(0.0);
            let _ = a.set_index(scope, k, v8::Number::new(scope, val as f64).into());
        }
    }
    rv.set(v8::undefined(scope).into());
}

/// `new AudioBuffer({length, numberOfChannels, sampleRate})` — zero-filled
/// channels at the requested shape.
fn cb_audio_buffer_ctor<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let (mut len, mut nch, mut rate) = (0.0, 1.0, crate::audio::SAMPLE_RATE);
    if let Some(opts) = args.get(0).to_object(scope) {
        len = opts
            .get(scope, sv(scope, "length"))
            .and_then(|v| v.to_number(scope))
            .map(|n| n.value())
            .unwrap_or(0.0);
        nch = opts
            .get(scope, sv(scope, "numberOfChannels"))
            .and_then(|v| v.to_number(scope))
            .map(|n| n.value())
            .unwrap_or(1.0);
        rate = opts
            .get(scope, sv(scope, "sampleRate"))
            .and_then(|v| v.to_number(scope))
            .map(|n| n.value())
            .unwrap_or(crate::audio::SAMPLE_RATE);
    }
    let len = len.round().clamp(0.0, 5_000_000.0) as usize;
    let nch = nch.round().clamp(1.0, 10.0) as usize;
    let rate = if rate > 0.0 && rate.is_finite() {
        rate
    } else {
        crate::audio::SAMPLE_RATE
    };
    let channels = vec![vec![0.0f32; len]; nch];
    let buf = make_audio_buffer(scope, &channels, rate);
    rv.set(buf.into());
}

/// Build an audio node object with the shared graph hidden fields and the
/// connect/disconnect methods. `_dest` records the context's destination
/// for strict-identity checks in `connect`.
fn make_audio_node<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    kind: &str,
    ctx: Local<'_, Object>,
) -> Local<'s, Object> {
    let node = v8::Object::new(scope);
    hide_prop(scope, node, "_seKind", sv(scope, kind));
    let ds = v8::Array::new(scope, 0);
    hide_prop(scope, node, "_downstream", ds.into());
    hide_prop(
        scope,
        node,
        "_toDest",
        v8::Boolean::new(scope, false).into(),
    );
    hide_prop(
        scope,
        node,
        "_started",
        v8::Boolean::new(scope, false).into(),
    );
    if let Some(dest) = ctx.get(scope, sv(scope, "destination")) {
        hide_prop(scope, node, "_dest", dest);
    }
    let connect = v8::Function::new(scope, cb_audio_connect).expect("fn alloc");
    set_prop(scope, node, "connect", connect.into());
    let disconnect = v8::Function::new(scope, cb_audio_disconnect).expect("fn alloc");
    set_prop(scope, node, "disconnect", disconnect.into());
    node
}

fn audio_ctx_push_node<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    ctx: Local<'_, Object>,
    node: Local<'_, Object>,
) {
    if let Some(arr) = ctx
        .get(scope, sv(scope, "_nodes"))
        .filter(|v| v.is_array())
        .map(|v| v.cast::<v8::Array>())
    {
        let _ = arr.set_index(scope, arr.length(), node.into());
    }
}

/// `node.connect(dest)` — identity-check against the context's
/// destination (sets `_toDest`), otherwise record the downstream edge.
/// Returns `dest` (the spec's chaining contract).
fn cb_audio_connect<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    let dest = args.get(0);
    let Some(node) = this.to_object(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    if dest.is_undefined() || dest.is_null() {
        rv.set(v8::undefined(scope).into());
        return;
    }
    let is_dest = node
        .get(scope, sv(scope, "_dest"))
        .map(|d| d.strict_equals(dest))
        .unwrap_or(false);
    if is_dest {
        let _ = node.set(scope, sv(scope, "_toDest"), v8::Boolean::new(scope, true).into());
    } else if let Some(arr) = node
        .get(scope, sv(scope, "_downstream"))
        .filter(|v| v.is_array())
        .map(|v| v.cast::<v8::Array>())
    {
        let _ = arr.set_index(scope, arr.length(), dest);
    }
    rv.set(dest);
}

fn cb_audio_disconnect<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    if let Some(node) = this.to_object(scope) {
        let fresh = v8::Array::new(scope, 0);
        let _ = node.set(scope, sv(scope, "_downstream"), fresh.into());
        let _ = node.set(scope, sv(scope, "_toDest"), v8::Boolean::new(scope, false).into());
    }
    rv.set(v8::undefined(scope).into());
}

/// `start()` on a source node — marks the chain renderable.
fn cb_audio_start<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    if let Some(node) = this.to_object(scope) {
        let _ = node.set(scope, sv(scope, "_started"), v8::Boolean::new(scope, true).into());
    }
    rv.set(v8::undefined(scope).into());
}

fn cb_audio_stop<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    rv.set(v8::undefined(scope).into());
}

/// Shared body for the simple node factories (merger/splitter/script
/// processor/media-element source): node + push into the context graph.
fn simple_audio_factory<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
    kind: &str,
) {
    let ctx = args.this();
    let node = make_audio_node(scope, kind, ctx);
    audio_ctx_push_node(scope, ctx, node);
    rv.set(node.into());
}

fn cb_audio_create_merger<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    rv: ReturnValue<'s, Value>,
) {
    simple_audio_factory(scope, args, rv, "channelMerger");
}

fn cb_audio_create_splitter<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    rv: ReturnValue<'s, Value>,
) {
    simple_audio_factory(scope, args, rv, "channelSplitter");
}

fn cb_audio_create_script_processor<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    rv: ReturnValue<'s, Value>,
) {
    simple_audio_factory(scope, args, rv, "scriptProcessor");
}

fn cb_audio_create_media_element_source<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    rv: ReturnValue<'s, Value>,
) {
    simple_audio_factory(scope, args, rv, "mediaElementSource");
}

fn cb_audio_create_oscillator<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let ctx = args.this();
    let node = make_audio_node(scope, "oscillator", ctx);
    set_prop(scope, node, "type", sv(scope, "sine"));
    let freq = audio_param_obj(scope, 440.0, 440.0, -22050.0, 22050.0);
    set_prop(scope, node, "frequency", freq.into());
    let detune = audio_param_obj(scope, 0.0, 0.0, -3.4028234663852886e38, 3.4028234663852886e38);
    set_prop(scope, node, "detune", detune.into());
    let start = v8::Function::new(scope, cb_audio_start).expect("fn alloc");
    set_prop(scope, node, "start", start.into());
    let stop = v8::Function::new(scope, cb_audio_stop).expect("fn alloc");
    set_prop(scope, node, "stop", stop.into());
    let spw = v8::Function::new(scope, cb_audio_stop).expect("fn alloc");
    set_prop(scope, node, "setPeriodicWave", spw.into());
    set_prop(scope, node, "onended", nullv(scope));
    audio_ctx_push_node(scope, ctx, node);
    rv.set(node.into());
}

fn cb_audio_create_gain<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let ctx = args.this();
    let node = make_audio_node(scope, "gain", ctx);
    let gain = audio_param_obj(scope, 1.0, 1.0, 0.0, 1.0);
    set_prop(scope, node, "gain", gain.into());
    audio_ctx_push_node(scope, ctx, node);
    rv.set(node.into());
}

fn cb_audio_create_compressor<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let ctx = args.this();
    let node = make_audio_node(scope, "dynamicsCompressor", ctx);
    let threshold = audio_param_obj(scope, -24.0, -24.0, -100.0, 0.0);
    set_prop(scope, node, "threshold", threshold.into());
    let knee = audio_param_obj(scope, 30.0, 30.0, 0.0, 40.0);
    set_prop(scope, node, "knee", knee.into());
    let ratio = audio_param_obj(scope, 12.0, 12.0, 1.0, 20.0);
    set_prop(scope, node, "ratio", ratio.into());
    let attack = audio_param_obj(scope, 0.003, 0.003, 0.0, 1.0);
    set_prop(scope, node, "attack", attack.into());
    let release = audio_param_obj(scope, 0.25, 0.25, 0.0, 1.0);
    set_prop(scope, node, "release", release.into());
    set_prop(scope, node, "reduction", v8::Number::new(scope, 0.0).into());
    audio_ctx_push_node(scope, ctx, node);
    rv.set(node.into());
}

fn cb_audio_create_buffer_source<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let ctx = args.this();
    let node = make_audio_node(scope, "bufferSource", ctx);
    set_prop(scope, node, "buffer", nullv(scope));
    let rate = audio_param_obj(scope, 1.0, 1.0, -3.4028234663852886e38, 3.4028234663852886e38);
    set_prop(scope, node, "playbackRate", rate.into());
    let detune = audio_param_obj(scope, 0.0, 0.0, -3.4028234663852886e38, 3.4028234663852886e38);
    set_prop(scope, node, "detune", detune.into());
    set_prop(scope, node, "loop", v8::Boolean::new(scope, false).into());
    set_prop(scope, node, "loopStart", v8::Number::new(scope, 0.0).into());
    set_prop(scope, node, "loopEnd", v8::Number::new(scope, 0.0).into());
    let start = v8::Function::new(scope, cb_audio_start).expect("fn alloc");
    set_prop(scope, node, "start", start.into());
    let stop = v8::Function::new(scope, cb_audio_stop).expect("fn alloc");
    set_prop(scope, node, "stop", stop.into());
    set_prop(scope, node, "onended", nullv(scope));
    audio_ctx_push_node(scope, ctx, node);
    rv.set(node.into());
}

fn cb_audio_create_analyser<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let ctx = args.this();
    let node = make_audio_node(scope, "analyser", ctx);
    set_prop(scope, node, "fftSize", v8::Number::new(scope, 2048.0).into());
    set_prop(scope, node, "minDecibels", v8::Number::new(scope, -100.0).into());
    set_prop(scope, node, "maxDecibels", v8::Number::new(scope, -30.0).into());
    set_prop(scope, node, "smoothingTimeConstant", v8::Number::new(scope, 0.8).into());
    let bin_name = v8::String::new(nullscope(scope), "frequencyBinCount")
        .expect("string alloc")
        .cast::<v8::Name>();
    let _ = node.set_accessor(scope, bin_name, cb_analyser_bin_count);
    let ff = v8::Function::new(scope, cb_analyser_float_freq).expect("fn alloc");
    set_prop(scope, node, "getFloatFrequencyData", ff.into());
    let bf = v8::Function::new(scope, cb_analyser_byte_freq).expect("fn alloc");
    set_prop(scope, node, "getByteFrequencyData", bf.into());
    let ft = v8::Function::new(scope, cb_analyser_float_time).expect("fn alloc");
    set_prop(scope, node, "getFloatTimeDomainData", ft.into());
    let bt = v8::Function::new(scope, cb_analyser_byte_time).expect("fn alloc");
    set_prop(scope, node, "getByteTimeDomainData", bt.into());
    audio_ctx_push_node(scope, ctx, node);
    rv.set(node.into());
}

fn cb_analyser_bin_count<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _name: Local<'s, v8::Name>,
    args: PropertyCallbackArguments<'s>,
    mut rv: ReturnValue<Value>,
) {
    // The accessor is installed directly on the analyser instance, so the
    // holder IS the node.
    let this = args.holder();
    let fft = audio_prop_f64(scope, this, "fftSize", 2048.0);
    rv.set(v8::Number::new(scope, fft / 2.0).into());
}

/// Silent-input analyser fills: frequency arrays at minDecibels (float) /
/// 0 (byte), time-domain 0.0 (float) / 128 (byte midpoint). Deterministic.
fn cb_analyser_float_freq<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    let min = this
        .to_object(scope)
        .map(|o| audio_prop_f64(scope, o, "minDecibels", -100.0))
        .unwrap_or(-100.0);
    fill_num_array(scope, args.get(0), |_| min);
    rv.set(v8::undefined(scope).into());
}

fn cb_analyser_byte_freq<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    fill_num_array(scope, args.get(0), |_| 0.0);
    rv.set(v8::undefined(scope).into());
}

fn cb_analyser_float_time<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    fill_num_array(scope, args.get(0), |_| 0.0);
    rv.set(v8::undefined(scope).into());
}

fn cb_analyser_byte_time<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    fill_num_array(scope, args.get(0), |_| 128.0);
    rv.set(v8::undefined(scope).into());
}

fn cb_audio_create_biquad<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let ctx = args.this();
    let node = make_audio_node(scope, "biquadFilter", ctx);
    set_prop(scope, node, "type", sv(scope, "lowpass"));
    let freq = audio_param_obj(scope, 350.0, 350.0, 10.0, 22050.0);
    set_prop(scope, node, "frequency", freq.into());
    let detune = audio_param_obj(scope, 0.0, 0.0, -3.4028234663852886e38, 3.4028234663852886e38);
    set_prop(scope, node, "detune", detune.into());
    let q = audio_param_obj(scope, 1.0, 1.0, 0.0001, 1000.0);
    set_prop(scope, node, "Q", q.into());
    let gain = audio_param_obj(scope, 0.0, 0.0, -40.0, 40.0);
    set_prop(scope, node, "gain", gain.into());
    audio_ctx_push_node(scope, ctx, node);
    rv.set(node.into());
}

fn cb_audio_create_delay<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let ctx = args.this();
    let node = make_audio_node(scope, "delay", ctx);
    let dt = audio_param_obj(scope, 0.0, 0.0, 0.0, 1.0);
    set_prop(scope, node, "delayTime", dt.into());
    audio_ctx_push_node(scope, ctx, node);
    rv.set(node.into());
}

fn cb_audio_create_waveshaper<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let ctx = args.this();
    let node = make_audio_node(scope, "waveShaper", ctx);
    set_prop(scope, node, "curve", nullv(scope));
    set_prop(scope, node, "oversample", sv(scope, "none"));
    audio_ctx_push_node(scope, ctx, node);
    rv.set(node.into());
}

/// `createPeriodicWave(real, imag)` — the wave object is recorded (a
/// 'custom' oscillator renders as sine this tier: documented floor).
fn cb_audio_create_periodic_wave<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let o = v8::Object::new(scope);
    hide_prop(scope, o, "_seKind", sv(scope, "periodicWave"));
    hide_prop(scope, o, "_real", args.get(0));
    hide_prop(scope, o, "_imag", args.get(1));
    rv.set(o.into());
}

/// `ctx.createBuffer(ch, len, rate)` — zero-filled AudioBuffer.
fn cb_audio_create_buffer<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let nch = audio_num_arg(scope, &args, 0, 1.0).round().clamp(1.0, 10.0) as usize;
    let len = audio_num_arg(scope, &args, 1, 0.0).round().clamp(0.0, 5_000_000.0) as usize;
    let rate = audio_num_arg(scope, &args, 2, crate::audio::SAMPLE_RATE);
    let rate = if rate > 0.0 && rate.is_finite() {
        rate
    } else {
        crate::audio::SAMPLE_RATE
    };
    let channels = vec![vec![0.0f32; len]; nch];
    let buf = make_audio_buffer(scope, &channels, rate);
    rv.set(buf.into());
}

/// `decodeAudioData` — no decoder exists in the engine; rejects with a
/// NotSupportedError DOMException (the honest answer, not fake silence).
fn cb_decode_audio_data<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let err = dom_exception_obj(
        scope,
        "decodeAudioData is not supported: no audio backend",
        "NotSupportedError",
    );
    let _ = resolver.reject(scope, err.into());
    rv.set(resolver.get_promise(scope).into());
}

fn cb_audio_close<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    if let Some(o) = this.to_object(scope) {
        let _ = o.set(scope, sv(scope, "state"), sv(scope, "closed"));
    }
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let _ = resolver.resolve(scope, v8::undefined(scope).into());
    rv.set(resolver.get_promise(scope).into());
}

fn cb_audio_suspend<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    if let Some(o) = this.to_object(scope) {
        let _ = o.set(scope, sv(scope, "state"), sv(scope, "suspended"));
    }
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let _ = resolver.resolve(scope, v8::undefined(scope).into());
    rv.set(resolver.get_promise(scope).into());
}

fn cb_audio_resume<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    if let Some(o) = this.to_object(scope) {
        let _ = o.set(scope, sv(scope, "state"), sv(scope, "running"));
    }
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let _ = resolver.resolve(scope, v8::undefined(scope).into());
    rv.set(resolver.get_promise(scope).into());
}

/// `currentTime` accessor for both context classes: realtime contexts
/// advance on the wall clock from construction (hidden `_seT0`); offline
/// contexts report 0 before/after rendering.
fn cb_audio_current_time<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _name: Local<'s, v8::Name>,
    args: PropertyCallbackArguments<'s>,
    mut rv: ReturnValue<Value>,
) {
    // Installed directly on the context instance, so the holder IS `this`.
    let this = args.holder();
    if audio_prop_string(scope, this, "_seKind", "") == "offline" {
        rv.set(v8::Number::new(scope, 0.0).into());
        return;
    }
    let t0 = audio_prop_f64(scope, this, "_seT0", now_ms());
    rv.set(
        v8::Number::new(scope, ((now_ms() - t0) / 1000.0).max(0.0)).into(),
    );
}

/// Shared context surface: destination, listener, the node factories,
/// decodeAudioData, suspend/resume, and (per class) close/startRendering.
fn install_audio_ctx_surface<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    ctx: Local<'_, Object>,
    offline: bool,
) {
    let dest = v8::Object::new(scope);
    hide_prop(scope, dest, "_seKind", sv(scope, "destination"));
    let dds = v8::Array::new(scope, 0);
    hide_prop(scope, dest, "_downstream", dds.into());
    hide_prop(scope, dest, "_toDest", v8::Boolean::new(scope, false).into());
    set_prop(scope, dest, "maxChannelCount", v8::Number::new(scope, 2.0).into());
    set_prop(scope, dest, "channelCount", v8::Number::new(scope, 2.0).into());
    let dconn = v8::Function::new(scope, cb_audio_connect).expect("fn alloc");
    set_prop(scope, dest, "connect", dconn.into());
    let ddis = v8::Function::new(scope, cb_audio_disconnect).expect("fn alloc");
    set_prop(scope, dest, "disconnect", ddis.into());
    set_prop(scope, ctx, "destination", dest.into());

    // listener — the 10 orientation/position params as AudioParam shapes.
    let listener = v8::Object::new(scope);
    for (k, v) in [
        ("positionX", 0.0),
        ("positionY", 0.0),
        ("positionZ", 0.0),
        ("forwardX", 0.0),
        ("forwardY", 0.0),
        ("forwardZ", -1.0),
        ("upX", 0.0),
        ("upY", 1.0),
        ("upZ", 0.0),
    ] {
        let p = audio_param_obj(
            scope,
            v,
            v,
            -3.4028234663852886e38,
            3.4028234663852886e38,
        );
        set_prop(scope, listener, k, p.into());
    }
    set_prop(scope, ctx, "listener", listener.into());

    let nodes = v8::Array::new(scope, 0);
    hide_prop(scope, ctx, "_nodes", nodes.into());
    set_prop(
        scope,
        ctx,
        "state",
        sv(scope, if offline { "suspended" } else { "running" }),
    );
    set_prop(scope, ctx, "onstatechange", nullv(scope));

    // Node factories — installed one by one so each callback stays a fn
    // ITEM (the UnitType bound v8::Function::new requires is implemented
    // for zero-sized fn items, not fn pointers, so they can't ride an
    // array).
    let f = v8::Function::new(scope, cb_audio_create_oscillator).expect("fn alloc");
    set_prop(scope, ctx, "createOscillator", f.into());
    let f = v8::Function::new(scope, cb_audio_create_gain).expect("fn alloc");
    set_prop(scope, ctx, "createGain", f.into());
    let f = v8::Function::new(scope, cb_audio_create_compressor).expect("fn alloc");
    set_prop(scope, ctx, "createDynamicsCompressor", f.into());
    let f = v8::Function::new(scope, cb_audio_create_analyser).expect("fn alloc");
    set_prop(scope, ctx, "createAnalyser", f.into());
    let f = v8::Function::new(scope, cb_audio_create_buffer_source).expect("fn alloc");
    set_prop(scope, ctx, "createBufferSource", f.into());
    let f = v8::Function::new(scope, cb_audio_create_buffer).expect("fn alloc");
    set_prop(scope, ctx, "createBuffer", f.into());
    let f = v8::Function::new(scope, cb_audio_create_merger).expect("fn alloc");
    set_prop(scope, ctx, "createChannelMerger", f.into());
    let f = v8::Function::new(scope, cb_audio_create_splitter).expect("fn alloc");
    set_prop(scope, ctx, "createChannelSplitter", f.into());
    let f = v8::Function::new(scope, cb_audio_create_biquad).expect("fn alloc");
    set_prop(scope, ctx, "createBiquadFilter", f.into());
    let f = v8::Function::new(scope, cb_audio_create_delay).expect("fn alloc");
    set_prop(scope, ctx, "createDelay", f.into());
    let f = v8::Function::new(scope, cb_audio_create_waveshaper).expect("fn alloc");
    set_prop(scope, ctx, "createWaveShaper", f.into());
    let f = v8::Function::new(scope, cb_audio_create_script_processor).expect("fn alloc");
    set_prop(scope, ctx, "createScriptProcessor", f.into());
    let f = v8::Function::new(scope, cb_audio_create_media_element_source).expect("fn alloc");
    set_prop(scope, ctx, "createMediaElementSource", f.into());
    let f = v8::Function::new(scope, cb_audio_create_periodic_wave).expect("fn alloc");
    set_prop(scope, ctx, "createPeriodicWave", f.into());
    let f = v8::Function::new(scope, cb_decode_audio_data).expect("fn alloc");
    set_prop(scope, ctx, "decodeAudioData", f.into());

    let susp = v8::Function::new(scope, cb_audio_suspend).expect("fn alloc");
    set_prop(scope, ctx, "suspend", susp.into());
    let res = v8::Function::new(scope, cb_audio_resume).expect("fn alloc");
    set_prop(scope, ctx, "resume", res.into());
    let aw = v8::Object::new(scope);
    let awm = v8::Function::new(scope, cb_noop).expect("fn alloc");
    set_prop(scope, aw, "addModule", awm.into());
    set_prop(scope, ctx, "audioWorklet", aw.into());

    if offline {
        set_prop(scope, ctx, "baseLatency", v8::Number::new(scope, 0.0).into());
        let sr = v8::Function::new(scope, cb_offline_start_rendering).expect("fn alloc");
        set_prop(scope, ctx, "startRendering", sr.into());
    } else {
        set_prop(
            scope,
            ctx,
            "baseLatency",
            v8::Number::new(scope, 512.0 / crate::audio::SAMPLE_RATE).into(),
        );
        set_prop(scope, ctx, "outputLatency", v8::Number::new(scope, 0.0).into());
        let cl = v8::Function::new(scope, cb_audio_close).expect("fn alloc");
        set_prop(scope, ctx, "close", cl.into());
    }
}

/// `new AudioContext()` — realtime context surface. Rendering is only
/// meaningful on OfflineAudioContext; this class is the shape pages probe
/// (state/sampleRate/baseLatency/destination/currentTime).
fn cb_audio_context_ctor<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    let Some(obj) = this.to_object(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    hide_prop(scope, obj, "_seKind", sv(scope, "context"));
    hide_prop(scope, obj, "_seT0", v8::Number::new(scope, now_ms()).into());
    let ct_name = v8::String::new(nullscope(scope), "currentTime")
        .expect("string alloc")
        .cast::<v8::Name>();
    let _ = obj.set_accessor(scope, ct_name, cb_audio_current_time);
    set_prop(
        scope,
        obj,
        "sampleRate",
        v8::Number::new(scope, crate::audio::SAMPLE_RATE).into(),
    );
    install_audio_ctx_surface(scope, obj, false);
    rv.set(this.into());
}

/// `new OfflineAudioContext(channels, length, sampleRate)` — the render
/// target. Length is capped (5M samples ≈ 113 s at 44.1 kHz) so a hostile
/// page can't force a giant allocation.
fn cb_offline_audio_context_ctor<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    let Some(obj) = this.to_object(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let nch = audio_num_arg(scope, &args, 0, 1.0).round().clamp(1.0, 10.0) as usize;
    let len = audio_num_arg(scope, &args, 1, 44100.0)
        .round()
        .clamp(0.0, 5_000_000.0) as usize;
    let rate = audio_num_arg(scope, &args, 2, crate::audio::SAMPLE_RATE);
    let rate = if rate > 0.0 && rate.is_finite() {
        rate
    } else {
        crate::audio::SAMPLE_RATE
    };
    hide_prop(scope, obj, "_seKind", sv(scope, "offline"));
    hide_prop(scope, obj, "_seCh", v8::Number::new(scope, nch as f64).into());
    hide_prop(scope, obj, "_seLen", v8::Number::new(scope, len as f64).into());
    hide_prop(scope, obj, "_seRate", v8::Number::new(scope, rate).into());
    set_prop(scope, obj, "length", v8::Number::new(scope, len as f64).into());
    set_prop(scope, obj, "sampleRate", v8::Number::new(scope, rate).into());
    let ct_name = v8::String::new(nullscope(scope), "currentTime")
        .expect("string alloc")
        .cast::<v8::Name>();
    let _ = obj.set_accessor(scope, ct_name, cb_audio_current_time);
    install_audio_ctx_surface(scope, obj, true);
    rv.set(this.into());
}

/// `OfflineAudioContext.startRendering()` — walk the captured graph and
/// render every started source chain into a mono mix, duplicated across
/// the requested channel count. Same graph in → same buffer out (the
/// determinism a stable fingerprint requires); different graph configs
/// → different buffers (the honesty a fingerprint probe checks for).
fn cb_offline_start_rendering<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let this = args.this();
    let Some(ctx) = this.to_object(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let len = audio_prop_f64(scope, ctx, "_seLen", 44100.0).max(0.0) as usize;
    let nch = audio_prop_f64(scope, ctx, "_seCh", 1.0).round().clamp(1.0, 10.0) as usize;
    let rate = {
        let r = audio_prop_f64(scope, ctx, "_seRate", crate::audio::SAMPLE_RATE);
        if r > 0.0 && r.is_finite() {
            r
        } else {
            crate::audio::SAMPLE_RATE
        }
    };
    let _ = ctx.set(scope, sv(scope, "state"), sv(scope, "running"));
    let mut mix = vec![0.0f32; len];
    if let Some(nodes) = ctx
        .get(scope, sv(scope, "_nodes"))
        .filter(|v| v.is_array())
        .map(|v| v.cast::<v8::Array>())
    {
        for i in 0..nodes.length() {
            let Some(node) = nodes.get_index(scope, i).and_then(|v| v.to_object(scope))
            else {
                continue;
            };
            let kind = audio_prop_string(scope, node, "_seKind", "");
            let is_osc = kind == "oscillator";
            if !is_osc && kind != "bufferSource" {
                continue;
            }
            if !audio_prop_bool(scope, node, "_started", false) {
                continue;
            }
            let mut chain = crate::audio::RenderChain::silence();
            if is_osc {
                let ty = audio_prop_string(scope, node, "type", "sine");
                let freq = audio_param_value(scope, node, "frequency", 440.0);
                chain.osc = Some((crate::audio::OscKind::from(ty.as_str()), freq));
            } else {
                let Some(bufo) = node
                    .get(scope, sv(scope, "buffer"))
                    .and_then(|b| b.to_object(scope))
                else {
                    continue;
                };
                let Some(chans) = bufo
                    .get(scope, sv(scope, "_chans"))
                    .filter(|v| v.is_array())
                    .map(|v| v.cast::<v8::Array>())
                else {
                    continue;
                };
                let Some(ch0) = chans.get_index(scope, 0) else {
                    continue;
                };
                let mut data = typed_array_f32(scope, ch0);
                if audio_prop_bool(scope, node, "loop", false) && !data.is_empty() && len > 0 {
                    let mut wrapped = Vec::with_capacity(len);
                    for j in 0..len {
                        wrapped.push(data[j % data.len()]);
                    }
                    data = wrapped;
                }
                chain.buffer = Some(data);
            }
            // Walk the linear downstream chain (first branch), ≤8 hops.
            let mut follow = node;
            for _hop in 0..8 {
                if audio_prop_bool(scope, follow, "_toDest", false) {
                    let rendered = crate::audio::render_chain(&mut chain, len);
                    for (j, s) in rendered.iter().enumerate() {
                        if j < mix.len() {
                            mix[j] += *s;
                        }
                    }
                    break;
                }
                let Some(ds) = follow
                    .get(scope, sv(scope, "_downstream"))
                    .filter(|v| v.is_array())
                    .map(|v| v.cast::<v8::Array>())
                else {
                    break;
                };
                if ds.length() == 0 {
                    break;
                }
                let Some(next) = ds.get_index(scope, 0).and_then(|v| v.to_object(scope))
                else {
                    break;
                };
                match audio_prop_string(scope, next, "_seKind", "").as_str() {
                    "gain" => {
                        chain.gain *= audio_param_value(scope, next, "gain", 1.0);
                    }
                    "dynamicsCompressor" => {
                        chain.compress = Some(crate::audio::Compressor::with_params(
                            audio_param_value(scope, next, "threshold", -24.0),
                            audio_param_value(scope, next, "knee", 30.0),
                            audio_param_value(scope, next, "ratio", 12.0),
                            audio_param_value(scope, next, "attack", 0.003),
                            audio_param_value(scope, next, "release", 0.25),
                        ));
                    }
                    // analyser and unmodelled kinds: signal passes through.
                    _ => {}
                }
                follow = next;
            }
        }
    }
    let channels: Vec<Vec<f32>> = (0..nch).map(|_| mix.clone()).collect();
    let buf = make_audio_buffer(scope, &channels, rate);
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let _ = resolver.resolve(scope, buf.into());
    rv.set(resolver.get_promise(scope).into());
}

/// `document.hasFocus()` — the page is the active tab of the only window.
fn cb_has_focus<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    rv.set(v8::Boolean::new(scope, true).into());
}

/// `navigator.userAgentData.getHighEntropyValues(hints)` — resolves with
/// the requested high-entropy Client Hints. Every value comes from the
/// se-net constants the `Sec-CH-UA` wire headers are built from, so the
/// page-readable identity can't drift from the server-visible one. A
/// pre-resolved promise is enough: the eval pump's microtask checkpoint
/// drains the `await` chain.
fn cb_uad_high_entropy<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let mut requested: Vec<String> = Vec::new();
    let hints = args.get(0);
    if hints.is_array() {
        let arr = hints.cast::<v8::Array>();
        for i in 0..arr.length() {
            if let Some(el) = arr.get_index(scope, i) {
                if let Some(s) = el.to_string(scope) {
                    requested.push(s.to_rust_string_lossy(scope));
                }
            }
        }
    } else if let Some(s) = hints.to_string(scope) {
        requested.push(s.to_rust_string_lossy(scope));
    }

    let brand_objs = |versions: &str| -> Vec<Local<'_, Value>> {
        se_net::CHROME_BRANDS
            .iter()
            .map(|(brand, short)| {
                let b = v8::Object::new(scope);
                set_prop(scope, b, "brand", sv(scope, brand));
                set_prop(
                    scope,
                    b,
                    "version",
                    sv(scope, if versions.is_empty() { *short } else { versions }),
                );
                b.into()
            })
            .collect()
    };

    let ans = v8::Object::new(scope);
    for key in requested {
        match key.as_str() {
            "architecture" => set_prop(scope, ans, "architecture", sv(scope, se_net::UA_ARCHITECTURE)),
            "bitness" => set_prop(scope, ans, "bitness", sv(scope, se_net::UA_BITNESS)),
            "model" => set_prop(scope, ans, "model", sv(scope, "")),
            "platform" => set_prop(scope, ans, "platform", sv(scope, se_net::UA_PLATFORM)),
            "platformVersion" => {
                set_prop(scope, ans, "platformVersion", sv(scope, se_net::UA_PLATFORM_VERSION))
            }
            "uaFullVersion" => {
                set_prop(scope, ans, "uaFullVersion", sv(scope, se_net::UA_FULL_VERSION))
            }
            "mobile" => set_prop(scope, ans, "mobile", v8::Boolean::new(scope, false).into()),
            "wow64" => set_prop(scope, ans, "wow64", v8::Boolean::new(scope, false).into()),
            "formFactor" => set_prop(scope, ans, "formFactor", sv(scope, "Desktop")),
            "brands" => {
                let arr = v8::Array::new_with_elements(scope, &brand_objs(""));
                set_prop(scope, ans, "brands", arr.into());
            }
            "fullVersionList" => {
                let arr =
                    v8::Array::new_with_elements(scope, &brand_objs(se_net::UA_FULL_VERSION));
                set_prop(scope, ans, "fullVersionList", arr.into());
            }
            _ => {}
        }
    }

    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let promise = resolver.get_promise(scope);
    let _ = resolver.resolve(scope, ans.into());
    rv.set(promise.into());
}

/// `window.matchMedia(query)` — the viewport IS a real constant
/// (innerWidth/innerHeight), so the common probe queries evaluate for real
/// against it (see `eval_media_query`); the `media` string rides along
/// verbatim. Listener methods stay callable noops — matches never change
/// during an eval, so no change event can fire.
fn cb_match_media<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let query = args
        .get(0)
        .to_string(scope)
        .map(|s| s.to_rust_string_lossy(scope))
        .unwrap_or_default();
    let num = |key: &str, fallback: f64| {
        args.this()
            .get(scope, sv(scope, key))
            .and_then(|v| v.to_number(scope))
            .map(|n| n.value())
            .unwrap_or(fallback)
    };
    let (w, h) = (num("innerWidth", 1920.0), num("innerHeight", 937.0));
    let matches = eval_media_query(&query, w, h);
    let mql = v8::Object::new(scope);
    set_prop(scope, mql, "matches", v8::Boolean::new(scope, matches).into());
    set_prop(scope, mql, "media", sv(scope, &query));
    for k in [
        "addListener",
        "removeListener",
        "addEventListener",
        "removeEventListener",
        "dispatchEvent",
    ] {
        // Real noop functions, not strings: pages that subscribe to theme
        // changes call these; a non-callable would throw.
        if let Some(f) = v8::Function::new(scope, cb_noop) {
            set_prop(scope, mql, k, f.into());
        }
    }
    set_prop(scope, mql, "onchange", v8::null(scope).into());
    rv.set(mql.into());
}

fn cb_console<'s, 'i>(
    _scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    _rv: ReturnValue<'s, Value>,
) {
    // Deliberately swallowed: page logging has no consumer yet and printing
    // from the isolate thread would interleave with the sidecar's logs.
}

/// Fingerprint-tier canvas: a stable, deterministic toDataURL payload.
///
/// Real Chrome's toDataURL reflects GPU/driver/font state and varies per
/// machine — a privacy leak fingerprint scripts exploit. This engine has no
/// rasterizer, so the payload is a fixed render of the canonical probe text
/// at a fixed size: identical across runs, machines, and eval sessions, which
/// is exactly what a deterministic scraper wants. The empty-canvas case
/// returns the RFC 2397 transparent-pixel PNG (what real Chrome produces for
/// a never-drawn 300x150 canvas).
///
/// Dirtiness is PER CANVAS, tracked as a `__seDirty` flag on the canvas's
/// cached context object(s): a probe that draws on one canvas must not change
/// what a different, pristine canvas reports.
fn cb_canvas_to_data_url<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let mut dirty = false;
    for key in ["__ctx2d", "__ctxWebgl"] {
        if let Some(ctx) = args.this().get(scope, sv(scope, key)) {
            if ctx.is_object() {
                if let Some(flag) = ctx.to_object(scope).and_then(|o| o.get(scope, sv(scope, "__seDirty"))) {
                    if flag.is_true() {
                        dirty = true;
                    }
                }
            }
        }
    }
    let payload = if dirty {
        CANVAS_FINGERPRINT.to_string()
    } else {
        CANVAS_EMPTY_PNG.to_string()
    };
    rv.set(js_string(scope, &payload));
}

/// `getContext(kind)` dispatcher: '2d' → the probe-tracker 2d context,
/// 'webgl'/'webgl2'/'experimental-webgl' → the WebGL stub, anything else
/// → null (matching real Chrome's answer for unknown context types).
fn cb_canvas_get_context<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let kind = arg_string(scope, &args, 0).unwrap_or_default();
    if kind.eq_ignore_ascii_case("2d") {
        cb_canvas_get_context_2d(scope, args, rv);
    } else if kind.eq_ignore_ascii_case("webgl")
        || kind.eq_ignore_ascii_case("webgl2")
        || kind.eq_ignore_ascii_case("experimental-webgl")
    {
        cb_canvas_get_context_webgl(scope, args, rv);
    } else {
        rv.set(nullv(scope));
    }
}

/// The 2d-context half of the fingerprint surface. No real rasterization —
/// instead a stateful probe tracker: fillText/fillRect mark the canvas
/// dirty (so a later toDataURL returns the fingerprint payload), and
/// getImageData returns a fixed plausible result for the probe rectangle.
fn cb_canvas_get_context_2d<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let kind = arg_string(scope, &args, 0).unwrap_or_default();
    if !kind.eq_ignore_ascii_case("2d") {
        rv.set(nullv(scope));
        return;
    }
    // One 2d context per canvas: the probe tracker lives on `this`.
    if let Some(existing) = args.this().get(scope, sv(scope, "__ctx2d")) {
        if existing.is_object() {
            rv.set(existing);
            return;
        }
    }
    let ctx = v8::Object::new(scope);
    set_prop(scope, ctx, "fillStyle", sv(scope, "#000000"));
    set_prop(scope, ctx, "font", sv(scope, "10px sans-serif"));
    set_prop(scope, ctx, "textBaseline", sv(scope, "alphabetic"));
    set_prop(scope, ctx, "globalAlpha", v8::Number::new(scope, 1.0).into());
    set_prop(scope, ctx, "globalCompositeOperation", sv(scope, "source-over"));
    for k in ["fillText", "strokeText", "fillRect", "strokeRect", "drawImage"] {
        if let Some(f) = v8::FunctionTemplate::builder(cb_canvas_mark_dirty)
            .data(args.data())
            .build(scope)
            .get_function(scope)
        {
            let _ = ctx.set(scope, sv(scope, k), f.into());
        }
    }
    if let Some(f) = v8::FunctionTemplate::builder(cb_canvas_get_image_data)
        .data(args.data())
        .build(scope)
        .get_function(scope)
    {
        let _ = ctx.set(scope, sv(scope, "getImageData"), f.into());
    }
    // getContext('2d') returns the same object on repeat calls.
    let _ = args.this().set(scope, sv(scope, "__ctx2d"), ctx.into());
    rv.set(ctx.into());
}

/// Marks the canvas dirty: `this` is the 2d CONTEXT, so the flag lands on the
/// context object the owning canvas caches under `__ctx2d` — `toDataURL`
/// reads it back from there. Per-context, so one canvas's draw never affects
/// another's report.
fn cb_canvas_mark_dirty<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    if let Some(ctx) = args.this().to_object(scope) {
        set_prop(scope, ctx, "__seDirty", v8::Boolean::new(scope, true).into());
    }
    let u = v8::undefined(scope);
    rv.set(u.into());
}

fn cb_canvas_get_image_data<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    // Fixed 1x1 result with an opaque-black pixel — deterministic and
    // plausible for a probe that drew black-on-white text.
    let img = v8::Object::new(scope);
    set_prop(scope, img, "width", v8::Number::new(scope, 1.0).into());
    set_prop(scope, img, "height", v8::Number::new(scope, 1.0).into());
    // data: Uint8ClampedArray [0, 0, 0, 255] — one opaque-black pixel.
    // Real getImageData for a fillText probe would return the glyph's
    // antialiased coverage; a fixed value keeps the fingerprint stable
    // across runs (the tier's goal).
    let mut data = [0u8; 4];
    data[3] = 255;
    let arr = v8::ArrayBuffer::new(scope, 4);
    // Write the pixel through the backing store's [Cell<u8>] view.
    let backing = arr.get_backing_store();
    let bytes: &[std::cell::Cell<u8>] = &backing;
    for (i, b) in data.iter().enumerate() {
        if i < bytes.len() {
            bytes[i].set(*b);
        }
    }
    if let Some(clamped) = v8::Uint8ClampedArray::new(scope, arr, 0, 4) {
        set_prop(scope, img, "data", clamped.into());
    }
    rv.set(img.into());
}

/// WebGL context stub: enough shape that a fingerprint probe doesn't throw,
/// but no real rendering (this tier has no GPU). getParameter returns
/// plausible values for the common fingerprint queries; getExtension returns
/// null (no optional extensions); getSupportedExtensions returns [].
fn cb_canvas_get_context_webgl<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let kind = arg_string(scope, &args, 0).unwrap_or_default();
    if !kind.eq_ignore_ascii_case("webgl")
        && !kind.eq_ignore_ascii_case("webgl2")
        && !kind.eq_ignore_ascii_case("experimental-webgl")
    {
        rv.set(nullv(scope));
        return;
    }
    // One context per canvas per kind.
    let key = "__ctxWebgl";
    if let Some(existing) = args.this().get(scope, sv(scope, key)) {
        if existing.is_object() {
            rv.set(existing);
            return;
        }
    }
    let ctx = v8::Object::new(scope);
    set_prop(scope, ctx, "VERSION", v8::Number::new(scope, 0x1F02 as f64).into());
    set_prop(scope, ctx, "SHADING_LANGUAGE_VERSION", v8::Number::new(scope, 0x8B8C as f64).into());
    set_prop(scope, ctx, "VENDOR", v8::Number::new(scope, 0x1F00 as f64).into());
    set_prop(scope, ctx, "RENDERER", v8::Number::new(scope, 0x1F01 as f64).into());
    if let Some(f) = v8::FunctionTemplate::builder(cb_webgl_get_parameter)
        .data(args.data())
        .build(scope)
        .get_function(scope)
    {
        let _ = ctx.set(scope, sv(scope, "getParameter"), f.into());
    }
    if let Some(f) = v8::FunctionTemplate::builder(cb_webgl_get_extension)
        .data(args.data())
        .build(scope)
        .get_function(scope)
    {
        let _ = ctx.set(scope, sv(scope, "getExtension"), f.into());
    }
    if let Some(f) = v8::FunctionTemplate::builder(cb_webgl_get_supported_extensions)
        .data(args.data())
        .build(scope)
        .get_function(scope)
    {
        let _ = ctx.set(scope, sv(scope, "getSupportedExtensions"), f.into());
    }
    if let Some(f) = v8::FunctionTemplate::builder(cb_webgl_is_context_lost)
        .data(args.data())
        .build(scope)
        .get_function(scope)
    {
        let _ = ctx.set(scope, sv(scope, "isContextLost"), f.into());
    }
    let _ = args.this().set(scope, sv(scope, key), ctx.into());
    rv.set(ctx.into());
}

fn cb_webgl_get_parameter<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    // GLenum is arg 0. Return plausible values for the common fingerprint
    // queries (keyed by the real WebGL enums a probe passes); null for
    // everything else.
    let pname = args.get(0).to_number(scope).map(|n| n.value() as i64).unwrap_or(-1);
    match pname {
        0x1F00 => rv.set(js_string(scope, "Google Inc.")),        // VENDOR
        0x1F01 => rv.set(js_string(scope, "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)), SwiftShader driver)")), // RENDERER
        0x1F02 => rv.set(js_string(scope, "WebGL 2.0 (OpenGL ES 3.0 Chromium)")), // VERSION
        0x8B8C => rv.set(js_string(scope, "WebGL GLSL ES 3.00 (OpenGL ES GLSL ES 3.0 Chromium)")), // SHADING_LANGUAGE_VERSION
        0x0D33 => rv.set(v8::Number::new(scope, 8192.0).into()),  // MAX_TEXTURE_SIZE (SwiftShader-ANGLE typical)
        0x851C => rv.set(v8::Number::new(scope, 8192.0).into()),  // MAX_CUBE_MAP_TEXTURE_SIZE
        0x8869 => rv.set(v8::Number::new(scope, 16.0).into()),    // MAX_VERTEX_ATTRIBS
        0x8FC4 => rv.set(v8::Number::new(scope, 30.0).into()),    // MAX_VARYING_VECTORS (WebGL2)
        0x8DFD => rv.set(v8::Number::new(scope, 224.0).into()),   // MAX_FRAGMENT_UNIFORM_VECTORS
        0x8DFB => rv.set(v8::Number::new(scope, 256.0).into()),   // MAX_VERTEX_UNIFORM_VECTORS
        0x8CA6 => rv.set(nullv(scope)),                           // FRAMEBUFFER_BINDING (default FBO)
        _ => rv.set(nullv(scope)),
    }
}

fn cb_webgl_get_extension<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    // No optional extensions — a minimal but honest answer. Real sites
    // probe for WEBGL_debug_renderer_info to read UNMASKED_VENDOR/RENDERER;
    // returning null keeps that path inert (the getParameter defaults above
    // are already the masked values).
    rv.set(nullv(scope));
}

fn cb_webgl_get_supported_extensions<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    rv.set(v8::Array::new(scope, 0).into());
}

/// WebGL context-lost probe: false (context is never lost on this tier).
fn cb_webgl_is_context_lost<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    rv.set(v8::Boolean::new(scope, false).into());
}

fn cb_resolve<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let v = args.get(0);
    let payload = match v8::json::stringify(scope, v) {
        Some(s) => s.to_rust_string_lossy(scope),
        None => "null".to_string(),
    };
    let st = unsafe { state_of(&args) };
    st.resolved = Some(payload);
    rv.set(v8::undefined(scope).into());
}

fn cb_reject<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let v = args.get(0);
    let reason = thrown_message_text(scope, v);
    let st = unsafe { state_of(&args) };
    st.rejected = Some(reason);
    rv.set(v8::undefined(scope).into());
}

/// Render a thrown/rejected value as the message text the wire reports —
/// shared by the promise-rejection path (`cb_reject`) and the sync-throw
/// path (`cb_throw`, fed by the eval wrapper's catch) so the same value
/// reads identically however it escapes. Error-like values stringify to {}
/// (message/stack are non-enumerable), so prefer a string `message`
/// property before falling back.
pub fn thrown_message_text<'s, 'i>(scope: &mut PinScope<'s, 'i>, v: Local<'s, Value>) -> String {
    if v.is_object() {
        let obj = v.cast::<Object>();
        let msg = obj
            .get(scope, sv(scope, "message"))
            .filter(|m| m.is_string());
        match msg {
            Some(m) => m
                .to_string(scope)
                .map(|s| s.to_rust_string_lossy(scope))
                .unwrap_or_else(|| "<unprintable rejection>".into()),
            None => match v8::json::stringify(scope, v) {
                Some(s) => s.to_rust_string_lossy(scope),
                None => "<undefined rejection>".into(),
            },
        }
    } else {
        v.to_string(scope)
            .map(|s| s.to_rust_string_lossy(scope))
            .unwrap_or_else(|| "<unprintable rejection>".into())
    }
}

/// `__seThrow`: the eval wrapper's catch calls this with the intercepted
/// exception, so a sync throw surfaces as `Error::Threw` carrying the same
/// rendered message a promise rejection would (firing 23 — previously the
/// wire reported "<v8 gave no message>" for sync throws; a Rust-side
/// TryCatch can't wrap `Script::run` because run takes `&PinScope`
/// concretely and the try-catch would exclusively borrow the scope).
fn cb_throw<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let v = args.get(0);
    let msg = thrown_message_text(scope, v);
    let st = unsafe { state_of(&args) };
    st.thrown = Some(msg);
    rv.set(v8::undefined(scope).into());
}

// ── template construction (pre-context scope) ────────────────────────────────

fn s_pre<'s, 'i>(scope: &PinScope<'s, 'i, ()>, v: &str) -> Local<'s, Value> {
    v8::String::new(scope, v).expect("string alloc").into()
}

fn key_pre<'s, 'i>(scope: &PinScope<'s, 'i, ()>, name: &str) -> Local<'s, Name> {
    v8::String::new(scope, name).expect("string alloc").into()
}

fn ft_pre<'s, 'i>(
    scope: &PinScope<'s, 'i, ()>,
    ext: Local<'s, Value>,
    cb: impl v8::MapFnTo<v8::FunctionCallback>,
) -> Local<'s, FunctionTemplate> {
    FunctionTemplate::builder(cb).data(ext).build(scope)
}

trait TplExt {
    fn prop<'s, 'i>(
        &self,
        scope: &PinScope<'s, 'i, ()>,
        name: &str,
        value: Local<'s, v8::Data>,
    );
}

impl TplExt for ObjectTemplate {
    fn prop<'s, 'i>(
        &self,
        scope: &PinScope<'s, 'i, ()>,
        name: &str,
        value: Local<'s, v8::Data>,
    ) {
        self.set(key_pre(scope, name), value);
    }
}

/// One Web Storage area object (`localStorage` / `sessionStorage`). The
/// methods are shared; the instance's internal field 0 says which area
/// `this` is, set per instance in `finalize_context`. `length` starts as a
/// plain 0 data property the mutating callbacks keep in sync.
fn storage_template<'s, 'i>(
    scope: &PinScope<'s, 'i, ()>,
    ext: Local<'s, Value>,
) -> Local<'s, ObjectTemplate> {
    let t = ObjectTemplate::new(scope);
    t.set_internal_field_count(1);
    t.prop(scope, "getItem", ft_pre(scope, ext, cb_storage_get).into());
    t.prop(scope, "setItem", ft_pre(scope, ext, cb_storage_set).into());
    t.prop(scope, "removeItem", ft_pre(scope, ext, cb_storage_remove).into());
    t.prop(scope, "clear", ft_pre(scope, ext, cb_storage_clear).into());
    t.prop(scope, "key", ft_pre(scope, ext, cb_storage_key).into());
    t.prop(scope, "length", v8::Number::new(scope, 0.0).into());
    t
}

/// Build the element wrapper template: runtime methods that read back
/// through the internal-field index into `state.elements`.
fn build_element_template<'s, 'i>(
    scope: &PinScope<'s, 'i, ()>,
    ext: Local<'s, Value>,
) -> Local<'s, ObjectTemplate> {
    let tpl = ObjectTemplate::new(scope);
    tpl.set_internal_field_count(1);

    // classList carries its own internal field, bound per wrapper instance
    // in wrap_element to the same element index — `contains` reads `this`'s
    // field, and inside the callback `this` IS the classList object.
    let class_list = ObjectTemplate::new(scope);
    class_list.set_internal_field_count(1);
    class_list.prop(scope, "contains", ft_pre(scope, ext, cb_class_list_contains).into());
    tpl.prop(scope, "classList", class_list.into());

    tpl.prop(scope, "getAttribute", ft_pre(scope, ext, cb_get_attribute).into());
    // The attribute-mutator trio (firing 22) — setAttribute/removeAttribute
    // mutate the live tree (or the synthetic wrapper's graft-bound snapshot);
    // hasAttribute reads presence back.
    tpl.prop(scope, "setAttribute", ft_pre(scope, ext, cb_set_attribute).into());
    tpl.prop(scope, "removeAttribute", ft_pre(scope, ext, cb_remove_attribute).into());
    tpl.prop(scope, "hasAttribute", ft_pre(scope, ext, cb_has_attribute).into());
    tpl.prop(scope, "querySelector", ft_pre(scope, ext, cb_query_selector).into());
    tpl.prop(scope, "querySelectorAll", ft_pre(scope, ext, cb_query_selector_all).into());
    // Selector self-tests — provider scripts and trackers lean on both.
    tpl.prop(scope, "matches", ft_pre(scope, ext, cb_el_matches).into());
    tpl.prop(scope, "closest", ft_pre(scope, ext, cb_el_closest).into());
    // parentElement is get-only, like the DOM — an accessor, not a data prop.
    let parent_get = v8::FunctionTemplate::builder(cb_el_parent)
        .data(ext)
        .build(scope);
    tpl.set_accessor_property(
        s_pre(scope, "parentElement").cast(),
        Some(parent_get),
        None,
        v8::PropertyAttribute::NONE,
    );
    // Mutation tier — innerHTML/textContent are live accessors (the setter
    // mutates the tree and invalidates the cached parse so the next query
    // re-parses), not static data props. outerHTML is get-only.
    let inner_html_get = v8::FunctionTemplate::builder(cb_inner_html_get)
        .data(ext)
        .build(scope);
    let inner_html_set = v8::FunctionTemplate::builder(cb_inner_html_set)
        .data(ext)
        .build(scope);
    tpl.set_accessor_property(
        s_pre(scope, "innerHTML").cast(),
        Some(inner_html_get),
        Some(inner_html_set),
        v8::PropertyAttribute::NONE,
    );
    let text_content_get = v8::FunctionTemplate::builder(cb_text_content_get)
        .data(ext)
        .build(scope);
    let text_content_set = v8::FunctionTemplate::builder(cb_text_content_set)
        .data(ext)
        .build(scope);
    tpl.set_accessor_property(
        s_pre(scope, "textContent").cast(),
        Some(text_content_get),
        Some(text_content_set),
        v8::PropertyAttribute::NONE,
    );
    let outer_html_get = v8::FunctionTemplate::builder(cb_outer_html_get)
        .data(ext)
        .build(scope);
    tpl.set_accessor_property(
        s_pre(scope, "outerHTML").cast(),
        Some(outer_html_get),
        None,
        v8::PropertyAttribute::NONE,
    );
    tpl.prop(scope, "appendChild", ft_pre(scope, ext, cb_append_child).into());
    tpl.prop(scope, "remove", ft_pre(scope, ext, cb_remove).into());
    tpl.prop(scope, "click", ft_pre(scope, ext, cb_click).into());
    // Canvas fingerprint surface: every element carries toDataURL and
    // getContext so a page's `document.createElement('canvas')` (which
    // lands here as a generic element wrapper) can run the standard
    // fingerprint probe without throwing. Non-canvas elements calling
    // these get plausible stubs (the probe is canvas-specific but the
    // methods exist on every element so the surface is uniform).
    tpl.prop(scope, "toDataURL", ft_pre(scope, ext, cb_canvas_to_data_url).into());
    tpl.prop(scope, "getContext", ft_pre(scope, ext, cb_canvas_get_context).into());
    // Element geometry: the honest no-layout zero rect (see rect_object).
    tpl.prop(
        scope,
        "getBoundingClientRect",
        ft_pre(scope, ext, cb_get_bounding_client_rect).into(),
    );
    tpl.prop(
        scope,
        "getClientRects",
        ft_pre(scope, ext, cb_get_client_rects).into(),
    );
    // EventTarget surface — elements register and dispatch through the same
    // listener registry as window/document (cb_add_event_listener keys on
    // the wrapper's internal field).
    tpl.prop(
        scope,
        "addEventListener",
        ft_pre(scope, ext, cb_add_event_listener).into(),
    );
    tpl.prop(
        scope,
        "removeEventListener",
        ft_pre(scope, ext, cb_remove_event_listener).into(),
    );
    tpl.prop(
        scope,
        "dispatchEvent",
        ft_pre(scope, ext, cb_dispatch_event).into(),
    );
    // Shadow DOM / fullscreen / pointer-lock shapes (firing 26):
    // attachShadow returns an inert open/closed root (open also fills
    // el.shadowRoot); fullscreen and pointer lock resolve as no-ops.
    tpl.prop(
        scope,
        "attachShadow",
        ft_pre(scope, ext, cb_attach_shadow).into(),
    );
    tpl.prop(
        scope,
        "requestFullscreen",
        ft_pre(scope, ext, cb_promise_resolve_undefined).into(),
    );
    tpl.prop(
        scope,
        "requestPointerLock",
        ft_pre(scope, ext, cb_noop).into(),
    );
    tpl
}

// ---------------------------------------------------------------------
// M4 remainder shape tier (firing 28). Survey-first: scripts/f28_probe.py
// showed caches / Credential / Clipboard / WakeLock / Bluetooth / USB /
// Serial / HID / Share and the bonus detect surface (getInstalledRelated-
// Apps / getGamepads / presentation / xr / locks / scheduling / gpu /
// mediaCapabilities) ALL undefined. The installs answer like a fresh-
// profile desktop Chrome with no devices, no permission, and no user
// activation — enumerations resolve empty, request* rejects NotFoundError
// (no device in range), share rejects NotAllowedError (no activation),
// read-side clipboard denies; nothing fakes hardware or a permission.
// The one semi-real piece is caches: a pure-JS per-eval-context
// CacheStorage/Cache round trip installed by the finalize trampoline —
// open/put/add/match round-trip within one eval; cross-eval persistence
// is a documented floor (no Page plumbing this tier). Rejection reasons
// are dom_exception_obj shapes (message/name/code) so err.name reads
// honestly.
// ---------------------------------------------------------------------

/// Async rejection with a DOMException-shaped reason; the FunctionTemplate
/// data slot carries "Name|message" so one callback serves every surface.
fn cb_promise_reject_domexception<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let spec = args.data().to_rust_string_lossy(scope);
    let (name, msg) = spec.split_once('|').unwrap_or(("Error", &spec));
    let reason = dom_exception_obj(scope, msg, name);
    let _ = resolver.reject(scope, reason.into());
    rv.set(resolver.get_promise(scope).into());
}

/// Resolves false — navigator.bluetooth.getAvailability() on a host with
/// no Bluetooth adapter (VM/server profile).
fn cb_promise_resolve_false<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let _ = resolver.resolve(scope, v8::Boolean::new(scope, false).into());
    rv.set(resolver.get_promise(scope).into());
}

/// Resolves null — navigator.credentials.get() against an empty store
/// (the common fresh-profile answer) and navigator.gpu.requestAdapter()
/// on a no-GPU host.
fn cb_promise_resolve_null<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let _ = resolver.resolve(scope, v8::null(scope).into());
    rv.set(resolver.get_promise(scope).into());
}

/// Resolves [] — getDevices/getPorts/getInstalledRelatedApps on a host
/// with nothing attached.
fn cb_promise_resolve_empty_array<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let _ = resolver.resolve(scope, v8::Array::new(scope, 0).into());
    rv.set(resolver.get_promise(scope).into());
}

/// `navigator.wakeLock.request(type)` — the screen stays awake trivially
/// (there is no display); the sentinel is real shape with a working
/// release() that flips `released` and would fire 'release' listeners.
fn cb_wakelock_request<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let ty = arg_string(scope, &args, 0).unwrap_or_else(|| "screen".to_string());
    let sentinel = v8::Object::new(scope);
    set_prop(scope, sentinel, "type", sv(scope, &ty));
    set_prop(
        scope,
        sentinel,
        "released",
        v8::Boolean::new(scope, false).into(),
    );
    set_prop(scope, sentinel, "onrelease", v8::null(scope).into());
    let release = v8::Function::new(scope, cb_wakelock_release).expect("fn alloc");
    set_prop(scope, sentinel, "release", release.into());
    for m in ["addEventListener", "removeEventListener", "dispatchEvent"] {
        let f = v8::Function::new(scope, cb_noop).expect("noop fn");
        set_prop(scope, sentinel, m, f.into());
    }
    let _ = resolver.resolve(scope, sentinel.into());
    rv.set(resolver.get_promise(scope).into());
}

/// `sentinel.release()` — flips `released` on the sentinel (the 'release'
/// event delivery is an EventTarget-registry floor, same as the other
/// shape objects this tier).
fn cb_wakelock_release<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    _rv: ReturnValue<'s, Value>,
) {
    let this = _args_this(scope, &_args);
    if let Some(obj) = this {
        set_prop(scope, obj, "released", v8::Boolean::new(scope, true).into());
    }
}

/// Page-side `this` (Local<Object>) for a method callback.
fn _args_this<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: &FunctionCallbackArguments<'s>,
) -> Option<Local<'s, Object>> {
    args.this().to_object(scope)
}

/// `navigator.share(data)` — with shareable fields present the call needs
/// transient user activation, which an engine eval never has: reject
/// NotAllowedError, like Chrome's no-gesture path. With NO known fields
/// (or a non-object) Chrome rejects TypeError — same split here.
fn cb_share<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let data = args.get(0);
    let has_field = data.to_object(scope).map(|o| {
        ["title", "text", "url"]
            .iter()
            .any(|k| o.has(scope, sv(scope, k)) == Some(true))
    });
    let reason = match has_field {
        Some(true) => dom_exception_obj(
            scope,
            "Share requires transient user activation",
            "NotAllowedError",
        ),
        _ => dom_exception_obj(
            scope,
            "Failed to execute 'share' on 'Navigator': No known share data fields supplied",
            "TypeError",
        ),
    };
    let _ = resolver.reject(scope, reason.into());
    rv.set(resolver.get_promise(scope).into());
}

/// `navigator.canShare(data)` — true iff at least one of title/text/url is
/// present and the url (when present) is an absolute http(s) URL. The URL
/// check is a starts-with floor (no URL parser host-side this tier).
fn cb_can_share<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let data = args.get(0);
    let answer = data.to_object(scope).map(|o| {
        let has_known = ["title", "text", "url"]
            .iter()
            .any(|k| o.has(scope, sv(scope, k)) == Some(true));
        if !has_known {
            return false;
        }
        match o.get(scope, sv(scope, "url")) {
            Some(u) if u.is_string() => {
                let u = u.to_rust_string_lossy(scope);
                u.starts_with("https://") || u.starts_with("http://")
            }
            _ => true,
        }
    });
    rv.set(v8::Boolean::new(scope, answer.unwrap_or(false)).into());
}

/// `navigator.locks.request(name, [opts], cb)` — the lock is granted
/// synchronously and the callback runs inline; the promise resolves with
/// the callback's return. Mutual exclusion across concurrent requests is
/// a documented floor (single-eval contexts don't interleave here).
fn cb_locks_request<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let name = arg_string(scope, &args, 0).unwrap_or_default();
    let (opts, cb) = if args.get(2).is_function() {
        (args.get(1), args.get(2))
    } else {
        (args.get(1), args.get(1))
    };
    let mode = opts
        .to_object(scope)
        .and_then(|o| o.get(scope, sv(scope, "mode")))
        .filter(|m| m.is_string())
        .map(|m| m.to_rust_string_lossy(scope))
        .unwrap_or_else(|| "exclusive".to_string());
    let lock = v8::Object::new(scope);
    set_prop(scope, lock, "name", sv(scope, &name));
    set_prop(scope, lock, "mode", sv(scope, &mode));
    set_prop(scope, lock, "clientId", sv(scope, ""));
    let ret = if cb.is_function() {
        cb.cast::<v8::Function>()
            .call(scope, v8::undefined(scope).into(), &[lock.into()])
            .unwrap_or_else(|| v8::undefined(scope).into())
    } else {
        v8::undefined(scope).into()
    };
    let _ = resolver.resolve(scope, ret);
    rv.set(resolver.get_promise(scope).into());
}

/// `navigator.locks.query()` — no held or pending locks (the sync-grant
/// floor means nothing stays pending).
fn cb_locks_query<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let out = v8::Object::new(scope);
    set_prop(scope, out, "held", v8::Array::new(scope, 0).into());
    set_prop(scope, out, "pending", v8::Array::new(scope, 0).into());
    let _ = resolver.resolve(scope, out.into());
    rv.set(resolver.get_promise(scope).into());
}

/// `navigator.mediaCapabilities.decodingInfo/encodingInfo(desc)` — a
/// curated codec table in the CSS.supports spirit: the codecs desktop
/// Chrome decodes get {supported, smooth} true / powerEfficient false (no
/// hardware codecs on this profile); anything unknown is all-false, never
/// a faked success.
fn cb_media_capabilities_info<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let mut supported = false;
    if let Some(desc) = args.get(0).to_object(scope) {
        let mut cts = Vec::new();
        for media in ["video", "audio"] {
            if let Some(m) = desc.get(scope, sv(scope, media)).and_then(|m| m.to_object(scope)) {
                if let Some(ct) = m.get(scope, sv(scope, "contentType")) {
                    cts.push(ct.to_rust_string_lossy(scope).to_lowercase());
                }
            }
        }
        let known = [
            "vp8", "vp09", "vp9", "av01", "av1", "avc1", "avc3", "h264",
            "opus", "vorbis", "mp4a", "aac", "flac", "pcm",
        ];
        supported = cts.iter().any(|ct| known.iter().any(|k| ct.contains(k)));
    }
    let out = v8::Object::new(scope);
    for (k, v) in [
        ("supported", supported),
        ("smooth", supported),
        ("powerEfficient", false),
    ] {
        set_prop(scope, out, k, v8::Boolean::new(scope, v).into());
    }
    let _ = resolver.resolve(scope, out.into());
    rv.set(resolver.get_promise(scope).into());
}

/// `navigator.xr.isSessionSupported(mode)` — no XR device: false for every
/// mode, like Chrome's no-headset answer.
fn cb_xr_supported<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Some(resolver) = v8::PromiseResolver::new(scope) else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let _ = resolver.resolve(scope, v8::Boolean::new(scope, false).into());
    rv.set(resolver.get_promise(scope).into());
}

/// `navigator.gpu.getPreferredCanvasFormat()` — desktop Chrome answers
/// "bgra8unorm" (little-endian Windows/D3D swap-chain format).
fn cb_gpu_canvas_format<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    rv.set(sv(scope, "bgra8unorm"));
}

/// Raw `scheduler.postTask(cb, opts)` trampoline half — the JS wrapper
/// (finalize) threads [resolve, reject]; the task runs on a 0ms timer so
/// the eval pump delivers it, resolving with the task's return (priorities
/// are a documented floor: FIFO at 0ms).
fn cb_post_task_raw<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let task = args.get(0);
    let pair = args.get(1);
    let resolver = v8::PromiseResolver::new(scope).expect("promise resolver");
    let Some(factory_src) = v8::String::new(scope, "(p,c)=>()=>{try{p[0](c());}catch(e){p[1](e);}}")
    else {
        rv.set(v8::undefined(scope).into());
        return;
    };
    let closure = v8::Script::compile(scope, factory_src, None)
        .and_then(|s| s.run(scope))
        .and_then(|f| f.cast::<Function>().call(scope, v8::undefined(scope).into(), &[pair, task]));
    match closure {
        Some(c) => {
            let st = unsafe { state_of(&args) };
            let id = st.next_timer_id;
            st.next_timer_id += 1;
            st.timers.push(Timer {
                id,
                deadline: Instant::now(),
                interval_ms: None,
                raf: false,
                callback: v8::Global::new(scope, c.cast::<Function>()),
            });
            rv.set(resolver.get_promise(scope).into());
        }
        None => rv.set(v8::undefined(scope).into()),
    }
}

/// Build the global template for one eval. `ext` is the State external every
/// callback's `.data()` points at. Runs before the context exists, so the
/// scope is the context-less variant.
pub fn build_globals<'s, 'i>(
    scope: &PinScope<'s, 'i, ()>,
    state_ptr: *mut State,
    ext: Local<'s, Value>,
) -> Local<'s, ObjectTemplate> {
    let globals = ObjectTemplate::new(scope);

    // navigator — must answer even at about:blank, because
    // SidecarClient.user_agent() evals it before any navigation. The surface
    // mirrors a real desktop Chrome 145 on Windows; every value is pinned
    // by the fingerprint-consistency tests so a drift between what the page
    // reads and what the wire presents can't creep in silently.
    //
    // `webdriver` is deliberately NOT set: a real, non-automated Chrome has
    // no such property (`typeof navigator.webdriver === 'undefined'`), and
    // a boolean false is itself an automation tell. patchright hides the
    // flag the same way.
    let navigator = ObjectTemplate::new(scope);
    navigator.prop(scope, "userAgent", s_pre(scope, USER_AGENT).into());
    navigator.prop(
        scope,
        "appVersion",
        s_pre(scope, "5.0 (Windows NT 10.0; Win64; x64)").into(),
    );
    navigator.prop(scope, "appName", s_pre(scope, "Netscape").into());
    navigator.prop(scope, "product", s_pre(scope, "Gecko").into());
    navigator.prop(scope, "productSub", s_pre(scope, "20030107").into());
    navigator.prop(scope, "platform", s_pre(scope, "Win32").into());
    navigator.prop(scope, "vendor", s_pre(scope, "Google Inc.").into());
    navigator.prop(scope, "vendorSub", s_pre(scope, "").into());
    navigator.prop(scope, "language", s_pre(scope, "en-US").into());
    // `languages` is an Array, which can only be created once a context
    // exists — finalize_context fills it.
    navigator.prop(scope, "hardwareConcurrency", v8::Number::new(scope, 8.0).into());
    navigator.prop(scope, "deviceMemory", v8::Number::new(scope, 8.0).into());
    navigator.prop(scope, "maxTouchPoints", v8::Number::new(scope, 0.0).into());
    navigator.prop(scope, "onLine", v8::Boolean::new(scope, true).into());
    navigator.prop(scope, "cookieEnabled", v8::Boolean::new(scope, true).into());
    navigator.prop(scope, "pdfViewerEnabled", v8::Boolean::new(scope, true).into());
    // connection (NetworkInformation) — the values Chrome reports on a
    // desktop ethernet/wifi link; probes read effectiveType/rtt/downlink.
    let conn = ObjectTemplate::new(scope);
    conn.prop(scope, "effectiveType", s_pre(scope, "4g").into());
    conn.prop(scope, "rtt", v8::Number::new(scope, 50.0).into());
    conn.prop(scope, "downlink", v8::Number::new(scope, 10.0).into());
    conn.prop(scope, "saveData", v8::Boolean::new(scope, false).into());
    navigator.prop(scope, "connection", conn.into());
    navigator.prop(scope, "javaEnabled", ft_pre(scope, ext, cb_java_enabled).into());
    // sendBeacon — accepted, payload dropped (the analytics contract is
    // only that the call returns true, not that data arrives anywhere).
    navigator.prop(scope, "sendBeacon", ft_pre(scope, ext, cb_send_beacon).into());
    // Permissions API (M4) — fingerprint scripts consistency-check
    // `notifications` against Notification.permission; the state table
    // lives in cb_permissions_query.
    let perms = ObjectTemplate::new(scope);
    perms.prop(
        scope,
        "query",
        ft_pre(scope, ext, cb_permissions_query).into(),
    );
    navigator.prop(scope, "permissions", perms.into());
    // mediaDevices — enumerateDevices answers the fresh-profile trio with
    // EMPTY labels (no getUserMedia permission, exactly like Chrome);
    // getUserMedia/getDisplayMedia reject without permission.
    let md = ObjectTemplate::new(scope);
    md.prop(
        scope,
        "enumerateDevices",
        ft_pre(scope, ext, cb_enum_devices).into(),
    );
    md.prop(
        scope,
        "getUserMedia",
        ft_pre(scope, ext, cb_media_denied).into(),
    );
    md.prop(
        scope,
        "getDisplayMedia",
        ft_pre(scope, ext, cb_media_denied).into(),
    );
    for m in ["addEventListener", "removeEventListener", "dispatchEvent"] {
        md.prop(scope, m, ft_pre(scope, ext, cb_noop).into());
    }
    md.prop(scope, "ondevicechange", v8::null(scope).into());
    navigator.prop(scope, "mediaDevices", md.into());
    // Geolocation — no location source and no prompt: the error callback
    // fires asynchronously with PERMISSION_DENIED, like a fresh profile.
    let geo = ObjectTemplate::new(scope);
    geo.prop(
        scope,
        "getCurrentPosition",
        ft_pre(scope, ext, cb_geo_get_current).into(),
    );
    geo.prop(
        scope,
        "watchPosition",
        ft_pre(scope, ext, cb_geo_watch).into(),
    );
    geo.prop(scope, "clearWatch", ft_pre(scope, ext, cb_noop).into());
    navigator.prop(scope, "geolocation", geo.into());
    // Storage Manager — fresh profile: a plausible quota, zero usage, no
    // persistent-storage grant.
    let storage_mgr = ObjectTemplate::new(scope);
    storage_mgr.prop(
        scope,
        "estimate",
        ft_pre(scope, ext, cb_storage_estimate).into(),
    );
    storage_mgr.prop(scope, "persist", ft_pre(scope, ext, cb_storage_bool).into());
    storage_mgr.prop(
        scope,
        "persisted",
        ft_pre(scope, ext, cb_storage_bool).into(),
    );
    navigator.prop(scope, "storage", storage_mgr.into());
    // vibrate — present on desktop Chrome, ineffective: false.
    navigator.prop(scope, "vibrate", ft_pre(scope, ext, cb_returns_false).into());
    // doNotTrack — unset on a fresh profile.
    navigator.prop(scope, "doNotTrack", v8::null(scope).into());
    // Battery Status — desktop Chrome: charging, full, never discharging.
    navigator.prop(scope, "getBattery", ft_pre(scope, ext, cb_get_battery).into());
    // userAgentData (Client Hints, low-entropy half) — modern fingerprint
    // scripts read brands/mobile/platform; getHighEntropyValues answers the
    // high-entropy half from the SAME se-net constants the Sec-CH-UA wire
    // headers are built from.
    let uad = ObjectTemplate::new(scope);
    uad.prop(scope, "mobile", v8::Boolean::new(scope, false).into());
    uad.prop(scope, "platform", s_pre(scope, se_net::UA_PLATFORM).into());
    uad.prop(
        scope,
        "getHighEntropyValues",
        ft_pre(scope, ext, cb_uad_high_entropy).into(),
    );
    navigator.prop(scope, "userAgentData", uad.into());
    // serviceWorker — the register/ready paths resolve with a shaped-but-
    // empty registration; `ready` is an accessor so its promise is built
    // with a live context at read time. `controller` stays null (honest:
    // no worker controls this page, as in a fresh tab).
    let sw = ObjectTemplate::new(scope);
    sw.prop(scope, "register", ft_pre(scope, ext, cb_sw_register).into());
    sw.prop(
        scope,
        "getRegistration",
        ft_pre(scope, ext, cb_sw_get_registration).into(),
    );
    sw.prop(
        scope,
        "getRegistrations",
        ft_pre(scope, ext, cb_sw_get_registrations).into(),
    );
    sw.prop(scope, "controller", v8::null(scope).into());
    sw.prop(scope, "oncontrollerchange", v8::null(scope).into());
    for m in ["addEventListener", "removeEventListener", "dispatchEvent"] {
        sw.prop(scope, m, ft_pre(scope, ext, cb_noop).into());
    }
    let sw_ready_get = v8::FunctionTemplate::builder(cb_sw_ready)
        .data(ext)
        .build(scope);
    sw.set_accessor_property(
        s_pre(scope, "ready").cast(),
        Some(sw_ready_get),
        None,
        v8::PropertyAttribute::NONE,
    );
    navigator.prop(scope, "serviceWorker", sw.into());
    // M4 remainder (firing 28) — device/permission API shapes. Answers
    // match a fresh-profile desktop Chrome with no devices, no
    // permission, and no user activation; see the callback block header.
    // Credential Management — no credential store: get resolves null (an
    // empty store), store/create need user activation (NotAllowedError),
    // preventSilentAccess resolves.
    let creds = ObjectTemplate::new(scope);
    creds.prop(
        scope,
        "get",
        FunctionTemplate::builder(cb_promise_resolve_null)
            .data(ext)
            .build(scope)
            .into(),
    );
    for m in ["store", "create"] {
        creds.prop(
            scope,
            m,
            FunctionTemplate::builder(cb_promise_reject_domexception)
                .data(s_pre(scope, "NotAllowedError|User activation is required"))
                .build(scope)
                .into(),
        );
    }
    creds.prop(
        scope,
        "preventSilentAccess",
        ft_pre(scope, ext, cb_promise_resolve_undefined).into(),
    );
    navigator.prop(scope, "credentials", creds.into());
    // Clipboard — writes are accepted (like sendBeacon: the call's
    // contract is the resolution, not delivery); reads reject without the
    // clipboard-read permission.
    let clip = ObjectTemplate::new(scope);
    for m in ["read", "readText"] {
        clip.prop(
            scope,
            m,
            FunctionTemplate::builder(cb_promise_reject_domexception)
                .data(s_pre(
                    scope,
                    "NotAllowedError|Failed to execute on 'Clipboard': The user has denied the 'clipboard-read' permission",
                ))
                .build(scope)
                .into(),
        );
    }
    clip.prop(
        scope,
        "write",
        ft_pre(scope, ext, cb_promise_resolve_undefined).into(),
    );
    clip.prop(
        scope,
        "writeText",
        ft_pre(scope, ext, cb_promise_resolve_undefined).into(),
    );
    navigator.prop(scope, "clipboard", clip.into());
    // WakeLock — the screen stays awake trivially; sentinel shape with a
    // working release().
    let wl = ObjectTemplate::new(scope);
    wl.prop(
        scope,
        "request",
        ft_pre(scope, ext, cb_wakelock_request).into(),
    );
    navigator.prop(scope, "wakeLock", wl.into());
    // Web Bluetooth — no adapter: availability false, requestDevice
    // rejects NotFoundError.
    let bt = ObjectTemplate::new(scope);
    bt.prop(
        scope,
        "requestDevice",
        FunctionTemplate::builder(cb_promise_reject_domexception)
            .data(s_pre(scope, "NotFoundError|No Bluetooth devices found"))
            .build(scope)
            .into(),
    );
    bt.prop(
        scope,
        "getAvailability",
        ft_pre(scope, ext, cb_promise_resolve_false).into(),
    );
    for m in ["addEventListener", "removeEventListener", "dispatchEvent"] {
        bt.prop(scope, m, ft_pre(scope, ext, cb_noop).into());
    }
    bt.prop(scope, "onavailabilitychanged", v8::null(scope).into());
    navigator.prop(scope, "bluetooth", bt.into());
    // WebUSB — nothing attached: getDevices [], requestDevice NotFound.
    let usb = ObjectTemplate::new(scope);
    usb.prop(
        scope,
        "getDevices",
        ft_pre(scope, ext, cb_promise_resolve_empty_array).into(),
    );
    usb.prop(
        scope,
        "requestDevice",
        FunctionTemplate::builder(cb_promise_reject_domexception)
            .data(s_pre(scope, "NotFoundError|No USB devices found"))
            .build(scope)
            .into(),
    );
    for m in ["addEventListener", "removeEventListener", "dispatchEvent"] {
        usb.prop(scope, m, ft_pre(scope, ext, cb_noop).into());
    }
    for k in ["onconnect", "ondisconnect"] {
        usb.prop(scope, k, v8::null(scope).into());
    }
    navigator.prop(scope, "usb", usb.into());
    // WebSerial — same no-device contract.
    let ser = ObjectTemplate::new(scope);
    ser.prop(
        scope,
        "getPorts",
        ft_pre(scope, ext, cb_promise_resolve_empty_array).into(),
    );
    ser.prop(
        scope,
        "requestPort",
        FunctionTemplate::builder(cb_promise_reject_domexception)
            .data(s_pre(scope, "NotFoundError|No serial ports found"))
            .build(scope)
            .into(),
    );
    for m in ["addEventListener", "removeEventListener", "dispatchEvent"] {
        ser.prop(scope, m, ft_pre(scope, ext, cb_noop).into());
    }
    for k in ["onconnect", "ondisconnect"] {
        ser.prop(scope, k, v8::null(scope).into());
    }
    navigator.prop(scope, "serial", ser.into());
    // WebHID — same no-device contract.
    let hid = ObjectTemplate::new(scope);
    hid.prop(
        scope,
        "getDevices",
        ft_pre(scope, ext, cb_promise_resolve_empty_array).into(),
    );
    hid.prop(
        scope,
        "requestDevice",
        FunctionTemplate::builder(cb_promise_reject_domexception)
            .data(s_pre(scope, "NotFoundError|No HID devices found"))
            .build(scope)
            .into(),
    );
    for m in ["addEventListener", "removeEventListener", "dispatchEvent"] {
        hid.prop(scope, m, ft_pre(scope, ext, cb_noop).into());
    }
    for k in ["onconnect", "ondisconnect"] {
        hid.prop(scope, k, v8::null(scope).into());
    }
    navigator.prop(scope, "hid", hid.into());
    // Web Share — canShare is a real shape check; share needs transient
    // activation this engine never has (NotAllowedError), and rejects
    // TypeError for data with no known fields, like Chrome.
    navigator.prop(scope, "share", ft_pre(scope, ext, cb_share).into());
    navigator.prop(scope, "canShare", ft_pre(scope, ext, cb_can_share).into());
    // getInstalledRelatedApps / getGamepads — empty enumerations.
    navigator.prop(
        scope,
        "getInstalledRelatedApps",
        ft_pre(scope, ext, cb_promise_resolve_empty_array).into(),
    );
    navigator.prop(scope, "getGamepads", ft_pre(scope, ext, cb_empty_array).into());
    // Presentation API shape — receiver null on a non-casting profile.
    let pres = ObjectTemplate::new(scope);
    pres.prop(scope, "defaultRequest", v8::null(scope).into());
    pres.prop(scope, "receiver", v8::null(scope).into());
    navigator.prop(scope, "presentation", pres.into());
    // WebXR — no device: isSessionSupported false, requestSession rejects.
    let xr = ObjectTemplate::new(scope);
    xr.prop(
        scope,
        "isSessionSupported",
        ft_pre(scope, ext, cb_xr_supported).into(),
    );
    xr.prop(
        scope,
        "requestSession",
        FunctionTemplate::builder(cb_promise_reject_domexception)
            .data(s_pre(scope, "NotSupportedError|WebXR is not supported"))
            .build(scope)
            .into(),
    );
    xr.prop(scope, "ondevicechange", v8::null(scope).into());
    for m in ["addEventListener", "removeEventListener", "dispatchEvent"] {
        xr.prop(scope, m, ft_pre(scope, ext, cb_noop).into());
    }
    navigator.prop(scope, "xr", xr.into());
    // Web Locks — sync-grant floor (see cb_locks_request).
    let locks = ObjectTemplate::new(scope);
    locks.prop(
        scope,
        "request",
        ft_pre(scope, ext, cb_locks_request).into(),
    );
    locks.prop(scope, "query", ft_pre(scope, ext, cb_locks_query).into());
    navigator.prop(scope, "locks", locks.into());
    // Scheduling — isInputPending false; scheduler.postTask installs in
    // finalize (needs the raw timer half + a JS promise wrapper).
    let sched = ObjectTemplate::new(scope);
    sched.prop(
        scope,
        "isInputPending",
        ft_pre(scope, ext, cb_returns_false).into(),
    );
    navigator.prop(scope, "scheduling", sched.into());
    // WebGPU — no adapter on this profile: requestAdapter null (the honest
    // no-device answer), the canvas format Chrome prefers.
    let gpu = ObjectTemplate::new(scope);
    gpu.prop(
        scope,
        "requestAdapter",
        ft_pre(scope, ext, cb_promise_resolve_null).into(),
    );
    gpu.prop(
        scope,
        "getPreferredCanvasFormat",
        ft_pre(scope, ext, cb_gpu_canvas_format).into(),
    );
    gpu.prop(scope, "onuncapturederror", v8::null(scope).into());
    for m in ["addEventListener", "removeEventListener", "dispatchEvent"] {
        gpu.prop(scope, m, ft_pre(scope, ext, cb_noop).into());
    }
    navigator.prop(scope, "gpu", gpu.into());
    // Media Capabilities — curated codec table (CSS.supports spirit).
    let mc = ObjectTemplate::new(scope);
    mc.prop(
        scope,
        "decodingInfo",
        ft_pre(scope, ext, cb_media_capabilities_info).into(),
    );
    mc.prop(
        scope,
        "encodingInfo",
        ft_pre(scope, ext, cb_media_capabilities_info).into(),
    );
    navigator.prop(scope, "mediaCapabilities", mc.into());
    globals.prop(scope, "navigator", navigator.into());

    // screen — a missing `screen` is a headless tell; desktop 1920x1080
    // matches the Windows UA above.
    let screen = ObjectTemplate::new(scope);
    for (k, v) in [
        ("width", 1920.0),
        ("height", 1080.0),
        ("availWidth", 1920.0),
        ("availHeight", 1040.0),
        ("colorDepth", 24.0),
        ("pixelDepth", 24.0),
    ] {
        screen.prop(scope, k, v8::Number::new(scope, v).into());
    }
    globals.prop(scope, "screen", screen.into());

    // Viewport geometry — plausible desktop window (maximized minus taskbar
    // for the inner pair), consistent with the screen size above.
    globals.prop(scope, "innerWidth", v8::Number::new(scope, 1920.0).into());
    globals.prop(scope, "innerHeight", v8::Number::new(scope, 937.0).into());
    globals.prop(scope, "outerWidth", v8::Number::new(scope, 1920.0).into());
    globals.prop(scope, "outerHeight", v8::Number::new(scope, 1080.0).into());
    // Scroll position: real bookkeeping (scrollBy/scrollTo advance it,
    // clamped at zero) even though this tier has no viewport to move.
    globals.prop(scope, "scrollX", v8::Number::new(scope, 0.0).into());
    globals.prop(scope, "scrollY", v8::Number::new(scope, 0.0).into());
    globals.prop(scope, "pageXOffset", v8::Number::new(scope, 0.0).into());
    globals.prop(scope, "pageYOffset", v8::Number::new(scope, 0.0).into());
    globals.prop(scope, "scrollBy", ft_pre(scope, ext, cb_window_scroll_by).into());
    globals.prop(scope, "scrollTo", ft_pre(scope, ext, cb_window_scroll_to).into());
    // getComputedStyle — initial values + the UA display table (see the cb).
    globals.prop(
        scope,
        "getComputedStyle",
        ft_pre(scope, ext, cb_get_computed_style).into(),
    );

    // window.chrome — presence is the tell; headless shells and automation
    // frameworks that omit it fail this probe instantly.
    let chrome = ObjectTemplate::new(scope);
    chrome.prop(scope, "app", ObjectTemplate::new(scope).into());
    chrome.prop(scope, "runtime", ObjectTemplate::new(scope).into());
    globals.prop(scope, "chrome", chrome.into());

    // speechSynthesis (M4) — present with an empty voice list; the speak
    // pipeline is shape-only (this engine has no audio stack).
    let ss = ObjectTemplate::new(scope);
    ss.prop(scope, "getVoices", ft_pre(scope, ext, cb_get_voices).into());
    for m in ["speak", "cancel", "pause", "resume"] {
        ss.prop(scope, m, ft_pre(scope, ext, cb_noop).into());
    }
    for k in ["pending", "speaking", "paused"] {
        ss.prop(scope, k, v8::Boolean::new(scope, false).into());
    }
    ss.prop(scope, "onvoiceschanged", v8::null(scope).into());
    globals.prop(scope, "speechSynthesis", ss.into());

    // visualViewport — the layout viewport is real geometry even with no
    // layout: it tracks the inner* pair.
    let vv = ObjectTemplate::new(scope);
    for (k, v) in [
        ("width", 1920.0),
        ("height", 937.0),
        ("scale", 1.0),
        ("offsetLeft", 0.0),
        ("offsetTop", 0.0),
        ("pageLeft", 0.0),
        ("pageTop", 0.0),
    ] {
        vv.prop(scope, k, v8::Number::new(scope, v).into());
    }
    for m in ["addEventListener", "removeEventListener", "dispatchEvent"] {
        vv.prop(scope, m, ft_pre(scope, ext, cb_noop).into());
    }
    vv.prop(scope, "onresize", v8::null(scope).into());
    vv.prop(scope, "onscroll", v8::null(scope).into());
    globals.prop(scope, "visualViewport", vv.into());

    // window.close — a real, native, no-op: page JS cannot close the
    // engine's tab, but `typeof close === 'function'` must hold.
    globals.prop(scope, "close", ft_pre(scope, ext, cb_noop).into());

    // ── M4 utility/crypto tier (firing 26) ─────────────────────────────
    // WebCrypto — getRandomValues/randomUUID are OS-randomness honest;
    // subtle.digest computes a real SHA-256 (sha256.rs); other algorithms
    // reject rather than fake a digest.
    let crypto = ObjectTemplate::new(scope);
    crypto.prop(
        scope,
        "getRandomValues",
        ft_pre(scope, ext, cb_crypto_get_random_values).into(),
    );
    crypto.prop(
        scope,
        "randomUUID",
        ft_pre(scope, ext, cb_crypto_random_uuid).into(),
    );
    let subtle = ObjectTemplate::new(scope);
    subtle.prop(
        scope,
        "digest",
        ft_pre(scope, ext, cb_subtle_digest).into(),
    );
    crypto.prop(scope, "subtle", subtle.into());
    globals.prop(scope, "crypto", crypto.into());
    // Text codecs — real UTF-8 both directions. TextDecoder's fatal flag
    // throws via the JS wrapper finalize installs over the raw callback.
    let text_encoder = FunctionTemplate::builder(cb_text_encoder_ctor)
        .data(ext)
        .build(scope);
    globals.prop(scope, "TextEncoder", text_encoder.into());
    let text_decoder = FunctionTemplate::builder(cb_text_decoder_ctor)
        .data(ext)
        .build(scope);
    globals.prop(scope, "TextDecoder", text_decoder.into());
    // CSS — supports() consults the curated table; paintWorklet is a stub.
    let css = ObjectTemplate::new(scope);
    css.prop(
        scope,
        "supports",
        ft_pre(scope, ext, cb_css_supports).into(),
    );
    let paint_worklet = ObjectTemplate::new(scope);
    paint_worklet.prop(scope, "addModule", ft_pre(scope, ext, cb_noop).into());
    css.prop(scope, "paintWorklet", paint_worklet.into());
    globals.prop(scope, "CSS", css.into());
    // AbortController — sync abort-event delivery; fetch honors a
    // pre-aborted signal via the trampoline's pre-check.
    globals.prop(
        scope,
        "AbortController",
        FunctionTemplate::builder(cb_abort_controller_ctor)
            .data(ext)
            .build(scope)
            .into(),
    );
    globals.prop(
        scope,
        "DOMException",
        FunctionTemplate::builder(cb_dom_exception_ctor)
            .data(ext)
            .build(scope)
            .into(),
    );
    // structuredClone — the JS wrapper (finalize) unwraps the host
    // callback's {__seOk, value|err} envelope and throws DataCloneError.
    globals.prop(
        scope,
        "structuredClone",
        ft_pre(scope, ext, cb_structured_clone).into(),
    );
    // reportError — routed to the console-report floor; must not throw.
    globals.prop(scope, "reportError", ft_pre(scope, ext, cb_noop).into());
    // indexedDB — no backend: open/deleteDatabase return a request whose
    // error event fires asynchronously; cmp is real.
    let idb = ObjectTemplate::new(scope);
    idb.prop(scope, "open", ft_pre(scope, ext, cb_idb_open).into());
    idb.prop(
        scope,
        "deleteDatabase",
        ft_pre(scope, ext, cb_idb_delete).into(),
    );
    idb.prop(scope, "cmp", ft_pre(scope, ext, cb_idb_cmp).into());
    idb.prop(scope, "databases", ft_pre(scope, ext, cb_noop).into());
    globals.prop(scope, "indexedDB", idb.into());
    // customElements — registry recorded; upgrade is a documented noop.
    let ce = ObjectTemplate::new(scope);
    ce.prop(
        scope,
        "define",
        ft_pre(scope, ext, cb_custom_elements_define).into(),
    );
    ce.prop(scope, "get", ft_pre(scope, ext, cb_custom_elements_get).into());
    ce.prop(
        scope,
        "whenDefined",
        ft_pre(scope, ext, cb_custom_elements_when_defined).into(),
    );
    ce.prop(scope, "upgrade", ft_pre(scope, ext, cb_noop).into());
    globals.prop(scope, "customElements", ce.into());
    // HTMLElement — the global base class custom elements extend. A plain
    // host ctor: instantiation is a documented noop floor (no custom
    // element reactions this tier), but `class X extends HTMLElement` must
    // parse and define must accept the class.
    globals.prop(
        scope,
        "HTMLElement",
        FunctionTemplate::builder(cb_noop).data(ext).build(scope).into(),
    );

    // ── M4 audio fingerprint tier (firing 27) ─────────────────────────
    // Real DSP lives in audio.rs; the graph is captured via hidden props
    // and rendered at OfflineAudioContext.startRendering(). webkit*
    // vendor aliases are probed first by feature-detect scripts.
    globals.prop(
        scope,
        "AudioContext",
        FunctionTemplate::builder(cb_audio_context_ctor)
            .data(ext)
            .build(scope)
            .into(),
    );
    globals.prop(
        scope,
        "OfflineAudioContext",
        FunctionTemplate::builder(cb_offline_audio_context_ctor)
            .data(ext)
            .build(scope)
            .into(),
    );
    globals.prop(
        scope,
        "webkitAudioContext",
        FunctionTemplate::builder(cb_audio_context_ctor)
            .data(ext)
            .build(scope)
            .into(),
    );
    globals.prop(
        scope,
        "webkitOfflineAudioContext",
        FunctionTemplate::builder(cb_offline_audio_context_ctor)
            .data(ext)
            .build(scope)
            .into(),
    );
    globals.prop(
        scope,
        "AudioBuffer",
        FunctionTemplate::builder(cb_audio_buffer_ctor)
            .data(ext)
            .build(scope)
            .into(),
    );
    // Interface ctors exist (typeof 'function') but aren't constructibly
    // useful this tier — the same floor as HTMLElement above.
    for name in [
        "AudioNode",
        "AudioParam",
        "OscillatorNode",
        "AnalyserNode",
        "GainNode",
        "DynamicsCompressorNode",
        "BiquadFilterNode",
        "PannerNode",
        "StereoPannerNode",
        "ConvolverNode",
        "WaveShaperNode",
        "DelayNode",
        "ChannelSplitterNode",
        "ChannelMergerNode",
        "MediaStreamAudioSourceNode",
        "AudioWorkletNode",
        "PeriodicWave",
        "BaseAudioContext",
        // M4 remainder (firing 28) — the device/permission API prototype
        // ctors; the instances pages actually touch are built host-side.
        "Credential",
        "PasswordCredential",
        "FederatedCredential",
        "ClipboardEvent",
        "WakeLockSentinel",
        "BluetoothDevice",
        "USBDevice",
        "SerialPort",
        "HIDDevice",
        "Gamepad",
        "PresentationRequest",
        "XRSystem",
        "Lock",
        "LockManager",
        "Scheduler",
        "GPU",
        "GPUAdapter",
        "MediaCapabilities",
        "NetworkInformation",
        "Cache",
        "CacheStorage",
    ] {
        globals.prop(
            scope,
            name,
            FunctionTemplate::builder(cb_noop).data(ext).build(scope).into(),
        );
    }
    // Hidden raw half of scheduler.postTask — the JS trampoline in
    // finalize_context wraps it into a promise-returning postTask.
    globals.prop(
        scope,
        "__sePostTask",
        ft_pre(scope, ext, cb_post_task_raw).into(),
    );

    // matchMedia — existence + a plausible answer; listeners are noops.
    globals.prop(scope, "matchMedia", ft_pre(scope, ext, cb_match_media).into());

    // location — every string prop is an accessor pair over State.page_url
    // (single source of truth; iteration 24 replaced the fill-once data
    // props that went stale on assignment). assign/replace/href= do an
    // IN-SESSION navigation (new history entry); a real document load is
    // se-serve's `goto`, not an eval. The object is stashed under the
    // hidden "__seLocation" and the public `location` is itself an accessor
    // whose setter navigates — page script can never replace the object.
    let location = ObjectTemplate::new(scope);
    location.prop(scope, "assign", ft_pre(scope, ext, cb_location_assign).into());
    location.prop(scope, "replace", ft_pre(scope, ext, cb_location_replace).into());
    location.prop(scope, "reload", ft_pre(scope, ext, cb_noop).into());
    location.prop(
        scope,
        "toString",
        ft_pre(scope, ext, cb_location_to_string).into(),
    );
    for (name, get, set) in [
        (
            "href",
            v8::FunctionTemplate::builder(cb_loc_get_href)
                .data(ext)
                .build(scope),
            Some(
                v8::FunctionTemplate::builder(cb_loc_set_href)
                    .data(ext)
                    .build(scope),
            ),
        ),
        (
            "protocol",
            v8::FunctionTemplate::builder(cb_loc_get_protocol)
                .data(ext)
                .build(scope),
            Some(
                v8::FunctionTemplate::builder(cb_loc_set_protocol)
                    .data(ext)
                    .build(scope),
            ),
        ),
        (
            "host",
            v8::FunctionTemplate::builder(cb_loc_get_host)
                .data(ext)
                .build(scope),
            Some(
                v8::FunctionTemplate::builder(cb_loc_set_host)
                    .data(ext)
                    .build(scope),
            ),
        ),
        (
            "hostname",
            v8::FunctionTemplate::builder(cb_loc_get_hostname)
                .data(ext)
                .build(scope),
            Some(
                v8::FunctionTemplate::builder(cb_loc_set_hostname)
                    .data(ext)
                    .build(scope),
            ),
        ),
        (
            "port",
            v8::FunctionTemplate::builder(cb_loc_get_port)
                .data(ext)
                .build(scope),
            Some(
                v8::FunctionTemplate::builder(cb_loc_set_port)
                    .data(ext)
                    .build(scope),
            ),
        ),
        (
            "pathname",
            v8::FunctionTemplate::builder(cb_loc_get_pathname)
                .data(ext)
                .build(scope),
            Some(
                v8::FunctionTemplate::builder(cb_loc_set_pathname)
                    .data(ext)
                    .build(scope),
            ),
        ),
        (
            "search",
            v8::FunctionTemplate::builder(cb_loc_get_search)
                .data(ext)
                .build(scope),
            Some(
                v8::FunctionTemplate::builder(cb_loc_set_search)
                    .data(ext)
                    .build(scope),
            ),
        ),
        (
            "hash",
            v8::FunctionTemplate::builder(cb_loc_get_hash)
                .data(ext)
                .build(scope),
            Some(
                v8::FunctionTemplate::builder(cb_loc_set_hash)
                    .data(ext)
                    .build(scope),
            ),
        ),
        (
            "origin",
            v8::FunctionTemplate::builder(cb_loc_get_origin)
                .data(ext)
                .build(scope),
            None,
        ),
    ] {
        location.set_accessor_property(
            s_pre(scope, name).cast(),
            Some(get),
            set,
            v8::PropertyAttribute::NONE,
        );
    }
    globals.prop(scope, "__seLocation", location.into());
    let wl_get = v8::FunctionTemplate::builder(cb_window_location_get)
        .data(ext)
        .build(scope);
    let wl_set = v8::FunctionTemplate::builder(cb_window_location_set)
        .data(ext)
        .build(scope);
    globals.set_accessor_property(
        s_pre(scope, "location").cast(),
        Some(wl_get),
        Some(wl_set),
        v8::PropertyAttribute::NONE,
    );

    // window.open — popup-blocked shape (null), see cb_window_open.
    globals.prop(scope, "open", ft_pre(scope, ext, cb_window_open).into());

    // SPA tier — session history (pushState/back/popstate within the eval)
    // and the Event surface pages dispatch through.
    let history = ObjectTemplate::new(scope);
    let hist_len_get = v8::FunctionTemplate::builder(cb_history_length)
        .data(ext)
        .build(scope);
    history.set_accessor_property(
        s_pre(scope, "length").cast(),
        Some(hist_len_get),
        None,
        v8::PropertyAttribute::NONE,
    );
    let hist_state_get = v8::FunctionTemplate::builder(cb_history_state)
        .data(ext)
        .build(scope);
    history.set_accessor_property(
        s_pre(scope, "state").cast(),
        Some(hist_state_get),
        None,
        v8::PropertyAttribute::NONE,
    );
    history.prop(scope, "scrollRestoration", s_pre(scope, "auto").into());
    history.prop(scope, "back", ft_pre(scope, ext, cb_history_back).into());
    history.prop(scope, "forward", ft_pre(scope, ext, cb_history_forward).into());
    history.prop(scope, "go", ft_pre(scope, ext, cb_history_go).into());
    history.prop(
        scope,
        "pushState",
        ft_pre(scope, ext, cb_history_push_state).into(),
    );
    history.prop(
        scope,
        "replaceState",
        ft_pre(scope, ext, cb_history_replace_state).into(),
    );
    globals.prop(scope, "history", history.into());

    let event_ctor = FunctionTemplate::builder(cb_event_ctor)
        .data(ext)
        .build(scope);
    globals.prop(scope, "Event", event_ctor.into());
    let custom_event_ctor = FunctionTemplate::builder(cb_custom_event_ctor)
        .data(ext)
        .build(scope);
    globals.prop(scope, "CustomEvent", custom_event_ctor.into());

    // performance — `now()` counts from eval start (State.started);
    // `timeOrigin` is filled with the epoch ms in finalize_context. The
    // memory shape is a plausible desktop-Chrome heap snapshot; the
    // timeline getters return empty arrays (no subresource timeline is
    // recorded on this tier — the honest report) and mark/measure are
    // noops (documented floor: entries stay empty).
    let performance = ObjectTemplate::new(scope);
    performance.prop(scope, "now", ft_pre(scope, ext, cb_performance_now).into());
    performance.prop(scope, "timeOrigin", v8::Number::new(scope, 0.0).into());
    let memory = ObjectTemplate::new(scope);
    memory.prop(
        scope,
        "jsHeapSizeLimit",
        v8::Number::new(scope, 4_294_705_152.0).into(),
    );
    memory.prop(
        scope,
        "totalJSHeapSize",
        v8::Number::new(scope, 29_000_000.0).into(),
    );
    memory.prop(
        scope,
        "usedJSHeapSize",
        v8::Number::new(scope, 21_000_000.0).into(),
    );
    performance.prop(scope, "memory", memory.into());
    performance.prop(
        scope,
        "getEntriesByType",
        ft_pre(scope, ext, cb_empty_array).into(),
    );
    performance.prop(
        scope,
        "getEntriesByName",
        ft_pre(scope, ext, cb_empty_array).into(),
    );
    performance.prop(scope, "getEntries", ft_pre(scope, ext, cb_empty_array).into());
    performance.prop(scope, "mark", ft_pre(scope, ext, cb_noop).into());
    performance.prop(scope, "measure", ft_pre(scope, ext, cb_noop).into());
    globals.prop(scope, "performance", performance.into());

    // Web Storage — per-page maps shared across evals via Arc.
    globals.prop(scope, "localStorage", storage_template(scope, ext).into());
    globals.prop(scope, "sessionStorage", storage_template(scope, ext).into());

    // console — swallowed for now (see cb_console).
    let console = ObjectTemplate::new(scope);
    console.prop(scope, "log", ft_pre(scope, ext, cb_console).into());
    console.prop(scope, "info", ft_pre(scope, ext, cb_console).into());
    console.prop(scope, "warn", ft_pre(scope, ext, cb_console).into());
    console.prop(scope, "error", ft_pre(scope, ext, cb_console).into());
    globals.prop(scope, "console", console.into());

    // timing: a real macrotask queue drained by settle()'s pump, plus a
    // working queueMicrotask (v8 runs enqueued functions at the checkpoint).
    globals.prop(scope, "setTimeout", ft_pre(scope, ext, cb_set_timeout).into());
    globals.prop(scope, "setInterval", ft_pre(scope, ext, cb_set_interval).into());
    globals.prop(scope, "clearTimeout", ft_pre(scope, ext, cb_clear_timer).into());
    globals.prop(scope, "clearInterval", ft_pre(scope, ext, cb_clear_timer).into());
    globals.prop(scope, "queueMicrotask", ft_pre(scope, ext, cb_queue_microtask).into());
    // EventTarget surface — the registry makes window.dispatchEvent and
    // page-registered listeners actually run (these were noops before this
    // tier; see cb_add_event_listener).
    globals.prop(
        scope,
        "addEventListener",
        ft_pre(scope, ext, cb_add_event_listener).into(),
    );
    globals.prop(
        scope,
        "removeEventListener",
        ft_pre(scope, ext, cb_remove_event_listener).into(),
    );
    globals.prop(
        scope,
        "dispatchEvent",
        ft_pre(scope, ext, cb_dispatch_event).into(),
    );
    // Animation frame — one-shot ~16ms callback carrying a timestamp; the
    // pump drives it like a timer, cancelAnimationFrame reuses the timer id.
    globals.prop(
        scope,
        "requestAnimationFrame",
        ft_pre(scope, ext, cb_request_animation_frame).into(),
    );
    globals.prop(
        scope,
        "cancelAnimationFrame",
        ft_pre(scope, ext, cb_clear_timer).into(),
    );

    // fetch — the page-context network. Host callbacks can't capture, so the
    // promisify trampoline below binds each call's [resolve, reject] pair as
    // the second argument and cb_fetch drives them by hand. One fetch per
    // eval (the page jar can't interleave them meaningfully at this tier).
    globals.prop(scope, "fetch", ft_pre(scope, ext, cb_fetch).into());
    let text_tpl = ft_pre(scope, ext, cb_response_text);
    unsafe {
        (*state_ptr).text_template = Some(v8::Global::new(scope, text_tpl));
    }

    // XMLHttpRequest — a sync-open/send/responseText shim for the FB
    // anonymous-listing idiom. The constructor builds a per-instance wrapper
    // (v8 callbacks can't capture, so the JS closure binds each `this`).
    let xhr_ctor = FunctionTemplate::builder(cb_xhr_ctor).data(ext).build(scope);
    globals.prop(scope, "XMLHttpRequest", xhr_ctor.into());

    // Observers — IntersectionObserver/ResizeObserver share one host-queued
    // notification pump (cb_observer_flush, stashed for the timer machinery);
    // MutationObserver (firing 24) is LIVE over the firing-16 mutation tier:
    // registrations are standing filters in State::mutation_targets, records
    // queue per matching mutation, and the same pump drains them. Constructors
    // are FunctionTemplates like XMLHttpRequest above.
    let io_ctor = FunctionTemplate::builder(cb_intersection_observer_ctor)
        .data(ext)
        .build(scope);
    globals.prop(scope, "IntersectionObserver", io_ctor.into());
    let ro_ctor = FunctionTemplate::builder(cb_resize_observer_ctor)
        .data(ext)
        .build(scope);
    globals.prop(scope, "ResizeObserver", ro_ctor.into());
    let mo_ctor = FunctionTemplate::builder(cb_mutation_observer_ctor)
        .data(ext)
        .build(scope);
    globals.prop(scope, "MutationObserver", mo_ctor.into());
    // cb_observer_flush's Global is built lazily on the first observe() —
    // get_function needs a live context, which doesn't exist yet while
    // build_globals is assembling the global template.

    // WebSocket (firing 17) — a constructible state-machine stub. The
    // connection never reaches OPEN (no wire backend; faking open/message
    // would let a page hang an eval on a socket that never carries data), so
    // this is SHAPE only: typeof WebSocket === 'function', constants on the
    // constructor + prototype, a CONNECTING readyState, bufferedAmount
    // accounting while CONNECTING, and close(). The ready-state constants go
    // on via Function::new below (build_globals has no live context for
    // get_function on a FunctionTemplate).
    let ws_ctor = FunctionTemplate::builder(cb_ws_ctor)
        .data(ext)
        .build(scope);
    globals.prop(scope, "WebSocket", ws_ctor.into());
    globals.prop(scope, "__wsCtor", v8::Boolean::new(scope, true).into());

    // Page-init shapes (firing 19) — feature-detected constructors whose
    // instances are inert: Worker/SharedWorker (no second script context is
    // ever run) and Image (the tracking-pixel idiom: assign src, never
    // throws). typeof checks pass; the methods are callable noops.
    globals.prop(scope, "Worker", ft_pre(scope, ext, cb_worker_ctor).into());
    globals.prop(
        scope,
        "SharedWorker",
        ft_pre(scope, ext, cb_shared_worker_ctor).into(),
    );
    globals.prop(scope, "Image", ft_pre(scope, ext, cb_image_ctor).into());

    // window.name — an accessor pair over the per-tab Name cell: reads and
    // writes cross evals and navigations (it is NOT origin-scoped — the
    // browsing context owns it, like a real window).
    let name_get = v8::FunctionTemplate::builder(cb_window_name_get)
        .data(ext)
        .build(scope);
    let name_set = v8::FunctionTemplate::builder(cb_window_name_set)
        .data(ext)
        .build(scope);
    globals.set_accessor_property(
        s_pre(scope, "name").cast(),
        Some(name_get),
        Some(name_set),
        v8::PropertyAttribute::NONE,
    );

    // promise sinks for settle().
    globals.prop(scope, "__seResolve", ft_pre(scope, ext, cb_resolve).into());
    globals.prop(scope, "__seReject", ft_pre(scope, ext, cb_reject).into());
    globals.prop(scope, "__seThrow", ft_pre(scope, ext, cb_throw).into());

    // element wrapper template — stashed in State so callbacks can
    // instantiate more wrappers mid-eval.
    let el_tpl = build_element_template(scope, ext);
    unsafe {
        (*state_ptr).el_template = Some(v8::Global::new(scope, el_tpl));
    }

    // document.
    let document = ObjectTemplate::new(scope);
    document.prop(scope, "readyState", s_pre(scope, "complete").into());
    document.prop(scope, "visibilityState", s_pre(scope, "visible").into());
    document.prop(scope, "hidden", v8::Boolean::new(scope, false).into());
    // Legacy webkit aliases — old tracker code still probes them; a missing
    // webkitVisibilityState is a cheap headless tell.
    document.prop(scope, "webkitVisibilityState", s_pre(scope, "visible").into());
    document.prop(scope, "webkitHidden", v8::Boolean::new(scope, false).into());
    document.prop(scope, "URL", s_pre(scope, "").into());
    document.prop(scope, "title", s_pre(scope, "").into());
    document.prop(scope, "querySelector", ft_pre(scope, ext, cb_query_selector).into());
    document.prop(
        scope,
        "querySelectorAll",
        ft_pre(scope, ext, cb_query_selector_all).into(),
    );
    document.prop(
        scope,
        "getElementById",
        ft_pre(scope, ext, cb_get_element_by_id).into(),
    );
    document.prop(
        scope,
        "createElement",
        ft_pre(scope, ext, cb_document_create_element).into(),
    );
    document.prop(
        scope,
        "createTextNode",
        ft_pre(scope, ext, cb_document_create_text_node).into(),
    );
    document.prop(
        scope,
        "addEventListener",
        ft_pre(scope, ext, cb_add_event_listener).into(),
    );
    document.prop(
        scope,
        "removeEventListener",
        ft_pre(scope, ext, cb_remove_event_listener).into(),
    );
    document.prop(
        scope,
        "dispatchEvent",
        ft_pre(scope, ext, cb_dispatch_event).into(),
    );
    document.prop(scope, "hasFocus", ft_pre(scope, ext, cb_has_focus).into());
    // Fullscreen shapes (firing 26): exit resolves; no element is ever
    // fullscreen on this tier (the honest fresh-profile report).
    document.prop(
        scope,
        "exitFullscreen",
        ft_pre(scope, ext, cb_promise_resolve_undefined).into(),
    );
    document.prop(scope, "fullscreenElement", v8::null(scope).into());
    document.prop(scope, "webkitFullscreenElement", v8::null(scope).into());
    document.prop(scope, "fullscreenEnabled", v8::Boolean::new(scope, true).into());
    // documentElement/body are live wrappers over the cached parse, so they
    // carry node ids — provider scroll loops compare and walk from them.
    let root_get = v8::FunctionTemplate::builder(cb_document_root)
        .data(ext)
        .build(scope);
    document.set_accessor_property(
        s_pre(scope, "documentElement").cast(),
        Some(root_get),
        None,
        v8::PropertyAttribute::NONE,
    );
    let body_get = v8::FunctionTemplate::builder(cb_document_body)
        .data(ext)
        .build(scope);
    document.set_accessor_property(
        s_pre(scope, "body").cast(),
        Some(body_get),
        None,
        v8::PropertyAttribute::NONE,
    );
    // activeElement — an unfocused page reports its body (the bridge tracks
    // no focus moves; body is the honest default).
    let active_get = v8::FunctionTemplate::builder(cb_document_active_element)
        .data(ext)
        .build(scope);
    document.set_accessor_property(
        s_pre(scope, "activeElement").cast(),
        Some(active_get),
        None,
        v8::PropertyAttribute::NONE,
    );
    // cookie is an accessor pair, not a data prop — reads must reflect the
    // live jar and writes must land in it (ObjectTemplate::set_accessor_
    // property takes FunctionTemplates, the same builder pattern as the
    // data props above).
    let cookie_get = v8::FunctionTemplate::builder(cb_document_cookie_get)
        .data(ext)
        .build(scope);
    let cookie_set = v8::FunctionTemplate::builder(cb_document_cookie_set)
        .data(ext)
        .build(scope);
    document.set_accessor_property(
        s_pre(scope, "cookie").cast(),
        Some(cookie_get),
        Some(cookie_set),
        v8::PropertyAttribute::NONE,
    );
    globals.prop(scope, "document", document.into());

    globals
}

/// After the context exists: window/self references plus page-dependent
/// strings (location parts, document.URL/title). Parses the document once
/// for the title; the State's lazy parse is unchanged.
pub fn finalize_context<'s, 'i>(scope: &mut PinScope<'s, 'i>, state: &mut State) {
    let context = scope.get_current_context();
    let global = context.global(nullscope(scope));
    let _ = global.set(scope, sv(scope, "window"), global.into());
    let _ = global.set(scope, sv(scope, "self"), global.into());
    let _ = global.set(scope, sv(scope, "globalThis"), global.into());

    // navigator.languages — Array needs a live context (see build_globals).
    if let Some(nav) = global.get(scope, sv(scope, "navigator")) {
        let nav = nav.cast::<Object>();
        let langs = v8::Array::new_with_elements(scope, &[sv(scope, "en-US")]);
        let _ = nav.set(scope, sv(scope, "languages"), langs.into());

        // userAgentData.brands — from the SAME se-net constants the
        // Sec-CH-UA wire headers are built from; the two surfaces must
        // agree exactly.
        if let Some(uad) = nav.get(scope, sv(scope, "userAgentData")) {
            let uad = uad.cast::<Object>();
            let mut brands = Vec::with_capacity(se_net::CHROME_BRANDS.len());
            for (brand, version) in se_net::CHROME_BRANDS {
                let b = v8::Object::new(scope);
                set_prop(scope, b, "brand", sv(scope, brand));
                set_prop(scope, b, "version", sv(scope, version));
                brands.push(b.into());
            }
            let arr = v8::Array::new_with_elements(scope, &brands);
            let _ = uad.set(scope, sv(scope, "brands"), arr.into());
        }

        // plugins — a zero-length list is a headless tell; desktop Chrome
        // ships the five PDF-viewer entries. Array of objects (not a true
        // PluginArray) covers the probes that matter: length, enumeration,
        // [i].name. mimeTypes mirrors the one entry scripts actually read.
        let plugin_specs: [(&str, &str, &str); 5] = [
            ("PDF Viewer", "internal-pdf-viewer", "Portable Document Format"),
            (
                "Chrome PDF Viewer",
                "internal-pdf-viewer",
                "Portable Document Format",
            ),
            (
                "Chromium PDF Viewer",
                "internal-pdf-viewer",
                "Portable Document Format",
            ),
            (
                "Microsoft Edge PDF Viewer",
                "internal-pdf-viewer",
                "Portable Document Format",
            ),
            (
                "WebKit built-in PDF",
                "internal-pdf-viewer",
                "Portable Document Format",
            ),
        ];
        let mut plugins = Vec::with_capacity(plugin_specs.len());
        for (name, filename, description) in plugin_specs {
            let p = v8::Object::new(scope);
            set_prop(scope, p, "name", sv(scope, name));
            set_prop(scope, p, "filename", sv(scope, filename));
            set_prop(scope, p, "description", sv(scope, description));
            set_prop(scope, p, "length", v8::Number::new(scope, 1.0).into());
            plugins.push(p.into());
        }
        let arr = v8::Array::new_with_elements(scope, &plugins);
        let _ = nav.set(scope, sv(scope, "plugins"), arr.into());

        let mt = v8::Object::new(scope);
        set_prop(scope, mt, "type", sv(scope, "application/pdf"));
        set_prop(scope, mt, "suffixes", sv(scope, "pdf"));
        set_prop(scope, mt, "description", sv(scope, "Portable Document Format"));
        let mts = v8::Array::new_with_elements(scope, &[mt.into()]);
        let _ = nav.set(scope, sv(scope, "mimeTypes"), mts.into());
    }

    // Notification — a callable constructor with the fresh-profile
    // permission state; needs a live context for Function::new.
    if let Some(f) = v8::Function::new(scope, cb_noop) {
        let f = f.cast::<Object>();
        set_prop(scope, f, "permission", sv(scope, "default"));
        let _ = global.set(scope, sv(scope, "Notification"), f.into());
    }

    // WebSocket ready-state constants (firing 17) — the ctor went on the
    // global as a FunctionTemplate in build_globals, which has no live
    // context for get_function; here the context exists, so read it back and
    // stamp CONNECTING..CLOSED on both the constructor and its prototype,
    // per spec.
    if global
        .get(scope, sv(scope, "__wsCtor"))
        .map(|m| m.is_true())
        .unwrap_or(false)
    {
        if let Some(ws) = global.get(scope, sv(scope, "WebSocket")) {
            let ws = ws.cast::<Object>();
            let n0 = v8::Number::new(scope, 0.0).into();
            let n1 = v8::Number::new(scope, 1.0).into();
            let n2 = v8::Number::new(scope, 2.0).into();
            let n3 = v8::Number::new(scope, 3.0).into();
            set_prop(scope, ws, "CONNECTING", n0);
            set_prop(scope, ws, "OPEN", n1);
            set_prop(scope, ws, "CLOSING", n2);
            set_prop(scope, ws, "CLOSED", n3);
            if let Some(proto) = ws.get(scope, sv(scope, "prototype")) {
                let proto = proto.cast::<Object>();
                set_prop(scope, proto, "CONNECTING", n0);
                set_prop(scope, proto, "OPEN", n1);
                set_prop(scope, proto, "CLOSING", n2);
                set_prop(scope, proto, "CLOSED", n3);
            }
        }
        // Marker consumed — drop it so page JS doesn't see the artifact.
        let _ = global.delete(scope, sv(scope, "__wsCtor"));
    }

    let url = state.page_url.clone();

    // `document.location` is the same object as `window.location`, per
    // spec — the hidden singleton whose accessors derive from page_url.
    if let Some(loc) = global.get(scope, sv(scope, "__seLocation")) {
        if let Some(doc) = global.get(scope, sv(scope, "document")) {
            let doc = doc.cast::<Object>();
            let _ = doc.set(scope, sv(scope, "location"), loc.into());
        }
    }

    // Storage instances: stamp which area each object is (internal field 0)
    // and sync the length property with the page's map.
    for (name, slot) in [("localStorage", 0u8), ("sessionStorage", 1u8)] {
        if let Some(obj) = global.get(scope, sv(scope, name)) {
            let obj = obj.cast::<Object>();
            let _ = obj.set_internal_field(0, v8::Number::new(scope, slot as f64).into());
            let len = storage_for(state, slot).len();
            let _ = obj.set(
                scope,
                sv(scope, "length"),
                v8::Number::new(scope, len as f64).into(),
            );
        }
    }

    // performance.timeOrigin — epoch ms at eval start.
    if let Some(perf) = global.get(scope, sv(scope, "performance")) {
        let perf = perf.cast::<Object>();
        let _ = perf.set(
            scope,
            sv(scope, "timeOrigin"),
            v8::Number::new(scope, state.started_epoch_ms).into(),
        );
    }

    let title = state
        .doc()
        .select_one("title")
        .ok()
        .flatten()
        .map(|t| t.text())
        .unwrap_or_default();
    if let Some(doc) = global.get(scope, sv(scope, "document")) {
        let doc = doc.cast::<Object>();
        let _ = doc.set(scope, sv(scope, "URL"), sv(scope, &url));
        let _ = doc.set(scope, sv(scope, "title"), sv(scope, title.trim()));
        // The navigation initiator, exactly as a followed navigation leaves
        // it: full previous URL, empty string on an address-bar load.
        let _ = doc.set(scope, sv(scope, "referrer"), sv(scope, &state.page_referrer));
    }

    // fetch promisify. cb_fetch is a raw function so the [resolve, reject]
    // pair can be threaded as an argument (v8 callbacks can't capture); this
    // trampoline makes the global `fetch(input)` read as a normal promise.
    // It also normalizes `init` — method default GET, Headers instance OR
    // plain object (Headers.forEach already lowercased its names, matching
    // the wire), body stringified — so the host side reads plain strings
    // and never enumerates v8 objects. The resolve interceptor then upgrades
    // the response's read side to browser parity: `headers` arrives as plain
    // own props (lowercased names), so the Headers methods (get/has/forEach/
    // entries) close over a pair snapshot taken BEFORE the methods attach,
    // and `json()` is text() + JSON.parse with spec-shaped rejection.
    let shim = r#"
        (function() {
            var raw = this.fetch;
            this.fetch = function(input, init) {
                // AbortController integration: a PRE-ABORTED signal rejects
                // immediately with its reason (spec order). Mid-flight
                // cancellation is a documented floor — the request already
                // in flight runs to completion.
                if (init && init.signal && init.signal.aborted) {
                    return Promise.reject(init.signal.reason !== undefined
                        ? init.signal.reason
                        : new DOMException('The operation was aborted.', 'AbortError'));
                }
                return new Promise(function(resolve, reject) {
                    var method = (init && init.method) ? String(init.method) : 'GET';
                    var body = (init && init.body != null) ? String(init.body) : '';
                    var headers = [];
                    if (init && init.headers) {
                        if (typeof init.headers.forEach === 'function') {
                            init.headers.forEach(function(v, k) { headers.push([String(k), String(v)]); });
                        } else {
                            for (var k in init.headers) headers.push([k, String(init.headers[k])]);
                        }
                    }
                    raw(String(input), [function(resp) {
                        var h = resp.headers;
                        var pairs = [];
                        for (var k in h) {
                            if (typeof h[k] === 'string') pairs.push([k, h[k]]);
                        }
                        h.get = function(name) {
                            name = String(name).toLowerCase();
                            for (var i = 0; i < pairs.length; i++) {
                                if (pairs[i][0] === name) return pairs[i][1];
                            }
                            return null;
                        };
                        h.has = function(name) {
                            name = String(name).toLowerCase();
                            for (var i = 0; i < pairs.length; i++) {
                                if (pairs[i][0] === name) return true;
                            }
                            return false;
                        };
                        h.forEach = function(cb) {
                            for (var i = 0; i < pairs.length; i++) cb(pairs[i][1], pairs[i][0], h);
                        };
                        h.entries = function() {
                            var i = 0;
                            return {
                                next: function() {
                                    return i < pairs.length
                                        ? { value: pairs[i++], done: false }
                                        : { value: undefined, done: true };
                                }
                            };
                        };
                        resp.json = function() {
                            return new Promise(function(res, rej) {
                                resp.text([function(t) {
                                    try { res(JSON.parse(t)); } catch (e) { rej(e); }
                                }, rej]);
                            });
                        };
                        // The standard page idiom is `await resp.text()` — a
                        // bare call. The native read is the no-capture
                        // [resolve, reject]-array contract (like fetch's), so
                        // without this wrapper a bare text() returns the
                        // unresolved native promise and the await yields
                        // undefined (caught live against httpbin: pages that
                        // read fetch bodies the standard way got nothing).
                        // Dual-mode keeps the array shape working for the
                        // internal json() above and every existing caller.
                        var rawText = resp.text;
                        resp.text = function(a) {
                            if (a instanceof Array) {
                                return rawText.call(resp, a);
                            }
                            return new Promise(function(res, rej) {
                                rawText.call(resp, [res, rej]);
                            });
                        };
                        resolve(resp);
                    }, reject], method, JSON.stringify(headers), body);
                });
            };
        })()
    "#;
    let code = v8::String::new(scope, shim).expect("string alloc");
    if let Some(script) = v8::Script::compile(scope, code, None) {
        let _ = script.run(scope);
    }

    // Function.prototype.toString dispatch (M4). The fetch trampoline is a
    // JS function, and the toString INTRINSIC reflects its source — the
    // `Function.prototype.toString.call(fetch)` form fingerprint scripts
    // use invokes the intrinsic directly, so no own-property mask can
    // intercept it. The intrinsic is therefore replaced with a HOST
    // dispatcher: the trampoline (by identity, both rooted here) answers
    // with the native string, every other function falls through to the
    // original. Template-born, the dispatcher reads as native itself; its
    // name is pinned to "toString" like the real intrinsic.
    let fproto = global
        .get(scope, sv(scope, "Function"))
        .and_then(|f| f.to_object(scope))
        .and_then(|f| f.get(scope, sv(scope, "prototype")))
        .and_then(|p| p.to_object(scope));
    let fetch_obj = global
        .get(scope, sv(scope, "fetch"))
        .and_then(|f| f.to_object(scope));
    if let (Some(fproto), Some(fetch_obj)) = (fproto, fetch_obj) {
        if let Some(orig) = fproto
            .get(scope, sv(scope, "toString"))
            .map(|t| t.cast::<v8::Function>())
        {
            state.fp_tostring_orig = Some(v8::Global::new(scope, orig));
            state
                .fp_masks
                .push((v8::Global::new(scope, fetch_obj), "fetch".to_string()));
            // The trampoline source (`this.fetch = function(input, init)…`)
            // gets no V8 name inference from a member assignment — pin
            // `fetch.name === 'fetch'` like the real binding.
            let fetch_fn = fetch_obj.cast::<v8::Function>();
            if let Some(fname) = v8::String::new(scope, "fetch") {
                fetch_fn.set_name(fname);
            }
            let ext = v8::External::new(scope, state as *mut State as *mut std::ffi::c_void);
            let dispatch = v8::FunctionTemplate::builder(cb_fp_tostring)
                .data(ext.into())
                .build(scope)
                .get_function(scope);
            if let Some(dispatch) = dispatch {
                if let Some(name) = v8::String::new(scope, "toString") {
                    dispatch.set_name(name);
                }
                let _ = fproto.set(scope, sv(scope, "toString"), dispatch.into());
            }
        }
    }

    // ── M4 utility tier (firing 26), finalize-time installs ─────────────
    let ext = v8::External::new(scope, state as *mut State as *mut std::ffi::c_void);

    // structuredClone: the host callback returns the {__seOk, value|err}
    // envelope (a page's own __seOk keys can't collide — the wrapper reads
    // the wrapper's field, not the clone's); this JS trampoline unwraps
    // success and turns a clone failure into a DataCloneError DOMException.
    // v8 152 can't throw from a host callback, hence the envelope. The
    // trampoline is masked so its toString still reports native.
    let sc_obj = global
        .get(scope, sv(scope, "structuredClone"))
        .and_then(|f| f.to_object(scope));
    if let Some(sc_obj) = sc_obj {
        let shim = v8::String::new(
            scope,
            "(raw)=>function(v,o){var r=raw(v,o);if(r&&r.__seOk)return r.value;throw new DOMException(r.err,'DataCloneError');}",
        )
        .expect("string alloc");
        let wrapper = v8::Script::compile(scope, shim, None)
            .and_then(|s| s.run(scope))
            .and_then(|f| {
                f.cast::<Function>().call(
                    scope,
                    v8::undefined(scope).into(),
                    &[sc_obj.cast::<Value>()],
                )
            });
        if let Some(wrapper) = wrapper {
            if let Some(wobj) = wrapper.to_object(scope) {
                if let Some(name) = v8::String::new(scope, "structuredClone") {
                    wobj.cast::<Function>().set_name(name);
                }
                state
                    .fp_masks
                    .push((v8::Global::new(scope, wobj), "structuredClone".to_string()));
                let _ = global.set(scope, sv(scope, "structuredClone"), wrapper);
            }
        }
    }

    // Hidden `__seIdbError(request, err)`: the async half of an IDB request
    // error, reachable from make_idb_request's timer closure. Rooted in
    // State so the callback needs no context-global lookup per call.
    if let Some(f) = v8::FunctionTemplate::builder(cb_idb_error)
        .data(ext.into())
        .build(scope)
        .get_function(scope)
    {
        if let Some(o) = f.to_object(scope) {
            state.idb_error_fn = Some(v8::Global::new(scope, o));
            let _ = global.set(scope, sv(scope, "__seIdbError"), f.into());
        }
    }

    // ── M4 remainder (firing 28), finalize-time installs ────────────────

    // caches — a pure-JS per-eval-context CacheStorage/Cache round trip.
    // open/put/add/match/delete/keys all work within one eval (entries
    // live in JS Maps keyed by the request URL string as-given — no URL
    // resolution is a documented floor). Cross-eval persistence is the
    // other floor: real CacheStorage is per-origin persistent; this tier
    // has no Page plumbing, so each eval's context starts empty (same
    // class of floor as the fetch response registry). put() accepts our
    // fetch responses (raw text() pair contract) AND plain
    // string/response-likes; bodies ride as strings, so a cache hit's
    // text()/json() resolve without host involvement.
    let caches_shim = r#"
        (function() {
            var store = new Map();
            function keyOf(req) {
                if (req && typeof req === 'object' && 'url' in req) return String(req.url);
                return String(req);
            }
            function snapHeaders(h) {
                var out = {};
                if (h) {
                    if (typeof h.forEach === 'function') {
                        h.forEach(function(v, k) { out[String(k).toLowerCase()] = String(v); });
                    } else {
                        for (var k in h) out[String(k).toLowerCase()] = String(h[k]);
                    }
                }
                return out;
            }
            function makeResp(e) {
                var resp = {
                    status: e.status,
                    url: e.url,
                    ok: e.status >= 200 && e.status < 300,
                    redirected: false,
                    type: 'basic',
                    headers: Object.assign({}, e.headers),
                    body: null,
                    bodyUsed: false
                };
                resp.text = function() {
                    return new Promise(function(res) { res(e.body); });
                };
                resp.json = function() {
                    return new Promise(function(res, rej) {
                        try { res(JSON.parse(e.body)); } catch (err) { rej(err); }
                    });
                };
                return resp;
            }
            function makeCache(name) {
                var rec = { entries: new Map(), cache: null };
                store.set(name, rec);
                var cache = {};
                cache.put = function(req, resp) {
                    return new Promise(function(resolve, reject) {
                        var key = keyOf(req);
                        var settled = false;
                        var done = function(bodyText) {
                            // Both consumption paths may fire (the raw host
                            // text() resolves its returned promise undefined
                            // after calling the pair callback) — the first
                            // body wins, later calls must not overwrite.
                            if (settled) return;
                            settled = true;
                            rec.entries.set(key, {
                                status: resp && resp.status !== undefined ? Number(resp.status) : 200,
                                url: String(resp && resp.url !== undefined ? resp.url : key),
                                headers: snapHeaders(resp && resp.headers),
                                body: String(bodyText)
                            });
                            resolve(undefined);
                        };
                        if (resp && typeof resp.text === 'function') {
                            var maybe = resp.text([function(t) { done(t); }, reject]);
                            if (maybe && typeof maybe.then === 'function') maybe.then(done, reject);
                        } else {
                            done(resp === undefined || resp === null ? '' : String(resp));
                        }
                    });
                };
                cache.add = function(req) {
                    var url = String(req && req.url !== undefined ? req.url : req);
                    return fetch(url).then(function(resp) { return cache.put(url, resp); });
                };
                cache.addAll = function(reqs) {
                    return Promise.all(Array.prototype.map.call(reqs, function(r) { return cache.add(r); }));
                };
                cache.match = function(req) {
                    var e = rec.entries.get(keyOf(req));
                    return Promise.resolve(e === undefined ? undefined : makeResp(e));
                };
                cache.matchAll = function(req) {
                    if (req === undefined) {
                        return Promise.resolve(Array.from(rec.entries.values()).map(makeResp));
                    }
                    var e = rec.entries.get(keyOf(req));
                    return Promise.resolve(e === undefined ? [] : [makeResp(e)]);
                };
                cache.delete = function(req) {
                    return Promise.resolve(rec.entries.delete(keyOf(req)));
                };
                cache.keys = function() {
                    return Promise.resolve(Array.from(rec.entries.keys()));
                };
                rec.cache = cache;
                return cache;
            }
            this.caches = {
                open: function(name) {
                    name = String(name);
                    if (store.has(name)) return Promise.resolve(store.get(name).cache);
                    return Promise.resolve(makeCache(name));
                },
                has: function(name) { return Promise.resolve(store.has(String(name))); },
                keys: function() { return Promise.resolve(Array.from(store.keys())); },
                match: function(req) {
                    var key = keyOf(req);
                    var all = Array.from(store.values());
                    for (var i = 0; i < all.length; i++) {
                        var e = all[i].entries.get(key);
                        if (e !== undefined) return Promise.resolve(makeResp(e));
                    }
                    return Promise.resolve(undefined);
                },
                matchAll: function(req) {
                    var out = [];
                    if (req !== undefined) {
                        var key = keyOf(req);
                        var all = Array.from(store.values());
                        for (var i = 0; i < all.length; i++) {
                            var e = all[i].entries.get(key);
                            if (e !== undefined) out.push(makeResp(e));
                        }
                    }
                    return Promise.resolve(out);
                },
                delete: function(name) { return Promise.resolve(store.delete(String(name))); }
            };
        })()
    "#;
    let code = v8::String::new(scope, caches_shim).expect("string alloc");
    if let Some(script) = v8::Script::compile(scope, code, None) {
        let _ = script.run(scope);
    }

    // scheduler.postTask — the raw host half (0ms timer via the State
    // queue) wrapped into a promise-returning task scheduler; priorities
    // are a documented floor (everything runs as a 0ms FIFO timer). The
    // wrapper is masked so its toString reports native, like fetch and
    // structuredClone.
    let sched_obj = global.get(scope, sv(scope, "__sePostTask"));
    if let Some(raw) = sched_obj {
        let shim = v8::String::new(
            scope,
            "(raw)=>this.scheduler={postTask:function(cb,opts){return new Promise(function(res,rej){raw(cb,[res,rej]);});}}",
        )
        .expect("string alloc");
        let wrapper = v8::Script::compile(scope, shim, None)
            .and_then(|s| s.run(scope))
            .and_then(|f| f.cast::<Function>().call(scope, global.into(), &[raw]));
        if let Some(post_task) = wrapper
            .and_then(|w| w.to_object(scope))
            .and_then(|o| o.get(scope, sv(scope, "postTask")))
            .and_then(|p| p.to_object(scope))
        {
            if let Some(name) = v8::String::new(scope, "postTask") {
                post_task.cast::<Function>().set_name(name);
            }
            state
                .fp_masks
                .push((v8::Global::new(scope, post_task), "postTask".to_string()));
        }
    }

    // The custom-elements registry (define records; get/whenDefined read).
    let _ = global.set(scope, sv(scope, "__seCustomRegistry"), Object::new(scope).into());
}

/// Fire every timer whose deadline has passed. Drains due entries from the
/// queue, runs each callback under a TryCatch (a throwing timer must not
/// poison the eval's pending-exception slot), then reschedules intervals
/// whose id wasn't cancelled from inside the callback.
fn fire_due_timers<'s, 'i>(state: &mut State, scope: &mut PinScope<'s, 'i>) {
    let now = Instant::now();
    let pending = std::mem::take(&mut state.timers);
    let (due, rest): (Vec<_>, Vec<_>) = pending
        .into_iter()
        .partition(|t| t.deadline <= now);
    state.timers = rest;
    for t in due {
        let f = Local::new(scope, t.callback);
        let recv = v8::undefined(scope).into();
        {
            // Call under a TryCatch: a throwing timer callback must not leave
            // a pending exception to poison the settle stringify. V8's
            // ~TryCatch clears the caught exception as the guard drops.
            v8::tc_scope!(tc, scope);
            if t.raf {
                // Frame tick: the argument is a DOMHighResTimeStamp from the
                // same monotonic clock performance.now() reads.
                let ts = v8::Number::new(&mut *tc, state.started.elapsed().as_millis() as f64);
                let _ = f.call(&mut *tc, recv, &[ts.into()]);
            } else {
                let _ = f.call(&mut *tc, recv, &[]);
            }
        }
        if let Some(ms) = t.interval_ms {
            if !state.cancelled.contains(&t.id) {
                state.timers.push(Timer {
                    id: t.id,
                    deadline: Instant::now() + Duration::from_millis(ms),
                    interval_ms: Some(ms),
                    raf: false,
                    callback: v8::Global::new(scope, f),
                });
            }
        }
    }
}

/// Handle the completion value and run the event-loop pump.
///
/// A top-level Promise gets the resolve/reject sinks attached; then every
/// completion — promise or plain value — drives the pump: microtask
/// checkpoint, fire due timers, repeat, until the tracked promise settles,
/// no timers remain, or the wall-clock budget trips. This is what makes
/// `await new Promise(r => setTimeout(r, n))`, scroll loops, and interval
/// accumulators return their answers instead of the pre-schedule value.
/// `budget` caps the pump (render mode passes the caller's `settle_ms`).
pub fn settle<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    result: Local<'s, Value>,
    state: &mut State,
    budget: Duration,
) -> Settled {
    let tracked = result.is_promise();
    if tracked {
        let context = scope.get_current_context();
        let global = context.global(nullscope(scope));
        let resolve = global
            .get(scope, sv(scope, "__seResolve"))
            .filter(|v| v.is_function())
            .map(|v| v.cast::<Function>());
        let reject = global
            .get(scope, sv(scope, "__seReject"))
            .filter(|v| v.is_function())
            .map(|v| v.cast::<Function>());
        if let (Some(on_ok), Some(on_err)) = (resolve, reject) {
            let promise = result.cast::<Promise>();
            let _ = promise.then2(scope, on_ok, on_err);
        }
    }
    let deadline = Instant::now() + budget;
    loop {
        scope.perform_microtask_checkpoint();
        if state.resolved.is_some() || state.rejected.is_some() {
            break;
        }
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        match state.timers.iter().map(|t| t.deadline).min() {
            None => break,
            // Wake at the nearest timer OR the budget's end, whichever is
            // sooner: sleeping straight to a far timer deadline would blow
            // past the budget (render mode passes short settle_ms values).
            // fire_due_timers only fires timers whose deadline passed, so the
            // extra budget wake simply fires nothing and the loop breaks.
            Some(d) => {
                let wake = d.min(deadline);
                if wake > now {
                    std::thread::sleep(wake - now);
                }
                fire_due_timers(state, scope);
            }
        }
    }
    if !tracked {
        return Settled::Value;
    }
    if let Some(reason) = state.rejected.take() {
        return Settled::Rejected(reason);
    }
    Settled::Resolved(state.resolved.take().unwrap_or_else(|| "null".into()))
}

/// Raw pointer access for `Runtime` — the State box outlives the eval.
pub fn state_ptr(state: &mut State) -> *mut State {
    state as *mut State
}

#[cfg(test)]
mod webapi_tests {
    use super::*;

    /// Minimal loopback HTTP/1.1 server answering requests with a JSON echo
    /// of the path and a marker header. Served by a detached, non-blocking
    /// thread so a fully-served server never blocks process exit. The request
    /// head is read until its blank line — a single `read` can return a partial
    /// head if the request arrives in more than one TCP segment, and answering
    /// early would desync the connection.
    fn spawn_server<F>(n: usize, handle: F) -> String
    where
        F: Fn(&str, &str) -> (u16, String) + Send + 'static,
    {
        spawn_server_with_headers(n, move |path, req| {
            let (status, body) = handle(path, req);
            (status, body, Vec::new())
        })
    }

    /// `spawn_server` with extra response headers per answer — the Set-Cookie
    /// tests need the wire to carry cookies back into the session jar.
    fn spawn_server_with_headers<F>(n: usize, handle: F) -> String
    where
        F: Fn(&str, &str) -> (u16, String, Vec<(String, String)>) + Send + 'static,
    {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::mpsc as std_mpsc;
        use std::time::{Duration, Instant};
        let (addr_tx, addr_rx) = std_mpsc::channel();
        std::thread::spawn(move || {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let bound = listener.local_addr().unwrap();
            addr_tx.send(bound).unwrap();
            for _ in 0..n {
                let (mut socket, _peer) = match listener.accept() {
                    Ok(c) => c,
                    Err(_) => break,
                };
                let _ = socket.set_nodelay(true);
                let _ = socket.set_read_timeout(Some(Duration::from_secs(10)));
                let mut buf = Vec::with_capacity(8192);
                let mut chunk = [0u8; 4096];
                // Read until the request head's terminating blank line.
                let start = Instant::now();
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    if start.elapsed() > Duration::from_secs(10) {
                        break;
                    }
                    match socket.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(m) => {
                            buf.extend_from_slice(&chunk[..m]);
                            if buf.len() > 64 * 1024 {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let req = String::from_utf8_lossy(&buf).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                let (status, body, extra) = handle(&path, &req);
                let extra_lines: String = extra
                    .iter()
                    .map(|(k, v)| format!("{k}: {v}\r\n"))
                    .collect();
                let head = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\nX-Marker: webapi\r\n{extra_lines}\r\n",
                    body.len()
                );
                let _ = socket.write_all(format!("{head}{body}").as_bytes());
                let _ = socket.flush();
            }
        });
        let addr = addr_rx.recv().unwrap();
        format!("http://{addr}")
    }

    /// Iteration-23 seam: like `spawn_server_with_headers`, but the handler
    /// returns the EXACT response bytes to write verbatim — the honesty
    /// fixtures (chunked framing, no Content-Length, oversized heads,
    /// mid-head closes) are shapes the always-Content-Length seams above
    /// cannot produce.
    fn spawn_raw_server<F>(n: usize, handle: F) -> String
    where
        F: Fn(&str, &str) -> Vec<u8> + Send + 'static,
    {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::mpsc as std_mpsc;
        use std::time::{Duration, Instant};
        let (addr_tx, addr_rx) = std_mpsc::channel();
        std::thread::spawn(move || {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let bound = listener.local_addr().unwrap();
            addr_tx.send(bound).unwrap();
            for _ in 0..n {
                let (mut socket, _peer) = match listener.accept() {
                    Ok(c) => c,
                    Err(_) => break,
                };
                let _ = socket.set_nodelay(true);
                let _ = socket.set_read_timeout(Some(Duration::from_secs(10)));
                let mut buf = Vec::with_capacity(8192);
                let mut chunk = [0u8; 4096];
                // Same request-head discipline as the other seams: read to
                // the blank line, bounded, then answer.
                let start = Instant::now();
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    if start.elapsed() > Duration::from_secs(10) {
                        break;
                    }
                    match socket.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(m) => {
                            buf.extend_from_slice(&chunk[..m]);
                            if buf.len() > 64 * 1024 {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let req = String::from_utf8_lossy(&buf).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                let bytes = handle(&path, &req);
                let _ = socket.write_all(&bytes);
                let _ = socket.flush();
            }
        });
        let addr = addr_rx.recv().unwrap();
        format!("http://{addr}")
    }

    /// Spawn a closure on a detached thread that yields rather than blocks, so
    /// the thread can't hold the test process open at exit.
    #[allow(dead_code)]
    fn non_blocking<F>(f: F) -> std::thread::JoinHandle<()>
    where
        F: FnOnce() + Send + 'static,
    {
        std::thread::spawn(f)
    }

    #[test]
    fn fetch_resolves_through_the_microtask_checkpoint() {
        let base = spawn_server(1, |path, _| {
            (200, format!(r#"{{"you_asked_for":"{path}"}}"#))
        });
        let mut rt = crate::Runtime::new();
        let page = Page::new(format!("{base}/page"), "<html><body>shell</body></html>");
        let js = "(async () => { const r = await fetch('/api/items'); return r.status; })()";
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("fetch eval resolves");
        assert_eq!(out, serde_json::json!(200));
    }
    #[test]
    fn fetch_text_and_headers_are_readable() {
        let base = spawn_server(1, |_path, _| (200, "hello body".to_string()));
        let mut rt = crate::Runtime::new();
        let page = Page::new(format!("{base}/page"), "<html><body>shell</body></html>");
        let js = r#"
            (async () => {
                const r = await fetch('/data');
                // r.text is a raw host function (v8 callbacks can't capture):
                // thread a [resolve, reject] pair like the fetch trampoline
                // does, and send the body text to __seResolve.
                const text = await new Promise((res, rej) => r.text([res, rej]));
                return { status: r.status, ok: r.ok, marker: r.headers['x-marker'], text };
            })()
        "#;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("fetch text eval resolves");
        assert_eq!(out["status"], serde_json::json!(200));
        assert_eq!(out["ok"], serde_json::json!(true));
        assert_eq!(out["marker"], serde_json::json!("webapi"));
        assert_eq!(out["text"], serde_json::json!("hello body"));
    }
    #[test]
    fn fetch_rejects_when_the_network_says_no() {
        // Nothing listens on this port; the page-context fetch must reject
        // (not throw synchronously, not hang) so the eval sees a rejection.
        let mut rt = crate::Runtime::new();
        let page = Page::new("http://127.0.0.1:1/page", "<html><body>shell</body></html>");
        let js = "(async () => { await fetch('/nope'); return 'unreached'; })()";
        let result = rt.eval_with_page(Some(&page), js);
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("failed to fetch"),
            "rejection reason mentions the network failure: {err}"
        );
    }

    #[test]
    fn fetch_refuses_a_link_local_literal_before_any_dial() {
        // Bug 28: page-side fetch() is a full network surface -- a script
        // aiming it at the cloud metadata endpoint dialed the refused
        // address outright (the raw-TCP branch had no target guard at
        // all). No listener exists; the rejection must name the policy
        // token, and nothing connects.
        let mut rt = crate::Runtime::new();
        let page = Page::new("http://127.0.0.1:1/page", "<html><body>shell</body></html>");
        let js = "(async () => { await fetch('http://169.254.169.254/latest/meta-data'); return 'unreached'; })()";
        let err = rt.eval_with_page(Some(&page), js).unwrap_err();
        assert!(
            err.to_string().contains("target_refused"),
            "link-local literal must reject target_refused, got: {err}"
        );
    }

    #[test]
    fn fetch_refuses_a_redirect_to_link_local_on_the_hop() {
        // The fixture 302s at the metadata endpoint; it answers EXACTLY
        // ONE request, so a followed hop dials link-local (a connect
        // error or hang, never the policy token) -- the refusal must
        // fire between the 302 and the dial.
        let base = spawn_server_with_headers(1, |_path, _req| {
            (
                302,
                String::new(),
                vec![(
                    "Location".to_string(),
                    "http://169.254.169.254/latest/meta-data".to_string(),
                )],
            )
        });
        let mut rt = crate::Runtime::new();
        let page = Page::new(format!("{base}/page"), "<html><body>shell</body></html>");
        let js = "(async () => { await fetch('/jump'); return 'unreached'; })()";
        let err = rt.eval_with_page(Some(&page), js).unwrap_err();
        assert!(
            err.to_string().contains("target_refused"),
            "302 to link-local must reject target_refused, got: {err}"
        );
    }

    #[test]
    fn fetch_refuses_a_non_http_scheme_target() {
        // A page-side redirect (or direct call) at a non-http(s) scheme
        // must refuse the way the navigation client does -- pre-fix the
        // raw branch fell through to a nonsense dial (or a 'no host'
        // error), never the policy token.
        let mut rt = crate::Runtime::new();
        let page = Page::new("http://127.0.0.1:1/page", "<html><body>shell</body></html>");
        let js = "(async () => { await fetch('file:///etc/passwd'); return 'unreached'; })()";
        let err = rt.eval_with_page(Some(&page), js).unwrap_err();
        assert!(
            err.to_string().contains("target_refused"),
            "file: target must reject target_refused, got: {err}"
        );
    }

    #[test]
    fn fetch_over_http_serves_through_the_checked_dial() {
        // The raw branch now resolves and vets before dialing -- this
        // pins the integration: the localhost NAME (not a literal) must
        // resolve, pass the vetting, and serve.
        let base = spawn_server(1, |path, _| {
            (200, format!(r#"{{"you_asked_for":"{path}"}}"#))
        });
        let base = base.replacen("127.0.0.1", "localhost", 1);
        let mut rt = crate::Runtime::new();
        let page = Page::new(format!("{base}/page"), "<html><body>shell</body></html>");
        let js = "(async () => { const r = await fetch('/api/items'); return r.status; })()";
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("named-host fetch resolves");
        assert_eq!(out, serde_json::json!(200));
    }

    #[test]
    fn vet_addrs_refused_answer_poisons_the_set() {
        // Bug 27's rule one tier down: a legit name never answers
        // link-local, so ANY refused answer poisons the whole set.
        let ok: std::net::SocketAddr = "127.0.0.1:80".parse().unwrap();
        let link: std::net::SocketAddr = "169.254.169.254:80".parse().unwrap();
        assert!(vet_addrs("ok.test", vec![ok]).is_ok());
        let err = vet_addrs("evil.test", vec![link]).unwrap_err();
        assert!(
            err.contains("target_refused: dns:evil.test"),
            "the refused name rides the message: {err}"
        );
        let err = vet_addrs("evil.test", vec![ok, link]).unwrap_err();
        assert!(err.contains("target_refused"), "mixed set poisons: {err}");
        let mapped: std::net::SocketAddr = "[::ffff:169.254.169.254]:80".parse().unwrap();
        assert!(vet_addrs("evil.test", vec![mapped]).is_err());
        let v6link: std::net::SocketAddr = "[fe80::1]:80".parse().unwrap();
        assert!(vet_addrs("evil.test", vec![v6link]).is_err());
    }

    // ---- Iteration 23: fetch-shim raw-HTTP honesty family ----------------
    // The raw-TCP arm below the guarded https path served the wire
    // verbatim: chunk frames and gzip bytes landed in the page's hands as
    // "body text", head and body reads were unbounded, and a SYN-blackhole
    // connect parked the isolate thread on the OS TCP timeout (bug-24
    // class). These probes pin the honest shapes; they use the
    // `spawn_raw_server` verbatim-bytes seam because the older seams always
    // set Content-Length and cannot frame these responses.

    #[test]
    fn fetch_decodes_a_chunked_response_body() {
        // Transfer-Encoding frames must never reach the page: the shim
        // de-frames chunks (and drains trailers) before text() sees bytes.
        let base = spawn_raw_server(1, |_path, _req| {
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: t\r\n\r\n".to_vec()
        });
        let mut rt = crate::Runtime::new();
        let page = Page::new(format!("{base}/page"), "<html><body>shell</body></html>");
        let js = "(async () => { const r = await fetch('/c'); return await new Promise((res, rej) => r.text([res, rej])); })()";
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("chunked fetch resolves");
        assert_eq!(out, serde_json::json!("hello world"));
    }

    #[test]
    fn fetch_refuses_a_gzip_body_it_did_not_ask_for() {
        // The shim asks for identity (pinned below) and cannot decode gzip
        // in v1: a Content-Encoding it didn't negotiate must refuse
        // honestly, never serve compressed bytes as text. The fixture is
        // gzip("hello"), 25 bytes, written as decimal literals because
        // non-ASCII source gets mangled in transmission.
        let gz: [u8; 25] = [
            31, 139, 8, 0, 0, 0, 0, 0, 2, 255, 203, 72, 205, 201, 201, 7, 0, 134, 166, 16, 54, 5,
            0, 0, 0,
        ];
        let base = spawn_raw_server(1, move |_path, _req| {
            let mut bytes = format!(
                "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                gz.len()
            )
            .into_bytes();
            bytes.extend_from_slice(&gz);
            bytes
        });
        let mut rt = crate::Runtime::new();
        let page = Page::new(format!("{base}/page"), "<html><body>shell</body></html>");
        let js = "(async () => { await fetch('/gzip'); return 'unreached'; })()";
        let err = rt.eval_with_page(Some(&page), js).unwrap_err();
        assert!(
            err.to_string().contains("unsupported_content_encoding:gzip"),
            "gzip must refuse with the honesty token, got: {err}"
        );
    }

    /// Echo fixture for the Accept-Encoding pair: the response body is the
    /// request's Accept-Encoding value (or MISSING when absent).
    fn spawn_ae_echo() -> String {
        spawn_raw_server(1, |_path, req| {
            let ae = req
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("accept-encoding:"))
                .map(|l| l.splitn(2, ':').nth(1).unwrap_or("").trim().to_string())
                .unwrap_or_else(|| "MISSING".to_string());
            let mut bytes = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                ae.len()
            )
            .into_bytes();
            bytes.extend_from_slice(ae.as_bytes());
            bytes
        })
    }

    #[test]
    fn fetch_sends_accept_encoding_identity_by_default() {
        // The raw arm can't decode anything, so its default offer must be
        // `identity` — anything else invites bytes it would have to serve
        // as garbage (the gzip probe above).
        let base = spawn_ae_echo();
        let mut rt = crate::Runtime::new();
        let page = Page::new(format!("{base}/page"), "<html><body>shell</body></html>");
        let js = "(async () => { const r = await fetch('/echo'); return await new Promise((res, rej) => r.text([res, rej])); })()";
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("echo fetch resolves");
        assert_eq!(out, serde_json::json!("identity"));
    }

    #[test]
    fn fetch_passes_a_page_supplied_accept_encoding_through() {
        // Guard (already true pre-fix): the fetch-spec header merge lets a
        // page set its own Accept-Encoding; the identity default must not
        // clobber it.
        let base = spawn_ae_echo();
        let mut rt = crate::Runtime::new();
        let page = Page::new(format!("{base}/page"), "<html><body>shell</body></html>");
        let js = "(async () => { const r = await fetch('/echo', { headers: { 'Accept-Encoding': 'br' } }); return await new Promise((res, rej) => r.text([res, rej])); })()";
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("echo fetch resolves");
        assert_eq!(out, serde_json::json!("br"));
    }

    #[test]
    fn fetch_refuses_an_oversized_declared_body_before_reading_it() {
        // Content-Length over the subresource cap (se-net's 16 MiB, which
        // this shim mirrors) refuses from the HEADERS — the body is never
        // pulled. The fixture closes after a short body, so a shim that
        // ignored the declared length resolves with "short" instead.
        let base = spawn_raw_server(1, |_path, _req| {
            b"HTTP/1.1 200 OK\r\nContent-Length: 20971520\r\nConnection: close\r\n\r\nshort".to_vec()
        });
        let mut rt = crate::Runtime::new();
        let page = Page::new(format!("{base}/page"), "<html><body>shell</body></html>");
        let js = "(async () => { await fetch('/big'); return 'unreached'; })()";
        let err = rt.eval_with_page(Some(&page), js).unwrap_err();
        assert!(
            err.to_string().contains("too_large"),
            "an over-cap Content-Length must refuse too_large, got: {err}"
        );
    }

    #[test]
    fn fetch_refuses_a_chunked_body_over_the_cap_while_streaming() {
        // No Content-Length to pre-check: the streamed DECODED total trips
        // the same cap. 257 x 64 KiB chunks = 16 MiB + one chunk over.
        let base = spawn_raw_server(1, |_path, _req| {
            let mut bytes =
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                    .to_vec();
            let chunk = vec![b'x'; 65536];
            for _ in 0..257 {
                bytes.extend_from_slice(b"10000\r\n");
                bytes.extend_from_slice(&chunk);
                bytes.extend_from_slice(b"\r\n");
            }
            bytes.extend_from_slice(b"0\r\n\r\n");
            bytes
        });
        let mut rt = crate::Runtime::new();
        let page = Page::new(format!("{base}/page"), "<html><body>shell</body></html>");
        let js = "(async () => { await fetch('/big'); return 'unreached'; })()";
        let err = rt.eval_with_page(Some(&page), js).unwrap_err();
        assert!(
            err.to_string().contains("too_large"),
            "a streamed over-cap chunked body must refuse too_large, got: {err}"
        );
    }

    #[test]
    fn fetch_refuses_an_oversized_response_head() {
        // A head without a terminator within 64 KiB refuses too_large
        // instead of slurping without bound.
        let base = spawn_raw_server(1, |_path, _req| {
            let mut bytes = b"HTTP/1.1 200 OK\r\nX-Pad: ".to_vec();
            bytes.extend(std::iter::repeat(b'a').take(70 * 1024));
            bytes.extend_from_slice(b"\r\n\r\nbody");
            bytes
        });
        let mut rt = crate::Runtime::new();
        let page = Page::new(format!("{base}/page"), "<html><body>shell</body></html>");
        let js = "(async () => { await fetch('/fat'); return 'unreached'; })()";
        let err = rt.eval_with_page(Some(&page), js).unwrap_err();
        assert!(
            err.to_string().contains("too_large"),
            "an over-cap response head must refuse too_large, got: {err}"
        );
    }

    #[test]
    fn fetch_connect_is_bounded_instead_of_parking_the_isolate() {
        // 192.0.2.0/24 (TEST-NET-1, RFC 5737) is never routed: the SYN gets
        // dropped, and an unbounded dial parks blocking_fetch's rx.recv() —
        // the whole isolate thread — on the OS TCP timeout (~21s Windows,
        // ~2m+ Linux). The checked dial bounds each address at 5s. (If this
        // box's gateway fast-fails unreachable instead, the bite is the
        // missing "timed out" token rather than the elapsed time.)
        let mut rt = crate::Runtime::new();
        let page = Page::new("http://127.0.0.1:1/page", "<html><body>shell</body></html>");
        let js = "(async () => { await fetch('http://192.0.2.1:81/'); return 'unreached'; })()";
        let started = std::time::Instant::now();
        let err = rt.eval_with_page(Some(&page), js).unwrap_err();
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(15),
            "an unbounded dial parks the isolate on the OS timeout: {elapsed:?}"
        );
        assert!(
            err.to_string().contains("timed out"),
            "the bounded dial reports its timeout, got: {err}"
        );
    }

    #[test]
    fn fetch_refuses_a_response_that_closes_mid_head() {
        // EOF before the head's blank line: pre-fix the parser found no
        // terminator, served the raw head bytes AS the body, and still
        // reported status 200. The honest shape is a truncated: refusal.
        let base = spawn_raw_server(1, |_path, _req| {
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n".to_vec()
        });
        let mut rt = crate::Runtime::new();
        let page = Page::new(format!("{base}/page"), "<html><body>shell</body></html>");
        let js = "(async () => { await fetch('/half'); return 'unreached'; })()";
        let err = rt.eval_with_page(Some(&page), js).unwrap_err();
        assert!(
            err.to_string().contains("truncated"),
            "a head closed before its blank line must refuse truncated, got: {err}"
        );
    }

    #[test]
    fn fetch_refuses_a_body_truncated_below_content_length() {
        // EOF before the declared length: never serve the short prefix as
        // if it were the whole body (the iteration-16 honesty rule, one
        // tier down).
        let base = spawn_raw_server(1, |_path, _req| {
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nshort".to_vec()
        });
        let mut rt = crate::Runtime::new();
        let page = Page::new(format!("{base}/page"), "<html><body>shell</body></html>");
        let js = "(async () => { await fetch('/short'); return 'unreached'; })()";
        let err = rt.eval_with_page(Some(&page), js).unwrap_err();
        assert!(
            err.to_string().contains("truncated"),
            "a short body must refuse truncated, got: {err}"
        );
    }

    #[test]
    fn xhr_sync_open_send_reads_response_text() {
        let base = spawn_server(1, |path, _| {
            (200, format!(r#"{{"path":"{path}"}}"#))
        });
        let mut rt = crate::Runtime::new();
        let page = Page::new(format!("{base}/page"), "<html><body>shell</body></html>");
        let js = r#"
            (function() {
                var x = new XMLHttpRequest();
                x.open('GET', '/api/list', false);
                x.send();
                var data = JSON.parse(x.responseText);
                return { status: x.status, path: data.path };
            })()
        "#;
        let out = rt.eval_with_page(Some(&page), js).expect("xhr eval runs");
        assert_eq!(out["status"], serde_json::json!(200));
        assert_eq!(out["path"], serde_json::json!("/api/list"));
    }

    // ── timers ────────────────────────────────────────────────────────────

    #[test]
    fn timer_timeout_fires_after_the_script_task() {
        // Macrotask ordering: sync script body runs first, then the 0ms
        // timer, then the await's continuation observes both.
        let mut rt = crate::Runtime::new();
        let js = r#"
            (async () => {
                const order = [];
                setTimeout(() => order.push('timer'), 0);
                order.push('script');
                await new Promise(r => setTimeout(r, 5));
                return order;
            })()
        "#;
        let out = rt.eval(js).expect("timer eval resolves");
        assert_eq!(out, serde_json::json!(["script", "timer"]));
    }

    #[test]
    fn timer_microtasks_run_before_zero_ms_timers() {
        // The HTML event loop drains microtasks before the next macrotask.
        let mut rt = crate::Runtime::new();
        let js = r#"
            (async () => {
                const order = [];
                Promise.resolve().then(() => order.push('micro'));
                setTimeout(() => order.push('macro'), 0);
                await new Promise(r => setTimeout(r, 5));
                return order;
            })()
        "#;
        let out = rt.eval(js).expect("ordering eval resolves");
        assert_eq!(out, serde_json::json!(["micro", "macro"]));
    }

    #[test]
    fn timer_clear_timeout_prevents_the_fire() {
        let mut rt = crate::Runtime::new();
        let js = r#"
            (async () => {
                let fired = false;
                const id = setTimeout(() => { fired = true; }, 0);
                clearTimeout(id);
                await new Promise(r => setTimeout(r, 10));
                return fired;
            })()
        "#;
        let out = rt.eval(js).expect("clearTimeout eval resolves");
        assert_eq!(out, serde_json::json!(false));
    }

    #[test]
    fn timer_interval_repeats_until_cleared() {
        let mut rt = crate::Runtime::new();
        let js = r#"
            (async () => {
                let count = 0;
                const id = setInterval(() => { count += 1; if (count >= 3) clearInterval(id); }, 1);
                await new Promise(r => setTimeout(r, 50));
                return count;
            })()
        "#;
        let out = rt.eval(js).expect("interval eval resolves");
        assert_eq!(out, serde_json::json!(3));
    }

    #[test]
    fn timer_throwing_callback_does_not_break_the_pump() {
        // A timer that throws must not poison the eval — later timers still
        // fire and the tracked promise still settles.
        let mut rt = crate::Runtime::new();
        let js = r#"
            (async () => {
                const seen = [];
                setTimeout(() => { seen.push('first'); throw new Error('boom'); }, 0);
                setTimeout(() => seen.push('second'), 1);
                await new Promise(r => setTimeout(r, 20));
                return seen;
            })()
        "#;
        let out = rt.eval(js).expect("throwing-timer eval resolves");
        assert_eq!(out, serde_json::json!(["first", "second"]));
    }

    // ── storage ───────────────────────────────────────────────────────────

    #[test]
    fn storage_round_trips_and_coerces_to_strings() {
        let mut rt = crate::Runtime::new();
        let js = r#"
            (async () => {
                localStorage.setItem('n', 42);
                localStorage.setItem('undef', undefined);
                sessionStorage.setItem('shadow', 'session-wins');
                localStorage.setItem('shadow', 'local-loses');
                const out = {
                    n: localStorage.getItem('n'),
                    nType: typeof localStorage.getItem('n'),
                    undef: localStorage.getItem('undef'),
                    length: localStorage.length,
                    session: sessionStorage.getItem('shadow'),
                    local: localStorage.getItem('shadow'),
                    missing: localStorage.getItem('nope'),
                };
                localStorage.removeItem('n');
                out.afterRemove = localStorage.getItem('n');
                out.removeLength = localStorage.length;
                return out;
            })()
        "#;
        let out = rt.eval(js).expect("storage eval resolves");
        assert_eq!(out["n"], serde_json::json!("42"));
        assert_eq!(out["nType"], serde_json::json!("string"));
        assert_eq!(out["undef"], serde_json::json!("undefined"));
        assert_eq!(out["length"], serde_json::json!(3));
        assert_eq!(out["session"], serde_json::json!("session-wins"));
        assert_eq!(out["local"], serde_json::json!("local-loses"));
        assert_eq!(out["missing"], serde_json::json!(null));
        assert_eq!(out["afterRemove"], serde_json::json!(null));
        assert_eq!(out["removeLength"], serde_json::json!(2));
    }

    #[test]
    fn storage_persists_across_evals_on_the_same_page() {
        // The Arc-shared maps are the persistence layer: eval 2 sees what
        // eval 1 stored, unlike JS state (fresh context per eval).
        let mut rt = crate::Runtime::new();
        let page = Page::new("https://example.test/", "<html></html>");
        let js1 = "localStorage.setItem('token', 'abc123'); 'stored'";
        let first = rt.eval_with_page(Some(&page), js1).expect("set eval runs");
        assert_eq!(first, serde_json::json!("stored"));
        let js2 = r#"
            (async () => ({
                token: localStorage.getItem('token'),
                length: localStorage.length,
                key0: localStorage.key(0),
            }))()
        "#;
        let second = rt.eval_with_page(Some(&page), js2).expect("get eval runs");
        assert_eq!(second["token"], serde_json::json!("abc123"));
        assert_eq!(second["length"], serde_json::json!(1));
        assert_eq!(second["key0"], serde_json::json!("token"));
    }

    #[test]
    fn storage_clear_empties_the_area() {
        let mut rt = crate::Runtime::new();
        let js = r#"
            (async () => {
                localStorage.setItem('a', '1');
                localStorage.setItem('b', '2');
                localStorage.clear();
                return { length: localStorage.length, a: localStorage.getItem('a') };
            })()
        "#;
        let out = rt.eval(js).expect("clear eval resolves");
        assert_eq!(out["length"], serde_json::json!(0));
        assert_eq!(out["a"], serde_json::json!(null));
    }

    // ── location / performance ────────────────────────────────────────────

    #[test]
    fn location_reports_full_url_parts() {
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "http://127.0.0.1:8080/path?q=1#frag",
            "<html><head><title>t</title></head></html>",
        );
        let js = r#"
            (async () => ({
                href: location.href,
                protocol: location.protocol,
                host: location.host,
                hostname: location.hostname,
                port: location.port,
                pathname: location.pathname,
                search: location.search,
                hash: location.hash,
                origin: location.origin,
                str: String(location),
                docLoc: document.location === location,
                assignable: typeof location.assign === 'function',
            }))()
        "#;
        let out = rt.eval_with_page(Some(&page), js).expect("location eval runs");
        assert_eq!(out["href"], serde_json::json!("http://127.0.0.1:8080/path?q=1#frag"));
        assert_eq!(out["protocol"], serde_json::json!("http:"));
        assert_eq!(out["host"], serde_json::json!("127.0.0.1:8080"));
        assert_eq!(out["hostname"], serde_json::json!("127.0.0.1"));
        assert_eq!(out["port"], serde_json::json!("8080"));
        assert_eq!(out["pathname"], serde_json::json!("/path"));
        assert_eq!(out["search"], serde_json::json!("?q=1"));
        assert_eq!(out["hash"], serde_json::json!("#frag"));
        assert_eq!(out["origin"], serde_json::json!("http://127.0.0.1:8080"));
        assert_eq!(out["str"], serde_json::json!("http://127.0.0.1:8080/path?q=1#frag"));
        assert_eq!(out["docLoc"], serde_json::json!(true));
        assert_eq!(out["assignable"], serde_json::json!(true));
    }

    // ---- Iteration 24: in-session navigation-state honesty ---------------
    // `location` was a bag of plain data props: assigning `location.href`
    // rewrote ONLY href (host/pathname stayed stale and State.page_url never
    // moved, so relative fetch() kept resolving against the OLD page), and
    // `window.location = url` REPLACED the object with a string, destroying
    // the whole API. Every read now derives from State.page_url (the single
    // source of truth) and every assignment navigates in-session, Chrome
    // semantics. No document load ever happens at this tier (se-serve's
    // goto owns loads), and fetch() re-guards at entry (bug 28) — the
    // composition pin below proves a corrupted base can't smuggle a dial.

    #[test]
    fn location_href_assignment_rewrites_all_props() {
        let mut rt = crate::Runtime::new();
        let page = Page::new("http://127.0.0.1:8080/old", "<html><body>s</body></html>");
        let js = r#"
            (async () => {
                location.href = 'http://example.com:8080/a/b?x=1#y';
                return {
                    href: location.href,
                    host: location.host,
                    hostname: location.hostname,
                    port: location.port,
                    pathname: location.pathname,
                    search: location.search,
                    hash: location.hash,
                    origin: location.origin,
                    str: String(location),
                };
            })()
        "#;
        let out = rt.eval_with_page(Some(&page), js).expect("href= eval runs");
        assert_eq!(out["href"], serde_json::json!("http://example.com:8080/a/b?x=1#y"));
        assert_eq!(out["host"], serde_json::json!("example.com:8080"));
        assert_eq!(out["hostname"], serde_json::json!("example.com"));
        assert_eq!(out["port"], serde_json::json!("8080"));
        assert_eq!(out["pathname"], serde_json::json!("/a/b"));
        assert_eq!(out["search"], serde_json::json!("?x=1"));
        assert_eq!(out["hash"], serde_json::json!("#y"));
        assert_eq!(out["origin"], serde_json::json!("http://example.com:8080"));
        assert_eq!(out["str"], serde_json::json!("http://example.com:8080/a/b?x=1#y"));
    }

    #[test]
    fn eval_with_nav_reports_a_timer_scheduled_navigation() {
        // The render-follow seam (se-serve render_tab): the navigated-to URL
        // must be read from State.page_url AFTER the settle pump — a
        // setTimeout-scheduled location.href= hasn't landed when the
        // script's completion value is computed. This pins that the nav
        // variant reports the post-pump truth (and that the pump runs for a
        // plain-value script that scheduled a timer). Nothing dials:
        // page_url moves are inert state.
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "http://example.test/dir/shell",
            "<html><body><div id=\"root\"></div></body></html>",
        );
        let js = "setTimeout(function () { location.href = 'target'; }, 0); 'shell evaluated'";
        let (out, nav) = rt.eval_with_page_with_nav(
            Some(&page),
            js,
            std::time::Duration::from_secs(5),
        );
        assert_eq!(out.expect("eval runs"), serde_json::json!("shell evaluated"));
        assert_eq!(nav.as_deref(), Some("http://example.test/dir/target"));

        // No navigation: the reported URL is the page's own, unchanged.
        let (out, nav) = rt.eval_with_page_with_nav(
            Some(&page),
            "1 + 1",
            std::time::Duration::from_secs(5),
        );
        assert_eq!(out.expect("eval runs"), serde_json::json!(2));
        assert_eq!(nav.as_deref(), Some("http://example.test/dir/shell"));

        // No page bound: no URL to report.
        let (_, nav) = rt.eval_with_page_with_nav(None, "1 + 1", std::time::Duration::from_secs(5));
        assert_eq!(nav, None);
    }

    #[test]
    fn location_href_assignment_moves_the_fetch_base() {
        // The fixture answers 200 ONLY at /base/rel.json: a shim whose
        // page_url didn't move fetches /rel.json and sees 418.
        let base = spawn_server(1, |path, _| {
            if path == "/base/rel.json" {
                (200, "{}".to_string())
            } else {
                (418, "wrong base".to_string())
            }
        });
        let mut rt = crate::Runtime::new();
        let page = Page::new(format!("{base}/page"), "<html><body>s</body></html>");
        let js = format!(
            "(async () => {{ location.href = '{base}/base/'; const r = await fetch('rel.json'); return r.status; }})()"
        );
        let out = rt
            .eval_with_page(Some(&page), &js)
            .expect("href= + fetch eval runs");
        assert_eq!(out, serde_json::json!(200));
    }

    #[test]
    fn location_href_to_a_refused_target_relative_fetch_still_refuses() {
        // Guard composition: href= can put a refused URL into page_url (no
        // load happens, so no guard fires THERE), but a relative fetch
        // against that base must still hit the bug-28 entry check.
        let mut rt = crate::Runtime::new();
        let page = Page::new("http://127.0.0.1:1/page", "<html><body>s</body></html>");
        let js = "(async () => { location.href = 'http://169.254.169.254/'; await fetch('/latest/meta-data'); return 'unreached'; })()";
        let err = rt.eval_with_page(Some(&page), js).unwrap_err();
        assert!(
            err.to_string().contains("target_refused"),
            "relative fetch against a refused base must reject target_refused, got: {err}"
        );
    }

    #[test]
    fn window_location_assignment_navigates_instead_of_destroying() {
        // Chrome: assigning window.location navigates (the object is
        // unforgeable). Pre-fix the plain prop let a string REPLACE the
        // object — every later location read broke.
        let mut rt = crate::Runtime::new();
        let page = Page::new("http://127.0.0.1:8080/old", "<html><body>s</body></html>");
        let js = r#"
            (async () => {
                window.location = 'http://example.com/next';
                return [typeof location, location.href, typeof location.assign, document.location === location];
            })()
        "#;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("window.location= eval runs");
        assert_eq!(out[0], serde_json::json!("object"));
        assert_eq!(out[1], serde_json::json!("http://example.com/next"));
        assert_eq!(out[2], serde_json::json!("function"));
        assert_eq!(out[3], serde_json::json!(true));
    }

    #[test]
    fn location_component_setters_navigate() {
        // Per spec the writable components navigate with that component
        // substituted; origin stays read-only.
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "http://127.0.0.1:8080/old/path?a=1#f",
            "<html><body>s</body></html>",
        );
        let js = r#"
            (async () => {
                location.pathname = '/deep/space';
                const afterPath = location.href;
                location.hash = 'zz';
                const afterHash = location.href;
                return [afterPath, afterHash];
            })()
        "#;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("component setters eval runs");
        assert_eq!(
            out[0],
            serde_json::json!("http://127.0.0.1:8080/deep/space?a=1#f")
        );
        assert_eq!(
            out[1],
            serde_json::json!("http://127.0.0.1:8080/deep/space?a=1#zz")
        );
    }

    #[test]
    fn window_open_returns_null_like_a_blocked_popup() {
        // The shim is always gesture-less; real Chrome answers a
        // gesture-less window.open with null (popup blocked). The stub
        // must exist and return exactly that — an absent function is a
        // TypeError, a shape no real page sees.
        let mut rt = crate::Runtime::new();
        let page = Page::new("http://127.0.0.1:8080/old", "<html><body>s</body></html>");
        let js = "(async () => [typeof window.open, typeof window.open === 'function' ? window.open('http://x/') : 'MISSING'])()";
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("window.open eval runs");
        assert_eq!(out[0], serde_json::json!("function"));
        assert_eq!(out[1], serde_json::Value::Null);
    }

    #[test]
    fn location_href_assignment_pushes_history() {
        let mut rt = crate::Runtime::new();
        let page = Page::new("http://127.0.0.1:8080/old", "<html><body>s</body></html>");
        let js = r#"
            (async () => {
                const before = history.length;
                location.href = '/a';
                location.href = '/b';
                return [before, history.length, location.pathname];
            })()
        "#;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("href= history eval runs");
        assert_eq!(out[0], serde_json::json!(1));
        assert_eq!(out[1], serde_json::json!(3));
        assert_eq!(out[2], serde_json::json!("/b"));
    }

    #[test]
    fn performance_answers_now_and_time_origin() {
        let mut rt = crate::Runtime::new();
        let js = r#"
            (async () => {
                const t0 = performance.now();
                await new Promise(r => setTimeout(r, 2));
                const t1 = performance.now();
                return {
                    t0Number: typeof t0 === 'number',
                    advanced: t1 > t0,
                    originType: typeof performance.timeOrigin,
                    epochish: performance.timeOrigin > 1_700_000_000_000,
                };
            })()
        "#;
        let out = rt.eval(js).expect("performance eval resolves");
        assert_eq!(out["t0Number"], serde_json::json!(true));
        assert_eq!(out["advanced"], serde_json::json!(true));
        assert_eq!(out["originType"], serde_json::json!("number"));
        assert_eq!(out["epochish"], serde_json::json!(true));
    }

    // ── session-bound fetch ───────────────────────────────────────────────

    #[test]
    fn session_bound_fetch_sends_jar_cookies_and_writes_back_set_cookie() {
        // The browser contract: a page-context request presents the session
        // jar on same-origin calls, and a response Set-Cookie feeds the jar
        // the way a document request would — so the NEXT request carries it.
        let store = std::sync::Arc::new(se_net::SessionStore::default());
        let base = spawn_server_with_headers(2, |path, req| match path {
            "/set" => (
                200,
                "ok".to_string(),
                vec![("Set-Cookie".to_string(), "sid=abc123; Path=/".to_string())],
            ),
            "/echo" => {
                // Answer with the raw request head; the test asserts the
                // cookie the server observed. Match the pair value, not the
                // header prefix — jar cookie order is HashMap-iter order
                // (nondeterministic across runs), so another seeded cookie
                // may precede this one in the header.
                let seen = if req.contains("sid=abc123") {
                    "carried"
                } else {
                    "missing"
                };
                (200, seen.to_string(), Vec::new())
            }
            _ => (200, "other".to_string(), Vec::new()),
        });
        // Seed the jar with a same-origin cookie, the way storage_state_set
        // would for a logged-in session.
        let mut entry = se_net::CookieEntry::new("pref", "dark");
        entry.domain = "127.0.0.1".to_string();
        assert!(store.insert_entry(&entry));
        // A foreign-domain cookie must never ride this request.
        let mut foreign = se_net::CookieEntry::new("evil", "no");
        foreign.domain = "example.com".to_string();
        assert!(store.insert_entry(&foreign));

        let page = Page {
            cookie_store: Some(store.clone()),
            ..Page::new(format!("{base}/page"), "<html><body>shell</body></html>")
        };
        let js = r#"
            (async () => {
                // r.text is a raw host function: thread a [resolve, reject]
                // pair like the fetch trampoline does.
                const r1 = await fetch('/set');
                const t1 = await new Promise((res, rej) => r1.text([res, rej]));
                const r2 = await fetch('/echo');
                const t2 = await new Promise((res, rej) => r2.text([res, rej]));
                return { first: t1, second: t2 };
            })()
        "#;
        let mut rt = crate::Runtime::new();
        let out = rt.eval_with_page(Some(&page), js).expect("session fetch resolves");
        assert_eq!(out["first"], serde_json::json!("ok"));
        assert_eq!(out["second"], serde_json::json!("carried"));
        // The response Set-Cookie landed in the live jar.
        let snap = store.snapshot();
        assert!(
            snap.iter().any(|c| c.name == "sid" && c.value == "abc123"),
            "set-cookie written back: {snap:?}"
        );
    }

    #[test]
    fn session_bound_xhr_sends_jar_cookies() {
        // XHR rides the same blocking_fetch, so the same jar wiring covers
        // `var x = new XMLHttpRequest(); x.open('GET', u, false); x.send()`.
        let store = std::sync::Arc::new(se_net::SessionStore::default());
        let base = spawn_server(1, |_path, req| {
            // Match the cookie pair value, not the header prefix — the jar's
            // cookie order is nondeterministic when more than one matches.
            let seen = if req.contains("sess=xyz") {
                "carried"
            } else {
                "missing"
            };
            (200, seen.to_string())
        });
        let mut entry = se_net::CookieEntry::new("sess", "xyz");
        entry.domain = "127.0.0.1".to_string();
        assert!(store.insert_entry(&entry));

        let page = Page {
            cookie_store: Some(store),
            ..Page::new(format!("{base}/page"), "<html><body>shell</body></html>")
        };
        let js = r#"
            (function() {
                var x = new XMLHttpRequest();
                x.open('GET', '/echo', false);
                x.send();
                return x.responseText;
            })()
        "#;
        let mut rt = crate::Runtime::new();
        let out = rt.eval_with_page(Some(&page), js).expect("xhr eval runs");
        assert_eq!(out, serde_json::json!("carried"));
    }

    #[test]
    fn document_cookie_reads_and_writes_the_session_jar() {
        // The visibility contract: httpOnly cookies never show in page JS;
        // a page-written cookie lands in the live jar and rides the next
        // same-origin request — exactly the document-request semantics a
        // consent-check or session-marker read depends on.
        let store = std::sync::Arc::new(se_net::SessionStore::default());
        let base = spawn_server(1, |_path, req| {
            let saw = req.contains("js_set=frompage");
            (200, if saw { "carried" } else { "missing" }.to_string())
        });
        let mut seed = se_net::CookieEntry::new("seed", "abc");
        seed.domain = "127.0.0.1".to_string();
        assert!(store.insert_entry(&seed));
        let mut hidden = se_net::CookieEntry::new("hid", "1");
        hidden.domain = "127.0.0.1".to_string();
        hidden.http_only = true;
        assert!(store.insert_entry(&hidden));

        let page = Page {
            cookie_store: Some(store.clone()),
            ..Page::new(format!("{base}/page"), "<html><body>shell</body></html>")
        };
        let js = r#"
            (async () => {
                const before = document.cookie;
                document.cookie = 'js_set=frompage; Path=/; Max-Age=3600';
                const after = document.cookie;
                const r = await fetch('/echo');
                const t = await new Promise((res, rej) => r.text([res, rej]));
                return { before, after, wire: t };
            })()
        "#;
        let mut rt = crate::Runtime::new();
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("document.cookie eval runs");
        let before = out["before"].as_str().unwrap_or("");
        assert!(before.contains("seed=abc"), "seed visible: {before}");
        assert!(!before.contains("hid="), "httpOnly leaked: {before}");
        let after = out["after"].as_str().unwrap_or("");
        assert!(after.contains("js_set=frompage"), "write visible: {after}");
        assert_eq!(
            out["wire"],
            serde_json::json!("carried"),
            "page-written cookie must ride the next same-origin request"
        );
    }

    #[test]
    fn document_cookie_without_a_jar_is_empty_and_inert() {
        // Standalone pages (no jar wired) keep the anonymous default:
        // reading is "" and writing is a silent no-op, never a throw.
        let mut rt = crate::Runtime::new();
        let page = Page::new("http://127.0.0.1:9/page", "<html></html>");
        let out = rt
            .eval_with_page(
                Some(&page),
                "document.cookie = 'noop=1'; document.cookie",
            )
            .expect("standalone cookie eval runs");
        assert_eq!(out, serde_json::json!(""));
    }

    #[test]
    fn page_fetch_presents_subresource_fetch_metadata() {
        // The page-context request must look like a browser XHR, not a bare
        // GET: client hints + Fetch Metadata (dest empty, mode cors), the
        // engine UA, */* Accept — and crucially NOT the navigation markers
        // (Upgrade-Insecure-Requests, Sec-Fetch-User) the goto client sends.
        // The request line also preserves the query string.
        let base = spawn_server(1, |path, req| {
            // The query rides the request target (Url::path would drop it).
            assert_eq!(path, "/api?x=1", "query lost from the request line: {path}");
            let mut seen: Vec<&str> = Vec::new();
            for (needle, label) in [
                ("sec-ch-ua: \"Chromium\";v=\"145\"", "chua"),
                ("sec-ch-ua-mobile: ?0", "chmobile"),
                ("sec-ch-ua-platform: \"Windows\"", "chplatform"),
                ("Sec-Fetch-Dest: empty", "sfdest"),
                ("Sec-Fetch-Mode: cors", "sfmode"),
                ("Sec-Fetch-Site: same-origin", "sfsite"),
                ("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "ua"),
                ("Accept: */*", "accept"),
                ("Accept-Language: en-US,en;q=0.9", "lang"),
            ] {
                if req.contains(needle) {
                    seen.push(label);
                }
            }
            assert!(
                !req.to_ascii_lowercase().contains("upgrade-insecure-requests"),
                "navigation marker leaked into a subresource request: {req}"
            );
            assert!(
                !req.contains("Sec-Fetch-User"),
                "navigation marker leaked into a subresource request: {req}"
            );
            (200, seen.join(","))
        });
        let page = Page::new(format!("{base}/page"), "<html><body>shell</body></html>");
        let js = r#"
            (async () => {
                const r = await fetch('/api?x=1');
                return await new Promise((res, rej) => r.text([res, rej]));
            })()
        "#;
        let mut rt = crate::Runtime::new();
        let out = rt.eval_with_page(Some(&page), js).expect("fetch metadata eval runs");
        let got = out.as_str().unwrap_or("");
        for want in ["chua", "chmobile", "chplatform", "sfdest", "sfmode", "sfsite", "ua", "accept", "lang"] {
            assert!(got.contains(want), "missing {want}; server saw: {got}");
        }
    }

    #[test]
    fn document_referrer_reflects_the_navigation_initiator() {
        // A followed navigation leaves the previous page's URL in
        // document.referrer; an address-bar load leaves it empty. The value
        // travels with Page.referrer (se-serve fills it from the tab).
        let mut page = Page::new(
            "http://127.0.0.1:9/here",
            "<html><head><title>t</title></head><body>x</body></html>",
        );
        page.referrer = "http://127.0.0.1:9/prev".to_string();
        let mut rt = crate::Runtime::new();
        let out = rt
            .eval_with_page(Some(&page), "document.referrer")
            .expect("referrer eval runs");
        assert_eq!(out, serde_json::json!("http://127.0.0.1:9/prev"));

        let page = Page::new(
            "http://127.0.0.1:9/here",
            "<html><head><title>t</title></head><body>x</body></html>",
        );
        let mut rt = crate::Runtime::new();
        let out = rt
            .eval_with_page(Some(&page), "document.referrer")
            .expect("empty referrer eval runs");
        assert_eq!(out, serde_json::json!(""));
    }

    #[test]
    fn page_fetch_post_sends_method_body_and_content_length() {
        // fetch(url, {method, body}) is the GraphQL idiom: the request line
        // must say POST, the body must follow the head, Content-Length must
        // match, and the string-body default content type applies. The
        // subresource signature from the GET tests must ride along.
        let base = spawn_server(1, |path, req| {
            assert_eq!(path, "/api", "POST target: {path}");
            assert!(
                req.starts_with("POST /api HTTP/1.1"),
                "request line must be POST: {}",
                req.lines().next().unwrap_or("")
            );
            let lower = req.to_ascii_lowercase();
            assert!(
                lower.contains("content-length: 11"),
                "Content-Length must match the body: {lower}"
            );
            assert!(
                lower.contains("content-type: text/plain;charset=utf-8"),
                "string-body default content type: {lower}"
            );
            assert!(req.contains("hello world"), "body after the head: {req}");
            assert!(
                req.contains("Sec-Fetch-Dest: empty"),
                "subresource signature rides along: {req}"
            );
            (200, "ok".to_string())
        });
        let page = Page::new(format!("{base}/page"), "<html><body>shell</body></html>");
        let js = r#"
            (async () => {
                const r = await fetch('/api', { method: 'POST', body: 'hello world' });
                return await new Promise((res, rej) => r.text([res, rej]));
            })()
        "#;
        let mut rt = crate::Runtime::new();
        let out = rt.eval_with_page(Some(&page), js).expect("POST fetch resolves");
        assert_eq!(out, serde_json::json!("ok"));
    }

    #[test]
    fn fetch_init_headers_merge_over_the_subresource_defaults() {
        // init.headers: a new name appends; a default's name REPLACES it
        // (one Accept on the wire, the caller's value). Headers instances
        // normalize names to lowercase via forEach — a plain object works too.
        let base = spawn_server(1, |_path, req| {
            assert!(
                req.contains("X-Test: yes"),
                "caller header appended verbatim: {req}"
            );
            assert!(
                req.contains("Accept: application/json"),
                "caller Accept replaced the default: {req}"
            );
            assert!(
                !req.contains("Accept: */*"),
                "default Accept must be replaced, not duplicated: {req}"
            );
            (200, "ok".to_string())
        });
        let page = Page::new(format!("{base}/page"), "<html><body>shell</body></html>");
        let js = r#"
            (async () => {
                const r = await fetch('/api', { headers: { 'X-Test': 'yes', 'Accept': 'application/json' } });
                return await new Promise((res, rej) => r.text([res, rej]));
            })()
        "#;
        let mut rt = crate::Runtime::new();
        let out = rt.eval_with_page(Some(&page), js).expect("header merge fetch resolves");
        assert_eq!(out, serde_json::json!("ok"));
    }

    #[test]
    fn xhr_post_sends_method_body_and_set_request_headers() {
        // The synchronous XHR idiom with a body — FB's GraphQL extraction
        // shape. open records the method, setRequestHeader accumulates,
        // send(body) delivers both on the wire.
        let base = spawn_server(1, |path, req| {
            assert_eq!(path, "/api", "XHR POST target: {path}");
            assert!(
                req.starts_with("POST /api HTTP/1.1"),
                "request line must be POST: {}",
                req.lines().next().unwrap_or("")
            );
            assert!(req.contains("X-Actor: se"), "setRequestHeader value: {req}");
            assert!(req.contains("q=1"), "XHR body after the head: {req}");
            (200, "done".to_string())
        });
        let page = Page::new(format!("{base}/page"), "<html><body>shell</body></html>");
        let js = r#"
            (function() {
                var x = new XMLHttpRequest();
                x.open('POST', '/api', false);
                x.setRequestHeader('X-Actor', 'se');
                x.send('q=1');
                return x.responseText;
            })()
        "#;
        let mut rt = crate::Runtime::new();
        let out = rt.eval_with_page(Some(&page), js).expect("xhr POST eval runs");
        assert_eq!(out, serde_json::json!("done"));
    }

    #[test]
    fn page_fetch_follows_redirects_with_fetch_spec_rewrite_rules() {
        // 302 rewrites POST to GET (body + entity headers dropped), 307
        // preserves method and body; Location resolves against the request
        // URL and `response.url` reports the final address. Four
        // connections: POST /start, rewritten GET /landed, POST /keep,
        // preserved POST /kept.
        let base = spawn_server_with_headers(4, |path, req| {
            match path {
                "/start" => {
                    assert!(
                        req.starts_with("POST /start HTTP/1.1"),
                        "first hop must be POST: {}",
                        req.lines().next().unwrap_or("")
                    );
                    assert!(req.contains("q=1"), "first hop body: {req}");
                    (302, String::new(), vec![("Location".into(), "/landed".into())])
                }
                "/landed" => {
                    assert!(
                        req.starts_with("GET /landed HTTP/1.1"),
                        "302 must rewrite POST to GET: {}",
                        req.lines().next().unwrap_or("")
                    );
                    assert!(
                        !req.to_ascii_lowercase().contains("content-length:"),
                        "rewritten GET must not carry entity headers: {req}"
                    );
                    (200, "landed-get".to_string(), Vec::new())
                }
                "/keep" => {
                    assert!(
                        req.starts_with("POST /keep HTTP/1.1"),
                        "307 hop keeps POST: {}",
                        req.lines().next().unwrap_or("")
                    );
                    (307, String::new(), vec![("Location".into(), "/kept".into())])
                }
                "/kept" => {
                    assert!(
                        req.starts_with("POST /kept HTTP/1.1"),
                        "307 lands with method preserved: {}",
                        req.lines().next().unwrap_or("")
                    );
                    assert!(req.contains("q=1"), "307 lands with body preserved: {req}");
                    (200, "kept-post".to_string(), Vec::new())
                }
                other => panic!("unexpected path {other}"),
            }
        });
        let page = Page::new(format!("{base}/page"), "<html><body>shell</body></html>");
        let js = r#"
            (async () => {
                const read = (r) => new Promise((res, rej) => r.text([res, rej]));
                const a = await fetch('/start', { method: 'POST', body: 'q=1' });
                const at = await read(a);
                const b = await fetch('/keep', { method: 'POST', body: 'q=1' });
                const bt = await read(b);
                return {
                    a_status: a.status, a_url: a.url, a_text: at,
                    b_status: b.status, b_url: b.url, b_text: bt,
                };
            })()
        "#;
        let mut rt = crate::Runtime::new();
        let out = rt.eval_with_page(Some(&page), js).expect("redirect eval runs");
        assert_eq!(out["a_status"], serde_json::json!(200));
        assert!(out["a_url"].as_str().unwrap_or("").ends_with("/landed"), "a_url: {out}");
        assert_eq!(out["a_text"], serde_json::json!("landed-get"));
        assert_eq!(out["b_status"], serde_json::json!(200));
        assert!(
            out["b_url"].as_str().unwrap_or("").ends_with("/kept"),
            "b_url: {out}"
        );
        assert_eq!(out["b_text"], serde_json::json!("kept-post"));
    }

    #[test]
    fn fetch_response_read_side_matches_browser_parity() {
        // The idioms real pages use to read a response: r.json(), a bare
        // `await r.text()` (the standard read shape — caught live returning
        // undefined before the dual-mode wrapper), and headers.get/has/
        // forEach/entries with case-insensitive names. The pair snapshot
        // must be taken BEFORE the methods attach (entries' first pair is
        // a wire header, not a function prop). Two fetches: one read idiom
        // each (the shim's contract is sequential fetches, one in flight).
        let base = spawn_server_with_headers(2, |path, _| {
            assert_eq!(path, "/api");
            (
                200,
                r#"{"n":42,"s":"hi"}"#.to_string(),
                vec![
                    ("Content-Type".into(), "application/json".into()),
                    ("X-Edge".into(), "edge-1".into()),
                ],
            )
        });
        let page = Page::new(format!("{base}/page"), "<html><body>shell</body></html>");
        let js = r#"
            (async () => {
                const r = await fetch('/api');
                const data = await r.json();
                // The other idiom real pages use: a bare `await r.text()`.
                // A second fetch keeps the two reads independent (one fetch
                // per eval is the shim's contract).
                const r2 = await fetch('/api');
                const t = await r2.text();
                const seen = [];
                r.headers.forEach((v, k) => seen.push(k + '=' + v));
                const it = r.headers.entries();
                const first = it.next().value;
                return {
                    n: data.n,
                    s: data.s,
                    ct: r.headers.get('content-type'),
                    ctCase: r.headers.get('Content-Type'),
                    edge: r.headers.get('x-edge'),
                    missing: r.headers.get('nope'),
                    has: r.headers.has('x-edge'),
                    hasNot: r.headers.has('nope'),
                    forEachHasEdge: seen.indexOf('x-edge=edge-1') !== -1,
                    forEachHasCt: seen.indexOf('content-type=application/json') !== -1,
                    entryKey: first ? first[0] : null,
                    entryVal: first ? first[1] : null,
                };
            })()
        "#;
        let mut rt = crate::Runtime::new();
        let out = rt.eval_with_page(Some(&page), js).expect("read-side eval runs");
        assert_eq!(out["n"], serde_json::json!(42));
        assert_eq!(out["s"], serde_json::json!("hi"));
        assert_eq!(out["ct"], serde_json::json!("application/json"));
        assert_eq!(out["ctCase"], serde_json::json!("application/json"));
        assert_eq!(out["edge"], serde_json::json!("edge-1"));
        assert_eq!(out["missing"], serde_json::json!(null));
        assert_eq!(out["has"], serde_json::json!(true));
        assert_eq!(out["hasNot"], serde_json::json!(false));
        assert_eq!(out["forEachHasEdge"], serde_json::json!(true));
        assert_eq!(out["forEachHasCt"], serde_json::json!(true));
        // entries()' first pair is a real wire header (content-length leads
        // the test server's head) — proving the snapshot predates the
        // method props.
        assert_eq!(out["entryKey"], serde_json::json!("content-length"));
        assert!(out["entryVal"].as_str().unwrap_or("").chars().all(|c| c.is_ascii_digit()), "entryVal: {out}");
    }

    #[test]
    fn xhr_response_headers_are_readable() {
        // getResponseHeader (case-insensitive, null when absent) and
        // getAllResponseHeaders (CRLF-joined wire pairs) — the XHR read-side
        // contract FB's own GraphQL callers rely on.
        let base = spawn_server_with_headers(1, |path, _| {
            assert_eq!(path, "/api");
            (
                200,
                "payload".to_string(),
                vec![
                    ("X-Edge".into(), "edge-1".into()),
                    ("Content-Type".into(), "text/plain".into()),
                ],
            )
        });
        let page = Page::new(format!("{base}/page"), "<html><body>shell</body></html>");
        let js = r#"
            (function() {
                var x = new XMLHttpRequest();
                x.open('GET', '/api', false);
                x.send();
                return {
                    one: x.getResponseHeader('X-Edge'),
                    miss: x.getResponseHeader('X-Nope'),
                    status: x.status,
                    text: x.responseText,
                    all: x.getAllResponseHeaders(),
                };
            })()
        "#;
        let mut rt = crate::Runtime::new();
        let out = rt.eval_with_page(Some(&page), js).expect("xhr header eval runs");
        assert_eq!(out["one"], serde_json::json!("edge-1"));
        assert_eq!(out["miss"], serde_json::json!(null));
        assert_eq!(out["status"], serde_json::json!(200));
        assert_eq!(out["text"], serde_json::json!("payload"));
        let all = out["all"].as_str().unwrap_or("");
        assert!(all.contains("x-edge: edge-1"), "all: {all}");
        assert!(all.contains("content-type: text/plain"), "all: {all}");
        assert!(all.contains("\r\n"), "CRLF-joined: {all}");
    }

    #[test]
    fn cookieless_page_fetch_stays_cookieless() {
        // Standalone pages (no jar wired) keep the old bare-HTTP behavior —
        // the wiring is opt-in via Page.cookie_store, so nothing leaks by
        // accident.
        let base = spawn_server(1, |_path, req| {
            let seen = if req.to_ascii_lowercase().contains("cookie:") {
                "had-cookie-header"
            } else {
                "clean"
            };
            (200, seen.to_string())
        });
        let page = Page::new(format!("{base}/page"), "<html><body>shell</body></html>");
        let js = "(async () => { const r = await fetch('/echo'); return await new Promise((res, rej) => r.text([res, rej])); })()";
        let mut rt = crate::Runtime::new();
        let out = rt.eval_with_page(Some(&page), js).expect("fetch resolves");
        assert_eq!(out, serde_json::json!("clean"));
    }

    #[test]
    fn user_agent_data_high_entropy_values_resolve() {
        // getHighEntropyValues returns a promise the eval pump drains; the
        // answers must be the SAME se-net constants the Sec-CH-UA wire
        // headers are built from (cross-surface consistency).
        let mut rt = crate::Runtime::new();
        let js = r#"
            (async () => {
                const h = await navigator.userAgentData.getHighEntropyValues([
                    'architecture', 'bitness', 'platform', 'platformVersion',
                    'uaFullVersion', 'mobile', 'model', 'formFactor', 'wow64',
                    'brands', 'fullVersionList',
                ]);
                const one = await navigator.userAgentData.getHighEntropyValues(['bitness']);
                return {
                    architecture: h.architecture,
                    bitness: h.bitness,
                    platform: h.platform,
                    platformVersion: h.platformVersion,
                    uaFullVersion: h.uaFullVersion,
                    mobile: h.mobile,
                    model: h.model,
                    formFactor: h.formFactor,
                    wow64: h.wow64,
                    brands: h.brands.map(b => b.brand + '/' + b.version).join('|'),
                    full: h.fullVersionList.map(b => b.brand + '/' + b.version).join('|'),
                    // per spec, only the requested hint comes back
                    singleKeys: Object.keys(one).join(','),
                };
            })()
        "#;
        let out = rt.eval(js).expect("high-entropy eval resolves");
        assert_eq!(out["architecture"], serde_json::json!("x86"));
        assert_eq!(out["bitness"], serde_json::json!("64"));
        assert_eq!(out["platform"], serde_json::json!("Windows"));
        assert_eq!(out["platformVersion"], serde_json::json!("10.0.0"));
        assert_eq!(out["uaFullVersion"], serde_json::json!("145.0.0.0"));
        assert_eq!(out["mobile"], serde_json::json!(false));
        assert_eq!(out["model"], serde_json::json!(""));
        assert_eq!(out["formFactor"], serde_json::json!("Desktop"));
        assert_eq!(out["wow64"], serde_json::json!(false));
        assert_eq!(
            out["brands"],
            serde_json::json!("Chromium/145|Google Chrome/145|Not.A/Brand/99")
        );
        assert_eq!(
            out["full"],
            serde_json::json!("Chromium/145.0.0.0|Google Chrome/145.0.0.0|Not.A/Brand/145.0.0.0")
        );
        assert_eq!(out["singleKeys"], serde_json::json!("bitness"));
    }

    /// The Facebook provider's scroll loop, verbatim shape
    /// (`providers/facebook.py::_SCROLL_JS`): walk up from a listing anchor
    /// via parentElement/getComputedStyle looking for a scrollable pane,
    /// fall back to window.scrollBy. With no layout every overflowY is
    /// "visible", so the loop must take the window branch, advance scrollY
    /// by innerHeight*3, and resolve its count — not throw.
    #[test]
    fn provider_scroll_loop_runs_verbatim_shape() {
        let html = r##"<html><body><div class="feed"><div class="card">
            <a href="/marketplace/item/111">one</a></div>
            <a href="/marketplace/item/222">two</a>
        </div></body></html>"##;
        let page = Page::new("https://www.facebook.com/marketplace".to_string(), html);
        let js = r##"
            (async () => {
                const sel = 'a[href*="/marketplace/item/"]';
                const count = () => document.querySelectorAll(sel).length;
                const anchor = document.querySelector(sel);
                let pane = null;
                for (let el = anchor; el && el !== document.documentElement; el = el.parentElement) {
                    const st = getComputedStyle(el);
                    if ((st.overflowY === 'auto' || st.overflowY === 'scroll') &&
                        el.scrollHeight > el.clientHeight + 50) { pane = el; break; }
                }
                if (pane) {
                    pane.scrollTop = Math.min(pane.scrollTop + pane.clientHeight * 2, pane.scrollHeight);
                } else {
                    window.scrollBy(0, window.innerHeight * 3);
                }
                await new Promise(r => setTimeout(r, 10));
                return { count: count(), pane: !!pane, scrollY: window.scrollY,
                         pageYOffset: window.pageYOffset };
            })()
        "##;
        let mut rt = crate::Runtime::new();
        let out = rt.eval_with_page(Some(&page), js).expect("scroll loop resolves");
        assert_eq!(out["count"], serde_json::json!(2));
        assert_eq!(out["pane"], serde_json::json!(false));
        assert_eq!(out["scrollY"], serde_json::json!(2811));
        assert_eq!(out["pageYOffset"], serde_json::json!(2811));
    }

    /// The pane branch: when getComputedStyle reports a scrollable ancestor
    /// and the geometry props say it overflows, the loop assigns scrollTop
    /// (a plain writable data prop) and does NOT touch the window position.
    #[test]
    fn provider_scroll_loop_pane_branch_assigns_scroll_top() {
        let html = r##"<html><body><div class="pane">
            <a href="/marketplace/item/111">one</a>
        </div></body></html>"##;
        let page = Page::new("https://www.facebook.com/marketplace".to_string(), html);
        let js = r##"
            (async () => {
                const sel = 'a[href*="/marketplace/item/"]';
                const anchor = document.querySelector(sel);
                getComputedStyle = (el) => ({
                    overflowY: el.classList.contains('pane') ? 'auto' : 'visible',
                });
                let pane = null;
                for (let el = anchor; el && el !== document.documentElement; el = el.parentElement) {
                    // Emulate what layout would report for the scroll
                    // container — wrappers are per-access snapshots, so the
                    // geometry rides on the instance the loop is examining.
                    if (el.classList.contains('pane')) {
                        el.scrollHeight = 1000;
                        el.clientHeight = 200;
                    }
                    const st = getComputedStyle(el);
                    if ((st.overflowY === 'auto' || st.overflowY === 'scroll') &&
                        el.scrollHeight > el.clientHeight + 50) { pane = el; break; }
                }
                if (pane) {
                    pane.scrollTop = Math.min(pane.scrollTop + pane.clientHeight * 2, pane.scrollHeight);
                } else {
                    window.scrollBy(0, window.innerHeight * 3);
                }
                await new Promise(r => setTimeout(r, 10));
                return { paneTag: pane && pane.tagName, scrollTop: pane && pane.scrollTop,
                         scrollY: window.scrollY };
            })()
        "##;
        let mut rt = crate::Runtime::new();
        let out = rt.eval_with_page(Some(&page), js).expect("pane branch resolves");
        assert_eq!(out["paneTag"], serde_json::json!("DIV"));
        assert_eq!(out["paneTag"], serde_json::json!("DIV"), "full: {out}");
        assert_eq!(out["scrollTop"], serde_json::json!(400));
        assert_eq!(out["scrollY"], serde_json::json!(0));
    }

    /// parentElement walks real ancestors to the root and stops;
    /// documentElement/body wrap the same live parse.
    #[test]
    fn parent_element_chain_and_document_accessors() {
        let html = r##"<html><body><div class="card"><span>
            <a href="/marketplace/item/111">x</a>
        </span></div></body></html>"##;
        let page = Page::new("https://www.facebook.com/marketplace".to_string(), html);
        let js = r##"
            (() => {
                const anchor = document.querySelector('a[href*="/marketplace/item/"]');
                const chain = [];
                for (let el = anchor; el; el = el.parentElement) chain.push(el.tagName);
                return {
                    chain,
                    rootTag: document.documentElement.tagName,
                    rootParent: document.documentElement.parentElement,
                    bodyTag: document.body.tagName,
                    bodyParentTag: document.body.parentElement.tagName,
                };
            })()
        "##;
        let mut rt = crate::Runtime::new();
        let out = rt.eval_with_page(Some(&page), js).expect("chain eval resolves");
        assert_eq!(
            out["chain"],
            serde_json::json!(["A", "SPAN", "DIV", "BODY", "HTML"])
        );
        assert_eq!(out["rootTag"], serde_json::json!("HTML"));
        assert_eq!(out["rootParent"], serde_json::Value::Null);
        assert_eq!(out["bodyTag"], serde_json::json!("BODY"));
        assert_eq!(out["bodyParentTag"], serde_json::json!("HTML"));
    }

    /// getComputedStyle: UA-display per tag, CSS initial values elsewhere —
    /// the honest no-layout answer.
    #[test]
    fn computed_style_reports_ua_display_and_initial_values() {
        let html = r##"<html><body><div><span>x</span><ul><li>i</li></ul></div>
            <script>var x = 1;</script>
        </body></html>"##;
        let page = Page::new("https://example.test/".to_string(), html);
        let js = r##"
            (() => {
                const cs = (s) => getComputedStyle(document.querySelector(s));
                return {
                    div: cs('div').display,
                    span: cs('span').display,
                    li: cs('li').display,
                    script: cs('script').display,
                    unknown: cs('marquee').display,
                    overflowY: cs('div').overflowY,
                    visibility: cs('div').visibility,
                    position: cs('div').position,
                };
            })()
        "##;
        let mut rt = crate::Runtime::new();
        let out = rt.eval_with_page(Some(&page), js).expect("computed style resolves");
        assert_eq!(out["div"], serde_json::json!("block"));
        assert_eq!(out["span"], serde_json::json!("inline"));
        assert_eq!(out["li"], serde_json::json!("list-item"));
        assert_eq!(out["script"], serde_json::json!("none"));
        assert_eq!(out["unknown"], serde_json::json!("inline"));
        assert_eq!(out["overflowY"], serde_json::json!("visible"));
        assert_eq!(out["visibility"], serde_json::json!("visible"));
        assert_eq!(out["position"], serde_json::json!("static"));
    }

    // ── canvas / WebGL fingerprint tier ─────────────────────────────────────
    // No real rasterizer (module doc: no layout/paint), so the fingerprint's
    // job is STABILITY: a drawn canvas must answer an identical payload on
    // every run, machine, and eval, and a pristine canvas the empty-pixel PNG
    // a real browser produces for a never-drawn 300x150 canvas.

    #[test]
    fn canvas_pristine_todataurl_is_the_empty_png() {
        let mut rt = crate::Runtime::new();
        let page = Page::new("https://example.test/".to_string(), "<html><body></body></html>");
        let js = r##"
            (() => {
                const c = document.createElement('canvas');
                return { url: c.toDataURL(), tag: c.tagName };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("pristine canvas eval runs");
        assert_eq!(out["url"], serde_json::json!(CANVAS_EMPTY_PNG));
        assert_eq!(out["tag"], serde_json::json!("CANVAS"));
    }

    #[test]
    fn canvas_fingerprint_is_stable_across_instances() {
        let mut rt = crate::Runtime::new();
        let page = Page::new("https://example.test/".to_string(), "<html><body></body></html>");
        // The canonical probe: draw text/shapes on TWO independent canvases;
        // both must hash to the SAME payload (deterministic across instances),
        // and it must differ from the pristine answer.
        let js = r##"
            (() => {
                const probe = () => {
                    const c = document.createElement('canvas');
                    c.width = 220; c.height = 30;
                    const ctx = c.getContext('2d');
                    ctx.font = '14px Arial';
                    ctx.fillStyle = '#f60';
                    ctx.fillRect(0, 0, 100, 20);
                    ctx.fillStyle = '#069';
                    ctx.fillText('Cwm fjordbank glyphs vext quiz', 4, 15);
                    return c.toDataURL();
                };
                const a = probe();
                const b = probe();
                return { a, b, differsFromEmpty: a !== document.createElement('canvas').toDataURL() };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("fingerprint eval runs");
        assert_eq!(out["a"], serde_json::json!(CANVAS_FINGERPRINT));
        assert_eq!(out["b"], serde_json::json!(CANVAS_FINGERPRINT));
        assert_eq!(out["differsFromEmpty"], serde_json::json!(true));
    }

    #[test]
    fn canvas_2d_context_is_cached_per_canvas() {
        let mut rt = crate::Runtime::new();
        let page = Page::new("https://example.test/".to_string(), "<html><body></body></html>");
        let js = r##"
            (() => {
                const c = document.createElement('canvas');
                const first = c.getContext('2d');
                const again = c.getContext('2d');
                const other = document.createElement('canvas').getContext('2d');
                return {
                    sameOnRepeat: first === again,
                    distinctAcrossCanvases: first !== other,
                    hasFillText: typeof first.fillText === 'function',
                    hasGetImageData: typeof first.getImageData === 'function',
                };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("2d context caching eval runs");
        assert_eq!(out["sameOnRepeat"], serde_json::json!(true));
        assert_eq!(out["distinctAcrossCanvases"], serde_json::json!(true));
        assert_eq!(out["hasFillText"], serde_json::json!(true));
        assert_eq!(out["hasGetImageData"], serde_json::json!(true));
    }

    #[test]
    fn canvas_get_image_data_returns_clamped_opaque_black() {
        let mut rt = crate::Runtime::new();
        let page = Page::new("https://example.test/".to_string(), "<html><body></body></html>");
        let js = r##"
            (() => {
                const c = document.createElement('canvas');
                const ctx = c.getContext('2d');
                ctx.fillRect(0, 0, 10, 10);
                const px = ctx.getImageData(0, 0, 1, 1);
                const d = px.data;
                return {
                    width: px.width,
                    height: px.height,
                    isClampedArray: typeof Uint8ClampedArray !== 'undefined' && d instanceof Uint8ClampedArray,
                    length: d.length,
                    pixel: [d[0], d[1], d[2], d[3]],
                };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("getImageData eval runs");
        assert_eq!(out["width"], serde_json::json!(1));
        assert_eq!(out["height"], serde_json::json!(1));
        assert_eq!(out["isClampedArray"], serde_json::json!(true));
        assert_eq!(out["length"], serde_json::json!(4));
        assert_eq!(out["pixel"], serde_json::json!([0, 0, 0, 255]));
    }

    #[test]
    fn canvas_webgl_stub_answers_the_fingerprint_probes() {
        let mut rt = crate::Runtime::new();
        let page = Page::new("https://example.test/".to_string(), "<html><body></body></html>");
        // FingerprintJS-style WebGL probe: VENDOR/RENDERER via getParameter,
        // extension enumeration, context-lost state.
        let js = r##"
            (() => {
                const c = document.createElement('canvas');
                const gl = c.getContext('webgl');
                const again = c.getContext('webgl');
                return {
                    sameOnRepeat: gl === again,
                    vendor: gl.getParameter(gl.VENDOR),
                    renderer: gl.getParameter(gl.RENDERER),
                    version: gl.getParameter(gl.VERSION),
                    maxTextureSize: gl.getParameter(0x0D33),
                    extension: gl.getExtension('WEBGL_debug_renderer_info'),
                    supportedLen: gl.getSupportedExtensions().length,
                    contextLost: gl.isContextLost(),
                };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("webgl stub eval runs");
        assert_eq!(out["sameOnRepeat"], serde_json::json!(true));
        assert_eq!(out["vendor"], serde_json::json!("Google Inc."));
        assert_eq!(
            out["renderer"],
            serde_json::json!("ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) (0x0000C0DE)), SwiftShader driver)")
        );
        assert_eq!(out["version"], serde_json::json!("WebGL 2.0 (OpenGL ES 3.0 Chromium)"));
        assert_eq!(out["maxTextureSize"], serde_json::json!(8192));
        assert_eq!(out["extension"], serde_json::Value::Null);
        assert_eq!(out["supportedLen"], serde_json::json!(0));
        assert_eq!(out["contextLost"], serde_json::json!(false));
    }

    #[test]
    fn canvas_unknown_context_kind_returns_null() {
        let mut rt = crate::Runtime::new();
        let page = Page::new("https://example.test/".to_string(), "<html><body></body></html>");
        let js = r##"
            (() => {
                const c = document.createElement('canvas');
                return {
                    webgpu: c.getContext('webgpu'),
                    bogus: c.getContext('not-a-context'),
                    empty: c.getContext(),
                };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("unknown-context eval runs");
        assert_eq!(out["webgpu"], serde_json::Value::Null);
        assert_eq!(out["bogus"], serde_json::Value::Null);
        assert_eq!(out["empty"], serde_json::Value::Null);
    }

    // ── dynamic-page driving surface ─────────────────────────────────────────
    // requestAnimationFrame + element geometry + observers. Target.com-style
    // pages gate their content behind these APIs (lazy-loaders poll rects,
    // infinite scroll waits on IO), so the engine's contract is REVEAL: rAF
    // fires on a ~16ms cadence with a timestamp, rects report the honest
    // zero-geometry, and every observed target is delivered as intersecting
    // so gated loaders actually populate.

    #[test]
    fn raf_fires_with_a_timestamp_and_cancel_stops_it() {
        let mut rt = crate::Runtime::new();
        let page = Page::new("https://example.test/".to_string(), "<html><body></body></html>");
        let js = r##"
            (async () => {
                let fired = 0;
                let ts = -1;
                requestAnimationFrame((t) => { fired++; ts = t; });
                const doomed = requestAnimationFrame(() => { fired++; });
                cancelAnimationFrame(doomed);
                await new Promise((res) => setTimeout(res, 60));
                return { fired, tsIsNumber: typeof ts === 'number', tsNonNeg: ts >= 0 };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("raf eval resolves");
        assert_eq!(out["fired"], serde_json::json!(1));
        assert_eq!(out["tsIsNumber"], serde_json::json!(true));
        assert_eq!(out["tsNonNeg"], serde_json::json!(true));
    }

    #[test]
    fn raf_chains_drive_animation_loops() {
        let mut rt = crate::Runtime::new();
        let page = Page::new("https://example.test/".to_string(), "<html><body></body></html>");
        // A self-rescheduling rAF loop (the idiomatic driver) must tick
        // repeatedly under the pump, not just once.
        let js = r##"
            (async () => {
                let ticks = 0;
                const step = () => { ticks++; if (ticks < 3) requestAnimationFrame(step); };
                requestAnimationFrame(step);
                await new Promise((res) => setTimeout(res, 80));
                return { ticks };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("chained raf eval resolves");
        assert_eq!(out["ticks"], serde_json::json!(3));
    }

    #[test]
    fn get_bounding_client_rect_reports_the_honest_zero_rect() {
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/".to_string(),
            "<html><body><div id=\"app\">hi</div></body></html>",
        );
        let js = r##"
            (() => {
                const el = document.querySelector('#app');
                const r = el.getBoundingClientRect();
                const rects = el.getClientRects();
                const rr = rects[0];
                return {
                    top: r.top, right: r.right, bottom: r.bottom, left: r.left,
                    width: r.width, height: r.height, x: r.x, y: r.y,
                    clientRectsLen: rects.length,
                    rrTop: rr.top, rrWidth: rr.width,
                    // the visibility probe lazy-loaders use:
                    inViewport: r.top < window.innerHeight && r.bottom >= 0,
                };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("rect eval runs");
        for k in [
            "top", "right", "bottom", "left", "width", "height", "x", "y", "rrTop", "rrWidth",
        ] {
            assert_eq!(out[k], serde_json::json!(0), "{k} is zero");
        }
        assert_eq!(out["clientRectsLen"], serde_json::json!(1));
        // Reveal-everything consequence: the zero rect reads as in-viewport,
        // so visibility-gated loaders treat the whole page as visible.
        assert_eq!(out["inViewport"], serde_json::json!(true));
    }

    #[test]
    fn intersection_observer_reveals_the_target() {
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/".to_string(),
            "<html><body><div id=\"feed\"></div></body></html>",
        );
        let js = r##"
            (async () => {
                const el = document.querySelector('#feed');
                const seen = [];
                const io = new IntersectionObserver((entries, obs) => {
                    for (const e of entries) {
                        seen.push({
                            isIntersecting: e.isIntersecting,
                            ratio: e.intersectionRatio,
                            targetOk: e.target === el,
                            obsOk: obs === io,
                            rectZero: e.boundingClientRect.width === 0,
                            hasTime: typeof e.time === 'number',
                        });
                    }
                });
                io.observe(el);
                await new Promise((res) => setTimeout(res, 50));
                return { delivered: seen.length, first: seen[0] || null };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("io eval resolves");
        assert_eq!(out["delivered"], serde_json::json!(1));
        let first = &out["first"];
        assert_eq!(first["isIntersecting"], serde_json::json!(true));
        assert_eq!(first["ratio"], serde_json::json!(1));
        assert_eq!(first["targetOk"], serde_json::json!(true));
        assert_eq!(first["obsOk"], serde_json::json!(true));
        assert_eq!(first["rectZero"], serde_json::json!(true));
        assert_eq!(first["hasTime"], serde_json::json!(true));
    }

    #[test]
    fn intersection_observer_disconnect_cancels_pending_delivery() {
        let mut rt = crate::Runtime::new();
        let page = Page::new("https://example.test/".to_string(), "<html><body></body></html>");
        let js = r##"
            (async () => {
                let calls = 0;
                const io = new IntersectionObserver(() => { calls++; });
                io.observe(document.createElement('div'));
                io.disconnect();
                await new Promise((res) => setTimeout(res, 40));
                return { calls };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("disconnect eval resolves");
        assert_eq!(out["calls"], serde_json::json!(0));
    }

    #[test]
    fn resize_observer_reports_then_take_records_is_empty() {
        let mut rt = crate::Runtime::new();
        let page = Page::new("https://example.test/".to_string(), "<html><body></body></html>");
        let js = r##"
            (async () => {
                const el = document.createElement('div');
                let calls = 0;
                const sizes = [];
                const ro = new ResizeObserver((entries) => {
                    calls++;
                    for (const e of entries) sizes.push([e.contentRect.width, e.contentRect.height]);
                });
                ro.observe(el);
                await new Promise((res) => setTimeout(res, 50));
                const taken = ro.takeRecords();
                return { calls, sizes, takenLen: taken.length };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("ro eval resolves");
        assert_eq!(out["calls"], serde_json::json!(1));
        assert_eq!(out["sizes"], serde_json::json!([[0, 0]]));
        assert_eq!(out["takenLen"], serde_json::json!(0));
    }


    #[test]
    fn m4_permissions_media_battery_surface() {
        // FingerprintJS-class probes: the Permissions API (consistency-checked
        // against Notification.permission), the device enumerators, and the
        // battery state must all answer like a fresh-profile desktop Chrome.
        let mut rt = crate::Runtime::new();
        let js = r##"
            (async () => {
                const notif = await navigator.permissions.query({ name: 'notifications' });
                const geo = await navigator.permissions.query({ name: 'geolocation' });
                const clip = await navigator.permissions.query({ name: 'clipboard-write' });
                let unknownRejected = '';
                try {
                    await navigator.permissions.query({ name: 'bogus-permission' });
                } catch (e) { unknownRejected = String(e).slice(0, 120); }
                const devs = await navigator.mediaDevices.enumerateDevices();
                const kinds = devs.map((d) => d.kind).sort().join(',');
                const labels = devs.map((d) => d.label).join('|');
                let gumRejected = '';
                try {
                    await navigator.mediaDevices.getUserMedia({ audio: true });
                } catch (e) { gumRejected = String(e).slice(0, 30); }
                const batt = await navigator.getBattery();
                return {
                    notifState: notif.state,
                    notifOnchange: notif.onchange,
                    geoState: geo.state,
                    clipState: clip.state,
                    unknownRejected,
                    devCount: devs.length,
                    kinds,
                    labels,
                    gumRejected,
                    charging: batt.charging,
                    level: batt.level,
                    chargingTime: batt.chargingTime,
                    dischargingInfinite: batt.dischargingTime === Infinity,
                };
            })()
        "##;
        let out = rt.eval_with_page(None, js).expect("m4 probe resolves");
        assert_eq!(out["notifState"], serde_json::json!("prompt")); // ↔ Notification.permission 'default'
        assert_eq!(out["notifOnchange"], serde_json::Value::Null);
        assert_eq!(out["geoState"], serde_json::json!("prompt"));
        assert_eq!(out["clipState"], serde_json::json!("granted"));
        assert!(out["unknownRejected"]
            .as_str()
            .unwrap()
            .contains("not a valid enum value"));
        assert_eq!(out["devCount"], serde_json::json!(3));
        assert_eq!(out["kinds"], serde_json::json!("audioinput,audiooutput,videoinput"));
        assert_eq!(out["labels"], serde_json::json!("||")); // empty without permission
        assert!(out["gumRejected"].as_str().unwrap().contains("NotAllowedError"));
        assert_eq!(out["charging"], serde_json::json!(true));
        assert_eq!(out["level"], serde_json::json!(1));
        assert_eq!(out["chargingTime"], serde_json::json!(0));
        assert_eq!(out["dischargingInfinite"], serde_json::json!(true));
    }

    #[test]
    fn m4_speech_visualviewport_close_surface() {
        let mut rt = crate::Runtime::new();
        let js = r##"
            (async () => {
                const voices = speechSynthesis.getVoices();
                return {
                    ssShape: typeof speechSynthesis.speak === 'function'
                        && speechSynthesis.pending === false
                        && speechSynthesis.speaking === false
                        && speechSynthesis.paused === false
                        && speechSynthesis.onvoiceschanged === null,
                    voiceLen: voices.length,
                    vvW: visualViewport.width,
                    vvH: visualViewport.height,
                    vvScale: visualViewport.scale,
                    vvOffset: visualViewport.offsetLeft + visualViewport.offsetTop
                        + visualViewport.pageLeft + visualViewport.pageTop,
                    closeType: typeof window.close,
                };
            })()
        "##;
        let out = rt.eval_with_page(None, js).expect("m4 surface eval resolves");
        assert_eq!(out["ssShape"], serde_json::json!(true));
        assert_eq!(out["voiceLen"], serde_json::json!(0));
        assert_eq!(out["vvW"], serde_json::json!(1920));
        assert_eq!(out["vvH"], serde_json::json!(937));
        assert_eq!(out["vvScale"], serde_json::json!(1));
        assert_eq!(out["vvOffset"], serde_json::json!(0));
        assert_eq!(out["closeType"], serde_json::json!("function"));
    }

    #[test]
    fn m4_fetch_tostring_reads_native_code() {
        // The fetch trampoline is JS (init normalization + promisify), and
        // its source leaked through Function.prototype.toString — an
        // automation tell. The host-function mask must read as native, and
        // the mask itself must toString as native too.
        let mut rt = crate::Runtime::new();
        let js = r##"
            (async () => {
                const ts = Function.prototype.toString;
                const body = ts.call(fetch);
                return {
                    exact: body,
                    nameIsFetch: fetch.name === 'fetch',
                    maskIsNative: ts.call(fetch.toString).indexOf('[native code]') >= 0,
                    domStillNative: ts.call(document.querySelector) === 'function querySelector() { [native code] }',
                };
            })()
        "##;
        let out = rt
            .eval_with_page(None, js)
            .expect("fetch toString eval resolves");
        assert_eq!(
            out["exact"],
            serde_json::json!("function fetch() { [native code] }")
        );
        assert_eq!(out["nameIsFetch"], serde_json::json!(true));
        assert_eq!(out["maskIsNative"], serde_json::json!(true));
        assert_eq!(out["domStillNative"], serde_json::json!(true));
    }

    #[test]
    fn m4_crypto_text_codecs_surface() {
        // Firing 26, utility/crypto tier: WebCrypto answers honestly
        // (SHA-256 known vector, OS-random fills, v4 UUID), text codecs are
        // real UTF-8 (fatal throws), structuredClone deep-clones and turns
        // uncloneable values into DataCloneError, and the engine-installed
        // JS trampolines (structuredClone / TextDecoder.decode) toString
        // as native through the fp_masks dispatcher.
        let mut rt = crate::Runtime::new();
        let js = r##"
            (async () => {
                const enc = new TextEncoder();
                const digest = await crypto.subtle.digest('SHA-256', enc.encode('abc'));
                const hex = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
                const arr = new Uint8Array(8);
                const same = crypto.getRandomValues(arr) === arr;
                const filled = Array.from(arr).some(b => b !== 0);
                const uuid = crypto.randomUUID();
                const round = new TextDecoder().decode(enc.encode('héllo'));
                let fatalThrew = '';
                try {
                    new TextDecoder('utf-8', {fatal: true}).decode(new Uint8Array([0xff, 0xfe]));
                } catch (e) { fatalThrew = e.name; }
                const cloned = structuredClone({a: [1, 2], d: new Date(1000), s: 'x'});
                let cloneErr = '';
                try { structuredClone(() => 1); } catch (e) { cloneErr = e.name; }
                let reported = true;
                try { reportError(new Error('x')); } catch (e) { reported = false; }
                const ts = Function.prototype.toString;
                return {
                    sha256: hex,
                    same, filled,
                    uuidOk: /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(uuid),
                    round, fatalThrew,
                    cloneDeep: cloned.a.length === 2 && cloned.a !== undefined,
                    cloneDate: cloned.d instanceof Date && cloned.d.getTime() === 1000,
                    cloneErr, reported,
                    cloneNative: ts.call(structuredClone).indexOf('[native code]') >= 0,
                    decodeNative: ts.call(new TextDecoder().decode).indexOf('[native code]') >= 0,
                };
            })()
        "##;
        let out = rt
            .eval_with_page(None, js)
            .expect("crypto/codecs eval resolves");
        assert_eq!(
            out["sha256"],
            serde_json::json!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(out["same"], serde_json::json!(true));
        assert_eq!(out["filled"], serde_json::json!(true));
        assert_eq!(out["uuidOk"], serde_json::json!(true));
        assert_eq!(out["round"], serde_json::json!("héllo"));
        assert_eq!(out["fatalThrew"], serde_json::json!("TypeError"));
        assert_eq!(out["cloneDeep"], serde_json::json!(true));
        assert_eq!(out["cloneDate"], serde_json::json!(true));
        assert_eq!(out["cloneErr"], serde_json::json!("DataCloneError"));
        assert_eq!(out["reported"], serde_json::json!(true));
        assert_eq!(out["cloneNative"], serde_json::json!(true));
        assert_eq!(out["decodeNative"], serde_json::json!(true));
    }

    #[test]
    fn m4_abort_css_performance_surface() {
        // Firing 26: AbortController flips + sync listener delivery, fetch
        // honors a PRE-aborted signal (rejects with AbortError before any
        // wire work), CSS.supports consults the curated table (and answers
        // false for unknown properties rather than faking support), and
        // the performance extras are the honest fresh-profile shapes.
        let mut rt = crate::Runtime::new();
        let js = r##"
            (async () => {
                const ac = new AbortController();
                const before = ac.signal.aborted;
                let events = 0;
                ac.signal.addEventListener('abort', () => events++);
                ac.abort();
                const reasonName = ac.signal.reason && ac.signal.reason.name;
                const code = ac.signal.reason && ac.signal.reason.code;
                let fetchErr = '';
                try {
                    const c = new AbortController();
                    c.abort();
                    await fetch('https://example.test/x', {signal: c.signal});
                } catch (e) { fetchErr = e.name; }
                return {
                    before, after: ac.signal.aborted, events, reasonName, code, fetchErr,
                    flex: CSS.supports('display', 'flex'),
                    bogus: CSS.supports('display', 'bogus-value'),
                    sticky: CSS.supports('position', 'sticky'),
                    cond: CSS.supports('(display: grid)'),
                    touch: CSS.supports('touch-action', 'manipulation'),
                    unknown: CSS.supports('not-a-prop', 'x'),
                    heap: performance.memory.jsHeapSizeLimit,
                    heapTotal: performance.memory.totalJSHeapSize > 0,
                    resources: performance.getEntriesByType('resource').length,
                    entries: performance.getEntries().length,
                    originType: typeof performance.timeOrigin,
                };
            })()
        "##;
        let out = rt
            .eval_with_page(None, js)
            .expect("abort/css/perf eval resolves");
        assert_eq!(out["before"], serde_json::json!(false));
        assert_eq!(out["after"], serde_json::json!(true));
        assert_eq!(out["events"], serde_json::json!(1));
        assert_eq!(out["reasonName"], serde_json::json!("AbortError"));
        assert_eq!(out["code"], serde_json::json!(20));
        assert_eq!(out["fetchErr"], serde_json::json!("AbortError"));
        assert_eq!(out["flex"], serde_json::json!(true));
        assert_eq!(out["bogus"], serde_json::json!(false));
        assert_eq!(out["sticky"], serde_json::json!(true));
        assert_eq!(out["cond"], serde_json::json!(true));
        assert_eq!(out["touch"], serde_json::json!(true));
        assert_eq!(out["unknown"], serde_json::json!(false));
        assert_eq!(out["heap"], serde_json::json!(4294705152u64));
        assert_eq!(out["heapTotal"], serde_json::json!(true));
        assert_eq!(out["resources"], serde_json::json!(0));
        assert_eq!(out["entries"], serde_json::json!(0));
        assert_eq!(out["originType"], serde_json::json!("number"));
    }

    #[test]
    fn m4_dom_utility_surface() {
        // Firing 26: geolocation denies asynchronously (fresh-profile
        // contract), storage.estimate resolves a plausible quota, vibrate/
        // doNotTrack are the desktop shapes, indexedDB.open reports its
        // missing backend via an async error event (cmp is real), and
        // customElements/attachShadow/fullscreen answer without throwing.
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/".to_string(),
            "<html><body><div id=\"host\"></div></body></html>",
        );
        let js = r##"
            (async () => {
                const geo = await new Promise((res) => {
                    navigator.geolocation.getCurrentPosition(
                        () => res('unexpected-success'),
                        (e) => res({code: e.code, msg: e.message, perm: e.PERMISSION_DENIED}),
                    );
                });
                const watchId = navigator.geolocation.watchPosition(() => {}, () => {});
                navigator.geolocation.clearWatch(watchId);
                const est = await navigator.storage.estimate();
                const persisted = await navigator.storage.persisted();
                const persist = await navigator.storage.persist();
                const idb = await new Promise((res) => {
                    const req = indexedDB.open('probe', 1);
                    req.onerror = () => res({
                        state: req.readyState,
                        hasErr: !!req.error,
                        name: req.error && req.error.name,
                    });
                    req.onsuccess = () => res('unexpected-success');
                });
                let probeClass = null;
                class ProbeElement extends HTMLElement {}
                probeClass = ProbeElement;
                let defined = false;
                try { customElements.define('x-probe', ProbeElement); defined = true; } catch (e) {}
                const got = customElements.get('x-probe');
                const wd = customElements.whenDefined('x-probe');
                const el = document.createElement('div');
                const shadow = el.attachShadow({mode: 'open'});
                let fsResolved = false;
                await el.requestFullscreen().then(() => { fsResolved = true; });
                await document.exitFullscreen();
                return {
                    geo, watchId,
                    quota: est.quota, usage: est.usage,
                    persisted, persist,
                    vib: navigator.vibrate(100),
                    dnt: navigator.doNotTrack,
                    idb,
                    cmp: indexedDB.cmp(1, 2),
                    defined, gotIsCtor: got === probeClass, wdThen: typeof wd.then,
                    shadowMode: shadow.mode,
                    shadowHost: shadow.host === el,
                    elShadow: el.shadowRoot === shadow,
                    fsType: typeof el.requestFullscreen,
                    plType: typeof el.requestPointerLock,
                    fsResolved,
                };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("dom utility eval resolves");
        assert_eq!(out["geo"]["code"], serde_json::json!(1));
        assert_eq!(out["geo"]["perm"], serde_json::json!(1));
        assert!(out["geo"]["msg"].as_str().unwrap().contains("denied"));
        assert_eq!(out["watchId"], serde_json::json!(0));
        assert_eq!(out["quota"], serde_json::json!(60000000000u64));
        assert_eq!(out["usage"], serde_json::json!(0));
        assert_eq!(out["persisted"], serde_json::json!(false));
        assert_eq!(out["persist"], serde_json::json!(false));
        assert_eq!(out["vib"], serde_json::json!(false));
        assert_eq!(out["dnt"], serde_json::json!(null));
        assert_eq!(out["idb"]["state"], serde_json::json!("done"));
        assert_eq!(out["idb"]["hasErr"], serde_json::json!(true));
        assert!(out["idb"]["name"].as_str().unwrap().len() > 0);
        assert_eq!(out["cmp"], serde_json::json!(-1));
        assert_eq!(out["defined"], serde_json::json!(true));
        assert_eq!(out["gotIsCtor"], serde_json::json!(true));
        assert_eq!(out["wdThen"], serde_json::json!("function"));
        assert_eq!(out["shadowMode"], serde_json::json!("open"));
        assert_eq!(out["shadowHost"], serde_json::json!(true));
        assert_eq!(out["elShadow"], serde_json::json!(true));
        assert_eq!(out["fsType"], serde_json::json!("function"));
        assert_eq!(out["plType"], serde_json::json!("function"));
        assert_eq!(out["fsResolved"], serde_json::json!(true));
    }

    #[test]
    fn m4_audio_context_surface() {
        // Firing 27: the audio fingerprint surface. Context classes install
        // the full node-factory surface, AudioParams expose value/ranges,
        // close() flips state, and OfflineAudioContext renders a real buffer
        // (default 440 Hz sine → nonzero sum) through startRendering().
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/".to_string(),
            "<html><body></body></html>",
        );
        let js = r##"
            (async () => {
                const ctx = new AudioContext();
                const osc = ctx.createOscillator();
                const gain = ctx.createGain();
                const comp = ctx.createDynamicsCompressor();
                const an = ctx.createAnalyser();
                const t1 = ctx.currentTime;
                const st = {
                    state: ctx.state,
                    sr: ctx.sampleRate,
                    bl: ctx.baseLatency,
                    destCh: ctx.destination.maxChannelCount,
                };
                const fftArr = new Uint8Array(4);
                an.getByteFrequencyData(fftArr);
                await ctx.close();
                const off = new OfflineAudioContext(1, 44100, 44100);
                const offState0 = off.state;
                const oosc = off.createOscillator();
                oosc.connect(off.destination);
                oosc.start(0);
                const rendered = await off.startRendering();
                const data = rendered.getChannelData(0);
                let sum = 0;
                for (let i = 0; i < data.length; i++) sum += Math.abs(data[i]);
                return {
                    types: [
                        typeof AudioContext, typeof OfflineAudioContext,
                        typeof webkitAudioContext, typeof webkitOfflineAudioContext,
                        typeof AudioBuffer, typeof OscillatorNode, typeof AudioParam,
                        typeof BaseAudioContext,
                    ],
                    oscType: osc.type,
                    freq: osc.frequency.value,
                    freqMin: osc.frequency.minValue,
                    freqMax: osc.frequency.maxValue,
                    det: osc.detune.value,
                    gainVal: gain.gain.value,
                    gainDef: gain.gain.defaultValue,
                    cThresh: comp.threshold.value,
                    cKnee: comp.knee.value,
                    cRatio: comp.ratio.value,
                    cAtt: comp.attack.value,
                    cRel: comp.release.value,
                    cRed: comp.reduction,
                    fft: an.fftSize,
                    bins: an.frequencyBinCount,
                    minDb: an.minDecibels,
                    maxDb: an.maxDecibels,
                    smooth: an.smoothingTimeConstant,
                    ff0: fftArr[0],
                    curTimeNum: typeof t1,
                    st,
                    stateAfterClose: ctx.state,
                    offState0,
                    offLen: off.length,
                    offSr: off.sampleRate,
                    offCurTime: off.currentTime,
                    rendLen: data.length,
                    sum,
                    duration: rendered.duration,
                    nch: rendered.numberOfChannels,
                    srBuf: rendered.sampleRate,
                };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("audio surface eval resolves");
        assert_eq!(
            out["types"],
            serde_json::json!([
                "function", "function", "function", "function",
                "function", "function", "function", "function"
            ])
        );
        assert_eq!(out["oscType"], serde_json::json!("sine"));
        assert_eq!(out["freq"], serde_json::json!(440));
        assert_eq!(out["freqMin"], serde_json::json!(-22050));
        assert_eq!(out["freqMax"], serde_json::json!(22050));
        assert_eq!(out["det"], serde_json::json!(0));
        assert_eq!(out["gainVal"], serde_json::json!(1));
        assert_eq!(out["gainDef"], serde_json::json!(1));
        assert_eq!(out["cThresh"], serde_json::json!(-24));
        assert_eq!(out["cKnee"], serde_json::json!(30));
        assert_eq!(out["cRatio"], serde_json::json!(12));
        assert!((out["cAtt"].as_f64().unwrap() - 0.003).abs() < 1e-9);
        assert_eq!(out["cRel"], serde_json::json!(0.25));
        assert_eq!(out["cRed"], serde_json::json!(0));
        assert_eq!(out["fft"], serde_json::json!(2048));
        assert_eq!(out["bins"], serde_json::json!(1024));
        assert_eq!(out["minDb"], serde_json::json!(-100));
        assert_eq!(out["maxDb"], serde_json::json!(-30));
        assert!((out["smooth"].as_f64().unwrap() - 0.8).abs() < 1e-9);
        assert_eq!(out["ff0"], serde_json::json!(0));
        assert_eq!(out["curTimeNum"], serde_json::json!("number"));
        assert_eq!(out["st"]["state"], serde_json::json!("running"));
        assert_eq!(out["st"]["sr"], serde_json::json!(44100));
        assert!((out["st"]["bl"].as_f64().unwrap() - 0.01161).abs() < 0.001);
        assert_eq!(out["st"]["destCh"], serde_json::json!(2));
        assert_eq!(out["stateAfterClose"], serde_json::json!("closed"));
        assert_eq!(out["offState0"], serde_json::json!("suspended"));
        assert_eq!(out["offLen"], serde_json::json!(44100));
        assert_eq!(out["offSr"], serde_json::json!(44100));
        assert_eq!(out["offCurTime"], serde_json::json!(0));
        assert_eq!(out["rendLen"], serde_json::json!(44100));
        assert!(out["sum"].as_f64().unwrap() > 1000.0);
        assert!((out["duration"].as_f64().unwrap() - 1.0).abs() < 1e-9);
        assert_eq!(out["nch"], serde_json::json!(1));
        assert_eq!(out["srBuf"], serde_json::json!(44100));
    }

    #[test]
    fn m4_offline_audio_rendering_deterministic() {
        // The render must be a pure function of the graph config: identical
        // graphs → identical buffers (stable fingerprint), and different
        // frequencies/waveforms/compressor settings → different buffers
        // (the honesty check a stubbed constant would fail).
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/".to_string(),
            "<html><body></body></html>",
        );
        let js = r##"
            (async () => {
                async function render(freq, type, useComp, thresh) {
                    const ctx = new OfflineAudioContext(1, 44100, 44100);
                    const osc = ctx.createOscillator();
                    osc.type = type;
                    osc.frequency.value = freq;
                    const tail = useComp
                        ? ctx.createDynamicsCompressor()
                        : ctx.createGain();
                    if (useComp) tail.threshold.value = thresh;
                    osc.connect(tail);
                    tail.connect(ctx.destination);
                    osc.start(0);
                    const b = await ctx.startRendering();
                    const d = b.getChannelData(0);
                    let s = 0;
                    for (let i = 0; i < d.length; i++) s += d[i] * d[i];
                    return s;
                }
                const a1 = await render(1000, 'sine', false, 0);
                const a2 = await render(1000, 'sine', false, 0);
                const b = await render(2000, 'sine', false, 0);
                const c = await render(1000, 'triangle', false, 0);
                const d = await render(1000, 'sine', true, -50);
                const e = await render(1000, 'sine', true, -10);
                return {
                    same: a1 === a2,
                    diffFreq: a1 !== b,
                    diffType: a1 !== c,
                    nonzero: a1 > 0,
                    diffComp: d !== e,
                    compChanged: d !== a1,
                };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("offline rendering eval resolves");
        for k in [
            "same",
            "diffFreq",
            "diffType",
            "nonzero",
            "diffComp",
            "compChanged",
        ] {
            assert_eq!(out[k], serde_json::json!(true), "{k} must hold");
        }
    }

    #[test]
    fn m4_audio_buffer_param_surface() {
        // AudioParam chaining + both mutation paths (automation setter and
        // direct .value assignment), AudioBuffer channel copies both
        // directions, the global AudioBuffer ctor, bufferSource rendering
        // of a written buffer, and analyser silence fills.
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/".to_string(),
            "<html><body></body></html>",
        );
        let js = r##"
            (async () => {
                const ctx = new AudioContext();
                const g = ctx.createGain();
                const ret = g.gain.setValueAtTime(0.5, 0)
                    .linearRampToValueAtTime(1, 1).cancelScheduledValues(0);
                const chained = ret === g.gain;
                const v = g.gain.value;
                g.gain.value = 0.25;
                const v2 = g.gain.value;

                const buf = ctx.createBuffer(2, 1000, 44100);
                const ch0 = buf.getChannelData(0);
                const sameArr = buf.getChannelData(0) === ch0;
                ch0[0] = 0.5;
                ch0[1] = -0.5;
                const src = new Float32Array(4);
                src[0] = 1; src[1] = 2; src[2] = 3; src[3] = 4;
                buf.copyToChannel(src, 0, 10);
                const after = [ch0[10], ch0[11], ch0[12], ch0[13]];
                const out = new Float32Array(4);
                buf.copyFromChannel(out, 0, 10);
                const back = [out[0], out[1], out[2], out[3]];
                const len = buf.length;
                const dur = buf.duration;
                const nch = buf.numberOfChannels;
                const sr = buf.sampleRate;

                const ab = new AudioBuffer({length: 500, numberOfChannels: 1, sampleRate: 48000});
                const abLen = ab.length;
                ab.getChannelData(0)[3] = 7;
                const abRead = ab.getChannelData(0)[3];
                const abSr = ab.sampleRate;

                const off = new OfflineAudioContext(1, 500, 44100);
                const bs = off.createBufferSource();
                bs.buffer = buf;
                bs.connect(off.destination);
                bs.start(0);
                const rendered = await off.startRendering();
                const rd = rendered.getChannelData(0);
                const rs = rd[10] + rd[11];

                const an = ctx.createAnalyser();
                const ff = new Float32Array(8);
                an.getFloatFrequencyData(ff);
                const bt = new Uint8Array(8);
                an.getByteTimeDomainData(bt);
                const fa = new Float32Array(8);
                an.getFloatTimeDomainData(fa);

                return {
                    chained, v, v2, sameArr, after, back,
                    len, dur, nch, sr, abLen, abRead, abSr, rs,
                    ff0: ff[0], bt0: bt[0], fa0: fa[0],
                };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("audio buffer/param eval resolves");
        assert_eq!(out["chained"], serde_json::json!(true));
        // The chain's last setter wins: setValueAtTime(0.5) → ramp(1) → 1.
        assert_eq!(out["v"], serde_json::json!(1));
        assert_eq!(out["v2"], serde_json::json!(0.25));
        assert_eq!(out["sameArr"], serde_json::json!(true));
        assert_eq!(out["after"], serde_json::json!([1, 2, 3, 4]));
        assert_eq!(out["back"], serde_json::json!([1, 2, 3, 4]));
        assert_eq!(out["len"], serde_json::json!(1000));
        assert!((out["dur"].as_f64().unwrap() - 1000.0 / 44100.0).abs() < 1e-9);
        assert_eq!(out["nch"], serde_json::json!(2));
        assert_eq!(out["sr"], serde_json::json!(44100));
        assert_eq!(out["abLen"], serde_json::json!(500));
        assert_eq!(out["abRead"], serde_json::json!(7));
        assert_eq!(out["abSr"], serde_json::json!(48000));
        assert!((out["rs"].as_f64().unwrap() - 3.0).abs() < 1e-6);
        assert_eq!(out["ff0"], serde_json::json!(-100));
        assert_eq!(out["bt0"], serde_json::json!(128));
        assert_eq!(out["fa0"], serde_json::json!(0));
    }

    #[test]
    fn m4_caches_round_trip() {
        // Firing 28: the pure-JS CacheStorage/Cache — open/put/match round
        // trip against a real fetched response, miss → undefined, per-cache
        // and storage-wide enumeration, delete both levels, add() via
        // fetch, and the global Cache/CacheStorage ctor shapes.
        let srv = spawn_server(2, |path, _req| match path {
            "/data" => (200, "hello cache".to_string()),
            _ => (404, "nope".to_string()),
        });
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            format!("{srv}/page"),
            "<html><body></body></html>",
        );
        let js = format!(
            r##"
            (async () => {{
                const cache = await caches.open('v1');
                const cacheType = typeof cache;
                const resp = await fetch('{srv}/data');
                await cache.put('{srv}/data', resp);
                const hit = await cache.match('{srv}/data');
                const roundTrip = hit ? await hit.text() : null;
                const hitStatus = hit && hit.status;
                const miss = await cache.match('{srv}/nope');
                const keys = await cache.keys();
                const has = await caches.has('v1');
                const storeKeys = await caches.keys();
                const all = await caches.match('{srv}/data');
                const allText = all ? await all.text() : null;
                const delEntry = await cache.delete('{srv}/data');
                const afterDel = await cache.match('{srv}/data');
                const c2 = await caches.open('v2');
                await c2.add('{srv}/data');
                const addHit = await c2.match('{srv}/data');
                const addText = addHit ? await addHit.text() : null;
                const delCache = await caches.delete('v2');
                const hasV2 = await caches.has('v2');
                return {{
                    cacheType, roundTrip, hitStatus,
                    missUndefined: miss === undefined,
                    keyLen: keys.length, key0: keys[0],
                    has, storeKeys,
                    allText,
                    delEntry, afterUndefined: afterDel === undefined,
                    addText, delCache, hasV2,
                    globalCache: typeof Cache,
                    globalCacheStorage: typeof CacheStorage,
                    globalCaches: typeof caches,
                }};
            }})()
        "##
        );
        let out = rt
            .eval_with_page(Some(&page), &js)
            .expect("caches round trip resolves");
        assert_eq!(out["cacheType"], serde_json::json!("object"));
        assert_eq!(out["roundTrip"], serde_json::json!("hello cache"));
        assert_eq!(out["hitStatus"], serde_json::json!(200));
        assert_eq!(out["missUndefined"], serde_json::json!(true));
        assert_eq!(out["keyLen"], serde_json::json!(1));
        assert_eq!(out["key0"], serde_json::json!(format!("{srv}/data")));
        assert_eq!(out["has"], serde_json::json!(true));
        // c2 isn't opened until later in the script — storage keys at this
        // point are just ['v1'].
        assert_eq!(out["storeKeys"], serde_json::json!(["v1"]));
        assert_eq!(out["allText"], serde_json::json!("hello cache"));
        assert_eq!(out["delEntry"], serde_json::json!(true));
        assert_eq!(out["afterUndefined"], serde_json::json!(true));
        assert_eq!(out["addText"], serde_json::json!("hello cache"));
        assert_eq!(out["delCache"], serde_json::json!(true));
        assert_eq!(out["hasV2"], serde_json::json!(false));
        assert_eq!(out["globalCache"], serde_json::json!("function"));
        assert_eq!(out["globalCacheStorage"], serde_json::json!("function"));
        assert_eq!(out["globalCaches"], serde_json::json!("object"));
    }

    #[test]
    fn m4_device_api_shapes() {
        // Firing 28: the M4-remainder device/permission shapes answer like
        // a fresh-profile desktop Chrome — no devices (empty enumerations,
        // NotFoundError on request*), no activation (NotAllowedError on
        // share/store), no adapter (bluetooth availability false, gpu
        // adapter null), clipboard reads denied, and the mediaCapabilities
        // curated table.
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/".to_string(),
            "<html><body></body></html>",
        );
        let js = r##"
            (async () => {
                const ctors = [
                    typeof Credential, typeof PasswordCredential,
                    typeof FederatedCredential, typeof ClipboardEvent,
                    typeof WakeLockSentinel, typeof BluetoothDevice,
                    typeof USBDevice, typeof SerialPort, typeof HIDDevice,
                    typeof Gamepad, typeof Lock, typeof LockManager,
                    typeof Scheduler, typeof GPU, typeof GPUAdapter,
                    typeof MediaCapabilities, typeof NetworkInformation,
                ];
                const cred = await navigator.credentials.get({password: true});
                let credStoreErr = null;
                try { await navigator.credentials.store({}); }
                catch (e) { credStoreErr = e.name; }
                await navigator.credentials.preventSilentAccess();
                let clipErr = null;
                try { await navigator.clipboard.readText(); }
                catch (e) { clipErr = e.name; }
                await navigator.clipboard.writeText('x');
                const wl = await navigator.wakeLock.request('screen');
                const wlType = wl.type;
                const wlReleased0 = wl.released;
                wl.release();
                const wlReleased1 = wl.released;
                const btAvail = await navigator.bluetooth.getAvailability();
                let btErr = null;
                try {
                    await navigator.bluetooth.requestDevice({acceptAllDevices: true});
                } catch (e) { btErr = e.name; }
                const usbDevs = await navigator.usb.getDevices();
                let usbErr = null;
                try { await navigator.usb.requestDevice({filters: []}); }
                catch (e) { usbErr = e.name; }
                const ports = await navigator.serial.getPorts();
                let serErr = null;
                try { await navigator.serial.requestPort(); }
                catch (e) { serErr = e.name; }
                const hidDevs = await navigator.hid.getDevices();
                let hidErr = null;
                try { await navigator.hid.requestDevice({filters: []}); }
                catch (e) { hidErr = e.name; }
                let shareErr = null;
                try { await navigator.share({title: 't', url: 'https://example.com'}); }
                catch (e) { shareErr = e.name; }
                let shareTypeErr = null;
                try { await navigator.share({}); }
                catch (e) { shareTypeErr = e.name; }
                const canShare = navigator.canShare({title: 't', url: 'https://example.com'});
                const cannotShare = navigator.canShare({});
                const related = await navigator.getInstalledRelatedApps();
                const pads = navigator.getGamepads();
                const sched = navigator.scheduling.isInputPending();
                const schedType = typeof scheduler;
                const postTaskResult = await scheduler.postTask(() => 42);
                const xrOk = await navigator.xr.isSessionSupported('immersive-vr');
                let xrErr = null;
                try { await navigator.xr.requestSession('immersive-vr'); }
                catch (e) { xrErr = e.name; }
                const mc = await navigator.mediaCapabilities.decodingInfo(
                    {type: 'file', video: {contentType: 'video/webm;codecs=vp9'}});
                const mcBad = await navigator.mediaCapabilities.decodingInfo(
                    {type: 'file', video: {contentType: 'video/x-madeup-codec'}});
                const gpuAdapter = await navigator.gpu.requestAdapter();
                const gpuFmt = navigator.gpu.getPreferredCanvasFormat();
                const q = await navigator.locks.query();
                let lockRet = null;
                await navigator.locks.request('k', (lock) => {
                    lockRet = lock.name + ':' + lock.mode + ':' + lock.clientId;
                });
                return {
                    ctors,
                    credNull: cred === null,
                    credStoreErr, clipErr,
                    wlType, wlReleased0, wlReleased1,
                    btAvail, btErr,
                    usbLen: usbDevs.length, usbErr,
                    portsLen: ports.length, serErr,
                    hidLen: hidDevs.length, hidErr,
                    shareErr, shareTypeErr, canShare, cannotShare,
                    relatedLen: related.length, padsLen: pads.length,
                    sched, schedType, postTaskResult,
                    xrOk, xrErr,
                    mcSupported: mc.supported, mcSmooth: mc.smooth,
                    mcPower: mc.powerEfficient,
                    mcBadSupported: mcBad.supported,
                    gpuNull: gpuAdapter === null, gpuFmt,
                    qHeld: q.held.length, qPending: q.pending.length,
                    lockRet,
                };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("device API shape eval resolves");
        for (i, c) in out["ctors"].as_array().unwrap().iter().enumerate() {
            assert_eq!(c, &serde_json::json!("function"), "ctor {i}");
        }
        assert_eq!(out["credNull"], serde_json::json!(true));
        assert_eq!(out["credStoreErr"], serde_json::json!("NotAllowedError"));
        assert_eq!(out["clipErr"], serde_json::json!("NotAllowedError"));
        assert_eq!(out["wlType"], serde_json::json!("screen"));
        assert_eq!(out["wlReleased0"], serde_json::json!(false));
        assert_eq!(out["wlReleased1"], serde_json::json!(true));
        assert_eq!(out["btAvail"], serde_json::json!(false));
        assert_eq!(out["btErr"], serde_json::json!("NotFoundError"));
        assert_eq!(out["usbLen"], serde_json::json!(0));
        assert_eq!(out["usbErr"], serde_json::json!("NotFoundError"));
        assert_eq!(out["portsLen"], serde_json::json!(0));
        assert_eq!(out["serErr"], serde_json::json!("NotFoundError"));
        assert_eq!(out["hidLen"], serde_json::json!(0));
        assert_eq!(out["hidErr"], serde_json::json!("NotFoundError"));
        assert_eq!(out["shareErr"], serde_json::json!("NotAllowedError"));
        assert_eq!(out["shareTypeErr"], serde_json::json!("TypeError"));
        assert_eq!(out["canShare"], serde_json::json!(true));
        assert_eq!(out["cannotShare"], serde_json::json!(false));
        assert_eq!(out["relatedLen"], serde_json::json!(0));
        assert_eq!(out["padsLen"], serde_json::json!(0));
        assert_eq!(out["sched"], serde_json::json!(false));
        assert_eq!(out["schedType"], serde_json::json!("object"));
        assert_eq!(out["postTaskResult"], serde_json::json!(42));
        assert_eq!(out["xrOk"], serde_json::json!(false));
        assert_eq!(out["xrErr"], serde_json::json!("NotSupportedError"));
        assert_eq!(out["mcSupported"], serde_json::json!(true));
        assert_eq!(out["mcSmooth"], serde_json::json!(true));
        assert_eq!(out["mcPower"], serde_json::json!(false));
        assert_eq!(out["mcBadSupported"], serde_json::json!(false));
        assert_eq!(out["gpuNull"], serde_json::json!(true));
        assert_eq!(out["gpuFmt"], serde_json::json!("bgra8unorm"));
        assert_eq!(out["qHeld"], serde_json::json!(0));
        assert_eq!(out["qPending"], serde_json::json!(0));
        assert_eq!(out["lockRet"], serde_json::json!("k:exclusive:"));
    }

    #[test]
    fn mutation_observer_delivers_child_list_on_append_child() {
        // Firing 24: the wait-for-node idiom every lazy-load driver uses —
        // observe(body, {childList, subtree}), append, callback fires.
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/".to_string(),
            "<html><body><div id=\"host\"></div></body></html>",
        );
        let js = r##"
            (async () => {
                let calls = 0; let recs = null;
                const mo = new MutationObserver((records) => { calls++; recs = records; });
                mo.observe(document.body, { childList: true, subtree: true });
                const d = document.createElement('div');
                d.id = 'fresh'; d.textContent = 'hello';
                document.querySelector('#host').appendChild(d);
                await new Promise((res) => setTimeout(res, 30));
                return {
                    calls,
                    type: recs && recs[0] && recs[0].type,
                    targetTag: recs && recs[0] && recs[0].target && recs[0].target.tagName,
                    addedLen: recs && recs[0] && recs[0].addedNodes.length,
                    addedId: recs && recs[0] && recs[0].addedNodes[0] && recs[0].addedNodes[0].id,
                    addedText: recs && recs[0] && recs[0].addedNodes[0] && recs[0].addedNodes[0].textContent,
                };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("mutation observer eval resolves");
        assert_eq!(out["calls"], serde_json::json!(1));
        assert_eq!(out["type"], serde_json::json!("childList"));
        assert_eq!(out["targetTag"], serde_json::json!("DIV")); // #host, re-wrapped
        assert_eq!(out["addedLen"], serde_json::json!(1));
        assert_eq!(out["addedId"], serde_json::json!("fresh"));
        assert_eq!(out["addedText"], serde_json::json!("hello"));
    }

    #[test]
    fn mutation_observer_attribute_records_carry_name_and_old_value() {
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/".to_string(),
            "<html><body><div id=\"a\" data-x=\"0\"></div></body></html>",
        );
        let js = r##"
            (async () => {
                let calls = 0; let recs = null;
                const mo = new MutationObserver((records) => { calls++; recs = records; });
                const el = document.querySelector('#a');
                mo.observe(el, { attributes: true, attributeOldValue: true });
                el.setAttribute('data-x', '1');
                el.setAttribute('data-x', '2');
                await new Promise((res) => setTimeout(res, 30));
                // Spec batching: two mutations in one delivery pass = ONE
                // callback with TWO records.
                return {
                    calls,
                    len: recs && recs.length,
                    firstName: recs && recs[0] && recs[0].attributeName,
                    firstOld: recs && recs[0] && recs[0].oldValue,
                    secondOld: recs && recs[1] && recs[1].oldValue,
                    targetId: recs && recs[0] && recs[0].target && recs[0].target.id,
                };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("mutation observer eval resolves");
        assert_eq!(out["calls"], serde_json::json!(1));
        assert_eq!(out["len"], serde_json::json!(2));
        assert_eq!(out["firstName"], serde_json::json!("data-x"));
        assert_eq!(out["firstOld"], serde_json::json!("0"));
        assert_eq!(out["secondOld"], serde_json::json!("1"));
        assert_eq!(out["targetId"], serde_json::json!("a"));
    }

    #[test]
    fn mutation_observer_subtree_flag_governs_descendant_matching() {
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/".to_string(),
            "<html><body><div id=\"outer\"><div id=\"inner\"></div></div><div id=\"peer\"></div></body></html>",
        );
        let js = r##"
            (async () => {
                const outer = document.querySelector('#outer');
                const inner = document.querySelector('#inner');
                const peer = document.querySelector('#peer');
                // Spec batching: all mutations in one delivery pass reach an
                // observer as ONE callback with every record in one array —
                // so count RECORDS, not callback invocations.
                let narrowRecs = 0; let wideRecs = 0; let docRecs = 0;
                const narrow = new MutationObserver((rs) => { narrowRecs += rs.length; });
                const wide = new MutationObserver((rs) => { wideRecs += rs.length; });
                const docWide = new MutationObserver((rs) => { docRecs += rs.length; });
                narrow.observe(outer, { childList: true });                    // no subtree
                wide.observe(outer, { childList: true, subtree: true });
                docWide.observe(document, { childList: true });                // document sentinel
                const mk = () => { const s = document.createElement('span'); s.textContent = 'x'; return s; };
                inner.appendChild(mk());      // descendant: wide + docWide only
                peer.appendChild(mk());       // unrelated: docWide only
                outer.appendChild(mk());      // exact target: all three
                await new Promise((res) => setTimeout(res, 30));
                return { narrowRecs, wideRecs, docRecs };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("mutation observer eval resolves");
        assert_eq!(out["narrowRecs"], serde_json::json!(1)); // only the exact-target append
        assert_eq!(out["wideRecs"], serde_json::json!(2)); // descendant + exact
        assert_eq!(out["docRecs"], serde_json::json!(3)); // document-level matches all
    }

    #[test]
    fn mutation_observer_take_records_drains_pending_delivery() {
        let mut rt = crate::Runtime::new();
        let page = Page::new("https://example.test/".to_string(), "<html><body></body></html>");
        let js = r##"
            (async () => {
                let calls = 0;
                const mo = new MutationObserver(() => { calls++; });
                mo.observe(document.body, { childList: true, subtree: true });
                const d = document.createElement('i');
                document.body.appendChild(d);
                // Synchronous take: the record was queued at append time.
                const taken = mo.takeRecords();
                await new Promise((res) => setTimeout(res, 30));
                return { takenLen: taken.length, takenType: taken[0] && taken[0].type, calls };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("mutation observer eval resolves");
        assert_eq!(out["takenLen"], serde_json::json!(1));
        assert_eq!(out["takenType"], serde_json::json!("childList"));
        assert_eq!(out["calls"], serde_json::json!(0)); // drained: nothing left to deliver
    }

    #[test]
    fn mutation_observer_disconnect_discards_pending_records() {
        let mut rt = crate::Runtime::new();
        let page = Page::new("https://example.test/".to_string(), "<html><body></body></html>");
        let js = r##"
            (async () => {
                let calls = 0;
                const mo = new MutationObserver(() => { calls++; });
                mo.observe(document.body, { childList: true, subtree: true });
                const d = document.createElement('b');
                document.body.appendChild(d);
                mo.disconnect(); // unregisters AND drops the pending record
                await new Promise((res) => setTimeout(res, 30));
                return { calls, takenLen: mo.takeRecords().length, disconnectOk: typeof mo.disconnect === 'function' };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("mutation observer eval resolves");
        assert_eq!(out["calls"], serde_json::json!(0));
        assert_eq!(out["takenLen"], serde_json::json!(0));
        assert_eq!(out["disconnectOk"], serde_json::json!(true));
    }

    #[test]
    fn mutation_observer_observe_without_kind_throws_type_error() {
        let mut rt = crate::Runtime::new();
        let page = Page::new("https://example.test/".to_string(), "<html><body></body></html>");
        let js = r##"
            var mo = new MutationObserver(function() {});
            try {
                mo.observe(document.body, {});
                'no-throw';
            } catch (e) {
                e.name + '|' + (e.message.indexOf('childList') >= 0);
            }
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("mutation observer eval resolves");
        assert_eq!(out, serde_json::json!("TypeError|true"));
    }

    #[test]
    fn mutation_observer_remove_delivers_parent_target_with_removed_node() {
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/".to_string(),
            "<html><body><ul><li id=\"victim\">bye</li></ul></body></html>",
        );
        let js = r##"
            (async () => {
                let calls = 0; let recs = null;
                const mo = new MutationObserver((records) => { calls++; recs = records; });
                mo.observe(document.body, { childList: true, subtree: true });
                document.querySelector('#victim').remove();
                await new Promise((res) => setTimeout(res, 30));
                return {
                    calls,
                    type: recs && recs[0] && recs[0].type,
                    targetTag: recs && recs[0] && recs[0].target && recs[0].target.tagName,
                    removedLen: recs && recs[0] && recs[0].removedNodes.length,
                    removedId: recs && recs[0] && recs[0].removedNodes[0] && recs[0].removedNodes[0].id,
                };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("mutation observer eval resolves");
        assert_eq!(out["calls"], serde_json::json!(1));
        assert_eq!(out["type"], serde_json::json!("childList"));
        assert_eq!(out["targetTag"], serde_json::json!("UL")); // spec: target is the parent
        assert_eq!(out["removedLen"], serde_json::json!(1));
        assert_eq!(out["removedId"], serde_json::json!("victim"));
    }

    #[test]
    fn mutation_observer_character_data_on_text_content_set() {
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/".to_string(),
            "<html><body><p id=\"t\">old words</p></body></html>",
        );
        let js = r##"
            (async () => {
                let calls = 0; let recs = null;
                const mo = new MutationObserver((records) => { calls++; recs = records; });
                const el = document.querySelector('#t');
                mo.observe(el, { characterData: true, characterDataOldValue: true });
                el.textContent = 'new words';
                await new Promise((res) => setTimeout(res, 30));
                return {
                    calls,
                    type: recs && recs[0] && recs[0].type,
                    oldValue: recs && recs[0] && recs[0].oldValue,
                };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("mutation observer eval resolves");
        assert_eq!(out["calls"], serde_json::json!(1));
        assert_eq!(out["type"], serde_json::json!("characterData"));
        assert_eq!(out["oldValue"], serde_json::json!("old words"));
    }

    // ── SPA runtime tier ─────────────────────────────────────────────────────
    // Session history + live location, the EventTarget registry, heuristic
    // matchMedia, and the serviceWorker stub — what client-side routers and
    // page init observe. All in-session: navigation rewrites location and
    // fires the events a router listens for; no document load leaves an eval.

    #[test]
    fn history_pushstate_rewrites_location_and_grows_length() {
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/shop".to_string(),
            "<html><body></body></html>",
        );
        let js = r##"
            (() => {
                let popstateFired = 0;
                window.addEventListener('popstate', () => { popstateFired++; });
                history.pushState({ page: 2 }, '', '/shop?page=2&t=sofa#reviews');
                const after = {
                    href: location.href,
                    pathname: location.pathname,
                    search: location.search,
                    hash: location.hash,
                    length: history.length,
                    state: history.state,
                    popstateFired,
                };
                return after;
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("pushstate eval runs");
        assert_eq!(
            out["href"],
            serde_json::json!("https://example.test/shop?page=2&t=sofa#reviews")
        );
        assert_eq!(out["pathname"], serde_json::json!("/shop"));
        assert_eq!(out["search"], serde_json::json!("?page=2&t=sofa"));
        assert_eq!(out["hash"], serde_json::json!("#reviews"));
        assert_eq!(out["length"], serde_json::json!(2));
        assert_eq!(out["state"], serde_json::json!({ "page": 2 }));
        // pushState must NOT fire popstate (spec).
        assert_eq!(out["popstateFired"], serde_json::json!(0));
    }

    #[test]
    fn history_replace_state_swaps_without_growing() {
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/a".to_string(),
            "<html><body></body></html>",
        );
        let js = r##"
            (() => {
                history.replaceState({ tab: 'b' }, '', '/b');
                return {
                    href: location.href,
                    length: history.length,
                    state: history.state,
                };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("replaceState eval runs");
        assert_eq!(out["href"], serde_json::json!("https://example.test/b"));
        assert_eq!(out["length"], serde_json::json!(1));
        assert_eq!(out["state"], serde_json::json!({ "tab": "b" }));
    }

    #[test]
    fn history_back_fires_popstate_with_restored_state() {
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/start".to_string(),
            "<html><body></body></html>",
        );
        let js = r##"
            (() => {
                const events = [];
                window.addEventListener('popstate', (e) => {
                    events.push({ state: e.state, pathname: location.pathname });
                });
                history.pushState({ step: 1 }, '', '/next');
                history.pushState({ step: 2 }, '', '/last');
                history.back();
                const afterBack = { pathname: location.pathname, state: history.state, length: history.length };
                history.back();
                history.forward();
                return { events, afterBack, finalPathname: location.pathname };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("back/forward eval runs");
        // Two backs: /next then /start; the forward returns to /next.
        assert_eq!(out["events"], serde_json::json!([
            { "state": { "step": 1 }, "pathname": "/next" },
            { "state": null, "pathname": "/start" },
            { "state": { "step": 1 }, "pathname": "/next" },
        ]));
        assert_eq!(out["afterBack"]["pathname"], serde_json::json!("/next"));
        assert_eq!(out["afterBack"]["state"], serde_json::json!({ "step": 1 }));
        assert_eq!(out["afterBack"]["length"], serde_json::json!(3));
        assert_eq!(out["finalPathname"], serde_json::json!("/next"));
    }

    #[test]
    fn window_event_dispatch_runs_listeners_and_honors_stop() {
        let mut rt = crate::Runtime::new();
        let page = Page::new("https://example.test/".to_string(), "<html><body></body></html>");
        let js = r##"
            (() => {
                const calls = [];
                const a = (e) => { calls.push(['a', e.type, e.target === window, e.isTrusted]); };
                const b = (e) => { calls.push(['b']); e.stopImmediatePropagation(); };
                const c = () => { calls.push(['c']); };
                window.addEventListener('app:ready', a);
                window.addEventListener('app:ready', b);
                window.addEventListener('app:ready', c);
                const ok = window.dispatchEvent(new Event('app:ready', { bubbles: true }));
                // A second dispatch after removing `a` — dedup: re-adding a
                // must not double-register.
                window.addEventListener('app:ready', a);
                window.removeEventListener('app:ready', a);
                window.dispatchEvent(new Event('app:ready'));
                // CustomEvent carries detail.
                let detailSeen = null;
                window.addEventListener('app:data', (e) => { detailSeen = e.detail; });
                window.dispatchEvent(new CustomEvent('app:data', { detail: { n: 7 } }));
                return { ok, calls, detailSeen };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("event dispatch eval runs");
        assert_eq!(out["ok"], serde_json::json!(true));
        // First dispatch: a runs, b's stopImmediatePropagation keeps c out.
        // Second dispatch: only b runs (a was removed).
        assert_eq!(out["calls"], serde_json::json!([
            ["a", "app:ready", true, false],
            ["b"],
            ["b"],
        ]));
        assert_eq!(out["detailSeen"], serde_json::json!({ "n": 7 }));
    }

    #[test]
    fn element_and_document_dispatch_with_window_endpoint() {
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/".to_string(),
            "<html><body><div id=\"card\">x</div></body></html>",
        );
        let js = r##"
            (() => {
                const el = document.querySelector('#card');
                const order = [];
                // window non-capture listener sees BUBBLING element dispatches
                // (the bubble endpoint) even though the bridge DOM doesn't
                // walk; a non-bubbling event stays on its target.
                window.addEventListener('card:tap', () => { order.push('window'); });
                el.addEventListener('card:tap', (e) => {
                    order.push('el');
                    el.tapDetail = e.detail;
                    el.targetOk = e.target === el;
                });
                document.addEventListener('doc:ready', (e) => {
                    order.push('doc');
                    document.readyDetail = e.detail;
                });
                // bubbling tap reaches window; non-bubbling ready does not.
                el.dispatchEvent(new CustomEvent('card:tap', { detail: 42, bubbles: true }));
                document.dispatchEvent(new CustomEvent('doc:ready', { detail: 'go' }));
                return {
                    order,
                    tapDetail: el.tapDetail,
                    targetOk: el.targetOk,
                    readyDetail: document.readyDetail,
                };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("element dispatch eval runs");
        assert_eq!(out["order"], serde_json::json!(["el", "window", "doc"]));
        assert_eq!(out["tapDetail"], serde_json::json!(42));
        assert_eq!(out["targetOk"], serde_json::json!(true));
        assert_eq!(out["readyDetail"], serde_json::json!("go"));
    }

    #[test]
    fn matchmedia_evaluates_against_the_viewport() {
        let mut rt = crate::Runtime::new();
        let page = Page::new("https://example.test/".to_string(), "<html><body></body></html>");
        let js = r##"
            (() => {
                const probe = (q) => {
                    const m = window.matchMedia(q);
                    return { matches: m.matches, media: m.media, callable: typeof m.addEventListener === 'function' };
                };
                return {
                    wide: probe('(min-width: 1024px)'),
                    narrow: probe('(max-width: 600px)'),
                    dark: probe('(prefers-color-scheme: dark)'),
                    light: probe('(prefers-color-scheme: light)'),
                    landscape: probe('(orientation: landscape)'),
                    compound: probe('screen and (min-width: 1280px) and (max-width: 1920px)'),
                    hover: probe('(hover: hover)'),
                    touchPointer: probe('(pointer: coarse)'),
                };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("matchMedia eval runs");
        // Viewport is 1920x937 (wired in build_globals).
        assert_eq!(out["wide"]["matches"], serde_json::json!(true));
        assert_eq!(out["wide"]["media"], serde_json::json!("(min-width: 1024px)"));
        assert_eq!(out["narrow"]["matches"], serde_json::json!(false));
        assert_eq!(out["dark"]["matches"], serde_json::json!(false));
        assert_eq!(out["light"]["matches"], serde_json::json!(true));
        assert_eq!(out["landscape"]["matches"], serde_json::json!(true));
        assert_eq!(out["compound"]["matches"], serde_json::json!(true));
        assert_eq!(out["hover"]["matches"], serde_json::json!(true));
        assert_eq!(out["touchPointer"]["matches"], serde_json::json!(false));
        for k in ["wide", "narrow", "dark"] {
            assert_eq!(out[k]["callable"], serde_json::json!(true), "{k} callable");
        }
    }

    #[test]
    fn serviceworker_register_and_ready_resolve() {
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/app".to_string(),
            "<html><body></body></html>",
        );
        let js = r##"
            (async () => {
                const sw = navigator.serviceWorker;
                const reg = await sw.register('/sw.js', { scope: '/app/' });
                const scope = reg.scope;
                const unreg = await reg.unregister();
                const ready = await sw.ready;
                return {
                    hasSw: typeof sw === 'object' && sw !== null,
                    controller: sw.controller,
                    registerOk: reg !== null && typeof reg === 'object',
                    scope,
                    updateViaCache: reg.updateViaCache,
                    active: reg.active,
                    unreg,
                    readyOk: ready !== null && typeof ready === 'object',
                    readyScope: ready.scope,
                };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("serviceWorker eval resolves");
        assert_eq!(out["hasSw"], serde_json::json!(true));
        assert_eq!(out["controller"], serde_json::Value::Null);
        assert_eq!(out["registerOk"], serde_json::json!(true));
        assert_eq!(out["scope"], serde_json::json!("https://example.test/app/"));
        assert_eq!(out["updateViaCache"], serde_json::json!("imports"));
        assert_eq!(out["active"], serde_json::Value::Null);
        assert_eq!(out["unreg"], serde_json::json!(true));
        assert_eq!(out["readyOk"], serde_json::json!(true));
        assert_eq!(out["readyScope"], serde_json::json!("https://example.test/"));
    }

    #[test]
    fn scrollby_dispatches_a_scroll_event_on_window() {
        let mut rt = crate::Runtime::new();
        let page = Page::new("https://example.test/".to_string(), "<html><body></body></html>");
        let js = r##"
            (() => {
                let scrollEvents = 0;
                let scrollYSeen = -1;
                window.addEventListener('scroll', (e) => {
                    scrollEvents++;
                    scrollYSeen = window.scrollY;
                });
                window.scrollBy(0, 120);
                window.scrollBy(0, 30);
                return { scrollEvents, scrollYSeen, finalY: window.scrollY };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("scroll event eval runs");
        assert_eq!(out["scrollEvents"], serde_json::json!(2));
        assert_eq!(out["scrollYSeen"], serde_json::json!(150));
        assert_eq!(out["finalY"], serde_json::json!(150));
    }

    // ── firing 16: same-eval DOM mutation + interaction tier ──────────────

    /// `el.innerHTML = ...` followed by `querySelector` sees the new node —
    /// the setter mutates the live tree and invalidates the cached parse so
    /// the next query re-parses from the mutated serialization.
    #[test]
    fn inner_html_setter_updates_subsequent_queries() {
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/".to_string(),
            "<html><body><div id='root'><p>old</p></div></body></html>",
        );
        let js = r##"
            (() => {
                const root = document.querySelector('#root');
                root.innerHTML = '<span class="new">fresh</span><b>bold</b>';
                // Old <p> gone, new nodes present.
                const p = root.querySelector('p');
                const span = root.querySelector('.new');
                const b = root.querySelector('b');
                return {
                    pGone: p === null,
                    spanText: span ? span.textContent : null,
                    bText: b ? b.textContent : null,
                    inner: root.innerHTML,
                };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("innerHTML setter eval runs");
        assert_eq!(out["pGone"], serde_json::json!(true));
        assert_eq!(out["spanText"], serde_json::json!("fresh"));
        assert_eq!(out["bText"], serde_json::json!("bold"));
        assert!(out["inner"].as_str().unwrap().contains("fresh"));
    }

    /// The innerHTML getter reflects the pre-mutation subtree, and after a
    /// mutation it reflects the new one (live read).
    #[test]
    fn inner_html_getter_is_live() {
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/".to_string(),
            "<html><body><div id='a'><p>one</p></div></body></html>",
        );
        let js = r##"
            (() => {
                const a = document.querySelector('#a');
                const before = a.innerHTML;
                a.innerHTML = '<i>two</i>';
                const after = a.innerHTML;
                return { before, after };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("innerHTML getter eval runs");
        assert!(out["before"].as_str().unwrap().contains("one"));
        assert!(out["after"].as_str().unwrap().contains("two"));
        assert!(!out["after"].as_str().unwrap().contains("one"));
    }

    /// `textContent = ...` replaces the subtree with one text node; the
    /// getter returns it.
    #[test]
    fn text_content_setter_replaces_subtree() {
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/".to_string(),
            "<html><body><div id='a'><p>hi</p><span>x</span></div></body></html>",
        );
        let js = r##"
            (() => {
                const a = document.querySelector('#a');
                a.textContent = 'REPLACED';
                return {
                    text: a.textContent,
                    childrenGone: a.querySelector('p') === null && a.querySelector('span') === null,
                };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("textContent setter eval runs");
        assert_eq!(out["text"], serde_json::json!("REPLACED"));
        assert_eq!(out["childrenGone"], serde_json::json!(true));
    }

    /// `appendChild` of a created element grafts it; tree order is observable
    /// via the parent's innerHTML; `createTextNode` + `appendChild` adds text.
    #[test]
    fn append_child_grafts_and_orders() {
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/".to_string(),
            "<html><body><div id='root'><p>first</p></div></body></html>",
        );
        let js = r##"
            (() => {
                const root = document.querySelector('#root');
                const span = document.createElement('span');
                span.innerHTML = 'appended';
                root.appendChild(span);
                root.appendChild(document.createTextNode('+tail'));
                const spanNow = root.querySelector('span');
                return {
                    order: root.innerHTML,
                    spanText: spanNow ? spanNow.textContent : null,
                };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("appendChild eval runs");
        let order = out["order"].as_str().unwrap();
        // <p> first, then the <span>, then the text tail.
        let p_pos = order.find("first").unwrap();
        let span_pos = order.find("appended").unwrap();
        let tail_pos = order.find("+tail").unwrap();
        assert!(p_pos < span_pos && span_pos < tail_pos, "order: {}", order);
        assert_eq!(out["spanText"], serde_json::json!("appended"));
    }

    /// `el.remove()` detaches the subtree; later document queries no longer
    /// see it and the parent's innerHTML loses it.
    #[test]
    fn remove_detaches_from_later_queries() {
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/".to_string(),
            "<html><body><div id='a'><p class='gone'>x</p><p class='stay'>y</p></div></body></html>",
        );
        let js = r##"
            (() => {
                const gone = document.querySelector('.gone');
                gone.remove();
                return {
                    docGone: document.querySelector('.gone') === null,
                    stayPresent: document.querySelector('.stay') !== null,
                    parentHtml: document.querySelector('#a').innerHTML,
                };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("remove eval runs");
        assert_eq!(out["docGone"], serde_json::json!(true));
        assert_eq!(out["stayPresent"], serde_json::json!(true));
        assert!(!out["parentHtml"].as_str().unwrap().contains("gone"));
        assert!(out["parentHtml"].as_str().unwrap().contains("stay"));
    }

    /// `el.click()` runs a handler registered via addEventListener, and the
    /// bubbling click reaches the document and window listeners.
    #[test]
    fn click_dispatches_through_event_registry() {
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/".to_string(),
            "<html><body><button id='btn'>Go</button></body></html>",
        );
        let js = r##"
            (() => {
                let elementHits = 0;
                let docHits = 0;
                let windowHits = 0;
                let typeSeen = '';
                let btn = document.querySelector('#btn');
                btn.addEventListener('click', (e) => { elementHits++; typeSeen = e.type; });
                document.addEventListener('click', () => { docHits++; });
                window.addEventListener('click', () => { windowHits++; });
                btn.click();
                return { elementHits, docHits, windowHits, typeSeen };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("click eval runs");
        assert_eq!(out["elementHits"], serde_json::json!(1));
        assert_eq!(out["docHits"], serde_json::json!(1));
        assert_eq!(out["windowHits"], serde_json::json!(1));
        assert_eq!(out["typeSeen"], serde_json::json!("click"));
    }

    #[test]
    fn websocket_is_a_constructible_function() {
        let mut rt = crate::Runtime::new();
        let page = Page::new("https://example.test/".to_string(), "<html><body></body></html>");
        let js = r##"
            (() => {
                const ws = new WebSocket('wss://example.test/socket');
                return {
                    typeofCtor: typeof WebSocket,
                    typeofInstance: typeof ws,
                    url: ws.url,
                    readyState: ws.readyState,
                    bufferedAmount: ws.bufferedAmount,
                    protocol: ws.protocol,
                    extensions: ws.extensions,
                    binaryType: ws.binaryType,
                    onopen: ws.onopen,
                    ctorConnecting: WebSocket.CONNECTING,
                    ctorOpen: WebSocket.OPEN,
                    ctorClosing: WebSocket.CLOSING,
                    ctorClosed: WebSocket.CLOSED,
                    protoConnecting: WebSocket.prototype.CONNECTING,
                    protoClosed: WebSocket.prototype.CLOSED,
                };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("websocket ctor eval runs");
        assert_eq!(out["typeofCtor"], serde_json::json!("function"));
        assert_eq!(out["typeofInstance"], serde_json::json!("object"));
        assert_eq!(out["url"], serde_json::json!("wss://example.test/socket"));
        assert_eq!(out["readyState"], serde_json::json!(0));
        assert_eq!(out["bufferedAmount"], serde_json::json!(0));
        assert_eq!(out["protocol"], serde_json::json!(""));
        assert_eq!(out["extensions"], serde_json::json!(""));
        assert_eq!(out["binaryType"], serde_json::json!("blob"));
        assert_eq!(out["onopen"], serde_json::Value::Null);
        // Constants on both the constructor and the prototype, per spec.
        assert_eq!(out["ctorConnecting"], serde_json::json!(0));
        assert_eq!(out["ctorOpen"], serde_json::json!(1));
        assert_eq!(out["ctorClosing"], serde_json::json!(2));
        assert_eq!(out["ctorClosed"], serde_json::json!(3));
        assert_eq!(out["protoConnecting"], serde_json::json!(0));
        assert_eq!(out["protoClosed"], serde_json::json!(3));
    }

    #[test]
    fn websocket_send_accumulates_buffered_amount_while_connecting() {
        let mut rt = crate::Runtime::new();
        let page = Page::new("https://example.test/".to_string(), "<html><body></body></html>");
        let js = r##"
            (() => {
                const ws = new WebSocket('wss://example.test/socket');
                ws.send('hello');       // 5 bytes
                ws.send(' world');      // 6 bytes
                const afterTwo = ws.bufferedAmount;
                ws.send('!');           // 1 byte
                return { afterTwo, final: ws.bufferedAmount, readyState: ws.readyState };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("websocket send eval runs");
        assert_eq!(out["afterTwo"], serde_json::json!(11));
        assert_eq!(out["final"], serde_json::json!(12));
        assert_eq!(out["readyState"], serde_json::json!(0));
    }

    #[test]
    fn websocket_close_transitions_to_closed_and_drops_buffer() {
        let mut rt = crate::Runtime::new();
        let page = Page::new("https://example.test/".to_string(), "<html><body></body></html>");
        let js = r##"
            (() => {
                const ws = new WebSocket('wss://example.test/socket');
                ws.send('queued');
                ws.close();
                return { readyState: ws.readyState, bufferedAmount: ws.bufferedAmount };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("websocket close eval runs");
        assert_eq!(out["readyState"], serde_json::json!(3));
        assert_eq!(out["bufferedAmount"], serde_json::json!(0));
    }

    #[test]
    fn websocket_send_after_close_throws_invalid_state_error() {
        let mut rt = crate::Runtime::new();
        let page = Page::new("https://example.test/".to_string(), "<html><body></body></html>");
        let js = r##"
            (() => {
                const ws = new WebSocket('wss://example.test/socket');
                ws.close();
                try {
                    ws.send('too late');
                    return { threw: false };
                } catch (e) {
                    return { threw: true, name: e.name, readyState: ws.readyState };
                }
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("websocket throw eval runs");
        assert_eq!(out["threw"], serde_json::json!(true));
        assert_eq!(out["name"], serde_json::json!("InvalidStateError"));
        assert_eq!(out["readyState"], serde_json::json!(3));
    }

    #[test]
    fn element_matches_and_closest_run_selectors() {
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/".to_string(),
            "<html><body><div class='card outer'><div class='card inner'>\
             <a href='/x' id='lnk'>x</a></div></div></body></html>",
        );
        let js = r##"
            (() => {
                const a = document.querySelector('#lnk');
                const c = a.closest('.inner');
                return {
                    matchesSelf: a.matches("#lnk"),
                    matchesAttr: a.matches("a[href='/x']"),
                    matchesMiss: a.matches('span'),
                    badSelector: a.matches('a['),
                    closestClass: c ? c.className : null,
                    closestOuter: a.closest('.outer') ? a.closest('.outer').className : null,
                    closestSelf: a.closest('a') ? a.closest('a').id : null,
                    closestMiss: a.closest('section'),
                };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("matches/closest eval runs");
        assert_eq!(out["matchesSelf"], serde_json::json!(true));
        assert_eq!(out["matchesAttr"], serde_json::json!(true));
        assert_eq!(out["matchesMiss"], serde_json::json!(false));
        assert_eq!(out["badSelector"], serde_json::json!(false)); // no-throw contract
        assert_eq!(out["closestClass"], serde_json::json!("card inner"));
        assert_eq!(out["closestOuter"], serde_json::json!("card outer"));
        assert_eq!(out["closestSelf"], serde_json::json!("lnk"));
        assert_eq!(out["closestMiss"], serde_json::Value::Null);
    }

    #[test]
    fn document_init_probes_report_a_visible_focused_page() {
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/".to_string(),
            "<html><body><p>hi</p></body></html>",
        );
        let js = r##"
            (() => ({
                visibilityState: document.visibilityState,
                hidden: document.hidden,
                webkitVisibilityState: document.webkitVisibilityState,
                webkitHidden: document.webkitHidden,
                activeTag: document.activeElement ? document.activeElement.tagName : null,
                hasFocus: document.hasFocus(),
            }))()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("document probes eval runs");
        assert_eq!(out["visibilityState"], serde_json::json!("visible"));
        assert_eq!(out["hidden"], serde_json::json!(false));
        assert_eq!(out["webkitVisibilityState"], serde_json::json!("visible"));
        assert_eq!(out["webkitHidden"], serde_json::json!(false));
        assert_eq!(out["activeTag"], serde_json::json!("BODY"));
        assert_eq!(out["hasFocus"], serde_json::json!(true));
    }

    #[test]
    fn window_name_persists_across_evals_on_one_context() {
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/".to_string(),
            "<html><body></body></html>",
        );
        // First eval writes the context name; the second (a fresh V8 context,
        // like a navigation would build) must read it back through the shared
        // per-tab cell.
        let out = rt
            .eval_with_page(Some(&page), "window.name = 'ctx-1'; window.name")
            .expect("name set eval runs");
        assert_eq!(out, serde_json::json!("ctx-1"));
        let out = rt
            .eval_with_page(Some(&page), "window.name")
            .expect("name read eval runs");
        assert_eq!(out, serde_json::json!("ctx-1"));
        // Assignment is the accessor's setter, not a plain data prop.
        let out = rt
            .eval_with_page(Some(&page), "window.name = ''; window.name")
            .expect("name clear eval runs");
        assert_eq!(out, serde_json::json!(""));
        // Sanity: a pageless eval gets a fresh, empty cell.
        let out = rt
            .eval_with_page(None, "window.name")
            .expect("about:blank name eval runs");
        assert_eq!(out, serde_json::json!(""));
    }

    #[test]
    fn mutation_writeback_publishes_across_eval_outcomes() {
        // Cross-eval DOM persistence: a mutating eval publishes the mutated
        // serialization into the page's writeback slot, tagged with the html
        // it started from; a read-only eval leaves the slot alone; and a
        // script that mutates THEN throws still publishes — a real tab keeps
        // mutations made before the throw.
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/".to_string(),
            "<html><body><p>one</p></body></html>",
        );
        // Read-only eval: the slot stays empty.
        let out = rt
            .eval_with_page(Some(&page), "document.querySelector('p').textContent")
            .expect("read eval runs");
        assert_eq!(out, serde_json::json!("one"));
        assert!(page.writeback.lock().expect("writeback lock").is_none());

        // Mutating eval: the slot carries the mutated document, from = the
        // pre-eval html (the tab owner's adoption check).
        let out = rt
            .eval_with_page(
                Some(&page),
                "document.body.innerHTML = '<p>one</p><div id=\"added\">two</div>'; document.querySelectorAll('div').length",
            )
            .expect("mutate eval runs");
        assert_eq!(out, serde_json::json!(1));
        let wb = page
            .writeback
            .lock()
            .expect("writeback lock")
            .clone()
            .expect("a mutation published");
        assert_eq!(wb.from, "<html><body><p>one</p></body></html>");
        assert!(
            wb.html.contains("added"),
            "writeback carries the mutated document: {}",
            wb.html
        );

        // The tab owner adopting the slot and feeding the written html into
        // the next eval's Page is exactly what cross-eval persistence means:
        // a second context observes the mutation.
        let page2 = Page {
            html: wb.html.clone(),
            ..Page::new("https://example.test/".to_string(), String::new())
        };
        let out = rt
            .eval_with_page(Some(&page2), "document.querySelectorAll('#added').length")
            .expect("second-context read runs");
        assert_eq!(out, serde_json::json!(1));

        // Throw-after-mutate: the eval errors, the mutation still publishes.
        let err = rt
            .eval_with_page(
                Some(&page),
                "document.body.innerHTML = '<span>x</span>'; throw new Error('boom');",
            )
            .expect_err("throwing eval errors");
        match err {
            crate::Error::Threw(msg) => assert_eq!(msg, "boom", "sync throw carries its message"),
            other => panic!("sync throw surfaces as Threw, got {other:?}"),
        }
        let wb = page
            .writeback
            .lock()
            .expect("writeback lock")
            .clone()
            .expect("throw-after-mutate still publishes");
        assert!(
            wb.html.contains("<span>x</span>"),
            "the pre-throw mutation is in the writeback: {}",
            wb.html
        );
    }

    /// Sync-throw message extraction (firing 23): compile + run sit under a
    /// TryCatch, so a throwing eval reports the exception's message — the
    /// SAME rendering the promise-rejection path uses — instead of the
    /// "<v8 gave no message>" default. Error objects give their `message`,
    /// thrown values their string form, syntax errors the SyntaxError text.
    #[test]
    fn sync_throws_and_compile_errors_carry_their_messages() {
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/".to_string(),
            "<html><body><p>one</p></body></html>",
        );

        // Error object: the `message` property, like a rejection reason.
        match rt
            .eval_with_page(Some(&page), "throw new Error('sync-boom');")
            .expect_err("throwing eval errors")
        {
            crate::Error::Threw(msg) => assert_eq!(msg, "sync-boom"),
            other => panic!("Threw expected, got {other:?}"),
        }

        // A plain thrown value stringifies (the rejection path does too).
        match rt
            .eval_with_page(Some(&page), "throw 'plain-string';")
            .expect_err("string throw errors")
        {
            crate::Error::Threw(msg) => assert_eq!(msg, "plain-string"),
            other => panic!("Threw expected, got {other:?}"),
        }

        // A TypeError from a bad property read carries the engine's message.
        match rt
            .eval_with_page(Some(&page), "null.noSuchProperty;")
            .expect_err("TypeError eval errors")
        {
            crate::Error::Threw(msg) => {
                assert!(
                    msg.contains("noSuchProperty"),
                    "TypeError message names the property: {msg}"
                );
            }
            other => panic!("Threw expected, got {other:?}"),
        }

        // Syntax errors surface as Compile with the SyntaxError text.
        match rt
            .eval_with_page(Some(&page), "var 1bad = ;")
            .expect_err("syntax-error eval fails to compile")
        {
            crate::Error::Compile(msg) => {
                assert!(
                    !msg.is_empty() && msg != "<v8 gave no message>",
                    "syntax error carries real text: {msg}"
                );
            }
            other => panic!("Compile expected, got {other:?}"),
        }

        // Sanity: the rejection path reads identically for the same value.
        match rt
            .eval_with_page(Some(&page), "Promise.reject(new Error('sync-boom'));")
            .expect_err("rejecting eval errors")
        {
            crate::Error::Threw(msg) => assert_eq!(msg, "sync-boom"),
            other => panic!("Threw expected, got {other:?}"),
        }
    }

    /// The attribute-mutator trio over a RESIDENT element: setAttribute lands
    /// in the live tree — visible to getAttribute/hasAttribute, `[attr]`
    /// selector matching, and classList within the SAME eval; mutating the
    /// id itself moves `#` matching (the se_dom node-value rebuild keeps
    /// scraper's memoized id/class caches honest); removeAttribute detaches
    /// from every view and is silent when the attribute is already absent.
    #[test]
    fn set_attribute_mutates_live_tree_and_selector_matching() {
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/".to_string(),
            "<html><body><div id='a' class='one'><p>x</p></div></body></html>",
        );
        let js = r##"
            (() => {
                const a = document.querySelector('#a');
                a.setAttribute('data-x', '1');
                const added = {
                    get: a.getAttribute('data-x'),
                    has: a.hasAttribute('data-x'),
                    bySelector: document.querySelectorAll('[data-x="1"]').length,
                };
                a.setAttribute('id', 'b');
                const idMoved = document.querySelectorAll('#b').length === 1
                    && document.querySelectorAll('#a').length === 0
                    && a.getAttribute('id') === 'b';
                a.setAttribute('class', 'two');
                const classMoved = a.classList.contains('two') && !a.classList.contains('one');
                a.setAttribute('data-x', '2');
                const replaced = a.getAttribute('data-x') === '2'
                    && document.querySelectorAll('[data-x="2"]').length === 1;
                a.removeAttribute('data-x');
                const removed = {
                    get: a.getAttribute('data-x'),
                    has: a.hasAttribute('data-x'),
                    bySelector: document.querySelectorAll('[data-x]').length,
                };
                a.removeAttribute('data-x'); // silent no-op, like the spec
                return { added, idMoved, classMoved, replaced, removed };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("attribute mutator eval runs");
        assert_eq!(out["added"]["get"], serde_json::json!("1"));
        assert_eq!(out["added"]["has"], serde_json::json!(true));
        assert_eq!(out["added"]["bySelector"], serde_json::json!(1));
        assert_eq!(out["idMoved"], serde_json::json!(true));
        assert_eq!(out["classMoved"], serde_json::json!(true));
        assert_eq!(out["replaced"], serde_json::json!(true));
        assert_eq!(out["removed"]["get"], serde_json::json!(null));
        assert_eq!(out["removed"]["has"], serde_json::json!(false));
        assert_eq!(out["removed"]["bySelector"], serde_json::json!(0));
        // The mutations rode mutate(), so the writeback slot published — the
        // cross-eval half se-serve adopts into the tab.
        let wb = page
            .writeback
            .lock()
            .expect("writeback lock")
            .clone()
            .expect("setAttribute publishes a writeback");
        assert!(
            wb.html.contains("id=\"b\""),
            "the mutated attribute is in the writeback: {}",
            wb.html
        );
    }

    /// The firing-21 probe idiom now works end to end: setAttribute on a
    /// synthetic (createElement, not-yet-grafted) wrapper lands on the
    /// snapshot `appendChild` serializes, so the attribute rides the graft
    /// into the live tree — the build-an-element idiom provider scripts use.
    #[test]
    fn set_attribute_on_synthetic_wrapper_rides_the_graft() {
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/".to_string(),
            "<html><body><p>anchor</p></body></html>",
        );
        let js = r##"
            (() => {
                const d = document.createElement('div');
                d.setAttribute('id', 'made');
                d.setAttribute('data-role', 'card');
                d.innerHTML = 'x';
                const hasBefore = d.hasAttribute('data-role');
                document.body.appendChild(d);
                const grafted = document.querySelector('#made');
                return {
                    hasBefore,
                    bySelector: document.querySelectorAll('#made').length,
                    role: grafted ? grafted.getAttribute('data-role') : null,
                    text: grafted ? grafted.textContent : null,
                };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("synthetic setAttribute eval runs");
        assert_eq!(out["hasBefore"], serde_json::json!(true));
        assert_eq!(out["bySelector"], serde_json::json!(1));
        assert_eq!(out["role"], serde_json::json!("card"));
        assert_eq!(out["text"], serde_json::json!("x"));
    }

    #[test]
    fn beacon_worker_shared_worker_image_shapes() {
        let mut rt = crate::Runtime::new();
        let page = Page::new(
            "https://example.test/".to_string(),
            "<html><body></body></html>",
        );
        let js = r##"
            (() => {
                const w = new Worker('/w.js');
                const sw = new SharedWorker('/sw.js');
                const img = new Image();
                img.src = 'https://example.test/pixel.gif';
                w.postMessage('ping');
                return {
                    workerType: typeof Worker,
                    sharedType: typeof SharedWorker,
                    imageType: typeof Image,
                    wPost: typeof w.postMessage,
                    wTerm: typeof w.terminate,
                    wOnmessage: w.onmessage,
                    swPort: typeof sw.port,
                    swPortPost: typeof sw.port.postMessage,
                    imgW: img.width,
                    imgNatural: img.naturalWidth,
                    imgSrc: img.src,
                    beacon: navigator.sendBeacon('https://example.test/collect', 'd'),
                };
            })()
        "##;
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("shape constructors eval runs");
        assert_eq!(out["workerType"], serde_json::json!("function"));
        assert_eq!(out["sharedType"], serde_json::json!("function"));
        assert_eq!(out["imageType"], serde_json::json!("function"));
        assert_eq!(out["wPost"], serde_json::json!("function"));
        assert_eq!(out["wTerm"], serde_json::json!("function"));
        assert_eq!(out["wOnmessage"], serde_json::Value::Null);
        assert_eq!(out["swPort"], serde_json::json!("object"));
        assert_eq!(out["swPortPost"], serde_json::json!("function"));
        assert_eq!(out["imgW"], serde_json::json!(0));
        assert_eq!(out["imgNatural"], serde_json::json!(0));
        assert_eq!(out["imgSrc"], serde_json::json!("https://example.test/pixel.gif"));
        assert_eq!(out["beacon"], serde_json::json!(true));
    }
}

/// Page-context fetches over TLS with ALPN — the subresource-path parity
/// slice. Real Chrome negotiates h2 per origin through ALPN; the page shim's
/// https branch dispatches to `se_net::subresource_fetch` (reqwest + ALPN),
/// so these fixtures terminate TLS with `tokio-rustls` and serve either h2
/// (via the `h2` crate) or raw h1.1 depending on the negotiated ALPN. The
/// self-signed dev cert requires `Page::accepting_dev_certs` (test tier only).
#[cfg(test)]
mod tls_tests {
    use super::*;
    use std::sync::mpsc as std_mpsc;

    /// What the fixture server observed on the wire — the assertions pin the
    /// h2 wire shape (lowercase names, no hop-by-hop headers, fetch-metadata
    /// intact, query preserved) rather than only the response the page saw.
    #[derive(Debug)]
    struct SeenRequest {
        method: String,
        path: String,
        headers: Vec<(String, String)>,
    }

    impl SeenRequest {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        }
    }

    #[derive(Clone, Copy)]
    enum TlsMode {
        H2,
        H1_1,
    }

    /// One-shot TLS server: binds a loopback port, negotiates per `mode`'s
    /// ALPN, serves a single request, and reports what it saw. Runs a
    /// current_thread tokio runtime entirely inside the detached thread — the
    /// same discipline as `blocking_fetch` itself.
    fn spawn_tls_server(mode: TlsMode) -> (String, std_mpsc::Receiver<SeenRequest>) {
        let (addr_tx, addr_rx) = std_mpsc::channel();
        let (seen_tx, seen_rx) = std_mpsc::channel();
        std::thread::spawn(move || {
            use std::net::TcpListener;
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let bound = listener.local_addr().unwrap();
            addr_tx.send(bound).unwrap();
            let (socket, _) = listener.accept().unwrap();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(serve_one(socket, mode, seen_tx));
            // Listener dropped here: exactly one connection, then the thread
            // (and its runtime) exits.
        });
        let addr = addr_rx.recv().unwrap();
        (format!("https://{addr}"), seen_rx)
    }

    async fn serve_one(
        socket: std::net::TcpStream,
        mode: TlsMode,
        seen_tx: std_mpsc::Sender<SeenRequest>,
    ) {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;
        let cert_path = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/dev-localhost.crt");
        let key_path = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/dev-localhost.key");
        let certs = vec![CertificateDer::from_pem_file(cert_path).unwrap()];
        let key = PrivateKeyDer::from_pem_file(key_path).unwrap();
        let mut cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        cfg.alpn_protocols = match mode {
            TlsMode::H2 => vec![b"h2".to_vec()],
            TlsMode::H1_1 => vec![b"http/1.1".to_vec()],
        };
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(cfg));
        // `from_std` demands a non-blocking socket; a blocking accepted
        // socket wedges the reactor (handshake completes on buffered bytes,
        // then the connection stalls forever).
        socket.set_nonblocking(true).unwrap();
        let socket = TcpStream::from_std(socket).unwrap();
        let mut tls = acceptor.accept(socket).await.unwrap();
        match mode {
            TlsMode::H2 => {
                // h2 0.4: `handshake` returns the Connection itself; polling
                // `accept` drives the whole state machine, so after answering
                // we keep polling until the client hangs up — that flush is
                // what actually puts the body on the wire.
                let mut h2_conn = h2::server::Builder::new()
                    .handshake::<_, bytes::Bytes>(tls)
                    .await
                    .unwrap();
                if let Some(Ok((req, mut respond))) = h2_conn.accept().await {
                    let method = req.method().to_string();
                    let path = req.uri().path_and_query().map(|pq| pq.to_string()).unwrap();
                    let headers: Vec<(String, String)> = req
                        .headers()
                        .iter()
                        .map(|(n, v)| (n.to_string(), v.to_str().unwrap().to_string()))
                        .collect();
                    let _ = seen_tx.send(SeenRequest { method, path, headers });
                    let response = http::Response::builder()
                        .status(200)
                        .header("x-h2-marker", "yes")
                        .body(())
                        .unwrap();
                    let mut send = respond.send_response(response, false).unwrap();
                    send.send_data(bytes::Bytes::from_static(b"h2 body"), true)
                        .unwrap();
                    drop(send);
                    // Drive the connection until the client hangs up so the
                    // queued body actually flushes; a stream error ends the
                    // loop too (a spin on Some(Err) would hang the test).
                    loop {
                        match h2_conn.accept().await {
                            Some(Ok(_)) => continue,
                            _ => break,
                        }
                    }
                }
            }
            TlsMode::H1_1 => {
                // Read the request head until its blank line, then answer raw.
                let mut buf = Vec::with_capacity(8192);
                let mut chunk = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut chunk).await {
                        Ok(0) => break,
                        Ok(m) => buf.extend_from_slice(&chunk[..m]),
                        Err(_) => break,
                    }
                    if buf.len() > 64 * 1024 {
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&buf).to_string();
                let mut lines = head.split("\r\n");
                let req_line = lines.next().unwrap_or("");
                let method = req_line.split_whitespace().next().unwrap_or("").to_string();
                let path = req_line.split_whitespace().nth(1).unwrap_or("/").to_string();
                let mut headers = Vec::new();
                for line in lines {
                    if line.is_empty() {
                        break;
                    }
                    if let Some(colon) = line.find(':') {
                        headers.push((
                            line[..colon].trim().to_string(),
                            line[colon + 1..].trim().to_string(),
                        ));
                    }
                }
                let _ = seen_tx.send(SeenRequest { method, path, headers });
                let body = b"h1 body";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                tls.write_all(response.as_bytes()).await.unwrap();
                tls.write_all(body).await.unwrap();
                tls.flush().await.unwrap();
            }
        }
    }

    /// The h2 page fetch: ALPN selects h2, the response lands with its marker
    /// header, and the server sees the exact wire shape Chrome would send —
    /// lowercase header names (RFC 7540), no Connection header (hop-by-hop
    /// is forbidden on h2), fetch metadata intact, query string preserved.
    #[test]
    fn page_fetch_negotiates_h2_over_tls() {
        let (base, seen_rx) = spawn_tls_server(TlsMode::H2);
        let page = Page::new(format!("{base}/page"), "<html><body>shell</body></html>")
            .accepting_dev_certs();
        let js = r##"
            (async () => {
                const r = await fetch('/sub?q=1');
                // r.text is a raw host function: thread the [resolve, reject]
                // pair like the fetch trampoline does.
                const body = await new Promise((res, rej) => r.text([res, rej]));
                return {
                    status: r.status,
                    body,
                    marker: r.headers.get('x-h2-marker'),
                    url: r.url,
                };
            })()
        "##;
        let mut rt = crate::Runtime::new();
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("h2 fetch eval resolves");
        assert_eq!(out["status"], serde_json::json!(200));
        assert_eq!(out["body"], serde_json::json!("h2 body"));
        assert_eq!(out["marker"], serde_json::json!("yes"));
        let seen = seen_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("server saw the h2 request");
        assert_eq!(seen.method, "GET");
        assert_eq!(seen.path, "/sub?q=1", "query must survive the URL handling");
        // RFC 7540 §8.1.2: header names are lowercase on the h2 wire — the
        // page passed 'Sec-Fetch-Dest' mixed-case, the ALPN stack must not.
        assert!(
            seen.headers.iter().all(|(n, _)| n.chars().all(|c| c.is_lowercase() || c == '-' || c.is_ascii_digit())),
            "h2 wire names must be lowercase: {seen:?}"
        );
        assert!(
            seen.headers.iter().all(|(n, _)| n != "connection"),
            "hop-by-hop Connection must be stripped for h2: {seen:?}"
        );
        assert_eq!(seen.header("sec-fetch-dest"), Some("empty"));
        assert_eq!(seen.header("sec-fetch-mode"), Some("cors"));
        assert_eq!(seen.header("sec-fetch-site"), Some("same-origin"));
    }

    /// When ALPN declines h2 (origin offers only http/1.1), the same
    /// `subresource_fetch` path falls back to h1.1 and the page still gets
    /// its response — the per-origin fork a real browser takes.
    #[test]
    fn page_fetch_falls_back_to_h1_1_when_alpn_declines() {
        let (base, seen_rx) = spawn_tls_server(TlsMode::H1_1);
        let page = Page::new(format!("{base}/page"), "<html><body>shell</body></html>")
            .accepting_dev_certs();
        let js = r##"
            (async () => {
                const r = await fetch('/sub?q=1');
                const body = await new Promise((res, rej) => r.text([res, rej]));
                return { status: r.status, body };
            })()
        "##;
        let mut rt = crate::Runtime::new();
        let out = rt
            .eval_with_page(Some(&page), js)
            .expect("h1.1 fallback eval resolves");
        assert_eq!(out["status"], serde_json::json!(200));
        assert_eq!(out["body"], serde_json::json!("h1 body"));
        let seen = seen_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("server saw the h1.1 request");
        assert_eq!(seen.method, "GET");
        assert_eq!(seen.path, "/sub?q=1");
        assert_eq!(seen.header("sec-fetch-dest"), Some("empty"));
    }
}

