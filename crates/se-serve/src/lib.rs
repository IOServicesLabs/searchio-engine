//! se-serve: the sidecar's public wire surface.
//!
//! Implements the exact JSON-RPC protocol searchio's `SidecarClient` speaks
//! (see `docs/sidecar-protocol.md`): `GET /healthz`, `POST /rpc`, result
//! envelopes where every success carries a JSON *object*. Verbs beyond the
//! engine's current capability return verb-level `{"ok": false, ...}`
//! results — never transport errors — so callers degrade the same way they
//! do against the patchright sidecar's optional verbs.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub mod imgmeta;

use axum::extract::State;
use axum::response::Json;use axum::routing::{get, post};
use axum::Router;
use se_dom::Document;
use se_js::bridge::Page;
use se_net::Client as NetClient;
use serde::Deserialize;
use serde_json::{json, Value};

/// One eval request handed to the JS worker thread. `budget` caps the
/// macrotask pump: plain evals carry the bridge default; render mode passes
/// the caller's `settle_ms`. The reply also carries where page-script
/// navigation left the page (the bridge's post-settle page_url): render
/// mode's follow loop drives off it; the plain eval verb drops it (goto
/// parses, eval executes — an eval is not a navigation surface).
struct JsCmd {
    page: Option<Page>,
    js: String,
    budget: std::time::Duration,
    opts: JsOpts,
    reply: tokio::sync::oneshot::Sender<(Result<Value, String>, Option<String>)>,
}

/// Per-call JS options, carried from a verb to the actor through a task
/// local so the verb -> render -> eval call chain needs no extra arguments.
#[derive(Clone, Copy, Default)]
struct JsOpts {
    /// Settle-pump quiescence rounds (0 = run the whole budget, the default).
    quiesce: u32,
    /// Page fetch/XHR send Referer / Origin as Chrome does.
    page_referer: bool,
    /// Render with the browser-globals prelude and the `load` lifecycle.
    prelude: bool,
    /// External scripts: fetched together, non-content hosts skipped,
    /// wider caps (`script_pipeline: true`).
    pipeline: bool,
    /// Render against the JS-side live DOM (`live_dom: true`; needs `prelude`).
    live_dom: bool,
    /// Page fetches share one keep-alive transport and settle from the
    /// event-loop pump instead of each blocking the isolate (`fetch_pool`).
    fetch_pool: bool,
    /// Run `<script type="module">` (static and dynamic imports) and skip
    /// `nomodule` fallbacks (`modules: true`; needs `prelude`).
    modules: bool,
    /// Settle-pump quiet window in ms (`quiet_ms`; 0 = off): a still page
    /// stops waiting on far one-shot timers.
    quiet_ms: u64,
    /// Classic scripts run as real Scripts with V8's code cache kept per
    /// URL + content (`code_cache: true`; needs `prelude`).
    code_cache: bool,
}

/// `script_pipeline` caps: a modern page ships its app as a dozen chunks and
/// one of them is routinely over the 512 KB the serial path allows.
const PIPELINE_MAX_EXTERNALS: usize = 24;
const PIPELINE_MAX_SCRIPT_BYTES: usize = 2 * 1024 * 1024;
const PIPELINE_MAX_TOTAL_BYTES: usize = 6 * 1024 * 1024;

/// Hosts whose scripts measure, advertise or ask for consent. They draw no
/// content, they cost a round trip each, and several of them are the sensor
/// scripts that judge the client that runs them.
fn noncontent_script(url: &str) -> bool {
    const HOSTS: &[&str] = &[
        "google-analytics.com", "googletagmanager.com", "googletagservices.com",
        "doubleclick.net", "googlesyndication.com", "googleadservices.com",
        "connect.facebook.net", "hotjar.com", "segment.com", "segment.io",
        "amplitude.com", "mixpanel.com", "sentry-cdn.com", "sentry.io",
        "newrelic.com", "nr-data.net", "clarity.ms", "optimizely.com",
        "intercom.io", "intercomcdn.com", "fullstory.com", "scorecardresearch.com",
        "quantserve.com", "cookiebot.com", "onetrust.com", "cookielaw.org",
        "hs-scripts.com", "hs-analytics.net", "hsadspixel.net", "bat.bing.com",
        "datadoghq-browser-agent.com", "analytics.tiktok.com", "snap.licdn.com",
        "static.ads-twitter.com", "chartbeat.com", "criteo.net", "taboola.com",
        "outbrain.com", "amazon-adsystem.com", "adnxs.com", "matomo.cloud",
        "plausible.io", "usercentrics.eu", "trustarc.com", "crazyegg.com",
    ];
    let Ok(u) = url::Url::parse(url) else { return false };
    let Some(host) = u.host_str().map(str::to_ascii_lowercase) else { return false };
    if HOSTS.iter().any(|d| host == *d || host.ends_with(&format!(".{d}"))) {
        return true;
    }
    let path = u.path();
    (host.ends_with("google.com") || host.ends_with("gstatic.com")) && path.contains("/recaptcha/")
}

/// The browser globals a page expects before its first script (see the file).
const PRELUDE_JS: &str = include_str!("prelude.js");
/// The JS-side live DOM installed by `live_dom` renders (see the file head).
const LIVEDOM_JS: &str = include_str!("livedom.js");

tokio::task_local! {
    static JS_OPTS: JsOpts;
}

/// Hard ceiling on one eval: its settle budget plus this grace. Past it the
/// watchdog terminates the script (a `while(true){}` used to pin the single
/// JS thread, and with it every tab, for the life of the process).
/// SE_JS_GRACE_MS overrides; 0 turns the watchdog off.
fn js_grace() -> Option<std::time::Duration> {
    let ms: u64 = std::env::var("SE_JS_GRACE_MS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(20_000);
    (ms > 0).then(|| std::time::Duration::from_millis(ms))
}

/// Shared between the JS thread and its watchdog: the running eval's hard
/// deadline (None while idle) and whether the watchdog cut it short.
#[derive(Default)]
struct Watch {
    deadline: Mutex<Option<std::time::Instant>>,
    tripped: std::sync::atomic::AtomicBool,
    evals: std::sync::atomic::AtomicU64,
    killed: std::sync::atomic::AtomicU64,
    panics: std::sync::atomic::AtomicU64,
    skipped: std::sync::atomic::AtomicU64,
}

fn lock_ok<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Owns the V8 `Runtime` on a dedicated thread. Isolates are `!Send`, so
/// evals cross a channel instead of a lock; one actor serves the whole
/// process because every eval is independent (fresh context, fresh DOM
/// state) — the actor is just a serializer around a !Send resource.
#[derive(Clone)]
pub struct JsActor {
    tx: tokio::sync::mpsc::Sender<JsCmd>,
    watch: Arc<Watch>,
}

impl Default for JsActor {
    fn default() -> Self {
        Self::with_grace(js_grace())
    }
}

impl JsActor {
    /// An actor whose watchdog allows `grace` past each eval's settle budget
    /// (None = no watchdog).
    fn with_grace(grace: Option<std::time::Duration>) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<JsCmd>(16);
        let watch = Arc::new(Watch::default());
        let w = watch.clone();
        std::thread::spawn(move || {
            use std::sync::atomic::Ordering::SeqCst;
            let mut rt = se_js::Runtime::new();
            if grace.is_some() {
                let handle = rt.handle();
                let wd = w.clone();
                std::thread::spawn(move || loop {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    let due = lock_ok(&wd.deadline)
                        .map(|d| std::time::Instant::now() >= d)
                        .unwrap_or(false);
                    if due && !wd.tripped.swap(true, SeqCst) {
                        handle.terminate_execution();
                    }
                });
            }
            while let Some(cmd) = rx.blocking_recv() {
                // The caller gave up (timeout, dropped connection): running
                // its script would only delay the evals queued behind it.
                if cmd.reply.is_closed() {
                    w.skipped.fetch_add(1, SeqCst);
                    continue;
                }
                se_js::bridge::set_quiesce_rounds(cmd.opts.quiesce);
                se_js::bridge::set_page_fetch_referer(cmd.opts.page_referer);
                se_js::bridge::set_async_fetch(cmd.opts.fetch_pool);
                se_js::bridge::set_quiet_ms(cmd.opts.quiet_ms);
                se_net::SUBRESOURCE_POOL.store(cmd.opts.fetch_pool, SeqCst);
                w.evals.fetch_add(1, SeqCst);
                w.tripped.store(false, SeqCst);
                if let Some(g) = grace {
                    *lock_ok(&w.deadline) = Some(std::time::Instant::now() + cmd.budget + g);
                }
                let ran = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    rt.eval_with_page_with_nav(cmd.page.as_ref(), &cmd.js, cmd.budget)
                }));
                *lock_ok(&w.deadline) = None;
                let timed_out = w.tripped.swap(false, SeqCst);
                let (out, nav) = match ran {
                    Ok((out, nav)) => (out.map_err(|e| e.to_string()), nav),
                    Err(_) => {
                        // A panic inside a bridge callback: the isolate's
                        // state is unknown, so it is replaced, and the actor
                        // lives on instead of taking every later eval down.
                        w.panics.fetch_add(1, SeqCst);
                        (Err("js runtime panicked; the script was abandoned".to_string()), None)
                    }
                };
                let heap = rt.recover();
                let out = if heap {
                    w.killed.fetch_add(1, SeqCst);
                    Err("script exceeded the JS heap limit and was terminated".to_string())
                } else if timed_out {
                    w.killed.fetch_add(1, SeqCst);
                    Err(format!(
                        "script exceeded its time limit ({} ms settle budget + grace) and was terminated",
                        cmd.budget.as_millis()
                    ))
                } else {
                    out
                };
                let _ = cmd.reply.send((out, nav));
            }
        });
        Self { tx, watch }
    }
}

impl JsActor {
    /// Liveness and counters for the `health` verb.
    fn health(&self) -> Value {
        use std::sync::atomic::Ordering::SeqCst;
        json!({
            "alive": !self.tx.is_closed(),
            "queue_free": self.tx.capacity(),
            "busy": lock_ok(&self.watch.deadline).is_some(),
            "evals": self.watch.evals.load(SeqCst),
            "terminated": self.watch.killed.load(SeqCst),
            "panics": self.watch.panics.load(SeqCst),
            "skipped_abandoned": self.watch.skipped.load(SeqCst),
        })
    }

    async fn eval(&self, page: Option<Page>, js: String) -> Result<Value, String> {
        self.eval_with_budget(page, js, se_js::bridge::TIMER_BUDGET)
            .await
    }

    async fn eval_with_budget(
        &self,
        page: Option<Page>,
        js: String,
        budget: std::time::Duration,
    ) -> Result<Value, String> {
        self.eval_with_nav(page, js, budget).await.0
    }

    /// `eval_with_budget` that also reports the post-settle page_url: where
    /// page-script navigation (location.href= & friends) would have taken a
    /// real browser. Only render mode consumes it.
    async fn eval_with_nav(
        &self,
        page: Option<Page>,
        js: String,
        budget: std::time::Duration,
    ) -> (Result<Value, String>, Option<String>) {
        let (reply, rx) = tokio::sync::oneshot::channel();
        let send = self
            .tx
            .send(JsCmd {
                page,
                js,
                budget,
                opts: JS_OPTS.try_with(|o| *o).unwrap_or_default(),
                reply,
            })
            .await;
        if let Err(e) = send {
            return (Err(format!("js actor unreachable: {e}")), None);
        }
        match rx.await {
            Ok(pair) => pair,
            Err(e) => (Err(format!("js actor dropped the reply: {e}")), None),
        }
    }
}

/// How many isolates serve evals (`SE_JS_ISOLATES`, 1..=8; default 1).
fn js_isolates() -> usize {
    std::env::var("SE_JS_ISOLATES")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(1)
        .clamp(1, 8)
}

/// A pool of JS actors, one isolate and one thread each. Every eval builds a
/// fresh context and its own DOM state, so any isolate can take any eval:
/// with one isolate a slow render made every other tab's script wait behind
/// it. An idle isolate is preferred; when all are busy the evals queue
/// round-robin. Isolates past the first start on first need.
#[derive(Clone)]
pub struct JsPool {
    workers: Arc<Mutex<Vec<JsActor>>>,
    max: usize,
    next: Arc<std::sync::atomic::AtomicUsize>,
}

impl Default for JsPool {
    fn default() -> Self {
        Self::with_size(js_isolates())
    }
}

impl JsPool {
    fn with_size(max: usize) -> Self {
        Self {
            workers: Arc::new(Mutex::new(vec![JsActor::default()])),
            max: max.max(1),
            next: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    fn pick(&self) -> JsActor {
        let mut workers = lock_ok(&self.workers);
        let idle = |w: &JsActor| lock_ok(&w.watch.deadline).is_none() && w.tx.capacity() == w.tx.max_capacity();
        if let Some(w) = workers.iter().find(|w| idle(w)) {
            return w.clone();
        }
        if workers.len() < self.max {
            let w = JsActor::default();
            workers.push(w.clone());
            return w;
        }
        let i = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % workers.len();
        workers[i].clone()
    }

    /// Liveness and counters for the `health` verb, summed over the pool.
    fn health(&self) -> Value {
        let workers = lock_ok(&self.workers);
        let each: Vec<Value> = workers.iter().map(|w| w.health()).collect();
        let sum = |k: &str| each.iter().filter_map(|h| h[k].as_u64()).sum::<u64>();
        json!({
            "alive": each.iter().all(|h| h["alive"] == json!(true)),
            "queue_free": sum("queue_free"),
            "busy": each.iter().any(|h| h["busy"] == json!(true)),
            "busy_isolates": each.iter().filter(|h| h["busy"] == json!(true)).count(),
            "isolates": each.len(),
            "isolates_max": self.max,
            "evals": sum("evals"),
            "terminated": sum("terminated"),
            "panics": sum("panics"),
            "skipped_abandoned": sum("skipped_abandoned"),
        })
    }

    async fn eval(&self, page: Option<Page>, js: String) -> Result<Value, String> {
        self.pick().eval(page, js).await
    }

    #[cfg_attr(not(test), allow(dead_code))]
    async fn eval_with_budget(
        &self,
        page: Option<Page>,
        js: String,
        budget: std::time::Duration,
    ) -> Result<Value, String> {
        self.pick().eval_with_budget(page, js, budget).await
    }

    async fn eval_with_nav(
        &self,
        page: Option<Page>,
        js: String,
        budget: std::time::Duration,
    ) -> (Result<Value, String>, Option<String>) {
        self.pick().eval_with_nav(page, js, budget).await
    }
}

#[derive(Clone)]
pub struct Engine {
    tabs: Arc<Mutex<HashMap<String, Tab>>>,
    client: Arc<Mutex<NetClient>>,
    js: JsPool,
    /// The session's network log (firing 32): document hops are recorded by
    /// the goto/fetch verbs, page-context fetch/XHR hops by the JS bridge.
    /// Returned (and optionally drained) by the `network_log` verb.
    net_log: Arc<se_net::NetLog>,
    /// Default on-disk session file for the `session_save` / `session_load`
    /// verbs when the caller passes no explicit `path` — set from the
    /// `--session-file` CLI flag. `None` (the test default) means the verbs
    /// require an explicit path.
    session_file: Option<std::path::PathBuf>,
    /// Session-global LOCAL storage pool, keyed by origin (`scheme://host:port`)
    /// — the browser's shared-per-profile localStorage (firing 36): every tab
    /// on an origin reads and writes the SAME map, so a write in one tab is
    /// visible to another tab on that origin, exactly as a headed browser's
    /// profile pool behaves. The per-tab archive this replaces gave second
    /// tabs their own copies — the divergence firing 35 named. `Storage` is
    /// an `Arc<Mutex<..>>` handle, so pool entries clone into eval Pages as
    /// live shared maps. `sessionStorage` deliberately stays per-tab: its
    /// spec lifetime is the top-level browsing context, not the profile.
    local_pool: Arc<Mutex<HashMap<String, se_js::bridge::Storage>>>,
    /// The agent's WebSocket pool (firing 39): sockets the `ws_connect` verb
    /// opened, keyed by `ws-N` id, owned by the AGENT (never page JS — the
    /// page-side stub stays shape-only forever). The verbs take a conn out of
    /// this map, run one async op, and put it back (drop on error), so no
    /// std::sync::Mutex guard is ever held across an await.
    ws_conns: Arc<Mutex<HashMap<String, se_net::ws::WsConn>>>,
    /// Monotonic source of `ws-N` ids for `ws_connect`.
    ws_next: Arc<std::sync::atomic::AtomicU64>,
    /// Last use and in-flight count per tab, for the idle sweep.
    tab_use: Arc<Mutex<TabUse>>,
}

/// Tab bookkeeping for the sweep: a tab nobody closed (a caller that died, a
/// loop that names a fresh tab per page) used to stay for the life of the
/// process, holding its document text and storage.
#[derive(Default)]
struct TabUse {
    last: HashMap<String, (std::time::Instant, u32)>,
    swept: u64,
}

/// `SE_WS_IDLE_S` (default 1800, 0 = never) and `SE_WS_MAX` (default 32,
/// 0 = unbounded) for the agent's WebSocket pool.
fn ws_limits() -> (Option<std::time::Duration>, usize) {
    static L: std::sync::OnceLock<(Option<std::time::Duration>, usize)> = std::sync::OnceLock::new();
    *L.get_or_init(|| {
        let num = |k: &str, d: u64| std::env::var(k).ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(d);
        let idle = num("SE_WS_IDLE_S", 1800);
        (
            (idle > 0).then(|| std::time::Duration::from_secs(idle)),
            num("SE_WS_MAX", 32) as usize,
        )
    })
}

/// `SE_TAB_IDLE_S` (default 1800, 0 = never) and `SE_TAB_MAX` (default 64,
/// 0 = unbounded).
fn tab_limits() -> (Option<std::time::Duration>, usize) {
    static L: std::sync::OnceLock<(Option<std::time::Duration>, usize)> = std::sync::OnceLock::new();
    *L.get_or_init(|| {
        let num = |k: &str, d: u64| std::env::var(k).ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(d);
        let idle = num("SE_TAB_IDLE_S", 1800);
        (
            (idle > 0).then(|| std::time::Duration::from_secs(idle)),
            num("SE_TAB_MAX", 64) as usize,
        )
    })
}

impl Default for Engine {
    fn default() -> Self {
        // The network session presents the SAME User-Agent the JS bridge
        // answers for navigator.userAgent — clearance cookies bind to it.
        Self {
            tabs: Arc::new(Mutex::new(HashMap::new())),
            client: Arc::new(Mutex::new(NetClient::new(se_js::bridge::USER_AGENT))),
            js: JsPool::default(),
            net_log: Arc::new(se_net::NetLog::default()),
            session_file: None,
            local_pool: Arc::new(Mutex::new(HashMap::new())),
            ws_conns: Arc::new(Mutex::new(HashMap::new())),
            ws_next: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            tab_use: Arc::new(Mutex::new(TabUse::default())),
        }
    }
}

impl Engine {
    /// Drop agent sockets idle past `idle`; returns how many remain. A socket
    /// inside a verb is out of the map and so is never dropped here.
    fn sweep_ws(&self, idle: Option<std::time::Duration>) -> usize {
        let mut conns = self.ws_conns.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(idle) = idle {
            conns.retain(|_, c| c.idle() < idle);
        }
        conns.len()
    }

    /// Mark a tab used; `delta` moves its in-flight count.
    fn tab_touch(&self, tab_id: &str, delta: i32) {
        let mut u = self.tab_use.lock().unwrap_or_else(|e| e.into_inner());
        let e = u.last.entry(tab_id.to_string()).or_insert((std::time::Instant::now(), 0));
        e.0 = std::time::Instant::now();
        e.1 = if delta >= 0 { e.1.saturating_add(delta as u32) } else { e.1.saturating_sub((-delta) as u32) };
    }

    /// Drop tabs idle past `idle`, then the least recently used ones beyond
    /// `cap`. A tab with a request in flight is never dropped. Returns how
    /// many went. Lock order: tabs, then tab_use.
    fn sweep_tabs(&self, idle: Option<std::time::Duration>, cap: usize) -> usize {
        let now = std::time::Instant::now();
        let mut tabs = self.tabs.lock().unwrap_or_else(|e| e.into_inner());
        let mut u = self.tab_use.lock().unwrap_or_else(|e| e.into_inner());
        // A tab first seen here (created by a verb that just ran) starts its
        // clock now; a record whose tab is gone and idle is dropped.
        for id in tabs.keys() {
            u.last.entry(id.clone()).or_insert((now, 0));
        }
        u.last.retain(|id, (_, busy)| *busy > 0 || tabs.contains_key(id));
        let mut gone: Vec<String> = Vec::new();
        if let Some(idle) = idle {
            for (id, (at, busy)) in u.last.iter() {
                if *busy == 0 && tabs.contains_key(id) && now.duration_since(*at) >= idle {
                    gone.push(id.clone());
                }
            }
        }
        for id in &gone {
            tabs.remove(id);
            u.last.remove(id);
        }
        if cap > 0 && tabs.len() > cap {
            let mut by_age: Vec<(std::time::Instant, String)> = u
                .last
                .iter()
                .filter(|(id, (_, busy))| *busy == 0 && tabs.contains_key(*id))
                .map(|(id, (at, _))| (*at, id.clone()))
                .collect();
            by_age.sort();
            for (_, id) in by_age {
                if tabs.len() <= cap {
                    break;
                }
                tabs.remove(&id);
                u.last.remove(&id);
                gone.push(id);
            }
        }
        u.swept += gone.len() as u64;
        gone.len()
    }

    /// Builder: set the default on-disk session file (the `--session-file`
    /// CLI path). Returns self so `Engine::default().with_session_file(p)`
    /// composes at the call site.
    pub fn with_session_file(mut self, path: Option<std::path::PathBuf>) -> Self {
        self.session_file = path;
        self
    }

    /// The shared localStorage map for `origin` — one per session, so writes
    /// from any tab on the origin are visible to every other tab on it, the
    /// way a headed browser's per-profile pool works. Lock order: callers may
    /// hold the TABS lock while taking the pool lock (eval, artifact), never
    /// the reverse.
    fn local_storage_for(&self, origin: &str) -> se_js::bridge::Storage {
        self.local_pool
            .lock().unwrap_or_else(|e| e.into_inner())
            .entry(origin.to_string())
            .or_default()
            .clone()
    }

    /// Render pass for `tab_id` (see the render-mode section above): collect
    /// the loaded document's scripts, execute them in one failure-isolated
    /// eval, pump timers to `budget`, adopt the DOM writeback — then follow
    /// page-script navigation: if the pump left the bridge's page_url
    /// somewhere else (location.href=/assign/replace), a real browser lands
    /// on the TARGET, so the follow re-navigates through the full guard
    /// stack (se-net navigate: refused_target + 302 + meta refresh) and
    /// renders the landed document, up to RENDER_NAV_MAX_HOPS. A
    /// fragment-only move is same-document navigation (no refetch); an
    /// unchanged URL is a reload no-op (the document was fetched moments
    /// ago). Chain exhaustion or a refused/failed hop serves the last loaded
    /// document honestly with the token in errors — the same shape as the
    /// meta-refresh surface. Mirrors the eval verb's snapshot → eval →
    /// adopt sequence exactly, including the lock order (TABS lock held
    /// while taking the pool lock, never the reverse, and no guard crosses
    /// an await).
    async fn render_tab(&self, tab_id: &str, budget: std::time::Duration) -> RenderStats {
        let mut total = RenderStats::default();
        let mut terminal: Option<String> = None;
        loop {
            let (mut pass, nav) = self.render_pass(tab_id, budget).await;
            total.scripts += pass.scripts;
            total.page_errors.append(&mut pass.page_errors);
            total.skipped += pass.skipped;
            total.errors.append(&mut pass.errors);
            total.errors_total += pass.errors_total;
            total.ms += pass.ms;
            let Some(target) = nav else { break };
            let current = self
                .tabs
                .lock().unwrap_or_else(|e| e.into_inner())
                .get(tab_id)
                .map(|t| t.url.clone());
            let Some(current) = current else { break }; // tab vanished mid-render
            if same_document_url(&current, &target) {
                break;
            }
            if total.nav_hops >= RENDER_NAV_MAX_HOPS {
                terminal = Some(format!(
                    "redirect_loop: render navigation chain exceeded {RENDER_NAV_MAX_HOPS} hops ({target})"
                ));
                break;
            }
            // A followed navigation: the document whose script navigated is
            // the initiator (wire Referer + Sec-Fetch-Site, document.referrer).
            let client = self.client.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let hop_started = std::time::Instant::now();
            let resp = match client.navigate(&target, Some(&current)).await {
                Ok(r) => r,
                Err(e) => {
                    // Refused (target_refused/redirect_loop) or failed
                    // (transient): the loaded document stays served, the
                    // token says why the follow stopped. A refused hop was
                    // never performed, so it does not count as one.
                    terminal = Some(format!("render navigation: {e}"));
                    break;
                }
            };
            total.nav_hops += 1;
            self.net_log
                .record("document", "GET", &target, resp.status, hop_started.elapsed());
            let tab = {
                let tabs = self.tabs.lock().unwrap_or_else(|e| e.into_inner());
                Tab::after_navigation(
                    tabs.get(tab_id),
                    &resp.final_url,
                    current.clone(),
                    resp.body.clone(),
                )
            };
            self.tabs
                .lock().unwrap_or_else(|e| e.into_inner())
                .insert(tab_id.to_string(), tab);
            total.final_url = Some(resp.final_url);
            total.final_status = Some(resp.status);
        }
        // A terminal token must survive the error-cap truncate: it is the
        // honest-refusal signal the caller keys on, so it keeps the last
        // slot.
        if let Some(t) = terminal {
            total.errors.truncate(RENDER_MAX_ERRORS - 1);
            total.errors.push(t);
        } else {
            total.errors.truncate(RENDER_MAX_ERRORS);
        }
        total
    }

    /// One render pass over the tab's current document: collect scripts,
    /// execute, pump, adopt the writeback. Returns the stats and — when the
    /// eval ran — the bridge's POST-SETTLE page_url: where page-script
    /// navigation would have taken a real browser. The post-settle read is
    /// load-bearing: a setTimeout-scheduled location.href= hasn't landed
    /// when the harness's completion value is computed, so reading any
    /// earlier would miss it.
    async fn render_pass(
        &self,
        tab_id: &str,
        budget: std::time::Duration,
    ) -> (RenderStats, Option<String>) {
        let started = std::time::Instant::now();
        let mut stats = RenderStats::default();
        let cookie_store = Some(self.client.lock().unwrap_or_else(|e| e.into_inner()).store());
        let page = self
            .tabs
            .lock().unwrap_or_else(|e| e.into_inner())
            .get(tab_id)
            .map(|tab| Page {
                url: tab.url.clone(),
                referrer: tab.referrer.clone(),
                html: tab.html.clone(),
                local_storage: self.local_storage_for(&origin_of(&tab.url)),
                session_storage: tab.session_storage.clone(),
                window_name: tab.window_name.clone(),
                cookie_store,
                net_log: Some(self.net_log.clone()),
                danger_accept_invalid_host_certs: false,
                writeback: tab.writeback.clone(),
            });
        let Some(page) = page else {
            stats.errors.push("render: no tab".to_string());
            stats.ms = started.elapsed().as_secs_f64() * 1000.0;
            return (stats, None);
        };
        let writeback = page.writeback.clone();
        let want_modules = JS_OPTS.try_with(|o| o.modules && o.prelude).unwrap_or(false);
        let (units, unit_modules, skips) = collect_scripts_ext(&page.html, &page.url, want_modules);
        stats.skipped += skips.len();
        stats.errors.extend(skips);
        // Fetch externals through the session client (outside every lock),
        // in document order, with the caps above. Presentation is
        // subresource-shaped (fetch/XHR Sec-Fetch headers) — close enough
        // for v1; a Script DataKind would be the fidelity upgrade.
        let mut sources: Vec<String> = Vec::new();
        // Parallel to `sources`: the URL of an external script, None inline.
        let mut source_keys: Vec<Option<String>> = Vec::new();
        // Parallel to `sources`: is this one a module script?
        let mut source_modules: Vec<bool> = Vec::new();
        let mut externals = 0usize;
        let client = self.client.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let pipeline = JS_OPTS.try_with(|o| o.pipeline).unwrap_or(false);
        let (max_ext, max_bytes) = if pipeline {
            (PIPELINE_MAX_EXTERNALS, PIPELINE_MAX_SCRIPT_BYTES)
        } else {
            (RENDER_MAX_EXTERNALS, RENDER_MAX_SCRIPT_BYTES)
        };
        type Fetched = (Result<se_net::Response, String>, std::time::Duration);
        // Pipeline: every eligible external starts NOW; the loop below awaits
        // them in document order, so execution order is unchanged while the
        // waits overlap. One slot per external unit (None = not fetched).
        let mut started_fetches: std::collections::VecDeque<Option<tokio::task::JoinHandle<Fetched>>> =
            std::collections::VecDeque::new();
        if pipeline {
            let mut n = 0usize;
            for unit in &units {
                let ScriptUnit::External(u) = unit else { continue };
                if noncontent_script(u) {
                    started_fetches.push_back(None);
                    continue;
                }
                n += 1;
                if n > max_ext {
                    started_fetches.push_back(None);
                    continue;
                }
                let (c, u2, from) = (client.clone(), u.clone(), page.url.clone());
                started_fetches.push_back(Some(tokio::spawn(async move {
                    let t = std::time::Instant::now();
                    let r = c
                        .request_data(&u2, "GET", &[], "", Some(&from), se_net::DataKind::Data)
                        .await
                        .map_err(|e| e.to_string());
                    (r, t.elapsed())
                })));
            }
        }
        let mut total_bytes = 0usize;
        for (unit, is_module) in units.into_iter().zip(unit_modules) {
            match unit {
                ScriptUnit::Inline(src) => {
                    sources.push(src);
                    source_keys.push(None);
                    source_modules.push(is_module);
                }
                ScriptUnit::External(u) => {
                    let handle = if pipeline { started_fetches.pop_front().flatten() } else { None };
                    if pipeline && noncontent_script(&u) {
                        stats.skipped += 1;
                        stats.errors.push(format!("script skipped: non-content host {u}"));
                        continue;
                    }
                    externals += 1;
                    if externals > max_ext {
                        stats.skipped += 1;
                        stats
                            .errors
                            .push(format!("script skipped: external cap {max_ext}"));
                        continue;
                    }
                    let (got, took): Fetched = match handle {
                        Some(h) => h
                            .await
                            .unwrap_or_else(|e| (Err(format!("fetch task: {e}")), Default::default())),
                        None => {
                            let t = std::time::Instant::now();
                            let r = client
                                .request_data(&u, "GET", &[], "", Some(&page.url), se_net::DataKind::Data)
                                .await
                                .map_err(|e| e.to_string());
                            (r, t.elapsed())
                        }
                    };
                    match got {
                        Ok(resp) if (200..300).contains(&resp.status)
                            && resp.body.len() <= max_bytes
                            && (!pipeline || total_bytes + resp.body.len() <= PIPELINE_MAX_TOTAL_BYTES) =>
                        {
                            self.net_log.record("fetch", "GET", &u, resp.status, took);
                            total_bytes += resp.body.len();
                            sources.push(resp.body);
                            source_keys.push(Some(u.clone()));
                            source_modules.push(is_module);
                        }
                        Ok(resp) => {
                            self.net_log.record("fetch", "GET", &u, resp.status, took);
                            stats.skipped += 1;
                            stats.errors.push(format!(
                                "script skipped: {} -> {} ({} bytes)",
                                u,
                                resp.status,
                                resp.body.len()
                            ));
                        }
                        Err(e) => {
                            stats.skipped += 1;
                            stats.errors.push(format!("script skipped: {u}: {e}"));
                        }
                    }
                }
            }
        }
        if sources.is_empty() {
            stats.errors_total = stats.errors.len();
            stats.errors.truncate(RENDER_MAX_ERRORS);
            stats.ms = started.elapsed().as_secs_f64() * 1000.0;
            return (stats, None);
        }
        let n_sources = sources.len();
        let encoded = serde_json::to_string(&sources).unwrap_or_else(|_| "[]".to_string());
        let prelude = JS_OPTS.try_with(|o| o.prelude).unwrap_or(false);
        let live = prelude && JS_OPTS.try_with(|o| o.live_dom).unwrap_or(false);
        let code_cache = prelude && JS_OPTS.try_with(|o| o.code_cache).unwrap_or(false);
        let harness = if prelude && (live || want_modules || code_cache) {
            render_harness_full(
                &encoded,
                &serde_json::to_string(&source_keys).unwrap_or_else(|_| "[]".to_string()),
                &serde_json::to_string(&source_modules).unwrap_or_else(|_| "[]".to_string()),
                live,
                code_cache,
            )
        } else {
            render_harness_live(&encoded, prelude, None)
        };
        let (result, nav) = self.js.eval_with_nav(Some(page), harness, budget).await;
        // With the prelude the harness answers {errors, page_errors}.
        let result = match result {
            Ok(Value::Object(mut o)) => {
                if let Some(Value::Array(pe)) = o.remove("page_errors") {
                    stats.page_errors = pe
                        .into_iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .take(10)
                        .collect();
                }
                Ok(o.remove("errors").unwrap_or(Value::Array(Vec::new())))
            }
            other => other,
        };
        match result {
            Ok(Value::Array(errs)) => {
                // `scripts` counts scripts that ran clean; each harness-side
                // compile/run failure moves one from executed to skipped.
                stats.scripts = n_sources.saturating_sub(errs.len());
                stats.skipped += errs.len();
                for e in errs {
                    stats
                        .errors
                        .push(e.as_str().unwrap_or("<unprintable>").to_string());
                }
            }
            Ok(_) => stats.scripts = n_sources,
            Err(e) => stats.errors.push(format!("render eval failed: {e}")),
        }
        // Adopt the DOM-mutation writeback — the same take-and-adopt the
        // eval verb runs: publish only if no navigation replaced the tab
        // while the pump drained (the writeback's `from` is still current).
        let pending = writeback.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(wb) = pending {
            let mut tabs = self.tabs.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(tab) = tabs.get_mut(tab_id) {
                if tab.html == wb.from {
                    tab.html = wb.html;
                }
            }
        }
        stats.errors_total = stats.errors.len();
        stats.errors.truncate(RENDER_MAX_ERRORS);
        stats.ms = started.elapsed().as_secs_f64() * 1000.0;
        (stats, nav)
    }

    /// The session for `tab_id` as a Playwright `storage_state` artifact —
    /// the producer half of `session_restore`, and (wrapped in the wire
    /// envelope) exactly what the `storage_state_get` verb answers. Cookies
    /// come from the live jar; origins carry the WHOLE session-global
    /// localStorage pool — every origin the session touched, not just the
    /// ones this tab visited, because the pool IS the context a saved
    /// session must restore (the headed-browser per-profile semantics the
    /// engine now models). Session storage is deliberately excluded: its
    /// lifetime is the top-level browsing context, so Playwright's format —
    /// and any session the artifact reopens into — never persists it.
    fn session_artifact(&self, tab_id: &str) -> Value {
        let client = self.client.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let cookies: Vec<Value> = client
            .store()
            .snapshot()
            .iter()
            .map(cookie_wire)
            .collect();
        let tabs = self.tabs.lock().unwrap_or_else(|e| e.into_inner());
        let mut origins: Vec<Value> = Vec::new();
        if tabs.get(tab_id).is_some() {
            // The WHOLE pool exports: Playwright's artifact is per-context,
            // and the pool IS the context — every origin the session touched
            // rides along, not just the ones this tab visited.
            let pool = self.local_pool.lock().unwrap_or_else(|e| e.into_inner());
            let mut sources: Vec<(String, &se_js::bridge::Storage)> =
                pool.iter().map(|(o, s)| (o.clone(), s)).collect();
            sources.sort_by(|a, b| a.0.cmp(&b.0));
            for (origin, storage) in sources {
                let local_storage: Vec<Value> = storage
                    .entries()
                    .into_iter()
                    .map(|(name, value)| json!({"name": name, "value": value}))
                    .collect();
                origins.push(json!({"origin": origin, "localStorage": local_storage}));
            }
        }
        json!({"cookies": cookies, "origins": origins})
    }

    /// Restore a session artifact (the `session_restore` producer's shape)
    /// into the live jar + `tab_id`'s origin maps — the consumer half of
    /// `session_artifact`, shared by `storage_state_set` and `session_load`.
    /// Returns the number of cookies the jar accepted. The artifact must be
    /// a JSON object; individual malformed cookies are skipped (same lenient
    /// contract `storage_state_set` has always had).
    fn session_restore(&self, state: &Value, tab_id: &str) -> Result<usize, String> {
        if !state.is_object() {
            return Err("storage_state must be a JSON object".to_string());
        }
        let mut entries = Vec::new();
        for item in state
            .get("cookies")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(name) = item.get("name").and_then(Value::as_str) else {
                continue;
            };
            entries.push(se_net::CookieEntry {
                name: name.to_string(),
                value: item
                    .get("value")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                domain: item
                    .get("domain")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                path: item
                    .get("path")
                    .and_then(Value::as_str)
                    .unwrap_or("/")
                    .to_string(),
                secure: item.get("secure").and_then(Value::as_bool).unwrap_or(false),
                http_only: item
                    .get("httpOnly")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                // Playwright: -1/omitted means session; non-positive
                // values stay session cookies here too.
                expires: item.get("expires").and_then(Value::as_i64).filter(|e| *e > 0),
                // Playwright always sends this ("Lax" when the source
                // server set nothing); pass it through to the jar.
                same_site: item
                    .get("sameSite")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                // CDP's cookie shape: a LEADING DOT means domain-scoped;
                // a bare domain is a host-only cookie. The dot is the
                // flag — no separate hostOnly field in the artifact.
                host_only: !item
                    .get("domain")
                    .and_then(Value::as_str)
                    .map(|d| d.starts_with('.'))
                    .unwrap_or(false),
            });
        }
        // Inject into the LIVE jar: the next fetch/goto carries the
        // session, which is the point of the verb.
        let client = self.client.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let mut loaded = 0usize;
        for e in &entries {
            if client.store().insert_entry(e) {
                loaded += 1;
            }
        }
        // Origins: restore each origin's localStorage into the SESSION-GLOBAL
        // pool — the reopened session resumes with the local state the save
        // carried, and ANY tab landing on the origin sees it (browser
        // per-profile semantics). Session storage is never restored — its
        // lifetime is the browsing context, not the session.
        {
            let mut tabs = self.tabs.lock().unwrap_or_else(|e| e.into_inner());
            tabs.entry(tab_id.to_string()).or_insert_with(|| Tab {
                url: String::new(),
                referrer: String::new(),
                html: String::new(),
                session_storage: Default::default(),
                session_archive: HashMap::new(),
                window_name: Default::default(),
                writeback: Default::default(),
            });
        }
        let mut pool = self.local_pool.lock().unwrap_or_else(|e| e.into_inner());
        for origin_state in state
            .get("origins")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(origin) = origin_state.get("origin").and_then(Value::as_str) else {
                continue;
            };
            let storage = se_js::bridge::Storage::default();
            for item in origin_state
                .get("localStorage")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let (Some(name), Some(value)) = (
                    item.get("name").and_then(Value::as_str),
                    item.get("value").and_then(Value::as_str),
                ) {
                    storage.set(name.to_string(), value.to_string());
                }
            }
            if storage.len() == 0 {
                continue;
            }
            pool.insert(origin.to_string(), storage);
        }
        Ok(loaded)
    }

    /// Persist the session artifact for `tab_id` to `path` as pretty-printed
    /// JSON — the on-disk tier of save/restore. The write is atomic-ish:
    /// the bytes land in a sibling `.tmp` file first and are renamed over
    /// the target, so a crash mid-write cannot leave a half artifact (the
    /// rename is the commit). Returns the wire-shaped success value.
    pub fn session_save_file(
        &self,
        path: &std::path::Path,
        tab_id: &str,
    ) -> Result<Value, String> {
        let artifact = self.session_artifact(tab_id);
        let bytes = serde_json::to_vec_pretty(&artifact)
            .map_err(|e| format!("serialize session: {e}"))?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &bytes).map_err(|e| format!("write {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("commit {}: {e}", path.display()))?;
        Ok(json!({
            "ok": true,
            "path": path.display().to_string(),
            "cookies": artifact["cookies"].as_array().map_or(0, Vec::len),
            "origins": artifact["origins"].as_array().map_or(0, Vec::len),
        }))
    }

    /// Load a session artifact from `path` and restore it via
    /// `session_restore`. A missing or malformed file is an `Err`, never a
    /// panic — the startup path treats "no readable session" as "start
    /// fresh" and the verb maps it to `{"ok": false}`.
    pub fn session_load_file(
        &self,
        path: &std::path::Path,
        tab_id: &str,
    ) -> Result<usize, String> {
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let state: Value =
            serde_json::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))?;
        self.session_restore(&state, tab_id)
    }
}

#[derive(Clone)]
struct Tab {
    url: String,
    /// The navigation initiator — the previous page's URL when this tab's
    /// load followed from one. Surfaced as the wire `Referer` +
    /// `Sec-Fetch-Site` pair on the next navigation and as
    /// `document.referrer` to evals; empty on an address-bar load.
    referrer: String,
    /// The live document serialized at `goto` time. Stored as text rather
    /// than `se_dom::Document` because scraper's tree is Rc-backed (not
    /// Send/Sync) and axum state must be both; selector-scoped reads
    /// re-parse on demand, which benches fine at fixture scale.
    html: String,
    /// Per-tab SESSION storage for the CURRENT origin. LOCAL storage is not
    /// here: since firing 36 it lives in the Engine's session-global pool
    /// (shared across tabs per origin, the way a headed browser's profile
    /// pool works), and eval's Page receives the pool handle for the tab's
    /// origin. Only sessionStorage — whose spec lifetime is the top-level
    /// browsing context — stays per-tab, archived per origin below.
    /// `session_reset` clears both maps plus the archive.
    session_storage: se_js::bridge::Storage,
    /// Non-current origins' SESSION storage, keyed by origin
    /// (`scheme://host:port`), retained across cross-origin hops so a later
    /// return restores them. (Local storage needs no archive: the pool IS
    /// keyed by origin, so A→B→A is inherent.)
    session_archive: HashMap<String, se_js::bridge::Storage>,
    /// The browsing-context name (`window.name`) — NOT origin-scoped and not
    /// Web Storage; the context owns it, so every navigation carries it and
    /// a script's write survives across evals (trackers read it for session
    /// correlation, so `session_reset` clears it with the jar).
    window_name: se_js::bridge::WindowName,
    /// DOM-mutation writeback slot: the eval verb clones this into the eval
    /// Page, and after the eval the handler adopts a pending writeback into
    /// `html` — page JS mutations persist across evals and into read_html,
    /// like patchright's live DOM. A navigation builds a fresh slot: a
    /// writeback pending across a navigation targets the old document and
    /// the adoption's `from` check drops it (the fresh document wins).
    writeback: Arc<Mutex<Option<se_js::bridge::MutationWriteback>>>,
}

/// scheme://host[:port] — enough for a same-origin decision; path, query,
/// and fragment never count toward origin. Unparseable → empty (never
/// matches, so a garbage URL gets fresh storage).
fn origin_of(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return String::new();
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    format!("{scheme}://{}", &rest[..end])
}

/// Playwright wire shape for one jar entry. A cookie whose server sent no
/// SameSite attribute reports as "Lax": Chromium has treated unset SameSite
/// as Lax-by-default since Chrome 80, and Playwright's own export shows
/// "Lax" — the engine reports observable behavior, not the raw header.
fn cookie_wire(c: &se_net::CookieEntry) -> Value {
    json!({
        "name": c.name,
        "value": c.value,
        "domain": playwright_domain(&c.domain, c.host_only),
        "path": c.path,
        "expires": c.expires.unwrap_or(-1),
        "httpOnly": c.http_only,
        "secure": c.secure,
        "sameSite": c.same_site.clone().unwrap_or_else(|| "Lax".into()),
    })
}

/// Playwright's artifact encodes a domain-scoped cookie AS the leading dot
/// (CDP's shape — a host-only cookie exports bare). IPs have no subdomains,
/// so the dot there would be noise, and the hostOnly flag round-trips
/// through `storage_state_set` to keep scope exact on re-import.
fn playwright_domain(domain: &str, host_only: bool) -> String {
    if !host_only && !domain.is_empty() && domain.parse::<std::net::IpAddr>().is_err() {
        format!(".{domain}")
    } else {
        domain.to_string()
    }
}

/// Storage for a navigation replacing `tab_id`, handled by
/// [`Tab::after_navigation`]: same-origin carries the session map unchanged;
/// cross-origin archives the outgoing origin's session map and restores the
/// destination's (fresh on first visit). Local storage needs no handling —
/// the Engine's per-origin pool is keyed by origin, so any tab landing on
/// an origin reads and writes that origin's single shared map.

impl Tab {
    /// Test helper: a Tab with empty storage maps.
    #[cfg(test)]
    fn default_for_test() -> Self {
        Self {
            url: String::new(),
            referrer: String::new(),
            html: String::new(),
            session_storage: Default::default(),
            session_archive: Default::default(),
            window_name: Default::default(),
            writeback: Default::default(),
        }
    }

    /// Build the tab state after a navigation to `final_url`. `old` is the
    /// tab being navigated (None → address-bar load on a fresh tab).
    ///
    /// Session-storage semantics: a same-origin hop carries the map
    /// unchanged; a cross-origin hop files the outgoing origin's map in the
    /// per-tab archive and restores the destination origin's (fresh on first
    /// visit). Without the archive, a multi-URL crawl's A→B→A pattern would
    /// lose everything origin A wrote — browsers persist Web Storage per
    /// origin for the life of the session, and the crawl-workload contract
    /// pins that here. A tab with an empty URL (never navigated) archives
    /// nothing. LOCAL storage never passes through here: the Engine's pool
    /// holds one shared map per origin for the session's life.
    fn after_navigation(
        old: Option<&Tab>,
        final_url: &str,
        referrer: String,
        html: String,
    ) -> Tab {
        let mut archive = old
            .map(|t| t.session_archive.clone())
            .unwrap_or_default();
        let session_storage = match old {
            Some(old) if !old.url.is_empty() => {
                let old_origin = origin_of(&old.url);
                if old_origin == origin_of(final_url) {
                    old.session_storage.clone()
                } else {
                    archive.insert(old_origin, old.session_storage.clone());
                    archive.remove(&origin_of(final_url)).unwrap_or_default()
                }
            }
            // A never-navigated tab archives nothing, but its archive still
            // RESTORES: this is exactly the reopened-session flow — a fresh
            // tab after storage_state_set holds injected origins, and the
            // first goto must pull the destination's saved storage.
            _ => archive.remove(&origin_of(final_url)).unwrap_or_default(),
        };
        Tab {
            url: final_url.to_string(),
            referrer,
            html,
            session_storage,
            session_archive: archive,
            // The browsing context keeps its name across every navigation.
            window_name: old
                .map(|o| o.window_name.clone())
                .unwrap_or_default(),
            // Fresh document → fresh writeback slot: a pending writeback
            // targets the old document and the adoption's `from` check drops
            // it when a navigation raced the eval.
            writeback: Default::default(),
        }
    }
}

#[derive(Deserialize)]
struct RpcRequest {
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

pub async fn serve(engine: Engine, port: u16) -> Result<(), std::io::Error> {
    serve_inner(engine, port, None).await
}

/// `serve` plus the disk-session lifecycle: when `session_file` is `Some`,
/// the engine restores the artifact at startup (a missing or unreadable
/// file just starts fresh — a first boot has no session yet) and persists
/// the default tab's session on graceful shutdown (Ctrl+C), so a sidecar
/// restart resumes the jar + origin storage where the last session left
/// off. `None` behaves exactly like `serve`.
pub async fn serve_with_session(
    engine: Engine,
    port: u16,
    session_file: Option<std::path::PathBuf>,
) -> Result<(), std::io::Error> {
    serve_inner(engine, port, session_file).await
}

async fn serve_inner(
    engine: Engine,
    port: u16,
    session_file: Option<std::path::PathBuf>,
) -> Result<(), std::io::Error> {
    if let Some(path) = &session_file {
        match engine.session_load_file(path, "default") {
            Ok(n) => eprintln!(
                "se-serve: restored session from {} ({n} cookies)",
                path.display()
            ),
            Err(_) => eprintln!(
                "se-serve: no readable session at {} (starting fresh)",
                path.display()
            ),
        }
    }
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/rpc", post(rpc))
        .with_state(engine.clone());
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    let Some(path) = session_file else {
        return axum::serve(listener, app).await;
    };
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    // Graceful shutdown: persist the session before exit. A save failure
    // logs to stderr but does not flip the exit code — the session on disk
    // is best-effort durability, and the next boot treats a missing or
    // stale file as "start fresh" either way.
    match engine.session_save_file(&path, "default") {
        Ok(v) => eprintln!(
            "se-serve: saved session to {} ({} cookies, {} origins)",
            v["path"].as_str().unwrap_or("?"),
            v["cookies"].as_u64().unwrap_or(0),
            v["origins"].as_u64().unwrap_or(0),
        ),
        Err(e) => eprintln!("se-serve: session save failed: {e}"),
    }
    Ok(())
}

async fn healthz() -> Json<Value> {
    // SidecarClient._healthy requires a JSON body {"ok": true}, not bare 200.
    Json(json!({"ok": true}))
}

async fn rpc(State(engine): State<Engine>, body: String) -> Json<Value> {
    let req: RpcRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => {
            return Json(json!({
                "jsonrpc": "2.0", "id": Value::Null,
                "error": {"code": -32700, "message": format!("parse error: {e}")}
            }))
        }
    };
    match dispatch(&engine, &req.method, req.params.unwrap_or(Value::Null)).await {
        Ok(result) => Json(json!({"jsonrpc": "2.0", "id": req.id, "result": result})),
        Err((code, message)) => Json(json!({
            "jsonrpc": "2.0", "id": req.id,
            "error": {"code": code, "message": message}
        })),
    }
}

/// A verb-level failure the client maps to `{"ok": false}` — the sidecar
/// working correctly and reporting a failed call.
fn verb_error(message: impl Into<String>) -> Value {
    json!({"ok": false, "error": message.into()})
}

fn param<'v>(params: &'v Value, key: &str) -> Option<&'v str> {
    params.get(key).and_then(Value::as_str)
}

fn tab_id_of(params: &Value) -> &str {
    param(params, "tab_id").unwrap_or("default")
}

/// Challenge/shell signatures the escalation decision relies on. Kept
/// deliberately conservative: a false positive aborts a good retrieval.
/// Bare words like "captcha" are unusable — Facebook's normal pages name
/// `arkose_captcha` in a resource-loader list — so signatures must mark a
/// *presented* challenge, not a mentioned one.
/// `detect_bot` with the signatures tied to where they mean something
/// (`bot_scoped: true` on goto/fetch). The bare-substring form flags any
/// page that MENTIONS a vendor: an article about Arkose, a forum post
/// quoting `/login/checkpoint`, a JSON API with a null `feed_units`. Scoped:
/// the two Facebook signatures count on Facebook hosts only, and a vendor
/// name counts only inside a tag (a script/iframe/form attribute), not in
/// prose or in a script's text.
pub fn detect_bot_scoped(body: &str, url: &str) -> Option<&'static str> {
    fn in_tag(body: &str, sig: &str) -> bool {
        let mut from = 0;
        while let Some(i) = body[from..].find(sig) {
            let at = from + i;
            let head = &body[..at];
            if let Some(lt) = head.rfind('<') {
                let open = &head[lt..];
                let is_text_tag = open.len() > 1
                    && open.as_bytes()[1].is_ascii_alphabetic()
                    && !open.contains('>');
                if is_text_tag {
                    return true;
                }
            }
            from = at + sig.len();
        }
        false
    }
    let host = url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
        .unwrap_or_default();
    let facebook = ["facebook.com", "fb.com", "messenger.com", "instagram.com"]
        .iter()
        .any(|d| host == *d || host.ends_with(&format!(".{d}")));
    if in_tag(body, "px-captcha") {
        return Some("perimeterx_challenge");
    }
    if in_tag(body, "arkoselabs.com") {
        return Some("arkose_enforcement");
    }
    if facebook {
        if body.contains("/login/checkpoint") {
            return Some("login_checkpoint");
        }
        if body.contains("feed_units\":null") {
            return Some("empty_feed_units");
        }
    }
    None
}

fn bot_verdict(body: &str, url: &str, params: &Value) -> Option<&'static str> {
    if bool_param(params, "bot_scoped") {
        detect_bot_scoped(body, url)
    } else {
        detect_bot(body)
    }
}

/// `timeout_ms` on goto/fetch: ONE deadline for the whole verb (every
/// redirect hop and the body read), so the caller's budget is the engine's
/// budget. Absent = the client's own timeouts, as before.
fn deadline_param(params: &Value) -> Option<std::time::Duration> {
    let ms = params
        .get("timeout_ms")
        .and_then(Value::as_u64)
        .or_else(|| param(params, "timeout_ms").and_then(|s| s.parse().ok()))?;
    Some(std::time::Duration::from_millis(ms.clamp(100, 300_000)))
}

/// Run a CPU-bound read (an HTML parse, a snapshot walk) without holding a
/// runtime worker: the worker's queued tasks -- other connections' requests
/// -- move to another thread instead of waiting for the parse to end.
fn off_worker<T>(f: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(h) if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
    }
}

/// A tab's URL and document, copied out under the lock (the lock is not
/// held while the caller parses).
fn tab_document(engine: &Engine, params: &Value) -> Option<(String, String)> {
    let tabs = engine.tabs.lock().unwrap_or_else(|e| e.into_inner());
    let tab = tabs.get(tab_id_of(params))?;
    Some((tab.url.clone(), tab.html.clone()))
}

/// Snapshot shaping options (`read_snapshot` and `read`), all opt-in:
/// `dedupe` drops an entry that only repeats its listed ancestor's text,
/// `absolute` resolves `href` against the document base, `max_entries` and
/// `max_text` cap the list and each entry's text.
#[derive(Clone, Copy, Default)]
struct SnapShape {
    dedupe: bool,
    absolute: bool,
    max_entries: usize,
    max_text: usize,
}

impl SnapShape {
    fn from_params(params: &Value) -> Self {
        let num = |k: &str| params.get(k).and_then(Value::as_u64).unwrap_or(0) as usize;
        Self {
            dedupe: bool_param(params, "dedupe"),
            absolute: bool_param(params, "absolute"),
            max_entries: num("max_entries"),
            max_text: num("max_text"),
        }
    }

    fn any(&self) -> bool {
        self.dedupe || self.absolute || self.max_entries > 0 || self.max_text > 0
    }

    /// Shape `entries` and write `snapshot` (+ the counts when shaping ran).
    fn apply(
        &self,
        mut entries: Vec<se_dom::snapshot::SnapEntry>,
        page_url: &str,
        doc: &Document,
        out: &mut Value,
    ) {
        if !self.any() {
            out["snapshot"] = json!(entries);
            return;
        }
        let total = entries.len();
        if self.dedupe {
            entries = dedupe_snapshot(entries);
        }
        let deduped = total - entries.len();
        if self.absolute {
            if let Some(base) = document_base(doc, page_url) {
                for e in entries.iter_mut() {
                    if let Some(h) = e.href.as_deref() {
                        let h = h.trim();
                        if h.is_empty() || h.starts_with('#') || h.starts_with("javascript:") {
                            continue;
                        }
                        if let Ok(abs) = base.join(h) {
                            e.href = Some(abs.to_string());
                        }
                    }
                }
            }
        }
        if self.max_text > 0 {
            for e in entries.iter_mut() {
                if e.text.chars().count() > self.max_text {
                    let mut cut: String = e.text.chars().take(self.max_text).collect();
                    cut.push('\u{2026}');
                    e.text = cut;
                }
            }
        }
        let truncated = self.max_entries > 0 && entries.len() > self.max_entries;
        if truncated {
            entries.truncate(self.max_entries);
        }
        out["snapshot"] = json!(entries);
        out["snapshot_total"] = json!(total);
        out["snapshot_deduped"] = json!(deduped);
        out["snapshot_truncated"] = json!(truncated);
    }
}

/// What relative URLs in the document resolve against: `<base href>` wins
/// over the page URL, as in a browser.
fn document_base(doc: &Document, page_url: &str) -> Option<url::Url> {
    let page = url::Url::parse(page_url).ok();
    doc.select_one("base[href]")
        .ok()
        .flatten()
        .and_then(|b| b.attr("href").map(str::to_string))
        .and_then(|h| page.as_ref()?.join(&h).ok())
        .or(page)
}

/// Drop entries that carry nothing their listed ancestor does not already
/// say: a non-interactive element with no identity attribute whose text is
/// part of a textual ancestor's text (`<p>Hello <b>world</b></p>` lists the
/// `p`; `<a><span>Buy</span></a>` lists the `a`). Depths are left as they
/// were, so the surviving entries still nest correctly.
fn dedupe_snapshot(entries: Vec<se_dom::snapshot::SnapEntry>) -> Vec<se_dom::snapshot::SnapEntry> {
    let mut out: Vec<se_dom::snapshot::SnapEntry> = Vec::with_capacity(entries.len());
    // (depth, text) of the listed ancestors that carry text.
    let mut stack: Vec<(usize, String)> = Vec::new();
    for e in entries {
        while stack.last().is_some_and(|(d, _)| *d >= e.depth) {
            stack.pop();
        }
        let plain = !e.interactive
            && e.id.is_none()
            && e.href.is_none()
            && e.alt.is_none()
            && e.name.is_none()
            && e.aria_label.is_none()
            && e.control_type.is_none();
        let repeats = plain
            && !e.text.is_empty()
            && stack.iter().any(|(_, t)| t.contains(e.text.as_str()));
        if !e.text.is_empty() {
            stack.push((e.depth, e.text.clone()));
        }
        if !repeats {
            out.push(e);
        }
    }
    out
}

/// The `read` verb's body: `include` picks any of "html", "text",
/// "snapshot", "links"; `selector` scopes all of them to the first match.
fn read_combined(params: &Value, url: &str, html: String) -> Value {
    let include: Vec<String> = match params.get("include") {
        Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
        Some(Value::String(s)) => s.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect(),
        _ => vec!["text".to_string()],
    };
    for part in &include {
        if !matches!(part.as_str(), "html" | "text" | "snapshot" | "links") {
            return verb_error(format!("read: unknown include {part:?}"));
        }
    }
    let wants = |k: &str| include.iter().any(|p| p == k);
    let selector = param(params, "selector").filter(|s| !s.is_empty());
    let mut out = json!({"ok": true, "tab_id": tab_id_of(params), "url": url});
    if selector.is_none() && include.iter().all(|p| p == "html") {
        // The whole document and nothing else: no parse at all.
        out["html"] = json!(html);
        return out;
    }
    let doc = Document::parse(&html);
    let scope = match selector {
        Some(sel) => match doc.select_one(sel) {
            Ok(Some(n)) => Some(n),
            Ok(None) => return verb_error(format!("read: no match {sel:?}")),
            Err(e) => return verb_error(format!("read: {e}")),
        },
        None => None,
    };
    if wants("text") {
        let target = match scope {
            Some(n) => Some(n),
            None => doc.select_one("body").ok().flatten().or_else(|| doc.root()),
        };
        out["text"] = json!(target.map(|n| n.inner_text()).unwrap_or_default());
    }
    if wants("snapshot") || wants("links") {
        let entries = se_dom::snapshot::snapshot(&doc, scope);
        if wants("links") {
            // Document order, one row per target: what an agent follows next.
            let base = document_base(&doc, url);
            let mut seen = std::collections::HashSet::new();
            let mut links = Vec::new();
            for e in entries.iter().filter(|e| e.kind == "a") {
                let Some(h) = e.href.as_deref().map(str::trim) else { continue };
                if h.is_empty() || h.starts_with('#') || h.starts_with("javascript:") {
                    continue;
                }
                let abs = base
                    .as_ref()
                    .and_then(|b| b.join(h).ok())
                    .map(|u| u.to_string())
                    .unwrap_or_else(|| h.to_string());
                if seen.insert(abs.clone()) {
                    let label = if e.text.is_empty() { e.aria_label.clone().unwrap_or_default() } else { e.text.clone() };
                    links.push(json!({"href": abs, "text": label}));
                }
            }
            out["links"] = json!(links);
        }
        if wants("snapshot") {
            SnapShape::from_params(params).apply(entries, url, &doc, &mut out);
        }
    }
    if wants("html") {
        out["html"] = match scope {
            Some(n) => json!(n.html()),
            None => json!(html),
        };
    }
    out
}

fn js_opts_param(params: &Value) -> JsOpts {
    let quiesce = params
        .get("quiesce")
        .and_then(Value::as_u64)
        .map(|n| n.min(1000) as u32)
        .unwrap_or(0);
    JsOpts {
        quiesce,
        page_referer: bool_param(params, "page_referer"),
        prelude: bool_param(params, "prelude"),
        pipeline: bool_param(params, "script_pipeline"),
        live_dom: bool_param(params, "live_dom"),
        fetch_pool: bool_param(params, "fetch_pool"),
        modules: bool_param(params, "modules"),
        quiet_ms: params.get("quiet_ms").and_then(|v| v.as_u64()).unwrap_or(0).min(10_000),
        code_cache: bool_param(params, "code_cache"),
    }
}

/// A body the caller cannot use as text: not a text/markup/JSON content
/// type, or PDF magic whatever the header says.
fn is_binary_body(content_type: &str, bytes: &[u8]) -> bool {
    if bytes.starts_with(b"%PDF-") {
        return true;
    }
    let ct = content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    if ct.is_empty() || ct.starts_with("text/") {
        return false;
    }
    !(ct.contains("json") || ct.contains("xml") || ct.contains("html")
        || ct.contains("javascript") || ct.contains("x-www-form-urlencoded"))
}

pub fn detect_bot(body: &str) -> Option<&'static str> {
    for (sig, reason) in [
        ("px-captcha", "perimeterx_challenge"),
        ("arkoselabs.com", "arkose_enforcement"),
        ("/login/checkpoint", "login_checkpoint"),
        ("feed_units\":null", "empty_feed_units"),
    ] {
        if body.contains(sig) {
            return Some(reason);
        }
    }
    None
}

// ── Render mode (benchmark-loop firing 3) ───────────────────────────────────
//
// `goto`/`fetch` with `render: true` execute the loaded document's <script>
// nodes in document order, pump the bridge's timer queue to settle, and
// adopt the DOM mutations through the SAME writeback slot the eval verb
// uses — the opt-in, one-call counterpart of driving the page by hand
// through eval. Default off: the agent-contract pin "goto parses, eval
// executes" (docs/sidecar-protocol.md §7) stays true unless the caller
// asks.

/// A page can reference dozens of external scripts; fetching them all would
/// turn one render into a crawl. These caps keep the pass bounded; every
/// skipped script is reported in `render_errors`, never silently dropped.
const RENDER_MAX_EXTERNALS: usize = 8;
const RENDER_MAX_SCRIPT_BYTES: usize = 512 * 1024;
const RENDER_MAX_ERRORS: usize = 5;
/// Page-script navigation follows per render call (location.href= and
/// friends during the script pump). Contract symmetry with the meta-refresh
/// cap in se-net: a page chaining script redirects past the cap is a
/// redirect loop, not content.
const RENDER_NAV_MAX_HOPS: usize = 10;

/// Per-pass stats folded into the goto/fetch envelope. `final_url` /
/// `final_status` are set when a page-script navigation follow replaced the
/// document — the envelope overwrites its top-level url/status with them so
/// the caller sees where the render actually landed.
#[derive(Default)]
struct RenderStats {
    /// What the page reported about itself during the pass (console.error,
    /// handler exceptions): `page_errors` in the envelope. Prelude renders only.
    page_errors: Vec<String>,
    scripts: usize,
    skipped: usize,
    errors: Vec<String>,
    /// Uncapped count behind `errors`: the array is truncated to
    /// RENDER_MAX_ERRORS for the envelope, and this tells the caller how
    /// many were lost to the cap (a flooded boot error tail, not 5 errors).
    errors_total: usize,
    ms: f64,
    nav_hops: usize,
    final_url: Option<String>,
    final_status: Option<u16>,
}

/// Same-document test for the render follow: a location.hash= move (or a
/// self-assignment reload) must not refetch — the fragment is stripped and
/// the rest compared literally. Both sides are already absolutized (tab.url
/// is the navigation's final_url, the bridge absolutizes page_url), so a
/// literal compare is the contract; an unparseable-looking value just
/// compares as-is.
fn same_document_url(current: &str, target: &str) -> bool {
    fn strip(u: &str) -> &str {
        u.split('#').next().unwrap_or(u)
    }
    strip(current) == strip(target)
}

/// One script the render pass will execute: inline source (or a decoded
/// data-URI src), or an external URL fetched through the session client
/// first.
enum ScriptUnit {
    Inline(String),
    External(String),
}

/// Optional boolean param with string tolerance (the `network_log clear`
/// pattern, lib.rs below) — agents wire params as strings sometimes.
fn bool_param(params: &Value, key: &str) -> bool {
    match params.get(key) {
        Some(Value::Bool(b)) => *b,
        _ => param(params, key).map(|v| v == "true").unwrap_or(false),
    }
}

/// Optional pump-budget param with string tolerance (the `ws_recv
/// timeout_ms` pattern). Capped: the pump sleeps until the nearest timer
/// deadline, so an uncapped caller value could pin the single JS worker.
fn settle_ms_param(params: &Value) -> Option<std::time::Duration> {
    let ms = params
        .get("settle_ms")
        .and_then(Value::as_u64)
        .or_else(|| param(params, "settle_ms").and_then(|s| s.parse().ok()))?;
    Some(std::time::Duration::from_millis(ms.clamp(1, 15_000)))
}

/// Decide whether a <script type="..."> is executable classic JS. Empty /
/// missing means classic; the JS mimes mean classic; `module` and the data
/// blocks (importmap, JSON-LD — the extractors read those) are skipped with
/// a reason.
fn script_kind(type_attr: Option<&str>) -> Result<(), &'static str> {
    let Some(t) = type_attr.map(str::trim) else {
        return Ok(());
    };
    let t = t.split(';').next().unwrap_or(t).trim().to_ascii_lowercase();
    if t.is_empty() {
        return Ok(());
    }
    match t.as_str() {
        "text/javascript" | "application/javascript" | "text/ecmascript"
        | "application/ecmascript" | "text/jscript" | "text/x-javascript"
        | "text/x-ecmascript" => Ok(()),
        "module" => Err("module scripts unsupported"),
        _ => Err("non-JS type"),
    }
}

/// Document-order script inventory. Returns the executable units plus a
/// reason per skipped script (non-JS type, unresolvable src, non-JS or
/// oversized data URI). `data:`-URI srcs decode straight to Inline units —
/// browsers execute JS-mime data-URI scripts, and Comet-class pages (FB's
/// marketplace among them) boot partly from data chunks; before this they
/// fell into the unresolvable skip and hydration never completed.
#[cfg_attr(not(test), allow(dead_code))]
fn collect_scripts(html: &str, base_url: &str) -> (Vec<ScriptUnit>, Vec<String>) {
    let (units, _, skips) = collect_scripts_ext(html, base_url, false);
    (units, skips)
}

/// `collect_scripts` that can keep module scripts: with `modules` on, a
/// `type="module"` script is a unit (flagged in the parallel vector) and a
/// `nomodule` fallback is skipped, as in a browser that runs modules.
fn collect_scripts_ext(
    html: &str,
    base_url: &str,
    modules: bool,
) -> (Vec<ScriptUnit>, Vec<bool>, Vec<String>) {
    let mut units = Vec::new();
    let mut flags = Vec::new();
    let mut skips = Vec::new();
    let parsed = Document::parse(html);
    let Ok(doc) = parsed.select("script") else {
        return (units, flags, skips);
    };
    // The flag of the unit the previous node produced (a node may `continue`
    // out of the match below after pushing its unit).
    let mut last_module = false;
    for node in doc {
        flags.resize(units.len(), last_module);
        let is_module = modules
            && node
                .attr("type")
                .map(|t| t.trim().eq_ignore_ascii_case("module"))
                .unwrap_or(false);
        if !is_module {
            if let Err(why) = script_kind(node.attr("type")) {
                skips.push(format!("script skipped: {why}"));
                continue;
            }
            if modules && node.attr("nomodule").is_some() {
                skips.push("script skipped: nomodule fallback".to_string());
                continue;
            }
        }
        last_module = is_module;
        match node.attr("src") {
            Some(src) if !src.trim().is_empty() => {
                let src = src.trim();
                if let Some(decoded) = data_uri_script(src) {
                    match decoded {
                        Ok(source) => units.push(ScriptUnit::Inline(source)),
                        Err(why) => skips.push(format!("script skipped: {why}")),
                    }
                    continue;
                }
                match url::Url::parse(base_url).and_then(|b| b.join(src)) {
                    Ok(u) if u.scheme() == "http" || u.scheme() == "https" => {
                        units.push(ScriptUnit::External(u.to_string()));
                    }
                    _ => {
                        // Skip reasons ride render_errors in the RPC
                        // response, and a rejected src (data-URI class
                        // values run to hundreds of KB) must not bloat it —
                        // only a preview goes in the reason.
                        let preview: String = src.chars().take(80).collect();
                        skips.push(format!("script skipped: unresolvable src {preview:?}"));
                    }
                }
            }
            _ => units.push(ScriptUnit::Inline(node.text())),
        }
    }
    flags.resize(units.len(), last_module);
    (units, flags, skips)
}

/// Executable JS mimes for `data:`-URI script srcs — the `script_kind`
/// classic six plus the vendor spellings (FB serves Comet bootloader chunks
/// as `application/x-javascript`). An empty/missing mediatype defaults to
/// text/plain (RFC 2397) and is NOT executable, matching browsers.
fn is_js_mime(mime: &str) -> bool {
    matches!(
        mime,
        "text/javascript"
            | "application/javascript"
            | "text/ecmascript"
            | "application/ecmascript"
            | "text/jscript"
            | "application/jscript"
            | "text/x-javascript"
            | "text/x-ecmascript"
            | "application/x-javascript"
    )
}

/// A `src="data:..."` script decoded to source. `None` = not a data URI at
/// all (caller falls through to URL resolution); `Some(Err)` = a data URI
/// that can't be an executable unit (the reason lands in the skip log).
/// Base64 payloads reuse imgmeta's RFC-4648 decoder (whitespace-tolerant,
/// padding-checked); the plain form is percent-encoded, where '+' is a
/// literal plus (data URIs are NOT form-urlencoded). Decoded size is capped
/// like fetched externals.
fn data_uri_script(src: &str) -> Option<Result<String, String>> {
    let head = src.get(..5)?;
    if !head.eq_ignore_ascii_case("data:") {
        return None;
    }
    let rest = &src[5..];
    let (meta, payload) = rest.split_once(',')?;
    let mime = meta
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if !is_js_mime(&mime) {
        return Some(Err(format!("non-JS data URI mime {mime:?}")));
    }
    let base64 = meta
        .split(';')
        .skip(1)
        .any(|p| p.trim().eq_ignore_ascii_case("base64"));
    let decoded: Result<Vec<u8>, String> = if base64 {
        imgmeta::base64_decode(payload)
            .ok_or_else(|| "malformed base64 data URI".to_string())
    } else {
        percent_decode(payload.as_bytes())
            .ok_or_else(|| "malformed percent-encoding in data URI".to_string())
    };
    let bytes = match decoded {
        Ok(b) => b,
        Err(why) => return Some(Err(why)),
    };
    if bytes.len() > RENDER_MAX_SCRIPT_BYTES {
        return Some(Err(format!(
            "data URI script exceeds {RENDER_MAX_SCRIPT_BYTES} bytes"
        )));
    }
    Some(Ok(String::from_utf8_lossy(&bytes).into_owned()))
}

/// Percent-decode a data-URI payload: only %XX escapes decode; every other
/// byte (including '+') is literal. None on a dangling or non-hex escape so
/// the caller records a skip instead of running corrupt source.
fn percent_decode(bytes: &[u8]) -> Option<Vec<u8>> {
    fn hex(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hi = hex(*bytes.get(i + 1)?)?;
            let lo = hex(*bytes.get(i + 2)?)?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Some(out)
}

/// The render harness: ONE eval drives the whole pass. A fresh context per
/// eval means cross-script `var`/function sharing requires a single eval;
/// the per-script `new Function` probe plus per-script try/catch isolate
/// failures the way separate <script> elements do in a browser. Indirect
/// `(0, eval)` runs each script in the global scope (var/function shared in
/// document order); its lexical `let`/`const` stay script-local, a
/// documented limitation. The epilogue dispatches DOMContentLoaded on
/// document — the bridge never fires it and readyState is hardcoded
/// "complete", so gating scripts register but never run without this;
/// bubbles:true carries it to window listeners (event_phases' bubble leg).
/// Completion value: the error array, which lands in `render_errors`.
#[allow(dead_code)]
fn render_harness(encoded_sources: &str, prelude: bool) -> String {
    render_harness_live(encoded_sources, prelude, None)
}

/// `render_harness` with the live DOM: `keys` is a JSON array parallel to the
/// sources (the external script's URL, or null for an inline one), so each
/// script runs with `document.currentScript` and a `document.write` position.
fn render_harness_live(encoded_sources: &str, prelude: bool, keys: Option<&str>) -> String {
    if let (true, Some(keys)) = (prelude, keys) {
        let mods = "[]";
        return render_harness_full(encoded_sources, keys, mods, true, false);
    }
    render_harness_plain(encoded_sources, prelude)
}

/// The prelude harness with every optional piece: the live DOM (`live`),
/// module scripts (`mods`: a JSON array of booleans parallel to the sources;
/// modules run after the classic scripts, in order, before DOMContentLoaded,
/// as deferred scripts do) and the cached classic-script runner (`cache`).
fn render_harness_full(
    encoded_sources: &str,
    keys: &str,
    mods: &str,
    live: bool,
    cache: bool,
) -> String {
    {
        let live_boot = if live {
            format!(
                r#"try {{ if (typeof __seRunScript === "function") {{ __seRunScript({live_src}, "se:livedom"); }} else {{ (0, eval)({live_src}); }} }} catch (__el) {{ (globalThis.__sePageErrors = globalThis.__sePageErrors || []).push("livedom: " + (__el && __el.stack || __el)); }}"#,
                live_src = serde_json::to_string(LIVEDOM_JS).unwrap_or_else(|_| "\"\"".to_string()),
            )
        } else {
            String::new()
        };
        return format!(
            r#"var __seRE = [];
try {{ if (typeof __seRunScript === "function") {{ __seRunScript({prelude_src}, "se:prelude"); }} else {{ (0, eval)({prelude_src}); }} }} catch (__ep) {{ globalThis.__sePageErrors = ["prelude: " + __ep]; }}
{live_boot}
var __seSS = {encoded_sources};
var __seSK = {keys};
var __seSM = {mods};
var __seCC = {cache} && typeof __seRunScript === "function";
var __seLV = globalThis.__seLive;
var __seMQ = [];
for (var __sei = 0; __sei < __seSS.length; __sei++) {{
  var __s = __seSS[__sei];
  if (__seSM[__sei]) {{ __seMQ.push(__sei); continue; }}
  if (__seCC) {{
    if (__seLV) {{ try {{ __seLV.enter(__s, __seSK[__sei]); }} catch (__e5) {{}} }}
    try {{ __seRunScript(__s, __seSK[__sei] || null); }} catch (__e2) {{
      __seRE.push((__e2 instanceof SyntaxError ? "compile script " : "run script ") + __sei + ": " + __e2);
    }}
    if (__seLV) {{ try {{ __seLV.leave(); }} catch (__e6) {{}} }}
    continue;
  }}
  try {{ new Function(__s); }} catch (__e) {{
    __seRE.push("compile script " + __sei + ": " + __e); continue;
  }}
  if (__seLV) {{ try {{ __seLV.enter(__s, __seSK[__sei]); }} catch (__e5) {{}} }}
  try {{ (0, eval)(__s); }} catch (__e2) {{
    __seRE.push("run script " + __sei + ": " + __e2);
  }}
  if (__seLV) {{ try {{ __seLV.leave(); }} catch (__e6) {{}} }}
}}
for (var __seq = 0; __seq < __seMQ.length; __seq++) {{
  var __mi = __seMQ[__seq];
  try {{
    var __mp = __seRunModule(__seSS[__mi], __seSK[__mi] || null);
    if (__mp && typeof __mp.then === "function") {{
      __mp.then(null, function (__me) {{
        (globalThis.__sePageErrors = globalThis.__sePageErrors || []).push("module: " + (__me && __me.message || __me));
      }});
    }}
  }} catch (__e7) {{
    __seRE.push("run module " + __mi + ": " + (__e7 && __e7.message || __e7));
  }}
}}
try {{
  document.dispatchEvent({{ type: "DOMContentLoaded", bubbles: true }});
}} catch (__e3) {{ __seRE.push("dispatch: " + __e3); }}
try {{
  if (typeof window.onload === "function") {{
    var __o = window.onload, __c = 0;
    window.onload = function (e) {{ __c++; return __o.call(this, e); }};
    window.dispatchEvent({{ type: "load" }});
    if (!__c) {{ window.onload({{ type: "load", target: window }}); }}
    window.onload = __o;
  }} else {{
    window.dispatchEvent({{ type: "load" }});
  }}
}} catch (__e4) {{ (globalThis.__sePageErrors = globalThis.__sePageErrors || []).push("load: " + __e4); }}
({{ errors: __seRE, page_errors: (globalThis.__sePageErrors || []).slice(0, 10) }});"#,
            prelude_src = serde_json::to_string(PRELUDE_JS).unwrap_or_else(|_| "\"\"".to_string()),
        );
    }
}

fn render_harness_plain(encoded_sources: &str, prelude: bool) -> String {
    if prelude {
        // Same script loop, between the globals prelude and the lifecycle a
        // browser runs after parsing: DOMContentLoaded, then `load` on window
        // (listeners and a bare `window.onload`, once each). Pages that start
        // from `load` never started before this.
        return format!(
            r#"var __seRE = [];
try {{ if (typeof __seRunScript === "function") {{ __seRunScript({prelude_src}, "se:prelude"); }} else {{ (0, eval)({prelude_src}); }} }} catch (__ep) {{ globalThis.__sePageErrors = ["prelude: " + __ep]; }}
var __seSS = {encoded_sources};
for (var __sei = 0; __sei < __seSS.length; __sei++) {{
  var __s = __seSS[__sei];
  try {{ new Function(__s); }} catch (__e) {{
    __seRE.push("compile script " + __sei + ": " + __e); continue;
  }}
  try {{ (0, eval)(__s); }} catch (__e2) {{
    __seRE.push("run script " + __sei + ": " + __e2);
  }}
}}
try {{
  document.dispatchEvent({{ type: "DOMContentLoaded", bubbles: true }});
}} catch (__e3) {{ __seRE.push("dispatch: " + __e3); }}
try {{
  if (typeof window.onload === "function") {{
    var __o = window.onload, __c = 0;
    window.onload = function (e) {{ __c++; return __o.call(this, e); }};
    window.dispatchEvent({{ type: "load" }});
    if (!__c) {{ window.onload({{ type: "load", target: window }}); }}
    window.onload = __o;
  }} else {{
    window.dispatchEvent({{ type: "load" }});
  }}
}} catch (__e4) {{ (globalThis.__sePageErrors = globalThis.__sePageErrors || []).push("load: " + __e4); }}
({{ errors: __seRE, page_errors: (globalThis.__sePageErrors || []).slice(0, 10) }});"#,
            prelude_src = serde_json::to_string(PRELUDE_JS).unwrap_or_else(|_| "\"\"".to_string()),
        );
    }
    format!(
        r#"var __seRE = [];
var __seSS = {encoded_sources};
for (var __sei = 0; __sei < __seSS.length; __sei++) {{
  var __s = __seSS[__sei];
  try {{ new Function(__s); }} catch (__e) {{
    __seRE.push("compile script " + __sei + ": " + __e); continue;
  }}
  try {{ (0, eval)(__s); }} catch (__e2) {{
    __seRE.push("run script " + __sei + ": " + __e2);
  }}
}}
try {{
  document.dispatchEvent({{ type: "DOMContentLoaded", bubbles: true }});
}} catch (__e3) {{ __seRE.push("dispatch: " + __e3); }}
__seRE;"#
    )
}

/// The verb dispatcher. Deliberately NOT an `async fn`: `rpc` awaits this
/// boxed future, so axum's `Handler` bound sees a small nameable type. The
/// per-verb match composes ~20 verb futures into one opaque generator, and
/// that composed type overflows trait resolution when it bubbles up through
/// `rpc` (firing 38 — read_snapshot/read_image tipped it over).
fn dispatch<'a>(
    engine: &'a Engine,
    method: &'a str,
    params: Value,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Value, (i64, String)>> + Send + 'a>,
> {
    Box::pin(async move {
        // Tab bookkeeping around every verb: the tab it names is in use for
        // the length of the call, and idle tabs are swept on the way in.
        struct InUse<'e>(&'e Engine, String);
        impl Drop for InUse<'_> {
            fn drop(&mut self) {
                self.0.tab_touch(&self.1, -1);
            }
        }
        let tab = tab_id_of(&params).to_string();
        engine.tab_touch(&tab, 1);
        let _in_use = InUse(engine, tab);
        let (idle, cap) = tab_limits();
        engine.sweep_tabs(idle, cap);
        dispatch_inner(engine, method, params).await
    })
}

fn dispatch_inner<'a>(
    engine: &'a Engine,
    method: &'a str,
    params: Value,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Value, (i64, String)>> + Send + 'a>,
> {
    Box::pin(async move {
    match method {
        "health" => Ok(json!({
            "ok": true,
            "engine": "searchio-engine",
            "version": env!("CARGO_PKG_VERSION"),
            "js": engine.js.health(),
            "code_cache": {
                "hits": se_js::code_cache_stats().0,
                "misses": se_js::code_cache_stats().1,
                "rejected": se_js::code_cache_stats().2,
                "entries": se_js::code_cache_stats().3,
                "bytes": se_js::code_cache_stats().4,
            },
            "tls_impersonate": {
                "built": se_net::TLS_IMPERSONATE_BUILT,
                "on": se_net::tls_impersonate_enabled(),
            },
            "tabs": engine.tabs.lock().unwrap_or_else(|e| e.into_inner()).len(),
            "ws": engine.ws_conns.lock().unwrap_or_else(|e| e.into_inner()).len(),
            "tabs_swept": engine.tab_use.lock().unwrap_or_else(|e| e.into_inner()).swept,
            "tab_idle_s": tab_limits().0.map(|d| d.as_secs()).unwrap_or(0),
            "tab_max": tab_limits().1,
        })),

        "goto" => {
            let url = param(&params, "url").unwrap_or("");
            if url.is_empty() {
                return Ok(verb_error("goto: missing url"));
            }
            // A followed navigation: the tab's current URL is this load's
            // initiator (wire Referer + Sec-Fetch-Site, document.referrer).
            // First load on the tab → None → address-bar presentation.
            let initiator = {
                let tabs = engine.tabs.lock().unwrap_or_else(|e| e.into_inner());
                tabs.get(tab_id_of(&params)).map(|t| t.url.clone())
            };
            let client = engine.client.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let hop_started = std::time::Instant::now();
            let nav = client.navigate(url, initiator.as_deref());
            let resp = match deadline_param(&params) {
                Some(d) => match tokio::time::timeout(d, nav).await {
                    Ok(r) => r,
                    Err(_) => {
                        return Ok(verb_error(format!(
                            "goto: no answer within timeout_ms ({} ms)", d.as_millis()
                        )))
                    }
                },
                None => nav.await,
            };
            let resp = match resp {
                Ok(r) => r,
                Err(e) => return Ok(verb_error(format!("goto: {e}"))),
            };
            // One document entry per completed navigation, keyed by the
            // REQUESTED url — redirect hops inside the HTTP client are not
            // individually visible at this layer (the page-fetch path logs
            // each hop because it follows redirects itself).
            engine.net_log.record(
                "document",
                "GET",
                url,
                resp.status,
                hop_started.elapsed(),
            );
            let bot = bot_verdict(&resp.body, &resp.final_url, &params);
            let tab = {
                let tabs = engine.tabs.lock().unwrap_or_else(|e| e.into_inner());
                Tab::after_navigation(
                    tabs.get(tab_id_of(&params)),
                    &resp.final_url,
                    initiator.unwrap_or_default(),
                    resp.body.clone(),
                )
            };
            engine
                .tabs
                .lock().unwrap_or_else(|e| e.into_inner())
                .insert(tab_id_of(&params).to_string(), tab);
            let mut out = json!({
                "ok": true,
                "status": resp.status,
                "final_url": resp.final_url,
                "http_version": resp.version,
                "bot_detected": bot.is_some(),
                "bot_reason": bot.unwrap_or(""),
            });
            if bool_param(&params, "render") {
                let budget = settle_ms_param(&params).unwrap_or(se_js::bridge::TIMER_BUDGET);
                let stats = JS_OPTS
                    .scope(js_opts_param(&params), engine.render_tab(tab_id_of(&params), budget))
                    .await;
                out["rendered"] = json!(true);
                out["render_scripts"] = json!(stats.scripts);
                out["render_skipped"] = json!(stats.skipped);
                out["render_errors"] = json!(stats.errors);
                out["render_errors_total"] = json!(stats.errors_total);
                out["render_ms"] = json!(stats.ms);
                out["render_nav_hops"] = json!(stats.nav_hops);
                if !stats.page_errors.is_empty() {
                    out["page_errors"] = json!(stats.page_errors);
                }
                // A page-script navigation follow replaced the document:
                // the envelope reports where the render actually LANDED.
                if let (Some(u), Some(s)) = (stats.final_url, stats.final_status) {
                    out["final_url"] = json!(u);
                    out["status"] = json!(s);
                }
            }
            Ok(out)
        }

        "read" => {
            // One call, one parse: any of html / text / snapshot / links of a
            // tab (`include`), all from the same document state.
            let Some((url, html)) = tab_document(engine, &params) else {
                return Ok(verb_error(format!("read: no tab {:?}", tab_id_of(&params))));
            };
            Ok(off_worker(|| read_combined(&params, &url, html)))
        }

        "read_html" => {
            // The tab lock is held for the copy only: parsing a large page
            // under it made every other tab's read wait.
            let Some((_, tab_html)) = tab_document(engine, &params) else {
                return Ok(verb_error(format!("read_html: no tab {:?}", tab_id_of(&params))));
            };
            let html = match param(&params, "selector") {
                Some(sel) if !sel.is_empty() => {
                    let picked = off_worker(|| {
                        let doc = Document::parse(&tab_html);
                        doc.select(sel)
                            .map(|nodes| nodes.iter().map(|n| n.html()).collect::<String>())
                            .map_err(|e| e.to_string())
                    });
                    match picked {
                        Ok(html) => html,
                        Err(e) => return Ok(verb_error(format!("read_html: {e}"))),
                    }
                }
                _ => tab_html,
            };
            Ok(json!({"ok": true, "html": html}))
        }

        "read_text" => {
            off_worker(|| -> Result<Value, (i64, String)> {
            // The protocol's text-extraction verb (Playwright `inner_text`
            // parity): `selector` → first match, else `body`. The engine
            // has no CSSOM, so the se-dom walk is a structural floor —
            // block boundaries become newlines, script/style/noscript/
            // template subtrees are skipped, whitespace collapses.
            // Hidden-element evaluation would need layout; the zero-DOMRect
            // precedent documents that as out of scope by design.
            let Some((tab_url, tab_html)) = tab_document(engine, &params) else {
                return Ok(verb_error(format!(
                    "read_text: no tab {:?}",
                    tab_id_of(&params)
                )));
            };
            let doc = Document::parse(&tab_html);
            let target = match param(&params, "selector") {
                Some(sel) if !sel.is_empty() => match doc.select_one(sel) {
                    Ok(t) => t,
                    Err(e) => return Ok(verb_error(format!("read_text: {e}"))),
                },
                _ => match doc.select_one("body") {
                    Ok(b) => b.or_else(|| doc.root()),
                    Err(e) => return Ok(verb_error(format!("read_text: {e}"))),
                },
            };
            let text = target.map(|n| n.inner_text()).unwrap_or_default();
            Ok(json!({
                "ok": true,
                "tab_id": tab_id_of(&params),
                "url": tab_url,
                "text": text,
            }))
                    })
        }

        "read_snapshot" => {
            off_worker(|| -> Result<Value, (i64, String)> {
            // The agent's structural "eyes" (firing 38): a flat, document-
            // order list of VISIBLE elements — kind, computed role, text,
            // interactivity, and the identity attributes an agent acts on.
            // Visibility is the no-CSSOM structural floor (hidden attr,
            // inline display:none/visibility:hidden/opacity:0, type=hidden,
            // aria-hidden) — hidden subtrees are pruned, not listed. `selector`
            // scopes to the FIRST match's subtree; absent = whole document.
            let Some((tab_url, tab_html)) = tab_document(engine, &params) else {
                return Ok(verb_error(format!(
                    "read_snapshot: no tab {:?}",
                    tab_id_of(&params)
                )));
            };
            let doc = Document::parse(&tab_html);
            let scope_node = match param(&params, "selector") {
                Some(sel) if !sel.is_empty() => match doc.select_one(sel) {
                    Ok(Some(node)) => Some(node),
                    Ok(None) => {
                        return Ok(verb_error(format!("read_snapshot: no match {sel:?}")))
                    }
                    Err(e) => return Ok(verb_error(format!("read_snapshot: {e}"))),
                },
                _ => None,
            };
            let entries = se_dom::snapshot::snapshot(&doc, scope_node);
            // Shaping is opt-in: without the options the list is as before.
            let shape = SnapShape::from_params(&params);
            let mut out = json!({
                "ok": true,
                "tab_id": tab_id_of(&params),
                "url": tab_url,
            });
            shape.apply(entries, &tab_url, &doc, &mut out);
            Ok(out)
                    })
        }

        "read_image" => {
            // The capture half of "capture and solve" (firing 38): resolve an
            // image element, fetch its bytes THROUGH THE SESSION (jar rides,
            // <img>-shaped Fetch Metadata — no-cors/image), and hand the agent
            // raw bytes + container metadata for a vision model. data: URLs
            // decode in place. Page pixels stay a non-goal — this is image
            // extraction, not rasterization.
            // Phase 1 — scoped extraction under the lock (the goto-arm
            // pattern): the guard AND the scraper parse tree (ego-tree nodes
            // are !Sync, so a Node held across an await poisons the whole
            // dispatch future's Send) die at this block's close, before any
            // await. Only owned values escape.
            let (base, alt, src) = {
                let tabs = engine.tabs.lock().unwrap_or_else(|e| e.into_inner());
                let Some(tab) = tabs.get(tab_id_of(&params)) else {
                    return Ok(verb_error(format!(
                        "read_image: no tab {:?}",
                        tab_id_of(&params)
                    )));
                };
                let sel = param(&params, "selector").unwrap_or("img");
                let doc = Document::parse(&tab.html);
                let node = match doc.select_one(sel) {
                    Ok(t) => t,
                    Err(e) => return Ok(verb_error(format!("read_image: {e}"))),
                };
                let Some(node) = node else {
                    return Ok(verb_error(format!("read_image: no match {sel:?}")));
                };
                let alt = node.attr("alt").map(|s| s.to_string());
                // src wins; an inline background-image url() is the fallback
                // (elements that carry their imagery in CSS).
                let src = node.attr("src").map(|s| s.to_string()).or_else(|| {
                    node.attr("style").and_then(|style| {
                        let squashed: String =
                            style.chars().filter(|c| !c.is_whitespace()).collect();
                        let at = squashed.find("url(")? + 4;
                        let rest = &squashed[at..];
                        // Skip an optional OPENING quote before scanning for
                        // the closer — quoted urls are the common form.
                        let rest = match rest.as_bytes().first() {
                            Some(b'\'') | Some(b'"') => &rest[1..],
                            _ => rest,
                        };
                        let end = rest.find(&[')', '\"', '\''][..])?;
                        Some(rest[..end].to_string())
                    })
                });
                (tab.url.clone(), alt, src)
            };
            let Some(src) = src else {
                return Ok(verb_error("read_image: element has no image source"));
            };
            let (bytes, content_type, final_src) = if let Some(rest) = src.strip_prefix("data:") {
                // data:<mime>;base64,<payload> — decode in place, no fetch.
                let (mime, payload) = rest.split_once(',').unwrap_or((rest, ""));
                let bytes = if mime.ends_with(";base64") {
                    match imgmeta::base64_decode(payload) {
                        Some(b) => b,
                        None => return Ok(verb_error("read_image: bad data: URL base64")),
                    }
                } else {
                    payload.as_bytes().to_vec()
                };
                let mime = mime.trim_end_matches(";base64").to_string();
                (bytes, mime, src.clone())
            } else {
                // Resolve relative src against the tab URL, then fetch through
                // the session with the <img>-shaped block (DataKind::Image).
                let abs = match url::Url::parse(&base).and_then(|b| b.join(&src)) {
                    Ok(u) => u.to_string(),
                    Err(_) => return Ok(verb_error(format!("read_image: bad src {src:?}"))),
                };
                let client = engine.client.lock().unwrap_or_else(|e| e.into_inner()).clone();
                let initiator = Some(base.as_str());
                let hop_started = std::time::Instant::now();
                let resp =
                    match client.request_data(&abs, "GET", &[], "", initiator, se_net::DataKind::Image).await {
                        Ok(r) => r,
                        Err(e) => return Ok(verb_error(format!("read_image: {e}"))),
                    };
                engine
                    .net_log
                    .record("fetch", "GET", &abs, resp.status, hop_started.elapsed());
                let ct = resp
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default();
                if resp.status != 200 {
                    return Ok(verb_error(format!(
                        "read_image: HTTP {} for {abs}",
                        resp.status
                    )));
                }
                (resp.body_bytes, ct, abs)
            };
            let meta = imgmeta::sniff(&bytes, &content_type);
            Ok(json!({
                "ok": true,
                "tab_id": tab_id_of(&params),
                "src": final_src,
                "alt": alt,
                "content_type": content_type,
                "format": meta.format,
                "width": meta.width,
                "height": meta.height,
                "byte_length": bytes.len(),
                "bytes_base64": imgmeta::base64_encode(&bytes),
            }))
        }

        // ------------------------------------------------------------------
        // The agent's WebSocket tier (firing 39): agent-side socket verbs.
        // The page-side `WebSocket` stub stays shape-only FOREVER — the AGENT
        // owns the socket, so no page eval can hang on a live connection and
        // the handshake presents the session exactly like a data call (UA,
        // Origin, the jar's full Cookie line incl. httpOnly). Take-replace
        // discipline throughout: a conn leaves the map, one async op runs,
        // it goes back (or is dropped on error) — no guard crosses an await.
        // ------------------------------------------------------------------
        "ws_connect" => {
            let Some(url) = param(&params, "url") else {
                return Ok(verb_error("ws_connect: missing url"));
            };
            if !url.starts_with("ws://") && !url.starts_with("wss://") {
                return Ok(verb_error(format!("ws_connect: want ws:// or wss://, got {url:?}")));
            }
            // Extra headers: a flat object of strings, appended verbatim after
            // the engine block (auth tokens, Sec-WebSocket-Protocol, ...).
            let mut extra: Vec<(String, String)> = Vec::new();
            if let Some(Value::Object(map)) = params.get("headers") {
                for (k, v) in map {
                    let Some(vs) = v.as_str() else {
                        return Ok(verb_error(format!("ws_connect: header {k:?} is not a string")));
                    };
                    // A line break in a name or value would write a second
                    // header (or a second request) into the handshake.
                    if k.is_empty()
                        || k.bytes().any(|b| b <= b' ' || b == b':' || b >= 0x7f)
                        || vs.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
                    {
                        return Ok(verb_error(format!("ws_connect: header {k:?} is not a valid header")));
                    }
                    extra.push((k.clone(), vs.to_string()));
                }
            }
            // Sockets the agent never closed: drop the idle ones, then refuse
            // past the cap rather than grow without bound.
            let (ws_idle, ws_max) = ws_limits();
            let open = engine.sweep_ws(ws_idle);
            if ws_max > 0 && open >= ws_max {
                return Ok(verb_error(format!(
                    "ws_connect: {open} connections open (limit {ws_max}); close one first"
                )));
            }
            let (ua, cookie) = {
                let client = engine.client.lock().unwrap_or_else(|e| e.into_inner()).clone();
                let ua = client.user_agent();
                // The jar keys on scheme: normalize ws→http / wss→https so
                // secure-cookie matching sees the TLS flag it expects.
                let cookie_url = if let Some(rest) = url.strip_prefix("wss://") {
                    format!("https://{rest}")
                } else if let Some(rest) = url.strip_prefix("ws://") {
                    format!("http://{rest}")
                } else {
                    url.to_string()
                };
                (ua, client.store().cookie_header(&cookie_url))
            };
            let ctx = se_net::ws::HandshakeCtx {
                ua,
                origin: param(&params, "origin").map(str::to_string),
                cookie,
                headers: extra,
            };
            let budget = params
                .get("timeout_ms")
                .and_then(Value::as_u64)
                .unwrap_or(15_000)
                .clamp(100, 120_000);
            let (conn, resp_headers) = match se_net::ws::connect_within(
                url,
                &ctx,
                std::time::Duration::from_millis(budget),
            )
            .await
            {
                Ok(t) => t,
                Err(e) => return Ok(verb_error(format!("ws_connect: {e}"))),
            };
            let id_n = engine
                .ws_next
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let ws_id = format!("ws-{id_n}");
            engine
                .ws_conns
                .lock().unwrap_or_else(|e| e.into_inner())
                .insert(ws_id.clone(), conn);
            let headers_obj: serde_json::Map<String, Value> = resp_headers
                .into_iter()
                .map(|(k, v)| (k, Value::String(v)))
                .collect();
            Ok(json!({
                "ok": true,
                "ws_id": ws_id,
                "url": url,
                "status": 101,
                "response_headers": Value::Object(headers_obj),
            }))
        }

        "ws_send" => {
            let Some(ws_id) = param(&params, "ws_id") else {
                return Ok(verb_error("ws_send: missing ws_id"));
            };
            let data = param(&params, "data");
            let data_b64 = param(&params, "data_base64");
            let (payload, text) = match (data, data_b64) {
                (Some(s), None) => (s.as_bytes().to_vec(), true),
                (None, Some(s)) => match imgmeta::base64_decode(s) {
                    Some(b) => (b, false),
                    None => return Ok(verb_error("ws_send: bad data_base64")),
                },
                (Some(_), Some(_)) => {
                    return Ok(verb_error("ws_send: pass exactly one of data / data_base64"));
                }
                (None, None) => return Ok(verb_error("ws_send: missing data or data_base64")),
            };
            let conn = {
                let mut conns = engine.ws_conns.lock().unwrap_or_else(|e| e.into_inner());
                conns.remove(ws_id)
            };
            let Some(mut conn) = conn else {
                return Ok(verb_error(format!("ws_send: no ws connection {ws_id:?}")));
            };
            match conn.send(&payload, text).await {
                Ok(()) => {
                    let sent = payload.len();
                    engine
                        .ws_conns
                        .lock().unwrap_or_else(|e| e.into_inner())
                        .insert(ws_id.to_string(), conn);
                    Ok(json!({"ok": true, "ws_id": ws_id, "sent_bytes": sent}))
                }
                Err(e) => Ok(verb_error(format!("ws_send: {e}"))),
            }
        }

        "ws_recv" => {
            let Some(ws_id) = param(&params, "ws_id") else {
                return Ok(verb_error("ws_recv: missing ws_id"));
            };
            let timeout_ms = params
                .get("timeout_ms")
                .and_then(Value::as_u64)
                .or_else(|| param(&params, "timeout_ms").and_then(|s| s.parse().ok()))
                .unwrap_or(30_000)
                .min(600_000);
            let conn = {
                let mut conns = engine.ws_conns.lock().unwrap_or_else(|e| e.into_inner());
                conns.remove(ws_id)
            };
            let Some(mut conn) = conn else {
                return Ok(verb_error(format!("ws_recv: no ws connection {ws_id:?}")));
            };
            // Timeout is a NORMAL long-poll outcome for agent loops, not an
            // error: the conn goes back into the pool and the agent retries.
            let outcome = tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), conn.recv())
                .await;
            match outcome {
                Ok(Ok(se_net::ws::WsMessage::Text(s))) => {
                    engine.ws_conns.lock().unwrap_or_else(|e| e.into_inner()).insert(ws_id.to_string(), conn);
                    Ok(json!({"ok": true, "ws_id": ws_id, "kind": "text", "data": s}))
                }
                Ok(Ok(se_net::ws::WsMessage::Binary(b))) => {
                    engine.ws_conns.lock().unwrap_or_else(|e| e.into_inner()).insert(ws_id.to_string(), conn);
                    Ok(json!({"ok": true, "ws_id": ws_id, "kind": "binary", "data_base64": imgmeta::base64_encode(&b)}))
                }
                Ok(Ok(se_net::ws::WsMessage::Pong(p))) => {
                    engine.ws_conns.lock().unwrap_or_else(|e| e.into_inner()).insert(ws_id.to_string(), conn);
                    Ok(json!({"ok": true, "ws_id": ws_id, "kind": "pong", "data_base64": imgmeta::base64_encode(&p)}))
                }
                Ok(Ok(se_net::ws::WsMessage::Close { code, reason })) => {
                    // Closed conns never go back — a second recv would only
                    // error. The agent learns the terminal code/reason here.
                    Ok(json!({"ok": true, "ws_id": ws_id, "kind": "close", "code": code, "reason": reason}))
                }
                Ok(Err(e)) => Ok(verb_error(format!("ws_recv: {e}"))),
                Err(_elapsed) => {
                    engine.ws_conns.lock().unwrap_or_else(|e| e.into_inner()).insert(ws_id.to_string(), conn);
                    Ok(json!({"ok": true, "ws_id": ws_id, "kind": "timeout"}))
                }
            }
        }

        "ws_close" => {
            let Some(ws_id) = param(&params, "ws_id") else {
                return Ok(verb_error("ws_close: missing ws_id"));
            };
            let conn = {
                let mut conns = engine.ws_conns.lock().unwrap_or_else(|e| e.into_inner());
                conns.remove(ws_id)
            };
            let Some(conn) = conn else {
                return Ok(verb_error(format!("ws_close: no ws connection {ws_id:?}")));
            };
            match conn.close().await {
                Ok(()) => Ok(json!({"ok": true, "ws_id": ws_id, "closed": true})),
                Err(e) => Ok(verb_error(format!("ws_close: {e}"))),
            }
        }

        "eval" => {
            let Some(js) = param(&params, "js") else {
                return Ok(verb_error("eval: missing js"));
            };
            let cookie_store = Some(engine.client.lock().unwrap_or_else(|e| e.into_inner()).store());
            let page = engine
                .tabs
                .lock().unwrap_or_else(|e| e.into_inner())
                .get(tab_id_of(&params))
                .map(|tab| Page {
                    url: tab.url.clone(),
                    referrer: tab.referrer.clone(),
                    html: tab.html.clone(),
                    // LOCAL storage comes from the session-global pool: this
                    // tab's handle is the SAME map every tab on the origin
                    // gets, so a write in one tab is visible in another —
                    // the browser's per-profile semantics (firing 36). The
                    // tabs lock is held here; the pool lock nests inside it
                    // (the documented lock order).
                    local_storage: engine.local_storage_for(&origin_of(&tab.url)),
                    session_storage: tab.session_storage.clone(),
                    window_name: tab.window_name.clone(),
                    cookie_store,
                    net_log: Some(engine.net_log.clone()),
                    // Production path: full certificate verification. The
                    // accepting_dev_certs builder is test-tier only.
                    danger_accept_invalid_host_certs: false,
                    // The tab's writeback slot: a mutating eval publishes the
                    // mutated document here and the handler adopts it below.
                    writeback: tab.writeback.clone(),
                });
            let writeback = page
                .as_ref()
                .map(|p| p.writeback.clone());
            let result = engine.js.eval(page, js.to_string()).await;
            // Adopt a DOM-mutation writeback: if the eval mutated the
            // document and no navigation replaced the tab in between (the
            // writeback's `from` is still the tab's current html), the
            // mutation becomes the tab's live document — read_html and the
            // next eval both observe it, the way patchright's live DOM does.
            if let Some(slot) = writeback {
                let pending = slot.lock().unwrap_or_else(|e| e.into_inner()).take();
                if let Some(wb) = pending {
                    let mut tabs = engine.tabs.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(tab) = tabs.get_mut(tab_id_of(&params)) {
                        if tab.html == wb.from {
                            tab.html = wb.html;
                        }
                    }
                }
            }
            match result {
                Ok(value) => Ok(json!({"ok": true, "result": value})),
                Err(e) => Ok(verb_error(format!("eval: {e}"))),
            }
        }

        "fetch" => {
            // Two shapes, one verb (firing 37). Plain `{url}` stays the
            // HTTP-first DOCUMENT loader it has always been — the ladder's
            // tier-2 entry point, leaves a loaded tab behind so fetch → eval
            // composes. With ANY of `method`/`headers`/`body` present it is
            // a session-bound DATA call instead: subresource-shaped wire
            // block, jar rides and lands, response body comes back in the
            // envelope — and NO tab is loaded (a POST response isn't a
            // document you'd script).
            let url = param(&params, "url").unwrap_or("");
            if url.is_empty() {
                return Ok(verb_error("fetch: missing url"));
            }
            let data_call = params.get("method").is_some()
                || params.get("headers").is_some()
                || params.get("body").is_some();
            if data_call {
                let method = match params.get("method") {
                    Some(Value::String(m)) => m.clone(),
                    Some(_) => return Ok(verb_error("fetch: method must be a string")),
                    None => "GET".to_string(),
                };
                let mut custom: Vec<(String, String)> = Vec::new();
                match params.get("headers") {
                    Some(Value::Object(map)) => {
                        for (k, v) in map {
                            match v.as_str() {
                                Some(s) => custom.push((k.clone(), s.to_string())),
                                None => {
                                    return Ok(verb_error(
                                        "fetch: headers must be an object of string values",
                                    ))
                                }
                            }
                        }
                    }
                    Some(_) => {
                        return Ok(verb_error("fetch: headers must be an object of string values"))
                    }
                    None => {}
                }
                let body = match params.get("body") {
                    Some(Value::String(b)) => b.clone(),
                    Some(_) => return Ok(verb_error("fetch: body must be a string")),
                    None => String::new(),
                };
                let client = engine.client.lock().unwrap_or_else(|e| e.into_inner()).clone();
                let hop_started = std::time::Instant::now();
                // Same initiator presentation as the document path: the tab's
                // current page is the data call's initiator.
                let initiator = {
                    let tabs = engine.tabs.lock().unwrap_or_else(|e| e.into_inner());
                    tabs.get(tab_id_of(&params)).map(|t| t.url.clone())
                };
                let call = client
                    .request_data(url, &method, &custom, &body, initiator.as_deref(), se_net::DataKind::Data);
                let resp = match deadline_param(&params) {
                    Some(d) => match tokio::time::timeout(d, call).await {
                        Ok(r) => r,
                        Err(_) => {
                            return Ok(verb_error(format!(
                                "fetch: no answer within timeout_ms ({} ms)", d.as_millis()
                            )))
                        }
                    },
                    None => call.await,
                };
                let resp = match resp {
                    Ok(r) => r,
                    Err(e) => return Ok(verb_error(format!("fetch: {e}"))),
                };
                engine.net_log.record(
                    "fetch",
                    &method,
                    url,
                    resp.status,
                    hop_started.elapsed(),
                );
                let resp_headers: serde_json::Map<String, Value> = resp
                    .headers
                    .iter()
                    .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                    .collect();
                // Last-wins on duplicate names (Set-Cookie included) — the jar
                // is the source of truth for response cookies, enumerated via
                // cookies_get; this map is for content-type style lookups.
                return Ok(json!({
                    "ok": true,
                    "status": resp.status,
                    "body": resp.body,
                    "url": resp.final_url,
                    "http_version": resp.version,
                    "via": "http",
                    "headers": Value::Object(resp_headers),
                }));
            }
            // HTTP-first page fetch, the ladder's tier-2 entry point. A 4xx
            // or challenge page rides in an `ok: true` envelope — the ladder's
            // refusal check is status/signature-driven, so the verb must not
            // turn a site-level "no" into a transport error.
            let client = engine.client.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let hop_started = std::time::Instant::now();
            // A page-context HTTP fetch presents the tab's page as initiator
            // (Referer + same-origin Sec-Fetch-Site), like a subresource.
            let initiator = {
                let tabs = engine.tabs.lock().unwrap_or_else(|e| e.into_inner());
                tabs.get(tab_id_of(&params)).map(|t| t.url.clone())
            };
            let nav = client.navigate(url, initiator.as_deref());
            let resp = match deadline_param(&params) {
                Some(d) => match tokio::time::timeout(d, nav).await {
                    Ok(r) => r,
                    Err(_) => {
                        return Ok(verb_error(format!(
                            "fetch: no answer within timeout_ms ({} ms)", d.as_millis()
                        )))
                    }
                },
                None => nav.await,
            };
            let resp = match resp {
                Ok(r) => r,
                Err(e) => return Ok(verb_error(format!("fetch: {e}"))),
            };
            engine.net_log.record(
                "document",
                "GET",
                url,
                resp.status,
                hop_started.elapsed(),
            );
            let bot = bot_verdict(&resp.body, &resp.final_url, &params);
            // fetch leaves a loaded tab behind, so fetch → eval composes the
            // same way it does after the patchright sidecar's escalation.
            let tab = {
                let tabs = engine.tabs.lock().unwrap_or_else(|e| e.into_inner());
                Tab::after_navigation(
                    tabs.get(tab_id_of(&params)),
                    &resp.final_url,
                    initiator.unwrap_or_default(),
                    resp.body.clone(),
                )
            };
            engine
                .tabs
                .lock().unwrap_or_else(|e| e.into_inner())
                .insert(tab_id_of(&params).to_string(), tab);
            // The origin's content-type rides the envelope: without it the
            // caller has to assume text/html, and a binary body (a PDF is
            // the common case) then reaches page classifiers mislabeled —
            // searchio bug 20, two live PDFs shipped as ok pages.
            let content_type = resp
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            // The origin's response headers ride the page envelope the way
            // they ride the data-call one (searchio bug 166): the ladder's
            // classifier names the anti-bot vendor from them (server,
            // cf-mitigated, cf-ray, x-datadome ...) and decides whether a
            // block is worth a browser rescue; without them every tier-2
            // block was "blocked by unknown". Last-wins on duplicates; the
            // jar is the source of truth for Set-Cookie.
            let resp_headers: serde_json::Map<String, Value> = resp
                .headers
                .iter()
                .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                .collect();
            let mut out = json!({
                "ok": true,
                "status": resp.status,
                "html": resp.body,
                "url": resp.final_url,
                "http_version": resp.version,
                "via": "http",
                "content_type": content_type,
                "headers": Value::Object(resp_headers),
            });
            if let Some(reason) = bot {
                out["bot_wall"] = json!(true);
                out["blocked"] = json!(true);
                out["bot_reason"] = json!(reason);
            }
            // `binary: true`: a non-text body rides the envelope as the bytes
            // the origin sent. `html` is a lossy text decode -- a PDF read
            // through it is unusable, and the caller's only other route is a
            // second download WITHOUT this session's cookies, which a gated
            // file refuses.
            if bool_param(&params, "binary") && is_binary_body(&content_type, &resp.body_bytes) {
                out["body_base64"] = json!(imgmeta::base64_encode(&resp.body_bytes));
                out["body_bytes"] = json!(resp.body_bytes.len());
            }
            if bool_param(&params, "render") {
                let budget = settle_ms_param(&params).unwrap_or(se_js::bridge::TIMER_BUDGET);
                let stats = JS_OPTS
                    .scope(js_opts_param(&params), engine.render_tab(tab_id_of(&params), budget))
                    .await;
                out["rendered"] = json!(true);
                out["render_scripts"] = json!(stats.scripts);
                out["render_skipped"] = json!(stats.skipped);
                out["render_errors"] = json!(stats.errors);
                out["render_errors_total"] = json!(stats.errors_total);
                out["render_ms"] = json!(stats.ms);
                out["render_nav_hops"] = json!(stats.nav_hops);
                if !stats.page_errors.is_empty() {
                    out["page_errors"] = json!(stats.page_errors);
                }
                // A page-script navigation follow replaced the document:
                // the envelope reports where the render actually LANDED.
                if let (Some(u), Some(s)) = (stats.final_url, stats.final_status) {
                    out["url"] = json!(u);
                    out["status"] = json!(s);
                }
                // The tab adopted the rendered DOM; the envelope's html
                // should be the same document read_html returns.
                let tabs = engine.tabs.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(tab) = tabs.get(tab_id_of(&params)) {
                    out["html"] = json!(tab.html);
                }
            }
            Ok(out)
        }

        "cookies_get" => {
            // The live jar, in Playwright shape — including anything servers
            // set during the session, not just what was injected.
            let client = engine.client.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let cookies: Vec<Value> = client
                .store()
                .snapshot()
                .iter()
                .map(cookie_wire)
                .collect();
            Ok(json!({"ok": true, "cookies": cookies}))
        }

        "storage_state_get" => {
            // The session, exported as a Playwright storage_state artifact —
            // the producer half of storage_state_set. The shape (cookies full
            // from the live jar + LOCAL storage for current and archived
            // origins, sessionStorage excluded) lives in Engine::session_artifact
            // so the disk tier (session_save) emits byte-identical artifacts.
            Ok(json!({
                "ok": true,
                "storage_state": engine.session_artifact(tab_id_of(&params)),
            }))
        }

        "close_tab" => {
            engine
                .tabs
                .lock().unwrap_or_else(|e| e.into_inner())
                .remove(tab_id_of(&params));
            Ok(json!({"ok": true}))
        }

        "network_log" => {
            // Session network observability (firing 32): every completed
            // document navigation (goto/fetch) and page-context fetch/XHR
            // hop, oldest first, capped at se_net::NET_LOG_CAP. `clear: true`
            // drains in one round trip — the response carries the entries
            // that were present, then empties the ring.
            let entries: Vec<Value> = engine
                .net_log
                .snapshot()
                .iter()
                .map(|e| {
                    json!({
                        "seq": e.seq,
                        "kind": e.kind,
                        "method": e.method,
                        "url": e.url,
                        "status": e.status,
                        "elapsed_ms": e.elapsed_ms,
                    })
                })
                .collect();
            let cleared = match params.get("clear") {
                Some(Value::Bool(b)) => *b,
                _ => param(&params, "clear").map(|v| v == "true").unwrap_or(false),
            };
            if cleared {
                engine.net_log.clear();
            }
            Ok(json!({"ok": true, "entries": entries, "cleared": cleared}))
        }

        "session_reset" => {
            engine.client.lock().unwrap_or_else(|e| e.into_inner()).store().clear();
            // The protocol pins this: session_reset clears the cookie jar
            // AND any per-origin storage — a fresh session must not inherit
            // a gated page's leftover state. The network log is session
            // observability, so it resets with the session.
            engine.net_log.clear();
            // The local pool is session state: reset with the jar. Taken
            // AFTER the tabs work below (tabs lock before pool lock).
            // The tabs themselves stay (parity with the patchright sidecar,
            // whose session_reset clears the context's cookies and the
            // page's storage but keeps every page open): a session reset
            // used to `tabs.clear()`, so a caller resetting for an
            // anonymous retry dropped every OTHER caller's loaded tab with
            // it -- their next read_html/eval answered "unknown tab"
            // (searchio bug 161). What each tab holds as session state is
            // wiped; its document, url and referrer are not.
            let tabs = engine.tabs.lock().unwrap_or_else(|e| e.into_inner());
            for tab in tabs.values() {
                tab.session_storage.clear();
                tab.window_name.clear();
                for archived_session in tab.session_archive.values() {
                    archived_session.clear();
                }
            }
            drop(tabs);
            engine
                .local_pool
                .lock().unwrap_or_else(|e| e.into_inner())
                .clear();
            Ok(json!({"ok": true, "cookies_cleared": true}))
        }

        "storage_state_set" => {
            // The FB provider sends the parsed storage-state JSON object;
            // older callers send a JSON-encoded string. Accept both.
            let Some(raw) = params.get("storage_state") else {
                return Ok(verb_error("storage_state_set: missing storage_state"));
            };
            let state = match raw {
                Value::String(s) => match serde_json::from_str::<Value>(s) {
                    Ok(v) => v,
                    Err(e) => {
                        return Ok(verb_error(format!(
                            "storage_state_set: storage_state is not JSON: {e}"
                        )))
                    }
                },
                Value::Object(_) => raw.clone(),
                _ => {
                    return Ok(verb_error(
                        "storage_state_set: storage_state must be an object or JSON string",
                    ))
                }
            };
            // The jar-insert + origin-restore consumer lives in
            // Engine::session_restore so the disk tier (session_load) restores
            // byte-identical artifacts.
            match engine.session_restore(&state, tab_id_of(&params)) {
                Ok(loaded) => {
                    // The provider reports `loaded:{cookies}c` from this count.
                    Ok(json!({"ok": true, "cookies": loaded}))
                }
                Err(e) => Ok(verb_error(format!("storage_state_set: {e}"))),
            }
        }

        "session_save" => {
            // The disk tier: persist the session artifact for this tab to a
            // JSON file, for sidecar restarts that resume where the last
            // session left off. The path comes from the param, or the
            // engine's configured default (--session-file) when absent.
            let path = param(&params, "path")
                .map(str::to_string)
                .or_else(|| {
                    engine
                        .session_file
                        .as_ref()
                        .map(|p| p.display().to_string())
                });
            let Some(path) = path else {
                return Ok(verb_error(
                    "session_save: no path (pass params.path or start se-serve with --session-file)",
                ));
            };
            match engine.session_save_file(std::path::Path::new(&path), tab_id_of(&params)) {
                Ok(v) => Ok(v),
                Err(e) => Ok(verb_error(format!("session_save: {e}"))),
            }
        }

        "session_load" => {
            // The disk tier's restore half: read a session artifact from disk
            // and load it into the live jar + the tab's origin maps. The
            // path resolution matches session_save.
            let path = param(&params, "path")
                .map(str::to_string)
                .or_else(|| {
                    engine
                        .session_file
                        .as_ref()
                        .map(|p| p.display().to_string())
                });
            let Some(path) = path else {
                return Ok(verb_error(
                    "session_load: no path (pass params.path or start se-serve with --session-file)",
                ));
            };
            match engine.session_load_file(std::path::Path::new(&path), tab_id_of(&params)) {
                Ok(loaded) => Ok(json!({
                    "ok": true,
                    "path": path,
                    "cookies": loaded,
                })),
                Err(e) => Ok(verb_error(format!("session_load: {e}"))),
            }
        }

        other => Err((-32601, format!("Unknown method: {other}"))),
    }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bot_detection_flags_signatures() {
        assert_eq!(detect_bot("<div id=\"px-captcha\"></div>"), Some("perimeterx_challenge"));
        assert_eq!(detect_bot("\"feed_units\":null"), Some("empty_feed_units"));
        assert!(detect_bot("<p>ordinary listings</p>").is_none());
    }

    #[test]
    fn real_facebook_page_is_not_flagged() {
        // The live capture names arkose_captcha in a resource loader and
        // mentions checkpoint URLs — a true positive here would abort every
        // good Marketplace retrieval. Pinned by the actual fixture.
        let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.push("../se-dom/tests/fixtures/fb_marketplace.html");
        let html = std::fs::read_to_string(p).expect("fixture");
        assert_eq!(detect_bot(&html), None);
    }

    #[test]
    fn unknown_method_is_rpc_error_not_panic() {
        // dispatch is async; exercise the match arm through a tiny runtime
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        let err = rt
            .block_on(dispatch(&engine, "screenshot", Value::Null))
            .unwrap_err();
        assert_eq!(err.0, -32601);
    }

    #[test]
    fn network_log_verb_reports_entries_in_order_and_clear_drains() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        engine.net_log.record(
            "document",
            "GET",
            "http://a.test/page",
            200,
            std::time::Duration::from_millis(12),
        );
        engine.net_log.record(
            "fetch",
            "GET",
            "http://a.test/api",
            404,
            std::time::Duration::from_millis(3),
        );
        let out = rt
            .block_on(dispatch(&engine, "network_log", json!({})))
            .unwrap();
        assert_eq!(out["ok"], true);
        let entries = out["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["kind"], "document");
        assert_eq!(entries[0]["url"], "http://a.test/page");
        assert_eq!(entries[0]["status"], 200);
        assert_eq!(entries[0]["elapsed_ms"], 12);
        assert_eq!(entries[1]["kind"], "fetch");
        assert!(
            entries[1]["seq"].as_u64().unwrap() > entries[0]["seq"].as_u64().unwrap()
        );
        // clear:true returns the drained entries, then the ring is empty.
        let drained = rt
            .block_on(dispatch(&engine, "network_log", json!({"clear": true})))
            .unwrap();
        assert_eq!(drained["entries"].as_array().unwrap().len(), 2);
        assert_eq!(drained["cleared"], true);
        let empty = rt
            .block_on(dispatch(&engine, "network_log", json!({})))
            .unwrap();
        assert!(empty["entries"].as_array().unwrap().is_empty());
    }

    #[test]
    fn session_reset_clears_the_network_log_with_the_session() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        engine.net_log.record(
            "document",
            "GET",
            "http://a.test/",
            200,
            std::time::Duration::from_millis(1),
        );
        let out = rt
            .block_on(dispatch(&engine, "session_reset", json!({})))
            .unwrap();
        assert_eq!(out["ok"], true);
        let log = rt
            .block_on(dispatch(&engine, "network_log", json!({})))
            .unwrap();
        assert!(
            log["entries"].as_array().unwrap().is_empty(),
            "session_reset resets session observability with the session"
        );
    }

    #[test]
    fn cross_origin_navigation_archives_and_restores_session_storage() {
        // The crawl A→B→A pattern for SESSION storage: the per-tab archive
        // carries it (sessionStorage's spec lifetime is the browsing
        // context). LOCAL storage no longer passes through here — it rides
        // the Engine's per-origin pool (`local_storage_pool_is_shared...`).
        let mut a = Tab::default_for_test();
        a.url = "http://a.test/".into();
        a.session_storage.set("sess".into(), "a".into());

        // A → B: A's session map archives; B starts fresh.
        let b = Tab::after_navigation(Some(&a), "http://b.test/x", String::new(), String::new());
        assert_eq!(b.session_storage.get("sess"), None);
        assert_eq!(b.url, "http://b.test/x");

        // B writes its own session mark.
        let b = b;
        b.session_storage.set("sess".into(), "b".into());

        // B → A: A's session map restores from the archive.
        let a2 = Tab::after_navigation(Some(&b), "http://a.test/back", String::new(), String::new());
        assert_eq!(a2.session_storage.get("sess").as_deref(), Some("a"));

        // A → B again: B's map restores too — the archive holds every
        // visited origin, not just the previous one.
        let b2 = Tab::after_navigation(Some(&a2), "http://b.test/again", String::new(), String::new());
        assert_eq!(b2.session_storage.get("sess").as_deref(), Some("b"));
    }

    #[test]
    fn session_reset_keeps_open_tabs_but_wipes_their_session_state() {
        // searchio bug 161: the reset dropped every tab, so a concurrent
        // caller's loaded page vanished under it. Patchright keeps pages
        // open across a reset; so does the engine now.
        let engine = Engine::default();
        let mut tab = Tab::default_for_test();
        tab.url = "http://a.test/page".into();
        tab.html = "<html><body><p>still here</p></body></html>".into();
        tab.session_storage.set("sess".into(), "a".into());
        tab.window_name.set("ctx".into());
        engine
            .tabs
            .lock().unwrap_or_else(|e| e.into_inner())
            .insert("other-caller".into(), tab);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let r = rt.block_on(dispatch(&engine, "session_reset", json!({}))).unwrap();
        assert_eq!(r["ok"], json!(true));
        let tabs = engine.tabs.lock().unwrap_or_else(|e| e.into_inner());
        let kept = tabs.get("other-caller").expect("the tab survives a session reset");
        assert_eq!(kept.url, "http://a.test/page");
        assert!(kept.html.contains("still here"), "the document is untouched");
        assert_eq!(kept.session_storage.get("sess"), None, "session storage is wiped");
        assert_eq!(kept.window_name.get(), "", "window.name is wiped");
    }

    #[test]
    fn local_storage_pool_is_shared_per_origin_across_tabs() {
        // Browser per-profile semantics (firing 36): every tab on an origin
        // reads and writes the SAME localStorage map — a write through one
        // tab's eval is visible to another tab's eval on that origin.
        let engine = Engine::default();
        let t1_handle = engine.local_storage_for("http://a.test");
        let t2_handle = engine.local_storage_for("http://a.test");
        let other_origin = engine.local_storage_for("http://b.test");
        t1_handle.set("mark".into(), "shared".into());
        assert_eq!(
            t2_handle.get("mark").as_deref(),
            Some("shared"),
            "second tab on the origin sees the first tab's write"
        );
        assert_eq!(
            other_origin.get("mark"),
            None,
            "a different origin gets its own map"
        );
        // And session_reset wipes the pool with the rest of the session.
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(dispatch(&engine, "session_reset", json!({}))).unwrap();
        let fresh = engine.local_storage_for("http://a.test");
        assert_eq!(fresh.get("mark"), None, "session_reset clears the pool");
    }

    #[test]
    fn same_origin_navigation_carries_session_storage_unchanged() {
        let mut t = Tab::default_for_test();
        t.url = "http://a.test/page1".into();
        t.session_storage.set("k".into(), "v".into());
        let t2 = Tab::after_navigation(
            Some(&t),
            "http://a.test/page2",
            "http://a.test/page1".into(),
            String::new(),
        );
        assert_eq!(t2.session_storage.get("k").as_deref(), Some("v"));
        assert_eq!(t2.referrer, "http://a.test/page1");
        // Nothing archived on a same-origin hop.
        assert!(t2.session_archive.is_empty());
    }

    #[test]
    fn fresh_tab_gets_fresh_session_storage_and_archives_nothing() {
        let t = Tab::after_navigation(None, "http://a.test/", String::new(), String::new());
        assert_eq!(t.session_storage.len(), 0);
        assert!(t.session_archive.is_empty());

        // A tab that was never navigated (empty url) archives no garbage.
        let empty = Tab::default_for_test();
        let t2 = Tab::after_navigation(Some(&empty), "http://a.test/", String::new(), String::new());
        assert!(t2.session_archive.is_empty());
    }

    #[test]
    fn eval_verb_runs_js_with_and_without_page() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();

        // No tab: about:blank semantics — navigator answers anyway.
        let r = rt
            .block_on(dispatch(
                &engine,
                "eval",
                json!({"tab_id": "default", "js": "1 + 1"}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(true));
        assert_eq!(r["result"], json!(2));

        let r = rt
            .block_on(dispatch(
                &engine,
                "eval",
                json!({"tab_id": "default", "js": "navigator.userAgent"}),
            ))
            .unwrap();
        assert!(r["result"].as_str().unwrap().contains("Chrome/145"));

        // With a tab: the DOM bridge serves `document`.
        engine.tabs.lock().unwrap_or_else(|e| e.into_inner()).insert(
            "default".to_string(),
            Tab {
                url: "https://example.test/".into(),
                html: "<a class='x'>one</a><a class='x'>two</a>".into(),
                ..Tab::default_for_test()
            },
        );
        let r = rt
            .block_on(dispatch(
                &engine,
                "eval",
                json!({"tab_id": "default", "js": "document.querySelectorAll('a.x').length"}),
            ))
            .unwrap();
        assert_eq!(r["result"], json!(2));
    }

    #[test]
    fn eval_mutation_persists_into_read_html_and_the_next_eval() {
        // Cross-eval DOM persistence at the wire level: an eval that mutates
        // the document adopts its writeback into the tab, so read_html and a
        // second eval both observe the mutation — patchright's live-DOM
        // behavior, where previously mutations died with the eval's State.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        engine.tabs.lock().unwrap_or_else(|e| e.into_inner()).insert(
            "default".to_string(),
            Tab {
                url: "https://example.test/".into(),
                html: "<html><body><p>one</p></body></html>".into(),
                ..Tab::default_for_test()
            },
        );

        let r = rt
            .block_on(dispatch(
                &engine,
                "eval",
                json!({
                    "tab_id": "default",
                    "js": "document.body.innerHTML = '<p>one</p><div id=\"added\">two</div>'; 'mutated'",
                }),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(true));

        // read_html sees the adopted document...
        let r = rt
            .block_on(dispatch(&engine, "read_html", json!({"tab_id": "default"})))
            .unwrap();
        let html = r["html"].as_str().unwrap();
        assert!(html.contains("added"), "read_html: {html}");

        // ...and a second eval queries the mutated tree.
        let r = rt
            .block_on(dispatch(
                &engine,
                "eval",
                json!({"tab_id": "default", "js": "document.querySelectorAll('#added').length"}),
            ))
            .unwrap();
        assert_eq!(r["result"], json!(1));

        // Read-only evals adopt nothing: a bare read leaves the document as
        // the mutation left it (the writeback slot was taken, not re-filled).
        let r = rt
            .block_on(dispatch(
                &engine,
                "eval",
                json!({"tab_id": "default", "js": "document.querySelectorAll('p').length"}),
            ))
            .unwrap();
        assert_eq!(r["result"], json!(1));
    }

    #[test]
    fn eval_writeback_adoption_drops_a_navigation_superseded_document() {
        // The writeback's `from` guard: a writeback whose `from` no longer
        // matches the tab's current document targets a page a navigation
        // replaced — the fresh navigation must win, never the stale mutation.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        let tab = Tab {
            url: "https://example.test/new".into(),
            html: "<html><body><p>new document</p></body></html>".into(),
            ..Tab::default_for_test()
        };
        // A stale writeback left pending across the navigation (what a racing
        // goto would leave behind).
        *tab.writeback.lock().unwrap_or_else(|e| e.into_inner()) = Some(se_js::bridge::MutationWriteback {
            from: "<html><body><p>old document</p></body></html>".into(),
            html: "<html><body><p>STALE</p></body></html>".into(),
        });
        engine
            .tabs
            .lock().unwrap_or_else(|e| e.into_inner())
            .insert("default".to_string(), tab);

        // Any eval triggers the adoption pass; the guard must drop the stale
        // writeback because the tab's document has moved on.
        let r = rt
            .block_on(dispatch(
                &engine,
                "eval",
                json!({"tab_id": "default", "js": "'noop'"}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(true));

        let r = rt
            .block_on(dispatch(&engine, "read_html", json!({"tab_id": "default"})))
            .unwrap();
        let html = r["html"].as_str().unwrap();
        assert!(
            html.contains("new document") && !html.contains("STALE"),
            "the fresh document survives: {html}"
        );
    }

    #[test]
    fn eval_set_attribute_persists_over_the_wire() {
        // The firing-22 trio at the dispatch level: setAttribute on a
        // resident element rides mutate() into the writeback, so read_html
        // and a SECOND eval (a fresh State over the adopted document) both
        // observe the attribute — and the createElement idiom grafts a
        // synthetic wrapper's attribute into the live tree in one eval.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        engine.tabs.lock().unwrap_or_else(|e| e.into_inner()).insert(
            "default".to_string(),
            Tab {
                url: "https://example.test/".into(),
                html: "<html><body><div id='a'><p>one</p></div></body></html>".into(),
                ..Tab::default_for_test()
            },
        );

        // Resident element: setAttribute, then read it back three ways.
        let r = rt
            .block_on(dispatch(
                &engine,
                "eval",
                json!({
                    "tab_id": "default",
                    "js": "var a = document.querySelector('#a'); a.setAttribute('data-x', '1'); a.getAttribute('data-x')",
                }),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(true));
        assert_eq!(r["result"], json!("1"));

        // read_html sees the adopted attribute...
        let r = rt
            .block_on(dispatch(&engine, "read_html", json!({"tab_id": "default"})))
            .unwrap();
        let html = r["html"].as_str().unwrap();
        assert!(
            html.contains("data-x=\"1\""),
            "read_html carries the set attribute: {html}"
        );

        // ...and a second eval's hasAttribute sees it cross-eval.
        let r = rt
            .block_on(dispatch(
                &engine,
                "eval",
                json!({"tab_id": "default", "js": "document.querySelector('#a').hasAttribute('data-x')"}),
            ))
            .unwrap();
        assert_eq!(r["result"], json!(true));

        // The createElement idiom: synthetic wrapper attrs ride the graft.
        let r = rt
            .block_on(dispatch(
                &engine,
                "eval",
                json!({
                    "tab_id": "default",
                    "js": "var d = document.createElement('div'); d.setAttribute('id', 'made'); d.textContent = 'two'; document.body.appendChild(d); document.querySelectorAll('#made').length",
                }),
            ))
            .unwrap();
        assert_eq!(r["result"], json!(1));
        let r = rt
            .block_on(dispatch(&engine, "read_html", json!({"tab_id": "default"})))
            .unwrap();
        assert!(
            r["html"].as_str().unwrap().contains("id=\"made\""),
            "the grafted synthetic attribute persists: {}",
            r["html"]
        );
    }

    #[test]
    fn fetch_verb_is_http_first_and_reports_ladder_contract() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        // Two requests: the 302 and the followed landing. `Connection:
        // close` forces separate connections, so accept both. Listener and
        // accept loop live on the server's own runtime.
        let body = "<div id=\"px-captcha\">challenge</div>".to_string();
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                addr_tx.send(listener.local_addr().unwrap()).unwrap();
                for _ in 0..2 {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let mut buf = vec![0u8; 8192];
                    let n = socket.read(&mut buf).await.unwrap();
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let (status, payload) = if path == "/start" {
                        (302u16, String::new())
                    } else {
                        (200u16, body.clone())
                    };
                    let reason = if status == 302 { "Found" } else { "OK" };
                    let mut head = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n",
                        payload.len()
                    );
                    if status == 302 {
                        head.push_str("Location: /landing\r\n");
                    }
                    socket
                        .write_all(format!("{head}\r\n{payload}").as_bytes())
                        .await
                        .unwrap();
                }
            });
        });
        let addr = addr_rx.recv().unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        let r = rt
            .block_on(dispatch(
                &engine,
                "fetch",
                json!({"url": format!("http://{addr}/start"), "tab_id": "f"}),
            ))
            .unwrap();

        assert_eq!(r["ok"], json!(true));
        assert_eq!(r["status"], json!(200));
        assert!(r["url"].as_str().unwrap().ends_with("/landing"));
        assert_eq!(r["via"], json!("http"));
        assert!(r["html"].as_str().unwrap().contains("px-captcha"));
        // Challenge signatures ride in the ok:true envelope — the ladder's
        // refusal check is signature-driven.
        assert_eq!(r["bot_wall"], json!(true));
        assert_eq!(r["bot_reason"], json!("perimeterx_challenge"));

        // fetch leaves a loaded tab: read_html and eval compose over it.
        let r = rt
            .block_on(dispatch(&engine, "read_html", json!({"tab_id": "f"})))
            .unwrap();
        assert!(r["html"].as_str().unwrap().contains("px-captcha"));
        let r = rt
            .block_on(dispatch(
                &engine,
                "eval",
                json!({"tab_id": "f", "js": "document.querySelectorAll('div').length"}),
            ))
            .unwrap();
        assert_eq!(r["result"], json!(1));

        handle.join().unwrap();
    }

    #[test]
    fn fetch_verb_reports_the_origins_content_type() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        // searchio bug 20: the document envelope carried no content-type, so
        // the ladder labeled every tier-2 body text/html and live PDFs sailed
        // through page classification. The origin's header must ride along.
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                addr_tx.send(listener.local_addr().unwrap()).unwrap();
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 8192];
                let _ = socket.read(&mut buf).await.unwrap();
                let payload = "%PDF-1.7\n1 0 obj<<>>endobj";
                socket
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                            payload.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            });
        });
        let addr = addr_rx.recv().unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        let r = rt
            .block_on(dispatch(
                &engine,
                "fetch",
                json!({"url": format!("http://{addr}/doc.pdf"), "tab_id": "p"}),
            ))
            .unwrap();

        assert_eq!(r["ok"], json!(true));
        assert_eq!(r["content_type"], json!("application/pdf"));
        assert!(r["html"].as_str().unwrap().starts_with("%PDF-"));

        handle.join().unwrap();
    }

    #[test]
    fn fetch_verb_missing_url_is_verb_error() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        let r = rt
            .block_on(dispatch(&engine, "fetch", json!({"url": ""})))
            .unwrap();
        assert_eq!(r["ok"], json!(false));
    }

    #[test]
    fn fetch_verb_with_method_headers_body_is_a_session_data_call() {
        // Firing 37: fetch with ANY of method/headers/body is a session-bound
        // DATA call — subresource-shaped block, jar rides AND lands, response
        // body in the envelope, and NO tab loaded (a POST response is not a
        // document). Wrong-typed params are verb errors (hostile tier).
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                addr_tx.send(listener.local_addr().unwrap()).unwrap();
                for _ in 0..1 {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let mut buf = vec![0u8; 8192];
                    let n = socket.read(&mut buf).await.unwrap();
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let find = |name: &str| -> String {
                        req.lines()
                            .find(|l| l.to_ascii_lowercase().starts_with(&format!("{name}:")))
                            .unwrap_or("")
                            .to_string()
                    };
                    let method = req
                        .lines()
                        .next()
                        .unwrap_or("")
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                        .to_string();
                    let req_body = req.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
                    let payload = format!(
                        "method={method}|ct={}|xc={}|cookie={}|body={req_body}",
                        find("content-type"),
                        find("x-custom"),
                        find("cookie"),
                    );
                    socket
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nSet-Cookie: data_sess=1; Path=/\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                                payload.len()
                            )
                            .as_bytes(),
                        )
                        .await
                        .unwrap();
                }
            });
        });
        let addr = addr_rx.recv().unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        // Seed the jar so the data call's Cookie header is provable.
        engine
            .client
            .lock().unwrap_or_else(|e| e.into_inner())
            .store()
            .store_set_cookie("seeded=1; Path=/", &format!("http://{addr}/"));

        let r = rt
            .block_on(dispatch(
                &engine,
                "fetch",
                json!({
                    "url": format!("http://{addr}/echo"),
                    "tab_id": "d",
                    "method": "POST",
                    "headers": {"Content-Type": "application/json", "X-Custom": "abc"},
                    "body": r#"{"k":1}"#,
                }),
            ))
            .unwrap();

        assert_eq!(r["ok"], json!(true));
        assert_eq!(r["status"], json!(200));
        assert_eq!(r["via"], json!("http"));
        // The DATA envelope: `body`, not `html`, and response headers ride.
        assert!(r.get("html").is_none(), "no document key on a data call: {r}");
        let b = r["body"].as_str().unwrap();
        assert!(b.contains("method=POST"), "{b}");
        assert!(b.contains("ct=content-type: application/json"), "{b}");
        assert!(b.contains("xc=x-custom: abc"), "{b}");
        assert!(b.contains("cookie=cookie: seeded=1"), "{b}");
        assert!(b.contains("body={\"k\":1}"), "{b}");
        assert_eq!(r["headers"]["content-type"], json!("text/plain"));

        // The response Set-Cookie LANDED in the session jar.
        let jar = engine
            .client
            .lock().unwrap_or_else(|e| e.into_inner())
            .store()
            .snapshot();
        assert!(
            jar.iter().any(|c| c.name == "data_sess"),
            "response cookie landed: {jar:?}"
        );

        // NO tab was loaded: read_html on the data call's tab id is the
        // missing-tab verb error, and net_log holds ONE fetch-kind entry
        // (not a document one).
        let r = rt
            .block_on(dispatch(&engine, "read_html", json!({"tab_id": "d"})))
            .unwrap();
        assert_eq!(r["ok"], json!(false));
        assert!(r["error"].as_str().unwrap().contains("no tab"), "{r}");
        let log = rt.block_on(dispatch(&engine, "network_log", json!({}))).unwrap();
        let entries = log["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0]["kind"], json!("fetch"));
        assert_eq!(entries[0]["method"], json!("POST"));

        // Wrong-typed params refuse at the verb layer (hostile-input tier).
        for bad in [
            json!({"url": format!("http://{addr}/"), "method": 7}),
            json!({"url": format!("http://{addr}/"), "headers": "x-custom: abc"}),
            json!({"url": format!("http://{addr}/"), "headers": {"X": 7}}),
            json!({"url": format!("http://{addr}/"), "body": 7}),
        ] {
            let r = rt.block_on(dispatch(&engine, "fetch", bad)).unwrap();
            assert_eq!(r["ok"], json!(false), "{r}");
        }

        handle.join().unwrap();
    }

    #[test]
    fn read_text_verb_extracts_the_rendered_text_floor() {
        // The protocol's text verb: body by default, first match under a
        // selector, structural innerText floor (blocks → newlines,
        // script/style skipped, whitespace collapsed), unknown tab and bad
        // selector are verb errors like read_html's.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        engine.tabs.lock().unwrap_or_else(|e| e.into_inner()).insert(
            "t".to_string(),
            Tab {
                url: "http://x.test/page".into(),
                html: r#"<html><head><style>body { margin: 0 }</style></head>
                    <body><script>var hidden = 1;</script>
                    <div><p>hello  world</p><ul><li>one</li><li>two</li></ul></div>
                    </body></html>"#
                    .into(),
                ..Tab::default_for_test()
            },
        );

        // Body default: script/style gone, blocks newline-joined.
        let r = rt
            .block_on(dispatch(&engine, "read_text", json!({"tab_id": "t"})))
            .unwrap();
        assert_eq!(r["ok"], json!(true));
        assert_eq!(r["url"], json!("http://x.test/page"));
        assert_eq!(r["text"], json!("hello world\none\ntwo"));

        // Selector scope: first match only.
        let r = rt
            .block_on(dispatch(
                &engine,
                "read_text",
                json!({"tab_id": "t", "selector": "ul"}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(true));
        assert_eq!(r["text"], json!("one\ntwo"));

        // No-match selector yields empty text, not an error (read_html's
        // collect-over-empty contract).
        let r = rt
            .block_on(dispatch(
                &engine,
                "read_text",
                json!({"tab_id": "t", "selector": "section.nope"}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(true));
        assert_eq!(r["text"], json!(""));

        // Unknown tab and bad selector are verb errors, not panics.
        let r = rt
            .block_on(dispatch(&engine, "read_text", json!({"tab_id": "nope"})))
            .unwrap();
        assert_eq!(r["ok"], json!(false));
        let r = rt
            .block_on(dispatch(
                &engine,
                "read_text",
                json!({"tab_id": "t", "selector": "ul["}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(false));
    }

    #[test]
    fn read_snapshot_verb_lists_visible_elements_with_roles_and_scoping() {
        // Firing 38: the agent's structural eyes. Visible-only flat dump in
        // document order with computed roles + interactivity; hidden subtrees
        // pruned; selector scopes to the first match's subtree; missing tab /
        // bad selector are verb errors like read_html's.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        engine.tabs.lock().unwrap_or_else(|e| e.into_inner()).insert(
            "s".to_string(),
            Tab {
                url: "http://x.test/page".into(),
                html: r#"<html><body>
                    <nav><a href="/a">Alpha</a><a href="/b">Beta</a></nav>
                    <p hidden>ghost</p>
                    <main><h1>Title</h1>
                    <form action="/go"><input type="text" name="q"><input type="hidden" name="t"></form>
                    </main></body></html>"#
                    .into(),
                ..Tab::default_for_test()
            },
        );

        let r = rt
            .block_on(dispatch(&engine, "read_snapshot", json!({"tab_id": "s"})))
            .unwrap();
        assert_eq!(r["ok"], json!(true));
        assert_eq!(r["url"], json!("http://x.test/page"));
        let snap = r["snapshot"].as_array().unwrap();
        let kinds: Vec<&str> = snap.iter().map(|e| e["kind"].as_str().unwrap()).collect();
        // nav, two links, main, heading, form, text box — the hidden <p> and
        // the type=hidden input are pruned entirely.
        assert_eq!(
            kinds,
            vec!["nav", "a", "a", "main", "h1", "form", "input"],
            "{snap:?}"
        );
        assert_eq!(snap[0]["role"], json!("navigation"));
        assert_eq!(snap[1]["role"], json!("link"));
        assert_eq!(snap[1]["text"], json!("Alpha"));
        assert_eq!(snap[1]["href"], json!("/a"));
        assert_eq!(snap[1]["interactive"], json!(true));
        assert_eq!(snap[4]["role"], json!("heading"));
        // The form is a landmark, not interactive; the text box is.
        assert_eq!(snap[5]["role"], json!("form"));
        assert_eq!(snap[5]["interactive"], json!(false));
        assert_eq!(snap[6]["control_type"], json!("text"));
        assert_eq!(snap[6]["name"], json!("q"));
        assert_eq!(snap[6]["interactive"], json!(true));
        // No identity attr on the nav → the optional key is absent.
        assert!(snap[0].get("id").is_none(), "{snap:?}");

        // Selector scope: first match's subtree, depth 0 at the scope root.
        let r = rt
            .block_on(dispatch(
                &engine,
                "read_snapshot",
                json!({"tab_id": "s", "selector": "main"}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(true));
        let scoped = r["snapshot"].as_array().unwrap();
        let kinds: Vec<&str> = scoped.iter().map(|e| e["kind"].as_str().unwrap()).collect();
        assert_eq!(kinds, vec!["main", "h1", "form", "input"], "{scoped:?}");
        assert_eq!(scoped[0]["depth"], json!(0));

        // Missing tab and bad selector are verb errors.
        let r = rt
            .block_on(dispatch(&engine, "read_snapshot", json!({"tab_id": "nope"})))
            .unwrap();
        assert_eq!(r["ok"], json!(false));
        let r = rt
            .block_on(dispatch(
                &engine,
                "read_snapshot",
                json!({"tab_id": "s", "selector": "main["}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(false));
    }

    #[test]
    fn read_image_verb_fetches_session_bytes_and_decodes_data_urls() {
        // Firing 38: the capture half. A relative <img src> resolves against
        // the tab URL and fetches THROUGH THE SESSION — the seeded jar cookie
        // rides the image request (proved by what the one-shot server saw) —
        // and the envelope carries container-parsed dims + base64 bytes. A
        // data: URL decodes in place with no fetch at all.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        // Hand-built 2x3 PNG: signature + IHDR (the sniffer reads BE dims at
        // 16/20) + bare IEND tail.
        let png = {
            let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
            v.extend_from_slice(&[0, 0, 0, 13, b'I', b'H', b'D', b'R']);
            v.extend_from_slice(&2u32.to_be_bytes());
            v.extend_from_slice(&3u32.to_be_bytes());
            v.extend_from_slice(&[8, 2, 0, 0, 0]);
            v.extend_from_slice(&[0, 0, 0, 0, b'I', b'E', b'N', b'D']);
            v
        };

        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let (cookie_tx, cookie_rx) = std::sync::mpsc::channel();
        let server_png = png.clone();
        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                addr_tx.send(listener.local_addr().unwrap()).unwrap();
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 8192];
                let n = socket.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                cookie_tx
                    .send(
                        req.lines()
                            .find(|l| l.to_ascii_lowercase().starts_with("cookie:"))
                            .unwrap_or("")
                            .to_string(),
                    )
                    .unwrap();
                socket
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            server_png.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                socket.write_all(&server_png).await.unwrap();
            });
        });
        let addr = addr_rx.recv().unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        engine
            .client
            .lock().unwrap_or_else(|e| e.into_inner())
            .store()
            .store_set_cookie("seeded=1; Path=/", &format!("http://{addr}/"));
        engine.tabs.lock().unwrap_or_else(|e| e.into_inner()).insert(
            "i".to_string(),
            Tab {
                url: format!("http://{addr}/gallery"),
                html: r#"<html><body><img src="/pixel.png" alt="dot"></body></html>"#.into(),
                ..Tab::default_for_test()
            },
        );

        let r = rt
            .block_on(dispatch(&engine, "read_image", json!({"tab_id": "i"})))
            .unwrap();
        assert_eq!(r["ok"], json!(true));
        assert_eq!(r["alt"], json!("dot"));
        assert_eq!(r["content_type"], json!("image/png"));
        assert_eq!(r["format"], json!("png"));
        assert_eq!(r["width"], json!(2));
        assert_eq!(r["height"], json!(3));
        assert_eq!(r["byte_length"], json!(png.len()));
        assert_eq!(r["src"], json!(format!("http://{addr}/pixel.png")));
        let decoded = imgmeta::base64_decode(r["bytes_base64"].as_str().unwrap()).unwrap();
        assert_eq!(decoded, png, "bytes round-trip the wire envelope");
        assert!(decoded.starts_with(b"\x89PNG\r\n\x1a\n"));

        // The image request rode the SESSION: the server saw the seeded jar
        // cookie, proving jar transport (not a fresh anonymous fetch).
        handle.join().unwrap();
        let seen = cookie_rx.recv().unwrap();
        assert!(seen.contains("seeded=1"), "server saw: {seen:?}");

        // Relative src resolved against the TAB's url (gallery → /pixel.png).
        // The net_log holds ONE document entry for the goto-less tab: the
        // image fetch itself is the request_data image kind.
        let log = rt.block_on(dispatch(&engine, "network_log", json!({}))).unwrap();
        let entries = log["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0]["kind"], json!("fetch"));
        assert_eq!(entries[0]["method"], json!("GET"));

        // data: URL decodes in place — no server, no fetch.
        let gif = {
            let mut v = b"GIF89a".to_vec();
            v.extend_from_slice(&[4, 0, 6, 0]); // 4x6 LE logical screen
            v.extend_from_slice(&[0, 0, 0]);
            v
        };
        let data_url = format!("data:image/gif;base64,{}", imgmeta::base64_encode(&gif));
        engine.tabs.lock().unwrap_or_else(|e| e.into_inner()).insert(
            "d".to_string(),
            Tab {
                url: "http://x.test/inline".into(),
                html: format!(
                    r#"<html><body>
                    <div id="bg" style="background-image: url('{data_url}')">bg</div>
                    <img src="{data_url}" alt="inline dot"></body></html>"#
                )
                .into(),
                ..Tab::default_for_test()
            },
        );
        let r = rt
            .block_on(dispatch(&engine, "read_image", json!({"tab_id": "d"})))
            .unwrap();
        assert_eq!(r["ok"], json!(true));
        assert_eq!(r["format"], json!("gif"));
        assert_eq!(r["width"], json!(4));
        assert_eq!(r["height"], json!(6));
        assert_eq!(r["alt"], json!("inline dot"));
        assert_eq!(r["src"], json!(data_url));
        assert_eq!(
            imgmeta::base64_decode(r["bytes_base64"].as_str().unwrap()).unwrap(),
            gif
        );

        // The inline-style url() fallback: a <div> carrying its imagery in
        // CSS extracts the quoted url() (opening quote skipped, close at the
        // matching quote) and decodes the data: URL in place.
        let r = rt
            .block_on(dispatch(
                &engine,
                "read_image",
                json!({"tab_id": "d", "selector": "#bg"}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(true), "{r}");
        assert_eq!(r["format"], json!("gif"), "{r}");
        assert_eq!(r["width"], json!(4));
        assert_eq!(r["height"], json!(6));
        assert_eq!(r["src"], json!(data_url));

        // Error floor: missing tab, no match, no image source, corrupt base64.
        let r = rt
            .block_on(dispatch(&engine, "read_image", json!({"tab_id": "nope"})))
            .unwrap();
        assert_eq!(r["ok"], json!(false));
        let r = rt
            .block_on(dispatch(
                &engine,
                "read_image",
                json!({"tab_id": "i", "selector": "#absent"}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(false));
        engine.tabs.lock().unwrap_or_else(|e| e.into_inner()).insert(
            "bare".to_string(),
            Tab {
                url: "http://x.test/bare".into(),
                html: "<html><body><div id=\"x\">no imagery here</div></body></html>".into(),
                ..Tab::default_for_test()
            },
        );
        let r = rt
            .block_on(dispatch(
                &engine,
                "read_image",
                json!({"tab_id": "bare", "selector": "#x"}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(false));
        // Corrupt base64 in a data: URL is a verb error, not a panic.
        engine.tabs.lock().unwrap_or_else(|e| e.into_inner()).insert(
            "corrupt".to_string(),
            Tab {
                url: "http://x.test/corrupt".into(),
                html: "<html><body><img src=\"data:image/gif;base64,***\"></body></html>".into(),
                ..Tab::default_for_test()
            },
        );
        let r = rt
            .block_on(dispatch(&engine, "read_image", json!({"tab_id": "corrupt"})))
            .unwrap();
        assert_eq!(r["ok"], json!(false));
        assert!(r["error"].as_str().unwrap().contains("base64"), "{r}");
    }

    #[test]
    fn ws_verbs_own_the_socket_and_present_the_session() {
        // Firing 39: the agent's WebSocket tier. An independent raw-TCP echo
        // server (second implementation = wire truth, the h2cap philosophy)
        // answers the opening handshake with the RFC 6455 accept and echoes
        // frames. The test proves, server-side: the SESSION jar cookie rode
        // the upgrade; the client masked every frame; text/binary round-trip;
        // timeout is a normal long-poll outcome; close handshakes cleanly;
        // the hostile battery errors instead of panicking.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let (cookie_tx, cookie_rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                addr_tx.send(listener.local_addr().unwrap()).unwrap();
                let (mut socket, _) = listener.accept().await.unwrap();

                // --- Opening handshake: read headers until the blank line. ---
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.ends_with(b"\r\n\r\n") {
                    let n = socket.read(&mut chunk).await.unwrap();
                    assert!(n > 0, "eof mid-handshake");
                    buf.extend_from_slice(&chunk[..n]);
                }
                let head = String::from_utf8_lossy(&buf).to_string();
                let hdr = |name: &str| -> String {
                    head.lines()
                        .find(|l| {
                            l.split_once(':')
                                .map(|(k, _)| k.trim().eq_ignore_ascii_case(name))
                                .unwrap_or(false)
                        })
                        .and_then(|l| l.split_once(':').map(|(_, v)| v.trim().to_string()))
                        .unwrap_or_default()
                };
                cookie_tx.send(hdr("cookie")).unwrap();
                assert!(hdr("upgrade").eq_ignore_ascii_case("websocket"), "Upgrade header: {head}");
                let key = hdr("sec-websocket-key");
                assert!(!key.is_empty(), "no key in {head}");
                // The engine must present its session UA on the upgrade too.
                assert!(hdr("user-agent").contains("Chrome"), "UA: {head}");
                socket
                    .write_all(
                        format!(
                            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\nX-Echo: yes\r\n\r\n",
                            se_net::ws::accept_key(&key)
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();

                // --- Frame loop: unmask, echo, answer pings, echo close. ---
                loop {
                    let mut hb = [0u8; 2];
                    if socket.read_exact(&mut hb).await.is_err() {
                        return; // client vanished
                    }
                    let fin = hb[0] & 0x80 != 0;
                    let op = hb[0] & 0x0F;
                    assert!(fin, "test server didn't script fragmentation");
                    let masked = hb[1] & 0x80 != 0;
                    assert!(masked, "client frames must be masked (RFC 6455 §5.3)");
                    let len = (hb[1] & 0x7F) as usize;
                    assert!(len < 126, "test server only scripts short frames");
                    let mut mask = [0u8; 4];
                    socket.read_exact(&mut mask).await.unwrap();
                    let mut payload = vec![0u8; len];
                    socket.read_exact(&mut payload).await.unwrap();
                    for (i, b) in payload.iter_mut().enumerate() {
                        *b ^= mask[i % 4];
                    }
                    match op {
                        0x8 => {
                            // Echo the close payload (code+reason), then done.
                            let mut out = vec![0x88, payload.len() as u8];
                            out.extend_from_slice(&payload);
                            socket.write_all(&out).await.unwrap();
                            return;
                        }
                        0x9 => {
                            let mut out = vec![0x8A, payload.len() as u8];
                            out.extend_from_slice(&payload);
                            socket.write_all(&out).await.unwrap();
                        }
                        0x1 | 0x2 => {
                            let mut out = vec![0x80 | op, payload.len() as u8];
                            out.extend_from_slice(&payload);
                            socket.write_all(&out).await.unwrap();
                        }
                        other => panic!("unexpected opcode {other}"),
                    }
                }
            });
        });
        let addr = addr_rx.recv().unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        // Seed the jar the way a logged-in session would look: the handshake
        // must present this cookie, proving the upgrade rides the session.
        engine
            .client
            .lock().unwrap_or_else(|e| e.into_inner())
            .store()
            .store_set_cookie("seeded=1; Path=/", &format!("http://{addr}/"));

        let r = rt
            .block_on(dispatch(
                &engine,
                "ws_connect",
                json!({"url": format!("ws://{addr}/feed"), "headers": {"X-Auth": "tok"}}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(true), "{r}");
        assert_eq!(r["ws_id"], json!("ws-1"));
        assert_eq!(r["status"], json!(101));
        assert_eq!(r["response_headers"]["x-echo"], json!("yes"));
        // The server saw the seeded jar cookie on the upgrade — session ride.
        assert!(cookie_rx.recv().unwrap().contains("seeded=1"));

        // Text round-trip.
        let r = rt
            .block_on(dispatch(
                &engine,
                "ws_send",
                json!({"ws_id": "ws-1", "data": "hello"}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(true), "{r}");
        assert_eq!(r["sent_bytes"], json!(5));
        let r = rt
            .block_on(dispatch(&engine, "ws_recv", json!({"ws_id": "ws-1", "timeout_ms": 3000})))
            .unwrap();
        assert_eq!(r["kind"], json!("text"), "{r}");
        assert_eq!(r["data"], json!("hello"));

        // Binary round-trip via data_base64.
        let raw = vec![0u8, 1, 2, 255];
        let r = rt
            .block_on(dispatch(
                &engine,
                "ws_send",
                json!({"ws_id": "ws-1", "data_base64": imgmeta::base64_encode(&raw)}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(true), "{r}");
        let r = rt
            .block_on(dispatch(&engine, "ws_recv", json!({"ws_id": "ws-1", "timeout_ms": 3000})))
            .unwrap();
        assert_eq!(r["kind"], json!("binary"), "{r}");
        assert_eq!(imgmeta::base64_decode(r["data_base64"].as_str().unwrap()).unwrap(), raw);

        // Long-poll timeout is a normal outcome, not an error.
        let r = rt
            .block_on(dispatch(&engine, "ws_recv", json!({"ws_id": "ws-1", "timeout_ms": 80})))
            .unwrap();
        assert_eq!(r["ok"], json!(true), "{r}");
        assert_eq!(r["kind"], json!("timeout"));

        // Hostile battery: every misuse is a verb error, never a panic.
        for params in [
            json!({"ws_id": "nope", "data": "x"}),
            json!({"ws_id": "ws-1", "data": 7}),
            json!({"ws_id": "ws-1"}),
            json!({"ws_id": "ws-1", "data": "x", "data_base64": "eA=="}),
            json!({"ws_id": "ws-1", "data_base64": "***"}),
        ] {
            let r = rt.block_on(dispatch(&engine, "ws_send", params)).unwrap();
            assert_eq!(r["ok"], json!(false), "{r}");
        }
        let r = rt
            .block_on(dispatch(&engine, "ws_recv", json!({"ws_id": "nope"})))
            .unwrap();
        assert_eq!(r["ok"], json!(false));
        let r = rt
            .block_on(dispatch(&engine, "ws_close", json!({"ws_id": "nope"})))
            .unwrap();
        assert_eq!(r["ok"], json!(false));
        assert!(r["error"].as_str().unwrap().contains("no ws connection"), "{r}");

        // Clean close; the conn leaves the pool for good.
        let r = rt
            .block_on(dispatch(&engine, "ws_close", json!({"ws_id": "ws-1"})))
            .unwrap();
        assert_eq!(r["ok"], json!(true), "{r}");
        assert_eq!(r["closed"], json!(true));
        let r = rt
            .block_on(dispatch(
                &engine,
                "ws_send",
                json!({"ws_id": "ws-1", "data": "gone"}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(false));
        assert!(r["error"].as_str().unwrap().contains("no ws connection"), "{r}");

        // A bad URL never reaches the wire.
        let r = rt
            .block_on(dispatch(&engine, "ws_connect", json!({"url": "http://x.test/"})))
            .unwrap();
        assert_eq!(r["ok"], json!(false));
        assert!(r["error"].as_str().unwrap().contains("ws://"), "{r}");

        handle.join().unwrap();
    }

    #[test]
    fn storage_state_set_accepts_object_or_string_and_loads_live_jar() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        // Playwright shape: the FB provider sends the parsed object, not a
        // JSON string.
        let state = json!({
            "cookies": [{
                "name": "c_user",
                "value": "61593717497664",
                "domain": ".facebook.com",
                "path": "/",
                "expires": 1893456000,
                "httpOnly": false,
                "secure": true,
            }],
            "origins": [],
        });

        // Object form (the provider's shape).
        let r = rt
            .block_on(dispatch(
                &engine,
                "storage_state_set",
                json!({"storage_state": state}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(true));
        assert_eq!(r["cookies"], json!(1)); // provider renders loaded:{n}c

        // cookies_get reports the live jar in Playwright shape.
        let r = rt.block_on(dispatch(&engine, "cookies_get", Value::Null)).unwrap();
        let cookies = r["cookies"].as_array().unwrap();
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0]["name"], json!("c_user"));
        assert_eq!(cookies[0]["domain"], json!(".facebook.com"));
        assert_eq!(cookies[0]["secure"], json!(true));
        assert_eq!(cookies[0]["expires"], json!(1893456000));

        // String form (the older caller shape) still lands.
        let r = rt
            .block_on(dispatch(
                &engine,
                "storage_state_set",
                json!({"storage_state": serde_json::to_string(&json!({
                    "cookies": [{
                        "name": "xs",
                        "value": "1:2:3",
                        "domain": ".facebook.com",
                        "path": "/",
                    }],
                    "origins": [],
                })).unwrap()}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(true));
        assert_eq!(r["cookies"], json!(1));
        let r = rt.block_on(dispatch(&engine, "cookies_get", Value::Null)).unwrap();
        assert_eq!(r["cookies"].as_array().unwrap().len(), 2);

        // Garbage in, verb error out — not a panic, not ok:true.
        let r = rt
            .block_on(dispatch(
                &engine,
                "storage_state_set",
                json!({"storage_state": "not json"}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(false));

        // session_reset wipes the live jar.
        let r = rt.block_on(dispatch(&engine, "session_reset", Value::Null)).unwrap();
        assert_eq!(r["ok"], json!(true));
        let r = rt.block_on(dispatch(&engine, "cookies_get", Value::Null)).unwrap();
        assert_eq!(r["cookies"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn restored_session_storage_is_visible_to_a_fresh_tabs_eval() {
        // The reopened-session flow under the pool design: storage_state_set
        // writes the artifact's origins into the session-global pool; once
        // the fresh tab lands on one of those origins, its evals read the
        // restored localStorage straight from the pool. The firing-29 bug
        // (first goto never consulting the archive) is structurally
        // impossible now — the pool IS keyed by origin, there is nothing to
        // consult beyond the lookup.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        let r = rt
            .block_on(dispatch(
                &engine,
                "storage_state_set",
                json!({"storage_state": {"cookies": [], "origins": [
                    {"origin": "http://a.test", "localStorage": [{"name": "mark", "value": "A"}]},
                ]}}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(true));
        // The post-goto state: the fresh tab has landed on origin A.
        engine.tabs.lock().unwrap_or_else(|e| e.into_inner()).insert(
            "fresh".to_string(),
            Tab {
                url: "http://a.test/back".into(),
                ..Tab::default_for_test()
            },
        );
        let r = rt
            .block_on(dispatch(
                &engine,
                "eval",
                json!({"tab_id": "fresh", "js": "localStorage.getItem('mark')"}),
            ))
            .unwrap();
        assert_eq!(r["result"], json!("A"));
    }

    #[test]
    fn storage_state_get_exports_jar_and_the_whole_local_pool() {
        // The producer half of storage_state_set: cookies from the live jar,
        // localStorage from the WHOLE session pool (Playwright's artifact is
        // per-context, and the pool IS the context); sessionStorage never
        // leaves its tab.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        let r = rt
            .block_on(dispatch(
                &engine,
                "storage_state_set",
                json!({"storage_state": {"cookies": [
                    {"name": "c_user", "value": "6159", "domain": ".facebook.com",
                     "path": "/", "secure": true, "expires": 1893456000,
                     "sameSite": "Strict"},
                    {"name": "sb", "value": "xy", "domain": ".facebook.com", "path": "/"},
                    // Bare domain (no dot) → host-only on import, bare on
                    // export — CDP's shape round-trips through the artifact.
                    {"name": "fr", "value": "1", "domain": "auth.facebook.com",
                     "path": "/"},
                ], "origins": []}}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(true));

        // Origin A restored earlier in the session; origin B written by some
        // tab's eval. A per-tab sessionStorage write must NOT leak into the
        // artifact.
        engine
            .local_storage_for("http://a.test")
            .set("amark".into(), "A".into());
        engine
            .local_storage_for("http://b.test")
            .set("bmark".into(), "B".into());
        let tab = Tab {
            url: "http://b.test/page".into(),
            ..Tab::default_for_test()
        };
        tab.session_storage.set("bsess".into(), "secret".into());
        engine
            .tabs
            .lock().unwrap_or_else(|e| e.into_inner())
            .insert("default".to_string(), tab);

        let r = rt
            .block_on(dispatch(
                &engine,
                "storage_state_get",
                json!({"tab_id": "default"}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(true));
        let state = &r["storage_state"];

        // Cookies: full Playwright shape; an absent SameSite attribute
        // reports "Lax" (Chromium Lax-by-default — what Playwright shows).
        // Domain-scoped cookies carry CDP's leading dot; host-only ones
        // export bare.
        let cookies = state["cookies"].as_array().unwrap();
        assert_eq!(cookies.len(), 3);
        let c_user = cookies
            .iter()
            .find(|c| c["name"] == json!("c_user"))
            .unwrap();
        assert_eq!(c_user["domain"], json!(".facebook.com"));
        assert_eq!(c_user["sameSite"], json!("Strict"));
        assert_eq!(c_user["secure"], json!(true));
        assert_eq!(c_user["expires"], json!(1893456000));
        let sb = cookies.iter().find(|c| c["name"] == json!("sb")).unwrap();
        assert_eq!(sb["sameSite"], json!("Lax"));
        let fr = cookies.iter().find(|c| c["name"] == json!("fr")).unwrap();
        assert_eq!(fr["domain"], json!("auth.facebook.com"));

        // Origins: current + archived, sorted by origin string, localStorage
        // only, sorted by name.
        let origins = state["origins"].as_array().unwrap();
        assert_eq!(origins.len(), 2);
        assert_eq!(origins[0]["origin"], json!("http://a.test"));
        assert_eq!(
            origins[0]["localStorage"],
            json!([{"name": "amark", "value": "A"}])
        );
        assert_eq!(origins[1]["origin"], json!("http://b.test"));
        assert_eq!(
            origins[1]["localStorage"],
            json!([{"name": "bmark", "value": "B"}])
        );
        let dumped = serde_json::to_string(&r).unwrap();
        assert!(
            !dumped.contains("secret"),
            "sessionStorage never leaves the tab: {dumped}"
        );
    }

    #[test]
    fn storage_state_get_on_a_fresh_session_is_an_empty_artifact() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        let r = rt
            .block_on(dispatch(&engine, "storage_state_get", Value::Null))
            .unwrap();
        assert_eq!(r["ok"], json!(true));
        assert_eq!(r["storage_state"]["cookies"], json!([]));
        assert_eq!(r["storage_state"]["origins"], json!([]));
    }

    #[test]
    fn exported_storage_state_round_trips_through_set() {
        // The artifact storage_state_get produces must be exactly what
        // storage_state_set accepts: export from one engine, inject into a
        // fresh one, export again — same cookies, same origins.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine_a = Engine::default();
        rt.block_on(dispatch(
            &engine_a,
            "storage_state_set",
            json!({"storage_state": {"cookies": [
                {"name": "c_user", "value": "6159", "domain": ".facebook.com",
                 "path": "/", "sameSite": "None", "secure": true},
                {"name": "fr", "value": "1", "domain": "auth.facebook.com",
                 "path": "/"},
            ], "origins": []}}),
        ))
        .unwrap();
        let tab = Tab {
            url: "http://b.test/".into(),
            ..Tab::default_for_test()
        };
        engine_a
            .local_storage_for("http://b.test")
            .set("mark".into(), "1".into());
        engine_a
            .tabs
            .lock().unwrap_or_else(|e| e.into_inner())
            .insert("default".to_string(), tab);
        let exported = rt
            .block_on(dispatch(&engine_a, "storage_state_get", Value::Null))
            .unwrap();
        let state = exported["storage_state"].clone();

        let engine_b = Engine::default();
        let r = rt
            .block_on(dispatch(
                &engine_b,
                "storage_state_set",
                json!({"storage_state": state}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(true));
        assert_eq!(r["cookies"], json!(2));
        let again = rt
            .block_on(dispatch(&engine_b, "storage_state_get", Value::Null))
            .unwrap();
        let cookies = again["storage_state"]["cookies"].as_array().unwrap();
        assert_eq!(cookies.len(), 2);
        let c_user = cookies
            .iter()
            .find(|c| c["name"] == json!("c_user"))
            .unwrap();
        assert_eq!(c_user["domain"], json!(".facebook.com"));
        assert_eq!(c_user["sameSite"], json!("None"));
        assert_eq!(c_user["secure"], json!(true));
        // The host-only cookie came back host-scoped — not widened to a
        // Domain attribute by the round trip.
        let fr = cookies.iter().find(|c| c["name"] == json!("fr")).unwrap();
        assert_eq!(fr["domain"], json!("auth.facebook.com"));
        // set filed b.test's localStorage into the fresh engine's archive.
        let origins = again["storage_state"]["origins"].as_array().unwrap();
        assert_eq!(origins.len(), 1);
        assert_eq!(origins[0]["origin"], json!("http://b.test"));
        assert_eq!(
            origins[0]["localStorage"],
            json!([{"name": "mark", "value": "1"}])
        );
    }

    #[test]
    fn eval_reads_youtube_initial_data_over_the_dom_bridge() {
        // The second engine fixture workload end to end through dispatch:
        // the page's own ytInitialData, read by page-facing JS over the
        // DOM bridge (script textContent scan), not by the Rust scanner.
        let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.push("../se-dom/tests/fixtures/yt_results.html");
        let html = std::fs::read_to_string(p).expect("fixture");
        let renderers = html.matches("videoRenderer").count();
        assert!(renderers >= 19, "fixture carries >= 19 renderers: {renderers}");

        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        engine.tabs.lock().unwrap_or_else(|e| e.into_inner()).insert(
            "yt".to_string(),
            Tab {
                url: "https://www.youtube.com/results?search_query=rust".into(),
                html,
                ..Tab::default_for_test()
            },
        );
        let js = r#"
            (function() {
                var scripts = document.querySelectorAll('script');
                for (var i = 0; i < scripts.length; i++) {
                    var t = scripts[i].textContent;
                    if (t.indexOf('ytInitialData') !== -1) {
                        var n = 0, p = 0;
                        while ((p = t.indexOf('videoRenderer', p)) !== -1) { n++; p += 13; }
                        return n;
                    }
                }
                return 0;
            })()
        "#;
        let r = rt
            .block_on(dispatch(
                &engine,
                "eval",
                json!({"tab_id": "yt", "js": js}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(true));
        let n = r["result"].as_i64().unwrap_or(0);
        assert!(n >= 19, "bridge script scan found {n} videoRenderers, want >= 19");
    }

    #[test]
    fn eval_page_fetch_presents_the_live_session_jar() {
        // The session-bound fetch wiring end to end at the dispatch level:
        // a cookie injected via storage_state_set rides a page-context
        // fetch() the way the browser would send the session on an XHR.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                addr_tx.send(listener.local_addr().unwrap()).unwrap();
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 8192];
                let n = socket.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                // Match the cookie pair value, not the header prefix — jar
                // cookie order is nondeterministic when several match.
                let body = if req.contains("c_user=6159") {
                    "carried"
                } else {
                    "missing"
                };
                socket
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            });
        });
        let addr = addr_rx.recv().unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();

        // Seed the live jar the way the FB provider's login flow would.
        let r = rt
            .block_on(dispatch(
                &engine,
                "storage_state_set",
                json!({"storage_state": {"cookies": [{
                    "name": "c_user",
                    "value": "6159",
                    "domain": "127.0.0.1",
                    "path": "/",
                }], "origins": []}}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(true));
        assert_eq!(r["cookies"], json!(1));

        // A tab on the loopback origin; the eval'd page fetch must carry it.
        engine.tabs.lock().unwrap_or_else(|e| e.into_inner()).insert(
            "s".to_string(),
            Tab {
                url: format!("http://{addr}/page"),
                html: "<html><body>shell</body></html>".into(),
                ..Tab::default_for_test()
            },
        );
        let r = rt
            .block_on(dispatch(
                &engine,
                "eval",
                json!({
                    "tab_id": "s",
                    "js": "(async () => { const r = await fetch('/echo'); return await new Promise((res, rej) => r.text([res, rej])); })()",
                }),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(true));
        assert_eq!(r["result"], json!("carried"));

        handle.join().unwrap();
    }

    #[test]
    fn goto_chain_presents_the_initiator_and_document_referrer() {
        // A followed navigation is not an address-bar load: the second goto
        // on a tab must carry Referer + Sec-Fetch-Site: same-origin on the
        // wire, and the eval'd document must see the initiator as
        // document.referrer. (Server answers path|referer|site per request;
        // hyper writes header names lowercase on the wire.)
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let seen: std::sync::Arc<
            std::sync::Mutex<Vec<String>>,
        > = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen_server = seen.clone();
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                addr_tx.send(listener.local_addr().unwrap()).unwrap();
                for _ in 0..2 {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let mut buf = vec![0u8; 8192];
                    let n = socket.read(&mut buf).await.unwrap();
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let pick = |name: &str| {
                        req.lines()
                            .find(|l| l.to_ascii_lowercase().starts_with(&format!("{name}:")))
                            .unwrap_or("")
                            .to_string()
                    };
                    let body = format!("{path}|{}|{}", pick("referer"), pick("sec-fetch-site"));
                    seen_server
                        .lock().unwrap_or_else(|e| e.into_inner())
                        .push(body.clone());
                    socket
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            )
                            .as_bytes(),
                        )
                        .await
                        .unwrap();
                }
            });
        });
        let addr = addr_rx.recv().unwrap();
        let base = format!("http://{addr}");

        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();

        let r = rt
            .block_on(dispatch(&engine, "goto", json!({"tab_id": "t", "url": format!("{base}/first")})))
            .unwrap();
        assert_eq!(r["ok"], json!(true));
        assert_eq!(r["status"], json!(200));

        let r = rt
            .block_on(dispatch(&engine, "goto", json!({"tab_id": "t", "url": format!("{base}/second")})))
            .unwrap();
        assert_eq!(r["ok"], json!(true));
        assert_eq!(r["status"], json!(200));

        let requests = seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(requests.len(), 2, "server saw {} requests", requests.len());
        // First load: address-bar — no Referer, Sec-Fetch-Site: none.
        assert!(
            !requests[0].to_ascii_lowercase().contains("referer:"),
            "first goto leaked a Referer: {}",
            requests[0]
        );
        assert!(
            requests[0].contains("sec-fetch-site: none"),
            "first goto Sec-Fetch-Site: {}",
            requests[0]
        );
        // Followed navigation: Referer + same-origin.
        let mut parts = requests[1].split('|');
        assert_eq!(parts.next(), Some("/second"), "second request: {}", requests[1]);
        assert!(
            parts.next().unwrap_or("").contains(&format!("{base}/first")),
            "second goto Referer: {}",
            requests[1]
        );
        assert!(
            parts.next().unwrap_or("").contains("same-origin"),
            "second goto Sec-Fetch-Site: {}",
            requests[1]
        );

        // The eval'd page sees the initiator the way a followed navigation
        // leaves it.
        let r = rt
            .block_on(dispatch(
                &engine,
                "eval",
                json!({"tab_id": "t", "js": "document.referrer"}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(true));
        assert_eq!(r["result"], json!(format!("{base}/first")));

        handle.join().unwrap();
    }

    #[test]
    fn eval_probe_reports_the_stealth_fingerprint_over_the_wire() {
        // The M3 stealth surface as a sidecar client sees it: the same eval
        // a fingerprint script would run must answer with the pinned,
        // self-consistent Chrome-on-Windows identity.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        let js = r#"
            (async () => {
                const h = await navigator.userAgentData.getHighEntropyValues([
                    'architecture', 'platformVersion', 'uaFullVersion', 'formFactor',
                ]);
                return {
                    ua: navigator.userAgent,
                    webdriverAbsent: !('webdriver' in navigator),
                    vendor: navigator.vendor,
                    platform: navigator.platform,
                    hardwareConcurrency: navigator.hardwareConcurrency,
                    screenW: screen.width,
                    chromePresent: typeof window.chrome === 'object' && window.chrome !== null,
                    uadPlatform: navigator.userAgentData.platform,
                    pluginsLen: navigator.plugins.length,
                    heArch: h.architecture,
                    hePlatformVersion: h.platformVersion,
                    heUaFull: h.uaFullVersion,
                    heFormFactor: h.formFactor,
                };
            })()
        "#;
        let r = rt
            .block_on(dispatch(
                &engine,
                "eval",
                json!({"tab_id": "fp", "js": js}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(true));
        let p = &r["result"];
        assert!(p["ua"].as_str().unwrap().contains("Chrome/145"));
        assert_eq!(p["webdriverAbsent"], json!(true));
        assert_eq!(p["vendor"], json!("Google Inc."));
        assert_eq!(p["platform"], json!("Win32"));
        assert_eq!(p["hardwareConcurrency"], json!(8));
        assert_eq!(p["screenW"], json!(1920));
        assert_eq!(p["chromePresent"], json!(true));
        assert_eq!(p["uadPlatform"], json!("Windows"));
        assert_eq!(p["pluginsLen"], json!(5));
        assert_eq!(p["heArch"], json!("x86"));
        assert_eq!(p["hePlatformVersion"], json!("10.0.0"));
        assert_eq!(p["heUaFull"], json!("145.0.0.0"));
        assert_eq!(p["heFormFactor"], json!("Desktop"));
    }

    /// A per-test temp path that cannot collide with a parallel test's file.
    /// The thread name is sanitized — test names contain `::`, which is an
    /// illegal Windows filename character.
    fn temp_session_file(tag: &str) -> std::path::PathBuf {
        let name: String = std::thread::current()
            .name()
            .unwrap_or("t")
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
            .collect();
        let mut p = std::env::temp_dir();
        p.push(format!(
            "se_serve_f29_{}_{}_{}.json",
            tag,
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn session_save_then_load_round_trips_jar_and_origin_storage() {
        // The disk tier's core contract: save writes the same artifact
        // storage_state_get produces; load after a session_reset restores
        // the live jar AND the per-origin storage archive (an archived
        // origin — not the current one — must survive the round trip, that
        // is what makes a resumed crawl keep A's writes after visiting B).
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        let path = temp_session_file("roundtrip");

        // Seed: one cookie in the jar, one archived origin's localStorage.
        let r = rt
            .block_on(dispatch(
                &engine,
                "storage_state_set",
                json!({"storage_state": {
                    "cookies": [{
                        "name": "xs", "value": "1:2:3",
                        "domain": ".facebook.com", "path": "/",
                        // Full wire shape: cookie_wire always emits these
                        // keys (expires -1 / sameSite "Lax" are the
                        // defaults), so a seed omitting them would make the
                        // post-restore artifact differ from the saved one.
                        "expires": -1, "httpOnly": false, "secure": false,
                        "sameSite": "Lax",
                    }],
                    "origins": [{
                        "origin": "http://a.test",
                        "localStorage": [{"name": "mark", "value": "A"}],
                    }],
                }}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(true));

        // The saved file is byte-identical to the storage_state_get artifact
        // — one shape for wire and disk, no second format to drift.
        let r = rt
            .block_on(dispatch(&engine, "storage_state_get", Value::Null))
            .unwrap();
        let expected = r["storage_state"].clone();
        let r = rt
            .block_on(dispatch(
                &engine,
                "session_save",
                json!({"path": path.display().to_string()}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(true));
        assert_eq!(r["cookies"], json!(1));
        assert_eq!(r["origins"], json!(1));
        let on_disk: Value = serde_json::from_str(
            &std::fs::read_to_string(&path).expect("session file written"),
        )
        .expect("session file is JSON");
        assert_eq!(on_disk, expected);

        // Wipe everything, then load the file back.
        let r = rt.block_on(dispatch(&engine, "session_reset", Value::Null)).unwrap();
        assert_eq!(r["ok"], json!(true));
        let r = rt.block_on(dispatch(&engine, "cookies_get", Value::Null)).unwrap();
        assert_eq!(r["cookies"].as_array().unwrap().len(), 0);

        let r = rt
            .block_on(dispatch(
                &engine,
                "session_load",
                json!({"path": path.display().to_string()}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(true));
        assert_eq!(r["cookies"], json!(1));

        // Jar + archived origin both came back, and the artifact matches
        // what was saved — the restore is lossless.
        let r = rt
            .block_on(dispatch(&engine, "storage_state_get", Value::Null))
            .unwrap();
        assert_eq!(r["storage_state"], expected);

        // And the reopened-session flow works off the restore: the pool is
        // keyed by origin, so once the tab lands on the saved origin its
        // evals read the restored localStorage directly — no archive consult.
        let tabs = engine.tabs.lock().unwrap_or_else(|e| e.into_inner());
        let tab = tabs.get("default").expect("default tab exists after load");
        let restored = Tab::after_navigation(
            Some(tab),
            "http://a.test/back",
            String::new(),
            String::new(),
        );
        drop(tabs);
        let _ = restored;
        assert_eq!(
            engine
                .local_storage_for("http://a.test")
                .get("mark")
                .as_deref(),
            Some("A")
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn session_verbs_error_cleanly_without_a_path_or_with_a_bad_one() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        // No engine default (--session-file absent) and no param → verb error
        // that names the fix, not a panic.
        let engine = Engine::default();
        let r = rt.block_on(dispatch(&engine, "session_save", Value::Null)).unwrap();
        assert_eq!(r["ok"], json!(false));
        assert!(r["error"].as_str().unwrap().contains("--session-file"));
        let r = rt.block_on(dispatch(&engine, "session_load", Value::Null)).unwrap();
        assert_eq!(r["ok"], json!(false));
        assert!(r["error"].as_str().unwrap().contains("--session-file"));

        // A missing file on load is an ok:false, never a crash.
        let missing = temp_session_file("missing");
        let r = rt
            .block_on(dispatch(
                &engine,
                "session_load",
                json!({"path": missing.display().to_string()}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(false));

        // A file whose JSON is not an object is rejected by the restore half.
        let bad = temp_session_file("badsyntax");
        std::fs::write(&bad, "42").unwrap();
        let r = rt
            .block_on(dispatch(
                &engine,
                "session_load",
                json!({"path": bad.display().to_string()}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(false));
        let _ = std::fs::remove_file(&bad);

        // An unwritable target directory on save is an ok:false, and no
        // stray .tmp is left behind in the unwritable directory.
        let mut nope = temp_session_file("unwritable");
        nope.pop();
        nope.push("no_such_dir_f29");
        nope.push("s.json");
        let r = rt
            .block_on(dispatch(
                &engine,
                "session_save",
                json!({"path": nope.display().to_string()}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(false));
    }

    #[test]
    fn engine_default_session_file_is_the_verb_fallback_path() {
        // --session-file wires the engine's default: the verbs persist to it
        // without the caller passing a path (the sidecar-restart contract).
        let rt = tokio::runtime::Runtime::new().unwrap();
        let path = temp_session_file("engine_default");
        let engine = Engine::default().with_session_file(Some(path.clone()));

        let r = rt
            .block_on(dispatch(
                &engine,
                "storage_state_set",
                json!({"storage_state": {
                    "cookies": [{
                        "name": "sid", "value": "abc",
                        "domain": ".example.com", "path": "/",
                    }],
                    "origins": [],
                }}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(true));

        let r = rt.block_on(dispatch(&engine, "session_save", Value::Null)).unwrap();
        assert_eq!(r["ok"], json!(true));
        assert_eq!(r["path"], json!(path.display().to_string()));
        assert!(path.exists());

        let r = rt.block_on(dispatch(&engine, "session_reset", Value::Null)).unwrap();
        assert_eq!(r["ok"], json!(true));
        let r = rt.block_on(dispatch(&engine, "session_load", Value::Null)).unwrap();
        assert_eq!(r["ok"], json!(true));
        let r = rt.block_on(dispatch(&engine, "cookies_get", Value::Null)).unwrap();
        let cookies = r["cookies"].as_array().unwrap();
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0]["name"], json!("sid"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn session_save_survives_a_concurrent_read_shape_unchanged() {
        // Durability shape: the .tmp sibling from the atomic write is
        // renamed away on success, so a successful save leaves exactly one
        // file at the target path.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        let path = temp_session_file("tmp_gone");
        let r = rt
            .block_on(dispatch(
                &engine,
                "storage_state_set",
                json!({"storage_state": {"cookies": [], "origins": []}}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(true));
        let r = rt
            .block_on(dispatch(
                &engine,
                "session_save",
                json!({"path": path.display().to_string()}),
            ))
            .unwrap();
        assert_eq!(r["ok"], json!(true));
        let mut tmp = path.clone();
        tmp.set_extension("tmp");
        assert!(!tmp.exists(), "no .tmp sibling left after a successful save");
        assert!(path.exists());

        let _ = std::fs::remove_file(&path);
    }

    // ── Render mode (benchmark-loop firing 3) ───────────────────────────

    /// Tiny one-shot HTTP server for the render tests: serves `routes`
    /// (path → status, body) over plain TCP, `Connection: close` per
    /// request, on its own runtime/thread — the same pattern as the
    /// fetch-verb wire test above. Accepts exactly `accepts` connections.
    fn render_test_server(
        routes: Vec<(&'static str, u16, String)>,
        accepts: usize,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                addr_tx.send(listener.local_addr().unwrap()).unwrap();
                for _ in 0..accepts {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let mut buf = vec![0u8; 65536];
                    let n = socket.read(&mut buf).await.unwrap();
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let (status, payload) = routes
                        .iter()
                        .find(|(p, _, _)| path == *p)
                        .map(|(_, s, b)| (*s, b.clone()))
                        .unwrap_or((404, String::new()));
                    let head = format!(
                        "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        payload.len()
                    );
                    socket
                        .write_all(format!("{head}{payload}").as_bytes())
                        .await
                        .unwrap();
                }
            });
        });
        (addr_rx.recv().unwrap(), handle)
    }

    fn seeded_tab(engine: &Engine, tab_id: &str, url: &str, html: &str) {
        let mut tab = Tab::default_for_test();
        tab.url = url.to_string();
        tab.html = html.to_string();
        engine
            .tabs
            .lock().unwrap_or_else(|e| e.into_inner())
            .insert(tab_id.to_string(), tab);
    }

    #[test]
    fn render_goto_executes_inline_scripts_and_adopts_dom() {
        let (addr, handle) = render_test_server(
            vec![(
                "/p",
                200,
                r#"<html><body><div id="price">loading</div><script>document.getElementById("price").textContent = "$" + "74.50";</script></body></html>"#.to_string(),
            )],
            1,
        );
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        let out = rt
            .block_on(dispatch(
                &engine,
                "goto",
                json!({"url": format!("http://{addr}/p"), "render": true}),
            ))
            .unwrap();
        assert_eq!(out["ok"], json!(true));
        assert_eq!(out["rendered"], json!(true));
        assert_eq!(out["render_scripts"], json!(1));
        assert_eq!(out["render_skipped"], json!(0));
        assert_eq!(out["render_errors"], json!([]));
        let r = rt
            .block_on(dispatch(&engine, "read_html", json!({"tab_id": "default"})))
            .unwrap();
        assert!(
            r["html"].as_str().unwrap().contains("$74.50"),
            "rendered DOM adopted into the tab: {}",
            r["html"]
        );
        handle.join().unwrap();
    }

    #[test]
    fn render_goto_executes_data_uri_scripts_and_adopts_dom() {
        // The Comet-bootloader shape: the executable script arrives as a
        // data:-URI src (FB's marketplace serves application/x-javascript
        // base64 chunks). Before the collect_scripts data-URI path this page
        // rendered zero scripts and the skeleton never mutated; the unit
        // pins cover decoding, this pins the whole pass — collect, harness
        // execution, writeback adoption.
        let (addr, handle) = render_test_server(
            vec![(
                "/p",
                200,
                r#"<html><body><div id="boot">skeleton</div><script src="data:application/x-javascript;base64,ZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoImJvb3QiKS50ZXh0Q29udGVudCA9ICJoeWRyYXRlZCI7"></script></body></html>"#.to_string(),
            )],
            1,
        );
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        let out = rt
            .block_on(dispatch(
                &engine,
                "goto",
                json!({"url": format!("http://{addr}/p"), "render": true}),
            ))
            .unwrap();
        assert_eq!(out["ok"], json!(true));
        assert_eq!(out["rendered"], json!(true));
        assert_eq!(out["render_scripts"], json!(1));
        assert_eq!(out["render_skipped"], json!(0));
        assert_eq!(out["render_errors"], json!([]));
        let r = rt
            .block_on(dispatch(&engine, "read_html", json!({"tab_id": "default"})))
            .unwrap();
        assert!(
            r["html"].as_str().unwrap().contains("hydrated"),
            "data-URI script ran and the DOM writeback was adopted: {}",
            r["html"]
        );
        handle.join().unwrap();
    }

    #[test]
    fn render_leaves_dynamically_inserted_scripts_as_inert_markup() {
        // Documents today's contract: render executes the STATICALLY
        // collected scripts only. A page script that injects <script src>
        // gets the tag grafted into the DOM (it serializes with the
        // writeback) but nothing fetches or runs it — the test server
        // serves exactly one request, so any fetch attempt would surface
        // as a render error. When dynamic script loading ships (Comet lazy
        // modules need it), this pin flips to assert execution.
        let (addr, handle) = render_test_server(
            vec![(
                "/p",
                200,
                r#"<html><body><div id="boot">skeleton</div><script>
var s = document.createElement("script");
s.setAttribute("src", "/dyn.js");
document.body.appendChild(s);
</script></body></html>"#.to_string(),
            )],
            1,
        );
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        let out = rt
            .block_on(dispatch(
                &engine,
                "goto",
                json!({"url": format!("http://{addr}/p"), "render": true}),
            ))
            .unwrap();
        assert_eq!(out["ok"], json!(true));
        assert_eq!(out["render_errors"], json!([]));
        let r = rt
            .block_on(dispatch(&engine, "read_html", json!({"tab_id": "default"})))
            .unwrap();
        let html = r["html"].as_str().unwrap();
        assert!(
            html.contains("dyn.js"),
            "injected script tag grafts into the adopted DOM: {html}"
        );
        handle.join().unwrap();
    }

    #[test]
    fn render_reports_total_error_count_beyond_the_cap() {
        // render_errors is capped at RENDER_MAX_ERRORS to bound the RPC
        // envelope; render_errors_total tells the caller how many were
        // truncated away. (A flooded boot error tail reads as "5 errors"
        // without it — the FB Comet diagnosis needed the real count.)
        let boom = "<script>throw new Error(\"x\")</script>".repeat(7);
        let (addr, handle) = render_test_server(
            vec![("/p", 200, format!("<html><body>{boom}</body></html>"))],
            1,
        );
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        let out = rt
            .block_on(dispatch(
                &engine,
                "goto",
                json!({"url": format!("http://{addr}/p"), "render": true}),
            ))
            .unwrap();
        assert_eq!(out["ok"], json!(true));
        assert_eq!(out["render_errors_total"], json!(7));
        assert_eq!(out["render_errors"].as_array().unwrap().len(), 5);
        handle.join().unwrap();
    }

    #[test]
    fn render_fetch_document_branch_renders_and_reports_rendered_html() {
        let (addr, handle) = render_test_server(
            vec![(
                "/p",
                200,
                r#"<html><body><span id="v">raw</span><script>document.getElementById("v").textContent = "cooked"</script></body></html>"#.to_string(),
            )],
            1,
        );
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        let out = rt
            .block_on(dispatch(
                &engine,
                "fetch",
                json!({"url": format!("http://{addr}/p"), "render": true}),
            ))
            .unwrap();
        assert_eq!(out["rendered"], json!(true));
        assert!(
            out["html"].as_str().unwrap().contains("cooked"),
            "envelope html is the rendered document: {}",
            out["html"]
        );
        handle.join().unwrap();
    }

    #[test]
    fn render_dispatches_domcontentloaded_to_document_and_window_listeners() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        seeded_tab(
            &engine,
            "default",
            "http://x.test/p",
            r#"<html><body><div id="doc">0</div><div id="win">0</div>
<script>
document.addEventListener("DOMContentLoaded", function () { document.getElementById("doc").textContent = "doc-fired"; });
window.addEventListener("DOMContentLoaded", function () { document.getElementById("win").textContent = "win-fired"; });
</script></body></html>"#,
        );
        let stats = rt.block_on(engine.render_tab("default", std::time::Duration::from_secs(2)));
        assert_eq!(stats.scripts, 1, "errors: {:?}", stats.errors);
        let r = rt
            .block_on(dispatch(&engine, "read_html", json!({"tab_id": "default"})))
            .unwrap();
        let html = r["html"].as_str().unwrap();
        assert!(html.contains("doc-fired"), "document listener: {}", html);
        assert!(html.contains("win-fired"), "window listener via bubbles: {}", html);
    }

    #[test]
    fn render_isolates_a_syntax_bad_script_and_continues() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        seeded_tab(
            &engine,
            "default",
            "http://x.test/p",
            r#"<html><body><div id="ok">no</div>
<script>this is not javascript (</script>
<script>document.getElementById("ok").textContent = "yes"</script>
</body></html>"#,
        );
        let stats = rt.block_on(engine.render_tab("default", std::time::Duration::from_secs(2)));
        assert_eq!(stats.scripts, 1);
        assert_eq!(stats.skipped, 1);
        assert!(
            stats.errors.iter().any(|e| e.contains("compile script 0")),
            "compile failure reported: {:?}",
            stats.errors
        );
        let r = rt
            .block_on(dispatch(&engine, "read_html", json!({"tab_id": "default"})))
            .unwrap();
        assert!(r["html"].as_str().unwrap().contains("yes"));
    }

    #[test]
    fn render_skips_module_and_data_block_scripts() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        seeded_tab(
            &engine,
            "default",
            "http://x.test/p",
            r##"<html><head>
<script type="application/ld+json">{"@type":"Product","name":"keepme"}</script>
<script type="module">var m = document.createElement("div"); m.id = "mod" + "mark"; document.body.appendChild(m);</script>
</head><body><div id="a">0</div>
<script>document.getElementById("a").textContent = "ran"</script>
</body></html>"##,
        );
        let stats = rt.block_on(engine.render_tab("default", std::time::Duration::from_secs(2)));
        assert_eq!(stats.scripts, 1);
        assert_eq!(stats.skipped, 2);
        let r = rt
            .block_on(dispatch(&engine, "read_html", json!({"tab_id": "default"})))
            .unwrap();
        let html = r["html"].as_str().unwrap();
        assert!(html.contains("ran"));
        assert!(html.contains("keepme"), "data block untouched: {}", html);
        assert!(
            !html.contains("modmark"),
            "module must not execute (its source stays in the DOM): {}",
            html
        );
    }

    #[test]
    fn render_fetches_external_scripts_in_document_order() {
        let (addr, handle) = render_test_server(
            vec![
                (
                    "/p",
                    200,
                    r#"<html><body><div id="out"></div><script src="/a.js"></script><script src="b.js"></script></body></html>"#.to_string(),
                ),
                (
                    "/a.js",
                    200,
                    r#"document.getElementById("out").textContent = "A";"#.to_string(),
                ),
                (
                    "/b.js",
                    200,
                    r#"document.getElementById("out").textContent += "B";"#.to_string(),
                ),
            ],
            3,
        );
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        let out = rt
            .block_on(dispatch(
                &engine,
                "goto",
                json!({"url": format!("http://{addr}/p"), "render": true}),
            ))
            .unwrap();
        assert_eq!(out["render_scripts"], json!(2), "errors: {:?}", out["render_errors"]);
        assert_eq!(out["render_skipped"], json!(0));
        let r = rt
            .block_on(dispatch(&engine, "read_html", json!({"tab_id": "default"})))
            .unwrap();
        assert!(
            r["html"].as_str().unwrap().contains("AB"),
            "externals fetched and ran in order (relative src resolved): {}",
            r["html"]
        );
        handle.join().unwrap();
    }

    #[test]
    fn render_settle_ms_bounds_the_timer_pump() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        seeded_tab(
            &engine,
            "default",
            "http://x.test/p",
            r#"<html><body><div id="t">early</div>
<script>setTimeout(function () { document.getElementById("t").textContent = "late"; }, 4000);</script>
</body></html>"#,
        );
        let started = std::time::Instant::now();
        let stats = rt.block_on(engine.render_tab("default", std::time::Duration::from_millis(100)));
        assert!(
            started.elapsed().as_millis() < 3000,
            "short budget must cut the 4s timer wait: {:?}",
            started.elapsed()
        );
        let r = rt
            .block_on(dispatch(&engine, "read_html", json!({"tab_id": "default"})))
            .unwrap();
        assert!(
            r["html"].as_str().unwrap().contains("early"),
            "4s timer must not have fired inside a 100ms budget: {}",
            r["html"]
        );
        let _ = stats;
    }

    #[test]
    fn render_off_by_default_envelope_unchanged() {
        // The agent-contract pin (§7: goto parses, eval executes) survives
        // render mode: without render:true the envelope carries no render
        // keys and the document stays the raw parse.
        let (addr, handle) = render_test_server(
            vec![(
                "/p",
                200,
                r#"<html><body><div id="v">raw</div><script>document.getElementById("v").textContent = "cooked"</script></body></html>"#.to_string(),
            )],
            1,
        );
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        let out = rt
            .block_on(dispatch(
                &engine,
                "goto",
                json!({"url": format!("http://{addr}/p")}),
            ))
            .unwrap();
        assert!(out.get("rendered").is_none());
        assert!(out.get("render_scripts").is_none());
        let r = rt
            .block_on(dispatch(&engine, "read_html", json!({"tab_id": "default"})))
            .unwrap();
        assert!(
            r["html"].as_str().unwrap().contains("raw"),
            "no render without opt-in: {}",
            r["html"]
        );
        handle.join().unwrap();
    }

    #[test]
    fn render_tab_without_a_tab_reports_an_error() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        let stats = rt.block_on(engine.render_tab("missing", std::time::Duration::from_secs(1)));
        assert_eq!(stats.scripts, 0);
        assert!(stats.errors.iter().any(|e| e.contains("no tab")));
    }

    // ── render-tier page-script navigation follow (iteration 26) ─────────
    // A real browser lands on the TARGET when page script navigates
    // (location.href=/window.location=/assign/replace); a render that keeps
    // serving the shell hands the agent the redirector. These tests are the
    // bite run: they compile and run pre-fix and fail on the shell being
    // served. The follow-family tests DETACH the server handle (no join):
    // pre-fix the follow never happens, the server blocks on its next accept
    // forever, and a join would hang the bite run; the thread dies with the
    // test process.
    #[test]
    fn render_goto_follows_a_page_script_navigation() {
        let (addr, _handle) = render_test_server(
            vec![
                (
                    "/shell",
                    200,
                    r#"<html><body>redirector shell<script>location.href="/real";</script></body></html>"#.to_string(),
                ),
                (
                    "/real",
                    200,
                    r#"<html><body>REAL TARGET REACHED</body></html>"#.to_string(),
                ),
            ],
            2,
        );
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        let out = rt
            .block_on(dispatch(
                &engine,
                "goto",
                json!({"url": format!("http://{addr}/shell"), "render": true}),
            ))
            .unwrap();
        assert_eq!(out["ok"], json!(true));
        assert_eq!(out["rendered"], json!(true));
        assert!(
            out["final_url"].as_str().unwrap().ends_with("/real"),
            "the envelope's final_url is the FOLLOWED document: {}",
            out["final_url"]
        );
        let r = rt
            .block_on(dispatch(&engine, "read_text", json!({"tab_id": "default"})))
            .unwrap();
        assert!(
            r["text"].as_str().unwrap().contains("REAL TARGET REACHED"),
            "the tab holds the followed document, not the shell: {}",
            r["text"]
        );
    }

    #[test]
    fn render_fetch_branch_follows_a_page_script_navigation() {
        let (addr, _handle) = render_test_server(
            vec![
                (
                    "/shell",
                    200,
                    r#"<html><body>redirector shell<script>window.location="/real";</script></body></html>"#.to_string(),
                ),
                (
                    "/real",
                    200,
                    r#"<html><body>REAL TARGET REACHED</body></html>"#.to_string(),
                ),
            ],
            2,
        );
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        let out = rt
            .block_on(dispatch(
                &engine,
                "fetch",
                json!({"url": format!("http://{addr}/shell"), "render": true}),
            ))
            .unwrap();
        assert_eq!(out["ok"], json!(true));
        assert!(
            out["html"].as_str().unwrap().contains("REAL TARGET REACHED"),
            "the fetch envelope's html is the followed document: {}",
            out["html"]
        );
        assert!(
            out["url"].as_str().unwrap().ends_with("/real"),
            "the fetch envelope's url is the followed document: {}",
            out["url"]
        );
    }

    #[test]
    fn render_follow_is_bounded_with_the_redirect_loop_token() {
        // location.href ping-pong: the follow budget (10, mirroring the HTTP
        // and meta-refresh budgets) stops the chain and the LAST loaded
        // document is served honestly with the contractual token.
        let (addr, _handle) = render_test_server(
            vec![
                (
                    "/loop_a",
                    200,
                    r#"<html><body>LOOP A<script>location.href="loop_b";</script></body></html>"#.to_string(),
                ),
                (
                    "/loop_b",
                    200,
                    r#"<html><body>LOOP B<script>location.href="loop_a";</script></body></html>"#.to_string(),
                ),
            ],
            11, // the goto + 10 capped follows; an 11th would be refused
        );
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        let out = rt
            .block_on(dispatch(
                &engine,
                "goto",
                json!({"url": format!("http://{addr}/loop_a"), "render": true}),
            ))
            .unwrap();
        assert_eq!(out["ok"], json!(true));
        assert_eq!(out["render_nav_hops"], json!(10));
        let errs = out["render_errors"].as_array().unwrap();
        assert!(
            errs.iter().any(|e| e.as_str().unwrap_or("").contains("redirect_loop")),
            "the loop surfaces the contractual token: {errs:?}"
        );
        let r = rt
            .block_on(dispatch(&engine, "read_text", json!({"tab_id": "default"})))
            .unwrap();
        assert!(
            r["text"].as_str().unwrap().contains("LOOP"),
            "the last loaded document is served, not an error: {}",
            r["text"]
        );
    }

    #[test]
    fn render_follow_to_a_refused_target_stops_with_the_token() {
        // The script aims the navigation at the cloud metadata endpoint: the
        // follow passes the same refused_target guard every other navigation
        // surface has, the shell is still served, and the token rides the
        // render errors. (On this unrouted box even an unguarded dial fails
        // fast; the token is the pin.)
        let (addr, handle) = render_test_server(
            vec![(
                "/shell",
                200,
                r#"<html><body>SHELL SERVED<script>location.href="http://169.254.169.254/latest/meta-data";</script></body></html>"#.to_string(),
            )],
            1,
        );
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        let out = rt
            .block_on(dispatch(
                &engine,
                "goto",
                json!({"url": format!("http://{addr}/shell"), "render": true}),
            ))
            .unwrap();
        assert_eq!(out["ok"], json!(true));
        assert_eq!(out["render_nav_hops"], json!(0));
        let errs = out["render_errors"].as_array().unwrap();
        assert!(
            errs.iter().any(|e| e.as_str().unwrap_or("").contains("target_refused")),
            "the refused hop surfaces the contractual token: {errs:?}"
        );
        let r = rt
            .block_on(dispatch(&engine, "read_text", json!({"tab_id": "default"})))
            .unwrap();
        assert!(
            r["text"].as_str().unwrap().contains("SHELL SERVED"),
            "the refused navigation leaves the loaded document in place: {}",
            r["text"]
        );
        handle.join().unwrap();
    }

    #[test]
    fn render_follow_resolves_relative_against_the_documents_url() {
        // location.replace from a DIRECTORY path: the relative target
        // resolves against the document's URL (sibling, not root child).
        let (addr, _handle) = render_test_server(
            vec![
                (
                    "/dir/shell",
                    200,
                    r#"<html><body>redirector shell<script>location.replace("real");</script></body></html>"#.to_string(),
                ),
                (
                    "/dir/real",
                    200,
                    r#"<html><body>REAL TARGET REACHED</body></html>"#.to_string(),
                ),
            ],
            2,
        );
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        let out = rt
            .block_on(dispatch(
                &engine,
                "goto",
                json!({"url": format!("http://{addr}/dir/shell"), "render": true}),
            ))
            .unwrap();
        assert_eq!(out["ok"], json!(true));
        assert!(
            out["final_url"].as_str().unwrap().ends_with("/dir/real"),
            "replace resolves against the document URL: {}",
            out["final_url"]
        );
    }

    #[test]
    fn render_follow_ignores_a_same_document_hash_navigation() {
        // location.hash = a same-document navigation in a real browser: no
        // reload, no refetch. Green pre-fix (nothing to bite) — the pin
        // against OVER-reach: a follow that re-navigated here would hit a
        // dead listener and land a connection error in render_errors.
        let (addr, handle) = render_test_server(
            vec![(
                "/p",
                200,
                r#"<html><body>HASH PAGE<script>location.hash="sec";</script></body></html>"#.to_string(),
            )],
            1,
        );
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        let out = rt
            .block_on(dispatch(
                &engine,
                "goto",
                json!({"url": format!("http://{addr}/p"), "render": true}),
            ))
            .unwrap();
        assert_eq!(out["ok"], json!(true));
        assert_eq!(out["render_errors"], json!([]));
        handle.join().unwrap();
    }

    #[test]
    fn collect_scripts_resolves_relative_src_against_the_page() {
        let (units, skips) = collect_scripts(
            r#"<html><head>
<script src="https://cdn.example/lib.js"></script>
<script src="//cdn2.example/pc.js"></script>
<script src="/root.js"></script>
<script src="sub/dir.js"></script>
<script src="../up.js"></script>
<script>inline()</script>
</head></html>"#,
            "http://site.example/a/b/page?q=1",
        );
        assert_eq!(skips, Vec::<String>::new());
        let urls: Vec<String> = units
            .iter()
            .map(|u| match u {
                ScriptUnit::External(u) => u.clone(),
                ScriptUnit::Inline(s) => format!("inline:{s}"),
            })
            .collect();
        assert_eq!(
            urls,
            vec![
                "https://cdn.example/lib.js",
                "http://cdn2.example/pc.js",
                "http://site.example/root.js",
                "http://site.example/a/b/sub/dir.js",
                "http://site.example/a/up.js",
                "inline:inline()",
            ]
        );
    }

    #[test]
    fn collect_scripts_decodes_data_uri_srcs_to_inline_units() {
        // Comet-class bootloaders (FB's marketplace among them) ship early
        // chunks as data-URI srcs; before this they hit the unresolvable
        // skip and the page never hydrated. Both spellings decode: base64
        // (FB's application/x-javascript) and percent-encoded plain.
        let (units, skips) = collect_scripts(
            r#"<script src="data:application/x-javascript;base64,Ym9vdCgp"></script>
<script src="data:text/javascript,var%20x%3D1%3B"></script>"#,
            "http://site.example/",
        );
        assert_eq!(skips, Vec::<String>::new());
        assert_eq!(units.len(), 2);
        match &units[0] {
            ScriptUnit::Inline(s) => assert_eq!(s, "boot()"),
            ScriptUnit::External(u) => panic!("data URI became an external fetch: {u}"),
        }
        match &units[1] {
            ScriptUnit::Inline(s) => assert_eq!(s, "var x=1;"),
            ScriptUnit::External(u) => panic!("data URI became an external fetch: {u}"),
        }
    }

    #[test]
    fn collect_scripts_skips_non_js_and_oversized_data_uris() {
        // A text/plain data URI is not executable (browsers refuse those as
        // script srcs too); a decoded body over RENDER_MAX_SCRIPT_BYTES gets
        // the same bomb guard fetched externals have.
        let oversized = format!(
            r#"<script src="data:text/javascript,{}"></script>"#,
            "a".repeat(RENDER_MAX_SCRIPT_BYTES + 1)
        );
        let (units, skips) = collect_scripts(
            &format!("<script src=\"data:text/plain;base64,YQ==\"></script>{oversized}"),
            "http://site.example/",
        );
        assert!(units.is_empty());
        assert_eq!(skips.len(), 2);
        assert!(skips[0].contains("non-JS data URI mime"), "{skips:?}");
        assert!(skips[1].contains("exceeds"), "{skips:?}");
    }

    #[test]
    fn collect_scripts_truncates_unresolvable_src_echoes() {
        // Skip reasons ride render_errors in the RPC response; a junk src
        // (data-URI class values run to hundreds of KB) must not bloat it.
        let junk = format!("datax:{}", "y".repeat(5000));
        let (units, skips) = collect_scripts(
            &format!("<script src=\"{junk}\"></script>"),
            "http://site.example/",
        );
        assert!(units.is_empty());
        assert_eq!(skips.len(), 1);
        assert!(
            skips[0].len() <= 120,
            "skip reason bloats render_errors: {} bytes",
            skips[0].len()
        );
    }
}

#[cfg(test)]
mod hardening_tests {
    use super::*;

    fn seed_tab(engine: &Engine, id: &str) {
        engine.tabs.lock().unwrap().insert(id.to_string(), Tab {
            url: String::new(),
            referrer: String::new(),
            html: String::new(),
            session_storage: Default::default(),
            session_archive: HashMap::new(),
            window_name: Default::default(),
            writeback: Default::default(),
        });
        engine.tab_touch(id, 0);
    }

    #[test]
    fn ws_connect_refuses_a_header_that_would_split_the_handshake() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        for headers in [
            json!({"X-A": "v\r\nX-Injected: 1"}),
            json!({"X A": "v"}),
            json!({"X-A\r\nHost": "evil"}),
        ] {
            let r = rt
                .block_on(dispatch(
                    &engine,
                    "ws_connect",
                    json!({"url": "ws://127.0.0.1:9/", "headers": headers}),
                ))
                .unwrap();
            assert_eq!(r["ok"], json!(false));
            assert!(r["error"].as_str().unwrap().contains("not a valid header"), "{r}");
        }
        // The link-local class is refused on this path too.
        let r = rt
            .block_on(dispatch(&engine, "ws_connect", json!({"url": "ws://169.254.169.254/"})))
            .unwrap();
        assert!(r["error"].as_str().unwrap().contains("refused target"), "{r}");
    }

    #[test]
    fn idle_tabs_are_swept_and_busy_tabs_are_kept() {
        let engine = Engine::default();
        for id in ["a", "b", "c"] {
            seed_tab(&engine, id);
        }
        assert_eq!(engine.tabs.lock().unwrap().len(), 3);
        // Nothing is idle yet.
        assert_eq!(engine.sweep_tabs(Some(std::time::Duration::from_secs(60)), 0), 0);
        std::thread::sleep(std::time::Duration::from_millis(60));
        engine.tab_touch("b", 0); // b was just used
        engine.tab_touch("c", 1); // c has a request in flight
        let n = engine.sweep_tabs(Some(std::time::Duration::from_millis(50)), 0);
        assert_eq!(n, 1);
        let tabs = engine.tabs.lock().unwrap();
        assert!(!tabs.contains_key("a") && tabs.contains_key("b") && tabs.contains_key("c"));
        drop(tabs);
        // Once its request ends and it idles, c goes too.
        engine.tab_touch("c", -1);
        std::thread::sleep(std::time::Duration::from_millis(60));
        assert_eq!(engine.sweep_tabs(Some(std::time::Duration::from_millis(50)), 0), 2);
        assert_eq!(engine.tabs.lock().unwrap().len(), 0);
    }

    #[test]
    fn the_tab_cap_evicts_least_recently_used_first() {
        let engine = Engine::default();
        for id in ["t1", "t2", "t3", "t4", "t5"] {
            seed_tab(&engine, id);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        engine.tab_touch("t1", 0); // t1 becomes the most recent
        assert_eq!(engine.sweep_tabs(None, 3), 2);
        let tabs = engine.tabs.lock().unwrap();
        let mut left: Vec<&String> = tabs.keys().collect();
        left.sort();
        assert_eq!(left, ["t1", "t4", "t5"]);
        drop(tabs);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let h = rt.block_on(dispatch(&engine, "health", json!({}))).unwrap();
        assert_eq!(h["tabs_swept"], json!(2));
        assert_eq!(h["tabs"], json!(3));
        // A swept tab is simply a fresh tab on its next use.
        seed_tab(&engine, "t2");
        assert!(engine.tabs.lock().unwrap().contains_key("t2"));
    }

    #[test]
    fn a_runaway_script_is_terminated_and_the_next_eval_runs() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let actor = JsActor::with_grace(Some(std::time::Duration::from_millis(300)));
        let started = std::time::Instant::now();
        let out = rt.block_on(actor.eval_with_budget(
            None,
            "while (true) {}".to_string(),
            std::time::Duration::from_millis(100),
        ));
        let err = out.expect_err("an endless loop must not return a value");
        assert!(err.contains("time limit"), "{err}");
        assert!(started.elapsed() < std::time::Duration::from_secs(5), "{:?}", started.elapsed());
        // The isolate is usable again: the termination was cleared.
        let next = rt.block_on(actor.eval(None, "1 + 2".to_string()));
        assert_eq!(next.unwrap(), json!(3));
        let health = actor.health();
        assert_eq!(health["terminated"], json!(1));
        assert_eq!(health["alive"], json!(true));
    }

    #[test]
    fn an_abandoned_eval_is_skipped() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let actor = JsActor::with_grace(None);
        rt.block_on(async {
            // First eval holds the JS thread ~300 ms; the second caller gives
            // up while queued, so its script must never run.
            let slow = actor.eval(
                None,
                "var t = Date.now(); while (Date.now() - t < 300) {} 1".to_string(),
            );
            let gone = tokio::time::timeout(
                std::time::Duration::from_millis(50),
                actor.eval(None, "2".to_string()),
            );
            let (a, b) = tokio::join!(slow, gone);
            assert_eq!(a.unwrap(), json!(1));
            assert!(b.is_err(), "the queued eval should have timed out");
            assert_eq!(actor.eval(None, "3".to_string()).await.unwrap(), json!(3));
        });
        assert_eq!(actor.health()["skipped_abandoned"], json!(1));
    }

    #[test]
    fn host_strings_reach_js_as_unicode_not_latin1() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        engine.tabs.lock().unwrap().insert(
            "u".to_string(),
            Tab::after_navigation(None, "https://example.test/", String::new(),
                "<html><body><p>x</p></body></html>".to_string()),
        );
        let js = "localStorage.setItem('k', 'n\\u00e9 \\u65e5\\u672c'); \
                  var v = localStorage.getItem('k'); [v.length, v.charCodeAt(1), v.charCodeAt(3)]";
        let r = rt
            .block_on(dispatch(&engine, "eval", json!({"tab_id": "u", "js": js})))
            .unwrap();
        assert_eq!(r["result"], json!([5, 0xe9, 0x65e5]), "{r}");
    }

    #[test]
    fn scoped_bot_detection_ignores_mentions() {
        let article = "<p>Our login flow uses arkoselabs.com and posts to /login/checkpoint.</p>\
                       <script>var cfg = {\"feed_units\":null, host: \"arkoselabs.com\"};</script>";
        // The bare form flags a page that only mentions the vendor.
        assert!(detect_bot(article).is_some());
        assert_eq!(detect_bot_scoped(article, "https://blog.example.com/a"), None);
        // A presented challenge still counts, wherever it is served.
        assert_eq!(
            detect_bot_scoped("<iframe src=\"https://client-api.arkoselabs.com/fc/\"></iframe>",
                              "https://shop.example.com/"),
            Some("arkose_enforcement")
        );
        assert_eq!(
            detect_bot_scoped("<div id=\"px-captcha\"></div>", "https://shop.example.com/"),
            Some("perimeterx_challenge")
        );
        // Facebook signatures on Facebook hosts only.
        assert_eq!(
            detect_bot_scoped("{\"feed_units\":null}", "https://www.facebook.com/marketplace/"),
            Some("empty_feed_units")
        );
        assert_eq!(detect_bot_scoped("{\"feed_units\":null}", "https://api.example.com/x"), None);
        assert_eq!(
            detect_bot_scoped("<a href=\"/login/checkpoint\">x</a>", "https://m.facebook.com/"),
            Some("login_checkpoint")
        );
    }

    #[test]
    fn binary_bodies_are_recognised() {
        assert!(is_binary_body("application/pdf", b"%PDF-1.7"));
        assert!(is_binary_body("text/html", b"%PDF-1.7 mislabeled"));
        assert!(is_binary_body("application/octet-stream", b"\x00\x01"));
        assert!(!is_binary_body("text/html; charset=utf-8", b"<html>"));
        assert!(!is_binary_body("application/ld+json", b"{}"));
        assert!(!is_binary_body("", b"<html>"));
    }

    #[test]
    fn deadline_param_is_clamped() {
        assert_eq!(deadline_param(&json!({})), None);
        assert_eq!(deadline_param(&json!({"timeout_ms": 5})),
                   Some(std::time::Duration::from_millis(100)));
        assert_eq!(deadline_param(&json!({"timeout_ms": "2500"})),
                   Some(std::time::Duration::from_millis(2500)));
    }
}

#[cfg(test)]
mod prelude_tests {
    use super::*;

    fn render(html: &str, prelude: bool) -> (RenderStats, String) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        engine.tabs.lock().unwrap().insert(
            "default".to_string(),
            Tab::after_navigation(None, "https://example.test/a/b?x=1", String::new(), html.to_string()),
        );
        let opts = JsOpts { prelude, ..JsOpts::default() };
        let stats = rt.block_on(JS_OPTS.scope(
            opts,
            engine.render_tab("default", std::time::Duration::from_millis(800)),
        ));
        let out = engine.tabs.lock().unwrap().get("default").unwrap().html.clone();
        (stats, out)
    }

    const PAGE: &str = r#"<html><head><title>t</title></head><body><div id="o"></div><script>
      var u = new URL("../c?q=caf%C3%A9&n=2#h", location.href);
      var p = new URLSearchParams("a=1&b=two+words");
      p.append("c", "x y");
      var h = new Headers({"Content-Type": "text/plain"});
      var bits = [u.pathname, u.searchParams.get("q"), u.origin, p.toString(), atob(btoa("round trip")),
                  h.get("content-type"), document.head ? document.head.tagName : "nohead"];
      window.onload = function () {
        document.getElementById("o").innerHTML = "<p id='done'>" + bits.join("|") + "</p>";
      };
    </script></body></html>"#;

    #[test]
    fn prelude_supplies_the_globals_and_fires_load() {
        let (stats, html) = render(PAGE, true);
        assert_eq!(stats.scripts, 1, "errors: {:?} {:?}", stats.errors, stats.page_errors);
        assert!(
            html.contains("/c|caf\u{e9}|https://example.test|a=1&amp;b=two+words&amp;c=x+y|round trip|text/plain|HEAD")
                || html.contains("/c|caf\u{e9}|https://example.test|a=1&b=two+words&c=x+y|round trip|text/plain|HEAD"),
            "{html}"
        );
    }

    #[test]
    fn without_the_prelude_the_same_page_fails_as_before() {
        let (stats, html) = render(PAGE, false);
        assert!(!html.contains("round trip|"), "{html}");
        assert_eq!(stats.scripts, 0);
        assert!(stats.page_errors.is_empty());
    }

    #[test]
    fn a_throwing_load_handler_is_reported_not_fatal() {
        let (stats, _) = render(
            "<html><body><script>window.addEventListener('load', function(){ console.error('boom', 7); });</script></body></html>",
            true,
        );
        assert_eq!(stats.scripts, 1);
        assert!(stats.page_errors.iter().any(|e| e.contains("boom 7")), "{:?}", stats.page_errors);
    }
}

#[cfg(test)]
mod pipeline_tests {
    use super::*;

    #[test]
    fn noncontent_hosts_are_recognised_by_host_not_by_mention() {
        assert!(noncontent_script("https://www.googletagmanager.com/gtm.js?id=X"));
        assert!(noncontent_script("https://connect.facebook.net/en_US/fbevents.js"));
        assert!(noncontent_script("https://www.google.com/recaptcha/api.js"));
        assert!(!noncontent_script("https://cdn.example.com/app.js"));
        assert!(!noncontent_script("https://example.com/vendor/googletagmanager.com.js"));
        assert!(!noncontent_script("https://www.google.com/maps/api.js"));
        assert!(!noncontent_script("not a url"));
    }
}

#[cfg(test)]
mod fetch_pool_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A server whose every answer takes 120 ms, counting how many requests
    /// were being served at once.
    fn slow_server() -> (String, Arc<AtomicUsize>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let peak = Arc::new(AtomicUsize::new(0));
        let live = Arc::new(AtomicUsize::new(0));
        let (peak2, live2) = (peak.clone(), live.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let (peak, live) = (peak2.clone(), live2.clone());
                std::thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    std::thread::sleep(std::time::Duration::from_millis(120));
                    live.fetch_sub(1, Ordering::SeqCst);
                    let body = format!("part{}", path.rsplit('/').next().unwrap_or(""));
                    let _ = stream.write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    );
                });
            }
        });
        (format!("http://{addr}"), peak)
    }

    /// The switch is process-wide (one JS thread reads it in production);
    /// tests that set it differently must not overlap.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn render(base: &str, fetch_pool: bool) -> (RenderStats, String, u128) {
        let _one = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let html = r#"<html><head><title>t</title></head><body><div id="o"></div><script>
          var jobs = [];
          for (var i = 0; i < 6; i++) { jobs.push(fetch("/api/" + i).then(function (r) { return r.text(); })); }
          Promise.all(jobs).then(function (parts) {
            document.getElementById("o").innerHTML = "<p id='done'>" + parts.join(",") + "</p>";
          });
        </script></body></html>"#;
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        engine.tabs.lock().unwrap().insert(
            "default".to_string(),
            Tab::after_navigation(None, &format!("{base}/page"), String::new(), html.to_string()),
        );
        let opts = JsOpts { prelude: true, quiesce: 3, fetch_pool, ..JsOpts::default() };
        let t0 = std::time::Instant::now();
        let stats = rt.block_on(JS_OPTS.scope(
            opts,
            engine.render_tab("default", std::time::Duration::from_millis(4000)),
        ));
        let ms = t0.elapsed().as_millis();
        let out = engine.tabs.lock().unwrap().get("default").unwrap().html.clone();
        (stats, out, ms)
    }

    const DONE: &str = "part0,part1,part2,part3,part4,part5";

    #[test]
    fn without_the_pool_six_fetches_run_one_after_another() {
        let (base, peak) = slow_server();
        let (stats, out, ms) = render(&base, false);
        assert!(out.contains(DONE), "{out} {:?}", stats.errors);
        assert_eq!(peak.load(Ordering::SeqCst), 1);
        assert!(ms >= 700, "six serial 120 ms answers took {ms} ms");
    }

    #[test]
    fn with_the_pool_six_fetches_overlap_and_settle_in_order() {
        let (base, peak) = slow_server();
        let (stats, out, ms) = render(&base, true);
        assert!(out.contains(DONE), "{out} {:?}", stats.errors);
        assert!(stats.page_errors.is_empty(), "{:?}", stats.page_errors);
        assert!(peak.load(Ordering::SeqCst) >= 4, "peak {}", peak.load(Ordering::SeqCst));
        assert!(ms < 600, "six overlapping 120 ms answers took {ms} ms");
    }

    #[test]
    fn a_failed_fetch_rejects_from_the_pump() {
        let html = r#"<html><body><div id="o"></div><script>
          fetch("http://127.0.0.1:9/nothing").then(function () {
            document.getElementById("o").innerHTML = "<p>resolved</p>";
          }, function (e) {
            document.getElementById("o").innerHTML = "<p id='r'>rejected " + String(e).slice(0, 9) + "</p>";
          });
        </script></body></html>"#;
        let rt = tokio::runtime::Runtime::new().unwrap();
        let engine = Engine::default();
        engine.tabs.lock().unwrap().insert(
            "default".to_string(),
            Tab::after_navigation(None, "http://127.0.0.1:9/page", String::new(), html.to_string()),
        );
        let opts = JsOpts { prelude: true, quiesce: 3, fetch_pool: true, ..JsOpts::default() };
        let _one = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        rt.block_on(JS_OPTS.scope(
            opts,
            engine.render_tab("default", std::time::Duration::from_millis(8000)),
        ));
        let out = engine.tabs.lock().unwrap().get("default").unwrap().html.clone();
        assert!(out.contains("rejected TypeError"), "{out}");
    }
}

#[cfg(test)]
mod livedom_tests;
#[cfg(test)]
mod modules_tests;
#[cfg(test)]
mod read_tests;
