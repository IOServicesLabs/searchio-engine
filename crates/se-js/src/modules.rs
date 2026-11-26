//! ES modules and the script code cache.
//!
//! The render harness used to run every script through indirect `eval`,
//! which has no module grammar: a `<script type="module">` page (Vite, modern
//! Vue / Svelte / Lit builds) never started. Two host functions fix that:
//!
//! * `__seRunModule(source, url)` compiles `source` as a module, loads its
//!   static import graph (each dependency fetched through the page's own
//!   network path, relative to its importer), instantiates and evaluates it,
//!   and returns the evaluation promise. `import()` goes through the same
//!   loader via the isolate's dynamic-import callback.
//! * `__seRunScript(source, url)` runs a classic script as a real Script
//!   (shared global lexical scope, one compile) and keeps V8's code cache for
//!   it keyed by URL + content hash, so the next render that meets the same
//!   bundle skips its parse and compile.
//!
//! Failures leave a JS exception pending, so the calling harness's own
//! try/catch reports them like any other script error.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use v8::{
    Context, Data, FixedArray, FunctionCallbackArguments, Local, Module, PinScope, Promise,
    ReturnValue, Value,
};

use crate::bridge::{self, State};

/// A page may not pull an unbounded graph through the one JS thread.
const MAX_MODULES: usize = 96;
const MAX_MODULE_BYTES: usize = 12 * 1024 * 1024;

struct Registry {
    by_url: HashMap<String, v8::Global<Module>>,
    /// identity hash -> (module, url): how the resolve callback learns the
    /// importer's URL.
    by_hash: HashMap<i32, Vec<(v8::Global<Module>, String)>>,
    bytes: usize,
    inline_seq: usize,
}

impl Registry {
    fn new() -> Self {
        Self {
            by_url: HashMap::new(),
            by_hash: HashMap::new(),
            bytes: 0,
            inline_seq: 0,
        }
    }
}

thread_local! {
    static REG: RefCell<Registry> = RefCell::new(Registry::new());
    static STATE: Cell<*mut State> = const { Cell::new(std::ptr::null_mut()) };
    /// `import()` promises waiting on a graph with top-level await.
    static PENDING_IMPORTS: RefCell<Vec<Option<(v8::Global<v8::PromiseResolver>, v8::Global<Value>)>>> =
        const { RefCell::new(Vec::new()) };
}

/// Scope of one eval: the module registry lives exactly as long as the
/// context it was built in.
pub(crate) struct EvalGuard;

pub(crate) fn begin(state: *mut State) -> EvalGuard {
    REG.with(|r| *r.borrow_mut() = Registry::new());
    PENDING_IMPORTS.with(|p| p.borrow_mut().clear());
    STATE.with(|s| s.set(state));
    EvalGuard
}

impl Drop for EvalGuard {
    fn drop(&mut self) {
        STATE.with(|s| s.set(std::ptr::null_mut()));
        REG.with(|r| *r.borrow_mut() = Registry::new());
        PENDING_IMPORTS.with(|p| p.borrow_mut().clear());
    }
}

fn throw<'s, 'i>(scope: &mut PinScope<'s, 'i>, msg: &str) {
    if let Some(m) = v8::String::new(scope, msg) {
        let e = v8::Exception::type_error(scope, m);
        scope.throw_exception(e);
    }
}

/// The URL a specifier names from `base`. Bare specifiers ("vue", "lodash")
/// need an import map, which this loader does not read.
fn resolve_specifier(base: &str, spec: &str) -> Result<String, String> {
    let relative = spec.starts_with("./") || spec.starts_with("../") || spec.starts_with('/');
    if !relative {
        return match url::Url::parse(spec) {
            Ok(u) if matches!(u.scheme(), "http" | "https") => Ok(u.to_string()),
            _ => Err(format!("module specifier {spec:?} is bare (no import map support)")),
        };
    }
    url::Url::parse(base)
        .and_then(|b| b.join(spec))
        .map(|u| u.to_string())
        .map_err(|e| format!("module specifier {spec:?} from {base}: {e}"))
}

fn remember<'s, 'i>(scope: &mut PinScope<'s, 'i>, url: &str, module: Local<'s, Module>, bytes: usize) {
    let g = v8::Global::new(scope, module);
    let g2 = v8::Global::new(scope, module);
    let hash = module.get_identity_hash().get();
    REG.with(|r| {
        let mut r = r.borrow_mut();
        r.by_url.insert(url.to_string(), g);
        r.by_hash.entry(hash).or_default().push((g2, url.to_string()));
        r.bytes += bytes;
    });
}

fn url_of<'s, 'i>(scope: &mut PinScope<'s, 'i>, module: Local<'s, Module>) -> Option<String> {
    let hash = module.get_identity_hash().get();
    let candidates: Vec<(v8::Global<Module>, String)> = REG.with(|r| {
        r.borrow()
            .by_hash
            .get(&hash)
            .map(|v| v.iter().map(|(g, u)| (g.clone(), u.clone())).collect())
            .unwrap_or_default()
    });
    for (g, u) in candidates {
        if Local::new(scope, &g) == module {
            return Some(u);
        }
    }
    None
}

fn compile<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    url: &str,
    code: Local<'s, v8::String>,
) -> Option<Local<'s, Module>> {
    let name = v8::String::new(scope, url)?;
    let origin = v8::ScriptOrigin::new(
        scope,
        name.into(),
        0,
        0,
        false,
        0,
        None,
        false,
        false,
        true,
        None,
    );
    let mut source = v8::script_compiler::Source::new(code, Some(&origin));
    v8::script_compiler::compile_module(scope, &mut source)
}

/// Compile `url` (fetching it unless `given` carries the source) and every
/// module it statically imports. `None` = a JS exception is pending.
fn load<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    url: &str,
    given: Option<Local<'s, v8::String>>,
) -> Option<Local<'s, Module>> {
    let known = REG.with(|r| r.borrow().by_url.get(url).cloned());
    if let Some(g) = known {
        return Some(Local::new(scope, &g));
    }
    let (count, bytes) = REG.with(|r| {
        let r = r.borrow();
        (r.by_url.len(), r.bytes)
    });
    if count >= MAX_MODULES || bytes >= MAX_MODULE_BYTES {
        throw(scope, &format!("module graph too large at {url}"));
        return None;
    }
    let (code, len) = match given {
        Some(code) => (code, code.length()),
        None => {
            let state = STATE.with(|s| s.get());
            if state.is_null() {
                throw(scope, "module loader: no page");
                return None;
            }
            let text = match bridge::fetch_text(unsafe { &mut *state }, url) {
                Ok(t) => t,
                Err(e) => {
                    throw(scope, &format!("module {url}: {e}"));
                    return None;
                }
            };
            let Some(code) = v8::String::new(scope, &text) else {
                throw(scope, &format!("module {url}: source too large"));
                return None;
            };
            (code, text.len())
        }
    };
    let module = compile(scope, url, code)?;
    // Registered BEFORE its imports load: a cycle finds it.
    remember(scope, url, module, len);
    let requests = module.get_module_requests();
    for i in 0..requests.length() {
        let Some(req) = requests.get(scope, i) else { continue };
        let Ok(req) = Local::<v8::ModuleRequest>::try_from(req) else { continue };
        let spec = req.get_specifier().to_rust_string_lossy(scope);
        let dep = match resolve_specifier(url, &spec) {
            Ok(u) => u,
            Err(e) => {
                throw(scope, &e);
                return None;
            }
        };
        load(scope, &dep, None)?;
    }
    Some(module)
}

fn resolve_cb<'s>(
    context: Local<'s, Context>,
    specifier: Local<'s, v8::String>,
    _attrs: Local<'s, FixedArray>,
    referrer: Local<'s, Module>,
) -> Option<Local<'s, Module>> {
    v8::callback_scope!(unsafe scope, context);
    let spec = specifier.to_rust_string_lossy(scope);
    let Some(base) = url_of(scope, referrer) else {
        throw(scope, &format!("module {spec:?}: unknown importer"));
        return None;
    };
    let url = match resolve_specifier(&base, &spec) {
        Ok(u) => u,
        Err(e) => {
            throw(scope, &e);
            return None;
        }
    };
    let found = REG.with(|r| r.borrow().by_url.get(&url).cloned());
    match found {
        Some(g) => Some(Local::new(scope, &g)),
        None => {
            throw(scope, &format!("module {url} was not loaded"));
            None
        }
    }
}

/// Load, link and evaluate. `None` = a JS exception is pending.
fn run<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    url: &str,
    given: Option<Local<'s, v8::String>>,
) -> Option<(Local<'s, Module>, Local<'s, Value>)> {
    let module = load(scope, url, given)?;
    if module.get_status() == v8::ModuleStatus::Uninstantiated {
        match module.instantiate_module(scope, resolve_cb) {
            Some(true) => {}
            _ => return None,
        }
    }
    if module.get_status() == v8::ModuleStatus::Errored {
        let e = module.get_exception();
        scope.throw_exception(e);
        return None;
    }
    let result = module.evaluate(scope)?;
    Some((module, result))
}

/// `__seRunModule(source | null, url | null)` -> the evaluation promise.
pub(crate) fn cb_run_module<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let source = args.get(0);
    let given = if source.is_string() {
        Local::<v8::String>::try_from(source).ok()
    } else {
        None
    };
    let key = args.get(1);
    let url = if key.is_string() {
        key.to_rust_string_lossy(scope)
    } else {
        let state = STATE.with(|s| s.get());
        let page = if state.is_null() {
            "about:blank".to_string()
        } else {
            unsafe { &*state }.page_url().to_string()
        };
        let n = REG.with(|r| {
            let mut r = r.borrow_mut();
            r.inline_seq += 1;
            r.inline_seq
        });
        // An inline module resolves its imports against the page; the
        // fragment only keeps two inline modules apart in the registry.
        match url::Url::parse(&page) {
            Ok(mut u) => {
                u.set_fragment(Some(&format!("se-inline-module-{n}")));
                u.to_string()
            }
            Err(_) => format!("{page}#se-inline-module-{n}"),
        }
    };
    if let Some((_, result)) = run(scope, &url, given) {
        // A module that threw while evaluating answers with an already
        // rejected promise: surface it as the throw it was, so the caller's
        // try/catch reports it with the other script errors.
        if let Ok(p) = Local::<Promise>::try_from(result) {
            if p.state() == v8::PromiseState::Rejected {
                let why = p.result(scope);
                p.mark_as_handled();
                scope.throw_exception(why);
                return;
            }
        }
        rv.set(result);
    }
}

/// `import(specifier)` from any script or module.
pub(crate) fn dynamic_import_cb<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    _host_defined_options: Local<'s, Data>,
    resource_name: Local<'s, Value>,
    specifier: Local<'s, v8::String>,
    _import_attributes: Local<'s, FixedArray>,
) -> Option<Local<'s, Promise>> {
    let resolver = v8::PromiseResolver::new(scope)?;
    let promise = resolver.get_promise(scope);
    let spec = specifier.to_rust_string_lossy(scope);
    let referrer = resource_name.to_rust_string_lossy(scope);
    let state = STATE.with(|s| s.get());
    let base = match url::Url::parse(&referrer) {
        Ok(u) if matches!(u.scheme(), "http" | "https") => u.to_string(),
        _ if !state.is_null() => unsafe { &*state }.page_url().to_string(),
        _ => referrer,
    };
    let url = match resolve_specifier(&base, &spec) {
        Ok(u) => u,
        Err(e) => {
            if let Some(m) = v8::String::new(scope, &e) {
                let err = v8::Exception::type_error(scope, m);
                resolver.reject(scope, err);
            }
            return Some(promise);
        }
    };
    let outcome = {
        v8::tc_scope!(tc, scope);
        match run(&mut *tc, &url, None) {
            Some((module, result)) => Ok((
                v8::Global::new(&mut *tc, module),
                v8::Global::new(&mut *tc, result),
            )),
            None => {
                let e = tc.exception().map(|e| v8::Global::new(&mut *tc, e));
                tc.reset();
                Err(e)
            }
        }
    };
    match outcome {
        Err(e) => {
            let reason: Local<Value> = match e {
                Some(g) => Local::new(scope, &g),
                None => v8::undefined(scope).into(),
            };
            resolver.reject(scope, reason);
        }
        Ok((module, result)) => {
            let module = Local::new(scope, &module);
            let result = Local::new(scope, &result);
            let ns = module.get_module_namespace();
            let settled = Local::<Promise>::try_from(result).ok();
            match settled.map(|p| (p, p.state())) {
                Some((p, v8::PromiseState::Rejected)) => {
                    let why = p.result(scope);
                    resolver.reject(scope, why);
                }
                Some((p, v8::PromiseState::Pending)) => {
                    // Top-level await somewhere in the graph: hand the
                    // namespace over when evaluation finishes.
                    let slot = PENDING_IMPORTS.with(|p| {
                        let mut p = p.borrow_mut();
                        p.push(Some((v8::Global::new(scope, resolver), v8::Global::new(scope, ns))));
                        p.len() - 1
                    });
                    let pack: Local<Value> = v8::Number::new(scope, slot as f64).into();
                    let ok = v8::Function::builder(dyn_settled_ok).data(pack).build(scope);
                    let err = v8::Function::builder(dyn_settled_err).data(pack).build(scope);
                    if let (Some(ok), Some(err)) = (ok, err) {
                        let _ = p.then2(scope, ok, err);
                    }
                }
                _ => {
                    resolver.resolve(scope, ns);
                }
            }
        }
    }
    Some(promise)
}

fn dyn_pack<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: &FunctionCallbackArguments<'s>,
) -> Option<(Local<'s, v8::PromiseResolver>, Local<'s, Value>)> {
    let slot = args.data().number_value(scope)? as usize;
    let (resolver, ns) = PENDING_IMPORTS.with(|p| p.borrow_mut().get_mut(slot).and_then(Option::take))?;
    Some((Local::new(scope, &resolver), Local::new(scope, &ns)))
}

fn dyn_settled_ok<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    _rv: ReturnValue<'s, Value>,
) {
    if let Some((resolver, ns)) = dyn_pack(scope, &args) {
        resolver.resolve(scope, ns);
    }
}

fn dyn_settled_err<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    _rv: ReturnValue<'s, Value>,
) {
    if let Some((resolver, _)) = dyn_pack(scope, &args) {
        let why = args.get(0);
        resolver.reject(scope, why);
    }
}

// ── classic scripts + code cache ────────────────────────────────────────────

/// Scripts under this size compile faster than their cache deserializes.
const CACHE_MIN_SOURCE: usize = 8 * 1024;
const CACHE_MAX_ENTRY: usize = 24 * 1024 * 1024;
const CACHE_MAX_TOTAL: usize = 128 * 1024 * 1024;

type CacheKey = (String, u64, usize);

struct CodeCache {
    entries: HashMap<CacheKey, Arc<Vec<u8>>>,
    bytes: usize,
}

fn code_cache() -> &'static Mutex<CodeCache> {
    static CACHE: OnceLock<Mutex<CodeCache>> = OnceLock::new();
    CACHE.get_or_init(|| {
        Mutex::new(CodeCache {
            entries: HashMap::new(),
            bytes: 0,
        })
    })
}

/// Where the engine's OWN scripts (keys "se:...": the prelude, the live DOM)
/// keep their code cache between processes (`SE_CODE_CACHE_DIR`). A fresh
/// engine otherwise compiles ~150 KB of its own JavaScript on its first
/// render. Page bundles stay in memory only: a disk copy of every bundle a
/// crawl meets has no bound. V8 checks version, flags and source length
/// before it accepts a cache, and the file name carries the content hash.
fn disk_dir() -> Option<&'static std::path::PathBuf> {
    static DIR: OnceLock<Option<std::path::PathBuf>> = OnceLock::new();
    DIR.get_or_init(|| {
        let d = std::env::var("SE_CODE_CACHE_DIR").ok()?;
        let d = d.trim();
        if d.is_empty() {
            return None;
        }
        let path = std::path::PathBuf::from(d);
        std::fs::create_dir_all(&path).ok()?;
        Some(path)
    })
    .as_ref()
}

fn disk_name(key: &CacheKey) -> Option<(String, String)> {
    let stem = key.0.strip_prefix("se:")?;
    if stem.is_empty() || !stem.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return None;
    }
    Some((format!("{stem}-"), format!("{stem}-{:016x}-{}.v8c", key.1, key.2)))
}

fn disk_load(key: &CacheKey) -> Option<Vec<u8>> {
    let (_, name) = disk_name(key)?;
    let bytes = std::fs::read(disk_dir()?.join(name)).ok()?;
    (!bytes.is_empty() && bytes.len() <= CACHE_MAX_ENTRY).then_some(bytes)
}

fn disk_store(key: &CacheKey, bytes: &[u8]) {
    let (Some((prefix, name)), Some(dir)) = (disk_name(key), disk_dir()) else {
        return;
    };
    // Older builds of the same script are dead weight: one file per script.
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let f = entry.file_name().to_string_lossy().to_string();
            if f.starts_with(&prefix) && f.ends_with(".v8c") && f != name {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    // Write-then-rename: a second engine never reads a half-written file.
    let tmp = dir.join(format!("{name}.{}.tmp", std::process::id()));
    if std::fs::write(&tmp, bytes).is_ok() && std::fs::rename(&tmp, dir.join(&name)).is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
}

fn disk_forget(key: &CacheKey) {
    if let (Some((_, name)), Some(dir)) = (disk_name(key), disk_dir()) {
        let _ = std::fs::remove_file(dir.join(name));
    }
}

static HITS: AtomicU64 = AtomicU64::new(0);
static MISSES: AtomicU64 = AtomicU64::new(0);
static REJECTED: AtomicU64 = AtomicU64::new(0);

/// (hits, misses, rejected, entries, bytes) of the process-wide code cache.
pub fn code_cache_stats() -> (u64, u64, u64, usize, usize) {
    let c = code_cache().lock().unwrap_or_else(|e| e.into_inner());
    (
        HITS.load(Ordering::Relaxed),
        MISSES.load(Ordering::Relaxed),
        REJECTED.load(Ordering::Relaxed),
        c.entries.len(),
        c.bytes,
    )
}

/// FNV-1a over the source: the cache key must name the CONTENT, because V8's
/// own sanity check on a code cache compares source length, not text.
fn content_hash(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// `__seRunScript(source, url | null)` -> the script's completion value.
pub(crate) fn cb_run_script<'s, 'i>(
    scope: &mut PinScope<'s, 'i>,
    args: FunctionCallbackArguments<'s>,
    mut rv: ReturnValue<'s, Value>,
) {
    let Ok(code) = Local::<v8::String>::try_from(args.get(0)) else {
        throw(scope, "__seRunScript: source must be a string");
        return;
    };
    let key = args.get(1);
    let url = key.is_string().then(|| key.to_rust_string_lossy(scope));
    let name: Local<Value> = match &url {
        Some(u) => match v8::String::new(scope, u) {
            Some(s) => s.into(),
            None => v8::undefined(scope).into(),
        },
        None => v8::undefined(scope).into(),
    };
    let origin = v8::ScriptOrigin::new(
        scope, name, 0, 0, false, 0, None, false, false, false, None,
    );
    let cache_key: Option<CacheKey> = match &url {
        Some(u) if code.length() >= CACHE_MIN_SOURCE => {
            let text = code.to_rust_string_lossy(scope);
            Some((u.clone(), content_hash(&text), text.len()))
        }
        _ => None,
    };
    let cached: Option<Arc<Vec<u8>>> = cache_key.as_ref().and_then(|k| {
        let held = code_cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entries
            .get(k)
            .cloned();
        held.or_else(|| {
            let bytes = Arc::new(disk_load(k)?);
            let mut c = code_cache().lock().unwrap_or_else(|e| e.into_inner());
            c.bytes += bytes.len();
            c.entries.insert(k.clone(), bytes.clone());
            Some(bytes)
        })
    });
    let script = match &cached {
        Some(bytes) => {
            let data = v8::script_compiler::CachedData::new(bytes);
            let mut source =
                v8::script_compiler::Source::new_with_cached_data(code, Some(&origin), data);
            let script = v8::script_compiler::compile(
                scope,
                &mut source,
                v8::script_compiler::CompileOptions::ConsumeCodeCache,
                v8::script_compiler::NoCacheReason::NoReason,
            );
            if source.get_cached_data().map(|c| c.rejected()).unwrap_or(false) {
                REJECTED.fetch_add(1, Ordering::Relaxed);
                if let Some(k) = &cache_key {
                    let mut c = code_cache().lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(old) = c.entries.remove(k) {
                        c.bytes = c.bytes.saturating_sub(old.len());
                    }
                    disk_forget(k);
                }
            } else {
                HITS.fetch_add(1, Ordering::Relaxed);
            }
            script
        }
        None => {
            let mut source = v8::script_compiler::Source::new(code, Some(&origin));
            v8::script_compiler::compile(
                scope,
                &mut source,
                v8::script_compiler::CompileOptions::NoCompileOptions,
                v8::script_compiler::NoCacheReason::NoReason,
            )
        }
    };
    let Some(script) = script else {
        return; // SyntaxError pending
    };
    let result = script.run(scope);
    if cached.is_none() {
        if let Some(k) = cache_key {
            MISSES.fetch_add(1, Ordering::Relaxed);
            // After the run: the cache then holds the functions the script
            // actually compiled, not only its top level.
            if let Some(data) = script.get_unbound_script(scope).create_code_cache() {
                let bytes: &[u8] = &data;
                if bytes.len() <= CACHE_MAX_ENTRY {
                    let mut c = code_cache().lock().unwrap_or_else(|e| e.into_inner());
                    if c.bytes + bytes.len() > CACHE_MAX_TOTAL {
                        c.entries.clear();
                        c.bytes = 0;
                    }
                    c.bytes += bytes.len();
                    disk_store(&k, bytes);
                    c.entries.insert(k, Arc::new(bytes.to_vec()));
                }
            }
        }
    }
    if let Some(v) = result {
        rv.set(v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specifiers_resolve_like_urls_and_bare_names_are_refused() {
        let base = "https://app.example/assets/main.js";
        assert_eq!(resolve_specifier(base, "./dep.js").unwrap(), "https://app.example/assets/dep.js");
        assert_eq!(resolve_specifier(base, "../x/y.js").unwrap(), "https://app.example/x/y.js");
        assert_eq!(resolve_specifier(base, "/root.js").unwrap(), "https://app.example/root.js");
        assert_eq!(
            resolve_specifier(base, "https://cdn.example/lib.js").unwrap(),
            "https://cdn.example/lib.js"
        );
        assert!(resolve_specifier(base, "vue").unwrap_err().contains("bare"));
        assert!(resolve_specifier(base, "data:text/javascript,1").is_err());
    }

    #[test]
    fn only_the_engines_own_scripts_get_a_disk_name() {
        let own = ("se:livedom".to_string(), 0xabcu64, 10usize);
        let (prefix, name) = disk_name(&own).unwrap();
        assert_eq!(prefix, "livedom-");
        assert_eq!(name, "livedom-0000000000000abc-10.v8c");
        assert!(disk_name(&("https://site.example/app.js".to_string(), 1, 1)).is_none());
        assert!(disk_name(&("se:../../x".to_string(), 1, 1)).is_none());
        assert!(disk_name(&("se:".to_string(), 1, 1)).is_none());
    }

    #[test]
    fn content_hash_separates_same_length_sources() {
        assert_ne!(content_hash("var a = 1;"), content_hash("var a = 2;"));
        assert_eq!(content_hash("x"), content_hash("x"));
    }
}
