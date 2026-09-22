//! se-net: network tier for the searchio engine.
//!
//! M2 slice 1 scope: a session-bound async client whose cookie store is the
//! single source of truth for the session — servers' Set-Cookie headers land
//! in it, the sidecar's session verbs enumerate and inject it, and every
//! request the engine makes reads it. Stealth (TLS impersonation via
//! `rquest`, header order, HTTP/2 fingerprint) lands in its own slice against
//! a live target; today's correctness bar is session semantics: cookies
//! persist across requests, redirects resolve, final URL is reported, and a
//! Playwright storage-state round-trips through the live jar.

use std::sync::{Arc, RwLock};

use reqwest::header::HeaderValue;

/// Raw-h2 ground-truth capture fixture (firing 12). `h2::hpack` is private,
/// so the capture side needs its own minimal RFC 7541 decoder; see the
/// module docs. Not public API — the bin, tests, and `scripts/capture_h2_wire.py`
/// are its consumers.
#[doc(hidden)]
pub mod h2cap;

/// The agent's WebSocket tier (firing 39): hand-rolled RFC 6455 client
/// (opening handshake, masked frame codec, fragmentation, ping/pong, close)
/// over a boxed stream, so `ws://` and `wss://` ride one code path. The
/// page-side `WebSocket` stub stays shape-only forever — the AGENT owns the
/// socket through the se-serve verbs.
pub mod ws;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The transport failure with its WHOLE cause chain flattened ("error
    /// sending request: client error (Connect): invalid peer certificate:
    /// UnknownIssuer"): reqwest's own Display stops at the first link, and
    /// a caller could not tell a bad certificate from a dead host
    /// (searchio bug 157). Nothing downstream matches on the inner
    /// reqwest::Error, so the text is what is kept.
    #[error("request failed: {0}")]
    Http(String),
    #[error("subresource runtime: {0}")]
    Runtime(#[from] std::io::Error),
    #[error("subresource fetch failed: {0}")]
    Subresource(String),
    #[error("invalid url: {0}")]
    BadUrl(String),
    #[error("websocket: {0}")]
    Ws(String),
    /// Body refused for size, counted on the DECODED bytes. A gzip bomb is
    /// kilobytes on the wire and gigabytes in memory -- the shape that must
    /// never materialize. The `too_large:` prefix is contractual: searchio's
    /// span suite asserts the token rides the error all the way out through
    /// se-serve's fetch arm.
    #[error("too_large: {0}")]
    TooLarge(String),
    /// Fetch/redirect target refused by policy: a non-http(s) scheme or a
    /// link-local/unspecified IP literal (169.254.169.254 is the cloud
    /// metadata endpoint, the canonical SSRF shape). Bug 25 -- every stack's
    /// auto-follow chased such a Location before this guard existed. The
    /// `target_refused:` prefix is contractual for span, same as too_large.
    #[error("target_refused: {0}")]
    TargetRefused(String),
    /// A client-side redirect chain (meta refresh) that never settles. The
    /// `redirect_loop:` token matches what reqwest's own policy produces for
    /// an HTTP loop, so searchio's span suite and tier loop treat both the
    /// same. Iteration 25.
    #[error("redirect_loop: {0}")]
    RedirectLoop(String),
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        // A redirect-policy refusal arrives wrapped in reqwest's generic
        // "error following redirect" kind -- the policy's message lives in
        // the SOURCE chain, invisible to Display. The token is contractual
        // (span asserts it rides out through se-serve's fetch arm, and
        // searchio's tier loop keys on it for the no-climb rule), so promote
        // it to the typed variant instead of letting it drown as
        // "request failed".
        let mut src = std::error::Error::source(&err);
        while let Some(e) = src {
            let msg = e.to_string();
            if let Some(why) = msg.strip_prefix("target_refused: ") {
                return Error::TargetRefused(why.to_string());
            }
            src = e.source();
        }
        Error::Http(error_chain(&err))
    }
}

/// Every Display in an error's source chain, outermost first, joined with
/// ": " and de-duplicated when a link merely repeats its parent.
pub fn error_chain(err: &dyn std::error::Error) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut cur: Option<&dyn std::error::Error> = Some(err);
    while let Some(e) = cur {
        let msg = e.to_string();
        if parts.last().map_or(true, |p| p != &msg) {
            parts.push(msg);
        }
        cur = e.source();
    }
    parts.join(": ")
}

/// Hard caps on response bodies, counted on DECODED bytes. Documents share
/// the data cap; subresources get headroom for real-world JS bundles; images
/// more, since read_image serves the bytes themselves. Over the cap is an
/// honest refusal, never a silent truncation. The document number was 4 MiB
/// until vinted's SSR catalog (7.2 MB of inlined Nuxt state) refused live:
/// the browser tier is precisely where big documents are expected, and
/// searchio's PDF path already trusts 25 MiB -- HTML pages outgrow PDFs on
/// the modern web. Bomb safety is the cap's shape (decoded bytes, enforced
/// on the stream), not its size.
pub const MAX_DOCUMENT_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_SUBRESOURCE_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_IMAGE_BYTES: u64 = 32 * 1024 * 1024;

/// The address classes no fetch may dial, `None` when allowed.
///
/// Shared by the URL-literal guard (`refused_target`) and the connect-time
/// resolver guard (`GuardedResolver`): an IPv4-mapped IPv6 address is
/// unwrapped first, link-local (169.254/16, fe80::/10 -- std's
/// `is_unicast_link_local` is unstable, so the v6 prefix test is by hand) is
/// the cloud-metadata SSRF class, and unspecified (0.0.0.0, ::) is not a
/// routable destination. Loopback and RFC1918 stay allowed -- the suite runs
/// on 127.0.0.1 and intranet targets are legitimate.
pub fn refused_ip(ip: std::net::IpAddr) -> Option<String> {
    let v4 = match ip {
        std::net::IpAddr::V4(v4) => v4,
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(mapped) => mapped,
            None => {
                if v6.is_unspecified() {
                    return Some(format!("unspecified:{v6}"));
                }
                if v6.segments()[0] & 0xffc0 == 0xfe80 {
                    return Some(format!("link_local:{v6}"));
                }
                return None;
            }
        },
    };
    if v4.is_link_local() {
        return Some(format!("link_local:{v4}"));
    }
    if v4.is_unspecified() {
        return Some(format!("unspecified:{v4}"));
    }
    None
}

/// Policy refusal for a fetch or redirect target, `None` when allowed.
///
/// Two classes are never fetched: non-http(s) schemes, and IP literals in a
/// refused class (see `refused_ip`) -- 169.254.169.254 (the cloud metadata
/// endpoint) is the canonical SSRF shape. Hostnames pass the literal check:
/// a name that DNS-points at a refused address slips through HERE, which is
/// why every client's resolver vets the answers at connect time (bug 27 --
/// `GuardedResolver`).
pub fn refused_target(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Some(format!("scheme:{}", parsed.scheme()));
    }
    match parsed.host()? {
        url::Host::Ipv4(v4) => refused_ip(std::net::IpAddr::V4(v4)),
        url::Host::Ipv6(v6) => refused_ip(std::net::IpAddr::V6(v6)),
        url::Host::Domain(_) => None,
    }
}

/// The redirect policy for the document client: the pre-guard default
/// (`limited(10)`), plus the target guard on every hop. Auto-follow was the
/// bug-25 hole -- reqwest chased a Location to 169.254.169.254 like any
/// other. The hop cap mirrors `Policy::limited(10)` EXACTLY: `previous`
/// includes the initial URL, and exceeding the cap errors (TooManyRedirects
/// shape) rather than surfacing the 30x -- the span suite's redirect-loop
/// control pins both the budget and the error shape.
fn redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if let Some(why) = refused_target(attempt.url().as_str()) {
            attempt.error(format!("target_refused: {why}"))
        } else if attempt.previous().len() > 10 {
            attempt.error("too many redirects")
        } else {
            attempt.follow()
        }
    })
}

/// The system-lookup seam inside `GuardedResolver`: given a hostname,
/// produce the candidate addresses. Production resolves with
/// `tokio::net::lookup_host`; wire tests script the answers (a refused
/// class, a loopback answer) without depending on real DNS.
type DnsLookup = Arc<
    dyn Fn(&str) -> std::pin::Pin<
            Box<dyn std::future::Future<
                    Output = std::io::Result<Vec<std::net::SocketAddr>>,
                > + Send>,
        > + Send
        + Sync,
>;

/// DNS resolution with the refused-answer guard (bug 27).
///
/// A HOSTNAME's address exists only after resolution, so the URL-literal
/// guard never saw a rebound name -- a name pointing at 169.254.169.254 was
/// dialed by every tier. Here every lookup answer passes `refused_ip`
/// BEFORE the dial, and ANY refused answer poisons the whole set (a legit
/// name never answers link-local), erroring with the contractual
/// `target_refused:` token the `From<reqwest::Error>` source-chain walk
/// promotes to the typed variant. reqwest dials exactly the addresses this
/// returns, so the dial observes no second resolution -- no TOCTOU window.
pub struct GuardedResolver {
    lookup: DnsLookup,
}

impl GuardedResolver {
    /// Production resolver: the system lookup via tokio. Port 0 is a
    /// placeholder -- reqwest overrides resolved ports with the URL's
    /// explicit port (or the scheme default).
    pub fn system() -> Arc<Self> {
        Arc::new(Self {
            lookup: Arc::new(|host| {
                let host = host.to_string();
                Box::pin(async move {
                    Ok(tokio::net::lookup_host((host.as_str(), 0))
                        .await?
                        .collect())
                })
            }),
        })
    }

    /// Test seam: script the answers a lookup produces.
    #[cfg(test)]
    pub(crate) fn with_lookup(lookup: DnsLookup) -> Arc<Self> {
        Arc::new(Self { lookup })
    }
}

impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let lookup = self.lookup.clone();
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs = (lookup)(&host).await?;
            let mut out: Vec<std::net::SocketAddr> = Vec::with_capacity(addrs.len());
            for addr in addrs {
                if let Some(why) = refused_ip(addr.ip()) {
                    return Err(format!("target_refused: dns:{host} -> {why}").into());
                }
                out.push(addr);
            }
            Ok(Box::new(out.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// The flavor of a data call (firing 38): an agent's `fetch()`-shaped call
/// answers CORS mode/empty dest; an image load answers no-cors/image with
/// Chrome's image `Accept`. Both share the session jar and fingerprint block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataKind {
    /// fetch/XHR-shaped data call (`Sec-Fetch-Mode: cors`,
    /// `Sec-Fetch-Dest: empty`, `Accept: */*`).
    Data,
    /// `<img>`-shaped load (`Sec-Fetch-Mode: no-cors`,
    /// `Sec-Fetch-Dest: image`, Chrome's image Accept) — the `read_image`
    /// verb's wire presentation.
    Image,
}

#[derive(Debug, Clone)]
pub struct Response {
    pub final_url: String,
    pub status: u16,
    /// Negotiated protocol version ("HTTP/1.1" / "HTTP/2.0"). A real Chrome
    /// speaks h2 everywhere; h1.1 to an h2-capable edge is an ALPN-level
    /// fingerprint tell, so the sidecar reports it on every document load.
    pub version: String,
    /// Response headers as received, lowercased names — the shape the
    /// page-context `fetch` shim hands back as a `Headers`-like object.
    pub headers: Vec<(String, String)>,
    pub body: String,
    /// Raw response bytes, untouched by UTF-8 interpretation. `body` is the
    /// lossy text view the document/data tiers consume; binary payloads
    /// (read_image's container sniff) need these — a lossy round trip
    /// corrupts magic bytes.
    pub body_bytes: Vec<u8>,
}

/// The `charset=...` parameter of a content-type value (or of a `<meta>` tag
/// seen as one), as raw label bytes. Handles the real-world variations:
/// quoted, spaced, first or later parameter, and the legacy
/// `http-equiv="content-type" content="text/html; charset=..."` form.
fn charset_label(s: &str) -> Option<Vec<u8>> {
    let lower = s.to_ascii_lowercase();
    let at = lower.find("charset")?;
    let rest = lower[at + "charset".len()..].trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    let label = rest
        .trim_start_matches(|c| c == '"' || c == '\'')
        .split(|c| matches!(c, ';' | ' ' | '\t' | '"' | '\'' | '>'))
        .next()
        .unwrap_or("")
        .trim();
    if label.is_empty() {
        None
    } else {
        Some(label.as_bytes().to_vec())
    }
}

/// WHATWG's meta-charset prescan, simplified: the first 1024 bytes scanned
/// ASCII-case-insensitively for a `<meta` tag carrying a charset. Charset
/// labels are ASCII and the legacy encodings this rescues are ASCII-compatible
/// in the markup region, so a lossy view of the head is safe to scan. Every
/// browser has done this since the HTML5 spec; reqwest deliberately does not.
fn sniff_meta_charset(bytes: &[u8]) -> Option<&'static encoding_rs::Encoding> {
    let head = &bytes[..bytes.len().min(1024)];
    let text = String::from_utf8_lossy(head).into_owned().to_ascii_lowercase();
    let mut rest = text.as_str();
    while let Some(m) = rest.find("<meta") {
        let tag = &rest[m..];
        let tag_end = tag.find('>').unwrap_or(tag.len());
        if let Some(label) = charset_label(&tag[..tag_end]) {
            if let Some(enc) = encoding_rs::Encoding::for_label(&label) {
                return Some(enc);
            }
        }
        rest = &rest[m + tag_end..];
    }
    None
}

/// Decode a response body the way a browser does: the content-type header's
/// charset wins; HTML without one gets the meta prescan; UTF-8 with lossy
/// replacement is the fallback. Decoding every body as lossy UTF-8 was the
/// Shift_JIS mojibake bug — searchio's bench/span.py ctl.charset_shift_jis
/// caught 156 U+FFFD and a lost marker on a header-declared page at tier 2.
fn decode_body(bytes: &[u8], headers: &[(String, String)]) -> String {
    let ctype = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    if let Some(label) = charset_label(ctype) {
        if let Some(enc) = encoding_rs::Encoding::for_label(&label) {
            return enc.decode(bytes).0.into_owned();
        }
    }
    if ctype.to_ascii_lowercase().contains("html") {
        if let Some(enc) = sniff_meta_charset(bytes) {
            return enc.decode(bytes).0.into_owned();
        }
    }
    String::from_utf8_lossy(bytes).into_owned()
}

/// Client-side navigation (iteration 25): a `<meta http-equiv="refresh"
/// content="0; url=...">` in a 200 HTML head is a redirect the server never
/// sent -- the squeeze/parked/affiliate-interstitial class routes through it,
/// and a stack that ignores the tag serves the interstitial as content. The
/// contract mirrors searchio's ladder EXACTLY (bench/span.py control rows
/// 100-118 pin both stacks over the wire):
///
/// * only a 200 whose content-type carries "html" navigates -- a JSON body
///   whose text holds a refresh-looking string is data, not a page;
/// * the tag must live in the head window (first 64 KiB);
/// * the FIRST refresh tag decides, even a broken one (Chrome's rule --
///   scanning on to the first *followable* tag would hop where a browser
///   would not);
/// * a delay over 5 s is served as-is -- that interstitial IS the document;
///   at or under it the hop is followed immediately (a search engine never
///   sleeps for a redirect; Google treats an instant refresh as 301-class);
/// * no `url=` is a self-reload (the polling pattern): a no-op;
/// * the target resolves against the document's final URL.
const META_REFRESH_MAX_HOPS: u32 = 10; // mirrors the HTTP redirect budget
const META_REFRESH_MAX_DELAY_S: f64 = 5.0;
const META_HEAD_BYTES: usize = 64 * 1024;

/// One attribute's value from a meta tag: double-quoted, single-quoted, or
/// bare; the name matches ASCII-case-insensitively, the value keeps its case
/// (URL paths are case-sensitive). Scans a lowercased copy and slices the
/// original at the same byte offsets -- to_ascii_lowercase never changes
/// length, and the offsets only ever land on ASCII bytes.
fn meta_attr(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let lb = lower.as_bytes();
    let mut m = 0usize;
    while let Some(found) = lower[m..].find(name) {
        let at = m + found;
        let before_ok = at == 0 || lb[at - 1].is_ascii_whitespace();
        let mut j = at + name.len();
        while j < lb.len() && lb[j].is_ascii_whitespace() {
            j += 1;
        }
        if before_ok && j < lb.len() && lb[j] == b'=' {
            j += 1;
            while j < lb.len() && lb[j].is_ascii_whitespace() {
                j += 1;
            }
            let (vs, ve) = if j < lb.len() && (lb[j] == b'"' || lb[j] == b'\'') {
                let q = lb[j];
                let vs = j + 1;
                let mut ve = vs;
                while ve < lb.len() && lb[ve] != q {
                    ve += 1;
                }
                (vs, ve)
            } else {
                let vs = j;
                let mut ve = vs;
                while ve < lb.len() && !lb[ve].is_ascii_whitespace() && lb[ve] != b'>' {
                    ve += 1;
                }
                (vs, ve)
            };
            return Some(tag[vs..ve].to_string());
        }
        m = at + name.len();
    }
    None
}

/// WHATWG-lenient parse of a refresh content attribute: a leading float
/// delay, an optional `;`/`,` separator, an optional case-insensitive `url=`
/// prefix, then the URL under any quoting. Returns the delay and the raw
/// target -- `None` target means a bare-delay self-reload; `None` overall
/// means unparseable.
fn parse_refresh_content(content: &str) -> Option<(f64, Option<String>)> {
    let s = content.trim_start();
    let bytes = s.as_bytes();
    let mut end = 0;
    while end < bytes.len() && (bytes[end].is_ascii_digit() || bytes[end] == b'.') {
        end += 1;
    }
    let delay: f64 = s[..end].parse().ok()?;
    let rest = s[end..].trim_start();
    if rest.is_empty() {
        return Some((delay, None));
    }
    let rest = rest
        .strip_prefix(';')
        .or_else(|| rest.strip_prefix(','))?
        .trim_start();
    let lower = rest.to_ascii_lowercase();
    let raw = if let Some(r) = lower.strip_prefix("url") {
        let t = r.trim_start();
        if t.starts_with('=') {
            // Same-length lowercasing: the offset into `rest` is exact.
            rest[rest.len() - t.len() + 1..].trim()
        } else {
            // "url" not followed by '=' -> the remainder IS the target.
            rest.trim()
        }
    } else {
        rest.trim()
    };
    let raw = {
        let b = raw.as_bytes();
        if raw.len() >= 2 && (b[0] == b'"' || b[0] == b'\'') && b[raw.len() - 1] == b[0] {
            raw[1..raw.len() - 1].trim()
        } else {
            raw
        }
    };
    if raw.is_empty() {
        return Some((delay, None));
    }
    Some((delay, Some(raw.to_string())))
}

/// The navigation a document's first meta-refresh tag asks for -- the
/// absolute target, or `None` when the document is served as-is.
fn meta_refresh_target(res: &Response) -> Option<String> {
    if res.status != 200 {
        return None;
    }
    let ctype = res
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    if !ctype.to_ascii_lowercase().contains("html") {
        return None;
    }
    // Char-boundary-safe head window: if 64 KiB lands mid-character, scan
    // the whole body rather than panic (the tag is not near the cut anyway).
    let head = res.body.get(..META_HEAD_BYTES).unwrap_or(&res.body);
    let lower = head.to_ascii_lowercase();
    let mut rest = lower.as_str();
    let mut off = 0usize; // byte offset of `rest` within head (== lower)
    while let Some(m) = rest.find("<meta") {
        let tag_rel = &rest[m..];
        let tag_len = tag_rel.find('>').map(|e| e + 1).unwrap_or(tag_rel.len());
        // Slice the ORIGINAL head so attribute values keep their case.
        let tag = &head[off + m..off + m + tag_len];
        let is_refresh = meta_attr(tag, "http-equiv")
            .map(|e| e.trim().eq_ignore_ascii_case("refresh"))
            .unwrap_or(false);
        if is_refresh {
            // The FIRST refresh tag decides -- a broken one included.
            let content = meta_attr(tag, "content")?;
            let (delay, raw) = parse_refresh_content(&content)?;
            let raw = raw?; // bare delay = self-reload -> no-op
            if delay > META_REFRESH_MAX_DELAY_S {
                return None;
            }
            let base = url::Url::parse(&res.final_url).ok()?;
            return Some(base.join(&raw).ok()?.to_string());
        }
        off += m + tag_len;
        rest = &rest[m + tag_len..];
    }
    None
}

/// Read a response body with a hard cap on the DECODED bytes.
///
/// Replaces `res.bytes()`, which reads the whole body into memory with no
/// bound -- fine until an origin answers with a 6 MB "page" or a 10 KB
/// gzip stream that inflates to gigabytes (searchio span-suite iteration 18:
/// every tier read unbounded; the Python tiers cap at the same size class).
/// With no content-encoding the wire length IS the decoded length, so an
/// over-cap Content-Length refuses before a single body byte is read;
/// compressed bodies decode larger than the wire, so their cap is enforced
/// on the streamed total. Over the cap is an honest `too_large` refusal,
/// never a silent truncation -- a prefix of a page is not the page.
async fn read_body_capped(
    mut res: reqwest::Response,
    cap: u64,
    what: &str,
) -> Result<Vec<u8>, Error> {
    let encoded = res
        .headers()
        .get(reqwest::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            let v = v.to_ascii_lowercase();
            !(v.is_empty() || v == "identity")
        })
        .unwrap_or(false);
    if !encoded {
        if let Some(len) = res.content_length() {
            if len > cap {
                return Err(Error::TooLarge(format!(
                    "{what}: content-length {len} exceeds cap {cap}"
                )));
            }
        }
    }
    let mut buf = Vec::new();
    while let Some(chunk) = res.chunk().await? {
        if buf.len() as u64 + chunk.len() as u64 > cap {
            return Err(Error::TooLarge(format!(
                "{what}: decoded body exceeds cap {cap}"
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// One cookie in the Playwright storage-state shape, so the sidecar's
/// `cookies_get`/`storage_state_set` round-trip through Python without
/// translation. `expires` is unix seconds; `None` (or non-positive) is a
/// session cookie. `same_site` is the raw SameSite attribute value
/// ("Lax"/"Strict"/"None"); `None` means the server sent no attribute —
/// Chromium treats that as Lax-by-default, which is a wire-shape decision
/// for the sidecar, not this struct. `domain` carries no leading dot;
/// `host_only` is the CDP-style companion flag — Playwright's artifact
/// encodes it AS the leading dot on export, but keeping it explicit here
/// preserves scoping exactly across a set→get round trip (a host-only
/// cookie must not come back scoped to an entire domain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieEntry {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub http_only: bool,
    pub expires: Option<i64>,
    pub same_site: Option<String>,
    pub host_only: bool,
}

impl CookieEntry {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            domain: String::new(),
            path: "/".to_string(),
            secure: false,
            http_only: false,
            expires: None,
            same_site: None,
            host_only: false,
        }
    }
}

/// The live session cookie store. Implements reqwest's `CookieStore` so
/// response cookies land here on every request, and adds enumeration plus
/// Playwright-shaped injection for the sidecar's session verbs — the two
/// things reqwest's opaque `Jar` does not expose.
#[derive(Debug, Default)]
pub struct SessionStore {
    inner: RwLock<cookie_store::CookieStore>,
}

impl SessionStore {
    /// All unexpired cookies, in Playwright shape.
    pub fn snapshot(&self) -> Vec<CookieEntry> {
        self.inner
            .read()
            .expect("cookie store lock")
            .iter_unexpired()
            .map(|c| {
                let expires = match c.expires {
                    cookie_store::CookieExpiration::AtUtc(dt) => Some(dt.unix_timestamp()),
                    cookie_store::CookieExpiration::SessionEnd => None,
                };
                let (domain, host_only) = match &c.domain {
                    cookie_store::CookieDomain::HostOnly(h) => (h.clone(), true),
                    cookie_store::CookieDomain::Suffix(d) => (d.clone(), false),
                    // Empty/NotPresent: nothing meaningful to export.
                    _ => (String::new(), true),
                };
                CookieEntry {
                    name: c.name().to_string(),
                    value: c.value().to_string(),
                    domain,
                    path: c.path().unwrap_or("/").to_string(),
                    secure: c.secure().unwrap_or(false),
                    http_only: c.http_only().unwrap_or(false),
                    expires,
                    same_site: c.same_site().map(|s| s.to_string()),
                    host_only,
                }
            })
            .collect()
    }

    pub fn clear(&self) {
        self.inner.write().expect("cookie store lock").clear();
    }

    /// Inject one Playwright-shaped cookie into the store. Returns false if
    /// the entry is unusable (empty name, unparsable domain).
    pub fn insert_entry(&self, e: &CookieEntry) -> bool {
        if e.name.is_empty() {
            return false;
        }
        let mut b = cookie::Cookie::build((e.name.as_str(), e.value.as_str()))
            .path(e.path.clone());
        if !e.domain.is_empty() && !e.host_only {
            // A host-only entry must NOT get a Domain attribute — that would
            // widen its scope to the whole domain on the way back in. The
            // request URL below still associates it with the right host.
            b = b.domain(e.domain.clone());
        }
        if e.secure {
            b = b.secure(true);
        }
        if e.http_only {
            b = b.http_only(true);
        }
        if let Some(secs) = e.expires.filter(|s| *s > 0) {
            if let Ok(dt) = cookie::time::OffsetDateTime::from_unix_timestamp(secs) {
                b = b.expires(dt);
            }
        }
        if let Some(ss) = &e.same_site {
            let v = match ss.as_str() {
                "Strict" => cookie::SameSite::Strict,
                "None" => cookie::SameSite::None,
                // "Lax" and anything unmapped: the attribute's default posture.
                _ => cookie::SameSite::Lax,
            };
            b = b.same_site(v);
        }
        let raw = b.build();
        // `insert_raw` validates the Domain attribute against a request URL;
        // derive one from the cookie's own domain so host-only and domain
        // cookies both land.
        let host = e.domain.trim_start_matches('.');
        if host.is_empty() {
            return false;
        }
        let url = match url::Url::parse(&format!("http://{host}/")) {
            Ok(u) => u,
            Err(_) => return false,
        };
        self.inner
            .write()
            .expect("cookie store lock")
            .insert_raw(&raw, &url)
            .is_ok()
    }

    /// Add a raw `Set-Cookie` string (the shape `jar.add_cookie_str` took).
    pub fn add_cookie_str(&self, cookie_str: &str, url: &url::Url) {
        let parsed = cookie::Cookie::parse(cookie_str).ok().map(|c| c.into_owned());
        if let Some(c) = parsed {
            self.inner
                .write()
                .expect("cookie store lock")
                .store_response_cookies(std::iter::once(c), url);
        }
    }

    /// The `Cookie` header value (`a=1; b=2`) the jar would present on a
    /// request to `url` — `None` when nothing matches. This is the hook the
    /// page-context fetch/XHR tier uses to send the session the way a
    /// browser's document request would; the store's own domain/path rules
    /// decide what matches, so a cross-origin request can't pull another
    /// origin's cookies.
    pub fn cookie_header(&self, url: &str) -> Option<String> {
        let u = url::Url::parse(url).ok()?;
        <Self as reqwest::cookie::CookieStore>::cookies(self, &u)
            .and_then(|hv| hv.to_str().ok().map(String::from))
    }

    /// String-URL form of `add_cookie_str` for tiers that hold the URL as
    /// text. Silently drops unparsable URLs and malformed cookies — a
    /// misbehaving response must not break the request path.
    pub fn store_set_cookie(&self, set_cookie: &str, url: &str) {
        if let Ok(u) = url::Url::parse(url) {
            self.add_cookie_str(set_cookie, &u);
        }
    }

    /// The `document.cookie` string for `url`: the cookies that would ride
    /// a request here MINUS the httpOnly ones (those are wire-only, invisible
    /// to page JS), joined as `a=1; b=2`. `None` when nothing visible
    /// matches. Two passes over the store: `get_request_values` owns the
    /// domain/path matching rules, then the metadata pass filters httpOnly
    /// by name — name collisions across domains drop invisibly, which is
    /// acceptable for a visibility surface.
    pub fn document_cookie(&self, url: &str) -> Option<String> {
        let u = url::Url::parse(url).ok()?;
        let visible: std::collections::HashSet<String> = self
            .inner
            .read()
            .expect("cookie store lock")
            .iter_unexpired()
            .filter(|c| !c.http_only().unwrap_or(false))
            .map(|c| c.name().to_string())
            .collect();
        let s = self
            .inner
            .read()
            .expect("cookie store lock")
            .get_request_values(&u)
            .filter(|(name, _)| visible.iter().any(|v| v == name))
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }
}

impl reqwest::cookie::CookieStore for SessionStore {
    fn set_cookies(&self, cookie_headers: &mut dyn Iterator<Item = &HeaderValue>, url: &url::Url) {
        let iter = cookie_headers
            .filter_map(|v| std::str::from_utf8(v.as_bytes()).ok())
            .filter_map(|s| cookie::Cookie::parse(s).ok().map(|c| c.into_owned()));
        self.inner
            .write()
            .expect("cookie store lock")
            .store_response_cookies(iter, url);
    }

    fn cookies(&self, url: &url::Url) -> Option<HeaderValue> {
        let s = self
            .inner
            .read()
            .expect("cookie store lock")
            .get_request_values(url)
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        if s.is_empty() {
            return None;
        }
        HeaderValue::from_str(&s).ok()
    }
}

/// One `Client` per browsing session: owns the store the sidecar's
/// `cookies_get`/`storage_state_set`/`session_reset` verbs read and write,
/// and presents the session's fingerprint on every request.
#[derive(Clone)]
pub struct Client {
    inner: reqwest::Client,
    store: Arc<SessionStore>,
    /// The session fingerprint UA, kept so `navigate` can place it inside
    /// the hand-ordered header block (see `document_headers`).
    ua: String,
}

/// Client-hint identity — the ONE source of truth for both the wire headers
/// (`Sec-CH-UA*`) and the JS tier's `navigator.userAgentData`. The two
/// surfaces must agree exactly; a mismatch between what the server sees and
/// what the page reads is itself a bot signal. Values describe the same
/// desktop Chrome 145 on Windows that `se_js::bridge::USER_AGENT` names.
pub const CHROME_BRANDS: [(&str, &str); 3] = [
    ("Chromium", "145"),
    ("Google Chrome", "145"),
    ("Not.A/Brand", "99"),
];
pub const UA_PLATFORM: &str = "Windows";
/// Windows NT 10.0 in the UA pairs with platformVersion "10.0.0" (Chrome
/// reports Windows 11 as NT 10.0 too but raises the platformVersion).
pub const UA_PLATFORM_VERSION: &str = "10.0.0";
pub const UA_FULL_VERSION: &str = "145.0.0.0";
pub const UA_ARCHITECTURE: &str = "x86";
pub const UA_BITNESS: &str = "64";

/// One completed network hop, as the `network_log` verb reports it. `kind`
/// is `"document"` for tab navigations, `"fetch"` / `"xhr"` for page-context
/// subresources. Only COMPLETED hops are logged — a transport failure
/// rejects the caller's fetch promise with the error, which is the
/// observable the caller needs; the log answers "what did the session
/// touch", not "what did the session attempt".
#[derive(Clone, Debug)]
pub struct NetLogEntry {
    pub seq: u64,
    pub kind: String,
    pub method: String,
    pub url: String,
    pub status: u16,
    pub elapsed_ms: u64,
}

/// Ring of the last [`NET_LOG_CAP`] completed hops, session-scoped. The
/// engine owns one `Arc` and both record sites — document navigations in
/// se-serve, page-context fetch/XHR hops in the JS bridge — append to it.
/// `seq` is a lamport clock: monotonic across `clear` (a reset session
/// keeps its numbering), assigned at record time so concurrent recorders
/// never collide.
#[derive(Default)]
pub struct NetLog {
    inner: std::sync::Mutex<std::collections::VecDeque<NetLogEntry>>,
    next_seq: std::sync::atomic::AtomicU64,
}

/// How many hops the log retains; older entries fall off the front.
pub const NET_LOG_CAP: usize = 256;

impl NetLog {
    pub fn record(
        &self,
        kind: &str,
        method: &str,
        url: &str,
        status: u16,
        elapsed: std::time::Duration,
    ) {
        let seq = self
            .next_seq
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let entry = NetLogEntry {
            seq,
            kind: kind.to_string(),
            method: method.to_string(),
            url: url.to_string(),
            status,
            elapsed_ms: elapsed.as_millis() as u64,
        };
        let mut q = self.inner.lock().expect("net log lock");
        if q.len() >= NET_LOG_CAP {
            q.pop_front();
        }
        q.push_back(entry);
    }

    /// Entries in arrival order, oldest first.
    pub fn snapshot(&self) -> Vec<NetLogEntry> {
        self.inner
            .lock()
            .expect("net log lock")
            .iter()
            .cloned()
            .collect()
    }

    pub fn clear(&self) {
        self.inner.lock().expect("net log lock").clear();
    }
}

/// The `Sec-CH-UA` header value built from [`CHROME_BRANDS`].
pub fn sec_ch_ua() -> String {    CHROME_BRANDS
        .iter()
        .map(|(b, v)| format!("\"{b}\";v=\"{v}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The `scheme://host[:port]` prefix. `Url::port` reports None for default
/// ports (the URL crate normalizes them away), so both sides compare equal
/// whether or not the default was spelled out.
fn origin_of(u: &url::Url) -> String {
    let scheme = u.scheme();
    match (u.host_str(), u.port()) {
        (Some(h), Some(p)) => format!("{scheme}://{h}:{p}"),
        (Some(h), None) => format!("{scheme}://{h}"),
        _ => String::new(),
    }
}

/// Headers h2 forbids on the wire and proxies own on h1.1 — never forward.
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "transfer-encoding"
            | "upgrade"
            | "te"
            | "trailer"
    )
}

/// One page-context subresource request over TLS with ALPN — the engine's
/// counterpart to a real Chrome page fetch reusing its negotiated h2
/// connection. Unlike [`Client::get`] this is a one-shot: no cookie provider
/// (the page-context layer owns the jar), redirects disabled (the caller
/// follows per the fetch spec), fresh `current_thread` runtime created AND
/// dropped inside the call on the caller's own thread.
///
/// That last point is the whole design: the bridge's fetch shim runs on a
/// spawned thread outside V8 (driving tokio from an isolate callback
/// deadlocked on this platform), so owning a short-lived runtime here is
/// safe and leaks nothing into the isolate thread. The negotiated version is
/// reported honestly — h2 when ALPN picks it, h1.1 when the origin declines,
/// exactly the fork a real browser takes per origin.
///
/// `danger_accept_invalid_host_certs` exists for the test tier only (a
/// loopback TLS fixture with a self-signed cert); the engine's production
/// path always passes false.
pub fn subresource_fetch(
    url: &str,
    method: &str,
    headers: &[(String, String)],
    body: &str,
    danger_accept_invalid_host_certs: bool,
) -> Result<Response, Error> {
    if !url.starts_with("https://") {
        return Err(Error::Subresource(
            "subresource_fetch is https-only; the caller serves http itself".into(),
        ));
    }
    // The entry guard the document client has always had (bug 25) was
    // MISSING here -- found designing iteration 21's connect-time guard: a
    // link-local literal subresource URL dialed the refused target outright.
    if let Some(why) = refused_target(url) {
        return Err(Error::TargetRefused(format!("{why} ({url})")));
    }
    let headers: Vec<(String, String)> = headers
        .iter()
        .filter(|(n, _)| !is_hop_by_hop(n))
        .cloned()
        .collect();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(subresource_fetch_inner(
        url,
        method,
        &headers,
        body,
        danger_accept_invalid_host_certs,
    ))
}

async fn subresource_fetch_inner(
    url: &str,
    method: &str,
    headers: &[(String, String)],
    body: &str,
    danger_accept_invalid_host_certs: bool,
) -> Result<Response, Error> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(false)
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        // Same connect-time guard as the document client (bug 27): a
        // hostname's answers are vetted before the dial.
        .dns_resolver(GuardedResolver::system())
        // No idle keepalive: the client (and its connections) must be fully
        // gone when the runtime drops at the end of this call.
        .pool_max_idle_per_host(0);
    if danger_accept_invalid_host_certs {
        builder = builder.danger_accept_invalid_certs(true);
    }
    let client = builder.build()?;
    let method = reqwest::Method::from_bytes(method.as_bytes())
        .map_err(|e| Error::Subresource(format!("bad method {method:?}: {e}")))?;
    let mut req = client.request(method, url);
    let mut map = reqwest::header::HeaderMap::new();
    for (name, value) in headers {
        let (Ok(n), Ok(v)) = (
            reqwest::header::HeaderName::from_bytes(name.to_ascii_lowercase().as_bytes()),
            reqwest::header::HeaderValue::from_str(value),
        ) else {
            continue;
        };
        map.append(n, v);
    }
    req = req.headers(map);
    if !body.is_empty() {
        req = req.body(body.to_string());
    }
    let resp = req.send().await?;
    let status = resp.status().as_u16();
    let version = format!("{:?}", resp.version());
    let resp_headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
        .collect();
    let bytes = read_body_capped(resp, MAX_SUBRESOURCE_BYTES, "subresource").await?;
    let text = decode_body(&bytes, &resp_headers);
    Ok(Response {
        final_url: url.to_string(),
        status,
        version,
        headers: resp_headers,
        body: text,
        body_bytes: bytes.into(),
    })
}

impl Client {
    /// `ua` is the session's fingerprint User-Agent — the SAME string the
    /// JS tier presents via `navigator.userAgent`. They must match: a
    /// cf_clearance cookie is bound to the UA that earned it, and a
    /// reqwest-default UA is a bot tell on its own.
    pub fn new(ua: &str) -> Self {
        // Production deadlines: 10s to connect, 30s for the whole exchange
        // (headers AND body). The subresource one-shot has always had them;
        // the document client carrying none meant an origin that answers and
        // then goes silent parked the request forever (bug 24, found designing
        // span-suite iteration 16's mid-body-stall control).
        Self::with_timeouts(
            ua,
            std::time::Duration::from_secs(10),
            std::time::Duration::from_secs(30),
        )
    }

    /// Same client with caller-chosen deadlines. Production goes through
    /// [`Client::new`]; wire tests pass short ones so a stall fixture fails
    /// in a second, not half a minute.
    pub fn with_timeouts(
        ua: &str,
        connect: std::time::Duration,
        overall: std::time::Duration,
    ) -> Self {
        Self::with_resolver(ua, connect, overall, GuardedResolver::system())
    }

    /// Same client with a caller-chosen DNS resolver. Production goes
    /// through [`Client::with_timeouts`] (the guarded system resolver, bug
    /// 27); wire tests pass a scripted [`GuardedResolver`] so a name's
    /// answers are deterministic without a real DNS dependency.
    pub fn with_resolver(
        ua: &str,
        connect: std::time::Duration,
        overall: std::time::Duration,
        resolver: Arc<GuardedResolver>,
    ) -> Self {
        let store = Arc::new(SessionStore::default());
        let inner = reqwest::Client::builder()
            .user_agent(ua)
            .default_headers(Self::browser_headers(ua))
            .cookie_provider(store.clone())
            .connect_timeout(connect)
            .timeout(overall)
            .redirect(redirect_policy())
            .dns_resolver(resolver)
            .build()
            .expect("reqwest client builds with default TLS");
        Self {
            inner,
            store,
            ua: ua.to_string(),
        }
    }

    /// Response metadata. HTTP status rides through untouched — a 4xx/5xx
    /// response is still a response (the sidecar layer decides what a
    /// refusal means), so `get` only fails on transport errors (DNS,
    /// refused, TLS).
    pub async fn get(&self, url: &str) -> Result<Response, Error> {
        self.navigate(url, None).await
    }

    /// Document navigation with an initiator — the previous page's URL when
    /// this navigation follows from one (link click, JS location change).
    /// Real browsers send `Referer` and `Sec-Fetch-Site: same-origin` /
    /// `cross-site` on such loads; only an address-bar load has no initiator
    /// (`Sec-Fetch-Site: none`, no Referer — what `document_headers`
    /// presets). A session where every document request claims to be
    /// typed-in is its own tell, and some endpoints require Referer outright.
    ///
    /// The request is built BY HAND (not through `RequestBuilder`) because
    /// reqwest's builder path re-orders headers — it prepends its
    /// auto-inserted User-Agent/Accept ahead of the defaults and re-appends
    /// per-request headers in add-order, which scrambles the fingerprinted
    /// block order (probed during the header-order slice; pinned by
    /// `session_wire_order_matches_chrome_fingerprint`). A manual
    /// `reqwest::Request` carries exactly the map `document_headers` builds,
    /// in order; the jar middleware still injects Cookie at send time.
    pub async fn navigate(&self, url: &str, initiator: Option<&str>) -> Result<Response, Error> {
        // Client-side redirect loop (iteration 25): a followed meta refresh
        // is a redirect in every respect -- the target passes the same
        // refused_target guard an HTTP Location would (with the hop's
        // provenance in the token), the referer chains off the previous
        // hop's final URL, the session jar rides through the store, and the
        // budget mirrors the HTTP one before an honest redirect_loop.
        let mut current = url.to_string();
        let mut from = initiator.map(|s| s.to_string());
        for _meta in 0..=META_REFRESH_MAX_HOPS {
            let res = self.navigate_once(&current, from.as_deref()).await?;
            let Some(target) = meta_refresh_target(&res) else {
                return Ok(res);
            };
            if let Some(why) = refused_target(&target) {
                return Err(Error::TargetRefused(format!("meta refresh: {why} ({target})")));
            }
            from = Some(res.final_url);
            current = target;
        }
        Err(Error::RedirectLoop(format!(
            "meta-refresh chain exceeded {META_REFRESH_MAX_HOPS} hops ({url})"
        )))
    }

    async fn navigate_once(&self, url: &str, initiator: Option<&str>) -> Result<Response, Error> {
        if let Some(why) = refused_target(url) {
            return Err(Error::TargetRefused(format!("{why} ({url})")));
        }
        let site = initiator.and_then(|from| {
            match (url::Url::parse(from), url::Url::parse(url)) {
                (Ok(from), Ok(to)) => Some(if origin_of(&from) == origin_of(&to) {
                    "same-origin"
                } else {
                    "cross-site"
                }),
                _ => None,
            }
        });
        let mut req = reqwest::Request::new(
            reqwest::Method::GET,
            reqwest::Url::parse(url).map_err(|_| Error::BadUrl(url.to_string()))?,
        );
        *req.headers_mut() = Self::document_headers(&self.ua, initiator, site);
        let res = self.inner.execute(req).await?;
        // HTTP status rides through untouched — a 4xx/5xx response is still
        // a response (the sidecar layer decides what a refusal means), so
        // only transport failures reach `Error::Http`.
        let final_url = res.url().to_string();
        let status = res.status().as_u16();
        let version = format!("{:?}", res.version());
        let resp_headers: Vec<(String, String)> = res
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let bytes = read_body_capped(res, MAX_DOCUMENT_BYTES, "document").await?;
        let text = decode_body(&bytes, &resp_headers);
        Ok(Response {
            final_url,
            status,
            version,
            headers: resp_headers,
            body: text,
            body_bytes: bytes.into(),
        })
    }

    /// A session-bound DATA call — the agent-facing fetch surface (firing 37,
    /// kind split in firing 38). Same jar (session cookies ride AND land),
    /// same UA identity, but a subresource-shaped header block and
    /// caller-supplied method/headers/body: the wire shape of the page's own
    /// `fetch()`/`XHR` (or `<img>` load), not a document load.
    ///
    /// The block mirrors Chrome's subresource fetch: client hints + UA, a
    /// default `Accept` by kind ([`DataKind::Data`] `*/*`, caller may
    /// override; [`DataKind::Image`] Chrome's image list), `Sec-Fetch-Site`
    /// from the initiator (`none` without one), the kind's `Sec-Fetch-Mode`/
    /// `Sec-Fetch-Dest` — no `Upgrade-Insecure-Requests`, no
    /// `Sec-Fetch-User`, and the document `Accept` never leaks onto a data
    /// call. Custom headers are merged AFTER the fingerprint block in caller
    /// order: a name already present replaces in place (Accept/Content-Type
    /// overrides keep Chrome's slot), new names append. Hop-by-hop headers
    /// (Connection/Transfer-Encoding/Content-Length and friends) are dropped
    /// from the custom set — the transport owns those. Like `navigate`, the
    /// request is built BY HAND for fingerprint order, and HTTP status rides
    /// through untouched.
    pub async fn request_data(
        &self,
        url: &str,
        method: &str,
        custom_headers: &[(String, String)],
        body: &str,
        initiator: Option<&str>,
        kind: DataKind,
    ) -> Result<Response, Error> {
        if let Some(why) = refused_target(url) {
            return Err(Error::TargetRefused(format!("{why} ({url})")));
        }
        let method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| Error::Subresource(format!("bad method {method:?}: {e}")))?;
        let site = initiator.and_then(|from| {
            match (url::Url::parse(from), url::Url::parse(url)) {
                (Ok(from), Ok(to)) => Some(if origin_of(&from) == origin_of(&to) {
                    "same-origin"
                } else {
                    "cross-site"
                }),
                _ => None,
            }
        });
        let mut h = reqwest::header::HeaderMap::new();
        h.insert(
            "sec-ch-ua",
            HeaderValue::from_str(&sec_ch_ua()).expect("static header value"),
        );
        h.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        h.insert("sec-ch-ua-platform", HeaderValue::from_static("\"Windows\""));
        h.insert(
            reqwest::header::USER_AGENT,
            HeaderValue::from_str(&self.ua).expect("session UA is a valid header value"),
        );
        h.insert(
            reqwest::header::ACCEPT,
            HeaderValue::from_static(match kind {
                DataKind::Data => "*/*",
                // Chrome's `<img>` navigation Accept (captured list, M3-era
                // ground truth) — an image load never asks for text/html.
                DataKind::Image => {
                    "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"
                }
            }),
        );
        h.insert(
            "sec-fetch-site",
            HeaderValue::from_str(site.unwrap_or("none")).expect("static fetch-site value"),
        );
        h.insert(
            "sec-fetch-mode",
            HeaderValue::from_static(match kind {
                DataKind::Data => "cors",
                DataKind::Image => "no-cors",
            }),
        );
        h.insert(
            "sec-fetch-dest",
            HeaderValue::from_static(match kind {
                DataKind::Data => "empty",
                DataKind::Image => "image",
            }),
        );
        if let Some(initiator) = initiator {
            if let Ok(v) = HeaderValue::from_str(initiator) {
                h.insert(reqwest::header::REFERER, v);
            }
        }
        h.insert(
            "accept-encoding",
            HeaderValue::from_static("gzip, deflate, br, zstd"),
        );
        h.insert(
            reqwest::header::ACCEPT_LANGUAGE,
            HeaderValue::from_static("en-US,en;q=0.9"),
        );
        for (name, value) in custom_headers {
            if is_hop_by_hop(name) {
                continue;
            }
            let (Ok(n), Ok(v)) = (
                reqwest::header::HeaderName::from_bytes(name.to_ascii_lowercase().as_bytes()),
                HeaderValue::from_str(value),
            ) else {
                continue;
            };
            h.insert(n, v);
        }
        // `Connection: keep-alive` LAST — same swap-remove discipline as
        // `document_headers`: hyper's h2 codec strips it before framing, and
        // from the final slot that eviction is a pure pop.
        h.insert("connection", HeaderValue::from_static("keep-alive"));
        let mut req = reqwest::Request::new(
            method,
            reqwest::Url::parse(url).map_err(|_| Error::BadUrl(url.to_string()))?,
        );
        *req.headers_mut() = h;
        if !body.is_empty() {
            *req.body_mut() = Some(reqwest::Body::from(body.to_string()));
        }
        let res = self.inner.execute(req).await?;
        let final_url = res.url().to_string();
        let status = res.status().as_u16();
        let version = format!("{:?}", res.version());
        let resp_headers: Vec<(String, String)> = res
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        // Images carry their bytes to the agent (read_image base64s them),
        // so they get the generous cap; data answers share the document cap.
        let cap = match kind {
            DataKind::Image => MAX_IMAGE_BYTES,
            DataKind::Data => MAX_DOCUMENT_BYTES,
        };
        let bytes = read_body_capped(res, cap, "data").await?;
        let text = decode_body(&bytes, &resp_headers);
        Ok(Response {
            final_url,
            status,
            version,
            headers: resp_headers,
            body: text,
            body_bytes: bytes.into(),
        })
    }

    /// The exact header block a headed-Chromium document navigation puts on
    /// the wire, in Chrome's order, captured verbatim off patchright
    /// Chromium 148 by `scripts/capture_chrome_wire.py`:
    ///
    /// ```text
    /// Host, Connection: keep-alive, sec-ch-ua, sec-ch-ua-mobile,
    /// sec-ch-ua-platform, Upgrade-Insecure-Requests, User-Agent, Accept,
    /// Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-User, Sec-Fetch-Dest,
    /// [Referer], Accept-Encoding, Accept-Language, Cookie
    /// ```
    ///
    /// The jar adds Cookie at send time (after the map, as Chrome does) and
    /// hyper appends Host on h1.1 (its one positional quirk — on the live h2
    /// tier it becomes `:authority`, a pseudo-header). `Host` is deliberately
    /// NOT placed in the map: hyper's h2 codec would treat a literal host
    /// header as a duplicate authority. Everything else is exact — including
    /// Chrome's full Accept (image/apng, signed-exchange) and Accept-Encoding
    /// (`gzip, deflate, br, zstd`, not reqwest's feature-driven default).
    ///
    /// `pub` so the `h2cap` bin's `--engine` self-drive can hand-build the
    /// same request `navigate()` would (firing 12's h2 wire capture).
    pub fn document_headers(
        ua: &str,
        initiator: Option<&str>,
        site: Option<&str>,
    ) -> reqwest::header::HeaderMap {
        let mut h = reqwest::header::HeaderMap::new();
        // Client hints — the same identity the JS userAgentData answers.
        h.insert(
            "sec-ch-ua",
            HeaderValue::from_str(&sec_ch_ua()).expect("static header value"),
        );
        h.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        h.insert("sec-ch-ua-platform", HeaderValue::from_static("\"Windows\""));
        h.insert("upgrade-insecure-requests", HeaderValue::from_static("1"));
        h.insert(
            reqwest::header::USER_AGENT,
            HeaderValue::from_str(ua).expect("session UA is a valid header value"),
        );
        h.insert(
            reqwest::header::ACCEPT,
            HeaderValue::from_static(
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            ),
        );
        // Navigation metadata — a real Chrome document request carries these
        // on every top-level load, and some edges (Facebook's anonymous tier
        // among them) flat-400 a request that lacks the Fetch Metadata
        // signature: it's the cheapest non-browser signal they check.
        // Chrome's block order: Site, Mode, User, Dest.
        h.insert(
            "sec-fetch-site",
            HeaderValue::from_str(site.unwrap_or("none")).expect("static fetch-site value"),
        );
        h.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        h.insert("sec-fetch-user", HeaderValue::from_static("?1"));
        h.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        if let Some(initiator) = initiator {
            if let Ok(v) = HeaderValue::from_str(initiator) {
                h.insert(reqwest::header::REFERER, v);
            }
        }
        // Chrome's exact value — pinned, not reqwest's feature-driven
        // `zstd,gzip,deflate,br` (no spaces, different order).
        h.insert(
            "accept-encoding",
            HeaderValue::from_static("gzip, deflate, br, zstd"),
        );
        h.insert(
            reqwest::header::ACCEPT_LANGUAGE,
            HeaderValue::from_static("en-US,en;q=0.9"),
        );
        // `Connection: keep-alive` LAST, and that is load-bearing: hyper's
        // h2 codec strips connection headers before framing, and
        // `http::HeaderMap::remove` is a SWAP-remove — evicting a header
        // that sits earlier in the map would move the map's last entry into
        // its slot and corrupt the h2 wire order (probed: connection at the
        // front put cookie/accept-language first on h2). At the final slot
        // the swap is a pure pop, so the live tier rides the exact order
        // above. Chrome places this header second on its h1.1 wire; on h1.1
        // it rides here instead (hyper floor), keep-alive semantics intact.
        h.insert("connection", HeaderValue::from_static("keep-alive"));
        // Chrome's h2 wire ends with `priority: u=0, i` (RFC 9218 ext
        // priority; captured from patchright headed Chromium 148 via h2cap).
        // reqwest/hyper 1.x has no Priority header support, so this header
        // is NOT on the engine's wire — it is documented as a deviation in
        // `session_h2_wire_matches_chrome_fingerprint` below.
        h
    }

    /// Same presentation, no cookie jar — for subresource requests issued
    /// from a page context (`fetch()` in the DOM bridge). A dedicated jar
    /// means session cookies can't leak cross-origin into an XHR the way a
    /// page's own `fetch` wouldn't carry them either.
    #[allow(dead_code)] // superseded by se-js's session-bound raw-TCP fetch; kept for reference
    pub fn for_page_fetch(ua: &str) -> Self {
        let store = Arc::new(SessionStore::default());
        let mut headers = Self::browser_headers(ua);
        // One request per connection: a page-context fetch/XHR is a discrete
        // subresource grab, and a pooled keep-alive socket against a
        // single-threaded origin would stall the next accept.
        headers.insert(
            reqwest::header::CONNECTION,
            HeaderValue::from_static("close"),
        );
        let inner = reqwest::Client::builder()
            .user_agent(ua)
            .default_headers(headers)
            .cookie_provider(store.clone())
            // A page-context subresource must fail fast, not stall the
            // blocking bridge callback on a half-open connect.
            .connect_timeout(std::time::Duration::from_secs(5))
            .http1_only()
            .build()
            .expect("reqwest client builds with default TLS");
        Self {
            inner,
            store,
            ua: ua.to_string(),
        }
    }

    /// Client-default header map — a safety net for any internal request that
    /// doesn't go through `navigate`'s hand-built path. The REAL document
    /// block is [`Client::document_headers`], built per request in exact
    /// headed-Chromium order (see its comment for the captured ground truth
    /// and the wire-order pin); this delegate just reuses that map so the
    /// two surfaces can never drift.
    fn browser_headers(ua: &str) -> reqwest::header::HeaderMap {
        Self::document_headers(ua, None, None)
    }

    /// The session's live cookie store — enumeration and injection for the
    /// session verbs.
    pub fn store(&self) -> Arc<SessionStore> {
        self.store.clone()
    }

    /// The session fingerprint UA — the agent's WebSocket handshake (firing
    /// 39) presents it identically to a data call so the two surfaces can't
    /// drift into a fingerprint tell.
    pub fn user_agent(&self) -> String {
        self.ua.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Bug 157 (searchio iteration 70): reqwest's Display for a transport
    /// failure is the bare "error sending request"; the CAUSE -- an invalid
    /// peer certificate, a refused connection -- lives in the source chain.
    /// The engine's error must carry the whole chain so a caller can tell a
    /// bad certificate from a dead host.
    #[tokio::test]
    async fn transport_error_display_carries_the_cause_chain() {
        // A closed port: reqwest says "error sending request", the chain says
        // "client error (Connect)" and then the OS refusal.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(5)).build().unwrap();
        let err: Error = client.get(format!("http://127.0.0.1:{port}/")).send().await.unwrap_err().into();
        let msg = err.to_string();
        assert!(msg.starts_with("request failed: "), "{msg}");
        assert!(msg.len() > "request failed: error sending request".len() + 8, "no cause in {msg:?}");
        assert!(msg.contains("onnect") || msg.contains("refused"), "{msg}");
    }

    /// The fingerprint the tests present — same shape as the engine UA.
    const TEST_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36";

    /// Minimal HTTP/1.1 test server, spawned alongside the client. `n`
    /// connections are accepted sequentially (redirects need two); each
    /// request is answered by `handle(path, headers)` -> `(status, body)`.
    /// Real connections because cookie and redirect behavior only means
    /// something over the wire.
    async fn spawn_server<F>(n: usize, handle: F) -> (String, tokio::task::JoinHandle<()>)
    where
        F: Fn(&str, &str) -> (u16, String) + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let h = tokio::spawn(async move {
            for _ in 0..n {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 8192];
                let n = socket.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("/")
                    .to_string();
                let (status, body) = handle(&path, &req);
                let reason = if status == 302 { "Found" } else { "OK" };
                let head = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n",
                    body.len()
                );
                let head = if status == 302 {
                    format!("{head}Location: /landing\r\n")
                } else {
                    head
                };
                socket
                    .write_all(format!("{head}\r\n{body}").as_bytes())
                    .await
                    .unwrap();
            }
        });
        (format!("http://{addr}"), h)
    }

    #[tokio::test]
    async fn follows_redirect_and_reports_final_url() {
        // two connections: the 302 and the followed landing
        let (base, server) = spawn_server(2, |path, _| {
            if path == "/start" {
                (302, String::new())
            } else {
                (200, format!("landed at {path}"))
            }
        })
        .await;
        let client = Client::new(TEST_UA);
        let res = client.get(&format!("{base}/start")).await.unwrap();
        assert_eq!(res.status, 200);
        assert!(res.final_url.ends_with("/landing"), "{}", res.final_url);
        assert_eq!(res.body, "landed at /landing");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn navigate_with_initiator_sends_referer_and_fetch_site() {
        // A followed navigation carries the initiator: Referer + a
        // Sec-Fetch-Site derived from the origin pair (hyper writes header
        // names lowercase on the wire — match that). Three connections:
        // same-origin initiator, cross-site initiator, then address-bar.
        let (base, server) = spawn_server(3, |path, req| {
            let referer = req
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("referer:"))
                .unwrap_or("")
                .to_string();
            let site = req
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("sec-fetch-site:"))
                .unwrap_or("")
                .to_string();
            (200, format!("{path}|{referer}|{site}"))
        })
        .await;
        let client = Client::new(TEST_UA);

        let res = client
            .navigate(&format!("{base}/a"), Some(&format!("{base}/prev")))
            .await
            .unwrap();
        let mut parts = res.body.split('|');
        assert_eq!(parts.next(), Some("/a"));
        assert!(
            parts.next().unwrap_or("").contains(&format!("{base}/prev")),
            "same-origin Referer: {}",
            res.body
        );
        assert!(
            parts.next().unwrap_or("").contains("same-origin"),
            "same-origin Sec-Fetch-Site: {}",
            res.body
        );

        let res = client
            .navigate(
                &format!("{base}/b"),
                Some("https://elsewhere.example/page"),
            )
            .await
            .unwrap();
        let mut parts = res.body.split('|');
        assert_eq!(parts.next(), Some("/b"));
        assert!(
            parts.next().unwrap_or("").contains("https://elsewhere.example/page"),
            "cross-site Referer: {}",
            res.body
        );
        assert!(
            parts.next().unwrap_or("").contains("cross-site"),
            "cross-site Sec-Fetch-Site: {}",
            res.body
        );

        // No initiator → the address-bar default from browser_headers: no
        // Referer at all, Sec-Fetch-Site: none.
        let res = client.navigate(&format!("{base}/c"), None).await.unwrap();
        assert!(
            !res.body.to_ascii_lowercase().contains("referer:"),
            "address-bar nav leaked a Referer: {}",
            res.body
        );
        assert!(
            res.body.contains("sec-fetch-site: none"),
            "address-bar nav lost Sec-Fetch-Site none: {}",
            res.body
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn content_encoded_responses_decode_on_the_wire() {
        // Real edges (FB's among them — live smoke once died with "error
        // decoding response body" mid-session) defflate document bodies.
        // Without reqwest's decode features any compressed response fails
        // the whole goto; pin gzip + zlib-deflate + brotli + zstd.
        use std::io::Write as _;
        let payload = b"hello engine";
        let gz = {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            e.write_all(payload).unwrap();
            e.finish().unwrap()
        };
        let zl = {
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
            e.write_all(payload).unwrap();
            e.finish().unwrap()
        };
        let br = {
            let mut out = Vec::new();
            brotli::BrotliCompress(&mut &payload[..], &mut out, &brotli::enc::BrotliEncoderParams::default()).unwrap();
            out
        };
        let zs = zstd::encode_all(&payload[..], 0).unwrap();
        let bodies = vec![
            ("gzip", gz),
            ("deflate", zl),
            ("br", br),
            ("zstd", zs),
        ];

        // Bespoke server: spawn_server can't emit Content-Encoding heads or
        // binary bodies.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for (encoding, body) in bodies {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 8192];
                let _ = socket.read(&mut buf).await.unwrap();
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Encoding: {}\r\nConnection: close\r\n\r\n",
                    body.len(),
                    encoding
                );
                socket.write_all(head.as_bytes()).await.unwrap();
                socket.write_all(&body).await.unwrap();
            }
        });

        let client = Client::new(TEST_UA);
        for encoding in ["gzip", "deflate", "br", "zstd"] {
            let res = client.get(&format!("http://{addr}/{encoding}")).await.unwrap();
            assert_eq!(res.status, 200, "{encoding}");
            assert_eq!(res.body, "hello engine", "{encoding} decoded body");
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn charset_declared_and_meta_sniffed_bodies_decode() {
        // A body whose bytes are Shift_JIS must arrive as text, not U+FFFD
        // stew: the header-declared leg exercises the content-type charset,
        // the meta-only leg the HTML prescan every browser does (and reqwest
        // deliberately does not). searchio's bench/span.py caught the old
        // lossy-UTF-8 decode shipping 156 replacement chars on both shapes.
        let jp = "\u{30b9}\u{30d1}\u{30f3}\u{30b3}\u{30f3}\u{30c8}\u{30ed}\u{30fc}\u{30eb}";
        let sjis = encoding_rs::SHIFT_JIS.encode(jp).0.into_owned();
        let mut meta_body = b"<html><head><meta charset=\"shift_jis\"></head><body>".to_vec();
        meta_body.extend_from_slice(&sjis);
        meta_body.extend_from_slice(b"</body></html>");
        let bodies: Vec<(&str, Vec<u8>)> = vec![
            ("text/html; charset=shift_jis", sjis.clone()),
            ("text/html", meta_body),
            ("text/html; charset=utf-8", b"plain utf-8 body".to_vec()),
        ];

        // Bespoke server: spawn_server can't emit Content-Type heads or
        // non-UTF-8 bodies.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for (ctype, body) in bodies {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 8192];
                let _ = socket.read(&mut buf).await.unwrap();
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: close\r\n\r\n",
                    body.len(),
                    ctype
                );
                socket.write_all(head.as_bytes()).await.unwrap();
                socket.write_all(&body).await.unwrap();
            }
        });

        let client = Client::new(TEST_UA);
        // Header-declared: decode per the content-type charset.
        let res = client.get(&format!("http://{addr}/declared")).await.unwrap();
        assert_eq!(res.status, 200);
        assert!(res.body.contains(jp), "declared shift_jis: {:?}", res.body);
        assert!(!res.body.contains('\u{fffd}'), "no replacement chars: {:?}", res.body);
        // Meta-only: the prescan finds <meta charset> in the first 1KB.
        let res = client.get(&format!("http://{addr}/meta")).await.unwrap();
        assert!(res.body.contains(jp), "meta sniff: {:?}", res.body);
        assert!(!res.body.contains('\u{fffd}'));
        // UTF-8 sanity: the default path is unchanged.
        let res = client.get(&format!("http://{addr}/utf8")).await.unwrap();
        assert_eq!(res.body, "plain utf-8 body");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn mid_body_stall_errors_within_budget() {
        // Bug 24 (span-suite iteration 16): the document client carried NO
        // deadline -- an origin that answers headers, dribbles a partial
        // body and then goes silent parked the request (and its connection,
        // inside se-serve) forever. The subresource one-shot has always had
        // 10s/30s; navigate now does too. Here the fixture stalls 5s against
        // a 1s budget: the fetch must error inside the budget, never return
        // the partial body as a page.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let _ = socket.read(&mut buf).await.unwrap();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\nContent-Type: text/html\r\n\r\n<html><body><p>partial")
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        });
        let client = Client::with_timeouts(
            TEST_UA,
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1),
        );
        let t0 = std::time::Instant::now();
        let res = client.get(&format!("http://{addr}/drip")).await;
        let elapsed = t0.elapsed();
        assert!(res.is_err(), "a stalled body must not become a page");
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "stall bounded by the client budget, took {elapsed:?}"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn huge_body_truthful_length_refused_before_read() {
        // Iteration 18: a body over the document cap is REFUSED, never
        // served. With no content-encoding the wire length IS the decoded
        // length, so a truthful over-cap Content-Length refuses before a
        // single body byte is read -- the fixture declares the big length
        // but sends only a fragment and closes; code that read first would
        // error on the incomplete body instead of naming too_large.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let _ = socket.read(&mut buf).await.unwrap();
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/html\r\n\r\n",
                MAX_DOCUMENT_BYTES + 1
            );
            let _ = socket.write_all(head.as_bytes()).await;
            // The client must already be gone (pre-check); tolerate the
            // reset either way.
            let _ = socket.write_all(b"<html><body>short").await;
        });
        let client = Client::new(TEST_UA);
        let err = client.get(&format!("http://{addr}/huge")).await.unwrap_err();
        assert!(
            format!("{err}").contains("too_large"),
            "over-cap declared length must refuse too_large, got: {err}"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn huge_body_close_delimited_refused_at_stream_cap() {
        // No Content-Length at all (close-delimited): the streamed-total cap
        // is the only guard between the client and an unbounded read.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let _ = socket.read(&mut buf).await.unwrap();
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
                .await;
            let chunk = vec![b'x'; 65536];
            for _ in 0..(MAX_DOCUMENT_BYTES / 65536 + 2) {
                if socket.write_all(&chunk).await.is_err() {
                    break; // the client quite rightly hung up mid-stream
                }
            }
        });
        let client = Client::new(TEST_UA);
        let err = client.get(&format!("http://{addr}/huge")).await.unwrap_err();
        assert!(
            format!("{err}").contains("too_large"),
            "close-delimited over-cap body must refuse too_large, got: {err}"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn gzip_bomb_refused_on_decoded_bytes() {
        // The bomb shape: kilobytes on the wire, megabytes decoded. The cap
        // must count the DECODED stream -- a wire-size check waves this
        // through and the whole thing materializes in memory.
        use std::io::Write as _;
        let payload = vec![b'a'; (MAX_DOCUMENT_BYTES + 1024) as usize];
        let gz = {
            let mut e =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            e.write_all(&payload).unwrap();
            e.finish().unwrap()
        };
        assert!(
            (gz.len() as u64) < MAX_DOCUMENT_BYTES,
            "fixture must be small on the wire, got {}",
            gz.len()
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let _ = socket.read(&mut buf).await.unwrap();
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
                gz.len()
            );
            let _ = socket.write_all(head.as_bytes()).await;
            let _ = socket.write_all(&gz).await;
        });
        let client = Client::new(TEST_UA);
        let err = client.get(&format!("http://{addr}/bomb")).await.unwrap_err();
        assert!(
            format!("{err}").contains("too_large"),
            "gzip bomb must refuse too_large on decoded bytes, got: {err}"
        );
        server.await.unwrap();
    }

    #[test]
    fn refused_target_truth_table() {
        // The guard itself, no wire: IP literals in the two refused classes,
        // the mapped-v6 dodge, and the allowed shapes (loopback = the span
        // suite's own server, RFC1918 = legitimate intranet, hostnames).
        for (url, want) in [
            ("http://169.254.169.254/latest/meta-data", Some("link_local")),
            ("http://169.254.0.1/", Some("link_local")),
            ("http://0.0.0.0/", Some("unspecified")),
            ("http://[::ffff:a9fe:a9a9]/", Some("link_local")),
            ("http://[fe80::1]/", Some("link_local")),
            ("http://[::]/", Some("unspecified")),
            ("file:///C:/Windows/win.ini", Some("scheme:")),
            ("ftp://example.com/x", Some("scheme:")),
            ("http://127.0.0.1:8000/prose", None),
            ("http://192.168.1.1/", None),
            ("http://10.0.0.5/", None),
            ("https://example.com/", None),
        ] {
            let got = refused_target(url);
            match want {
                Some(prefix) => assert!(
                    got.as_deref().unwrap_or("").starts_with(prefix),
                    "{url}: want {prefix}*, got {got:?}"
                ),
                None => assert!(got.is_none(), "{url}: want allowed, got {got:?}"),
            }
        }
    }

    #[tokio::test]
    async fn redirect_to_link_local_refused_on_the_hop() {
        // Bug 25: a 302 Location pointing at the cloud metadata endpoint was
        // chased by auto-follow like any other hop. The custom policy must
        // refuse BEFORE the connection -- the fixture accepts one request
        // (the 302); a follow would hang waiting for a second accept that
        // never comes, which is itself the tell.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let _ = socket.read(&mut buf).await.unwrap();
            let _ = socket
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
        });
        let client = Client::new(TEST_UA);
        let err = client.get(&format!("http://{addr}/jump")).await.unwrap_err();
        assert!(
            format!("{err}").contains("target_refused"),
            "redirect to link-local must refuse target_refused, got: {err}"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn direct_link_local_fetch_refused_before_connect() {
        // No server at all: the entry check must fire before any connection
        // is attempted. The variant pin is exact -- TargetRefused, not a
        // transport flake.
        let client = Client::new(TEST_UA);
        let err = client
            .get("http://169.254.169.254/latest/meta-data")
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::TargetRefused(_)),
            "direct metadata fetch must be TargetRefused, got: {err}"
        );
        let err = client.get("http://[::ffff:a9fe:a9a9]/").await.unwrap_err();
        assert!(
            matches!(err, Error::TargetRefused(_)),
            "mapped-v6 metadata dodge must be TargetRefused, got: {err}"
        );
    }

    #[tokio::test]
    async fn redirect_hop_cap_still_bounded() {
        // The custom policy must preserve the pre-guard limited(10) shape
        // EXACTLY: an infinite 302 loop errors (too many redirects) after
        // initial + 10 follows = 11 requests -- never an unbounded chase,
        // never the 30x surfaced as a page.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..11 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 8192];
                let _ = socket.read(&mut buf).await.unwrap();
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
            }
        });
        let client = Client::new(TEST_UA);
        let err = client.get(&format!("http://{addr}/loop")).await.unwrap_err();
        assert!(
            format!("{err}").contains("redirect"),
            "hop cap must error like limited(10), got: {err}"
        );
        server.await.unwrap();
    }

    // ── meta-refresh follow (iteration 25) ────────────────────────────────
    // A <meta http-equiv="refresh" content="0; url=..."> in a 200 HTML head
    // is a redirect the server never sent — the squeeze/parked-page class
    // routes through it, and a stack that ignores the tag reads the
    // interstitial. `navigate` follows it like a redirect: same target
    // guard, a hop budget mirroring limited(10), the jar riding, and the
    // previous page as the next hop's initiator. The contract is mirrored
    // by searchio's Python tiers (`_meta_refresh_target`) and pinned
    // end-to-end by span control rows 100-118.

    /// Test server with per-path content-type and extra headers (the plain
    /// spawn_server emits neither).
    async fn spawn_meta_server<F>(
        n: usize,
        handle: F,
    ) -> (String, tokio::task::JoinHandle<()>)
    where
        F: Fn(&str, &str) -> (u16, &'static str, &'static str, String) + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let h = tokio::spawn(async move {
            for _ in 0..n {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 8192];
                let n = socket.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                let (status, ctype, extra, body) = handle(&path, &req);
                let head = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n",
                    body.len()
                );
                socket
                    .write_all(format!("{head}{body}").as_bytes())
                    .await
                    .unwrap();
            }
        });
        (format!("http://{addr}"), h)
    }

    fn meta_page(content: &str, marker: &str) -> String {
        format!(
            "<html><head><meta http-equiv=\"refresh\" content=\"{content}\"></head><body><p>{marker}</p></body></html>"
        )
    }

    #[tokio::test]
    async fn meta_refresh_follow_lands_on_target() {
        let (base, server) = spawn_meta_server(2, |path, _| {
            if path == "/go" {
                (200, "text/html", "", meta_page("0; url=/landing", "SQUEEZE"))
            } else {
                (200, "text/html", "", format!("landed at {path}"))
            }
        })
        .await;
        let client = Client::new(TEST_UA);
        let res = client.get(&format!("{base}/go")).await.unwrap();
        assert_eq!(res.status, 200);
        assert!(res.final_url.ends_with("/landing"), "{}", res.final_url);
        assert_eq!(res.body, "landed at /landing");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn meta_refresh_relative_case_and_quotes() {
        // Relative target, upper-case tag/attrs, single-quoted URL — all of
        // it is what browsers accept in the wild.
        let (base, server) = spawn_meta_server(2, |path, _| {
            if path == "/go" {
                (
                    200,
                    "text/html",
                    "",
                    "<html><head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"0; URL='landing'\"></head><body>sq</body></html>"
                        .to_string(),
                )
            } else {
                (200, "text/html", "", format!("landed at {path}"))
            }
        })
        .await;
        let client = Client::new(TEST_UA);
        let res = client.get(&format!("{base}/go")).await.unwrap();
        assert!(res.final_url.ends_with("/landing"), "{}", res.final_url);
        assert_eq!(res.body, "landed at /landing");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn meta_refresh_slow_is_served_as_is() {
        // 6s is over the follow bound: the interstitial IS the document — a
        // search engine never sleeps for a slow redirect.
        let (base, server) = spawn_meta_server(1, |_, _| {
            (200, "text/html", "", meta_page("6; url=/landing", "SQUEEZE SLOW"))
        })
        .await;
        let client = Client::new(TEST_UA);
        let res = client.get(&format!("{base}/go")).await.unwrap();
        assert!(res.body.contains("SQUEEZE SLOW"), "{}", res.body);
        assert!(res.final_url.ends_with("/go"), "{}", res.final_url);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn meta_refresh_reload_is_a_noop() {
        // No url= is a self-reload (the polling pattern) — never a hop.
        let (base, server) = spawn_meta_server(1, |_, _| {
            (200, "text/html", "", meta_page("2", "SQUEEZE RELOAD"))
        })
        .await;
        let client = Client::new(TEST_UA);
        let res = client.get(&format!("{base}/go")).await.unwrap();
        assert!(res.body.contains("SQUEEZE RELOAD"), "{}", res.body);
        assert!(res.final_url.ends_with("/go"), "{}", res.final_url);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn meta_refresh_loop_is_bounded() {
        // A meta ping-pong must error like limited(10), never chase forever:
        // initial + 10 follows = 11 document fetches, then redirect_loop.
        let (base, server) = spawn_meta_server(11, |path, _| {
            if path == "/a" {
                (200, "text/html", "", meta_page("0; url=/b", "LOOP A"))
            } else {
                (200, "text/html", "", meta_page("0; url=/a", "LOOP B"))
            }
        })
        .await;
        let client = Client::new(TEST_UA);
        let err = client.get(&format!("{base}/a")).await.unwrap_err();
        assert!(
            format!("{err}").contains("redirect_loop"),
            "meta loop must carry the redirect_loop token, got: {err}"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn meta_refresh_to_link_local_is_refused() {
        // The guard half: a meta hop to the cloud metadata endpoint draws
        // the same target_refused a 302 to it would (bug 25's class, one
        // hop later) — and the message names the meta refresh as the cause.
        let (base, server) = spawn_meta_server(1, |_, _| {
            (
                200,
                "text/html",
                "",
                meta_page("0; url=http://169.254.169.254/latest/meta-data", "SQUEEZE"),
            )
        })
        .await;
        let client = Client::new(TEST_UA);
        let err = client.get(&format!("{base}/go")).await.unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("target_refused"), "got: {msg}");
        assert!(msg.contains("meta refresh"), "got: {msg}");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn meta_refresh_first_tag_decides() {
        // Chrome's rule: the FIRST refresh tag wins. A reload first means a
        // later instant hop never fires — a stack scanning for the first
        // FOLLOWABLE tag hops where a browser would not.
        let (base, server) = spawn_meta_server(1, |_, _| {
            (
                200,
                "text/html",
                "",
                "<html><head><meta http-equiv=\"refresh\" content=\"5\"><meta http-equiv=\"refresh\" content=\"0; url=/landing\"></head><body><p>SQUEEZE FIRST</p></body></html>"
                    .to_string(),
            )
        })
        .await;
        let client = Client::new(TEST_UA);
        let res = client.get(&format!("{base}/go")).await.unwrap();
        assert!(res.body.contains("SQUEEZE FIRST"), "{}", res.body);
        assert!(res.final_url.ends_with("/go"), "{}", res.final_url);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn meta_refresh_in_a_json_body_is_not_followed() {
        // A 200 application/json body whose text carries a refresh-looking
        // string is not a document — never a hop.
        let (base, server) = spawn_meta_server(1, |_, _| {
            (
                200,
                "application/json",
                "",
                "{\"next\":\"<meta http-equiv='refresh' content='0; url=/landing'>\"}"
                    .to_string(),
            )
        })
        .await;
        let client = Client::new(TEST_UA);
        let res = client.get(&format!("{base}/go")).await.unwrap();
        assert!(res.body.contains("http-equiv"), "{}", res.body);
        assert!(res.final_url.ends_with("/go"), "{}", res.final_url);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn meta_refresh_same_host_cookie_rides() {
        // The jar spans the refresh navigation: a cookie the squeeze page
        // deposits must ride to the same-host target (browser semantics;
        // cross-host scoping is reqwest's jar, pinned by the redirect
        // cookie tests).
        let (base, server) = spawn_meta_server(2, |path, req| {
            if path == "/go" {
                (
                    200,
                    "text/html",
                    "Set-Cookie: se_ms=ride; Path=/\r\n",
                    meta_page("0; url=/check", "SQUEEZE"),
                )
            } else {
                let cookie = req
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("cookie:"))
                    .unwrap_or("cookie: <absent>")
                    .to_string();
                (200, "text/html", "", cookie)
            }
        })
        .await;
        let client = Client::new(TEST_UA);
        let res = client.get(&format!("{base}/go")).await.unwrap();
        assert!(
            res.body.contains("se_ms=ride"),
            "the deposited cookie must ride the same-host meta hop: {}",
            res.body
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn meta_refresh_chains_the_referer() {
        // A refresh navigation carries the previous page as initiator —
        // real browsers send Referer on it; an address-bar shape on hop 2
        // is its own tell.
        let (base, server) = spawn_meta_server(2, |path, req| {
            if path == "/go" {
                (200, "text/html", "", meta_page("0; url=/landing", "SQUEEZE"))
            } else {
                let referer = req
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("referer:"))
                    .unwrap_or("referer: <absent>")
                    .to_string();
                (200, "text/html", "", referer)
            }
        })
        .await;
        let client = Client::new(TEST_UA);
        let res = client.get(&format!("{base}/go")).await.unwrap();
        assert!(
            res.body.contains("/go"),
            "the meta hop must carry the previous page as Referer: {}",
            res.body
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn redirect_cross_host_strips_caller_credentials() {
        // Bug 26 (engine side, by construction): the Python ladder's cheap
        // tiers forwarded caller credential headers (clearance Cookie,
        // Authorization) to EVERY redirect hop until iteration 20's fix.
        // The engine must never have that shape: reqwest's redirect layer
        // strips sensitive headers when a hop crosses host/port
        // (redirect.rs `remove_sensitive_headers`, which treats a host-STRING
        // change as crossing -- "localhost" vs 127.0.0.1 counts, exactly the
        // split the span suite's cross-host controls use), and the cookie
        // store scopes deposited cookies by RFC 6265 domain rules. Pin both
        // at the wire: A (127.0.0.1) answers a request carrying caller
        // Cookie+Authorization with a Set-Cookie and a 302 to the localhost
        // NAME; B echoes what it observed and must see neither the caller
        // credentials nor A's deposited cookie.
        use std::net::ToSocketAddrs;
        let alt = "localhost:0"
            .to_socket_addrs()
            .unwrap()
            .find(|a| a.is_ipv4())
            .expect("localhost has an IPv4 loopback mapping on this box");
        let listener_b = TcpListener::bind(alt).await.unwrap();
        let port_b = listener_b.local_addr().unwrap().port();
        let server_b = tokio::spawn(async move {
            let (mut socket, _) = listener_b.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = socket.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let cookie = req
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("cookie:"))
                .unwrap_or("cookie: <absent>")
                .to_string();
            let auth = req
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
                .unwrap_or("authorization: <absent>")
                .to_string();
            let body = format!("{cookie}|{auth}");
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            socket
                .write_all(format!("{head}{body}").as_bytes())
                .await
                .unwrap();
        });
        let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_a = listener_a.local_addr().unwrap();
        let server_a = tokio::spawn(async move {
            let (mut socket, _) = listener_a.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let _ = socket.read(&mut buf).await.unwrap();
            let head = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://localhost:{port_b}/echo\r\nSet-Cookie: se_sid=secret-x; Path=/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            socket.write_all(head.as_bytes()).await.unwrap();
        });
        let client = Client::new(TEST_UA);
        let headers = vec![
            ("Cookie".to_string(), "span_clear=hdr-token".to_string()),
            ("Authorization".to_string(), "Bearer hdr-token".to_string()),
        ];
        let res = client
            .request_data(
                &format!("http://{addr_a}/jump"),
                "GET",
                &headers,
                "",
                None,
                DataKind::Data,
            )
            .await
            .unwrap();
        assert_eq!(res.status, 200, "the cross-host hop completes: {res:?}");
        assert!(
            res.final_url.starts_with(&format!("http://localhost:{port_b}")),
            "the hop must land on the localhost name, got {}",
            res.final_url
        );
        assert!(
            res.body.contains("cookie: <absent>"),
            "caller Cookie and A's stored cookie must not cross hosts: {}",
            res.body
        );
        assert!(
            res.body.contains("authorization: <absent>"),
            "caller Authorization must not cross hosts: {}",
            res.body
        );
        server_a.await.unwrap();
        server_b.await.unwrap();
    }

    #[tokio::test]
    async fn redirect_same_host_keeps_credentials_and_store_cookie_rides() {
        // The other half of the bug-26 contract: the strip must not be
        // over-broad. A same-host hop keeps the caller's Cookie/Authorization
        // (a clearance cookie that vanished on an in-site redirect would
        // break every challenged flow), and the store cookie deposited by
        // the 302 rides a LATER header-free request to the same host. Also
        // pinned on the way through: an explicit Cookie header suppresses
        // store injection for that request (cookie.rs CookieService), so the
        // landing sees the caller's header, not a merged one.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 8192];
                let n = socket.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                let (status, extra, body) = match path.as_str() {
                    "/jump" => (
                        302,
                        "Set-Cookie: se_sid=secret-x; Path=/\r\nLocation: /landing\r\n",
                        String::new(),
                    ),
                    _ => {
                        let cookie = req
                            .lines()
                            .find(|l| l.to_ascii_lowercase().starts_with("cookie:"))
                            .unwrap_or("cookie: <absent>")
                            .to_string();
                        let auth = req
                            .lines()
                            .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
                            .unwrap_or("authorization: <absent>")
                            .to_string();
                        (200, "", format!("{cookie}|{auth}"))
                    }
                };
                let reason = if status == 302 { "Found" } else { "OK" };
                let head = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n",
                    body.len()
                );
                socket
                    .write_all(format!("{head}{body}").as_bytes())
                    .await
                    .unwrap();
            }
        });
        let client = Client::new(TEST_UA);
        let headers = vec![
            ("Cookie".to_string(), "span_clear=hdr-token".to_string()),
            ("Authorization".to_string(), "Bearer hdr-token".to_string()),
        ];
        let res = client
            .request_data(
                &format!("http://{addr}/jump"),
                "GET",
                &headers,
                "",
                None,
                DataKind::Data,
            )
            .await
            .unwrap();
        assert!(
            res.body.contains("span_clear=hdr-token"),
            "same-host hop keeps the caller Cookie: {}",
            res.body
        );
        assert!(
            res.body.contains("Bearer hdr-token"),
            "same-host hop keeps the caller Authorization: {}",
            res.body
        );
        assert!(
            !res.body.contains("se_sid"),
            "explicit Cookie suppresses store injection for that request: {}",
            res.body
        );
        // Header-free request to the same host: the deposited cookie rides.
        let res = client.get(&format!("http://{addr}/check")).await.unwrap();
        assert!(
            res.body.contains("se_sid=secret-x"),
            "store cookie deposited by the 302 rides same-host: {}",
            res.body
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn dns_answer_in_a_refused_class_poisons_the_dial() {
        // Bug 27: the URL-literal guard only sees a name, never its
        // address -- a hostname resolving to the cloud metadata endpoint
        // was dialed like any other. The guarded resolver must refuse
        // BEFORE connecting (no listener exists to accept anything; a dial
        // to 169.254.x would hang into the connect timeout, itself a tell),
        // and the contractual token must ride the source chain out as the
        // typed TargetRefused variant, not drown in "request failed".
        let resolver = GuardedResolver::with_lookup(std::sync::Arc::new(|host| {
            assert_eq!(host, "metadata.test");
            Box::pin(async move {
                Ok(vec![std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(169, 254, 169, 254)),
                    0,
                )])
            })
        }));
        let client = Client::with_resolver(
            TEST_UA,
            std::time::Duration::from_secs(2),
            std::time::Duration::from_secs(4),
            resolver,
        );
        let err = client
            .get("http://metadata.test/latest/meta-data")
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::TargetRefused(_)),
            "refused DNS answer must surface as TargetRefused, got: {err}"
        );
        assert!(
            format!("{err}").contains("dns:metadata.test"),
            "the refused name rides the message: {err}"
        );
    }

    #[tokio::test]
    async fn dns_answer_clean_serves_via_checked_dial() {
        // The flip side: a scripted CLEAN answer must connect and serve --
        // through a name real DNS would never resolve -- proving the dial
        // consumes exactly the resolver's vetted answers (reqwest overrides
        // the placeholder port 0 with the URL's port).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let _ = socket.read(&mut buf).await.unwrap();
            let _ = socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 19\r\nConnection: close\r\n\r\nchecked-dial served",
                )
                .await;
        });
        let resolver = GuardedResolver::with_lookup(std::sync::Arc::new(|host| {
            assert_eq!(host, "unit.test");
            Box::pin(async move {
                Ok(vec![std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    0,
                )])
            })
        }));
        let client = Client::with_resolver(
            TEST_UA,
            std::time::Duration::from_secs(2),
            std::time::Duration::from_secs(4),
            resolver,
        );
        let res = client
            .get(&format!("http://unit.test:{}/", addr.port()))
            .await
            .unwrap();
        assert_eq!(res.status, 200);
        assert!(
            res.body.contains("checked-dial served"),
            "the scripted answer is what got dialed: {}",
            res.body
        );
        server.await.unwrap();
    }

    #[test]
    fn subresource_fetch_refuses_a_link_local_literal_at_entry() {
        // The bonus hole from iteration 21's design review: navigate and
        // request_data had the bug-25 entry check, subresource_fetch did
        // not -- a link-local literal subresource URL dialed the refused
        // target outright. No listener: the check must fire pre-connect.
        let err = subresource_fetch(
            "https://169.254.169.254/latest/meta-data",
            "GET",
            &[],
            "",
            false,
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::TargetRefused(_)),
            "subresource link-local literal must be TargetRefused, got: {err}"
        );
    }

    #[tokio::test]
    async fn response_reports_the_negotiated_http_version() {
        // The local test server is HTTP/1.1-only, so this pins the plumbing
        // (Response.version populated from the wire). The h2 negotiation
        // itself is verified by scripts/live_smoke.py against the real
        // sites — a real Chrome speaks h2 everywhere, so h1.1 to an
        // h2-capable edge would be an ALPN-level tell.
        let (base, server) = spawn_server(1, |_, _| (200, "version probe".into())).await;
        let client = Client::new(TEST_UA);
        let res = client.get(&base).await.unwrap();
        assert_eq!(res.version, "HTTP/1.1");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn cookies_persist_across_requests_in_a_session() {
        let (base, server) = spawn_server(1, |path, req| {
            if path == "/set" {
                (200, "Set-Cookie: sid=abc; Path=/\r\n".into())
            } else {
                let has = req.contains("sid=abc");
                (200, format!("cookie_seen={has}"))
            }
        })
        .await;
        let client = Client::new(TEST_UA);
        // /set's response is a single connection; emulate the two-request
        // flow with one server by checking jar behavior on a direct set:
        client
            .store()
            .add_cookie_str("sid=abc", &base.parse().unwrap());
        let res = client.get(&format!("{base}/check")).await.unwrap();
        assert_eq!(res.body, "cookie_seen=true");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn injected_playwright_cookie_rides_the_wire_and_enumerates() {
        let (base, server) = spawn_server(1, |_path, req| {
            // headers arrive lowercased (hyper writes them as given);
            // match the Cookie header case-insensitively
            let seen = req
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("cookie:"))
                .unwrap_or("");
            (200, seen.to_string())
        })
        .await;
        let url: url::Url = base.parse().unwrap();
        let host = url.host_str().unwrap().to_string();

        let client = Client::new(TEST_UA);
        let mut entry = CookieEntry::new("c_user", "61593717497664");
        entry.domain = host.clone(); // host-only (no leading dot) for 127.0.0.1
        entry.expires = Some(1_893_456_000); // 2030-01-01, persistent
        assert!(client.store().insert_entry(&entry), "entry lands in store");

        // Domain-matched send: the request carries the injected cookie.
        let res = client.get(&format!("{base}/profile")).await.unwrap();
        assert!(res.body.contains("c_user=61593717497664"), "{}", res.body);

        // Enumeration: the snapshot round-trips name/value/domain/expiry.
        let snap = client.store().snapshot();
        let found = snap.iter().find(|c| c.name == "c_user").expect("in snapshot");
        assert_eq!(found.value, "61593717497664");
        assert_eq!(found.domain, host);
        assert_eq!(found.expires, Some(1_893_456_000));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn session_presents_engine_fingerprint_on_the_wire() {
        // The UA the client presents must be the SAME string the JS tier
        // answers for navigator.userAgent — cf_clearance binds to it — and
        // the Accept headers must read like a browser, not reqwest's */*.
        let (base, server) = spawn_server(1, |_path, req| {
            let pick = |name: &str| {
                req.lines()
                    .find(|l| {
                        let lower = l.to_ascii_lowercase();
                        lower.starts_with(&format!("{name}:"))
                    })
                    .unwrap_or("")
                    .to_string()
            };
            let body = format!(
                "{ua}|{accept}|{lang}|{chua}|{chmobile}|{chplatform}|{uir}|{sfdest}|{sfmode}|{sfsite}|{sfuser}",
                ua = pick("user-agent"),
                accept = pick("accept"),
                lang = pick("accept-language"),
                chua = pick("sec-ch-ua"),
                chmobile = pick("sec-ch-ua-mobile"),
                chplatform = pick("sec-ch-ua-platform"),
                uir = pick("upgrade-insecure-requests"),
                sfdest = pick("sec-fetch-dest"),
                sfmode = pick("sec-fetch-mode"),
                sfsite = pick("sec-fetch-site"),
                sfuser = pick("sec-fetch-user"),
            );
            (200, body)
        })
        .await;
        let client = Client::new(TEST_UA);
        let res = client.get(&format!("{base}/")).await.unwrap();
        let mut parts = res.body.split('|');
        let ua = parts.next().unwrap_or("");
        let accept = parts.next().unwrap_or("");
        let lang = parts.next().unwrap_or("");
        let chua = parts.next().unwrap_or("");
        let chmobile = parts.next().unwrap_or("");
        let chplatform = parts.next().unwrap_or("");
        let uir = parts.next().unwrap_or("");
        let sfdest = parts.next().unwrap_or("");
        let sfmode = parts.next().unwrap_or("");
        let sfsite = parts.next().unwrap_or("");
        let sfuser = parts.next().unwrap_or("");
        assert!(ua.contains("Chrome/145.0.0.0"), "wire UA: {ua}");
        assert!(accept.contains("text/html"), "wire Accept: {accept}");
        assert!(!accept.trim_end().ends_with("*/*"), "reqwest default Accept leaks: {accept}");
        assert!(lang.contains("en-US"), "wire Accept-Language: {lang}");
        // Client hints — the same identity the JS userAgentData answers. A
        // missing or contradicting hint pair is a bot signal.
        let expect = "\"Chromium\";v=\"145\", \"Google Chrome\";v=\"145\", \"Not.A/Brand\";v=\"99\"";
        assert_eq!(chua.trim(), format!("sec-ch-ua: {expect}"), "wire Sec-CH-UA: {chua}");
        assert_eq!(chmobile.trim(), "sec-ch-ua-mobile: ?0", "wire Sec-CH-UA-Mobile: {chmobile}");
        assert_eq!(
            chplatform.trim(),
            "sec-ch-ua-platform: \"Windows\"",
            "wire Sec-CH-UA-Platform: {chplatform}"
        );
        // Fetch Metadata + upgrade-insecure-requests: a real Chrome document
        // navigation carries this signature; edges like Facebook's anonymous
        // tier flat-400 a request without it, before any cookie or JS check.
        assert_eq!(uir.trim(), "upgrade-insecure-requests: 1", "wire UIR: {uir}");
        assert_eq!(sfdest.trim(), "sec-fetch-dest: document", "wire Sec-Fetch-Dest: {sfdest}");
        assert_eq!(sfmode.trim(), "sec-fetch-mode: navigate", "wire Sec-Fetch-Mode: {sfmode}");
        assert_eq!(sfsite.trim(), "sec-fetch-site: none", "wire Sec-Fetch-Site: {sfsite}");
        assert_eq!(sfuser.trim(), "sec-fetch-user: ?1", "wire Sec-Fetch-User: {sfuser}");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn client_hints_constants_drive_the_wire_value() {
        // The JS tier reads these same constants for userAgentData — pin the
        // rendering so the two surfaces cannot drift apart.
        assert_eq!(
            sec_ch_ua(),
            "\"Chromium\";v=\"145\", \"Google Chrome\";v=\"145\", \"Not.A/Brand\";v=\"99\""
        );
        assert_eq!(UA_PLATFORM, "Windows");
        assert_eq!(UA_FULL_VERSION, "145.0.0.0");
    }

    #[tokio::test]
    async fn domain_cookie_matches_subdomains_and_clear_empties_the_store() {
        let store = SessionStore::default();
        let mut entry = CookieEntry::new("sess", "xyz");
        // example.com (unlike the reserved *.test TLD) is not a public
        // suffix, so the store accepts a domain cookie for it.
        entry.domain = ".example.com".to_string();
        entry.secure = true;
        entry.http_only = true;
        assert!(store.insert_entry(&entry));

        // Domain cookies match subdomains: the URL gets the Cookie header.
        // Secure cookies are only matched onto https URLs (RFC 6265 §5.4),
        // hence the scheme below.
        let url = url::Url::parse("https://www.example.com/").unwrap();
        let hv = reqwest::cookie::CookieStore::cookies(&store, &url).expect("header");
        assert_eq!(hv.to_str().unwrap(), "sess=xyz");

        let snap = store.snapshot();
        assert_eq!(snap.len(), 1);
        assert!(snap[0].secure && snap[0].http_only);

        store.clear();
        assert!(store.snapshot().is_empty());
        let url = url::Url::parse("https://www.example.com/").unwrap();
        assert!(reqwest::cookie::CookieStore::cookies(&store, &url).is_none());
    }

    #[test]
    fn insert_entry_rejects_garbage() {
        let store = SessionStore::default();
        assert!(!store.insert_entry(&CookieEntry::new("", "x")));
        let mut bad = CookieEntry::new("n", "v");
        bad.domain = "not a host".to_string();
        assert!(!store.insert_entry(&bad));
    }

    #[test]
    fn expired_cookies_never_snapshot_or_match() {
        let store = SessionStore::default();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mut dead = CookieEntry::new("dead", "1");
        dead.domain = "127.0.0.1".to_string();
        dead.expires = Some(now - 10); // expired ten seconds ago
        // The store REFUSES already-expired entries outright (insert_raw's
        // Expired error) — stronger than storing-and-filtering.
        assert!(!store.insert_entry(&dead));
        let mut alive = CookieEntry::new("alive", "1");
        alive.domain = "127.0.0.1".to_string();
        alive.expires = Some(now + 3600);
        assert!(store.insert_entry(&alive));

        // Enumeration filters expired entries; matching never sends them.
        let names: Vec<String> = store.snapshot().iter().map(|c| c.name.clone()).collect();
        assert_eq!(names, vec!["alive"]);
        let hv = store
            .cookie_header("http://127.0.0.1/")
            .expect("header");
        assert!(hv.contains("alive=1"), "{hv}");
        assert!(!hv.contains("dead"), "{hv}");
    }

    #[test]
    fn max_age_zero_never_rides_and_replacement_value_wins() {
        let store = SessionStore::default();
        let url = "http://127.0.0.1/";
        // Dead on arrival, the way a response sets it (Max-Age=0).
        store.store_set_cookie("gone=1; Max-Age=0; Path=/", url);
        store.store_set_cookie("flip=1; Max-Age=3600; Path=/", url);
        store.store_set_cookie("flip=updated; Max-Age=3600; Path=/", url);

        let hv = store.cookie_header(url).expect("header");
        assert!(hv.contains("flip=updated"), "{hv}");
        assert!(!hv.contains("flip=1"), "replacement value wins: {hv}");
        assert!(!hv.contains("gone"), "Max-Age=0 never rides: {hv}");
        let names: Vec<String> = store.snapshot().iter().map(|c| c.name.clone()).collect();
        assert!(!names.iter().any(|n| n == "gone"), "{names:?}");
        let flip = store
            .snapshot()
            .into_iter()
            .find(|c| c.name == "flip")
            .expect("flip");
        assert_eq!(flip.value, "updated");
    }

    #[tokio::test]
    async fn request_data_posts_method_body_custom_headers_and_rides_session_jar() {
        // The agent-facing data call (firing 37): method + body + custom
        // headers go on the wire, the subresource fetch-metadata block
        // replaces the document one, and — the point of being session-bound —
        // the jar's cookies RIDE (and a response Set-Cookie LANDS).
        let (base, server) = spawn_server(1, |_, req| {
            let find = |name: &str| -> String {
                req.lines()
                    .find(|l| l.to_ascii_lowercase().starts_with(&format!("{name}:")))
                    .unwrap_or("")
                    .to_string()
            };
            // Echo what the data call presented, attribute by attribute.
            (
                200,
                format!(
                    "method={}|ct={}|xc={}|accept={}|site={}|mode={}|dest={}|body={}|cookie={}",
                    req.lines().next().unwrap_or("").split_whitespace().next().unwrap_or(""),
                    find("content-type"),
                    find("x-custom"),
                    find("accept"),
                    find("sec-fetch-site"),
                    find("sec-fetch-mode"),
                    find("sec-fetch-dest"),
                    req.split("\r\n\r\n").nth(1).unwrap_or("").to_string(),
                    find("cookie"),
                ),
            )
        })
        .await;
        let client = Client::new(TEST_UA);
        // Seed the jar directly (first-visit lesson: a Set-Cookie never rides
        // the request that established it, so we plant sess= and prove it
        // RIDES the data call).
        client
            .store()
            .store_set_cookie("sess=abc; Path=/", &format!("{base}/"));

        let res = client
            .request_data(
                &format!("{base}/echo"),
                "POST",
                &[
                    ("Content-Type".to_string(), "application/json".to_string()),
                    ("X-Custom".to_string(), "abc".to_string()),
                ],
                r#"{"k":1}"#,
                Some(&format!("{base}/page")),
                DataKind::Data,
            )
            .await
            .unwrap();
        assert_eq!(res.status, 200);
        let b = res.body;
        assert!(b.contains("method=POST"), "{b}");
        assert!(b.contains("ct=content-type: application/json"), "{b}");
        assert!(b.contains("xc=x-custom: abc"), "{b}");
        assert!(
            b.contains("accept: */*") && !b.contains("text/html"),
            "subresource Accept, never the document one: {b}"
        );
        assert!(b.contains("site=sec-fetch-site: same-origin"), "{b}");
        assert!(b.contains("mode=sec-fetch-mode: cors"), "{b}");
        assert!(b.contains("dest=sec-fetch-dest: empty"), "{b}");
        assert!(
            b.contains("body={\"k\":1}"),
            "the JSON body rides the request: {b}"
        );
        assert!(b.contains("cookie=cookie: sess=abc"), "{b}");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn request_data_without_initiator_is_an_address_bar_call() {
        // No initiator: Sec-Fetch-Site none (like an address-bar fetch),
        // no Referer — and a bad method is a refusal, not a panic.
        let (base, server) = spawn_server(1, |_, req| {
            let site = req
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("sec-fetch-site:"))
                .unwrap_or("")
                .to_string();
            let has_referer = req
                .lines()
                .any(|l| l.to_ascii_lowercase().starts_with("referer:"));
            (200, format!("{site}|referer={has_referer}"))
        })
        .await;
        let client = Client::new(TEST_UA);
        let res = client
            .request_data(&format!("{base}/x"), "PUT", &[], "payload", None, DataKind::Data)
            .await
            .unwrap();
        assert!(res.body.contains("sec-fetch-site: none"), "{}", res.body);
        assert!(res.body.contains("referer=false"), "{}", res.body);
        server.await.unwrap();

        let bad = client
            .request_data(&format!("{base}/x"), "NOT A METHOD", &[], "", None, DataKind::Data)
            .await;
        assert!(bad.is_err(), "a garbage method refuses: {bad:?}");
    }

    #[tokio::test]
    async fn request_data_image_kind_answers_no_cors_image_metadata() {
        // Firing 38: an <img>-shaped load answers no-cors/image with Chrome's
        // image Accept — never the data-call cors/empty + */* block.
        let (base, server) = spawn_server(1, |_, req| {
            let find = |name: &str| -> String {
                req.lines()
                    .find(|l| l.to_ascii_lowercase().starts_with(&format!("{name}:")))
                    .unwrap_or("")
                    .to_string()
            };
            (
                200,
                format!(
                    "accept={}|mode={}|dest={}",
                    find("accept"),
                    find("sec-fetch-mode"),
                    find("sec-fetch-dest"),
                ),
            )
        })
        .await;
        let client = Client::new(TEST_UA);
        let res = client
            .request_data(&format!("{base}/img"), "GET", &[], "", None, DataKind::Image)
            .await
            .unwrap();
        let b = res.body;
        assert!(b.contains("sec-fetch-mode: no-cors"), "{b}");
        assert!(b.contains("sec-fetch-dest: image"), "{b}");
        assert!(
            b.contains("accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"),
            "{b}"
        );
        server.await.unwrap();
    }

    /// Test-only constructor: accepts the dev-localhost self-signed fixture
    /// (`rustls` rejects it — CaUsedAsEndEntity plus hostname mismatch, both
    /// correct refusals in production). Production callers use [`Client::new`].
    fn tls_fixture_client(ua: &str) -> Client {
        let store = Arc::new(SessionStore::default());
        let inner = reqwest::Client::builder()
            .user_agent(ua)
            .default_headers(Client::browser_headers(ua))
            .cookie_provider(store.clone())
            .danger_accept_invalid_certs(true)
            .build()
            .expect("reqwest client builds with default TLS");
        Client {
            inner,
            store,
            ua: ua.to_string(),
        }
    }

    /// The page-context one-shot reports the ALPN-negotiated version
    /// honestly: h2 when the origin offers it, h1.1 when it declines — the
    /// per-origin fork a real browser takes. Direct tier (no page): the
    /// caller's headers go on the h2 wire lowercase, the query survives, and
    /// `danger_accept_invalid_host_certs` covers the self-signed fixture.
    #[test]
    fn subresource_fetch_reports_negotiated_version_honestly() {
        // H2 origin.
        let (base_h2, seen_h2) = spawn_tls_server(TlsMode::H2);
        let url = format!("{base_h2}/probe?x=1");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            // subresource_fetch owns a fresh runtime; it must run on a
            // thread with no runtime context of its own.
            let r = subresource_fetch(
                &url,
                "GET",
                &[("Accept".into(), "*/*".into()), ("Connection".into(), "close".into())],
                "",
                true,
            );
            tx.send(r).unwrap();
        });
        let res = rx.recv().expect("fetch thread").expect("h2 fetch ok");
        assert_eq!(res.status, 200);
        assert_eq!(res.body, "h2 body");
        assert_eq!(res.version, "HTTP/2.0");
        let seen = seen_h2
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("server saw the h2 request");
        assert_eq!(seen.method, "GET");
        assert_eq!(seen.path, "/probe?x=1");
        assert!(
            seen.headers.iter().all(|(n, _)| n.chars().all(|c| c.is_lowercase() || c == '-' || c.is_ascii_digit())),
            "h2 wire names must be lowercase: {seen:?}"
        );
        assert!(
            seen.headers.iter().all(|(n, _)| n != "connection"),
            "hop-by-hop Connection must be stripped for h2: {seen:?}"
        );
        assert!(seen.header("accept").is_some(), "caller Accept arrives: {seen:?}");

        // h1.1-declining origin: same call, version reports the fallback.
        let (base_h1, seen_h1) = spawn_tls_server(TlsMode::H1_1);
        let url = format!("{base_h1}/probe?x=1");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let r = subresource_fetch(&url, "GET", &[], "", true);
            tx.send(r).unwrap();
        });
        let res = rx.recv().expect("fetch thread").expect("h1.1 fetch ok");
        assert_eq!(res.status, 200);
        assert_eq!(res.body, "h1 body");
        assert_eq!(res.version, "HTTP/1.1");
        let seen = seen_h1
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("server saw the h1.1 request");
        assert_eq!(seen.path, "/probe?x=1");
    }

    /// Header ORDER is fingerprinted (Akamai and friends diff it), so the
    /// session client's wire order is pinned here against the headed-Chromium
    /// ground truth captured verbatim by `scripts/capture_chrome_wire.py`
    /// (patchright Chromium 148, address-bar load then followed link):
    ///
    /// ```text
    /// Chrome:  Host, Connection: keep-alive, sec-ch-ua, sec-ch-ua-mobile,
    ///          sec-ch-ua-platform, Upgrade-Insecure-Requests, User-Agent,
    ///          Accept, Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-User,
    ///          Sec-Fetch-Dest, Referer (followed only), Accept-Encoding,
    ///          Accept-Language, Cookie
    /// ```
    ///
    /// `navigate` builds its request BY HAND (see `Client::navigate`) because
    /// reqwest's RequestBuilder path re-orders the map — it prepends its
    /// auto-inserted User-Agent/Accept ahead of the defaults and re-appends
    /// per-request headers in add-order (probed with a scrambled insertion
    /// map during this slice: the tail rides insertion order, but UA/Accept
    /// always encode first and Host always lands last). The manual request
    /// carries exactly `document_headers`' map: User-Agent and Accept sit at
    /// Chrome's true positions, Referer lands between Sec-Fetch-Dest and
    /// Accept-Encoding on a followed navigation, and the jar's Cookie still
    /// trails the map. Two hyper-level deviations remain, both understood at
    /// the mechanism level and asserted below:
    ///
    /// * h1.1 lowercases every name (Chrome capitalizes on h1.1; on the live
    ///   h2 tier lowercase is RFC 7540-correct, so this only reads as a
    ///   loopback artifact), and hyper synthesizes `Host` and appends it
    ///   LAST instead of first.
    /// * On h1.1 the explicit `Connection: keep-alive` rides at the end of
    ///   the block — it must sit at the END of the header map, because
    ///   hyper's h2 codec strips connection headers via
    ///   `http::HeaderMap::remove`, which is a SWAP-remove: from any earlier
    ///   slot the eviction would drag the map's last header (Cookie, when
    ///   the jar rides) into that slot and corrupt the h2 order. From the
    ///   final slot the swap is a pure pop, so on the live h2 tier the
    ///   block — Cookie included — lands in Chrome's exact order.
    ///
    /// (The presence/value side of the fingerprint is the sibling test
    /// `session_presents_engine_fingerprint_on_the_wire`.)
    #[test]
    fn session_wire_order_matches_chrome_fingerprint() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // ---- h1.1 tier: cleartext loopback, two sequential navigations.
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (head_tx, head_rx) = std::sync::mpsc::channel::<String>();
            let server = tokio::spawn(async move {
                loop {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let head_tx = head_tx.clone();
                    tokio::spawn(async move {
                        let mut buf = Vec::new();
                        let mut chunk = [0u8; 4096];
                        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            let n = socket.read(&mut chunk).await.unwrap_or(0);
                            if n == 0 {
                                break;
                            }
                            buf.extend_from_slice(&chunk[..n]);
                        }
                        let head = String::from_utf8_lossy(&buf).to_string();
                        let is_first = head.starts_with("GET /first ");
                        let body = b"ok";
                        // The first response plants a jar cookie so the second
                        // request pins the Cookie position too.
                        let extra = if is_first {
                            "Set-Cookie: sid=abc123; Path=/\r\n"
                        } else {
                            ""
                        };
                        let _ = socket
                            .write_all(
                                format!(
                                    "HTTP/1.1 200 OK\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
                                    body.len()
                                )
                                .as_bytes(),
                            )
                            .await;
                        let _ = socket.write_all(body).await;
                        if !is_first {
                            head_tx.send(head).unwrap();
                        }
                    });
                }
            });
            let client = Client::new(TEST_UA);
            let first = format!("http://{addr}/first");
            client.navigate(&first, None).await.unwrap();
            client
                .navigate(&format!("http://{addr}/second"), Some(&first))
                .await
                .unwrap();
            server.abort();
            let head = head_rx.recv().expect("second request head");
            let lines: Vec<&str> = head.split("\r\n").collect();
            let names: Vec<String> = lines[1..]
                .iter()
                .take_while(|l| !l.is_empty())
                .map(|l| l.split(':').next().unwrap().to_string())
                .collect();
            let expected = [
                "sec-ch-ua",
                "sec-ch-ua-mobile",
                "sec-ch-ua-platform",
                "upgrade-insecure-requests",
                "user-agent",
                "accept",
                "sec-fetch-site",
                "sec-fetch-mode",
                "sec-fetch-user",
                "sec-fetch-dest",
                "referer",
                "accept-encoding",
                "accept-language",
                "connection",
                "cookie",
                "host",
            ];
            assert_eq!(
                names, expected,
                "h1.1 wire order must match the pinned engine fingerprint"
            );
            // Values that make the order mean something.
            let value = |n: &str| -> String {
                lines[1..]
                    .iter()
                    .find(|l| l.split(':').next().unwrap().eq_ignore_ascii_case(n))
                    .unwrap_or_else(|| panic!("missing {n}"))
                    .splitn(2, ':')
                    .nth(1)
                    .unwrap()
                    .trim()
                    .to_string()
            };
            assert_eq!(value("connection"), "keep-alive");
            assert_eq!(value("upgrade-insecure-requests"), "1");
            assert_eq!(value("sec-fetch-site"), "same-origin");
            assert_eq!(value("sec-fetch-mode"), "navigate");
            assert_eq!(value("sec-fetch-user"), "?1");
            assert_eq!(value("sec-fetch-dest"), "document");
            assert_eq!(value("accept-encoding"), "gzip, deflate, br, zstd");
            assert_eq!(
                value("accept"),
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
            );
            assert_eq!(value("referer"), first);
            assert!(
                value("cookie").contains("sid=abc123"),
                "jar cookie rides the followed navigation: {head}"
            );

            // ---- h2 tier: the live fork. Same session shape over TLS; the
            // hop-by-hop Connection name must not reach the h2 frame, every
            // name is lowercase (RFC 7540), and the block must land in
            // Chrome's exact order — Cookie LAST, which only holds because
            // Connection occupies the map's final slot (swap-remove pop).
            let (base, seen_rx) = spawn_tls_server(TlsMode::H2);
            let client = tls_fixture_client(TEST_UA);
            // Seed the jar (host-only for the 127.0.0.1 fixture origin) so
            // the h2 pin covers the Cookie position — the swap-remove case.
            let mut e = CookieEntry::new("sid", "abc123");
            e.domain = "127.0.0.1".to_string();
            assert!(client.store().insert_entry(&e));
            let res = client
                .navigate(&format!("{base}/landing"), None)
                .await
                .unwrap();
            assert_eq!(res.version, "HTTP/2.0");
            let seen = seen_rx
                .recv_timeout(std::time::Duration::from_secs(10))
                .expect("server saw the h2 request");
            assert!(
                seen.headers.iter().all(|(n, _)| {
                    n.chars().all(|c| c.is_lowercase() || c == '-' || c.is_ascii_digit())
                }),
                "h2 wire names must be lowercase: {seen:?}"
            );
            assert!(
                seen.headers.iter().all(|(n, _)| n != "connection"),
                "hop-by-hop Connection must never reach an h2 frame: {seen:?}"
            );
            assert_eq!(
                seen.header("cookie"),
                Some("sid=abc123"),
                "jar cookie rides the h2 request: {seen:?}"
            );
            let seen_names: Vec<&str> = seen.headers.iter().map(|(n, _)| n.as_str()).collect();
            // Exact h2 block: the hand-built map (Connection stripped as
            // hop-by-hop) with the jar's Cookie last — pseudo-headers
            // :method/:authority/:path/:scheme are decoded into the request
            // line/URI by the h2 crate and so don't appear here.
            let expected_h2 = [
                "sec-ch-ua",
                "sec-ch-ua-mobile",
                "sec-ch-ua-platform",
                "upgrade-insecure-requests",
                "user-agent",
                "accept",
                "sec-fetch-site",
                "sec-fetch-mode",
                "sec-fetch-user",
                "sec-fetch-dest",
                "accept-encoding",
                "accept-language",
                "cookie",
            ];
            assert_eq!(
                seen_names, expected_h2,
                "h2 header block must match Chrome's order exactly: {seen:?}"
            );
            assert_eq!(seen.header("accept-encoding"), Some("gzip, deflate, br, zstd"));
            assert_eq!(seen.header("sec-fetch-dest"), Some("document"));
        });
    }

    /// Firing-12's h2 wire ground truth, captured from headed patchright
    /// Chromium 148 against the h2cap fixture (`scripts/capture_h2_wire.py
    /// chrome`) and pinned here as a regression test so a reqwest/hyper
    /// upgrade that silently re-shapes the engine's h2 wire fails loudly.
    ///
    /// Chromium's captured shape:
    /// ```text
    /// SETTINGS: HEADER_TABLE_SIZE=65536, ENABLE_PUSH=0,
    ///           INITIAL_WINDOW_SIZE=6291456, MAX_HEADER_LIST_SIZE=262144
    /// pseudo order: :method, :authority, :scheme, :path
    /// regular order: sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform,
    ///                upgrade-insecure-requests, user-agent, accept,
    ///                sec-fetch-site, sec-fetch-mode, sec-fetch-user,
    ///                sec-fetch-dest, accept-encoding, accept-language,
    ///                cookie, priority
    /// ```
    ///
    /// The engine's measured shape (same fixture, `--engine` self-drive):
    /// ```text
    /// SETTINGS: ENABLE_PUSH=0, INITIAL_WINDOW_SIZE=2097152,
    ///           MAX_FRAME_SIZE=16384, MAX_HEADER_LIST_SIZE=16384
    /// pseudo order: :method, :scheme, :authority, :path
    /// regular order: accept, accept-encoding
    /// ```
    ///
    /// Documented deviations (hyper floor — reqwest/hyper 1.x does not
    /// expose these knobs without forking the codec):
    /// * SETTINGS values: hyper sends ENABLE_PUSH=0, INITIAL_WINDOW_SIZE=2MB,
    ///   MAX_FRAME_SIZE=16KB, MAX_HEADER_LIST_SIZE=16KB; Chromium sends
    ///   HEADER_TABLE_SIZE=64KB, ENABLE_PUSH=0, INITIAL_WINDOW_SIZE=6MB,
    ///   MAX_HEADER_LIST_SIZE=256KB. Interop-safe (all within RFC 7540
    ///   bounds) but fingerprint-visible on the wire.
    /// * Pseudo-header order: hyper sends :method, :scheme, :authority, :path;
    ///   Chromium sends :method, :authority, :scheme, :path. Both are
    ///   RFC 7540-compliant (pseudo-headers must appear before regular
    ///   headers; relative order among them is unspecified) but differ.
    /// * `priority: u=0, i`: Chromium ends every document request with the
    ///   RFC 9218 priority header; hyper has no API for it.
    /// * `cookie`: engine's jar carries it when set; the self-drive bin
    ///   doesn't seed one, so it's absent there.
    #[test]
    fn session_h2_wire_matches_measured_engine_fingerprint() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let acceptor = crate::h2cap::dev_tls_acceptor();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (report_tx, report_rx) = std::sync::mpsc::channel();
            let server = tokio::spawn(async move {
                // Chrome opens 1-3 speculative connections before the
                // request-bearing one (HTTP/3 probe, TLS retry after
                // CertificateUnknown, etc.) — accept up to 4 like the bin.
                let mut report = None;
                for _ in 0..4 {
                    let (tcp, _) = listener.accept().await.unwrap();
                    tcp.set_nodelay(true).ok();
                    match acceptor.accept(tcp).await {
                        Ok(mut tls) => {
                            match crate::h2cap::capture_one(&mut tls, 16).await {
                                Ok(r) => {
                                    report = Some(r);
                                    break;
                                }
                                Err(_) => continue,
                            }
                        }
                        Err(_) => continue,
                    }
                }
                report_tx.send(report).unwrap();
            });
            let client = tls_fixture_client(TEST_UA);
            let res = client
                .navigate(&format!("https://{addr}/landing"), None)
                .await
                .unwrap();
            assert_eq!(res.status, 200);
            let report = report_rx
                .recv_timeout(std::time::Duration::from_secs(15))
                .expect("server thread reports")
                .expect("capture succeeded");
            // Engine SETTINGS: hyper's defaults, measured and pinned.
            let settings = &report.settings;
            assert!(
                settings.contains(&(2u16, 0u32)),
                "ENABLE_PUSH=0 must ride: {settings:?}"
            );
            assert!(
                settings.contains(&(4u16, 2_097_152u32)),
                "INITIAL_WINDOW_SIZE=2097152 (hyper default): {settings:?}"
            );
            assert!(
                settings.contains(&(5u16, 16_384u32)),
                "MAX_FRAME_SIZE=16384 (hyper default): {settings:?}"
            );
            assert!(
                settings.contains(&(6u16, 16_384u32)),
                "MAX_HEADER_LIST_SIZE=16384 (hyper default): {settings:?}"
            );
            // Pseudo-header order: :method, :scheme, :authority, :path.
            let names = report.header_names();
            let pseudo: Vec<&str> = names.iter().take_while(|n| n.starts_with(':')).copied().collect();
            assert_eq!(
                pseudo,
                [":method", ":scheme", ":authority", ":path"],
                "engine h2 pseudo-header order: {names:?}"
            );
            // Regular header order: Chrome-exact after Connection stripped
            // (hyper h2 strip). Cookie absent (jar not seeded here).
            let regular: Vec<&str> = names.iter().skip_while(|n| n.starts_with(':')).copied().collect();
            let expected_regular = [
                "sec-ch-ua",
                "sec-ch-ua-mobile",
                "sec-ch-ua-platform",
                "upgrade-insecure-requests",
                "user-agent",
                "accept",
                "sec-fetch-site",
                "sec-fetch-mode",
                "sec-fetch-user",
                "sec-fetch-dest",
                "accept-encoding",
                "accept-language",
            ];
            assert_eq!(
                regular, expected_regular,
                "engine h2 regular-header order: {names:?}"
            );
            // Sanity on values that make the order meaningful.
            let hv = |n: &str| -> &str {
                report.headers.iter().find(|h| h.name == n).map(|h| h.value.as_str()).unwrap_or("")
            };
            assert_eq!(hv("accept-encoding"), "gzip, deflate, br, zstd");
            assert_eq!(hv("sec-fetch-dest"), "document");
            assert_eq!(hv("upgrade-insecure-requests"), "1");
            assert_eq!(report.path.as_deref(), Some("/landing"));
            assert_eq!(report.method.as_deref(), Some("GET"));
            server.abort();
        });
    }

    /// One-shot TLS fixture for `subresource_fetch`: a std thread running an
    /// inner current_thread runtime (the same discipline the production call
    /// uses), ALPN per `mode`, exactly one connection.
    fn spawn_tls_server(mode: TlsMode) -> (String, std::sync::mpsc::Receiver<SeenRequest>) {
        use std::sync::mpsc as std_mpsc;
        let (addr_tx, addr_rx) = std_mpsc::channel();
        let (seen_tx, seen_rx) = std_mpsc::channel();
        std::thread::spawn(move || {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let bound = listener.local_addr().unwrap();
            addr_tx.send(bound).unwrap();
            let (socket, _) = listener.accept().unwrap();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(serve_one_tls(socket, mode, seen_tx));
        });
        let addr = addr_rx.recv().unwrap();
        (format!("https://{addr}"), seen_rx)
    }

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

    #[derive(Debug, Clone, Copy)]
    enum TlsMode {
        H2,
        H1_1,
    }

    async fn serve_one_tls(
        socket: std::net::TcpStream,
        mode: TlsMode,
        seen_tx: std::sync::mpsc::Sender<SeenRequest>,
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

    #[test]
    fn net_log_ring_keeps_the_last_cap_entries_in_arrival_order() {
        let log = NetLog::default();
        for i in 0..(NET_LOG_CAP + 44) {
            log.record("document", "GET", &format!("http://a.test/{i}"), 200, std::time::Duration::from_millis(i as u64));
        }
        let snap = log.snapshot();
        assert_eq!(snap.len(), NET_LOG_CAP);
        // Oldest survivor is entry 44; seqs strictly increasing, never
        // renumbered by eviction.
        assert_eq!(snap[0].url, "http://a.test/44");
        assert_eq!(snap[0].seq, 44);
        for w in snap.windows(2) {
            assert!(w[1].seq > w[0].seq);
        }
        assert_eq!(snap.last().unwrap().url, format!("http://a.test/{}", NET_LOG_CAP + 43));
        // Recorded fields ride through.
        let e = &snap[1];
        assert_eq!(e.kind, "document");
        assert_eq!(e.method, "GET");
        assert_eq!(e.status, 200);
        assert_eq!(e.elapsed_ms, 45);
    }

    #[test]
    fn net_log_clear_empties_but_seq_stays_monotonic() {
        let log = NetLog::default();
        log.record("fetch", "GET", "http://a.test/1", 200, std::time::Duration::from_millis(1));
        log.clear();
        assert!(log.snapshot().is_empty());
        log.record("xhr", "POST", "http://a.test/2", 201, std::time::Duration::from_millis(2));
        let snap = log.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].seq, 1, "seq is a session lamport clock, not per-snapshot");
        assert_eq!(snap[0].kind, "xhr");
        assert_eq!(snap[0].method, "POST");
        assert_eq!(snap[0].status, 201);
    }
}
