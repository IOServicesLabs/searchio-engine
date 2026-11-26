//! Browser TLS + HTTP/2 impersonation (`SE_TLS_IMPERSONATE`).
//!
//! The default client speaks rustls: a correct TLS stack whose ClientHello no
//! browser sends (no GREASE, no ALPS, no extension permutation, a different
//! cipher list). Edge vendors score that hello before any byte of HTTP, so a
//! perfect Chrome header block still draws a 403. This module carries the
//! same requests over a BoringSSL client configured as the Chrome the session
//! already claims to be: Chrome's ClientHello, ALPN, h2 SETTINGS,
//! WINDOW_UPDATE, pseudo-header order and priority.
//!
//! Everything above the transport is unchanged and shared with the default
//! client: the hand-built header maps, the session cookie jar, the guarded
//! resolver, the redirect guard, the body caps.

use std::sync::Arc;

use futures_util::StreamExt;
use http::{HeaderMap, HeaderValue};

use crate::{refused_ip, refused_target, Error, GuardedResolver, SessionStore};

/// What one exchange hands back to the shared response builder.
pub(crate) struct Raw {
    pub final_url: String,
    pub status: u16,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub bytes: Vec<u8>,
}

struct Jar(Arc<SessionStore>);

impl wreq::cookie::CookieStore for Jar {
    fn set_cookies(
        &self,
        cookie_headers: &mut dyn Iterator<Item = &HeaderValue>,
        uri: &wreq::Uri,
    ) {
        let Ok(url) = url::Url::parse(&uri.to_string()) else {
            return;
        };
        reqwest::cookie::CookieStore::set_cookies(&*self.0, cookie_headers, &url);
    }

    fn cookies(&self, uri: &wreq::Uri, _version: wreq::Version) -> wreq::cookie::Cookies {
        let Ok(url) = url::Url::parse(&uri.to_string()) else {
            return wreq::cookie::Cookies::Empty;
        };
        // One combined field on every version: what the default client
        // sends, and what Chrome sends on h1; on h2 Chrome splits crumbs,
        // which HPACK-level observers can see but origin servers cannot.
        match reqwest::cookie::CookieStore::cookies(&*self.0, &url) {
            Some(v) => wreq::cookie::Cookies::Compressed(v),
            None => wreq::cookie::Cookies::Empty,
        }
    }
}

struct Dns(Arc<GuardedResolver>);

impl wreq::dns::Resolve for Dns {
    fn resolve(&self, name: wreq::dns::Name) -> wreq::dns::Resolving {
        let lookup = self.0.lookup.clone();
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
            Ok(Box::new(out.into_iter()) as wreq::dns::Addrs)
        })
    }
}

fn map_err(err: wreq::Error) -> Error {
    let mut src = std::error::Error::source(&err);
    while let Some(e) = src {
        let msg = e.to_string();
        if let Some(why) = msg.strip_prefix("target_refused: ") {
            return Error::TargetRefused(why.to_string());
        }
        src = e.source();
    }
    Error::Http(crate::error_chain(&err))
}

/// The Chrome profile matching the major the session's UA and client hints
/// name (`CHROME_BRANDS`). A hello from a different major than the UA is
/// itself a signal.
fn profile() -> wreq_util::Profile {
    match crate::CHROME_BRANDS[0].1 {
        "140" => wreq_util::Profile::Chrome140,
        "141" => wreq_util::Profile::Chrome141,
        "142" => wreq_util::Profile::Chrome142,
        "143" => wreq_util::Profile::Chrome143,
        "144" => wreq_util::Profile::Chrome144,
        "146" => wreq_util::Profile::Chrome146,
        "147" => wreq_util::Profile::Chrome147,
        "148" => wreq_util::Profile::Chrome148,
        "149" => wreq_util::Profile::Chrome149,
        _ => wreq_util::Profile::Chrome145,
    }
}

#[derive(Clone)]
pub(crate) struct ImpClient {
    inner: wreq::Client,
}

impl ImpClient {
    pub(crate) fn build(
        _ua: &str,
        connect: std::time::Duration,
        overall: std::time::Duration,
        resolver: Arc<GuardedResolver>,
        store: Arc<SessionStore>,
    ) -> Result<Self, String> {
        let emulation = wreq_util::Emulation::builder()
            .profile(profile())
            .platform(wreq_util::Platform::Windows)
            // The engine builds every header block by hand, in Chrome's
            // order; the profile contributes the transport only.
            .headers(false)
            .build();
        let mut builder = wreq::Client::builder()
            .emulation(emulation)
            .cookie_provider(Arc::new(Jar(store)))
            .connect_timeout(connect)
            .timeout(overall)
            .read_timeout(overall.min(std::time::Duration::from_secs(15)))
            .redirect(wreq::redirect::Policy::custom(|attempt| {
                if let Some(why) = refused_target(&attempt.uri.to_string()) {
                    attempt.error(format!("target_refused: {why}"))
                } else if attempt.previous.len() > 10 {
                    attempt.error("too many redirects")
                } else {
                    attempt.follow()
                }
            }))
            .dns_resolver(Arc::new(Dns(resolver)));
        if let Some(proxy) = std::env::var("SE_PROXY")
            .ok()
            .filter(|p| !p.trim().is_empty())
            .and_then(|p| wreq::Proxy::all(p.trim().to_string()).ok())
        {
            builder = builder.proxy(proxy);
        }
        let inner = builder.build().map_err(|e| e.to_string())?;
        Ok(Self { inner })
    }

    /// The page-fetch flavour: no redirect following (the bridge follows
    /// hop by hop under the fetch spec's rules) and no jar (the bridge sets
    /// Cookie itself from the session store).
    pub(crate) fn build_subresource(resolver: Arc<GuardedResolver>) -> Result<Self, String> {
        let emulation = wreq_util::Emulation::builder()
            .profile(profile())
            .platform(wreq_util::Platform::Windows)
            .headers(false)
            .build();
        let inner = wreq::Client::builder()
            .emulation(emulation)
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30))
            .redirect(wreq::redirect::Policy::none())
            .dns_resolver(Arc::new(Dns(resolver)))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self { inner })
    }

    pub(crate) async fn execute(
        &self,
        method: &str,
        url: &str,
        headers: HeaderMap,
        body: Option<String>,
        cap: u64,
        what: &str,
    ) -> Result<Raw, Error> {
        let method = wreq::Method::from_bytes(method.as_bytes())
            .map_err(|e| Error::Http(format!("bad method {method:?}: {e}")))?;
        let mut headers = headers;
        // Chrome's h2 requests end with the RFC 9218 priority field (a
        // navigation is u=0, a fetch u=1); the rustls path never sent it.
        if !headers.contains_key("priority") {
            let v = if what == "document" { "u=0, i" } else { "u=1, i" };
            headers.insert("priority", HeaderValue::from_static(v));
        }
        headers.remove(http::header::CONNECTION);
        let mut req = self.inner.request(method, url).headers(headers);
        if let Some(body) = body {
            req = req.body(body);
        }
        let res = req.send().await.map_err(map_err)?;
        let final_url = res.uri().to_string();
        let status = res.status().as_u16();
        let version = format!("{:?}", res.version());
        let resp_headers: Vec<(String, String)> = res
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let encoded = res
            .headers()
            .get(http::header::CONTENT_ENCODING)
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
        let mut stream = res.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(map_err)?;
            if buf.len() as u64 + chunk.len() as u64 > cap {
                return Err(Error::TooLarge(format!(
                    "{what}: decoded body exceeds cap {cap}"
                )));
            }
            buf.extend_from_slice(&chunk);
        }
        Ok(Raw {
            final_url,
            status,
            version,
            headers: resp_headers,
            bytes: buf,
        })
    }
}
