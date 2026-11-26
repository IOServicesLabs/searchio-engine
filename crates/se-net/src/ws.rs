//! The agent's WebSocket tier (firing 39): a hand-rolled RFC 6455 client.
//!
//! The page-side `WebSocket` stub stays shape-only forever — it never opens
//! an in-page socket by design. Instead the AGENT owns the socket through the
//! sidecar verbs `ws_connect` / `ws_send` / `ws_recv` / `ws_close`, so no
//! page script can hang an eval on a live socket and the engine's footprint
//! of the connection (handshake headers like a data call, jar cookies riding
//! the upgrade) is observable end to end. This module is the transport under
//! those verbs. It is deliberately dependency-light (tokio + rustls +
//! getrandom, all already in the tree) in the "own everything observable"
//! ethos — a third-party client would hide the frame layer we want to pin.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::Error;

/// Both plaintext and TLS streams flow through `Box<dyn Stream>` so the frame
/// codec below never matches on which transport it rides.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// One reassembled message as seen by the agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsMessage {
    Text(String),
    Binary(Vec<u8>),
    /// A pong's payload.
    Pong(Vec<u8>),
    /// The peer closed. The connection is finished once this is observed.
    Close { code: u16, reason: String },
}

const MAX_MESSAGE: u64 = 16 * 1024 * 1024;
const MAX_HEADER_BLOCK: usize = 64 * 1024;
/// TCP connect + TLS + opening handshake, as one budget.
const CONNECT_BUDGET: Duration = Duration::from_secs(15);
/// One outbound frame.
const WRITE_BUDGET: Duration = Duration::from_secs(30);
/// RFC 6455 section 5.5: a control frame carries at most 125 bytes.
const MAX_CONTROL: u64 = 125;

const GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// ---------------------------------------------------------------------------
// Hand-rolled SHA-1 (RFC 3174) — needed for Sec-WebSocket-Accept.
// ---------------------------------------------------------------------------

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let bitlen = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(B64[(n >> 6) as usize & 63] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64[n as usize & 63] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// The RFC 6455 §1.3 accept value for a given Sec-WebSocket-Key. Public so the
/// test fixtures (Rust dispatch fixture + the Python wire fixture) can answer
/// a handshake without re-implementing the hash.
pub fn accept_key(key: &str) -> String {
    let mut buf = Vec::with_capacity(key.len() + GUID.len());
    buf.extend_from_slice(key.as_bytes());
    buf.extend_from_slice(GUID);
    b64_encode(&sha1(&buf))
}

// ---------------------------------------------------------------------------
// Frame codec (RFC 6455 §5).
// ---------------------------------------------------------------------------

const OP_CONT: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

fn rand4() -> Result<[u8; 4], Error> {
    let mut m = [0u8; 4];
    getrandom::fill(&mut m).map_err(|e| Error::Ws(format!("rng: {e}")))?;
    Ok(m)
}

/// Encode one frame the way a client must: masked, with the given opcode.
pub(crate) fn encode_frame(opcode: u8, payload: &[u8]) -> Result<Vec<u8>, Error> {
    let mask = rand4()?;
    Ok(encode_frame_with_mask(opcode, payload, mask))
}

fn encode_frame_with_mask(opcode: u8, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(0x80 | opcode);
    let len = payload.len();
    if len < 126 {
        out.push(0x80 | len as u8);
    } else if len <= 0xFFFF {
        out.push(0x80 | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0x80 | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(&mask);
    for (i, b) in payload.iter().enumerate() {
        out.push(b ^ mask[i % 4]);
    }
    out
}

struct FrameHead {
    fin: bool,
    opcode: u8,
    /// Payload mask if the (non-conforming but tolerated) server masked.
    mask: [u8; 4],
    payload_len: u64,
}

/// Parse a frame header from the front of `buf`: `Ok(None)` until the whole
/// header is present. Returns the header and its length in bytes.
fn peek_head(buf: &[u8]) -> Result<Option<(FrameHead, usize)>, Error> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let fin = buf[0] & 0x80 != 0;
    if buf[0] & 0x70 != 0 {
        // No extension is ever negotiated, so a reserved bit is a protocol error.
        return Err(Error::Ws("reserved bits set".into()));
    }
    let opcode = buf[0] & 0x0F;
    let masked = buf[1] & 0x80 != 0;
    let mut at = 2usize;
    let mut payload_len = (buf[1] & 0x7F) as u64;
    if payload_len == 126 {
        if buf.len() < at + 2 {
            return Ok(None);
        }
        payload_len = u16::from_be_bytes([buf[at], buf[at + 1]]) as u64;
        at += 2;
    } else if payload_len == 127 {
        if buf.len() < at + 8 {
            return Ok(None);
        }
        let mut e = [0u8; 8];
        e.copy_from_slice(&buf[at..at + 8]);
        payload_len = u64::from_be_bytes(e);
        at += 8;
    }
    if payload_len > MAX_MESSAGE {
        return Err(Error::Ws(format!("frame too large: {payload_len}")));
    }
    if opcode >= 0x8 && (payload_len > MAX_CONTROL || !fin) {
        return Err(Error::Ws("bad control frame (fragmented or over 125 bytes)".into()));
    }
    let mut mask = [0u8; 4];
    if masked {
        if buf.len() < at + 4 {
            return Ok(None);
        }
        mask.copy_from_slice(&buf[at..at + 4]);
        at += 4;
    }
    Ok(Some((FrameHead { fin, opcode, mask, payload_len }, at)))
}

#[cfg(test)]
async fn read_head(s: &mut (impl AsyncRead + Unpin)) -> Result<FrameHead, Error> {
    let mut b = [0u8; 2];
    s.read_exact(&mut b).await.map_err(|e| Error::Ws(format!("frame head: {e}")))?;
    let fin = b[0] & 0x80 != 0;
    let opcode = b[0] & 0x0F;
    let masked = b[1] & 0x80 != 0;
    let mut payload_len = (b[1] & 0x7F) as u64;
    if payload_len == 126 {
        let mut e = [0u8; 2];
        s.read_exact(&mut e).await.map_err(|e| Error::Ws(format!("frame len: {e}")))?;
        payload_len = u16::from_be_bytes(e) as u64;
    } else if payload_len == 127 {
        let mut e = [0u8; 8];
        s.read_exact(&mut e).await.map_err(|e| Error::Ws(format!("frame len: {e}")))?;
        payload_len = u64::from_be_bytes(e);
    }
    if payload_len > MAX_MESSAGE {
        return Err(Error::Ws(format!("frame too large: {payload_len}")));
    }
    let mut mask = [0u8; 4];
    if masked {
        s.read_exact(&mut mask).await.map_err(|e| Error::Ws(format!("frame mask: {e}")))?;
    }
    Ok(FrameHead { fin, opcode, mask, payload_len })
}

#[cfg(test)]
async fn read_payload(s: &mut (impl AsyncRead + Unpin), len: u64, mask: [u8; 4]) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0u8; len as usize];
    s.read_exact(&mut buf).await.map_err(|e| Error::Ws(format!("frame payload: {e}")))?;
    if mask != [0; 4] {
        for (i, b) in buf.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
    }
    Ok(buf)
}

/// Internal event so a ping is distinguishable from a real (empty) pong.
enum FrameEvent {
    /// A ping arrived; it has been auto-answered per §5.5.3 and is NOT
    /// surfaced to the agent.
    Ping,
    Message(WsMessage),
}

// ---------------------------------------------------------------------------
// WsConn.
// ---------------------------------------------------------------------------

/// One established agent-owned WebSocket. Lives in the Engine's `ws_conns`
/// map between verb calls; the se-serve verbs take it out, run one async op,
/// and put it back (drop on error), so no lock is ever held across an await.
pub struct WsConn {
    stream: Box<dyn Stream>,
    closed: bool,
    /// Bytes read from the socket and not yet consumed as whole frames. The
    /// reader only ever takes COMPLETE frames out of this buffer, so a recv
    /// the caller abandons (the `ws_recv` long-poll timeout) loses nothing:
    /// the next recv resumes on the same frame boundary. Reading the header
    /// and payload straight off the socket dropped a half-read frame on that
    /// timeout and every later frame was parsed from the middle of a payload.
    rbuf: Vec<u8>,
    /// A fragmented message in progress: its opcode and the bytes so far.
    frag: Option<(u8, Vec<u8>)>,
    /// A frame write is in flight. Still set when the next call starts means
    /// the write was abandoned part-way: the outbound stream is desynced and
    /// the connection is finished.
    writing: bool,
    last_used: std::time::Instant,
}

impl WsConn {
    /// Test-only constructor around an in-memory duplex pair.
    #[cfg(test)]
    fn from_stream(s: impl Stream + 'static) -> Self {
        WsConn::new(Box::new(s))
    }

    fn new(stream: Box<dyn Stream>) -> Self {
        WsConn {
            stream,
            closed: false,
            rbuf: Vec::new(),
            frag: None,
            writing: false,
            last_used: std::time::Instant::now(),
        }
    }

    /// Time since the last send or recv on this connection.
    pub fn idle(&self) -> Duration {
        self.last_used.elapsed()
    }

    /// Write one whole frame within the write budget. A write that is cut
    /// short (budget, or the caller dropping the future) poisons the
    /// connection instead of leaving half a frame on the wire.
    async fn write_frame(&mut self, frame: &[u8], what: &str) -> Result<(), Error> {
        if self.writing {
            self.closed = true;
            return Err(Error::Ws("connection desynced by an abandoned write".into()));
        }
        self.writing = true;
        let stream = &mut self.stream;
        let io = async {
            stream.write_all(frame).await?;
            stream.flush().await
        };
        match tokio::time::timeout(WRITE_BUDGET, io).await {
            Ok(Ok(())) => {
                self.writing = false;
                Ok(())
            }
            Ok(Err(e)) => {
                self.closed = true;
                Err(Error::Ws(format!("{what}: {e}")))
            }
            Err(_) => {
                self.closed = true;
                Err(Error::Ws(format!("{what}: timed out")))
            }
        }
    }

    /// Send one message: text or binary.
    pub async fn send(&mut self, data: &[u8], text: bool) -> Result<(), Error> {
        if self.closed {
            return Err(Error::Ws("send on closed connection".into()));
        }
        if data.len() as u64 > MAX_MESSAGE {
            return Err(Error::Ws(format!("message too large: {}", data.len())));
        }
        self.last_used = std::time::Instant::now();
        let frame = encode_frame(if text { OP_TEXT } else { OP_BINARY }, data)?;
        self.write_frame(&frame, "send").await
    }

    /// The RFC 6455 closing handshake: send close(1000), keep draining until
    /// the peer's close echoes back (or the stream dies / 250ms pass).
    pub async fn close(mut self) -> Result<(), Error> {
        if self.closed {
            return Ok(());
        }
        let frame = encode_frame(OP_CLOSE, &1000u16.to_be_bytes())?;
        let _ = tokio::time::timeout(Duration::from_millis(500), self.write_frame(&frame, "close")).await;
        let drain = async {
            loop {
                match self.next_frame().await {
                    Ok(Some(_)) => continue,
                    _ => break,
                }
            }
        };
        let _ = tokio::time::timeout(Duration::from_millis(250), drain).await;
        Ok(())
    }

    /// Take one whole frame off the front of the buffer, unmasked.
    fn take_frame(&mut self) -> Result<Option<(FrameHead, Vec<u8>)>, Error> {
        let Some((head, hlen)) = peek_head(&self.rbuf)? else {
            return Ok(None);
        };
        let total = hlen + head.payload_len as usize;
        if self.rbuf.len() < total {
            return Ok(None);
        }
        let mut payload = self.rbuf[hlen..total].to_vec();
        if head.mask != [0; 4] {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= head.mask[i % 4];
            }
        }
        self.rbuf.drain(..total);
        Ok(Some((head, payload)))
    }

    /// Cancel-safe: the only await that can be abandoned without loss is the
    /// socket `read`, and nothing is consumed from `rbuf` except whole frames.
    async fn next_frame(&mut self) -> Result<Option<FrameEvent>, Error> {
        if self.closed {
            return Ok(None);
        }
        if self.writing {
            self.closed = true;
            return Err(Error::Ws("connection desynced by an abandoned write".into()));
        }
        loop {
            let frame = match self.take_frame() {
                Ok(f) => f,
                Err(e) => {
                    self.closed = true;
                    return Err(e);
                }
            };
            let Some((head, payload)) = frame else {
                let mut chunk = [0u8; 16 * 1024];
                let n = self
                    .stream
                    .read(&mut chunk)
                    .await
                    .map_err(|e| Error::Ws(format!("frame read: {e}")))?;
                if n == 0 {
                    self.closed = true;
                    return Err(Error::Ws("frame read: connection closed".into()));
                }
                self.rbuf.extend_from_slice(&chunk[..n]);
                continue;
            };
            self.last_used = std::time::Instant::now();
            match head.opcode {
                OP_PING => {
                    let pong = encode_frame(OP_PONG, &payload)?;
                    self.write_frame(&pong, "pong").await?;
                    return Ok(Some(FrameEvent::Ping));
                }
                OP_PONG => return Ok(Some(FrameEvent::Message(WsMessage::Pong(payload)))),
                OP_CLOSE => {
                    let (code, reason) = close_parts(&payload);
                    // Section 5.5.1: if we didn't initiate, echo the close back.
                    let echo = encode_frame(OP_CLOSE, &payload)?;
                    let _ = self.write_frame(&echo, "close").await;
                    self.closed = true;
                    return Ok(Some(FrameEvent::Message(WsMessage::Close { code, reason })));
                }
                OP_TEXT | OP_BINARY => {
                    if self.frag.is_some() {
                        self.closed = true;
                        return Err(Error::Ws("new message inside a fragmented one".into()));
                    }
                    if head.fin {
                        return self.finish(head.opcode, payload).map(Some);
                    }
                    self.frag = Some((head.opcode, payload));
                }
                OP_CONT => {
                    let Some((opcode, mut sofar)) = self.frag.take() else {
                        self.closed = true;
                        return Err(Error::Ws("unexpected continuation frame".into()));
                    };
                    sofar.extend_from_slice(&payload);
                    if sofar.len() as u64 > MAX_MESSAGE {
                        self.closed = true;
                        return Err(Error::Ws("message too large".into()));
                    }
                    if head.fin {
                        return self.finish(opcode, sofar).map(Some);
                    }
                    self.frag = Some((opcode, sofar));
                }
                other => {
                    self.closed = true;
                    return Err(Error::Ws(format!("unknown opcode {other}")));
                }
            }
        }
    }

    fn finish(&mut self, opcode: u8, payload: Vec<u8>) -> Result<FrameEvent, Error> {
        if opcode == OP_TEXT {
            match String::from_utf8(payload) {
                Ok(s) => Ok(FrameEvent::Message(WsMessage::Text(s))),
                Err(_) => {
                    self.closed = true;
                    Err(Error::Ws("invalid utf-8 text frame".into()))
                }
            }
        } else {
            Ok(FrameEvent::Message(WsMessage::Binary(payload)))
        }
    }

    /// The agent-facing receive: pings are auto-answered and skipped, so this
    /// returns the next data message, a pong, or a close.
    pub async fn recv(&mut self) -> Result<WsMessage, Error> {
        loop {
            match self.next_frame().await? {
                Some(FrameEvent::Ping) => continue,
                Some(FrameEvent::Message(m)) => return Ok(m),
                None => return Err(Error::Ws("connection closed".into())),
            }
        }
    }
}

fn close_parts(payload: &[u8]) -> (u16, String) {
    let code = if payload.len() >= 2 {
        u16::from_be_bytes([payload[0], payload[1]])
    } else {
        1005
    };
    let reason = if payload.len() > 2 {
        String::from_utf8_lossy(&payload[2..]).into_owned()
    } else {
        String::new()
    };
    (code, reason)
}

// ---------------------------------------------------------------------------
// Opening handshake (RFC 6455 §4, §1.3) and connection setup.
// ---------------------------------------------------------------------------

/// What the caller supplies, all pre-serialized: the engine User-Agent, an
/// engine-or-param Origin, the session jar's full Cookie line for the target
/// host (httpOnly included — the wire form), and optional extra headers.
/// Keeping these as strings lets se-serve stay decoupled from jar/UA
/// internals.
pub struct HandshakeCtx {
    pub ua: String,
    pub origin: Option<String>,
    pub cookie: Option<String>,
    pub headers: Vec<(String, String)>,
}

/// Open an agent-owned WebSocket to `url` (ws:// or wss://).
///
/// Returns the established connection plus the response headers the server
/// sent with its 101, so the sidecar can echo them to the agent (an
/// authentication challenge or a Sec-WebSocket-Protocol negotiation lands
/// there).
pub async fn connect(url: &str, ctx: &HandshakeCtx) -> Result<(WsConn, Vec<(String, String)>), Error> {
    connect_within(url, ctx, CONNECT_BUDGET).await
}

/// `connect` with an explicit budget for TCP + TLS + the opening handshake. A
/// peer that accepts and then says nothing used to hold the verb forever.
pub async fn connect_within(
    url: &str,
    ctx: &HandshakeCtx,
    budget: Duration,
) -> Result<(WsConn, Vec<(String, String)>), Error> {
    match tokio::time::timeout(budget, connect_inner(url, ctx)).await {
        Ok(r) => r,
        Err(_) => Err(Error::Ws(format!("connect: timed out after {} ms", budget.as_millis()))),
    }
}

async fn connect_inner(url: &str, ctx: &HandshakeCtx) -> Result<(WsConn, Vec<(String, String)>), Error> {
    let u = url::Url::parse(url).map_err(|e| Error::Ws(format!("bad url: {e}")))?;
    let secure = match u.scheme() {
        "ws" => false,
        "wss" => true,
        other => return Err(Error::Ws(format!("scheme {other}: want ws:// or wss://"))),
    };
    let host = u
        .host_str()
        .ok_or_else(|| Error::Ws("missing host".into()))?
        .to_string();
    let port = u.port_or_known_default().ok_or_else(|| Error::Ws("missing port".into()))?;

    // The same address policy as every HTTP client in the crate: an answer in
    // a refused class (link-local = cloud metadata, unspecified) poisons the
    // dial. This path used to dial whatever the name resolved to.
    let lookup_host = host.trim_start_matches('[').trim_end_matches(']').to_string();
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((lookup_host.as_str(), port))
        .await
        .map_err(|e| Error::Ws(format!("resolve {host}: {e}")))?
        .collect();
    if let Some(why) = addrs.iter().find_map(|a| crate::refused_ip(a.ip())) {
        return Err(Error::Ws(format!("refused target {host}: {why}")));
    }
    if addrs.is_empty() {
        return Err(Error::Ws(format!("resolve {host}: no addresses")));
    }
    let tcp = tokio::net::TcpStream::connect(&addrs[..])
        .await
        .map_err(|e| Error::Ws(format!("connect {host}:{port}: {e}")))?;
    tcp.set_nodelay(true).map_err(|e| Error::Ws(format!("tcp: {e}")))?;

    let stream: Box<dyn Stream> = if secure {
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(cert);
        }
        let cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
        let name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|e| Error::Ws(format!("server name {host}: {e}")))?;
        let tls = connector
            .connect(name, tcp)
            .await
            .map_err(|e| Error::Ws(format!("tls: {e}")))?;
        Box::new(tls)
    } else {
        Box::new(tcp)
    };

    let mut conn = WsConn::new(stream);
    let headers = handshake(&mut conn, &u, &host, port, secure, ctx).await?;
    Ok((conn, headers))
}

async fn handshake(
    conn: &mut WsConn,
    u: &url::Url,
    host: &str,
    port: u16,
    secure: bool,
    ctx: &HandshakeCtx,
) -> Result<Vec<(String, String)>, Error> {
    let mut key_raw = [0u8; 16];
    getrandom::fill(&mut key_raw).map_err(|e| Error::Ws(format!("rng: {e}")))?;
    let key = b64_encode(&key_raw);
    let origin = ctx
        .origin
        .clone()
        .unwrap_or_else(|| format!("{scheme}://{host}:{port}", scheme = if secure { "https" } else { "http" }));

    let host_header = if u.port().is_some() {
        format!("{host}:{port}")
    } else {
        host.to_string()
    };

    let mut path = u.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(q) = u.query() {
        path.push('?');
        path.push_str(q);
    }

    let mut req = String::new();
    req.push_str(&format!("GET {path} HTTP/1.1\r\n"));
    req.push_str(&format!("Host: {host_header}\r\n"));
    req.push_str("Connection: Upgrade\r\n");
    req.push_str("Upgrade: websocket\r\n");
    req.push_str(&format!("Origin: {origin}\r\n"));
    req.push_str(&format!("Sec-WebSocket-Key: {key}\r\n"));
    req.push_str("Sec-WebSocket-Version: 13\r\n");
    req.push_str(&format!("User-Agent: {}\r\n", ctx.ua));
    if let Some(c) = &ctx.cookie {
        if !c.is_empty() {
            req.push_str(&format!("Cookie: {c}\r\n"));
        }
    }
    for (k, v) in &ctx.headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");

    conn.stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| Error::Ws(format!("handshake send: {e}")))?;
    conn.stream.flush().await.map_err(|e| Error::Ws(format!("flush: {e}")))?;

    // Read the status + headers until the blank line, capped.
    // A server may put its first frame in the same segment as the 101: the
    // header block ends at the FIRST blank line and everything after it is
    // frame data. Waiting for the buffer to END with the blank line read
    // those frame bytes as headers (and then hung, or ran to the cap).
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > MAX_HEADER_BLOCK {
            return Err(Error::Ws("handshake headers too large".into()));
        }
        let n = conn
            .stream
            .read(&mut chunk)
            .await
            .map_err(|e| Error::Ws(format!("handshake recv: {e}")))?;
        if n == 0 {
            return Err(Error::Ws("handshake: connection closed".into()));
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    conn.rbuf.extend_from_slice(&buf[head_end..]);
    buf.truncate(head_end);

    let head = String::from_utf8_lossy(&buf);
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut parts = status_line.split_whitespace();
    let _version = parts.next().unwrap_or("");
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::Ws(format!("handshake: bad status line {status_line:?}")))?;
    let mut resp_headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            // Lowercased names, matching Response.headers' shape elsewhere in
            // the engine.
            resp_headers.push((k.trim().to_lowercase(), v.trim().to_string()));
        }
    }
    if status != 101 {
        return Err(Error::Ws(format!("handshake: expected 101, got {status}")));
    }
    let find = |name: &str| -> Option<String> {
        resp_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    };
    let accept = find("sec-websocket-accept")
        .ok_or_else(|| Error::Ws("handshake: no Sec-WebSocket-Accept".into()))?;
    if accept.trim() != accept_key(&key) {
        return Err(Error::Ws("handshake: Sec-WebSocket-Accept mismatch".into()));
    }
    if let Some(up) = find("upgrade") {
        if !up.eq_ignore_ascii_case("websocket") {
            return Err(Error::Ws(format!("handshake: Upgrade: {up}")));
        }
    }
    Ok(resp_headers)
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn sha1_vectors_and_accept_key() {
        // RFC 3174 test vectors.
        assert_eq!(hex(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        let long = vec![b'a'; 1_000_000];
        assert_eq!(hex(&sha1(&long)), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
        // RFC 6455 §1.3 worked example.
        assert_eq!(accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn base64_encodes() {
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(b64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn masked_frame_matches_rfc_5_3_vector() {
        // §5.3: masking "Hello" with 37 fa 21 3d must yield 7f 9f 4d 51 58.
        let frame = encode_frame_with_mask(OP_TEXT, b"Hello", [0x37, 0xfa, 0x21, 0x3d]);
        assert_eq!(frame, vec![0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58]);
    }

    #[tokio::test]
    async fn length_boundaries_round_trip() {
        for len in [0usize, 1, 125, 126, 127, 65535, 65536] {
            let payload = vec![0xABu8; len];
            let frame = encode_frame(OP_BINARY, &payload).expect("encode");
            let (mut a, b) = duplex(frame.len() + 16);
            a.write_all(&frame).await.unwrap();
            let mut conn = WsConn::from_stream(b);
            let head = read_head(&mut conn.stream).await.unwrap();
            assert_eq!(head.opcode, OP_BINARY);
            assert!(head.fin);
            assert_eq!(head.payload_len, len as u64);
            let got = read_payload(&mut conn.stream, head.payload_len, head.mask).await.unwrap();
            assert_eq!(got, payload, "len {len}");
        }
    }

    #[tokio::test]
    async fn ping_is_auto_ponged_and_not_surfaced() {
        let (mut server, client) = duplex(2048);
        // Server sends a ping for "abc", then a text frame "yo".
        let mut script = Vec::new();
        script.extend_from_slice(&[0x89, 0x03]);
        script.extend_from_slice(b"abc");
        script.extend_from_slice(&[0x81, 0x02]);
        script.extend_from_slice(b"yo");
        server.write_all(&script).await.unwrap();
        server.shutdown().await.unwrap();
        let mut conn = WsConn::from_stream(client);
        let msg = conn.recv().await.unwrap();
        assert_eq!(msg, WsMessage::Text("yo".into()));
        // The auto-pong should be sitting on the server half: 8A, masked len 3.
        let mut got = vec![0u8; 2 + 4 + 3];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got[0], 0x8A);
        assert_eq!(got[1] & 0x80, 0x80);
        assert_eq!(got[1] & 0x7F, 3);
        let mask = [got[2], got[3], got[4], got[5]];
        let payload: Vec<u8> = got[6..].iter().enumerate().map(|(i, b)| b ^ mask[i % 4]).collect();
        assert_eq!(payload, b"abc");
    }

    #[tokio::test]
    async fn fragmented_text_is_reassembled() {
        let (mut server, client) = duplex(1024);
        let mut script = Vec::new();
        // FIN=0 text "Hel", then FIN=1 continuation "lo".
        script.extend_from_slice(&[0x01, 0x03]);
        script.extend_from_slice(b"Hel");
        script.extend_from_slice(&[0x80, 0x02]);
        script.extend_from_slice(b"lo");
        server.write_all(&script).await.unwrap();
        server.shutdown().await.unwrap();
        let mut conn = WsConn::from_stream(client);
        assert_eq!(conn.recv().await.unwrap(), WsMessage::Text("Hello".into()));
    }

    #[tokio::test]
    async fn close_frame_echoes_and_reports_code() {
        let (mut server, client) = duplex(1024);
        let mut script = vec![0x88, 0x06];
        script.extend_from_slice(&[0x03, 0xE8]); // code 1000
        script.extend_from_slice(b"done");
        server.write_all(&script).await.unwrap();
        server.shutdown().await.unwrap();
        let mut conn = WsConn::from_stream(client);
        assert_eq!(
            conn.recv().await.unwrap(),
            WsMessage::Close { code: 1000, reason: "done".into() }
        );
        // Client must have echoed the close payload (masked).
        let mut got = vec![0u8; 2 + 4 + 6];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got[0], 0x88);
        let mask = [got[2], got[3], got[4], got[5]];
        let payload: Vec<u8> = got[6..].iter().enumerate().map(|(i, b)| b ^ mask[i % 4]).collect();
        assert_eq!(&payload[..2], &1000u16.to_be_bytes());
        assert_eq!(&payload[2..], b"done");
    }

    #[tokio::test]
    async fn an_abandoned_recv_does_not_desync_the_stream() {
        let (mut server, client) = duplex(4096);
        let mut conn = WsConn::from_stream(client);
        // Header and half the payload of "hello world", then silence.
        server.write_all(&[0x81, 0x0B]).await.unwrap();
        server.write_all(b"hello").await.unwrap();
        let timed_out = tokio::time::timeout(Duration::from_millis(60), conn.recv()).await;
        assert!(timed_out.is_err(), "half a frame is not a message");
        // The rest arrives, then a second message.
        server.write_all(b" world").await.unwrap();
        server.write_all(&[0x81, 0x02]).await.unwrap();
        server.write_all(b"ok").await.unwrap();
        assert_eq!(conn.recv().await.unwrap(), WsMessage::Text("hello world".into()));
        assert_eq!(conn.recv().await.unwrap(), WsMessage::Text("ok".into()));
    }

    #[tokio::test]
    async fn an_abandoned_recv_mid_fragment_keeps_the_pieces() {
        let (mut server, client) = duplex(4096);
        let mut conn = WsConn::from_stream(client);
        server.write_all(&[0x01, 0x03]).await.unwrap();
        server.write_all(b"Hel").await.unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(60), conn.recv()).await.is_err());
        server.write_all(&[0x80, 0x02]).await.unwrap();
        server.write_all(b"lo").await.unwrap();
        assert_eq!(conn.recv().await.unwrap(), WsMessage::Text("Hello".into()));
    }

    #[tokio::test]
    async fn a_ping_between_fragments_is_answered_not_fatal() {
        let (mut server, client) = duplex(4096);
        let mut script = Vec::new();
        script.extend_from_slice(&[0x01, 0x03]);
        script.extend_from_slice(b"Hel");
        script.extend_from_slice(&[0x89, 0x01, b'p']); // ping inside the message
        script.extend_from_slice(&[0x80, 0x02]);
        script.extend_from_slice(b"lo");
        server.write_all(&script).await.unwrap();
        let mut conn = WsConn::from_stream(client);
        assert_eq!(conn.recv().await.unwrap(), WsMessage::Text("Hello".into()));
        let mut got = vec![0u8; 2 + 4 + 1];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got[0], 0x8A, "the ping was answered");
    }

    #[tokio::test]
    async fn bad_control_frames_and_reserved_bits_are_refused() {
        for script in [
            vec![0x89u8, 0x7E, 0x00, 0x7E], // ping claiming 126 bytes
            vec![0x09, 0x00],               // fragmented ping
            vec![0xC1, 0x00],               // RSV1 with no extension negotiated
        ] {
            let (mut server, client) = duplex(64);
            server.write_all(&script).await.unwrap();
            let mut conn = WsConn::from_stream(client);
            assert!(conn.recv().await.is_err(), "{script:02x?}");
            // A protocol error finishes the connection.
            assert!(conn.send(b"x", true).await.is_err());
        }
    }

    #[tokio::test]
    async fn a_frame_sent_with_the_101_is_not_lost() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let mut req = Vec::new();
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = sock.read(&mut buf).await.unwrap();
                req.extend_from_slice(&buf[..n]);
            }
            let text = String::from_utf8_lossy(&req).to_string();
            let key = text
                .lines()
                .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
                .unwrap()
                .trim()
                .to_string();
            // 101 and the first frame in ONE write.
            let mut out = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                accept_key(&key)
            )
            .into_bytes();
            out.extend_from_slice(&[0x81, 0x05]);
            out.extend_from_slice(b"early");
            sock.write_all(&out).await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
        let ctx = HandshakeCtx { ua: "t".into(), origin: None, cookie: None, headers: vec![] };
        let (mut conn, headers) = connect(&format!("ws://127.0.0.1:{port}/"), &ctx).await.unwrap();
        assert!(headers.iter().any(|(k, _)| k == "sec-websocket-accept"));
        let got = tokio::time::timeout(Duration::from_secs(1), conn.recv()).await;
        assert_eq!(got.expect("the early frame is delivered").unwrap(), WsMessage::Text("early".into()));
    }

    #[tokio::test]
    async fn a_silent_server_fails_the_connect_inside_the_budget() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (_sock, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await; // accepts, never answers
        });
        let ctx = HandshakeCtx { ua: "t".into(), origin: None, cookie: None, headers: vec![] };
        let t0 = std::time::Instant::now();
        let err = connect_within(&format!("ws://127.0.0.1:{port}/"), &ctx, Duration::from_millis(200))
            .await
            .err()
            .expect("no handshake answer is a failure")
            .to_string();
        assert!(err.contains("timed out"), "{err}");
        assert!(t0.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn a_link_local_target_is_refused_before_the_dial() {
        let ctx = HandshakeCtx { ua: "t".into(), origin: None, cookie: None, headers: vec![] };
        let err = connect("ws://169.254.169.254/latest", &ctx).await.err().unwrap().to_string();
        assert!(err.contains("refused target") && err.contains("link_local"), "{err}");
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected() {
        let (mut server, client) = duplex(64);
        // 127 + a huge u64 length.
        server.write_all(&[0x82, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).await.unwrap();
        server.shutdown().await.unwrap();
        let mut conn = WsConn::from_stream(client);
        let err = conn.recv().await.unwrap_err().to_string();
        assert!(err.contains("too large"), "{err}");
    }

    #[tokio::test]
    async fn server_masked_frame_is_tolerated() {
        let (mut server, client) = duplex(1024);
        // A masked (non-conforming but tolerated) text frame, mask 01 02 03 04.
        let payload: Vec<u8> = b"hi".iter().enumerate().map(|(i, b)| b ^ [1u8, 2, 3, 4][i % 4]).collect();
        server.write_all(&[0x81, 0x82, 1, 2, 3, 4]).await.unwrap();
        server.write_all(&payload).await.unwrap();
        server.shutdown().await.unwrap();
        let mut conn = WsConn::from_stream(client);
        assert_eq!(conn.recv().await.unwrap(), WsMessage::Text("hi".into()));
    }
}
