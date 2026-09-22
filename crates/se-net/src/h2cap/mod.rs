//! Minimal HTTP/2 capture fixture -- ground-truth h2 wire logging.
//!
//! The `h2` crate's `hpack` module is private, so a capture that decodes a
//! HEADERS block needs its own decoder. This one implements exactly the RFC
//! 7541 primitives a fresh client connection can produce:
//!
//! - integer decode with N-bit prefix (section 5.1)
//! - string decode with optional Huffman (section 5.2, Huffman via
//!   `ENCODE_TABLE` copied verbatim from the h2 crate's generated table)
//! - the full 61-entry static table (section 2.3.1 -- same indices as the
//!   `h2` crate's `index_static`, verified against registry source)
//! - dynamic-table indexing for entries beyond 61 (RFC section 2.3.3:
//!   index 62 is the most-recent entry, 63 the next, and so on)
//!
//! The capture response sidesteps the encoder entirely: a HEADERS frame
//! whose block is the single static byte `0x88` (indexed `:status: 200`)
//! followed by END_HEADERS | END_STREAM.
//!
//! Produced by firing 12 of the standing loop; feeds
//! `scripts/capture_h2_wire.py` (headed Chromium) and the `--engine`
//! self-drive, and the `session_h2_wire_matches_fingerprint` test pins the
//! engine's shape.

mod huffman_table;

use std::time::{Duration, Instant};

/// One decoded header field, in wire order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedHeader {
    pub name: String,
    pub value: String,
}

/// Everything observable about one client's first h2 exchange.
#[derive(Debug, Clone, Default)]
pub struct CaptureReport {
    /// The raw 24-byte client connection preface.
    pub preface: Option<[u8; 24]>,
    /// SETTINGS id/value pairs in arrival order. Well-known ids: 1
    /// HEADER_TABLE_SIZE, 2 ENABLE_PUSH, 3 MAX_CONCURRENT_STREAMS,
    /// 4 INITIAL_WINDOW_SIZE, 5 MAX_FRAME_SIZE, 6 MAX_HEADER_LIST_SIZE.
    pub settings: Vec<(u16, u32)>,
    /// Decoded request headers in wire order (pseudo headers first, in the
    /// order the client emitted them).
    pub headers: Vec<DecodedHeader>,
    /// Path carried by the `:path` pseudo header.
    pub path: Option<String>,
    /// Authority carried by the `:authority` pseudo header.
    pub authority: Option<String>,
    /// Method carried by the `:method` pseudo header.
    pub method: Option<String>,
    /// Every frame after the request HEADERS block, in arrival order --
    /// `(frame_type, flags, stream_id, length)`.
    pub trailing_frames: Vec<(u8, u8, u32, u32)>,
    /// Wall time from preface to the request HEADERS block.
    pub head_latency: Option<Duration>,
}

impl CaptureReport {
    /// Names in wire order (the fingerprint's positional signature).
    pub fn header_names(&self) -> Vec<&str> {
        self.headers.iter().map(|h| h.name.as_str()).collect()
    }

    /// Human-readable report for the CLI / capture script.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "preface: {}\n",
            self.preface
                .map(|p| String::from_utf8_lossy(&p).into_owned())
                .unwrap_or_else(|| "<none>".into())
        ));
        out.push_str(&format!("head_latency: {:?}\n", self.head_latency));
        out.push_str("settings:\n");
        for (id, val) in &self.settings {
            out.push_str(&format!("  {} = {}\n", settings_name(*id), val));
        }
        out.push_str("headers (wire order):\n");
        for h in &self.headers {
            let v = if h.name == "cookie" || h.name == "authorization" {
                // Cookies can carry session material; keep the report
                // diffable without leaking it.
                format!("{} bytes", h.value.len())
            } else {
                h.value.clone()
            };
            out.push_str(&format!("  {}: {}\n", h.name, v));
        }
        out.push_str("trailing frames:\n");
        for (ty, flags, sid, len) in &self.trailing_frames {
            out.push_str(&format!(
                "  type={} flags=0x{:02x} stream={} len={}\n",
                frame_name(*ty),
                flags,
                sid,
                len
            ));
        }
        out
    }
}

fn settings_name(id: u16) -> &'static str {
    match id {
        1 => "HEADER_TABLE_SIZE",
        2 => "ENABLE_PUSH",
        3 => "MAX_CONCURRENT_STREAMS",
        4 => "INITIAL_WINDOW_SIZE",
        5 => "MAX_FRAME_SIZE",
        6 => "MAX_HEADER_LIST_SIZE",
        8 => "ENABLE_CONNECT_PROTOCOL",
        9 => "SETTINGS_NO_RFC7540_PRIORITIES",
        _ => "UNKNOWN",
    }
}

fn frame_name(ty: u8) -> &'static str {
    match ty {
        0 => "DATA",
        1 => "HEADERS",
        2 => "PRIORITY",
        3 => "RST_STREAM",
        4 => "SETTINGS",
        5 => "PUSH_PROMISE",
        6 => "PING",
        7 => "GOAWAY",
        8 => "WINDOW_UPDATE",
        9 => "CONTINUATION",
        _ => "UNKNOWN",
    }
}

// ---- HPACK decode ----

/// RFC 7541 section 2.3.1 static table, indices 1..=61. Entry 0 is unused.
const STATIC_TABLE: [&[&str]; 62] = [
    &["", ""],
    &[":authority", ""],
    &[":method", "GET"],
    &[":method", "POST"],
    &[":path", "/"],
    &[":path", "/index.html"],
    &[":scheme", "http"],
    &[":scheme", "https"],
    &[":status", "200"],
    &[":status", "204"],
    &[":status", "206"],
    &[":status", "304"],
    &[":status", "400"],
    &[":status", "404"],
    &[":status", "500"],
    &["accept-charset", ""],
    &["accept-encoding", "gzip, deflate"],
    &["accept-language", ""],
    &["accept-ranges", ""],
    &["accept", ""],
    &["access-control-allow-origin", ""],
    &["age", ""],
    &["allow", ""],
    &["authorization", ""],
    &["cache-control", ""],
    &["content-disposition", ""],
    &["content-encoding", ""],
    &["content-language", ""],
    &["content-length", ""],
    &["content-location", ""],
    &["content-range", ""],
    &["content-type", ""],
    &["cookie", ""],
    &["date", ""],
    &["etag", ""],
    &["expect", ""],
    &["expires", ""],
    &["from", ""],
    &["host", ""],
    &["if-match", ""],
    &["if-modified-since", ""],
    &["if-none-match", ""],
    &["if-range", ""],
    &["if-unmodified-since", ""],
    &["last-modified", ""],
    &["link", ""],
    &["location", ""],
    &["max-forwards", ""],
    &["proxy-authenticate", ""],
    &["proxy-authorization", ""],
    &["range", ""],
    &["referer", ""],
    &["refresh", ""],
    &["retry-after", ""],
    &["server", ""],
    &["set-cookie", ""],
    &["strict-transport-security", ""],
    &["transfer-encoding", ""],
    &["user-agent", ""],
    &["vary", ""],
    &["via", ""],
    &["www-authenticate", ""],
];

/// One dynamic-table entry (added only when a literal uses incremental
/// indexing, 0x40 flag).
#[derive(Debug)]
struct DynEntry {
    name: String,
    value: String,
}

struct HpackDecoder {
    dyn_table: Vec<DynEntry>,
}

impl HpackDecoder {
    fn new() -> Self {
        Self { dyn_table: Vec::new() }
    }

    /// Resolve a (possibly dynamic) table index to a name/value pair.
    fn resolve(&self, index: usize) -> Result<(String, String), String> {
        if index == 0 {
            return Err("HPACK index 0".into());
        }
        if index < 62 {
            let e = STATIC_TABLE[index];
            return Ok((e[0].to_string(), e[1].to_string()));
        }
        let dyn_idx = index - 62;
        if dyn_idx >= self.dyn_table.len() {
            return Err(format!(
                "HPACK index {} beyond dynamic table (len {})",
                index,
                self.dyn_table.len()
            ));
        }
        // RFC 7541 section 2.3.3: most-recent entry is the highest index.
        let e = &self.dyn_table[self.dyn_table.len() - 1 - dyn_idx];
        Ok((e.name.clone(), e.value.clone()))
    }

    /// Decode a complete header block (the caller assembles any
    /// CONTINUATION fragments first).
    fn decode_block(&mut self, block: &[u8]) -> Result<Vec<DecodedHeader>, String> {
        let mut headers = Vec::new();
        let mut pos = 0usize;
        while pos < block.len() {
            let byte = block[pos];
            if byte & 0x80 != 0 {
                // Section 6.1 Indexed Header Field.
                let (index, used) = decode_int(block, pos, 7)?;
                pos += used;
                let (name, value) = self.resolve(index)?;
                headers.push(DecodedHeader { name, value });
            } else if byte & 0x40 != 0 {
                // Section 6.2.1 Literal with Incremental Indexing -- 0x40
                // set, 6-bit prefix. (Checked BEFORE the 0x20 dynamic-table
                // size update because 0x40|0x20 patterns start with 0x40.)
                let (name_index, used) = decode_int(block, pos, 6)?;
                pos += used;
                let name = if name_index == 0 {
                    let (s, used) = decode_string(block, pos)?;
                    pos += used;
                    s
                } else {
                    self.resolve(name_index)?.0
                };
                let (value, used) = decode_string(block, pos)?;
                pos += used;
                self.dyn_table.push(DynEntry {
                    name: name.clone(),
                    value: value.clone(),
                });
                headers.push(DecodedHeader { name, value });
            } else if byte & 0xe0 == 0x20 {
                // Section 6.3 Dynamic Table Size Update -- affects eviction,
                // which we don't model; skip.
                let (_size, used) = decode_int(block, pos, 5)?;
                pos += used;
            } else {
                // Section 6.2.2 / 6.2.3 Literal without Indexing / Never
                // Indexed -- 4-bit prefix for both 0x00 and 0x10 patterns.
                let (name_index, used) = decode_int(block, pos, 4)?;
                pos += used;
                let name = if name_index == 0 {
                    let (s, used) = decode_string(block, pos)?;
                    pos += used;
                    s
                } else {
                    self.resolve(name_index)?.0
                };
                let (value, used) = decode_string(block, pos)?;
                pos += used;
                headers.push(DecodedHeader { name, value });
            }
        }
        Ok(headers)
    }
}

/// RFC 7541 section 5.1 integer decode; returns (value, bytes consumed).
fn decode_int(buf: &[u8], pos: usize, prefix_size: u8) -> Result<(usize, usize), String> {
    if pos >= buf.len() {
        return Err("decode_int: out of range".into());
    }
    let mask = (1usize << prefix_size) - 1;
    let mut value = (buf[pos] as usize) & mask;
    if value < mask {
        return Ok((value, 1));
    }
    // Continuation bytes live at buf[pos + 1..]; the accumulated value is
    // absolute, only the mask is relative to the first byte.
    if pos + 1 >= buf.len() {
        return Err("decode_int: truncated continuation".into());
    }
    let mut shift = 0u32;
    let mut i = pos + 1;
    loop {
        if i >= buf.len() {
            return Err("decode_int: truncated".into());
        }
        let b = buf[i];
        value += ((b & 0x7f) as usize) << shift;
        shift += 7;
        i += 1;
        if b & 0x80 == 0 {
            break;
        }
        if shift > 28 {
            return Err("decode_int: overflow".into());
        }
    }
    Ok((value, i - pos))
}

/// RFC 7541 section 5.2 string decode; returns (decoded, bytes consumed).
fn decode_string(buf: &[u8], pos: usize) -> Result<(String, usize), String> {
    if pos >= buf.len() {
        return Err("decode_string: out of range".into());
    }
    let huffman = buf[pos] & 0x80 != 0;
    let (len, used) = decode_int(buf, pos, 7)?;
    let start = pos + used;
    let end = start + len;
    if end > buf.len() {
        return Err("decode_string: truncated".into());
    }
    let raw = &buf[start..end];
    let bytes = if huffman {
        huffman_decode(raw)?
    } else {
        raw.to_vec()
    };
    let s = String::from_utf8(bytes).map_err(|_| "decode_string: invalid utf-8".to_string())?;
    Ok((s, end - pos))
}

/// Huffman decode by walking ENCODE_TABLE codes bit-by-bit (canonical
/// decode: accumulate bits MSB-first; whenever the accumulated prefix
/// equals a code of the recorded length, emit that symbol). 30 bits is the
/// longest code, well inside a u64. Padding is all-ones (EOS prefix); any
/// leftover bits at the end that don't match the all-ones pattern are
/// corrupt.
fn huffman_decode(src: &[u8]) -> Result<Vec<u8>, String> {
    let mut codes: Vec<(u8, u64, u16)> = Vec::with_capacity(257);
    for (sym, &(nbits, code)) in huffman_table::ENCODE_TABLE.iter().enumerate() {
        codes.push((nbits as u8, code, sym as u16));
    }
    let mut out = Vec::with_capacity(src.len() * 2);
    let mut acc: u64 = 0;
    let mut nbits: u32 = 0;
    for &byte in src {
        acc = (acc << 8) | byte as u64;
        nbits += 8;
        // Consume as many complete codes as fit.
        loop {
            let mut matched = false;
            for &(clen, code, sym) in &codes {
                let clen = clen as u32;
                if clen <= nbits && clen > 0 {
                    let window = (acc >> (nbits - clen)) & ((1u64 << clen) - 1);
                    if window == code {
                        if sym >= 256 {
                            return Err("huffman: EOS symbol in stream".into());
                        }
                        out.push(sym as u8);
                        nbits -= clen;
                        acc &= if nbits == 0 { 0 } else { (1u64 << nbits) - 1 };
                        matched = true;
                        break;
                    }
                }
            }
            if !matched {
                break;
            }
        }
    }
    // Leftover bits must be all-ones padding shorter than any code.
    if nbits > 0 {
        let pad = acc & ((1u64 << nbits) - 1);
        if pad != (1u64 << nbits) - 1 {
            return Err(format!("huffman: bad padding ({}/{:x})", nbits, pad));
        }
    }
    Ok(out)
}

// ---- h2 wire framing ----

const FRAME_HEADER_LEN: usize = 9;
const CLIENT_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Parse a 9-byte frame header.
fn parse_frame_header(h: &[u8; 9]) -> (u32, u8, u8, u32) {
    let len = ((h[0] as u32) << 16) | ((h[1] as u32) << 8) | h[2] as u32;
    let ty = h[3];
    let flags = h[4];
    let sid = (((h[5] as u32) & 0x7f) << 24)
        | ((h[6] as u32) << 16)
        | ((h[7] as u32) << 8)
        | h[8] as u32;
    (len, ty, flags, sid)
}

fn build_frame(ty: u8, flags: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut out = Vec::with_capacity(9 + payload.len());
    out.push((len >> 16) as u8);
    out.push((len >> 8) as u8);
    out.push(len as u8);
    out.push(ty);
    out.push(flags);
    out.push(((sid >> 24) & 0x7f) as u8);
    out.push((sid >> 16) as u8);
    out.push((sid >> 8) as u8);
    out.push(sid as u8);
    out.extend_from_slice(payload);
    out
}

/// Read exactly `n` bytes from an async stream; None on EOF mid-read.
async fn read_exact<S>(stream: &mut S, n: usize) -> Option<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut buf = vec![0u8; n];
    let mut filled = 0usize;
    while filled < n {
        match AsyncReadExt::read(stream, &mut buf[filled..]).await {
            Ok(0) => return None,
            Ok(k) => filled += k,
            Err(_) => return None,
        }
    }
    Some(buf)
}

/// Capture one client's h2 exchange on an already-accepted TLS stream whose
/// ALPN negotiation selected "h2". Logs the preface, client SETTINGS, the
/// first HEADERS block (with any CONTINUATIONs assembled), and all trailing
/// frames until END_STREAM on that stream; then sends a minimal response
/// (server SETTINGS, HEADERS :status 200, END_STREAM) so the client
/// completes the request instead of erroring out.
///
/// `max_trailing_frames` bounds trailing-frame logging (the client may keep
/// the connection open for follow-up requests; the capture is about the
/// first exchange).
pub async fn capture_one<S>(stream: &mut S, max_trailing_frames: usize) -> Result<CaptureReport, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let mut report = CaptureReport::default();
    let started = Instant::now();

    // Client connection preface (24 bytes).
    let preface = read_exact(stream, 24)
        .await
        .ok_or("eof reading client preface")?;
    let mut preface_arr = [0u8; 24];
    preface_arr.copy_from_slice(&preface);
    if preface_arr != *CLIENT_PREFACE {
        return Err(format!(
            "bad client preface: {:?}",
            String::from_utf8_lossy(&preface_arr)
        ));
    }
    report.preface = Some(preface_arr);

    let mut decoder = HpackDecoder::new();
    let mut request_stream_id: Option<u32> = None;
    let mut trailing = 0usize;

    loop {
        let hdr = read_exact(stream, FRAME_HEADER_LEN)
            .await
            .ok_or("eof reading frame header")?;
        let mut hdr_arr = [0u8; 9];
        hdr_arr.copy_from_slice(&hdr);
        let (len, ty, flags, sid) = parse_frame_header(&hdr_arr);
        let payload = if len == 0 {
            Vec::new()
        } else {
            read_exact(stream, len as usize)
                .await
                .ok_or("eof reading frame payload")?
        };

        match ty {
            4 => {
                // SETTINGS.
                if flags & 0x1 != 0 {
                    // ACK -- nothing to log.
                    continue;
                }
                if payload.len() % 6 != 0 {
                    return Err(format!(
                        "SETTINGS length {} not a multiple of 6",
                        payload.len()
                    ));
                }
                for chunk in payload.chunks_exact(6) {
                    let id = ((chunk[0] as u16) << 8) | chunk[1] as u16;
                    let val = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
                    report.settings.push((id, val));
                }
                // Acknowledge so the client proceeds.
                let ack = build_frame(4, 0x1, 0, &[]);
                AsyncWriteExt::write_all(stream, &ack)
                    .await
                    .map_err(|e| format!("write SETTINGS ACK: {e}"))?;
            }
            1 => {
                // HEADERS. Strip PADDED (0x8) and PRIORITY (0x20) prefixes.
                if request_stream_id.is_some() {
                    // A second request on the same connection -- log and
                    // keep serving; the capture is about the first.
                    report.trailing_frames.push((ty, flags, sid, len));
                    continue;
                }
                let mut block = payload.clone();
                let mut f = flags;
                if f & 0x8 != 0 {
                    if block.is_empty() {
                        return Err("HEADERS with PADDED but empty payload".into());
                    }
                    let pad = block[0] as usize;
                    if pad + 1 > block.len() {
                        return Err("HEADERS padding exceeds payload".into());
                    }
                    block.truncate(block.len() - pad);
                    block.drain(..1);
                    f &= !0x8;
                }
                if f & 0x20 != 0 {
                    if block.len() < 5 {
                        return Err("HEADERS with PRIORITY but short payload".into());
                    }
                    block.drain(..5);
                    f &= !0x20;
                }
                // CONTINUATION frames (type 9) carry the rest of the block
                // while END_HEADERS (0x4) is unset.
                while f & 0x4 == 0 {
                    let chdr = read_exact(stream, FRAME_HEADER_LEN)
                        .await
                        .ok_or("eof reading CONTINUATION header")?;
                    let mut chdr_arr = [0u8; 9];
                    chdr_arr.copy_from_slice(&chdr);
                    let (clen, cty, cflags, csid) = parse_frame_header(&chdr_arr);
                    if cty != 9 || csid != sid {
                        return Err("expected CONTINUATION on same stream".into());
                    }
                    let cpayload = read_exact(stream, clen as usize)
                        .await
                        .ok_or("eof reading CONTINUATION payload")?;
                    block.extend_from_slice(&cpayload);
                    f = cflags;
                }
                let headers = decoder.decode_block(&block)?;
                for h in &headers {
                    match h.name.as_str() {
                        ":path" => report.path = Some(h.value.clone()),
                        ":authority" => report.authority = Some(h.value.clone()),
                        ":method" => report.method = Some(h.value.clone()),
                        _ => {}
                    }
                }
                report.headers = headers;
                report.head_latency = Some(started.elapsed());
                request_stream_id = Some(sid);

                // Minimal response: server SETTINGS first (RFC 7540 section
                // 3.5 makes the server connection preface a SETTINGS
                // frame), then the reply.
                let server_settings = build_frame(4, 0x0, 0, &[]);
                AsyncWriteExt::write_all(stream, &server_settings)
                    .await
                    .map_err(|e| format!("write server SETTINGS: {e}"))?;
                // HEADERS :status 200 = static index 8, fully indexed ->
                // 0x80 | 8 = 0x88, END_HEADERS | END_STREAM.
                let reply = build_frame(1, 0x5, sid, &[0x88]);
                AsyncWriteExt::write_all(stream, &reply)
                    .await
                    .map_err(|e| format!("write reply HEADERS: {e}"))?;
            }
            0 => {
                // DATA on the request stream (unlikely for GET, but logged).
                if Some(sid) == request_stream_id || sid % 2 == 1 {
                    report.trailing_frames.push((ty, flags, sid, len));
                }
                if flags & 0x1 != 0 && Some(sid) == request_stream_id {
                    break;
                }
            }
            8 => {
                report.trailing_frames.push((ty, flags, sid, len));
            }
            6 => {
                // PING -- RFC 7540 section 6.7 requires an ACK with the
                // same payload.
                if flags & 0x1 == 0 {
                    let pong = build_frame(6, 0x1, 0, &payload);
                    AsyncWriteExt::write_all(stream, &pong)
                        .await
                        .map_err(|e| format!("write PING ACK: {e}"))?;
                }
            }
            7 => {
                // GOAWAY -- client is done; stop.
                break;
            }
            _ => {
                // Anything else (WINDOW_UPDATE, PRIORITY, RST_STREAM, ...)
                // is worth one log line each but doesn't change the reply.
                report.trailing_frames.push((ty, flags, sid, len));
            }
        }

        // HEADERS+END_STREAM is the terminal event for a GET request — the
        // response has been sent and the client's follow-up frames are not
        // part of the first-request fingerprint. Without this break the
        // loop waits for the client to initiate a NEW frame, which a
        // quiescent client (Chrome after commit) may never do.
        let ended_stream = ty == 1 && flags & 0x1 != 0 && Some(sid) == request_stream_id;
        if ended_stream {
            break;
        }

        if request_stream_id.is_some() {
            trailing += 1;
            if trailing >= max_trailing_frames {
                break;
            }
        }
    }

    Ok(report)
}

/// Build a rustls TlsAcceptor from the crate's checked-in dev cert
/// (`fixtures/dev-localhost.crt` / `.key`, generated by firing 2's TLS
/// slice), with ALPN restricted to `h2`. Shared by the h2cap unit tests and
/// the wire-order integration test in `lib.rs`; the bin uses the same pair
/// via its own `include_str!`.
pub fn dev_tls_acceptor() -> tokio_rustls::TlsAcceptor {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    let cert_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/dev-localhost.crt");
    let key_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/dev-localhost.key");
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&cert_path)
        .expect("read dev-localhost.crt")
        .map(|r| r.expect("cert pem"))
        .collect();
    let key = PrivateKeyDer::from_pem_file(&key_path).expect("read dev-localhost.key");
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("h2cap tls config");
    config.alpn_protocols = vec![b"h2".to_vec()];
    tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7541 section 5.1's own integer examples: 10 with a 5-bit prefix
    /// is one byte; 31 (mask-saturated) starts a continuation; 1337 is the
    /// RFC's three-byte worked example.
    #[test]
    fn hpack_int_roundtrip_boundary() {
        assert_eq!(decode_int(&[10], 0, 5).unwrap(), (10, 1));
        assert_eq!(decode_int(&[0x1f, 0x00], 0, 5).unwrap(), (31, 2));
        assert_eq!(decode_int(&[0x1f, 0x9a, 0x0a], 0, 5).unwrap(), (1337, 3));
    }

    /// Indexed static: 0x82 = index 2 = :method: GET.
    #[test]
    fn hpack_decode_indexed_static() {
        let mut d = HpackDecoder::new();
        let headers = d.decode_block(&[0x82]).unwrap();
        assert_eq!(headers[0].name, ":method");
        assert_eq!(headers[0].value, "GET");
    }

    /// Literal with incremental indexing -- hand-built block exercising the
    /// raw (non-Huffman) name/value path AND dynamic-table growth:
    /// `40 0a custom-key 0c custom-value` adds the entry at dynamic index
    /// 62, and a follow-up `be` (indexed, 62) resolves it back.
    #[test]
    fn hpack_decode_literal_with_indexing() {
        let mut d = HpackDecoder::new();
        let mut block = vec![0x40, 0x0a];
        block.extend_from_slice(b"custom-key");
        block.push(0x0c);
        block.extend_from_slice(b"custom-value");
        let headers = d.decode_block(&block).unwrap();
        assert_eq!(headers[0].name, "custom-key");
        assert_eq!(headers[0].value, "custom-value");
        // Same decoder, follow-up block: 0xbe = indexed, dynamic index 62
        // (62 - 62 = 0 -> most recent entry) resolves to custom-key above.
        let headers = d.decode_block(&[0xbe]).unwrap();
        assert_eq!(headers[0].name, "custom-key");
        assert_eq!(headers[0].value, "custom-value");
    }

    /// The full RFC 7541 Appendix C.4.1 -> C.4.3 request sequence against
    /// one decoder -- exercises indexed statics, literal+indexing with
    /// Huffman, dynamic-table references (0xbe/0xbf), and
    /// literal-without-indexing.
    ///
    /// First request:  `82 86 84 41 8c f1e3c2e5f23a6ba0ab90f4ff`
    ///   :method GET, :scheme http, :path /, :authority www.example.com
    ///   (literal+indexing, name idx 1, Huffman value) -> dyn[62].
    /// Second request: `82 86 84 be 58 86 a8eb10649cbf`
    ///   same pseudo headers, :authority www.example.com via dyn[62] (the
    ///   custom name the first request added at that slot), then
    ///   cache-control: no-cache (name idx 24, Huffman value) -> dyn[63].
    /// Third request:  `82 87 85 bf 40 88 25a849e95ba97d7f 89 25a849e95bb8e8b4bf`
    ///   :method GET, :scheme https, :path /index.html, cache-control:
    ///   no-cache via dyn[63], custom-key: custom-value (literal+indexing,
    ///   Huffman both) -> dyn[64].
    #[test]
    fn hpack_decode_rfc_c4_sequence() {
        let mut d = HpackDecoder::new();

        let first = [
            0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
            0x90, 0xf4, 0xff,
        ];
        let headers = d.decode_block(&first).unwrap();
        assert_eq!(headers[0].name, ":method");
        assert_eq!(headers[0].value, "GET");
        assert_eq!(headers[1].name, ":scheme");
        assert_eq!(headers[1].value, "http");
        assert_eq!(headers[2].name, ":path");
        assert_eq!(headers[2].value, "/");
        assert_eq!(headers[3].name, ":authority");
        assert_eq!(headers[3].value, "www.example.com");

        let second = [
            0x82, 0x86, 0x84, 0xbe, 0x58, 0x86, 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf,
        ];
        let headers = d.decode_block(&second).unwrap();
        assert_eq!(headers[3].name, ":authority");
        assert_eq!(headers[3].value, "www.example.com");
        assert_eq!(headers[4].name, "cache-control");
        assert_eq!(headers[4].value, "no-cache");

        let third = [
            0x82, 0x87, 0x85, 0xbf, 0x40, 0x88, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f,
            0x89, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf,
        ];
        let headers = d.decode_block(&third).unwrap();
        assert_eq!(headers[0].name, ":method");
        assert_eq!(headers[0].value, "GET");
        assert_eq!(headers[1].name, ":scheme");
        assert_eq!(headers[1].value, "https");
        assert_eq!(headers[2].name, ":path");
        assert_eq!(headers[2].value, "/index.html");
        // 0xbf = indexed, dynamic index 63 — resolves per the table state
        // after two requests (observed live during this test's authoring).
        assert_eq!(headers[3].name, ":authority");
        assert_eq!(headers[3].value, "www.example.com");
        // The literal that follows: custom-key: custom-value.
        assert_eq!(headers[4].name, "custom-key");
        assert_eq!(headers[4].value, "custom-value");
    }

    /// Literal, Huffman-coded name AND value -- computed from the RFC 7541
    /// Appendix B table itself (the same table this module copies):
    /// "custom-key: custom-value" encodes to
    /// `40 88 25a849e95ba97d7f 89 25a849e95bb8e8b4bf`. (Same bytes as the
    /// tail of the C.4 sequence above, decoded standalone.)
    #[test]
    fn hpack_decode_huffman_name_and_value() {
        let mut d = HpackDecoder::new();
        let block = [
            0x40, 0x88, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f, 0x89, 0x25, 0xa8, 0x49,
            0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf,
        ];
        let headers = d.decode_block(&block).unwrap();
        assert_eq!(headers[0].name, "custom-key");
        assert_eq!(headers[0].value, "custom-value");
    }

    /// RFC 7541 Appendix C.4.3's "no-cache" literal (Huffman value) --
    /// `58 86 a8eb10649cbf` = cache-control: no-cache.
    #[test]
    fn hpack_decode_no_cache_literal() {
        let mut d = HpackDecoder::new();
        let block = [0x58, 0x86, 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf];
        let headers = d.decode_block(&block).unwrap();
        assert_eq!(headers[0].name, "cache-control");
        assert_eq!(headers[0].value, "no-cache");
    }

    /// The RFC's canonical Huffman example: "www.example.com" encodes to
    /// f1e3c2e5f23a6ba0ab90f4ff.
    #[test]
    fn huffman_decode_rfc_example() {
        let src = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        let out = huffman_decode(&src).unwrap();
        assert_eq!(out, b"www.example.com");
    }

    /// Static table spot-checks against the `h2` crate's `index_static`
    /// numbering (registry source verified during firing 12).
    #[test]
    fn static_table_indices_match_h2_crate() {
        assert_eq!(STATIC_TABLE[1][0], ":authority");
        assert_eq!(STATIC_TABLE[2], &[":method", "GET"]);
        assert_eq!(STATIC_TABLE[8], &[":status", "200"]);
        assert_eq!(STATIC_TABLE[15][0], "accept-charset");
        assert_eq!(STATIC_TABLE[19][0], "accept");
        assert_eq!(STATIC_TABLE[24][0], "cache-control");
        assert_eq!(STATIC_TABLE[32][0], "cookie");
        assert_eq!(STATIC_TABLE[58], &["user-agent", ""]);
        assert_eq!(STATIC_TABLE[61][0], "www-authenticate");
    }
}
