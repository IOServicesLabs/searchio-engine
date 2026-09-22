//! Image metadata sniffer for the `read_image` verb (firing 38).
//!
//! The engine has no rasterizer by design — `read_image` returns the RAW
//! image bytes plus what an agent needs to route them: format, dimensions,
//! content type. Dimensions are parsed from container headers (PNG IHDR,
//! JPEG SOF, GIF logical screen, BMP header, WebP VP8/VP8L/VP8X, ICO dir) —
//! never decoded pixels. Formats the sniffer doesn't know answer
//! `format: "unknown"` with no dimensions, bytes intact.

/// What the sniffer learned about an image payload.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ImgMeta {
    /// Container format: png | jpeg | gif | bmp | webp | svg | ico | unknown.
    pub format: String,
    /// Pixel width from the container header, when the format exposes one.
    pub width: Option<u32>,
    /// Pixel height from the container header, when the format exposes one.
    pub height: Option<u32>,
}

fn le16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(at)?, *b.get(at + 1)?]))
}
fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}
fn le32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *b.get(at)?,
        *b.get(at + 1)?,
        *b.get(at + 2)?,
        *b.get(at + 3)?,
    ]))
}
fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *b.get(at)?,
        *b.get(at + 1)?,
        *b.get(at + 2)?,
        *b.get(at + 3)?,
    ]))
}

fn sniff_jpeg(b: &[u8]) -> ImgMeta {
    // Walk segments: [FF marker][len BE incl. itself][payload]. SOF0-SOF15
    // (C0-CF except C4/C8/CC, the Huffman/arith tables) carry dimensions.
    let mut at = 2;
    while at + 9 < b.len() {
        if b[at] != 0xFF {
            at += 1;
            continue;
        }
        let marker = b[at + 1];
        if (0xC0..=0xCF).contains(&marker) && !matches!(marker, 0xC4 | 0xC8 | 0xCC) {
            return ImgMeta {
                format: "jpeg".into(),
                height: be16(b, at + 5).map(u32::from),
                width: be16(b, at + 7).map(u32::from),
            };
        }
        let len = match be16(b, at + 2) {
            Some(l) if l >= 2 => l as usize,
            _ => break,
        };
        at += 2 + len;
    }
    ImgMeta {
        format: "jpeg".into(),
        width: None,
        height: None,
    }
}

fn sniff_webp(b: &[u8]) -> ImgMeta {
    // RIFF....WEBP<fourcc><payload>. VP8X: 1+LE24 at 24/27; VP8 lossy: tag at
    // 20, signature 9D 012A, 14-bit LE dims at 26/28; VP8L: 0x2F at 20, 14-bit
    // dims packed in LE u32 at 21.
    let fourcc = |b: &[u8]| -> String {
        b.get(12..16)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .unwrap_or_default()
    };
    match fourcc(b).as_str() {
        "VP8X" => {
            let le24 = |at: usize| -> Option<u32> {
                Some(
                    *b.get(at)? as u32
                        | (*b.get(at + 1)? as u32) << 8
                        | (*b.get(at + 2)? as u32) << 16,
                )
            };
            ImgMeta {
                format: "webp".into(),
                width: le24(24).map(|w| w + 1),
                height: le24(27).map(|h| h + 1),
            }
        }
        "VP8 " => {
            // Frame tag (3 bytes) then start code 9D 01 2A then 14-bit dims.
            if b.get(23) == Some(&0x9D) && b.get(24) == Some(&0x01) && b.get(25) == Some(&0x2A) {
                let w = le16(b, 26).map(|v| (v & 0x3FFF) as u32);
                let h = le16(b, 28).map(|v| (v & 0x3FFF) as u32);
                ImgMeta {
                    format: "webp".into(),
                    width: w,
                    height: h,
                }
            } else {
                ImgMeta {
                    format: "webp".into(),
                    width: None,
                    height: None,
                }
            }
        }
        "VP8L" => {
            if b.get(20) == Some(&0x2F) {
                let bits = le32(b, 21);
                ImgMeta {
                    format: "webp".into(),
                    width: bits.map(|v| (v & 0x3FFF) + 1),
                    height: bits.map(|v| ((v >> 14) & 0x3FFF) + 1),
                }
            } else {
                ImgMeta {
                    format: "webp".into(),
                    width: None,
                    height: None,
                }
            }
        }
        _ => ImgMeta {
            format: "webp".into(),
            width: None,
            height: None,
        },
    }
}

/// Identify the payload by magic bytes (content type is a fallback hint for
/// formats like SVG that have no magic).
pub fn sniff(bytes: &[u8], content_type: &str) -> ImgMeta {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return ImgMeta {
            format: "png".into(),
            width: be32(bytes, 16),
            height: be32(bytes, 20),
        };
    }
    if bytes.starts_with(b"\xFF\xD8\xFF") {
        return sniff_jpeg(bytes);
    }
    if bytes.starts_with(b"GIF8") {
        return ImgMeta {
            format: "gif".into(),
            width: le16(bytes, 6).map(u32::from),
            height: le16(bytes, 8).map(u32::from),
        };
    }
    if bytes.starts_with(b"BM") {
        let w = le32(bytes, 18);
        let h = le32(bytes, 22).map(|v| v & 0x7FFF_FFFF); // top-down uses negative
        return ImgMeta {
            format: "bmp".into(),
            width: w,
            height: h,
        };
    }
    if bytes.starts_with(b"RIFF") && bytes.len() > 12 && &bytes[8..12] == b"WEBP" {
        return sniff_webp(bytes);
    }
    if bytes.starts_with(b"\x00\x00\x01\x00") {
        // ICO: width/height are BYTES (0 encodes 256) in the dir entry.
        return ImgMeta {
            format: "ico".into(),
            width: bytes.get(6).map(|v| if *v == 0 { 256 } else { u32::from(*v) }),
            height: bytes.get(7).map(|v| if *v == 0 { 256 } else { u32::from(*v) }),
        };
    }
    let looks_like_svg = content_type.contains("svg")
        || bytes
            .get(..64)
            .map(|head| {
                let s = String::from_utf8_lossy(head);
                s.trim_start().starts_with("<svg") || s.contains("<svg")
            })
            .unwrap_or(false);
    if looks_like_svg {
        // Dimensions live in width/height attributes (possibly percentages,
        // which are meaningless without layout) — the honest answer is the
        // format alone.
        return ImgMeta {
            format: "svg".into(),
            width: None,
            height: None,
        };
    }
    ImgMeta {
        format: "unknown".into(),
        width: None,
        height: None,
    }
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard (padded) base64 — the wire shape image bytes ride to the agent.
pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map(u32::from).unwrap_or(0);
        let b2 = chunk.get(2).copied().map(u32::from).unwrap_or(0);
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn b64_val(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode standard padded base64 — the `data:` URL path of `read_image`.
/// Whitespace is skipped (MIME transport folds); anything else outside the
/// alphabet fails the decode so a corrupt data URL answers a verb error
/// instead of silently wrong bytes.
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut nbits = 0u32;
    let mut pad = 0usize;
    for &c in s.as_bytes() {
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == b'=' {
            pad += 1;
            continue;
        }
        if pad > 0 {
            // data after padding is malformed.
            return None;
        }
        acc = (acc << 6) | b64_val(c)?;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    if pad > 2 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-built 2x3 RGB PNG: signature + IHDR (2 BE) + bare IEND-ish tail —
    /// the sniffer only reads the IHDR offsets.
    fn fake_png(w: u32, h: u32) -> Vec<u8> {
        let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
        v.extend_from_slice(&[0, 0, 0, 13, b'I', b'H', b'D', b'R']);
        v.extend_from_slice(&w.to_be_bytes());
        v.extend_from_slice(&h.to_be_bytes());
        v.extend_from_slice(&[8, 2, 0, 0, 0]); // 8-bit, truecolor
        v.extend_from_slice(&[0, 0, 0, 0, b'I', b'E', b'N', b'D']);
        v
    }

    #[test]
    fn sniffs_png_dimensions_from_ihdr() {
        let meta = sniff(&fake_png(2, 3), "image/png");
        assert_eq!(meta.format, "png");
        assert_eq!(meta.width, Some(2));
        assert_eq!(meta.height, Some(3));
    }

    #[test]
    fn sniffs_jpeg_sof_dimensions() {
        // SOI + APP0 + SOF0(8x6) + EOI
        let mut v = vec![0xFF, 0xD8, 0xFF];
        v.extend_from_slice(&[0xE0, 0x00, 0x04, 0, 0]); // APP0 len 4
        v.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 8]); // SOF0 len 17, precision 8
        v.extend_from_slice(&[0x00, 6, 0x00, 8]); // height 6, width 8
        v.extend_from_slice(&[3, 1, 0x11, 0, 2, 0x11, 1, 3, 0x11, 1]); // 3 components
        v.extend_from_slice(&[0xFF, 0xD9]);
        let meta = sniff(&v, "image/jpeg");
        assert_eq!(meta.format, "jpeg");
        assert_eq!((meta.width, meta.height), (Some(8), Some(6)));
    }

    #[test]
    fn sniffs_gif_and_bmp_and_ico() {
        // GIF: header + logical screen descriptor.
        let mut gif = b"GIF89a".to_vec();
        gif.extend_from_slice(&[7, 0, 5, 0]); // 7x5 LE
        gif.extend_from_slice(&[0, 0, 0]);
        let meta = sniff(&gif, "image/gif");
        assert_eq!((meta.format.as_str(), meta.width, meta.height), ("gif", Some(7), Some(5)));

        let mut bmp = b"BM".to_vec();
        bmp.extend_from_slice(&[0; 16]);
        bmp.extend_from_slice(&[9, 0, 0, 0]); // width 9
        bmp.extend_from_slice(&[4, 0, 0, 0]); // height 4
        let meta = sniff(&bmp, "image/bmp");
        assert_eq!((meta.format.as_str(), meta.width, meta.height), ("bmp", Some(9), Some(4)));

        let mut ico = vec![0, 0, 1, 0, 1, 0];
        ico.extend_from_slice(&[32, 32, 0, 0]); // 32x32
        let meta = sniff(&ico, "image/x-icon");
        assert_eq!((meta.format.as_str(), meta.width, meta.height), ("ico", Some(32), Some(32)));
    }

    #[test]
    fn sniffs_webp_vp8x_and_falls_back_honestly() {
        let mut vp8x = b"RIFF".to_vec();
        vp8x.extend_from_slice(&[0; 4]); // riff size
        vp8x.extend_from_slice(b"WEBPVP8X");
        // chunk-size(4) + flags(1) + reserved(3) — width/height land at 24/27.
        vp8x.extend_from_slice(&[0; 8]);
        vp8x.extend_from_slice(&[1, 0, 0]); // width-1 = 1 → 2
        vp8x.extend_from_slice(&[2, 0, 0]); // height-1 = 2 → 3
        let meta = sniff(&vp8x, "image/webp");
        assert_eq!((meta.format.as_str(), meta.width, meta.height), ("webp", Some(2), Some(3)));

        let unknown = sniff(b"\x00\x01\x02\x03", "application/octet-stream");
        assert_eq!(unknown.format, "unknown");
        assert_eq!(unknown.width, None);
    }

    #[test]
    fn svg_by_content_type_and_base64_round_trips() {
        let meta = sniff(b"<svg xmlns='x'><rect/></svg>", "image/svg+xml");
        assert_eq!(meta.format, "svg");
        assert_eq!(meta.width, None);

        // base64 known vectors: "Man" -> TWFu; "M" -> TQ==; "Ma" -> TWE=
        assert_eq!(base64_encode(b"Man"), "TWFu");
        assert_eq!(base64_encode(b"M"), "TQ==");
        assert_eq!(base64_encode(b"Ma"), "TWE=");
    }

    #[test]
    fn base64_decode_round_trips_and_rejects_junk() {
        assert_eq!(base64_decode("TWFu").unwrap(), b"Man");
        assert_eq!(base64_decode("TQ==").unwrap(), b"M");
        assert_eq!(base64_decode("TWE=").unwrap(), b"Ma");
        // MIME folding (embedded whitespace) decodes.
        assert_eq!(base64_decode("TW\r\nFu").unwrap(), b"Man");
        assert!(base64_decode("T*W!u").is_none());
        assert!(base64_decode("TQ==x").is_none(), "data after padding");
        // Round-trip through encode for a non-multiple-of-3 payload.
        let payload = b"\x89PNG\r\n\x1a\n\x00\x01";
        let enc = base64_encode(payload);
        assert_eq!(base64_decode(&enc).unwrap(), payload);
    }
}
