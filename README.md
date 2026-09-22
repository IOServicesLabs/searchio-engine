# searchio-engine

A from-scratch Rust browsing engine built for searchio's acquisition ladder —
not a general browser. Owns the full stack (DOM, JS bridge, network, stealth,
sidecar protocol) with no upstream browser to wait on.

## Get the binary

The engine ships as the `se-serve` sidecar binary. Most users get it via the
[searchio](https://github.com/IOServicesLabs/searchio) installer or the
all-in-one Docker image. To install just the binary:

```bash
curl -fsSL https://raw.githubusercontent.com/IOServicesLabs/searchio-engine/main/scripts/install.sh | sh
```

That drops `se-serve` at `~/.searchio/bin/se-serve` (prebuilt releases for
linux-x86_64/arm64, windows-x86_64, macos-aarch64/x86_64; other targets build
from source: `cargo build --release --bin se-serve`). Run it standalone with
`se-serve [port]` (default 8931), or point `SEARCHIO_ENGINE_BIN` at it and
let searchio spawn it as a sidecar.

## Principles

- **Scraping-grade, not general-purpose.** No layout, paint, rasterization,
  media, or accessibility tree. `read_html` / `eval_js` / cookies need DOM +
  JS + network only. Skipping geometry is what makes this buildable by one
  person instead of a foundation.
- **Components, not dependencies we fear.** V8 (`rusty_v8`, Deno-maintained)
  executes JS; html5ever parses HTML5 with browser error-recovery. Everything
  a site can observe — DOM semantics, Web APIs, network behavior, fingerprint,
  TLS — is ours.
- **Real fixtures or it didn't happen.** Every tier is pinned against captures
  of the live sites searchio serves, not toy HTML. A dependency bump that
  changes what we see on a real page fails here first.
- **Lean by construction.** Single process, no renderer fan-out, memory
  released on task exit. The reference point: an always-on Chromium sidecar
  idles at ~250MB; this engine's target idle is tens of MB.
- **Falls through, never blocks.** Challenge/shell signatures are detected
  and reported so searchio escalates to the patchright tier — this engine
  never pretends a gated page is empty.

## Crates

| Crate | Role |
|---|---|
| `se-dom` | HTML5 DOM (html5ever) with the semantics sites actually probe |
| `se-js` | V8 bridge — Web APIs, script execution, page context |
| `se-net` | HTTP stack: fingerprints, cookies, headers, body handling |
| `se-serve` | The sidecar binary — speaks the JSON sidecar protocol over a local WebSocket; the reference client is `searchio/net/sidecar.py` |

## Develop

```bash
cargo build --workspace --locked
cargo test  --workspace --locked
```

CI runs the same matrix on linux, windows, and macOS on every push.

## License

Apache-2.0.
