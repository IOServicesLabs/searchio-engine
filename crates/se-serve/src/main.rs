//! `se-serve` binary: run the sidecar wire surface standalone.
//!
//! Usage: se-serve [port] [--session-file PATH]   (default 8931, or SE_SERVE_PORT;
//! session file also from SE_SERVE_SESSION)
//!
//! With `--session-file`, the sidecar restores the saved session at startup
//! and persists it on graceful shutdown (Ctrl+C), so a restart resumes the
//! cookie jar + per-origin storage. The file is the Playwright storage_state
//! artifact shape (`storage_state_get` output verbatim).

#[tokio::main]
async fn main() {
    let mut port: Option<u16> = None;
    let mut session_file: Option<std::path::PathBuf> = std::env::var_os("SE_SERVE_SESSION")
        .map(std::path::PathBuf::from);
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--session-file" {
            session_file = args.next().map(std::path::PathBuf::from);
        } else if let Some(v) = a.strip_prefix("--session-file=") {
            session_file = Some(std::path::PathBuf::from(v));
        } else if port.is_none() {
            port = a.parse().ok();
        }
    }
    let port = port
        .or_else(|| std::env::var("SE_SERVE_PORT").ok().and_then(|p| p.parse().ok()))
        .unwrap_or(8931);
    let engine = se_serve::Engine::default().with_session_file(session_file.clone());
    if let Err(e) = se_serve::serve_with_session(engine, port, session_file).await {
        eprintln!("se-serve: {e}");
        std::process::exit(1);
    }
}
