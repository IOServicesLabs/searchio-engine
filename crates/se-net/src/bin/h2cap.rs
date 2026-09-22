//! h2cap — raw-h2 ground-truth capture server (firing 12).
//!
//! Serves one HTTP/2 capture over TLS (ALPN h2) using the crate's
//! checked-in dev cert, prints a `LISTEN <port>` line so drivers can
//! connect, then prints the decoded `CaptureReport` once the client's first
//! request exchange completes. Two modes:
//!
//! - default: wait for an external client (patchright headed Chromium via
//!   `scripts/capture_h2_wire.py`). Chromium auto-probes HTTP/3 (QUIC) on
//!   loopback and our server is h2-only, so the failed probe burns one TCP
//!   connection before the h1/h2 retry — we therefore accept up to
//!   `--accepts N` connections (default 4) and capture the first that
//!   completes a TLS+h2 handshake, tolerating aborted attempts before it.
//! - `--engine`: self-drive — after printing LISTEN, spawn the engine's own
//!   reqwest client (danger-accepting, test-only) and fetch
//!   `https://127.0.0.1:<port>/landing` so the report captures the engine's
//!   own h2 wire shape
//!
//! The report goes to stdout between `REPORT-BEGIN` / `REPORT-END` markers
//! so the Python driver can extract it without parsing the rest.

use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let self_drive = std::env::args().any(|a| a == "--engine");
    let accepts: usize = std::env::args()
        .position(|a| a == "--accepts")
        .and_then(|i| std::env::args().nth(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(4);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();

    // Same dev cert the se-net tests use; ALPN h2 only.
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    let cert_path = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/dev-localhost.crt");
    let key_path = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/dev-localhost.key");
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| format!("read {cert_path}: {e}"))?
        .map(|r| r.map_err(|e| format!("cert pem: {e}")))
        .collect::<Result<_, _>>()?;
    let key = PrivateKeyDer::from_pem_file(key_path).map_err(|e| format!("read {key_path}: {e}"))?;
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    println!("LISTEN {port}");
    use tokio::io::AsyncWriteExt as _;

    let (report, client_result) = if self_drive {
        // Spawn the engine client in the background, then accept its
        // connection on the listener.
        let client = tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .build()?;
            let url = format!("https://127.0.0.1:{port}/landing");
            let res = client.get(&url).send().await?;
            let status = res.status();
            let _ = res.text().await;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(status)
        });
        let mut report = None;
        let mut last_err = String::new();
        for _ in 0..accepts {
            let (tcp, _) = listener.accept().await?;
            tcp.set_nodelay(true).ok();
            match acceptor.accept(tcp).await {
                Ok(mut tls) => {
                    // reqwest's ALPN negotiates h2 here; if it somehow lands
                    // on h1.1 the capture fails loudly on the preface check.
                    match se_net::h2cap::capture_one(&mut tls, 16).await {
                        Ok(r) => {
                            report = Some(r);
                            break;
                        }
                        Err(e) => last_err = e,
                    }
                }
                Err(e) => last_err = format!("tls: {e}"),
            }
        }
        let report = report.ok_or_else(|| format!("no capture after {accepts} attempts: {last_err}"))?;
        let status = client
            .await
            .map_err(|e| format!("engine client join: {e}"))?
            .map_err(|e| format!("engine client: {e}"))?;
        (report, Some(status))
    } else {
        let mut report = None;
        let mut last_err = String::new();
        for _ in 0..accepts {
            let (tcp, _) = listener.accept().await?;
            tcp.set_nodelay(true).ok();
            match acceptor.accept(tcp).await {
                Ok(mut tls) => match se_net::h2cap::capture_one(&mut tls, 16).await {
                    Ok(r) => {
                        report = Some(r);
                        break;
                    }
                    Err(e) => last_err = e,
                },
                Err(e) => last_err = format!("tls: {e}"),
            }
        }
        let report =
            report.ok_or_else(|| format!("no capture after {accepts} attempts: {last_err}"))?;
        (report, None)
    };

    println!("REPORT-BEGIN");
    print!("{}", report.render());
    if let Some(status) = client_result {
        println!("engine_status: {status}");
    }
    println!("REPORT-END");
    let _ = tokio::io::stdout().flush().await;
    Ok(())
}
