//! HTTP `/health` for LB probes -- a separate port from the LDAP
//! listener, since LDAP itself is raw BER over TCP, not HTTP (unlike
//! fastetcd, which can share its gRPC port with an HTTP route since both
//! are HTTP/2-based).
//!
//! Deliberately a hand-rolled minimal HTTP/1.1 responder rather than
//! pulling in axum/hyper for one endpoint. Does a real backend check
//! ([`Store::ping`]) rather than just accepting the TCP connection, so
//! the LB can actually detect a dead fastetcd connection, not just a
//! live process.

use std::sync::Arc;

use iron_store::store::Store;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

pub async fn serve(listener: TcpListener, store: Arc<Mutex<Store>>) -> std::io::Result<()> {
    loop {
        let (mut stream, _peer) = listener.accept().await?;
        let store = store.clone();
        tokio::spawn(async move {
            // Drain and ignore the request; this is a liveness/readiness
            // probe, not a real HTTP server -- any request gets the same
            // answer based on backend connectivity.
            let ok = store.lock().await.ping().await.is_ok();
            let body = if ok { "{\"health\":\"true\"}" } else { "{\"health\":\"false\"}" };
            let status = if ok { "200 OK" } else { "503 Service Unavailable" };
            let resp = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}
