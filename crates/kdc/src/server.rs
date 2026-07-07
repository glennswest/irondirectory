//! UDP + TCP listeners for the KDC (RFC 4120 §7.2), dispatching each
//! decoded request to the AS or TGS exchange handler.

use std::sync::Arc;

use rasn_kerberos::KrbError;
use tokio::net::{TcpListener, UdpSocket};

use crate::krberror;
use crate::wire::{self, KdcRequest, KdcResponse};
use crate::AppState;

async fn dispatch(app: &AppState, bytes: &[u8]) -> Vec<u8> {
    let response = match wire::decode_request(bytes) {
        Ok(KdcRequest::As(req)) => crate::as_exchange::handle(app, &req.0).await,
        Ok(KdcRequest::Tgs(req)) => crate::tgs_exchange::handle(app, &req.0).await,
        Err(e) => {
            tracing::debug!("failed to decode KDC request: {e}");
            KdcResponse::Error(malformed_request_error(&app.realm, &e))
        }
    };
    if let KdcResponse::Error(e) = &response {
        tracing::info!(error_code = e.error_code, e_text = ?e.e_text, "returning KRB-ERROR");
    }
    match response.encode() {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("failed to encode KDC response: {e}");
            // Fall back to a minimal, always-encodable error rather than
            // dropping the request with no reply at all.
            rasn::der::encode(&krberror::build(krberror::KRB_ERR_GENERIC, &app.realm, crate::krbtgt_principal_name(&app.realm), Some("internal error".into()), None))
                .unwrap_or_default()
        }
    }
}

fn malformed_request_error(realm: &str, e: &wire::WireError) -> KrbError {
    krberror::build(krberror::KRB_ERR_GENERIC, realm, crate::krbtgt_principal_name(realm), Some(format!("malformed request: {e}")), None)
}

/// Serves UDP requests on `socket` until it errors. Each datagram is one
/// complete request; if a reply would exceed a UDP-safe size, sends
/// `KRB_ERR_RESPONSE_TOO_BIG` instead (RFC 4120 §7.2.1), forcing the
/// client to retry over TCP.
pub async fn serve_udp(socket: UdpSocket, app: Arc<AppState>) -> std::io::Result<()> {
    const UDP_SAFE_REPLY_LEN: usize = 1400; // conservative, avoids IP fragmentation on typical MTUs
    let socket = Arc::new(socket);
    let mut buf = vec![0u8; 65536];
    loop {
        let (n, peer) = socket.recv_from(&mut buf).await?;
        let request = buf[..n].to_vec();
        let app = app.clone();
        let socket = socket.clone();
        tokio::spawn(async move {
            let mut reply = dispatch(&app, &request).await;
            if reply.len() > UDP_SAFE_REPLY_LEN {
                let err = krberror::build(52 /* KRB_ERR_RESPONSE_TOO_BIG */, &app.realm, crate::krbtgt_principal_name(&app.realm), Some("response too large for UDP; retry with TCP".into()), None);
                reply = rasn::der::encode(&err).unwrap_or_default();
            }
            if let Err(e) = socket.send_to(&reply, peer).await {
                tracing::debug!(%peer, "failed to send UDP reply: {e}");
            }
        });
    }
}

/// Serves TCP requests on `listener` until it errors. Each connection
/// may carry multiple length-prefixed requests (RFC 4120 §7.2.2);
/// handled sequentially per connection, concurrently across connections.
pub async fn serve_tcp(listener: TcpListener, app: Arc<AppState>) -> std::io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let app = app.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_tcp_connection(stream, app).await {
                tracing::debug!(%peer, "TCP connection ended: {e}");
            }
        });
    }
}

async fn handle_tcp_connection(mut stream: tokio::net::TcpStream, app: Arc<AppState>) -> Result<(), wire::WireError> {
    while let Some(request) = wire::read_tcp_message(&mut stream).await? {
        let reply = dispatch(&app, &request).await;
        wire::write_tcp_message(&mut stream, &reply).await?;
    }
    Ok(())
}
