//! A minimal `ncacn_ip_tcp` DCE/RPC listener (#19) -- see crate docs for
//! why this transport (not `ncacn_np`/SMB named pipes, which is
//! `rocketsmbd`'s territory) and why it's still genuinely useful (real
//! Samba `rpcclient`/`net rpc` can point straight at it).
//!
//! One presentation-context binding per connection (the abstract syntax
//! negotiated by that connection's single `bind` PDU) -- real clients
//! (`rpcclient`, `net rpc`) open one connection per interface anyway, so
//! `alter_context` (binding a second interface on the same connection)
//! isn't needed for this pass.

use std::sync::Arc;

use iron_partition::Sid;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::pdu::{self, CtxResult, PduError};
use crate::uuid::{LSARPC_SYNTAX, NETLOGON_SYNTAX, SAMR_SYNTAX};
use crate::{lsarpc, netlogon, samr};

/// What this server tells clients about the domain it's serving.
pub struct DomainInfo {
    pub netbios_name: String,
    pub dns_domain_name: String,
    pub dns_forest_name: String,
    pub domain_sid: Sid,
}

pub struct AppState {
    pub domain_info: DomainInfo,
    pub samr: samr::SamrState,
    pub netlogon: netlogon::NetlogonState,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BoundInterface {
    Lsarpc,
    Samr,
    Netlogon,
}

pub async fn serve(listener: TcpListener, app: Arc<AppState>) -> std::io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        tracing::info!(%peer, "accepted RPC connection");
        let app = app.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, app).await {
                tracing::debug!(%peer, "RPC connection ended: {e}");
            }
            tracing::info!(%peer, "RPC connection closed");
        });
    }
}

async fn read_pdu(stream: &mut TcpStream) -> std::io::Result<Option<Vec<u8>>> {
    let mut header = [0u8; 16];
    if stream.read_exact(&mut header).await.is_err() {
        return Ok(None);
    }
    let frag_len = u16::from_le_bytes([header[8], header[9]]) as usize;
    if frag_len < 16 {
        return Ok(None);
    }
    let mut rest = vec![0u8; frag_len - 16];
    stream.read_exact(&mut rest).await?;
    let mut pdu = header.to_vec();
    pdu.extend_from_slice(&rest);
    Ok(Some(pdu))
}

async fn handle_connection(mut stream: TcpStream, app: Arc<AppState>) -> std::io::Result<()> {
    let mut bound: Option<(u16, BoundInterface)> = None;
    let mut netlogon_session = netlogon::Session::default();

    while let Some(pdu) = read_pdu(&mut stream).await? {
        let (header, _) = match pdu::parse_header(&pdu) {
            Ok(h) => h,
            Err(PduError::TooShort(_)) => break,
            Err(_) => break,
        };
        let body = &pdu[16..];

        match header.ptype {
            pdu::PTYPE_BIND => {
                let Some(items) = pdu::parse_bind_body(body) else { break };
                let mut results = Vec::with_capacity(items.len());
                for item in &items {
                    let iface = if item.abstract_syntax == *LSARPC_SYNTAX {
                        Some(BoundInterface::Lsarpc)
                    } else if item.abstract_syntax == *SAMR_SYNTAX {
                        Some(BoundInterface::Samr)
                    } else if item.abstract_syntax == *NETLOGON_SYNTAX {
                        Some(BoundInterface::Netlogon)
                    } else {
                        None
                    };
                    match iface {
                        Some(iface) => {
                            bound = Some((item.ctx_id, iface));
                            results.push(CtxResult::accept());
                        }
                        None => results.push(CtxResult::reject_abstract_syntax_not_supported()),
                    }
                }
                let ack = pdu::build_bind_ack(header.call_id, 4280, 1, &results);
                stream.write_all(&ack).await?;
            }
            pdu::PTYPE_REQUEST => {
                let Some(req) = pdu::parse_request_body(body) else { break };
                let response = match bound {
                    Some((ctx_id, iface)) if ctx_id == req.ctx_id => dispatch(&app, &mut netlogon_session, iface, req.opnum, req.stub_data).await,
                    _ => None,
                };
                let pdu_out = match response {
                    Some(stub) => pdu::build_response(header.call_id, req.ctx_id, &stub),
                    None => pdu::build_fault(header.call_id, req.ctx_id, pdu::FAULT_UNK_IF),
                };
                stream.write_all(&pdu_out).await?;
            }
            _ => break, // unsupported PDU type (alter_context, auth3, ...) -- not this pass's scope
        }
    }
    Ok(())
}

async fn dispatch(app: &AppState, netlogon_session: &mut netlogon::Session, iface: BoundInterface, opnum: u16, stub: &[u8]) -> Option<Vec<u8>> {
    match iface {
        BoundInterface::Lsarpc => match opnum {
            lsarpc::OPNUM_OPEN_POLICY2 => Some(lsarpc::open_policy2()),
            lsarpc::OPNUM_CLOSE => Some(lsarpc::close()),
            lsarpc::OPNUM_QUERY_INFORMATION_POLICY2 => {
                let info = lsarpc::DomainInfo {
                    netbios_name: &app.domain_info.netbios_name,
                    dns_domain_name: &app.domain_info.dns_domain_name,
                    dns_forest_name: &app.domain_info.dns_forest_name,
                    domain_sid: &app.domain_info.domain_sid,
                };
                lsarpc::query_information_policy2(stub, &info)
            }
            _ => None,
        },
        BoundInterface::Samr => samr::dispatch(&app.samr, &app.domain_info.domain_sid, opnum, stub).await,
        BoundInterface::Netlogon => netlogon::dispatch(&app.netlogon, netlogon_session, opnum, stub).await,
    }
}
