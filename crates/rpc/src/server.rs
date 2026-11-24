//! The DCE/RPC connection loop, over `ncacn_ip_tcp` (#19, [`serve`]) or
//! over an SMB named pipe forwarded by rocketsmbd ([`crate::pipe`], #53),
//! which adds the SMB session's identity and key ([`PipeIdentity`]).
//!
//! One presentation-context binding per connection (the abstract syntax
//! negotiated by that connection's single `bind` PDU) -- real clients
//! (`rpcclient`, `net rpc`) open one connection per interface anyway, so
//! `alter_context` (binding a second interface on the same connection)
//! isn't needed for this pass.
//!
//! A bind may carry Netlogon secure-channel auth (#20, [`crate::schannel`]):
//! the binding then names a computer whose channel `NetrServerAuthenticate3`
//! established, and every request on it must be signed (or sealed, at
//! `PKT_PRIVACY`) under that channel's session key; responses are too.

use std::sync::Arc;

use iron_partition::Sid;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::pdu::{self, CtxResult, PduError, SecTrailer};
use crate::pipe::PipeIdentity;
use crate::schannel::{self, AUTH_LEVEL_INTEGRITY, AUTH_LEVEL_PRIVACY, AUTH_TYPE_NETLOGON};
use crate::uuid::{LSARPC_SYNTAX, NDR_TRANSFER_SYNTAX, NETLOGON_SYNTAX, SAMR_SYNTAX};
use crate::{lsarpc, netlogon, samr, CallError};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoundInterface {
    Lsarpc,
    Samr,
    Netlogon,
}

/// Answers each presentation context of a bind: an interface this server
/// serves, in NDR 2.0, is accepted; an unknown interface is refused
/// (abstract syntax not supported); any other transfer syntax -- NDR64, or
/// MS-RPCE 3.3.1.5.3 bind-time feature negotiation -- is refused (transfer
/// syntaxes not supported). Samba's rpcclient offers SAMR as both NDR 2.0
/// and NDR64 plus a feature context, then calls on the NDR 2.0 one, so
/// every accepted context is kept, not just one.
fn negotiate_contexts(items: &[pdu::BindCtxItem]) -> (Vec<CtxResult>, Vec<(u16, BoundInterface)>) {
    let mut results = Vec::with_capacity(items.len());
    let mut accepted = Vec::new();
    for item in items {
        let iface = if item.abstract_syntax == *LSARPC_SYNTAX {
            Some(BoundInterface::Lsarpc)
        } else if item.abstract_syntax == *SAMR_SYNTAX {
            Some(BoundInterface::Samr)
        } else if item.abstract_syntax == *NETLOGON_SYNTAX {
            Some(BoundInterface::Netlogon)
        } else {
            None
        };
        if item.transfer_syntax != *NDR_TRANSFER_SYNTAX {
            results.push(CtxResult::reject_transfer_syntax_not_supported());
        } else if let Some(iface) = iface {
            accepted.push((item.ctx_id, iface));
            results.push(CtxResult::accept());
        } else {
            results.push(CtxResult::reject_abstract_syntax_not_supported());
        }
    }
    (results, accepted)
}

pub async fn serve(listener: TcpListener, app: Arc<AppState>) -> std::io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        tracing::info!(%peer, "accepted RPC connection");
        let app = app.clone();
        tokio::spawn(async move {
            let peer = peer.to_string();
            if let Err(e) = handle_connection(stream, &peer, app, None).await {
                tracing::debug!(%peer, "RPC connection ended: {e}");
            }
            tracing::info!(%peer, "RPC connection closed");
        });
    }
}

async fn read_pdu<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<Option<Vec<u8>>> {
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

/// A binding authenticated with the Netlogon secure channel.
struct SchannelAuth {
    computer: String,
    level: u8,
    context_id: u32,
    session_key: [u8; 16],
    /// MS-NRPC's one counter for both directions: request N, response N+1.
    seq: u64,
}

/// What an authenticated bind asks for: the binding, or a `bind_nak` reason.
fn schannel_bind(app: &AppState, peer: &str, trailer: SecTrailer, value: &[u8]) -> Result<SchannelAuth, u16> {
    if trailer.auth_type != AUTH_TYPE_NETLOGON {
        tracing::warn!(%peer, auth_type = trailer.auth_type, "bind with an auth type other than Netlogon (68) refused");
        return Err(pdu::NAK_AUTH_TYPE_NOT_RECOGNIZED);
    }
    if trailer.auth_level != AUTH_LEVEL_INTEGRITY && trailer.auth_level != AUTH_LEVEL_PRIVACY {
        tracing::warn!(%peer, level = trailer.auth_level, "Netlogon bind below PKT_INTEGRITY refused");
        return Err(pdu::NAK_NOT_SPECIFIED);
    }
    let Some(computer) = schannel::auth_message_computer(value) else {
        tracing::warn!(%peer, "Netlogon bind: NL_AUTH_MESSAGE names no computer");
        return Err(pdu::NAK_NOT_SPECIFIED);
    };
    let Some(session_key) = app.netlogon.session_key(&computer) else {
        tracing::warn!(%peer, %computer, "Netlogon bind: no secure channel for this computer (NetrServerAuthenticate3 first)");
        return Err(pdu::NAK_INVALID_CHECKSUM);
    };
    tracing::info!(%peer, %computer, level = trailer.auth_level, "Netlogon secure channel bind");
    Ok(SchannelAuth { computer, level: trailer.auth_level, context_id: trailer.context_id, session_key, seq: 0 })
}

/// `NL_AUTH_MESSAGE` response (MS-NRPC 2.2.1.3.1): MessageType 1, no
/// flags, a 4-byte buffer.
const NL_AUTH_MESSAGE_RESPONSE: [u8; 12] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

/// Serves one connection until it closes. `identity` is the SMB session's
/// when the connection is a forwarded pipe, `None` over TCP.
pub async fn handle_connection<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, peer: &str, app: Arc<AppState>, identity: Option<PipeIdentity>) -> std::io::Result<()> {
    // Every presentation context the last bind accepted.
    let mut bound: Vec<(u16, BoundInterface)> = Vec::new();
    let mut netlogon_session = netlogon::Session::default();
    let mut auth: Option<SchannelAuth> = None;

    while let Some(pdu) = read_pdu(&mut stream).await? {
        let (header, _) = match pdu::parse_header(&pdu) {
            Ok(h) => h,
            Err(PduError::TooShort(_)) => break,
            Err(_) => break,
        };
        let (body, sec) = if header.auth_len > 0 {
            match pdu::split_auth(&pdu, header.auth_len) {
                Some((body, trailer, value)) => (body, Some((trailer, value))),
                None => break,
            }
        } else {
            (&pdu[16..], None)
        };

        match header.ptype {
            pdu::PTYPE_BIND => {
                let Some(items) = pdu::parse_bind_body(body) else { break };
                auth = None;
                let mut ack_auth = None;
                if let Some((trailer, value)) = sec {
                    match schannel_bind(&app, peer, trailer, value) {
                        Ok(a) => {
                            ack_auth = Some(SecTrailer { auth_type: AUTH_TYPE_NETLOGON, auth_level: a.level, auth_pad_len: 0, context_id: a.context_id });
                            auth = Some(a);
                        }
                        Err(reason) => {
                            stream.write_all(&pdu::build_bind_nak(header.call_id, reason)).await?;
                            continue;
                        }
                    }
                }
                let (results, accepted) = negotiate_contexts(&items);
                bound = accepted;
                let ack = pdu::build_bind_ack_auth(header.call_id, 4280, 1, &results, ack_auth.as_ref().map(|t| (*t, &NL_AUTH_MESSAGE_RESPONSE[..])));
                stream.write_all(&ack).await?;
            }
            pdu::PTYPE_REQUEST => {
                let Some(req) = pdu::parse_request_body(body) else { break };
                // On an authenticated binding: check (and unseal) the stub.
                let stub: Vec<u8> = match (&mut auth, sec) {
                    (Some(a), Some((trailer, value))) if trailer.auth_type == AUTH_TYPE_NETLOGON && trailer.auth_level == a.level => {
                        match schannel::unprotect(&app.netlogon.fips, &a.session_key, a.seq, true, a.level == AUTH_LEVEL_PRIVACY, req.stub_data, value) {
                            Ok(mut plain) => {
                                a.seq += 1;
                                plain.truncate(plain.len().saturating_sub(trailer.auth_pad_len as usize));
                                plain
                            }
                            Err(e) => {
                                tracing::warn!(%peer, computer = %a.computer, "Netlogon secure channel request refused: {e}");
                                stream.write_all(&pdu::build_fault(header.call_id, req.ctx_id, pdu::FAULT_ACCESS_DENIED)).await?;
                                break;
                            }
                        }
                    }
                    (None, None) => req.stub_data.to_vec(),
                    _ => {
                        tracing::warn!(%peer, "request's auth does not match its binding's");
                        stream.write_all(&pdu::build_fault(header.call_id, req.ctx_id, pdu::FAULT_ACCESS_DENIED)).await?;
                        break;
                    }
                };
                let binding = auth.as_ref().map(|a| netlogon::Binding { computer: a.computer.clone(), auth_level: a.level });
                let status = match bound.iter().find(|(ctx_id, _)| *ctx_id == req.ctx_id).map(|(_, iface)| *iface) {
                    Some(iface) => match dispatch(&app, &mut netlogon_session, binding.as_ref(), identity.as_ref(), iface, req.opnum, &stub).await {
                        Ok(stub) => Ok(stub),
                        Err(e) => {
                            tracing::warn!(%peer, ?iface, opnum = req.opnum, "RPC call faulted: {e:?}");
                            Err(match e {
                                CallError::UnknownOpnum => pdu::FAULT_OP_RNG_ERROR,
                                CallError::Malformed => pdu::FAULT_NDR,
                            })
                        }
                    },
                    _ => {
                        tracing::warn!(%peer, ctx_id = req.ctx_id, "RPC request on a presentation context no bind accepted");
                        Err(pdu::FAULT_UNK_IF)
                    }
                };
                let pdu_out = match (status, &mut auth) {
                    (Ok(stub), Some(a)) => match protect_response(&app, a, header.call_id, req.ctx_id, &stub) {
                        Ok(pdu) => pdu,
                        Err(e) => {
                            tracing::warn!(%peer, "could not sign the response: {e}");
                            break;
                        }
                    },
                    (Ok(stub), None) => pdu::build_response(header.call_id, req.ctx_id, &stub),
                    (Err(fault), _) => pdu::build_fault(header.call_id, req.ctx_id, fault),
                };
                stream.write_all(&pdu_out).await?;
            }
            _ => break, // unsupported PDU type (alter_context, auth3, ...) -- not this pass's scope
        }
    }
    Ok(())
}

/// Pads `stub` to 16 bytes (as Samba's DCERPC_AUTH_PAD_ALIGNMENT), signs or
/// seals it as the binding's next sequence number, and frames it.
fn protect_response(app: &AppState, a: &mut SchannelAuth, call_id: u32, ctx_id: u16, stub: &[u8]) -> Result<Vec<u8>, String> {
    let pad = (16 - stub.len() % 16) % 16;
    let mut padded = stub.to_vec();
    padded.resize(stub.len() + pad, 0);
    let confounder = if a.level == AUTH_LEVEL_PRIVACY {
        let r = iron_crypto::kerberos::random_bytes(&app.netlogon.fips, 8).map_err(|e| e.to_string())?;
        Some(<[u8; 8]>::try_from(r).map_err(|_| "confounder")?)
    } else {
        None
    };
    let (wire, sig) = schannel::protect(&app.netlogon.fips, &a.session_key, a.seq, false, confounder, &padded).map_err(|e| e.to_string())?;
    a.seq += 1;
    let trailer = SecTrailer { auth_type: AUTH_TYPE_NETLOGON, auth_level: a.level, auth_pad_len: pad as u8, context_id: a.context_id };
    Ok(pdu::build_response_auth(call_id, ctx_id, stub.len() as u32, &wire, trailer, &sig))
}

async fn dispatch(app: &AppState, netlogon_session: &mut netlogon::Session, binding: Option<&netlogon::Binding>, identity: Option<&PipeIdentity>, iface: BoundInterface, opnum: u16, stub: &[u8]) -> Result<Vec<u8>, CallError> {
    match iface {
        BoundInterface::Lsarpc => match opnum {
            lsarpc::OPNUM_OPEN_POLICY2 => Ok(lsarpc::open_policy2()),
            lsarpc::OPNUM_CLOSE => Ok(lsarpc::close()),
            lsarpc::OPNUM_QUERY_INFORMATION_POLICY2 => {
                let info = lsarpc::DomainInfo {
                    netbios_name: &app.domain_info.netbios_name,
                    dns_domain_name: &app.domain_info.dns_domain_name,
                    dns_forest_name: &app.domain_info.dns_forest_name,
                    domain_sid: &app.domain_info.domain_sid,
                };
                lsarpc::query_information_policy2(stub, &info).ok_or(CallError::Malformed)
            }
            _ => Err(CallError::UnknownOpnum),
        },
        BoundInterface::Samr => samr::dispatch(app, identity, opnum, stub).await,
        BoundInterface::Netlogon => netlogon::dispatch(&app.netlogon, netlogon_session, binding, opnum, stub).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uuid::syntax_id;

    fn item(ctx_id: u16, abstract_syntax: [u8; 20], transfer_syntax: [u8; 20]) -> pdu::BindCtxItem {
        pdu::BindCtxItem { ctx_id, abstract_syntax, transfer_syntax }
    }

    /// The bind Samba's rpcclient sends for \PIPE\samr: SAMR in NDR 2.0
    /// (ctx 0) and NDR64 (ctx 1), then bind-time feature negotiation (ctx 2).
    /// It then calls on ctx 0, which the server took for ctx 1 before.
    #[test]
    fn samba_shaped_bind_accepts_only_the_ndr20_context() {
        let ndr64 = syntax_id("71710533-beba-4937-8319-b5dbef9ccc36", 1, 0);
        let features = syntax_id("6cb71c2c-9812-4540-0300-000000000000", 1, 0);
        let items = [item(0, *SAMR_SYNTAX, *NDR_TRANSFER_SYNTAX), item(1, *SAMR_SYNTAX, ndr64), item(2, *SAMR_SYNTAX, features)];
        let (results, accepted) = negotiate_contexts(&items);
        assert_eq!(accepted, vec![(0, BoundInterface::Samr)]);
        let got: Vec<(u16, u16)> = results.iter().map(|r| (r.result, r.reason)).collect();
        assert_eq!(got, vec![(0, 0), (2, 2), (2, 2)]);
    }

    #[test]
    fn every_known_ndr20_context_is_kept_and_unknown_interfaces_are_refused() {
        let unknown = syntax_id("4b324fc8-1670-01d3-1278-5a47bf6ee188", 3, 0); // srvsvc: not served here
        let items = [item(0, *LSARPC_SYNTAX, *NDR_TRANSFER_SYNTAX), item(1, unknown, *NDR_TRANSFER_SYNTAX), item(2, *NETLOGON_SYNTAX, *NDR_TRANSFER_SYNTAX)];
        let (results, accepted) = negotiate_contexts(&items);
        assert_eq!(accepted, vec![(0, BoundInterface::Lsarpc), (2, BoundInterface::Netlogon)]);
        let got: Vec<(u16, u16)> = results.iter().map(|r| (r.result, r.reason)).collect();
        assert_eq!(got, vec![(0, 0), (2, 1), (0, 0)]);
    }
}
