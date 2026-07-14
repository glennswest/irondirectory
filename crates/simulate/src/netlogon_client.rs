//! Client-side NETLOGON secure-channel handshake (#23): encodes
//! requests / decodes responses for `NetrServerReqChallenge`/
//! `NetrServerAuthenticate3`, computing the session key/credentials
//! with the exact same math `iron_rpc::netlogon`'s server half uses
//! (reused directly, not reimplemented) -- proving the two sides
//! genuinely agree, not just that the wire framing round-trips.

use iron_crypto::FipsContext;
use iron_rpc::ndr::{NdrReader, NdrWriter};
use iron_rpc::netlogon::{self, NETLOGON_NEG_SUPPORTS_AES};
use iron_rpc::uuid::NETLOGON_SYNTAX;

use crate::rpc_client::{RpcClient, RpcClientError};

fn m() -> RpcClientError {
    RpcClientError::Malformed
}

pub async fn connect(addr: &str) -> Result<RpcClient, RpcClientError> {
    RpcClient::connect(addr, *NETLOGON_SYNTAX).await
}

pub async fn req_challenge(client: &mut RpcClient, computer_name: &str, client_challenge: &[u8; 8]) -> Result<[u8; 8], RpcClientError> {
    let mut w = NdrWriter::new();
    w.null_ptr(); // PrimaryName: PLOGONSRV_HANDLE -- NULL is valid (server doesn't use it)
    w.embedded_wstr(computer_name);
    w.bytes(client_challenge);
    let resp = client.call(netlogon::OPNUM_SERVER_REQ_CHALLENGE, &w.buf).await?;

    let mut r = NdrReader::new(&resp);
    let server_challenge: [u8; 8] = r.bytes(8).map_err(|_| m())?.try_into().map_err(|_| m())?;
    let status = r.u32().map_err(|_| m())?;
    if status != 0 {
        return Err(RpcClientError::Fault(status));
    }
    Ok(server_challenge)
}

/// Establishes the secure channel: computes the session key from
/// `ntowf` and both challenges, sends the client credential, and
/// verifies the server's returned credential matches what's
/// independently expected -- returning the negotiated session key for
/// any further (out of scope here) authenticated NETLOGON calls.
#[allow(clippy::too_many_arguments)]
pub async fn authenticate3(
    client: &mut RpcClient,
    fips: &FipsContext,
    account_name: &str,
    computer_name: &str,
    ntowf: &[u8; 16],
    client_challenge: &[u8; 8],
    server_challenge: &[u8; 8],
) -> Result<[u8; 16], RpcClientError> {
    let session_key = netlogon::compute_session_key_aes(fips, ntowf, client_challenge, server_challenge).map_err(|_| m())?;
    let client_credential = netlogon::compute_credential(fips, &session_key, client_challenge).map_err(|_| m())?;

    let mut w = NdrWriter::new();
    w.null_ptr(); // PrimaryName
    w.embedded_wstr(account_name);
    w.u16(2); // SecureChannelType = WorkstationSecureChannel
    w.embedded_wstr(computer_name);
    w.bytes(&client_credential);
    w.u32(NETLOGON_NEG_SUPPORTS_AES);
    let resp = client.call(netlogon::OPNUM_SERVER_AUTHENTICATE3, &w.buf).await?;

    let mut r = NdrReader::new(&resp);
    let server_credential: [u8; 8] = r.bytes(8).map_err(|_| m())?.try_into().map_err(|_| m())?;
    let _negotiate_flags = r.u32().map_err(|_| m())?;
    let _account_rid = r.u32().map_err(|_| m())?;
    let status = r.u32().map_err(|_| m())?;
    if status != 0 {
        return Err(RpcClientError::Fault(status));
    }

    let expected_server_credential = netlogon::compute_credential(fips, &session_key, server_challenge).map_err(|_| m())?;
    if expected_server_credential != server_credential {
        return Err(m());
    }
    Ok(session_key)
}
