//! Client-side SAMR calls (#23): encodes requests / decodes responses
//! for exactly the operations `iron_rpc::samr`'s server implements,
//! using the identical wire shapes already verified live in #19.

use iron_partition::Sid;
use iron_rpc::ndr::{NdrReader, NdrWriter};
use iron_rpc::samr;
use iron_rpc::uuid::SAMR_SYNTAX;

use crate::rpc_client::{RpcClient, RpcClientError};

fn m() -> RpcClientError {
    RpcClientError::Malformed
}

pub async fn connect(addr: &str) -> Result<RpcClient, RpcClientError> {
    RpcClient::connect(addr, *SAMR_SYNTAX).await
}

pub async fn connect5(client: &mut RpcClient) -> Result<[u8; 20], RpcClientError> {
    let mut w = NdrWriter::new();
    w.null_ptr(); // ServerName: PSAMPR_SERVER_NAME (a bare LPWSTR pointer, not RPC_UNICODE_STRING) -- NULL is valid and unused by this server anyway
    w.u32(0); // DesiredAccess
    w.u32(1); // InVersion
    w.u32(1); // InRevisionInfo tag = V1
    w.u32(1); // Revision
    w.u32(0); // SupportedFeatures
    let resp = client.call(samr::OPNUM_CONNECT5, &w.buf).await?;

    let mut r = NdrReader::new(&resp);
    let _out_version = r.u32().map_err(|_| m())?;
    let _tag = r.u32().map_err(|_| m())?;
    let _revision = r.u32().map_err(|_| m())?;
    let _supported_features = r.u32().map_err(|_| m())?;
    let handle = r.handle().map_err(|_| m())?;
    Ok(handle)
}

pub async fn lookup_domain_in_sam_server(client: &mut RpcClient, server_handle: &[u8; 20], netbios_name: &str) -> Result<Sid, RpcClientError> {
    let mut w = NdrWriter::new();
    w.handle(server_handle);
    let s = w.unicode_string_header(Some(netbios_name));
    if let Some(s) = s {
        w.unicode_string_deferred(&s);
    }
    let resp = client.call(samr::OPNUM_LOOKUP_DOMAIN, &w.buf).await?;

    let mut r = NdrReader::new(&resp);
    let _referent = r.u32().map_err(|_| m())?;
    r.sid_deferred().map_err(|_| m())
}

pub async fn open_domain(client: &mut RpcClient, server_handle: &[u8; 20], domain_sid: &Sid) -> Result<[u8; 20], RpcClientError> {
    let mut w = NdrWriter::new();
    w.handle(server_handle);
    w.u32(0); // DesiredAccess
    w.sid_deferred(domain_sid);
    let resp = client.call(samr::OPNUM_OPEN_DOMAIN, &w.buf).await?;
    resp[0..20].try_into().map_err(|_| m())
}

/// Returns `None` if the name isn't found (RID 0), matching this
/// server's own `SidTypeInvalid` convention.
pub async fn lookup_name_in_domain(client: &mut RpcClient, domain_handle: &[u8; 20], name: &str) -> Result<Option<u32>, RpcClientError> {
    let mut w = NdrWriter::new();
    w.handle(domain_handle);
    w.u32(1); // Count
    w.u32(1); // Names: MaximumCount
    w.u32(0); // Offset
    w.u32(1); // ActualCount
    let s = w.unicode_string_header(Some(name));
    if let Some(s) = s {
        w.unicode_string_deferred(&s);
    }
    let resp = client.call(samr::OPNUM_LOOKUP_NAMES, &w.buf).await?;

    let mut r = NdrReader::new(&resp);
    let _count1 = r.u32().map_err(|_| m())?;
    let _referent1 = r.u32().map_err(|_| m())?;
    let _max_count1 = r.u32().map_err(|_| m())?;
    let rid = r.u32().map_err(|_| m())?;
    Ok(if rid == 0 { None } else { Some(rid) })
}

pub async fn create_user2_in_domain(client: &mut RpcClient, domain_handle: &[u8; 20], account_name: &str) -> Result<([u8; 20], u32), RpcClientError> {
    let mut w = NdrWriter::new();
    w.handle(domain_handle);
    let s = w.unicode_string_header(Some(account_name));
    // AccountType: USER_WORKSTATION_TRUST_ACCOUNT (0x00000001 per MS-SAMR).
    // DesiredAccess follows in the fixed part, per SamrCreateUser2InDomain.
    if let Some(s) = &s {
        w.unicode_string_deferred(s);
    }
    w.u32(0x0000_0001); // AccountType
    w.u32(0); // DesiredAccess
    let resp = client.call(samr::OPNUM_CREATE_USER2_IN_DOMAIN, &w.buf).await?;

    let mut r = NdrReader::new(&resp);
    let handle = r.handle().map_err(|_| m())?;
    let _granted_access = r.u32().map_err(|_| m())?;
    let rid = r.u32().map_err(|_| m())?;
    Ok((handle, rid))
}

pub async fn close_handle(client: &mut RpcClient, handle: &[u8; 20]) -> Result<(), RpcClientError> {
    let mut w = NdrWriter::new();
    w.handle(handle);
    client.call(samr::OPNUM_CLOSE_HANDLE, &w.buf).await?;
    Ok(())
}
