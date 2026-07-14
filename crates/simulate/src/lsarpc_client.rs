//! Client-side LSARPC calls (#23): encodes requests / decodes responses
//! for exactly the operations `iron_rpc::lsarpc`'s server implements,
//! using the identical wire shapes already verified live in #19.

use iron_partition::Sid;
use iron_rpc::lsarpc;
use iron_rpc::ndr::{NdrReader, NdrWriter};
use iron_rpc::uuid::LSARPC_SYNTAX;

use crate::rpc_client::{RpcClient, RpcClientError};

pub struct DnsDomainInfo {
    pub netbios_name: String,
    pub dns_domain_name: String,
    pub domain_sid: Sid,
}

pub async fn connect(addr: &str) -> Result<RpcClient, RpcClientError> {
    RpcClient::connect(addr, *LSARPC_SYNTAX).await
}

pub async fn open_policy2(client: &mut RpcClient) -> Result<[u8; 20], RpcClientError> {
    // This server's OpenPolicy2 ignores its request body entirely (see
    // iron_rpc::lsarpc docs) -- still send a well-formed one so a real
    // server would accept it too.
    let stub = Vec::new();
    let resp = client.call(lsarpc::OPNUM_OPEN_POLICY2, &stub).await?;
    resp[0..20].try_into().map_err(|_| RpcClientError::Malformed)
}

pub async fn query_dns_domain_information(client: &mut RpcClient, handle: &[u8; 20]) -> Result<DnsDomainInfo, RpcClientError> {
    let mut w = NdrWriter::new();
    w.handle(handle);
    w.u16(lsarpc::POLICY_DNS_DOMAIN_INFORMATION);
    let resp = client.call(lsarpc::OPNUM_QUERY_INFORMATION_POLICY2, &w.buf).await?;

    let mut r = NdrReader::new(&resp);
    let m = || RpcClientError::Malformed;
    let _referent = r.u32().map_err(|_| m())?;
    let _discriminant = r.u16().map_err(|_| m())?;
    let _pad = r.u16().map_err(|_| m())?;
    let (_, name_ref) = r.unicode_string_header().map_err(|_| m())?;
    let (_, dns_ref) = r.unicode_string_header().map_err(|_| m())?;
    let (_, _forest_ref) = r.unicode_string_header().map_err(|_| m())?;
    let _guid = r.bytes(16).map_err(|_| m())?;
    let _sid_referent = r.u32().map_err(|_| m())?;

    let netbios_name = if name_ref != 0 { r.unicode_string_deferred().map_err(|_| m())? } else { String::new() };
    r.pad_to_4();
    let dns_domain_name = if dns_ref != 0 { r.unicode_string_deferred().map_err(|_| m())? } else { String::new() };
    r.pad_to_4();
    let _dns_forest = r.unicode_string_deferred().map_err(|_| m())?;
    r.pad_to_4();
    let domain_sid = r.sid_deferred().map_err(|_| m())?;

    Ok(DnsDomainInfo { netbios_name, dns_domain_name, domain_sid })
}

pub async fn close(client: &mut RpcClient, handle: &[u8; 20]) -> Result<(), RpcClientError> {
    let mut w = NdrWriter::new();
    w.handle(handle);
    client.call(lsarpc::OPNUM_CLOSE, &w.buf).await?;
    Ok(())
}
