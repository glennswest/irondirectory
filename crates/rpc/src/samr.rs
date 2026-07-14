//! SAMR (MS-SAMR): account enumeration/creation for the domain-join
//! handshake (#19), backed by the real DIT (`iron-store`) -- a computer
//! account created via `SamrCreateUser2InDomain` is a genuine entry,
//! discoverable via LDAP afterward, with a real allocated `objectSid`
//! (#17's RID pool). Password-setting (`SamrSetInformationUser2`) needs
//! an authenticated (NTLMSSP) RPC bind's session key to decrypt the
//! wire-encrypted password material -- out of scope for this pass (see
//! crate docs); a computer account created here has no Kerberos keys
//! yet.
//!
//! Handles are synthetic, not a real handle table (matching
//! `lsarpc`'s approach): a domain/server handle is a fixed constant;
//! a user handle encodes that user's RID directly in its opaque bytes,
//! so `SamrOpenUser`/`SamrQueryInformationUser2` need no server-side
//! session state at all.

use iron_partition::{Dn, Sid};
use iron_store::binary_attrs::{decode_binary_attr, encode_binary_attr, OBJECT_SID_ATTR};
use iron_store::index::IndexSpec;
use iron_store::model::Entry;
use iron_store::store::Store;
use tokio::sync::Mutex;

use crate::ndr::{NdrReader, NdrWriter};

pub const OPNUM_CLOSE_HANDLE: u16 = 1;
pub const OPNUM_LOOKUP_DOMAIN: u16 = 5;
pub const OPNUM_OPEN_DOMAIN: u16 = 7;
pub const OPNUM_LOOKUP_NAMES: u16 = 17;
pub const OPNUM_OPEN_USER: u16 = 34;
pub const OPNUM_QUERY_INFORMATION_USER2: u16 = 47;
pub const OPNUM_CREATE_USER2_IN_DOMAIN: u16 = 50;
pub const OPNUM_CONNECT5: u16 = 64;

const SERVER_HANDLE: [u8; 20] = [b'S', b'A', b'M', b'R', 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const DOMAIN_HANDLE: [u8; 20] = [b'S', b'A', b'M', b'R', 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

fn user_handle(rid: u32) -> [u8; 20] {
    let mut h = [0u8; 20];
    h[0..4].copy_from_slice(b"USR\0");
    h[4..8].copy_from_slice(&rid.to_le_bytes());
    h
}
fn rid_from_user_handle(h: &[u8; 20]) -> Option<u32> {
    if &h[0..4] != b"USR\0" {
        return None;
    }
    Some(u32::from_le_bytes(h[4..8].try_into().unwrap()))
}

pub struct SamrState {
    pub store: Mutex<Store>,
    pub base_dn: Dn,
    pub index_spec: IndexSpec,
}

pub async fn dispatch(state: &SamrState, domain_sid: &Sid, opnum: u16, stub: &[u8]) -> Option<Vec<u8>> {
    match opnum {
        OPNUM_CONNECT5 => Some(connect5()),
        OPNUM_LOOKUP_DOMAIN => Some(lookup_domain_in_sam_server(domain_sid)),
        OPNUM_OPEN_DOMAIN => Some(open_domain()),
        OPNUM_LOOKUP_NAMES => lookup_names_in_domain(state, stub).await,
        OPNUM_CREATE_USER2_IN_DOMAIN => create_user2_in_domain(state, domain_sid, stub).await,
        OPNUM_OPEN_USER => Some(open_user(stub)?),
        OPNUM_QUERY_INFORMATION_USER2 => query_information_user2(state, domain_sid, stub).await,
        OPNUM_CLOSE_HANDLE => Some(close_handle()),
        _ => None,
    }
}

fn connect5() -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.u32(1); // OutVersion
    w.u32(3); // SAMPR_REVISION_INFO_V1.SupportedFeatures (permissive default)
    w.handle(&SERVER_HANDLE);
    w.u32(0); // STATUS_SUCCESS
    w.buf
}

fn lookup_domain_in_sam_server(domain_sid: &Sid) -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.referent_id();
    w.sid_deferred(domain_sid);
    w.u32(0); // STATUS_SUCCESS
    w.buf
}

fn open_domain() -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.handle(&DOMAIN_HANDLE);
    w.u32(0);
    w.buf
}

fn close_handle() -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.handle(&[0u8; 20]);
    w.u32(0);
    w.buf
}

fn open_user(stub: &[u8]) -> Option<Vec<u8>> {
    let mut r = NdrReader::new(stub);
    let _domain_handle = r.handle().ok()?;
    let _desired_access = r.u32().ok()?;
    let rid = r.u32().ok()?;
    let mut w = NdrWriter::new();
    w.handle(&user_handle(rid));
    w.u32(0);
    Some(w.buf)
}

async fn lookup_names_in_domain(state: &SamrState, stub: &[u8]) -> Option<Vec<u8>> {
    let mut r = NdrReader::new(stub);
    let _domain_handle = r.handle().ok()?;
    let count = r.u32().ok()?;
    // RPC_UNICODE_STRING_ARRAY: a conformant array of RPC_UNICODE_STRING
    // (MaximumCount header, then `count` fixed-part headers, then deferred data).
    let _max_count = r.u32().ok()?;
    let mut headers = Vec::with_capacity(count as usize);
    for _ in 0..count {
        headers.push(r.unicode_string_header().ok()?);
    }
    let mut names = Vec::with_capacity(count as usize);
    for (_len, referent) in &headers {
        names.push(if *referent != 0 { r.unicode_string_deferred().ok()? } else { String::new() });
    }

    let mut store = state.store.lock().await;
    let mut rids = Vec::with_capacity(names.len());
    let mut uses = Vec::with_capacity(names.len());
    for name in &names {
        let dns = store.lookup_by_index(&state.base_dn, "cn", name).await.unwrap_or_default();
        let mut found = None;
        for dn in dns {
            if let Ok(Some(entry)) = store.get_entry(&dn).await {
                if let Some(rid) = object_rid(&entry) {
                    found = Some(rid);
                    break;
                }
            }
        }
        match found {
            Some(rid) => {
                rids.push(rid);
                uses.push(1u32); // SidTypeUser
            }
            None => {
                rids.push(0);
                uses.push(0u32); // SidTypeInvalid / not found
            }
        }
    }
    drop(store);

    let mut w = NdrWriter::new();
    // SAMPR_ULONG_ARRAY (RelativeIds): Count(u32) + referent + conformant array.
    w.u32(rids.len() as u32);
    w.referent_id();
    w.u32(rids.len() as u32);
    for rid in &rids {
        w.u32(*rid);
    }
    // SAMPR_ULONG_ARRAY (Use).
    w.u32(uses.len() as u32);
    w.referent_id();
    w.u32(uses.len() as u32);
    for u in &uses {
        w.u32(*u);
    }
    let all_found = rids.iter().all(|r| *r != 0);
    w.u32(if all_found { 0 } else { 0x0000_0107 }); // STATUS_SUCCESS / STATUS_SOME_NOT_MAPPED
    Some(w.buf)
}

fn object_rid(entry: &Entry) -> Option<u32> {
    let sid_b64 = entry.get(OBJECT_SID_ATTR)?.first()?;
    let sid = Sid::decode(&decode_binary_attr(sid_b64))?;
    sid.sub_authorities().last().copied()
}

async fn create_user2_in_domain(state: &SamrState, domain_sid: &Sid, stub: &[u8]) -> Option<Vec<u8>> {
    let mut r = NdrReader::new(stub);
    let _domain_handle = r.handle().ok()?;
    let (_len, referent) = r.unicode_string_header().ok()?;
    let name = if referent != 0 { r.unicode_string_deferred().ok()? } else { return None };
    let _account_type = r.u32().ok()?;
    let _desired_access = r.u32().ok()?;

    let dn = Dn::parse(&format!("cn={name},{}", state.base_dn)).ok()?;
    let mut store = state.store.lock().await;
    let rid = store.allocate_rid(&dn).await.ok()?;
    let object_sid = domain_sid.with_sub_authority(rid);

    let mut entry = Entry::new();
    entry.set("objectclass", ["top", "computer"]);
    entry.set("cn", [name.clone()]);
    entry.set(OBJECT_SID_ATTR, [encode_binary_attr(&object_sid.encode())]);
    let descriptor = iron_partition::security_descriptor::default_descriptor(domain_sid);
    entry.set(iron_store::binary_attrs::NT_SECURITY_DESCRIPTOR_ATTR, [encode_binary_attr(&descriptor)]);

    store.put_entry(&dn, &entry, &state.index_spec).await.ok()?;
    drop(store);

    let mut w = NdrWriter::new();
    w.handle(&user_handle(rid));
    w.u32(0x0200_0000); // GrantedAccess: a permissive default (USER_ALL_ACCESS-shaped)
    w.u32(rid);
    w.u32(0); // STATUS_SUCCESS
    Some(w.buf)
}

/// Minimal (`UserId` only, not a full `SAMPR_USER_ALL_INFORMATION`) --
/// this server's synthetic user handles already carry the RID (see
/// module docs), so nothing needs looking up in the DIT to answer this.
async fn query_information_user2(_state: &SamrState, _domain_sid: &Sid, stub: &[u8]) -> Option<Vec<u8>> {
    let mut r = NdrReader::new(stub);
    let handle = r.handle().ok()?;
    let _info_level = r.u16().ok()?;
    let rid = rid_from_user_handle(&handle)?;

    let mut w = NdrWriter::new();
    w.referent_id(); // Buffer: PSAMPR_USER_INFO_BUFFER
    w.u16(21); // UserInformationClass = UserAllInformation (matching level requested in practice)
    w.u16(0); // pad
    w.u32(rid); // minimal: report the RID as UserId (not full SAMPR_USER_ALL_INFORMATION shape)
    w.u32(0); // STATUS_SUCCESS
    Some(w.buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_handle_roundtrips_the_rid() {
        let h = user_handle(1234);
        assert_eq!(rid_from_user_handle(&h), Some(1234));
    }

    #[test]
    fn foreign_handle_bytes_dont_parse_as_a_user_handle() {
        assert_eq!(rid_from_user_handle(&SERVER_HANDLE), None);
    }

    #[test]
    fn connect5_response_carries_server_handle() {
        let resp = connect5();
        // OutVersion(4) + SupportedFeatures(4) + handle(20) + status(4)
        assert_eq!(&resp[8..28], &SERVER_HANDLE);
        assert_eq!(u32::from_le_bytes(resp[28..32].try_into().unwrap()), 0);
    }
}
