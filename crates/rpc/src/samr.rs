//! SAMR (MS-SAMR): account enumeration/creation for the domain-join
//! handshake (#19), backed by the real DIT (`iron-store`) -- a computer
//! account created via `SamrCreateUser2InDomain` is a genuine entry,
//! discoverable via LDAP afterward, with a real allocated `objectSid`
//! (#17's RID pool).
//!
//! Over an SMB named pipe (#53, [`crate::pipe`]) the caller is the SMB
//! session's user. There a Domain Admin (by the Kerberos PAC) may create
//! accounts and set their passwords with `SamrSetInformationUser2` /
//! `SamrSetInformationUser` at `UserInternal7InformationNew` (31), the AES
//! password buffer keyed from the SMB session key ([`crate::samr_aes`]);
//! the account gets its NTOWF and Kerberos keys as from
//! `NetrServerPasswordSet2`, after the domain's password policy (#70). The
//! RC4 levels (23-26) are refused (`STATUS_INVALID_INFO_CLASS`): D4. No
//! password can be set over `ncacn_ip_tcp`, which has no session key.
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
use crate::pipe::PipeIdentity;
use crate::samr_aes::EncryptedPasswordAes;
use crate::server::{AppState, DomainInfo};
use crate::{ntstatus, CallError};

pub const OPNUM_CLOSE_HANDLE: u16 = 1;
pub const OPNUM_LOOKUP_DOMAIN: u16 = 5;
pub const OPNUM_ENUMERATE_DOMAINS: u16 = 6;
pub const OPNUM_OPEN_DOMAIN: u16 = 7;
pub const OPNUM_LOOKUP_NAMES: u16 = 17;
pub const OPNUM_OPEN_USER: u16 = 34;
pub const OPNUM_SET_INFORMATION_USER: u16 = 37;
pub const OPNUM_QUERY_INFORMATION_USER2: u16 = 47;
pub const OPNUM_CREATE_USER2_IN_DOMAIN: u16 = 50;
pub const OPNUM_SET_INFORMATION_USER2: u16 = 58;
pub const OPNUM_CONNECT5: u16 = 64;

/// `UserInternal7InformationNew`: `SAMPR_USER_INTERNAL7_INFORMATION`, an
/// AES-encrypted password and a PasswordExpired flag.
pub const USER_INTERNAL7_INFORMATION_NEW: u16 = 31;
/// `SamrConnect5`'s `SAM_SUPPORTED_FEATURES` bit: the server takes AES
/// password buffers (so clients use them, not RC4).
const SAMR_CONNECT_FEATURE_USE_AES: u32 = 0x10;

const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_WRONG_PASSWORD: u32 = 0xC000_006A; // the AES buffer did not authenticate or decrypt
const STATUS_PASSWORD_RESTRICTION: u32 = 0xC000_006C;
const STATUS_NO_SUCH_USER: u32 = 0xC000_0064;
const STATUS_NO_SUCH_DOMAIN: u32 = 0xC000_00DF;

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

/// `Ok` is the response stub; a handler's `None` means its stub didn't
/// decode. `identity` is the SMB session's on a named pipe, `None` over TCP.
pub async fn dispatch(app: &AppState, identity: Option<&PipeIdentity>, opnum: u16, stub: &[u8]) -> Result<Vec<u8>, CallError> {
    let state = &app.samr;
    let domain = &app.domain_info;
    let domain_sid = &domain.domain_sid;
    let response = match opnum {
        OPNUM_CONNECT5 => Some(connect5()),
        OPNUM_ENUMERATE_DOMAINS => Some(enumerate_domains(&domain.netbios_name)),
        OPNUM_LOOKUP_DOMAIN => lookup_domain_in_sam_server(domain, stub),
        OPNUM_OPEN_DOMAIN => open_domain(domain_sid, stub),
        OPNUM_LOOKUP_NAMES => lookup_names_in_domain(state, stub).await,
        OPNUM_CREATE_USER2_IN_DOMAIN => {
            // Over a pipe the caller is known: only a Domain Admin creates
            // accounts. (ncacn_ip_tcp keeps its unauthenticated create, #76.)
            if identity.is_some_and(|id| !id.is_domain_admin(domain_sid)) {
                tracing::warn!(user = %identity.map(|i| i.user.as_str()).unwrap_or(""), "SamrCreateUser2InDomain denied: not a Domain Admin");
                Some(create_user2_response(0, ntstatus::ACCESS_DENIED))
            } else {
                create_user2_in_domain(state, domain_sid, stub).await
            }
        }
        OPNUM_OPEN_USER => open_user(state, domain_sid, stub).await,
        OPNUM_QUERY_INFORMATION_USER2 => query_information_user2(state, domain_sid, stub).await,
        OPNUM_SET_INFORMATION_USER | OPNUM_SET_INFORMATION_USER2 => set_information_user(app, identity, stub).await,
        OPNUM_CLOSE_HANDLE => Some(close_handle()),
        _ => return Err(CallError::UnknownOpnum),
    };
    response.ok_or(CallError::Malformed)
}

fn status_only(status: u32) -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.u32(status);
    w.buf
}

/// `SamrEnumerateDomainsInSamServer`: this server's one domain (no
/// `Builtin`, which it does not serve).
fn enumerate_domains(netbios_name: &str) -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.u32(0); // EnumerationContext: done
    w.referent_id(); // *Buffer
    w.u32(1); // EntriesRead
    w.referent_id(); // Buffer->Buffer
    w.u32(1); // conformant array MaximumCount
    w.u32(0); // RelativeId (unused for domains)
    let name = w.unicode_string_header(Some(netbios_name));
    if let Some(name) = name {
        w.unicode_string_deferred(&name);
    }
    w.u32(1); // CountReturned
    w.u32(ntstatus::SUCCESS);
    w.buf
}

fn connect5() -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.u32(1); // OutVersion
    // SAMPR_REVISION_INFO is an NDR union discriminated by a leading
    // `tag` ULONG -- only arm 1 (V1) exists, so the tag must be 1, not
    // OutVersion's own value (a prior version of this function
    // conflated the two and omitted the tag/Revision fields entirely).
    w.u32(1); // union tag = V1
    w.u32(1); // SAMPR_REVISION_INFO_V1.Revision
    w.u32(SAMR_CONNECT_FEATURE_USE_AES); // SAMPR_REVISION_INFO_V1.SupportedFeatures
    w.handle(&SERVER_HANDLE);
    w.u32(0); // STATUS_SUCCESS
    w.buf
}

/// `SamrLookupDomainInSamServer`: the domain SID for this server's
/// NetBIOS or DNS domain name; any other name is `STATUS_NO_SUCH_DOMAIN`.
fn lookup_domain_in_sam_server(domain: &DomainInfo, stub: &[u8]) -> Option<Vec<u8>> {
    let mut r = NdrReader::new(stub);
    let _server_handle = r.handle().ok()?;
    let (_len, referent) = r.unicode_string_header().ok()?;
    let name = if referent != 0 { r.unicode_string_deferred().ok()? } else { String::new() };
    let mut w = NdrWriter::new();
    if name.eq_ignore_ascii_case(&domain.netbios_name) || name.eq_ignore_ascii_case(&domain.dns_domain_name) {
        w.referent_id();
        w.sid_deferred(&domain.domain_sid);
        w.u32(ntstatus::SUCCESS);
    } else {
        tracing::warn!(%name, "SamrLookupDomainInSamServer: not this server's domain");
        w.null_ptr();
        w.u32(STATUS_NO_SUCH_DOMAIN);
    }
    Some(w.buf)
}

/// `SamrOpenDomain`: only this server's domain SID opens.
fn open_domain(domain_sid: &Sid, stub: &[u8]) -> Option<Vec<u8>> {
    let mut r = NdrReader::new(stub);
    let _server_handle = r.handle().ok()?;
    let _desired_access = r.u32().ok()?;
    let sid = r.sid_deferred().ok()?;
    let mut w = NdrWriter::new();
    if sid == *domain_sid {
        w.handle(&DOMAIN_HANDLE);
        w.u32(ntstatus::SUCCESS);
    } else {
        tracing::warn!(sid = %sid, "SamrOpenDomain: not this server's domain");
        w.handle(&[0u8; 20]);
        w.u32(STATUS_NO_SUCH_DOMAIN);
    }
    Some(w.buf)
}

fn close_handle() -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.handle(&[0u8; 20]);
    w.u32(0);
    w.buf
}

/// `SamrOpenUser`: a handle for an account that exists, else
/// `STATUS_NO_SUCH_USER`.
async fn open_user(state: &SamrState, domain_sid: &Sid, stub: &[u8]) -> Option<Vec<u8>> {
    let mut r = NdrReader::new(stub);
    let _domain_handle = r.handle().ok()?;
    let _desired_access = r.u32().ok()?;
    let rid = r.u32().ok()?;
    let mut w = NdrWriter::new();
    match find_by_rid(state, domain_sid, rid).await {
        Ok(Some(_)) => {
            w.handle(&user_handle(rid));
            w.u32(ntstatus::SUCCESS);
        }
        Ok(None) => {
            w.handle(&[0u8; 20]);
            w.u32(STATUS_NO_SUCH_USER);
        }
        Err(e) => {
            tracing::warn!(rid, "SamrOpenUser: {e}");
            w.handle(&[0u8; 20]);
            w.u32(ntstatus::INTERNAL_DB_ERROR);
        }
    }
    Some(w.buf)
}

/// The account whose `objectSid` is `domain_sid`-`rid`. A scan of the
/// partition (SAMR's handles carry only the RID; `objectSid` has no index).
async fn find_by_rid(state: &SamrState, domain_sid: &Sid, rid: u32) -> Result<Option<(Dn, Entry)>, String> {
    let want = domain_sid.with_sub_authority(rid);
    let mut store = state.store.lock().await;
    let rows = store.scan_subtree(&state.base_dn).await.map_err(|e| e.to_string())?;
    Ok(rows.into_iter().find(|(_, e)| {
        e.get(OBJECT_SID_ATTR).and_then(|v| v.first()).and_then(|b64| Sid::decode(&decode_binary_attr(b64))).is_some_and(|s| s == want)
    }))
}

/// `SAMPR_ENCRYPTED_PASSWORD_AES` and PasswordExpired, from a
/// `SamrSetInformationUser`/`2` stub at level 31: `(handle, level,
/// password, expired)`, `None` if it does not decode. Other levels
/// return before the buffer is read.
#[allow(clippy::type_complexity)]
fn parse_set_information(stub: &[u8]) -> Option<([u8; 20], u16, Option<(EncryptedPasswordAes, bool)>)> {
    let mut r = NdrReader::new(stub);
    let handle = r.handle().ok()?;
    let level = r.u16().ok()?;
    // Buffer: a [ref] pointer (nothing on the wire) to the union, whose
    // u16 discriminant comes first.
    let arm = r.u16().ok()?;
    if arm != level {
        return None;
    }
    if level != USER_INTERNAL7_INFORMATION_NEW {
        return Some((handle, level, None));
    }
    // SAMPR_USER_INTERNAL7_INFORMATION: 8-aligned (PBKDF2Iterations is a hyper).
    r.align(8);
    let auth_data: [u8; 64] = r.bytes(64).ok()?.try_into().ok()?;
    let salt: [u8; 16] = r.bytes(16).ok()?.try_into().ok()?;
    let cipher_len = r.u32().ok()? as usize;
    let cipher_ref = r.u32().ok()?;
    r.align(8);
    let pbkdf2_iterations = r.u64().ok()?;
    let expired = r.u8().ok()? != 0;
    // Deferred: the conformant Cipher array.
    let cipher = if cipher_ref != 0 {
        r.align(4);
        let max = r.u32().ok()? as usize;
        if max != cipher_len {
            return None;
        }
        r.bytes(cipher_len).ok()?.to_vec()
    } else {
        Vec::new()
    };
    Some((handle, level, Some((EncryptedPasswordAes { auth_data, salt, cipher, pbkdf2_iterations }, expired))))
}

/// `SamrSetInformationUser` / `SamrSetInformationUser2` (module docs).
async fn set_information_user(app: &AppState, identity: Option<&PipeIdentity>, stub: &[u8]) -> Option<Vec<u8>> {
    let (handle, level, password) = parse_set_information(stub)?;
    let domain_sid = &app.domain_info.domain_sid;
    let Some(rid) = rid_from_user_handle(&handle) else {
        return Some(status_only(STATUS_INVALID_HANDLE));
    };
    let Some((enc, expired)) = password else {
        tracing::warn!(rid, level, "SamrSetInformationUser2: information level not served (only 31, UserInternal7InformationNew: AES)");
        return Some(status_only(STATUS_INVALID_INFO_CLASS));
    };
    let Some(identity) = identity else {
        tracing::warn!(rid, "SamrSetInformationUser2 denied: not over an SMB named pipe (no session key, no caller)");
        return Some(status_only(ntstatus::ACCESS_DENIED));
    };
    if !identity.is_domain_admin(domain_sid) {
        tracing::warn!(rid, user = %identity.user, "SamrSetInformationUser2 denied: not a Domain Admin");
        return Some(status_only(ntstatus::ACCESS_DENIED));
    }
    let buffer = match crate::samr_aes::decrypt(&app.netlogon.fips, &identity.session_key, &enc) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(rid, user = %identity.user, "SamrSetInformationUser2 denied: {e}");
            return Some(status_only(STATUS_WRONG_PASSWORD));
        }
    };
    let utf16 = match crate::samr_aes::password_from_buffer(&buffer) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(rid, "SamrSetInformationUser2 denied: {e}");
            return Some(status_only(STATUS_WRONG_PASSWORD));
        }
    };
    let (dn, entry) = match find_by_rid(&app.samr, domain_sid, rid).await {
        Ok(Some(found)) => found,
        Ok(None) => return Some(status_only(STATUS_NO_SUCH_USER)),
        Err(e) => {
            tracing::warn!(rid, "SamrSetInformationUser2: {e}");
            return Some(status_only(ntstatus::INTERNAL_DB_ERROR));
        }
    };
    let account = entry
        .get("samaccountname")
        .or_else(|| entry.get("cn"))
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_default();
    match crate::netlogon::store_password(&app.netlogon, &dn, entry, &account, &utf16, expired).await {
        Ok(principal) => {
            tracing::info!(rid, %dn, %principal, by = %identity.user, expired, "SamrSetInformationUser2: password set (AES)");
            Some(status_only(ntstatus::SUCCESS))
        }
        Err(e) => {
            tracing::warn!(rid, %dn, by = %identity.user, "SamrSetInformationUser2 refused: {e}");
            Some(status_only(STATUS_PASSWORD_RESTRICTION))
        }
    }
}

async fn lookup_names_in_domain(state: &SamrState, stub: &[u8]) -> Option<Vec<u8>> {
    let mut r = NdrReader::new(stub);
    let _domain_handle = r.handle().ok()?;
    let count = r.u32().ok()?;
    // Names: RPC_UNICODE_STRING_ARRAY -- embedded directly (not behind a
    // pointer), and *conformant-varying* (impacket's
    // NDRUniConformantVaryingArray): MaximumCount, Offset, ActualCount
    // (3 header words, not 1 -- an earlier version of this function only
    // read one and misaligned every read after it, caught live against a
    // real impacket client), then `count` RPC_UNICODE_STRING fixed-part
    // headers, then deferred string data.
    let _max_count = r.u32().ok()?;
    let _offset = r.u32().ok()?;
    let _actual_count = r.u32().ok()?;
    let mut headers = Vec::with_capacity(count as usize);
    for _ in 0..count {
        headers.push(r.unicode_string_header().ok()?);
    }
    let mut names = Vec::with_capacity(count as usize);
    for (_len, referent) in &headers {
        let name = if *referent != 0 { r.unicode_string_deferred().ok()? } else { String::new() };
        r.pad_to_4(); // each RPC_UNICODE_STRING's deferred data is 4-byte aligned before the next
        names.push(name);
    }

    let mut store = state.store.lock().await;
    let mut rids = Vec::with_capacity(names.len());
    let mut uses = Vec::with_capacity(names.len());
    for name in &names {
        let dns = store.lookup_by_index(&state.base_dn, "cn", name).await.unwrap_or_else(|e| {
            tracing::warn!(name, "SamrLookupNamesInDomain: index lookup failed: {e}");
            Vec::new()
        });
        let mut found = None;
        for dn in dns {
            match store.get_entry(&dn).await {
                Ok(Some(entry)) => {
                    if let Some(rid) = object_rid(&entry) {
                        found = Some(rid);
                        break;
                    }
                }
                Ok(None) => {}
                Err(e) => tracing::warn!(%dn, "SamrLookupNamesInDomain: read failed: {e}"),
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
    r.pad_to_4(); // AccountType (a plain ULONG) needs 4-byte alignment
    let account_type = r.u32().ok()?;
    let _desired_access = r.u32().ok()?;
    let Some((classes, uac)) = account_shape(account_type) else {
        tracing::warn!(%name, account_type, "SamrCreateUser2InDomain: AccountType is not one of USER_NORMAL/WORKSTATION_TRUST/SERVER_TRUST/INTERDOMAIN_TRUST_ACCOUNT");
        return Some(create_user2_response(0, STATUS_INVALID_PARAMETER));
    };

    let dn = Dn::parse(&format!("cn={name},{}", state.base_dn)).ok()?;
    let mut store = state.store.lock().await;
    let rid = match store.allocate_rid(&dn).await {
        Ok(rid) => rid,
        Err(e) => {
            tracing::warn!(%dn, "SamrCreateUser2InDomain: RID allocation failed: {e}");
            return Some(create_user2_response(0, ntstatus::INTERNAL_DB_ERROR));
        }
    };
    let object_sid = domain_sid.with_sub_authority(rid);

    let mut entry = Entry::new();
    entry.set("objectclass", classes.iter().copied());
    entry.set("cn", [name.clone()]);
    entry.set("samaccountname", [name.clone()]);
    entry.set("useraccountcontrol", [uac.to_string()]);
    entry.set(OBJECT_SID_ATTR, [encode_binary_attr(&object_sid.encode())]);
    let descriptor = iron_partition::security_descriptor::default_descriptor(domain_sid);
    entry.set(iron_store::binary_attrs::NT_SECURITY_DESCRIPTOR_ATTR, [encode_binary_attr(&descriptor)]);

    // Create-only: an existing account is STATUS_USER_EXISTS, as on
    // Windows, not overwritten with a new SID (the RID just allocated is
    // burnt, as AD burns one on a failed create).
    let status = match store.create_entry(&dn, &entry, &state.index_spec).await {
        Ok(true) => ntstatus::SUCCESS,
        Ok(false) => {
            tracing::warn!(%dn, "SamrCreateUser2InDomain: account already exists");
            ntstatus::USER_EXISTS
        }
        Err(e) => {
            tracing::warn!(%dn, "SamrCreateUser2InDomain: write failed: {e}");
            ntstatus::INTERNAL_DB_ERROR
        }
    };
    drop(store);
    Some(create_user2_response(if status == ntstatus::SUCCESS { rid } else { 0 }, status))
}

/// MS-SAMR 2.2.1.12 `AccountType` -> the objectClasses and
/// `userAccountControl` AD gives the new object (MS-ADTS 2.2.16).
fn account_shape(account_type: u32) -> Option<(&'static [&'static str], u32)> {
    const USER: &[&str] = &["top", "person", "organizationalPerson", "user"];
    const COMPUTER: &[&str] = &["top", "person", "organizationalPerson", "user", "computer"];
    match account_type {
        0x0000_0010 => Some((USER, 0x0200)),       // USER_NORMAL_ACCOUNT -> UF_NORMAL_ACCOUNT
        0x0000_0040 => Some((USER, 0x0800)),       // USER_INTERDOMAIN_TRUST_ACCOUNT
        0x0000_0080 => Some((COMPUTER, 0x1000)),   // USER_WORKSTATION_TRUST_ACCOUNT
        0x0000_0100 => Some((COMPUTER, 0x2000)),   // USER_SERVER_TRUST_ACCOUNT
        _ => None,
    }
}

fn create_user2_response(rid: u32, status: u32) -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.handle(&if status == ntstatus::SUCCESS { user_handle(rid) } else { [0u8; 20] });
    w.u32(if status == ntstatus::SUCCESS { 0x0200_0000 } else { 0 }); // GrantedAccess: a permissive default (USER_ALL_ACCESS-shaped)
    w.u32(rid);
    w.u32(status);
    w.buf
}

/// `UserPrimaryGroupInformation` (level 9) -- the simplest real
/// `SAMPR_USER_INFO_BUFFER` union arm (`USER_PRIMARY_GROUP_INFORMATION`
/// is just one `ULONG`), returned regardless of the level the caller
/// actually asked for. Deliberately not `UserAllInformation` (level 21,
/// what a real join client typically requests): that arm is a large
/// struct with a dozen-plus fields, and claiming that level while
/// returning a truncated body isn't just incomplete, it desyncs the
/// wire (found live -- a real impacket client's own generic union
/// decode reads exactly as many bytes as the discriminant promises).
/// Honestly declaring level 9 here, matching what's actually sent, is
/// correct NDR even though it doesn't answer what UserAllInformation
/// would have. This server's synthetic user handles already carry the
/// RID (see module docs), so nothing needs looking up in the DIT to
/// answer this.
async fn query_information_user2(_state: &SamrState, _domain_sid: &Sid, stub: &[u8]) -> Option<Vec<u8>> {
    let mut r = NdrReader::new(stub);
    let handle = r.handle().ok()?;
    let _info_level = r.u16().ok()?;
    rid_from_user_handle(&handle)?; // validates it's a handle this server issued

    const DEFAULT_PRIMARY_GROUP_RID: u32 = 513; // Domain Users -- see iron-kdc::pac
    let mut w = NdrWriter::new();
    w.referent_id(); // Buffer: PSAMPR_USER_INFO_BUFFER
    w.u16(9); // UserInformationClass = UserPrimaryGroupInformation
    w.u16(0); // pad
    w.u32(DEFAULT_PRIMARY_GROUP_RID);
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
    fn account_type_decides_the_object() {
        assert_eq!(account_shape(0x80).unwrap().0.last(), Some(&"computer"));
        assert_eq!(account_shape(0x80).unwrap().1, 0x1000);
        assert_eq!(account_shape(0x10).unwrap().0.last(), Some(&"user"));
        assert_eq!(account_shape(0x10).unwrap().1, 0x200);
        assert!(account_shape(0x1).is_none()); // USER_ACCOUNT_DISABLED is a flag, not a type
    }

    /// A level-31 `SamrSetInformationUser2` stub as Samba's NDR lays it
    /// out: handle, level, the union's discriminant, the 8-aligned
    /// `SAMPR_USER_INTERNAL7_INFORMATION`, then the deferred Cipher.
    fn level31_stub(cipher: &[u8], expired: u8) -> Vec<u8> {
        let mut w = NdrWriter::new();
        w.handle(&user_handle(1104));
        w.u16(31);
        w.u16(31);
        w.align(8);
        w.bytes(&[0xaa; 64]);
        w.bytes(&[0xbb; 16]);
        w.u32(cipher.len() as u32);
        w.referent_id();
        w.align(8);
        w.u64(0);
        w.u8(expired);
        w.align(4);
        w.u32(cipher.len() as u32);
        w.bytes(cipher);
        w.buf
    }

    #[test]
    fn parses_a_level31_set_information() {
        let (handle, level, pw) = parse_set_information(&level31_stub(&[1, 2, 3, 4], 1)).unwrap();
        assert_eq!(rid_from_user_handle(&handle), Some(1104));
        assert_eq!(level, 31);
        let (enc, expired) = pw.unwrap();
        assert_eq!(enc.auth_data, [0xaa; 64]);
        assert_eq!(enc.salt, [0xbb; 16]);
        assert_eq!(enc.cipher, vec![1, 2, 3, 4]);
        assert!(expired);
        // A conformant count that disagrees with cipher_len does not decode.
        let mut bad = level31_stub(&[1, 2, 3, 4], 0);
        let n = bad.len();
        bad[n - 8] = 9;
        assert!(parse_set_information(&bad).is_none());
    }

    #[test]
    fn other_levels_are_named_without_reading_a_buffer() {
        let mut w = NdrWriter::new();
        w.handle(&user_handle(7));
        w.u16(25);
        w.u16(25);
        let (_, level, pw) = parse_set_information(&w.buf).unwrap();
        assert_eq!(level, 25);
        assert!(pw.is_none());
    }

    #[test]
    fn connect5_response_carries_server_handle() {
        let resp = connect5();
        // OutVersion(4) + tag(4) + Revision(4) + SupportedFeatures(4) + handle(20) + status(4)
        assert_eq!(&resp[16..36], &SERVER_HANDLE);
        assert_eq!(u32::from_le_bytes(resp[36..40].try_into().unwrap()), 0);
    }
}
