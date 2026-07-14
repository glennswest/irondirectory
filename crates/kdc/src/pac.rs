//! Kerberos PAC (Privilege Attribute Certificate) generation (MS-PAC, #18):
//! Windows-side authorization depends on a service ticket's
//! `AD-WIN2K-PAC` authorization-data element carrying the client's
//! `objectSid` and group SIDs -- without it, a real Windows client
//! accepts the ticket but has no group memberships to authorize against.
//!
//! This hand-rolls the MS-PAC wire format rather than pulling in a
//! generic NDR/DCE-RPC crate (none exists in this workspace, #19 is
//! where that infrastructure would actually earn its keep) -- the same
//! "one shape, by hand" approach as `iron-partition::sid`/
//! `security_descriptor` (#17). The one NDR-marshaled buffer this needs
//! (`KERB_VALIDATION_INFO`, MS-PAC §2.5) is built directly against the
//! exact byte layout documented in MS-PAC and cross-checked against
//! [impacket](https://github.com/fortra/impacket)'s `krb5.pac`/
//! `dcerpc.v5.nrpc` modules (a real, Windows-interoperable independent
//! implementation) rather than from memory alone -- NDR's "conformant
//! structure" pointer/array deferral rules are exactly the kind of
//! finicky, easy-to-get-subtly-wrong wire detail that's worth checking
//! against a working reference before shipping.
//!
//! Scope (D10, happy path): one `KERB_VALIDATION_INFO` (logon info) +
//! one `PAC_CLIENT_INFO` + the two required signature buffers. No
//! `PAC_UPN_DNS_INFO`, no compound-identity/device claims, no resource
//! groups, no extra/foreign SIDs -- a real Windows client still accepts
//! a PAC missing these, it just has less to authorize against. No PAC
//! *verification* either (this is PAC *generation* for tickets this KDC
//! itself issues); a resource server independently checking a PAC's
//! signature is out of scope here.
//!
//! No real Windows machine exists in this project's test infra to
//! validate PAC *acceptance* against (#20 tracks that gap) -- this is
//! verified by: (a) precise adherence to the MS-PAC/MS-DTYP/MS-NRPC
//! wire formats as documented and cross-checked against impacket's
//! independent implementation, (b) internal round-trip self-consistency
//! tests, and (c) an independent Python/impacket structural parse of a
//! real generated PAC (see the #18 live-verification notes in
//! `CLAUDE.md`) -- not "a real Windows DC accepted this ticket."

use iron_crypto::kerberos::{self, Enctype};
use iron_crypto::FipsContext;
use iron_partition::{Dn, PartitionRegistry, Sid};
use iron_store::binary_attrs::{decode_binary_attr, OBJECT_SID_ATTR};
use iron_store::model::Entry;
use iron_store::store::Store;

/// Windows FILETIME epoch (1601-01-01) is this many seconds before the
/// Unix epoch (1970-01-01).
const FILETIME_UNIX_EPOCH_OFFSET_SECS: i64 = 11_644_473_600;
/// MS-DTYP `LARGE_INTEGER`'s "never" placeholder (`0x7FFFFFFFFFFFFFFF`),
/// used for `LogoffTime`/`KickOffTime`/`PasswordMustChange` etc. when no
/// expiration policy is modeled (this project doesn't track one yet).
const FILETIME_NEVER: u64 = 0x7FFF_FFFF_FFFF_FFFF;

const PAC_LOGON_INFO: u32 = 1;
const PAC_SERVER_CHECKSUM: u32 = 6;
const PAC_PRIVSVR_CHECKSUM: u32 = 7;
const PAC_CLIENT_INFO_TYPE: u32 = 10;

/// RFC 3961/RFC 4757's assigned key-usage number for PAC signatures
/// (`KERB_NON_KERB_CKSUM_SALT`) -- distinct from the key-usage numbers
/// `iron_crypto::kerberos::{encrypt,decrypt}` use for ticket/reply
/// bodies, but processed by the same `checksum` primitive.
const PAC_SIGNATURE_KEY_USAGE: u32 = 17;

/// `SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED`
/// -- the standard "ordinary, active group membership" attributes real
/// Windows sets on every `GROUP_MEMBERSHIP` entry it issues.
const GROUP_ATTRS_DEFAULT: u32 = 0x0000_0007;

/// Domain Users' well-known RID -- this project doesn't model a
/// per-user `primaryGroupID` attribute yet, so every user's primary
/// group is this fixed default (matches a real, unmodified AD user
/// account's default before any admin changes it).
pub const DEFAULT_PRIMARY_GROUP_RID: u32 = 513;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("crypto error: {0}")]
    Crypto(#[from] iron_crypto::Error),
}

/// Everything [`generate`] needs about the client and its domain to
/// build a PAC -- gathered by the caller (`as_exchange`/`tgs_exchange`)
/// from the client's `Entry` (`objectSid`, #17) plus a `member`
/// reverse-index lookup for group SIDs, since neither lives in the
/// Kerberos-specific attributes `principal.rs` already reads.
pub struct PacInput<'a> {
    /// The client's own `objectSid` (#17).
    pub client_sid: &'a Sid,
    /// The client's domain SID (`client_sid` minus its own RID) --
    /// needed separately for `LogonDomainId`.
    pub domain_sid: &'a Sid,
    /// RIDs of every `groupOfNames` this client is a `member` of, other
    /// than its primary group.
    pub group_rids: &'a [u32],
    /// Account name (`cn`) -- used for both `EffectiveName` and
    /// `FullName` (no separate `displayName` modeled).
    pub account_name: &'a str,
    /// NetBIOS-shaped domain name (e.g. the realm's first label,
    /// uppercased) -- used for both `LogonDomainName` and (for lack of
    /// a separate per-DC NetBIOS name in this project) `LogonServer`.
    pub domain_netbios_name: &'a str,
    /// Ticket's `auth_time`, as Unix seconds -- becomes `LogonTime` and
    /// `PAC_CLIENT_INFO.ClientId`.
    pub auth_time_unix_secs: i64,
}

fn filetime_from_unix_secs(secs: i64) -> u64 {
    ((secs + FILETIME_UNIX_EPOCH_OFFSET_SECS) as u64).saturating_mul(10_000_000)
}

/// Minimal little-endian NDR byte-buffer builder -- just the primitives
/// `KERB_VALIDATION_INFO` needs, not a general NDR engine (see module
/// docs). Every write here is either self-evidently 4-byte-aligned by
/// construction (this structure's fields happen to compose into
/// multiples of 4 throughout, verified against impacket's field list)
/// or explicitly padded via `pad_to_4` at the one place it's needed
/// (variable-length string buffers).
struct NdrBuf {
    buf: Vec<u8>,
    next_referent_id: u32,
}

impl NdrBuf {
    fn new() -> Self {
        NdrBuf { buf: Vec::new(), next_referent_id: 0x0002_0000 }
    }

    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    fn filetime(&mut self, ticks: u64) {
        // FILETIME (MS-DTYP 2.3.3): dwLowDateTime then dwHighDateTime,
        // each a little-endian ULONG.
        self.u32(ticks as u32);
        self.u32((ticks >> 32) as u32);
    }

    fn pad_to_4(&mut self) {
        while self.buf.len() % 4 != 0 {
            self.buf.push(0);
        }
    }

    /// A non-null pointer's referent id (fixed-part placeholder; the
    /// actual value is arbitrary to a conformant decoder as long as
    /// it's non-zero -- deferred data is matched by encounter order,
    /// not by this value).
    fn referent_id(&mut self) -> u32 {
        let id = self.next_referent_id;
        self.next_referent_id += 4;
        self.u32(id);
        id
    }

    fn null_ptr(&mut self) {
        self.u32(0);
    }
}

/// Encodes an `RPC_UNICODE_STRING`'s fixed part (`Length`,
/// `MaximumLength`, a pointer to the `Buffer`) -- `None`/empty becomes a
/// null pointer, matching how empty optional strings (`LogonScript`,
/// `HomeDirectory`, ...) are conventionally represented rather than a
/// pointer to a zero-length buffer.
fn write_unicode_string_header(out: &mut NdrBuf, s: Option<&str>) -> Option<String> {
    match s {
        Some(s) if !s.is_empty() => {
            let len = (s.encode_utf16().count() * 2) as u16;
            out.u16(len);
            out.u16(len);
            out.referent_id();
            Some(s.to_string())
        }
        _ => {
            out.u16(0);
            out.u16(0);
            out.null_ptr();
            None
        }
    }
}

/// Encodes an `RPC_UNICODE_STRING`'s deferred data (the conformant-and-
/// varying `WCHAR` buffer: `MaximumCount`, `Offset`, `ActualCount`, then
/// the raw UTF-16LE bytes themselves, not NUL-terminated -- matching
/// `Length`/`MaximumLength` above exactly).
fn write_unicode_string_deferred(out: &mut NdrBuf, s: &str) {
    let units: Vec<u16> = s.encode_utf16().collect();
    out.u32(units.len() as u32); // MaximumCount
    out.u32(0); // Offset
    out.u32(units.len() as u32); // ActualCount
    for u in units {
        out.u16(u);
    }
    out.pad_to_4();
}

/// A SID in its NDR (`RPC_SID`) representation: MS-RPCE's "conformant
/// structure" rule hoists the trailing conformant array's `MaximumCount`
/// to the very front of the structure, ahead of `Revision` -- otherwise
/// identical to [`Sid::encode`]'s flat MS-DTYP bytes.
fn write_sid_deferred(out: &mut NdrBuf, sid: &Sid) {
    out.u32(sid.sub_authorities().len() as u32);
    out.bytes(&sid.encode());
}

/// Builds the NDR-encoded `KERB_VALIDATION_INFO` (MS-PAC §2.5) fixed
/// part plus its deferred pointer data, in encounter order.
fn kerb_validation_info(input: &PacInput) -> Vec<u8> {
    let mut out = NdrBuf::new();

    let logon_time = filetime_from_unix_secs(input.auth_time_unix_secs);
    out.filetime(logon_time); // LogonTime
    out.filetime(FILETIME_NEVER); // LogoffTime
    out.filetime(FILETIME_NEVER); // KickOffTime
    out.filetime(logon_time); // PasswordLastSet (no expiry policy modeled)
    out.filetime(logon_time); // PasswordCanChange
    out.filetime(FILETIME_NEVER); // PasswordMustChange

    let effective_name = write_unicode_string_header(&mut out, Some(input.account_name));
    let full_name = write_unicode_string_header(&mut out, Some(input.account_name));
    write_unicode_string_header(&mut out, None); // LogonScript
    write_unicode_string_header(&mut out, None); // ProfilePath
    write_unicode_string_header(&mut out, None); // HomeDirectory
    write_unicode_string_header(&mut out, None); // HomeDirectoryDrive

    out.u16(0); // LogonCount
    out.u16(0); // BadPasswordCount
    out.u32(*input.client_sid.sub_authorities().last().unwrap_or(&0)); // UserId (RID)
    out.u32(DEFAULT_PRIMARY_GROUP_RID); // PrimaryGroupId
    out.u32(input.group_rids.len() as u32); // GroupCount
    out.referent_id(); // GroupIds -- always non-null, even if empty (it's the
    // core membership list, not an "extra" optional field)

    out.u32(0); // UserFlags
    out.bytes(&[0u8; 16]); // UserSessionKey (MUST be ignored per MS-PAC)

    let logon_server = write_unicode_string_header(&mut out, Some(input.domain_netbios_name));
    let logon_domain_name = write_unicode_string_header(&mut out, Some(input.domain_netbios_name));
    out.referent_id(); // LogonDomainId

    out.bytes(&[0u8; 8]); // LMKey / Reserved1
    out.u32(0x0000_0200); // UserAccountControl (UF_NORMAL_ACCOUNT) -- fixed
    // default; this project doesn't model per-user UAC bits yet.
    out.u32(0); // SubAuthStatus
    out.filetime(0); // LastSuccessfulILogon (not tracked)
    out.filetime(0); // LastFailedILogon (not tracked)
    out.u32(0); // FailedILogonCount
    out.u32(0); // Reserved3

    out.u32(0); // SidCount
    out.null_ptr(); // ExtraSids -- none modeled
    out.null_ptr(); // ResourceGroupDomainSid -- none modeled
    out.u32(0); // ResourceGroupCount
    out.null_ptr(); // ResourceGroupIds -- none modeled

    // Deferred data, strictly in the order pointers were encountered above.
    if let Some(s) = effective_name {
        write_unicode_string_deferred(&mut out, &s);
    }
    if let Some(s) = full_name {
        write_unicode_string_deferred(&mut out, &s);
    }
    // GroupIds: a conformant array (MaximumCount header, no Offset/ActualCount
    // -- unlike the conformant+varying WCHAR buffers above).
    out.u32(input.group_rids.len() as u32);
    for rid in input.group_rids {
        out.u32(*rid);
        out.u32(GROUP_ATTRS_DEFAULT);
    }
    if let Some(s) = logon_server {
        write_unicode_string_deferred(&mut out, &s);
    }
    if let Some(s) = logon_domain_name {
        write_unicode_string_deferred(&mut out, &s);
    }
    write_sid_deferred(&mut out, input.domain_sid);

    out.buf
}

/// Everything [`generate`] needs about a client, gathered from its
/// `Entry` plus a `member` reverse-index lookup -- owned (not
/// `PacInput`'s borrowed form) so it can be assembled across `.await`
/// points before `generate` borrows from it.
pub struct PacContext {
    pub client_sid: Sid,
    pub domain_sid: Sid,
    pub group_rids: Vec<u32>,
    pub account_name: String,
    pub domain_netbios_name: String,
}

impl PacContext {
    pub fn as_input(&self, auth_time_unix_secs: i64) -> PacInput<'_> {
        PacInput {
            client_sid: &self.client_sid,
            domain_sid: &self.domain_sid,
            group_rids: &self.group_rids,
            account_name: &self.account_name,
            domain_netbios_name: &self.domain_netbios_name,
            auth_time_unix_secs,
        }
    }
}

/// Gathers a [`PacContext`] for `client_entry` (at `client_dn`), or
/// `None` -- a deliberate no-op, not an error, matching
/// `security::stamp_security_principal`'s shape -- if any prerequisite
/// is missing: no forest topology configured, the partition has no
/// provisioned domain SID yet (#17), or the principal itself has no
/// `objectSid` (e.g. `krbtgt` and ordinary service principals aren't
/// security principals and never get one). Callers skip embedding a PAC
/// entirely in that case, exactly like a real KDC that has nothing to
/// vouch for.
pub async fn gather_context(store: &mut Store, base_dn: &Dn, topology: Option<&PartitionRegistry>, realm: &str, client_dn: &Dn, client_entry: &Entry) -> Option<PacContext> {
    let domain_sid_str = topology?.resolve(base_dn)?.domain_sid.clone()?;
    let domain_sid = Sid::parse(&domain_sid_str)?;
    let object_sid_b64 = client_entry.get(OBJECT_SID_ATTR)?.first()?;
    let client_sid = Sid::decode(&decode_binary_attr(object_sid_b64))?;
    let account_name = client_entry.get("cn")?.first()?.clone();
    let domain_netbios_name = realm.split('.').next().unwrap_or(realm).to_ascii_uppercase();
    let group_rids = group_rids(store, base_dn, client_dn).await;
    Some(PacContext { client_sid, domain_sid, group_rids, account_name, domain_netbios_name })
}

/// The RIDs of every `groupOfNames` entry whose `member` list contains
/// `client_dn`, via the `"member"` secondary index (`index_spec`, #18).
/// A group missing/malformed `objectSid` is silently skipped rather than
/// aborting the whole lookup -- one bad group entry shouldn't block a
/// client's PAC entirely.
async fn group_rids(store: &mut Store, base_dn: &Dn, client_dn: &Dn) -> Vec<u32> {
    let Ok(group_dns) = store.lookup_by_index(base_dn, "member", &client_dn.to_string()).await else {
        return Vec::new();
    };
    let mut rids = Vec::new();
    for dn in group_dns {
        let Ok(Some(entry)) = store.get_entry(&dn).await else { continue };
        let Some(sid_b64) = entry.get(OBJECT_SID_ATTR).and_then(|v| v.first()) else { continue };
        let Some(sid) = Sid::decode(&decode_binary_attr(sid_b64)) else { continue };
        if let Some(rid) = sid.sub_authorities().last() {
            rids.push(*rid);
        }
    }
    rids
}

/// Wraps NDR-marshaled bytes in the standard MS-RPCE "top-level
/// serialization" envelope (`TypeSerialization1`: an 8-byte Common Type
/// Header + 8-byte Private Header) that PAC_LOGON_INFO's buffer content
/// requires -- this is what makes the buffer parseable as "an NDR
/// pointer to a KERB_VALIDATION_INFO", not just the raw structure bytes.
fn wrap_type_serialization1(inner_bytes: Vec<u8>) -> Vec<u8> {
    let referent_and_struct = {
        let mut b = NdrBuf::new();
        b.referent_id();
        b.bytes(&inner_bytes);
        b.buf
    };
    let mut out = Vec::with_capacity(16 + referent_and_struct.len());
    // Common Type Header (MS-RPCE 2.2.6.1): Version=1, Endianness=0x10
    // (little-endian), CommonHeaderLength=8, Filler=0xCCCCCCCC.
    out.push(1);
    out.push(0x10);
    out.extend_from_slice(&8u16.to_le_bytes());
    out.extend_from_slice(&0xCCCC_CCCCu32.to_le_bytes());
    // Private Header (MS-RPCE 2.2.6.2): ObjectBufferLength, Filler.
    out.extend_from_slice(&(referent_and_struct.len() as u32).to_le_bytes());
    out.extend_from_slice(&0xCCCC_CCCCu32.to_le_bytes());
    out.extend_from_slice(&referent_and_struct);
    out
}

/// `PAC_CLIENT_INFO` (MS-PAC §2.7) -- a flat structure, not NDR-marshaled
/// (unlike `KERB_VALIDATION_INFO`).
fn pac_client_info(auth_time_unix_secs: i64, name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&filetime_from_unix_secs(auth_time_unix_secs).to_le_bytes());
    let units: Vec<u16> = name.encode_utf16().collect();
    out.extend_from_slice(&((units.len() * 2) as u16).to_le_bytes());
    for u in units {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

/// `PAC_SIGNATURE_DATA` (MS-PAC §2.8) -- also flat: a signature-type tag
/// plus the raw checksum bytes.
fn pac_signature_data(signature_type: i32, signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + signature.len());
    out.extend_from_slice(&signature_type.to_le_bytes());
    out.extend_from_slice(signature);
    out
}

fn block_len(n: usize) -> usize {
    n.div_ceil(8) * 8
}

/// Assembles a `PACTYPE` (MS-PAC §2.3): an 8-byte header, one 16-byte
/// `PAC_INFO_BUFFER` per buffer (`ulType`, `cbBufferSize`, `Offset`),
/// then each buffer's data, individually padded so it ends on an
/// 8-byte boundary (`Offset` is absolute from the start of the whole
/// blob) -- verified byte-for-byte against impacket's `build_pac_type`.
fn build_pac_type(buffers: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let header_len = 8 + 16 * buffers.len();
    let mut offset = header_len;
    let mut info_buffers = Vec::with_capacity(header_len - 8);
    let mut data_blobs = Vec::new();
    for (ul_type, data) in buffers {
        info_buffers.extend_from_slice(&ul_type.to_le_bytes());
        info_buffers.extend_from_slice(&(data.len() as u32).to_le_bytes());
        info_buffers.extend_from_slice(&(offset as u64).to_le_bytes());

        data_blobs.extend_from_slice(data);
        let pad = block_len(data.len()) - data.len();
        data_blobs.extend(std::iter::repeat_n(0u8, pad));
        offset = block_len(offset + data.len());
    }

    let mut out = Vec::with_capacity(header_len + data_blobs.len());
    out.extend_from_slice(&(buffers.len() as u32).to_le_bytes()); // cBuffers
    out.extend_from_slice(&0u32.to_le_bytes()); // Version
    out.extend_from_slice(&info_buffers);
    out.extend_from_slice(&data_blobs);
    out
}

/// The MS-PAC `SignatureType` for a checksum computed with an
/// `enctype`-derived key. AES-SHA1 enctypes (RFC 3962, etypes 17/18)
/// use distinct checksum-type numbers (15/16); the newer AES-SHA2
/// enctypes (RFC 8009, etypes 19/20) reuse their own etype number as
/// the checksum type -- both confirmed against impacket's
/// `krb5.constants.ChecksumTypes` and RFC 8009 §2.
fn pac_checksum_type(enctype: Enctype) -> i32 {
    match enctype {
        Enctype::Aes128CtsHmacSha1_96 => 15,
        Enctype::Aes256CtsHmacSha1_96 => 16,
        Enctype::Aes128CtsHmacSha256_128 => 19,
        Enctype::Aes256CtsHmacSha384_192 => 20,
    }
}

/// Generates a signed PAC (the raw bytes to embed as an `AD-WIN2K-PAC`
/// authorization-data element, MS-KILE) for `input`, signed with
/// `server_key` (the ticket's own encrypting key -- the target
/// service's key for a service ticket, or the krbtgt's own key for a
/// TGT, since krbtgt IS the "server" there) and `kdc_key` (the krbtgt
/// key of the realm vouching for this PAC -- for a TGS-REP this is the
/// key that decrypted the presented TGT, i.e. `tgs_exchange`'s
/// `issuer_key`).
///
/// Signing algorithm (MS-PAC §2.8.2, verified against impacket's
/// `sign_pac`): build the whole PAC with both signature buffers'
/// `Signature` bytes zeroed; the **server** checksum is an HMAC over
/// that *entire* zeroed buffer using `server_key`; the **KDC/privsvr**
/// checksum is an HMAC using `kdc_key`, but over the server checksum's
/// own signature bytes only, not the whole PAC again -- a signature
/// chained through the server signature, not two independent checksums
/// of the same buffer (an easy detail to get wrong from memory alone,
/// which is why this was checked against a working reference rather
/// than implemented from recollection).
#[allow(clippy::too_many_arguments)]
pub fn generate(
    ctx: &FipsContext,
    input: &PacInput,
    server_key: &[u8],
    server_enctype: Enctype,
    kdc_key: &[u8],
    kdc_enctype: Enctype,
) -> Result<Vec<u8>, Error> {
    let logon_info = wrap_type_serialization1(kerb_validation_info(input));
    let client_info = pac_client_info(input.auth_time_unix_secs, input.account_name);

    let server_sig_len = server_enctype.hmac_len();
    let kdc_sig_len = kdc_enctype.hmac_len();
    let server_sig_type = pac_checksum_type(server_enctype);
    let kdc_sig_type = pac_checksum_type(kdc_enctype);

    let buffers_zeroed = vec![
        (PAC_LOGON_INFO, logon_info.clone()),
        (PAC_CLIENT_INFO_TYPE, client_info.clone()),
        (PAC_SERVER_CHECKSUM, pac_signature_data(server_sig_type, &vec![0u8; server_sig_len])),
        (PAC_PRIVSVR_CHECKSUM, pac_signature_data(kdc_sig_type, &vec![0u8; kdc_sig_len])),
    ];
    let blob_to_checksum = build_pac_type(&buffers_zeroed);

    let server_signature = kerberos::checksum(ctx, server_enctype, server_key, PAC_SIGNATURE_KEY_USAGE, &blob_to_checksum)?;
    let kdc_signature = kerberos::checksum(ctx, kdc_enctype, kdc_key, PAC_SIGNATURE_KEY_USAGE, &server_signature)?;

    let buffers_signed = vec![
        (PAC_LOGON_INFO, logon_info),
        (PAC_CLIENT_INFO_TYPE, client_info),
        (PAC_SERVER_CHECKSUM, pac_signature_data(server_sig_type, &server_signature)),
        (PAC_PRIVSVR_CHECKSUM, pac_signature_data(kdc_sig_type, &kdc_signature)),
    ];
    Ok(build_pac_type(&buffers_signed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_input() -> (Sid, Sid, PacInput<'static>) {
        let domain_sid = Sid::new(Sid::NT_AUTHORITY, [21, 1004336348, 1177238915, 682003330]);
        let client_sid = domain_sid.with_sub_authority(1105);
        let input = PacInput {
            client_sid: Box::leak(Box::new(client_sid.clone())),
            domain_sid: Box::leak(Box::new(domain_sid.clone())),
            group_rids: Box::leak(Box::new([1108u32, 1109])),
            account_name: "alice",
            domain_netbios_name: "IRONLO",
            auth_time_unix_secs: 1_700_000_000,
        };
        (domain_sid, client_sid, input)
    }

    #[test]
    fn filetime_conversion_matches_known_value() {
        // 1704067200 is 2024-01-01T00:00:00Z (confirmed via `date -u -r
        // 1704067200`); FILETIME ticks independently re-derived via
        // `(unix + 11644473600) * 10_000_000` in Python, not by re-deriving
        // the same formula in the test.
        let unix = 1_704_067_200i64;
        assert_eq!(filetime_from_unix_secs(unix), 133_485_408_000_000_000);
    }

    #[test]
    fn build_pac_type_offsets_are_8_byte_aligned_and_sequential() {
        let buffers = vec![(PAC_LOGON_INFO, vec![1u8; 5]), (PAC_CLIENT_INFO_TYPE, vec![2u8; 3])];
        let bytes = build_pac_type(&buffers);

        let c_buffers = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        assert_eq!(c_buffers, 2);
        let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        assert_eq!(version, 0);

        // First PAC_INFO_BUFFER: ulType, cbBufferSize, Offset.
        let ul_type_0 = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let size_0 = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        let offset_0 = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        assert_eq!(ul_type_0, PAC_LOGON_INFO);
        assert_eq!(size_0, 5);
        assert_eq!(offset_0, 8 + 16 * 2); // right after the header + 2 info buffers

        let offset_1 = u64::from_le_bytes(bytes[24 + 8..24 + 16].try_into().unwrap());
        // First blob (5 bytes) padded to the next multiple of 8 (8), so the
        // second buffer's offset is offset_0 + 8.
        assert_eq!(offset_1, offset_0 + 8);
        assert_eq!(offset_1 % 8, 0);

        assert_eq!(&bytes[offset_0 as usize..offset_0 as usize + 5], &[1u8; 5]);
        assert_eq!(&bytes[offset_1 as usize..offset_1 as usize + 3], &[2u8; 3]);
    }

    #[test]
    fn kerb_validation_info_fixed_part_is_216_bytes_before_deferred_data() {
        let (_domain_sid, _client_sid, input) = sample_input();
        let bytes = kerb_validation_info(&input);
        // Fixed part is exactly 216 bytes (verified field-by-field against
        // impacket's KERB_VALIDATION_INFO structure list) before any
        // deferred unicode-string/group/SID data.
        assert!(bytes.len() > 216);
        // UserId (RID) sits at fixed offset 100 (after 6 FILETIMEs [48] + 6
        // RPC_UNICODE_STRING headers [48] + LogonCount/BadPasswordCount [4]).
        let user_id = u32::from_le_bytes(bytes[100..104].try_into().unwrap());
        assert_eq!(user_id, 1105);
        let primary_group_id = u32::from_le_bytes(bytes[104..108].try_into().unwrap());
        assert_eq!(primary_group_id, DEFAULT_PRIMARY_GROUP_RID);
        let group_count = u32::from_le_bytes(bytes[108..112].try_into().unwrap());
        assert_eq!(group_count, 2);
    }

    #[test]
    fn wrap_type_serialization1_header_is_correct() {
        let wrapped = wrap_type_serialization1(vec![0xAA; 20]);
        assert_eq!(wrapped[0], 1, "version");
        assert_eq!(wrapped[1], 0x10, "endianness");
        assert_eq!(u16::from_le_bytes(wrapped[2..4].try_into().unwrap()), 8, "common header length");
        assert_eq!(u32::from_le_bytes(wrapped[4..8].try_into().unwrap()), 0xCCCC_CCCC);
        let object_buffer_len = u32::from_le_bytes(wrapped[8..12].try_into().unwrap());
        // referent id (4 bytes) + the 20-byte inner struct.
        assert_eq!(object_buffer_len, 24);
        assert_eq!(u32::from_le_bytes(wrapped[12..16].try_into().unwrap()), 0xCCCC_CCCC);
    }

    #[test]
    fn pac_checksum_type_matches_rfc_assignments() {
        assert_eq!(pac_checksum_type(Enctype::Aes128CtsHmacSha1_96), 15);
        assert_eq!(pac_checksum_type(Enctype::Aes256CtsHmacSha1_96), 16);
        assert_eq!(pac_checksum_type(Enctype::Aes128CtsHmacSha256_128), 19);
        assert_eq!(pac_checksum_type(Enctype::Aes256CtsHmacSha384_192), 20);
    }

    #[test]
    fn generate_produces_a_well_formed_signed_pac() {
        let ctx = FipsContext::new().unwrap();
        let (_domain_sid, _client_sid, input) = sample_input();
        let server_key = vec![0x11u8; 32];
        let kdc_key = vec![0x22u8; 32];
        let pac = generate(&ctx, &input, &server_key, Enctype::Aes256CtsHmacSha384_192, &kdc_key, Enctype::Aes256CtsHmacSha384_192).unwrap();

        let c_buffers = u32::from_le_bytes(pac[0..4].try_into().unwrap());
        assert_eq!(c_buffers, 4);

        // Independently re-verify the server signature: HMAC(server_key,
        // whole-PAC-with-both-sigs-zeroed) must equal what's stored, proving
        // the signing pass is internally self-consistent (round-tripping
        // the exact zero-then-sign algorithm, not just "produces some bytes").
        let mut zeroed = pac.clone();
        // Locate the two PAC_INFO_BUFFER entries for the checksums and zero
        // their signature bytes back out, mirroring generate()'s own first pass.
        for i in 0..4 {
            let entry_off = 8 + i * 16;
            let ul_type = u32::from_le_bytes(pac[entry_off..entry_off + 4].try_into().unwrap());
            let size = u32::from_le_bytes(pac[entry_off + 4..entry_off + 8].try_into().unwrap()) as usize;
            let offset = u64::from_le_bytes(pac[entry_off + 8..entry_off + 16].try_into().unwrap()) as usize;
            if ul_type == PAC_SERVER_CHECKSUM || ul_type == PAC_PRIVSVR_CHECKSUM {
                // Signature bytes start 4 bytes into the buffer (past SignatureType).
                for b in &mut zeroed[offset + 4..offset + size] {
                    *b = 0;
                }
            }
        }
        let recomputed_server_sig = kerberos::checksum(&ctx, Enctype::Aes256CtsHmacSha384_192, &server_key, PAC_SIGNATURE_KEY_USAGE, &zeroed).unwrap();

        // Extract the stored server signature bytes.
        let mut stored_server_sig = None;
        for i in 0..4 {
            let entry_off = 8 + i * 16;
            let ul_type = u32::from_le_bytes(pac[entry_off..entry_off + 4].try_into().unwrap());
            let size = u32::from_le_bytes(pac[entry_off + 4..entry_off + 8].try_into().unwrap()) as usize;
            let offset = u64::from_le_bytes(pac[entry_off + 8..entry_off + 16].try_into().unwrap()) as usize;
            if ul_type == PAC_SERVER_CHECKSUM {
                stored_server_sig = Some(pac[offset + 4..offset + size].to_vec());
            }
        }
        assert_eq!(stored_server_sig.unwrap(), recomputed_server_sig);
    }
}
