//! `nTSecurityDescriptor` (#17): a minimal, well-formed MS-DTYP
//! `SECURITY_DESCRIPTOR` in self-relative form (§2.4.6), hand-rolled the
//! same way `sid.rs` is.
//!
//! Scope is deliberately narrow: this builds one **static template** --
//! owner = Domain Admins, DACL granting Domain Admins `GENERIC_ALL` and
//! Authenticated Users `GENERIC_READ` -- stamped onto every provisioned
//! `user`/`computer`/`group` object. The point of #17 is that the
//! attribute exists, is binary-correct, and round-trips through real
//! MS-DTYP parsing; an actual ACE-editing engine (`dsacls`-equivalent
//! semantics, per-object custom ACLs, enforcement of any of this against
//! directory operations) is a separate, later, much larger feature --
//! this template is never evaluated to gate anything yet.
//!
//! All multi-byte fields in the self-relative form are little-endian
//! (Windows' native byte order) -- unlike a [`crate::sid::Sid`]'s
//! *authority*, which is the one big-endian field in this whole area.

use crate::sid::Sid;

/// `SE_DACL_PRESENT` -- a DACL is present (vs. "no DACL" -- an
/// unrestricted-access absence rather than an empty deny-all one, per
/// MS-DTYP §2.4.6; every descriptor this module builds always sets it).
const SE_DACL_PRESENT: u16 = 0x0004;
/// `SE_SELF_RELATIVE` -- required for the on-the-wire/on-disk form
/// (offsets, not pointers); the only form irondirectory ever produces.
const SE_SELF_RELATIVE: u16 = 0x8000;

/// `ACCESS_ALLOWED_ACE_TYPE` (MS-DTYP §2.4.4.1).
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
/// `GENERIC_ALL` (MS-DTYP §2.4.3).
pub const GENERIC_ALL: u32 = 0x1000_0000;
/// `GENERIC_READ` (MS-DTYP §2.4.3).
pub const GENERIC_READ: u32 = 0x8000_0000;

/// `Authenticated Users` -- a universal well-known SID (`S-1-5-11`),
/// identical in every domain, unlike Domain Admins (`<domain-sid>-512`).
pub fn authenticated_users() -> Sid {
    Sid::new(Sid::NT_AUTHORITY, [11])
}

fn build_ace(mask: u32, trustee: &Sid) -> Vec<u8> {
    let sid_bytes = trustee.encode();
    let size = 8 + sid_bytes.len(); // 4-byte ACE header + 4-byte mask + SID
    let mut out = Vec::with_capacity(size);
    out.push(ACCESS_ALLOWED_ACE_TYPE);
    out.push(0); // AceFlags: no inheritance
    out.extend_from_slice(&(size as u16).to_le_bytes());
    out.extend_from_slice(&mask.to_le_bytes());
    out.extend(sid_bytes);
    out
}

fn build_dacl(aces: &[(u32, Sid)]) -> Vec<u8> {
    let bodies: Vec<Vec<u8>> = aces.iter().map(|(mask, sid)| build_ace(*mask, sid)).collect();
    let body_len: usize = bodies.iter().map(Vec::len).sum();
    let acl_size = 8 + body_len; // ACL header is 8 bytes
    let mut out = Vec::with_capacity(acl_size);
    out.push(2); // AclRevision (ACL_REVISION, supports ACCESS_ALLOWED_ACE)
    out.push(0); // Sbz1
    out.extend_from_slice(&(acl_size as u16).to_le_bytes());
    out.extend_from_slice(&(aces.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // Sbz2
    for body in bodies {
        out.extend(body);
    }
    out
}

/// Byte length of the fixed `SECURITY_DESCRIPTOR` header (revision +
/// Sbz1 + control + 4 × u32 offsets).
const HEADER_LEN: u32 = 1 + 1 + 2 + 4 * 4;

/// Builds the default MVP `nTSecurityDescriptor` for a newly-provisioned
/// object: owner = Domain Admins (`<domain_sid>-512`), group = Domain
/// Admins, DACL grants Domain Admins `GENERIC_ALL` and Authenticated
/// Users `GENERIC_READ`. No SACL.
pub fn default_descriptor(domain_sid: &Sid) -> Vec<u8> {
    let domain_admins = domain_sid.with_sub_authority(512);
    let dacl = build_dacl(&[(GENERIC_ALL, domain_admins.clone()), (GENERIC_READ, authenticated_users())]);
    let owner = domain_admins.encode();
    let group = domain_admins.encode();

    let offset_dacl = HEADER_LEN;
    let offset_owner = offset_dacl + dacl.len() as u32;
    let offset_group = offset_owner + owner.len() as u32;
    let offset_sacl = 0u32; // absent

    let control = SE_DACL_PRESENT | SE_SELF_RELATIVE;
    let mut out = Vec::with_capacity(HEADER_LEN as usize + dacl.len() + owner.len() + group.len());
    out.push(1); // Revision
    out.push(0); // Sbz1
    out.extend_from_slice(&control.to_le_bytes());
    out.extend_from_slice(&offset_owner.to_le_bytes());
    out.extend_from_slice(&offset_group.to_le_bytes());
    out.extend_from_slice(&offset_sacl.to_le_bytes());
    out.extend_from_slice(&offset_dacl.to_le_bytes());
    out.extend(dacl);
    out.extend(owner);
    out.extend(group);
    out
}

/// A decoded ACE, for tests/verification -- not used by
/// `default_descriptor` itself.
#[derive(Debug, PartialEq, Eq)]
pub struct DecodedAce {
    /// The access mask granted (e.g. [`GENERIC_ALL`]/[`GENERIC_READ`]).
    pub mask: u32,
    /// The SID this ACE grants `mask` to.
    pub trustee: Sid,
}

/// A decoded `SECURITY_DESCRIPTOR`, enough of one to verify
/// `default_descriptor`'s output is genuinely well-formed (own
/// round-trip check, independent of whatever external tool a live
/// verification pass also uses).
#[derive(Debug, PartialEq, Eq)]
pub struct DecodedDescriptor {
    /// The owning security principal's SID.
    pub owner: Sid,
    /// The owning primary group's SID.
    pub group: Sid,
    /// The discretionary access control list -- empty if absent.
    pub dacl: Vec<DecodedAce>,
}

/// The inverse of [`default_descriptor`] (general enough for any
/// single-DACL, no-SACL, self-relative descriptor this module might
/// produce in the future, not just today's exact static template).
pub fn decode(bytes: &[u8]) -> Option<DecodedDescriptor> {
    if bytes.len() < HEADER_LEN as usize {
        return None;
    }
    let control = u16::from_le_bytes(bytes[2..4].try_into().ok()?);
    if control & SE_SELF_RELATIVE == 0 {
        return None; // only the self-relative form is supported
    }
    let offset_owner = u32::from_le_bytes(bytes[4..8].try_into().ok()?) as usize;
    let offset_group = u32::from_le_bytes(bytes[8..12].try_into().ok()?) as usize;
    let offset_dacl = u32::from_le_bytes(bytes[16..20].try_into().ok()?) as usize;

    let owner = decode_sid_at(bytes, offset_owner)?;
    let group = decode_sid_at(bytes, offset_group)?;

    let dacl = if control & SE_DACL_PRESENT != 0 && offset_dacl != 0 {
        decode_dacl_at(bytes, offset_dacl)?
    } else {
        Vec::new()
    };

    Some(DecodedDescriptor { owner, group, dacl })
}

fn decode_sid_at(bytes: &[u8], offset: usize) -> Option<Sid> {
    let header = bytes.get(offset..offset + 2)?;
    let count = header[1] as usize;
    let len = 8 + 4 * count;
    Sid::decode(bytes.get(offset..offset + len)?)
}

fn decode_dacl_at(bytes: &[u8], offset: usize) -> Option<Vec<DecodedAce>> {
    let header = bytes.get(offset..offset + 8)?;
    let ace_count = u16::from_le_bytes(header[4..6].try_into().ok()?) as usize;
    let mut pos = offset + 8;
    let mut aces = Vec::with_capacity(ace_count);
    for _ in 0..ace_count {
        let ace_header = bytes.get(pos..pos + 4)?;
        let ace_size = u16::from_le_bytes(ace_header[2..4].try_into().ok()?) as usize;
        let mask = u32::from_le_bytes(bytes.get(pos + 4..pos + 8)?.try_into().ok()?);
        let trustee = decode_sid_at(bytes, pos + 8)?;
        aces.push(DecodedAce { mask, trustee });
        pos += ace_size;
    }
    Some(aces)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_domain_sid() -> Sid {
        Sid::new(Sid::NT_AUTHORITY, [21, 1004336348, 1177238915, 682003330])
    }

    #[test]
    fn default_descriptor_decodes_back_correctly() {
        let domain_sid = test_domain_sid();
        let blob = default_descriptor(&domain_sid);
        let decoded = decode(&blob).unwrap();

        let domain_admins = domain_sid.with_sub_authority(512);
        assert_eq!(decoded.owner, domain_admins);
        assert_eq!(decoded.group, domain_admins);
        assert_eq!(decoded.dacl.len(), 2);
        assert_eq!(decoded.dacl[0], DecodedAce { mask: GENERIC_ALL, trustee: domain_admins });
        assert_eq!(decoded.dacl[1], DecodedAce { mask: GENERIC_READ, trustee: authenticated_users() });
    }

    #[test]
    fn control_flags_are_set_correctly() {
        let blob = default_descriptor(&test_domain_sid());
        let control = u16::from_le_bytes(blob[2..4].try_into().unwrap());
        assert_eq!(control & SE_SELF_RELATIVE, SE_SELF_RELATIVE);
        assert_eq!(control & SE_DACL_PRESENT, SE_DACL_PRESENT);
    }

    #[test]
    fn revision_is_one() {
        let blob = default_descriptor(&test_domain_sid());
        assert_eq!(blob[0], 1);
    }

    #[test]
    fn decode_rejects_non_self_relative_and_truncated_input() {
        assert!(decode(&[0u8; 4]).is_none(), "too short for even the header");
        let mut blob = default_descriptor(&test_domain_sid());
        blob[2] = 0;
        blob[3] = 0; // clear control flags, including SE_SELF_RELATIVE
        assert!(decode(&blob).is_none());
    }
}
