//! Windows SID (MS-DTYP §2.4.2), hand-rolled -- a small, self-contained
//! binary codec, matching this project's existing style for well-known
//! fixed-layout binary formats (e.g. `iron-kdc`'s MIT keytab writer).
//! Needed by #17 (SID/RID allocation): real Windows/AD tooling
//! identifies security principals by SID, not DN.
//!
//! Wire format: 1 byte revision (always 1) + 1 byte sub-authority count
//! (N) + 6 bytes identifier authority (big-endian) + N × 4-byte
//! sub-authorities (little-endian). The mixed endianness is exactly
//! what the spec requires -- not a typo relative to `iron_kdc::keytab`'s
//! all-big-endian format, which is why it's called out explicitly here.

use std::fmt;

/// A Windows security identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sid {
    revision: u8,
    /// Only the low 48 bits are meaningful (the wire format is 6 bytes).
    authority: u64,
    sub_authorities: Vec<u32>,
}

impl Sid {
    /// `NT_AUTHORITY` -- the identifier authority every domain/user/group
    /// SID this project creates uses (the only one real AD assigns to
    /// security principals it creates itself, as opposed to well-known
    /// SIDs like `WORLD_AUTHORITY`).
    pub const NT_AUTHORITY: u64 = 5;

    /// Builds a SID (always revision 1) from an identifier authority and
    /// its sub-authority list.
    pub fn new(authority: u64, sub_authorities: impl Into<Vec<u32>>) -> Self {
        Sid { revision: 1, authority, sub_authorities: sub_authorities.into() }
    }

    /// This SID with one more sub-authority appended -- e.g. a domain
    /// SID plus an allocated RID makes a full object SID.
    pub fn with_sub_authority(&self, extra: u32) -> Self {
        let mut sub_authorities = self.sub_authorities.clone();
        sub_authorities.push(extra);
        Sid { revision: self.revision, authority: self.authority, sub_authorities }
    }

    /// This SID's sub-authority list, root-to-leaf (e.g. for a domain
    /// SID: `[21, a, b, c]`; for an object SID: `[21, a, b, c, rid]`).
    pub fn sub_authorities(&self) -> &[u32] {
        &self.sub_authorities
    }

    /// The MS-DTYP §2.4.2 binary wire format.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 4 * self.sub_authorities.len());
        out.push(self.revision);
        out.push(self.sub_authorities.len() as u8);
        // Big-endian, low 6 of the 8 bytes `to_be_bytes` produces.
        out.extend_from_slice(&self.authority.to_be_bytes()[2..8]);
        for sa in &self.sub_authorities {
            out.extend_from_slice(&sa.to_le_bytes());
        }
        out
    }

    /// The inverse of [`Sid::encode`]. `None` if `bytes` is too short or
    /// its declared sub-authority count doesn't match its actual length.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }
        let revision = bytes[0];
        let count = bytes[1] as usize;
        if bytes.len() != 8 + 4 * count {
            return None;
        }
        let mut authority_bytes = [0u8; 8];
        authority_bytes[2..8].copy_from_slice(&bytes[2..8]);
        let authority = u64::from_be_bytes(authority_bytes);
        let sub_authorities = bytes[8..].chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();
        Some(Sid { revision, authority, sub_authorities })
    }

    /// Parses the standard `S-<revision>-<authority>-<sub1>-<sub2>-...`
    /// string form.
    pub fn parse(s: &str) -> Option<Self> {
        let mut parts = s.split('-');
        if parts.next()? != "S" {
            return None;
        }
        let revision: u8 = parts.next()?.parse().ok()?;
        let authority: u64 = parts.next()?.parse().ok()?;
        let sub_authorities: Vec<u32> = parts.map(|p| p.parse().ok()).collect::<Option<_>>()?;
        Some(Sid { revision, authority, sub_authorities })
    }
}

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "S-{}-{}", self.revision, self.authority)?;
        for sa in &self.sub_authorities {
            write!(f, "-{sa}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let sid = Sid::new(Sid::NT_AUTHORITY, [21, 1004336348, 1177238915, 682003330, 512]);
        let encoded = sid.encode();
        assert_eq!(Sid::decode(&encoded).unwrap(), sid);
    }

    #[test]
    fn display_matches_real_ad_sid_string() {
        // A real, well-known-shaped AD domain-relative SID.
        let sid = Sid::new(Sid::NT_AUTHORITY, [21, 1004336348, 1177238915, 682003330, 512]);
        assert_eq!(sid.to_string(), "S-1-5-21-1004336348-1177238915-682003330-512");
    }

    #[test]
    fn parse_then_display_roundtrip() {
        let s = "S-1-5-21-1004336348-1177238915-682003330-1105";
        let sid = Sid::parse(s).unwrap();
        assert_eq!(sid.to_string(), s);
    }

    #[test]
    fn encoding_uses_correct_mixed_endianness() {
        // Authority big-endian, sub-authorities little-endian -- verify
        // byte-for-byte, not just round-trip (a bug that swapped both to
        // the same endianness would still round-trip against itself).
        let sid = Sid::new(5, [21]);
        let bytes = sid.encode();
        assert_eq!(bytes[0], 1, "revision");
        assert_eq!(bytes[1], 1, "sub-authority count");
        assert_eq!(&bytes[2..8], &[0, 0, 0, 0, 0, 5], "authority, big-endian");
        assert_eq!(&bytes[8..12], &21u32.to_le_bytes(), "sub-authority, little-endian");
    }

    #[test]
    fn with_sub_authority_appends() {
        let domain_sid = Sid::new(Sid::NT_AUTHORITY, [21, 1, 2, 3]);
        let object_sid = domain_sid.with_sub_authority(1105);
        assert_eq!(object_sid.to_string(), "S-1-5-21-1-2-3-1105");
    }

    #[test]
    fn decode_rejects_truncated_or_mismatched_length() {
        assert!(Sid::decode(&[1, 2, 0, 0, 0, 0, 0, 5]).is_none(), "claims 2 sub-authorities but has 0");
        assert!(Sid::decode(&[1]).is_none(), "too short even for the header");
    }

    #[test]
    fn parse_rejects_malformed_input() {
        assert!(Sid::parse("not-a-sid").is_none());
        assert!(Sid::parse("S-1-5-abc").is_none());
        assert!(Sid::parse("").is_none());
    }
}
