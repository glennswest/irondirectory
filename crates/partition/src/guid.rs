//! Windows GUID (MS-DTYP §2.3.4), hand-rolled like [`crate::sid`].
//!
//! Text form: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` (lower-case hex).
//! Wire form (MS-DTYP §2.3.4.2, the `GUID` packet): Data1 as a
//! little-endian u32, Data2 and Data3 as little-endian u16s, then Data4's
//! eight bytes as written -- so the first three groups of the text form
//! are byte-swapped on the wire and the last two are not.

use std::fmt;

/// A Windows GUID, kept in text (RFC 4122) byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Guid([u8; 16]);

impl Guid {
    /// A version-4 (random) GUID from 16 random bytes: the version and
    /// variant bits are set as RFC 4122 §4.4 says.
    pub fn from_random(mut bytes: [u8; 16]) -> Self {
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Guid(bytes)
    }

    /// Parses the text form (case-insensitive, optional surrounding braces).
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().trim_start_matches('{').trim_end_matches('}');
        let groups: Vec<&str> = s.split('-').collect();
        if groups.iter().map(|g| g.len()).collect::<Vec<_>>() != [8, 4, 4, 4, 12] {
            return None;
        }
        let hex: String = groups.concat();
        let mut out = [0u8; 16];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
        }
        Some(Guid(out))
    }

    /// The MS-DTYP §2.3.4.2 wire form.
    pub fn to_wire(&self) -> [u8; 16] {
        let b = &self.0;
        [b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]
    }

    /// The inverse of [`Guid::to_wire`].
    pub fn from_wire(w: &[u8; 16]) -> Self {
        Guid([w[3], w[2], w[1], w[0], w[5], w[4], w[7], w[6], w[8], w[9], w[10], w[11], w[12], w[13], w[14], w[15]])
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let h: String = self.0.iter().map(|b| format!("{b:02x}")).collect();
        write!(f, "{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_round_trips_and_wire_swaps_the_first_three_groups() {
        let g = Guid::parse("{00112233-4455-6677-8899-AABBCCDDEEFF}").unwrap();
        assert_eq!(g.to_string(), "00112233-4455-6677-8899-aabbccddeeff");
        assert_eq!(
            g.to_wire(),
            [0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
        assert_eq!(Guid::from_wire(&g.to_wire()), g);
    }

    #[test]
    fn random_guids_carry_version_4_and_the_rfc_4122_variant() {
        let g = Guid::from_random([0xff; 16]).to_string();
        assert_eq!(&g[14..15], "4");
        assert_eq!(&g[19..20], "b");
    }

    #[test]
    fn malformed_text_is_refused() {
        for s in ["", "00112233-4455-6677-8899", "0011223-34455-6677-8899-aabbccddeeff", "zz112233-4455-6677-8899-aabbccddeeff"] {
            assert!(Guid::parse(s).is_none(), "{s}");
        }
    }
}
