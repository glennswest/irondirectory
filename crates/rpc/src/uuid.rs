//! MS-RPCE syntax-id UUIDs: a 16-byte mixed-endian GUID (`Data1` LE u32,
//! `Data2`/`Data3` LE u16, `Data4` 8 raw bytes, no reordering) -- the
//! same wire form Microsoft GUIDs always use, distinct from the
//! big-endian-throughout form this project's own `iron-partition::Sid`
//! uses for SIDs.

fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

fn hex_byte(b: &[u8], hi: usize) -> u8 {
    (hex_nibble(b[hi]) << 4) | hex_nibble(b[hi + 1])
}

/// Parses a canonical `"8a885d04-1ceb-11c9-9fe8-08002b104860"` string
/// into its 16-byte wire form. Panics on malformed input -- only ever
/// called on this module's own hard-coded values below, not
/// arbitrary/client-supplied data.
fn uuid_wire(s: &str) -> [u8; 16] {
    let b = s.as_bytes();
    // Group offsets in "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx".
    let d1 = [hex_byte(b, 0), hex_byte(b, 2), hex_byte(b, 4), hex_byte(b, 6)];
    let d2 = [hex_byte(b, 9), hex_byte(b, 11)];
    let d3 = [hex_byte(b, 14), hex_byte(b, 16)];
    let d4 = [
        hex_byte(b, 19),
        hex_byte(b, 21),
        hex_byte(b, 24),
        hex_byte(b, 26),
        hex_byte(b, 28),
        hex_byte(b, 30),
        hex_byte(b, 32),
        hex_byte(b, 34),
    ];

    [
        // Data1, Data2, Data3: little-endian.
        d1[3], d1[2], d1[1], d1[0], d2[1], d2[0], d3[1], d3[0],
        // Data4: raw byte order, no reordering.
        d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7],
    ]
}

/// A syntax id (abstract or transfer): 16-byte UUID + 2-byte major
/// version (LE) + 2-byte minor version (LE) = 20 bytes total.
pub fn syntax_id(uuid: &str, major: u16, minor: u16) -> [u8; 20] {
    let u = uuid_wire(uuid);
    let maj = major.to_le_bytes();
    let min = minor.to_le_bytes();
    [u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15], maj[0], maj[1], min[0], min[1]]
}

/// NDR transfer syntax (MS-RPCE 2.2.5.3) -- the only one this server offers.
pub fn ndr_transfer_syntax() -> [u8; 20] {
    syntax_id("8a885d04-1ceb-11c9-9fe8-08002b104860", 2, 0)
}

/// LSARPC (MS-LSAD) abstract syntax.
pub fn lsarpc_syntax() -> [u8; 20] {
    syntax_id("12345778-1234-abcd-ef00-0123456789ab", 0, 0)
}
/// SAMR (MS-SAMR) abstract syntax.
pub fn samr_syntax() -> [u8; 20] {
    syntax_id("12345778-1234-abcd-ef00-0123456789ac", 1, 0)
}
/// NETLOGON (MS-NRPC) abstract syntax.
pub fn netlogon_syntax() -> [u8; 20] {
    syntax_id("12345678-1234-abcd-ef00-01234567cffb", 1, 0)
}

use std::sync::LazyLock;

/// Cached NDR transfer syntax bytes -- computed once, reused everywhere
/// this needs comparing/embedding (every `bind_ack`).
pub static NDR_TRANSFER_SYNTAX: LazyLock<[u8; 20]> = LazyLock::new(ndr_transfer_syntax);
/// Cached LSARPC abstract syntax bytes.
pub static LSARPC_SYNTAX: LazyLock<[u8; 20]> = LazyLock::new(lsarpc_syntax);
/// Cached SAMR abstract syntax bytes.
pub static SAMR_SYNTAX: LazyLock<[u8; 20]> = LazyLock::new(samr_syntax);
/// Cached NETLOGON abstract syntax bytes.
pub static NETLOGON_SYNTAX: LazyLock<[u8; 20]> = LazyLock::new(netlogon_syntax);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ndr_transfer_syntax_matches_known_wire_bytes() {
        // Cross-checked against impacket's DCERPC.NDRSyntax
        // (uuidtup_to_bin(('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0'))).
        assert_eq!(
            *NDR_TRANSFER_SYNTAX,
            [0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn samr_syntax_version_is_1_0() {
        assert_eq!(&SAMR_SYNTAX[16..20], &[1, 0, 0, 0]);
    }
}
