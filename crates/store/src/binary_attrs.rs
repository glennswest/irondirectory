//! Shared storage convention for MS-DTYP binary attribute values
//! (`objectSid`, `nTSecurityDescriptor`) that don't fit `Entry`'s
//! UTF-8-only value model (#17): stored as base64 text, decoded back to
//! raw bytes only at each protocol frontend's own wire boundary. Shared
//! between `iron-ldap` (LDAP wire projection, #17) and `iron-kdc` (PAC
//! generation, #18) -- both need to read a principal's `objectSid`, and
//! neither should duplicate the encoding convention.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// `objectSid`, stored as base64.
pub const OBJECT_SID_ATTR: &str = "objectsid";
/// `nTSecurityDescriptor`, stored as base64.
pub const NT_SECURITY_DESCRIPTOR_ATTR: &str = "ntsecuritydescriptor";

/// Whether `name` is one of the attributes this module's convention applies to.
pub fn is_binary_attr(name: &str) -> bool {
    name.eq_ignore_ascii_case(OBJECT_SID_ATTR) || name.eq_ignore_ascii_case(NT_SECURITY_DESCRIPTOR_ATTR)
}

/// Decodes a stored base64 value back to raw bytes. Falls back to the
/// stored string's own UTF-8 bytes on a decode failure (should never
/// happen for a value this convention itself wrote) rather than dropping
/// the value or panicking.
pub fn decode_binary_attr(value: &str) -> Vec<u8> {
    STANDARD.decode(value).unwrap_or_else(|_| value.as_bytes().to_vec())
}

/// Encodes raw bytes for storage as an `Entry` attribute value.
pub fn encode_binary_attr(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_attr_roundtrips_through_base64() {
        let raw = vec![1u8, 5, 21, 0, 0, 0, 0, 0, 5, 0, 0, 0];
        let encoded = encode_binary_attr(&raw);
        assert!(is_binary_attr("objectSid"));
        assert!(is_binary_attr("NTSECURITYDESCRIPTOR"));
        assert!(!is_binary_attr("cn"));
        assert_eq!(decode_binary_attr(&encoded), raw);
    }
}
