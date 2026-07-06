//! The stored entry format: a multi-valued attribute map, serialized as the
//! fastetcd value at an entry's key (`iron_partition::key::entry_key`).
//!
//! Deliberately schema-free for now (#3) — `iron-ldap` will layer objectClass
//! / schema validation on top later. Attribute names are folded to lowercase
//! (LDAP attribute names are case-insensitive); values are UTF-8 strings.
//! Binary attribute values are out of scope until a concrete need shows up.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::StoreError;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    attrs: BTreeMap<String, Vec<String>>,
}

impl Entry {
    pub fn new() -> Self {
        Entry::default()
    }

    /// Replaces the values of `attr` (folded to lowercase).
    pub fn set(&mut self, attr: impl AsRef<str>, values: impl IntoIterator<Item = impl Into<String>>) {
        self.attrs.insert(
            attr.as_ref().to_ascii_lowercase(),
            values.into_iter().map(Into::into).collect(),
        );
    }

    /// The values of `attr` (case-insensitive), if present.
    pub fn get(&self, attr: &str) -> Option<&[String]> {
        self.attrs.get(&attr.to_ascii_lowercase()).map(Vec::as_slice)
    }

    /// Every attribute name currently set.
    pub fn attr_names(&self) -> impl Iterator<Item = &str> {
        self.attrs.keys().map(String::as_str)
    }

    pub fn encode(&self) -> Vec<u8> {
        // BTreeMap<String, Vec<String>> of our own construction always
        // serializes; this can't fail in practice.
        serde_json::to_vec(self).expect("Entry is always serializable")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        serde_json::from_slice(bytes).map_err(StoreError::EntryDecode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_names_fold_to_lowercase() {
        let mut e = Entry::new();
        e.set("CN", ["Alice"]);
        assert_eq!(e.get("cn"), Some(["Alice".to_string()].as_slice()));
        assert_eq!(e.get("Cn"), Some(["Alice".to_string()].as_slice()));
    }

    #[test]
    fn encode_decode_roundtrip() {
        let mut e = Entry::new();
        e.set("cn", ["alice"]);
        e.set("objectClass", ["person", "top"]);
        let bytes = e.encode();
        let decoded = Entry::decode(&bytes).unwrap();
        assert_eq!(e, decoded);
        assert_eq!(decoded.get("objectclass"), Some(["person".to_string(), "top".to_string()].as_slice()));
    }
}
