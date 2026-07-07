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

    /// Appends `values` to `attr`'s existing values (creating it if
    /// absent), silently skipping any value already present rather than
    /// erroring (a simplification of RFC 4511's `AttributeOrValueExists`).
    pub fn add_values(&mut self, attr: impl AsRef<str>, values: impl IntoIterator<Item = impl Into<String>>) {
        let key = attr.as_ref().to_ascii_lowercase();
        let entry = self.attrs.entry(key).or_default();
        for v in values.into_iter().map(Into::into) {
            if !entry.contains(&v) {
                entry.push(v);
            }
        }
    }

    /// Removes `values` from `attr`; if `values` is empty, removes the
    /// whole attribute. Removing the attribute's last value also removes
    /// the attribute entirely. A no-op (not an error) if `attr` or the
    /// listed values aren't present -- a simplification of RFC 4511's
    /// `NoSuchAttribute`.
    pub fn delete_values(&mut self, attr: &str, values: &[String]) {
        let key = attr.to_ascii_lowercase();
        if values.is_empty() {
            self.attrs.remove(&key);
            return;
        }
        if let std::collections::btree_map::Entry::Occupied(mut e) = self.attrs.entry(key) {
            e.get_mut().retain(|v| !values.contains(v));
            if e.get().is_empty() {
                e.remove();
            }
        }
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

    #[test]
    fn add_values_creates_or_appends_and_dedups() {
        let mut e = Entry::new();
        e.add_values("mail", ["a@example.com"]);
        e.add_values("mail", ["b@example.com", "a@example.com"]);
        assert_eq!(
            e.get("mail"),
            Some(["a@example.com".to_string(), "b@example.com".to_string()].as_slice())
        );
    }

    #[test]
    fn delete_values_removes_listed_or_whole_attribute() {
        let mut e = Entry::new();
        e.set("mail", ["a@example.com", "b@example.com"]);
        e.delete_values("mail", &["a@example.com".to_string()]);
        assert_eq!(e.get("mail"), Some(["b@example.com".to_string()].as_slice()));

        e.delete_values("mail", &[]);
        assert_eq!(e.get("mail"), None);
    }

    #[test]
    fn delete_values_removes_attribute_when_last_value_goes() {
        let mut e = Entry::new();
        e.set("cn", ["alice"]);
        e.delete_values("cn", &["alice".to_string()]);
        assert_eq!(e.get("cn"), None);
    }
}
