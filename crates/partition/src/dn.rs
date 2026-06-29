//! Distinguished Name (DN) handling — RFC 4514 string form, pragmatic subset.
//!
//! A [`Dn`] is an ordered sequence of [`Rdn`]s, most-specific first
//! (`cn=alice,ou=users,dc=g10,dc=lo`). DNs are the addressing primitive for the
//! whole directory: partitions are identified by their base DN, and routing a
//! request means finding the partition whose base DN is the longest **suffix**
//! of the target DN (see [`crate::registry::PartitionRegistry::resolve`]).
//!
//! Equality and containment use a normalized form: attribute types are
//! lower-cased and values are compared case-insensitively. This is deliberately
//! simpler than per-attribute LDAP matching rules — it is the right behavior for
//! the structural attributes that form DNs (`dc`, `ou`, `cn`, …) and for routing.
//!
//! Storage keys reverse the RDN order so that a subtree maps to a key prefix
//! (see [`crate::key`]).
//!
//! ## Known limitations (happy-path; expand under D10 testing)
//! - Hex-pair escapes (`\\41`) are decoded as single bytes; multi-byte UTF-8
//!   hex sequences are not reassembled.
//! - No BER/DER (`#`-prefixed) value form.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::PartitionError;

/// One attribute-value assertion within an RDN, e.g. `cn=Alice`.
#[derive(Debug, Clone)]
pub struct Ava {
    /// Attribute type, normalized to lower-case (e.g. `cn`).
    attr: String,
    /// Value as originally supplied (for display).
    value: String,
    /// Case-folded value, used for equality/containment.
    norm_value: String,
}

impl Ava {
    /// Attribute type (lower-cased).
    pub fn attr(&self) -> &str {
        &self.attr
    }
    /// Original (display) value.
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl PartialEq for Ava {
    fn eq(&self, other: &Self) -> bool {
        self.attr == other.attr && self.norm_value == other.norm_value
    }
}
impl Eq for Ava {}

/// A relative distinguished name: one or more [`Ava`]s (multi-valued RDNs are
/// joined by `+`). AVAs are kept sorted by `(attr, norm_value)` so that
/// equality is order-independent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rdn {
    avas: Vec<Ava>,
}

impl Rdn {
    /// The AVAs of this RDN, in normalized order.
    pub fn avas(&self) -> &[Ava] {
        &self.avas
    }

    /// Canonical, normalized string form (`attr=normvalue[+attr=normvalue]`),
    /// used to build storage keys so keys are case-insensitive-consistent.
    fn normalized_string(&self) -> String {
        self.avas
            .iter()
            .map(|a| format!("{}={}", a.attr, a.norm_value))
            .collect::<Vec<_>>()
            .join("+")
    }
}

impl fmt::Display for Rdn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts: Vec<String> = self
            .avas
            .iter()
            .map(|a| format!("{}={}", a.attr, escape_value(&a.value)))
            .collect();
        f.write_str(&parts.join("+"))
    }
}

/// A distinguished name: an ordered list of [`Rdn`]s, most-specific first.
/// An empty `Dn` is the root DSE.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Dn {
    rdns: Vec<Rdn>,
}

impl Dn {
    /// The empty DN (root DSE).
    pub fn root() -> Self {
        Dn { rdns: Vec::new() }
    }

    /// Parse a DN from its RFC 4514 string form.
    pub fn parse(s: &str) -> Result<Self, PartitionError> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Ok(Dn::root());
        }
        let mut rdns = Vec::new();
        for rdn_str in split_unescaped(trimmed, ',') {
            let rdn_str = rdn_str.trim();
            if rdn_str.is_empty() {
                return Err(PartitionError::InvalidDn {
                    input: s.to_string(),
                    reason: "empty RDN".into(),
                });
            }
            let mut avas = Vec::new();
            for ava_str in split_unescaped(rdn_str, '+') {
                avas.push(parse_ava(ava_str.trim(), s)?);
            }
            avas.sort_by(|a, b| (&a.attr, &a.norm_value).cmp(&(&b.attr, &b.norm_value)));
            rdns.push(Rdn { avas });
        }
        Ok(Dn { rdns })
    }

    /// True if this DN has no RDNs (the root DSE).
    pub fn is_empty(&self) -> bool {
        self.rdns.is_empty()
    }

    /// Number of RDNs (tree depth).
    pub fn depth(&self) -> usize {
        self.rdns.len()
    }

    /// The RDNs, most-specific first.
    pub fn rdns(&self) -> &[Rdn] {
        &self.rdns
    }

    /// The immediate parent DN, or `None` if this is the root DSE.
    pub fn parent(&self) -> Option<Dn> {
        if self.rdns.is_empty() {
            None
        } else {
            Some(Dn {
                rdns: self.rdns[1..].to_vec(),
            })
        }
    }

    /// True if `self` is at or below `base` in the tree — i.e. `base` is a
    /// suffix of `self`. Equal DNs are within each other. This is the SUBTREE
    /// containment test used for routing and scope handling.
    pub fn is_within(&self, base: &Dn) -> bool {
        if base.rdns.len() > self.rdns.len() {
            return false;
        }
        let off = self.rdns.len() - base.rdns.len();
        self.rdns[off..] == base.rdns[..]
    }

    /// True if `self` is strictly below `base` (within, but not equal).
    pub fn is_strict_descendant_of(&self, base: &Dn) -> bool {
        self.rdns.len() > base.rdns.len() && self.is_within(base)
    }

    /// Normalized RDN components ordered root-first (the reverse of DN order),
    /// each as a canonical `attr=normvalue` string. Used to build hierarchical
    /// storage keys where a subtree is a key prefix.
    pub fn reversed_components(&self) -> Vec<String> {
        self.rdns
            .iter()
            .rev()
            .map(|r| r.normalized_string())
            .collect()
    }
}

impl fmt::Display for Dn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts: Vec<String> = self.rdns.iter().map(|r| r.to_string()).collect();
        f.write_str(&parts.join(","))
    }
}

impl FromStr for Dn {
    type Err = PartitionError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Dn::parse(s)
    }
}

impl Serialize for Dn {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Dn {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Dn::parse(&s).map_err(serde::de::Error::custom)
    }
}

fn parse_ava(s: &str, full: &str) -> Result<Ava, PartitionError> {
    let eq = find_unescaped(s, '=').ok_or_else(|| PartitionError::InvalidDn {
        input: full.to_string(),
        reason: format!("AVA {s:?} has no '='"),
    })?;
    let attr = s[..eq].trim().to_ascii_lowercase();
    if attr.is_empty() {
        return Err(PartitionError::InvalidDn {
            input: full.to_string(),
            reason: "empty attribute type".into(),
        });
    }
    let raw_value = s[eq + 1..].trim();
    let value = unescape(raw_value);
    let norm_value = value.trim().to_ascii_lowercase();
    Ok(Ava {
        attr,
        value,
        norm_value,
    })
}

/// Split `s` on each unescaped occurrence of `delim`, preserving backslash
/// escape sequences in the output (they are removed later by [`unescape`]).
fn split_unescaped(s: &str, delim: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut escaped = false;
    for c in s.chars() {
        if escaped {
            cur.push('\\');
            cur.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == delim {
            parts.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    if escaped {
        cur.push('\\');
    }
    parts.push(cur);
    parts
}

fn find_unescaped(s: &str, delim: char) -> Option<usize> {
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == delim {
            return Some(i);
        }
    }
    None
}

/// Remove RFC 4514 escaping from a value. Backslash escapes the next character
/// literally; `\\XX` decodes a single hex byte (best-effort, ASCII).
fn unescape(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.peek().copied() {
            Some(h1) if h1.is_ascii_hexdigit() => {
                chars.next();
                match chars.peek().copied() {
                    Some(h2) if h2.is_ascii_hexdigit() => {
                        chars.next();
                        let byte =
                            u8::from_str_radix(&format!("{h1}{h2}"), 16).expect("two hex digits");
                        out.push(byte as char);
                    }
                    // single hex digit after backslash: treat literally
                    _ => out.push(h1),
                }
            }
            Some(other) => {
                chars.next();
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// Escape a value for canonical DN display (RFC 4514 special characters and
/// leading/trailing space).
fn escape_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let chars: Vec<char> = v.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        let edge = i == 0 || i == chars.len() - 1;
        match c {
            '\\' | ',' | '+' | '=' | '<' | '>' | '#' | ';' | '"' => {
                out.push('\\');
                out.push(c);
            }
            ' ' if edge => {
                out.push('\\');
                out.push(' ');
            }
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_display_roundtrip() {
        let dn = Dn::parse("cn=alice,ou=users,dc=g10,dc=lo").unwrap();
        assert_eq!(dn.depth(), 4);
        assert_eq!(dn.to_string(), "cn=alice,ou=users,dc=g10,dc=lo");
    }

    #[test]
    fn root_dse_is_empty() {
        assert!(Dn::parse("").unwrap().is_empty());
        assert!(Dn::parse("   ").unwrap().is_empty());
        assert!(Dn::root().parent().is_none());
    }

    #[test]
    fn equality_is_case_insensitive_on_type_and_value() {
        let a = Dn::parse("CN=Alice,DC=G10,DC=LO").unwrap();
        let b = Dn::parse("cn=alice,dc=g10,dc=lo").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn within_is_suffix_containment() {
        let base = Dn::parse("dc=g10,dc=lo").unwrap();
        let child = Dn::parse("cn=alice,ou=users,dc=g10,dc=lo").unwrap();
        let other = Dn::parse("dc=g11,dc=lo").unwrap();
        assert!(child.is_within(&base));
        assert!(base.is_within(&base)); // reflexive
        assert!(child.is_strict_descendant_of(&base));
        assert!(!base.is_strict_descendant_of(&base));
        assert!(!other.is_within(&base));
        assert!(!base.is_within(&child));
    }

    #[test]
    fn parent_walks_up() {
        let dn = Dn::parse("cn=alice,ou=users,dc=g10,dc=lo").unwrap();
        let p = dn.parent().unwrap();
        assert_eq!(p, Dn::parse("ou=users,dc=g10,dc=lo").unwrap());
    }

    #[test]
    fn reversed_components_are_root_first_and_normalized() {
        let dn = Dn::parse("CN=Alice,DC=G10,DC=LO").unwrap();
        assert_eq!(
            dn.reversed_components(),
            vec!["dc=lo".to_string(), "dc=g10".into(), "cn=alice".into()]
        );
    }

    #[test]
    fn escaped_comma_in_value() {
        let dn = Dn::parse(r"cn=Doe\, Jane,dc=g10,dc=lo").unwrap();
        assert_eq!(dn.rdns()[0].avas()[0].value(), "Doe, Jane");
        // round-trips through canonical escaping
        assert_eq!(Dn::parse(&dn.to_string()).unwrap(), dn);
    }

    #[test]
    fn multivalued_rdn_is_order_independent() {
        let a = Dn::parse("cn=alice+uid=a1,dc=lo").unwrap();
        let b = Dn::parse("uid=a1+cn=alice,dc=lo").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn serde_roundtrip() {
        let dn = Dn::parse("ou=users,dc=g10,dc=lo").unwrap();
        let j = serde_json::to_string(&dn).unwrap();
        assert_eq!(j, "\"ou=users,dc=g10,dc=lo\"");
        let back: Dn = serde_json::from_str(&j).unwrap();
        assert_eq!(dn, back);
    }
}
