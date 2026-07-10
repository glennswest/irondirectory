//! Partition (naming context) model.
//!
//! A [`Partition`] is one naming context — the unit that, per decision D8, maps
//! to its own strongly-consistent fastetcd Raft cluster. The set of partitions
//! and their relationships is held by the [`crate::registry::PartitionRegistry`].

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::dn::Dn;
use crate::error::PartitionError;

/// Validate a `[a-z0-9-]` identifier with no leading/trailing `-`.
fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Stable identifier for a partition. Used directly in storage keys
/// (`/iron/<id>/…`), so it is constrained to `[a-z0-9-]`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartitionId(String);

impl PartitionId {
    /// Construct, validating the `[a-z0-9-]` rule.
    pub fn new(s: impl Into<String>) -> Result<Self, PartitionError> {
        let s = s.into();
        if valid_id(&s) {
            Ok(PartitionId(s))
        } else {
            Err(PartitionError::InvalidId(s))
        }
    }
    /// The id as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PartitionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl FromStr for PartitionId {
    type Err = PartitionError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PartitionId::new(s)
    }
}
impl Serialize for PartitionId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}
impl<'de> Deserialize<'de> for PartitionId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        PartitionId::new(s).map_err(serde::de::Error::custom)
    }
}

/// Stable identifier for a forest (a set of partitions sharing a schema and
/// configuration). Distinct forests are independent security boundaries (D9).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ForestId(String);

impl ForestId {
    /// Construct, validating the `[a-z0-9-]` rule.
    pub fn new(s: impl Into<String>) -> Result<Self, PartitionError> {
        let s = s.into();
        if valid_id(&s) {
            Ok(ForestId(s))
        } else {
            Err(PartitionError::InvalidForestId(s))
        }
    }
    /// The id as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Display for ForestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl Serialize for ForestId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}
impl<'de> Deserialize<'de> for ForestId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        ForestId::new(s).map_err(serde::de::Error::custom)
    }
}

/// The kind of naming context, mirroring Active Directory's partition types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PartitionKind {
    /// A domain naming context — replicated only among that domain's DCs. Has a
    /// Kerberos realm.
    Domain,
    /// The schema naming context — forest-wide, replicated to every DC.
    Schema,
    /// The configuration naming context — forest-wide (holds the registry of
    /// partitions, the crossRef-equivalents).
    Configuration,
    /// An application naming context (e.g. a DNS zone partition).
    Application,
}

/// Reference to a TLS identity for talking to a fastetcd cluster. These are
/// *references* (file paths / secret names), never embedded key material — see
/// the project security rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsRef {
    /// Path/secret-ref of the CA bundle that signs the cluster's server certs.
    pub ca: String,
    /// Path/secret-ref of this client's certificate.
    pub cert: String,
    /// Path/secret-ref of this client's private key.
    pub key: String,
}

/// How to reach the fastetcd cluster that hosts a partition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterRef {
    /// etcd v3 gRPC endpoints for the cluster (e.g. `https://10.0.0.1:2379`).
    pub endpoints: Vec<String>,
    /// Optional mTLS identity. `None` means plaintext (test/dev only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsRef>,
}

impl ClusterRef {
    /// A plaintext (no-TLS) cluster reference — for tests/dev only.
    pub fn plaintext(endpoints: impl IntoIterator<Item = impl Into<String>>) -> Self {
        ClusterRef {
            endpoints: endpoints.into_iter().map(Into::into).collect(),
            tls: None,
        }
    }
}

/// A naming context and everything needed to host, route, and federate it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Partition {
    /// Stable id; also the storage-key namespace.
    pub id: PartitionId,
    /// Forest this partition belongs to (D9 isolation boundary).
    pub forest: ForestId,
    /// Base DN — the root of this naming context.
    pub base_dn: Dn,
    /// Partition kind.
    pub kind: PartitionKind,
    /// Kerberos realm (upper-cased), present for domain partitions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    /// The fastetcd cluster hosting this partition.
    pub cluster: ClusterRef,
    /// Superior (parent) naming context, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superior: Option<PartitionId>,
    /// Subordinate (child) naming contexts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subordinates: Vec<PartitionId>,
    /// LDAP URL clients are referred to for this partition (for cross-NC
    /// referrals), e.g. `ldaps://dc1.g10.lo:636`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ldap_url: Option<String>,
    /// KDC host:port for this partition's realm (for cross-realm Kerberos
    /// referral routing, #11), e.g. `kdc1.g10.lo:88`. Real clients find
    /// this via `_kerberos._udp` SRV records (`iron-dns`); this field is
    /// the same kind of hint `ldap_url` is -- useful for testing/ops
    /// visibility, not itself consulted by `iron-kdc` to reach a peer
    /// (referral tickets only need the *key*, not the address; the
    /// client's own krb5.conf/DNS gets it to the next KDC).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdc_url: Option<String>,
}

impl Partition {
    /// Start building a domain partition. The realm is derived from the base DN
    /// `dc=` components (e.g. `dc=g10,dc=lo` → `G10.LO`) unless overridden.
    pub fn domain(
        id: impl Into<String>,
        forest: ForestId,
        base_dn: Dn,
        cluster: ClusterRef,
    ) -> Result<Self, PartitionError> {
        let realm = realm_from_dn(&base_dn);
        Ok(Partition {
            id: PartitionId::new(id)?,
            forest,
            base_dn,
            kind: PartitionKind::Domain,
            realm,
            cluster,
            superior: None,
            subordinates: Vec::new(),
            ldap_url: None,
            kdc_url: None,
        })
    }

    /// Start building a configuration partition (#9) -- the forest-wide NC
    /// that holds the [`crate::registry::PartitionRegistry`]'s persisted
    /// form (crossRef-equivalent records, one per partition, including a
    /// self-describing record for the configuration partition itself). No
    /// realm (only `Domain` partitions have one) and never has a superior.
    pub fn configuration(id: impl Into<String>, forest: ForestId, base_dn: Dn, cluster: ClusterRef) -> Result<Self, PartitionError> {
        Ok(Partition {
            id: PartitionId::new(id)?,
            forest,
            base_dn,
            kind: PartitionKind::Configuration,
            realm: None,
            cluster,
            superior: None,
            subordinates: Vec::new(),
            ldap_url: None,
            kdc_url: None,
        })
    }

    /// Builder: set the superior (parent) partition.
    pub fn with_superior(mut self, superior: PartitionId) -> Self {
        self.superior = Some(superior);
        self
    }

    /// Builder: set the Kerberos realm explicitly (upper-cased).
    pub fn with_realm(mut self, realm: impl Into<String>) -> Self {
        self.realm = Some(realm.into().to_ascii_uppercase());
        self
    }

    /// Builder: set the LDAP referral URL.
    pub fn with_ldap_url(mut self, url: impl Into<String>) -> Self {
        self.ldap_url = Some(url.into());
        self
    }

    /// Builder: set the KDC host:port hint.
    pub fn with_kdc_url(mut self, url: impl Into<String>) -> Self {
        self.kdc_url = Some(url.into());
        self
    }
}

/// Derive a Kerberos realm from the `dc=` components of a base DN, root-first
/// and upper-cased (`dc=g10,dc=lo` → `G10.LO`). Returns `None` if there are no
/// `dc=` components.
pub fn realm_from_dn(dn: &Dn) -> Option<String> {
    let labels: Vec<String> = dn
        .rdns()
        .iter()
        .filter_map(|r| {
            let avas = r.avas();
            if avas.len() == 1 && avas[0].attr() == "dc" {
                Some(avas[0].value().to_ascii_uppercase())
            } else {
                None
            }
        })
        .collect();
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_id_validation() {
        assert!(PartitionId::new("g10-domain").is_ok());
        assert!(PartitionId::new("dc0").is_ok());
        assert!(PartitionId::new("Bad").is_err());
        assert!(PartitionId::new("-x").is_err());
        assert!(PartitionId::new("x-").is_err());
        assert!(PartitionId::new("").is_err());
        assert!(PartitionId::new("a/b").is_err());
    }

    #[test]
    fn realm_derivation() {
        let dn = Dn::parse("dc=g10,dc=lo").unwrap();
        assert_eq!(realm_from_dn(&dn).as_deref(), Some("G10.LO"));
        let child = Dn::parse("dc=emea,dc=g10,dc=lo").unwrap();
        assert_eq!(realm_from_dn(&child).as_deref(), Some("EMEA.G10.LO"));
        let nodc = Dn::parse("o=acme").unwrap();
        assert_eq!(realm_from_dn(&nodc), None);
    }

    #[test]
    fn domain_builder_sets_realm() {
        let p = Partition::domain(
            "g10",
            ForestId::new("acme").unwrap(),
            Dn::parse("dc=g10,dc=lo").unwrap(),
            ClusterRef::plaintext(["http://127.0.0.1:2379"]),
        )
        .unwrap();
        assert_eq!(p.realm.as_deref(), Some("G10.LO"));
        assert_eq!(p.kind, PartitionKind::Domain);
    }

    #[test]
    fn configuration_builder_has_no_realm_or_superior() {
        let p = Partition::configuration(
            "config",
            ForestId::new("acme").unwrap(),
            Dn::parse("cn=configuration,dc=lo").unwrap(),
            ClusterRef::plaintext(["http://127.0.0.1:2379"]),
        )
        .unwrap();
        assert_eq!(p.kind, PartitionKind::Configuration);
        assert_eq!(p.realm, None);
        assert_eq!(p.superior, None);
    }

    #[test]
    fn partition_serde_roundtrip() {
        let p = Partition::domain(
            "g10",
            ForestId::new("acme").unwrap(),
            Dn::parse("dc=g10,dc=lo").unwrap(),
            ClusterRef::plaintext(["http://127.0.0.1:2379"]),
        )
        .unwrap()
        .with_ldap_url("ldaps://dc1.g10.lo:636")
        .with_kdc_url("kdc1.g10.lo:88");
        let j = serde_json::to_string(&p).unwrap();
        let back: Partition = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
        assert_eq!(p.kdc_url.as_deref(), Some("kdc1.g10.lo:88"));
    }
}
