//! iron-kdc: Kerberos 5 KDC over the iron-store DIT (#5).
//!
//! AS-REQ/AS-REP with PA-ENC-TIMESTAMP pre-auth, TGS-REQ/TGS-REP for
//! service tickets, realm-per-partition (D8 -- a `Partition` already
//! carries a `realm`), AES-only enctypes (D4 -- see `iron_crypto::kerberos`
//! for the crypto; RC4/DES are never implemented, not just disabled).
//! Keytab I/O for handing service principal keys to other daemons
//! (rocketsmbd, sshd, ...). Cross-realm `krbtgt/CHILD@PARENT` key slots
//! and one-hop referral-ticket routing (#11) follow the same
//! `Partition.superior`/`.subordinates` relationships `iron-ldap`'s
//! rootDSE uses for `rootDomainNamingContext` -- `AppState::topology`,
//! loaded from the persisted configuration partition (#9) exactly like
//! `iron-ldap`'s referral wiring (#10). Transitive multi-realm
//! trust-path walking and shortcut trusts are explicitly out of scope
//! (D10 -- one hop only).

pub mod as_exchange;
pub mod keytab;
pub mod krberror;
pub mod pac;
pub mod principal;
pub mod server;
pub mod tgs_exchange;
pub mod time;
pub mod wire;

use std::sync::Arc;

use iron_crypto::FipsContext;
use iron_partition::{Dn, PartitionId, PartitionRegistry};
use iron_store::index::IndexSpec;
use iron_store::store::Store;
use rasn::types::GeneralString;
use rasn_kerberos::{PrincipalName, Realm};
use tokio::sync::Mutex;

/// Default ticket lifetime: 10 hours, matching common AD/MIT krb5
/// defaults.
pub const TICKET_LIFETIME_SECS: i64 = 10 * 3600;
/// Default renewable lifetime, when renewal is requested/granted.
pub const RENEWABLE_LIFETIME_SECS: i64 = 7 * 24 * 3600;
/// RFC 4120's recommended default clock-skew tolerance.
pub const CLOCK_SKEW_SECS: i64 = 300;

/// Attributes `iron-kdc` reads/writes on shared DIT entries -- passed to
/// `Store::put_entry`/`lookup_by_index` alongside whatever `iron-ldap`
/// already indexes, so principal lookups work regardless of which tool
/// wrote the entry. `"member"` (#18) gives `pac::group_sids` an
/// efficient reverse lookup from a user DN to the `groupOfNames` entries
/// that list it -- must match `iron-ldap`'s own index spec, since
/// whichever tool actually writes a group entry is the one whose spec
/// determines what gets indexed for it.
pub fn index_spec() -> IndexSpec {
    IndexSpec::new(["cn", "mail", "uid", "member", principal::ATTR_PRINCIPAL_NAME])
}

/// Shared server state handed to every request.
pub struct AppState {
    pub store: Mutex<Store>,
    pub index_spec: IndexSpec,
    /// A DN inside the served partition, used only to resolve which
    /// partition/cluster to query (`Store::lookup_by_index` needs one) --
    /// not a search scope.
    pub base_dn: Dn,
    pub realm: String,
    /// Unlike `iron-ldap`'s optional FIPS context (anonymous bind/search
    /// still work without it), a KDC that can't do Kerberos crypto can't
    /// do anything at all -- `AppState::new` fails outright if the FIPS
    /// provider isn't active, rather than starting in a half-working mode.
    pub fips: FipsContext,
    /// The forest-wide partition topology (#9/#10), loaded once at
    /// startup from the persisted configuration partition if
    /// `IRON_KDC_CONFIG_*` env vars are set. Lets TGS-REQ find a direct
    /// (one-hop) trust with another realm and route a referral ticket
    /// through it instead of failing closed (#11, `tgs_exchange`'s
    /// `referral_tgs_rep`). `None` if no configuration partition is set
    /// up -- no cross-realm referrals are possible then (matching
    /// `iron-ldap`'s `AppState::topology` fallback behavior). A
    /// snapshot, not watched.
    pub topology: Option<PartitionRegistry>,
    /// This instance's own partition id in `topology`, needed to look up
    /// its superior/subordinate partitions via `PartitionRegistry::superior_of`/
    /// `subordinates_of`.
    pub own_partition_id: Option<PartitionId>,
}

impl AppState {
    pub fn new(
        store: Store,
        base_dn: Dn,
        realm: String,
        topology: Option<PartitionRegistry>,
        own_partition_id: Option<PartitionId>,
    ) -> Result<Arc<Self>, iron_crypto::Error> {
        let fips = FipsContext::new()?;
        Ok(Arc::new(AppState { store: Mutex::new(store), index_spec: index_spec(), base_dn, realm, fips, topology, own_partition_id }))
    }
}

/// `GeneralString` doesn't implement `Display` (it's an arbitrary-byte
/// wrapper, not a validated Unicode string) -- every place that needs to
/// print, compare-as-`str`, or `format!` a `Realm`/`KerberosString` goes
/// through this instead of assuming valid UTF-8 round-trips cleanly.
pub fn gstring_to_string(gs: &GeneralString) -> String {
    String::from_utf8_lossy(gs.as_bytes()).into_owned()
}

/// Converts a plain `&str` to a `GeneralString`/`KerberosString`/`Realm`
/// (all the same underlying type). Never panics: bytes outside
/// `GeneralString`'s permitted character set (C0 controls, space, Basic
/// Latin, DELETE, Latin-1 Supplement) become `?` instead. Every string
/// built this way ultimately traces back to either a value we configured
/// ourselves (always plain ASCII in practice) or client-supplied input
/// echoed into an error message -- neither should ever be able to crash
/// request handling over a byte outside a niche permitted-character-set
/// rule.
pub fn string_to_gstring(s: &str) -> GeneralString {
    let sanitized: Vec<u8> = s.bytes().map(|b| if matches!(b, 0x00..=0x7F | 0xA0..=0xFF) { b } else { b'?' }).collect();
    GeneralString::from_bytes(&sanitized).expect("sanitized to only permitted-set bytes")
}

pub fn realm_to_string(realm: &Realm) -> String {
    gstring_to_string(realm)
}

/// Splits `"primary/instance"` into a two-component [`PrincipalName`]
/// (`NT-SRV-INST`), or a single-component one (`NT-PRINCIPAL`) if there's
/// no `/`.
pub fn string_to_principal_name(name: &str) -> PrincipalName {
    let parts: Vec<GeneralString> = name.split('/').map(string_to_gstring).collect();
    let r#type = if parts.len() > 1 { 2 } else { 1 }; // NT-SRV-INST : NT-PRINCIPAL
    PrincipalName { r#type, string: parts }
}

/// The inverse of [`string_to_principal_name`] (ignores `r#type`, which
/// is documented as a hint -- RFC 4120 §6.2).
pub fn principal_name_to_string(pn: &PrincipalName) -> String {
    pn.string.iter().map(gstring_to_string).collect::<Vec<_>>().join("/")
}

/// The well-known ticket-granting-service principal name for `realm`.
pub fn krbtgt_principal_name(realm: &str) -> PrincipalName {
    string_to_principal_name(&format!("krbtgt/{realm}"))
}

/// The well-known `AD-WIN2K-PAC` authorization-data type (MS-KILE).
const AD_WIN2K_PAC: i32 = 128;

/// Wraps a signed PAC blob (`pac::generate`, #18) as ticket
/// authorization-data: an outer `AD-IF-RELEVANT` (RFC 4120 §5.2.6.1)
/// element whose own `data` is a DER-encoded `AuthorizationData`
/// containing exactly one `AD-WIN2K-PAC` element -- this two-level
/// wrapping (not just a bare `AD-WIN2K-PAC` entry) is what MS-KILE
/// actually puts on the wire, and what lets a client ignore the PAC
/// entirely (per AD-IF-RELEVANT's own semantics) if it doesn't
/// recognize it. `None` only if DER-encoding the inner element fails
/// (unreachable for well-formed input; kept as `Option` rather than
/// `expect` since this is on the ticket-issuing hot path).
pub fn wrap_pac_authorization_data(pac_bytes: Vec<u8>) -> Option<rasn_kerberos::AuthorizationData> {
    let inner = vec![rasn_kerberos::AuthorizationDataValue { r#type: AD_WIN2K_PAC, data: pac_bytes.into() }];
    let inner_encoded = rasn::der::encode(&inner).ok()?;
    Some(vec![rasn_kerberos::AuthorizationDataValue {
        r#type: rasn_kerberos::AuthorizationDataValue::IF_RELEVANT,
        data: inner_encoded.into(),
    }])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_name_roundtrip() {
        let pn = string_to_principal_name("alice");
        assert_eq!(pn.r#type, 1);
        assert_eq!(principal_name_to_string(&pn), "alice");

        let pn = string_to_principal_name("krbtgt/IRON.LO");
        assert_eq!(pn.r#type, 2);
        assert_eq!(principal_name_to_string(&pn), "krbtgt/IRON.LO");
    }
}
