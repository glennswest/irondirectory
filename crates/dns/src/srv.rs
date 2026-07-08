//! SRV record name conventions for LDAP (RFC 2782's generic
//! `_service._proto.name` applied to `ldap`/`tcp`) and Kerberos (RFC
//! 4120 §7.2.3.2's `_kerberos._udp`/`_kerberos._tcp`).
//!
//! Names here are **relative to the zone**, not full FQDNs -- confirmed
//! against the live g8.lo zone's existing `_etcd-server-ssl._tcp` SRV
//! records, whose `name` field is exactly that (no `.g8.lo` suffix); the
//! zone itself supplies the domain when MicroDNS answers a query.

/// `_ldap._tcp` -- the record name for LDAP SRV autodiscovery, relative
/// to whichever zone it's published in (e.g. `"g8.lo"`).
pub const LDAP_SRV_NAME: &str = "_ldap._tcp";

/// `_kerberos._udp` -- KDC discovery over UDP, relative to the realm's
/// zone. RFC 4120 says clients SHOULD try UDP first, so this is the
/// primary record; `KERBEROS_TCP_SRV_NAME` is the TCP fallback.
pub const KERBEROS_UDP_SRV_NAME: &str = "_kerberos._udp";

/// `_kerberos._tcp` -- KDC discovery over TCP, relative to the realm's zone.
pub const KERBEROS_TCP_SRV_NAME: &str = "_kerberos._tcp";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_match_rfc_conventions() {
        assert_eq!(LDAP_SRV_NAME, "_ldap._tcp");
        assert_eq!(KERBEROS_UDP_SRV_NAME, "_kerberos._udp");
        assert_eq!(KERBEROS_TCP_SRV_NAME, "_kerberos._tcp");
    }
}
