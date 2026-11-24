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

/// The one site there is (no `cn=Sites` yet), as the LDAP ping (#52) says.
pub const DEFAULT_SITE: &str = "Default-First-Site-Name";

/// Which of a DC's services a record points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    Ldap,
    Kerberos,
    Kpasswd,
}

/// One SRV record a DC registers: the zone it lives in, its name
/// relative to that zone, and the service it points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DcRecord {
    pub zone: String,
    pub name: String,
    pub service: Service,
}

/// The SRV records a writable, non-GC DC registers for its domain (#87):
/// MS-ADTS 6.3.2.3's list (what Netlogon writes to `netlogon.dns`), minus
/// the GC records (`_gc._tcp`, `_ldap._tcp.gc._msdcs`: the ping says this
/// DC is not a GC). Windows' DC locator asks for the `dc._msdcs` names (by
/// site first), the PDC name and the domain-GUID name; RFC 2782 clients
/// for the plain ones. Zone-relative names: `domain` and `forest` are DNS
/// names, `domain_guid` the GUID's text form, `site` the DC's site.
pub fn dc_records(domain: &str, forest: &str, domain_guid: &str, site: &str) -> Vec<DcRecord> {
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    let f = forest.trim_end_matches('.').to_ascii_lowercase();
    let g = domain_guid.trim().trim_start_matches('{').trim_end_matches('}').to_ascii_lowercase();
    // DNS names are case-insensitive (RFC 4343); publish the canonical
    // lower-case form, so a server that compares case-sensitively against
    // a lower-cased query still answers (MicroDNS, found by #87's e2e).
    let rec = |zone: &str, name: String, service| DcRecord { zone: zone.to_string(), name: name.to_ascii_lowercase(), service };
    vec![
        rec(&d, "_ldap._tcp".into(), Service::Ldap),
        rec(&d, format!("_ldap._tcp.{site}._sites"), Service::Ldap),
        rec(&d, "_ldap._tcp.dc._msdcs".into(), Service::Ldap),
        rec(&d, format!("_ldap._tcp.{site}._sites.dc._msdcs"), Service::Ldap),
        rec(&d, "_ldap._tcp.pdc._msdcs".into(), Service::Ldap),
        rec(&f, format!("_ldap._tcp.{g}.domains._msdcs"), Service::Ldap),
        rec(&d, KERBEROS_TCP_SRV_NAME.into(), Service::Kerberos),
        rec(&d, KERBEROS_UDP_SRV_NAME.into(), Service::Kerberos),
        rec(&d, format!("_kerberos._tcp.{site}._sites"), Service::Kerberos),
        rec(&d, "_kerberos._tcp.dc._msdcs".into(), Service::Kerberos),
        rec(&d, format!("_kerberos._tcp.{site}._sites.dc._msdcs"), Service::Kerberos),
        rec(&d, "_kpasswd._tcp".into(), Service::Kpasswd),
        rec(&d, "_kpasswd._udp".into(), Service::Kpasswd),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_root_domain_dc_registers_every_locator_name_in_its_zone() {
        let r = dc_records("Corp.Example.LO.", "corp.example.lo", "{0A7B31C0-099C-4443-8EFD-F20A6F72E9B2}", DEFAULT_SITE);
        assert_eq!(r.len(), 13);
        assert!(r.iter().all(|x| x.zone == "corp.example.lo"));
        let names: Vec<&str> = r.iter().map(|x| x.name.as_str()).collect();
        for want in [
            "_ldap._tcp.dc._msdcs",
            "_ldap._tcp.default-first-site-name._sites.dc._msdcs",
            "_ldap._tcp.pdc._msdcs",
            "_ldap._tcp.0a7b31c0-099c-4443-8efd-f20a6f72e9b2.domains._msdcs",
            "_kerberos._tcp.dc._msdcs",
            "_kpasswd._udp",
        ] {
            assert!(names.contains(&want), "{want} missing from {names:?}");
        }
        assert!(!names.iter().any(|n| n.contains("_gc") || n.contains("gc._msdcs")));
    }

    #[test]
    fn a_child_domain_puts_only_the_guid_record_in_the_forest_zone() {
        let r = dc_records("eu.corp.lo", "corp.lo", "00112233-4455-6677-8899-aabbccddeeff", DEFAULT_SITE);
        let forest: Vec<&DcRecord> = r.iter().filter(|x| x.zone == "corp.lo").collect();
        assert_eq!(forest.len(), 1);
        assert_eq!(forest[0].name, "_ldap._tcp.00112233-4455-6677-8899-aabbccddeeff.domains._msdcs");
        assert_eq!(r.iter().filter(|x| x.zone == "eu.corp.lo").count(), 12);
    }

    #[test]
    fn names_match_rfc_conventions() {
        assert_eq!(LDAP_SRV_NAME, "_ldap._tcp");
        assert_eq!(KERBEROS_UDP_SRV_NAME, "_kerberos._udp");
        assert_eq!(KERBEROS_TCP_SRV_NAME, "_kerberos._tcp");
    }
}
