//! Synthesizes the rootDSE entry (RFC 4512 §5.1) from the PartitionRegistry:
//! `namingContexts` lists every partition's base DN. Also exposes the
//! AD-shaped rootDSE attributes (#4's acceptance criteria) --
//! `defaultNamingContext`, `configurationNamingContext`,
//! `schemaNamingContext`, `rootDomainNamingContext` -- when the registry
//! has enough partitions to derive them (a single-domain-partition
//! deployment, the only kind provisioned so far, only yields
//! `defaultNamingContext`; config/schema partitions and multi-domain
//! forests are tracked by separate roadmap issues, e.g. #9's child-domain
//! provisioning and #17's MS schema objects).

use iron_partition::{Partition, PartitionKind, PartitionRegistry};
use rasn::types::SetOf;
use rasn_ldap::{PartialAttribute, SearchResultEntry};

fn attr(name: &str, values: impl IntoIterator<Item = String>) -> PartialAttribute {
    PartialAttribute::new(
        name.into(),
        SetOf::from_vec(values.into_iter().map(|v| v.into_bytes().into()).collect()),
    )
}

/// The registry's one `Domain`-kind partition, if there's exactly one.
/// Ambiguous with more than one (which domain is "default" isn't
/// decidable from the registry alone yet) or none.
fn single_domain_partition(registry: &PartitionRegistry) -> Option<&Partition> {
    let mut it = registry.iter().filter(|p| p.kind == PartitionKind::Domain);
    let first = it.next()?;
    match it.next() {
        None => Some(first),
        Some(_) => None,
    }
}

pub fn build(registry: &PartitionRegistry, fips_active: bool) -> SearchResultEntry {
    let mut attrs = vec![
        attr("objectClass", ["top".to_string()]),
        attr("supportedLDAPVersion", ["3".to_string()]),
        attr("vendorName", ["irondirectory".to_string()]),
    ];

    // Found live testing macOS's dsconfigad against a real client (#20):
    // it reads rootDSE's supportedSASLMechanisms up front to decide how
    // to authenticate, and gives up the whole join silently if the
    // attribute is absent -- even though GSSAPI bind (#7) was already
    // implemented and working, nothing ever advertised it here. Only
    // claim it when the FIPS provider backing GSSAPI/Kerberos crypto is
    // actually active (session.rs's handle_sasl_bind fails the bind
    // outright otherwise) -- match capability, don't just claim one.
    if fips_active {
        // TEMPORARY test-only addition of GSS-SPNEGO (#20 diagnostic):
        // NOT actually implemented server-side yet -- checking whether
        // macOS's dsconfigad specifically requires seeing this exact
        // mechanism name advertised (matching real Windows AD, which
        // lists GSSAPI/GSS-SPNEGO/EXTERNAL/DIGEST-MD5) before it will
        // even attempt a bind, independent of whether the bind itself
        // would succeed.
        attrs.push(attr("supportedSASLMechanisms", ["GSSAPI".to_string(), "GSS-SPNEGO".to_string()]));
    }

    let naming_contexts: Vec<String> = registry.iter().map(|p| p.base_dn.to_string()).collect();
    if !naming_contexts.is_empty() {
        attrs.push(attr("namingContexts", naming_contexts));
    }

    if let Some(domain) = single_domain_partition(registry) {
        // LDAP_CAP_ACTIVE_DIRECTORY_OID (MS-ADTS 3.1.1.3.2.24) -- a
        // real Windows AD DC always advertises this, and AD-aware
        // clients (macOS's dsconfigad among them, found live in #20)
        // check for it up front to decide whether to treat the target
        // as Active Directory at all, independent of anything it
        // explicitly asked for in the search's attribute list.
        attrs.push(attr("supportedCapabilities", ["1.2.840.113556.1.4.800".to_string()]));
        attrs.push(attr("defaultNamingContext", [domain.base_dn.to_string()]));
        if let Some(cfg) = registry.config_partition(&domain.forest) {
            attrs.push(attr("configurationNamingContext", [cfg.base_dn.to_string()]));
        }
        if let Some(schema) = registry.schema_partition(&domain.forest) {
            attrs.push(attr("schemaNamingContext", [schema.base_dn.to_string()]));
        }
        if let Some(root) = registry.root_domain_partition(&domain.forest) {
            attrs.push(attr("rootDomainNamingContext", [root.base_dn.to_string()]));
        }

        // TEMPORARY diagnostic batch (#20): matching a real Windows
        // Server 2025 AD DC's rootDSE as closely as possible, to
        // isolate which of these (if any) macOS's dsconfigad actually
        // requires before it will proceed past the initial rootDSE
        // read -- not yet confirmed which of these matter, or whether
        // any do. Functional-level values are placeholders for this
        // experiment, not a claim of real feature support.
        attrs.push(attr("domainFunctionality", ["7".to_string()]));
        attrs.push(attr("forestFunctionality", ["7".to_string()]));
        attrs.push(attr("domainControllerFunctionality", ["10".to_string()]));
        attrs.push(attr("isSynchronized", ["TRUE".to_string()]));
        attrs.push(attr("highestCommittedUSN", ["1".to_string()]));
        if let Some(realm) = &domain.realm {
            attrs.push(attr("dnsHostName", [format!("iron-ldapd.{}", realm.to_ascii_lowercase())]));
            attrs.push(attr("ldapServiceName", [format!("{}:iron-ldapd@{realm}", realm.to_ascii_lowercase())]));
            attrs.push(attr("serverName", [format!("cn=iron-ldapd,{}", domain.base_dn)]));
            attrs.push(attr("dsServiceName", [format!("cn=iron-ldapd,{}", domain.base_dn)]));
        }
        if let Some(schema) = registry.schema_partition(&domain.forest) {
            attrs.push(attr("subschemaSubentry", [format!("cn=aggregate,{}", schema.base_dn)]));
        }
    }

    SearchResultEntry::new(String::new().into(), attrs)
}
