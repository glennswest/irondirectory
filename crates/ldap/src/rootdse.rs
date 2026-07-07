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

pub fn build(registry: &PartitionRegistry) -> SearchResultEntry {
    let mut attrs = vec![
        attr("objectClass", ["top".to_string()]),
        attr("supportedLDAPVersion", ["3".to_string()]),
        attr("vendorName", ["irondirectory".to_string()]),
    ];

    let naming_contexts: Vec<String> = registry.iter().map(|p| p.base_dn.to_string()).collect();
    if !naming_contexts.is_empty() {
        attrs.push(attr("namingContexts", naming_contexts));
    }

    if let Some(domain) = single_domain_partition(registry) {
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
    }

    SearchResultEntry::new(String::new().into(), attrs)
}
