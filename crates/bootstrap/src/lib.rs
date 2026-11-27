//! iron-bootstrap: idempotent first-boot provisioning of a new domain (#25).
//!
//! irondirectory-operator runs this as a container beside fastetcd,
//! iron-ldapd and iron-kdcd in every member pod of a `Directory`. It waits
//! for fastetcd, then creates whatever a new domain needs and is missing:
//!
//! 1. the forest registry (what `iron-config-ctl init-forest` writes): a
//!    configuration partition `<pid>-config` at `cn=configuration,<base>`, a
//!    schema partition `<pid>-schema` under it, and the root domain `<pid>`
//!    with its realm, NetBIOS name and a freshly generated domain SID and
//!    domain GUID (#52);
//! 2. the domain's base entry (`objectSid` = the domain SID);
//! 3. `krbtgt/<REALM>`, with a random key (RID 502);
//! 4. `cn=administrator,<base>` (RID 500), whose `userPassword` (PBKDF2, for
//!    LDAP simple bind) and Kerberos keys both come from the admin password
//!    file;
//! 5. for each name in `IRON_BOOTSTRAP_SERVICE_HOSTS` (#43), the service
//!    principals `ldap/<name>@<REALM>` (what a GSSAPI LDAP bind asks the KDC
//!    for, and whose key iron-ldapd's acceptor reads from the store) and
//!    `host/<name>@<REALM>`, each with a random key, at
//!    `cn=ldap.<name>,<base>` / `cn=host.<name>,<base>` -- the DN
//!    `iron-kdc-ctl set-password` gives them. A principal that already exists
//!    under any DN is left alone.
//!
//! Every write is create-only: one etcd transaction guarded on the key not
//! existing yet ([`iron_store::store::Store::create_entry`]). Nothing that
//! exists is ever rewritten, so a restart or golden swap does nothing, and
//! members of one directory provisioning it at the same time agree on one
//! domain SID instead of the last writer winning. Two members may both
//! derive keys for the administrator, but only one entry is stored.
//!
//! The one exception to "never rewrites": a root-domain record that exists
//! but predates a field (no domain SID, GUID or NetBIOS name) gets that field
//! filled in. A realm or base DN that disagrees with the stored record is an
//! error, not something to overwrite.

use std::time::Duration;

use anyhow::{bail, Context};
use iron_partition::{security_descriptor, ClusterRef, Dn, ForestId, Partition, PartitionId, PartitionRegistry, Sid};
use iron_store::binary_attrs::{encode_binary_attr, NT_SECURITY_DESCRIPTOR_ATTR, OBJECT_SID_ATTR};
use iron_store::model::Entry;
use iron_store::store::Store;

/// The well-known RIDs AD gives these two accounts (MS-DTYP §2.4.2.4).
pub const ADMINISTRATOR_RID: u32 = 500;
pub const KRBTGT_RID: u32 = 502;

/// The administrator's account name: `cn=administrator,<base>` and
/// `administrator@<REALM>`.
pub const ADMINISTRATOR: &str = "administrator";

/// What `iron-bootstrap` is asked to provision, from its environment.
#[derive(Debug, Clone)]
pub struct Settings {
    pub endpoint: String,
    /// mTLS to fastetcd (#26): `IRON_BOOTSTRAP_FASTETCD_CA`/`_CERT`/`_KEY`.
    /// Persisted with the partitions it creates, so every daemon that loads
    /// the forest registry reaches them the same way.
    pub tls: Option<iron_partition::TlsRef>,
    pub partition_id: String,
    pub base_dn: Dn,
    pub realm: String,
    pub netbios_name: String,
    pub admin_password: Vec<u8>,
    /// Host names to create `ldap/` and `host/` service principals for
    /// (`IRON_BOOTSTRAP_SERVICE_HOSTS`, comma-separated; see [`service_hosts`]).
    pub service_hosts: Vec<String>,
}

/// The service classes bootstrap creates a principal of for each host.
pub const SERVICE_CLASSES: [&str; 2] = ["ldap", "host"];

/// Parses `IRON_BOOTSTRAP_SERVICE_HOSTS`: comma-separated host names,
/// trimmed, lower-cased (Kerberos host-based names are compared exactly, and
/// clients lower-case the host part), one trailing dot dropped, duplicates
/// dropped. A name must be DNS-shaped (letters, digits, `-`, dot-separated
/// non-empty labels) -- an IP literal like `127.0.0.1` is too; anything else
/// (a `/`, `@`, `,`, space, empty label) is refused rather than turned into
/// a principal no client would ask for.
pub fn service_hosts(raw: &str) -> anyhow::Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for part in raw.split(',') {
        let mut name = part.trim().to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        if name.ends_with('.') {
            name.pop();
        }
        let ok = name.len() <= 253
            && name.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
        if !ok {
            bail!("IRON_BOOTSTRAP_SERVICE_HOSTS: {:?} is not a host name", part.trim());
        }
        if !out.contains(&name) {
            out.push(name);
        }
    }
    Ok(out)
}

impl Settings {
    /// The cluster these settings reach.
    pub fn cluster(&self) -> ClusterRef {
        ClusterRef { endpoints: self.endpoint.split(',').map(|e| e.trim().to_string()).filter(|e| !e.is_empty()).collect(), tls: self.tls.clone() }
    }

    /// Reads the `IRON_BOOTSTRAP_*` environment (see `docs/CONFIGURATION.md`)
    /// and the admin password file it names.
    pub fn from_env() -> anyhow::Result<Self> {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty()).with_context(|| format!("{name} is required"));
        let password_file = var("IRON_BOOTSTRAP_ADMIN_PASSWORD_FILE")?;
        let raw = std::fs::read(&password_file).with_context(|| format!("reading the admin password file {password_file}"))?;
        let base_dn = var("IRON_BOOTSTRAP_BASE_DN")?;
        let endpoint = var("IRON_BOOTSTRAP_FASTETCD_ENDPOINT")?;
        let tls = iron_store::cluster_from_env(&endpoint, "IRON_BOOTSTRAP_FASTETCD")?.tls;
        Ok(Settings {
            endpoint,
            tls,
            partition_id: var("IRON_BOOTSTRAP_PARTITION_ID")?,
            base_dn: Dn::parse(&base_dn).with_context(|| format!("IRON_BOOTSTRAP_BASE_DN {base_dn:?}"))?,
            realm: var("IRON_BOOTSTRAP_REALM")?.to_ascii_uppercase(),
            netbios_name: var("IRON_BOOTSTRAP_NETBIOS_NAME")?.to_ascii_uppercase(),
            admin_password: password_from_file(&raw)?,
            service_hosts: service_hosts(&std::env::var("IRON_BOOTSTRAP_SERVICE_HOSTS").unwrap_or_default())?,
        })
    }

    pub fn config_partition_id(&self) -> String {
        format!("{}-config", self.partition_id)
    }

    pub fn schema_partition_id(&self) -> String {
        format!("{}-schema", self.partition_id)
    }

    pub fn config_dn(&self) -> anyhow::Result<Dn> {
        Ok(Dn::parse(&format!("cn=configuration,{}", self.base_dn))?)
    }

    pub fn admin_dn(&self) -> anyhow::Result<Dn> {
        Ok(Dn::parse(&format!("cn={ADMINISTRATOR},{}", self.base_dn))?)
    }

    pub fn krbtgt_dn(&self) -> anyhow::Result<Dn> {
        Ok(Dn::parse(&format!("cn=krbtgt,{}", self.base_dn))?)
    }

    /// `ldap/<host>` -> `cn=ldap.<host>,<base>`, as `iron-kdc-ctl
    /// set-password` names a principal it creates.
    pub fn service_dn(&self, service: &str, host: &str) -> anyhow::Result<Dn> {
        Ok(Dn::parse(&format!("cn={service}.{host},{}", self.base_dn))?)
    }
}

/// The password in a mounted Secret key: the file's bytes, less trailing
/// line endings (`echo pw > file` and `kubectl create secret --from-file`
/// both tend to leave one). The FIPS provider's PBKDF2 refuses passwords
/// under 8 bytes, so a shorter one is rejected here with the reason.
pub fn password_from_file(raw: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut end = raw.len();
    while end > 0 && matches!(raw[end - 1], b'\n' | b'\r') {
        end -= 1;
    }
    let pw = &raw[..end];
    if pw.len() < 8 {
        bail!("the admin password is {} bytes; the FIPS provider needs at least 8", pw.len());
    }
    Ok(pw.to_vec())
}

/// What one run did: the names of what it created, in order. Empty on an
/// already-provisioned store.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    pub created: Vec<String>,
    pub domain_sid: String,
    pub domain_guid: String,
}

/// Connects to fastetcd, retrying every `retry` until a `Status` round trip
/// succeeds. Never gives up: in a pod, fastetcd starts beside this and a
/// new Raft set can take a while to elect a leader.
pub async fn wait_for_store(s: &Settings, retry: Duration) -> anyhow::Result<Store> {
    let mut attempt = 0u64;
    loop {
        attempt += 1;
        match connect(s).await {
            Ok(mut store) => match store.ping().await {
                Ok(()) => return Ok(store),
                Err(e) => tracing::info!(attempt, error = %e, endpoint = %s.endpoint, "fastetcd not ready yet"),
            },
            Err(e) => tracing::info!(attempt, error = %e, endpoint = %s.endpoint, "fastetcd not reachable yet"),
        }
        tokio::time::sleep(retry).await;
    }
}

async fn connect(s: &Settings) -> anyhow::Result<Store> {
    let cluster = s.cluster();
    let forest = ForestId::new(s.partition_id.clone())?;
    let mut registry = PartitionRegistry::new();
    registry.insert(Partition::configuration(s.config_partition_id(), forest.clone(), s.config_dn()?, cluster.clone())?)?;
    registry.insert(Partition::domain(s.partition_id.clone(), forest, s.base_dn.clone(), cluster)?)?;
    Ok(Store::connect(registry).await?)
}

/// Creates whatever of the domain is missing (see the module docs).
pub async fn provision(store: &mut Store, s: &Settings) -> anyhow::Result<Report> {
    let mut report = Report::default();
    let fips = iron_crypto::FipsContext::new().context("the FIPS provider is not active (set OPENSSL_CONF)")?;
    let config_dn = s.config_dn()?;
    let config_spec = iron_config::index_spec();
    let cluster = s.cluster();
    let forest = ForestId::new(s.partition_id.clone())?;

    // 1. The forest registry.
    let config = Partition::configuration(s.config_partition_id(), forest.clone(), config_dn.clone(), cluster.clone())?;
    let schema_dn = Dn::parse(&format!("cn=schema,{config_dn}"))?;
    let schema = Partition::schema(s.schema_partition_id(), forest.clone(), schema_dn, cluster.clone())?;
    let root = Partition::domain(s.partition_id.clone(), forest, s.base_dn.clone(), cluster)?
        .with_realm(s.realm.clone())
        .with_netbios_name(s.netbios_name.clone())
        .with_domain_sid(iron_config::generate_domain_sid()?)
        .with_domain_guid(iron_config::generate_domain_guid()?);
    for p in [&config, &schema, &root] {
        if iron_config::create_partition(store, &config_dn, &config_spec, p).await? {
            report.created.push(format!("partition {}", p.id.as_str()));
        }
    }

    let registry = iron_config::load_registry(store, &config_dn).await?;
    let pid = PartitionId::new(s.partition_id.clone())?;
    let stored = registry.get(&pid).context("the root domain's record is missing right after creating it")?.clone();
    check_matches(&stored, s)?;
    let mut filled = stored.clone();
    if filled.domain_sid.is_none() {
        filled = filled.with_domain_sid(iron_config::generate_domain_sid()?);
    }
    if filled.domain_guid.is_none() {
        filled = filled.with_domain_guid(iron_config::generate_domain_guid()?);
    }
    if filled.netbios_name.is_none() {
        filled = filled.with_netbios_name(s.netbios_name.clone());
    }
    if filled != stored {
        iron_config::put_partition(store, &config_dn, &config_spec, &filled).await?;
        report.created.push(format!("partition {} (missing fields filled)", pid.as_str()));
    }
    let domain_sid_str = filled.domain_sid.clone().unwrap_or_default();
    let domain_sid = Sid::parse(&domain_sid_str).with_context(|| format!("stored domain SID {domain_sid_str:?} does not parse"))?;
    report.domain_sid = domain_sid_str;
    report.domain_guid = filled.domain_guid.clone().unwrap_or_default();

    // 2-4. The entries, all indexed the way iron-kdc looks them up.
    let spec = iron_kdc::index_spec();
    if store.create_entry(&s.base_dn, &base_entry(&s.base_dn, &domain_sid), &spec).await? {
        report.created.push(s.base_dn.to_string());
    }

    let krbtgt = format!("krbtgt/{}@{}", s.realm, s.realm);
    if !principal_exists(store, s, &krbtgt).await? {
        let secret: String = iron_crypto::kerberos::random_bytes(&fips, 32)?.iter().map(|b| format!("{b:02x}")).collect();
        let mut entry = account_entry("krbtgt", &domain_sid, KRBTGT_RID);
        iron_kdc::principal::set_password(&fips, &mut entry, &krbtgt, secret.as_bytes())?;
        if store.create_entry(&s.krbtgt_dn()?, &entry, &spec).await? {
            report.created.push(krbtgt);
        }
    }

    let admin = format!("{ADMINISTRATOR}@{}", s.realm);
    let admin_dn = s.admin_dn()?;
    if !principal_exists(store, s, &admin).await? && store.get_entry(&admin_dn).await?.is_none() {
        let mut entry = account_entry(ADMINISTRATOR, &domain_sid, ADMINISTRATOR_RID);
        entry.set("uid", [ADMINISTRATOR.to_string()]);
        entry.set("userpassword", [iron_crypto::pbkdf2::hash_password(&fips, &s.admin_password)?]);
        iron_kdc::principal::set_password(&fips, &mut entry, &admin, &s.admin_password)?;
        if store.create_entry(&admin_dn, &entry, &spec).await? {
            report.created.push(admin);
        }
    }

    // 5. Service principals (#43).
    for host in &s.service_hosts {
        for service in SERVICE_CLASSES {
            let principal = format!("{service}/{host}@{}", s.realm);
            if principal_exists(store, s, &principal).await? {
                continue;
            }
            let dn = s.service_dn(service, host)?;
            let mut entry = service_entry(service, host);
            let secret: String = iron_crypto::kerberos::random_bytes(&fips, 32)?.iter().map(|b| format!("{b:02x}")).collect();
            iron_kdc::principal::set_password(&fips, &mut entry, &principal, secret.as_bytes())?;
            if store.create_entry(&dn, &entry, &spec).await? {
                report.created.push(principal);
            }
        }
    }

    Ok(report)
}

/// A stored root-domain record that names a different realm or base DN
/// than this pod was given is a misconfiguration to report, not something
/// to rewrite.
fn check_matches(stored: &Partition, s: &Settings) -> anyhow::Result<()> {
    if stored.base_dn != s.base_dn {
        bail!("partition {} is stored with base DN {}, not {}", s.partition_id, stored.base_dn, s.base_dn);
    }
    if stored.realm.as_deref() != Some(s.realm.as_str()) {
        bail!("partition {} is stored with realm {:?}, not {}", s.partition_id, stored.realm, s.realm);
    }
    Ok(())
}

async fn principal_exists(store: &mut Store, s: &Settings, principal: &str) -> anyhow::Result<bool> {
    Ok(!store.lookup_by_index(&s.base_dn, iron_kdc::principal::ATTR_PRINCIPAL_NAME, principal).await?.is_empty())
}

/// The domain object itself: AD's `domainDNS`, carrying the domain SID.
pub fn base_entry(base_dn: &Dn, domain_sid: &Sid) -> Entry {
    let mut e = Entry::new();
    e.set("objectclass", ["top", "domain", "domainDNS"]);
    if let Some(dc) = base_dn.rdns().first().and_then(|r| r.avas().first()).filter(|a| a.attr().eq_ignore_ascii_case("dc")) {
        e.set("dc", [dc.value().to_string()]);
    }
    e.set(OBJECT_SID_ATTR, [encode_binary_attr(&domain_sid.encode())]);
    e
}

/// A service principal's entry, the shape `iron-kdc-ctl set-password`
/// creates (keys added by the caller). No `objectSid`: nothing logs on as
/// it, so no PAC is ever built for it.
pub fn service_entry(service: &str, host: &str) -> Entry {
    let mut e = Entry::new();
    e.set("objectclass", ["top"]);
    e.set("cn", [format!("{service}.{host}")]);
    e
}

/// A user account with a well-known RID: `objectSid` and the default
/// `nTSecurityDescriptor`, as iron-ldap stamps on an added user (#17), but
/// with the fixed RID instead of one from the pool (which starts at 1000).
pub fn account_entry(name: &str, domain_sid: &Sid, rid: u32) -> Entry {
    let mut e = Entry::new();
    e.set("objectclass", ["top", "person", "organizationalPerson", "user"]);
    e.set("cn", [name.to_string()]);
    e.set("samaccountname", [name.to_string()]);
    e.set(OBJECT_SID_ATTR, [encode_binary_attr(&domain_sid.with_sub_authority(rid).encode())]);
    e.set(NT_SECURITY_DESCRIPTOR_ATTR, [encode_binary_attr(&security_descriptor::default_descriptor(domain_sid))]);
    e
}

#[cfg(test)]
mod tests {
    use super::*;
    use iron_store::binary_attrs::decode_binary_attr;

    fn sid() -> Sid {
        Sid::parse("S-1-5-21-1-2-3").unwrap()
    }

    #[test]
    fn password_file_trailing_newlines_are_dropped() {
        assert_eq!(password_from_file(b"TestPass123!\n").unwrap(), b"TestPass123!");
        assert_eq!(password_from_file(b"TestPass123!\r\n").unwrap(), b"TestPass123!");
        assert_eq!(password_from_file(b"TestPass123!").unwrap(), b"TestPass123!");
    }

    #[test]
    fn password_file_keeps_inner_and_leading_whitespace() {
        assert_eq!(password_from_file(b" pass word\n").unwrap(), b" pass word");
    }

    #[test]
    fn short_password_is_refused_with_the_reason() {
        let e = password_from_file(b"short\n").unwrap_err().to_string();
        assert!(e.contains("at least 8"), "{e}");
    }

    #[test]
    fn service_hosts_are_normalized() {
        assert_eq!(service_hosts("").unwrap(), Vec::<String>::new());
        assert_eq!(
            service_hosts(" Dir.NS.svc , ldap.Example.LO., dir.ns.svc,,127.0.0.1").unwrap(),
            ["dir.ns.svc", "ldap.example.lo", "127.0.0.1"]
        );
    }

    #[test]
    fn service_hosts_refuses_what_is_not_a_host_name() {
        for bad in ["ldap/dir", "dir@REALM", "a b", "a..b", ".a", "a_b"] {
            let e = service_hosts(bad).unwrap_err().to_string();
            assert!(e.contains("not a host name"), "{bad}: {e}");
        }
    }

    #[test]
    fn service_entry_matches_kdc_ctl() {
        let e = service_entry("ldap", "dir.ns.svc");
        assert_eq!(e.get("cn").unwrap()[0], "ldap.dir.ns.svc");
        assert!(e.get(OBJECT_SID_ATTR).is_none());
    }

    #[test]
    fn account_gets_the_well_known_rid() {
        let e = account_entry(ADMINISTRATOR, &sid(), ADMINISTRATOR_RID);
        let raw = decode_binary_attr(&e.get(OBJECT_SID_ATTR).unwrap()[0]);
        assert_eq!(Sid::decode(&raw).unwrap().to_string(), "S-1-5-21-1-2-3-500");
        assert!(e.get(NT_SECURITY_DESCRIPTOR_ATTR).is_some());
        assert_eq!(e.get("cn").unwrap()[0], "administrator");
    }

    #[test]
    fn base_entry_carries_dc_and_the_domain_sid() {
        let e = base_entry(&Dn::parse("dc=corp,dc=example,dc=lo").unwrap(), &sid());
        assert_eq!(e.get("dc").unwrap()[0], "corp");
        let raw = decode_binary_attr(&e.get(OBJECT_SID_ATTR).unwrap()[0]);
        assert_eq!(Sid::decode(&raw).unwrap(), sid());
    }

    #[test]
    fn layout_hangs_off_the_base_dn() {
        let s = Settings {
            endpoint: "http://127.0.0.1:2379".into(),
            tls: None,
            partition_id: "corp".into(),
            base_dn: Dn::parse("dc=corp,dc=example,dc=lo").unwrap(),
            realm: "CORP.EXAMPLE.LO".into(),
            netbios_name: "CORP".into(),
            admin_password: b"TestPass123!".to_vec(),
            service_hosts: vec!["dir.ns.svc".into()],
        };
        assert_eq!(s.service_dn("ldap", "dir.ns.svc").unwrap().to_string(), "cn=ldap.dir.ns.svc,dc=corp,dc=example,dc=lo");
        assert_eq!(s.config_dn().unwrap().to_string(), "cn=configuration,dc=corp,dc=example,dc=lo");
        assert_eq!(s.admin_dn().unwrap().to_string(), "cn=administrator,dc=corp,dc=example,dc=lo");
        assert_eq!(s.config_partition_id(), "corp-config");
        assert_eq!(s.schema_partition_id(), "corp-schema");
    }
}
