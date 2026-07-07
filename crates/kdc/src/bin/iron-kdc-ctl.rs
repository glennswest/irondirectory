//! iron-kdc-ctl: admin tool for provisioning Kerberos principals (#5).
//! Mirrors fastetcd-ctl/iron-ldapd's env-var configuration convention.
//!
//! Usage:
//!   iron-kdc-ctl set-password <principal> <password>
//!
//! <principal> is the primary/instance part only (no `@REALM` -- the
//! realm comes from IRON_KDC_REALM). Upserts: creates the entry if it
//! doesn't exist (DN `cn=<principal>,<base-dn>`), or updates its keys in
//! place if it does. Deriving Kerberos keys needs the FIPS provider
//! active (OPENSSL_CONF, see docs/FIPS.md) -- there is no other way to
//! set a principal's password.
//!
//! Required env: IRON_KDC_FASTETCD_ENDPOINT, IRON_KDC_PARTITION_ID,
//! IRON_KDC_BASE_DN, IRON_KDC_REALM.

use iron_partition::{ClusterRef, Dn, ForestId, Partition, PartitionRegistry};
use iron_store::model::Entry;
use iron_store::store::Store;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn require_env(name: &str) -> anyhow::Result<String> {
    env(name).ok_or_else(|| anyhow::anyhow!("{name} is required"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let (Some(cmd), Some(principal), Some(password)) = (args.get(1), args.get(2), args.get(3)) else {
        anyhow::bail!("usage: iron-kdc-ctl set-password <principal> <password>");
    };
    if cmd != "set-password" {
        anyhow::bail!("unknown command {cmd:?}; only set-password is implemented");
    }

    let endpoint = require_env("IRON_KDC_FASTETCD_ENDPOINT")?;
    let pid = require_env("IRON_KDC_PARTITION_ID")?;
    let base_dn_str = require_env("IRON_KDC_BASE_DN")?;
    let realm = require_env("IRON_KDC_REALM")?;

    let cluster = ClusterRef::plaintext([endpoint]);
    let forest = ForestId::new(pid.clone())?;
    let base_dn = Dn::parse(&base_dn_str)?;
    let partition = Partition::domain(pid, forest, base_dn.clone(), cluster)?;
    let mut registry = PartitionRegistry::new();
    registry.insert(partition)?;

    let mut store = Store::connect(registry).await?;
    let fips = iron_crypto::FipsContext::new()?;
    let index_spec = iron_kdc::index_spec();

    let principal_fqn = format!("{principal}@{realm}");
    let existing = store.lookup_by_index(&base_dn, iron_kdc::principal::ATTR_PRINCIPAL_NAME, &principal_fqn).await?;

    let (dn, mut entry) = match existing.as_slice() {
        [] => {
            let cn_value = principal.replace('/', ".");
            let dn = Dn::parse(&format!("cn={cn_value},{base_dn_str}"))?;
            let mut entry = Entry::new();
            entry.set("objectclass", ["top".to_string()]);
            entry.set("cn", [cn_value]);
            (dn, entry)
        }
        [dn] => {
            let entry = store.get_entry(dn).await?.ok_or_else(|| anyhow::anyhow!("index points at {dn} but the entry is missing"))?;
            (dn.clone(), entry)
        }
        multiple => anyhow::bail!("principal {principal_fqn} is not unique: {} entries found", multiple.len()),
    };

    iron_kdc::principal::set_password(&fips, &mut entry, &principal_fqn, password.as_bytes())?;
    store.put_entry(&dn, &entry, &index_spec).await?;

    println!("set password for {principal_fqn} (dn: {dn})");
    Ok(())
}
