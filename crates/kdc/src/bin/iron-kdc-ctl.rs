//! iron-kdc-ctl: admin tool for provisioning Kerberos principals (#5).
//! Mirrors fastetcd-ctl/iron-ldapd's env-var configuration convention.
//!
//! Usage:
//!   iron-kdc-ctl set-password <principal> <password>
//!   iron-kdc-ctl export-keytab <principal> <output-file>
//!
//! <principal> is the primary/instance part only (no `@REALM` -- the
//! realm comes from IRON_KDC_REALM). `set-password` upserts: creates the
//! entry if it doesn't exist (DN `cn=<principal>,<base-dn>`), or updates
//! its keys in place if it does. Deriving Kerberos keys needs the FIPS
//! provider active (OPENSSL_CONF, see docs/FIPS.md) -- there is no other
//! way to set a principal's password.
//!
//! `export-keytab` hands a service principal's key to another daemon
//! (rocketsmbd's `cifs/<host>@REALM`, sshd's `host/<host>@REALM`, etc.)
//! as a keytab file -- writes every enctype currently stored for the
//! principal (#8), mirroring what a real KDC's `ktadd` does.
//!
//! Required env: IRON_KDC_FASTETCD_ENDPOINT, IRON_KDC_PARTITION_ID,
//! IRON_KDC_BASE_DN, IRON_KDC_REALM.

use iron_kdc::keytab::KeytabEntry;
use iron_partition::{ClusterRef, Dn, ForestId, Partition, PartitionRegistry};
use iron_store::model::Entry;
use iron_store::store::Store;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn require_env(name: &str) -> anyhow::Result<String> {
    env(name).ok_or_else(|| anyhow::anyhow!("{name} is required"))
}

async fn connect(base_dn_str: &str, pid: &str, endpoint: &str) -> anyhow::Result<(Store, Dn)> {
    let cluster = ClusterRef::plaintext([endpoint.to_string()]);
    let forest = ForestId::new(pid.to_string())?;
    let base_dn = Dn::parse(base_dn_str)?;
    let partition = Partition::domain(pid.to_string(), forest, base_dn.clone(), cluster)?;
    let mut registry = PartitionRegistry::new();
    registry.insert(partition)?;
    let store = Store::connect(registry).await?;
    Ok((store, base_dn))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let (Some(cmd), Some(principal), Some(third)) = (args.get(1), args.get(2), args.get(3)) else {
        anyhow::bail!("usage: iron-kdc-ctl <set-password|export-keytab> <principal> <password|output-file>");
    };

    let endpoint = require_env("IRON_KDC_FASTETCD_ENDPOINT")?;
    let pid = require_env("IRON_KDC_PARTITION_ID")?;
    let base_dn_str = require_env("IRON_KDC_BASE_DN")?;
    let realm = require_env("IRON_KDC_REALM")?;
    let principal_fqn = format!("{principal}@{realm}");

    match cmd.as_str() {
        "set-password" => {
            let password = third;
            let (mut store, base_dn) = connect(&base_dn_str, &pid, &endpoint).await?;
            let fips = iron_crypto::FipsContext::new()?;
            let index_spec = iron_kdc::index_spec();

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
                    let entry =
                        store.get_entry(dn).await?.ok_or_else(|| anyhow::anyhow!("index points at {dn} but the entry is missing"))?;
                    (dn.clone(), entry)
                }
                multiple => anyhow::bail!("principal {principal_fqn} is not unique: {} entries found", multiple.len()),
            };

            iron_kdc::principal::set_password(&fips, &mut entry, &principal_fqn, password.as_bytes())?;
            store.put_entry(&dn, &entry, &index_spec).await?;

            println!("set password for {principal_fqn} (dn: {dn})");
        }
        "export-keytab" => {
            let output_path = third;
            let (mut store, base_dn) = connect(&base_dn_str, &pid, &endpoint).await?;

            let existing = store.lookup_by_index(&base_dn, iron_kdc::principal::ATTR_PRINCIPAL_NAME, &principal_fqn).await?;
            let dn = match existing.as_slice() {
                [] => anyhow::bail!("no such principal: {principal_fqn}"),
                [dn] => dn.clone(),
                multiple => anyhow::bail!("principal {principal_fqn} is not unique: {} entries found", multiple.len()),
            };
            let entry = store.get_entry(&dn).await?.ok_or_else(|| anyhow::anyhow!("index points at {dn} but the entry is missing"))?;
            let keys = iron_kdc::principal::keys(&entry)?;
            if keys.is_empty() {
                anyhow::bail!("{principal_fqn} has no stored keys (set-password it first)");
            }

            let components: Vec<String> =
                iron_kdc::string_to_principal_name(principal).string.iter().map(iron_kdc::gstring_to_string).collect();
            let name_type = if components.len() > 1 { 2 } else { 1 };
            let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as u32).unwrap_or(0);

            let entries: Vec<KeytabEntry> = keys
                .into_iter()
                .map(|k| KeytabEntry {
                    realm: realm.clone(),
                    components: components.clone(),
                    name_type,
                    timestamp,
                    kvno: k.kvno,
                    enctype: k.enctype,
                    key: k.key,
                })
                .collect();

            let mut file = std::fs::File::create(output_path)?;
            iron_kdc::keytab::write(&mut file, &entries)?;

            println!("wrote {} key(s) for {principal_fqn} to {output_path}", entries.len());
        }
        other => anyhow::bail!("unknown command {other:?}; expected set-password or export-keytab"),
    }

    Ok(())
}
