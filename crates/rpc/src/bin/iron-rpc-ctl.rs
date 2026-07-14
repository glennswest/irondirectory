//! iron-rpc-ctl: admin tool for provisioning what `iron-rpcd` needs
//! beyond what SAMR/LSARPC/NETLOGON themselves can set up (#19).
//!
//! Usage:
//!   iron-rpc-ctl set-computer-secret <account-name> <secret>
//!
//! `SamrSetInformationUser2` (real password-setting) needs an
//! authenticated RPC bind's session key to decrypt the wire-encrypted
//! password material, which this pass doesn't implement (see the
//! `iron_rpc` crate docs) -- so a computer account created via
//! `SamrCreateUser2InDomain` has no NTOWF for `NetrServerAuthenticate3`
//! to authenticate against. This command sets one directly, standing in
//! for that missing step until real SAMR password-setting exists.
//!
//! Required env: IRON_RPC_FASTETCD_ENDPOINT, IRON_RPC_PARTITION_ID,
//! IRON_RPC_BASE_DN (matching `iron-rpcd`'s own contract).

use iron_partition::{ClusterRef, Dn, ForestId, Partition, PartitionRegistry};
use iron_rpc::netlogon::NTOWF_ATTR;
use iron_store::index::IndexSpec;
use iron_store::store::Store;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}
fn require_env(name: &str) -> anyhow::Result<String> {
    env(name).ok_or_else(|| anyhow::anyhow!("{name} is required"))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let (Some(cmd), Some(account_name), Some(secret)) = (args.get(1), args.get(2), args.get(3)) else {
        anyhow::bail!("usage: iron-rpc-ctl set-computer-secret <account-name> <secret>");
    };
    if cmd != "set-computer-secret" {
        anyhow::bail!("unknown command {cmd:?}; expected set-computer-secret");
    }

    let endpoint = require_env("IRON_RPC_FASTETCD_ENDPOINT")?;
    let pid = require_env("IRON_RPC_PARTITION_ID")?;
    let base_dn_str = require_env("IRON_RPC_BASE_DN")?;

    let cluster = ClusterRef::plaintext([endpoint]);
    let forest = ForestId::new(pid.clone())?;
    let base_dn = Dn::parse(&base_dn_str)?;
    let partition = Partition::domain(pid, forest, base_dn.clone(), cluster)?;
    let mut registry = PartitionRegistry::new();
    registry.insert(partition)?;
    let mut store = Store::connect(registry).await?;

    let existing = store.lookup_by_index(&base_dn, "cn", account_name).await?;
    let dn = match existing.as_slice() {
        [] => anyhow::bail!("no such computer account: {account_name} (create it via SamrCreateUser2InDomain first)"),
        [dn] => dn.clone(),
        multiple => anyhow::bail!("account {account_name} is not unique: {} entries found", multiple.len()),
    };
    let mut entry = store.get_entry(&dn).await?.ok_or_else(|| anyhow::anyhow!("index points at {dn} but the entry is missing"))?;

    let ntowf = iron_crypto::md4::ntowf(secret);
    entry.set(NTOWF_ATTR, [hex_encode(&ntowf)]);
    store.put_entry(&dn, &entry, &IndexSpec::new(["cn", "member"])).await?;

    println!("set NETLOGON secret for {account_name} (dn: {dn})");
    Ok(())
}
