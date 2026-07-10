//! iron-config-ctl: forest bootstrap + child-domain provisioning (#9, #10).
//!
//! Usage:
//!   iron-config-ctl init-forest <forest-id> <config-id> <config-base-dn> <root-domain-id> <root-base-dn> [realm]
//!   iron-config-ctl create-child <parent-id> <new-id> <new-base-dn> [realm]
//!   iron-config-ctl set-ldap-url <partition-id> <ldap-url>
//!   iron-config-ctl show
//!
//! `init-forest` bootstraps a brand-new forest: creates the configuration
//! partition (self-describing -- it writes its own record into its own
//! DIT, matching AD's Configuration NC hosting its own crossRef objects)
//! and the forest's root domain partition, both on the same fastetcd
//! cluster (`IRON_CONFIG_FASTETCD_ENDPOINT`) -- happy path only (D10):
//! provisioning a *dedicated* cluster per naming context (the D8 ideal)
//! is an operational choice the caller makes via `IRON_CONFIG_FASTETCD_ENDPOINT`
//! before running this, not something this tool automates. Optional env
//! `IRON_CONFIG_ROOT_LDAP_URL` sets the root domain's `ldap_url` (#10:
//! what other partitions refer clients to).
//!
//! `create-child` reads the existing registry from an already-bootstrapped
//! configuration partition, registers a new child domain under an existing
//! parent (defaulting to the parent's own cluster -- override with
//! `IRON_CHILD_FASTETCD_ENDPOINT` for a dedicated cluster), and updates the
//! parent's `subordinates` list so the link is bidirectional. Optional env
//! `IRON_CONFIG_LDAP_URL` sets the child's `ldap_url`.
//!
//! `set-ldap-url` updates an existing partition's `ldap_url` after the
//! fact -- useful since a server's real address is often only known once
//! it's actually deployed, after the partition record already exists.
//!
//! Required env (all commands): IRON_CONFIG_FASTETCD_ENDPOINT.
//! Required env (create-child/set-ldap-url/show): IRON_CONFIG_PARTITION_ID,
//! IRON_CONFIG_BASE_DN -- the bootstrap pointer to the already-existing
//! configuration partition.

use iron_partition::{ClusterRef, Dn, ForestId, Partition, PartitionId, PartitionRegistry};
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
    let Some(cmd) = args.get(1) else {
        anyhow::bail!("usage: iron-config-ctl <init-forest|create-child|show> ...");
    };

    match cmd.as_str() {
        "init-forest" => init_forest(&args[2..]).await,
        "create-child" => create_child(&args[2..]).await,
        "set-ldap-url" => set_ldap_url(&args[2..]).await,
        "show" => show().await,
        other => anyhow::bail!("unknown command {other:?}; expected init-forest, create-child, set-ldap-url, or show"),
    }
}

/// Connects to the configuration partition's own cluster (a fresh,
/// single-partition registry, exactly like every other daemon's env-var
/// bootstrap) and loads the FULL registry from what's persisted there.
/// Shared by every command except `init-forest`, which is the one place
/// the configuration partition doesn't exist yet.
async fn connect_and_load() -> anyhow::Result<(Store, Dn, PartitionRegistry)> {
    let config_endpoint = require_env("IRON_CONFIG_FASTETCD_ENDPOINT")?;
    let config_pid = require_env("IRON_CONFIG_PARTITION_ID")?;
    let config_base_dn_str = require_env("IRON_CONFIG_BASE_DN")?;
    let config_dn = Dn::parse(&config_base_dn_str)?;

    let bootstrap_cluster = ClusterRef::plaintext([config_endpoint]);
    let bootstrap_forest = ForestId::new(config_pid.clone())?; // placeholder, overwritten by the loaded record
    let bootstrap_config_partition = Partition::configuration(config_pid, bootstrap_forest, config_dn.clone(), bootstrap_cluster)?;
    let mut bootstrap_registry = PartitionRegistry::new();
    bootstrap_registry.insert(bootstrap_config_partition)?;
    let mut store = Store::connect(bootstrap_registry).await?;

    let registry = iron_config::load_registry(&mut store, &config_dn).await?;
    Ok((store, config_dn, registry))
}

/// Loads and prints the full registry from an already-bootstrapped
/// configuration partition -- an operational inspection command, and
/// what #9's live verification uses to confirm superior/subordinate
/// links round-trip through real storage.
async fn show() -> anyhow::Result<()> {
    let (_store, _config_dn, registry) = connect_and_load().await?;
    for p in registry.iter() {
        println!(
            "{:<20} kind={:<13} base_dn={:<40} realm={:<20} superior={:<20} ldap_url={:<30} subordinates={:?}",
            p.id.as_str(),
            format!("{:?}", p.kind),
            p.base_dn.to_string(),
            p.realm.as_deref().unwrap_or("-"),
            p.superior.as_ref().map(|s| s.as_str()).unwrap_or("-"),
            p.ldap_url.as_deref().unwrap_or("-"),
            p.subordinates.iter().map(|s| s.as_str()).collect::<Vec<_>>()
        );
    }
    Ok(())
}

/// Updates an existing partition's `ldap_url` (#10) -- a server's real
/// address is often only known once it's deployed, after the partition
/// record already exists.
async fn set_ldap_url(args: &[String]) -> anyhow::Result<()> {
    let (Some(partition_id), Some(url)) = (args.first(), args.get(1)) else {
        anyhow::bail!("usage: iron-config-ctl set-ldap-url <partition-id> <ldap-url>");
    };
    let (mut store, config_dn, registry) = connect_and_load().await?;
    let pid = PartitionId::new(partition_id.clone())?;
    let mut p = registry.get(&pid).ok_or_else(|| anyhow::anyhow!("no such partition: {partition_id}"))?.clone();
    p = p.with_ldap_url(url.clone());
    let index_spec = iron_config::index_spec();
    iron_config::put_partition(&mut store, &config_dn, &index_spec, &p).await?;
    println!("{partition_id}: ldap_url set to {url}");
    Ok(())
}

async fn init_forest(args: &[String]) -> anyhow::Result<()> {
    let (Some(forest_id), Some(config_id), Some(config_base_dn), Some(root_id), Some(root_base_dn)) =
        (args.first(), args.get(1), args.get(2), args.get(3), args.get(4))
    else {
        anyhow::bail!("usage: iron-config-ctl init-forest <forest-id> <config-id> <config-base-dn> <root-domain-id> <root-base-dn> [realm]");
    };
    let realm_override = args.get(5);

    let endpoint = require_env("IRON_CONFIG_FASTETCD_ENDPOINT")?;
    let cluster = ClusterRef::plaintext([endpoint]);
    let forest = ForestId::new(forest_id.clone())?;
    let config_dn = Dn::parse(config_base_dn)?;
    let root_dn = Dn::parse(root_base_dn)?;

    let config_partition = Partition::configuration(config_id.clone(), forest.clone(), config_dn.clone(), cluster.clone())?;

    let mut registry = PartitionRegistry::new();
    registry.insert(config_partition.clone())?;
    let mut store = Store::connect(registry).await?;
    let index_spec = iron_config::index_spec();

    // The configuration partition describes itself, matching AD's
    // Configuration NC hosting its own crossRef object.
    iron_config::put_partition(&mut store, &config_dn, &index_spec, &config_partition).await?;

    let mut root = Partition::domain(root_id.clone(), forest, root_dn, cluster)?;
    if let Some(realm) = realm_override {
        root = root.with_realm(realm.clone());
    }
    if let Some(url) = env("IRON_CONFIG_ROOT_LDAP_URL") {
        root = root.with_ldap_url(url);
    }
    iron_config::put_partition(&mut store, &config_dn, &index_spec, &root).await?;

    println!("forest {forest_id} bootstrapped: configuration partition {config_id} ({config_base_dn}), root domain {root_id} ({root_base_dn}, realm {})", root.realm.as_deref().unwrap_or("<none>"));
    Ok(())
}

async fn create_child(args: &[String]) -> anyhow::Result<()> {
    let (Some(parent_id), Some(new_id), Some(new_base_dn)) = (args.first(), args.get(1), args.get(2)) else {
        anyhow::bail!("usage: iron-config-ctl create-child <parent-id> <new-id> <new-base-dn> [realm]");
    };
    let realm_override = args.get(3);

    let (mut store, config_dn, registry) = connect_and_load().await?;
    let parent_pid = PartitionId::new(parent_id.clone())?;
    let parent = registry.get(&parent_pid).ok_or_else(|| anyhow::anyhow!("no such partition: {parent_id}"))?.clone();
    let new_pid = PartitionId::new(new_id.clone())?;
    if registry.get(&new_pid).is_some() {
        anyhow::bail!("partition {new_id} already exists");
    }

    let child_cluster = match env("IRON_CHILD_FASTETCD_ENDPOINT") {
        Some(ep) => ClusterRef::plaintext([ep]),
        None => parent.cluster.clone(),
    };
    let new_dn = Dn::parse(new_base_dn)?;
    let mut child = Partition::domain(new_id.clone(), parent.forest.clone(), new_dn, child_cluster)?.with_superior(parent_pid.clone());
    if let Some(realm) = realm_override {
        child = child.with_realm(realm.clone());
    }
    if let Some(url) = env("IRON_CONFIG_LDAP_URL") {
        child = child.with_ldap_url(url);
    }

    let index_spec = iron_config::index_spec();
    iron_config::put_partition(&mut store, &config_dn, &index_spec, &child).await?;

    let mut updated_parent = parent;
    updated_parent.subordinates.push(new_pid);
    iron_config::put_partition(&mut store, &config_dn, &index_spec, &updated_parent).await?;

    println!(
        "child domain {new_id} ({new_base_dn}, realm {}) registered under parent {parent_id}, cluster {:?}",
        child.realm.as_deref().unwrap_or("<none>"),
        child.cluster
    );
    Ok(())
}
