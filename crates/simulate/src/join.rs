//! Orchestration: the full realistic "Windows Server / PC joins the
//! domain, then logs in" sequence (#23), and a "normal PC" ordinary
//! interactive logon with no join step.
//!
//! Two things a *real* join client can't do, which this harness does
//! because it's testing its own server, not acting as an unprivileged
//! client:
//! - Provisioning the new computer account's NTOWF/Kerberos keys
//!   directly via the DIT (standing in for real `SamrSetInformationUser2`
//!   password-setting, which needs an authenticated RPC bind -- #19).
//! - Decrypting the resulting service ticket with an independently-known
//!   server key, to confirm its PAC (#18) -- a real client never sees
//!   inside its own service tickets.

use std::time::Instant;

use iron_crypto::kerberos::Enctype;
use iron_crypto::FipsContext;
use iron_partition::Dn;
use iron_rpc::netlogon::NTOWF_ATTR;
use iron_store::model::Entry;
use iron_store::store::Store;

use crate::{krb_client, lsarpc_client, netlogon_client, samr_client};

#[derive(Debug, thiserror::Error)]
pub enum JoinError {
    #[error("RPC error: {0}")]
    Rpc(#[from] crate::rpc_client::RpcClientError),
    #[error("Kerberos error: {0}")]
    Krb(#[from] krb_client::KrbClientError),
    #[error("store error: {0}")]
    Store(#[from] iron_store::StoreError),
    #[error("crypto error: {0}")]
    Crypto(#[from] iron_crypto::Error),
    #[error("principal error: {0}")]
    Principal(#[from] iron_kdc::principal::Error),
    #[error("partition error: {0}")]
    Partition(#[from] iron_partition::PartitionError),
    #[error("no such account after creation -- store may be misconfigured")]
    AccountMissing,
    #[error("PAC missing or malformed in the service ticket")]
    NoPac,
}

pub struct SimConfig {
    pub rpc_addr: String,
    pub kdc_addr: String,
    pub base_dn: String,
    pub realm: String,
    pub service_principal: String,
    pub service_password: Vec<u8>,
}

pub struct JoinReport {
    pub computer_name: String,
    pub rid: u32,
    pub domain_sid: String,
    pub netlogon_established: bool,
    pub tgt_acquired: bool,
    pub service_ticket_acquired: bool,
    pub pac_buffer_types: Vec<u32>,
    pub elapsed: std::time::Duration,
}

pub struct LoginReport {
    pub username: String,
    pub tgt_acquired: bool,
    pub service_ticket_acquired: bool,
    pub pac_buffer_types: Vec<u32>,
    pub elapsed: std::time::Duration,
}

/// Ensures the "service" principal this harness decrypts tickets with
/// has both a real Kerberos key (so the KDC can issue tickets to it)
/// -- idempotent, safe to call once per process before any simulated
/// joins/logins.
pub async fn ensure_service_principal(config: &SimConfig, fips: &FipsContext) -> Result<(), JoinError> {
    let mut store = connect_store(config).await?;
    let base_dn = Dn::parse(&config.base_dn)?;
    let principal_fqn = format!("{}@{}", config.service_principal, config.realm);
    let existing = store.lookup_by_index(&base_dn, iron_kdc::principal::ATTR_PRINCIPAL_NAME, &principal_fqn).await?;
    let (dn, mut entry) = match existing.as_slice() {
        [] => {
            let cn_value = config.service_principal.replace('/', ".");
            let dn = Dn::parse(&format!("cn={cn_value},{}", config.base_dn))?;
            let mut e = Entry::new();
            e.set("objectclass", ["top".to_string()]);
            e.set("cn", [cn_value]);
            (dn, e)
        }
        [dn] => {
            let e = store.get_entry(dn).await?.ok_or(JoinError::AccountMissing)?;
            (dn.clone(), e)
        }
        _ => return Err(JoinError::AccountMissing),
    };
    iron_kdc::principal::set_password(fips, &mut entry, &principal_fqn, &config.service_password)?;
    store.put_entry(&dn, &entry, &iron_kdc::index_spec()).await?;
    Ok(())
}

async fn connect_store(config: &SimConfig) -> Result<Store, JoinError> {
    // The simulator's own store connection is separate from iron-rpcd's/
    // iron-kdcd's -- this is the "test-harness-only" provisioning path
    // described in the module docs, not something a real client has.
    let cluster = iron_partition::ClusterRef::plaintext([std::env::var("IRON_SIM_FASTETCD_ENDPOINT").expect("IRON_SIM_FASTETCD_ENDPOINT required")]);
    let forest = iron_partition::ForestId::new("sim")?;
    let base_dn = Dn::parse(&config.base_dn)?;
    let partition = iron_partition::Partition::domain("sim".to_string(), forest, base_dn, cluster)?;
    let mut registry = iron_partition::PartitionRegistry::new();
    registry.insert(partition)?;
    Ok(Store::connect(registry).await?)
}

/// The full join+login simulation: LSARPC -> SAMR -> provision secrets
/// (direct store access, see module docs) -> NETLOGON -> Kerberos
/// AS-REQ -> Kerberos TGS-REQ -> PAC check.
pub async fn simulate_join(config: &SimConfig, fips: &FipsContext, computer_name: &str, password: &[u8]) -> Result<JoinReport, JoinError> {
    let start = Instant::now();

    let mut lsa = lsarpc_client::connect(&config.rpc_addr).await?;
    let policy_handle = lsarpc_client::open_policy2(&mut lsa).await?;
    let domain_info = lsarpc_client::query_dns_domain_information(&mut lsa, &policy_handle).await?;
    lsarpc_client::close(&mut lsa, &policy_handle).await?;

    let mut samr = samr_client::connect(&config.rpc_addr).await?;
    let server_handle = samr_client::connect5(&mut samr).await?;
    let domain_sid = samr_client::lookup_domain_in_sam_server(&mut samr, &server_handle, &domain_info.netbios_name).await?;
    let domain_handle = samr_client::open_domain(&mut samr, &server_handle, &domain_sid).await?;
    let (user_handle, rid) = samr_client::create_user2_in_domain(&mut samr, &domain_handle, computer_name).await?;
    samr_client::close_handle(&mut samr, &user_handle).await?;
    samr_client::close_handle(&mut samr, &domain_handle).await?;
    samr_client::close_handle(&mut samr, &server_handle).await?;

    // Provision the new account's secrets -- standing in for real
    // SamrSetInformationUser2 (see module docs).
    let ntowf = iron_crypto::md4::ntowf(std::str::from_utf8(password).unwrap_or_default());
    let mut store = connect_store(config).await?;
    let base_dn = Dn::parse(&config.base_dn)?;
    let dn = Dn::parse(&format!("cn={computer_name},{}", config.base_dn))?;
    let mut entry = store.get_entry(&dn).await?.ok_or(JoinError::AccountMissing)?;
    entry.set(NTOWF_ATTR, [ntowf.iter().map(|b| format!("{b:02x}")).collect::<String>()]);
    let principal_fqn = format!("{computer_name}@{}", config.realm);
    iron_kdc::principal::set_password(fips, &mut entry, &principal_fqn, password)?;
    store.put_entry(&dn, &entry, &iron_kdc::index_spec()).await?;
    let _ = base_dn;

    let mut nl = netlogon_client::connect(&config.rpc_addr).await?;
    let client_challenge = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let server_challenge = netlogon_client::req_challenge(&mut nl, computer_name, &client_challenge).await?;
    netlogon_client::authenticate3(&mut nl, fips, &principal_fqn.replace(&format!("@{}", config.realm), ""), computer_name, &ntowf, &client_challenge, &server_challenge)
        .await?;

    let tgt = krb_client::as_exchange(fips, &config.kdc_addr, &config.realm, &principal_fqn, password).await?;
    let service_ticket = krb_client::tgs_exchange(fips, &config.kdc_addr, &config.realm, &tgt, &config.service_principal).await?;

    let service_key = iron_crypto::kerberos::string_to_key(fips, Enctype::Aes256CtsHmacSha384_192, &config.service_password, format!("{}@{}", config.service_principal, config.realm).as_bytes(), None)?;
    let enc_ticket = krb_client::decrypt_ticket(fips, &service_ticket.ticket, &service_key, Enctype::Aes256CtsHmacSha384_192)
        .or_else(|_| {
            let key128 = iron_crypto::kerberos::string_to_key(fips, Enctype::Aes256CtsHmacSha1_96, &config.service_password, format!("{}@{}", config.service_principal, config.realm).as_bytes(), None)?;
            krb_client::decrypt_ticket(fips, &service_ticket.ticket, &key128, Enctype::Aes256CtsHmacSha1_96)
        })?;
    let pac_bytes = krb_client::extract_pac(&enc_ticket).ok_or(JoinError::NoPac)?;
    let pac_buffer_types = krb_client::pac_buffer_types(&pac_bytes).ok_or(JoinError::NoPac)?;

    Ok(JoinReport {
        computer_name: computer_name.to_string(),
        rid,
        domain_sid: domain_sid.to_string(),
        netlogon_established: true,
        tgt_acquired: true,
        service_ticket_acquired: true,
        pac_buffer_types,
        elapsed: start.elapsed(),
    })
}

/// A "normal PC" ordinary interactive logon: AS-REQ + TGS-REQ only, no
/// join. `username` must already have a Kerberos key set (e.g. via
/// `iron-kdc-ctl set-password`, or provisioned by the caller beforehand).
pub async fn simulate_login(config: &SimConfig, fips: &FipsContext, username: &str, password: &[u8]) -> Result<LoginReport, JoinError> {
    let start = Instant::now();
    let principal_fqn = format!("{username}@{}", config.realm);

    let tgt = krb_client::as_exchange(fips, &config.kdc_addr, &config.realm, &principal_fqn, password).await?;
    let service_ticket = krb_client::tgs_exchange(fips, &config.kdc_addr, &config.realm, &tgt, &config.service_principal).await?;

    let service_key = iron_crypto::kerberos::string_to_key(fips, Enctype::Aes256CtsHmacSha384_192, &config.service_password, format!("{}@{}", config.service_principal, config.realm).as_bytes(), None)?;
    let enc_ticket = krb_client::decrypt_ticket(fips, &service_ticket.ticket, &service_key, Enctype::Aes256CtsHmacSha384_192)?;
    let pac_bytes = krb_client::extract_pac(&enc_ticket).ok_or(JoinError::NoPac)?;
    let pac_buffer_types = krb_client::pac_buffer_types(&pac_bytes).ok_or(JoinError::NoPac)?;

    Ok(LoginReport {
        username: username.to_string(),
        tgt_acquired: true,
        service_ticket_acquired: true,
        pac_buffer_types,
        elapsed: start.elapsed(),
    })
}
