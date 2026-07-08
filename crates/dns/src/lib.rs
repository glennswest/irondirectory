//! iron-dns: LDAP/Kerberos SRV autodiscovery record publishing (#6).
//!
//! Not a DNS server or protocol implementation -- MicroDNS already is
//! the nameserver for every network this deploys to. `iron-dns` (and
//! its `iron-dns-ctl` CLI) is purely a thin publisher: given a
//! domain/realm and a list of target hosts, compute the right
//! `_ldap._tcp`/`_kerberos._udp`/`_kerberos._tcp` SRV records (RFC 2782,
//! RFC 4120 §7.2.3.2) and push them into MicroDNS's management API.

pub mod microdns;
pub mod srv;

use microdns::{MicroDns, SrvData};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    MicroDns(#[from] microdns::Error),
}

/// One SRV target: a host to point the record at, on `port`, with the
/// given RFC 2782 `priority`/`weight` (equal-priority, equal-weight
/// round-robin across all targets is the common case: priority 10,
/// weight 20 for every target, matching the existing
/// `_etcd-server-ssl._tcp` records in the g8.lo zone).
#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub priority: u16,
    pub weight: u16,
}

impl Target {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Target { host: host.into(), port, priority: 10, weight: 20 }
    }
}

/// Publishes `_ldap._tcp` SRV records in `domain`'s zone for every target.
pub async fn publish_ldap(microdns_url: &str, domain: &str, targets: &[Target]) -> Result<(), Error> {
    publish(microdns_url, domain, srv::LDAP_SRV_NAME, targets).await
}

/// Publishes `_kerberos._udp` and `_kerberos._tcp` SRV records (in the
/// zone named after `realm`, lowercased) for every target -- KDCs
/// normally listen on both protocols on the same port, per RFC 4120 §7.2.
pub async fn publish_kerberos(microdns_url: &str, realm: &str, targets: &[Target]) -> Result<(), Error> {
    let domain = realm.to_ascii_lowercase();
    publish(microdns_url, &domain, srv::KERBEROS_UDP_SRV_NAME, targets).await?;
    publish(microdns_url, &domain, srv::KERBEROS_TCP_SRV_NAME, targets).await?;
    Ok(())
}

async fn publish(microdns_url: &str, zone_name: &str, record_name: &str, targets: &[Target]) -> Result<(), Error> {
    let dns = MicroDns::new(microdns_url);
    let zone = dns.find_or_create_zone(zone_name).await?;
    for t in targets {
        dns.create_srv_record(
            &zone.id,
            record_name,
            300,
            SrvData { priority: t.priority, weight: t.weight, port: t.port, target: t.host.clone() },
        )
        .await?;
    }
    Ok(())
}
