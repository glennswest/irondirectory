//! iron-dns-ctl: publishes LDAP/Kerberos SRV autodiscovery records into
//! MicroDNS (#6). An operator/provisioning tool, not a daemon -- run it
//! once per deployment (or after topology changes), same posture as
//! `deploy/dns/etcd-lb.sh`/`ldap-lb.sh` but as a real, reusable binary
//! rather than another one-off shell script.
//!
//! Usage:
//!   iron-dns-ctl ldap <microdns-url> <domain> <host:port> [<host:port> ...]
//!   iron-dns-ctl kerberos <microdns-url> <realm> <host:port> [<host:port> ...]
//!
//! Example:
//!   iron-dns-ctl ldap http://192.168.8.252:8080/api/v1 g8.lo il1.g8.lo:389 il2.g8.lo:389 il3.g8.lo:389
//!   iron-dns-ctl kerberos http://192.168.8.252:8080/api/v1 G8.LO kdc1.g8.lo:88

use iron_dns::Target;

fn parse_target(s: &str) -> anyhow::Result<Target> {
    let (host, port) = s.rsplit_once(':').ok_or_else(|| anyhow::anyhow!("expected host:port, got {s:?}"))?;
    let port: u16 = port.parse()?;
    Ok(Target::new(host, port))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let (Some(kind), Some(microdns_url), Some(name)) = (args.get(1), args.get(2), args.get(3)) else {
        anyhow::bail!(
            "usage: iron-dns-ctl <ldap|kerberos> <microdns-url> <domain-or-realm> <host:port> [<host:port> ...]"
        );
    };
    if args.len() < 5 {
        anyhow::bail!("at least one host:port target is required");
    }
    let targets: Vec<Target> = args[4..].iter().map(|s| parse_target(s)).collect::<Result<_, _>>()?;

    match kind.as_str() {
        "ldap" => {
            iron_dns::publish_ldap(microdns_url, name, &targets).await?;
            println!("published _ldap._tcp in zone {name} for {} target(s)", targets.len());
        }
        "kerberos" => {
            iron_dns::publish_kerberos(microdns_url, name, &targets).await?;
            println!("published _kerberos._udp + _kerberos._tcp in zone {} for {} target(s)", name.to_ascii_lowercase(), targets.len());
        }
        other => anyhow::bail!("unknown record kind {other:?}; expected ldap or kerberos"),
    }
    Ok(())
}
