//! iron-dns-ctl: publishes LDAP/Kerberos SRV autodiscovery records into
//! MicroDNS (#6). An operator/provisioning tool, not a daemon -- run it
//! once per deployment (or after topology changes), same posture as
//! `deploy/dns/etcd-lb.sh`/`ldap-lb.sh` but as a real, reusable binary
//! rather than another one-off shell script.
//!
//! Usage:
//!   iron-dns-ctl ldap <microdns-url> <domain> <host:port> [<host:port> ...]
//!   iron-dns-ctl kerberos <microdns-url> <realm> <host:port> [<host:port> ...]
//!   iron-dns-ctl dc <microdns-url> <domain> <forest> <domain-guid> <dc-host> [ldap-port kdc-port kpasswd-port]
//!
//! `dc` publishes the DC-locator SRV records a writable, non-GC DC
//! registers (#87, MS-ADTS 6.3.2.3) -- what Windows' DsGetDcName looks
//! up before its LDAP ping: `_ldap._tcp.dc._msdcs.<domain>`, the site,
//! PDC and domain-GUID forms, `_kerberos.*` and `_kpasswd.*`. The domain
//! GUID is the one `iron-config-ctl show` prints. Ports default to 389,
//! 88 and 464. Re-running is harmless: MicroDNS keeps an identical record once.
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

async fn dc(args: &[String]) -> anyhow::Result<()> {
    let [url, domain, forest, guid, host, rest @ ..] = args else {
        anyhow::bail!("usage: iron-dns-ctl dc <microdns-url> <domain> <forest> <domain-guid> <dc-host> [ldap-port kdc-port kpasswd-port]");
    };
    let mut ports = iron_dns::DcPorts::default();
    match rest {
        [] => {}
        [l, k, p] => ports = iron_dns::DcPorts { ldap: l.parse()?, kerberos: k.parse()?, kpasswd: p.parse()? },
        _ => anyhow::bail!("give all three ports (ldap kdc kpasswd) or none"),
    }
    let written = iron_dns::publish_dc(url, domain, forest, guid, host, ports).await?;
    for name in &written {
        println!("published {name} -> {host}");
    }
    println!("{} DC-locator SRV records for {host}", written.len());
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("dc") {
        return dc(&args[2..]).await;
    }
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
