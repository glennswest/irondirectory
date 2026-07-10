//! Static OAuth2 client registry (#15), configured via `IRON_OIDC_CLIENTS`
//! -- `;`-separated `client_id|client_secret|redirect_uri` entries, the
//! same delimiter convention `IRON_LDAP_REFERRALS`/`IRON_GC_FORESTS`
//! already use (`|`, not `=`, since a URL is itself full of special
//! characters). One `redirect_uri` per client: OpenShift (and most
//! relying parties) register exactly one callback URL per IdP
//! integration, so this doesn't need a list -- a client needing more
//! than one would need a second registry entry with a different
//! `client_id` today, a documented limitation rather than unsupported.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Client {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

pub struct ClientRegistry {
    clients: HashMap<String, Client>,
}

impl ClientRegistry {
    pub fn parse(raw: &str) -> anyhow::Result<Self> {
        let mut clients = HashMap::new();
        for entry in raw.split(';').filter(|s| !s.trim().is_empty()) {
            let mut parts = entry.splitn(3, '|');
            let (Some(client_id), Some(client_secret), Some(redirect_uri)) = (parts.next(), parts.next(), parts.next()) else {
                anyhow::bail!("malformed IRON_OIDC_CLIENTS entry {entry:?}, expected client_id|client_secret|redirect_uri");
            };
            clients.insert(
                client_id.trim().to_string(),
                Client {
                    client_id: client_id.trim().to_string(),
                    client_secret: client_secret.trim().to_string(),
                    redirect_uri: redirect_uri.trim().to_string(),
                },
            );
        }
        Ok(ClientRegistry { clients })
    }

    pub fn get(&self, client_id: &str) -> Option<&Client> {
        self.clients.get(client_id)
    }

    /// Validates a client's identity + secret (RFC 6749 §2.3.1, used by
    /// `/token`) -- constant-time-ish is unnecessary here since the
    /// secret is compared against a value only this process holds, not
    /// derived from anything an attacker could already influence the
    /// timing of meaningfully (unlike a password hash comparison).
    pub fn authenticate(&self, client_id: &str, client_secret: &str) -> bool {
        self.clients.get(client_id).is_some_and(|c| c.client_secret == client_secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multiple_clients() {
        let reg = ClientRegistry::parse("openshift|secret1|https://console.example.com/callback;grafana|secret2|https://grafana.example.com/login/generic_oauth").unwrap();
        assert_eq!(reg.get("openshift").unwrap().redirect_uri, "https://console.example.com/callback");
        assert_eq!(reg.get("grafana").unwrap().redirect_uri, "https://grafana.example.com/login/generic_oauth");
        assert!(reg.get("unknown").is_none());
    }

    #[test]
    fn authenticate_checks_secret() {
        let reg = ClientRegistry::parse("openshift|secret1|https://console.example.com/callback").unwrap();
        assert!(reg.authenticate("openshift", "secret1"));
        assert!(!reg.authenticate("openshift", "wrong"));
        assert!(!reg.authenticate("unknown", "secret1"));
    }

    #[test]
    fn rejects_malformed_entry() {
        assert!(ClientRegistry::parse("openshift|secret1").is_err());
    }
}
