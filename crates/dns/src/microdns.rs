//! Minimal MicroDNS REST client (#6) -- just enough to find/create a
//! zone and create records. MicroDNS is the actual nameserver; iron-dns
//! never speaks the DNS protocol itself, only MicroDNS's management API.

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("MicroDNS returned {status}: {body}")]
    Api { status: reqwest::StatusCode, body: String },
}

#[derive(Debug, Deserialize)]
pub struct Zone {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Serialize)]
struct CreateZoneReq<'a> {
    name: &'a str,
}

#[derive(Debug, Serialize)]
pub struct SrvData {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

#[derive(Debug, Serialize)]
struct CreateRecordReq {
    name: String,
    ttl: u32,
    data: RecordDataWire,
    enabled: bool,
}

// MicroDNS's record wire shape is `{"type": "SRV", "data": {...}}` (a
// single object, not our RecordData enum's `{"type":..,"data":..}`
// double-nesting) -- match it exactly rather than relying on serde's
// enum representation lining up by accident.
#[derive(Debug, Serialize)]
struct RecordDataWire {
    #[serde(rename = "type")]
    ty: &'static str,
    data: SrvDataInner,
}

#[derive(Debug, Serialize)]
struct SrvDataInner {
    priority: u16,
    weight: u16,
    port: u16,
    target: String,
}

pub struct MicroDns {
    base_url: String,
    client: reqwest::Client,
}

impl MicroDns {
    pub fn new(base_url: impl Into<String>) -> Self {
        MicroDns { base_url: base_url.into(), client: reqwest::Client::new() }
    }

    async fn check_status(resp: reqwest::Response) -> Result<reqwest::Response, Error> {
        if resp.status().is_success() {
            Ok(resp)
        } else {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            Err(Error::Api { status, body })
        }
    }

    pub async fn list_zones(&self) -> Result<Vec<Zone>, Error> {
        let resp = self.client.get(format!("{}/zones", self.base_url)).send().await?;
        let resp = Self::check_status(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn find_zone(&self, name: &str) -> Result<Option<Zone>, Error> {
        Ok(self.list_zones().await?.into_iter().find(|z| z.name.eq_ignore_ascii_case(name)))
    }

    pub async fn create_zone(&self, name: &str) -> Result<Zone, Error> {
        let resp = self
            .client
            .post(format!("{}/zones", self.base_url))
            .json(&CreateZoneReq { name })
            .send()
            .await?;
        let resp = Self::check_status(resp).await?;
        Ok(resp.json().await?)
    }

    /// Finds `name`'s zone, creating it if it doesn't exist yet.
    pub async fn find_or_create_zone(&self, name: &str) -> Result<Zone, Error> {
        if let Some(z) = self.find_zone(name).await? {
            return Ok(z);
        }
        self.create_zone(name).await
    }

    /// Creates an SRV record. MicroDNS treats a record with the same
    /// name+type+data as already existing (returns the existing one
    /// rather than erroring) -- publishing is naturally idempotent.
    pub async fn create_srv_record(&self, zone_id: &str, name: &str, ttl: u32, srv: SrvData) -> Result<(), Error> {
        let req = CreateRecordReq {
            name: name.to_string(),
            ttl,
            data: RecordDataWire {
                ty: "SRV",
                data: SrvDataInner { priority: srv.priority, weight: srv.weight, port: srv.port, target: srv.target },
            },
            enabled: true,
        };
        let resp = self
            .client
            .post(format!("{}/zones/{}/records", self.base_url, zone_id))
            .json(&req)
            .send()
            .await?;
        Self::check_status(resp).await?;
        Ok(())
    }
}
