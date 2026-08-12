use anyhow::{anyhow, Result};
use chrono::Utc;
use reqwest::Client;
use serde_json::Value;

use super::auth::{access_token, GcpCreds};

pub struct GcpResource {
    pub provider: &'static str,
    pub resource_id: String,
    pub resource_type: &'static str,
    pub region: Option<String>,
    pub name: Option<String>,
    pub monthly_cost_estimate: Option<f64>,
    pub last_active_at: Option<String>,
    pub raw: Value,
}

pub async fn list_resources(http: &Client, creds: &GcpCreds) -> Result<Vec<GcpResource>> {
    let token = access_token(http, creds).await?;
    let mut out = Vec::new();
    out.extend(list_instances(http, &token, &creds.project_id).await?);
    out.extend(idle_recommendations(http, &token, &creds.project_id).await?);
    Ok(out)
}

async fn list_instances(http: &Client, token: &str, project: &str) -> Result<Vec<GcpResource>> {
    let url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/instances?maxResults=500"
    );
    let resp = http.get(&url).bearer_auth(token).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "GCP instances ({}): {}",
            resp.status(),
            resp.text().await?
        ));
    }
    let data: Value = resp.json().await?;
    let mut out = Vec::new();

    for (zone_key, zone_data) in data["items"].as_object().cloned().unwrap_or_default() {
        // zone_key is like "zones/us-central1-a" — derive region by dropping last segment
        let region = zone_key.rsplit('/').next().and_then(|z| {
            let parts: Vec<&str> = z.rsplitn(2, '-').collect();
            if parts.len() == 2 {
                Some(parts[1].to_string())
            } else {
                None
            }
        });

        for inst in zone_data["instances"]
            .as_array()
            .cloned()
            .unwrap_or_default()
        {
            let status = inst["status"].as_str().unwrap_or("UNKNOWN");
            out.push(GcpResource {
                provider: "gcp",
                resource_id: inst["id"].as_str().unwrap_or("").to_string(),
                resource_type: "gce_instance",
                region: region.clone(),
                name: inst["name"].as_str().map(String::from),
                monthly_cost_estimate: None,
                last_active_at: if status == "RUNNING" {
                    Some(Utc::now().to_rfc3339())
                } else {
                    None
                },
                raw: inst,
            });
        }
    }
    Ok(out)
}

// ── Persistent Disks ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GcpDisk {
    pub name: String,
    pub id: String,
    pub size_gb: u64,
    pub disk_type: String, // "pd-standard", "pd-ssd", "pd-balanced"
    pub status: String,    // "READY", "CREATING", etc.
    pub zone: String,
    pub region: String,
    /// True if attached to at least one instance.
    pub attached: bool,
}

pub async fn list_disks(http: &Client, token: &str, project: &str) -> Result<Vec<GcpDisk>> {
    let url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/disks?maxResults=500"
    );
    let resp = http.get(&url).bearer_auth(token).send().await?;
    if !resp.status().is_success() {
        return Ok(Vec::new());
    }
    let data: Value = resp.json().await?;
    let mut out = Vec::new();

    for (zone_key, zone_data) in data["items"].as_object().cloned().unwrap_or_default() {
        let zone = zone_key.rsplit('/').next().unwrap_or("").to_string();
        let region = zone.rsplit_once('-').map(|x| x.0).unwrap_or("").to_string();

        for disk in zone_data["disks"].as_array().cloned().unwrap_or_default() {
            let name = disk["name"].as_str().unwrap_or("").to_string();
            let id = disk["id"].as_str().unwrap_or("").to_string();
            let size_gb = disk["sizeGb"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let disk_type = disk["type"]
                .as_str()
                .and_then(|t| t.rsplit('/').next())
                .unwrap_or("pd-standard")
                .to_string();
            let status = disk["status"].as_str().unwrap_or("").to_string();
            let attached = disk["users"]
                .as_array()
                .map(|a| !a.is_empty())
                .unwrap_or(false);

            out.push(GcpDisk {
                name,
                id,
                size_gb,
                disk_type,
                status,
                zone: zone.clone(),
                region: region.clone(),
                attached,
            });
        }
    }
    Ok(out)
}

// ── Static IPs (Addresses) ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GcpAddress {
    pub name: String,
    pub address: String,
    pub status: String, // "RESERVED" = unattached, "IN_USE" = attached
    pub region: String,
    pub address_type: String, // "EXTERNAL", "INTERNAL"
}

pub async fn list_addresses(http: &Client, token: &str, project: &str) -> Result<Vec<GcpAddress>> {
    let url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/addresses?maxResults=500"
    );
    let resp = http.get(&url).bearer_auth(token).send().await?;
    if !resp.status().is_success() {
        return Ok(Vec::new());
    }
    let data: Value = resp.json().await?;
    let mut out = Vec::new();

    for (_key, region_data) in data["items"].as_object().cloned().unwrap_or_default() {
        for addr in region_data["addresses"]
            .as_array()
            .cloned()
            .unwrap_or_default()
        {
            let name = addr["name"].as_str().unwrap_or("").to_string();
            let address = addr["address"].as_str().unwrap_or("").to_string();
            let status = addr["status"].as_str().unwrap_or("").to_string();
            let region = addr["region"]
                .as_str()
                .and_then(|r| r.rsplit('/').next())
                .unwrap_or("")
                .to_string();
            let addr_type = addr["addressType"]
                .as_str()
                .unwrap_or("EXTERNAL")
                .to_string();

            out.push(GcpAddress {
                name,
                address,
                status,
                region,
                address_type: addr_type,
            });
        }
    }
    Ok(out)
}

// ── Snapshots ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GcpSnapshot {
    pub name: String,
    pub id: String,
    pub disk_size_gb: u64,
    pub storage_bytes: u64,
    pub status: String,
    pub creation_timestamp: Option<String>,
    pub source_disk: String,
    /// Whether the source disk still exists.
    pub source_disk_exists: bool,
}

pub async fn list_snapshots(http: &Client, token: &str, project: &str) -> Result<Vec<GcpSnapshot>> {
    let url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{project}/global/snapshots?maxResults=500"
    );
    let resp = http.get(&url).bearer_auth(token).send().await?;
    if !resp.status().is_success() {
        return Ok(Vec::new());
    }
    let data: Value = resp.json().await?;

    Ok(data["items"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|s| {
            let name = s["name"].as_str()?.to_string();
            let id = s["id"].as_str().unwrap_or("").to_string();
            let disk_size = s["diskSizeGb"]
                .as_str()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let storage = s["storageBytes"]
                .as_str()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let status = s["status"].as_str().unwrap_or("").to_string();
            let created = s["creationTimestamp"].as_str().map(String::from);
            let source = s["sourceDisk"].as_str().unwrap_or("").to_string();

            Some(GcpSnapshot {
                name,
                id,
                disk_size_gb: disk_size,
                storage_bytes: storage,
                status,
                creation_timestamp: created,
                source_disk: source,
                source_disk_exists: true, // will be set correctly by the analyzer
            })
        })
        .collect())
}

// ── Forwarding Rules (Load Balancers) ────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GcpForwardingRule {
    pub name: String,
    pub region: String,
    pub ip_address: String,
    pub target: String, // target pool or proxy URL
    pub load_balancing_scheme: String,
}

pub async fn list_forwarding_rules(
    http: &Client,
    token: &str,
    project: &str,
) -> Result<Vec<GcpForwardingRule>> {
    let url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/forwardingRules?maxResults=500"
    );
    let resp = http.get(&url).bearer_auth(token).send().await?;
    if !resp.status().is_success() {
        return Ok(Vec::new());
    }
    let data: Value = resp.json().await?;
    let mut out = Vec::new();

    for (_key, region_data) in data["items"].as_object().cloned().unwrap_or_default() {
        for rule in region_data["forwardingRules"]
            .as_array()
            .cloned()
            .unwrap_or_default()
        {
            let name = rule["name"].as_str().unwrap_or("").to_string();
            let region = rule["region"]
                .as_str()
                .and_then(|r| r.rsplit('/').next())
                .unwrap_or("")
                .to_string();
            let ip = rule["IPAddress"].as_str().unwrap_or("").to_string();
            let target = rule["target"].as_str().unwrap_or("").to_string();
            let scheme = rule["loadBalancingScheme"]
                .as_str()
                .unwrap_or("")
                .to_string();

            out.push(GcpForwardingRule {
                name,
                region,
                ip_address: ip,
                target,
                load_balancing_scheme: scheme,
            });
        }
    }
    Ok(out)
}

// ── Idle Recommendations (legacy — now superseded by recommender.rs) ────────

async fn idle_recommendations(
    http: &Client,
    token: &str,
    project: &str,
) -> Result<Vec<GcpResource>> {
    let zones_resp = http
        .get(format!(
            "https://compute.googleapis.com/compute/v1/projects/{project}/zones"
        ))
        .bearer_auth(token)
        .send()
        .await?;
    if !zones_resp.status().is_success() {
        return Ok(Vec::new());
    }
    let zones_data: Value = zones_resp.json().await?;
    let zones: Vec<String> = zones_data["items"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|z| z["name"].as_str().map(String::from))
        .collect();

    let mut out = Vec::new();
    for zone in zones {
        let url = format!(
            "https://recommender.googleapis.com/v1/projects/{project}/locations/{zone}/recommenders/google.compute.instance.IdleResourceRecommender/recommendations"
        );
        let resp = http.get(&url).bearer_auth(token).send().await?;
        if !resp.status().is_success() {
            continue;
        }
        let data: Value = resp.json().await?;
        for rec in data["recommendations"]
            .as_array()
            .cloned()
            .unwrap_or_default()
        {
            if rec["stateInfo"]["state"].as_str() != Some("ACTIVE") {
                continue;
            }
            let name = rec["content"]["overview"]["resourceName"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let savings = rec["primaryImpact"]["costProjection"]["cost"]["units"]
                .as_str()
                .and_then(|s| s.parse::<f64>().ok())
                .map(|v| v.abs());
            out.push(GcpResource {
                provider: "gcp",
                resource_id: format!("idle/{zone}/{name}"),
                resource_type: "gce_instance_idle",
                region: Some(zone.clone()),
                name: Some(name),
                monthly_cost_estimate: savings,
                last_active_at: None,
                raw: rec,
            });
        }
    }
    Ok(out)
}
