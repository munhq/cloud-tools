//! Google Cloud NAT gateway inventory.
//!
//! NAT configs are nested inside Cloud Routers, so we must iterate all regions,
//! fetch routers per region, and extract the `nats[]` array from each router.
//! Pricing: ~$5/mo per NAT gateway (excluding data processing charges).

use anyhow::{anyhow, Result};
use reqwest::Client;

use super::auth::{access_token, GcpCreds};

#[derive(Debug, Clone)]
pub struct CloudNat {
    pub name: String,        // NAT gateway name
    pub router_name: String, // parent router name
    pub region: String,
    pub source_ranges: String, // e.g. "ALL_SUBNETWORKS_ALL_IP_RANGES"
    pub nat_ips: Vec<String>,  // external IPs used (may be auto-allocated)
}

pub async fn list_cloud_nats(http: &Client, creds: &GcpCreds) -> Result<Vec<CloudNat>> {
    let token = access_token(http, creds).await?;
    let project = &creds.project_id;

    let regions = list_regions(http, &token, project).await?;
    if regions.is_empty() {
        return Ok(Vec::new());
    }

    let futs: Vec<_> = regions
        .iter()
        .map(|region| list_routers_in_region(http, &token, project, region))
        .collect();

    let results = futures::future::join_all(futs).await;

    let mut out = Vec::new();
    for result in results {
        out.extend(result?);
    }
    Ok(out)
}

async fn list_regions(http: &Client, token: &str, project: &str) -> Result<Vec<String>> {
    let url = format!("https://compute.googleapis.com/compute/v1/projects/{project}/regions");
    let resp = http.get(&url).bearer_auth(token).send().await?;
    if !resp.status().is_success() {
        return Ok(Vec::new());
    }
    let data: serde_json::Value = resp.json().await?;
    Ok(data["items"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|r| r["name"].as_str().map(String::from))
        .collect())
}

async fn list_routers_in_region(
    http: &Client,
    token: &str,
    project: &str,
    region: &str,
) -> Result<Vec<CloudNat>> {
    let url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{project}/regions/{region}/routers"
    );
    let resp = http.get(&url).bearer_auth(token).send().await?;
    let status = resp.status();
    if !status.is_success() {
        // Every failure used to return an empty list, so "the Compute API is
        // disabled" and "this region has no routers" were the same answer. They
        // are not. The caller records the failure per region and carries on, so
        // reporting it costs no resilience.
        let text = resp.text().await.unwrap_or_default();
        return Err(anyhow!(
            "Cloud NAT could not be read for project {project} region {region} (HTTP {status}): \
             enable compute.googleapis.com and check the credentials have permission. Response: {}",
            text.chars().take(200).collect::<String>()
        ));
    }

    let data: serde_json::Value = resp.json().await?;
    let mut out = Vec::new();

    for router in data["items"].as_array().cloned().unwrap_or_default() {
        let router_name = router["name"].as_str().unwrap_or("").to_string();

        for nat in router["nats"].as_array().cloned().unwrap_or_default() {
            let name = nat["name"].as_str().unwrap_or("").to_string();
            let source_ranges = nat["sourceSubnetworkIpRangesToNat"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let nat_ips = nat["natIps"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .filter_map(|ip| {
                    // natIps are full resource URLs — extract just the IP name
                    ip.as_str()
                        .and_then(|s| s.rsplit('/').next())
                        .map(String::from)
                })
                .collect();

            out.push(CloudNat {
                name,
                router_name: router_name.clone(),
                region: region.to_string(),
                source_ranges,
                nat_ips,
            });
        }
    }

    Ok(out)
}
