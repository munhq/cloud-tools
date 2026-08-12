use anyhow::{anyhow, Result};
use futures::future::join_all;
use reqwest::Client;
use serde_json::Value;

use super::auth::CloudflareCreds;

#[derive(Debug, Clone)]
pub struct CfDnsRecord {
    pub zone_id: String,
    pub zone_name: String,
    pub record_id: String,
    pub name: String,
    pub record_type: String,
    pub content: String,
    pub proxied: bool,
    pub ttl: u32,
}

#[derive(Debug, Clone)]
pub struct ZoneDnsSummary {
    pub zone_id: String,
    pub zone_name: String,
    pub total_records: usize,
    pub proxied_count: usize,
    pub dns_only_count: usize,
    pub records: Vec<CfDnsRecord>,
}

/// List all DNS records across all zones in the account.
/// Fetches zones first, then queries DNS records for each zone in parallel.
pub async fn list_dns_records(
    http: &Client,
    creds: &CloudflareCreds,
) -> Result<Vec<ZoneDnsSummary>> {
    // Step 1: Fetch all zones
    let zones = fetch_zone_ids(http, creds).await?;

    // Step 2: Fetch DNS records for each zone in parallel
    let futures: Vec<_> = zones
        .into_iter()
        .map(|(zone_id, zone_name)| {
            let http = http.clone();
            let token = creds.api_token.clone();
            async move { fetch_zone_dns(&http, &token, &zone_id, &zone_name).await }
        })
        .collect();

    let results = join_all(futures).await;

    let mut summaries = Vec::new();
    for result in results {
        match result {
            Ok(summary) => summaries.push(summary),
            Err(e) => tracing::warn!("CF DNS fetch failed for a zone: {e}"),
        }
    }

    Ok(summaries)
}

/// Fetch all zone IDs and names for the account.
async fn fetch_zone_ids(http: &Client, creds: &CloudflareCreds) -> Result<Vec<(String, String)>> {
    let mut zones = Vec::new();
    let mut page = 1u32;

    loop {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones?account.id={}&per_page=50&page={}",
            creds.account_id, page
        );
        let resp = http.get(&url).bearer_auth(&creds.api_token).send().await?;

        let status = resp.status();
        if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::NOT_FOUND {
            return Ok(Vec::new());
        }
        if !status.is_success() {
            return Err(anyhow!("CF zones ({}): {}", status, resp.text().await?));
        }

        let data: Value = resp.json().await?;
        let results = data["result"].as_array().cloned().unwrap_or_default();
        if results.is_empty() {
            break;
        }

        for zone in &results {
            let id = zone["id"].as_str().unwrap_or("").to_string();
            let name = zone["name"].as_str().unwrap_or("").to_string();
            if !id.is_empty() {
                zones.push((id, name));
            }
        }

        let total_pages = data["result_info"]["total_pages"].as_u64().unwrap_or(1);
        if (page as u64) >= total_pages {
            break;
        }
        page += 1;
    }

    Ok(zones)
}

/// Fetch DNS records for a single zone, handling pagination.
async fn fetch_zone_dns(
    http: &Client,
    token: &str,
    zone_id: &str,
    zone_name: &str,
) -> Result<ZoneDnsSummary> {
    let mut records = Vec::new();
    let mut page = 1u32;

    loop {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?per_page=100&page={page}"
        );
        let resp = http.get(&url).bearer_auth(token).send().await?;

        let status = resp.status();
        if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::NOT_FOUND {
            break;
        }
        if !status.is_success() {
            return Err(anyhow!(
                "CF DNS records for zone {zone_name} ({}): {}",
                status,
                resp.text().await?
            ));
        }

        let data: Value = resp.json().await?;
        let results = data["result"].as_array().cloned().unwrap_or_default();
        if results.is_empty() {
            break;
        }

        for rec in &results {
            records.push(CfDnsRecord {
                zone_id: zone_id.to_string(),
                zone_name: zone_name.to_string(),
                record_id: rec["id"].as_str().unwrap_or("").to_string(),
                name: rec["name"].as_str().unwrap_or("").to_string(),
                record_type: rec["type"].as_str().unwrap_or("").to_string(),
                content: rec["content"].as_str().unwrap_or("").to_string(),
                proxied: rec["proxied"].as_bool().unwrap_or(false),
                ttl: rec["ttl"].as_u64().unwrap_or(1) as u32,
            });
        }

        let total_pages = data["result_info"]["total_pages"].as_u64().unwrap_or(1);
        if (page as u64) >= total_pages {
            break;
        }
        page += 1;
    }

    let proxied_count = records.iter().filter(|r| r.proxied).count();
    let dns_only_count = records.iter().filter(|r| !r.proxied).count();

    Ok(ZoneDnsSummary {
        zone_id: zone_id.to_string(),
        zone_name: zone_name.to_string(),
        total_records: records.len(),
        proxied_count,
        dns_only_count,
        records,
    })
}
