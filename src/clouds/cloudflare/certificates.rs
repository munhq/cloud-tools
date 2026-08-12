use anyhow::{anyhow, Result};
use futures::future::join_all;
use reqwest::Client;
use serde_json::Value;

use super::auth::CloudflareCreds;

#[derive(Debug, Clone)]
pub struct CfCertificate {
    pub zone_id: String,
    pub zone_name: String,
    pub cert_id: String,
    pub cert_type: String,
    pub status: String,
    pub hosts: Vec<String>,
    pub expires_on: Option<String>,
}

/// List SSL/TLS certificate packs across all zones in the account.
/// Fetches zones first, then queries certificate packs for each zone in parallel.
pub async fn list_certificates(
    http: &Client,
    creds: &CloudflareCreds,
) -> Result<Vec<CfCertificate>> {
    // Step 1: Fetch all zones
    let zones = fetch_zone_ids(http, creds).await?;

    // Step 2: Fetch certificate packs for each zone in parallel
    let futures: Vec<_> = zones
        .into_iter()
        .map(|(zone_id, zone_name)| {
            let http = http.clone();
            let token = creds.api_token.clone();
            async move { fetch_zone_certs(&http, &token, &zone_id, &zone_name).await }
        })
        .collect();

    let results = join_all(futures).await;

    let mut certs = Vec::new();
    for result in results {
        match result {
            Ok(mut zone_certs) => certs.append(&mut zone_certs),
            Err(e) => tracing::warn!("CF certificate fetch failed for a zone: {e}"),
        }
    }

    Ok(certs)
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

/// Fetch certificate packs for a single zone.
async fn fetch_zone_certs(
    http: &Client,
    token: &str,
    zone_id: &str,
    zone_name: &str,
) -> Result<Vec<CfCertificate>> {
    let url = format!(
        "https://api.cloudflare.com/client/v4/zones/{zone_id}/ssl/certificate_packs?status=all"
    );
    let resp = http.get(&url).bearer_auth(token).send().await?;

    let status = resp.status();
    if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::NOT_FOUND {
        return Ok(Vec::new());
    }
    if !status.is_success() {
        return Err(anyhow!(
            "CF certificates for zone {zone_name} ({}): {}",
            status,
            resp.text().await?
        ));
    }

    let data: Value = resp.json().await?;
    let packs = data["result"].as_array().cloned().unwrap_or_default();

    let certs = packs
        .into_iter()
        .map(|pack| {
            let hosts = pack["hosts"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|h| h.as_str().map(|s| s.to_string()))
                .collect();

            let expires_on = pack["certificates"]
                .as_array()
                .and_then(|certs| certs.first())
                .and_then(|cert| cert["expires_on"].as_str())
                .map(|s| s.to_string());

            CfCertificate {
                zone_id: zone_id.to_string(),
                zone_name: zone_name.to_string(),
                cert_id: pack["id"].as_str().unwrap_or("").to_string(),
                cert_type: pack["type"].as_str().unwrap_or("unknown").to_string(),
                status: pack["status"].as_str().unwrap_or("unknown").to_string(),
                hosts,
                expires_on,
            }
        })
        .collect();

    Ok(certs)
}
