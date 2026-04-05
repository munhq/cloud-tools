use anyhow::{anyhow, Result};
use reqwest::Client;
use serde_json::Value;

use super::auth::CloudflareCreds;

#[derive(Debug, Clone)]
pub struct CfZone {
    pub id: String,
    pub name: String,
    pub status: String,
    pub plan_name: String,
    pub plan_price: f64,
    pub plan_currency: String,
    pub paused: bool,
    pub name_servers: Vec<String>,
}

/// Fetch all zones for the account, handling pagination.
pub async fn list_zones(http: &Client, creds: &CloudflareCreds) -> Result<Vec<CfZone>> {
    let mut all_zones = Vec::new();
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
            return Err(anyhow!(
                "CF zones ({}): {}",
                status,
                resp.text().await?
            ));
        }

        let data: Value = resp.json().await?;
        let zones = data["result"].as_array().cloned().unwrap_or_default();

        if zones.is_empty() {
            break;
        }

        for zone in &zones {
            let name_servers = zone["name_servers"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|ns| ns.as_str().map(|s| s.to_string()))
                .collect();

            all_zones.push(CfZone {
                id: zone["id"].as_str().unwrap_or("").to_string(),
                name: zone["name"].as_str().unwrap_or("").to_string(),
                status: zone["status"].as_str().unwrap_or("unknown").to_string(),
                plan_name: zone["plan"]["name"].as_str().unwrap_or("Unknown").to_string(),
                plan_price: zone["plan"]["price"].as_f64().unwrap_or(0.0),
                plan_currency: zone["plan"]["currency"]
                    .as_str()
                    .unwrap_or("USD")
                    .to_string(),
                paused: zone["paused"].as_bool().unwrap_or(false),
                name_servers,
            });
        }

        // Check if there are more pages
        let total_pages = data["result_info"]["total_pages"].as_u64().unwrap_or(1);
        if (page as u64) >= total_pages {
            break;
        }
        page += 1;
    }

    Ok(all_zones)
}
