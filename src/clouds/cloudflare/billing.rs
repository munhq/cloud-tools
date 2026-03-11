use anyhow::{anyhow, Result};
use chrono::Utc;
use reqwest::Client;

use crate::types::CostEntry;

use super::auth::CloudflareCreds;

pub async fn get_costs(http: &Client, creds: &CloudflareCreds) -> Result<Vec<CostEntry>> {
    // Fetch billing profile to get currency
    let profile_url = format!(
        "https://api.cloudflare.com/client/v4/accounts/{}/billing/profile",
        creds.account_id
    );
    let profile_resp = http
        .get(&profile_url)
        .bearer_auth(&creds.api_token)
        .send()
        .await?;
    if !profile_resp.status().is_success() {
        return Err(anyhow!(
            "CF billing profile ({}): {}",
            profile_resp.status(),
            profile_resp.text().await?
        ));
    }
    let profile: serde_json::Value = profile_resp.json().await?;
    let _currency = profile["result"]["currency"]
        .as_str()
        .unwrap_or("USD")
        .to_string();

    // Fetch subscriptions for itemised breakdown
    let subs_url = format!(
        "https://api.cloudflare.com/client/v4/accounts/{}/subscriptions",
        creds.account_id
    );
    let subs_resp = http
        .get(&subs_url)
        .bearer_auth(&creds.api_token)
        .send()
        .await?;
    if !subs_resp.status().is_success() {
        return Ok(Vec::new());
    }

    let subs: serde_json::Value = subs_resp.json().await?;
    let now = Utc::now().date_naive();

    Ok(subs["result"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|sub| {
            let price = sub["price"].as_f64().unwrap_or(0.0);
            if price == 0.0 {
                return None;
            }
            let service = sub["component_values"][0]["name"]
                .as_str()
                .unwrap_or("subscription")
                .to_string();
            Some(CostEntry {
                service,
                amount_usd: price,
                period_start: now - chrono::Duration::days(30),
                period_end: now,
            })
        })
        .collect())
}
