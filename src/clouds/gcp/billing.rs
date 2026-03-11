use anyhow::Result;
use chrono::Utc;
use reqwest::Client;

use crate::types::CostEntry;

use super::auth::{access_token, GcpCreds};

pub async fn get_costs(http: &Client, creds: &GcpCreds) -> Result<Vec<CostEntry>> {
    let token = access_token(http, creds).await?;
    let end = Utc::now().date_naive();
    let start = end - chrono::Duration::days(30);

    let url = format!(
        "https://billingbudgets.googleapis.com/v1/billingAccounts/{}/budgets",
        creds.billing_account_id
    );
    let resp = http.get(&url).bearer_auth(&token).send().await?;
    if !resp.status().is_success() {
        tracing::warn!(
            "GCP billing budgets not accessible ({}); enable Cloud Billing Budget API or use BigQuery export",
            resp.status()
        );
        return Ok(Vec::new());
    }

    let data: serde_json::Value = resp.json().await?;
    Ok(data["budgets"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|b| {
            let amount = b["amount"]["specifiedAmount"]["units"]
                .as_str()
                .and_then(|s| s.parse::<f64>().ok())
                .unwrap_or(0.0);
            if amount == 0.0 {
                return None;
            }
            Some(CostEntry {
                service: b["displayName"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string(),
                amount_usd: amount,
                period_start: start,
                period_end: end,
            })
        })
        .collect())
}
