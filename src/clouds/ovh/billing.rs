use anyhow::Result;
use chrono::Utc;
use reqwest::Client;

use crate::types::CostEntry;

use super::auth::{get, OvhCreds};

pub async fn get_costs(http: &Client, creds: &OvhCreds) -> Result<Vec<CostEntry>> {
    let bill_ids: Vec<String> =
        serde_json::from_value(get(http, creds, "/me/bill").await?).unwrap_or_default();

    let now = Utc::now().date_naive();
    let mut entries = Vec::new();
    for id in bill_ids.into_iter().take(6) {
        let bill = get(http, creds, &format!("/me/bill/{id}")).await?;
        let amount = bill["priceWithTax"]["value"].as_f64().unwrap_or(0.0);
        let date_str = bill["date"].as_str().unwrap_or("");
        // Bill date is ISO-8601; parse to NaiveDate
        let date = chrono::NaiveDate::parse_from_str(
            date_str.get(..10).unwrap_or(date_str),
            "%Y-%m-%d",
        )
        .unwrap_or(now);
        entries.push(CostEntry {
            service: "cloud".into(),
            amount_usd: amount,
            period_start: date,
            period_end: date,
        });
    }
    Ok(entries)
}
