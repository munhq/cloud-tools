use anyhow::{anyhow, Result};
use chrono::Utc;
use reqwest::Client;
use serde_json::Value;

use super::auth::CloudflareCreds;

pub struct CfResource {
    pub provider: &'static str,
    pub resource_id: String,
    pub resource_type: &'static str,
    pub name: Option<String>,
    pub last_active_at: Option<String>,
    pub raw: Value,
}

pub async fn list_resources(http: &Client, creds: &CloudflareCreds) -> Result<Vec<CfResource>> {
    let mut out = Vec::new();
    out.extend(list_workers(http, creds).await?);
    out.extend(list_zones(http, creds).await?);
    Ok(out)
}

async fn list_workers(http: &Client, creds: &CloudflareCreds) -> Result<Vec<CfResource>> {
    let now = Utc::now();
    let start = now - chrono::Duration::days(30);
    let query = serde_json::json!({
        "query": "query WorkerAnalytics($accountTag: string!, $datetimeStart: string!, $datetimeEnd: string!) { viewer { accounts(filter: {accountTag: $accountTag}) { workersInvocationsAdaptive(limit: 10000 filter: {datetime_geq: $datetimeStart, datetime_leq: $datetimeEnd} orderBy: [scriptName_ASC]) { dimensions { scriptName } sum { requests } } } } }",
        "variables": {
            "accountTag": creds.account_id,
            "datetimeStart": start.to_rfc3339(),
            "datetimeEnd": now.to_rfc3339(),
        }
    });

    let resp = http
        .post("https://api.cloudflare.com/client/v4/graphql")
        .bearer_auth(&creds.api_token)
        .json(&query)
        .send()
        .await?;
    if !resp.status().is_success() {
        tracing::warn!("CF Workers GraphQL ({}): skipping", resp.status());
        return Ok(Vec::new());
    }

    let data: Value = resp.json().await?;
    let rows = data["data"]["viewer"]["accounts"][0]["workersInvocationsAdaptive"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    Ok(rows
        .into_iter()
        .map(|row| {
            let name = row["dimensions"]["scriptName"]
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            let requests = row["sum"]["requests"].as_i64().unwrap_or(0);
            CfResource {
                provider: "cloudflare",
                resource_id: format!("worker/{name}"),
                resource_type: "cf_worker",
                name: Some(name),
                last_active_at: if requests > 0 {
                    Some(now.to_rfc3339())
                } else {
                    None
                },
                raw: row,
            }
        })
        .collect())
}

async fn list_zones(http: &Client, creds: &CloudflareCreds) -> Result<Vec<CfResource>> {
    let url = format!(
        "https://api.cloudflare.com/client/v4/zones?account.id={}&per_page=50",
        creds.account_id
    );
    let resp = http.get(&url).bearer_auth(&creds.api_token).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "CF zones ({}): {}",
            resp.status(),
            resp.text().await?
        ));
    }
    let data: Value = resp.json().await?;
    let now = Utc::now();

    Ok(data["result"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|zone| {
            let name = zone["name"].as_str().unwrap_or("unknown").to_string();
            let id = zone["id"].as_str().unwrap_or("").to_string();
            let active = zone["status"].as_str() == Some("active");
            CfResource {
                provider: "cloudflare",
                resource_id: format!("zone/{id}"),
                resource_type: "cf_zone",
                name: Some(name),
                last_active_at: if active { Some(now.to_rfc3339()) } else { None },
                raw: zone,
            }
        })
        .collect())
}
