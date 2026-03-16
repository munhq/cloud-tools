//! GCP Committed Use Discounts (CUDs).
//!
//! Lists active and expiring commitments for Compute Engine resources.

use anyhow::Result;
use reqwest::Client;

use super::auth::{access_token, GcpCreds};

#[derive(Debug, Clone)]
pub struct Commitment {
    pub name: String,
    pub region: String,
    pub status: String,        // "ACTIVE", "EXPIRED", "NOT_YET_ACTIVE"
    pub plan: String,          // "TWELVE_MONTH", "THIRTY_SIX_MONTH"
    pub start_timestamp: Option<String>,
    pub end_timestamp: Option<String>,
    pub category: String,      // "MACHINE_IMAGES_E2", "GENERAL_PURPOSE_N2", etc.
    /// Resources committed (vCPUs, memory GB).
    pub resources: Vec<CommittedResource>,
}

#[derive(Debug, Clone)]
pub struct CommittedResource {
    pub resource_type: String, // "VCPU", "MEMORY"
    pub amount: f64,
}

pub async fn list_commitments(
    http: &Client,
    creds: &GcpCreds,
) -> Result<Vec<Commitment>> {
    let token = access_token(http, creds).await?;
    let url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{}/aggregatedList/commitments",
        creds.project_id
    );
    let resp = http.get(&url).bearer_auth(&token).send().await?;
    if !resp.status().is_success() {
        return Ok(Vec::new());
    }

    let data: serde_json::Value = resp.json().await?;
    let mut out = Vec::new();

    for (_key, region_data) in data["items"].as_object().cloned().unwrap_or_default() {
        for c in region_data["commitments"].as_array().cloned().unwrap_or_default() {
            let name = c["name"].as_str().unwrap_or("").to_string();
            let region = c["region"]
                .as_str()
                .and_then(|r| r.rsplit('/').next())
                .unwrap_or("")
                .to_string();
            let status = c["status"].as_str().unwrap_or("").to_string();
            let plan = c["plan"].as_str().unwrap_or("").to_string();
            let start = c["startTimestamp"].as_str().map(String::from);
            let end = c["endTimestamp"].as_str().map(String::from);
            let category = c["category"].as_str().unwrap_or("").to_string();

            let resources = c["resources"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|r| {
                    let rtype = r["type"].as_str()?.to_string();
                    let amount = r["amount"]
                        .as_str()
                        .and_then(|s| s.parse().ok())
                        .or_else(|| r["amount"].as_f64())
                        .unwrap_or(0.0);
                    Some(CommittedResource {
                        resource_type: rtype,
                        amount,
                    })
                })
                .collect();

            out.push(Commitment {
                name, region, status, plan, start_timestamp: start,
                end_timestamp: end, category, resources,
            });
        }
    }
    Ok(out)
}
