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
        "https://compute.googleapis.com/compute/v1/projects/{project}/aggregatedList/instances?maxResults=500"
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
            if parts.len() == 2 { Some(parts[1].to_string()) } else { None }
        });

        for inst in zone_data["instances"].as_array().cloned().unwrap_or_default() {
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
        for rec in data["recommendations"].as_array().cloned().unwrap_or_default() {
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
