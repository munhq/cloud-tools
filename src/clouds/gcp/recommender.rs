//! GCP Recommender API — fetches recommendations across all resource types.
//!
//! Queries multiple recommender types (idle VMs, rightsizing, idle disks,
//! idle IPs, Cloud SQL) across all zones/regions. This is GCP's equivalent
//! of AWS Compute Optimizer.

use anyhow::Result;
use futures::future::join_all;
use reqwest::Client;

use super::auth::{access_token, GcpCreds};

#[derive(Debug, Clone)]
pub struct GcpRecommendation {
    pub recommender_type: String, // e.g. "google.compute.instance.MachineTypeRecommender"
    pub subtype: String,          // e.g. "CHANGE_MACHINE_TYPE"
    pub resource_name: String,
    pub description: String,
    pub estimated_monthly_savings_usd: f64,
    pub location: String, // zone or region
    pub state: String,    // "ACTIVE"
}

/// Recommender types to query.
const RECOMMENDER_TYPES: &[&str] = &[
    "google.compute.instance.IdleResourceRecommender",
    "google.compute.instance.MachineTypeRecommender",
    "google.compute.disk.IdleResourceRecommender",
    "google.compute.address.IdleResourceRecommender",
    "google.cloudsql.instance.IdleRecommender",
    "google.cloudsql.instance.OverprovisionedRecommender",
];

/// Fetch all active recommendations across all zones and regions.
pub async fn get_recommendations(
    http: &Client,
    creds: &GcpCreds,
) -> Result<Vec<GcpRecommendation>> {
    let token = access_token(http, creds).await?;
    let locations = list_locations(http, &token, &creds.project_id).await?;

    // Query each (location, recommender_type) pair in parallel
    let tasks: Vec<_> = locations
        .iter()
        .flat_map(|loc| {
            let token = token.clone();
            RECOMMENDER_TYPES.iter().map(move |rtype| {
                let http = http.clone();
                let token = token.clone();
                let project = creds.project_id.clone();
                let loc = loc.clone();
                let rtype = rtype.to_string();
                async move { fetch_recommendations(&http, &token, &project, &loc, &rtype).await }
            })
        })
        .collect();

    let results = join_all(tasks).await;
    Ok(results
        .into_iter()
        .filter_map(|r| r.ok())
        .flatten()
        .collect())
}

async fn list_locations(http: &Client, token: &str, project: &str) -> Result<Vec<String>> {
    // Get zones (for compute recommenders)
    let url = format!("https://compute.googleapis.com/compute/v1/projects/{project}/zones");
    let resp = http.get(&url).bearer_auth(token).send().await?;
    if !resp.status().is_success() {
        return Ok(Vec::new());
    }
    let data: serde_json::Value = resp.json().await?;
    let mut locations: Vec<String> = data["items"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|z| z["name"].as_str().map(String::from))
        .collect();

    // Also add regions (for Cloud SQL recommenders)
    let url = format!("https://compute.googleapis.com/compute/v1/projects/{project}/regions");
    let resp = http.get(&url).bearer_auth(token).send().await?;
    if resp.status().is_success() {
        let data: serde_json::Value = resp.json().await?;
        for r in data["items"].as_array().cloned().unwrap_or_default() {
            if let Some(name) = r["name"].as_str() {
                locations.push(name.to_string());
            }
        }
    }

    Ok(locations)
}

async fn fetch_recommendations(
    http: &Client,
    token: &str,
    project: &str,
    location: &str,
    recommender_type: &str,
) -> Result<Vec<GcpRecommendation>> {
    let url = format!(
        "https://recommender.googleapis.com/v1/projects/{project}/locations/{location}/recommenders/{recommender_type}/recommendations"
    );

    let resp = http.get(&url).bearer_auth(token).send().await?;
    if !resp.status().is_success() {
        return Ok(Vec::new()); // Recommender not available in this location
    }

    let data: serde_json::Value = resp.json().await?;

    Ok(data["recommendations"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|rec| {
            let state = rec["stateInfo"]["state"].as_str().unwrap_or("");
            if state != "ACTIVE" {
                return None;
            }

            let resource_name = rec["content"]["overview"]["resourceName"]
                .as_str()
                .or_else(|| rec["content"]["overview"]["resource"].as_str())
                .unwrap_or("")
                .to_string();

            let description = rec["description"].as_str().unwrap_or("").to_string();

            let subtype = rec["recommenderSubtype"].as_str().unwrap_or("").to_string();

            // Extract savings — can be in units (string) or nanos
            let cost = &rec["primaryImpact"]["costProjection"]["cost"];
            let units = cost["units"]
                .as_str()
                .and_then(|s| s.parse::<f64>().ok())
                .unwrap_or(0.0);
            let nanos = cost["nanos"].as_i64().unwrap_or(0) as f64 / 1_000_000_000.0;
            let savings = (units + nanos).abs();

            // Duration is typically per month but the API returns it as a duration
            // "cost" is negative for savings recommendations
            let monthly_savings = if savings > 0.0 { savings } else { 0.0 };

            Some(GcpRecommendation {
                recommender_type: recommender_type.to_string(),
                subtype,
                resource_name,
                description,
                estimated_monthly_savings_usd: monthly_savings,
                location: location.to_string(),
                state: state.to_string(),
            })
        })
        .collect())
}
