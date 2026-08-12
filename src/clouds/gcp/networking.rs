//! GCP networking inventory — subnets, flow logs, and Private Service Connect.

use anyhow::Result;
use reqwest::Client;
use serde_json::Value;

use super::auth::{access_token, GcpCreds};

#[derive(Debug, Clone)]
pub struct GcpSubnet {
    pub name: String,
    pub region: String,
    pub ip_cidr_range: String,
    pub flow_logs_enabled: bool,
    pub flow_sampling: f64, // 0.0 to 1.0, only meaningful if flow_logs_enabled
    pub purpose: String,    // "PRIVATE", "REGIONAL_MANAGED_PROXY", etc.
}

/// List all subnetworks across all regions, including flow log configuration.
///
/// Note: `aggregatedList/subnetworks` does NOT exist in the GCP Compute API,
/// so we must list regions first, then fetch subnets per region in parallel.
pub async fn list_subnetworks(
    http: &Client,
    creds: &GcpCreds,
) -> Result<Vec<GcpSubnet>> {
    let token = access_token(http, creds).await?;
    let project = &creds.project_id;

    // List all regions
    let regions_url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{project}/regions"
    );
    let resp = http.get(&regions_url).bearer_auth(&token).send().await?;
    if !resp.status().is_success() {
        return Ok(Vec::new());
    }
    let data: Value = resp.json().await?;
    let regions: Vec<String> = data["items"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|r| r["name"].as_str().map(String::from))
        .collect();

    // Fetch subnets per region in parallel
    let tasks: Vec<_> = regions
        .iter()
        .map(|region| {
            let http = http.clone();
            let token = token.clone();
            let project = project.clone();
            let region = region.clone();
            async move {
                let url = format!(
                    "https://compute.googleapis.com/compute/v1/projects/{project}/regions/{region}/subnetworks"
                );
                let resp = http.get(&url).bearer_auth(&token).send().await;
                let resp = match resp {
                    Ok(r) => r,
                    Err(_) => return Vec::new(),
                };
                if !resp.status().is_success() {
                    return Vec::new();
                }
                let data: Value = match resp.json().await {
                    Ok(d) => d,
                    Err(_) => return Vec::new(),
                };

                data["items"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|subnet| {
                        let name = subnet["name"].as_str()?.to_string();
                        let ip_cidr_range =
                            subnet["ipCidrRange"].as_str().unwrap_or("").to_string();
                        let flow_logs_enabled =
                            subnet["logConfig"]["enable"].as_bool().unwrap_or(false);
                        let flow_sampling =
                            subnet["logConfig"]["flowSampling"].as_f64().unwrap_or(0.0);
                        let purpose =
                            subnet["purpose"].as_str().unwrap_or("PRIVATE").to_string();

                        Some(GcpSubnet {
                            name,
                            region: region.clone(),
                            ip_cidr_range,
                            flow_logs_enabled,
                            flow_sampling,
                            purpose,
                        })
                    })
                    .collect::<Vec<_>>()
            }
        })
        .collect();

    let results = futures::future::join_all(tasks).await;
    Ok(results.into_iter().flatten().collect())
}

#[derive(Debug, Clone)]
pub struct PscEndpoint {
    pub name: String,
    pub region: String,
    pub address: String,
    pub target: String,  // service attachment URL
    pub status: String,
}

/// List Private Service Connect forwarding rule endpoints.
///
/// PSC forwarding rules are identified by having a `pscConnectionId` field
/// and an empty `loadBalancingScheme`.
pub async fn list_psc_endpoints(
    http: &Client,
    token: &str,
    project: &str,
) -> Result<Vec<PscEndpoint>> {
    let mut out = Vec::new();

    // Check global forwarding rules
    let global_url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{project}/global/forwardingRules"
    );
    collect_psc_rules(http, token, &global_url, &mut out).await?;

    // Check regional forwarding rules via aggregatedList
    let agg_url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{project}/aggregated/forwardingRules"
    );
    let resp = http.get(&agg_url).bearer_auth(token).send().await?;
    if resp.status().is_success() {
        let data: Value = resp.json().await?;
        for (_scope_key, scope_data) in data["items"].as_object().cloned().unwrap_or_default() {
            for rule in scope_data["forwardingRules"].as_array().cloned().unwrap_or_default() {
                if let Some(endpoint) = extract_psc_endpoint(&rule) {
                    out.push(endpoint);
                }
            }
        }
    }

    Ok(out)
}

/// Fetch forwarding rules from a URL and collect any that are PSC endpoints.
async fn collect_psc_rules(
    http: &Client,
    token: &str,
    url: &str,
    out: &mut Vec<PscEndpoint>,
) -> Result<()> {
    let resp = http.get(url).bearer_auth(token).send().await?;
    if !resp.status().is_success() {
        // Non-fatal: global forwarding rules may not exist
        return Ok(());
    }

    let data: Value = resp.json().await?;
    for rule in data["items"].as_array().cloned().unwrap_or_default() {
        if let Some(endpoint) = extract_psc_endpoint(&rule) {
            out.push(endpoint);
        }
    }

    Ok(())
}

/// Check if a forwarding rule is a PSC endpoint and extract its fields.
///
/// PSC forwarding rules have `loadBalancingScheme: ""` (empty) and a
/// `pscConnectionId` field, or their `target` contains `serviceAttachments`.
fn extract_psc_endpoint(rule: &Value) -> Option<PscEndpoint> {
    let has_psc_id = rule.get("pscConnectionId").is_some();
    let target = rule["target"].as_str().unwrap_or("");
    let has_service_attachment = target.contains("serviceAttachments");

    if !has_psc_id && !has_service_attachment {
        return None;
    }

    let name = rule["name"].as_str().unwrap_or("").to_string();

    // Extract region from the selfLink or region field
    let region = rule["region"]
        .as_str()
        .and_then(|r| r.rsplit('/').next())
        .unwrap_or("global")
        .to_string();

    let address = rule["IPAddress"].as_str().unwrap_or("").to_string();
    let status = rule["pscConnectionStatus"]
        .as_str()
        .unwrap_or("UNKNOWN")
        .to_string();

    Some(PscEndpoint {
        name,
        region,
        address,
        target: target.to_string(),
        status,
    })
}
