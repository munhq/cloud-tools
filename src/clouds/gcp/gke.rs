//! Google Kubernetes Engine cluster inventory.

use anyhow::{anyhow, Result};
use reqwest::Client;

use super::auth::{access_token, GcpCreds};

#[derive(Debug, Clone)]
pub struct GkeCluster {
    pub name: String,
    pub location: String, // e.g. "us-central1" or "us-central1-a"
    pub status: String,   // "RUNNING", "PROVISIONING", "STOPPING", etc.
    pub node_count: u32,  // total nodes across all pools
    pub node_pools: Vec<GkeNodePool>,
}

#[derive(Debug, Clone)]
pub struct GkeNodePool {
    pub name: String,
    pub machine_type: String,
    pub node_count: u32,
    pub autoscaling_enabled: bool,
    pub min_node_count: u32,
    pub max_node_count: u32,
}

pub async fn list_clusters(http: &Client, creds: &GcpCreds) -> Result<Vec<GkeCluster>> {
    let token = access_token(http, creds).await?;
    // locations/- means all regions and zones
    let url = format!(
        "https://container.googleapis.com/v1/projects/{}/locations/-/clusters",
        creds.project_id
    );
    let resp = http.get(&url).bearer_auth(&token).send().await?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await?;

        // A 403 or a 404 is NOT an empty result, and returning one made this

        // tool answer "nothing here" when the truth was "not allowed to look"

        // or "no such project". A caller that scans several projects still

        // survives this: the inventory records the failure against the

        // resource and carries on with the rest.

        if status.as_u16() == 403 || status.as_u16() == 404 {
            return Err(anyhow!(
                "GKE could not be read for project {} (HTTP {}): enable container.googleapis.com \
                 and check the credentials have permission. Response: {}",
                creds.project_id,
                status,
                text.chars().take(200).collect::<String>()
            ));
        }
        return Err(anyhow!("GKE API error {status}: {text}"));
    }

    let data: serde_json::Value = resp.json().await?;
    Ok(data["clusters"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|c| {
            let name = c["name"].as_str()?.to_string();
            let location = c["location"].as_str().unwrap_or("").to_string();
            let status = c["status"].as_str().unwrap_or("UNKNOWN").to_string();
            let node_count = c["currentNodeCount"].as_u64().unwrap_or(0) as u32;

            let node_pools = c["nodePools"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|np| {
                    let np_name = np["name"].as_str()?.to_string();
                    let machine_type = np["config"]["machineType"]
                        .as_str()
                        .unwrap_or("unknown")
                        .to_string();
                    let np_count = np["initialNodeCount"].as_u64().unwrap_or(0) as u32;
                    let autoscaling = np["autoscaling"]["enabled"].as_bool().unwrap_or(false);
                    let min = np["autoscaling"]["minNodeCount"].as_u64().unwrap_or(0) as u32;
                    let max = np["autoscaling"]["maxNodeCount"].as_u64().unwrap_or(0) as u32;

                    Some(GkeNodePool {
                        name: np_name,
                        machine_type,
                        node_count: np_count,
                        autoscaling_enabled: autoscaling,
                        min_node_count: min,
                        max_node_count: max,
                    })
                })
                .collect();

            Some(GkeCluster {
                name,
                location,
                status,
                node_count,
                node_pools,
            })
        })
        .collect())
}
