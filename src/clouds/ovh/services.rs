use anyhow::Result;
use reqwest::Client;

use super::auth::{get, OvhCreds};

#[derive(Debug, Clone)]
pub struct OvhService {
    pub service_id: String,
    pub service_type: String,
    pub display_name: Option<String>,
    pub status: String,
    pub creation_date: Option<String>,
    pub expiration_date: Option<String>,
    pub renew_type: Option<String>,
    pub can_delete: bool,
    pub monthly_cost: Option<f64>,
}

/// List all OVH services with their renewal/billing details.
///
/// Fetches `/services` for the list of service IDs, then retrieves details
/// for each one sequentially (OVH rate-limits aggressively).
pub async fn list_services(http: &Client, creds: &OvhCreds) -> Result<Vec<OvhService>> {
    let ids_json = get(http, creds, "/services").await?;
    let ids: Vec<u64> = serde_json::from_value(ids_json)?;

    let mut services = Vec::with_capacity(ids.len());

    for chunk in ids.chunks(10) {
        for id in chunk {
            let path = format!("/services/{id}");
            let detail = match get(http, creds, &path).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("Failed to fetch OVH service {id}: {e}");
                    continue;
                }
            };

            let resource = &detail["resource"];
            let billing = &detail["billing"];
            let lifecycle = &billing["lifecycle"]["current"];

            let display_name = resource["displayName"]
                .as_str()
                .or_else(|| resource["name"].as_str())
                .map(String::from);

            let service_type = resource["product"]["name"]
                .as_str()
                .unwrap_or("unknown")
                .to_string();

            let status = resource["state"].as_str().unwrap_or("unknown").to_string();

            let creation_date = lifecycle["creationDate"].as_str().map(String::from);

            let expiration_date = billing["expirationDate"].as_str().map(String::from);

            let renew_type = billing["renew"]["current"]["mode"]
                .as_str()
                .map(String::from);

            let can_delete = billing["lifecycle"]["capacities"]["actions"]
                .as_array()
                .map(|a| a.iter().any(|v| v.as_str() == Some("terminate")))
                .unwrap_or(false);

            let monthly_cost = billing["pricing"]["price"]["value"].as_f64().or_else(|| {
                billing["pricing"]["price"]["value"]
                    .as_str()
                    .and_then(|s| s.parse::<f64>().ok())
            });

            services.push(OvhService {
                service_id: id.to_string(),
                service_type,
                display_name,
                status,
                creation_date,
                expiration_date,
                renew_type,
                can_delete,
                monthly_cost,
            });
        }

        // Small delay between chunks to respect rate limits.
        if chunk.len() == 10 {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    }

    Ok(services)
}
