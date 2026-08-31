//! Google Cloud IDS (Intrusion Detection System) endpoint inventory.
//!
//! Lists Cloud IDS endpoints across all locations using the wildcard `-` location.
//! Pricing: $390/mo per endpoint (Palo Alto managed firewall) -- very expensive.

use anyhow::{anyhow, Result};
use reqwest::Client;

use super::auth::{access_token, GcpCreds};

#[derive(Debug, Clone)]
pub struct CloudIdsEndpoint {
    pub name: String,
    pub network: String,
    pub severity: String, // "INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    pub state: String,    // "ACTIVE", "CREATING", etc.
    pub region: String,   // extracted from location in the name field
}

pub async fn list_ids_endpoints(http: &Client, creds: &GcpCreds) -> Result<Vec<CloudIdsEndpoint>> {
    let token = access_token(http, creds).await?;
    let project = &creds.project_id;
    let mut out = Vec::new();
    let mut page_token: Option<String> = None;

    loop {
        let mut url = format!(
            "https://ids.googleapis.com/v1/projects/{project}/locations/-/endpoints?pageSize=100"
        );
        if let Some(ref t) = page_token {
            url.push_str(&format!("&pageToken={}", urlencoding::encode(t)));
        }

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

                    "Cloud IDS could not be read for project {} (HTTP {}): enable ids.googleapis.com \
                     and check the credentials have permission. Response: {}",

                    creds.project_id, status, text.chars().take(200).collect::<String>()

                ));
            }
            return Err(anyhow!("Cloud IDS API error {status}: {text}"));
        }

        let data: serde_json::Value = resp.json().await?;

        for ep in data["endpoints"].as_array().cloned().unwrap_or_default() {
            let full_name = ep["name"].as_str().unwrap_or("").to_string();
            let short_name = full_name.rsplit('/').next().unwrap_or("").to_string();
            // name format: projects/{project}/locations/{location}/endpoints/{name}
            let region = full_name
                .split("/locations/")
                .nth(1)
                .and_then(|s| s.split('/').next())
                .unwrap_or("")
                .to_string();
            let network = ep["network"].as_str().unwrap_or("").to_string();
            let severity = ep["severity"]
                .as_str()
                .unwrap_or("INFORMATIONAL")
                .to_string();
            let state = ep["state"].as_str().unwrap_or("UNKNOWN").to_string();

            out.push(CloudIdsEndpoint {
                name: short_name,
                network,
                severity,
                state,
                region,
            });
        }

        match data["nextPageToken"].as_str() {
            Some(t) if !t.is_empty() => page_token = Some(t.to_string()),
            _ => break,
        }
    }

    Ok(out)
}
