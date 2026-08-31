//! Google Cloud Run service inventory.

use anyhow::{anyhow, Result};
use reqwest::Client;

use super::auth::{access_token, GcpCreds};

#[derive(Debug, Clone)]
pub struct CloudRunService {
    pub name: String,
    pub full_name: String,
    pub region: String,
    pub uri: Option<String>, // serving URL
    pub update_time: Option<String>,
    pub latest_ready_revision: Option<String>,
}

pub async fn list_services(http: &Client, creds: &GcpCreds) -> Result<Vec<CloudRunService>> {
    let token = access_token(http, creds).await?;
    let mut out = Vec::new();
    let mut page_token: Option<String> = None;

    loop {
        let mut url = format!(
            "https://run.googleapis.com/v2/projects/{}/locations/-/services?pageSize=100",
            creds.project_id
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

                    "Cloud Run could not be read for project {} (HTTP {}): enable run.googleapis.com \
                     and check the credentials have permission. Response: {}",

                    creds.project_id, status, text.chars().take(200).collect::<String>()

                ));
            }
            return Err(anyhow!("Cloud Run API error {status}: {text}"));
        }

        let data: serde_json::Value = resp.json().await?;

        for svc in data["services"].as_array().cloned().unwrap_or_default() {
            let full_name = svc["name"].as_str().unwrap_or("").to_string();
            let short_name = full_name.rsplit('/').next().unwrap_or("").to_string();
            let region = full_name
                .split("/locations/")
                .nth(1)
                .and_then(|s| s.split('/').next())
                .unwrap_or("")
                .to_string();
            let uri = svc["uri"].as_str().map(String::from);
            let update_time = svc["updateTime"].as_str().map(String::from);
            let latest = svc["latestReadyRevision"].as_str().map(String::from);

            out.push(CloudRunService {
                name: short_name,
                full_name,
                region,
                uri,
                update_time,
                latest_ready_revision: latest,
            });
        }

        match data["nextPageToken"].as_str() {
            Some(t) if !t.is_empty() => page_token = Some(t.to_string()),
            _ => break,
        }
    }

    Ok(out)
}
