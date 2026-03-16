//! Google Cloud Storage bucket inventory.

use anyhow::{anyhow, Result};
use reqwest::Client;

use super::auth::{access_token, GcpCreds};

#[derive(Debug, Clone)]
pub struct GcsBucket {
    pub name: String,
    pub location: String,         // e.g. "US", "EU", "us-central1"
    pub storage_class: String,    // "STANDARD", "NEARLINE", "COLDLINE", "ARCHIVE"
    pub has_lifecycle_rules: bool,
    pub versioning_enabled: bool,
}

pub async fn list_buckets(
    http: &Client,
    creds: &GcpCreds,
) -> Result<Vec<GcsBucket>> {
    let token = access_token(http, creds).await?;
    let url = format!(
        "https://storage.googleapis.com/storage/v1/b?project={}",
        creds.project_id
    );
    let resp = http.get(&url).bearer_auth(&token).send().await?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await?;
        if status.as_u16() == 403 || status.as_u16() == 404 {
            return Ok(Vec::new());
        }
        return Err(anyhow!("GCS API error {status}: {text}"));
    }

    let data: serde_json::Value = resp.json().await?;
    Ok(data["items"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|b| {
            let name = b["name"].as_str()?.to_string();
            let location = b["location"].as_str().unwrap_or("").to_string();
            let storage_class = b["storageClass"].as_str().unwrap_or("STANDARD").to_string();
            let has_lifecycle = b["lifecycle"]["rule"]
                .as_array()
                .map(|a| !a.is_empty())
                .unwrap_or(false);
            let versioning = b["versioning"]["enabled"].as_bool().unwrap_or(false);

            Some(GcsBucket {
                name,
                location,
                storage_class,
                has_lifecycle_rules: has_lifecycle,
                versioning_enabled: versioning,
            })
        })
        .collect())
}
