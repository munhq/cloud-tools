//! Google Cloud Functions inventory.

use anyhow::{anyhow, Result};
use reqwest::Client;

use super::auth::{access_token, GcpCreds};

#[derive(Debug, Clone)]
pub struct CloudFunction {
    pub name: String,      // short name
    pub full_name: String, // projects/*/locations/*/functions/*
    pub runtime: String,   // e.g. "python311", "nodejs20", "go121"
    pub state: String,     // "ACTIVE", "FAILED", "DEPLOYING"
    pub region: String,
    pub memory_mb: u32,
    pub update_time: Option<String>,
}

pub async fn list_functions(http: &Client, creds: &GcpCreds) -> Result<Vec<CloudFunction>> {
    let token = access_token(http, creds).await?;
    let mut out = Vec::new();
    let mut page_token: Option<String> = None;

    loop {
        let mut url = format!(
            "https://cloudfunctions.googleapis.com/v2/projects/{}/locations/-/functions?pageSize=100",
            creds.project_id
        );
        if let Some(ref token) = page_token {
            url.push_str(&format!("&pageToken={}", urlencoding::encode(token)));
        }

        let resp = http.get(&url).bearer_auth(&token).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await?;
            if status.as_u16() == 403 || status.as_u16() == 404 {
                return Ok(Vec::new());
            }
            return Err(anyhow!("Cloud Functions API error {status}: {text}"));
        }

        let data: serde_json::Value = resp.json().await?;

        for f in data["functions"].as_array().cloned().unwrap_or_default() {
            let full_name = f["name"].as_str().unwrap_or("").to_string();
            let short_name = full_name.rsplit('/').next().unwrap_or("").to_string();
            let region = full_name
                .split("/locations/")
                .nth(1)
                .and_then(|s| s.split('/').next())
                .unwrap_or("")
                .to_string();
            let state = f["state"].as_str().unwrap_or("UNKNOWN").to_string();
            let runtime = f["buildConfig"]["runtime"]
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            let memory_mb = f["serviceConfig"]["availableMemory"]
                .as_str()
                .and_then(|s| {
                    // Format: "256M" or "1Gi"
                    if s.ends_with('M') {
                        s.trim_end_matches('M').parse().ok()
                    } else if s.ends_with("Gi") {
                        s.trim_end_matches("Gi")
                            .parse::<u32>()
                            .ok()
                            .map(|g| g * 1024)
                    } else {
                        s.parse().ok()
                    }
                })
                .unwrap_or(256);
            let update_time = f["updateTime"].as_str().map(String::from);

            out.push(CloudFunction {
                name: short_name,
                full_name,
                runtime,
                state,
                region,
                memory_mb,
                update_time,
            });
        }

        match data["nextPageToken"].as_str() {
            Some(t) if !t.is_empty() => page_token = Some(t.to_string()),
            _ => break,
        }
    }

    Ok(out)
}
