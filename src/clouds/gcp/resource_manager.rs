//! GCP Cloud Resource Manager — lists projects in an organization.
//!
//! Used for org-wide scanning (equivalent to AWS Organizations).

use anyhow::{anyhow, Result};
use reqwest::Client;

use super::auth::{access_token, GcpCreds};

#[derive(Debug, Clone)]
pub struct GcpProject {
    pub project_id: String,
    pub name: String,
    pub project_number: String,
    pub lifecycle_state: String, // "ACTIVE", "DELETE_REQUESTED", etc.
}

/// List all active projects accessible by the service account.
pub async fn list_projects(
    http: &Client,
    creds: &GcpCreds,
) -> Result<Vec<GcpProject>> {
    let token = access_token(http, creds).await?;
    let mut out = Vec::new();
    let mut page_token: Option<String> = None;

    loop {
        let mut url = "https://cloudresourcemanager.googleapis.com/v1/projects?filter=lifecycleState:ACTIVE&pageSize=100".to_string();
        if let Some(ref t) = page_token {
            url.push_str(&format!("&pageToken={}", urlencoding::encode(t)));
        }

        let resp = http.get(&url).bearer_auth(&token).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await?;
            return Err(anyhow!("Resource Manager error {status}: {text}"));
        }

        let data: serde_json::Value = resp.json().await?;

        for p in data["projects"].as_array().cloned().unwrap_or_default() {
            let project_id = p["projectId"].as_str().unwrap_or("").to_string();
            let name = p["name"].as_str().unwrap_or("").to_string();
            let number = p["projectNumber"].as_str().unwrap_or("").to_string();
            let state = p["lifecycleState"].as_str().unwrap_or("").to_string();

            out.push(GcpProject {
                project_id,
                name,
                project_number: number,
                lifecycle_state: state,
            });
        }

        match data["nextPageToken"].as_str() {
            Some(t) if !t.is_empty() => page_token = Some(t.to_string()),
            _ => break,
        }
    }
    Ok(out)
}
