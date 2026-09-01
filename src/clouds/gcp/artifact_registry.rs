//! Google Artifact Registry repository inventory.
//!
//! The Artifact Registry API does NOT support `locations/-` wildcard, so we must
//! enumerate compute regions plus multi-region locations and query each one.
//! Pricing: $0.10/GB/month for standard storage.

use anyhow::{anyhow, Result};
use reqwest::Client;

use super::auth::{access_token, GcpCreds};
use super::common::list_regions;

#[derive(Debug, Clone)]
pub struct ArtifactRepo {
    pub name: String,   // repo name (e.g. "gcr.io", "docker-repo")
    pub format: String, // "DOCKER", "NPM", "PYTHON", etc.
    pub location: String,
    pub size_bytes: u64,
    pub cleanup_policy_count: usize,
}

/// Multi-region locations where gcr.io repos and other multi-region repos live.
const MULTI_REGION_LOCATIONS: &[&str] = &["us", "europe", "asia"];

pub async fn list_artifact_repos(http: &Client, creds: &GcpCreds) -> Result<Vec<ArtifactRepo>> {
    let token = access_token(http, creds).await?;
    let project = &creds.project_id;

    let mut locations = list_regions(http, &token, project).await?;
    // Add multi-region locations where gcr.io repos typically live
    for mr in MULTI_REGION_LOCATIONS {
        locations.push(mr.to_string());
    }

    let futs: Vec<_> = locations
        .iter()
        .map(|loc| list_repos_in_location(http, &token, project, loc))
        .collect();

    let results = futures::future::join_all(futs).await;

    let mut out = Vec::new();
    for result in results {
        out.extend(result?);
    }
    Ok(out)
}

async fn list_repos_in_location(
    http: &Client,
    token: &str,
    project: &str,
    location: &str,
) -> Result<Vec<ArtifactRepo>> {
    let mut out = Vec::new();
    let mut page_token: Option<String> = None;

    loop {
        let mut url = format!(
            "https://artifactregistry.googleapis.com/v1/projects/{project}/locations/{location}/repositories?pageSize=100"
        );
        if let Some(ref t) = page_token {
            url.push_str(&format!("&pageToken={}", urlencoding::encode(t)));
        }

        let resp = http.get(&url).bearer_auth(token).send().await?;
        let status = resp.status();
        if !status.is_success() {
            // 403 = API not enabled, 404 = location not valid for AR
            if status.as_u16() == 403 || status.as_u16() == 404 {
                return Ok(Vec::new());
            }
            let text = resp.text().await?;
            return Err(anyhow!(
                "Artifact Registry API error {status} for location {location}: {text}"
            ));
        }

        let data: serde_json::Value = resp.json().await?;

        for repo in data["repositories"].as_array().cloned().unwrap_or_default() {
            let full_name = repo["name"].as_str().unwrap_or("").to_string();
            let short_name = full_name.rsplit('/').next().unwrap_or("").to_string();
            let format = repo["format"].as_str().unwrap_or("UNKNOWN").to_string();
            let size_bytes = repo["sizeBytes"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let cleanup_policy_count = repo["cleanupPolicies"]
                .as_object()
                .map(|m| m.len())
                .unwrap_or(0);

            out.push(ArtifactRepo {
                name: short_name,
                format,
                location: location.to_string(),
                size_bytes,
                cleanup_policy_count,
            });
        }

        match data["nextPageToken"].as_str() {
            Some(t) if !t.is_empty() => page_token = Some(t.to_string()),
            _ => break,
        }
    }

    Ok(out)
}
