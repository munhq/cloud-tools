//! Shared plumbing for the GCP service modules.
//!
//! `list_regions` had three byte-identical copies, in cloud_nat, cloud_vpn and
//! artifact_registry. Each one also called the API separately, so a scan that
//! touched all three listed the project's regions three times.

use anyhow::{anyhow, Result};
use reqwest::Client;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Cached region lists, keyed by project.
///
/// Regions are enumerated per project, and this server scans several projects in
/// one call, so a single shared list would report one project's regions while
/// walking another.
fn region_cache() -> &'static Mutex<HashMap<String, Vec<String>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Vec<String>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Every region available to this project.
///
/// The three copies of this returned `Ok(Vec::new())` on any non-success status,
/// which is the same silent-failure pattern that made this tool report "$0.00
/// wasted" for accounts it could not read: a disabled Compute API produced an
/// empty region list, every per-region scan then found nothing, and the result
/// looked like a clean account. It returns an error now, and the caller records
/// it against the resource and carries on.
pub(crate) async fn list_regions(http: &Client, token: &str, project: &str) -> Result<Vec<String>> {
    if let Some(hit) = region_cache()
        .lock()
        .ok()
        .and_then(|c| c.get(project).cloned())
    {
        return Ok(hit);
    }

    let url = format!("https://compute.googleapis.com/compute/v1/projects/{project}/regions");
    let resp = http.get(&url).bearer_auth(token).send().await?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(anyhow!(
            "Could not list regions for project {project} (HTTP {status}): enable \
             compute.googleapis.com and check the credentials have permission. \
             Every per-region scan depends on this. Response: {}",
            text.chars().take(200).collect::<String>()
        ));
    }

    let data: serde_json::Value = resp.json().await?;
    let regions: Vec<String> = data["items"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|r| r["name"].as_str().map(String::from))
        .collect();

    if let Ok(mut c) = region_cache().lock() {
        c.insert(project.to_string(), regions.clone());
    }
    Ok(regions)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Keyed per project, because one call scans several and each has its own
    /// set of enabled regions.
    #[test]
    fn the_region_cache_is_keyed_per_project() {
        let cache = region_cache();
        {
            let mut c = cache.lock().unwrap();
            c.insert("project-a".into(), vec!["europe-west1".into()]);
            c.insert(
                "project-b".into(),
                vec!["us-central1".into(), "asia-east1".into()],
            );
        }
        let c = cache.lock().unwrap();
        assert_eq!(c.get("project-a").unwrap().len(), 1);
        assert_eq!(c.get("project-b").unwrap().len(), 2);
        assert!(c.get("project-unknown").is_none());
    }
}
