//! Google Cloud SQL instance inventory.

use anyhow::{anyhow, Result};
use reqwest::Client;

use super::auth::{access_token, GcpCreds};

#[derive(Debug, Clone)]
pub struct CloudSqlInstance {
    pub name: String,
    pub database_version: String, // e.g. "POSTGRES_15", "MYSQL_8_0"
    pub tier: String,             // e.g. "db-custom-2-7680", "db-f1-micro"
    pub state: String,            // "RUNNABLE", "STOPPED", "SUSPENDED"
    pub region: String,
    pub data_disk_size_gb: u64,
    pub data_disk_type: String,   // "PD_SSD", "PD_HDD"
}

pub async fn list_instances(
    http: &Client,
    creds: &GcpCreds,
) -> Result<Vec<CloudSqlInstance>> {
    let token = access_token(http, creds).await?;
    let url = format!(
        "https://sqladmin.googleapis.com/v1/projects/{}/instances",
        creds.project_id
    );
    let resp = http.get(&url).bearer_auth(&token).send().await?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await?;
        if status.as_u16() == 403 || status.as_u16() == 404 {
            return Ok(Vec::new()); // API not enabled or no permission
        }
        return Err(anyhow!("Cloud SQL API error {status}: {text}"));
    }

    let data: serde_json::Value = resp.json().await?;
    Ok(data["items"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|inst| {
            let name = inst["name"].as_str()?.to_string();
            let state = inst["state"].as_str().unwrap_or("UNKNOWN").to_string();
            let region = inst["region"].as_str().unwrap_or("").to_string();
            let tier = inst["settings"]["tier"].as_str().unwrap_or("").to_string();
            let db_version = inst["databaseVersion"].as_str().unwrap_or("").to_string();
            let disk_size = inst["settings"]["dataDiskSizeGb"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let disk_type = inst["settings"]["dataDiskType"]
                .as_str()
                .unwrap_or("PD_SSD")
                .to_string();

            Some(CloudSqlInstance {
                name,
                database_version: db_version,
                tier,
                state,
                region,
                data_disk_size_gb: disk_size,
                data_disk_type: disk_type,
            })
        })
        .collect())
}
