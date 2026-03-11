use anyhow::Result;
use chrono::Utc;
use reqwest::Client;
use serde_json::Value;

use super::auth::{get, OvhCreds};

pub struct OvhResource {
    pub provider: &'static str,
    pub resource_id: String,
    pub resource_type: &'static str,
    pub region: Option<String>,
    pub name: Option<String>,
    pub last_active_at: Option<String>,
    pub raw: Value,
}

pub async fn list_resources(http: &Client, creds: &OvhCreds) -> Result<Vec<OvhResource>> {
    let project_ids: Vec<String> =
        serde_json::from_value(get(http, creds, "/cloud/project").await?).unwrap_or_default();

    let now = Utc::now();
    let mut out = Vec::new();

    for project in project_ids {
        let instances = get(http, creds, &format!("/cloud/project/{project}/instance"))
            .await
            .unwrap_or(Value::Array(Vec::new()));

        for inst in instances.as_array().cloned().unwrap_or_default() {
            let id = inst["id"].as_str().unwrap_or("").to_string();
            let status = inst["status"].as_str().unwrap_or("UNKNOWN");
            out.push(OvhResource {
                provider: "ovh",
                resource_id: format!("{project}/{id}"),
                resource_type: "ovh_instance",
                region: inst["region"].as_str().map(String::from),
                name: inst["name"].as_str().map(String::from),
                last_active_at: if status == "ACTIVE" {
                    Some(now.to_rfc3339())
                } else {
                    None
                },
                raw: inst,
            });
        }
    }
    Ok(out)
}
