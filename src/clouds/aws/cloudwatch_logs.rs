use anyhow::{anyhow, Result};
use futures::future::join_all;

use super::common::list_regions;
use super::auth::{sign, AwsCreds};

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LogGroup {
    pub name: String,
    pub region: String,
    pub stored_bytes: u64,
    pub retention_days: Option<u32>, // None means "never expire"
}

// ── Public API ────────────────────────────────────────────────────────────────

/// List all CloudWatch log groups that have no retention policy (store data indefinitely).
pub async fn list_log_groups_without_retention(
    client: &reqwest::Client,
    creds: &AwsCreds,
) -> Result<Vec<LogGroup>> {
    let regions = list_regions(client, creds).await?;
    let tasks: Vec<_> = regions
        .iter()
        .map(|r| list_log_groups_in_region(client, creds, r))
        .collect();
    let results = join_all(tasks).await;
    Ok(results
        .into_iter()
        .filter_map(|r| r.ok())
        .flatten()
        .collect())
}

// ── Region discovery (reuse EC2 DescribeRegions) ─────────────────────────────

// ── Per-region log group listing ─────────────────────────────────────────────

async fn list_log_groups_in_region(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
) -> Result<Vec<LogGroup>> {
    let mut out = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let body = match &next_token {
            Some(token) => serde_json::json!({ "nextToken": token }).to_string(),
            None => "{}".to_string(),
        };

        let url = format!("https://logs.{region}.amazonaws.com/");
        let creds_for_region = AwsCreds {
            region: region.to_string(),
            ..creds.clone()
        };

        let signed = sign(
            &creds_for_region,
            "POST",
            &url,
            &[
                ("content-type", "application/x-amz-json-1.1"),
                ("x-amz-target", "Logs_20140328.DescribeLogGroups"),
            ],
            body.as_bytes(),
            "logs",
        )?;

        let mut req = client
            .post(&url)
            .header("content-type", "application/x-amz-json-1.1")
            .header("x-amz-target", "Logs_20140328.DescribeLogGroups")
            .header("x-amz-date", &signed.x_amz_date)
            .header("x-amz-content-sha256", &signed.x_amz_content_sha256)
            .header("authorization", &signed.authorization)
            .body(body);
        if let Some(token) = &signed.x_amz_security_token {
            req = req.header("x-amz-security-token", token);
        }

        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(anyhow!(
                "CloudWatch Logs API error {status} in {region}: {text}"
            ));
        }

        let v: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| anyhow!("Failed to parse CloudWatch Logs response in {region}: {e}"))?;

        if let Some(log_groups) = v["logGroups"].as_array() {
            for lg in log_groups {
                let retention = lg["retentionInDays"].as_u64().map(|d| d as u32);
                // Only include log groups without a retention policy
                if retention.is_none() {
                    out.push(LogGroup {
                        name: lg["logGroupName"].as_str().unwrap_or("").to_string(),
                        region: region.to_string(),
                        stored_bytes: lg["storedBytes"].as_u64().unwrap_or(0),
                        retention_days: None,
                    });
                }
            }
        }

        match v["nextToken"].as_str() {
            Some(t) if !t.is_empty() => next_token = Some(t.to_string()),
            _ => break,
        }
    }
    Ok(out)
}

// ── Helpers ──────────────────────────────────────────────────────────────────
