//! AWS ECS cluster and service inventory.
//!
//! Lists ECS clusters and their services across all regions. Used to detect
//! idle clusters (no running tasks) and services scaled to zero.

use anyhow::{anyhow, Result};
use futures::future::join_all;
use serde::Deserialize;

use super::auth::{sign, AwsCreds};

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct EcsService {
    pub cluster_arn: String,
    pub cluster_name: String,
    pub service_arn: String,
    pub service_name: String,
    pub desired_count: u32,
    pub running_count: u32,
    pub launch_type: String,
    pub region: String,
    pub status: String,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// List all ECS services across all regions.
pub async fn list_services(
    client: &reqwest::Client,
    creds: &AwsCreds,
) -> Result<Vec<EcsService>> {
    let regions = list_regions(client, creds).await?;
    let tasks: Vec<_> = regions
        .iter()
        .map(|r| list_in_region(client, creds, r))
        .collect();
    let results = join_all(tasks).await;
    Ok(results.into_iter().filter_map(|r| r.ok()).flatten().collect())
}

// ── Region discovery ─────────────────────────────────────────────────────────

async fn list_regions(client: &reqwest::Client, creds: &AwsCreds) -> Result<Vec<String>> {
    let body = form_params(&[("Action", "DescribeRegions"), ("Version", "2016-11-15")]);
    let url = "https://ec2.us-east-1.amazonaws.com/";
    let creds_for_region = AwsCreds { region: "us-east-1".into(), ..creds.clone() };
    let signed = sign(
        &creds_for_region, "POST", url,
        &[("content-type", "application/x-www-form-urlencoded")],
        body.as_bytes(), "ec2",
    )?;
    let mut req = client.post(url)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("x-amz-date", &signed.x_amz_date)
        .header("x-amz-content-sha256", &signed.x_amz_content_sha256)
        .header("authorization", &signed.authorization)
        .body(body);
    if let Some(t) = &signed.x_amz_security_token { req = req.header("x-amz-security-token", t); }
    let resp = req.send().await?;
    let xml = resp.text().await?;
    let v = super::xml_to_value(&xml)?;
    Ok(super::as_items(&v["regionInfo"]["item"])
        .into_iter()
        .filter_map(|r| r["regionName"].as_str().map(String::from))
        .collect())
}

// ── Per-region listing ───────────────────────────────────────────────────────

async fn list_in_region(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
) -> Result<Vec<EcsService>> {
    // Step 1: List all cluster ARNs
    let cluster_arns = list_cluster_arns(client, creds, region).await?;
    if cluster_arns.is_empty() {
        return Ok(Vec::new());
    }

    // Step 2: For each cluster, list and describe services
    let tasks: Vec<_> = cluster_arns.iter().map(|arn| {
        let client = client.clone();
        let creds = creds.clone();
        let region = region.to_string();
        let arn = arn.clone();
        async move {
            list_services_in_cluster(&client, &creds, &region, &arn).await
        }
    }).collect();

    let results = join_all(tasks).await;
    Ok(results.into_iter().filter_map(|r| r.ok()).flatten().collect())
}

async fn list_cluster_arns(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
) -> Result<Vec<String>> {
    let mut arns = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let body = match &next_token {
            Some(token) => serde_json::json!({"maxResults": 100, "nextToken": token}),
            None => serde_json::json!({"maxResults": 100}),
        };

        let resp = ecs_query(client, creds, region,
            "AmazonEC2ContainerServiceV20141113.ListClusters",
            &serde_json::to_vec(&body)?,
        ).await;

        let resp = match resp {
            Ok(r) => r,
            Err(_) => break, // ECS not available in this region
        };

        if let Some(arr) = resp["clusterArns"].as_array() {
            for arn in arr {
                if let Some(s) = arn.as_str() {
                    arns.push(s.to_string());
                }
            }
        }

        match resp["nextToken"].as_str() {
            Some(t) if !t.is_empty() => next_token = Some(t.to_string()),
            _ => break,
        }
    }
    Ok(arns)
}

async fn list_services_in_cluster(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
    cluster_arn: &str,
) -> Result<Vec<EcsService>> {
    // Step 1: List service ARNs in this cluster
    let mut service_arns = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let body = match &next_token {
            Some(token) => serde_json::json!({
                "cluster": cluster_arn,
                "maxResults": 100,
                "nextToken": token,
            }),
            None => serde_json::json!({
                "cluster": cluster_arn,
                "maxResults": 100,
            }),
        };

        let resp = ecs_query(client, creds, region,
            "AmazonEC2ContainerServiceV20141113.ListServices",
            &serde_json::to_vec(&body)?,
        ).await?;

        if let Some(arr) = resp["serviceArns"].as_array() {
            for arn in arr {
                if let Some(s) = arn.as_str() {
                    service_arns.push(s.to_string());
                }
            }
        }

        match resp["nextToken"].as_str() {
            Some(t) if !t.is_empty() => next_token = Some(t.to_string()),
            _ => break,
        }
    }

    if service_arns.is_empty() {
        return Ok(Vec::new());
    }

    // Step 2: Describe services in batches of 10 (API limit)
    let cluster_name = cluster_arn
        .rsplit('/')
        .next()
        .unwrap_or(cluster_arn)
        .to_string();

    let mut out = Vec::new();
    for chunk in service_arns.chunks(10) {
        let body = serde_json::json!({
            "cluster": cluster_arn,
            "services": chunk,
        });

        let resp = ecs_query(client, creds, region,
            "AmazonEC2ContainerServiceV20141113.DescribeServices",
            &serde_json::to_vec(&body)?,
        ).await?;

        let parsed: DescribeServicesResponse = serde_json::from_value(resp)
            .unwrap_or_default();

        for svc in parsed.services {
            out.push(EcsService {
                cluster_arn: cluster_arn.to_string(),
                cluster_name: cluster_name.clone(),
                service_arn: svc.service_arn.unwrap_or_default(),
                service_name: svc.service_name.unwrap_or_default(),
                desired_count: svc.desired_count.unwrap_or(0),
                running_count: svc.running_count.unwrap_or(0),
                launch_type: svc.launch_type.unwrap_or_else(|| "EC2".into()),
                region: region.to_string(),
                status: svc.status.unwrap_or_else(|| "ACTIVE".into()),
            });
        }
    }
    Ok(out)
}

// ── ECS HTTP helper ──────────────────────────────────────────────────────────

async fn ecs_query(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
    target: &str,
    body: &[u8],
) -> Result<serde_json::Value> {
    let url = format!("https://ecs.{region}.amazonaws.com/");
    let creds_for_region = AwsCreds { region: region.to_string(), ..creds.clone() };

    let signed = sign(
        &creds_for_region,
        "POST",
        &url,
        &[
            ("content-type", "application/x-amz-json-1.1"),
            ("x-amz-target", target),
        ],
        body,
        "ecs",
    )?;

    let mut req = client
        .post(&url)
        .header("content-type", "application/x-amz-json-1.1")
        .header("x-amz-target", target)
        .header("x-amz-date", &signed.x_amz_date)
        .header("x-amz-content-sha256", &signed.x_amz_content_sha256)
        .header("authorization", &signed.authorization)
        .body(body.to_vec());
    if let Some(token) = &signed.x_amz_security_token {
        req = req.header("x-amz-security-token", token);
    }

    let resp = req.send().await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        return Err(anyhow!("ECS API error {status} in {region}: {text}"));
    }
    Ok(serde_json::from_str(&text)?)
}

// ── Response types ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
struct DescribeServicesResponse {
    #[serde(default)]
    services: Vec<ServiceDetail>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServiceDetail {
    service_arn: Option<String>,
    service_name: Option<String>,
    desired_count: Option<u32>,
    running_count: Option<u32>,
    launch_type: Option<String>,
    status: Option<String>,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn form_params(params: &[(&str, &str)]) -> String {
    let mut p = params.to_vec();
    p.sort_by_key(|(k, _)| *k);
    p.iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}
