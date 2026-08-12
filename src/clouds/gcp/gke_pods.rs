//! GKE pod resource utilization — compares requests vs actual usage.
//!
//! Uses Cloud Monitoring `kubernetes.io/container/cpu/request_utilization` and
//! `kubernetes.io/container/memory/request_utilization` metrics to identify
//! over-provisioned pods.

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};
use reqwest::Client;

use super::auth::{access_token, GcpCreds};

#[derive(Debug, Clone)]
pub struct PodResourceUsage {
    pub namespace: String,
    pub container_name: String,
    pub cpu_request_utilization: Option<f64>,
    pub memory_request_utilization: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct NamespaceResourceSummary {
    pub namespace: String,
    pub container_count: usize,
    pub avg_cpu_request_util: f64,
    pub avg_memory_request_util: f64,
    pub containers: Vec<PodResourceUsage>,
}

const SKIP_NAMESPACES: &[&str] = &["kube-system", "gke-managed-system"];

/// Fetch a single Cloud Monitoring metric and return a map of
/// `(namespace, container_name) -> mean value`.
async fn fetch_metric(
    http: &Client,
    token: &str,
    project_id: &str,
    metric_type: &str,
    start_str: &str,
    end_str: &str,
    alignment_period: &str,
) -> Result<HashMap<(String, String), f64>> {
    let url = format!("https://monitoring.googleapis.com/v3/projects/{project_id}/timeSeries");

    let filter = format!("metric.type=\"{metric_type}\"");

    let resp = http
        .get(&url)
        .bearer_auth(token)
        .header("x-goog-user-project", project_id)
        .query(&[
            ("filter", filter.as_str()),
            ("interval.startTime", start_str),
            ("interval.endTime", end_str),
            ("aggregation.alignmentPeriod", alignment_period),
            ("aggregation.perSeriesAligner", "ALIGN_MEAN"),
            ("pageSize", "10000"),
        ])
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await?;
        return Err(anyhow!("Cloud Monitoring error {status}: {text}"));
    }

    let data: serde_json::Value = resp.json().await?;

    let mut map: HashMap<(String, String), f64> = HashMap::new();

    for series in data["timeSeries"].as_array().cloned().unwrap_or_default() {
        let labels = &series["resource"]["labels"];
        let namespace = labels["namespace_name"].as_str().unwrap_or("").to_string();
        let container = labels["container_name"].as_str().unwrap_or("").to_string();

        // Skip system namespaces and unnamed containers.
        if container.is_empty() || SKIP_NAMESPACES.contains(&namespace.as_str()) {
            continue;
        }

        // Take the first (and typically only, given we aligned over the full window) point.
        if let Some(point) = series["points"].as_array().and_then(|a| a.first()) {
            if let Some(v) = point["value"]["doubleValue"].as_f64() {
                map.insert((namespace, container), v);
            }
        }
    }

    Ok(map)
}

/// Query GKE pod resource utilization over the last `days` days.
///
/// Returns per-namespace summaries sorted by ascending average CPU request
/// utilization (most over-provisioned namespaces first).
pub async fn get_pod_resource_usage(
    http: &Client,
    creds: &GcpCreds,
    days: u32,
) -> Result<Vec<NamespaceResourceSummary>> {
    let token = access_token(http, creds).await?;
    let now = Utc::now();
    let start = now - Duration::days(days as i64);

    let start_str = start.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let end_str = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let alignment_period = format!("{}s", days as u64 * 86400);

    let (cpu_result, mem_result) = tokio::join!(
        fetch_metric(
            http,
            &token,
            &creds.project_id,
            "kubernetes.io/container/cpu/request_utilization",
            &start_str,
            &end_str,
            &alignment_period,
        ),
        fetch_metric(
            http,
            &token,
            &creds.project_id,
            "kubernetes.io/container/memory/request_utilization",
            &start_str,
            &end_str,
            &alignment_period,
        ),
    );

    let cpu_map = cpu_result?;
    let mem_map = mem_result?;

    // Merge CPU and memory data. Collect all unique (namespace, container) keys.
    let mut all_keys: std::collections::HashSet<(String, String)> =
        cpu_map.keys().cloned().collect();
    for key in mem_map.keys() {
        all_keys.insert(key.clone());
    }

    // Build per-container entries grouped by namespace.
    let mut by_namespace: HashMap<String, Vec<PodResourceUsage>> = HashMap::new();

    for key in all_keys {
        let usage = PodResourceUsage {
            namespace: key.0.clone(),
            container_name: key.1.clone(),
            cpu_request_utilization: cpu_map.get(&key).copied(),
            memory_request_utilization: mem_map.get(&key).copied(),
        };
        by_namespace.entry(key.0).or_default().push(usage);
    }

    let mut summaries: Vec<NamespaceResourceSummary> = by_namespace
        .into_iter()
        .map(|(namespace, containers)| {
            let count = containers.len();

            let cpu_vals: Vec<f64> = containers
                .iter()
                .filter_map(|c| c.cpu_request_utilization)
                .collect();
            let mem_vals: Vec<f64> = containers
                .iter()
                .filter_map(|c| c.memory_request_utilization)
                .collect();

            let avg_cpu = if cpu_vals.is_empty() {
                0.0
            } else {
                cpu_vals.iter().sum::<f64>() / cpu_vals.len() as f64
            };
            let avg_mem = if mem_vals.is_empty() {
                0.0
            } else {
                mem_vals.iter().sum::<f64>() / mem_vals.len() as f64
            };

            NamespaceResourceSummary {
                namespace,
                container_count: count,
                avg_cpu_request_util: avg_cpu,
                avg_memory_request_util: avg_mem,
                containers,
            }
        })
        .collect();

    // Sort ascending by avg CPU utilization — most over-provisioned first.
    summaries.sort_by(|a, b| {
        a.avg_cpu_request_util
            .partial_cmp(&b.avg_cpu_request_util)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    Ok(summaries)
}
