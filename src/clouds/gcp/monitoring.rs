//! GCP Cloud Monitoring client.
//!
//! Queries `monitoring.googleapis.com/v3` for time-series data (CPU, network,
//! connections, invocations). Used by the waste analyzer for idle/oversized detection.

use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};
use reqwest::Client;

use super::auth::{access_token, GcpCreds};

/// Fetch metric values over the last `days` days for a specific resource.
///
/// Returns a Vec of (aggregated) values — one per alignment period.
/// `aligner` is typically `ALIGN_MEAN` for CPU or `ALIGN_SUM` for counts.
pub async fn get_metric(
    http: &Client,
    creds: &GcpCreds,
    metric_type: &str,
    filter: &str,
    days: u32,
    aligner: &str,
) -> Result<Vec<f64>> {
    let token = access_token(http, creds).await?;
    let now = Utc::now();
    let start = now - Duration::days(days as i64);

    let start_str = start.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let end_str = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let period = "3600s";

    let full_filter = format!(
        "metric.type=\"{}\" AND {}",
        metric_type, filter
    );

    let url = format!(
        "https://monitoring.googleapis.com/v3/projects/{}/timeSeries",
        creds.project_id
    );

    let resp = http
        .get(&url)
        .bearer_auth(&token)
        .query(&[
            ("filter", full_filter.as_str()),
            ("interval.startTime", &start_str),
            ("interval.endTime", &end_str),
            ("aggregation.alignmentPeriod", period),
            ("aggregation.perSeriesAligner", aligner),
        ])
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await?;
        return Err(anyhow!("Cloud Monitoring error {status}: {text}"));
    }

    let data: serde_json::Value = resp.json().await?;

    let mut values = Vec::new();
    for series in data["timeSeries"].as_array().cloned().unwrap_or_default() {
        for point in series["points"].as_array().cloned().unwrap_or_default() {
            if let Some(v) = point["value"]["doubleValue"].as_f64() {
                values.push(v);
            } else if let Some(v) = point["value"]["int64Value"].as_str() {
                if let Ok(n) = v.parse::<f64>() {
                    values.push(n);
                }
            }
        }
    }

    Ok(values)
}

/// Get average CPU utilisation for a GCE instance over `days` days.
/// Returns a value between 0.0 and 1.0 (not percentage).
pub async fn gce_cpu_avg(
    http: &Client,
    creds: &GcpCreds,
    instance_id: &str,
    zone: &str,
    days: u32,
) -> Result<Option<f64>> {
    let filter = format!(
        "resource.type=\"gce_instance\" AND resource.labels.instance_id=\"{}\" AND resource.labels.zone=\"{}\"",
        instance_id, zone
    );
    let values = get_metric(
        http, creds,
        "compute.googleapis.com/instance/cpu/utilization",
        &filter,
        days,
        "ALIGN_MEAN",
    ).await?;

    if values.is_empty() {
        return Ok(None);
    }
    Ok(Some(values.iter().sum::<f64>() / values.len() as f64))
}

/// Get total invocation count for a Cloud Function over `days` days.
pub async fn cloud_function_invocations(
    http: &Client,
    creds: &GcpCreds,
    function_name: &str,
    days: u32,
) -> Result<u64> {
    let filter = format!(
        "resource.type=\"cloud_function\" AND resource.labels.function_name=\"{}\"",
        function_name
    );
    let values = get_metric(
        http, creds,
        "cloudfunctions.googleapis.com/function/execution_count",
        &filter,
        days,
        "ALIGN_SUM",
    ).await?;

    Ok(values.iter().sum::<f64>() as u64)
}

/// Get total request count for a Cloud Run service over `days` days.
pub async fn cloud_run_requests(
    http: &Client,
    creds: &GcpCreds,
    service_name: &str,
    days: u32,
) -> Result<u64> {
    let filter = format!(
        "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"{}\"",
        service_name
    );
    let values = get_metric(
        http, creds,
        "run.googleapis.com/request_count",
        &filter,
        days,
        "ALIGN_SUM",
    ).await?;

    Ok(values.iter().sum::<f64>() as u64)
}

/// Get average CPU utilisation for a Cloud SQL instance over `days` days.
/// Returns a value between 0.0 and 1.0.
pub async fn cloud_sql_cpu_avg(
    http: &Client,
    creds: &GcpCreds,
    instance_id: &str,
    days: u32,
) -> Result<Option<f64>> {
    let filter = format!(
        "resource.type=\"cloudsql_database\" AND resource.labels.database_id=\"{}:{}\"",
        creds.project_id, instance_id
    );
    let values = get_metric(
        http, creds,
        "cloudsql.googleapis.com/database/cpu/utilization",
        &filter,
        days,
        "ALIGN_MEAN",
    ).await?;

    if values.is_empty() {
        return Ok(None);
    }
    Ok(Some(values.iter().sum::<f64>() / values.len() as f64))
}

/// Get total Cloud Logging bytes ingested over the last `days` days.
/// Uses the `logging.googleapis.com/byte_count` metric from Cloud Monitoring.
/// Returns total bytes ingested (sum across all log types).
pub async fn logging_bytes_ingested(
    http: &Client,
    creds: &GcpCreds,
    days: u32,
) -> Result<u64> {
    let token = access_token(http, creds).await?;
    let now = Utc::now();
    let start = now - Duration::days(days as i64);

    let start_str = start.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let end_str = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let alignment_period = format!("{}s", days as u64 * 86400);

    let url = format!(
        "https://monitoring.googleapis.com/v3/projects/{}/timeSeries",
        creds.project_id
    );

    let resp = http
        .get(&url)
        .bearer_auth(&token)
        .header("x-goog-user-project", &creds.project_id)
        .query(&[
            ("filter", "metric.type=\"logging.googleapis.com/byte_count\""),
            ("interval.startTime", &start_str),
            ("interval.endTime", &end_str),
            ("aggregation.alignmentPeriod", &alignment_period),
            ("aggregation.perSeriesAligner", "ALIGN_SUM"),
            ("aggregation.crossSeriesReducer", "REDUCE_SUM"),
        ])
        .send()
        .await?;

    if !resp.status().is_success() {
        // Return 0 on API errors (permission denied, API not enabled, etc.)
        let _text = resp.text().await?;
        return Ok(0);
    }

    let data: serde_json::Value = resp.json().await?;

    let mut total: u64 = 0;
    for series in data["timeSeries"].as_array().cloned().unwrap_or_default() {
        for point in series["points"].as_array().cloned().unwrap_or_default() {
            if let Some(v) = point["value"]["int64Value"].as_str() {
                if let Ok(n) = v.parse::<u64>() {
                    total = total.saturating_add(n);
                }
            } else if let Some(v) = point["value"]["doubleValue"].as_f64() {
                total = total.saturating_add(v as u64);
            }
        }
    }

    Ok(total)
}
