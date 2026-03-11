use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};

use super::{as_items, auth::{sign, AwsCreds}, xml_to_value};

/// Average CPU utilisation over the last `days` days for a single resource.
#[derive(Debug, Clone)]
pub struct CpuStats {
    pub resource_id: String,
    pub avg_percent: f64,
    pub max_percent: f64,
    pub sample_count: usize,
}

/// Fetch average CPU utilisation for a list of EC2 instances in the same region.
///
/// Uses 1-hour periods over the last `days` days.
/// Instances with no datapoints (e.g. stopped the whole time) get avg=0.
pub async fn ec2_cpu_stats(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
    instance_ids: &[String],
    days: u32,
) -> Result<Vec<CpuStats>> {
    let mut out = Vec::new();
    for id in instance_ids {
        let stats = get_metric(
            client, creds, region,
            "AWS/EC2", "CPUUtilization",
            &[("InstanceId", id.as_str())],
            days,
        ).await.unwrap_or_default();
        out.push(summarise(id.clone(), stats));
    }
    Ok(out)
}

/// Fetch average CPU utilisation for a list of RDS instances in the same region.
pub async fn rds_cpu_stats(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
    db_ids: &[String],
    days: u32,
) -> Result<Vec<CpuStats>> {
    let mut out = Vec::new();
    for id in db_ids {
        let stats = get_metric(
            client, creds, region,
            "AWS/RDS", "CPUUtilization",
            &[("DBInstanceIdentifier", id.as_str())],
            days,
        ).await.unwrap_or_default();
        out.push(summarise(id.clone(), stats));
    }
    Ok(out)
}

// ── Core metric fetch ─────────────────────────────────────────────────────────

async fn get_metric(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
    namespace: &str,
    metric_name: &str,
    dimensions: &[(&str, &str)],
    days: u32,
) -> Result<Vec<f64>> {
    let end = Utc::now();
    let start = end - Duration::days(days as i64);

    let start_str = start.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let end_str = end.format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let dim_names: Vec<String> = (1..=dimensions.len())
        .map(|i| format!("Dimensions.member.{i}.Name"))
        .collect();
    let dim_values: Vec<String> = (1..=dimensions.len())
        .map(|i| format!("Dimensions.member.{i}.Value"))
        .collect();

    let mut final_params: Vec<(&str, &str)> = vec![
        ("Action", "GetMetricStatistics"),
        ("Version", "2010-08-01"),
        ("Namespace", namespace),
        ("MetricName", metric_name),
        ("StartTime", &start_str),
        ("EndTime", &end_str),
        ("Period", "3600"),
        ("Statistics.member.1", "Average"),
    ];
    for (i, (name, value)) in dimensions.iter().enumerate() {
        final_params.push((dim_names[i].as_str(), name));
        final_params.push((dim_values[i].as_str(), value));
    }

    let body = form_params(&final_params);
    let url = format!("https://monitoring.{region}.amazonaws.com/");
    let creds_for_region = AwsCreds { region: region.to_string(), ..creds.clone() };

    let signed = sign(
        &creds_for_region,
        "POST",
        &url,
        &[("content-type", "application/x-www-form-urlencoded")],
        body.as_bytes(),
        "monitoring",
    )?;

    let mut req = client
        .post(&url)
        .header("content-type", "application/x-www-form-urlencoded")
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
        return Err(anyhow!("CloudWatch error {status}: {text}"));
    }

    let v = xml_to_value(&text)?;
    let datapoints = as_items(&v["GetMetricStatisticsResult"]["Datapoints"]["member"]);
    let values: Vec<f64> = datapoints
        .iter()
        .filter_map(|dp| dp["Average"].as_str()?.parse().ok())
        .collect();

    Ok(values)
}

fn summarise(resource_id: String, values: Vec<f64>) -> CpuStats {
    if values.is_empty() {
        return CpuStats { resource_id, avg_percent: 0.0, max_percent: 0.0, sample_count: 0 };
    }
    let avg = values.iter().sum::<f64>() / values.len() as f64;
    let max = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    CpuStats {
        resource_id,
        avg_percent: (avg * 100.0).round() / 100.0,
        max_percent: (max * 100.0).round() / 100.0,
        sample_count: values.len(),
    }
}

fn form_params(params: &[(&str, &str)]) -> String {
    let mut p = params.to_vec();
    p.sort_by_key(|(k, _)| *k);
    p.iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}
