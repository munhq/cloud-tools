use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};
use futures::future::join_all;

use super::{as_items, auth::{sign, AwsCreds}, xml_to_value};

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NatGateway {
    pub id: String,
    pub vpc_id: String,
    pub state: String,        // "available" | "deleting" | "deleted" | "failed" | "pending"
    pub region: String,
    pub name: Option<String>,
    /// Total bytes sent from internal instances → internet via this NAT GW over last 14 days.
    /// None means CloudWatch returned no data (very new or truly idle).
    pub bytes_out_14d: Option<u64>,
    /// Peak active connection count over last 14 days. 0 or None → no traffic.
    pub active_connections_max: Option<u64>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// List all available NAT gateways across all regions, enriched with CloudWatch traffic stats.
pub async fn list_nat_gateways(
    client: &reqwest::Client,
    creds: &AwsCreds,
) -> Result<Vec<NatGateway>> {
    let regions = list_regions(client, creds).await?;
    let tasks: Vec<_> = regions
        .iter()
        .map(|r| list_in_region(client, creds, r))
        .collect();
    let results = join_all(tasks).await;
    Ok(results.into_iter().filter_map(|r| r.ok()).flatten().collect())
}

// ── Region discovery ──────────────────────────────────────────────────────────

async fn list_regions(client: &reqwest::Client, creds: &AwsCreds) -> Result<Vec<String>> {
    let body = form_params(&[
        ("Action", "DescribeRegions"),
        ("Version", "2016-11-15"),
    ]);
    let xml = ec2_query(client, creds, "us-east-1", &body).await?;
    let v = xml_to_value(&xml)?;
    Ok(as_items(&v["regionInfo"]["item"])
        .into_iter()
        .filter_map(|r| r["regionName"].as_str().map(String::from))
        .collect())
}

// ── Per-region listing ────────────────────────────────────────────────────────

async fn list_in_region(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
) -> Result<Vec<NatGateway>> {
    let mut out = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut params = vec![
            ("Action", "DescribeNatGateways"),
            ("Version", "2016-11-15"),
            ("Filter.1.Name", "state"),
            ("Filter.1.Value.1", "available"),
        ];
        let token_owned;
        if let Some(ref t) = next_token {
            token_owned = t.clone();
            params.push(("NextToken", token_owned.as_str()));
        }

        let body = form_params(&params);
        let xml = ec2_query(client, creds, region, &body).await?;
        let v = xml_to_value(&xml)?;

        for gw in as_items(&v["natGatewaySet"]["item"]) {
            let id = gw["natGatewayId"].as_str().unwrap_or("").to_string();
            if id.is_empty() {
                continue;
            }

            let (bytes_res, conn_res) = futures::join!(
                bytes_out(client, creds, region, &id),
                active_connections_max(client, creds, region, &id),
            );

            out.push(NatGateway {
                id,
                vpc_id: gw["vpcId"].as_str().unwrap_or("").to_string(),
                state: gw["state"].as_str().unwrap_or("unknown").to_string(),
                region: region.to_string(),
                name: tag_value(&gw["tagSet"], "Name"),
                bytes_out_14d: bytes_res.ok().flatten(),
                active_connections_max: conn_res.ok().flatten(),
            });
        }

        match v["nextToken"].as_str() {
            Some(t) if !t.is_empty() => next_token = Some(t.to_string()),
            _ => break,
        }
    }
    Ok(out)
}

// ── CloudWatch helpers ────────────────────────────────────────────────────────

/// Sum of BytesOutToDestination over 14 days — total egress bytes.
async fn bytes_out(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
    nat_id: &str,
) -> Result<Option<u64>> {
    let vals = cw_metric(
        client, creds, region,
        "AWS/NATGateway", "BytesOutToDestination",
        &[("NatGatewayId", nat_id)],
        14, "Sum",
    ).await?;
    if vals.is_empty() {
        return Ok(None);
    }
    Ok(Some(vals.iter().sum::<f64>() as u64))
}

/// Peak ActiveConnectionCount over 14 days.
async fn active_connections_max(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
    nat_id: &str,
) -> Result<Option<u64>> {
    let vals = cw_metric(
        client, creds, region,
        "AWS/NATGateway", "ActiveConnectionCount",
        &[("NatGatewayId", nat_id)],
        14, "Maximum",
    ).await?;
    if vals.is_empty() {
        return Ok(None);
    }
    Ok(vals.into_iter().reduce(f64::max).map(|m| m as u64))
}

/// Fetch CloudWatch metric datapoints using the given statistic (Sum / Maximum / Average).
async fn cw_metric(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
    namespace: &str,
    metric_name: &str,
    dimensions: &[(&str, &str)],
    days: u32,
    stat: &str,
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

    let mut params: Vec<(&str, &str)> = vec![
        ("Action", "GetMetricStatistics"),
        ("Version", "2010-08-01"),
        ("Namespace", namespace),
        ("MetricName", metric_name),
        ("StartTime", &start_str),
        ("EndTime", &end_str),
        ("Period", "3600"),
        ("Statistics.member.1", stat),
    ];
    for (i, (name, value)) in dimensions.iter().enumerate() {
        params.push((dim_names[i].as_str(), name));
        params.push((dim_values[i].as_str(), value));
    }

    let body = form_params(&params);
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
        return Err(anyhow!("CloudWatch error {status} in {region}: {text}"));
    }

    let v = xml_to_value(&text)?;
    let datapoints = as_items(&v["GetMetricStatisticsResult"]["Datapoints"]["member"]);
    let values: Vec<f64> = datapoints
        .iter()
        .filter_map(|dp| dp[stat].as_str()?.parse().ok())
        .collect();

    Ok(values)
}

// ── EC2 HTTP helper ───────────────────────────────────────────────────────────

async fn ec2_query(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
    body: &str,
) -> Result<String> {
    let url = format!("https://ec2.{region}.amazonaws.com/");
    let creds_for_region = AwsCreds { region: region.to_string(), ..creds.clone() };

    let signed = sign(
        &creds_for_region,
        "POST",
        &url,
        &[("content-type", "application/x-www-form-urlencoded")],
        body.as_bytes(),
        "ec2",
    )?;

    let mut req = client
        .post(&url)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("x-amz-date", &signed.x_amz_date)
        .header("x-amz-content-sha256", &signed.x_amz_content_sha256)
        .header("authorization", &signed.authorization)
        .body(body.to_string());
    if let Some(token) = &signed.x_amz_security_token {
        req = req.header("x-amz-security-token", token);
    }

    let resp = req.send().await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        return Err(anyhow!("EC2 API error {status} in {region}: {text}"));
    }
    Ok(text)
}

// ── Misc helpers ──────────────────────────────────────────────────────────────

fn tag_value(tag_set: &serde_json::Value, key: &str) -> Option<String> {
    as_items(&tag_set["item"])
        .iter()
        .find(|i| i["key"].as_str() == Some(key))
        .and_then(|i| i["value"].as_str().map(String::from))
}

fn form_params(params: &[(&str, &str)]) -> String {
    let mut p = params.to_vec();
    p.sort_by_key(|(k, _)| *k);
    p.iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}
