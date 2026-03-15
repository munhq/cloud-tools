use anyhow::{anyhow, Result};
use futures::future::join_all;

use super::{as_items, auth::{sign, AwsCreds}, cloudwatch, xml_to_value};

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ElastiCacheCluster {
    pub cluster_id: String,
    pub engine: String,           // "redis" | "memcached"
    pub engine_version: String,
    pub node_type: String,        // e.g. "cache.r6g.large"
    pub num_nodes: u32,
    pub status: String,           // "available", "creating", etc.
    pub region: String,
    pub name: Option<String>,     // from tags or description
    /// Average CPU utilisation over last 14 days (None = no data).
    pub avg_cpu_14d: Option<f64>,
    /// Peak current connections over last 14 days.
    pub peak_connections_14d: Option<u64>,
    /// Average current connections over last 14 days.
    pub avg_connections_14d: Option<f64>,
    /// Average bytes used for cache over last 14 days (Redis only).
    pub avg_bytes_used: Option<f64>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// List all ElastiCache clusters across all regions, enriched with CloudWatch metrics.
pub async fn list_clusters(
    client: &reqwest::Client,
    creds: &AwsCreds,
) -> Result<Vec<ElastiCacheCluster>> {
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
) -> Result<Vec<ElastiCacheCluster>> {
    let mut out = Vec::new();
    let mut marker: Option<String> = None;

    loop {
        let mut params = vec![
            ("Action", "DescribeCacheClusters"),
            ("Version", "2015-02-02"),
            ("ShowCacheNodeInfo", "true"),
        ];
        let marker_owned;
        if let Some(ref m) = marker {
            marker_owned = m.clone();
            params.push(("Marker", marker_owned.as_str()));
        }

        let body = form_params(&params);
        let xml = elasticache_query(client, creds, region, &body).await?;
        let v = xml_to_value(&xml)?;

        let clusters = as_items(
            &v["DescribeCacheClustersResult"]["CacheClusters"]["CacheCluster"]
        );

        // Enrich each cluster with CloudWatch metrics concurrently
        let enrich_tasks: Vec<_> = clusters.into_iter().filter_map(|c| {
            let id = c["CacheClusterId"].as_str()?.to_string();
            let engine = c["Engine"].as_str().unwrap_or("unknown").to_string();
            let engine_version = c["EngineVersion"].as_str().unwrap_or("").to_string();
            let node_type = c["CacheNodeType"].as_str().unwrap_or("unknown").to_string();
            let num_nodes = c["NumCacheNodes"].as_str()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1);
            let status = c["CacheClusterStatus"].as_str().unwrap_or("unknown").to_string();

            // Only include available clusters
            if status != "available" { return None; }

            let client = client.clone();
            let creds = creds.clone();
            let region = region.to_string();
            Some(async move {
                enrich(&client, &creds, &region, id, engine, engine_version, node_type, num_nodes, status).await
            })
        }).collect();

        let enriched = join_all(enrich_tasks).await;
        out.extend(enriched.into_iter().filter_map(|r| r.ok()));

        match v["DescribeCacheClustersResult"]["Marker"].as_str() {
            Some(m) if !m.is_empty() => marker = Some(m.to_string()),
            _ => break,
        }
    }
    Ok(out)
}

async fn enrich(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
    cluster_id: String,
    engine: String,
    engine_version: String,
    node_type: String,
    num_nodes: u32,
    status: String,
) -> Result<ElastiCacheCluster> {
    let dims = [("CacheClusterId", cluster_id.as_str())];

    let (cpu_res, conn_res, bytes_res) = futures::join!(
        cloudwatch::get_metric_stat(client, creds, region, "AWS/ElastiCache", "CPUUtilization", &dims, 14, "Average"),
        cloudwatch::get_metric_stat(client, creds, region, "AWS/ElastiCache", "CurrConnections", &dims, 14, "Maximum"),
        cloudwatch::get_metric_stat(client, creds, region, "AWS/ElastiCache", "BytesUsedForCache", &dims, 14, "Average"),
    );

    let avg_cpu_14d = cpu_res.ok().and_then(|v| {
        if v.is_empty() { None } else { Some(v.iter().sum::<f64>() / v.len() as f64) }
    });

    let peak_connections_14d = conn_res.as_ref().ok().and_then(|v| {
        v.iter().cloned().reduce(f64::max).map(|m| m as u64)
    });

    let avg_connections_14d = conn_res.ok().and_then(|v| {
        if v.is_empty() { None } else { Some(v.iter().sum::<f64>() / v.len() as f64) }
    });

    let avg_bytes_used = bytes_res.ok().and_then(|v| {
        if v.is_empty() { None } else { Some(v.iter().sum::<f64>() / v.len() as f64) }
    });

    Ok(ElastiCacheCluster {
        cluster_id,
        engine,
        engine_version,
        node_type,
        num_nodes,
        status,
        region: region.to_string(),
        name: None,
        avg_cpu_14d,
        peak_connections_14d,
        avg_connections_14d,
        avg_bytes_used,
    })
}

// ── ElastiCache HTTP helper ──────────────────────────────────────────────────

async fn elasticache_query(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
    body: &str,
) -> Result<String> {
    let url = format!("https://elasticache.{region}.amazonaws.com/");
    let creds_for_region = AwsCreds { region: region.to_string(), ..creds.clone() };

    let signed = sign(
        &creds_for_region,
        "POST",
        &url,
        &[("content-type", "application/x-www-form-urlencoded")],
        body.as_bytes(),
        "elasticache",
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
    // ElastiCache not available in some opt-in regions
    if status.as_u16() == 404 {
        return Ok(String::new());
    }
    if !status.is_success() {
        return Err(anyhow!("ElastiCache API error {status} in {region}: {text}"));
    }
    Ok(text)
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
