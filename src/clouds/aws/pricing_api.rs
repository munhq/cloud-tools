//! AWS Pricing API client for per-region pricing.
//!
//! Queries `api.pricing.us-east-1.amazonaws.com` to get real on-demand prices
//! for EC2, RDS, and ElastiCache instance types in any region. Falls back to
//! hardcoded us-east-1 prices from `pricing.rs` when the API is unreachable
//! or returns no data.

use std::collections::HashSet;
use anyhow::{anyhow, Result};
use futures::future::join_all;
use std::collections::HashMap;

use super::auth::{sign, AwsCreds};
use super::pricing;

// ── Public types ──────────────────────────────────────────────────────────────

/// Cached per-region pricing. Constructed before waste analysis runs.
pub struct PriceCache {
    // (instance_type, region) → hourly_usd
    ec2: HashMap<(String, String), f64>,
    rds: HashMap<(String, String), f64>,
    elasticache: HashMap<(String, String), f64>,
}

impl PriceCache {
    /// Build a price cache from inventory data.
    ///
    /// Extracts unique (type, region) pairs from each service, queries the
    /// AWS Pricing API in parallel, and caches results. Any API failure is
    /// swallowed — `monthly_*` methods fall back to hardcoded prices.
    pub async fn build(
        client: &reqwest::Client,
        creds: &AwsCreds,
        ec2_queries: &[(String, String)],           // (instance_type, region)
        rds_queries: &[(String, String, String)],    // (instance_class, region, engine)
        cache_queries: &[(String, String, String)],  // (node_type, region, engine)
    ) -> Self {
        let ec2 = fetch_ec2_prices(client, creds, ec2_queries).await;
        let rds = fetch_rds_prices(client, creds, rds_queries).await;
        let elasticache = fetch_elasticache_prices(client, creds, cache_queries).await;
        Self { ec2, rds, elasticache }
    }

    /// Monthly EC2 cost, preferring per-region API price, falling back to hardcoded.
    pub fn ec2_monthly(&self, instance_type: &str, region: &str) -> Option<f64> {
        self.ec2
            .get(&(instance_type.to_string(), region.to_string()))
            .map(|h| h * pricing::HOURS_PER_MONTH)
            .or_else(|| pricing::ec2_monthly(instance_type))
    }

    /// Monthly RDS cost (single-AZ), preferring per-region API price.
    pub fn rds_monthly(&self, instance_class: &str, region: &str) -> Option<f64> {
        self.rds
            .get(&(instance_class.to_string(), region.to_string()))
            .map(|h| h * pricing::HOURS_PER_MONTH)
            .or_else(|| pricing::rds_monthly(instance_class))
    }

    /// Monthly ElastiCache cost (all nodes), preferring per-region API price.
    pub fn elasticache_monthly(&self, node_type: &str, num_nodes: u32, region: &str) -> Option<f64> {
        self.elasticache
            .get(&(node_type.to_string(), region.to_string()))
            .map(|h| h * pricing::HOURS_PER_MONTH * num_nodes as f64)
            .or_else(|| pricing::elasticache_monthly(node_type, num_nodes))
    }
}

// ── EC2 price fetching ───────────────────────────────────────────────────────

async fn fetch_ec2_prices(
    client: &reqwest::Client,
    creds: &AwsCreds,
    queries: &[(String, String)],
) -> HashMap<(String, String), f64> {
    let unique: HashSet<_> = queries.iter().cloned().collect();
    let tasks: Vec<_> = unique.into_iter().map(|(itype, region)| {
        let client = client.clone();
        let creds = creds.clone();
        async move {
            let result = fetch_ec2_hourly(&client, &creds, &itype, &region).await;
            ((itype, region), result)
        }
    }).collect();

    let results = join_all(tasks).await;
    results.into_iter()
        .filter_map(|(key, result)| result.ok().map(|price| (key, price)))
        .collect()
}

async fn fetch_ec2_hourly(
    client: &reqwest::Client,
    creds: &AwsCreds,
    instance_type: &str,
    region: &str,
) -> Result<f64> {
    let location = region_display_name(region)
        .ok_or_else(|| anyhow!("Unknown region for pricing: {region}"))?;

    let body = serde_json::json!({
        "ServiceCode": "AmazonEC2",
        "Filters": [
            {"Type": "TERM_MATCH", "Field": "instanceType", "Value": instance_type},
            {"Type": "TERM_MATCH", "Field": "location", "Value": location},
            {"Type": "TERM_MATCH", "Field": "operatingSystem", "Value": "Linux"},
            {"Type": "TERM_MATCH", "Field": "tenancy", "Value": "Shared"},
            {"Type": "TERM_MATCH", "Field": "preInstalledSw", "Value": "NA"},
            {"Type": "TERM_MATCH", "Field": "capacitystatus", "Value": "Used"}
        ],
        "MaxResults": 1
    });

    let resp = pricing_query(client, creds, &body).await?;
    extract_hourly_price(&resp)
}

// ── RDS price fetching ───────────────────────────────────────────────────────

async fn fetch_rds_prices(
    client: &reqwest::Client,
    creds: &AwsCreds,
    queries: &[(String, String, String)],
) -> HashMap<(String, String), f64> {
    let unique: HashSet<_> = queries.iter().cloned().collect();
    let tasks: Vec<_> = unique.into_iter().map(|(iclass, region, engine)| {
        let client = client.clone();
        let creds = creds.clone();
        async move {
            let result = fetch_rds_hourly(&client, &creds, &iclass, &region, &engine).await;
            ((iclass, region), result)
        }
    }).collect();

    let results = join_all(tasks).await;
    results.into_iter()
        .filter_map(|(key, result)| result.ok().map(|price| (key, price)))
        .collect()
}

async fn fetch_rds_hourly(
    client: &reqwest::Client,
    creds: &AwsCreds,
    instance_class: &str,
    region: &str,
    engine: &str,
) -> Result<f64> {
    let location = region_display_name(region)
        .ok_or_else(|| anyhow!("Unknown region for pricing: {region}"))?;

    // Map engine names to pricing API values
    let db_engine = match engine {
        e if e.starts_with("postgres") => "PostgreSQL",
        e if e.starts_with("mysql") => "MySQL",
        e if e.starts_with("mariadb") => "MariaDB",
        e if e.starts_with("oracle") => "Oracle",
        e if e.starts_with("sqlserver") => "SQL Server",
        e if e.starts_with("aurora-mysql") => "Aurora MySQL",
        e if e.starts_with("aurora-postgresql") => "Aurora PostgreSQL",
        _ => engine,
    };

    let body = serde_json::json!({
        "ServiceCode": "AmazonRDS",
        "Filters": [
            {"Type": "TERM_MATCH", "Field": "instanceType", "Value": instance_class},
            {"Type": "TERM_MATCH", "Field": "location", "Value": location},
            {"Type": "TERM_MATCH", "Field": "databaseEngine", "Value": db_engine},
            {"Type": "TERM_MATCH", "Field": "deploymentOption", "Value": "Single-AZ"}
        ],
        "MaxResults": 1
    });

    let resp = pricing_query(client, creds, &body).await?;
    extract_hourly_price(&resp)
}

// ── ElastiCache price fetching ───────────────────────────────────────────────

async fn fetch_elasticache_prices(
    client: &reqwest::Client,
    creds: &AwsCreds,
    queries: &[(String, String, String)],
) -> HashMap<(String, String), f64> {
    let unique: HashSet<_> = queries.iter().cloned().collect();
    let tasks: Vec<_> = unique.into_iter().map(|(ntype, region, engine)| {
        let client = client.clone();
        let creds = creds.clone();
        async move {
            let result = fetch_elasticache_hourly(&client, &creds, &ntype, &region, &engine).await;
            ((ntype, region), result)
        }
    }).collect();

    let results = join_all(tasks).await;
    results.into_iter()
        .filter_map(|(key, result)| result.ok().map(|price| (key, price)))
        .collect()
}

async fn fetch_elasticache_hourly(
    client: &reqwest::Client,
    creds: &AwsCreds,
    node_type: &str,
    region: &str,
    engine: &str,
) -> Result<f64> {
    let location = region_display_name(region)
        .ok_or_else(|| anyhow!("Unknown region for pricing: {region}"))?;

    let cache_engine = match engine {
        "redis" => "Redis",
        "memcached" => "Memcached",
        _ => engine,
    };

    let body = serde_json::json!({
        "ServiceCode": "AmazonElastiCache",
        "Filters": [
            {"Type": "TERM_MATCH", "Field": "instanceType", "Value": node_type},
            {"Type": "TERM_MATCH", "Field": "location", "Value": location},
            {"Type": "TERM_MATCH", "Field": "cacheEngine", "Value": cache_engine}
        ],
        "MaxResults": 1
    });

    let resp = pricing_query(client, creds, &body).await?;
    extract_hourly_price(&resp)
}

// ── Pricing API HTTP ─────────────────────────────────────────────────────────

/// Query the AWS Pricing API (global endpoint in us-east-1).
async fn pricing_query(
    client: &reqwest::Client,
    creds: &AwsCreds,
    body: &serde_json::Value,
) -> Result<serde_json::Value> {
    let url = "https://api.pricing.us-east-1.amazonaws.com/";
    let body_bytes = serde_json::to_vec(body)?;
    let creds_for_pricing = AwsCreds { region: "us-east-1".into(), ..creds.clone() };

    let signed = sign(
        &creds_for_pricing,
        "POST",
        url,
        &[
            ("content-type", "application/x-amz-json-1.1"),
            ("x-amz-target", "AWSPriceListService.GetProducts"),
        ],
        &body_bytes,
        "pricing",
    )?;

    let mut req = client
        .post(url)
        .header("content-type", "application/x-amz-json-1.1")
        .header("x-amz-target", "AWSPriceListService.GetProducts")
        .header("x-amz-date", &signed.x_amz_date)
        .header("x-amz-content-sha256", &signed.x_amz_content_sha256)
        .header("authorization", &signed.authorization)
        .body(body_bytes);
    if let Some(token) = &signed.x_amz_security_token {
        req = req.header("x-amz-security-token", token);
    }

    let resp = req.send().await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        return Err(anyhow!("Pricing API error {status}: {text}"));
    }
    Ok(serde_json::from_str(&text)?)
}

/// Extract the hourly USD price from a GetProducts response.
///
/// Response shape:
/// ```json
/// { "PriceList": ["{...stringified JSON with terms.OnDemand...}"] }
/// ```
fn extract_hourly_price(resp: &serde_json::Value) -> Result<f64> {
    let price_list = resp["PriceList"]
        .as_array()
        .ok_or_else(|| anyhow!("No PriceList in response"))?;

    let first = price_list
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Empty PriceList"))?;

    let product: serde_json::Value = serde_json::from_str(first)?;

    // Navigate: terms.OnDemand.<first key>.priceDimensions.<first key>.pricePerUnit.USD
    let on_demand = product["terms"]["OnDemand"]
        .as_object()
        .ok_or_else(|| anyhow!("No OnDemand terms"))?;

    let term = on_demand
        .values()
        .next()
        .ok_or_else(|| anyhow!("No term entries"))?;

    let dimensions = term["priceDimensions"]
        .as_object()
        .ok_or_else(|| anyhow!("No priceDimensions"))?;

    let dimension = dimensions
        .values()
        .next()
        .ok_or_else(|| anyhow!("No dimension entries"))?;

    let usd_str = dimension["pricePerUnit"]["USD"]
        .as_str()
        .ok_or_else(|| anyhow!("No USD price"))?;

    usd_str
        .parse::<f64>()
        .map_err(|e| anyhow!("Failed to parse price '{usd_str}': {e}"))
}

// ── Region display name mapping ──────────────────────────────────────────────

/// Map AWS region codes to the display names used by the Pricing API.
fn region_display_name(region: &str) -> Option<&'static str> {
    Some(match region {
        "us-east-1"      => "US East (N. Virginia)",
        "us-east-2"      => "US East (Ohio)",
        "us-west-1"      => "US West (N. California)",
        "us-west-2"      => "US West (Oregon)",
        "eu-west-1"      => "EU (Ireland)",
        "eu-west-2"      => "EU (London)",
        "eu-west-3"      => "EU (Paris)",
        "eu-central-1"   => "EU (Frankfurt)",
        "eu-central-2"   => "EU (Zurich)",
        "eu-north-1"     => "EU (Stockholm)",
        "eu-south-1"     => "EU (Milan)",
        "eu-south-2"     => "EU (Spain)",
        "ap-northeast-1" => "Asia Pacific (Tokyo)",
        "ap-northeast-2" => "Asia Pacific (Seoul)",
        "ap-northeast-3" => "Asia Pacific (Osaka)",
        "ap-southeast-1" => "Asia Pacific (Singapore)",
        "ap-southeast-2" => "Asia Pacific (Sydney)",
        "ap-southeast-3" => "Asia Pacific (Jakarta)",
        "ap-southeast-4" => "Asia Pacific (Melbourne)",
        "ap-south-1"     => "Asia Pacific (Mumbai)",
        "ap-south-2"     => "Asia Pacific (Hyderabad)",
        "ap-east-1"      => "Asia Pacific (Hong Kong)",
        "sa-east-1"      => "South America (Sao Paulo)",
        "ca-central-1"   => "Canada (Central)",
        "ca-west-1"      => "Canada West (Calgary)",
        "me-south-1"     => "Middle East (Bahrain)",
        "me-central-1"   => "Middle East (UAE)",
        "af-south-1"     => "Africa (Cape Town)",
        "il-central-1"   => "Israel (Tel Aviv)",
        _ => return None,
    })
}
