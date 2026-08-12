use anyhow::{anyhow, Result};
use futures::future::join_all;

use super::{
    as_items,
    auth::{sign, AwsCreds},
    xml_to_value,
};

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct S3Bucket {
    pub name: String,
    pub region: String,
    pub has_lifecycle_policy: bool,
    pub incomplete_multipart_count: u32,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// List S3 buckets with waste issues: missing lifecycle policies or
/// incomplete multipart uploads.
pub async fn list_buckets_with_issues(
    client: &reqwest::Client,
    creds: &AwsCreds,
) -> Result<Vec<S3Bucket>> {
    // 1. List all buckets (global endpoint, us-east-1)
    let bucket_names = list_all_buckets(client, creds).await?;

    // 2. Resolve each bucket's region
    let location_tasks: Vec<_> = bucket_names
        .iter()
        .map(|name| get_bucket_region(client, creds, name))
        .collect();
    let locations = join_all(location_tasks).await;

    let buckets_with_regions: Vec<(String, String)> = bucket_names
        .into_iter()
        .zip(locations)
        .filter_map(|(name, region_result)| region_result.ok().map(|region| (name, region)))
        .collect();

    // 3. Check each bucket for issues in parallel
    let issue_tasks: Vec<_> = buckets_with_regions
        .iter()
        .map(|(name, region)| check_bucket_issues(client, creds, name, region))
        .collect();
    let results = join_all(issue_tasks).await;

    // 4. Only return buckets that have issues
    let buckets: Vec<S3Bucket> = results
        .into_iter()
        .filter_map(|r| r.ok())
        .filter(|b| !b.has_lifecycle_policy || b.incomplete_multipart_count > 0)
        .collect();

    Ok(buckets)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// List all bucket names via the global S3 endpoint.
async fn list_all_buckets(client: &reqwest::Client, creds: &AwsCreds) -> Result<Vec<String>> {
    let xml = s3_get(
        client,
        creds,
        "us-east-1",
        "https://s3.us-east-1.amazonaws.com/",
    )
    .await?;
    let v = xml_to_value(&xml)?;

    let names = as_items(&v["Buckets"]["Bucket"])
        .into_iter()
        .filter_map(|b| b["Name"].as_str().map(String::from))
        .collect();

    Ok(names)
}

/// Determine a bucket's region via GetBucketLocation.
async fn get_bucket_region(
    client: &reqwest::Client,
    creds: &AwsCreds,
    bucket: &str,
) -> Result<String> {
    let url = format!("https://s3.us-east-1.amazonaws.com/{bucket}?location");
    let xml = s3_get(client, creds, "us-east-1", &url).await?;
    let v = xml_to_value(&xml)?;

    // LocationConstraint is empty/absent for us-east-1
    let region = match v["LocationConstraint"].as_str() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => "us-east-1".to_string(),
    };

    Ok(region)
}

/// Check a single bucket for lifecycle policy and incomplete multipart uploads.
async fn check_bucket_issues(
    client: &reqwest::Client,
    creds: &AwsCreds,
    bucket: &str,
    region: &str,
) -> Result<S3Bucket> {
    let (lifecycle_result, multipart_result) = futures::join!(
        check_lifecycle(client, creds, bucket, region),
        count_incomplete_multiparts(client, creds, bucket, region),
    );

    Ok(S3Bucket {
        name: bucket.to_string(),
        region: region.to_string(),
        has_lifecycle_policy: lifecycle_result.unwrap_or(false),
        incomplete_multipart_count: multipart_result.unwrap_or(0),
    })
}

/// Returns true if the bucket has a lifecycle configuration.
async fn check_lifecycle(
    client: &reqwest::Client,
    creds: &AwsCreds,
    bucket: &str,
    region: &str,
) -> Result<bool> {
    let url = format!("https://s3.{region}.amazonaws.com/{bucket}?lifecycle");
    match s3_get(client, creds, region, &url).await {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Count incomplete multipart uploads for a bucket.
async fn count_incomplete_multiparts(
    client: &reqwest::Client,
    creds: &AwsCreds,
    bucket: &str,
    region: &str,
) -> Result<u32> {
    let url = format!("https://s3.{region}.amazonaws.com/{bucket}?uploads");
    let xml = s3_get(client, creds, region, &url).await?;
    let v = xml_to_value(&xml)?;

    let count = as_items(&v["Upload"]).len() as u32;
    Ok(count)
}

// ── HTTP helper ───────────────────────────────────────────────────────────────

/// Perform a signed GET request against the S3 REST API.
async fn s3_get(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
    url: &str,
) -> Result<String> {
    let creds_for_region = AwsCreds {
        region: region.to_string(),
        ..creds.clone()
    };

    let signed = sign(&creds_for_region, "GET", url, &[], b"", "s3")?;

    let mut req = client
        .get(url)
        .header("x-amz-date", &signed.x_amz_date)
        .header("x-amz-content-sha256", &signed.x_amz_content_sha256)
        .header("authorization", &signed.authorization);
    if let Some(token) = &signed.x_amz_security_token {
        req = req.header("x-amz-security-token", token);
    }

    let resp = req.send().await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        return Err(anyhow!("S3 API error {status} for {url}: {text}"));
    }
    Ok(text)
}
