//! AWS Compute Optimizer integration.
//!
//! Fetches ML-based rightsizing recommendations for EC2 instances.
//! Requires the account to have opted in to Compute Optimizer
//! (`compute-optimizer:GetEnrollmentStatus` returns "Active").

use anyhow::{anyhow, Result};
use futures::future::join_all;
use serde::Deserialize;

use super::auth::{sign, AwsCreds};

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Ec2Recommendation {
    pub instance_arn: String,
    pub instance_name: Option<String>,
    pub current_instance_type: String,
    pub recommended_instance_type: String,
    pub finding: String,
    pub finding_reasons: Vec<String>,
    pub estimated_monthly_savings_usd: f64,
    pub region: String,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Fetch Compute Optimizer EC2 rightsizing recommendations across all regions.
///
/// Returns only OVER_PROVISIONED findings (resources that could be downsized).
/// Returns an empty Vec if Compute Optimizer is not enrolled for this account.
pub async fn get_ec2_recommendations(
    client: &reqwest::Client,
    creds: &AwsCreds,
) -> Result<Vec<Ec2Recommendation>> {
    // Check enrollment first — skip entirely if not opted in
    if !is_enrolled(client, creds).await {
        return Ok(Vec::new());
    }

    let regions = list_regions(client, creds).await?;
    let tasks: Vec<_> = regions
        .iter()
        .map(|r| get_in_region(client, creds, r))
        .collect();
    let results = join_all(tasks).await;
    Ok(results
        .into_iter()
        .filter_map(|r| r.ok())
        .flatten()
        .collect())
}

// ── Enrollment check ─────────────────────────────────────────────────────────

async fn is_enrolled(client: &reqwest::Client, creds: &AwsCreds) -> bool {
    let result = co_query(
        client,
        creds,
        "us-east-1",
        "ComputeOptimizerService.GetEnrollmentStatus",
        b"{}",
    )
    .await;

    match result {
        Ok(resp) => resp["status"].as_str() == Some("Active"),
        Err(_) => false,
    }
}

// ── Region discovery ─────────────────────────────────────────────────────────

async fn list_regions(client: &reqwest::Client, creds: &AwsCreds) -> Result<Vec<String>> {
    let body = form_params(&[("Action", "DescribeRegions"), ("Version", "2016-11-15")]);
    let url = "https://ec2.us-east-1.amazonaws.com/";
    let creds_for_region = AwsCreds {
        region: "us-east-1".into(),
        ..creds.clone()
    };
    let signed = sign(
        &creds_for_region,
        "POST",
        url,
        &[("content-type", "application/x-www-form-urlencoded")],
        body.as_bytes(),
        "ec2",
    )?;
    let mut req = client
        .post(url)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("x-amz-date", &signed.x_amz_date)
        .header("x-amz-content-sha256", &signed.x_amz_content_sha256)
        .header("authorization", &signed.authorization)
        .body(body);
    if let Some(t) = &signed.x_amz_security_token {
        req = req.header("x-amz-security-token", t);
    }
    let resp = req.send().await?;
    let xml = resp.text().await?;
    let v = super::xml_to_value(&xml)?;
    Ok(super::as_items(&v["regionInfo"]["item"])
        .into_iter()
        .filter_map(|r| r["regionName"].as_str().map(String::from))
        .collect())
}

// ── Per-region recommendation fetch ──────────────────────────────────────────

async fn get_in_region(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
) -> Result<Vec<Ec2Recommendation>> {
    let mut out = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let body = match &next_token {
            Some(token) => serde_json::json!({
                "maxResults": 200,
                "filters": [{"name": "Finding", "values": ["OVER_PROVISIONED"]}],
                "nextToken": token,
            }),
            None => serde_json::json!({
                "maxResults": 200,
                "filters": [{"name": "Finding", "values": ["OVER_PROVISIONED"]}],
            }),
        };

        let body_bytes = serde_json::to_vec(&body)?;
        let resp = co_query(
            client,
            creds,
            region,
            "ComputeOptimizerService.GetEC2InstanceRecommendations",
            &body_bytes,
        )
        .await;

        // Compute Optimizer may not be available in all regions
        let resp = match resp {
            Ok(r) => r,
            Err(_) => break,
        };

        let parsed: GetEc2RecommendationsResponse =
            serde_json::from_value(resp).unwrap_or_default();

        for rec in parsed.instance_recommendations {
            // Get the rank-1 recommendation (best fit)
            let best = rec
                .recommendation_options
                .iter()
                .find(|o| o.rank == Some(1))
                .or_else(|| rec.recommendation_options.first());

            if let Some(opt) = best {
                let savings = opt
                    .estimated_monthly_savings
                    .as_ref()
                    .map(|s| s.value)
                    .unwrap_or(0.0);

                // Only include if there are actual savings
                if savings > 0.0 {
                    out.push(Ec2Recommendation {
                        instance_arn: rec.instance_arn.unwrap_or_default(),
                        instance_name: rec.instance_name,
                        current_instance_type: rec.current_instance_type.unwrap_or_default(),
                        recommended_instance_type: opt.instance_type.clone().unwrap_or_default(),
                        finding: rec.finding.unwrap_or_default(),
                        finding_reasons: rec.finding_reason_codes,
                        estimated_monthly_savings_usd: savings,
                        region: region.to_string(),
                    });
                }
            }
        }

        match parsed.next_token {
            Some(t) if !t.is_empty() => next_token = Some(t),
            _ => break,
        }
    }
    Ok(out)
}

// ── Compute Optimizer HTTP helper ────────────────────────────────────────────

async fn co_query(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
    target: &str,
    body: &[u8],
) -> Result<serde_json::Value> {
    let url = format!("https://compute-optimizer.{region}.amazonaws.com/");
    let creds_for_region = AwsCreds {
        region: region.to_string(),
        ..creds.clone()
    };

    let signed = sign(
        &creds_for_region,
        "POST",
        &url,
        &[
            ("content-type", "application/x-amz-json-1.0"),
            ("x-amz-target", target),
        ],
        body,
        "compute-optimizer",
    )?;

    let mut req = client
        .post(&url)
        .header("content-type", "application/x-amz-json-1.0")
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
        return Err(anyhow!(
            "Compute Optimizer error {status} in {region}: {text}"
        ));
    }
    Ok(serde_json::from_str(&text)?)
}

// ── Response types ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct GetEc2RecommendationsResponse {
    #[serde(default)]
    instance_recommendations: Vec<InstanceRec>,
    next_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InstanceRec {
    instance_arn: Option<String>,
    instance_name: Option<String>,
    current_instance_type: Option<String>,
    finding: Option<String>,
    #[serde(default)]
    finding_reason_codes: Vec<String>,
    #[serde(default)]
    recommendation_options: Vec<RecOption>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RecOption {
    instance_type: Option<String>,
    rank: Option<u32>,
    estimated_monthly_savings: Option<MonthlySavings>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MonthlySavings {
    #[serde(default)]
    value: f64,
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
