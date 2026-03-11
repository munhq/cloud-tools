use anyhow::{anyhow, Result};
use chrono::NaiveDate;
use serde::Deserialize;

use super::auth::{sign, AwsCreds};
use crate::types::CostEntry;

const CE_ENDPOINT: &str = "https://ce.us-east-1.amazonaws.com/";
const CE_CONTENT_TYPE: &str = "application/x-amz-json-1.1";
const CE_TARGET: &str = "AWSInsightsIndexService.GetCostAndUsage";

/// Grouping dimension for Cost Explorer queries.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CeGroupBy {
    /// Cost per AWS service (EC2, RDS, S3, …) — default
    Service,
    /// Cost per linked account — use from management account for org-wide view
    LinkedAccount,
}

/// Fetch costs from AWS Cost Explorer.
///
/// `start` is inclusive, `end` is exclusive (AWS CE convention).
/// Automatically paginates. Zero-cost entries are dropped. Results sorted by cost descending.
///
/// Call with `CeGroupBy::LinkedAccount` from the management account role to get
/// org-wide costs broken down per member account.
pub async fn get_costs(
    client: &reqwest::Client,
    creds: &AwsCreds,
    start: NaiveDate,
    end: NaiveDate,
) -> Result<Vec<CostEntry>> {
    get_costs_grouped(client, creds, start, end, CeGroupBy::Service).await
}

/// Org-wide costs per linked account — call from management account role.
pub async fn get_costs_by_account(
    client: &reqwest::Client,
    creds: &AwsCreds,
    start: NaiveDate,
    end: NaiveDate,
) -> Result<Vec<CostEntry>> {
    get_costs_grouped(client, creds, start, end, CeGroupBy::LinkedAccount).await
}

async fn get_costs_grouped(
    client: &reqwest::Client,
    creds: &AwsCreds,
    start: NaiveDate,
    end: NaiveDate,
    group_by: CeGroupBy,
) -> Result<Vec<CostEntry>> {
    let mut all = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let (entries, token) = fetch_page(client, creds, start, end, next_token.as_deref(), group_by).await?;
        all.extend(entries);
        match token {
            Some(t) if !t.is_empty() => next_token = Some(t),
            _ => break,
        }
    }

    all.sort_by(|a, b| b.amount_usd.partial_cmp(&a.amount_usd).unwrap_or(std::cmp::Ordering::Equal));
    Ok(all)
}

async fn fetch_page(
    client: &reqwest::Client,
    creds: &AwsCreds,
    start: NaiveDate,
    end: NaiveDate,
    next_token: Option<&str>,
    group_by: CeGroupBy,
) -> Result<(Vec<CostEntry>, Option<String>)> {
    let body = build_request(start, end, next_token, group_by)?;

    let signed = sign(
        creds,
        "POST",
        CE_ENDPOINT,
        &[
            ("content-type", CE_CONTENT_TYPE),
            ("x-amz-target", CE_TARGET),
        ],
        &body,
        "ce",
    )?;

    let mut req = client
        .post(CE_ENDPOINT)
        .header("content-type", CE_CONTENT_TYPE)
        .header("x-amz-target", CE_TARGET)
        .header("x-amz-date", &signed.x_amz_date)
        .header("x-amz-content-sha256", &signed.x_amz_content_sha256)
        .header("authorization", &signed.authorization)
        .body(body);

    if let Some(token) = &signed.x_amz_security_token {
        req = req.header("x-amz-security-token", token);
    }

    let resp = req.send().await?;
    let status = resp.status();

    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(anyhow!("Cost Explorer error {status}: {text}"));
    }

    let data: CeResponse = resp.json().await?;
    let next = data.next_page_token;

    let entries = data
        .results_by_time
        .into_iter()
        .flat_map(|result| {
            let period_start = result.time_period.start.clone();
            let period_end = result.time_period.end.clone();
            result.groups.into_iter().filter_map(move |g| {
                let service = g.keys.into_iter().next()?;
                let amount: f64 = g
                    .metrics
                    .get("UnblendedCost")
                    .and_then(|m| m.amount.parse().ok())
                    .unwrap_or(0.0);

                if amount <= 0.0 {
                    return None;
                }

                Some(CostEntry {
                    service,
                    amount_usd: amount,
                    period_start: NaiveDate::parse_from_str(&period_start, "%Y-%m-%d").ok()?,
                    period_end: NaiveDate::parse_from_str(&period_end, "%Y-%m-%d").ok()?,
                })
            })
        })
        .collect();

    Ok((entries, next))
}

fn build_request(
    start: NaiveDate,
    end: NaiveDate,
    next_token: Option<&str>,
    group_by: CeGroupBy,
) -> Result<Vec<u8>> {
    let group_key = match group_by {
        CeGroupBy::Service => "SERVICE",
        CeGroupBy::LinkedAccount => "LINKED_ACCOUNT",
    };
    let mut req = serde_json::json!({
        "TimePeriod": {
            "Start": start.format("%Y-%m-%d").to_string(),
            "End":   end.format("%Y-%m-%d").to_string(),
        },
        "Granularity": "MONTHLY",
        "Filter": {
            "Not": {
                "Dimensions": {
                    "Key": "RECORD_TYPE",
                    "Values": ["Credit", "Refund", "Upfront", "Support"],
                }
            }
        },
        "Metrics": ["UnblendedCost"],
        "GroupBy": [{ "Type": "DIMENSION", "Key": group_key }],
    });
    if let Some(t) = next_token {
        req["NextPageToken"] = serde_json::Value::String(t.to_string());
    }
    Ok(serde_json::to_vec(&req)?)
}

// ── Response types ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CeResponse {
    results_by_time: Vec<ResultByTime>,
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ResultByTime {
    time_period: ResponseTimePeriod,
    groups: Vec<Group>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ResponseTimePeriod {
    start: String,
    end: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Group {
    keys: Vec<String>,
    metrics: std::collections::HashMap<String, MetricValue>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct MetricValue {
    amount: String,
    #[allow(dead_code)]
    unit: String,
}
