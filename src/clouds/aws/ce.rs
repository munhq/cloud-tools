use anyhow::{anyhow, Result};
use chrono::{Datelike, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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

/// Fair month-over-month cost comparison using identical day windows.
///
/// If today is March 12, compares March 1–12 vs Feb 1–12 so partial-month
/// data doesn't create a misleading "costs dropped" illusion.
/// On the 1st day of the month, compares the full previous month vs the one before.
#[derive(Debug, Clone, Serialize)]
pub struct CostComparison {
    pub current_period: CostPeriod,
    pub previous_period: CostPeriod,
    pub total_change_usd: f64,
    pub total_change_pct: Option<f64>,
    /// Per-service comparison, sorted by absolute change descending.
    pub by_service: Vec<ServiceComparison>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CostPeriod {
    pub start: NaiveDate,
    pub end: NaiveDate,
    pub total_usd: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceComparison {
    pub service: String,
    pub current_usd: f64,
    pub previous_usd: f64,
    pub change_usd: f64,
    pub change_pct: Option<f64>,
}

pub async fn compare_costs(
    client: &reqwest::Client,
    creds: &AwsCreds,
) -> Result<CostComparison> {
    let today = Utc::now().date_naive();
    let day_of_month = today.day();

    let (cur_start, cur_end, prev_start, prev_end) = if day_of_month <= 1 {
        // First day of month: compare full previous month vs the one before
        let prev_month_start = first_of_prev_month(today);
        let two_months_ago_start = first_of_prev_month(prev_month_start);
        (prev_month_start, today, two_months_ago_start, prev_month_start)
    } else {
        // Mid-month: compare day 1..today vs same window last month
        let cur_start = NaiveDate::from_ymd_opt(today.year(), today.month(), 1).unwrap();
        let prev_month_start = first_of_prev_month(today);
        // Clamp the day in case previous month is shorter (e.g., Feb 28 vs Mar 30)
        let prev_end_day = day_of_month.min(days_in_month(prev_month_start.year(), prev_month_start.month()));
        let prev_end = NaiveDate::from_ymd_opt(prev_month_start.year(), prev_month_start.month(), prev_end_day).unwrap();
        (cur_start, today, prev_month_start, prev_end)
    };

    let (current_costs, previous_costs) = tokio::join!(
        get_costs(client, creds, cur_start, cur_end),
        get_costs(client, creds, prev_start, prev_end),
    );

    let current_costs = current_costs?;
    let previous_costs = previous_costs?;

    let cur_total: f64 = current_costs.iter().map(|c| c.amount_usd).sum();
    let prev_total: f64 = previous_costs.iter().map(|c| c.amount_usd).sum();
    let total_change = cur_total - prev_total;
    let total_change_pct = if prev_total > 0.0 {
        Some((total_change / prev_total) * 100.0)
    } else {
        None
    };

    // Build per-service comparison
    let mut service_map: std::collections::HashMap<String, (f64, f64)> = std::collections::HashMap::new();
    for c in &current_costs {
        service_map.entry(c.service.clone()).or_default().0 += c.amount_usd;
    }
    for c in &previous_costs {
        service_map.entry(c.service.clone()).or_default().1 += c.amount_usd;
    }
    let mut by_service: Vec<ServiceComparison> = service_map
        .into_iter()
        .map(|(service, (cur, prev))| {
            let change = cur - prev;
            let change_pct = if prev > 0.0 { Some((change / prev) * 100.0) } else { None };
            ServiceComparison { service, current_usd: cur, previous_usd: prev, change_usd: change, change_pct }
        })
        .collect();
    by_service.sort_by(|a, b| b.change_usd.abs().partial_cmp(&a.change_usd.abs()).unwrap_or(std::cmp::Ordering::Equal));

    Ok(CostComparison {
        current_period: CostPeriod { start: cur_start, end: cur_end, total_usd: cur_total },
        previous_period: CostPeriod { start: prev_start, end: prev_end, total_usd: prev_total },
        total_change_usd: total_change,
        total_change_pct,
        by_service,
    })
}

fn first_of_prev_month(date: NaiveDate) -> NaiveDate {
    if date.month() == 1 {
        NaiveDate::from_ymd_opt(date.year() - 1, 12, 1).unwrap()
    } else {
        NaiveDate::from_ymd_opt(date.year(), date.month() - 1, 1).unwrap()
    }
}

fn days_in_month(year: i32, month: u32) -> u32 {
    if month == 12 {
        NaiveDate::from_ymd_opt(year + 1, 1, 1)
    } else {
        NaiveDate::from_ymd_opt(year, month + 1, 1)
    }
    .unwrap()
    .signed_duration_since(NaiveDate::from_ymd_opt(year, month, 1).unwrap())
    .num_days() as u32
}

// ── Data transfer breakdown ───────────────────────────────────────────────────

/// One usage-type line item from a data transfer cost breakdown.
#[derive(Debug, Clone, Serialize)]
pub struct DataTransferEntry {
    pub usage_type: String,
    pub description: String,
    pub amount_usd: f64,
}

/// Fetch data transfer costs broken down by usage type for the given period.
///
/// Groups by USAGE_TYPE filtered to the "AWS Data Transfer" service.
/// Returns items sorted by cost descending — useful for identifying
/// expensive internet egress or cross-AZ traffic.
pub async fn get_data_transfer_breakdown(
    client: &reqwest::Client,
    creds: &AwsCreds,
    start: NaiveDate,
    end: NaiveDate,
) -> Result<Vec<DataTransferEntry>> {
    let body = serde_json::to_vec(&serde_json::json!({
        "TimePeriod": {
            "Start": start.format("%Y-%m-%d").to_string(),
            "End":   end.format("%Y-%m-%d").to_string(),
        },
        "Granularity": "MONTHLY",
        "Filter": {
            "Dimensions": {
                "Key": "SERVICE",
                "Values": ["AWS Data Transfer"],
            }
        },
        "Metrics": ["UnblendedCost"],
        "GroupBy": [{ "Type": "DIMENSION", "Key": "USAGE_TYPE" }],
    }))?;

    // Paginate and collect all entries
    let mut all: HashMap<String, f64> = HashMap::new();
    let mut next_token: Option<String> = None;

    loop {
        let body_with_token = if let Some(ref t) = next_token {
            let mut v: serde_json::Value = serde_json::from_slice(&body)?;
            v["NextPageToken"] = serde_json::Value::String(t.clone());
            serde_json::to_vec(&v)?
        } else {
            body.clone()
        };

        let signed = sign(
            creds,
            "POST",
            CE_ENDPOINT,
            &[
                ("content-type", CE_CONTENT_TYPE),
                ("x-amz-target", CE_TARGET),
            ],
            &body_with_token,
            "ce",
        )?;

        let mut req = client
            .post(CE_ENDPOINT)
            .header("content-type", CE_CONTENT_TYPE)
            .header("x-amz-target", CE_TARGET)
            .header("x-amz-date", &signed.x_amz_date)
            .header("x-amz-content-sha256", &signed.x_amz_content_sha256)
            .header("authorization", &signed.authorization)
            .body(body_with_token);
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
        let token = data.next_page_token;

        for result in data.results_by_time {
            for group in result.groups {
                if let Some(usage_type) = group.keys.into_iter().next() {
                    let amount: f64 = group
                        .metrics
                        .get("UnblendedCost")
                        .and_then(|m| m.amount.parse().ok())
                        .unwrap_or(0.0);
                    if amount > 0.0 {
                        *all.entry(usage_type).or_default() += amount;
                    }
                }
            }
        }

        match token {
            Some(t) if !t.is_empty() => next_token = Some(t),
            _ => break,
        }
    }

    let mut entries: Vec<DataTransferEntry> = all
        .into_iter()
        .map(|(usage_type, amount_usd)| {
            let description = describe_usage_type(&usage_type);
            DataTransferEntry { usage_type, description, amount_usd }
        })
        .collect();

    entries.sort_by(|a, b| b.amount_usd.partial_cmp(&a.amount_usd).unwrap_or(std::cmp::Ordering::Equal));
    Ok(entries)
}

/// Human-readable interpretation of a CE USAGE_TYPE string for data transfer.
fn describe_usage_type(usage_type: &str) -> String {
    let ut = usage_type.to_lowercase();
    let region = usage_type_region(usage_type);

    if ut.contains("cloudfront") && ut.contains("out") {
        format!("CloudFront internet egress{region}")
    } else if ut.contains("out-bytes") {
        format!("Internet egress{region}")
    } else if ut.contains("regional-bytes") {
        format!("Cross-AZ / intra-region transfer{region}")
    } else if ut.contains("in-bytes") {
        format!("Inbound transfer{region} (typically free)")
    } else if ut.contains("s3-egress") {
        format!("S3 egress{region}")
    } else {
        usage_type.to_string()
    }
}

/// Extract region name from a CE usage type prefix (e.g. "USE1" → " (us-east-1)").
fn usage_type_region(usage_type: &str) -> &'static str {
    let prefix = usage_type.split('-').next().unwrap_or("");
    match prefix {
        "USE1" => " (us-east-1)",
        "USE2" => " (us-east-2)",
        "USW1" => " (us-west-1)",
        "USW2" => " (us-west-2)",
        "EUW1" => " (eu-west-1)",
        "EUW2" => " (eu-west-2)",
        "EUW3" => " (eu-west-3)",
        "EUC1" => " (eu-central-1)",
        "EUN1" => " (eu-north-1)",
        "APN1" => " (ap-northeast-1)",
        "APN2" => " (ap-northeast-2)",
        "APS1" => " (ap-southeast-1)",
        "APS2" => " (ap-southeast-2)",
        "SAE1" => " (sa-east-1)",
        "CAC1" => " (ca-central-1)",
        _ => "",
    }
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
