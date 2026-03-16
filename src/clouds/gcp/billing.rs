//! GCP billing data.
//!
//! Primary path: BigQuery billing export (requires `billing_table` in GcpCreds).
//! Gives per-service cost breakdown equivalent to AWS Cost Explorer.
//!
//! Fallback: Cloud Billing Budgets API (only returns budget amounts, not actual spend).

use anyhow::{anyhow, Result};
use chrono::{Duration, NaiveDate, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::types::CostEntry;

use super::auth::{access_token, GcpCreds};

// ── Public API ───────────────────────────────────────────────────────────────

/// Get costs for a date range. Uses BigQuery billing export if configured,
/// otherwise falls back to the Budgets API.
pub async fn get_costs(http: &Client, creds: &GcpCreds) -> Result<Vec<CostEntry>> {
    if let Some(ref table) = creds.billing_table {
        let end = Utc::now().date_naive();
        let start = end - Duration::days(30);
        return bigquery_costs(http, creds, table, start, end).await;
    }
    // Fallback to budgets
    budgets_costs(http, creds).await
}

/// Get costs for a specific date range (BigQuery only).
pub async fn get_costs_range(
    http: &Client,
    creds: &GcpCreds,
    start: NaiveDate,
    end: NaiveDate,
) -> Result<Vec<CostEntry>> {
    let table = creds.billing_table.as_ref()
        .ok_or_else(|| anyhow!("billing_table not configured — set CLOUD_GCP_BILLING_TABLE for real cost data"))?;
    bigquery_costs(http, creds, table, start, end).await
}

/// Fair month-over-month comparison (same day window, like AWS CE compare).
/// Only available with BigQuery billing export.
pub async fn compare_costs(http: &Client, creds: &GcpCreds) -> Result<CostComparison> {
    let table = creds.billing_table.as_ref()
        .ok_or_else(|| anyhow!("billing_table not configured — needed for cost comparison"))?;

    let now = Utc::now().date_naive();
    let day_of_month = now.day() as i64;

    // Current period: 1st of this month → today
    let cur_start = NaiveDate::from_ymd_opt(now.year(), now.month(), 1)
        .ok_or_else(|| anyhow!("Invalid date"))?;
    let cur_end = now;

    // Prior period: 1st of last month → same day of last month
    let prev_month = cur_start - Duration::days(1);
    let prev_start = NaiveDate::from_ymd_opt(prev_month.year(), prev_month.month(), 1)
        .ok_or_else(|| anyhow!("Invalid date"))?;
    let prev_end = prev_start + Duration::days(day_of_month - 1);

    let (cur_costs, prev_costs) = tokio::join!(
        bigquery_costs(http, creds, table, cur_start, cur_end),
        bigquery_costs(http, creds, table, prev_start, prev_end),
    );

    let current = cur_costs.unwrap_or_default();
    let previous = prev_costs.unwrap_or_default();

    let cur_total: f64 = current.iter().map(|c| c.amount_usd).sum();
    let prev_total: f64 = previous.iter().map(|c| c.amount_usd).sum();
    let change_pct = if prev_total > 0.0 {
        ((cur_total - prev_total) / prev_total) * 100.0
    } else {
        0.0
    };

    Ok(CostComparison {
        current_period: format!("{cur_start} to {cur_end}"),
        previous_period: format!("{prev_start} to {prev_end}"),
        current_total_usd: round2(cur_total),
        previous_total_usd: round2(prev_total),
        change_pct: round2(change_pct),
        current_by_service: current,
        previous_by_service: previous,
    })
}

/// Get costs grouped by project (for multi-project/org scanning).
/// Requires BigQuery billing export.
pub async fn get_costs_by_project(
    http: &Client,
    creds: &GcpCreds,
) -> Result<Vec<ProjectCost>> {
    let table = creds.billing_table.as_ref()
        .ok_or_else(|| anyhow!("billing_table not configured"))?;
    let token = access_token(http, creds).await?;

    let now = Utc::now().date_naive();
    let start = now - Duration::days(30);

    let query = format!(
        "SELECT project.id as project_id, project.name as project_name, \
         SUM(cost) + SUM(IFNULL((SELECT SUM(c.amount) FROM UNNEST(credits) c), 0)) as net_cost \
         FROM `{table}` \
         WHERE usage_start_time >= TIMESTAMP('{start}') \
         AND usage_start_time < TIMESTAMP('{now}') \
         GROUP BY project.id, project.name \
         ORDER BY net_cost DESC",
    );

    let resp = run_bq_query(http, &token, &creds.project_id, &query).await?;
    let rows = bq_rows(&resp);

    Ok(rows
        .iter()
        .filter_map(|row| {
            let cells = row.as_array()?;
            let project_id = cells.first()?.get("v")?.as_str()?.to_string();
            let project_name = cells.get(1)?.get("v")?.as_str().map(String::from);
            let amount = cells.get(2)?.get("v")?.as_str()?.parse::<f64>().ok()?;
            Some(ProjectCost {
                project_id,
                project_name,
                amount_usd: round2(amount),
            })
        })
        .collect())
}

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct CostComparison {
    pub current_period: String,
    pub previous_period: String,
    pub current_total_usd: f64,
    pub previous_total_usd: f64,
    pub change_pct: f64,
    pub current_by_service: Vec<CostEntry>,
    pub previous_by_service: Vec<CostEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectCost {
    pub project_id: String,
    pub project_name: Option<String>,
    pub amount_usd: f64,
}

// ── BigQuery billing export ──────────────────────────────────────────────────

async fn bigquery_costs(
    http: &Client,
    creds: &GcpCreds,
    table: &str,
    start: NaiveDate,
    end: NaiveDate,
) -> Result<Vec<CostEntry>> {
    let token = access_token(http, creds).await?;

    let query = format!(
        "SELECT service.description as service, \
         SUM(cost) + SUM(IFNULL((SELECT SUM(c.amount) FROM UNNEST(credits) c), 0)) as net_cost \
         FROM `{table}` \
         WHERE usage_start_time >= TIMESTAMP('{start}') \
         AND usage_start_time < TIMESTAMP('{end}') \
         GROUP BY service.description \
         HAVING net_cost > 0.01 \
         ORDER BY net_cost DESC",
    );

    let resp = run_bq_query(http, &token, &creds.project_id, &query).await?;
    let rows = bq_rows(&resp);

    Ok(rows
        .iter()
        .filter_map(|row| {
            let cells = row.as_array()?;
            let service = cells.first()?.get("v")?.as_str()?.to_string();
            let amount = cells.get(1)?.get("v")?.as_str()?.parse::<f64>().ok()?;
            Some(CostEntry {
                service,
                amount_usd: round2(amount),
                period_start: start,
                period_end: end,
            })
        })
        .collect())
}

async fn run_bq_query(
    http: &Client,
    token: &str,
    project_id: &str,
    query: &str,
) -> Result<serde_json::Value> {
    let url = format!(
        "https://bigquery.googleapis.com/bigquery/v2/projects/{project_id}/queries"
    );

    let body = serde_json::json!({
        "query": query,
        "useLegacySql": false,
        "maxResults": 10000,
        "timeoutMs": 30000,
    });

    let resp = http
        .post(&url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .await?;

    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        return Err(anyhow!("BigQuery error {status}: {text}"));
    }

    let data: serde_json::Value = serde_json::from_str(&text)?;

    // Check if query completed
    if data["jobComplete"].as_bool() != Some(true) {
        return Err(anyhow!("BigQuery query timed out — try a smaller date range"));
    }

    Ok(data)
}

fn bq_rows(resp: &serde_json::Value) -> Vec<serde_json::Value> {
    resp["rows"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|row| row.get("f").cloned())
        .collect()
}

// ── Budgets API fallback ─────────────────────────────────────────────────────

async fn budgets_costs(http: &Client, creds: &GcpCreds) -> Result<Vec<CostEntry>> {
    let token = access_token(http, creds).await?;
    let end = Utc::now().date_naive();
    let start = end - Duration::days(30);

    let url = format!(
        "https://billingbudgets.googleapis.com/v1/billingAccounts/{}/budgets",
        creds.billing_account_id
    );
    let resp = http.get(&url).bearer_auth(&token).send().await?;
    if !resp.status().is_success() {
        tracing::warn!(
            "GCP billing budgets not accessible ({}); set billing_table for real cost data via BigQuery export",
            resp.status()
        );
        return Ok(Vec::new());
    }

    let data: serde_json::Value = resp.json().await?;
    Ok(data["budgets"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|b| {
            let amount = b["amount"]["specifiedAmount"]["units"]
                .as_str()
                .and_then(|s| s.parse::<f64>().ok())
                .unwrap_or(0.0);
            if amount == 0.0 {
                return None;
            }
            Some(CostEntry {
                service: b["displayName"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string(),
                amount_usd: amount,
                period_start: start,
                period_end: end,
            })
        })
        .collect())
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

use chrono::Datelike;
