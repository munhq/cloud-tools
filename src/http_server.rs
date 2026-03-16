use axum::{Json, Router, extract::State, http::StatusCode, routing::get, routing::post};
use axum::response::IntoResponse;
use chrono::{Duration as ChronoDuration, NaiveDate};
use serde::Deserialize;
use std::sync::Arc;

use crate::analyzers::{gcp_waste, waste, WasteItem}; // OrgWasteReport serialised via serde_json::to_value
use crate::clouds::aws::{auth::assume_role, ce, organizations};
use crate::clouds::cloudflare::{auth::CloudflareCreds, billing as cf_billing, workers};
use crate::clouds::gcp::{auth::GcpCreds, billing as gcp_billing, compute};
use crate::clouds::ovh::{auth::OvhCreds, billing as ovh_billing, instances};
use crate::setup::aws as aws_setup;
use crate::types::CostEntry;

#[derive(Clone)]
struct AppState {
    http: reqwest::Client,
}

// ── Request types ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AwsCostsRequest {
    role_arn: String,
    external_id: Option<String>,
    start_date: String,
    end_date: String,
}

#[derive(Deserialize)]
struct AwsWasteRequest {
    role_arn: String,
    external_id: Option<String>,
}

/// Org-level requests — only need the management account ID.
/// cloud-tools constructs the role ARN and external ID internally.
#[derive(Deserialize)]
struct AwsOrgRequest {
    management_account_id: String,
}

#[derive(Deserialize)]
struct GcpRequest {
    service_account_json: String,
    project_id: String,
    billing_account_id: String,
}

#[derive(Deserialize)]
struct CfRequest {
    api_token: String,
    account_id: String,
}

#[derive(Deserialize)]
struct OvhRequest {
    app_key: String,
    app_secret: String,
    consumer_key: String,
    #[serde(default = "default_ovh_endpoint")]
    endpoint: String,
}

fn default_ovh_endpoint() -> String {
    "ovh-eu".into()
}

// ── Server setup ──────────────────────────────────────────────────────────────

pub async fn serve(port: u16) -> anyhow::Result<()> {
    let state = Arc::new(AppState {
        http: reqwest::Client::new(),
    });

    let app = Router::new()
        .route("/health", get(health))
        // AWS onboarding
        .route("/setup/aws/cloudformation.yaml", get(setup_aws_template))
        .route("/setup/aws/member-cloudformation.yaml", get(setup_aws_member_template))
        .route("/setup/aws/initiate", post(setup_aws_initiate))
        .route("/setup/aws/verify", post(setup_aws_verify))
        // AWS data (single-account or management-role service view)
        .route("/aws/costs", post(aws_costs))
        .route("/aws/costs/compare", post(aws_costs_compare))
        .route("/aws/costs/data-transfer", post(aws_data_transfer))
        .route("/aws/savings-plans", post(aws_savings_plans))
        .route("/aws/waste", post(aws_waste))
        // AWS org-level data (management account must have MunbotFinOpsRole deployed)
        .route("/aws/org/costs", post(aws_org_costs))
        .route("/aws/org/waste", post(aws_org_waste))
        // GCP
        .route("/gcp/costs", post(gcp_costs))
        .route("/gcp/resources", post(gcp_resources))
        .route("/gcp/waste", post(gcp_waste))
        // Cloudflare
        .route("/cloudflare/costs", post(cf_costs))
        .route("/cloudflare/resources", post(cf_resources))
        // OVH
        .route("/ovh/costs", post(ovh_costs))
        .route("/ovh/resources", post(ovh_resources))
        .with_state(state);

    let addr = format!("0.0.0.0:{port}");
    tracing::info!("cloud-tools HTTP server listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> StatusCode {
    StatusCode::OK
}

// ── Route handlers ────────────────────────────────────────────────────────────

macro_rules! handle {
    ($fn:expr) => {
        match $fn {
            Ok(v) => (StatusCode::OK, Json(v)),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            ),
        }
    };
}

async fn aws_costs(
    State(s): State<Arc<AppState>>,
    Json(req): Json<AwsCostsRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    handle!(do_aws_costs(&s.http, req).await)
}

async fn aws_costs_compare(
    State(s): State<Arc<AppState>>,
    Json(req): Json<AwsWasteRequest>, // same shape: role_arn + optional external_id
) -> (StatusCode, Json<serde_json::Value>) {
    handle!(do_aws_costs_compare(&s.http, req).await)
}

async fn aws_data_transfer(
    State(s): State<Arc<AppState>>,
    Json(req): Json<AwsWasteRequest>, // role_arn + optional external_id
) -> (StatusCode, Json<serde_json::Value>) {
    handle!(do_aws_data_transfer(&s.http, req).await)
}

async fn aws_savings_plans(
    State(s): State<Arc<AppState>>,
    Json(req): Json<AwsWasteRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    handle!(do_aws_savings_plans(&s.http, req).await)
}

async fn aws_waste(
    State(s): State<Arc<AppState>>,
    Json(req): Json<AwsWasteRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    handle!(do_aws_waste(&s.http, req).await)
}

async fn aws_org_costs(
    State(s): State<Arc<AppState>>,
    Json(req): Json<AwsOrgRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    handle!(do_aws_org_costs(&s.http, req).await)
}

async fn aws_org_waste(
    State(s): State<Arc<AppState>>,
    Json(req): Json<AwsOrgRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    handle!(do_aws_org_waste(&s.http, req).await)
}

async fn gcp_costs(
    State(s): State<Arc<AppState>>,
    Json(req): Json<GcpRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    handle!(do_gcp_costs(&s.http, req).await)
}

async fn gcp_resources(
    State(s): State<Arc<AppState>>,
    Json(req): Json<GcpRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    handle!(do_gcp_resources(&s.http, req).await)
}

async fn gcp_waste(
    State(s): State<Arc<AppState>>,
    Json(req): Json<GcpRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    handle!(do_gcp_waste(&s.http, req).await)
}

async fn cf_costs(
    State(s): State<Arc<AppState>>,
    Json(req): Json<CfRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    handle!(do_cf_costs(&s.http, req).await)
}

async fn cf_resources(
    State(s): State<Arc<AppState>>,
    Json(req): Json<CfRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    handle!(do_cf_resources(&s.http, req).await)
}

async fn ovh_costs(
    State(s): State<Arc<AppState>>,
    Json(req): Json<OvhRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    handle!(do_ovh_costs(&s.http, req).await)
}

async fn ovh_resources(
    State(s): State<Arc<AppState>>,
    Json(req): Json<OvhRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    handle!(do_ovh_resources(&s.http, req).await)
}

// ── Business logic ────────────────────────────────────────────────────────────

async fn do_aws_costs(
    http: &reqwest::Client,
    req: AwsCostsRequest,
) -> anyhow::Result<serde_json::Value> {
    let creds = assume_role(http, &req.role_arn, req.external_id.as_deref()).await?;
    let start = NaiveDate::parse_from_str(&req.start_date, "%Y-%m-%d")
        .map_err(|_| anyhow::anyhow!("Invalid start_date"))?;
    let end = NaiveDate::parse_from_str(&req.end_date, "%Y-%m-%d")
        .map_err(|_| anyhow::anyhow!("Invalid end_date"))?;
    let costs: Vec<CostEntry> = ce::get_costs(http, &creds, start, end).await?;
    Ok(costs_response(&req.start_date, &req.end_date, &costs))
}

async fn do_aws_costs_compare(
    http: &reqwest::Client,
    req: AwsWasteRequest,
) -> anyhow::Result<serde_json::Value> {
    let creds = assume_role(http, &req.role_arn, req.external_id.as_deref()).await?;
    let comparison = ce::compare_costs(http, &creds).await?;
    Ok(serde_json::to_value(comparison)?)
}

async fn do_aws_data_transfer(
    http: &reqwest::Client,
    req: AwsWasteRequest,
) -> anyhow::Result<serde_json::Value> {
    let creds = assume_role(http, &req.role_arn, req.external_id.as_deref()).await?;
    let now = chrono::Utc::now().date_naive();
    let start = now - chrono::Duration::days(30);
    let entries = ce::get_data_transfer_breakdown(http, &creds, start, now).await?;
    let total: f64 = entries.iter().map(|e| e.amount_usd).sum();
    Ok(serde_json::json!({
        "period": { "start": start.to_string(), "end": now.to_string() },
        "total_usd": round2(total),
        "by_usage_type": entries.iter().map(|e| serde_json::json!({
            "usage_type": e.usage_type,
            "description": e.description,
            "amount_usd": round2(e.amount_usd),
        })).collect::<Vec<_>>(),
    }))
}

async fn do_aws_savings_plans(
    http: &reqwest::Client,
    req: AwsWasteRequest,
) -> anyhow::Result<serde_json::Value> {
    let creds = assume_role(http, &req.role_arn, req.external_id.as_deref()).await?;
    let now = chrono::Utc::now().date_naive();
    let start = now - ChronoDuration::days(30);
    let report = ce::get_savings_plans_report(http, &creds, start, now).await?;
    Ok(serde_json::to_value(report)?)
}

async fn do_aws_waste(
    http: &reqwest::Client,
    req: AwsWasteRequest,
) -> anyhow::Result<serde_json::Value> {
    let creds = assume_role(http, &req.role_arn, req.external_id.as_deref()).await?;
    let findings: Vec<WasteItem> = waste::analyse(http, &creds).await?;
    let total: f64 = findings.iter().map(|f| f.estimated_monthly_usd).sum();
    Ok(serde_json::json!({
        "total_estimated_monthly_waste_usd": round2(total),
        "finding_count": findings.len(),
        "findings": findings,
    }))
}

/// Org-wide costs grouped by linked account ID.
/// Returns `by_account` array: [{ account_id, amount_usd }]
async fn do_aws_org_costs(
    http: &reqwest::Client,
    req: AwsOrgRequest,
) -> anyhow::Result<serde_json::Value> {
    let external_id = format!("munbot-{}", req.management_account_id);
    let mgmt_arn = format!("arn:aws:iam::{}:role/MunbotFinOpsRole", req.management_account_id);
    let creds = assume_role(http, &mgmt_arn, Some(&external_id)).await?;

    let now = chrono::Utc::now().date_naive();
    let start = now - chrono::Duration::days(30);
    let costs = ce::get_costs_by_account(http, &creds, start, now).await?;

    // Try to map account IDs to names
    let accounts = organizations::list_accounts(http, &creds).await.unwrap_or_default();
    let name_map: std::collections::HashMap<_, _> =
        accounts.into_iter().map(|a| (a.id, a.name)).collect();

    let total: f64 = costs.iter().map(|c| c.amount_usd).sum();
    let by_account: Vec<serde_json::Value> = costs
        .iter()
        .map(|c| {
            let account_id = &c.service; // LINKED_ACCOUNT grouping puts ID in "service"
            let name = name_map.get(account_id).cloned();
            serde_json::json!({
                "account_id": account_id,
                "account_name": name,
                "amount_usd": round2(c.amount_usd),
            })
        })
        .collect();

    Ok(serde_json::json!({
        "period": { "start": start.to_string(), "end": now.to_string() },
        "total_usd": round2(total),
        "by_account": by_account,
    }))
}

/// Org-wide waste scan — assumes MunbotFinOpsMemberRole in each member account in parallel.
async fn do_aws_org_waste(
    http: &reqwest::Client,
    req: AwsOrgRequest,
) -> anyhow::Result<serde_json::Value> {
    let report = waste::analyse_org(http, &req.management_account_id).await?;
    Ok(serde_json::to_value(report)?)
}

async fn do_gcp_costs(
    http: &reqwest::Client,
    req: GcpRequest,
) -> anyhow::Result<serde_json::Value> {
    let creds = GcpCreds {
        service_account_json: req.service_account_json,
        project_id: req.project_id,
        billing_account_id: req.billing_account_id,
    };
    let costs = gcp_billing::get_costs(http, &creds).await?;
    let now = chrono::Utc::now().date_naive();
    let start = (now - chrono::Duration::days(30)).to_string();
    let end = now.to_string();
    Ok(costs_response(&start, &end, &costs))
}

async fn do_gcp_resources(
    http: &reqwest::Client,
    req: GcpRequest,
) -> anyhow::Result<serde_json::Value> {
    let creds = GcpCreds {
        service_account_json: req.service_account_json,
        project_id: req.project_id,
        billing_account_id: req.billing_account_id,
    };
    let resources = compute::list_resources(http, &creds).await?;
    let json: Vec<serde_json::Value> = resources
        .into_iter()
        .map(|r| resource_json(r.provider, &r.resource_id, r.resource_type, r.region, r.name, None, r.monthly_cost_estimate, r.last_active_at, r.raw))
        .collect();
    Ok(serde_json::json!({ "total_count": json.len(), "resources": json }))
}

async fn do_gcp_waste(
    http: &reqwest::Client,
    req: GcpRequest,
) -> anyhow::Result<serde_json::Value> {
    let creds = GcpCreds {
        service_account_json: req.service_account_json,
        project_id: req.project_id,
        billing_account_id: req.billing_account_id,
    };
    let findings: Vec<WasteItem> = gcp_waste::analyse(http, &creds).await?;
    let total: f64 = findings.iter().map(|f| f.estimated_monthly_usd).sum();
    Ok(serde_json::json!({
        "total_estimated_monthly_waste_usd": round2(total),
        "finding_count": findings.len(),
        "findings": findings,
    }))
}

async fn do_cf_costs(
    http: &reqwest::Client,
    req: CfRequest,
) -> anyhow::Result<serde_json::Value> {
    let creds = CloudflareCreds {
        api_token: req.api_token,
        account_id: req.account_id,
    };
    let costs = cf_billing::get_costs(http, &creds).await?;
    let now = chrono::Utc::now().date_naive();
    let start = (now - chrono::Duration::days(30)).to_string();
    let end = now.to_string();
    Ok(costs_response(&start, &end, &costs))
}

async fn do_cf_resources(
    http: &reqwest::Client,
    req: CfRequest,
) -> anyhow::Result<serde_json::Value> {
    let creds = CloudflareCreds {
        api_token: req.api_token,
        account_id: req.account_id,
    };
    let resources = workers::list_resources(http, &creds).await?;
    let json: Vec<serde_json::Value> = resources
        .into_iter()
        .map(|r| resource_json(r.provider, &r.resource_id, r.resource_type, None, r.name, None, None, r.last_active_at, r.raw))
        .collect();
    Ok(serde_json::json!({ "total_count": json.len(), "resources": json }))
}

async fn do_ovh_costs(
    http: &reqwest::Client,
    req: OvhRequest,
) -> anyhow::Result<serde_json::Value> {
    let creds = OvhCreds {
        app_key: req.app_key,
        app_secret: req.app_secret,
        consumer_key: req.consumer_key,
        endpoint: req.endpoint,
    };
    let costs = ovh_billing::get_costs(http, &creds).await?;
    let now = chrono::Utc::now().date_naive();
    let start = (now - chrono::Duration::days(180)).to_string();
    let end = now.to_string();
    Ok(costs_response(&start, &end, &costs))
}

async fn do_ovh_resources(
    http: &reqwest::Client,
    req: OvhRequest,
) -> anyhow::Result<serde_json::Value> {
    let creds = OvhCreds {
        app_key: req.app_key,
        app_secret: req.app_secret,
        consumer_key: req.consumer_key,
        endpoint: req.endpoint,
    };
    let resources = instances::list_resources(http, &creds).await?;
    let json: Vec<serde_json::Value> = resources
        .into_iter()
        .map(|r| resource_json(r.provider, &r.resource_id, r.resource_type, r.region, r.name, None, None, r.last_active_at, r.raw))
        .collect();
    Ok(serde_json::json!({ "total_count": json.len(), "resources": json }))
}

// ── Setup / onboarding ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct SetupAwsInitiateRequest {
    management_account_id: String,
}

#[derive(Deserialize)]
struct SetupAwsVerifyRequest {
    management_account_id: String,
}

async fn setup_aws_template() -> impl IntoResponse {
    (StatusCode::OK, [("content-type", "application/x-yaml")], aws_setup::CLOUDFORMATION_TEMPLATE)
}

async fn setup_aws_member_template() -> impl IntoResponse {
    (StatusCode::OK, [("content-type", "application/x-yaml")], aws_setup::MEMBER_CLOUDFORMATION_TEMPLATE)
}

async fn setup_aws_initiate(
    Json(req): Json<SetupAwsInitiateRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    match aws_setup::initiate(&req.management_account_id) {
        Ok(r) => (StatusCode::OK, Json(serde_json::to_value(r).unwrap())),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        ),
    }
}

async fn setup_aws_verify(
    State(s): State<Arc<AppState>>,
    Json(req): Json<SetupAwsVerifyRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let result = aws_setup::verify(&s.http, &req.management_account_id).await;
    let status = if result.connected { StatusCode::OK } else { StatusCode::BAD_GATEWAY };
    (status, Json(serde_json::to_value(result).unwrap()))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn costs_response(start: &str, end: &str, costs: &[CostEntry]) -> serde_json::Value {
    let total: f64 = costs.iter().map(|c| c.amount_usd).sum();
    serde_json::json!({
        "period": { "start": start, "end": end },
        "total_usd": round2(total),
        "by_service": costs.iter().map(|c| serde_json::json!({
            "service": c.service,
            "amount_usd": round2(c.amount_usd),
        })).collect::<Vec<_>>(),
    })
}

#[allow(clippy::too_many_arguments)]
fn resource_json(
    provider: &str,
    resource_id: &str,
    resource_type: &str,
    region: Option<String>,
    name: Option<String>,
    tags: Option<String>,
    monthly_cost_estimate: Option<f64>,
    last_active_at: Option<String>,
    raw: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "provider": provider,
        "resource_id": resource_id,
        "resource_type": resource_type,
        "region": region,
        "name": name,
        "tags": tags,
        "monthly_cost_estimate": monthly_cost_estimate,
        "last_active_at": last_active_at,
        "raw_data": raw.to_string(),
    })
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}
