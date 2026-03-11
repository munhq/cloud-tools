use anyhow::Result;
use chrono::NaiveDate;
use rmcp::{
    ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    schemars, tool, tool_router,
};
use serde::Deserialize;

use crate::clouds::aws::{auth::assume_role, ce};
use crate::tools::waste::{FindWasteInput, WasteTool};
use crate::types::CostEntry;

// ── Input types ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetAwsCostsInput {
    #[schemars(description = "Customer's IAM Role ARN, e.g. arn:aws:iam::123456789:role/CloudToolsReadOnly")]
    pub role_arn: String,
    #[schemars(description = "Optional external ID from the role's trust policy")]
    pub external_id: Option<String>,
    #[schemars(description = "Start date inclusive, format YYYY-MM-DD")]
    pub start_date: String,
    #[schemars(description = "End date exclusive, format YYYY-MM-DD")]
    pub end_date: String,
}

// ── MCP server handler ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CloudTools {
    #[allow(dead_code)] // used by #[tool_router] macro expansion
    tool_router: ToolRouter<Self>,
    http: reqwest::Client,
}

impl CloudTools {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
            http: reqwest::Client::new(),
        }
    }
}

impl Default for CloudTools {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_router]
impl CloudTools {
    #[tool(description = "Get AWS costs grouped by service for a date range. Returns total spend and per-service breakdown sorted by cost descending. Use for questions like 'what did we spend last week?' or 'which services cost the most?'")]
    async fn get_aws_costs(&self, Parameters(input): Parameters<GetAwsCostsInput>) -> String {
        match self.fetch_aws_costs(input).await {
            Ok(result) => result,
            Err(e) => format!(r#"{{"error": "{e}"}}"#),
        }
    }

    #[tool(description = "Analyse an AWS account for waste, idle resources, oversized instances, orphaned volumes, unattached EIPs, and optimisation opportunities. Returns findings sorted by estimated monthly savings.")]
    async fn find_aws_waste(&self, Parameters(input): Parameters<FindWasteInput>) -> String {
        WasteTool::new(self.http.clone()).run(input).await
    }
}

impl CloudTools {
    async fn fetch_aws_costs(&self, input: GetAwsCostsInput) -> Result<String> {
        let creds = assume_role(&self.http, &input.role_arn, input.external_id.as_deref()).await?;

        let start = NaiveDate::parse_from_str(&input.start_date, "%Y-%m-%d")
            .map_err(|_| anyhow::anyhow!("Invalid start_date, expected YYYY-MM-DD"))?;
        let end = NaiveDate::parse_from_str(&input.end_date, "%Y-%m-%d")
            .map_err(|_| anyhow::anyhow!("Invalid end_date, expected YYYY-MM-DD"))?;

        let costs: Vec<CostEntry> = ce::get_costs(&self.http, &creds, start, end).await?;
        let total: f64 = costs.iter().map(|c| c.amount_usd).sum();

        let output = serde_json::json!({
            "period": { "start": input.start_date, "end": input.end_date },
            "total_usd": round2(total),
            "by_service": costs.iter().map(|c| serde_json::json!({
                "service": c.service,
                "amount_usd": round2(c.amount_usd),
            })).collect::<Vec<_>>(),
        });

        Ok(serde_json::to_string_pretty(&output)?)
    }
}

impl ServerHandler for CloudTools {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(
                "Multi-cloud data extraction: AWS costs, resource inventory, waste detection. \
                 Credentials are never stored — pass a Role ARN per call.",
            )
    }
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}
