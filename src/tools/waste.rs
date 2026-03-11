use serde::Deserialize;
use rmcp::schemars;

use crate::analyzers::waste;
use crate::clouds::aws::auth::assume_role;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FindWasteInput {
    #[schemars(description = "Customer's IAM Role ARN, e.g. arn:aws:iam::123456789:role/CloudToolsReadOnly")]
    pub role_arn: String,
    #[schemars(description = "Optional external ID from the role's trust policy")]
    pub external_id: Option<String>,
}

pub(crate) struct WasteTool {
    pub(crate) http: reqwest::Client,
}

impl WasteTool {
    pub fn new(http: reqwest::Client) -> Self {
        Self { http }
    }

    pub async fn run(&self, input: FindWasteInput) -> String {
        match self.find_waste(input).await {
            Ok(result) => result,
            Err(e) => format!(r#"{{"error": "{e}"}}"#),
        }
    }

    async fn find_waste(&self, input: FindWasteInput) -> anyhow::Result<String> {
        let creds = assume_role(&self.http, &input.role_arn, input.external_id.as_deref()).await?;
        let findings = waste::analyse(&self.http, &creds).await?;

        let total_waste: f64 = findings.iter().map(|f| f.estimated_monthly_usd).sum();

        let output = serde_json::json!({
            "total_estimated_monthly_waste_usd": round2(total_waste),
            "finding_count": findings.len(),
            "findings": findings,
        });

        Ok(serde_json::to_string_pretty(&output)?)
    }
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}
