use anyhow::{Context, Result};
use chrono::{NaiveDate, Utc};
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{Implementation, ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router, ServerHandler,
};
use serde::Deserialize;

use crate::analyzers::gcp_waste;
use crate::clouds::aws::{
    auth::{ambient_credentials, assume_role, AwsCreds},
    ce,
};
use crate::clouds::cloudflare::{
    auth::CloudflareCreds, billing as cf_billing, certificates as cf_certs, dns as cf_dns,
    workers as cf_workers, zones as cf_zones,
};
use crate::clouds::gcp::{
    artifact_registry, auth::GcpCreds, billing as gcp_billing, cloud_functions, cloud_ids,
    cloud_nat, cloud_run, cloud_sql, cloud_vpn, commitments, compute, gke, monitoring, networking,
    recommender, storage,
};
use crate::clouds::ovh::{
    auth::OvhCreds, billing as ovh_billing, instances as ovh_instances, services as ovh_services,
};
use crate::types::CostEntry;

// ── One credential shape, one cloud selector ─────────────────────────────────
//
// Every tool below takes the same two things: which cloud, and the credentials
// for it. That is the whole of the unification. The surface used to be thirteen
// tools whose names encoded the cloud — get_aws_costs beside get_gcp_inventory —
// so an agent had to learn a different name, and a different argument shape, for
// every cloud and capability pair. Seven tools with one shape replace them.
//
// The credentials are a struct of optionals rather than an enum, because
// get_cross_cloud_summary needs several at once and the alternative is two
// vocabularies for the same thing.

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Cloud {
    Aws,
    Gcp,
    Cloudflare,
    Ovh,
}

impl Cloud {
    fn name(&self) -> &'static str {
        match self {
            Cloud::Aws => "aws",
            Cloud::Gcp => "gcp",
            Cloud::Cloudflare => "cloudflare",
            Cloud::Ovh => "ovh",
        }
    }
}

/// A capability this cloud does not have, answered as a sentence rather than a
/// silent empty result.
///
/// Coverage is uneven and saying so is the honest option: waste analysis exists
/// for AWS and GCP only, and a caller who asks for it on OVH deserves to be told
/// which clouds do support it rather than reading an empty findings list as
/// "nothing is wasted".
fn unsupported(what: &str, cloud: &Cloud, supported: &[&str]) -> anyhow::Error {
    anyhow::anyhow!(
        "{what} is not implemented for {}; supported: {}",
        cloud.name(),
        supported.join(", ")
    )
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AwsCredentials {
    #[schemars(
        description = "Optional IAM Role ARN to assume, e.g. arn:aws:iam::123456789012:role/CloudToolsReadOnly. \
                       Omit it to use the server's own credentials directly, which is what you want when \
                       cloud-tools runs on your machine against your own account."
    )]
    pub role_arn: Option<String>,
    #[schemars(description = "Optional external ID, when the role's trust policy requires one")]
    pub external_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GcpCredentials {
    #[schemars(
        description = "One or more GCP project IDs, e.g. [\"example-dev\", \"example-prod\"]"
    )]
    pub project_ids: Vec<String>,
    #[schemars(
        description = "Optional service account JSON. Omit it to use Application Default Credentials from `gcloud auth application-default login`."
    )]
    pub service_account_json: Option<String>,
    #[schemars(
        description = "Optional BigQuery billing export table, as project.dataset.table. \
                       REQUIRED for get_costs and compare_costs on GCP: Google publishes no \
                       per-service spend API, so the numbers come from the billing export. \
                       Without it, get_costs falls back to the Budgets API, which returns \
                       budget amounts rather than actual spend."
    )]
    pub billing_table: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CloudflareCredentials {
    #[schemars(description = "Cloudflare API token with read access to account resources")]
    pub api_token: String,
    #[schemars(description = "Cloudflare account ID")]
    pub account_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct OvhCredentials {
    #[schemars(description = "OVH application key")]
    pub app_key: String,
    #[schemars(description = "OVH application secret")]
    pub app_secret: String,
    #[schemars(description = "OVH consumer key")]
    pub consumer_key: String,
    #[schemars(description = "OVH API endpoint: ovh-eu (default), ovh-us, or ovh-ca")]
    pub endpoint: Option<String>,
}

/// Credentials for any subset of the clouds.
///
/// A single-cloud tool reads the one field matching its `cloud` argument;
/// get_cross_cloud_summary reads every field it is given and skips the rest.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct Credentials {
    pub aws: Option<AwsCredentials>,
    pub gcp: Option<GcpCredentials>,
    pub cloudflare: Option<CloudflareCredentials>,
    pub ovh: Option<OvhCredentials>,
}

impl Credentials {
    fn aws(&self) -> Result<&AwsCredentials> {
        self.aws.as_ref().context(
            "credentials.aws is missing. It may be an empty object: AWS works from the \
                      server's own credentials unless you pass a role_arn to assume.",
        )
    }
    fn gcp(&self) -> Result<&GcpCredentials> {
        self.gcp
            .as_ref()
            .context("credentials.gcp is missing. It needs at least project_ids.")
    }
    fn cloudflare(&self) -> Result<&CloudflareCredentials> {
        self.cloudflare
            .as_ref()
            .context("credentials.cloudflare is missing. It needs api_token and account_id.")
    }
    fn ovh(&self) -> Result<&OvhCredentials> {
        self.ovh
            .as_ref()
            .context("credentials.ovh is missing. It needs app_key, app_secret and consumer_key.")
    }
}

// ── Tool inputs ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CostsInput {
    #[schemars(description = "Which cloud to query: aws, gcp, cloudflare or ovh")]
    pub cloud: Cloud,
    pub credentials: Credentials,
    #[schemars(
        description = "Start date inclusive, YYYY-MM-DD. AWS and GCP only; defaults to 30 days ago."
    )]
    pub start_date: Option<String>,
    #[schemars(
        description = "End date exclusive, YYYY-MM-DD. AWS and GCP only; defaults to today."
    )]
    pub end_date: Option<String>,
    #[schemars(
        description = "AWS only. \"service\" (default) breaks spend down by service; \
                       \"data_transfer\" breaks it down by transfer usage type instead — \
                       internet egress, cross-AZ and inter-region."
    )]
    pub group_by: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CloudInput {
    #[schemars(description = "Which cloud to query: aws, gcp, cloudflare or ovh")]
    pub cloud: Cloud,
    pub credentials: Credentials,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SummaryInput {
    #[schemars(
        description = "Credentials for every cloud to include. A cloud you omit is skipped."
    )]
    pub credentials: Credentials,
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
    #[tool(
        description = "Cloud spend. AWS: by service over a date range, from Cost Explorer; pass group_by=\"data_transfer\" for transfer cost by usage type. GCP: by service from the BigQuery billing export, which credentials.gcp.billing_table must name — without it you get budget amounts, not spend. Cloudflare: subscriptions and zone plan costs. OVH: the 6 most recent invoices."
    )]
    async fn get_costs(&self, Parameters(input): Parameters<CostsInput>) -> String {
        answer(self.costs(input).await)
    }

    #[tool(
        description = "This period against the same day window of the previous month, so a partial month does not read as a fall. AWS and GCP only. GCP needs credentials.gcp.billing_table."
    )]
    async fn compare_costs(&self, Parameters(input): Parameters<CloudInput>) -> String {
        answer(self.compare(input).await)
    }

    #[tool(
        description = "What exists. GCP: GCE instances, disks, addresses, snapshots, forwarding rules, GKE clusters with node pools, Cloud SQL, Cloud Functions, Cloud Run, GCS buckets, Cloud NAT, Cloud IDS, Artifact Registry, VPN gateways, subnets, PSC endpoints and Cloud Logging ingestion, with a per-project summary. Cloudflare: zones with plan and price, DNS records split proxied against dns-only, certificates with hosts and expiry, and Workers with invocation counts. OVH: instances and active services with renewal dates and monthly cost. Not implemented for AWS."
    )]
    async fn get_inventory(&self, Parameters(input): Parameters<CloudInput>) -> String {
        answer(self.inventory(input).await)
    }

    #[tool(
        description = "What is wasted, with the monthly cost of each finding and the utilisation evidence behind it. AWS: idle and oversized EC2 and RDS measured from CloudWatch CPU series, stopped instances, orphaned volumes and snapshots, unused AMIs and Elastic IPs, idle load balancers and NAT gateways, DynamoDB and ElastiCache, and log groups with no retention. GCP: idle and oversized instances, orphaned disks, unattached addresses, snapshots over 90 days, idle Cloud SQL, GKE clusters with no nodes, Cloud Functions and Cloud Run with no invocations, buckets with no lifecycle rule. Not implemented for Cloudflare or OVH."
    )]
    async fn get_waste(&self, Parameters(input): Parameters<CloudInput>) -> String {
        answer(self.waste(input).await)
    }

    #[tool(
        description = "Commitments you are paying for, and whether you are consuming them. AWS: Savings Plans utilisation, coverage of eligible spend, and the saving a further commitment would give. GCP: committed use discounts with their expiry. Not implemented for Cloudflare or OVH, which sell no commitments."
    )]
    async fn get_commitments(&self, Parameters(input): Parameters<CloudInput>) -> String {
        answer(self.commitments(input).await)
    }

    #[tool(
        description = "The cloud provider's own optimisation suggestions. GCP: the Recommender API across every zone and region — idle VMs, machine type rightsizing, idle disks and addresses, idle and oversized Cloud SQL. Not implemented for the others; AWS Compute Optimizer is read as part of get_waste instead."
    )]
    async fn get_recommendations(&self, Parameters(input): Parameters<CloudInput>) -> String {
        answer(self.recommendations(input).await)
    }

    #[tool(
        description = "One cost and waste report over every cloud you pass credentials for, with a grand total. Omit a cloud's credentials to skip it."
    )]
    async fn get_cross_cloud_summary(&self, Parameters(input): Parameters<SummaryInput>) -> String {
        answer(self.summary(input).await)
    }
}

/// Render a tool result, so every tool reports failure the same way.
///
/// The old code formatted the error straight into a JSON string with `format!`,
/// which produces invalid JSON the moment a message contains a quote — and AWS
/// error messages contain XML. Serialising it closes that.
fn answer(result: Result<String>) -> String {
    match result {
        Ok(body) => body,
        Err(e) => serde_json::json!({ "error": e.to_string() }).to_string(),
    }
}

impl CloudTools {
    // ── Dispatch: one arm per cloud, or a sentence saying there is none ───────

    /// Resolve AWS credentials for a call.
    ///
    /// `role_arn` is optional now. It used to be required on every AWS tool,
    /// which is right for a service scanning other people's accounts and wrong
    /// for someone running this on their own machine against their own account —
    /// they had to create a role in their account that trusts themselves before
    /// a single tool would answer. Omitting it uses the credentials the server
    /// already resolved.
    async fn aws_creds(&self, c: &AwsCredentials) -> Result<AwsCreds> {
        match c.role_arn.as_deref() {
            Some(arn) => assume_role(&self.http, arn, c.external_id.as_deref()).await,
            None => ambient_credentials(&self.http).await,
        }
    }

    /// GCP credentials for the first project, carrying the billing table.
    fn gcp_for(&self, c: &GcpCredentials, project_id: &str) -> Result<GcpCreds> {
        Self::gcp_creds(
            project_id,
            c.service_account_json.as_deref(),
            c.billing_table.clone(),
            None,
        )
    }

    async fn costs(&self, input: CostsInput) -> Result<String> {
        let cr = &input.credentials;
        // A missing range means the last 30 days, which is the window every one
        // of these APIs is cheapest to answer for.
        let end = input
            .end_date
            .clone()
            .unwrap_or_else(|| Utc::now().date_naive().to_string());
        let start = input
            .start_date
            .clone()
            .unwrap_or_else(|| (Utc::now().date_naive() - chrono::Duration::days(30)).to_string());

        match input.cloud {
            Cloud::Aws => {
                let aws = cr.aws()?;
                match input.group_by.as_deref() {
                    Some("data_transfer") => self.do_data_transfer(aws).await,
                    Some("service") | None => self.fetch_aws_costs(aws, &start, &end).await,
                    Some(other) => Err(anyhow::anyhow!(
                        "group_by \"{other}\" is not known; use \"service\" or \"data_transfer\""
                    )),
                }
            }
            Cloud::Gcp => self.gcp_costs(cr.gcp()?, &start, &end).await,
            Cloud::Cloudflare => self.fetch_cf_costs(cr.cloudflare()?).await,
            Cloud::Ovh => self.fetch_ovh_costs(cr.ovh()?).await,
        }
    }

    /// GCP spend, which Google publishes nowhere except a billing export.
    ///
    /// There is no per-service spend API. With `billing_table` set this queries
    /// the BigQuery export; without it the Budgets API answers with budget
    /// amounts, which are not spend — so that case says so in the payload rather
    /// than letting a budget be read as a bill.
    async fn gcp_costs(&self, c: &GcpCredentials, start: &str, end: &str) -> Result<String> {
        let project = c
            .project_ids
            .first()
            .context("credentials.gcp.project_ids is empty")?;
        let creds = self.gcp_for(c, project)?;
        let start_d = NaiveDate::parse_from_str(start, "%Y-%m-%d")
            .map_err(|_| anyhow::anyhow!("Invalid start_date, expected YYYY-MM-DD"))?;
        let end_d = NaiveDate::parse_from_str(end, "%Y-%m-%d")
            .map_err(|_| anyhow::anyhow!("Invalid end_date, expected YYYY-MM-DD"))?;

        let (costs, source) = if c.billing_table.is_some() {
            (
                gcp_billing::get_costs_range(&self.http, &creds, start_d, end_d).await?,
                "bigquery_billing_export",
            )
        } else {
            (gcp_billing::get_costs(&self.http, &creds).await?, "budgets")
        };
        let total: f64 = costs.iter().map(|c| c.amount_usd).sum();
        Ok(serde_json::to_string_pretty(&serde_json::json!({
            "period": { "start": start, "end": end },
            "source": source,
            "note": if c.billing_table.is_some() { serde_json::Value::Null } else {
                serde_json::json!("No billing_table was given, so these are BUDGET amounts from the \
                                   Budgets API, not actual spend. Set credentials.gcp.billing_table \
                                   to the BigQuery billing export table for real costs.")
            },
            "total_usd": round2(total),
            "by_service": costs.iter().map(|c| serde_json::json!({
                "service": c.service,
                "amount_usd": round2(c.amount_usd),
            })).collect::<Vec<_>>(),
        }))?)
    }

    async fn compare(&self, input: CloudInput) -> Result<String> {
        let cr = &input.credentials;
        match input.cloud {
            Cloud::Aws => self.do_compare_costs(cr.aws()?).await,
            Cloud::Gcp => {
                let c = cr.gcp()?;
                let project = c
                    .project_ids
                    .first()
                    .context("credentials.gcp.project_ids is empty")?;
                let creds = self.gcp_for(c, project)?;
                let cmp = gcp_billing::compare_costs(&self.http, &creds).await?;
                Ok(serde_json::to_string_pretty(&cmp)?)
            }
            ref other => Err(unsupported("cost comparison", other, &["aws", "gcp"])),
        }
    }

    async fn inventory(&self, input: CloudInput) -> Result<String> {
        let cr = &input.credentials;
        match input.cloud {
            Cloud::Gcp => self.fetch_gcp_inventory(cr.gcp()?).await,
            Cloud::Cloudflare => self.fetch_cf_inventory(cr.cloudflare()?).await,
            Cloud::Ovh => self.fetch_ovh_inventory(cr.ovh()?).await,
            // The building blocks exist — waste analysis lists EC2, RDS, S3 and
            // the rest — but nothing assembles them into an inventory yet.
            ref other => Err(unsupported(
                "inventory",
                other,
                &["gcp", "cloudflare", "ovh"],
            )),
        }
    }

    async fn waste(&self, input: CloudInput) -> Result<String> {
        let cr = &input.credentials;
        match input.cloud {
            Cloud::Aws => {
                let creds = self.aws_creds(cr.aws()?).await?;
                let findings = crate::analyzers::waste::analyse(&self.http, &creds).await?;
                let total: f64 = findings.iter().map(|f| f.estimated_monthly_usd).sum();
                Ok(serde_json::to_string_pretty(&serde_json::json!({
                    "total_estimated_monthly_waste_usd": round2(total),
                    "finding_count": findings.len(),
                    "findings": findings,
                }))?)
            }
            Cloud::Gcp => self.do_find_gcp_waste(cr.gcp()?).await,
            ref other => Err(unsupported("waste analysis", other, &["aws", "gcp"])),
        }
    }

    async fn commitments(&self, input: CloudInput) -> Result<String> {
        let cr = &input.credentials;
        match input.cloud {
            Cloud::Aws => self.do_savings_plans(cr.aws()?).await,
            Cloud::Gcp => {
                let c = cr.gcp()?;
                let mut all = Vec::new();
                for project in &c.project_ids {
                    let creds = self.gcp_for(c, project)?;
                    match commitments::list_commitments(&self.http, &creds).await {
                        Ok(list) => all.push(serde_json::json!({
                            "project_id": project,
                            "commitments": list,
                        })),
                        Err(e) => all.push(serde_json::json!({
                            "project_id": project,
                            "error": e.to_string(),
                        })),
                    }
                }
                Ok(serde_json::to_string_pretty(&serde_json::json!({
                    "projects": all,
                }))?)
            }
            // Neither sells a commitment, so there is nothing to report rather
            // than something not yet built.
            ref other => Err(unsupported("commitment reporting", other, &["aws", "gcp"])),
        }
    }

    async fn recommendations(&self, input: CloudInput) -> Result<String> {
        let cr = &input.credentials;
        match input.cloud {
            Cloud::Gcp => self.fetch_gcp_recommendations(cr.gcp()?).await,
            ref other => Err(unsupported("provider recommendations", other, &["gcp"])),
        }
    }

    async fn summary(&self, input: SummaryInput) -> Result<String> {
        self.fetch_cross_cloud_summary(&input.credentials).await
    }

    async fn do_savings_plans(&self, input: &AwsCredentials) -> Result<String> {
        let creds = self.aws_creds(input).await?;
        let now = Utc::now().date_naive();
        let start = now - chrono::Duration::days(30);
        let report = ce::get_savings_plans_report(&self.http, &creds, start, now).await?;
        Ok(serde_json::to_string_pretty(&report)?)
    }

    async fn do_data_transfer(&self, input: &AwsCredentials) -> Result<String> {
        let creds = self.aws_creds(input).await?;
        let now = Utc::now().date_naive();
        let start = now - chrono::Duration::days(30);
        let entries = ce::get_data_transfer_breakdown(&self.http, &creds, start, now).await?;
        let total: f64 = entries.iter().map(|e| e.amount_usd).sum();
        let output = serde_json::json!({
            "period": { "start": start.to_string(), "end": now.to_string() },
            "total_usd": round2(total),
            "by_usage_type": entries.iter().map(|e| serde_json::json!({
                "usage_type": e.usage_type,
                "description": e.description,
                "amount_usd": round2(e.amount_usd),
            })).collect::<Vec<_>>(),
        });
        Ok(serde_json::to_string_pretty(&output)?)
    }

    async fn do_compare_costs(&self, input: &AwsCredentials) -> Result<String> {
        let creds = self.aws_creds(input).await?;
        let comparison = ce::compare_costs(&self.http, &creds).await?;
        Ok(serde_json::to_string_pretty(&comparison)?)
    }

    async fn fetch_aws_costs(
        &self,
        input: &AwsCredentials,
        start_date: &str,
        end_date: &str,
    ) -> Result<String> {
        let creds = self.aws_creds(input).await?;

        let start = NaiveDate::parse_from_str(start_date, "%Y-%m-%d")
            .map_err(|_| anyhow::anyhow!("Invalid start_date, expected YYYY-MM-DD"))?;
        let end = NaiveDate::parse_from_str(end_date, "%Y-%m-%d")
            .map_err(|_| anyhow::anyhow!("Invalid end_date, expected YYYY-MM-DD"))?;

        let costs: Vec<CostEntry> = ce::get_costs(&self.http, &creds, start, end).await?;
        let total: f64 = costs.iter().map(|c| c.amount_usd).sum();

        let output = serde_json::json!({
            "period": { "start": start_date, "end": end_date },
            "total_usd": round2(total),
            "by_service": costs.iter().map(|c| serde_json::json!({
                "service": c.service,
                "amount_usd": round2(c.amount_usd),
            })).collect::<Vec<_>>(),
        });

        Ok(serde_json::to_string_pretty(&output)?)
    }
}

// ── GCP implementation ───────────────────────────────────────────────────────

impl CloudTools {
    /// Build GcpCreds from tool input — uses ADC when service_account_json is absent.
    fn gcp_creds(
        project_id: &str,
        service_account_json: Option<&str>,
        billing_table: Option<String>,
        billing_account_id: Option<String>,
    ) -> Result<GcpCreds> {
        match service_account_json {
            Some(json) => Ok(GcpCreds {
                service_account_json: json.to_string(),
                project_id: project_id.to_string(),
                billing_account_id: billing_account_id.unwrap_or_default(),
                billing_table,
                organization_id: None,
            }),
            None => {
                let mut creds = GcpCreds::from_adc(project_id)?;
                creds.billing_table = billing_table;
                creds.billing_account_id = billing_account_id.unwrap_or_default();
                Ok(creds)
            }
        }
    }

    async fn fetch_gcp_inventory(&self, input: &GcpCredentials) -> Result<String> {
        let mut projects_data = Vec::new();

        for project_id in &input.project_ids {
            let creds = Self::gcp_creds(
                project_id,
                input.service_account_json.as_deref(),
                None,
                None,
            )?;
            let token = crate::clouds::gcp::auth::access_token(&self.http, &creds).await?;

            // Fetch all resource types in parallel — split into nested joins
            // to stay within Rust's tuple size limits.
            let (
                (
                    instances_res,
                    disks_res,
                    addresses_res,
                    snapshots_res,
                    fwd_rules_res,
                    clusters_res,
                ),
                (sql_res, functions_res, run_res, buckets_res, nat_res, ids_res),
                (artifact_res, vpn_res, subnets_res, psc_res, logging_bytes_res),
            ) = tokio::join!(
                async {
                    tokio::join!(
                        compute::list_resources(&self.http, &creds),
                        compute::list_disks(&self.http, &token, project_id),
                        compute::list_addresses(&self.http, &token, project_id),
                        compute::list_snapshots(&self.http, &token, project_id),
                        compute::list_forwarding_rules(&self.http, &token, project_id),
                        gke::list_clusters(&self.http, &creds),
                    )
                },
                async {
                    tokio::join!(
                        cloud_sql::list_instances(&self.http, &creds),
                        cloud_functions::list_functions(&self.http, &creds),
                        cloud_run::list_services(&self.http, &creds),
                        storage::list_buckets(&self.http, &creds),
                        cloud_nat::list_cloud_nats(&self.http, &creds),
                        cloud_ids::list_ids_endpoints(&self.http, &creds),
                    )
                },
                async {
                    tokio::join!(
                        artifact_registry::list_artifact_repos(&self.http, &creds),
                        cloud_vpn::list_vpn_gateways(&self.http, &creds),
                        networking::list_subnetworks(&self.http, &creds),
                        networking::list_psc_endpoints(&self.http, &token, project_id),
                        monitoring::logging_bytes_ingested(&self.http, &creds, 30),
                    )
                },
            );

            let instances: Vec<_> = instances_res
                .unwrap_or_default()
                .into_iter()
                .filter(|r| r.resource_type == "gce_instance")
                .map(|r| {
                    let status = r.raw["status"].as_str().unwrap_or("UNKNOWN");
                    let machine_type = r.raw["machineType"]
                        .as_str()
                        .and_then(|t| t.rsplit('/').next())
                        .unwrap_or("unknown");
                    let zone = r.raw["zone"]
                        .as_str()
                        .and_then(|z| z.rsplit('/').next())
                        .unwrap_or("");
                    serde_json::json!({
                        "name": r.name,
                        "id": r.resource_id,
                        "status": status,
                        "machine_type": machine_type,
                        "zone": zone,
                        "region": r.region,
                    })
                })
                .collect();

            let disks: Vec<_> = disks_res
                .unwrap_or_default()
                .into_iter()
                .map(|d| {
                    serde_json::json!({
                        "name": d.name,
                        "size_gb": d.size_gb,
                        "type": d.disk_type,
                        "status": d.status,
                        "zone": d.zone,
                        "attached": d.attached,
                    })
                })
                .collect();

            let addresses: Vec<_> = addresses_res
                .unwrap_or_default()
                .into_iter()
                .map(|a| {
                    serde_json::json!({
                        "name": a.name,
                        "address": a.address,
                        "status": a.status,
                        "region": a.region,
                        "type": a.address_type,
                    })
                })
                .collect();

            let snapshots: Vec<_> = snapshots_res
                .unwrap_or_default()
                .into_iter()
                .map(|s| {
                    serde_json::json!({
                        "name": s.name,
                        "disk_size_gb": s.disk_size_gb,
                        "storage_bytes": s.storage_bytes,
                        "status": s.status,
                        "created": s.creation_timestamp,
                        "source_disk": s.source_disk,
                    })
                })
                .collect();

            let forwarding_rules: Vec<_> = fwd_rules_res
                .unwrap_or_default()
                .into_iter()
                .map(|fr| {
                    serde_json::json!({
                        "name": fr.name,
                        "region": fr.region,
                        "ip_address": fr.ip_address,
                        "target": fr.target,
                        "load_balancing_scheme": fr.load_balancing_scheme,
                    })
                })
                .collect();

            // GKE clusters with pricing
            let gke_clusters_raw = clusters_res.unwrap_or_default();
            let total_gke_clusters = gke_clusters_raw.len();
            let total_gke_nodes: u32 = gke_clusters_raw.iter().map(|c| c.node_count).sum();
            let clusters: Vec<_> = gke_clusters_raw
                .into_iter()
                .map(|c| {
                    let pools: Vec<_> = c.node_pools.iter().map(|np| {
                        let per_node = gke_node_monthly_estimate(&np.machine_type);
                        serde_json::json!({
                            "name": np.name,
                            "machine_type": np.machine_type,
                            "node_count": np.node_count,
                            "autoscaling": np.autoscaling_enabled,
                            "min_nodes": np.min_node_count,
                            "max_nodes": np.max_node_count,
                            "estimated_monthly_usd_per_node": round2(per_node),
                            "estimated_monthly_usd_total": round2(per_node * np.node_count as f64),
                        })
                    }).collect();
                    serde_json::json!({
                        "name": c.name,
                        "location": c.location,
                        "status": c.status,
                        "total_nodes": c.node_count,
                        "management_fee_monthly_usd": 74.0,
                        "node_pools": pools,
                    })
                })
                .collect();

            let sql_instances: Vec<_> = sql_res
                .unwrap_or_default()
                .into_iter()
                .map(|s| {
                    serde_json::json!({
                        "name": s.name,
                        "database_version": s.database_version,
                        "tier": s.tier,
                        "state": s.state,
                        "region": s.region,
                        "disk_size_gb": s.data_disk_size_gb,
                        "disk_type": s.data_disk_type,
                    })
                })
                .collect();

            let functions: Vec<_> = functions_res
                .unwrap_or_default()
                .into_iter()
                .map(|f| {
                    serde_json::json!({
                        "name": f.name,
                        "runtime": f.runtime,
                        "state": f.state,
                        "region": f.region,
                        "memory_mb": f.memory_mb,
                    })
                })
                .collect();

            let run_services: Vec<_> = run_res
                .unwrap_or_default()
                .into_iter()
                .map(|r| {
                    serde_json::json!({
                        "name": r.name,
                        "region": r.region,
                        "uri": r.uri,
                        "latest_revision": r.latest_ready_revision,
                    })
                })
                .collect();

            let buckets: Vec<_> = buckets_res
                .unwrap_or_default()
                .into_iter()
                .map(|b| {
                    serde_json::json!({
                        "name": b.name,
                        "location": b.location,
                        "storage_class": b.storage_class,
                        "has_lifecycle_rules": b.has_lifecycle_rules,
                        "versioning": b.versioning_enabled,
                    })
                })
                .collect();

            // New resource types
            let cloud_nat: Vec<_> = nat_res
                .unwrap_or_default()
                .into_iter()
                .map(|n| {
                    serde_json::json!({
                        "name": n.name,
                        "router_name": n.router_name,
                        "region": n.region,
                        "source_ranges": n.source_ranges,
                        "nat_ips": n.nat_ips,
                    })
                })
                .collect();

            let cloud_ids: Vec<_> = ids_res
                .unwrap_or_default()
                .into_iter()
                .map(|e| {
                    serde_json::json!({
                        "name": e.name,
                        "network": e.network,
                        "severity": e.severity,
                        "state": e.state,
                        "region": e.region,
                    })
                })
                .collect();

            let artifact_registry: Vec<_> = artifact_res
                .unwrap_or_default()
                .into_iter()
                .map(|r| {
                    let estimated_usd = r.size_bytes as f64 / 1e9 * 0.10;
                    serde_json::json!({
                        "name": r.name,
                        "format": r.format,
                        "location": r.location,
                        "size_bytes": r.size_bytes,
                        "cleanup_policy_count": r.cleanup_policy_count,
                        "estimated_monthly_usd": round2(estimated_usd),
                    })
                })
                .collect();

            let vpn_gateways: Vec<_> = vpn_res
                .unwrap_or_default()
                .into_iter()
                .map(|v| {
                    let tunnels: Vec<_> = v
                        .tunnels
                        .iter()
                        .map(|t| {
                            serde_json::json!({
                                "name": t.name,
                                "status": t.status,
                                "peer_ip": t.peer_ip,
                                "ike_version": t.ike_version,
                            })
                        })
                        .collect();
                    serde_json::json!({
                        "gateway_name": v.gateway_name,
                        "region": v.region,
                        "tunnel_count": v.tunnel_count,
                        "tunnels": tunnels,
                    })
                })
                .collect();

            let subnetworks: Vec<_> = subnets_res
                .unwrap_or_default()
                .into_iter()
                .filter(|s| s.flow_logs_enabled)
                .map(|s| {
                    serde_json::json!({
                        "name": s.name,
                        "region": s.region,
                        "ip_cidr_range": s.ip_cidr_range,
                        "flow_logs_enabled": s.flow_logs_enabled,
                        "flow_sampling": s.flow_sampling,
                        "purpose": s.purpose,
                    })
                })
                .collect();

            let psc_endpoints: Vec<_> = psc_res
                .unwrap_or_default()
                .into_iter()
                .map(|p| {
                    serde_json::json!({
                        "name": p.name,
                        "region": p.region,
                        "address": p.address,
                        "target": p.target,
                        "status": p.status,
                    })
                })
                .collect();

            // Logging cost estimation
            let logging_bytes = logging_bytes_res.unwrap_or(0);
            let logging_estimated_monthly_usd =
                round2(logging_bytes as f64 / 1_073_741_824.0 * 0.50);

            let summary = serde_json::json!({
                "total_gke_clusters": total_gke_clusters,
                "total_gke_nodes": total_gke_nodes,
                "total_disks": disks.len(),
                "total_buckets": buckets.len(),
                "logging_bytes_30d": logging_bytes,
                "logging_estimated_monthly_usd": logging_estimated_monthly_usd,
            });

            projects_data.push(serde_json::json!({
                "project_id": project_id,
                "instances": instances,
                "disks": disks,
                "addresses": addresses,
                "snapshots": snapshots,
                "forwarding_rules": forwarding_rules,
                "gke_clusters": clusters,
                "cloud_sql": sql_instances,
                "cloud_functions": functions,
                "cloud_run": run_services,
                "buckets": buckets,
                "cloud_nat": cloud_nat,
                "cloud_ids": cloud_ids,
                "artifact_registry": artifact_registry,
                "vpn_gateways": vpn_gateways,
                "subnetworks": subnetworks,
                "psc_endpoints": psc_endpoints,
                "logging_bytes_30d": logging_bytes,
                "logging_estimated_monthly_usd": logging_estimated_monthly_usd,
                "summary": summary,
            }));
        }

        Ok(serde_json::to_string_pretty(&projects_data)?)
    }

    async fn do_find_gcp_waste(&self, input: &GcpCredentials) -> Result<String> {
        let mut all_findings = Vec::new();

        for project_id in &input.project_ids {
            let creds = Self::gcp_creds(
                project_id,
                input.service_account_json.as_deref(),
                None,
                None,
            )?;
            match gcp_waste::analyse(&self.http, &creds).await {
                Ok(mut findings) => {
                    for f in &mut findings {
                        f.account_id = Some(project_id.clone());
                    }
                    all_findings.extend(findings);
                }
                Err(e) => {
                    all_findings.push(crate::analyzers::WasteItem {
                        resource_id: project_id.clone(),
                        resource_type: "project".into(),
                        region: String::new(),
                        issue: crate::analyzers::WasteKind::GcpRecommenderFinding,
                        detail: format!("Failed to scan project {project_id}: {e}"),
                        estimated_monthly_usd: 0.0,
                        action: "Check service account permissions for this project".into(),
                        account_id: Some(project_id.clone()),
                        account_name: None,
                    });
                }
            }
        }

        all_findings.sort_by(|a, b| {
            b.estimated_monthly_usd
                .partial_cmp(&a.estimated_monthly_usd)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let total_waste: f64 = all_findings.iter().map(|f| f.estimated_monthly_usd).sum();
        let output = serde_json::json!({
            "projects_scanned": input.project_ids,
            "total_estimated_monthly_waste_usd": round2(total_waste),
            "finding_count": all_findings.len(),
            "findings": all_findings,
        });
        Ok(serde_json::to_string_pretty(&output)?)
    }

    async fn fetch_gcp_recommendations(&self, input: &GcpCredentials) -> Result<String> {
        let mut all_recs = Vec::new();

        for project_id in &input.project_ids {
            let creds = Self::gcp_creds(
                project_id,
                input.service_account_json.as_deref(),
                None,
                None,
            )?;
            match recommender::get_recommendations(&self.http, &creds).await {
                Ok(recs) => {
                    for rec in recs {
                        all_recs.push(serde_json::json!({
                            "project_id": project_id,
                            "recommender_type": rec.recommender_type,
                            "subtype": rec.subtype,
                            "resource_name": rec.resource_name,
                            "description": rec.description,
                            "estimated_monthly_savings_usd": round2(rec.estimated_monthly_savings_usd),
                            "location": rec.location,
                        }));
                    }
                }
                Err(e) => {
                    all_recs.push(serde_json::json!({
                        "project_id": project_id,
                        "error": format!("Failed to fetch recommendations: {e}"),
                    }));
                }
            }
        }

        let total_savings: f64 = all_recs
            .iter()
            .filter_map(|r| r["estimated_monthly_savings_usd"].as_f64())
            .sum();

        let output = serde_json::json!({
            "projects_scanned": input.project_ids,
            "total_potential_monthly_savings_usd": round2(total_savings),
            "recommendation_count": all_recs.iter().filter(|r| r.get("error").is_none()).count(),
            "recommendations": all_recs,
        });
        Ok(serde_json::to_string_pretty(&output)?)
    }
}

// ── OVH implementation ──────────────────────────────────────────────────────

impl CloudTools {
    fn ovh_creds(input: &OvhCredentials) -> OvhCreds {
        OvhCreds {
            app_key: input.app_key.clone(),
            app_secret: input.app_secret.clone(),
            consumer_key: input.consumer_key.clone(),
            endpoint: input.endpoint.clone().unwrap_or_else(|| "ovh-eu".into()),
        }
    }

    async fn fetch_ovh_costs(&self, input: &OvhCredentials) -> Result<String> {
        let creds = Self::ovh_creds(input);
        let costs = ovh_billing::get_costs(&self.http, &creds).await?;
        let total: f64 = costs.iter().map(|c| c.amount_usd).sum();
        let output = serde_json::json!({
            "provider": "ovh",
            "total_usd": round2(total),
            "bills": costs.iter().map(|c| serde_json::json!({
                "service": c.service,
                "amount_usd": round2(c.amount_usd),
                "date": c.period_start.to_string(),
            })).collect::<Vec<_>>(),
        });
        Ok(serde_json::to_string_pretty(&output)?)
    }

    async fn fetch_ovh_inventory(&self, input: &OvhCredentials) -> Result<String> {
        let creds = Self::ovh_creds(input);
        let (instances_res, services_res) = tokio::join!(
            ovh_instances::list_resources(&self.http, &creds),
            ovh_services::list_services(&self.http, &creds),
        );

        let instances: Vec<_> = instances_res
            .unwrap_or_default()
            .into_iter()
            .map(|r| {
                serde_json::json!({
                    "name": r.name,
                    "id": r.resource_id,
                    "type": r.resource_type,
                    "region": r.region,
                    "status": if r.last_active_at.is_some() { "ACTIVE" } else { "INACTIVE" },
                })
            })
            .collect();

        let services: Vec<_> = services_res
            .unwrap_or_default()
            .into_iter()
            .map(|s| {
                serde_json::json!({
                    "service_id": s.service_id,
                    "type": s.service_type,
                    "name": s.display_name,
                    "status": s.status,
                    "expiration": s.expiration_date,
                    "renew": s.renew_type,
                    "monthly_cost": s.monthly_cost,
                })
            })
            .collect();

        let output = serde_json::json!({
            "provider": "ovh",
            "instances": instances,
            "services": services,
        });
        Ok(serde_json::to_string_pretty(&output)?)
    }
}

// ── Cloudflare implementation ───────────────────────────────────────────────

impl CloudTools {
    fn cf_creds(input: &CloudflareCredentials) -> CloudflareCreds {
        CloudflareCreds {
            api_token: input.api_token.clone(),
            account_id: input.account_id.clone(),
        }
    }

    async fn fetch_cf_costs(&self, input: &CloudflareCredentials) -> Result<String> {
        let creds = Self::cf_creds(input);
        let (costs_res, zones_res) = tokio::join!(
            cf_billing::get_costs(&self.http, &creds),
            cf_zones::list_zones(&self.http, &creds),
        );
        let costs = costs_res.unwrap_or_default();
        let zones = zones_res.unwrap_or_default();
        let sub_total: f64 = costs.iter().map(|c| c.amount_usd).sum();
        let zone_total: f64 = zones.iter().map(|z| z.plan_price).sum();

        let output = serde_json::json!({
            "provider": "cloudflare",
            "subscription_total_usd": round2(sub_total),
            "zone_plan_total_usd": round2(zone_total),
            "total_usd": round2(sub_total + zone_total),
            "subscriptions": costs.iter().map(|c| serde_json::json!({
                "service": c.service,
                "amount_usd": round2(c.amount_usd),
            })).collect::<Vec<_>>(),
            "zone_plans": zones.iter().filter(|z| z.plan_price > 0.0).map(|z| serde_json::json!({
                "zone": z.name,
                "plan": z.plan_name,
                "monthly_usd": z.plan_price,
            })).collect::<Vec<_>>(),
        });
        Ok(serde_json::to_string_pretty(&output)?)
    }

    async fn fetch_cf_inventory(&self, input: &CloudflareCredentials) -> Result<String> {
        let creds = Self::cf_creds(input);
        let (zones_res, dns_res, certs_res, workers_res) = tokio::join!(
            cf_zones::list_zones(&self.http, &creds),
            cf_dns::list_dns_records(&self.http, &creds),
            cf_certs::list_certificates(&self.http, &creds),
            cf_workers::list_resources(&self.http, &creds),
        );

        let zones: Vec<_> = zones_res
            .unwrap_or_default()
            .into_iter()
            .map(|z| {
                serde_json::json!({
                    "name": z.name,
                    "status": z.status,
                    "plan": z.plan_name,
                    "plan_price_usd": z.plan_price,
                    "paused": z.paused,
                })
            })
            .collect();

        let dns: Vec<_> = dns_res
            .unwrap_or_default()
            .into_iter()
            .map(|d| {
                serde_json::json!({
                    "zone": d.zone_name,
                    "total_records": d.total_records,
                    "proxied": d.proxied_count,
                    "dns_only": d.dns_only_count,
                })
            })
            .collect();

        let certs: Vec<_> = certs_res
            .unwrap_or_default()
            .into_iter()
            .map(|c| {
                serde_json::json!({
                    "zone": c.zone_name,
                    "type": c.cert_type,
                    "status": c.status,
                    "hosts": c.hosts,
                    "expires": c.expires_on,
                })
            })
            .collect();

        let workers: Vec<_> = workers_res
            .unwrap_or_default()
            .into_iter()
            .filter(|w| w.resource_type == "cf_worker")
            .map(|w| {
                let requests = w.raw["sum"]["requests"].as_i64().unwrap_or(0);
                serde_json::json!({
                    "name": w.name,
                    "requests_30d": requests,
                    "active": w.last_active_at.is_some(),
                })
            })
            .collect();

        let output = serde_json::json!({
            "provider": "cloudflare",
            "zones": zones,
            "dns": dns,
            "certificates": certs,
            "workers": workers,
        });
        Ok(serde_json::to_string_pretty(&output)?)
    }
}

// ── Cross-cloud summary implementation ──────────────────────────────────────

impl CloudTools {
    async fn fetch_cross_cloud_summary(&self, input: &Credentials) -> Result<String> {
        let mut providers = Vec::new();

        // ── AWS ──
        //
        // AWS was absent from this report entirely, because it is the one cloud
        // that may need a role assumed and the old input carried no AWS fields at
        // all. A "cross-cloud" total that silently omits the largest bill is
        // worse than no total.
        if let Some(ref aws) = input.aws {
            let entry = match self.aws_creds(aws).await {
                Ok(creds) => match crate::analyzers::waste::analyse(&self.http, &creds).await {
                    Ok(findings) => {
                        let total: f64 = findings.iter().map(|f| f.estimated_monthly_usd).sum();
                        serde_json::json!({
                            "provider": "aws",
                            "waste_total_monthly_usd": round2(total),
                            "finding_count": findings.len(),
                        })
                    }
                    Err(e) => serde_json::json!({ "provider": "aws", "error": e.to_string() }),
                },
                Err(e) => serde_json::json!({ "provider": "aws", "error": e.to_string() }),
            };
            providers.push(entry);
        }

        // ── GCP ──
        if let Some(ref gcp) = input.gcp {
            let project_ids = &gcp.project_ids;
            if !project_ids.is_empty() {
                let waste_json = self
                    .do_find_gcp_waste(gcp)
                    .await
                    .unwrap_or_else(|e| serde_json::json!({ "error": e.to_string() }).to_string());
                let waste: serde_json::Value =
                    serde_json::from_str(&waste_json).unwrap_or_default();

                // Summarize waste findings by project
                let waste_total = waste["total_estimated_monthly_waste_usd"]
                    .as_f64()
                    .unwrap_or(0.0);
                let finding_count = waste["finding_count"].as_u64().unwrap_or(0);
                let mut by_project: std::collections::HashMap<String, f64> =
                    std::collections::HashMap::new();
                if let Some(findings) = waste["findings"].as_array() {
                    for f in findings {
                        let pid = f["account_id"].as_str().unwrap_or("unknown").to_string();
                        let cost = f["estimated_monthly_usd"].as_f64().unwrap_or(0.0);
                        *by_project.entry(pid).or_default() += cost;
                    }
                }

                let project_summaries: Vec<_> = project_ids
                    .iter()
                    .map(|pid| {
                        let waste_usd = by_project.get(pid.as_str()).copied().unwrap_or(0.0);
                        serde_json::json!({
                            "project_id": pid,
                            "waste_monthly_usd": round2(waste_usd),
                        })
                    })
                    .collect();

                providers.push(serde_json::json!({
                    "provider": "gcp",
                    "waste_total_monthly_usd": round2(waste_total),
                    "finding_count": finding_count,
                    "projects": project_summaries,
                }));
            }
        }

        // ── OVH ──
        if let Some(ref ovh) = input.ovh {
            let creds = Self::ovh_creds(ovh);
            let costs = ovh_billing::get_costs(&self.http, &creds)
                .await
                .unwrap_or_default();
            let services = ovh_services::list_services(&self.http, &creds)
                .await
                .unwrap_or_default();
            let total: f64 = costs.iter().map(|c| c.amount_usd).sum();
            let active = services.iter().filter(|s| s.status == "active").count();

            providers.push(serde_json::json!({
                "provider": "ovh",
                "total_billed_usd": round2(total),
                "active_services": active,
                "total_services": services.len(),
            }));
        }

        // ── Cloudflare ──
        if let Some(ref cf) = input.cloudflare {
            let creds = Self::cf_creds(cf);
            let (costs_res, zones_res) = tokio::join!(
                cf_billing::get_costs(&self.http, &creds),
                cf_zones::list_zones(&self.http, &creds),
            );
            let costs = costs_res.unwrap_or_default();
            let zones = zones_res.unwrap_or_default();
            let sub_total: f64 = costs.iter().map(|c| c.amount_usd).sum();
            let zone_total: f64 = zones.iter().map(|z| z.plan_price).sum();

            providers.push(serde_json::json!({
                "provider": "cloudflare",
                "subscription_total_usd": round2(sub_total),
                "zone_plan_total_usd": round2(zone_total),
                "total_usd": round2(sub_total + zone_total),
                "zones": zones.len(),
            }));
        }

        // ── Grand total ──
        let grand_total: f64 = providers
            .iter()
            .filter_map(|p| {
                p.get("waste_total_monthly_usd")
                    .or(p.get("total_billed_usd"))
                    .or(p.get("total_usd"))
                    .and_then(|v| v.as_f64())
            })
            .sum();

        let output = serde_json::json!({
            "summary": {
                "grand_total_estimated_monthly_usd": round2(grand_total),
                "providers_included": providers.iter()
                    .filter_map(|p| p["provider"].as_str().map(String::from))
                    .collect::<Vec<_>>(),
            },
            "providers": providers,
        });
        Ok(serde_json::to_string_pretty(&output)?)
    }
}

#[tool_handler]
impl ServerHandler for CloudTools {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            // Without this, rmcp answers the handshake with its own crate name
            // and version, so every client, the Smithery tool card and the
            // .mcpb bundle all report the server as "rmcp 1.1.1". The name is
            // written out rather than taken from `Implementation::from_build_env`,
            // which reads CARGO_CRATE_NAME and would say "cloud_tools".
            .with_server_info(
                Implementation::new("cloud-tools", env!("CARGO_PKG_VERSION"))
                    .with_title("cloud-tools")
                    .with_website_url("https://github.com/munhq/cloud-tools"),
            )
            .with_instructions(
                "Multi-cloud cost, inventory, and waste analysis for AWS, GCP, OVH, and Cloudflare. \
                 AWS: pass an IAM Role ARN per call. \
                 GCP: uses Application Default Credentials by default, or pass service_account_json. \
                 OVH: pass app_key, app_secret, consumer_key per call. \
                 Cloudflare: pass api_token and account_id per call. \
                 Cross-cloud summary: pass credentials for each provider you want included.",
            )
    }
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

fn gke_node_monthly_estimate(machine_type: &str) -> f64 {
    match machine_type {
        "f1-micro" => 3.88,
        "g1-small" => 13.80,
        "e2-micro" => 6.11,
        "e2-small" => 12.23,
        "e2-medium" => 24.46,
        "e2-standard-2" => 48.92,
        "e2-standard-4" => 97.83,
        "e2-standard-8" => 195.67,
        "e2-highcpu-2" => 43.46,
        "e2-highcpu-4" => 86.93,
        "e2-highcpu-8" => 173.85,
        "e2-highmem-2" => 54.63,
        "e2-highmem-4" => 109.25,
        "e2-highmem-8" => 218.51,
        "n1-standard-1" => 24.27,
        "n1-standard-2" => 48.55,
        "n1-standard-4" => 97.09,
        "n2-standard-2" => 48.92,
        "n2-standard-4" => 97.83,
        "n2d-standard-2" => 42.56,
        "c2-standard-4" => 124.62,
        "c3-standard-4" => 130.90,
        _ => 50.0,
    }
}
