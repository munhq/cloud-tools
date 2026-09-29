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

// ── Selectors in the schema, secrets in the environment ──────────────────────
//
// Every tool used to take a `credentials` object carrying all four clouds'
// secrets. That was wrong three times over.
//
// It asked the AGENT to hold the secrets, which means something has to put them
// into the agent's context first — where they land in transcripts and logs.
//
// It cost every user tokens forever. The credential definitions came to ~2,530
// bytes, repeated in all seven tool schemas: ~17.7 KB of a 21 KB total, about
// 6,250 tokens present in every conversation before a single call.
//
// And it ignored the setup people already have. A developer has
// ~/.aws/credentials and has run `gcloud auth application-default login`. The
// agent cannot know that, so it passed nothing, and a tool that would have
// worked returned an error about a missing credentials block.
//
// So: secrets come from the server's environment, the way AWS and GCP already
// resolved theirs. What stays in the schema is the SELECTOR — which account,
// which projects — because that is not a secret and an agent legitimately needs
// to choose it.

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

/// One environment variable, or nothing.
fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

// The selector a caller may pass. Never a secret.
//
// Every field is optional, and each is only needed to look at something other
// than the server's default: another AWS account, or particular GCP projects.
//
// The descriptions here are deliberately terse. This struct is inlined into all
// seven tool schemas, so every word costs seven times over in the context of
// every conversation that loads this server. The long version belongs in the
// README, which is read once.
#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
pub struct Target {
    /// AWS role to assume, to scan another account.
    pub role_arn: Option<String>,
    /// External ID, if that role's trust policy needs one.
    pub external_id: Option<String>,
    /// GCP projects to query. Defaults to the server's configuration.
    pub project_ids: Option<Vec<String>>,
}

/// AWS: the role to assume, if any. The credentials themselves come from the
/// server's chain — env vars, ~/.aws/credentials, an ECS task role, an EC2
/// instance role.
pub struct AwsTarget {
    pub role_arn: Option<String>,
    pub external_id: Option<String>,
}

/// GCP: which projects. Credentials come from Application Default Credentials
/// or GOOGLE_APPLICATION_CREDENTIALS, both resolved in `clouds::gcp::auth`.
pub struct GcpTarget {
    pub project_ids: Vec<String>,
    pub billing_table: Option<String>,
}

/// Cloudflare and OVH have no ambient credential mechanism of their own, so the
/// server reads named variables. The names match each vendor's own convention,
/// so anyone who already exports them for the vendor's CLI needs to do nothing.
pub struct CloudflareTarget {
    pub api_token: String,
    pub account_id: String,
}

pub struct OvhTarget {
    pub app_key: String,
    pub app_secret: String,
    pub consumer_key: String,
    pub endpoint: String,
}

impl Target {
    fn aws(&self) -> AwsTarget {
        AwsTarget {
            role_arn: self
                .role_arn
                .clone()
                .or_else(|| env("CLOUD_TOOLS_AWS_ROLE_ARN")),
            external_id: self
                .external_id
                .clone()
                .or_else(|| env("CLOUD_TOOLS_AWS_EXTERNAL_ID")),
        }
    }

    fn gcp(&self) -> Result<GcpTarget> {
        let project_ids = match &self.project_ids {
            Some(p) if !p.is_empty() => p.clone(),
            _ => env("CLOUD_TOOLS_GCP_PROJECTS")
                .map(|v| {
                    v.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                })
                .filter(|v: &Vec<String>| !v.is_empty())
                .context(
                    "No GCP project to query. Pass project_ids, or set CLOUD_TOOLS_GCP_PROJECTS \
                     on the server to a comma-separated list.",
                )?,
        };
        Ok(GcpTarget {
            project_ids,
            billing_table: env("CLOUD_TOOLS_GCP_BILLING_TABLE"),
        })
    }

    fn cloudflare(&self) -> Result<CloudflareTarget> {
        Ok(CloudflareTarget {
            api_token: env("CLOUDFLARE_API_TOKEN")
                .context("CLOUDFLARE_API_TOKEN is not set on the server.")?,
            account_id: env("CLOUDFLARE_ACCOUNT_ID")
                .context("CLOUDFLARE_ACCOUNT_ID is not set on the server.")?,
        })
    }

    fn ovh(&self) -> Result<OvhTarget> {
        Ok(OvhTarget {
            app_key: env("OVH_APPLICATION_KEY")
                .context("OVH_APPLICATION_KEY is not set on the server.")?,
            app_secret: env("OVH_APPLICATION_SECRET")
                .context("OVH_APPLICATION_SECRET is not set on the server.")?,
            consumer_key: env("OVH_CONSUMER_KEY")
                .context("OVH_CONSUMER_KEY is not set on the server.")?,
            endpoint: env("OVH_ENDPOINT").unwrap_or_else(|| "ovh-eu".to_string()),
        })
    }
}

// ── Tool inputs ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CostsInput {
    #[schemars(description = "Which cloud to query: aws, gcp, cloudflare or ovh")]
    pub cloud: Cloud,
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
                       \"data_transfer\" breaks it down by transfer usage type instead."
    )]
    pub group_by: Option<String>,
    #[serde(default)]
    pub target: Target,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CloudInput {
    #[schemars(description = "Which cloud to query: aws, gcp, cloudflare or ovh")]
    pub cloud: Cloud,
    #[serde(default)]
    pub target: Target,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SummaryInput {
    #[serde(default)]
    pub target: Target,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct NoInput {}

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
        description = "Which clouds this server can reach, and what is missing for the ones it cannot. Call this first: it is cheap, needs no arguments, and turns a guess about credentials into a fact. It reports configuration only and contacts no cloud.",
        annotations(
            title = "Check cloud access",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn check_access(&self, Parameters(_): Parameters<NoInput>) -> String {
        answer(self.access())
    }

    #[tool(
        description = "Cloud spend. AWS: by service over a date range, from Cost Explorer; pass group_by=\"data_transfer\" for transfer cost by usage type. GCP: by service from the BigQuery billing export, which CLOUD_TOOLS_GCP_BILLING_TABLE on the server must name — without it you get budget amounts, not spend. Cloudflare: subscriptions and zone plan costs. OVH: the 6 most recent invoices.",
        annotations(
            title = "Cloud spend",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn get_costs(&self, Parameters(input): Parameters<CostsInput>) -> String {
        answer(self.costs(input).await)
    }

    #[tool(
        description = "This period against the same day window of the previous month, so a partial month does not read as a fall. AWS and GCP only. GCP needs CLOUD_TOOLS_GCP_BILLING_TABLE set on the server.",
        annotations(
            title = "Spend, month over month",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn compare_costs(&self, Parameters(input): Parameters<CloudInput>) -> String {
        answer(self.compare(input).await)
    }

    #[tool(
        description = "What exists. GCP: GCE instances, disks, addresses, snapshots, forwarding rules, GKE clusters with node pools, Cloud SQL, Cloud Functions, Cloud Run, GCS buckets, Cloud NAT, Cloud IDS, Artifact Registry, VPN gateways, subnets, PSC endpoints and Cloud Logging ingestion, with a per-project summary. Cloudflare: zones with plan and price, DNS records split proxied against dns-only, certificates with hosts and expiry, and Workers with invocation counts. OVH: instances and active services with renewal dates and monthly cost. Not implemented for AWS.",
        annotations(
            title = "Cloud inventory",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn get_inventory(&self, Parameters(input): Parameters<CloudInput>) -> String {
        answer(self.inventory(input).await)
    }

    #[tool(
        description = "What is wasted, with the monthly cost of each finding and the utilisation evidence behind it. AWS: idle and oversized EC2 and RDS measured from CloudWatch CPU series, stopped instances, orphaned volumes and snapshots, unused AMIs and Elastic IPs, idle load balancers and NAT gateways, DynamoDB and ElastiCache, and log groups with no retention. GCP: idle and oversized instances, orphaned disks, unattached addresses, snapshots over 90 days, idle Cloud SQL, GKE clusters with no nodes, Cloud Functions and Cloud Run with no invocations, buckets with no lifecycle rule. Not implemented for Cloudflare or OVH.",
        annotations(
            title = "Wasted spend",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn get_waste(&self, Parameters(input): Parameters<CloudInput>) -> String {
        answer(self.waste(input).await)
    }

    #[tool(
        description = "Commitments you are paying for, and whether you are consuming them, over the last 30 days. AWS: Savings Plans utilisation, coverage of eligible spend, and the saving a further commitment would give. GCP: committed use discounts with their expiry. Not implemented for Cloudflare or OVH, which sell no commitments.",
        annotations(
            title = "Commitment utilisation",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn get_commitments(&self, Parameters(input): Parameters<CloudInput>) -> String {
        answer(self.commitments(input).await)
    }

    #[tool(
        description = "The cloud provider's own optimisation suggestions. GCP: the Recommender API across every zone and region — idle VMs, machine type rightsizing, idle disks and addresses, idle and oversized Cloud SQL. Not implemented for the others; AWS Compute Optimizer is read as part of get_waste instead.",
        annotations(
            title = "Provider recommendations",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn get_recommendations(&self, Parameters(input): Parameters<CloudInput>) -> String {
        answer(self.recommendations(input).await)
    }

    #[tool(
        description = "One cost and waste report over every cloud you pass credentials for, with a grand total. Omit a cloud's credentials to skip it.",
        annotations(
            title = "Cross-cloud summary",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn get_cross_cloud_summary(&self, Parameters(input): Parameters<SummaryInput>) -> String {
        answer(self.summary(input).await)
    }
}

/// Take the value, or record why there is none.
///
/// The GCP inventory called sixteen APIs and ended every one with
/// `.unwrap_or_default()`. A disabled API, a missing permission, an exhausted
/// quota and a project that does not exist all became an empty list, so the
/// report was a confident row of zeros with no indication anything had failed.
/// For a cost tool that is the worst possible failure: an agent reads "no
/// resources, no waste" and tells someone their account is clean when the truth
/// is that nothing could be seen. Verified against a project that does not
/// exist — it returned a complete, error-free, all-zero inventory.
fn taken<T: Default>(what: &str, r: Result<T>, failures: &mut Vec<serde_json::Value>) -> T {
    match r {
        Ok(v) => v,
        Err(e) => {
            failures.push(serde_json::json!({ "resource": what, "error": e.to_string() }));
            T::default()
        }
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

/// A caller-supplied date pair, validated before it reaches any provider.
///
/// The strings used to travel straight to the cloud APIs, which answered an
/// inverted or equal range with their own "invalid parameter" response after
/// the request was already on its way. Naming both values here turns it into
/// a message an agent can correct.
fn checked_dates(start: &str, end: &str) -> Result<(NaiveDate, NaiveDate)> {
    let start = NaiveDate::parse_from_str(start, "%Y-%m-%d")
        .map_err(|_| anyhow::anyhow!("Invalid start_date, expected YYYY-MM-DD"))?;
    let end = NaiveDate::parse_from_str(end, "%Y-%m-%d")
        .map_err(|_| anyhow::anyhow!("Invalid end_date, expected YYYY-MM-DD"))?;
    if start >= end {
        anyhow::bail!("start_date must be before end_date (got {start} and {end})");
    }
    Ok((start, end))
}

/// Build the OVH row for the cross-cloud summary. Failed calls arrive as a
/// failure list and are attached to the row; a token that 401s must not render
/// as a clean zero bill.
fn ovh_summary_entry(
    costs: Vec<CostEntry>,
    services: Vec<ovh_services::OvhService>,
    failures: Vec<serde_json::Value>,
) -> serde_json::Value {
    let total: f64 = costs.iter().map(|c| c.amount_usd).sum();
    let active = services.iter().filter(|s| s.status == "active").count();
    let mut entry = serde_json::json!({
        "provider": "ovh",
        "total_billed_usd": round2(total),
        "active_services": active,
        "total_services": services.len(),
    });
    if !failures.is_empty() {
        entry["errors"] = serde_json::json!(failures);
    }
    entry
}

/// Build the Cloudflare row for the cross-cloud summary, same contract as
/// `ovh_summary_entry`: failures are reported, never zeroed.
fn cloudflare_summary_entry(
    costs: Vec<CostEntry>,
    zones: Vec<cf_zones::CfZone>,
    failures: Vec<serde_json::Value>,
) -> serde_json::Value {
    let sub_total: f64 = costs.iter().map(|c| c.amount_usd).sum();
    let zone_total: f64 = zones.iter().map(|z| z.plan_price).sum();
    let mut entry = serde_json::json!({
        "provider": "cloudflare",
        "subscription_total_usd": round2(sub_total),
        "zone_plan_total_usd": round2(zone_total),
        "total_usd": round2(sub_total + zone_total),
        "zones": zones.len(),
    });
    if !failures.is_empty() {
        entry["errors"] = serde_json::json!(failures);
    }
    entry
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
    async fn aws_creds(&self, c: &AwsTarget) -> Result<AwsCreds> {
        match c.role_arn.as_deref() {
            Some(arn) => assume_role(&self.http, arn, c.external_id.as_deref()).await,
            None => ambient_credentials(&self.http).await,
        }
    }

    /// GCP credentials for the first project, carrying the billing table.
    fn gcp_for(&self, c: &GcpTarget, project_id: &str) -> Result<GcpCreds> {
        Self::gcp_creds(project_id, None, c.billing_table.clone(), None)
    }

    /// What the server can reach, without contacting anything.
    ///
    /// An agent that cannot see the operator's environment otherwise has to
    /// guess, call a scan, and read a failure. This turns that into one cheap
    /// question, and it names the variable to set rather than saying "not
    /// configured".
    fn access(&self) -> Result<String> {
        let t = Target::default();
        let clouds = [
            (
                "aws",
                true,
                "the credential chain: AWS_ACCESS_KEY_ID, ~/.aws/credentials \
                 (AWS_PROFILE, else [default]), an ECS task role, or an EC2 instance role"
                    .to_string(),
            ),
            (
                "gcp",
                t.gcp().is_ok(),
                match t.gcp() {
                    Ok(g) => format!("projects: {}", g.project_ids.join(", ")),
                    Err(e) => e.to_string(),
                },
            ),
            (
                "cloudflare",
                t.cloudflare().is_ok(),
                match t.cloudflare() {
                    Ok(_) => "CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID are set".to_string(),
                    Err(e) => e.to_string(),
                },
            ),
            (
                "ovh",
                t.ovh().is_ok(),
                match t.ovh() {
                    Ok(o) => format!("configured, endpoint {}", o.endpoint),
                    Err(e) => e.to_string(),
                },
            ),
        ];

        let rows: Vec<_> = clouds
            .iter()
            .map(|(name, ok, detail)| {
                serde_json::json!({ "cloud": name, "configured": ok, "detail": detail })
            })
            .collect();

        Ok(serde_json::to_string_pretty(&serde_json::json!({
            "clouds": rows,
            // AWS reports configured because its chain always has somewhere to
            // look. Whether anything answers is only knowable by calling it, and
            // this tool deliberately calls nothing.
            "note": "Configuration only — no cloud was contacted. GCP costs additionally need \
                     CLOUD_TOOLS_GCP_BILLING_TABLE, a BigQuery billing export; without it \
                     get_costs returns budget amounts and says so.",
            "billing_table_set": env("CLOUD_TOOLS_GCP_BILLING_TABLE").is_some(),
        }))?)
    }

    async fn costs(&self, input: CostsInput) -> Result<String> {
        let t = &input.target;
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
                let aws = &t.aws();
                match input.group_by.as_deref() {
                    Some("data_transfer") => {
                        let (s, e) = checked_dates(&start, &end)?;
                        self.do_data_transfer(aws, s, e).await
                    }
                    Some("service") | None => self.fetch_aws_costs(aws, &start, &end).await,
                    Some(other) => Err(anyhow::anyhow!(
                        "group_by \"{other}\" is not known; use \"service\" or \"data_transfer\""
                    )),
                }
            }
            Cloud::Gcp => self.gcp_costs(&t.gcp()?, &start, &end).await,
            Cloud::Cloudflare => self.fetch_cf_costs(&t.cloudflare()?).await,
            Cloud::Ovh => self.fetch_ovh_costs(&t.ovh()?).await,
        }
    }

    /// GCP spend, which Google publishes nowhere except a billing export.
    ///
    /// There is no per-service spend API. With `billing_table` set this queries
    /// the BigQuery export; without it the Budgets API answers with budget
    /// amounts, which are not spend — so that case says so in the payload rather
    /// than letting a budget be read as a bill.
    /// GCP spend, across every project given.
    ///
    /// `project_ids` is a list and every other GCP arm walks all of it. This one
    /// read `.first()` and dropped the rest, so a caller asking about four
    /// projects was answered about one — silently, with a plausible number.
    async fn gcp_costs(&self, c: &GcpTarget, start: &str, end: &str) -> Result<String> {
        if c.project_ids.is_empty() {
            anyhow::bail!("credentials.gcp.project_ids is empty");
        }
        let (start_d, end_d) = checked_dates(start, end)?;

        let mut per_project = Vec::new();
        let mut grand_total = 0.0;
        for project in &c.project_ids {
            let creds = self.gcp_for(c, project)?;
            let costs = if c.billing_table.is_some() {
                gcp_billing::get_costs_range(&self.http, &creds, start_d, end_d).await
            } else {
                gcp_billing::get_costs(&self.http, &creds).await
            };
            match costs {
                Ok(costs) => {
                    let total: f64 = costs.iter().map(|c| c.amount_usd).sum();
                    grand_total += total;
                    per_project.push(serde_json::json!({
                        "project_id": project,
                        "total_usd": round2(total),
                        "by_service": costs.iter().map(|c| serde_json::json!({
                            "service": c.service,
                            "amount_usd": round2(c.amount_usd),
                        })).collect::<Vec<_>>(),
                    }));
                }
                // One project failing must not lose the others: a missing
                // permission on a single project is the common case.
                Err(e) => per_project.push(serde_json::json!({
                    "project_id": project,
                    "error": e.to_string(),
                })),
            }
        }

        Ok(serde_json::to_string_pretty(&serde_json::json!({
            "period": { "start": start, "end": end },
            "source": if c.billing_table.is_some() { "bigquery_billing_export" } else { "budgets" },
            "note": if c.billing_table.is_some() { serde_json::Value::Null } else {
                serde_json::json!("No billing_table was given, so these are BUDGET amounts from the \
                                   Budgets API, not actual spend. Set CLOUD_TOOLS_GCP_BILLING_TABLE \
                                   on the server to the BigQuery billing export table for real costs.")
            },
            "total_usd": round2(grand_total),
            "projects": per_project,
        }))?)
    }

    async fn compare(&self, input: CloudInput) -> Result<String> {
        let t = &input.target;
        match input.cloud {
            Cloud::Aws => self.do_compare_costs(&t.aws()).await,
            Cloud::Gcp => {
                let c = &t.gcp()?;
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
        let t = &input.target;
        match input.cloud {
            Cloud::Gcp => self.fetch_gcp_inventory(&t.gcp()?).await,
            Cloud::Cloudflare => self.fetch_cf_inventory(&t.cloudflare()?).await,
            Cloud::Ovh => self.fetch_ovh_inventory(&t.ovh()?).await,
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
        let t = &input.target;
        match input.cloud {
            Cloud::Aws => {
                let creds = self.aws_creds(&t.aws()).await?;
                let (findings, failures) =
                    crate::analyzers::waste::analyse_reporting(&self.http, &creds).await?;
                let total: f64 = findings.iter().map(|f| f.estimated_monthly_usd).sum();
                Ok(serde_json::to_string_pretty(&serde_json::json!({
                    "total_estimated_monthly_waste_usd": round2(total),
                    "finding_count": findings.len(),
                    "findings": findings,
                    "errors": failures,
                    "coverage": if failures.is_empty() {
                        serde_json::json!("complete")
                    } else {
                        serde_json::json!(format!(
                            "PARTIAL — {} API call(s) failed, so this is not a full picture. \
                             A zero total does not mean nothing is wasted; it means part of the \
                             account could not be read. See errors.",
                            failures.len()
                        ))
                    },
                }))?)
            }
            Cloud::Gcp => self.do_find_gcp_waste(&t.gcp()?).await,
            ref other => Err(unsupported("waste analysis", other, &["aws", "gcp"])),
        }
    }

    async fn commitments(&self, input: CloudInput) -> Result<String> {
        let t = &input.target;
        match input.cloud {
            Cloud::Aws => self.do_savings_plans(&t.aws()).await,
            Cloud::Gcp => {
                let c = &t.gcp()?;
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
        let t = &input.target;
        match input.cloud {
            Cloud::Gcp => self.fetch_gcp_recommendations(&t.gcp()?).await,
            ref other => Err(unsupported("provider recommendations", other, &["gcp"])),
        }
    }

    async fn summary(&self, input: SummaryInput) -> Result<String> {
        self.fetch_cross_cloud_summary(&input.target).await
    }

    async fn do_savings_plans(&self, input: &AwsTarget) -> Result<String> {
        let creds = self.aws_creds(input).await?;
        let now = Utc::now().date_naive();
        let start = now - chrono::Duration::days(30);
        let report = ce::get_savings_plans_report(&self.http, &creds, start, now).await?;
        Ok(serde_json::to_string_pretty(&report)?)
    }

    /// AWS transfer cost by usage type, over the window the caller asked for.
    ///
    /// This hardcoded the last 30 days while get_costs advertises start_date and
    /// end_date, so those two arguments were accepted and silently discarded for
    /// group_by="data_transfer".
    async fn do_data_transfer(
        &self,
        input: &AwsTarget,
        start: NaiveDate,
        end: NaiveDate,
    ) -> Result<String> {
        let creds = self.aws_creds(input).await?;
        let (start, now) = (start, end);
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

    async fn do_compare_costs(&self, input: &AwsTarget) -> Result<String> {
        let creds = self.aws_creds(input).await?;
        let comparison = ce::compare_costs(&self.http, &creds).await?;
        Ok(serde_json::to_string_pretty(&comparison)?)
    }

    async fn fetch_aws_costs(
        &self,
        input: &AwsTarget,
        start_date: &str,
        end_date: &str,
    ) -> Result<String> {
        let creds = self.aws_creds(input).await?;

        let (start, end) = checked_dates(start_date, end_date)?;

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

    async fn fetch_gcp_inventory(&self, input: &GcpTarget) -> Result<String> {
        let mut projects_data = Vec::new();

        for project_id in &input.project_ids {
            let mut failures: Vec<serde_json::Value> = Vec::new();
            let creds = Self::gcp_creds(project_id, None, None, None)?;
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

            let instances: Vec<_> = taken("compute.instances", instances_res, &mut failures)
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

            let disks: Vec<_> = taken("compute.disks", disks_res, &mut failures)
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

            let addresses: Vec<_> = taken("compute.addresses", addresses_res, &mut failures)
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

            let snapshots: Vec<_> = taken("compute.snapshots", snapshots_res, &mut failures)
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

            let forwarding_rules: Vec<_> =
                taken("compute.forwardingRules", fwd_rules_res, &mut failures)
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
            let gke_clusters_raw = taken("container.clusters", clusters_res, &mut failures);
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

            let sql_instances: Vec<_> = taken("sqladmin.instances", sql_res, &mut failures)
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

            let functions: Vec<_> = taken("cloudfunctions.functions", functions_res, &mut failures)
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

            let run_services: Vec<_> = taken("run.services", run_res, &mut failures)
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

            let buckets: Vec<_> = taken("storage.buckets", buckets_res, &mut failures)
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
            let cloud_nat: Vec<_> = taken("compute.routers(nat)", nat_res, &mut failures)
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

            let cloud_ids: Vec<_> = taken("ids.endpoints", ids_res, &mut failures)
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

            let artifact_registry: Vec<_> =
                taken("artifactregistry.repositories", artifact_res, &mut failures)
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

            let vpn_gateways: Vec<_> = taken("compute.vpnGateways", vpn_res, &mut failures)
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

            let subnetworks: Vec<_> = taken("compute.subnetworks", subnets_res, &mut failures)
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

            let psc_endpoints: Vec<_> = taken("compute.pscEndpoints", psc_res, &mut failures)
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
                // Present even when empty, so a reader can tell "nothing there"
                // apart from "nothing could be read". A project whose every call
                // failed says so outright rather than reporting zeros.
                "errors": failures,
                "error": if failures.len() >= 17 {
                    serde_json::json!(format!(
                        "no part of project {project_id} could be read — every API call failed. \
                         The counts below are not zero because the project is empty; they are \
                         zero because nothing was readable. Check the project exists, that the \
                         Compute, Storage and related APIs are enabled, and that the credentials \
                         have permission."
                    ))
                } else {
                    serde_json::Value::Null
                },
            }));
        }

        Ok(serde_json::to_string_pretty(&projects_data)?)
    }

    async fn do_find_gcp_waste(&self, input: &GcpTarget) -> Result<String> {
        let mut all_findings = Vec::new();
        // Which API calls could not be made. "0 findings" with an empty errors
        // list means nothing is wasted; "0 findings" with entries here means
        // nothing could be read, and the two must not look alike.
        let mut failures: Vec<serde_json::Value> = Vec::new();

        for project_id in &input.project_ids {
            let creds = Self::gcp_creds(project_id, None, None, None)?;
            match gcp_waste::analyse_reporting(&self.http, &creds).await {
                Ok((mut findings, mut project_failures)) => {
                    for f in &mut project_failures {
                        f["project_id"] = serde_json::json!(project_id);
                    }
                    failures.append(&mut project_failures);
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
            "errors": failures,
            "coverage": if failures.is_empty() {
                serde_json::json!("complete")
            } else {
                serde_json::json!(format!(
                    "PARTIAL — {} API call(s) failed, so this is not a full picture. \
                     A zero total does not mean nothing is wasted; it means part of the \
                     account could not be read. See errors.",
                    failures.len()
                ))
            },
        });
        Ok(serde_json::to_string_pretty(&output)?)
    }

    async fn fetch_gcp_recommendations(&self, input: &GcpTarget) -> Result<String> {
        let mut all_recs = Vec::new();

        for project_id in &input.project_ids {
            let creds = Self::gcp_creds(project_id, None, None, None)?;
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
    fn ovh_creds(input: &OvhTarget) -> OvhCreds {
        OvhCreds {
            app_key: input.app_key.clone(),
            app_secret: input.app_secret.clone(),
            consumer_key: input.consumer_key.clone(),
            endpoint: input.endpoint.clone(),
        }
    }

    async fn fetch_ovh_costs(&self, input: &OvhTarget) -> Result<String> {
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

    async fn fetch_ovh_inventory(&self, input: &OvhTarget) -> Result<String> {
        let creds = Self::ovh_creds(input);
        let mut failures: Vec<serde_json::Value> = Vec::new();
        let (instances_res, services_res) = tokio::join!(
            ovh_instances::list_resources(&self.http, &creds),
            ovh_services::list_services(&self.http, &creds),
        );

        let instances: Vec<_> = taken("ovh.instances", instances_res, &mut failures)
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

        let services: Vec<_> = taken("ovh.services", services_res, &mut failures)
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
            // Empty when both calls succeeded. A caller must be able to tell an
            // account with nothing in it from one that could not be read.
            "errors": failures,
        });
        Ok(serde_json::to_string_pretty(&output)?)
    }
}

// ── Cloudflare implementation ───────────────────────────────────────────────

impl CloudTools {
    fn cf_creds(input: &CloudflareTarget) -> CloudflareCreds {
        CloudflareCreds {
            api_token: input.api_token.clone(),
            account_id: input.account_id.clone(),
        }
    }

    async fn fetch_cf_costs(&self, input: &CloudflareTarget) -> Result<String> {
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

    async fn fetch_cf_inventory(&self, input: &CloudflareTarget) -> Result<String> {
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
    async fn fetch_cross_cloud_summary(&self, input: &Target) -> Result<String> {
        let mut providers = Vec::new();

        // ── AWS ──
        //
        // AWS was absent from this report entirely, because it is the one cloud
        // that may need a role assumed and the old input carried no AWS fields at
        // all. A "cross-cloud" total that silently omits the largest bill is
        // worse than no total.
        // AWS is always attempted: its credential chain always has somewhere to
        // look, and if nothing answers, the entry below records that rather than
        // omitting the provider silently.
        {
            let aws = &input.aws();
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
        if let Ok(ref gcp) = input.gcp() {
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

                let mut gcp_entry = serde_json::json!({
                    "provider": "gcp",
                    "waste_total_monthly_usd": round2(waste_total),
                    "finding_count": finding_count,
                    "projects": project_summaries,
                });
                if let Some(err) = waste.get("error") {
                    gcp_entry["error"] = err.clone();
                }
                providers.push(gcp_entry);
            }
        }

        // ── OVH ──
        if let Ok(ref ovh) = input.ovh() {
            let creds = Self::ovh_creds(ovh);
            let mut failures: Vec<serde_json::Value> = Vec::new();
            let costs = taken(
                "ovh.billing",
                ovh_billing::get_costs(&self.http, &creds).await,
                &mut failures,
            );
            let services = taken(
                "ovh.services",
                ovh_services::list_services(&self.http, &creds).await,
                &mut failures,
            );
            providers.push(ovh_summary_entry(costs, services, failures));
        }

        // ── Cloudflare ──
        if let Ok(ref cf) = input.cloudflare() {
            let creds = Self::cf_creds(cf);
            let (costs_res, zones_res) = tokio::join!(
                cf_billing::get_costs(&self.http, &creds),
                cf_zones::list_zones(&self.http, &creds),
            );
            let mut failures: Vec<serde_json::Value> = Vec::new();
            let costs = taken("cloudflare.billing", costs_res, &mut failures);
            let zones = taken("cloudflare.zones", zones_res, &mut failures);
            providers.push(cloudflare_summary_entry(costs, zones, failures));
        }

        // ── Totals ──
        //
        // Spend and waste are counted separately, and that is the point. One
        // "grand_total_estimated_monthly_usd" used to add whichever figure each
        // provider happened to report — AWS and GCP contribute WASTE, Cloudflare
        // and OVH contribute BILLED SPEND — so the headline number was money
        // wasted plus money spent, which is not a quantity. Adding AWS to this
        // report made it wronger, since AWS reports waste.
        let waste_total: f64 = providers
            .iter()
            .filter_map(|p| p.get("waste_total_monthly_usd").and_then(|v| v.as_f64()))
            .sum();
        let spend_total: f64 = providers
            .iter()
            .filter_map(|p| {
                p.get("total_billed_usd")
                    .or(p.get("total_usd"))
                    .and_then(|v| v.as_f64())
            })
            .sum();

        let output = serde_json::json!({
            "summary": {
                "estimated_monthly_waste_usd": round2(waste_total),
                "waste_reported_by": providers.iter()
                    .filter(|p| p.get("waste_total_monthly_usd").is_some())
                    .filter_map(|p| p["provider"].as_str().map(String::from))
                    .collect::<Vec<_>>(),
                "billed_monthly_usd": round2(spend_total),
                "spend_reported_by": providers.iter()
                    .filter(|p| p.get("total_billed_usd").is_some() || p.get("total_usd").is_some())
                    .filter_map(|p| p["provider"].as_str().map(String::from))
                    .collect::<Vec<_>>(),
                "note": "Waste and spend are separate figures. Adding them together would \
                         double-count: waste is a subset of what some providers bill, and no \
                         provider here reports both.",
                "providers_included": providers.iter()
                    .filter_map(|p| p["provider"].as_str().map(String::from))
                    .collect::<Vec<_>>(),
                "partial": providers.iter().any(|p| p.get("errors").is_some() || p.get("error").is_some()),
            },
            "providers": providers,
        });
        Ok(serde_json::to_string_pretty(&output)?)
    }
}

/// The guidance every MCP client receives at handshake. It describes the
/// environment-based credential design the schemas implement; the old design
/// asked the agent to pass credentials per call, and this text said so until
/// the two disagreed. Kept as a constant so a test can hold it honest.
const SERVER_INSTRUCTIONS: &str = "Multi-cloud cost, inventory and waste analysis for AWS, GCP, \
    OVH and Cloudflare. Credentials come from the server's environment, never from tool \
    arguments. Call check_access first: it contacts nothing and reports which clouds are \
    configured and what is missing for the ones that are not. AWS: the server's credential \
    chain, or scan another account by assuming its role with target.role_arn \
    (CLOUD_TOOLS_AWS_ROLE_ARN sets a default). GCP: Application Default Credentials or \
    GOOGLE_APPLICATION_CREDENTIALS; choose projects with target.project_ids or \
    CLOUD_TOOLS_GCP_PROJECTS, and set CLOUD_TOOLS_GCP_BILLING_TABLE for real spend from the \
    BigQuery billing export. Cloudflare: CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID. OVH: \
    OVH_APPLICATION_KEY, OVH_APPLICATION_SECRET, OVH_CONSUMER_KEY, OVH_ENDPOINT. Every tool is \
    read-only and takes only a cloud name plus optional target selectors.";

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
            .with_instructions(SERVER_INSTRUCTIONS)
    }
}

fn round2(v: f64) -> f64 {
    // + 0.0 turns -0.0 into 0.0: summing an empty findings list produced
    // "total_estimated_monthly_waste_usd": -0.0, which reads as a defect.
    (v * 100.0).round() / 100.0 + 0.0
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

#[cfg(test)]
mod tests {
    use super::*;

    fn target(json: &str) -> Target {
        serde_json::from_str(json).expect("target should parse")
    }

    /// The cloud selector is an enum, so a typo is rejected by the schema rather
    /// than reaching a match arm and falling through to a default cloud.
    #[test]
    fn cloud_parses_only_the_four_names() {
        for (input, expect) in [
            ("\"aws\"", "aws"),
            ("\"gcp\"", "gcp"),
            ("\"cloudflare\"", "cloudflare"),
            ("\"ovh\"", "ovh"),
        ] {
            let c: Cloud = serde_json::from_str(input).expect("known cloud");
            assert_eq!(c.name(), expect);
        }
        assert!(serde_json::from_str::<Cloud>("\"azure\"").is_err());
        assert!(serde_json::from_str::<Cloud>("\"AWS\"").is_err());
    }

    /// A capability a cloud does not have must name the ones that do. An empty
    /// result would read as "nothing found", which for waste means a clean bill.
    #[test]
    fn unsupported_names_the_clouds_that_do_support_it() {
        let msg = unsupported("waste analysis", &Cloud::Ovh, &["aws", "gcp"]).to_string();
        assert_eq!(
            msg,
            "waste analysis is not implemented for ovh; supported: aws, gcp"
        );
    }

    /// The whole point of the selector/secret split: a tool call carries no
    /// credentials, so an empty object is a complete, valid input.
    #[test]
    fn an_empty_target_is_valid_and_carries_no_secret() {
        let t = target("{}");
        assert!(t.role_arn.is_none());
        assert!(t.external_id.is_none());
        assert!(t.project_ids.is_none());

        // And the tool inputs default it, so `{"cloud":"aws"}` is a whole call.
        let input: CloudInput =
            serde_json::from_str(r#"{"cloud":"aws"}"#).expect("cloud alone is enough");
        assert!(input.target.role_arn.is_none());
    }

    /// Selectors are not secrets, so they may still be passed — that is how one
    /// agent scans several AWS accounts or several GCP projects.
    #[test]
    fn selectors_are_still_accepted_for_multi_account_use() {
        let t =
            target(r#"{"role_arn":"arn:aws:iam::000000000000:role/Example","external_id":"x"}"#);
        let aws = t.aws();
        assert_eq!(
            aws.role_arn.as_deref(),
            Some("arn:aws:iam::000000000000:role/Example")
        );
        assert_eq!(aws.external_id.as_deref(), Some("x"));

        let t = target(r#"{"project_ids":["a","b","c"]}"#);
        assert_eq!(t.gcp().unwrap().project_ids, vec!["a", "b", "c"]);
    }

    /// A cloud with nothing configured must name the variable to set. "Not
    /// configured" sends the caller reading source.
    #[test]
    fn missing_configuration_names_the_variable() {
        let t = Target::default();
        for (result, expect) in [
            (t.cloudflare().err(), "CLOUDFLARE_API_TOKEN"),
            (t.ovh().err(), "OVH_APPLICATION_KEY"),
        ] {
            let msg = result
                .expect("absent configuration must be an error")
                .to_string();
            assert!(msg.contains(expect), "{msg:?} should name {expect}");
        }
        // GCP names both ways of supplying a project.
        let msg = t.gcp().err().map(|e| e.to_string()).unwrap_or_default();
        assert!(msg.contains("project_ids") && msg.contains("CLOUD_TOOLS_GCP_PROJECTS"));
    }

    /// An empty or whitespace-only variable is not configuration. Treating it as
    /// set is how a blank value in a compose file becomes a confusing 401.
    #[test]
    fn blank_environment_values_do_not_count_as_set() {
        let key = "CLOUD_TOOLS_TEST_BLANK_VALUE";
        std::env::set_var(key, "   ");
        assert!(env(key).is_none());
        std::env::set_var(key, "real");
        assert_eq!(env(key).as_deref(), Some("real"));
        std::env::remove_var(key);
        assert!(env(key).is_none());
    }

    /// Errors are serialised, not interpolated. The old code built the JSON with
    /// format!, so any message containing a quote produced a broken payload —
    /// and AWS answers with XML.
    #[test]
    fn error_payloads_survive_quotes_in_the_message() {
        let xml = r#"<Error><Message xmlns="x">no "token"</Message></Error>"#;
        let rendered = answer(Err(anyhow::anyhow!("STS failed: {xml}")));
        let parsed: serde_json::Value =
            serde_json::from_str(&rendered).expect("the payload must be valid JSON");
        assert!(parsed["error"].as_str().unwrap().contains(r#"no "token""#));
    }

    /// A successful result is passed through untouched, not re-wrapped.
    #[test]
    fn success_is_returned_verbatim() {
        assert_eq!(
            answer(Ok("{\"total_usd\":1.5}".into())),
            "{\"total_usd\":1.5}"
        );
    }

    /// Inverted, equal or malformed date ranges are rejected locally with a
    /// message naming both values, instead of surfacing as the provider's own
    /// "invalid parameter" after the request has travelled there.
    #[test]
    fn checked_dates_rejects_empty_and_inverted_ranges() {
        let msg = checked_dates("2024-03-01", "2024-02-01")
            .expect_err("inverted range must fail")
            .to_string();
        assert!(msg.contains("must be before"), "{msg}");
        assert!(
            msg.contains("2024-03-01") && msg.contains("2024-02-01"),
            "{msg}"
        );
        assert!(checked_dates("2024-03-01", "2024-03-01").is_err());
        assert!(checked_dates("2024-02-01", "not-a-date").is_err());

        let (s, e) = checked_dates("2024-02-01", "2024-03-01").expect("valid range");
        assert_eq!(s.to_string(), "2024-02-01");
        assert_eq!(e.to_string(), "2024-03-01");
    }

    /// A failed provider call in the cross-cloud summary is attached to its
    /// row as errors — never silently rendered as a zero bill.
    #[test]
    fn summary_rows_report_failures_instead_of_fabricating_zeros() {
        let ok = ovh_summary_entry(vec![], vec![], vec![]);
        assert_eq!(ok["total_billed_usd"], 0.0);
        assert!(ok.get("errors").is_none());

        let failed = ovh_summary_entry(
            vec![],
            vec![],
            vec![serde_json::json!({ "resource": "ovh.billing", "error": "HTTP 401" })],
        );
        assert_eq!(failed["total_billed_usd"], 0.0);
        assert!(failed["errors"][0]["error"]
            .as_str()
            .unwrap()
            .contains("401"));

        let cf = cloudflare_summary_entry(
            vec![],
            vec![],
            vec![serde_json::json!({
                "resource": "cloudflare.zones", "error": "quota exceeded"
            })],
        );
        assert!(cf["errors"][0]["error"].as_str().unwrap().contains("quota"));
    }

    /// The instructions every client receives at handshake describe the
    /// environment-based credential design — not the removed per-call
    /// credentials the old schema carried.
    #[test]
    fn server_instructions_describe_the_environment_design() {
        let text = SERVER_INSTRUCTIONS.to_lowercase();
        assert!(
            text.contains("check_access"),
            "should point at check_access"
        );
        assert!(text.contains("environment"), "should name the environment");
        assert!(text.contains("cloud_tools_gcp_billing_table"));
        for removed in ["service_account_json", "app_key", "credentials object"] {
            assert!(!text.contains(removed), "must not mention {removed}");
        }
    }
}
