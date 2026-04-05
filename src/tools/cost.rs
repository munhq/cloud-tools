use anyhow::Result;
use chrono::{NaiveDate, Utc};
use rmcp::{
    ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router,
};
use serde::Deserialize;

use crate::analyzers::gcp_waste;
use crate::clouds::aws::{auth::assume_role, ce};
use crate::clouds::cloudflare::{
    auth::CloudflareCreds,
    billing as cf_billing,
    certificates as cf_certs,
    dns as cf_dns,
    workers as cf_workers,
    zones as cf_zones,
};
use crate::clouds::gcp::{
    auth::GcpCreds,
    artifact_registry,
    cloud_functions,
    cloud_ids,
    cloud_nat,
    cloud_run,
    cloud_sql,
    cloud_vpn,
    compute,
    gke,
    monitoring,
    networking,
    recommender,
    storage,
};
use crate::clouds::ovh::{
    auth::OvhCreds,
    billing as ovh_billing,
    instances as ovh_instances,
    services as ovh_services,
};
use crate::tools::waste::{FindWasteInput, WasteTool};
use crate::types::CostEntry;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CompareAwsCostsInput {
    #[schemars(description = "Customer's IAM Role ARN, e.g. arn:aws:iam::123456789:role/CloudToolsReadOnly")]
    pub role_arn: String,
    #[schemars(description = "Optional external ID from the role's trust policy")]
    pub external_id: Option<String>,
}

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

// ── GCP input types ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetGcpInventoryInput {
    #[schemars(description = "One or more GCP project IDs to scan, e.g. [\"my-project-dev\", \"my-project-prod\"]")]
    pub project_ids: Vec<String>,
    #[schemars(description = "Optional: service account JSON string. If omitted, uses Application Default Credentials (ADC) from gcloud auth.")]
    pub service_account_json: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FindGcpWasteInput {
    #[schemars(description = "One or more GCP project IDs to analyse for waste, e.g. [\"my-project-dev\", \"my-project-prod\"]")]
    pub project_ids: Vec<String>,
    #[schemars(description = "Optional: service account JSON string. If omitted, uses Application Default Credentials (ADC) from gcloud auth.")]
    pub service_account_json: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetGcpRecommendationsInput {
    #[schemars(description = "One or more GCP project IDs to fetch recommendations for")]
    pub project_ids: Vec<String>,
    #[schemars(description = "Optional: service account JSON string. If omitted, uses Application Default Credentials (ADC) from gcloud auth.")]
    pub service_account_json: Option<String>,
}

// ── OVH input types ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct OvhInput {
    #[schemars(description = "OVH application key")]
    pub app_key: String,
    #[schemars(description = "OVH application secret")]
    pub app_secret: String,
    #[schemars(description = "OVH consumer key")]
    pub consumer_key: String,
    #[schemars(description = "OVH API endpoint: ovh-eu (default), ovh-us, or ovh-ca")]
    pub endpoint: Option<String>,
}

// ── Cloudflare input types ──────────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CloudflareInput {
    #[schemars(description = "Cloudflare API token with read access to account resources")]
    pub api_token: String,
    #[schemars(description = "Cloudflare account ID")]
    pub account_id: String,
}

// ── Cross-cloud summary input ───────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CrossCloudSummaryInput {
    #[schemars(description = "GCP project IDs to include")]
    pub gcp_project_ids: Option<Vec<String>>,
    #[schemars(description = "Optional: GCP service account JSON. If omitted, uses ADC.")]
    pub gcp_service_account_json: Option<String>,
    #[schemars(description = "Optional: OVH app key (omit to skip OVH)")]
    pub ovh_app_key: Option<String>,
    #[schemars(description = "Optional: OVH app secret")]
    pub ovh_app_secret: Option<String>,
    #[schemars(description = "Optional: OVH consumer key")]
    pub ovh_consumer_key: Option<String>,
    #[schemars(description = "Optional: OVH endpoint (default: ovh-eu)")]
    pub ovh_endpoint: Option<String>,
    #[schemars(description = "Optional: Cloudflare API token (omit to skip Cloudflare)")]
    pub cf_api_token: Option<String>,
    #[schemars(description = "Optional: Cloudflare account ID")]
    pub cf_account_id: Option<String>,
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

    #[tool(description = "Fair month-over-month cost comparison. Compares identical day windows (e.g. Mar 1-12 vs Feb 1-12) to avoid misleading partial-month deltas. Returns current vs previous period totals, percentage change, and per-service breakdown sorted by biggest movers.")]
    async fn compare_aws_costs(&self, Parameters(input): Parameters<CompareAwsCostsInput>) -> String {
        match self.do_compare_costs(input).await {
            Ok(result) => result,
            Err(e) => format!(r#"{{"error": "{e}"}}"#),
        }
    }

    #[tool(description = "Analyse an AWS account for waste and optimisation opportunities. Checks: idle/oversized EC2 (CPU metrics), stopped instances, orphaned EBS volumes, gp2→gp3 upgrades, unattached EIPs, previous-gen instance types, expiring Reserved Instances, unused AMIs (>90d), orphaned/stale EBS snapshots, unused key pairs, unused load balancers, idle NAT gateways (< 1 GB in 14 days), idle/zero-invocation Lambda functions, high Lambda error rates, idle/over-provisioned DynamoDB tables, S3 buckets without lifecycle policies, incomplete S3 multipart uploads, and CloudWatch log groups without retention. Returns findings sorted by estimated monthly savings.")]
    async fn find_aws_waste(&self, Parameters(input): Parameters<FindWasteInput>) -> String {
        WasteTool::new(self.http.clone()).run(input).await
    }

    #[tool(description = "Break down AWS data transfer costs by usage type for the last 30 days. Identifies expensive internet egress, cross-AZ traffic, and inter-region transfer. Returns items sorted by cost descending with human-readable descriptions (e.g. 'Internet egress (us-east-1)', 'Cross-AZ transfer').")]
    async fn get_aws_data_transfer(&self, Parameters(input): Parameters<CompareAwsCostsInput>) -> String {
        match self.do_data_transfer(input).await {
            Ok(result) => result,
            Err(e) => format!(r#"{{"error": "{e}"}}"#),
        }
    }

    #[tool(description = "Analyse AWS Savings Plans: existing SP utilisation (are you using what you committed to?), coverage percentage (what % of eligible spend is covered?), and CE purchase recommendations showing estimated monthly savings from buying Compute or EC2 Instance Savings Plans. Call from the management/payer account for org-wide recommendations.")]
    async fn get_aws_savings_plans(&self, Parameters(input): Parameters<CompareAwsCostsInput>) -> String {
        match self.do_savings_plans(input).await {
            Ok(result) => result,
            Err(e) => format!(r#"{{"error": "{e}"}}"#),
        }
    }

    // ── GCP tools ────────────────────────────────────────────────────────────

    #[tool(description = "Full GCP resource inventory across one or more projects. Returns: GCE instances, persistent disks, static IPs/addresses, snapshots, forwarding rules (load balancers), GKE clusters with node pools and pricing estimates, Cloud SQL instances, Cloud Functions, Cloud Run services, GCS buckets, Cloud NAT gateways, Cloud IDS endpoints, Artifact Registry repos with storage costs, VPN gateways and tunnels, subnets with flow logs enabled, PSC endpoints, and Cloud Logging ingestion bytes with cost estimate. Includes per-project summary. Auth: uses Application Default Credentials unless service_account_json is provided.")]
    async fn get_gcp_inventory(&self, Parameters(input): Parameters<GetGcpInventoryInput>) -> String {
        match self.fetch_gcp_inventory(input).await {
            Ok(result) => result,
            Err(e) => format!(r#"{{"error": "{e}"}}"#),
        }
    }

    #[tool(description = "Analyse GCP projects for waste and optimisation opportunities. Checks: idle/oversized GCE instances (CPU metrics), stopped instances, orphaned persistent disks, unattached static IPs, old snapshots (>90d), idle Cloud SQL, idle GKE clusters (0 nodes), zero-invocation Cloud Functions/Cloud Run, GCS buckets without lifecycle policies, expiring committed use discounts, and Recommender API findings. Returns findings sorted by estimated monthly savings. Auth: uses ADC unless service_account_json is provided.")]
    async fn find_gcp_waste(&self, Parameters(input): Parameters<FindGcpWasteInput>) -> String {
        match self.do_find_gcp_waste(input).await {
            Ok(result) => result,
            Err(e) => format!(r#"{{"error": "{e}"}}"#),
        }
    }

    #[tool(description = "Fetch GCP Recommender API suggestions across one or more projects. Queries: idle VM recommender, machine type rightsizing, idle persistent disks, idle static IPs, idle/oversized Cloud SQL. Scans all zones and regions in parallel. Returns active recommendations with estimated monthly savings. Auth: uses ADC unless service_account_json is provided.")]
    async fn get_gcp_recommendations(&self, Parameters(input): Parameters<GetGcpRecommendationsInput>) -> String {
        match self.fetch_gcp_recommendations(input).await {
            Ok(result) => result,
            Err(e) => format!(r#"{{"error": "{e}"}}"#),
        }
    }

    // ── OVH tools ────────────────────────────────────────────────────────────

    #[tool(description = "Get OVH billing: recent invoices with amounts. Returns up to 6 most recent bills.")]
    async fn get_ovh_costs(&self, Parameters(input): Parameters<OvhInput>) -> String {
        match self.fetch_ovh_costs(input).await {
            Ok(r) => r, Err(e) => format!(r#"{{"error": "{e}"}}"#),
        }
    }

    #[tool(description = "Get OVH inventory: cloud instances and all active services with renewal dates and monthly costs.")]
    async fn get_ovh_inventory(&self, Parameters(input): Parameters<OvhInput>) -> String {
        match self.fetch_ovh_inventory(input).await {
            Ok(r) => r, Err(e) => format!(r#"{{"error": "{e}"}}"#),
        }
    }

    // ── Cloudflare tools ─────────────────────────────────────────────────────

    #[tool(description = "Get Cloudflare billing: subscriptions with prices, and zone plan costs.")]
    async fn get_cloudflare_costs(&self, Parameters(input): Parameters<CloudflareInput>) -> String {
        match self.fetch_cf_costs(input).await {
            Ok(r) => r, Err(e) => format!(r#"{{"error": "{e}"}}"#),
        }
    }

    #[tool(description = "Get Cloudflare inventory: zones with plan/pricing, DNS records per zone (proxied vs dns-only counts), SSL certificates with hosts and expiry, and Workers with invocation counts.")]
    async fn get_cloudflare_inventory(&self, Parameters(input): Parameters<CloudflareInput>) -> String {
        match self.fetch_cf_inventory(input).await {
            Ok(r) => r, Err(e) => format!(r#"{{"error": "{e}"}}"#),
        }
    }

    // ── Cross-cloud summary ──────────────────────────────────────────────────

    #[tool(description = "Combined cost and waste report across all cloud providers (GCP, OVH, Cloudflare). Aggregates inventory costs and waste findings into one JSON report with grand total. Pass credentials for each provider you want included — omit a provider's credentials to skip it.")]
    async fn get_cross_cloud_summary(&self, Parameters(input): Parameters<CrossCloudSummaryInput>) -> String {
        match self.fetch_cross_cloud_summary(input).await {
            Ok(r) => r, Err(e) => format!(r#"{{"error": "{e}"}}"#),
        }
    }
}

impl CloudTools {
    async fn do_savings_plans(&self, input: CompareAwsCostsInput) -> Result<String> {
        let creds = assume_role(&self.http, &input.role_arn, input.external_id.as_deref()).await?;
        let now = Utc::now().date_naive();
        let start = now - chrono::Duration::days(30);
        let report = ce::get_savings_plans_report(&self.http, &creds, start, now).await?;
        Ok(serde_json::to_string_pretty(&report)?)
    }

    async fn do_data_transfer(&self, input: CompareAwsCostsInput) -> Result<String> {
        let creds = assume_role(&self.http, &input.role_arn, input.external_id.as_deref()).await?;
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

    async fn do_compare_costs(&self, input: CompareAwsCostsInput) -> Result<String> {
        let creds = assume_role(&self.http, &input.role_arn, input.external_id.as_deref()).await?;
        let comparison = ce::compare_costs(&self.http, &creds).await?;
        Ok(serde_json::to_string_pretty(&comparison)?)
    }

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

    async fn fetch_gcp_inventory(&self, input: GetGcpInventoryInput) -> Result<String> {
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
                (
                    sql_res,
                    functions_res,
                    run_res,
                    buckets_res,
                    nat_res,
                    ids_res,
                ),
                (
                    artifact_res,
                    vpn_res,
                    subnets_res,
                    psc_res,
                    logging_bytes_res,
                ),
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
                .map(|d| serde_json::json!({
                    "name": d.name,
                    "size_gb": d.size_gb,
                    "type": d.disk_type,
                    "status": d.status,
                    "zone": d.zone,
                    "attached": d.attached,
                }))
                .collect();

            let addresses: Vec<_> = addresses_res
                .unwrap_or_default()
                .into_iter()
                .map(|a| serde_json::json!({
                    "name": a.name,
                    "address": a.address,
                    "status": a.status,
                    "region": a.region,
                    "type": a.address_type,
                }))
                .collect();

            let snapshots: Vec<_> = snapshots_res
                .unwrap_or_default()
                .into_iter()
                .map(|s| serde_json::json!({
                    "name": s.name,
                    "disk_size_gb": s.disk_size_gb,
                    "storage_bytes": s.storage_bytes,
                    "status": s.status,
                    "created": s.creation_timestamp,
                    "source_disk": s.source_disk,
                }))
                .collect();

            let forwarding_rules: Vec<_> = fwd_rules_res
                .unwrap_or_default()
                .into_iter()
                .map(|fr| serde_json::json!({
                    "name": fr.name,
                    "region": fr.region,
                    "ip_address": fr.ip_address,
                    "target": fr.target,
                    "load_balancing_scheme": fr.load_balancing_scheme,
                }))
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
                .map(|s| serde_json::json!({
                    "name": s.name,
                    "database_version": s.database_version,
                    "tier": s.tier,
                    "state": s.state,
                    "region": s.region,
                    "disk_size_gb": s.data_disk_size_gb,
                    "disk_type": s.data_disk_type,
                }))
                .collect();

            let functions: Vec<_> = functions_res
                .unwrap_or_default()
                .into_iter()
                .map(|f| serde_json::json!({
                    "name": f.name,
                    "runtime": f.runtime,
                    "state": f.state,
                    "region": f.region,
                    "memory_mb": f.memory_mb,
                }))
                .collect();

            let run_services: Vec<_> = run_res
                .unwrap_or_default()
                .into_iter()
                .map(|r| serde_json::json!({
                    "name": r.name,
                    "region": r.region,
                    "uri": r.uri,
                    "latest_revision": r.latest_ready_revision,
                }))
                .collect();

            let buckets: Vec<_> = buckets_res
                .unwrap_or_default()
                .into_iter()
                .map(|b| serde_json::json!({
                    "name": b.name,
                    "location": b.location,
                    "storage_class": b.storage_class,
                    "has_lifecycle_rules": b.has_lifecycle_rules,
                    "versioning": b.versioning_enabled,
                }))
                .collect();

            // New resource types
            let cloud_nat: Vec<_> = nat_res
                .unwrap_or_default()
                .into_iter()
                .map(|n| serde_json::json!({
                    "name": n.name,
                    "router_name": n.router_name,
                    "region": n.region,
                    "source_ranges": n.source_ranges,
                    "nat_ips": n.nat_ips,
                }))
                .collect();

            let cloud_ids: Vec<_> = ids_res
                .unwrap_or_default()
                .into_iter()
                .map(|e| serde_json::json!({
                    "name": e.name,
                    "network": e.network,
                    "severity": e.severity,
                    "state": e.state,
                    "region": e.region,
                }))
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
                    let tunnels: Vec<_> = v.tunnels.iter().map(|t| serde_json::json!({
                        "name": t.name,
                        "status": t.status,
                        "peer_ip": t.peer_ip,
                        "ike_version": t.ike_version,
                    })).collect();
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
                .map(|s| serde_json::json!({
                    "name": s.name,
                    "region": s.region,
                    "ip_cidr_range": s.ip_cidr_range,
                    "flow_logs_enabled": s.flow_logs_enabled,
                    "flow_sampling": s.flow_sampling,
                    "purpose": s.purpose,
                }))
                .collect();

            let psc_endpoints: Vec<_> = psc_res
                .unwrap_or_default()
                .into_iter()
                .map(|p| serde_json::json!({
                    "name": p.name,
                    "region": p.region,
                    "address": p.address,
                    "target": p.target,
                    "status": p.status,
                }))
                .collect();

            // Logging cost estimation
            let logging_bytes = logging_bytes_res.unwrap_or(0);
            let logging_estimated_monthly_usd = round2(logging_bytes as f64 / 1_073_741_824.0 * 0.50);

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

    async fn do_find_gcp_waste(&self, input: FindGcpWasteInput) -> Result<String> {
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

    async fn fetch_gcp_recommendations(&self, input: GetGcpRecommendationsInput) -> Result<String> {
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
    fn ovh_creds(input: &OvhInput) -> OvhCreds {
        OvhCreds {
            app_key: input.app_key.clone(),
            app_secret: input.app_secret.clone(),
            consumer_key: input.consumer_key.clone(),
            endpoint: input.endpoint.clone().unwrap_or_else(|| "ovh-eu".into()),
        }
    }

    async fn fetch_ovh_costs(&self, input: OvhInput) -> Result<String> {
        let creds = Self::ovh_creds(&input);
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

    async fn fetch_ovh_inventory(&self, input: OvhInput) -> Result<String> {
        let creds = Self::ovh_creds(&input);
        let (instances_res, services_res) = tokio::join!(
            ovh_instances::list_resources(&self.http, &creds),
            ovh_services::list_services(&self.http, &creds),
        );

        let instances: Vec<_> = instances_res.unwrap_or_default().into_iter().map(|r| {
            serde_json::json!({
                "name": r.name,
                "id": r.resource_id,
                "type": r.resource_type,
                "region": r.region,
                "status": if r.last_active_at.is_some() { "ACTIVE" } else { "INACTIVE" },
            })
        }).collect();

        let services: Vec<_> = services_res.unwrap_or_default().into_iter().map(|s| {
            serde_json::json!({
                "service_id": s.service_id,
                "type": s.service_type,
                "name": s.display_name,
                "status": s.status,
                "expiration": s.expiration_date,
                "renew": s.renew_type,
                "monthly_cost": s.monthly_cost,
            })
        }).collect();

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
    fn cf_creds(input: &CloudflareInput) -> CloudflareCreds {
        CloudflareCreds {
            api_token: input.api_token.clone(),
            account_id: input.account_id.clone(),
        }
    }

    async fn fetch_cf_costs(&self, input: CloudflareInput) -> Result<String> {
        let creds = Self::cf_creds(&input);
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

    async fn fetch_cf_inventory(&self, input: CloudflareInput) -> Result<String> {
        let creds = Self::cf_creds(&input);
        let (zones_res, dns_res, certs_res, workers_res) = tokio::join!(
            cf_zones::list_zones(&self.http, &creds),
            cf_dns::list_dns_records(&self.http, &creds),
            cf_certs::list_certificates(&self.http, &creds),
            cf_workers::list_resources(&self.http, &creds),
        );

        let zones: Vec<_> = zones_res.unwrap_or_default().into_iter().map(|z| {
            serde_json::json!({
                "name": z.name,
                "status": z.status,
                "plan": z.plan_name,
                "plan_price_usd": z.plan_price,
                "paused": z.paused,
            })
        }).collect();

        let dns: Vec<_> = dns_res.unwrap_or_default().into_iter().map(|d| {
            serde_json::json!({
                "zone": d.zone_name,
                "total_records": d.total_records,
                "proxied": d.proxied_count,
                "dns_only": d.dns_only_count,
            })
        }).collect();

        let certs: Vec<_> = certs_res.unwrap_or_default().into_iter().map(|c| {
            serde_json::json!({
                "zone": c.zone_name,
                "type": c.cert_type,
                "status": c.status,
                "hosts": c.hosts,
                "expires": c.expires_on,
            })
        }).collect();

        let workers: Vec<_> = workers_res.unwrap_or_default().into_iter()
            .filter(|w| w.resource_type == "cf_worker")
            .map(|w| {
                let requests = w.raw["sum"]["requests"].as_i64().unwrap_or(0);
                serde_json::json!({
                    "name": w.name,
                    "requests_30d": requests,
                    "active": w.last_active_at.is_some(),
                })
            }).collect();

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
    async fn fetch_cross_cloud_summary(&self, input: CrossCloudSummaryInput) -> Result<String> {
        let mut providers = Vec::new();

        // ── GCP ──
        if let Some(ref project_ids) = input.gcp_project_ids {
            if !project_ids.is_empty() {
                let waste_input = FindGcpWasteInput {
                    project_ids: project_ids.clone(),
                    service_account_json: input.gcp_service_account_json.clone(),
                };
                let waste_json = self.do_find_gcp_waste(waste_input).await
                    .unwrap_or_else(|e| format!(r#"{{"error":"{e}"}}"#));
                let waste: serde_json::Value = serde_json::from_str(&waste_json).unwrap_or_default();

                // Summarize waste findings by project
                let waste_total = waste["total_estimated_monthly_waste_usd"].as_f64().unwrap_or(0.0);
                let finding_count = waste["finding_count"].as_u64().unwrap_or(0);
                let mut by_project: std::collections::HashMap<String, f64> = std::collections::HashMap::new();
                if let Some(findings) = waste["findings"].as_array() {
                    for f in findings {
                        let pid = f["account_id"].as_str().unwrap_or("unknown").to_string();
                        let cost = f["estimated_monthly_usd"].as_f64().unwrap_or(0.0);
                        *by_project.entry(pid).or_default() += cost;
                    }
                }

                let project_summaries: Vec<_> = project_ids.iter().map(|pid| {
                    let waste_usd = by_project.get(pid.as_str()).copied().unwrap_or(0.0);
                    serde_json::json!({
                        "project_id": pid,
                        "waste_monthly_usd": round2(waste_usd),
                    })
                }).collect();

                providers.push(serde_json::json!({
                    "provider": "gcp",
                    "waste_total_monthly_usd": round2(waste_total),
                    "finding_count": finding_count,
                    "projects": project_summaries,
                }));
            }
        }

        // ── OVH ──
        if let (Some(ref key), Some(ref secret), Some(ref ck)) =
            (&input.ovh_app_key, &input.ovh_app_secret, &input.ovh_consumer_key)
        {
            let creds = OvhCreds {
                app_key: key.clone(),
                app_secret: secret.clone(),
                consumer_key: ck.clone(),
                endpoint: input.ovh_endpoint.clone().unwrap_or_else(|| "ovh-eu".into()),
            };
            let costs = ovh_billing::get_costs(&self.http, &creds).await.unwrap_or_default();
            let services = ovh_services::list_services(&self.http, &creds).await.unwrap_or_default();
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
        if let (Some(ref token), Some(ref account_id)) = (&input.cf_api_token, &input.cf_account_id) {
            let creds = CloudflareCreds {
                api_token: token.clone(),
                account_id: account_id.clone(),
            };
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
        let grand_total: f64 = providers.iter().filter_map(|p| {
            p.get("waste_total_monthly_usd")
                .or(p.get("total_billed_usd"))
                .or(p.get("total_usd"))
                .and_then(|v| v.as_f64())
        }).sum();

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
