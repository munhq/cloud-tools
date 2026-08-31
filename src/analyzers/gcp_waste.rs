//! GCP waste analysis — mirrors the AWS waste analyzer.
//!
//! Fetches inventory and metrics across Compute Engine, Cloud SQL, GKE,
//! Cloud Functions, Cloud Run, GCS, and the Recommender API, then applies
//! detection rules and returns findings sorted by estimated monthly savings.

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};

use super::waste::{OrgWasteReport, WasteItem, WasteKind};
use crate::clouds::gcp::{
    artifact_registry, auth::GcpCreds, cloud_functions, cloud_ids, cloud_run, cloud_sql, cloud_vpn,
    commitments, compute, gke, monitoring, networking, recommender, resource_manager, storage,
};

// ── Thresholds ───────────────────────────────────────────────────────────────

const IDLE_CPU_FRACTION: f64 = 0.05; // 5% (GCP returns 0.0–1.0, not percentage)
const OVERSIZED_CPU_FRACTION: f64 = 0.20; // 20%
const STALE_SNAPSHOT_DAYS: i64 = 90;
const STATIC_IP_MONTHLY_USD: f64 = 7.30; // $0.01/hr for unattached static IP

/// Previous-generation GCE machine type families.
const PREV_GEN_FAMILIES: &[&str] = &["n1", "f1", "g1"];

fn is_prev_gen_machine(machine_type: &str) -> bool {
    let family = machine_type.split('-').next().unwrap_or("");
    PREV_GEN_FAMILIES.contains(&family)
}

// ── GCE pricing (rough estimates, us-central1) ──────────────────────────────

fn gce_monthly_estimate(machine_type: &str) -> f64 {
    match machine_type {
        "f1-micro" => 3.88,
        "g1-small" => 13.80,
        "e2-micro" => 6.11,
        "e2-small" => 12.23,
        "e2-medium" => 24.46,
        "e2-standard-2" => 48.92,
        "e2-standard-4" => 97.83,
        "e2-standard-8" => 195.67,
        "n1-standard-1" => 24.27,
        "n1-standard-2" => 48.55,
        "n1-standard-4" => 97.09,
        "n1-standard-8" => 194.18,
        "n2-standard-2" => 48.92,
        "n2-standard-4" => 97.83,
        "n2-standard-8" => 195.67,
        "n2d-standard-2" => 42.56,
        "n2d-standard-4" => 85.12,
        "c2-standard-4" => 124.62,
        "c2-standard-8" => 249.24,
        _ => 50.0, // fallback estimate
    }
}

fn cloud_sql_monthly_estimate(tier: &str) -> f64 {
    match tier {
        "db-f1-micro" => 7.67,
        "db-g1-small" => 25.55,
        t if t.starts_with("db-custom-1-") => 36.72,
        t if t.starts_with("db-custom-2-") => 73.44,
        t if t.starts_with("db-custom-4-") => 146.88,
        t if t.starts_with("db-custom-8-") => 293.76,
        t if t.starts_with("db-custom-16-") => 587.52,
        _ => 75.0,
    }
}

fn pd_monthly_per_gb(disk_type: &str) -> f64 {
    match disk_type {
        "pd-standard" => 0.04,
        "pd-balanced" => 0.10,
        "pd-ssd" => 0.17,
        "pd-extreme" => 0.125,
        _ => 0.04,
    }
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Run full waste analysis for a GCP project.
/// Take the value, or record why there is none.
///
/// Every one of the twelve API calls below ended in `.unwrap_or_default()`, so a
/// disabled API or a missing permission produced an empty list and the analyser
/// reported "0 findings, $0 wasted". That is the most dangerous answer this tool
/// can give: it reads as a clean bill of health when the truth is that nothing
/// could be seen. Verified against a real project with the Compute, GKE, Cloud
/// Run, Cloud Functions and Cloud IDS APIs disabled — it reported no waste.
fn taken<T: Default>(what: &str, r: Result<T>, failures: &mut Vec<serde_json::Value>) -> T {
    match r {
        Ok(v) => v,
        Err(e) => {
            failures.push(serde_json::json!({ "resource": what, "error": e.to_string() }));
            T::default()
        }
    }
}

/// Waste findings only. Callers that can report the failures should use
/// [`analyse_reporting`] instead.
pub async fn analyse(client: &reqwest::Client, creds: &GcpCreds) -> Result<Vec<WasteItem>> {
    Ok(analyse_reporting(client, creds).await?.0)
}

/// Waste findings, and every API call that could not be made.
pub async fn analyse_reporting(
    client: &reqwest::Client,
    creds: &GcpCreds,
) -> Result<(Vec<WasteItem>, Vec<serde_json::Value>)> {
    let mut failures: Vec<serde_json::Value> = Vec::new();
    let token = crate::clouds::gcp::auth::access_token(client, creds).await?;

    // Fetch all inventory in parallel (nested joins to avoid tuple size limits)
    let (
        (
            disks_res,
            addresses_res,
            snapshots_res,
            sql_res,
            gke_res,
            functions_res,
            run_res,
            buckets_res,
            recommender_res,
        ),
        (ids_res, artifact_res, vpn_res),
    ) = tokio::join!(
        async {
            tokio::join!(
                compute::list_disks(client, &token, &creds.project_id),
                compute::list_addresses(client, &token, &creds.project_id),
                compute::list_snapshots(client, &token, &creds.project_id),
                cloud_sql::list_instances(client, creds),
                gke::list_clusters(client, creds),
                cloud_functions::list_functions(client, creds),
                cloud_run::list_services(client, creds),
                storage::list_buckets(client, creds),
                recommender::get_recommendations(client, creds),
            )
        },
        async {
            tokio::join!(
                cloud_ids::list_ids_endpoints(client, creds),
                artifact_registry::list_artifact_repos(client, creds),
                cloud_vpn::list_vpn_gateways(client, creds),
            )
        },
    );

    let disks = taken("compute.disks", disks_res, &mut failures);
    let addresses = taken("compute.addresses", addresses_res, &mut failures);
    let snapshots = taken("compute.snapshots", snapshots_res, &mut failures);
    let sql_instances = taken("sqladmin.instances", sql_res, &mut failures);
    let gke_clusters = taken("container.clusters", gke_res, &mut failures);
    let functions = taken("cloudfunctions.functions", functions_res, &mut failures);
    let run_services = taken("run.services", run_res, &mut failures);
    let buckets = taken("storage.buckets", buckets_res, &mut failures);
    let recommendations = taken(
        "recommender.recommendations",
        recommender_res,
        &mut failures,
    );
    let ids_endpoints = taken("ids.endpoints", ids_res, &mut failures);
    let artifact_repos = taken("artifactregistry.repositories", artifact_res, &mut failures);
    let vpn_gateways = taken("compute.vpnGateways", vpn_res, &mut failures);

    let mut findings: Vec<WasteItem> = Vec::new();

    // ── GCE Instance analysis (CPU-based idle/oversized) ───────────────────
    //
    // Also fetch the instance list to check stopped instances and CPU utilisation.
    // The Recommender API handles most of this, but we add our own checks for
    // consistency with the AWS approach.

    let instances_res = compute::list_resources(client, creds).await;
    let gce_instances = instances_res.unwrap_or_default();

    for inst in &gce_instances {
        if inst.resource_type != "gce_instance" {
            continue;
        }

        let status = inst.raw["status"].as_str().unwrap_or("");
        let machine_type = inst.raw["machineType"]
            .as_str()
            .and_then(|t| t.rsplit('/').next())
            .unwrap_or("unknown");
        let zone = inst.raw["zone"]
            .as_str()
            .and_then(|z| z.rsplit('/').next())
            .unwrap_or("");
        let monthly = gce_monthly_estimate(machine_type);

        // Stopped instances still incur disk costs
        if status == "TERMINATED" || status == "STOPPED" {
            findings.push(WasteItem {
                resource_id: inst.resource_id.clone(),
                resource_type: "gce_instance".into(),
                region: inst.region.clone().unwrap_or_default(),
                issue: WasteKind::StoppedGceInstance,
                detail: format!(
                    "GCE instance '{}' ({}) is {} — persistent disk costs still accruing",
                    inst.name.as_deref().unwrap_or(&inst.resource_id),
                    machine_type,
                    status,
                ),
                estimated_monthly_usd: monthly * 0.1, // disk cost estimate
                action: "Delete instance if no longer needed, or create machine image and delete"
                    .into(),
                account_id: None,
                account_name: None,
            });
            continue;
        }

        // Previous-generation machine type
        if is_prev_gen_machine(machine_type) && status == "RUNNING" {
            findings.push(WasteItem {
                resource_id: inst.resource_id.clone(),
                resource_type: "gce_instance".into(),
                region: inst.region.clone().unwrap_or_default(),
                issue: WasteKind::PrevGenInstance,
                detail: format!(
                    "GCE '{}' uses previous-gen type {} — n2/e2 family is cheaper and faster",
                    inst.name.as_deref().unwrap_or(&inst.resource_id),
                    machine_type,
                ),
                estimated_monthly_usd: monthly * 0.1,
                action: format!(
                    "Migrate {} to current-gen equivalent (n1→n2/e2, f1→e2-micro, g1→e2-small)",
                    machine_type,
                ),
                account_id: None,
                account_name: None,
            });
        }

        // Running — check CPU via Cloud Monitoring
        if status == "RUNNING" {
            if let Ok(Some(avg_cpu)) =
                monitoring::gce_cpu_avg(client, creds, &inst.resource_id, zone, 14).await
            {
                if avg_cpu < IDLE_CPU_FRACTION {
                    findings.push(WasteItem {
                        resource_id: inst.resource_id.clone(),
                        resource_type: "gce_instance".into(),
                        region: inst.region.clone().unwrap_or_default(),
                        issue: WasteKind::Idle,
                        detail: format!(
                            "GCE '{}' ({}) avg CPU {:.1}% over 14 days",
                            inst.name.as_deref().unwrap_or(&inst.resource_id),
                            machine_type, avg_cpu * 100.0,
                        ),
                        estimated_monthly_usd: monthly,
                        action: "Stop or delete if unused. Consider preemptible/spot VMs for batch workloads.".into(),
                        account_id: None,
                        account_name: None,
                    });
                } else if avg_cpu < OVERSIZED_CPU_FRACTION {
                    findings.push(WasteItem {
                        resource_id: inst.resource_id.clone(),
                        resource_type: "gce_instance".into(),
                        region: inst.region.clone().unwrap_or_default(),
                        issue: WasteKind::Oversized,
                        detail: format!(
                            "GCE '{}' ({}) avg CPU {:.1}% over 14 days — likely oversized",
                            inst.name.as_deref().unwrap_or(&inst.resource_id),
                            machine_type,
                            avg_cpu * 100.0,
                        ),
                        estimated_monthly_usd: monthly * 0.5,
                        action: format!(
                            "Consider downsizing from {machine_type} to a smaller machine type"
                        ),
                        account_id: None,
                        account_name: None,
                    });
                }
            }
        }
    }

    // ── Orphaned Persistent Disks ────────────────────────────────────────

    for disk in &disks {
        if !disk.attached && disk.status == "READY" {
            let monthly = disk.size_gb as f64 * pd_monthly_per_gb(&disk.disk_type);
            findings.push(WasteItem {
                resource_id: format!("{}/{}", disk.zone, disk.name),
                resource_type: "gcp_persistent_disk".into(),
                region: disk.region.clone(),
                issue: WasteKind::OrphanedPersistentDisk,
                detail: format!(
                    "Disk '{}' ({}GB {}) not attached to any instance",
                    disk.name, disk.size_gb, disk.disk_type,
                ),
                estimated_monthly_usd: monthly,
                action: "Delete disk or snapshot and delete. Verify no workloads reference it."
                    .into(),
                account_id: None,
                account_name: None,
            });
        }
    }

    // ── Unattached Static IPs ────────────────────────────────────────────

    for addr in &addresses {
        if addr.status == "RESERVED" && addr.address_type == "EXTERNAL" {
            findings.push(WasteItem {
                resource_id: format!("{}/{}", addr.region, addr.name),
                resource_type: "gcp_static_ip".into(),
                region: addr.region.clone(),
                issue: WasteKind::UnattachedStaticIp,
                detail: format!(
                    "Static IP '{}' ({}) is reserved but not in use",
                    addr.name, addr.address,
                ),
                estimated_monthly_usd: STATIC_IP_MONTHLY_USD,
                action: "Release static IP if no longer needed".into(),
                account_id: None,
                account_name: None,
            });
        }
    }

    // ── Stale Snapshots ──────────────────────────────────────────────────

    let now = Utc::now();
    let snapshot_threshold = now - Duration::days(STALE_SNAPSHOT_DAYS);

    for snap in &snapshots {
        if let Some(ref ts) = snap.creation_timestamp {
            if let Ok(created) = ts.parse::<DateTime<Utc>>() {
                if created < snapshot_threshold {
                    let age_days = (now - created).num_days();
                    let storage_gb = snap.storage_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                    let monthly = storage_gb * 0.026; // $0.026/GB-month for snapshots
                    findings.push(WasteItem {
                        resource_id: snap.name.clone(),
                        resource_type: "gcp_snapshot".into(),
                        region: String::new(), // snapshots are global
                        issue: WasteKind::StaleGcpSnapshot,
                        detail: format!(
                            "Snapshot '{}' is {} days old ({:.1}GB stored)",
                            snap.name, age_days, storage_gb,
                        ),
                        estimated_monthly_usd: monthly,
                        action: "Delete old snapshot if newer backups exist".into(),
                        account_id: None,
                        account_name: None,
                    });
                }
            }
        }
    }

    // ── Cloud SQL ────────────────────────────────────────────────────────

    for inst in &sql_instances {
        if inst.state != "RUNNABLE" {
            continue;
        }
        let monthly = cloud_sql_monthly_estimate(&inst.tier);

        // Check CPU
        match monitoring::cloud_sql_cpu_avg(client, creds, &inst.name, 14).await {
            Ok(Some(avg_cpu)) => {
                if avg_cpu < IDLE_CPU_FRACTION {
                    findings.push(WasteItem {
                        resource_id: inst.name.clone(),
                        resource_type: "cloud_sql_instance".into(),
                        region: inst.region.clone(),
                        issue: WasteKind::IdleCloudSql,
                        detail: format!(
                            "Cloud SQL '{}' ({} {}) avg CPU {:.1}% over 14 days — idle",
                            inst.name, inst.database_version, inst.tier,
                            avg_cpu * 100.0,
                        ),
                        estimated_monthly_usd: monthly,
                        action: "Stop instance or delete if unused. Consider Cloud SQL Auth Proxy for intermittent access.".into(),
                        account_id: None,
                        account_name: None,
                    });
                } else if avg_cpu < OVERSIZED_CPU_FRACTION {
                    findings.push(WasteItem {
                        resource_id: inst.name.clone(),
                        resource_type: "cloud_sql_instance".into(),
                        region: inst.region.clone(),
                        issue: WasteKind::OversizedCloudSql,
                        detail: format!(
                            "Cloud SQL '{}' ({} {}) avg CPU {:.1}% over 14 days — oversized",
                            inst.name,
                            inst.database_version,
                            inst.tier,
                            avg_cpu * 100.0,
                        ),
                        estimated_monthly_usd: monthly * 0.5,
                        action: format!("Downsize tier from {}", inst.tier),
                        account_id: None,
                        account_name: None,
                    });
                }
            }
            _ => {} // No metrics — skip
        }
    }

    // ── GKE Clusters ─────────────────────────────────────────────────────

    for cluster in &gke_clusters {
        if cluster.status != "RUNNING" {
            continue;
        }
        if cluster.node_count == 0 {
            findings.push(WasteItem {
                resource_id: cluster.name.clone(),
                resource_type: "gke_cluster".into(),
                region: cluster.location.clone(),
                issue: WasteKind::IdleGkeCluster,
                detail: format!(
                    "GKE cluster '{}' in {} has 0 nodes — paying for control plane only (~$73/mo)",
                    cluster.name, cluster.location,
                ),
                estimated_monthly_usd: 73.0, // GKE management fee
                action: "Delete cluster if no longer needed".into(),
                account_id: None,
                account_name: None,
            });
        }
    }

    // ── Cloud Functions ──────────────────────────────────────────────────

    for func in &functions {
        if func.state != "ACTIVE" {
            continue;
        }
        if let Ok(0) = monitoring::cloud_function_invocations(client, creds, &func.name, 30).await {
            findings.push(WasteItem {
                resource_id: func.full_name.clone(),
                resource_type: "cloud_function".into(),
                region: func.region.clone(),
                issue: WasteKind::IdleCloudFunction,
                detail: format!(
                    "Cloud Function '{}' ({} {}MB) had 0 invocations in 30 days",
                    func.name, func.runtime, func.memory_mb,
                ),
                estimated_monthly_usd: 0.0, // billed per invocation
                action: "Delete function to reduce attack surface. Check Cloud Scheduler and Pub/Sub triggers first.".into(),
                account_id: None,
                account_name: None,
            });
        }
    }

    // ── Cloud Run Services ───────────────────────────────────────────────

    for svc in &run_services {
        if let Ok(0) = monitoring::cloud_run_requests(client, creds, &svc.name, 30).await {
            findings.push(WasteItem {
                resource_id: svc.full_name.clone(),
                resource_type: "cloud_run_service".into(),
                region: svc.region.clone(),
                issue: WasteKind::IdleCloudRunService,
                detail: format!(
                    "Cloud Run service '{}' in {} had 0 requests in 30 days",
                    svc.name, svc.region,
                ),
                estimated_monthly_usd: 0.0, // billed per request (scale-to-zero)
                action: "Delete service if no longer needed. Check for custom domains or integrations first.".into(),
                account_id: None,
                account_name: None,
            });
        }
    }

    // ── GCS Buckets without lifecycle ────────────────────────────────────

    for bucket in &buckets {
        if !bucket.has_lifecycle_rules {
            findings.push(WasteItem {
                resource_id: bucket.name.clone(),
                resource_type: "gcs_bucket".into(),
                region: bucket.location.clone(),
                issue: WasteKind::NoGcsLifecyclePolicy,
                detail: format!(
                    "Bucket '{}' ({}) has no lifecycle rules — objects stored indefinitely",
                    bucket.name, bucket.storage_class,
                ),
                estimated_monthly_usd: 0.0, // can't estimate without bucket size
                action: "Add lifecycle rules to transition objects to Nearline/Coldline/Archive or delete old objects".into(),
                account_id: None,
                account_name: None,
            });
        }
    }

    // ── Committed Use Discounts (CUDs) ─────────────────────────────────

    let cuds = commitments::list_commitments(client, creds)
        .await
        .unwrap_or_default();
    let cud_expiry_threshold = now + Duration::days(30);

    for cud in &cuds {
        if cud.status != "ACTIVE" {
            continue;
        }
        if let Some(ref end_ts) = cud.end_timestamp {
            if let Ok(end_time) = end_ts.parse::<DateTime<Utc>>() {
                if end_time < cud_expiry_threshold {
                    let days_left = (end_time - now).num_days();
                    let status_text = if days_left < 0 { "EXPIRED" } else { "expiring" };
                    let resources_desc: Vec<String> = cud
                        .resources
                        .iter()
                        .map(|r| format!("{} {}", r.amount, r.resource_type))
                        .collect();

                    findings.push(WasteItem {
                        resource_id: cud.name.clone(),
                        resource_type: "gcp_commitment".into(),
                        region: cud.region.clone(),
                        issue: WasteKind::ExpiringReservedInstance,
                        detail: format!(
                            "CUD '{}' ({} {}) is {} ({}) — {}",
                            cud.name, cud.plan, cud.category, status_text,
                            if days_left < 0 {
                                format!("expired {} days ago", -days_left)
                            } else {
                                format!("{} days remaining", days_left)
                            },
                            resources_desc.join(", "),
                        ),
                        estimated_monthly_usd: 0.0, // CUD cost is already committed
                        action: "Renew commitment, adjust resource allocation, or switch to on-demand if workload changed".into(),
                        account_id: None,
                        account_name: None,
                    });
                }
            }
        }
    }

    // ── Recommender API findings ─────────────────────────────────────────

    for rec in &recommendations {
        if rec.estimated_monthly_savings_usd <= 0.0 {
            continue;
        }

        let (resource_type, issue_detail) = match rec.recommender_type.as_str() {
            t if t.contains("IdleResource") => ("gcp_idle_resource", "idle"),
            t if t.contains("MachineType") => ("gce_instance", "over-provisioned"),
            t if t.contains("disk.Idle") => ("gcp_persistent_disk", "idle"),
            t if t.contains("address.Idle") => ("gcp_static_ip", "idle"),
            t if t.contains("cloudsql") && t.contains("Idle") => ("cloud_sql_instance", "idle"),
            t if t.contains("cloudsql") && t.contains("Overprovisioned") => {
                ("cloud_sql_instance", "over-provisioned")
            }
            _ => ("gcp_resource", "optimization recommended"),
        };

        findings.push(WasteItem {
            resource_id: rec.resource_name.clone(),
            resource_type: resource_type.into(),
            region: rec.location.clone(),
            issue: WasteKind::GcpRecommenderFinding,
            detail: format!(
                "GCP Recommender: {} — {} ({})",
                rec.resource_name,
                issue_detail,
                if rec.description.is_empty() {
                    &rec.subtype
                } else {
                    &rec.description
                },
            ),
            estimated_monthly_usd: rec.estimated_monthly_savings_usd,
            action: format!(
                "Follow GCP Recommender suggestion: {}. Savings: ${:.2}/mo",
                rec.subtype, rec.estimated_monthly_savings_usd,
            ),
            account_id: None,
            account_name: None,
        });
    }

    // ── Cloud IDS — $390/mo per endpoint, always flag as expensive ─────

    for endpoint in &ids_endpoints {
        if endpoint.state == "ACTIVE" {
            findings.push(WasteItem {
                resource_id: endpoint.name.clone(),
                resource_type: "cloud_ids_endpoint".into(),
                region: endpoint.region.clone(),
                issue: WasteKind::CloudIdsEndpoint,
                detail: format!(
                    "Cloud IDS endpoint '{}' on network {} — $390/mo (Palo Alto managed firewall)",
                    endpoint.name, endpoint.network,
                ),
                estimated_monthly_usd: 390.0,
                action: "Evaluate if Cloud IDS is needed. Consider GKE network policies or Cloud Armor as cheaper alternatives.".into(),
                account_id: None,
                account_name: None,
            });
        }
    }

    // ── Artifact Registry — flag repos with no cleanup policy ────────

    for repo in &artifact_repos {
        let size_gb = repo.size_bytes as f64 / 1e9;
        let monthly_cost = size_gb * 0.10;

        if repo.cleanup_policy_count == 0 && size_gb > 1.0 {
            findings.push(WasteItem {
                resource_id: format!("{}/{}", repo.location, repo.name),
                resource_type: "artifact_registry".into(),
                region: repo.location.clone(),
                issue: WasteKind::NoArtifactRegistryCleanup,
                detail: format!(
                    "Artifact Registry '{}' ({:.1}GB, {} format) has no cleanup policy — storage grows unbounded",
                    repo.name, size_gb, repo.format,
                ),
                estimated_monthly_usd: monthly_cost,
                action: "Add a cleanup policy to keep only N most recent tags per image. Storage cost: $0.10/GB/mo.".into(),
                account_id: None,
                account_name: None,
            });
        } else if size_gb > 100.0 {
            findings.push(WasteItem {
                resource_id: format!("{}/{}", repo.location, repo.name),
                resource_type: "artifact_registry".into(),
                region: repo.location.clone(),
                issue: WasteKind::LargeArtifactRegistry,
                detail: format!(
                    "Artifact Registry '{}' is {:.1}GB ({} cleanup policies) — ${:.0}/mo",
                    repo.name, size_gb, repo.cleanup_policy_count, monthly_cost,
                ),
                estimated_monthly_usd: monthly_cost,
                action: format!(
                    "Review cleanup policies. Current cost: ${:.0}/mo. Consider more aggressive tag retention.",
                    monthly_cost,
                ),
                account_id: None,
                account_name: None,
            });
        }
    }

    // ── Cloud Logging cost estimation ────────────────────────────────

    if let Ok(bytes) = monitoring::logging_bytes_ingested(client, creds, 30).await {
        let gib = bytes as f64 / 1_073_741_824.0;
        let monthly_cost = gib * 0.50; // $0.50/GiB
        if monthly_cost > 10.0 {
            // Only flag if >$10/mo
            findings.push(WasteItem {
                resource_id: format!("{}/logging", creds.project_id),
                resource_type: "cloud_logging".into(),
                region: String::new(),
                issue: WasteKind::HighLoggingIngestion,
                detail: format!(
                    "Cloud Logging ingested {:.1} GiB in 30 days — ~${:.0}/mo",
                    gib, monthly_cost,
                ),
                estimated_monthly_usd: monthly_cost,
                action: "Add log exclusion filters (e.g. exclude GKE container logs below WARNING). Review log router sinks.".into(),
                account_id: None,
                account_name: None,
            });
        }
    }

    // ── VPC Flow Logs — flag 100% sampling ───────────────────────────

    if let Ok(subnets) = networking::list_subnetworks(client, creds).await {
        for subnet in &subnets {
            if subnet.flow_logs_enabled && subnet.flow_sampling >= 1.0 {
                // Rough estimate: $0.50/GB for flow log data, varies heavily by traffic
                let estimated = 12.50; // ~$12.50/mo per subnet at 100% sampling (conservative)
                findings.push(WasteItem {
                    resource_id: format!("{}/{}", subnet.region, subnet.name),
                    resource_type: "vpc_subnet".into(),
                    region: subnet.region.clone(),
                    issue: WasteKind::HighFlowLogSampling,
                    detail: format!(
                        "Subnet '{}' has VPC flow logs at {:.0}% sampling — 25-50% is usually sufficient",
                        subnet.name, subnet.flow_sampling * 100.0,
                    ),
                    estimated_monthly_usd: estimated,
                    action: "Reduce flow log sampling rate to 0.25-0.50 (25-50%). This provides sufficient visibility while reducing costs by 50-75%.".into(),
                    account_id: None,
                    account_name: None,
                });
            }
        }
    }

    // ── VPN — flag idle gateways ─────────────────────────────────────

    for vpn in &vpn_gateways {
        let all_tunnels_down = vpn.tunnels.iter().all(|t| t.status != "ESTABLISHED");
        if vpn.tunnel_count == 0 || all_tunnels_down {
            findings.push(WasteItem {
                resource_id: vpn.gateway_name.clone(),
                resource_type: "cloud_vpn".into(),
                region: vpn.region.clone(),
                issue: WasteKind::IdleVpnGateway,
                detail: format!(
                    "VPN gateway '{}' has {} tunnels, {} established — ~$37/mo",
                    vpn.gateway_name,
                    vpn.tunnel_count,
                    if all_tunnels_down { "none" } else { "all" },
                ),
                estimated_monthly_usd: 37.0,
                action: "Delete VPN gateway if no longer needed.".into(),
                account_id: None,
                account_name: None,
            });
        }
    }

    // Sort by estimated cost descending
    findings.sort_by(|a, b| {
        b.estimated_monthly_usd
            .partial_cmp(&a.estimated_monthly_usd)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    Ok((findings, failures))
}

/// Run waste analysis across all projects accessible by the service account.
///
/// Discovers projects via Cloud Resource Manager, then analyses each in parallel.
/// This is the GCP equivalent of AWS `analyse_org`.
pub async fn analyse_org(client: &reqwest::Client, creds: &GcpCreds) -> Result<OrgWasteReport> {
    let projects = resource_manager::list_projects(client, creds).await?;
    let total_accounts = projects.len();

    let scan_futures: Vec<_> = projects
        .iter()
        .map(|project| {
            let client = client.clone();
            let mut project_creds = creds.clone();
            project_creds.project_id = project.project_id.clone();
            let project_id = project.project_id.clone();
            let project_name = project.name.clone();

            async move {
                match analyse(&client, &project_creds).await {
                    Ok(mut findings) => {
                        for f in &mut findings {
                            f.account_id = Some(project_id.clone());
                            f.account_name = Some(project_name.clone());
                        }
                        (project_id, Some(findings))
                    }
                    Err(_) => (project_id, None),
                }
            }
        })
        .collect();

    let results = futures::future::join_all(scan_futures).await;

    let mut all_findings: Vec<WasteItem> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    let mut scanned = 0usize;

    for (project_id, findings) in results {
        match findings {
            Some(f) => {
                scanned += 1;
                all_findings.extend(f);
            }
            None => skipped.push(project_id),
        }
    }

    all_findings.sort_by(|a, b| {
        b.estimated_monthly_usd
            .partial_cmp(&a.estimated_monthly_usd)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let total_waste: f64 = all_findings.iter().map(|f| f.estimated_monthly_usd).sum();
    let coverage_note = if !skipped.is_empty() {
        Some(format!(
            "{} project(s) skipped — ensure the service account has viewer roles in all projects",
            skipped.len()
        ))
    } else {
        None
    };

    Ok(OrgWasteReport {
        total_accounts,
        scanned_accounts: scanned,
        skipped_account_ids: skipped,
        total_estimated_monthly_waste_usd: total_waste,
        finding_count: all_findings.len(),
        findings: all_findings,
        coverage_note,
    })
}
