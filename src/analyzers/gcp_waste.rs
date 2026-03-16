//! GCP waste analysis — mirrors the AWS waste analyzer.
//!
//! Fetches inventory and metrics across Compute Engine, Cloud SQL, GKE,
//! Cloud Functions, Cloud Run, GCS, and the Recommender API, then applies
//! detection rules and returns findings sorted by estimated monthly savings.

use anyhow::Result;
use chrono::{DateTime, Duration, Utc};

use super::waste::{WasteItem, WasteKind};
use crate::clouds::gcp::{
    auth::GcpCreds,
    cloud_functions,
    cloud_run,
    cloud_sql,
    compute,
    gke,
    monitoring,
    recommender,
    storage,
};

// ── Thresholds ───────────────────────────────────────────────────────────────

const IDLE_CPU_FRACTION: f64 = 0.05;     // 5% (GCP returns 0.0–1.0, not percentage)
const OVERSIZED_CPU_FRACTION: f64 = 0.20; // 20%
const STALE_SNAPSHOT_DAYS: i64 = 90;
const STATIC_IP_MONTHLY_USD: f64 = 7.30;  // $0.01/hr for unattached static IP

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
pub async fn analyse(client: &reqwest::Client, creds: &GcpCreds) -> Result<Vec<WasteItem>> {
    let token = crate::clouds::gcp::auth::access_token(client, creds).await?;

    // Fetch all inventory in parallel
    let (
        disks_res,
        addresses_res,
        snapshots_res,
        sql_res,
        gke_res,
        functions_res,
        run_res,
        buckets_res,
        recommender_res,
    ) = tokio::join!(
        compute::list_disks(client, &token, &creds.project_id),
        compute::list_addresses(client, &token, &creds.project_id),
        compute::list_snapshots(client, &token, &creds.project_id),
        cloud_sql::list_instances(client, creds),
        gke::list_clusters(client, creds),
        cloud_functions::list_functions(client, creds),
        cloud_run::list_services(client, creds),
        storage::list_buckets(client, creds),
        recommender::get_recommendations(client, creds),
    );

    let disks = disks_res.unwrap_or_default();
    let addresses = addresses_res.unwrap_or_default();
    let snapshots = snapshots_res.unwrap_or_default();
    let sql_instances = sql_res.unwrap_or_default();
    let gke_clusters = gke_res.unwrap_or_default();
    let functions = functions_res.unwrap_or_default();
    let run_services = run_res.unwrap_or_default();
    let buckets = buckets_res.unwrap_or_default();
    let recommendations = recommender_res.unwrap_or_default();

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
                    machine_type, status,
                ),
                estimated_monthly_usd: monthly * 0.1, // disk cost estimate
                action: "Delete instance if no longer needed, or create machine image and delete".into(),
                account_id: None,
                account_name: None,
            });
            continue;
        }

        // Running — check CPU via Cloud Monitoring
        if status == "RUNNING" {
            if let Ok(Some(avg_cpu)) = monitoring::gce_cpu_avg(
                client, creds, &inst.resource_id, zone, 14,
            ).await {
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
                            machine_type, avg_cpu * 100.0,
                        ),
                        estimated_monthly_usd: monthly * 0.5,
                        action: format!("Consider downsizing from {machine_type} to a smaller machine type"),
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
                action: "Delete disk or snapshot and delete. Verify no workloads reference it.".into(),
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
                            inst.name, inst.database_version, inst.tier,
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
        match monitoring::cloud_function_invocations(client, creds, &func.name, 30).await {
            Ok(invocations) if invocations == 0 => {
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
            _ => {}
        }
    }

    // ── Cloud Run Services ───────────────────────────────────────────────

    for svc in &run_services {
        match monitoring::cloud_run_requests(client, creds, &svc.name, 30).await {
            Ok(requests) if requests == 0 => {
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
            _ => {}
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
            t if t.contains("cloudsql") && t.contains("Overprovisioned") => ("cloud_sql_instance", "over-provisioned"),
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
                if rec.description.is_empty() { &rec.subtype } else { &rec.description },
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

    // Sort by estimated cost descending
    findings.sort_by(|a, b| {
        b.estimated_monthly_usd
            .partial_cmp(&a.estimated_monthly_usd)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    Ok(findings)
}
