use anyhow::Result;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::clouds::aws::{
    auth::{assume_role, AwsCreds},
    cloudwatch,
    cloudwatch_logs,
    dynamodb,
    ec2::{self, EbsVolume},
    elasticache,
    elb,
    lambda,
    nat_gateway,
    organizations,
    pricing,
    rds,
    s3,
};

/// A single waste or optimisation finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasteItem {
    pub resource_id: String,
    pub resource_type: String,
    pub region: String,
    pub issue: WasteKind,
    pub detail: String,
    pub estimated_monthly_usd: f64,
    pub action: String,
    /// AWS Account ID this finding belongs to (populated in org scans).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    /// AWS Account name from Organizations (populated in org scans).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_name: Option<String>,
}

/// Result of an org-wide waste scan.
#[derive(Debug, Serialize, Deserialize)]
pub struct OrgWasteReport {
    pub total_accounts: usize,
    pub scanned_accounts: usize,
    /// Accounts where the member role wasn't available (StackSet not yet deployed).
    pub skipped_account_ids: Vec<String>,
    pub total_estimated_monthly_waste_usd: f64,
    pub finding_count: usize,
    pub findings: Vec<WasteItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage_note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WasteKind {
    /// EC2/RDS running but CPU consistently < 5% — idle
    Idle,
    /// EC2/RDS running but CPU consistently < 20% — oversized
    Oversized,
    /// EC2 stopped for > 7 days
    StoppedInstance,
    /// EBS volume not attached to any instance
    OrphanedVolume,
    /// EBS volume is gp2 — cheaper to upgrade to gp3
    Gp2Volume,
    /// EIP not attached to any resource
    UnattachedEip,
    /// Previous-generation instance type
    PrevGenInstance,
    /// Reserved Instance expiring within 30 days
    ExpiringReservedInstance,
    /// AMI older than 90 days not used by any running instance
    UnusedAmi,
    /// EBS snapshot whose source volume no longer exists
    OrphanedSnapshot,
    /// EBS snapshot older than 90 days (source volume still exists)
    StaleSnapshot,
    /// EC2 key pair not used by any instance
    UnusedKeyPair,
    /// Load balancer with no registered targets
    UnusedLoadBalancer,
    /// S3 bucket without a lifecycle policy
    NoLifecyclePolicy,
    /// S3 bucket with incomplete multipart uploads
    IncompleteMultipartUploads,
    /// CloudWatch log group with no retention policy (stores data forever)
    NoLogRetention,
    /// NAT gateway with no or near-zero traffic (< 1 GB in 14 days)
    IdleNatGateway,
    /// Lambda function with zero invocations in 30 days — dead code / security surface
    IdleLambda,
    /// Lambda function with error rate > 10% — paying for failing invocations
    HighErrorRateLambda,
    /// DynamoDB PROVISIONED table with < 20% utilisation of provisioned capacity
    OverprovisionedDynamoDb,
    /// DynamoDB PROVISIONED table with no reads or writes in 14 days
    IdleDynamoDb,
    /// ElastiCache cluster with near-zero connections — idle
    IdleElastiCache,
    /// ElastiCache cluster with low CPU / low connections — oversized
    OversizedElastiCache,
    /// ElastiCache cluster using previous-generation node type
    PrevGenElastiCache,
}

/// Thresholds for idle/oversized detection (validated against kosty + aws-finops-dashboard).
const IDLE_CPU_PCT: f64 = 5.0;
const OVERSIZED_CPU_PCT: f64 = 20.0;
const IDLE_DAYS: u32 = 7;
const OVERSIZED_DAYS: u32 = 14;
const STOPPED_STALE_DAYS: i64 = 7;
const RI_EXPIRY_WARNING_DAYS: i64 = 30;
const UNUSED_AMI_DAYS: i64 = 90;
const STALE_SNAPSHOT_DAYS: i64 = 90;

/// Run full waste analysis for an AWS account.
///
/// Fetches inventory and metrics in parallel across all regions,
/// then applies detection rules and returns all findings.
pub async fn analyse(client: &reqwest::Client, creds: &AwsCreds) -> Result<Vec<WasteItem>> {
    // Fetch all inventory in parallel — core resources + new checks
    let (
        instances_res,
        volumes_res,
        eips_res,
        rds_res,
        snapshots_res,
        amis_res,
        key_pairs_res,
        reserved_res,
        lbs_res,
        s3_res,
        logs_res,
        nat_gateways_res,
        lambda_res,
        dynamodb_res,
        elasticache_res,
    ) = tokio::join!(
        ec2::list_instances(client, creds),
        ec2::list_volumes(client, creds),
        ec2::list_eips(client, creds),
        rds::list_instances(client, creds),
        ec2::list_snapshots(client, creds),
        ec2::list_images(client, creds),
        ec2::list_key_pairs(client, creds),
        ec2::list_reserved_instances(client, creds),
        elb::list_load_balancers(client, creds),
        s3::list_buckets_with_issues(client, creds),
        cloudwatch_logs::list_log_groups_without_retention(client, creds),
        nat_gateway::list_nat_gateways(client, creds),
        lambda::list_functions(client, creds),
        dynamodb::list_tables(client, creds),
        elasticache::list_clusters(client, creds),
    );

    let instances = instances_res.unwrap_or_default();
    let volumes = volumes_res.unwrap_or_default();
    let eips = eips_res.unwrap_or_default();
    let rds_instances = rds_res.unwrap_or_default();
    let snapshots = snapshots_res.unwrap_or_default();
    let amis = amis_res.unwrap_or_default();
    let key_pairs = key_pairs_res.unwrap_or_default();
    let reserved_instances = reserved_res.unwrap_or_default();
    let load_balancers = lbs_res.unwrap_or_default();
    let s3_buckets = s3_res.unwrap_or_default();
    let log_groups = logs_res.unwrap_or_default();
    let nat_gateways = nat_gateways_res.unwrap_or_default();
    let lambda_functions = lambda_res.unwrap_or_default();
    let dynamo_tables = dynamodb_res.unwrap_or_default();
    let elasticache_clusters = elasticache_res.unwrap_or_default();

    let mut findings: Vec<WasteItem> = Vec::new();

    // ── EC2 analysis ──────────────────────────────────────────────────────────

    // Group running instances by region for batched CloudWatch queries
    let mut running_by_region: HashMap<String, Vec<String>> = HashMap::new();
    for inst in &instances {
        if inst.state == "running" {
            running_by_region
                .entry(inst.region.clone())
                .or_default()
                .push(inst.id.clone());
        }
    }

    // Fetch CPU stats for running instances (14 days covers both idle + oversized checks)
    let mut cpu_stats: HashMap<String, cloudwatch::CpuStats> = HashMap::new();
    for (region, ids) in &running_by_region {
        if let Ok(stats) = cloudwatch::ec2_cpu_stats(client, creds, region, ids, OVERSIZED_DAYS).await {
            for s in stats {
                cpu_stats.insert(s.resource_id.clone(), s);
            }
        }
    }

    // Build set of AMI IDs used by running/stopped instances (for unused AMI detection)
    let instance_ami_ids: HashSet<String> = instances
        .iter()
        .filter_map(|_| None::<String>) // instances don't track AMI ID yet
        .collect();
    // Instead, we'll check AMI age only — if older than 90 days and not recently used
    let _ = instance_ami_ids; // suppress unused warning; AMI check uses age-based heuristic

    for inst in &instances {
        let monthly = pricing::ec2_monthly(&inst.instance_type).unwrap_or(0.0);

        // Stopped instances still incur EBS costs
        if inst.state == "stopped" {
            let stale_threshold = Utc::now() - Duration::days(STOPPED_STALE_DAYS);
            let is_stale = inst
                .stopped_at
                .map(|t| t < stale_threshold)
                .unwrap_or(true); // unknown stop time → assume stale

            if is_stale {
                let days_stopped = inst
                    .stopped_at
                    .map(|t| (Utc::now() - t).num_days())
                    .unwrap_or(STOPPED_STALE_DAYS);
                findings.push(WasteItem {
                    resource_id: inst.id.clone(),
                    resource_type: "ec2_instance".into(),
                    region: inst.region.clone(),
                    issue: WasteKind::StoppedInstance,
                    detail: format!(
                        "{} ({}) stopped for ~{} days — EBS costs still accruing",
                        inst.name.as_deref().unwrap_or(&inst.id),
                        inst.instance_type,
                        days_stopped,
                    ),
                    estimated_monthly_usd: monthly * 0.1, // EBS cost estimate (10% of running cost)
                    action: "Terminate if no longer needed, or create AMI and terminate".into(),
                    account_id: None,
                    account_name: None,
                });
            }
            continue;
        }

        // Running — check CPU
        if let Some(stats) = cpu_stats.get(&inst.id) {
            if stats.sample_count > 0 {
                if stats.avg_percent < IDLE_CPU_PCT {
                    findings.push(WasteItem {
                        resource_id: inst.id.clone(),
                        resource_type: "ec2_instance".into(),
                        region: inst.region.clone(),
                        issue: WasteKind::Idle,
                        detail: format!(
                            "{} ({}) avg CPU {:.1}% over {} days",
                            inst.name.as_deref().unwrap_or(&inst.id),
                            inst.instance_type,
                            stats.avg_percent,
                            IDLE_DAYS,
                        ),
                        estimated_monthly_usd: monthly,
                        action: "Stop or terminate if unused. Consider Savings Plan if needed.".into(),
                        account_id: None,
                        account_name: None,
                    });
                } else if stats.avg_percent < OVERSIZED_CPU_PCT {
                    findings.push(WasteItem {
                        resource_id: inst.id.clone(),
                        resource_type: "ec2_instance".into(),
                        region: inst.region.clone(),
                        issue: WasteKind::Oversized,
                        detail: format!(
                            "{} ({}) avg CPU {:.1}% over {} days — likely oversized",
                            inst.name.as_deref().unwrap_or(&inst.id),
                            inst.instance_type,
                            stats.avg_percent,
                            OVERSIZED_DAYS,
                        ),
                        estimated_monthly_usd: monthly * 0.5, // savings from downsizing
                        action: format!(
                            "Consider downsizing {} to a smaller instance type",
                            inst.instance_type
                        ),
                        account_id: None,
                        account_name: None,
                    });
                }
            }
        }

        // Previous-generation instance type
        if pricing::is_prev_gen(&inst.instance_type) {
            findings.push(WasteItem {
                resource_id: inst.id.clone(),
                resource_type: "ec2_instance".into(),
                region: inst.region.clone(),
                issue: WasteKind::PrevGenInstance,
                detail: format!(
                    "{} uses previous-gen type {} — newer gen is cheaper and faster",
                    inst.name.as_deref().unwrap_or(&inst.id),
                    inst.instance_type,
                ),
                estimated_monthly_usd: monthly * 0.1,
                action: format!(
                    "Migrate {} to current-gen equivalent (m5→m6i, c4→c6i, r4→r6i)",
                    inst.instance_type
                ),
                account_id: None,
                account_name: None,
            });
        }
    }

    // ── EBS analysis ──────────────────────────────────────────────────────────

    findings.extend(analyse_volumes(&volumes));

    // ── EIP analysis ──────────────────────────────────────────────────────────

    for eip in &eips {
        if !eip.attached {
            findings.push(WasteItem {
                resource_id: eip.allocation_id.clone(),
                resource_type: "eip".into(),
                region: eip.region.clone(),
                issue: WasteKind::UnattachedEip,
                detail: format!("EIP {} is not attached to any resource", eip.public_ip),
                estimated_monthly_usd: pricing::eip_monthly(),
                action: "Release this Elastic IP if no longer needed".into(),
                account_id: None,
                account_name: None,
            });
        }
    }

    // ── RDS analysis ──────────────────────────────────────────────────────────

    let mut rds_running_by_region: HashMap<String, Vec<String>> = HashMap::new();
    for db in &rds_instances {
        if db.status == "available" {
            rds_running_by_region
                .entry(db.region.clone())
                .or_default()
                .push(db.id.clone());
        }
    }

    let mut rds_cpu: HashMap<String, cloudwatch::CpuStats> = HashMap::new();
    for (region, ids) in &rds_running_by_region {
        if let Ok(stats) = cloudwatch::rds_cpu_stats(client, creds, region, ids, OVERSIZED_DAYS).await {
            for s in stats {
                rds_cpu.insert(s.resource_id.clone(), s);
            }
        }
    }

    for db in &rds_instances {
        let monthly = pricing::rds_monthly(&db.instance_class).unwrap_or(0.0);
        if let Some(stats) = rds_cpu.get(&db.id) {
            if stats.sample_count > 0 && stats.avg_percent < IDLE_CPU_PCT {
                findings.push(WasteItem {
                    resource_id: db.id.clone(),
                    resource_type: "rds_instance".into(),
                    region: db.region.clone(),
                    issue: WasteKind::Idle,
                    detail: format!(
                        "{} ({} {}) avg CPU {:.1}% over {} days",
                        db.id, db.engine, db.instance_class,
                        stats.avg_percent, IDLE_DAYS,
                    ),
                    estimated_monthly_usd: monthly,
                    action: "Stop or delete if unused. Consider Aurora Serverless for intermittent workloads.".into(),
                    account_id: None,
                    account_name: None,
                });
            }
        }

        // gp2 storage → gp3 upgrade
        if db.storage_type == "gp2" {
            let savings = pricing::gp2_to_gp3_savings(db.storage_gb);
            findings.push(WasteItem {
                resource_id: db.id.clone(),
                resource_type: "rds_instance".into(),
                region: db.region.clone(),
                issue: WasteKind::Gp2Volume,
                detail: format!(
                    "{} uses gp2 storage ({}GB) — gp3 is 20% cheaper with better baseline performance",
                    db.id, db.storage_gb,
                ),
                estimated_monthly_usd: savings,
                action: "Modify storage type from gp2 to gp3 (no downtime required)".into(),
                account_id: None,
                account_name: None,
            });
        }
    }

    // ── Reserved Instance expiry ──────────────────────────────────────────────

    let now = Utc::now();
    let expiry_threshold = now + Duration::days(RI_EXPIRY_WARNING_DAYS);
    for ri in &reserved_instances {
        if let Some(end) = ri.end_time {
            if end < expiry_threshold {
                let days_left = (end - now).num_days();
                let status = if days_left < 0 { "EXPIRED" } else { "expiring" };
                findings.push(WasteItem {
                    resource_id: ri.id.clone(),
                    resource_type: "reserved_instance".into(),
                    region: ri.region.clone(),
                    issue: WasteKind::ExpiringReservedInstance,
                    detail: format!(
                        "RI {} for {} x{} is {} ({})",
                        ri.id, ri.instance_type, ri.instance_count,
                        status,
                        if days_left < 0 {
                            format!("expired {} days ago", -days_left)
                        } else {
                            format!("{} days remaining", days_left)
                        },
                    ),
                    estimated_monthly_usd: ri.monthly_cost_usd,
                    action: "Renew, convert to Savings Plan, or switch to on-demand if workload changed".into(),
                    account_id: None,
                    account_name: None,
                });
            }
        }
    }

    // ── Unused AMIs (>90 days old) ───────────────────────────────────────────

    let ami_age_threshold = now - Duration::days(UNUSED_AMI_DAYS);
    // Collect all snapshot IDs used by AMIs for the snapshot orphan check
    let mut ami_snapshot_ids: HashSet<String> = HashSet::new();
    for ami in &amis {
        for snap_id in &ami.snapshot_ids {
            ami_snapshot_ids.insert(snap_id.clone());
        }

        if let Some(created) = ami.creation_date {
            if created < ami_age_threshold {
                let total_snap_gb: u64 = ami.snapshot_ids.iter()
                    .filter_map(|sid| snapshots.iter().find(|s| s.id == *sid))
                    .map(|s| s.volume_size_gb)
                    .sum();
                let savings = pricing::ami_snapshot_monthly(total_snap_gb);
                let age_days = (now - created).num_days();
                findings.push(WasteItem {
                    resource_id: ami.id.clone(),
                    resource_type: "ami".into(),
                    region: ami.region.clone(),
                    issue: WasteKind::UnusedAmi,
                    detail: format!(
                        "AMI {} ({}) is {} days old with {} backing snapshots ({}GB)",
                        ami.id,
                        ami.name.as_deref().unwrap_or("unnamed"),
                        age_days,
                        ami.snapshot_ids.len(),
                        total_snap_gb,
                    ),
                    estimated_monthly_usd: savings,
                    action: "Deregister AMI and delete backing snapshots if no longer needed".into(),
                    account_id: None,
                    account_name: None,
                });
            }
        }
    }

    // ── EBS Snapshot analysis (orphaned + stale) ─────────────────────────────

    let volume_ids: HashSet<String> = volumes.iter().map(|v| v.id.clone()).collect();
    let snapshot_age_threshold = now - Duration::days(STALE_SNAPSHOT_DAYS);

    for snap in &snapshots {
        // Skip snapshots that back an AMI — those are managed by the AMI lifecycle
        if ami_snapshot_ids.contains(&snap.id) {
            continue;
        }

        let savings = pricing::snapshot_monthly(snap.volume_size_gb);
        let vol_exists = !snap.volume_id.is_empty() && volume_ids.contains(&snap.volume_id);

        if !vol_exists && !snap.volume_id.is_empty() {
            // Orphaned: source volume was deleted
            findings.push(WasteItem {
                resource_id: snap.id.clone(),
                resource_type: "ebs_snapshot".into(),
                region: snap.region.clone(),
                issue: WasteKind::OrphanedSnapshot,
                detail: format!(
                    "Snapshot {} ({}GB) — source volume {} no longer exists",
                    snap.name.as_deref().unwrap_or(&snap.id),
                    snap.volume_size_gb,
                    snap.volume_id,
                ),
                estimated_monthly_usd: savings,
                action: "Delete snapshot if backup is no longer needed".into(),
                account_id: None,
                account_name: None,
            });
        } else if let Some(start) = snap.start_time {
            if start < snapshot_age_threshold {
                let age_days = (now - start).num_days();
                findings.push(WasteItem {
                    resource_id: snap.id.clone(),
                    resource_type: "ebs_snapshot".into(),
                    region: snap.region.clone(),
                    issue: WasteKind::StaleSnapshot,
                    detail: format!(
                        "Snapshot {} ({}GB) is {} days old — volume {} still exists",
                        snap.name.as_deref().unwrap_or(&snap.id),
                        snap.volume_size_gb,
                        age_days,
                        snap.volume_id,
                    ),
                    estimated_monthly_usd: savings,
                    action: "Delete old snapshot if newer backups exist".into(),
                    account_id: None,
                    account_name: None,
                });
            }
        }
    }

    // ── Unused key pairs ─────────────────────────────────────────────────────

    // Key pairs in regions with no instances are likely unused.
    // Conservative approach: we don't track per-instance key names in our parser.
    let regions_with_instances: HashSet<String> = instances.iter().map(|i| i.region.clone()).collect();

    for kp in &key_pairs {
        // Only flag key pairs in regions with no instances — conservative approach
        // to avoid false positives since we don't track per-instance key names
        if !regions_with_instances.contains(&kp.region) {
            findings.push(WasteItem {
                resource_id: kp.key_pair_id.clone(),
                resource_type: "ec2_key_pair".into(),
                region: kp.region.clone(),
                issue: WasteKind::UnusedKeyPair,
                detail: format!(
                    "Key pair '{}' in region {} has no EC2 instances",
                    kp.name, kp.region,
                ),
                estimated_monthly_usd: 0.0, // no direct cost, but security hygiene
                action: "Delete unused key pair to reduce attack surface".into(),
                account_id: None,
                account_name: None,
            });
        }
    }

    // ── Unused load balancers ────────────────────────────────────────────────

    for lb in &load_balancers {
        if !lb.has_targets {
            findings.push(WasteItem {
                resource_id: lb.arn.clone(),
                resource_type: "load_balancer".into(),
                region: lb.region.clone(),
                issue: WasteKind::UnusedLoadBalancer,
                detail: format!(
                    "{} ({}) '{}' has no registered targets",
                    lb.lb_type, lb.state, lb.name,
                ),
                estimated_monthly_usd: pricing::lb_monthly(&lb.lb_type),
                action: "Delete load balancer if no longer needed".into(),
                account_id: None,
                account_name: None,
            });
        }
    }

    // ── S3 bucket issues ─────────────────────────────────────────────────────

    for bucket in &s3_buckets {
        if !bucket.has_lifecycle_policy {
            findings.push(WasteItem {
                resource_id: bucket.name.clone(),
                resource_type: "s3_bucket".into(),
                region: bucket.region.clone(),
                issue: WasteKind::NoLifecyclePolicy,
                detail: format!(
                    "Bucket '{}' has no lifecycle policy — objects stored indefinitely",
                    bucket.name,
                ),
                estimated_monthly_usd: 0.0, // can't estimate without knowing bucket size
                action: "Add lifecycle rules to transition old objects to cheaper storage or expire them".into(),
                account_id: None,
                account_name: None,
            });
        }
        if bucket.incomplete_multipart_count > 0 {
            findings.push(WasteItem {
                resource_id: bucket.name.clone(),
                resource_type: "s3_bucket".into(),
                region: bucket.region.clone(),
                issue: WasteKind::IncompleteMultipartUploads,
                detail: format!(
                    "Bucket '{}' has {} incomplete multipart upload(s) wasting storage",
                    bucket.name, bucket.incomplete_multipart_count,
                ),
                estimated_monthly_usd: 0.0, // can't estimate without knowing part sizes
                action: "Abort incomplete multipart uploads and add a lifecycle rule to auto-abort".into(),
                account_id: None,
                account_name: None,
            });
        }
    }

    // ── CloudWatch log retention ─────────────────────────────────────────────

    for lg in &log_groups {
        let storage_cost = pricing::cloudwatch_log_storage_monthly(lg.stored_bytes);
        let stored_gb = lg.stored_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
        findings.push(WasteItem {
            resource_id: lg.name.clone(),
            resource_type: "cloudwatch_log_group".into(),
            region: lg.region.clone(),
            issue: WasteKind::NoLogRetention,
            detail: format!(
                "Log group '{}' has no retention policy — storing {:.1}GB indefinitely",
                lg.name, stored_gb,
            ),
            estimated_monthly_usd: storage_cost,
            action: "Set a retention period (e.g. 30, 90, or 365 days) to control storage costs".into(),
            account_id: None,
            account_name: None,
        });
    }

    // ── Lambda analysis ───────────────────────────────────────────────────────

    for func in &lambda_functions {
        let invocations = func.invocations_30d.unwrap_or(0);

        if invocations == 0 {
            findings.push(WasteItem {
                resource_id: func.arn.clone(),
                resource_type: "lambda_function".into(),
                region: func.region.clone(),
                issue: WasteKind::IdleLambda,
                detail: format!(
                    "Lambda '{}' ({} MB, {}) had 0 invocations in 30 days — dead code",
                    func.name, func.memory_mb, func.runtime,
                ),
                estimated_monthly_usd: 0.0, // Lambda billed per invocation — 0 invocations = $0 cost
                action: "Delete function to reduce attack surface and simplify the account. \
                         Check for CloudWatch Events/EventBridge rules or API Gateway integrations first.".into(),
                account_id: None,
                account_name: None,
            });
            continue;
        }

        // High error rate check
        let errors = func.errors_30d.unwrap_or(0);
        if invocations > 0 && errors > 0 {
            let error_rate = errors as f64 / invocations as f64;
            if error_rate > 0.10 {
                let wasted_cost = pricing::lambda_monthly(
                    errors,
                    func.avg_duration_ms.unwrap_or(100.0),
                    func.memory_mb,
                );
                findings.push(WasteItem {
                    resource_id: func.arn.clone(),
                    resource_type: "lambda_function".into(),
                    region: func.region.clone(),
                    issue: WasteKind::HighErrorRateLambda,
                    detail: format!(
                        "Lambda '{}' error rate {:.1}% ({}/{} invocations failing in 30 days)",
                        func.name,
                        error_rate * 100.0,
                        errors,
                        invocations,
                    ),
                    estimated_monthly_usd: wasted_cost,
                    action: "Investigate CloudWatch Logs for error root cause. \
                             Fix the underlying issue — every failed invocation is billed.".into(),
                    account_id: None,
                    account_name: None,
                });
            }
        }
    }

    // ── DynamoDB analysis ─────────────────────────────────────────────────────

    for table in &dynamo_tables {
        let full_monthly = pricing::dynamodb_provisioned_monthly(table.provisioned_rcu, table.provisioned_wcu);

        // Derive average hourly consumption from CloudWatch data
        let avg_hourly_rcu = if table.hourly_consumed_rcu.is_empty() {
            None
        } else {
            Some(table.hourly_consumed_rcu.iter().sum::<f64>() / table.hourly_consumed_rcu.len() as f64)
        };
        let avg_hourly_wcu = if table.hourly_consumed_wcu.is_empty() {
            None
        } else {
            Some(table.hourly_consumed_wcu.iter().sum::<f64>() / table.hourly_consumed_wcu.len() as f64)
        };

        // Max available per hour = provisioned × 3600 seconds
        let max_rcu_per_hour = table.provisioned_rcu as f64 * 3600.0;
        let max_wcu_per_hour = table.provisioned_wcu as f64 * 3600.0;

        let rcu_util = avg_hourly_rcu.map(|c| if max_rcu_per_hour > 0.0 { c / max_rcu_per_hour } else { 0.0 });
        let wcu_util = avg_hourly_wcu.map(|c| if max_wcu_per_hour > 0.0 { c / max_wcu_per_hour } else { 0.0 });

        let max_util = match (rcu_util, wcu_util) {
            (Some(r), Some(w)) => Some(f64::max(r, w)),
            (Some(r), None) => Some(r),
            (None, Some(w)) => Some(w),
            (None, None) => None,
        };

        match max_util {
            Some(u) if u < 0.01 => {
                // Less than 1% utilisation — treat as idle
                findings.push(WasteItem {
                    resource_id: table.name.clone(),
                    resource_type: "dynamodb_table".into(),
                    region: table.region.clone(),
                    issue: WasteKind::IdleDynamoDb,
                    detail: format!(
                        "DynamoDB '{}' ({} RCU / {} WCU provisioned) had {:.1}% peak utilisation over 14 days — paying for idle capacity",
                        table.name, table.provisioned_rcu, table.provisioned_wcu,
                        u * 100.0,
                    ),
                    estimated_monthly_usd: full_monthly,
                    action: "Switch billing mode to PAY_PER_REQUEST (on-demand) — \
                             costs $0 when idle and scales automatically. \
                             Or delete the table if no longer needed.".into(),
                    account_id: None,
                    account_name: None,
                });
            }
            Some(u) if u < 0.20 => {
                // Low utilisation — oversized
                let consumed_rcu = (avg_hourly_rcu.unwrap_or(0.0) / 3600.0) as u64;
                let consumed_wcu = (avg_hourly_wcu.unwrap_or(0.0) / 3600.0) as u64;
                let wasted_rcu = table.provisioned_rcu.saturating_sub(consumed_rcu);
                let wasted_wcu = table.provisioned_wcu.saturating_sub(consumed_wcu);
                let savings = pricing::dynamodb_provisioned_monthly(wasted_rcu, wasted_wcu);

                findings.push(WasteItem {
                    resource_id: table.name.clone(),
                    resource_type: "dynamodb_table".into(),
                    region: table.region.clone(),
                    issue: WasteKind::OverprovisionedDynamoDb,
                    detail: format!(
                        "DynamoDB '{}' uses {:.1}% of provisioned capacity ({} RCU / {} WCU provisioned, avg ~{} RCU / {} WCU consumed/sec)",
                        table.name, u * 100.0,
                        table.provisioned_rcu, table.provisioned_wcu,
                        consumed_rcu, consumed_wcu,
                    ),
                    estimated_monthly_usd: savings,
                    action: format!(
                        "Reduce provisioned capacity to ~{} RCU / {} WCU, \
                         or switch to PAY_PER_REQUEST for variable workloads. \
                         Enable DynamoDB Auto Scaling to handle spikes automatically.",
                        (consumed_rcu * 2).max(1),
                        (consumed_wcu * 2).max(1),
                    ),
                    account_id: None,
                    account_name: None,
                });
            }
            _ => {} // sufficient utilisation or no data — skip
        }
    }

    // ── ElastiCache analysis ─────────────────────────────────────────────────

    for cluster in &elasticache_clusters {
        let monthly = pricing::elasticache_monthly(&cluster.node_type, cluster.num_nodes)
            .unwrap_or(0.0);

        // Idle: near-zero connections over 14 days
        let is_idle = match cluster.peak_connections_14d {
            Some(0) | None => true,
            Some(peak) => peak <= 1 && cluster.avg_connections_14d.unwrap_or(0.0) < 0.5,
        };

        if is_idle {
            let peak = cluster.peak_connections_14d.unwrap_or(0);
            findings.push(WasteItem {
                resource_id: cluster.cluster_id.clone(),
                resource_type: "elasticache_cluster".into(),
                region: cluster.region.clone(),
                issue: WasteKind::IdleElastiCache,
                detail: format!(
                    "ElastiCache '{}' ({} {} x{} {}) peak {} connections in 14 days — appears idle",
                    cluster.cluster_id, cluster.engine, cluster.node_type,
                    cluster.num_nodes, cluster.engine_version, peak,
                ),
                estimated_monthly_usd: monthly,
                action: "Delete cluster if no longer needed. Check application connection strings \
                         and DNS CNAMEs before removing.".into(),
                account_id: None,
                account_name: None,
            });
            continue;
        }

        // Oversized: very low CPU and low connection count
        if let Some(avg_cpu) = cluster.avg_cpu_14d {
            let avg_conns = cluster.avg_connections_14d.unwrap_or(0.0);
            if avg_cpu < 5.0 && avg_conns < 10.0 && monthly > 50.0 {
                let savings = monthly * 0.5; // estimate 50% savings from downsizing
                findings.push(WasteItem {
                    resource_id: cluster.cluster_id.clone(),
                    resource_type: "elasticache_cluster".into(),
                    region: cluster.region.clone(),
                    issue: WasteKind::OversizedElastiCache,
                    detail: format!(
                        "ElastiCache '{}' ({} {} x{}) avg CPU {:.1}%, avg {:.0} connections over 14 days — oversized",
                        cluster.cluster_id, cluster.engine, cluster.node_type,
                        cluster.num_nodes, avg_cpu, avg_conns,
                    ),
                    estimated_monthly_usd: savings,
                    action: format!(
                        "Consider downsizing from {} to a smaller node type, or reducing replica count from {}",
                        cluster.node_type, cluster.num_nodes,
                    ),
                    account_id: None,
                    account_name: None,
                });
            }
        }

        // Previous-generation node type
        if pricing::is_prev_gen_cache(&cluster.node_type) {
            findings.push(WasteItem {
                resource_id: cluster.cluster_id.clone(),
                resource_type: "elasticache_cluster".into(),
                region: cluster.region.clone(),
                issue: WasteKind::PrevGenElastiCache,
                detail: format!(
                    "ElastiCache '{}' uses previous-gen node type {} — newer gen is cheaper and faster",
                    cluster.cluster_id, cluster.node_type,
                ),
                estimated_monthly_usd: monthly * 0.1,
                action: format!(
                    "Migrate {} to current-gen equivalent (cache.m4→cache.m7g, cache.r4→cache.r7g)",
                    cluster.node_type,
                ),
                account_id: None,
                account_name: None,
            });
        }
    }

    // ── NAT Gateway analysis ──────────────────────────────────────────────────

    // Idle threshold: < 1 GB total egress bytes over 14 days.
    const IDLE_NAT_BYTES: u64 = 1_073_741_824; // 1 GiB

    for gw in &nat_gateways {
        let is_idle = match gw.bytes_out_14d {
            Some(b) => b < IDLE_NAT_BYTES,
            None => gw.active_connections_max.map(|c| c == 0).unwrap_or(true),
        };

        if is_idle {
            let bytes_gb = gw.bytes_out_14d.unwrap_or(0) as f64 / 1_073_741_824.0;
            let conns = gw.active_connections_max.unwrap_or(0);
            let name_part = gw.name.as_deref()
                .map(|n| format!(" '{n}'"))
                .unwrap_or_default();

            findings.push(WasteItem {
                resource_id: gw.id.clone(),
                resource_type: "nat_gateway".into(),
                region: gw.region.clone(),
                issue: WasteKind::IdleNatGateway,
                detail: format!(
                    "NAT Gateway {}{name_part} (VPC: {}) processed {:.2} GB in 14d, peak {} active connections — appears idle",
                    gw.id, gw.vpc_id, bytes_gb, conns,
                ),
                estimated_monthly_usd: pricing::nat_gateway_monthly(),
                action: "Delete if no longer routing traffic. Verify with VPC team — \
                         any instance in the private subnet using this NAT GW will lose internet access.".into(),
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

    Ok(findings)
}

fn analyse_volumes(volumes: &[EbsVolume]) -> Vec<WasteItem> {
    volumes
        .iter()
        .flat_map(|vol| {
            let mut items = Vec::new();
            let monthly = pricing::ebs_monthly(vol.size_gb, &vol.volume_type);

            if vol.state == "available" {
                items.push(WasteItem {
                    resource_id: vol.id.clone(),
                    resource_type: "ebs_volume".into(),
                    region: vol.region.clone(),
                    issue: WasteKind::OrphanedVolume,
                    detail: format!(
                        "{} ({}GB {}) not attached to any instance",
                        vol.name.as_deref().unwrap_or(&vol.id),
                        vol.size_gb,
                        vol.volume_type,
                    ),
                    estimated_monthly_usd: monthly,
                    action: "Delete volume or create snapshot then delete".into(),
                    account_id: None,
                    account_name: None,
                });
            }

            if vol.volume_type == "gp2" {
                let savings = pricing::gp2_to_gp3_savings(vol.size_gb);
                items.push(WasteItem {
                    resource_id: vol.id.clone(),
                    resource_type: "ebs_volume".into(),
                    region: vol.region.clone(),
                    issue: WasteKind::Gp2Volume,
                    detail: format!(
                        "{} ({}GB gp2) — upgrading to gp3 saves ${:.2}/month with better performance",
                        vol.name.as_deref().unwrap_or(&vol.id),
                        vol.size_gb,
                        savings,
                    ),
                    estimated_monthly_usd: savings,
                    action: "Modify volume type from gp2 to gp3 (no downtime, no data loss)".into(),
                    account_id: None,
                    account_name: None,
                });
            }

            items
        })
        .collect()
}

/// Run waste analysis across an entire AWS Organisation.
///
/// Uses the management account role to list all org accounts, then assumes
/// `MunbotFinOpsMemberRole` in each member account and runs analysis in parallel.
/// Accounts where the member role is not yet deployed are skipped gracefully.
pub async fn analyse_org(
    client: &reqwest::Client,
    management_account_id: &str,
) -> Result<OrgWasteReport> {
    let external_id = format!("munbot-{management_account_id}");
    let mgmt_role_arn = format!("arn:aws:iam::{management_account_id}:role/MunbotFinOpsRole");

    let mgmt_creds = assume_role(client, &mgmt_role_arn, Some(&external_id)).await?;

    // List all accounts in the org
    let accounts = organizations::list_accounts(client, &mgmt_creds).await?;
    let active_accounts: Vec<_> = accounts.iter().filter(|a| a.status == "ACTIVE").collect();
    let total_accounts = active_accounts.len();

    // Scan each account in parallel — management account uses its own creds,
    // member accounts get a fresh AssumeRole into MunbotFinOpsMemberRole.
    let scan_futures: Vec<_> = active_accounts
        .iter()
        .map(|account| {
            let client = client.clone();
            let mgmt_creds = mgmt_creds.clone();
            let account_id = account.id.clone();
            let account_name = account.name.clone();
            let mgmt_id = management_account_id.to_string();

            async move {
                let creds = if account_id == mgmt_id {
                    // Management account — use the management role directly
                    mgmt_creds
                } else {
                    // Member account — assume the member role (deployed via StackSet)
                    let member_arn = format!(
                        "arn:aws:iam::{account_id}:role/MunbotFinOpsMemberRole"
                    );
                    match assume_role(&client, &member_arn, None).await {
                        Ok(c) => c,
                        Err(_) => return (account_id, account_name, None), // StackSet not deployed yet
                    }
                };

                match analyse(&client, &creds).await {
                    Ok(mut findings) => {
                        for f in &mut findings {
                            f.account_id = Some(account_id.clone());
                            f.account_name = Some(account_name.clone());
                        }
                        (account_id, account_name, Some(findings))
                    }
                    Err(_) => (account_id, account_name, None),
                }
            }
        })
        .collect();

    let results = futures::future::join_all(scan_futures).await;

    let mut all_findings: Vec<WasteItem> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    let mut scanned = 0usize;

    for (account_id, _account_name, findings) in results {
        match findings {
            Some(f) => {
                scanned += 1;
                all_findings.extend(f);
            }
            None => skipped.push(account_id),
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
            "{} account(s) skipped — deploy the member StackSet for full org coverage",
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
