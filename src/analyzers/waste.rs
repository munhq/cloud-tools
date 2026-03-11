use anyhow::Result;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::clouds::aws::{
    auth::{assume_role, AwsCreds},
    cloudwatch,
    ec2::{self, EbsVolume},
    organizations,
    pricing,
    rds,
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
}

/// Thresholds for idle/oversized detection (validated against kosty + aws-finops-dashboard).
const IDLE_CPU_PCT: f64 = 5.0;
const OVERSIZED_CPU_PCT: f64 = 20.0;
const IDLE_DAYS: u32 = 7;
const OVERSIZED_DAYS: u32 = 14;
const STOPPED_STALE_DAYS: i64 = 7;

/// Run full waste analysis for an AWS account.
///
/// Fetches inventory and metrics in parallel across all regions,
/// then applies detection rules and returns all findings.
pub async fn analyse(client: &reqwest::Client, creds: &AwsCreds) -> Result<Vec<WasteItem>> {
    // Fetch all inventory in parallel
    let (instances_res, volumes_res, eips_res, rds_res) = tokio::join!(
        ec2::list_instances(client, creds),
        ec2::list_volumes(client, creds),
        ec2::list_eips(client, creds),
        rds::list_instances(client, creds),
    );

    let instances = instances_res.unwrap_or_default();
    let volumes = volumes_res.unwrap_or_default();
    let eips = eips_res.unwrap_or_default();
    let rds_instances = rds_res.unwrap_or_default();

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
