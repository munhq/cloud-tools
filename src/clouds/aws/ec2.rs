use anyhow::Result;
use chrono::{DateTime, Utc};
use futures::future::join_all;

use super::common::{ec2_query, form_params, list_regions};
use super::{as_items, auth::AwsCreds, az_to_region, xml_to_value};

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Ec2Instance {
    pub id: String,
    pub instance_type: String,
    pub state: String, // "running" | "stopped" | "pending" | etc.
    pub region: String,
    pub name: Option<String>,
    pub launch_time: Option<DateTime<Utc>>,
    /// Only set for stopped instances — parsed from StateTransitionReason.
    pub stopped_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct EbsVolume {
    pub id: String,
    pub volume_type: String, // "gp2" | "gp3" | "io1" | "st1" | "sc1" | "standard"
    pub size_gb: u64,
    pub state: String, // "available" (unattached) | "in-use"
    pub region: String,
    pub name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Eip {
    pub allocation_id: String,
    pub public_ip: String,
    pub attached: bool,
    pub region: String,
}

#[derive(Debug, Clone)]
pub struct EbsSnapshot {
    pub id: String,
    pub volume_id: String, // "" if source volume deleted
    pub volume_size_gb: u64,
    pub state: String, // "completed"
    pub start_time: Option<DateTime<Utc>>,
    pub region: String,
    pub name: Option<String>,
    /// Whether the source volume still exists (set by the analyzer, not the API)
    pub source_volume_exists: bool,
}

#[derive(Debug, Clone)]
pub struct Ami {
    pub id: String,
    pub name: Option<String>,
    pub creation_date: Option<DateTime<Utc>>,
    pub region: String,
    /// Snapshot IDs backing this AMI's block device mappings
    pub snapshot_ids: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub name: String,
    pub key_pair_id: String,
    pub region: String,
}

#[derive(Debug, Clone)]
pub struct ReservedInstance {
    pub id: String,
    pub instance_type: String,
    pub instance_count: u32,
    pub state: String, // "active" | "retired"
    pub end_time: Option<DateTime<Utc>>,
    pub region: String,
    pub monthly_cost_usd: f64,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// List all EC2 instances across all regions (running + stopped).
pub async fn list_instances(
    client: &reqwest::Client,
    creds: &AwsCreds,
) -> Result<Vec<Ec2Instance>> {
    let regions = list_regions(client, creds).await?;
    let tasks: Vec<_> = regions
        .iter()
        .map(|r| list_instances_in_region(client, creds, r))
        .collect();
    let results = join_all(tasks).await;
    Ok(results
        .into_iter()
        .filter_map(|r| r.ok())
        .flatten()
        .collect())
}

/// List all EBS volumes across all regions.
pub async fn list_volumes(client: &reqwest::Client, creds: &AwsCreds) -> Result<Vec<EbsVolume>> {
    let regions = list_regions(client, creds).await?;
    let tasks: Vec<_> = regions
        .iter()
        .map(|r| list_volumes_in_region(client, creds, r))
        .collect();
    let results = join_all(tasks).await;
    Ok(results
        .into_iter()
        .filter_map(|r| r.ok())
        .flatten()
        .collect())
}

/// List all Elastic IPs across all regions.
pub async fn list_eips(client: &reqwest::Client, creds: &AwsCreds) -> Result<Vec<Eip>> {
    let regions = list_regions(client, creds).await?;
    let tasks: Vec<_> = regions
        .iter()
        .map(|r| list_eips_in_region(client, creds, r))
        .collect();
    let results = join_all(tasks).await;
    Ok(results
        .into_iter()
        .filter_map(|r| r.ok())
        .flatten()
        .collect())
}

/// List all EBS snapshots owned by self across all regions.
pub async fn list_snapshots(
    client: &reqwest::Client,
    creds: &AwsCreds,
) -> Result<Vec<EbsSnapshot>> {
    let regions = list_regions(client, creds).await?;
    let tasks: Vec<_> = regions
        .iter()
        .map(|r| list_snapshots_in_region(client, creds, r))
        .collect();
    let results = join_all(tasks).await;
    Ok(results
        .into_iter()
        .filter_map(|r| r.ok())
        .flatten()
        .collect())
}

/// List all AMIs owned by self across all regions.
pub async fn list_images(client: &reqwest::Client, creds: &AwsCreds) -> Result<Vec<Ami>> {
    let regions = list_regions(client, creds).await?;
    let tasks: Vec<_> = regions
        .iter()
        .map(|r| list_images_in_region(client, creds, r))
        .collect();
    let results = join_all(tasks).await;
    Ok(results
        .into_iter()
        .filter_map(|r| r.ok())
        .flatten()
        .collect())
}

/// List all key pairs across all regions.
pub async fn list_key_pairs(client: &reqwest::Client, creds: &AwsCreds) -> Result<Vec<KeyPair>> {
    let regions = list_regions(client, creds).await?;
    let tasks: Vec<_> = regions
        .iter()
        .map(|r| list_key_pairs_in_region(client, creds, r))
        .collect();
    let results = join_all(tasks).await;
    Ok(results
        .into_iter()
        .filter_map(|r| r.ok())
        .flatten()
        .collect())
}

/// List all active reserved instances across all regions.
pub async fn list_reserved_instances(
    client: &reqwest::Client,
    creds: &AwsCreds,
) -> Result<Vec<ReservedInstance>> {
    let regions = list_regions(client, creds).await?;
    let tasks: Vec<_> = regions
        .iter()
        .map(|r| list_reserved_instances_in_region(client, creds, r))
        .collect();
    let results = join_all(tasks).await;
    Ok(results
        .into_iter()
        .filter_map(|r| r.ok())
        .flatten()
        .collect())
}

// ── Region discovery ──────────────────────────────────────────────────────────

// ── Per-region resource listers ───────────────────────────────────────────────

async fn list_instances_in_region(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
) -> Result<Vec<Ec2Instance>> {
    let mut out = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut params = vec![
            ("Action", "DescribeInstances"),
            ("Version", "2016-11-15"),
            ("Filter.1.Name", "instance-state-name"),
            ("Filter.1.Value.1", "running"),
            ("Filter.1.Value.2", "stopped"),
        ];
        let token_owned;
        if let Some(ref t) = next_token {
            token_owned = t.clone();
            params.push(("NextToken", token_owned.as_str()));
        }

        let body = form_params(&params);
        let xml = ec2_query(client, creds, region, &body).await?;
        let v = xml_to_value(&xml)?;

        for reservation in as_items(&v["reservationSet"]["item"]) {
            for instance in as_items(&reservation["instancesSet"]["item"]) {
                if let Some(inst) = parse_instance(&instance, region) {
                    out.push(inst);
                }
            }
        }

        match v["nextToken"].as_str() {
            Some(t) if !t.is_empty() => next_token = Some(t.to_string()),
            _ => break,
        }
    }
    Ok(out)
}

async fn list_volumes_in_region(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
) -> Result<Vec<EbsVolume>> {
    let mut out = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut params = vec![("Action", "DescribeVolumes"), ("Version", "2016-11-15")];
        let token_owned;
        if let Some(ref t) = next_token {
            token_owned = t.clone();
            params.push(("NextToken", token_owned.as_str()));
        }

        let body = form_params(&params);
        let xml = ec2_query(client, creds, region, &body).await?;
        let v = xml_to_value(&xml)?;

        for vol in as_items(&v["volumeSet"]["item"]) {
            out.push(EbsVolume {
                id: vol["volumeId"].as_str().unwrap_or("").to_string(),
                volume_type: vol["volumeType"].as_str().unwrap_or("unknown").to_string(),
                size_gb: vol["size"].as_str().unwrap_or("0").parse().unwrap_or(0),
                state: vol["status"].as_str().unwrap_or("unknown").to_string(),
                region: region.to_string(),
                name: tag_value(&vol["tagSet"], "Name"),
            });
        }

        match v["nextToken"].as_str() {
            Some(t) if !t.is_empty() => next_token = Some(t.to_string()),
            _ => break,
        }
    }
    Ok(out)
}

async fn list_eips_in_region(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
) -> Result<Vec<Eip>> {
    let body = form_params(&[("Action", "DescribeAddresses"), ("Version", "2016-11-15")]);
    let xml = ec2_query(client, creds, region, &body).await?;
    let v = xml_to_value(&xml)?;

    Ok(as_items(&v["addressesSet"]["item"])
        .into_iter()
        .map(|e| Eip {
            allocation_id: e["allocationId"].as_str().unwrap_or("").to_string(),
            public_ip: e["publicIp"].as_str().unwrap_or("").to_string(),
            attached: e["instanceId"].is_string() || e["networkInterfaceId"].is_string(),
            region: region.to_string(),
        })
        .collect())
}

async fn list_snapshots_in_region(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
) -> Result<Vec<EbsSnapshot>> {
    let mut out = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let mut params = vec![
            ("Action", "DescribeSnapshots"),
            ("Version", "2016-11-15"),
            ("Owner.1", "self"),
        ];
        let token_owned;
        if let Some(ref t) = next_token {
            token_owned = t.clone();
            params.push(("NextToken", token_owned.as_str()));
        }

        let body = form_params(&params);
        let xml = ec2_query(client, creds, region, &body).await?;
        let v = xml_to_value(&xml)?;

        for snap in as_items(&v["snapshotSet"]["item"]) {
            let start_time = snap["startTime"]
                .as_str()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc));

            out.push(EbsSnapshot {
                id: snap["snapshotId"].as_str().unwrap_or("").to_string(),
                volume_id: snap["volumeId"].as_str().unwrap_or("").to_string(),
                volume_size_gb: snap["volumeSize"]
                    .as_str()
                    .unwrap_or("0")
                    .parse()
                    .unwrap_or(0),
                state: snap["status"].as_str().unwrap_or("unknown").to_string(),
                start_time,
                region: region.to_string(),
                name: tag_value(&snap["tagSet"], "Name"),
                source_volume_exists: true,
            });
        }

        match v["nextToken"].as_str() {
            Some(t) if !t.is_empty() => next_token = Some(t.to_string()),
            _ => break,
        }
    }
    Ok(out)
}

async fn list_images_in_region(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
) -> Result<Vec<Ami>> {
    let body = form_params(&[
        ("Action", "DescribeImages"),
        ("Version", "2016-11-15"),
        ("Owner.1", "self"),
    ]);
    let xml = ec2_query(client, creds, region, &body).await?;
    let v = xml_to_value(&xml)?;

    Ok(as_items(&v["imagesSet"]["item"])
        .into_iter()
        .map(|img| {
            let creation_date = img["creationDate"]
                .as_str()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc));

            let snapshot_ids: Vec<String> = as_items(&img["blockDeviceMapping"]["item"])
                .iter()
                .filter_map(|bdm| bdm["ebs"]["snapshotId"].as_str().map(String::from))
                .collect();

            Ami {
                id: img["imageId"].as_str().unwrap_or("").to_string(),
                name: img["name"].as_str().map(String::from),
                creation_date,
                region: region.to_string(),
                snapshot_ids,
            }
        })
        .collect())
}

async fn list_key_pairs_in_region(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
) -> Result<Vec<KeyPair>> {
    let body = form_params(&[("Action", "DescribeKeyPairs"), ("Version", "2016-11-15")]);
    let xml = ec2_query(client, creds, region, &body).await?;
    let v = xml_to_value(&xml)?;

    Ok(as_items(&v["keySet"]["item"])
        .into_iter()
        .map(|kp| KeyPair {
            name: kp["keyName"].as_str().unwrap_or("").to_string(),
            key_pair_id: kp["keyPairId"].as_str().unwrap_or("").to_string(),
            region: region.to_string(),
        })
        .collect())
}

async fn list_reserved_instances_in_region(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
) -> Result<Vec<ReservedInstance>> {
    let body = form_params(&[
        ("Action", "DescribeReservedInstances"),
        ("Version", "2016-11-15"),
        ("Filter.1.Name", "state"),
        ("Filter.1.Value.1", "active"),
    ]);
    let xml = ec2_query(client, creds, region, &body).await?;
    let v = xml_to_value(&xml)?;

    Ok(as_items(&v["reservedInstancesSet"]["item"])
        .into_iter()
        .map(|ri| {
            let end_time = ri["end"]
                .as_str()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc));

            let usage_price: f64 = ri["usagePrice"]
                .as_str()
                .unwrap_or("0")
                .parse()
                .unwrap_or(0.0);
            let fixed_price: f64 = ri["fixedPrice"]
                .as_str()
                .unwrap_or("0")
                .parse()
                .unwrap_or(0.0);
            let duration: f64 = ri["duration"]
                .as_str()
                .unwrap_or("0")
                .parse()
                .unwrap_or(0.0);

            let monthly_cost_usd = if usage_price > 0.0 {
                usage_price * 730.0
            } else if fixed_price > 0.0 && duration > 0.0 {
                // duration is in seconds; convert to months (avg 730 hours = 2_628_000 seconds)
                fixed_price / (duration / 2_628_000.0)
            } else {
                0.0
            };

            ReservedInstance {
                id: ri["reservedInstancesId"].as_str().unwrap_or("").to_string(),
                instance_type: ri["instanceType"].as_str().unwrap_or("unknown").to_string(),
                instance_count: ri["instanceCount"]
                    .as_str()
                    .unwrap_or("0")
                    .parse()
                    .unwrap_or(0),
                state: ri["state"].as_str().unwrap_or("unknown").to_string(),
                end_time,
                region: region.to_string(),
                monthly_cost_usd,
            }
        })
        .collect())
}

// ── HTTP helper ───────────────────────────────────────────────────────────────

// ── Parsers ───────────────────────────────────────────────────────────────────

fn parse_instance(i: &serde_json::Value, region: &str) -> Option<Ec2Instance> {
    let id = i["instanceId"].as_str()?.to_string();
    let instance_type = i["instanceType"].as_str().unwrap_or("unknown").to_string();
    let state = i["instanceState"]["name"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();

    let region = i["placement"]["availabilityZone"]
        .as_str()
        .map(az_to_region)
        .unwrap_or_else(|| region.to_string());

    let launch_time = i["launchTime"]
        .as_str()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc));

    // StateTransitionReason format: "User initiated (2026-03-01 12:00:00 UTC)"
    let stopped_at = if state == "stopped" {
        i["stateTransitionReason"].as_str().and_then(|r| {
            let start = r.find('(')? + 1;
            let end = r.find(')')?;
            let ts = &r[start..end]; // "2026-03-01 12:00:00 UTC"
            let ts = ts.trim_end_matches(" UTC");
            chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S")
                .ok()
                .map(|ndt| ndt.and_utc())
        })
    } else {
        None
    };

    Some(Ec2Instance {
        id,
        instance_type,
        state,
        region,
        name: tag_value(&i["tagSet"], "Name"),
        launch_time,
        stopped_at,
    })
}

fn tag_value(tag_set: &serde_json::Value, key: &str) -> Option<String> {
    as_items(&tag_set["item"])
        .iter()
        .find(|i| i["key"].as_str() == Some(key))
        .and_then(|i| i["value"].as_str().map(String::from))
}
