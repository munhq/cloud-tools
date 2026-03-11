use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use futures::future::join_all;

use super::{as_items, auth::{sign, AwsCreds}, az_to_region, xml_to_value};

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Ec2Instance {
    pub id: String,
    pub instance_type: String,
    pub state: String,        // "running" | "stopped" | "pending" | etc.
    pub region: String,
    pub name: Option<String>,
    pub launch_time: Option<DateTime<Utc>>,
    /// Only set for stopped instances — parsed from StateTransitionReason.
    pub stopped_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct EbsVolume {
    pub id: String,
    pub volume_type: String,  // "gp2" | "gp3" | "io1" | "st1" | "sc1" | "standard"
    pub size_gb: u64,
    pub state: String,        // "available" (unattached) | "in-use"
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

// ── Public API ────────────────────────────────────────────────────────────────

/// List all EC2 instances across all regions (running + stopped).
pub async fn list_instances(client: &reqwest::Client, creds: &AwsCreds) -> Result<Vec<Ec2Instance>> {
    let regions = list_regions(client, creds).await?;
    let tasks: Vec<_> = regions
        .iter()
        .map(|r| list_instances_in_region(client, creds, r))
        .collect();
    let results = join_all(tasks).await;
    Ok(results.into_iter().filter_map(|r| r.ok()).flatten().collect())
}

/// List all EBS volumes across all regions.
pub async fn list_volumes(client: &reqwest::Client, creds: &AwsCreds) -> Result<Vec<EbsVolume>> {
    let regions = list_regions(client, creds).await?;
    let tasks: Vec<_> = regions
        .iter()
        .map(|r| list_volumes_in_region(client, creds, r))
        .collect();
    let results = join_all(tasks).await;
    Ok(results.into_iter().filter_map(|r| r.ok()).flatten().collect())
}

/// List all Elastic IPs across all regions.
pub async fn list_eips(client: &reqwest::Client, creds: &AwsCreds) -> Result<Vec<Eip>> {
    let regions = list_regions(client, creds).await?;
    let tasks: Vec<_> = regions
        .iter()
        .map(|r| list_eips_in_region(client, creds, r))
        .collect();
    let results = join_all(tasks).await;
    Ok(results.into_iter().filter_map(|r| r.ok()).flatten().collect())
}

// ── Region discovery ──────────────────────────────────────────────────────────

async fn list_regions(client: &reqwest::Client, creds: &AwsCreds) -> Result<Vec<String>> {
    let body = form_params(&[
        ("Action", "DescribeRegions"),
        ("Version", "2016-11-15"),
    ]);
    let xml = ec2_query(client, creds, "us-east-1", &body).await?;
    let v = xml_to_value(&xml)?;
    let regions = as_items(&v["regionInfo"]["item"])
        .into_iter()
        .filter_map(|r| r["regionName"].as_str().map(String::from))
        .collect();
    Ok(regions)
}

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
        let mut params = vec![
            ("Action", "DescribeVolumes"),
            ("Version", "2016-11-15"),
        ];
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
    let body = form_params(&[
        ("Action", "DescribeAddresses"),
        ("Version", "2016-11-15"),
    ]);
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

// ── HTTP helper ───────────────────────────────────────────────────────────────

async fn ec2_query(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
    body: &str,
) -> Result<String> {
    let url = format!("https://ec2.{region}.amazonaws.com/");
    let creds_for_region = AwsCreds { region: region.to_string(), ..creds.clone() };
    let body_bytes = body.as_bytes();

    let signed = sign(
        &creds_for_region,
        "POST",
        &url,
        &[("content-type", "application/x-www-form-urlencoded")],
        body_bytes,
        "ec2",
    )?;

    let mut req = client
        .post(&url)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("x-amz-date", &signed.x_amz_date)
        .header("x-amz-content-sha256", &signed.x_amz_content_sha256)
        .header("authorization", &signed.authorization)
        .body(body.to_string());
    if let Some(token) = &signed.x_amz_security_token {
        req = req.header("x-amz-security-token", token);
    }

    let resp = req.send().await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        return Err(anyhow!("EC2 API error {status} in {region}: {text}"));
    }
    Ok(text)
}

// ── Parsers ───────────────────────────────────────────────────────────────────

fn parse_instance(i: &serde_json::Value, region: &str) -> Option<Ec2Instance> {
    let id = i["instanceId"].as_str()?.to_string();
    let instance_type = i["instanceType"].as_str().unwrap_or("unknown").to_string();
    let state = i["instanceState"]["name"].as_str().unwrap_or("unknown").to_string();

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
        i["stateTransitionReason"]
            .as_str()
            .and_then(|r| {
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

fn form_params(params: &[(&str, &str)]) -> String {
    let mut p: Vec<(&str, &str)> = params.to_vec();
    p.sort_by_key(|(k, _)| *k);
    p.iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}
