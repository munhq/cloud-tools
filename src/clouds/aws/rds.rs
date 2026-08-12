use anyhow::{anyhow, Result};
use futures::future::join_all;

use super::{
    as_items,
    auth::{sign, AwsCreds},
    az_to_region, xml_to_value,
};

#[derive(Debug, Clone)]
pub struct RdsInstance {
    pub id: String,
    pub instance_class: String, // "db.t3.micro", "db.r5.large", etc.
    pub engine: String,         // "mysql", "postgres", "aurora", etc.
    pub status: String,         // "available", "stopped", etc.
    pub multi_az: bool,
    pub storage_gb: u64,
    pub storage_type: String, // "gp2", "gp3", "io1"
    pub region: String,
}

/// List all RDS instances across all regions.
pub async fn list_instances(
    client: &reqwest::Client,
    creds: &AwsCreds,
) -> Result<Vec<RdsInstance>> {
    let regions = list_rds_regions(client, creds).await?;
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

// ── Region list (reuse EC2 region list) ──────────────────────────────────────

async fn list_rds_regions(client: &reqwest::Client, creds: &AwsCreds) -> Result<Vec<String>> {
    // Reuse EC2 DescribeRegions — it's the same region list
    let body = form_params(&[("Action", "DescribeRegions"), ("Version", "2016-11-15")]);
    let url = "https://ec2.us-east-1.amazonaws.com/";
    let signed = sign(
        creds,
        "POST",
        url,
        &[("content-type", "application/x-www-form-urlencoded")],
        body.as_bytes(),
        "ec2",
    )?;
    let mut req = client
        .post(url)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("x-amz-date", &signed.x_amz_date)
        .header("x-amz-content-sha256", &signed.x_amz_content_sha256)
        .header("authorization", &signed.authorization)
        .body(body);
    if let Some(t) = &signed.x_amz_security_token {
        req = req.header("x-amz-security-token", t);
    }
    let resp = req.send().await?;
    let xml = resp.text().await?;
    let v = xml_to_value(&xml)?;
    Ok(as_items(&v["regionInfo"]["item"])
        .into_iter()
        .filter_map(|r| r["regionName"].as_str().map(String::from))
        .collect())
}

async fn list_instances_in_region(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
) -> Result<Vec<RdsInstance>> {
    let mut out = Vec::new();
    let mut marker: Option<String> = None;

    loop {
        let mut params = vec![("Action", "DescribeDBInstances"), ("Version", "2014-10-31")];
        let marker_owned;
        if let Some(ref m) = marker {
            marker_owned = m.clone();
            params.push(("Marker", marker_owned.as_str()));
        }

        let body = form_params(&params);
        let url = format!("https://rds.{region}.amazonaws.com/");
        let creds_for_region = AwsCreds {
            region: region.to_string(),
            ..creds.clone()
        };

        let signed = sign(
            &creds_for_region,
            "POST",
            &url,
            &[("content-type", "application/x-www-form-urlencoded")],
            body.as_bytes(),
            "rds",
        )?;

        let mut req = client
            .post(&url)
            .header("content-type", "application/x-www-form-urlencoded")
            .header("x-amz-date", &signed.x_amz_date)
            .header("x-amz-content-sha256", &signed.x_amz_content_sha256)
            .header("authorization", &signed.authorization)
            .body(body);
        if let Some(t) = &signed.x_amz_security_token {
            req = req.header("x-amz-security-token", t);
        }

        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(anyhow!("RDS API error {status} in {region}: {text}"));
        }

        let v = xml_to_value(&text)?;
        let dbs = as_items(&v["DescribeDBInstancesResult"]["DBInstances"]["DBInstance"]);

        for db in dbs {
            let az = db["AvailabilityZone"].as_str().unwrap_or(region);
            out.push(RdsInstance {
                id: db["DBInstanceIdentifier"]
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
                instance_class: db["DBInstanceClass"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string(),
                engine: db["Engine"].as_str().unwrap_or("unknown").to_string(),
                status: db["DBInstanceStatus"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string(),
                multi_az: db["MultiAZ"].as_str() == Some("true"),
                storage_gb: db["AllocatedStorage"]
                    .as_str()
                    .unwrap_or("0")
                    .parse()
                    .unwrap_or(0),
                storage_type: db["StorageType"].as_str().unwrap_or("gp2").to_string(),
                region: az_to_region(az),
            });
        }

        match v["DescribeDBInstancesResult"]["Marker"].as_str() {
            Some(m) if !m.is_empty() => marker = Some(m.to_string()),
            _ => break,
        }
    }
    Ok(out)
}

fn form_params(params: &[(&str, &str)]) -> String {
    let mut p = params.to_vec();
    p.sort_by_key(|(k, _)| *k);
    p.iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}
