use anyhow::{anyhow, Result};
use futures::future::join_all;

use super::{as_items, auth::{sign, AwsCreds}, xml_to_value};

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LoadBalancer {
    pub arn: String,
    pub name: String,
    pub lb_type: String,        // "application" | "network" | "gateway"
    pub state: String,          // "active" | "provisioning"
    pub region: String,
    pub has_targets: bool,      // false initially, updated by checking target groups
}

// ── Public API ────────────────────────────────────────────────────────────────

/// List all ELBv2 load balancers across all regions, enriched with target info.
pub async fn list_load_balancers(
    client: &reqwest::Client,
    creds: &AwsCreds,
) -> Result<Vec<LoadBalancer>> {
    let regions = list_elb_regions(client, creds).await?;
    let tasks: Vec<_> = regions
        .iter()
        .map(|r| list_lbs_in_region(client, creds, r))
        .collect();
    let results = join_all(tasks).await;
    Ok(results.into_iter().filter_map(|r| r.ok()).flatten().collect())
}

// ── Region list (reuse EC2 region list) ──────────────────────────────────────

async fn list_elb_regions(client: &reqwest::Client, creds: &AwsCreds) -> Result<Vec<String>> {
    let body = form_params(&[
        ("Action", "DescribeRegions"),
        ("Version", "2016-11-15"),
    ]);
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

// ── Per-region LB lister ─────────────────────────────────────────────────────

async fn list_lbs_in_region(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
) -> Result<Vec<LoadBalancer>> {
    let mut out = Vec::new();
    let mut marker: Option<String> = None;

    loop {
        let mut params = vec![
            ("Action", "DescribeLoadBalancers"),
            ("Version", "2015-12-01"),
        ];
        let marker_owned;
        if let Some(ref m) = marker {
            marker_owned = m.clone();
            params.push(("Marker", marker_owned.as_str()));
        }

        let body = form_params(&params);
        let xml = elb_query(client, creds, region, &body).await?;
        let v = xml_to_value(&xml)?;

        let members = as_items(
            &v["DescribeLoadBalancersResult"]["LoadBalancers"]["member"],
        );

        for lb in members {
            let arn = lb["LoadBalancerArn"].as_str().unwrap_or("").to_string();
            let name = lb["LoadBalancerName"].as_str().unwrap_or("").to_string();
            let lb_type = lb["Type"].as_str().unwrap_or("unknown").to_string();
            let state = lb["State"]["Code"].as_str().unwrap_or("unknown").to_string();

            let has_targets = check_has_targets(client, creds, region, &arn).await;

            out.push(LoadBalancer {
                arn,
                name,
                lb_type,
                state,
                region: region.to_string(),
                has_targets,
            });
        }

        match v["DescribeLoadBalancersResult"]["NextMarker"].as_str() {
            Some(m) if !m.is_empty() => marker = Some(m.to_string()),
            _ => break,
        }
    }
    Ok(out)
}

// ── Target group / target health checks ──────────────────────────────────────

/// Check whether any target group attached to this LB has registered targets.
async fn check_has_targets(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
    lb_arn: &str,
) -> bool {
    match describe_target_group_arns(client, creds, region, lb_arn).await {
        Ok(tg_arns) => {
            for tg_arn in tg_arns {
                if has_registered_targets(client, creds, region, &tg_arn)
                    .await
                    .unwrap_or(false)
                {
                    return true;
                }
            }
            false
        }
        Err(_) => false,
    }
}

/// Get all target group ARNs associated with a load balancer.
async fn describe_target_group_arns(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
    lb_arn: &str,
) -> Result<Vec<String>> {
    let body = form_params(&[
        ("Action", "DescribeTargetGroups"),
        ("Version", "2015-12-01"),
        ("LoadBalancerArn", lb_arn),
    ]);
    let xml = elb_query(client, creds, region, &body).await?;
    let v = xml_to_value(&xml)?;

    let members = as_items(
        &v["DescribeTargetGroupsResult"]["TargetGroups"]["member"],
    );

    Ok(members
        .iter()
        .filter_map(|tg| tg["TargetGroupArn"].as_str().map(String::from))
        .collect())
}

/// Check whether a target group has at least one registered target.
async fn has_registered_targets(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
    tg_arn: &str,
) -> Result<bool> {
    let body = form_params(&[
        ("Action", "DescribeTargetHealth"),
        ("Version", "2015-12-01"),
        ("TargetGroupArn", tg_arn),
    ]);
    let xml = elb_query(client, creds, region, &body).await?;
    let v = xml_to_value(&xml)?;

    let members = as_items(
        &v["DescribeTargetHealthResult"]["TargetHealthDescriptions"]["member"],
    );

    Ok(!members.is_empty())
}

// ── HTTP helper ───────────────────────────────────────────────────────────────

async fn elb_query(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
    body: &str,
) -> Result<String> {
    let url = format!("https://elasticloadbalancing.{region}.amazonaws.com/");
    let creds_for_region = AwsCreds { region: region.to_string(), ..creds.clone() };
    let body_bytes = body.as_bytes();

    let signed = sign(
        &creds_for_region,
        "POST",
        &url,
        &[("content-type", "application/x-www-form-urlencoded")],
        body_bytes,
        "elasticloadbalancing",
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
        return Err(anyhow!("ELB API error {status} in {region}: {text}"));
    }
    Ok(text)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn form_params(params: &[(&str, &str)]) -> String {
    let mut p = params.to_vec();
    p.sort_by_key(|(k, _)| *k);
    p.iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}
