use anyhow::{anyhow, Result};
use futures::future::join_all;

use super::{
    as_items,
    auth::{sign, AwsCreds},
    cloudwatch, xml_to_value,
};

const DDB_CONTENT_TYPE: &str = "application/x-amz-json-1.0";

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DynamoTable {
    pub name: String,
    pub region: String,
    /// "PROVISIONED" | "PAY_PER_REQUEST"
    pub billing_mode: String,
    /// Provisioned read capacity units/second (0 for on-demand tables).
    pub provisioned_rcu: u64,
    /// Provisioned write capacity units/second (0 for on-demand tables).
    pub provisioned_wcu: u64,
    /// Per-hour ConsumedReadCapacityUnits totals over last 14 days (Sum stat).
    /// Empty means no CloudWatch data (table might be brand new or in a different state).
    pub hourly_consumed_rcu: Vec<f64>,
    /// Per-hour ConsumedWriteCapacityUnits totals over last 14 days.
    pub hourly_consumed_wcu: Vec<f64>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// List all DynamoDB tables across all regions and enrich provisioned tables
/// with 14-day CloudWatch consumption data.
pub async fn list_tables(client: &reqwest::Client, creds: &AwsCreds) -> Result<Vec<DynamoTable>> {
    let regions = list_regions(client, creds).await?;
    let tasks: Vec<_> = regions
        .iter()
        .map(|r| list_in_region(client, creds, r))
        .collect();
    let results = join_all(tasks).await;
    Ok(results
        .into_iter()
        .filter_map(|r| r.ok())
        .flatten()
        .collect())
}

// ── Region discovery via EC2 DescribeRegions ──────────────────────────────────

async fn list_regions(client: &reqwest::Client, creds: &AwsCreds) -> Result<Vec<String>> {
    let body = form_params_ec2(&[("Action", "DescribeRegions"), ("Version", "2016-11-15")]);
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

// ── Per-region listing ────────────────────────────────────────────────────────

async fn list_in_region(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
) -> Result<Vec<DynamoTable>> {
    let names = list_table_names(client, creds, region).await?;

    // Describe each table and enrich provisioned ones with CloudWatch concurrently
    let tasks: Vec<_> = names
        .iter()
        .map(|name| {
            let client = client.clone();
            let creds = creds.clone();
            let region = region.to_string();
            let name = name.clone();
            async move { describe_and_enrich(&client, &creds, &region, &name).await }
        })
        .collect();

    let results = join_all(tasks).await;
    Ok(results
        .into_iter()
        .filter_map(|r| r.ok())
        .flatten()
        .collect())
}

async fn list_table_names(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
) -> Result<Vec<String>> {
    let mut names = Vec::new();
    let mut last_name: Option<String> = None;

    loop {
        let body = match &last_name {
            Some(n) => {
                serde_json::json!({ "Limit": 100, "ExclusiveStartTableName": n }).to_string()
            }
            None => serde_json::json!({ "Limit": 100 }).to_string(),
        };

        let resp = ddb_call(client, creds, region, "DynamoDB_20120810.ListTables", &body).await?;
        let v: serde_json::Value = serde_json::from_str(&resp)
            .map_err(|e| anyhow!("DynamoDB ListTables parse error in {region}: {e}"))?;

        if let Some(table_names) = v["TableNames"].as_array() {
            names.extend(
                table_names
                    .iter()
                    .filter_map(|n| n.as_str().map(String::from)),
            );
        }

        match v["LastEvaluatedTableName"].as_str() {
            Some(n) if !n.is_empty() => last_name = Some(n.to_string()),
            _ => break,
        }
    }
    Ok(names)
}

/// Returns None for on-demand tables (we skip those — no capacity waste to flag).
async fn describe_and_enrich(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
    name: &str,
) -> Result<Option<DynamoTable>> {
    let body = serde_json::json!({ "TableName": name }).to_string();
    let resp = ddb_call(
        client,
        creds,
        region,
        "DynamoDB_20120810.DescribeTable",
        &body,
    )
    .await?;
    let v: serde_json::Value = serde_json::from_str(&resp)
        .map_err(|e| anyhow!("DynamoDB DescribeTable parse error: {e}"))?;

    let table = &v["Table"];

    // Only ACTIVE tables are relevant
    if table["TableStatus"].as_str() != Some("ACTIVE") {
        return Ok(None);
    }

    // Billing mode — absent means PROVISIONED (legacy default)
    let billing_mode = table["BillingModeSummary"]["BillingMode"]
        .as_str()
        .unwrap_or("PROVISIONED")
        .to_string();

    // Skip on-demand tables — no fixed capacity to waste
    if billing_mode == "PAY_PER_REQUEST" {
        return Ok(None);
    }

    let provisioned_rcu = table["ProvisionedThroughput"]["ReadCapacityUnits"]
        .as_u64()
        .unwrap_or(0);
    let provisioned_wcu = table["ProvisionedThroughput"]["WriteCapacityUnits"]
        .as_u64()
        .unwrap_or(0);

    // Skip tables with 0 provisioned (shouldn't happen but guard against it)
    if provisioned_rcu == 0 && provisioned_wcu == 0 {
        return Ok(None);
    }

    // Fetch CloudWatch consumption metrics concurrently
    let dims = [("TableName", name)];
    let (rcu_res, wcu_res) = futures::join!(
        cloudwatch::get_metric_stat(
            client,
            creds,
            region,
            "AWS/DynamoDB",
            "ConsumedReadCapacityUnits",
            &dims,
            14,
            "Sum"
        ),
        cloudwatch::get_metric_stat(
            client,
            creds,
            region,
            "AWS/DynamoDB",
            "ConsumedWriteCapacityUnits",
            &dims,
            14,
            "Sum"
        ),
    );

    Ok(Some(DynamoTable {
        name: name.to_string(),
        region: region.to_string(),
        billing_mode,
        provisioned_rcu,
        provisioned_wcu,
        hourly_consumed_rcu: rcu_res.unwrap_or_default(),
        hourly_consumed_wcu: wcu_res.unwrap_or_default(),
    }))
}

// ── DynamoDB JSON API helper ──────────────────────────────────────────────────

async fn ddb_call(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
    target: &str,
    body: &str,
) -> Result<String> {
    let url = format!("https://dynamodb.{region}.amazonaws.com/");
    let creds_for_region = AwsCreds {
        region: region.to_string(),
        ..creds.clone()
    };

    let signed = sign(
        &creds_for_region,
        "POST",
        &url,
        &[("content-type", DDB_CONTENT_TYPE), ("x-amz-target", target)],
        body.as_bytes(),
        "dynamodb",
    )?;

    let mut req = client
        .post(&url)
        .header("content-type", DDB_CONTENT_TYPE)
        .header("x-amz-target", target)
        .header("x-amz-date", &signed.x_amz_date)
        .header("x-amz-content-sha256", &signed.x_amz_content_sha256)
        .header("authorization", &signed.authorization)
        .body(body.to_string());
    if let Some(t) = &signed.x_amz_security_token {
        req = req.header("x-amz-security-token", t);
    }

    let resp = req.send().await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        return Err(anyhow!(
            "DynamoDB API error {status} in {region} [{target}]: {text}"
        ));
    }
    Ok(text)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn form_params_ec2(params: &[(&str, &str)]) -> String {
    let mut p = params.to_vec();
    p.sort_by_key(|(k, _)| *k);
    p.iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}
