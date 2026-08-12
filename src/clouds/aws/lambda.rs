use anyhow::{anyhow, Result};
use futures::future::join_all;
use serde::Deserialize;

use super::{
    as_items,
    auth::{sign, AwsCreds},
    cloudwatch, xml_to_value,
};

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LambdaFunction {
    pub name: String,
    pub arn: String,
    pub runtime: String,
    pub memory_mb: u32,
    pub region: String,
    /// Total invocations in the last 30 days (None = no CloudWatch data yet).
    pub invocations_30d: Option<u64>,
    /// Average execution duration in ms over last 30 days.
    pub avg_duration_ms: Option<f64>,
    /// Total errors in the last 30 days.
    pub errors_30d: Option<u64>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// List all Lambda functions across all regions, enriched with 30-day CloudWatch metrics.
pub async fn list_functions(
    client: &reqwest::Client,
    creds: &AwsCreds,
) -> Result<Vec<LambdaFunction>> {
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

// ── Per-region function listing ───────────────────────────────────────────────

async fn list_in_region(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
) -> Result<Vec<LambdaFunction>> {
    let mut out = Vec::new();
    let mut next_marker: Option<String> = None;

    loop {
        let url = match &next_marker {
            Some(m) => format!(
                "https://lambda.{region}.amazonaws.com/2015-03-31/functions?MaxItems=50&Marker={}",
                urlencoding::encode(m)
            ),
            None => {
                format!("https://lambda.{region}.amazonaws.com/2015-03-31/functions?MaxItems=50")
            }
        };

        let creds_for_region = AwsCreds {
            region: region.to_string(),
            ..creds.clone()
        };
        let signed = sign(&creds_for_region, "GET", &url, &[], b"", "lambda")?;

        let mut req = client
            .get(&url)
            .header("x-amz-date", &signed.x_amz_date)
            .header("x-amz-content-sha256", &signed.x_amz_content_sha256)
            .header("authorization", &signed.authorization);
        if let Some(t) = &signed.x_amz_security_token {
            req = req.header("x-amz-security-token", t);
        }

        let resp = req.send().await?;
        let status = resp.status();
        // Lambda not available in opt-in regions that haven't been enabled
        if status.as_u16() == 404 {
            break;
        }
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(anyhow!(
                "Lambda ListFunctions error {status} in {region}: {text}"
            ));
        }

        let data: ListFunctionsResponse = serde_json::from_str(&text)
            .map_err(|e| anyhow!("Lambda parse error in {region}: {e}"))?;

        // Enrich each function with CloudWatch metrics concurrently
        let enrich_tasks: Vec<_> = data
            .functions
            .into_iter()
            .map(|f| {
                let client = client.clone();
                let creds = creds.clone();
                let region = region.to_string();
                async move { enrich(&client, &creds, &region, f).await }
            })
            .collect();

        let enriched = join_all(enrich_tasks).await;
        out.extend(enriched.into_iter().filter_map(|r| r.ok()));

        match data.next_marker {
            Some(m) if !m.is_empty() => next_marker = Some(m),
            _ => break,
        }
    }
    Ok(out)
}

async fn enrich(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
    func: FunctionConfig,
) -> Result<LambdaFunction> {
    let name = func.function_name.as_str();
    let dims = [("FunctionName", name)];

    let (inv_res, dur_res, err_res) = futures::join!(
        cloudwatch::get_metric_stat(
            client,
            creds,
            region,
            "AWS/Lambda",
            "Invocations",
            &dims,
            30,
            "Sum"
        ),
        cloudwatch::get_metric_stat(
            client,
            creds,
            region,
            "AWS/Lambda",
            "Duration",
            &dims,
            30,
            "Average"
        ),
        cloudwatch::get_metric_stat(
            client,
            creds,
            region,
            "AWS/Lambda",
            "Errors",
            &dims,
            30,
            "Sum"
        ),
    );

    let invocations_30d = inv_res.ok().map(|v| v.iter().sum::<f64>() as u64);
    let avg_duration_ms = dur_res.ok().and_then(|v| {
        if v.is_empty() {
            None
        } else {
            Some(v.iter().sum::<f64>() / v.len() as f64)
        }
    });
    let errors_30d = err_res.ok().map(|v| v.iter().sum::<f64>() as u64);

    Ok(LambdaFunction {
        name: func.function_name,
        arn: func.function_arn,
        runtime: func.runtime.unwrap_or_else(|| "unknown".into()),
        memory_mb: func.memory_size.unwrap_or(128),
        region: region.to_string(),
        invocations_30d,
        avg_duration_ms,
        errors_30d,
    })
}

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListFunctionsResponse {
    #[serde(default)]
    functions: Vec<FunctionConfig>,
    next_marker: Option<String>,
}

#[derive(Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
struct FunctionConfig {
    function_name: String,
    #[serde(default)]
    function_arn: String,
    runtime: Option<String>,
    memory_size: Option<u32>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn form_params(params: &[(&str, &str)]) -> String {
    let mut p = params.to_vec();
    p.sort_by_key(|(k, _)| *k);
    p.iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}
