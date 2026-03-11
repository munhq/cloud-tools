use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use super::auth::{sign, AwsCreds};

const ORG_ENDPOINT: &str = "https://organizations.us-east-1.amazonaws.com/";
const CONTENT_TYPE: &str = "application/x-amz-json-1.1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgAccount {
    pub id: String,
    pub name: String,
    pub email: String,
    pub status: String,
}

/// List all accounts in the AWS Organisation.
/// Must be called with credentials from the management account.
pub async fn list_accounts(http: &reqwest::Client, creds: &AwsCreds) -> Result<Vec<OrgAccount>> {
    let mut all = Vec::new();
    let mut next_token: Option<String> = None;

    loop {
        let (accounts, token) = list_accounts_page(http, creds, next_token.as_deref()).await?;
        all.extend(accounts);
        match token {
            Some(t) if !t.is_empty() => next_token = Some(t),
            _ => break,
        }
    }

    Ok(all)
}

async fn list_accounts_page(
    http: &reqwest::Client,
    creds: &AwsCreds,
    next_token: Option<&str>,
) -> Result<(Vec<OrgAccount>, Option<String>)> {
    let target = "AmazonOrganizationsV20161128.ListAccounts";
    let body = match next_token {
        Some(t) => serde_json::to_vec(&serde_json::json!({ "NextToken": t }))?,
        None => b"{}".to_vec(),
    };

    let signed = sign(
        creds,
        "POST",
        ORG_ENDPOINT,
        &[("content-type", CONTENT_TYPE), ("x-amz-target", target)],
        &body,
        "organizations",
    )?;

    let mut req = http
        .post(ORG_ENDPOINT)
        .header("content-type", CONTENT_TYPE)
        .header("x-amz-target", target)
        .header("x-amz-date", &signed.x_amz_date)
        .header("x-amz-content-sha256", &signed.x_amz_content_sha256)
        .header("authorization", &signed.authorization)
        .body(body);

    if let Some(token) = &signed.x_amz_security_token {
        req = req.header("x-amz-security-token", token);
    }

    let resp = req.send().await?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(anyhow!("Organizations ListAccounts {status}: {text}"));
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Response {
        accounts: Vec<RawAccount>,
        next_token: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct RawAccount {
        id: String,
        name: String,
        email: String,
        status: String,
    }

    let data: Response = resp.json().await?;
    let accounts = data
        .accounts
        .into_iter()
        .map(|a| OrgAccount {
            id: a.id,
            name: a.name,
            email: a.email,
            status: a.status,
        })
        .collect();

    Ok((accounts, data.next_token))
}
