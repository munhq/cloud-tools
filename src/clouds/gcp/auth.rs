use anyhow::{Context, Result};
use chrono::Utc;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct GcpCreds {
    pub service_account_json: String,
    pub project_id: String,
    pub billing_account_id: String,
    /// Optional: fully qualified BigQuery table for billing export.
    /// Format: `project.dataset.table` (e.g. `my-project.billing.gcp_billing_export_v1_XXXX`).
    /// When set, enables real cost breakdown by service (equivalent to AWS Cost Explorer).
    pub billing_table: Option<String>,
    /// Optional: GCP organization ID for multi-project scanning.
    pub organization_id: Option<String>,
}

#[derive(Deserialize)]
struct ServiceAccountKey {
    client_email: String,
    private_key: String,
}

#[derive(Serialize)]
struct Claims {
    iss: String,
    scope: String,
    aud: String,
    iat: i64,
    exp: i64,
}

pub async fn access_token(http: &Client, creds: &GcpCreds) -> Result<String> {
    let sa: ServiceAccountKey = serde_json::from_str(&creds.service_account_json)
        .context("invalid GCP service account JSON")?;

    let now = Utc::now().timestamp();
    let claims = Claims {
        iss: sa.client_email,
        scope: "https://www.googleapis.com/auth/cloud-platform \
                https://www.googleapis.com/auth/billing.readonly"
            .into(),
        aud: "https://oauth2.googleapis.com/token".into(),
        iat: now,
        exp: now + 3600,
    };

    let key = EncodingKey::from_rsa_pem(sa.private_key.as_bytes())
        .context("invalid RSA private key in GCP service account")?;
    let jwt = encode(&Header::new(Algorithm::RS256), &claims, &key)?;

    let resp: serde_json::Value = http
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &jwt),
        ])
        .send()
        .await?
        .json()
        .await?;

    resp["access_token"]
        .as_str()
        .map(String::from)
        .context("GCP: missing access_token in response")
}
