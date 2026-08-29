use anyhow::{Context, Result};
use chrono::Utc;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct GcpCreds {
    /// JSON credentials — can be a service account key or ADC authorized_user JSON.
    /// Left empty when using ADC from the well-known file location.
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

impl GcpCreds {
    /// Construct credentials from Application Default Credentials (ADC).
    ///
    /// Reads from `GOOGLE_APPLICATION_CREDENTIALS` env var, or the well-known
    /// gcloud ADC path (`~/.config/gcloud/application_default_credentials.json`).
    pub fn from_adc(project_id: &str) -> Result<Self> {
        let json = read_adc_file()?;
        Ok(Self {
            service_account_json: json,
            project_id: project_id.to_string(),
            billing_account_id: String::new(),
            billing_table: None,
            organization_id: None,
        })
    }
}

/// Read the ADC credentials file from the well-known location.
fn read_adc_file() -> Result<String> {
    // 1. Check GOOGLE_APPLICATION_CREDENTIALS env var
    if let Ok(path) = std::env::var("GOOGLE_APPLICATION_CREDENTIALS") {
        return std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read GOOGLE_APPLICATION_CREDENTIALS at {path}"));
    }

    // 2. Well-known gcloud ADC path
    let home = std::env::var("HOME").context("HOME not set")?;
    let path = format!("{home}/.config/gcloud/application_default_credentials.json");
    std::fs::read_to_string(&path).with_context(|| {
        "no ADC credentials found — run `gcloud auth application-default login` \
             or set GOOGLE_APPLICATION_CREDENTIALS"
            .to_string()
    })
}

#[derive(Deserialize)]
struct ServiceAccountKey {
    client_email: String,
    private_key: String,
}

#[derive(Deserialize)]
struct AuthorizedUserKey {
    client_id: String,
    client_secret: String,
    refresh_token: String,
}

#[derive(Serialize)]
struct Claims {
    iss: String,
    scope: String,
    aud: String,
    iat: i64,
    exp: i64,
}

/// Get an access token from the credentials in `GcpCreds`.
///
/// Detects the credential type automatically:
/// - `"type": "service_account"` → JWT assertion flow (existing path)
/// - `"type": "authorized_user"` → refresh token flow (ADC from `gcloud auth`)
/// - empty string → reads ADC from the well-known file location
pub async fn access_token(http: &Client, creds: &GcpCreds) -> Result<String> {
    let json_str = if creds.service_account_json.is_empty() {
        read_adc_file()?
    } else {
        creds.service_account_json.clone()
    };

    let parsed: serde_json::Value =
        serde_json::from_str(&json_str).context("invalid GCP credentials JSON")?;

    match parsed["type"].as_str() {
        Some("authorized_user") => adc_refresh_token(http, &json_str).await,
        _ => sa_jwt_token(http, &json_str).await,
    }
}

/// Pull the access token out of an OAuth response, or report why there is none.
///
/// Both flows below used `.context("missing access_token")`, which is true and
/// useless: the token endpoint answers 400 with `error` and `error_description`
/// naming the actual cause, and those two fields are the difference between
/// "something went wrong" and "run `gcloud auth application-default login`".
/// An expired ADC reauth reads as `invalid_grant: reauth related error
/// (invalid_rapt)`, which says exactly what to do.
fn token_from(resp: &serde_json::Value, flow: &str) -> Result<String> {
    if let Some(token) = resp["access_token"].as_str() {
        return Ok(token.to_string());
    }
    let err = resp["error"].as_str().unwrap_or("unknown_error");
    let detail = resp["error_description"]
        .as_str()
        .unwrap_or("no description");
    let hint = match err {
        "invalid_grant" => {
            " — the credentials are expired or revoked. Run `gcloud auth application-default login`."
        }
        "invalid_client" => " — the client_id or client_secret in the credentials file is wrong.",
        _ => "",
    };
    anyhow::bail!("GCP {flow} failed: {err}: {detail}{hint}")
}

/// Service account JWT assertion flow.
async fn sa_jwt_token(http: &Client, json_str: &str) -> Result<String> {
    let sa: ServiceAccountKey =
        serde_json::from_str(json_str).context("invalid GCP service account JSON")?;

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

    token_from(&resp, "service account sign-in")
}

/// ADC authorized_user refresh token flow.
async fn adc_refresh_token(http: &Client, json_str: &str) -> Result<String> {
    let user: AuthorizedUserKey =
        serde_json::from_str(json_str).context("invalid ADC authorized_user JSON")?;

    let resp: serde_json::Value = http
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", &user.client_id),
            ("client_secret", &user.client_secret),
            ("refresh_token", &user.refresh_token),
        ])
        .send()
        .await?
        .json()
        .await?;

    token_from(&resp, "ADC token refresh")
}
