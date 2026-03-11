use chrono::Utc;
use reqwest::Client;
use sha1::{Digest, Sha1};

#[derive(Debug, Clone)]
pub struct OvhCreds {
    pub app_key: String,
    pub app_secret: String,
    pub consumer_key: String,
    /// "ovh-eu" | "ovh-us" | "ovh-ca"
    pub endpoint: String,
}

impl OvhCreds {
    pub fn base_url(&self) -> &'static str {
        match self.endpoint.as_str() {
            "ovh-us" => "https://api.us.ovhcloud.com/1.0",
            "ovh-ca" => "https://ca.api.ovh.com/1.0",
            _ => "https://eu.api.ovh.com/1.0",
        }
    }

    pub fn sign(&self, method: &str, url: &str, body: &str, ts: i64) -> String {
        let pre = format!(
            "{}+{}+{}+{}+{}+{}",
            self.app_secret, self.consumer_key, method, url, body, ts
        );
        let mut hasher = Sha1::new();
        hasher.update(pre.as_bytes());
        format!("$1${:x}", hasher.finalize())
    }
}

pub async fn get(http: &Client, creds: &OvhCreds, path: &str) -> anyhow::Result<serde_json::Value> {
    let ts = Utc::now().timestamp();
    let url = format!("{}{path}", creds.base_url());
    let sig = creds.sign("GET", &url, "", ts);
    let resp = http
        .get(&url)
        .header("X-Ovh-Application", &creds.app_key)
        .header("X-Ovh-Consumer", &creds.consumer_key)
        .header("X-Ovh-Timestamp", ts.to_string())
        .header("X-Ovh-Signature", sig)
        .send()
        .await?;
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!(
            "OVH GET {path} ({}): {}",
            resp.status(),
            resp.text().await?
        ));
    }
    Ok(resp.json().await?)
}
