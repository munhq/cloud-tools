/// Cloudflare credentials — API token + account ID, passed per call.
#[derive(Debug, Clone)]
pub struct CloudflareCreds {
    pub api_token: String,
    pub account_id: String,
}
