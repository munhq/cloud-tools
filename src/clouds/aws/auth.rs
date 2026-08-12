use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Temporary AWS credentials obtained after STS AssumeRole.
/// Used internally for all API calls — never stored.
#[derive(Debug, Clone)]
pub struct AwsCreds {
    pub access_key_id: String,
    pub secret_access_key: String,
    /// Always present for assumed-role credentials.
    pub session_token: Option<String>,
    pub region: String,
}

/// Resolve ambient AWS credentials from the environment.
///
/// Priority:
/// 1. `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` env vars (Hetzner / local)
/// 2. ECS container credentials endpoint
/// 3. IMDSv2 (EC2 instance role)
///
/// These are YOUR credentials (the bot's identity), used only to call
/// `sts:AssumeRole` for each customer. They are never exposed to customers.
pub async fn ambient_credentials(client: &reqwest::Client) -> Result<AwsCreds> {
    // 1. Env vars — works on Hetzner and local dev
    if let (Ok(key), Ok(secret)) = (
        std::env::var("AWS_ACCESS_KEY_ID"),
        std::env::var("AWS_SECRET_ACCESS_KEY"),
    ) {
        return Ok(AwsCreds {
            access_key_id: key,
            secret_access_key: secret,
            session_token: std::env::var("AWS_SESSION_TOKEN").ok(),
            region: std::env::var("AWS_REGION")
                .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
                .unwrap_or_else(|_| "us-east-1".to_string()),
        });
    }

    // 2. ECS task role
    if let Ok(rel) = std::env::var("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") {
        let v: serde_json::Value = client
            .get(format!("http://169.254.170.2{rel}"))
            .send()
            .await?
            .json()
            .await?;
        return Ok(AwsCreds {
            access_key_id: v["AccessKeyId"]
                .as_str()
                .context("missing AccessKeyId")?
                .to_string(),
            secret_access_key: v["SecretAccessKey"]
                .as_str()
                .context("missing SecretAccessKey")?
                .to_string(),
            session_token: v["Token"].as_str().map(String::from),
            region: std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string()),
        });
    }

    // 3. IMDSv2 (EC2 instance role)
    let token = client
        .put("http://169.254.169.254/latest/api/token")
        .header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
        .send()
        .await?
        .text()
        .await?;
    let role = client
        .get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
        .header("X-aws-ec2-metadata-token", &token)
        .send()
        .await?
        .text()
        .await?;
    let v: serde_json::Value = client
        .get(format!(
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/{}",
            role.trim()
        ))
        .header("X-aws-ec2-metadata-token", &token)
        .send()
        .await?
        .json()
        .await?;
    Ok(AwsCreds {
        access_key_id: v["AccessKeyId"]
            .as_str()
            .context("missing AccessKeyId")?
            .to_string(),
        secret_access_key: v["SecretAccessKey"]
            .as_str()
            .context("missing SecretAccessKey")?
            .to_string(),
        session_token: v["Token"].as_str().map(String::from),
        region: "us-east-1".to_string(),
    })
}

/// Assume a customer's IAM role and return temporary credentials.
///
/// `role_arn`: the customer's role ARN, e.g. `arn:aws:iam::123456789:role/CloudToolsReadOnly`
/// `external_id`: optional extra condition on the trust policy for added security
pub async fn assume_role(
    client: &reqwest::Client,
    role_arn: &str,
    external_id: Option<&str>,
) -> Result<AwsCreds> {
    let base = ambient_credentials(client).await?;

    let mut params = vec![
        ("Action", "AssumeRole"),
        ("Version", "2011-06-15"),
        ("RoleArn", role_arn),
        ("RoleSessionName", "cloud-tools"),
        ("DurationSeconds", "3600"),
    ];
    let eid_owned;
    if let Some(eid) = external_id {
        eid_owned = eid.to_string();
        params.push(("ExternalId", eid_owned.as_str()));
    }
    params.sort_by_key(|(k, _)| *k);

    let query: String = params
        .iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    let url = format!("https://sts.amazonaws.com/?{query}");

    let signed = sign_at(
        &AwsCreds {
            access_key_id: base.access_key_id.clone(),
            secret_access_key: base.secret_access_key.clone(),
            session_token: base.session_token.clone(),
            region: "us-east-1".to_string(),
        },
        "GET",
        &url,
        &[],
        b"",
        "sts",
        &Utc::now(),
    )?;

    let mut req = client
        .get(&url)
        .header("x-amz-date", &signed.x_amz_date)
        .header("x-amz-content-sha256", &signed.x_amz_content_sha256)
        .header("authorization", &signed.authorization);
    if let Some(token) = &signed.x_amz_security_token {
        req = req.header("x-amz-security-token", token);
    }

    let resp = req.send().await.context("STS AssumeRole request failed")?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        return Err(anyhow!("STS AssumeRole failed ({status}): {body}"));
    }

    Ok(AwsCreds {
        access_key_id: extract_xml(&body, "AccessKeyId")
            .context("STS response missing AccessKeyId")?,
        secret_access_key: extract_xml(&body, "SecretAccessKey")
            .context("STS response missing SecretAccessKey")?,
        session_token: extract_xml(&body, "SessionToken"),
        region: "us-east-1".to_string(),
    })
}

fn extract_xml(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    Some(xml[start..start + xml[start..].find(&close)?].to_string())
}

/// The set of headers to add to an outgoing AWS request after signing.
///
/// Caller must attach all of these to the request in addition to whatever
/// extra headers were passed to `sign()`.
pub struct SignedHeaders {
    pub authorization: String,
    pub x_amz_date: String,
    pub x_amz_content_sha256: String,
    /// Only present when `AwsCreds::session_token` is set.
    pub x_amz_security_token: Option<String>,
}

/// Sign a request with AWS Signature Version 4.
///
/// # Arguments
/// - `method`: HTTP method in uppercase, e.g. `"POST"`
/// - `url`: full URL including scheme, e.g. `"https://ce.us-east-1.amazonaws.com/"`
/// - `extra_headers`: additional headers that will be sent and must be covered by the
///   signature, e.g. `&[("content-type", "application/x-amz-json-1.1"), ("x-amz-target", "...")]`
/// - `body`: raw request body bytes
/// - `service`: AWS service identifier, e.g. `"ce"`, `"ec2"`, `"monitoring"`
///
/// The datetime is taken from the system clock. Use `sign_at` in tests to inject
/// a fixed time and verify against AWS SigV4 test vectors.
pub fn sign(
    creds: &AwsCreds,
    method: &str,
    url: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
    service: &str,
) -> Result<SignedHeaders> {
    sign_at(
        creds,
        method,
        url,
        extra_headers,
        body,
        service,
        &Utc::now(),
    )
}

/// Same as `sign` but with an injectable datetime — use in tests.
pub fn sign_at(
    creds: &AwsCreds,
    method: &str,
    url: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
    service: &str,
    now: &DateTime<Utc>,
) -> Result<SignedHeaders> {
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string(); // "20260301T120000Z"
    let date = now.format("%Y%m%d").to_string(); // "20260301"

    let parsed = parse_url(url)?;
    let body_hash = sha256_hex(body);

    // ── Step 1: Build canonical headers ────────────────────────────────────────
    // Must include host, x-amz-date, x-amz-content-sha256, and any extras.
    // x-amz-security-token must be signed when present.
    let mut headers: Vec<(String, String)> = vec![
        ("host".into(), parsed.host.clone()),
        ("x-amz-content-sha256".into(), body_hash.clone()),
        ("x-amz-date".into(), amz_date.clone()),
    ];
    if let Some(token) = &creds.session_token {
        headers.push(("x-amz-security-token".into(), token.clone()));
    }
    for (k, v) in extra_headers {
        headers.push((k.to_lowercase(), v.trim().to_string()));
    }

    // Sort lexicographically by header name.
    headers.sort_by(|a, b| a.0.cmp(&b.0));

    // Combine values for any duplicate header names (rare but spec-required).
    // After sort, duplicates are adjacent. Keep the first occurrence, append rest.
    let mut deduped: Vec<(String, String)> = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        match deduped.last_mut() {
            Some(last) if last.0 == name => {
                last.1.push(',');
                last.1.push_str(&value);
            }
            _ => deduped.push((name, value)),
        }
    }

    // "name:value\n" for each header, all concatenated
    let canonical_headers: String = deduped.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();

    // "name1;name2;name3"
    let signed_headers: String = deduped
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");

    // ── Step 2: Canonical request ───────────────────────────────────────────────
    // Note: canonical_headers already ends with \n, so the extra \n produces
    // the required blank line between headers and signed-headers.
    let canonical_request = format!(
        "{method}\n{}\n{}\n{canonical_headers}\n{signed_headers}\n{body_hash}",
        parsed.path, parsed.canonical_query,
    );

    // ── Step 3: String to sign ──────────────────────────────────────────────────
    let credential_scope = format!("{date}/{}/{service}/aws4_request", creds.region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
        sha256_hex(canonical_request.as_bytes()),
    );

    // ── Step 4: Derive signing key and sign ─────────────────────────────────────
    let signing_key = derive_signing_key(&creds.secret_access_key, &date, &creds.region, service);
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
        creds.access_key_id,
    );

    Ok(SignedHeaders {
        authorization,
        x_amz_date: amz_date,
        x_amz_content_sha256: body_hash,
        x_amz_security_token: creds.session_token.clone(),
    })
}

// ── Crypto helpers ──────────────────────────────────────────────────────────────

fn derive_signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

// ── URL parsing ─────────────────────────────────────────────────────────────────

struct ParsedUrl {
    host: String,
    path: String,
    /// Already sorted and percent-encoded per SigV4 spec.
    canonical_query: String,
}

fn parse_url(url: &str) -> Result<ParsedUrl> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or_else(|| anyhow!("URL must have http(s) scheme: {url}"))?;

    let (authority, path_and_query) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };

    // Strip port from host for the Host header value (standard HTTPS = port 443,
    // which is omitted per SigV4 spec).
    let host = match authority.rfind(':') {
        Some(i) if authority[i + 1..].parse::<u16>().is_ok() => &authority[..i],
        _ => authority,
    };

    let (path, query_str) = match path_and_query.find('?') {
        Some(i) => (&path_and_query[..i], &path_and_query[i + 1..]),
        None => (path_and_query, ""),
    };

    // Canonical query string: sort params by encoded key, then encoded value.
    let canonical_query = if query_str.is_empty() {
        String::new()
    } else {
        let mut pairs: Vec<(String, String)> = query_str
            .split('&')
            .filter(|p| !p.is_empty())
            .map(|p| {
                let (k, v) = p.split_once('=').unwrap_or((p, ""));
                (
                    urlencoding::encode(k).into_owned(),
                    urlencoding::encode(v).into_owned(),
                )
            })
            .collect();
        pairs.sort();
        pairs
            .into_iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&")
    };

    Ok(ParsedUrl {
        host: host.to_string(),
        path: path.to_string(),
        canonical_query,
    })
}

// ── Tests ───────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn test_creds() -> AwsCreds {
        AwsCreds {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
            region: "us-east-1".into(),
        }
    }

    fn fixed_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 3, 1, 12, 0, 0).unwrap()
    }

    // SHA256("") is a well-known constant — verifies our hash function is correct.
    #[test]
    fn sha256_empty_body() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn parse_simple_url() {
        let p = parse_url("https://ce.us-east-1.amazonaws.com/").unwrap();
        assert_eq!(p.host, "ce.us-east-1.amazonaws.com");
        assert_eq!(p.path, "/");
        assert_eq!(p.canonical_query, "");
    }

    #[test]
    fn parse_url_with_query_sorts_params() {
        let p = parse_url(
            "https://ec2.us-east-1.amazonaws.com/?Version=2016-11-15&Action=DescribeInstances",
        )
        .unwrap();
        // Sorted: Action before Version
        assert!(p.canonical_query.starts_with("Action="));
        assert!(p.canonical_query.contains("&Version="));
    }

    #[test]
    fn parse_url_strips_default_port() {
        let p = parse_url("https://ce.us-east-1.amazonaws.com:443/").unwrap();
        assert_eq!(p.host, "ce.us-east-1.amazonaws.com");
    }

    #[test]
    fn sign_produces_valid_authorization_header() {
        let result = sign_at(
            &test_creds(),
            "POST",
            "https://ce.us-east-1.amazonaws.com/",
            &[
                ("content-type", "application/x-amz-json-1.1"),
                ("x-amz-target", "AWSInsightsIndexService.GetCostAndUsage"),
            ],
            b"{}",
            "ce",
            &fixed_time(),
        )
        .unwrap();

        assert!(result.authorization.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20260301/us-east-1/ce/aws4_request"
        ));
        assert!(result.authorization.contains("SignedHeaders="));
        assert!(result.authorization.contains("Signature="));
        assert_eq!(result.x_amz_date, "20260301T120000Z");
        assert!(result.x_amz_security_token.is_none());
    }

    #[test]
    fn sign_includes_session_token_in_headers() {
        let mut creds = test_creds();
        creds.session_token = Some("AQoToken".into());

        let result = sign_at(
            &creds,
            "POST",
            "https://sts.amazonaws.com/",
            &[("content-type", "application/x-amz-json-1.1")],
            b"",
            "sts",
            &fixed_time(),
        )
        .unwrap();

        // x-amz-security-token must be in both SignedHeaders and the returned struct
        assert!(result.authorization.contains("x-amz-security-token"));
        assert_eq!(result.x_amz_security_token.as_deref(), Some("AQoToken"));
    }

    #[test]
    fn signed_headers_are_sorted() {
        let result = sign_at(
            &test_creds(),
            "POST",
            "https://ec2.us-east-1.amazonaws.com/",
            &[("content-type", "application/x-www-form-urlencoded")],
            b"Action=DescribeInstances&Version=2016-11-15",
            "ec2",
            &fixed_time(),
        )
        .unwrap();

        // Extract signed headers from authorization string
        let sh_start =
            result.authorization.find("SignedHeaders=").unwrap() + "SignedHeaders=".len();
        let sh_end = result.authorization.find(", Signature=").unwrap();
        let signed_headers = &result.authorization[sh_start..sh_end];

        // Verify lexicographic order
        let names: Vec<&str> = signed_headers.split(';').collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
    }
}
