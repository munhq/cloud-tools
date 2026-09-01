//! The plumbing every AWS service module needs, written once.
//!
//! Before this existed, `list_regions` had ELEVEN definitions across the tree
//! and `form_params` had ten. The copies were not even consistent with each
//! other — six distinct implementations of the region lister, ranging from 9 to
//! 33 lines, three of them inlining the request signing that the other three had
//! already factored out.
//!
//! They all *behaved* the same, which is why nothing caught it. What it cost was
//! extension: adding one service meant a twelfth copy, and adding an inventory
//! surface over the same services meant a dozen more.
//!
//! It also cost every scan. Eight modules each called DescribeRegions
//! independently, so one `get_waste` against AWS opened eight identical
//! round-trips before doing any work. `list_regions` here answers the first
//! caller and hands every later one the cached list.

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use super::auth::{sign, AwsCreds};
use super::{as_items, xml_to_value};

/// Canonical query-string encoding for the AWS Query APIs.
///
/// Sorted by key, because SigV4 signs the body and the signature must match the
/// bytes sent. Ten copies of this existed; seven were byte-identical and the
/// other three differed only by a type annotation and a name.
pub(crate) fn form_params(params: &[(&str, &str)]) -> String {
    let mut p = params.to_vec();
    p.sort_by_key(|(k, _)| *k);
    p.iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// A signed POST to the EC2 Query API in one region.
///
/// Several service modules reach the EC2 API — for regions, instances, volumes,
/// NAT gateways — and each had its own copy of this signing dance.
pub(crate) async fn ec2_query(
    client: &reqwest::Client,
    creds: &AwsCreds,
    region: &str,
    body: &str,
) -> Result<String> {
    let url = format!("https://ec2.{region}.amazonaws.com/");
    // The signature is region-scoped, so it is signed for the region being
    // called rather than whatever region the credentials were resolved with.
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
        "ec2",
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
        return Err(anyhow!("EC2 API error {status} in {region}: {text}"));
    }
    Ok(text)
}

/// Cached region lists, keyed by access key id.
///
/// NOT a single global list. DescribeRegions returns the regions enabled for the
/// calling ACCOUNT, and this server assumes a different role per account, so one
/// shared list would report account A's regions while scanning account B. The
/// access key id identifies the credential set, and assumed-role credentials are
/// temporary, so entries fall out of use naturally.
fn region_cache() -> &'static Mutex<HashMap<String, Vec<String>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Vec<String>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Every region enabled for this account.
///
/// The first caller in a scan performs the request; the rest read the cache. A
/// waste scan touches eight service modules, so this is eight round-trips saved
/// per scan rather than a micro-optimisation.
pub(crate) async fn list_regions(
    client: &reqwest::Client,
    creds: &AwsCreds,
) -> Result<Vec<String>> {
    let key = creds.access_key_id.clone();

    // Scoped so the lock is released before the await below: holding a std Mutex
    // across an await point would make this future non-Send and can deadlock.
    if let Some(hit) = region_cache()
        .lock()
        .ok()
        .and_then(|c| c.get(&key).cloned())
    {
        return Ok(hit);
    }

    let body = form_params(&[("Action", "DescribeRegions"), ("Version", "2016-11-15")]);
    let xml = ec2_query(client, creds, "us-east-1", &body).await?;
    let v = xml_to_value(&xml)?;
    let regions: Vec<String> = as_items(&v["regionInfo"]["item"])
        .into_iter()
        .filter_map(|r| r["regionName"].as_str().map(String::from))
        .collect();

    if regions.is_empty() {
        return Err(anyhow!(
            "DescribeRegions returned no regions. The credentials may lack \
             ec2:DescribeRegions, which every multi-region scan needs."
        ));
    }

    if let Ok(mut c) = region_cache().lock() {
        c.insert(key, regions.clone());
    }
    Ok(regions)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SigV4 signs the body, so the encoding must be stable and sorted or the
    /// signature will not match what was sent.
    #[test]
    fn form_params_sorts_by_key_and_encodes() {
        let s = form_params(&[("Version", "2016-11-15"), ("Action", "DescribeRegions")]);
        assert_eq!(s, "Action=DescribeRegions&Version=2016-11-15");
    }

    #[test]
    fn form_params_percent_encodes_reserved_characters() {
        let s = form_params(&[("Filter.1.Value", "a b/c&d")]);
        assert_eq!(s, "Filter.1.Value=a%20b%2Fc%26d");
    }

    /// The cache must be per credential set. A single global list would report
    /// one account's regions while scanning another.
    #[test]
    fn the_region_cache_is_keyed_per_credential() {
        let cache = region_cache();
        {
            let mut c = cache.lock().unwrap();
            c.insert("AKIA_ACCOUNT_A".into(), vec!["eu-west-1".into()]);
            c.insert(
                "AKIA_ACCOUNT_B".into(),
                vec!["us-east-1".into(), "ap-south-1".into()],
            );
        }
        let c = cache.lock().unwrap();
        assert_eq!(
            c.get("AKIA_ACCOUNT_A").unwrap(),
            &vec!["eu-west-1".to_string()]
        );
        assert_eq!(c.get("AKIA_ACCOUNT_B").unwrap().len(), 2);
        assert!(c.get("AKIA_UNKNOWN").is_none());
    }
}
