//! Google Cloud VPN gateway and tunnel inventory.
//!
//! Uses aggregatedList for both vpnGateways and vpnTunnels. Falls back to
//! iterating regions if aggregatedList returns 404.
//! Pricing: ~$37/mo per VPN gateway ($0.05/hr for both Classic and HA VPN).

use anyhow::Result;
use reqwest::Client;

use super::auth::{access_token, GcpCreds};
use super::common::list_regions;

#[derive(Debug, Clone)]
pub struct CloudVpn {
    pub gateway_name: String,
    pub region: String,
    pub tunnel_count: u32,
    pub tunnels: Vec<VpnTunnel>,
}

#[derive(Debug, Clone)]
pub struct VpnTunnel {
    pub name: String,
    pub status: String, // "ESTABLISHED", "NO_INCOMING_PACKETS", etc.
    pub peer_ip: String,
    pub ike_version: u32,
}

pub async fn list_vpn_gateways(http: &Client, creds: &GcpCreds) -> Result<Vec<CloudVpn>> {
    let token = access_token(http, creds).await?;
    let project = &creds.project_id;

    // Fetch gateways and tunnels in parallel
    let (gateways, tunnels) = futures::future::try_join(
        fetch_gateways(http, &token, project),
        fetch_tunnels(http, &token, project),
    )
    .await?;

    // Build a map of gateway self_link -> CloudVpn, then attach tunnels
    let mut vpn_map: std::collections::HashMap<String, CloudVpn> = std::collections::HashMap::new();

    for (self_link, gw_name, region) in &gateways {
        vpn_map.insert(
            self_link.clone(),
            CloudVpn {
                gateway_name: gw_name.clone(),
                region: region.clone(),
                tunnel_count: 0,
                tunnels: Vec::new(),
            },
        );
    }

    // Attach tunnels to their parent gateway
    for (tunnel_name, status, peer_ip, ike_version, vpn_gateway_link, tunnel_region) in &tunnels {
        let tunnel = VpnTunnel {
            name: tunnel_name.clone(),
            status: status.clone(),
            peer_ip: peer_ip.clone(),
            ike_version: *ike_version,
        };

        if let Some(vpn) = vpn_map.get_mut(vpn_gateway_link.as_str()) {
            vpn.tunnel_count += 1;
            vpn.tunnels.push(tunnel);
        } else {
            // Tunnel exists but gateway wasn't found (Classic VPN or orphaned) --
            // create a synthetic gateway entry keyed by the gateway link
            let gw_name = vpn_gateway_link
                .rsplit('/')
                .next()
                .unwrap_or("unknown")
                .to_string();
            let entry = vpn_map
                .entry(vpn_gateway_link.clone())
                .or_insert_with(|| CloudVpn {
                    gateway_name: gw_name,
                    region: tunnel_region.clone(),
                    tunnel_count: 0,
                    tunnels: Vec::new(),
                });
            entry.tunnel_count += 1;
            entry.tunnels.push(tunnel);
        }
    }

    Ok(vpn_map.into_values().collect())
}

/// Returns Vec<(self_link, name, region)>
async fn fetch_gateways(
    http: &Client,
    token: &str,
    project: &str,
) -> Result<Vec<(String, String, String)>> {
    let url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{project}/aggregatedList/vpnGateways?maxResults=500"
    );
    let resp = http.get(&url).bearer_auth(token).send().await?;
    let status = resp.status();

    if status.as_u16() == 404 {
        // aggregatedList not available -- fall back to region iteration
        return fetch_gateways_by_region(http, token, project).await;
    }
    if !status.is_success() {
        return Ok(Vec::new());
    }

    let data: serde_json::Value = resp.json().await?;
    let mut out = Vec::new();

    for (_key, region_data) in data["items"].as_object().cloned().unwrap_or_default() {
        for gw in region_data["vpnGateways"]
            .as_array()
            .cloned()
            .unwrap_or_default()
        {
            let self_link = gw["selfLink"].as_str().unwrap_or("").to_string();
            let name = gw["name"].as_str().unwrap_or("").to_string();
            let region = gw["region"]
                .as_str()
                .and_then(|r| r.rsplit('/').next())
                .unwrap_or("")
                .to_string();
            out.push((self_link, name, region));
        }
    }
    Ok(out)
}

/// Fallback: iterate regions to find VPN gateways.
async fn fetch_gateways_by_region(
    http: &Client,
    token: &str,
    project: &str,
) -> Result<Vec<(String, String, String)>> {
    let regions = list_regions(http, token, project).await?;
    let futs: Vec<_> = regions
        .iter()
        .map(|region| {
            let url = format!(
                "https://compute.googleapis.com/compute/v1/projects/{project}/regions/{region}/vpnGateways"
            );
            let token = token.to_string();
            let region = region.clone();
            async move {
                let resp = http.get(&url).bearer_auth(&token).send().await?;
                if !resp.status().is_success() {
                    return Ok::<Vec<(String, String, String)>, anyhow::Error>(Vec::new());
                }
                let data: serde_json::Value = resp.json().await?;
                let mut out = Vec::new();
                for gw in data["items"].as_array().cloned().unwrap_or_default() {
                    let self_link = gw["selfLink"].as_str().unwrap_or("").to_string();
                    let name = gw["name"].as_str().unwrap_or("").to_string();
                    out.push((self_link, name, region.clone()));
                }
                Ok(out)
            }
        })
        .collect();

    let results = futures::future::join_all(futs).await;
    let mut out = Vec::new();
    for result in results {
        out.extend(result?);
    }
    Ok(out)
}

/// Returns Vec<(name, status, peer_ip, ike_version, vpn_gateway_link, region)>
async fn fetch_tunnels(
    http: &Client,
    token: &str,
    project: &str,
) -> Result<Vec<(String, String, String, u32, String, String)>> {
    let url = format!(
        "https://compute.googleapis.com/compute/v1/projects/{project}/aggregatedList/vpnTunnels?maxResults=500"
    );
    let resp = http.get(&url).bearer_auth(token).send().await?;
    let status = resp.status();

    if status.as_u16() == 404 {
        return fetch_tunnels_by_region(http, token, project).await;
    }
    if !status.is_success() {
        return Ok(Vec::new());
    }

    let data: serde_json::Value = resp.json().await?;
    let mut out = Vec::new();

    for (_key, region_data) in data["items"].as_object().cloned().unwrap_or_default() {
        for tun in region_data["vpnTunnels"]
            .as_array()
            .cloned()
            .unwrap_or_default()
        {
            out.push(parse_tunnel(&tun));
        }
    }
    Ok(out)
}

/// Fallback: iterate regions to find VPN tunnels.
async fn fetch_tunnels_by_region(
    http: &Client,
    token: &str,
    project: &str,
) -> Result<Vec<(String, String, String, u32, String, String)>> {
    let regions = list_regions(http, token, project).await?;
    let futs: Vec<_> = regions
        .iter()
        .map(|region| {
            let url = format!(
                "https://compute.googleapis.com/compute/v1/projects/{project}/regions/{region}/vpnTunnels"
            );
            let token = token.to_string();
            async move {
                let resp = http.get(&url).bearer_auth(&token).send().await?;
                if !resp.status().is_success() {
                    return Ok::<Vec<(String, String, String, u32, String, String)>, anyhow::Error>(
                        Vec::new(),
                    );
                }
                let data: serde_json::Value = resp.json().await?;
                let mut out = Vec::new();
                for tun in data["items"].as_array().cloned().unwrap_or_default() {
                    out.push(parse_tunnel(&tun));
                }
                Ok(out)
            }
        })
        .collect();

    let results = futures::future::join_all(futs).await;
    let mut out = Vec::new();
    for result in results {
        out.extend(result?);
    }
    Ok(out)
}

fn parse_tunnel(tun: &serde_json::Value) -> (String, String, String, u32, String, String) {
    let name = tun["name"].as_str().unwrap_or("").to_string();
    let status = tun["status"].as_str().unwrap_or("UNKNOWN").to_string();
    let peer_ip = tun["peerIp"].as_str().unwrap_or("").to_string();
    let ike_version = tun["ikeVersion"].as_u64().unwrap_or(2) as u32;
    // HA VPN uses "vpnGateway", Classic VPN uses "targetVpnGateway"
    let vpn_gateway = tun["vpnGateway"]
        .as_str()
        .or_else(|| tun["targetVpnGateway"].as_str())
        .unwrap_or("")
        .to_string();
    let region = tun["region"]
        .as_str()
        .and_then(|r| r.rsplit('/').next())
        .unwrap_or("")
        .to_string();
    (name, status, peer_ip, ike_version, vpn_gateway, region)
}
