pub mod auth;
pub mod ce;
pub mod cloudwatch;
pub mod cloudwatch_logs;
pub mod compute_optimizer;
pub mod dynamodb;
pub mod ec2;
pub mod ecs;
pub mod elasticache;
pub mod elb;
pub mod lambda;
pub mod nat_gateway;
pub mod organizations;
pub mod pricing;
pub mod pricing_api;
pub mod rds;
pub mod s3;

// ── Shared XML helpers used across all AWS modules ────────────────────────────

/// Convert an AWS XML response body into a serde_json::Value tree.
/// Single-child elements stay as objects; repeated tags become arrays.
pub(crate) fn xml_to_value(xml: &str) -> anyhow::Result<serde_json::Value> {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;
    use std::collections::HashMap;

    fn node(reader: &mut Reader<&[u8]>, buf: &mut Vec<u8>) -> anyhow::Result<serde_json::Value> {
        let mut map: HashMap<String, Vec<serde_json::Value>> = HashMap::new();
        let mut text = String::new();
        loop {
            buf.clear();
            match reader.read_event_into(buf) {
                Ok(Event::Start(e)) => {
                    let name = std::str::from_utf8(e.local_name().into_inner())?.to_string();
                    let child = node(reader, buf)?;
                    map.entry(name).or_default().push(child);
                }
                Ok(Event::Text(e)) => text = e.unescape()?.to_string(),
                Ok(Event::End(_)) | Ok(Event::Eof) => break,
                Err(e) => return Err(anyhow::anyhow!("XML: {e}")),
                _ => {}
            }
        }
        if map.is_empty() {
            return Ok(serde_json::Value::String(text));
        }
        Ok(serde_json::Value::Object(
            map.into_iter()
                .map(|(k, mut v)| {
                    (
                        k,
                        if v.len() == 1 {
                            v.remove(0)
                        } else {
                            serde_json::Value::Array(v)
                        },
                    )
                })
                .collect(),
        ))
    }

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    node(&mut reader, &mut Vec::new())
}

/// Normalise a field that AWS returns as either a single object or an array of items.
pub(crate) fn as_items(v: &serde_json::Value) -> Vec<serde_json::Value> {
    match v {
        serde_json::Value::Array(a) => a.clone(),
        serde_json::Value::Object(_) => vec![v.clone()],
        _ => vec![],
    }
}

/// Derive region name from availability zone: "us-east-1a" → "us-east-1".
pub(crate) fn az_to_region(az: &str) -> String {
    let chars: Vec<char> = az.chars().collect();
    if chars.len() >= 2
        && chars.last().map(|c| c.is_alphabetic()).unwrap_or(false)
        && chars[chars.len() - 2].is_ascii_digit()
    {
        chars[..chars.len() - 1].iter().collect()
    } else {
        az.to_string()
    }
}

/// Extract the first text value of a named XML tag (simple cases only).
#[allow(dead_code)]
pub(crate) fn xml_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    Some(xml[start..start + xml[start..].find(&close)?].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn az_to_region_strips_suffix() {
        assert_eq!(az_to_region("us-east-1a"), "us-east-1");
        assert_eq!(az_to_region("eu-west-1b"), "eu-west-1");
        assert_eq!(az_to_region("ap-southeast-2c"), "ap-southeast-2");
        assert_eq!(az_to_region("us-east-1"), "us-east-1"); // no suffix, unchanged
    }
}
