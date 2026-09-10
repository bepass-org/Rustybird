use anyhow::{Context, Result, anyhow};
use std::time::Duration;
use url::Url;

use crate::config::profile::Subscription;
use crate::parser::clash::parse_clash_yaml;
use crate::parser::node::ProxyNode;
use crate::parser::uri::{decode_b64, parse_proxy_uri};

const MAX_SUBSCRIPTION_BYTES: usize = 8 * 1024 * 1024;
pub const USER_AGENT: &str = "sing-box/1.13.0 ClashMeta/1.18.0 RustyBird/0.2.0";

pub struct SubscriptionFetchResult {
    pub nodes: Vec<ProxyNode>,
    pub total_traffic: Option<u64>,
    pub used_traffic: Option<u64>,
    pub expire_time: Option<chrono::DateTime<chrono::Utc>>,
}

pub fn validate_subscription_url(raw: &str) -> Result<Url> {
    let url = Url::parse(raw.trim()).context("invalid subscription URL")?;
    match url.scheme() {
        "https" => Ok(url),
        "http" => Err(anyhow!(
            "refusing plain http subscription; use an https:// URL so the node list cannot be tampered with"
        )),
        other => Err(anyhow!("unsupported subscription scheme: {}", other)),
    }
}

pub async fn fetch_subscription(sub: &Subscription) -> Result<SubscriptionFetchResult> {
    let url = validate_subscription_url(&sub.url)?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .user_agent(USER_AGENT)
        .build()?;

    let response = client.get(url).send().await?;
    let status = response.status();
    if !status.is_success() {
        return Err(anyhow!("subscription server returned {}", status));
    }

    let user_info = response
        .headers()
        .get("subscription-userinfo")
        .and_then(|value| value.to_str().ok())
        .map(parse_user_info)
        .unwrap_or_default();

    let bytes = response.bytes().await?;
    if bytes.len() > MAX_SUBSCRIPTION_BYTES {
        return Err(anyhow!(
            "subscription payload is too large ({} bytes)",
            bytes.len()
        ));
    }
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let nodes = parse_subscription_content(&text, &sub.id)?;

    Ok(SubscriptionFetchResult {
        nodes,
        total_traffic: user_info.total,
        used_traffic: user_info.used,
        expire_time: user_info.expire,
    })
}

#[derive(Default)]
struct UserInfo {
    total: Option<u64>,
    used: Option<u64>,
    expire: Option<chrono::DateTime<chrono::Utc>>,
}

fn parse_user_info(raw: &str) -> UserInfo {
    let mut info = UserInfo::default();
    let mut upload = 0u64;
    let mut download = 0u64;
    let mut saw_usage = false;

    for part in raw.split(';') {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim().to_ascii_lowercase().as_str() {
            "upload" => {
                if let Ok(v) = value.parse::<u64>() {
                    upload = v;
                    saw_usage = true;
                }
            }
            "download" => {
                if let Ok(v) = value.parse::<u64>() {
                    download = v;
                    saw_usage = true;
                }
            }
            "total" => info.total = value.parse::<u64>().ok().filter(|v| *v > 0),
            "expire" => {
                info.expire = value
                    .parse::<i64>()
                    .ok()
                    .filter(|ts| *ts > 0)
                    .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0));
            }
            _ => {}
        }
    }

    if saw_usage {
        info.used = Some(upload.saturating_add(download));
    }
    info
}

pub fn parse_subscription_content(content: &str, subscription_id: &str) -> Result<Vec<ProxyNode>> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("subscription is empty"));
    }

    if looks_like_clash(trimmed) {
        if let Ok(nodes) = parse_clash_yaml(trimmed) {
            return Ok(tag_nodes(nodes, subscription_id));
        }
    }

    let mut nodes = collect_uri_nodes(trimmed);

    if nodes.is_empty() {
        if let Ok(decoded) = decode_b64(trimmed).and_then(|b| Ok(String::from_utf8(b)?)) {
            nodes = collect_uri_nodes(&decoded);
            if nodes.is_empty() && looks_like_clash(&decoded) {
                if let Ok(clash_nodes) = parse_clash_yaml(&decoded) {
                    return Ok(tag_nodes(clash_nodes, subscription_id));
                }
            }
        }
    }

    if nodes.is_empty() {
        if let Ok(clash_nodes) = parse_clash_yaml(trimmed) {
            return Ok(tag_nodes(clash_nodes, subscription_id));
        }
        return Err(anyhow!("no supported proxy nodes found in subscription"));
    }

    Ok(tag_nodes(nodes, subscription_id))
}

fn looks_like_clash(content: &str) -> bool {
    content.lines().any(|line| {
        let trimmed = line.trim_start();
        trimmed.starts_with("proxies:") || trimmed.starts_with("proxy-groups:")
    })
}

fn collect_uri_nodes(content: &str) -> Vec<ProxyNode> {
    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#') && line.contains("://"))
        .filter_map(|line| match parse_proxy_uri(line) {
            Ok(node) => Some(node),
            Err(e) => {
                tracing::debug!("skipping subscription line: {}", e);
                None
            }
        })
        .collect()
}

fn tag_nodes(mut nodes: Vec<ProxyNode>, subscription_id: &str) -> Vec<ProxyNode> {
    for node in &mut nodes {
        node.subscription_id = Some(subscription_id.to_string());
    }
    nodes
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    #[test]
    fn parses_base64_line_list() {
        let combined = "trojan://password123@example.com:443#Node1\nhysteria2://password123@example2.com:443#Node2";
        let encoded = STANDARD.encode(combined.as_bytes());

        let nodes = parse_subscription_content(&encoded, "sub-123").expect("parse failed");
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "Node1");
        assert_eq!(nodes[0].subscription_id.as_deref(), Some("sub-123"));
        assert_eq!(nodes[1].name, "Node2");
    }

    #[test]
    fn parses_plain_line_list() {
        let content = "# comment\ntrojan://pw@example.com:443#Plain\n\n";
        let nodes = parse_subscription_content(content, "sub").expect("parse failed");
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "Plain");
    }

    #[test]
    fn rejects_plain_http_subscriptions() {
        assert!(validate_subscription_url("http://example.com/sub").is_err());
        assert!(validate_subscription_url("https://example.com/sub").is_ok());
    }

    #[test]
    fn parses_user_info_header() {
        let info = parse_user_info("upload=100; download=200; total=1000; expire=1893456000");
        assert_eq!(info.used, Some(300));
        assert_eq!(info.total, Some(1000));
        assert!(info.expire.is_some());
    }
}
