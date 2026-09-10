use anyhow::{Result, anyhow};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::config::paths::AppPaths;
use crate::config::profile::{ProfileStore, RuleType};
use crate::config::settings::{AppSettings, write_private_bytes};

pub const ADS_RULE_SET_TAG: &str = "geosite-category-ads-all";
const MAX_RULE_SET_BYTES: usize = 32 * 1024 * 1024;
const REFRESH_AFTER: Duration = Duration::from_secs(7 * 24 * 60 * 60);

pub fn rule_set_url(tag: &str) -> Result<String> {
    if !tag
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(anyhow!("invalid rule-set name: {}", tag));
    }

    if let Some(name) = tag.strip_prefix("geoip-") {
        Ok(format!(
            "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-{}.srs",
            name
        ))
    } else {
        let name = tag.strip_prefix("geosite-").unwrap_or(tag);
        Ok(format!(
            "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-{}.srs",
            name
        ))
    }
}

pub fn required_tags(settings: &AppSettings, profile_store: &ProfileStore) -> Vec<String> {
    let mut tags = Vec::new();
    if settings.block_ads {
        tags.push(ADS_RULE_SET_TAG.to_string());
    }
    for rule in &profile_store.custom_rules {
        if rule.enabled && rule.rule_type == RuleType::RuleSet {
            let tag = rule.value.trim().to_string();
            if !tag.is_empty() && !tags.contains(&tag) {
                tags.push(tag);
            }
        }
    }
    tags
}

pub fn remote_rule_set_tag(url: &str) -> String {
    let trimmed = url.trim();
    let stem = trimmed
        .rsplit('/')
        .next()
        .unwrap_or(trimmed)
        .split(['?', '#'])
        .next()
        .unwrap_or(trimmed);
    let stem = stem
        .strip_suffix(".srs")
        .or_else(|| stem.strip_suffix(".json"))
        .unwrap_or(stem);
    let sanitized: String = stem
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let sanitized = sanitized.trim_matches('-').to_string();
    let digest = stable_digest(trimmed);
    if sanitized.is_empty() {
        format!("remote-{:08x}", digest)
    } else {
        let short: String = sanitized.chars().take(40).collect();
        format!("{}-{:08x}", short, digest)
    }
}

fn stable_digest(value: &str) -> u32 {
    let mut hash: u32 = 2166136261;
    for byte in value.as_bytes() {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(16777619);
    }
    hash
}

pub fn cached_path(tag: &str) -> Option<PathBuf> {
    let path = AppPaths::get().rule_set_file(tag);
    if path.is_file() { Some(path) } else { None }
}

fn is_stale(path: &Path) -> bool {
    path.metadata()
        .and_then(|meta| meta.modified())
        .and_then(|modified| {
            SystemTime::now()
                .duration_since(modified)
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "clock went backwards"))
        })
        .map(|age| age > REFRESH_AFTER)
        .unwrap_or(true)
}

pub async fn ensure_rule_sets(tags: &[String]) -> Vec<(String, String)> {
    let mut failures = Vec::new();
    for tag in tags {
        if let Err(error) = ensure_rule_set(tag).await {
            failures.push((tag.clone(), error.to_string()));
        }
    }
    failures
}

pub async fn ensure_rule_set(tag: &str) -> Result<PathBuf> {
    let path = AppPaths::get().rule_set_file(tag);
    if path.is_file() && !is_stale(&path) {
        return Ok(path);
    }

    let url = rule_set_url(tag)?;
    match download(&url).await {
        Ok(bytes) => {
            write_private_bytes(&path, &bytes);
            Ok(path)
        }
        Err(error) => {
            if path.is_file() {
                tracing::warn!("keeping stale rule-set {}: {}", tag, error);
                Ok(path)
            } else {
                Err(error)
            }
        }
    }
}

async fn download(url: &str) -> Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(45))
        .connect_timeout(Duration::from_secs(10))
        .user_agent("RustyBird")
        .build()?;

    let response = client.get(url).send().await?;
    if !response.status().is_success() {
        return Err(anyhow!("rule-set server returned {}", response.status()));
    }

    let bytes = response.bytes().await?;
    if bytes.len() > MAX_RULE_SET_BYTES {
        return Err(anyhow!("rule-set is too large ({} bytes)", bytes.len()));
    }
    if !bytes.starts_with(b"SRS") {
        return Err(anyhow!("downloaded file is not a sing-box rule-set"));
    }
    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_geosite_and_geoip_urls() {
        assert_eq!(
            rule_set_url("geosite-category-ads-all").unwrap(),
            "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs"
        );
        assert_eq!(
            rule_set_url("geoip-ir").unwrap(),
            "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ir.srs"
        );
        assert_eq!(
            rule_set_url("netflix").unwrap(),
            "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-netflix.srs"
        );
    }

    #[test]
    fn remote_tags_are_stable_and_sanitized() {
        let first = remote_rule_set_tag("https://example.com/path/my rules.srs");
        let second = remote_rule_set_tag("https://example.com/path/my rules.srs");
        assert_eq!(first, second);
        assert!(first.starts_with("my-rules-"));
        assert!(first
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')));
        assert_ne!(
            remote_rule_set_tag("https://example.com/a.srs"),
            remote_rule_set_tag("https://other.com/a.srs")
        );
    }

    #[test]
    fn remote_tags_survive_query_strings() {
        let tag = remote_rule_set_tag("https://example.com/list.srs?token=abc");
        assert!(tag.starts_with("list-"));
    }

    #[test]
    fn rejects_path_traversal_in_tags() {
        assert!(rule_set_url("../../etc/passwd").is_err());
        assert!(rule_set_url("a/b").is_err());
    }
}
