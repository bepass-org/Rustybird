use anyhow::{Context, Result, anyhow};
use std::time::Duration;

use crate::config::paths::AppPaths;
use crate::config::profile::ConfigProfile;
use crate::config::settings::write_private_bytes;

const MAX_PROFILE_BYTES: usize = 16 * 1024 * 1024;
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

pub fn read_profile_content(id: &str) -> Result<String> {
    let path = AppPaths::get().config_profile_file(id);
    std::fs::read_to_string(&path).with_context(|| format!("could not read {:?}", path))
}

pub fn write_profile_content(id: &str, content: &str) -> Result<()> {
    validate_profile_content(content)?;
    let path = AppPaths::get().config_profile_file(id);
    write_private_bytes(&path, content.as_bytes());
    if !path.is_file() {
        return Err(anyhow!("could not persist the profile to {:?}", path));
    }
    Ok(())
}

pub fn validate_profile_content(content: &str) -> Result<()> {
    if content.len() > MAX_PROFILE_BYTES {
        return Err(anyhow!(
            "the profile is larger than {} MiB",
            MAX_PROFILE_BYTES / (1024 * 1024)
        ));
    }
    let value: serde_json::Value =
        serde_json::from_str(content).map_err(|e| anyhow!("invalid JSON: {}", e))?;
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("a sing-box profile must be a JSON object"))?;
    if !object.contains_key("outbounds") && !object.contains_key("endpoints") {
        return Err(anyhow!(
            "the profile declares neither outbounds nor endpoints"
        ));
    }
    Ok(())
}

pub fn profile_summary(content: &str) -> String {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(content) else {
        return "Not valid JSON".to_string();
    };
    let outbounds = value
        .get("outbounds")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let endpoints = value
        .get("endpoints")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let inbounds = value
        .get("inbounds")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let rules = value
        .get("route")
        .and_then(|v| v.get("rules"))
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    format!(
        "{} outbounds \u{2022} {} endpoints \u{2022} {} inbounds \u{2022} {} route rules",
        outbounds, endpoints, inbounds, rules
    )
}

pub async fn fetch_remote_profile(profile: &ConfigProfile) -> Result<String> {
    let url = profile
        .remote_url
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .ok_or_else(|| anyhow!("the profile has no remote URL"))?;
    let parsed = url::Url::parse(url).context("invalid profile URL")?;
    if parsed.scheme() != "https" {
        return Err(anyhow!(
            "refusing a plain http profile URL; use https:// so the configuration cannot be tampered with"
        ));
    }

    let client = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .connect_timeout(Duration::from_secs(10))
        .user_agent(crate::parser::subscription::USER_AGENT)
        .build()?;

    let response = client.get(parsed).send().await?;
    if !response.status().is_success() {
        return Err(anyhow!("profile server returned {}", response.status()));
    }
    let bytes = response.bytes().await?;
    if bytes.len() > MAX_PROFILE_BYTES {
        return Err(anyhow!("the remote profile is too large"));
    }
    let content = String::from_utf8(bytes.to_vec()).context("the profile is not UTF-8")?;
    validate_profile_content(&content)?;
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_minimal_profile() {
        let content = r#"{"outbounds":[{"type":"direct","tag":"direct"}]}"#;
        assert!(validate_profile_content(content).is_ok());
    }

    #[test]
    fn accepts_an_endpoint_only_profile() {
        let content = r#"{"endpoints":[{"type":"wireguard","tag":"wg"}]}"#;
        assert!(validate_profile_content(content).is_ok());
    }

    #[test]
    fn rejects_broken_profiles() {
        assert!(validate_profile_content("not json").is_err());
        assert!(validate_profile_content("[]").is_err());
        assert!(validate_profile_content("{}").is_err());
    }

    #[test]
    fn summary_counts_the_sections() {
        let content = r#"{
            "inbounds": [{"type":"mixed","tag":"in"}],
            "outbounds": [{"type":"direct","tag":"direct"},{"type":"block","tag":"block"}],
            "endpoints": [{"type":"wireguard","tag":"wg"}],
            "route": { "rules": [{"action":"sniff"}] }
        }"#;
        let summary = profile_summary(content);
        assert!(summary.starts_with("2 outbounds"));
        assert!(summary.contains("1 endpoints"));
        assert!(summary.contains("1 inbounds"));
        assert!(summary.contains("1 route rules"));
    }

    #[test]
    fn summary_reports_invalid_json() {
        assert_eq!(profile_summary("oops"), "Not valid JSON");
    }
}
