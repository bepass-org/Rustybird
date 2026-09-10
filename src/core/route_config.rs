use serde_json::{Map, Value, json};
use std::collections::HashSet;

use crate::config::profile::{CustomRule, ProfileStore, RuleOutbound, RuleType};
use crate::config::settings::AppSettings;
use crate::core::dns_config::DNS_DIRECT_TAG;
use crate::core::rule_sets::{ADS_RULE_SET_TAG, cached_path, remote_rule_set_tag};

pub struct RouteSection {
    pub rules: Vec<Value>,
    pub rule_sets: Vec<Value>,
}

pub struct RouteBuilder<'a> {
    settings: &'a AppSettings,
    proxy_tag: &'a str,
    direct_tag: &'a str,
    rules: Vec<Value>,
    rule_sets: Vec<Value>,
    declared: HashSet<String>,
}

impl<'a> RouteBuilder<'a> {
    pub fn new(settings: &'a AppSettings, proxy_tag: &'a str, direct_tag: &'a str) -> Self {
        Self {
            settings,
            proxy_tag,
            direct_tag,
            rules: Vec::new(),
            rule_sets: Vec::new(),
            declared: HashSet::new(),
        }
    }

    pub fn build(mut self, profile_store: &ProfileStore) -> RouteSection {
        if self.settings.enable_sniff {
            self.rules.push(json!({ "action": "sniff" }));
        }
        self.rules
            .push(json!({ "protocol": "dns", "action": "hijack-dns" }));
        self.rules
            .push(json!({ "port": 53, "action": "hijack-dns" }));

        if self.settings.sniff_override_destination {
            self.rules.push(json!({
                "action": "resolve",
                "strategy": self.settings.dns_strategy.as_str()
            }));
        }

        self.rules
            .push(json!({ "clash_mode": "Direct", "outbound": self.direct_tag }));
        self.rules
            .push(json!({ "clash_mode": "Global", "outbound": self.proxy_tag }));

        if self.settings.bypass_private_networks {
            self.rules
                .push(json!({ "ip_is_private": true, "outbound": self.direct_tag }));
        }

        if self.settings.block_quic {
            self.rules.push(json!({
                "protocol": "quic",
                "action": "reject",
                "method": "drop"
            }));
        }

        if self.settings.block_ads && self.declare_local_rule_set(ADS_RULE_SET_TAG) {
            self.rules
                .push(json!({ "rule_set": [ADS_RULE_SET_TAG], "action": "reject" }));
        }

        for rule in &profile_store.custom_rules {
            if let Some(value) = self.build_custom_rule(rule) {
                self.rules.push(value);
            }
        }

        RouteSection {
            rules: self.rules,
            rule_sets: self.rule_sets,
        }
    }

    fn declare_local_rule_set(&mut self, tag: &str) -> bool {
        if self.declared.contains(tag) {
            return true;
        }
        match cached_path(tag) {
            Some(path) => {
                self.rule_sets.push(json!({
                    "type": "local",
                    "tag": tag,
                    "format": "binary",
                    "path": path.to_string_lossy()
                }));
                self.declared.insert(tag.to_string());
                true
            }
            None => {
                tracing::warn!("rule-set {} is not downloaded yet, skipping its rules", tag);
                false
            }
        }
    }

    fn declare_remote_rule_set(&mut self, url: &str) -> Option<String> {
        let trimmed = url.trim();
        if !trimmed.starts_with("https://") && !trimmed.starts_with("http://") {
            tracing::warn!("rule-set URL {} is not an http(s) URL, skipping", trimmed);
            return None;
        }
        let tag = remote_rule_set_tag(trimmed);
        if self.declared.contains(&tag) {
            return Some(tag);
        }
        let format = if trimmed.ends_with(".json") {
            "source"
        } else {
            "binary"
        };
        self.rule_sets.push(json!({
            "type": "remote",
            "tag": tag,
            "format": format,
            "url": trimmed,
            "update_interval": "1d",
            "http_client": { "detour": self.direct_tag }
        }));
        self.declared.insert(tag.clone());
        Some(tag)
    }

    fn build_custom_rule(&mut self, rule: &CustomRule) -> Option<Value> {
        if !rule.enabled {
            return None;
        }
        let value = rule.value.trim();
        if value.is_empty() {
            return None;
        }

        let mut object = Map::new();
        match rule.rule_type {
            RuleType::RuleSet => {
                if !self.declare_local_rule_set(value) {
                    return None;
                }
                object.insert("rule_set".to_string(), json!([value]));
            }
            RuleType::RuleSetUrl => {
                let tag = self.declare_remote_rule_set(value)?;
                object.insert("rule_set".to_string(), json!([tag]));
            }
            RuleType::Port => {
                let ports: Vec<u16> = value
                    .split(',')
                    .filter_map(|p| p.trim().parse::<u16>().ok())
                    .collect();
                if ports.is_empty() {
                    tracing::warn!("skipping port rule with no valid port: {}", value);
                    return None;
                }
                object.insert("port".to_string(), json!(ports));
            }
            RuleType::Network => {
                let network = value.to_ascii_lowercase();
                if !matches!(network.as_str(), "tcp" | "udp") {
                    tracing::warn!("skipping network rule with unknown network: {}", value);
                    return None;
                }
                object.insert("network".to_string(), json!([network]));
            }
            other => {
                object.insert(other.singbox_key().to_string(), json!([value]));
            }
        }

        match rule.outbound {
            RuleOutbound::Proxy => {
                object.insert("outbound".to_string(), json!(self.proxy_tag));
            }
            RuleOutbound::Direct => {
                object.insert("outbound".to_string(), json!(self.direct_tag));
            }
            RuleOutbound::Block => {
                object.insert("action".to_string(), json!("reject"));
            }
            RuleOutbound::BlockDrop => {
                object.insert("action".to_string(), json!("reject"));
                object.insert("method".to_string(), json!("drop"));
            }
        }
        Some(Value::Object(object))
    }
}

fn needs_process_matching(profile_store: &ProfileStore) -> bool {
    profile_store.custom_rules.iter().any(|rule| {
        rule.enabled
            && matches!(rule.rule_type, RuleType::ProcessName | RuleType::ProcessPath)
            && !rule.value.trim().is_empty()
    })
}

pub fn route_section(
    settings: &AppSettings,
    profile_store: &ProfileStore,
    proxy_tag: &str,
    direct_tag: &str,
    final_outbound: &str,
) -> Value {
    let section = RouteBuilder::new(settings, proxy_tag, direct_tag).build(profile_store);

    let mut route = Map::new();
    route.insert("rules".to_string(), Value::Array(section.rules));
    if !section.rule_sets.is_empty() {
        route.insert("rule_set".to_string(), Value::Array(section.rule_sets));
    }
    route.insert("final".to_string(), json!(final_outbound));
    route.insert("auto_detect_interface".to_string(), json!(true));
    route.insert("default_domain_resolver".to_string(), json!(DNS_DIRECT_TAG));
    if needs_process_matching(profile_store) {
        route.insert("find_process".to_string(), json!(true));
    }
    Value::Object(route)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::profile::{CustomRule, RuleOutbound, RuleType};

    fn rules_for(settings: &AppSettings, store: &ProfileStore) -> Vec<Value> {
        RouteBuilder::new(settings, "proxy", "direct")
            .build(store)
            .rules
    }

    #[test]
    fn sniff_is_first_when_enabled_and_absent_otherwise() {
        let mut settings = AppSettings::default();
        let store = ProfileStore::default();
        let rules = rules_for(&settings, &store);
        assert_eq!(rules[0]["action"], "sniff");

        settings.enable_sniff = false;
        let rules = rules_for(&settings, &store);
        assert!(rules.iter().all(|r| r["action"] != "sniff"));
    }

    #[test]
    fn port_rules_become_numbers() {
        let settings = AppSettings::default();
        let mut store = ProfileStore::default();
        store.custom_rules.push(CustomRule::new(
            RuleType::Port,
            "443, 8443",
            RuleOutbound::Direct,
        ));
        let rules = rules_for(&settings, &store);
        let rule = rules.last().unwrap();
        assert_eq!(rule["port"], json!([443, 8443]));
        assert_eq!(rule["outbound"], "direct");
    }

    #[test]
    fn invalid_port_rules_are_dropped() {
        let settings = AppSettings::default();
        let mut store = ProfileStore::default();
        store.custom_rules.push(CustomRule::new(
            RuleType::Port,
            "not-a-port",
            RuleOutbound::Direct,
        ));
        let rules = rules_for(&settings, &store);
        assert!(rules.iter().all(|r| r.get("port").is_none() || r["port"] == 53));
    }

    #[test]
    fn block_drop_emits_the_drop_method() {
        let settings = AppSettings::default();
        let mut store = ProfileStore::default();
        store.custom_rules.push(CustomRule::new(
            RuleType::DomainSuffix,
            ".tracker.example",
            RuleOutbound::BlockDrop,
        ));
        let rules = rules_for(&settings, &store);
        let rule = rules.last().unwrap();
        assert_eq!(rule["action"], "reject");
        assert_eq!(rule["method"], "drop");
    }

    #[test]
    fn remote_rule_sets_are_declared_once_with_a_direct_detour() {
        let settings = AppSettings::default();
        let mut store = ProfileStore::default();
        store.custom_rules.push(CustomRule::new(
            RuleType::RuleSetUrl,
            "https://example.com/list.srs",
            RuleOutbound::Direct,
        ));
        store.custom_rules.push(CustomRule::new(
            RuleType::RuleSetUrl,
            "https://example.com/list.srs",
            RuleOutbound::Proxy,
        ));
        let section = RouteBuilder::new(&settings, "proxy", "direct").build(&store);
        assert_eq!(section.rule_sets.len(), 1);
        assert_eq!(section.rule_sets[0]["type"], "remote");
        assert_eq!(section.rule_sets[0]["format"], "binary");
        assert_eq!(section.rule_sets[0]["http_client"]["detour"], "direct");
    }

    #[test]
    fn remote_json_rule_sets_use_the_source_format() {
        let settings = AppSettings::default();
        let mut store = ProfileStore::default();
        store.custom_rules.push(CustomRule::new(
            RuleType::RuleSetUrl,
            "https://example.com/list.json",
            RuleOutbound::Direct,
        ));
        let section = RouteBuilder::new(&settings, "proxy", "direct").build(&store);
        assert_eq!(section.rule_sets[0]["format"], "source");
    }

    #[test]
    fn non_http_rule_set_urls_are_rejected() {
        let settings = AppSettings::default();
        let mut store = ProfileStore::default();
        store.custom_rules.push(CustomRule::new(
            RuleType::RuleSetUrl,
            "file:///etc/passwd",
            RuleOutbound::Direct,
        ));
        let section = RouteBuilder::new(&settings, "proxy", "direct").build(&store);
        assert!(section.rule_sets.is_empty());
    }

    #[test]
    fn process_matching_is_only_enabled_when_a_process_rule_exists() {
        let settings = AppSettings::default();
        let mut store = ProfileStore::default();
        assert!(!needs_process_matching(&store));

        store.custom_rules.push(CustomRule::new(
            RuleType::DomainSuffix,
            ".example.com",
            RuleOutbound::Direct,
        ));
        assert!(!needs_process_matching(&store));

        store.custom_rules.push(CustomRule::new(
            RuleType::ProcessName,
            "firefox",
            RuleOutbound::Proxy,
        ));
        assert!(needs_process_matching(&store));

        let route = route_section(&settings, &store, "proxy", "direct", "proxy");
        assert_eq!(route["find_process"], true);

        store.custom_rules.last_mut().unwrap().enabled = false;
        assert!(!needs_process_matching(&store));
        let route = route_section(&settings, &store, "proxy", "direct", "proxy");
        assert!(route.get("find_process").is_none());
    }

    #[test]
    fn quic_blocking_adds_a_drop_rule() {
        let mut settings = AppSettings::default();
        settings.block_quic = true;
        let store = ProfileStore::default();
        let rules = rules_for(&settings, &store);
        assert!(rules
            .iter()
            .any(|r| r["protocol"] == "quic" && r["method"] == "drop"));
    }

    #[test]
    fn override_destination_adds_a_resolve_action() {
        let mut settings = AppSettings::default();
        settings.sniff_override_destination = true;
        let store = ProfileStore::default();
        let rules = rules_for(&settings, &store);
        assert!(rules.iter().any(|r| r["action"] == "resolve"));
    }
}
