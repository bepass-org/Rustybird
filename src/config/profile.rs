use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use uuid::Uuid;

use std::os::unix::fs::PermissionsExt;

use crate::config::paths::AppPaths;
use crate::config::settings::write_private_json;
use crate::parser::node::ProxyNode;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub url: String,
    pub auto_update: bool,
    pub update_interval_hours: u32,
    pub last_updated: Option<chrono::DateTime<chrono::Utc>>,
    pub total_traffic: Option<u64>,
    pub used_traffic: Option<u64>,
    pub expire_time: Option<chrono::DateTime<chrono::Utc>>,
    pub node_ids: Vec<String>,
}

impl Default for Subscription {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: String::new(),
            url: String::new(),
            auto_update: true,
            update_interval_hours: 24,
            last_updated: None,
            total_traffic: None,
            used_traffic: None,
            expire_time: None,
            node_ids: Vec::new(),
        }
    }
}

impl Subscription {
    pub fn new(name: String, url: String) -> Self {
        Self {
            name,
            url,
            ..Default::default()
        }
    }

    pub fn is_due(&self, fallback_hours: u32) -> bool {
        if !self.auto_update {
            return false;
        }
        let interval = if self.update_interval_hours == 0 {
            fallback_hours.max(1)
        } else {
            self.update_interval_hours
        };
        match self.last_updated {
            Some(last) => {
                let age = chrono::Utc::now().signed_duration_since(last);
                age.num_minutes() >= (interval as i64) * 60
            }
            None => true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProfileKind {
    #[default]
    Local,
    Remote,
}

impl ProfileKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Local => "Local",
            Self::Remote => "Remote",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ConfigProfile {
    pub id: String,
    pub name: String,
    pub kind: ProfileKind,
    pub remote_url: Option<String>,
    pub auto_update: bool,
    pub update_interval_minutes: u32,
    pub last_updated: Option<chrono::DateTime<chrono::Utc>>,
}

impl Default for ConfigProfile {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: String::new(),
            kind: ProfileKind::Local,
            remote_url: None,
            auto_update: false,
            update_interval_minutes: 60,
            last_updated: None,
        }
    }
}

impl ConfigProfile {
    pub fn local(name: String) -> Self {
        Self {
            name,
            kind: ProfileKind::Local,
            ..Default::default()
        }
    }

    pub fn remote(name: String, url: String) -> Self {
        Self {
            name,
            kind: ProfileKind::Remote,
            remote_url: Some(url),
            auto_update: true,
            ..Default::default()
        }
    }

    pub fn is_due(&self) -> bool {
        if !self.auto_update || self.kind != ProfileKind::Remote {
            return false;
        }
        let interval = self.update_interval_minutes.max(15) as i64;
        match self.last_updated {
            Some(last) => {
                chrono::Utc::now().signed_duration_since(last).num_minutes() >= interval
            }
            None => true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleType {
    Domain,
    DomainSuffix,
    DomainKeyword,
    DomainRegex,
    IpCidr,
    SourceIpCidr,
    Port,
    PortRange,
    ProcessName,
    ProcessPath,
    Network,
    Protocol,
    ClashMode,
    WifiSsid,
    RuleSet,
    RuleSetUrl,
}

impl RuleType {
    pub const ALL: [Self; 16] = [
        Self::DomainSuffix,
        Self::DomainKeyword,
        Self::Domain,
        Self::DomainRegex,
        Self::IpCidr,
        Self::SourceIpCidr,
        Self::Port,
        Self::PortRange,
        Self::ProcessName,
        Self::ProcessPath,
        Self::Network,
        Self::Protocol,
        Self::ClashMode,
        Self::WifiSsid,
        Self::RuleSet,
        Self::RuleSetUrl,
    ];

    pub fn from_index(index: u32) -> Self {
        Self::ALL
            .get(index as usize)
            .copied()
            .unwrap_or(Self::DomainSuffix)
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Domain => "Full Domain",
            Self::DomainSuffix => "Domain Suffix",
            Self::DomainKeyword => "Domain Keyword",
            Self::DomainRegex => "Domain Regex",
            Self::IpCidr => "IP CIDR",
            Self::SourceIpCidr => "Source IP CIDR",
            Self::Port => "Destination Port",
            Self::PortRange => "Port Range",
            Self::ProcessName => "Process Name",
            Self::ProcessPath => "Process Path",
            Self::Network => "Network",
            Self::Protocol => "Sniffed Protocol",
            Self::ClashMode => "Clash Mode",
            Self::WifiSsid => "Wi-Fi SSID",
            Self::RuleSet => "Rule Set (sing-geo)",
            Self::RuleSetUrl => "Rule Set (remote URL)",
        }
    }

    pub fn singbox_key(&self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::DomainSuffix => "domain_suffix",
            Self::DomainKeyword => "domain_keyword",
            Self::DomainRegex => "domain_regex",
            Self::IpCidr => "ip_cidr",
            Self::SourceIpCidr => "source_ip_cidr",
            Self::Port => "port",
            Self::PortRange => "port_range",
            Self::ProcessName => "process_name",
            Self::ProcessPath => "process_path",
            Self::Network => "network",
            Self::Protocol => "protocol",
            Self::ClashMode => "clash_mode",
            Self::WifiSsid => "wifi_ssid",
            Self::RuleSet | Self::RuleSetUrl => "rule_set",
        }
    }

    pub fn placeholder(&self) -> &'static str {
        match self {
            Self::Domain => "example.com",
            Self::DomainSuffix => ".example.com",
            Self::DomainKeyword => "example",
            Self::DomainRegex => "^ads\\..+$",
            Self::IpCidr => "10.0.0.0/8",
            Self::SourceIpCidr => "192.168.1.0/24",
            Self::Port => "443",
            Self::PortRange => "1000:2000",
            Self::ProcessName => "firefox",
            Self::ProcessPath => "/usr/bin/firefox",
            Self::Network => "udp",
            Self::Protocol => "quic",
            Self::ClashMode => "Global",
            Self::WifiSsid => "HomeNetwork",
            Self::RuleSet => "geosite-category-ads-all",
            Self::RuleSetUrl => "https://example.com/rules.srs",
        }
    }

}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleOutbound {
    Proxy,
    Direct,
    Block,
    BlockDrop,
}

impl RuleOutbound {
    pub const ALL: [Self; 4] = [Self::Proxy, Self::Direct, Self::Block, Self::BlockDrop];

    pub fn from_index(index: u32) -> Self {
        Self::ALL.get(index as usize).copied().unwrap_or(Self::Proxy)
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Proxy => "Proxy",
            Self::Direct => "Direct",
            Self::Block => "Block",
            Self::BlockDrop => "Block silently",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CustomRule {
    pub id: String,
    pub rule_type: RuleType,
    pub value: String,
    pub outbound: RuleOutbound,
    pub enabled: bool,
}

impl Default for CustomRule {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            rule_type: RuleType::DomainSuffix,
            value: String::new(),
            outbound: RuleOutbound::Proxy,
            enabled: true,
        }
    }
}

impl CustomRule {
    pub fn new(rule_type: RuleType, value: &str, outbound: RuleOutbound) -> Self {
        Self {
            rule_type,
            value: value.trim().to_string(),
            outbound,
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProfileStore {
    pub subscriptions: Vec<Subscription>,
    pub nodes: Vec<ProxyNode>,
    pub custom_rules: Vec<CustomRule>,
    pub active_node_id: Option<String>,
    pub config_profiles: Vec<ConfigProfile>,
}

impl ProfileStore {
    pub fn load() -> Self {
        let paths = AppPaths::get();
        let file_path = paths.profiles_file();
        match fs::read_to_string(&file_path) {
            Ok(content) => match serde_json::from_str::<ProfileStore>(&content) {
                Ok(mut store) => {
                    store.prune();
                    if file_is_group_or_world_readable(&file_path) {
                        tracing::info!("tightening permissions on {:?}", file_path);
                        store.save();
                    }
                    store
                }
                Err(e) => {
                    tracing::error!("Failed to parse profiles, starting empty: {}", e);
                    Self::default()
                }
            },
            Err(_) => {
                let default = Self::default();
                default.save();
                default
            }
        }
    }

    pub fn save(&self) {
        let paths = AppPaths::get();
        write_private_json(&paths.profiles_file(), self);
    }

    fn prune(&mut self) {
        let mut seen = HashSet::new();
        self.nodes.retain(|node| seen.insert(node.id.clone()));

        let node_ids: HashSet<String> = self.nodes.iter().map(|n| n.id.clone()).collect();
        for sub in &mut self.subscriptions {
            sub.node_ids.retain(|id| node_ids.contains(id));
        }

        if self
            .active_node_id
            .as_ref()
            .is_none_or(|id| !node_ids.contains(id))
        {
            self.active_node_id = self.nodes.first().map(|n| n.id.clone());
        }
    }

    pub fn get_active_node(&self) -> Option<&ProxyNode> {
        match self.active_node_id.as_ref() {
            Some(id) => self
                .nodes
                .iter()
                .find(|n| &n.id == id)
                .or_else(|| self.nodes.first()),
            None => self.nodes.first(),
        }
    }

    pub fn set_active_node(&mut self, id: &str) {
        if self.nodes.iter().any(|n| n.id == id) {
            self.active_node_id = Some(id.to_string());
        }
    }

    pub fn add_or_update_node(&mut self, node: ProxyNode) {
        match self.nodes.iter_mut().find(|n| n.id == node.id) {
            Some(existing) => *existing = node,
            None => self.nodes.push(node),
        }
        if self.active_node_id.is_none() {
            self.active_node_id = self.nodes.first().map(|n| n.id.clone());
        }
    }

    pub fn remove_node(&mut self, id: &str) {
        self.nodes.retain(|n| n.id != id);
        for sub in &mut self.subscriptions {
            sub.node_ids.retain(|nid| nid != id);
        }
        if self.active_node_id.as_deref() == Some(id) {
            self.active_node_id = self.nodes.first().map(|n| n.id.clone());
        }
    }

    pub fn replace_subscription_nodes(&mut self, subscription_id: &str, nodes: Vec<ProxyNode>) {
        let previous_active = self.active_node_id.clone();
        let previous_active_tag = previous_active
            .as_ref()
            .and_then(|id| self.nodes.iter().find(|n| &n.id == id))
            .map(|node| (node.server.clone(), node.port, node.name.clone()));

        self.nodes
            .retain(|n| n.subscription_id.as_deref() != Some(subscription_id));

        let node_ids: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
        self.nodes.extend(nodes);

        if let Some(sub) = self
            .subscriptions
            .iter_mut()
            .find(|s| s.id == subscription_id)
        {
            sub.node_ids = node_ids;
        }

        let still_valid = previous_active
            .as_ref()
            .is_some_and(|id| self.nodes.iter().any(|n| &n.id == id));

        if still_valid {
            return;
        }

        let mut replacement = None;
        if let Some((server, port, name)) = previous_active_tag {
            replacement = self
                .nodes
                .iter()
                .find(|n| n.server == server && n.port == port && n.name == name)
                .map(|n| n.id.clone());
        }
        if replacement.is_none() {
            replacement = self.nodes.first().map(|n| n.id.clone());
        }
        self.active_node_id = replacement;
    }

    pub fn remove_subscription(&mut self, id: &str) {
        self.nodes
            .retain(|n| n.subscription_id.as_deref() != Some(id));
        self.subscriptions.retain(|s| s.id != id);
        self.prune();
    }

    pub fn subscription_name(&self, id: Option<&str>) -> String {
        match id {
            Some(id) => self
                .subscriptions
                .iter()
                .find(|s| s.id == id)
                .map(|s| s.name.clone())
                .unwrap_or_else(|| "Subscription".to_string()),
            None => "Custom Nodes".to_string(),
        }
    }

    pub fn config_profile(&self, id: &str) -> Option<&ConfigProfile> {
        self.config_profiles.iter().find(|p| p.id == id)
    }

    pub fn unique_profile_name(&self, base: &str) -> String {
        let base = if base.trim().is_empty() {
            "Profile"
        } else {
            base.trim()
        };
        let existing: HashSet<&str> = self
            .config_profiles
            .iter()
            .map(|p| p.name.as_str())
            .collect();
        if !existing.contains(base) {
            return base.to_string();
        }
        let mut counter = 1;
        loop {
            let candidate = format!("{} ({})", base, counter);
            if !existing.contains(candidate.as_str()) {
                return candidate;
            }
            counter += 1;
        }
    }

    pub fn remove_config_profile(&mut self, id: &str) {
        self.config_profiles.retain(|p| p.id != id);
        let _ = fs::remove_file(AppPaths::get().config_profile_file(id));
    }
}

fn file_is_group_or_world_readable(path: &std::path::Path) -> bool {
    path.metadata()
        .map(|meta| meta.permissions().mode() & 0o077 != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_type_indexes_round_trip() {
        for (index, rule_type) in RuleType::ALL.iter().enumerate() {
            assert_eq!(RuleType::from_index(index as u32), *rule_type);
        }
        for (index, outbound) in RuleOutbound::ALL.iter().enumerate() {
            assert_eq!(RuleOutbound::from_index(index as u32), *outbound);
        }
        assert_eq!(RuleType::from_index(999), RuleType::DomainSuffix);
        assert_eq!(RuleOutbound::from_index(999), RuleOutbound::Proxy);
    }

    #[test]
    fn legacy_rules_without_new_fields_still_load() {
        let legacy = r#"{"custom_rules":[{"id":"a","rule_type":"domain_suffix","value":".example.com","outbound":"direct","enabled":true}]}"#;
        let store: ProfileStore = serde_json::from_str(legacy).expect("legacy store must load");
        assert_eq!(store.custom_rules.len(), 1);
        assert_eq!(store.custom_rules[0].rule_type, RuleType::DomainSuffix);
    }

    #[test]
    fn unique_profile_name_avoids_collisions() {
        let mut store = ProfileStore::default();
        store
            .config_profiles
            .push(ConfigProfile::local("Work".to_string()));
        assert_eq!(store.unique_profile_name("Home"), "Home");
        assert_eq!(store.unique_profile_name("Work"), "Work (1)");
        store
            .config_profiles
            .push(ConfigProfile::local("Work (1)".to_string()));
        assert_eq!(store.unique_profile_name("Work"), "Work (2)");
    }

    #[test]
    fn subscription_due_tracks_interval() {
        let mut sub = Subscription::new("S".to_string(), "https://example.com".to_string());
        assert!(sub.is_due(24));
        sub.last_updated = Some(chrono::Utc::now());
        assert!(!sub.is_due(24));
        sub.last_updated = Some(chrono::Utc::now() - chrono::Duration::hours(25));
        assert!(sub.is_due(24));
        sub.auto_update = false;
        assert!(!sub.is_due(24));
    }

    #[test]
    fn remote_profile_due_respects_minimum_interval() {
        let mut profile =
            ConfigProfile::remote("P".to_string(), "https://example.com".to_string());
        profile.update_interval_minutes = 1;
        profile.last_updated = Some(chrono::Utc::now() - chrono::Duration::minutes(5));
        assert!(!profile.is_due());
        profile.last_updated = Some(chrono::Utc::now() - chrono::Duration::minutes(20));
        assert!(profile.is_due());
    }
}
