use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use uuid::Uuid;

use crate::config::paths::AppPaths;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ProxyMode {
    #[default]
    Rule,
    Global,
    Direct,
}

impl ProxyMode {
    pub fn clash_name(&self) -> &'static str {
        match self {
            Self::Rule => "Rule",
            Self::Global => "Global",
            Self::Direct => "Direct",
        }
    }

    pub fn index(&self) -> u32 {
        match self {
            Self::Rule => 0,
            Self::Global => 1,
            Self::Direct => 2,
        }
    }

    pub fn from_index(index: u32) -> Self {
        match index {
            0 => Self::Rule,
            1 => Self::Global,
            _ => Self::Direct,
        }
    }
}

impl std::fmt::Display for ProxyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.clash_name())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ThemePreference {
    #[default]
    System,
    Light,
    Dark,
}

impl ThemePreference {
    pub fn index(&self) -> u32 {
        match self {
            Self::System => 0,
            Self::Light => 1,
            Self::Dark => 2,
        }
    }

    pub fn from_index(index: u32) -> Self {
        match index {
            0 => Self::System,
            1 => Self::Light,
            _ => Self::Dark,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::System => "Follow system",
            Self::Light => "Light",
            Self::Dark => "Dark",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TunStack {
    #[default]
    Go,
    System,
    Gvisor,
    Mixed,
}

impl TunStack {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::System => "system",
            Self::Gvisor => "gvisor",
            Self::Mixed => "mixed",
        }
    }

    pub fn index(&self) -> u32 {
        match self {
            Self::Go => 0,
            Self::System => 1,
            Self::Gvisor => 2,
            Self::Mixed => 3,
        }
    }

    pub fn from_index(index: u32) -> Self {
        match index {
            0 => Self::Go,
            1 => Self::System,
            2 => Self::Gvisor,
            _ => Self::Mixed,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
    Fatal,
    Panic,
}

impl LogLevel {
    pub const ALL: [Self; 7] = [
        Self::Trace,
        Self::Debug,
        Self::Info,
        Self::Warn,
        Self::Error,
        Self::Fatal,
        Self::Panic,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
            Self::Fatal => "fatal",
            Self::Panic => "panic",
        }
    }

    pub fn index(&self) -> u32 {
        Self::ALL.iter().position(|l| l == self).unwrap_or(2) as u32
    }

    pub fn from_index(index: u32) -> Self {
        Self::ALL
            .get(index as usize)
            .copied()
            .unwrap_or(Self::Info)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DnsStrategy {
    #[default]
    PreferIpv4,
    PreferIpv6,
    Ipv4Only,
    Ipv6Only,
}

impl DnsStrategy {
    pub const ALL: [Self; 4] = [
        Self::PreferIpv4,
        Self::PreferIpv6,
        Self::Ipv4Only,
        Self::Ipv6Only,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PreferIpv4 => "prefer_ipv4",
            Self::PreferIpv6 => "prefer_ipv6",
            Self::Ipv4Only => "ipv4_only",
            Self::Ipv6Only => "ipv6_only",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::PreferIpv4 => "Prefer IPv4",
            Self::PreferIpv6 => "Prefer IPv6",
            Self::Ipv4Only => "IPv4 only",
            Self::Ipv6Only => "IPv6 only",
        }
    }

    pub fn index(&self) -> u32 {
        Self::ALL.iter().position(|s| s == self).unwrap_or(0) as u32
    }

    pub fn from_index(index: u32) -> Self {
        Self::ALL
            .get(index as usize)
            .copied()
            .unwrap_or(Self::PreferIpv4)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GroupMode {
    #[default]
    Manual,
    UrlTest,
}

impl GroupMode {
    pub fn index(&self) -> u32 {
        match self {
            Self::Manual => 0,
            Self::UrlTest => 1,
        }
    }

    pub fn from_index(index: u32) -> Self {
        match index {
            0 => Self::Manual,
            _ => Self::UrlTest,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Manual => "Manual selection",
            Self::UrlTest => "Fastest node (URLTest)",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionSort {
    #[default]
    Traffic,
    TrafficTotal,
    Date,
    Host,
}

impl ConnectionSort {
    pub const ALL: [Self; 4] = [Self::Traffic, Self::TrafficTotal, Self::Date, Self::Host];

    pub fn label(&self) -> &'static str {
        match self {
            Self::Traffic => "Live traffic",
            Self::TrafficTotal => "Total traffic",
            Self::Date => "Newest first",
            Self::Host => "Host name",
        }
    }

    pub fn index(&self) -> u32 {
        Self::ALL.iter().position(|s| s == self).unwrap_or(0) as u32
    }

    pub fn from_index(index: u32) -> Self {
        Self::ALL
            .get(index as usize)
            .copied()
            .unwrap_or(Self::Traffic)
    }
}

fn default_singbox_path() -> String {
    for candidate in [
        "/usr/bin/sing-box",
        "/usr/local/bin/sing-box",
        "/opt/sing-box/sing-box",
    ] {
        if std::path::Path::new(candidate).is_file() {
            return candidate.to_string();
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        let local = std::path::Path::new(&home).join(".local/bin/sing-box");
        if local.is_file() {
            return local.to_string_lossy().into_owned();
        }
    }
    "/usr/bin/sing-box".to_string()
}

pub const DEFAULT_REMOTE_DNS: &str = "https://1.1.1.1/dns-query";
pub const DEFAULT_DIRECT_DNS: &str = "local";
pub const DEFAULT_TUN_ADDRESS_V4: &str = "172.19.0.1/30";
pub const DEFAULT_TUN_ADDRESS_V6: &str = "fdfe:dcba:9876::1/126";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppSettings {
    pub proxy_mode: ProxyMode,
    pub singbox_path: String,
    pub tun_mode: bool,
    pub tun_stack: TunStack,
    pub tun_mtu: u32,
    pub tun_auto_route: bool,
    pub tun_strict_route: bool,
    pub tun_auto_redirect: bool,
    pub tun_address_v4: String,
    pub tun_address_v6: String,
    pub tun_ipv6: bool,
    pub tun_exclude_routes: Vec<String>,
    pub system_proxy_auto_toggle: bool,
    pub mixed_port: u16,
    pub http_port: u16,
    pub socks_port: u16,
    pub clash_api_port: u16,
    pub clash_api_secret: String,
    pub clash_api_external_ui: String,
    pub allow_lan: bool,
    pub bypass_private_networks: bool,
    pub block_ads: bool,
    pub block_quic: bool,
    pub enable_sniff: bool,
    pub sniff_override_destination: bool,
    pub auto_update_subscriptions: bool,
    pub update_interval_hours: u32,
    pub latency_test_url: String,
    pub theme: ThemePreference,
    pub log_level: LogLevel,
    pub group_mode: GroupMode,
    pub urltest_interval_minutes: u32,
    pub urltest_tolerance: u32,
    pub remote_dns: String,
    pub direct_dns: String,
    pub dns_strategy: DnsStrategy,
    pub fakeip_enabled: bool,
    pub independent_dns_cache: bool,
    pub store_fakeip: bool,
    pub store_rdrc: bool,
    pub ntp_enabled: bool,
    pub ntp_server: String,
    pub keep_running_in_background: bool,
    pub start_hidden: bool,
    pub autostart_enabled: bool,
    pub connect_on_start: bool,
    pub connection_sort: ConnectionSort,
    pub show_closed_connections: bool,
    pub active_profile_id: Option<String>,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            proxy_mode: ProxyMode::Rule,
            singbox_path: default_singbox_path(),
            tun_mode: false,
            tun_stack: TunStack::default(),
            tun_mtu: 9000,
            tun_auto_route: true,
            tun_strict_route: true,
            tun_auto_redirect: true,
            tun_address_v4: DEFAULT_TUN_ADDRESS_V4.to_string(),
            tun_address_v6: DEFAULT_TUN_ADDRESS_V6.to_string(),
            tun_ipv6: true,
            tun_exclude_routes: Vec::new(),
            system_proxy_auto_toggle: false,
            mixed_port: 2080,
            http_port: 0,
            socks_port: 0,
            clash_api_port: 9090,
            clash_api_secret: Uuid::new_v4().to_string(),
            clash_api_external_ui: String::new(),
            allow_lan: false,
            bypass_private_networks: true,
            block_ads: false,
            block_quic: false,
            enable_sniff: true,
            sniff_override_destination: false,
            auto_update_subscriptions: true,
            update_interval_hours: 24,
            latency_test_url: "https://www.gstatic.com/generate_204".to_string(),
            theme: ThemePreference::default(),
            log_level: LogLevel::default(),
            group_mode: GroupMode::default(),
            urltest_interval_minutes: 3,
            urltest_tolerance: 50,
            remote_dns: DEFAULT_REMOTE_DNS.to_string(),
            direct_dns: DEFAULT_DIRECT_DNS.to_string(),
            dns_strategy: DnsStrategy::default(),
            fakeip_enabled: false,
            independent_dns_cache: false,
            store_fakeip: false,
            store_rdrc: true,
            ntp_enabled: false,
            ntp_server: "time.apple.com".to_string(),
            keep_running_in_background: false,
            start_hidden: false,
            autostart_enabled: false,
            connect_on_start: false,
            connection_sort: ConnectionSort::default(),
            show_closed_connections: false,
            active_profile_id: None,
        }
    }
}

impl AppSettings {
    pub fn load() -> Self {
        let paths = AppPaths::get();
        let file_path = paths.settings_file();
        match fs::read_to_string(&file_path) {
            Ok(content) => match serde_json::from_str::<AppSettings>(&content) {
                Ok(mut settings) => {
                    let dirty = settings.repair();
                    if dirty {
                        settings.save();
                    }
                    settings
                }
                Err(e) => {
                    tracing::warn!("Invalid settings file, regenerating defaults: {}", e);
                    let default = Self::default();
                    default.save();
                    default
                }
            },
            Err(_) => {
                let default = Self::default();
                default.save();
                default
            }
        }
    }

    fn repair(&mut self) -> bool {
        let mut dirty = false;
        if self.singbox_path.trim().is_empty() || !self.singbox_path.contains('/') {
            self.singbox_path = default_singbox_path();
            dirty = true;
        }
        if self.clash_api_secret.is_empty() {
            self.clash_api_secret = Uuid::new_v4().to_string();
            dirty = true;
        }
        if self.mixed_port == 0 {
            self.mixed_port = 2080;
            dirty = true;
        }
        if self.clash_api_port == 0 {
            self.clash_api_port = 9090;
            dirty = true;
        }
        if self.latency_test_url.trim().is_empty()
            || self.latency_test_url.starts_with("http://")
        {
            self.latency_test_url = "https://www.gstatic.com/generate_204".to_string();
            dirty = true;
        }
        if self.remote_dns.trim().is_empty() {
            self.remote_dns = DEFAULT_REMOTE_DNS.to_string();
            dirty = true;
        }
        if self.direct_dns.trim().is_empty() {
            self.direct_dns = DEFAULT_DIRECT_DNS.to_string();
            dirty = true;
        }
        if self.tun_mtu < 576 || self.tun_mtu > 65535 {
            self.tun_mtu = 9000;
            dirty = true;
        }
        if self.tun_address_v4.trim().is_empty() {
            self.tun_address_v4 = DEFAULT_TUN_ADDRESS_V4.to_string();
            dirty = true;
        }
        if self.tun_address_v6.trim().is_empty() {
            self.tun_address_v6 = DEFAULT_TUN_ADDRESS_V6.to_string();
            dirty = true;
        }
        if self.urltest_interval_minutes == 0 {
            self.urltest_interval_minutes = 3;
            dirty = true;
        }
        if self.ntp_server.trim().is_empty() {
            self.ntp_server = "time.apple.com".to_string();
            dirty = true;
        }
        if self.http_port != 0 && self.http_port == self.mixed_port {
            self.http_port = 0;
            dirty = true;
        }
        if self.socks_port != 0
            && (self.socks_port == self.mixed_port || self.socks_port == self.http_port)
        {
            self.socks_port = 0;
            dirty = true;
        }
        dirty
    }

    pub fn urltest_interval(&self) -> String {
        format!("{}m", self.urltest_interval_minutes.max(1))
    }

    pub fn save(&self) {
        let paths = AppPaths::get();
        write_private_json(&paths.settings_file(), self);
    }
}

pub fn write_private_json<T: Serialize>(path: &std::path::Path, value: &T) {
    let content = match serde_json::to_string_pretty(value) {
        Ok(content) => content,
        Err(e) => {
            tracing::error!("Failed to serialize {:?}: {}", path, e);
            return;
        }
    };
    write_private_bytes(path, content.as_bytes());
}

pub fn write_private_bytes(path: &std::path::Path, content: &[u8]) {
    let tmp_path = path.with_extension("tmp");
    let write_result = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp_path)
        .and_then(|mut file| {
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
            file.write_all(content)?;
            file.sync_all()
        });

    match write_result {
        Ok(()) => {
            if let Err(e) = fs::rename(&tmp_path, path) {
                tracing::error!("Failed to persist {:?}: {}", path, e);
                let _ = fs::remove_file(&tmp_path);
            }
        }
        Err(e) => {
            tracing::error!("Failed to write {:?}: {}", path, e);
            let _ = fs::remove_file(&tmp_path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_legacy_lowercase_tun_stack() {
        let legacy = r#"{"tun_stack":"mixed"}"#;
        let parsed: AppSettings = serde_json::from_str(legacy).expect("legacy settings must load");
        assert_eq!(parsed.tun_stack, TunStack::Mixed);
    }

    #[test]
    fn tun_stack_roundtrips_lowercase() {
        for stack in [
            TunStack::Go,
            TunStack::System,
            TunStack::Gvisor,
            TunStack::Mixed,
        ] {
            let json = serde_json::to_string(&stack).unwrap();
            assert_eq!(json, format!("\"{}\"", stack.as_str()));
            let back: TunStack = serde_json::from_str(&json).unwrap();
            assert_eq!(back, stack);
        }
    }

    #[test]
    fn unknown_settings_keys_are_ignored_and_defaults_fill_in() {
        let legacy = r#"{"core_type":"SingBox","xray_path":"xray","http_port":2081,"socks_port":2082,"proxy_mode":"Global"}"#;
        let parsed: AppSettings = serde_json::from_str(legacy).expect("must tolerate removed keys");
        assert_eq!(parsed.proxy_mode, ProxyMode::Global);
        assert_eq!(parsed.mixed_port, 2080);
        assert!(!parsed.clash_api_secret.is_empty());
    }

    #[test]
    fn proxy_mode_names_match_clash_api() {
        assert_eq!(ProxyMode::Rule.clash_name(), "Rule");
        assert_eq!(ProxyMode::Global.clash_name(), "Global");
        assert_eq!(ProxyMode::Direct.clash_name(), "Direct");
        for mode in [ProxyMode::Rule, ProxyMode::Global, ProxyMode::Direct] {
            assert_eq!(ProxyMode::from_index(mode.index()), mode);
        }
    }

    #[test]
    fn repair_rejects_duplicate_listen_ports() {
        let mut settings = AppSettings::default();
        settings.http_port = settings.mixed_port;
        settings.socks_port = settings.mixed_port;
        assert!(settings.repair());
        assert_eq!(settings.http_port, 0);
        assert_eq!(settings.socks_port, 0);
    }

    #[test]
    fn repair_restores_out_of_range_tun_mtu() {
        let mut settings = AppSettings::default();
        settings.tun_mtu = 2;
        assert!(settings.repair());
        assert_eq!(settings.tun_mtu, 9000);
    }

    #[test]
    fn enum_indexes_round_trip() {
        for level in LogLevel::ALL {
            assert_eq!(LogLevel::from_index(level.index()), level);
        }
        for strategy in DnsStrategy::ALL {
            assert_eq!(DnsStrategy::from_index(strategy.index()), strategy);
        }
        for sort in ConnectionSort::ALL {
            assert_eq!(ConnectionSort::from_index(sort.index()), sort);
        }
        for mode in [GroupMode::Manual, GroupMode::UrlTest] {
            assert_eq!(GroupMode::from_index(mode.index()), mode);
        }
        for stack in [
            TunStack::Go,
            TunStack::System,
            TunStack::Gvisor,
            TunStack::Mixed,
        ] {
            assert_eq!(TunStack::from_index(stack.index()), stack);
        }
        for theme in [
            ThemePreference::System,
            ThemePreference::Light,
            ThemePreference::Dark,
        ] {
            assert_eq!(ThemePreference::from_index(theme.index()), theme);
        }
    }
}
