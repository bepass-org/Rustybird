use anyhow::{Result, anyhow};
use serde_json::{Map, Value, json};

use crate::config::profile::ProfileStore;
use crate::config::settings::{AppSettings, GroupMode, ProxyMode};
use crate::core::dns_config::build_dns;
use crate::core::outbound::build_outbound;
use crate::core::route_config::route_section;

pub const PROXY_SELECTOR_TAG: &str = "proxy";
pub const AUTO_GROUP_TAG: &str = "auto";
pub const DIRECT_TAG: &str = "direct";
pub const TUN_INTERFACE_NAME: &str = "rustybird0";

pub struct BuiltConfig {
    pub value: Value,
    pub node_tags: Vec<(String, String)>,
}

pub struct SingboxConfigBuilder;

impl SingboxConfigBuilder {
    #[cfg(test)]
    pub fn build(settings: &AppSettings, profile_store: &ProfileStore) -> Result<BuiltConfig> {
        Self::build_with_privileges(settings, profile_store, false)
    }

    pub fn build_with_privileges(
        settings: &AppSettings,
        profile_store: &ProfileStore,
        elevated: bool,
    ) -> Result<BuiltConfig> {
        if profile_store.nodes.is_empty() {
            return Err(anyhow!("no proxy nodes configured"));
        }

        let active_node = profile_store
            .get_active_node()
            .ok_or_else(|| anyhow!("no active proxy node selected"))?;

        let mut outbounds = Vec::new();
        let mut endpoints = Vec::new();
        let mut node_tags = Vec::new();
        let mut selector_members = Vec::new();
        let mut used_tags = std::collections::HashSet::new();

        for node in &profile_store.nodes {
            if node.requires_exclusive_endpoint() && node.id != active_node.id {
                continue;
            }

            let mut tag = node.outbound_tag();
            let mut suffix = 2;
            while !used_tags.insert(tag.clone()) {
                tag = format!("{} #{}", node.outbound_tag(), suffix);
                suffix += 1;
            }

            match build_outbound(node, &tag) {
                Ok(built) => {
                    if built.is_endpoint {
                        endpoints.extend(built.values);
                    } else {
                        outbounds.extend(built.values);
                    }
                    selector_members.push(tag.clone());
                    node_tags.push((node.id.clone(), tag));
                }
                Err(e) => {
                    tracing::warn!("Skipping node {}: {}", node.name, e);
                }
            }
        }

        if selector_members.is_empty() {
            return Err(anyhow!("none of the configured nodes are usable"));
        }

        let active_tag = node_tags
            .iter()
            .find(|(id, _)| id == &active_node.id)
            .map(|(_, tag)| tag.clone())
            .unwrap_or_else(|| selector_members[0].clone());

        let mut group_members = selector_members.clone();
        if settings.group_mode == GroupMode::UrlTest && selector_members.len() > 1 {
            outbounds.push(json!({
                "type": "urltest",
                "tag": AUTO_GROUP_TAG,
                "outbounds": selector_members,
                "url": settings.latency_test_url,
                "interval": settings.urltest_interval(),
                "tolerance": settings.urltest_tolerance,
                "interrupt_exist_connections": false
            }));
            group_members.insert(0, AUTO_GROUP_TAG.to_string());
        }
        group_members.push(DIRECT_TAG.to_string());

        let default_member = if settings.group_mode == GroupMode::UrlTest
            && group_members.first().map(String::as_str) == Some(AUTO_GROUP_TAG)
        {
            AUTO_GROUP_TAG.to_string()
        } else {
            active_tag
        };

        outbounds.push(json!({
            "type": "selector",
            "tag": PROXY_SELECTOR_TAG,
            "outbounds": group_members,
            "default": default_member,
            "interrupt_exist_connections": true
        }));
        outbounds.push(json!({
            "type": "direct",
            "tag": DIRECT_TAG
        }));

        let final_outbound = match settings.proxy_mode {
            ProxyMode::Rule | ProxyMode::Global => PROXY_SELECTOR_TAG,
            ProxyMode::Direct => DIRECT_TAG,
        };

        let mut root = Map::new();
        root.insert("log".to_string(), build_log(settings));
        root.insert(
            "dns".to_string(),
            build_dns(settings, PROXY_SELECTOR_TAG, DIRECT_TAG),
        );
        if settings.ntp_enabled {
            root.insert("ntp".to_string(), build_ntp(settings));
        }
        root.insert(
            "inbounds".to_string(),
            Value::Array(build_inbounds(settings)),
        );
        root.insert("outbounds".to_string(), Value::Array(outbounds));
        if !endpoints.is_empty() {
            root.insert("endpoints".to_string(), Value::Array(endpoints));
        }
        root.insert(
            "route".to_string(),
            route_section(
                settings,
                profile_store,
                PROXY_SELECTOR_TAG,
                DIRECT_TAG,
                final_outbound,
            ),
        );
        root.insert("experimental".to_string(), build_experimental(settings, elevated));

        Ok(BuiltConfig {
            value: Value::Object(root),
            node_tags,
        })
    }

    pub fn build_from_profile(
        settings: &AppSettings,
        content: &str,
        elevated: bool,
    ) -> Result<BuiltConfig> {
        let mut value: Value =
            serde_json::from_str(content).map_err(|e| anyhow!("invalid sing-box profile: {}", e))?;
        let root = value
            .as_object_mut()
            .ok_or_else(|| anyhow!("a sing-box profile must be a JSON object"))?;

        if !root.contains_key("outbounds") && !root.contains_key("endpoints") {
            return Err(anyhow!(
                "the profile declares neither outbounds nor endpoints"
            ));
        }

        let experimental = root
            .entry("experimental".to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        let experimental = experimental
            .as_object_mut()
            .ok_or_else(|| anyhow!("experimental must be a JSON object"))?;

        experimental.insert(
            "clash_api".to_string(),
            build_clash_api(settings, experimental.get("clash_api")),
        );
        if !experimental.contains_key("cache_file") {
            experimental.insert("cache_file".to_string(), build_cache_file(settings, elevated));
        }

        Ok(BuiltConfig {
            value,
            node_tags: Vec::new(),
        })
    }
}

fn build_log(settings: &AppSettings) -> Value {
    json!({ "level": settings.log_level.as_str(), "timestamp": true })
}

fn build_ntp(settings: &AppSettings) -> Value {
    json!({
        "enabled": true,
        "server": settings.ntp_server.trim(),
        "server_port": 123,
        "interval": "30m",
        "detour": DIRECT_TAG
    })
}

fn build_inbounds(settings: &AppSettings) -> Vec<Value> {
    let listen_addr = if settings.allow_lan {
        "0.0.0.0"
    } else {
        "127.0.0.1"
    };

    let mut inbounds = Vec::new();
    if settings.tun_mode {
        let mut address = vec![settings.tun_address_v4.trim().to_string()];
        if settings.tun_ipv6 && !settings.tun_address_v6.trim().is_empty() {
            address.push(settings.tun_address_v6.trim().to_string());
        }

        let mut tun = Map::new();
        tun.insert("type".to_string(), json!("tun"));
        tun.insert("tag".to_string(), json!("tun-in"));
        tun.insert("interface_name".to_string(), json!(TUN_INTERFACE_NAME));
        tun.insert("address".to_string(), json!(address));
        tun.insert("mtu".to_string(), json!(settings.tun_mtu));
        tun.insert("auto_route".to_string(), json!(settings.tun_auto_route));
        tun.insert("strict_route".to_string(), json!(settings.tun_strict_route));
        tun.insert("stack".to_string(), json!(settings.tun_stack.as_str()));
        if settings.tun_auto_redirect {
            tun.insert("auto_redirect".to_string(), json!(true));
        }
        let excluded: Vec<String> = settings
            .tun_exclude_routes
            .iter()
            .map(|route| route.trim().to_string())
            .filter(|route| !route.is_empty())
            .collect();
        if !excluded.is_empty() {
            tun.insert("route_exclude_address".to_string(), json!(excluded));
        }
        inbounds.push(Value::Object(tun));
    }

    inbounds.push(json!({
        "type": "mixed",
        "tag": "mixed-in",
        "listen": listen_addr,
        "listen_port": settings.mixed_port
    }));

    if settings.http_port != 0 && settings.http_port != settings.mixed_port {
        inbounds.push(json!({
            "type": "http",
            "tag": "http-in",
            "listen": listen_addr,
            "listen_port": settings.http_port
        }));
    }
    if settings.socks_port != 0
        && settings.socks_port != settings.mixed_port
        && settings.socks_port != settings.http_port
    {
        inbounds.push(json!({
            "type": "socks",
            "tag": "socks-in",
            "listen": listen_addr,
            "listen_port": settings.socks_port
        }));
    }

    inbounds
}

fn build_cache_file(settings: &AppSettings, elevated: bool) -> Value {
    let paths = crate::config::paths::AppPaths::get();
    json!({
        "enabled": true,
        "path": paths.singbox_cache_file(elevated).to_string_lossy(),
        "store_fakeip": settings.store_fakeip && settings.fakeip_enabled,
        "store_rdrc": settings.store_rdrc
    })
}

fn build_clash_api(settings: &AppSettings, existing: Option<&Value>) -> Value {
    let mut clash_api = existing
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    clash_api.insert(
        "external_controller".to_string(),
        json!(format!("127.0.0.1:{}", settings.clash_api_port)),
    );
    clash_api.insert("secret".to_string(), json!(settings.clash_api_secret));
    clash_api.insert(
        "default_mode".to_string(),
        json!(settings.proxy_mode.clash_name()),
    );
    let external_ui = settings.clash_api_external_ui.trim();
    if !external_ui.is_empty() {
        clash_api.insert("external_ui".to_string(), json!(external_ui));
    }
    Value::Object(clash_api)
}

fn build_experimental(settings: &AppSettings, elevated: bool) -> Value {
    json!({
        "cache_file": build_cache_file(settings, elevated),
        "clash_api": build_clash_api(settings, None)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::profile::{CustomRule, RuleOutbound, RuleType};
    use crate::parser::node::{
        MultiplexConfig, MultiplexProtocol, ProtocolConfig, ProtocolType, ProxyNode, RealityConfig,
        TlsConfig, TransportType, UtlsFingerprint, VlessConfig,
    };

    pub fn reality_node() -> ProxyNode {
        let mut node = ProxyNode::new(
            "US Reality".to_string(),
            "1.2.3.4".to_string(),
            443,
            ProtocolType::Vless,
            ProtocolConfig::Vless(VlessConfig {
                uuid: "12345678-1234-1234-1234-1234567890ab".to_string(),
                flow: Some("xtls-rprx-vision".to_string()),
                packet_encoding: None,
            }),
        );
        node.tls = TlsConfig {
            enabled: true,
            server_name: Some("www.example.com".to_string()),
            alpn: vec!["h2".to_string()],
            utls: Some(UtlsFingerprint::Chrome),
            reality: Some(RealityConfig {
                public_key: "ozBIkHZm7eCLgeb9WhyS-Im6DURA2FrHmx8E16HYO2Y".to_string(),
                short_id: "a1b2c3d4".to_string(),
            }),
            ..TlsConfig::default()
        };
        node
    }

    #[test]
    fn builds_selector_with_all_nodes() {
        let settings = AppSettings::default();
        let mut store = ProfileStore::default();
        store.add_or_update_node(reality_node());

        let mut second = reality_node();
        second.id = uuid::Uuid::new_v4().to_string();
        second.name = "DE Reality".to_string();
        store.add_or_update_node(second);

        let built = SingboxConfigBuilder::build(&settings, &store).expect("build failed");
        let outbounds = built.value["outbounds"].as_array().unwrap();

        let selector = outbounds
            .iter()
            .find(|o| o["tag"] == PROXY_SELECTOR_TAG)
            .expect("missing selector");
        assert_eq!(selector["type"], "selector");
        assert_eq!(selector["outbounds"].as_array().unwrap().len(), 3);
        assert_eq!(built.node_tags.len(), 2);
        assert!(outbounds.iter().all(|o| o["type"] != "urltest"));
    }

    #[test]
    fn urltest_mode_adds_an_auto_group_as_the_default() {
        let mut settings = AppSettings::default();
        settings.group_mode = GroupMode::UrlTest;
        let mut store = ProfileStore::default();
        store.add_or_update_node(reality_node());
        let mut second = reality_node();
        second.id = uuid::Uuid::new_v4().to_string();
        second.name = "DE Reality".to_string();
        store.add_or_update_node(second);

        let built = SingboxConfigBuilder::build(&settings, &store).expect("build failed");
        let outbounds = built.value["outbounds"].as_array().unwrap();

        let auto = outbounds
            .iter()
            .find(|o| o["tag"] == AUTO_GROUP_TAG)
            .expect("missing urltest group");
        assert_eq!(auto["type"], "urltest");
        assert_eq!(auto["outbounds"].as_array().unwrap().len(), 2);
        assert_eq!(auto["tolerance"], settings.urltest_tolerance);
        assert_eq!(auto["interval"], "3m");

        let selector = outbounds
            .iter()
            .find(|o| o["tag"] == PROXY_SELECTOR_TAG)
            .unwrap();
        assert_eq!(selector["default"], AUTO_GROUP_TAG);
        assert_eq!(selector["outbounds"][0], AUTO_GROUP_TAG);
    }

    #[test]
    fn urltest_is_skipped_for_a_single_node() {
        let mut settings = AppSettings::default();
        settings.group_mode = GroupMode::UrlTest;
        let mut store = ProfileStore::default();
        store.add_or_update_node(reality_node());

        let built = SingboxConfigBuilder::build(&settings, &store).expect("build failed");
        let outbounds = built.value["outbounds"].as_array().unwrap();
        assert!(outbounds.iter().all(|o| o["type"] != "urltest"));
    }

    #[test]
    fn shadowsocks_carries_no_tls_or_transport() {
        let settings = AppSettings::default();
        let mut store = ProfileStore::default();
        let mut node = ProxyNode::new(
            "SS".to_string(),
            "ss.example.com".to_string(),
            8388,
            ProtocolType::Shadowsocks,
            ProtocolConfig::Shadowsocks(crate::parser::node::ShadowsocksConfig {
                method: "aes-256-gcm".to_string(),
                password: "secret".to_string(),
                plugin: None,
                plugin_opts: None,
                shadow_tls: None,
            }),
        );
        node.tls.enabled = true;
        node.transport.transport_type = TransportType::Ws;
        store.add_or_update_node(node);

        let built = SingboxConfigBuilder::build(&settings, &store).expect("build failed");
        let outbound = built.value["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["type"] == "shadowsocks")
            .expect("missing shadowsocks outbound");

        assert!(outbound.get("tls").is_none());
        assert!(outbound.get("transport").is_none());
    }

    #[test]
    fn shadowsocks_multiplex_is_emitted() {
        let settings = AppSettings::default();
        let mut store = ProfileStore::default();
        let mut node = ProxyNode::new(
            "SS mux".to_string(),
            "ss.example.com".to_string(),
            8388,
            ProtocolType::Shadowsocks,
            ProtocolConfig::Shadowsocks(crate::parser::node::ShadowsocksConfig {
                method: "aes-256-gcm".to_string(),
                password: "secret".to_string(),
                plugin: None,
                plugin_opts: None,
                shadow_tls: None,
            }),
        );
        node.multiplex = Some(MultiplexConfig {
            enabled: true,
            protocol: MultiplexProtocol::H2mux,
            max_streams: Some(8),
            padding: true,
            brutal_up_mbps: Some(50),
            brutal_down_mbps: Some(100),
            ..MultiplexConfig::default()
        });
        store.add_or_update_node(node);

        let built = SingboxConfigBuilder::build(&settings, &store).expect("build failed");
        let outbound = built.value["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["type"] == "shadowsocks")
            .unwrap();
        assert_eq!(outbound["multiplex"]["protocol"], "h2mux");
        assert_eq!(outbound["multiplex"]["max_streams"], 8);
        assert_eq!(outbound["multiplex"]["padding"], true);
        assert_eq!(outbound["multiplex"]["brutal"]["down_mbps"], 100);
    }

    #[test]
    fn netstack_wireguard_nodes_all_stay_selectable() {
        let settings = AppSettings::default();
        let mut store = ProfileStore::default();
        store.add_or_update_node(reality_node());
        store.add_or_update_node(wireguard_node(None));

        let built = SingboxConfigBuilder::build(&settings, &store).expect("build failed");
        assert_eq!(built.value["endpoints"].as_array().unwrap().len(), 1);
        assert_eq!(built.node_tags.len(), 2);
    }

    #[test]
    fn system_interface_wireguard_is_limited_to_the_active_node() {
        let settings = AppSettings::default();
        let mut store = ProfileStore::default();
        store.add_or_update_node(reality_node());
        let mut node = wireguard_node(None);
        if let ProtocolConfig::Wireguard(config) = &mut node.config {
            config.system_interface = true;
        }
        store.add_or_update_node(node);

        let built = SingboxConfigBuilder::build(&settings, &store).expect("build failed");
        assert!(built.value.get("endpoints").is_none());
        assert_eq!(built.node_tags.len(), 1);
    }

    fn wireguard_node(mtu: Option<u32>) -> ProxyNode {
        ProxyNode::new(
            "WG".to_string(),
            "wg.example.com".to_string(),
            51820,
            ProtocolType::Wireguard,
            ProtocolConfig::Wireguard(crate::parser::node::WireguardConfig {
                private_key: "uCRsuACIPWUXQAi0h2/aD6rLLqYfoHpMguB362WzlHQ=".to_string(),
                peer_public_key: "gK3h8wLb3tS40GDsJeMYbh5z8U2ktfcYv+5F1yzTyRQ=".to_string(),
                pre_shared_key: None,
                local_address: vec!["10.0.0.2/32".to_string()],
                mtu,
                reserved: None,
                allowed_ips: Vec::new(),
                persistent_keepalive_interval: None,
                system_interface: false,
            }),
        )
    }

    #[test]
    fn wireguard_becomes_an_endpoint() {
        let settings = AppSettings::default();
        let mut store = ProfileStore::default();
        store.add_or_update_node(wireguard_node(Some(1420)));

        let built = SingboxConfigBuilder::build(&settings, &store).expect("build failed");
        assert!(built.value["endpoints"].is_array());
        assert_eq!(built.value["endpoints"][0]["type"], "wireguard");
        assert!(built.value["endpoints"][0]["peers"].is_array());
        assert_eq!(
            built.value["endpoints"][0]["peers"][0]["allowed_ips"],
            json!(["0.0.0.0/0", "::/0"])
        );
    }

    #[test]
    fn tun_inbound_follows_the_settings() {
        let mut settings = AppSettings::default();
        settings.tun_mode = true;
        settings.tun_mtu = 1500;
        settings.tun_ipv6 = false;
        settings.tun_auto_redirect = false;
        settings.tun_exclude_routes = vec!["192.168.9.0/24".to_string()];
        let mut store = ProfileStore::default();
        store.add_or_update_node(reality_node());

        let built = SingboxConfigBuilder::build(&settings, &store).expect("build failed");
        let tun = built.value["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["type"] == "tun")
            .expect("missing tun inbound");
        assert_eq!(tun["mtu"], 1500);
        assert_eq!(tun["address"].as_array().unwrap().len(), 1);
        assert!(tun.get("auto_redirect").is_none());
        assert_eq!(tun["route_exclude_address"], json!(["192.168.9.0/24"]));
    }

    #[test]
    fn extra_listen_ports_become_inbounds() {
        let mut settings = AppSettings::default();
        settings.http_port = 2081;
        settings.socks_port = 2082;
        let mut store = ProfileStore::default();
        store.add_or_update_node(reality_node());

        let built = SingboxConfigBuilder::build(&settings, &store).expect("build failed");
        let inbounds = built.value["inbounds"].as_array().unwrap();
        assert!(inbounds
            .iter()
            .any(|i| i["type"] == "http" && i["listen_port"] == 2081));
        assert!(inbounds
            .iter()
            .any(|i| i["type"] == "socks" && i["listen_port"] == 2082));
    }

    #[test]
    fn log_level_and_ntp_reach_the_config() {
        let mut settings = AppSettings::default();
        settings.log_level = crate::config::settings::LogLevel::Debug;
        settings.ntp_enabled = true;
        settings.ntp_server = "time.cloudflare.com".to_string();
        let mut store = ProfileStore::default();
        store.add_or_update_node(reality_node());

        let built = SingboxConfigBuilder::build(&settings, &store).expect("build failed");
        assert_eq!(built.value["log"]["level"], "debug");
        assert_eq!(built.value["ntp"]["server"], "time.cloudflare.com");
        assert_eq!(built.value["ntp"]["detour"], DIRECT_TAG);
    }

    #[test]
    fn external_ui_is_only_set_when_configured() {
        let mut settings = AppSettings::default();
        let mut store = ProfileStore::default();
        store.add_or_update_node(reality_node());

        let built = SingboxConfigBuilder::build(&settings, &store).expect("build failed");
        assert!(built.value["experimental"]["clash_api"]
            .get("external_ui")
            .is_none());

        settings.clash_api_external_ui = "ui".to_string();
        let built = SingboxConfigBuilder::build(&settings, &store).expect("build failed");
        assert_eq!(built.value["experimental"]["clash_api"]["external_ui"], "ui");
    }

    #[test]
    fn profile_builds_keep_the_original_outbounds_and_gain_a_clash_api() {
        let settings = AppSettings::default();
        let profile = r#"{
            "outbounds": [ { "type": "direct", "tag": "direct" } ],
            "route": { "final": "direct" }
        }"#;
        let built = SingboxConfigBuilder::build_from_profile(&settings, profile, false)
            .expect("profile build failed");
        assert_eq!(built.value["outbounds"][0]["tag"], "direct");
        assert_eq!(
            built.value["experimental"]["clash_api"]["external_controller"],
            format!("127.0.0.1:{}", settings.clash_api_port)
        );
        assert_eq!(
            built.value["experimental"]["clash_api"]["secret"],
            settings.clash_api_secret
        );
        assert!(built.node_tags.is_empty());
    }

    #[test]
    fn profile_builds_reject_configs_without_outbounds() {
        let settings = AppSettings::default();
        assert!(SingboxConfigBuilder::build_from_profile(&settings, "{}", false).is_err());
        assert!(SingboxConfigBuilder::build_from_profile(&settings, "[]", false).is_err());
        assert!(SingboxConfigBuilder::build_from_profile(&settings, "not json", false).is_err());
    }

    #[test]
    fn profile_builds_preserve_an_existing_cache_file() {
        let settings = AppSettings::default();
        let profile = r#"{
            "outbounds": [ { "type": "direct", "tag": "direct" } ],
            "experimental": { "cache_file": { "enabled": true, "path": "/tmp/custom.db" } }
        }"#;
        let built = SingboxConfigBuilder::build_from_profile(&settings, profile, false)
            .expect("profile build failed");
        assert_eq!(
            built.value["experimental"]["cache_file"]["path"],
            "/tmp/custom.db"
        );
    }

    #[test]
    fn custom_rules_reach_the_route_section() {
        let settings = AppSettings::default();
        let mut store = ProfileStore::default();
        store.add_or_update_node(reality_node());
        store.custom_rules.push(CustomRule::new(
            RuleType::ProcessName,
            "firefox",
            RuleOutbound::Proxy,
        ));
        let built = SingboxConfigBuilder::build(&settings, &store).expect("build failed");
        let rules = built.value["route"]["rules"].as_array().unwrap();
        assert!(rules
            .iter()
            .any(|r| r["process_name"] == json!(["firefox"]) && r["outbound"] == PROXY_SELECTOR_TAG));
    }

    #[test]
    fn rejects_empty_store() {
        let settings = AppSettings::default();
        let store = ProfileStore::default();
        assert!(SingboxConfigBuilder::build(&settings, &store).is_err());
    }
}
