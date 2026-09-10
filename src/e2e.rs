#![cfg(test)]

use base64::Engine;
use serde_json::Value;
use std::process::Command;

use crate::config::profile::{ConfigProfile, CustomRule, ProfileStore, RuleOutbound, RuleType};
use crate::config::settings::{AppSettings, GroupMode, LogLevel};
use crate::core::config_builder::SingboxConfigBuilder;
use crate::parser::clash::parse_clash_yaml;
use crate::parser::node::{
    MultiplexConfig, MultiplexProtocol, ProtocolConfig, ProtocolType, ProxyNode, TorConfig,
    UdpOverTcpConfig,
};
use crate::parser::subscription::parse_subscription_content;
use crate::parser::uri::parse_proxy_uri;

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const REALITY_KEY: &str = "ozBIkHZm7eCLgeb9WhyS-Im6DURA2FrHmx8E16HYO2Y";
const WG_PRIVATE: &str = "uCRsuACIPWUXQAi0h2/aD6rLLqYfoHpMguB362WzlHQ=";
const WG_PUBLIC: &str = "gK3h8wLb3tS40GDsJeMYbh5z8U2ktfcYv+5F1yzTyRQ=";
const WG_PRIVATE_ENCODED: &str = "uCRsuACIPWUXQAi0h2%2FaD6rLLqYfoHpMguB362WzlHQ%3D";

fn vmess_uri(net: &str, tls: &str) -> String {
    let payload = format!(
        r#"{{"v":"2","ps":"VMess {net}","add":"vm.example.com","port":"443","id":"{UUID}","aid":"0","scy":"auto","net":"{net}","host":"vm.example.com","path":"/path","tls":"{tls}","sni":"vm.example.com"}}"#
    );
    format!(
        "vmess://{}",
        base64::engine::general_purpose::STANDARD.encode(payload.as_bytes())
    )
}

pub fn every_supported_uri() -> Vec<String> {
    vec![
        format!("vless://{UUID}@1.2.3.4:443?encryption=none&security=tls&sni=a.example.com&type=tcp#VLESS-TLS"),
        format!("vless://{UUID}@1.2.3.5:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk={REALITY_KEY}&sid=a1b2c3d4&type=tcp#VLESS-Reality"),
        format!("vless://{UUID}@1.2.3.6:443?encryption=none&security=tls&sni=b.example.com&type=ws&path=%2Fws&host=b.example.com&ed=2048#VLESS-WS"),
        format!("vless://{UUID}@1.2.3.7:443?encryption=none&security=tls&sni=c.example.com&type=grpc&serviceName=GunSvc&permitWithoutStream=1#VLESS-gRPC"),
        format!("vless://{UUID}@1.2.3.8:443?encryption=none&security=tls&sni=d.example.com&type=httpupgrade&path=%2Fhu&host=d.example.com#VLESS-HTTPUpgrade"),
        format!("vless://{UUID}@1.2.3.9:443?encryption=none&security=tls&sni=e.example.com&type=quic#VLESS-QUIC"),
        format!("vless://{UUID}@1.2.3.10:443?encryption=none&security=tls&sni=f.example.com&type=tcp&mux=yamux&muxmaxstreams=8&muxpadding=1#VLESS-Mux"),
        vmess_uri("tcp", "tls"),
        vmess_uri("ws", "tls"),
        vmess_uri("grpc", "tls"),
        vmess_uri("h2", "tls"),
        vmess_uri("tcp", ""),
        "trojan://password123@t.example.com:443?sni=t.example.com&type=ws&path=%2Ftr#Trojan-WS".to_string(),
        "trojan://password123@t2.example.com:443?sni=t2.example.com&alpn=h2,http/1.1&fragment=1#Trojan-TCP".to_string(),
        "trojan-go://password123@t3.example.com:443?sni=t3.example.com&path=%2Fgo#Trojan-Go".to_string(),
        "ss://YWVzLTI1Ni1nY206c2VjcmV0@s.example.com:8388#SS-Legacy".to_string(),
        "ss://2022-blake3-aes-256-gcm:GcRPS0j%2FpVaCTF9UZ%2FGDSPWrM6rMTMKGUEUvzC%2FJzFA%3D@s2.example.com:8388#SS-2022".to_string(),
        "ss://YWVzLTI1Ni1nY206c2VjcmV0@s3.example.com:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.example.com#SS-Obfs".to_string(),
        "ss://YWVzLTEyOC1nY206c2VjcmV0@s4.example.com:443?plugin=shadow-tls%3Bpassword%3Dstls%3Bversion%3D3%3Bhost%3Dwww.microsoft.com#SS-ShadowTLS".to_string(),
        "ss://YWVzLTI1Ni1nY206c2VjcmV0@s5.example.com:8388?uot=1#SS-UoT".to_string(),
        "hysteria2://password123@h.example.com:443?sni=h.example.com&obfs=salamander&obfs-password=xyz&up=50&down=200#HY2".to_string(),
        "hy2://password123@h2.example.com:443?insecure=1#HY2-Short".to_string(),
        "hysteria://h3.example.com:443?auth=token&upmbps=50&downmbps=200&sni=h3.example.com&obfs=xplus#HY1".to_string(),
        format!("tuic://{UUID}:pass@tu.example.com:443?sni=tu.example.com&congestion_control=bbr&udp_relay_mode=native&alpn=h3&zero_rtt_handshake=1#TUIC"),
        "anytls://password123@any.example.com:8443?sni=any.example.com&fp=chrome&min_idle_session=2#AnyTLS".to_string(),
        "snell://psk123@sn.example.com:44046?version=4&obfs=tls&obfs-host=bing.com#Snell4".to_string(),
        "snell://psk123@sn6.example.com:44046?version=6&mode=unshaped#Snell6".to_string(),
        "ssh://root:secret@ssh.example.com:22#SSH".to_string(),
        "socks5://user:pass@socks.example.com:1080#SOCKS5".to_string(),
        "socks4://socks4.example.com:1080#SOCKS4".to_string(),
        "http://user:pass@proxy.example.com:8080#HTTP".to_string(),
        "https://user:pass@proxy2.example.com:8443?sni=proxy2.example.com#HTTPS".to_string(),
        format!("wireguard://{}@wg.example.com:51820?publickey={WG_PUBLIC}&address=10.0.0.2%2F32,fd00::2%2F128&mtu=1408&reserved=1,2,3#WireGuard", WG_PRIVATE_ENCODED),
    ]
}

fn store_from_uris(uris: &[String]) -> ProfileStore {
    let mut store = ProfileStore::default();
    for uri in uris {
        let node = parse_proxy_uri(uri).unwrap_or_else(|e| panic!("failed to parse {uri}: {e}"));
        store.add_or_update_node(node);
    }
    store
}

fn build_from_uris(uris: &[String]) -> Value {
    SingboxConfigBuilder::build(&AppSettings::default(), &store_from_uris(uris))
        .expect("config build failed")
        .value
}

fn singbox_binary() -> Option<String> {
    std::env::var("RUSTYBIRD_SINGBOX_BIN")
        .ok()
        .filter(|path| std::path::Path::new(path).is_file())
}

fn check_with_singbox(label: &str, config: &Value) {
    let Some(binary) = singbox_binary() else {
        return;
    };
    let directory = std::env::temp_dir().join(format!(
        "rustybird-check-{}-{}",
        std::process::id(),
        label.replace(['/', ' '], "_")
    ));
    std::fs::create_dir_all(&directory).expect("failed to create the check directory");
    let path = directory.join("config.json");
    std::fs::write(&path, serde_json::to_vec_pretty(config).unwrap())
        .expect("failed to write the config");

    let output = Command::new(&binary)
        .arg("check")
        .arg("-c")
        .arg(&path)
        .arg("-D")
        .arg(&directory)
        .output()
        .expect("failed to run sing-box check");

    let _ = std::fs::remove_dir_all(&directory);
    assert!(
        output.status.success(),
        "sing-box rejected the {label} config:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn every_supported_uri_scheme_reaches_a_valid_outbound() {
    let uris = every_supported_uri();
    let config = build_from_uris(&uris);
    let outbounds = config["outbounds"].as_array().unwrap();

    let group_types = ["selector", "urltest", "direct"];
    let node_outbounds: Vec<_> = outbounds
        .iter()
        .filter(|o| !group_types.contains(&o["type"].as_str().unwrap_or_default()))
        .collect();

    let shadow_tls_count = node_outbounds
        .iter()
        .filter(|o| o["type"] == "shadowtls")
        .count();
    assert_eq!(shadow_tls_count, 1, "the shadow-tls plugin must add a layer");

    let wireguard = config["endpoints"].as_array().expect("missing endpoints");
    assert_eq!(wireguard.len(), 1);
    assert_eq!(wireguard[0]["type"], "wireguard");

    assert_eq!(node_outbounds.len(), uris.len() - 1 + shadow_tls_count);

    for outbound in &node_outbounds {
        let kind = outbound["type"].as_str().unwrap();
        assert!(outbound["tag"].is_string(), "{kind} is missing a tag");

        if kind != "tor" {
            let detoured = outbound.get("detour").is_some();
            if !detoured {
                assert!(outbound["server"].is_string(), "{kind} is missing a server");
                assert!(
                    outbound["server_port"].is_number() || outbound["server_ports"].is_array(),
                    "{kind} is missing a port"
                );
            }
        }

        match kind {
            "vless" | "vmess" => assert!(outbound["uuid"].is_string()),
            "trojan" | "hysteria2" | "anytls" | "shadowtls" => {
                assert!(outbound["password"].is_string())
            }
            "hysteria" => {
                assert!(outbound.get("auth_str").is_some() || outbound.get("auth").is_some());
                assert!(outbound["up_mbps"].is_number());
                assert!(outbound["down_mbps"].is_number());
            }
            "shadowsocks" => {
                assert!(outbound["method"].is_string());
                assert!(outbound["password"].is_string());
            }
            "tuic" => {
                assert!(outbound["uuid"].is_string());
                assert!(outbound["password"].is_string());
            }
            "snell" => {
                assert!(outbound["psk"].is_string());
                assert!(matches!(outbound["version"].as_u64(), Some(4) | Some(6)));
            }
            "ssh" => assert!(outbound["user"].is_string()),
            "socks" | "http" | "tor" => {}
            other => panic!("unexpected outbound type {other}"),
        }

        if matches!(kind, "shadowsocks" | "snell" | "ssh" | "socks" | "tor") {
            assert!(outbound.get("tls").is_none(), "{kind} must not carry tls");
        }
        if !matches!(kind, "vless" | "vmess" | "trojan") {
            assert!(
                outbound.get("transport").is_none(),
                "{kind} must not carry a v2ray transport"
            );
        }
        if !matches!(kind, "vless" | "vmess" | "trojan" | "shadowsocks") {
            assert!(
                outbound.get("multiplex").is_none(),
                "{kind} must not carry multiplex"
            );
        }
    }

    check_with_singbox("all-uris", &config);
}

#[test]
fn generated_config_passes_singbox_check_with_every_feature_enabled() {
    let mut settings = AppSettings::default();
    settings.tun_mode = true;
    settings.tun_ipv6 = true;
    settings.http_port = 2081;
    settings.socks_port = 2082;
    settings.allow_lan = true;
    settings.group_mode = GroupMode::UrlTest;
    settings.log_level = LogLevel::Debug;
    settings.fakeip_enabled = true;
    settings.store_fakeip = true;
    settings.independent_dns_cache = true;
    settings.block_quic = true;
    settings.enable_sniff = true;
    settings.sniff_override_destination = true;
    settings.ntp_enabled = true;
    settings.remote_dns = "https://1.1.1.1/dns-query".to_string();
    settings.direct_dns = "tls://8.8.8.8".to_string();
    settings.tun_exclude_routes = vec!["192.168.9.0/24".to_string()];

    let mut store = store_from_uris(&every_supported_uri());
    store.custom_rules.push(CustomRule::new(
        RuleType::DomainSuffix,
        ".example.org",
        RuleOutbound::Direct,
    ));
    store.custom_rules.push(CustomRule::new(
        RuleType::DomainRegex,
        "^ads\\..+$",
        RuleOutbound::Block,
    ));
    store.custom_rules.push(CustomRule::new(
        RuleType::IpCidr,
        "10.20.0.0/16",
        RuleOutbound::BlockDrop,
    ));
    store.custom_rules.push(CustomRule::new(
        RuleType::SourceIpCidr,
        "192.168.1.0/24",
        RuleOutbound::Direct,
    ));
    store
        .custom_rules
        .push(CustomRule::new(RuleType::Port, "8080,8443", RuleOutbound::Proxy));
    store.custom_rules.push(CustomRule::new(
        RuleType::PortRange,
        "10000:20000",
        RuleOutbound::Direct,
    ));
    store.custom_rules.push(CustomRule::new(
        RuleType::ProcessName,
        "firefox",
        RuleOutbound::Proxy,
    ));
    store.custom_rules.push(CustomRule::new(
        RuleType::ProcessPath,
        "/usr/bin/curl",
        RuleOutbound::Direct,
    ));
    store
        .custom_rules
        .push(CustomRule::new(RuleType::Network, "udp", RuleOutbound::Direct));
    store.custom_rules.push(CustomRule::new(
        RuleType::Protocol,
        "bittorrent",
        RuleOutbound::BlockDrop,
    ));
    store.custom_rules.push(CustomRule::new(
        RuleType::DomainKeyword,
        "tracker",
        RuleOutbound::Block,
    ));
    store.custom_rules.push(CustomRule::new(
        RuleType::Domain,
        "exact.example.com",
        RuleOutbound::Proxy,
    ));
    store.custom_rules.push(CustomRule::new(
        RuleType::WifiSsid,
        "HomeNetwork",
        RuleOutbound::Direct,
    ));
    store.custom_rules.push(CustomRule::new(
        RuleType::RuleSetUrl,
        "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-netflix.srs",
        RuleOutbound::Proxy,
    ));

    let built = SingboxConfigBuilder::build(&settings, &store).expect("build failed");

    let route = &built.value["route"];
    assert!(route["rule_set"].is_array());
    assert_eq!(built.value["inbounds"].as_array().unwrap().len(), 4);
    assert_eq!(
        built.value["experimental"]["cache_file"]["store_fakeip"],
        true
    );

    check_with_singbox("all-features", &built.value);
}

#[test]
fn tor_outbound_is_accepted_without_a_server() {
    let mut store = ProfileStore::default();
    let mut node = ProxyNode::new(
        "Tor".to_string(),
        String::new(),
        0,
        ProtocolType::Tor,
        ProtocolConfig::Tor(TorConfig::default()),
    );
    node.id = "tor-node".to_string();
    store.add_or_update_node(node);

    let built = SingboxConfigBuilder::build(&AppSettings::default(), &store).expect("build failed");
    let tor = built.value["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["type"] == "tor")
        .expect("missing tor outbound");
    assert!(tor.get("server").is_none());

    check_with_singbox("tor", &built.value);
}

#[test]
fn clash_subscription_builds_a_valid_config() {
    let yaml = r#"
proxies:
  - name: VLESS Reality
    type: vless
    server: v.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    flow: xtls-rprx-vision
    tls: true
    servername: www.microsoft.com
    client-fingerprint: chrome
    reality-opts:
      public-key: ozBIkHZm7eCLgeb9WhyS-Im6DURA2FrHmx8E16HYO2Y
      short-id: a1b2c3d4
  - name: VMess WS
    type: vmess
    server: vm.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: auto
    tls: true
    network: ws
    ws-opts:
      path: /ray
      headers:
        Host: cdn.example.com
  - name: SS mux
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: pw
    udp: true
    smux:
      enabled: true
      protocol: h2mux
      max-streams: 8
  - name: AnyTLS
    type: anytls
    server: any.example.com
    port: 8443
    password: pw
    sni: any.example.com
  - name: Snell
    type: snell
    server: sn.example.com
    port: 44046
    psk: psk123
    version: 4
    obfs-opts:
      mode: tls
      host: bing.com
  - name: Hysteria
    type: hysteria
    server: h.example.com
    port: 443
    auth-str: token
    up: 50
    down: 200
    sni: h.example.com
  - name: Hysteria2
    type: hysteria2
    server: h2.example.com
    port: 443
    password: pw
    obfs: salamander
    obfs-password: xyz
    sni: h2.example.com
  - name: TUIC
    type: tuic
    server: tu.example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    password: pw
    congestion-controller: bbr
    udp-relay-mode: native
    sni: tu.example.com
    alpn:
      - h3
  - name: Trojan gRPC
    type: trojan
    server: t.example.com
    port: 443
    password: pw
    sni: t.example.com
    network: grpc
    grpc-opts:
      grpc-service-name: GunService
  - name: SSH
    type: ssh
    server: ssh.example.com
    port: 22
    username: root
    password: secret
  - name: SOCKS5
    type: socks5
    server: socks.example.com
    port: 1080
  - name: HTTP
    type: http
    server: proxy.example.com
    port: 8080
"#;

    let nodes = parse_clash_yaml(yaml).expect("clash parse failed");
    assert_eq!(nodes.len(), 12);

    let mut store = ProfileStore::default();
    for node in nodes {
        store.add_or_update_node(node);
    }

    let built = SingboxConfigBuilder::build(&AppSettings::default(), &store).expect("build failed");
    check_with_singbox("clash", &built.value);
}

#[test]
fn clash_yaml_routes_through_the_subscription_pipeline() {
    let yaml = r#"
proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - Node
proxies:
  - name: Node
    type: trojan
    server: t.example.com
    port: 443
    password: pw
"#;
    let nodes = parse_subscription_content(yaml, "sub-id").expect("subscription parse failed");
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].subscription_id.as_deref(), Some("sub-id"));
}

#[test]
fn base64_clash_subscription_is_detected() {
    let yaml = "proxies:\n  - name: Node\n    type: trojan\n    server: t.example.com\n    port: 443\n    password: pw\n";
    let encoded = base64::engine::general_purpose::STANDARD.encode(yaml.as_bytes());
    let nodes = parse_subscription_content(&encoded, "sub").expect("parse failed");
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].name, "Node");
}

#[test]
fn hand_written_profile_passes_singbox_check() {
    let settings = AppSettings::default();
    let profile = serde_json::json!({
        "log": { "level": "info" },
        "dns": {
            "servers": [ { "type": "local", "tag": "local" } ],
            "final": "local"
        },
        "inbounds": [
            { "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080 }
        ],
        "outbounds": [
            { "type": "direct", "tag": "direct" },
            {
                "type": "vless",
                "tag": "vless-out",
                "server": "1.2.3.4",
                "server_port": 443,
                "uuid": UUID,
                "tls": { "enabled": true, "server_name": "example.com" }
            },
            { "type": "selector", "tag": "proxy", "outbounds": ["vless-out", "direct"] }
        ],
        "route": { "final": "proxy", "default_domain_resolver": "local" }
    });

    let built =
        SingboxConfigBuilder::build_from_profile(&settings, &profile.to_string(), false)
            .expect("profile build failed");
    assert_eq!(
        built.value["experimental"]["clash_api"]["secret"],
        settings.clash_api_secret
    );
    check_with_singbox("profile", &built.value);
}

#[test]
fn dns_variants_all_pass_singbox_check() {
    let specs = [
        ("udp", "udp://8.8.8.8", "local"),
        ("tcp", "tcp://8.8.8.8", "local"),
        ("tls", "tls://1.1.1.1", "udp://192.168.1.1"),
        ("https", "https://dns.google/dns-query", "tcp://9.9.9.9"),
        ("quic", "quic://dns.adguard.com", "local"),
        ("h3", "h3://1.1.1.1/dns-query", "local"),
        ("dhcp", "https://1.1.1.1/dns-query", "dhcp://auto"),
    ];

    let store = store_from_uris(&[format!(
        "vless://{UUID}@1.2.3.4:443?security=tls&sni=a.example.com#Node"
    )]);

    for (label, remote, direct) in specs {
        let mut settings = AppSettings::default();
        settings.remote_dns = remote.to_string();
        settings.direct_dns = direct.to_string();
        let built = SingboxConfigBuilder::build(&settings, &store).expect("build failed");
        check_with_singbox(&format!("dns-{label}"), &built.value);
    }
}

#[test]
fn multiplex_and_udp_over_tcp_survive_a_round_trip_through_storage() {
    let mut node = parse_proxy_uri(&format!(
        "ss://YWVzLTI1Ni1nY206c2VjcmV0@s.example.com:8388?uot=1#SS"
    ))
    .expect("parse failed");
    node.multiplex = Some(MultiplexConfig {
        enabled: true,
        protocol: MultiplexProtocol::Smux,
        max_connections: Some(4),
        min_streams: Some(2),
        max_streams: Some(16),
        padding: true,
        brutal_up_mbps: Some(20),
        brutal_down_mbps: Some(80),
    });
    node.udp_over_tcp = Some(UdpOverTcpConfig {
        enabled: true,
        version: Some(1),
    });

    let encoded = serde_json::to_string(&node).expect("serialize failed");
    let decoded: ProxyNode = serde_json::from_str(&encoded).expect("deserialize failed");
    assert_eq!(decoded.multiplex, node.multiplex);
    assert_eq!(decoded.udp_over_tcp, node.udp_over_tcp);

    let mut store = ProfileStore::default();
    store.add_or_update_node(decoded);
    let built = SingboxConfigBuilder::build(&AppSettings::default(), &store).expect("build failed");
    let outbound = built.value["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["type"] == "shadowsocks")
        .unwrap();
    assert_eq!(outbound["multiplex"]["max_connections"], 4);
    assert_eq!(outbound["udp_over_tcp"]["version"], 1);
    check_with_singbox("mux-uot", &built.value);
}

#[test]
fn profile_metadata_round_trips_through_the_store() {
    let mut store = ProfileStore::default();
    let profile = ConfigProfile::remote(
        "Remote".to_string(),
        "https://example.com/config.json".to_string(),
    );
    let id = profile.id.clone();
    store.config_profiles.push(profile);

    let encoded = serde_json::to_string(&store).expect("serialize failed");
    let decoded: ProfileStore = serde_json::from_str(&encoded).expect("deserialize failed");
    let restored = decoded.config_profile(&id).expect("profile lost");
    assert_eq!(
        restored.remote_url.as_deref(),
        Some("https://example.com/config.json")
    );
}

#[test]
fn dumps_config_for_manual_inspection() {
    let Some(output) = std::env::var_os("RUSTYBIRD_CONFIG_DUMP") else {
        return;
    };
    let mut settings = AppSettings::default();
    settings.tun_mode = true;
    settings.group_mode = GroupMode::UrlTest;
    let store = store_from_uris(&every_supported_uri());
    let built = SingboxConfigBuilder::build(&settings, &store).expect("build failed");
    std::fs::write(output, serde_json::to_string_pretty(&built.value).unwrap()).unwrap();
}
