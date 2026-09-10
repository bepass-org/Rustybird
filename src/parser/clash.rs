use anyhow::{Result, anyhow};
use serde::Deserialize;
use serde_yaml::Value;
use std::collections::HashMap;

use crate::parser::node::{
    AnyTlsConfig, EchConfig, HttpProxyConfig, HysteriaConfig, Hysteria2Config, Hysteria2ObfsType,
    MultiplexConfig, MultiplexProtocol, ProtocolConfig, ProtocolType, ProxyNode, RealityConfig,
    ShadowTlsConfig, ShadowsocksConfig, SnellConfig, SocksConfig, SshConfig, TlsConfig,
    TransportConfig, TransportType, TrojanConfig, TuicConfig, TuicCongestionControl,
    TuicUdpRelayMode, UdpOverTcpConfig, UtlsFingerprint, VlessConfig, VmessConfig, WireguardConfig,
};
use crate::parser::uri::{is_hex_short_id, normalize_vmess_security};

#[derive(Debug, Deserialize)]
struct ClashConfig {
    proxies: Option<Vec<HashMap<String, Value>>>,
}

pub fn parse_clash_yaml(yaml_content: &str) -> Result<Vec<ProxyNode>> {
    let clash: ClashConfig = serde_yaml::from_str(yaml_content)?;
    let proxies = clash
        .proxies
        .ok_or_else(|| anyhow!("no proxies section in Clash configuration"))?;

    let nodes: Vec<ProxyNode> = proxies.iter().filter_map(parse_clash_proxy_map).collect();

    if nodes.is_empty() {
        return Err(anyhow!("no supported proxies found in Clash configuration"));
    }
    Ok(nodes)
}

fn get_str(map: &HashMap<String, Value>, key: &str) -> Option<String> {
    map.get(key).and_then(|v| match v {
        Value::String(s) => Some(s.trim().to_string()).filter(|s| !s.is_empty()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    })
}

fn get_any_str(map: &HashMap<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| get_str(map, key))
}

fn get_u16(map: &HashMap<String, Value>, key: &str) -> Option<u16> {
    map.get(key).and_then(|v| match v {
        Value::Number(n) => n.as_u64().and_then(|x| u16::try_from(x).ok()),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    })
}

fn get_u32(map: &HashMap<String, Value>, key: &str) -> Option<u32> {
    map.get(key).and_then(|v| match v {
        Value::Number(n) => n.as_u64().and_then(|x| u32::try_from(x).ok()),
        Value::String(s) => parse_leading_u32(s.trim()),
        _ => None,
    })
}

fn get_any_u32(map: &HashMap<String, Value>, keys: &[&str]) -> Option<u32> {
    keys.iter().find_map(|key| get_u32(map, key))
}

fn parse_leading_u32(value: &str) -> Option<u32> {
    let digits: String = value.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

fn get_bool(map: &HashMap<String, Value>, key: &str) -> bool {
    map.get(key)
        .map(|v| match v {
            Value::Bool(b) => *b,
            Value::Number(n) => n.as_u64().unwrap_or(0) != 0,
            Value::String(s) => matches!(s.trim(), "1" | "true" | "yes"),
            _ => false,
        })
        .unwrap_or(false)
}

fn get_any_bool(map: &HashMap<String, Value>, keys: &[&str]) -> bool {
    keys.iter().any(|key| get_bool(map, key))
}

fn get_string_list(map: &HashMap<String, Value>, key: &str) -> Vec<String> {
    match map.get(key) {
        Some(Value::Sequence(items)) => items
            .iter()
            .filter_map(|v| match v {
                Value::String(s) => Some(s.trim().to_string()),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            })
            .filter(|s| !s.is_empty())
            .collect(),
        Some(Value::String(s)) => s
            .split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect(),
        Some(Value::Number(n)) => vec![n.to_string()],
        _ => Vec::new(),
    }
}

fn section(map: &HashMap<String, Value>, name: &str) -> Option<HashMap<String, Value>> {
    let mapping = map.get(name)?.as_mapping()?;
    let mut result = HashMap::new();
    for (key, value) in mapping {
        if let Some(key) = key.as_str() {
            result.insert(key.trim().to_ascii_lowercase(), value.clone());
        }
    }
    Some(result)
}

fn mapping_str(map: &HashMap<String, Value>, section_name: &str, key: &str) -> Option<String> {
    section(map, section_name).and_then(|inner| get_str(&inner, key))
}

fn section_header_host(map: &HashMap<String, Value>, section_name: &str) -> Option<String> {
    let inner = section(map, section_name)?;
    let headers = inner.get("headers")?.as_mapping()?;
    for (key, value) in headers {
        if key
            .as_str()
            .map(|k| k.eq_ignore_ascii_case("host"))
            .unwrap_or(false)
        {
            return match value {
                Value::String(s) => Some(s.trim().to_string()).filter(|s| !s.is_empty()),
                Value::Sequence(items) => items
                    .first()
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
                _ => None,
            };
        }
    }
    None
}

fn section_headers(map: &HashMap<String, Value>, section_name: &str) -> Vec<(String, String)> {
    let Some(inner) = section(map, section_name) else {
        return Vec::new();
    };
    let Some(headers) = inner.get("headers").and_then(|v| v.as_mapping()) else {
        return Vec::new();
    };
    let mut result = Vec::new();
    for (key, value) in headers {
        let Some(name) = key.as_str() else { continue };
        if name.eq_ignore_ascii_case("host") {
            continue;
        }
        let text = match value {
            Value::String(s) => Some(s.trim().to_string()),
            Value::Sequence(items) => items.first().and_then(|v| v.as_str()).map(str::to_string),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        };
        if let Some(text) = text.filter(|t| !t.is_empty()) {
            result.push((name.trim().to_string(), text));
        }
    }
    result
}

fn build_multiplex(p: &HashMap<String, Value>) -> Option<MultiplexConfig> {
    let smux = section(p, "smux")?;
    if !get_bool(&smux, "enabled") {
        return None;
    }
    let brutal = section(&smux, "brutal-opts");
    Some(MultiplexConfig {
        enabled: true,
        protocol: get_str(&smux, "protocol")
            .and_then(|p| MultiplexProtocol::parse(&p))
            .unwrap_or_default(),
        max_connections: get_u32(&smux, "max-connections"),
        min_streams: get_u32(&smux, "min-streams"),
        max_streams: get_u32(&smux, "max-streams"),
        padding: get_bool(&smux, "padding"),
        brutal_up_mbps: brutal
            .as_ref()
            .filter(|b| get_bool(b, "enabled"))
            .and_then(|b| get_u32(b, "up")),
        brutal_down_mbps: brutal
            .as_ref()
            .filter(|b| get_bool(b, "enabled"))
            .and_then(|b| get_u32(b, "down")),
    })
}

fn build_udp_over_tcp(p: &HashMap<String, Value>) -> Option<UdpOverTcpConfig> {
    if !get_bool(p, "udp-over-tcp") {
        return None;
    }
    Some(UdpOverTcpConfig {
        enabled: true,
        version: get_u32(p, "udp-over-tcp-version").map(|v| v as u8),
    })
}

fn build_ech(p: &HashMap<String, Value>) -> Option<EchConfig> {
    let ech = section(p, "ech-opts")?;
    if !get_bool(&ech, "enable") && !get_bool(&ech, "enabled") {
        return None;
    }
    Some(EchConfig {
        enabled: true,
        config: get_str(&ech, "config").map(|v| vec![v]).unwrap_or_default(),
        config_path: None,
        query_server_name: None,
    })
}

fn build_transport(p: &HashMap<String, Value>, sni: Option<&String>) -> TransportConfig {
    let network = get_str(p, "network").unwrap_or_else(|| "tcp".to_string());
    let mut transport_type = TransportType::parse(&network);
    if transport_type == TransportType::Tcp {
        if let Some(http_opts) = section(p, "http-opts") {
            if !http_opts.is_empty() {
                transport_type = TransportType::Http;
            }
        }
    }

    let ws_host = section_header_host(p, "ws-opts");
    let http_host = get_string_list(p, "http-opts").first().cloned().or_else(|| {
        section(p, "http-opts")
            .map(|opts| get_string_list(&opts, "host"))
            .and_then(|hosts| hosts.first().cloned())
    });
    let h2_host = section(p, "h2-opts")
        .map(|opts| get_string_list(&opts, "host"))
        .and_then(|hosts| hosts.first().cloned());

    let ws_opts = section(p, "ws-opts");
    let headers = match transport_type {
        TransportType::Ws => section_headers(p, "ws-opts"),
        TransportType::Http => section_headers(p, "http-opts"),
        TransportType::HttpUpgrade => section_headers(p, "ws-opts"),
        _ => Vec::new(),
    };

    TransportConfig {
        transport_type,
        path: mapping_str(p, "ws-opts", "path")
            .or_else(|| mapping_str(p, "http-opts", "path"))
            .or_else(|| mapping_str(p, "h2-opts", "path"))
            .or_else(|| get_str(p, "ws-path")),
        service_name: mapping_str(p, "grpc-opts", "grpc-service-name"),
        host: ws_host
            .or(http_host)
            .or(h2_host)
            .or_else(|| get_str(p, "servername"))
            .or_else(|| sni.cloned()),
        method: mapping_str(p, "http-opts", "method"),
        headers,
        max_early_data: ws_opts
            .as_ref()
            .and_then(|opts| get_u32(opts, "max-early-data")),
        early_data_header_name: ws_opts
            .as_ref()
            .and_then(|opts| get_str(opts, "early-data-header-name")),
        permit_without_stream: false,
        idle_timeout: None,
    }
}

fn build_shadowsocks_plugin(p: &HashMap<String, Value>, config: &mut ShadowsocksConfig) {
    let Some(plugin) = get_str(p, "plugin") else {
        return;
    };
    let opts = section(p, "plugin-opts").unwrap_or_default();

    match plugin.to_ascii_lowercase().as_str() {
        "obfs" | "obfs-local" | "simple-obfs" => {
            let mode = get_str(&opts, "mode").unwrap_or_else(|| "http".to_string());
            let mut spec = format!("obfs={}", mode);
            if let Some(host) = get_str(&opts, "host") {
                spec.push_str(&format!(";obfs-host={}", host));
            }
            config.plugin = Some("obfs-local".to_string());
            config.plugin_opts = Some(spec);
        }
        "v2ray-plugin" => {
            let mode = get_str(&opts, "mode").unwrap_or_else(|| "websocket".to_string());
            let mut spec = format!("mode={}", mode);
            if let Some(host) = get_str(&opts, "host") {
                spec.push_str(&format!(";host={}", host));
            }
            if let Some(path) = get_str(&opts, "path") {
                spec.push_str(&format!(";path={}", path));
            }
            if get_bool(&opts, "tls") {
                spec.push_str(";tls");
            }
            config.plugin = Some("v2ray-plugin".to_string());
            config.plugin_opts = Some(spec);
        }
        "shadow-tls" => {
            if let Some(password) = get_str(&opts, "password") {
                config.shadow_tls = Some(ShadowTlsConfig {
                    version: get_u32(&opts, "version").unwrap_or(3) as u8,
                    password,
                    server: None,
                    port: None,
                    server_name: get_str(&opts, "host"),
                    utls: get_str(p, "client-fingerprint").map(|fp| UtlsFingerprint::parse(&fp)),
                });
            }
        }
        _ => {}
    }
}

fn parse_clash_proxy_map(p: &HashMap<String, Value>) -> Option<ProxyNode> {
    let name = get_str(p, "name")?;
    let proxy_type = get_str(p, "type")?.to_ascii_lowercase();
    let server = get_str(p, "server")?;
    let port = get_u16(p, "port")
        .or_else(|| get_u16(p, "listen-port"))
        .filter(|p| *p > 0)
        .or_else(|| {
            if proxy_type == "wireguard" {
                Some(51820)
            } else {
                None
            }
        })?;

    let transport = build_transport(p, get_str(p, "sni").as_ref());
    let sni = get_str(p, "sni").or_else(|| get_str(p, "servername"));
    let insecure = get_any_bool(p, &["skip-cert-verify", "insecure"]);
    let alpn = get_string_list(p, "alpn");
    let utls = get_str(p, "client-fingerprint").map(|fp| UtlsFingerprint::parse(&fp));

    let reality = section(p, "reality-opts").and_then(|opts| {
        let public_key = get_str(&opts, "public-key")?;
        Some(RealityConfig {
            public_key,
            short_id: get_str(&opts, "short-id")
                .filter(|s| is_hex_short_id(s))
                .unwrap_or_default(),
        })
    });

    let implicit_tls = matches!(
        proxy_type.as_str(),
        "hysteria" | "hysteria2" | "hy2" | "tuic" | "trojan" | "anytls"
    );
    let tls_enabled = implicit_tls || get_bool(p, "tls") || reality.is_some();

    let default_alpn: Vec<String> = if alpn.is_empty()
        && matches!(proxy_type.as_str(), "hysteria" | "hysteria2" | "hy2")
    {
        vec!["h3".to_string()]
    } else {
        alpn
    };

    let tls = TlsConfig {
        enabled: tls_enabled,
        server_name: sni.clone().or_else(|| {
            if tls_enabled {
                Some(server.clone())
            } else {
                None
            }
        }),
        insecure,
        disable_sni: get_bool(p, "disable-sni"),
        alpn: default_alpn,
        min_version: None,
        max_version: None,
        certificate: Vec::new(),
        certificate_path: get_str(p, "ca"),
        fragment: false,
        record_fragment: false,
        utls: if reality.is_some() {
            Some(utls.unwrap_or_default())
        } else {
            utls
        },
        reality,
        ech: build_ech(p),
    };

    let multiplex = build_multiplex(p);
    let udp_over_tcp = build_udp_over_tcp(p);

    let mut node = match proxy_type.as_str() {
        "vless" => {
            let uuid = get_str(p, "uuid")?;
            let mut node = ProxyNode::new(
                name,
                server,
                port,
                ProtocolType::Vless,
                ProtocolConfig::Vless(VlessConfig {
                    uuid,
                    flow: get_str(p, "flow"),
                    packet_encoding: get_str(p, "packet-encoding"),
                }),
            );
            node.tls = tls;
            node.transport = transport;
            node
        }
        "vmess" => {
            let uuid = get_str(p, "uuid")?;
            let mut node = ProxyNode::new(
                name,
                server,
                port,
                ProtocolType::Vmess,
                ProtocolConfig::Vmess(VmessConfig {
                    uuid,
                    alter_id: get_any_u32(p, &["alterId", "alterid"]).unwrap_or(0),
                    security: normalize_vmess_security(get_str(p, "cipher")),
                    global_padding: get_bool(p, "global-padding"),
                    authenticated_length: get_bool(p, "authenticated-length"),
                    packet_encoding: get_str(p, "packet-encoding"),
                }),
            );
            node.tls = tls;
            node.transport = transport;
            node
        }
        "trojan" => {
            let password = get_str(p, "password")?;
            let mut node = ProxyNode::new(
                name,
                server,
                port,
                ProtocolType::Trojan,
                ProtocolConfig::Trojan(TrojanConfig { password }),
            );
            node.tls = tls;
            node.transport = transport;
            node
        }
        "ss" | "shadowsocks" => {
            let method = get_str(p, "cipher")?.to_ascii_lowercase();
            let mut config = ShadowsocksConfig {
                method,
                password: get_str(p, "password").unwrap_or_default(),
                plugin: None,
                plugin_opts: None,
                shadow_tls: None,
            };
            build_shadowsocks_plugin(p, &mut config);
            ProxyNode::new(
                name,
                server,
                port,
                ProtocolType::Shadowsocks,
                ProtocolConfig::Shadowsocks(config),
            )
        }
        "hysteria" => {
            let mut node = ProxyNode::new(
                name,
                server,
                port,
                ProtocolType::Hysteria,
                ProtocolConfig::Hysteria(HysteriaConfig {
                    auth_str: get_any_str(p, &["auth-str", "auth_str", "auth-string"]),
                    auth_base64: get_str(p, "auth"),
                    up_mbps: get_any_u32(p, &["up", "up-speed", "up_mbps"]),
                    down_mbps: get_any_u32(p, &["down", "down-speed", "down_mbps"]),
                    obfs: get_str(p, "obfs"),
                    disable_mtu_discovery: get_bool(p, "disable-mtu-discovery"),
                }),
            );
            node.tls = tls;
            node
        }
        "hysteria2" | "hy2" => {
            let password = get_any_str(p, &["password", "auth"])?;
            let obfs = get_str(p, "obfs").and_then(|o| Hysteria2ObfsType::parse(&o));
            let obfs_password = get_str(p, "obfs-password");
            let mut node = ProxyNode::new(
                name,
                server,
                port,
                ProtocolType::Hysteria2,
                ProtocolConfig::Hysteria2(Hysteria2Config {
                    password,
                    up_mbps: get_u32(p, "up").filter(|v| *v > 0),
                    down_mbps: get_u32(p, "down").filter(|v| *v > 0),
                    obfs_password: if obfs.is_some() { obfs_password } else { None },
                    obfs,
                    server_ports: get_string_list(p, "ports"),
                    hop_interval: get_str(p, "hop-interval"),
                }),
            );
            node.tls = tls;
            node
        }
        "tuic" => {
            let uuid = get_str(p, "uuid")?;
            let mut node = ProxyNode::new(
                name,
                server,
                port,
                ProtocolType::Tuic,
                ProtocolConfig::Tuic(TuicConfig {
                    uuid,
                    password: get_str(p, "password").unwrap_or_default(),
                    congestion_control: get_any_str(
                        p,
                        &["congestion-controller", "congestion-control"],
                    )
                    .and_then(|v| TuicCongestionControl::parse(&v)),
                    udp_relay_mode: get_str(p, "udp-relay-mode")
                        .and_then(|v| TuicUdpRelayMode::parse(&v)),
                    zero_rtt_handshake: get_any_bool(p, &["reduce-rtt", "zero-rtt-handshake"]),
                }),
            );
            node.tls = tls;
            node
        }
        "anytls" => {
            let password = get_str(p, "password")?;
            let mut node = ProxyNode::new(
                name,
                server,
                port,
                ProtocolType::AnyTls,
                ProtocolConfig::AnyTls(AnyTlsConfig {
                    password,
                    idle_session_check_interval: get_str(p, "idle-session-check-interval"),
                    idle_session_timeout: get_str(p, "idle-session-timeout"),
                    min_idle_session: get_u32(p, "min-idle-session"),
                }),
            );
            node.tls = tls;
            node
        }
        "snell" => {
            let psk = get_str(p, "psk")?;
            let obfs_opts = section(p, "obfs-opts").unwrap_or_default();
            let version = get_u32(p, "version").unwrap_or(4) as u8;
            if !matches!(version, 4 | 6) {
                return None;
            }
            ProxyNode::new(
                name,
                server,
                port,
                ProtocolType::Snell,
                ProtocolConfig::Snell(SnellConfig {
                    psk,
                    version,
                    obfs_mode: get_str(&obfs_opts, "mode"),
                    obfs_host: get_str(&obfs_opts, "host"),
                    user_key: get_any_str(p, &["userkey", "user-key"]),
                    mode: get_str(p, "mode"),
                }),
            )
        }
        "ssh" => {
            let user = get_any_str(p, &["username", "user"])?;
            ProxyNode::new(
                name,
                server,
                port,
                ProtocolType::Ssh,
                ProtocolConfig::Ssh(SshConfig {
                    user,
                    password: get_str(p, "password"),
                    private_key: get_string_list(p, "private-key"),
                    private_key_path: get_str(p, "private-key-path"),
                    private_key_passphrase: get_str(p, "private-key-passphrase"),
                    host_key: get_string_list(p, "host-key"),
                    host_key_algorithms: get_string_list(p, "host-key-algorithms"),
                    client_version: get_str(p, "client-version"),
                }),
            )
        }
        "socks5" | "socks" => ProxyNode::new(
            name,
            server,
            port,
            ProtocolType::Socks,
            ProtocolConfig::Socks(SocksConfig {
                version: None,
                username: get_str(p, "username"),
                password: get_str(p, "password"),
            }),
        ),
        "http" | "https" => {
            let mut node = ProxyNode::new(
                name,
                server,
                port,
                ProtocolType::Http,
                ProtocolConfig::Http(HttpProxyConfig {
                    username: get_str(p, "username"),
                    password: get_str(p, "password"),
                    path: None,
                    headers: Vec::new(),
                }),
            );
            if tls_enabled || proxy_type == "https" {
                node.tls = TlsConfig {
                    enabled: true,
                    ..tls
                };
            }
            node
        }
        "wireguard" => {
            let private_key = get_any_str(p, &["private-key", "privatekey"])?;
            let peer_public_key = get_any_str(p, &["public-key", "publickey"])?;
            let mut local_address = get_string_list(p, "ip");
            if local_address.is_empty() {
                if let Some(ip) = get_str(p, "ip") {
                    local_address.push(normalize_wireguard_address(&ip, false));
                }
            } else {
                local_address = local_address
                    .iter()
                    .map(|addr| normalize_wireguard_address(addr, false))
                    .collect();
            }
            if let Some(ipv6) = get_str(p, "ipv6") {
                local_address.push(normalize_wireguard_address(&ipv6, true));
            }
            if local_address.is_empty() {
                return None;
            }
            ProxyNode::new(
                name,
                server,
                port,
                ProtocolType::Wireguard,
                ProtocolConfig::Wireguard(WireguardConfig {
                    private_key,
                    peer_public_key,
                    pre_shared_key: get_any_str(p, &["pre-shared-key", "preshared-key"]),
                    local_address,
                    mtu: get_u32(p, "mtu"),
                    reserved: parse_clash_reserved(p.get("reserved")),
                    allowed_ips: get_string_list(p, "allowed-ips"),
                    persistent_keepalive_interval: get_u32(p, "persistent-keepalive"),
                    system_interface: false,
                }),
            )
        }
        _ => return None,
    };

    if node.protocol.supports_multiplex() {
        node.multiplex = multiplex;
    }
    if node.protocol.supports_udp_over_tcp() {
        node.udp_over_tcp = udp_over_tcp;
    }
    if !get_bool(p, "udp") && matches!(node.protocol, ProtocolType::Shadowsocks) {
        node.network = None;
    }
    Some(node)
}

fn normalize_wireguard_address(address: &str, ipv6: bool) -> String {
    let trimmed = address.trim();
    if trimmed.contains('/') {
        return trimmed.to_string();
    }
    if ipv6 || trimmed.contains(':') {
        format!("{}/128", trimmed)
    } else {
        format!("{}/32", trimmed)
    }
}

fn parse_clash_reserved(value: Option<&Value>) -> Option<Vec<u8>> {
    match value? {
        Value::Sequence(items) => {
            let bytes: Vec<u8> = items
                .iter()
                .filter_map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok()))
                .collect();
            if bytes.len() == 3 { Some(bytes) } else { None }
        }
        Value::String(s) => crate::parser::uri::decode_b64(s)
            .ok()
            .filter(|bytes| bytes.len() == 3),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn single(yaml: &str) -> ProxyNode {
        let nodes = parse_clash_yaml(yaml).expect("parse failed");
        assert_eq!(nodes.len(), 1, "expected exactly one node");
        nodes.into_iter().next().unwrap()
    }

    #[test]
    fn parses_anytls() {
        let node = single(
            r#"
proxies:
  - name: AnyTLS
    type: anytls
    server: a.example.com
    port: 8443
    password: pw
    sni: a.example.com
    client-fingerprint: firefox
"#,
        );
        assert_eq!(node.protocol, ProtocolType::AnyTls);
        assert!(node.tls.enabled);
        assert_eq!(node.tls.utls, Some(UtlsFingerprint::Firefox));
        match node.config {
            ProtocolConfig::AnyTls(config) => assert_eq!(config.password, "pw"),
            _ => panic!("wrong protocol"),
        }
    }

    #[test]
    fn parses_snell_and_rejects_unsupported_versions() {
        let node = single(
            r#"
proxies:
  - name: Snell
    type: snell
    server: s.example.com
    port: 44046
    psk: psk123
    version: 4
    obfs-opts:
      mode: tls
      host: bing.com
"#,
        );
        match node.config {
            ProtocolConfig::Snell(config) => {
                assert_eq!(config.version, 4);
                assert_eq!(config.obfs_mode.as_deref(), Some("tls"));
                assert_eq!(config.obfs_host.as_deref(), Some("bing.com"));
            }
            _ => panic!("wrong protocol"),
        }

        let unsupported = r#"
proxies:
  - name: Snell3
    type: snell
    server: s.example.com
    port: 44046
    psk: psk123
    version: 3
"#;
        assert!(parse_clash_yaml(unsupported).is_err());
    }

    #[test]
    fn parses_ssh_socks_and_http() {
        let nodes = parse_clash_yaml(
            r#"
proxies:
  - name: SSH
    type: ssh
    server: ssh.example.com
    port: 22
    username: root
    password: secret
  - name: SOCKS
    type: socks5
    server: socks.example.com
    port: 1080
    username: u
    password: p
  - name: HTTPS
    type: http
    server: http.example.com
    port: 8443
    tls: true
    username: u
    password: p
"#,
        )
        .expect("parse failed");
        assert_eq!(nodes.len(), 3);
        assert_eq!(nodes[0].protocol, ProtocolType::Ssh);
        assert_eq!(nodes[1].protocol, ProtocolType::Socks);
        assert_eq!(nodes[2].protocol, ProtocolType::Http);
        assert!(nodes[2].tls.enabled);
    }

    #[test]
    fn parses_hysteria_v1() {
        let node = single(
            r#"
proxies:
  - name: Hysteria
    type: hysteria
    server: h.example.com
    port: 443
    auth-str: token
    up: 50
    down: 200
    obfs: xyz
    sni: h.example.com
"#,
        );
        assert_eq!(node.protocol, ProtocolType::Hysteria);
        assert_eq!(node.tls.alpn, vec!["h3".to_string()]);
        match node.config {
            ProtocolConfig::Hysteria(config) => {
                assert_eq!(config.auth_str.as_deref(), Some("token"));
                assert_eq!(config.up_mbps, Some(50));
                assert_eq!(config.obfs.as_deref(), Some("xyz"));
            }
            _ => panic!("wrong protocol"),
        }
    }

    #[test]
    fn parses_smux_and_udp_over_tcp() {
        let node = single(
            r#"
proxies:
  - name: SS
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: pw
    udp-over-tcp: true
    udp-over-tcp-version: 1
    smux:
      enabled: true
      protocol: yamux
      max-streams: 16
      padding: true
      brutal-opts:
        enabled: true
        up: 50
        down: 100
"#,
        );
        let multiplex = node.multiplex.expect("missing multiplex");
        assert_eq!(multiplex.protocol, MultiplexProtocol::Yamux);
        assert_eq!(multiplex.max_streams, Some(16));
        assert!(multiplex.padding);
        assert_eq!(multiplex.brutal_down_mbps, Some(100));
        let uot = node.udp_over_tcp.expect("missing udp over tcp");
        assert_eq!(uot.version, Some(1));
    }

    #[test]
    fn parses_shadowsocks_obfs_plugin() {
        let node = single(
            r#"
proxies:
  - name: SS obfs
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-128-gcm
    password: pw
    plugin: obfs
    plugin-opts:
      mode: http
      host: cdn.example.com
"#,
        );
        match node.config {
            ProtocolConfig::Shadowsocks(config) => {
                assert_eq!(config.plugin.as_deref(), Some("obfs-local"));
                assert_eq!(
                    config.plugin_opts.as_deref(),
                    Some("obfs=http;obfs-host=cdn.example.com")
                );
            }
            _ => panic!("wrong protocol"),
        }
    }

    #[test]
    fn parses_shadowsocks_shadow_tls_plugin() {
        let node = single(
            r#"
proxies:
  - name: SS stls
    type: ss
    server: ss.example.com
    port: 443
    cipher: 2022-blake3-aes-128-gcm
    password: pw
    client-fingerprint: chrome
    plugin: shadow-tls
    plugin-opts:
      host: www.microsoft.com
      password: stlspw
      version: 3
"#,
        );
        match node.config {
            ProtocolConfig::Shadowsocks(config) => {
                let shadow_tls = config.shadow_tls.expect("missing shadow-tls");
                assert_eq!(shadow_tls.version, 3);
                assert_eq!(shadow_tls.password, "stlspw");
                assert_eq!(shadow_tls.server_name.as_deref(), Some("www.microsoft.com"));
            }
            _ => panic!("wrong protocol"),
        }
    }

    #[test]
    fn parses_wireguard_with_ipv6_and_reserved() {
        let node = single(
            r#"
proxies:
  - name: WG
    type: wireguard
    server: wg.example.com
    port: 51820
    private-key: uCRsuACIPWUXQAi0h2/aD6rLLqYfoHpMguB362WzlHQ=
    public-key: gK3h8wLb3tS40GDsJeMYbh5z8U2ktfcYv+5F1yzTyRQ=
    ip: 10.0.0.2
    ipv6: fd00::2
    mtu: 1408
    reserved: [1, 2, 3]
"#,
        );
        match node.config {
            ProtocolConfig::Wireguard(config) => {
                assert_eq!(
                    config.local_address,
                    vec!["10.0.0.2/32".to_string(), "fd00::2/128".to_string()]
                );
                assert_eq!(config.reserved, Some(vec![1, 2, 3]));
                assert_eq!(config.mtu, Some(1408));
            }
            _ => panic!("wrong protocol"),
        }
    }

    #[test]
    fn parses_vless_reality_with_grpc() {
        let node = single(
            r#"
proxies:
  - name: VLESS
    type: vless
    server: v.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-1234567890ab
    flow: xtls-rprx-vision
    tls: true
    servername: www.microsoft.com
    network: grpc
    client-fingerprint: chrome
    grpc-opts:
      grpc-service-name: GunService
    reality-opts:
      public-key: ozBIkHZm7eCLgeb9WhyS-Im6DURA2FrHmx8E16HYO2Y
      short-id: a1b2c3d4
"#,
        );
        assert_eq!(node.transport.transport_type, TransportType::Grpc);
        assert_eq!(node.transport.service_name.as_deref(), Some("GunService"));
        let reality = node.tls.reality.expect("missing reality");
        assert_eq!(reality.short_id, "a1b2c3d4");
    }

    #[test]
    fn parses_websocket_early_data_and_extra_headers() {
        let node = single(
            r#"
proxies:
  - name: VMess
    type: vmess
    server: vm.example.com
    port: 443
    uuid: 12345678-1234-1234-1234-1234567890ab
    alterId: 0
    cipher: auto
    tls: true
    network: ws
    ws-opts:
      path: /ray
      max-early-data: 2048
      early-data-header-name: Sec-WebSocket-Protocol
      headers:
        Host: cdn.example.com
        User-Agent: rustybird
"#,
        );
        assert_eq!(node.transport.max_early_data, Some(2048));
        assert_eq!(node.transport.host.as_deref(), Some("cdn.example.com"));
        assert_eq!(
            node.transport.headers,
            vec![("User-Agent".to_string(), "rustybird".to_string())]
        );
    }

    #[test]
    fn skips_unsupported_proxy_types() {
        let yaml = r#"
proxies:
  - name: Broken
    type: unknown-protocol
    server: x.example.com
    port: 443
  - name: Good
    type: trojan
    server: t.example.com
    port: 443
    password: pw
"#;
        let nodes = parse_clash_yaml(yaml).expect("parse failed");
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "Good");
    }
}
