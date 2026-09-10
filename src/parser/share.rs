use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};

use crate::parser::node::{ProtocolConfig, ProxyNode, TransportType};

const COMPONENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'+')
    .add(b'/')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}')
    .add(b':');

fn encode(value: &str) -> String {
    utf8_percent_encode(value, COMPONENT).to_string()
}

const FRAGMENT: &AsciiSet = &CONTROLS.add(b' ').add(b'#').add(b'%');

fn encode_fragment(value: &str) -> String {
    utf8_percent_encode(value, FRAGMENT).to_string()
}

fn host_for_uri(node: &ProxyNode) -> String {
    if node.server.contains(':') && !node.server.starts_with('[') {
        format!("[{}]", node.server)
    } else {
        node.server.clone()
    }
}

struct Query(Vec<(String, String)>);

impl Query {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn push(&mut self, key: &str, value: &str) {
        if !value.is_empty() {
            self.0.push((key.to_string(), value.to_string()));
        }
    }

    fn push_flag(&mut self, key: &str, value: bool) {
        if value {
            self.0.push((key.to_string(), "1".to_string()));
        }
    }

    fn render(&self) -> String {
        if self.0.is_empty() {
            return String::new();
        }
        let body = self
            .0
            .iter()
            .map(|(key, value)| format!("{}={}", key, encode(value)))
            .collect::<Vec<_>>()
            .join("&");
        format!("?{}", body)
    }
}

fn tls_query(node: &ProxyNode, query: &mut Query) {
    if let Some(server_name) = node
        .tls
        .server_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        query.push("sni", server_name);
    }
    if !node.tls.alpn.is_empty() {
        query.push("alpn", &node.tls.alpn.join(","));
    }
    if let Some(utls) = node.tls.utls {
        query.push("fp", utls.as_str());
    }
    query.push_flag("insecure", node.tls.insecure);
    query.push_flag("fragment", node.tls.fragment);
    if let Some(reality) = &node.tls.reality {
        query.push("pbk", &reality.public_key);
        query.push("sid", &reality.short_id);
    }
}

fn transport_query(node: &ProxyNode, query: &mut Query) {
    let Some(kind) = node.transport.transport_type.singbox_type() else {
        return;
    };
    query.push("type", kind);
    if let Some(path) = node
        .transport
        .path
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        query.push("path", path);
    }
    if let Some(host) = node
        .transport
        .host
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        query.push("host", host);
    }
    if let Some(service_name) = node
        .transport
        .service_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        query.push("serviceName", service_name);
    }
}

pub fn node_share_link(node: &ProxyNode) -> Option<String> {
    let host = host_for_uri(node);
    let fragment = encode_fragment(&node.name);

    match &node.config {
        ProtocolConfig::Vless(config) => {
            let mut query = Query::new();
            query.push("encryption", "none");
            query.push(
                "security",
                if node.tls.reality.is_some() {
                    "reality"
                } else if node.tls.enabled {
                    "tls"
                } else {
                    "none"
                },
            );
            if let Some(flow) = config.flow.as_deref().filter(|f| !f.trim().is_empty()) {
                query.push("flow", flow);
            }
            tls_query(node, &mut query);
            transport_query(node, &mut query);
            Some(format!(
                "vless://{}@{}:{}{}#{}",
                encode(&config.uuid),
                host,
                node.port,
                query.render(),
                fragment
            ))
        }
        ProtocolConfig::Vmess(config) => {
            let net = match node.transport.transport_type {
                TransportType::Tcp => "tcp",
                TransportType::Ws => "ws",
                TransportType::Grpc => "grpc",
                TransportType::HttpUpgrade => "httpupgrade",
                TransportType::Http => "h2",
                TransportType::Quic => "quic",
            };
            let payload = serde_json::json!({
                "v": "2",
                "ps": node.name,
                "add": node.server,
                "port": node.port.to_string(),
                "id": config.uuid,
                "aid": config.alter_id.to_string(),
                "scy": config.security,
                "net": net,
                "host": node.transport.host.clone().unwrap_or_default(),
                "path": node.transport.path.clone().unwrap_or_default(),
                "tls": if node.tls.enabled { "tls" } else { "" },
                "sni": node.tls.server_name.clone().unwrap_or_default(),
                "alpn": node.tls.alpn.join(","),
                "fp": node.tls.utls.map(|f| f.as_str()).unwrap_or_default()
            });
            Some(format!(
                "vmess://{}",
                STANDARD.encode(payload.to_string().as_bytes())
            ))
        }
        ProtocolConfig::Trojan(config) => {
            let mut query = Query::new();
            tls_query(node, &mut query);
            transport_query(node, &mut query);
            Some(format!(
                "trojan://{}@{}:{}{}#{}",
                encode(&config.password),
                host,
                node.port,
                query.render(),
                fragment
            ))
        }
        ProtocolConfig::Shadowsocks(config) => {
            let userinfo = STANDARD.encode(format!("{}:{}", config.method, config.password));
            let mut query = Query::new();
            if let Some(plugin) = config.plugin.as_deref() {
                let spec = match config.plugin_opts.as_deref() {
                    Some(opts) if !opts.is_empty() => format!("{};{}", plugin, opts),
                    _ => plugin.to_string(),
                };
                query.push("plugin", &spec);
            }
            if let Some(shadow_tls) = &config.shadow_tls {
                let mut spec = format!(
                    "shadow-tls;password={};version={}",
                    shadow_tls.password, shadow_tls.version
                );
                if let Some(server_name) = &shadow_tls.server_name {
                    spec.push_str(&format!(";host={}", server_name));
                }
                query.push("plugin", &spec);
            }
            if node
                .udp_over_tcp
                .as_ref()
                .map(|uot| uot.enabled)
                .unwrap_or(false)
            {
                query.push_flag("uot", true);
            }
            Some(format!(
                "ss://{}@{}:{}{}#{}",
                userinfo,
                host,
                node.port,
                query.render(),
                fragment
            ))
        }
        ProtocolConfig::Hysteria2(config) => {
            let mut query = Query::new();
            tls_query(node, &mut query);
            if let Some(up) = config.up_mbps {
                query.push("up", &up.to_string());
            }
            if let Some(down) = config.down_mbps {
                query.push("down", &down.to_string());
            }
            if let Some(obfs) = config.obfs {
                query.push("obfs", obfs.as_str());
                if let Some(password) = &config.obfs_password {
                    query.push("obfs-password", password);
                }
            }
            Some(format!(
                "hysteria2://{}@{}:{}{}#{}",
                encode(&config.password),
                host,
                node.port,
                query.render(),
                fragment
            ))
        }
        ProtocolConfig::Hysteria(config) => {
            let mut query = Query::new();
            tls_query(node, &mut query);
            if let Some(auth) = &config.auth_str {
                query.push("auth", auth);
            }
            if let Some(up) = config.up_mbps {
                query.push("upmbps", &up.to_string());
            }
            if let Some(down) = config.down_mbps {
                query.push("downmbps", &down.to_string());
            }
            if let Some(obfs) = &config.obfs {
                query.push("obfs", obfs);
            }
            Some(format!(
                "hysteria://{}:{}{}#{}",
                host,
                node.port,
                query.render(),
                fragment
            ))
        }
        ProtocolConfig::Tuic(config) => {
            let mut query = Query::new();
            tls_query(node, &mut query);
            if let Some(congestion) = config.congestion_control {
                query.push("congestion_control", congestion.as_str());
            }
            if let Some(mode) = config.udp_relay_mode {
                query.push("udp_relay_mode", mode.as_str());
            }
            query.push_flag("zero_rtt_handshake", config.zero_rtt_handshake);
            Some(format!(
                "tuic://{}:{}@{}:{}{}#{}",
                encode(&config.uuid),
                encode(&config.password),
                host,
                node.port,
                query.render(),
                fragment
            ))
        }
        ProtocolConfig::AnyTls(config) => {
            let mut query = Query::new();
            tls_query(node, &mut query);
            Some(format!(
                "anytls://{}@{}:{}{}#{}",
                encode(&config.password),
                host,
                node.port,
                query.render(),
                fragment
            ))
        }
        ProtocolConfig::Snell(config) => {
            let mut query = Query::new();
            query.push("version", &config.version.to_string());
            if let Some(mode) = &config.obfs_mode {
                query.push("obfs", mode);
            }
            if let Some(obfs_host) = &config.obfs_host {
                query.push("obfs-host", obfs_host);
            }
            if let Some(mode) = &config.mode {
                query.push("mode", mode);
            }
            Some(format!(
                "snell://{}@{}:{}{}#{}",
                encode(&config.psk),
                host,
                node.port,
                query.render(),
                fragment
            ))
        }
        ProtocolConfig::Ssh(config) => {
            let credentials = match config.password.as_deref().filter(|p| !p.is_empty()) {
                Some(password) => format!("{}:{}", encode(&config.user), encode(password)),
                None => encode(&config.user),
            };
            Some(format!(
                "ssh://{}@{}:{}#{}",
                credentials, host, node.port, fragment
            ))
        }
        ProtocolConfig::Socks(config) => {
            let credentials = match (
                config.username.as_deref().filter(|u| !u.is_empty()),
                config.password.as_deref().filter(|p| !p.is_empty()),
            ) {
                (Some(user), Some(password)) => {
                    format!("{}:{}@", encode(user), encode(password))
                }
                (Some(user), None) => format!("{}@", encode(user)),
                _ => String::new(),
            };
            Some(format!(
                "socks5://{}{}:{}#{}",
                credentials, host, node.port, fragment
            ))
        }
        ProtocolConfig::Http(config) => {
            let credentials = match (
                config.username.as_deref().filter(|u| !u.is_empty()),
                config.password.as_deref().filter(|p| !p.is_empty()),
            ) {
                (Some(user), Some(password)) => {
                    format!("{}:{}@", encode(user), encode(password))
                }
                (Some(user), None) => format!("{}@", encode(user)),
                _ => String::new(),
            };
            let scheme = if node.tls.enabled { "https" } else { "http" };
            Some(format!(
                "{}://{}{}:{}#{}",
                scheme, credentials, host, node.port, fragment
            ))
        }
        ProtocolConfig::Wireguard(config) => {
            let mut query = Query::new();
            query.push("publickey", &config.peer_public_key);
            query.push("address", &config.local_address.join(","));
            if let Some(psk) = &config.pre_shared_key {
                query.push("presharedkey", psk);
            }
            if let Some(mtu) = config.mtu {
                query.push("mtu", &mtu.to_string());
            }
            if let Some(reserved) = &config.reserved {
                let rendered: Vec<String> = reserved.iter().map(|b| b.to_string()).collect();
                query.push("reserved", &rendered.join(","));
            }
            Some(format!(
                "wireguard://{}@{}:{}{}#{}",
                encode(&config.private_key),
                host,
                node.port,
                query.render(),
                fragment
            ))
        }
        ProtocolConfig::Tor(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::uri::parse_proxy_uri;

    fn round_trip(uri: &str) -> ProxyNode {
        let node = parse_proxy_uri(uri).expect("original parse failed");
        let link = node_share_link(&node).expect("no share link");
        parse_proxy_uri(&link).unwrap_or_else(|e| panic!("re-parse of {link} failed: {e}"))
    }

    #[test]
    fn vless_reality_round_trips() {
        let uri = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=ozBIkHZm7eCLgeb9WhyS-Im6DURA2FrHmx8E16HYO2Y&sid=a1b2c3d4&type=tcp#Reality%20Node";
        let node = round_trip(uri);
        assert_eq!(node.name, "Reality Node");
        assert_eq!(node.server, "1.2.3.4");
        assert_eq!(node.port, 443);
        let reality = node.tls.reality.expect("reality lost");
        assert_eq!(
            reality.public_key,
            "ozBIkHZm7eCLgeb9WhyS-Im6DURA2FrHmx8E16HYO2Y"
        );
        assert_eq!(reality.short_id, "a1b2c3d4");
        match node.config {
            ProtocolConfig::Vless(config) => {
                assert_eq!(config.flow.as_deref(), Some("xtls-rprx-vision"))
            }
            _ => panic!("wrong protocol"),
        }
    }

    #[test]
    fn websocket_trojan_round_trips() {
        let node = round_trip(
            "trojan://p%40ssword@t.example.com:443?sni=t.example.com&type=ws&path=%2Fws&host=cdn.example.com#Trojan",
        );
        assert_eq!(node.transport.transport_type, TransportType::Ws);
        assert_eq!(node.transport.path.as_deref(), Some("/ws"));
        assert_eq!(node.transport.host.as_deref(), Some("cdn.example.com"));
        match node.config {
            ProtocolConfig::Trojan(config) => assert_eq!(config.password, "p@ssword"),
            _ => panic!("wrong protocol"),
        }
    }

    #[test]
    fn shadowsocks_round_trips_with_a_base64_password() {
        let node = round_trip(
            "ss://2022-blake3-aes-256-gcm:GcRPS0j%2FpVaCTF9UZ%2FGDSPWrM6rMTMKGUEUvzC%2FJzFA%3D@s.example.com:8388#SS",
        );
        match node.config {
            ProtocolConfig::Shadowsocks(config) => {
                assert_eq!(config.method, "2022-blake3-aes-256-gcm");
                assert_eq!(config.password, "GcRPS0j/pVaCTF9UZ/GDSPWrM6rMTMKGUEUvzC/JzFA=");
            }
            _ => panic!("wrong protocol"),
        }
    }

    #[test]
    fn vmess_round_trips_through_base64_json() {
        let node = round_trip(
            "vmess://eyJ2IjoiMiIsInBzIjoiVk1lc3MiLCJhZGQiOiJ2bS5leGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6ImI4MzEzODFkLTYzMjQtNGQ1My1hZDRmLThjZGE0OGIzMDgxMSIsImFpZCI6IjAiLCJzY3kiOiJhdXRvIiwibmV0Ijoid3MiLCJob3N0Ijoidm0uZXhhbXBsZS5jb20iLCJwYXRoIjoiL3JheSIsInRscyI6InRscyJ9",
        );
        assert_eq!(node.name, "VMess");
        assert_eq!(node.transport.transport_type, TransportType::Ws);
        assert_eq!(node.transport.path.as_deref(), Some("/ray"));
        assert!(node.tls.enabled);
    }

    #[test]
    fn hysteria2_obfs_round_trips() {
        let node = round_trip(
            "hysteria2://pw@h.example.com:443?sni=h.example.com&obfs=salamander&obfs-password=xyz&up=50&down=200#HY2",
        );
        match node.config {
            ProtocolConfig::Hysteria2(config) => {
                assert_eq!(config.obfs_password.as_deref(), Some("xyz"));
                assert_eq!(config.up_mbps, Some(50));
                assert_eq!(config.down_mbps, Some(200));
            }
            _ => panic!("wrong protocol"),
        }
    }

    #[test]
    fn tuic_anytls_snell_ssh_socks_http_round_trip() {
        for uri in [
            "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pw@tu.example.com:443?sni=tu.example.com&congestion_control=bbr&udp_relay_mode=native#TUIC",
            "anytls://pw@any.example.com:8443?sni=any.example.com#AnyTLS",
            "snell://psk@sn.example.com:44046?version=4&obfs=tls&obfs-host=bing.com#Snell",
            "ssh://root:secret@ssh.example.com:22#SSH",
            "socks5://user:pass@socks.example.com:1080#SOCKS",
            "http://user:pass@proxy.example.com:8080#HTTP",
        ] {
            let original = parse_proxy_uri(uri).expect("parse failed");
            let node = round_trip(uri);
            assert_eq!(node.protocol, original.protocol, "protocol changed for {uri}");
            assert_eq!(node.server, original.server, "server changed for {uri}");
            assert_eq!(node.port, original.port, "port changed for {uri}");
            assert_eq!(node.name, original.name, "name changed for {uri}");
        }
    }

    #[test]
    fn wireguard_round_trips_with_reserved_bytes() {
        let original = parse_proxy_uri(
            "wireguard://uCRsuACIPWUXQAi0h2%2FaD6rLLqYfoHpMguB362WzlHQ%3D@wg.example.com:51820?publickey=gK3h8wLb3tS40GDsJeMYbh5z8U2ktfcYv%2B5F1yzTyRQ%3D&address=10.0.0.2%2F32&mtu=1408&reserved=1,2,3#WG",
        )
        .expect("parse failed");
        let link = node_share_link(&original).expect("no share link");
        let node = parse_proxy_uri(&link).expect("re-parse failed");
        match (node.config, original.config) {
            (ProtocolConfig::Wireguard(new), ProtocolConfig::Wireguard(old)) => {
                assert_eq!(new.private_key, old.private_key);
                assert_eq!(new.peer_public_key, old.peer_public_key);
                assert_eq!(new.local_address, old.local_address);
                assert_eq!(new.reserved, Some(vec![1, 2, 3]));
                assert_eq!(new.mtu, Some(1408));
            }
            _ => panic!("wrong protocol"),
        }
    }

    #[test]
    fn tor_nodes_have_no_share_link() {
        let node = ProxyNode::new(
            "Tor".to_string(),
            String::new(),
            0,
            crate::parser::node::ProtocolType::Tor,
            ProtocolConfig::Tor(crate::parser::node::TorConfig::default()),
        );
        assert!(node_share_link(&node).is_none());
    }
}
