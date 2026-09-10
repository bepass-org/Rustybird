use anyhow::{Result, anyhow};
use serde_json::{Map, Value, json};

use crate::parser::node::{
    EchConfig, MultiplexConfig, ProtocolConfig, ProxyNode, ShadowTlsConfig, TlsConfig,
    TransportConfig, UdpOverTcpConfig,
};

pub struct BuiltOutbound {
    pub values: Vec<Value>,
    pub is_endpoint: bool,
}

pub fn build_outbound(node: &ProxyNode, tag: &str) -> Result<BuiltOutbound> {
    if node.protocol.is_endpoint() {
        let ProtocolConfig::Wireguard(config) = &node.config else {
            return Err(anyhow!("endpoint node carries a mismatched configuration"));
        };
        return Ok(BuiltOutbound {
            values: vec![build_wireguard_endpoint(node, tag, config)?],
            is_endpoint: true,
        });
    }

    if let ProtocolConfig::Tor(config) = &node.config {
        return Ok(BuiltOutbound {
            values: vec![build_tor(tag, config)],
            is_endpoint: false,
        });
    }

    if node.protocol.needs_server_address() {
        if node.server.trim().is_empty() {
            return Err(anyhow!("empty server address"));
        }
        if node.port == 0 {
            return Err(anyhow!("invalid server port"));
        }
    }

    if node.protocol.requires_tls() && !node.tls.enabled {
        return Err(anyhow!(
            "{} always runs over TLS but the node has it disabled",
            node.protocol
        ));
    }

    let mut extra = Vec::new();
    let mut object = Map::new();
    object.insert("type".to_string(), json!(node.protocol.singbox_type()));
    object.insert("tag".to_string(), json!(tag));

    let mut detour: Option<String> = None;
    if let ProtocolConfig::Shadowsocks(config) = &node.config {
        if let Some(shadow_tls) = &config.shadow_tls {
            let shadow_tag = format!("{} (shadowtls)", tag);
            extra.push(build_shadow_tls(node, &shadow_tag, shadow_tls)?);
            detour = Some(shadow_tag);
        }
    }

    if detour.is_none() {
        object.insert("server".to_string(), json!(node.server.trim()));
        object.insert("server_port".to_string(), json!(node.port));
    }

    match &node.config {
        ProtocolConfig::Vless(config) => {
            if config.uuid.trim().is_empty() {
                return Err(anyhow!("missing VLESS uuid"));
            }
            object.insert("uuid".to_string(), json!(config.uuid.trim()));
            object.insert(
                "packet_encoding".to_string(),
                json!(config.packet_encoding.as_deref().unwrap_or("xudp")),
            );
            if let Some(flow) = trimmed(config.flow.as_deref()) {
                object.insert("flow".to_string(), json!(flow));
            }
        }
        ProtocolConfig::Vmess(config) => {
            if config.uuid.trim().is_empty() {
                return Err(anyhow!("missing VMess uuid"));
            }
            object.insert("uuid".to_string(), json!(config.uuid.trim()));
            object.insert("security".to_string(), json!(config.security));
            object.insert(
                "packet_encoding".to_string(),
                json!(config.packet_encoding.as_deref().unwrap_or("xudp")),
            );
            if config.alter_id > 0 {
                object.insert("alter_id".to_string(), json!(config.alter_id));
            }
            if config.global_padding {
                object.insert("global_padding".to_string(), json!(true));
            }
            if config.authenticated_length {
                object.insert("authenticated_length".to_string(), json!(true));
            }
        }
        ProtocolConfig::Trojan(config) => {
            if config.password.is_empty() {
                return Err(anyhow!("missing Trojan password"));
            }
            object.insert("password".to_string(), json!(config.password));
        }
        ProtocolConfig::Shadowsocks(config) => {
            if config.method.trim().is_empty() {
                return Err(anyhow!("missing Shadowsocks method"));
            }
            object.insert("method".to_string(), json!(config.method.trim()));
            object.insert("password".to_string(), json!(config.password));
            if let Some(plugin) = trimmed(config.plugin.as_deref()) {
                object.insert("plugin".to_string(), json!(plugin));
                if let Some(opts) = trimmed(config.plugin_opts.as_deref()) {
                    object.insert("plugin_opts".to_string(), json!(opts));
                }
            }
        }
        ProtocolConfig::Hysteria(config) => {
            let has_auth = config
                .auth_str
                .as_deref()
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false)
                || config
                    .auth_base64
                    .as_deref()
                    .map(|v| !v.trim().is_empty())
                    .unwrap_or(false);
            if !has_auth {
                return Err(anyhow!("missing Hysteria auth"));
            }
            if let Some(auth) = trimmed(config.auth_str.as_deref()) {
                object.insert("auth_str".to_string(), json!(auth));
            } else if let Some(auth) = trimmed(config.auth_base64.as_deref()) {
                object.insert("auth".to_string(), json!(auth));
            }
            object.insert(
                "up_mbps".to_string(),
                json!(config.up_mbps.unwrap_or(100).max(1)),
            );
            object.insert(
                "down_mbps".to_string(),
                json!(config.down_mbps.unwrap_or(100).max(1)),
            );
            if let Some(obfs) = trimmed(config.obfs.as_deref()) {
                object.insert("obfs".to_string(), json!(obfs));
            }
        }
        ProtocolConfig::Hysteria2(config) => {
            object.insert("password".to_string(), json!(config.password));
            if let Some(up) = config.up_mbps {
                object.insert("up_mbps".to_string(), json!(up));
            }
            if let Some(down) = config.down_mbps {
                object.insert("down_mbps".to_string(), json!(down));
            }
            if let Some(obfs) = config.obfs {
                object.insert(
                    "obfs".to_string(),
                    json!({
                        "type": obfs.as_str(),
                        "password": config.obfs_password.as_deref().unwrap_or_default()
                    }),
                );
            }
            if !config.server_ports.is_empty() {
                object.insert("server_ports".to_string(), json!(config.server_ports));
                object.remove("server_port");
            }
            if let Some(interval) = trimmed(config.hop_interval.as_deref()) {
                object.insert("hop_interval".to_string(), json!(interval));
            }
        }
        ProtocolConfig::Tuic(config) => {
            if config.uuid.trim().is_empty() {
                return Err(anyhow!("missing TUIC uuid"));
            }
            object.insert("uuid".to_string(), json!(config.uuid.trim()));
            object.insert("password".to_string(), json!(config.password));
            if let Some(congestion_control) = config.congestion_control {
                object.insert(
                    "congestion_control".to_string(),
                    json!(congestion_control.as_str()),
                );
            }
            if let Some(udp_relay_mode) = config.udp_relay_mode {
                object.insert("udp_relay_mode".to_string(), json!(udp_relay_mode.as_str()));
            }
            if config.zero_rtt_handshake {
                object.insert("zero_rtt_handshake".to_string(), json!(true));
            }
        }
        ProtocolConfig::AnyTls(config) => {
            if config.password.trim().is_empty() {
                return Err(anyhow!("missing AnyTLS password"));
            }
            object.insert("password".to_string(), json!(config.password));
            if let Some(interval) = trimmed(config.idle_session_check_interval.as_deref()) {
                object.insert(
                    "idle_session_check_interval".to_string(),
                    json!(interval),
                );
            }
            if let Some(timeout) = trimmed(config.idle_session_timeout.as_deref()) {
                object.insert("idle_session_timeout".to_string(), json!(timeout));
            }
            if let Some(sessions) = config.min_idle_session {
                object.insert("min_idle_session".to_string(), json!(sessions));
            }
        }
        ProtocolConfig::Snell(config) => {
            if config.psk.trim().is_empty() {
                return Err(anyhow!("missing Snell PSK"));
            }
            if !matches!(config.version, 4 | 6) {
                return Err(anyhow!(
                    "sing-box supports Snell client versions 4 and 6, not {}",
                    config.version
                ));
            }
            object.insert("version".to_string(), json!(config.version));
            object.insert("psk".to_string(), json!(config.psk.trim()));
            if let Some(user_key) = trimmed(config.user_key.as_deref()) {
                object.insert("userkey".to_string(), json!(user_key));
            }
            if config.version == 4 {
                if let Some(mode) = normalized_obfs_mode(config.obfs_mode.as_deref()) {
                    object.insert("obfs_mode".to_string(), json!(mode));
                    if let Some(host) = trimmed(config.obfs_host.as_deref()) {
                        object.insert("obfs_host".to_string(), json!(host));
                    }
                }
            } else if let Some(mode) = normalized_snell_mode(config.mode.as_deref()) {
                object.insert("mode".to_string(), json!(mode));
            }
        }
        ProtocolConfig::Ssh(config) => {
            if config.user.trim().is_empty() {
                return Err(anyhow!("missing SSH user"));
            }
            object.insert("user".to_string(), json!(config.user.trim()));
            if let Some(password) = trimmed(config.password.as_deref()) {
                object.insert("password".to_string(), json!(password));
            }
            if !config.private_key.is_empty() {
                object.insert("private_key".to_string(), json!(config.private_key));
            }
            if let Some(path) = trimmed(config.private_key_path.as_deref()) {
                object.insert("private_key_path".to_string(), json!(path));
            }
            if let Some(passphrase) = trimmed(config.private_key_passphrase.as_deref()) {
                object.insert("private_key_passphrase".to_string(), json!(passphrase));
            }
            if !config.host_key.is_empty() {
                object.insert("host_key".to_string(), json!(config.host_key));
            }
            if !config.host_key_algorithms.is_empty() {
                object.insert(
                    "host_key_algorithms".to_string(),
                    json!(config.host_key_algorithms),
                );
            }
            if let Some(version) = trimmed(config.client_version.as_deref()) {
                object.insert("client_version".to_string(), json!(version));
            }
        }
        ProtocolConfig::Http(config) => {
            if let Some(username) = trimmed(config.username.as_deref()) {
                object.insert("username".to_string(), json!(username));
            }
            if let Some(password) = trimmed(config.password.as_deref()) {
                object.insert("password".to_string(), json!(password));
            }
            if let Some(path) = trimmed(config.path.as_deref()) {
                object.insert("path".to_string(), json!(path));
            }
            if let Some(headers) = build_headers(&config.headers) {
                object.insert("headers".to_string(), headers);
            }
        }
        ProtocolConfig::Socks(config) => {
            if let Some(version) = trimmed(config.version.as_deref()) {
                object.insert("version".to_string(), json!(version));
            }
            if let Some(username) = trimmed(config.username.as_deref()) {
                object.insert("username".to_string(), json!(username));
            }
            if let Some(password) = trimmed(config.password.as_deref()) {
                object.insert("password".to_string(), json!(password));
            }
        }
        ProtocolConfig::Tor(_) | ProtocolConfig::Wireguard(_) => {
            return Err(anyhow!("handled before the protocol switch"));
        }
    }

    if let Some(detour) = detour {
        object.insert("detour".to_string(), json!(detour));
    } else if node.tls.enabled && node.protocol.supports_tls() {
        object.insert("tls".to_string(), build_tls(&node.tls));
    }

    if node.protocol.supports_v2ray_transport() {
        if let Some(transport) = build_transport(&node.transport, &node.tls) {
            object.insert("transport".to_string(), transport);
        }
    }

    if node.protocol.supports_multiplex() {
        if let Some(multiplex) = node.multiplex.as_ref().and_then(build_multiplex) {
            object.insert("multiplex".to_string(), multiplex);
        }
    }

    if node.protocol.supports_udp_over_tcp() {
        if let Some(udp_over_tcp) = node.udp_over_tcp.as_ref().and_then(build_udp_over_tcp) {
            object.insert("udp_over_tcp".to_string(), udp_over_tcp);
        }
    }

    if let Some(network) = normalized_network(node.network.as_deref()) {
        object.insert("network".to_string(), json!(network));
    }

    let mut values = extra;
    values.push(Value::Object(object));
    Ok(BuiltOutbound {
        values,
        is_endpoint: false,
    })
}

fn trimmed(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|s| !s.is_empty())
}

fn normalized_network(value: Option<&str>) -> Option<&'static str> {
    match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("tcp") => Some("tcp"),
        Some("udp") => Some("udp"),
        _ => None,
    }
}

fn normalized_obfs_mode(value: Option<&str>) -> Option<&'static str> {
    match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("http") => Some("http"),
        Some("tls") => Some("tls"),
        Some("none") => Some("none"),
        _ => None,
    }
}

fn normalized_snell_mode(value: Option<&str>) -> Option<&'static str> {
    match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("unshaped") => Some("unshaped"),
        Some("unsafe-raw") => Some("unsafe-raw"),
        Some("default") => Some("default"),
        _ => None,
    }
}

fn build_headers(headers: &[(String, String)]) -> Option<Value> {
    if headers.is_empty() {
        return None;
    }
    let mut object = Map::new();
    for (name, value) in headers {
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        object.insert(name.to_string(), json!(value));
    }
    if object.is_empty() {
        None
    } else {
        Some(Value::Object(object))
    }
}

fn build_ech(ech: &EchConfig) -> Option<Value> {
    if !ech.enabled {
        return None;
    }
    let mut object = Map::new();
    object.insert("enabled".to_string(), json!(true));
    if !ech.config.is_empty() {
        object.insert("config".to_string(), json!(ech.config));
    }
    if let Some(path) = trimmed(ech.config_path.as_deref()) {
        object.insert("config_path".to_string(), json!(path));
    }
    if let Some(name) = trimmed(ech.query_server_name.as_deref()) {
        object.insert("query_server_name".to_string(), json!(name));
    }
    Some(Value::Object(object))
}

pub fn build_tls(tls: &TlsConfig) -> Value {
    let mut object = Map::new();
    object.insert("enabled".to_string(), json!(true));

    if tls.disable_sni {
        object.insert("disable_sni".to_string(), json!(true));
    } else if let Some(server_name) = trimmed(tls.server_name.as_deref()) {
        object.insert("server_name".to_string(), json!(server_name));
    }
    if tls.insecure {
        object.insert("insecure".to_string(), json!(true));
    }
    if !tls.alpn.is_empty() {
        object.insert("alpn".to_string(), json!(tls.alpn));
    }
    if let Some(version) = normalized_tls_version(tls.min_version.as_deref()) {
        object.insert("min_version".to_string(), json!(version));
    }
    if let Some(version) = normalized_tls_version(tls.max_version.as_deref()) {
        object.insert("max_version".to_string(), json!(version));
    }
    if !tls.certificate.is_empty() {
        object.insert("certificate".to_string(), json!(tls.certificate));
    }
    if let Some(path) = trimmed(tls.certificate_path.as_deref()) {
        object.insert("certificate_path".to_string(), json!(path));
    }
    if tls.fragment {
        object.insert("fragment".to_string(), json!(true));
    }
    if tls.record_fragment {
        object.insert("record_fragment".to_string(), json!(true));
    }
    if let Some(ech) = tls.ech.as_ref().and_then(build_ech) {
        object.insert("ech".to_string(), ech);
    }
    if let Some(reality) = &tls.reality {
        let mut reality_object = Map::new();
        reality_object.insert("enabled".to_string(), json!(true));
        reality_object.insert("public_key".to_string(), json!(reality.public_key));
        if !reality.short_id.trim().is_empty() {
            reality_object.insert("short_id".to_string(), json!(reality.short_id.trim()));
        }
        object.insert("reality".to_string(), Value::Object(reality_object));
    }
    if let Some(utls) = tls.utls {
        object.insert(
            "utls".to_string(),
            json!({ "enabled": true, "fingerprint": utls.as_str() }),
        );
    }
    Value::Object(object)
}

fn normalized_tls_version(value: Option<&str>) -> Option<&'static str> {
    match value.map(str::trim).as_deref() {
        Some("1.0") => Some("1.0"),
        Some("1.1") => Some("1.1"),
        Some("1.2") => Some("1.2"),
        Some("1.3") => Some("1.3"),
        _ => None,
    }
}

pub fn build_transport(transport: &TransportConfig, tls: &TlsConfig) -> Option<Value> {
    let transport_type = transport.transport_type.singbox_type()?;
    let mut object = Map::new();
    object.insert("type".to_string(), json!(transport_type));

    let host = trimmed(transport.host.as_deref())
        .or_else(|| trimmed(tls.server_name.as_deref()));
    let path = trimmed(transport.path.as_deref());

    match transport_type {
        "ws" => {
            object.insert("path".to_string(), json!(path.unwrap_or("/")));
            let mut headers = Map::new();
            if let Some(host) = host {
                headers.insert("Host".to_string(), json!(host));
            }
            for (name, value) in &transport.headers {
                let name = name.trim();
                if !name.is_empty() {
                    headers.insert(name.to_string(), json!(value));
                }
            }
            if !headers.is_empty() {
                object.insert("headers".to_string(), Value::Object(headers));
            }
            if let Some(max_early_data) = transport.max_early_data {
                object.insert("max_early_data".to_string(), json!(max_early_data));
                object.insert(
                    "early_data_header_name".to_string(),
                    json!(
                        trimmed(transport.early_data_header_name.as_deref())
                            .unwrap_or("Sec-WebSocket-Protocol")
                    ),
                );
            }
        }
        "httpupgrade" => {
            object.insert("path".to_string(), json!(path.unwrap_or("/")));
            if let Some(host) = host {
                object.insert("host".to_string(), json!(host));
            }
            if let Some(headers) = build_headers(&transport.headers) {
                object.insert("headers".to_string(), headers);
            }
        }
        "http" => {
            if let Some(path) = path {
                object.insert("path".to_string(), json!(path));
            }
            if let Some(host) = host {
                object.insert("host".to_string(), json!([host]));
            }
            if let Some(method) = trimmed(transport.method.as_deref()) {
                object.insert("method".to_string(), json!(method));
            }
            if let Some(headers) = build_headers(&transport.headers) {
                object.insert("headers".to_string(), headers);
            }
            if let Some(idle_timeout) = trimmed(transport.idle_timeout.as_deref()) {
                object.insert("idle_timeout".to_string(), json!(idle_timeout));
            }
        }
        "grpc" => {
            object.insert(
                "service_name".to_string(),
                json!(trimmed(transport.service_name.as_deref()).unwrap_or("")),
            );
            if transport.permit_without_stream {
                object.insert("permit_without_stream".to_string(), json!(true));
            }
            if let Some(idle_timeout) = trimmed(transport.idle_timeout.as_deref()) {
                object.insert("idle_timeout".to_string(), json!(idle_timeout));
            }
        }
        "quic" => {}
        _ => return None,
    }

    Some(Value::Object(object))
}

fn build_multiplex(multiplex: &MultiplexConfig) -> Option<Value> {
    if !multiplex.enabled {
        return None;
    }
    let mut object = Map::new();
    object.insert("enabled".to_string(), json!(true));
    object.insert("protocol".to_string(), json!(multiplex.protocol.as_str()));
    if let Some(max_connections) = multiplex.max_connections {
        object.insert("max_connections".to_string(), json!(max_connections));
    }
    if let Some(min_streams) = multiplex.min_streams {
        object.insert("min_streams".to_string(), json!(min_streams));
    }
    if let Some(max_streams) = multiplex.max_streams {
        object.insert("max_streams".to_string(), json!(max_streams));
    }
    if multiplex.padding {
        object.insert("padding".to_string(), json!(true));
    }
    if multiplex.brutal_up_mbps.is_some() || multiplex.brutal_down_mbps.is_some() {
        object.insert(
            "brutal".to_string(),
            json!({
                "enabled": true,
                "up_mbps": multiplex.brutal_up_mbps.unwrap_or(0),
                "down_mbps": multiplex.brutal_down_mbps.unwrap_or(0)
            }),
        );
    }
    Some(Value::Object(object))
}

fn build_udp_over_tcp(udp_over_tcp: &UdpOverTcpConfig) -> Option<Value> {
    if !udp_over_tcp.enabled {
        return None;
    }
    match udp_over_tcp.version {
        Some(version) if version != 2 => Some(json!({ "enabled": true, "version": version })),
        _ => Some(json!(true)),
    }
}

fn build_shadow_tls(node: &ProxyNode, tag: &str, config: &ShadowTlsConfig) -> Result<Value> {
    if config.password.trim().is_empty() {
        return Err(anyhow!("missing ShadowTLS password"));
    }
    if !matches!(config.version, 1 | 2 | 3) {
        return Err(anyhow!(
            "ShadowTLS supports versions 1 to 3, not {}",
            config.version
        ));
    }

    let server = config
        .server
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| node.server.trim());
    if server.is_empty() {
        return Err(anyhow!("empty ShadowTLS server address"));
    }
    let port = config.port.unwrap_or(node.port);
    if port == 0 {
        return Err(anyhow!("invalid ShadowTLS server port"));
    }

    let server_name = config
        .server_name
        .clone()
        .or_else(|| node.tls.server_name.clone())
        .unwrap_or_else(|| server.to_string());

    let tls = TlsConfig {
        enabled: true,
        server_name: Some(server_name),
        insecure: node.tls.insecure,
        alpn: node.tls.alpn.clone(),
        utls: config.utls.or(node.tls.utls).or(Some(Default::default())),
        ..TlsConfig::default()
    };

    let mut object = Map::new();
    object.insert("type".to_string(), json!("shadowtls"));
    object.insert("tag".to_string(), json!(tag));
    object.insert("server".to_string(), json!(server));
    object.insert("server_port".to_string(), json!(port));
    object.insert("version".to_string(), json!(config.version));
    object.insert("password".to_string(), json!(config.password.trim()));
    object.insert("tls".to_string(), build_tls(&tls));
    Ok(Value::Object(object))
}

fn build_tor(tag: &str, config: &crate::parser::node::TorConfig) -> Value {
    let mut object = Map::new();
    object.insert("type".to_string(), json!("tor"));
    object.insert("tag".to_string(), json!(tag));
    if let Some(path) = trimmed(config.executable_path.as_deref()) {
        object.insert("executable_path".to_string(), json!(path));
    }
    if !config.extra_args.is_empty() {
        object.insert("extra_args".to_string(), json!(config.extra_args));
    }
    if let Some(directory) = trimmed(config.data_directory.as_deref()) {
        object.insert("data_directory".to_string(), json!(directory));
    }
    if let Some(torrc) = build_headers(&config.torrc) {
        object.insert("torrc".to_string(), torrc);
    }
    Value::Object(object)
}

fn build_wireguard_endpoint(
    node: &ProxyNode,
    tag: &str,
    config: &crate::parser::node::WireguardConfig,
) -> Result<Value> {
    if config.private_key.trim().is_empty() {
        return Err(anyhow!("missing WireGuard private key"));
    }
    if config.peer_public_key.trim().is_empty() {
        return Err(anyhow!("missing WireGuard peer public key"));
    }
    if config.local_address.is_empty() {
        return Err(anyhow!("missing WireGuard local address"));
    }
    if node.server.trim().is_empty() {
        return Err(anyhow!("empty server address"));
    }
    if node.port == 0 {
        return Err(anyhow!("invalid server port"));
    }

    let allowed_ips = if config.allowed_ips.is_empty() {
        vec!["0.0.0.0/0".to_string(), "::/0".to_string()]
    } else {
        config.allowed_ips.clone()
    };

    let mut peer = Map::new();
    peer.insert("address".to_string(), json!(node.server.trim()));
    peer.insert("port".to_string(), json!(node.port));
    peer.insert(
        "public_key".to_string(),
        json!(config.peer_public_key.trim()),
    );
    peer.insert("allowed_ips".to_string(), json!(allowed_ips));
    if let Some(pre_shared_key) = trimmed(config.pre_shared_key.as_deref()) {
        peer.insert("pre_shared_key".to_string(), json!(pre_shared_key));
    }
    if let Some(reserved) = &config.reserved {
        if !reserved.is_empty() {
            peer.insert("reserved".to_string(), json!(reserved));
        }
    }
    if let Some(interval) = config.persistent_keepalive_interval {
        peer.insert(
            "persistent_keepalive_interval".to_string(),
            json!(interval),
        );
    }

    let mut object = Map::new();
    object.insert("type".to_string(), json!("wireguard"));
    object.insert("tag".to_string(), json!(tag));
    object.insert("address".to_string(), json!(config.local_address));
    object.insert("private_key".to_string(), json!(config.private_key.trim()));
    object.insert("peers".to_string(), json!([Value::Object(peer)]));
    if let Some(mtu) = config.mtu {
        object.insert("mtu".to_string(), json!(mtu));
    }
    if config.system_interface {
        object.insert("system".to_string(), json!(true));
    }

    Ok(Value::Object(object))
}
