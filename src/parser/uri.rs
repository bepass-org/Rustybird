use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use percent_encoding::percent_decode_str;
use serde::Deserialize;
use std::collections::HashMap;
use url::Url;

use crate::parser::node::{
    AnyTlsConfig, EchConfig, HttpProxyConfig, HysteriaConfig, Hysteria2Config, Hysteria2ObfsType,
    MultiplexConfig, MultiplexProtocol, ProtocolConfig, ProtocolType, ProxyNode, RealityConfig,
    ShadowTlsConfig, ShadowsocksConfig, SnellConfig, SocksConfig, SshConfig, TlsConfig,
    TransportConfig, TransportType, TrojanConfig, TuicConfig, TuicCongestionControl,
    TuicUdpRelayMode, UdpOverTcpConfig, UtlsFingerprint, VlessConfig, VmessConfig, WireguardConfig,
};

pub const SUPPORTED_SCHEMES: &[&str] = &[
    "vless://",
    "vmess://",
    "trojan://",
    "trojan-go://",
    "ss://",
    "hysteria://",
    "hy://",
    "hysteria2://",
    "hy2://",
    "tuic://",
    "anytls://",
    "snell://",
    "ssh://",
    "socks://",
    "socks4://",
    "socks5://",
    "http://",
    "https://",
    "wireguard://",
    "wg://",
];

pub fn parse_proxy_uri(raw_uri: &str) -> Result<ProxyNode> {
    let trimmed = raw_uri.trim();
    let scheme_end = trimmed
        .find("://")
        .ok_or_else(|| anyhow!("not a proxy URI: {}", truncate_for_error(trimmed)))?;
    let scheme = trimmed[..scheme_end].to_ascii_lowercase();

    match scheme.as_str() {
        "vless" => parse_vless(trimmed),
        "vmess" => parse_vmess(trimmed),
        "trojan" => parse_trojan(trimmed, false),
        "trojan-go" => parse_trojan(trimmed, true),
        "ss" => parse_shadowsocks(trimmed),
        "hy2" | "hysteria2" => parse_hysteria2(trimmed),
        "hy" | "hysteria" => parse_hysteria(trimmed),
        "tuic" => parse_tuic(trimmed),
        "anytls" => parse_anytls(trimmed),
        "snell" => parse_snell(trimmed),
        "ssh" => parse_ssh(trimmed),
        "socks" | "socks4" | "socks4a" | "socks5" | "socks5h" => parse_socks(trimmed, &scheme),
        "http" => parse_http_proxy(trimmed, false),
        "https" => parse_http_proxy(trimmed, true),
        "wireguard" | "wg" => parse_wireguard(trimmed),
        other => Err(anyhow!("unsupported URI scheme: {}", other)),
    }
}

fn truncate_for_error(input: &str) -> String {
    let limit = 48;
    if input.chars().count() <= limit {
        return input.to_string();
    }
    let head: String = input.chars().take(limit).collect();
    format!("{}...", head)
}

pub fn decode_b64(input: &str) -> Result<Vec<u8>> {
    let clean: String = input
        .trim()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if clean.is_empty() {
        return Err(anyhow!("empty base64 input"));
    }

    for engine in [
        &STANDARD as &dyn DecodeEngine,
        &URL_SAFE,
        &STANDARD_NO_PAD,
        &URL_SAFE_NO_PAD,
    ] {
        if let Ok(data) = engine.decode_str(&clean) {
            return Ok(data);
        }
    }

    let trimmed = clean.trim_end_matches('=');
    let padded = match trimmed.len() % 4 {
        2 => format!("{}==", trimmed),
        3 => format!("{}=", trimmed),
        1 => return Err(anyhow!("invalid base64 length")),
        _ => trimmed.to_string(),
    };

    STANDARD
        .decode(&padded)
        .or_else(|_| URL_SAFE.decode(&padded))
        .map_err(|e| anyhow!("base64 decode failed: {}", e))
}

trait DecodeEngine {
    fn decode_str(&self, input: &str) -> Result<Vec<u8>, base64::DecodeError>;
}

impl<T: Engine> DecodeEngine for T {
    fn decode_str(&self, input: &str) -> Result<Vec<u8>, base64::DecodeError> {
        self.decode(input)
    }
}

pub fn is_hex_short_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 16
        && value.len() % 2 == 0
        && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn parse_raw_query_map(url: &Url) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let Some(query) = url.query() else {
        return map;
    };
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = match pair.split_once('=') {
            Some((key, value)) => (key, value),
            None => (pair, ""),
        };
        let key = percent_decode_str(key)
            .decode_utf8_lossy()
            .to_ascii_lowercase();
        let value = percent_decode_str(value).decode_utf8_lossy().to_string();
        map.entry(key).or_insert(value);
    }
    map
}

fn parse_query_map(url: &Url) -> HashMap<String, String> {
    url.query_pairs()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.to_string()))
        .collect()
}

fn query_flag(q: &HashMap<String, String>, keys: &[&str]) -> bool {
    keys.iter().any(|key| {
        q.get(*key)
            .map(|v| matches!(v.trim(), "1" | "true" | "yes"))
            .unwrap_or(false)
    })
}

fn query_first(q: &HashMap<String, String>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        q.get(*key)
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
            .map(|v| v.to_string())
    })
}

fn query_u32(q: &HashMap<String, String>, keys: &[&str]) -> Option<u32> {
    query_first(q, keys).and_then(|v| parse_leading_u32(&v))
}

fn parse_leading_u32(value: &str) -> Option<u32> {
    let digits: String = value
        .trim()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok().filter(|v| *v > 0)
}

fn parse_alpn(value: Option<String>) -> Vec<String> {
    value
        .map(|raw| {
            raw.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn parse_string_list(value: Option<String>) -> Vec<String> {
    parse_alpn(value)
}

fn get_node_name(url: &Url, default: &str) -> String {
    url.fragment()
        .map(|f| percent_decode_str(f).decode_utf8_lossy().trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn decoded_username(url: &Url) -> String {
    percent_decode_str(url.username())
        .decode_utf8_lossy()
        .to_string()
}

fn decoded_password(url: &Url) -> String {
    url.password()
        .map(|p| percent_decode_str(p).decode_utf8_lossy().to_string())
        .unwrap_or_default()
}

fn require_host(url: &Url) -> Result<String> {
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("missing host"))?
        .trim_matches(['[', ']'])
        .to_string();
    if host.is_empty() {
        return Err(anyhow!("empty host"));
    }
    Ok(host)
}

fn parse_reserved(value: &str) -> Option<Vec<u8>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.contains(',') {
        let parts: Vec<u8> = trimmed
            .split(',')
            .filter_map(|p| p.trim().parse::<u8>().ok())
            .collect();
        return if parts.len() == 3 { Some(parts) } else { None };
    }
    decode_b64(trimmed).ok().filter(|bytes| bytes.len() == 3)
}

fn build_multiplex(q: &HashMap<String, String>) -> Option<MultiplexConfig> {
    let protocol = query_first(q, &["mux", "muxtype", "mux-type"])
        .and_then(|value| MultiplexProtocol::parse(&value));
    let enabled = protocol.is_some() || query_flag(q, &["mux", "multiplex"]);
    if !enabled {
        return None;
    }
    Some(MultiplexConfig {
        enabled: true,
        protocol: protocol.unwrap_or_default(),
        max_connections: query_u32(q, &["muxmaxconnections", "max_connections"]),
        min_streams: query_u32(q, &["muxminstreams", "min_streams"]),
        max_streams: query_u32(q, &["muxmaxstreams", "max_streams"]),
        padding: query_flag(q, &["muxpadding", "padding"]),
        brutal_up_mbps: query_u32(q, &["brutalup", "brutal_up_mbps"]),
        brutal_down_mbps: query_u32(q, &["brutaldown", "brutal_down_mbps"]),
    })
}

fn build_ech(q: &HashMap<String, String>) -> Option<EchConfig> {
    if !query_flag(q, &["ech"]) && query_first(q, &["ech-config", "echconfig"]).is_none() {
        return None;
    }
    Some(EchConfig {
        enabled: true,
        config: query_first(q, &["ech-config", "echconfig"])
            .map(|v| vec![v])
            .unwrap_or_default(),
        config_path: query_first(q, &["ech-config-path"]),
        query_server_name: query_first(q, &["ech-query-server-name"]),
    })
}

fn build_transport(q: &HashMap<String, String>, fallback_host: Option<&String>) -> TransportConfig {
    let transport_type = TransportType::parse(q.get("type").map(|s| s.as_str()).unwrap_or("tcp"));
    TransportConfig {
        transport_type,
        path: query_first(q, &["path"]),
        service_name: query_first(q, &["servicename", "service_name"]),
        host: query_first(q, &["host"]).or_else(|| fallback_host.cloned()),
        method: query_first(q, &["method"]),
        headers: Vec::new(),
        max_early_data: query_u32(q, &["earlydata", "max_early_data", "ed"]),
        early_data_header_name: query_first(q, &["eh", "earlydataheadername"]),
        permit_without_stream: query_flag(q, &["permitwithoutstream"]),
        idle_timeout: query_first(q, &["idletimeout", "idle_timeout"]),
    }
}

fn build_tls(
    q: &HashMap<String, String>,
    enabled: bool,
    server_name: Option<String>,
    default_alpn: &[&str],
) -> TlsConfig {
    let alpn = parse_alpn(query_first(q, &["alpn"]));
    let reality = query_first(q, &["pbk", "public-key", "publickey"]).map(|public_key| {
        RealityConfig {
            public_key,
            short_id: query_first(q, &["sid", "short-id", "shortid"])
                .filter(|sid| is_hex_short_id(sid))
                .unwrap_or_default(),
        }
    });
    let utls = query_first(q, &["fp", "fingerprint"]).map(|fp| UtlsFingerprint::parse(&fp));

    TlsConfig {
        enabled,
        server_name,
        insecure: query_flag(
            q,
            &[
                "allowinsecure",
                "insecure",
                "allow_insecure",
                "skip-cert-verify",
            ],
        ),
        disable_sni: query_flag(q, &["disablesni", "disable_sni"]),
        alpn: if alpn.is_empty() {
            default_alpn.iter().map(|s| s.to_string()).collect()
        } else {
            alpn
        },
        min_version: query_first(q, &["minversion", "min_version"]),
        max_version: query_first(q, &["maxversion", "max_version"]),
        certificate: Vec::new(),
        certificate_path: query_first(q, &["certificatepath", "certificate_path", "ca"]),
        fragment: query_flag(q, &["fragment", "tlsfragment"]),
        record_fragment: query_flag(q, &["recordfragment", "record_fragment"]),
        utls: if reality.is_some() {
            Some(utls.unwrap_or_default())
        } else {
            utls
        },
        reality,
        ech: build_ech(q),
    }
}

fn parse_vless(raw: &str) -> Result<ProxyNode> {
    let url = Url::parse(raw).context("invalid VLESS URL")?;
    let host = require_host(&url)?;
    let port = url.port().unwrap_or(443);
    let uuid = decoded_username(&url);
    if uuid.is_empty() {
        return Err(anyhow!("missing UUID in VLESS URL"));
    }

    let q = parse_query_map(&url);
    let security = q
        .get("security")
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_else(|| "none".to_string());
    let sni = query_first(&q, &["sni", "peer"]);
    let tls_enabled = matches!(security.as_str(), "tls" | "reality" | "xtls");

    if security == "reality" && query_first(&q, &["pbk", "public-key", "publickey"]).is_none() {
        return Err(anyhow!("reality security requires a pbk parameter"));
    }

    let server_name = sni.clone().or_else(|| {
        if tls_enabled {
            Some(host.clone())
        } else {
            None
        }
    });
    let mut tls = build_tls(&q, tls_enabled, server_name, &[]);
    if security != "reality" {
        tls.reality = None;
    }

    let transport = build_transport(&q, sni.as_ref());
    let name = get_node_name(&url, &format!("VLESS {}:{}", host, port));

    let mut node = ProxyNode::new(
        name,
        host,
        port,
        ProtocolType::Vless,
        ProtocolConfig::Vless(VlessConfig {
            uuid,
            flow: query_first(&q, &["flow"]),
            packet_encoding: query_first(&q, &["packetencoding", "packet_encoding"]),
        }),
    );
    node.tls = tls;
    node.transport = transport;
    node.multiplex = build_multiplex(&q);
    node.network = query_first(&q, &["network-type"]);
    Ok(node)
}

#[derive(Deserialize)]
struct VmessJson {
    ps: Option<String>,
    add: Option<String>,
    port: Option<serde_json::Value>,
    id: Option<String>,
    aid: Option<serde_json::Value>,
    scy: Option<String>,
    net: Option<String>,
    host: Option<String>,
    path: Option<String>,
    tls: Option<String>,
    sni: Option<String>,
    alpn: Option<String>,
    fp: Option<String>,
    #[serde(rename = "type")]
    header_type: Option<String>,
    #[serde(rename = "allowInsecure")]
    allow_insecure: Option<serde_json::Value>,
}

fn json_to_u32(value: Option<serde_json::Value>, default: u32) -> u32 {
    match value {
        Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(default as u64) as u32,
        Some(serde_json::Value::String(s)) => s.trim().parse().unwrap_or(default),
        _ => default,
    }
}

fn json_to_bool(value: Option<serde_json::Value>) -> bool {
    match value {
        Some(serde_json::Value::Bool(b)) => b,
        Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(0) != 0,
        Some(serde_json::Value::String(s)) => matches!(s.trim(), "1" | "true" | "yes"),
        _ => false,
    }
}

pub fn normalize_vmess_security(value: Option<String>) -> String {
    let raw = value
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    match raw.as_str() {
        "auto" | "none" | "zero" | "aes-128-cfb" | "aes-128-gcm" | "chacha20-poly1305" => raw,
        _ => "auto".to_string(),
    }
}

fn parse_vmess(raw: &str) -> Result<ProxyNode> {
    let payload = raw.strip_prefix("vmess://").unwrap_or(raw);
    let decoded = decode_b64(payload).context("VMess payload is not valid base64")?;
    let decoded_str = String::from_utf8(decoded).context("VMess payload is not UTF-8")?;
    let json: VmessJson =
        serde_json::from_str(decoded_str.trim()).context("invalid VMess JSON payload")?;

    let host = json
        .add
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .ok_or_else(|| anyhow!("missing add in VMess payload"))?;
    let port = json_to_u32(json.port, 443).min(u16::MAX as u32) as u16;
    if port == 0 {
        return Err(anyhow!("invalid port in VMess payload"));
    }
    let uuid = json
        .id
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty())
        .ok_or_else(|| anyhow!("missing id in VMess payload"))?;

    let is_tls = json
        .tls
        .as_deref()
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "tls" | "reality"))
        .unwrap_or(false);

    let sni = json
        .sni
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let ws_host = json
        .host
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let tls = TlsConfig {
        enabled: is_tls,
        server_name: sni
            .clone()
            .or_else(|| ws_host.clone())
            .or_else(|| if is_tls { Some(host.clone()) } else { None }),
        insecure: json_to_bool(json.allow_insecure),
        alpn: parse_alpn(json.alpn),
        utls: json.fp.map(|fp| UtlsFingerprint::parse(&fp)),
        ..TlsConfig::default()
    };

    let network = json.net.as_deref().unwrap_or("tcp");
    let header_type = json
        .header_type
        .map(|t| t.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let transport_type = if network.eq_ignore_ascii_case("tcp") && header_type == "http" {
        TransportType::Http
    } else {
        TransportType::parse(network)
    };

    let transport = TransportConfig {
        transport_type,
        path: json.path.filter(|p| !p.trim().is_empty()),
        service_name: None,
        host: ws_host.or_else(|| sni.clone()),
        ..TransportConfig::default()
    };

    let name = json
        .ps
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("VMess {}:{}", host, port));

    let mut node = ProxyNode::new(
        name,
        host,
        port,
        ProtocolType::Vmess,
        ProtocolConfig::Vmess(VmessConfig {
            uuid,
            alter_id: json_to_u32(json.aid, 0),
            security: normalize_vmess_security(json.scy),
            global_padding: false,
            authenticated_length: false,
            packet_encoding: None,
        }),
    );
    node.tls = tls;
    node.transport = transport;
    Ok(node)
}

fn parse_trojan(raw: &str, trojan_go: bool) -> Result<ProxyNode> {
    let normalized = match raw.strip_prefix("trojan-go://") {
        Some(rest) => format!("trojan://{}", rest),
        None => raw.to_string(),
    };
    let url = Url::parse(&normalized).context("invalid Trojan URL")?;
    let host = require_host(&url)?;
    let port = url.port().unwrap_or(443);
    let password = decoded_username(&url);
    if password.is_empty() {
        return Err(anyhow!("missing password in Trojan URL"));
    }

    let q = parse_query_map(&url);
    let sni = query_first(&q, &["sni", "peer"]);
    let server_name = Some(sni.clone().unwrap_or_else(|| host.clone()));
    let mut tls = build_tls(&q, true, server_name, &[]);
    tls.reality = None;

    let mut transport = build_transport(&q, sni.as_ref());
    if trojan_go && transport.transport_type == TransportType::Tcp && transport.path.is_some() {
        transport.transport_type = TransportType::Ws;
    }

    let name = get_node_name(&url, &format!("Trojan {}:{}", host, port));

    let mut node = ProxyNode::new(
        name,
        host,
        port,
        ProtocolType::Trojan,
        ProtocolConfig::Trojan(TrojanConfig { password }),
    );
    node.tls = tls;
    node.transport = transport;
    node.multiplex = build_multiplex(&q);
    Ok(node)
}

fn parse_plugin_opts(raw: &str) -> HashMap<String, String> {
    let mut options = HashMap::new();
    for part in raw.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part.split_once('=') {
            Some((key, value)) => {
                options.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
            }
            None => {
                options.insert(part.to_ascii_lowercase(), "true".to_string());
            }
        }
    }
    options
}

fn apply_shadowsocks_plugin(
    node: &mut ProxyNode,
    plugin_spec: &str,
) -> Result<()> {
    let (name, opts_raw) = match plugin_spec.split_once(';') {
        Some((name, rest)) => (name.trim().to_ascii_lowercase(), rest),
        None => (plugin_spec.trim().to_ascii_lowercase(), ""),
    };
    let opts = parse_plugin_opts(opts_raw);

    match name.as_str() {
        "obfs-local" | "simple-obfs" | "obfs" => {
            if let ProtocolConfig::Shadowsocks(config) = &mut node.config {
                config.plugin = Some("obfs-local".to_string());
                config.plugin_opts = Some(opts_raw.trim().to_string()).filter(|s| !s.is_empty());
            }
        }
        "v2ray-plugin" => {
            if let ProtocolConfig::Shadowsocks(config) = &mut node.config {
                config.plugin = Some("v2ray-plugin".to_string());
                config.plugin_opts = Some(opts_raw.trim().to_string()).filter(|s| !s.is_empty());
            }
        }
        "shadow-tls" | "shadowtls" => {
            let password = opts
                .get("password")
                .cloned()
                .ok_or_else(|| anyhow!("shadow-tls plugin requires a password option"))?;
            let version = opts
                .get("version")
                .and_then(|v| v.parse::<u8>().ok())
                .unwrap_or(3);
            let server_name = opts.get("host").or_else(|| opts.get("sni")).cloned();
            if let ProtocolConfig::Shadowsocks(config) = &mut node.config {
                config.shadow_tls = Some(ShadowTlsConfig {
                    version,
                    password,
                    server: None,
                    port: None,
                    server_name,
                    utls: opts.get("fp").map(|fp| UtlsFingerprint::parse(fp)),
                });
            }
        }
        other => return Err(anyhow!("unsupported Shadowsocks plugin: {}", other)),
    }
    Ok(())
}

fn parse_shadowsocks(raw: &str) -> Result<ProxyNode> {
    let without_scheme = raw.strip_prefix("ss://").unwrap_or(raw);
    let (body, fragment) = match without_scheme.split_once('#') {
        Some((body, fragment)) => (body, Some(fragment)),
        None => (without_scheme, None),
    };

    let name_from_fragment = fragment
        .map(|f| percent_decode_str(f).decode_utf8_lossy().trim().to_string())
        .filter(|s| !s.is_empty());

    let (method, password, host, port, query) = if body.contains('@') {
        let url = Url::parse(&format!("ss://{}", body)).context("invalid Shadowsocks URL")?;
        let host = require_host(&url)?;
        let port = url.port().unwrap_or(8388);
        let user = url.username();
        let query = parse_query_map(&url);

        if let Some(password) = url.password() {
            (
                percent_decode_str(user).decode_utf8_lossy().to_string(),
                percent_decode_str(password).decode_utf8_lossy().to_string(),
                host,
                port,
                query,
            )
        } else {
            let decoded = decode_b64(&percent_decode_str(user).decode_utf8_lossy())
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
                .ok_or_else(|| anyhow!("invalid Shadowsocks user info"))?;
            let (method, password) = decoded
                .split_once(':')
                .ok_or_else(|| anyhow!("invalid Shadowsocks method:password pair"))?;
            (
                method.to_string(),
                password.to_string(),
                host,
                port,
                query,
            )
        }
    } else {
        let decoded = String::from_utf8(decode_b64(body).context("invalid Shadowsocks payload")?)
            .context("Shadowsocks payload is not UTF-8")?;
        let url = Url::parse(&format!("ss://{}", decoded.trim()))
            .context("invalid Shadowsocks URL after base64 decode")?;
        let host = require_host(&url)?;
        let port = url.port().unwrap_or(8388);
        let method = percent_decode_str(url.username())
            .decode_utf8_lossy()
            .to_string();
        let password = decoded_password(&url);
        if method.is_empty() {
            return Err(anyhow!("missing Shadowsocks method"));
        }
        (method, password, host, port, parse_query_map(&url))
    };

    if method.trim().is_empty() {
        return Err(anyhow!("missing Shadowsocks method"));
    }

    let name = name_from_fragment.unwrap_or_else(|| format!("Shadowsocks {}:{}", host, port));

    let mut node = ProxyNode::new(
        name,
        host,
        port,
        ProtocolType::Shadowsocks,
        ProtocolConfig::Shadowsocks(ShadowsocksConfig {
            method: method.trim().to_ascii_lowercase(),
            password,
            plugin: None,
            plugin_opts: None,
            shadow_tls: None,
        }),
    );

    if let Some(plugin) = query_first(&query, &["plugin"]) {
        apply_shadowsocks_plugin(&mut node, &plugin)?;
    }
    node.multiplex = build_multiplex(&query);
    if query_flag(&query, &["uot", "udp-over-tcp"]) {
        node.udp_over_tcp = Some(UdpOverTcpConfig {
            enabled: true,
            version: query_u32(&query, &["uot-version"]).map(|v| v as u8),
        });
    }
    Ok(node)
}

fn parse_hysteria2(raw: &str) -> Result<ProxyNode> {
    let normalized = match raw.strip_prefix("hy2://") {
        Some(rest) => format!("hysteria2://{}", rest),
        None => raw.to_string(),
    };
    let url = Url::parse(&normalized).context("invalid Hysteria2 URL")?;
    let host = require_host(&url)?;
    let port = url.port().unwrap_or(443);

    let mut password = decoded_username(&url);
    let user_password = decoded_password(&url);
    if !user_password.is_empty() {
        password = format!("{}:{}", password, user_password);
    }
    if password.is_empty() {
        return Err(anyhow!("missing password in Hysteria2 URL"));
    }

    let q = parse_query_map(&url);
    let sni = query_first(&q, &["sni", "peer"]).unwrap_or_else(|| host.clone());

    let mut tls = build_tls(&q, true, Some(sni), &["h3"]);
    tls.reality = None;

    let obfs = query_first(&q, &["obfs"]).and_then(|o| Hysteria2ObfsType::parse(&o));
    let obfs_password = query_first(&q, &["obfs-password", "obfs_password"]);
    let name = get_node_name(&url, &format!("Hysteria2 {}:{}", host, port));

    let mut node = ProxyNode::new(
        name,
        host,
        port,
        ProtocolType::Hysteria2,
        ProtocolConfig::Hysteria2(Hysteria2Config {
            password,
            up_mbps: query_u32(&q, &["up", "upmbps"]),
            down_mbps: query_u32(&q, &["down", "downmbps"]),
            obfs_password: if obfs.is_some() { obfs_password } else { None },
            obfs,
            server_ports: parse_string_list(query_first(&q, &["mport", "server_ports"])),
            hop_interval: query_first(&q, &["hop_interval", "hopinterval"]),
        }),
    );
    node.tls = tls;
    Ok(node)
}

fn parse_hysteria(raw: &str) -> Result<ProxyNode> {
    let normalized = match raw.strip_prefix("hy://") {
        Some(rest) => format!("hysteria://{}", rest),
        None => raw.to_string(),
    };
    let url = Url::parse(&normalized).context("invalid Hysteria URL")?;
    let host = require_host(&url)?;
    let port = url.port().unwrap_or(443);

    let q = parse_query_map(&url);
    let auth = query_first(&q, &["auth", "auth_str", "authstr"]);
    let auth_base64 = query_first(&q, &["auth-base64", "auth_base64"]);
    if auth.is_none() && auth_base64.is_none() && url.username().is_empty() {
        return Err(anyhow!("missing auth in Hysteria URL"));
    }

    let sni = query_first(&q, &["sni", "peer"]).unwrap_or_else(|| host.clone());
    let mut tls = build_tls(&q, true, Some(sni), &["h3"]);
    tls.reality = None;

    let name = get_node_name(&url, &format!("Hysteria {}:{}", host, port));
    let username = decoded_username(&url);

    let mut node = ProxyNode::new(
        name,
        host,
        port,
        ProtocolType::Hysteria,
        ProtocolConfig::Hysteria(HysteriaConfig {
            auth_str: auth.or_else(|| {
                if username.is_empty() {
                    None
                } else {
                    Some(username)
                }
            }),
            auth_base64,
            up_mbps: query_u32(&q, &["upmbps", "up"]),
            down_mbps: query_u32(&q, &["downmbps", "down"]),
            obfs: query_first(&q, &["obfs", "obfsparam"]),
            disable_mtu_discovery: query_flag(&q, &["disable_mtu_discovery"]),
        }),
    );
    node.tls = tls;
    Ok(node)
}

fn parse_tuic(raw: &str) -> Result<ProxyNode> {
    let url = Url::parse(raw).context("invalid TUIC URL")?;
    let host = require_host(&url)?;
    let port = url.port().unwrap_or(443);
    let uuid = decoded_username(&url);
    if uuid.is_empty() {
        return Err(anyhow!("missing UUID in TUIC URL"));
    }

    let q = parse_query_map(&url);
    let sni = query_first(&q, &["sni", "peer"]).unwrap_or_else(|| host.clone());
    let mut tls = build_tls(&q, true, Some(sni), &[]);
    tls.reality = None;

    let name = get_node_name(&url, &format!("TUIC {}:{}", host, port));

    let mut node = ProxyNode::new(
        name,
        host,
        port,
        ProtocolType::Tuic,
        ProtocolConfig::Tuic(TuicConfig {
            uuid,
            password: decoded_password(&url),
            congestion_control: query_first(&q, &["congestion_control", "congestion-controller"])
                .and_then(|v| TuicCongestionControl::parse(&v)),
            udp_relay_mode: query_first(&q, &["udp_relay_mode", "udp-relay-mode"])
                .and_then(|v| TuicUdpRelayMode::parse(&v)),
            zero_rtt_handshake: query_flag(&q, &["zero_rtt_handshake", "reduce_rtt"]),
        }),
    );
    node.tls = tls;
    Ok(node)
}

fn parse_anytls(raw: &str) -> Result<ProxyNode> {
    let url = Url::parse(raw).context("invalid AnyTLS URL")?;
    let host = require_host(&url)?;
    let port = url.port().unwrap_or(443);

    let mut password = decoded_username(&url);
    let user_password = decoded_password(&url);
    if password.is_empty() {
        password = user_password;
    } else if !user_password.is_empty() {
        password = format!("{}:{}", password, user_password);
    }
    if password.is_empty() {
        return Err(anyhow!("missing password in AnyTLS URL"));
    }

    let q = parse_query_map(&url);
    let sni = query_first(&q, &["sni", "peer"]).unwrap_or_else(|| host.clone());
    let mut tls = build_tls(&q, true, Some(sni), &[]);
    tls.reality = None;

    let name = get_node_name(&url, &format!("AnyTLS {}:{}", host, port));

    let mut node = ProxyNode::new(
        name,
        host,
        port,
        ProtocolType::AnyTls,
        ProtocolConfig::AnyTls(AnyTlsConfig {
            password,
            idle_session_check_interval: query_first(&q, &["idle_session_check_interval"]),
            idle_session_timeout: query_first(&q, &["idle_session_timeout"]),
            min_idle_session: query_u32(&q, &["min_idle_session"]),
        }),
    );
    node.tls = tls;
    Ok(node)
}

fn parse_snell(raw: &str) -> Result<ProxyNode> {
    let url = Url::parse(raw).context("invalid Snell URL")?;
    let host = require_host(&url)?;
    let port = url.port().ok_or_else(|| anyhow!("missing Snell port"))?;
    let psk = {
        let user = decoded_username(&url);
        if user.is_empty() {
            decoded_password(&url)
        } else {
            user
        }
    };
    if psk.is_empty() {
        return Err(anyhow!("missing PSK in Snell URL"));
    }

    let q = parse_query_map(&url);
    let version = query_u32(&q, &["version"]).unwrap_or(4) as u8;
    if !matches!(version, 4 | 6) {
        return Err(anyhow!(
            "sing-box only supports Snell client versions 4 and 6"
        ));
    }

    let name = get_node_name(&url, &format!("Snell {}:{}", host, port));
    Ok(ProxyNode::new(
        name,
        host,
        port,
        ProtocolType::Snell,
        ProtocolConfig::Snell(SnellConfig {
            psk,
            version,
            obfs_mode: query_first(&q, &["obfs", "obfs-mode", "obfs_mode"]),
            obfs_host: query_first(&q, &["obfs-host", "obfs_host", "host"]),
            user_key: query_first(&q, &["userkey", "user-key"]),
            mode: query_first(&q, &["mode"]),
        }),
    ))
}

fn parse_ssh(raw: &str) -> Result<ProxyNode> {
    let url = Url::parse(raw).context("invalid SSH URL")?;
    let host = require_host(&url)?;
    let port = url.port().unwrap_or(22);
    let user = decoded_username(&url);
    if user.is_empty() {
        return Err(anyhow!("missing user in SSH URL"));
    }

    let q = parse_query_map(&url);
    let password = {
        let value = decoded_password(&url);
        if value.is_empty() {
            query_first(&q, &["password"])
        } else {
            Some(value)
        }
    };

    let name = get_node_name(&url, &format!("SSH {}:{}", host, port));
    Ok(ProxyNode::new(
        name,
        host,
        port,
        ProtocolType::Ssh,
        ProtocolConfig::Ssh(SshConfig {
            user,
            password,
            private_key: Vec::new(),
            private_key_path: query_first(&q, &["private_key_path", "key"]),
            private_key_passphrase: query_first(&q, &["private_key_passphrase", "passphrase"]),
            host_key: parse_string_list(query_first(&q, &["host_key"])),
            host_key_algorithms: parse_string_list(query_first(&q, &["host_key_algorithms"])),
            client_version: query_first(&q, &["client_version"]),
        }),
    ))
}

fn parse_socks(raw: &str, scheme: &str) -> Result<ProxyNode> {
    let normalized = format!(
        "socks5://{}",
        raw.split_once("://").map(|(_, rest)| rest).unwrap_or(raw)
    );
    let url = Url::parse(&normalized).context("invalid SOCKS URL")?;
    let host = require_host(&url)?;
    let port = url.port().unwrap_or(1080);

    let version = match scheme {
        "socks4" => Some("4".to_string()),
        "socks4a" => Some("4a".to_string()),
        _ => None,
    };

    let username = Some(decoded_username(&url)).filter(|u| !u.is_empty());
    let password = Some(decoded_password(&url)).filter(|p| !p.is_empty());
    let q = parse_query_map(&url);

    let name = get_node_name(&url, &format!("SOCKS {}:{}", host, port));
    let mut node = ProxyNode::new(
        name,
        host,
        port,
        ProtocolType::Socks,
        ProtocolConfig::Socks(SocksConfig {
            version,
            username,
            password,
        }),
    );
    if query_flag(&q, &["uot", "udp-over-tcp"]) {
        node.udp_over_tcp = Some(UdpOverTcpConfig {
            enabled: true,
            version: query_u32(&q, &["uot-version"]).map(|v| v as u8),
        });
    }
    Ok(node)
}

fn parse_http_proxy(raw: &str, tls_enabled: bool) -> Result<ProxyNode> {
    let url = Url::parse(raw).context("invalid HTTP proxy URL")?;
    let host = require_host(&url)?;
    let port = url.port().unwrap_or(if tls_enabled { 443 } else { 80 });

    let q = parse_query_map(&url);
    let name = get_node_name(&url, &format!("HTTP {}:{}", host, port));
    let server_name = query_first(&q, &["sni"]).or_else(|| Some(host.clone()));

    let mut node = ProxyNode::new(
        name,
        host,
        port,
        ProtocolType::Http,
        ProtocolConfig::Http(HttpProxyConfig {
            username: Some(decoded_username(&url)).filter(|u| !u.is_empty()),
            password: Some(decoded_password(&url)).filter(|p| !p.is_empty()),
            path: Some(url.path().to_string()).filter(|p| !p.is_empty() && p != "/"),
            headers: Vec::new(),
        }),
    );
    if tls_enabled {
        let mut tls = build_tls(&q, true, server_name, &[]);
        tls.reality = None;
        node.tls = tls;
    }
    Ok(node)
}

fn parse_wireguard(raw: &str) -> Result<ProxyNode> {
    let normalized = match raw.strip_prefix("wg://") {
        Some(rest) => format!("wireguard://{}", rest),
        None => raw.to_string(),
    };
    let url = Url::parse(&normalized).context("invalid WireGuard URL")?;
    let host = require_host(&url)?;
    let port = url.port().unwrap_or(51820);

    let q = parse_query_map(&url);
    let raw = parse_raw_query_map(&url);
    let private_key = {
        let user = decoded_username(&url);
        if user.is_empty() {
            query_first(&raw, &["privatekey", "private_key"])
                .ok_or_else(|| anyhow!("missing private key in WireGuard URL"))?
        } else {
            user
        }
    };
    let peer_public_key = query_first(&raw, &["publickey", "public_key", "peer_public_key"])
        .ok_or_else(|| anyhow!("missing peer public key in WireGuard URL"))?;
    let local_address = parse_string_list(query_first(&q, &["address", "ip", "local_address"]));
    if local_address.is_empty() {
        return Err(anyhow!("missing local address in WireGuard URL"));
    }

    let name = get_node_name(&url, &format!("WireGuard {}:{}", host, port));
    Ok(ProxyNode::new(
        name,
        host,
        port,
        ProtocolType::Wireguard,
        ProtocolConfig::Wireguard(WireguardConfig {
            private_key,
            peer_public_key,
            pre_shared_key: query_first(&raw, &["presharedkey", "pre_shared_key", "psk"]),
            local_address,
            mtu: query_u32(&q, &["mtu"]),
            reserved: query_first(&q, &["reserved"]).and_then(|v| parse_reserved(&v)),
            allowed_ips: parse_string_list(query_first(&q, &["allowed_ips", "allowedips"])),
            persistent_keepalive_interval: query_u32(
                &q,
                &["persistent_keepalive_interval", "keepalive"],
            ),
            system_interface: query_flag(&q, &["system", "system_interface"]),
        }),
    ))
}
