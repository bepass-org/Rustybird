use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolType {
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
    Hysteria,
    Hysteria2,
    Tuic,
    AnyTls,
    Snell,
    Ssh,
    Tor,
    Http,
    Socks,
    Wireguard,
}

impl ProtocolType {
    pub fn supports_tls(&self) -> bool {
        matches!(
            self,
            Self::Vless
                | Self::Vmess
                | Self::Trojan
                | Self::Hysteria
                | Self::Hysteria2
                | Self::Tuic
                | Self::AnyTls
                | Self::Http
        )
    }

    pub fn requires_tls(&self) -> bool {
        matches!(
            self,
            Self::Hysteria | Self::Hysteria2 | Self::Tuic | Self::AnyTls
        )
    }

    pub fn supports_v2ray_transport(&self) -> bool {
        matches!(self, Self::Vless | Self::Vmess | Self::Trojan)
    }

    pub fn supports_multiplex(&self) -> bool {
        matches!(
            self,
            Self::Vless | Self::Vmess | Self::Trojan | Self::Shadowsocks
        )
    }

    pub fn supports_udp_over_tcp(&self) -> bool {
        matches!(self, Self::Shadowsocks | Self::Socks)
    }

    pub fn is_endpoint(&self) -> bool {
        matches!(self, Self::Wireguard)
    }

    pub fn needs_server_address(&self) -> bool {
        !matches!(self, Self::Tor)
    }

    pub fn singbox_type(&self) -> &'static str {
        match self {
            Self::Vless => "vless",
            Self::Vmess => "vmess",
            Self::Trojan => "trojan",
            Self::Shadowsocks => "shadowsocks",
            Self::Hysteria => "hysteria",
            Self::Hysteria2 => "hysteria2",
            Self::Tuic => "tuic",
            Self::AnyTls => "anytls",
            Self::Snell => "snell",
            Self::Ssh => "ssh",
            Self::Tor => "tor",
            Self::Http => "http",
            Self::Socks => "socks",
            Self::Wireguard => "wireguard",
        }
    }
}

impl std::fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Vless => "VLESS",
            Self::Vmess => "VMess",
            Self::Trojan => "Trojan",
            Self::Shadowsocks => "Shadowsocks",
            Self::Hysteria => "Hysteria",
            Self::Hysteria2 => "Hysteria 2",
            Self::Tuic => "TUIC",
            Self::AnyTls => "AnyTLS",
            Self::Snell => "Snell",
            Self::Ssh => "SSH",
            Self::Tor => "Tor",
            Self::Http => "HTTP",
            Self::Socks => "SOCKS",
            Self::Wireguard => "WireGuard",
        };
        f.write_str(name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TransportType {
    #[default]
    Tcp,
    Ws,
    Grpc,
    HttpUpgrade,
    Http,
    Quic,
}

impl TransportType {
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "ws" | "websocket" => Self::Ws,
            "grpc" | "gun" => Self::Grpc,
            "httpupgrade" | "http-upgrade" | "http_upgrade" => Self::HttpUpgrade,
            "http" | "h2" | "h2mux" | "h3" => Self::Http,
            "quic" => Self::Quic,
            _ => Self::Tcp,
        }
    }

    pub fn singbox_type(&self) -> Option<&'static str> {
        match self {
            Self::Tcp => None,
            Self::Ws => Some("ws"),
            Self::Grpc => Some("grpc"),
            Self::HttpUpgrade => Some("httpupgrade"),
            Self::Http => Some("http"),
            Self::Quic => Some("quic"),
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Ws => "WebSocket",
            Self::Grpc => "gRPC",
            Self::HttpUpgrade => "HTTPUpgrade",
            Self::Http => "HTTP/2",
            Self::Quic => "QUIC",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UtlsFingerprint {
    #[default]
    Chrome,
    ChromePsk,
    ChromePq,
    Firefox,
    Edge,
    Safari,
    Qq,
    Tri60,
    Ios,
    Android,
    Random,
    Randomized,
}

impl UtlsFingerprint {
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "chrome_psk" | "chrome-psk" => Self::ChromePsk,
            "chrome_pq" | "chrome-pq" => Self::ChromePq,
            "firefox" => Self::Firefox,
            "edge" => Self::Edge,
            "safari" => Self::Safari,
            "qq" => Self::Qq,
            "360" => Self::Tri60,
            "ios" => Self::Ios,
            "android" => Self::Android,
            "random" => Self::Random,
            "randomized" => Self::Randomized,
            _ => Self::Chrome,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::ChromePsk => "chrome_psk",
            Self::ChromePq => "chrome_pq",
            Self::Firefox => "firefox",
            Self::Edge => "edge",
            Self::Safari => "safari",
            Self::Qq => "qq",
            Self::Tri60 => "360",
            Self::Ios => "ios",
            Self::Android => "android",
            Self::Random => "random",
            Self::Randomized => "randomized",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct EchConfig {
    pub enabled: bool,
    pub config: Vec<String>,
    pub config_path: Option<String>,
    pub query_server_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct TlsConfig {
    pub enabled: bool,
    pub server_name: Option<String>,
    pub insecure: bool,
    pub disable_sni: bool,
    pub alpn: Vec<String>,
    pub min_version: Option<String>,
    pub max_version: Option<String>,
    pub certificate: Vec<String>,
    pub certificate_path: Option<String>,
    pub fragment: bool,
    pub record_fragment: bool,
    pub utls: Option<UtlsFingerprint>,
    pub reality: Option<RealityConfig>,
    pub ech: Option<EchConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealityConfig {
    pub public_key: String,
    pub short_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct TransportConfig {
    pub transport_type: TransportType,
    pub path: Option<String>,
    pub service_name: Option<String>,
    pub host: Option<String>,
    pub method: Option<String>,
    pub headers: Vec<(String, String)>,
    pub max_early_data: Option<u32>,
    pub early_data_header_name: Option<String>,
    pub permit_without_stream: bool,
    pub idle_timeout: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MultiplexProtocol {
    #[default]
    Smux,
    Yamux,
    H2mux,
}

impl MultiplexProtocol {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "smux" => Some(Self::Smux),
            "yamux" => Some(Self::Yamux),
            "h2mux" => Some(Self::H2mux),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Smux => "smux",
            Self::Yamux => "yamux",
            Self::H2mux => "h2mux",
        }
    }

    pub fn index(&self) -> u32 {
        match self {
            Self::Smux => 0,
            Self::Yamux => 1,
            Self::H2mux => 2,
        }
    }

    pub fn from_index(index: u32) -> Self {
        match index {
            0 => Self::Smux,
            1 => Self::Yamux,
            _ => Self::H2mux,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct MultiplexConfig {
    pub enabled: bool,
    pub protocol: MultiplexProtocol,
    pub max_connections: Option<u32>,
    pub min_streams: Option<u32>,
    pub max_streams: Option<u32>,
    pub padding: bool,
    pub brutal_up_mbps: Option<u32>,
    pub brutal_down_mbps: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct UdpOverTcpConfig {
    pub enabled: bool,
    pub version: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowTlsConfig {
    pub version: u8,
    pub password: String,
    pub server: Option<String>,
    pub port: Option<u16>,
    pub server_name: Option<String>,
    pub utls: Option<UtlsFingerprint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VlessConfig {
    pub uuid: String,
    pub flow: Option<String>,
    #[serde(default)]
    pub packet_encoding: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmessConfig {
    pub uuid: String,
    pub alter_id: u32,
    pub security: String,
    #[serde(default)]
    pub global_padding: bool,
    #[serde(default)]
    pub authenticated_length: bool,
    #[serde(default)]
    pub packet_encoding: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrojanConfig {
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowsocksConfig {
    pub method: String,
    pub password: String,
    #[serde(default)]
    pub plugin: Option<String>,
    #[serde(default)]
    pub plugin_opts: Option<String>,
    #[serde(default)]
    pub shadow_tls: Option<ShadowTlsConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Hysteria2ObfsType {
    Salamander,
}

impl Hysteria2ObfsType {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "salamander" => Some(Self::Salamander),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Salamander => "salamander",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hysteria2Config {
    pub password: String,
    pub up_mbps: Option<u32>,
    pub down_mbps: Option<u32>,
    pub obfs: Option<Hysteria2ObfsType>,
    pub obfs_password: Option<String>,
    #[serde(default)]
    pub server_ports: Vec<String>,
    #[serde(default)]
    pub hop_interval: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HysteriaConfig {
    pub auth_str: Option<String>,
    pub auth_base64: Option<String>,
    pub up_mbps: Option<u32>,
    pub down_mbps: Option<u32>,
    pub obfs: Option<String>,
    #[serde(default)]
    pub disable_mtu_discovery: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TuicCongestionControl {
    Cubic,
    NewReno,
    Bbr,
}

impl TuicCongestionControl {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "cubic" => Some(Self::Cubic),
            "new_reno" | "newreno" => Some(Self::NewReno),
            "bbr" => Some(Self::Bbr),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cubic => "cubic",
            Self::NewReno => "new_reno",
            Self::Bbr => "bbr",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TuicUdpRelayMode {
    Native,
    Quic,
}

impl TuicUdpRelayMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "native" => Some(Self::Native),
            "quic" => Some(Self::Quic),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Quic => "quic",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TuicConfig {
    pub uuid: String,
    pub password: String,
    pub congestion_control: Option<TuicCongestionControl>,
    pub udp_relay_mode: Option<TuicUdpRelayMode>,
    #[serde(default)]
    pub zero_rtt_handshake: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnyTlsConfig {
    pub password: String,
    #[serde(default)]
    pub idle_session_check_interval: Option<String>,
    #[serde(default)]
    pub idle_session_timeout: Option<String>,
    #[serde(default)]
    pub min_idle_session: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnellConfig {
    pub psk: String,
    pub version: u8,
    #[serde(default)]
    pub obfs_mode: Option<String>,
    #[serde(default)]
    pub obfs_host: Option<String>,
    #[serde(default)]
    pub user_key: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshConfig {
    pub user: String,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub private_key: Vec<String>,
    #[serde(default)]
    pub private_key_path: Option<String>,
    #[serde(default)]
    pub private_key_passphrase: Option<String>,
    #[serde(default)]
    pub host_key: Vec<String>,
    #[serde(default)]
    pub host_key_algorithms: Vec<String>,
    #[serde(default)]
    pub client_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct TorConfig {
    pub executable_path: Option<String>,
    pub extra_args: Vec<String>,
    pub data_directory: Option<String>,
    pub torrc: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpProxyConfig {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocksConfig {
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireguardConfig {
    pub private_key: String,
    pub peer_public_key: String,
    pub pre_shared_key: Option<String>,
    pub local_address: Vec<String>,
    pub mtu: Option<u32>,
    pub reserved: Option<Vec<u8>>,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub persistent_keepalive_interval: Option<u32>,
    #[serde(default)]
    pub system_interface: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "details")]
pub enum ProtocolConfig {
    Vless(VlessConfig),
    Vmess(VmessConfig),
    Trojan(TrojanConfig),
    Shadowsocks(ShadowsocksConfig),
    Hysteria(HysteriaConfig),
    Hysteria2(Hysteria2Config),
    Tuic(TuicConfig),
    AnyTls(AnyTlsConfig),
    Snell(SnellConfig),
    Ssh(SshConfig),
    Tor(TorConfig),
    Http(HttpProxyConfig),
    Socks(SocksConfig),
    Wireguard(WireguardConfig),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyNode {
    pub id: String,
    pub name: String,
    pub server: String,
    pub port: u16,
    pub protocol: ProtocolType,
    pub config: ProtocolConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub transport: TransportConfig,
    #[serde(default)]
    pub multiplex: Option<MultiplexConfig>,
    #[serde(default)]
    pub udp_over_tcp: Option<UdpOverTcpConfig>,
    #[serde(default)]
    pub network: Option<String>,
    pub subscription_id: Option<String>,
    pub latency_ms: Option<u32>,
    pub last_checked: Option<chrono::DateTime<chrono::Utc>>,
}

impl ProxyNode {
    pub fn new(
        name: String,
        server: String,
        port: u16,
        protocol: ProtocolType,
        config: ProtocolConfig,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            server,
            port,
            protocol,
            config,
            tls: TlsConfig::default(),
            transport: TransportConfig::default(),
            multiplex: None,
            udp_over_tcp: None,
            network: None,
            subscription_id: None,
            latency_ms: None,
            last_checked: None,
        }
    }

    pub fn requires_exclusive_endpoint(&self) -> bool {
        match &self.config {
            ProtocolConfig::Wireguard(config) => config.system_interface,
            _ => false,
        }
    }

    pub fn outbound_tag(&self) -> String {
        let mut tag = String::with_capacity(self.name.len() + 10);
        for ch in self.name.chars() {
            if ch.is_alphanumeric() || matches!(ch, '-' | '_' | '.' | ' ') {
                tag.push(ch);
            }
        }
        let trimmed = tag.trim();
        let short_id: String = self.id.chars().take(8).collect();
        if trimmed.is_empty() {
            format!("node-{}", short_id)
        } else {
            let truncated: String = trimmed.chars().take(48).collect();
            format!("{} [{}]", truncated.trim_end(), short_id)
        }
    }

    pub fn country_code(&self) -> &'static str {
        const MATCHES: &[(&str, &[&str])] = &[
            ("US", &["UNITED STATES", "AMERICA", "USA"]),
            ("HK", &["HONG KONG", "HONGKONG"]),
            ("JP", &["JAPAN", "TOKYO", "OSAKA"]),
            ("SG", &["SINGAPORE"]),
            ("DE", &["GERMANY", "FRANKFURT", "DEUTSCHLAND"]),
            ("GB", &["UNITED KINGDOM", "LONDON", "ENGLAND", "BRITAIN"]),
            ("NL", &["NETHERLANDS", "AMSTERDAM", "HOLLAND"]),
            ("FR", &["FRANCE", "PARIS"]),
            ("CA", &["CANADA", "TORONTO", "MONTREAL"]),
            ("TR", &["TURKEY", "ISTANBUL", "TURKIYE"]),
            ("KR", &["KOREA", "SEOUL"]),
            ("TW", &["TAIWAN", "TAIPEI"]),
            ("IR", &["IRAN", "TEHRAN"]),
            ("AE", &["DUBAI", "EMIRATES", "UAE"]),
            ("RU", &["RUSSIA", "MOSCOW"]),
            ("FI", &["FINLAND", "HELSINKI"]),
            ("SE", &["SWEDEN", "STOCKHOLM"]),
            ("CH", &["SWITZERLAND", "ZURICH"]),
            ("AT", &["AUSTRIA", "VIENNA"]),
            ("PL", &["POLAND", "WARSAW"]),
            ("IN", &["INDIA", "MUMBAI"]),
            ("AU", &["AUSTRALIA", "SYDNEY"]),
            ("BR", &["BRAZIL"]),
            ("AM", &["ARMENIA", "YEREVAN"]),
            ("AZ", &["AZERBAIJAN", "BAKU"]),
            ("QA", &["QATAR", "DOHA"]),
            ("CN", &["CHINA", "SHANGHAI", "BEIJING"]),
        ];

        let upper = self.name.to_uppercase();
        for (code, keywords) in MATCHES {
            if keywords.iter().any(|kw| upper.contains(kw)) {
                return code;
            }
        }
        for (code, _) in MATCHES {
            if contains_standalone_token(&upper, code) {
                return code;
            }
        }
        "GLOBAL"
    }

    pub fn flag_emoji(&self) -> &'static str {
        match self.country_code() {
            "US" => "\u{1F1FA}\u{1F1F8}",
            "HK" => "\u{1F1ED}\u{1F1F0}",
            "JP" => "\u{1F1EF}\u{1F1F5}",
            "SG" => "\u{1F1F8}\u{1F1EC}",
            "DE" => "\u{1F1E9}\u{1F1EA}",
            "GB" => "\u{1F1EC}\u{1F1E7}",
            "NL" => "\u{1F1F3}\u{1F1F1}",
            "FR" => "\u{1F1EB}\u{1F1F7}",
            "CA" => "\u{1F1E8}\u{1F1E6}",
            "TR" => "\u{1F1F9}\u{1F1F7}",
            "KR" => "\u{1F1F0}\u{1F1F7}",
            "TW" => "\u{1F1F9}\u{1F1FC}",
            "IR" => "\u{1F1EE}\u{1F1F7}",
            "AE" => "\u{1F1E6}\u{1F1EA}",
            "RU" => "\u{1F1F7}\u{1F1FA}",
            "FI" => "\u{1F1EB}\u{1F1EE}",
            "SE" => "\u{1F1F8}\u{1F1EA}",
            "CH" => "\u{1F1E8}\u{1F1ED}",
            "AT" => "\u{1F1E6}\u{1F1F9}",
            "PL" => "\u{1F1F5}\u{1F1F1}",
            "IN" => "\u{1F1EE}\u{1F1F3}",
            "AU" => "\u{1F1E6}\u{1F1FA}",
            "BR" => "\u{1F1E7}\u{1F1F7}",
            "AM" => "\u{1F1E6}\u{1F1F2}",
            "AZ" => "\u{1F1E6}\u{1F1FF}",
            "QA" => "\u{1F1F6}\u{1F1E6}",
            "CN" => "\u{1F1E8}\u{1F1F3}",
            _ => "\u{1F310}",
        }
    }
}

fn contains_standalone_token(haystack: &str, token: &str) -> bool {
    let bytes = haystack.as_bytes();
    let token_bytes = token.as_bytes();
    if token_bytes.is_empty() || bytes.len() < token_bytes.len() {
        return false;
    }
    for start in 0..=bytes.len() - token_bytes.len() {
        if &bytes[start..start + token_bytes.len()] != token_bytes {
            continue;
        }
        let before_ok = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
        let after_index = start + token_bytes.len();
        let after_ok = after_index == bytes.len() || !bytes[after_index].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return true;
        }
    }
    false
}
