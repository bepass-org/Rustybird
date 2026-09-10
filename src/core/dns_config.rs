use serde_json::{Map, Value, json};

use crate::config::settings::{AppSettings, DnsStrategy};

pub const DNS_PROXY_TAG: &str = "dns-proxy";
pub const DNS_DIRECT_TAG: &str = "dns-direct";
pub const DNS_FAKEIP_TAG: &str = "dns-fakeip";

pub const FAKEIP_INET4_RANGE: &str = "198.18.0.0/15";
pub const FAKEIP_INET6_RANGE: &str = "fc00::/18";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsServerSpec {
    pub kind: String,
    pub server: Option<String>,
    pub server_port: Option<u16>,
    pub path: Option<String>,
    pub interface: Option<String>,
}

impl DnsServerSpec {
    pub fn to_value(&self, tag: &str, detour: Option<&str>) -> Value {
        let mut object = Map::new();
        object.insert("type".to_string(), json!(self.kind));
        object.insert("tag".to_string(), json!(tag));
        if let Some(server) = &self.server {
            object.insert("server".to_string(), json!(server));
        }
        if let Some(port) = self.server_port {
            object.insert("server_port".to_string(), json!(port));
        }
        if let Some(path) = &self.path {
            object.insert("path".to_string(), json!(path));
        }
        if let Some(interface) = &self.interface {
            object.insert("interface".to_string(), json!(interface));
        }
        if let Some(detour) = detour {
            if self.accepts_detour() {
                object.insert("detour".to_string(), json!(detour));
            }
        }
        Value::Object(object)
    }

    fn accepts_detour(&self) -> bool {
        !matches!(self.kind.as_str(), "local" | "fakeip" | "hosts" | "mdns")
    }
}

pub fn parse_dns_server(spec: &str) -> Option<DnsServerSpec> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return None;
    }

    let lowered = trimmed.to_ascii_lowercase();
    if matches!(lowered.as_str(), "local" | "system" | "local://") {
        return Some(DnsServerSpec {
            kind: "local".to_string(),
            server: None,
            server_port: None,
            path: None,
            interface: None,
        });
    }
    if lowered == "mdns" || lowered == "mdns://" {
        return Some(DnsServerSpec {
            kind: "mdns".to_string(),
            server: None,
            server_port: None,
            path: None,
            interface: None,
        });
    }
    if let Some(rest) = lowered.strip_prefix("dhcp://") {
        let interface = rest.trim_end_matches('/').trim();
        return Some(DnsServerSpec {
            kind: "dhcp".to_string(),
            server: None,
            server_port: None,
            path: None,
            interface: if interface.is_empty() || interface == "auto" {
                None
            } else {
                Some(interface.to_string())
            },
        });
    }

    let (kind, rest) = match trimmed.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest.to_string()),
        None => ("udp".to_string(), trimmed.to_string()),
    };

    let kind = match kind.as_str() {
        "udp" | "dns" => "udp",
        "tcp" => "tcp",
        "tls" | "dot" => "tls",
        "https" | "doh" | "h2" => "https",
        "quic" | "doq" => "quic",
        "h3" | "http3" => "h3",
        _ => return None,
    };

    let default_port = match kind {
        "udp" | "tcp" => 53,
        "tls" | "quic" => 853,
        _ => 443,
    };

    let (authority, path) = match rest.find('/') {
        Some(index) => {
            let (authority, path) = rest.split_at(index);
            (authority.to_string(), Some(path.to_string()))
        }
        None => (rest, None),
    };

    let (host, port) = split_host_port(&authority)?;
    if host.is_empty() {
        return None;
    }

    let path = match kind {
        "https" | "h3" => Some(
            path.filter(|p| !p.is_empty() && p != "/")
                .unwrap_or_else(|| "/dns-query".to_string()),
        ),
        _ => None,
    };

    Some(DnsServerSpec {
        kind: kind.to_string(),
        server: Some(host),
        server_port: Some(port.unwrap_or(default_port)).filter(|p| *p != default_port),
        path,
        interface: None,
    })
}

fn split_host_port(authority: &str) -> Option<(String, Option<u16>)> {
    let authority = authority.trim();
    if authority.is_empty() {
        return None;
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail
            .strip_prefix(':')
            .and_then(|value| value.parse::<u16>().ok());
        return Some((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => match port.parse::<u16>() {
            Ok(port) => Some((host.to_string(), Some(port))),
            Err(_) => Some((authority.to_string(), None)),
        },
        None => Some((authority.to_string(), None)),
    }
}

pub fn fallback_spec(kind: &str, server: &str) -> DnsServerSpec {
    DnsServerSpec {
        kind: kind.to_string(),
        server: Some(server.to_string()),
        server_port: None,
        path: None,
        interface: None,
    }
}

fn fakeip_query_types(strategy: DnsStrategy) -> Vec<&'static str> {
    match strategy {
        DnsStrategy::Ipv4Only => vec!["A"],
        DnsStrategy::Ipv6Only => vec!["AAAA"],
        _ => vec!["A", "AAAA"],
    }
}

pub fn build_dns(settings: &AppSettings, proxy_tag: &str, direct_tag: &str) -> Value {
    let remote = parse_dns_server(&settings.remote_dns)
        .unwrap_or_else(|| fallback_spec("https", "1.1.1.1"));
    let direct = parse_dns_server(&settings.direct_dns).unwrap_or_else(|| DnsServerSpec {
        kind: "local".to_string(),
        server: None,
        server_port: None,
        path: None,
        interface: None,
    });

    let mut servers = vec![
        remote.to_value(DNS_PROXY_TAG, Some(proxy_tag)),
        direct.to_value(DNS_DIRECT_TAG, Some(direct_tag)),
    ];

    let mut rules = vec![
        json!({ "clash_mode": "Direct", "server": DNS_DIRECT_TAG }),
        json!({ "clash_mode": "Global", "server": DNS_PROXY_TAG }),
        json!({
            "domain_suffix": [".local", ".lan", ".internal", ".home.arpa"],
            "server": DNS_DIRECT_TAG
        }),
    ];

    if settings.fakeip_enabled {
        let mut fakeip = Map::new();
        fakeip.insert("type".to_string(), json!("fakeip"));
        fakeip.insert("tag".to_string(), json!(DNS_FAKEIP_TAG));
        if settings.dns_strategy != DnsStrategy::Ipv6Only {
            fakeip.insert("inet4_range".to_string(), json!(FAKEIP_INET4_RANGE));
        }
        if settings.dns_strategy != DnsStrategy::Ipv4Only {
            fakeip.insert("inet6_range".to_string(), json!(FAKEIP_INET6_RANGE));
        }
        servers.push(Value::Object(fakeip));
        rules.push(json!({
            "query_type": fakeip_query_types(settings.dns_strategy),
            "server": DNS_FAKEIP_TAG
        }));
    }

    let mut dns = Map::new();
    dns.insert("servers".to_string(), Value::Array(servers));
    dns.insert("rules".to_string(), Value::Array(rules));
    dns.insert("final".to_string(), json!(DNS_PROXY_TAG));
    dns.insert("strategy".to_string(), json!(settings.dns_strategy.as_str()));
    if settings.independent_dns_cache {
        dns.insert("independent_cache".to_string(), json!(true));
    }
    if settings.fakeip_enabled {
        dns.insert("reverse_mapping".to_string(), json!(true));
    }
    Value::Object(dns)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_address_as_udp() {
        let spec = parse_dns_server("8.8.8.8").expect("parse failed");
        assert_eq!(spec.kind, "udp");
        assert_eq!(spec.server.as_deref(), Some("8.8.8.8"));
        assert_eq!(spec.server_port, None);
    }

    #[test]
    fn parses_doh_with_default_path() {
        let spec = parse_dns_server("https://dns.google").expect("parse failed");
        assert_eq!(spec.kind, "https");
        assert_eq!(spec.path.as_deref(), Some("/dns-query"));
        assert_eq!(spec.server.as_deref(), Some("dns.google"));
    }

    #[test]
    fn parses_doh_with_explicit_path_and_port() {
        let spec = parse_dns_server("https://example.com:8443/custom").expect("parse failed");
        assert_eq!(spec.server_port, Some(8443));
        assert_eq!(spec.path.as_deref(), Some("/custom"));
    }

    #[test]
    fn parses_dot_quic_and_h3() {
        assert_eq!(parse_dns_server("tls://1.1.1.1").unwrap().kind, "tls");
        assert_eq!(parse_dns_server("quic://dns.adguard.com").unwrap().kind, "quic");
        let h3 = parse_dns_server("h3://1.1.1.1/dns-query").unwrap();
        assert_eq!(h3.kind, "h3");
        assert_eq!(h3.path.as_deref(), Some("/dns-query"));
    }

    #[test]
    fn parses_local_and_dhcp() {
        assert_eq!(parse_dns_server("local").unwrap().kind, "local");
        let dhcp = parse_dns_server("dhcp://auto").unwrap();
        assert_eq!(dhcp.kind, "dhcp");
        assert_eq!(dhcp.interface, None);
        let dhcp_eth = parse_dns_server("dhcp://eth0").unwrap();
        assert_eq!(dhcp_eth.interface.as_deref(), Some("eth0"));
    }

    #[test]
    fn parses_ipv6_literal_with_port() {
        let spec = parse_dns_server("udp://[2606:4700:4700::1111]:5353").expect("parse failed");
        assert_eq!(spec.server.as_deref(), Some("2606:4700:4700::1111"));
        assert_eq!(spec.server_port, Some(5353));
    }

    #[test]
    fn rejects_unknown_scheme() {
        assert!(parse_dns_server("ftp://1.1.1.1").is_none());
        assert!(parse_dns_server("   ").is_none());
    }

    #[test]
    fn local_server_never_gets_a_detour() {
        let spec = parse_dns_server("local").unwrap();
        let value = spec.to_value("dns-direct", Some("direct"));
        assert!(value.get("detour").is_none());
    }

    #[test]
    fn remote_server_gets_the_proxy_detour() {
        let spec = parse_dns_server("https://1.1.1.1/dns-query").unwrap();
        let value = spec.to_value(DNS_PROXY_TAG, Some("proxy"));
        assert_eq!(value["detour"], "proxy");
        assert_eq!(value["type"], "https");
    }

    #[test]
    fn fakeip_adds_a_server_and_rule() {
        let mut settings = AppSettings::default();
        settings.fakeip_enabled = true;
        let dns = build_dns(&settings, "proxy", "direct");
        let servers = dns["servers"].as_array().unwrap();
        let fakeip = servers
            .iter()
            .find(|s| s["type"] == "fakeip")
            .expect("missing fakeip server");
        assert_eq!(fakeip["inet4_range"], FAKEIP_INET4_RANGE);
        assert_eq!(fakeip["inet6_range"], FAKEIP_INET6_RANGE);
        assert_eq!(dns["reverse_mapping"], true);
    }

    #[test]
    fn fakeip_ranges_and_queries_follow_the_address_family() {
        let mut settings = AppSettings::default();
        settings.fakeip_enabled = true;

        settings.dns_strategy = DnsStrategy::Ipv4Only;
        let dns = build_dns(&settings, "proxy", "direct");
        let fakeip = dns["servers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["type"] == "fakeip")
            .unwrap()
            .clone();
        assert!(fakeip.get("inet6_range").is_none());
        assert_eq!(fakeip_query_types(DnsStrategy::Ipv4Only), vec!["A"]);

        settings.dns_strategy = DnsStrategy::Ipv6Only;
        let dns = build_dns(&settings, "proxy", "direct");
        let fakeip = dns["servers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["type"] == "fakeip")
            .unwrap()
            .clone();
        assert!(fakeip.get("inet4_range").is_none());
        assert_eq!(fakeip_query_types(DnsStrategy::Ipv6Only), vec!["AAAA"]);
    }
}
