pub mod clash;
pub mod node;
pub mod share;
pub mod subscription;
pub mod uri;

#[cfg(test)]
mod tests {
    use crate::parser::node::{ProtocolConfig, ProtocolType, TransportType};
    use crate::parser::uri::parse_proxy_uri;

    #[test]
    fn parses_vless_reality() {
        let uri = "vless://12345678-1234-1234-1234-1234567890ab@1.2.3.4:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com&fp=chrome&pbk=1234567890abcdef&sid=123456&type=tcp#TestRealityNode";
        let node = parse_proxy_uri(uri).expect("parse failed");
        assert_eq!(node.name, "TestRealityNode");
        assert_eq!(node.server, "1.2.3.4");
        assert_eq!(node.port, 443);
        assert_eq!(node.protocol, ProtocolType::Vless);
        assert!(node.tls.enabled);
        let reality = node.tls.reality.expect("missing reality");
        assert_eq!(reality.public_key, "1234567890abcdef");
        assert!(node.tls.utls.is_some());
    }

    #[test]
    fn reality_without_public_key_is_rejected() {
        let uri = "vless://12345678-1234-1234-1234-1234567890ab@1.2.3.4:443?security=reality#Bad";
        assert!(parse_proxy_uri(uri).is_err());
    }

    #[test]
    fn tls_without_reality_drops_a_stray_public_key() {
        let uri = "vless://12345678-1234-1234-1234-1234567890ab@1.2.3.4:443?security=tls&pbk=abc#Stray";
        let node = parse_proxy_uri(uri).expect("parse failed");
        assert!(node.tls.reality.is_none());
    }

    #[test]
    fn parses_hysteria2() {
        let uri = "hysteria2://password123@my-server.com:443?sni=my-server.com&insecure=1&obfs=salamander&obfs-password=xyz#Hysteria2Test";
        let node = parse_proxy_uri(uri).expect("parse failed");
        assert_eq!(node.protocol, ProtocolType::Hysteria2);
        assert!(node.tls.insecure);
        match node.config {
            ProtocolConfig::Hysteria2(config) => {
                assert!(config.obfs.is_some());
                assert_eq!(config.obfs_password.as_deref(), Some("xyz"));
            }
            _ => panic!("wrong protocol config"),
        }
    }

    #[test]
    fn unknown_obfs_is_dropped() {
        let uri = "hysteria2://pw@server.com:443?obfs=nonsense#Obfs";
        let node = parse_proxy_uri(uri).expect("parse failed");
        match node.config {
            ProtocolConfig::Hysteria2(config) => assert!(config.obfs.is_none()),
            _ => panic!("wrong protocol config"),
        }
    }

    #[test]
    fn parses_trojan_websocket() {
        let uri = "trojan://mypassword@trojan.example.com:443?sni=trojan.example.com&type=ws&path=%2Fws#TrojanWS";
        let node = parse_proxy_uri(uri).expect("parse failed");
        assert_eq!(node.protocol, ProtocolType::Trojan);
        assert_eq!(node.transport.transport_type, TransportType::Ws);
        assert_eq!(node.transport.path.as_deref(), Some("/ws"));
    }

    #[test]
    fn parses_shadowsocks_base64_userinfo() {
        let uri = "ss://YWVzLTI1Ni1nY206c2VjcmV0@ss.example.com:8388#SSNode";
        let node = parse_proxy_uri(uri).expect("parse failed");
        assert_eq!(node.protocol, ProtocolType::Shadowsocks);
        match node.config {
            ProtocolConfig::Shadowsocks(config) => {
                assert_eq!(config.method, "aes-256-gcm");
                assert_eq!(config.password, "secret");
            }
            _ => panic!("wrong protocol config"),
        }
    }

    #[test]
    fn parses_vmess_json() {
        let payload = r#"{"v":"2","ps":"VMessNode","add":"vm.example.com","port":"443","id":"12345678-1234-1234-1234-1234567890ab","aid":"0","scy":"auto","net":"ws","host":"vm.example.com","path":"/ray","tls":"tls"}"#;
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            payload.as_bytes(),
        );
        let node = parse_proxy_uri(&format!("vmess://{}", encoded)).expect("parse failed");
        assert_eq!(node.name, "VMessNode");
        assert_eq!(node.port, 443);
        assert!(node.tls.enabled);
        assert_eq!(node.transport.transport_type, TransportType::Ws);
    }

    #[test]
    fn vmess_tcp_with_http_header_becomes_the_http_transport() {
        let payload = r#"{"v":"2","ps":"Obfs","add":"vm.example.com","port":"443","id":"12345678-1234-1234-1234-1234567890ab","net":"tcp","type":"http","host":"cdn.example.com","path":"/"}"#;
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            payload.as_bytes(),
        );
        let node = parse_proxy_uri(&format!("vmess://{}", encoded)).expect("parse failed");
        assert_eq!(node.transport.transport_type, TransportType::Http);
    }

    #[test]
    fn parses_anytls() {
        let node = parse_proxy_uri("anytls://pw@any.example.com:8443?sni=any.example.com&min_idle_session=4#AnyTLS")
            .expect("parse failed");
        assert_eq!(node.protocol, ProtocolType::AnyTls);
        assert!(node.tls.enabled);
        match node.config {
            ProtocolConfig::AnyTls(config) => {
                assert_eq!(config.password, "pw");
                assert_eq!(config.min_idle_session, Some(4));
            }
            _ => panic!("wrong protocol config"),
        }
    }

    #[test]
    fn parses_snell_and_rejects_server_only_versions() {
        let node = parse_proxy_uri("snell://psk@sn.example.com:44046?version=6&mode=unshaped#Snell6")
            .expect("parse failed");
        match node.config {
            ProtocolConfig::Snell(config) => {
                assert_eq!(config.version, 6);
                assert_eq!(config.mode.as_deref(), Some("unshaped"));
            }
            _ => panic!("wrong protocol config"),
        }
        assert!(parse_proxy_uri("snell://psk@sn.example.com:44046?version=5#Bad").is_err());
        assert!(parse_proxy_uri("snell://psk@sn.example.com?version=4#NoPort").is_err());
    }

    #[test]
    fn parses_ssh_socks_and_http_proxies() {
        let ssh = parse_proxy_uri("ssh://root:secret@ssh.example.com:22#SSH").expect("ssh failed");
        assert_eq!(ssh.protocol, ProtocolType::Ssh);
        match ssh.config {
            ProtocolConfig::Ssh(config) => {
                assert_eq!(config.user, "root");
                assert_eq!(config.password.as_deref(), Some("secret"));
            }
            _ => panic!("wrong protocol config"),
        }

        let socks = parse_proxy_uri("socks4://s.example.com:1080#S4").expect("socks failed");
        match socks.config {
            ProtocolConfig::Socks(config) => assert_eq!(config.version.as_deref(), Some("4")),
            _ => panic!("wrong protocol config"),
        }

        let https = parse_proxy_uri("https://u:p@proxy.example.com:8443#HTTPS").expect("http failed");
        assert_eq!(https.protocol, ProtocolType::Http);
        assert!(https.tls.enabled);
    }

    #[test]
    fn parses_hysteria_v1_and_requires_auth() {
        let node = parse_proxy_uri("hysteria://h.example.com:443?auth=token&upmbps=50&downmbps=200#HY1")
            .expect("parse failed");
        assert_eq!(node.protocol, ProtocolType::Hysteria);
        match node.config {
            ProtocolConfig::Hysteria(config) => {
                assert_eq!(config.auth_str.as_deref(), Some("token"));
                assert_eq!(config.up_mbps, Some(50));
            }
            _ => panic!("wrong protocol config"),
        }
        assert!(parse_proxy_uri("hysteria://h.example.com:443#NoAuth").is_err());
    }

    #[test]
    fn parses_wireguard_links() {
        let node = parse_proxy_uri(
            "wireguard://uCRsuACIPWUXQAi0h2%2FaD6rLLqYfoHpMguB362WzlHQ%3D@wg.example.com:51820?publickey=gK3h8wLb3tS40GDsJeMYbh5z8U2ktfcYv%2B5F1yzTyRQ%3D&address=10.0.0.2%2F32&mtu=1408&reserved=1,2,3#WG",
        )
        .expect("parse failed");
        assert_eq!(node.protocol, ProtocolType::Wireguard);
        match node.config {
            ProtocolConfig::Wireguard(config) => {
                assert_eq!(config.private_key, "uCRsuACIPWUXQAi0h2/aD6rLLqYfoHpMguB362WzlHQ=");
                assert_eq!(
                    config.peer_public_key,
                    "gK3h8wLb3tS40GDsJeMYbh5z8U2ktfcYv+5F1yzTyRQ="
                );
                assert_eq!(config.local_address, vec!["10.0.0.2/32".to_string()]);
                assert_eq!(config.reserved, Some(vec![1, 2, 3]));
            }
            _ => panic!("wrong protocol config"),
        }
        assert!(parse_proxy_uri("wireguard://key@wg.example.com:51820#NoPeer").is_err());
    }

    #[test]
    fn parses_shadowsocks_plugins() {
        let obfs = parse_proxy_uri(
            "ss://YWVzLTI1Ni1nY206c2VjcmV0@s.example.com:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.example.com#SS",
        )
        .expect("parse failed");
        match obfs.config {
            ProtocolConfig::Shadowsocks(config) => {
                assert_eq!(config.plugin.as_deref(), Some("obfs-local"));
                assert!(config.plugin_opts.as_deref().unwrap().contains("obfs=http"));
            }
            _ => panic!("wrong protocol config"),
        }

        let shadow_tls = parse_proxy_uri(
            "ss://YWVzLTI1Ni1nY206c2VjcmV0@s.example.com:443?plugin=shadow-tls%3Bpassword%3Dstls%3Bversion%3D3%3Bhost%3Dwww.microsoft.com#SS",
        )
        .expect("parse failed");
        match shadow_tls.config {
            ProtocolConfig::Shadowsocks(config) => {
                let stls = config.shadow_tls.expect("missing shadow-tls");
                assert_eq!(stls.version, 3);
                assert_eq!(stls.server_name.as_deref(), Some("www.microsoft.com"));
            }
            _ => panic!("wrong protocol config"),
        }

        assert!(parse_proxy_uri(
            "ss://YWVzLTI1Ni1nY206c2VjcmV0@s.example.com:443?plugin=nonsense#SS"
        )
        .is_err());
    }

    #[test]
    fn trojan_go_path_implies_websocket() {
        let node = parse_proxy_uri("trojan-go://pw@t.example.com:443?path=%2Fgo#TG")
            .expect("parse failed");
        assert_eq!(node.protocol, ProtocolType::Trojan);
        assert_eq!(node.transport.transport_type, TransportType::Ws);
    }

    #[test]
    fn parses_multiplex_hints() {
        let node = parse_proxy_uri(
            "vless://12345678-1234-1234-1234-1234567890ab@1.2.3.4:443?security=tls&mux=yamux&muxmaxstreams=8&muxpadding=1#Mux",
        )
        .expect("parse failed");
        let multiplex = node.multiplex.expect("missing multiplex");
        assert_eq!(
            multiplex.protocol,
            crate::parser::node::MultiplexProtocol::Yamux
        );
        assert_eq!(multiplex.max_streams, Some(8));
        assert!(multiplex.padding);
    }

    #[test]
    fn rejects_unknown_scheme() {
        assert!(parse_proxy_uri("ftp://example.com").is_err());
        assert!(parse_proxy_uri("not a uri").is_err());
    }

    #[test]
    fn outbound_tags_are_unique_and_sanitized() {
        let node =
            parse_proxy_uri("trojan://pw@a.example.com:443#My%20Node%20%F0%9F%87%BA%F0%9F%87%B8")
                .expect("parse failed");
        let tag = node.outbound_tag();
        assert!(tag.starts_with("My Node"));
        assert!(!tag.contains('\u{1F1FA}'));
    }
}
