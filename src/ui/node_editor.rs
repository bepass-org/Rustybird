use gtk4::glib;
use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;

use crate::app::{AppContext, AppEvent};
use crate::parser::node::{
    MultiplexConfig, MultiplexProtocol, ProxyNode, TransportType, UdpOverTcpConfig,
    UtlsFingerprint,
};

const TRANSPORTS: [TransportType; 6] = [
    TransportType::Tcp,
    TransportType::Ws,
    TransportType::Grpc,
    TransportType::HttpUpgrade,
    TransportType::Http,
    TransportType::Quic,
];

const FINGERPRINTS: [UtlsFingerprint; 12] = [
    UtlsFingerprint::Chrome,
    UtlsFingerprint::ChromePsk,
    UtlsFingerprint::ChromePq,
    UtlsFingerprint::Firefox,
    UtlsFingerprint::Edge,
    UtlsFingerprint::Safari,
    UtlsFingerprint::Qq,
    UtlsFingerprint::Tri60,
    UtlsFingerprint::Ios,
    UtlsFingerprint::Android,
    UtlsFingerprint::Random,
    UtlsFingerprint::Randomized,
];

const TLS_VERSIONS: [&str; 5] = ["auto", "1.0", "1.1", "1.2", "1.3"];
const NETWORKS: [&str; 3] = ["tcp and udp", "tcp only", "udp only"];

fn spin(value: f64, min: f64, max: f64) -> gtk4::Adjustment {
    gtk4::Adjustment::new(value, min, max, 1.0, 10.0, 0.0)
}

fn tls_version_index(value: Option<&str>) -> u32 {
    match value {
        Some("1.0") => 1,
        Some("1.1") => 2,
        Some("1.2") => 3,
        Some("1.3") => 4,
        _ => 0,
    }
}

fn tls_version_from_index(index: u32) -> Option<String> {
    TLS_VERSIONS
        .get(index as usize)
        .filter(|value| **value != "auto")
        .map(|value| value.to_string())
}

fn network_index(value: Option<&str>) -> u32 {
    match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("tcp") => 1,
        Some("udp") => 2,
        _ => 0,
    }
}

fn network_from_index(index: u32) -> Option<String> {
    match index {
        1 => Some("tcp".to_string()),
        2 => Some("udp".to_string()),
        _ => None,
    }
}

fn optional_text(entry: &adw::EntryRow) -> Option<String> {
    let text = entry.text().to_string().trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

fn optional_count(row: &adw::SpinRow) -> Option<u32> {
    let value = row.value() as u32;
    if value == 0 { None } else { Some(value) }
}

pub fn show_node_editor(parent: Option<&gtk4::Window>, ctx: AppContext, node: ProxyNode) {
    let dialog = adw::PreferencesWindow::builder()
        .title(format!("Edit {}", node.name))
        .modal(true)
        .default_width(480)
        .default_height(620)
        .build();
    if let Some(parent) = parent {
        dialog.set_transient_for(Some(parent));
    }

    let page = adw::PreferencesPage::new();

    let identity_group = adw::PreferencesGroup::builder()
        .title("Endpoint")
        .description(format!("{} node", node.protocol))
        .build();
    let name_row = adw::EntryRow::builder().title("Name").build();
    name_row.set_text(&node.name);
    let server_row = adw::EntryRow::builder().title("Server").build();
    server_row.set_text(&node.server);
    let port_row = adw::SpinRow::builder()
        .title("Port")
        .adjustment(&spin(node.port as f64, 1.0, 65535.0))
        .build();
    let network_row = adw::ComboRow::builder()
        .title("Allowed networks")
        .model(&gtk4::StringList::new(&NETWORKS))
        .selected(network_index(node.network.as_deref()))
        .build();
    identity_group.add(&name_row);
    identity_group.add(&server_row);
    identity_group.add(&port_row);
    identity_group.add(&network_row);
    page.add(&identity_group);

    let supports_tls = node.protocol.supports_tls();
    let tls_group = adw::PreferencesGroup::builder()
        .title("TLS")
        .description(if supports_tls {
            "Applied to the outbound TLS block"
        } else {
            "This protocol does not carry a TLS block"
        })
        .sensitive(supports_tls)
        .build();
    let tls_enabled_row = adw::SwitchRow::builder()
        .title("Enable TLS")
        .active(node.tls.enabled)
        .sensitive(!node.protocol.requires_tls())
        .build();
    let sni_row = adw::EntryRow::builder().title("Server name (SNI)").build();
    sni_row.set_text(node.tls.server_name.as_deref().unwrap_or_default());
    let alpn_row = adw::EntryRow::builder()
        .title("ALPN")
        .tooltip_text("Comma separated, for example h2,http/1.1")
        .build();
    alpn_row.set_text(&node.tls.alpn.join(","));
    let insecure_row = adw::SwitchRow::builder()
        .title("Skip certificate verification")
        .subtitle("Only for servers with a self-signed certificate")
        .active(node.tls.insecure)
        .build();
    let disable_sni_row = adw::SwitchRow::builder()
        .title("Omit the SNI extension")
        .active(node.tls.disable_sni)
        .build();
    let fingerprint_row = adw::ComboRow::builder()
        .title("uTLS fingerprint")
        .model(&gtk4::StringList::new(
            &std::iter::once("off")
                .chain(FINGERPRINTS.iter().map(|f| f.as_str()))
                .collect::<Vec<_>>(),
        ))
        .selected(match node.tls.utls {
            Some(current) => FINGERPRINTS
                .iter()
                .position(|f| *f == current)
                .map(|index| index as u32 + 1)
                .unwrap_or(0),
            None => 0,
        })
        .build();
    let min_version_row = adw::ComboRow::builder()
        .title("Minimum version")
        .model(&gtk4::StringList::new(&TLS_VERSIONS))
        .selected(tls_version_index(node.tls.min_version.as_deref()))
        .build();
    let max_version_row = adw::ComboRow::builder()
        .title("Maximum version")
        .model(&gtk4::StringList::new(&TLS_VERSIONS))
        .selected(tls_version_index(node.tls.max_version.as_deref()))
        .build();
    let fragment_row = adw::SwitchRow::builder()
        .title("Fragment the client hello")
        .subtitle("Splits the first packet to get past some filters")
        .active(node.tls.fragment)
        .build();
    let record_fragment_row = adw::SwitchRow::builder()
        .title("Fragment TLS records")
        .active(node.tls.record_fragment)
        .build();
    let ech_row = adw::SwitchRow::builder()
        .title("Encrypted client hello")
        .active(node.tls.ech.as_ref().map(|e| e.enabled).unwrap_or(false))
        .build();
    let certificate_path_row = adw::EntryRow::builder()
        .title("Certificate authority path")
        .build();
    certificate_path_row.set_text(node.tls.certificate_path.as_deref().unwrap_or_default());
    tls_group.add(&tls_enabled_row);
    tls_group.add(&sni_row);
    tls_group.add(&alpn_row);
    tls_group.add(&fingerprint_row);
    tls_group.add(&insecure_row);
    tls_group.add(&disable_sni_row);
    tls_group.add(&min_version_row);
    tls_group.add(&max_version_row);
    tls_group.add(&fragment_row);
    tls_group.add(&record_fragment_row);
    tls_group.add(&ech_row);
    tls_group.add(&certificate_path_row);
    page.add(&tls_group);

    let supports_transport = node.protocol.supports_v2ray_transport();
    let transport_group = adw::PreferencesGroup::builder()
        .title("Transport")
        .description(if supports_transport {
            "V2Ray transport layer"
        } else {
            "This protocol has no V2Ray transport"
        })
        .sensitive(supports_transport)
        .build();
    let transport_row = adw::ComboRow::builder()
        .title("Type")
        .model(&gtk4::StringList::new(
            &TRANSPORTS.map(|kind| kind.label()),
        ))
        .selected(
            TRANSPORTS
                .iter()
                .position(|kind| *kind == node.transport.transport_type)
                .unwrap_or(0) as u32,
        )
        .build();
    let path_row = adw::EntryRow::builder().title("Path").build();
    path_row.set_text(node.transport.path.as_deref().unwrap_or_default());
    let host_row = adw::EntryRow::builder().title("Host header").build();
    host_row.set_text(node.transport.host.as_deref().unwrap_or_default());
    let service_name_row = adw::EntryRow::builder().title("gRPC service name").build();
    service_name_row.set_text(node.transport.service_name.as_deref().unwrap_or_default());
    let method_row = adw::EntryRow::builder().title("HTTP method").build();
    method_row.set_text(node.transport.method.as_deref().unwrap_or_default());
    let early_data_row = adw::SpinRow::builder()
        .title("Max early data")
        .subtitle("Zero disables WebSocket early data")
        .adjustment(&spin(
            node.transport.max_early_data.unwrap_or(0) as f64,
            0.0,
            65535.0,
        ))
        .build();
    let early_data_header_row = adw::EntryRow::builder()
        .title("Early data header name")
        .build();
    early_data_header_row.set_text(
        node.transport
            .early_data_header_name
            .as_deref()
            .unwrap_or_default(),
    );
    let permit_without_stream_row = adw::SwitchRow::builder()
        .title("gRPC permit without stream")
        .active(node.transport.permit_without_stream)
        .build();
    transport_group.add(&transport_row);
    transport_group.add(&path_row);
    transport_group.add(&host_row);
    transport_group.add(&service_name_row);
    transport_group.add(&method_row);
    transport_group.add(&early_data_row);
    transport_group.add(&early_data_header_row);
    transport_group.add(&permit_without_stream_row);
    page.add(&transport_group);

    let supports_multiplex = node.protocol.supports_multiplex();
    let multiplex = node.multiplex.clone().unwrap_or_default();
    let multiplex_group = adw::PreferencesGroup::builder()
        .title("Multiplex")
        .description(if supports_multiplex {
            "Carries several streams over one connection"
        } else {
            "This protocol does not support multiplexing"
        })
        .sensitive(supports_multiplex)
        .build();
    let multiplex_enabled_row = adw::SwitchRow::builder()
        .title("Enable multiplexing")
        .active(multiplex.enabled)
        .build();
    let multiplex_protocol_row = adw::ComboRow::builder()
        .title("Protocol")
        .model(&gtk4::StringList::new(&["smux", "yamux", "h2mux"]))
        .selected(multiplex.protocol.index())
        .build();
    let max_connections_row = adw::SpinRow::builder()
        .title("Max connections")
        .adjustment(&spin(
            multiplex.max_connections.unwrap_or(0) as f64,
            0.0,
            64.0,
        ))
        .build();
    let min_streams_row = adw::SpinRow::builder()
        .title("Min streams")
        .adjustment(&spin(multiplex.min_streams.unwrap_or(0) as f64, 0.0, 1024.0))
        .build();
    let max_streams_row = adw::SpinRow::builder()
        .title("Max streams")
        .adjustment(&spin(multiplex.max_streams.unwrap_or(0) as f64, 0.0, 1024.0))
        .build();
    let padding_row = adw::SwitchRow::builder()
        .title("Padding")
        .active(multiplex.padding)
        .build();
    let brutal_up_row = adw::SpinRow::builder()
        .title("Brutal upload (Mbps)")
        .adjustment(&spin(
            multiplex.brutal_up_mbps.unwrap_or(0) as f64,
            0.0,
            10000.0,
        ))
        .build();
    let brutal_down_row = adw::SpinRow::builder()
        .title("Brutal download (Mbps)")
        .adjustment(&spin(
            multiplex.brutal_down_mbps.unwrap_or(0) as f64,
            0.0,
            10000.0,
        ))
        .build();
    multiplex_group.add(&multiplex_enabled_row);
    multiplex_group.add(&multiplex_protocol_row);
    multiplex_group.add(&max_connections_row);
    multiplex_group.add(&min_streams_row);
    multiplex_group.add(&max_streams_row);
    multiplex_group.add(&padding_row);
    multiplex_group.add(&brutal_up_row);
    multiplex_group.add(&brutal_down_row);
    page.add(&multiplex_group);

    let supports_uot = node.protocol.supports_udp_over_tcp();
    let uot_group = adw::PreferencesGroup::builder()
        .title("UDP over TCP")
        .sensitive(supports_uot)
        .build();
    let uot_row = adw::SwitchRow::builder()
        .title("Tunnel UDP over TCP")
        .active(
            node.udp_over_tcp
                .as_ref()
                .map(|uot| uot.enabled)
                .unwrap_or(false),
        )
        .build();
    let uot_version_row = adw::SpinRow::builder()
        .title("Protocol version")
        .subtitle("Zero keeps the sing-box default")
        .adjustment(&spin(
            node.udp_over_tcp
                .as_ref()
                .and_then(|uot| uot.version)
                .unwrap_or(0) as f64,
            0.0,
            2.0,
        ))
        .build();
    uot_group.add(&uot_row);
    uot_group.add(&uot_version_row);
    page.add(&uot_group);

    let action_group = adw::PreferencesGroup::new();
    let save_button = gtk4::Button::builder()
        .label("Save")
        .css_classes(vec!["suggested-action".to_string(), "pill".to_string()])
        .margin_top(12)
        .margin_bottom(12)
        .halign(gtk4::Align::Center)
        .build();
    let error_label = gtk4::Label::builder()
        .visible(false)
        .wrap(true)
        .xalign(0.0)
        .css_classes(vec!["caption".to_string(), "error".to_string()])
        .build();
    action_group.add(&save_button);
    action_group.add(&error_label);
    page.add(&action_group);
    dialog.add(&page);

    let dialog_for_save = dialog.clone();
    save_button.connect_clicked(move |_| {
        let name = name_row.text().to_string().trim().to_string();
        let server = server_row.text().to_string().trim().to_string();
        if name.is_empty() {
            error_label.set_text("Give the node a name.");
            error_label.set_visible(true);
            return;
        }
        if server.is_empty() && node.protocol.needs_server_address() {
            error_label.set_text("Enter a server address.");
            error_label.set_visible(true);
            return;
        }
        error_label.set_visible(false);

        let mut updated = node.clone();
        updated.name = name;
        updated.server = server;
        updated.port = port_row.value() as u16;
        updated.network = network_from_index(network_row.selected());

        updated.tls.enabled = tls_enabled_row.is_active() || node.protocol.requires_tls();
        updated.tls.server_name = optional_text(&sni_row);
        updated.tls.alpn = alpn_row
            .text()
            .split(',')
            .map(|part| part.trim().to_string())
            .filter(|part| !part.is_empty())
            .collect();
        updated.tls.insecure = insecure_row.is_active();
        updated.tls.disable_sni = disable_sni_row.is_active();
        updated.tls.utls = match fingerprint_row.selected() {
            0 => None,
            index => FINGERPRINTS.get(index as usize - 1).copied(),
        };
        updated.tls.min_version = tls_version_from_index(min_version_row.selected());
        updated.tls.max_version = tls_version_from_index(max_version_row.selected());
        updated.tls.fragment = fragment_row.is_active();
        updated.tls.record_fragment = record_fragment_row.is_active();
        updated.tls.certificate_path = optional_text(&certificate_path_row);
        updated.tls.ech = if ech_row.is_active() {
            let mut ech = updated.tls.ech.clone().unwrap_or_default();
            ech.enabled = true;
            Some(ech)
        } else {
            None
        };

        updated.transport.transport_type = TRANSPORTS
            .get(transport_row.selected() as usize)
            .copied()
            .unwrap_or_default();
        updated.transport.path = optional_text(&path_row);
        updated.transport.host = optional_text(&host_row);
        updated.transport.service_name = optional_text(&service_name_row);
        updated.transport.method = optional_text(&method_row);
        updated.transport.max_early_data = optional_count(&early_data_row);
        updated.transport.early_data_header_name = optional_text(&early_data_header_row);
        updated.transport.permit_without_stream = permit_without_stream_row.is_active();

        updated.multiplex = if multiplex_enabled_row.is_active() {
            Some(MultiplexConfig {
                enabled: true,
                protocol: MultiplexProtocol::from_index(multiplex_protocol_row.selected()),
                max_connections: optional_count(&max_connections_row),
                min_streams: optional_count(&min_streams_row),
                max_streams: optional_count(&max_streams_row),
                padding: padding_row.is_active(),
                brutal_up_mbps: optional_count(&brutal_up_row),
                brutal_down_mbps: optional_count(&brutal_down_row),
            })
        } else {
            None
        };

        updated.udp_over_tcp = if uot_row.is_active() {
            Some(UdpOverTcpConfig {
                enabled: true,
                version: optional_count(&uot_version_row).map(|value| value as u8),
            })
        } else {
            None
        };

        let ctx = ctx.clone();
        let dialog = dialog_for_save.clone();
        glib::spawn_future_local(async move {
            {
                let mut profiles = ctx.profiles.write().await;
                profiles.add_or_update_node(updated);
                profiles.save();
            }
            ctx.notify(AppEvent::ProfilesChanged);
            if let Err(error) = ctx.reload().await {
                tracing::error!("reload after editing a node failed: {}", error);
            }
            dialog.close();
        });
    });

    dialog.present();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_version_round_trips() {
        for version in ["1.0", "1.1", "1.2", "1.3"] {
            let index = tls_version_index(Some(version));
            assert_eq!(tls_version_from_index(index).as_deref(), Some(version));
        }
        assert_eq!(tls_version_index(None), 0);
        assert_eq!(tls_version_from_index(0), None);
        assert_eq!(tls_version_index(Some("9.9")), 0);
    }

    #[test]
    fn network_round_trips() {
        assert_eq!(network_from_index(network_index(Some("tcp"))).as_deref(), Some("tcp"));
        assert_eq!(network_from_index(network_index(Some("UDP"))).as_deref(), Some("udp"));
        assert_eq!(network_from_index(network_index(None)), None);
        assert_eq!(network_from_index(network_index(Some("sctp"))), None);
    }

    #[test]
    fn every_fingerprint_is_offered() {
        let mut seen: Vec<&str> = FINGERPRINTS.iter().map(|f| f.as_str()).collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), FINGERPRINTS.len());
        for fingerprint in FINGERPRINTS {
            assert_eq!(UtlsFingerprint::parse(fingerprint.as_str()), fingerprint);
        }
    }

    #[test]
    fn every_transport_is_offered() {
        for transport in TRANSPORTS {
            assert!(TRANSPORTS.contains(&transport));
        }
        assert_eq!(TRANSPORTS.len(), 6);
    }
}
