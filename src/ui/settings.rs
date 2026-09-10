use gtk4::glib;
use gtk4::prelude::*;
use gtk4::{Box, Orientation, ScrolledWindow};
use libadwaita as adw;
use libadwaita::prelude::*;
use std::cell::Cell;
use std::rc::Rc;

use crate::app::{AppContext, AppEvent};
use crate::config::autostart;
use crate::config::settings::{
    AppSettings, DnsStrategy, LogLevel, ThemePreference, TunStack,
};
use crate::core::dns_config::parse_dns_server;

pub struct SettingsPage {
    pub container: ScrolledWindow,
    theme_row: adw::ComboRow,
    core_path_row: adw::EntryRow,
    core_status_row: adw::ActionRow,
    log_level_row: adw::ComboRow,
    mixed_port_row: adw::SpinRow,
    http_port_row: adw::SpinRow,
    socks_port_row: adw::SpinRow,
    clash_port_row: adw::SpinRow,
    external_ui_row: adw::EntryRow,
    allow_lan_row: adw::SwitchRow,
    tun_stack_row: adw::ComboRow,
    tun_mtu_row: adw::SpinRow,
    tun_ipv6_row: adw::SwitchRow,
    tun_auto_route_row: adw::SwitchRow,
    tun_strict_route_row: adw::SwitchRow,
    tun_auto_redirect_row: adw::SwitchRow,
    tun_exclude_row: adw::EntryRow,
    remote_dns_row: adw::EntryRow,
    direct_dns_row: adw::EntryRow,
    dns_strategy_row: adw::ComboRow,
    fakeip_row: adw::SwitchRow,
    independent_cache_row: adw::SwitchRow,
    sniff_row: adw::SwitchRow,
    sniff_override_row: adw::SwitchRow,
    block_quic_row: adw::SwitchRow,
    latency_url_row: adw::EntryRow,
    urltest_interval_row: adw::SpinRow,
    urltest_tolerance_row: adw::SpinRow,
    ntp_row: adw::SwitchRow,
    ntp_server_row: adw::EntryRow,
    autostart_row: adw::SwitchRow,
    start_hidden_row: adw::SwitchRow,
    background_row: adw::SwitchRow,
    connect_on_start_row: adw::SwitchRow,
    auto_update_row: adw::SwitchRow,
    update_interval_row: adw::SpinRow,
    cache_row: adw::ActionRow,
    config_check_row: adw::ActionRow,
    suppress_signals: Rc<Cell<bool>>,
}

fn spin(min: f64, max: f64, step: f64) -> gtk4::Adjustment {
    gtk4::Adjustment::new(min, min, max, step, step * 10.0, 0.0)
}

impl SettingsPage {
    pub fn new(app_ctx: AppContext) -> Rc<Self> {
        let main_box = Box::builder()
            .orientation(Orientation::Vertical)
            .spacing(16)
            .margin_top(16)
            .margin_bottom(24)
            .margin_start(16)
            .margin_end(16)
            .build();

        let clamp = adw::Clamp::builder()
            .maximum_size(620)
            .tightening_threshold(400)
            .child(&main_box)
            .build();

        let container = ScrolledWindow::builder()
            .hscrollbar_policy(gtk4::PolicyType::Never)
            .child(&clamp)
            .build();

        let appearance_group = adw::PreferencesGroup::builder().title("Appearance").build();
        let theme_row = adw::ComboRow::builder()
            .title("Theme")
            .subtitle("Applies immediately")
            .model(&gtk4::StringList::new(&[
                ThemePreference::System.label(),
                ThemePreference::Light.label(),
                ThemePreference::Dark.label(),
            ]))
            .build();
        appearance_group.add(&theme_row);
        main_box.append(&appearance_group);

        let startup_group = adw::PreferencesGroup::builder().title("Startup").build();
        let autostart_row = adw::SwitchRow::builder()
            .title("Start on login")
            .subtitle("Adds a desktop entry to the XDG autostart directory")
            .build();
        let start_hidden_row = adw::SwitchRow::builder()
            .title("Start without a window")
            .subtitle("Only takes effect for the autostart entry")
            .build();
        let background_row = adw::SwitchRow::builder()
            .title("Keep running when the window closes")
            .subtitle("The core stays connected until you quit with Ctrl+Q")
            .build();
        let connect_on_start_row = adw::SwitchRow::builder()
            .title("Connect on launch")
            .subtitle("Starts the core as soon as RustyBird opens")
            .build();
        startup_group.add(&autostart_row);
        startup_group.add(&start_hidden_row);
        startup_group.add(&background_row);
        startup_group.add(&connect_on_start_row);
        main_box.append(&startup_group);

        let engine_group = adw::PreferencesGroup::builder()
            .title("Core engine")
            .description("RustyBird drives the sing-box binary installed on this system.")
            .build();
        let core_path_row = adw::EntryRow::builder()
            .title("sing-box binary path")
            .show_apply_button(true)
            .build();
        let core_status_row = adw::ActionRow::builder()
            .title("Binary status")
            .subtitle("Checking")
            .build();
        let log_level_row = adw::ComboRow::builder()
            .title("Log level")
            .model(&gtk4::StringList::new(
                &LogLevel::ALL.map(|level| level.as_str()),
            ))
            .build();
        let config_check_row = adw::ActionRow::builder()
            .title("Configuration")
            .subtitle("Not checked yet")
            .activatable(true)
            .build();
        config_check_row.add_suffix(
            &gtk4::Image::builder()
                .icon_name("emblem-ok-symbolic")
                .build(),
        );
        engine_group.add(&core_path_row);
        engine_group.add(&core_status_row);
        engine_group.add(&log_level_row);
        engine_group.add(&config_check_row);
        main_box.append(&engine_group);

        let ports_group = adw::PreferencesGroup::builder()
            .title("Local listeners")
            .description("Changing a port restarts the core when connected. Zero disables a listener.")
            .build();
        let mixed_port_row = adw::SpinRow::builder()
            .title("Mixed HTTP and SOCKS5 port")
            .adjustment(&spin(1024.0, 65535.0, 1.0))
            .build();
        let http_port_row = adw::SpinRow::builder()
            .title("Extra HTTP port")
            .adjustment(&spin(0.0, 65535.0, 1.0))
            .build();
        let socks_port_row = adw::SpinRow::builder()
            .title("Extra SOCKS5 port")
            .adjustment(&spin(0.0, 65535.0, 1.0))
            .build();
        let clash_port_row = adw::SpinRow::builder()
            .title("Clash API port")
            .subtitle("Bound to 127.0.0.1 and protected by a generated secret")
            .adjustment(&spin(1024.0, 65535.0, 1.0))
            .build();
        let external_ui_row = adw::EntryRow::builder()
            .title("Clash dashboard directory")
            .show_apply_button(true)
            .build();
        let allow_lan_row = adw::SwitchRow::builder()
            .title("Allow LAN connections")
            .subtitle("Exposes an unauthenticated proxy to your whole network")
            .build();
        ports_group.add(&mixed_port_row);
        ports_group.add(&http_port_row);
        ports_group.add(&socks_port_row);
        ports_group.add(&clash_port_row);
        ports_group.add(&external_ui_row);
        ports_group.add(&allow_lan_row);
        main_box.append(&ports_group);

        let tun_group = adw::PreferencesGroup::builder()
            .title("TUN")
            .description("Used when TUN mode is switched on from the Home page.")
            .build();
        let tun_stack_row = adw::ComboRow::builder()
            .title("Network stack")
            .subtitle("go is the sing-box default and uses the least memory")
            .model(&gtk4::StringList::new(&["go", "system", "gvisor", "mixed"]))
            .build();
        let tun_mtu_row = adw::SpinRow::builder()
            .title("MTU")
            .adjustment(&spin(576.0, 65535.0, 1.0))
            .build();
        let tun_ipv6_row = adw::SwitchRow::builder()
            .title("IPv6 inside the tunnel")
            .build();
        let tun_auto_route_row = adw::SwitchRow::builder()
            .title("Automatic routes")
            .subtitle("Let sing-box install the system routes")
            .build();
        let tun_strict_route_row = adw::SwitchRow::builder()
            .title("Strict route")
            .subtitle("Blocks traffic that tries to leave outside the tunnel")
            .build();
        let tun_auto_redirect_row = adw::SwitchRow::builder()
            .title("Automatic redirect")
            .subtitle("Uses nftables redirection for better TCP throughput")
            .build();
        let tun_exclude_row = adw::EntryRow::builder()
            .title("Excluded routes")
            .show_apply_button(true)
            .build();
        tun_group.add(&tun_stack_row);
        tun_group.add(&tun_mtu_row);
        tun_group.add(&tun_ipv6_row);
        tun_group.add(&tun_auto_route_row);
        tun_group.add(&tun_strict_route_row);
        tun_group.add(&tun_auto_redirect_row);
        tun_group.add(&tun_exclude_row);
        main_box.append(&tun_group);

        let dns_group = adw::PreferencesGroup::builder()
            .title("DNS")
            .description(
                "Accepts udp:// tcp:// tls:// https:// quic:// h3:// dhcp:// or local. \
                 A bare address means plain UDP.",
            )
            .build();
        let remote_dns_row = adw::EntryRow::builder()
            .title("Proxied resolver")
            .show_apply_button(true)
            .build();
        let direct_dns_row = adw::EntryRow::builder()
            .title("Direct resolver")
            .show_apply_button(true)
            .build();
        let dns_strategy_row = adw::ComboRow::builder()
            .title("Address family")
            .model(&gtk4::StringList::new(
                &DnsStrategy::ALL.map(|strategy| strategy.label()),
            ))
            .build();
        let fakeip_row = adw::SwitchRow::builder()
            .title("FakeIP")
            .subtitle("Answers with a synthetic address so domains survive TUN routing")
            .build();
        let independent_cache_row = adw::SwitchRow::builder()
            .title("Independent cache")
            .subtitle("Caches per resolver instead of globally")
            .build();
        dns_group.add(&remote_dns_row);
        dns_group.add(&direct_dns_row);
        dns_group.add(&dns_strategy_row);
        dns_group.add(&fakeip_row);
        dns_group.add(&independent_cache_row);
        main_box.append(&dns_group);

        let traffic_group = adw::PreferencesGroup::builder().title("Traffic").build();
        let sniff_row = adw::SwitchRow::builder()
            .title("Protocol sniffing")
            .subtitle("Reads the requested domain so routing rules can match it")
            .build();
        let sniff_override_row = adw::SwitchRow::builder()
            .title("Resolve sniffed domains")
            .subtitle("Re-resolves the sniffed name before connecting")
            .build();
        let block_quic_row = adw::SwitchRow::builder()
            .title("Block QUIC")
            .subtitle("Forces browsers back to TCP, which most proxies handle better")
            .build();
        let latency_url_row = adw::EntryRow::builder()
            .title("Latency test URL")
            .show_apply_button(true)
            .build();
        let urltest_interval_row = adw::SpinRow::builder()
            .title("URLTest interval (minutes)")
            .adjustment(&spin(1.0, 1440.0, 1.0))
            .build();
        let urltest_tolerance_row = adw::SpinRow::builder()
            .title("URLTest tolerance (ms)")
            .subtitle("How much faster another node must be before switching")
            .adjustment(&spin(0.0, 5000.0, 10.0))
            .build();
        traffic_group.add(&sniff_row);
        traffic_group.add(&sniff_override_row);
        traffic_group.add(&block_quic_row);
        traffic_group.add(&latency_url_row);
        traffic_group.add(&urltest_interval_row);
        traffic_group.add(&urltest_tolerance_row);
        main_box.append(&traffic_group);

        let updates_group = adw::PreferencesGroup::builder()
            .title("Remote sources")
            .build();
        let auto_update_row = adw::SwitchRow::builder()
            .title("Update subscriptions automatically")
            .build();
        let update_interval_row = adw::SpinRow::builder()
            .title("Default interval (hours)")
            .adjustment(&spin(1.0, 720.0, 1.0))
            .build();
        updates_group.add(&auto_update_row);
        updates_group.add(&update_interval_row);
        main_box.append(&updates_group);

        let time_group = adw::PreferencesGroup::builder().title("Clock").build();
        let ntp_row = adw::SwitchRow::builder()
            .title("Correct the clock over NTP")
            .subtitle("Helps when the system time drifts and TLS handshakes fail")
            .build();
        let ntp_server_row = adw::EntryRow::builder()
            .title("NTP server")
            .show_apply_button(true)
            .build();
        time_group.add(&ntp_row);
        time_group.add(&ntp_server_row);
        main_box.append(&time_group);

        let storage_group = adw::PreferencesGroup::builder().title("Storage").build();
        let cache_row = adw::ActionRow::builder()
            .title("Cached rule sets and core state")
            .subtitle("Measuring")
            .build();
        let clear_cache_button = gtk4::Button::builder()
            .label("Clear")
            .css_classes(vec!["flat".to_string()])
            .valign(gtk4::Align::Center)
            .build();
        cache_row.add_suffix(&clear_cache_button);
        storage_group.add(&cache_row);
        main_box.append(&storage_group);

        let about_group = adw::PreferencesGroup::builder().title("About").build();
        let about_row = adw::ActionRow::builder()
            .title("RustyBird")
            .subtitle("A sing-box client for GNOME")
            .activatable(true)
            .build();
        about_group.add(&about_row);
        main_box.append(&about_group);

        let page = Rc::new(Self {
            container,
            theme_row,
            core_path_row,
            core_status_row,
            log_level_row,
            mixed_port_row,
            http_port_row,
            socks_port_row,
            clash_port_row,
            external_ui_row,
            allow_lan_row,
            tun_stack_row,
            tun_mtu_row,
            tun_ipv6_row,
            tun_auto_route_row,
            tun_strict_route_row,
            tun_auto_redirect_row,
            tun_exclude_row,
            remote_dns_row,
            direct_dns_row,
            dns_strategy_row,
            fakeip_row,
            independent_cache_row,
            sniff_row,
            sniff_override_row,
            block_quic_row,
            latency_url_row,
            urltest_interval_row,
            urltest_tolerance_row,
            ntp_row,
            ntp_server_row,
            autostart_row,
            start_hidden_row,
            background_row,
            connect_on_start_row,
            auto_update_row,
            update_interval_row,
            cache_row,
            config_check_row,
            suppress_signals: Rc::new(Cell::new(false)),
        });

        about_row.connect_activated(|row| {
            let root = row.root().and_then(|r| r.downcast::<gtk4::Window>().ok());
            let about = adw::AboutDialog::builder()
                .application_name("RustyBird")
                .application_icon("org.rustybird.RustyBird")
                .developer_name("RustyBird Contributors")
                .version(env!("CARGO_PKG_VERSION"))
                .comments("A mobile-first sing-box client for GNU/Linux following the GNOME HIG.")
                .website("https://github.com/rustybird/rustybird")
                .issue_url("https://github.com/rustybird/rustybird/issues")
                .license_type(gtk4::License::Gpl30)
                .developers(vec!["RustyBird Contributors"])
                .build();
            about.present(root.as_ref());
        });

        let page_for_cache = page.clone();
        clear_cache_button.connect_clicked(move |button| {
            button.set_sensitive(false);
            let page = page_for_cache.clone();
            let button = button.clone();
            glib::spawn_future_local(async move {
                clear_cache();
                page.refresh_cache_size();
                button.set_sensitive(true);
            });
        });

        page.connect_signals(app_ctx);
        page
    }

    fn connect_signals(self: &Rc<Self>, app_ctx: AppContext) {
        let page = self.clone();
        let ctx = app_ctx.clone();
        glib::spawn_future_local(async move {
            let settings = ctx.settings.read().await.clone();
            page.apply_settings(&settings);
        });

        let page = self.clone();
        let ctx = app_ctx.clone();
        self.theme_row.connect_selected_notify(move |row| {
            if page.suppress_signals.get() {
                return;
            }
            let theme = ThemePreference::from_index(row.selected());
            crate::apply_theme(theme);
            let ctx = ctx.clone();
            glib::spawn_future_local(async move {
                let mut settings = ctx.settings.write().await;
                settings.theme = theme;
                settings.save();
            });
        });

        let page = self.clone();
        let ctx = app_ctx.clone();
        self.core_path_row.connect_apply(move |entry| {
            if page.suppress_signals.get() {
                return;
            }
            let path = entry.text().to_string().trim().to_string();
            let page = page.clone();
            let ctx = ctx.clone();
            glib::spawn_future_local(async move {
                {
                    let mut settings = ctx.settings.write().await;
                    settings.singbox_path = path.clone();
                    settings.save();
                }
                page.refresh_binary_status(&path);
                reload(&ctx).await;
            });
        });

        self.bind_combo(&app_ctx, &self.log_level_row, |settings, index| {
            settings.log_level = LogLevel::from_index(index);
        });
        self.bind_combo(&app_ctx, &self.tun_stack_row, |settings, index| {
            settings.tun_stack = TunStack::from_index(index);
        });
        self.bind_combo(&app_ctx, &self.dns_strategy_row, |settings, index| {
            settings.dns_strategy = DnsStrategy::from_index(index);
        });

        self.bind_spin(&app_ctx, &self.mixed_port_row, |settings, value| {
            settings.mixed_port = value as u16;
        });
        self.bind_spin(&app_ctx, &self.http_port_row, |settings, value| {
            settings.http_port = value as u16;
        });
        self.bind_spin(&app_ctx, &self.socks_port_row, |settings, value| {
            settings.socks_port = value as u16;
        });
        self.bind_spin(&app_ctx, &self.clash_port_row, |settings, value| {
            settings.clash_api_port = value as u16;
        });
        self.bind_spin(&app_ctx, &self.tun_mtu_row, |settings, value| {
            settings.tun_mtu = value as u32;
        });
        self.bind_spin(&app_ctx, &self.urltest_interval_row, |settings, value| {
            settings.urltest_interval_minutes = value as u32;
        });
        self.bind_spin(&app_ctx, &self.urltest_tolerance_row, |settings, value| {
            settings.urltest_tolerance = value as u32;
        });
        self.bind_spin(&app_ctx, &self.update_interval_row, |settings, value| {
            settings.update_interval_hours = value as u32;
        });

        self.bind_switch(&app_ctx, &self.allow_lan_row, |settings, value| {
            settings.allow_lan = value;
        });
        self.bind_switch(&app_ctx, &self.tun_ipv6_row, |settings, value| {
            settings.tun_ipv6 = value;
        });
        self.bind_switch(&app_ctx, &self.tun_auto_route_row, |settings, value| {
            settings.tun_auto_route = value;
        });
        self.bind_switch(&app_ctx, &self.tun_strict_route_row, |settings, value| {
            settings.tun_strict_route = value;
        });
        self.bind_switch(&app_ctx, &self.tun_auto_redirect_row, |settings, value| {
            settings.tun_auto_redirect = value;
        });
        self.bind_switch(&app_ctx, &self.fakeip_row, |settings, value| {
            settings.fakeip_enabled = value;
            settings.store_fakeip = value;
        });
        self.bind_switch(&app_ctx, &self.independent_cache_row, |settings, value| {
            settings.independent_dns_cache = value;
        });
        self.bind_switch(&app_ctx, &self.sniff_row, |settings, value| {
            settings.enable_sniff = value;
        });
        self.bind_switch(&app_ctx, &self.sniff_override_row, |settings, value| {
            settings.sniff_override_destination = value;
        });
        self.bind_switch(&app_ctx, &self.block_quic_row, |settings, value| {
            settings.block_quic = value;
        });
        self.bind_switch(&app_ctx, &self.ntp_row, |settings, value| {
            settings.ntp_enabled = value;
        });

        self.bind_plain_switch(&app_ctx, &self.background_row, |settings, value| {
            settings.keep_running_in_background = value;
        });
        self.bind_plain_switch(&app_ctx, &self.connect_on_start_row, |settings, value| {
            settings.connect_on_start = value;
        });
        self.bind_plain_switch(&app_ctx, &self.auto_update_row, |settings, value| {
            settings.auto_update_subscriptions = value;
        });

        self.bind_entry(&app_ctx, &self.external_ui_row, |settings, value| {
            settings.clash_api_external_ui = value;
        });
        self.bind_entry(&app_ctx, &self.latency_url_row, |settings, value| {
            if !value.trim().is_empty() {
                settings.latency_test_url = value;
            }
        });
        self.bind_entry(&app_ctx, &self.ntp_server_row, |settings, value| {
            if !value.trim().is_empty() {
                settings.ntp_server = value;
            }
        });
        self.bind_entry(&app_ctx, &self.tun_exclude_row, |settings, value| {
            settings.tun_exclude_routes = value
                .split(',')
                .map(|part| part.trim().to_string())
                .filter(|part| !part.is_empty())
                .collect();
        });

        let page = self.clone();
        let ctx = app_ctx.clone();
        self.remote_dns_row.connect_apply(move |entry| {
            if page.suppress_signals.get() {
                return;
            }
            let value = entry.text().to_string();
            if parse_dns_server(&value).is_none() {
                page.remote_dns_row.add_css_class("error");
                return;
            }
            page.remote_dns_row.remove_css_class("error");
            let ctx = ctx.clone();
            glib::spawn_future_local(async move {
                {
                    let mut settings = ctx.settings.write().await;
                    settings.remote_dns = value;
                    settings.save();
                }
                reload(&ctx).await;
            });
        });

        let page = self.clone();
        let ctx = app_ctx.clone();
        self.direct_dns_row.connect_apply(move |entry| {
            if page.suppress_signals.get() {
                return;
            }
            let value = entry.text().to_string();
            if parse_dns_server(&value).is_none() {
                page.direct_dns_row.add_css_class("error");
                return;
            }
            page.direct_dns_row.remove_css_class("error");
            let ctx = ctx.clone();
            glib::spawn_future_local(async move {
                {
                    let mut settings = ctx.settings.write().await;
                    settings.direct_dns = value;
                    settings.save();
                }
                reload(&ctx).await;
            });
        });

        let page = self.clone();
        let ctx = app_ctx.clone();
        self.autostart_row.connect_active_notify(move |row| {
            if page.suppress_signals.get() {
                return;
            }
            let enabled = row.is_active();
            let page = page.clone();
            let ctx = ctx.clone();
            let row = row.clone();
            glib::spawn_future_local(async move {
                let hidden = {
                    let mut settings = ctx.settings.write().await;
                    settings.autostart_enabled = enabled;
                    settings.save();
                    settings.start_hidden
                };
                if let Err(error) = autostart::set_enabled(enabled, hidden) {
                    tracing::error!("could not update the autostart entry: {}", error);
                    row.set_subtitle(&format!("Failed: {}", error));
                    page.suppress_signals.set(true);
                    row.set_active(autostart::is_enabled());
                    page.suppress_signals.set(false);
                } else {
                    row.set_subtitle("Adds a desktop entry to the XDG autostart directory");
                }
            });
        });

        let page = self.clone();
        let ctx = app_ctx.clone();
        self.start_hidden_row.connect_active_notify(move |row| {
            if page.suppress_signals.get() {
                return;
            }
            let hidden = row.is_active();
            let ctx = ctx.clone();
            glib::spawn_future_local(async move {
                let autostart_enabled = {
                    let mut settings = ctx.settings.write().await;
                    settings.start_hidden = hidden;
                    settings.save();
                    settings.autostart_enabled
                };
                if autostart_enabled {
                    if let Err(error) = autostart::set_enabled(true, hidden) {
                        tracing::error!("could not refresh the autostart entry: {}", error);
                    }
                }
            });
        });

        let ctx = app_ctx;
        self.config_check_row.connect_activated(move |row| {
            let ctx = ctx.clone();
            let row = row.clone();
            row.set_subtitle("Checking");
            glib::spawn_future_local(async move {
                match ctx.validate_current_config().await {
                    Ok(built) => {
                        let outbounds = built
                            .value
                            .get("outbounds")
                            .and_then(|value| value.as_array())
                            .map(|array| array.len())
                            .unwrap_or(0);
                        let mut summary = format!("Valid, {} outbounds", outbounds);
                        if ctx.runner.is_running() {
                            if let Ok(version) = ctx.clash_client().await.get_version().await {
                                if !version.version.is_empty() {
                                    summary.push_str(&format!(
                                        " \u{2022} running core {}",
                                        version.version
                                    ));
                                }
                            }
                        }
                        row.remove_css_class("error");
                        row.add_css_class("success");
                        row.set_subtitle(&summary);
                    }
                    Err(error) => {
                        row.remove_css_class("success");
                        row.add_css_class("error");
                        row.set_subtitle(&error.to_string());
                    }
                }
            });
        });
    }

    fn bind_combo<F>(self: &Rc<Self>, app_ctx: &AppContext, row: &adw::ComboRow, apply: F)
    where
        F: Fn(&mut AppSettings, u32) + 'static,
    {
        let page = self.clone();
        let ctx = app_ctx.clone();
        let apply = Rc::new(apply);
        row.connect_selected_notify(move |row| {
            if page.suppress_signals.get() {
                return;
            }
            let index = row.selected();
            let ctx = ctx.clone();
            let apply = apply.clone();
            glib::spawn_future_local(async move {
                {
                    let mut settings = ctx.settings.write().await;
                    apply(&mut settings, index);
                    settings.save();
                }
                reload(&ctx).await;
            });
        });
    }

    fn bind_spin<F>(self: &Rc<Self>, app_ctx: &AppContext, row: &adw::SpinRow, apply: F)
    where
        F: Fn(&mut AppSettings, f64) + 'static,
    {
        let page = self.clone();
        let ctx = app_ctx.clone();
        let apply = Rc::new(apply);
        row.connect_value_notify(move |row| {
            if page.suppress_signals.get() {
                return;
            }
            let value = row.value();
            let ctx = ctx.clone();
            let apply = apply.clone();
            glib::spawn_future_local(async move {
                {
                    let mut settings = ctx.settings.write().await;
                    apply(&mut settings, value);
                    settings.save();
                }
                reload(&ctx).await;
            });
        });
    }

    fn bind_switch<F>(self: &Rc<Self>, app_ctx: &AppContext, row: &adw::SwitchRow, apply: F)
    where
        F: Fn(&mut AppSettings, bool) + 'static,
    {
        let page = self.clone();
        let ctx = app_ctx.clone();
        let apply = Rc::new(apply);
        row.connect_active_notify(move |row| {
            if page.suppress_signals.get() {
                return;
            }
            let value = row.is_active();
            let ctx = ctx.clone();
            let apply = apply.clone();
            glib::spawn_future_local(async move {
                {
                    let mut settings = ctx.settings.write().await;
                    apply(&mut settings, value);
                    settings.save();
                }
                reload(&ctx).await;
            });
        });
    }

    fn bind_plain_switch<F>(self: &Rc<Self>, app_ctx: &AppContext, row: &adw::SwitchRow, apply: F)
    where
        F: Fn(&mut AppSettings, bool) + 'static,
    {
        let page = self.clone();
        let ctx = app_ctx.clone();
        let apply = Rc::new(apply);
        row.connect_active_notify(move |row| {
            if page.suppress_signals.get() {
                return;
            }
            let value = row.is_active();
            let ctx = ctx.clone();
            let apply = apply.clone();
            glib::spawn_future_local(async move {
                let mut settings = ctx.settings.write().await;
                apply(&mut settings, value);
                settings.save();
            });
        });
    }

    fn bind_entry<F>(self: &Rc<Self>, app_ctx: &AppContext, row: &adw::EntryRow, apply: F)
    where
        F: Fn(&mut AppSettings, String) + 'static,
    {
        let page = self.clone();
        let ctx = app_ctx.clone();
        let apply = Rc::new(apply);
        row.connect_apply(move |row| {
            if page.suppress_signals.get() {
                return;
            }
            let value = row.text().to_string();
            let ctx = ctx.clone();
            let apply = apply.clone();
            glib::spawn_future_local(async move {
                {
                    let mut settings = ctx.settings.write().await;
                    apply(&mut settings, value);
                    settings.save();
                }
                reload(&ctx).await;
            });
        });
    }

    fn apply_settings(&self, settings: &AppSettings) {
        self.suppress_signals.set(true);
        self.theme_row.set_selected(settings.theme.index());
        self.core_path_row.set_text(&settings.singbox_path);
        self.log_level_row.set_selected(settings.log_level.index());
        self.mixed_port_row.set_value(settings.mixed_port as f64);
        self.http_port_row.set_value(settings.http_port as f64);
        self.socks_port_row.set_value(settings.socks_port as f64);
        self.clash_port_row
            .set_value(settings.clash_api_port as f64);
        self.external_ui_row
            .set_text(&settings.clash_api_external_ui);
        self.allow_lan_row.set_active(settings.allow_lan);
        self.tun_stack_row.set_selected(settings.tun_stack.index());
        self.tun_mtu_row.set_value(settings.tun_mtu as f64);
        self.tun_ipv6_row.set_active(settings.tun_ipv6);
        self.tun_auto_route_row.set_active(settings.tun_auto_route);
        self.tun_strict_route_row
            .set_active(settings.tun_strict_route);
        self.tun_auto_redirect_row
            .set_active(settings.tun_auto_redirect);
        self.tun_exclude_row
            .set_text(&settings.tun_exclude_routes.join(", "));
        self.remote_dns_row.set_text(&settings.remote_dns);
        self.direct_dns_row.set_text(&settings.direct_dns);
        self.dns_strategy_row
            .set_selected(settings.dns_strategy.index());
        self.fakeip_row.set_active(settings.fakeip_enabled);
        self.independent_cache_row
            .set_active(settings.independent_dns_cache);
        self.sniff_row.set_active(settings.enable_sniff);
        self.sniff_override_row
            .set_active(settings.sniff_override_destination);
        self.block_quic_row.set_active(settings.block_quic);
        self.latency_url_row.set_text(&settings.latency_test_url);
        self.urltest_interval_row
            .set_value(settings.urltest_interval_minutes as f64);
        self.urltest_tolerance_row
            .set_value(settings.urltest_tolerance as f64);
        self.ntp_row.set_active(settings.ntp_enabled);
        self.ntp_server_row.set_text(&settings.ntp_server);
        self.autostart_row.set_active(autostart::is_enabled());
        self.start_hidden_row.set_active(settings.start_hidden);
        self.background_row
            .set_active(settings.keep_running_in_background);
        self.connect_on_start_row
            .set_active(settings.connect_on_start);
        self.auto_update_row
            .set_active(settings.auto_update_subscriptions);
        self.update_interval_row
            .set_value(settings.update_interval_hours as f64);
        self.suppress_signals.set(false);
        self.refresh_binary_status(&settings.singbox_path);
        self.refresh_cache_size();
    }

    fn refresh_cache_size(&self) {
        let row = self.cache_row.clone();
        glib::spawn_future_local(async move {
            let size = cache_size();
            row.set_subtitle(&crate::ui::widgets::speed_badge::format_bytes(size));
        });
    }

    fn refresh_binary_status(&self, path: &str) {
        let row = self.core_status_row.clone();
        let path = path.to_string();

        glib::spawn_future_local(async move {
            let found = std::path::Path::new(&path).is_file();
            if !found {
                row.set_subtitle("Not found, set a valid path above");
                row.remove_css_class("success");
                row.add_css_class("error");
                return;
            }

            let version = tokio::process::Command::new(&path)
                .arg("version")
                .output()
                .await
                .ok()
                .filter(|output| output.status.success())
                .map(|output| {
                    String::from_utf8_lossy(&output.stdout)
                        .lines()
                        .next()
                        .unwrap_or_default()
                        .trim()
                        .to_string()
                })
                .filter(|line| !line.is_empty());

            match version {
                Some(version) => {
                    row.set_subtitle(&version);
                    row.remove_css_class("error");
                    row.add_css_class("success");
                }
                None => {
                    row.set_subtitle("Found, but it did not report a version");
                    row.remove_css_class("success");
                    row.add_css_class("warning");
                }
            }
        });
    }

    pub fn sync_from_settings(&self, settings: &AppSettings) {
        self.apply_settings(settings);
    }
}

async fn reload(ctx: &AppContext) {
    ctx.notify(AppEvent::SettingsChanged);
    if let Err(error) = ctx.reload().await {
        tracing::error!("reload after a settings change failed: {}", error);
    }
}

fn directory_size(path: &std::path::Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    let mut total = 0;
    for entry in entries.flatten() {
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if metadata.is_dir() {
            total += directory_size(&entry.path());
        } else {
            total += metadata.len();
        }
    }
    total
}

fn cache_size() -> u64 {
    let paths = crate::config::paths::AppPaths::get();
    directory_size(&paths.cache_dir) + directory_size(&paths.rule_set_dir())
}

fn clear_cache() {
    let paths = crate::config::paths::AppPaths::get();
    for directory in [paths.cache_dir.clone(), paths.rule_set_dir()] {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let result = if path.is_dir() {
                std::fs::remove_dir_all(&path)
            } else {
                std::fs::remove_file(&path)
            };
            if let Err(error) = result {
                tracing::warn!("could not remove {:?}: {}", path, error);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_size_counts_nested_files() {
        let base = std::env::temp_dir().join(format!("rustybird-size-{}", std::process::id()));
        let nested = base.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(base.join("a.bin"), vec![0u8; 100]).unwrap();
        std::fs::write(nested.join("b.bin"), vec![0u8; 50]).unwrap();
        assert_eq!(directory_size(&base), 150);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn directory_size_of_a_missing_path_is_zero() {
        assert_eq!(
            directory_size(std::path::Path::new("/nonexistent-rustybird-path")),
            0
        );
    }
}
