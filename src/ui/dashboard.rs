use gtk4::glib;
use gtk4::prelude::*;
use gtk4::{Box, Button, Label, Orientation, ScrolledWindow};
use libadwaita as adw;
use libadwaita::prelude::*;
use std::cell::Cell;
use std::rc::Rc;

use crate::app::AppContext;
use crate::config::settings::ProxyMode;
use crate::network::gnome_proxy::GnomeProxyManager;
use crate::network::tun::TunHelper;
use crate::ui::widgets::node_row::glib_escape;
use crate::ui::widgets::speed_badge::{format_bytes, format_duration, format_speed};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Failed,
}

const PILL_CLASSES: [&str; 4] = ["pill-off", "pill-busy", "pill-on", "pill-fail"];
const BUTTON_CLASSES: [&str; 4] = ["power-off", "power-busy", "power-on", "power-fail"];
impl ConnectionStatus {
    fn pill_class(&self) -> &'static str {
        match self {
            Self::Disconnected => "pill-off",
            Self::Connecting => "pill-busy",
            Self::Connected => "pill-on",
            Self::Failed => "pill-fail",
        }
    }

    fn button_class(&self) -> &'static str {
        match self {
            Self::Disconnected => "power-off",
            Self::Connecting => "power-busy",
            Self::Connected => "power-on",
            Self::Failed => "power-fail",
        }
    }

    fn action_label(&self) -> &'static str {
        match self {
            Self::Connected => "Disconnect",
            Self::Connecting => "Connecting",
            _ => "Connect",
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Disconnected => "DISCONNECTED",
            Self::Connecting => "CONNECTING",
            Self::Connected => "CONNECTED",
            Self::Failed => "FAILED",
        }
    }

    fn tooltip(&self) -> &'static str {
        match self {
            Self::Connected => "Disconnect",
            Self::Connecting => "Connecting",
            _ => "Connect",
        }
    }
}

pub struct DashboardPage {
    pub container: ScrolledWindow,
    connect_button: Button,
    power_icon: gtk4::Image,
    connect_label: Label,
    status_pill: Label,
    status_detail: Label,
    node_banner: Box,
    node_name_label: Label,
    node_flag_label: Label,
    speed_down_label: Label,
    speed_up_label: Label,
    total_down_label: Label,
    total_up_label: Label,
    uptime_label: Label,
    ip_row: adw::ActionRow,
    ip_label: Label,
    system_proxy_row: adw::SwitchRow,
    tun_row: adw::SwitchRow,
    mode_row: adw::ComboRow,
    suppress_signals: Rc<Cell<bool>>,
}

impl DashboardPage {
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
            .maximum_size(540)
            .tightening_threshold(360)
            .child(&main_box)
            .build();

        let container = ScrolledWindow::builder()
            .hscrollbar_policy(gtk4::PolicyType::Never)
            .child(&clamp)
            .build();

        let hero_card = Box::builder()
            .orientation(Orientation::Vertical)
            .spacing(12)
            .css_classes(vec!["card".to_string()])
            .build();

        let status_pill = Label::builder()
            .label(ConnectionStatus::Disconnected.label())
            .css_classes(vec!["status-pill".to_string(), "pill-off".to_string()])
            .halign(gtk4::Align::Center)
            .margin_top(22)
            .build();

        let power_icon = gtk4::Image::builder()
            .icon_name("rustybird-power-symbolic")
            .pixel_size(22)
            .build();

        let connect_label = Label::builder()
            .label(ConnectionStatus::Disconnected.action_label())
            .css_classes(vec!["connect-label".to_string()])
            .build();

        let button_content = Box::builder()
            .orientation(Orientation::Horizontal)
            .spacing(10)
            .halign(gtk4::Align::Center)
            .build();
        button_content.append(&power_icon);
        button_content.append(&connect_label);

        let connect_button = Button::builder()
            .child(&button_content)
            .css_classes(vec!["connect-button".to_string(), "power-off".to_string()])
            .height_request(56)
            .hexpand(true)
            .margin_start(16)
            .margin_end(16)
            .margin_top(4)
            .tooltip_text("Connect")
            .build();

        let status_detail = Label::builder()
            .label("")
            .visible(false)
            .wrap(true)
            .justify(gtk4::Justification::Center)
            .max_width_chars(40)
            .margin_start(12)
            .margin_end(12)
            .css_classes(vec!["caption".to_string()])
            .build();

        let node_banner = Box::builder()
            .orientation(Orientation::Horizontal)
            .spacing(10)
            .halign(gtk4::Align::Center)
            .css_classes(vec!["node-chip".to_string()])
            .margin_bottom(22)
            .margin_top(4)
            .build();
        if let Some(cursor) = gtk4::gdk::Cursor::from_name("pointer", None) {
            node_banner.set_cursor(Some(&cursor));
        }

        let node_flag_label = Label::builder()
            .label("\u{1F310}")
            .css_classes(vec!["title-2".to_string()])
            .build();

        let node_name_label = Label::builder()
            .label("No proxy selected")
            .css_classes(vec!["heading".to_string()])
            .ellipsize(gtk4::pango::EllipsizeMode::End)
            .max_width_chars(26)
            .build();

        node_banner.append(&node_flag_label);
        node_banner.append(&node_name_label);
        node_banner.append(
            &gtk4::Image::builder()
                .icon_name("go-next-symbolic")
                .css_classes(vec!["dim-label".to_string()])
                .build(),
        );

        hero_card.append(&status_pill);
        hero_card.append(&connect_button);
        hero_card.append(&status_detail);
        hero_card.append(&node_banner);

        let controls_group = adw::PreferencesGroup::builder()
            .title("Network controls")
            .build();

        let system_proxy_row = adw::SwitchRow::builder()
            .title("System proxy")
            .subtitle("Point the GNOME proxy settings at RustyBird")
            .build();
        if !GnomeProxyManager::is_available() {
            system_proxy_row.set_sensitive(false);
            system_proxy_row.set_subtitle("GNOME proxy settings are not available");
        }

        let tun_row = adw::SwitchRow::builder()
            .title("TUN mode")
            .subtitle("Route all system traffic, requires authentication")
            .build();
        if let Some(reason) = TunHelper::unavailable_reason() {
            tun_row.set_sensitive(false);
            tun_row.set_subtitle(reason);
        }

        let mode_row = adw::ComboRow::builder()
            .title("Routing mode")
            .subtitle("Applies instantly while connected")
            .model(&gtk4::StringList::new(&["Rule", "Global", "Direct"]))
            .build();

        controls_group.add(&system_proxy_row);
        controls_group.add(&tun_row);
        controls_group.add(&mode_row);

        let metrics_group = adw::PreferencesGroup::builder()
            .title("Live traffic")
            .build();

        let metrics_box = Box::builder()
            .orientation(Orientation::Horizontal)
            .spacing(12)
            .homogeneous(true)
            .build();

        let (down_card, speed_down_label) = build_metric_card("\u{2B07} Download");
        let (up_card, speed_up_label) = build_metric_card("\u{2B06} Upload");
        metrics_box.append(&down_card);
        metrics_box.append(&up_card);
        metrics_group.add(&metrics_box);

        let stats_group = adw::PreferencesGroup::builder().title("Session").build();

        let uptime_row = adw::ActionRow::builder().title("Uptime").build();
        let uptime_label = Label::builder()
            .label("00:00:00")
            .css_classes(vec!["numeric".to_string(), "dim-label".to_string()])
            .build();
        uptime_row.add_suffix(&uptime_label);

        let traffic_row = adw::ActionRow::builder().title("Session data").build();
        let traffic_box = Box::builder()
            .orientation(Orientation::Horizontal)
            .spacing(8)
            .build();
        let total_down_label = Label::builder()
            .label("\u{2B07} 0 B")
            .css_classes(vec!["numeric".to_string(), "dim-label".to_string()])
            .build();
        let total_up_label = Label::builder()
            .label("\u{2B06} 0 B")
            .css_classes(vec!["numeric".to_string(), "dim-label".to_string()])
            .build();
        traffic_box.append(&total_down_label);
        traffic_box.append(&total_up_label);
        traffic_row.add_suffix(&traffic_box);

        let ip_row = adw::ActionRow::builder()
            .title("Outbound IP")
            .subtitle("Not connected")
            .build();
        let ip_label = Label::builder()
            .label("Direct")
            .css_classes(vec!["caption".to_string(), "dim-label".to_string()])
            .build();
        ip_row.add_suffix(&ip_label);

        stats_group.add(&uptime_row);
        stats_group.add(&traffic_row);
        stats_group.add(&ip_row);

        main_box.append(&hero_card);
        main_box.append(&controls_group);
        main_box.append(&metrics_group);
        main_box.append(&stats_group);

        let page = Rc::new(Self {
            container,
            connect_button,
            power_icon,
            connect_label,
            status_pill,
            status_detail,
            node_banner,
            node_name_label,
            node_flag_label,
            speed_down_label,
            speed_up_label,
            total_down_label,
            total_up_label,
            uptime_label,
            ip_row,
            ip_label,
            system_proxy_row,
            tun_row,
            mode_row,
            suppress_signals: Rc::new(Cell::new(false)),
        });

        page.connect_signals(app_ctx);
        page
    }

    fn connect_signals(self: &Rc<Self>, app_ctx: AppContext) {
        let page = self.clone();
        let ctx = app_ctx.clone();
        glib::spawn_future_local(async move {
            let settings = ctx.settings.read().await.clone();
            page.suppress_signals.set(true);
            page.system_proxy_row
                .set_active(settings.system_proxy_auto_toggle);
            page.tun_row.set_active(settings.tun_mode);
            page.mode_row.set_selected(settings.proxy_mode.index());
            page.suppress_signals.set(false);
        });

        let page = self.clone();
        let ctx = app_ctx.clone();
        self.connect_button.connect_clicked(move |_| {
            let page = page.clone();
            let ctx = ctx.clone();
            page.set_status(ConnectionStatus::Connecting, None);
            page.connect_button.set_sensitive(false);

            glib::spawn_future_local(async move {
                match ctx.toggle_connect().await {
                    Ok(true) => {
                        page.set_status(ConnectionStatus::Connected, None);
                        page.set_health_checking();
                        let page = page.clone();
                        let ctx = ctx.clone();
                        glib::spawn_future_local(async move {
                            match ctx.probe_active_node().await {
                                Ok(latency) => page.set_health_ok(latency),
                                Err(error) => page.set_health_failed(&error),
                            }
                        });
                    }
                    Ok(false) => {
                        page.set_status(ConnectionStatus::Disconnected, None);
                        page.reset_metrics();
                    }
                    Err(error) => {
                        page.set_status(ConnectionStatus::Failed, Some(&error));
                        page.reset_metrics();
                    }
                }
                page.connect_button.set_sensitive(true);
            });
        });

        let page = self.clone();
        let ctx = app_ctx.clone();
        self.mode_row.connect_selected_notify(move |combo| {
            if page.suppress_signals.get() {
                return;
            }
            let mode = ProxyMode::from_index(combo.selected());
            let page = page.clone();
            let ctx = ctx.clone();
            glib::spawn_future_local(async move {
                if let Err(error) = ctx.set_proxy_mode(mode).await {
                    page.set_status(ConnectionStatus::Failed, Some(&error));
                }
            });
        });

        let page = self.clone();
        let ctx = app_ctx.clone();
        self.system_proxy_row.connect_active_notify(move |row| {
            if page.suppress_signals.get() {
                return;
            }
            let enabled = row.is_active();
            let page = page.clone();
            let ctx = ctx.clone();
            glib::spawn_future_local(async move {
                if let Err(error) = ctx.set_system_proxy(enabled).await {
                    page.set_status(ConnectionStatus::Failed, Some(&error));
                }
            });
        });

        let page = self.clone();
        let ctx = app_ctx;
        self.tun_row.connect_active_notify(move |row| {
            if page.suppress_signals.get() {
                return;
            }
            let enabled = row.is_active();
            let page = page.clone();
            let ctx = ctx.clone();
            glib::spawn_future_local(async move {
                {
                    let mut settings = ctx.settings.write().await;
                    settings.tun_mode = enabled;
                    settings.save();
                }
                if ctx.runner.is_running() {
                    page.set_status(ConnectionStatus::Connecting, None);
                    match ctx.reload().await {
                        Ok(()) => page.set_status(ConnectionStatus::Connected, None),
                        Err(error) => page.set_status(ConnectionStatus::Failed, Some(&error)),
                    }
                }
            });
        });
    }

    pub fn set_status(&self, status: ConnectionStatus, detail: Option<&str>) {
        for class in PILL_CLASSES {
            self.status_pill.remove_css_class(class);
        }
        self.status_pill.set_text(status.label());
        self.status_pill.add_css_class(status.pill_class());

        for class in BUTTON_CLASSES {
            self.connect_button.remove_css_class(class);
        }
        self.connect_button.add_css_class(status.button_class());

        self.power_icon.set_icon_name(Some(match status {
            ConnectionStatus::Connected => "rustybird-shield-symbolic",
            _ => "rustybird-power-symbolic",
        }));
        self.connect_label.set_text(status.action_label());
        self.connect_button.set_tooltip_text(Some(status.tooltip()));

        self.clear_health_classes();
        match detail {
            Some(detail) if !detail.is_empty() => {
                self.status_detail.add_css_class("error");
                self.status_detail.set_text(detail);
                self.status_detail.set_visible(true);
            }
            _ => {
                self.status_detail.set_text("");
                self.status_detail.set_visible(false);
            }
        }
    }

    pub async fn sync_mode_from_core(&self, app_ctx: &AppContext) {
        let Ok(mode) = app_ctx.clash_client().await.get_mode().await else {
            return;
        };
        let resolved = match mode.as_str() {
            "Global" => ProxyMode::Global,
            "Direct" => ProxyMode::Direct,
            "Rule" => ProxyMode::Rule,
            _ => return,
        };
        let mut settings = app_ctx.settings.write().await;
        if settings.proxy_mode != resolved {
            settings.proxy_mode = resolved;
            settings.save();
        }
        self.suppress_signals.set(true);
        self.mode_row.set_selected(resolved.index());
        self.suppress_signals.set(false);
    }

    pub fn set_profile_mode(&self, profile_active: bool) {
        self.tun_row.set_sensitive(!profile_active && TunHelper::unavailable_reason().is_none());
        self.system_proxy_row
            .set_sensitive(!profile_active && GnomeProxyManager::is_available());
        if profile_active {
            self.tun_row
                .set_subtitle("The active profile declares its own inbounds");
            self.system_proxy_row
                .set_subtitle("The active profile declares its own listeners");
        } else {
            self.tun_row
                .set_subtitle(TunHelper::unavailable_reason().unwrap_or(
                    "Route all system traffic, requires authentication",
                ));
            self.system_proxy_row.set_subtitle(if GnomeProxyManager::is_available() {
                "Point the GNOME proxy settings at RustyBird"
            } else {
                "GNOME proxy settings are not available"
            });
        }
    }

    pub fn sync_from_settings(&self, settings: &crate::config::settings::AppSettings) {
        self.suppress_signals.set(true);
        self.system_proxy_row
            .set_active(settings.system_proxy_auto_toggle);
        self.tun_row.set_active(settings.tun_mode);
        self.mode_row.set_selected(settings.proxy_mode.index());
        self.suppress_signals.set(false);
    }

    fn clear_health_classes(&self) {
        for class in ["error", "warning", "success", "dim-label"] {
            self.status_detail.remove_css_class(class);
        }
    }

    pub fn set_health_checking(&self) {
        self.clear_health_classes();
        self.status_detail.add_css_class("dim-label");
        self.status_detail.set_text("Checking the proxy\u{2026}");
        self.status_detail.set_visible(true);
    }

    pub fn set_health_ok(&self, latency_ms: u32) {
        self.clear_health_classes();
        self.status_detail.add_css_class("success");
        self.status_detail
            .set_text(&format!("Proxy responded in {} ms", latency_ms));
        self.status_detail.set_visible(true);
    }

    pub fn set_health_failed(&self, reason: &str) {
        self.clear_health_classes();
        self.status_detail.add_css_class("warning");
        self.status_detail.set_text(&format!(
            "Connected, but the proxy is not usable: {}",
            reason
        ));
        self.status_detail.set_visible(true);
    }

    pub fn update_active_node(&self, name: &str, flag: &str) {
        self.node_name_label.set_text(name);
        self.node_flag_label.set_text(flag);
        self.node_banner.set_tooltip_text(Some(&glib_escape(name)));
    }

    pub fn update_speeds(&self, down: u64, up: u64, total_down: u64, total_up: u64) {
        self.speed_down_label.set_text(&format_speed(down));
        self.speed_up_label.set_text(&format_speed(up));
        self.total_down_label
            .set_text(&format!("\u{2B07} {}", format_bytes(total_down)));
        self.total_up_label
            .set_text(&format!("\u{2B06} {}", format_bytes(total_up)));
    }

    pub fn update_uptime(&self, elapsed_seconds: u64) {
        self.uptime_label
            .set_text(&format_duration(elapsed_seconds));
    }

    pub fn update_ip_info(&self, ip: &str, location: &str) {
        self.ip_row.set_subtitle(&glib_escape(ip));
        self.ip_label.set_text(location);
    }

    pub fn reset_metrics(&self) {
        self.update_speeds(0, 0, 0, 0);
        self.update_uptime(0);
        self.update_ip_info("Not connected", "Direct");
    }

    pub fn on_select_node_click<F: Fn() + 'static>(&self, callback: F) {
        let gesture = gtk4::GestureClick::new();
        gesture.set_button(gtk4::gdk::BUTTON_PRIMARY);
        let banner = self.node_banner.clone();
        gesture.connect_released(move |gesture, n_press, x, y| {
            if n_press < 1 {
                return;
            }
            let width = banner.width() as f64;
            let height = banner.height() as f64;
            if x < 0.0 || y < 0.0 || x > width || y > height {
                return;
            }
            gesture.set_state(gtk4::EventSequenceState::Claimed);
            callback();
        });
        self.node_banner.add_controller(gesture);
    }
}

fn build_metric_card(title: &str) -> (Box, Label) {
    let card = Box::builder()
        .orientation(Orientation::Vertical)
        .spacing(4)
        .css_classes(vec!["card".to_string()])
        .build();

    let title_label = Label::builder()
        .label(title)
        .css_classes(vec!["caption".to_string(), "dim-label".to_string()])
        .margin_top(10)
        .build();

    let value_label = Label::builder()
        .label("0 B/s")
        .css_classes(vec!["title-4".to_string(), "numeric".to_string()])
        .ellipsize(gtk4::pango::EllipsizeMode::End)
        .margin_bottom(10)
        .build();

    card.append(&title_label);
    card.append(&value_label);
    (card, value_label)
}
