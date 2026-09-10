use gio::prelude::*;
use gtk4::glib;
use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;
use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use crate::app::{AppContext, AppEvent};
use crate::ui::connections::ConnectionsPage;
use crate::ui::dashboard::{ConnectionStatus, DashboardPage};
use crate::ui::profiles::ProfilesPage;
use crate::ui::proxies::ProxiesPage;
use crate::ui::routing::RoutingPage;
use crate::core::runner::CoreState;
use crate::ui::settings::SettingsPage;

const STATS_INTERVAL: Duration = Duration::from_millis(1000);
const IP_REFRESH_TICKS: u32 = 300;
const AUTO_UPDATE_INTERVAL: Duration = Duration::from_secs(300);

pub struct MainWindow {
    window: adw::ApplicationWindow,
    connection_indicator: gtk4::Image,
    dashboard: Rc<DashboardPage>,
    proxies: Rc<ProxiesPage>,
    profiles: Rc<ProfilesPage>,
    routing: Rc<RoutingPage>,
    connections: Rc<ConnectionsPage>,
    settings: Rc<SettingsPage>,
}

impl MainWindow {
    pub fn new(app: &adw::Application, app_ctx: AppContext) -> Rc<Self> {
        let window = adw::ApplicationWindow::builder()
            .application(app)
            .title("RustyBird")
            .default_width(420)
            .default_height(760)
            .width_request(360)
            .height_request(480)
            .build();

        let dashboard = DashboardPage::new(app_ctx.clone());
        let proxies = ProxiesPage::new(app_ctx.clone());
        let profiles = ProfilesPage::new(app_ctx.clone());
        let routing = RoutingPage::new(app_ctx.clone());
        let connections = ConnectionsPage::new(app_ctx.clone());
        let settings = SettingsPage::new(app_ctx.clone());

        let view_stack = adw::ViewStack::new();
        view_stack.add_titled_with_icon(
            &dashboard.container,
            Some("dashboard"),
            "Home",
            "network-vpn-symbolic",
        );
        view_stack.add_titled_with_icon(
            &proxies.container,
            Some("proxies"),
            "Proxies",
            "network-server-symbolic",
        );
        view_stack.add_titled_with_icon(
            &profiles.container,
            Some("profiles"),
            "Profiles",
            "folder-download-symbolic",
        );
        view_stack.add_titled_with_icon(
            &routing.container,
            Some("routing"),
            "Routing",
            "preferences-system-network-symbolic",
        );
        view_stack.add_titled_with_icon(
            &connections.container,
            Some("activity"),
            "Activity",
            "utilities-system-monitor-symbolic",
        );
        view_stack.add_titled_with_icon(
            &settings.container,
            Some("settings"),
            "Settings",
            "emblem-system-symbolic",
        );

        let header_bar = adw::HeaderBar::new();

        let connection_indicator = gtk4::Image::builder()
            .icon_name("network-offline-symbolic")
            .tooltip_text("Disconnected")
            .css_classes(vec!["dim-label".to_string()])
            .build();
        header_bar.pack_end(&connection_indicator);
        let header_switcher = adw::ViewSwitcher::builder()
            .stack(&view_stack)
            .policy(adw::ViewSwitcherPolicy::Wide)
            .build();
        header_bar.set_title_widget(Some(&header_switcher));

        let bottom_switcher = adw::ViewSwitcherBar::builder()
            .stack(&view_stack)
            .reveal(false)
            .build();

        let toolbar_view = adw::ToolbarView::new();
        toolbar_view.add_top_bar(&header_bar);
        toolbar_view.set_content(Some(&view_stack));
        toolbar_view.add_bottom_bar(&bottom_switcher);

        let toast_overlay = adw::ToastOverlay::new();
        toast_overlay.set_child(Some(&toolbar_view));
        window.set_content(Some(&toast_overlay));

        let breakpoint = adw::Breakpoint::new(adw::BreakpointCondition::new_length(
            adw::BreakpointConditionLengthType::MaxWidth,
            540.0,
            adw::LengthUnit::Sp,
        ));
        breakpoint.add_setter(&bottom_switcher, "reveal", Some(&true.to_value()));
        breakpoint.add_setter(&header_switcher, "visible", Some(&false.to_value()));
        window.add_breakpoint(breakpoint);

        view_stack.set_visible_child_name("dashboard");

        let stack_for_banner = view_stack.clone();
        dashboard.on_select_node_click(move || {
            stack_for_banner.set_visible_child_name("proxies");
        });

        let main_window = Rc::new(Self {
            window,
            connection_indicator,
            dashboard,
            proxies,
            profiles,
            routing,
            connections,
            settings,
        });

        main_window.install_shortcuts(app, &view_stack);
        main_window.load_initial_state(&app_ctx);
        main_window.listen_for_events(app_ctx.clone());
        main_window.start_stats_loop(app_ctx.clone());
        main_window.start_auto_update_loop(app_ctx.clone());
        main_window.handle_close(app_ctx);

        main_window
    }

    fn load_initial_state(self: &Rc<Self>, app_ctx: &AppContext) {
        self.proxies.reload(app_ctx);
        self.profiles.reload(app_ctx);
        self.routing.reload(app_ctx);

        let window = self.clone();
        let ctx = app_ctx.clone();
        glib::spawn_future_local(async move {
            window.refresh_active_node(&ctx).await;
            if ctx.settings.read().await.connect_on_start {
                window
                    .dashboard
                    .set_status(ConnectionStatus::Connecting, None);
                match ctx.connect().await {
                    Ok(()) => window
                        .dashboard
                        .set_status(ConnectionStatus::Connected, None),
                    Err(error) => window
                        .dashboard
                        .set_status(ConnectionStatus::Failed, Some(&error)),
                }
            }
        });
    }

    fn listen_for_events(self: &Rc<Self>, app_ctx: AppContext) {
        let window = self.clone();
        let mut receiver = app_ctx.subscribe_events();

        glib::spawn_future_local(async move {
            loop {
                match receiver.recv().await {
                    Ok(AppEvent::ProfilesChanged) => {
                        window.proxies.reload(&app_ctx);
                        window.profiles.reload(&app_ctx);
                        window.routing.reload(&app_ctx);
                        window.refresh_active_node(&app_ctx).await;
                    }
                    Ok(AppEvent::SettingsChanged) => {
                        let settings = app_ctx.settings.read().await.clone();
                        window.dashboard.sync_from_settings(&settings);
                        window.routing.sync_from_settings(&settings);
                        window.settings.sync_from_settings(&settings);
                        window.proxies.sync_from_settings(&settings);
                        window.connections.sync_from_settings(&settings);
                    }
                    Ok(AppEvent::ConnectionStateChanged) => {
                        let connected = app_ctx.runner.is_running();
                        window.set_connection_indicator(connected);
                        window.proxies.set_connected(connected);
                        if !connected {
                            window.connections.clear();
                        }
                        let settings = app_ctx.settings.read().await.clone();
                        window.dashboard.sync_from_settings(&settings);
                        window.routing.sync_from_settings(&settings);
                        window.settings.sync_from_settings(&settings);
                        window.proxies.sync_from_settings(&settings);
                        window.proxies.reload(&app_ctx);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    async fn refresh_active_node(&self, app_ctx: &AppContext) {
        if let Some(name) = app_ctx.active_profile_name().await {
            self.dashboard.update_active_node(&name, "\u{1F4C4}");
            self.dashboard.set_profile_mode(true);
            return;
        }
        self.dashboard.set_profile_mode(false);
        let profiles = app_ctx.profiles.read().await;
        match profiles.get_active_node() {
            Some(node) => self
                .dashboard
                .update_active_node(&node.name, node.flag_emoji()),
            None => self
                .dashboard
                .update_active_node("No proxy selected", "\u{1F310}"),
        }
    }

    fn start_auto_update_loop(self: &Rc<Self>, app_ctx: AppContext) {
        glib::spawn_future_local(async move {
            loop {
                let updated = app_ctx.update_due_subscriptions().await
                    + app_ctx.update_due_profiles().await;
                if updated > 0 {
                    tracing::info!("automatically updated {} remote sources", updated);
                }
                glib::timeout_future(AUTO_UPDATE_INTERVAL).await;
            }
        });
    }

    fn start_stats_loop(self: &Rc<Self>, app_ctx: AppContext) {
        let window = self.clone();
        let uptime = Rc::new(Cell::new(0u64));
        let last_down = Rc::new(Cell::new(0u64));
        let last_up = Rc::new(Cell::new(0u64));
        let tick = Rc::new(Cell::new(0u32));
        let was_running = Rc::new(Cell::new(false));

        glib::spawn_future_local(async move {
            loop {
                glib::timeout_future(STATS_INTERVAL).await;

                let running = app_ctx.runner.is_running();
                if !running {
                    if was_running.replace(false) {
                        uptime.set(0);
                        last_down.set(0);
                        last_up.set(0);
                        tick.set(0);
                        window.dashboard.reset_metrics();
                        match app_ctx.runner.state().await {
                            CoreState::Error(detail) => window
                                .dashboard
                                .set_status(ConnectionStatus::Failed, Some(&detail)),
                            _ => window
                                .dashboard
                                .set_status(ConnectionStatus::Disconnected, None),
                        }
                        window.connections.clear();
                    }
                    continue;
                }

                if !was_running.replace(true) {
                    window
                        .dashboard
                        .set_status(ConnectionStatus::Connected, None);
                    window.dashboard.sync_mode_from_core(&app_ctx).await;
                }

                uptime.set(uptime.get() + 1);
                window.dashboard.update_uptime(uptime.get());

                let client = app_ctx.clash_client().await;
                if let Ok(snapshot) = client.get_connections().await {
                    let previous_down = last_down.replace(snapshot.download_total);
                    let previous_up = last_up.replace(snapshot.upload_total);

                    let down_speed = if previous_down == 0 {
                        0
                    } else {
                        snapshot.download_total.saturating_sub(previous_down)
                    };
                    let up_speed = if previous_up == 0 {
                        0
                    } else {
                        snapshot.upload_total.saturating_sub(previous_up)
                    };

                    window.dashboard.update_speeds(
                        down_speed,
                        up_speed,
                        snapshot.download_total,
                        snapshot.upload_total,
                    );
                    window
                        .connections
                        .update_connections(snapshot.connections);
                }

                window
                    .connections
                    .update_memory(app_ctx.runner.memory_bytes().await);

                let current_tick = tick.get();
                if current_tick == 0 || current_tick >= IP_REFRESH_TICKS {
                    tick.set(1);
                    let dashboard = window.dashboard.clone();
                    let mixed_port = app_ctx.settings.read().await.mixed_port;
                    glib::spawn_future_local(async move {
                        match crate::core::stats::check_outbound_ip(Some(mixed_port)).await {
                            Ok(info) => {
                                let ip = if info.ip.is_empty() {
                                    "Unknown".to_string()
                                } else {
                                    info.ip.clone()
                                };
                                dashboard.update_ip_info(&ip, &info.location());
                            }
                            Err(error) => {
                                tracing::debug!("outbound ip lookup failed: {}", error);
                                dashboard
                                    .update_ip_info("Unavailable", "Lookup service unreachable")
                            }
                        }
                    });
                } else {
                    tick.set(current_tick + 1);
                }
            }
        });
    }

    fn handle_close(self: &Rc<Self>, app_ctx: AppContext) {
        self.window.connect_close_request(move |window| {
            let ctx = app_ctx.clone();
            let window = window.clone();
            glib::spawn_future_local(async move {
                if ctx.settings.read().await.keep_running_in_background {
                    window.set_visible(false);
                    return;
                }
                if let Err(error) = ctx.disconnect().await {
                    tracing::error!("failed to stop the core on exit: {}", error);
                }
                window.destroy();
            });
            glib::Propagation::Stop
        });
    }

    fn set_connection_indicator(&self, connected: bool) {
        if connected {
            self.connection_indicator
                .set_icon_name(Some("network-vpn-symbolic"));
            self.connection_indicator.set_tooltip_text(Some("Connected"));
            self.connection_indicator.remove_css_class("dim-label");
            self.connection_indicator.add_css_class("success");
        } else {
            self.connection_indicator
                .set_icon_name(Some("network-offline-symbolic"));
            self.connection_indicator
                .set_tooltip_text(Some("Disconnected"));
            self.connection_indicator.remove_css_class("success");
            self.connection_indicator.add_css_class("dim-label");
        }
    }

    fn install_shortcuts(self: &Rc<Self>, app: &adw::Application, view_stack: &adw::ViewStack) {
        let window = self.window.clone();
        let quit = gio::SimpleAction::new("quit", None);
        quit.connect_activate(move |_, _| {
            window.close();
        });
        app.add_action(&quit);
        app.set_accels_for_action("app.quit", &["<Primary>q", "<Primary>w"]);

        for (index, name) in [
            "dashboard",
            "proxies",
            "profiles",
            "routing",
            "activity",
            "settings",
        ]
        .iter()
        .enumerate()
        {
            let action = gio::SimpleAction::new(&format!("page-{}", index + 1), None);
            let stack = view_stack.clone();
            let name = name.to_string();
            action.connect_activate(move |_, _| {
                stack.set_visible_child_name(&name);
            });
            app.add_action(&action);
            app.set_accels_for_action(
                &format!("app.page-{}", index + 1),
                &[&format!("<Primary>{}", index + 1)],
            );
        }
    }

    pub fn present(&self) {
        self.window.present();
    }

    pub fn present_unless_hidden(&self, hidden: bool) {
        if hidden {
            return;
        }
        self.window.present();
    }
}
