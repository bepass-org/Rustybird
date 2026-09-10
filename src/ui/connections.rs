use gtk4::glib;
use gtk4::prelude::*;
use gtk4::{Box, Button, Label, Orientation, ScrolledWindow, TextView};
use libadwaita as adw;
use libadwaita::prelude::*;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use crate::app::AppContext;
use crate::config::settings::{AppSettings, ConnectionSort};
use crate::core::stats::ConnectionInfo;
use crate::ui::widgets::node_row::glib_escape;
use crate::ui::widgets::speed_badge::format_bytes;

const MAX_LOG_LINES: i32 = 2000;
const MAX_VISIBLE_CONNECTIONS: usize = 100;
const MAX_CLOSED_HISTORY: usize = 200;

#[derive(Clone)]
struct ClosedConnection {
    id: String,
    host: String,
    network: String,
    chain: String,
    download: u64,
    upload: u64,
    closed_at: chrono::DateTime<chrono::Utc>,
}

pub struct ConnectionsPage {
    pub container: ScrolledWindow,
    connections_group: adw::PreferencesGroup,
    connections_box: Box,
    sort_row: adw::ComboRow,
    closed_row: adw::SwitchRow,
    memory_label: Label,
    memory_row: adw::ActionRow,
    app_ctx: AppContext,
    log_view: TextView,
    log_scroll: ScrolledWindow,
    autoscroll: Rc<RefCell<bool>>,
    rendered_ids: RefCell<Vec<String>>,
    active_snapshot: RefCell<HashMap<String, ConnectionInfo>>,
    closed_history: RefCell<Vec<ClosedConnection>>,
    sort: Cell<ConnectionSort>,
    show_closed: Cell<bool>,
    suppress_signals: Rc<Cell<bool>>,
}

impl ConnectionsPage {
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
            .maximum_size(650)
            .tightening_threshold(450)
            .child(&main_box)
            .build();

        let container = ScrolledWindow::builder()
            .hscrollbar_policy(gtk4::PolicyType::Never)
            .child(&clamp)
            .build();

        let runtime_group = adw::PreferencesGroup::builder().title("Core runtime").build();
        let memory_row = adw::ActionRow::builder()
            .title("Memory in use")
            .subtitle("Reported by the sing-box Clash API")
            .build();
        let memory_label = Label::builder()
            .label("\u{2014}")
            .css_classes(vec!["numeric".to_string(), "dim-label".to_string()])
            .build();
        memory_row.add_suffix(&memory_label);
        runtime_group.add(&memory_row);
        main_box.append(&runtime_group);

        let view_group = adw::PreferencesGroup::builder().title("View").build();
        let sort_row = adw::ComboRow::builder()
            .title("Sort connections by")
            .model(&gtk4::StringList::new(
                &ConnectionSort::ALL.map(|s| s.label()),
            ))
            .build();
        let closed_row = adw::SwitchRow::builder()
            .title("Show recently closed")
            .subtitle("Keeps the last 200 finished flows of this session")
            .build();
        view_group.add(&sort_row);
        view_group.add(&closed_row);
        main_box.append(&view_group);

        let connections_group = adw::PreferencesGroup::builder()
            .title("Active connections")
            .description("Live flows reported by the sing-box Clash API")
            .build();

        let close_all_button = Button::builder()
            .label("Close all")
            .css_classes(vec!["flat".to_string()])
            .valign(gtk4::Align::Center)
            .build();
        connections_group.set_header_suffix(Some(&close_all_button));

        let connections_box = Box::builder()
            .orientation(Orientation::Vertical)
            .spacing(0)
            .build();
        connections_group.add(&connections_box);
        main_box.append(&connections_group);

        let logs_group = adw::PreferencesGroup::builder()
            .title("Core log")
            .description("Output from the sing-box process")
            .build();

        let log_view = TextView::builder()
            .editable(false)
            .cursor_visible(false)
            .wrap_mode(gtk4::WrapMode::WordChar)
            .monospace(true)
            .margin_top(8)
            .margin_bottom(8)
            .margin_start(8)
            .margin_end(8)
            .build();

        let log_scroll = ScrolledWindow::builder()
            .height_request(240)
            .css_classes(vec!["card".to_string()])
            .child(&log_view)
            .build();
        logs_group.add(&log_scroll);

        let log_actions = Box::builder()
            .orientation(Orientation::Horizontal)
            .spacing(8)
            .halign(gtk4::Align::End)
            .margin_top(6)
            .build();

        let autoscroll_button = gtk4::ToggleButton::builder()
            .label("Follow")
            .active(true)
            .css_classes(vec!["flat".to_string()])
            .build();
        let copy_button = Button::builder()
            .label("Copy")
            .css_classes(vec!["flat".to_string()])
            .build();
        let clear_button = Button::builder()
            .label("Clear")
            .css_classes(vec!["flat".to_string()])
            .build();

        log_actions.append(&autoscroll_button);
        log_actions.append(&copy_button);
        log_actions.append(&clear_button);
        logs_group.add(&log_actions);
        main_box.append(&logs_group);

        let page = Rc::new(Self {
            container,
            connections_group,
            connections_box,
            sort_row,
            closed_row,
            memory_label,
            memory_row,
            app_ctx: app_ctx.clone(),
            log_view,
            log_scroll,
            autoscroll: Rc::new(RefCell::new(true)),
            rendered_ids: RefCell::new(Vec::new()),
            active_snapshot: RefCell::new(HashMap::new()),
            closed_history: RefCell::new(Vec::new()),
            sort: Cell::new(ConnectionSort::default()),
            show_closed: Cell::new(false),
            suppress_signals: Rc::new(Cell::new(false)),
        });

        let buffer = page.log_view.buffer();
        clear_button.connect_clicked(move |_| buffer.set_text(""));

        let buffer = page.log_view.buffer();
        copy_button.connect_clicked(move |button| {
            let text = buffer
                .text(&buffer.start_iter(), &buffer.end_iter(), false)
                .to_string();
            if let Some(display) = gtk4::gdk::Display::default() {
                display.clipboard().set_text(&text);
            }
            button.set_label("Copied");
            let button = button.clone();
            glib::timeout_add_local_once(std::time::Duration::from_secs(2), move || {
                button.set_label("Copy");
            });
        });

        let autoscroll = page.autoscroll.clone();
        autoscroll_button.connect_toggled(move |button| {
            *autoscroll.borrow_mut() = button.is_active();
        });

        let ctx = app_ctx.clone();
        close_all_button.connect_clicked(move |_| {
            let ctx = ctx.clone();
            glib::spawn_future_local(async move {
                if let Err(error) = ctx.clash_client().await.close_all_connections().await {
                    tracing::error!("failed to close connections: {}", error);
                }
            });
        });

        let page_for_sort = page.clone();
        let ctx_for_sort = app_ctx.clone();
        page.sort_row.connect_selected_notify(move |row| {
            if page_for_sort.suppress_signals.get() {
                return;
            }
            let sort = ConnectionSort::from_index(row.selected());
            page_for_sort.sort.set(sort);
            page_for_sort.rerender();
            let ctx = ctx_for_sort.clone();
            glib::spawn_future_local(async move {
                let mut settings = ctx.settings.write().await;
                settings.connection_sort = sort;
                settings.save();
            });
        });

        let page_for_closed = page.clone();
        let ctx_for_closed = app_ctx.clone();
        page.closed_row.connect_active_notify(move |row| {
            if page_for_closed.suppress_signals.get() {
                return;
            }
            let enabled = row.is_active();
            page_for_closed.show_closed.set(enabled);
            page_for_closed.rerender();
            let ctx = ctx_for_closed.clone();
            glib::spawn_future_local(async move {
                let mut settings = ctx.settings.write().await;
                settings.show_closed_connections = enabled;
                settings.save();
            });
        });

        page.start_log_stream(app_ctx);
        page.show_placeholder("Not connected", "Connect to see live traffic.");
        page
    }

    pub fn sync_from_settings(&self, settings: &AppSettings) {
        self.suppress_signals.set(true);
        self.sort.set(settings.connection_sort);
        self.show_closed.set(settings.show_closed_connections);
        self.sort_row.set_selected(settings.connection_sort.index());
        self.closed_row
            .set_active(settings.show_closed_connections);
        self.suppress_signals.set(false);
    }

    pub fn update_memory(&self, bytes: Option<u64>) {
        match bytes {
            Some(bytes) => {
                self.memory_label.set_text(&format_bytes(bytes));
                self.memory_row
                    .set_subtitle("Resident size of the sing-box process");
            }
            None => {
                self.memory_label.set_text("\u{2014}");
                self.memory_row.set_subtitle("The core is not running");
            }
        }
    }

    fn start_log_stream(self: &Rc<Self>, app_ctx: AppContext) {
        let mut receiver = app_ctx.runner.subscribe_logs();
        let page = self.clone();

        glib::spawn_future_local(async move {
            loop {
                match receiver.recv().await {
                    Ok(line) => page.append_log(&line),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        page.append_log(&format!("... {} log lines dropped ...", skipped));
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    fn append_log(&self, line: &str) {
        let buffer = self.log_view.buffer();
        let mut end = buffer.end_iter();
        buffer.insert(&mut end, line);
        buffer.insert(&mut end, "\n");

        let line_count = buffer.line_count();
        if line_count > MAX_LOG_LINES {
            let mut start = buffer.start_iter();
            if let Some(mut cutoff) = buffer.iter_at_line(line_count - MAX_LOG_LINES) {
                buffer.delete(&mut start, &mut cutoff);
            }
        }

        if *self.autoscroll.borrow() {
            let adjustment = self.log_scroll.vadjustment();
            glib::idle_add_local_once(move || {
                adjustment.set_value(adjustment.upper() - adjustment.page_size());
            });
        }
    }

    fn show_placeholder(&self, title: &str, subtitle: &str) {
        while let Some(child) = self.connections_box.first_child() {
            self.connections_box.remove(&child);
        }
        self.rendered_ids.borrow_mut().clear();
        self.connections_box.append(
            &adw::ActionRow::builder()
                .title(title)
                .subtitle(subtitle)
                .build(),
        );
    }

    pub fn clear(&self) {
        self.connections_group
            .set_description(Some("Live flows reported by the sing-box Clash API"));
        self.active_snapshot.borrow_mut().clear();
        self.closed_history.borrow_mut().clear();
        self.show_placeholder("Not connected", "Connect to see live traffic.");
        self.update_memory(None);
    }

    pub fn update_connections(&self, connections: Vec<ConnectionInfo>) {
        let mut next: HashMap<String, ConnectionInfo> = HashMap::new();
        for connection in connections {
            next.insert(connection.id.clone(), connection);
        }

        {
            let previous = self.active_snapshot.borrow();
            let mut history = self.closed_history.borrow_mut();
            for (id, connection) in previous.iter() {
                if next.contains_key(id) {
                    continue;
                }
                history.push(ClosedConnection {
                    id: id.clone(),
                    host: connection.metadata.display_host(),
                    network: connection.metadata.network.to_uppercase(),
                    chain: connection
                        .chains
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "direct".to_string()),
                    download: connection.download,
                    upload: connection.upload,
                    closed_at: chrono::Utc::now(),
                });
            }
            let overflow = history.len().saturating_sub(MAX_CLOSED_HISTORY);
            if overflow > 0 {
                history.drain(0..overflow);
            }
        }

        *self.active_snapshot.borrow_mut() = next;
        self.render();
    }

    fn rerender(&self) {
        self.render();
    }

    fn render(&self) {
        let app_ctx = &self.app_ctx;
        let mut visible: Vec<ConnectionInfo> =
            self.active_snapshot.borrow().values().cloned().collect();
        let total = visible.len();
        self.connections_group.set_description(Some(&format!(
            "{} active {}",
            total,
            if total == 1 { "flow" } else { "flows" }
        )));

        let closed: Vec<ClosedConnection> = if self.show_closed.get() {
            let mut closed = self.closed_history.borrow().clone();
            closed.reverse();
            closed.truncate(MAX_VISIBLE_CONNECTIONS);
            closed
        } else {
            Vec::new()
        };

        if visible.is_empty() && closed.is_empty() {
            self.show_placeholder(
                "No active connections",
                "Traffic will appear here as soon as an app connects.",
            );
            return;
        }

        let sort = self.sort.get();
        visible.sort_by(|a, b| match sort {
            ConnectionSort::Traffic | ConnectionSort::TrafficTotal => (b.download + b.upload)
                .cmp(&(a.download + a.upload))
                .then_with(|| a.id.cmp(&b.id)),
            ConnectionSort::Date => b.start.cmp(&a.start).then_with(|| a.id.cmp(&b.id)),
            ConnectionSort::Host => a
                .metadata
                .display_host()
                .to_lowercase()
                .cmp(&b.metadata.display_host().to_lowercase())
                .then_with(|| a.id.cmp(&b.id)),
        });
        visible.truncate(MAX_VISIBLE_CONNECTIONS);

        *self.rendered_ids.borrow_mut() = visible.iter().map(|c| c.id.clone()).collect();

        while let Some(child) = self.connections_box.first_child() {
            self.connections_box.remove(&child);
        }

        for connection in visible {
            let chain = connection
                .chains
                .first()
                .cloned()
                .unwrap_or_else(|| "direct".to_string());

            let row = adw::ActionRow::builder()
                .title(glib_escape(&connection.metadata.display_host()))
                .subtitle(glib_escape(&format!(
                    "{} \u{2022} :{} \u{2192} :{} \u{2022} {}",
                    connection.metadata.network.to_uppercase(),
                    connection.metadata.source_port,
                    connection.metadata.destination_port,
                    chain
                )))
                .build();

            let traffic_label = Label::builder()
                .label(format!(
                    "\u{2B07} {}  \u{2B06} {}",
                    format_bytes(connection.download),
                    format_bytes(connection.upload)
                ))
                .css_classes(vec![
                    "caption".to_string(),
                    "numeric".to_string(),
                    "dim-label".to_string(),
                ])
                .valign(gtk4::Align::Center)
                .build();

            let close_button = Button::builder()
                .icon_name("window-close-symbolic")
                .has_frame(false)
                .tooltip_text("Close this connection")
                .valign(gtk4::Align::Center)
                .build();

            let connection_id = connection.id.clone();
            let ctx = app_ctx.clone();
            close_button.connect_clicked(move |_| {
                let connection_id = connection_id.clone();
                let ctx = ctx.clone();
                glib::spawn_future_local(async move {
                    if let Err(error) = ctx
                        .clash_client()
                        .await
                        .close_connection(&connection_id)
                        .await
                    {
                        tracing::error!("failed to close connection: {}", error);
                    }
                });
            });

            row.add_suffix(&traffic_label);
            row.add_suffix(&close_button);
            self.connections_box.append(&row);
        }

        for entry in closed {
            let row = adw::ActionRow::builder()
                .title(glib_escape(&entry.host))
                .subtitle(glib_escape(&format!(
                    "closed {} \u{2022} {} \u{2022} {}",
                    entry.closed_at.format("%H:%M:%S"),
                    entry.network,
                    entry.chain
                )))
                .css_classes(vec!["dim-label".to_string()])
                .build();
            let traffic_label = Label::builder()
                .label(format!(
                    "\u{2B07} {}  \u{2B06} {}",
                    format_bytes(entry.download),
                    format_bytes(entry.upload)
                ))
                .css_classes(vec![
                    "caption".to_string(),
                    "numeric".to_string(),
                    "dim-label".to_string(),
                ])
                .valign(gtk4::Align::Center)
                .build();
            row.add_suffix(&traffic_label);
            row.set_widget_name(&entry.id);
            self.connections_box.append(&row);
        }
    }
}
