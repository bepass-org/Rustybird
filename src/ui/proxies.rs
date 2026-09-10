use gtk4::glib;
use gtk4::prelude::*;
use gtk4::{Box, Button, Orientation, ScrolledWindow, SearchEntry};
use libadwaita as adw;
use libadwaita::prelude::*;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;

use crate::app::{AppContext, AppEvent};
use crate::config::settings::{AppSettings, GroupMode};
use crate::core::config_builder::PROXY_SELECTOR_TAG;
use crate::core::ping::ping_node_tcp;
use crate::parser::node::ProxyNode;
use crate::parser::share::node_share_link;
use crate::parser::uri::parse_proxy_uri;
use crate::ui::widgets::node_row::NodeRow;

pub struct ProxiesPage {
    pub container: ScrolledWindow,
    list_box: Box,
    search_entry: SearchEntry,
    test_all_button: Button,
    add_button: Button,
    group_mode_row: adw::ComboRow,
    rows: RefCell<HashMap<String, Rc<NodeRow>>>,
    suppress_signals: Rc<Cell<bool>>,
}

impl ProxiesPage {
    pub fn new(app_ctx: AppContext) -> Rc<Self> {
        let main_box = Box::builder()
            .orientation(Orientation::Vertical)
            .spacing(12)
            .margin_top(12)
            .margin_bottom(24)
            .margin_start(16)
            .margin_end(16)
            .build();

        let clamp = adw::Clamp::builder()
            .maximum_size(600)
            .tightening_threshold(400)
            .child(&main_box)
            .build();

        let container = ScrolledWindow::builder()
            .hscrollbar_policy(gtk4::PolicyType::Never)
            .child(&clamp)
            .build();

        let header_box = Box::builder()
            .orientation(Orientation::Horizontal)
            .spacing(8)
            .build();

        let search_entry = SearchEntry::builder()
            .hexpand(true)
            .placeholder_text("Search proxies")
            .build();

        let test_all_button = Button::builder()
            .label("Test all")
            .css_classes(vec!["flat".to_string()])
            .tooltip_text("Measure latency for every node")
            .build();

        let add_button = Button::builder()
            .icon_name("list-add-symbolic")
            .tooltip_text("Add proxy links")
            .css_classes(vec!["suggested-action".to_string()])
            .build();

        header_box.append(&search_entry);
        header_box.append(&test_all_button);
        header_box.append(&add_button);
        main_box.append(&header_box);

        let selection_group = adw::PreferencesGroup::new();
        let group_mode_row = adw::ComboRow::builder()
            .title("Selection")
            .subtitle("URLTest lets the core pick the fastest node on its own")
            .model(&gtk4::StringList::new(&[
                GroupMode::Manual.label(),
                GroupMode::UrlTest.label(),
            ]))
            .build();
        selection_group.add(&group_mode_row);
        main_box.append(&selection_group);

        let list_box = Box::builder()
            .orientation(Orientation::Vertical)
            .spacing(16)
            .build();
        main_box.append(&list_box);

        let page = Rc::new(Self {
            container,
            list_box,
            search_entry,
            test_all_button,
            add_button,
            group_mode_row,
            rows: RefCell::new(HashMap::new()),
            suppress_signals: Rc::new(Cell::new(false)),
        });

        page.connect_signals(app_ctx);
        page
    }

    fn connect_signals(self: &Rc<Self>, app_ctx: AppContext) {
        let page = self.clone();
        self.search_entry.connect_search_changed(move |entry| {
            let query = entry.text().to_lowercase();
            for row in page.rows.borrow().values() {
                row.row.set_visible(row.matches(&query));
            }
        });

        let page = self.clone();
        let ctx = app_ctx.clone();
        self.test_all_button.connect_clicked(move |button| {
            let page = page.clone();
            let ctx = ctx.clone();
            let button = button.clone();
            button.set_sensitive(false);

            glib::spawn_future_local(async move {
                if ctx.runner.is_running() {
                    if let Err(error) = ctx.test_group(PROXY_SELECTOR_TAG).await {
                        tracing::debug!("group latency test unavailable: {}", error);
                    }
                }
                let nodes = ctx.profiles.read().await.nodes.clone();
                for node in nodes {
                    measure_latency(&ctx, &page, &node).await;
                }
                persist_latencies(&ctx).await;
                button.set_sensitive(true);
            });
        });

        let page = self.clone();
        let ctx = app_ctx.clone();
        self.group_mode_row.connect_selected_notify(move |row| {
            if page.suppress_signals.get() {
                return;
            }
            let mode = GroupMode::from_index(row.selected());
            let ctx = ctx.clone();
            glib::spawn_future_local(async move {
                {
                    let mut settings = ctx.settings.write().await;
                    if settings.group_mode == mode {
                        return;
                    }
                    settings.group_mode = mode;
                    settings.save();
                }
                ctx.notify(AppEvent::SettingsChanged);
                if let Err(error) = ctx.reload().await {
                    tracing::error!("reload after a selection change failed: {}", error);
                }
            });
        });

        let page = self.clone();
        let ctx = app_ctx;
        self.add_button.connect_clicked(move |button| {
            let root = button
                .root()
                .and_then(|root| root.downcast::<gtk4::Window>().ok());
            show_add_node_dialog(root.as_ref(), ctx.clone(), page.clone());
        });
    }

    pub fn sync_from_settings(&self, settings: &AppSettings) {
        self.suppress_signals.set(true);
        self.group_mode_row
            .set_selected(settings.group_mode.index());
        self.suppress_signals.set(false);
    }

    pub fn reload(self: &Rc<Self>, app_ctx: &AppContext) {
        let page = self.clone();
        let ctx = app_ctx.clone();

        glib::spawn_future_local(async move {
            let profiles = ctx.profiles.read().await.clone();
            let settings = ctx.settings.read().await.clone();
            let connected = ctx.runner.is_running();
            page.sync_from_settings(&settings);

            clear(&page.list_box);
            page.rows.borrow_mut().clear();

            let uses_profile = settings
                .active_profile_id
                .as_deref()
                .is_some_and(|id| profiles.config_profile(id).is_some());

            if uses_profile {
                page.group_mode_row.set_sensitive(false);
                page.group_mode_row
                    .set_subtitle("The active profile defines its own outbound groups");
                render_remote_groups(&page, &ctx, connected).await;
                return;
            }

            page.group_mode_row.set_sensitive(true);
            page.group_mode_row
                .set_subtitle("URLTest lets the core pick the fastest node on its own");

            if profiles.nodes.is_empty() {
                page.list_box.append(
                    &adw::StatusPage::builder()
                        .icon_name("network-wired-symbolic")
                        .title("No proxies yet")
                        .description("Add a proxy link or import a subscription to get started.")
                        .build(),
                );
                return;
            }

            let mut groups: BTreeMap<String, Vec<ProxyNode>> = BTreeMap::new();
            for node in &profiles.nodes {
                let group = profiles.subscription_name(node.subscription_id.as_deref());
                groups.entry(group).or_default().push(node.clone());
            }

            let active_id = profiles.active_node_id.clone();
            let query = page.search_entry.text().to_lowercase();

            for (group_title, nodes) in groups {
                let group = adw::PreferencesGroup::builder().title(&group_title).build();

                for node in nodes {
                    let is_active = active_id.as_deref() == Some(node.id.as_str());
                    let row = Rc::new(NodeRow::new(&node, is_active));
                    row.ping_badge.set_enabled(connected);
                    row.row.set_visible(row.matches(&query));

                    let node_id = node.id.clone();
                    let ctx_for_select = ctx.clone();
                    let page_for_select = page.clone();
                    row.row.connect_activated(move |_| {
                        let node_id = node_id.clone();
                        let ctx = ctx_for_select.clone();
                        let page = page_for_select.clone();
                        glib::spawn_future_local(async move {
                            for (id, row) in page.rows.borrow().iter() {
                                row.set_active(id == &node_id);
                            }
                            if let Err(error) = ctx.select_node(&node_id).await {
                                tracing::error!("failed to select node: {}", error);
                            }
                        });
                    });

                    let node_id = node.id.clone();
                    let ctx_for_remove = ctx.clone();
                    row.remove_button.connect_clicked(move |_| {
                        let node_id = node_id.clone();
                        let ctx = ctx_for_remove.clone();
                        glib::spawn_future_local(async move {
                            {
                                let mut profiles = ctx.profiles.write().await;
                                profiles.remove_node(&node_id);
                                profiles.save();
                            }
                            ctx.notify(AppEvent::ProfilesChanged);
                            if let Err(error) = ctx.reload().await {
                                tracing::error!("reload after removal failed: {}", error);
                            }
                        });
                    });

                    let node_for_edit = node.clone();
                    let ctx_for_edit = ctx.clone();
                    row.edit_button.connect_clicked(move |button| {
                        let root = button
                            .root()
                            .and_then(|root| root.downcast::<gtk4::Window>().ok());
                        crate::ui::node_editor::show_node_editor(
                            root.as_ref(),
                            ctx_for_edit.clone(),
                            node_for_edit.clone(),
                        );
                    });

                    let node_for_share = node.clone();
                    row.share_button.connect_clicked(move |button| {
                        match node_share_link(&node_for_share) {
                            Some(link) => {
                                if let Some(display) = gtk4::gdk::Display::default() {
                                    display.clipboard().set_text(&link);
                                }
                                button.set_icon_name("object-select-symbolic");
                                let button = button.clone();
                                glib::timeout_add_local_once(
                                    std::time::Duration::from_secs(2),
                                    move || {
                                        button.set_icon_name("edit-copy-symbolic");
                                    },
                                );
                            }
                            None => button.set_sensitive(false),
                        }
                    });

                    let node_for_ping = node.clone();
                    let ctx_for_ping = ctx.clone();
                    let page_for_ping = page.clone();
                    row.ping_badge.on_click(move || {
                        let node = node_for_ping.clone();
                        let ctx = ctx_for_ping.clone();
                        let page = page_for_ping.clone();
                        glib::spawn_future_local(async move {
                            measure_latency(&ctx, &page, &node).await;
                            persist_latencies(&ctx).await;
                        });
                    });

                    group.add(&row.row);
                    page.rows.borrow_mut().insert(node.id.clone(), row);
                }

                page.list_box.append(&group);
            }
        });
    }

    pub fn set_connected(&self, connected: bool) {
        for row in self.rows.borrow().values() {
            row.ping_badge.set_enabled(connected);
        }
    }
}

fn clear(container: &Box) {
    while let Some(child) = container.first_child() {
        container.remove(&child);
    }
}

async fn render_remote_groups(page: &Rc<ProxiesPage>, ctx: &AppContext, connected: bool) {
    if !connected {
        page.list_box.append(
            &adw::StatusPage::builder()
                .icon_name("document-properties-symbolic")
                .title("Profile is active")
                .description("Connect to list the outbound groups this profile declares.")
                .build(),
        );
        return;
    }

    let proxies = match ctx.clash_client().await.get_proxies().await {
        Ok(response) => response.proxies,
        Err(error) => {
            page.list_box.append(
                &adw::StatusPage::builder()
                    .icon_name("dialog-warning-symbolic")
                    .title("Could not read the outbound list")
                    .description(error.to_string())
                    .build(),
            );
            return;
        }
    };

    let mut group_names: Vec<&String> = proxies
        .iter()
        .filter(|(_, entry)| entry.is_group() && !entry.all.is_empty())
        .map(|(name, _)| name)
        .collect();
    group_names.sort();

    if group_names.is_empty() {
        page.list_box.append(
            &adw::StatusPage::builder()
                .icon_name("network-wired-symbolic")
                .title("No outbound groups")
                .description("This profile routes traffic without a selector group.")
                .build(),
        );
        return;
    }

    for name in group_names {
        let entry = &proxies[name];
        let group = adw::PreferencesGroup::builder()
            .title(glib::markup_escape_text(name).to_string())
            .description(format!("{} \u{2022} {} members", entry.kind, entry.all.len()))
            .build();

        let test_button = Button::builder()
            .label("Test")
            .css_classes(vec!["flat".to_string()])
            .valign(gtk4::Align::Center)
            .build();
        let ctx_for_test = ctx.clone();
        let group_name = name.clone();
        let page_for_test = page.clone();
        test_button.connect_clicked(move |button| {
            let ctx = ctx_for_test.clone();
            let group_name = group_name.clone();
            let page = page_for_test.clone();
            let button = button.clone();
            button.set_sensitive(false);
            glib::spawn_future_local(async move {
                if let Err(error) = ctx.test_group(&group_name).await {
                    tracing::error!("group latency test failed: {}", error);
                }
                button.set_sensitive(true);
                page.reload(&ctx);
            });
        });
        group.set_header_suffix(Some(&test_button));

        for member in &entry.all {
            let latency = proxies
                .get(member)
                .and_then(|member_entry| member_entry.latency_ms());
            let kind = proxies
                .get(member)
                .map(|member_entry| member_entry.kind.clone())
                .unwrap_or_default();

            let udp = proxies
                .get(member)
                .map(|member_entry| member_entry.udp)
                .unwrap_or(false);
            let mut parts = vec![kind];
            if udp {
                parts.push("UDP".to_string());
            }
            if let Some(latency) = latency {
                parts.push(format!("{} ms", latency));
            }
            let subtitle = parts.join(" \u{2022} ");
            let row = adw::ActionRow::builder()
                .title(glib::markup_escape_text(member).to_string())
                .subtitle(subtitle)
                .activatable(entry.is_selectable())
                .build();

            let check = gtk4::CheckButton::builder()
                .active(entry.now.as_deref() == Some(member.as_str()))
                .can_target(false)
                .can_focus(false)
                .build();
            row.add_prefix(&check);

            if entry.is_selectable() {
                let ctx_for_select = ctx.clone();
                let group_name = name.clone();
                let member_name = member.clone();
                let page_for_select = page.clone();
                row.connect_activated(move |_| {
                    let ctx = ctx_for_select.clone();
                    let group_name = group_name.clone();
                    let member_name = member_name.clone();
                    let page = page_for_select.clone();
                    glib::spawn_future_local(async move {
                        if let Err(error) =
                            ctx.select_group_member(&group_name, &member_name).await
                        {
                            tracing::error!("could not switch the group member: {}", error);
                        }
                        page.reload(&ctx);
                    });
                });
            }

            group.add(&row);
        }

        page.list_box.append(&group);
    }
}

async fn measure_latency(ctx: &AppContext, page: &Rc<ProxiesPage>, node: &ProxyNode) {
    let badge = match page.rows.borrow().get(&node.id) {
        Some(row) => row.ping_badge.clone(),
        None => return,
    };
    badge.set_loading();

    let settings = ctx.settings.read().await.clone();
    let outbound_tag = ctx.runner.outbound_tag_for(&node.id).await;

    let latency = match (ctx.runner.is_running(), outbound_tag) {
        (true, Some(tag)) => ctx
            .clash_client()
            .await
            .test_delay(&tag, &settings.latency_test_url, 5000)
            .await
            .ok(),
        _ => ping_node_tcp(&node.server, node.port, 5000).await.ok(),
    };

    badge.set_ping(latency);

    let mut profiles = ctx.profiles.write().await;
    if let Some(stored) = profiles.nodes.iter_mut().find(|n| n.id == node.id) {
        stored.latency_ms = latency;
        stored.last_checked = Some(chrono::Utc::now());
    }
}

async fn persist_latencies(ctx: &AppContext) {
    ctx.profiles.read().await.save();
}

fn show_add_node_dialog(parent: Option<&gtk4::Window>, ctx: AppContext, page: Rc<ProxiesPage>) {
    let dialog = adw::PreferencesWindow::builder()
        .title("Add proxy nodes")
        .modal(true)
        .default_width(440)
        .default_height(420)
        .build();
    if let Some(parent) = parent {
        dialog.set_transient_for(Some(parent));
    }

    let pref_page = adw::PreferencesPage::new();
    let schemes = crate::parser::uri::SUPPORTED_SCHEMES
        .iter()
        .map(|scheme| scheme.trim_end_matches("://"))
        .collect::<Vec<_>>()
        .join(" ");
    let group = adw::PreferencesGroup::builder()
        .title("Proxy links")
        .description(format!("One link per line. Supported schemes: {}", schemes))
        .build();

    let text_view = gtk4::TextView::builder()
        .monospace(true)
        .wrap_mode(gtk4::WrapMode::WordChar)
        .top_margin(8)
        .bottom_margin(8)
        .left_margin(8)
        .right_margin(8)
        .build();
    let scroll = ScrolledWindow::builder()
        .height_request(160)
        .css_classes(vec!["card".to_string()])
        .child(&text_view)
        .build();
    group.add(&scroll);

    let paste_button = Button::builder()
        .label("Paste from clipboard")
        .css_classes(vec!["flat".to_string()])
        .margin_top(6)
        .halign(gtk4::Align::Start)
        .build();
    group.add(&paste_button);

    let status_label = gtk4::Label::builder()
        .visible(false)
        .wrap(true)
        .xalign(0.0)
        .margin_top(6)
        .css_classes(vec!["caption".to_string()])
        .build();

    pref_page.add(&group);

    let action_group = adw::PreferencesGroup::new();
    let save_button = Button::builder()
        .label("Parse and add")
        .css_classes(vec!["suggested-action".to_string(), "pill".to_string()])
        .margin_top(12)
        .margin_bottom(12)
        .halign(gtk4::Align::Center)
        .build();
    action_group.add(&save_button);
    action_group.add(&status_label);
    pref_page.add(&action_group);
    dialog.add(&pref_page);

    let buffer_for_paste = text_view.buffer();
    paste_button.connect_clicked(move |_| {
        let Some(display) = gtk4::gdk::Display::default() else {
            return;
        };
        let buffer = buffer_for_paste.clone();
        display.clipboard().read_text_async(
            gtk4::gio::Cancellable::NONE,
            move |result| {
                if let Ok(Some(text)) = result {
                    buffer.set_text(&text);
                }
            },
        );
    });

    let dialog_clone = dialog.clone();
    let buffer = text_view.buffer();
    save_button.connect_clicked(move |_| {
        let text = buffer
            .text(&buffer.start_iter(), &buffer.end_iter(), false)
            .to_string();
        let (nodes, failures) = parse_links(&text);

        if nodes.is_empty() {
            let message = if failures.is_empty() {
                "Paste at least one proxy link.".to_string()
            } else {
                format!("Could not parse any link: {}", failures.join("; "))
            };
            show_status(&status_label, &message, true);
            return;
        }

        let added = nodes.len();
        let ctx = ctx.clone();
        let page = page.clone();
        let dialog = dialog_clone.clone();
        let status_label = status_label.clone();
        glib::spawn_future_local(async move {
            {
                let mut profiles = ctx.profiles.write().await;
                for node in nodes {
                    profiles.add_or_update_node(node);
                }
                profiles.save();
            }
            ctx.notify(AppEvent::ProfilesChanged);
            page.reload(&ctx);
            if let Err(error) = ctx.reload().await {
                tracing::error!("reload after adding nodes failed: {}", error);
            }
            if failures.is_empty() {
                dialog.close();
            } else {
                show_status(
                    &status_label,
                    &format!(
                        "Added {} node(s); skipped {}: {}",
                        added,
                        failures.len(),
                        failures.join("; ")
                    ),
                    false,
                );
            }
        });
    });

    dialog.present();
}

fn parse_links(text: &str) -> (Vec<ProxyNode>, Vec<String>) {
    let mut nodes = Vec::new();
    let mut failures = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_proxy_uri(line) {
            Ok(node) => nodes.push(node),
            Err(error) => failures.push(error.to_string()),
        }
    }
    (nodes, failures)
}

fn show_status(label: &gtk4::Label, message: &str, is_error: bool) {
    for class in ["error", "warning"] {
        label.remove_css_class(class);
    }
    label.add_css_class(if is_error { "error" } else { "warning" });
    label.set_text(message);
    label.set_visible(true);
}

#[cfg(test)]
mod tests {
    use super::parse_links;

    #[test]
    fn parses_a_multi_line_paste_and_reports_failures() {
        let text = "\
trojan://pw@a.example.com:443#A
# a comment

not-a-link
ss://YWVzLTI1Ni1nY206c2VjcmV0@b.example.com:8388#B
";
        let (nodes, failures) = parse_links(text);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "A");
        assert_eq!(nodes[1].name, "B");
        assert_eq!(failures.len(), 1);
    }

    #[test]
    fn empty_input_yields_nothing() {
        let (nodes, failures) = parse_links("   \n\n# only comments\n");
        assert!(nodes.is_empty());
        assert!(failures.is_empty());
    }
}
