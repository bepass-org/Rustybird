use gtk4::glib;
use gtk4::prelude::*;
use gtk4::{Box, Button, Label, Orientation, ScrolledWindow};
use libadwaita as adw;
use libadwaita::prelude::*;
use std::rc::Rc;

use crate::app::{AppContext, AppEvent};
use crate::config::profile::{ConfigProfile, ProfileKind, Subscription};
use crate::config::profile_store;
use crate::parser::subscription::{fetch_subscription, validate_subscription_url};
use crate::ui::widgets::node_row::glib_escape;
use crate::ui::widgets::speed_badge::format_bytes;

pub struct ProfilesPage {
    pub container: ScrolledWindow,
    subscription_box: Box,
    profile_box: Box,
    add_subscription_button: Button,
    add_profile_button: Button,
    import_profile_button: Button,
}

impl ProfilesPage {
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

        let subscription_header = Box::builder()
            .orientation(Orientation::Horizontal)
            .spacing(8)
            .build();
        subscription_header.append(
            &Label::builder()
                .label("Subscriptions")
                .css_classes(vec!["title-2".to_string()])
                .hexpand(true)
                .xalign(0.0)
                .build(),
        );
        let add_subscription_button = Button::builder()
            .icon_name("list-add-symbolic")
            .label("Add")
            .css_classes(vec!["suggested-action".to_string()])
            .build();
        subscription_header.append(&add_subscription_button);
        main_box.append(&subscription_header);

        let subscription_box = Box::builder()
            .orientation(Orientation::Vertical)
            .spacing(16)
            .build();
        main_box.append(&subscription_box);

        let profile_header = Box::builder()
            .orientation(Orientation::Horizontal)
            .spacing(8)
            .margin_top(8)
            .build();
        profile_header.append(
            &Label::builder()
                .label("Configuration profiles")
                .css_classes(vec!["title-2".to_string()])
                .hexpand(true)
                .xalign(0.0)
                .wrap(true)
                .build(),
        );
        let import_profile_button = Button::builder()
            .icon_name("document-open-symbolic")
            .tooltip_text("Import a sing-box configuration file")
            .build();
        let add_profile_button = Button::builder()
            .icon_name("list-add-symbolic")
            .tooltip_text("Create or subscribe to a sing-box configuration")
            .css_classes(vec!["suggested-action".to_string()])
            .build();
        profile_header.append(&import_profile_button);
        profile_header.append(&add_profile_button);
        main_box.append(&profile_header);

        let profile_box = Box::builder()
            .orientation(Orientation::Vertical)
            .spacing(16)
            .build();
        main_box.append(&profile_box);

        let page = Rc::new(Self {
            container,
            subscription_box,
            profile_box,
            add_subscription_button,
            add_profile_button,
            import_profile_button,
        });

        page.connect_signals(app_ctx);
        page
    }

    fn connect_signals(self: &Rc<Self>, app_ctx: AppContext) {
        let ctx = app_ctx.clone();
        self.add_subscription_button.connect_clicked(move |button| {
            show_add_subscription_dialog(root_window(button).as_ref(), ctx.clone());
        });

        let ctx = app_ctx.clone();
        self.add_profile_button.connect_clicked(move |button| {
            show_add_profile_dialog(root_window(button).as_ref(), ctx.clone());
        });

        let ctx = app_ctx;
        self.import_profile_button.connect_clicked(move |button| {
            let ctx = ctx.clone();
            let Some(window) = root_window(button) else {
                return;
            };
            let dialog = gtk4::FileDialog::builder()
                .title("Import a sing-box configuration")
                .modal(true)
                .build();
            dialog.open(Some(&window), gtk4::gio::Cancellable::NONE, move |result| {
                let Ok(file) = result else { return };
                let Some(path) = file.path() else { return };
                let name = path
                    .file_stem()
                    .map(|stem| stem.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "Imported".to_string());
                match std::fs::read_to_string(&path) {
                    Ok(content) => import_profile(ctx.clone(), name, content),
                    Err(error) => tracing::error!("could not read {:?}: {}", path, error),
                }
            });
        });
    }

    pub fn reload(self: &Rc<Self>, app_ctx: &AppContext) {
        let page = self.clone();
        let ctx = app_ctx.clone();

        glib::spawn_future_local(async move {
            let profiles = ctx.profiles.read().await.clone();
            let active_profile_id = ctx.settings.read().await.active_profile_id.clone();

            clear(&page.subscription_box);
            clear(&page.profile_box);

            if profiles.subscriptions.is_empty() {
                page.subscription_box.append(
                    &adw::StatusPage::builder()
                        .icon_name("folder-download-symbolic")
                        .title("No subscriptions")
                        .description("Add an https subscription URL to import nodes automatically.")
                        .build(),
                );
            } else {
                let group = adw::PreferencesGroup::new();
                for sub in &profiles.subscriptions {
                    group.add(&subscription_row(&ctx, sub, &profiles));
                }
                page.subscription_box.append(&group);
            }

            let group = adw::PreferencesGroup::builder()
                .description(
                    "A profile is a complete sing-box configuration. \
                     Selecting one hands every routing decision to that file.",
                )
                .build();

            let node_row = adw::ActionRow::builder()
                .title("Nodes and rules from this app")
                .subtitle("Build the configuration from the Proxies and Routing pages")
                .activatable(true)
                .build();
            let node_check = gtk4::CheckButton::builder()
                .active(active_profile_id.is_none())
                .can_target(false)
                .can_focus(false)
                .build();
            node_row.add_prefix(&node_check);
            let ctx_for_default = ctx.clone();
            node_row.connect_activated(move |_| {
                let ctx = ctx_for_default.clone();
                glib::spawn_future_local(async move {
                    if let Err(error) = ctx.select_config_profile(None).await {
                        tracing::error!("could not switch to the node list: {}", error);
                    }
                    ctx.notify(AppEvent::ProfilesChanged);
                });
            });
            group.add(&node_row);

            for profile in &profiles.config_profiles {
                group.add(&profile_row(&ctx, profile, active_profile_id.as_deref()));
            }
            page.profile_box.append(&group);
        });
    }
}

fn clear(container: &Box) {
    while let Some(child) = container.first_child() {
        container.remove(&child);
    }
}

fn root_window(widget: &impl IsA<gtk4::Widget>) -> Option<gtk4::Window> {
    widget
        .as_ref()
        .root()
        .and_then(|root| root.downcast::<gtk4::Window>().ok())
}

fn subscription_row(
    ctx: &AppContext,
    sub: &Subscription,
    profiles: &crate::config::profile::ProfileStore,
) -> adw::ExpanderRow {
    let node_count = profiles
        .nodes
        .iter()
        .filter(|n| n.subscription_id.as_deref() == Some(sub.id.as_str()))
        .count();

    let expander = adw::ExpanderRow::builder()
        .title(glib_escape(&sub.name))
        .subtitle(format!("{} nodes", node_count))
        .build();

    let spinner = gtk4::Spinner::builder().visible(false).build();
    let refresh_button = Button::builder()
        .icon_name("view-refresh-symbolic")
        .has_frame(false)
        .tooltip_text("Update this subscription")
        .valign(gtk4::Align::Center)
        .build();

    let ctx_refresh = ctx.clone();
    let sub_refresh = sub.clone();
    let spinner_refresh = spinner.clone();
    refresh_button.connect_clicked(move |button| {
        let ctx = ctx_refresh.clone();
        let sub = sub_refresh.clone();
        let button = button.clone();
        let spinner = spinner_refresh.clone();
        button.set_visible(false);
        spinner.set_visible(true);
        spinner.set_spinning(true);

        glib::spawn_future_local(async move {
            match fetch_subscription(&sub).await {
                Ok(result) => {
                    {
                        let mut profiles = ctx.profiles.write().await;
                        if let Some(stored) =
                            profiles.subscriptions.iter_mut().find(|s| s.id == sub.id)
                        {
                            stored.total_traffic = result.total_traffic;
                            stored.used_traffic = result.used_traffic;
                            stored.expire_time = result.expire_time;
                            stored.last_updated = Some(chrono::Utc::now());
                        }
                        profiles.replace_subscription_nodes(&sub.id, result.nodes);
                        profiles.save();
                    }
                    ctx.notify(AppEvent::ProfilesChanged);
                    if let Err(error) = ctx.reload().await {
                        tracing::error!("reload after update failed: {}", error);
                    }
                }
                Err(error) => tracing::error!("subscription update failed: {}", error),
            }
            spinner.set_spinning(false);
            spinner.set_visible(false);
            button.set_visible(true);
        });
    });

    let delete_button = Button::builder()
        .icon_name("user-trash-symbolic")
        .has_frame(false)
        .tooltip_text("Delete this subscription and its nodes")
        .css_classes(vec!["flat".to_string()])
        .valign(gtk4::Align::Center)
        .build();

    let ctx_delete = ctx.clone();
    let sub_id = sub.id.clone();
    delete_button.connect_clicked(move |_| {
        let ctx = ctx_delete.clone();
        let sub_id = sub_id.clone();
        glib::spawn_future_local(async move {
            {
                let mut profiles = ctx.profiles.write().await;
                profiles.remove_subscription(&sub_id);
                profiles.save();
            }
            ctx.notify(AppEvent::ProfilesChanged);
            if let Err(error) = ctx.reload().await {
                tracing::error!("reload after deletion failed: {}", error);
            }
        });
    });

    expander.add_suffix(&spinner);
    expander.add_suffix(&refresh_button);
    expander.add_suffix(&delete_button);

    expander.add_row(
        &adw::ActionRow::builder()
            .title("URL")
            .subtitle(glib_escape(&sub.url))
            .build(),
    );

    let usage = match (sub.used_traffic, sub.total_traffic) {
        (Some(used), Some(total)) => {
            format!("{} of {}", format_bytes(used), format_bytes(total))
        }
        (Some(used), None) => format_bytes(used),
        _ => "Not reported".to_string(),
    };
    expander.add_row(
        &adw::ActionRow::builder()
            .title("Data usage")
            .subtitle(usage)
            .build(),
    );

    let auto_update_row = adw::SwitchRow::builder()
        .title("Automatic updates")
        .subtitle(format!("Every {} hours", sub.update_interval_hours.max(1)))
        .active(sub.auto_update)
        .build();
    let ctx_auto = ctx.clone();
    let sub_id = sub.id.clone();
    auto_update_row.connect_active_notify(move |row| {
        let enabled = row.is_active();
        let ctx = ctx_auto.clone();
        let sub_id = sub_id.clone();
        glib::spawn_future_local(async move {
            let mut profiles = ctx.profiles.write().await;
            if let Some(stored) = profiles.subscriptions.iter_mut().find(|s| s.id == sub_id) {
                stored.auto_update = enabled;
            }
            profiles.save();
        });
    });
    expander.add_row(&auto_update_row);

    if let Some(expire) = sub.expire_time {
        expander.add_row(
            &adw::ActionRow::builder()
                .title("Expires")
                .subtitle(expire.format("%Y-%m-%d %H:%M UTC").to_string())
                .build(),
        );
    }

    if let Some(updated) = sub.last_updated {
        expander.add_row(
            &adw::ActionRow::builder()
                .title("Last updated")
                .subtitle(updated.format("%Y-%m-%d %H:%M UTC").to_string())
                .build(),
        );
    }

    expander
}

fn profile_row(
    ctx: &AppContext,
    profile: &ConfigProfile,
    active_profile_id: Option<&str>,
) -> adw::ExpanderRow {
    let summary = profile_store::read_profile_content(&profile.id)
        .map(|content| profile_store::profile_summary(&content))
        .unwrap_or_else(|_| "The profile file is missing".to_string());

    let expander = adw::ExpanderRow::builder()
        .title(glib_escape(&profile.name))
        .subtitle(format!("{} \u{2022} {}", profile.kind.label(), summary))
        .build();

    let check = gtk4::CheckButton::builder()
        .active(active_profile_id == Some(profile.id.as_str()))
        .tooltip_text("Use this profile")
        .valign(gtk4::Align::Center)
        .build();
    let ctx_select = ctx.clone();
    let profile_id = profile.id.clone();
    check.connect_toggled(move |button| {
        if !button.is_active() {
            return;
        }
        let ctx = ctx_select.clone();
        let profile_id = profile_id.clone();
        glib::spawn_future_local(async move {
            if let Err(error) = ctx.select_config_profile(Some(&profile_id)).await {
                tracing::error!("could not activate the profile: {}", error);
            }
            ctx.notify(AppEvent::ProfilesChanged);
        });
    });
    expander.add_prefix(&check);

    let edit_button = Button::builder()
        .icon_name("document-edit-symbolic")
        .has_frame(false)
        .tooltip_text("Edit this configuration")
        .valign(gtk4::Align::Center)
        .build();
    let ctx_edit = ctx.clone();
    let profile_for_edit = profile.clone();
    edit_button.connect_clicked(move |button| {
        show_profile_editor(
            root_window(button).as_ref(),
            ctx_edit.clone(),
            profile_for_edit.clone(),
        );
    });
    expander.add_suffix(&edit_button);

    if profile.kind == ProfileKind::Remote {
        let refresh_button = Button::builder()
            .icon_name("view-refresh-symbolic")
            .has_frame(false)
            .tooltip_text("Download the latest version")
            .valign(gtk4::Align::Center)
            .build();
        let ctx_refresh = ctx.clone();
        let profile_for_refresh = profile.clone();
        refresh_button.connect_clicked(move |button| {
            let ctx = ctx_refresh.clone();
            let profile = profile_for_refresh.clone();
            let button = button.clone();
            button.set_sensitive(false);
            glib::spawn_future_local(async move {
                match profile_store::fetch_remote_profile(&profile).await {
                    Ok(content) => {
                        match profile_store::write_profile_content(&profile.id, &content) {
                            Ok(()) => {
                                {
                                    let mut profiles = ctx.profiles.write().await;
                                    if let Some(stored) = profiles
                                        .config_profiles
                                        .iter_mut()
                                        .find(|p| p.id == profile.id)
                                    {
                                        stored.last_updated = Some(chrono::Utc::now());
                                    }
                                    profiles.save();
                                }
                                ctx.notify(AppEvent::ProfilesChanged);
                                if let Err(error) = ctx.reload().await {
                                    tracing::error!("reload after profile update failed: {}", error);
                                }
                            }
                            Err(error) => tracing::error!("could not store the profile: {}", error),
                        }
                    }
                    Err(error) => tracing::error!("profile download failed: {}", error),
                }
                button.set_sensitive(true);
            });
        });
        expander.add_suffix(&refresh_button);
    }

    let delete_button = Button::builder()
        .icon_name("user-trash-symbolic")
        .has_frame(false)
        .tooltip_text("Delete this profile")
        .css_classes(vec!["flat".to_string()])
        .valign(gtk4::Align::Center)
        .build();
    let ctx_delete = ctx.clone();
    let profile_id = profile.id.clone();
    delete_button.connect_clicked(move |_| {
        let ctx = ctx_delete.clone();
        let profile_id = profile_id.clone();
        glib::spawn_future_local(async move {
            let was_active =
                ctx.settings.read().await.active_profile_id.as_deref() == Some(profile_id.as_str());
            {
                let mut profiles = ctx.profiles.write().await;
                profiles.remove_config_profile(&profile_id);
                profiles.save();
            }
            if was_active {
                if let Err(error) = ctx.select_config_profile(None).await {
                    tracing::error!("could not fall back to the node list: {}", error);
                }
            }
            ctx.notify(AppEvent::ProfilesChanged);
        });
    });
    expander.add_suffix(&delete_button);

    if let Some(url) = &profile.remote_url {
        expander.add_row(
            &adw::ActionRow::builder()
                .title("URL")
                .subtitle(glib_escape(url))
                .build(),
        );

        let auto_update_row = adw::SwitchRow::builder()
            .title("Automatic updates")
            .subtitle(format!(
                "Every {} minutes",
                profile.update_interval_minutes.max(15)
            ))
            .active(profile.auto_update)
            .build();
        let ctx_auto = ctx.clone();
        let profile_id = profile.id.clone();
        auto_update_row.connect_active_notify(move |row| {
            let enabled = row.is_active();
            let ctx = ctx_auto.clone();
            let profile_id = profile_id.clone();
            glib::spawn_future_local(async move {
                let mut profiles = ctx.profiles.write().await;
                if let Some(stored) = profiles
                    .config_profiles
                    .iter_mut()
                    .find(|p| p.id == profile_id)
                {
                    stored.auto_update = enabled;
                }
                profiles.save();
            });
        });
        expander.add_row(&auto_update_row);
    }

    if let Some(updated) = profile.last_updated {
        expander.add_row(
            &adw::ActionRow::builder()
                .title("Last updated")
                .subtitle(updated.format("%Y-%m-%d %H:%M UTC").to_string())
                .build(),
        );
    }

    let export_row = adw::ActionRow::builder()
        .title("Export to a file")
        .activatable(true)
        .build();
    export_row.add_suffix(
        &gtk4::Image::builder()
            .icon_name("document-save-symbolic")
            .build(),
    );
    let profile_for_export = profile.clone();
    export_row.connect_activated(move |row| {
        let Some(window) = root_window(row) else { return };
        let Ok(content) = profile_store::read_profile_content(&profile_for_export.id) else {
            return;
        };
        let dialog = gtk4::FileDialog::builder()
            .title("Export the profile")
            .initial_name(format!("{}.json", profile_for_export.name))
            .modal(true)
            .build();
        dialog.save(Some(&window), gtk4::gio::Cancellable::NONE, move |result| {
            let Ok(file) = result else { return };
            let Some(path) = file.path() else { return };
            if let Err(error) = std::fs::write(&path, content.as_bytes()) {
                tracing::error!("could not export to {:?}: {}", path, error);
            }
        });
    });
    expander.add_row(&export_row);

    expander
}

fn import_profile(ctx: AppContext, name: String, content: String) {
    glib::spawn_future_local(async move {
        if let Err(error) = profile_store::validate_profile_content(&content) {
            tracing::error!("rejected the imported profile: {}", error);
            return;
        }
        let profile = {
            let mut profiles = ctx.profiles.write().await;
            let unique = profiles.unique_profile_name(&name);
            let profile = ConfigProfile::local(unique);
            if let Err(error) = profile_store::write_profile_content(&profile.id, &content) {
                tracing::error!("could not store the profile: {}", error);
                return;
            }
            profiles.config_profiles.push(profile.clone());
            profiles.save();
            profile
        };
        tracing::info!("imported profile {}", profile.name);
        ctx.notify(AppEvent::ProfilesChanged);
    });
}

fn show_add_subscription_dialog(parent: Option<&gtk4::Window>, ctx: AppContext) {
    let dialog = adw::PreferencesWindow::builder()
        .title("Add subscription")
        .modal(true)
        .default_width(420)
        .default_height(320)
        .build();
    if let Some(parent) = parent {
        dialog.set_transient_for(Some(parent));
    }

    let pref_page = adw::PreferencesPage::new();
    let group = adw::PreferencesGroup::builder()
        .description("Only https URLs are accepted so the node list cannot be tampered with.")
        .build();

    let name_entry = adw::EntryRow::builder().title("Name").build();
    let url_entry = adw::EntryRow::builder().title("Subscription URL").build();
    group.add(&name_entry);
    group.add(&url_entry);
    pref_page.add(&group);

    let action_group = adw::PreferencesGroup::new();
    let save_button = Button::builder()
        .label("Import")
        .css_classes(vec!["suggested-action".to_string(), "pill".to_string()])
        .margin_top(12)
        .margin_bottom(12)
        .halign(gtk4::Align::Center)
        .build();
    let spinner = gtk4::Spinner::builder().visible(false).build();
    let error_label = Label::builder()
        .visible(false)
        .wrap(true)
        .xalign(0.0)
        .css_classes(vec!["caption".to_string(), "error".to_string()])
        .build();

    action_group.add(&save_button);
    action_group.add(&spinner);
    action_group.add(&error_label);
    pref_page.add(&action_group);
    dialog.add(&pref_page);

    let dialog_clone = dialog.clone();
    save_button.connect_clicked(move |button| {
        let url = url_entry.text().to_string();
        if let Err(error) = validate_subscription_url(&url) {
            error_label.set_text(&error.to_string());
            error_label.set_visible(true);
            return;
        }

        let name = {
            let entered = name_entry.text().to_string();
            if entered.trim().is_empty() {
                url.parse::<url::Url>()
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_string))
                    .unwrap_or_else(|| "Subscription".to_string())
            } else {
                entered.trim().to_string()
            }
        };

        error_label.set_visible(false);
        button.set_sensitive(false);
        spinner.set_visible(true);
        spinner.set_spinning(true);

        let subscription = Subscription::new(name, url);
        let ctx = ctx.clone();
        let dialog = dialog_clone.clone();
        let button = button.clone();
        let spinner = spinner.clone();
        let error_label = error_label.clone();

        glib::spawn_future_local(async move {
            match fetch_subscription(&subscription).await {
                Ok(result) => {
                    {
                        let mut profiles = ctx.profiles.write().await;
                        let mut stored = subscription.clone();
                        stored.total_traffic = result.total_traffic;
                        stored.used_traffic = result.used_traffic;
                        stored.expire_time = result.expire_time;
                        stored.last_updated = Some(chrono::Utc::now());
                        stored.node_ids = result.nodes.iter().map(|n| n.id.clone()).collect();
                        profiles.subscriptions.push(stored);
                        profiles.replace_subscription_nodes(&subscription.id, result.nodes);
                        profiles.save();
                    }
                    ctx.notify(AppEvent::ProfilesChanged);
                    if let Err(error) = ctx.reload().await {
                        tracing::error!("reload after import failed: {}", error);
                    }
                    dialog.close();
                }
                Err(error) => {
                    error_label.set_text(&format!("Import failed: {}", error));
                    error_label.set_visible(true);
                }
            }
            spinner.set_spinning(false);
            spinner.set_visible(false);
            button.set_sensitive(true);
        });
    });

    dialog.present();
}

const STARTER_PROFILE: &str = r#"{
  "log": {
    "level": "info"
  },
  "dns": {
    "servers": [
      {
        "type": "local",
        "tag": "local"
      }
    ],
    "final": "local"
  },
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "127.0.0.1",
      "listen_port": 2080
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "rules": [
      {
        "action": "sniff"
      }
    ],
    "final": "direct",
    "default_domain_resolver": "local"
  }
}
"#;

fn show_add_profile_dialog(parent: Option<&gtk4::Window>, ctx: AppContext) {
    let dialog = adw::PreferencesWindow::builder()
        .title("Add configuration profile")
        .modal(true)
        .default_width(440)
        .default_height(360)
        .build();
    if let Some(parent) = parent {
        dialog.set_transient_for(Some(parent));
    }

    let pref_page = adw::PreferencesPage::new();
    let group = adw::PreferencesGroup::builder()
        .description(
            "A remote profile downloads a sing-box JSON configuration over https. \
             A local profile starts from a small template you can edit.",
        )
        .build();

    let name_entry = adw::EntryRow::builder().title("Name").build();
    let kind_row = adw::ComboRow::builder()
        .title("Source")
        .model(&gtk4::StringList::new(&["Local", "Remote URL"]))
        .build();
    let url_entry = adw::EntryRow::builder().title("Profile URL").build();
    url_entry.set_sensitive(false);

    let url_for_toggle = url_entry.clone();
    kind_row.connect_selected_notify(move |row| {
        url_for_toggle.set_sensitive(row.selected() == 1);
    });

    group.add(&name_entry);
    group.add(&kind_row);
    group.add(&url_entry);
    pref_page.add(&group);

    let action_group = adw::PreferencesGroup::new();
    let save_button = Button::builder()
        .label("Create")
        .css_classes(vec!["suggested-action".to_string(), "pill".to_string()])
        .margin_top(12)
        .margin_bottom(12)
        .halign(gtk4::Align::Center)
        .build();
    let spinner = gtk4::Spinner::builder().visible(false).build();
    let error_label = Label::builder()
        .visible(false)
        .wrap(true)
        .xalign(0.0)
        .css_classes(vec!["caption".to_string(), "error".to_string()])
        .build();
    action_group.add(&save_button);
    action_group.add(&spinner);
    action_group.add(&error_label);
    pref_page.add(&action_group);
    dialog.add(&pref_page);

    let dialog_clone = dialog.clone();
    save_button.connect_clicked(move |button| {
        let remote = kind_row.selected() == 1;
        let url = url_entry.text().to_string().trim().to_string();
        if remote {
            if let Err(error) = validate_subscription_url(&url) {
                error_label.set_text(&error.to_string());
                error_label.set_visible(true);
                return;
            }
        }

        let entered_name = name_entry.text().to_string().trim().to_string();
        let fallback = if remote {
            url.parse::<url::Url>()
                .ok()
                .and_then(|u| u.host_str().map(str::to_string))
                .unwrap_or_else(|| "Profile".to_string())
        } else {
            "Local profile".to_string()
        };
        let name = if entered_name.is_empty() {
            fallback
        } else {
            entered_name
        };

        error_label.set_visible(false);
        button.set_sensitive(false);
        spinner.set_visible(true);
        spinner.set_spinning(true);

        let ctx = ctx.clone();
        let dialog = dialog_clone.clone();
        let button = button.clone();
        let spinner = spinner.clone();
        let error_label = error_label.clone();

        glib::spawn_future_local(async move {
            let result = if remote {
                let probe = ConfigProfile::remote(name.clone(), url.clone());
                profile_store::fetch_remote_profile(&probe)
                    .await
                    .map(|content| (probe, content))
            } else {
                Ok((
                    ConfigProfile::local(name.clone()),
                    STARTER_PROFILE.to_string(),
                ))
            };

            match result {
                Ok((mut profile, content)) => {
                    {
                        let mut profiles = ctx.profiles.write().await;
                        profile.name = profiles.unique_profile_name(&profile.name);
                        profile.last_updated = Some(chrono::Utc::now());
                        match profile_store::write_profile_content(&profile.id, &content) {
                            Ok(()) => {
                                profiles.config_profiles.push(profile);
                                profiles.save();
                            }
                            Err(error) => {
                                error_label.set_text(&format!("Could not save: {}", error));
                                error_label.set_visible(true);
                                spinner.set_spinning(false);
                                spinner.set_visible(false);
                                button.set_sensitive(true);
                                return;
                            }
                        }
                    }
                    ctx.notify(AppEvent::ProfilesChanged);
                    dialog.close();
                }
                Err(error) => {
                    error_label.set_text(&format!("Could not add the profile: {}", error));
                    error_label.set_visible(true);
                }
            }
            spinner.set_spinning(false);
            spinner.set_visible(false);
            button.set_sensitive(true);
        });
    });

    dialog.present();
}

fn show_profile_editor(parent: Option<&gtk4::Window>, ctx: AppContext, profile: ConfigProfile) {
    let content = profile_store::read_profile_content(&profile.id).unwrap_or_default();

    let window = adw::Window::builder()
        .title(format!("Edit {}", profile.name))
        .modal(true)
        .default_width(720)
        .default_height(640)
        .build();
    if let Some(parent) = parent {
        window.set_transient_for(Some(parent));
    }

    let header = adw::HeaderBar::new();
    let save_button = Button::builder()
        .label("Save")
        .css_classes(vec!["suggested-action".to_string()])
        .build();
    let format_button = Button::builder()
        .label("Format")
        .tooltip_text("Re-indent the JSON")
        .build();
    header.pack_end(&save_button);
    header.pack_start(&format_button);

    let text_view = gtk4::TextView::builder()
        .monospace(true)
        .wrap_mode(gtk4::WrapMode::None)
        .top_margin(8)
        .bottom_margin(8)
        .left_margin(8)
        .right_margin(8)
        .build();
    text_view.buffer().set_text(&content);

    let scroll = ScrolledWindow::builder()
        .vexpand(true)
        .child(&text_view)
        .build();

    let status_label = Label::builder()
        .visible(false)
        .wrap(true)
        .xalign(0.0)
        .margin_start(12)
        .margin_end(12)
        .margin_bottom(8)
        .css_classes(vec!["caption".to_string()])
        .build();

    let content_box = Box::builder()
        .orientation(Orientation::Vertical)
        .build();
    content_box.append(&scroll);
    content_box.append(&status_label);

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&content_box));
    window.set_content(Some(&toolbar));

    let buffer_for_format = text_view.buffer();
    let status_for_format = status_label.clone();
    format_button.connect_clicked(move |_| {
        let text = buffer_for_format
            .text(
                &buffer_for_format.start_iter(),
                &buffer_for_format.end_iter(),
                false,
            )
            .to_string();
        match serde_json::from_str::<serde_json::Value>(&text) {
            Ok(value) => {
                buffer_for_format.set_text(&serde_json::to_string_pretty(&value).unwrap_or(text));
                status_for_format.set_visible(false);
            }
            Err(error) => {
                show_status(&status_for_format, &format!("Invalid JSON: {}", error), true);
            }
        }
    });

    let buffer_for_save = text_view.buffer();
    let window_for_save = window.clone();
    save_button.connect_clicked(move |_| {
        let text = buffer_for_save
            .text(
                &buffer_for_save.start_iter(),
                &buffer_for_save.end_iter(),
                false,
            )
            .to_string();

        if let Err(error) = profile_store::validate_profile_content(&text) {
            show_status(&status_label, &error.to_string(), true);
            return;
        }
        if let Err(error) = profile_store::write_profile_content(&profile.id, &text) {
            show_status(&status_label, &error.to_string(), true);
            return;
        }

        let ctx = ctx.clone();
        let profile_id = profile.id.clone();
        let window = window_for_save.clone();
        glib::spawn_future_local(async move {
            {
                let mut profiles = ctx.profiles.write().await;
                if let Some(stored) = profiles
                    .config_profiles
                    .iter_mut()
                    .find(|p| p.id == profile_id)
                {
                    stored.last_updated = Some(chrono::Utc::now());
                }
                profiles.save();
            }
            ctx.notify(AppEvent::ProfilesChanged);
            let is_active =
                ctx.settings.read().await.active_profile_id.as_deref() == Some(profile_id.as_str());
            if is_active {
                if let Err(error) = ctx.reload().await {
                    tracing::error!("reload after editing the profile failed: {}", error);
                }
            }
            window.close();
        });
    });

    window.present();
}

fn show_status(label: &Label, message: &str, is_error: bool) {
    for class in ["error", "success"] {
        label.remove_css_class(class);
    }
    label.add_css_class(if is_error { "error" } else { "success" });
    label.set_text(message);
    label.set_visible(true);
}
