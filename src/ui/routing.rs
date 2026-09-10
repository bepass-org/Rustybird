use gtk4::glib;
use gtk4::prelude::*;
use gtk4::{Box, Button, Label, Orientation, ScrolledWindow};
use libadwaita as adw;
use libadwaita::prelude::*;
use std::cell::Cell;
use std::rc::Rc;

use crate::app::{AppContext, AppEvent};
use crate::config::profile::{CustomRule, RuleOutbound, RuleType};
use crate::core::rule_sets;
use crate::ui::widgets::node_row::glib_escape;

const ADS_SUBTITLE: &str = "Uses the sing-geosite ads rule set";

pub struct RoutingPage {
    pub container: ScrolledWindow,
    list_box: Box,
    add_button: Button,
    bypass_private_row: adw::SwitchRow,
    block_ads_row: adw::SwitchRow,
    suppress_signals: Rc<Cell<bool>>,
}

impl RoutingPage {
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

        let title_label = Label::builder()
            .label("Routing")
            .css_classes(vec!["title-2".to_string()])
            .hexpand(true)
            .xalign(0.0)
            .build();

        let add_button = Button::builder()
            .icon_name("list-add-symbolic")
            .label("Add rule")
            .css_classes(vec!["suggested-action".to_string()])
            .build();

        header_box.append(&title_label);
        header_box.append(&add_button);
        main_box.append(&header_box);

        let preset_group = adw::PreferencesGroup::builder()
            .title("Presets")
            .description("Changes are applied to the running core immediately.")
            .build();

        let bypass_private_row = adw::SwitchRow::builder()
            .title("Bypass private networks")
            .subtitle("Send LAN and loopback traffic direct")
            .build();

        let block_ads_row = adw::SwitchRow::builder()
            .title("Block ads and trackers")
            .subtitle(ADS_SUBTITLE)
            .build();

        preset_group.add(&bypass_private_row);
        preset_group.add(&block_ads_row);
        main_box.append(&preset_group);

        let list_box = Box::builder()
            .orientation(Orientation::Vertical)
            .spacing(16)
            .build();
        main_box.append(&list_box);

        let page = Rc::new(Self {
            container,
            list_box,
            add_button,
            bypass_private_row,
            block_ads_row,
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
            page.bypass_private_row
                .set_active(settings.bypass_private_networks);
            page.block_ads_row.set_active(settings.block_ads);
            page.suppress_signals.set(false);
        });

        let page = self.clone();
        let ctx = app_ctx.clone();
        self.bypass_private_row.connect_active_notify(move |row| {
            if page.suppress_signals.get() {
                return;
            }
            let enabled = row.is_active();
            let ctx = ctx.clone();
            glib::spawn_future_local(async move {
                {
                    let mut settings = ctx.settings.write().await;
                    settings.bypass_private_networks = enabled;
                    settings.save();
                }
                if let Err(error) = ctx.reload().await {
                    tracing::error!("reload after preset change failed: {}", error);
                }
            });
        });

        let page = self.clone();
        let ctx = app_ctx.clone();
        self.block_ads_row.connect_active_notify(move |row| {
            if page.suppress_signals.get() {
                return;
            }
            let enabled = row.is_active();
            let page = page.clone();
            let ctx = ctx.clone();
            let row = row.clone();

            glib::spawn_future_local(async move {
                if enabled {
                    row.set_sensitive(false);
                    row.set_subtitle("Downloading the ads rule set");
                    let downloaded = rule_sets::ensure_rule_set(rule_sets::ADS_RULE_SET_TAG).await;
                    row.set_sensitive(true);

                    if let Err(error) = downloaded {
                        row.set_subtitle(&format!("Download failed: {}", error));
                        page.suppress_signals.set(true);
                        row.set_active(false);
                        page.suppress_signals.set(false);
                        return;
                    }
                    row.set_subtitle(ADS_SUBTITLE);
                }

                {
                    let mut settings = ctx.settings.write().await;
                    settings.block_ads = enabled;
                    settings.save();
                }
                if let Err(error) = ctx.reload().await {
                    tracing::error!("reload after preset change failed: {}", error);
                }
            });
        });

        let ctx = app_ctx;
        self.add_button.connect_clicked(move |button| {
            let root = button
                .root()
                .and_then(|root| root.downcast::<gtk4::Window>().ok());
            show_add_rule_dialog(root.as_ref(), ctx.clone());
        });
    }

    pub fn reload(self: &Rc<Self>, app_ctx: &AppContext) {
        let page = self.clone();
        let ctx = app_ctx.clone();

        glib::spawn_future_local(async move {
            let profiles = ctx.profiles.read().await.clone();

            while let Some(child) = page.list_box.first_child() {
                page.list_box.remove(&child);
            }

            let group = adw::PreferencesGroup::builder()
                .title("Custom rules")
                .description("Evaluated top to bottom before the default route.")
                .build();

            if profiles.custom_rules.is_empty() {
                group.add(
                    &adw::ActionRow::builder()
                        .title("No custom rules")
                        .subtitle(
                            "Add a rule to override routing for a domain, IP range or process.",
                        )
                        .build(),
                );
            } else {
                for rule in &profiles.custom_rules {
                    let row = adw::ActionRow::builder()
                        .title(glib_escape(&rule.value))
                        .subtitle(format!(
                            "{} \u{2192} {}",
                            rule.rule_type.label(),
                            rule.outbound.label()
                        ))
                        .build();

                    let toggle = gtk4::Switch::builder()
                        .active(rule.enabled)
                        .valign(gtk4::Align::Center)
                        .tooltip_text("Enable or disable this rule")
                        .build();

                    let rule_id = rule.id.clone();
                    let ctx_toggle = ctx.clone();
                    toggle.connect_state_set(move |_, state| {
                        let rule_id = rule_id.clone();
                        let ctx = ctx_toggle.clone();
                        glib::spawn_future_local(async move {
                            {
                                let mut profiles = ctx.profiles.write().await;
                                if let Some(stored) =
                                    profiles.custom_rules.iter_mut().find(|r| r.id == rule_id)
                                {
                                    stored.enabled = state;
                                }
                                profiles.save();
                            }
                            if let Err(error) = ctx.reload().await {
                                tracing::error!("reload after rule toggle failed: {}", error);
                            }
                        });
                        glib::Propagation::Proceed
                    });

                    let delete_button = Button::builder()
                        .icon_name("user-trash-symbolic")
                        .has_frame(false)
                        .tooltip_text("Delete this rule")
                        .css_classes(vec!["flat".to_string()])
                        .valign(gtk4::Align::Center)
                        .build();

                    let rule_id = rule.id.clone();
                    let ctx_delete = ctx.clone();
                    delete_button.connect_clicked(move |_| {
                        let rule_id = rule_id.clone();
                        let ctx = ctx_delete.clone();
                        glib::spawn_future_local(async move {
                            {
                                let mut profiles = ctx.profiles.write().await;
                                profiles.custom_rules.retain(|r| r.id != rule_id);
                                profiles.save();
                            }
                            ctx.notify(AppEvent::ProfilesChanged);
                            if let Err(error) = ctx.reload().await {
                                tracing::error!("reload after rule deletion failed: {}", error);
                            }
                        });
                    });

                    row.add_suffix(&toggle);
                    row.add_suffix(&delete_button);
                    group.add(&row);
                }
            }

            page.list_box.append(&group);
        });
    }

    pub fn sync_from_settings(&self, settings: &crate::config::settings::AppSettings) {
        self.suppress_signals.set(true);
        self.bypass_private_row
            .set_active(settings.bypass_private_networks);
        self.block_ads_row.set_active(settings.block_ads);
        self.suppress_signals.set(false);
    }
}

fn show_add_rule_dialog(parent: Option<&gtk4::Window>, ctx: AppContext) {
    let dialog = adw::PreferencesWindow::builder()
        .title("Add routing rule")
        .modal(true)
        .default_width(400)
        .default_height(340)
        .build();
    if let Some(parent) = parent {
        dialog.set_transient_for(Some(parent));
    }

    let pref_page = adw::PreferencesPage::new();
    let group = adw::PreferencesGroup::new();

    let labels: Vec<&str> = RuleType::ALL.iter().map(|t| t.label()).collect();
    let type_combo = adw::ComboRow::builder()
        .title("Match on")
        .model(&gtk4::StringList::new(&labels))
        .build();

    let value_entry = adw::EntryRow::builder().title("Value").build();
    value_entry.set_text(RuleType::DomainSuffix.placeholder());

    let outbound_labels: Vec<&str> = RuleOutbound::ALL.iter().map(|o| o.label()).collect();
    let target_combo = adw::ComboRow::builder()
        .title("Send to")
        .model(&gtk4::StringList::new(&outbound_labels))
        .build();

    let value_entry_clone = value_entry.clone();
    type_combo.connect_selected_notify(move |combo| {
        let rule_type = RuleType::from_index(combo.selected());
        value_entry_clone.set_text(rule_type.placeholder());
    });

    group.add(&type_combo);
    group.add(&value_entry);
    group.add(&target_combo);
    pref_page.add(&group);

    let action_group = adw::PreferencesGroup::new();
    let save_button = Button::builder()
        .label("Save rule")
        .css_classes(vec!["suggested-action".to_string(), "pill".to_string()])
        .margin_top(12)
        .margin_bottom(12)
        .halign(gtk4::Align::Center)
        .build();
    let error_label = Label::builder()
        .visible(false)
        .wrap(true)
        .xalign(0.0)
        .css_classes(vec!["caption".to_string(), "error".to_string()])
        .build();
    action_group.add(&save_button);
    action_group.add(&error_label);
    pref_page.add(&action_group);
    dialog.add(&pref_page);

    let dialog_clone = dialog.clone();
    let save_button_clone = save_button.clone();
    save_button.connect_clicked(move |_| {
        let rule_type = RuleType::from_index(type_combo.selected());
        let outbound = RuleOutbound::from_index(target_combo.selected());
        let value = value_entry.text().to_string();

        if let Err(message) = validate_rule_value(rule_type, &value) {
            error_label.set_text(message);
            error_label.set_visible(true);
            return;
        }

        error_label.set_visible(false);
        let rule = CustomRule::new(rule_type, &value, outbound);
        let ctx = ctx.clone();
        let dialog = dialog_clone.clone();
        let error_label = error_label.clone();
        let save_button = save_button_clone.clone();

        glib::spawn_future_local(async move {
            if rule.rule_type == RuleType::RuleSet {
                save_button.set_sensitive(false);
                let downloaded = rule_sets::ensure_rule_set(&rule.value).await;
                save_button.set_sensitive(true);

                if let Err(error) = downloaded {
                    error_label.set_text(&format!("Could not download that rule set: {}", error));
                    error_label.set_visible(true);
                    return;
                }
            }

            {
                let mut profiles = ctx.profiles.write().await;
                profiles.custom_rules.push(rule);
                profiles.save();
            }
            ctx.notify(AppEvent::ProfilesChanged);
            if let Err(error) = ctx.reload().await {
                tracing::error!("reload after adding rule failed: {}", error);
            }
            dialog.close();
        });
    });

    dialog.present();
}

fn validate_rule_value(rule_type: RuleType, value: &str) -> Result<(), &'static str> {
    let value = value.trim();
    if value.is_empty() {
        return Err("Enter a value for the rule.");
    }
    if rule_type != RuleType::WifiSsid
        && rule_type != RuleType::ProcessPath
        && value.contains(char::is_whitespace)
    {
        return Err("The value cannot contain spaces.");
    }

    match rule_type {
        RuleType::IpCidr | RuleType::SourceIpCidr => {
            for part in value.split(',') {
                if part.trim().parse::<ipnet_lite::Cidr>().is_err() {
                    return Err("Enter a valid CIDR range such as 10.0.0.0/8.");
                }
            }
        }
        RuleType::Port => {
            if !value
                .split(',')
                .all(|part| part.trim().parse::<u16>().is_ok())
            {
                return Err("Enter one or more port numbers separated by commas.");
            }
        }
        RuleType::PortRange => {
            let Some((start, end)) = value.split_once(':') else {
                return Err("Enter a range such as 1000:2000.");
            };
            let start = start.trim().parse::<u16>();
            let end = end.trim().parse::<u16>();
            match (start, end) {
                (Ok(start), Ok(end)) if start <= end => {}
                _ => return Err("Enter a range such as 1000:2000."),
            }
        }
        RuleType::Network => {
            if !matches!(value.to_ascii_lowercase().as_str(), "tcp" | "udp") {
                return Err("Network must be tcp or udp.");
            }
        }
        RuleType::ClashMode => {
            if !matches!(value, "Rule" | "Global" | "Direct") {
                return Err("Clash mode must be Rule, Global or Direct.");
            }
        }
        RuleType::DomainRegex => {
            if value.len() > 512 {
                return Err("That regular expression is too long.");
            }
        }
        RuleType::RuleSetUrl => {
            if !value.starts_with("https://") {
                return Err("Use an https:// URL so the rule set cannot be tampered with.");
            }
        }
        RuleType::RuleSet => {
            if !value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            {
                return Err("Rule set names may only use letters, digits, dots, dashes and underscores.");
            }
        }
        _ => {}
    }
    Ok(())
}

mod ipnet_lite {
    use std::net::IpAddr;
    use std::str::FromStr;

    pub struct Cidr;

    impl FromStr for Cidr {
        type Err = ();

        fn from_str(value: &str) -> Result<Self, Self::Err> {
            let (address, prefix) = value.split_once('/').ok_or(())?;
            let address: IpAddr = address.parse().map_err(|_| ())?;
            let prefix: u8 = prefix.parse().map_err(|_| ())?;
            let max = if address.is_ipv4() { 32 } else { 128 };
            if prefix > max {
                return Err(());
            }
            Ok(Cidr)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::validate_rule_value;
    use crate::config::profile::RuleType;

    #[test]
    fn rejects_empty_and_spaced_values() {
        assert!(validate_rule_value(RuleType::Domain, "   ").is_err());
        assert!(validate_rule_value(RuleType::Domain, "a b").is_err());
    }

    #[test]
    fn validates_cidr_values() {
        assert!(validate_rule_value(RuleType::IpCidr, "10.0.0.0/8").is_ok());
        assert!(validate_rule_value(RuleType::IpCidr, "10.0.0.0/8,192.168.0.0/16").is_ok());
        assert!(validate_rule_value(RuleType::IpCidr, "10.0.0.0/40").is_err());
        assert!(validate_rule_value(RuleType::SourceIpCidr, "not-a-cidr").is_err());
        assert!(validate_rule_value(RuleType::IpCidr, "fd00::/8").is_ok());
    }

    #[test]
    fn validates_ports_and_ranges() {
        assert!(validate_rule_value(RuleType::Port, "443").is_ok());
        assert!(validate_rule_value(RuleType::Port, "443,8443").is_ok());
        assert!(validate_rule_value(RuleType::Port, "70000").is_err());
        assert!(validate_rule_value(RuleType::PortRange, "1000:2000").is_ok());
        assert!(validate_rule_value(RuleType::PortRange, "2000:1000").is_err());
        assert!(validate_rule_value(RuleType::PortRange, "1000").is_err());
    }

    #[test]
    fn validates_enumerated_values() {
        assert!(validate_rule_value(RuleType::Network, "udp").is_ok());
        assert!(validate_rule_value(RuleType::Network, "sctp").is_err());
        assert!(validate_rule_value(RuleType::ClashMode, "Global").is_ok());
        assert!(validate_rule_value(RuleType::ClashMode, "global").is_err());
    }

    #[test]
    fn validates_rule_set_names_and_urls() {
        assert!(validate_rule_value(RuleType::RuleSet, "geosite-netflix").is_ok());
        assert!(validate_rule_value(RuleType::RuleSet, "../escape").is_err());
        assert!(validate_rule_value(RuleType::RuleSetUrl, "https://e.com/a.srs").is_ok());
        assert!(validate_rule_value(RuleType::RuleSetUrl, "http://e.com/a.srs").is_err());
    }

    #[test]
    fn allows_spaces_in_ssids_and_process_paths() {
        assert!(validate_rule_value(RuleType::WifiSsid, "Home Network").is_ok());
        assert!(validate_rule_value(RuleType::ProcessPath, "/opt/My App/bin").is_ok());
    }
}
