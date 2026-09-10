use gtk4::prelude::*;
use gtk4::{Box, Button, CheckButton, Image, Label, Orientation};
use libadwaita as adw;
use libadwaita::prelude::*;
use std::sync::Arc;

use crate::parser::node::ProxyNode;
use crate::ui::widgets::ping_badge::PingBadge;

pub struct NodeRow {
    pub row: adw::ActionRow,
    pub ping_badge: Arc<PingBadge>,
    pub remove_button: Button,
    pub share_button: Button,
    pub edit_button: Button,
    check_button: CheckButton,
    active_icon: Image,
}

impl NodeRow {
    pub fn new(node: &ProxyNode, is_active: bool) -> Self {
        let mut descriptors = vec![node.protocol.to_string()];
        if node.transport.transport_type != crate::parser::node::TransportType::Tcp {
            descriptors.push(node.transport.transport_type.label().to_string());
        }
        if node.tls.reality.is_some() {
            descriptors.push("REALITY".to_string());
        } else if node.tls.enabled {
            descriptors.push("TLS".to_string());
        }
        if node.multiplex.as_ref().map(|m| m.enabled).unwrap_or(false) {
            descriptors.push("mux".to_string());
        }

        let row = adw::ActionRow::builder()
            .title(glib_escape(&node.name))
            .subtitle(glib_escape(&format!(
                "{}:{} \u{2022} {}",
                node.server,
                node.port,
                descriptors.join(" \u{00B7} ")
            )))
            .activatable(true)
            .build();

        let prefix_box = Box::builder()
            .orientation(Orientation::Horizontal)
            .spacing(10)
            .valign(gtk4::Align::Center)
            .build();

        let check_button = CheckButton::builder()
            .active(is_active)
            .can_target(false)
            .can_focus(false)
            .build();

        let flag_label = Label::builder()
            .label(node.flag_emoji())
            .css_classes(vec!["title-3".to_string()])
            .build();

        prefix_box.append(&check_button);
        prefix_box.append(&flag_label);
        row.add_prefix(&prefix_box);

        let suffix_box = Box::builder()
            .orientation(Orientation::Horizontal)
            .spacing(6)
            .valign(gtk4::Align::Center)
            .build();

        let active_icon = Image::builder()
            .icon_name("object-select-symbolic")
            .css_classes(vec!["accent".to_string()])
            .visible(is_active)
            .build();

        let ping_badge = Arc::new(PingBadge::new());
        match node.latency_ms {
            Some(latency) => ping_badge.set_ping(Some(latency)),
            None => ping_badge.reset(),
        }

        let edit_button = Button::builder()
            .icon_name("document-edit-symbolic")
            .has_frame(false)
            .tooltip_text("Edit this node")
            .css_classes(vec!["flat".to_string()])
            .valign(gtk4::Align::Center)
            .build();

        let share_button = Button::builder()
            .icon_name("edit-copy-symbolic")
            .has_frame(false)
            .tooltip_text("Copy a share link for this node")
            .css_classes(vec!["flat".to_string()])
            .valign(gtk4::Align::Center)
            .build();

        let remove_button = Button::builder()
            .icon_name("user-trash-symbolic")
            .has_frame(false)
            .tooltip_text("Remove this node")
            .css_classes(vec!["flat".to_string()])
            .valign(gtk4::Align::Center)
            .build();

        suffix_box.append(&ping_badge.container);
        suffix_box.append(&active_icon);
        suffix_box.append(&edit_button);
        suffix_box.append(&share_button);
        suffix_box.append(&remove_button);
        row.add_suffix(&suffix_box);

        let node_row = Self {
            row,
            ping_badge,
            remove_button,
            share_button,
            edit_button,
            check_button,
            active_icon,
        };
        node_row.set_active(is_active);
        node_row
    }

    pub fn set_active(&self, active: bool) {
        self.check_button.set_active(active);
        self.active_icon.set_visible(active);
        if active {
            self.row.add_css_class("accent");
        } else {
            self.row.remove_css_class("accent");
        }
    }

    pub fn matches(&self, query: &str) -> bool {
        if query.is_empty() {
            return true;
        }
        let title = self.row.title().to_lowercase();
        let subtitle = self
            .row
            .subtitle()
            .map(|s| s.to_lowercase())
            .unwrap_or_default();
        title.contains(query) || subtitle.contains(query)
    }
}

pub fn glib_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
