use gtk4::prelude::*;
use gtk4::{Box, Button, Label, Orientation, Spinner};

pub struct PingBadge {
    pub container: Box,
    label: Label,
    spinner: Spinner,
    button: Button,
}

impl PingBadge {
    pub fn new() -> Self {
        let container = Box::builder()
            .orientation(Orientation::Horizontal)
            .spacing(4)
            .valign(gtk4::Align::Center)
            .build();

        let spinner = Spinner::builder().spinning(false).visible(false).build();

        let label = Label::builder()
            .label("\u{2014}")
            .width_chars(7)
            .xalign(1.0)
            .css_classes(vec!["dim-label".to_string(), "caption".to_string()])
            .build();

        let button = Button::builder()
            .icon_name("network-transmit-receive-symbolic")
            .has_frame(false)
            .tooltip_text("Test latency through the proxy")
            .valign(gtk4::Align::Center)
            .build();

        container.append(&spinner);
        container.append(&label);
        container.append(&button);

        Self {
            container,
            label,
            spinner,
            button,
        }
    }

    pub fn set_ping(&self, latency_ms: Option<u32>) {
        self.spinner.set_spinning(false);
        self.spinner.set_visible(false);
        self.label.set_visible(true);

        for class in ["success", "warning", "error", "dim-label"] {
            self.label.remove_css_class(class);
        }

        match latency_ms {
            Some(ms) => {
                self.label.set_text(&format!("{} ms", ms));
                let class = if ms < 200 {
                    "success"
                } else if ms < 500 {
                    "warning"
                } else {
                    "error"
                };
                self.label.add_css_class(class);
            }
            None => {
                self.label.set_text("failed");
                self.label.add_css_class("error");
            }
        }
    }

    pub fn reset(&self) {
        self.spinner.set_spinning(false);
        self.spinner.set_visible(false);
        self.label.set_visible(true);
        for class in ["success", "warning", "error"] {
            self.label.remove_css_class(class);
        }
        self.label.add_css_class("dim-label");
        self.label.set_text("\u{2014}");
    }

    pub fn set_loading(&self) {
        self.label.set_visible(false);
        self.spinner.set_visible(true);
        self.spinner.set_spinning(true);
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.button.set_sensitive(enabled);
        self.button.set_tooltip_text(Some(if enabled {
            "Test latency through the proxy"
        } else {
            "Connect first to measure real latency"
        }));
    }

    pub fn on_click<F: Fn() + 'static>(&self, callback: F) {
        self.button.connect_clicked(move |_| callback());
    }
}
