mod app;
mod config;
mod core;
#[cfg(test)]
mod e2e;
mod network;
mod parser;
mod ui;

use gio::prelude::*;
use gtk4::CssProvider;
use gtk4::gdk::Display;
use gtk4::glib;
use libadwaita as adw;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::app::AppContext;
use crate::config::settings::{AppSettings, ThemePreference};
use crate::ui::MainWindow;

const APP_ID: &str = "org.rustybird.RustyBird";

const APP_CSS: &str = "
.connect-button {
    border-radius: 14px;
    border: none;
    padding: 0 20px;
    min-height: 56px;
    box-shadow: 0 2px 8px alpha(@shade_color, 0.35);
    transition: box-shadow 180ms ease;
}

.connect-button:hover {
    box-shadow: 0 4px 14px alpha(@shade_color, 0.5);
}

.connect-button:active {
    box-shadow: inset 0 2px 6px alpha(@shade_color, 0.5);
}

.connect-button:disabled {
    opacity: 0.6;
}

.connect-label {
    font-size: 15px;
    font-weight: 700;
    letter-spacing: 0.3px;
}

.power-off {
    background-image: linear-gradient(180deg, @accent_bg_color 0%, shade(@accent_bg_color, 0.88) 100%);
    color: @accent_fg_color;
}

.power-busy {
    background-image: linear-gradient(180deg, @warning_bg_color 0%, shade(@warning_bg_color, 0.88) 100%);
    color: @warning_fg_color;
}

.power-on {
    background-image: linear-gradient(180deg, @success_bg_color 0%, shade(@success_bg_color, 0.88) 100%);
    color: @success_fg_color;
}

.power-fail {
    background-image: linear-gradient(180deg, @error_bg_color 0%, shade(@error_bg_color, 0.88) 100%);
    color: @error_fg_color;
}

.status-pill {
    border-radius: 9999px;
    padding: 5px 14px;
    font-size: 11px;
    font-weight: 800;
    letter-spacing: 1px;
}

.pill-off {
    background-color: alpha(@window_fg_color, 0.08);
    color: alpha(@window_fg_color, 0.65);
}

.pill-busy {
    background-color: alpha(@warning_color, 0.18);
    color: @warning_color;
}

.pill-on {
    background-color: alpha(@success_color, 0.18);
    color: @success_color;
}

.pill-fail {
    background-color: alpha(@error_color, 0.18);
    color: @error_color;
}

.node-chip {
    border-radius: 12px;
    padding: 10px 16px;
    background-color: alpha(@window_fg_color, 0.05);
    transition: background-color 150ms ease;
}

.node-chip:hover {
    background-color: alpha(@window_fg_color, 0.1);
}
";

const START_MINIMIZED_FLAG: &str = "--minimized";

fn main() -> glib::ExitCode {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("rustybird-worker")
        .build()
        .expect("failed to initialise the Tokio runtime");
    let _guard = runtime.enter();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("warn,rustybird=info")),
        )
        .init();

    info!("RustyBird {} starting", env!("CARGO_PKG_VERSION"));

    let arguments: Vec<String> = std::env::args().collect();
    let start_minimized = arguments.iter().any(|arg| arg == START_MINIMIZED_FLAG);

    let application = adw::Application::builder()
        .application_id(APP_ID)
        .flags(gio::ApplicationFlags::HANDLES_COMMAND_LINE)
        .build();

    application.connect_startup(|_| {
        load_css();
        register_icons();
    });

    let app_ctx = AppContext::new();
    let window = std::rc::Rc::new(std::cell::RefCell::new(
        None::<std::rc::Rc<MainWindow>>,
    ));
    let hold_guard = std::rc::Rc::new(std::cell::RefCell::new(
        None::<gio::ApplicationHoldGuard>,
    ));

    let window_for_activate = window.clone();
    application.connect_activate(move |application| {
        if let Some(existing) = window_for_activate.borrow().as_ref() {
            existing.present();
            return;
        }
        let settings = AppSettings::load();
        apply_theme(settings.theme);
        let main_window = MainWindow::new(application, app_ctx.clone());
        let hidden = start_minimized && settings.start_hidden;
        main_window.present_unless_hidden(hidden);
        if hidden {
            *hold_guard.borrow_mut() = Some(application.hold());
        }
        *window_for_activate.borrow_mut() = Some(main_window);
    });

    application.connect_command_line(|application, _| {
        application.activate();
        0
    });

    application.run_with_args::<String>(&[])
}

fn register_icons() {
    let Some(display) = Display::default() else {
        return;
    };
    let theme = gtk4::IconTheme::for_display(&display);
    if let Ok(dir) = std::env::var("RUSTYBIRD_ICON_DIR") {
        theme.add_search_path(dir);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(root) = exe.parent().and_then(|p| p.parent()).and_then(|p| p.parent()) {
            let bundled = root.join("data/icons");
            if bundled.is_dir() {
                theme.add_search_path(bundled);
            }
        }
    }
}

fn load_css() {
    let provider = CssProvider::new();
    provider.load_from_string(APP_CSS);

    if let Some(display) = Display::default() {
        gtk4::style_context_add_provider_for_display(
            &display,
            &provider,
            gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    }
}

pub fn apply_theme(theme: ThemePreference) {
    let scheme = match theme {
        ThemePreference::System => adw::ColorScheme::Default,
        ThemePreference::Light => adw::ColorScheme::ForceLight,
        ThemePreference::Dark => adw::ColorScheme::ForceDark,
    };
    adw::StyleManager::default().set_color_scheme(scheme);
}
