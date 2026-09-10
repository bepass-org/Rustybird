use anyhow::{Result, anyhow};
use gio::prelude::*;
use gio::{Settings, SettingsSchemaSource};
use tracing::info;

const PROXY_SCHEMA: &str = "org.gnome.system.proxy";
const HTTP_SCHEMA: &str = "org.gnome.system.proxy.http";
const HTTPS_SCHEMA: &str = "org.gnome.system.proxy.https";
const SOCKS_SCHEMA: &str = "org.gnome.system.proxy.socks";

const IGNORED_HOSTS: &[&str] = &[
    "localhost",
    "127.0.0.0/8",
    "::1",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "fc00::/7",
    "fe80::/10",
];

pub struct GnomeProxyManager;

impl GnomeProxyManager {
    pub fn is_available() -> bool {
        SettingsSchemaSource::default()
            .and_then(|source| source.lookup(PROXY_SCHEMA, true))
            .is_some()
            && SettingsSchemaSource::default()
                .and_then(|source| source.lookup(SOCKS_SCHEMA, true))
                .is_some()
    }

    pub fn enable(mixed_port: u16) -> Result<()> {
        if !Self::is_available() {
            return Err(anyhow!("GNOME proxy schemas are not installed"));
        }

        let proxy = Settings::new(PROXY_SCHEMA);
        let http = Settings::new(HTTP_SCHEMA);
        let https = Settings::new(HTTPS_SCHEMA);
        let socks = Settings::new(SOCKS_SCHEMA);

        http.set_string("host", "127.0.0.1")?;
        http.set_int("port", mixed_port as i32)?;
        http.set_boolean("enabled", true)?;

        https.set_string("host", "127.0.0.1")?;
        https.set_int("port", mixed_port as i32)?;

        socks.set_string("host", "127.0.0.1")?;
        socks.set_int("port", mixed_port as i32)?;

        proxy.set_strv("ignore-hosts", IGNORED_HOSTS)?;
        proxy.set_string("mode", "manual")?;

        gio::Settings::sync();
        info!("GNOME system proxy pointed at 127.0.0.1:{}", mixed_port);
        Ok(())
    }

    pub fn disable() -> Result<()> {
        if !Self::is_available() {
            return Ok(());
        }

        let proxy = Settings::new(PROXY_SCHEMA);
        proxy.set_string("mode", "none")?;

        let http = Settings::new(HTTP_SCHEMA);
        http.set_boolean("enabled", false)?;

        gio::Settings::sync();
        info!("GNOME system proxy disabled");
        Ok(())
    }
}
