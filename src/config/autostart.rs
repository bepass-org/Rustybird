use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;

const DESKTOP_FILE_NAME: &str = "org.rustybird.RustyBird.desktop";

fn autostart_dir() -> Option<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(value) if !value.is_empty() => PathBuf::from(value),
        _ => PathBuf::from(std::env::var_os("HOME")?).join(".config"),
    };
    Some(base.join("autostart"))
}

pub fn autostart_file() -> Option<PathBuf> {
    Some(autostart_dir()?.join(DESKTOP_FILE_NAME))
}

pub fn is_enabled() -> bool {
    autostart_file()
        .map(|path| path.is_file())
        .unwrap_or(false)
}

pub fn desktop_entry(executable: &str, minimized: bool) -> String {
    let arguments = if minimized { " --minimized" } else { "" };
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=RustyBird\n\
         Comment=Start the RustyBird proxy client when you log in\n\
         Exec={}{}\n\
         Icon=org.rustybird.RustyBird\n\
         Terminal=false\n\
         Categories=Network;Security;\n\
         X-GNOME-Autostart-enabled=true\n",
        executable, arguments
    )
}

pub fn set_enabled(enabled: bool, minimized: bool) -> Result<()> {
    let path = autostart_file().context("could not determine the autostart directory")?;
    if !enabled {
        if path.is_file() {
            fs::remove_file(&path).with_context(|| format!("failed to remove {:?}", path))?;
        }
        return Ok(());
    }

    let executable = std::env::current_exe()
        .map(|exe| exe.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "rustybird".to_string());

    let parent = path.parent().context("invalid autostart path")?;
    fs::create_dir_all(parent).with_context(|| format!("failed to create {:?}", parent))?;
    fs::write(&path, desktop_entry(&executable, minimized))
        .with_context(|| format!("failed to write {:?}", path))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_entry_contains_the_executable_and_flag() {
        let entry = desktop_entry("/usr/bin/rustybird", true);
        assert!(entry.contains("Exec=/usr/bin/rustybird --minimized"));
        assert!(entry.starts_with("[Desktop Entry]"));
        assert!(entry.contains("X-GNOME-Autostart-enabled=true"));

        let plain = desktop_entry("/usr/bin/rustybird", false);
        assert!(plain.contains("Exec=/usr/bin/rustybird\n"));
    }

    #[test]
    fn autostart_path_follows_xdg_config_home() {
        let path = autostart_file().expect("no autostart path");
        assert!(path.ends_with("autostart/org.rustybird.RustyBird.desktop"));
    }
}
