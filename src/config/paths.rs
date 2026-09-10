use directories::ProjectDirs;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

pub struct AppPaths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub cache_dir: PathBuf,
}

impl AppPaths {
    pub fn get() -> Self {
        let proj_dirs = ProjectDirs::from("org", "rustybird", "RustyBird")
            .expect("could not determine XDG project directories");

        let config_dir = proj_dirs.config_dir().to_path_buf();
        let data_dir = proj_dirs.data_dir().to_path_buf();
        let cache_dir = proj_dirs.cache_dir().to_path_buf();

        for dir in [&config_dir, &data_dir, &cache_dir] {
            if let Err(e) = fs::create_dir_all(dir) {
                tracing::error!("Failed to create {:?}: {}", dir, e);
            }
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
        }

        Self {
            config_dir,
            data_dir,
            cache_dir,
        }
    }

    pub fn settings_file(&self) -> PathBuf {
        self.config_dir.join("settings.json")
    }

    pub fn profiles_file(&self) -> PathBuf {
        self.data_dir.join("profiles.json")
    }

    pub fn singbox_runtime_config(&self) -> PathBuf {
        self.config_dir.join("singbox_active.json")
    }

    pub fn singbox_cache_file(&self, elevated: bool) -> PathBuf {
        if elevated {
            self.cache_dir.join("singbox_cache_root.db")
        } else {
            self.cache_dir.join("singbox_cache.db")
        }
    }

    pub fn config_profile_dir(&self) -> PathBuf {
        let dir = self.data_dir.join("config-profiles");
        let _ = fs::create_dir_all(&dir);
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        dir
    }

    pub fn config_profile_file(&self, id: &str) -> PathBuf {
        let safe: String = id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
            .collect();
        self.config_profile_dir().join(format!("{}.json", safe))
    }

    pub fn rule_set_dir(&self) -> PathBuf {
        let dir = self.data_dir.join("rule-sets");
        let _ = fs::create_dir_all(&dir);
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        dir
    }

    pub fn rule_set_file(&self, tag: &str) -> PathBuf {
        self.rule_set_dir().join(format!("{}.srs", tag))
    }
}
