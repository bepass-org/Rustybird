use anyhow::Result;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};

use crate::config::profile::ProfileStore;
use crate::config::profile_store;
use crate::config::settings::AppSettings;
use crate::core::config_builder::{BuiltConfig, PROXY_SELECTOR_TAG, SingboxConfigBuilder};
use crate::core::rule_sets;
use crate::core::runner::{CoreRunner, needs_elevation};
use crate::core::stats::ClashApiClient;
use crate::network::gnome_proxy::GnomeProxyManager;
use crate::parser::subscription::fetch_subscription;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppEvent {
    ProfilesChanged,
    ConnectionStateChanged,
    SettingsChanged,
}

#[derive(Clone)]
pub struct AppContext {
    pub settings: Arc<RwLock<AppSettings>>,
    pub profiles: Arc<RwLock<ProfileStore>>,
    pub runner: Arc<CoreRunner>,
    pub event_tx: broadcast::Sender<AppEvent>,
}

impl AppContext {
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(64);
        Self {
            settings: Arc::new(RwLock::new(AppSettings::load())),
            profiles: Arc::new(RwLock::new(ProfileStore::load())),
            runner: Arc::new(CoreRunner::new()),
            event_tx,
        }
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<AppEvent> {
        self.event_tx.subscribe()
    }

    pub fn notify(&self, event: AppEvent) {
        let _ = self.event_tx.send(event);
    }

    pub async fn clash_client(&self) -> ClashApiClient {
        let settings = self.settings.read().await;
        ClashApiClient::new(settings.clash_api_port, &settings.clash_api_secret)
    }

    pub async fn active_profile_name(&self) -> Option<String> {
        let settings = self.settings.read().await;
        let id = settings.active_profile_id.as_deref()?;
        self.profiles
            .read()
            .await
            .config_profile(id)
            .map(|profile| profile.name.clone())
    }

    fn build_config(settings: &AppSettings, profiles: &ProfileStore) -> Result<BuiltConfig> {
        let elevated = needs_elevation(settings);
        match settings.active_profile_id.as_deref() {
            Some(id) if profiles.config_profile(id).is_some() => {
                let content = profile_store::read_profile_content(id)?;
                SingboxConfigBuilder::build_from_profile(settings, &content, elevated)
            }
            _ => SingboxConfigBuilder::build_with_privileges(settings, profiles, elevated),
        }
    }

    pub async fn validate_current_config(&self) -> Result<BuiltConfig> {
        let settings = self.settings.read().await.clone();
        let profiles = self.profiles.read().await.clone();
        let built = Self::build_config(&settings, &profiles)?;
        check_with_core(&settings.singbox_path, &built.value).await?;
        Ok(built)
    }

    pub async fn toggle_connect(&self) -> Result<bool, String> {
        if self.runner.is_running() {
            self.disconnect().await?;
            Ok(false)
        } else {
            self.connect().await?;
            Ok(true)
        }
    }

    pub async fn connect(&self) -> Result<(), String> {
        let settings = self.settings.read().await.clone();
        let profiles = self.profiles.read().await.clone();

        let uses_profile = settings
            .active_profile_id
            .as_deref()
            .is_some_and(|id| profiles.config_profile(id).is_some());

        if !uses_profile && profiles.nodes.is_empty() {
            return Err("Add a proxy node, a subscription or a profile first".to_string());
        }

        if !uses_profile {
            self.prepare_rule_sets(&settings, &profiles).await;
        }

        let built = Self::build_config(&settings, &profiles).map_err(|e| e.to_string())?;
        self.runner
            .start(&settings, built)
            .await
            .map_err(|e| e.to_string())?;

        if !uses_profile {
            self.enforce_active_selection(&profiles).await;
        }
        self.apply_system_proxy(&settings, true);
        self.notify(AppEvent::ConnectionStateChanged);
        Ok(())
    }

    pub async fn prepare_rule_sets(&self, settings: &AppSettings, profiles: &ProfileStore) {
        let tags = rule_sets::required_tags(settings, profiles);
        if tags.is_empty() {
            return;
        }
        for (tag, error) in rule_sets::ensure_rule_sets(&tags).await {
            tracing::warn!(
                "rule-set {} unavailable, its rules are skipped: {}",
                tag,
                error
            );
        }
    }

    async fn enforce_active_selection(&self, profiles: &ProfileStore) {
        let Some(node) = profiles.get_active_node() else {
            return;
        };
        let Some(tag) = self.runner.outbound_tag_for(&node.id).await else {
            return;
        };
        if let Err(error) = self
            .clash_client()
            .await
            .select_outbound(PROXY_SELECTOR_TAG, &tag)
            .await
        {
            tracing::warn!("could not pin the selected outbound: {}", error);
        }
    }

    pub async fn disconnect(&self) -> Result<(), String> {
        let settings = self.settings.read().await.clone();
        self.runner.stop().await.map_err(|e| e.to_string())?;
        self.apply_system_proxy(&settings, false);
        self.notify(AppEvent::ConnectionStateChanged);
        Ok(())
    }

    pub async fn reload(&self) -> Result<(), String> {
        if !self.runner.is_running() {
            return Ok(());
        }
        let settings = self.settings.read().await.clone();
        let profiles = self.profiles.read().await.clone();

        let uses_profile = settings
            .active_profile_id
            .as_deref()
            .is_some_and(|id| profiles.config_profile(id).is_some());

        if !uses_profile {
            self.prepare_rule_sets(&settings, &profiles).await;
        }

        let built = Self::build_config(&settings, &profiles).map_err(|e| e.to_string())?;
        self.runner
            .restart(&settings, built)
            .await
            .map_err(|e| e.to_string())?;

        if !uses_profile {
            self.enforce_active_selection(&profiles).await;
        }
        self.apply_system_proxy(&settings, true);
        self.notify(AppEvent::ConnectionStateChanged);
        Ok(())
    }

    pub async fn select_node(&self, node_id: &str) -> Result<(), String> {
        {
            let mut profiles = self.profiles.write().await;
            profiles.set_active_node(node_id);
            profiles.save();
        }
        self.notify(AppEvent::ProfilesChanged);

        if !self.runner.is_running() {
            return Ok(());
        }

        match self.runner.outbound_tag_for(node_id).await {
            Some(tag) => self
                .clash_client()
                .await
                .select_outbound(PROXY_SELECTOR_TAG, &tag)
                .await
                .map_err(|e| e.to_string()),
            None => self.reload().await,
        }
    }

    pub async fn select_group_member(&self, group: &str, member: &str) -> Result<(), String> {
        self.clash_client()
            .await
            .select_outbound(group, member)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn test_group(&self, group: &str) -> Result<(), String> {
        let settings = self.settings.read().await.clone();
        self.clash_client()
            .await
            .test_group_delay(group, &settings.latency_test_url, 5000)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn probe_active_node(&self) -> Result<u32, String> {
        if !self.runner.is_running() {
            return Err("the core is not running".to_string());
        }
        let settings = self.settings.read().await.clone();
        let client = self.clash_client().await;

        let (uses_profile, active_node_id) = {
            let profiles = self.profiles.read().await;
            let uses_profile = settings
                .active_profile_id
                .as_deref()
                .is_some_and(|id| profiles.config_profile(id).is_some());
            (
                uses_profile,
                profiles.get_active_node().map(|node| node.id.clone()),
            )
        };

        if uses_profile {
            return client
                .test_delay(PROXY_SELECTOR_TAG, &settings.latency_test_url, 6000)
                .await
                .map_err(|e| e.to_string());
        }

        let node_id = active_node_id.ok_or_else(|| "no active node".to_string())?;

        let tag = self
            .runner
            .outbound_tag_for(&node_id)
            .await
            .ok_or_else(|| "the active node is not in the running config".to_string())?;

        client
            .test_delay(&tag, &settings.latency_test_url, 6000)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn set_proxy_mode(
        &self,
        mode: crate::config::settings::ProxyMode,
    ) -> Result<(), String> {
        {
            let mut settings = self.settings.write().await;
            if settings.proxy_mode == mode {
                return Ok(());
            }
            settings.proxy_mode = mode;
            settings.save();
        }
        self.notify(AppEvent::SettingsChanged);

        if !self.runner.is_running() {
            return Ok(());
        }

        self.clash_client()
            .await
            .set_mode(mode.clash_name())
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn set_system_proxy(&self, enabled: bool) -> Result<(), String> {
        let settings = {
            let mut settings = self.settings.write().await;
            settings.system_proxy_auto_toggle = enabled;
            settings.save();
            settings.clone()
        };

        if self.runner.is_running() {
            self.apply_system_proxy(&settings, enabled);
        }
        Ok(())
    }

    pub async fn select_config_profile(&self, id: Option<&str>) -> Result<(), String> {
        {
            let mut settings = self.settings.write().await;
            settings.active_profile_id = id.map(str::to_string);
            settings.save();
        }
        self.notify(AppEvent::SettingsChanged);
        self.reload().await
    }

    pub async fn update_due_subscriptions(&self) -> usize {
        let (fallback_hours, auto_update) = {
            let settings = self.settings.read().await;
            (settings.update_interval_hours, settings.auto_update_subscriptions)
        };
        if !auto_update {
            return 0;
        }

        let due: Vec<crate::config::profile::Subscription> = self
            .profiles
            .read()
            .await
            .subscriptions
            .iter()
            .filter(|sub| sub.is_due(fallback_hours))
            .cloned()
            .collect();

        let mut updated = 0;
        for subscription in due {
            match fetch_subscription(&subscription).await {
                Ok(result) => {
                    let mut profiles = self.profiles.write().await;
                    if let Some(stored) = profiles
                        .subscriptions
                        .iter_mut()
                        .find(|s| s.id == subscription.id)
                    {
                        stored.total_traffic = result.total_traffic;
                        stored.used_traffic = result.used_traffic;
                        stored.expire_time = result.expire_time;
                        stored.last_updated = Some(chrono::Utc::now());
                    }
                    profiles.replace_subscription_nodes(&subscription.id, result.nodes);
                    profiles.save();
                    updated += 1;
                }
                Err(error) => {
                    tracing::warn!(
                        "automatic update of subscription {} failed: {}",
                        subscription.name,
                        error
                    );
                }
            }
        }

        if updated > 0 {
            self.notify(AppEvent::ProfilesChanged);
            if let Err(error) = self.reload().await {
                tracing::warn!("reload after automatic update failed: {}", error);
            }
        }
        updated
    }

    pub async fn update_due_profiles(&self) -> usize {
        let due: Vec<crate::config::profile::ConfigProfile> = self
            .profiles
            .read()
            .await
            .config_profiles
            .iter()
            .filter(|profile| profile.is_due())
            .cloned()
            .collect();

        let mut updated = 0;
        let mut active_changed = false;
        let active_id = self.settings.read().await.active_profile_id.clone();

        for profile in due {
            match profile_store::fetch_remote_profile(&profile).await {
                Ok(content) => {
                    if let Err(error) = profile_store::write_profile_content(&profile.id, &content) {
                        tracing::warn!("could not store profile {}: {}", profile.name, error);
                        continue;
                    }
                    let mut profiles = self.profiles.write().await;
                    if let Some(stored) = profiles
                        .config_profiles
                        .iter_mut()
                        .find(|p| p.id == profile.id)
                    {
                        stored.last_updated = Some(chrono::Utc::now());
                    }
                    profiles.save();
                    updated += 1;
                    if active_id.as_deref() == Some(profile.id.as_str()) {
                        active_changed = true;
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        "automatic update of profile {} failed: {}",
                        profile.name,
                        error
                    );
                }
            }
        }

        if updated > 0 {
            self.notify(AppEvent::ProfilesChanged);
            if active_changed {
                if let Err(error) = self.reload().await {
                    tracing::warn!("reload after a profile update failed: {}", error);
                }
            }
        }
        updated
    }

    fn apply_system_proxy(&self, settings: &AppSettings, connecting: bool) {
        let result = if connecting && settings.system_proxy_auto_toggle && !settings.tun_mode {
            GnomeProxyManager::enable(settings.mixed_port)
        } else if !connecting || !settings.system_proxy_auto_toggle {
            GnomeProxyManager::disable()
        } else {
            Ok(())
        };

        if let Err(e) = result {
            tracing::warn!("system proxy update failed: {}", e);
        }
    }
}

async fn check_with_core(binary: &str, config: &serde_json::Value) -> Result<()> {
    let binary = binary.trim();
    if binary.is_empty() || !std::path::Path::new(binary).is_file() {
        return Ok(());
    }

    let paths = crate::config::paths::AppPaths::get();
    let directory = paths
        .cache_dir
        .join("check")
        .join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir_all(&directory)?;
    let path = directory.join("config.json");
    crate::config::settings::write_private_bytes(&path, &serde_json::to_vec_pretty(config)?);

    let output = tokio::process::Command::new(binary)
        .arg("check")
        .arg("-c")
        .arg(&path)
        .arg("-D")
        .arg(&directory)
        .output()
        .await?;
    let _ = std::fs::remove_dir_all(&directory);

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = stderr
        .lines()
        .chain(stdout.lines())
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| crate::core::runner::strip_ansi(line))
        .unwrap_or_else(|| "sing-box rejected the configuration".to_string());
    Err(anyhow::anyhow!("{}", detail))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn singbox_binary() -> Option<String> {
        std::env::var("RUSTYBIRD_SINGBOX_BIN")
            .ok()
            .filter(|path| std::path::Path::new(path).is_file())
    }

    #[tokio::test]
    async fn a_missing_binary_skips_the_check() {
        let config = json!({ "outbounds": [] });
        assert!(check_with_core("", &config).await.is_ok());
        assert!(
            check_with_core("/nonexistent/sing-box", &config)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn the_core_accepts_a_valid_configuration() {
        let Some(binary) = singbox_binary() else {
            return;
        };
        let config = json!({
            "outbounds": [{ "type": "direct", "tag": "direct" }],
            "route": { "final": "direct" }
        });
        check_with_core(&binary, &config)
            .await
            .expect("the core rejected a valid configuration");
    }

    #[tokio::test]
    async fn concurrent_checks_do_not_clobber_each_other() {
        let Some(binary) = singbox_binary() else {
            return;
        };
        let config = json!({
            "outbounds": [{ "type": "direct", "tag": "direct" }],
            "route": { "final": "direct" }
        });
        let checks = (0..4).map(|_| check_with_core(&binary, &config));
        for result in futures_join_all(checks).await {
            result.expect("a concurrent check failed");
        }
    }

    async fn futures_join_all<F>(futures: impl IntoIterator<Item = F>) -> Vec<F::Output>
    where
        F: std::future::Future,
    {
        let handles: Vec<_> = futures.into_iter().collect();
        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            results.push(handle.await);
        }
        results
    }

    #[tokio::test]
    async fn the_core_reports_a_readable_error_for_a_broken_configuration() {
        let Some(binary) = singbox_binary() else {
            return;
        };
        let config = json!({
            "outbounds": [{
                "type": "vless",
                "tag": "bad",
                "server": "1.2.3.4",
                "server_port": 443,
                "uuid": "not-a-uuid",
                "nonsense_field": true
            }]
        });
        let error = check_with_core(&binary, &config)
            .await
            .expect_err("the core accepted a broken configuration");
        let message = error.to_string();
        assert!(!message.is_empty());
        assert!(!message.contains('\u{1b}'), "the message still has colour codes");
    }
}
