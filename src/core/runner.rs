use anyhow::{Context, Result, anyhow};
use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, broadcast};
use tracing::{error, info, warn};

use crate::config::paths::AppPaths;
use crate::config::settings::{AppSettings, write_private_bytes};
use crate::core::config_builder::BuiltConfig;

const STARTUP_PROBE_TIMEOUT: Duration = Duration::from_secs(12);
const GRACEFUL_STOP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreState {
    Stopped,
    Starting,
    Running,
    Error(String),
}

struct RunningCore {
    child: Child,
    pid: i32,
    elevated: bool,
}

pub struct CoreRunner {
    state: Arc<Mutex<CoreState>>,
    current: Arc<Mutex<Option<RunningCore>>>,
    node_tags: Arc<Mutex<HashMap<String, String>>>,
    log_sender: broadcast::Sender<String>,
    is_running: Arc<AtomicBool>,
    start_lock: Arc<Mutex<()>>,
}

impl CoreRunner {
    pub fn new() -> Self {
        let (log_sender, _) = broadcast::channel(1000);
        Self {
            state: Arc::new(Mutex::new(CoreState::Stopped)),
            current: Arc::new(Mutex::new(None)),
            node_tags: Arc::new(Mutex::new(HashMap::new())),
            log_sender,
            is_running: Arc::new(AtomicBool::new(false)),
            start_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn subscribe_logs(&self) -> broadcast::Receiver<String> {
        self.log_sender.subscribe()
    }

    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }

    pub async fn outbound_tag_for(&self, node_id: &str) -> Option<String> {
        self.node_tags.lock().await.get(node_id).cloned()
    }

    pub async fn start(&self, settings: &AppSettings, built: BuiltConfig) -> Result<()> {
        let _guard = self.start_lock.lock().await;

        if self.is_running() {
            return Ok(());
        }
        *self.state.lock().await = CoreState::Starting;

        match self.spawn(settings, built).await {
            Ok(()) => Ok(()),
            Err(e) => {
                *self.state.lock().await = CoreState::Error(e.to_string());
                self.is_running.store(false, Ordering::SeqCst);
                Err(e)
            }
        }
    }

    async fn spawn(&self, settings: &AppSettings, built: BuiltConfig) -> Result<()> {
        let binary = settings.singbox_path.trim();
        if binary.is_empty() {
            return Err(anyhow!("sing-box binary path is not configured"));
        }
        if !std::path::Path::new(binary).is_file() {
            return Err(anyhow!(
                "sing-box binary not found at {}; set the correct path in Settings",
                binary
            ));
        }

        let elevated = needs_elevation(settings);
        let config_bytes = serde_json::to_vec_pretty(&built.value)?;

        let paths = AppPaths::get();
        let config_path = paths.singbox_runtime_config();
        write_private_bytes(&config_path, &config_bytes);

        info!(
            "Starting sing-box ({}), tun={}, nodes={}",
            binary,
            settings.tun_mode,
            built.node_tags.len()
        );

        let mut command = if elevated {
            let mut command = Command::new("pkexec");
            command.arg("--disable-internal-agent");
            command.arg(binary);
            command
        } else {
            Command::new(binary)
        };

        command
            .arg("run")
            .arg("-c")
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        if !elevated {
            unsafe {
                command.pre_exec(|| {
                    if libc::setpgid(0, 0) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }

        let mut child = command
            .spawn()
            .with_context(|| format!("failed to launch {}", binary))?;

        let pid = child
            .id()
            .ok_or_else(|| anyhow!("sing-box exited before it could be tracked"))?
            as i32;

        let mut startup_errors = Vec::new();
        let (error_tx, mut error_rx) = tokio::sync::mpsc::unbounded_channel::<String>();

        if let Some(stdout) = child.stdout.take() {
            self.pump_output(stdout, error_tx.clone());
        }
        if let Some(stderr) = child.stderr.take() {
            self.pump_output(stderr, error_tx);
        }

        let started_at = tokio::time::Instant::now();
        loop {
            if let Ok(Some(status)) = child.try_wait() {
                while let Ok(line) = error_rx.try_recv() {
                    startup_errors.push(line);
                }
                let detail = startup_errors
                    .iter()
                    .rev()
                    .find(|line| {
                        let lower = line.to_lowercase();
                        lower.contains("error") || lower.contains("fatal")
                    })
                    .cloned()
                    .unwrap_or_else(|| format!("sing-box exited with {}", status));
                return Err(anyhow!(clean_log_line(&detail)));
            }

            if self.probe_clash_api(settings).await {
                break;
            }

            if started_at.elapsed() > STARTUP_PROBE_TIMEOUT {
                let _ = child.start_kill();
                return Err(anyhow!(
                    "sing-box did not become ready within {} seconds",
                    STARTUP_PROBE_TIMEOUT.as_secs()
                ));
            }

            while let Ok(line) = error_rx.try_recv() {
                startup_errors.push(line);
                if startup_errors.len() > 50 {
                    startup_errors.remove(0);
                }
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }

        *self.node_tags.lock().await = built.node_tags.into_iter().collect();
        *self.current.lock().await = Some(RunningCore {
            child,
            pid,
            elevated,
        });
        self.is_running.store(true, Ordering::SeqCst);
        *self.state.lock().await = CoreState::Running;
        info!("sing-box is running (pid {})", pid);
        Ok(())
    }

    fn pump_output<R>(&self, reader: R, error_tx: tokio::sync::mpsc::UnboundedSender<String>)
    where
        R: tokio::io::AsyncRead + Unpin + Send + 'static,
    {
        let log_tx = self.log_sender.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let line = strip_ansi(&line);
                let _ = error_tx.send(line.clone());
                let _ = log_tx.send(line);
            }
        });
    }

    pub async fn memory_bytes(&self) -> Option<u64> {
        let guard = self.current.lock().await;
        let running = guard.as_ref()?;
        let pid = if running.elevated {
            first_child_pid(running.pid).unwrap_or(running.pid)
        } else {
            running.pid
        };
        resident_bytes(pid)
    }

    async fn probe_clash_api(&self, settings: &AppSettings) -> bool {
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_millis(700))
            .no_proxy()
            .build()
        {
            Ok(client) => client,
            Err(_) => return false,
        };

        client
            .get(format!(
                "http://127.0.0.1:{}/version",
                settings.clash_api_port
            ))
            .header(
                "Authorization",
                format!("Bearer {}", settings.clash_api_secret),
            )
            .send()
            .await
            .map(|response| response.status().is_success())
            .unwrap_or(false)
    }

    pub async fn stop(&self) -> Result<()> {
        let _guard = self.start_lock.lock().await;
        let running = self.current.lock().await.take();

        if let Some(mut running) = running {
            info!("Stopping sing-box (pid {})", running.pid);
            terminate(running.pid, running.elevated);

            let graceful = tokio::time::timeout(GRACEFUL_STOP_TIMEOUT, running.child.wait()).await;
            if graceful.is_err() {
                warn!("sing-box did not exit gracefully, sending SIGKILL");
                kill(running.pid, running.elevated);
                let _ = tokio::time::timeout(Duration::from_secs(3), running.child.wait()).await;
            }
        }

        self.node_tags.lock().await.clear();
        self.is_running.store(false, Ordering::SeqCst);
        *self.state.lock().await = CoreState::Stopped;
        Ok(())
    }

    pub async fn restart(&self, settings: &AppSettings, built: BuiltConfig) -> Result<()> {
        self.stop().await?;
        self.start(settings, built).await
    }

    pub async fn state(&self) -> CoreState {
        self.state.lock().await.clone()
    }
}

pub fn needs_elevation(settings: &AppSettings) -> bool {
    settings.tun_mode && unsafe { libc::geteuid() } != 0
}

pub fn strip_ansi(line: &str) -> String {
    let mut output = String::with_capacity(line.len());
    let mut characters = line.chars().peekable();
    while let Some(character) = characters.next() {
        if character != '\u{1b}' {
            output.push(character);
            continue;
        }
        match characters.peek() {
            Some('[') => {
                characters.next();
                for inner in characters.by_ref() {
                    if inner.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            Some(']') => {
                characters.next();
                while let Some(inner) = characters.next() {
                    if inner == '\u{7}' {
                        break;
                    }
                    if inner == '\u{1b}' && characters.peek() == Some(&'\\') {
                        characters.next();
                        break;
                    }
                }
            }
            _ => {
                characters.next();
            }
        }
    }
    output
}

fn resident_bytes(pid: i32) -> Option<u64> {
    let statm = std::fs::read_to_string(format!("/proc/{}/statm", pid)).ok()?;
    let resident_pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return None;
    }
    Some(resident_pages * page_size as u64)
}

fn first_child_pid(pid: i32) -> Option<i32> {
    let children =
        std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children")).ok()?;
    children.split_whitespace().next()?.parse().ok()
}

fn clean_log_line(line: &str) -> String {
    let trimmed = line.trim();
    match trimmed.split_once("ERROR ") {
        Some((_, rest)) => rest.trim().to_string(),
        None => trimmed.to_string(),
    }
}

fn terminate(pid: i32, elevated: bool) {
    if elevated {
        signal_elevated(pid, "TERM");
    } else {
        unsafe {
            libc::kill(-pid, libc::SIGTERM);
            libc::kill(pid, libc::SIGTERM);
        }
    }
}

fn kill(pid: i32, elevated: bool) {
    if elevated {
        signal_elevated(pid, "KILL");
    } else {
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
            libc::kill(pid, libc::SIGKILL);
        }
    }
}

fn signal_elevated(pid: i32, signal: &str) {
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    match std::process::Command::new("pkexec")
        .arg("--disable-internal-agent")
        .arg("/usr/bin/pkill")
        .arg(format!("-{}", signal))
        .arg("-P")
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(status) if status.success() => {}
        _ => error!(
            "could not signal the elevated sing-box child of pid {}; it may still be running",
            pid
        ),
    }
}

impl Drop for CoreRunner {
    fn drop(&mut self) {
        self.is_running.store(false, Ordering::SeqCst);
        if let Ok(mut guard) = self.current.try_lock() {
            if let Some(running) = guard.take() {
                terminate(running.pid, running.elevated);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_colour_codes_from_core_logs() {
        let raw = "\u{1b}[36mINFO\u{1b}[0m[0019] router: found process";
        assert_eq!(strip_ansi(raw), "INFO[0019] router: found process");
    }

    #[test]
    fn leaves_plain_lines_untouched() {
        let plain = "INFO[0019] inbound connection to 127.0.0.1:18080";
        assert_eq!(strip_ansi(plain), plain);
    }

    #[test]
    fn strips_operating_system_command_sequences() {
        let raw = "\u{1b}]0;title\u{7}payload";
        assert_eq!(strip_ansi(raw), "payload");
    }

    #[test]
    fn clean_log_line_keeps_the_message_after_the_level() {
        assert_eq!(
            clean_log_line("2026-01-01 ERROR start service: bad config"),
            "start service: bad config"
        );
        assert_eq!(clean_log_line("  plain message  "), "plain message");
    }

    #[test]
    fn resident_bytes_reads_our_own_process() {
        let pid = std::process::id() as i32;
        let bytes = resident_bytes(pid).expect("no resident size");
        assert!(bytes > 0);
        assert!(resident_bytes(-1).is_none());
    }

    #[test]
    fn elevation_follows_the_tun_setting() {
        let mut settings = AppSettings::default();
        settings.tun_mode = false;
        assert!(!needs_elevation(&settings));
    }
}
