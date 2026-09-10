use anyhow::{Result, anyhow};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
pub struct ConnectionInfo {
    pub id: String,
    #[serde(default)]
    pub metadata: ConnectionMetadata,
    #[serde(default)]
    pub upload: u64,
    #[serde(default)]
    pub download: u64,
    #[serde(default)]
    pub chains: Vec<String>,
    #[serde(default)]
    pub start: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ConnectionMetadata {
    #[serde(default)]
    pub network: String,
    #[serde(rename = "destinationIP", default)]
    pub destination_ip: String,
    #[serde(rename = "sourcePort", default)]
    pub source_port: String,
    #[serde(rename = "destinationPort", default)]
    pub destination_port: String,
    #[serde(default)]
    pub host: String,
}

impl ConnectionMetadata {
    pub fn display_host(&self) -> String {
        if !self.host.is_empty() {
            return self.host.clone();
        }
        if !self.destination_ip.is_empty() {
            return self.destination_ip.clone();
        }
        "unknown".to_string()
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ConnectionsResponse {
    #[serde(rename = "downloadTotal", default)]
    pub download_total: u64,
    #[serde(rename = "uploadTotal", default)]
    pub upload_total: u64,
    #[serde(default)]
    pub connections: Vec<ConnectionInfo>,
}

#[derive(Debug, Clone, Deserialize)]
struct DelayResponse {
    delay: u32,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProxyEntry {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub now: Option<String>,
    #[serde(default)]
    pub all: Vec<String>,
    #[serde(default)]
    pub history: Vec<DelayHistory>,
    #[serde(default)]
    pub udp: bool,
}

impl ProxyEntry {
    pub fn is_group(&self) -> bool {
        matches!(
            self.kind.to_ascii_lowercase().as_str(),
            "selector" | "urltest" | "fallback" | "loadbalance" | "relay"
        )
    }

    pub fn is_selectable(&self) -> bool {
        self.kind.eq_ignore_ascii_case("selector")
    }

    pub fn latency_ms(&self) -> Option<u32> {
        self.history.last().map(|entry| entry.delay).filter(|d| *d > 0)
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DelayHistory {
    #[serde(default)]
    pub delay: u32,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProxiesResponse {
    #[serde(default)]
    pub proxies: std::collections::HashMap<String, ProxyEntry>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct CoreVersion {
    #[serde(default)]
    pub version: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IpGeoInfo {
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub city: String,
    #[serde(default)]
    pub country_name: String,
    #[serde(default)]
    pub org: String,
    #[serde(default)]
    error: bool,
    #[serde(default)]
    reason: String,
}

impl IpGeoInfo {
    pub fn location(&self) -> String {
        let mut parts = Vec::new();
        if !self.city.is_empty() {
            parts.push(self.city.as_str());
        }
        if !self.country_name.is_empty() {
            parts.push(self.country_name.as_str());
        }
        let location = if parts.is_empty() {
            "Unknown location".to_string()
        } else {
            parts.join(", ")
        };
        if self.org.is_empty() {
            location
        } else {
            format!("{} \u{2022} {}", location, self.org)
        }
    }
}

pub async fn check_outbound_ip(proxy_port: Option<u16>) -> Result<IpGeoInfo> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .user_agent("RustyBird");

    builder = match proxy_port {
        Some(port) => {
            let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{}", port))?;
            builder.proxy(proxy)
        }
        None => builder.no_proxy(),
    };

    let response = builder
        .build()?
        .get("https://ipapi.co/json/")
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(anyhow!("geolocation lookup returned {}", response.status()));
    }

    let info = response.json::<IpGeoInfo>().await?;
    if info.error {
        let reason = if info.reason.is_empty() {
            "rejected the lookup".to_string()
        } else {
            info.reason.clone()
        };
        return Err(anyhow!("geolocation service {}", reason));
    }
    if info.ip.is_empty() {
        return Err(anyhow!("geolocation service returned no address"));
    }
    Ok(info)
}

#[derive(Clone)]
pub struct ClashApiClient {
    base_url: String,
    client: reqwest::Client,
    secret: String,
}

impl ClashApiClient {
    pub fn new(port: u16, secret: &str) -> Self {
        Self {
            base_url: format!("http://127.0.0.1:{}", port),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .no_proxy()
                .build()
                .unwrap_or_default(),
            secret: secret.to_string(),
        }
    }

    fn authorize(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if self.secret.is_empty() {
            request
        } else {
            request.header("Authorization", format!("Bearer {}", self.secret))
        }
    }

    pub async fn get_connections(&self) -> Result<ConnectionsResponse> {
        let request = self.client.get(format!("{}/connections", self.base_url));
        let response = self.authorize(request).send().await?;
        if !response.status().is_success() {
            return Err(anyhow!("clash api returned {}", response.status()));
        }
        Ok(response.json::<ConnectionsResponse>().await?)
    }

    pub async fn close_connection(&self, id: &str) -> Result<()> {
        let encoded = utf8_percent_encode(id, NON_ALPHANUMERIC).to_string();
        let request = self
            .client
            .delete(format!("{}/connections/{}", self.base_url, encoded));
        self.authorize(request).send().await?;
        Ok(())
    }

    pub async fn close_all_connections(&self) -> Result<()> {
        let request = self.client.delete(format!("{}/connections", self.base_url));
        self.authorize(request).send().await?;
        Ok(())
    }

    pub async fn set_mode(&self, mode: &str) -> Result<()> {
        let request = self
            .client
            .patch(format!("{}/configs", self.base_url))
            .json(&serde_json::json!({ "mode": mode }));
        let response = self.authorize(request).send().await?;
        if !response.status().is_success() {
            return Err(anyhow!("failed to switch mode: {}", response.status()));
        }
        Ok(())
    }

    pub async fn select_outbound(&self, selector: &str, outbound: &str) -> Result<()> {
        let encoded = utf8_percent_encode(selector, NON_ALPHANUMERIC).to_string();
        let request = self
            .client
            .put(format!("{}/proxies/{}", self.base_url, encoded))
            .json(&serde_json::json!({ "name": outbound }));
        let response = self.authorize(request).send().await?;
        if !response.status().is_success() {
            return Err(anyhow!(
                "failed to select outbound {}: {}",
                outbound,
                response.status()
            ));
        }
        Ok(())
    }

    pub async fn get_version(&self) -> Result<CoreVersion> {
        let request = self.client.get(format!("{}/version", self.base_url));
        let response = self.authorize(request).send().await?;
        if !response.status().is_success() {
            return Err(anyhow!("clash api returned {}", response.status()));
        }
        Ok(response.json::<CoreVersion>().await?)
    }

    pub async fn get_proxies(&self) -> Result<ProxiesResponse> {
        let request = self.client.get(format!("{}/proxies", self.base_url));
        let response = self.authorize(request).send().await?;
        if !response.status().is_success() {
            return Err(anyhow!("clash api returned {}", response.status()));
        }
        Ok(response.json::<ProxiesResponse>().await?)
    }

    pub async fn get_mode(&self) -> Result<String> {
        let request = self.client.get(format!("{}/configs", self.base_url));
        let response = self.authorize(request).send().await?;
        if !response.status().is_success() {
            return Err(anyhow!("clash api returned {}", response.status()));
        }
        let value = response.json::<serde_json::Value>().await?;
        Ok(value
            .get("mode")
            .and_then(|mode| mode.as_str())
            .unwrap_or_default()
            .to_string())
    }

    pub async fn test_group_delay(
        &self,
        group: &str,
        test_url: &str,
        timeout_ms: u32,
    ) -> Result<()> {
        let encoded_name = utf8_percent_encode(group, NON_ALPHANUMERIC).to_string();
        let encoded_url = utf8_percent_encode(test_url, NON_ALPHANUMERIC).to_string();
        let request = self
            .client
            .get(format!(
                "{}/group/{}/delay?timeout={}&url={}",
                self.base_url, encoded_name, timeout_ms, encoded_url
            ))
            .timeout(Duration::from_millis(timeout_ms as u64 + 5000));
        let response = self.authorize(request).send().await?;
        if !response.status().is_success() {
            return Err(anyhow!("group latency test failed: {}", response.status()));
        }
        Ok(())
    }

    pub async fn test_delay(&self, outbound: &str, test_url: &str, timeout_ms: u32) -> Result<u32> {
        let encoded_name = utf8_percent_encode(outbound, NON_ALPHANUMERIC).to_string();
        let encoded_url = utf8_percent_encode(test_url, NON_ALPHANUMERIC).to_string();
        let request = self
            .client
            .get(format!(
                "{}/proxies/{}/delay?timeout={}&url={}",
                self.base_url, encoded_name, timeout_ms, encoded_url
            ))
            .timeout(Duration::from_millis(timeout_ms as u64 + 2000));

        let response = self.authorize(request).send().await?;
        if !response.status().is_success() {
            return Err(anyhow!("latency test failed: {}", response.status()));
        }
        Ok(response.json::<DelayResponse>().await?.delay)
    }
}
