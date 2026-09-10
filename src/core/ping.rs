use anyhow::{Result, anyhow};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

pub async fn ping_node_tcp(server: &str, port: u16, timeout_ms: u64) -> Result<u32> {
    let target = format!("{}:{}", server, port);
    let start = Instant::now();

    match tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        TcpStream::connect(&target),
    )
    .await
    {
        Ok(Ok(_)) => Ok((start.elapsed().as_millis() as u32).max(1)),
        Ok(Err(e)) => Err(anyhow!("{}", e)),
        Err(_) => Err(anyhow!("timed out after {} ms", timeout_ms)),
    }
}
