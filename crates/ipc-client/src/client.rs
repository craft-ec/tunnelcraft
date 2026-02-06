//! IPC Client implementation

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tracing::debug;

use crate::protocol::{
    AvailableExitsResult, ConnectParams, ConnectResult, CreditsResult, NodeStatsResult,
    RequestResult, RpcRequest, RpcResponse, StatusResult,
};
use crate::{IpcError, Result};

/// IPC Client for communicating with the TunnelCraft daemon
pub struct IpcClient {
    socket_path: PathBuf,
    request_id: AtomicU64,
}

impl IpcClient {
    /// Create a new IPC client
    ///
    /// Note: This doesn't establish a connection. Each request creates a new connection.
    pub fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            request_id: AtomicU64::new(1),
        }
    }

    /// Connect to the daemon and verify it's running
    pub async fn connect(socket_path: &PathBuf) -> Result<Self> {
        let client = Self::new(socket_path.clone());

        // Verify daemon is running by sending a status request
        client.status().await?;

        Ok(client)
    }

    /// Get the next request ID
    fn next_id(&self) -> u64 {
        self.request_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Send a raw JSON-RPC request
    pub async fn send_request(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value> {
        let stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound
                    || e.kind() == std::io::ErrorKind::ConnectionRefused
                {
                    IpcError::DaemonNotRunning
                } else {
                    IpcError::ConnectionFailed(e.to_string())
                }
            })?;

        let (reader, mut writer) = stream.into_split();

        // Build and send request
        let request = RpcRequest::new(method, params, self.next_id());
        let request_json = serde_json::to_string(&request)?;
        debug!("Sending request: {}", request_json);

        writer.write_all(request_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;

        // Read response
        let mut reader = BufReader::new(reader);
        let mut response_str = String::new();
        reader.read_line(&mut response_str).await?;
        debug!("Received response: {}", response_str.trim());

        let response: RpcResponse = serde_json::from_str(&response_str)
            .map_err(|e| IpcError::InvalidResponse(e.to_string()))?;

        // Check for error
        if let Some(error) = response.error {
            return Err(IpcError::DaemonError {
                code: error.code,
                message: error.message,
            });
        }

        Ok(response.result.unwrap_or(serde_json::Value::Null))
    }

    /// Connect to the VPN network
    ///
    /// # Arguments
    ///
    /// * `hops` - Number of relay hops (0 = direct, 1 = light, 2 = standard, 3+ = paranoid)
    pub async fn connect_vpn(&self, hops: u8) -> Result<ConnectResult> {
        let params = ConnectParams { hops };
        let result = self
            .send_request("connect", Some(serde_json::to_value(params)?))
            .await?;
        serde_json::from_value(result).map_err(|e| IpcError::InvalidResponse(e.to_string()))
    }

    /// Disconnect from the VPN network
    pub async fn disconnect(&self) -> Result<()> {
        self.send_request("disconnect", None).await?;
        Ok(())
    }

    /// Get current connection status
    pub async fn status(&self) -> Result<StatusResult> {
        let result = self.send_request("status", None).await?;
        serde_json::from_value(result).map_err(|e| IpcError::InvalidResponse(e.to_string()))
    }

    /// Get current credit balance
    pub async fn get_credits(&self) -> Result<CreditsResult> {
        let result = self.send_request("get_credits", None).await?;
        serde_json::from_value(result).map_err(|e| IpcError::InvalidResponse(e.to_string()))
    }

    /// Purchase credits
    ///
    /// # Arguments
    ///
    /// * `amount` - Amount of credits to purchase
    pub async fn purchase_credits(&self, amount: u64) -> Result<serde_json::Value> {
        let params = serde_json::json!({ "amount": amount });
        self.send_request("purchase_credits", Some(params)).await
    }

    /// Set the privacy level (hop mode)
    pub async fn set_privacy_level(&self, level: &str) -> Result<()> {
        let params = serde_json::json!({ "level": level });
        self.send_request("set_privacy_level", Some(params)).await?;
        Ok(())
    }

    /// Set node mode (client, node, both)
    pub async fn set_mode(&self, mode: &str) -> Result<()> {
        let params = serde_json::json!({ "mode": mode });
        self.send_request("set_mode", Some(params)).await?;
        Ok(())
    }

    /// Get node stats (relay/exit metrics)
    pub async fn get_node_stats(&self) -> Result<NodeStatsResult> {
        let result = self.send_request("get_node_stats", None).await?;
        serde_json::from_value(result).map_err(|e| IpcError::InvalidResponse(e.to_string()))
    }

    /// Make an HTTP request through the tunnel
    pub async fn request(
        &self,
        method: &str,
        url: &str,
        body: Option<&str>,
        headers: Option<std::collections::HashMap<String, String>>,
    ) -> Result<RequestResult> {
        let params = serde_json::json!({
            "method": method,
            "url": url,
            "body": body,
            "headers": headers,
        });
        let result = self.send_request("request", Some(params)).await?;
        serde_json::from_value(result).map_err(|e| IpcError::InvalidResponse(e.to_string()))
    }

    /// Set preferred exit node geography
    pub async fn set_exit_node(
        &self,
        region: &str,
        country_code: Option<&str>,
        city: Option<&str>,
    ) -> Result<()> {
        let params = serde_json::json!({
            "region": region,
            "country_code": country_code,
            "city": city,
        });
        self.send_request("set_exit_node", Some(params)).await?;
        Ok(())
    }

    /// Set local discovery preference
    pub async fn set_local_discovery(&self, enabled: bool) -> Result<()> {
        let params = serde_json::json!({ "enabled": enabled });
        self.send_request("set_local_discovery", Some(params)).await?;
        Ok(())
    }

    /// Get available exit nodes
    pub async fn get_available_exits(&self) -> Result<AvailableExitsResult> {
        let result = self.send_request("get_available_exits", None).await?;
        serde_json::from_value(result).map_err(|e| IpcError::InvalidResponse(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = IpcClient::new(PathBuf::from("/tmp/test.sock"));
        assert_eq!(client.socket_path, PathBuf::from("/tmp/test.sock"));
    }

    #[test]
    fn test_request_id_increments() {
        let client = IpcClient::new(PathBuf::from("/tmp/test.sock"));
        assert_eq!(client.next_id(), 1);
        assert_eq!(client.next_id(), 2);
        assert_eq!(client.next_id(), 3);
    }
}
