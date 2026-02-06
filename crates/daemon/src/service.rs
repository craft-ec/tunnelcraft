//! Daemon service implementation

use std::sync::Arc;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, RwLock};
use tracing::{debug, info, error};

use tunnelcraft_client::{SDKConfig, TunnelCraftSDK, TunnelResponse};

use crate::ipc::IpcHandler;
use crate::Result;

/// Daemon state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DaemonState {
    /// Service is starting up
    Starting,
    /// Service is ready but not connected
    Ready,
    /// VPN is connecting
    Connecting,
    /// VPN is connected
    Connected,
    /// VPN is disconnecting
    Disconnecting,
    /// Service is shutting down
    Stopping,
}

/// Status response
#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub state: DaemonState,
    pub connected: bool,
    pub credits: u64,
    pub pending_requests: usize,
}

/// Connect parameters
#[derive(Debug, Deserialize, Default)]
pub struct ConnectParams {
    pub hops: Option<u8>,
}

/// Commands sent to the SDK task
enum SdkCommand {
    Connect(oneshot::Sender<std::result::Result<(), String>>),
    Disconnect(oneshot::Sender<std::result::Result<(), String>>),
    Request {
        method: String,
        url: String,
        reply: oneshot::Sender<std::result::Result<TunnelResponse, String>>,
    },
}

/// SDK status info (simpler version for channel communication)
#[derive(Debug, Clone, Default)]
struct SdkStatusInfo {
    connected: bool,
    credits: u64,
    pending_requests: usize,
    peer_count: usize,
}

/// Daemon service
pub struct DaemonService {
    state: Arc<RwLock<DaemonState>>,
    cmd_tx: Arc<RwLock<Option<mpsc::Sender<SdkCommand>>>>,
    sdk_status: Arc<RwLock<SdkStatusInfo>>,
}

impl DaemonService {
    /// Create a new daemon service
    pub fn new() -> Result<Self> {
        Ok(Self {
            state: Arc::new(RwLock::new(DaemonState::Ready)),
            cmd_tx: Arc::new(RwLock::new(None)),
            sdk_status: Arc::new(RwLock::new(SdkStatusInfo::default())),
        })
    }

    /// Initialize and start the SDK in a background task
    pub async fn init(&self, config: SDKConfig) -> Result<()> {
        info!("Initializing TunnelCraft SDK...");

        let (cmd_tx, cmd_rx) = mpsc::channel::<SdkCommand>(32);
        let sdk_status = self.sdk_status.clone();

        // Spawn SDK task
        tokio::spawn(async move {
            if let Err(e) = run_sdk_task(config, cmd_rx, sdk_status).await {
                error!("SDK task error: {}", e);
            }
        });

        *self.cmd_tx.write().await = Some(cmd_tx);
        info!("SDK task started");
        Ok(())
    }

    /// Get current state
    pub async fn state(&self) -> DaemonState {
        *self.state.read().await
    }

    /// Get status
    pub async fn status(&self) -> StatusResponse {
        let state = *self.state.read().await;
        let sdk_status = self.sdk_status.read().await;

        StatusResponse {
            state,
            connected: sdk_status.connected,
            credits: sdk_status.credits,
            pending_requests: sdk_status.pending_requests,
        }
    }

    /// Connect to VPN
    pub async fn connect(&self, params: ConnectParams) -> Result<()> {
        info!("Connecting to VPN with hops: {:?}", params.hops);

        // Initialize SDK if not already done
        {
            let cmd_tx = self.cmd_tx.read().await;
            if cmd_tx.is_none() {
                drop(cmd_tx);
                self.init(SDKConfig::default()).await?;
            }
        }

        {
            let mut state = self.state.write().await;
            *state = DaemonState::Connecting;
        }

        let cmd_tx = self.cmd_tx.read().await;
        if let Some(ref tx) = *cmd_tx {
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(SdkCommand::Connect(reply_tx)).await
                .map_err(|_| crate::DaemonError::SdkError("SDK channel closed".to_string()))?;

            drop(cmd_tx); // Release lock before waiting

            reply_rx.await
                .map_err(|_| crate::DaemonError::SdkError("SDK reply channel closed".to_string()))?
                .map_err(|e| crate::DaemonError::SdkError(e))?;

            let mut state = self.state.write().await;
            *state = DaemonState::Connected;
            info!("Connected to VPN");
        }

        Ok(())
    }

    /// Disconnect from VPN
    pub async fn disconnect(&self) -> Result<()> {
        info!("Disconnecting from VPN");

        {
            let mut state = self.state.write().await;
            *state = DaemonState::Disconnecting;
        }

        let cmd_tx = self.cmd_tx.read().await;
        if let Some(ref tx) = *cmd_tx {
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(SdkCommand::Disconnect(reply_tx)).await
                .map_err(|_| crate::DaemonError::SdkError("SDK channel closed".to_string()))?;

            drop(cmd_tx); // Release lock before waiting

            reply_rx.await
                .map_err(|_| crate::DaemonError::SdkError("SDK reply channel closed".to_string()))?
                .map_err(|e| crate::DaemonError::SdkError(e))?;
        }

        {
            let mut state = self.state.write().await;
            *state = DaemonState::Ready;
        }

        info!("Disconnected from VPN");
        Ok(())
    }

    /// Get credit balance
    pub async fn get_credits(&self) -> u64 {
        self.sdk_status.read().await.credits
    }

    /// Make an HTTP request through the tunnel
    pub async fn request(&self, method: &str, url: &str) -> Result<TunnelResponse> {
        let cmd_tx = self.cmd_tx.read().await;
        if let Some(ref tx) = *cmd_tx {
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(SdkCommand::Request {
                method: method.to_string(),
                url: url.to_string(),
                reply: reply_tx,
            }).await
                .map_err(|_| crate::DaemonError::SdkError("SDK channel closed".to_string()))?;

            drop(cmd_tx); // Release lock before waiting

            reply_rx.await
                .map_err(|_| crate::DaemonError::SdkError("SDK reply channel closed".to_string()))?
                .map_err(|e| crate::DaemonError::SdkError(e))
        } else {
            Err(crate::DaemonError::SdkError("SDK not initialized".to_string()))
        }
    }
}

/// Run the SDK in its own task
async fn run_sdk_task(
    config: SDKConfig,
    mut cmd_rx: mpsc::Receiver<SdkCommand>,
    status: Arc<RwLock<SdkStatusInfo>>,
) -> std::result::Result<(), String> {
    let mut sdk = TunnelCraftSDK::new(config)
        .await
        .map_err(|e| e.to_string())?;

    info!("SDK initialized in background task");

    loop {
        // Update status
        {
            let sdk_status = sdk.status();
            let mut status = status.write().await;
            status.connected = sdk_status.connected;
            status.credits = sdk_status.credits;
            status.pending_requests = sdk_status.pending_requests;
            status.peer_count = sdk_status.peer_count;
        }

        // Check for commands (non-blocking)
        match cmd_rx.try_recv() {
            Ok(cmd) => {
                match cmd {
                    SdkCommand::Connect(reply) => {
                        let result = sdk.connect().await.map_err(|e| e.to_string());
                        let _ = reply.send(result);
                    }
                    SdkCommand::Disconnect(reply) => {
                        sdk.disconnect().await;
                        let _ = reply.send(Ok(()));
                    }
                    SdkCommand::Request { method, url, reply } => {
                        let result = match method.to_uppercase().as_str() {
                            "GET" => sdk.get(&url).await,
                            "POST" => sdk.post(&url, Vec::new()).await,
                            _ => Err(tunnelcraft_client::ClientError::RequestFailed(
                                format!("Unsupported method: {}", method)
                            )),
                        };
                        let _ = reply.send(result.map_err(|e| e.to_string()));
                    }
                }
            }
            Err(mpsc::error::TryRecvError::Empty) => {
                // No command, continue polling network
            }
            Err(mpsc::error::TryRecvError::Disconnected) => {
                info!("Command channel closed, shutting down SDK task");
                break;
            }
        }

        // Poll network events briefly
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }

    Ok(())
}

impl Default for DaemonService {
    fn default() -> Self {
        Self::new().expect("Failed to create daemon service")
    }
}

impl IpcHandler for DaemonService {
    fn handle(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::result::Result<serde_json::Value, String>> + Send + '_>> {
        let method = method.to_string();
        Box::pin(async move {
            debug!("Handling method: {}", method);

            match method.as_str() {
                "status" => {
                    let status = self.status().await;
                    serde_json::to_value(status)
                        .map_err(|e| format!("Serialize error: {}", e))
                }

                "connect" => {
                    let params: ConnectParams = params
                        .map(|p| serde_json::from_value(p).unwrap_or_default())
                        .unwrap_or_default();

                    self.connect(params).await
                        .map_err(|e| format!("Connect error: {}", e))?;

                    Ok(serde_json::json!({"success": true}))
                }

                "disconnect" => {
                    self.disconnect().await
                        .map_err(|e| format!("Disconnect error: {}", e))?;

                    Ok(serde_json::json!({"success": true}))
                }

                "get_credits" => {
                    let credits = self.get_credits().await;
                    Ok(serde_json::json!({"credits": credits}))
                }

                "purchase_credits" => {
                    // TODO: Implement actual credit purchase
                    Err("Not implemented".to_string())
                }

                "request" => {
                    #[derive(Deserialize)]
                    struct RequestParams {
                        method: String,
                        url: String,
                    }

                    let params: RequestParams = params
                        .ok_or_else(|| "Missing params".to_string())
                        .and_then(|p| serde_json::from_value(p).map_err(|e| format!("Invalid params: {}", e)))?;

                    let response = self.request(&params.method, &params.url).await
                        .map_err(|e| format!("Request error: {}", e))?;

                    Ok(serde_json::json!({
                        "status": response.status,
                        "headers": response.headers,
                        "body": String::from_utf8_lossy(&response.body)
                    }))
                }

                _ => {
                    Err(format!("Unknown method: {}", method))
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_response_serialization() {
        let status = StatusResponse {
            state: DaemonState::Connected,
            connected: true,
            credits: 1000,
            pending_requests: 5,
        };

        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("connected"));
        assert!(json.contains("1000"));
    }

    #[test]
    fn test_connect_params_default() {
        let params = ConnectParams::default();
        assert!(params.hops.is_none());
    }

    #[test]
    fn test_connect_params_deserialize() {
        let json = r#"{"hops": 3}"#;
        let params: ConnectParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.hops, Some(3));
    }

    #[tokio::test]
    async fn test_service_creation() {
        let service = DaemonService::new().unwrap();
        assert_eq!(service.state().await, DaemonState::Ready);
    }

    #[tokio::test]
    async fn test_service_status() {
        let service = DaemonService::new().unwrap();
        let status = service.status().await;

        assert_eq!(status.state, DaemonState::Ready);
        assert!(!status.connected);
        assert_eq!(status.credits, 0);
    }

    #[tokio::test]
    async fn test_connect_disconnect() {
        let service = DaemonService::new().unwrap();

        // Connect
        service.connect(ConnectParams::default()).await.unwrap();
        assert_eq!(service.state().await, DaemonState::Connected);

        // Disconnect
        service.disconnect().await.unwrap();
        assert_eq!(service.state().await, DaemonState::Ready);
    }

    #[tokio::test]
    async fn test_ipc_handler_status() {
        let service = DaemonService::new().unwrap();

        let result = service.handle("status", None).await;
        assert!(result.is_ok());

        let value = result.unwrap();
        assert!(value.get("state").is_some());
    }

    #[tokio::test]
    async fn test_ipc_handler_unknown_method() {
        let service = DaemonService::new().unwrap();

        let result = service.handle("unknown_method", None).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown method"));
    }

    // ==================== NEGATIVE TESTS ====================

    #[tokio::test]
    async fn test_ipc_handler_connect_with_invalid_params() {
        let service = DaemonService::new().unwrap();

        // Invalid params should default to empty params
        let result = service.handle("connect", Some(serde_json::json!({"invalid": "field"}))).await;
        // Should succeed since ConnectParams uses Default for missing fields
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ipc_handler_get_credits_returns_zero() {
        let service = DaemonService::new().unwrap();

        let result = service.handle("get_credits", None).await;
        assert!(result.is_ok());

        let value = result.unwrap();
        assert_eq!(value["credits"], 0);
    }

    #[tokio::test]
    async fn test_ipc_handler_purchase_credits_not_implemented() {
        let service = DaemonService::new().unwrap();

        let result = service.handle("purchase_credits", None).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Not implemented"));
    }

    #[tokio::test]
    async fn test_multiple_unknown_methods() {
        let service = DaemonService::new().unwrap();

        // Various unknown methods should all fail
        let methods = ["foo", "bar", "get_status_typo", "CONNECT", "Status"];

        for method in methods {
            let result = service.handle(method, None).await;
            assert!(result.is_err(), "Method '{}' should fail", method);
        }
    }

    #[tokio::test]
    async fn test_connect_with_null_params() {
        let service = DaemonService::new().unwrap();

        // Null value should be handled gracefully
        let result = service.handle("connect", Some(serde_json::Value::Null)).await;
        // Should work since we handle None params
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_status_after_disconnect() {
        let service = DaemonService::new().unwrap();

        // Connect then disconnect
        service.connect(ConnectParams::default()).await.unwrap();
        service.disconnect().await.unwrap();

        // Give SDK task time to update status
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Status should show Ready state
        let status = service.status().await;
        assert_eq!(status.state, DaemonState::Ready);
        // Note: connected status comes from SDK which updates async
        // The daemon state is what we control
    }

    #[test]
    fn test_daemon_state_serialization() {
        // All states should serialize to lowercase
        assert_eq!(
            serde_json::to_string(&DaemonState::Starting).unwrap(),
            "\"starting\""
        );
        assert_eq!(
            serde_json::to_string(&DaemonState::Ready).unwrap(),
            "\"ready\""
        );
        assert_eq!(
            serde_json::to_string(&DaemonState::Connecting).unwrap(),
            "\"connecting\""
        );
        assert_eq!(
            serde_json::to_string(&DaemonState::Connected).unwrap(),
            "\"connected\""
        );
        assert_eq!(
            serde_json::to_string(&DaemonState::Disconnecting).unwrap(),
            "\"disconnecting\""
        );
        assert_eq!(
            serde_json::to_string(&DaemonState::Stopping).unwrap(),
            "\"stopping\""
        );
    }

    #[test]
    fn test_status_response_full_serialization() {
        let status = StatusResponse {
            state: DaemonState::Connected,
            connected: true,
            credits: 12345,
            pending_requests: 42,
        };

        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"state\":\"connected\""));
        assert!(json.contains("\"connected\":true"));
        assert!(json.contains("\"credits\":12345"));
        assert!(json.contains("\"pending_requests\":42"));
    }

    #[test]
    fn test_connect_params_with_hops() {
        let json = r#"{"hops": 5}"#;
        let params: ConnectParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.hops, Some(5));
    }

    #[test]
    fn test_connect_params_with_zero_hops() {
        let json = r#"{"hops": 0}"#;
        let params: ConnectParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.hops, Some(0));
    }

    #[test]
    fn test_connect_params_empty_json() {
        let json = r#"{}"#;
        let params: ConnectParams = serde_json::from_str(json).unwrap();
        assert!(params.hops.is_none());
    }

    #[tokio::test]
    async fn test_disconnect_multiple_times() {
        let service = DaemonService::new().unwrap();

        // Connect
        service.connect(ConnectParams::default()).await.unwrap();

        // Disconnect multiple times should not cause issues
        service.disconnect().await.unwrap();
        service.disconnect().await.unwrap();
        service.disconnect().await.unwrap();

        assert_eq!(service.state().await, DaemonState::Ready);
    }

    #[tokio::test]
    async fn test_credits_after_connect() {
        let service = DaemonService::new().unwrap();

        // Before connect, credits should be 0
        assert_eq!(service.get_credits().await, 0);

        service.connect(ConnectParams::default()).await.unwrap();

        // Give SDK task time to update status
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // After connect, credits come from the real SDK (starts at 0 unless topped up)
        // This tests that we can read credits after connecting
        let credits = service.get_credits().await;
        // Credits start at 0 in the real SDK
        assert_eq!(credits, 0);
    }

    #[test]
    fn test_all_daemon_states_are_different() {
        let states = [
            DaemonState::Starting,
            DaemonState::Ready,
            DaemonState::Connecting,
            DaemonState::Connected,
            DaemonState::Disconnecting,
            DaemonState::Stopping,
        ];

        // Each state should be unique
        for i in 0..states.len() {
            for j in (i + 1)..states.len() {
                assert_ne!(states[i], states[j]);
            }
        }
    }
}
