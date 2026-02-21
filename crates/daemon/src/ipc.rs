//! IPC server for JSON-RPC communication
//!
//! Uses `craftec-ipc` for the shared IpcHandler trait and protocol types.
//! Keeps CraftNet-specific IpcConfig and IpcServer (event streaming, shutdown).

use std::sync::Arc;
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, error, info, warn};

use crate::{DaemonError, Result};

// Re-export the shared IpcHandler trait from craftec-ipc
pub use craftec_ipc::server::IpcHandler;

// Re-export protocol types with backward-compatible aliases
pub use craftec_ipc::protocol::RpcRequest as JsonRpcRequest;
pub use craftec_ipc::protocol::RpcResponse as JsonRpcResponse;
#[allow(unused_imports)]
pub use craftec_ipc::protocol::RpcError as JsonRpcError;

/// IPC server configuration (CraftNet-specific defaults)
#[derive(Debug, Clone)]
pub struct IpcConfig {
    /// Socket path (Unix) or pipe name (Windows)
    pub socket_path: PathBuf,
}

impl Default for IpcConfig {
    fn default() -> Self {
        let path = if cfg!(target_os = "macos") {
            PathBuf::from("/tmp/craftnet.sock")
        } else if cfg!(target_os = "linux") {
            let xdg_runtime = std::env::var("XDG_RUNTIME_DIR")
                .unwrap_or_else(|_| "/tmp".to_string());
            PathBuf::from(format!("{}/craftnet.sock", xdg_runtime))
        } else {
            PathBuf::from("\\\\.\\pipe\\craftnet")
        };

        Self { socket_path: path }
    }
}

/// IPC server with event streaming and graceful shutdown.
pub struct IpcServer {
    config: IpcConfig,
    shutdown_tx: Option<mpsc::Sender<()>>,
    event_tx: Option<broadcast::Sender<String>>,
}

impl IpcServer {
    /// Create a new IPC server
    pub fn new(config: IpcConfig) -> Self {
        Self {
            config,
            shutdown_tx: None,
            event_tx: None,
        }
    }

    /// Set the event broadcast sender for streaming events to clients
    pub fn set_event_sender(&mut self, tx: broadcast::Sender<String>) {
        self.event_tx = Some(tx);
    }

    /// Start the IPC server
    pub async fn start<H: IpcHandler + 'static>(&mut self, handler: H) -> Result<()> {
        // Remove existing socket file
        if self.config.socket_path.exists() {
            std::fs::remove_file(&self.config.socket_path)?;
        }

        let listener = UnixListener::bind(&self.config.socket_path)
            .map_err(|e| DaemonError::IpcError(format!("Failed to bind: {}", e)))?;

        info!("IPC server listening on {:?}", self.config.socket_path);

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        let handler = Arc::new(handler);
        let event_tx = self.event_tx.clone();

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, _addr)) => {
                            let handler = handler.clone();
                            let event_rx = event_tx.as_ref().map(|tx| tx.subscribe());
                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_connection(stream, handler, event_rx).await {
                                    warn!("Connection error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Accept error: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("IPC server shutting down");
                    break;
                }
            }
        }

        // Cleanup socket file
        let _ = std::fs::remove_file(&self.config.socket_path);

        Ok(())
    }

    /// Handle a single connection with concurrent request handling and event streaming
    async fn handle_connection<H: IpcHandler + 'static>(
        stream: UnixStream,
        handler: Arc<H>,
        event_rx: Option<broadcast::Receiver<String>>,
    ) -> Result<()> {
        let (reader, writer) = stream.into_split();
        let reader = BufReader::new(reader);
        let writer = Arc::new(tokio::sync::Mutex::new(writer));

        let request_writer = writer.clone();
        let request_handler = handler.clone();

        // Task 1: Read JSON-RPC requests and write responses
        let request_task = tokio::spawn(async move {
            let mut reader = reader;
            let mut line = String::new();

            loop {
                line.clear();
                let bytes_read = match reader.read_line(&mut line).await {
                    Ok(n) => n,
                    Err(e) => {
                        debug!("Read error: {}", e);
                        break;
                    }
                };

                if bytes_read == 0 {
                    break;
                }

                debug!("Received: {}", line.trim());

                let response = match serde_json::from_str::<JsonRpcRequest>(&line) {
                    Ok(request) => {
                        if request.jsonrpc != "2.0" {
                            JsonRpcResponse::error(
                                request.id,
                                -32600,
                                "Invalid Request: jsonrpc must be '2.0'".to_string(),
                            )
                        } else {
                            match request_handler.handle(&request.method, request.params).await {
                                Ok(result) => JsonRpcResponse::success(request.id, result),
                                Err(msg) => JsonRpcResponse::error(request.id, -32000, msg),
                            }
                        }
                    }
                    Err(e) => {
                        JsonRpcResponse::error(
                            serde_json::Value::Null,
                            -32700,
                            format!("Parse error: {}", e),
                        )
                    }
                };

                let response_str = match serde_json::to_string(&response) {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Serialize error: {}", e);
                        break;
                    }
                };

                debug!("Sending: {}", response_str);
                let mut w = request_writer.lock().await;
                if w.write_all(response_str.as_bytes()).await.is_err()
                    || w.write_all(b"\n").await.is_err()
                    || w.flush().await.is_err()
                {
                    break;
                }
            }
        });

        // Task 2: Forward broadcast events to the client
        let event_task = if let Some(mut rx) = event_rx {
            let event_writer = writer.clone();
            Some(tokio::spawn(async move {
                loop {
                    match rx.recv().await {
                        Ok(event) => {
                            let mut w = event_writer.lock().await;
                            if w.write_all(event.as_bytes()).await.is_err()
                                || w.write_all(b"\n").await.is_err()
                                || w.flush().await.is_err()
                            {
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("Event stream lagged, missed {} events", n);
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
            }))
        } else {
            None
        };

        // Wait for the request task to finish (client disconnected)
        let _ = request_task.await;

        // Cancel the event task
        if let Some(task) = event_task {
            task.abort();
        }

        Ok(())
    }

    /// Stop the IPC server
    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }
    }

    /// Get the socket path
    pub fn socket_path(&self) -> &PathBuf {
        &self.config.socket_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = IpcConfig::default();
        assert!(config.socket_path.to_str().unwrap().contains("craftnet"));
    }

    #[test]
    fn test_custom_socket_path() {
        let config = IpcConfig {
            socket_path: PathBuf::from("/custom/path/to/socket.sock"),
        };
        assert_eq!(
            config.socket_path.to_str().unwrap(),
            "/custom/path/to/socket.sock"
        );
    }

    #[test]
    fn test_json_rpc_response_success() {
        let response = JsonRpcResponse::success(
            serde_json::json!(1),
            serde_json::json!({"status": "connected"}),
        );
        assert_eq!(response.jsonrpc, "2.0");
        assert!(response.result.is_some());
        assert!(response.error.is_none());
    }

    #[test]
    fn test_json_rpc_response_error() {
        let response = JsonRpcResponse::error(
            serde_json::json!(1),
            -32600,
            "Invalid Request".to_string(),
        );
        assert_eq!(response.jsonrpc, "2.0");
        assert!(response.result.is_none());
        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, -32600);
    }

    #[test]
    fn test_parse_request() {
        let json = r#"{"jsonrpc":"2.0","method":"status","id":1}"#;
        let request: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.jsonrpc, "2.0");
        assert_eq!(request.method, "status");
        assert!(request.params.is_none());
    }

    #[test]
    fn test_parse_request_with_params() {
        let json = r#"{"jsonrpc":"2.0","method":"connect","params":{"hops":2},"id":1}"#;
        let request: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.method, "connect");
        assert!(request.params.is_some());
        let params = request.params.unwrap();
        assert_eq!(params["hops"], 2);
    }

    #[test]
    fn test_ipc_server_creation() {
        let config = IpcConfig {
            socket_path: PathBuf::from("/tmp/test.sock"),
        };
        let server = IpcServer::new(config.clone());
        assert_eq!(server.socket_path(), &config.socket_path);
    }

    #[test]
    fn test_ipc_server_with_event_sender() {
        let config = IpcConfig {
            socket_path: PathBuf::from("/tmp/test_events.sock"),
        };
        let mut server = IpcServer::new(config);
        let (tx, _rx) = broadcast::channel::<String>(16);
        server.set_event_sender(tx);
        assert!(server.event_tx.is_some());
    }
}
