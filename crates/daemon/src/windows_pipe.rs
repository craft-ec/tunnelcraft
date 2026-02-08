//! Windows Named Pipe IPC Server
//!
//! Implements JSON-RPC 2.0 over Windows named pipes for the TunnelCraft daemon.

#[cfg(windows)]
use std::sync::Arc;

#[cfg(windows)]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(windows)]
use tokio::net::windows::named_pipe::{
    NamedPipeServer, ServerOptions, PipeMode,
};
#[cfg(windows)]
use tokio::sync::mpsc;
#[cfg(windows)]
use tracing::{debug, error, info, warn};

#[cfg(windows)]
use crate::{DaemonError, Result};
#[cfg(windows)]
use crate::ipc::{IpcHandler, JsonRpcRequest, JsonRpcResponse};

/// Windows Named Pipe configuration
#[cfg(windows)]
#[derive(Debug, Clone)]
pub struct WindowsPipeConfig {
    /// Pipe name (e.g., "\\\\.\\pipe\\tunnelcraft")
    pub pipe_name: String,
    /// Maximum number of concurrent connections
    pub max_connections: u32,
}

#[cfg(windows)]
impl Default for WindowsPipeConfig {
    fn default() -> Self {
        Self {
            pipe_name: r"\\.\pipe\tunnelcraft".to_string(),
            max_connections: 10,
        }
    }
}

/// Windows Named Pipe IPC Server
#[cfg(windows)]
pub struct WindowsPipeServer {
    config: WindowsPipeConfig,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

#[cfg(windows)]
impl WindowsPipeServer {
    /// Create a new Windows named pipe server
    pub fn new(config: WindowsPipeConfig) -> Self {
        Self {
            config,
            shutdown_tx: None,
        }
    }

    /// Start the named pipe server
    pub async fn start<H: IpcHandler + 'static>(&mut self, handler: H) -> Result<()> {
        info!("Starting Windows named pipe server on {}", self.config.pipe_name);

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        let handler = Arc::new(handler);
        let pipe_name = self.config.pipe_name.clone();
        
        // Create the first pipe server instance
        let mut server = ServerOptions::new()
            .first_pipe_instance(true)
            .pipe_mode(PipeMode::Message)
            .create(&pipe_name)
            .map_err(|e| DaemonError::IpcError(format!("Failed to create pipe: {}", e)))?;

        loop {
            tokio::select! {
                // Wait for a client to connect
                result = server.connect() => {
                    match result {
                        Ok(()) => {
                            let handler_clone = handler.clone();
                            let connected_pipe = server;
                            
                            // Create a new server for the next connection
                            server = ServerOptions::new()
                                .pipe_mode(PipeMode::Message)
                                .create(&pipe_name)
                                .map_err(|e| DaemonError::IpcError(format!("Failed to create pipe: {}", e)))?;
                            
                            // Handle this connection in a separate task
                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_connection(connected_pipe, handler_clone).await {
                                    warn!("Pipe connection error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Failed to accept pipe connection: {}", e);
                        }
                    }
                }
                
                // Check for shutdown signal
                _ = shutdown_rx.recv() => {
                    info!("Named pipe server shutting down");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle a single pipe connection
    async fn handle_connection<H: IpcHandler>(
        pipe: NamedPipeServer,
        handler: Arc<H>,
    ) -> Result<()> {
        let (reader, mut writer) = tokio::io::split(pipe);
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

        loop {
            line.clear();
            let bytes_read = reader.read_line(&mut line).await
                .map_err(|e| DaemonError::IpcError(format!("Read error: {}", e)))?;

            if bytes_read == 0 {
                // Connection closed
                break;
            }

            debug!("Received: {}", line.trim());

            // Parse request
            let response = match serde_json::from_str::<JsonRpcRequest>(&line) {
                Ok(request) => {
                    if request.jsonrpc != "2.0" {
                        JsonRpcResponse::error(
                            request.id,
                            -32600,
                            "Invalid Request: jsonrpc must be '2.0'".to_string(),
                        )
                    } else {
                        match handler.handle(&request.method, request.params).await {
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

            // Send response
            let response_str = serde_json::to_string(&response)
                .map_err(|e| DaemonError::IpcError(format!("Serialize error: {}", e)))?;

            debug!("Sending: {}", response_str);
            writer.write_all(response_str.as_bytes()).await
                .map_err(|e| DaemonError::IpcError(format!("Write error: {}", e)))?;
            writer.write_all(b"\n").await
                .map_err(|e| DaemonError::IpcError(format!("Write error: {}", e)))?;
            writer.flush().await
                .map_err(|e| DaemonError::IpcError(format!("Flush error: {}", e)))?;
        }

        Ok(())
    }

    /// Stop the named pipe server
    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }
    }

    /// Get the pipe name
    pub fn pipe_name(&self) -> &str {
        &self.config.pipe_name
    }
}

// Stub implementations for non-Windows platforms
#[cfg(not(windows))]
pub struct WindowsPipeConfig {
    pub pipe_name: String,
    pub max_connections: u32,
}

#[cfg(not(windows))]
impl Default for WindowsPipeConfig {
    fn default() -> Self {
        Self {
            pipe_name: r"\\.\pipe\tunnelcraft".to_string(),
            max_connections: 10,
        }
    }
}

#[cfg(not(windows))]
pub struct WindowsPipeServer {
    config: WindowsPipeConfig,
}

#[cfg(not(windows))]
impl WindowsPipeServer {
    pub fn new(config: WindowsPipeConfig) -> Self {
        Self { config }
    }

    pub async fn start<H: crate::ipc::IpcHandler + 'static>(&mut self, _handler: H) -> crate::Result<()> {
        Err(crate::DaemonError::IpcError(
            "Windows named pipes are only available on Windows".to_string()
        ))
    }

    pub async fn stop(&mut self) {}

    pub fn pipe_name(&self) -> &str {
        &self.config.pipe_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = WindowsPipeConfig::default();
        assert!(config.pipe_name.contains("tunnelcraft"));
        assert!(config.max_connections > 0);
    }

    #[test]
    fn test_server_creation() {
        let config = WindowsPipeConfig::default();
        let _server = WindowsPipeServer::new(config);
    }
}
