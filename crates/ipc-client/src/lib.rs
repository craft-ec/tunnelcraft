//! TunnelCraft IPC Client
//!
//! JSON-RPC 2.0 client for communicating with the TunnelCraft daemon.
//!
//! ## Supported Platforms
//!
//! - **Unix (macOS/Linux)**: Unix domain sockets
//! - **Windows**: Named pipes
//!
//! ## Usage
//!
//! ```ignore
//! use tunnelcraft_ipc_client::{IpcClient, DEFAULT_SOCKET_PATH};
//! use std::path::PathBuf;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = IpcClient::connect(&PathBuf::from(DEFAULT_SOCKET_PATH)).await?;
//!
//!     // Connect to VPN with 2 hops
//!     let result = client.connect_vpn(2).await?;
//!     println!("Connected: {:?}", result);
//!
//!     // Get status
//!     let status = client.status().await?;
//!     println!("Status: {:?}", status);
//!
//!     Ok(())
//! }
//! ```

mod client;
mod protocol;

pub use client::IpcClient;
pub use protocol::{
    AvailableExitsResult, ConnectParams, ConnectResult, CreditsResult, ExitNodeInfo,
    NodeStatsResult, RequestResult, RpcError, RpcRequest, RpcResponse, StatusResult,
};

use thiserror::Error;

/// Default socket path for Unix systems
#[cfg(unix)]
pub const DEFAULT_SOCKET_PATH: &str = "/tmp/tunnelcraft.sock";

/// Default named pipe path for Windows
#[cfg(windows)]
pub const DEFAULT_PIPE_PATH: &str = r"\\.\pipe\tunnelcraft";

/// Default path (platform-appropriate)
#[cfg(windows)]
pub const DEFAULT_SOCKET_PATH: &str = r"\\.\pipe\tunnelcraft";

#[derive(Error, Debug)]
pub enum IpcError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Request failed: {0}")]
    RequestFailed(String),

    #[error("Daemon error: {message} (code: {code})")]
    DaemonError { code: i32, message: String },

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Daemon not running")]
    DaemonNotRunning,
}

pub type Result<T> = std::result::Result<T, IpcError>;
