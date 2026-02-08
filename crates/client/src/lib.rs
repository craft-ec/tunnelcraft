//! TunnelCraft Client SDK
//!
//! Client-side SDK for connecting to the TunnelCraft network.
//!
//! ## Overview
//!
//! The client SDK provides a high-level interface for:
//! - Creating and managing VPN connections
//! - Fragmenting requests into shards
//! - Reconstructing responses from shards
//! - Managing credits and settlement
//! - Running as a relay/exit node
//!
//! ## Unified Node
//!
//! The `TunnelCraftNode` is the recommended way to use this SDK. It supports
//! three modes:
//! - **Client**: Route your traffic through the VPN (spend credits)
//! - **Node**: Relay traffic for others (earn credits)
//! - **Both**: Use VPN + help the network (spend & earn)
//!
//! ## Example
//!
//! ```ignore
//! use tunnelcraft_client::{TunnelCraftNode, NodeConfig, NodeMode};
//!
//! // Create a node in Both mode (VPN + relay)
//! let config = NodeConfig {
//!     mode: NodeMode::Both,
//!     ..Default::default()
//! };
//! let mut node = TunnelCraftNode::new(config)?;
//! node.start().await?;
//!
//! // Make an HTTP request through the tunnel
//! let response = node.get("https://example.com").await?;
//! println!("Status: {}", response.status);
//!
//! // Check stats (includes relay stats)
//! let stats = node.stats();
//! println!("Shards relayed: {}", stats.shards_relayed);
//! ```

mod credits;
mod node;
mod request;
mod response;

// Unified node (the single networking implementation)
pub use node::{NodeConfig, NodeMode, NodeStats, NodeStatus, NodeType, TunnelCraftNode};

// Credit management
pub use credits::CreditManager;

// Request builder
pub use request::RequestBuilder;

// Tunnel response
pub use response::TunnelResponse;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Not connected")]
    NotConnected,

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Request failed: {0}")]
    RequestFailed(String),

    #[error("Response timeout")]
    Timeout,

    #[error("Insufficient credits: have {have}, need {need}")]
    InsufficientCredits { have: u64, need: u64 },

    #[error("Erasure coding error: {0}")]
    ErasureError(String),

    #[error("No exit nodes available")]
    NoExitNodes,

    #[error("No exit nodes available in region: {0}")]
    NoExitsInRegion(String),

    #[error("Invalid response")]
    InvalidResponse,

    #[error("Crypto error: {0}")]
    CryptoError(String),
}

pub type Result<T> = std::result::Result<T, ClientError>;
