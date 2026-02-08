//! TunnelCraft UniFFI Bindings
//!
//! Mobile bindings for iOS (Swift) and Android (Kotlin) via uniffi.
//!
//! This module provides a synchronous interface that wraps the async SDK
//! for use in mobile applications via their Network Extension / VpnService APIs.

use std::sync::Arc;
use std::time::Instant;

use once_cell::sync::OnceCell;
use parking_lot::{Mutex, RwLock};
use tokio::runtime::Runtime;
use tracing::{debug, info};

use tunnelcraft_client::{
    NodeMode as ClientNodeMode, TunnelCraftNode,
};
use tunnelcraft_core::HopMode;

// Export UniFFI scaffolding
uniffi::setup_scaffolding!();

// Global tokio runtime for async operations
static RUNTIME: OnceCell<Runtime> = OnceCell::new();

/// Initialize the library (call once at app startup)
#[uniffi::export]
pub fn init_library() {
    // Initialize runtime
    let _ = RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            // Tokio runtime is required for all operations
            .expect("Failed to create tokio runtime")
    });

    // Initialize tracing (simplified for mobile)
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();

    info!("TunnelCraft library initialized");
}

fn get_runtime() -> &'static Runtime {
    RUNTIME.get().expect("Library not initialized - call init_library() first")
}

/// VPN connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Error,
}

/// Privacy level (number of relay hops)
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PrivacyLevel {
    Direct,    // 0 hops
    Light,     // 1 hop
    Standard,  // 2 hops
    Paranoid,  // 3 hops
}

/// Operating mode for the unified node
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum NodeMode {
    /// Use VPN only (spend credits, route personal traffic)
    Client,
    /// Help network only (earn credits, relay/exit for others)
    Node,
    /// Both: Use VPN + help network simultaneously
    Both,
}

impl From<NodeMode> for ClientNodeMode {
    fn from(mode: NodeMode) -> Self {
        match mode {
            NodeMode::Client => ClientNodeMode::Client,
            NodeMode::Node => ClientNodeMode::Node,
            NodeMode::Both => ClientNodeMode::Both,
        }
    }
}

impl From<ClientNodeMode> for NodeMode {
    fn from(mode: ClientNodeMode) -> Self {
        match mode {
            ClientNodeMode::Client => NodeMode::Client,
            ClientNodeMode::Node => NodeMode::Node,
            ClientNodeMode::Both => NodeMode::Both,
        }
    }
}

/// Type of node services to run
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum NodeType {
    /// Only relay shards (lower bandwidth, lower earnings)
    Relay,
    /// Only exit (fetch HTTP, higher earnings, more risk)
    Exit,
    /// Both relay and exit (maximum earnings)
    Full,
}

impl From<PrivacyLevel> for HopMode {
    fn from(level: PrivacyLevel) -> Self {
        match level {
            PrivacyLevel::Direct => HopMode::Direct,
            PrivacyLevel::Light => HopMode::Light,
            PrivacyLevel::Standard => HopMode::Standard,
            PrivacyLevel::Paranoid => HopMode::Paranoid,
        }
    }
}

/// Configuration for the unified TunnelCraft node
#[derive(Debug, Clone, uniffi::Record)]
pub struct UnifiedNodeConfig {
    /// Operating mode
    pub mode: NodeMode,
    /// Privacy level for VPN traffic (Client/Both modes)
    pub privacy_level: PrivacyLevel,
    /// Type of node services (Node/Both modes)
    pub node_type: NodeType,
    /// Bootstrap peer address (optional)
    pub bootstrap_peer: Option<String>,
    /// Request timeout in seconds
    pub request_timeout_secs: u64,
}

impl Default for UnifiedNodeConfig {
    fn default() -> Self {
        Self {
            mode: NodeMode::Both,
            privacy_level: PrivacyLevel::Standard,
            node_type: NodeType::Full,
            bootstrap_peer: None,
            request_timeout_secs: 30,
        }
    }
}

/// Statistics for the unified node
#[derive(Debug, Clone, uniffi::Record)]
pub struct UnifiedNodeStats {
    // Client stats (when routing personal traffic)
    pub bytes_sent: u64,
    pub bytes_received: u64,
    // Node stats (when helping network)
    pub shards_relayed: u64,
    pub requests_exited: u64,
    pub credits_earned: u64,
    pub credits_spent: u64,
    // Connection stats
    pub connected_peers: u32,
    pub uptime_secs: u64,
}

impl Default for UnifiedNodeStats {
    fn default() -> Self {
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            shards_relayed: 0,
            requests_exited: 0,
            credits_earned: 0,
            credits_spent: 0,
            connected_peers: 0,
            uptime_secs: 0,
        }
    }
}

/// Response from an HTTP request through the tunnel
#[derive(Debug, Clone, uniffi::Record)]
pub struct TunnelResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub headers: Vec<String>,
}

/// Information about an available exit node
#[derive(Debug, Clone, uniffi::Record)]
pub struct ExitNodeInfo {
    pub pubkey: String,
    pub address: String,
    pub region: String,
    pub country_code: Option<String>,
    pub city: Option<String>,
    pub reputation: u64,
    pub latency_ms: u32,
}

/// Error types for VPN operations
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum TunnelCraftError {
    #[error("Library not initialized")]
    NotInitialized,

    #[error("Already connected")]
    AlreadyConnected,

    #[error("Not connected")]
    NotConnected,

    #[error("Connection failed: {msg}")]
    ConnectionFailed { msg: String },

    #[error("No exit nodes available")]
    NoExitNodes,

    #[error("Request timed out")]
    Timeout,

    #[error("Insufficient credits")]
    InsufficientCredits,

    #[error("Invalid configuration: {msg}")]
    InvalidConfig { msg: String },

    #[error("Internal error: {msg}")]
    InternalError { msg: String },
}

/// Create a default unified node configuration
#[uniffi::export]
pub fn create_default_unified_config() -> UnifiedNodeConfig {
    UnifiedNodeConfig::default()
}

/// Create a unified node configuration with custom settings
#[uniffi::export]
pub fn create_unified_config(
    mode: NodeMode,
    privacy_level: PrivacyLevel,
    node_type: NodeType,
    bootstrap_peer: Option<String>,
) -> UnifiedNodeConfig {
    UnifiedNodeConfig {
        mode,
        privacy_level,
        node_type,
        bootstrap_peer,
        request_timeout_secs: 30,
    }
}

/// Internal state for the unified node
struct UnifiedNodeState {
    node: Option<TunnelCraftNode>,
    state: ConnectionState,
    mode: NodeMode,
    error: Option<String>,
    stats: UnifiedNodeStats,
    start_time: Option<Instant>,
}

impl Default for UnifiedNodeState {
    fn default() -> Self {
        Self {
            node: None,
            state: ConnectionState::Disconnected,
            mode: NodeMode::Both,
            error: None,
            stats: UnifiedNodeStats::default(),
            start_time: None,
        }
    }
}

unsafe impl Send for UnifiedNodeState {}

/// Unified TunnelCraft node supporting Client, Node, or Both modes
///
/// This is the recommended interface for mobile apps. It provides:
/// - Client mode: Route your traffic through VPN (spend credits)
/// - Node mode: Help the network by relaying/exiting (earn credits)
/// - Both mode: Use VPN + help network simultaneously
#[derive(uniffi::Object)]
pub struct TunnelCraftUnifiedNode {
    config: RwLock<UnifiedNodeConfig>,
    state: Mutex<UnifiedNodeState>,
}

#[uniffi::export]
impl TunnelCraftUnifiedNode {
    /// Create a new unified node instance
    #[uniffi::constructor]
    pub fn new(config: UnifiedNodeConfig) -> Result<Arc<Self>, TunnelCraftError> {
        if RUNTIME.get().is_none() {
            return Err(TunnelCraftError::NotInitialized);
        }

        info!("Creating TunnelCraftUnifiedNode with mode: {:?}", config.mode);

        let mut state = UnifiedNodeState::default();
        state.mode = config.mode;

        Ok(Arc::new(Self {
            config: RwLock::new(config),
            state: Mutex::new(state),
        }))
    }

    /// Start the node and connect to the network
    pub fn start(&self) -> Result<(), TunnelCraftError> {
        let mut state = self.state.lock();

        if state.state == ConnectionState::Connected {
            return Err(TunnelCraftError::AlreadyConnected);
        }

        info!("Starting TunnelCraftUnifiedNode...");
        state.state = ConnectionState::Connecting;
        state.error = None;

        let config = self.config.read().clone();

        // Build node config
        let mut node_config = tunnelcraft_client::NodeConfig::default();
        node_config.mode = config.mode.into();
        node_config.hop_mode = config.privacy_level.into();

        // Drop state lock before async operation
        drop(state);

        // Run async start on runtime
        let result = get_runtime().block_on(async {
            let mut node = TunnelCraftNode::new(node_config)
                .map_err(|e| TunnelCraftError::ConnectionFailed { msg: e.to_string() })?;

            node.start().await
                .map_err(|e| TunnelCraftError::ConnectionFailed { msg: e.to_string() })?;

            Ok::<_, TunnelCraftError>(node)
        });

        let mut state = self.state.lock();
        match result {
            Ok(node) => {
                state.node = Some(node);
                state.state = ConnectionState::Connected;
                state.start_time = Some(Instant::now());
                info!("TunnelCraftUnifiedNode started successfully");
                Ok(())
            }
            Err(e) => {
                state.state = ConnectionState::Error;
                state.error = Some(e.to_string());
                Err(e)
            }
        }
    }

    /// Stop the node and disconnect from the network
    pub fn stop(&self) -> Result<(), TunnelCraftError> {
        let mut state = self.state.lock();

        if state.state == ConnectionState::Disconnected {
            return Ok(());
        }

        info!("Stopping TunnelCraftUnifiedNode...");
        state.state = ConnectionState::Disconnecting;

        if let Some(mut node) = state.node.take() {
            drop(state);

            get_runtime().block_on(async {
                node.stop().await;
            });

            let mut state = self.state.lock();
            state.state = ConnectionState::Disconnected;
            state.start_time = None;
        } else {
            state.state = ConnectionState::Disconnected;
        }

        info!("TunnelCraftUnifiedNode stopped");
        Ok(())
    }

    /// Get current operating mode
    pub fn get_mode(&self) -> NodeMode {
        self.state.lock().mode
    }

    /// Set operating mode (can be changed while running)
    pub fn set_mode(&self, mode: NodeMode) -> Result<(), TunnelCraftError> {
        let mut state = self.state.lock();
        let old_mode = state.mode;
        state.mode = mode;

        if let Some(ref mut node) = state.node {
            node.set_mode(mode.into());
            info!("Mode changed from {:?} to {:?}", old_mode, mode);
        }

        // Update config too
        drop(state);
        self.config.write().mode = mode;

        Ok(())
    }

    /// Check if VPN routing is active (Client or Both mode)
    pub fn is_vpn_active(&self) -> bool {
        let mode = self.state.lock().mode;
        matches!(mode, NodeMode::Client | NodeMode::Both)
    }

    /// Check if node services are active (Node or Both mode)
    pub fn is_node_active(&self) -> bool {
        let mode = self.state.lock().mode;
        matches!(mode, NodeMode::Node | NodeMode::Both)
    }

    /// Check if connected to the network
    pub fn is_connected(&self) -> bool {
        self.state.lock().state == ConnectionState::Connected
    }

    /// Get current connection state
    pub fn get_state(&self) -> ConnectionState {
        self.state.lock().state
    }

    /// Get comprehensive statistics
    pub fn get_stats(&self) -> UnifiedNodeStats {
        let state = self.state.lock();
        let mut stats = state.stats.clone();

        if let Some(start) = state.start_time {
            stats.uptime_secs = start.elapsed().as_secs();
        }

        if let Some(ref node) = state.node {
            let node_stats = node.stats();
            stats.bytes_sent = node_stats.bytes_sent;
            stats.bytes_received = node_stats.bytes_received;
            stats.shards_relayed = node_stats.shards_relayed;
            stats.requests_exited = node_stats.requests_exited;
            stats.credits_earned = node_stats.credits_earned;
            stats.credits_spent = node_stats.credits_spent;
            stats.connected_peers = node_stats.peers_connected as u32;
        }

        stats
    }

    /// Get peer ID
    pub fn get_peer_id(&self) -> String {
        let state = self.state.lock();
        if let Some(ref node) = state.node {
            node.status().peer_id.to_string()
        } else {
            String::new()
        }
    }

    /// Get number of connected peers
    pub fn get_peer_count(&self) -> u32 {
        let state = self.state.lock();
        if let Some(ref node) = state.node {
            node.status().peer_count as u32
        } else {
            0
        }
    }

    /// Set available credits
    pub fn set_credits(&self, credits: u64) {
        let mut state = self.state.lock();
        if let Some(ref mut node) = state.node {
            node.set_credits(credits);
        }
    }

    /// Get available credits
    pub fn get_credits(&self) -> u64 {
        let state = self.state.lock();
        if let Some(ref node) = state.node {
            node.credits()
        } else {
            0
        }
    }

    /// Set privacy level for VPN traffic
    pub fn set_privacy_level(&self, level: PrivacyLevel) {
        self.config.write().privacy_level = level;
        debug!("Privacy level set to: {:?}", level);
    }

    /// Get current privacy level
    pub fn get_privacy_level(&self) -> PrivacyLevel {
        self.config.read().privacy_level
    }

    /// Get error message if any
    pub fn get_error(&self) -> Option<String> {
        self.state.lock().error.clone()
    }

    /// Make an HTTP request through the tunnel
    ///
    /// Only works in Client or Both mode.
    pub fn request(
        &self,
        method: String,
        url: String,
        body: Option<Vec<u8>>,
    ) -> Result<TunnelResponse, TunnelCraftError> {
        let state = self.state.lock();

        if state.state != ConnectionState::Connected {
            return Err(TunnelCraftError::NotConnected);
        }

        if state.node.is_none() {
            return Err(TunnelCraftError::NotConnected);
        }

        drop(state);

        let result = get_runtime().block_on(async {
            let mut state = self.state.lock();
            if let Some(ref mut node) = state.node {
                node.fetch(&method, &url, body, None)
                    .await
                    .map_err(|e| TunnelCraftError::InternalError { msg: e.to_string() })
            } else {
                Err(TunnelCraftError::NotConnected)
            }
        });

        result.map(|r| TunnelResponse {
            status: r.status,
            body: r.body,
            headers: r.headers.into_iter().map(|(k, v)| format!("{}: {}", k, v)).collect(),
        })
    }

    /// Get available exit nodes from the network
    pub fn get_available_exits(&self) -> Vec<ExitNodeInfo> {
        let state = self.state.lock();
        if let Some(ref node) = state.node {
            node.online_exit_nodes()
                .into_iter()
                .map(|e| ExitNodeInfo {
                    pubkey: hex::encode(e.pubkey),
                    address: e.address.clone(),
                    region: e.region.code().to_string(),
                    country_code: e.country_code.clone(),
                    city: e.city.clone(),
                    reputation: e.reputation,
                    latency_ms: e.latency_ms,
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Select an exit node by public key hex string
    pub fn select_exit(&self, pubkey: String) -> Result<(), TunnelCraftError> {
        let mut state = self.state.lock();
        if let Some(ref mut node) = state.node {
            // Find the exit by pubkey
            let pubkey_bytes = hex::decode(&pubkey)
                .map_err(|e| TunnelCraftError::InvalidConfig { msg: format!("Invalid pubkey hex: {}", e) })?;
            if pubkey_bytes.len() != 32 {
                return Err(TunnelCraftError::InvalidConfig { msg: "Pubkey must be 32 bytes".to_string() });
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&pubkey_bytes);

            let exit = node.exit_nodes().into_iter().find(|e| e.pubkey == pk).cloned();
            if let Some(exit_info) = exit {
                node.select_exit(exit_info);
                Ok(())
            } else {
                Err(TunnelCraftError::NoExitNodes)
            }
        } else {
            Err(TunnelCraftError::NotConnected)
        }
    }

    /// Purchase credits using mock settlement
    pub fn purchase_credits(&self, amount: u64) -> Result<u64, TunnelCraftError> {
        let mut state = self.state.lock();
        if let Some(ref mut node) = state.node {
            let current = node.credits();
            let new_balance = current + amount;
            node.set_credits(new_balance);
            Ok(new_balance)
        } else {
            Err(TunnelCraftError::NotConnected)
        }
    }

    /// Poll the network once (for manual event loop control)
    ///
    /// Call this periodically when you want to manually drive the event loop.
    /// Returns true if there was work done.
    pub fn poll_once(&self) -> bool {
        let has_node = self.state.lock().node.is_some();
        if has_node {
            // Take node out temporarily for polling
            let mut node = {
                let mut state = self.state.lock();
                state.node.take()
            };

            if let Some(ref mut n) = node {
                get_runtime().block_on(async {
                    n.poll_once().await;
                });
            }

            // Put node back
            let mut state = self.state.lock();
            state.node = node;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privacy_level_conversion() {
        assert_eq!(HopMode::from(PrivacyLevel::Direct), HopMode::Direct);
        assert_eq!(HopMode::from(PrivacyLevel::Light), HopMode::Light);
        assert_eq!(HopMode::from(PrivacyLevel::Standard), HopMode::Standard);
        assert_eq!(HopMode::from(PrivacyLevel::Paranoid), HopMode::Paranoid);
    }

    #[test]
    fn test_default_unified_config() {
        let config = UnifiedNodeConfig::default();
        assert_eq!(config.privacy_level, PrivacyLevel::Standard);
        assert_eq!(config.mode, NodeMode::Both);
        assert_eq!(config.request_timeout_secs, 30);
        assert!(config.bootstrap_peer.is_none());
    }

    #[test]
    fn test_create_unified_config() {
        let config = create_unified_config(
            NodeMode::Client,
            PrivacyLevel::Paranoid,
            NodeType::Relay,
            Some("peer@/ip4/127.0.0.1/tcp/9000".to_string()),
        );
        assert_eq!(config.privacy_level, PrivacyLevel::Paranoid);
        assert_eq!(config.mode, NodeMode::Client);
        assert_eq!(config.request_timeout_secs, 30);
    }

    #[test]
    fn test_init_library() {
        init_library();
        assert!(RUNTIME.get().is_some());
    }

    #[test]
    fn test_create_unified_node_with_init() {
        init_library();

        let node = TunnelCraftUnifiedNode::new(UnifiedNodeConfig::default());
        assert!(node.is_ok());

        let node = node.unwrap();
        assert!(!node.is_connected());
        assert_eq!(node.get_state(), ConnectionState::Disconnected);
        assert_eq!(node.get_mode(), NodeMode::Both);
    }

    #[test]
    fn test_unified_node_set_privacy_level() {
        init_library();

        let node = TunnelCraftUnifiedNode::new(UnifiedNodeConfig::default()).unwrap();
        assert_eq!(node.get_privacy_level(), PrivacyLevel::Standard);

        node.set_privacy_level(PrivacyLevel::Paranoid);
        assert_eq!(node.get_privacy_level(), PrivacyLevel::Paranoid);
    }
}
