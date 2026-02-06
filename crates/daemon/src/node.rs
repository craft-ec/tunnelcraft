//! Node Service - Shared relay/exit node runner
//!
//! This module provides a unified node service that can be used by:
//! - CLI (direct)
//! - Desktop apps (via IPC)
//! - Mobile apps (via FFI)

use std::sync::Arc;
use std::time::Duration;

use libp2p::{Multiaddr, PeerId};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use tunnelcraft_core::{Shard, ShardType};
use tunnelcraft_crypto::SigningKeypair;
use tunnelcraft_exit::{ExitConfig, ExitHandler};
use tunnelcraft_network::{NetworkConfig, NetworkEvent, NetworkNode, ShardResponse};
use tunnelcraft_relay::{RelayConfig, RelayHandler};

use crate::{DaemonError, Result};

/// Node operating mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    /// Relay only - forward shards between peers
    Relay,
    /// Exit only - fetch from internet
    Exit,
    /// Full node - both relay and exit
    Full,
}

/// Node configuration
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Node type (relay, exit, or full)
    pub node_type: NodeType,
    /// Listen address
    pub listen_addr: Multiaddr,
    /// Bootstrap peers
    pub bootstrap_peers: Vec<(PeerId, Multiaddr)>,
    /// Allow being last hop (for relay)
    pub allow_last_hop: bool,
    /// HTTP request timeout (for exit)
    pub request_timeout: Duration,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node_type: NodeType::Full,
            listen_addr: "/ip4/0.0.0.0/tcp/9000".parse().expect("valid hardcoded multiaddr"),
            bootstrap_peers: Vec::new(),
            allow_last_hop: true,
            request_timeout: Duration::from_secs(30),
        }
    }
}

/// Node statistics
#[derive(Debug, Clone, Default)]
pub struct NodeStats {
    pub shards_relayed: u64,
    pub shards_exited: u64,
    pub peers_connected: usize,
}

/// Internal node state
struct NodeState {
    relay_handler: Option<RelayHandler>,
    exit_handler: Option<ExitHandler>,
    stats: NodeStats,
}

/// Node service - runs relay/exit node
pub struct NodeService {
    config: NodeConfig,
    state: Arc<RwLock<NodeState>>,
    node: Option<NetworkNode>,
}

impl NodeService {
    /// Create a new node service
    pub fn new(config: NodeConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(NodeState {
                relay_handler: None,
                exit_handler: None,
                stats: NodeStats::default(),
            })),
            node: None,
        }
    }

    /// Initialize and start the node
    pub async fn start(&mut self, keypair: libp2p::identity::Keypair) -> Result<()> {
        let peer_id = PeerId::from(keypair.public());
        info!("Starting node {} in {:?} mode", peer_id, self.config.node_type);

        // Create signing keypair for handlers
        let signing_keypair = SigningKeypair::generate();
        let our_pubkey = signing_keypair.public_key_bytes();
        let our_secret = signing_keypair.secret_key_bytes();

        // Create network config
        let network_config = NetworkConfig {
            listen_addrs: vec![self.config.listen_addr.clone()],
            bootstrap_peers: self.config.bootstrap_peers.clone(),
        };

        // Create network node
        let (node, event_rx) = NetworkNode::new(keypair, network_config)
            .await
            .map_err(|e| DaemonError::SdkError(e.to_string()))?;

        self.node = Some(node);

        // Initialize handlers based on mode
        let mut state = self.state.write().await;
        match self.config.node_type {
            NodeType::Relay => {
                let relay_config = RelayConfig {
                    can_be_last_hop: self.config.allow_last_hop,
                    ..Default::default()
                };
                state.relay_handler = Some(RelayHandler::with_config(signing_keypair, relay_config));
                info!("Relay handler initialized");
            }
            NodeType::Exit => {
                let exit_config = ExitConfig {
                    timeout: self.config.request_timeout,
                    ..Default::default()
                };
                match ExitHandler::new(exit_config, our_pubkey, our_secret) {
                    Ok(handler) => {
                        state.exit_handler = Some(handler);
                        info!("Exit handler initialized");
                    }
                    Err(e) => error!("Failed to create exit handler: {}", e),
                }
            }
            NodeType::Full => {
                let relay_keypair = SigningKeypair::generate();
                let relay_config = RelayConfig {
                    can_be_last_hop: true,
                    ..Default::default()
                };
                state.relay_handler = Some(RelayHandler::with_config(relay_keypair, relay_config));

                let exit_config = ExitConfig {
                    timeout: self.config.request_timeout,
                    ..Default::default()
                };
                match ExitHandler::new(exit_config, our_pubkey, our_secret) {
                    Ok(handler) => {
                        state.exit_handler = Some(handler);
                        info!("Full node initialized (relay + exit)");
                    }
                    Err(e) => error!("Failed to create exit handler for full node: {}", e),
                }
            }
        }
        drop(state);

        // Bootstrap if we have peers
        if let Some(ref mut node) = self.node {
            if node.num_connected() == 0 && !self.config.bootstrap_peers.is_empty() {
                if let Err(e) = node.bootstrap() {
                    warn!("Bootstrap failed: {}", e);
                }
            }
        }

        // Spawn event handler
        let state = self.state.clone();
        tokio::spawn(async move {
            Self::run_event_loop(event_rx, state).await;
        });

        info!("Node started on {}", self.config.listen_addr);
        Ok(())
    }

    /// Run the main event loop (internal)
    async fn run_event_loop(
        mut event_rx: tokio::sync::mpsc::Receiver<NetworkEvent>,
        state: Arc<RwLock<NodeState>>,
    ) {
        while let Some(event) = event_rx.recv().await {
            if let Err(e) = Self::handle_event(&state, event).await {
                warn!("Event handling error: {}", e);
            }
        }
    }

    /// Handle a network event
    async fn handle_event(
        state: &Arc<RwLock<NodeState>>,
        event: NetworkEvent,
    ) -> Result<()> {
        match event {
            NetworkEvent::ShardReceived { shard, .. } => {
                let response = Self::process_shard(state, shard).await;
                debug!("Shard processed: {:?}", response);
            }
            NetworkEvent::PeerConnected(peer_id) => {
                debug!("Peer connected: {}", peer_id);
                let mut state = state.write().await;
                state.stats.peers_connected += 1;
            }
            NetworkEvent::PeerDisconnected(peer_id) => {
                debug!("Peer disconnected: {}", peer_id);
                let mut state = state.write().await;
                state.stats.peers_connected = state.stats.peers_connected.saturating_sub(1);
            }
            _ => {}
        }
        Ok(())
    }

    /// Process an incoming shard
    async fn process_shard(
        state: &Arc<RwLock<NodeState>>,
        shard: Shard,
    ) -> ShardResponse {
        let mut state = state.write().await;

        match shard.shard_type {
            ShardType::Request => {
                // If hops_remaining == 0, we're the exit
                if shard.hops_remaining == 0 {
                    if let Some(ref mut exit_handler) = state.exit_handler {
                        match exit_handler.process_shard(shard).await {
                            Ok(Some(_)) => {
                                state.stats.shards_exited += 1;
                                return ShardResponse::Accepted;
                            }
                            Ok(None) => return ShardResponse::Accepted,
                            Err(e) => return ShardResponse::Rejected(e.to_string()),
                        }
                    } else {
                        return ShardResponse::Rejected("Not an exit node".to_string());
                    }
                }

                // Otherwise relay
                if let Some(ref mut relay_handler) = state.relay_handler {
                    match relay_handler.handle_shard(shard) {
                        Ok(_) => {
                            state.stats.shards_relayed += 1;
                            ShardResponse::Accepted
                        }
                        Err(e) => ShardResponse::Rejected(e.to_string()),
                    }
                } else {
                    ShardResponse::Rejected("Not a relay node".to_string())
                }
            }
            ShardType::Response => {
                if let Some(ref mut relay_handler) = state.relay_handler {
                    match relay_handler.handle_shard(shard) {
                        Ok(_) => {
                            state.stats.shards_relayed += 1;
                            ShardResponse::Accepted
                        }
                        Err(e) => ShardResponse::Rejected(e.to_string()),
                    }
                } else {
                    ShardResponse::Rejected("Not a relay node".to_string())
                }
            }
        }
    }

    /// Get current statistics
    pub async fn stats(&self) -> NodeStats {
        self.state.read().await.stats.clone()
    }

    /// Get peer ID
    pub fn peer_id(&self) -> Option<PeerId> {
        self.node.as_ref().map(|n| n.local_peer_id().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_config_default() {
        let config = NodeConfig::default();
        assert_eq!(config.node_type, NodeType::Full);
        assert!(config.allow_last_hop);
    }

    #[test]
    fn test_node_type_equality() {
        assert_eq!(NodeType::Relay, NodeType::Relay);
        assert_ne!(NodeType::Relay, NodeType::Exit);
        assert_ne!(NodeType::Exit, NodeType::Full);
    }

    #[test]
    fn test_node_stats_default() {
        let stats = NodeStats::default();
        assert_eq!(stats.shards_relayed, 0);
        assert_eq!(stats.shards_exited, 0);
        assert_eq!(stats.peers_connected, 0);
    }
}
