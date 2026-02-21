//! Network node for CraftNet
//!
//! Main entry point for P2P networking functionality.
//! Delegates to craftec-network for swarm construction.

use libp2p::{
    identity::Keypair,
    Multiaddr, PeerId,
};
use thiserror::Error;
use tracing::info;

use crate::behaviour::CraftNetBehaviour;
use crate::protocol::SHARD_STREAM_PROTOCOL;

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Transport error: {0}")]
    Transport(String),

    #[error("Dial error: {0}")]
    Dial(String),

    #[error("Listen error: {0}")]
    Listen(String),

    #[error("Bootstrap error: no known peers")]
    BootstrapNoPeers,

    #[error("Channel closed")]
    ChannelClosed,

    #[error("Swarm build error: {0}")]
    SwarmBuild(String),

    #[error("Not connected to peer: {0}")]
    NotConnected(PeerId),

    #[error("Send error: {0}")]
    SendError(String),
}

/// Network configuration
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Addresses to listen on
    pub listen_addrs: Vec<Multiaddr>,
    /// Bootstrap peers to connect to
    pub bootstrap_peers: Vec<(PeerId, Multiaddr)>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addrs: vec!["/ip4/0.0.0.0/tcp/0".parse().expect("valid hardcoded multiaddr")],
            bootstrap_peers: crate::bootstrap::default_bootstrap_peers(),
        }
    }
}

/// Events emitted by the network node
#[derive(Debug)]
pub enum NetworkEvent {
    /// A new peer was discovered via mDNS
    MdnsPeerDiscovered(PeerId),
    /// A peer expired from mDNS
    MdnsPeerExpired(PeerId),
    /// A new peer was discovered via Kademlia
    PeerDiscovered(PeerId),
    /// Connected to a peer
    PeerConnected(PeerId),
    /// Disconnected from a peer
    PeerDisconnected(PeerId),
    /// Listening on a new address
    Listening(Multiaddr),
    /// Bootstrap completed
    BootstrapComplete,
    /// Registered with rendezvous server
    RendezvousRegistered {
        rendezvous_peer: PeerId,
        ttl: u64,
    },
    /// Registration with rendezvous failed
    RendezvousRegisterFailed {
        rendezvous_peer: PeerId,
        error: String,
    },
    /// Discovered peers via rendezvous (bootstrap)
    RendezvousDiscovered {
        rendezvous_peer: PeerId,
        peers: Vec<(PeerId, Vec<Multiaddr>)>,
    },
    /// Exit node record retrieved from DHT
    ExitRecordFound {
        peer_id: PeerId,
        record: Vec<u8>,
    },
    /// Exit node record not found in DHT
    ExitRecordNotFound {
        peer_id: PeerId,
    },
    /// Exit record stored successfully in DHT
    ExitRecordStored {
        peer_id: PeerId,
    },
    /// Exit providers found via get_providers
    ExitProvidersFound {
        providers: Vec<PeerId>,
    },
    /// Gossipsub message received
    GossipMessage {
        source: PeerId,
        data: Vec<u8>,
    },
    /// A peer registered with our rendezvous server
    RendezvousPeerRegistered {
        peer: PeerId,
    },
}

/// Build a CraftNet swarm using the generic CraftBehaviour from craftec-network.
///
/// The swarm uses protocol prefix "craftnet" for Kademlia (`/craftnet/kad/1.0.0`),
/// identify (`/craftnet/id/1.0.0`), etc.
///
/// Returns the swarm, local peer ID, and incoming streams for the shard protocol.
pub async fn build_swarm(
    keypair: Keypair,
    config: NetworkConfig,
) -> Result<(libp2p::Swarm<CraftNetBehaviour>, PeerId, libp2p_stream::IncomingStreams), NetworkError> {
    let craftec_config = craftec_network::NetworkConfig {
        protocol_prefix: "craftnet".to_string(),
        // Enable secondary Kademlia for the exit/relay provider registry.
        // Without this, kademlia_secondary is None and all StartProviding/
        // GetProviders calls for exit and relay discovery are silently no-ops.
        secondary_protocol_prefix: Some("craftnet-reg".to_string()),
        listen_addrs: config.listen_addrs,
        bootstrap_peers: config.bootstrap_peers,
        enable_mdns: true,
    };

    let (swarm, peer_id) = craftec_network::build_swarm(keypair, craftec_config)
        .await
        .map_err(|e| NetworkError::SwarmBuild(e.to_string()))?;

    // Register shard stream protocol BEFORE any connections are established.
    // `listen_protocol()` on the connection handler captures the set of supported
    // inbound protocols at handler-creation time. If we register after connections
    // are established, those handlers won't negotiate our protocol on inbound
    // substreams and inbound streams will be silently dropped.
    let incoming_streams = swarm
        .behaviour()
        .stream_control()
        .accept(SHARD_STREAM_PROTOCOL)
        .expect("shard stream protocol not yet registered");

    info!("CraftNet swarm built with peer ID: {}", peer_id);
    Ok((swarm, peer_id, incoming_streams))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = NetworkConfig::default();
        assert!(!config.listen_addrs.is_empty());
        assert!(!config.bootstrap_peers.is_empty());
    }

    #[test]
    fn test_config_with_bootstrap() {
        let keypair = Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/9000".parse().unwrap();

        let config = NetworkConfig {
            listen_addrs: vec!["/ip4/0.0.0.0/tcp/8000".parse().unwrap()],
            bootstrap_peers: vec![(peer_id, addr)],
        };

        assert_eq!(config.listen_addrs.len(), 1);
        assert_eq!(config.bootstrap_peers.len(), 1);
    }

    #[tokio::test]
    async fn test_build_swarm() {
        let keypair = Keypair::generate_ed25519();
        let expected_peer_id = PeerId::from(keypair.public());
        let config = NetworkConfig::default();

        let result = build_swarm(keypair, config).await;
        assert!(result.is_ok());

        let (swarm, peer_id, _incoming) = result.unwrap();
        assert_eq!(peer_id, expected_peer_id);
        assert_eq!(swarm.connected_peers().count(), 0);
    }

    #[test]
    fn test_network_error_display() {
        let err = NetworkError::NotConnected(PeerId::random());
        assert!(err.to_string().contains("Not connected"));

        let err = NetworkError::BootstrapNoPeers;
        assert!(err.to_string().contains("no known peers"));
    }
}
