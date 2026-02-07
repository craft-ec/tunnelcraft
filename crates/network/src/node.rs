//! Network node for TunnelCraft
//!
//! Main entry point for P2P networking functionality.

use libp2p::{
    identity::Keypair,
    noise, tcp, yamux,
    request_response::{InboundRequestId, OutboundRequestId, ResponseChannel},
    Multiaddr, PeerId, SwarmBuilder,
};
use thiserror::Error;
use tracing::info;
use tunnelcraft_core::Shard;

use crate::behaviour::TunnelCraftBehaviour;
use crate::protocol::{new_shard_behaviour, ShardResponse};

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
    /// Received a shard from a peer
    ShardReceived {
        peer: PeerId,
        shard: Shard,
        request_id: InboundRequestId,
        channel: ResponseChannel<ShardResponse>,
    },
    /// Shard was sent successfully
    ShardSent {
        peer: PeerId,
        request_id: OutboundRequestId,
    },
    /// Shard send failed
    ShardSendFailed {
        peer: PeerId,
        request_id: OutboundRequestId,
        error: String,
    },
    /// Received response to our shard send
    ShardResponseReceived {
        peer: PeerId,
        request_id: OutboundRequestId,
        response: ShardResponse,
    },
}

/// Build a raw swarm and return it along with the local peer ID.
///
/// This is the recommended way to create a swarm — callers own the swarm
/// directly and drive it in their own event loop (no intermediate wrapper).
pub async fn build_swarm(
    keypair: Keypair,
    config: NetworkConfig,
) -> Result<(libp2p::Swarm<TunnelCraftBehaviour>, PeerId), NetworkError> {
    let local_peer_id = PeerId::from(keypair.public());
    info!("Local peer ID: {}", local_peer_id);

    // Create the behaviour - returns (behaviour, relay_transport)
    let (behaviour, relay_transport) = TunnelCraftBehaviour::new(local_peer_id, &keypair);

    // Build swarm with relay transport
    let mut swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| NetworkError::Transport(e.to_string()))?
        .with_relay_client(noise::Config::new, yamux::Config::default)
        .map_err(|e| NetworkError::Transport(e.to_string()))?
        .with_behaviour(|_key, relay_behaviour| {
            Ok(TunnelCraftBehaviour {
                kademlia: behaviour.kademlia,
                identify: behaviour.identify,
                mdns: behaviour.mdns,
                gossipsub: behaviour.gossipsub,
                rendezvous_client: behaviour.rendezvous_client,
                rendezvous_server: behaviour.rendezvous_server,
                relay_client: relay_behaviour,
                dcutr: behaviour.dcutr,
                shard: new_shard_behaviour(),
            })
        })
        .map_err(|e| NetworkError::SwarmBuild(format!("{:?}", e)))?
        .build();

    // Drop the unused relay_transport from our manual creation
    drop(relay_transport);

    // Start listening
    for addr in config.listen_addrs {
        swarm
            .listen_on(addr)
            .map_err(|e| NetworkError::Listen(e.to_string()))?;
    }

    // Add bootstrap peers
    for (peer_id, addr) in config.bootstrap_peers {
        swarm.behaviour_mut().add_address(&peer_id, addr);
    }

    Ok((swarm, local_peer_id))
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

        let (swarm, peer_id) = result.unwrap();
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
