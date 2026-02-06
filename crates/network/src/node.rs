//! Network node for TunnelCraft
//!
//! Main entry point for P2P networking functionality.

use libp2p::{
    identity::Keypair,
    noise, tcp, yamux,
    request_response::{self, InboundRequestId, OutboundRequestId, ResponseChannel},
    swarm::SwarmEvent,
    Multiaddr, PeerId, SwarmBuilder,
};
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use tunnelcraft_core::Shard;

use crate::behaviour::{TunnelCraftBehaviour, TunnelCraftBehaviourEvent};
use crate::protocol::{new_shard_behaviour, ShardRequest, ShardResponse};

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

/// The main network node
pub struct NetworkNode {
    swarm: libp2p::Swarm<TunnelCraftBehaviour>,
    local_peer_id: PeerId,
    event_tx: mpsc::Sender<NetworkEvent>,
}

impl NetworkNode {
    /// Create a new network node
    pub async fn new(
        keypair: Keypair,
        config: NetworkConfig,
    ) -> Result<(Self, mpsc::Receiver<NetworkEvent>), NetworkError> {
        let local_peer_id = PeerId::from(keypair.public());
        info!("Local peer ID: {}", local_peer_id);

        // Create the behaviour - returns (behaviour, relay_transport)
        let (behaviour, relay_transport) = TunnelCraftBehaviour::new(local_peer_id, &keypair);

        // Build swarm with relay transport
        let swarm = SwarmBuilder::with_existing_identity(keypair)
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
                // We need to use the relay behaviour from with_relay_client
                // but also include our other behaviours
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

        let (event_tx, event_rx) = mpsc::channel(100);

        let mut node = Self {
            swarm,
            local_peer_id,
            event_tx,
        };

        // Start listening
        for addr in config.listen_addrs {
            node.listen_on(addr)?;
        }

        // Add bootstrap peers
        for (peer_id, addr) in config.bootstrap_peers {
            node.add_peer(peer_id, addr);
        }

        Ok((node, event_rx))
    }

    /// Get the local peer ID
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// Start listening on an address
    pub fn listen_on(&mut self, addr: Multiaddr) -> Result<(), NetworkError> {
        self.swarm
            .listen_on(addr)
            .map_err(|e| NetworkError::Listen(e.to_string()))?;
        Ok(())
    }

    /// Add a known peer
    pub fn add_peer(&mut self, peer_id: PeerId, addr: Multiaddr) {
        self.swarm.behaviour_mut().add_address(&peer_id, addr);
    }

    /// Dial a peer
    pub fn dial(&mut self, peer_id: PeerId) -> Result<(), NetworkError> {
        self.swarm
            .dial(peer_id)
            .map_err(|e| NetworkError::Dial(e.to_string()))?;
        Ok(())
    }

    /// Bootstrap the DHT
    pub fn bootstrap(&mut self) -> Result<(), NetworkError> {
        self.swarm
            .behaviour_mut()
            .bootstrap()
            .map_err(|_| NetworkError::BootstrapNoPeers)?;
        Ok(())
    }

    /// Register with a rendezvous server for peer discovery
    /// Returns an error if registration fails (e.g., no external addresses available)
    pub fn register_with_rendezvous(&mut self, rendezvous_peer: PeerId) -> Result<(), libp2p::rendezvous::client::RegisterError> {
        self.swarm
            .behaviour_mut()
            .register_with_rendezvous(rendezvous_peer)
    }

    /// Add an external address for the swarm to advertise
    /// This is needed for rendezvous registration when listening on localhost
    pub fn add_external_address(&mut self, addr: Multiaddr) {
        self.swarm.add_external_address(addr);
    }

    /// Discover peers from a rendezvous server (bootstrap only)
    pub fn discover_from_rendezvous(&mut self, rendezvous_peer: PeerId) {
        self.swarm
            .behaviour_mut()
            .discover_from_rendezvous(rendezvous_peer, None);
    }

    /// Announce this node as an exit by storing info in DHT
    /// The record should be serialized ExitInfo
    pub fn announce_exit(&mut self, record_value: Vec<u8>) {
        // Store detailed exit info
        if let Err(e) = self.swarm
            .behaviour_mut()
            .put_exit_record(&self.local_peer_id, record_value)
        {
            warn!("Failed to put exit record in DHT: {:?}", e);
        }
        // Also register as provider (lightweight announcement)
        if let Err(e) = self.swarm.behaviour_mut().start_providing_exit() {
            warn!("Failed to start providing exit: {:?}", e);
        }
    }

    /// Stop announcing as exit
    pub fn stop_exit_announcement(&mut self) {
        self.swarm.behaviour_mut().stop_providing_exit();
    }

    /// Query DHT for a specific exit node's info
    pub fn query_exit(&mut self, peer_id: &PeerId) {
        self.swarm.behaviour_mut().get_exit_record(peer_id);
    }

    /// Find exit nodes on the network using provider records
    /// Results come back via ExitProvidersFound events
    pub fn discover_exits(&mut self) {
        self.swarm.behaviour_mut().get_exit_providers();
    }

    /// Get the number of connected peers
    pub fn num_connected(&self) -> usize {
        self.swarm.connected_peers().count()
    }

    /// Check if connected to a specific peer
    pub fn is_connected(&self, peer_id: &PeerId) -> bool {
        self.swarm.is_connected(peer_id)
    }

    /// Get list of connected peers
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.swarm.connected_peers().cloned().collect()
    }

    /// Send a shard to a peer
    pub fn send_shard(&mut self, peer_id: PeerId, shard: Shard) -> OutboundRequestId {
        let request = ShardRequest { shard };
        self.swarm.behaviour_mut().send_shard(peer_id, request)
    }

    /// Send a response to a received shard
    pub fn respond_to_shard(
        &mut self,
        channel: ResponseChannel<ShardResponse>,
        response: ShardResponse,
    ) -> Result<(), NetworkError> {
        self.swarm
            .behaviour_mut()
            .send_shard_response(channel, response)
            .map_err(|_| NetworkError::SendError("Failed to send response".to_string()))
    }

    /// Accept a received shard
    pub fn accept_shard(
        &mut self,
        channel: ResponseChannel<ShardResponse>,
    ) -> Result<(), NetworkError> {
        self.respond_to_shard(channel, ShardResponse::Accepted)
    }

    /// Reject a received shard
    pub fn reject_shard(
        &mut self,
        channel: ResponseChannel<ShardResponse>,
        reason: String,
    ) -> Result<(), NetworkError> {
        self.respond_to_shard(channel, ShardResponse::Rejected(reason))
    }

    /// Run the network event loop
    pub async fn run(&mut self) -> Result<(), NetworkError> {
        use futures::StreamExt;

        loop {
            let event = self.swarm.select_next_some().await;
            self.handle_event(event).await?;
        }
    }

    /// Poll the swarm once and process any pending events
    /// Returns true if an event was processed, false if no events were pending
    pub async fn poll_once(&mut self) -> Result<bool, NetworkError> {
        use std::task::Poll;
        use std::pin::Pin;
        use futures::Stream;

        let swarm_stream = Pin::new(&mut self.swarm);

        // Create a dummy context for polling
        let waker = futures::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);

        match swarm_stream.poll_next(&mut cx) {
            Poll::Ready(Some(event)) => {
                self.handle_event(event).await?;
                Ok(true)
            }
            Poll::Ready(None) => Ok(false),
            Poll::Pending => Ok(false),
        }
    }

    /// Get a reference to the swarm for advanced use cases
    pub fn swarm_mut(&mut self) -> &mut libp2p::Swarm<TunnelCraftBehaviour> {
        &mut self.swarm
    }

    /// Handle a swarm event
    async fn handle_event(
        &mut self,
        event: SwarmEvent<TunnelCraftBehaviourEvent>,
    ) -> Result<(), NetworkError> {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on {}", address);
                self.emit_event(NetworkEvent::Listening(address)).await?;
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                debug!("Connected to {}", peer_id);
                self.emit_event(NetworkEvent::PeerConnected(peer_id)).await?;
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                debug!("Disconnected from {}", peer_id);
                self.emit_event(NetworkEvent::PeerDisconnected(peer_id))
                    .await?;
            }
            SwarmEvent::Behaviour(event) => {
                self.handle_behaviour_event(event).await?;
            }
            _ => {}
        }
        Ok(())
    }

    async fn handle_behaviour_event(
        &mut self,
        event: TunnelCraftBehaviourEvent,
    ) -> Result<(), NetworkError> {
        match event {
            TunnelCraftBehaviourEvent::Kademlia(kad_event) => {
                use libp2p::kad::{Event, QueryResult, GetRecordOk, PutRecordOk};
                use crate::behaviour::EXIT_DHT_KEY_PREFIX;
                match kad_event {
                    Event::RoutingUpdated { peer, .. } => {
                        debug!("Kademlia routing updated for {}", peer);
                        self.emit_event(NetworkEvent::PeerDiscovered(peer)).await?;
                    }
                    Event::OutboundQueryProgressed { result, .. } => {
                        match result {
                            QueryResult::Bootstrap(Ok(_)) => {
                                info!("Bootstrap complete");
                                self.emit_event(NetworkEvent::BootstrapComplete).await?;
                            }
                            QueryResult::GetRecord(Ok(GetRecordOk::FoundRecord(peer_record))) => {
                                let key_str = String::from_utf8_lossy(peer_record.record.key.as_ref());
                                if key_str.starts_with(EXIT_DHT_KEY_PREFIX) {
                                    // Extract peer_id from key
                                    let peer_id_str = key_str.trim_start_matches(EXIT_DHT_KEY_PREFIX);
                                    if let Ok(peer_id) = peer_id_str.parse::<PeerId>() {
                                        info!("Found exit record for {}", peer_id);
                                        self.emit_event(NetworkEvent::ExitRecordFound {
                                            peer_id,
                                            record: peer_record.record.value,
                                        }).await?;
                                    }
                                }
                            }
                            QueryResult::GetRecord(Err(err)) => {
                                let key_str = String::from_utf8_lossy(err.key().as_ref());
                                if key_str.starts_with(EXIT_DHT_KEY_PREFIX) {
                                    let peer_id_str = key_str.trim_start_matches(EXIT_DHT_KEY_PREFIX);
                                    if let Ok(peer_id) = peer_id_str.parse::<PeerId>() {
                                        debug!("Exit record not found for {}", peer_id);
                                        self.emit_event(NetworkEvent::ExitRecordNotFound { peer_id }).await?;
                                    }
                                }
                            }
                            QueryResult::PutRecord(Ok(PutRecordOk { key })) => {
                                let key_str = String::from_utf8_lossy(key.as_ref());
                                if key_str.starts_with(EXIT_DHT_KEY_PREFIX) {
                                    let peer_id_str = key_str.trim_start_matches(EXIT_DHT_KEY_PREFIX);
                                    if let Ok(peer_id) = peer_id_str.parse::<PeerId>() {
                                        info!("Exit record stored for {}", peer_id);
                                        self.emit_event(NetworkEvent::ExitRecordStored { peer_id }).await?;
                                    }
                                }
                            }
                            QueryResult::GetProviders(Ok(result)) => {
                                use libp2p::kad::GetProvidersOk;
                                match result {
                                    GetProvidersOk::FoundProviders { providers, .. } => {
                                        let provider_ids: Vec<PeerId> = providers.into_iter().collect();
                                        if !provider_ids.is_empty() {
                                            info!("Found {} exit providers", provider_ids.len());
                                            self.emit_event(NetworkEvent::ExitProvidersFound {
                                                providers: provider_ids,
                                            }).await?;
                                        }
                                    }
                                    GetProvidersOk::FinishedWithNoAdditionalRecord { .. } => {
                                        // Query finished, no more providers
                                    }
                                }
                            }
                            QueryResult::StartProviding(Ok(_)) => {
                                info!("Now providing as exit node");
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
            TunnelCraftBehaviourEvent::Identify(identify_event) => {
                use libp2p::identify::Event;
                if let Event::Received { peer_id, info, .. } = identify_event {
                    debug!("Identified peer {}: {:?}", peer_id, info.protocols);
                    for addr in info.listen_addrs {
                        self.swarm.behaviour_mut().add_address(&peer_id, addr);
                    }
                }
            }
            TunnelCraftBehaviourEvent::Mdns(mdns_event) => {
                use libp2p::mdns::Event;
                match mdns_event {
                    Event::Discovered(peers) => {
                        for (peer_id, addr) in peers {
                            info!("mDNS discovered peer {} at {}", peer_id, addr);
                            self.swarm.behaviour_mut().add_address(&peer_id, addr);
                            self.emit_event(NetworkEvent::MdnsPeerDiscovered(peer_id)).await?;
                        }
                    }
                    Event::Expired(peers) => {
                        for (peer_id, _addr) in peers {
                            debug!("mDNS peer expired: {}", peer_id);
                            self.emit_event(NetworkEvent::MdnsPeerExpired(peer_id)).await?;
                        }
                    }
                }
            }
            TunnelCraftBehaviourEvent::Gossipsub(gossip_event) => {
                use libp2p::gossipsub::Event;
                match gossip_event {
                    Event::Message { propagation_source, message, .. } => {
                        // Forward gossipsub messages for handling (exit status updates)
                        self.emit_event(NetworkEvent::GossipMessage {
                            source: propagation_source,
                            data: message.data,
                        }).await?;
                    }
                    Event::Subscribed { peer_id, topic } => {
                        debug!("Peer {} subscribed to {}", peer_id, topic);
                    }
                    Event::Unsubscribed { peer_id, topic } => {
                        debug!("Peer {} unsubscribed from {}", peer_id, topic);
                    }
                    _ => {}
                }
            }
            TunnelCraftBehaviourEvent::RendezvousClient(rendezvous_event) => {
                use libp2p::rendezvous::client::Event;
                match rendezvous_event {
                    Event::Registered { rendezvous_node, ttl, .. } => {
                        info!("Registered with rendezvous server {} (TTL: {}s)", rendezvous_node, ttl);
                        self.emit_event(NetworkEvent::RendezvousRegistered {
                            rendezvous_peer: rendezvous_node,
                            ttl,
                        }).await?;
                    }
                    Event::RegisterFailed { rendezvous_node, error, .. } => {
                        warn!("Failed to register with rendezvous {}: {:?}", rendezvous_node, error);
                        self.emit_event(NetworkEvent::RendezvousRegisterFailed {
                            rendezvous_peer: rendezvous_node,
                            error: format!("{:?}", error),
                        }).await?;
                    }
                    Event::Discovered { rendezvous_node, registrations, .. } => {
                        let peers: Vec<_> = registrations
                            .iter()
                            .map(|r| (r.record.peer_id(), r.record.addresses().to_vec()))
                            .collect();
                        info!("Discovered {} peers via rendezvous {}", peers.len(), rendezvous_node);

                        // Add discovered peers to Kademlia
                        for (peer_id, addrs) in &peers {
                            for addr in addrs {
                                self.swarm.behaviour_mut().add_address(peer_id, addr.clone());
                            }
                        }

                        self.emit_event(NetworkEvent::RendezvousDiscovered {
                            rendezvous_peer: rendezvous_node,
                            peers,
                        }).await?;
                    }
                    Event::DiscoverFailed { rendezvous_node, error, .. } => {
                        warn!("Discovery from rendezvous {} failed: {:?}", rendezvous_node, error);
                    }
                    Event::Expired { peer } => {
                        debug!("Rendezvous registration expired for {}", peer);
                    }
                }
            }
            TunnelCraftBehaviourEvent::RendezvousServer(server_event) => {
                use libp2p::rendezvous::server::Event;
                match server_event {
                    Event::PeerRegistered { peer, .. } => {
                        info!("Peer {} registered with our rendezvous server", peer);
                        self.emit_event(NetworkEvent::RendezvousPeerRegistered { peer }).await?;
                    }
                    Event::PeerNotRegistered { peer, error, .. } => {
                        debug!("Peer {} registration failed: {:?}", peer, error);
                    }
                    Event::PeerUnregistered { peer, .. } => {
                        debug!("Peer {} unregistered from our rendezvous server", peer);
                    }
                    Event::DiscoverServed { enquirer, .. } => {
                        debug!("Served discovery request from {}", enquirer);
                    }
                    Event::DiscoverNotServed { enquirer, error, .. } => {
                        debug!("Could not serve discovery to {}: {:?}", enquirer, error);
                    }
                    _ => {}
                }
            }
            TunnelCraftBehaviourEvent::RelayClient(event) => {
                debug!("Relay client event: {:?}", event);
            }
            TunnelCraftBehaviourEvent::Dcutr(event) => {
                debug!("DCUtR event: {:?}", event);
            }
            TunnelCraftBehaviourEvent::Shard(shard_event) => {
                self.handle_shard_event(shard_event).await?;
            }
        }
        Ok(())
    }

    async fn handle_shard_event(
        &mut self,
        event: request_response::Event<ShardRequest, ShardResponse>,
    ) -> Result<(), NetworkError> {
        use request_response::Event;
        use request_response::Message;

        match event {
            Event::Message { peer, message, .. } => match message {
                Message::Request {
                    request,
                    request_id,
                    channel,
                } => {
                    debug!("Received shard from {}: {:?}", peer, request.shard.shard_id);
                    self.emit_event(NetworkEvent::ShardReceived {
                        peer,
                        shard: request.shard,
                        request_id,
                        channel,
                    })
                    .await?;
                }
                Message::Response {
                    request_id,
                    response,
                } => {
                    debug!("Received response from {}: {:?}", peer, response);
                    self.emit_event(NetworkEvent::ShardResponseReceived {
                        peer,
                        request_id,
                        response,
                    })
                    .await?;
                }
            },
            Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                warn!("Failed to send shard to {}: {:?}", peer, error);
                self.emit_event(NetworkEvent::ShardSendFailed {
                    peer,
                    request_id,
                    error: format!("{:?}", error),
                })
                .await?;
            }
            Event::InboundFailure { peer, error, .. } => {
                warn!("Inbound shard failure from {}: {:?}", peer, error);
            }
            Event::ResponseSent { peer, request_id, .. } => {
                debug!("Response sent to {} for request {:?}", peer, request_id);
            }
        }
        Ok(())
    }

    async fn emit_event(&self, event: NetworkEvent) -> Result<(), NetworkError> {
        self.event_tx
            .send(event)
            .await
            .map_err(|_| NetworkError::ChannelClosed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = NetworkConfig::default();
        assert!(!config.listen_addrs.is_empty());
        assert!(config.bootstrap_peers.is_empty());
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
    async fn test_create_node() {
        let keypair = Keypair::generate_ed25519();
        let config = NetworkConfig::default();

        let result = NetworkNode::new(keypair, config).await;
        assert!(result.is_ok());

        let (node, _rx) = result.unwrap();
        assert_eq!(node.num_connected(), 0);
    }

    #[tokio::test]
    async fn test_local_peer_id() {
        let keypair = Keypair::generate_ed25519();
        let expected_peer_id = PeerId::from(keypair.public());
        let config = NetworkConfig::default();

        let (node, _rx) = NetworkNode::new(keypair, config).await.unwrap();
        assert_eq!(node.local_peer_id(), expected_peer_id);
    }

    #[tokio::test]
    async fn test_connected_peers_empty() {
        let keypair = Keypair::generate_ed25519();
        let config = NetworkConfig::default();

        let (node, _rx) = NetworkNode::new(keypair, config).await.unwrap();
        assert!(node.connected_peers().is_empty());
    }

    #[tokio::test]
    async fn test_is_connected_false() {
        let keypair = Keypair::generate_ed25519();
        let config = NetworkConfig::default();

        let (node, _rx) = NetworkNode::new(keypair, config).await.unwrap();

        let other_keypair = Keypair::generate_ed25519();
        let other_peer_id = PeerId::from(other_keypair.public());

        assert!(!node.is_connected(&other_peer_id));
    }

    #[test]
    fn test_network_error_display() {
        let err = NetworkError::NotConnected(PeerId::random());
        assert!(err.to_string().contains("Not connected"));

        let err = NetworkError::BootstrapNoPeers;
        assert!(err.to_string().contains("no known peers"));
    }
}
