//! Network behaviour for TunnelCraft
//!
//! Combines Kademlia DHT, Identify, mDNS, rendezvous, relay protocols, and shard exchange.

use libp2p::{
    dcutr, gossipsub, identify, kad, mdns, relay, rendezvous,
    request_response::{self, OutboundRequestId, ResponseChannel},
    swarm::NetworkBehaviour,
    Multiaddr, PeerId, StreamProtocol,
};
use std::time::Duration;

use crate::protocol::{new_shard_behaviour, ShardBehaviour, ShardRequest, ShardResponse};

/// Kademlia protocol name
pub const KADEMLIA_PROTOCOL: StreamProtocol = StreamProtocol::new("/tunnelcraft/kad/1.0.0");

/// Rendezvous namespace for TunnelCraft nodes (bootstrap only)
pub const RENDEZVOUS_NAMESPACE: &str = "tunnelcraft";

/// DHT key prefix for exit node records
pub const EXIT_DHT_KEY_PREFIX: &str = "/tunnelcraft/exits/";

/// DHT key prefix for peer pubkey → PeerId records
/// Used by clients to announce themselves so relays can route response shards
pub const PEER_DHT_KEY_PREFIX: &str = "/tunnelcraft/peers/";

/// TTL for peer records (5 minutes, same as exit records)
pub const PEER_RECORD_TTL: Duration = Duration::from_secs(300);

/// Generate DHT key for an exit node's info record
pub fn exit_dht_key(peer_id: &PeerId) -> Vec<u8> {
    format!("{}{}", EXIT_DHT_KEY_PREFIX, peer_id).into_bytes()
}

/// Generate DHT key for a peer's pubkey → PeerId record
pub fn peer_dht_key(pubkey: &[u8; 32]) -> Vec<u8> {
    format!("{}{}", PEER_DHT_KEY_PREFIX, hex::encode(pubkey)).into_bytes()
}

/// Well-known DHT key for the exit node registry
/// Nodes query this to get the list of known exit peer IDs
pub const EXIT_REGISTRY_KEY: &[u8] = b"/tunnelcraft/exit-registry";

/// TTL for exit records (5 minutes)
/// Exits re-announce every 2 minutes, so 5 min gives 2.5x safety margin
/// Shorter TTL optimized for mobile churn - faster dead exit detection
pub const EXIT_RECORD_TTL: Duration = Duration::from_secs(300);

/// Gossipsub topic for exit node status (heartbeat, load, online/offline)
pub const EXIT_STATUS_TOPIC: &str = "tunnelcraft/exit-status/1.0.0";

/// Heartbeat interval for exit nodes (30 seconds)
pub const EXIT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Consider exit offline if no heartbeat for this duration (90 seconds = 3 missed heartbeats)
pub const EXIT_OFFLINE_THRESHOLD: Duration = Duration::from_secs(90);

/// Combined network behaviour for TunnelCraft nodes
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "TunnelCraftBehaviourEvent")]
pub struct TunnelCraftBehaviour {
    /// Kademlia DHT for peer discovery
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    /// Identify protocol for peer info exchange
    pub identify: identify::Behaviour,
    /// mDNS for local network discovery
    pub mdns: mdns::tokio::Behaviour,
    /// Gossipsub for exit status updates (heartbeat, load, online/offline)
    pub gossipsub: gossipsub::Behaviour,
    /// Rendezvous client for decentralized discovery
    pub rendezvous_client: rendezvous::client::Behaviour,
    /// Rendezvous server (nodes can act as rendezvous points)
    pub rendezvous_server: rendezvous::server::Behaviour,
    /// Relay client for NAT traversal
    pub relay_client: relay::client::Behaviour,
    /// DCUtR for direct connection upgrade
    pub dcutr: dcutr::Behaviour,
    /// Shard exchange protocol
    pub shard: ShardBehaviour,
}

/// Events emitted by TunnelCraft behaviour
#[derive(Debug)]
pub enum TunnelCraftBehaviourEvent {
    Kademlia(kad::Event),
    Identify(identify::Event),
    Mdns(mdns::Event),
    Gossipsub(gossipsub::Event),
    RendezvousClient(rendezvous::client::Event),
    RendezvousServer(rendezvous::server::Event),
    RelayClient(relay::client::Event),
    Dcutr(dcutr::Event),
    Shard(request_response::Event<ShardRequest, ShardResponse>),
}

impl From<kad::Event> for TunnelCraftBehaviourEvent {
    fn from(e: kad::Event) -> Self {
        TunnelCraftBehaviourEvent::Kademlia(e)
    }
}

impl From<identify::Event> for TunnelCraftBehaviourEvent {
    fn from(e: identify::Event) -> Self {
        TunnelCraftBehaviourEvent::Identify(e)
    }
}

impl From<mdns::Event> for TunnelCraftBehaviourEvent {
    fn from(e: mdns::Event) -> Self {
        TunnelCraftBehaviourEvent::Mdns(e)
    }
}

impl From<gossipsub::Event> for TunnelCraftBehaviourEvent {
    fn from(e: gossipsub::Event) -> Self {
        TunnelCraftBehaviourEvent::Gossipsub(e)
    }
}

impl From<rendezvous::client::Event> for TunnelCraftBehaviourEvent {
    fn from(e: rendezvous::client::Event) -> Self {
        TunnelCraftBehaviourEvent::RendezvousClient(e)
    }
}

impl From<rendezvous::server::Event> for TunnelCraftBehaviourEvent {
    fn from(e: rendezvous::server::Event) -> Self {
        TunnelCraftBehaviourEvent::RendezvousServer(e)
    }
}

impl From<relay::client::Event> for TunnelCraftBehaviourEvent {
    fn from(e: relay::client::Event) -> Self {
        TunnelCraftBehaviourEvent::RelayClient(e)
    }
}

impl From<dcutr::Event> for TunnelCraftBehaviourEvent {
    fn from(e: dcutr::Event) -> Self {
        TunnelCraftBehaviourEvent::Dcutr(e)
    }
}

impl From<request_response::Event<ShardRequest, ShardResponse>> for TunnelCraftBehaviourEvent {
    fn from(e: request_response::Event<ShardRequest, ShardResponse>) -> Self {
        TunnelCraftBehaviourEvent::Shard(e)
    }
}

impl TunnelCraftBehaviour {
    /// Create a new TunnelCraft behaviour
    ///
    /// Returns the behaviour and the relay transport that must be layered on the base transport
    pub fn new(
        local_peer_id: PeerId,
        keypair: &libp2p::identity::Keypair,
    ) -> (Self, relay::client::Transport) {
        // Kademlia configuration
        let mut kad_config = kad::Config::new(KADEMLIA_PROTOCOL);
        kad_config.set_query_timeout(Duration::from_secs(60));

        let store = kad::store::MemoryStore::new(local_peer_id);
        let kademlia = kad::Behaviour::with_config(local_peer_id, store, kad_config);

        // Identify configuration
        let identify_config = identify::Config::new(
            "/tunnelcraft/id/1.0.0".to_string(),
            keypair.public(),
        )
        .with_agent_version(format!("tunnelcraft/{}", env!("CARGO_PKG_VERSION")));
        let identify = identify::Behaviour::new(identify_config);

        // mDNS for local network discovery
        let mdns = mdns::tokio::Behaviour::new(
            mdns::Config::default(),
            local_peer_id,
        ).expect("Failed to create mDNS behaviour");

        // Gossipsub for exit status updates
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(10))
            .validation_mode(gossipsub::ValidationMode::Permissive)
            .message_id_fn(|msg: &gossipsub::Message| {
                // Use hash of data + source for deduplication
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                msg.data.hash(&mut hasher);
                if let Some(peer) = &msg.source {
                    Hash::hash(peer, &mut hasher);
                }
                gossipsub::MessageId::from(hasher.finish().to_be_bytes().to_vec())
            })
            .build()
            .expect("Valid gossipsub config");

        let gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(keypair.clone()),
            gossipsub_config,
        ).expect("Failed to create gossipsub behaviour");

        // Rendezvous client for decentralized discovery
        let rendezvous_client = rendezvous::client::Behaviour::new(keypair.clone());

        // Rendezvous server (any node can be a rendezvous point)
        let rendezvous_server = rendezvous::server::Behaviour::new(
            rendezvous::server::Config::default(),
        );

        // Relay client - returns (Transport, Behaviour)
        let (relay_transport, relay_client) = relay::client::new(local_peer_id);

        // DCUtR for direct connection upgrade
        let dcutr = dcutr::Behaviour::new(local_peer_id);

        // Shard exchange protocol
        let shard = new_shard_behaviour();

        let behaviour = Self {
            kademlia,
            identify,
            mdns,
            gossipsub,
            rendezvous_client,
            rendezvous_server,
            relay_client,
            dcutr,
            shard,
        };

        (behaviour, relay_transport)
    }

    /// Subscribe to the exit status topic
    pub fn subscribe_exit_status(&mut self) -> Result<bool, gossipsub::SubscriptionError> {
        let topic = gossipsub::IdentTopic::new(EXIT_STATUS_TOPIC);
        self.gossipsub.subscribe(&topic)
    }

    /// Unsubscribe from the exit status topic
    pub fn unsubscribe_exit_status(&mut self) -> bool {
        let topic = gossipsub::IdentTopic::new(EXIT_STATUS_TOPIC);
        self.gossipsub.unsubscribe(&topic)
    }

    /// Publish exit status message (heartbeat, load, online/offline)
    pub fn publish_exit_status(&mut self, data: Vec<u8>) -> Result<gossipsub::MessageId, gossipsub::PublishError> {
        let topic = gossipsub::IdentTopic::new(EXIT_STATUS_TOPIC);
        self.gossipsub.publish(topic, data)
    }

    /// Register with a rendezvous server
    /// Returns an error if registration fails (e.g., no external addresses available)
    pub fn register_with_rendezvous(&mut self, rendezvous_peer: PeerId) -> Result<(), rendezvous::client::RegisterError> {
        self.rendezvous_client.register(
            rendezvous::Namespace::from_static(RENDEZVOUS_NAMESPACE),
            rendezvous_peer,
            None, // Use default TTL
        )
    }

    /// Discover peers from a rendezvous server (bootstrap only)
    pub fn discover_from_rendezvous(&mut self, rendezvous_peer: PeerId, cookie: Option<rendezvous::Cookie>) {
        self.rendezvous_client.discover(
            Some(rendezvous::Namespace::from_static(RENDEZVOUS_NAMESPACE)),
            cookie,
            None, // No limit
            rendezvous_peer,
        );
    }

    /// Store exit node info in DHT (record with exit details)
    /// Exit nodes call this to store their detailed info
    /// Record expires after EXIT_RECORD_TTL (15 minutes)
    pub fn put_exit_record(&mut self, peer_id: &PeerId, record_value: Vec<u8>) -> Result<kad::QueryId, kad::store::Error> {
        let key = kad::RecordKey::new(&exit_dht_key(peer_id));
        let expires = std::time::Instant::now() + EXIT_RECORD_TTL;
        let record = kad::Record {
            key,
            value: record_value,
            publisher: Some(*peer_id),
            expires: Some(expires),
        };
        self.kademlia.put_record(record, kad::Quorum::One)
    }

    /// Announce as exit provider (lightweight - just says "I'm an exit")
    /// Uses Kademlia's provider mechanism which scales to entire network
    pub fn start_providing_exit(&mut self) -> Result<kad::QueryId, kad::store::Error> {
        let key = kad::RecordKey::new(&EXIT_REGISTRY_KEY);
        self.kademlia.start_providing(key)
    }

    /// Stop announcing as exit provider
    pub fn stop_providing_exit(&mut self) {
        let key = kad::RecordKey::new(&EXIT_REGISTRY_KEY);
        self.kademlia.stop_providing(&key);
    }

    /// Query DHT for an exit node's detailed info
    pub fn get_exit_record(&mut self, peer_id: &PeerId) -> kad::QueryId {
        let key = kad::RecordKey::new(&exit_dht_key(peer_id));
        self.kademlia.get_record(key)
    }

    /// Find all exit providers in the network
    /// Returns providers who called start_providing_exit()
    pub fn get_exit_providers(&mut self) -> kad::QueryId {
        let key = kad::RecordKey::new(&EXIT_REGISTRY_KEY);
        self.kademlia.get_providers(key)
    }

    /// Store a peer's signing pubkey → PeerId mapping in DHT
    /// Clients call this so relays can route response shards by destination lookup
    pub fn put_peer_record(&mut self, pubkey: &[u8; 32], peer_id: &PeerId) -> Result<kad::QueryId, kad::store::Error> {
        let key = kad::RecordKey::new(&peer_dht_key(pubkey));
        let expires = std::time::Instant::now() + PEER_RECORD_TTL;
        let record = kad::Record {
            key,
            value: peer_id.to_bytes(),
            publisher: Some(*peer_id),
            expires: Some(expires),
        };
        self.kademlia.put_record(record, kad::Quorum::One)
    }

    /// Query DHT for a peer's PeerId by their signing pubkey
    pub fn get_peer_record(&mut self, pubkey: &[u8; 32]) -> kad::QueryId {
        let key = kad::RecordKey::new(&peer_dht_key(pubkey));
        self.kademlia.get_record(key)
    }

    /// Add a known peer address to Kademlia
    pub fn add_address(&mut self, peer_id: &PeerId, addr: Multiaddr) {
        self.kademlia.add_address(peer_id, addr);
    }

    /// Bootstrap the Kademlia DHT
    pub fn bootstrap(&mut self) -> Result<kad::QueryId, kad::NoKnownPeers> {
        self.kademlia.bootstrap()
    }

    /// Send a shard to a peer
    pub fn send_shard(&mut self, peer_id: PeerId, request: ShardRequest) -> OutboundRequestId {
        self.shard.send_request(&peer_id, request)
    }

    /// Send a response to a shard request
    pub fn send_shard_response(
        &mut self,
        channel: ResponseChannel<ShardResponse>,
        response: ShardResponse,
    ) -> Result<(), ShardResponse> {
        self.shard.send_response(channel, response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;

    #[test]
    fn test_kademlia_protocol() {
        assert_eq!(KADEMLIA_PROTOCOL.as_ref(), "/tunnelcraft/kad/1.0.0");
    }

    #[test]
    fn test_behaviour_creation() {
        let keypair = Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());
        let (behaviour, _transport) = TunnelCraftBehaviour::new(peer_id, &keypair);

        // Verify all sub-behaviours are created
        let _ = &behaviour.kademlia;
        let _ = &behaviour.identify;
        let _ = &behaviour.mdns;
        let _ = &behaviour.rendezvous_client;
        let _ = &behaviour.rendezvous_server;
        let _ = &behaviour.relay_client;
        let _ = &behaviour.dcutr;
        let _ = &behaviour.shard;
    }

    #[test]
    fn test_rendezvous_namespace() {
        assert_eq!(RENDEZVOUS_NAMESPACE, "tunnelcraft");
    }

    #[test]
    fn test_add_address() {
        let keypair = Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());
        let (mut behaviour, _transport) = TunnelCraftBehaviour::new(peer_id, &keypair);

        let other_keypair = Keypair::generate_ed25519();
        let other_peer_id = PeerId::from(other_keypair.public());
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/9000".parse().unwrap();

        behaviour.add_address(&other_peer_id, addr);
    }

    #[test]
    fn test_event_from_kad() {
        // Just verify the From impl compiles
        fn _check_from(e: kad::Event) -> TunnelCraftBehaviourEvent {
            e.into()
        }
    }

    #[test]
    fn test_event_from_identify() {
        fn _check_from(e: identify::Event) -> TunnelCraftBehaviourEvent {
            e.into()
        }
    }

    #[test]
    fn test_event_from_mdns() {
        fn _check_from(e: mdns::Event) -> TunnelCraftBehaviourEvent {
            e.into()
        }
    }

    #[test]
    fn test_event_from_rendezvous_client() {
        fn _check_from(e: rendezvous::client::Event) -> TunnelCraftBehaviourEvent {
            e.into()
        }
    }

    #[test]
    fn test_event_from_rendezvous_server() {
        fn _check_from(e: rendezvous::server::Event) -> TunnelCraftBehaviourEvent {
            e.into()
        }
    }

    #[test]
    fn test_event_from_relay() {
        fn _check_from(e: relay::client::Event) -> TunnelCraftBehaviourEvent {
            e.into()
        }
    }

    #[test]
    fn test_event_from_dcutr() {
        fn _check_from(e: dcutr::Event) -> TunnelCraftBehaviourEvent {
            e.into()
        }
    }

    #[test]
    fn test_event_from_shard() {
        fn _check_from(
            e: request_response::Event<ShardRequest, ShardResponse>,
        ) -> TunnelCraftBehaviourEvent {
            e.into()
        }
    }
}
