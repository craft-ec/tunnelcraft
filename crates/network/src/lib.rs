//! TunnelCraft Network
//!
//! libp2p integration for P2P networking (Kademlia DHT, NAT traversal).
//!
//! ## Features
//!
//! - Peer discovery via Kademlia DHT
//! - Local discovery via mDNS
//! - Decentralized discovery via rendezvous protocol
//! - NAT traversal (relay, DCUtR)
//! - Secure transport (Noise protocol)
//! - Shard routing and delivery

mod behaviour;
mod bootstrap;
mod node;
mod proof_message;
mod protocol;
mod relay_status;
mod status;
mod subscription;

pub use behaviour::{
    TunnelCraftBehaviour, TunnelCraftBehaviourEvent,
    KADEMLIA_PROTOCOL, RENDEZVOUS_NAMESPACE,
    EXIT_DHT_KEY_PREFIX, EXIT_REGISTRY_KEY, EXIT_RECORD_TTL, exit_dht_key,
    PEER_DHT_KEY_PREFIX, PEER_RECORD_TTL, peer_dht_key,
    EXIT_STATUS_TOPIC, EXIT_HEARTBEAT_INTERVAL, EXIT_OFFLINE_THRESHOLD,
    PROOF_TOPIC, SUBSCRIPTION_TOPIC,
    RELAY_DHT_KEY_PREFIX, RELAY_REGISTRY_KEY, RELAY_RECORD_TTL,
    RELAY_STATUS_TOPIC, RELAY_HEARTBEAT_INTERVAL, RELAY_OFFLINE_THRESHOLD,
    relay_dht_key,
};
pub use proof_message::{ProofMessage, PoolType, ProofStateQuery, ProofStateResponse};
pub use relay_status::{RelayStatusMessage, RelayStatusType};
pub use status::{ExitStatusMessage, ExitStatusType};
pub use subscription::SubscriptionAnnouncement;
pub use bootstrap::{
    DEFAULT_BOOTSTRAP_NODES, DEFAULT_PORT,
    default_bootstrap_peers, parse_bootstrap_nodes, parse_bootstrap_addr,
    make_bootstrap_addr, has_bootstrap_nodes,
};
pub use node::{build_swarm, NetworkConfig, NetworkEvent, NetworkError};
pub use protocol::{
    ShardProtocol, ShardCodec, ShardRequest, ShardResponse, ShardBehaviour,
    new_shard_behaviour, SHARD_PROTOCOL_ID, MAX_SHARD_SIZE,
};

// Re-export commonly used libp2p types
pub use libp2p::{Multiaddr, PeerId};
pub use libp2p::request_response::{OutboundRequestId, ResponseChannel, InboundRequestId};
