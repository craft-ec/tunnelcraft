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
mod protocol;
mod status;

pub use behaviour::{
    TunnelCraftBehaviour, TunnelCraftBehaviourEvent,
    KADEMLIA_PROTOCOL, RENDEZVOUS_NAMESPACE,
    EXIT_DHT_KEY_PREFIX, EXIT_REGISTRY_KEY, EXIT_RECORD_TTL, exit_dht_key,
    EXIT_STATUS_TOPIC, EXIT_HEARTBEAT_INTERVAL, EXIT_OFFLINE_THRESHOLD,
};
pub use status::{ExitStatusMessage, ExitStatusType};
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
