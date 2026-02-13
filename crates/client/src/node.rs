//! Unified TunnelCraft Node
//!
//! A single component that supports three modes:
//! - Client: Route your traffic through the VPN (spend credits)
//! - Node: Relay traffic for others (earn credits)
//! - Both: Use VPN + help the network (spend & earn)
//!
//! The VPN extension runs in all modes for persistent P2P connectivity,
//! but traffic routing is only active in Client/Both modes.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{BufRead, Write as IoWrite};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use libp2p::identity::Keypair;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId};
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use tunnelcraft_core::{Capabilities, ExitInfo, ExitRegion, ForwardReceipt, HopMode, Id, PublicKey, RelayInfo, Shard, TunnelMetadata};
use tunnelcraft_crypto::{SigningKeypair, EncryptionKeypair};
use tunnelcraft_erasure::{ErasureCoder, DATA_SHARDS, TOTAL_SHARDS};
use tunnelcraft_erasure::chunker::reassemble;
use tunnelcraft_exit::{ExitConfig, ExitHandler};
use tunnelcraft_network::{
    build_swarm, NetworkConfig, ShardResponse, TunnelCraftBehaviour,
    TunnelCraftBehaviourEvent, ExitStatusMessage, ExitStatusType,
    RelayStatusMessage, RelayStatusType,
    ProofMessage, PoolType,
    SubscriptionAnnouncement, SUBSCRIPTION_TOPIC,

    EXIT_HEARTBEAT_INTERVAL, EXIT_OFFLINE_THRESHOLD,
    RELAY_HEARTBEAT_INTERVAL, RELAY_OFFLINE_THRESHOLD,
    EXIT_STATUS_TOPIC, RELAY_STATUS_TOPIC, PROOF_TOPIC,
    AGGREGATOR_SYNC_TOPIC, HistorySyncRequest, HistorySyncResponse,
    StreamManager, InboundShard, OutboundShard,
};
use tunnelcraft_aggregator::Aggregator;
use tunnelcraft_prover::{ReceiptCompression, ReceiptCompressor};
use tunnelcraft_relay::{RelayConfig, RelayHandler};
use tunnelcraft_settlement::{SettlementClient, SettlementConfig};
#[cfg(feature = "sp1")]
use tunnelcraft_settlement::PostDistribution;

use sha2::{Sha256, Digest};

use crate::path::PathHop;
use crate::{ClientError, RequestBuilder, Result, TunnelResponse};

/// Derive a deterministic tunnel_id from two peer IDs.
/// Both sides of a connection can compute this independently.
/// `tunnel_id = SHA256(client_peer_id || gateway_peer_id || "tunnel")`
fn derive_tunnel_id(client_peer_id: &PeerId, gateway_peer_id: &PeerId) -> Id {
    let mut hasher = Sha256::new();
    hasher.update(client_peer_id.to_bytes());
    hasher.update(gateway_peer_id.to_bytes());
    hasher.update(b"tunnel");
    let result = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    id
}

/// Result from async receipt compression (spawn_blocking)
struct CompressionResult {
    pool_key: (PublicKey, PoolType),
    batch: Vec<ForwardReceipt>,
    output: std::result::Result<tunnelcraft_prover::CompressedBatch, tunnelcraft_prover::CompressionError>,
    start: Instant,
}

// === Proof state persistence types ===

/// On-disk proof state: pool_roots + pending receipts
#[derive(serde::Serialize, serde::Deserialize)]
struct ProofStateFile {
    pool_roots: HashMap<String, PoolRootState>,
    pending_receipts: Vec<PendingReceiptEntry>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PoolRootState {
    root: String,
    cumulative_bytes: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PendingReceiptEntry {
    pool_key: String,
    receipt: ForwardReceipt,
}

/// Format a pool key as "hex_pubkey:PoolType" for serialization
fn format_pool_key(pubkey: &PublicKey, pool_type: &PoolType) -> String {
    format!("{}:{:?}", hex::encode(pubkey), pool_type)
}

/// Parse a pool key from "hex_pubkey:PoolType"
fn parse_pool_key(s: &str) -> Option<(PublicKey, PoolType)> {
    let parts: Vec<&str> = s.splitn(3, ':').collect();
    if parts.len() < 2 { return None; }
    let bytes = hex::decode(parts[0]).ok()?;
    if bytes.len() != 32 { return None; }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&bytes);
    let pool_type = match parts[1] {
        "Subscribed" => PoolType::Subscribed,
        "Free" => PoolType::Free,
        _ => return None,
    };
    Some((pubkey, pool_type))
}

/// Maximum time receipts can sit in the proof queue before forcing a prove,
/// regardless of batch size. Ensures low-traffic relays still settle.
const PROOF_DEADLINE: Duration = Duration::from_secs(15 * 60); // 15 minutes

/// How often to run batch on-chain subscription verification (60 seconds)
const SUBSCRIPTION_VERIFY_INTERVAL: Duration = Duration::from_secs(60);

/// Max users to verify per batch (avoid RPC rate limits)
const SUBSCRIPTION_VERIFY_BATCH_SIZE: usize = 10;

/// Cached subscription entry for a user
#[derive(Debug, Clone)]
struct SubscriptionEntry {
    /// Subscription tier (0=Basic, 1=Standard, 2=Premium, 255=None/Free)
    tier: u8,
    /// Claimed expiry (from announcement)
    expires_at: u64,
    /// Whether this has been verified on-chain
    verified: bool,
    /// Last time we saw traffic from this user
    last_seen: std::time::Instant,
}

/// Configuration for the unified node
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Node capabilities (composable bitflags: CLIENT, RELAY, EXIT, AGGREGATOR)
    pub capabilities: Capabilities,

    /// Listen address for P2P
    pub listen_addr: Multiaddr,

    /// Bootstrap peers
    pub bootstrap_peers: Vec<(PeerId, Multiaddr)>,

    /// Privacy level (hop count)
    pub hop_mode: HopMode,

    /// Request timeout
    pub request_timeout: Duration,

    /// Allow being last hop before exit (relay config)
    pub allow_last_hop: bool,

    /// Exit node region (auto-detected or configured)
    pub exit_region: ExitRegion,

    /// Exit node country code (ISO 3166-1 alpha-2, e.g., "US", "DE")
    pub exit_country_code: Option<String>,

    /// Exit node city
    pub exit_city: Option<String>,

    /// Settlement configuration (defaults to devnet)
    pub settlement_config: SettlementConfig,

    /// Optional 32-byte ed25519 secret for deterministic signing identity.
    /// When set, the node uses this secret instead of generating a random keypair.
    pub signing_secret: Option<[u8; 32]>,

    /// Optional libp2p keypair for persistent peer ID
    /// When None, a random keypair is generated.
    pub libp2p_keypair: Option<Keypair>,

    /// Optional data directory for persisting receipts and proof state.
    /// When set, receipts are appended to `{data_dir}/receipts.jsonl`.
    pub data_dir: Option<PathBuf>,

    /// Override exit handler's blocked domains list.
    /// When None, uses the default (localhost, 127.0.0.1, 0.0.0.0).
    /// Set to Some(vec![]) to allow all destinations (useful for testing).
    pub exit_blocked_domains: Option<Vec<String>>,

    /// Proof batch size: minimum receipts before triggering compression.
    /// Lower values cause more frequent (smaller) batches. Default: 10,000.
    /// The runtime value adapts based on compression speed, but starts here.
    pub proof_batch_size: usize,

    /// Proof deadline: max time receipts can sit idle before forcing compression,
    /// even if the batch is not full. Default: 15 minutes.
    pub proof_deadline: Duration,

    /// Maintenance interval: how often `poll_once()` runs background housekeeping
    /// (heartbeats, discovery, cleanup, subscription verification, distribution posting).
    /// Default: 30 seconds.
    pub maintenance_interval: Duration,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            capabilities: Capabilities::CLIENT,
            listen_addr: "/ip4/0.0.0.0/tcp/0".parse().unwrap(),
            bootstrap_peers: Vec::new(),
            hop_mode: HopMode::Triple,
            request_timeout: Duration::from_secs(5),
            allow_last_hop: true,
            exit_region: ExitRegion::Auto,
            exit_country_code: None,
            exit_city: None,
            settlement_config: SettlementConfig::devnet_default(),
            signing_secret: None,
            libp2p_keypair: None,
            data_dir: None,
            exit_blocked_domains: None,
            proof_batch_size: 10_000,
            proof_deadline: PROOF_DEADLINE,
            maintenance_interval: Duration::from_secs(30),
        }
    }
}

/// Proof pipeline status for monitoring
#[derive(Debug, Clone, Default)]
pub struct CompressionStatus {
    pub queued: usize,
    pub compressing: bool,
    pub batches_compressed: u64,
    pub compressions_failed: u64,
    pub last_proof_duration_ms: Option<u64>,
}

/// Statistics for the node
#[derive(Debug, Clone, Default)]
pub struct NodeStats {
    /// Shards relayed for others
    pub shards_relayed: u64,

    /// Requests processed as exit node
    pub requests_exited: u64,

    /// Connected peers count
    pub peers_connected: usize,

    /// Credits earned (from relaying)
    pub credits_earned: u64,

    /// Credits spent (from using VPN)
    pub credits_spent: u64,

    /// Bytes sent through tunnel (client traffic)
    pub bytes_sent: u64,

    /// Bytes received through tunnel (client traffic)
    pub bytes_received: u64,

    /// Bytes relayed for others
    pub bytes_relayed: u64,
}

/// Status of the unified node
#[derive(Debug, Clone)]
pub struct NodeStatus {
    /// Active capabilities
    pub capabilities: Capabilities,

    /// Our peer ID
    pub peer_id: String,

    /// Is P2P network connected
    pub connected: bool,

    /// Number of connected peers
    pub peer_count: usize,

    /// Available credits
    pub credits: u64,

    /// Is traffic routing active (Client/Both mode)
    pub routing_active: bool,

    /// Is relay active (Node/Both mode)
    pub relay_active: bool,

    /// Is exit active (if enabled)
    pub exit_active: bool,

    /// Statistics
    pub stats: NodeStats,
}

/// Pending request state (for client mode)
struct PendingRequest {
    /// Collected shard payloads indexed by (chunk_index, shard_index)
    shards: HashMap<(u16, u8), Vec<u8>>,
    /// Total chunks expected for this response
    total_chunks: u16,
    response_tx: mpsc::Sender<Result<TunnelResponse>>,
    /// Exit signing pubkey for this request (for measurement updates)
    exit_pubkey: [u8; 32],
    /// Exit X25519 encryption pubkey (stored at request time for response decryption)
    exit_enc_pubkey: [u8; 32],
    /// Request size in bytes (for throughput calculation)
    request_bytes: usize,
    /// Time when request was sent
    sent_at: std::time::Instant,
}

/// Pending tunnel request state (for SOCKS5 tunnel mode)
#[allow(dead_code)]
struct PendingTunnelRequest {
    /// Collected shard payloads indexed by (chunk_index, shard_index)
    shards: HashMap<(u16, u8), Vec<u8>>,
    /// Total chunks expected for this response
    total_chunks: u16,
    /// Channel to send raw response bytes back to the SOCKS5 connection
    response_tx: mpsc::Sender<std::result::Result<Vec<u8>, ClientError>>,
    /// Exit X25519 encryption pubkey (stored at request time for response decryption)
    exit_enc_pubkey: [u8; 32],
    /// Time when request was sent
    sent_at: std::time::Instant,
}

/// A burst of TCP data from a SOCKS5 connection to be sent through the tunnel
pub struct TunnelBurst {
    /// Tunnel metadata (host, port, session_id, is_close)
    pub metadata: TunnelMetadata,
    /// Raw TCP data to send
    pub data: Vec<u8>,
    /// Channel to receive the response bytes
    pub response_tx: mpsc::Sender<std::result::Result<Vec<u8>, ClientError>>,
}

/// Base score for new exits (50% - neutral starting point)
const EXIT_BASE_SCORE: u8 = 50;

/// Exit node status tracked via gossipsub
///
/// Combines announced values (from exit's heartbeat) with measured values
/// (from actual traffic) to compute a score for exit selection.
/// New exits start at base 50% score; measurements adjust over time.
#[derive(Debug, Clone)]
struct ExitNodeStatus {
    /// Static info from DHT
    info: ExitInfo,
    /// libp2p PeerId of this exit (learned from gossipsub source)
    peer_id: Option<PeerId>,
    /// Last DHT record seen
    last_dht_seen: std::time::Instant,
    /// Last gossipsub heartbeat received
    last_heartbeat: Option<std::time::Instant>,
    /// Is exit online (received recent heartbeat)
    online: bool,

    // === Announced values (from exit's gossipsub heartbeat) ===
    /// Current load percentage (0-100)
    announced_load_percent: u8,
    /// Self-reported uplink capacity (KB/s)
    announced_uplink_kbps: u32,
    /// Self-reported downlink capacity (KB/s)
    announced_downlink_kbps: u32,
    /// Self-reported uptime in seconds
    announced_uptime_secs: u64,
    /// Region hint from announcement
    announced_region: Option<String>,

    // === Observed values (client-side tracking) ===
    /// When client first observed this exit online
    observed_online_since: Option<std::time::Instant>,

    // === Measured values (from actual traffic) ===
    /// Measured latency in ms (from request/response timing)
    measured_latency_ms: Option<u32>,
    /// Measured uplink throughput (KB/s)
    measured_uplink_kbps: Option<u32>,
    /// Measured downlink throughput (KB/s)
    measured_downlink_kbps: Option<u32>,
    /// Number of measurement samples
    measurement_samples: u32,
    /// Last measurement timestamp
    last_measurement: Option<std::time::Instant>,

    // === Combined score ===
    /// Selection score (0-100, lower = better)
    /// Starts at 50, adjusted by measurements
    score: u8,
}

impl ExitNodeStatus {
    /// Create a new exit status with base score
    fn new(info: ExitInfo) -> Self {
        let now = std::time::Instant::now();
        Self {
            info,
            peer_id: None,
            last_dht_seen: now,
            last_heartbeat: Some(now), // Treat discovery as initial heartbeat
            online: true, // Assume online until timeout
            announced_load_percent: 50,
            announced_uplink_kbps: 0,
            announced_downlink_kbps: 0,
            announced_uptime_secs: 0,
            announced_region: None,
            observed_online_since: Some(now), // Start tracking from discovery
            measured_latency_ms: None,
            measured_uplink_kbps: None,
            measured_downlink_kbps: None,
            measurement_samples: 0,
            last_measurement: None,
            score: EXIT_BASE_SCORE,
        }
    }

    /// Update announced values from heartbeat
    fn update_from_heartbeat(
        &mut self,
        load_percent: u8,
        uplink_kbps: u32,
        downlink_kbps: u32,
        uptime_secs: u64,
        region: Option<String>,
    ) {
        let now = std::time::Instant::now();
        self.last_heartbeat = Some(now);

        // Track when exit came back online (for observed uptime)
        if !self.online {
            self.observed_online_since = Some(now);
        }

        self.online = true;
        self.announced_load_percent = load_percent;
        self.announced_uplink_kbps = uplink_kbps;
        self.announced_downlink_kbps = downlink_kbps;
        self.announced_uptime_secs = uptime_secs;
        self.announced_region = region;
        self.recalculate_score();
    }

    /// Get observed uptime (how long client has seen this exit online)
    fn observed_uptime_secs(&self) -> u64 {
        self.observed_online_since
            .map(|since| since.elapsed().as_secs())
            .unwrap_or(0)
    }

    /// Update measured values from actual traffic
    fn update_measurement(&mut self, latency_ms: u32, uplink_kbps: u32, downlink_kbps: u32) {
        // Rolling average for throughput
        let samples = self.measurement_samples;

        self.measured_latency_ms = Some(if samples > 0 {
            let old = self.measured_latency_ms.unwrap_or(latency_ms);
            (old * samples + latency_ms) / (samples + 1)
        } else {
            latency_ms
        });

        self.measured_uplink_kbps = Some(if samples > 0 {
            let old = self.measured_uplink_kbps.unwrap_or(uplink_kbps);
            (old * samples + uplink_kbps) / (samples + 1)
        } else {
            uplink_kbps
        });

        self.measured_downlink_kbps = Some(if samples > 0 {
            let old = self.measured_downlink_kbps.unwrap_or(downlink_kbps);
            (old * samples + downlink_kbps) / (samples + 1)
        } else {
            downlink_kbps
        });

        self.measurement_samples = samples.saturating_add(1);
        self.last_measurement = Some(std::time::Instant::now());
        self.recalculate_score();
    }

    /// Recalculate score based on announced and measured values
    ///
    /// Score breakdown (lower = better):
    /// - Load: 0-15 points (15% weight)
    /// - Latency: 0-25 points (25% weight)
    /// - Throughput: 0-40 points (40% weight)
    /// - Uptime: 0-20 points (20% weight, longer = lower score = better)
    /// - Trust penalty: +10 if announced > 3x measured
    fn recalculate_score(&mut self) {
        // Use minimum of announced uptime and observed uptime for reliability
        let uptime_secs = self.announced_uptime_secs.min(self.observed_uptime_secs());

        // Even without traffic measurements, we can score based on uptime
        let mut score = 0u32;

        // Load factor (0-100 → 0-15 points)
        let load_score = (self.announced_load_percent as u32) * 15 / 100;
        score += load_score;

        // Uptime factor (longer uptime = lower score = better)
        // 0 hours → 20 points, 24+ hours → 0 points
        let uptime_hours = uptime_secs / 3600;
        let uptime_score = 20u32.saturating_sub(uptime_hours.min(24) as u32 * 20 / 24);
        score += uptime_score;

        if self.measurement_samples == 0 {
            // No traffic measurements yet - use uptime + load only
            // Add neutral scores for latency and throughput
            score += 12; // Neutral latency (half of 25)
            score += 20; // Neutral throughput (half of 40)
            self.score = score.min(100) as u8;
            return;
        }

        // Latency factor (0-500ms → 0-25 points, lower is better)
        if let Some(latency) = self.measured_latency_ms {
            let latency_score = latency.min(500) * 25 / 500;
            score += latency_score;
        } else {
            score += 12; // Unknown latency = neutral
        }

        // Throughput factor (higher is better, 0-40 points total)
        // Convert to inverse score (high throughput = low score)
        let throughput_score = match (self.measured_uplink_kbps, self.measured_downlink_kbps) {
            (Some(up), Some(down)) => {
                let avg_kbps = (up + down) / 2;
                // 0-50000 KB/s (50MB/s) → 40-0 points
                40u32.saturating_sub(avg_kbps.min(50000) * 40 / 50000)
            }
            _ => 20, // Unknown throughput = neutral
        };
        score += throughput_score;

        // Check for trust issues (announced vs measured discrepancy)
        if let Some(measured_down) = self.measured_downlink_kbps {
            if self.announced_downlink_kbps > 0 && measured_down < self.announced_downlink_kbps / 3 {
                // Exit claims 3x more than measured - penalty
                score += 10;
            }
        }

        self.score = score.min(100) as u8;
    }
}

/// Relay node status tracked via DHT + gossipsub heartbeats
///
/// Scoring formula (lower = better):
/// - load: 30% weight (0-30 points)
/// - queue: 20% weight (0-20 points)
/// - bandwidth: 30% weight (0-30 points, inverted — high bw = low score)
/// - uptime: 20% weight (0-20 points, inverted — long uptime = low score)
#[derive(Debug, Clone)]
struct RelayNodeStatus {
    info: RelayInfo,
    peer_id: PeerId,
    online: bool,
    score: u8,
    // Load metrics from heartbeats
    load_percent: u8,
    active_connections: u32,
    queue_depth: u32,
    bandwidth_kbps: u32,
    uptime_secs: u64,
    last_heartbeat: Option<std::time::Instant>,
    last_dht_seen: std::time::Instant,
}

impl RelayNodeStatus {
    fn new(info: RelayInfo, peer_id: PeerId) -> Self {
        let now = std::time::Instant::now();
        Self {
            info,
            peer_id,
            online: true,
            score: 50,
            load_percent: 50,
            active_connections: 0,
            queue_depth: 0,
            bandwidth_kbps: 0,
            uptime_secs: 0,
            last_heartbeat: Some(now), // Treat discovery as initial heartbeat
            last_dht_seen: now,
        }
    }

    fn update_from_heartbeat(
        &mut self,
        load_percent: u8,
        active_connections: u32,
        queue_depth: u32,
        bandwidth_kbps: u32,
        uptime_secs: u64,
    ) {
        self.last_heartbeat = Some(std::time::Instant::now());
        if !self.online {
            self.online = true;
        }
        self.load_percent = load_percent;
        self.active_connections = active_connections;
        self.queue_depth = queue_depth;
        self.bandwidth_kbps = bandwidth_kbps;
        self.uptime_secs = uptime_secs;
        self.recalculate_score();
    }

    /// Score: load 30%, queue 20%, bandwidth 30% (inverted), uptime 20% (inverted)
    fn recalculate_score(&mut self) {
        let mut score = 0u32;

        // Load factor (0-100 → 0-30 points)
        score += (self.load_percent as u32) * 30 / 100;

        // Queue factor (0-1000 → 0-20 points)
        score += self.queue_depth.min(1000) * 20 / 1000;

        // Bandwidth factor (inverted: high bw = low score = better)
        // 0-100000 KB/s → 30-0 points
        score += 30u32.saturating_sub(self.bandwidth_kbps.min(100_000) * 30 / 100_000);

        // Uptime factor (inverted: long uptime = low score = better)
        // 0-86400s (24h) → 20-0 points
        let uptime_capped = self.uptime_secs.min(86400) as u32;
        score += 20u32.saturating_sub(uptime_capped * 20 / 86400);

        self.score = score.min(100) as u8;
    }
}

/// NAT status detected via AutoNAT
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NatStatus {
    /// Not yet determined
    Unknown,
    /// Publicly reachable
    Public,
    /// Behind NAT (not directly reachable)
    Private,
}

/// Result from a spawned exit processing task.
#[allow(dead_code)]
struct ExitTaskResult {
    handler: ExitHandler,
    shard_pairs: Vec<(Shard, Option<Vec<u8>>)>,
    process_ms: u128,
}

/// Internal state that needs synchronization
struct NodeState {
    stats: NodeStats,
    relay_handler: Option<RelayHandler>,
    exit_handler: Option<ExitHandler>,
}

/// Unified TunnelCraft Node
///
/// Combines client SDK and node service into a single component
/// with flexible mode switching.
pub struct TunnelCraftNode {
    /// Active capabilities (composable bitflags)
    capabilities: Capabilities,

    /// Configuration
    config: NodeConfig,

    /// Signing keypair for shards
    keypair: SigningKeypair,

    /// Encryption keypair for onion routing (X25519)
    encryption_keypair: EncryptionKeypair,

    /// libp2p keypair
    libp2p_keypair: Keypair,

    /// libp2p swarm (owned directly — no intermediate wrapper)
    swarm: Option<libp2p::Swarm<TunnelCraftBehaviour>>,

    /// Our local peer ID (set after start)
    local_peer_id: Option<PeerId>,

    /// Whether P2P is connected
    connected: bool,

    /// Available credits
    credits: u64,

    /// Known exit nodes with status info (for client mode)
    /// Key: pubkey, Value: ExitNodeStatus
    exit_nodes: HashMap<[u8; 32], ExitNodeStatus>,

    /// Selected exit node
    selected_exit: Option<ExitInfo>,

    /// Pending requests (client mode)
    pending: HashMap<Id, PendingRequest>,

    /// Erasure coder
    erasure: ErasureCoder,

    /// DHT-verified relay nodes with load scores (pubkey → status)
    relay_nodes: HashMap<[u8; 32], RelayNodeStatus>,

    /// Unverified relay peers (from ConnectionEstablished, mDNS — not yet confirmed as relays)
    unverified_relay_peers: Vec<PeerId>,

    /// Last relay announcement time (for periodic re-announcement)
    last_relay_announcement: Option<std::time::Instant>,
    /// Last relay heartbeat sent time
    last_relay_heartbeat_sent: Option<std::time::Instant>,
    /// Pending relay provider query IDs (to distinguish from exit queries)
    pending_relay_provider_queries: HashSet<libp2p::kad::QueryId>,
    /// Pending exit provider query IDs (to distinguish from relay queries)
    pending_exit_provider_queries: HashSet<libp2p::kad::QueryId>,
    /// Pending relay record query IDs (to distinguish from exit record queries)
    pending_relay_record_queries: HashSet<libp2p::kad::QueryId>,

    /// Last relay discovery time (throttle DHT queries)
    last_relay_discovery: Option<std::time::Instant>,
    /// Last exit discovery time (throttle DHT queries)
    last_exit_discovery: Option<std::time::Instant>,

    /// Shared state (for async access)
    state: Arc<RwLock<NodeState>>,

    /// Last exit announcement time (for periodic re-announcement)
    last_exit_announcement: Option<std::time::Instant>,
    /// Last heartbeat sent time (for exits)
    last_heartbeat_sent: Option<std::time::Instant>,
    /// Active request count (for load calculation)
    active_requests: u32,

    // === Exit node throughput tracking (self-measurement) ===
    /// Bytes uploaded in current measurement window
    exit_bytes_up: u64,
    /// Bytes downloaded in current measurement window
    exit_bytes_down: u64,
    /// Start of current measurement window
    exit_throughput_window_start: Option<std::time::Instant>,
    /// Calculated uplink throughput (KB/s)
    exit_uplink_kbps: u32,
    /// Calculated downlink throughput (KB/s)
    exit_downlink_kbps: u32,
    /// Node start time (for uptime calculation)
    start_time: std::time::Instant,

    /// Whether mDNS local discovery is enabled
    local_discovery_enabled: bool,

    /// Bandwidth limit in kbps (None = unlimited)
    bandwidth_limit_kbps: Option<u64>,

    /// Client's preferred exit region (Auto = any region)
    exit_preference_region: ExitRegion,

    /// Client's preferred exit country code (e.g., "US", "DE")
    exit_preference_country: Option<String>,

    /// Client's preferred exit city
    exit_preference_city: Option<String>,

    /// Pubkey → PeerId cache for destination-based routing
    /// Populated from DHT peer records (clients announce pubkey → PeerId)
    known_peers: HashMap<[u8; 32], PeerId>,

    /// Last time we announced our pubkey → PeerId in DHT
    last_peer_announcement: Option<std::time::Instant>,

    /// Shards waiting for DHT destination lookup (pubkey → buffered shards)
    pending_destination: HashMap<[u8; 32], Vec<Shard>>,

    /// Forward receipts collected from peers proving they received our shards.
    /// Key: request_id, Value: receipts for that request's shards.
    /// Used for on-chain settlement (each receipt proves work done).
    forward_receipts: HashMap<Id, Vec<ForwardReceipt>>,

    // === Proof queue + backpressure ===

    /// Bounded proof queue: (user_pubkey, pool_type) → pending receipts awaiting compression
    proof_queue: HashMap<(PublicKey, PoolType), VecDeque<ForwardReceipt>>,
    /// Max queue size per pool before backpressure kicks in
    proof_queue_limit: usize,
    /// Map request_id → (user_pubkey, pool_type) for receipt-to-pool routing
    request_user: HashMap<Id, (PublicKey, PoolType)>,
    /// Cumulative Merkle roots per pool: (root, cumulative_bytes)
    pool_roots: HashMap<(PublicKey, PoolType), ([u8; 32], u64)>,
    /// Adaptive batch size (starts at 10K, adjusts based on compression speed)
    proof_batch_size: usize,
    /// Maximum time receipts can sit in the proof queue before forcing compression.
    /// Defaults to 15 minutes. Configurable for testing.
    proof_deadline: Duration,
    /// Compressor busy flag (set while compressing, cleared when done)
    compressor_busy: bool,
    /// Number of receipt batches compressed successfully
    batches_compressed: u64,
    /// Number of receipt compressions that failed
    compressions_failed: u64,
    /// Last compression duration (for adaptive batch sizing)
    last_proof_duration: Option<Duration>,
    /// Path to receipts file for persistence (None = in-memory only)
    receipt_file: Option<PathBuf>,
    /// Path to proof state file for persistence (None = in-memory only)
    proof_state_file: Option<PathBuf>,
    /// Counter for debouncing proof state saves after enqueue (save every 100 receipts)
    proof_enqueue_since_save: u64,
    /// Timestamp of the oldest uncompressed receipt per pool (for deadline flush)
    proof_oldest_receipt: HashMap<(PublicKey, PoolType), Instant>,
    /// Pool keys that need chain recovery (have pending receipts but no pool_roots entry).
    /// On startup, if proof state is lost, query aggregator peers for latest chain state.
    needs_chain_recovery: Vec<(PublicKey, PoolType)>,
    /// Persistent stream manager for shard transport
    stream_manager: Option<StreamManager>,
    /// High-priority inbound shard channel (subscribed peers)
    inbound_high_rx: Option<mpsc::Receiver<InboundShard>>,
    /// Low-priority inbound shard channel (free-tier peers)
    inbound_low_rx: Option<mpsc::Receiver<InboundShard>>,
    /// Buffered incoming streams from peers (bridged from libp2p-stream's 0-buffer channel)
    incoming_stream_rx: Option<mpsc::Receiver<(PeerId, libp2p::Stream)>>,
    /// Receipt channel from fire-and-forget stream acks
    stream_receipt_rx: Option<mpsc::Receiver<ForwardReceipt>>,
    /// Data plane channel: outbound shards written by background writer task
    outbound_tx: Option<mpsc::Sender<OutboundShard>>,
    /// Buffered receipts pending batch disk flush (avoids per-receipt file I/O)
    receipt_buffer: Vec<ForwardReceipt>,
    /// Channel for receiving results from spawned exit processing tasks
    exit_task_tx: mpsc::Sender<ExitTaskResult>,
    exit_task_rx: mpsc::Receiver<ExitTaskResult>,
    /// Shards queued for exit processing while handler is busy (async HTTP fetch)
    exit_shard_queue: VecDeque<Shard>,

    /// Aggregator service (collects proof messages, builds distributions)
    aggregator: Option<Aggregator>,
    /// Tracks which user_pubkeys have had distributions posted on-chain
    posted_distributions: HashSet<[u8; 32]>,
    /// Pluggable receipt compression backend (ReceiptCompressor by default)
    compressor: Arc<dyn ReceiptCompression>,
    /// Stub compressor for free-tier receipts (instant)
    stub_compressor: Arc<ReceiptCompressor>,
    /// SP1 Groth16 distribution prover (lazy-initialized, requires `sp1` feature)
    #[cfg(feature = "sp1")]
    distribution_prover: Option<tunnelcraft_prover::DistributionProver>,
    /// Channel for receiving compression results from spawn_blocking
    compression_result_rx: Option<tokio::sync::oneshot::Receiver<CompressionResult>>,
    /// Path for persisting aggregator state to disk
    aggregator_state_file: Option<PathBuf>,
    /// Path for the append-only history JSONL log
    aggregator_history_file: Option<PathBuf>,
    /// Whether on-chain reconciliation has been performed after loading aggregator from disk
    aggregator_reconciled: bool,

    /// Subscription cache: user pubkey → subscription info
    /// Populated from gossipsub announcements, verified on-chain periodically
    subscription_cache: HashMap<PublicKey, SubscriptionEntry>,
    /// Settlement client for on-chain subscription verification
    settlement_client: Option<Arc<SettlementClient>>,
    /// Last time we ran batch subscription verification
    last_subscription_verify: Option<std::time::Instant>,

    /// NAT status detected by AutoNAT
    nat_status: NatStatus,
    /// Bootstrap peer IDs for reconnection
    bootstrap_peer_ids: Vec<PeerId>,
    /// Last time we checked bootstrap connectivity
    last_bootstrap_check: Option<std::time::Instant>,

    // === SOCKS5 tunnel mode ===

    /// Pending tunnel requests (raw byte responses, not HTTP)
    pending_tunnel: HashMap<Id, PendingTunnelRequest>,
    /// Channel for receiving tunnel bursts from SOCKS5 server
    tunnel_burst_rx: Option<mpsc::Receiver<TunnelBurst>>,

    /// Topology graph for onion path selection (populated from relay/exit discovery)
    topology: crate::path::TopologyGraph,

    /// Maintenance interval (from config)
    maintenance_interval: Duration,
    /// Last time maintenance was run (for auto-maintenance in poll_once)
    last_maintenance: Instant,
}

impl TunnelCraftNode {
    /// Create a new unified node
    pub fn new(config: NodeConfig) -> Result<Self> {
        let enable_aggregator = config.capabilities.is_aggregator();
        let proof_batch_size = config.proof_batch_size;
        let proof_deadline = config.proof_deadline;
        let maintenance_interval = config.maintenance_interval;
        let keypair = match config.signing_secret {
            Some(ref secret) => SigningKeypair::from_secret_bytes(secret),
            None => SigningKeypair::generate(),
        };
        let encryption_keypair = EncryptionKeypair::generate();
        let libp2p_keypair = config.libp2p_keypair.clone().unwrap_or_else(Keypair::generate_ed25519);
        let erasure =
            ErasureCoder::new().map_err(|e| ClientError::ErasureError(e.to_string()))?;

        let state = Arc::new(RwLock::new(NodeState {
            stats: NodeStats::default(),
            relay_handler: None,
            exit_handler: None,
        }));

        let (exit_task_tx, exit_task_rx) = mpsc::channel(4);

        // Set up receipt and proof state persistence (unique files per peer ID)
        let peer_id = PeerId::from(libp2p_keypair.public());
        let receipt_file = config.data_dir.as_ref().map(|dir| {
            dir.join(format!("receipts-{}.jsonl", peer_id))
        });
        let proof_state_file = config.data_dir.as_ref().map(|dir| {
            dir.join(format!("proof-state-{}.json", peer_id))
        });
        let aggregator_state_file = config.data_dir.as_ref().map(|dir| {
            dir.join(format!("aggregator-state-{}.json", peer_id))
        });
        let aggregator_history_file = config.data_dir.as_ref().map(|dir| {
            dir.join(format!("aggregator-history-{}.bin", peer_id))
        });

        // Load existing receipts from disk
        let mut forward_receipts: HashMap<Id, Vec<ForwardReceipt>> = HashMap::new();
        if let Some(ref path) = receipt_file {
            if path.exists() {
                match std::fs::File::open(path) {
                    Ok(file) => {
                        let reader = std::io::BufReader::new(file);
                        let mut loaded = 0u64;
                        for line in reader.lines().map_while(|r| r.ok()) {
                            if let Ok(receipt) = serde_json::from_str::<ForwardReceipt>(&line) {
                                forward_receipts
                                    .entry(receipt.shard_id)
                                    .or_default()
                                    .push(receipt);
                                loaded += 1;
                            }
                        }
                        if loaded > 0 {
                            info!("Loaded {} receipts from {}", loaded, path.display());
                        }
                    }
                    Err(e) => warn!("Failed to open receipts file {}: {}", path.display(), e),
                }
            }
        }

        // Load proof state (pool_roots + pending receipts) from disk
        let mut proof_queue: HashMap<(PublicKey, PoolType), VecDeque<ForwardReceipt>> = HashMap::new();
        let mut pool_roots: HashMap<(PublicKey, PoolType), ([u8; 32], u64)> = HashMap::new();
        if let Some(ref path) = proof_state_file {
            if path.exists() {
                match std::fs::read_to_string(path) {
                    Ok(contents) => {
                        if let Ok(state) = serde_json::from_str::<ProofStateFile>(&contents) {
                            for (key_str, root_state) in &state.pool_roots {
                                if let Some(pool_key) = parse_pool_key(key_str) {
                                    let mut root = [0u8; 32];
                                    if let Ok(bytes) = hex::decode(&root_state.root) {
                                        if bytes.len() == 32 {
                                            root.copy_from_slice(&bytes);
                                        }
                                    }
                                    pool_roots.insert(pool_key, (root, root_state.cumulative_bytes));
                                }
                            }
                            for pending in &state.pending_receipts {
                                if let Some(pool_key) = parse_pool_key(&pending.pool_key) {
                                    proof_queue.entry(pool_key).or_default().push_back(pending.receipt.clone());
                                }
                            }
                            info!(
                                "Loaded proof state: {} pool roots, {} pending receipts from {}",
                                pool_roots.len(),
                                proof_queue.values().map(|q| q.len()).sum::<usize>(),
                                path.display(),
                            );
                        }
                    }
                    Err(e) => warn!("Failed to read proof state file {}: {}", path.display(), e),
                }
            }
        }

        // Detect pools that need chain recovery: have queued receipts but no pool_roots entry
        let needs_chain_recovery: Vec<(PublicKey, PoolType)> = proof_queue.keys()
            .filter(|key| !pool_roots.contains_key(key))
            .copied()
            .collect();
        if !needs_chain_recovery.is_empty() {
            warn!(
                "Chain recovery needed for {} pools — will query aggregator peers on startup",
                needs_chain_recovery.len(),
            );
        }

        // Seed deadline tracker for any pools restored with pending receipts
        let proof_oldest_receipt: HashMap<(PublicKey, PoolType), Instant> = proof_queue.iter()
            .filter(|(_, q)| !q.is_empty())
            .map(|(k, _)| (*k, Instant::now()))
            .collect();

        // Will be populated if aggregator state is loaded from disk
        let mut loaded_posted_distributions: Option<HashSet<[u8; 32]>> = None;

        Ok(Self {
            capabilities: config.capabilities,
            config,
            keypair,
            encryption_keypair,
            libp2p_keypair,
            swarm: None,
            local_peer_id: None,
            connected: false,
            credits: 0,
            exit_nodes: HashMap::new(),
            selected_exit: None,
            pending: HashMap::new(),
            erasure,
            relay_nodes: HashMap::new(),
            unverified_relay_peers: Vec::new(),
            last_relay_announcement: None,
            last_relay_heartbeat_sent: None,
            pending_relay_provider_queries: HashSet::new(),
            pending_exit_provider_queries: HashSet::new(),
            pending_relay_record_queries: HashSet::new(),
            last_relay_discovery: None,
            last_exit_discovery: None,
            state,
            last_exit_announcement: None,
            last_heartbeat_sent: None,
            active_requests: 0,
            exit_bytes_up: 0,
            exit_bytes_down: 0,
            exit_throughput_window_start: None,
            exit_uplink_kbps: 0,
            exit_downlink_kbps: 0,
            start_time: std::time::Instant::now(),
            local_discovery_enabled: true,
            bandwidth_limit_kbps: None,
            exit_preference_region: ExitRegion::Auto,
            exit_preference_country: None,
            exit_preference_city: None,
            known_peers: HashMap::new(),
            last_peer_announcement: None,
            pending_destination: HashMap::new(),
            forward_receipts,
            proof_queue,
            proof_queue_limit: 100_000,
            request_user: HashMap::new(),
            pool_roots,
            proof_batch_size,
            proof_deadline,
            compressor_busy: false,
            batches_compressed: 0,
            compressions_failed: 0,
            last_proof_duration: None,
            receipt_file,
            proof_state_file,
            proof_enqueue_since_save: 0,
            proof_oldest_receipt,
            needs_chain_recovery,
            stream_manager: None,
            inbound_high_rx: None,
            inbound_low_rx: None,
            incoming_stream_rx: None,
            stream_receipt_rx: None,
            outbound_tx: None,
            receipt_buffer: Vec::new(),
            exit_task_tx,
            exit_task_rx,
            exit_shard_queue: VecDeque::new(),
            aggregator: if enable_aggregator {
                // Try loading from disk first
                let mut agg = if let Some(ref path) = aggregator_state_file {
                    if path.exists() {
                        match Aggregator::load_from_file(path) {
                            Ok((loaded_agg, posted)) => {
                                loaded_posted_distributions = Some(posted);
                                loaded_agg
                            }
                            Err(e) => {
                                warn!("Failed to load aggregator state from {}: {} — starting fresh", path.display(), e);
                                Aggregator::new()
                            }
                        }
                    } else {
                        Aggregator::new()
                    }
                } else {
                    Aggregator::new()
                };
                // Recover history sequence number from binary file (doesn't load into memory)
                if let Some(ref path) = aggregator_history_file {
                    let next_seq = Aggregator::recover_history_seq(path);
                    if next_seq > 0 {
                        agg.set_history_seq(next_seq);
                    }
                }
                Some(agg)
            } else { None },
            posted_distributions: loaded_posted_distributions.unwrap_or_default(),
            compressor: Arc::new(ReceiptCompressor::new()),
            stub_compressor: Arc::new(ReceiptCompressor::new()),
            #[cfg(feature = "sp1")]
            distribution_prover: None,
            compression_result_rx: None,
            aggregator_state_file,
            aggregator_history_file,
            aggregator_reconciled: false,
            subscription_cache: HashMap::new(),
            settlement_client: None,
            last_subscription_verify: None,
            nat_status: NatStatus::Unknown,
            bootstrap_peer_ids: Vec::new(),
            last_bootstrap_check: None,
            pending_tunnel: HashMap::new(),
            tunnel_burst_rx: None,
            topology: crate::path::TopologyGraph::new(),
            maintenance_interval,
            last_maintenance: Instant::now(),
        })
    }

    /// Get active capabilities.
    pub fn capabilities(&self) -> Capabilities {
        self.capabilities
    }

    /// Set capabilities (can be changed at runtime).
    pub fn set_capabilities(&mut self, caps: Capabilities) {
        info!("Changing capabilities from {:?} to {:?}", self.capabilities, caps);
        self.capabilities = caps;

        // Initialize handlers when service capabilities are added
        if caps.is_service_node() {
            let mut state = self.state.write();
            if caps.is_relay() && state.relay_handler.is_none() {
                let relay_config = RelayConfig {
                    can_be_last_hop: self.config.allow_last_hop,
                };
                state.relay_handler =
                    Some(RelayHandler::with_config(
                        self.keypair.clone(),
                        self.encryption_keypair.clone(),
                        relay_config,
                    ));
                info!("Relay handler initialized");
            }

            if caps.is_exit() && state.exit_handler.is_none() {
                let mut exit_config = ExitConfig {
                    timeout: self.config.request_timeout,
                    ..Default::default()
                };
                if let Some(ref blocked) = self.config.exit_blocked_domains {
                    exit_config.blocked_domains = blocked.clone();
                }
                let settlement_client = Arc::new(SettlementClient::with_secret_key(
                    self.config.settlement_config.clone(),
                    &self.keypair.secret_key_bytes(),
                ));
                match ExitHandler::with_keypairs(
                    exit_config,
                    self.keypair.clone(),
                    self.encryption_keypair.clone(),
                ) {
                    Ok(mut handler) => {
                        handler.set_settlement_client(settlement_client);
                        state.exit_handler = Some(handler);
                        info!("Exit handler initialized with devnet settlement");
                    }
                    Err(e) => error!("Failed to create exit handler: {}", e),
                }
            }
        }
    }

    /// Get our peer ID
    pub fn peer_id(&self) -> Option<PeerId> {
        self.local_peer_id
    }

    /// Get our public key
    pub fn pubkey(&self) -> [u8; 32] {
        self.keypair.public_key_bytes()
    }

    /// Start the node (connect to P2P network)
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting TunnelCraftNode with capabilities {:?}", self.capabilities);

        // Build swarm with default network config (listens on 0.0.0.0:0,
        // adds hardcoded bootstrap peers to Kademlia).
        // build_swarm() registers the shard stream protocol BEFORE listening,
        // so connection handlers on every connection will negotiate it.
        let (swarm, peer_id, mut incoming) = build_swarm(self.libp2p_keypair.clone(), NetworkConfig::default())
            .await
            .map_err(|e| ClientError::ConnectionFailed(e.to_string()))?;

        info!("Node started with peer ID: {}", peer_id);

        // Initialize persistent stream manager
        let stream_control = swarm.behaviour().stream_control();
        let (stream_mgr, high_rx, low_rx, receipt_rx, outbound_tx) =
            StreamManager::new(stream_control);
        self.stream_manager = Some(stream_mgr);
        self.inbound_high_rx = Some(high_rx);
        self.inbound_low_rx = Some(low_rx);
        self.stream_receipt_rx = Some(receipt_rx);
        self.outbound_tx = Some(outbound_tx);

        // Bridge IncomingStreams (0-buffer futures channel) into a buffered tokio
        // mpsc channel. The bridging task continuously polls IncomingStreams::next()
        // so that streams are never dropped by the zero-buffer try_send().
        {
            let (incoming_tx, incoming_rx) = mpsc::channel(256);
            tokio::spawn(async move {
                use futures::StreamExt;
                while let Some((peer, stream)) = incoming.next().await {
                    if incoming_tx.send((peer, stream)).await.is_err() {
                        break;
                    }
                }
            });
            self.incoming_stream_rx = Some(incoming_rx);
            info!("Registered for inbound shard streams");
        }

        self.local_peer_id = Some(peer_id);
        self.swarm = Some(swarm);

        // Initialize handlers based on mode
        self.set_capabilities(self.capabilities);

        // Start listening
        if let Some(ref mut swarm) = self.swarm {
            swarm
                .listen_on(self.config.listen_addr.clone())
                .map_err(|e| ClientError::ConnectionFailed(e.to_string()))?;
        }

        // Connect to bootstrap peers
        self.connect_bootstrap().await?;

        // Record bootstrap peer IDs for reconnection
        let bootstrap_peers = if !self.config.bootstrap_peers.is_empty() {
            self.config.bootstrap_peers.clone()
        } else {
            tunnelcraft_network::default_bootstrap_peers()
        };
        self.bootstrap_peer_ids = bootstrap_peers.iter().map(|(pid, _)| *pid).collect();

        // Bootstrap the Kademlia DHT so we discover peers and exit nodes
        if let Some(ref mut swarm) = self.swarm {
            match swarm.behaviour_mut().bootstrap() {
                Ok(_) => info!("Kademlia DHT bootstrap initiated"),
                Err(e) => warn!("DHT bootstrap failed (no peers?): {:?}", e),
            }
        }

        // Subscribe to exit status gossipsub topic
        if let Some(ref mut swarm) = self.swarm {
            if let Err(e) = swarm.behaviour_mut().subscribe_exit_status() {
                warn!("Failed to subscribe to exit status topic: {:?}", e);
            } else {
                debug!("Subscribed to exit status topic");
            }
        }

        // Subscribe to proof gossipsub topic (for receiving + publishing proofs)
        if let Some(ref mut swarm) = self.swarm {
            if let Err(e) = swarm.behaviour_mut().subscribe_proofs() {
                warn!("Failed to subscribe to proof topic: {:?}", e);
            } else {
                debug!("Subscribed to proof topic");
            }
        }

        // Subscribe to relay status gossipsub topic
        if let Some(ref mut swarm) = self.swarm {
            if let Err(e) = swarm.behaviour_mut().subscribe_relay_status() {
                warn!("Failed to subscribe to relay status topic: {:?}", e);
            } else {
                debug!("Subscribed to relay status topic");
            }
        }

        // Subscribe to subscription announcement topic
        if let Some(ref mut swarm) = self.swarm {
            if let Err(e) = swarm.behaviour_mut().subscribe_subscriptions() {
                warn!("Failed to subscribe to subscription topic: {:?}", e);
            } else {
                debug!("Subscribed to subscription topic");
            }
        }

        // Topology data is now carried in relay/exit heartbeats (connected_peers field),
        // so no separate topology topic subscription is needed.

        // Subscribe to aggregator sync topic (history sync for new aggregators)
        if self.aggregator.is_some() {
            if let Some(ref mut swarm) = self.swarm {
                if let Err(e) = swarm.behaviour_mut().subscribe_aggregator_sync() {
                    warn!("Failed to subscribe to aggregator sync topic: {:?}", e);
                } else {
                    debug!("Subscribed to aggregator sync topic");
                }
            }
        }

        // Create settlement client for subscription verification (Node/Both modes)
        if self.capabilities.is_service_node() {
            self.settlement_client = Some(Arc::new(SettlementClient::with_secret_key(
                self.config.settlement_config.clone(),
                &self.keypair.secret_key_bytes(),
            )));
        }

        // Announce as exit node if enabled
        if self.capabilities.is_exit() {
            self.announce_as_exit();
        }

        // Announce as relay node if in relay mode
        if self.capabilities.is_relay() {
            self.announce_as_relay();
        }

        // Announce our pubkey → PeerId in DHT so relays can route responses to us
        self.announce_as_peer();

        self.connected = true;
        Ok(())
    }

    /// Connect to bootstrap peers
    async fn connect_bootstrap(&mut self) -> Result<()> {
        if self.swarm.is_none() {
            return Ok(());
        }

        // Determine if we have explicitly configured bootstrap peers.
        // Fallback to hardcoded defaults when none are configured, but only
        // block on connection for explicit peers — nodes using defaults may be
        // bootstrap nodes themselves (or defaults may be unreachable).
        let has_explicit_peers = !self.config.bootstrap_peers.is_empty();
        let bootstrap_peers = if has_explicit_peers {
            self.config.bootstrap_peers.clone()
        } else {
            tunnelcraft_network::default_bootstrap_peers()
        };
        // Don't try to dial ourselves
        let local_peer = self.local_peer_id;
        let bootstrap_peers: Vec<_> = bootstrap_peers
            .into_iter()
            .filter(|(pid, _)| Some(*pid) != local_peer)
            .collect();

        if bootstrap_peers.is_empty() {
            info!("No bootstrap peers configured, running as bootstrap node");
            return Ok(());
        }

        for (peer_id, addr) in &bootstrap_peers {
            debug!("Connecting to bootstrap peer: {}", peer_id);
            if let Some(ref mut swarm) = self.swarm {
                swarm.behaviour_mut().add_address(peer_id, addr.clone());
                if let Err(e) = swarm.dial(*peer_id) {
                    warn!("Failed to dial bootstrap peer {}: {}", peer_id, e);
                }
            }
        }

        // Only block on connection when we have explicitly configured peers.
        // Nodes using fallback defaults may be bootstrap nodes themselves —
        // don't fail startup on unreachable default peers.
        if !has_explicit_peers {
            info!("Using default bootstrap peers — dialed best-effort");
            return Ok(());
        }

        // Wait for at least one connection to an explicit bootstrap peer
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while tokio::time::Instant::now() < deadline {
            let connected = self.swarm.as_ref().map(|s| s.connected_peers().count()).unwrap_or(0);
            if connected > 0 {
                info!("Connected to {} peers", connected);
                return Ok(());
            }
            self.poll_once().await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Err(ClientError::ConnectionFailed(
            "Failed to connect to any bootstrap peer".to_string(),
        ))
    }

    /// Wait for at least one exit node to be discovered.
    ///
    /// Triggers DHT exit provider lookup and polls the swarm until an exit
    /// is found or the timeout expires. Useful for short-lived client flows
    /// (like `fetch`) that need an exit before making a request.
    pub async fn wait_for_exit(&mut self, timeout: Duration) -> Result<()> {
        if self.selected_exit.is_some() && self.available_relay_count() >= 3 {
            return Ok(());
        }

        info!("Waiting for exit node discovery and relay peers...");

        // Trigger DHT exit + relay provider lookup
        self.discover_exits();
        self.discover_relays();

        let deadline = tokio::time::Instant::now() + timeout;
        while tokio::time::Instant::now() < deadline {
            // Need both: an exit node AND at least 3 relay peers for multi-hop
            if self.selected_exit.is_some() && self.available_relay_count() >= 3 {
                info!(
                    "Ready: exit node found, {} relay peers available",
                    self.available_relay_count(),
                );
                return Ok(());
            }
            self.poll_once().await;
        }

        if self.selected_exit.is_some() {
            let relay_count = self.available_relay_count();
            if relay_count == 0 {
                warn!("Exit found but no relay peers — shards may not route properly");
            } else {
                info!(
                    "Ready (timeout): exit found, {} relay peers",
                    relay_count,
                );
            }
            Ok(())
        } else {
            Err(ClientError::NoExitNodes)
        }
    }

    /// Wait until the node is fully ready to send requests (cold-start).
    ///
    /// Drives `poll_once()` in a loop, triggering exit and relay discovery,
    /// until `is_ready()` returns true or the timeout expires.
    ///
    /// `is_ready()` requires:
    /// - Connected to the swarm
    /// - An exit node selected with a valid encryption key
    /// - A gateway relay available and connected
    /// - An active shard stream to that gateway
    pub async fn wait_until_ready(&mut self, timeout: Duration) -> Result<()> {
        if self.is_ready() {
            return Ok(());
        }

        info!("Waiting for node to become ready (exit + relay + stream)...");

        self.discover_exits();
        self.discover_relays();

        let deadline = tokio::time::Instant::now() + timeout;
        let mut last_discovery = Instant::now();

        while tokio::time::Instant::now() < deadline {
            self.poll_once().await;

            if self.is_ready() {
                info!("Node is ready");
                return Ok(());
            }

            // Re-trigger discovery every 5s to find exits/relays faster
            if last_discovery.elapsed() >= Duration::from_secs(5) {
                last_discovery = Instant::now();
                self.discover_exits();
                self.discover_relays();
                self.run_maintenance();
            }
        }

        if self.is_ready() {
            return Ok(());
        }

        Err(ClientError::ConnectionFailed(
            "Timeout waiting for node to become ready".to_string(),
        ))
    }

    /// Stop the node
    pub async fn stop(&mut self) {
        info!("Stopping TunnelCraftNode");

        // Announce offline if we're an exit
        if self.capabilities.is_exit() {
            self.announce_offline();
        }

        // Announce relay offline if we're a relay
        if self.capabilities.is_relay() {
            self.announce_relay_offline();
        }

        self.connected = false;
        self.pending.clear();
        self.relay_nodes.clear();
        self.unverified_relay_peers.clear();
        self.swarm = None;
        self.local_peer_id = None;
    }

    /// Announce going offline via gossipsub (for exits)
    fn announce_offline(&mut self) {
        if let Some(ref mut swarm) = self.swarm {
            let peer_id_str = self.local_peer_id.map(|p| p.to_string()).unwrap_or_default();
            let msg = ExitStatusMessage::offline(
                self.keypair.public_key_bytes(),
                &peer_id_str,
            );
            if let Err(e) = swarm.behaviour_mut().publish_exit_status(msg.to_bytes()) {
                warn!("Failed to announce offline: {:?}", e);
            } else {
                debug!("Announced offline status");
            }
        }
    }

    /// Publish heartbeat via gossipsub (for exits)
    fn publish_heartbeat(&mut self) {
        if !self.capabilities.is_exit() {
            return;
        }

        // Calculate throughput from measurement window
        self.calculate_exit_throughput();

        // Calculate load percentage (0-100)
        // For now, use active_requests as a simple metric
        // Could be enhanced with CPU/memory/bandwidth metrics
        let load_percent = (self.active_requests.min(100) as u8).min(100);

        // Calculate uptime
        let uptime_secs = self.start_time.elapsed().as_secs();

        // Get region string from config
        let region = match self.config.exit_region {
            ExitRegion::Auto => self.config.exit_country_code.clone(),
            _ => Some(self.config.exit_region.code().to_string()),
        };

        let connected_peers = self.connected_stream_peers();
        if let Some(ref mut swarm) = self.swarm {
            let peer_id_str = self.local_peer_id.map(|p| p.to_string()).unwrap_or_default();
            let mut msg = ExitStatusMessage::heartbeat(
                self.keypair.public_key_bytes(),
                &peer_id_str,
                load_percent,
                self.active_requests,
                self.exit_uplink_kbps,
                self.exit_downlink_kbps,
                uptime_secs,
                region,
                connected_peers,
            );
            msg.encryption_pubkey = Some(hex::encode(self.encryption_keypair.public_key_bytes()));
            if let Err(e) = swarm.behaviour_mut().publish_exit_status(msg.to_bytes()) {
                // Don't warn on InsufficientPeers - normal during startup
                debug!("Failed to publish heartbeat: {:?}", e);
            } else {
                debug!(
                    "Published heartbeat (load: {}%, uplink: {}KB/s, downlink: {}KB/s, uptime: {}s, peers: {})",
                    load_percent, self.exit_uplink_kbps, self.exit_downlink_kbps, uptime_secs, msg.connected_peers.len()
                );
            }
        }
        self.last_heartbeat_sent = Some(std::time::Instant::now());
    }

    /// Calculate exit throughput from measurement window
    fn calculate_exit_throughput(&mut self) {
        let now = std::time::Instant::now();

        if let Some(start) = self.exit_throughput_window_start {
            let elapsed_ms = now.duration_since(start).as_millis() as u64;
            if elapsed_ms > 0 {
                // Calculate KB/s from bytes in window
                self.exit_uplink_kbps = ((self.exit_bytes_up * 1000) / elapsed_ms / 1024) as u32;
                self.exit_downlink_kbps = ((self.exit_bytes_down * 1000) / elapsed_ms / 1024) as u32;
            }
        }

        // Reset window
        self.exit_bytes_up = 0;
        self.exit_bytes_down = 0;
        self.exit_throughput_window_start = Some(now);
    }

    /// Check if we should send a heartbeat
    fn maybe_send_heartbeat(&mut self) {
        if !self.capabilities.is_exit() {
            return;
        }

        let should_send = match self.last_heartbeat_sent {
            None => true,
            Some(last) => last.elapsed() >= EXIT_HEARTBEAT_INTERVAL,
        };

        if should_send {
            self.publish_heartbeat();
        }
    }

    /// Handle incoming exit status message from gossipsub
    fn handle_exit_status(&mut self, data: &[u8], source: Option<PeerId>) {
        let Some(msg) = ExitStatusMessage::from_bytes(data) else {
            debug!("Failed to parse exit status message");
            return;
        };

        let Some(pubkey) = msg.pubkey_bytes() else {
            debug!("Invalid pubkey in exit status message");
            return;
        };

        match msg.status {
            ExitStatusType::Heartbeat => {
                // Update exit node status with announced values
                if let Some(status) = self.exit_nodes.get_mut(&pubkey) {
                    // Track PeerId from gossipsub source
                    if status.peer_id.is_none() {
                        status.peer_id = source;
                        // Keep known_peers in sync
                        if let Some(pid) = source {
                            self.known_peers.insert(pubkey, pid);
                        }
                    }
                    status.update_from_heartbeat(
                        msg.load_percent,
                        msg.uplink_kbps,
                        msg.downlink_kbps,
                        msg.uptime_secs,
                        msg.region.clone(),
                    );
                    debug!(
                        "Updated exit status for {}: load={}%, uplink={}KB/s, downlink={}KB/s, uptime={}s, score={}",
                        msg.peer_id, msg.load_percent, msg.uplink_kbps, msg.downlink_kbps, msg.uptime_secs, status.score
                    );
                } else {
                    // We don't have this exit in our DHT-discovered list yet
                    // Could optionally trigger a DHT lookup here
                    debug!(
                        "Received heartbeat from unknown exit: {} (from {:?})",
                        msg.peer_id, source
                    );
                }

                // Update topology from heartbeat's connected_peers
                if !msg.connected_peers.is_empty() {
                    if let Some(enc_hex) = &msg.encryption_pubkey {
                        if let Ok(enc_bytes) = hex::decode(enc_hex) {
                            if enc_bytes.len() == 32 {
                                use crate::path::TopologyRelay;
                                let mut enc_key = [0u8; 32];
                                enc_key.copy_from_slice(&enc_bytes);
                                let connected: HashSet<Vec<u8>> = msg.connected_peers.iter()
                                    .filter_map(|s| s.parse::<PeerId>().ok().map(|p| p.to_bytes()))
                                    .collect();
                                let peer_id_bytes = msg.peer_id.parse::<PeerId>()
                                    .map(|p| p.to_bytes())
                                    .unwrap_or_default();
                                if !peer_id_bytes.is_empty() {
                                    self.topology.update_relay(TopologyRelay {
                                        peer_id: peer_id_bytes,
                                        signing_pubkey: pubkey,
                                        encryption_pubkey: enc_key,
                                        connected_peers: connected,
                                        last_seen: std::time::Instant::now(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
            ExitStatusType::Offline => {
                // Mark exit as offline
                if let Some(status) = self.exit_nodes.get_mut(&pubkey) {
                    status.online = false;
                    info!("Exit {} went offline", msg.peer_id);

                    // If this was our selected exit, select a new one
                    if self.selected_exit.as_ref().map(|e| e.pubkey) == Some(pubkey) {
                        warn!("Selected exit went offline, selecting new exit");
                        self.select_best_exit();
                    }
                }
            }
        }
    }

    /// Select the best available exit (online, lowest score, matching geo preference)
    ///
    /// Score combines: load (20%), latency (30%), throughput (50%)
    /// Lower score = better exit.
    /// When a geo preference is set (region != Auto, or country/city specified),
    /// only exits matching the preference are considered.
    fn select_best_exit(&mut self) {
        let has_geo_preference = self.exit_preference_region != ExitRegion::Auto
            || self.exit_preference_country.is_some()
            || self.exit_preference_city.is_some();

        let candidates = self
            .exit_nodes
            .values()
            .filter(|s| s.online)
            .filter(|s| {
                if !has_geo_preference {
                    return true;
                }
                // Filter by region if set
                if self.exit_preference_region != ExitRegion::Auto
                    && s.info.region != self.exit_preference_region
                {
                    return false;
                }
                // Filter by country if set
                if let Some(ref pref_country) = self.exit_preference_country {
                    if s.info.country_code.as_deref() != Some(pref_country.as_str()) {
                        return false;
                    }
                }
                // Filter by city if set
                if let Some(ref pref_city) = self.exit_preference_city {
                    if s.info.city.as_deref() != Some(pref_city.as_str()) {
                        return false;
                    }
                }
                true
            });

        // Collect all candidates with the best (lowest) score, then pick one
        // based on local_peer_id hash so different clients spread across exits.
        let mut all: Vec<_> = candidates.collect();
        if let Some(min_score) = all.iter().map(|s| s.score).min() {
            all.retain(|s| s.score == min_score);
        }
        let best = if all.len() > 1 {
            // Deterministic but peer-specific pick: hash local_peer_id bytes
            let seed = self.local_peer_id
                .map(|p| {
                    let b = p.to_bytes();
                    b.iter().fold(0usize, |acc, &x| acc.wrapping_mul(31).wrapping_add(x as usize))
                })
                .unwrap_or(0);
            let idx = seed % all.len();
            Some(all[idx].info.clone())
        } else {
            all.first().map(|s| s.info.clone())
        };

        if let Some(exit) = best {
            let status = self.exit_nodes.get(&exit.pubkey);
            info!(
                "Selected exit: {} (score: {}, load: {}%, latency: {:?}ms, down: {:?}KB/s)",
                hex::encode(&exit.pubkey[..8]),
                status.map(|s| s.score).unwrap_or(EXIT_BASE_SCORE),
                status.map(|s| s.announced_load_percent).unwrap_or(0),
                status.and_then(|s| s.measured_latency_ms),
                status.and_then(|s| s.measured_downlink_kbps),
            );
            self.selected_exit = Some(exit);
        } else if has_geo_preference {
            warn!(
                "No exits available matching preference: region={:?}, country={:?}, city={:?}",
                self.exit_preference_region, self.exit_preference_country, self.exit_preference_city
            );
            self.selected_exit = None;
        } else {
            warn!("No online exits available");
            self.selected_exit = None;
        }
    }

    /// Mark exits as offline if no heartbeat received recently
    fn check_exit_timeouts(&mut self) {
        let now = std::time::Instant::now();
        let mut any_changed = false;

        for (_pubkey, status) in self.exit_nodes.iter_mut() {
            if status.online {
                let timed_out = status.last_heartbeat
                    .map(|t| now.duration_since(t) > EXIT_OFFLINE_THRESHOLD)
                    .unwrap_or(true); // No heartbeat ever = treat as offline after DHT TTL

                if timed_out {
                    status.online = false;
                    any_changed = true;
                    debug!("Exit timed out (no heartbeat): {}", hex::encode(&status.info.pubkey[..8]));
                }
            }
        }

        // Re-select exit if current one went offline
        if any_changed {
            if let Some(ref selected) = self.selected_exit {
                if !self.exit_nodes.get(&selected.pubkey).map(|s| s.online).unwrap_or(false) {
                    self.select_best_exit();
                }
            }
        }
    }

    /// Announce interval for exit nodes (2 minutes)
    /// DHT records expire after 5 min, so re-announce every 2 min for safety
    /// Shorter interval optimized for mobile churn
    const EXIT_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(120);

    /// Announce this node as an exit to the DHT
    fn announce_as_exit(&mut self) {
        let Some(ref mut swarm) = self.swarm else {
            warn!("Cannot announce exit: swarm not initialized");
            return;
        };

        let local_peer_id = match self.local_peer_id {
            Some(pid) => pid,
            None => {
                warn!("Cannot announce exit: no local peer ID");
                return;
            }
        };

        // Build exit info
        let exit_info = ExitInfo {
            pubkey: self.keypair.public_key_bytes(),
            address: self.config.listen_addr.to_string(),
            region: self.config.exit_region,
            country_code: self.config.exit_country_code.clone(),
            city: self.config.exit_city.clone(),
            reputation: 0, // New node starts with 0 reputation
            latency_ms: 0, // Will be measured by clients
            encryption_pubkey: Some(self.encryption_keypair.public_key_bytes()),
            peer_id: self.local_peer_id.map(|p| p.to_string()),
        };

        // Serialize to JSON
        let record = match serde_json::to_vec(&exit_info) {
            Ok(data) => data,
            Err(e) => {
                warn!("Failed to serialize exit info: {}", e);
                return;
            }
        };

        // Announce to DHT
        if let Err(e) = swarm.behaviour_mut().put_exit_record(&local_peer_id, record) {
            warn!("Failed to put exit record in DHT: {:?}", e);
        }
        if let Err(e) = swarm.behaviour_mut().start_providing_exit() {
            warn!("Failed to start providing exit: {:?}", e);
        }
        self.last_exit_announcement = Some(std::time::Instant::now());
        info!(
            "Announced as exit node: region={:?}, country={:?}, city={:?}",
            exit_info.region, exit_info.country_code, exit_info.city
        );
    }

    /// Check if exit re-announcement is needed and do it
    fn maybe_reannounce_exit(&mut self) {
        if !self.capabilities.is_exit() || !self.connected {
            return;
        }

        let should_announce = match self.last_exit_announcement {
            None => true,
            Some(last) => last.elapsed() >= Self::EXIT_ANNOUNCE_INTERVAL,
        };

        if should_announce {
            self.announce_as_exit();
        }
    }

    /// Announce this node's signing pubkey → PeerId in DHT
    /// so relays can route response shards to us by destination lookup
    fn announce_as_peer(&mut self) {
        let Some(ref mut swarm) = self.swarm else {
            return;
        };
        let Some(local_peer_id) = self.local_peer_id else {
            return;
        };

        let pubkey = self.keypair.public_key_bytes();
        if let Err(e) = swarm.behaviour_mut().put_peer_record(&pubkey, &local_peer_id) {
            warn!("Failed to put peer record in DHT: {:?}", e);
        } else {
            debug!("Announced peer record: pubkey {} → {}", hex::encode(&pubkey[..8]), local_peer_id);
        }
        self.last_peer_announcement = Some(std::time::Instant::now());
    }

    /// Re-announce peer record periodically (same interval as exit)
    fn maybe_reannounce_peer(&mut self) {
        if !self.connected {
            return;
        }

        let should_announce = match self.last_peer_announcement {
            None => true,
            Some(last) => last.elapsed() >= Self::EXIT_ANNOUNCE_INTERVAL,
        };

        if should_announce {
            self.announce_as_peer();
        }
    }

    /// Update exit node geo information (e.g., from auto-detection)
    pub fn set_exit_geo(&mut self, region: ExitRegion, country_code: Option<String>, city: Option<String>) {
        self.config.exit_region = region;
        self.config.exit_country_code = country_code;
        self.config.exit_city = city;

        // Re-announce if already connected and exit is enabled
        if self.connected && self.capabilities.is_exit() {
            self.announce_as_exit();
        }
    }

    /// Set preferred exit node geography for client mode
    ///
    /// When set, `select_best_exit()` only considers exits matching these criteria.
    /// Set region to `ExitRegion::Auto` and country/city to `None` to clear the preference.
    pub fn set_exit_preference(&mut self, region: ExitRegion, country_code: Option<String>, city: Option<String>) {
        info!(
            "Exit preference set: region={:?}, country={:?}, city={:?}",
            region, country_code, city
        );
        self.exit_preference_region = region;
        self.exit_preference_country = country_code;
        self.exit_preference_city = city;

        // Re-select exit with new preference
        self.select_best_exit();
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Check if traffic routing is active
    pub fn is_routing_active(&self) -> bool {
        self.capabilities.is_client() && self.connected
    }

    /// Check if relay is active
    pub fn is_relay_active(&self) -> bool {
        self.capabilities.is_service_node() && self.connected
    }

    /// Get current status
    pub fn status(&self) -> NodeStatus {
        let state = self.state.read();
        NodeStatus {
            capabilities: self.capabilities,
            peer_id: self
                .peer_id()
                .map(|p| p.to_string())
                .unwrap_or_default(),
            connected: self.connected,
            peer_count: self.swarm.as_ref().map(|s| s.connected_peers().count()).unwrap_or(0),
            credits: self.credits,
            routing_active: self.is_routing_active(),
            relay_active: self.is_relay_active(),
            exit_active: self.capabilities.is_exit() && state.exit_handler.is_some(),
            stats: state.stats.clone(),
        }
    }

    /// Get statistics
    pub fn stats(&self) -> NodeStats {
        self.state.read().stats.clone()
    }

    /// Set available credits
    pub fn set_credits(&mut self, credits: u64) {
        self.credits = credits;
    }

    /// Get available credits
    pub fn credits(&self) -> u64 {
        self.credits
    }

    /// Set proof batch size (number of receipts before triggering a prove).
    /// Lower values cause more frequent proofs. Useful for testing.
    pub fn set_proof_batch_size(&mut self, size: usize) {
        self.proof_batch_size = size;
    }

    /// Set proof deadline (max time receipts can sit before forcing a prove).
    /// Shorter values cause faster proof generation. Useful for testing.
    pub fn set_proof_deadline(&mut self, deadline: Duration) {
        self.proof_deadline = deadline;
    }

    /// Get total number of stored forward receipts
    pub fn receipt_count(&self) -> usize {
        self.forward_receipts.values().map(|v| v.len()).sum()
    }

    /// Get the proof queue sizes per pool
    pub fn proof_queue_sizes(&self) -> Vec<(String, usize)> {
        self.proof_queue.iter().map(|((pool, pool_type), q)| {
            (format!("{}:{:?}", hex::encode(&pool[..8]), pool_type), q.len())
        }).collect()
    }

    /// Add an exit node manually (for client mode)
    pub fn add_exit_node(&mut self, exit: ExitInfo) {
        let status = ExitNodeStatus::new(exit.clone());
        self.exit_nodes.insert(exit.pubkey, status);
        if self.selected_exit.is_none() {
            self.selected_exit = Some(exit);
        }
    }

    /// Select an exit node
    pub fn select_exit(&mut self, exit: ExitInfo) {
        self.selected_exit = Some(exit);
    }

    // =========================================================================
    // Client functionality (traffic routing)
    // =========================================================================

    /// Check if the node is ready to send requests.
    ///
    /// Returns `true` when:
    /// - Connected to the network
    /// - An exit node is selected with a valid encryption key
    /// - A gateway relay is available (swarm-connected)
    pub fn is_ready(&self) -> bool {
        if !self.connected {
            debug!("is_ready: not connected");
            return false;
        }
        // Must have a selected exit with encryption key
        let has_exit = self.selected_exit.as_ref().is_some_and(|e| {
            e.encryption_pubkey.is_some_and(|k| k != [0u8; 32])
        });
        if !has_exit {
            debug!(
                "is_ready: no exit (selected={}, has_enc_key={}, exit_nodes={})",
                self.selected_exit.is_some(),
                self.selected_exit.as_ref().and_then(|e| e.encryption_pubkey).is_some(),
                self.exit_nodes.len(),
            );
            return false;
        }
        // Must have a gateway relay we're connected to AND have a stream to it
        let our_bytes = match self.local_peer_id {
            Some(pid) => pid.to_bytes(),
            None => return false,
        };
        let gateway = self.select_gateway_relay(&our_bytes);
        if gateway.is_none() {
            debug!("is_ready: no gateway relay available");
            return false;
        }
        let (gw_peer_id, _) = gateway.unwrap();
        let has_stream = self.stream_manager.as_ref()
            .map(|sm| sm.has_stream(&gw_peer_id))
            .unwrap_or(false);
        if !has_stream {
            debug!("is_ready: gateway {} found but no shard-stream yet", gw_peer_id);
        }
        has_stream
    }

    /// Make an HTTP GET request through the tunnel (Client/Both mode)
    pub async fn get(&mut self, url: &str) -> Result<TunnelResponse> {
        self.fetch("GET", url, None, None).await
    }

    /// Make an HTTP POST request through the tunnel
    pub async fn post(&mut self, url: &str, body: Vec<u8>) -> Result<TunnelResponse> {
        self.fetch("POST", url, Some(body), None).await
    }

    /// Make an HTTP request through the tunnel
    pub async fn fetch(
        &mut self,
        method: &str,
        url: &str,
        body: Option<Vec<u8>>,
        headers: Option<Vec<(String, String)>>,
    ) -> Result<TunnelResponse> {
        // Check mode
        if !self.capabilities.is_client() {
            return Err(ClientError::NotConnected);
        }

        if !self.connected {
            return Err(ClientError::NotConnected);
        }

        let exit_info = self
            .selected_exit
            .as_ref()
            .ok_or(ClientError::NoExitNodes)?
            .clone();

        // Build exit PathHop from selected exit info
        let exit_peer_id = self.known_peers.get(&exit_info.pubkey).copied();
        let exit_peer_id_bytes = exit_peer_id
            .map(|p| p.to_bytes())
            .unwrap_or_default();
        let exit_hop = PathHop {
            peer_id: exit_peer_id_bytes,
            signing_pubkey: exit_info.pubkey,
            encryption_pubkey: exit_info.encryption_pubkey.unwrap_or([0u8; 32]),
        };

        // Build topology-based paths and LeaseSet
        let (paths, first_hops, lease_set) = self.build_request_paths(&exit_hop)?;

        // Build request
        let mut builder = RequestBuilder::new(method, url);
        if let Some(hdrs) = headers {
            for (key, value) in hdrs {
                builder = builder.header(&key, &value);
            }
        }
        if let Some(body_data) = body {
            builder = builder.body(body_data);
        }

        // Send our long-term encryption pubkey so exit can encrypt responses for us.
        // Response decryption uses exit_enc_pubkey (stored from request path).
        let (request_id, shards) = builder.build_onion_with_enc_key(
            &self.keypair,
            &exit_hop,
            &paths,
            &lease_set,
            self.encryption_keypair.public_key_bytes(), // response encryption key
            self.keypair.public_key_bytes(), // pool_pubkey — always user pubkey (tracks subscription or free usage)
        )?;

        // Calculate request size for throughput measurement
        let request_bytes: usize = shards.iter().map(|s| s.payload.len()).sum();

        info!(
            "Sending request={} url={} shards={} gateway={:?} exit_enc={}",
            hex::encode(&request_id[..8]),
            url,
            shards.len(),
            first_hops.first().map(|p| p.to_string()),
            hex::encode(&exit_hop.encryption_pubkey[..8]),
        );

        info!(
            "[SHARD-FLOW] CLIENT created {} shards for request={} ({} bytes, {} hops, gateway={:?})",
            shards.len(),
            hex::encode(&request_id[..8]),
            request_bytes,
            self.config.hop_mode.min_relays(),
            first_hops.first().map(|p| {
                let s = p.to_string();
                s[s.len().saturating_sub(6)..].to_string()
            }),
        );

        // Create response channel
        let (response_tx, mut response_rx) = mpsc::channel(1);

        // Store pending request with exit's encryption pubkey for response decryption
        self.pending.insert(
            request_id,
            PendingRequest {
                shards: HashMap::new(),
                total_chunks: 0, // Updated when first response shard arrives
                response_tx,
                exit_pubkey: exit_info.pubkey,
                exit_enc_pubkey: exit_hop.encryption_pubkey,
                request_bytes,
                sent_at: std::time::Instant::now(),
            },
        );

        // Update stats
        {
            let mut state = self.state.write();
            state.stats.credits_spent += 1;
        }
        self.credits = self.credits.saturating_sub(1);

        // Prepare the send queue: list of (shard, target_peer) to send.
        // We send shards inside the poll_once loop so the swarm is driven
        // concurrently — open_stream requires swarm.poll() to negotiate the
        // substream, which only runs inside poll_once().
        let mut send_queue: VecDeque<(Shard, PeerId)> = VecDeque::new();
        if first_hops.is_empty() {
            // Direct mode: send all shards to exit
            if let Some(exit_pid) = exit_peer_id {
                for shard in shards {
                    send_queue.push_back((shard, exit_pid));
                }
            }
        } else {
            // Relayed mode: send each shard to its path's first hop
            for (i, shard) in shards.into_iter().enumerate() {
                let target = first_hops[i % first_hops.len()];
                send_queue.push_back((shard, target));
            }
        }

        // Combined send + response loop.
        // Each iteration: poll the swarm, collect opened streams, try to send
        // shards, and check for response. Stream opens happen in background tasks
        // (spawned by StreamManager::ensure_opening) that complete as the swarm
        // is polled. poll_open_streams() collects their results.
        let req_id_hex = hex::encode(&request_id[..8]);
        let send_count = send_queue.len();
        let mut sent = 0usize;
        let send_start = std::time::Instant::now();
        let has_stream_to_gw = first_hops.first().map_or(false, |gw| {
            self.stream_manager.as_ref().map_or(false, |sm| sm.has_stream(gw))
        });
        warn!(
            "[TRACE] CLIENT SEND_START request={} shards={} gateway={:?} has_stream={} timeout={:?}",
            req_id_hex,
            send_count,
            first_hops.first().map(|p| { let s = p.to_string(); s[s.len().saturating_sub(6)..].to_string() }),
            has_stream_to_gw,
            self.config.request_timeout,
        );

        // Progress-based timeout: resets every time a new response shard arrives.
        // This allows large transfers (1GB+) to complete as long as the pipeline
        // keeps making progress. Only triggers when NO shards arrive for the full
        // timeout window (idle stall = real failure).
        let mut last_progress = Instant::now();
        let mut last_shard_count = 0usize;
        let response = loop {
            // Check for idle timeout (no new shards received within window)
            let current_shard_count = self.pending.get(&request_id)
                .map(|p| p.shards.len())
                .unwrap_or(0);
            if current_shard_count > last_shard_count {
                last_progress = Instant::now();
                last_shard_count = current_shard_count;
            }
            if last_progress.elapsed() > self.config.request_timeout {
                // Idle timeout — no progress
                let elapsed_ms = send_start.elapsed().as_millis();
                if let Some(pending) = self.pending.get(&request_id) {
                    let mut chunk_coverage: HashMap<u16, usize> = HashMap::new();
                    for &(chunk_idx, _) in pending.shards.keys() {
                        *chunk_coverage.entry(chunk_idx).or_default() += 1;
                    }
                    let coverage_str: String = (0..pending.total_chunks.max(1))
                        .map(|c| format!("c{}={}", c, chunk_coverage.get(&c).unwrap_or(&0)))
                        .collect::<Vec<_>>()
                        .join(" ");
                    warn!(
                        "[TRACE] CLIENT TIMEOUT request={} elapsed={}ms idle={}ms sent={}/{} collected={}/{} chunks={} coverage=[{}]",
                        req_id_hex, elapsed_ms, self.config.request_timeout.as_millis(),
                        sent, send_count,
                        pending.shards.len(),
                        if pending.total_chunks > 0 { pending.total_chunks as usize * DATA_SHARDS } else { 0 },
                        pending.total_chunks,
                        coverage_str,
                    );
                } else {
                    warn!("[TRACE] CLIENT TIMEOUT request={} elapsed={}ms (no pending entry)", req_id_hex, elapsed_ms);
                }
                self.pending.remove(&request_id);
                return Err(ClientError::Timeout);
            }

            // Collect any streams that finished opening in the background
            if let Some(ref mut sm) = self.stream_manager {
                sm.poll_open_streams();
            }

            // Push request shards to outbound channel (data plane).
            // Ensure stream exists first so writer task can send them.
            while let Some((shard, target)) = send_queue.pop_front() {
                if let Some(ref mut sm) = self.stream_manager {
                    if !sm.has_stream(&target) {
                        sm.ensure_opening(target);
                        // Re-queue — stream opening in background, will retry next cycle
                        send_queue.push_back((shard, target));
                        break;
                    }
                }
                if let Some(ref tx) = self.outbound_tx {
                    let payload_len = shard.payload.len();
                    let _ = tx.try_send(OutboundShard { peer: target, shard });
                    sent += 1;
                    let target_str = target.to_string();
                    warn!(
                        "[TRACE] CLIENT SHARD_SENT request={} shard={}/{} target={} elapsed={}ms payload={}B",
                        req_id_hex, sent, send_count,
                        &target_str[target_str.len().saturating_sub(6)..],
                        send_start.elapsed().as_millis(),
                        payload_len,
                    );
                }
            }
            if sent == send_count && sent > 0 {
                info!(
                    "[TRACE] CLIENT ALL_SENT request={} shards={} elapsed={}ms — waiting for response",
                    req_id_hex, sent, send_start.elapsed().as_millis(),
                );
            }

            tokio::select! {
                response = response_rx.recv() => {
                    match response {
                        Some(r) => break r,
                        None => return Err(ClientError::Timeout),
                    }
                }
                _ = self.poll_once() => {}
            }
        };

        Ok(response?)
    }

    /// Send shards to peers.
    // =========================================================================
    // Node functionality (relay/exit)
    // =========================================================================

    /// Process an incoming shard (onion-routed)
    ///
    /// In onion mode, we don't know the shard type, request_id, or user_pubkey
    /// from the shard itself. The relay handler peels one onion layer to learn
    /// the next hop and settlement data.
    ///
    /// If this shard is for us as a client (response), we detect that by trying
    /// to decrypt the routing_tag with our encryption key.
    async fn process_incoming_shard(&mut self, shard: Shard, source_peer: PeerId) -> ShardResponse {
        let local_id = self.local_peer_id.map(|p| p.to_string()).unwrap_or_default();
        let local_short = &local_id[local_id.len().saturating_sub(6)..];
        let source_str = source_peer.to_string();
        let source_short = &source_str[source_str.len().saturating_sub(6)..];
        // Shard fingerprint: stable across hops (payload doesn't change during relay)
        let fp = if shard.payload.len() >= 4 {
            format!("{:02x}{:02x}{:02x}{:02x}", shard.payload[0], shard.payload[1], shard.payload[2], shard.payload[3])
        } else {
            "short".to_string()
        };
        warn!(
            "[TRACE] node={} RECV fp={} from={} header={}B payload={}B",
            local_short, fp, source_short, shard.header.len(), shard.payload.len(),
        );

        // Try to decrypt routing_tag with our own encryption key.
        // If it succeeds AND matches a pending request/tunnel, this is a response shard for us.
        // Important: exit nodes can also decrypt routing_tags on REQUEST shards (since
        // the client encrypted them with the exit's key). We distinguish by checking
        // whether the assembly_id matches something we're waiting for.
        let tag_result = tunnelcraft_crypto::decrypt_routing_tag(
            &self.encryption_keypair.secret_key_bytes(),
            &shard.routing_tag,
        );
        let tag_ok = tag_result.is_ok();
        if let Ok(tag) = tag_result {
            let assembly_id = tag.assembly_id;
            let has_pending_request = self.pending.contains_key(&assembly_id);
            let has_pending_tunnel = self.pending_tunnel.contains_key(&assembly_id);

            if has_pending_request || has_pending_tunnel {
                self.handle_response_shard(shard);
                return ShardResponse::Accepted(None);
            }
            // Not a response for us — fall through to relay/exit processing
        }

        // Not for us — process as relay or exit
        if !self.capabilities.is_service_node() {
            return ShardResponse::Rejected("Not in relay mode".to_string());
        }

        if shard.header.is_empty() {
            // CRITICAL: empty header = exit processing. If tag decryption failed,
            // this shard is NOT a response for us and will hit the exit handler.
            // Log this since it's the path that causes EXIT_REJECTED on non-exit nodes.
            if !tag_ok {
                warn!(
                    "[TRACE] node={} EMPTY_HEADER_NO_TAG fp={} from={} routing_tag_len={} pending_count={} is_exit={} — shard with empty header but routing_tag decrypt failed, will try exit processing",
                    local_short, fp, source_short, shard.routing_tag.len(), self.pending.len(), self.capabilities.is_exit(),
                );
            }
            return self.process_as_exit(shard, source_peer).await;
        }

        self.relay_shard(shard, Some(source_peer)).await
    }

    /// Process shard as exit node (non-blocking).
    ///
    /// Shard collection is synchronous (microseconds). When an assembly completes,
    /// the slow HTTP fetch + response creation is spawned as a background task so
    /// poll_once() keeps running and swarm connections stay healthy.
    async fn process_as_exit(&mut self, shard: Shard, _source_peer: PeerId) -> ShardResponse {
        let local_id = self.local_peer_id.map(|p| p.to_string()).unwrap_or_default();
        let local_short = local_id[local_id.len().saturating_sub(6)..].to_string();

        let exit_handler = {
            let mut state = self.state.write();
            state.exit_handler.take()
        };

        let Some(mut handler) = exit_handler else {
            // Handler is busy in a spawned task — queue shard for later
            self.exit_shard_queue.push_back(shard);
            return ShardResponse::Accepted(None);
        };

        // Fast path: collect shard into assembly (no I/O, microseconds)
        let collect_result = handler.collect_shard(shard);

        match collect_result {
            Ok(None) => {
                // Still collecting — restore handler immediately
                let mut state = self.state.write();
                state.exit_handler = Some(handler);
                return ShardResponse::Accepted(None);
            }
            Ok(Some(assembly_id)) => {
                // Assembly complete — spawn slow processing as background task.
                // Handler is moved into the task and returned via channel when done.
                // This prevents blocking poll_once during HTTP fetch.
                let tx = self.exit_task_tx.clone();
                let ls = local_short.clone();
                tokio::spawn(async move {
                    let start = std::time::Instant::now();
                    let result = tokio::time::timeout(
                        Duration::from_secs(15),
                        handler.process_complete_assembly(assembly_id),
                    ).await;
                    let process_ms = start.elapsed().as_millis();

                    let shard_pairs = match result {
                        Ok(Ok(Some(pairs))) => {
                            warn!(
                                "[TRACE] node={} EXIT_COMPLETE response_shards={} process_ms={}",
                                ls, pairs.len(), process_ms,
                            );
                            pairs
                        }
                        Ok(Ok(None)) => vec![],
                        Ok(Err(e)) => {
                            warn!("[TRACE] node={} EXIT_ERROR err={} process_ms={}", ls, e, process_ms);
                            vec![]
                        }
                        Err(_) => {
                            warn!("[TRACE] node={} EXIT_TIMEOUT process_ms={} — handler returned", ls, process_ms);
                            vec![]
                        }
                    };

                    let _ = tx.send(ExitTaskResult { handler, shard_pairs, process_ms }).await;
                });
                return ShardResponse::Accepted(None);
            }
            Err(e) => {
                // Collection failed (e.g., bad routing_tag) — restore handler
                let mut state = self.state.write();
                state.exit_handler = Some(handler);
                warn!("[TRACE] node={} EXIT_ERROR err={}", local_short, e);
                return ShardResponse::Rejected(e.to_string());
            }
        }
    }

    /// Queue completed exit task results: restore handler, enqueue response shards.
    fn drain_exit_task_results(&mut self) {
        while let Ok(result) = self.exit_task_rx.try_recv() {
            // Restore exit handler
            {
                let mut state = self.state.write();
                if !result.shard_pairs.is_empty() {
                    state.stats.requests_exited += 1;
                }
                state.exit_handler = Some(result.handler);
            }

            // Push response shards to outbound channel (data plane).
            // The background writer task writes them to TCP without blocking poll_once.
            let local_id = self.local_peer_id.map(|p| p.to_string()).unwrap_or_default();
            let local_short = &local_id[local_id.len().saturating_sub(6)..];
            let mut queued = 0u32;
            for (shard, gateway_bytes) in result.shard_pairs {
                if let Some(target) = gateway_bytes.and_then(|gw| PeerId::from_bytes(&gw).ok()) {
                    // Ensure outbound stream is being opened for this target
                    if let Some(ref mut sm) = self.stream_manager {
                        sm.ensure_opening(target);
                    }
                    if let Some(ref tx) = self.outbound_tx {
                        let shard_bytes = shard.payload.len() as u64;
                        match tx.try_send(OutboundShard { peer: target, shard }) {
                            Ok(()) => {
                                queued += 1;
                                let mut state = self.state.write();
                                state.stats.bytes_relayed += shard_bytes;
                            }
                            Err(e) => {
                                warn!("[TRACE] node={} EXIT_RESPONSE_DROP target={} err={}", local_short, &target.to_string()[target.to_string().len().saturating_sub(6)..], e);
                            }
                        }
                    }
                } else {
                    warn!("[TRACE] node={} EXIT_RESPONSE_NO_GATEWAY", local_short);
                }
            }
            if queued > 0 {
                warn!(
                    "[TRACE] node={} EXIT_RESPONSE queued={} process_ms={}",
                    local_short, queued, result.process_ms,
                );
            }
        }

        // Process queued exit shards now that handler may be available
        while self.state.read().exit_handler.is_some() && !self.exit_shard_queue.is_empty() {
            let shard = self.exit_shard_queue.pop_front().unwrap();
            // Fast path only: collect_shard is sync, won't block.
            // If assembly completes, it spawns a new task (handler taken again → loop breaks).
            let exit_handler = {
                let mut state = self.state.write();
                state.exit_handler.take()
            };
            let Some(mut handler) = exit_handler else { break; };

            match handler.collect_shard(shard) {
                Ok(None) => {
                    self.state.write().exit_handler = Some(handler);
                }
                Ok(Some(assembly_id)) => {
                    let tx = self.exit_task_tx.clone();
                    let local_id = self.local_peer_id.map(|p| p.to_string()).unwrap_or_default();
                    let ls = local_id[local_id.len().saturating_sub(6)..].to_string();
                    tokio::spawn(async move {
                        let start = std::time::Instant::now();
                        let result = tokio::time::timeout(
                            Duration::from_secs(15),
                            handler.process_complete_assembly(assembly_id),
                        ).await;
                        let process_ms = start.elapsed().as_millis();
                        let shard_pairs = match result {
                            Ok(Ok(Some(pairs))) => {
                                warn!("[TRACE] node={} EXIT_COMPLETE response_shards={} process_ms={}", ls, pairs.len(), process_ms);
                                pairs
                            }
                            Ok(Ok(None)) => vec![],
                            Ok(Err(e)) => { warn!("[TRACE] node={} EXIT_ERROR err={} process_ms={}", ls, e, process_ms); vec![] }
                            Err(_) => { warn!("[TRACE] node={} EXIT_TIMEOUT process_ms={}", ls, process_ms); vec![] }
                        };
                        let _ = tx.send(ExitTaskResult { handler, shard_pairs, process_ms }).await;
                    });
                    break; // handler is in task, stop draining queue
                }
                Err(e) => {
                    warn!("[TRACE] EXIT_QUEUE_ERROR err={}", e);
                    self.state.write().exit_handler = Some(handler);
                }
            }
        }
    }

    /// Relay a shard by peeling one onion layer and forwarding to the next hop.
    ///
    /// The relay handler returns (modified_shard, next_peer_id_bytes, receipt).
    /// We forward the modified shard to the specified next peer.
    async fn relay_shard(&mut self, shard: Shard, _source_peer: Option<PeerId>) -> ShardResponse {
        // Get sender_pubkey from libp2p connection (for ForwardReceipt anti-replay)
        let sender_pubkey = self.keypair.public_key_bytes(); // placeholder: use connection auth

        // Process shard with relay handler (under lock)
        let relay_result = {
            let state = self.state.read();

            let Some(ref relay_handler) = state.relay_handler else {
                return ShardResponse::Rejected("Relay not active".to_string());
            };

            relay_handler.handle_shard(shard, sender_pubkey)
        };
        // Lock released here

        match relay_result {
            Ok((modified_shard, next_peer_bytes, receipt, pool_pubkey)) => {
                let has_tunnel = modified_shard.header.is_empty();
                let local_id = self.local_peer_id.map(|p| p.to_string()).unwrap_or_default();
                let local_short = &local_id[local_id.len().saturating_sub(6)..];
                let fp = if modified_shard.payload.len() >= 4 {
                    format!("{:02x}{:02x}{:02x}{:02x}", modified_shard.payload[0], modified_shard.payload[1], modified_shard.payload[2], modified_shard.payload[3])
                } else { "short".to_string() };
                if let Ok(next_pid) = PeerId::from_bytes(&next_peer_bytes) {
                    let connected = self.swarm.as_ref().is_some_and(|s| s.is_connected(&next_pid));
                    let has_stream = self.stream_manager.as_ref().map_or(false, |sm| sm.has_stream(&next_pid));
                    let next_str = next_pid.to_string();
                    warn!(
                        "[TRACE] node={} RELAY_FWD fp={} next={} gateway={} connected={} stream={}",
                        local_short, fp,
                        &next_str[next_str.len().saturating_sub(6)..],
                        has_tunnel, connected, has_stream,
                    );
                } else {
                    warn!("[TRACE] node={} RELAY_FWD fp={} next=INVALID gateway={}", local_short, fp, has_tunnel);
                }
                {
                    let mut state = self.state.write();
                    state.stats.shards_relayed += 1;
                    state.stats.bytes_relayed += modified_shard.payload.len() as u64;
                }

                // Route receipt to the correct pool using pool_pubkey from onion layer.
                // Check subscription_cache to determine if this user has an active subscription.
                let pool_type = if self.subscription_cache.get(&pool_pubkey)
                    .map_or(false, |e| e.tier != 255)
                {
                    PoolType::Subscribed
                } else {
                    PoolType::Free
                };
                self.request_user.insert(receipt.shard_id, (pool_pubkey, pool_type));

                // Store the receipt for settlement
                self.store_forward_receipt(receipt.clone());

                // Data plane: push to outbound channel for background writer task.
                // Never blocks poll_once — writer task handles TCP at its own pace.
                if let Ok(next_peer) = PeerId::from_bytes(&next_peer_bytes) {
                    // Safety net: if the relay peeled to find next_peer == ourselves,
                    // process as exit locally instead of forwarding (no stream to self).
                    // This can happen if the exit was selected as relay for its own circuit.
                    if Some(next_peer) == self.local_peer_id {
                        warn!(
                            "[TRACE] node={} RELAY_SELF_DELIVERY fp={} header={}B — processing as exit locally",
                            local_short, fp, modified_shard.header.len(),
                        );
                        return self.process_as_exit(modified_shard, next_peer).await;
                    }
                    // If not connected to next peer, dial them first so open_stream can succeed.
                    if let Some(ref mut swarm) = self.swarm {
                        if !swarm.is_connected(&next_peer) {
                            let _ = swarm.dial(next_peer);
                        }
                    }
                    // Ensure stream exists (triggers background open if needed)
                    if let Some(ref mut sm) = self.stream_manager {
                        sm.ensure_opening(next_peer);
                    }
                    if let Some(ref tx) = self.outbound_tx {
                        let _ = tx.try_send(OutboundShard { peer: next_peer, shard: modified_shard });
                    }
                } else {
                    warn!("Could not parse next_peer PeerId from onion layer");
                }

                ShardResponse::Accepted(Some(Box::new(receipt)))
            }
            Err(e) => {
                // Onion peel failed — could be wrong key (shard wasn't for us)
                // or corrupted header. Try processing as exit instead.
                debug!("Onion peel failed: {} — not relaying", e);
                ShardResponse::Rejected(e.to_string())
            }
        }
    }

    /// Select a relay peer using load-weighted selection, excluding specific peers.
    ///
    /// First tries DHT-discovered online relays weighted by inverted score
    /// (lower score = higher selection weight). Falls back to unverified relay peers.
    #[allow(dead_code)]
    fn select_relay_peer_multi_exclude(&self, exclude: &HashSet<PeerId>) -> Option<PeerId> {
        use rand::Rng;

        // First: try DHT-discovered online relay nodes (load-weighted)
        let dht_candidates: Vec<(PeerId, u8)> = self.relay_nodes.values()
            .filter(|s| s.online && !exclude.contains(&s.peer_id))
            .map(|s| (s.peer_id, s.score))
            .collect();

        if !dht_candidates.is_empty() {
            // Weight = 101 - score (so lower score → higher weight)
            let total_weight: u32 = dht_candidates.iter()
                .map(|(_, score)| 101u32.saturating_sub(*score as u32))
                .sum();
            if total_weight > 0 {
                let mut pick = rand::thread_rng().gen_range(0..total_weight);
                for (peer_id, score) in &dht_candidates {
                    let weight = 101u32.saturating_sub(*score as u32);
                    if pick < weight {
                        return Some(*peer_id);
                    }
                    pick -= weight;
                }
                // Fallthrough (shouldn't happen): return last
                return Some(dht_candidates.last().unwrap().0);
            }
        }

        // Fallback: unverified relay peers (random selection, legacy behavior)
        let candidates: Vec<PeerId> = self.unverified_relay_peers.iter()
            .filter(|p| !exclude.contains(p))
            .copied()
            .collect();
        if candidates.is_empty() {
            // Last resort: try all unverified relay peers ignoring exclusion
            if self.unverified_relay_peers.is_empty() {
                return None;
            }
            let idx = rand::thread_rng().gen_range(0..self.unverified_relay_peers.len());
            return Some(self.unverified_relay_peers[idx]);
        }
        let idx = rand::thread_rng().gen_range(0..candidates.len());
        Some(candidates[idx])
    }

    /// Store a forward receipt received from a peer.
    /// Receipts are grouped by request_id for later batch settlement.
    fn store_forward_receipt(&mut self, receipt: ForwardReceipt) {
        info!(
            "Stored ForwardReceipt: shard={}, from={}",
            hex::encode(&receipt.shard_id[..8]),
            hex::encode(&receipt.receiver_pubkey[..8]),
        );

        // Buffer for batch disk write instead of per-receipt file I/O
        self.receipt_buffer.push(receipt.clone());

        // Store in forward_receipts for per-request tracking
        self.forward_receipts
            .entry(receipt.shard_id)
            .or_default()
            .push(receipt.clone());

        // Route into proof queue for compression (relay/exit mode only)
        if self.capabilities.is_service_node() {
            if let Some((pool, pool_type)) = self.request_user.get(&receipt.shard_id) {
                let key = (*pool, *pool_type);
                let queue = self.proof_queue.entry(key).or_default();
                if queue.len() < self.proof_queue_limit {
                    info!(
                        "Receipt queued for compression: pool={}, pool_type={:?}, queue_size={}",
                        hex::encode(&key.0[..8]),
                        key.1,
                        queue.len() + 1,
                    );
                    queue.push_back(receipt);

                    // Track when the first receipt entered this pool's queue
                    self.proof_oldest_receipt.entry(key).or_insert_with(Instant::now);

                    // Debounced persistence: save every 100 enqueued receipts
                    self.proof_enqueue_since_save += 1;
                    if self.proof_enqueue_since_save >= 100 {
                        self.proof_enqueue_since_save = 0;
                        self.save_proof_state();
                    }
                } else {
                    warn!(
                        "Proof queue full for pool {} ({:?}) — receipt dropped (backpressure)",
                        hex::encode(&key.0[..8]),
                        key.1,
                    );
                }
            }
        }
    }

    /// Handle response shard for our own request (onion-routed, multi-chunk aware)
    ///
    /// In onion mode, we decrypt the routing_tag with our encryption key to get
    /// assembly_id. We then map assembly_id → request_id via a lookup table that
    /// was populated when we sent the request.
    fn handle_response_shard(&mut self, shard: Shard) {
        // Decrypt routing_tag to get assembly_id + shard/chunk metadata
        let tag = match tunnelcraft_crypto::decrypt_routing_tag(
            &self.encryption_keypair.secret_key_bytes(),
            &shard.routing_tag,
        ) {
            Ok(tag) => tag,
            Err(_) => return,
        };

        let assembly_id = tag.assembly_id;
        let shard_index = tag.shard_index;
        let chunk_index = tag.chunk_index;
        let total_chunks = tag.total_chunks;

        // Check tunnel map first (SOCKS5 tunnel mode responses are raw bytes)
        if self.handle_tunnel_response_shard_by_assembly(&assembly_id, shard_index, chunk_index, total_chunks, &shard) {
            return;
        }

        // Find the request_id that corresponds to this assembly_id
        // We use assembly_id as the key for pending requests directly
        // (request_id tracking was populated at send time)
        let request_id = assembly_id; // In onion mode, the exit uses a response assembly_id
        // that we map to our pending requests

        // Try to find this in pending requests — iterate to find by assembly_id
        // Since we don't know the request_id from the shard, we try all pending requests
        // For now, use the assembly_id as a lookup key in pending
        if let Some(pending) = self.pending.get_mut(&request_id) {
            if pending.total_chunks == 0 {
                pending.total_chunks = total_chunks;
            }
            pending.shards.insert((chunk_index, shard_index), shard.payload);

            let needed = pending.total_chunks as usize * DATA_SHARDS;
            info!(
                "[SHARD-FLOW] CLIENT response shard: chunk={} shard={} for request={} ({}/{} collected)",
                chunk_index,
                shard_index,
                hex::encode(&request_id[..8]),
                pending.shards.len(),
                needed,
            );

            if self.all_response_chunks_ready(&request_id) {
                info!(
                    "[SHARD-FLOW] CLIENT all response shards ready for request={}, reconstructing",
                    hex::encode(&request_id[..8]),
                );
                if let Some(pending) = self.pending.remove(&request_id) {
                    let response_tx = pending.response_tx.clone();

                    let result = self.reconstruct_response(&pending);
                    match result {
                        Ok(response) => {
                            let response_bytes = response.body.len();
                            info!(
                                "[SHARD-FLOW] CLIENT response reconstructed: request={} status={} body_len={}",
                                hex::encode(&request_id[..8]),
                                response.status,
                                response_bytes,
                            );
                            self.update_exit_measurement(&pending, response_bytes);

                            {
                                let mut state = self.state.write();
                                state.stats.bytes_received += response_bytes as u64;
                            }
                            let _ = response_tx.try_send(Ok(response));
                        }
                        Err(e) => {
                            warn!(
                                "[SHARD-FLOW] CLIENT response reconstruction FAILED: request={} err={}",
                                hex::encode(&request_id[..8]),
                                e,
                            );
                            let _ = response_tx.try_send(Err(e));
                        }
                    }
                }
            }
        } else {
            warn!(
                "[SHARD-FLOW] CLIENT response shard ORPHAN: assembly={} not in pending ({} pending requests)",
                hex::encode(&request_id[..8]),
                self.pending.len(),
            );
        }
    }

    /// Check if all response chunks have enough shards for reconstruction
    fn all_response_chunks_ready(&self, request_id: &Id) -> bool {
        let Some(pending) = self.pending.get(request_id) else {
            return false;
        };
        if pending.total_chunks == 0 {
            return false;
        }

        let mut chunk_counts: HashMap<u16, usize> = HashMap::new();
        for &(chunk_idx, _) in pending.shards.keys() {
            *chunk_counts.entry(chunk_idx).or_default() += 1;
        }

        if chunk_counts.len() < pending.total_chunks as usize {
            return false;
        }
        chunk_counts.values().all(|&count| count >= DATA_SHARDS)
    }

    /// Update exit node measurement after receiving response
    fn update_exit_measurement(&mut self, pending: &PendingRequest, response_bytes: usize) {
        let elapsed_ms = pending.sent_at.elapsed().as_millis() as u32;
        if elapsed_ms == 0 {
            return;
        }

        // Calculate throughput in KB/s
        // Uplink: request_bytes / (elapsed_ms / 1000) / 1024
        // Simplified: (request_bytes * 1000) / elapsed_ms / 1024
        let uplink_kbps = (pending.request_bytes as u64 * 1000 / elapsed_ms as u64 / 1024) as u32;
        let downlink_kbps = (response_bytes as u64 * 1000 / elapsed_ms as u64 / 1024) as u32;
        let latency_ms = elapsed_ms; // Round-trip time as proxy for latency

        // Update exit node status
        if let Some(status) = self.exit_nodes.get_mut(&pending.exit_pubkey) {
            status.update_measurement(latency_ms, uplink_kbps, downlink_kbps);
            debug!(
                "Updated exit measurement: latency={}ms, uplink={}KB/s, downlink={}KB/s, score={}",
                latency_ms, uplink_kbps, downlink_kbps, status.score
            );
        }
    }

    /// Reconstruct response from shard payloads (multi-chunk aware)
    fn reconstruct_response(&self, pending: &PendingRequest) -> Result<TunnelResponse> {
        use std::collections::BTreeMap;

        // Group shard payloads by chunk_index
        let mut chunks_by_index: HashMap<u16, Vec<(u8, &Vec<u8>)>> = HashMap::new();
        for (&(chunk_idx, shard_idx), payload) in &pending.shards {
            chunks_by_index
                .entry(chunk_idx)
                .or_default()
                .push((shard_idx, payload));
        }

        // Reconstruct each chunk independently
        let mut reconstructed_chunks: BTreeMap<u16, Vec<u8>> = BTreeMap::new();

        for chunk_idx in 0..pending.total_chunks {
            let chunk_shards = chunks_by_index.get(&chunk_idx);
            let mut shard_data: Vec<Option<Vec<u8>>> = vec![None; TOTAL_SHARDS];
            let mut shard_size = 0usize;

            if let Some(payloads) = chunk_shards {
                for &(shard_idx, payload) in payloads {
                    let idx = shard_idx as usize;
                    if idx < TOTAL_SHARDS {
                        shard_size = payload.len();
                        shard_data[idx] = Some(payload.clone());
                    }
                }
            }

            let max_len = shard_size * DATA_SHARDS;
            let chunk_data = self
                .erasure
                .decode(&mut shard_data, max_len)
                .map_err(|e| ClientError::ErasureError(e.to_string()))?;

            reconstructed_chunks.insert(chunk_idx, chunk_data);
        }

        // Reassemble
        let total_possible = reconstructed_chunks.values().map(|c| c.len()).sum();
        let framed_data = reassemble(&reconstructed_chunks, pending.total_chunks, total_possible)
            .map_err(|e| ClientError::ErasureError(e.to_string()))?;

        // Strip length-prefixed framing (4-byte LE u32 original length)
        if framed_data.len() < 4 {
            return Err(ClientError::InvalidResponse);
        }
        let original_len = u32::from_le_bytes(
            framed_data[..4].try_into().unwrap()
        ) as usize;
        if framed_data.len() < 4 + original_len {
            return Err(ClientError::InvalidResponse);
        }
        let encrypted_data = &framed_data[4..4 + original_len];

        // Decrypt the response using the exit's encryption pubkey stored at request time
        let data = tunnelcraft_crypto::decrypt_from_sender(
            &pending.exit_enc_pubkey,
            &self.encryption_keypair.secret_key_bytes(),
            encrypted_data,
        ).map_err(|e| ClientError::CryptoError(format!("Response decrypt failed: {}", e)))?;

        TunnelResponse::from_bytes(&data)
    }

    // =========================================================================
    // SOCKS5 tunnel mode
    // =========================================================================

    /// Set the tunnel burst receiver channel (called by SOCKS5 server integration)
    pub fn set_tunnel_burst_rx(&mut self, rx: mpsc::Receiver<TunnelBurst>) {
        self.tunnel_burst_rx = Some(rx);
    }

    /// Handle a tunnel burst from the SOCKS5 server
    async fn handle_tunnel_burst(&mut self, burst: TunnelBurst) {
        let exit_info = match &self.selected_exit {
            Some(e) => e.clone(),
            None => {
                let _ = burst.response_tx.try_send(Err(ClientError::NoExitNodes));
                return;
            }
        };

        // Build exit PathHop from selected exit info
        let exit_peer_id = self.known_peers.get(&exit_info.pubkey).copied();
        let exit_peer_id_bytes = exit_peer_id
            .map(|p| p.to_bytes())
            .unwrap_or_default();
        let exit_hop = PathHop {
            peer_id: exit_peer_id_bytes,
            signing_pubkey: exit_info.pubkey,
            encryption_pubkey: exit_info.encryption_pubkey.unwrap_or([0u8; 32]),
        };

        // Build topology-based paths and LeaseSet
        let (paths, first_hops, lease_set) = match self.build_request_paths(&exit_hop) {
            Ok(v) => v,
            Err(e) => {
                let _ = burst.response_tx.try_send(Err(e));
                return;
            }
        };

        let result = crate::tunnel::build_tunnel_shards(
            &burst.metadata,
            &burst.data,
            &self.keypair,
            &exit_hop,
            &paths,
            &lease_set,
            self.keypair.public_key_bytes(), // pool_pubkey — always user pubkey (tracks subscription or free usage)
        );

        let (request_id, shards) = match result {
            Ok(v) => v,
            Err(e) => {
                let _ = burst.response_tx.try_send(Err(e));
                return;
            }
        };

        debug!(
            "Tunnel burst: {} shards for session {}, request {} ({} hops)",
            shards.len(),
            hex::encode(&burst.metadata.session_id[..8]),
            hex::encode(&request_id[..8]),
            self.config.hop_mode.min_relays()
        );

        // Store pending tunnel request
        self.pending_tunnel.insert(
            request_id,
            PendingTunnelRequest {
                shards: HashMap::new(),
                total_chunks: 0,
                response_tx: burst.response_tx,
                exit_enc_pubkey: exit_hop.encryption_pubkey,
                sent_at: std::time::Instant::now(),
            },
        );

        // Push shards to outbound channel (data plane).
        if first_hops.is_empty() {
            if let Some(exit_pid) = exit_peer_id {
                if let Some(ref tx) = self.outbound_tx {
                    for shard in shards {
                        let _ = tx.try_send(OutboundShard { peer: exit_pid, shard });
                    }
                }
            }
        } else {
            if let Some(ref tx) = self.outbound_tx {
                for (i, shard) in shards.into_iter().enumerate() {
                    let target = first_hops[i % first_hops.len()];
                    let _ = tx.try_send(OutboundShard { peer: target, shard });
                }
            }
        }
        // Pre-warm stream opens for target peers
        if let Some(ref mut sm) = self.stream_manager {
            if let Some(exit_pid) = exit_peer_id {
                if first_hops.is_empty() {
                    sm.ensure_opening(exit_pid);
                }
            }
            for hop in &first_hops {
                sm.ensure_opening(*hop);
            }
        }
    }

    /// Handle response shard for a tunnel request by assembly_id (raw bytes, no HTTP parsing)
    fn handle_tunnel_response_shard_by_assembly(
        &mut self,
        assembly_id: &Id,
        shard_index: u8,
        chunk_index: u16,
        total_chunks: u16,
        shard: &Shard,
    ) -> bool {
        let Some(pending) = self.pending_tunnel.get_mut(assembly_id) else {
            return false;
        };

        // Update total_chunks from first arriving shard
        if pending.total_chunks == 0 {
            pending.total_chunks = total_chunks;
        }
        pending.shards.insert((chunk_index, shard_index), shard.payload.clone());

        // Check if all chunks have enough shards
        if !self.all_tunnel_response_chunks_ready(assembly_id) {
            return true; // Claimed but not yet complete
        }

        if let Some(pending) = self.pending_tunnel.remove(assembly_id) {
            let response_tx = pending.response_tx.clone();

            match self.reconstruct_tunnel_response(&pending) {
                Ok(data) => {
                    let _ = response_tx.try_send(Ok(data));
                }
                Err(e) => {
                    let _ = response_tx.try_send(Err(e));
                }
            }
        }

        true
    }

    /// Check if all tunnel response chunks have enough shards
    fn all_tunnel_response_chunks_ready(&self, request_id: &Id) -> bool {
        let Some(pending) = self.pending_tunnel.get(request_id) else {
            return false;
        };
        if pending.total_chunks == 0 {
            return false;
        }

        let mut chunk_counts: HashMap<u16, usize> = HashMap::new();
        for &(chunk_idx, _) in pending.shards.keys() {
            *chunk_counts.entry(chunk_idx).or_default() += 1;
        }

        if chunk_counts.len() < pending.total_chunks as usize {
            return false;
        }
        chunk_counts.values().all(|&count| count >= DATA_SHARDS)
    }

    /// Reconstruct tunnel response as raw bytes (no HTTP parsing)
    fn reconstruct_tunnel_response(&self, pending: &PendingTunnelRequest) -> Result<Vec<u8>> {
        use std::collections::BTreeMap;

        let mut chunks_by_index: HashMap<u16, Vec<(u8, &Vec<u8>)>> = HashMap::new();
        for (&(chunk_idx, shard_idx), payload) in &pending.shards {
            chunks_by_index
                .entry(chunk_idx)
                .or_default()
                .push((shard_idx, payload));
        }

        let mut reconstructed_chunks: BTreeMap<u16, Vec<u8>> = BTreeMap::new();

        for chunk_idx in 0..pending.total_chunks {
            let chunk_payloads = chunks_by_index.get(&chunk_idx);
            let mut shard_data: Vec<Option<Vec<u8>>> = vec![None; TOTAL_SHARDS];
            let mut shard_size = 0usize;

            if let Some(payloads) = chunk_payloads {
                for &(shard_idx, payload) in payloads {
                    let idx = shard_idx as usize;
                    if idx < TOTAL_SHARDS {
                        shard_size = payload.len();
                        shard_data[idx] = Some(payload.clone());
                    }
                }
            }

            let max_len = shard_size * DATA_SHARDS;
            let chunk_data = self
                .erasure
                .decode(&mut shard_data, max_len)
                .map_err(|e| ClientError::ErasureError(e.to_string()))?;

            reconstructed_chunks.insert(chunk_idx, chunk_data);
        }

        let total_possible = reconstructed_chunks.values().map(|c| c.len()).sum();
        let framed_data = reassemble(&reconstructed_chunks, pending.total_chunks, total_possible)
            .map_err(|e| ClientError::ErasureError(e.to_string()))?;

        // Strip length-prefixed framing (4-byte LE u32 original length)
        if framed_data.len() < 4 {
            return Err(ClientError::InvalidResponse);
        }
        let original_len = u32::from_le_bytes(
            framed_data[..4].try_into().unwrap()
        ) as usize;
        if framed_data.len() < 4 + original_len {
            return Err(ClientError::InvalidResponse);
        }
        let encrypted_data = &framed_data[4..4 + original_len];

        // Decrypt the response using the exit's encryption pubkey stored at request time
        tunnelcraft_crypto::decrypt_from_sender(
            &pending.exit_enc_pubkey,
            &self.encryption_keypair.secret_key_bytes(),
            encrypted_data,
        ).map_err(|e| ClientError::CryptoError(format!("Tunnel response decrypt failed: {}", e)))
    }

    // =========================================================================
    // Event loop
    // =========================================================================

    /// Poll network once (for integration with VPN event loop)
    pub async fn poll_once(&mut self) {
        // Try to compress queued receipts (relay/exit mode)
        if self.capabilities.is_service_node() {
            self.poll_compression_result();
            self.try_compress();
        }

        let Some(ref mut swarm) = self.swarm else {
            // No swarm: yield to runtime so callers using select! don't busy-spin
            tokio::time::sleep(Duration::from_millis(100)).await;
            return;
        };

        // Drain all immediately available swarm events (don't wait after the first)
        // This prevents DHT events from starving shard delivery.
        tokio::select! {
            event = swarm.select_next_some() => {
                self.handle_swarm_event(event).await;
                // Drain remaining ready events without blocking.
                // Interleave shard drain+flush every 50 events to prevent
                // gossip traffic from starving shard delivery.
                let mut events_since_drain = 0u32;
                loop {
                    let Some(ref mut swarm) = self.swarm else { break };
                    tokio::select! {
                        biased;
                        event = swarm.select_next_some() => {
                            self.handle_swarm_event(event).await;
                            events_since_drain += 1;
                            if events_since_drain >= 50 {
                                events_since_drain = 0;
                                self.drain_stream_shards().await;
                            }
                        }
                        _ = async {} => { break; }
                    }
                }
            }
            burst = async {
                if let Some(ref mut rx) = self.tunnel_burst_rx {
                    rx.recv().await
                } else {
                    std::future::pending().await
                }
            } => {
                if let Some(burst) = burst {
                    self.handle_tunnel_burst(burst).await;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(1)) => {}
        }

        // Accept inbound streams from the bridging task.
        // This runs outside the select! so it's processed every poll_once() cycle,
        // regardless of which select! branch won above.
        // Collect first to avoid borrow conflicts between rx, get_peer_tier, and stream_manager.
        let mut incoming_batch = Vec::new();
        if let Some(ref mut rx) = self.incoming_stream_rx {
            while let Ok(item) = rx.try_recv() {
                incoming_batch.push(item);
            }
        }
        for (peer, stream) in incoming_batch {
            let tier = self.get_peer_tier(&peer);
            if let Some(ref mut sm) = self.stream_manager {
                sm.accept_stream(peer, stream, tier);
            }
        }

        // Collect completed background stream opens before processing shards,
        // and clean up streams whose reader task has terminated (half-dead streams).
        if let Some(ref mut sm) = self.stream_manager {
            let newly_opened = sm.poll_open_streams();
            sm.cleanup_dead_streams();
            // Topology is now carried in heartbeats (30s interval), so new
            // stream connections will be picked up at the next heartbeat cycle.
            let _ = newly_opened;
        }

        // Collect completed exit task results (restore handler, push response shards to outbound channel).
        self.drain_exit_task_results();

        // Priority-ordered stream shard processing:
        // 1. Drain high-priority (subscribed peers) first
        // 2. Then low-priority (free-tier peers)
        // 3. Then deferred forwards (layer 2: free-tier shards after onion peel)
        self.drain_stream_shards().await;

        // Drain receipts from fire-and-forget stream acks
        self.drain_stream_receipts();

        // Batch-flush buffered receipts to disk (one file open/close per poll cycle)
        self.flush_receipts();

        // Auto-maintenance: run periodic housekeeping on a timer so callers
        // of poll_once() don't need to drive maintenance separately.
        if self.last_maintenance.elapsed() >= self.maintenance_interval {
            self.last_maintenance = Instant::now();
            self.run_maintenance();
            self.run_async_maintenance().await;
        }
    }

    /// Drain inbound shards from stream channels in priority order.
    async fn drain_stream_shards(&mut self) {
        // Collect inbound shards into a vec to avoid borrow conflicts
        // (channel borrow vs &mut self for process_incoming_shard)
        let mut high_batch: Vec<InboundShard> = Vec::new();
        if let Some(ref mut rx) = self.inbound_high_rx {
            while let Ok(inbound) = rx.try_recv() {
                high_batch.push(inbound);
            }
        }

        let mut low_batch: Vec<InboundShard> = Vec::new();
        if let Some(ref mut rx) = self.inbound_low_rx {
            while let Ok(inbound) = rx.try_recv() {
                low_batch.push(inbound);
            }
        }

        // Process high-priority first, then low-priority
        for inbound in high_batch.into_iter().chain(low_batch.into_iter()) {
            let peer = inbound.peer;
            let seq_id = inbound.seq_id;
            let response = self.process_incoming_shard(inbound.shard, peer).await;
            match response {
                ShardResponse::Accepted(receipt) => {
                    if let Some(ref sm) = self.stream_manager {
                        sm.send_ack(peer, seq_id, receipt.map(|b| *b));
                    }
                }
                ShardResponse::Rejected(reason) => {
                    if let Some(ref sm) = self.stream_manager {
                        sm.send_nack(peer, seq_id, &reason);
                    }
                    if reason.contains("Not in relay mode") {
                        info!("Removing non-relay peer {} from relay pool", peer);
                        self.unverified_relay_peers.retain(|p| *p != peer);
                        self.relay_nodes.retain(|_, s| s.peer_id != peer);
                    }
                }
            }
        }

        // No deferred drain needed — all outbound shards go through the data plane
        // channel (outbound_tx → writer task). Acks/nacks are fire-and-forget
        // (spawned tasks) to avoid writer mutex contention under load.
    }

    /// Drain receipts arriving from stream ack frames.
    fn drain_stream_receipts(&mut self) {
        // Collect first to avoid borrow conflicts
        let mut receipts = Vec::new();
        if let Some(ref mut rx) = self.stream_receipt_rx {
            while let Ok(receipt) = rx.try_recv() {
                receipts.push(receipt);
            }
        }
        for receipt in receipts {
            self.store_forward_receipt(receipt);
        }
    }

    /// Flush buffered receipts to disk in a single file open/close.
    /// Called at the end of poll_once() to batch all per-shard receipts.
    fn flush_receipts(&mut self) {
        if self.receipt_buffer.is_empty() {
            return;
        }
        if let Some(ref path) = self.receipt_file {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            match std::fs::OpenOptions::new().create(true).append(true).open(path) {
                Ok(mut file) => {
                    for receipt in self.receipt_buffer.drain(..) {
                        if let Ok(json) = serde_json::to_string(&receipt) {
                            let _ = writeln!(file, "{}", json);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to persist receipts to {}: {}", path.display(), e);
                    self.receipt_buffer.clear();
                }
            }
        } else {
            self.receipt_buffer.clear();
        }
    }

    /// Get a peer's subscription tier (0=free, 1+=subscribed).
    fn get_peer_tier(&self, _peer: &PeerId) -> u8 {
        // Both inbound channels are fully drained each poll_once() cycle,
        // so priority only matters under backpressure (channel full).
        // Until load-based throttling is added, tier lookup has no effect.
        0
    }

    /// Run periodic maintenance tasks (heartbeats, DHT discovery, cleanup).
    /// Normally called automatically every 30s by `run()`. Call manually
    /// when using `poll_once()` in a custom event loop.
    pub fn run_maintenance(&mut self) {
        self.maybe_reannounce_exit();
        self.maybe_reannounce_peer();
        self.maybe_send_heartbeat();
        self.check_exit_timeouts();
        self.discover_exits();
        self.cleanup_stale_exits();
        self.maybe_reannounce_relay();
        self.maybe_send_relay_heartbeat();
        self.discover_relays();
        self.check_relay_timeouts();
        self.cleanup_stale_relays();
        self.maybe_reconnect_bootstrap();
        self.update_topology();
        self.refresh_and_evict_tunnels();
    }

    /// Run async maintenance tasks (subscription verification, distribution posting, aggregator persistence).
    /// Call this periodically alongside `run_maintenance()` when not using `run()`.
    pub async fn run_async_maintenance(&mut self) {
        if !self.aggregator_reconciled {
            self.reconcile_aggregator_state().await;
            self.aggregator_reconciled = true;
        }
        self.maybe_verify_subscriptions().await;
        self.maybe_post_distributions().await;
        self.save_aggregator_state();
        self.flush_aggregator_history();
    }

    /// Refresh tunnel registrations for all connected peers and evict expired ones.
    /// Tunnels have a 5-minute TTL from ConnectionEstablished. Since connections
    /// are persistent, we must renew them periodically to prevent expiration.
    fn refresh_and_evict_tunnels(&mut self) {
        if let (Some(local_pid), Some(swarm)) = (self.local_peer_id, self.swarm.as_ref()) {
            let connected_peers: Vec<PeerId> = swarm.connected_peers().cloned().collect();
            let expires_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() + 300;
            let mut state = self.state.write();
            if let Some(ref mut relay_handler) = state.relay_handler {
                for peer in connected_peers {
                    let tunnel_id = derive_tunnel_id(&peer, &local_pid);
                    relay_handler.register_tunnel(tunnel_id, peer.to_bytes(), expires_at);
                }
                relay_handler.evict_expired_tunnels();
            }
        } else {
            let mut state = self.state.write();
            if let Some(ref mut relay_handler) = state.relay_handler {
                relay_handler.evict_expired_tunnels();
            }
        }
    }

    /// Ensure DHT-discovered relays/exits exist in the topology graph.
    /// Does NOT overwrite `connected_peers` from gossip — only adds new entries
    /// for relays not yet seen via topology gossip. Prunes stale entries.
    fn update_topology(&mut self) {
        use crate::path::TopologyRelay;

        // Add relays that aren't already in topology (from DHT discovery)
        for status in self.relay_nodes.values().filter(|s| s.online) {
            let peer_bytes = status.peer_id.to_bytes();
            if self.topology.get_relay(&peer_bytes).is_none() {
                // Only add if not already present (don't overwrite gossip data)
                self.topology.update_relay(TopologyRelay {
                    peer_id: peer_bytes,
                    signing_pubkey: status.info.pubkey,
                    encryption_pubkey: status.info.encryption_pubkey.unwrap_or([0u8; 32]),
                    connected_peers: HashSet::new(), // Will be filled by topology gossip
                    last_seen: std::time::Instant::now(),
                });
            }
        }

        // Exit nodes are NOT added to the topology graph. They are tracked
        // separately in self.exit_nodes and used directly as OnionPath.exit.
        // Adding exits to the relay topology would allow them to be selected
        // as intermediate relay hops, causing shards to arrive at the exit
        // with non-empty headers (relayed instead of exit-processed).

        // Prune stale entries not seen in 5 minutes
        self.topology.prune_stale(Duration::from_secs(300));
    }

    /// Collect peer IDs that have active streams (intersection of swarm
    /// connected peers and stream-manager peers). Used to populate the
    /// `connected_peers` field in heartbeat messages.
    fn connected_stream_peers(&self) -> Vec<String> {
        if let Some(ref sm) = self.stream_manager {
            let stream_peers: HashSet<PeerId> = sm.stream_peers().into_iter().collect();
            self.swarm.as_ref()
                .map(|s| s.connected_peers()
                    .filter(|p| stream_peers.contains(p))
                    .map(|p| p.to_string())
                    .collect())
                .unwrap_or_default()
        } else {
            vec![]
        }
    }

    /// Build topology-based onion paths and LeaseSet for a request.
    ///
    /// Returns `(paths, first_hop_targets, lease_set)` where:
    /// - `paths`: onion paths for each shard (relay hops + exit)
    /// - `first_hop_targets`: PeerId of the first relay for each path
    /// - `lease_set`: gateway info for response routing
    fn build_request_paths(&self, exit_hop: &PathHop) -> Result<(Vec<crate::path::OnionPath>, Vec<PeerId>, tunnelcraft_core::lease_set::LeaseSet)> {
        use crate::path::{PathSelector, OnionPath, random_id};
        use tunnelcraft_core::lease_set::{LeaseSet, Lease};

        let extra_hops = self.config.hop_mode.extra_hops() as usize;
        let our_peer_id = self.local_peer_id
            .ok_or(ClientError::NotConnected)?;
        let our_bytes = our_peer_id.to_bytes();

        // Select all eligible gateway relays. The primary gateway is the first
        // onion hop for this request's shards. Additional gateways are included
        // in the LeaseSet so the exit can pick any for response routing.
        //
        // Path: client → gateway → [extra_hops relays] → exit
        let all_gateways = self.select_all_gateway_relays(&our_bytes);
        let (gw_peer_id, gw_hop) = all_gateways.first().cloned()
            .ok_or(ClientError::RequestFailed(
                "No gateway relay available (not connected to any relay)".to_string(),
            ))?;

        let tunnel_id = derive_tunnel_id(&our_peer_id, &gw_peer_id);

        info!(
            "Path built: client={} gateway={} tunnel_id={} enc_key={} (lease_set has {} gateways)",
            our_peer_id,
            gw_peer_id,
            hex::encode(&tunnel_id[..8]),
            hex::encode(&gw_hop.encryption_pubkey[..8]),
            all_gateways.len(),
        );

        // Build LeaseSet with all available gateways
        let leases: Vec<Lease> = all_gateways.iter().map(|(pid, hop)| {
            let tid = derive_tunnel_id(&our_peer_id, pid);
            Lease {
                gateway_peer_id: pid.to_bytes(),
                gateway_encryption_pubkey: hop.encryption_pubkey,
                tunnel_id: tid,
                expires_at: u64::MAX,
            }
        }).collect();

        let lease_set = LeaseSet {
            session_id: random_id(),
            leases,
        };

        // Build paths: gateway is always the first onion hop
        let gw_bytes = gw_peer_id.to_bytes();

        if extra_hops == 0 {
            // Direct mode: path = [gateway] → exit (1 onion hop)
            let path = OnionPath {
                hops: vec![gw_hop],
                exit: exit_hop.clone(),
            };
            return Ok((vec![path], vec![gw_peer_id], lease_set));
        }

        // Multi-hop: select additional relay hops after gateway
        // entry_peer = gateway, so first extra relay must be connected to gateway
        let extra_paths = PathSelector::select_diverse_paths(
            &self.topology,
            extra_hops,
            exit_hop,
            tunnelcraft_erasure::TOTAL_SHARDS,
            Some(&gw_bytes),
        )?;

        // Prepend gateway to each path
        let paths: Vec<OnionPath> = extra_paths.into_iter().map(|p| {
            let mut hops = vec![gw_hop.clone()];
            hops.extend(p.hops);
            OnionPath { hops, exit: p.exit }
        }).collect();

        // first_hops is always the gateway for all paths
        let first_hops = vec![gw_peer_id; paths.len()];

        Ok((paths, first_hops, lease_set))
    }

    /// Select a gateway relay using relay_nodes (DHT-verified relays) + topology.
    ///
    /// Only DHT-verified relay nodes are eligible as gateways. Topology gossip
    /// is used to prefer relays that confirm they see us, and to supply the
    /// encryption pubkey (needed for onion headers). The gateway MUST be a peer
    /// we're directly connected to via swarm (tunnel registration happens on
    /// ConnectionEstablished).
    ///
    /// Returns `(PeerId, PathHop)` with full info needed for onion layer.
    fn select_gateway_relay(&self, our_bytes: &[u8]) -> Option<(PeerId, PathHop)> {
        let swarm = self.swarm.as_ref()?;
        let sm = self.stream_manager.as_ref();

        info!("Selecting gateway relay from {} known relay nodes", self.relay_nodes.len());

        for relay_status in self.relay_nodes.values() {
            let connected = swarm.is_connected(&relay_status.peer_id);
            let has_stream = sm.map(|s| s.has_stream(&relay_status.peer_id)).unwrap_or(false);
            let has_enc_key = relay_status.info.encryption_pubkey.is_some()
                && relay_status.info.encryption_pubkey != Some([0u8; 32]);
            info!(
                "  relay {} connected={} stream={} has_encryption_key={}",
                relay_status.peer_id, connected, has_stream, has_enc_key
            );
        }

        // Best: DHT relay that also appears in topology with our bytes in connected_peers
        // AND has an established shard-stream
        for relay_status in self.relay_nodes.values() {
            if !swarm.is_connected(&relay_status.peer_id) {
                continue;
            }
            if !sm.map(|s| s.has_stream(&relay_status.peer_id)).unwrap_or(false) {
                continue;
            }
            // Check if topology confirms this relay sees us
            if let Some(topo_relay) = self.topology.relays_with_encryption()
                .into_iter()
                .find(|r| r.signing_pubkey == relay_status.info.pubkey
                    && r.connected_peers.contains(our_bytes))
            {
                info!("Selected gateway relay {} (topology-confirmed, stream=true)", relay_status.peer_id);
                return Some((relay_status.peer_id, PathHop {
                    peer_id: relay_status.peer_id.to_bytes(),
                    signing_pubkey: topo_relay.signing_pubkey,
                    encryption_pubkey: topo_relay.encryption_pubkey,
                }));
            }
        }

        // Fallback: any DHT relay connected via swarm with stream (use topology enc key if available)
        for relay_status in self.relay_nodes.values() {
            if !swarm.is_connected(&relay_status.peer_id) {
                continue;
            }
            if !sm.map(|s| s.has_stream(&relay_status.peer_id)).unwrap_or(false) {
                continue;
            }
            // Try to get encryption key from topology
            let enc_key = self.topology.relays_with_encryption()
                .into_iter()
                .find(|r| r.signing_pubkey == relay_status.info.pubkey)
                .map(|r| r.encryption_pubkey)
                .or(relay_status.info.encryption_pubkey)
                .unwrap_or([0u8; 32]);

            if enc_key == [0u8; 32] {
                continue; // Skip relays with no encryption key
            }

            info!("Selected gateway relay {} (fallback, stream=true)", relay_status.peer_id);
            return Some((relay_status.peer_id, PathHop {
                peer_id: relay_status.peer_id.to_bytes(),
                signing_pubkey: relay_status.info.pubkey,
                encryption_pubkey: enc_key,
            }));
        }

        info!("No suitable gateway relay found");
        None
    }

    /// Select ALL eligible gateway relays for the LeaseSet.
    ///
    /// Returns a list of `(PeerId, PathHop)` sorted: topology-confirmed first,
    /// then fallback relays. The first entry is the primary gateway for this
    /// request. Additional entries go into the LeaseSet so the exit can pick
    /// any for response routing.
    fn select_all_gateway_relays(&self, our_bytes: &[u8]) -> Vec<(PeerId, PathHop)> {
        let Some(swarm) = self.swarm.as_ref() else { return vec![] };
        let sm = self.stream_manager.as_ref();

        let mut results = Vec::new();
        let mut seen = HashSet::new();

        // First pass: topology-confirmed relays with stream (best quality)
        for relay_status in self.relay_nodes.values() {
            if !swarm.is_connected(&relay_status.peer_id) {
                continue;
            }
            if !sm.map(|s| s.has_stream(&relay_status.peer_id)).unwrap_or(false) {
                continue;
            }
            if let Some(topo_relay) = self.topology.relays_with_encryption()
                .into_iter()
                .find(|r| r.signing_pubkey == relay_status.info.pubkey
                    && r.connected_peers.contains(our_bytes))
            {
                if seen.insert(relay_status.peer_id) {
                    results.push((relay_status.peer_id, PathHop {
                        peer_id: relay_status.peer_id.to_bytes(),
                        signing_pubkey: topo_relay.signing_pubkey,
                        encryption_pubkey: topo_relay.encryption_pubkey,
                    }));
                }
            }
        }

        // Second pass: DHT relays with encryption keys + stream (fallback)
        for relay_status in self.relay_nodes.values() {
            if !swarm.is_connected(&relay_status.peer_id) || seen.contains(&relay_status.peer_id) {
                continue;
            }
            if !sm.map(|s| s.has_stream(&relay_status.peer_id)).unwrap_or(false) {
                continue;
            }
            let enc_key = self.topology.relays_with_encryption()
                .into_iter()
                .find(|r| r.signing_pubkey == relay_status.info.pubkey)
                .map(|r| r.encryption_pubkey)
                .or(relay_status.info.encryption_pubkey)
                .unwrap_or([0u8; 32]);

            if enc_key == [0u8; 32] {
                continue;
            }

            if seen.insert(relay_status.peer_id) {
                results.push((relay_status.peer_id, PathHop {
                    peer_id: relay_status.peer_id.to_bytes(),
                    signing_pubkey: relay_status.info.pubkey,
                    encryption_pubkey: enc_key,
                }));
            }
        }

        // Sort: gateways with active streams first (ready to send immediately)
        if let Some(ref sm) = self.stream_manager {
            results.sort_by_key(|(pid, _)| if sm.has_stream(pid) { 0 } else { 1 });
        }

        info!("Selected {} gateway relays for LeaseSet ({} with active streams)",
            results.len(),
            results.iter().filter(|(pid, _)| {
                self.stream_manager.as_ref().map_or(false, |sm| sm.has_stream(pid))
            }).count(),
        );
        results
    }

    /// Register a tunnel_id → client PeerId mapping in this node's relay handler.
    /// Used for gateway mode: the client pre-registers so the gateway knows
    /// where to forward response shards.
    pub fn register_tunnel(&self, tunnel_id: Id, client_peer_id: Vec<u8>, expires_at: u64) {
        let mut state = self.state.write();
        if let Some(ref mut relay_handler) = state.relay_handler {
            relay_handler.register_tunnel(tunnel_id, client_peer_id, expires_at);
        } else {
            warn!("register_tunnel: no relay_handler, skipping tunnel {}", hex::encode(&tunnel_id[..8]));
        }
    }

    /// Run the event loop (blocking)
    pub async fn run(&mut self) -> Result<()> {
        info!("Node event loop started with capabilities {:?}", self.capabilities);

        // Periodic maintenance interval (configurable, default 30 seconds)
        let mut maintenance_interval = tokio::time::interval(self.maintenance_interval);

        loop {
            if self.swarm.is_none() {
                break;
            }

            tokio::select! {
                // Handle network events
                event = async {
                    if let Some(ref mut swarm) = self.swarm {
                        Some(swarm.select_next_some().await)
                    } else {
                        None
                    }
                } => {
                    if let Some(event) = event {
                        self.handle_swarm_event(event).await;
                    }
                }

                // Handle tunnel bursts from SOCKS5 proxy
                burst = async {
                    if let Some(ref mut rx) = self.tunnel_burst_rx {
                        rx.recv().await
                    } else {
                        // No SOCKS5 server configured — pend forever
                        std::future::pending().await
                    }
                } => {
                    if let Some(burst) = burst {
                        self.handle_tunnel_burst(burst).await;
                    }
                }

                // Periodic maintenance tasks
                _ = maintenance_interval.tick() => {
                    self.maybe_reannounce_exit();
                    self.maybe_reannounce_peer();
                    self.maybe_send_heartbeat();
                    self.check_exit_timeouts();
                    self.discover_exits();
                    self.cleanup_stale_exits();
                    // Relay maintenance
                    self.maybe_reannounce_relay();
                    self.maybe_send_relay_heartbeat();
                    self.discover_relays();
                    self.check_relay_timeouts();
                    self.cleanup_stale_relays();
                    // Subscription verification
                    self.maybe_verify_subscriptions().await;
                    // Distribution posting
                    self.maybe_post_distributions().await;
                    // NAT traversal
                    self.maybe_reconnect_bootstrap();
                }
            }
        }

        Ok(())
    }

    /// Trigger exit discovery via DHT
    pub fn discover_exits(&mut self) {
        // Throttle: skip if we have enough exits and discovered recently
        let online_exits = self.exit_nodes.values().filter(|s| s.online).count();
        if online_exits >= 1 {
            if let Some(last) = self.last_exit_discovery {
                if last.elapsed() < Duration::from_secs(120) {
                    return;
                }
            }
        }
        if let Some(ref mut swarm) = self.swarm {
            debug!("Starting exit discovery via DHT (existing exit_nodes={})", self.exit_nodes.len());
            let qid = swarm.behaviour_mut().get_exit_providers();
            self.pending_exit_provider_queries.insert(qid);
            self.last_exit_discovery = Some(std::time::Instant::now());
        }
    }

    /// Handle swarm event
    async fn handle_swarm_event(&mut self, event: SwarmEvent<TunnelCraftBehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on {}", address);
                if let Some(ref mut swarm) = self.swarm {
                    swarm.add_external_address(address);
                }
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                debug!("Connected to peer: {}", peer_id);
                if !self.unverified_relay_peers.contains(&peer_id) {
                    self.unverified_relay_peers.push(peer_id);
                }
                // Register a deterministic tunnel for this connection.
                // Both sides derive the same tunnel_id from their peer IDs.
                // This node acts as gateway: remote peer → us (tunnel lookup returns remote_peer_id).
                if let Some(local_pid) = self.local_peer_id {
                    let tunnel_id = derive_tunnel_id(&peer_id, &local_pid);
                    // 5-minute TTL — renewed periodically in refresh_and_evict_tunnels()
                    let expires_at = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() + 300;
                    self.register_tunnel(tunnel_id, peer_id.to_bytes(), expires_at);
                }
                let mut state = self.state.write();
                state.stats.peers_connected += 1;
                drop(state);
                // Queue a stream open to the new peer. ensure_opening adds to a
                // pending queue; poll_open_streams drains it with a concurrency limit
                // (MAX_CONCURRENT_OPENS) to avoid substream contention with Kademlia.
                // Clear any stale cooldown first — the fresh connection means we can open.
                if let Some(ref mut sm) = self.stream_manager {
                    sm.clear_open_cooldown(&peer_id);
                    sm.ensure_opening(peer_id);
                }
                // Topology is now carried in heartbeats (30s interval), so new
                // connections will be picked up at the next heartbeat cycle.
            }
            SwarmEvent::ConnectionClosed { peer_id, num_established, .. } => {
                debug!("Connection closed to peer: {} (remaining={})", peer_id, num_established);
                let mut state = self.state.write();
                state.stats.peers_connected = state.stats.peers_connected.saturating_sub(1);
                drop(state);

                // Tunnel registrations are time-committed — topology gossip is
                // the commitment. Don't unregister tunnels on connection events;
                // let refresh_and_evict_tunnels() handle cleanup in maintenance.
                if num_established == 0 {
                    info!("Fully disconnected from peer: {}", peer_id);
                    self.unverified_relay_peers.retain(|p| p != &peer_id);
                    for status in self.relay_nodes.values_mut() {
                        if status.peer_id == peer_id {
                            status.online = false;
                        }
                    }
                    // Clean up persistent stream
                    if let Some(ref mut sm) = self.stream_manager {
                        sm.on_peer_disconnected(&peer_id);
                    }
                    // Topology is now carried in heartbeats — disconnection will be
                    // reflected at the next 30s heartbeat cycle.
                }
            }
            SwarmEvent::Behaviour(behaviour_event) => {
                self.handle_behaviour_event(behaviour_event).await;
            }
            _ => {}
        }
    }

    /// Handle behaviour event
    async fn handle_behaviour_event(&mut self, event: TunnelCraftBehaviourEvent) {
        match event {
            TunnelCraftBehaviourEvent::Kademlia(kad_event) => {
                self.handle_kademlia_event(kad_event);
            }
            TunnelCraftBehaviourEvent::Mdns(mdns_event) => {
                use libp2p::mdns::Event;
                match mdns_event {
                    Event::Discovered(peers) => {
                        if !self.local_discovery_enabled {
                            debug!("mDNS discovery disabled, ignoring {} peers", peers.len());
                            return;
                        }
                        let mut new_peers = false;
                        for (peer_id, addr) in peers {
                            debug!("mDNS discovered peer {} at {}", peer_id, addr);
                            if let Some(ref mut swarm) = self.swarm {
                                swarm.behaviour_mut().add_address(&peer_id, addr);
                            }
                            if !self.unverified_relay_peers.contains(&peer_id) {
                                self.unverified_relay_peers.push(peer_id);
                                new_peers = true;
                            }
                        }
                        // Re-announce our peer record when new peers join
                        // so they learn our pubkey → PeerId mapping faster
                        if new_peers {
                            self.announce_as_peer();
                        }
                    }
                    Event::Expired(peers) => {
                        for (peer_id, _) in peers {
                            self.unverified_relay_peers.retain(|p| p != &peer_id);
                        }
                    }
                }
            }
            TunnelCraftBehaviourEvent::Gossipsub(gossip_event) => {
                use libp2p::gossipsub::{Event, IdentTopic};
                if let Event::Message { message, propagation_source, .. } = gossip_event {
                    // Route by topic hash
                    let exit_hash = IdentTopic::new(EXIT_STATUS_TOPIC).hash();
                    let relay_hash = IdentTopic::new(RELAY_STATUS_TOPIC).hash();
                    let proof_hash = IdentTopic::new(PROOF_TOPIC).hash();
                    let sub_hash = IdentTopic::new(SUBSCRIPTION_TOPIC).hash();
                    let agg_sync_hash = IdentTopic::new(AGGREGATOR_SYNC_TOPIC).hash();

                    if message.topic == exit_hash {
                        self.handle_exit_status(&message.data, Some(propagation_source));
                    } else if message.topic == relay_hash {
                        self.handle_relay_status(&message.data, Some(propagation_source));
                    } else if message.topic == proof_hash {
                        self.handle_proof_message(&message.data, Some(propagation_source));
                    } else if message.topic == sub_hash {
                        self.handle_subscription_announcement(&message.data);
                    } else if message.topic == agg_sync_hash {
                        self.handle_aggregator_sync(&message.data);
                    } else {
                        debug!("Received gossipsub message on unknown topic: {:?}", message.topic);
                    }
                }
            }
            TunnelCraftBehaviourEvent::AutoNat(autonat_event) => {
                self.handle_autonat_event(autonat_event);
            }
            _ => {}
        }
    }

    /// Handle AutoNAT events (NAT detection)
    fn handle_autonat_event(&mut self, event: libp2p::autonat::Event) {
        use libp2p::autonat::Event;
        if let Event::StatusChanged { new, .. } = event {
            use libp2p::autonat::NatStatus as LibNatStatus;
            match new {
                LibNatStatus::Public(_addr) => {
                    info!("AutoNAT: Publicly reachable");
                    self.nat_status = NatStatus::Public;
                }
                LibNatStatus::Private => {
                    warn!("AutoNAT: Behind NAT (private)");
                    self.nat_status = NatStatus::Private;
                    // Register with circuit relay through bootstrap peers
                    self.register_with_circuit_relay();
                }
                LibNatStatus::Unknown => {
                    debug!("AutoNAT: Status unknown");
                    self.nat_status = NatStatus::Unknown;
                }
            }
        }
    }

    /// Register with circuit relay through bootstrap peers (for NATted nodes)
    fn register_with_circuit_relay(&mut self) {
        if self.bootstrap_peer_ids.is_empty() {
            return;
        }

        for bootstrap_id in self.bootstrap_peer_ids.clone() {
            if let Some(ref mut swarm) = self.swarm {
                // Build relay-circuit multiaddr: /p2p/<bootstrap_id>/p2p-circuit
                let relay_addr: Multiaddr = format!("/p2p/{}/p2p-circuit", bootstrap_id)
                    .parse()
                    .unwrap();
                match swarm.listen_on(relay_addr.clone()) {
                    Ok(_) => info!("Listening via circuit relay through {}", bootstrap_id),
                    Err(e) => debug!("Failed to listen via circuit relay through {}: {:?}", bootstrap_id, e),
                }
            }
        }
    }

    /// Reconnect to bootstrap peers if we've lost all connections
    fn maybe_reconnect_bootstrap(&mut self) {
        let should_check = self.last_bootstrap_check
            .map(|t| t.elapsed() > Duration::from_secs(60))
            .unwrap_or(true);

        if !should_check {
            return;
        }
        self.last_bootstrap_check = Some(std::time::Instant::now());

        // Check if we're connected to any bootstrap peer
        let connected_to_bootstrap = if let Some(ref swarm) = self.swarm {
            self.bootstrap_peer_ids.iter().any(|pid| swarm.is_connected(pid))
        } else {
            return;
        };

        if !connected_to_bootstrap && !self.bootstrap_peer_ids.is_empty() {
            warn!("Lost connection to all bootstrap peers, reconnecting...");

            // Re-dial bootstrap peers
            let bootstrap_peers = if !self.config.bootstrap_peers.is_empty() {
                self.config.bootstrap_peers.clone()
            } else {
                tunnelcraft_network::default_bootstrap_peers()
            };

            for (peer_id, addr) in &bootstrap_peers {
                if let Some(ref mut swarm) = self.swarm {
                    swarm.behaviour_mut().add_address(peer_id, addr.clone());
                    let _ = swarm.dial(*peer_id);
                }
            }

            // Re-bootstrap Kademlia
            if let Some(ref mut swarm) = self.swarm {
                match swarm.behaviour_mut().bootstrap() {
                    Ok(_) => debug!("Re-bootstrapped Kademlia DHT"),
                    Err(e) => warn!("Re-bootstrap failed: {:?}", e),
                }
            }
        }
    }

    /// Handle Kademlia DHT events (exit/relay node discovery + peer connectivity)
    fn handle_kademlia_event(&mut self, event: libp2p::kad::Event) {
        use libp2p::kad::{Event, QueryResult, GetRecordOk, GetProvidersOk};
        use tunnelcraft_network::{EXIT_DHT_KEY_PREFIX, RELAY_DHT_KEY_PREFIX, PEER_DHT_KEY_PREFIX};

        match event {
            // Kademlia discovered a new peer in the routing table.
            // Do NOT auto-dial: relay/exit peers are discovered via targeted
            // DHT queries (GET_PROVIDERS). Auto-dialing RoutingUpdated peers
            // pulls in global network nodes that pollute topology and waste
            // connections (causes gossipsub queue overflow in test networks).
            Event::RoutingUpdated { peer, is_new_peer, .. } => {
                if is_new_peer {
                    debug!("DHT routing updated: new peer {} (not auto-dialing)", peer);
                }
            }
            Event::OutboundQueryProgressed { id, result, .. } => {
                match result {
                    QueryResult::GetRecord(Ok(GetRecordOk::FoundRecord(peer_record))) => {
                        let key_str = String::from_utf8_lossy(peer_record.record.key.as_ref());
                        if key_str.starts_with(EXIT_DHT_KEY_PREFIX) {
                            // Parse PeerId from DHT key: /tunnelcraft/exits/<peer_id>
                            let exit_peer_id = key_str.strip_prefix(EXIT_DHT_KEY_PREFIX)
                                .and_then(|pid_str| pid_str.parse::<PeerId>().ok());

                            // Parse exit info from record
                            if let Ok(exit_info) = serde_json::from_slice::<ExitInfo>(&peer_record.record.value) {
                                self.on_exit_discovered(exit_info, exit_peer_id);
                            }
                        } else if key_str.starts_with(RELAY_DHT_KEY_PREFIX) {
                            // Parse PeerId from DHT key: /tunnelcraft/relays/<peer_id>
                            let relay_peer_id = key_str.strip_prefix(RELAY_DHT_KEY_PREFIX)
                                .and_then(|pid_str| pid_str.parse::<PeerId>().ok());

                            // Parse relay info from record
                            match serde_json::from_slice::<RelayInfo>(&peer_record.record.value) {
                                Ok(relay_info) => {
                                    info!("DHT relay record retrieved: peer_id={:?} pubkey={}", relay_peer_id, hex::encode(&relay_info.pubkey[..8]));
                                    self.on_relay_discovered(relay_info, relay_peer_id);
                                }
                                Err(e) => {
                                    warn!("DHT relay record deserialization failed: peer_id={:?} err={} raw_len={} raw={}",
                                        relay_peer_id, e, peer_record.record.value.len(),
                                        String::from_utf8_lossy(&peer_record.record.value[..peer_record.record.value.len().min(200)]));
                                }
                            }
                            self.pending_relay_record_queries.remove(&id);
                        } else if key_str.starts_with(PEER_DHT_KEY_PREFIX) {
                            // Parse peer record: /tunnelcraft/peers/<pubkey_hex> → PeerId bytes
                            if let Some(pubkey_hex) = key_str.strip_prefix(PEER_DHT_KEY_PREFIX) {
                                if let Ok(pubkey_bytes) = hex::decode(pubkey_hex) {
                                    if pubkey_bytes.len() == 32 {
                                        if let Ok(peer_id) = PeerId::from_bytes(&peer_record.record.value) {
                                            let mut pubkey = [0u8; 32];
                                            pubkey.copy_from_slice(&pubkey_bytes);
                                            info!("Resolved peer record: {} → {}", pubkey_hex, peer_id);
                                            self.known_peers.insert(pubkey, peer_id);

                                            // Flush any shards buffered for this destination via outbound channel
                                            if let Some(shards) = self.pending_destination.remove(&pubkey) {
                                                let count = shards.len();
                                                if let Some(ref tx) = self.outbound_tx {
                                                    for shard in shards {
                                                        let _ = tx.try_send(OutboundShard { peer: peer_id, shard });
                                                    }
                                                }
                                                info!("Queued {} buffered shards for peer {} via outbound channel", count, peer_id);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    QueryResult::GetProviders(Ok(result)) => {
                        // Use contains (not remove) because get_providers fires FoundProviders
                        // progressively — removing on first event would misclassify later batches.
                        // Removal happens in FinishedWithNoAdditionalRecord when the query is done.
                        let is_relay_query = self.pending_relay_provider_queries.contains(&id);
                        let is_exit_query = self.pending_exit_provider_queries.contains(&id);

                        match result {
                            GetProvidersOk::FoundProviders { providers, .. } => {
                                if is_relay_query {
                                    info!("DHT found {} relay providers", providers.len());
                                    for provider_id in &providers {
                                        debug!("DHT relay provider: {}", provider_id);
                                    }
                                    for provider_id in providers {
                                        if let Some(ref mut swarm) = self.swarm {
                                            let qid = swarm.behaviour_mut().get_relay_record(&provider_id);
                                            self.pending_relay_record_queries.insert(qid);
                                        }
                                    }
                                } else if is_exit_query {
                                    info!("DHT found {} exit providers", providers.len());
                                    for provider_id in &providers {
                                        debug!("DHT exit provider: {}", provider_id);
                                    }
                                    for provider_id in providers {
                                        if let Some(ref mut swarm) = self.swarm {
                                            swarm.behaviour_mut().get_exit_record(&provider_id);
                                        }
                                    }
                                } else {
                                    warn!("DHT GetProviders for unknown query id {:?}, {} providers", id, providers.len());
                                }
                            }
                            GetProvidersOk::FinishedWithNoAdditionalRecord { .. } => {
                                // Now safe to remove — query is complete
                                if self.pending_relay_provider_queries.remove(&id) {
                                    debug!("DHT relay provider query finished (relay_nodes={})", self.relay_nodes.len());
                                } else if self.pending_exit_provider_queries.remove(&id) {
                                    debug!("DHT exit provider query finished (exit_nodes={})", self.exit_nodes.len());
                                }
                            }
                        }
                    }
                    QueryResult::GetProviders(Err(ref e)) => {
                        warn!("DHT GetProviders failed: {:?}", e);
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    /// Called when a new exit node is discovered via DHT
    fn on_exit_discovered(&mut self, exit_info: ExitInfo, peer_id: Option<PeerId>) {
        let is_new = !self.exit_nodes.contains_key(&exit_info.pubkey);

        if is_new {
            // New exit - create status entry with base 50% score
            let mut status = ExitNodeStatus::new(exit_info.clone());
            status.peer_id = peer_id;
            // Register in known_peers so destination_peer_id() works uniformly
            if let Some(pid) = peer_id {
                self.known_peers.insert(exit_info.pubkey, pid);
            }
            self.exit_nodes.insert(exit_info.pubkey, status);

            info!(
                "Discovered exit node: region={:?}, country={:?}, city={:?}, score={}",
                exit_info.region, exit_info.country_code, exit_info.city, EXIT_BASE_SCORE
            );

            // Auto-select best exit if none selected (respects geo preference)
            if self.selected_exit.is_none() {
                self.select_best_exit();
            }
        } else {
            // Existing exit - update DHT timestamp and peer_id if available
            if let Some(status) = self.exit_nodes.get_mut(&exit_info.pubkey) {
                status.last_dht_seen = std::time::Instant::now();
                status.info = exit_info.clone();
                if status.peer_id.is_none() && peer_id.is_some() {
                    status.peer_id = peer_id;
                }
                // Keep known_peers in sync
                if let Some(pid) = peer_id {
                    self.known_peers.insert(exit_info.pubkey, pid);
                }
            }
        }
    }

    /// Remove stale exits that haven't been seen recently
    /// Called periodically from the run loop
    fn cleanup_stale_exits(&mut self) {
        use tunnelcraft_network::EXIT_RECORD_TTL;

        let now = std::time::Instant::now();
        let before_count = self.exit_nodes.len();

        self.exit_nodes.retain(|_pubkey, status| {
            now.duration_since(status.last_dht_seen) < EXIT_RECORD_TTL
        });

        let removed = before_count - self.exit_nodes.len();
        if removed > 0 {
            info!("Removed {} stale exit nodes", removed);

            // Clear selected exit if it was removed
            if let Some(ref selected) = self.selected_exit {
                if !self.exit_nodes.contains_key(&selected.pubkey) {
                    self.select_best_exit();
                }
            }
        }
    }

    /// Get discovered exit nodes (excludes stale ones)
    pub fn exit_nodes(&self) -> Vec<&ExitInfo> {
        self.exit_nodes.values().map(|status| &status.info).collect()
    }

    /// Get online exit nodes only
    pub fn online_exit_nodes(&self) -> Vec<&ExitInfo> {
        self.exit_nodes.values()
            .filter(|status| status.online)
            .map(|status| &status.info)
            .collect()
    }

    /// Get exit nodes filtered by region
    pub fn exit_nodes_by_region(&self, region: ExitRegion) -> Vec<&ExitInfo> {
        self.exit_nodes.values()
            .filter(|status| status.online && status.info.region == region)
            .map(|status| &status.info)
            .collect()
    }

    /// Get exit nodes filtered by country
    pub fn exit_nodes_by_country(&self, country_code: &str) -> Vec<&ExitInfo> {
        self.exit_nodes.values()
            .filter(|status| status.online && status.info.country_code.as_deref() == Some(country_code))
            .map(|status| &status.info)
            .collect()
    }

    /// Get exit node load percentage
    pub fn exit_load(&self, pubkey: &[u8; 32]) -> Option<u8> {
        self.exit_nodes.get(pubkey).map(|status| status.announced_load_percent)
    }

    /// Get exit node score (lower is better)
    pub fn exit_score(&self, pubkey: &[u8; 32]) -> Option<u8> {
        self.exit_nodes.get(pubkey).map(|status| status.score)
    }

    /// Get exit node measured stats
    pub fn exit_measured_stats(&self, pubkey: &[u8; 32]) -> Option<(Option<u32>, Option<u32>, Option<u32>)> {
        self.exit_nodes.get(pubkey).map(|status| {
            (status.measured_latency_ms, status.measured_uplink_kbps, status.measured_downlink_kbps)
        })
    }

    /// Check if exit is online
    pub fn is_exit_online(&self, pubkey: &[u8; 32]) -> bool {
        self.exit_nodes.get(pubkey).map(|status| status.online).unwrap_or(false)
    }

    /// Get count of known exits
    pub fn exit_count(&self) -> usize {
        self.exit_nodes.len()
    }

    /// Get exit node uptime (announced by exit)
    pub fn exit_uptime(&self, pubkey: &[u8; 32]) -> Option<u64> {
        self.exit_nodes.get(pubkey).map(|status| status.announced_uptime_secs)
    }

    /// Get our own uptime (how long this node has been running)
    pub fn uptime(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Set whether mDNS local discovery is enabled
    ///
    /// When disabled, mDNS-discovered peers are ignored (not added to relay list).
    /// The mDNS behaviour itself remains active (libp2p doesn't support runtime removal),
    /// but discovered peers are simply not used.
    pub fn set_local_discovery(&mut self, enabled: bool) {
        self.local_discovery_enabled = enabled;
        info!("Local discovery set to: {}", enabled);
    }

    /// Check if local discovery is enabled
    pub fn local_discovery_enabled(&self) -> bool {
        self.local_discovery_enabled
    }

    /// Set bandwidth limit in kbps (None = unlimited)
    pub fn set_bandwidth_limit(&mut self, limit_kbps: Option<u64>) {
        self.bandwidth_limit_kbps = limit_kbps;
        info!("Bandwidth limit set to: {:?} kbps", limit_kbps);
    }

    // =========================================================================
    // Relay DHT discovery + load gossip lifecycle
    // =========================================================================

    /// Count of available relays (DHT-verified online + unverified peers)
    pub fn available_relay_count(&self) -> usize {
        let dht_online = self.relay_nodes.values().filter(|s| s.online).count();
        dht_online + self.unverified_relay_peers.len()
    }

    /// Announce self as relay in DHT (put record + start providing)
    fn announce_as_relay(&mut self) {
        let peer_id = match self.local_peer_id {
            Some(pid) => pid,
            None => return,
        };

        let relay_info = RelayInfo {
            pubkey: self.keypair.public_key_bytes(),
            address: self.config.listen_addr.to_string(),
            allows_last_hop: self.config.allow_last_hop,
            reputation: 0,
            encryption_pubkey: Some(self.encryption_keypair.public_key_bytes()),
        };

        if let Some(ref mut swarm) = self.swarm {
            let record_value = serde_json::to_vec(&relay_info).unwrap_or_default();
            if let Err(e) = swarm.behaviour_mut().put_relay_record(&peer_id, record_value) {
                warn!("Failed to put relay DHT record: {:?}", e);
            }
            if let Err(e) = swarm.behaviour_mut().start_providing_relay() {
                warn!("Failed to start providing relay: {:?}", e);
            }
            debug!("announce_as_relay: peer_id={}, put_record + start_providing done", peer_id);
            info!("Announced as relay node via DHT");
        }

        self.last_relay_announcement = Some(std::time::Instant::now());
    }

    /// Re-announce as relay every 2 minutes (if in relay mode)
    fn maybe_reannounce_relay(&mut self) {
        if !self.capabilities.is_relay() {
            return;
        }
        let should_reannounce = self.last_relay_announcement
            .map(|t| t.elapsed() > Duration::from_secs(120))
            .unwrap_or(true);
        if should_reannounce {
            self.announce_as_relay();
        }
    }

    /// Publish relay heartbeat via gossipsub
    fn publish_relay_heartbeat(&mut self) {
        if !self.capabilities.is_relay() {
            return;
        }

        let load_percent = (self.active_requests.min(100) as u8).min(100);
        let uptime_secs = self.start_time.elapsed().as_secs();
        let queue_depth = self.proof_queue_depth() as u32;
        let connected_peers = self.connected_stream_peers();

        if let Some(ref mut swarm) = self.swarm {
            let peer_id_str = self.local_peer_id.map(|p| p.to_string()).unwrap_or_default();
            let mut msg = RelayStatusMessage::heartbeat(
                self.keypair.public_key_bytes(),
                &peer_id_str,
                load_percent,
                self.active_requests,
                queue_depth,
                self.exit_downlink_kbps, // reuse throughput measurement
                uptime_secs,
                connected_peers,
            );
            msg.encryption_pubkey = Some(hex::encode(self.encryption_keypair.public_key_bytes()));
            if let Err(e) = swarm.behaviour_mut().publish_relay_status(msg.to_bytes()) {
                debug!("Failed to publish relay heartbeat: {:?}", e);
            }
        }
    }

    /// Send relay heartbeat every RELAY_HEARTBEAT_INTERVAL (30s)
    fn maybe_send_relay_heartbeat(&mut self) {
        if !self.capabilities.is_relay() {
            return;
        }
        let should_send = self.last_relay_heartbeat_sent
            .map(|t| t.elapsed() >= RELAY_HEARTBEAT_INTERVAL)
            .unwrap_or(true);
        if should_send {
            self.publish_relay_heartbeat();
            self.last_relay_heartbeat_sent = Some(std::time::Instant::now());
        }
    }

    /// Handle incoming relay status gossipsub message
    fn handle_relay_status(&mut self, data: &[u8], source: Option<PeerId>) {
        let Some(msg) = RelayStatusMessage::from_bytes(data) else {
            debug!("Failed to parse relay status message");
            return;
        };

        let Some(pubkey) = msg.pubkey_bytes() else {
            debug!("Invalid pubkey in relay status message");
            return;
        };

        match msg.status {
            RelayStatusType::Heartbeat => {
                if let Some(status) = self.relay_nodes.get_mut(&pubkey) {
                    if status.peer_id == PeerId::random() {
                        // Update peer_id from gossipsub source if we don't have one yet
                        if let Some(src) = source {
                            status.peer_id = src;
                        }
                    }
                    status.update_from_heartbeat(
                        msg.load_percent,
                        msg.active_connections,
                        msg.queue_depth,
                        msg.bandwidth_available_kbps,
                        msg.uptime_secs,
                    );
                    debug!(
                        "Updated relay status for {}: load={}%, queue={}, bw={}KB/s, score={}",
                        msg.peer_id, msg.load_percent, msg.queue_depth, msg.bandwidth_available_kbps, status.score
                    );
                } else {
                    // Unknown relay — trigger DHT lookup
                    debug!("Heartbeat from unknown relay: {} (from {:?})", msg.peer_id, source);
                }

                // Update topology from heartbeat's connected_peers
                if !msg.connected_peers.is_empty() {
                    if let Some(enc_hex) = &msg.encryption_pubkey {
                        if let Ok(enc_bytes) = hex::decode(enc_hex) {
                            if enc_bytes.len() == 32 {
                                use crate::path::TopologyRelay;
                                let mut enc_key = [0u8; 32];
                                enc_key.copy_from_slice(&enc_bytes);
                                let connected: HashSet<Vec<u8>> = msg.connected_peers.iter()
                                    .filter_map(|s| s.parse::<PeerId>().ok().map(|p| p.to_bytes()))
                                    .collect();
                                let peer_id_bytes = msg.peer_id.parse::<PeerId>()
                                    .map(|p| p.to_bytes())
                                    .unwrap_or_default();
                                if !peer_id_bytes.is_empty() {
                                    self.topology.update_relay(TopologyRelay {
                                        peer_id: peer_id_bytes,
                                        signing_pubkey: pubkey,
                                        encryption_pubkey: enc_key,
                                        connected_peers: connected,
                                        last_seen: std::time::Instant::now(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
            RelayStatusType::Offline => {
                if let Some(status) = self.relay_nodes.get_mut(&pubkey) {
                    status.online = false;
                    info!("Relay {} went offline", msg.peer_id);
                }
            }
        }
    }

    /// Handle incoming proof gossipsub message
    fn handle_proof_message(&mut self, data: &[u8], _source: Option<PeerId>) {
        let Some(ref mut aggregator) = self.aggregator else {
            return; // Not in aggregator mode
        };

        let msg = match ProofMessage::from_bytes(data) {
            Ok(msg) => msg,
            Err(e) => {
                debug!("Failed to parse proof message: {:?}", e);
                return;
            }
        };

        if let Err(e) = aggregator.handle_proof(msg) {
            debug!("Aggregator rejected proof: {:?}", e);
        }
    }

    /// Handle aggregator sync messages (request or response).
    ///
    /// Sync requests: if we have history, respond with entries from the requested seq.
    /// Sync responses: if targeted at us, replay the entries into our history.
    fn handle_aggregator_sync(&mut self, data: &[u8]) {
        if self.aggregator.is_none() {
            return;
        }

        // Try parsing as a sync request first
        if let Ok(req) = HistorySyncRequest::from_bytes(data) {
            let our_pubkey = self.keypair.public_key_bytes();
            if req.requester == our_pubkey {
                return; // Ignore our own requests
            }

            let Some(ref path) = self.aggregator_history_file else { return };
            let entries = Aggregator::history_since(path, req.from_seq);
            if entries.is_empty() {
                return;
            }

            // Batch up to 1000 entries
            const SYNC_BATCH_SIZE: usize = 1000;
            let batch: Vec<Vec<u8>> = entries.iter()
                .take(SYNC_BATCH_SIZE)
                .filter_map(|e| bincode::serialize(e).ok())
                .collect();
            let has_more = entries.len() > SYNC_BATCH_SIZE;
            let batch_len = batch.len();

            let resp = HistorySyncResponse {
                target: req.requester,
                entries: batch,
                has_more,
            };

            let resp_bytes = resp.to_bytes();
            if let Some(ref mut swarm) = self.swarm {
                let _ = swarm.behaviour_mut().publish_aggregator_sync(resp_bytes);
                debug!(
                    "Sent {} history entries to sync requester (has_more={})",
                    batch_len, has_more,
                );
            }
            return;
        }

        // Try parsing as a sync response
        if let Ok(resp) = HistorySyncResponse::from_bytes(data) {
            let our_pubkey = self.keypair.public_key_bytes();
            if resp.target != our_pubkey {
                return; // Not for us
            }

            let mut applied = 0usize;
            for entry_bytes in &resp.entries {
                if serde_json::from_slice::<tunnelcraft_aggregator::HistoryEntry>(entry_bytes).is_ok() {
                    applied += 1;
                }
            }

            if applied > 0 {
                info!("Received {} history entries from peer (has_more={})", applied, resp.has_more);
            }
        }
    }

    /// Handle a subscription announcement from gossipsub
    fn handle_subscription_announcement(&mut self, data: &[u8]) {
        let msg = match SubscriptionAnnouncement::from_bytes(data) {
            Ok(msg) => msg,
            Err(e) => {
                debug!("Failed to parse subscription announcement: {:?}", e);
                return;
            }
        };

        // Verify signature using the announced pubkey
        let signable = msg.signable_data();
        if msg.signature.len() != 64 {
            debug!("Invalid subscription signature length");
            return;
        }
        let sig: [u8; 64] = msg.signature[..64].try_into().unwrap();
        if !tunnelcraft_crypto::verify_signature(&msg.user_pubkey, &signable, &sig) {
            debug!(
                "Invalid subscription signature from {}",
                hex::encode(&msg.user_pubkey[..8]),
            );
            return;
        }

        // Insert/update cache (unverified until on-chain check)
        let now = std::time::Instant::now();
        let entry = self.subscription_cache.entry(msg.user_pubkey).or_insert(SubscriptionEntry {
            tier: msg.tier,
            expires_at: msg.expires_at,
            verified: false,
            last_seen: now,
        });
        entry.tier = msg.tier;
        entry.expires_at = msg.expires_at;
        entry.last_seen = now;

        debug!(
            "Cached subscription announcement: user={}, tier={}, expires={}",
            hex::encode(&msg.user_pubkey[..8]),
            msg.tier,
            msg.expires_at,
        );
    }

    /// Periodically verify recently-seen subscriptions on-chain in batches
    async fn maybe_verify_subscriptions(&mut self) {
        // Only verify in relay mode
        if !self.capabilities.is_service_node() {
            return;
        }

        let should_verify = match self.last_subscription_verify {
            None => true,
            Some(last) => last.elapsed() >= SUBSCRIPTION_VERIFY_INTERVAL,
        };
        if !should_verify {
            return;
        }
        self.last_subscription_verify = Some(std::time::Instant::now());

        let Some(ref settlement) = self.settlement_client else {
            return;
        };
        let settlement = Arc::clone(settlement);

        // Collect unverified users sorted by last_seen (most recent first)
        let mut to_verify: Vec<PublicKey> = self.subscription_cache.iter()
            .filter(|(_, entry)| !entry.verified)
            .map(|(pubkey, _)| *pubkey)
            .collect();
        to_verify.truncate(SUBSCRIPTION_VERIFY_BATCH_SIZE);

        if to_verify.is_empty() {
            return;
        }

        debug!("Verifying {} subscriptions on-chain", to_verify.len());

        for pubkey in to_verify {
            match settlement.is_subscribed(pubkey).await {
                Ok(true) => {
                    if let Some(entry) = self.subscription_cache.get_mut(&pubkey) {
                        entry.verified = true;
                        debug!(
                            "Verified subscription on-chain: {}",
                            hex::encode(&pubkey[..8]),
                        );
                    }
                }
                Ok(false) => {
                    // Not subscribed on-chain — mark as free tier
                    if let Some(entry) = self.subscription_cache.get_mut(&pubkey) {
                        entry.tier = 255; // Free
                        entry.verified = true;
                        debug!(
                            "Subscription NOT found on-chain: {} (marking free)",
                            hex::encode(&pubkey[..8]),
                        );
                    }
                }
                Err(e) => {
                    debug!(
                        "Failed to verify subscription for {}: {:?}",
                        hex::encode(&pubkey[..8]),
                        e,
                    );
                    // Leave unverified, will retry next interval
                }
            }
        }
    }

    /// Pre-build Merkle distributions for expired pool epochs.
    ///
    /// Called periodically from the maintenance interval. For each subscribed pool
    /// the aggregator knows about, checks if the epoch has expired and builds the
    /// distribution Merkle tree. The distribution is recorded but NOT posted
    /// on-chain — an external prover must generate a Groth16 proof and post the
    /// distribution + proof via the settlement client.
    async fn maybe_post_distributions(&mut self) {
        let Some(ref aggregator) = self.aggregator else { return };

        let pools = aggregator.subscribed_pools();
        if pools.is_empty() {
            return;
        }

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for (user_pubkey, _pool_type) in &pools {
            if self.posted_distributions.contains(user_pubkey) {
                continue;
            }

            // Only post distributions after the subscription epoch has expired
            if let Some(entry) = self.subscription_cache.get(user_pubkey) {
                if entry.expires_at > now_unix {
                    info!(
                        "Skipping distribution for pool {}: subscription still active (expires in {}s)",
                        hex::encode(&user_pubkey[..8]),
                        entry.expires_at - now_unix,
                    );
                    continue;
                }
                info!(
                    "Pool {} epoch expired (expired {}s ago) — proceeding with distribution",
                    hex::encode(&user_pubkey[..8]),
                    now_unix - entry.expires_at,
                );
            } else {
                // No subscription info — skip until we receive it via gossip
                info!(
                    "Skipping distribution for pool {}: no subscription info in cache",
                    hex::encode(&user_pubkey[..8]),
                );
                continue;
            }

            let pool_key = (*user_pubkey, _pool_type.clone());
            let Some(dist) = self.aggregator.as_ref().unwrap().build_distribution(&pool_key) else {
                continue;
            };

            // Record distribution-built event in history
            if let Some(ref mut agg) = self.aggregator {
                agg.record_distribution_built(
                    *user_pubkey, *_pool_type,
                    dist.root, dist.total, dist.entries.len(),
                );
            }

            info!(
                "Distribution built for pool {}: {} entries, {} total bytes",
                hex::encode(&user_pubkey[..8]),
                dist.entries.len(),
                dist.total,
            );

            // Verify on-chain subscription exists before expensive proving
            if let Some(ref settlement) = self.settlement_client {
                match settlement.get_subscription_state(*user_pubkey).await {
                    Ok(Some(state)) => {
                        if state.distribution_posted {
                            info!("Distribution already posted on-chain for pool {} — skipping", hex::encode(&user_pubkey[..8]));
                            self.posted_distributions.insert(*user_pubkey);
                            continue;
                        }
                        info!("On-chain subscription confirmed for pool {} (balance: {})", hex::encode(&user_pubkey[..8]), state.pool_balance);
                    }
                    Ok(None) => {
                        info!("No on-chain subscription for pool {} — skipping prove", hex::encode(&user_pubkey[..8]));
                        self.posted_distributions.insert(*user_pubkey);
                        continue;
                    }
                    Err(e) => {
                        warn!("Failed to check subscription for pool {}: {} — skipping this round", hex::encode(&user_pubkey[..8]), e);
                        continue;
                    }
                }
            }

            // Generate Groth16 proof (SP1 feature required)
            #[cfg(not(feature = "sp1"))]
            {
                warn!("SP1 feature not enabled — cannot generate distribution proof, skipping post");
                continue;
            }

            #[cfg(feature = "sp1")]
            let (groth16_proof, sp1_public_inputs) = {
                // Lazy-init the distribution prover
                if self.distribution_prover.is_none() {
                    info!("Initializing SP1 distribution prover...");
                    self.distribution_prover = Some(tunnelcraft_prover::DistributionProver::new());
                }
                let prover = self.distribution_prover.as_ref().unwrap();
                let entries: Vec<([u8; 32], u64)> = dist.entries.iter()
                    .map(|(relay, bytes)| (*relay, *bytes))
                    .collect();
                match prover.prove_distribution(&entries, *user_pubkey) {
                    Ok(proof) => {
                        info!(
                            "Groth16 proof generated: {} proof bytes, {} public values, vkey={}",
                            proof.proof_bytes.len(),
                            proof.public_values.len(),
                            proof.vkey_hash,
                        );
                        (proof.proof_bytes, proof.public_values)
                    }
                    Err(e) => {
                        error!("Groth16 distribution proof failed for pool {}: {}", hex::encode(&user_pubkey[..8]), e);
                        continue;
                    }
                }
            };

            // Post on-chain via settlement client
            #[cfg(feature = "sp1")]
            {
                let Some(ref settlement) = self.settlement_client else {
                    warn!("No settlement client — cannot post distribution on-chain");
                    continue;
                };

                let post = PostDistribution {
                    pool_pubkey: *user_pubkey,
                    distribution_root: dist.root,
                    total_bytes: dist.total,
                    groth16_proof,
                    sp1_public_inputs,
                };

                match settlement.post_distribution(post).await {
                    Ok(sig) => {
                        info!(
                            "Distribution posted on-chain for pool {}: sig={}",
                            hex::encode(&user_pubkey[..8]),
                            hex::encode(sig),
                        );
                        self.posted_distributions.insert(*user_pubkey);
                    }
                    Err(e) => {
                        let err_str = format!("{}", e);
                        if err_str.contains("already been posted") || err_str.contains("AlreadyPosted") {
                            info!(
                                "Distribution already posted for pool {} — marking done",
                                hex::encode(&user_pubkey[..8]),
                            );
                            self.posted_distributions.insert(*user_pubkey);
                        } else if err_str.contains("AccountNotInitialized") || err_str.contains("not initialized") {
                            // No on-chain subscription for this pool — skip permanently
                            info!(
                                "No on-chain subscription for pool {} — skipping",
                                hex::encode(&user_pubkey[..8]),
                            );
                            self.posted_distributions.insert(*user_pubkey);
                        } else {
                            error!(
                                "Failed to post distribution for pool {}: {}",
                                hex::encode(&user_pubkey[..8]),
                                e,
                            );
                        }
                    }
                }
            }
        }
    }

    /// Reconcile aggregator state with on-chain data after loading from disk.
    ///
    /// For each tracked pool, queries the on-chain subscription state to sync
    /// distribution/claim status. This prevents wasting RPC calls re-posting
    /// distributions that already exist on-chain.
    async fn reconcile_aggregator_state(&mut self) {
        let Some(ref aggregator) = self.aggregator else { return };
        let Some(ref settlement) = self.settlement_client else {
            debug!("No settlement client — skipping aggregator reconciliation");
            return;
        };
        let settlement = Arc::clone(settlement);

        let pool_keys = aggregator.pool_keys_for_reconciliation();
        if pool_keys.is_empty() {
            return;
        }

        info!("Reconciling {} aggregator pools with on-chain state", pool_keys.len());

        for batch in pool_keys.chunks(SUBSCRIPTION_VERIFY_BATCH_SIZE) {
            for user_pubkey in batch {
                match settlement.get_subscription_state(*user_pubkey).await {
                    Ok(Some(state)) => {
                        if state.distribution_posted {
                            self.posted_distributions.insert(*user_pubkey);
                            debug!(
                                "Reconciled pool user={}: distribution already posted",
                                hex::encode(&user_pubkey[..8]),
                            );
                        }
                        if state.pool_balance == 0 {
                            debug!(
                                "Reconciled pool user={}: fully claimed",
                                hex::encode(&user_pubkey[..8]),
                            );
                        } else if state.original_pool_balance > 0 && state.pool_balance < state.original_pool_balance {
                            debug!(
                                "Reconciled pool user={}: partially claimed ({} of {} remaining)",
                                hex::encode(&user_pubkey[..8]),
                                state.pool_balance,
                                state.original_pool_balance,
                            );
                        }
                    }
                    Ok(None) => {
                        // No on-chain subscription — mark as posted to prevent
                        // wasting RPC calls attempting post_distribution.
                        self.posted_distributions.insert(*user_pubkey);
                        debug!(
                            "No on-chain subscription for pool user={}, marking as skipped",
                            hex::encode(&user_pubkey[..8]),
                        );
                    }
                    Err(e) => {
                        warn!(
                            "Failed to query on-chain state for user={}: {:?}",
                            hex::encode(&user_pubkey[..8]),
                            e,
                        );
                    }
                }
            }
        }

        info!(
            "Aggregator reconciliation complete: {} posted distributions known",
            self.posted_distributions.len(),
        );
    }

    /// Persist aggregator state (pools + pending proofs + posted_distributions) to disk.
    fn save_aggregator_state(&self) {
        let Some(ref aggregator) = self.aggregator else { return };
        let Some(ref path) = self.aggregator_state_file else { return };
        aggregator.save_to_file(path, &self.posted_distributions);
    }

    /// Flush unflushed history entries to the append-only binary file.
    fn flush_aggregator_history(&mut self) {
        let Some(ref mut aggregator) = self.aggregator else { return };
        let Some(ref path) = self.aggregator_history_file else { return };
        aggregator.flush_history(path);
    }

    /// Announce our subscription to the network (client mode)
    pub fn announce_subscription(&mut self, tier: u8, expires_at: u64) {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut announcement = SubscriptionAnnouncement {
            user_pubkey: self.keypair.public_key_bytes(),
            tier,
            expires_at,
            timestamp,
            signature: vec![],
        };

        let signable = announcement.signable_data();
        announcement.signature = tunnelcraft_crypto::sign_data(&self.keypair, &signable).to_vec();

        if let Some(ref mut swarm) = self.swarm {
            match swarm.behaviour_mut().publish_subscription(announcement.to_bytes()) {
                Ok(_) => info!(
                    "Announced subscription: tier={}, expires={}",
                    tier, expires_at,
                ),
                Err(e) => warn!("Failed to announce subscription: {:?}", e),
            }
        }
    }

    /// Trigger relay discovery via DHT
    pub fn discover_relays(&mut self) {
        // Throttle: skip if we have enough relays and discovered recently
        let online_relays = self.relay_nodes.values().filter(|s| s.online).count();
        if online_relays >= 3 {
            if let Some(last) = self.last_relay_discovery {
                if last.elapsed() < Duration::from_secs(120) {
                    return;
                }
            }
        }
        if let Some(ref mut swarm) = self.swarm {
            debug!("Starting relay discovery via DHT (existing relay_nodes={})", self.relay_nodes.len());
            let qid = swarm.behaviour_mut().get_relay_providers();
            self.pending_relay_provider_queries.insert(qid);
            self.last_relay_discovery = Some(std::time::Instant::now());
        }
    }

    /// Called when a relay node is discovered via DHT
    fn on_relay_discovered(&mut self, relay_info: RelayInfo, peer_id: Option<PeerId>) {
        // Skip ourselves — we can't be our own gateway
        if let (Some(discovered_pid), Some(local_pid)) = (peer_id, self.local_peer_id) {
            if discovered_pid == local_pid {
                return;
            }
        }

        let pubkey = relay_info.pubkey;
        let is_new = !self.relay_nodes.contains_key(&pubkey);

        if is_new {
            let pid = peer_id.unwrap_or(PeerId::random());
            let status = RelayNodeStatus::new(relay_info, pid);
            self.relay_nodes.insert(pubkey, status);

            info!(
                "Discovered relay node via DHT: pubkey={}, peer_id={:?}",
                hex::encode(&pubkey[..8]), peer_id
            );

            // Add the relay's address and dial to establish a swarm connection
            if let Some(real_pid) = peer_id {
                if let Some(ref mut swarm) = self.swarm {
                    // Add address from DHT record so the swarm knows how to reach this peer
                    if let Ok(addr) = self.relay_nodes.get(&pubkey)
                        .map(|s| s.info.address.clone())
                        .unwrap_or_default()
                        .parse::<Multiaddr>()
                    {
                        swarm.behaviour_mut().add_address(&real_pid, addr);
                    }
                    if !swarm.is_connected(&real_pid) {
                        info!("Dialing newly discovered relay {}", real_pid);
                        let _ = swarm.dial(real_pid);
                    }
                }
            }

            // Remove from unverified if present (now DHT-verified)
            if let Some(pid) = peer_id {
                self.unverified_relay_peers.retain(|p| *p != pid);
            }
        } else {
            // Update existing entry
            if let Some(status) = self.relay_nodes.get_mut(&pubkey) {
                status.last_dht_seen = std::time::Instant::now();
                status.info = relay_info;
                if let Some(pid) = peer_id {
                    status.peer_id = pid;
                }
            }
        }
    }

    /// Mark relays as offline if no heartbeat for RELAY_OFFLINE_THRESHOLD
    fn check_relay_timeouts(&mut self) {
        let now = std::time::Instant::now();
        for status in self.relay_nodes.values_mut() {
            if status.online {
                let last_seen = status.last_heartbeat
                    .unwrap_or(now);
                if now.duration_since(last_seen) > RELAY_OFFLINE_THRESHOLD {
                    status.online = false;
                    debug!("Relay {} timed out (no heartbeat)", hex::encode(&status.info.pubkey[..8]));
                }
            }
        }
    }

    /// Remove stale relay entries older than TTL
    fn cleanup_stale_relays(&mut self) {
        use tunnelcraft_network::RELAY_RECORD_TTL;

        let now = std::time::Instant::now();
        let before_count = self.relay_nodes.len();

        self.relay_nodes.retain(|_pubkey, status| {
            now.duration_since(status.last_dht_seen) < RELAY_RECORD_TTL
        });

        let removed = before_count - self.relay_nodes.len();
        if removed > 0 {
            info!("Removed {} stale relay nodes", removed);
        }
    }

    /// Announce relay going offline via gossipsub
    fn announce_relay_offline(&mut self) {
        if let Some(ref mut swarm) = self.swarm {
            let peer_id_str = self.local_peer_id.map(|p| p.to_string()).unwrap_or_default();
            let msg = RelayStatusMessage::offline(
                self.keypair.public_key_bytes(),
                &peer_id_str,
            );
            if let Err(e) = swarm.behaviour_mut().publish_relay_status(msg.to_bytes()) {
                warn!("Failed to announce relay offline: {:?}", e);
            } else {
                debug!("Announced relay offline status");
            }
        }

        // Stop providing in DHT
        if let Some(ref mut swarm) = self.swarm {
            swarm.behaviour_mut().stop_providing_relay();
        }
    }

    /// Get count of DHT-verified relay nodes
    pub fn relay_node_count(&self) -> usize {
        self.relay_nodes.len()
    }

    /// Get count of online relay nodes
    pub fn online_relay_count(&self) -> usize {
        self.relay_nodes.values().filter(|s| s.online).count()
    }

    /// Get aggregator network stats (if aggregator is enabled)
    pub fn aggregator_stats(&self) -> Option<tunnelcraft_aggregator::NetworkStats> {
        self.aggregator.as_ref().map(|a| a.get_network_stats())
    }

    /// Get aggregator pool usage for a specific user (if aggregator is enabled)
    pub fn aggregator_pool_usage(&self, pool_key: &(PublicKey, PoolType)) -> Vec<(PublicKey, u64)> {
        self.aggregator.as_ref()
            .map(|a| a.get_pool_usage(pool_key))
            .unwrap_or_default()
    }

    /// Get all pool keys tracked by the aggregator (both Subscribed and Free)
    pub fn aggregator_pool_keys(&self) -> Vec<(PublicKey, PoolType)> {
        self.aggregator.as_ref()
            .map(|a| a.all_pool_keys())
            .unwrap_or_default()
    }

    /// Get aggregator relay stats for a specific relay (if aggregator is enabled)
    pub fn aggregator_relay_stats(&self, relay: &PublicKey) -> Vec<((PublicKey, PoolType), u64)> {
        self.aggregator.as_ref()
            .map(|a| a.get_relay_stats(relay))
            .unwrap_or_default()
    }

    /// Build a Merkle distribution for a specific pool (if aggregator is enabled)
    pub fn aggregator_build_distribution(
        &self,
        pool_pubkey: [u8; 32],
        pool_type: PoolType,
    ) -> Option<tunnelcraft_aggregator::Distribution> {
        self.aggregator.as_ref()?.build_distribution(&(pool_pubkey, pool_type))
    }

    // =========================================================================
    // Proof queue + adaptive batch compressor
    // =========================================================================

    /// Try to compress queued receipts into a Merkle root.
    ///
    /// Called from `poll_once()` on every tick. If the compressor is busy or no
    /// pool has enough queued receipts, this is a no-op.
    ///
    /// The actual compress() call runs on spawn_blocking to avoid blocking the
    /// async event loop.
    fn try_compress(&mut self) {
        if self.compressor_busy {
            return;
        }

        let now = Instant::now();

        // Find pools that are ready to compress:
        // - queue_len >= proof_batch_size (batch full), OR
        // - oldest receipt age >= proof_deadline (deadline expired)
        let best_pool = self.proof_queue.iter()
            .filter(|(_, q)| !q.is_empty())
            .filter(|(k, _)| !self.needs_chain_recovery.contains(k))
            .filter(|(k, q)| {
                let batch_ready = q.len() >= self.proof_batch_size;
                let deadline_expired = self.proof_oldest_receipt
                    .get(k)
                    .map(|t| now.duration_since(*t) >= self.proof_deadline)
                    .unwrap_or(false);
                batch_ready || deadline_expired
            })
            .max_by_key(|(_, q)| q.len())
            .map(|(k, q)| (*k, q.len()));

        let Some(((pool, pool_type), queue_len)) = best_pool else {
            return;
        };

        let batch_size = queue_len.min(self.proof_batch_size);
        if batch_size == 0 {
            return;
        }

        // Take receipts from the front of the queue
        let pool_key = (pool, pool_type);
        let queue = self.proof_queue.get_mut(&pool_key).unwrap();
        let batch: Vec<ForwardReceipt> = queue.drain(..batch_size).collect();

        self.compressor_busy = true;

        // Select compressor: free-tier receipts use stub_compressor (instant),
        // subscribed receipts use the main compressor
        let compressor: Arc<dyn ReceiptCompression> = if pool_type == PoolType::Free {
            Arc::clone(&self.stub_compressor) as Arc<dyn ReceiptCompression>
        } else {
            Arc::clone(&self.compressor)
        };

        // Spawn compression on a blocking thread to avoid starving the async event loop
        let batch_clone = batch.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.compression_result_rx = Some(rx);

        tokio::task::spawn_blocking(move || {
            let start = Instant::now();
            let output = compressor.compress(&batch_clone);
            let _ = tx.send(CompressionResult {
                pool_key,
                batch: batch_clone,
                output,
                start,
            });
        });
    }

    /// Check for completed compression results from spawn_blocking and process them.
    fn poll_compression_result(&mut self) {
        let rx = match self.compression_result_rx.as_mut() {
            Some(rx) => rx,
            None => return,
        };

        // Non-blocking check
        let result = match rx.try_recv() {
            Ok(result) => result,
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => return,
            Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                warn!("Compression result channel closed unexpectedly");
                self.compressor_busy = false;
                self.compression_result_rx = None;
                return;
            }
        };
        self.compression_result_rx = None;

        let pool_key = result.pool_key;
        let (pool, pool_type) = pool_key;

        let compressed = match result.output {
            Ok(output) => output,
            Err(e) => {
                warn!("Compressor failed: {:?}", e);
                self.compressor_busy = false;
                self.compressions_failed += 1;
                // Re-queue the batch
                let queue = self.proof_queue.entry(pool_key).or_default();
                for receipt in result.batch.into_iter().rev() {
                    queue.push_front(receipt);
                }
                return;
            }
        };

        let new_root = compressed.root;
        let (prev_root, prev_bytes) = self.pool_roots.get(&pool_key)
            .copied()
            .unwrap_or(([0u8; 32], 0));

        let batch_bytes_total: u64 = result.batch.iter().map(|r| r.payload_size as u64).sum();
        let cumulative_bytes = prev_bytes + batch_bytes_total;

        // Generate proof message for gossip
        let mut msg = ProofMessage {
            relay_pubkey: self.keypair.public_key_bytes(),
            pool_pubkey: pool,
            pool_type,
            batch_bytes: batch_bytes_total,
            cumulative_bytes,
            prev_root,
            new_root,
            proof: vec![],
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            signature: vec![], // placeholder, signed below
        };

        // Sign the proof message with relay's ed25519 keypair
        let sig = tunnelcraft_crypto::sign_data(&self.keypair, &msg.signable_data());
        msg.signature = sig.to_vec();

        // Publish to gossipsub
        if let Some(ref mut swarm) = self.swarm {
            let data = msg.to_bytes();
            match swarm.behaviour_mut().publish_proof(data) {
                Ok(msg_id) => {
                    debug!(
                        "Published proof for pool {} {:?} (batch_bytes: {}, cumulative_bytes: {}, msg: {:?})",
                        hex::encode(&pool[..8]),
                        pool_type,
                        batch_bytes_total,
                        cumulative_bytes,
                        msg_id,
                    );
                }
                Err(e) => {
                    warn!("Failed to publish proof: {:?}", e);
                }
            }
        }

        // Update pool roots
        self.pool_roots.insert(pool_key, (new_root, cumulative_bytes));

        // Reset deadline tracker: if queue is now empty, remove; otherwise reset timer
        if self.proof_queue.get(&pool_key).is_none_or(|q| q.is_empty()) {
            self.proof_oldest_receipt.remove(&pool_key);
        } else {
            self.proof_oldest_receipt.insert(pool_key, Instant::now());
        }

        // Persist proof state after successful compression (also resets enqueue counter)
        self.proof_enqueue_since_save = 0;
        self.save_proof_state();

        self.batches_compressed += 1;

        // Adaptive batch sizing
        let duration = result.start.elapsed();
        self.last_proof_duration = Some(duration);
        self.adjust_batch_size(duration);

        self.compressor_busy = false;
    }

    /// Adjust batch size based on compression duration (adaptive).
    ///
    /// If proof took < 10s, increase batch size (up to 100K).
    /// If proof took > 60s, decrease batch size (down to 10K).
    fn adjust_batch_size(&mut self, duration: Duration) {
        let secs = duration.as_secs();
        if secs < 10 && self.proof_batch_size < 100_000 {
            self.proof_batch_size = (self.proof_batch_size * 12 / 10).min(100_000);
            debug!("Increased proof batch size to {}", self.proof_batch_size);
        } else if secs > 60 && self.proof_batch_size > 10_000 {
            self.proof_batch_size = (self.proof_batch_size * 8 / 10).max(10_000);
            debug!("Decreased proof batch size to {}", self.proof_batch_size);
        }
    }

    /// Persist proof state (pool_roots + pending receipts) to disk.
    ///
    /// Uses atomic write (tmp file + rename) to prevent corruption.
    fn save_proof_state(&self) {
        let Some(ref path) = self.proof_state_file else { return };

        let mut pool_roots_map = HashMap::new();
        for ((pubkey, pool_type), (root, cumulative_bytes)) in &self.pool_roots {
            let key = format_pool_key(pubkey, pool_type);
            pool_roots_map.insert(key, PoolRootState {
                root: hex::encode(root),
                cumulative_bytes: *cumulative_bytes,
            });
        }

        let mut pending_receipts = Vec::new();
        for ((pubkey, pool_type), queue) in &self.proof_queue {
            let key = format_pool_key(pubkey, pool_type);
            for receipt in queue {
                pending_receipts.push(PendingReceiptEntry {
                    pool_key: key.clone(),
                    receipt: receipt.clone(),
                });
            }
        }

        let state = ProofStateFile {
            pool_roots: pool_roots_map,
            pending_receipts,
        };

        let json = match serde_json::to_string_pretty(&state) {
            Ok(j) => j,
            Err(e) => {
                warn!("Failed to serialize proof state: {}", e);
                return;
            }
        };

        // Atomic write: write to tmp file, then rename
        let tmp_path = path.with_extension("json.tmp");
        if let Err(e) = std::fs::write(&tmp_path, &json) {
            warn!("Failed to write proof state tmp file {}: {}", tmp_path.display(), e);
            return;
        }
        if let Err(e) = std::fs::rename(&tmp_path, path) {
            warn!("Failed to rename proof state file {} -> {}: {}", tmp_path.display(), path.display(), e);
            return;
        }

        debug!(
            "Saved proof state: {} pool roots, {} pending receipts to {}",
            self.pool_roots.len(),
            self.proof_queue.values().map(|q| q.len()).sum::<usize>(),
            path.display(),
        );
    }

    /// Get pool keys that need chain recovery from an aggregator.
    ///
    /// Returns pool keys that have pending receipts but no known proof chain root.
    /// The caller should query aggregator peers for each key and call
    /// `apply_chain_recovery()` with the response.
    pub fn pools_needing_recovery(&self) -> &[(PublicKey, PoolType)] {
        &self.needs_chain_recovery
    }

    /// Apply a chain recovery response from an aggregator.
    ///
    /// Sets the pool_roots entry for the given pool key so that the next
    /// `try_compress()` will chain from this root. If the aggregator's root
    /// is wrong, the proof will fail at other aggregators with `ChainBreak`,
    /// so this is trustless — no harm from a lying aggregator.
    pub fn apply_chain_recovery(
        &mut self,
        pool_key: (PublicKey, PoolType),
        root: [u8; 32],
        cumulative_bytes: u64,
    ) {
        info!(
            "Chain recovery applied for pool ({}, {:?}): root={}, cumulative={}",
            hex::encode(&pool_key.0[..8]),
            pool_key.1,
            hex::encode(&root[..8]),
            cumulative_bytes,
        );
        self.pool_roots.insert(pool_key, (root, cumulative_bytes));
        self.needs_chain_recovery.retain(|k| *k != pool_key);
        self.save_proof_state();
    }

    /// Get proof pipeline status snapshot
    pub fn compression_status(&self) -> CompressionStatus {
        CompressionStatus {
            queued: self.proof_queue_depth(),
            compressing: self.compressor_busy,
            batches_compressed: self.batches_compressed,
            compressions_failed: self.compressions_failed,
            last_proof_duration_ms: self.last_proof_duration.map(|d| d.as_millis() as u64),
        }
    }

    /// Get the current proof queue depth (for monitoring/debugging)
    pub fn proof_queue_depth(&self) -> usize {
        self.proof_queue.values().map(|q| q.len()).sum()
    }

    /// Get proof queue depth for a specific pool key
    pub fn pool_queue_depth(&self, pool_key: &(PublicKey, PoolType)) -> usize {
        self.proof_queue.get(pool_key).map(|q| q.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = NodeConfig::default();
        assert_eq!(config.capabilities, Capabilities::CLIENT);
        assert!(!config.capabilities.is_exit());
        assert!(!config.capabilities.is_relay());
        assert!(!config.capabilities.is_aggregator());
    }

    #[test]
    fn test_node_creation() {
        let config = NodeConfig::default();
        let node = TunnelCraftNode::new(config).unwrap();
        assert_eq!(node.capabilities(), Capabilities::CLIENT);
        assert!(!node.is_connected());
    }

    #[test]
    fn test_capabilities_switching() {
        let config = NodeConfig::default();
        let mut node = TunnelCraftNode::new(config).unwrap();

        assert!(node.capabilities().is_client());

        node.set_capabilities(Capabilities::RELAY);
        assert!(node.capabilities().is_relay());
        assert!(!node.capabilities().is_client());

        node.set_capabilities(Capabilities::CLIENT | Capabilities::RELAY);
        assert!(node.capabilities().is_client());
        assert!(node.capabilities().is_relay());

        node.set_capabilities(Capabilities::RELAY | Capabilities::EXIT);
        assert!(node.capabilities().is_relay());
        assert!(node.capabilities().is_exit());
        assert!(!node.capabilities().is_client());

        node.set_capabilities(Capabilities::CLIENT | Capabilities::RELAY | Capabilities::EXIT);
        assert!(node.capabilities().is_client());
        assert!(node.capabilities().is_service_node());
    }

    #[test]
    fn test_credits() {
        let config = NodeConfig::default();
        let mut node = TunnelCraftNode::new(config).unwrap();

        assert_eq!(node.credits(), 0);
        node.set_credits(100);
        assert_eq!(node.credits(), 100);
    }
}
