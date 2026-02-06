//! Unified TunnelCraft Node
//!
//! A single component that supports three modes:
//! - Client: Route your traffic through the VPN (spend credits)
//! - Node: Relay traffic for others (earn credits)
//! - Both: Use VPN + help the network (spend & earn)
//!
//! The VPN extension runs in all modes for persistent P2P connectivity,
//! but traffic routing is only active in Client/Both modes.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use libp2p::identity::Keypair;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId};
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use tunnelcraft_core::{CreditProof, ExitInfo, ExitRegion, HopMode, Id, Shard, ShardType};
use tunnelcraft_crypto::SigningKeypair;
use tunnelcraft_erasure::{ErasureCoder, DATA_SHARDS, TOTAL_SHARDS};
use tunnelcraft_exit::{ExitConfig, ExitHandler};
use tunnelcraft_network::{
    NetworkConfig, NetworkNode, ShardRequest, ShardResponse, TunnelCraftBehaviourEvent,
    ExitStatusMessage, ExitStatusType, EXIT_HEARTBEAT_INTERVAL, EXIT_OFFLINE_THRESHOLD,
};
use tunnelcraft_relay::{RelayConfig, RelayHandler};

use crate::{ClientError, RawPacketBuilder, RequestBuilder, Result, TunnelResponse};

/// Operating mode for the node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NodeMode {
    /// Client only - use VPN, spend credits
    /// Traffic is routed through the tunnel
    #[default]
    Client,

    /// Node only - help network, earn credits
    /// Traffic is NOT routed (normal internet for user)
    /// But P2P stays active to relay for others
    Node,

    /// Both client and node
    /// Traffic is routed + relay for others
    Both,
}

/// Node type for relay/exit behavior
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NodeType {
    /// Relay only - forward shards, don't execute HTTP
    #[default]
    Relay,

    /// Exit node - can execute HTTP requests
    Exit,

    /// Full - both relay and exit
    Full,
}

/// Configuration for the unified node
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Operating mode (Client, Node, Both)
    pub mode: NodeMode,

    /// Node type when in Node/Both mode (Relay, Exit, Full)
    pub node_type: NodeType,

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

    /// Enable exit node functionality
    pub enable_exit: bool,

    /// Exit node region (auto-detected or configured)
    pub exit_region: ExitRegion,

    /// Exit node country code (ISO 3166-1 alpha-2, e.g., "US", "DE")
    pub exit_country_code: Option<String>,

    /// Exit node city
    pub exit_city: Option<String>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            mode: NodeMode::Client,
            node_type: NodeType::Relay,
            listen_addr: "/ip4/0.0.0.0/tcp/0".parse().unwrap(),
            bootstrap_peers: Vec::new(),
            hop_mode: HopMode::Standard,
            request_timeout: Duration::from_secs(30),
            allow_last_hop: true,
            enable_exit: false,
            exit_region: ExitRegion::Auto,
            exit_country_code: None,
            exit_city: None,
        }
    }
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
    /// Current mode
    pub mode: NodeMode,

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
    shards: HashMap<u8, Shard>,
    response_tx: mpsc::Sender<Result<TunnelResponse>>,
    /// Exit pubkey for this request (for measurement updates)
    exit_pubkey: [u8; 32],
    /// Request size in bytes (for throughput calculation)
    request_bytes: usize,
    /// Time when request was sent
    sent_at: std::time::Instant,
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
            last_dht_seen: now,
            last_heartbeat: None,
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
    /// Current mode
    mode: NodeMode,

    /// Configuration
    config: NodeConfig,

    /// Signing keypair for shards
    keypair: SigningKeypair,

    /// libp2p keypair
    libp2p_keypair: Keypair,

    /// Network node (shared P2P identity)
    network: Option<NetworkNode>,

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

    /// User's credit proof for the current epoch
    /// Chain-signed proof of credit balance submitted with each request
    credit_proof: Option<CreditProof>,

    /// Known relay peers
    relay_peers: Vec<PeerId>,

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
}

impl TunnelCraftNode {
    /// Create a new unified node
    pub fn new(config: NodeConfig) -> Result<Self> {
        let keypair = SigningKeypair::generate();
        let libp2p_keypair = Keypair::generate_ed25519();
        let erasure =
            ErasureCoder::new().map_err(|e| ClientError::ErasureError(e.to_string()))?;

        let state = Arc::new(RwLock::new(NodeState {
            stats: NodeStats::default(),
            relay_handler: None,
            exit_handler: None,
        }));

        Ok(Self {
            mode: config.mode,
            config,
            keypair,
            libp2p_keypair,
            network: None,
            connected: false,
            credits: 0,
            exit_nodes: HashMap::new(),
            selected_exit: None,
            pending: HashMap::new(),
            erasure,
            credit_proof: None,
            relay_peers: Vec::new(),
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
        })
    }

    /// Get current mode
    pub fn mode(&self) -> NodeMode {
        self.mode
    }

    /// Set mode (can be changed at runtime)
    pub fn set_mode(&mut self, mode: NodeMode) {
        info!("Changing mode from {:?} to {:?}", self.mode, mode);
        self.mode = mode;

        // Initialize/cleanup handlers based on new mode
        let mut state = self.state.write();
        match mode {
            NodeMode::Client => {
                // Client mode: no relay/exit handlers needed
                // But we keep them if they exist for quick switch back
            }
            NodeMode::Node | NodeMode::Both => {
                // Ensure handlers are initialized
                if state.relay_handler.is_none() {
                    let relay_config = RelayConfig {
                        can_be_last_hop: self.config.allow_last_hop,
                        ..Default::default()
                    };
                    state.relay_handler =
                        Some(RelayHandler::with_config(self.keypair.clone(), relay_config));
                    info!("Relay handler initialized");
                }

                if self.config.enable_exit && state.exit_handler.is_none() {
                    let exit_config = ExitConfig {
                        timeout: self.config.request_timeout,
                        ..Default::default()
                    };
                    state.exit_handler = Some(ExitHandler::new(
                        exit_config,
                        self.keypair.public_key_bytes(),
                        self.keypair.secret_key_bytes(),
                    ));
                    info!("Exit handler initialized");
                }
            }
        }
    }

    /// Get our peer ID
    pub fn peer_id(&self) -> Option<PeerId> {
        self.network.as_ref().map(|n| n.local_peer_id())
    }

    /// Get our public key
    pub fn pubkey(&self) -> [u8; 32] {
        self.keypair.public_key_bytes()
    }

    /// Set credit proof for this epoch
    ///
    /// The credit proof is a chain-signed proof of the user's credit balance.
    /// It is submitted with each request so exit nodes can verify the user
    /// has sufficient credits. The user must track local consumption to
    /// avoid post-reconciliation penalties.
    pub fn set_credit_proof(&mut self, credit_proof: CreditProof) {
        self.credit_proof = Some(credit_proof);
    }

    /// Get current credit proof
    pub fn credit_proof(&self) -> Option<&CreditProof> {
        self.credit_proof.as_ref()
    }

    /// Start the node (connect to P2P network)
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting TunnelCraftNode in {:?} mode", self.mode);

        // Create network config
        let mut net_config = NetworkConfig::default();
        net_config.listen_addrs.push(self.config.listen_addr.clone());
        for (peer_id, addr) in &self.config.bootstrap_peers {
            net_config.bootstrap_peers.push((*peer_id, addr.clone()));
        }

        // Create network node
        let (node, _event_rx) = NetworkNode::new(self.libp2p_keypair.clone(), net_config)
            .await
            .map_err(|e| ClientError::ConnectionFailed(e.to_string()))?;

        let peer_id = node.local_peer_id();
        info!("Node started with peer ID: {}", peer_id);

        self.network = Some(node);

        // Initialize handlers based on mode
        self.set_mode(self.mode);

        // Start listening
        if let Some(ref mut network) = self.network {
            network
                .listen_on(self.config.listen_addr.clone())
                .map_err(|e| ClientError::ConnectionFailed(e.to_string()))?;
        }

        // Connect to bootstrap peers
        self.connect_bootstrap().await?;

        // Subscribe to exit status gossipsub topic
        if let Some(ref mut network) = self.network {
            if let Err(e) = network.swarm_mut().behaviour_mut().subscribe_exit_status() {
                warn!("Failed to subscribe to exit status topic: {:?}", e);
            } else {
                debug!("Subscribed to exit status topic");
            }
        }

        // Announce as exit node if enabled
        if self.config.enable_exit {
            self.announce_as_exit();
        }

        self.connected = true;
        Ok(())
    }

    /// Connect to bootstrap peers
    async fn connect_bootstrap(&mut self) -> Result<()> {
        if self.network.is_none() {
            return Ok(());
        }

        // Add and dial bootstrap peers
        let bootstrap_peers = self.config.bootstrap_peers.clone();
        for (peer_id, addr) in &bootstrap_peers {
            debug!("Connecting to bootstrap peer: {}", peer_id);
            if let Some(ref mut network) = self.network {
                network.add_peer(*peer_id, addr.clone());
                if let Err(e) = network.dial(*peer_id) {
                    warn!("Failed to dial bootstrap peer {}: {}", peer_id, e);
                }
            }
        }

        // Wait for at least one connection
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while tokio::time::Instant::now() < deadline {
            let connected = self.network.as_ref().map(|n| n.num_connected()).unwrap_or(0);
            if connected > 0 {
                break;
            }
            self.poll_once().await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let connected = self.network.as_ref().map(|n| n.num_connected()).unwrap_or(0);
        if connected > 0 {
            info!("Connected to {} peers", connected);
            Ok(())
        } else if self.config.bootstrap_peers.is_empty() {
            // No bootstrap peers is OK for first node
            info!("No bootstrap peers configured, running as bootstrap node");
            Ok(())
        } else {
            Err(ClientError::ConnectionFailed(
                "Failed to connect to any bootstrap peer".to_string(),
            ))
        }
    }

    /// Stop the node
    pub async fn stop(&mut self) {
        info!("Stopping TunnelCraftNode");

        // Announce offline if we're an exit
        if self.config.enable_exit {
            self.announce_offline();
        }

        self.connected = false;
        self.pending.clear();
        self.relay_peers.clear();
        self.network = None;
    }

    /// Announce going offline via gossipsub (for exits)
    fn announce_offline(&mut self) {
        if let Some(ref mut network) = self.network {
            let msg = ExitStatusMessage::offline(
                self.keypair.public_key_bytes(),
                &network.local_peer_id().to_string(),
            );
            if let Err(e) = network.swarm_mut().behaviour_mut().publish_exit_status(msg.to_bytes()) {
                warn!("Failed to announce offline: {:?}", e);
            } else {
                debug!("Announced offline status");
            }
        }
    }

    /// Publish heartbeat via gossipsub (for exits)
    fn publish_heartbeat(&mut self) {
        if !self.config.enable_exit {
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

        if let Some(ref mut network) = self.network {
            let msg = ExitStatusMessage::heartbeat(
                self.keypair.public_key_bytes(),
                &network.local_peer_id().to_string(),
                load_percent,
                self.active_requests,
                self.exit_uplink_kbps,
                self.exit_downlink_kbps,
                uptime_secs,
                region,
            );
            if let Err(e) = network.swarm_mut().behaviour_mut().publish_exit_status(msg.to_bytes()) {
                // Don't warn on InsufficientPeers - normal during startup
                debug!("Failed to publish heartbeat: {:?}", e);
            } else {
                debug!(
                    "Published heartbeat (load: {}%, uplink: {}KB/s, downlink: {}KB/s, uptime: {}s)",
                    load_percent, self.exit_uplink_kbps, self.exit_downlink_kbps, uptime_secs
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

    /// Record bytes for exit throughput measurement
    #[allow(dead_code)]
    fn record_exit_bytes(&mut self, bytes_up: u64, bytes_down: u64) {
        // Initialize window if not started
        if self.exit_throughput_window_start.is_none() {
            self.exit_throughput_window_start = Some(std::time::Instant::now());
        }
        self.exit_bytes_up += bytes_up;
        self.exit_bytes_down += bytes_down;
    }

    /// Check if we should send a heartbeat
    fn maybe_send_heartbeat(&mut self) {
        if !self.config.enable_exit {
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

    /// Select the best available exit (online, lowest score)
    ///
    /// Score combines: load (20%), latency (30%), throughput (50%)
    /// Lower score = better exit
    fn select_best_exit(&mut self) {
        let best = self
            .exit_nodes
            .values()
            .filter(|s| s.online)
            .min_by_key(|s| s.score)
            .map(|s| s.info.clone());

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
        let Some(ref mut network) = self.network else {
            warn!("Cannot announce exit: network not initialized");
            return;
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
        network.announce_exit(record);
        self.last_exit_announcement = Some(std::time::Instant::now());
        info!(
            "Announced as exit node: region={:?}, country={:?}, city={:?}",
            exit_info.region, exit_info.country_code, exit_info.city
        );
    }

    /// Check if exit re-announcement is needed and do it
    fn maybe_reannounce_exit(&mut self) {
        if !self.config.enable_exit || !self.connected {
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

    /// Update exit node geo information (e.g., from auto-detection)
    pub fn set_exit_geo(&mut self, region: ExitRegion, country_code: Option<String>, city: Option<String>) {
        self.config.exit_region = region;
        self.config.exit_country_code = country_code;
        self.config.exit_city = city;

        // Re-announce if already connected and exit is enabled
        if self.connected && self.config.enable_exit {
            self.announce_as_exit();
        }
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Check if traffic routing is active
    pub fn is_routing_active(&self) -> bool {
        matches!(self.mode, NodeMode::Client | NodeMode::Both) && self.connected
    }

    /// Check if relay is active
    pub fn is_relay_active(&self) -> bool {
        matches!(self.mode, NodeMode::Node | NodeMode::Both) && self.connected
    }

    /// Get current status
    pub fn status(&self) -> NodeStatus {
        let state = self.state.read();
        NodeStatus {
            mode: self.mode,
            peer_id: self
                .peer_id()
                .map(|p| p.to_string())
                .unwrap_or_default(),
            connected: self.connected,
            peer_count: self.network.as_ref().map(|n| n.num_connected()).unwrap_or(0),
            credits: self.credits,
            routing_active: self.is_routing_active(),
            relay_active: self.is_relay_active(),
            exit_active: self.config.enable_exit && state.exit_handler.is_some(),
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

    /// Make an HTTP GET request through the tunnel (Client/Both mode)
    pub async fn get(&mut self, url: &str) -> Result<TunnelResponse> {
        self.fetch("GET", url, None).await
    }

    /// Make an HTTP POST request through the tunnel
    pub async fn post(&mut self, url: &str, body: Vec<u8>) -> Result<TunnelResponse> {
        self.fetch("POST", url, Some(body)).await
    }

    /// Make an HTTP request through the tunnel
    pub async fn fetch(
        &mut self,
        method: &str,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<TunnelResponse> {
        // Check mode
        if !matches!(self.mode, NodeMode::Client | NodeMode::Both) {
            return Err(ClientError::NotConnected);
        }

        if !self.connected {
            return Err(ClientError::NotConnected);
        }

        let exit = self
            .selected_exit
            .as_ref()
            .ok_or(ClientError::NoExitNodes)?;

        if self.credits < 1 {
            return Err(ClientError::InsufficientCredits { have: 0, need: 1 });
        }

        // Get credit proof (required for requests)
        let credit_proof = self
            .credit_proof
            .clone()
            .ok_or(ClientError::InsufficientCredits { have: 0, need: 1 })?;

        // Build request
        let mut builder = RequestBuilder::new(method, url).hop_mode(self.config.hop_mode);
        if let Some(body_data) = body {
            builder = builder.body(body_data);
        }

        // Create shards
        let shards = builder.build(self.pubkey(), exit.pubkey, credit_proof)?;
        let request_id = shards[0].request_id;

        // Calculate request size for throughput measurement
        let request_bytes: usize = shards.iter().map(|s| s.payload.len()).sum();

        debug!(
            "Created {} shards for request {} ({} bytes)",
            shards.len(),
            hex::encode(&request_id[..8]),
            request_bytes
        );

        // Create response channel
        let (response_tx, mut response_rx) = mpsc::channel(1);

        // Store pending request with timing info
        self.pending.insert(
            request_id,
            PendingRequest {
                shards: HashMap::new(),
                response_tx,
                exit_pubkey: exit.pubkey,
                request_bytes,
                sent_at: std::time::Instant::now(),
            },
        );

        // Send shards
        self.send_shards(shards).await?;

        // Update stats
        {
            let mut state = self.state.write();
            state.stats.credits_spent += 1;
        }
        self.credits = self.credits.saturating_sub(1);

        // Wait for response
        let response = tokio::time::timeout(self.config.request_timeout, async {
            loop {
                tokio::select! {
                    response = response_rx.recv() => {
                        return response.ok_or(ClientError::Timeout)?;
                    }
                    _ = self.poll_once() => {}
                }
            }
        })
        .await
        .map_err(|_| ClientError::Timeout)??;

        Ok(response)
    }

    /// Tunnel a raw IP packet through the VPN (Client/Both mode)
    ///
    /// This is the core VPN function used by Network Extensions (iOS) and
    /// VpnService (Android). Takes a raw IP packet, tunnels it through
    /// the relay network to an exit node, and returns the response packet.
    pub async fn tunnel_packet(&mut self, packet: Vec<u8>) -> Result<Vec<u8>> {
        // Check mode
        if !matches!(self.mode, NodeMode::Client | NodeMode::Both) {
            return Err(ClientError::NotConnected);
        }

        if !self.connected {
            return Err(ClientError::NotConnected);
        }

        let exit = self
            .selected_exit
            .as_ref()
            .ok_or(ClientError::NoExitNodes)?;

        if self.credits < 1 {
            return Err(ClientError::InsufficientCredits { have: 0, need: 1 });
        }

        // Get credit proof (required for requests)
        let credit_proof = self
            .credit_proof
            .clone()
            .ok_or(ClientError::InsufficientCredits { have: 0, need: 1 })?;

        let packet_len = packet.len();
        debug!("Tunneling raw packet of {} bytes", packet_len);

        // Build raw packet shards
        let builder = RawPacketBuilder::new(packet).hop_mode(self.config.hop_mode);
        let shards = builder.build(self.pubkey(), exit.pubkey, credit_proof)?;
        let request_id = shards[0].request_id;

        // Calculate request size for throughput measurement
        let request_bytes: usize = shards.iter().map(|s| s.payload.len()).sum();

        debug!(
            "Created {} shards for raw packet {} ({} bytes)",
            shards.len(),
            hex::encode(&request_id[..8]),
            request_bytes
        );

        // Create response channel
        let (response_tx, mut response_rx) = mpsc::channel::<Result<TunnelResponse>>(1);

        // Store pending request with timing info
        self.pending.insert(
            request_id,
            PendingRequest {
                shards: HashMap::new(),
                response_tx,
                exit_pubkey: exit.pubkey,
                request_bytes,
                sent_at: std::time::Instant::now(),
            },
        );

        // Send shards
        self.send_shards(shards).await?;

        // Update stats
        {
            let mut state = self.state.write();
            state.stats.credits_spent += 1;
            state.stats.bytes_sent += packet_len as u64;
        }
        self.credits = self.credits.saturating_sub(1);

        // Wait for response
        let response = tokio::time::timeout(self.config.request_timeout, async {
            loop {
                tokio::select! {
                    response = response_rx.recv() => {
                        return response.ok_or(ClientError::Timeout)?;
                    }
                    _ = self.poll_once() => {}
                }
            }
        })
        .await
        .map_err(|_| ClientError::Timeout)??;

        // Update received bytes
        {
            let mut state = self.state.write();
            state.stats.bytes_received += response.body.len() as u64;
        }

        Ok(response.body)
    }

    /// Send shards to relay peers
    async fn send_shards(&mut self, shards: Vec<Shard>) -> Result<()> {
        if self.relay_peers.is_empty() {
            return Err(ClientError::ConnectionFailed(
                "No relay peers available".to_string(),
            ));
        }

        let Some(ref mut network) = self.network else {
            return Err(ClientError::NotConnected);
        };

        for (i, shard) in shards.into_iter().enumerate() {
            let peer_idx = i % self.relay_peers.len();
            let peer_id = self.relay_peers[peer_idx];

            debug!("Sending shard {} to peer {}", i, peer_id);

            let request = ShardRequest { shard };
            network.swarm_mut().behaviour_mut().send_shard(peer_id, request);
        }

        Ok(())
    }

    // =========================================================================
    // Node functionality (relay/exit)
    // =========================================================================

    /// Process an incoming shard (for relay/exit)
    async fn process_incoming_shard(&mut self, shard: Shard) -> ShardResponse {
        // Only process if in Node or Both mode
        if !matches!(self.mode, NodeMode::Node | NodeMode::Both) {
            // In Client mode, only handle response shards for our requests
            if shard.shard_type == ShardType::Response {
                self.handle_response_shard(shard).await;
                return ShardResponse::Accepted;
            }
            return ShardResponse::Rejected("Not in relay mode".to_string());
        }

        match shard.shard_type {
            ShardType::Request => {
                self.process_request_shard(shard).await
            }
            ShardType::Response => {
                // Check if this is for one of our pending requests
                if self.pending.contains_key(&shard.request_id) {
                    self.handle_response_shard(shard).await;
                    return ShardResponse::Accepted;
                }

                // Otherwise relay the response
                self.relay_shard(shard)
            }
        }
    }

    /// Process a request shard (relay or exit)
    async fn process_request_shard(&mut self, shard: Shard) -> ShardResponse {
        // If hops_remaining == 0, we're the exit
        if shard.hops_remaining == 0 {
            return self.process_as_exit(shard).await;
        }

        // Otherwise relay
        self.relay_shard(shard)
    }

    /// Process shard as exit node
    async fn process_as_exit(&mut self, shard: Shard) -> ShardResponse {
        // Take exit handler out temporarily to avoid holding lock across await
        let exit_handler = {
            let mut state = self.state.write();
            state.exit_handler.take()
        };

        let Some(mut handler) = exit_handler else {
            return ShardResponse::Rejected("Not an exit node".to_string());
        };

        let result: std::result::Result<Option<Vec<Shard>>, tunnelcraft_exit::ExitError> =
            handler.process_shard(shard).await;

        // Put handler back and extract response shards
        let response_shards = {
            let mut state = self.state.write();
            state.exit_handler = Some(handler);

            match result {
                Ok(Some(shards)) => {
                    state.stats.requests_exited += 1;
                    Some(shards)
                }
                Ok(None) => {
                    return ShardResponse::Accepted;
                }
                Err(e) => {
                    return ShardResponse::Rejected(e.to_string());
                }
            }
        };
        // Lock released here

        // Send response shards back through the network
        if let Some(shards) = response_shards {
            self.send_response_shards(shards);
        }

        ShardResponse::Accepted
    }

    /// Send response shards back through the network (exit node functionality)
    fn send_response_shards(&mut self, shards: Vec<Shard>) {
        if self.relay_peers.is_empty() {
            warn!("Cannot send response shards: no relay peers available");
            return;
        }

        let Some(ref mut network) = self.network else {
            warn!("Cannot send response shards: network not connected");
            return;
        };

        let shard_count = shards.len();
        for (i, shard) in shards.into_iter().enumerate() {
            // Select a different peer for each shard for path diversity
            let peer_idx = i % self.relay_peers.len();
            let peer_id = self.relay_peers[peer_idx];

            debug!(
                "Sending response shard {} to peer {}",
                hex::encode(&shard.shard_id[..8]),
                peer_id
            );

            let request = ShardRequest { shard };
            network.swarm_mut().behaviour_mut().send_shard(peer_id, request);
        }

        info!("Exit node sent {} response shards", shard_count);
    }

    /// Relay a shard to next hop
    fn relay_shard(&mut self, shard: Shard) -> ShardResponse {
        // Process shard with relay handler (under lock)
        let processed_shard = {
            let mut state = self.state.write();

            let Some(ref mut relay_handler) = state.relay_handler else {
                return ShardResponse::Rejected("Relay not active".to_string());
            };

            let result: std::result::Result<Option<Shard>, tunnelcraft_relay::RelayError> =
                relay_handler.handle_shard(shard);

            match result {
                Ok(Some(processed)) => {
                    state.stats.shards_relayed += 1;
                    state.stats.bytes_relayed += processed.payload.len() as u64;
                    Some(processed)
                }
                Ok(None) => return ShardResponse::Accepted,
                Err(e) => return ShardResponse::Rejected(e.to_string()),
            }
        };
        // Lock released here

        // Forward processed shard to next relay peer
        if let Some(shard_to_forward) = processed_shard {
            if let Some(peer_id) = self.select_relay_peer() {
                if let Some(ref mut network) = self.network {
                    debug!(
                        "Forwarding shard {} to peer {}",
                        hex::encode(&shard_to_forward.shard_id[..8]),
                        peer_id
                    );
                    let request = ShardRequest { shard: shard_to_forward };
                    network.swarm_mut().behaviour_mut().send_shard(peer_id, request);
                } else {
                    warn!("Cannot forward shard: network not connected");
                    return ShardResponse::Rejected("Network not connected".to_string());
                }
            } else {
                warn!("Cannot forward shard: no relay peers available");
                return ShardResponse::Rejected("No relay peers available".to_string());
            }
        }

        ShardResponse::Accepted
    }

    /// Select a random relay peer for forwarding
    fn select_relay_peer(&self) -> Option<PeerId> {
        if self.relay_peers.is_empty() {
            return None;
        }
        use rand::Rng;
        let idx = rand::thread_rng().gen_range(0..self.relay_peers.len());
        Some(self.relay_peers[idx])
    }

    /// Handle response shard for our own request
    async fn handle_response_shard(&mut self, shard: Shard) {
        if shard.shard_type != ShardType::Response {
            return;
        }

        let request_id = shard.request_id;
        let shard_index = shard.shard_index;

        if let Some(pending) = self.pending.get_mut(&request_id) {
            pending.shards.insert(shard_index, shard);
            debug!(
                "Received shard {}/{} for request {}",
                pending.shards.len(),
                DATA_SHARDS,
                hex::encode(&request_id[..8])
            );

            if pending.shards.len() >= DATA_SHARDS {
                let pending = self.pending.remove(&request_id).unwrap();
                let response_tx = pending.response_tx.clone();

                match self.reconstruct_response(&pending) {
                    Ok(response) => {
                        // Calculate throughput measurements
                        let response_bytes = response.body.len();
                        self.update_exit_measurement(&pending, response_bytes);

                        let mut state = self.state.write();
                        state.stats.bytes_received += response_bytes as u64;
                        drop(state);
                        let _ = response_tx.send(Ok(response)).await;
                    }
                    Err(e) => {
                        let _ = response_tx.send(Err(e)).await;
                    }
                }
            }
        }
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
        let uplink_kbps = (pending.request_bytes as u32 * 1000) / elapsed_ms / 1024;
        let downlink_kbps = (response_bytes as u32 * 1000) / elapsed_ms / 1024;
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

    /// Reconstruct response from shards
    fn reconstruct_response(&self, pending: &PendingRequest) -> Result<TunnelResponse> {
        let mut shard_data: Vec<Option<Vec<u8>>> = vec![None; TOTAL_SHARDS];
        let mut shard_size = 0usize;

        for (index, shard) in &pending.shards {
            let idx = *index as usize;
            if idx < TOTAL_SHARDS {
                shard_size = shard.payload.len();
                shard_data[idx] = Some(shard.payload.clone());
            }
        }

        // Use max possible length - the serialization format (TunnelResponse) handles its own length
        let max_len = shard_size * DATA_SHARDS;

        let data = self
            .erasure
            .decode(&mut shard_data, max_len)
            .map_err(|e| ClientError::ErasureError(e.to_string()))?;

        TunnelResponse::from_bytes(&data)
    }

    // =========================================================================
    // Event loop
    // =========================================================================

    /// Poll network once (for integration with VPN event loop)
    pub async fn poll_once(&mut self) {
        let Some(ref mut network) = self.network else {
            return;
        };

        tokio::select! {
            event = network.swarm_mut().select_next_some() => {
                self.handle_swarm_event(event).await;
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
    }

    /// Run the event loop (blocking)
    pub async fn run(&mut self) -> Result<()> {
        info!("Node event loop started in {:?} mode", self.mode);

        // Periodic maintenance interval (30 seconds)
        let mut maintenance_interval = tokio::time::interval(Duration::from_secs(30));

        loop {
            if self.network.is_none() {
                break;
            }

            tokio::select! {
                // Handle network events
                event = async {
                    if let Some(ref mut network) = self.network {
                        Some(network.swarm_mut().select_next_some().await)
                    } else {
                        None
                    }
                } => {
                    if let Some(event) = event {
                        self.handle_swarm_event(event).await;
                    }
                }

                // Periodic maintenance tasks
                _ = maintenance_interval.tick() => {
                    self.maybe_reannounce_exit();
                    self.maybe_send_heartbeat();
                    self.check_exit_timeouts();
                    self.discover_exits();
                    self.cleanup_stale_exits();
                }
            }
        }

        Ok(())
    }

    /// Trigger exit discovery via DHT
    pub fn discover_exits(&mut self) {
        if let Some(ref mut network) = self.network {
            network.discover_exits();
        }
    }

    /// Handle swarm event
    async fn handle_swarm_event(&mut self, event: SwarmEvent<TunnelCraftBehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on {}", address);
                if let Some(ref mut network) = self.network {
                    network.add_external_address(address);
                }
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                debug!("Connected to peer: {}", peer_id);
                self.relay_peers.push(peer_id);
                let mut state = self.state.write();
                state.stats.peers_connected += 1;
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                debug!("Disconnected from peer: {}", peer_id);
                self.relay_peers.retain(|p| p != &peer_id);
                let mut state = self.state.write();
                state.stats.peers_connected = state.stats.peers_connected.saturating_sub(1);
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
                        for (peer_id, addr) in peers {
                            debug!("mDNS discovered peer {} at {}", peer_id, addr);
                            if let Some(ref mut network) = self.network {
                                network.add_peer(peer_id, addr);
                            }
                            if !self.relay_peers.contains(&peer_id) {
                                self.relay_peers.push(peer_id);
                            }
                        }
                    }
                    Event::Expired(peers) => {
                        for (peer_id, _) in peers {
                            self.relay_peers.retain(|p| p != &peer_id);
                        }
                    }
                }
            }
            TunnelCraftBehaviourEvent::Gossipsub(gossip_event) => {
                use libp2p::gossipsub::Event;
                if let Event::Message { message, propagation_source, .. } = gossip_event {
                    // Handle exit status messages
                    self.handle_exit_status(&message.data, Some(propagation_source));
                }
            }
            TunnelCraftBehaviourEvent::Shard(shard_event) => {
                use libp2p::request_response::{Event, Message};
                match shard_event {
                    Event::Message {
                        message: Message::Request { request, channel, .. },
                        ..
                    } => {
                        let response = self.process_incoming_shard(request.shard).await;
                        if let Some(ref mut network) = self.network {
                            let _ = network
                                .swarm_mut()
                                .behaviour_mut()
                                .send_shard_response(channel, response);
                        }
                    }
                    Event::Message {
                        message: Message::Response { response, .. },
                        ..
                    } => {
                        if let ShardResponse::Accepted = response {
                            debug!("Shard accepted by peer");
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    /// Handle Kademlia DHT events (exit node discovery)
    fn handle_kademlia_event(&mut self, event: libp2p::kad::Event) {
        use libp2p::kad::{Event, QueryResult, GetRecordOk, GetProvidersOk};
        use tunnelcraft_network::EXIT_DHT_KEY_PREFIX;

        match event {
            Event::OutboundQueryProgressed { result, .. } => {
                match result {
                    QueryResult::GetRecord(Ok(GetRecordOk::FoundRecord(peer_record))) => {
                        let key_str = String::from_utf8_lossy(peer_record.record.key.as_ref());
                        if key_str.starts_with(EXIT_DHT_KEY_PREFIX) {
                            // Parse exit info from record
                            if let Ok(exit_info) = serde_json::from_slice::<ExitInfo>(&peer_record.record.value) {
                                self.on_exit_discovered(exit_info);
                            }
                        }
                    }
                    QueryResult::GetProviders(Ok(result)) => {
                        match result {
                            GetProvidersOk::FoundProviders { providers, .. } => {
                                // Found exit providers - query each for their detailed info
                                for provider_id in providers {
                                    if let Some(ref mut network) = self.network {
                                        network.query_exit(&provider_id);
                                    }
                                }
                            }
                            GetProvidersOk::FinishedWithNoAdditionalRecord { .. } => {}
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    /// Called when a new exit node is discovered via DHT
    fn on_exit_discovered(&mut self, exit_info: ExitInfo) {
        let is_new = !self.exit_nodes.contains_key(&exit_info.pubkey);

        if is_new {
            // New exit - create status entry with base 50% score
            let status = ExitNodeStatus::new(exit_info.clone());
            self.exit_nodes.insert(exit_info.pubkey, status);

            info!(
                "Discovered exit node: region={:?}, country={:?}, city={:?}, score={}",
                exit_info.region, exit_info.country_code, exit_info.city, EXIT_BASE_SCORE
            );

            // Auto-select first exit if none selected
            if self.selected_exit.is_none() {
                self.selected_exit = Some(exit_info);
            }
        } else {
            // Existing exit - update DHT timestamp
            if let Some(status) = self.exit_nodes.get_mut(&exit_info.pubkey) {
                status.last_dht_seen = std::time::Instant::now();
                status.info = exit_info;
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = NodeConfig::default();
        assert_eq!(config.mode, NodeMode::Client);
        assert_eq!(config.node_type, NodeType::Relay);
        assert!(!config.enable_exit);
    }

    #[test]
    fn test_node_mode() {
        assert_eq!(NodeMode::default(), NodeMode::Client);
        assert_ne!(NodeMode::Client, NodeMode::Node);
        assert_ne!(NodeMode::Node, NodeMode::Both);
    }

    #[test]
    fn test_node_creation() {
        let config = NodeConfig::default();
        let node = TunnelCraftNode::new(config).unwrap();
        assert_eq!(node.mode(), NodeMode::Client);
        assert!(!node.is_connected());
    }

    #[test]
    fn test_mode_switching() {
        let config = NodeConfig::default();
        let mut node = TunnelCraftNode::new(config).unwrap();

        assert_eq!(node.mode(), NodeMode::Client);

        node.set_mode(NodeMode::Node);
        assert_eq!(node.mode(), NodeMode::Node);

        node.set_mode(NodeMode::Both);
        assert_eq!(node.mode(), NodeMode::Both);
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
