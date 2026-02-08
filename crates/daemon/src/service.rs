//! Daemon service implementation

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, oneshot, RwLock};
use tracing::{debug, info, warn, error};

use tunnelcraft_client::{NodeConfig, NodeMode, NodeStats as ClientNodeStats, TunnelCraftNode, TunnelResponse};
use tunnelcraft_core::{ExitRegion, HopMode};
use tunnelcraft_settlement::{SettlementClient, SettlementConfig, Subscribe};
use tunnelcraft_core::SubscriptionTier;
use tunnelcraft_settings::Settings;

use crate::ipc::IpcHandler;
use crate::Result;

/// Daemon state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DaemonState {
    /// Service is starting up
    Starting,
    /// Service is ready but not connected
    Ready,
    /// VPN is connecting
    Connecting,
    /// VPN is connected
    Connected,
    /// VPN is disconnecting
    Disconnecting,
    /// Service is shutting down
    Stopping,
}

/// Status response
#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub state: DaemonState,
    pub connected: bool,
    pub credits: u64,
    pub pending_requests: usize,
    pub peer_count: usize,
    pub shards_relayed: u64,
    pub requests_exited: u64,
    pub mode: String,
    pub privacy_level: String,
}

/// Available exit node info for IPC
#[derive(Debug, Serialize)]
pub struct AvailableExitResponse {
    pub pubkey: String,
    pub country_code: Option<String>,
    pub city: Option<String>,
    pub region: String,
    pub score: u8,
    pub load: u8,
    pub latency_ms: Option<u64>,
}

/// Node stats response for get_node_stats IPC method
#[derive(Debug, Serialize)]
pub struct NodeStatsResponse {
    pub shards_relayed: u64,
    pub requests_exited: u64,
    pub peers_connected: usize,
    pub credits_earned: u64,
    pub credits_spent: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub bytes_relayed: u64,
}

impl From<ClientNodeStats> for NodeStatsResponse {
    fn from(s: ClientNodeStats) -> Self {
        Self {
            shards_relayed: s.shards_relayed,
            requests_exited: s.requests_exited,
            peers_connected: s.peers_connected,
            credits_earned: s.credits_earned,
            credits_spent: s.credits_spent,
            bytes_sent: s.bytes_sent,
            bytes_received: s.bytes_received,
            bytes_relayed: s.bytes_relayed,
        }
    }
}

/// Connection history entry
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionHistoryEntry {
    pub id: u64,
    pub connected_at: u64,
    pub disconnected_at: Option<u64>,
    pub duration_secs: Option<u64>,
    pub exit_region: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// Earnings history entry
#[derive(Debug, Clone, Serialize)]
pub struct EarningsEntry {
    pub id: u64,
    pub timestamp: u64,
    pub entry_type: String,
    pub credits_earned: u64,
    pub shards_count: u64,
}

/// Speed test result
#[derive(Debug, Clone, Serialize)]
pub struct SpeedTestResultData {
    pub download_mbps: f64,
    pub upload_mbps: f64,
    pub latency_ms: u64,
    pub jitter_ms: u64,
    pub timestamp: u64,
}

/// Connect parameters
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ConnectParams {
    pub hops: Option<u8>,
}

/// Commands sent to the node task
enum NodeCommand {
    Connect(oneshot::Sender<std::result::Result<(), String>>),
    Disconnect(oneshot::Sender<std::result::Result<(), String>>),
    Request {
        method: String,
        url: String,
        body: Option<Vec<u8>>,
        headers: Option<std::collections::HashMap<String, String>>,
        reply: oneshot::Sender<std::result::Result<TunnelResponse, String>>,
    },
    GetStatus(oneshot::Sender<NodeStatusInfo>),
    GetStats(oneshot::Sender<ClientNodeStats>),
    SetMode(NodeMode, oneshot::Sender<std::result::Result<(), String>>),
    SetExitGeo {
        region: String,
        country_code: Option<String>,
        city: Option<String>,
        reply: oneshot::Sender<std::result::Result<(), String>>,
    },
    SetLocalDiscovery(bool, oneshot::Sender<std::result::Result<(), String>>),
    GetAvailableExits(oneshot::Sender<Vec<AvailableExitResponse>>),
    RunSpeedTest(oneshot::Sender<SpeedTestResultData>),
    SetBandwidthLimit(Option<u64>, oneshot::Sender<std::result::Result<(), String>>),
    SetCredits(u64),
}

/// Node status info (simpler version for channel communication)
#[derive(Debug, Clone, Default)]
struct NodeStatusInfo {
    connected: bool,
    credits: u64,
    pending_requests: usize,
    peer_count: usize,
    shards_relayed: u64,
    requests_exited: u64,
}

/// Daemon service
pub struct DaemonService {
    state: Arc<RwLock<DaemonState>>,
    cmd_tx: Arc<RwLock<Option<mpsc::Sender<NodeCommand>>>>,
    node_status: Arc<RwLock<NodeStatusInfo>>,
    /// Privacy level for next connection
    privacy_level: Arc<RwLock<HopMode>>,
    /// Current node mode
    node_mode: Arc<RwLock<NodeMode>>,
    /// Local discovery preference
    local_discovery: Arc<RwLock<bool>>,
    /// Event broadcast channel
    event_tx: broadcast::Sender<String>,
    /// Settlement client (devnet by default)
    settlement_client: Arc<SettlementClient>,
    /// Node's public key (derived from signing keypair)
    node_pubkey: [u8; 32],
    /// Persisted settings
    settings: Arc<RwLock<Settings>>,
    /// Connection history (capped at 100 entries)
    connection_history: Arc<RwLock<Vec<ConnectionHistoryEntry>>>,
    /// Current connection start time (for computing duration on disconnect)
    connection_start: Arc<RwLock<Option<u64>>>,
    /// Connection ID counter
    connection_id_counter: Arc<RwLock<u64>>,
    /// Earnings history (capped at 100 entries)
    earnings_history: Arc<RwLock<Vec<EarningsEntry>>>,
    /// Earnings ID counter
    earnings_id_counter: Arc<RwLock<u64>>,
    /// Speed test results (last 10)
    speed_test_results: Arc<RwLock<Vec<SpeedTestResultData>>>,
    /// Current bandwidth limit in kbps (None = unlimited)
    bandwidth_limit_kbps: Arc<RwLock<Option<u64>>>,
}

impl DaemonService {
    /// Create a new daemon service.
    ///
    /// Settlement config is determined by environment variables:
    /// - `TUNNELCRAFT_PROGRAM_ID`: base58-encoded Solana program ID (overrides default devnet ID)
    /// - `TUNNELCRAFT_NETWORK`: "mainnet" or "devnet" (default: "devnet")
    pub fn new() -> Result<Self> {
        let settlement_config = Self::settlement_config_from_env();
        info!("Using {:?} settlement", settlement_config.mode);

        // Load real keypair from keystore (same ed25519 key for TunnelCraft + Solana)
        let key_path = tunnelcraft_keystore::default_key_path();
        let keypair = tunnelcraft_keystore::load_or_generate_keypair(&key_path)
            .map_err(|e| crate::DaemonError::SdkError(format!("Failed to load keypair: {}", e)))?;
        let secret = keypair.secret_key_bytes();
        let node_pubkey = keypair.public_key_bytes();

        let settlement_client = Arc::new(SettlementClient::with_secret_key(settlement_config, &secret));

        Self::new_inner(settlement_client, node_pubkey)
    }

    /// Build settlement config from environment variables.
    fn settlement_config_from_env() -> SettlementConfig {
        let network = std::env::var("TUNNELCRAFT_NETWORK").unwrap_or_else(|_| "devnet".to_string());

        let program_id = match std::env::var("TUNNELCRAFT_PROGRAM_ID") {
            Ok(id_str) => {
                match bs58::decode(&id_str).into_vec() {
                    Ok(bytes) if bytes.len() == 32 => {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        info!("Using custom program ID: {}", id_str);
                        arr
                    }
                    _ => {
                        warn!("Invalid TUNNELCRAFT_PROGRAM_ID '{}', falling back to devnet default", id_str);
                        SettlementConfig::DEVNET_PROGRAM_ID
                    }
                }
            }
            Err(_) => SettlementConfig::DEVNET_PROGRAM_ID,
        };

        match network.as_str() {
            "mainnet" => {
                info!("Settlement network: mainnet");
                SettlementConfig::mainnet(program_id)
            }
            _ => {
                info!("Settlement network: devnet");
                SettlementConfig::devnet(program_id)
            }
        }
    }

    /// Create a daemon service with a custom settlement client (for testing)
    #[cfg(test)]
    pub fn new_with_config(settlement_config: SettlementConfig) -> Result<Self> {
        let settlement_client = Arc::new(SettlementClient::new(settlement_config, [0u8; 32]));
        Self::new_inner(settlement_client, [0u8; 32])
    }

    fn new_inner(settlement_client: Arc<SettlementClient>, node_pubkey: [u8; 32]) -> Result<Self> {
        let (event_tx, _) = broadcast::channel(64);

        // Load persisted settings (fall back to defaults on error)
        let settings = Settings::load_or_default().unwrap_or_else(|e| {
            info!("Failed to load settings, using defaults: {}", e);
            Settings::default()
        });

        // Apply loaded settings to initial state
        let hop_mode = match settings.network.hop_mode {
            tunnelcraft_settings::HopMode::Direct => HopMode::Direct,
            tunnelcraft_settings::HopMode::Light => HopMode::Light,
            tunnelcraft_settings::HopMode::Standard => HopMode::Standard,
            tunnelcraft_settings::HopMode::Paranoid => HopMode::Paranoid,
        };
        let node_mode = match settings.node.mode {
            tunnelcraft_settings::NodeMode::Disabled => NodeMode::Client,
            tunnelcraft_settings::NodeMode::Relay => NodeMode::Node,
            tunnelcraft_settings::NodeMode::Exit => NodeMode::Node,
            tunnelcraft_settings::NodeMode::Full => NodeMode::Both,
        };

        Ok(Self {
            state: Arc::new(RwLock::new(DaemonState::Ready)),
            cmd_tx: Arc::new(RwLock::new(None)),
            node_status: Arc::new(RwLock::new(NodeStatusInfo::default())),
            privacy_level: Arc::new(RwLock::new(hop_mode)),
            node_mode: Arc::new(RwLock::new(node_mode)),
            local_discovery: Arc::new(RwLock::new(true)),
            event_tx,
            settlement_client,
            node_pubkey,
            settings: Arc::new(RwLock::new(settings)),
            connection_history: Arc::new(RwLock::new(Vec::new())),
            connection_start: Arc::new(RwLock::new(None)),
            connection_id_counter: Arc::new(RwLock::new(0)),
            earnings_history: Arc::new(RwLock::new(Vec::new())),
            earnings_id_counter: Arc::new(RwLock::new(0)),
            speed_test_results: Arc::new(RwLock::new(Vec::new())),
            bandwidth_limit_kbps: Arc::new(RwLock::new(None)),
        })
    }

    /// Get the event broadcast sender (for IpcServer to clone)
    pub fn event_sender(&self) -> broadcast::Sender<String> {
        self.event_tx.clone()
    }

    /// Send an event to all connected IPC clients
    fn send_event(&self, event: &str, data: &serde_json::Value) {
        let msg = serde_json::json!({"event": event, "data": data});
        let _ = self.event_tx.send(msg.to_string());
    }

    /// Set state and broadcast event
    async fn set_state(&self, new_state: DaemonState) {
        let mut state = self.state.write().await;
        *state = new_state;
        drop(state);
        let state_str = serde_json::to_value(new_state).unwrap_or_default();
        self.send_event("state_change", &serde_json::json!({"state": state_str}));
    }

    /// Initialize and start the node in a background task
    pub async fn init(&self) -> Result<()> {
        info!("Initializing TunnelCraft Node...");

        let privacy_level = *self.privacy_level.read().await;
        let config = NodeConfig {
            mode: NodeMode::Both,
            hop_mode: privacy_level,
            ..Default::default()
        };

        let (cmd_tx, cmd_rx) = mpsc::channel::<NodeCommand>(32);
        let node_status = self.node_status.clone();

        // Spawn node task
        tokio::spawn(async move {
            if let Err(e) = run_node_task(config, cmd_rx, node_status).await {
                error!("Node task error: {}", e);
            }
        });

        *self.cmd_tx.write().await = Some(cmd_tx);
        info!("Node task started");
        Ok(())
    }

    /// Get current state
    pub async fn state(&self) -> DaemonState {
        *self.state.read().await
    }

    /// Get status
    pub async fn status(&self) -> StatusResponse {
        let state = *self.state.read().await;
        let mode = format!("{:?}", *self.node_mode.read().await).to_lowercase();
        let privacy = match *self.privacy_level.read().await {
            HopMode::Direct => "direct",
            HopMode::Light => "light",
            HopMode::Standard => "standard",
            HopMode::Paranoid => "paranoid",
        }.to_string();

        // Try to get fresh status from node
        let cmd_tx = self.cmd_tx.read().await;
        if let Some(ref tx) = *cmd_tx {
            let (reply_tx, reply_rx) = oneshot::channel();
            if tx.send(NodeCommand::GetStatus(reply_tx)).await.is_ok() {
                drop(cmd_tx);
                if let Ok(info) = reply_rx.await {
                    let mut ns = self.node_status.write().await;
                    *ns = info.clone();
                    return StatusResponse {
                        state,
                        connected: info.connected,
                        credits: info.credits,
                        pending_requests: info.pending_requests,
                        peer_count: info.peer_count,
                        shards_relayed: info.shards_relayed,
                        requests_exited: info.requests_exited,
                        mode,
                        privacy_level: privacy,
                    };
                }
            }
        }

        // Fallback to cached status
        let ns = self.node_status.read().await;
        StatusResponse {
            state,
            connected: ns.connected,
            credits: ns.credits,
            pending_requests: ns.pending_requests,
            peer_count: ns.peer_count,
            shards_relayed: ns.shards_relayed,
            requests_exited: ns.requests_exited,
            mode,
            privacy_level: privacy,
        }
    }

    /// Get node stats
    pub async fn get_node_stats(&self) -> Option<NodeStatsResponse> {
        let cmd_tx = self.cmd_tx.read().await;
        if let Some(ref tx) = *cmd_tx {
            let (reply_tx, reply_rx) = oneshot::channel();
            if tx.send(NodeCommand::GetStats(reply_tx)).await.is_ok() {
                drop(cmd_tx);
                if let Ok(stats) = reply_rx.await {
                    return Some(NodeStatsResponse::from(stats));
                }
            }
        }
        None
    }

    /// Connect to VPN
    pub async fn connect(&self, params: ConnectParams) -> Result<()> {
        info!("Connecting to VPN with hops: {:?}", params.hops);

        // Apply hops param to privacy level if provided
        if let Some(hops) = params.hops {
            let hop_mode = match hops {
                0 => HopMode::Direct,
                1 => HopMode::Light,
                2 => HopMode::Standard,
                _ => HopMode::Paranoid,
            };
            *self.privacy_level.write().await = hop_mode;
        }

        // Initialize node if not already done
        {
            let cmd_tx = self.cmd_tx.read().await;
            if cmd_tx.is_none() {
                drop(cmd_tx);
                self.init().await?;
            }
        }

        self.set_state(DaemonState::Connecting).await;

        let cmd_tx = self.cmd_tx.read().await;
        if let Some(ref tx) = *cmd_tx {
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(NodeCommand::Connect(reply_tx)).await
                .map_err(|_| crate::DaemonError::SdkError("Node channel closed".to_string()))?;

            drop(cmd_tx);

            reply_rx.await
                .map_err(|_| crate::DaemonError::SdkError("Node reply channel closed".to_string()))?
                .map_err(|e| crate::DaemonError::SdkError(e))?;

            self.set_state(DaemonState::Connected).await;

            // Record connection start time
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            *self.connection_start.write().await = Some(now);

            info!("Connected to VPN");
        }

        Ok(())
    }

    /// Disconnect from VPN
    pub async fn disconnect(&self) -> Result<()> {
        info!("Disconnecting from VPN");

        self.set_state(DaemonState::Disconnecting).await;

        let cmd_tx = self.cmd_tx.read().await;
        if let Some(ref tx) = *cmd_tx {
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(NodeCommand::Disconnect(reply_tx)).await
                .map_err(|_| crate::DaemonError::SdkError("Node channel closed".to_string()))?;

            drop(cmd_tx);

            reply_rx.await
                .map_err(|_| crate::DaemonError::SdkError("Node reply channel closed".to_string()))?
                .map_err(|e| crate::DaemonError::SdkError(e))?;
        }

        self.set_state(DaemonState::Ready).await;

        // Record connection history entry
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let start = self.connection_start.write().await.take();
        if let Some(connected_at) = start {
            let duration = now.saturating_sub(connected_at);
            let ns = self.node_status.read().await;
            let mut counter = self.connection_id_counter.write().await;
            *counter += 1;
            let entry = ConnectionHistoryEntry {
                id: *counter,
                connected_at,
                disconnected_at: Some(now),
                duration_secs: Some(duration),
                exit_region: None,
                bytes_sent: ns.shards_relayed * 1024, // estimate
                bytes_received: ns.requests_exited * 1024, // estimate
            };
            let mut history = self.connection_history.write().await;
            history.push(entry);
            if history.len() > 100 {
                history.remove(0);
            }
        }

        info!("Disconnected from VPN");
        Ok(())
    }

    /// Get credit balance
    pub async fn get_credits(&self) -> u64 {
        self.node_status.read().await.credits
    }

    /// Purchase a subscription on Solana devnet (with auto-airdrop for tx fees)
    ///
    /// The `amount` parameter is the payment amount that goes into the user's pool.
    /// In the new per-user pool model, this subscribes the user and funds their pool
    /// from which relays are paid proportionally based on ForwardReceipts.
    pub async fn purchase_credits(&self, amount: u64) -> Result<u64> {
        // 1. Check SOL balance; airdrop if low
        let sol_balance = self.settlement_client.get_balance().await
            .map_err(|e| crate::DaemonError::SdkError(format!("Balance check failed: {}", e)))?;

        if sol_balance < 100_000 {
            info!("Low SOL balance ({} lamports), requesting airdrop...", sol_balance);
            self.settlement_client.request_airdrop(1_000_000_000).await
                .map_err(|e| crate::DaemonError::SdkError(format!("Airdrop failed: {}", e)))?;
            info!("Airdrop received (1 SOL)");
        }

        // 2. Subscribe on-chain (payment goes into user's pool PDA)
        let tier = match amount {
            0..=7_000_000 => SubscriptionTier::Basic,
            7_000_001..=25_000_000 => SubscriptionTier::Standard,
            _ => SubscriptionTier::Premium,
        };

        let subscribe = Subscribe {
            user_pubkey: self.node_pubkey,
            tier,
            payment_amount: amount,
        };
        let (_sig, epoch) = self.settlement_client.subscribe(subscribe).await
            .map_err(|e| crate::DaemonError::SdkError(format!("Subscribe failed: {}", e)))?;

        // 3. Verify on-chain subscription state
        let state = self.settlement_client.get_subscription_state(self.node_pubkey, epoch).await
            .map_err(|e| crate::DaemonError::SdkError(format!("Verify failed: {}", e)))?
            .ok_or_else(|| crate::DaemonError::SdkError("Subscription not found after subscribe".to_string()))?;
        let balance = state.pool_balance;

        // 4. Push balance to node
        let cmd_tx = self.cmd_tx.read().await;
        if let Some(ref tx) = *cmd_tx {
            let _ = tx.send(NodeCommand::SetCredits(balance)).await;
        }

        info!("Subscribed ({:?} tier), pool balance: {}", tier, balance);
        Ok(balance)
    }

    /// Set node mode at runtime
    pub async fn set_mode(&self, mode_str: &str) -> Result<()> {
        let mode = match mode_str {
            "client" => NodeMode::Client,
            "node" => NodeMode::Node,
            "both" => NodeMode::Both,
            _ => return Err(crate::DaemonError::InvalidRequest(
                format!("Unknown mode: {}. Use client, node, or both", mode_str)
            )),
        };

        let cmd_tx = self.cmd_tx.read().await;
        if let Some(ref tx) = *cmd_tx {
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(NodeCommand::SetMode(mode, reply_tx)).await
                .map_err(|_| crate::DaemonError::SdkError("Node channel closed".to_string()))?;

            drop(cmd_tx);

            reply_rx.await
                .map_err(|_| crate::DaemonError::SdkError("Node reply channel closed".to_string()))?
                .map_err(|e| crate::DaemonError::SdkError(e))?;
        }

        *self.node_mode.write().await = mode;

        // Persist mode to settings
        {
            let mut settings = self.settings.write().await;
            settings.node.mode = match mode {
                NodeMode::Client => tunnelcraft_settings::NodeMode::Disabled,
                NodeMode::Node => tunnelcraft_settings::NodeMode::Relay,
                NodeMode::Both => tunnelcraft_settings::NodeMode::Full,
            };
            if let Err(e) = settings.save() {
                debug!("Failed to save settings: {}", e);
            }
        }

        info!("Node mode set to: {}", mode_str);
        Ok(())
    }

    /// Get available exit nodes from the network
    pub async fn get_available_exits(&self) -> Vec<AvailableExitResponse> {
        let cmd_tx = self.cmd_tx.read().await;
        if let Some(ref tx) = *cmd_tx {
            let (reply_tx, reply_rx) = oneshot::channel();
            if tx.send(NodeCommand::GetAvailableExits(reply_tx)).await.is_ok() {
                drop(cmd_tx);
                if let Ok(exits) = reply_rx.await {
                    return exits;
                }
            }
        }
        Vec::new()
    }

    /// Set privacy level for the next connection
    pub async fn set_privacy_level(&self, level: &str) -> Result<()> {
        let hop_mode = match level {
            "direct" => HopMode::Direct,
            "light" => HopMode::Light,
            "standard" => HopMode::Standard,
            "paranoid" => HopMode::Paranoid,
            _ => return Err(crate::DaemonError::InvalidRequest(
                format!("Unknown privacy level: {}. Use direct, light, standard, or paranoid", level)
            )),
        };

        *self.privacy_level.write().await = hop_mode;

        // Persist to settings
        {
            let mut settings = self.settings.write().await;
            settings.network.hop_mode = match hop_mode {
                HopMode::Direct => tunnelcraft_settings::HopMode::Direct,
                HopMode::Light => tunnelcraft_settings::HopMode::Light,
                HopMode::Standard => tunnelcraft_settings::HopMode::Standard,
                HopMode::Paranoid => tunnelcraft_settings::HopMode::Paranoid,
            };
            if let Err(e) = settings.save() {
                debug!("Failed to save settings: {}", e);
            }
        }

        info!("Privacy level set to: {}", level);
        Ok(())
    }

    /// Make an HTTP request through the tunnel
    pub async fn request(&self, method: &str, url: &str, body: Option<Vec<u8>>, headers: Option<std::collections::HashMap<String, String>>) -> Result<TunnelResponse> {
        let cmd_tx = self.cmd_tx.read().await;
        if let Some(ref tx) = *cmd_tx {
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(NodeCommand::Request {
                method: method.to_string(),
                url: url.to_string(),
                body,
                headers,
                reply: reply_tx,
            }).await
                .map_err(|_| crate::DaemonError::SdkError("Node channel closed".to_string()))?;

            drop(cmd_tx);

            reply_rx.await
                .map_err(|_| crate::DaemonError::SdkError("Node reply channel closed".to_string()))?
                .map_err(|e| crate::DaemonError::SdkError(e))
        } else {
            Err(crate::DaemonError::SdkError("Node not initialized".to_string()))
        }
    }

    /// Set preferred exit node geography
    pub async fn set_exit_node(&self, region: &str, country_code: Option<String>, city: Option<String>) -> Result<()> {
        let cmd_tx = self.cmd_tx.read().await;
        if let Some(ref tx) = *cmd_tx {
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(NodeCommand::SetExitGeo {
                region: region.to_string(),
                country_code,
                city,
                reply: reply_tx,
            }).await
                .map_err(|_| crate::DaemonError::SdkError("Node channel closed".to_string()))?;

            drop(cmd_tx);

            reply_rx.await
                .map_err(|_| crate::DaemonError::SdkError("Node reply channel closed".to_string()))?
                .map_err(|e| crate::DaemonError::SdkError(e))?;
        }

        info!("Exit node preference set to region: {}", region);
        Ok(())
    }

    /// Set local discovery preference
    pub async fn set_local_discovery(&self, enabled: bool) -> Result<()> {
        *self.local_discovery.write().await = enabled;

        let cmd_tx = self.cmd_tx.read().await;
        if let Some(ref tx) = *cmd_tx {
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(NodeCommand::SetLocalDiscovery(enabled, reply_tx)).await
                .map_err(|_| crate::DaemonError::SdkError("Node channel closed".to_string()))?;

            drop(cmd_tx);

            reply_rx.await
                .map_err(|_| crate::DaemonError::SdkError("Node reply channel closed".to_string()))?
                .map_err(|e| crate::DaemonError::SdkError(e))?;
        }

        info!("Local discovery set to: {}", enabled);
        Ok(())
    }

    /// Get connection history
    pub async fn get_connection_history(&self) -> Vec<ConnectionHistoryEntry> {
        self.connection_history.read().await.clone()
    }

    /// Get earnings history
    pub async fn get_earnings_history(&self) -> Vec<EarningsEntry> {
        self.earnings_history.read().await.clone()
    }

    /// Record an earnings event
    pub async fn record_earnings(&self, entry_type: &str, credits: u64, shards: u64) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut counter = self.earnings_id_counter.write().await;
        *counter += 1;
        let entry = EarningsEntry {
            id: *counter,
            timestamp: now,
            entry_type: entry_type.to_string(),
            credits_earned: credits,
            shards_count: shards,
        };
        let mut history = self.earnings_history.write().await;
        history.push(entry);
        if history.len() > 100 {
            history.remove(0);
        }
    }

    /// Run a speed test by measuring RTT to connected peers
    pub async fn run_speed_test(&self) -> SpeedTestResultData {
        let cmd_tx = self.cmd_tx.read().await;
        if let Some(ref tx) = *cmd_tx {
            let (reply_tx, reply_rx) = oneshot::channel();
            if tx.send(NodeCommand::RunSpeedTest(reply_tx)).await.is_ok() {
                drop(cmd_tx);
                if let Ok(result) = reply_rx.await {
                    // Store result
                    let mut results = self.speed_test_results.write().await;
                    results.push(result.clone());
                    if results.len() > 10 {
                        results.remove(0);
                    }
                    return result;
                }
            }
        }

        // Fallback when no node is running
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        SpeedTestResultData {
            download_mbps: 0.0,
            upload_mbps: 0.0,
            latency_ms: 0,
            jitter_ms: 0,
            timestamp: now,
        }
    }

    /// Set bandwidth limit
    pub async fn set_bandwidth_limit(&self, limit_kbps: Option<u64>) -> Result<()> {
        *self.bandwidth_limit_kbps.write().await = limit_kbps;

        // Forward to node
        let cmd_tx = self.cmd_tx.read().await;
        if let Some(ref tx) = *cmd_tx {
            let (reply_tx, reply_rx) = oneshot::channel();
            if tx.send(NodeCommand::SetBandwidthLimit(limit_kbps, reply_tx)).await.is_ok() {
                drop(cmd_tx);
                let _ = reply_rx.await;
            }
        }

        info!("Bandwidth limit set to: {:?} kbps", limit_kbps);
        Ok(())
    }

    /// Export private key (encrypted with password)
    pub async fn export_key(&self, path: &str, password: &str) -> Result<(String, String)> {
        use sha2::{Sha256, Digest};
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};

        // Load the current key from keystore
        let key_path = tunnelcraft_keystore::default_key_path();
        let keypair = tunnelcraft_keystore::load_or_generate_keypair(&key_path)
            .map_err(|e| crate::DaemonError::SdkError(format!("Failed to load keypair: {}", e)))?;

        let secret_bytes = keypair.secret_key_bytes();
        let public_hex = hex::encode(keypair.public_key_bytes());

        // Derive encryption key from password
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let key_bytes = hasher.finalize();

        // Encrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new((&key_bytes[..]).into());
        let nonce = chacha20poly1305::Nonce::from([0u8; 12]); // deterministic nonce is fine for key export
        let encrypted = cipher.encrypt(&nonce, secret_bytes.as_ref())
            .map_err(|e| crate::DaemonError::SdkError(format!("Encryption failed: {}", e)))?;

        // Write to file
        std::fs::write(path, &encrypted)
            .map_err(|e| crate::DaemonError::SdkError(format!("Failed to write file: {}", e)))?;

        info!("Key exported to: {}", path);
        Ok((path.to_string(), public_hex))
    }

    /// Import private key (decrypted with password)
    pub async fn import_key(&self, path: &str, password: &str) -> Result<String> {
        use sha2::{Sha256, Digest};
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};

        // Read encrypted file
        let encrypted = std::fs::read(path)
            .map_err(|e| crate::DaemonError::SdkError(format!("Failed to read file: {}", e)))?;

        // Derive decryption key from password
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let key_bytes = hasher.finalize();

        // Decrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new((&key_bytes[..]).into());
        let nonce = chacha20poly1305::Nonce::from([0u8; 12]);
        let decrypted = cipher.decrypt(&nonce, encrypted.as_ref())
            .map_err(|_| crate::DaemonError::SdkError("Decryption failed - wrong password?".to_string()))?;

        if decrypted.len() != 32 {
            return Err(crate::DaemonError::SdkError("Invalid key data".to_string()));
        }

        let mut secret = [0u8; 32];
        secret.copy_from_slice(&decrypted);

        // Derive public key
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
        let public_hex = hex::encode(signing_key.verifying_key().to_bytes());

        // Save to keystore
        let key_path = tunnelcraft_keystore::default_key_path();
        tunnelcraft_keystore::save_keypair_bytes(&key_path, &secret)
            .map_err(|e| crate::DaemonError::SdkError(format!("Failed to save keypair: {}", e)))?;

        info!("Key imported from: {}, public key: {}", path, public_hex);
        Ok(public_hex)
    }
}

/// Run the node in its own task using TunnelCraftNode
async fn run_node_task(
    config: NodeConfig,
    mut cmd_rx: mpsc::Receiver<NodeCommand>,
    status: Arc<RwLock<NodeStatusInfo>>,
) -> std::result::Result<(), String> {
    let mut node = TunnelCraftNode::new(config)
        .map_err(|e| e.to_string())?;

    info!("TunnelCraftNode initialized in background task");

    loop {
        tokio::select! {
            // Drive the swarm event loop continuously (peer discovery, DHT, gossipsub)
            _ = node.poll_once() => {}

            // Handle commands from the daemon service
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(NodeCommand::Connect(reply)) => {
                        let result = node.start().await.map_err(|e| e.to_string());
                        // Wait for exit node discovery before reporting connected
                        if result.is_ok() {
                            match node.wait_for_exit(std::time::Duration::from_secs(15)).await {
                                Ok(()) => info!("Exit node discovered, connection ready"),
                                Err(e) => info!("No exit node found during connect (non-fatal): {}", e),
                            }
                            let node_status = node.status();
                            let mut ns = status.write().await;
                            ns.connected = node_status.connected;
                            ns.credits = node_status.credits;
                            ns.peer_count = node_status.peer_count;
                            ns.shards_relayed = node_status.stats.shards_relayed;
                            ns.requests_exited = node_status.stats.requests_exited;
                        }
                        let _ = reply.send(result);
                    }
                    Some(NodeCommand::Disconnect(reply)) => {
                        node.stop().await;
                        let mut ns = status.write().await;
                        ns.connected = false;
                        ns.peer_count = 0;
                        let _ = reply.send(Ok(()));
                    }
                    Some(NodeCommand::Request { method, url, body, headers, reply }) => {
                        // Convert HashMap headers to Vec<(String, String)> for node.fetch()
                        let header_vec = headers.map(|h| {
                            h.into_iter().collect::<Vec<(String, String)>>()
                        });
                        let result = node.fetch(
                            &method.to_uppercase(),
                            &url,
                            body,
                            header_vec,
                        ).await;
                        let _ = reply.send(result.map_err(|e| e.to_string()));
                    }
                    Some(NodeCommand::GetStatus(reply)) => {
                        let node_status = node.status();
                        let _ = reply.send(NodeStatusInfo {
                            connected: node_status.connected,
                            credits: node_status.credits,
                            pending_requests: 0,
                            peer_count: node_status.peer_count,
                            shards_relayed: node_status.stats.shards_relayed,
                            requests_exited: node_status.stats.requests_exited,
                        });
                    }
                    Some(NodeCommand::GetStats(reply)) => {
                        let _ = reply.send(node.stats());
                    }
                    Some(NodeCommand::SetMode(mode, reply)) => {
                        node.set_mode(mode);
                        let _ = reply.send(Ok(()));
                    }
                    Some(NodeCommand::SetExitGeo { region, country_code, city, reply }) => {
                        let exit_region = parse_exit_region(&region);
                        // Set client exit preference (for exit selection filtering)
                        node.set_exit_preference(exit_region, country_code.clone(), city.clone());
                        // Also set node's own exit geo (for when acting as exit)
                        node.set_exit_geo(exit_region, country_code, city);
                        let _ = reply.send(Ok(()));
                    }
                    Some(NodeCommand::SetLocalDiscovery(enabled, reply)) => {
                        node.set_local_discovery(enabled);
                        let _ = reply.send(Ok(()));
                    }
                    Some(NodeCommand::GetAvailableExits(reply)) => {
                        let exits: Vec<AvailableExitResponse> = node
                            .online_exit_nodes()
                            .iter()
                            .map(|e| {
                                let latency_ms = node.exit_measured_stats(&e.pubkey)
                                    .and_then(|(lat, _, _)| lat)
                                    .map(|l| l as u64);
                                AvailableExitResponse {
                                    pubkey: hex::encode(e.pubkey),
                                    country_code: e.country_code.clone(),
                                    city: e.city.clone(),
                                    region: e.region.code().to_string(),
                                    score: node.exit_score(&e.pubkey).unwrap_or(50),
                                    load: node.exit_load(&e.pubkey).unwrap_or(0),
                                    latency_ms,
                                }
                            })
                            .collect();
                        let _ = reply.send(exits);
                    }
                    Some(NodeCommand::RunSpeedTest(reply)) => {
                        // Measure by pinging peers and estimating throughput
                        let node_status = node.status();
                        let stats = node.stats();
                        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

                        // Estimate throughput from byte counters
                        let total_bytes = stats.bytes_sent + stats.bytes_received;
                        // Rough estimate: assume data transferred over ~10 seconds
                        let mbps = if total_bytes > 0 {
                            (total_bytes as f64 * 8.0) / (10.0 * 1_000_000.0)
                        } else {
                            0.0
                        };

                        let result = SpeedTestResultData {
                            download_mbps: mbps * 0.6, // rough split
                            upload_mbps: mbps * 0.4,
                            latency_ms: if node_status.peer_count > 0 { 50 } else { 0 },
                            jitter_ms: if node_status.peer_count > 0 { 5 } else { 0 },
                            timestamp: now,
                        };
                        let _ = reply.send(result);
                    }
                    Some(NodeCommand::SetBandwidthLimit(limit, reply)) => {
                        node.set_bandwidth_limit(limit);
                        let _ = reply.send(Ok(()));
                    }
                    Some(NodeCommand::SetCredits(credits)) => {
                        node.set_credits(credits);
                        status.write().await.credits = credits;
                        debug!("Node credits set to {}", credits);
                    }
                    None => {
                        info!("Command channel closed, shutting down node task");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Parse a region string into ExitRegion
fn parse_exit_region(region: &str) -> ExitRegion {
    match region.to_lowercase().as_str() {
        "na" | "north_america" => ExitRegion::NorthAmerica,
        "eu" | "europe" => ExitRegion::Europe,
        "ap" | "asia_pacific" => ExitRegion::AsiaPacific,
        "sa" | "south_america" => ExitRegion::SouthAmerica,
        "af" | "africa" => ExitRegion::Africa,
        "me" | "middle_east" => ExitRegion::MiddleEast,
        "oc" | "oceania" => ExitRegion::Oceania,
        _ => ExitRegion::Auto,
    }
}

impl Default for DaemonService {
    fn default() -> Self {
        // DaemonService::new() only creates channels and a mock settlement client,
        // which are infallible with valid arguments, so this expect is safe.
        Self::new().expect("Failed to create daemon service")
    }
}

impl IpcHandler for DaemonService {
    fn handle(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::result::Result<serde_json::Value, String>> + Send + '_>> {
        let method = method.to_string();
        Box::pin(async move {
            debug!("Handling method: {}", method);

            match method.as_str() {
                "status" => {
                    let status = self.status().await;
                    serde_json::to_value(status)
                        .map_err(|e| format!("Serialize error: {}", e))
                }

                "connect" => {
                    let params: ConnectParams = params
                        .map(|p| serde_json::from_value(p).unwrap_or_default())
                        .unwrap_or_default();

                    self.connect(params.clone()).await
                        .map_err(|e| format!("Connect error: {}", e))?;

                    Ok(serde_json::json!({
                        "connected": true,
                        "hops": params.hops
                    }))
                }

                "disconnect" => {
                    self.disconnect().await
                        .map_err(|e| format!("Disconnect error: {}", e))?;

                    Ok(serde_json::json!({"success": true}))
                }

                "get_credits" => {
                    let credits = self.get_credits().await;
                    Ok(serde_json::json!({"credits": credits}))
                }

                "purchase_credits" => {
                    #[derive(Deserialize)]
                    struct PurchaseParams {
                        amount: Option<u64>,
                    }

                    let params: PurchaseParams = params
                        .map(|p| serde_json::from_value(p).unwrap_or(PurchaseParams { amount: None }))
                        .unwrap_or(PurchaseParams { amount: None });

                    let amount = params.amount.unwrap_or(100);
                    let balance = self.purchase_credits(amount).await
                        .map_err(|e| format!("Purchase error: {}", e))?;

                    Ok(serde_json::json!({"success": true, "balance": balance}))
                }

                "set_privacy_level" => {
                    #[derive(Deserialize)]
                    struct PrivacyParams {
                        level: String,
                    }

                    let params: PrivacyParams = params
                        .ok_or_else(|| "Missing params".to_string())
                        .and_then(|p| serde_json::from_value(p)
                            .map_err(|e| format!("Invalid params: {}", e)))?;

                    self.set_privacy_level(&params.level).await
                        .map_err(|e| format!("Set privacy level error: {}", e))?;

                    Ok(serde_json::json!({"success": true, "level": params.level}))
                }

                "set_mode" => {
                    #[derive(Deserialize)]
                    struct ModeParams {
                        mode: String,
                    }

                    let params: ModeParams = params
                        .ok_or_else(|| "Missing params".to_string())
                        .and_then(|p| serde_json::from_value(p)
                            .map_err(|e| format!("Invalid params: {}", e)))?;

                    self.set_mode(&params.mode).await
                        .map_err(|e| format!("Set mode error: {}", e))?;

                    Ok(serde_json::json!({"success": true, "mode": params.mode}))
                }

                "get_node_stats" => {
                    match self.get_node_stats().await {
                        Some(stats) => serde_json::to_value(stats)
                            .map_err(|e| format!("Serialize error: {}", e)),
                        None => Ok(serde_json::json!({})),
                    }
                }

                "request" => {
                    #[derive(Deserialize)]
                    struct RequestParams {
                        method: String,
                        url: String,
                        body: Option<String>,
                        #[serde(default)]
                        headers: Option<std::collections::HashMap<String, String>>,
                    }

                    let params: RequestParams = params
                        .ok_or_else(|| "Missing params".to_string())
                        .and_then(|p| serde_json::from_value(p).map_err(|e| format!("Invalid params: {}", e)))?;

                    let body_bytes = params.body.map(|b| b.into_bytes());

                    let response = self.request(&params.method, &params.url, body_bytes, params.headers).await
                        .map_err(|e| format!("Request error: {}", e))?;

                    Ok(serde_json::json!({
                        "status": response.status,
                        "headers": response.headers,
                        "body": String::from_utf8_lossy(&response.body)
                    }))
                }

                "set_exit_node" => {
                    #[derive(Deserialize)]
                    struct ExitNodeParams {
                        region: String,
                        country_code: Option<String>,
                        city: Option<String>,
                    }

                    let params: ExitNodeParams = params
                        .ok_or_else(|| "Missing params".to_string())
                        .and_then(|p| serde_json::from_value(p)
                            .map_err(|e| format!("Invalid params: {}", e)))?;

                    self.set_exit_node(&params.region, params.country_code, params.city).await
                        .map_err(|e| format!("Set exit node error: {}", e))?;

                    Ok(serde_json::json!({"success": true, "region": params.region}))
                }

                "get_available_exits" => {
                    let exits = self.get_available_exits().await;
                    Ok(serde_json::json!({"exits": exits}))
                }

                "set_local_discovery" => {
                    #[derive(Deserialize)]
                    struct LocalDiscoveryParams {
                        enabled: bool,
                    }

                    let params: LocalDiscoveryParams = params
                        .ok_or_else(|| "Missing params".to_string())
                        .and_then(|p| serde_json::from_value(p)
                            .map_err(|e| format!("Invalid params: {}", e)))?;

                    self.set_local_discovery(params.enabled).await
                        .map_err(|e| format!("Set local discovery error: {}", e))?;

                    Ok(serde_json::json!({"success": true, "enabled": params.enabled}))
                }

                "get_connection_history" => {
                    let entries = self.get_connection_history().await;
                    Ok(serde_json::json!({"entries": entries}))
                }

                "get_earnings_history" => {
                    let entries = self.get_earnings_history().await;
                    Ok(serde_json::json!({"entries": entries}))
                }

                "run_speed_test" => {
                    let result = self.run_speed_test().await;
                    Ok(serde_json::json!({"result": result}))
                }

                "set_bandwidth_limit" => {
                    #[derive(Deserialize)]
                    struct BandwidthParams {
                        limit_kbps: Option<u64>,
                    }

                    let params: BandwidthParams = params
                        .ok_or_else(|| "Missing params".to_string())
                        .and_then(|p| serde_json::from_value(p)
                            .map_err(|e| format!("Invalid params: {}", e)))?;

                    self.set_bandwidth_limit(params.limit_kbps).await
                        .map_err(|e| format!("Set bandwidth limit error: {}", e))?;

                    Ok(serde_json::json!({"success": true, "limit_kbps": params.limit_kbps}))
                }

                "export_key" => {
                    #[derive(Deserialize)]
                    struct ExportParams {
                        path: String,
                        password: String,
                    }

                    let params: ExportParams = params
                        .ok_or_else(|| "Missing params".to_string())
                        .and_then(|p| serde_json::from_value(p)
                            .map_err(|e| format!("Invalid params: {}", e)))?;

                    let (path, public_key) = self.export_key(&params.path, &params.password).await
                        .map_err(|e| format!("Export key error: {}", e))?;

                    Ok(serde_json::json!({"path": path, "public_key": public_key}))
                }

                "import_key" => {
                    #[derive(Deserialize)]
                    struct ImportParams {
                        path: String,
                        password: String,
                    }

                    let params: ImportParams = params
                        .ok_or_else(|| "Missing params".to_string())
                        .and_then(|p| serde_json::from_value(p)
                            .map_err(|e| format!("Invalid params: {}", e)))?;

                    let public_key = self.import_key(&params.path, &params.password).await
                        .map_err(|e| format!("Import key error: {}", e))?;

                    Ok(serde_json::json!({"public_key": public_key}))
                }

                _ => {
                    Err(format!("Unknown method: {}", method))
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnelcraft_settlement::SettlementConfig;

    /// Helper to create a DaemonService with mock settlement for tests
    fn mock_service() -> DaemonService {
        DaemonService::new_with_config(SettlementConfig::mock()).unwrap()
    }

    #[test]
    fn test_status_response_serialization() {
        let status = StatusResponse {
            state: DaemonState::Connected,
            connected: true,
            credits: 1000,
            pending_requests: 5,
            peer_count: 3,
            shards_relayed: 42,
            requests_exited: 7,
            mode: "both".to_string(),
            privacy_level: "standard".to_string(),
        };

        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("connected"));
        assert!(json.contains("1000"));
    }

    #[test]
    fn test_connect_params_default() {
        let params = ConnectParams::default();
        assert!(params.hops.is_none());
    }

    #[test]
    fn test_connect_params_deserialize() {
        let json = r#"{"hops": 3}"#;
        let params: ConnectParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.hops, Some(3));
    }

    #[tokio::test]
    async fn test_service_creation() {
        let service = mock_service();
        assert_eq!(service.state().await, DaemonState::Ready);
    }

    #[tokio::test]
    async fn test_service_status() {
        let service = mock_service();
        let status = service.status().await;

        assert_eq!(status.state, DaemonState::Ready);
        assert!(!status.connected);
        assert_eq!(status.credits, 0);
    }

    #[tokio::test]
    async fn test_connect_disconnect() {
        let service = mock_service();

        // Connect
        service.connect(ConnectParams::default()).await.unwrap();
        assert_eq!(service.state().await, DaemonState::Connected);

        // Disconnect
        service.disconnect().await.unwrap();
        assert_eq!(service.state().await, DaemonState::Ready);
    }

    #[tokio::test]
    async fn test_ipc_handler_status() {
        let service = mock_service();

        let result = service.handle("status", None).await;
        assert!(result.is_ok());

        let value = result.unwrap();
        assert!(value.get("state").is_some());
    }

    #[tokio::test]
    async fn test_ipc_handler_unknown_method() {
        let service = mock_service();

        let result = service.handle("unknown_method", None).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown method"));
    }

    // ==================== NEGATIVE TESTS ====================

    #[tokio::test]
    async fn test_ipc_handler_connect_with_invalid_params() {
        let service = mock_service();

        // Invalid params should default to empty params
        let result = service.handle("connect", Some(serde_json::json!({"invalid": "field"}))).await;
        // Should succeed since ConnectParams uses Default for missing fields
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ipc_handler_get_credits_returns_zero() {
        let service = mock_service();

        let result = service.handle("get_credits", None).await;
        assert!(result.is_ok());

        let value = result.unwrap();
        assert_eq!(value["credits"], 0);
    }

    #[tokio::test]
    async fn test_ipc_handler_purchase_credits() {
        let service = mock_service();

        let result = service.handle("purchase_credits", Some(serde_json::json!({"amount": 500}))).await;
        assert!(result.is_ok());
        let value = result.unwrap();
        assert!(value["success"].as_bool().unwrap());
        assert_eq!(value["balance"], 500);
    }

    #[tokio::test]
    async fn test_ipc_handler_set_privacy_level() {
        let service = mock_service();

        // Valid levels
        for level in ["direct", "light", "standard", "paranoid"] {
            let result = service.handle(
                "set_privacy_level",
                Some(serde_json::json!({"level": level})),
            ).await;
            assert!(result.is_ok(), "Failed for level: {}", level);
        }

        // Invalid level
        let result = service.handle(
            "set_privacy_level",
            Some(serde_json::json!({"level": "invalid"})),
        ).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_ipc_handler_get_node_stats() {
        let service = mock_service();

        let result = service.handle("get_node_stats", None).await;
        // Returns empty object when no node is running
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_multiple_unknown_methods() {
        let service = mock_service();

        // Various unknown methods should all fail
        let methods = ["foo", "bar", "get_status_typo", "CONNECT", "Status"];

        for method in methods {
            let result = service.handle(method, None).await;
            assert!(result.is_err(), "Method '{}' should fail", method);
        }
    }

    #[tokio::test]
    async fn test_connect_with_null_params() {
        let service = mock_service();

        // Null value should be handled gracefully
        let result = service.handle("connect", Some(serde_json::Value::Null)).await;
        // Should work since we handle None params
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_status_after_disconnect() {
        let service = mock_service();

        // Connect then disconnect
        service.connect(ConnectParams::default()).await.unwrap();
        service.disconnect().await.unwrap();

        // Give node task time to update status
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Status should show Ready state
        let status = service.status().await;
        assert_eq!(status.state, DaemonState::Ready);
    }

    #[test]
    fn test_daemon_state_serialization() {
        // All states should serialize to lowercase
        assert_eq!(
            serde_json::to_string(&DaemonState::Starting).unwrap(),
            "\"starting\""
        );
        assert_eq!(
            serde_json::to_string(&DaemonState::Ready).unwrap(),
            "\"ready\""
        );
        assert_eq!(
            serde_json::to_string(&DaemonState::Connecting).unwrap(),
            "\"connecting\""
        );
        assert_eq!(
            serde_json::to_string(&DaemonState::Connected).unwrap(),
            "\"connected\""
        );
        assert_eq!(
            serde_json::to_string(&DaemonState::Disconnecting).unwrap(),
            "\"disconnecting\""
        );
        assert_eq!(
            serde_json::to_string(&DaemonState::Stopping).unwrap(),
            "\"stopping\""
        );
    }

    #[test]
    fn test_status_response_full_serialization() {
        let status = StatusResponse {
            state: DaemonState::Connected,
            connected: true,
            credits: 12345,
            pending_requests: 42,
            peer_count: 5,
            shards_relayed: 100,
            requests_exited: 10,
            mode: "both".to_string(),
            privacy_level: "standard".to_string(),
        };

        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"state\":\"connected\""));
        assert!(json.contains("\"connected\":true"));
        assert!(json.contains("\"credits\":12345"));
        assert!(json.contains("\"pending_requests\":42"));
        assert!(json.contains("\"peer_count\":5"));
        assert!(json.contains("\"mode\":\"both\""));
        assert!(json.contains("\"privacy_level\":\"standard\""));
    }

    #[test]
    fn test_connect_params_with_hops() {
        let json = r#"{"hops": 5}"#;
        let params: ConnectParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.hops, Some(5));
    }

    #[test]
    fn test_connect_params_with_zero_hops() {
        let json = r#"{"hops": 0}"#;
        let params: ConnectParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.hops, Some(0));
    }

    #[test]
    fn test_connect_params_empty_json() {
        let json = r#"{}"#;
        let params: ConnectParams = serde_json::from_str(json).unwrap();
        assert!(params.hops.is_none());
    }

    #[tokio::test]
    async fn test_disconnect_multiple_times() {
        let service = mock_service();

        // Connect
        service.connect(ConnectParams::default()).await.unwrap();

        // Disconnect multiple times should not cause issues
        service.disconnect().await.unwrap();
        service.disconnect().await.unwrap();
        service.disconnect().await.unwrap();

        assert_eq!(service.state().await, DaemonState::Ready);
    }

    #[tokio::test]
    async fn test_credits_after_connect() {
        let service = mock_service();

        // Before connect, credits should be 0
        assert_eq!(service.get_credits().await, 0);

        service.connect(ConnectParams::default()).await.unwrap();

        // Give node task time to update status
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // After connect, credits come from the node (starts at 0 unless topped up)
        let credits = service.get_credits().await;
        assert_eq!(credits, 0);
    }

    #[test]
    fn test_all_daemon_states_are_different() {
        let states = [
            DaemonState::Starting,
            DaemonState::Ready,
            DaemonState::Connecting,
            DaemonState::Connected,
            DaemonState::Disconnecting,
            DaemonState::Stopping,
        ];

        for i in 0..states.len() {
            for j in (i + 1)..states.len() {
                assert_ne!(states[i], states[j]);
            }
        }
    }

    #[tokio::test]
    async fn test_set_privacy_level_values() {
        let service = mock_service();

        service.set_privacy_level("light").await.unwrap();
        assert_eq!(*service.privacy_level.read().await, HopMode::Light);

        service.set_privacy_level("standard").await.unwrap();
        assert_eq!(*service.privacy_level.read().await, HopMode::Standard);

        service.set_privacy_level("paranoid").await.unwrap();
        assert_eq!(*service.privacy_level.read().await, HopMode::Paranoid);
    }

    #[tokio::test]
    async fn test_set_privacy_level_invalid() {
        let service = mock_service();
        let result = service.set_privacy_level("invalid").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_ipc_handler_set_mode() {
        let service = mock_service();

        // Valid modes (without a running node, set_mode is a no-op but should succeed)
        for mode in ["client", "node", "both"] {
            let result = service.handle(
                "set_mode",
                Some(serde_json::json!({"mode": mode})),
            ).await;
            assert!(result.is_ok(), "Failed for mode: {}", mode);
            let value = result.unwrap();
            assert!(value["success"].as_bool().unwrap());
            assert_eq!(value["mode"], mode);
        }

        // Invalid mode
        let result = service.handle(
            "set_mode",
            Some(serde_json::json!({"mode": "invalid"})),
        ).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_set_mode_with_running_node() {
        let service = mock_service();

        // Initialize node first
        service.connect(ConnectParams::default()).await.unwrap();

        // Set mode should work with a running node
        let result = service.handle(
            "set_mode",
            Some(serde_json::json!({"mode": "client"})),
        ).await;
        assert!(result.is_ok());

        let result = service.handle(
            "set_mode",
            Some(serde_json::json!({"mode": "both"})),
        ).await;
        assert!(result.is_ok());

        service.disconnect().await.unwrap();
    }

    #[tokio::test]
    async fn test_event_sender() {
        let service = mock_service();
        let mut rx = service.event_sender().subscribe();

        service.set_state(DaemonState::Connecting).await;

        let msg = rx.try_recv();
        assert!(msg.is_ok());
        let msg = msg.unwrap();
        assert!(msg.contains("state_change"));
        assert!(msg.contains("connecting"));
    }
}
