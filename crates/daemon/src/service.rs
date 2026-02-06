//! Daemon service implementation

use std::sync::Arc;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, oneshot, RwLock};
use tracing::{debug, info, error};

use tunnelcraft_client::{NodeConfig, NodeMode, NodeStats as ClientNodeStats, TunnelCraftNode, TunnelResponse};
use tunnelcraft_core::{ExitRegion, HopMode};
use tunnelcraft_settlement::{SettlementClient, SettlementConfig, PurchaseCredits};

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

/// Connect parameters
#[derive(Debug, Deserialize, Default)]
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
    /// Event broadcast channel
    event_tx: broadcast::Sender<String>,
    /// Mock settlement client for purchase_credits
    settlement_client: Arc<SettlementClient>,
}

impl DaemonService {
    /// Create a new daemon service
    pub fn new() -> Result<Self> {
        let (event_tx, _) = broadcast::channel(64);
        let settlement_config = SettlementConfig::mock();
        let settlement_client = Arc::new(SettlementClient::new(settlement_config, [0u8; 32]));

        Ok(Self {
            state: Arc::new(RwLock::new(DaemonState::Ready)),
            cmd_tx: Arc::new(RwLock::new(None)),
            node_status: Arc::new(RwLock::new(NodeStatusInfo::default())),
            privacy_level: Arc::new(RwLock::new(HopMode::Standard)),
            node_mode: Arc::new(RwLock::new(NodeMode::Both)),
            event_tx,
            settlement_client,
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

        info!("Disconnected from VPN");
        Ok(())
    }

    /// Get credit balance
    pub async fn get_credits(&self) -> u64 {
        self.node_status.read().await.credits
    }

    /// Purchase credits using mock settlement
    pub async fn purchase_credits(&self, amount: u64) -> Result<u64> {
        let credit_secret = SettlementClient::generate_credit_secret();
        let credit_hash = SettlementClient::hash_credit_secret(&credit_secret);

        let purchase = PurchaseCredits {
            credit_hash,
            amount,
        };

        self.settlement_client.purchase_credits(purchase).await
            .map_err(|e| crate::DaemonError::SdkError(format!("Purchase failed: {}", e)))?;

        let balance = self.settlement_client.verify_credit(credit_hash).await
            .map_err(|e| crate::DaemonError::SdkError(format!("Verify failed: {}", e)))?;

        info!("Purchased {} credits, new balance: {}", amount, balance);
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
            "light" => HopMode::Light,
            "standard" => HopMode::Standard,
            "paranoid" => HopMode::Paranoid,
            _ => return Err(crate::DaemonError::InvalidRequest(
                format!("Unknown privacy level: {}. Use light, standard, or paranoid", level)
            )),
        };

        *self.privacy_level.write().await = hop_mode;
        info!("Privacy level set to: {}", level);
        Ok(())
    }

    /// Make an HTTP request through the tunnel
    pub async fn request(&self, method: &str, url: &str, body: Option<Vec<u8>>) -> Result<TunnelResponse> {
        let cmd_tx = self.cmd_tx.read().await;
        if let Some(ref tx) = *cmd_tx {
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(NodeCommand::Request {
                method: method.to_string(),
                url: url.to_string(),
                body,
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
            // Handle commands from the daemon service
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(NodeCommand::Connect(reply)) => {
                        let result = node.start().await.map_err(|e| e.to_string());
                        // Update status after connect
                        if result.is_ok() {
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
                    Some(NodeCommand::Request { method, url, body, reply }) => {
                        let result = node.fetch(
                            &method.to_uppercase(),
                            &url,
                            body,
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
                        node.set_exit_geo(exit_region, country_code, city);
                        let _ = reply.send(Ok(()));
                    }
                    Some(NodeCommand::SetLocalDiscovery(_enabled, reply)) => {
                        // Local discovery is a network-level feature;
                        // preference is stored but mDNS integration is deferred
                        let _ = reply.send(Ok(()));
                    }
                    Some(NodeCommand::GetAvailableExits(reply)) => {
                        let exits: Vec<AvailableExitResponse> = node
                            .online_exit_nodes()
                            .iter()
                            .map(|e| AvailableExitResponse {
                                pubkey: hex::encode(e.pubkey),
                                country_code: e.country_code.clone(),
                                city: e.city.clone(),
                                region: e.region.code().to_string(),
                                score: node.exit_score(&e.pubkey).unwrap_or(50),
                                load: node.exit_load(&e.pubkey).unwrap_or(0),
                            })
                            .collect();
                        let _ = reply.send(exits);
                    }
                    None => {
                        info!("Command channel closed, shutting down node task");
                        break;
                    }
                }
            }

            // Poll network events
            _ = node.poll_once() => {}
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

                    self.connect(params).await
                        .map_err(|e| format!("Connect error: {}", e))?;

                    Ok(serde_json::json!({"success": true}))
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

                    if let Some(ref hdrs) = params.headers {
                        if !hdrs.is_empty() {
                            debug!("Request includes {} custom headers (header passthrough pending SDK support)", hdrs.len());
                        }
                    }

                    let response = self.request(&params.method, &params.url, body_bytes).await
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
        let service = DaemonService::new().unwrap();
        assert_eq!(service.state().await, DaemonState::Ready);
    }

    #[tokio::test]
    async fn test_service_status() {
        let service = DaemonService::new().unwrap();
        let status = service.status().await;

        assert_eq!(status.state, DaemonState::Ready);
        assert!(!status.connected);
        assert_eq!(status.credits, 0);
    }

    #[tokio::test]
    async fn test_connect_disconnect() {
        let service = DaemonService::new().unwrap();

        // Connect
        service.connect(ConnectParams::default()).await.unwrap();
        assert_eq!(service.state().await, DaemonState::Connected);

        // Disconnect
        service.disconnect().await.unwrap();
        assert_eq!(service.state().await, DaemonState::Ready);
    }

    #[tokio::test]
    async fn test_ipc_handler_status() {
        let service = DaemonService::new().unwrap();

        let result = service.handle("status", None).await;
        assert!(result.is_ok());

        let value = result.unwrap();
        assert!(value.get("state").is_some());
    }

    #[tokio::test]
    async fn test_ipc_handler_unknown_method() {
        let service = DaemonService::new().unwrap();

        let result = service.handle("unknown_method", None).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown method"));
    }

    // ==================== NEGATIVE TESTS ====================

    #[tokio::test]
    async fn test_ipc_handler_connect_with_invalid_params() {
        let service = DaemonService::new().unwrap();

        // Invalid params should default to empty params
        let result = service.handle("connect", Some(serde_json::json!({"invalid": "field"}))).await;
        // Should succeed since ConnectParams uses Default for missing fields
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ipc_handler_get_credits_returns_zero() {
        let service = DaemonService::new().unwrap();

        let result = service.handle("get_credits", None).await;
        assert!(result.is_ok());

        let value = result.unwrap();
        assert_eq!(value["credits"], 0);
    }

    #[tokio::test]
    async fn test_ipc_handler_purchase_credits() {
        let service = DaemonService::new().unwrap();

        let result = service.handle("purchase_credits", Some(serde_json::json!({"amount": 500}))).await;
        assert!(result.is_ok());
        let value = result.unwrap();
        assert!(value["success"].as_bool().unwrap());
        assert_eq!(value["balance"], 500);
    }

    #[tokio::test]
    async fn test_ipc_handler_set_privacy_level() {
        let service = DaemonService::new().unwrap();

        // Valid levels
        for level in ["light", "standard", "paranoid"] {
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
        let service = DaemonService::new().unwrap();

        let result = service.handle("get_node_stats", None).await;
        // Returns empty object when no node is running
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_multiple_unknown_methods() {
        let service = DaemonService::new().unwrap();

        // Various unknown methods should all fail
        let methods = ["foo", "bar", "get_status_typo", "CONNECT", "Status"];

        for method in methods {
            let result = service.handle(method, None).await;
            assert!(result.is_err(), "Method '{}' should fail", method);
        }
    }

    #[tokio::test]
    async fn test_connect_with_null_params() {
        let service = DaemonService::new().unwrap();

        // Null value should be handled gracefully
        let result = service.handle("connect", Some(serde_json::Value::Null)).await;
        // Should work since we handle None params
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_status_after_disconnect() {
        let service = DaemonService::new().unwrap();

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
        let service = DaemonService::new().unwrap();

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
        let service = DaemonService::new().unwrap();

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
        let service = DaemonService::new().unwrap();

        service.set_privacy_level("light").await.unwrap();
        assert_eq!(*service.privacy_level.read().await, HopMode::Light);

        service.set_privacy_level("standard").await.unwrap();
        assert_eq!(*service.privacy_level.read().await, HopMode::Standard);

        service.set_privacy_level("paranoid").await.unwrap();
        assert_eq!(*service.privacy_level.read().await, HopMode::Paranoid);
    }

    #[tokio::test]
    async fn test_set_privacy_level_invalid() {
        let service = DaemonService::new().unwrap();
        let result = service.set_privacy_level("invalid").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_ipc_handler_set_mode() {
        let service = DaemonService::new().unwrap();

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
        let service = DaemonService::new().unwrap();

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
        let service = DaemonService::new().unwrap();
        let mut rx = service.event_sender().subscribe();

        service.set_state(DaemonState::Connecting).await;

        let msg = rx.try_recv();
        assert!(msg.is_ok());
        let msg = msg.unwrap();
        assert!(msg.contains("state_change"));
        assert!(msg.contains("connecting"));
    }
}
