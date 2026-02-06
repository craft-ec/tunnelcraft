//! TunnelCraft SDK - High-level API for CLI and applications
//!
//! This module provides a simple interface for connecting to the TunnelCraft
//! network and making requests through the VPN tunnel.

use std::collections::HashMap;
use std::time::Duration;

use futures::StreamExt;
use libp2p::identity::Keypair;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use tunnelcraft_core::{CreditProof, ExitInfo, HopMode, Id, Shard, ShardType};
use tunnelcraft_crypto::SigningKeypair;
use tunnelcraft_erasure::{ErasureCoder, DATA_SHARDS, TOTAL_SHARDS};
use tunnelcraft_network::{
    NetworkConfig, NetworkEvent, NetworkNode, ShardRequest, ShardResponse,
    TunnelCraftBehaviourEvent,
};

use crate::{ClientError, RawPacketBuilder, RequestBuilder, Result, parse_raw_packet};

/// SDK configuration
#[derive(Debug, Clone)]
pub struct SDKConfig {
    /// Listen address for the local node
    pub listen_addr: Multiaddr,
    /// Bootstrap peers to connect to
    pub bootstrap_peers: Vec<(PeerId, Multiaddr)>,
    /// Hop mode (privacy level)
    pub hop_mode: HopMode,
    /// Request timeout
    pub request_timeout: Duration,
    /// Path to keypair file (optional)
    pub keypair_path: Option<String>,
}

impl Default for SDKConfig {
    fn default() -> Self {
        Self {
            listen_addr: "/ip4/0.0.0.0/tcp/0".parse().unwrap(),
            bootstrap_peers: Vec::new(),
            hop_mode: HopMode::Standard,
            request_timeout: Duration::from_secs(30),
            keypair_path: None,
        }
    }
}

/// SDK status information
#[derive(Debug, Clone)]
pub struct SDKStatus {
    /// Our peer ID
    pub peer_id: PeerId,
    /// Connection state
    pub connected: bool,
    /// Number of connected peers
    pub peer_count: usize,
    /// Known exit nodes
    pub exit_nodes: Vec<ExitInfo>,
    /// Available credits
    pub credits: u64,
    /// Pending requests
    pub pending_requests: usize,
}

/// HTTP response from the tunnel
#[derive(Debug, Clone)]
pub struct TunnelResponse {
    /// HTTP status code
    pub status: u16,
    /// Response headers
    pub headers: HashMap<String, String>,
    /// Response body
    pub body: Vec<u8>,
}

impl TunnelResponse {
    /// Parse response from raw bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        // Parse format: status\nheader_count\nheaders...\nbody_len\nbody
        let mut lines = data.split(|&b| b == b'\n');

        let status = lines
            .next()
            .ok_or_else(|| ClientError::InvalidResponse)?;
        let status: u16 = String::from_utf8_lossy(status)
            .parse()
            .map_err(|_| ClientError::InvalidResponse)?;

        let header_count = lines
            .next()
            .ok_or_else(|| ClientError::InvalidResponse)?;
        let header_count: usize = String::from_utf8_lossy(header_count)
            .parse()
            .map_err(|_| ClientError::InvalidResponse)?;

        let mut headers = HashMap::new();
        for _ in 0..header_count {
            let header_line = lines
                .next()
                .ok_or_else(|| ClientError::InvalidResponse)?;
            let header_str = String::from_utf8_lossy(header_line);
            if let Some((key, value)) = header_str.split_once(':') {
                headers.insert(key.trim().to_string(), value.trim().to_string());
            }
        }

        let body_len = lines
            .next()
            .ok_or_else(|| ClientError::InvalidResponse)?;
        let body_len: usize = String::from_utf8_lossy(body_len)
            .parse()
            .map_err(|_| ClientError::InvalidResponse)?;

        let body: Vec<u8> = lines
            .flat_map(|line| line.iter().copied().chain(std::iter::once(b'\n')))
            .take(body_len)
            .collect();

        Ok(Self {
            status,
            headers,
            body,
        })
    }

    /// Get body as string
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }
}

/// Pending request state
struct PendingRequest {
    /// Collected response shards
    shards: HashMap<u8, Shard>,
    /// Response sender
    response_tx: mpsc::Sender<Result<TunnelResponse>>,
}

/// TunnelCraft SDK
///
/// High-level interface for connecting to the TunnelCraft network
/// and making HTTP requests through the VPN tunnel.
pub struct TunnelCraftSDK {
    /// Our signing keypair
    keypair: SigningKeypair,
    /// libp2p keypair (kept for potential reconnection)
    _libp2p_keypair: Keypair,
    /// Network node
    node: NetworkNode,
    /// Network event receiver
    _event_rx: mpsc::Receiver<NetworkEvent>,
    /// SDK configuration
    config: SDKConfig,
    /// Whether we're connected
    connected: bool,
    /// Known exit nodes
    exit_nodes: Vec<ExitInfo>,
    /// Selected exit node
    selected_exit: Option<ExitInfo>,
    /// Available credits
    credits: u64,
    /// Pending requests awaiting response
    pending: HashMap<Id, PendingRequest>,
    /// Erasure coder
    erasure: ErasureCoder,
    /// Known relay peers
    relay_peers: Vec<PeerId>,
    /// User's credit proof for the current epoch
    /// Chain-signed proof of credit balance submitted with each request
    credit_proof: Option<CreditProof>,
}

impl TunnelCraftSDK {
    /// Create a new SDK instance
    pub async fn new(config: SDKConfig) -> Result<Self> {
        // Generate keypairs
        let keypair = SigningKeypair::generate();
        let libp2p_keypair = Keypair::generate_ed25519();

        // Create network config
        let mut net_config = NetworkConfig::default();
        net_config.listen_addrs.push(config.listen_addr.clone());
        for (peer_id, addr) in &config.bootstrap_peers {
            net_config.bootstrap_peers.push((*peer_id, addr.clone()));
        }

        // Create network node
        let (node, event_rx) = NetworkNode::new(libp2p_keypair.clone(), net_config)
            .await
            .map_err(|e| ClientError::ConnectionFailed(e.to_string()))?;

        let erasure = ErasureCoder::new()
            .map_err(|e| ClientError::ErasureError(e.to_string()))?;

        Ok(Self {
            keypair,
            _libp2p_keypair: libp2p_keypair,
            node,
            _event_rx: event_rx,
            config,
            connected: false,
            exit_nodes: Vec::new(),
            selected_exit: None,
            credits: 0,
            pending: HashMap::new(),
            erasure,
            relay_peers: Vec::new(),
            credit_proof: None,
        })
    }

    /// Get our peer ID
    pub fn peer_id(&self) -> PeerId {
        self.node.local_peer_id()
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

    /// Connect to the network
    pub async fn connect(&mut self) -> Result<()> {
        info!("Connecting to TunnelCraft network...");

        // Start listening on configured address
        self.node
            .listen_on(self.config.listen_addr.clone())
            .map_err(|e| ClientError::ConnectionFailed(e.to_string()))?;

        // Connect to bootstrap peers
        for (peer_id, addr) in &self.config.bootstrap_peers.clone() {
            debug!("Connecting to bootstrap peer: {}", peer_id);
            self.node.add_peer(*peer_id, addr.clone());
            if let Err(e) = self.node.dial(*peer_id) {
                warn!("Failed to dial bootstrap peer {}: {}", peer_id, e);
            }
        }

        // Wait for connections and discovery
        let discovery_result = timeout(Duration::from_secs(10), self.discover_peers()).await;

        match discovery_result {
            Ok(Ok(())) => {
                self.connected = true;
                info!(
                    "Connected to network with {} peers",
                    self.node.num_connected()
                );
                Ok(())
            }
            Ok(Err(e)) => {
                error!("Discovery failed: {}", e);
                Err(e)
            }
            Err(_) => {
                // Timeout is OK if we have some peers
                if self.node.num_connected() > 0 {
                    self.connected = true;
                    info!(
                        "Connected to network with {} peers (discovery timeout)",
                        self.node.num_connected()
                    );
                    Ok(())
                } else {
                    Err(ClientError::ConnectionFailed(
                        "No peers found within timeout".to_string(),
                    ))
                }
            }
        }
    }

    /// Discover peers on the network
    async fn discover_peers(&mut self) -> Result<()> {
        // Poll swarm events to discover peers via mDNS or rendezvous
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);

        while tokio::time::Instant::now() < deadline {
            tokio::select! {
                event = self.node.swarm_mut().select_next_some() => {
                    self.handle_swarm_event(event).await;
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }

            // Check if we have enough peers
            if self.node.num_connected() >= 1 {
                break;
            }
        }

        Ok(())
    }

    /// Handle swarm events
    async fn handle_swarm_event(&mut self, event: SwarmEvent<TunnelCraftBehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on {}", address);
                self.node.add_external_address(address);
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                debug!("Connected to peer: {}", peer_id);
                self.relay_peers.push(peer_id);
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                debug!("Disconnected from peer: {}", peer_id);
                self.relay_peers.retain(|p| p != &peer_id);
            }
            SwarmEvent::Behaviour(behaviour_event) => {
                self.handle_behaviour_event(behaviour_event).await;
            }
            _ => {}
        }
    }

    /// Handle behaviour events
    async fn handle_behaviour_event(&mut self, event: TunnelCraftBehaviourEvent) {
        match event {
            TunnelCraftBehaviourEvent::Mdns(mdns_event) => {
                use libp2p::mdns::Event;
                match mdns_event {
                    Event::Discovered(peers) => {
                        for (peer_id, addr) in peers {
                            debug!("mDNS discovered peer {} at {}", peer_id, addr);
                            self.node.add_peer(peer_id, addr);
                            self.relay_peers.push(peer_id);
                        }
                    }
                    Event::Expired(peers) => {
                        for (peer_id, _) in peers {
                            self.relay_peers.retain(|p| p != &peer_id);
                        }
                    }
                }
            }
            TunnelCraftBehaviourEvent::Shard(shard_event) => {
                use libp2p::request_response::{Event, Message};
                if let Event::Message {
                    message: Message::Response { response, .. },
                    ..
                } = shard_event
                {
                    if let ShardResponse::Accepted = response {
                        debug!("Shard accepted by peer");
                    }
                } else if let Event::Message {
                    message: Message::Request { request, channel, .. },
                    ..
                } = shard_event
                {
                    // Handle incoming response shard
                    self.handle_response_shard(request.shard).await;
                    // Accept the shard
                    let _ = self
                        .node
                        .swarm_mut()
                        .behaviour_mut()
                        .send_shard_response(channel, ShardResponse::Accepted);
                }
            }
            _ => {}
        }
    }

    /// Handle incoming response shard
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

            // Check if we have enough shards
            if pending.shards.len() >= DATA_SHARDS {
                // Remove from pending and reconstruct
                if let Some(pending) = self.pending.remove(&request_id) {
                    let response_tx = pending.response_tx.clone();

                    match self.reconstruct_response(&pending) {
                        Ok(response) => {
                            let _ = response_tx.send(Ok(response)).await;
                        }
                        Err(e) => {
                            let _ = response_tx.send(Err(e)).await;
                        }
                    }
                } else {
                    debug!("Request {} already completed", hex::encode(&request_id[..8]));
                }
            }
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

    /// Disconnect from the network
    pub async fn disconnect(&mut self) {
        info!("Disconnecting from network");
        self.connected = false;
        self.pending.clear();
        self.relay_peers.clear();
        self.selected_exit = None;
    }

    /// Set available credits
    pub fn set_credits(&mut self, credits: u64) {
        self.credits = credits;
    }

    /// Add an exit node
    pub fn add_exit_node(&mut self, exit: ExitInfo) {
        self.exit_nodes.push(exit.clone());
        if self.selected_exit.is_none() {
            self.selected_exit = Some(exit);
        }
    }

    /// Select an exit node
    pub fn select_exit(&mut self, exit: ExitInfo) {
        self.selected_exit = Some(exit);
    }

    /// Get SDK status
    pub fn status(&self) -> SDKStatus {
        SDKStatus {
            peer_id: self.peer_id(),
            connected: self.connected,
            peer_count: self.node.num_connected(),
            exit_nodes: self.exit_nodes.clone(),
            credits: self.credits,
            pending_requests: self.pending.len(),
        }
    }

    /// Make an HTTP GET request through the tunnel
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
        if !self.connected {
            return Err(ClientError::NotConnected);
        }

        let exit = self
            .selected_exit
            .as_ref()
            .ok_or(ClientError::NoExitNodes)?;

        // Check credits
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

        debug!(
            "Created {} shards for request {}",
            shards.len(),
            hex::encode(&request_id[..8])
        );

        // Create response channel
        let (response_tx, mut response_rx) = mpsc::channel(1);

        // Store pending request
        self.pending.insert(
            request_id,
            PendingRequest {
                shards: HashMap::new(),
                response_tx,
            },
        );

        // Send shards to relays
        self.send_shards(shards).await?;

        // Deduct credits
        self.credits = self.credits.saturating_sub(1);

        // Wait for response with timeout
        let response = timeout(self.config.request_timeout, async {
            // Poll network while waiting for response
            loop {
                tokio::select! {
                    response = response_rx.recv() => {
                        return response.ok_or(ClientError::Timeout)?;
                    }
                    event = self.node.swarm_mut().select_next_some() => {
                        self.handle_swarm_event(event).await;
                    }
                }
            }
        })
        .await
        .map_err(|_| ClientError::Timeout)??;

        Ok(response)
    }

    /// Tunnel a raw IP packet through the VPN
    ///
    /// This is the core VPN function used by Network Extensions (iOS) and
    /// VpnService (Android). Takes a raw IP packet, tunnels it through
    /// the relay network to an exit node, and returns the response packet.
    pub async fn tunnel_packet(&mut self, packet: Vec<u8>) -> Result<Vec<u8>> {
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

        debug!(
            "Created {} shards for raw packet {}",
            shards.len(),
            hex::encode(&request_id[..8])
        );

        // Create response channel
        let (response_tx, mut response_rx) = mpsc::channel::<Result<TunnelResponse>>(1);

        // Store pending request
        self.pending.insert(
            request_id,
            PendingRequest {
                shards: HashMap::new(),
                response_tx,
            },
        );

        // Send shards to relays
        self.send_shards(shards).await?;

        // Deduct credits
        self.credits = self.credits.saturating_sub(1);

        // Wait for response with timeout
        let response = timeout(self.config.request_timeout, async {
            loop {
                tokio::select! {
                    response = response_rx.recv() => {
                        return response.ok_or(ClientError::Timeout)?;
                    }
                    event = self.node.swarm_mut().select_next_some() => {
                        self.handle_swarm_event(event).await;
                    }
                }
            }
        })
        .await
        .map_err(|_| ClientError::Timeout)??;

        // Parse raw packet from response body
        // Response body contains the raw packet in our protocol format
        if let Some(raw_packet) = parse_raw_packet(&response.body) {
            Ok(raw_packet)
        } else {
            // Fallback: return body as-is if not in raw packet format
            Ok(response.body)
        }
    }

    /// Send shards to relay peers
    async fn send_shards(&mut self, shards: Vec<Shard>) -> Result<()> {
        if self.relay_peers.is_empty() {
            return Err(ClientError::ConnectionFailed(
                "No relay peers available".to_string(),
            ));
        }

        // Send each shard to a different relay (or round-robin if not enough)
        for (i, shard) in shards.into_iter().enumerate() {
            let peer_idx = i % self.relay_peers.len();
            let peer_id = self.relay_peers[peer_idx];

            debug!("Sending shard {} to peer {}", i, peer_id);

            let request = ShardRequest { shard };
            self.node
                .swarm_mut()
                .behaviour_mut()
                .send_shard(peer_id, request);
        }

        Ok(())
    }

    /// Run the SDK event loop (for background processing)
    pub async fn run(&mut self) -> Result<()> {
        info!("SDK event loop started");

        loop {
            let event = self.node.swarm_mut().select_next_some().await;
            self.handle_swarm_event(event).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SDKConfig::default();
        assert_eq!(config.hop_mode, HopMode::Standard);
        assert_eq!(config.request_timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_response_parsing() {
        let data = b"200\n2\nContent-Type: text/plain\nX-Custom: value\n5\nHello";
        let response = TunnelResponse::from_bytes(data).unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.headers.len(), 2);
        assert_eq!(response.text(), "Hello");
    }

    #[test]
    fn test_response_empty_body() {
        let data = b"404\n0\n0\n";
        let response = TunnelResponse::from_bytes(data).unwrap();

        assert_eq!(response.status, 404);
        assert!(response.headers.is_empty());
        assert!(response.body.is_empty());
    }
}
