//! VPN session management

use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, info};

use tunnelcraft_core::{CreditProof, Shard, Id, PublicKey, HopMode, ExitInfo, ShardType};
use tunnelcraft_erasure::{ErasureCoder, DATA_SHARDS, TOTAL_SHARDS};

use crate::{ClientError, Result, RequestBuilder};

/// Client configuration
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Hop mode (privacy level)
    pub hop_mode: HopMode,
    /// Request timeout
    pub timeout: Duration,
    /// Maximum concurrent requests
    pub max_concurrent: usize,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            hop_mode: HopMode::Standard,
            timeout: Duration::from_secs(30),
            max_concurrent: 10,
        }
    }
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not connected to network
    Disconnected,
    /// Connecting to network
    Connecting,
    /// Connected and ready
    Connected,
    /// Connection error
    Error,
}

/// Pending request awaiting response shards
struct PendingResponse {
    /// Collected response shards
    shards: HashMap<u8, Shard>,
}

/// TunnelCraft VPN client
#[deprecated(note = "Use TunnelCraftNode instead")]
pub struct TunnelCraftClient {
    config: ClientConfig,
    state: ConnectionState,
    /// Our keypair (Ed25519 public key)
    user_pubkey: PublicKey,
    /// Available credits
    credits: u64,
    /// Credit proof for current epoch
    credit_proof: Option<CreditProof>,
    /// Selected exit node
    exit_node: Option<ExitInfo>,
    /// Erasure coder
    erasure: ErasureCoder,
    /// Pending responses
    pending: HashMap<Id, PendingResponse>,
}

#[allow(deprecated)]
impl TunnelCraftClient {
    /// Create a new client
    pub fn new(config: ClientConfig, user_pubkey: PublicKey) -> Result<Self> {
        let erasure = ErasureCoder::new()
            .map_err(|e| ClientError::ErasureError(e.to_string()))?;

        Ok(Self {
            config,
            state: ConnectionState::Disconnected,
            user_pubkey,
            credits: 0,
            credit_proof: None,
            exit_node: None,
            erasure,
            pending: HashMap::new(),
        })
    }

    /// Get current connection state
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Get available credits
    pub fn credits(&self) -> u64 {
        self.credits
    }

    /// Set credits (would normally come from on-chain query)
    pub fn set_credits(&mut self, credits: u64) {
        self.credits = credits;
    }

    /// Set credit proof for this epoch
    ///
    /// The credit proof is a chain-signed proof of the user's credit balance.
    /// It is submitted with each request so exit nodes can verify the user
    /// has sufficient credits.
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
        self.state = ConnectionState::Connecting;

        // TODO: Actually connect to libp2p network
        // 1. Start listening
        // 2. Bootstrap Kademlia DHT
        // 3. Find exit nodes
        // 4. Select best exit node

        // For now, simulate connection
        self.state = ConnectionState::Connected;
        info!("Connected to network");

        Ok(())
    }

    /// Disconnect from the network
    pub async fn disconnect(&mut self) {
        info!("Disconnecting from network");
        self.state = ConnectionState::Disconnected;
        self.exit_node = None;
        self.pending.clear();
    }

    /// Set the exit node to use
    pub fn set_exit_node(&mut self, exit: ExitInfo) {
        debug!("Selected exit node: {:?}", exit.address);
        self.exit_node = Some(exit);
    }

    /// Create a new request builder
    pub fn request(&self, method: &str, url: &str) -> RequestBuilder {
        RequestBuilder::new(method, url).hop_mode(self.config.hop_mode)
    }

    /// Send a request and get response shards
    ///
    /// This creates shards and would send them through the network.
    /// Returns the request ID for tracking.
    pub async fn send_request(&mut self, builder: RequestBuilder) -> Result<Id> {
        if self.state != ConnectionState::Connected {
            return Err(ClientError::NotConnected);
        }

        let exit = self.exit_node.as_ref()
            .ok_or(ClientError::NoExitNodes)?;

        // Check credits (estimate cost)
        let cost = 1u64; // Simplified: 1 credit per request
        if self.credits < cost {
            return Err(ClientError::InsufficientCredits {
                have: self.credits,
                need: cost,
            });
        }

        // Get credit proof (required for requests)
        let credit_proof = self.credit_proof.clone()
            .ok_or(ClientError::InsufficientCredits { have: 0, need: 1 })?;

        // Build shards
        let shards = builder.build(self.user_pubkey, exit.pubkey, credit_proof)?;
        let request_id = shards[0].request_id;

        debug!("Created {} shards for request", shards.len());

        // Store pending response
        self.pending.insert(request_id, PendingResponse {
            shards: HashMap::new(),
        });

        // TODO: Actually send shards through network
        // Each shard would go to a different relay

        // Deduct credits
        self.credits = self.credits.saturating_sub(cost);

        Ok(request_id)
    }

    /// Process an incoming response shard
    ///
    /// Returns the reconstructed response body if complete
    pub fn receive_shard(&mut self, shard: Shard) -> Result<Option<Vec<u8>>> {
        // Only process response shards
        if shard.shard_type != ShardType::Response {
            return Ok(None);
        }

        let request_id = shard.request_id;
        let shard_index = shard.shard_index;

        // Find pending request
        let pending = self.pending.get_mut(&request_id)
            .ok_or_else(|| ClientError::RequestFailed("Unknown request".to_string()))?;

        // Add shard
        pending.shards.insert(shard_index, shard);

        debug!("Received shard {}/{} for request", pending.shards.len(), DATA_SHARDS);

        // Check if we have enough shards
        if pending.shards.len() >= DATA_SHARDS {
            // Remove from pending
            if let Some(pending) = self.pending.remove(&request_id) {
                // Reconstruct response
                let response = self.reconstruct_response(&pending)?;

                Ok(Some(response))
            } else {
                debug!("Request already completed");
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Reconstruct response from shards
    fn reconstruct_response(&self, pending: &PendingResponse) -> Result<Vec<u8>> {
        let mut shard_data: Vec<Option<Vec<u8>>> = vec![None; TOTAL_SHARDS];
        let mut shard_size = 0usize;

        for (index, shard) in &pending.shards {
            let idx = *index as usize;
            if idx < TOTAL_SHARDS {
                shard_size = shard.payload.len();
                shard_data[idx] = Some(shard.payload.clone());
            }
        }

        // Use max possible length - the serialization format (HttpResponse) handles its own length
        let max_len = shard_size * DATA_SHARDS;

        self.erasure.decode(&mut shard_data, max_len)
            .map_err(|e| ClientError::ErasureError(e.to_string()))
    }

    /// Get number of pending requests
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Cancel a pending request
    pub fn cancel_request(&mut self, request_id: &Id) -> bool {
        self.pending.remove(request_id).is_some()
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use tunnelcraft_core::ExitRegion;

    /// Create a test credit proof
    fn test_credit_proof(user_pubkey: [u8; 32]) -> CreditProof {
        CreditProof {
            user_pubkey,
            balance: 1000,
            epoch: 1,
            chain_signature: [0u8; 64],
        }
    }

    #[test]
    fn test_default_config() {
        let config = ClientConfig::default();
        assert_eq!(config.hop_mode, HopMode::Standard);
        assert_eq!(config.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_client_creation() {
        let client = TunnelCraftClient::new(ClientConfig::default(), [0u8; 32]).unwrap();
        assert_eq!(client.state(), ConnectionState::Disconnected);
        assert_eq!(client.credits(), 0);
    }

    #[tokio::test]
    async fn test_connect() {
        let mut client = TunnelCraftClient::new(ClientConfig::default(), [0u8; 32]).unwrap();
        client.connect().await.unwrap();
        assert_eq!(client.state(), ConnectionState::Connected);
    }

    #[tokio::test]
    async fn test_disconnect() {
        let mut client = TunnelCraftClient::new(ClientConfig::default(), [0u8; 32]).unwrap();
        client.connect().await.unwrap();
        client.disconnect().await;
        assert_eq!(client.state(), ConnectionState::Disconnected);
    }

    #[tokio::test]
    async fn test_send_requires_connection() {
        let mut client = TunnelCraftClient::new(ClientConfig::default(), [0u8; 32]).unwrap();
        let builder = client.request("GET", "https://example.com");

        let result = client.send_request(builder).await;
        assert!(matches!(result, Err(ClientError::NotConnected)));
    }

    #[tokio::test]
    async fn test_send_requires_exit() {
        let mut client = TunnelCraftClient::new(ClientConfig::default(), [0u8; 32]).unwrap();
        client.connect().await.unwrap();
        client.set_credits(100);

        let builder = client.request("GET", "https://example.com");
        let result = client.send_request(builder).await;

        assert!(matches!(result, Err(ClientError::NoExitNodes)));
    }

    #[tokio::test]
    async fn test_send_requires_credits() {
        let mut client = TunnelCraftClient::new(ClientConfig::default(), [0u8; 32]).unwrap();
        client.connect().await.unwrap();
        client.set_exit_node(ExitInfo {
            pubkey: [1u8; 32],
            address: "127.0.0.1:9000".to_string(),
            region: ExitRegion::Auto,
            country_code: None,
            city: None,
            reputation: 100,
            latency_ms: 50,
        });

        let builder = client.request("GET", "https://example.com");
        let result = client.send_request(builder).await;

        assert!(matches!(result, Err(ClientError::InsufficientCredits { .. })));
    }

    #[tokio::test]
    async fn test_successful_request() {
        let user_pubkey = [0u8; 32];
        let mut client = TunnelCraftClient::new(ClientConfig::default(), user_pubkey).unwrap();
        client.connect().await.unwrap();
        client.set_credits(100);
        client.set_credit_proof(test_credit_proof(user_pubkey));
        client.set_exit_node(ExitInfo {
            pubkey: [1u8; 32],
            address: "127.0.0.1:9000".to_string(),
            region: ExitRegion::Auto,
            country_code: None,
            city: None,
            reputation: 100,
            latency_ms: 50,
        });

        let builder = client.request("GET", "https://example.com");
        let request_id = client.send_request(builder).await.unwrap();

        assert_eq!(client.pending_count(), 1);
        assert_eq!(client.credits(), 99);

        // Cancel request
        assert!(client.cancel_request(&request_id));
        assert_eq!(client.pending_count(), 0);
    }

    // ==================== NEGATIVE TESTS ====================

    #[test]
    fn test_cancel_nonexistent_request() {
        let mut client = TunnelCraftClient::new(ClientConfig::default(), [0u8; 32]).unwrap();
        let fake_request_id: Id = [42u8; 32];

        // Should return false when request doesn't exist
        assert!(!client.cancel_request(&fake_request_id));
    }

    #[tokio::test]
    async fn test_disconnect_when_not_connected() {
        let mut client = TunnelCraftClient::new(ClientConfig::default(), [0u8; 32]).unwrap();
        assert_eq!(client.state(), ConnectionState::Disconnected);

        // Disconnecting when already disconnected should be fine
        client.disconnect().await;
        assert_eq!(client.state(), ConnectionState::Disconnected);
    }

    #[tokio::test]
    async fn test_multiple_connects() {
        let mut client = TunnelCraftClient::new(ClientConfig::default(), [0u8; 32]).unwrap();

        // Connect multiple times
        client.connect().await.unwrap();
        assert_eq!(client.state(), ConnectionState::Connected);

        // Second connect should still work (re-connect scenario)
        client.connect().await.unwrap();
        assert_eq!(client.state(), ConnectionState::Connected);
    }

    #[test]
    fn test_receive_request_shard_ignored() {
        let mut client = TunnelCraftClient::new(ClientConfig::default(), [0u8; 32]).unwrap();

        // Create a request shard (not response)
        let credit_proof = test_credit_proof([4u8; 32]);
        let shard = Shard::new_request(
            [1u8; 32],  // shard_id
            [2u8; 32],  // request_id
            [3u8; 32],  // credit_hash
            [4u8; 32],  // user_pubkey
            [5u8; 32],  // destination
            3,          // hops
            vec![0u8; 100],  // payload
            0,          // shard_index
            5,          // total_shards
            credit_proof,
        );

        // Request shards should be ignored (returns Ok(None))
        let result = client.receive_shard(shard);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_receive_shard_unknown_request() {
        let mut client = TunnelCraftClient::new(ClientConfig::default(), [0u8; 32]).unwrap();

        // Create a response shard for unknown request
        let shard = Shard::new_response(
            [1u8; 32],  // shard_id
            [99u8; 32], // request_id (unknown)
            [3u8; 32],  // credit_hash
            [4u8; 32],  // user_pubkey
            tunnelcraft_core::ChainEntry::new([5u8; 32], [0u8; 64], 3),
            3,          // hops
            vec![0u8; 100],  // payload
            0,          // shard_index
            5,          // total_shards
        );

        // Should fail with unknown request error
        let result = client.receive_shard(shard);
        assert!(matches!(result, Err(ClientError::RequestFailed(_))));
    }

    #[tokio::test]
    async fn test_send_with_exact_credits() {
        let user_pubkey = [0u8; 32];
        let mut client = TunnelCraftClient::new(ClientConfig::default(), user_pubkey).unwrap();
        client.connect().await.unwrap();
        client.set_credits(1);  // Exactly enough for one request
        client.set_credit_proof(test_credit_proof(user_pubkey));
        client.set_exit_node(ExitInfo {
            pubkey: [1u8; 32],
            address: "127.0.0.1:9000".to_string(),
            region: ExitRegion::Auto,
            country_code: None,
            city: None,
            reputation: 100,
            latency_ms: 50,
        });

        let builder = client.request("GET", "https://example.com");
        let _request_id = client.send_request(builder).await.unwrap();

        assert_eq!(client.credits(), 0);

        // Second request should fail - no credits left
        let builder2 = client.request("GET", "https://example.com/2");
        let result = client.send_request(builder2).await;
        assert!(matches!(result, Err(ClientError::InsufficientCredits { have: 0, need: 1 })));
    }

    #[tokio::test]
    async fn test_disconnect_clears_pending() {
        let user_pubkey = [0u8; 32];
        let mut client = TunnelCraftClient::new(ClientConfig::default(), user_pubkey).unwrap();
        client.connect().await.unwrap();
        client.set_credits(100);
        client.set_credit_proof(test_credit_proof(user_pubkey));
        client.set_exit_node(ExitInfo {
            pubkey: [1u8; 32],
            address: "127.0.0.1:9000".to_string(),
            region: ExitRegion::Auto,
            country_code: None,
            city: None,
            reputation: 100,
            latency_ms: 50,
        });

        // Send a request
        let builder = client.request("GET", "https://example.com");
        let _request_id = client.send_request(builder).await.unwrap();
        assert_eq!(client.pending_count(), 1);

        // Disconnect should clear pending
        client.disconnect().await;
        assert_eq!(client.pending_count(), 0);
        assert!(client.exit_node.is_none());
    }

    #[tokio::test]
    async fn test_disconnect_clears_exit_node() {
        let mut client = TunnelCraftClient::new(ClientConfig::default(), [0u8; 32]).unwrap();
        client.connect().await.unwrap();
        client.set_exit_node(ExitInfo {
            pubkey: [1u8; 32],
            address: "127.0.0.1:9000".to_string(),
            region: ExitRegion::Auto,
            country_code: None,
            city: None,
            reputation: 100,
            latency_ms: 50,
        });

        assert!(client.exit_node.is_some());

        client.disconnect().await;
        assert!(client.exit_node.is_none());
    }

    #[test]
    fn test_set_credits_overflow() {
        let mut client = TunnelCraftClient::new(ClientConfig::default(), [0u8; 32]).unwrap();

        client.set_credits(u64::MAX);
        assert_eq!(client.credits(), u64::MAX);
    }

    #[test]
    fn test_custom_config() {
        let config = ClientConfig {
            hop_mode: HopMode::Paranoid,
            timeout: Duration::from_secs(60),
            max_concurrent: 50,
        };

        assert_eq!(config.hop_mode, HopMode::Paranoid);
        assert_eq!(config.timeout, Duration::from_secs(60));
        assert_eq!(config.max_concurrent, 50);
    }

    #[test]
    fn test_connection_state_transitions() {
        // Test all state values exist and are distinguishable
        assert_ne!(ConnectionState::Disconnected, ConnectionState::Connecting);
        assert_ne!(ConnectionState::Connecting, ConnectionState::Connected);
        assert_ne!(ConnectionState::Connected, ConnectionState::Error);
        assert_ne!(ConnectionState::Error, ConnectionState::Disconnected);
    }
}
