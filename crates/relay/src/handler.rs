//! Relay shard handler
//!
//! Handles incoming shards, performs destination verification, signs, and forwards.
//!
//! ## Security Critical
//!
//! The `handle_response` method MUST verify that the response destination matches
//! the cached user_pubkey from the original request. This prevents exit nodes
//! from redirecting responses to colluding parties.

use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info, warn};
use tunnelcraft_core::{Id, PublicKey, Shard, ShardType, TunnelCraftError};
use tunnelcraft_crypto::{sign_shard, SigningKeypair};
use tunnelcraft_settlement::{SettlementClient, SettleResponseShard};

use crate::cache::RequestCache;

#[derive(Error, Debug)]
pub enum RelayError {
    /// Response destination does not match cached request origin
    ///
    /// SECURITY CRITICAL: This error indicates a potential attack where an exit node
    /// is trying to redirect a response to a different destination than the original user.
    #[error("Destination mismatch: response destination does not match request origin")]
    DestinationMismatch {
        expected: PublicKey,
        actual: PublicKey,
    },

    /// Request not found in cache (may have expired)
    #[error("Request not found in cache: {0:?}")]
    RequestNotFound(Id),

    /// Shard has no remaining hops
    #[error("No hops remaining")]
    NoHopsRemaining,

    /// Chain signature verification failed
    #[error("Chain verification failed: {0}")]
    ChainVerificationFailed(#[from] TunnelCraftError),

    /// Internal relay error
    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, RelayError>;

/// Relay configuration
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Whether to verify chain signatures on incoming shards
    pub verify_signatures: bool,
    /// Whether this relay can act as the last hop (submits to settlement)
    pub can_be_last_hop: bool,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            verify_signatures: true,
            can_be_last_hop: true,
        }
    }
}

/// Relay handler for processing shards
pub struct RelayHandler {
    /// This relay's signing keypair
    keypair: SigningKeypair,
    /// Cache of request_id → user_pubkey for destination verification
    cache: RequestCache,
    /// Relay configuration
    config: RelayConfig,
    /// Settlement client (optional - for mock/live settlement)
    settlement_client: Option<Arc<SettlementClient>>,
}

impl RelayHandler {
    /// Create a new relay handler with a signing keypair
    pub fn new(keypair: SigningKeypair) -> Self {
        Self {
            keypair,
            cache: RequestCache::new(),
            config: RelayConfig::default(),
            settlement_client: None,
        }
    }

    /// Create a relay handler with custom config
    pub fn with_config(keypair: SigningKeypair, config: RelayConfig) -> Self {
        Self {
            keypair,
            cache: RequestCache::new(),
            config,
            settlement_client: None,
        }
    }

    /// Create a relay handler with settlement client
    pub fn with_settlement(
        keypair: SigningKeypair,
        config: RelayConfig,
        settlement_client: Arc<SettlementClient>,
    ) -> Self {
        Self {
            keypair,
            cache: RequestCache::new(),
            config,
            settlement_client: Some(settlement_client),
        }
    }

    /// Set the settlement client
    pub fn set_settlement_client(&mut self, client: Arc<SettlementClient>) {
        self.settlement_client = Some(client);
    }

    /// Get this relay's public key
    pub fn pubkey(&self) -> PublicKey {
        self.keypair.public_key_bytes()
    }

    /// Handle an incoming shard
    ///
    /// Returns the processed shard ready to forward, or None if this is the final hop.
    pub fn handle_shard(&mut self, shard: Shard) -> Result<Option<Shard>> {
        match shard.shard_type {
            ShardType::Request => self.handle_request(shard),
            ShardType::Response => self.handle_response(shard),
        }
    }

    /// Handle an incoming shard (async version for settlement)
    ///
    /// Returns the processed shard ready to forward, or None if this is the final hop.
    /// Also handles settlement submission for last-hop responses.
    /// Network-level TCP ACK proves delivery - no explicit user acknowledgment needed.
    pub async fn handle_shard_async(&mut self, shard: Shard) -> Result<Option<Shard>> {
        match shard.shard_type {
            ShardType::Request => self.handle_request(shard),
            ShardType::Response => self.handle_response_async(shard).await,
        }
    }

    /// Handle an incoming request shard
    ///
    /// 1. Cache the request_id → user_pubkey mapping
    /// 2. Sign the shard
    /// 3. Decrement hops and forward (or deliver to exit if last hop)
    fn handle_request(&mut self, mut shard: Shard) -> Result<Option<Shard>> {
        // Cache the mapping for later response verification
        self.cache.insert(shard.request_id, shard.user_pubkey);

        // Sign the shard
        sign_shard(&self.keypair, &mut shard);

        // Decrement hops
        let is_last_hop = shard.decrement_hops();

        if is_last_hop {
            // This shard should go to the exit node (destination)
            // Return it for delivery to exit
            Ok(Some(shard))
        } else {
            // Forward to next relay
            Ok(Some(shard))
        }
    }

    /// Handle an incoming response shard
    ///
    /// Response shards take independent random paths back to the client,
    /// so this relay may or may not have seen the original request.
    /// If we have a cached entry, verify destination matches (security check).
    /// If not, still forward — random routing means we won't always be on the request path.
    fn handle_response(&mut self, mut shard: Shard) -> Result<Option<Shard>> {
        // If we saw the original request, verify destination matches
        if let Some(expected_user) = self.cache.get(&shard.request_id) {
            if shard.destination != expected_user {
                // ATTACK DETECTED: Exit node is trying to redirect response
                // to a different destination than the original requester.
                return Err(RelayError::DestinationMismatch {
                    expected: expected_user,
                    actual: shard.destination,
                });
            }
        }
        // If not in cache, still forward (response takes independent random path)

        // Sign the shard
        sign_shard(&self.keypair, &mut shard);

        // Decrement hops
        shard.decrement_hops();

        Ok(Some(shard))
    }

    /// Handle an incoming response shard (async version with settlement)
    ///
    /// Response shards take independent random paths. If we have a cached
    /// entry from the original request, verify destination. Otherwise forward.
    ///
    /// Network-level TCP ACK proves delivery - no explicit user acknowledgment needed.
    async fn handle_response_async(
        &mut self,
        mut shard: Shard,
    ) -> Result<Option<Shard>> {
        // If we saw the original request, verify destination matches
        if let Some(expected_user) = self.cache.get(&shard.request_id) {
            if shard.destination != expected_user {
                return Err(RelayError::DestinationMismatch {
                    expected: expected_user,
                    actual: shard.destination,
                });
            }
        }

        // Sign the shard
        sign_shard(&self.keypair, &mut shard);

        // Decrement hops
        let is_last_hop = shard.decrement_hops();

        if is_last_hop {
            // Submit response shard settlement if configured
            self.submit_response_shard_settlement(&shard).await;
            Ok(Some(shard))
        } else {
            Ok(Some(shard))
        }
    }

    /// Submit response shard settlement to the chain
    ///
    /// Network-level TCP ACK proves delivery; the response_chain proves work done.
    async fn submit_response_shard_settlement(&self, shard: &Shard) {
        let Some(client) = &self.settlement_client else {
            debug!("No settlement client configured, skipping settlement");
            return;
        };

        let settlement = SettleResponseShard {
            request_id: shard.request_id,
            shard_id: shard.shard_id,
            response_chain: shard.chain.clone(),
        };

        match client.settle_response_shard(settlement).await {
            Ok(sig) => {
                info!(
                    "Response shard {} settled for request {} (tx: {})",
                    hex::encode(&shard.shard_id[..8]),
                    hex::encode(&shard.request_id[..8]),
                    hex::encode(&sig[..8])
                );
            }
            Err(e) => {
                warn!(
                    "Failed to settle response shard {} for request {}: {}",
                    hex::encode(&shard.shard_id[..8]),
                    hex::encode(&shard.request_id[..8]),
                    e
                );
            }
        }
    }

    /// Get cache statistics
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }

    /// Clear expired cache entries
    pub fn evict_expired(&mut self) {
        self.cache.evict_expired();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnelcraft_core::CreditProof;
    use tunnelcraft_crypto::SigningKeypair;

    fn test_credit_proof(user_pubkey: [u8; 32]) -> CreditProof {
        CreditProof {
            user_pubkey,
            balance: 1000,
            epoch: 1,
            chain_signature: [0u8; 64],
        }
    }

    fn create_test_shard(shard_type: ShardType, hops: u8) -> Shard {
        let user_keypair = SigningKeypair::generate();
        let exit_keypair = SigningKeypair::generate();
        let user_pubkey = user_keypair.public_key_bytes();

        match shard_type {
            ShardType::Request => Shard::new_request(
                [1u8; 32],                       // shard_id
                [2u8; 32],                       // request_id
                [3u8; 32],                       // credit_hash
                user_pubkey,                     // user_pubkey
                exit_keypair.public_key_bytes(), // destination (exit)
                hops,
                vec![1, 2, 3, 4],           // payload
                0,                          // shard_index
                5,                          // total_shards
                test_credit_proof(user_pubkey), // credit_proof
            ),
            ShardType::Response => {
                let exit_entry = tunnelcraft_core::ChainEntry::new(
                    exit_keypair.public_key_bytes(),
                    [0u8; 64],
                    hops,
                );
                Shard::new_response(
                    [1u8; 32],                       // shard_id
                    [2u8; 32],                       // request_id
                    [3u8; 32],                       // credit_hash
                    user_keypair.public_key_bytes(), // user_pubkey (also destination)
                    exit_entry,
                    hops,
                    vec![5, 6, 7, 8], // payload
                    0,                // shard_index
                    5,                // total_shards
                )
            }
        }
    }

    #[test]
    fn test_handle_request_caches_user() {
        let keypair = SigningKeypair::generate();
        let mut handler = RelayHandler::new(keypair);

        let shard = create_test_shard(ShardType::Request, 2);
        let request_id = shard.request_id;
        let user_pubkey = shard.user_pubkey;

        let result = handler.handle_shard(shard).unwrap();
        assert!(result.is_some());

        // Verify the mapping was cached
        assert_eq!(handler.cache.get(&request_id), Some(user_pubkey));
    }

    #[test]
    fn test_handle_request_signs_shard() {
        let keypair = SigningKeypair::generate();
        let relay_pubkey = keypair.public_key_bytes();
        let mut handler = RelayHandler::new(keypair);

        let shard = create_test_shard(ShardType::Request, 2);
        let initial_chain_len = shard.chain.len();

        let result = handler.handle_shard(shard).unwrap().unwrap();

        // Chain should have one more entry
        assert_eq!(result.chain.len(), initial_chain_len + 1);
        // Last entry should be from this relay
        assert_eq!(result.chain.last().unwrap().pubkey, relay_pubkey);
    }

    #[test]
    fn test_handle_response_valid_destination() {
        let keypair = SigningKeypair::generate();
        let mut handler = RelayHandler::new(keypair);

        // First, handle a request to cache the mapping
        let request_shard = create_test_shard(ShardType::Request, 2);
        let request_id = request_shard.request_id;
        let user_pubkey = request_shard.user_pubkey;
        handler.handle_shard(request_shard).unwrap();

        // Now create a response with matching destination
        let exit_keypair = SigningKeypair::generate();
        let exit_entry = tunnelcraft_core::ChainEntry::new(
            exit_keypair.public_key_bytes(),
            [0u8; 64],
            2,
        );
        let response_shard = Shard::new_response(
            [10u8; 32],  // different shard_id
            request_id,  // same request_id
            [3u8; 32],   // credit_hash
            user_pubkey, // must match cached user
            exit_entry,
            2,
            vec![5, 6, 7, 8],
            0,
            5,
        );

        // Should succeed - destination matches cached user
        let result = handler.handle_shard(response_shard);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_response_destination_mismatch() {
        let keypair = SigningKeypair::generate();
        let mut handler = RelayHandler::new(keypair);

        // Handle a request to cache the mapping
        let request_shard = create_test_shard(ShardType::Request, 2);
        let request_id = request_shard.request_id;
        handler.handle_shard(request_shard).unwrap();

        // Create a response with WRONG destination (attack simulation)
        let attacker_keypair = SigningKeypair::generate();
        let exit_keypair = SigningKeypair::generate();
        let exit_entry = tunnelcraft_core::ChainEntry::new(
            exit_keypair.public_key_bytes(),
            [0u8; 64],
            2,
        );
        let malicious_response = Shard::new_response(
            [10u8; 32],
            request_id,
            [3u8; 32],
            attacker_keypair.public_key_bytes(), // WRONG user - attacker
            exit_entry,
            2,
            vec![5, 6, 7, 8],
            0,
            5,
        );

        // Should fail with DestinationMismatch
        let result = handler.handle_shard(malicious_response);
        assert!(matches!(result, Err(RelayError::DestinationMismatch { .. })));
    }

    #[test]
    fn test_handle_response_without_cached_request() {
        let keypair = SigningKeypair::generate();
        let mut handler = RelayHandler::new(keypair);

        // Response without cached request should still be forwarded
        // (response shards take independent random paths)
        let response_shard = create_test_shard(ShardType::Response, 2);

        let result = handler.handle_shard(response_shard);
        assert!(result.is_ok());
        let shard = result.unwrap().unwrap();
        assert_eq!(shard.hops_remaining, 1); // decremented
    }

    #[test]
    fn test_hops_decrement() {
        let keypair = SigningKeypair::generate();
        let mut handler = RelayHandler::new(keypair);

        let shard = create_test_shard(ShardType::Request, 3);
        let result = handler.handle_shard(shard).unwrap().unwrap();

        // Hops should be decremented
        assert_eq!(result.hops_remaining, 2);
    }

    // ==================== NEGATIVE TESTS ====================

    #[test]
    fn test_handle_response_with_unknown_request_id() {
        let keypair = SigningKeypair::generate();
        let mut handler = RelayHandler::new(keypair);

        // Cache a request with one ID
        let request_shard = create_test_shard(ShardType::Request, 2);
        handler.handle_shard(request_shard).unwrap();

        // Response with DIFFERENT request_id (not in cache) — still forwarded
        // because response shards take random paths through any relay
        let exit_keypair = SigningKeypair::generate();
        let exit_entry = tunnelcraft_core::ChainEntry::new(
            exit_keypair.public_key_bytes(),
            [0u8; 64],
            2,
        );
        let response = Shard::new_response(
            [10u8; 32],
            [99u8; 32],  // Different request_id - not in cache
            [3u8; 32],
            [1u8; 32],   // Some destination
            exit_entry,
            2,
            vec![5, 6, 7, 8],
            0,
            5,
        );

        let result = handler.handle_shard(response);
        assert!(result.is_ok()); // forwarded without cache verification
    }

    #[test]
    fn test_handle_response_after_cache_clear() {
        let keypair = SigningKeypair::generate();
        let mut handler = RelayHandler::new(keypair);

        // Handle a request
        let request_shard = create_test_shard(ShardType::Request, 2);
        let request_id = request_shard.request_id;
        let user_pubkey = request_shard.user_pubkey;
        handler.handle_shard(request_shard).unwrap();

        // Clear the cache (simulating expiration)
        handler.cache.clear();

        // Response should still be forwarded (cache miss = no verification, but still forward)
        let exit_keypair = SigningKeypair::generate();
        let exit_entry = tunnelcraft_core::ChainEntry::new(
            exit_keypair.public_key_bytes(),
            [0u8; 64],
            2,
        );
        let response_shard = Shard::new_response(
            [10u8; 32],
            request_id,
            [3u8; 32],
            user_pubkey,
            exit_entry,
            2,
            vec![5, 6, 7, 8],
            0,
            5,
        );

        let result = handler.handle_shard(response_shard);
        assert!(result.is_ok());
    }

    #[test]
    fn test_last_hop_response_forwarded() {
        let keypair = SigningKeypair::generate();
        let mut handler = RelayHandler::new(keypair);

        // Handle a request first
        let request_shard = create_test_shard(ShardType::Request, 2);
        let request_id = request_shard.request_id;
        let user_pubkey = request_shard.user_pubkey;
        handler.handle_shard(request_shard).unwrap();

        // Create response with hops=1 so after decrement it's the last hop
        let exit_keypair = SigningKeypair::generate();
        let exit_entry = tunnelcraft_core::ChainEntry::new(
            exit_keypair.public_key_bytes(),
            [0u8; 64],
            1,
        );
        let response_shard = Shard::new_response(
            [10u8; 32],
            request_id,
            [3u8; 32],
            user_pubkey,
            exit_entry,
            1,  // Will be 0 after decrement = last hop
            vec![5, 6, 7, 8],
            0,
            5,
        );

        let result = handler.handle_shard(response_shard);
        assert!(result.is_ok());
        let shard = result.unwrap().unwrap();
        assert_eq!(shard.hops_remaining, 0); // decremented to 0
    }

    #[test]
    fn test_multiple_responses_for_same_request() {
        let keypair = SigningKeypair::generate();
        let mut handler = RelayHandler::new(keypair);

        // Handle a request
        let request_shard = create_test_shard(ShardType::Request, 2);
        let request_id = request_shard.request_id;
        let user_pubkey = request_shard.user_pubkey;
        handler.handle_shard(request_shard).unwrap();

        // Handle first response successfully
        let exit_keypair = SigningKeypair::generate();
        let exit_entry = tunnelcraft_core::ChainEntry::new(
            exit_keypair.public_key_bytes(),
            [0u8; 64],
            2,
        );
        let response1 = Shard::new_response(
            [10u8; 32],
            request_id,
            [3u8; 32],
            user_pubkey,
            exit_entry.clone(),
            2,
            vec![5, 6, 7, 8],
            0,  // shard_index 0
            5,
        );

        let result1 = handler.handle_shard(response1);
        assert!(result1.is_ok());

        // Second response for same request should also work (multiple shards)
        let response2 = Shard::new_response(
            [11u8; 32],  // different shard_id
            request_id,
            [3u8; 32],
            user_pubkey,
            exit_entry,
            2,
            vec![9, 10, 11, 12],
            1,  // shard_index 1
            5,
        );

        let result2 = handler.handle_shard(response2);
        assert!(result2.is_ok());
    }

    #[test]
    fn test_response_shard_hops_decrement() {
        let keypair = SigningKeypair::generate();
        let mut handler = RelayHandler::new(keypair);

        // Response shard without cached request — still forwarded
        let exit_keypair = SigningKeypair::generate();
        let exit_entry = tunnelcraft_core::ChainEntry::new(
            exit_keypair.public_key_bytes(),
            [0u8; 64],
            3,
        );
        let response = Shard::new_response(
            [10u8; 32],
            [42u8; 32],
            [3u8; 32],
            [1u8; 32],
            exit_entry,
            3,
            vec![5, 6, 7, 8],
            0,
            5,
        );

        let result = handler.handle_shard(response);
        assert!(result.is_ok());
        let shard = result.unwrap().unwrap();
        assert_eq!(shard.hops_remaining, 2); // decremented from 3 to 2
    }

    #[test]
    fn test_destination_mismatch_preserves_error_details() {
        let keypair = SigningKeypair::generate();
        let mut handler = RelayHandler::new(keypair);

        // Handle a request
        let request_shard = create_test_shard(ShardType::Request, 2);
        let request_id = request_shard.request_id;
        let original_user = request_shard.user_pubkey;
        handler.handle_shard(request_shard).unwrap();

        // Create response with wrong destination
        let attacker_pubkey = [0xFFu8; 32];
        let exit_keypair = SigningKeypair::generate();
        let exit_entry = tunnelcraft_core::ChainEntry::new(
            exit_keypair.public_key_bytes(),
            [0u8; 64],
            2,
        );
        let malicious_response = Shard::new_response(
            [10u8; 32],
            request_id,
            [3u8; 32],
            attacker_pubkey,  // Wrong destination
            exit_entry,
            2,
            vec![5, 6, 7, 8],
            0,
            5,
        );

        let result = handler.handle_shard(malicious_response);

        // Verify error contains the correct pubkeys
        match result {
            Err(RelayError::DestinationMismatch { expected, actual }) => {
                assert_eq!(expected, original_user);
                assert_eq!(actual, attacker_pubkey);
            }
            _ => panic!("Expected DestinationMismatch error"),
        }
    }

    #[test]
    fn test_cache_size_after_operations() {
        let keypair = SigningKeypair::generate();
        let mut handler = RelayHandler::new(keypair);

        assert_eq!(handler.cache_size(), 0);

        // Add multiple requests
        for i in 0..5 {
            let mut shard = create_test_shard(ShardType::Request, 2);
            shard.request_id = [i as u8; 32];  // Unique request_id
            handler.handle_shard(shard).unwrap();
        }

        assert_eq!(handler.cache_size(), 5);
    }
}
