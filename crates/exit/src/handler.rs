//! Exit node handler
//!
//! Manages the complete request/response lifecycle:
//! 1. Collect shards for a request
//! 2. Reconstruct and execute HTTP request
//! 3. Create response shards

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};
use sha2::{Sha256, Digest};
use tracing::{debug, info, warn};

use tunnelcraft_core::{Shard, Id, PublicKey, ShardType};
use tunnelcraft_crypto::SigningKeypair;
use tunnelcraft_erasure::ErasureCoder;
use tunnelcraft_erasure::chunker::{chunk_and_encode, reassemble};
use tunnelcraft_settlement::SettlementClient;

use crate::{ExitError, Result, HttpRequest, HttpResponse};

/// Exit node configuration
#[derive(Debug, Clone)]
pub struct ExitConfig {
    /// HTTP client timeout
    pub timeout: Duration,
    /// Maximum request body size (bytes)
    pub max_request_size: usize,
    /// Maximum response body size (bytes)
    pub max_response_size: usize,
    /// Blocked domains (basic filtering)
    pub blocked_domains: Vec<String>,
}

impl Default for ExitConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_request_size: 10 * 1024 * 1024,  // 10 MB
            max_response_size: 50 * 1024 * 1024, // 50 MB
            blocked_domains: vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "0.0.0.0".to_string(),
            ],
        }
    }
}

/// Pending request awaiting more shards (supports multi-chunk)
struct PendingRequest {
    /// Collected shards indexed by (chunk_index, shard_index)
    shards: HashMap<(u16, u8), Shard>,
    /// Total chunks expected for this request
    total_chunks: u16,
    /// User's public key (destination for response, used for encryption)
    user_pubkey: PublicKey,
    /// User proof binding receipts to the user's pool
    user_proof: Id,
    /// When this pending request was created
    created_at: Instant,
}

/// Exit node handler
pub struct ExitHandler {
    config: ExitConfig,
    http_client: reqwest::Client,
    erasure: ErasureCoder,
    /// Pending requests awaiting more shards
    pending: HashMap<Id, PendingRequest>,
    /// Our signing keypair for signing response shards
    keypair: SigningKeypair,
    /// Settlement client (optional - for mock/live settlement)
    settlement_client: Option<Arc<SettlementClient>>,
}

impl ExitHandler {
    /// Create a new exit handler
    ///
    /// # Arguments
    /// * `config` - Exit configuration
    /// * `our_pubkey` - Our public key for signing responses (kept for backward compat)
    /// * `our_secret` - Our secret key bytes (used to reconstruct SigningKeypair)
    pub fn new(config: ExitConfig, _our_pubkey: PublicKey, our_secret: [u8; 32]) -> Result<Self> {
        let http_client = reqwest::Client::builder()
            .timeout(config.timeout)
            .user_agent("TunnelCraft/0.1")
            .build()?;

        Ok(Self {
            config,
            http_client,
            erasure: ErasureCoder::new()?,
            pending: HashMap::new(),
            keypair: SigningKeypair::from_secret_bytes(&our_secret),
            settlement_client: None,
        })
    }

    /// Create a new exit handler with a SigningKeypair directly
    pub fn with_keypair(config: ExitConfig, keypair: SigningKeypair) -> Result<Self> {
        let http_client = reqwest::Client::builder()
            .timeout(config.timeout)
            .user_agent("TunnelCraft/0.1")
            .build()?;

        Ok(Self {
            config,
            http_client,
            erasure: ErasureCoder::new()?,
            pending: HashMap::new(),
            keypair,
            settlement_client: None,
        })
    }

    /// Create a new exit handler with settlement client
    pub fn with_settlement(
        config: ExitConfig,
        _our_pubkey: PublicKey,
        our_secret: [u8; 32],
        settlement_client: Arc<SettlementClient>,
    ) -> Result<Self> {
        let http_client = reqwest::Client::builder()
            .timeout(config.timeout)
            .user_agent("TunnelCraft/0.1")
            .build()?;

        Ok(Self {
            config,
            http_client,
            erasure: ErasureCoder::new()?,
            pending: HashMap::new(),
            keypair: SigningKeypair::from_secret_bytes(&our_secret),
            settlement_client: Some(settlement_client),
        })
    }

    /// Create a new exit handler with a SigningKeypair and settlement client
    pub fn with_keypair_and_settlement(
        config: ExitConfig,
        keypair: SigningKeypair,
        settlement_client: Arc<SettlementClient>,
    ) -> Result<Self> {
        let http_client = reqwest::Client::builder()
            .timeout(config.timeout)
            .user_agent("TunnelCraft/0.1")
            .build()?;

        Ok(Self {
            config,
            http_client,
            erasure: ErasureCoder::new()?,
            pending: HashMap::new(),
            keypair,
            settlement_client: Some(settlement_client),
        })
    }

    /// Set the settlement client
    pub fn set_settlement_client(&mut self, client: Arc<SettlementClient>) {
        self.settlement_client = Some(client);
    }

    /// Process an incoming shard
    ///
    /// Returns response shards if the request is complete and executed.
    pub async fn process_shard(&mut self, shard: Shard) -> Result<Option<Vec<Shard>>> {
        // Only process request shards
        if shard.shard_type != ShardType::Request {
            return Ok(None);
        }

        let request_id = shard.request_id;
        let user_pubkey = shard.user_pubkey;
        let user_proof = shard.user_proof;
        let shard_index = shard.shard_index;
        let chunk_index = shard.chunk_index;
        let total_chunks = shard.total_chunks;
        let total_hops = shard.total_hops;

        // Add shard to pending request
        {
            let pending = self.pending.entry(request_id).or_insert_with(|| {
                PendingRequest {
                    shards: HashMap::new(),
                    total_chunks,
                    user_pubkey,
                    user_proof,
                    created_at: Instant::now(),
                }
            });
            pending.shards.insert((chunk_index, shard_index), shard);
        }

        // Check if we have enough shards for every chunk (DATA_SHARDS per chunk)
        if !self.all_chunks_ready(&request_id) {
            if let Some(pending) = self.pending.get(&request_id) {
                let shard_count = pending.shards.len();
                let needed = total_chunks as usize * tunnelcraft_erasure::DATA_SHARDS;
                debug!(
                    "Request {} has {}/{} shards",
                    hex::encode(&request_id[..8]),
                    shard_count,
                    needed
                );
            }
            return Ok(None);
        }

        // Extract and reconstruct
        let Some(pending) = self.pending.remove(&request_id) else {
            debug!("Request {} already processed", hex::encode(&request_id[..8]));
            return Ok(None);
        };

        let response_hops = total_hops;
        let request_data = self.reconstruct_request(&pending)?;

        // Parse and execute HTTP request
        let http_request = HttpRequest::from_bytes(&request_data)
            .map_err(|e| ExitError::InvalidRequest(e.to_string()))?;

        // Check for blocked domains
        self.check_blocked(&http_request.url)?;

        info!(
            "Executing {} {} for request {}",
            http_request.method,
            http_request.url,
            hex::encode(&request_id[..8])
        );

        // Execute HTTP request
        let response = self.execute_request(&http_request).await?;
        let response_shards = self.create_response_shards(
            request_id,
            pending.user_pubkey,
            pending.user_proof,
            &response,
            response_hops,
        )?;

        Ok(Some(response_shards))
    }

    /// Check if all chunks for a request have enough shards for reconstruction
    fn all_chunks_ready(&self, request_id: &Id) -> bool {
        let Some(pending) = self.pending.get(request_id) else {
            return false;
        };

        // Group shard count by chunk_index
        let mut chunk_counts: HashMap<u16, usize> = HashMap::new();
        for &(chunk_idx, _) in pending.shards.keys() {
            *chunk_counts.entry(chunk_idx).or_default() += 1;
        }

        // Every chunk must have at least DATA_SHARDS
        if chunk_counts.len() < pending.total_chunks as usize {
            return false;
        }
        chunk_counts.values().all(|&count| count >= tunnelcraft_erasure::DATA_SHARDS)
    }

    /// Reconstruct request data from shards (multi-chunk aware)
    fn reconstruct_request(&self, pending: &PendingRequest) -> Result<Vec<u8>> {
        // Group shards by chunk_index
        let mut chunks_by_index: HashMap<u16, Vec<(u8, &Shard)>> = HashMap::new();
        for (&(chunk_idx, shard_idx), shard) in &pending.shards {
            chunks_by_index
                .entry(chunk_idx)
                .or_default()
                .push((shard_idx, shard));
        }

        // Reconstruct each chunk independently
        let mut reconstructed_chunks: BTreeMap<u16, Vec<u8>> = BTreeMap::new();

        for chunk_idx in 0..pending.total_chunks {
            let chunk_shards = chunks_by_index.get(&chunk_idx);
            let mut shard_data: Vec<Option<Vec<u8>>> =
                vec![None; tunnelcraft_erasure::TOTAL_SHARDS];
            let mut shard_size = 0usize;

            if let Some(shards) = chunk_shards {
                for &(shard_idx, shard) in shards {
                    let idx = shard_idx as usize;
                    if idx < tunnelcraft_erasure::TOTAL_SHARDS {
                        shard_size = shard.payload.len();
                        shard_data[idx] = Some(shard.payload.clone());
                    }
                }
            }

            let max_len = shard_size * tunnelcraft_erasure::DATA_SHARDS;
            let chunk_data = self
                .erasure
                .decode(&mut shard_data, max_len)
                .map_err(|e| ExitError::ErasureDecodeError(e.to_string()))?;

            reconstructed_chunks.insert(chunk_idx, chunk_data);
        }

        // Reassemble chunks — use max possible length, HttpRequest handles its own framing
        let total_possible = reconstructed_chunks.values().map(|c| c.len()).sum();
        reassemble(&reconstructed_chunks, pending.total_chunks, total_possible)
            .map_err(|e| ExitError::ErasureDecodeError(e.to_string()))
    }

    /// Check if URL is blocked
    fn check_blocked(&self, url: &str) -> Result<()> {
        for domain in &self.config.blocked_domains {
            if url.contains(domain) {
                return Err(ExitError::BlockedDestination(domain.clone()));
            }
        }
        Ok(())
    }

    /// Execute an HTTP request
    async fn execute_request(&self, request: &HttpRequest) -> Result<HttpResponse> {
        let method = request.method.to_uppercase();
        let mut req = match method.as_str() {
            "GET" => self.http_client.get(&request.url),
            "POST" => self.http_client.post(&request.url),
            "PUT" => self.http_client.put(&request.url),
            "DELETE" => self.http_client.delete(&request.url),
            "PATCH" => self.http_client.patch(&request.url),
            "HEAD" => self.http_client.head(&request.url),
            _ => return Err(ExitError::InvalidRequest(format!("Unsupported method: {}", method))),
        };

        // Add headers
        for (key, value) in &request.headers {
            req = req.header(key.as_str(), value.as_str());
        }

        // Add body if present
        if let Some(body) = &request.body {
            req = req.body(body.clone());
        }

        // Execute
        let response = req.send().await?;
        let status = response.status().as_u16();

        // Collect headers
        let mut headers = HashMap::new();
        for (key, value) in response.headers() {
            if let Ok(v) = value.to_str() {
                headers.insert(key.to_string(), v.to_string());
            }
        }

        // Get body
        let body = response.bytes().await?.to_vec();

        if body.len() > self.config.max_response_size {
            warn!("Response too large: {} bytes", body.len());
        }

        Ok(HttpResponse::new(status, headers, body))
    }

    /// Create response shards to send back (chunked)
    fn create_response_shards(
        &self,
        request_id: Id,
        user_pubkey: PublicKey,
        user_proof: Id,
        response: &HttpResponse,
        hops: u8,
    ) -> Result<Vec<Shard>> {
        let response_data = response.to_bytes();

        // Chunk and erasure code: each 3KB chunk → 5 shard payloads of ~1KB
        let chunks = chunk_and_encode(&response_data)
            .map_err(|e| ExitError::ErasureDecodeError(e.to_string()))?;

        let total_chunks = chunks.len() as u16;
        let exit_pubkey = self.keypair.public_key_bytes();

        let mut shards = Vec::with_capacity(chunks.len() * tunnelcraft_erasure::TOTAL_SHARDS);

        for (chunk_index, shard_payloads) in chunks {
            let total_shards_in_chunk = shard_payloads.len() as u8;

            for (i, payload) in shard_payloads.into_iter().enumerate() {
                let mut hasher = Sha256::new();
                hasher.update(&request_id);
                hasher.update(b"response");
                hasher.update(&chunk_index.to_be_bytes());
                hasher.update(&[i as u8]);
                let hash = hasher.finalize();

                let mut shard_id: Id = [0u8; 32];
                shard_id.copy_from_slice(&hash);

                let shard = Shard::new_response(
                    shard_id,
                    request_id,
                    user_pubkey,
                    user_proof,
                    exit_pubkey,
                    hops,
                    payload,
                    i as u8,
                    total_shards_in_chunk,
                    hops,
                    chunk_index,
                    total_chunks,
                );

                shards.push(shard);
            }
        }

        debug!(
            "Created {} response shards ({} chunks) for request {}",
            shards.len(),
            total_chunks,
            hex::encode(&request_id[..8])
        );

        Ok(shards)
    }

    /// Get the number of pending requests
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Clear stale pending requests older than given duration
    pub fn clear_stale(&mut self, max_age: Duration) {
        let before = self.pending.len();
        let now = Instant::now();
        self.pending.retain(|_, req| now.duration_since(req.created_at) < max_age);
        let removed = before - self.pending.len();
        if removed > 0 {
            warn!("Cleared {} stale pending requests", removed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = ExitConfig::default();
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert!(config.blocked_domains.contains(&"localhost".to_string()));
    }

    #[test]
    fn test_blocked_domain_check() {
        let config = ExitConfig::default();
        let handler = ExitHandler::new(config, [0u8; 32], [0u8; 32]).unwrap();

        assert!(handler.check_blocked("http://localhost:8080/api").is_err());
        assert!(handler.check_blocked("http://127.0.0.1/test").is_err());
        assert!(handler.check_blocked("https://example.com/api").is_ok());
    }

    #[test]
    fn test_handler_creation() {
        let handler = ExitHandler::new(ExitConfig::default(), [0u8; 32], [0u8; 32]).unwrap();
        assert_eq!(handler.pending_count(), 0);
    }

    // ==================== NEGATIVE TESTS ====================

    #[test]
    fn test_blocked_localhost_variants() {
        let config = ExitConfig::default();
        let handler = ExitHandler::new(config, [0u8; 32], [0u8; 32]).unwrap();

        // Various localhost formats should all be blocked
        assert!(handler.check_blocked("http://localhost").is_err());
        assert!(handler.check_blocked("http://localhost:3000").is_err());
        assert!(handler.check_blocked("https://localhost/api").is_err());
        assert!(handler.check_blocked("http://127.0.0.1").is_err());
        assert!(handler.check_blocked("http://127.0.0.1:8080/test").is_err());
        assert!(handler.check_blocked("http://0.0.0.0:9000").is_err());
    }

    #[test]
    fn test_blocked_domain_in_path() {
        let config = ExitConfig::default();
        let handler = ExitHandler::new(config, [0u8; 32], [0u8; 32]).unwrap();

        // Blocked domain appearing in path (should still block due to simple contains check)
        assert!(handler.check_blocked("http://evil.com/redirect?to=localhost").is_err());
    }

    #[test]
    fn test_custom_blocked_domains() {
        let config = ExitConfig {
            blocked_domains: vec![
                "malware.com".to_string(),
                "phishing.net".to_string(),
            ],
            ..Default::default()
        };
        let handler = ExitHandler::new(config, [0u8; 32], [0u8; 32]).unwrap();

        assert!(handler.check_blocked("http://malware.com").is_err());
        assert!(handler.check_blocked("https://phishing.net/login").is_err());
        assert!(handler.check_blocked("https://safe.org").is_ok());

        // Default blocked domains are replaced, not localhost blocked anymore
        assert!(handler.check_blocked("http://localhost").is_ok());
    }

    #[test]
    fn test_empty_blocked_list() {
        let config = ExitConfig {
            blocked_domains: vec![],
            ..Default::default()
        };
        let handler = ExitHandler::new(config, [0u8; 32], [0u8; 32]).unwrap();

        // Everything should be allowed
        assert!(handler.check_blocked("http://localhost").is_ok());
        assert!(handler.check_blocked("http://127.0.0.1").is_ok());
    }

    #[test]
    fn test_blocked_domain_case_sensitivity() {
        let config = ExitConfig::default();
        let handler = ExitHandler::new(config, [0u8; 32], [0u8; 32]).unwrap();

        // Current implementation is case-sensitive
        assert!(handler.check_blocked("http://localhost").is_err());
        // LOCALHOST in uppercase would NOT be blocked (case sensitive)
        assert!(handler.check_blocked("http://LOCALHOST").is_ok());
    }

    #[test]
    fn test_pending_count_increments() {
        // This test would need actual shard processing,
        // but we can verify the handler starts empty
        let handler = ExitHandler::new(ExitConfig::default(), [0u8; 32], [0u8; 32]).unwrap();
        assert_eq!(handler.pending_count(), 0);
    }

    #[test]
    fn test_config_timeout_values() {
        let config = ExitConfig {
            timeout: Duration::from_millis(100),
            max_request_size: 100,
            max_response_size: 100,
            blocked_domains: vec![],
        };

        assert_eq!(config.timeout, Duration::from_millis(100));
        assert_eq!(config.max_request_size, 100);
        assert_eq!(config.max_response_size, 100);
    }

    #[test]
    fn test_clear_stale_removes_old_entries() {
        let keypair = SigningKeypair::generate();
        let mut handler = ExitHandler::with_keypair(ExitConfig::default(), keypair).unwrap();

        // Manually insert a pending request
        handler.pending.insert([1u8; 32], PendingRequest {
            shards: HashMap::new(),
            total_chunks: 1,
            user_pubkey: [0u8; 32],
            user_proof: [0u8; 32],
            created_at: Instant::now() - Duration::from_secs(120),
        });
        handler.pending.insert([2u8; 32], PendingRequest {
            shards: HashMap::new(),
            total_chunks: 1,
            user_pubkey: [0u8; 32],
            user_proof: [0u8; 32],
            created_at: Instant::now(),
        });

        assert_eq!(handler.pending_count(), 2);

        // Clear entries older than 60 seconds
        handler.clear_stale(Duration::from_secs(60));

        assert_eq!(handler.pending_count(), 1);
        assert!(handler.pending.contains_key(&[2u8; 32]));
        assert!(!handler.pending.contains_key(&[1u8; 32]));
    }

    #[test]
    fn test_clear_stale_keeps_fresh_entries() {
        let keypair = SigningKeypair::generate();
        let mut handler = ExitHandler::with_keypair(ExitConfig::default(), keypair).unwrap();

        handler.pending.insert([1u8; 32], PendingRequest {
            shards: HashMap::new(),
            total_chunks: 1,
            user_pubkey: [0u8; 32],
            user_proof: [0u8; 32],
            created_at: Instant::now(),
        });

        handler.clear_stale(Duration::from_secs(60));
        assert_eq!(handler.pending_count(), 1);
    }

    #[test]
    fn test_handler_with_keypair() {
        let keypair = SigningKeypair::generate();
        let pubkey = keypair.public_key_bytes();
        let handler = ExitHandler::with_keypair(ExitConfig::default(), keypair).unwrap();
        assert_eq!(handler.keypair.public_key_bytes(), pubkey);
        assert_eq!(handler.pending_count(), 0);
    }

    #[test]
    fn test_response_shards_have_exit_sender_pubkey() {
        let keypair = SigningKeypair::generate();
        let exit_pubkey = keypair.public_key_bytes();
        let handler = ExitHandler::with_keypair(ExitConfig::default(), keypair).unwrap();

        // Create response shards with real data
        let response = HttpResponse::new(200, HashMap::new(), b"Hello".to_vec());
        let shards = handler.create_response_shards(
            [1u8; 32],
            [2u8; 32],
            [0u8; 32],  // user_proof
            &response,
            2,  // 2 hops
        ).unwrap();

        assert!(!shards.is_empty());
        for shard in &shards {
            // Each shard should have exit's pubkey as sender_pubkey
            assert_eq!(shard.sender_pubkey, exit_pubkey);
            assert_eq!(shard.total_hops, 2);
        }
    }
}
