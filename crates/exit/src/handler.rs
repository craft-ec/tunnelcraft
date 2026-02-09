//! Exit node handler (onion-routed)
//!
//! Manages the complete request/response lifecycle:
//! 1. Decrypt routing_tag to get assembly_id
//! 2. Group shards by assembly_id
//! 3. Reconstruct and decrypt ExitPayload
//! 4. Execute HTTP request or tunnel connection
//! 5. Create response shards with onion routing via LeaseSet

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};
use sha2::{Sha256, Digest};
use tracing::{debug, info, warn};

use tunnelcraft_core::{
    Shard, Id, PublicKey, ExitPayload,
    TunnelMetadata, PAYLOAD_MODE_TUNNEL,
    compute_blind_token,
};
use tunnelcraft_crypto::{
    SigningKeypair, EncryptionKeypair,
    decrypt_routing_tag, decrypt_exit_payload,
    build_onion_header, encrypt_routing_tag,
};
use tunnelcraft_core::OnionSettlement;
use tunnelcraft_erasure::ErasureCoder;
use tunnelcraft_erasure::chunker::{chunk_and_encode, reassemble};
use tunnelcraft_settlement::SettlementClient;

use crate::{ExitError, Result, HttpRequest, HttpResponse};
use crate::tunnel_handler::TunnelHandler;

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

/// Pending assembly awaiting more shards (grouped by assembly_id)
struct PendingAssembly {
    /// Collected shard payloads indexed by (chunk_index, shard_index)
    shards: HashMap<(u16, u8), Vec<u8>>,
    /// Total chunks expected
    total_chunks: u16,
    /// Total shards per chunk
    #[allow(dead_code)]
    total_shards: u8,
    /// When this pending assembly was created
    created_at: Instant,
}

/// Exit node handler (onion-routed)
pub struct ExitHandler {
    config: ExitConfig,
    http_client: reqwest::Client,
    erasure: ErasureCoder,
    /// Pending assemblies: assembly_id → shard payloads
    pending: HashMap<Id, PendingAssembly>,
    /// Our signing keypair for signing response shards
    #[allow(dead_code)]
    keypair: SigningKeypair,
    /// Our encryption keypair for decrypting routing tags and exit payloads
    encryption_keypair: EncryptionKeypair,
    /// Settlement client (optional)
    settlement_client: Option<Arc<SettlementClient>>,
    /// TCP tunnel handler for SOCKS5 proxy mode
    tunnel_handler: TunnelHandler,
}

impl ExitHandler {
    /// Create a new exit handler with signing and encryption keypairs
    pub fn new(config: ExitConfig, _our_pubkey: PublicKey, our_secret: [u8; 32]) -> Result<Self> {
        let http_client = reqwest::Client::builder()
            .timeout(config.timeout)
            .user_agent("TunnelCraft/0.1")
            .build()?;

        let keypair = SigningKeypair::from_secret_bytes(&our_secret);
        let encryption_keypair = EncryptionKeypair::generate();
        let tunnel_handler = TunnelHandler::new(SigningKeypair::from_secret_bytes(&our_secret));

        Ok(Self {
            config,
            http_client,
            erasure: ErasureCoder::new()?,
            pending: HashMap::new(),
            keypair,
            encryption_keypair,
            settlement_client: None,
            tunnel_handler,
        })
    }

    /// Create a new exit handler with a SigningKeypair directly
    pub fn with_keypair(config: ExitConfig, keypair: SigningKeypair) -> Result<Self> {
        let http_client = reqwest::Client::builder()
            .timeout(config.timeout)
            .user_agent("TunnelCraft/0.1")
            .build()?;

        let encryption_keypair = EncryptionKeypair::generate();
        let tunnel_handler = TunnelHandler::new(keypair.clone());

        Ok(Self {
            config,
            http_client,
            erasure: ErasureCoder::new()?,
            pending: HashMap::new(),
            keypair,
            encryption_keypair,
            settlement_client: None,
            tunnel_handler,
        })
    }

    /// Create with explicit encryption keypair (for testing)
    pub fn with_keypairs(
        config: ExitConfig,
        keypair: SigningKeypair,
        encryption_keypair: EncryptionKeypair,
    ) -> Result<Self> {
        let http_client = reqwest::Client::builder()
            .timeout(config.timeout)
            .user_agent("TunnelCraft/0.1")
            .build()?;

        let tunnel_handler = TunnelHandler::new(keypair.clone());

        Ok(Self {
            config,
            http_client,
            erasure: ErasureCoder::new()?,
            pending: HashMap::new(),
            keypair,
            encryption_keypair,
            settlement_client: None,
            tunnel_handler,
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

        let keypair = SigningKeypair::from_secret_bytes(&our_secret);
        let encryption_keypair = EncryptionKeypair::generate();
        let tunnel_handler = TunnelHandler::new(SigningKeypair::from_secret_bytes(&our_secret));

        Ok(Self {
            config,
            http_client,
            erasure: ErasureCoder::new()?,
            pending: HashMap::new(),
            keypair,
            encryption_keypair,
            settlement_client: Some(settlement_client),
            tunnel_handler,
        })
    }

    /// Create with keypair and settlement client
    pub fn with_keypair_and_settlement(
        config: ExitConfig,
        keypair: SigningKeypair,
        settlement_client: Arc<SettlementClient>,
    ) -> Result<Self> {
        let http_client = reqwest::Client::builder()
            .timeout(config.timeout)
            .user_agent("TunnelCraft/0.1")
            .build()?;

        let encryption_keypair = EncryptionKeypair::generate();
        let tunnel_handler = TunnelHandler::new(keypair.clone());

        Ok(Self {
            config,
            http_client,
            erasure: ErasureCoder::new()?,
            pending: HashMap::new(),
            keypair,
            encryption_keypair,
            settlement_client: Some(settlement_client),
            tunnel_handler,
        })
    }

    /// Set the settlement client
    pub fn set_settlement_client(&mut self, client: Arc<SettlementClient>) {
        self.settlement_client = Some(client);
    }

    /// Get our encryption public key (for topology advertisements)
    pub fn encryption_pubkey(&self) -> [u8; 32] {
        self.encryption_keypair.public_key_bytes()
    }

    /// Process an incoming shard (onion-routed)
    ///
    /// 1. Decrypt routing_tag → assembly_id
    /// 2. Group by assembly_id
    /// 3. When all chunks ready: reconstruct → decrypt → process
    /// 4. Create response shards using LeaseSet
    /// Returns `(response_shards, gateway_peer_id_bytes)` where gateway is from the LeaseSet.
    /// If no LeaseSet gateway, gateway is None (direct mode — caller should use source_peer).
    pub async fn process_shard(&mut self, shard: Shard) -> Result<Option<(Vec<Shard>, Option<Vec<u8>>)>> {
        // Decrypt routing_tag to get assembly_id + shard/chunk metadata
        let tag = decrypt_routing_tag(
            &self.encryption_keypair.secret_key_bytes(),
            &shard.routing_tag,
        ).map_err(|e| ExitError::InvalidRequest(format!("routing_tag decrypt failed: {}", e)))?;

        let assembly_id = tag.assembly_id;
        let chunk_index = tag.chunk_index;
        let shard_index = tag.shard_index;
        let total_chunks = tag.total_chunks;
        let total_shards = tag.total_shards;

        // Add shard payload to pending assembly
        {
            let pending = self.pending.entry(assembly_id).or_insert_with(|| {
                PendingAssembly {
                    shards: HashMap::new(),
                    total_chunks,
                    total_shards,
                    created_at: Instant::now(),
                }
            });
            pending.shards.insert((chunk_index, shard_index), shard.payload);
        }

        // Check if we have enough shards for every chunk
        if !self.all_chunks_ready(&assembly_id) {
            if let Some(pending) = self.pending.get(&assembly_id) {
                let shard_count = pending.shards.len();
                let needed = total_chunks as usize * tunnelcraft_erasure::DATA_SHARDS;
                info!(
                    "[SHARD-FLOW] EXIT assembly={} shard received: chunk={} shard={} ({}/{} shards collected)",
                    hex::encode(&assembly_id[..8]),
                    chunk_index, shard_index,
                    shard_count, needed,
                );
            }
            return Ok(None);
        }

        info!(
            "[SHARD-FLOW] EXIT assembly={} COMPLETE — all shards collected, reconstructing",
            hex::encode(&assembly_id[..8]),
        );

        // Extract and reconstruct
        let Some(pending) = self.pending.remove(&assembly_id) else {
            debug!("Assembly {} already processed", hex::encode(&assembly_id[..8]));
            return Ok(None);
        };

        let framed_data = self.reconstruct_data(&pending)?;

        // Strip length-prefixed framing (4-byte LE u32 original length)
        if framed_data.len() < 4 {
            return Err(ExitError::InvalidRequest("Reconstructed data too short for length prefix".to_string()));
        }
        let original_len = u32::from_le_bytes(
            framed_data[..4].try_into().unwrap()
        ) as usize;
        if framed_data.len() < 4 + original_len {
            return Err(ExitError::InvalidRequest(format!(
                "Reconstructed data shorter than declared: {} < {}",
                framed_data.len() - 4, original_len
            )));
        }
        let encrypted_data = &framed_data[4..4 + original_len];

        // Decrypt exit payload
        let exit_payload = decrypt_exit_payload(
            &self.encryption_keypair.secret_key_bytes(),
            encrypted_data,
        ).map_err(|e| ExitError::InvalidRequest(format!("ExitPayload decrypt failed: {}", e)))?;

        debug!(
            "Reconstructed exit payload: request={} type={:?} mode={}",
            hex::encode(&exit_payload.request_id[..8]),
            exit_payload.shard_type,
            exit_payload.mode,
        );

        info!(
            "Processing request {} (type: {:?}, mode: {})",
            hex::encode(&exit_payload.request_id[..8]),
            exit_payload.shard_type,
            exit_payload.mode,
        );

        // Process based on mode
        if exit_payload.mode == PAYLOAD_MODE_TUNNEL {
            return self.process_tunnel_payload(&exit_payload).await;
        }

        // HTTP mode
        let http_request = HttpRequest::from_bytes(&exit_payload.data)
            .map_err(|e| ExitError::InvalidRequest(e.to_string()))?;

        self.check_blocked(&http_request.url)?;

        info!(
            "HTTP request starting: {} {} (request={})",
            http_request.method,
            http_request.url,
            hex::encode(&exit_payload.request_id[..8])
        );

        let response = match self.execute_request(&http_request).await {
            Ok(r) => r,
            Err(e) => {
                warn!("HTTP request failed: {} (request={})", e, hex::encode(&exit_payload.request_id[..8]));
                return Err(e);
            }
        };
        let response_data = response.to_bytes();

        info!(
            "HTTP request completed: request={} status={} response_bytes={}",
            hex::encode(&exit_payload.request_id[..8]),
            response.status,
            response_data.len(),
        );

        let gateway = exit_payload.lease_set.leases.first().map(|l| l.gateway_peer_id.clone());
        let response_shards = self.create_response_shards(
            &exit_payload,
            &response_data,
        )?;

        debug!(
            "Created {} response shards for request={} gateway={:?}",
            response_shards.len(),
            hex::encode(&exit_payload.request_id[..8]),
            gateway.as_ref().map(|g| hex::encode(&g[..8])),
        );

        Ok(Some((response_shards, gateway)))
    }

    /// Process a tunnel-mode payload
    async fn process_tunnel_payload(
        &mut self,
        exit_payload: &ExitPayload,
    ) -> Result<Option<(Vec<Shard>, Option<Vec<u8>>)>> {
        let request_data = &exit_payload.data;
        if request_data.len() < 4 {
            return Err(ExitError::InvalidRequest("Tunnel payload too short".to_string()));
        }

        let metadata_len = u32::from_be_bytes(
            request_data[0..4].try_into().unwrap()
        ) as usize;
        if request_data.len() < 4 + metadata_len {
            return Err(ExitError::InvalidRequest("Tunnel metadata truncated".to_string()));
        }

        let metadata = TunnelMetadata::from_bytes(&request_data[4..4 + metadata_len])
            .map_err(|e| ExitError::InvalidRequest(format!("Invalid tunnel metadata: {}", e)))?;
        let tcp_data = request_data[4 + metadata_len..].to_vec();

        self.check_blocked(&metadata.host)?;

        info!(
            "Tunnel request to {}:{} for request {} (session {})",
            metadata.host,
            metadata.port,
            hex::encode(&exit_payload.request_id[..8]),
            hex::encode(&metadata.session_id[..8])
        );

        // Use tunnel handler for TCP connections
        let response_bytes = self.tunnel_handler.process_tunnel_bytes(
            &metadata,
            tcp_data,
        ).await?;

        if response_bytes.is_empty() {
            return Ok(Some((Vec::new(), None)));
        }

        let gateway = exit_payload.lease_set.leases.first().map(|l| l.gateway_peer_id.clone());
        let response_shards = self.create_response_shards(
            exit_payload,
            &response_bytes,
        )?;

        Ok(Some((response_shards, gateway)))
    }

    /// Check if all chunks for an assembly have enough shards
    fn all_chunks_ready(&self, assembly_id: &Id) -> bool {
        let Some(pending) = self.pending.get(assembly_id) else {
            return false;
        };

        let mut chunk_counts: HashMap<u16, usize> = HashMap::new();
        for &(chunk_idx, _) in pending.shards.keys() {
            *chunk_counts.entry(chunk_idx).or_default() += 1;
        }

        if chunk_counts.len() < pending.total_chunks as usize {
            return false;
        }
        chunk_counts.values().all(|&count| count >= tunnelcraft_erasure::DATA_SHARDS)
    }

    /// Reconstruct data from shard payloads (multi-chunk aware)
    fn reconstruct_data(&self, pending: &PendingAssembly) -> Result<Vec<u8>> {
        let mut chunks_by_index: HashMap<u16, Vec<(u8, &Vec<u8>)>> = HashMap::new();
        for (&(chunk_idx, shard_idx), payload) in &pending.shards {
            chunks_by_index
                .entry(chunk_idx)
                .or_default()
                .push((shard_idx, payload));
        }

        let mut reconstructed_chunks: BTreeMap<u16, Vec<u8>> = BTreeMap::new();

        for chunk_idx in 0..pending.total_chunks {
            let chunk_shards = chunks_by_index.get(&chunk_idx);
            let mut shard_data: Vec<Option<Vec<u8>>> =
                vec![None; tunnelcraft_erasure::TOTAL_SHARDS];
            let mut shard_size = 0usize;

            if let Some(shards) = chunk_shards {
                for &(shard_idx, payload) in shards {
                    let idx = shard_idx as usize;
                    if idx < tunnelcraft_erasure::TOTAL_SHARDS {
                        shard_size = payload.len();
                        shard_data[idx] = Some(payload.clone());
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

        for (key, value) in &request.headers {
            req = req.header(key.as_str(), value.as_str());
        }

        if let Some(body) = &request.body {
            req = req.body(body.clone());
        }

        let response = req.send().await?;
        let status = response.status().as_u16();

        let mut headers = HashMap::new();
        for (key, value) in response.headers() {
            if let Ok(v) = value.to_str() {
                headers.insert(key.to_string(), v.to_string());
            }
        }

        let body = response.bytes().await?.to_vec();

        if body.len() > self.config.max_response_size {
            warn!("Response too large: {} bytes", body.len());
        }

        Ok(HttpResponse::new(status, headers, body))
    }

    /// Create response shards with onion routing via LeaseSet
    ///
    /// For now, creates simple shards encrypted for the client.
    /// Full onion response routing (via topology graph + lease set gateways)
    /// will be completed when TopologyGraph is integrated into exit.
    fn create_response_shards(
        &self,
        exit_payload: &ExitPayload,
        response_data: &[u8],
    ) -> Result<Vec<Shard>> {
        // Encrypt response for the client using their X25519 encryption pubkey.
        // Falls back to user_pubkey for pre-response_enc_pubkey payloads.
        let recipient_pubkey = if exit_payload.response_enc_pubkey != [0u8; 32] {
            &exit_payload.response_enc_pubkey
        } else {
            &exit_payload.user_pubkey
        };
        let encrypted_response = tunnelcraft_crypto::encrypt_for_recipient(
            recipient_pubkey,
            &self.encryption_keypair.secret_key_bytes(),
            response_data,
        ).map_err(|e| ExitError::InvalidRequest(format!("Response encryption failed: {}", e)))?;

        // Prepend original length (4-byte LE u32) so client can strip erasure padding
        let original_len = encrypted_response.len() as u32;
        let mut framed = Vec::with_capacity(4 + encrypted_response.len());
        framed.extend_from_slice(&original_len.to_le_bytes());
        framed.extend_from_slice(&encrypted_response);

        // Chunk and erasure code
        let chunks = chunk_and_encode(&framed)
            .map_err(|e| ExitError::ErasureDecodeError(e.to_string()))?;

        let total_chunks = chunks.len() as u16;
        // Use request_id as assembly_id so the client can match
        // response shards to its pending request map.
        let assembly_id = exit_payload.request_id;

        let mut shards = Vec::with_capacity(chunks.len() * tunnelcraft_erasure::TOTAL_SHARDS);

        for (chunk_index, shard_payloads) in chunks {
            let total_shards_in_chunk = shard_payloads.len() as u8;

            for (i, payload) in shard_payloads.into_iter().enumerate() {
                // For each shard, build a routing tag encrypted for the client
                let routing_tag = encrypt_routing_tag(
                    recipient_pubkey,
                    &assembly_id,
                    i as u8,
                    total_shards_in_chunk,
                    chunk_index,
                    total_chunks,
                ).map_err(|e| ExitError::InvalidRequest(
                    format!("routing_tag encrypt failed: {}", e),
                ))?;

                // Build onion header for response path
                // For now, use empty header (direct to gateway/client)
                // Full onion path via lease set gateways requires TopologyGraph integration
                let lease = exit_payload.lease_set.leases.first();

                let (header, ephemeral) = if let Some(lease) = lease {
                    // Build per-hop settlement: derive unique shard_id and blind_token for the gateway
                    let gateway_pubkey = {
                        // Use gateway_encryption_pubkey as a stand-in for signing_pubkey
                        // (gateway identity for settlement derivation)
                        lease.gateway_encryption_pubkey
                    };
                    let shard_id = {
                        let mut hasher = Sha256::new();
                        hasher.update(exit_payload.request_id);
                        hasher.update(b"response");
                        hasher.update(chunk_index.to_be_bytes());
                        hasher.update([i as u8]);
                        hasher.update(gateway_pubkey);
                        let hash = hasher.finalize();
                        let mut id: Id = [0u8; 32];
                        id.copy_from_slice(&hash);
                        id
                    };
                    let blind_token = compute_blind_token(&exit_payload.user_proof, &shard_id, &gateway_pubkey);

                    let settlement = vec![OnionSettlement {
                        blind_token,
                        shard_id,
                        payload_size: payload.len() as u32,
                        epoch: 0,
                        pool_pubkey: [0u8; 32],
                    }];

                    // Single-hop onion to gateway with tunnel_id
                    build_onion_header(
                        &[(&lease.gateway_peer_id, &lease.gateway_encryption_pubkey)],
                        (&lease.gateway_peer_id, &lease.gateway_encryption_pubkey),
                        &settlement,
                        Some(&lease.tunnel_id),
                    ).map_err(|e| ExitError::InvalidRequest(
                        format!("Onion header build failed: {}", e),
                    ))?
                } else {
                    // No lease set — direct mode (empty header)
                    (vec![], [0u8; 32])
                };

                shards.push(Shard::new(
                    ephemeral,
                    header,
                    payload,
                    routing_tag,
                ));
            }
        }

        debug!(
            "Created {} response shards ({} chunks) for request {}",
            shards.len(),
            total_chunks,
            hex::encode(&exit_payload.request_id[..8])
        );

        Ok(shards)
    }

    /// Get the number of pending assemblies
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Clear stale pending assemblies and tunnel sessions
    pub fn clear_stale(&mut self, max_age: Duration) {
        let before = self.pending.len();
        let now = Instant::now();
        self.pending.retain(|_, asm| now.duration_since(asm.created_at) < max_age);
        let removed = before - self.pending.len();
        if removed > 0 {
            warn!("Cleared {} stale pending assemblies", removed);
        }

        self.tunnel_handler.clear_stale(max_age);
    }

    /// Get the number of active tunnel sessions
    pub fn tunnel_session_count(&self) -> usize {
        self.tunnel_handler.session_count()
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

    #[test]
    fn test_blocked_localhost_variants() {
        let config = ExitConfig::default();
        let handler = ExitHandler::new(config, [0u8; 32], [0u8; 32]).unwrap();

        assert!(handler.check_blocked("http://localhost").is_err());
        assert!(handler.check_blocked("http://localhost:3000").is_err());
        assert!(handler.check_blocked("https://localhost/api").is_err());
        assert!(handler.check_blocked("http://127.0.0.1").is_err());
        assert!(handler.check_blocked("http://0.0.0.0:9000").is_err());
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
        assert!(handler.check_blocked("http://localhost").is_ok());
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
    fn test_encryption_pubkey() {
        let handler = ExitHandler::new(ExitConfig::default(), [0u8; 32], [0u8; 32]).unwrap();
        let enc_pub = handler.encryption_pubkey();
        // Should be a valid non-zero X25519 pubkey
        assert_ne!(enc_pub, [0u8; 32]);
    }

    #[test]
    fn test_clear_stale_removes_old_entries() {
        let keypair = SigningKeypair::generate();
        let mut handler = ExitHandler::with_keypair(ExitConfig::default(), keypair).unwrap();

        handler.pending.insert([1u8; 32], PendingAssembly {
            shards: HashMap::new(),
            total_chunks: 1,
            total_shards: 5,
            created_at: Instant::now() - Duration::from_secs(120),
        });
        handler.pending.insert([2u8; 32], PendingAssembly {
            shards: HashMap::new(),
            total_chunks: 1,
            total_shards: 5,
            created_at: Instant::now(),
        });

        assert_eq!(handler.pending_count(), 2);
        handler.clear_stale(Duration::from_secs(60));
        assert_eq!(handler.pending_count(), 1);
        assert!(handler.pending.contains_key(&[2u8; 32]));
    }

    #[test]
    fn test_empty_blocked_list() {
        let config = ExitConfig {
            blocked_domains: vec![],
            ..Default::default()
        };
        let handler = ExitHandler::new(config, [0u8; 32], [0u8; 32]).unwrap();

        assert!(handler.check_blocked("http://localhost").is_ok());
        assert!(handler.check_blocked("http://127.0.0.1").is_ok());
    }
}
