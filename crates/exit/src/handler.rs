//! Exit node handler
//!
//! Manages the complete request/response lifecycle:
//! 1. Collect shards for a request
//! 2. Reconstruct and execute HTTP request
//! 3. Create response shards
//! 4. Submit settlement

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use sha2::{Sha256, Digest};
use tracing::{debug, info, warn};

use tunnelcraft_core::{Shard, Id, PublicKey, ChainEntry, ShardType, CreditProof};
use tunnelcraft_crypto::{SigningKeypair, sign_shard};
use tunnelcraft_erasure::ErasureCoder;
use tunnelcraft_settlement::{SettlementClient, SettleRequest};

use crate::{ExitError, Result, HttpRequest, HttpResponse};

/// Magic bytes to identify raw packet tunneling (vs HTTP requests)
/// Must match tunnelcraft_client::packet::RAW_PACKET_MAGIC
const RAW_PACKET_MAGIC: &[u8] = b"TCRAW\x01";

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

/// Pending request awaiting more shards
struct PendingRequest {
    /// Collected shards indexed by shard_index
    shards: HashMap<u8, Shard>,
    /// User's public key (destination for response, used for encryption)
    user_pubkey: PublicKey,
    /// Credit hash for settlement
    credit_hash: Id,
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
        let credit_hash = shard.credit_hash;
        let shard_index = shard.shard_index;

        // Add shard to pending request
        let pending = self.pending.entry(request_id).or_insert_with(|| {
            PendingRequest {
                shards: HashMap::new(),
                user_pubkey,
                credit_hash,
                created_at: Instant::now(),
            }
        });
        pending.shards.insert(shard_index, shard);

        let shard_count = pending.shards.len();
        debug!("Request {} has {}/3 shards", hex::encode(&request_id[..8]), shard_count);

        // Check if we have enough shards to reconstruct
        if shard_count < tunnelcraft_erasure::DATA_SHARDS {
            return Ok(None);
        }

        // Extract and reconstruct
        let Some(pending) = self.pending.remove(&request_id) else {
            debug!("Request {} already processed", hex::encode(&request_id[..8]));
            return Ok(None);
        };

        // Collect request chains from all shards for settlement
        let request_chains: Vec<Vec<ChainEntry>> = pending.shards.values()
            .map(|s| s.chain.clone())
            .collect();

        // Derive response hop count from request chain length
        // (chain.len() == number of relays the request traversed)
        let response_hops = request_chains.first()
            .map(|c| c.len() as u8)
            .unwrap_or(0);

        let request_data = self.reconstruct_request(&pending)?;

        // Get credit proof from first shard for settlement
        let credit_proof = pending.shards.values()
            .next()
            .and_then(|s| s.credit_proof.clone());

        // Get response data (either raw packet or HTTP)
        let response_shards = if self.is_raw_packet(&request_data) {
            let response_data = self.handle_raw_packet(&request_data, &request_id).await?;
            self.create_raw_response_shards(
                request_id,
                pending.user_pubkey,
                pending.credit_hash,
                response_data,
                response_hops,
            )?
        } else {
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
            self.create_response_shards(
                request_id,
                pending.user_pubkey,
                pending.credit_hash,
                &response,
                response_hops,
            )?
        };

        // Submit request settlement if we have the credit proof
        if let Some(proof) = credit_proof {
            self.submit_request_settlement(
                request_id,
                pending.user_pubkey,
                proof,
                request_chains,
            ).await;
        } else {
            warn!(
                "No credit_proof found for request {}, skipping settlement",
                hex::encode(&request_id[..8])
            );
        }

        Ok(Some(response_shards))
    }

    /// Submit request settlement to the chain
    async fn submit_request_settlement(
        &self,
        request_id: Id,
        user_pubkey: PublicKey,
        credit_proof: CreditProof,
        request_chains: Vec<Vec<ChainEntry>>,
    ) {
        let Some(client) = &self.settlement_client else {
            debug!("No settlement client configured, skipping settlement");
            return;
        };

        let settle_request = SettleRequest {
            request_id,
            user_pubkey,
            credit_proof,
            request_chains,
        };

        match client.settle_request(settle_request).await {
            Ok(sig) => {
                info!(
                    "Request settlement submitted for {} (tx: {})",
                    hex::encode(&request_id[..8]),
                    hex::encode(&sig[..8])
                );
            }
            Err(e) => {
                warn!(
                    "Failed to submit request settlement for {}: {}",
                    hex::encode(&request_id[..8]),
                    e
                );
            }
        }
    }

    /// Reconstruct request data from shards
    fn reconstruct_request(&self, pending: &PendingRequest) -> Result<Vec<u8>> {
        // Convert shards to the format expected by erasure coder
        let mut shard_data: Vec<Option<Vec<u8>>> = vec![None; tunnelcraft_erasure::TOTAL_SHARDS];
        let mut shard_size = 0usize;

        for (index, shard) in &pending.shards {
            let idx = *index as usize;
            if idx < tunnelcraft_erasure::TOTAL_SHARDS {
                shard_size = shard.payload.len();
                shard_data[idx] = Some(shard.payload.clone());
            }
        }

        // Use max possible length - the serialization format (HttpRequest) handles its own length
        let max_len = shard_size * tunnelcraft_erasure::DATA_SHARDS;

        self.erasure.decode(&mut shard_data, max_len)
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

    /// Check if data is a raw IP packet (vs HTTP request)
    fn is_raw_packet(&self, data: &[u8]) -> bool {
        data.starts_with(RAW_PACKET_MAGIC)
    }

    /// Parse raw packet from protocol format
    fn parse_raw_packet(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < RAW_PACKET_MAGIC.len() + 4 {
            return Err(ExitError::InvalidRequest("Raw packet too short".to_string()));
        }

        let header_len = RAW_PACKET_MAGIC.len();
        let len_bytes = &data[header_len..header_len + 4];
        let packet_len = u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;

        let packet_start = header_len + 4;
        if data.len() < packet_start + packet_len {
            return Err(ExitError::InvalidRequest("Raw packet truncated".to_string()));
        }

        Ok(data[packet_start..packet_start + packet_len].to_vec())
    }

    /// Handle a raw IP packet
    ///
    /// Parses IP header, extracts protocol/destination, and forwards
    /// TCP or UDP payloads to the actual destination. Constructs a
    /// response IP packet with the data received back.
    async fn handle_raw_packet(&self, data: &[u8], request_id: &Id) -> Result<Vec<u8>> {
        let raw_packet = self.parse_raw_packet(data)?;

        info!(
            "Processing raw packet of {} bytes for request {}",
            raw_packet.len(),
            hex::encode(&request_id[..8])
        );

        // Parse IP header to get protocol and destination
        if raw_packet.len() < 20 {
            return Err(ExitError::InvalidRequest("IP packet too short".to_string()));
        }

        let ip_version = (raw_packet[0] >> 4) & 0x0F;
        if ip_version != 4 {
            return Err(ExitError::InvalidRequest(
                format!("Unsupported IP version: {} (only IPv4 supported)", ip_version),
            ));
        }

        let ihl = (raw_packet[0] & 0x0F) as usize * 4;
        if raw_packet.len() < ihl {
            return Err(ExitError::InvalidRequest("IP header length exceeds packet".to_string()));
        }

        let protocol = raw_packet[9];
        let src_ip = std::net::Ipv4Addr::new(
            raw_packet[12], raw_packet[13], raw_packet[14], raw_packet[15],
        );
        let dest_ip = std::net::Ipv4Addr::new(
            raw_packet[16], raw_packet[17], raw_packet[18], raw_packet[19],
        );

        debug!(
            "Raw packet: version={}, protocol={}, src={}, dest={}",
            ip_version, protocol, src_ip, dest_ip
        );

        let timeout_duration = Duration::from_secs(10);

        match protocol {
            6 => {
                // TCP
                if raw_packet.len() < ihl + 4 {
                    return Err(ExitError::InvalidRequest("TCP header too short".to_string()));
                }
                let dest_port = u16::from_be_bytes([raw_packet[ihl], raw_packet[ihl + 1]]);
                let src_port = u16::from_be_bytes([raw_packet[ihl + 2], raw_packet[ihl + 3]]);
                let tcp_header_len = ((raw_packet[ihl + 12] >> 4) as usize) * 4;
                let payload_start = ihl + tcp_header_len;
                let payload = if raw_packet.len() > payload_start {
                    &raw_packet[payload_start..]
                } else {
                    &[]
                };

                debug!("TCP {}:{} -> {}:{} ({} bytes payload)", src_ip, src_port, dest_ip, dest_port, payload.len());

                let response_payload = tokio::time::timeout(timeout_duration, async {
                    let addr = std::net::SocketAddr::new(std::net::IpAddr::V4(dest_ip), dest_port);
                    let mut stream = tokio::net::TcpStream::connect(addr).await
                        .map_err(|e| ExitError::InvalidRequest(format!("TCP connect failed: {e}")))?;

                    if !payload.is_empty() {
                        use tokio::io::AsyncWriteExt;
                        stream.write_all(payload).await
                            .map_err(|e| ExitError::InvalidRequest(format!("TCP write failed: {e}")))?;
                    }

                    use tokio::io::AsyncReadExt;
                    let mut buf = vec![0u8; 65535];
                    let n = stream.read(&mut buf).await
                        .map_err(|e| ExitError::InvalidRequest(format!("TCP read failed: {e}")))?;
                    buf.truncate(n);
                    Ok::<Vec<u8>, ExitError>(buf)
                })
                .await
                .map_err(|_| ExitError::Timeout)??;

                // Build response IP packet (swap src/dest, include response payload)
                Ok(self.build_ip_response(&raw_packet, ihl, &response_payload))
            }
            17 => {
                // UDP
                if raw_packet.len() < ihl + 8 {
                    return Err(ExitError::InvalidRequest("UDP header too short".to_string()));
                }
                let dest_port = u16::from_be_bytes([raw_packet[ihl], raw_packet[ihl + 1]]);
                let src_port = u16::from_be_bytes([raw_packet[ihl + 2], raw_packet[ihl + 3]]);
                let payload = &raw_packet[ihl + 8..];

                debug!("UDP {}:{} -> {}:{} ({} bytes payload)", src_ip, src_port, dest_ip, dest_port, payload.len());

                let response_payload = tokio::time::timeout(timeout_duration, async {
                    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await
                        .map_err(|e| ExitError::InvalidRequest(format!("UDP bind failed: {e}")))?;
                    let dest_addr = std::net::SocketAddr::new(std::net::IpAddr::V4(dest_ip), dest_port);
                    socket.send_to(payload, dest_addr).await
                        .map_err(|e| ExitError::InvalidRequest(format!("UDP send failed: {e}")))?;

                    let mut buf = vec![0u8; 65535];
                    let (n, _) = socket.recv_from(&mut buf).await
                        .map_err(|e| ExitError::InvalidRequest(format!("UDP recv failed: {e}")))?;
                    buf.truncate(n);
                    Ok::<Vec<u8>, ExitError>(buf)
                })
                .await
                .map_err(|_| ExitError::Timeout)??;

                Ok(self.build_ip_response(&raw_packet, ihl, &response_payload))
            }
            _ => {
                Err(ExitError::InvalidRequest(
                    format!("Unsupported IP protocol: {} (only TCP=6 and UDP=17 supported)", protocol),
                ))
            }
        }
    }

    /// Build a response IP packet by swapping src/dest addresses
    /// and attaching the response payload
    fn build_ip_response(&self, original: &[u8], ihl: usize, payload: &[u8]) -> Vec<u8> {
        let total_len = ihl + payload.len();
        let mut response = vec![0u8; total_len];

        // Copy original IP header
        response[..ihl].copy_from_slice(&original[..ihl]);

        // Swap source and destination IP addresses
        response[12..16].copy_from_slice(&original[16..20]); // new src = old dest
        response[16..20].copy_from_slice(&original[12..16]); // new dest = old src

        // Update total length
        let total_len_u16 = total_len as u16;
        response[2] = (total_len_u16 >> 8) as u8;
        response[3] = total_len_u16 as u8;

        // Clear checksum (set to 0 for recalculation by the OS/stack)
        response[10] = 0;
        response[11] = 0;

        // Append payload
        if !payload.is_empty() {
            response[ihl..].copy_from_slice(payload);
        }

        response
    }

    /// Create response shards for raw packet data
    fn create_raw_response_shards(
        &self,
        request_id: Id,
        user_pubkey: PublicKey,
        credit_hash: Id,
        response_data: Vec<u8>,
        hops: u8,
    ) -> Result<Vec<Shard>> {
        // Wrap response in same format for client to parse
        let mut wrapped = Vec::with_capacity(RAW_PACKET_MAGIC.len() + 4 + response_data.len());
        wrapped.extend_from_slice(RAW_PACKET_MAGIC);
        wrapped.extend_from_slice(&(response_data.len() as u32).to_be_bytes());
        wrapped.extend_from_slice(&response_data);

        // Encode with erasure coding
        let encoded = self.erasure.encode(&wrapped)
            .map_err(|e| ExitError::ErasureDecodeError(e.to_string()))?;

        // Create shards
        let mut shards = Vec::with_capacity(encoded.len());
        let total_shards = encoded.len() as u8;

        for (i, payload) in encoded.into_iter().enumerate() {
            // Generate shard_id from request_id and index
            let mut hasher = Sha256::new();
            hasher.update(&request_id);
            hasher.update(b"response");
            hasher.update(&[i as u8]);
            let hash = hasher.finalize();

            let mut shard_id: Id = [0u8; 32];
            shard_id.copy_from_slice(&hash);

            // Create shard with placeholder entry, then sign properly
            let placeholder_entry = ChainEntry::new(self.keypair.public_key_bytes(), [0u8; 64], hops);

            let mut shard = Shard::new_response(
                shard_id,
                request_id,
                credit_hash,
                user_pubkey,
                placeholder_entry,
                hops,
                payload,
                i as u8,
                total_shards,
            );

            // Replace the placeholder chain entry with a real signature
            shard.chain.clear();
            sign_shard(&self.keypair, &mut shard);

            shards.push(shard);
        }

        debug!(
            "Created {} raw response shards for request {}",
            shards.len(),
            hex::encode(&request_id[..8])
        );

        Ok(shards)
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

    /// Create response shards to send back
    fn create_response_shards(
        &self,
        request_id: Id,
        user_pubkey: PublicKey,
        credit_hash: Id,
        response: &HttpResponse,
        hops: u8,
    ) -> Result<Vec<Shard>> {
        let response_data = response.to_bytes();

        // Encode with erasure coding
        let encoded = self.erasure.encode(&response_data)
            .map_err(|e| ExitError::ErasureDecodeError(e.to_string()))?;

        // Create shards
        let mut shards = Vec::with_capacity(encoded.len());
        let total_shards = encoded.len() as u8;

        for (i, payload) in encoded.into_iter().enumerate() {
            // Generate shard_id from request_id and index
            let mut hasher = Sha256::new();
            hasher.update(&request_id);
            hasher.update(b"response");
            hasher.update(&[i as u8]);
            let hash = hasher.finalize();

            let mut shard_id: Id = [0u8; 32];
            shard_id.copy_from_slice(&hash);

            // Create shard with placeholder entry, then sign properly
            let placeholder_entry = ChainEntry::new(self.keypair.public_key_bytes(), [0u8; 64], hops);

            let mut shard = Shard::new_response(
                shard_id,
                request_id,
                credit_hash,
                user_pubkey,
                placeholder_entry,
                hops,
                payload,
                i as u8,
                total_shards,
            );

            // Replace the placeholder chain entry with a real signature
            shard.chain.clear();
            sign_shard(&self.keypair, &mut shard);

            shards.push(shard);
        }

        debug!(
            "Created {} response shards for request {}",
            shards.len(),
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
            user_pubkey: [0u8; 32],
            credit_hash: [0u8; 32],
            created_at: Instant::now() - Duration::from_secs(120),
        });
        handler.pending.insert([2u8; 32], PendingRequest {
            shards: HashMap::new(),
            user_pubkey: [0u8; 32],
            credit_hash: [0u8; 32],
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
            user_pubkey: [0u8; 32],
            credit_hash: [0u8; 32],
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
    fn test_response_shards_have_real_signatures() {
        use tunnelcraft_crypto::verify_chain;

        let keypair = SigningKeypair::generate();
        let handler = ExitHandler::with_keypair(ExitConfig::default(), keypair).unwrap();

        // Create response shards with real data
        let response = HttpResponse::new(200, HashMap::new(), b"Hello".to_vec());
        let shards = handler.create_response_shards(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            &response,
            2,  // 2 hops
        ).unwrap();

        assert!(!shards.is_empty());
        for shard in &shards {
            // Each shard should have exactly one chain entry (exit signature)
            assert_eq!(shard.chain.len(), 1);
            // The signature should not be all zeros
            assert_ne!(shard.chain[0].signature, [0u8; 64]);
            // The chain should verify correctly
            assert!(verify_chain(shard).is_ok());
        }
    }
}
