//! Request building and shard creation

use sha2::{Sha256, Digest};
use rand::Rng;

use tunnelcraft_core::{Shard, Id, PublicKey, HopMode};
use tunnelcraft_erasure::{ErasureCoder, TOTAL_SHARDS};

use crate::{ClientError, Result};

/// Builder for creating VPN requests
pub struct RequestBuilder {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    hop_mode: HopMode,
}

impl RequestBuilder {
    /// Create a new request builder
    pub fn new(method: &str, url: &str) -> Self {
        Self {
            method: method.to_uppercase(),
            url: url.to_string(),
            headers: Vec::new(),
            body: None,
            hop_mode: HopMode::Standard,
        }
    }

    /// Add a header
    pub fn header(mut self, key: &str, value: &str) -> Self {
        self.headers.push((key.to_string(), value.to_string()));
        self
    }

    /// Set request body
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    /// Set hop mode (privacy level)
    pub fn hop_mode(mut self, mode: HopMode) -> Self {
        self.hop_mode = mode;
        self
    }

    /// Serialize the request to bytes
    fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        data.extend_from_slice(self.method.as_bytes());
        data.push(b'\n');

        data.extend_from_slice(self.url.as_bytes());
        data.push(b'\n');

        data.extend_from_slice(self.headers.len().to_string().as_bytes());
        data.push(b'\n');

        for (key, value) in &self.headers {
            data.extend_from_slice(format!("{}: {}", key, value).as_bytes());
            data.push(b'\n');
        }

        let body_len = self.body.as_ref().map(|b| b.len()).unwrap_or(0);
        data.extend_from_slice(body_len.to_string().as_bytes());
        data.push(b'\n');

        if let Some(body) = &self.body {
            data.extend_from_slice(body);
        }

        data
    }

    /// Build request shards
    ///
    /// # Arguments
    /// * `user_pubkey` - User's public key for response destination and encryption
    /// * `exit_pubkey` - Exit node's public key
    ///
    /// # Returns
    /// * Vector of shards ready to send to relays
    pub fn build(
        self,
        user_pubkey: PublicKey,
        exit_pubkey: PublicKey,
    ) -> Result<Vec<Shard>> {
        let erasure = ErasureCoder::new()
            .map_err(|e| ClientError::ErasureError(e.to_string()))?;

        // Generate request ID
        let request_id = generate_request_id();

        // Serialize request data
        let request_data = self.serialize();

        // Encode with erasure coding
        let encoded = erasure.encode(&request_data)
            .map_err(|e| ClientError::ErasureError(e.to_string()))?;

        // Create shards
        let mut shards = Vec::with_capacity(TOTAL_SHARDS);
        let total_shards = encoded.len() as u8;
        let hops = self.hop_mode.hop_count();

        for (i, payload) in encoded.into_iter().enumerate() {
            // Generate unique shard ID
            let shard_id = generate_shard_id(&request_id, i as u8);

            let shard = Shard::new_request(
                shard_id,
                request_id,
                user_pubkey,
                exit_pubkey,  // Destination is exit for requests
                hops,
                payload,
                i as u8,
                total_shards,
            );

            shards.push(shard);
        }

        Ok(shards)
    }
}

/// Generate a random request ID
fn generate_request_id() -> Id {
    let mut rng = rand::thread_rng();
    let mut id = [0u8; 32];
    rng.fill(&mut id);
    id
}

/// Generate a shard ID from request ID and index
fn generate_shard_id(request_id: &Id, index: u8) -> Id {
    let mut hasher = Sha256::new();
    hasher.update(request_id);
    hasher.update(b"shard");
    hasher.update(&[index]);
    let result = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_builder() {
        let builder = RequestBuilder::new("GET", "https://example.com")
            .header("User-Agent", "TunnelCraft")
            .hop_mode(HopMode::Standard);

        assert_eq!(builder.method, "GET");
        assert_eq!(builder.url, "https://example.com");
        assert_eq!(builder.headers.len(), 1);
        assert_eq!(builder.hop_mode, HopMode::Standard);
    }

    #[test]
    fn test_request_serialization() {
        let builder = RequestBuilder::new("POST", "https://api.example.com")
            .header("Content-Type", "application/json")
            .body(b"{\"key\": \"value\"}".to_vec());

        let data = builder.serialize();
        assert!(data.starts_with(b"POST\n"));
        assert!(data.windows(b"application/json".len()).any(|w| w == b"application/json"));
    }

    #[test]
    fn test_build_shards() {
        let builder = RequestBuilder::new("GET", "https://example.com");

        let user_pubkey = [1u8; 32];
        let exit_pubkey = [2u8; 32];

        let shards = builder.build(user_pubkey, exit_pubkey).unwrap();

        assert_eq!(shards.len(), TOTAL_SHARDS);

        // All shards should have same request_id
        let request_id = shards[0].request_id;
        for shard in &shards {
            assert_eq!(shard.request_id, request_id);
            assert_eq!(shard.user_pubkey, user_pubkey);
            assert_eq!(shard.destination, exit_pubkey);
        }
    }

    // ==================== NEGATIVE TESTS ====================

    #[test]
    fn test_request_method_normalized_to_uppercase() {
        let builder = RequestBuilder::new("get", "https://example.com");
        assert_eq!(builder.method, "GET");

        let builder2 = RequestBuilder::new("PoSt", "https://example.com");
        assert_eq!(builder2.method, "POST");
    }

    #[test]
    fn test_empty_url() {
        let builder = RequestBuilder::new("GET", "");
        assert_eq!(builder.url, "");

        let user_pubkey = [1u8; 32];
        let exit_pubkey = [2u8; 32];

        // Should still build shards even with empty URL
        let result = builder.build(user_pubkey, exit_pubkey);
        assert!(result.is_ok());
    }

    #[test]
    fn test_empty_body() {
        let builder = RequestBuilder::new("POST", "https://example.com")
            .body(vec![]);

        let data = builder.serialize();
        // Should have 0 as body length
        assert!(data.windows(2).any(|w| w == b"0\n"));
    }

    #[test]
    fn test_large_body() {
        let large_body = vec![0xAB; 10 * 1024 * 1024]; // 10MB
        let builder = RequestBuilder::new("POST", "https://example.com")
            .body(large_body.clone());

        let data = builder.serialize();
        assert!(data.len() > 10 * 1024 * 1024);
    }

    #[test]
    fn test_no_headers() {
        let builder = RequestBuilder::new("GET", "https://example.com");
        assert!(builder.headers.is_empty());

        let data = builder.serialize();
        // Should have 0 headers
        assert!(data.windows(2).any(|w| w == b"0\n"));
    }

    #[test]
    fn test_multiple_headers() {
        let builder = RequestBuilder::new("GET", "https://example.com")
            .header("X-Header-1", "value1")
            .header("X-Header-2", "value2")
            .header("X-Header-3", "value3");

        assert_eq!(builder.headers.len(), 3);
    }

    #[test]
    fn test_header_with_special_characters() {
        let builder = RequestBuilder::new("GET", "https://example.com")
            .header("X-Custom", "value with spaces & symbols: =?");

        let data = builder.serialize();
        assert!(data.windows(b"value with spaces".len()).any(|w| w == b"value with spaces"));
    }

    #[test]
    fn test_url_with_special_characters() {
        let builder = RequestBuilder::new("GET", "https://example.com/path?q=hello%20world&a=1");
        let data = builder.serialize();
        assert!(data.windows(b"q=hello%20world".len()).any(|w| w == b"q=hello%20world"));
    }

    #[test]
    fn test_different_hop_modes() {
        let builder_direct = RequestBuilder::new("GET", "https://example.com")
            .hop_mode(HopMode::Direct);
        assert_eq!(builder_direct.hop_mode, HopMode::Direct);

        let builder_std = RequestBuilder::new("GET", "https://example.com")
            .hop_mode(HopMode::Standard);
        assert_eq!(builder_std.hop_mode, HopMode::Standard);

        let builder_paranoid = RequestBuilder::new("GET", "https://example.com")
            .hop_mode(HopMode::Paranoid);
        assert_eq!(builder_paranoid.hop_mode, HopMode::Paranoid);
    }

    #[test]
    fn test_shard_ids_unique() {
        let request_id: Id = [42u8; 32];

        let shard_id_0 = generate_shard_id(&request_id, 0);
        let shard_id_1 = generate_shard_id(&request_id, 1);
        let shard_id_2 = generate_shard_id(&request_id, 2);

        assert_ne!(shard_id_0, shard_id_1);
        assert_ne!(shard_id_1, shard_id_2);
        assert_ne!(shard_id_0, shard_id_2);
    }

    #[test]
    fn test_shard_id_deterministic() {
        let request_id: Id = [42u8; 32];

        let shard_id_a = generate_shard_id(&request_id, 0);
        let shard_id_b = generate_shard_id(&request_id, 0);

        assert_eq!(shard_id_a, shard_id_b);
    }

    #[test]
    fn test_request_id_is_random() {
        let id1 = generate_request_id();
        let id2 = generate_request_id();

        // Should be different (with overwhelming probability)
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_build_shards_with_zero_pubkeys() {
        let builder = RequestBuilder::new("GET", "https://example.com");

        let user_pubkey = [0u8; 32];  // All zeros
        let exit_pubkey = [0u8; 32];  // All zeros

        let shards = builder.build(user_pubkey, exit_pubkey).unwrap();

        // Should still work with zero pubkeys
        for shard in &shards {
            assert_eq!(shard.user_pubkey, [0u8; 32]);
            assert_eq!(shard.destination, [0u8; 32]);
        }
    }

    #[test]
    fn test_shards_have_correct_indices() {
        let builder = RequestBuilder::new("GET", "https://example.com");
        let user_pubkey = [1u8; 32];
        let exit_pubkey = [2u8; 32];

        let shards = builder.build(user_pubkey, exit_pubkey).unwrap();

        for (i, shard) in shards.iter().enumerate() {
            assert_eq!(shard.shard_index, i as u8);
            assert_eq!(shard.total_shards, TOTAL_SHARDS as u8);
        }
    }

    #[test]
    fn test_binary_body() {
        let binary_body = vec![0x00, 0xFF, 0x7F, 0x80, 0x01, 0xFE];
        let builder = RequestBuilder::new("POST", "https://example.com")
            .body(binary_body.clone());

        let data = builder.serialize();
        // Binary body should be preserved at end
        assert!(data.ends_with(&binary_body));
    }
}
