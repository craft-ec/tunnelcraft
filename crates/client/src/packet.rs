//! Raw IP packet tunneling
//!
//! Wraps raw IP packets for transmission through the shard network.
//! Used by VPN Network Extensions (iOS) and VpnService (Android).

use rand::Rng;
use sha2::{Digest, Sha256};

use tunnelcraft_core::{HopMode, Id, PublicKey, Shard};
use tunnelcraft_erasure::{ErasureCoder, TOTAL_SHARDS};

use crate::{ClientError, Result};

/// Magic bytes to identify raw packet tunneling (vs HTTP requests)
pub const RAW_PACKET_MAGIC: &[u8] = b"TCRAW\x01";

/// Builder for creating shards from raw IP packets
pub struct RawPacketBuilder {
    /// Raw IP packet data
    packet: Vec<u8>,
    /// Number of relay hops
    hop_mode: HopMode,
}

impl RawPacketBuilder {
    /// Create a new raw packet builder
    pub fn new(packet: Vec<u8>) -> Self {
        Self {
            packet,
            hop_mode: HopMode::Standard,
        }
    }

    /// Set hop mode (privacy level)
    pub fn hop_mode(mut self, mode: HopMode) -> Self {
        self.hop_mode = mode;
        self
    }

    /// Serialize the raw packet with protocol header
    fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(RAW_PACKET_MAGIC.len() + 4 + self.packet.len());

        // Magic bytes to identify raw packet
        data.extend_from_slice(RAW_PACKET_MAGIC);

        // Packet length (u32 big-endian)
        let len = self.packet.len() as u32;
        data.extend_from_slice(&len.to_be_bytes());

        // Raw packet data
        data.extend_from_slice(&self.packet);

        data
    }

    /// Build shards for the raw packet
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
        let erasure =
            ErasureCoder::new().map_err(|e| ClientError::ErasureError(e.to_string()))?;

        // Generate request ID
        let request_id = generate_request_id();

        // Serialize packet data with header
        let packet_data = self.serialize();

        // Encode with erasure coding
        let encoded = erasure
            .encode(&packet_data)
            .map_err(|e| ClientError::ErasureError(e.to_string()))?;

        // Create shards
        let mut shards = Vec::with_capacity(TOTAL_SHARDS);
        let total_shards = encoded.len() as u8;
        let hops = self.hop_mode.hop_count();

        for (i, payload) in encoded.into_iter().enumerate() {
            let shard_id = generate_shard_id(&request_id, i as u8);

            let shard = Shard::new_request(
                shard_id,
                request_id,
                user_pubkey,
                exit_pubkey,
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

/// Parse a raw packet from reconstructed shard data
///
/// Returns the raw IP packet if this is a raw packet request
pub fn parse_raw_packet(data: &[u8]) -> Option<Vec<u8>> {
    // Check magic bytes
    if data.len() < RAW_PACKET_MAGIC.len() + 4 {
        return None;
    }

    if !data.starts_with(RAW_PACKET_MAGIC) {
        return None;
    }

    let header_len = RAW_PACKET_MAGIC.len();
    let len_bytes = &data[header_len..header_len + 4];
    let packet_len = u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;

    let packet_start = header_len + 4;
    if data.len() < packet_start + packet_len {
        return None;
    }

    Some(data[packet_start..packet_start + packet_len].to_vec())
}

/// Check if data is a raw packet request (vs HTTP)
pub fn is_raw_packet(data: &[u8]) -> bool {
    data.starts_with(RAW_PACKET_MAGIC)
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
    fn test_raw_packet_builder() {
        let packet = vec![0x45, 0x00, 0x00, 0x28]; // Minimal IP header start
        let builder = RawPacketBuilder::new(packet.clone());

        let user_pubkey = [1u8; 32];
        let exit_pubkey = [2u8; 32];

        let shards = builder.build(user_pubkey, exit_pubkey).unwrap();

        assert_eq!(shards.len(), TOTAL_SHARDS);

        // All shards should have same request_id
        let request_id = shards[0].request_id;
        for shard in &shards {
            assert_eq!(shard.request_id, request_id);
        }
    }

    #[test]
    fn test_serialize_and_parse() {
        let packet = vec![0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x56, 0x78];
        let builder = RawPacketBuilder::new(packet.clone());

        let serialized = builder.serialize();

        // Should start with magic bytes
        assert!(serialized.starts_with(RAW_PACKET_MAGIC));

        // Should be parseable
        let parsed = parse_raw_packet(&serialized).unwrap();
        assert_eq!(parsed, packet);
    }

    #[test]
    fn test_is_raw_packet() {
        let raw = b"TCRAW\x01\x00\x00\x00\x04test";
        assert!(is_raw_packet(raw));

        let http = b"GET\nhttps://example.com\n";
        assert!(!is_raw_packet(http));
    }

    #[test]
    fn test_parse_invalid_data() {
        // Too short
        assert!(parse_raw_packet(b"short").is_none());

        // Wrong magic
        assert!(parse_raw_packet(b"WRONGMAGIC\x00\x00\x00\x04test").is_none());

        // Truncated packet
        let truncated = b"TCRAW\x01\x00\x00\x00\x10short";
        assert!(parse_raw_packet(truncated).is_none());
    }

    #[test]
    fn test_hop_mode() {
        let packet = vec![0x45, 0x00];
        let builder = RawPacketBuilder::new(packet).hop_mode(HopMode::Paranoid);

        assert_eq!(builder.hop_mode, HopMode::Paranoid);
    }
}
