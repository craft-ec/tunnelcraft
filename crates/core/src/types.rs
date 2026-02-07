use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// 32-byte identifier
pub type Id = [u8; 32];

/// 32-byte public key
pub type PublicKey = [u8; 32];

/// 64-byte signature (use BigArray for serde support)
pub type Signature = [u8; 64];

/// Subscription tier for users
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubscriptionTier {
    /// 10 GB / month
    Basic,
    /// 100 GB / month
    Standard,
    /// 1 TB + best-effort beyond / month
    Premium,
}

/// A single entry in the signature chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainEntry {
    /// Public key of the node that signed
    pub pubkey: PublicKey,
    /// Signature over the shard data
    #[serde(with = "BigArray")]
    pub signature: Signature,
    /// Hops remaining at the time of signing (needed for verification)
    pub hops_at_sign: u8,
}

impl ChainEntry {
    pub fn new(pubkey: PublicKey, signature: Signature, hops_at_sign: u8) -> Self {
        Self { pubkey, signature, hops_at_sign }
    }
}

/// Hop count configuration for privacy levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HopMode {
    /// Direct to exit (0 hops) - fast, less private
    Direct,
    /// 1 relay hop - basic privacy
    Light,
    /// 2 relay hops - good privacy
    Standard,
    /// 3 relay hops - maximum privacy
    Paranoid,
}

impl HopMode {
    pub fn hop_count(&self) -> u8 {
        match self {
            HopMode::Direct => 0,
            HopMode::Light => 1,
            HopMode::Standard => 2,
            HopMode::Paranoid => 3,
        }
    }

    pub fn from_count(count: u8) -> Self {
        match count {
            0 => HopMode::Direct,
            1 => HopMode::Light,
            2 => HopMode::Standard,
            _ => HopMode::Paranoid,
        }
    }
}

/// Geographic region for exit nodes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ExitRegion {
    /// Automatic selection based on latency
    #[default]
    Auto,
    /// North America
    NorthAmerica,
    /// Europe
    Europe,
    /// Asia Pacific
    AsiaPacific,
    /// South America
    SouthAmerica,
    /// Africa
    Africa,
    /// Middle East
    MiddleEast,
    /// Oceania (Australia, New Zealand)
    Oceania,
}

impl ExitRegion {
    /// Get display name for the region
    pub fn display_name(&self) -> &'static str {
        match self {
            ExitRegion::Auto => "Auto",
            ExitRegion::NorthAmerica => "North America",
            ExitRegion::Europe => "Europe",
            ExitRegion::AsiaPacific => "Asia Pacific",
            ExitRegion::SouthAmerica => "South America",
            ExitRegion::Africa => "Africa",
            ExitRegion::MiddleEast => "Middle East",
            ExitRegion::Oceania => "Oceania",
        }
    }

    /// Get short code for the region
    pub fn code(&self) -> &'static str {
        match self {
            ExitRegion::Auto => "auto",
            ExitRegion::NorthAmerica => "na",
            ExitRegion::Europe => "eu",
            ExitRegion::AsiaPacific => "ap",
            ExitRegion::SouthAmerica => "sa",
            ExitRegion::Africa => "af",
            ExitRegion::MiddleEast => "me",
            ExitRegion::Oceania => "oc",
        }
    }

    /// Get flag emoji for the region
    pub fn flag(&self) -> &'static str {
        match self {
            ExitRegion::Auto => "🌍",
            ExitRegion::NorthAmerica => "🇺🇸",
            ExitRegion::Europe => "🇪🇺",
            ExitRegion::AsiaPacific => "🇯🇵",
            ExitRegion::SouthAmerica => "🇧🇷",
            ExitRegion::Africa => "🇿🇦",
            ExitRegion::MiddleEast => "🇦🇪",
            ExitRegion::Oceania => "🇦🇺",
        }
    }
}

/// Information about an exit node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitInfo {
    pub pubkey: PublicKey,
    pub address: String,
    pub region: ExitRegion,
    pub country_code: Option<String>,
    pub city: Option<String>,
    pub reputation: u64,
    pub latency_ms: u32,
}

/// Information about a peer node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub pubkey: PublicKey,
    pub address: String,
    pub is_exit: bool,
}


/// Cryptographic receipt proving a relay received and will forward a shard.
///
/// When relay A sends a shard to relay B, relay B signs a receipt proving
/// delivery. Relay A uses this receipt as on-chain proof for settlement.
/// This replaces TCP ACK (which is fakeable at the transport level).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardReceipt {
    /// Request this shard belongs to
    pub request_id: Id,
    /// Shard index (identifies which shard in the erasure set)
    pub shard_index: u8,
    /// Public key of the receiving node (signs this receipt)
    pub receiver_pubkey: PublicKey,
    /// Unix timestamp (seconds) when the shard was received
    pub timestamp: u64,
    /// Receiver's ed25519 signature over the receipt payload
    #[serde(with = "BigArray")]
    pub signature: Signature,
}

impl ForwardReceipt {
    /// Get the data that the receiver signs:
    /// request_id || shard_index || receiver_pubkey || timestamp
    pub fn signable_data(
        request_id: &Id,
        shard_index: u8,
        receiver_pubkey: &PublicKey,
        timestamp: u64,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(32 + 1 + 32 + 8);
        data.extend_from_slice(request_id);
        data.push(shard_index);
        data.extend_from_slice(receiver_pubkey);
        data.extend_from_slice(&timestamp.to_le_bytes());
        data
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    // ==================== HopMode Tests ====================

    #[test]
    fn test_hop_mode_hop_count() {
        assert_eq!(HopMode::Direct.hop_count(), 0);
        assert_eq!(HopMode::Light.hop_count(), 1);
        assert_eq!(HopMode::Standard.hop_count(), 2);
        assert_eq!(HopMode::Paranoid.hop_count(), 3);
    }

    #[test]
    fn test_hop_mode_from_count() {
        assert_eq!(HopMode::from_count(0), HopMode::Direct);
        assert_eq!(HopMode::from_count(1), HopMode::Light);
        assert_eq!(HopMode::from_count(2), HopMode::Standard);
        assert_eq!(HopMode::from_count(3), HopMode::Paranoid);
    }

    #[test]
    fn test_hop_mode_from_count_high_values() {
        // Any value >= 3 should map to Paranoid
        assert_eq!(HopMode::from_count(4), HopMode::Paranoid);
        assert_eq!(HopMode::from_count(10), HopMode::Paranoid);
        assert_eq!(HopMode::from_count(255), HopMode::Paranoid);
    }

    #[test]
    fn test_hop_mode_roundtrip() {
        for mode in [HopMode::Direct, HopMode::Light, HopMode::Standard, HopMode::Paranoid] {
            let count = mode.hop_count();
            assert_eq!(HopMode::from_count(count), mode);
        }
    }

    #[test]
    fn test_hop_mode_equality() {
        assert_eq!(HopMode::Direct, HopMode::Direct);
        assert_ne!(HopMode::Direct, HopMode::Light);
        assert_ne!(HopMode::Light, HopMode::Standard);
        assert_ne!(HopMode::Standard, HopMode::Paranoid);
    }

    // ==================== ChainEntry Tests ====================

    #[test]
    fn test_chain_entry_creation() {
        let entry = ChainEntry::new([1u8; 32], [2u8; 64], 3);

        assert_eq!(entry.pubkey, [1u8; 32]);
        assert_eq!(entry.signature, [2u8; 64]);
        assert_eq!(entry.hops_at_sign, 3);
    }

    #[test]
    fn test_chain_entry_zero_hops() {
        let entry = ChainEntry::new([1u8; 32], [0u8; 64], 0);
        assert_eq!(entry.hops_at_sign, 0);
    }

    #[test]
    fn test_chain_entry_max_hops() {
        let entry = ChainEntry::new([1u8; 32], [0u8; 64], 255);
        assert_eq!(entry.hops_at_sign, 255);
    }

    // ==================== SubscriptionTier Tests ====================

    #[test]
    fn test_subscription_tier_equality() {
        assert_eq!(SubscriptionTier::Basic, SubscriptionTier::Basic);
        assert_eq!(SubscriptionTier::Standard, SubscriptionTier::Standard);
        assert_eq!(SubscriptionTier::Premium, SubscriptionTier::Premium);
        assert_ne!(SubscriptionTier::Basic, SubscriptionTier::Standard);
        assert_ne!(SubscriptionTier::Standard, SubscriptionTier::Premium);
    }

    #[test]
    fn test_subscription_tier_serialization() {
        for tier in [SubscriptionTier::Basic, SubscriptionTier::Standard, SubscriptionTier::Premium] {
            let json = serde_json::to_string(&tier).unwrap();
            let restored: SubscriptionTier = serde_json::from_str(&json).unwrap();
            assert_eq!(tier, restored);
        }
    }

    // ==================== ForwardReceipt Tests ====================

    #[test]
    fn test_forward_receipt_signable_data() {
        let request_id = [1u8; 32];
        let receiver_pubkey = [2u8; 32];
        let data = ForwardReceipt::signable_data(&request_id, 3, &receiver_pubkey, 1000);

        // 32 (request_id) + 1 (shard_index) + 32 (receiver_pubkey) + 8 (timestamp) = 73
        assert_eq!(data.len(), 73);
        assert_eq!(&data[0..32], &request_id);
        assert_eq!(data[32], 3);
        assert_eq!(&data[33..65], &receiver_pubkey);
        assert_eq!(&data[65..73], &1000u64.to_le_bytes());
    }

    #[test]
    fn test_forward_receipt_signable_data_different_inputs() {
        let data1 = ForwardReceipt::signable_data(&[1u8; 32], 0, &[2u8; 32], 100);
        let data2 = ForwardReceipt::signable_data(&[1u8; 32], 1, &[2u8; 32], 100);
        // Different shard_index should produce different data
        assert_ne!(data1, data2);
    }

    // ==================== ExitInfo Tests ====================

    #[test]
    fn test_exit_info_creation() {
        let exit = ExitInfo {
            pubkey: [1u8; 32],
            address: "exit.example.com:9000".to_string(),
            region: ExitRegion::NorthAmerica,
            country_code: Some("US".to_string()),
            city: Some("New York".to_string()),
            reputation: 100,
            latency_ms: 50,
        };

        assert_eq!(exit.pubkey, [1u8; 32]);
        assert_eq!(exit.address, "exit.example.com:9000");
        assert_eq!(exit.region, ExitRegion::NorthAmerica);
        assert_eq!(exit.country_code, Some("US".to_string()));
        assert_eq!(exit.city, Some("New York".to_string()));
        assert_eq!(exit.reputation, 100);
        assert_eq!(exit.latency_ms, 50);
    }

    #[test]
    fn test_exit_info_zero_values() {
        let exit = ExitInfo {
            pubkey: [0u8; 32],
            address: String::new(),
            region: ExitRegion::Auto,
            country_code: None,
            city: None,
            reputation: 0,
            latency_ms: 0,
        };

        assert!(exit.address.is_empty());
        assert_eq!(exit.region, ExitRegion::Auto);
        assert_eq!(exit.reputation, 0);
    }

    // ==================== PeerInfo Tests ====================

    #[test]
    fn test_peer_info_exit() {
        let peer = PeerInfo {
            pubkey: [1u8; 32],
            address: "peer.example.com:8000".to_string(),
            is_exit: true,
        };

        assert!(peer.is_exit);
    }

    #[test]
    fn test_peer_info_relay() {
        let peer = PeerInfo {
            pubkey: [1u8; 32],
            address: "relay.example.com:8000".to_string(),
            is_exit: false,
        };

        assert!(!peer.is_exit);
    }

    // ==================== Serialization Tests ====================

    #[test]
    fn test_hop_mode_serialization() {
        let mode = HopMode::Standard;
        let json = serde_json::to_string(&mode).unwrap();
        let restored: HopMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, restored);
    }

    #[test]
    fn test_chain_entry_serialization() {
        let entry = ChainEntry::new([1u8; 32], [2u8; 64], 3);
        let json = serde_json::to_string(&entry).unwrap();
        let restored: ChainEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(entry.pubkey, restored.pubkey);
        assert_eq!(entry.signature, restored.signature);
        assert_eq!(entry.hops_at_sign, restored.hops_at_sign);
    }

    #[test]
    fn test_exit_info_serialization() {
        let exit = ExitInfo {
            pubkey: [1u8; 32],
            address: "test.com:9000".to_string(),
            region: ExitRegion::Europe,
            country_code: Some("DE".to_string()),
            city: Some("Frankfurt".to_string()),
            reputation: 50,
            latency_ms: 100,
        };

        let json = serde_json::to_string(&exit).unwrap();
        let restored: ExitInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(exit.pubkey, restored.pubkey);
        assert_eq!(exit.address, restored.address);
        assert_eq!(exit.region, restored.region);
        assert_eq!(exit.country_code, restored.country_code);
        assert_eq!(exit.city, restored.city);
        assert_eq!(exit.reputation, restored.reputation);
        assert_eq!(exit.latency_ms, restored.latency_ms);
    }

}
