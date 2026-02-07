use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// 32-byte identifier
pub type Id = [u8; 32];

/// 32-byte public key
pub type PublicKey = [u8; 32];

/// Chain-signed proof of user's credit balance at end of epoch
///
/// Users include this with requests to prove they have credits.
/// Exits/relays verify the chain signature before processing.
/// Users track local consumption to avoid post-reconciliation penalties.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditProof {
    /// User's public key
    pub user_pubkey: PublicKey,
    /// Credit balance at epoch end
    pub balance: u64,
    /// Epoch number this proof is valid for
    pub epoch: u64,
    /// Chain's signature over (user_pubkey, balance, epoch)
    #[serde(with = "BigArray")]
    pub chain_signature: Signature,
}

impl CreditProof {
    /// Create a new credit proof
    pub fn new(user_pubkey: PublicKey, balance: u64, epoch: u64, chain_signature: Signature) -> Self {
        Self {
            user_pubkey,
            balance,
            epoch,
            chain_signature,
        }
    }

    /// Get the data that the chain signs
    pub fn signable_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(32 + 8 + 8);
        data.extend_from_slice(&self.user_pubkey);
        data.extend_from_slice(&self.balance.to_le_bytes());
        data.extend_from_slice(&self.epoch.to_le_bytes());
        data
    }
}

/// 64-byte signature (use BigArray for serde support)
pub type Signature = [u8; 64];

/// Request status in the settlement system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestStatus {
    /// Exit has settled the request, waiting for response settlement
    Pending,
    /// Last relay has settled the response with TCP ACK
    Complete,
    /// Request timed out, credits refunded
    Expired,
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

/// Request settlement data submitted by exit node
///
/// Records work done for reconciliation. No individual token burning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSettlement {
    pub request_id: Id,
    pub user_pubkey: PublicKey,
    /// User's credit proof (chain-signed epoch balance)
    pub credit_proof: CreditProof,
    /// Signature chains from request shards (proves relay work)
    pub request_chains: Vec<Vec<ChainEntry>>,
}

/// Response shard settlement data submitted by last relay
///
/// Each response shard is settled independently.
/// Network-level TCP ACK proves delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseShardSettlement {
    pub request_id: Id,
    pub shard_id: Id,
    /// Signature chain for this shard (Exit → Relays → User)
    pub response_chain: Vec<ChainEntry>,
}

/// Points earned by a node for work done
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkClaim {
    pub request_id: Id,
    pub node_pubkey: PublicKey,
    pub points: u64,
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

    // ==================== RequestStatus Tests ====================

    #[test]
    fn test_request_status_values() {
        assert_ne!(RequestStatus::Pending, RequestStatus::Complete);
        assert_ne!(RequestStatus::Complete, RequestStatus::Expired);
        assert_ne!(RequestStatus::Expired, RequestStatus::Pending);
    }

    #[test]
    fn test_request_status_clone() {
        let status = RequestStatus::Pending;
        let cloned = status;
        assert_eq!(status, cloned);
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

    // ==================== RequestSettlement Tests ====================

    fn test_credit_proof(user_pubkey: PublicKey) -> CreditProof {
        CreditProof {
            user_pubkey,
            balance: 1000,
            epoch: 1,
            chain_signature: [0u8; 64],
        }
    }

    #[test]
    fn test_request_settlement_creation() {
        let user_pubkey = [3u8; 32];
        let settlement = RequestSettlement {
            request_id: [1u8; 32],
            user_pubkey,
            credit_proof: test_credit_proof(user_pubkey),
            request_chains: vec![
                vec![ChainEntry::new([4u8; 32], [0u8; 64], 3)],
            ],
        };

        assert_eq!(settlement.request_id, [1u8; 32]);
        assert_eq!(settlement.credit_proof.balance, 1000);
        assert_eq!(settlement.request_chains.len(), 1);
    }

    #[test]
    fn test_request_settlement_multiple_chains() {
        let user_pubkey = [3u8; 32];
        let settlement = RequestSettlement {
            request_id: [1u8; 32],
            user_pubkey,
            credit_proof: test_credit_proof(user_pubkey),
            request_chains: vec![
                vec![ChainEntry::new([4u8; 32], [0u8; 64], 3)],
                vec![ChainEntry::new([5u8; 32], [0u8; 64], 3)],
                vec![ChainEntry::new([6u8; 32], [0u8; 64], 3)],
            ],
        };

        assert_eq!(settlement.request_chains.len(), 3);
    }

    #[test]
    fn test_request_settlement_empty_chains() {
        let user_pubkey = [3u8; 32];
        let settlement = RequestSettlement {
            request_id: [1u8; 32],
            user_pubkey,
            credit_proof: test_credit_proof(user_pubkey),
            request_chains: vec![],
        };

        assert!(settlement.request_chains.is_empty());
    }

    // ==================== ResponseShardSettlement Tests ====================

    #[test]
    fn test_response_shard_settlement_creation() {
        let settlement = ResponseShardSettlement {
            request_id: [1u8; 32],
            shard_id: [3u8; 32],
            response_chain: vec![ChainEntry::new([2u8; 32], [0u8; 64], 3)],
        };

        assert_eq!(settlement.request_id, [1u8; 32]);
        assert_eq!(settlement.shard_id, [3u8; 32]);
        assert_eq!(settlement.response_chain.len(), 1);
    }

    // ==================== CreditProof Tests ====================

    #[test]
    fn test_credit_proof_creation() {
        let user_pubkey = [42u8; 32];
        let proof = CreditProof {
            user_pubkey,
            balance: 1000,
            epoch: 5,
            chain_signature: [1u8; 64],
        };

        assert_eq!(proof.user_pubkey, user_pubkey);
        assert_eq!(proof.balance, 1000);
        assert_eq!(proof.epoch, 5);
    }

    #[test]
    fn test_credit_proof_equality() {
        let proof1 = CreditProof {
            user_pubkey: [1u8; 32],
            balance: 500,
            epoch: 1,
            chain_signature: [0u8; 64],
        };

        let proof2 = CreditProof {
            user_pubkey: [1u8; 32],
            balance: 500,
            epoch: 1,
            chain_signature: [0u8; 64],
        };

        // Same values should be equal
        assert_eq!(proof1.user_pubkey, proof2.user_pubkey);
        assert_eq!(proof1.balance, proof2.balance);
        assert_eq!(proof1.epoch, proof2.epoch);
    }

    // ==================== WorkClaim Tests ====================

    #[test]
    fn test_work_claim_creation() {
        let claim = WorkClaim {
            request_id: [1u8; 32],
            node_pubkey: [2u8; 32],
            points: 100,
        };

        assert_eq!(claim.request_id, [1u8; 32]);
        assert_eq!(claim.node_pubkey, [2u8; 32]);
        assert_eq!(claim.points, 100);
    }

    #[test]
    fn test_work_claim_zero_points() {
        let claim = WorkClaim {
            request_id: [0u8; 32],
            node_pubkey: [0u8; 32],
            points: 0,
        };

        assert_eq!(claim.points, 0);
    }

    #[test]
    fn test_work_claim_max_points() {
        let claim = WorkClaim {
            request_id: [0u8; 32],
            node_pubkey: [0u8; 32],
            points: u64::MAX,
        };

        assert_eq!(claim.points, u64::MAX);
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
