//! Subscription gossipsub message types
//!
//! Users announce their subscription status via the
//! `tunnelcraft/subscriptions/1.0.0` gossipsub topic. Relays cache these
//! announcements and periodically verify them on-chain in batches.
//! Subscribed users get priority routing; unsubscribed get best-effort.

use serde::{Deserialize, Serialize};

/// Subscription announcement broadcast by clients via gossipsub.
///
/// When a client connects, it announces its subscription status.
/// Relays cache this and give priority to subscribed users.
/// Periodic on-chain verification prevents fake announcements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionAnnouncement {
    /// User's public key (ed25519)
    pub user_pubkey: [u8; 32],
    /// Claimed subscription tier
    pub tier: u8, // 0=Basic, 1=Standard, 2=Premium, 255=None
    /// Subscription epoch (from UserMeta.next_epoch at subscribe time)
    pub epoch: u64,
    /// Claimed expiry timestamp (unix seconds)
    pub expires_at: u64,
    /// Timestamp of this announcement
    pub timestamp: u64,
    /// User's ed25519 signature over (user_pubkey || tier || epoch || expires_at || timestamp)
    pub signature: Vec<u8>,
}

impl SubscriptionAnnouncement {
    /// Serialize to bytes (bincode)
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("SubscriptionAnnouncement serialization cannot fail")
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// Data that gets signed (excludes signature field)
    pub fn signable_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(32 + 1 + 8 + 8 + 8);
        data.extend_from_slice(&self.user_pubkey);
        data.push(self.tier);
        data.extend_from_slice(&self.epoch.to_le_bytes());
        data.extend_from_slice(&self.expires_at.to_le_bytes());
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data
    }
}
