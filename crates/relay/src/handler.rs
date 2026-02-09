//! Onion relay shard handler
//!
//! Handles incoming shards by peeling one onion layer to learn the next hop.
//! No plaintext routing metadata is visible — the relay only sees:
//! - Settlement data (blind_token, shard_id, payload_size, epoch) from its onion layer
//! - The next hop's PeerId and ephemeral key
//!
//! Gateway mode: when the peeled layer contains a tunnel_id, the relay
//! looks up the registered client PeerId and forwards directly.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{debug, info, warn};
use tunnelcraft_core::{Id, PublicKey, Shard, ForwardReceipt, TunnelCraftError};
use tunnelcraft_crypto::{SigningKeypair, EncryptionKeypair, peel_onion_layer, sign_forward_receipt};
use tunnelcraft_settlement::SettlementClient;

#[derive(Error, Debug)]
pub enum RelayError {
    /// Failed to peel onion layer (corrupted header or wrong key)
    #[error("Onion peel failed: {0}")]
    OnionPeelFailed(String),

    /// Tunnel ID not found in registrations (gateway mode)
    #[error("Tunnel not found: {0}")]
    TunnelNotFound(String),

    /// Internal relay error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<TunnelCraftError> for RelayError {
    fn from(e: TunnelCraftError) -> Self {
        RelayError::Internal(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, RelayError>;

/// Relay configuration
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Whether this relay can act as the last hop
    pub can_be_last_hop: bool,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            can_be_last_hop: true,
        }
    }
}

/// Registration of a tunnel_id → client PeerId mapping (gateway mode)
struct TunnelRegistration {
    /// Client PeerId bytes (to forward shards to)
    client_peer_id: Vec<u8>,
    /// When this registration expires
    expires_at: u64,
    /// When this was created
    #[allow(dead_code)]
    created_at: Instant,
}

/// Relay handler for processing onion-routed shards
pub struct RelayHandler {
    /// This relay's signing keypair (for ForwardReceipts)
    keypair: SigningKeypair,
    /// This relay's encryption keypair (for onion layer decryption)
    encryption_keypair: EncryptionKeypair,
    /// Tunnel registrations: tunnel_id → client PeerId (gateway mode)
    tunnel_registrations: HashMap<Id, TunnelRegistration>,
    /// Relay configuration
    #[allow(dead_code)]
    config: RelayConfig,
    /// Settlement client (optional)
    settlement_client: Option<Arc<SettlementClient>>,
}

impl RelayHandler {
    /// Create a new relay handler with signing and encryption keypairs
    pub fn new(keypair: SigningKeypair, encryption_keypair: EncryptionKeypair) -> Self {
        Self {
            keypair,
            encryption_keypair,
            tunnel_registrations: HashMap::new(),
            config: RelayConfig::default(),
            settlement_client: None,
        }
    }

    /// Create a relay handler with custom config
    pub fn with_config(keypair: SigningKeypair, encryption_keypair: EncryptionKeypair, config: RelayConfig) -> Self {
        Self {
            keypair,
            encryption_keypair,
            tunnel_registrations: HashMap::new(),
            config,
            settlement_client: None,
        }
    }

    /// Create a relay handler with settlement client
    pub fn with_settlement(
        keypair: SigningKeypair,
        encryption_keypair: EncryptionKeypair,
        config: RelayConfig,
        settlement_client: Arc<SettlementClient>,
    ) -> Self {
        Self {
            keypair,
            encryption_keypair,
            tunnel_registrations: HashMap::new(),
            config,
            settlement_client: Some(settlement_client),
        }
    }

    /// Set the settlement client
    pub fn set_settlement_client(&mut self, client: Arc<SettlementClient>) {
        self.settlement_client = Some(client);
    }

    /// Get this relay's signing public key
    pub fn pubkey(&self) -> PublicKey {
        self.keypair.public_key_bytes()
    }

    /// Get this relay's encryption public key
    pub fn encryption_pubkey(&self) -> [u8; 32] {
        self.encryption_keypair.public_key_bytes()
    }

    /// Handle an incoming shard by peeling one onion layer.
    ///
    /// Returns `(modified_shard, next_peer_id_bytes, forward_receipt, pool_pubkey, epoch)`.
    /// The caller (node.rs) forwards the shard to the returned next_peer and uses
    /// pool_pubkey + epoch to route the receipt into the correct proof queue.
    ///
    /// `sender_pubkey` comes from the libp2p connection (authenticated via Noise).
    pub fn handle_shard(
        &self,
        mut shard: Shard,
        sender_pubkey: PublicKey,
    ) -> Result<(Shard, Vec<u8>, ForwardReceipt, PublicKey, u64)> {
        // Peel one onion layer
        let layer = peel_onion_layer(
            &self.encryption_keypair.secret_key_bytes(),
            &shard.ephemeral_pubkey,
            &shard.header,
        ).map_err(|e| RelayError::OnionPeelFailed(e.to_string()))?;

        // Extract pool routing info before moving layer fields
        let pool_pubkey = layer.settlement.pool_pubkey;
        let epoch = layer.settlement.epoch;

        // Create ForwardReceipt from the settlement data in this layer
        // request_id is [0u8; 32] for onion shards (not used for dedup — use shard_id)
        let receipt = sign_forward_receipt(
            &self.keypair,
            &[0u8; 32], // request_id not available in onion mode
            &layer.settlement.shard_id,
            &sender_pubkey,
            &layer.settlement.blind_token,
            layer.settlement.payload_size,
            epoch,
        );

        // Determine next peer
        let next_peer = if let Some(tunnel_id) = &layer.tunnel_id {
            // Gateway mode: look up client PeerId from tunnel registration
            info!(
                "[SHARD-FLOW] GATEWAY tunnel lookup: tunnel_id={} (enc_key={}, {} tunnels registered)",
                hex::encode(&tunnel_id[..8]),
                hex::encode(&self.encryption_keypair.public_key_bytes()[..8]),
                self.tunnel_registrations.len(),
            );
            self.lookup_tunnel(tunnel_id)?
        } else {
            layer.next_peer_id.clone()
        };

        // Update shard for next hop
        shard.header = layer.remaining_header;
        shard.ephemeral_pubkey = layer.next_ephemeral_pubkey;

        Ok((shard, next_peer, receipt, pool_pubkey, epoch))
    }

    /// Register a tunnel_id → client PeerId mapping (called via TunnelSetup message).
    /// Any connected relay can act as a gateway.
    pub fn register_tunnel(&mut self, tunnel_id: Id, client_peer_id: Vec<u8>, expires_at: u64) {
        self.tunnel_registrations.insert(tunnel_id, TunnelRegistration {
            client_peer_id,
            expires_at,
            created_at: Instant::now(),
        });
        debug!("Tunnel registered: {} (total={})", hex::encode(&tunnel_id[..8]), self.tunnel_registrations.len());
    }

    /// Remove a tunnel registration
    pub fn unregister_tunnel(&mut self, tunnel_id: &Id) {
        self.tunnel_registrations.remove(tunnel_id);
        debug!("Tunnel unregistered: {} (total={})", hex::encode(&tunnel_id[..8]), self.tunnel_registrations.len());
    }

    /// Look up a client PeerId by tunnel_id (gateway mode)
    fn lookup_tunnel(&self, tunnel_id: &Id) -> Result<Vec<u8>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let reg = self.tunnel_registrations.get(tunnel_id)
            .ok_or_else(|| {
                warn!(
                    "Tunnel lookup miss: tunnel_id={} ({} registered tunnels)",
                    hex::encode(&tunnel_id[..8]),
                    self.tunnel_registrations.len(),
                );
                for (k, v) in &self.tunnel_registrations {
                    debug!(
                        "  registered tunnel={} -> client={}",
                        hex::encode(&k[..8]),
                        hex::encode(&v.client_peer_id[..8]),
                    );
                }
                RelayError::TunnelNotFound(hex::encode(&tunnel_id[..8]))
            })?;

        if reg.expires_at < now {
            return Err(RelayError::TunnelNotFound(
                format!("{} (expired)", hex::encode(&tunnel_id[..8]))
            ));
        }

        Ok(reg.client_peer_id.clone())
    }

    /// Get the number of active tunnel registrations
    pub fn tunnel_count(&self) -> usize {
        self.tunnel_registrations.len()
    }

    /// Clear expired tunnel registrations
    pub fn evict_expired_tunnels(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.tunnel_registrations.retain(|_, reg| reg.expires_at >= now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnelcraft_crypto::{EncryptionKeypair, build_onion_header};
    use tunnelcraft_core::OnionSettlement;

    fn make_handler() -> RelayHandler {
        let keypair = SigningKeypair::generate();
        let enc_keypair = EncryptionKeypair::generate();
        RelayHandler::new(keypair, enc_keypair)
    }

    fn make_settlement(idx: u8) -> OnionSettlement {
        OnionSettlement {
            blind_token: [idx; 32],
            shard_id: [idx + 100; 32],
            payload_size: 1024,
            epoch: 42,
            pool_pubkey: [0u8; 32],
        }
    }

    #[test]
    fn test_handle_shard_1_hop() {
        let relay1 = EncryptionKeypair::generate();
        let relay1_signing = SigningKeypair::generate();
        let exit = EncryptionKeypair::generate();

        let handler = RelayHandler::new(relay1_signing, relay1.clone());

        let settlement = vec![make_settlement(1)];
        let (header, ephemeral) = build_onion_header(
            &[(b"relay1_pid".as_slice(), &relay1.public_key_bytes())],
            (b"exit_pid".as_slice(), &exit.public_key_bytes()),
            &settlement,
            None,
        ).unwrap();

        let shard = Shard::new(
            ephemeral, header, vec![1, 2, 3],
            vec![0; 92],
        );

        let sender = [9u8; 32];
        let (modified, next_peer, receipt, _, _) = handler.handle_shard(shard, sender).unwrap();

        assert_eq!(next_peer, b"exit_pid");
        assert!(modified.header.is_empty()); // terminal layer
        assert_eq!(receipt.sender_pubkey, sender);
        assert_eq!(receipt.blind_token, [1u8; 32]);
    }

    #[test]
    fn test_handle_shard_2_hops() {
        let relay1 = EncryptionKeypair::generate();
        let relay1_signing = SigningKeypair::generate();
        let relay2 = EncryptionKeypair::generate();
        let relay2_signing = SigningKeypair::generate();
        let exit = EncryptionKeypair::generate();

        let handler1 = RelayHandler::new(relay1_signing, relay1.clone());
        let handler2 = RelayHandler::new(relay2_signing, relay2.clone());

        let settlement = vec![make_settlement(1), make_settlement(2)];
        let (header, ephemeral) = build_onion_header(
            &[
                (b"r1".as_slice(), &relay1.public_key_bytes()),
                (b"r2".as_slice(), &relay2.public_key_bytes()),
            ],
            (b"exit".as_slice(), &exit.public_key_bytes()),
            &settlement,
            None,
        ).unwrap();

        let shard = Shard::new(
            ephemeral, header, vec![1, 2, 3],
            vec![0; 92],
        );

        // Relay 1 peels
        let sender1 = [10u8; 32];
        let (shard2, next1, receipt1, _, _) = handler1.handle_shard(shard, sender1).unwrap();
        assert_eq!(next1, b"r2");
        assert!(!shard2.header.is_empty());
        assert_eq!(receipt1.blind_token, [1u8; 32]); // settlement[0]

        // Relay 2 peels
        let sender2 = [11u8; 32];
        let (shard3, next2, receipt2, _, _) = handler2.handle_shard(shard2, sender2).unwrap();
        assert_eq!(next2, b"exit");
        assert!(shard3.header.is_empty());
        assert_eq!(receipt2.blind_token, [2u8; 32]); // settlement[1]
    }

    #[test]
    fn test_wrong_key_fails() {
        let relay1 = EncryptionKeypair::generate();
        let wrong_key = EncryptionKeypair::generate();
        let wrong_signing = SigningKeypair::generate();
        let exit = EncryptionKeypair::generate();

        let handler = RelayHandler::new(wrong_signing, wrong_key);

        let settlement = vec![make_settlement(1)];
        let (header, ephemeral) = build_onion_header(
            &[(b"r1".as_slice(), &relay1.public_key_bytes())],
            (b"exit".as_slice(), &exit.public_key_bytes()),
            &settlement,
            None,
        ).unwrap();

        let shard = Shard::new(
            ephemeral, header, vec![1, 2, 3],
            vec![0; 92],
        );

        let result = handler.handle_shard(shard, [0u8; 32]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RelayError::OnionPeelFailed(_)));
    }

    #[test]
    fn test_tunnel_registration_and_gateway() {
        let relay = EncryptionKeypair::generate();
        let relay_signing = SigningKeypair::generate();
        let exit = EncryptionKeypair::generate();

        let mut handler = RelayHandler::new(relay_signing, relay.clone());

        let tunnel_id = [42u8; 32];
        let client_peer = b"client_peer_id".to_vec();
        let far_future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() + 600;

        handler.register_tunnel(tunnel_id, client_peer.clone(), far_future);
        assert_eq!(handler.tunnel_count(), 1);

        // Build onion with tunnel_id
        let settlement = vec![make_settlement(1)];
        let (header, ephemeral) = build_onion_header(
            &[(b"relay".as_slice(), &relay.public_key_bytes())],
            (b"gateway".as_slice(), &exit.public_key_bytes()),
            &settlement,
            Some(&tunnel_id),
        ).unwrap();

        let shard = Shard::new(
            ephemeral, header, vec![1, 2, 3],
            vec![0; 92],
        );

        let (_, next_peer, _, _, _) = handler.handle_shard(shard, [0u8; 32]).unwrap();
        // Gateway mode: should return the client peer ID
        assert_eq!(next_peer, client_peer);
    }

    #[test]
    fn test_tunnel_not_found() {
        let handler = make_handler();

        let unknown_tunnel = [99u8; 32];
        let result = handler.lookup_tunnel(&unknown_tunnel);
        assert!(matches!(result, Err(RelayError::TunnelNotFound(_))));
    }

    #[test]
    fn test_tunnel_expired() {
        let mut handler = make_handler();

        let tunnel_id = [42u8; 32];
        handler.register_tunnel(tunnel_id, b"client".to_vec(), 0); // Already expired

        let result = handler.lookup_tunnel(&tunnel_id);
        assert!(matches!(result, Err(RelayError::TunnelNotFound(_))));
    }

    #[test]
    fn test_evict_expired_tunnels() {
        let mut handler = make_handler();

        let far_future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() + 600;

        handler.register_tunnel([1u8; 32], b"a".to_vec(), 0);           // expired
        handler.register_tunnel([2u8; 32], b"b".to_vec(), far_future);  // valid

        assert_eq!(handler.tunnel_count(), 2);
        handler.evict_expired_tunnels();
        assert_eq!(handler.tunnel_count(), 1);
    }

    #[test]
    fn test_unregister_tunnel() {
        let mut handler = make_handler();

        let tunnel_id = [42u8; 32];
        handler.register_tunnel(tunnel_id, b"client".to_vec(), u64::MAX);
        assert_eq!(handler.tunnel_count(), 1);

        handler.unregister_tunnel(&tunnel_id);
        assert_eq!(handler.tunnel_count(), 0);
    }

    #[test]
    fn test_pubkey_and_encryption_pubkey() {
        let signing = SigningKeypair::generate();
        let encryption = EncryptionKeypair::generate();
        let signing_pub = signing.public_key_bytes();
        let enc_pub = encryption.public_key_bytes();

        let handler = RelayHandler::new(signing, encryption);
        assert_eq!(handler.pubkey(), signing_pub);
        assert_eq!(handler.encryption_pubkey(), enc_pub);
    }
}
