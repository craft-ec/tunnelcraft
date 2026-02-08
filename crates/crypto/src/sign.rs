use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use tunnelcraft_core::{ChainEntry, ForwardReceipt, Shard, TunnelCraftError};

use crate::keys::SigningKeypair;

/// Sign data with a signing keypair
pub fn sign_data(keypair: &SigningKeypair, data: &[u8]) -> [u8; 64] {
    let signature: Signature = keypair.signing_key.sign(data);
    signature.to_bytes()
}

/// Verify a signature
pub fn verify_signature(pubkey: &[u8; 32], data: &[u8], signature: &[u8; 64]) -> bool {
    let verifying_key = match VerifyingKey::from_bytes(pubkey) {
        Ok(vk) => vk,
        Err(_) => return false,
    };

    let signature = Signature::from_bytes(signature);

    verifying_key.verify(data, &signature).is_ok()
}

/// Sign a shard and add the signature to its chain
pub fn sign_shard(keypair: &SigningKeypair, shard: &mut Shard) {
    let data = shard.signable_data();
    let signature = sign_data(keypair, &data);
    shard.add_signature(keypair.public_key_bytes(), signature);
}

/// Verify all signatures in a shard's chain
pub fn verify_chain(shard: &Shard) -> Result<(), TunnelCraftError> {
    for (i, entry) in shard.chain.iter().enumerate() {
        // Use the hops value that was recorded at the time of signing
        let signable_data = shard.signable_data_with_hops(entry.hops_at_sign);
        if !verify_signature(&entry.pubkey, &signable_data, &entry.signature) {
            return Err(TunnelCraftError::InvalidChainSignature(i));
        }
    }

    Ok(())
}

/// Create a chain entry for a node (uses current hops_remaining)
pub fn create_chain_entry(keypair: &SigningKeypair, shard: &Shard) -> ChainEntry {
    let data = shard.signable_data();
    let signature = sign_data(keypair, &data);
    ChainEntry::new(keypair.public_key_bytes(), signature, shard.hops_remaining)
}

/// Sign a forward receipt proving we received a shard.
///
/// The receiving relay calls this to create a cryptographic proof of delivery.
/// The sending relay uses the receipt as on-chain settlement proof.
/// Uses shard_id (unique hash) so request and response shards produce distinct receipts.
///
/// `sender_pubkey` binds this receipt to the forwarding relay (anti-Sybil).
/// `user_proof` binds this receipt to the originating user's pool, preventing
/// colluding relays from creating fake receipts against other users' pools.
/// `epoch` prevents cross-epoch receipt replay.
pub fn sign_forward_receipt(
    keypair: &SigningKeypair,
    request_id: &[u8; 32],
    shard_id: &[u8; 32],
    sender_pubkey: &[u8; 32],
    user_proof: &[u8; 32],
    epoch: u64,
) -> ForwardReceipt {
    let receiver_pubkey = keypair.public_key_bytes();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let data = ForwardReceipt::signable_data(
        request_id,
        shard_id,
        sender_pubkey,
        &receiver_pubkey,
        user_proof,
        epoch,
        timestamp,
    );
    let signature = sign_data(keypair, &data);
    ForwardReceipt {
        request_id: *request_id,
        shard_id: *shard_id,
        sender_pubkey: *sender_pubkey,
        receiver_pubkey,
        user_proof: *user_proof,
        epoch,
        timestamp,
        signature,
    }
}

/// Verify a forward receipt's signature
pub fn verify_forward_receipt(receipt: &ForwardReceipt) -> bool {
    let data = ForwardReceipt::signable_data(
        &receipt.request_id,
        &receipt.shard_id,
        &receipt.sender_pubkey,
        &receipt.receiver_pubkey,
        &receipt.user_proof,
        receipt.epoch,
        receipt.timestamp,
    );
    verify_signature(&receipt.receiver_pubkey, &data, &receipt.signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let keypair = SigningKeypair::generate();
        let data = b"Hello, TunnelCraft!";

        let signature = sign_data(&keypair, data);
        assert!(verify_signature(
            &keypair.public_key_bytes(),
            data,
            &signature
        ));

        // Wrong data should fail
        assert!(!verify_signature(
            &keypair.public_key_bytes(),
            b"Wrong data",
            &signature
        ));
    }

    #[test]
    fn test_wrong_pubkey_fails() {
        let keypair1 = SigningKeypair::generate();
        let keypair2 = SigningKeypair::generate();
        let data = b"Test data";

        let signature = sign_data(&keypair1, data);

        // Verification with wrong pubkey should fail
        assert!(!verify_signature(
            &keypair2.public_key_bytes(),
            data,
            &signature
        ));
    }
}
