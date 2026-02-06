use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use tunnelcraft_core::{ChainEntry, Shard, TunnelCraftError};

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
