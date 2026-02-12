//! SP1 ZK prover implementation.
//!
//! Uses the SP1 zkVM to generate and verify ZK proofs over batches
//! of ForwardReceipts. The guest program verifies sender/epoch consistency,
//! builds a Merkle tree, and commits the root + batch count + sender.
//!
//! `ProverClient::from_env()` reads the `SP1_PROVER` env var:
//! - `cpu`     — local CPU proving (dev/test)
//! - `network` — Succinct Prover Network (production, also needs `NETWORK_PRIVATE_KEY`)
//! - unset     — defaults to local CPU

use tracing::{info, warn};

use sp1_sdk::{include_elf, EnvProver, ProverClient, SP1Stdin};
use tunnelcraft_core::ForwardReceipt;
use tunnelcraft_prover_guest_types::{GuestInput, GuestOutput, GuestReceipt};

use crate::traits::{ProofOutput, Prover, ProverError};

/// The guest ELF binary, embedded at build time by sp1_build.
const ELF: &[u8] = include_elf!("tunnelcraft-prover-guest");

/// SP1 ZK prover.
///
/// Generates compressed proofs by running the guest program inside the SP1 VM.
/// `ProverClient::from_env()` selects local CPU or Succinct Network based on
/// the `SP1_PROVER` environment variable.
pub struct Sp1Prover {
    client: EnvProver,
}

impl Sp1Prover {
    pub fn new() -> Self {
        Self {
            client: ProverClient::from_env(),
        }
    }

    /// Convert a ForwardReceipt to a GuestReceipt for the guest program.
    fn to_guest_receipt(receipt: &ForwardReceipt) -> GuestReceipt {
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&receipt.signature);

        GuestReceipt {
            request_id: receipt.request_id,
            shard_id: receipt.shard_id,
            sender_pubkey: receipt.sender_pubkey,
            receiver_pubkey: receipt.receiver_pubkey,
            blind_token: receipt.blind_token,
            payload_size: receipt.payload_size,
            epoch: receipt.epoch,
            timestamp: receipt.timestamp,
            signature,
        }
    }
}

impl Default for Sp1Prover {
    fn default() -> Self {
        Self::new()
    }
}

impl Prover for Sp1Prover {
    fn prove(&self, batch: &[ForwardReceipt]) -> Result<ProofOutput, ProverError> {
        if batch.is_empty() {
            return Err(ProverError::EmptyBatch);
        }

        let input = GuestInput {
            receipts: batch.iter().map(Self::to_guest_receipt).collect(),
        };

        info!("Starting SP1 prove for {} receipts", batch.len());

        let t0 = std::time::Instant::now();

        // Write input to stdin
        let mut stdin = SP1Stdin::new();
        stdin.write(&input);

        // Setup proving and verifying keys
        let (pk, _vk) = self.client.setup(ELF);

        // Generate compressed proof (works for both local CPU and network)
        let mut proof = self.client
            .prove(&pk, &stdin)
            .compressed()
            .run()
            .map_err(|e| ProverError::ProofFailed(format!("SP1 prove failed: {}", e)))?;

        // Read committed output from proof public values
        let output: GuestOutput = proof
            .public_values
            .read();

        info!(
            "SP1 prove complete: root={}, batch_count={}, sender={}, elapsed={:?}",
            hex::encode(&output.root[..8]),
            output.batch_count,
            hex::encode(&output.sender_pubkey[..8]),
            t0.elapsed(),
        );

        // Serialize proof for transport
        let proof_bytes = bincode::serialize(&proof)
            .map_err(|e| ProverError::ProofFailed(format!("failed to serialize proof: {}", e)))?;

        Ok(ProofOutput {
            new_root: output.root,
            proof: proof_bytes,
        })
    }

    fn verify(&self, root: &[u8; 32], proof: &[u8], batch_size: u64) -> Result<bool, ProverError> {
        let mut proof: sp1_sdk::SP1ProofWithPublicValues = bincode::deserialize(proof)
            .map_err(|e| ProverError::VerificationFailed(format!("failed to deserialize proof: {}", e)))?;

        let (_pk, vk) = self.client.setup(ELF);

        if let Err(e) = self.client.verify(&proof, &vk) {
            warn!("SP1 verification failed: {}", e);
            return Ok(false);
        }

        let output: GuestOutput = proof.public_values.read();

        Ok(output.root == *root && output.batch_count == batch_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnelcraft_crypto::{SigningKeypair, sign_forward_receipt};

    fn make_batch(count: usize) -> Vec<ForwardReceipt> {
        let kp = SigningKeypair::generate();
        let sender = [0xFFu8; 32];
        (0..count)
            .map(|i| {
                let mut rid = [0u8; 32];
                let mut rpub = [0u8; 32];
                rid[..8].copy_from_slice(&(i as u64).to_le_bytes());
                rpub[..8].copy_from_slice(&((i + 10) as u64).to_le_bytes());
                sign_forward_receipt(&kp, &rid, &rpub, &sender, &[0u8; 32], 1024, 0)
            })
            .collect()
    }

    #[test]
    fn test_sp1_prove_5_receipts() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("tunnelcraft_prover=info")
            .with_test_writer()
            .try_init();

        let prover = Sp1Prover::new();
        let batch = make_batch(5);

        let start = std::time::Instant::now();
        let output = prover.prove(&batch).unwrap();
        let elapsed = start.elapsed();

        println!("SP1 prove 5 receipts: {:?}", elapsed);
        println!("root: {}", hex::encode(&output.new_root[..8]));
        println!("proof size: {} bytes", output.proof.len());

        assert_ne!(output.new_root, [0u8; 32]);
        assert!(!output.proof.is_empty());

        // Verify round-trip
        let verified = prover.verify(&output.new_root, &output.proof, 5).unwrap();
        println!("verify: {}", verified);
        assert!(verified);
    }
}
