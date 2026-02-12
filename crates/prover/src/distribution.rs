//! Distribution Groth16 prover for on-chain verification.
//!
//! Generates a Groth16 proof that the aggregator correctly computed
//! the distribution Merkle tree from relay entries. This proof is
//! verified on-chain by `sp1-solana` in the `post_distribution` instruction.
//!
//! The guest program (`distribution-guest`) sorts entries, builds the
//! Merkle tree, and commits the root + metadata as public values.
//!
//! `ProverClient::from_env()` reads `SP1_PROVER`:
//! - `network` — Succinct Prover Network (production, needs `NETWORK_PRIVATE_KEY`)
//! - `cpu`     — local CPU (very slow for Groth16, not recommended)
//! - unset     — defaults to local CPU

use tracing::info;

use sp1_sdk::{include_elf, EnvProver, HashableKey, ProverClient, SP1Stdin};
use tunnelcraft_distribution_guest_types::DistributionInput;

/// The distribution guest ELF binary, embedded at build time by sp1_build.
const DISTRIBUTION_ELF: &[u8] = include_elf!("tunnelcraft-distribution-guest");

/// A Groth16 proof over the distribution Merkle tree construction.
///
/// Contains the raw proof bytes and public values that the on-chain
/// program needs for verification via `sp1-solana`.
#[derive(Debug, Clone)]
pub struct DistributionGroth16Proof {
    /// Raw Groth16 proof bytes (~256 bytes)
    pub proof_bytes: Vec<u8>,
    /// Public values committed by the guest (84 bytes fixed layout)
    pub public_values: Vec<u8>,
    /// Verification key hash ("0x..." hex string)
    pub vkey_hash: String,
}

/// Groth16 distribution prover.
///
/// Generates proofs that the distribution Merkle tree was correctly
/// constructed from relay entries. These proofs are verified on-chain.
pub struct DistributionProver {
    client: EnvProver,
}

impl DistributionProver {
    pub fn new() -> Self {
        Self {
            client: ProverClient::from_env(),
        }
    }

    /// Get the verification key hash for the distribution guest program.
    ///
    /// This value must match the `DISTRIBUTION_VKEY_HASH` constant in
    /// the on-chain program. Run the `vkey_hash` example to compute it.
    pub fn vkey_hash(&self) -> String {
        let (_pk, vk) = self.client.setup(DISTRIBUTION_ELF);
        vk.bytes32()
    }

    /// Generate a Groth16 proof over the distribution construction.
    ///
    /// The proof attests that:
    /// 1. Entries were sorted by relay_pubkey
    /// 2. Merkle tree was correctly built (matching off-chain `MerkleTree`)
    /// 3. Total bytes and entry count are correct
    /// 4. Pool pubkey and epoch are bound to the proof
    pub fn prove_distribution(
        &self,
        entries: &[([u8; 32], u64)],
        pool_pubkey: [u8; 32],
        epoch: u64,
    ) -> Result<DistributionGroth16Proof, String> {
        if entries.is_empty() {
            return Err("empty distribution entries".to_string());
        }

        let input = DistributionInput {
            entries: entries.to_vec(),
            pool_pubkey,
            epoch,
        };

        info!(
            "Starting distribution Groth16 prove for {} entries, pool={}, epoch={}",
            entries.len(),
            hex::encode(&pool_pubkey[..8]),
            epoch,
        );

        let t0 = std::time::Instant::now();

        let mut stdin = SP1Stdin::new();
        stdin.write(&input);

        let (pk, vk) = self.client.setup(DISTRIBUTION_ELF);

        let proof = self.client
            .prove(&pk, &stdin)
            .groth16()
            .run()
            .map_err(|e| format!("Distribution Groth16 prove failed: {}", e))?;

        let public_values = proof.public_values.as_slice().to_vec();
        let proof_bytes = bincode::serialize(&proof.proof)
            .map_err(|e| format!("failed to serialize Groth16 proof: {}", e))?;

        let vkey_hash = vk.bytes32();

        info!(
            "Distribution Groth16 prove complete: proof_size={}, public_values_size={}, vkey={}, elapsed={:?}",
            proof_bytes.len(),
            public_values.len(),
            &vkey_hash[..16],
            t0.elapsed(),
        );

        Ok(DistributionGroth16Proof {
            proof_bytes,
            public_values,
            vkey_hash,
        })
    }
}

impl Default for DistributionProver {
    fn default() -> Self {
        Self::new()
    }
}
