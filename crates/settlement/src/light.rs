//! Light Protocol integration for off-chain claim preparation.
//!
//! Provides:
//! - Photon RPC client for validity proofs
//! - ClaimReceipt address derivation (matching on-chain `derive_address` v2)
//! - Remaining accounts builder for Light Protocol CPI

use solana_sdk::{
    instruction::AccountMeta,
    pubkey::Pubkey,
};
use light_sdk_types::address::v2::derive_address;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::{ClaimLightParams, SettlementError, Result};
use crate::types::LightTreeConfig;

// ============================================================================
// Devnet Constants
// ============================================================================

/// Light System Program: `SySTEM1eSU2p4BGQfQpimFEWWSC1XDFeun3Nqzz3rT7`
const LIGHT_SYSTEM_PROGRAM: Pubkey = pubkey_from_bs58(
    &light_sdk_types::constants::LIGHT_SYSTEM_PROGRAM_ID,
);

/// Registered Program PDA: `35hkDgaAKwMCaxRz2ocSZ6NaUrtKkyNqU6c4RV3tYJRh`
const REGISTERED_PROGRAM_PDA: Pubkey = pubkey_from_bs58(
    &light_sdk_types::constants::REGISTERED_PROGRAM_PDA,
);

/// Account Compression Authority PDA: `HwXnGK3tPkkVY6P439H2p68AxpeuWXd5PcrAxFpbmfbA`
const ACCOUNT_COMPRESSION_AUTHORITY: Pubkey = pubkey_from_bs58(
    &light_sdk_types::constants::ACCOUNT_COMPRESSION_AUTHORITY_PDA,
);

/// Account Compression Program: `compr6CUsB5m2jS4Y3831ztGSTnDpnKJTKS95d64XVq`
const ACCOUNT_COMPRESSION_PROGRAM: Pubkey = pubkey_from_bs58(
    &light_compressed_account::constants::ACCOUNT_COMPRESSION_PROGRAM_ID,
);

/// Devnet v2 address tree: `amt2kaJA14v3urZbZvnc5v2np8jqvc4Z8zDep5wbtzx`
pub const ADDRESS_TREE_V2: [u8; 32] = light_sdk_types::constants::ADDRESS_TREE_V2;

/// Devnet v2 output state tree: `bmt1LryLZUMmF7ZtqESaw7wifBXLfXHQYoE4GAmrahU`
/// From cloakcraft constants.ts — not in light-sdk-types
pub const OUTPUT_STATE_TREE_V2: [u8; 32] = bs58_to_bytes("bmt1LryLZUMmF7ZtqESaw7wifBXLfXHQYoE4GAmrahU");

/// Devnet v2 output queue: `oq1na8gojfdUhsfCpyjNt6h4JaDWtHf1yQj4koBWfto`
/// From cloakcraft constants.ts — not in light-sdk-types
pub const OUTPUT_QUEUE_V2: [u8; 32] = bs58_to_bytes("oq1na8gojfdUhsfCpyjNt6h4JaDWtHf1yQj4koBWfto");

/// Seed prefix for ClaimReceipt address (must match on-chain `ClaimReceipt::SEED_PREFIX`)
const CLAIM_RECEIPT_SEED: &[u8] = b"claim_receipt";

// ============================================================================
// Compile-time helpers
// ============================================================================

/// Convert a `[u8; 32]` constant to `Pubkey` at compile time.
const fn pubkey_from_bs58(bytes: &[u8; 32]) -> Pubkey {
    Pubkey::new_from_array(*bytes)
}

/// Decode a base58 string to `[u8; 32]` at compile time.
///
/// Only supports the standard Bitcoin base58 alphabet.
/// Panics at compile time if the decoded output is not exactly 32 bytes.
const fn bs58_to_bytes(s: &str) -> [u8; 32] {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    const fn char_to_val(c: u8) -> u8 {
        let mut i = 0;
        while i < ALPHABET.len() {
            if ALPHABET[i] == c {
                return i as u8;
            }
            i += 1;
        }
        panic!("invalid base58 character");
    }

    let bytes = s.as_bytes();
    // Work buffer (big-endian accumulator)
    let mut buf = [0u8; 64];
    let mut buf_len: usize = 0;

    let mut i = 0;
    while i < bytes.len() {
        let val = char_to_val(bytes[i]) as u32;
        let mut j = 0;
        let mut carry = val;
        while j < buf_len {
            carry += (buf[j] as u32) * 58;
            buf[j] = (carry & 0xFF) as u8;
            carry >>= 8;
            j += 1;
        }
        while carry > 0 {
            buf[buf_len] = (carry & 0xFF) as u8;
            carry >>= 8;
            buf_len += 1;
        }
        i += 1;
    }

    // Count leading '1's → leading zero bytes
    let mut leading = 0;
    while leading < bytes.len() && bytes[leading] == b'1' {
        leading += 1;
    }

    let total = leading + buf_len;
    if total != 32 {
        panic!("bs58 decoded length is not 32 bytes");
    }

    let mut out = [0u8; 32];
    // leading zeros are already 0 in `out`
    // copy buf in reverse (buf is little-endian)
    let mut k = 0;
    while k < buf_len {
        out[leading + k] = buf[buf_len - 1 - k];
        k += 1;
    }
    out
}

// ============================================================================
// PhotonClient — Helius Photon JSON-RPC
// ============================================================================

/// Photon validity proof response
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PhotonResponse {
    result: Option<PhotonResult>,
    error: Option<PhotonRpcError>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PhotonResult {
    value: PhotonProofValue,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PhotonProofValue {
    compressed_proof: PhotonCompressedProof,
    root_indices: Vec<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PhotonCompressedProof {
    a: Vec<u8>,
    b: Vec<u8>,
    c: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize)]
struct PhotonRpcError {
    code: i64,
    message: String,
}

/// Photon JSON-RPC request body
#[derive(Serialize)]
struct PhotonRequest {
    jsonrpc: &'static str,
    id: &'static str,
    method: &'static str,
    params: PhotonParams,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PhotonParams {
    new_addresses_with_trees: Vec<PhotonAddressWithTree>,
}

#[derive(Serialize)]
struct PhotonAddressWithTree {
    address: String,
    tree: String,
}

/// Client for Helius Photon RPC (Light Protocol indexer).
pub struct PhotonClient {
    url: String,
    http: reqwest::Client,
}

impl PhotonClient {
    /// Create with an explicit URL.
    pub fn new(url: String) -> Self {
        Self {
            url,
            http: reqwest::Client::new(),
        }
    }

    /// Create from RPC URL + optional Helius API key.
    ///
    /// If `api_key` is provided, uses `https://devnet.helius-rpc.com?api-key=<key>`.
    /// Otherwise uses the raw `rpc_url`.
    pub fn from_config(rpc_url: &str, api_key: Option<&str>) -> Self {
        let url = match api_key {
            Some(key) => {
                // Determine network from rpc_url
                let network = if rpc_url.contains("mainnet") {
                    "mainnet"
                } else {
                    "devnet"
                };
                format!("https://{network}.helius-rpc.com?api-key={key}")
            }
            None => rpc_url.to_string(),
        };
        Self::new(url)
    }

    /// Fetch a non-inclusion validity proof for a new compressed address.
    ///
    /// Calls Photon's `getValidityProof` RPC method with the address and tree.
    /// Retries up to 3 times with exponential backoff (500ms base).
    pub async fn get_validity_proof(
        &self,
        address: &[u8; 32],
        tree: &[u8; 32],
    ) -> Result<PhotonValidityProof> {
        let address_b58 = bs58::encode(address).into_string();
        let tree_b58 = bs58::encode(tree).into_string();

        debug!("Fetching validity proof for address {} tree {}", &address_b58[..8], &tree_b58[..8]);

        let body = PhotonRequest {
            jsonrpc: "2.0",
            id: "tunnelcraft-1",
            method: "getValidityProof",
            params: PhotonParams {
                new_addresses_with_trees: vec![PhotonAddressWithTree {
                    address: address_b58,
                    tree: tree_b58,
                }],
            },
        };

        let mut last_err = SettlementError::RpcError("no attempts made".into());
        for attempt in 0..3u32 {
            if attempt > 0 {
                let delay = std::time::Duration::from_millis(500 * 2u64.pow(attempt - 1));
                tokio::time::sleep(delay).await;
            }

            match self.http.post(&self.url).json(&body).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if !status.is_success() {
                        last_err = SettlementError::RpcError(
                            format!("Photon HTTP {}", status),
                        );
                        continue;
                    }

                    match resp.json::<PhotonResponse>().await {
                        Ok(parsed) => {
                            if let Some(err) = parsed.error {
                                last_err = SettlementError::RpcError(
                                    format!("Photon RPC error {}: {}", err.code, err.message),
                                );
                                continue;
                            }

                            let result = parsed.result.ok_or_else(|| {
                                SettlementError::RpcError("Photon: empty result".into())
                            })?;

                            let proof = &result.value.compressed_proof;
                            let root_index = result.value.root_indices
                                .first()
                                .copied()
                                .unwrap_or(0) as u16;

                            let mut a = [0u8; 32];
                            let mut b = [0u8; 64];
                            let mut c = [0u8; 32];

                            if proof.a.len() >= 32 {
                                a.copy_from_slice(&proof.a[..32]);
                            }
                            if proof.b.len() >= 64 {
                                b.copy_from_slice(&proof.b[..64]);
                            }
                            if proof.c.len() >= 32 {
                                c.copy_from_slice(&proof.c[..32]);
                            }

                            return Ok(PhotonValidityProof {
                                a,
                                b,
                                c,
                                root_index,
                            });
                        }
                        Err(e) => {
                            last_err = SettlementError::RpcError(
                                format!("Photon parse error: {}", e),
                            );
                        }
                    }
                }
                Err(e) => {
                    last_err = SettlementError::RpcError(
                        format!("Photon request error: {}", e),
                    );
                }
            }
        }

        Err(last_err)
    }
}

/// Parsed validity proof from Photon.
#[derive(Debug, Clone)]
pub struct PhotonValidityProof {
    pub a: [u8; 32],
    pub b: [u8; 64],
    pub c: [u8; 32],
    pub root_index: u16,
}

// ============================================================================
// Address Derivation
// ============================================================================

/// Derive the ClaimReceipt compressed address deterministically.
///
/// Seeds: `["claim_receipt", user_pubkey, epoch_le, relay_pubkey]`
/// Must match the on-chain `derive_address` call in the claim instruction.
pub fn derive_claim_receipt_address(
    user_pubkey: &[u8; 32],
    epoch: u64,
    relay_pubkey: &[u8; 32],
    address_tree: &[u8; 32],
    program_id: &[u8; 32],
) -> [u8; 32] {
    let epoch_le = epoch.to_le_bytes();
    let (address, _seed) = derive_address(
        &[
            CLAIM_RECEIPT_SEED,
            user_pubkey.as_ref(),
            epoch_le.as_ref(),
            relay_pubkey.as_ref(),
        ],
        address_tree,
        program_id,
    );
    address
}

// ============================================================================
// Remaining Accounts Builder
// ============================================================================

/// Result of building remaining accounts for the claim instruction.
pub struct ClaimRemainingAccounts {
    /// The AccountMeta list to append to the instruction.
    pub accounts: Vec<AccountMeta>,
    /// Index of address tree within the tree accounts section.
    pub address_tree_pubkey_index: u8,
    /// Index of address queue within the tree accounts section (same as address tree for v2).
    pub address_queue_pubkey_index: u8,
    /// Index of output state tree/queue within the tree accounts section.
    pub output_tree_index: u8,
}

/// Build the remaining accounts list for Light Protocol CPI in the claim instruction.
///
/// Layout (matches `CpiAccounts::new` v2 expectations):
/// ```text
/// [0] Light System Program          (readonly)
/// [1] CPI Signer PDA                (readonly)
/// [2] Registered Program PDA        (readonly)
/// [3] Account Compression Authority  (readonly)
/// [4] Account Compression Program    (readonly)
/// [5] System Program                 (readonly)
/// --- tree accounts (indices relative to [6]) ---
/// [6] Address Tree v2               (writable)
/// [7] Output Queue v2               (writable)
/// ```
pub fn build_claim_remaining_accounts(
    program_id: &[u8; 32],
    trees: &LightTreeConfig,
) -> ClaimRemainingAccounts {
    let cpi_signer = Pubkey::find_program_address(
        &[b"cpi_authority"],
        &Pubkey::new_from_array(*program_id),
    ).0;

    let address_tree = Pubkey::new_from_array(trees.address_tree);
    let output_queue = Pubkey::new_from_array(trees.output_queue);

    let accounts = vec![
        // System accounts [0..6]
        AccountMeta::new_readonly(LIGHT_SYSTEM_PROGRAM, false),
        AccountMeta::new_readonly(cpi_signer, false),
        AccountMeta::new_readonly(REGISTERED_PROGRAM_PDA, false),
        AccountMeta::new_readonly(ACCOUNT_COMPRESSION_AUTHORITY, false),
        AccountMeta::new_readonly(ACCOUNT_COMPRESSION_PROGRAM, false),
        AccountMeta::new_readonly(solana_sdk_ids::system_program::id(), false),
        // Tree accounts [6..]
        AccountMeta::new(address_tree, false),
        AccountMeta::new(output_queue, false),
    ];

    // Tree indices are relative to the tree accounts section (starting at index 6)
    // address_tree is at tree[0], output_queue is at tree[1]
    ClaimRemainingAccounts {
        accounts,
        address_tree_pubkey_index: 0,
        address_queue_pubkey_index: 0, // v2: address queue = address tree
        output_tree_index: 1,
    }
}

// ============================================================================
// Combined Preparation
// ============================================================================

/// Everything needed to execute a claim with Light Protocol.
pub struct ClaimProofResult {
    /// Populated ClaimLightParams for instruction data serialization.
    pub light_params: ClaimLightParams,
    /// Remaining accounts to append to the claim instruction.
    pub remaining_accounts: Vec<AccountMeta>,
}

/// Prepare all Light Protocol parameters for a claim instruction.
///
/// 1. Derives the ClaimReceipt address
/// 2. Fetches non-inclusion validity proof from Photon
/// 3. Builds remaining accounts
/// 4. Assembles `ClaimLightParams`
pub async fn prepare_claim_light_params(
    photon: &PhotonClient,
    user_pubkey: &[u8; 32],
    epoch: u64,
    relay_pubkey: &[u8; 32],
    program_id: &[u8; 32],
    trees: &LightTreeConfig,
) -> Result<ClaimProofResult> {
    // 1. Derive address
    let address = derive_claim_receipt_address(
        user_pubkey,
        epoch,
        relay_pubkey,
        &trees.address_tree,
        program_id,
    );

    // 2. Fetch validity proof from Photon
    let proof = photon.get_validity_proof(&address, &trees.address_tree).await?;

    // 3. Build remaining accounts
    let remaining = build_claim_remaining_accounts(program_id, trees);

    // 4. Assemble ClaimLightParams
    let light_params = ClaimLightParams {
        proof_a: proof.a,
        proof_b: proof.b,
        proof_c: proof.c,
        address_merkle_tree_pubkey_index: remaining.address_tree_pubkey_index,
        address_queue_pubkey_index: remaining.address_queue_pubkey_index,
        root_index: proof.root_index,
        output_tree_index: remaining.output_tree_index,
    };

    Ok(ClaimProofResult {
        light_params,
        remaining_accounts: remaining.accounts,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bs58_to_bytes_roundtrip() {
        // ADDRESS_TREE_V2 from light-sdk-types should match our bs58 decode
        let expected = light_sdk_types::constants::ADDRESS_TREE_V2;
        let decoded = bs58_to_bytes("amt2kaJA14v3urZbZvnc5v2np8jqvc4Z8zDep5wbtzx");
        assert_eq!(decoded, expected);
    }

    #[test]
    fn test_derive_claim_receipt_address_deterministic() {
        let user = [1u8; 32];
        let relay = [2u8; 32];
        let epoch = 42u64;
        let tree = ADDRESS_TREE_V2;
        let program_id = [99u8; 32];

        let addr1 = derive_claim_receipt_address(&user, epoch, &relay, &tree, &program_id);
        let addr2 = derive_claim_receipt_address(&user, epoch, &relay, &tree, &program_id);
        assert_eq!(addr1, addr2);
        assert_ne!(addr1, [0u8; 32]); // non-trivial
    }

    #[test]
    fn test_derive_claim_receipt_address_different_inputs() {
        let user = [1u8; 32];
        let relay = [2u8; 32];
        let tree = ADDRESS_TREE_V2;
        let program_id = [99u8; 32];

        let addr_epoch0 = derive_claim_receipt_address(&user, 0, &relay, &tree, &program_id);
        let addr_epoch1 = derive_claim_receipt_address(&user, 1, &relay, &tree, &program_id);
        assert_ne!(addr_epoch0, addr_epoch1);

        let relay2 = [3u8; 32];
        let addr_relay2 = derive_claim_receipt_address(&user, 0, &relay2, &tree, &program_id);
        assert_ne!(addr_epoch0, addr_relay2);
    }

    #[test]
    fn test_build_remaining_accounts_count_and_types() {
        let program_id = [99u8; 32];
        let trees = LightTreeConfig::devnet_v2();

        let result = build_claim_remaining_accounts(&program_id, &trees);

        // 6 system accounts + 2 tree accounts = 8
        assert_eq!(result.accounts.len(), 8);

        // System accounts are readonly
        for acc in &result.accounts[..6] {
            assert!(!acc.is_writable);
        }

        // Tree accounts are writable
        assert!(result.accounts[6].is_writable);
        assert!(result.accounts[7].is_writable);

        // Check known pubkeys
        assert_eq!(result.accounts[0].pubkey, LIGHT_SYSTEM_PROGRAM);
        assert_eq!(result.accounts[2].pubkey, REGISTERED_PROGRAM_PDA);
        assert_eq!(result.accounts[3].pubkey, ACCOUNT_COMPRESSION_AUTHORITY);
        assert_eq!(result.accounts[4].pubkey, ACCOUNT_COMPRESSION_PROGRAM);
        assert_eq!(result.accounts[5].pubkey, solana_sdk_ids::system_program::id());

        // Tree indices
        assert_eq!(result.address_tree_pubkey_index, 0);
        assert_eq!(result.address_queue_pubkey_index, 0);
        assert_eq!(result.output_tree_index, 1);
    }

    #[test]
    fn test_devnet_constants_non_zero() {
        assert_ne!(ADDRESS_TREE_V2, [0u8; 32]);
        assert_ne!(OUTPUT_STATE_TREE_V2, [0u8; 32]);
        assert_ne!(OUTPUT_QUEUE_V2, [0u8; 32]);
    }
}
