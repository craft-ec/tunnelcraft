//! Settlement client for interacting with Solana
//!
//! Supports two modes:
//! - **Mock Mode**: For development/testing without Solana. All operations succeed
//!   and state is tracked in-memory.
//! - **Live Mode**: Actual Solana RPC calls to the TunnelCraft settlement program.
//!
//! ## New Settlement Model
//!
//! Per-epoch subscriptions with direct payout. Each subscribe() creates a new
//! epoch (monotonic counter per user via UserMeta PDA). Claims pay directly
//! from pool PDA to relay wallet — no NodeAccount accumulation step.
//! Double-claim prevented by Light Protocol compressed ClaimReceipt
//! (in mock: HashSet dedup simulates compressed account uniqueness).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use sha2::{Sha256, Digest};
use tracing::{debug, info};

use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk_ids::system_program;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

use tunnelcraft_core::{Id, PublicKey, ForwardReceipt, SubscriptionTier};

use crate::{
    SettlementError, Result,
    Subscribe, PostDistribution, ClaimRewards,
    SubscriptionState, TransactionSignature,
    EpochPhase, EPOCH_DURATION_SECS,
    USDC_MINT_DEVNET, USDC_MINT_MAINNET,
    LightTreeConfig,
};
use crate::light::{self, PhotonClient};

/// Settlement mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettlementMode {
    /// Mock mode for development - all operations succeed, state is in-memory
    Mock,
    /// Live Solana mode (requires deployed program)
    Live,
}

/// Settlement client configuration
#[derive(Debug, Clone)]
pub struct SettlementConfig {
    /// Settlement mode (Mock or Live)
    pub mode: SettlementMode,
    /// Solana RPC endpoint (only used in Live mode)
    pub rpc_url: String,
    /// Program ID for the TunnelCraft settlement program
    pub program_id: [u8; 32],
    /// USDC mint address (6 decimal SPL token)
    pub usdc_mint: [u8; 32],
    /// Commitment level for transactions
    pub commitment: String,
    /// Helius API key for Photon RPC (Light Protocol validity proofs).
    /// If None, falls back to `rpc_url` for Photon calls.
    pub helius_api_key: Option<String>,
    /// Light Protocol tree configuration for compressed ClaimReceipts.
    /// If None, auto-fetch of Light params in `claim_rewards()` is disabled.
    pub light_trees: Option<LightTreeConfig>,
}

impl Default for SettlementConfig {
    fn default() -> Self {
        Self {
            mode: SettlementMode::Mock,
            rpc_url: "https://api.devnet.solana.com".to_string(),
            program_id: [0u8; 32],
            usdc_mint: USDC_MINT_DEVNET,
            commitment: "confirmed".to_string(),
            helius_api_key: None,
            light_trees: None,
        }
    }
}

impl SettlementConfig {
    /// Create a mock configuration for development
    pub fn mock() -> Self {
        Self {
            mode: SettlementMode::Mock,
            ..Default::default()
        }
    }

    /// Devnet program ID for TunnelCraft settlement
    /// Program: 2QQvVc5QmYkLEAFyoVd3hira43NE9qrhjRcuT1hmfMTH
    pub const DEVNET_PROGRAM_ID: [u8; 32] = [
        20, 219, 24, 53, 50, 190, 161, 233, 43, 183, 226, 86, 179, 16, 135, 37,
        125, 140, 196, 11, 102, 112, 243, 189, 110, 247, 244, 195, 28, 128, 17, 116,
    ];

    /// Create a live configuration for Solana devnet
    pub fn devnet(program_id: [u8; 32]) -> Self {
        Self {
            mode: SettlementMode::Live,
            rpc_url: "https://api.devnet.solana.com".to_string(),
            program_id,
            usdc_mint: USDC_MINT_DEVNET,
            light_trees: Some(LightTreeConfig::devnet_v2()),
            ..Default::default()
        }
    }

    /// Create a live configuration for Solana devnet with the default program ID
    pub fn devnet_default() -> Self {
        Self::devnet(Self::DEVNET_PROGRAM_ID)
    }

    /// Create a live configuration for Solana mainnet
    pub fn mainnet(program_id: [u8; 32]) -> Self {
        Self {
            mode: SettlementMode::Live,
            rpc_url: "https://api.mainnet-beta.solana.com".to_string(),
            program_id,
            usdc_mint: USDC_MINT_MAINNET,
            commitment: "finalized".to_string(),
            helius_api_key: None,
            light_trees: None,
        }
    }

    /// Get commitment config for Solana client
    fn commitment_config(&self) -> CommitmentConfig {
        match self.commitment.as_str() {
            "finalized" => CommitmentConfig::finalized(),
            "confirmed" => CommitmentConfig::confirmed(),
            "processed" => CommitmentConfig::processed(),
            _ => CommitmentConfig::confirmed(),
        }
    }
}

/// In-memory state for mock mode
#[derive(Debug, Default)]
struct MockState {
    /// Subscription states by (user_pubkey, epoch)
    subscriptions: HashMap<(PublicKey, u64), SubscriptionState>,
    /// Next epoch counter per user (simulates UserMeta.next_epoch)
    next_epoch: HashMap<PublicKey, u64>,
    /// Claimed relays: (user_pubkey, epoch, relay_pubkey) — simulates
    /// Light Protocol compressed ClaimReceipt uniqueness
    claimed_relays: HashSet<(PublicKey, u64, PublicKey)>,
    /// Transaction counter for generating mock signatures
    tx_counter: u64,
}

/// Anchor instruction discriminators for the TunnelCraft settlement program.
/// Each is the first 8 bytes of SHA256("global:<instruction_name>").
mod instruction {
    pub const SUBSCRIBE:          [u8; 8] = [0xfe, 0x1c, 0xbf, 0x8a, 0x9c, 0xb3, 0xb7, 0x35];
    pub const POST_DISTRIBUTION:  [u8; 8] = [0x0e, 0xa8, 0xf7, 0x4a, 0xbf, 0x7b, 0x15, 0xe8];
    pub const CLAIM:              [u8; 8] = [0x3e, 0xc6, 0xd6, 0xc1, 0xd5, 0x9f, 0x6c, 0xd2];
}

/// Settlement client for on-chain operations
///
/// This client abstracts the Solana RPC calls and transaction building.
/// In mock mode, all operations succeed and state is tracked in-memory.
pub struct SettlementClient {
    config: SettlementConfig,
    /// Our keypair for signing transactions
    signer_keypair: Option<Keypair>,
    /// Our public key
    signer_pubkey: PublicKey,
    /// Solana RPC client (only used in Live mode)
    rpc_client: Option<Arc<RpcClient>>,
    /// Mock state (only used in Mock mode)
    mock_state: Arc<RwLock<MockState>>,
}

impl SettlementClient {
    /// Create a new settlement client with a public key only (mock mode)
    pub fn new(config: SettlementConfig, signer_pubkey: PublicKey) -> Self {
        Self {
            config: config.clone(),
            signer_keypair: None,
            signer_pubkey,
            rpc_client: if config.mode == SettlementMode::Live {
                Some(Arc::new(RpcClient::new_with_commitment(
                    config.rpc_url.clone(),
                    config.commitment_config(),
                )))
            } else {
                None
            },
            mock_state: Arc::new(RwLock::new(MockState::default())),
        }
    }

    /// Create a new settlement client with a keypair for signing (live mode)
    pub fn with_keypair(config: SettlementConfig, keypair: Keypair) -> Self {
        let signer_pubkey = keypair.pubkey().to_bytes();

        let rpc_client = if config.mode == SettlementMode::Live {
            Some(Arc::new(RpcClient::new_with_commitment(
                config.rpc_url.clone(),
                config.commitment_config(),
            )))
        } else {
            None
        };

        Self {
            config,
            signer_keypair: Some(keypair),
            signer_pubkey,
            rpc_client,
            mock_state: Arc::new(RwLock::new(MockState::default())),
        }
    }

    /// Create a new settlement client from a 32-byte ed25519 secret key.
    pub fn with_secret_key(config: SettlementConfig, secret: &[u8; 32]) -> Self {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(secret);
        let public_bytes = signing_key.verifying_key().to_bytes();

        let mut full_key = [0u8; 64];
        full_key[..32].copy_from_slice(secret);
        full_key[32..].copy_from_slice(&public_bytes);
        let keypair = Keypair::try_from(full_key.as_ref())
            .expect("valid ed25519 keypair bytes");

        Self::with_keypair(config, keypair)
    }

    /// Get SOL balance in lamports for the signer's account
    pub async fn get_balance(&self) -> Result<u64> {
        if self.is_mock() {
            return Ok(u64::MAX);
        }

        let rpc = self.rpc_client.as_ref()
            .ok_or_else(|| SettlementError::RpcError("RPC client not initialized".to_string()))?;

        let pubkey = Pubkey::new_from_array(self.signer_pubkey);
        rpc.get_balance(&pubkey).await
            .map_err(|e| SettlementError::RpcError(format!("get_balance: {}", e)))
    }

    /// Request a devnet airdrop of the given lamports amount
    pub async fn request_airdrop(&self, lamports: u64) -> Result<()> {
        if self.is_mock() {
            return Ok(());
        }

        let rpc = self.rpc_client.as_ref()
            .ok_or_else(|| SettlementError::RpcError("RPC client not initialized".to_string()))?;

        let pubkey = Pubkey::new_from_array(self.signer_pubkey);
        info!("Requesting airdrop of {} lamports to {}", lamports, pubkey);

        let sig = rpc.request_airdrop(&pubkey, lamports).await
            .map_err(|e| SettlementError::RpcError(format!("request_airdrop: {}", e)))?;

        let commitment = self.config.commitment_config();
        rpc.confirm_transaction_with_commitment(&sig, commitment).await
            .map_err(|e| SettlementError::RpcError(format!("airdrop confirm: {}", e)))?;

        info!("Airdrop confirmed: {}", sig);
        Ok(())
    }

    /// Get the signer's public key bytes
    pub fn signer_pubkey_bytes(&self) -> &PublicKey {
        &self.signer_pubkey
    }

    /// Check if running in mock mode
    pub fn is_mock(&self) -> bool {
        self.config.mode == SettlementMode::Mock
    }

    /// Get program ID as Pubkey
    fn program_id(&self) -> Pubkey {
        Pubkey::new_from_array(self.config.program_id)
    }

    /// Create a Photon client from the current config.
    fn photon_client(&self) -> Result<PhotonClient> {
        Ok(PhotonClient::from_config(
            &self.config.rpc_url,
            self.config.helius_api_key.as_deref(),
        ))
    }

    /// Generate mock signature (when already holding lock)
    fn generate_mock_signature(state: &mut MockState) -> TransactionSignature {
        state.tx_counter += 1;
        let mut sig = [0u8; 64];
        sig[0..8].copy_from_slice(&state.tx_counter.to_le_bytes());
        sig[8..16].copy_from_slice(b"mocktxn!");
        sig
    }

    /// Get current timestamp
    fn now() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Derive PDA for per-epoch subscription account: ["sub", user_pubkey, epoch_le]
    fn subscription_pda(&self, user_pubkey: &PublicKey, epoch: u64) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[b"sub", user_pubkey, &epoch.to_le_bytes()],
            &self.program_id(),
        )
    }

    /// Derive PDA for user meta account: ["user", user_pubkey]
    fn user_meta_pda(&self, user_pubkey: &PublicKey) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[b"user", user_pubkey],
            &self.program_id(),
        )
    }

    /// Derive associated token account address for a given wallet and mint.
    ///
    /// ATA PDA = find_program_address(
    ///   [wallet, TOKEN_PROGRAM_ID, mint],
    ///   ASSOCIATED_TOKEN_PROGRAM_ID,
    /// )
    fn associated_token_address(wallet: &Pubkey, mint: &Pubkey) -> Pubkey {
        // SPL Associated Token Account program ID
        let ata_program_id = Pubkey::new_from_array([
            140, 151, 37, 143, 78, 36, 137, 241, 187, 61, 16, 41, 20, 142, 13, 131,
            11, 90, 19, 153, 218, 255, 16, 132, 4, 142, 123, 216, 219, 233, 248, 89,
        ]); // ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL
        let token_program_id = Pubkey::new_from_array([
            6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172,
            28, 180, 133, 237, 95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
        ]); // TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA

        let (ata, _) = Pubkey::find_program_address(
            &[wallet.as_ref(), token_program_id.as_ref(), mint.as_ref()],
            &ata_program_id,
        );
        ata
    }

    /// Get the next epoch for a user from on-chain UserMeta PDA.
    ///
    /// Returns 0 if the UserMeta account doesn't exist (first subscription).
    async fn get_next_epoch_live(&self, user_pubkey: &PublicKey) -> Result<u64> {
        let rpc = self.rpc_client.as_ref()
            .ok_or_else(|| SettlementError::RpcError("RPC client not initialized".to_string()))?;

        let (user_meta_pda, _) = self.user_meta_pda(user_pubkey);

        match rpc.get_account(&user_meta_pda).await {
            Ok(account) => {
                let data = &account.data;
                // UserMeta layout: 8 (discriminator) + 32 (user_pubkey) + 8 (next_epoch)
                if data.len() < 48 {
                    return Ok(0);
                }
                let next_epoch = u64::from_le_bytes(
                    data[40..48].try_into().expect("8 bytes for next_epoch")
                );
                Ok(next_epoch)
            }
            Err(_) => Ok(0), // Account doesn't exist — first subscription
        }
    }

    /// USDC mint pubkey from config
    fn usdc_mint(&self) -> Pubkey {
        Pubkey::new_from_array(self.config.usdc_mint)
    }

    /// Hash a receipt for dedup: SHA256(request_id || shard_id || receiver_pubkey)
    pub fn receipt_dedup_hash(receipt: &ForwardReceipt) -> Id {
        let mut hasher = Sha256::new();
        hasher.update(&receipt.request_id);
        hasher.update(&receipt.shard_id);
        hasher.update(&receipt.sender_pubkey);
        hasher.update(&receipt.receiver_pubkey);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Send a transaction to Solana
    async fn send_transaction(&self, instruction: Instruction) -> Result<TransactionSignature> {
        let rpc = self.rpc_client.as_ref()
            .ok_or_else(|| SettlementError::RpcError("RPC client not initialized".to_string()))?;

        let keypair = self.signer_keypair.as_ref()
            .ok_or(SettlementError::NotAuthorized)?;

        let blockhash = rpc.get_latest_blockhash().await
            .map_err(|e| SettlementError::RpcError(e.to_string()))?;

        let tx = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&keypair.pubkey()),
            &[keypair],
            blockhash,
        );

        let signature = rpc.send_and_confirm_transaction(&tx).await
            .map_err(|e| SettlementError::TransactionFailed(e.to_string()))?;

        info!("Transaction confirmed: {}", signature);

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature.as_ref());
        Ok(sig_bytes)
    }

    // ==================== Subscribe ====================

    /// Subscribe a user (creates per-epoch subscription PDA, increments UserMeta.next_epoch)
    ///
    /// Returns the epoch assigned to this subscription.
    pub async fn subscribe(
        &self,
        sub: Subscribe,
    ) -> Result<(TransactionSignature, u64)> {
        info!(
            "Subscribing user {} with tier {:?} (payment: {})",
            hex_encode(&sub.user_pubkey[..8]),
            sub.tier,
            sub.payment_amount,
        );

        if self.is_mock() {
            let mut state = self.mock_state.write().expect("settlement lock poisoned");

            let epoch = state.next_epoch.entry(sub.user_pubkey).or_insert(0);
            let current_epoch = *epoch;
            *epoch += 1;

            let now = Self::now();
            let expires_at = now + EPOCH_DURATION_SECS;

            let subscription = SubscriptionState {
                user_pubkey: sub.user_pubkey,
                epoch: current_epoch,
                tier: sub.tier,
                created_at: now,
                expires_at,
                pool_balance: sub.payment_amount,
                original_pool_balance: sub.payment_amount,
                total_bytes: 0,
                distribution_posted: false,
                distribution_root: [0u8; 32],
            };
            state.subscriptions.insert((sub.user_pubkey, current_epoch), subscription);

            info!(
                "[MOCK] User {} subscribed ({:?}, epoch: {}, pool: {}, expires: {})",
                hex_encode(&sub.user_pubkey[..8]),
                sub.tier,
                current_epoch,
                sub.payment_amount,
                expires_at,
            );
            return Ok((Self::generate_mock_signature(&mut state), current_epoch));
        }

        // Live mode: query UserMeta to get next_epoch before building tx
        let next_epoch = self.get_next_epoch_live(&sub.user_pubkey).await?;

        let (user_meta_pda, _) = self.user_meta_pda(&sub.user_pubkey);
        let (subscription_pda, _) = self.subscription_pda(&sub.user_pubkey, next_epoch);
        let signer = Pubkey::new_from_array(self.signer_pubkey);
        let usdc_mint = self.usdc_mint();

        let payer_token_account = Self::associated_token_address(&signer, &usdc_mint);
        let pool_token_account = Self::associated_token_address(&subscription_pda, &usdc_mint);

        let tier_byte = match sub.tier {
            SubscriptionTier::Basic => 0u8,
            SubscriptionTier::Standard => 1u8,
            SubscriptionTier::Premium => 2u8,
        };

        let mut data = instruction::SUBSCRIBE.to_vec();
        data.extend_from_slice(&sub.user_pubkey);
        data.push(tier_byte);
        data.extend_from_slice(&sub.payment_amount.to_le_bytes());

        // SPL Token and ATA program IDs
        let token_program_id = Pubkey::new_from_array([
            6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172,
            28, 180, 133, 237, 95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
        ]);
        let ata_program_id = Pubkey::new_from_array([
            140, 151, 37, 143, 78, 36, 137, 241, 187, 61, 16, 41, 20, 142, 13, 131,
            11, 90, 19, 153, 218, 255, 16, 132, 4, 142, 123, 216, 219, 233, 248, 89,
        ]);

        let instruction = Instruction {
            program_id: self.program_id(),
            accounts: vec![
                AccountMeta::new(signer, true),                              // payer
                AccountMeta::new(user_meta_pda, false),                      // user_meta
                AccountMeta::new(subscription_pda, false),                   // subscription_account
                AccountMeta::new(payer_token_account, false),                // payer_token_account
                AccountMeta::new(pool_token_account, false),                 // pool_token_account
                AccountMeta::new_readonly(usdc_mint, false),                 // usdc_mint
                AccountMeta::new_readonly(token_program_id, false),          // token_program
                AccountMeta::new_readonly(ata_program_id, false),            // associated_token_program
                AccountMeta::new_readonly(system_program::id(), false),      // system_program
            ],
            data,
        };

        let sig = self.send_transaction(instruction).await?;
        Ok((sig, next_epoch))
    }

    // ==================== Post Distribution ====================

    /// Post a distribution root for a user's pool epoch.
    ///
    /// Can only be called after the grace period (epoch expired + 1 day).
    /// The aggregator calls this after collecting ZK-proven summaries.
    pub async fn post_distribution(
        &self,
        dist: PostDistribution,
    ) -> Result<TransactionSignature> {
        info!(
            "Posting distribution for user pool {} epoch {} (root: {}, bytes: {})",
            hex_encode(&dist.user_pubkey[..8]),
            dist.epoch,
            hex_encode(&dist.distribution_root[..8]),
            dist.total_bytes,
        );

        if self.is_mock() {
            let mut state = self.mock_state.write().expect("settlement lock poisoned");

            let sub_key = (dist.user_pubkey, dist.epoch);
            let subscription = state.subscriptions.get(&sub_key)
                .ok_or_else(|| SettlementError::SubscriptionNotFound(
                    format!("{}:epoch={}", hex_encode(&dist.user_pubkey[..8]), dist.epoch)
                ))?;

            // Enforce epoch phase: must be past grace period
            let now = Self::now();
            let phase = subscription.phase(now);
            if matches!(phase, EpochPhase::Active | EpochPhase::Grace) {
                return Err(SettlementError::EpochNotComplete);
            }

            // First-writer-wins: reject if distribution already posted
            if subscription.distribution_posted {
                return Err(SettlementError::DistributionAlreadyPosted);
            }

            let subscription = state.subscriptions.get_mut(&sub_key).unwrap();
            subscription.distribution_posted = true;
            subscription.distribution_root = dist.distribution_root;
            subscription.total_bytes = dist.total_bytes;
            subscription.original_pool_balance = subscription.pool_balance;

            info!(
                "[MOCK] Distribution posted for user pool {} epoch {} (total: {})",
                hex_encode(&dist.user_pubkey[..8]),
                dist.epoch,
                dist.total_bytes,
            );
            return Ok(Self::generate_mock_signature(&mut state));
        }

        // Live mode
        let (subscription_pda, _) = self.subscription_pda(&dist.user_pubkey, dist.epoch);
        let signer = Pubkey::new_from_array(self.signer_pubkey);

        let mut data = instruction::POST_DISTRIBUTION.to_vec();
        data.extend_from_slice(&dist.user_pubkey);
        data.extend_from_slice(&dist.epoch.to_le_bytes());
        data.extend_from_slice(&dist.distribution_root);
        data.extend_from_slice(&dist.total_bytes.to_le_bytes());

        let instruction = Instruction {
            program_id: self.program_id(),
            accounts: vec![
                AccountMeta::new(signer, true),                 // signer
                AccountMeta::new(subscription_pda, false),      // subscription_account
            ],
            data,
        };

        self.send_transaction(instruction).await
    }

    // ==================== Claim Rewards ====================

    /// Claim proportional rewards from a user's pool epoch using Merkle proof.
    ///
    /// Payout transfers directly from pool PDA to relay wallet (no NodeAccount).
    /// payout = (relay_bytes / total_bytes) * pool_balance
    ///
    /// Requires: distribution posted, epoch past grace, relay not already claimed.
    /// Double-claim prevented by compressed ClaimReceipt (mock: HashSet dedup).
    pub async fn claim_rewards(
        &self,
        claim: ClaimRewards,
    ) -> Result<TransactionSignature> {
        info!(
            "Claiming rewards for node {} from user pool {} epoch {} ({} bytes)",
            hex_encode(&claim.node_pubkey[..8]),
            hex_encode(&claim.user_pubkey[..8]),
            claim.epoch,
            claim.relay_bytes,
        );

        if self.is_mock() {
            let mut state = self.mock_state.write().expect("settlement lock poisoned");

            let sub_key = (claim.user_pubkey, claim.epoch);
            let subscription = state.subscriptions.get(&sub_key)
                .ok_or_else(|| SettlementError::SubscriptionNotFound(
                    format!("{}:epoch={}", hex_encode(&claim.user_pubkey[..8]), claim.epoch)
                ))?
                .clone();

            // Enforce epoch phase
            let now = Self::now();
            let phase = subscription.phase(now);
            if matches!(phase, EpochPhase::Active | EpochPhase::Grace) {
                return Err(SettlementError::EpochNotComplete);
            }

            // Must have distribution posted
            if !subscription.distribution_posted {
                return Err(SettlementError::DistributionNotPosted);
            }

            if subscription.total_bytes == 0 {
                return Err(SettlementError::TransactionFailed(
                    "No bytes in pool".to_string()
                ));
            }

            // Check not already claimed (simulates compressed account uniqueness)
            let claim_key = (claim.user_pubkey, claim.epoch, claim.node_pubkey);
            if state.claimed_relays.contains(&claim_key) {
                return Err(SettlementError::AlreadyClaimed);
            }

            // Verify Merkle proof if distribution root and proof are provided
            if subscription.distribution_posted && !claim.merkle_proof.is_empty() {
                use tunnelcraft_prover::{merkle_leaf, MerkleProof, MerkleTree};
                let leaf = merkle_leaf(&claim.node_pubkey, claim.relay_bytes);
                let proof = MerkleProof {
                    siblings: claim.merkle_proof.clone(),
                    leaf_index: claim.leaf_index as usize,
                };
                if !MerkleTree::verify(&subscription.distribution_root, &leaf, &proof) {
                    return Err(SettlementError::InvalidMerkleProof);
                }
            }

            // Calculate proportional share (direct payout)
            let payout = (claim.relay_bytes as u128 * subscription.original_pool_balance as u128
                / subscription.total_bytes as u128) as u64;

            // Mark as claimed (simulates compressed ClaimReceipt creation)
            state.claimed_relays.insert(claim_key);

            // Deduct from pool (direct transfer to relay wallet)
            let subscription = state.subscriptions.get_mut(&sub_key).unwrap();
            subscription.pool_balance = subscription.pool_balance.saturating_sub(payout);

            info!(
                "[MOCK] Node {} claimed {} from user pool {} epoch {} ({} bytes, direct payout)",
                hex_encode(&claim.node_pubkey[..8]),
                payout,
                hex_encode(&claim.user_pubkey[..8]),
                claim.epoch,
                claim.relay_bytes,
            );
            return Ok(Self::generate_mock_signature(&mut state));
        }

        // Live mode — auto-fetch Light params if not provided
        let trees = self.config.light_trees.as_ref()
            .ok_or_else(|| SettlementError::TransactionFailed(
                "light_trees config required for live-mode claim".to_string()
            ))?;

        let (light, remaining_accounts) = match claim.light_params {
            Some(ref params) => {
                // Caller provided params; still build remaining accounts
                let remaining = light::build_claim_remaining_accounts(
                    &self.config.program_id,
                    trees,
                );
                (params.clone(), remaining.accounts)
            }
            None => {
                // Auto-fetch from Photon
                let photon = self.photon_client()?;
                let result = light::prepare_claim_light_params(
                    &photon,
                    &claim.user_pubkey,
                    claim.epoch,
                    &claim.node_pubkey,
                    &self.config.program_id,
                    trees,
                ).await?;
                (result.light_params, result.remaining_accounts)
            }
        };

        let (subscription_pda, _) = self.subscription_pda(&claim.user_pubkey, claim.epoch);
        let signer = Pubkey::new_from_array(self.signer_pubkey);
        let usdc_mint = self.usdc_mint();

        let pool_token_account = Self::associated_token_address(&subscription_pda, &usdc_mint);
        let relay_wallet = Pubkey::new_from_array(claim.node_pubkey);
        let relay_token_account = Self::associated_token_address(&relay_wallet, &usdc_mint);

        let token_program_id = Pubkey::new_from_array([
            6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172,
            28, 180, 133, 237, 95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
        ]);

        let mut data = instruction::CLAIM.to_vec();
        data.extend_from_slice(&claim.user_pubkey);
        data.extend_from_slice(&claim.epoch.to_le_bytes());
        data.extend_from_slice(&claim.node_pubkey);
        data.extend_from_slice(&claim.relay_bytes.to_le_bytes());
        data.extend_from_slice(&claim.leaf_index.to_le_bytes());
        // Serialize Merkle proof (Anchor Vec: 4-byte LE length prefix + elements)
        data.extend_from_slice(&(claim.merkle_proof.len() as u32).to_le_bytes());
        for hash in &claim.merkle_proof {
            data.extend_from_slice(hash);
        }

        // Serialize LightClaimParams
        // LightValidityProof { a: [u8;32], b: [u8;64], c: [u8;32] }
        data.extend_from_slice(&light.proof_a);
        data.extend_from_slice(&light.proof_b);
        data.extend_from_slice(&light.proof_c);
        // LightAddressTreeInfo { pubkey_index: u8, queue_index: u8, root_index: u16 }
        data.push(light.address_merkle_tree_pubkey_index);
        data.push(light.address_queue_pubkey_index);
        data.extend_from_slice(&light.root_index.to_le_bytes());
        // output_tree_index: u8
        data.push(light.output_tree_index);

        // Build accounts: fixed accounts + Light Protocol remaining accounts
        let mut accounts = vec![
            AccountMeta::new(signer, true),                         // signer
            AccountMeta::new(subscription_pda, false),              // subscription_account
            AccountMeta::new(pool_token_account, false),            // pool_token_account
            AccountMeta::new(relay_token_account, false),           // relay_token_account
            AccountMeta::new_readonly(usdc_mint, false),            // usdc_mint
            AccountMeta::new_readonly(token_program_id, false),     // token_program
            AccountMeta::new_readonly(system_program::id(), false), // system_program
        ];
        accounts.extend(remaining_accounts);

        let instruction = Instruction {
            program_id: self.program_id(),
            accounts,
            data,
        };

        self.send_transaction(instruction).await
    }

    // ==================== Query Methods ====================

    /// Get subscription state for a user's specific epoch
    pub async fn get_subscription_state(
        &self,
        user_pubkey: PublicKey,
        epoch: u64,
    ) -> Result<Option<SubscriptionState>> {
        debug!("Fetching subscription for user {} epoch {}", hex_encode(&user_pubkey[..8]), epoch);

        if self.is_mock() {
            let state = self.mock_state.read().expect("settlement lock poisoned");
            return Ok(state.subscriptions.get(&(user_pubkey, epoch)).cloned());
        }

        let rpc = self.rpc_client.as_ref()
            .ok_or_else(|| SettlementError::RpcError("RPC client not initialized".to_string()))?;

        let (subscription_pda, _) = self.subscription_pda(&user_pubkey, epoch);

        match rpc.get_account(&subscription_pda).await {
            Ok(account) => {
                let data = &account.data;
                // SubscriptionAccount layout (after 8-byte discriminator):
                //   0..32:  user_pubkey [u8; 32]
                //  32..40:  epoch u64
                //  40..41:  tier u8
                //  41..49:  created_at i64
                //  49..57:  expires_at i64
                //  57..65:  pool_balance u64
                //  65..73:  original_pool_balance u64
                //  73..81:  total_bytes u64
                //  81..113: distribution_root [u8; 32]
                // 113..114: distribution_posted bool
                const MIN_LEN: usize = 8 + 32 + 8 + 1 + 8 + 8 + 8 + 8 + 8 + 32 + 1; // = 122
                if data.len() < MIN_LEN {
                    return Ok(None);
                }
                let d = &data[8..]; // skip discriminator

                let mut pubkey = [0u8; 32];
                pubkey.copy_from_slice(&d[0..32]);

                let epoch_val = u64::from_le_bytes(d[32..40].try_into().expect("8 bytes"));

                let tier = match d[40] {
                    0 => SubscriptionTier::Basic,
                    1 => SubscriptionTier::Standard,
                    2 => SubscriptionTier::Premium,
                    _ => SubscriptionTier::Basic,
                };

                let created_at = i64::from_le_bytes(d[41..49].try_into().expect("8 bytes"));
                let expires_at = i64::from_le_bytes(d[49..57].try_into().expect("8 bytes"));
                let pool_balance = u64::from_le_bytes(d[57..65].try_into().expect("8 bytes"));
                let original_pool_balance = u64::from_le_bytes(d[65..73].try_into().expect("8 bytes"));
                let total_bytes = u64::from_le_bytes(d[73..81].try_into().expect("8 bytes"));

                let mut distribution_root = [0u8; 32];
                distribution_root.copy_from_slice(&d[81..113]);
                let distribution_posted = d[113] != 0;

                Ok(Some(SubscriptionState {
                    user_pubkey: pubkey,
                    epoch: epoch_val,
                    tier,
                    created_at: created_at as u64,
                    expires_at: expires_at as u64,
                    pool_balance,
                    original_pool_balance,
                    total_bytes,
                    distribution_posted,
                    distribution_root,
                }))
            }
            Err(e) => {
                debug!("Subscription account not found: {}", e);
                Ok(None)
            }
        }
    }

    /// Get the latest subscription state for a user (checks most recent epoch).
    ///
    /// In mock mode, finds the highest epoch for the user.
    /// In live mode, queries UserMeta to get next_epoch - 1.
    pub async fn get_latest_subscription(
        &self,
        user_pubkey: PublicKey,
    ) -> Result<Option<SubscriptionState>> {
        if self.is_mock() {
            let state = self.mock_state.read().expect("settlement lock poisoned");
            let next = state.next_epoch.get(&user_pubkey).copied().unwrap_or(0);
            if next == 0 {
                return Ok(None);
            }
            return Ok(state.subscriptions.get(&(user_pubkey, next - 1)).cloned());
        }

        // Live mode: query UserMeta PDA for next_epoch, then subscription PDA
        let next_epoch = self.get_next_epoch_live(&user_pubkey).await?;
        if next_epoch == 0 {
            return Ok(None);
        }
        self.get_subscription_state(user_pubkey, next_epoch - 1).await
    }

    /// Check if a user has an active subscription (any epoch)
    pub async fn is_subscribed(&self, user_pubkey: PublicKey) -> Result<bool> {
        match self.get_latest_subscription(user_pubkey).await? {
            Some(sub) => Ok(sub.expires_at > Self::now()),
            None => Ok(false),
        }
    }

    /// Get the next epoch for a user (mock mode helper)
    pub fn get_next_epoch(&self, user_pubkey: &PublicKey) -> u64 {
        if !self.is_mock() {
            return 0;
        }
        let state = self.mock_state.read().expect("settlement lock poisoned");
        state.next_epoch.get(user_pubkey).copied().unwrap_or(0)
    }

    // ==================== Mock Helpers ====================

    /// Add a mock subscription directly (mock mode only, for testing)
    pub fn add_mock_subscription(
        &self,
        user_pubkey: PublicKey,
        tier: SubscriptionTier,
        pool_balance: u64,
    ) -> Result<u64> {
        if !self.is_mock() {
            return Err(SettlementError::NotAuthorized);
        }

        let mut state = self.mock_state.write().expect("settlement lock poisoned");
        let epoch = state.next_epoch.entry(user_pubkey).or_insert(0);
        let current_epoch = *epoch;
        *epoch += 1;

        let now = Self::now();
        let expires_at = now + EPOCH_DURATION_SECS;
        state.subscriptions.insert((user_pubkey, current_epoch), SubscriptionState {
            user_pubkey,
            epoch: current_epoch,
            tier,
            created_at: now,
            expires_at,
            pool_balance,
            original_pool_balance: pool_balance,
            total_bytes: 0,
            distribution_posted: false,
            distribution_root: [0u8; 32],
        });
        info!(
            "[MOCK] Added subscription for {} ({:?}, epoch: {}, pool: {})",
            hex_encode(&user_pubkey[..8]),
            tier,
            current_epoch,
            pool_balance,
        );
        Ok(current_epoch)
    }

    /// Add a mock subscription with custom expiry (mock mode only, for testing epoch phases)
    pub fn add_mock_subscription_with_expiry(
        &self,
        user_pubkey: PublicKey,
        tier: SubscriptionTier,
        pool_balance: u64,
        created_at: u64,
        expires_at: u64,
    ) -> Result<u64> {
        if !self.is_mock() {
            return Err(SettlementError::NotAuthorized);
        }

        let mut state = self.mock_state.write().expect("settlement lock poisoned");
        let epoch = state.next_epoch.entry(user_pubkey).or_insert(0);
        let current_epoch = *epoch;
        *epoch += 1;

        state.subscriptions.insert((user_pubkey, current_epoch), SubscriptionState {
            user_pubkey,
            epoch: current_epoch,
            tier,
            created_at,
            expires_at,
            pool_balance,
            original_pool_balance: pool_balance,
            total_bytes: 0,
            distribution_posted: false,
            distribution_root: [0u8; 32],
        });
        info!(
            "[MOCK] Added subscription with expiry for {} ({:?}, epoch: {}, pool: {}, expires: {})",
            hex_encode(&user_pubkey[..8]),
            tier,
            current_epoch,
            pool_balance,
            expires_at,
        );
        Ok(current_epoch)
    }
}

/// Helper to encode bytes as hex (first N bytes)
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SettlementConfig::default();
        assert!(config.rpc_url.contains("solana"));
        assert_eq!(config.commitment, "confirmed");
        assert_eq!(config.mode, SettlementMode::Mock);
    }

    #[test]
    fn test_mock_config() {
        let config = SettlementConfig::mock();
        assert_eq!(config.mode, SettlementMode::Mock);
    }

    #[test]
    fn test_devnet_config() {
        let program_id = [42u8; 32];
        let config = SettlementConfig::devnet(program_id);
        assert_eq!(config.mode, SettlementMode::Live);
        assert_eq!(config.program_id, program_id);
    }

    #[test]
    fn test_receipt_dedup_hash() {
        let receipt = ForwardReceipt {
            request_id: [1u8; 32],
            shard_id: [10u8; 32],
            sender_pubkey: [0xFFu8; 32],
            receiver_pubkey: [2u8; 32],
            user_proof: [5u8; 32],
            payload_size: 1024,
            epoch: 0,
            timestamp: 1000,
            signature: [0u8; 64],
        };

        let hash1 = SettlementClient::receipt_dedup_hash(&receipt);
        let hash2 = SettlementClient::receipt_dedup_hash(&receipt);
        assert_eq!(hash1, hash2); // Deterministic

        // Different shard_id = different hash
        let receipt2 = ForwardReceipt {
            shard_id: [11u8; 32],
            ..receipt.clone()
        };
        let hash3 = SettlementClient::receipt_dedup_hash(&receipt2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_receipt_dedup_ignores_timestamp() {
        let receipt1 = ForwardReceipt {
            request_id: [1u8; 32],
            shard_id: [10u8; 32],
            sender_pubkey: [0xFFu8; 32],
            receiver_pubkey: [2u8; 32],
            user_proof: [5u8; 32],
            payload_size: 1024,
            epoch: 0,
            timestamp: 1000,
            signature: [0u8; 64],
        };

        let receipt2 = ForwardReceipt {
            timestamp: 2000,
            ..receipt1.clone()
        };

        assert_eq!(
            SettlementClient::receipt_dedup_hash(&receipt1),
            SettlementClient::receipt_dedup_hash(&receipt2),
        );
    }

    #[tokio::test]
    async fn test_client_creation() {
        let config = SettlementConfig::mock();
        let client = SettlementClient::new(config, [0u8; 32]);
        assert!(client.is_mock());
    }

    #[tokio::test]
    async fn test_mock_subscribe() {
        let config = SettlementConfig::mock();
        let client = SettlementClient::new(config, [0u8; 32]);

        let user_pubkey = [1u8; 32];
        let sub = Subscribe {
            user_pubkey,
            tier: SubscriptionTier::Standard,
            payment_amount: 15_000_000,
        };

        let (sig, epoch) = client.subscribe(sub).await.unwrap();
        assert_ne!(sig, [0u8; 64]);
        assert_eq!(epoch, 0);

        let state = client.get_subscription_state(user_pubkey, epoch).await.unwrap();
        assert!(state.is_some());
        let state = state.unwrap();
        assert_eq!(state.tier, SubscriptionTier::Standard);
        assert_eq!(state.epoch, 0);
        assert_eq!(state.pool_balance, 15_000_000);
        assert!(state.created_at > 0);
        assert!(!state.distribution_posted);

        assert!(client.is_subscribed(user_pubkey).await.unwrap());

        // Second subscribe increments epoch
        let (_, epoch2) = client.subscribe(Subscribe {
            user_pubkey,
            tier: SubscriptionTier::Premium,
            payment_amount: 40_000_000,
        }).await.unwrap();
        assert_eq!(epoch2, 1);
    }

    #[tokio::test]
    async fn test_mock_post_distribution_and_claim() {
        let config = SettlementConfig::mock();
        let client = SettlementClient::new(config, [0u8; 32]);

        let user_pubkey = [1u8; 32];
        let node1 = [2u8; 32];
        let node2 = [3u8; 32];

        // Create an already-expired subscription
        let now = SettlementClient::now();
        let epoch = client.add_mock_subscription_with_expiry(
            user_pubkey,
            SubscriptionTier::Standard,
            1_000_000,
            now - 40 * 24 * 3600, // created 40 days ago
            now - 10 * 24 * 3600, // expired 10 days ago (past grace)
        ).unwrap();

        // Post distribution: node1 has 7, node2 has 3 = 10 total
        let dist_root = [0xAA; 32];
        client.post_distribution(PostDistribution {
            user_pubkey,
            epoch,
            distribution_root: dist_root,
            total_bytes: 10,
        }).await.unwrap();

        // Verify distribution was stored
        let sub = client.get_subscription_state(user_pubkey, epoch).await.unwrap().unwrap();
        assert!(sub.distribution_posted);
        assert_eq!(sub.distribution_root, dist_root);
        assert_eq!(sub.total_bytes, 10);

        // Node1 claims 7/10 * 1_000_000 = 700_000 (direct payout)
        client.claim_rewards(ClaimRewards {
            user_pubkey,
            epoch,
            node_pubkey: node1,
            relay_bytes: 7,
            leaf_index: 0,
            merkle_proof: vec![],
            light_params: None,
        }).await.unwrap();

        // Node2 claims 3/10 * 1_000_000 = 300_000 (direct payout)
        client.claim_rewards(ClaimRewards {
            user_pubkey,
            epoch,
            node_pubkey: node2,
            relay_bytes: 3,
            leaf_index: 0,
            merkle_proof: vec![],
            light_params: None,
        }).await.unwrap();

        // Pool should be drained
        let sub = client.get_subscription_state(user_pubkey, epoch).await.unwrap().unwrap();
        assert_eq!(sub.pool_balance, 0);
    }

    #[tokio::test]
    async fn test_epoch_phase_enforcement_post_distribution() {
        let config = SettlementConfig::mock();
        let client = SettlementClient::new(config, [0u8; 32]);

        let user_pubkey = [1u8; 32];

        // Active subscription — post_distribution should fail
        let epoch = client.add_mock_subscription(user_pubkey, SubscriptionTier::Standard, 1_000_000).unwrap();

        let result = client.post_distribution(PostDistribution {
            user_pubkey,
            epoch,
            distribution_root: [0xAA; 32],
            total_bytes: 100,
        }).await;

        assert!(matches!(result, Err(SettlementError::EpochNotComplete)));
    }

    #[tokio::test]
    async fn test_epoch_phase_enforcement_claim() {
        let config = SettlementConfig::mock();
        let client = SettlementClient::new(config, [0u8; 32]);

        let user_pubkey = [1u8; 32];

        // Active subscription — claim should fail
        let epoch = client.add_mock_subscription(user_pubkey, SubscriptionTier::Standard, 1_000_000).unwrap();

        let result = client.claim_rewards(ClaimRewards {
            user_pubkey,
            epoch,
            node_pubkey: [2u8; 32],
            relay_bytes: 10,
            leaf_index: 0,
            merkle_proof: vec![],
            light_params: None,
        }).await;

        assert!(matches!(result, Err(SettlementError::EpochNotComplete)));
    }

    #[tokio::test]
    async fn test_claim_requires_distribution() {
        let config = SettlementConfig::mock();
        let client = SettlementClient::new(config, [0u8; 32]);

        let user_pubkey = [1u8; 32];
        let now = SettlementClient::now();

        // Expired subscription, past grace, but no distribution posted
        let epoch = client.add_mock_subscription_with_expiry(
            user_pubkey,
            SubscriptionTier::Standard,
            1_000_000,
            now - 40 * 24 * 3600,
            now - 10 * 24 * 3600,
        ).unwrap();

        let result = client.claim_rewards(ClaimRewards {
            user_pubkey,
            epoch,
            node_pubkey: [2u8; 32],
            relay_bytes: 10,
            leaf_index: 0,
            merkle_proof: vec![],
            light_params: None,
        }).await;

        assert!(matches!(result, Err(SettlementError::DistributionNotPosted)));
    }

    #[tokio::test]
    async fn test_double_claim_rejected() {
        let config = SettlementConfig::mock();
        let client = SettlementClient::new(config, [0u8; 32]);

        let user_pubkey = [1u8; 32];
        let node = [2u8; 32];
        let now = SettlementClient::now();

        let epoch = client.add_mock_subscription_with_expiry(
            user_pubkey,
            SubscriptionTier::Standard,
            1_000_000,
            now - 40 * 24 * 3600,
            now - 10 * 24 * 3600,
        ).unwrap();

        client.post_distribution(PostDistribution {
            user_pubkey,
            epoch,
            distribution_root: [0xAA; 32],
            total_bytes: 10,
        }).await.unwrap();

        // First claim succeeds
        client.claim_rewards(ClaimRewards {
            user_pubkey,
            epoch,
            node_pubkey: node,
            relay_bytes: 5,
            leaf_index: 0,
            merkle_proof: vec![],
            light_params: None,
        }).await.unwrap();

        // Second claim fails
        let result = client.claim_rewards(ClaimRewards {
            user_pubkey,
            epoch,
            node_pubkey: node,
            relay_bytes: 5,
            leaf_index: 0,
            merkle_proof: vec![],
            light_params: None,
        }).await;

        assert!(matches!(result, Err(SettlementError::AlreadyClaimed)));
    }

    #[tokio::test]
    async fn test_not_subscribed() {
        let config = SettlementConfig::mock();
        let client = SettlementClient::new(config, [0u8; 32]);

        assert!(!client.is_subscribed([99u8; 32]).await.unwrap());
    }

    #[test]
    fn test_config_custom_rpc() {
        let config = SettlementConfig {
            mode: SettlementMode::Live,
            rpc_url: "http://localhost:8899".to_string(),
            program_id: [1u8; 32],
            usdc_mint: USDC_MINT_DEVNET,
            commitment: "finalized".to_string(),
            helius_api_key: None,
            light_trees: None,
        };

        assert_eq!(config.rpc_url, "http://localhost:8899");
        assert_eq!(config.program_id, [1u8; 32]);
        assert_eq!(config.commitment, "finalized");
        assert_eq!(config.mode, SettlementMode::Live);
    }

    #[tokio::test]
    async fn test_first_writer_wins_distribution() {
        let config = SettlementConfig::mock();
        let client = SettlementClient::new(config, [0u8; 32]);

        let user_pubkey = [1u8; 32];
        let now = SettlementClient::now();

        let epoch = client.add_mock_subscription_with_expiry(
            user_pubkey,
            SubscriptionTier::Standard,
            1_000_000,
            now - 40 * 24 * 3600,
            now - 10 * 24 * 3600,
        ).unwrap();

        // First post succeeds
        client.post_distribution(PostDistribution {
            user_pubkey,
            epoch,
            distribution_root: [0xAA; 32],
            total_bytes: 100,
        }).await.unwrap();

        // Second post fails — first-writer-wins
        let result = client.post_distribution(PostDistribution {
            user_pubkey,
            epoch,
            distribution_root: [0xBB; 32],
            total_bytes: 200,
        }).await;

        assert!(matches!(result, Err(SettlementError::DistributionAlreadyPosted)));

        // Original distribution is preserved
        let sub = client.get_subscription_state(user_pubkey, epoch).await.unwrap().unwrap();
        assert!(sub.distribution_posted);
        assert_eq!(sub.distribution_root, [0xAA; 32]);
        assert_eq!(sub.total_bytes, 100);
    }

    #[tokio::test]
    async fn test_per_epoch_isolation() {
        let config = SettlementConfig::mock();
        let client = SettlementClient::new(config, [0u8; 32]);

        let user = [1u8; 32];
        let now = SettlementClient::now();

        // Create two epochs
        let epoch0 = client.add_mock_subscription_with_expiry(
            user, SubscriptionTier::Standard, 1_000_000,
            now - 80 * 24 * 3600, now - 50 * 24 * 3600,
        ).unwrap();
        let epoch1 = client.add_mock_subscription_with_expiry(
            user, SubscriptionTier::Premium, 2_000_000,
            now - 40 * 24 * 3600, now - 10 * 24 * 3600,
        ).unwrap();

        assert_eq!(epoch0, 0);
        assert_eq!(epoch1, 1);

        // Each epoch has independent state
        let sub0 = client.get_subscription_state(user, epoch0).await.unwrap().unwrap();
        let sub1 = client.get_subscription_state(user, epoch1).await.unwrap().unwrap();
        assert_eq!(sub0.pool_balance, 1_000_000);
        assert_eq!(sub1.pool_balance, 2_000_000);
        assert_eq!(sub0.tier, SubscriptionTier::Standard);
        assert_eq!(sub1.tier, SubscriptionTier::Premium);

        // Claiming on epoch0 doesn't affect epoch1
        client.post_distribution(PostDistribution {
            user_pubkey: user, epoch: epoch0,
            distribution_root: [0xAA; 32], total_bytes: 10,
        }).await.unwrap();
        client.claim_rewards(ClaimRewards {
            user_pubkey: user, epoch: epoch0, node_pubkey: [2u8; 32],
            relay_bytes: 10, leaf_index: 0, merkle_proof: vec![],
            light_params: None,
        }).await.unwrap();

        let sub0_after = client.get_subscription_state(user, epoch0).await.unwrap().unwrap();
        let sub1_after = client.get_subscription_state(user, epoch1).await.unwrap().unwrap();
        assert_eq!(sub0_after.pool_balance, 0);
        assert_eq!(sub1_after.pool_balance, 2_000_000); // Untouched
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0x00, 0xFF, 0xAB]), "00ffab");
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_encode(&[0x12, 0x34, 0x56, 0x78]), "12345678");
    }
}
