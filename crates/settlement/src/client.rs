//! Settlement client for interacting with Solana
//!
//! Supports two modes:
//! - **Mock Mode**: For development/testing without Solana. All operations succeed
//!   and state is tracked in-memory.
//! - **Live Mode**: Actual Solana RPC calls to the TunnelCraft settlement program.

use std::collections::HashMap;
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

use tunnelcraft_core::{Id, PublicKey, ChainEntry};

use crate::{
    SettlementError, Result,
    PurchaseCredits, SettleRequest, SettleResponseShard, ClaimWork, Withdraw,
    RequestState, NodePoints, OnChainStatus, TransactionSignature,
};

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
    /// Commitment level for transactions
    pub commitment: String,
    /// Initial mock credits for development (Mock mode only)
    pub mock_initial_credits: u64,
}

impl Default for SettlementConfig {
    fn default() -> Self {
        Self {
            mode: SettlementMode::Mock, // Default to mock for development
            rpc_url: "https://api.devnet.solana.com".to_string(),
            program_id: [0u8; 32],
            commitment: "confirmed".to_string(),
            mock_initial_credits: 10000, // 10k credits for testing
        }
    }
}

impl SettlementConfig {
    /// Create a mock configuration for development
    pub fn mock() -> Self {
        Self {
            mode: SettlementMode::Mock,
            mock_initial_credits: 10000,
            ..Default::default()
        }
    }

    /// Create a live configuration for Solana devnet
    pub fn devnet(program_id: [u8; 32]) -> Self {
        Self {
            mode: SettlementMode::Live,
            rpc_url: "https://api.devnet.solana.com".to_string(),
            program_id,
            ..Default::default()
        }
    }

    /// Create a live configuration for Solana mainnet
    pub fn mainnet(program_id: [u8; 32]) -> Self {
        Self {
            mode: SettlementMode::Live,
            rpc_url: "https://api.mainnet-beta.solana.com".to_string(),
            program_id,
            commitment: "finalized".to_string(),
            ..Default::default()
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
    /// Credit balances by credit_hash
    credits: HashMap<Id, u64>,
    /// Request states
    requests: HashMap<Id, RequestState>,
    /// Node points
    node_points: HashMap<PublicKey, NodePoints>,
    /// Transaction counter for generating mock signatures
    tx_counter: u64,
}

/// Instruction discriminators for the TunnelCraft settlement program
/// These match the Anchor program instruction indices
mod instruction {
    pub const PURCHASE_CREDITS: u8 = 0;
    pub const SETTLE_REQUEST: u8 = 1;
    pub const SETTLE_RESPONSE: u8 = 2;
    pub const CLAIM_WORK: u8 = 3;
    pub const WITHDRAW: u8 = 4;
}

/// Settlement client for on-chain operations
///
/// This client abstracts the Solana RPC calls and transaction building.
/// In mock mode, all operations succeed and state is tracked in-memory.
pub struct SettlementClient {
    config: SettlementConfig,
    /// Our keypair for signing transactions (stored as bytes for thread safety)
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
        let mock_initial_credits = config.mock_initial_credits;
        let is_mock = config.mode == SettlementMode::Mock;

        let client = Self {
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
        };

        // In mock mode, initialize with some credits for the signer
        if is_mock && mock_initial_credits > 0 {
            let credit_secret = Self::generate_credit_secret();
            let credit_hash = Self::hash_credit_secret(&credit_secret);
            if let Ok(mut state) = client.mock_state.write() {
                state.credits.insert(credit_hash, mock_initial_credits);
                info!(
                    "[MOCK] Initialized with {} credits (hash: {})",
                    mock_initial_credits,
                    hex_encode(&credit_hash[..8])
                );
            }
        }

        client
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

    /// Check if running in mock mode
    pub fn is_mock(&self) -> bool {
        self.config.mode == SettlementMode::Mock
    }

    /// Get program ID as Pubkey
    fn program_id(&self) -> Pubkey {
        Pubkey::new_from_array(self.config.program_id)
    }

    /// Generate a mock transaction signature (call when NOT holding state lock)
    fn mock_signature(&self) -> TransactionSignature {
        let mut state = self.mock_state.write().expect("settlement lock poisoned");
        Self::generate_mock_signature(&mut state)
    }

    /// Generate mock signature (call when already holding lock)
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

    /// Generate credit hash from secret
    pub fn hash_credit_secret(secret: &[u8; 32]) -> Id {
        let mut hasher = Sha256::new();
        hasher.update(secret);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Generate a random credit secret
    pub fn generate_credit_secret() -> [u8; 32] {
        let mut secret = [0u8; 32];
        use std::time::{SystemTime, UNIX_EPOCH};
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let mut hasher = Sha256::new();
        hasher.update(nonce.to_le_bytes());
        hasher.update(b"tunnelcraft_credit_secret");
        let result = hasher.finalize();
        secret.copy_from_slice(&result);
        secret
    }

    /// Derive PDA for credit account
    fn credit_pda(&self, credit_hash: &Id) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[b"credit", credit_hash],
            &self.program_id(),
        )
    }

    /// Derive PDA for request state account
    fn request_pda(&self, request_id: &Id) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[b"request", request_id],
            &self.program_id(),
        )
    }

    /// Derive PDA for node points account
    fn node_pda(&self, node_pubkey: &PublicKey) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[b"node", node_pubkey],
            &self.program_id(),
        )
    }

    /// Send a transaction to Solana
    async fn send_transaction(&self, instruction: Instruction) -> Result<TransactionSignature> {
        let rpc = self.rpc_client.as_ref()
            .ok_or_else(|| SettlementError::RpcError("RPC client not initialized".to_string()))?;

        let keypair = self.signer_keypair.as_ref()
            .ok_or(SettlementError::NotAuthorized)?;

        // Get recent blockhash
        let blockhash = rpc.get_latest_blockhash().await
            .map_err(|e| SettlementError::RpcError(e.to_string()))?;

        // Create and sign transaction
        let tx = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&keypair.pubkey()),
            &[keypair],
            blockhash,
        );

        // Submit transaction
        let signature = rpc.send_and_confirm_transaction(&tx).await
            .map_err(|e| SettlementError::TransactionFailed(e.to_string()))?;

        info!("Transaction confirmed: {}", signature);

        // Convert signature to our format
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature.as_ref());
        Ok(sig_bytes)
    }

    /// Purchase credits on-chain
    ///
    /// Returns the transaction signature
    pub async fn purchase_credits(
        &self,
        credits: PurchaseCredits,
    ) -> Result<TransactionSignature> {
        info!(
            "Purchasing {} credits with hash {}",
            credits.amount,
            hex_encode(&credits.credit_hash[..8])
        );

        if self.is_mock() {
            // Mock mode: add credits to in-memory state
            let mut state = self.mock_state.write().expect("settlement lock poisoned");
            let balance = state.credits.entry(credits.credit_hash).or_insert(0);
            *balance = balance.saturating_add(credits.amount);
            info!(
                "[MOCK] Credits added. New balance: {}",
                *balance
            );
            return Ok(Self::generate_mock_signature(&mut state));
        }

        // Live mode: build and send transaction
        let (credit_pda, _bump) = self.credit_pda(&credits.credit_hash);
        let signer = Pubkey::new_from_array(self.signer_pubkey);

        // Build instruction data
        let mut data = vec![instruction::PURCHASE_CREDITS];
        data.extend_from_slice(&credits.credit_hash);
        data.extend_from_slice(&credits.amount.to_le_bytes());

        let instruction = Instruction {
            program_id: self.program_id(),
            accounts: vec![
                AccountMeta::new(signer, true),           // payer
                AccountMeta::new(credit_pda, false),      // credit account (PDA)
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data,
        };

        self.send_transaction(instruction).await
    }

    /// Submit request settlement (exit node)
    ///
    /// Records work done with chain-signed credit proof for reconciliation.
    pub async fn settle_request(
        &self,
        settlement: SettleRequest,
    ) -> Result<TransactionSignature> {
        info!(
            "Settling request {} with credit proof (epoch {})",
            hex_encode(&settlement.request_id[..8]),
            settlement.credit_proof.epoch
        );

        debug!(
            "User pubkey: {}, balance: {}, chains: {}",
            hex_encode(&settlement.user_pubkey[..8]),
            settlement.credit_proof.balance,
            settlement.request_chains.len()
        );

        if self.is_mock() {
            let mut state = self.mock_state.write().expect("settlement lock poisoned");

            // Verify credit proof has sufficient balance (simplified)
            if settlement.credit_proof.balance == 0 {
                return Err(SettlementError::InsufficientCredits);
            }

            // Calculate total points from all chains
            let total_points: u64 = settlement.request_chains.iter()
                .map(|chain| chain.len() as u64 * 100) // Simplified
                .sum();

            // Create request state as COMPLETE (exit settlement directly completes)
            let request_state = RequestState {
                request_id: settlement.request_id,
                status: OnChainStatus::Complete,
                user_pubkey: Some(settlement.user_pubkey),
                credit_amount: 1,
                updated_at: Self::now(),
                total_points,
            };
            state.requests.insert(settlement.request_id, request_state);

            // Award points to all relays in request chains
            for chain in &settlement.request_chains {
                for (i, entry) in chain.iter().enumerate() {
                    let points = 100u64.saturating_sub(i as u64 * 10);
                    let node_points = state.node_points
                        .entry(entry.pubkey)
                        .or_insert_with(|| NodePoints {
                            node_pubkey: entry.pubkey,
                            current_epoch_points: 0,
                            lifetime_points: 0,
                            last_withdrawal_epoch: 0,
                        });
                    node_points.current_epoch_points += points;
                    node_points.lifetime_points += points;
                }
            }

            info!(
                "[MOCK] Request {} settled (COMPLETE) for epoch {}",
                hex_encode(&settlement.request_id[..8]),
                settlement.credit_proof.epoch
            );
            return Ok(Self::generate_mock_signature(&mut state));
        }

        // Live mode: build and send transaction
        let (request_pda, _) = self.request_pda(&settlement.request_id);
        let signer = Pubkey::new_from_array(self.signer_pubkey);

        // Serialize credit proof and chains
        let proof_data = bincode::serialize(&settlement.credit_proof)
            .map_err(|e| SettlementError::SerializationError(e.to_string()))?;
        let chains_data = bincode::serialize(&settlement.request_chains)
            .map_err(|e| SettlementError::SerializationError(e.to_string()))?;

        // Build instruction data
        let mut data = vec![instruction::SETTLE_REQUEST];
        data.extend_from_slice(&settlement.request_id);
        data.extend_from_slice(&settlement.user_pubkey);
        data.extend_from_slice(&(proof_data.len() as u32).to_le_bytes());
        data.extend_from_slice(&proof_data);
        data.extend_from_slice(&(chains_data.len() as u32).to_le_bytes());
        data.extend_from_slice(&chains_data);

        let instruction = Instruction {
            program_id: self.program_id(),
            accounts: vec![
                AccountMeta::new(signer, true),           // exit node (signer)
                AccountMeta::new(request_pda, false),     // request state (PDA)
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data,
        };

        self.send_transaction(instruction).await
    }

    /// Submit response shard settlement (last relay for each shard)
    ///
    /// Each response shard is settled independently. Awards points to all
    /// nodes in the response chain (Exit → Relays → User).
    pub async fn settle_response_shard(
        &self,
        settlement: SettleResponseShard,
    ) -> Result<TransactionSignature> {
        info!(
            "Settling response shard {} for request {}",
            hex_encode(&settlement.shard_id[..8]),
            hex_encode(&settlement.request_id[..8])
        );

        if self.is_mock() {
            let mut state = self.mock_state.write().expect("settlement lock poisoned");

            // Award points to relays in the response chain
            // Points are independent of request state
            for (i, entry) in settlement.response_chain.iter().enumerate() {
                let points = 100u64.saturating_sub(i as u64 * 10);
                let node_points = state.node_points
                    .entry(entry.pubkey)
                    .or_insert_with(|| NodePoints {
                        node_pubkey: entry.pubkey,
                        current_epoch_points: 0,
                        lifetime_points: 0,
                        last_withdrawal_epoch: 0,
                    });
                node_points.current_epoch_points += points;
                node_points.lifetime_points += points;
            }

            info!(
                "[MOCK] Response shard {} settled. Chain length: {}",
                hex_encode(&settlement.shard_id[..8]),
                settlement.response_chain.len()
            );
            return Ok(Self::generate_mock_signature(&mut state));
        }

        // Live mode: build and send transaction
        let signer = Pubkey::new_from_array(self.signer_pubkey);

        // Serialize the response chain
        let chain_data = bincode::serialize(&settlement.response_chain)
            .map_err(|e| SettlementError::SerializationError(e.to_string()))?;

        // Build instruction data
        let mut data = vec![instruction::SETTLE_RESPONSE];
        data.extend_from_slice(&settlement.request_id);
        data.extend_from_slice(&settlement.shard_id);
        data.extend_from_slice(&(chain_data.len() as u32).to_le_bytes());
        data.extend_from_slice(&chain_data);

        // Build accounts - include node PDAs for all relays in chain
        let mut accounts = vec![
            AccountMeta::new(signer, true),           // last relay (signer)
        ];

        // Add node accounts for point distribution
        for entry in &settlement.response_chain {
            let (node_pda, _) = self.node_pda(&entry.pubkey);
            accounts.push(AccountMeta::new(node_pda, false));
        }

        accounts.push(AccountMeta::new_readonly(system_program::id(), false));

        let instruction = Instruction {
            program_id: self.program_id(),
            accounts,
            data,
        };

        self.send_transaction(instruction).await
    }

    /// Claim work points from a completed request
    pub async fn claim_work(
        &self,
        claim: ClaimWork,
    ) -> Result<TransactionSignature> {
        debug!(
            "Claiming work for request {}",
            hex_encode(&claim.request_id[..8])
        );

        if self.is_mock() {
            // First check with read lock
            {
                let state = self.mock_state.read().expect("settlement lock poisoned");

                // Verify request is COMPLETE
                let request = state.requests.get(&claim.request_id)
                    .ok_or_else(|| SettlementError::RequestNotFound(
                        hex_encode(&claim.request_id[..8])
                    ))?;

                if request.status != OnChainStatus::Complete {
                    return Err(SettlementError::TransactionFailed(
                        "Request not complete".to_string()
                    ));
                }
            } // Release read lock

            // Points were already awarded in settle_response for mock mode
            info!(
                "[MOCK] Work claimed for request {}",
                hex_encode(&claim.request_id[..8])
            );
            return Ok(self.mock_signature());
        }

        // Live mode
        let (request_pda, _) = self.request_pda(&claim.request_id);
        let (node_pda, _) = self.node_pda(&claim.node_pubkey);
        let signer = Pubkey::new_from_array(self.signer_pubkey);

        let mut data = vec![instruction::CLAIM_WORK];
        data.extend_from_slice(&claim.request_id);
        data.extend_from_slice(&claim.node_pubkey);

        let instruction = Instruction {
            program_id: self.program_id(),
            accounts: vec![
                AccountMeta::new(signer, true),
                AccountMeta::new_readonly(request_pda, false),
                AccountMeta::new(node_pda, false),
            ],
            data,
        };

        self.send_transaction(instruction).await
    }

    /// Withdraw accumulated rewards
    pub async fn withdraw(
        &self,
        withdraw: Withdraw,
    ) -> Result<TransactionSignature> {
        info!("Withdrawing from epoch {}", withdraw.epoch);

        if self.is_mock() {
            // In mock mode, just log it
            info!("[MOCK] Withdrawal processed for epoch {}", withdraw.epoch);
            return Ok(self.mock_signature());
        }

        // Live mode
        let (node_pda, _) = self.node_pda(&self.signer_pubkey);
        let signer = Pubkey::new_from_array(self.signer_pubkey);

        let mut data = vec![instruction::WITHDRAW];
        data.extend_from_slice(&withdraw.epoch.to_le_bytes());
        data.extend_from_slice(&withdraw.amount.to_le_bytes());

        let instruction = Instruction {
            program_id: self.program_id(),
            accounts: vec![
                AccountMeta::new(signer, true),
                AccountMeta::new(node_pda, false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data,
        };

        self.send_transaction(instruction).await
    }

    /// Get request state from chain
    pub async fn get_request_state(
        &self,
        request_id: Id,
    ) -> Result<Option<RequestState>> {
        debug!("Fetching state for request {}", hex_encode(&request_id[..8]));

        if self.is_mock() {
            let state = self.mock_state.read().expect("settlement lock poisoned");
            return Ok(state.requests.get(&request_id).cloned());
        }

        // Live mode: fetch account from Solana
        let rpc = self.rpc_client.as_ref()
            .ok_or_else(|| SettlementError::RpcError("RPC client not initialized".to_string()))?;

        let (request_pda, _) = self.request_pda(&request_id);

        match rpc.get_account(&request_pda).await {
            Ok(account) => {
                // Deserialize account data
                // Skip first 8 bytes (Anchor discriminator)
                if account.data.len() < 8 {
                    return Ok(None);
                }

                // Parse the account data (simplified - production would use Anchor)
                let data = &account.data[8..];
                if data.len() < 32 + 1 + 32 + 8 + 8 + 8 {
                    return Ok(None);
                }

                let mut request_id_bytes = [0u8; 32];
                request_id_bytes.copy_from_slice(&data[0..32]);

                let status = match data[32] {
                    0 => OnChainStatus::Unknown,
                    1 => OnChainStatus::Complete,
                    2 => OnChainStatus::Expired,
                    _ => OnChainStatus::Unknown,
                };

                let has_user = data[33] == 1;
                let user_pubkey = if has_user {
                    let mut pubkey = [0u8; 32];
                    pubkey.copy_from_slice(&data[34..66]);
                    Some(pubkey)
                } else {
                    None
                };

                let offset = if has_user { 66 } else { 34 };
                let credit_amount = u64::from_le_bytes(data[offset..offset+8].try_into().expect("slice is exactly 8 bytes"));
                let updated_at = u64::from_le_bytes(data[offset+8..offset+16].try_into().expect("slice is exactly 8 bytes"));
                let total_points = u64::from_le_bytes(data[offset+16..offset+24].try_into().expect("slice is exactly 8 bytes"));

                Ok(Some(RequestState {
                    request_id: request_id_bytes,
                    status,
                    user_pubkey,
                    credit_amount,
                    updated_at,
                    total_points,
                }))
            }
            Err(e) => {
                debug!("Request account not found: {}", e);
                Ok(None)
            }
        }
    }

    /// Get node's accumulated points
    pub async fn get_node_points(
        &self,
        node_pubkey: PublicKey,
    ) -> Result<NodePoints> {
        debug!("Fetching points for node {}", hex_encode(&node_pubkey[..8]));

        if self.is_mock() {
            let state = self.mock_state.read().expect("settlement lock poisoned");
            return Ok(state.node_points.get(&node_pubkey).cloned().unwrap_or(NodePoints {
                node_pubkey,
                current_epoch_points: 0,
                lifetime_points: 0,
                last_withdrawal_epoch: 0,
            }));
        }

        // Live mode: fetch account from Solana
        let rpc = self.rpc_client.as_ref()
            .ok_or_else(|| SettlementError::RpcError("RPC client not initialized".to_string()))?;

        let (node_pda, _) = self.node_pda(&node_pubkey);

        match rpc.get_account(&node_pda).await {
            Ok(account) => {
                // Parse account data (skip 8-byte discriminator)
                let data = &account.data[8..];
                if data.len() < 32 + 8 + 8 + 8 {
                    return Ok(NodePoints {
                        node_pubkey,
                        current_epoch_points: 0,
                        lifetime_points: 0,
                        last_withdrawal_epoch: 0,
                    });
                }

                let current_epoch_points = u64::from_le_bytes(data[32..40].try_into().expect("slice is exactly 8 bytes"));
                let lifetime_points = u64::from_le_bytes(data[40..48].try_into().expect("slice is exactly 8 bytes"));
                let last_withdrawal_epoch = u64::from_le_bytes(data[48..56].try_into().expect("slice is exactly 8 bytes"));

                Ok(NodePoints {
                    node_pubkey,
                    current_epoch_points,
                    lifetime_points,
                    last_withdrawal_epoch,
                })
            }
            Err(_) => Ok(NodePoints {
                node_pubkey,
                current_epoch_points: 0,
                lifetime_points: 0,
                last_withdrawal_epoch: 0,
            }),
        }
    }

    /// Verify a credit hash exists and has balance
    pub async fn verify_credit(&self, credit_hash: Id) -> Result<u64> {
        debug!("Verifying credit {}", hex_encode(&credit_hash[..8]));

        if self.is_mock() {
            let state = self.mock_state.read().expect("settlement lock poisoned");
            return Ok(state.credits.get(&credit_hash).copied().unwrap_or(0));
        }

        // Live mode: fetch credit account
        let rpc = self.rpc_client.as_ref()
            .ok_or_else(|| SettlementError::RpcError("RPC client not initialized".to_string()))?;

        let (credit_pda, _) = self.credit_pda(&credit_hash);

        match rpc.get_account(&credit_pda).await {
            Ok(account) => {
                // Parse credit balance from account data
                let data = &account.data[8..]; // Skip discriminator
                if data.len() >= 40 { // credit_hash (32) + balance (8)
                    let balance = u64::from_le_bytes(data[32..40].try_into().expect("slice is exactly 8 bytes"));
                    Ok(balance)
                } else {
                    Ok(0)
                }
            }
            Err(_) => Ok(0),
        }
    }

    /// Add credits directly (mock mode only, for testing)
    pub fn add_mock_credits(&self, credit_hash: Id, amount: u64) -> Result<()> {
        if !self.is_mock() {
            return Err(SettlementError::NotAuthorized);
        }

        let mut state = self.mock_state.write().expect("settlement lock poisoned");
        let balance = state.credits.entry(credit_hash).or_insert(0);
        *balance = balance.saturating_add(amount);
        info!(
            "[MOCK] Added {} credits to {}. New balance: {}",
            amount,
            hex_encode(&credit_hash[..8]),
            *balance
        );
        Ok(())
    }

    /// Set credits directly (mock mode only, for testing)
    pub fn set_mock_credits(&self, credit_hash: Id, amount: u64) -> Result<()> {
        if !self.is_mock() {
            return Err(SettlementError::NotAuthorized);
        }

        let mut state = self.mock_state.write().expect("settlement lock poisoned");
        state.credits.insert(credit_hash, amount);
        info!(
            "[MOCK] Set credits for {} to {}",
            hex_encode(&credit_hash[..8]),
            amount
        );
        Ok(())
    }

    /// Calculate points for a relay based on chain position
    pub fn calculate_relay_points(chain: &[ChainEntry], relay_pubkey: &PublicKey) -> u64 {
        // Points decrease with position (earlier = more work = more points)
        // First relay gets 100, second gets 90, etc.
        for (i, entry) in chain.iter().enumerate() {
            if entry.pubkey == *relay_pubkey {
                return 100u64.saturating_sub(i as u64 * 10);
            }
        }
        0
    }
}

/// Helper to encode bytes as hex (first N bytes)
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnelcraft_core::CreditProof;

    #[test]
    fn test_credit_hash() {
        let secret = [42u8; 32];
        let hash = SettlementClient::hash_credit_secret(&secret);

        // Hash should be deterministic
        let hash2 = SettlementClient::hash_credit_secret(&secret);
        assert_eq!(hash, hash2);

        // Different secret = different hash
        let secret2 = [43u8; 32];
        let hash3 = SettlementClient::hash_credit_secret(&secret2);
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_generate_credit_secret() {
        let secret1 = SettlementClient::generate_credit_secret();
        let secret2 = SettlementClient::generate_credit_secret();

        // Secrets should be different (with very high probability)
        assert_eq!(secret1.len(), 32);
        assert_eq!(secret2.len(), 32);
    }

    #[test]
    fn test_relay_points_calculation() {
        let chain = vec![
            ChainEntry::new([1u8; 32], [0u8; 64], 3),
            ChainEntry::new([2u8; 32], [0u8; 64], 2),
            ChainEntry::new([3u8; 32], [0u8; 64], 1),
        ];

        assert_eq!(SettlementClient::calculate_relay_points(&chain, &[1u8; 32]), 100);
        assert_eq!(SettlementClient::calculate_relay_points(&chain, &[2u8; 32]), 90);
        assert_eq!(SettlementClient::calculate_relay_points(&chain, &[3u8; 32]), 80);
        assert_eq!(SettlementClient::calculate_relay_points(&chain, &[4u8; 32]), 0);
    }

    #[test]
    fn test_default_config() {
        let config = SettlementConfig::default();
        assert!(config.rpc_url.contains("solana"));
        assert_eq!(config.commitment, "confirmed");
        assert_eq!(config.mode, SettlementMode::Mock);
        assert_eq!(config.mock_initial_credits, 10000);
    }

    #[test]
    fn test_mock_config() {
        let config = SettlementConfig::mock();
        assert_eq!(config.mode, SettlementMode::Mock);
        assert_eq!(config.mock_initial_credits, 10000);
    }

    #[test]
    fn test_devnet_config() {
        let program_id = [42u8; 32];
        let config = SettlementConfig::devnet(program_id);
        assert_eq!(config.mode, SettlementMode::Live);
        assert_eq!(config.program_id, program_id);
    }

    #[tokio::test]
    async fn test_client_creation() {
        let config = SettlementConfig::mock();
        let client = SettlementClient::new(config, [0u8; 32]);

        assert!(client.is_mock());
        let points = client.get_node_points([0u8; 32]).await.unwrap();
        assert_eq!(points.current_epoch_points, 0);
    }

    // ==================== MOCK MODE TESTS ====================

    #[tokio::test]
    async fn test_mock_purchase_credits() {
        let config = SettlementConfig::mock();
        let client = SettlementClient::new(config, [0u8; 32]);

        let credit_hash = [1u8; 32];
        let purchase = PurchaseCredits {
            credit_hash,
            amount: 100,
        };

        let sig = client.purchase_credits(purchase).await.unwrap();
        assert_ne!(sig, [0u8; 64]); // Mock generates non-zero signatures

        // Verify credits were added
        let balance = client.verify_credit(credit_hash).await.unwrap();
        assert_eq!(balance, 100);
    }

    #[tokio::test]
    async fn test_mock_settle_full_flow() {
        let config = SettlementConfig::mock();
        let client = SettlementClient::new(config, [0u8; 32]);

        // Create credits - use user_pubkey directly as credit_hash for mock testing
        let user_pubkey = [2u8; 32];
        let credit_hash = user_pubkey; // In real usage, this would be derived
        client.set_mock_credits(credit_hash, 10).unwrap();

        let request_id = [1u8; 32];
        let relay_pubkey = [3u8; 32];
        let shard_id = [4u8; 32];

        // Create credit proof
        let credit_proof = CreditProof {
            user_pubkey,
            balance: 1000,
            epoch: 1,
            chain_signature: [0u8; 64],
        };

        // Exit settles request (directly COMPLETE, awards points to request chain)
        let settle_request = SettleRequest {
            request_id,
            user_pubkey,
            credit_proof,
            request_chains: vec![vec![ChainEntry::new(relay_pubkey, [0u8; 64], 3)]],
        };
        client.settle_request(settle_request).await.unwrap();

        // Verify state is COMPLETE (no PENDING state anymore)
        let state = client.get_request_state(request_id).await.unwrap().unwrap();
        assert_eq!(state.status, OnChainStatus::Complete);

        // Verify relay earned points from request chain
        let points = client.get_node_points(relay_pubkey).await.unwrap();
        assert_eq!(points.current_epoch_points, 100);

        // Response shard settlement (independent, awards more points)
        // Network-level TCP ACK proves delivery, no explicit TcpAck needed
        let settle_response = SettleResponseShard {
            request_id,
            shard_id,
            response_chain: vec![ChainEntry::new(relay_pubkey, [0u8; 64], 3)],
        };
        client.settle_response_shard(settle_response).await.unwrap();

        // Verify relay earned more points from response chain
        let points = client.get_node_points(relay_pubkey).await.unwrap();
        assert_eq!(points.current_epoch_points, 200); // 100 from request + 100 from response
    }

    #[tokio::test]
    async fn test_mock_insufficient_credits() {
        let config = SettlementConfig::mock();
        let client = SettlementClient::new(config, [0u8; 32]);

        // Create a credit proof with zero balance
        let user_pubkey = [2u8; 32];
        let credit_proof = CreditProof {
            user_pubkey,
            balance: 0,
            epoch: 1,
            chain_signature: [0u8; 64],
        };

        // Try to settle with zero balance credit proof
        let settle = SettleRequest {
            request_id: [1u8; 32],
            user_pubkey,
            credit_proof,
            request_chains: vec![],
        };

        let result = client.settle_request(settle).await;
        assert!(matches!(result, Err(SettlementError::InsufficientCredits)));
    }

    #[tokio::test]
    async fn test_mock_add_credits() {
        let config = SettlementConfig::mock();
        let client = SettlementClient::new(config, [0u8; 32]);

        let credit_hash = [5u8; 32];
        client.add_mock_credits(credit_hash, 50).unwrap();
        client.add_mock_credits(credit_hash, 50).unwrap();

        let balance = client.verify_credit(credit_hash).await.unwrap();
        assert_eq!(balance, 100);
    }

    // ==================== POINT CALCULATION TESTS ====================

    #[test]
    fn test_relay_points_empty_chain() {
        let chain: Vec<ChainEntry> = vec![];
        assert_eq!(SettlementClient::calculate_relay_points(&chain, &[1u8; 32]), 0);
    }

    #[test]
    fn test_relay_points_many_hops() {
        let chain: Vec<ChainEntry> = (0..15)
            .map(|i| ChainEntry::new([i as u8; 32], [0u8; 64], 15 - i as u8))
            .collect();

        assert_eq!(SettlementClient::calculate_relay_points(&chain, &[0u8; 32]), 100);
        assert_eq!(SettlementClient::calculate_relay_points(&chain, &[9u8; 32]), 10);
        assert_eq!(SettlementClient::calculate_relay_points(&chain, &[10u8; 32]), 0);
    }

    #[test]
    fn test_relay_points_duplicate_pubkeys() {
        let chain = vec![
            ChainEntry::new([1u8; 32], [0u8; 64], 3),
            ChainEntry::new([1u8; 32], [0u8; 64], 2),
            ChainEntry::new([1u8; 32], [0u8; 64], 1),
        ];
        assert_eq!(SettlementClient::calculate_relay_points(&chain, &[1u8; 32]), 100);
    }

    #[test]
    fn test_relay_points_single_relay() {
        let chain = vec![ChainEntry::new([1u8; 32], [0u8; 64], 1)];
        assert_eq!(SettlementClient::calculate_relay_points(&chain, &[1u8; 32]), 100);
    }

    // ==================== HASH TESTS ====================

    #[test]
    fn test_hash_zero_secret() {
        let secret = [0u8; 32];
        let hash = SettlementClient::hash_credit_secret(&secret);
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_hash_max_secret() {
        let secret = [0xFFu8; 32];
        let hash = SettlementClient::hash_credit_secret(&secret);
        assert_ne!(hash, [0xFFu8; 32]);
    }

    #[test]
    fn test_credit_hash_collision_resistant() {
        let secret1 = [42u8; 32];
        let mut secret2 = [42u8; 32];
        secret2[31] = 43;

        let hash1 = SettlementClient::hash_credit_secret(&secret1);
        let hash2 = SettlementClient::hash_credit_secret(&secret2);

        assert_ne!(hash1, hash2);

        let differences: usize = hash1.iter()
            .zip(hash2.iter())
            .filter(|(a, b)| a != b)
            .count();
        assert!(differences > 10, "Hash difference was only {} bytes", differences);
    }

    // ==================== CONFIG TESTS ====================

    #[test]
    fn test_config_custom_rpc() {
        let config = SettlementConfig {
            mode: SettlementMode::Live,
            rpc_url: "http://localhost:8899".to_string(),
            program_id: [1u8; 32],
            commitment: "finalized".to_string(),
            mock_initial_credits: 0,
        };

        assert_eq!(config.rpc_url, "http://localhost:8899");
        assert_eq!(config.program_id, [1u8; 32]);
        assert_eq!(config.commitment, "finalized");
        assert_eq!(config.mode, SettlementMode::Live);
    }

    #[tokio::test]
    async fn test_get_request_state_not_found() {
        let config = SettlementConfig::mock();
        let client = SettlementClient::new(config, [0u8; 32]);

        let state = client.get_request_state([99u8; 32]).await.unwrap();
        assert!(state.is_none());
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0x00, 0xFF, 0xAB]), "00ffab");
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_encode(&[0x12, 0x34, 0x56, 0x78]), "12345678");
    }
}
