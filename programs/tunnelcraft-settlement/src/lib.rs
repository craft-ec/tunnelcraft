use anchor_lang::prelude::*;
use anchor_spl::{
    associated_token::AssociatedToken,
    token::{self, Mint, Token, TokenAccount, Transfer},
};
use light_sdk::{derive_light_cpi_signer, CpiSigner, LightDiscriminator};
use light_sdk::account::LightAccount;
use light_sdk::address::v2::derive_address;
use light_sdk::cpi::v2::{LightSystemProgramCpi, CpiAccounts};
use light_sdk::cpi::{InvokeLightSystemProgram, LightCpiInstruction};
use light_sdk::instruction::{PackedAddressTreeInfo, ValidityProof};
use light_compressed_account::instruction_data::compressed_proof::CompressedProof;

// Program ID will be replaced after first build with `anchor keys list`
declare_id!("2QQvVc5QmYkLEAFyoVd3hira43NE9qrhjRcuT1hmfMTH");

/// Grace period after subscription expires before distribution can be posted (30 seconds)
const GRACE_PERIOD_SECS: i64 = 30;

/// Distribution guest verification key hash (hex string).
///
/// Computed by running:
///   `cargo run -p tunnelcraft-prover --features sp1 --example vkey_hash`
///
/// Must be updated whenever the distribution guest program changes.
/// Placeholder — replace with actual hash after first build.
const DISTRIBUTION_VKEY_HASH: &str = "0x0096ecd3b7a251ada0363ec42df8b66ab839a1ce18f638be527c34a16ded3bb5";

pub const LIGHT_CPI_SIGNER: CpiSigner =
    derive_light_cpi_signer!("2QQvVc5QmYkLEAFyoVd3hira43NE9qrhjRcuT1hmfMTH");

#[program]
pub mod tunnelcraft_settlement {
    use super::*;

    /// Subscribe: User purchases a subscription tier with USDC.
    ///
    /// Creates a UserMeta PDA (if first time), reads `next_epoch`, creates a
    /// per-epoch SubscriptionAccount PDA and pool token account, transfers USDC
    /// from payer to pool, then increments `next_epoch`.
    pub fn subscribe(
        ctx: Context<SubscribeCtx>,
        user_pubkey: [u8; 32],
        tier: u8,
        payment_amount: u64,
        epoch_duration_secs: u64,
    ) -> Result<()> {
        require!(epoch_duration_secs >= 60, SettlementError::InvalidEpochDuration);

        let user_meta = &mut ctx.accounts.user_meta;
        let subscription = &mut ctx.accounts.subscription_account;
        let clock = Clock::get()?;

        // Set UserMeta on first init
        user_meta.user_pubkey = user_pubkey;
        let epoch = user_meta.next_epoch;

        // Init subscription
        subscription.user_pubkey = user_pubkey;
        subscription.epoch = epoch;
        subscription.tier = tier;
        subscription.created_at = clock.unix_timestamp;
        subscription.expires_at = clock.unix_timestamp + epoch_duration_secs as i64;
        subscription.pool_balance = payment_amount;
        subscription.original_pool_balance = payment_amount;
        subscription.total_receipts = 0;
        subscription.distribution_root = [0u8; 32];
        subscription.distribution_posted = false;

        // Transfer USDC from payer to pool token account
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.payer_token_account.to_account_info(),
                    to: ctx.accounts.pool_token_account.to_account_info(),
                    authority: ctx.accounts.payer.to_account_info(),
                },
            ),
            payment_amount,
        )?;

        // Increment epoch for next subscription
        user_meta.next_epoch = epoch + 1;

        emit!(Subscribed {
            user_pubkey,
            epoch,
            tier,
            pool_balance: payment_amount,
            expires_at: subscription.expires_at,
        });

        Ok(())
    }

    /// Post Distribution: Aggregator posts a Merkle distribution root.
    ///
    /// Can only be called after the grace period (epoch expired + 1 day).
    /// The aggregator collects ZK-proven summaries from relays and builds
    /// this distribution off-chain.
    ///
    /// When `groth16_proof` is non-empty, the proof is verified on-chain
    /// using `sp1-solana`. The public values (84 bytes) must match the
    /// instruction arguments (root, total_receipts, user_pubkey, epoch).
    pub fn post_distribution(
        ctx: Context<PostDistributionCtx>,
        _user_pubkey: [u8; 32],
        _epoch: u64,
        distribution_root: [u8; 32],
        total_receipts: u64,
        groth16_proof: Vec<u8>,
        sp1_public_inputs: Vec<u8>,
    ) -> Result<()> {
        let subscription = &mut ctx.accounts.subscription_account;
        let clock = Clock::get()?;

        // Must be past grace period
        require!(
            clock.unix_timestamp >= subscription.expires_at + GRACE_PERIOD_SECS,
            SettlementError::EpochNotComplete,
        );

        // Must not already have a distribution
        require!(
            !subscription.distribution_posted,
            SettlementError::DistributionAlreadyPosted,
        );

        // Verify Groth16 proof if provided
        if !groth16_proof.is_empty() {
            require!(
                sp1_public_inputs.len() == 84,
                SettlementError::InvalidProof,
            );

            // Verify the SP1 Groth16 proof on-chain
            sp1_solana::verify_proof(
                &groth16_proof,
                &sp1_public_inputs,
                &DISTRIBUTION_VKEY_HASH,
                sp1_solana::GROTH16_VK_5_0_0_BYTES,
            )
            .map_err(|_| SettlementError::InvalidProof)?;

            // Parse 84-byte public values:
            //   root (32B) + total_bytes (8B LE) + entry_count (4B LE) + pool_pubkey (32B) + epoch (8B LE)
            let pi = &sp1_public_inputs;
            let mut proven_root = [0u8; 32];
            proven_root.copy_from_slice(&pi[0..32]);
            let proven_total = u64::from_le_bytes(pi[32..40].try_into().unwrap());
            // entry_count at pi[40..44] — not checked against instruction args
            let mut proven_pool = [0u8; 32];
            proven_pool.copy_from_slice(&pi[44..76]);
            let proven_epoch = u64::from_le_bytes(pi[76..84].try_into().unwrap());

            // Assert proven values match instruction arguments
            require!(
                proven_root == distribution_root,
                SettlementError::InvalidProof,
            );
            require!(
                proven_total == total_receipts,
                SettlementError::InvalidProof,
            );
            require!(
                proven_pool == subscription.user_pubkey,
                SettlementError::InvalidProof,
            );
            require!(
                proven_epoch == subscription.epoch,
                SettlementError::InvalidProof,
            );
        }

        subscription.distribution_root = distribution_root;
        subscription.total_receipts = total_receipts;
        subscription.original_pool_balance = subscription.pool_balance;
        subscription.distribution_posted = true;

        emit!(DistributionPosted {
            user_pubkey: subscription.user_pubkey,
            epoch: subscription.epoch,
            total_receipts,
            distribution_root,
        });

        Ok(())
    }

    /// Claim: Relay claims proportional rewards using Merkle proof.
    ///
    /// payout = (relay_count / total_receipts) * original_pool_balance
    ///
    /// Requires distribution to be posted. Double-claim prevented by
    /// Light Protocol compressed ClaimReceipt (address derived from
    /// ["claim", user_pubkey, epoch, relay_pubkey] — if it exists,
    /// validity proof fails and tx reverts).
    ///
    /// Payout is USDC transferred from pool token account to relay's token account.
    pub fn claim<'info>(
        ctx: Context<'_, '_, '_, 'info, ClaimCtx<'info>>,
        user_pubkey: [u8; 32],
        epoch: u64,
        relay_pubkey: [u8; 32],
        relay_count: u64,
        leaf_index: u32,
        merkle_proof: Vec<[u8; 32]>,
        light_params: LightClaimParams,
    ) -> Result<()> {
        // 1. Read immutable fields first
        let distribution_posted = ctx.accounts.subscription_account.distribution_posted;
        let total_receipts = ctx.accounts.subscription_account.total_receipts;
        let original_pool_balance = ctx.accounts.subscription_account.original_pool_balance;
        let pool_balance = ctx.accounts.subscription_account.pool_balance;
        let distribution_root = ctx.accounts.subscription_account.distribution_root;

        // 2. Enforce distribution posted
        require!(distribution_posted, SettlementError::DistributionNotPosted);
        require!(total_receipts > 0, SettlementError::NoReceipts);

        // 3. Verify Merkle proof of (relay_pubkey, relay_count) against distribution_root
        require!(
            verify_merkle_proof(
                &relay_pubkey,
                relay_count,
                &merkle_proof,
                leaf_index as usize,
                &distribution_root,
            ),
            SettlementError::InvalidMerkleProof,
        );

        // 4. Create compressed ClaimReceipt (Light Protocol)
        //    Address derived from ["claim_receipt", user_pubkey, epoch, relay_pubkey].
        //    If address already exists → non-inclusion validity proof fails → tx reverts.
        let light_proof: ValidityProof = light_params.proof.into();
        let light_tree_info: PackedAddressTreeInfo = light_params.address_tree_info.into();

        let signer_info = ctx.accounts.signer.to_account_info();
        let light_cpi_accounts = CpiAccounts::new(
            &signer_info,
            ctx.remaining_accounts,
            LIGHT_CPI_SIGNER,
        );

        let address_tree_pubkey = light_tree_info
            .get_tree_pubkey(&light_cpi_accounts)
            .map_err(|_| SettlementError::LightCpiError)?;

        let epoch_le = epoch.to_le_bytes();
        let (address, address_seed) = derive_address(
            &[
                ClaimReceipt::SEED_PREFIX,
                user_pubkey.as_ref(),
                epoch_le.as_ref(),
                relay_pubkey.as_ref(),
            ],
            &address_tree_pubkey,
            &crate::ID,
        );

        let new_address_params = light_tree_info
            .into_new_address_params_assigned_packed(address_seed, Some(light_params.output_tree_index));

        let mut claim_receipt = LightAccount::<ClaimReceipt>::new_init(
            &crate::ID,
            Some(address),
            light_params.output_tree_index,
        );
        let clock = Clock::get()?;
        claim_receipt.user_pubkey = user_pubkey;
        claim_receipt.epoch = epoch;
        claim_receipt.relay_pubkey = relay_pubkey;
        claim_receipt.claimed_at = clock.unix_timestamp;

        // Creates compressed account — reverts if address already exists (double-claim)
        LightSystemProgramCpi::new_cpi(LIGHT_CPI_SIGNER, light_proof)
            .with_light_account(claim_receipt)
            .map_err(|_| SettlementError::LightCpiError)?
            .with_new_addresses(&[new_address_params])
            .invoke(light_cpi_accounts)
            .map_err(|_| SettlementError::AlreadyClaimed)?;

        // 5. Calculate proportional payout
        let payout = (relay_count as u128)
            .checked_mul(original_pool_balance as u128)
            .unwrap()
            .checked_div(total_receipts as u128)
            .unwrap() as u64;

        require!(
            payout <= pool_balance,
            SettlementError::InsufficientPoolBalance,
        );

        // 6. Transfer USDC from pool to relay (PDA-signed)
        let bump = ctx.bumps.subscription_account;
        let epoch_bytes = epoch.to_le_bytes();
        let signer_seeds: &[&[u8]] = &[b"sub", user_pubkey.as_ref(), epoch_bytes.as_ref(), &[bump]];

        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.pool_token_account.to_account_info(),
                    to: ctx.accounts.relay_token_account.to_account_info(),
                    authority: ctx.accounts.subscription_account.to_account_info(),
                },
                &[signer_seeds],
            ),
            payout,
        )?;

        // 7. Update pool balance
        ctx.accounts.subscription_account.pool_balance = pool_balance.saturating_sub(payout);

        emit!(RewardsClaimed {
            user_pubkey,
            epoch,
            relay_pubkey,
            payout,
        });

        Ok(())
    }
}

// ============================================================================
// Merkle Proof Verification
// ============================================================================

/// Verify a Merkle proof that `(relay_pubkey, relay_count)` is included in `distribution_root`.
///
/// Leaf = SHA256(relay_pubkey || relay_count.to_le_bytes())
/// At each level, combine with sibling based on leaf_index bit (0 = left, 1 = right).
///
/// Uses `solana_program::hash::hashv` which is standard SHA-256 — identical
/// to `sha2::Sha256` used off-chain in `crates/prover/src/merkle.rs`.
fn verify_merkle_proof(
    relay_pubkey: &[u8; 32],
    relay_count: u64,
    proof: &[[u8; 32]],
    leaf_index: usize,
    distribution_root: &[u8; 32],
) -> bool {
    use solana_sha256_hasher::hashv;

    // Compute leaf: SHA256(relay_pubkey || relay_count.to_le_bytes())
    let count_bytes = relay_count.to_le_bytes();
    let leaf = hashv(&[relay_pubkey.as_ref(), count_bytes.as_ref()]);
    let mut current = leaf.to_bytes();
    let mut idx = leaf_index;

    // Walk up the tree
    for sibling in proof {
        current = if idx % 2 == 0 {
            // Current is left child
            hashv(&[current.as_ref(), sibling.as_ref()]).to_bytes()
        } else {
            // Current is right child
            hashv(&[sibling.as_ref(), current.as_ref()]).to_bytes()
        };
        idx /= 2;
    }

    current == *distribution_root
}

// ============================================================================
// Accounts (Context structs)
// ============================================================================

#[derive(Accounts)]
#[instruction(user_pubkey: [u8; 32], tier: u8, payment_amount: u64, epoch_duration_secs: u64)]
pub struct SubscribeCtx<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + UserMeta::INIT_SPACE,
        seeds = [b"user", user_pubkey.as_ref()],
        bump,
    )]
    pub user_meta: Account<'info, UserMeta>,

    #[account(
        init,
        payer = payer,
        space = 8 + SubscriptionAccount::INIT_SPACE,
        seeds = [b"sub", user_pubkey.as_ref(), &user_meta.next_epoch.to_le_bytes()],
        bump,
    )]
    pub subscription_account: Account<'info, SubscriptionAccount>,

    /// Payer's USDC token account
    #[account(mut)]
    pub payer_token_account: Account<'info, TokenAccount>,

    /// Pool USDC token account (ATA owned by subscription PDA)
    #[account(
        init,
        payer = payer,
        associated_token::mint = usdc_mint,
        associated_token::authority = subscription_account,
    )]
    pub pool_token_account: Account<'info, TokenAccount>,

    /// USDC mint
    pub usdc_mint: Account<'info, Mint>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(user_pubkey: [u8; 32], epoch: u64)]
pub struct PostDistributionCtx<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,

    #[account(
        mut,
        seeds = [b"sub", user_pubkey.as_ref(), &epoch.to_le_bytes()],
        bump,
    )]
    pub subscription_account: Account<'info, SubscriptionAccount>,
}

#[derive(Accounts)]
#[instruction(user_pubkey: [u8; 32], epoch: u64, relay_pubkey: [u8; 32])]
pub struct ClaimCtx<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,

    #[account(
        mut,
        seeds = [b"sub", user_pubkey.as_ref(), &epoch.to_le_bytes()],
        bump,
    )]
    pub subscription_account: Account<'info, SubscriptionAccount>,

    /// Pool USDC token account (owned by subscription PDA)
    #[account(
        mut,
        associated_token::mint = usdc_mint,
        associated_token::authority = subscription_account,
    )]
    pub pool_token_account: Account<'info, TokenAccount>,

    /// Relay's USDC token account
    #[account(mut)]
    pub relay_token_account: Account<'info, TokenAccount>,

    /// USDC mint
    pub usdc_mint: Account<'info, Mint>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

// ============================================================================
// Account Data
// ============================================================================

#[account]
#[derive(InitSpace)]
pub struct UserMeta {
    /// User's ed25519 public key
    pub user_pubkey: [u8; 32],
    /// Next epoch to be assigned on subscribe (monotonic counter)
    pub next_epoch: u64,
}

#[account]
#[derive(InitSpace)]
pub struct SubscriptionAccount {
    /// User's ed25519 public key
    pub user_pubkey: [u8; 32],
    /// Subscription epoch (monotonic per user)
    pub epoch: u64,
    /// Subscription tier (0=Basic, 1=Standard, 2=Premium)
    pub tier: u8,
    /// When subscription was created (unix timestamp)
    pub created_at: i64,
    /// When subscription expires (unix timestamp)
    pub expires_at: i64,
    /// Current pool balance in USDC (6 decimals) — decreases as relays claim
    pub pool_balance: u64,
    /// Pool balance at time of distribution posting (used for proportional claims)
    pub original_pool_balance: u64,
    /// Total receipts across all relays (set by post_distribution)
    pub total_receipts: u64,
    /// Merkle root of (relay, count) distribution
    pub distribution_root: [u8; 32],
    /// Whether distribution has been posted
    pub distribution_posted: bool,
}

// ============================================================================
// Compressed Account (Light Protocol)
// ============================================================================

/// Compressed ClaimReceipt — one per (user, epoch, relay).
/// Address derived from ["claim_receipt", user_pubkey, epoch_le, relay_pubkey].
/// If a relay already claimed, the address exists, non-inclusion proof fails,
/// and the transaction reverts — preventing double-claims.
#[derive(Clone, Debug, Default, LightDiscriminator, AnchorSerialize, AnchorDeserialize)]
pub struct ClaimReceipt {
    pub user_pubkey: [u8; 32],
    pub epoch: u64,
    pub relay_pubkey: [u8; 32],
    pub claimed_at: i64,
}

impl ClaimReceipt {
    pub const SEED_PREFIX: &'static [u8] = b"claim_receipt";
}

// ============================================================================
// IDL-safe Light Protocol Wrapper Types
// ============================================================================

/// Validity proof wrapper (Anchor IDL-safe).
/// Light SDK types don't implement AnchorSerialize/Deserialize.
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct LightValidityProof {
    pub a: [u8; 32],
    pub b: [u8; 64],
    pub c: [u8; 32],
}

impl From<LightValidityProof> for ValidityProof {
    fn from(proof: LightValidityProof) -> Self {
        ValidityProof(Some(CompressedProof {
            a: proof.a,
            b: proof.b,
            c: proof.c,
        }))
    }
}

/// Address tree info wrapper (Anchor IDL-safe).
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct LightAddressTreeInfo {
    pub address_merkle_tree_pubkey_index: u8,
    pub address_queue_pubkey_index: u8,
    pub root_index: u16,
}

impl From<LightAddressTreeInfo> for PackedAddressTreeInfo {
    fn from(info: LightAddressTreeInfo) -> Self {
        PackedAddressTreeInfo {
            address_merkle_tree_pubkey_index: info.address_merkle_tree_pubkey_index,
            address_queue_pubkey_index: info.address_queue_pubkey_index,
            root_index: info.root_index,
        }
    }
}

/// Combined Light Protocol params for the `claim` instruction.
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct LightClaimParams {
    pub proof: LightValidityProof,
    pub address_tree_info: LightAddressTreeInfo,
    pub output_tree_index: u8,
}

// ============================================================================
// Events
// ============================================================================

#[event]
pub struct Subscribed {
    pub user_pubkey: [u8; 32],
    pub epoch: u64,
    pub tier: u8,
    pub pool_balance: u64,
    pub expires_at: i64,
}

#[event]
pub struct DistributionPosted {
    pub user_pubkey: [u8; 32],
    pub epoch: u64,
    pub total_receipts: u64,
    pub distribution_root: [u8; 32],
}

#[event]
pub struct RewardsClaimed {
    pub user_pubkey: [u8; 32],
    pub epoch: u64,
    pub relay_pubkey: [u8; 32],
    pub payout: u64,
}

// ============================================================================
// Errors
// ============================================================================

#[error_code]
pub enum SettlementError {
    #[msg("Epoch not complete — wait for grace period")]
    EpochNotComplete,
    #[msg("Distribution already posted for this epoch")]
    DistributionAlreadyPosted,
    #[msg("Distribution not yet posted")]
    DistributionNotPosted,
    #[msg("No receipts in pool")]
    NoReceipts,
    #[msg("Insufficient pool balance for payout")]
    InsufficientPoolBalance,
    #[msg("Invalid Merkle proof")]
    InvalidMerkleProof,
    #[msg("Already claimed from this pool")]
    AlreadyClaimed,
    #[msg("Light Protocol CPI error")]
    LightCpiError,
    #[msg("Invalid distribution proof")]
    InvalidProof,
    #[msg("Epoch duration must be at least 60 seconds")]
    InvalidEpochDuration,
}
