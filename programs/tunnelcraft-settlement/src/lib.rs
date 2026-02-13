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
const DISTRIBUTION_VKEY_HASH: &str = "0x0066ecec5d94acf91c1ffa5674cc7535a33637ab9c6fd1b9a40cf086805226bf";

pub const LIGHT_CPI_SIGNER: CpiSigner =
    derive_light_cpi_signer!("2QQvVc5QmYkLEAFyoVd3hira43NE9qrhjRcuT1hmfMTH");

#[program]
pub mod tunnelcraft_settlement {
    use super::*;

    /// Subscribe: Any wallet purchases a subscription for an ephemeral pool identity.
    ///
    /// Creates a SubscriptionAccount PDA keyed by `pool_pubkey` (ephemeral key).
    /// The pool token account holds the USDC payment. No persistent UserMeta —
    /// each subscription is independent.
    pub fn subscribe(
        ctx: Context<SubscribeCtx>,
        pool_pubkey: [u8; 32],
        tier: u8,
        payment_amount: u64,
        duration_secs: u64,
    ) -> Result<()> {
        require!(duration_secs >= 60, SettlementError::InvalidDuration);

        let subscription = &mut ctx.accounts.subscription_account;
        let clock = Clock::get()?;

        // Init subscription
        subscription.pool_pubkey = pool_pubkey;
        subscription.tier = tier;
        subscription.created_at = clock.unix_timestamp;
        subscription.expires_at = clock.unix_timestamp + duration_secs as i64;
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

        emit!(Subscribed {
            pool_pubkey,
            tier,
            pool_balance: payment_amount,
            expires_at: subscription.expires_at,
        });

        Ok(())
    }

    /// Post Distribution: Aggregator posts a Merkle distribution root.
    ///
    /// Can only be called after the grace period (subscription expired + grace).
    /// The aggregator collects proven summaries from relays and builds
    /// this distribution off-chain.
    ///
    /// When `groth16_proof` is non-empty, the proof is verified on-chain
    /// using `sp1-solana`. The public values (76 bytes) must match the
    /// instruction arguments (root, total_receipts, pool_pubkey).
    pub fn post_distribution(
        ctx: Context<PostDistributionCtx>,
        _pool_pubkey: [u8; 32],
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
            SettlementError::PoolNotClaimable,
        );

        // Must not already have a distribution
        require!(
            !subscription.distribution_posted,
            SettlementError::DistributionAlreadyPosted,
        );

        // Proof is mandatory — reject empty proof
        require!(
            !groth16_proof.is_empty(),
            SettlementError::ProofRequired,
        );
        require!(
            sp1_public_inputs.len() == 76,
            SettlementError::InvalidProof,
        );

        // Verify the SP1 Groth16 proof on-chain
        msg!("Verifying proof: {} bytes, {} public values, vkey={}", groth16_proof.len(), sp1_public_inputs.len(), &DISTRIBUTION_VKEY_HASH[..18]);
        match sp1_solana::verify_proof(
            &groth16_proof,
            &sp1_public_inputs,
            &DISTRIBUTION_VKEY_HASH,
            sp1_solana::GROTH16_VK_5_0_0_BYTES,
        ) {
            Ok(()) => msg!("SP1 proof verified successfully"),
            Err(e) => {
                msg!("SP1 proof verification failed: {:?}", e);
                return Err(SettlementError::InvalidProof.into());
            }
        }

        // Parse 76-byte public values:
        //   root (32B) + total_bytes (8B LE) + entry_count (4B LE) + pool_pubkey (32B)
        let pi = &sp1_public_inputs;
        let mut proven_root = [0u8; 32];
        proven_root.copy_from_slice(&pi[0..32]);
        let proven_total = u64::from_le_bytes(pi[32..40].try_into().unwrap());
        // entry_count at pi[40..44] — not checked against instruction args
        let mut proven_pool = [0u8; 32];
        proven_pool.copy_from_slice(&pi[44..76]);

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
            proven_pool == subscription.pool_pubkey,
            SettlementError::InvalidProof,
        );

        subscription.distribution_root = distribution_root;
        subscription.total_receipts = total_receipts;
        subscription.original_pool_balance = subscription.pool_balance;
        subscription.distribution_posted = true;

        emit!(DistributionPosted {
            pool_pubkey: subscription.pool_pubkey,
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
    /// ["claim_receipt", pool_pubkey, relay_pubkey] — if it exists,
    /// validity proof fails and tx reverts).
    ///
    /// Payout is USDC transferred from pool token account to relay's token account.
    pub fn claim<'info>(
        ctx: Context<'_, '_, '_, 'info, ClaimCtx<'info>>,
        pool_pubkey: [u8; 32],
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
        //    Address derived from ["claim_receipt", pool_pubkey, relay_pubkey].
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

        let (address, address_seed) = derive_address(
            &[
                ClaimReceipt::SEED_PREFIX,
                pool_pubkey.as_ref(),
                relay_pubkey.as_ref(),
            ],
            &address_tree_pubkey,
            &crate::ID,
        );

        // assigned_account_index = 0: this address is assigned to the first (only) output account
        // (NOT output_tree_index, which is the tree accounts section index for the output queue)
        let new_address_params = light_tree_info
            .into_new_address_params_assigned_packed(address_seed, Some(0));

        let mut claim_receipt = LightAccount::<ClaimReceipt>::new_init(
            &crate::ID,
            Some(address),
            light_params.output_tree_index,
        );
        let clock = Clock::get()?;
        claim_receipt.pool_pubkey = pool_pubkey;
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
        let signer_seeds: &[&[u8]] = &[b"pool", pool_pubkey.as_ref(), &[bump]];

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
            pool_pubkey,
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
#[instruction(pool_pubkey: [u8; 32], tier: u8, payment_amount: u64, duration_secs: u64)]
pub struct SubscribeCtx<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + SubscriptionAccount::INIT_SPACE,
        seeds = [b"pool", pool_pubkey.as_ref()],
        bump,
    )]
    pub subscription_account: Account<'info, SubscriptionAccount>,

    /// Payer's USDC token account
    #[account(mut)]
    pub payer_token_account: Account<'info, TokenAccount>,

    /// Pool USDC token account (ATA owned by subscription PDA)
    #[account(
        init_if_needed,
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
#[instruction(pool_pubkey: [u8; 32])]
pub struct PostDistributionCtx<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,

    #[account(
        mut,
        seeds = [b"pool", pool_pubkey.as_ref()],
        bump,
    )]
    pub subscription_account: Account<'info, SubscriptionAccount>,
}

#[derive(Accounts)]
#[instruction(pool_pubkey: [u8; 32], relay_pubkey: [u8; 32])]
pub struct ClaimCtx<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,

    #[account(
        mut,
        seeds = [b"pool", pool_pubkey.as_ref()],
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

    /// Relay wallet — must match the relay_pubkey instruction arg
    /// CHECK: Validated by address constraint against relay_pubkey
    #[account(address = Pubkey::new_from_array(relay_pubkey))]
    pub relay_wallet: UncheckedAccount<'info>,

    /// Relay's USDC token account — must be the relay's ATA
    #[account(
        mut,
        associated_token::mint = usdc_mint,
        associated_token::authority = relay_wallet,
    )]
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
pub struct SubscriptionAccount {
    /// Ephemeral pool pubkey (subscription identity)
    pub pool_pubkey: [u8; 32],
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

/// Compressed ClaimReceipt — one per (pool, relay).
/// Address derived from ["claim_receipt", pool_pubkey, relay_pubkey].
/// If a relay already claimed, the address exists, non-inclusion proof fails,
/// and the transaction reverts — preventing double-claims.
#[derive(Clone, Debug, Default, LightDiscriminator, AnchorSerialize, AnchorDeserialize)]
pub struct ClaimReceipt {
    pub pool_pubkey: [u8; 32],
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
    pub pool_pubkey: [u8; 32],
    pub tier: u8,
    pub pool_balance: u64,
    pub expires_at: i64,
}

#[event]
pub struct DistributionPosted {
    pub pool_pubkey: [u8; 32],
    pub total_receipts: u64,
    pub distribution_root: [u8; 32],
}

#[event]
pub struct RewardsClaimed {
    pub pool_pubkey: [u8; 32],
    pub relay_pubkey: [u8; 32],
    pub payout: u64,
}

// ============================================================================
// Errors
// ============================================================================

#[error_code]
pub enum SettlementError {
    #[msg("Pool not claimable — wait for grace period")]
    PoolNotClaimable,
    #[msg("Distribution already posted for this pool")]
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
    #[msg("Distribution proof is required")]
    ProofRequired,
    #[msg("Invalid distribution proof")]
    InvalidProof,
    #[msg("Duration must be at least 60 seconds")]
    InvalidDuration,
}
