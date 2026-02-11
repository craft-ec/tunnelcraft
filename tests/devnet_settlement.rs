//! Devnet settlement integration tests with real Solana + Light Protocol.
//!
//! All tests are `#[ignore]` — run with:
//!   cargo test --test devnet_settlement -- --ignored --nocapture
//!
//! Environment variables:
//! - `DEVNET_KEYPAIR`    — path to funded Solana keypair JSON, or base58 secret key
//! - `HELIUS_API_KEY`    — Photon RPC access for Light Protocol validity proofs
//! - `DEVNET_TEST_EPOCH` — epoch number of a pre-existing expired subscription (for claim test)

use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};
use tunnelcraft_prover::MerkleTree;
use tunnelcraft_settlement::{
    light::{derive_claim_receipt_address, PhotonClient, ADDRESS_TREE_V2},
    ClaimRewards, EpochPhase, PostDistribution, SettlementClient,
    SettlementConfig, Subscribe,
};

// ============================================================================
// Helpers
// ============================================================================

/// Skip test gracefully if an environment variable is missing.
macro_rules! skip_if_no_env {
    ($var:expr) => {
        match std::env::var($var) {
            Ok(val) if !val.is_empty() => val,
            _ => {
                eprintln!("SKIP: {} not set, skipping test", $var);
                return Ok(());
            }
        }
    };
}

/// Load a Solana keypair from either a JSON file path or a base58 secret key.
fn load_keypair(raw: &str) -> anyhow::Result<Keypair> {
    let trimmed = raw.trim();

    // Try as file path first
    if let Ok(data) = std::fs::read_to_string(trimmed) {
        let bytes: Vec<u8> = serde_json::from_str(&data)?;
        return Ok(Keypair::try_from(bytes.as_slice())?);
    }

    // Try as base58-encoded secret key
    let bytes = bs58::decode(trimmed).into_vec()?;
    Ok(Keypair::try_from(bytes.as_slice())?)
}

/// Create a devnet RPC client.
fn devnet_rpc() -> RpcClient {
    RpcClient::new_with_commitment(
        "https://api.devnet.solana.com".to_string(),
        CommitmentConfig::confirmed(),
    )
}

// ============================================================================
// Test 1: Program existence (no env vars needed)
// ============================================================================

/// Verifies the TunnelCraft settlement program is deployed on devnet and executable.
/// Also checks that the devnet USDC mint account exists.
#[tokio::test]
#[ignore]
async fn test_devnet_program_exists() -> anyhow::Result<()> {
    let rpc = devnet_rpc();

    // Verify the settlement program account
    let program_id = Pubkey::new_from_array(SettlementConfig::DEVNET_PROGRAM_ID);
    println!("Checking program: {}", program_id);

    let account = rpc.get_account(&program_id).await?;
    assert!(account.executable, "Program account should be executable");
    println!(
        "  Program exists: executable={}, owner={}, data_len={}",
        account.executable,
        account.owner,
        account.data.len()
    );

    // Verify USDC mint exists on devnet
    let usdc_mint = Pubkey::new_from_array(tunnelcraft_settlement::USDC_MINT_DEVNET);
    println!("Checking USDC mint: {}", usdc_mint);

    let mint_account = rpc.get_account(&usdc_mint).await?;
    assert!(
        !mint_account.data.is_empty(),
        "USDC mint account should have data"
    );
    println!(
        "  USDC mint exists: owner={}, data_len={}",
        mint_account.owner,
        mint_account.data.len()
    );

    println!("PASS: Program and USDC mint verified on devnet");
    Ok(())
}

// ============================================================================
// Test 2: Photon validity proof (needs HELIUS_API_KEY)
// ============================================================================

/// Validates the Light Protocol client pipeline by fetching a non-inclusion
/// validity proof from Photon for a random ClaimReceipt address.
#[tokio::test]
#[ignore]
async fn test_devnet_photon_validity_proof() -> anyhow::Result<()> {
    let api_key = skip_if_no_env!("HELIUS_API_KEY");

    let photon = PhotonClient::from_config("https://api.devnet.solana.com", Some(&api_key));

    // Derive a ClaimReceipt address for a random (user, epoch, relay) triple.
    // This address almost certainly doesn't exist on-chain, so we should get
    // a valid non-inclusion proof.
    let user = [42u8; 32];
    let relay = [99u8; 32];
    let epoch = 999_999u64;
    let address_tree = ADDRESS_TREE_V2;
    let program_id = SettlementConfig::DEVNET_PROGRAM_ID;

    let address =
        derive_claim_receipt_address(&user, epoch, &relay, &address_tree, &program_id);

    println!(
        "Derived ClaimReceipt address: {}",
        bs58::encode(&address).into_string()
    );
    println!("Fetching non-inclusion validity proof from Photon...");

    let proof = photon
        .get_validity_proof(&address, &address_tree)
        .await?;

    // Verify proof fields are non-zero (a valid proof should have substance)
    assert_ne!(proof.a, [0u8; 32], "proof.a should be non-zero");
    assert_ne!(proof.b, [0u8; 64], "proof.b should be non-zero");
    assert_ne!(proof.c, [0u8; 32], "proof.c should be non-zero");

    println!("  proof.a: {}", hex::encode(&proof.a));
    println!("  proof.b: {}", hex::encode(&proof.b));
    println!("  proof.c: {}", hex::encode(&proof.c));
    println!("  root_index: {}", proof.root_index);

    println!("PASS: Photon validity proof fetched successfully");
    Ok(())
}

// ============================================================================
// Test 3: Subscribe (needs DEVNET_KEYPAIR with SOL + USDC)
// ============================================================================

/// Creates a real on-chain subscription on devnet.
/// Requires a funded wallet with SOL (for tx fees) and devnet USDC (for payment).
#[tokio::test]
#[ignore]
async fn test_devnet_subscribe() -> anyhow::Result<()> {
    let keypair_raw = skip_if_no_env!("DEVNET_KEYPAIR");
    let keypair = load_keypair(&keypair_raw)?;
    let user_pubkey: [u8; 32] = keypair.pubkey().to_bytes();

    println!("Wallet: {}", keypair.pubkey());

    let config = SettlementConfig::devnet_default();
    let client = SettlementClient::with_keypair(config, keypair);

    // Check SOL balance
    let balance = client.get_balance().await?;
    println!("SOL balance: {} lamports ({:.4} SOL)", balance, balance as f64 / 1e9);
    assert!(balance > 10_000, "Wallet needs SOL for transaction fees");

    // Subscribe with 1 USDC (6 decimals)
    let payment = 1_000_000u64; // 1 USDC
    println!("Subscribing with {} USDC...", payment as f64 / 1e6);

    let (tx_sig, epoch) = client
        .subscribe(Subscribe {
            user_pubkey,
            tier: tunnelcraft_core::SubscriptionTier::Standard,
            payment_amount: payment,
        })
        .await?;

    println!("  tx: {}", bs58::encode(&tx_sig).into_string());
    println!("  epoch: {}", epoch);

    // Read back subscription state
    let state = client
        .get_subscription_state(user_pubkey, epoch)
        .await?
        .expect("subscription should exist after subscribe()");

    assert_eq!(state.epoch, epoch);
    assert_eq!(state.tier, tunnelcraft_core::SubscriptionTier::Standard);
    assert!(state.pool_balance > 0, "Pool should have balance");
    assert!(state.expires_at > state.created_at, "expires_at > created_at");

    println!("  tier: {:?}", state.tier);
    println!("  pool_balance: {} USDC", state.pool_balance as f64 / 1e6);
    println!("  created_at: {}", state.created_at);
    println!("  expires_at: {}", state.expires_at);

    println!();
    println!("==> Use DEVNET_TEST_EPOCH={} for test_devnet_claim_with_light", epoch);
    println!("    (after epoch expires + 1 day grace period)");

    println!("PASS: Subscription created on devnet");
    Ok(())
}

// ============================================================================
// Test 4: Claim with Light Protocol (needs DEVNET_KEYPAIR, HELIUS_API_KEY,
//         DEVNET_TEST_EPOCH for an expired subscription)
// ============================================================================

/// End-to-end claim test against a pre-existing expired subscription.
///
/// Steps:
/// 1. Load subscription state, verify it's in Claimable phase
/// 2. Post distribution (if not already posted) with a single-relay Merkle tree
/// 3. Claim rewards with real Merkle proof + Light Protocol compressed account
/// 4. Verify pool balance decreased
/// 5. Attempt double-claim — expect failure
#[tokio::test]
#[ignore]
async fn test_devnet_claim_with_light() -> anyhow::Result<()> {
    let keypair_raw = skip_if_no_env!("DEVNET_KEYPAIR");
    let api_key = skip_if_no_env!("HELIUS_API_KEY");
    let epoch_str = skip_if_no_env!("DEVNET_TEST_EPOCH");

    let keypair = load_keypair(&keypair_raw)?;
    let user_pubkey: [u8; 32] = keypair.pubkey().to_bytes();
    let epoch: u64 = epoch_str.parse()?;

    println!("Wallet: {}", keypair.pubkey());
    println!("Epoch:  {}", epoch);

    let mut config = SettlementConfig::devnet_default();
    config.helius_api_key = Some(api_key);
    let client = SettlementClient::with_keypair(config, keypair);

    // 1. Load subscription state
    println!("Loading subscription state...");
    let state = client
        .get_subscription_state(user_pubkey, epoch)
        .await?
        .ok_or_else(|| anyhow::anyhow!(
            "No subscription found for epoch {}. Run test_devnet_subscribe first.",
            epoch,
        ))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let phase = state.phase(now);
    println!("  phase: {:?}", phase);
    println!("  pool_balance: {} USDC", state.pool_balance as f64 / 1e6);
    println!("  distribution_posted: {}", state.distribution_posted);

    assert_eq!(
        phase,
        EpochPhase::Claimable,
        "Subscription must be in Claimable phase (expired + grace period). \
         Current phase: {:?}. expires_at={}, now={}, diff={}s",
        phase, state.expires_at, now,
        now as i64 - state.expires_at as i64
    );

    // Use the signer as the relay (claiming to ourselves for the test)
    let relay_pubkey = user_pubkey;
    let relay_bytes = 1_000_000u64; // 1 MB

    // Build single-relay Merkle tree
    let tree = MerkleTree::from_entries(&[(relay_pubkey, relay_bytes)]);
    let root = tree.root();
    let proof = tree.proof(0).expect("proof for leaf 0 should exist");

    // 2. Post distribution if not yet posted
    if !state.distribution_posted {
        println!("Posting distribution...");
        let tx_sig = client
            .post_distribution(PostDistribution {
                user_pubkey,
                epoch,
                distribution_root: root,
                total_bytes: relay_bytes,
            })
            .await?;
        println!("  post_distribution tx: {}", bs58::encode(&tx_sig).into_string());

        // Re-read state to confirm
        let updated = client
            .get_subscription_state(user_pubkey, epoch)
            .await?
            .expect("subscription should still exist");
        assert!(updated.distribution_posted, "distribution should be posted now");
        println!("  distribution_posted: true");
        println!("  original_pool_balance: {} USDC", updated.original_pool_balance as f64 / 1e6);
    } else {
        println!("Distribution already posted, skipping...");
        // Verify root matches if already posted (it might differ if posted by someone else)
        if state.distribution_root != root {
            eprintln!(
                "WARNING: existing distribution root differs from our single-relay tree. \
                 Claim may fail with InvalidMerkleProof."
            );
        }
    }

    // 3. Claim rewards
    let balance_before = client
        .get_subscription_state(user_pubkey, epoch)
        .await?
        .map(|s| s.pool_balance)
        .unwrap_or(0);

    println!("Claiming rewards ({} bytes)...", relay_bytes);
    let merkle_siblings: Vec<[u8; 32]> = proof.siblings.clone();

    let claim_tx = client
        .claim_rewards(ClaimRewards {
            user_pubkey,
            epoch,
            node_pubkey: relay_pubkey,
            relay_bytes,
            leaf_index: proof.leaf_index as u32,
            merkle_proof: merkle_siblings.clone(),
            light_params: None, // auto-fetch from Photon
        })
        .await?;

    println!("  claim tx: {}", bs58::encode(&claim_tx).into_string());

    // 4. Verify pool balance decreased
    let balance_after = client
        .get_subscription_state(user_pubkey, epoch)
        .await?
        .map(|s| s.pool_balance)
        .unwrap_or(0);

    println!("  pool_balance: {} -> {} USDC",
        balance_before as f64 / 1e6,
        balance_after as f64 / 1e6
    );
    assert!(
        balance_after < balance_before,
        "Pool balance should decrease after claim: before={}, after={}",
        balance_before, balance_after
    );

    // 5. Double-claim should fail (Light Protocol non-inclusion proof should fail)
    println!("Attempting double-claim (should fail)...");
    let double_claim_result = client
        .claim_rewards(ClaimRewards {
            user_pubkey,
            epoch,
            node_pubkey: relay_pubkey,
            relay_bytes,
            leaf_index: proof.leaf_index as u32,
            merkle_proof: merkle_siblings,
            light_params: None,
        })
        .await;

    assert!(
        double_claim_result.is_err(),
        "Double-claim should fail, but got: {:?}",
        double_claim_result
    );
    println!("  Double-claim correctly rejected: {}", double_claim_result.unwrap_err());

    println!("PASS: Claim with Light Protocol succeeded, double-claim prevented");
    Ok(())
}
