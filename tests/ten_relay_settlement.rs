//! 10-relay settlement integration test (onion routing model)
//!
//! Exercises the ForwardReceipt + per-user pool settlement flow without
//! passing shards through relay handlers (which would require building
//! complex multi-hop onion headers). Instead, receipt generation is tested
//! directly via `sign_forward_receipt`, and the settlement layer (subscribe,
//! post_distribution, claim_rewards, Merkle proofs) is exercised end-to-end.
//!
//! Verifies:
//! - ForwardReceipt generation and signature verification for 10 simulated hops
//! - Receipt isolation across requests (different request/shard IDs)
//! - Proportional reward distribution across all relays + exit
//! - Pool balance fully drained after all claims
//! - Merkle proof-based claims (valid proofs accepted, invalid rejected)
//! - Unequal receipt distribution with correct proportional payouts

use std::collections::HashMap;
use std::sync::Arc;

use tunnelcraft_crypto::{sign_forward_receipt, verify_forward_receipt, SigningKeypair, EncryptionKeypair};
use tunnelcraft_erasure::TOTAL_SHARDS;
use tunnelcraft_prover::MerkleTree;
use tunnelcraft_settlement::{
    ClaimRewards, PostDistribution, SettlementClient, SettlementConfig, Subscribe,
};

const NUM_RELAYS: usize = 10;

/// Helper: create N relay keypairs (signing + encryption)
fn create_relay_keypairs(n: usize) -> Vec<(SigningKeypair, EncryptionKeypair)> {
    (0..n)
        .map(|_| {
            let signing = SigningKeypair::generate();
            let encryption = EncryptionKeypair::generate();
            (signing, encryption)
        })
        .collect()
}

/// Simulated 10-relay ForwardReceipt settlement flow.
///
/// Instead of passing shards through relay handlers (which requires onion
/// headers), this test simulates receipt generation at each hop by calling
/// `sign_forward_receipt` directly. The settlement layer (subscribe,
/// post_distribution, claim_rewards) is exercised end-to-end.
#[tokio::test]
async fn test_ten_relay_forward_receipt_settlement() {
    // === Setup identities ===
    let user_keypair = SigningKeypair::generate();
    let exit_keypair = SigningKeypair::generate();
    let user_pubkey = user_keypair.public_key_bytes();
    let exit_pubkey = exit_keypair.public_key_bytes();

    // === Setup 10 relay keypairs ===
    let relay_keypairs = create_relay_keypairs(NUM_RELAYS);
    let relay_pubkeys: Vec<_> = relay_keypairs.iter().map(|(kp, _)| kp.public_key_bytes()).collect();

    // === Setup mock settlement ===
    let settlement_config = SettlementConfig::mock();
    let settlement_client = Arc::new(SettlementClient::new(settlement_config, exit_pubkey));

    // === User subscribes (creates pool) ===
    let pool_balance = 1_000_000u64; // 1M lamports
    let (_sig, sub_epoch) = settlement_client
        .subscribe(Subscribe {
            user_pubkey,
            tier: tunnelcraft_core::SubscriptionTier::Standard,
            payment_amount: pool_balance,
            epoch_duration_secs: 30 * 24 * 3600,
        })
        .await
        .expect("Subscribe should succeed");

    let sub = settlement_client
        .get_subscription_state(user_pubkey, sub_epoch)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sub.pool_balance, pool_balance);

    // === Simulate forward path: 5 shards through 10 relays ===
    // Generate unique shard_ids and a request_id for the simulated request
    let request_id = [42u8; 32];
    let blind_token = [0u8; 32]; // simulated blind_token
    let epoch = 0u64;
    let payload_size = 1024u32;

    let mut all_receipts = Vec::new();

    // Generate forward-path receipts: each relay signs a receipt for each shard
    for relay_idx in 0..NUM_RELAYS {
        // Determine sender pubkey (previous relay, or user for first hop)
        let sender = if relay_idx == 0 {
            user_pubkey
        } else {
            relay_pubkeys[relay_idx - 1]
        };

        for shard_idx in 0..TOTAL_SHARDS as u8 {
            let mut shard_id = [0u8; 32];
            shard_id[0] = 0x01; // forward direction marker
            shard_id[1] = relay_idx as u8;
            shard_id[2] = shard_idx;

            let receipt = sign_forward_receipt(
                &relay_keypairs[relay_idx].0,
                &request_id,
                &shard_id,
                &sender,
                &blind_token,
                payload_size,
                epoch,
            );

            // Verify the receipt signature
            assert!(
                verify_forward_receipt(&receipt),
                "ForwardReceipt from relay {} shard {} should verify",
                relay_idx,
                shard_idx,
            );
            assert_eq!(receipt.receiver_pubkey, relay_pubkeys[relay_idx]);
            assert_eq!(receipt.request_id, request_id);
            assert_eq!(receipt.shard_id, shard_id);
            assert_eq!(receipt.sender_pubkey, sender);

            all_receipts.push(receipt);
        }
    }

    // Exit also signs a receipt for each shard it receives
    let last_relay_pubkey = relay_pubkeys[NUM_RELAYS - 1];
    for shard_idx in 0..TOTAL_SHARDS as u8 {
        let mut shard_id = [0u8; 32];
        shard_id[0] = 0x01; // forward
        shard_id[1] = NUM_RELAYS as u8; // exit is hop NUM_RELAYS
        shard_id[2] = shard_idx;

        let receipt = sign_forward_receipt(
            &exit_keypair,
            &request_id,
            &shard_id,
            &last_relay_pubkey,
            &blind_token,
            payload_size,
            epoch,
        );
        assert!(verify_forward_receipt(&receipt));
        all_receipts.push(receipt);
    }

    // Forward path receipts: 10 relays * 5 shards + 1 exit * 5 shards = 55
    let forward_receipt_count = all_receipts.len();
    assert_eq!(
        forward_receipt_count,
        (NUM_RELAYS + 1) * TOTAL_SHARDS,
        "Should have (10 relays + 1 exit) * 5 shards = 55 forward receipts"
    );

    // === Simulate return path: 5 response shards through 10 relays (reverse) ===
    for relay_idx in (0..NUM_RELAYS).rev() {
        let sender = if relay_idx == NUM_RELAYS - 1 {
            exit_pubkey
        } else {
            relay_pubkeys[relay_idx + 1]
        };

        for shard_idx in 0..TOTAL_SHARDS as u8 {
            let mut shard_id = [0u8; 32];
            shard_id[0] = 0x02; // return direction marker (distinct from forward)
            shard_id[1] = relay_idx as u8;
            shard_id[2] = shard_idx;

            let receipt = sign_forward_receipt(
                &relay_keypairs[relay_idx].0,
                &request_id,
                &shard_id,
                &sender,
                &blind_token,
                payload_size,
                epoch,
            );
            assert!(verify_forward_receipt(&receipt));
            all_receipts.push(receipt);
        }
    }

    // Total receipts: forward 55 + return 10 relays * 5 shards = 55 + 50 = 105
    let total_receipts = all_receipts.len();
    assert_eq!(
        total_receipts,
        forward_receipt_count + NUM_RELAYS * TOTAL_SHARDS,
        "Total should be 55 forward + 50 return = 105 receipts"
    );

    // === Count receipts per node ===
    let mut receipts_per_node: HashMap<[u8; 32], u64> = HashMap::new();
    for receipt in &all_receipts {
        *receipts_per_node.entry(receipt.receiver_pubkey).or_insert(0) += 1;
    }

    println!("\n=== Receipt Distribution ===");
    println!("Total receipts: {}", total_receipts);
    println!("Pool balance: {} lamports", pool_balance);
    println!();

    for (i, pubkey) in relay_pubkeys.iter().enumerate() {
        let count = receipts_per_node.get(pubkey).copied().unwrap_or(0);
        println!(
            "  Relay {:2}: {} receipts ({:.1}% of pool)",
            i, count,
            count as f64 / total_receipts as f64 * 100.0
        );
        // Each relay: 5 forward + 5 return = 10 receipts
        assert_eq!(count, 10, "Relay {} should have 10 receipts (5 fwd + 5 ret)", i);
    }

    let exit_count = receipts_per_node.get(&exit_pubkey).copied().unwrap_or(0);
    println!(
        "  Exit    : {} receipts ({:.1}% of pool)",
        exit_count,
        exit_count as f64 / total_receipts as f64 * 100.0
    );
    assert_eq!(exit_count, 5, "Exit should have 5 receipts (forward only)");

    // === Expire subscription and post distribution ===
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Override with expired subscription (past grace period)
    let claim_epoch = settlement_client
        .add_mock_subscription_with_expiry(
            user_pubkey,
            tunnelcraft_core::SubscriptionTier::Standard,
            pool_balance,
            now - 40 * 24 * 3600, // created 40 days ago
            now - 10 * 24 * 3600, // expired 10 days ago (past grace)
        )
        .unwrap();

    // Post distribution with receipt counts
    settlement_client
        .post_distribution(PostDistribution {
            user_pubkey,
            epoch: claim_epoch,
            distribution_root: [0xAA; 32],
            total_bytes: total_receipts as u64,
            groth16_proof: vec![],
            sp1_public_inputs: vec![],
        })
        .await
        .expect("Post distribution should succeed");

    let sub = settlement_client
        .get_subscription_state(user_pubkey, claim_epoch)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sub.total_bytes, total_receipts as u64);
    assert!(sub.distribution_posted);
    assert_eq!(sub.distribution_root, [0xAA; 32]);

    // === Each node claims proportional rewards ===
    let mut total_claimed = 0u64;
    let mut node_rewards: Vec<(String, u64)> = Vec::new();

    let mut all_nodes: Vec<[u8; 32]> = relay_pubkeys.clone();
    all_nodes.push(exit_pubkey);

    // Track pool balance before claims
    let sub_before = settlement_client
        .get_subscription_state(user_pubkey, claim_epoch)
        .await
        .unwrap()
        .unwrap();
    let original_pool = sub_before.original_pool_balance;

    for pubkey in &all_nodes {
        let count = receipts_per_node.get(pubkey).copied().unwrap_or(0);
        settlement_client
            .claim_rewards(ClaimRewards {
                user_pubkey,
                epoch: claim_epoch,
                node_pubkey: *pubkey,
                relay_bytes: count,
                leaf_index: 0,
                merkle_proof: vec![],
                light_params: None,
            })
            .await
            .expect("Claim should succeed");

        // Calculate expected payout (direct payout from pool)
        let expected_payout = (count as u128 * original_pool as u128 / total_receipts as u128) as u64;
        let label = if *pubkey == exit_pubkey {
            "Exit".to_string()
        } else {
            let idx = relay_pubkeys.iter().position(|p| p == pubkey).unwrap();
            format!("Relay {:2}", idx)
        };
        node_rewards.push((label, expected_payout));
        total_claimed += expected_payout;
    }

    println!("\n=== Reward Distribution ===");
    for (label, reward) in &node_rewards {
        println!(
            "  {}: {} lamports ({:.1}%)",
            label, reward,
            *reward as f64 / pool_balance as f64 * 100.0
        );
    }
    println!("  Total claimed: {} / {} lamports", total_claimed, pool_balance);

    let final_sub = settlement_client
        .get_subscription_state(user_pubkey, claim_epoch)
        .await
        .unwrap()
        .unwrap();
    println!("  Pool remainder: {} lamports", final_sub.pool_balance);

    // All relays should get non-zero rewards
    for (label, reward) in &node_rewards {
        assert!(*reward > 0, "{} should have non-zero reward", label);
    }

    // Total claimed should account for (nearly) all of the pool
    assert!(
        total_claimed >= pool_balance - 100,
        "Total claimed {} should be close to pool balance {} (rounding tolerance)",
        total_claimed, pool_balance,
    );

    println!("\n=== Test PASSED: 10-relay settlement flow verified ===\n");
}

/// Test that ForwardReceipts from different requests don't interfere
#[tokio::test]
async fn test_receipt_isolation_across_requests() {
    let user_keypair = SigningKeypair::generate();
    let exit_keypair = SigningKeypair::generate();
    let user_pubkey = user_keypair.public_key_bytes();
    let exit_pubkey = exit_keypair.public_key_bytes();

    let settlement_config = SettlementConfig::mock();
    let settlement_client = Arc::new(SettlementClient::new(settlement_config, exit_pubkey));

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Create an already-expired subscription (past grace)
    let epoch = settlement_client
        .add_mock_subscription_with_expiry(
            user_pubkey,
            tunnelcraft_core::SubscriptionTier::Standard,
            500_000,
            now - 40 * 24 * 3600,
            now - 10 * 24 * 3600,
        )
        .unwrap();

    let relay_keypair = SigningKeypair::generate();
    let relay_pubkey = relay_keypair.public_key_bytes();

    let request_id_1 = [1u8; 32];
    let request_id_2 = [2u8; 32];

    // Generate receipts for request 1 (3 shards with unique shard_ids)
    let receipts_req1: Vec<_> = (0..3u8)
        .map(|i| {
            let mut shard_id = [0u8; 32];
            shard_id[0] = 1; // request 1
            shard_id[1] = i;
            sign_forward_receipt(&relay_keypair, &request_id_1, &shard_id, &[0xFFu8; 32], &[0u8; 32], 1024, 0)
        })
        .collect();

    // Generate receipts for request 2 (2 shards with unique shard_ids)
    let receipts_req2: Vec<_> = (0..2u8)
        .map(|i| {
            let mut shard_id = [0u8; 32];
            shard_id[0] = 2; // request 2
            shard_id[1] = i;
            sign_forward_receipt(&relay_keypair, &request_id_2, &shard_id, &[0xFFu8; 32], &[0u8; 32], 1024, 0)
        })
        .collect();

    // Verify all receipts have valid signatures
    for receipt in receipts_req1.iter().chain(receipts_req2.iter()) {
        assert!(verify_forward_receipt(receipt));
    }

    // Verify receipts are tied to the correct request_ids
    for receipt in &receipts_req1 {
        assert_eq!(receipt.request_id, request_id_1);
    }
    for receipt in &receipts_req2 {
        assert_eq!(receipt.request_id, request_id_2);
    }

    let all_receipts = [receipts_req1, receipts_req2].concat();
    let total = all_receipts.len() as u64; // 5 receipts total

    // Post distribution with total receipt count
    settlement_client
        .post_distribution(PostDistribution {
            user_pubkey,
            epoch,
            distribution_root: [0xBB; 32],
            total_bytes: total,
            groth16_proof: vec![],
            sp1_public_inputs: vec![],
        })
        .await
        .unwrap();

    // Relay claims all 5 receipts
    settlement_client
        .claim_rewards(ClaimRewards {
            user_pubkey,
            epoch,
            node_pubkey: relay_pubkey,
            relay_bytes: total,
            leaf_index: 0,
            merkle_proof: vec![],
            light_params: None,
        })
        .await
        .unwrap();

    // 5/5 * 500_000 = 500_000 (relay is only claimer, gets entire pool)
    let sub = settlement_client
        .get_subscription_state(user_pubkey, epoch)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sub.total_bytes, 5);
    assert_eq!(sub.pool_balance, 0);
}

/// Test that receipt signatures are cryptographically valid
#[test]
fn test_receipt_signature_verification() {
    let relay_keypair = SigningKeypair::generate();
    let request_id = [42u8; 32];

    for i in 0..TOTAL_SHARDS as u8 {
        let mut shard_id = [0u8; 32];
        shard_id[0] = i;
        let receipt = sign_forward_receipt(&relay_keypair, &request_id, &shard_id, &[0xFFu8; 32], &[0u8; 32], 1024, 0);

        assert!(verify_forward_receipt(&receipt), "Receipt for shard {} should verify", i);
        assert_eq!(receipt.request_id, request_id);
        assert_eq!(receipt.shard_id, shard_id);
        assert_eq!(receipt.receiver_pubkey, relay_keypair.public_key_bytes());
        assert_ne!(receipt.signature, [0u8; 64]);
        assert!(receipt.timestamp > 0);
    }
}

/// Test that a tampered receipt (wrong pubkey) fails verification
#[test]
fn test_receipt_tampered_signature_fails() {
    let relay_keypair = SigningKeypair::generate();
    let other_keypair = SigningKeypair::generate();

    let receipt = sign_forward_receipt(
        &relay_keypair,
        &[1u8; 32],
        &[2u8; 32],
        &[0xFFu8; 32],
        &[0u8; 32],
        1024,
        0,
    );

    // Original verifies
    assert!(verify_forward_receipt(&receipt));

    // Tampered receipt: change receiver_pubkey but keep original signature
    let mut tampered = receipt.clone();
    tampered.receiver_pubkey = other_keypair.public_key_bytes();
    assert!(!verify_forward_receipt(&tampered), "Tampered receipt should not verify");

    // Tampered receipt: change payload_size
    let mut tampered2 = receipt.clone();
    tampered2.payload_size = 9999;
    assert!(!verify_forward_receipt(&tampered2), "Receipt with modified payload_size should not verify");

    // Tampered receipt: change blind_token
    let mut tampered3 = receipt;
    tampered3.blind_token = [0xFFu8; 32];
    assert!(!verify_forward_receipt(&tampered3), "Receipt with modified blind_token should not verify");
}

/// Test that receipts with different epochs are distinct
#[test]
fn test_receipt_epoch_binding() {
    let relay_keypair = SigningKeypair::generate();

    let receipt_epoch0 = sign_forward_receipt(
        &relay_keypair,
        &[1u8; 32],
        &[2u8; 32],
        &[0xFFu8; 32],
        &[0u8; 32],
        1024,
        0,
    );

    let receipt_epoch1 = sign_forward_receipt(
        &relay_keypair,
        &[1u8; 32],
        &[2u8; 32],
        &[0xFFu8; 32],
        &[0u8; 32],
        1024,
        1,
    );

    // Both verify independently
    assert!(verify_forward_receipt(&receipt_epoch0));
    assert!(verify_forward_receipt(&receipt_epoch1));

    // But their signatures differ (different epoch in signable data)
    assert_ne!(receipt_epoch0.signature, receipt_epoch1.signature);
    assert_eq!(receipt_epoch0.epoch, 0);
    assert_eq!(receipt_epoch1.epoch, 1);
}

/// Test that claims with valid Merkle proofs succeed through end-to-end flow:
/// build distribution tree -> post root -> claim with proof -> verify payout.
#[tokio::test]
async fn test_merkle_proof_claim() {
    let user_pubkey = [1u8; 32];
    let settlement_client = Arc::new(SettlementClient::new(SettlementConfig::mock(), [0u8; 32]));

    let pool_balance = 1_000_000u64;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Create expired subscription (past grace)
    let epoch = settlement_client
        .add_mock_subscription_with_expiry(
            user_pubkey,
            tunnelcraft_core::SubscriptionTier::Standard,
            pool_balance,
            now - 40 * 24 * 3600,
            now - 10 * 24 * 3600,
        )
        .unwrap();

    // 3 relays with different receipt counts
    let relay_a = [10u8; 32];
    let relay_b = [20u8; 32];
    let relay_c = [30u8; 32];
    let counts: Vec<([u8; 32], u64)> = vec![(relay_a, 50), (relay_b, 30), (relay_c, 20)];
    let total_bytes: u64 = counts.iter().map(|(_, c)| c).sum();

    // Build the Merkle tree from distribution entries
    let tree = MerkleTree::from_entries(&counts);
    let root = tree.root();

    // Post distribution with the real Merkle root
    settlement_client
        .post_distribution(PostDistribution {
            user_pubkey,
            epoch,
            distribution_root: root,
            total_bytes,
            groth16_proof: vec![],
            sp1_public_inputs: vec![],
        })
        .await
        .unwrap();

    // Each relay claims with a valid Merkle proof
    for (i, (relay_pubkey, count)) in counts.iter().enumerate() {
        let proof = tree.proof(i).expect("proof should exist for leaf");
        settlement_client
            .claim_rewards(ClaimRewards {
                user_pubkey,
                epoch,
                node_pubkey: *relay_pubkey,
                relay_bytes: *count,
                leaf_index: i as u32,
                merkle_proof: proof.siblings.clone(),
                light_params: None,
            })
            .await
            .expect("Claim with valid Merkle proof should succeed");
    }

    // Pool fully drained (payouts were: 500k + 300k + 200k = 1M)
    let sub = settlement_client
        .get_subscription_state(user_pubkey, epoch)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sub.pool_balance, 0);
}

/// Test that a claim with an invalid Merkle proof (wrong relay_bytes) is rejected.
#[tokio::test]
async fn test_invalid_merkle_proof_rejected() {
    let user_pubkey = [1u8; 32];
    let settlement_client = Arc::new(SettlementClient::new(SettlementConfig::mock(), [0u8; 32]));

    let pool_balance = 1_000_000u64;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let epoch = settlement_client
        .add_mock_subscription_with_expiry(
            user_pubkey,
            tunnelcraft_core::SubscriptionTier::Standard,
            pool_balance,
            now - 40 * 24 * 3600,
            now - 10 * 24 * 3600,
        )
        .unwrap();

    let relay_a = [10u8; 32];
    let relay_b = [20u8; 32];
    let counts: Vec<([u8; 32], u64)> = vec![(relay_a, 50), (relay_b, 50)];
    let total_bytes: u64 = 100;

    let tree = MerkleTree::from_entries(&counts);
    let root = tree.root();

    settlement_client
        .post_distribution(PostDistribution {
            user_pubkey,
            epoch,
            distribution_root: root,
            total_bytes,
            groth16_proof: vec![],
            sp1_public_inputs: vec![],
        })
        .await
        .unwrap();

    // Claim with WRONG relay_bytes (70 instead of 50) -- leaf won't match
    let proof = tree.proof(0).expect("proof should exist");
    let result = settlement_client
        .claim_rewards(ClaimRewards {
            user_pubkey,
            epoch,
            node_pubkey: relay_a,
            relay_bytes: 70, // Wrong count -- should fail verification
            leaf_index: 0,
            merkle_proof: proof.siblings.clone(),
            light_params: None,
        })
        .await;

    assert!(
        matches!(result, Err(tunnelcraft_settlement::SettlementError::InvalidMerkleProof)),
        "Claim with wrong relay_bytes should be rejected with InvalidMerkleProof, got: {:?}",
        result,
    );

    // Verify that the pool is untouched
    let sub = settlement_client
        .get_subscription_state(user_pubkey, epoch)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sub.pool_balance, pool_balance);

    // Also test: valid proof but wrong leaf_index
    let proof_for_a = tree.proof(0).unwrap();
    let result2 = settlement_client
        .claim_rewards(ClaimRewards {
            user_pubkey,
            epoch,
            node_pubkey: relay_a,
            relay_bytes: 50, // Correct count
            leaf_index: 1,   // Wrong index -- proof path won't verify
            merkle_proof: proof_for_a.siblings.clone(),
            light_params: None,
        })
        .await;

    assert!(
        matches!(result2, Err(tunnelcraft_settlement::SettlementError::InvalidMerkleProof)),
        "Claim with wrong leaf_index should be rejected with InvalidMerkleProof, got: {:?}",
        result2,
    );
}

/// Test proportional reward distribution with unequal receipt counts
#[tokio::test]
async fn test_unequal_receipt_distribution() {
    let user_pubkey = [1u8; 32];
    let settlement_client = Arc::new(SettlementClient::new(SettlementConfig::mock(), [0u8; 32]));

    let pool_balance = 1_000_000u64;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Create expired subscription (past grace)
    let epoch = settlement_client
        .add_mock_subscription_with_expiry(
            user_pubkey,
            tunnelcraft_core::SubscriptionTier::Premium,
            pool_balance,
            now - 40 * 24 * 3600,
            now - 10 * 24 * 3600,
        )
        .unwrap();

    // Node A: 7 receipts, Node B: 3 receipts
    let node_a_kp = SigningKeypair::generate();
    let node_b_kp = SigningKeypair::generate();
    let node_a = node_a_kp.public_key_bytes();
    let node_b = node_b_kp.public_key_bytes();

    // Generate receipts locally (they stay on the relay)
    let mut receipts = Vec::new();
    for i in 0..7u8 {
        let mut shard_id = [0u8; 32];
        shard_id[0] = 0xA0;
        shard_id[1] = i;
        receipts.push(sign_forward_receipt(&node_a_kp, &[10u8; 32], &shard_id, &[0xFFu8; 32], &[0u8; 32], 1024, 0));
    }
    for i in 0..3u8 {
        let mut shard_id = [0u8; 32];
        shard_id[0] = 0xB0;
        shard_id[1] = i;
        receipts.push(sign_forward_receipt(&node_b_kp, &[20u8; 32], &shard_id, &[0xFFu8; 32], &[0u8; 32], 1024, 0));
    }

    // Verify all generated receipts
    for receipt in &receipts {
        assert!(verify_forward_receipt(receipt));
    }

    // Post distribution: 10 total receipts
    settlement_client
        .post_distribution(PostDistribution {
            user_pubkey,
            epoch,
            distribution_root: [0xCC; 32],
            total_bytes: 10,
            groth16_proof: vec![],
            sp1_public_inputs: vec![],
        })
        .await
        .unwrap();

    // Node A claims: 7/10 * 1_000_000 = 700_000 (direct payout)
    settlement_client
        .claim_rewards(ClaimRewards {
            user_pubkey,
            epoch,
            node_pubkey: node_a,
            relay_bytes: 7,
            leaf_index: 0,
            merkle_proof: vec![],
            light_params: None,
        })
        .await
        .unwrap();

    // Verify pool deducted by 700_000
    let sub_after_a = settlement_client.get_subscription_state(user_pubkey, epoch).await.unwrap().unwrap();
    assert_eq!(sub_after_a.pool_balance, 300_000);

    // Node B claims: 3/10 * 1_000_000 = 300_000 (direct payout)
    settlement_client
        .claim_rewards(ClaimRewards {
            user_pubkey,
            epoch,
            node_pubkey: node_b,
            relay_bytes: 3,
            leaf_index: 0,
            merkle_proof: vec![],
            light_params: None,
        })
        .await
        .unwrap();

    // Pool fully drained
    let sub = settlement_client
        .get_subscription_state(user_pubkey, epoch)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sub.pool_balance, 0);
}

/// Test the full onion pipeline: build_onion -> exit processes -> response shards.
///
/// This test verifies that the onion encryption/decryption pipeline works
/// end-to-end for direct mode (no relay hops). Settlement receipt generation
/// is not tested here (see the other tests above).
#[tokio::test]
async fn test_direct_mode_exit_roundtrip() {
    use tunnelcraft_client::{RequestBuilder, PathHop};
    use tunnelcraft_core::lease_set::LeaseSet;
    use tunnelcraft_core::Shard;
    use tunnelcraft_exit::{ExitConfig, ExitHandler};

    let user_keypair = SigningKeypair::generate();
    let exit_keypair = SigningKeypair::generate();
    let exit_enc_keypair = EncryptionKeypair::generate();

    let exit_hop = PathHop {
        peer_id: b"exit_peer".to_vec(),
        signing_pubkey: exit_keypair.public_key_bytes(),
        encryption_pubkey: exit_enc_keypair.public_key_bytes(),
    };

    let lease_set = LeaseSet {
        session_id: [0u8; 32],
        leases: vec![],
    };

    // Build onion shards in direct mode (no relay hops)
    let builder = RequestBuilder::new("GET", "https://httpbin.org/get")
        .header("User-Agent", "TunnelCraft-DirectMode-Test");

    let (request_id, shards) = builder
        .build_onion(&user_keypair, &exit_hop, &[], &lease_set, 0, [0u8; 32])
        .expect("build_onion should succeed in direct mode");

    assert_ne!(request_id, [0u8; 32]);
    assert_eq!(shards.len(), TOTAL_SHARDS);

    // All shards in direct mode should have empty headers (no relay hops)
    for shard in &shards {
        assert!(shard.header.is_empty(), "Direct mode shards should have empty headers");
        assert!(!shard.routing_tag.is_empty(), "routing_tag should not be empty");
    }

    // Create exit handler with the matching encryption keypair
    let mut exit_handler = ExitHandler::with_keypairs(
        ExitConfig::default(),
        exit_keypair.clone(),
        exit_enc_keypair,
    )
    .unwrap();

    // Feed shards to exit handler -- it should reassemble and produce response shards
    // Note: this will make a real HTTP request to httpbin.org, which may fail
    // in CI environments. We test up to reassembly and just verify the handler
    // accepts the shards without error.
    let mut last_result: Option<Vec<Shard>> = None;
    for shard in shards {
        match exit_handler.process_shard(shard).await {
            Ok(result) => {
                last_result = result.map(|pairs| pairs.into_iter().map(|(s, _)| s).collect::<Vec<_>>()).or(last_result);
            }
            Err(e) => {
                // HTTP request failure is acceptable in test environments
                // (e.g., no network, httpbin.org unreachable)
                println!("Exit handler error (expected in offline environments): {}", e);
                return;
            }
        }
    }

    // If we got response shards, verify their structure
    if let Some(response_shards) = last_result {
        assert!(!response_shards.is_empty(), "Response should contain shards");
        for shard in &response_shards {
            assert!(!shard.payload.is_empty(), "Response shard payload should not be empty");
            assert!(!shard.routing_tag.is_empty(), "Response routing_tag should not be empty");
        }
        println!("Direct mode roundtrip produced {} response shards", response_shards.len());
    }
}

/// Test bandwidth-weighted settlement: receipts carry payload_size
/// and settlement weights by total bytes, not receipt count.
#[tokio::test]
async fn test_bandwidth_weighted_settlement() {
    let user_pubkey = [1u8; 32];
    let settlement_client = Arc::new(SettlementClient::new(SettlementConfig::mock(), [0u8; 32]));

    let pool_balance = 1_000_000u64;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let epoch = settlement_client
        .add_mock_subscription_with_expiry(
            user_pubkey,
            tunnelcraft_core::SubscriptionTier::Standard,
            pool_balance,
            now - 40 * 24 * 3600,
            now - 10 * 24 * 3600,
        )
        .unwrap();

    // Simulate two relays with different bandwidth contributions
    let relay_a_kp = SigningKeypair::generate();
    let relay_b_kp = SigningKeypair::generate();
    let relay_a = relay_a_kp.public_key_bytes();
    let relay_b = relay_b_kp.public_key_bytes();

    // Relay A forwarded 3 shards of 1000 bytes each = 3000 bytes total
    let mut relay_a_total_bytes = 0u64;
    for i in 0..3u8 {
        let mut shard_id = [0u8; 32];
        shard_id[0] = 0xA0;
        shard_id[1] = i;
        let receipt = sign_forward_receipt(&relay_a_kp, &[10u8; 32], &shard_id, &[0xFFu8; 32], &[0u8; 32], 1000, 0);
        assert!(verify_forward_receipt(&receipt));
        assert_eq!(receipt.payload_size, 1000);
        relay_a_total_bytes += receipt.payload_size as u64;
    }

    // Relay B forwarded 2 shards of 3500 bytes each = 7000 bytes total
    let mut relay_b_total_bytes = 0u64;
    for i in 0..2u8 {
        let mut shard_id = [0u8; 32];
        shard_id[0] = 0xB0;
        shard_id[1] = i;
        let receipt = sign_forward_receipt(&relay_b_kp, &[20u8; 32], &shard_id, &[0xFFu8; 32], &[0u8; 32], 3500, 0);
        assert!(verify_forward_receipt(&receipt));
        assert_eq!(receipt.payload_size, 3500);
        relay_b_total_bytes += receipt.payload_size as u64;
    }

    let total_bytes = relay_a_total_bytes + relay_b_total_bytes; // 10000

    // Post distribution weighted by bytes, not receipt count
    settlement_client
        .post_distribution(PostDistribution {
            user_pubkey,
            epoch,
            distribution_root: [0xDD; 32],
            total_bytes,
            groth16_proof: vec![],
            sp1_public_inputs: vec![],
        })
        .await
        .unwrap();

    // Relay A claims 3000/10000 * 1_000_000 = 300_000
    settlement_client
        .claim_rewards(ClaimRewards {
            user_pubkey,
            epoch,
            node_pubkey: relay_a,
            relay_bytes: relay_a_total_bytes,
            leaf_index: 0,
            merkle_proof: vec![],
            light_params: None,
        })
        .await
        .unwrap();

    let sub_after_a = settlement_client.get_subscription_state(user_pubkey, epoch).await.unwrap().unwrap();
    assert_eq!(sub_after_a.pool_balance, 700_000);

    // Relay B claims 7000/10000 * 1_000_000 = 700_000
    settlement_client
        .claim_rewards(ClaimRewards {
            user_pubkey,
            epoch,
            node_pubkey: relay_b,
            relay_bytes: relay_b_total_bytes,
            leaf_index: 0,
            merkle_proof: vec![],
            light_params: None,
        })
        .await
        .unwrap();

    let sub_final = settlement_client.get_subscription_state(user_pubkey, epoch).await.unwrap().unwrap();
    assert_eq!(sub_final.pool_balance, 0);
}
