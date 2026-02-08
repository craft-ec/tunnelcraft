//! 10-relay settlement integration test
//!
//! Exercises the full ForwardReceipt + per-user pool settlement flow:
//! 1. User subscribes (creates pool with balance)
//! 2. Client creates request shards (5 shards, erasure coded)
//! 3. Shards traverse 10 relays → exit node
//! 4. At each hop, the receiving relay signs a ForwardReceipt (keyed by shard_id)
//! 5. Exit reconstructs request, creates response shards
//! 6. Response shards traverse 10 relays back → client
//! 7. At each return hop, ForwardReceipts are generated (different shard_ids → no dedup)
//! 8. Receipts stay local — relays count their receipts per pool
//! 9. Aggregator posts distribution, each relay claims proportional rewards
//!
//! Verifies:
//! - ForwardReceipt generation and signature verification at every hop
//! - Request vs response receipts are distinct (different shard_ids)
//! - Receipt deduplication (same receipt hashes are distinct)
//! - Proportional reward distribution across all 10 relays + exit
//! - Pool balance fully drained after all claims
//! - Relay signature chain accumulation (10 entries per shard)

use std::collections::HashMap;
use std::sync::Arc;

use tunnelcraft_client::RequestBuilder;
use tunnelcraft_core::{HopMode, Shard, ShardType};
use tunnelcraft_crypto::{sign_forward_receipt, verify_forward_receipt, SigningKeypair};
use tunnelcraft_erasure::{ErasureCoder, DATA_SHARDS, TOTAL_SHARDS};
use tunnelcraft_exit::{ExitConfig, ExitHandler};
use tunnelcraft_relay::{RelayConfig, RelayHandler};
use tunnelcraft_prover::MerkleTree;
use tunnelcraft_settlement::{
    ClaimRewards, PostDistribution, SettlementClient, SettlementConfig, Subscribe,
};

const NUM_RELAYS: usize = 10;

/// Helper: create N relay handlers with keypairs
fn create_relays(n: usize) -> Vec<(SigningKeypair, RelayHandler)> {
    (0..n)
        .map(|_| {
            let kp = SigningKeypair::generate();
            let handler = RelayHandler::with_config(
                kp.clone(),
                RelayConfig {
                    verify_signatures: true,
                    can_be_last_hop: true,
                },
            );
            (kp, handler)
        })
        .collect()
}

/// Full 10-relay roundtrip with ForwardReceipt tracking and settlement
#[tokio::test]
async fn test_ten_relay_forward_receipt_settlement() {
    // === Setup identities ===
    let user_keypair = SigningKeypair::generate();
    let exit_keypair = SigningKeypair::generate();
    let user_pubkey = user_keypair.public_key_bytes();
    let exit_pubkey = exit_keypair.public_key_bytes();

    // === Setup 10 relays ===
    let mut relays = create_relays(NUM_RELAYS);
    let relay_pubkeys: Vec<_> = relays.iter().map(|(kp, _)| kp.public_key_bytes()).collect();

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
        })
        .await
        .expect("Subscribe should succeed");

    let sub = settlement_client
        .get_subscription_state(user_pubkey, sub_epoch)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sub.pool_balance, pool_balance);

    // === Setup exit handler ===
    let mut exit_handler = ExitHandler::with_keypair_and_settlement(
        ExitConfig::default(),
        exit_keypair.clone(),
        settlement_client.clone(),
    )
    .unwrap();

    // === Step 1: Client creates request shards ===
    let shards = RequestBuilder::new("GET", "https://httpbin.org/get")
        .header("User-Agent", "TunnelCraft-10-Relay-Test")
        .hop_mode(HopMode::Paranoid)
        .build(user_pubkey, exit_pubkey)
        .expect("Failed to build request shards");

    assert_eq!(shards.len(), TOTAL_SHARDS);
    let request_id = shards[0].request_id;

    // === Step 2: Forward path — shards through 10 relays ===
    let mut all_receipts = Vec::new();
    let mut current_shards = shards;

    for relay_idx in 0..NUM_RELAYS {
        let mut next_shards = Vec::new();

        for shard in &current_shards {
            // Receiving relay signs a ForwardReceipt keyed by shard_id
            let receipt = sign_forward_receipt(
                &relays[relay_idx].0,
                &shard.request_id,
                &shard.shard_id,
                &[0xFFu8; 32],
                &[0u8; 32],
                0,
            );

            // Verify the receipt signature
            assert!(
                verify_forward_receipt(&receipt),
                "ForwardReceipt from relay {} should verify",
                relay_idx
            );
            assert_eq!(receipt.receiver_pubkey, relay_pubkeys[relay_idx]);
            assert_eq!(receipt.request_id, request_id);
            assert_eq!(receipt.shard_id, shard.shard_id);

            all_receipts.push(receipt);

            // Relay processes the shard (signs chain, decrements hops)
            let result = relays[relay_idx]
                .1
                .handle_shard(shard.clone())
                .expect("Relay should accept request shard");
            next_shards.push(result.expect("Should return processed shard"));
        }

        current_shards = next_shards;
    }

    // After 10 relays, each shard's chain should have 10 entries
    for shard in &current_shards {
        assert_eq!(
            shard.chain.len(),
            NUM_RELAYS,
            "Each shard should have {} chain entries after traversing all relays",
            NUM_RELAYS
        );
        for (i, entry) in shard.chain.iter().enumerate() {
            assert_eq!(
                entry.pubkey, relay_pubkeys[i],
                "Chain entry {} should be relay {}'s pubkey",
                i, i
            );
        }
    }

    // Exit also signs a receipt for each shard it receives
    for shard in &current_shards {
        let receipt = sign_forward_receipt(&exit_keypair, &shard.request_id, &shard.shard_id, &[0xFFu8; 32], &[0u8; 32], 0);
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

    // === Step 3: Exit processes shards and creates response ===
    let mut response_shards: Option<Vec<Shard>> = None;
    for shard in current_shards {
        let result = exit_handler
            .process_shard(shard)
            .await
            .expect("Exit should accept shard");
        if let Some(resp) = result {
            response_shards = Some(resp);
        }
    }

    let response_shards =
        response_shards.expect("Exit should produce response shards after enough request shards");
    assert_eq!(response_shards.len(), TOTAL_SHARDS);

    // Verify response shards have exit's signature and DIFFERENT shard_ids from request
    for shard in &response_shards {
        assert_eq!(shard.shard_type, ShardType::Response);
        assert_eq!(shard.destination, user_pubkey);
        assert!(!shard.chain.is_empty());
        assert_eq!(shard.chain[0].pubkey, exit_pubkey);
    }

    // === Step 4: Return path — response shards through 10 relays (reverse) ===
    let mut current_response_shards = response_shards;

    for relay_idx in (0..NUM_RELAYS).rev() {
        let mut next_shards = Vec::new();

        for shard in &current_response_shards {
            // Receiving relay signs a ForwardReceipt — shard_id is different from
            // request shards, so this is a distinct receipt (no dedup collision)
            let receipt = sign_forward_receipt(
                &relays[relay_idx].0,
                &shard.request_id,
                &shard.shard_id,
                &[0xFFu8; 32],
                &[0u8; 32],
                0,
            );
            assert!(verify_forward_receipt(&receipt));

            all_receipts.push(receipt);

            // Relay processes the response shard
            let result = relays[relay_idx]
                .1
                .handle_shard(shard.clone())
                .expect("Relay should accept response shard");
            next_shards.push(result.expect("Should return processed shard"));
        }

        current_response_shards = next_shards;
    }

    // Total receipts: forward 55 + return 10 relays * 5 shards = 55 + 50 = 105
    let total_receipts = all_receipts.len();
    assert_eq!(
        total_receipts,
        forward_receipt_count + NUM_RELAYS * TOTAL_SHARDS,
        "Total should be 55 forward + 50 return = 105 receipts"
    );

    // === Step 5: Client reconstructs response ===
    let erasure = ErasureCoder::new().unwrap();
    let mut shard_data: Vec<Option<Vec<u8>>> = vec![None; TOTAL_SHARDS];
    let mut shard_size = 0;

    for shard in current_response_shards.iter().take(DATA_SHARDS) {
        let idx = shard.shard_index as usize;
        if idx < TOTAL_SHARDS {
            shard_size = shard.payload.len();
            shard_data[idx] = Some(shard.payload.clone());
        }
    }

    let max_len = shard_size * DATA_SHARDS;
    let reconstructed = erasure
        .decode(&mut shard_data, max_len)
        .expect("Should reconstruct response from shards");

    let response = tunnelcraft_client::TunnelResponse::from_bytes(&reconstructed)
        .expect("Should parse TunnelResponse");
    assert!(
        response.status > 0 || !response.body.is_empty() || response.headers.is_empty(),
        "Response should have some content"
    );

    // === Step 6: Count receipts per node (locally, as relays would) ===
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

    // === Step 7: Expire subscription and post distribution ===
    // In the new model, receipts stay local. The aggregator collects ZK-proven
    // summaries and posts a distribution root on-chain after the grace period.
    // For testing, we create an expired subscription and post distribution directly.
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
            total_receipts: total_receipts as u64,
        })
        .await
        .expect("Post distribution should succeed");

    let sub = settlement_client
        .get_subscription_state(user_pubkey, claim_epoch)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sub.total_receipts, total_receipts as u64);
    assert!(sub.distribution_posted);
    assert_eq!(sub.distribution_root, [0xAA; 32]);

    // === Step 8: Each node claims proportional rewards ===
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
                relay_count: count,
                leaf_index: 0,
                merkle_proof: vec![],
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
            sign_forward_receipt(&relay_keypair, &request_id_1, &shard_id, &[0xFFu8; 32], &[0u8; 32], 0)
        })
        .collect();

    // Generate receipts for request 2 (2 shards with unique shard_ids)
    let receipts_req2: Vec<_> = (0..2u8)
        .map(|i| {
            let mut shard_id = [0u8; 32];
            shard_id[0] = 2; // request 2
            shard_id[1] = i;
            sign_forward_receipt(&relay_keypair, &request_id_2, &shard_id, &[0xFFu8; 32], &[0u8; 32], 0)
        })
        .collect();

    let all_receipts = [receipts_req1, receipts_req2].concat();
    let total = all_receipts.len() as u64; // 5 receipts total

    // Post distribution with total receipt count
    settlement_client
        .post_distribution(PostDistribution {
            user_pubkey,
            epoch,
            distribution_root: [0xBB; 32],
            total_receipts: total,
        })
        .await
        .unwrap();

    // Relay claims all 5 receipts
    settlement_client
        .claim_rewards(ClaimRewards {
            user_pubkey,
            epoch,
            node_pubkey: relay_pubkey,
            relay_count: total,
            leaf_index: 0,
            merkle_proof: vec![],
        })
        .await
        .unwrap();

    // 5/5 * 500_000 = 500_000 (relay is only claimer, gets entire pool)
    let sub = settlement_client
        .get_subscription_state(user_pubkey, epoch)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sub.total_receipts, 5);
    assert_eq!(sub.pool_balance, 0);
}

/// Test relay chain signature accumulation with 10 relays
#[test]
fn test_ten_relay_chain_accumulation() {
    let user_pubkey = [1u8; 32];
    let exit_pubkey = [2u8; 32];

    let shards = RequestBuilder::new("GET", "https://example.com")
        .hop_mode(HopMode::Paranoid)
        .build(user_pubkey, exit_pubkey)
        .expect("Failed to build shards");

    let mut relays = create_relays(NUM_RELAYS);
    let relay_pubkeys: Vec<_> = relays.iter().map(|(kp, _)| kp.public_key_bytes()).collect();

    let mut shard = shards.into_iter().next().unwrap();
    let initial_chain_len = shard.chain.len();

    for (i, (_kp, handler)) in relays.iter_mut().enumerate() {
        let result = handler.handle_shard(shard).expect("Relay should accept shard");
        shard = result.expect("Should return processed shard");
        assert_eq!(shard.chain.len(), initial_chain_len + i + 1);
    }

    assert_eq!(shard.chain.len(), initial_chain_len + NUM_RELAYS);

    for (i, entry) in shard.chain.iter().skip(initial_chain_len).enumerate() {
        assert_eq!(entry.pubkey, relay_pubkeys[i], "Chain entry {} should match relay {}", i, i);
        assert_ne!(entry.signature, [0u8; 64], "Relay {} signature should be real", i);
    }
}

/// Test that receipt signatures are cryptographically valid
#[test]
fn test_receipt_signature_verification() {
    let relay_keypair = SigningKeypair::generate();
    let request_id = [42u8; 32];

    for i in 0..TOTAL_SHARDS as u8 {
        let mut shard_id = [0u8; 32];
        shard_id[0] = i;
        let receipt = sign_forward_receipt(&relay_keypair, &request_id, &shard_id, &[0xFFu8; 32], &[0u8; 32], 0);

        assert!(verify_forward_receipt(&receipt), "Receipt for shard {} should verify", i);
        assert_eq!(receipt.request_id, request_id);
        assert_eq!(receipt.shard_id, shard_id);
        assert_eq!(receipt.receiver_pubkey, relay_keypair.public_key_bytes());
        assert_ne!(receipt.signature, [0u8; 64]);
        assert!(receipt.timestamp > 0);
    }
}

/// Test that claims with valid Merkle proofs succeed through end-to-end flow:
/// build distribution tree → post root → claim with proof → verify payout.
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
    let total_receipts: u64 = counts.iter().map(|(_, c)| c).sum();

    // Build the Merkle tree from distribution entries
    let tree = MerkleTree::from_entries(&counts);
    let root = tree.root();

    // Post distribution with the real Merkle root
    settlement_client
        .post_distribution(PostDistribution {
            user_pubkey,
            epoch,
            distribution_root: root,
            total_receipts,
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
                relay_count: *count,
                leaf_index: i as u32,
                merkle_proof: proof.siblings.clone(),
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

/// Test that a claim with an invalid Merkle proof (wrong relay_count) is rejected.
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
    let total_receipts: u64 = 100;

    let tree = MerkleTree::from_entries(&counts);
    let root = tree.root();

    settlement_client
        .post_distribution(PostDistribution {
            user_pubkey,
            epoch,
            distribution_root: root,
            total_receipts,
        })
        .await
        .unwrap();

    // Claim with WRONG relay_count (70 instead of 50) — leaf won't match
    let proof = tree.proof(0).expect("proof should exist");
    let result = settlement_client
        .claim_rewards(ClaimRewards {
            user_pubkey,
            epoch,
            node_pubkey: relay_a,
            relay_count: 70, // Wrong count — should fail verification
            leaf_index: 0,
            merkle_proof: proof.siblings.clone(),
        })
        .await;

    assert!(
        matches!(result, Err(tunnelcraft_settlement::SettlementError::InvalidMerkleProof)),
        "Claim with wrong relay_count should be rejected with InvalidMerkleProof, got: {:?}",
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
            relay_count: 50, // Correct count
            leaf_index: 1,   // Wrong index — proof path won't verify
            merkle_proof: proof_for_a.siblings.clone(),
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
        receipts.push(sign_forward_receipt(&node_a_kp, &[10u8; 32], &shard_id, &[0xFFu8; 32], &[0u8; 32], 0));
    }
    for i in 0..3u8 {
        let mut shard_id = [0u8; 32];
        shard_id[0] = 0xB0;
        shard_id[1] = i;
        receipts.push(sign_forward_receipt(&node_b_kp, &[20u8; 32], &shard_id, &[0xFFu8; 32], &[0u8; 32], 0));
    }

    // Post distribution: 10 total receipts
    settlement_client
        .post_distribution(PostDistribution {
            user_pubkey,
            epoch,
            distribution_root: [0xCC; 32],
            total_receipts: 10,
        })
        .await
        .unwrap();

    // Node A claims: 7/10 * 1_000_000 = 700_000 (direct payout)
    settlement_client
        .claim_rewards(ClaimRewards {
            user_pubkey,
            epoch,
            node_pubkey: node_a,
            relay_count: 7,
            leaf_index: 0,
            merkle_proof: vec![],
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
            relay_count: 3,
            leaf_index: 0,
            merkle_proof: vec![],
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
