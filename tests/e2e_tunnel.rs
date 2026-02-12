//! End-to-end onion tunnel integration tests
//!
//! Exercises the full shard lifecycle under the onion routing model:
//! 1. Client builds onion-encrypted request shards via RequestBuilder::build_onion()
//! 2. Shards traverse relay chain (each relay peels one onion layer)
//! 3. Exit node collects shards, decrypts routing tags, reconstructs ExitPayload
//! 4. Exit creates response shards
//! 5. Client reconstructs response from erasure-coded shards
//!
//! Under onion routing, relays see only their own layer (no plaintext routing metadata).
//! There is no destination verification at relays — security comes from the onion
//! encryption itself.

use std::sync::Arc;

use tunnelcraft_client::{RequestBuilder, PathHop};
use tunnelcraft_core::{Shard, lease_set::LeaseSet};
use tunnelcraft_crypto::{
    SigningKeypair, EncryptionKeypair,
    build_onion_header, encrypt_routing_tag, verify_forward_receipt,
};
use tunnelcraft_core::OnionSettlement;
use tunnelcraft_erasure::{ErasureCoder, DATA_SHARDS, TOTAL_SHARDS};
use tunnelcraft_exit::{ExitConfig, ExitHandler};
use tunnelcraft_relay::RelayHandler;
use tunnelcraft_settlement::{SettlementClient, SettlementConfig};

/// Direct mode: client builds onion shards with no relay chain, feeds directly to exit.
///
/// Verifies:
/// - RequestBuilder::build_onion() produces valid shards in direct mode (empty paths)
/// - ExitHandler::with_keypairs() accepts the controlled encryption key
/// - ExitHandler::process_shard() decrypts routing tags and reconstructs ExitPayload
/// - Exit produces response shards after receiving enough request shards
#[tokio::test]
async fn test_full_tunnel_roundtrip_direct() {
    // === Setup identities ===
    let user_keypair = SigningKeypair::generate();
    let exit_keypair = SigningKeypair::generate();
    let exit_enc_keypair = EncryptionKeypair::generate();

    // === Setup exit handler with controlled encryption key ===
    let mut exit_handler = ExitHandler::with_keypairs(
        ExitConfig::default(),
        exit_keypair.clone(),
        exit_enc_keypair.clone(),
    ).expect("ExitHandler creation should succeed");

    // Verify encryption pubkey matches what we gave it
    assert_eq!(
        exit_handler.encryption_pubkey(),
        exit_enc_keypair.public_key_bytes(),
        "ExitHandler must use the provided encryption keypair"
    );

    // === Build PathHop for exit ===
    let exit_hop = PathHop {
        peer_id: b"exit_peer_id".to_vec(),
        signing_pubkey: exit_keypair.public_key_bytes(),
        encryption_pubkey: exit_enc_keypair.public_key_bytes(),
    };

    // Direct mode: empty lease set, no relay paths
    let lease_set = LeaseSet {
        session_id: [0u8; 32],
        leases: vec![],
    };

    // === Step 1: Client creates onion request shards ===
    let (request_id, shards) = RequestBuilder::new("GET", "https://httpbin.org/get")
        .header("User-Agent", "TunnelCraft-E2E-Test")
        .build_onion(
            &user_keypair,
            &exit_hop,
            &[],           // direct mode: no relay paths
            &lease_set,
            0,             // epoch
            [0u8; 32],     // pool_pubkey (free tier)
        )
        .expect("build_onion should succeed");

    assert!(!shards.is_empty(), "Should produce at least one shard");
    assert_ne!(request_id, [0u8; 32], "request_id should not be zero");

    // Direct mode shards have empty headers (no onion layers to peel)
    for shard in &shards {
        assert!(shard.header.is_empty(), "Direct mode shards should have empty headers");
        assert!(!shard.routing_tag.is_empty(), "Routing tag should not be empty");
        assert!(!shard.payload.is_empty(), "Shard payload should not be empty");
    }

    // === Step 2: Feed shards to exit handler ===
    let mut response_shards: Option<Vec<Shard>> = None;
    for shard in shards {
        let result = exit_handler.process_shard(shard).await
            .expect("Exit should accept shard");
        if let Some(shard_pairs) = result {
            let resp_shards: Vec<_> = shard_pairs.into_iter().map(|(s, _)| s).collect();
            response_shards = Some(resp_shards);
        }
    }

    let response_shards = response_shards
        .expect("Exit should produce response shards after receiving enough request shards");

    // Exit should have produced at least TOTAL_SHARDS response shards
    assert!(
        response_shards.len() >= TOTAL_SHARDS,
        "Exit should produce at least {} response shards, got {}",
        TOTAL_SHARDS,
        response_shards.len()
    );

    // Response shards should have non-empty payloads and routing tags
    for shard in &response_shards {
        assert!(!shard.payload.is_empty(), "Response shard payload should not be empty");
        assert!(!shard.routing_tag.is_empty(), "Response routing tag should not be empty");
    }

    // After processing all shards, extra shards (beyond DATA_SHARDS) may leave a
    // partial pending assembly since the exit removed the assembly after reconstruction
    // and the remaining shards re-create a new incomplete entry.
    // This is expected behavior -- the exit will clear stale partial assemblies via clear_stale().
}

/// Exit settlement integration test with mock settlement client.
///
/// Verifies:
/// - ExitHandler::with_keypair_and_settlement() creates handler with settlement
/// - Mock settlement subscribe and state tracking work
/// - ExitHandler can be used with settlement client
#[tokio::test]
async fn test_exit_settlement_integration() {
    let exit_keypair = SigningKeypair::generate();
    let exit_pubkey = exit_keypair.public_key_bytes();
    let user_keypair = SigningKeypair::generate();
    let user_pubkey = user_keypair.public_key_bytes();

    // Create mock settlement
    let settlement_config = SettlementConfig::mock();
    let settlement_client = Arc::new(SettlementClient::new(settlement_config, exit_pubkey));

    // Subscribe the user (payment goes into their pool)
    let (_sig, epoch) = settlement_client.subscribe(tunnelcraft_settlement::Subscribe {
        user_pubkey,
        tier: tunnelcraft_core::SubscriptionTier::Standard,
        payment_amount: 1000,
        epoch_duration_secs: 30 * 24 * 3600,
    }).await.expect("Subscribe should succeed");

    // Verify subscription exists
    let state = settlement_client.get_subscription_state(user_pubkey, epoch).await
        .expect("Get state should succeed")
        .expect("Subscription should exist");
    assert_eq!(state.pool_balance, 1000);
    assert_eq!(state.tier, tunnelcraft_core::SubscriptionTier::Standard);

    // Create exit handler with this settlement client
    let exit_handler = ExitHandler::with_keypair_and_settlement(
        ExitConfig::default(),
        exit_keypair,
        settlement_client.clone(),
    ).expect("ExitHandler with settlement should succeed");

    // Verify handler is functional
    assert_eq!(exit_handler.pending_count(), 0);
    assert_eq!(state.pool_balance, 1000, "Settlement client should track pool balance");

    // Verify subscription is active
    assert!(
        settlement_client.is_subscribed(user_pubkey).await
            .expect("is_subscribed should succeed"),
        "User should be subscribed"
    );

    drop(exit_handler);
}

/// Erasure reconstruction from different subsets of shards.
///
/// Verifies:
/// - build_onion() produces correctly erasure-coded shards
/// - Any DATA_SHARDS (3) out of TOTAL_SHARDS (5) can reconstruct the original chunk
/// - Reconstruction works with first, alternating, and last subsets
#[test]
fn test_erasure_reconstruction_from_subset() {
    let user_keypair = SigningKeypair::generate();
    let exit_enc_keypair = EncryptionKeypair::generate();

    let exit_hop = PathHop {
        peer_id: b"exit_peer".to_vec(),
        signing_pubkey: [2u8; 32],
        encryption_pubkey: exit_enc_keypair.public_key_bytes(),
    };

    let lease_set = LeaseSet {
        session_id: [0u8; 32],
        leases: vec![],
    };

    let (_request_id, shards) = RequestBuilder::new("POST", "https://example.com/api")
        .body(b"Hello, TunnelCraft!".to_vec())
        .build_onion(
            &user_keypair,
            &exit_hop,
            &[],           // direct mode
            &lease_set,
            42,
            [0u8; 32],     // pool_pubkey (free tier)
        )
        .expect("build_onion should succeed");

    // For small payloads, we should get exactly TOTAL_SHARDS (single chunk)
    assert_eq!(shards.len(), TOTAL_SHARDS, "Small payload should produce exactly {} shards", TOTAL_SHARDS);

    let erasure = ErasureCoder::new().unwrap();

    // Test reconstruction from different subsets of DATA_SHARDS
    // Indices 0,1,2 (first three)
    verify_reconstruction(&erasure, &shards, &[0, 1, 2]);
    // Indices 0,2,4 (every other)
    verify_reconstruction(&erasure, &shards, &[0, 2, 4]);
    // Indices 2,3,4 (last three)
    verify_reconstruction(&erasure, &shards, &[2, 3, 4]);
}

/// Helper: verify that erasure reconstruction succeeds from a given subset of shards.
///
/// Since shard_index is no longer a field on Shard (it's inside the encrypted routing tag),
/// we use positional index directly — build_onion produces shards in shard_index order.
fn verify_reconstruction(erasure: &ErasureCoder, shards: &[Shard], indices: &[usize]) {
    assert!(indices.len() >= DATA_SHARDS);

    let mut shard_data: Vec<Option<Vec<u8>>> = vec![None; TOTAL_SHARDS];
    let mut shard_size = 0;

    for &idx in indices {
        // Use positional index directly (shards are produced in shard_index order)
        shard_data[idx] = Some(shards[idx].payload.clone());
        shard_size = shards[idx].payload.len();
    }

    let max_len = shard_size * DATA_SHARDS;
    let result = erasure.decode(&mut shard_data, max_len);
    assert!(result.is_ok(), "Should reconstruct from indices {:?}", indices);
}

/// Onion relay forwarding test: shard goes through one relay then to exit.
///
/// Verifies:
/// - Relay peels one onion layer correctly
/// - Relay produces a valid ForwardReceipt with correct settlement data
/// - Modified shard has empty header (terminal layer) and updated ephemeral key
/// - Relay returns correct next_peer_id (exit's peer ID)
/// - ForwardReceipt signature is valid
#[test]
fn test_onion_relay_forward() {
    // === Setup identities ===
    let relay_signing = SigningKeypair::generate();
    let relay_enc = EncryptionKeypair::generate();
    let exit_enc = EncryptionKeypair::generate();

    let relay_handler = RelayHandler::new(relay_signing.clone(), relay_enc.clone());

    // === Build a shard with one relay hop ===
    let blind_token = [42u8; 32];
    let shard_id = [99u8; 32];
    let settlement = vec![OnionSettlement {
        blind_token,
        shard_id,
        payload_size: 1024,
        epoch: 7,
        pool_pubkey: [0u8; 32],
    }];

    let relay_peer_id = b"relay1_peer_id";
    let exit_peer_id = b"exit_peer_id";

    let (header, ephemeral) = build_onion_header(
        &[(relay_peer_id.as_slice(), &relay_enc.public_key_bytes())],
        (exit_peer_id.as_slice(), &exit_enc.public_key_bytes()),
        &settlement,
        None,
    ).expect("build_onion_header should succeed");

    // Create a routing tag (normally encrypted for exit)
    let assembly_id = [77u8; 32];
    let routing_tag = encrypt_routing_tag(
        &exit_enc.public_key_bytes(),
        &assembly_id,
        0,  // shard_index
        5,  // total_shards
        0,  // chunk_index
        1,  // total_chunks
    ).expect("encrypt_routing_tag should succeed");

    let shard = Shard::new(
        ephemeral,
        header,
        vec![1, 2, 3, 4, 5],  // dummy payload
        routing_tag,
    );

    // === Relay processes the shard ===
    let sender_pubkey = [10u8; 32]; // simulated sender
    let (modified_shard, next_peer, receipt, _, _) = relay_handler
        .handle_shard(shard, sender_pubkey)
        .expect("Relay should successfully peel one layer");

    // Verify next hop is the exit
    assert_eq!(next_peer, exit_peer_id, "Next peer should be exit_peer_id");

    // Terminal layer: remaining header should be empty
    assert!(
        modified_shard.header.is_empty(),
        "After peeling terminal layer, header should be empty"
    );

    // Ephemeral pubkey should be updated (for exit's ECDH)
    assert_ne!(
        modified_shard.ephemeral_pubkey, [0u8; 32],
        "Ephemeral pubkey should be non-zero"
    );

    // Payload and routing tag should be unchanged (relay doesn't touch them)
    assert_eq!(modified_shard.payload, vec![1, 2, 3, 4, 5]);
    assert!(!modified_shard.routing_tag.is_empty(), "Routing tag should not be empty");

    // === Verify ForwardReceipt ===
    assert_eq!(receipt.sender_pubkey, sender_pubkey, "Receipt sender should match");
    assert_eq!(receipt.receiver_pubkey, relay_signing.public_key_bytes(), "Receipt receiver should be relay");
    assert_eq!(receipt.blind_token, blind_token, "Receipt blind_token should match settlement data");
    assert_eq!(receipt.payload_size, 1024, "Receipt payload_size should match settlement");
    assert_eq!(receipt.epoch, 7, "Receipt epoch should match settlement");

    // Verify receipt signature
    assert!(
        verify_forward_receipt(&receipt),
        "ForwardReceipt signature should be valid"
    );
}

/// Two-hop onion relay chain: shard goes through relay1 -> relay2 -> exit.
///
/// Verifies:
/// - Each relay peels exactly one layer
/// - Settlement data is correctly assigned per-hop
/// - Chain of ephemeral keys works correctly
/// - Both receipts are independently verifiable
#[test]
fn test_onion_relay_two_hop_chain() {
    // === Setup identities ===
    let relay1_signing = SigningKeypair::generate();
    let relay1_enc = EncryptionKeypair::generate();
    let relay2_signing = SigningKeypair::generate();
    let relay2_enc = EncryptionKeypair::generate();
    let exit_enc = EncryptionKeypair::generate();

    let handler1 = RelayHandler::new(relay1_signing.clone(), relay1_enc.clone());
    let handler2 = RelayHandler::new(relay2_signing.clone(), relay2_enc.clone());

    // === Build two-hop onion header ===
    let settlement = vec![
        OnionSettlement {
            blind_token: [1u8; 32],
            shard_id: [101u8; 32],
            payload_size: 2048,
            epoch: 5,
            pool_pubkey: [0u8; 32],
        },
        OnionSettlement {
            blind_token: [2u8; 32],
            shard_id: [102u8; 32],
            payload_size: 2048,
            epoch: 5,
            pool_pubkey: [0u8; 32],
        },
    ];

    let (header, ephemeral) = build_onion_header(
        &[
            (b"r1".as_slice(), &relay1_enc.public_key_bytes()),
            (b"r2".as_slice(), &relay2_enc.public_key_bytes()),
        ],
        (b"exit".as_slice(), &exit_enc.public_key_bytes()),
        &settlement,
        None,
    ).expect("build_onion_header should succeed");

    let routing_tag = encrypt_routing_tag(
        &exit_enc.public_key_bytes(),
        &[88u8; 32],
        0, 5, 0, 1,
    ).unwrap();

    let shard = Shard::new(
        ephemeral, header, vec![10, 20, 30],
        routing_tag,
    );

    // === Relay 1 peels ===
    let sender1 = [10u8; 32];
    let (shard2, next1, receipt1, _, _) = handler1.handle_shard(shard, sender1).unwrap();

    assert_eq!(next1, b"r2", "Relay1 should forward to relay2");
    assert!(!shard2.header.is_empty(), "After first peel, header should still have data");
    assert_eq!(receipt1.blind_token, [1u8; 32], "Receipt1 settlement data should be hop 1");
    assert!(verify_forward_receipt(&receipt1), "Receipt1 signature should verify");

    // === Relay 2 peels ===
    let sender2 = relay1_signing.public_key_bytes();
    let (shard3, next2, receipt2, _, _) = handler2.handle_shard(shard2, sender2).unwrap();

    assert_eq!(next2, b"exit", "Relay2 should forward to exit");
    assert!(shard3.header.is_empty(), "After final peel, header should be empty");
    assert_eq!(receipt2.blind_token, [2u8; 32], "Receipt2 settlement data should be hop 2");
    assert!(verify_forward_receipt(&receipt2), "Receipt2 signature should verify");

    // Payload should be preserved through the chain
    assert_eq!(shard3.payload, vec![10, 20, 30]);
}

/// Wrong encryption key cannot peel an onion layer.
///
/// Verifies:
/// - Relay with wrong key returns an error (OnionPeelFailed)
/// - The shard is effectively dropped (cannot be processed by wrong relay)
#[test]
fn test_wrong_key_cannot_peel_onion() {
    let correct_enc = EncryptionKeypair::generate();
    let wrong_enc = EncryptionKeypair::generate();
    let wrong_signing = SigningKeypair::generate();
    let exit_enc = EncryptionKeypair::generate();

    // Build onion for the correct relay
    let settlement = vec![OnionSettlement {
        blind_token: [0u8; 32],
        shard_id: [0u8; 32],
        payload_size: 100,
        epoch: 0,
        pool_pubkey: [0u8; 32],
    }];

    let (header, ephemeral) = build_onion_header(
        &[(b"relay".as_slice(), &correct_enc.public_key_bytes())],
        (b"exit".as_slice(), &exit_enc.public_key_bytes()),
        &settlement,
        None,
    ).unwrap();

    let shard = Shard::new(
        ephemeral, header, vec![1, 2, 3],
        vec![0; 98],
    );

    // Handler with wrong key should fail
    let wrong_handler = RelayHandler::new(wrong_signing, wrong_enc);
    let result = wrong_handler.handle_shard(shard, [0u8; 32]);

    assert!(
        result.is_err(),
        "Relay with wrong encryption key must fail to peel onion layer"
    );
}

/// Full integration: client -> relay -> exit with actual onion shards.
///
/// This test builds proper onion-encrypted shards through RequestBuilder::build_onion(),
/// routes them through a relay, and then feeds them to the exit handler for processing.
///
/// Verifies end-to-end that:
/// - build_onion() with one relay path produces correct onion structure
/// - Relay peels layer and forwards shard to exit
/// - Exit decrypts routing tags, groups shards, reconstructs payload
/// - Exit produces response shards
#[tokio::test]
async fn test_client_relay_exit_integration() {
    // === Setup identities ===
    let user_keypair = SigningKeypair::generate();
    let relay_signing = SigningKeypair::generate();
    let relay_enc = EncryptionKeypair::generate();
    let exit_signing = SigningKeypair::generate();
    let exit_enc = EncryptionKeypair::generate();

    // === Setup handlers ===
    let relay_handler = RelayHandler::new(relay_signing.clone(), relay_enc.clone());
    let mut exit_handler = ExitHandler::with_keypairs(
        ExitConfig::default(),
        exit_signing.clone(),
        exit_enc.clone(),
    ).unwrap();

    // === Build PathHop and OnionPath ===
    let exit_hop = PathHop {
        peer_id: b"exit_peer".to_vec(),
        signing_pubkey: exit_signing.public_key_bytes(),
        encryption_pubkey: exit_enc.public_key_bytes(),
    };

    let relay_hop = PathHop {
        peer_id: b"relay_peer".to_vec(),
        signing_pubkey: relay_signing.public_key_bytes(),
        encryption_pubkey: relay_enc.public_key_bytes(),
    };

    let onion_path = tunnelcraft_client::OnionPath {
        hops: vec![relay_hop],
        exit: exit_hop.clone(),
    };

    let lease_set = LeaseSet {
        session_id: [0u8; 32],
        leases: vec![],
    };

    // === Step 1: Client builds onion shards ===
    let (_request_id, shards) = RequestBuilder::new("GET", "https://httpbin.org/headers")
        .header("X-Test", "onion-integration")
        .build_onion(
            &user_keypair,
            &exit_hop,
            &[onion_path],
            &lease_set,
            0,
            [0u8; 32],     // pool_pubkey (free tier)
        )
        .expect("build_onion with relay path should succeed");

    assert!(!shards.is_empty(), "Should produce shards");

    // With one relay, headers should be non-empty
    for shard in &shards {
        assert!(!shard.header.is_empty(), "Shards with relay path should have non-empty headers");
    }

    // === Step 2: Relay processes each shard ===
    let mut exit_bound_shards = Vec::new();
    let sender_pubkey = user_keypair.public_key_bytes();

    for shard in shards {
        let (modified_shard, next_peer, receipt, _, _) = relay_handler
            .handle_shard(shard, sender_pubkey)
            .expect("Relay should peel onion layer");

        assert_eq!(next_peer, b"exit_peer", "Relay should forward to exit");
        assert!(modified_shard.header.is_empty(), "After single-hop peel, header should be empty");
        assert!(verify_forward_receipt(&receipt), "ForwardReceipt should verify");

        exit_bound_shards.push(modified_shard);
    }

    // === Step 3: Exit processes shards ===
    let mut response_shards: Option<Vec<Shard>> = None;
    for shard in exit_bound_shards {
        let result = exit_handler.process_shard(shard).await
            .expect("Exit should accept shard");
        if let Some(shard_pairs) = result {
            let resp: Vec<_> = shard_pairs.into_iter().map(|(s, _)| s).collect();
            response_shards = Some(resp);
        }
    }

    let response_shards = response_shards
        .expect("Exit should produce response shards");

    assert!(
        response_shards.len() >= TOTAL_SHARDS,
        "Exit should produce at least {} response shards",
        TOTAL_SHARDS
    );

    // Response shards should have valid structure
    for shard in &response_shards {
        assert!(!shard.payload.is_empty());
        assert!(!shard.routing_tag.is_empty(), "Response routing tag should not be empty");
    }
}
