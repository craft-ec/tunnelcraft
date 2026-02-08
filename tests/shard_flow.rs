//! Integration tests for the complete shard flow
//!
//! Tests the full request/response lifecycle:
//! 1. Client creates request, erasure codes into shards
//! 2. Shards pass through relay handlers (sender_pubkey stamping)
//! 3. Exit node receives shards, reconstructs request
//! 4. Exit creates response shards
//! 5. Response shards pass back through relays (destination verification)
//! 6. Client reconstructs response

use tunnelcraft_client::RequestBuilder;
use tunnelcraft_core::{HopMode, Shard, ShardType};
use tunnelcraft_crypto::SigningKeypair;
use tunnelcraft_erasure::{ErasureCoder, DATA_SHARDS, TOTAL_SHARDS};
use tunnelcraft_exit::HttpResponse;
use tunnelcraft_relay::{RelayConfig, RelayHandler};

/// Test helper to create a user keypair
fn create_user_keypair() -> SigningKeypair {
    SigningKeypair::generate()
}

/// Test helper to create an exit keypair
fn create_exit_keypair() -> SigningKeypair {
    SigningKeypair::generate()
}

/// Test helper to create relay handlers
fn create_relay_chain(count: usize) -> Vec<RelayHandler> {
    (0..count)
        .map(|_| RelayHandler::new(SigningKeypair::generate()))
        .collect()
}

/// Create request shards for testing
fn create_test_request_shards(
    user_pubkey: [u8; 32],
    exit_pubkey: [u8; 32],
) -> Vec<Shard> {
    RequestBuilder::new("GET", "https://httpbin.org/get")
        .header("User-Agent", "TunnelCraft-Test")
        .hop_mode(HopMode::Standard)
        .build(user_pubkey, exit_pubkey)
        .expect("Failed to build request shards")
}

// =============================================================================
// FULL FLOW TESTS
// =============================================================================

#[test]
fn test_request_shards_through_single_relay() {
    let user_keypair = create_user_keypair();
    let exit_keypair = create_exit_keypair();
    let user_pubkey = user_keypair.public_key_bytes();
    let exit_pubkey = exit_keypair.public_key_bytes();

    // Create request shards
    let shards = create_test_request_shards(user_pubkey, exit_pubkey);
    assert_eq!(shards.len(), TOTAL_SHARDS);

    // Create a relay handler
    let mut relay = RelayHandler::new(SigningKeypair::generate());
    let relay_pubkey = relay.pubkey();

    // Process each shard through the relay
    let mut processed_shards = Vec::new();
    for shard in shards {
        let result = relay.handle_shard(shard).expect("Relay should accept shard");
        let processed = result.expect("Should return processed shard");

        // Verify relay stamped its pubkey as sender
        assert_eq!(
            processed.sender_pubkey, relay_pubkey,
            "sender_pubkey should be relay's pubkey"
        );

        // Verify hops decremented
        assert!(processed.hops_remaining < 3, "Hops should be decremented");

        processed_shards.push(processed);
    }

    assert_eq!(processed_shards.len(), TOTAL_SHARDS);
}

#[test]
fn test_request_shards_through_relay_chain() {
    let user_keypair = create_user_keypair();
    let exit_keypair = create_exit_keypair();
    let user_pubkey = user_keypair.public_key_bytes();
    let exit_pubkey = exit_keypair.public_key_bytes();

    // Create request with more hops
    let shards = RequestBuilder::new("GET", "https://example.com")
        .hop_mode(HopMode::Paranoid) // More hops
        .build(user_pubkey, exit_pubkey)
        .expect("Failed to build request shards");

    // Create a chain of relays
    let mut relays = create_relay_chain(3);
    let relay_pubkeys: Vec<_> = relays.iter().map(|r| r.pubkey()).collect();

    // Process each shard through the relay chain
    for mut shard in shards {
        for (i, relay) in relays.iter_mut().enumerate() {
            let result = relay.handle_shard(shard.clone()).expect("Relay should accept");
            shard = result.expect("Should return processed shard");

            // Verify sender_pubkey is the current relay
            assert_eq!(shard.sender_pubkey, relay_pubkeys[i]);
        }
    }
}

#[test]
fn test_response_destination_verification() {
    let user_keypair = create_user_keypair();
    let exit_keypair = create_exit_keypair();
    let user_pubkey = user_keypair.public_key_bytes();
    let exit_pubkey = exit_keypair.public_key_bytes();

    // Create and process request shards to populate relay cache
    let request_shards = create_test_request_shards(user_pubkey, exit_pubkey);
    let request_id = request_shards[0].request_id;

    let mut relay = RelayHandler::new(SigningKeypair::generate());

    // Process request shards (this caches request_id → user_pubkey)
    for shard in &request_shards {
        relay.handle_shard(shard.clone()).expect("Should process request");
    }

    // Create a valid response shard with correct destination
    let valid_response = Shard::new_response(
        [100u8; 32],
        request_id,
        user_pubkey, // Correct destination
        [0u8; 32],   // user_proof
        exit_pubkey,
        2,
        vec![1, 2, 3, 4],
        0,
        5,
        2,           // total_hops
        0,           // chunk_index
        1,           // total_chunks
    );

    // Should succeed - destination matches cached user
    let result = relay.handle_shard(valid_response);
    assert!(result.is_ok(), "Valid response should be accepted");

    // Create an INVALID response with wrong destination (attack simulation)
    let attacker_pubkey = [0xFFu8; 32];
    let malicious_response = Shard::new_response(
        [101u8; 32],
        request_id,
        attacker_pubkey, // WRONG destination
        [0u8; 32],       // user_proof
        exit_pubkey,
        2,
        vec![1, 2, 3, 4],
        1,
        5,
        2,               // total_hops
        0,               // chunk_index
        1,               // total_chunks
    );

    // Should fail - destination mismatch detected
    let result = relay.handle_shard(malicious_response);
    assert!(result.is_err(), "Malicious response should be rejected");

    match result {
        Err(tunnelcraft_relay::RelayError::DestinationMismatch { expected, actual }) => {
            assert_eq!(expected, user_pubkey, "Expected should be user pubkey");
            assert_eq!(actual, attacker_pubkey, "Actual should be attacker pubkey");
        }
        _ => panic!("Expected DestinationMismatch error"),
    }
}

// =============================================================================
// ERASURE CODING TESTS
// =============================================================================

#[test]
fn test_erasure_reconstruction_with_3_of_5_shards() {
    let coder = ErasureCoder::new().expect("Failed to create coder");

    let original_data = b"This is test data for erasure coding reconstruction";
    let encoded = coder.encode(original_data).expect("Failed to encode");

    assert_eq!(encoded.len(), TOTAL_SHARDS);

    // Test reconstruction with first 3 shards
    let mut shards: Vec<Option<Vec<u8>>> = vec![None; TOTAL_SHARDS];
    shards[0] = Some(encoded[0].clone());
    shards[1] = Some(encoded[1].clone());
    shards[2] = Some(encoded[2].clone());

    let decoded = coder
        .decode(&mut shards, original_data.len())
        .expect("Failed to decode");
    assert_eq!(decoded, original_data);

    // Test reconstruction with last 3 shards
    let mut shards: Vec<Option<Vec<u8>>> = vec![None; TOTAL_SHARDS];
    shards[2] = Some(encoded[2].clone());
    shards[3] = Some(encoded[3].clone());
    shards[4] = Some(encoded[4].clone());

    let decoded = coder
        .decode(&mut shards, original_data.len())
        .expect("Failed to decode");
    assert_eq!(decoded, original_data);

    // Test reconstruction with mixed shards (0, 2, 4)
    let mut shards: Vec<Option<Vec<u8>>> = vec![None; TOTAL_SHARDS];
    shards[0] = Some(encoded[0].clone());
    shards[2] = Some(encoded[2].clone());
    shards[4] = Some(encoded[4].clone());

    let decoded = coder
        .decode(&mut shards, original_data.len())
        .expect("Failed to decode");
    assert_eq!(decoded, original_data);
}

#[test]
fn test_erasure_fails_with_2_of_5_shards() {
    let coder = ErasureCoder::new().expect("Failed to create coder");

    let original_data = b"Test data";
    let encoded = coder.encode(original_data).expect("Failed to encode");

    // Only 2 shards available - should fail
    let mut shards: Vec<Option<Vec<u8>>> = vec![None; TOTAL_SHARDS];
    shards[0] = Some(encoded[0].clone());
    shards[1] = Some(encoded[1].clone());

    let result = coder.decode(&mut shards, original_data.len());
    assert!(result.is_err(), "Should fail with only 2 shards");
}

#[test]
fn test_request_shards_contain_erasure_encoded_data() {
    let user_pubkey = [1u8; 32];
    let exit_pubkey = [2u8; 32];

    let shards = create_test_request_shards(user_pubkey, exit_pubkey);

    // All shards should have same request_id
    let request_id = shards[0].request_id;
    for shard in &shards {
        assert_eq!(shard.request_id, request_id);
    }

    // Verify shard indices are correct
    for (i, shard) in shards.iter().enumerate() {
        assert_eq!(shard.shard_index, i as u8);
        assert_eq!(shard.total_shards, TOTAL_SHARDS as u8);
    }

    // Verify payloads are present and non-empty
    for shard in &shards {
        assert!(!shard.payload.is_empty(), "Shard payload should not be empty");
    }
}

// =============================================================================
// SENDER PUBKEY STAMPING TESTS
// =============================================================================

#[test]
fn test_sender_pubkey_stamped_through_relays() {
    let user_pubkey = [1u8; 32];
    let exit_pubkey = [2u8; 32];

    let shards = RequestBuilder::new("GET", "https://example.com")
        .hop_mode(HopMode::Paranoid)
        .build(user_pubkey, exit_pubkey)
        .expect("Failed to build shards");

    let mut relays = create_relay_chain(3);
    let relay_pubkeys: Vec<_> = relays.iter().map(|r| r.pubkey()).collect();

    // Take just one shard for testing
    let mut shard = shards.into_iter().next().unwrap();

    // Process through each relay
    for (i, relay) in relays.iter_mut().enumerate() {
        let result = relay.handle_shard(shard).expect("Should process");
        shard = result.expect("Should return shard");

        // After each relay, sender_pubkey should be that relay's pubkey
        assert_eq!(shard.sender_pubkey, relay_pubkeys[i]);
    }

    // After the last relay, sender_pubkey should be the last relay's pubkey
    assert_eq!(shard.sender_pubkey, relay_pubkeys[2]);
}

#[test]
fn test_relay_decrements_hops_and_stamps_sender() {
    let user_pubkey = [1u8; 32];
    let exit_pubkey = [2u8; 32];

    let shards = RequestBuilder::new("GET", "https://example.com")
        .hop_mode(HopMode::Standard)
        .build(user_pubkey, exit_pubkey)
        .expect("Failed to build");

    let relay_keypair = SigningKeypair::generate();
    let relay_pubkey = relay_keypair.public_key_bytes();
    let mut relay = RelayHandler::new(relay_keypair);
    let mut shard = shards.into_iter().next().unwrap();
    let initial_hops = shard.hops_remaining;

    let result = relay.handle_shard(shard).expect("Should process");
    shard = result.expect("Should return");

    // Hops should be decremented
    assert_eq!(shard.hops_remaining, initial_hops - 1);

    // sender_pubkey should be the relay's pubkey
    assert_eq!(shard.sender_pubkey, relay_pubkey);
}

// =============================================================================
// SECURITY TESTS
// =============================================================================

#[test]
fn test_response_without_prior_request_forwarded() {
    let mut relay = RelayHandler::new(SigningKeypair::generate());

    // Response without prior request should still be forwarded
    // (response shards take independent random paths through any relay)
    let orphan_response = Shard::new_response(
        [1u8; 32],
        [99u8; 32], // Unknown request_id
        [4u8; 32],
        [0u8; 32],  // user_proof
        [9u8; 32],  // exit_pubkey
        2,
        vec![1, 2, 3],
        0,
        5,
        2,          // total_hops
        0,          // chunk_index
        1,          // total_chunks
    );

    let result = relay.handle_shard(orphan_response);
    assert!(result.is_ok());
    let shard = result.unwrap().unwrap();
    assert_eq!(shard.hops_remaining, 1); // decremented
}

#[test]
fn test_multiple_request_shards_share_cache_entry() {
    let user_keypair = create_user_keypair();
    let exit_keypair = create_exit_keypair();
    let user_pubkey = user_keypair.public_key_bytes();
    let exit_pubkey = exit_keypair.public_key_bytes();

    let shards = create_test_request_shards(user_pubkey, exit_pubkey);
    let request_id = shards[0].request_id;

    let mut relay = RelayHandler::new(SigningKeypair::generate());

    // Process all request shards
    for shard in &shards {
        relay.handle_shard(shard.clone()).expect("Should process");
    }

    // Cache should have just one entry for this request
    assert_eq!(relay.cache_size(), 1);

    // Response with correct destination should work
    let response = Shard::new_response(
        [100u8; 32],
        request_id,
        user_pubkey,
        [0u8; 32],  // user_proof
        exit_pubkey,
        2,
        vec![1, 2, 3],
        0,
        5,
        2,          // total_hops
        0,          // chunk_index
        1,          // total_chunks
    );

    let result = relay.handle_shard(response);
    assert!(result.is_ok());
}

#[test]
fn test_relay_last_hop_response_forwarded() {
    let user_keypair = create_user_keypair();
    let exit_keypair = create_exit_keypair();
    let user_pubkey = user_keypair.public_key_bytes();
    let exit_pubkey = exit_keypair.public_key_bytes();

    let mut relay = RelayHandler::new(SigningKeypair::generate());

    // Create request shard and process it
    let mut shards = RequestBuilder::new("GET", "https://example.com")
        .hop_mode(HopMode::Direct)
        .build(user_pubkey, exit_pubkey)
        .expect("Failed to build");

    let request_shard = shards.remove(0);
    let request_id = request_shard.request_id;
    relay.handle_shard(request_shard).expect("Request should work");

    // Response with hops=1 (will be 0 = last hop) should be forwarded
    let response = Shard::new_response(
        [100u8; 32],
        request_id,
        user_pubkey,
        [0u8; 32],  // user_proof
        exit_pubkey,
        1,
        vec![1, 2, 3],
        0,
        5,
        1,          // total_hops
        0,          // chunk_index
        1,          // total_chunks
    );

    let result = relay.handle_shard(response);
    assert!(result.is_ok());
    let shard = result.unwrap().unwrap();
    assert_eq!(shard.hops_remaining, 0);
}

// =============================================================================
// HTTP REQUEST/RESPONSE TESTS
// =============================================================================

#[test]
fn test_http_request_serialization_roundtrip() {
    use tunnelcraft_exit::HttpRequest;
    use std::collections::HashMap;

    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    headers.insert("Authorization".to_string(), "Bearer token123".to_string());

    let request = HttpRequest {
        method: "POST".to_string(),
        url: "https://api.example.com/data".to_string(),
        headers,
        body: Some(b"{\"key\": \"value\"}".to_vec()),
    };

    let bytes = request.to_bytes();
    let parsed = HttpRequest::from_bytes(&bytes).expect("Should parse");

    assert_eq!(parsed.method, "POST");
    assert_eq!(parsed.url, "https://api.example.com/data");
    assert_eq!(parsed.headers.len(), 2);
    assert_eq!(parsed.body.unwrap(), b"{\"key\": \"value\"}");
}

#[test]
fn test_http_response_serialization() {
    use std::collections::HashMap;

    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), "text/html".to_string());

    let response = HttpResponse::new(200, headers, b"<html>Hello</html>".to_vec());

    let bytes = response.to_bytes();
    assert!(!bytes.is_empty());
}

// =============================================================================
// END-TO-END FLOW TEST
// =============================================================================

#[test]
fn test_complete_request_response_flow() {
    // This test simulates the complete flow:
    // Client -> Relay1 -> Relay2 -> Exit -> Relay2 -> Relay1 -> Client

    let user_keypair = create_user_keypair();
    let exit_keypair = create_exit_keypair();
    let user_pubkey = user_keypair.public_key_bytes();
    let exit_pubkey = exit_keypair.public_key_bytes();

    // Create request shards with enough hops for the relay chain
    let request_shards = RequestBuilder::new("GET", "https://example.com/api")
        .header("Accept", "application/json")
        .hop_mode(HopMode::Paranoid) // Use more hops to avoid last-hop issues
        .build(user_pubkey, exit_pubkey)
        .expect("Failed to build request");

    let request_id = request_shards[0].request_id;

    // Create relay chain - configure to not remove cache entries on last hop
    // This allows processing all response shards without cache invalidation
    let relay_config = RelayConfig {
        can_be_last_hop: false, // Don't remove cache entries
    };
    let mut relay1 = RelayHandler::with_config(SigningKeypair::generate(), relay_config.clone());
    let mut relay2 = RelayHandler::with_config(SigningKeypair::generate(), relay_config);

    // ========== REQUEST PHASE ==========
    // Process request shards through relays
    let mut shards_after_relay1 = Vec::new();
    for shard in request_shards {
        let result = relay1.handle_shard(shard).expect("Relay1 should process");
        shards_after_relay1.push(result.expect("Should return shard"));
    }

    let mut shards_after_relay2 = Vec::new();
    for shard in shards_after_relay1 {
        let result = relay2.handle_shard(shard).expect("Relay2 should process");
        shards_after_relay2.push(result.expect("Should return shard"));
    }

    // Verify shards reached exit with relay2's sender_pubkey stamped
    for shard in &shards_after_relay2 {
        assert_eq!(shard.sender_pubkey, relay2.pubkey(), "sender_pubkey should be relay2");
        assert_eq!(shard.shard_type, ShardType::Request);
    }

    // ========== RESPONSE PHASE ==========
    // Create response shards (simulating what exit would create)
    let coder = ErasureCoder::new().unwrap();
    let response_data = b"HTTP response body";
    let encoded_response = coder.encode(response_data).unwrap();

    let mut response_shards = Vec::new();

    for (i, payload) in encoded_response.into_iter().enumerate() {
        let shard = Shard::new_response(
            [100 + i as u8; 32],
            request_id,
            user_pubkey, // Destination is user
            [0u8; 32],   // user_proof
            exit_pubkey,
            4, // More hops to avoid last-hop issues
            payload,
            i as u8,
            TOTAL_SHARDS as u8,
            4,           // total_hops
            0,           // chunk_index
            1,           // total_chunks
        );
        response_shards.push(shard);
    }

    // Process response shards back through relays (reverse order)
    let mut response_after_relay2 = Vec::new();
    for shard in response_shards {
        let result = relay2
            .handle_shard(shard)
            .expect("Relay2 should process response");
        response_after_relay2.push(result.expect("Should return shard"));
    }

    let mut response_after_relay1 = Vec::new();
    for shard in response_after_relay2 {
        let result = relay1
            .handle_shard(shard)
            .expect("Relay1 should process response");
        response_after_relay1.push(result.expect("Should return shard"));
    }

    // ========== CLIENT RECONSTRUCTION ==========
    // Collect response shard payloads
    let mut shard_data: Vec<Option<Vec<u8>>> = vec![None; TOTAL_SHARDS];
    for shard in &response_after_relay1 {
        shard_data[shard.shard_index as usize] = Some(shard.payload.clone());
    }

    // Reconstruct response
    let reconstructed = coder
        .decode(&mut shard_data, response_data.len())
        .expect("Should reconstruct");

    assert_eq!(reconstructed, response_data, "Response should match");

    // Verify response shards have relay1's sender_pubkey (last relay in return path)
    for shard in &response_after_relay1 {
        assert_eq!(shard.sender_pubkey, relay1.pubkey(), "sender_pubkey should be relay1 after return");
        assert_eq!(shard.shard_type, ShardType::Response);
    }
}

#[test]
fn test_partial_shard_reconstruction() {
    // Test that we can reconstruct with only 3 of 5 shards arriving

    let user_pubkey = [1u8; 32];
    let exit_pubkey = [2u8; 32];

    let shards = create_test_request_shards(user_pubkey, exit_pubkey);

    // Simulate only 3 shards arriving (network loss)
    let received_shards: Vec<_> = shards.into_iter().take(DATA_SHARDS).collect();

    // Prepare for reconstruction
    let mut shard_data: Vec<Option<Vec<u8>>> = vec![None; TOTAL_SHARDS];
    for shard in &received_shards {
        shard_data[shard.shard_index as usize] = Some(shard.payload.clone());
    }

    // Should be able to verify we have enough
    let coder = ErasureCoder::new().unwrap();
    assert!(coder.verify(&shard_data), "Should have enough shards");
}
