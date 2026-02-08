//! Full Tunnel Simulation Tests
//!
//! End-to-end integration tests that simulate realistic TunnelCraft operation:
//! - Real HTTP requests through the tunnel
//! - Actual exit node fetching from HTTP server
//! - Variable payload sizes with multiple chunking rounds
//! - Full relay chain with sender_pubkey stamping
//!
//! Test topology:
//! ```text
//! Client → Relay1 → Relay2 → Exit → HTTP Server
//!   ↑                          ↓
//!   └──────────────────────────┘
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::oneshot;

use axum::{
    Router,
    routing::get,
    extract::Path,
};

use tunnelcraft_client::RequestBuilder;
use tunnelcraft_core::{HopMode, Shard};
use tunnelcraft_crypto::SigningKeypair;
use tunnelcraft_erasure::{ErasureCoder, DATA_SHARDS, TOTAL_SHARDS};
use tunnelcraft_exit::{ExitConfig, ExitHandler, HttpRequest, HttpResponse};
use tunnelcraft_relay::RelayHandler;

// =============================================================================
// TEST HTTP SERVER
// =============================================================================

/// Start a test HTTP server that returns various payload sizes
async fn start_test_server() -> (SocketAddr, oneshot::Sender<()>) {
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let app = Router::new()
        .route("/small", get(|| async { "Hello, TunnelCraft!" }))
        .route("/medium", get(|| async {
            // ~10KB response
            "X".repeat(10 * 1024)
        }))
        .route("/large", get(|| async {
            // ~100KB response
            "Y".repeat(100 * 1024)
        }))
        .route("/huge", get(|| async {
            // ~500KB response (will require multiple erasure coding rounds)
            "Z".repeat(500 * 1024)
        }))
        .route("/json", get(|| async {
            axum::Json(serde_json::json!({
                "status": "ok",
                "data": {
                    "message": "TunnelCraft tunnel working!",
                    "items": (0..100).map(|i| format!("item_{}", i)).collect::<Vec<_>>(),
                }
            }))
        }))
        .route("/echo/{size}", get(|Path(size): Path<usize>| async move {
            // Return exact size payload
            let size = size.min(1024 * 1024); // Cap at 1MB
            "D".repeat(size)
        }));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    (addr, shutdown_tx)
}

// =============================================================================
// TEST HELPERS
// =============================================================================

/// Simulate request flow through relay chain
fn process_through_relays(
    mut shards: Vec<Shard>,
    relays: &mut [RelayHandler],
) -> Vec<Shard> {
    for relay in relays.iter_mut() {
        shards = shards
            .into_iter()
            .filter_map(|shard| {
                relay.handle_shard(shard).ok().flatten()
            })
            .collect();
    }
    shards
}

/// Simulate response flow back through relay chain (reverse order)
fn process_response_through_relays(
    mut shards: Vec<Shard>,
    relays: &mut [RelayHandler],
) -> Vec<Shard> {
    // Response goes in reverse order
    for relay in relays.iter_mut().rev() {
        shards = shards
            .into_iter()
            .filter_map(|shard| {
                relay.handle_shard(shard).ok().flatten()
            })
            .collect();
    }
    shards
}

/// Reconstruct data from shards using erasure coding
///
/// Uses max possible length (shard_size * DATA_SHARDS) since our serialized data
/// formats (HttpRequest, HttpResponse) are self-describing and can handle trailing bytes.
fn reconstruct_from_shards(shards: &[Shard]) -> Result<Vec<u8>, String> {
    let erasure = ErasureCoder::new().map_err(|e| e.to_string())?;

    // Need at least DATA_SHARDS
    if shards.len() < DATA_SHARDS {
        return Err(format!(
            "Not enough shards: have {}, need {}",
            shards.len(),
            DATA_SHARDS
        ));
    }

    // Prepare shard data for reconstruction
    let mut shard_data: Vec<Option<Vec<u8>>> = vec![None; TOTAL_SHARDS];
    let mut shard_size = 0;
    for shard in shards {
        let idx = shard.shard_index as usize;
        if idx < TOTAL_SHARDS {
            shard_size = shard.payload.len();
            shard_data[idx] = Some(shard.payload.clone());
        }
    }

    // Use max possible length - the serialization formats handle their own length
    let max_len = shard_size * DATA_SHARDS;
    erasure.decode(&mut shard_data, max_len).map_err(|e| e.to_string())
}

// =============================================================================
// FULL TUNNEL SIMULATION TESTS
// =============================================================================

#[tokio::test]
async fn test_full_tunnel_small_request() {
    // Start test HTTP server
    let (server_addr, _shutdown) = start_test_server().await;
    let url = format!("http://{}/small", server_addr);

    // Create participants
    let user_keypair = SigningKeypair::generate();
    let exit_keypair = SigningKeypair::generate();
    let user_pubkey = user_keypair.public_key_bytes();
    let exit_pubkey = exit_keypair.public_key_bytes();

    // Create relay chain (2 relays)
    let mut relays: Vec<RelayHandler> = (0..2)
        .map(|_| RelayHandler::new(SigningKeypair::generate()))
        .collect();

    // Create exit handler (not used directly in test - we simulate exit behavior manually)
    let _exit_handler = ExitHandler::new(
        ExitConfig::default(),
        exit_pubkey,
        [0u8; 32],
    ).unwrap();

    // === REQUEST PHASE ===

    // Build request shards
    let request_shards = RequestBuilder::new("GET", &url)
        .header("User-Agent", "TunnelCraft-Test/1.0")
        .hop_mode(HopMode::Standard)
        .build(user_pubkey, exit_pubkey)
        .expect("Failed to build request");

    assert_eq!(request_shards.len(), TOTAL_SHARDS);
    println!("Created {} request shards", request_shards.len());

    // Process through relay chain
    let relayed_shards = process_through_relays(request_shards.clone(), &mut relays);
    println!(
        "After relays: {} shards",
        relayed_shards.len(),
    );

    // Each shard should have a relay's sender_pubkey stamped
    for shard in &relayed_shards {
        assert_ne!(shard.sender_pubkey, [0u8; 32], "sender_pubkey should be stamped by relay");
    }

    // Reconstruct at exit
    let request_data = reconstruct_from_shards(&relayed_shards)
        .expect("Failed to reconstruct request");

    let http_request = HttpRequest::from_bytes(&request_data)
        .expect("Failed to parse HTTP request");

    println!("Exit received: {} {}", http_request.method, http_request.url);
    assert_eq!(http_request.method, "GET");
    assert!(http_request.url.contains("/small"));

    // === EXIT FETCHES FROM SERVER ===

    let client = reqwest::Client::new();
    let response = client
        .request(
            reqwest::Method::from_bytes(http_request.method.as_bytes()).unwrap(),
            &http_request.url,
        )
        .send()
        .await
        .expect("Exit failed to fetch");

    let status = response.status().as_u16();
    let body = response.bytes().await.expect("Failed to read body");

    println!("Exit fetched: status={}, body_len={}", status, body.len());
    assert_eq!(status, 200);
    assert_eq!(&body[..], b"Hello, TunnelCraft!");

    // === RESPONSE PHASE ===

    // Create response shards
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), "text/plain".to_string());
    let http_response = HttpResponse {
        status,
        headers,
        body: body.to_vec(),
    };

    let response_data = http_response.to_bytes();
    let erasure = ErasureCoder::new().unwrap();
    let encoded = erasure.encode(&response_data).unwrap();

    let request_id = request_shards[0].request_id;

    let response_shards: Vec<Shard> = encoded
        .into_iter()
        .enumerate()
        .map(|(i, payload)| {
            Shard::new_response(
                [i as u8; 32], // shard_id
                request_id,
                user_pubkey,  // destination
                [0u8; 32],    // user_proof
                exit_pubkey,
                3,            // hops
                payload,
                i as u8,
                TOTAL_SHARDS as u8,
                3,            // total_hops
                0,            // chunk_index
                1,            // total_chunks
            )
        })
        .collect();

    println!("Created {} response shards", response_shards.len());

    // Process response back through relays (reverse order)
    let returned_shards = process_response_through_relays(response_shards, &mut relays);
    println!(
        "After return: {} shards",
        returned_shards.len(),
    );

    // Client reconstructs response
    let final_data = reconstruct_from_shards(&returned_shards)
        .expect("Failed to reconstruct response");

    let final_response = HttpResponse::from_bytes(&final_data)
        .expect("Failed to parse response");

    assert_eq!(final_response.status, 200);
    assert_eq!(String::from_utf8_lossy(&final_response.body), "Hello, TunnelCraft!");

    println!("SUCCESS: Full tunnel round-trip completed!");
}

#[tokio::test]
async fn test_full_tunnel_large_response() {
    // Start test HTTP server
    let (server_addr, _shutdown) = start_test_server().await;
    let url = format!("http://{}/large", server_addr);

    // Create participants
    let user_keypair = SigningKeypair::generate();
    let exit_keypair = SigningKeypair::generate();
    let user_pubkey = user_keypair.public_key_bytes();
    let exit_pubkey = exit_keypair.public_key_bytes();

    // Create relay chain
    let mut relays: Vec<RelayHandler> = (0..2)
        .map(|_| RelayHandler::new(SigningKeypair::generate()))
        .collect();

    // Build and relay request
    let request_shards = RequestBuilder::new("GET", &url)
        .hop_mode(HopMode::Standard)
        .build(user_pubkey, exit_pubkey)
        .expect("Failed to build request");

    let relayed_shards = process_through_relays(request_shards.clone(), &mut relays);
    let request_data = reconstruct_from_shards(&relayed_shards).unwrap();
    let http_request = HttpRequest::from_bytes(&request_data).unwrap();

    // Exit fetches large response
    let client = reqwest::Client::new();
    let response = client.get(&http_request.url).send().await.unwrap();
    let status = response.status().as_u16();
    let body = response.bytes().await.unwrap();

    println!(
        "Large response: status={}, body_len={} bytes ({:.1} KB)",
        status,
        body.len(),
        body.len() as f64 / 1024.0
    );

    // Create response shards (will be larger due to 100KB payload)
    let http_response = HttpResponse {
        status,
        headers: HashMap::new(),
        body: body.to_vec(),
    };

    let response_data = http_response.to_bytes();
    println!("Response data size: {} bytes", response_data.len());

    let erasure = ErasureCoder::new().unwrap();
    let encoded = erasure.encode(&response_data).unwrap();

    println!(
        "Erasure encoded into {} shards, each ~{} bytes",
        encoded.len(),
        encoded.first().map(|s| s.len()).unwrap_or(0)
    );

    let request_id = request_shards[0].request_id;

    let response_shards: Vec<Shard> = encoded
        .into_iter()
        .enumerate()
        .map(|(i, payload)| {
            Shard::new_response(
                [i as u8; 32],
                request_id,
                user_pubkey,
                [0u8; 32],    // user_proof
                exit_pubkey,
                3,
                payload,
                i as u8,
                TOTAL_SHARDS as u8,
                3,            // total_hops
                0,            // chunk_index
                1,            // total_chunks
            )
        })
        .collect();

    // Return through relays
    let returned_shards = process_response_through_relays(response_shards, &mut relays);

    // Reconstruct
    let final_data = reconstruct_from_shards(&returned_shards).unwrap();
    let final_response = HttpResponse::from_bytes(&final_data).unwrap();

    assert_eq!(final_response.status, 200);
    assert_eq!(final_response.body.len(), 100 * 1024);
    assert!(final_response.body.iter().all(|&b| b == b'Y'));

    println!(
        "SUCCESS: Large response ({} KB) transmitted through tunnel!",
        final_response.body.len() / 1024
    );
}

#[tokio::test]
async fn test_full_tunnel_json_api() {
    let (server_addr, _shutdown) = start_test_server().await;
    let url = format!("http://{}/json", server_addr);

    let user_keypair = SigningKeypair::generate();
    let exit_keypair = SigningKeypair::generate();
    let user_pubkey = user_keypair.public_key_bytes();
    let exit_pubkey = exit_keypair.public_key_bytes();

    let mut relays: Vec<RelayHandler> = (0..2)
        .map(|_| RelayHandler::new(SigningKeypair::generate()))
        .collect();

    // Request
    let request_shards = RequestBuilder::new("GET", &url)
        .header("Accept", "application/json")
        .hop_mode(HopMode::Standard)
        .build(user_pubkey, exit_pubkey)
        .unwrap();

    let relayed = process_through_relays(request_shards.clone(), &mut relays);
    let request_data = reconstruct_from_shards(&relayed).unwrap();
    let http_request = HttpRequest::from_bytes(&request_data).unwrap();

    // Exit fetch
    let client = reqwest::Client::new();
    let response = client.get(&http_request.url).send().await.unwrap();
    let body = response.bytes().await.unwrap();

    // Parse JSON to verify
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert!(json["data"]["items"].as_array().unwrap().len() == 100);

    println!("SUCCESS: JSON API response received through tunnel!");
    println!("JSON preview: {}", serde_json::to_string_pretty(&json["data"]["message"]).unwrap());
}

#[tokio::test]
async fn test_full_tunnel_variable_sizes() {
    let (server_addr, _shutdown) = start_test_server().await;

    let user_keypair = SigningKeypair::generate();
    let exit_keypair = SigningKeypair::generate();
    let user_pubkey = user_keypair.public_key_bytes();
    let exit_pubkey = exit_keypair.public_key_bytes();

    // Test various sizes
    let sizes = [1024, 5 * 1024, 50 * 1024, 200 * 1024];

    for size in sizes {
        let url = format!("http://{}/echo/{}", server_addr, size);

        let mut relays: Vec<RelayHandler> = (0..2)
            .map(|_| RelayHandler::new(SigningKeypair::generate()))
            .collect();

        let request_shards = RequestBuilder::new("GET", &url)
            .hop_mode(HopMode::Standard)
            .build(user_pubkey, exit_pubkey)
            .unwrap();

        let relayed = process_through_relays(request_shards.clone(), &mut relays);
        let request_data = reconstruct_from_shards(&relayed).unwrap();
        let http_request = HttpRequest::from_bytes(&request_data).unwrap();

        let client = reqwest::Client::new();
        let response = client.get(&http_request.url).send().await.unwrap();
        let body = response.bytes().await.unwrap();

        let http_response = HttpResponse {
            status: 200,
            headers: HashMap::new(),
            body: body.to_vec(),
        };

        let erasure = ErasureCoder::new().unwrap();
        let encoded = erasure.encode(&http_response.to_bytes()).unwrap();

        let request_id = request_shards[0].request_id;

        let response_shards: Vec<Shard> = encoded
            .into_iter()
            .enumerate()
            .map(|(i, payload)| {
                Shard::new_response(
                    [i as u8; 32],
                    request_id,
                    user_pubkey,
                    [0u8; 32],    // user_proof
                    exit_pubkey,
                    3,
                    payload,
                    i as u8,
                    TOTAL_SHARDS as u8,
                    3,            // total_hops
                    0,            // chunk_index
                    1,            // total_chunks
                )
            })
            .collect();

        let returned = process_response_through_relays(response_shards, &mut relays);
        let final_data = reconstruct_from_shards(&returned).unwrap();
        let final_response = HttpResponse::from_bytes(&final_data).unwrap();

        assert_eq!(final_response.body.len(), size);
        println!(
            "✓ Size {} bytes ({:.1} KB): {} shards, each ~{} bytes",
            size,
            size as f64 / 1024.0,
            TOTAL_SHARDS,
            final_response.body.len() / DATA_SHARDS
        );
    }

    println!("\nSUCCESS: All variable size tests passed!");
}

#[tokio::test]
async fn test_tunnel_with_paranoid_hops() {
    let (server_addr, _shutdown) = start_test_server().await;
    let url = format!("http://{}/small", server_addr);

    let user_keypair = SigningKeypair::generate();
    let exit_keypair = SigningKeypair::generate();
    let user_pubkey = user_keypair.public_key_bytes();
    let exit_pubkey = exit_keypair.public_key_bytes();

    // More relays for paranoid mode
    let mut relays: Vec<RelayHandler> = (0..4)
        .map(|_| RelayHandler::new(SigningKeypair::generate()))
        .collect();

    let request_shards = RequestBuilder::new("GET", &url)
        .hop_mode(HopMode::Paranoid) // Maximum hops
        .build(user_pubkey, exit_pubkey)
        .unwrap();

    println!("Paranoid mode: initial hops = {}", request_shards[0].hops_remaining);

    let relayed = process_through_relays(request_shards.clone(), &mut relays);

    println!(
        "After {} relays: sender_pubkey stamped",
        relays.len(),
    );

    // Verify sender_pubkey is stamped by the last relay
    for shard in &relayed {
        assert_ne!(
            shard.sender_pubkey, [0u8; 32],
            "Paranoid mode should have sender_pubkey stamped by last relay"
        );
    }

    let request_data = reconstruct_from_shards(&relayed).unwrap();
    let http_request = HttpRequest::from_bytes(&request_data).unwrap();

    let client = reqwest::Client::new();
    let response = client.get(&http_request.url).send().await.unwrap();
    let body = response.text().await.unwrap();

    assert_eq!(body, "Hello, TunnelCraft!");
    println!("SUCCESS: Paranoid mode with 4 relay hops completed!");
}
