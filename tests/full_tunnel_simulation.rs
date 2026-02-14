//! Full Tunnel Simulation Tests (Onion Routing)
//!
//! End-to-end integration tests that simulate direct-mode TunnelCraft operation:
//! - Client builds onion-encrypted shards via RequestBuilder::build_onion()
//! - Exit node decrypts, reassembles, and fetches from real HTTP server
//! - Exit creates encrypted response shards
//! - Client decrypts response
//!
//! Test topology (direct mode -- no relay chain):
//! ```text
//! Client --> Exit --> HTTP Server
//!   ^                    |
//!   +--------------------+
//! ```
//!
//! Direct mode is used because building proper multi-hop onion headers
//! for integration tests requires a live relay network. These tests verify
//! the core encrypt -> shard -> reassemble -> decrypt -> fetch -> respond
//! pipeline end-to-end.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::oneshot;

use axum::{
    Router,
    routing::get,
    extract::Path,
};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use tunnelcraft_client::{RequestBuilder, PathHop, OnionPath, build_tunnel_shards};
use tunnelcraft_core::{Shard, TunnelMetadata, lease_set::LeaseSet};
use tunnelcraft_crypto::{SigningKeypair, EncryptionKeypair, decrypt_from_sender, decrypt_routing_tag};
use tunnelcraft_erasure::{ErasureCoder, DATA_SHARDS, TOTAL_SHARDS};
use tunnelcraft_erasure::chunker::reassemble;
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

/// Create an ExitConfig that allows localhost connections (for test server).
/// The default ExitConfig blocks localhost and 127.0.0.1.
fn test_exit_config() -> ExitConfig {
    ExitConfig {
        blocked_domains: vec![],
        allow_private_ips: true,
        ..Default::default()
    }
}

/// Decrypt and reconstruct response data from exit-produced response shards.
///
/// The exit encrypts response data via `encrypt_for_recipient(response_enc_pubkey, exit_secret)`,
/// where `response_enc_pubkey` is the client's X25519 encryption pubkey.
/// To decrypt, the client uses `decrypt_from_sender(exit_enc_pubkey, client_enc_secret)`.
fn decrypt_response_shards(
    shards: &[Shard],
    exit_enc_pubkey: &[u8; 32],
    client_enc_secret: &[u8; 32],
) -> Vec<u8> {
    let erasure = ErasureCoder::new().unwrap();

    // Decrypt routing tags to get shard/chunk metadata (no longer plaintext on Shard)
    let tags: Vec<_> = shards.iter().map(|shard| {
        assert!(!shard.routing_tag.is_empty(), "routing tag must not be empty");
        decrypt_routing_tag(client_enc_secret, &shard.routing_tag)
            .expect("failed to decrypt routing tag")
    }).collect();

    // Group shards by chunk_index using decrypted routing tags
    let total_chunks = tags[0].total_chunks;
    let mut chunks_by_index: HashMap<u16, Vec<(usize, &Shard)>> = HashMap::new();
    for (i, shard) in shards.iter().enumerate() {
        chunks_by_index.entry(tags[i].chunk_index).or_default().push((i, shard));
    }

    let mut reconstructed_chunks: std::collections::BTreeMap<u16, Vec<u8>> = std::collections::BTreeMap::new();

    for chunk_idx in 0..total_chunks {
        let chunk_shards = chunks_by_index.get(&chunk_idx).expect("missing chunk");

        let mut shard_data: Vec<Option<Vec<u8>>> = vec![None; TOTAL_SHARDS];
        let mut shard_size = 0;

        for &(tag_idx, shard) in chunk_shards {
            let idx = tags[tag_idx].shard_index as usize;
            if idx < TOTAL_SHARDS {
                shard_size = shard.payload.len();
                shard_data[idx] = Some(shard.payload.clone());
            }
        }

        let max_len = shard_size * DATA_SHARDS;
        let chunk_data = erasure.decode(&mut shard_data, max_len).expect("erasure decode failed");
        reconstructed_chunks.insert(chunk_idx, chunk_data);
    }

    let total_possible: usize = reconstructed_chunks.values().map(|c| c.len()).sum();
    let framed = reassemble(&reconstructed_chunks, total_chunks, total_possible)
        .expect("reassemble failed");

    // Strip length-prefixed framing (4-byte LE u32 original length)
    assert!(framed.len() >= 4, "Framed response data too short for length prefix");
    let original_len = u32::from_le_bytes(framed[..4].try_into().unwrap()) as usize;
    assert!(
        framed.len() >= 4 + original_len,
        "Framed data shorter than declared: {} < {}",
        framed.len() - 4,
        original_len
    );
    let encrypted_response = &framed[4..4 + original_len];

    // Decrypt: exit used encrypt_for_recipient(response_enc_pubkey, exit_enc_secret),
    // so client decrypts with decrypt_from_sender(exit_enc_pubkey, client_enc_secret).
    decrypt_from_sender(
        exit_enc_pubkey,
        client_enc_secret,
        encrypted_response,
    ).expect("response decryption failed")
}

// =============================================================================
// FULL TUNNEL SIMULATION TESTS
// =============================================================================

#[tokio::test]
async fn test_full_tunnel_small_request() {
    // Start test HTTP server
    let (server_addr, _shutdown) = start_test_server().await;
    let url = format!("http://{}/small", server_addr);

    // Create client keypairs
    let client_signing = SigningKeypair::generate();
    let client_enc = EncryptionKeypair::generate();
    let client_enc_pubkey = client_enc.public_key_bytes();
    let client_enc_secret = client_enc.secret_key_bytes();

    // Create exit keypairs
    let exit_signing = SigningKeypair::generate();
    let exit_enc = EncryptionKeypair::generate();
    let exit_enc_pubkey = exit_enc.public_key_bytes();

    // Build exit PathHop (must capture pubkey before moving exit_enc)
    let exit_hop = PathHop {
        peer_id: b"exit_peer".to_vec(),
        signing_pubkey: exit_signing.public_key_bytes(),
        encryption_pubkey: exit_enc_pubkey,
    };

    // Create exit handler with known encryption keypair
    let mut exit_handler = ExitHandler::with_keypairs(
        test_exit_config(),
        exit_signing,
        exit_enc,
    ).unwrap();

    // Build lease set (empty for direct mode -- no gateway routing)
    let lease_set = LeaseSet {
        session_id: [0u8; 32],
        leases: vec![],
    };

    // === REQUEST PHASE ===

    // Build onion-encrypted request shards with client encryption pubkey for response
    let (_request_id, shards) = RequestBuilder::new("GET", &url)
        .header("User-Agent", "TunnelCraft-Test/1.0")
        .build_onion_with_enc_key(&client_signing, &exit_hop, &[], &lease_set, client_enc_pubkey, [0u8; 32])
        .expect("Failed to build onion request");

    assert_eq!(shards.len(), TOTAL_SHARDS);
    println!("Created {} request shards", shards.len());

    // All shards should have empty headers in direct mode
    for shard in &shards {
        assert!(shard.header.is_empty(), "Direct mode shards should have empty headers");
    }

    // === EXIT PROCESSES SHARDS ===

    // Feed shards to exit handler; it should accumulate them and
    // process when enough are collected.
    let mut response_shards = None;
    for shard in shards {
        let result = exit_handler.process_shard(shard).await
            .expect("Exit failed to process shard");
        if let Some(shard_pairs) = result {
            let resp: Vec<_> = shard_pairs.into_iter().map(|(s, _)| s).collect();
            response_shards = Some(resp);
        }
    }

    let response_shards = response_shards.expect("Exit should have produced response shards");
    assert!(!response_shards.is_empty(), "Response shards should not be empty");
    println!("Exit produced {} response shards", response_shards.len());

    // === CLIENT DECRYPTS RESPONSE ===

    let response_data = decrypt_response_shards(
        &response_shards,
        &exit_enc_pubkey,
        &client_enc_secret,
    );

    let http_response = HttpResponse::from_bytes(&response_data)
        .expect("Failed to parse HTTP response");

    assert_eq!(http_response.status, 200);
    assert_eq!(
        String::from_utf8_lossy(&http_response.body),
        "Hello, TunnelCraft!"
    );

    println!(
        "SUCCESS: Full tunnel round-trip completed! Response: {} bytes, status {}",
        http_response.body.len(),
        http_response.status
    );
}

#[tokio::test]
async fn test_full_tunnel_large_response() {
    // Start test HTTP server
    let (server_addr, _shutdown) = start_test_server().await;
    let url = format!("http://{}/large", server_addr);

    // Create client keypairs
    let client_signing = SigningKeypair::generate();
    let client_enc = EncryptionKeypair::generate();
    let client_enc_pubkey = client_enc.public_key_bytes();
    let client_enc_secret = client_enc.secret_key_bytes();

    // Create exit keypairs
    let exit_signing = SigningKeypair::generate();
    let exit_enc = EncryptionKeypair::generate();
    let exit_enc_pubkey = exit_enc.public_key_bytes();

    let exit_hop = PathHop {
        peer_id: b"exit_peer".to_vec(),
        signing_pubkey: exit_signing.public_key_bytes(),
        encryption_pubkey: exit_enc_pubkey,
    };

    let mut exit_handler = ExitHandler::with_keypairs(
        test_exit_config(),
        exit_signing,
        exit_enc,
    ).unwrap();

    let lease_set = LeaseSet {
        session_id: [0u8; 32],
        leases: vec![],
    };

    // Build onion request shards
    let (_request_id, shards) = RequestBuilder::new("GET", &url)
        .build_onion_with_enc_key(&client_signing, &exit_hop, &[], &lease_set, client_enc_pubkey, [0u8; 32])
        .expect("Failed to build onion request");

    println!(
        "Created {} request shards for large response test",
        shards.len()
    );

    // Feed all shards to exit
    let mut response_shards = None;
    for shard in shards {
        let result = exit_handler.process_shard(shard).await
            .expect("Exit failed to process shard");
        if let Some(shard_pairs) = result {
            let resp: Vec<_> = shard_pairs.into_iter().map(|(s, _)| s).collect();
            response_shards = Some(resp);
        }
    }

    let response_shards = response_shards.expect("Exit should have produced response shards");
    println!(
        "Exit produced {} response shards for large response",
        response_shards.len()
    );

    // Decrypt and verify
    let response_data = decrypt_response_shards(
        &response_shards,
        &exit_enc_pubkey,
        &client_enc_secret,
    );

    let http_response = HttpResponse::from_bytes(&response_data)
        .expect("Failed to parse HTTP response");

    assert_eq!(http_response.status, 200);
    assert_eq!(http_response.body.len(), 100 * 1024);
    assert!(
        http_response.body.iter().all(|&b| b == b'Y'),
        "Large response body should be all 'Y' characters"
    );

    println!(
        "SUCCESS: Large response ({} KB) transmitted through onion tunnel!",
        http_response.body.len() / 1024
    );
}

#[tokio::test]
async fn test_full_tunnel_json_api() {
    let (server_addr, _shutdown) = start_test_server().await;
    let url = format!("http://{}/json", server_addr);

    // Create client keypairs
    let client_signing = SigningKeypair::generate();
    let client_enc = EncryptionKeypair::generate();
    let client_enc_pubkey = client_enc.public_key_bytes();
    let client_enc_secret = client_enc.secret_key_bytes();

    // Create exit keypairs
    let exit_signing = SigningKeypair::generate();
    let exit_enc = EncryptionKeypair::generate();
    let exit_enc_pubkey = exit_enc.public_key_bytes();

    let exit_hop = PathHop {
        peer_id: b"exit_peer".to_vec(),
        signing_pubkey: exit_signing.public_key_bytes(),
        encryption_pubkey: exit_enc_pubkey,
    };

    let mut exit_handler = ExitHandler::with_keypairs(
        test_exit_config(),
        exit_signing,
        exit_enc,
    ).unwrap();

    let lease_set = LeaseSet {
        session_id: [0u8; 32],
        leases: vec![],
    };

    // Build request with Accept header
    let (_request_id, shards) = RequestBuilder::new("GET", &url)
        .header("Accept", "application/json")
        .build_onion_with_enc_key(&client_signing, &exit_hop, &[], &lease_set, client_enc_pubkey, [0u8; 32])
        .unwrap();

    // Feed to exit
    let mut response_shards = None;
    for shard in shards {
        let result = exit_handler.process_shard(shard).await.unwrap();
        if let Some(shard_pairs) = result {
            let resp: Vec<_> = shard_pairs.into_iter().map(|(s, _)| s).collect();
            response_shards = Some(resp);
        }
    }

    let response_shards = response_shards.expect("Exit should have produced response shards");

    // Decrypt response
    let response_data = decrypt_response_shards(
        &response_shards,
        &exit_enc_pubkey,
        &client_enc_secret,
    );

    let http_response = HttpResponse::from_bytes(&response_data)
        .expect("Failed to parse HTTP response");

    assert_eq!(http_response.status, 200);

    // Parse JSON to verify content
    let json: serde_json::Value = serde_json::from_slice(&http_response.body).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(
        json["data"]["items"].as_array().unwrap().len(),
        100
    );

    println!("SUCCESS: JSON API response received through onion tunnel!");
    println!(
        "JSON preview: {}",
        serde_json::to_string_pretty(&json["data"]["message"]).unwrap()
    );
}

#[tokio::test]
async fn test_full_tunnel_variable_sizes() {
    let (server_addr, _shutdown) = start_test_server().await;

    // Test various payload sizes
    let sizes = [1024, 5 * 1024, 50 * 1024, 200 * 1024];

    for size in sizes {
        let url = format!("http://{}/echo/{}", server_addr, size);

        // Create fresh keypairs for each size test
        let client_signing = SigningKeypair::generate();
        let client_enc = EncryptionKeypair::generate();
        let client_enc_pubkey = client_enc.public_key_bytes();
        let client_enc_secret = client_enc.secret_key_bytes();

        let exit_signing = SigningKeypair::generate();
        let exit_enc = EncryptionKeypair::generate();
        let exit_enc_pubkey = exit_enc.public_key_bytes();

        let exit_hop = PathHop {
            peer_id: b"exit_peer".to_vec(),
            signing_pubkey: exit_signing.public_key_bytes(),
            encryption_pubkey: exit_enc_pubkey,
        };

        let mut exit_handler = ExitHandler::with_keypairs(
            test_exit_config(),
            exit_signing,
            exit_enc,
        ).unwrap();

        let lease_set = LeaseSet {
            session_id: [0u8; 32],
            leases: vec![],
        };

        let (_request_id, shards) = RequestBuilder::new("GET", &url)
            .build_onion_with_enc_key(&client_signing, &exit_hop, &[], &lease_set, client_enc_pubkey, [0u8; 32])
            .unwrap();

        let num_request_shards = shards.len();

        // Feed to exit
        let mut response_shards = None;
        for shard in shards {
            let result = exit_handler.process_shard(shard).await.unwrap();
            if let Some(shard_pairs) = result {
                let resp: Vec<_> = shard_pairs.into_iter().map(|(s, _)| s).collect();
                response_shards = Some(resp);
            }
        }

        let response_shards = response_shards.expect("Exit should have produced response shards");

        // Decrypt and verify
        let response_data = decrypt_response_shards(
            &response_shards,
            &exit_enc_pubkey,
            &client_enc_secret,
        );

        let http_response = HttpResponse::from_bytes(&response_data)
            .expect("Failed to parse HTTP response");

        assert_eq!(http_response.status, 200);
        assert_eq!(http_response.body.len(), size);
        assert!(
            http_response.body.iter().all(|&b| b == b'D'),
            "Response body should be all 'D' characters"
        );

        println!(
            "  Size {} bytes ({:.1} KB): {} request shards, {} response shards",
            size,
            size as f64 / 1024.0,
            num_request_shards,
            response_shards.len()
        );
    }

    println!("\nSUCCESS: All variable size tests passed!");
}

#[tokio::test]
async fn test_http_request_serialization() {
    // Test HttpRequest serialization round-trip with various configurations

    // Simple GET request
    let request = HttpRequest {
        method: "GET".to_string(),
        url: "https://example.com/api/data".to_string(),
        headers: HashMap::new(),
        body: None,
    };
    let bytes = request.to_bytes();
    let parsed = HttpRequest::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.method, "GET");
    assert_eq!(parsed.url, "https://example.com/api/data");
    assert!(parsed.body.is_none());

    // POST request with headers and body
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    headers.insert("Authorization".to_string(), "Bearer token123".to_string());

    let body = b"{\"key\": \"value\", \"number\": 42}".to_vec();
    let request = HttpRequest {
        method: "POST".to_string(),
        url: "https://api.example.com/submit".to_string(),
        headers,
        body: Some(body.clone()),
    };
    let bytes = request.to_bytes();
    let parsed = HttpRequest::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.method, "POST");
    assert_eq!(parsed.url, "https://api.example.com/submit");
    assert_eq!(parsed.headers.len(), 2);
    assert_eq!(parsed.body.unwrap(), body);

    // HttpResponse serialization round-trip
    let mut resp_headers = HashMap::new();
    resp_headers.insert("Content-Type".to_string(), "text/html".to_string());
    let response = HttpResponse::new(200, resp_headers, b"<html>OK</html>".to_vec());
    let bytes = response.to_bytes();
    let parsed = HttpResponse::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.status, 200);
    assert_eq!(
        parsed.headers.get("Content-Type").unwrap(),
        "text/html"
    );
    assert_eq!(parsed.body, b"<html>OK</html>");

    // Empty body response
    let response = HttpResponse::new(204, HashMap::new(), Vec::new());
    let bytes = response.to_bytes();
    let parsed = HttpResponse::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.status, 204);
    assert!(parsed.body.is_empty());

    // Large body round-trip
    let large_body = vec![0xAB; 50 * 1024];
    let response = HttpResponse::new(200, HashMap::new(), large_body.clone());
    let bytes = response.to_bytes();
    let parsed = HttpResponse::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.body, large_body);

    println!("SUCCESS: All HTTP serialization round-trip tests passed!");
}

// =============================================================================
// TCP ECHO SERVER (for tunnel mode tests)
// =============================================================================

/// Start a TCP echo server that echoes back all received bytes
async fn start_tcp_echo_server() -> (SocketAddr, oneshot::Sender<()>) {
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let mut shutdown = shutdown_rx;
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    if let Ok((mut stream, _)) = accepted {
                        tokio::spawn(async move {
                            let mut buf = [0u8; 8192];
                            loop {
                                match stream.read(&mut buf).await {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        if stream.write_all(&buf[..n]).await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        });
                    }
                }
                _ = &mut shutdown => break,
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, shutdown_tx)
}

// =============================================================================
// TUNNEL MODE (SOCKS5/TCP) E2E TESTS
// =============================================================================

/// Direct tunnel mode: client builds tunnel shards → exit opens TCP to echo server → response back.
///
/// Verifies the full tunnel/socket pipeline:
/// - build_tunnel_shards() produces valid mode=0x01 shards
/// - Exit decrypts ExitPayload and dispatches to TunnelHandler
/// - TunnelHandler connects to destination, writes tcp_data, reads response
/// - Exit creates response shards from raw TCP bytes
/// - Client decrypts response and gets echoed bytes back
#[tokio::test]
async fn test_tunnel_mode_direct_echo() {
    let (echo_addr, _shutdown) = start_tcp_echo_server().await;

    // Create keypairs
    let client_signing = SigningKeypair::generate();
    let client_enc = EncryptionKeypair::generate();
    let client_enc_pubkey = client_enc.public_key_bytes();
    let client_enc_secret = client_enc.secret_key_bytes();

    let exit_signing = SigningKeypair::generate();
    let exit_enc = EncryptionKeypair::generate();
    let exit_enc_pubkey = exit_enc.public_key_bytes();

    let exit_hop = PathHop {
        peer_id: b"exit_peer".to_vec(),
        signing_pubkey: exit_signing.public_key_bytes(),
        encryption_pubkey: exit_enc_pubkey,
    };

    let mut exit_handler = ExitHandler::with_keypairs(
        test_exit_config(),
        exit_signing,
        exit_enc,
    ).unwrap();

    let lease_set = LeaseSet {
        session_id: [0u8; 32],
        leases: vec![],
    };

    // Build tunnel metadata pointing to echo server
    let metadata = TunnelMetadata {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
        session_id: [42u8; 32],
        is_close: false,
    };

    let tcp_data = b"Hello from TunnelCraft socket mode!";

    // Build tunnel-mode shards (mode 0x01)
    let (_request_id, shards) = build_tunnel_shards(
        &metadata,
        tcp_data,
        &client_signing,
        &exit_hop,
        &[],  // direct mode
        &lease_set,
        client_enc_pubkey,
        [0u8; 32],
    ).unwrap();

    assert_eq!(shards.len(), TOTAL_SHARDS);
    for shard in &shards {
        assert!(shard.header.is_empty(), "Direct mode: empty headers");
        assert_eq!(shard.total_hops, 0);
    }

    // Feed shards to exit
    let mut response_shards = None;
    for shard in shards {
        let result = exit_handler.process_shard(shard).await
            .expect("Exit should process tunnel shard");
        if let Some(shard_pairs) = result {
            let resp: Vec<_> = shard_pairs.into_iter().map(|(s, _)| s).collect();
            response_shards = Some(resp);
        }
    }

    let response_shards = response_shards.expect("Exit should produce response shards");
    assert!(!response_shards.is_empty());

    // Decrypt response
    let response_data = decrypt_response_shards(
        &response_shards,
        &exit_enc_pubkey,
        &client_enc_secret,
    );

    // Tunnel mode response is raw TCP bytes (not HttpResponse)
    assert_eq!(
        response_data, tcp_data,
        "Echoed bytes should match sent bytes"
    );

    println!(
        "SUCCESS: Tunnel mode direct echo — sent {} bytes, received {} bytes",
        tcp_data.len(), response_data.len()
    );
}

/// Tunnel mode with relay hop: client → relay → exit → echo server → response back.
///
/// Verifies tunnel shards work through the onion relay chain.
#[tokio::test]
async fn test_tunnel_mode_with_relay() {
    let (echo_addr, _shutdown) = start_tcp_echo_server().await;

    // Create keypairs
    let client_signing = SigningKeypair::generate();
    let client_enc = EncryptionKeypair::generate();
    let client_enc_pubkey = client_enc.public_key_bytes();
    let client_enc_secret = client_enc.secret_key_bytes();

    let relay_signing = SigningKeypair::generate();
    let relay_enc = EncryptionKeypair::generate();

    let exit_signing = SigningKeypair::generate();
    let exit_enc = EncryptionKeypair::generate();
    let exit_enc_pubkey = exit_enc.public_key_bytes();

    let relay_handler = RelayHandler::new(relay_signing.clone(), relay_enc.clone());

    let mut exit_handler = ExitHandler::with_keypairs(
        test_exit_config(),
        exit_signing.clone(),
        exit_enc.clone(),
    ).unwrap();

    let exit_hop = PathHop {
        peer_id: b"exit_peer".to_vec(),
        signing_pubkey: exit_signing.public_key_bytes(),
        encryption_pubkey: exit_enc_pubkey,
    };

    let relay_hop = PathHop {
        peer_id: b"relay_peer".to_vec(),
        signing_pubkey: relay_signing.public_key_bytes(),
        encryption_pubkey: relay_enc.public_key_bytes(),
    };

    let onion_path = OnionPath {
        hops: vec![relay_hop],
        exit: exit_hop.clone(),
    };

    let lease_set = LeaseSet {
        session_id: [0u8; 32],
        leases: vec![],
    };

    let metadata = TunnelMetadata {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
        session_id: [99u8; 32],
        is_close: false,
    };

    let tcp_data = b"TCP tunnel through relay!";

    // Build tunnel shards with 1 relay hop
    let (_request_id, shards) = build_tunnel_shards(
        &metadata,
        tcp_data,
        &client_signing,
        &exit_hop,
        &[onion_path],
        &lease_set,
        client_enc_pubkey,
        [0u8; 32],
    ).unwrap();

    // All shards should have non-empty headers (1 relay hop)
    for shard in &shards {
        assert!(!shard.header.is_empty(), "Relay-hop shards need onion headers");
        assert_eq!(shard.total_hops, 1);
        assert_eq!(shard.hops_remaining, 1);
    }

    // Relay peels each shard
    let sender_pubkey = client_signing.public_key_bytes();
    let mut exit_bound_shards = Vec::new();
    for shard in shards {
        let (modified, next_peer, _receipt, _) = relay_handler
            .handle_shard(shard, sender_pubkey)
            .expect("Relay should peel tunnel shard");
        assert_eq!(next_peer, b"exit_peer");
        assert!(modified.header.is_empty(), "Terminal layer: empty header");
        exit_bound_shards.push(modified);
    }

    // Feed peeled shards to exit
    let mut response_shards = None;
    for shard in exit_bound_shards {
        let result = exit_handler.process_shard(shard).await
            .expect("Exit should process tunnel shard");
        if let Some(shard_pairs) = result {
            let resp: Vec<_> = shard_pairs.into_iter().map(|(s, _)| s).collect();
            response_shards = Some(resp);
        }
    }

    let response_shards = response_shards.expect("Exit should produce response shards");

    let response_data = decrypt_response_shards(
        &response_shards,
        &exit_enc_pubkey,
        &client_enc_secret,
    );

    assert_eq!(response_data, tcp_data, "Echoed bytes should match");

    println!(
        "SUCCESS: Tunnel mode with relay — {} bytes through onion relay chain",
        response_data.len()
    );
}

/// Tunnel mode large payload: verify multi-chunk tunnel data works.
#[tokio::test]
async fn test_tunnel_mode_large_payload() {
    let (echo_addr, _shutdown) = start_tcp_echo_server().await;

    let client_signing = SigningKeypair::generate();
    let client_enc = EncryptionKeypair::generate();
    let client_enc_pubkey = client_enc.public_key_bytes();
    let client_enc_secret = client_enc.secret_key_bytes();

    let exit_signing = SigningKeypair::generate();
    let exit_enc = EncryptionKeypair::generate();
    let exit_enc_pubkey = exit_enc.public_key_bytes();

    let exit_hop = PathHop {
        peer_id: b"exit_peer".to_vec(),
        signing_pubkey: exit_signing.public_key_bytes(),
        encryption_pubkey: exit_enc_pubkey,
    };

    let mut exit_handler = ExitHandler::with_keypairs(
        test_exit_config(),
        exit_signing,
        exit_enc,
    ).unwrap();

    let lease_set = LeaseSet {
        session_id: [0u8; 32],
        leases: vec![],
    };

    let metadata = TunnelMetadata {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
        session_id: [77u8; 32],
        is_close: false,
    };

    // 10KB payload — will require multiple erasure chunks
    let tcp_data: Vec<u8> = (0..10240).map(|i| (i % 256) as u8).collect();

    let (_request_id, shards) = build_tunnel_shards(
        &metadata,
        &tcp_data,
        &client_signing,
        &exit_hop,
        &[],
        &lease_set,
        client_enc_pubkey,
        [0u8; 32],
    ).unwrap();

    // Should have more than TOTAL_SHARDS (multiple chunks)
    assert!(
        shards.len() >= TOTAL_SHARDS,
        "Large payload should produce at least {} shards, got {}",
        TOTAL_SHARDS, shards.len()
    );
    println!("Large tunnel payload: {} shards from {} bytes", shards.len(), tcp_data.len());

    let mut response_shards = None;
    for shard in shards {
        let result = exit_handler.process_shard(shard).await
            .expect("Exit should process tunnel shard");
        if let Some(shard_pairs) = result {
            let resp: Vec<_> = shard_pairs.into_iter().map(|(s, _)| s).collect();
            response_shards = Some(resp);
        }
    }

    let response_shards = response_shards.expect("Exit should produce response shards");

    let response_data = decrypt_response_shards(
        &response_shards,
        &exit_enc_pubkey,
        &client_enc_secret,
    );

    assert_eq!(response_data, tcp_data, "Large echoed payload should match");

    println!(
        "SUCCESS: Tunnel mode large payload — {} bytes echoed through tunnel",
        response_data.len()
    );
}

/// Tunnel mode close signal: verify session teardown produces empty response.
#[tokio::test]
async fn test_tunnel_mode_close_signal() {
    let (echo_addr, _shutdown) = start_tcp_echo_server().await;

    let client_signing = SigningKeypair::generate();
    let client_enc = EncryptionKeypair::generate();
    let client_enc_pubkey = client_enc.public_key_bytes();

    let exit_signing = SigningKeypair::generate();
    let exit_enc = EncryptionKeypair::generate();

    let exit_hop = PathHop {
        peer_id: b"exit_peer".to_vec(),
        signing_pubkey: exit_signing.public_key_bytes(),
        encryption_pubkey: exit_enc.public_key_bytes(),
    };

    let mut exit_handler = ExitHandler::with_keypairs(
        test_exit_config(),
        exit_signing,
        exit_enc,
    ).unwrap();

    let lease_set = LeaseSet {
        session_id: [0u8; 32],
        leases: vec![],
    };

    let session_id = [55u8; 32];

    // First: establish session with some data
    let metadata_open = TunnelMetadata {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
        session_id,
        is_close: false,
    };

    let (_req_id, shards) = build_tunnel_shards(
        &metadata_open,
        b"init",
        &client_signing,
        &exit_hop,
        &[],
        &lease_set,
        client_enc_pubkey,
        [0u8; 32],
    ).unwrap();

    for shard in shards {
        let _ = exit_handler.process_shard(shard).await;
    }

    assert_eq!(exit_handler.tunnel_session_count(), 1, "Session should be open");

    // Now: send close signal
    let metadata_close = TunnelMetadata {
        host: echo_addr.ip().to_string(),
        port: echo_addr.port(),
        session_id,
        is_close: true,
    };

    let (_req_id, close_shards) = build_tunnel_shards(
        &metadata_close,
        &[],
        &client_signing,
        &exit_hop,
        &[],
        &lease_set,
        client_enc_pubkey,
        [0u8; 32],
    ).unwrap();

    let mut close_response = None;
    for shard in close_shards {
        let result = exit_handler.process_shard(shard).await
            .expect("Exit should process close shard");
        if let Some(pairs) = result {
            close_response = Some(pairs);
        }
    }

    // Close signal returns empty response shards vec
    let close_response = close_response.expect("Should get response for close");
    assert!(close_response.is_empty(), "Close signal should produce empty response");

    assert_eq!(exit_handler.tunnel_session_count(), 0, "Session should be closed");

    println!("SUCCESS: Tunnel mode close signal — session opened and closed cleanly");
}
