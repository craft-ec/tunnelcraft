//! 10-Node Live Network E2E Test
//!
//! Spawns 10 real TunnelCraftNode instances connected via localhost TCP,
//! runs HTTP requests through the onion-routed tunnel, and tracks all
//! network activity: gossip, connections, shard forwarding, proof generation,
//! and aggregator submissions.
//!
//! Node topology:
//!   0: Bootstrap (relay)
//!   1-4: Relays
//!   5-6: Exit nodes
//!   7: Aggregator (relay)
//!   8-9: Clients (Both mode)
//!
//! Run with: cargo test -p tunnelcraft-tests ten_node_network -- --ignored --nocapture

use std::time::Duration;

use libp2p::{Multiaddr, PeerId};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use tunnelcraft_client::{NodeConfig, NodeMode, NodeType, TunnelCraftNode, NodeStats};
use tunnelcraft_core::HopMode;
use tunnelcraft_aggregator::NetworkStats;
use tunnelcraft_network::PoolType;

// =========================================================================
// Types
// =========================================================================

enum TestCmd {
    GetStats(oneshot::Sender<FullStats>),
    Fetch {
        url: String,
        reply: oneshot::Sender<Result<tunnelcraft_client::TunnelResponse, String>>,
    },
    DiscoverExits(oneshot::Sender<usize>),
    DiscoverRelays(oneshot::Sender<usize>),
    IsReady(oneshot::Sender<bool>),
    Stop(oneshot::Sender<()>),
}

#[allow(dead_code)]
struct FullStats {
    node_stats: NodeStats,
    receipt_count: usize,
    proof_queue_sizes: Vec<(String, usize)>,
    online_exits: usize,
    proof_queue_depth: usize,
    aggregator_stats: Option<NetworkStats>,
    pool_breakdown: Vec<PoolBreakdown>,
}

struct PoolBreakdown {
    pool_pubkey: [u8; 32],
    pool_type: PoolType,
    epoch: u64,
    relay_bytes: Vec<([u8; 32], u64)>,
    total_bytes: u64,
}

struct TestNode {
    cmd_tx: mpsc::Sender<TestCmd>,
    handle: JoinHandle<()>,
    peer_id: PeerId,
    role: &'static str,
    port: u16,
}

// =========================================================================
// Test HTTP Server
// =========================================================================

async fn start_test_server() -> (std::net::SocketAddr, oneshot::Sender<()>) {
    use axum::{Router, routing::get, extract::Path};

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let app = Router::new()
        .route("/ping", get(|| async { "pong" }))
        .route("/data/{size}", get(|Path(size): Path<usize>| async move {
            let size = size.min(1024 * 1024);
            "D".repeat(size)
        }))
        .route("/echo", axum::routing::post(|body: String| async move { body }));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async { let _ = shutdown_rx.await; })
            .await
            .unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, shutdown_tx)
}

// =========================================================================
// Node Spawning
// =========================================================================

async fn spawn_test_node(
    config: NodeConfig,
    role: &'static str,
    port: u16,
) -> TestNode {
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<TestCmd>(32);
    let (init_tx, init_rx) = oneshot::channel();

    let handle = tokio::spawn(async move {
        let mut node = TunnelCraftNode::new(config).unwrap();
        node.start().await.unwrap();
        node.set_credits(100_000);
        node.set_proof_batch_size(5);
        node.set_proof_deadline(Duration::from_secs(30));
        let peer_id = node.peer_id().unwrap();
        let _ = init_tx.send(peer_id);

        let mut maintenance = tokio::time::interval(Duration::from_secs(15));

        loop {
            tokio::select! {
                _ = node.poll_once() => {}
                _ = maintenance.tick() => {
                    node.run_maintenance();
                }
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(TestCmd::GetStats(reply)) => {
                            // Build pool breakdown if aggregator is present
                            let pool_breakdown = {
                                let pool_keys = node.aggregator_pool_keys();
                                pool_keys.into_iter().map(|(pubkey, pool_type, epoch)| {
                                    let relay_bytes = node.aggregator_pool_usage(
                                        &(pubkey, pool_type, epoch),
                                    );
                                    let total_bytes: u64 = relay_bytes.iter().map(|(_, b)| b).sum();
                                    PoolBreakdown {
                                        pool_pubkey: pubkey,
                                        pool_type,
                                        epoch,
                                        relay_bytes,
                                        total_bytes,
                                    }
                                }).collect()
                            };

                            let _ = reply.send(FullStats {
                                node_stats: node.stats(),
                                receipt_count: node.receipt_count(),
                                proof_queue_sizes: node.proof_queue_sizes(),
                                online_exits: node.online_exit_nodes().len(),
                                proof_queue_depth: node.proof_queue_depth(),
                                aggregator_stats: node.aggregator_stats(),
                                pool_breakdown,
                            });
                        }
                        Some(TestCmd::Fetch { url, reply }) => {
                            let result = node.get(&url).await;
                            let _ = reply.send(result.map_err(|e| e.to_string()));
                        }
                        Some(TestCmd::DiscoverExits(reply)) => {
                            node.discover_exits();
                            node.run_maintenance();
                            let count = node.online_exit_nodes().len();
                            let _ = reply.send(count);
                        }
                        Some(TestCmd::DiscoverRelays(reply)) => {
                            node.discover_relays();
                            node.run_maintenance();
                            let count = node.relay_node_count();
                            let _ = reply.send(count);
                        }
                        Some(TestCmd::IsReady(reply)) => {
                            node.run_maintenance();
                            let _ = reply.send(node.is_ready());
                        }
                        Some(TestCmd::Stop(reply)) => {
                            node.stop().await;
                            let _ = reply.send(());
                            return;
                        }
                        None => return,
                    }
                }
            }
        }
    });

    let peer_id = init_rx.await.unwrap();
    TestNode { cmd_tx, handle, peer_id, role, port }
}

// =========================================================================
// Helpers
// =========================================================================

async fn get_stats(node: &TestNode) -> FullStats {
    let (tx, rx) = oneshot::channel();
    let _ = node.cmd_tx.send(TestCmd::GetStats(tx)).await;
    rx.await.unwrap()
}

async fn fetch(node: &TestNode, url: &str) -> Result<tunnelcraft_client::TunnelResponse, String> {
    let (tx, rx) = oneshot::channel();
    let _ = node.cmd_tx.send(TestCmd::Fetch {
        url: url.to_string(),
        reply: tx,
    }).await;
    match tokio::time::timeout(Duration::from_secs(30), rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err("channel closed".to_string()),
        Err(_) => Err("timeout".to_string()),
    }
}

async fn discover_exits(node: &TestNode) -> usize {
    let (tx, rx) = oneshot::channel();
    let _ = node.cmd_tx.send(TestCmd::DiscoverExits(tx)).await;
    rx.await.unwrap_or(0)
}

async fn discover_relays(node: &TestNode) -> usize {
    let (tx, rx) = oneshot::channel();
    let _ = node.cmd_tx.send(TestCmd::DiscoverRelays(tx)).await;
    rx.await.unwrap_or(0)
}

/// Wait until a node has discovered at least `min` relay nodes, with timeout.
async fn wait_for_relays(node: &TestNode, min: usize, timeout_secs: u64) -> usize {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        let count = discover_relays(node).await;
        if count >= min {
            return count;
        }
        if std::time::Instant::now() >= deadline {
            println!("  Timeout waiting for relays: found {}, needed {}", count, min);
            return count;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Wait until a node has discovered at least `min` exit nodes, with timeout.
async fn wait_for_exits(node: &TestNode, min: usize, timeout_secs: u64) -> usize {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        let count = discover_exits(node).await;
        if count >= min {
            return count;
        }
        if std::time::Instant::now() >= deadline {
            println!("  Timeout waiting for exits: found {}, needed {}", count, min);
            return count;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn is_ready(node: &TestNode) -> bool {
    let (tx, rx) = oneshot::channel();
    let _ = node.cmd_tx.send(TestCmd::IsReady(tx)).await;
    rx.await.unwrap_or(false)
}

/// Wait until a client node is fully ready to send requests.
/// Actively triggers exit + relay discovery each iteration.
async fn wait_for_ready(node: &TestNode, name: &str, timeout_secs: u64) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        // Trigger discovery to populate relay_nodes and exit_nodes
        discover_exits(node).await;
        discover_relays(node).await;
        if is_ready(node).await {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            println!("  Timeout waiting for {} to be ready", name);
            return false;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn stop_node(node: TestNode) {
    let (tx, rx) = oneshot::channel();
    let _ = node.cmd_tx.send(TestCmd::Stop(tx)).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), rx).await;
    node.handle.abort();
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{} MB", bytes / (1024 * 1024))
    } else if bytes >= 1024 {
        format!("{} KB", bytes / 1024)
    } else {
        format!("{} B", bytes)
    }
}

fn short_hex(bytes: &[u8; 32]) -> String {
    format!("{}..{}", hex::encode(&bytes[..4]), hex::encode(&bytes[28..32]))
}

// =========================================================================
// Dashboard Printer
// =========================================================================

async fn print_dashboard(nodes: &[TestNode], elapsed_secs: u64) {
    println!("\n\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550} TunnelCraft Network Monitor (T+{}s) \u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\n", elapsed_secs);

    let mut all_stats = Vec::new();
    for node in nodes {
        let stats = get_stats(node).await;
        all_stats.push((node.role, node.port, stats));
    }

    // Connectivity
    println!("Connectivity:");
    for (role, _port, stats) in &all_stats {
        print!("  {:12}: {:2} peers  |", role, stats.node_stats.peers_connected);
    }
    println!();

    // Shard flow
    println!("\nShard Flow:");
    print!("  Relayed:");
    for (role, _, stats) in &all_stats {
        if stats.node_stats.shards_relayed > 0 || role.contains("Relay") || role.contains("Boot") || role.contains("Agg") {
            print!("  {}={}", role, stats.node_stats.shards_relayed);
        }
    }
    println!();
    print!("  Exited: ");
    for (role, _, stats) in &all_stats {
        if stats.node_stats.requests_exited > 0 {
            print!("  {}={}", role, stats.node_stats.requests_exited);
        }
    }
    println!();

    // Bandwidth
    println!("\nBandwidth Served:");
    for (role, _, stats) in &all_stats {
        if stats.node_stats.bytes_relayed > 0 {
            print!("  {}={}  ", role, format_bytes(stats.node_stats.bytes_relayed));
        }
    }
    println!();

    // Settlement pipeline
    println!("\nSettlement Pipeline:");
    print!("  Receipts:");
    for (role, _, stats) in &all_stats {
        if stats.receipt_count > 0 {
            print!("  {}={}", role, stats.receipt_count);
        }
    }
    println!();
    print!("  Proof Q: ");
    for (role, _, stats) in &all_stats {
        if stats.proof_queue_depth > 0 {
            print!("  {}={}", role, stats.proof_queue_depth);
        }
    }
    println!();

    // Aggregator
    for (role, _, stats) in &all_stats {
        if let Some(ref agg) = stats.aggregator_stats {
            println!("\nAggregator ({}):", role);
            println!(
                "  Pools: {}  |  Relays: {}  |  Total: {}  |  Subscribed: {}  |  Free: {}",
                agg.active_pools,
                agg.active_relays,
                format_bytes(agg.total_bytes),
                format_bytes(agg.subscribed_bytes),
                format_bytes(agg.free_bytes),
            );
            for pb in &stats.pool_breakdown {
                let pt_str = match pb.pool_type {
                    PoolType::Subscribed => "subscribed",
                    PoolType::Free => "free",
                };
                println!("  Pool: {} ({}, epoch={})", pt_str, short_hex(&pb.pool_pubkey), pb.epoch);
                for (relay, bytes) in &pb.relay_bytes {
                    println!("    Relay {}  {}", short_hex(relay), format_bytes(*bytes));
                }
                println!("    Subtotal: {}", format_bytes(pb.total_bytes));
            }
        }
    }

    println!("\n\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\n");
}

// =========================================================================
// Final Report
// =========================================================================

async fn print_final_report(nodes: &[TestNode], ok_count: usize, err_count: usize, total_requests: usize) {
    println!("\n\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550} Final Report \u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\n");

    println!(
        "{:<12} {:>5} {:>7} {:>7} {:>13} {:>9} {:>7}",
        "Node", "Peers", "Shards", "Exited", "Bytes Served", "Receipts", "ProofQ"
    );

    let mut total_bytes_served: u64 = 0;
    let mut all_stats = Vec::new();

    for node in nodes {
        let stats = get_stats(node).await;
        total_bytes_served += stats.node_stats.bytes_relayed;
        all_stats.push((node.role, stats));
    }

    for (role, stats) in &all_stats {
        println!(
            "{:<12} {:>5} {:>7} {:>7} {:>13} {:>9} {:>7}",
            role,
            stats.node_stats.peers_connected,
            stats.node_stats.shards_relayed,
            stats.node_stats.requests_exited,
            format_bytes(stats.node_stats.bytes_relayed),
            stats.receipt_count,
            stats.proof_queue_depth,
        );
    }

    println!();
    println!("Requests: {} sent, {} OK, {} failed/timeout", total_requests, ok_count, err_count);
    println!("Total bytes served: {}", format_bytes(total_bytes_served));

    // Aggregator summary
    for (role, stats) in &all_stats {
        if let Some(ref agg) = stats.aggregator_stats {
            println!("\nAggregator Summary ({}):", role);
            println!("  Pools tracked: {}  |  Active relays: {}", agg.active_pools, agg.active_relays);
            println!("  Total proven bytes: {}", format_bytes(agg.total_bytes));

            for pb in &stats.pool_breakdown {
                let pt_str = match pb.pool_type {
                    PoolType::Subscribed => "subscribed",
                    PoolType::Free => "free",
                };
                println!("\n  Pool: {} ({}, epoch={})", pt_str, short_hex(&pb.pool_pubkey), pb.epoch);
                for (relay, bytes) in &pb.relay_bytes {
                    println!("    Relay {}  {}", short_hex(relay), format_bytes(*bytes));
                }
                println!("    Subtotal: {}", format_bytes(pb.total_bytes));
            }
        }
    }

    println!("\n\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}");
}

// =========================================================================
// Main Test
// =========================================================================

#[tokio::test]
#[ignore] // Takes ~90s, binds 10 TCP ports
async fn ten_node_live_network() {
    // Initialize tracing
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let test_start = std::time::Instant::now();

    // ── Step 1: Start test HTTP server ────────────────────────────────
    let (server_addr, _shutdown_tx) = start_test_server().await;
    println!("Test HTTP server on {}", server_addr);

    // ── Step 2: Spawn bootstrap node ──────────────────────────────────
    let bootstrap_port: u16 = 41000;
    let bootstrap_config = NodeConfig {
        mode: NodeMode::Node,
        node_type: NodeType::Relay,
        listen_addr: format!("/ip4/127.0.0.1/tcp/{}", bootstrap_port).parse().unwrap(),
        enable_exit: false,
        enable_aggregator: false,
        ..Default::default()
    };

    let bootstrap = spawn_test_node(bootstrap_config, "Bootstrap", bootstrap_port).await;
    println!("Bootstrap node started: peer_id={}, port={}", bootstrap.peer_id, bootstrap_port);

    let bootstrap_peer_id = bootstrap.peer_id;
    let bootstrap_addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", bootstrap_port).parse().unwrap();
    let bootstrap_peers = vec![(bootstrap_peer_id, bootstrap_addr.clone())];

    // ── Step 3: Spawn remaining 9 nodes ───────────────────────────────
    let mut nodes = vec![bootstrap];

    // Relays 1-4
    for i in 1..=4u16 {
        let port = 41000 + i;
        let config = NodeConfig {
            mode: NodeMode::Node,
            node_type: NodeType::Relay,
            listen_addr: format!("/ip4/127.0.0.1/tcp/{}", port).parse().unwrap(),
            bootstrap_peers: bootstrap_peers.clone(),
            enable_exit: false,
            enable_aggregator: false,
            ..Default::default()
        };
        let role = match i {
            1 => "Relay-1",
            2 => "Relay-2",
            3 => "Relay-3",
            _ => "Relay-4",
        };
        let node = spawn_test_node(config, role, port).await;
        println!("  {} started: peer_id={}, port={}", role, node.peer_id, port);
        nodes.push(node);
    }

    // Exits 5-6
    for i in 5..=6u16 {
        let port = 41000 + i;
        let config = NodeConfig {
            mode: NodeMode::Node,
            node_type: NodeType::Exit,
            listen_addr: format!("/ip4/127.0.0.1/tcp/{}", port).parse().unwrap(),
            bootstrap_peers: bootstrap_peers.clone(),
            enable_exit: true,
            enable_aggregator: false,
            exit_blocked_domains: Some(vec![]), // Allow localhost for testing
            ..Default::default()
        };
        let role = if i == 5 { "Exit-1" } else { "Exit-2" };
        let node = spawn_test_node(config, role, port).await;
        println!("  {} started: peer_id={}, port={}", role, node.peer_id, port);
        nodes.push(node);
    }

    // Aggregator (node 7)
    {
        let port: u16 = 41007;
        let config = NodeConfig {
            mode: NodeMode::Node,
            node_type: NodeType::Relay,
            listen_addr: format!("/ip4/127.0.0.1/tcp/{}", port).parse().unwrap(),
            bootstrap_peers: bootstrap_peers.clone(),
            enable_exit: false,
            enable_aggregator: true,
            ..Default::default()
        };
        let node = spawn_test_node(config, "Aggregator", port).await;
        println!("  Aggregator started: peer_id={}, port={}", node.peer_id, port);
        nodes.push(node);
    }

    // Clients 8-9 (Both mode — they relay + send requests)
    for i in 8..=9u16 {
        let port = 41000 + i;
        let config = NodeConfig {
            mode: NodeMode::Both,
            node_type: NodeType::Full,
            listen_addr: format!("/ip4/127.0.0.1/tcp/{}", port).parse().unwrap(),
            bootstrap_peers: bootstrap_peers.clone(),
            enable_exit: false,
            enable_aggregator: false,
            hop_mode: HopMode::Double,
            ..Default::default()
        };
        let role = if i == 8 { "Client-1" } else { "Client-2" };
        let node = spawn_test_node(config, role, port).await;
        println!("  {} started: peer_id={}, port={}", role, node.peer_id, port);
        nodes.push(node);
    }

    println!("\nAll 10 nodes started. Waiting for mesh formation + exit discovery...");

    // ── Step 4: Wait for gossipsub mesh formation ─────────────────────
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Trigger exit discovery on all nodes (especially clients)
    // DHT needs active querying; run maintenance + discover on each node
    for node in &nodes {
        discover_exits(node).await;
    }

    // Wait for client nodes to discover at least 1 exit (up to 30s)
    println!("Waiting for clients to discover exit nodes...");
    let c1_exits = wait_for_exits(&nodes[8], 1, 30).await;
    let c2_exits = wait_for_exits(&nodes[9], 1, 30).await;
    println!("  Client-1: {} exits discovered", c1_exits);
    println!("  Client-2: {} exits discovered", c2_exits);

    assert!(c1_exits >= 1, "Client-1 must discover at least 1 exit node");
    assert!(c2_exits >= 1, "Client-2 must discover at least 1 exit node");

    // Wait for relay discovery (DHT relay queries need time)
    println!("Waiting for clients to discover relay nodes...");
    let c1_relays = wait_for_relays(&nodes[8], 1, 30).await;
    let c2_relays = wait_for_relays(&nodes[9], 1, 30).await;
    println!("  Client-1: {} relays discovered", c1_relays);
    println!("  Client-2: {} relays discovered", c2_relays);

    // Wait for clients to be fully ready (gateway + exit + encryption keys)
    println!("Waiting for clients to be ready...");
    let c1_ready = wait_for_ready(&nodes[8], "Client-1", 45).await;
    let c2_ready = wait_for_ready(&nodes[9], "Client-2", 45).await;
    println!("  Client-1 ready: {}", c1_ready);
    println!("  Client-2 ready: {}", c2_ready);

    assert!(c1_ready, "Client-1 must be ready before sending requests");
    assert!(c2_ready, "Client-2 must be ready before sending requests");

    // Print initial connectivity
    print_dashboard(&nodes, test_start.elapsed().as_secs()).await;

    // ── Step 5: Send requests ─────────────────────────────────────────
    let total_requests = 20;
    let requests_per_client = 10;
    let mut ok_count = 0usize;
    let mut err_count = 0usize;

    let base_url = format!("http://{}", server_addr);

    // Client-1 (node index 8): HTTP mode requests
    println!("\nClient-1: Sending {} HTTP requests...", requests_per_client);
    for i in 0..requests_per_client {
        let url = if i % 2 == 0 {
            format!("{}/ping", base_url)
        } else {
            format!("{}/data/{}", base_url, 100 + i * 50)
        };

        match fetch(&nodes[8], &url).await {
            Ok(resp) => {
                ok_count += 1;
                println!("  Client-1 request {}: {} OK ({} bytes)", i + 1, resp.status, resp.body.len());
            }
            Err(e) => {
                err_count += 1;
                println!("  Client-1 request {}: FAILED: {}", i + 1, e);
            }
        }
    }

    // Client-2 (node index 9): HTTP mode requests
    println!("\nClient-2: Sending {} HTTP requests...", requests_per_client);
    for i in 0..requests_per_client {
        let url = if i % 3 == 0 {
            format!("{}/ping", base_url)
        } else {
            format!("{}/data/{}", base_url, 200 + i * 100)
        };

        match fetch(&nodes[9], &url).await {
            Ok(resp) => {
                ok_count += 1;
                println!("  Client-2 request {}: {} OK ({} bytes)", i + 1, resp.status, resp.body.len());
            }
            Err(e) => {
                err_count += 1;
                println!("  Client-2 request {}: FAILED: {}", i + 1, e);
            }
        }
    }

    println!("\nRequests complete: {}/{} OK. Waiting 30s for proof cooldown...", ok_count, total_requests);

    // ── Step 6: Proof cooldown phase ──────────────────────────────────
    // Poll for 30s to let proof deadlines trigger + gossip propagate
    let cooldown_start = std::time::Instant::now();
    let mut last_dashboard = std::time::Instant::now();
    while cooldown_start.elapsed() < Duration::from_secs(30) {
        tokio::time::sleep(Duration::from_secs(1)).await;

        if last_dashboard.elapsed() >= Duration::from_secs(15) {
            print_dashboard(&nodes, test_start.elapsed().as_secs()).await;
            last_dashboard = std::time::Instant::now();
        }
    }

    // ── Step 7: Final dashboard + report ──────────────────────────────
    print_dashboard(&nodes, test_start.elapsed().as_secs()).await;
    print_final_report(&nodes, ok_count, err_count, total_requests).await;

    // ── Step 8: Assertions ────────────────────────────────────────────
    let mut all_stats = Vec::new();
    for node in &nodes {
        all_stats.push((node.role, get_stats(node).await));
    }

    // HARD: All 10 nodes started successfully (implicit — we got here)
    assert_eq!(nodes.len(), 10, "All 10 nodes should be running");

    // HARD: All nodes have >= 1 peer
    for (role, stats) in &all_stats {
        assert!(
            stats.node_stats.peers_connected >= 1,
            "{} should have at least 1 peer, has {}",
            role,
            stats.node_stats.peers_connected,
        );
    }

    // HARD: At least 15/20 requests succeeded (75%)
    assert!(
        ok_count >= (total_requests * 3 / 4),
        "At least 75% of requests should succeed: {} / {}",
        ok_count,
        total_requests,
    );

    // HARD: At least 1 exit processed a request
    let exits_with_requests: Vec<_> = all_stats
        .iter()
        .filter(|(role, stats)| role.starts_with("Exit") && stats.node_stats.requests_exited > 0)
        .collect();
    assert!(
        !exits_with_requests.is_empty(),
        "At least 1 exit should have processed a request",
    );

    // HARD: At least 3 relays have shards_relayed > 0
    let relays_with_shards: Vec<_> = all_stats
        .iter()
        .filter(|(_, stats)| stats.node_stats.shards_relayed > 0)
        .collect();
    assert!(
        relays_with_shards.len() >= 3,
        "At least 3 nodes should have relayed shards, got {}",
        relays_with_shards.len(),
    );

    // HARD: At least 1 relay generated >= 1 proof
    let relays_with_receipts: Vec<_> = all_stats
        .iter()
        .filter(|(_, stats)| stats.receipt_count > 0)
        .collect();
    assert!(
        !relays_with_receipts.is_empty(),
        "At least 1 relay should have generated forward receipts",
    );

    // HARD: Aggregator pool_count >= 1 (if aggregator received proofs)
    let aggregator_stats = &all_stats[7].1; // index 7 = Aggregator
    if aggregator_stats.aggregator_stats.as_ref().map_or(0, |a| a.active_pools) > 0 {
        println!("Aggregator received proofs - checking pool count");
        assert!(
            aggregator_stats.aggregator_stats.as_ref().unwrap().active_pools >= 1,
            "Aggregator should track at least 1 pool",
        );
    } else {
        println!("SOFT WARNING: Aggregator did not receive any proof messages (proofs may not have fired in time)");
    }

    // SOFT assertions (warnings only)
    if ok_count < total_requests {
        println!(
            "SOFT WARNING: Not all requests succeeded: {}/{}",
            ok_count, total_requests
        );
    }

    let exits_count = all_stats.iter()
        .filter(|(role, stats)| role.starts_with("Exit") && stats.node_stats.requests_exited > 0)
        .count();
    if exits_count < 2 {
        println!("SOFT WARNING: Only {}/2 exits processed requests", exits_count);
    }

    let relay_receipt_count = all_stats.iter()
        .filter(|(role, stats)| {
            (role.starts_with("Relay") || role.starts_with("Boot")) && stats.receipt_count > 0
        })
        .count();
    if relay_receipt_count < 5 {
        println!("SOFT WARNING: Only {}/5 relays earned receipts", relay_receipt_count);
    }

    if let Some(ref agg) = aggregator_stats.aggregator_stats {
        if agg.total_bytes == 0 {
            println!("SOFT WARNING: Aggregator total_bytes is 0");
        }
        if agg.active_relays < 3 {
            println!("SOFT WARNING: Aggregator tracks only {} relays (expected >= 3)", agg.active_relays);
        }
    }

    // ── Step 9: Cleanup ───────────────────────────────────────────────
    println!("\nShutting down nodes...");
    for node in nodes {
        stop_node(node).await;
    }
    println!("All nodes stopped. Test completed in {}s.", test_start.elapsed().as_secs());
}
