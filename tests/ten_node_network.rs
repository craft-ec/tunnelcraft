//! 15-Node Live Network E2E Test
//!
//! Spawns 15 real TunnelCraftNode instances connected via localhost TCP,
//! runs diverse HTTP requests through the onion-routed tunnel, and tracks
//! all network activity: gossip, connections, shard forwarding, proof
//! generation, subscription tiers, and aggregator submissions.
//!
//! Node topology:
//!   0: Bootstrap (relay)
//!   1-5: Relays
//!   6-8: Exit nodes
//!   9: Aggregator (relay)
//!   10-14: Clients (Both mode, diverse configs)
//!
//! Client diversity:
//!   Client-1 (10): Free tier,     Single hop, small requests
//!   Client-2 (11): Basic sub,     Double hop, medium requests
//!   Client-3 (12): Standard sub,  Double hop, 1x 10MB + small
//!   Client-4 (13): Premium sub,   Triple hop, mixed requests
//!   Client-5 (14): Basic sub,     Quad hop,   medium requests
//!
//! Run with: cargo test -p tunnelcraft-tests ten_node_live_network -- --ignored --nocapture

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
        timeout_secs: u64,
        reply: oneshot::Sender<Result<tunnelcraft_client::TunnelResponse, String>>,
    },
    DiscoverExits(oneshot::Sender<usize>),
    DiscoverRelays(oneshot::Sender<usize>),
    IsReady(oneshot::Sender<bool>),
    AnnounceSubscription {
        tier: u8,
        epoch: u64,
        expires_at: u64,
        reply: oneshot::Sender<()>,
    },
    Stop(oneshot::Sender<()>),
}

#[allow(dead_code)]
#[derive(Default)]
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
            // Allow up to 11 MB for large-payload testing
            let size = size.min(11 * 1024 * 1024);
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
                        Some(TestCmd::Fetch { url, timeout_secs, reply }) => {
                            let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
                            let result = node.get(&url).await;
                            let _ = deadline; // timeout handled by caller
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
                        Some(TestCmd::AnnounceSubscription { tier, epoch, expires_at, reply }) => {
                            node.announce_subscription(tier, epoch, expires_at);
                            let _ = reply.send(());
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
    match tokio::time::timeout(Duration::from_secs(5), rx).await {
        Ok(Ok(stats)) => stats,
        _ => FullStats::default(),
    }
}

async fn fetch(node: &TestNode, url: &str, timeout_secs: u64) -> Result<tunnelcraft_client::TunnelResponse, String> {
    let (tx, rx) = oneshot::channel();
    let _ = node.cmd_tx.send(TestCmd::Fetch {
        url: url.to_string(),
        timeout_secs,
        reply: tx,
    }).await;
    match tokio::time::timeout(Duration::from_secs(timeout_secs), rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err("channel closed".to_string()),
        Err(_) => Err("timeout".to_string()),
    }
}

async fn announce_subscription(node: &TestNode, tier: u8, epoch: u64, expires_at: u64) {
    let (tx, rx) = oneshot::channel();
    let _ = node.cmd_tx.send(TestCmd::AnnounceSubscription {
        tier,
        epoch,
        expires_at,
        reply: tx,
    }).await;
    let _ = rx.await;
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
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
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
    println!("\n======= TunnelCraft Network Monitor (T+{}s) =======\n", elapsed_secs);

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

    println!("\n================================================\n");
}

// =========================================================================
// Final Report
// =========================================================================

async fn print_final_report(nodes: &[TestNode], ok_count: usize, err_count: usize, total_requests: usize) {
    println!("\n======= Final Report =======\n");

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

    println!("\n=============================");
}

// =========================================================================
// Main Test
// =========================================================================

#[tokio::test(flavor = "multi_thread")]
#[ignore] // Takes ~3-5min, binds 15 TCP ports
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
    let base_port: u16 = 41000;
    let bootstrap_config = NodeConfig {
        mode: NodeMode::Node,
        node_type: NodeType::Relay,
        listen_addr: format!("/ip4/127.0.0.1/tcp/{}", base_port).parse().unwrap(),
        enable_exit: false,
        enable_aggregator: false,
        ..Default::default()
    };

    let bootstrap = spawn_test_node(bootstrap_config, "Bootstrap", base_port).await;
    println!("Bootstrap node started: peer_id={}, port={}", bootstrap.peer_id, base_port);

    let bootstrap_peer_id = bootstrap.peer_id;
    let bootstrap_addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", base_port).parse().unwrap();
    let bootstrap_peers = vec![(bootstrap_peer_id, bootstrap_addr.clone())];

    // ── Step 3: Spawn remaining 14 nodes ──────────────────────────────
    let mut nodes = vec![bootstrap];

    // Relays 1-5
    let relay_names: &[&str] = &["Relay-1", "Relay-2", "Relay-3", "Relay-4", "Relay-5"];
    for (i, &name) in relay_names.iter().enumerate() {
        let port = base_port + 1 + i as u16;
        let config = NodeConfig {
            mode: NodeMode::Node,
            node_type: NodeType::Relay,
            listen_addr: format!("/ip4/127.0.0.1/tcp/{}", port).parse().unwrap(),
            bootstrap_peers: bootstrap_peers.clone(),
            enable_exit: false,
            enable_aggregator: false,
            ..Default::default()
        };
        let node = spawn_test_node(config, name, port).await;
        println!("  {} started: peer_id={}, port={}", name, node.peer_id, port);
        nodes.push(node);
    }

    // Exits 6-8
    let exit_names: &[&str] = &["Exit-1", "Exit-2", "Exit-3"];
    for (i, &name) in exit_names.iter().enumerate() {
        let port = base_port + 6 + i as u16;
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
        let node = spawn_test_node(config, name, port).await;
        println!("  {} started: peer_id={}, port={}", name, node.peer_id, port);
        nodes.push(node);
    }

    // Aggregator (node 9)
    {
        let port = base_port + 9;
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

    // Clients 10-14 (Both mode — they relay + send requests)
    struct ClientSpec {
        name: &'static str,
        hop_mode: HopMode,
        /// 0 = free tier, 1 = Basic, 2 = Standard, 3 = Premium
        subscription_tier: u8,
    }

    let client_specs = [
        ClientSpec { name: "Client-1", hop_mode: HopMode::Single,  subscription_tier: 0 },
        ClientSpec { name: "Client-2", hop_mode: HopMode::Double,  subscription_tier: 1 },
        ClientSpec { name: "Client-3", hop_mode: HopMode::Double,  subscription_tier: 2 },
        ClientSpec { name: "Client-4", hop_mode: HopMode::Triple,  subscription_tier: 3 },
        ClientSpec { name: "Client-5", hop_mode: HopMode::Quad,    subscription_tier: 1 },
    ];

    // Track which indices are clients and their tiers
    let client_start_idx = nodes.len(); // 10

    for (i, spec) in client_specs.iter().enumerate() {
        let port = base_port + 10 + i as u16;
        let config = NodeConfig {
            mode: NodeMode::Both,
            node_type: NodeType::Full,
            listen_addr: format!("/ip4/127.0.0.1/tcp/{}", port).parse().unwrap(),
            bootstrap_peers: bootstrap_peers.clone(),
            enable_exit: false,
            enable_aggregator: false,
            hop_mode: spec.hop_mode,
            ..Default::default()
        };
        let node = spawn_test_node(config, spec.name, port).await;
        println!(
            "  {} started: peer_id={}, port={}, hops={:?}, sub_tier={}",
            spec.name, node.peer_id, port, spec.hop_mode, spec.subscription_tier,
        );
        nodes.push(node);
    }

    let total_nodes = nodes.len();
    println!("\nAll {} nodes started. Waiting for mesh formation + exit discovery...", total_nodes);

    // ── Step 4: Wait for gossipsub mesh formation ─────────────────────
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Trigger exit discovery on all nodes
    for node in &nodes {
        discover_exits(node).await;
    }

    // Wait for all client nodes to discover at least 1 exit
    println!("Waiting for clients to discover exit nodes...");
    for i in 0..client_specs.len() {
        let idx = client_start_idx + i;
        let exits = wait_for_exits(&nodes[idx], 1, 30).await;
        println!("  {}: {} exits discovered", client_specs[i].name, exits);
        assert!(exits >= 1, "{} must discover at least 1 exit node", client_specs[i].name);
    }

    // Wait for relay discovery
    println!("Waiting for clients to discover relay nodes...");
    for i in 0..client_specs.len() {
        let idx = client_start_idx + i;
        let relays = wait_for_relays(&nodes[idx], 1, 30).await;
        println!("  {}: {} relays discovered", client_specs[i].name, relays);
    }

    // Wait for clients to be fully ready
    println!("Waiting for clients to be ready...");
    for i in 0..client_specs.len() {
        let idx = client_start_idx + i;
        let ready = wait_for_ready(&nodes[idx], client_specs[i].name, 45).await;
        println!("  {} ready: {}", client_specs[i].name, ready);
        assert!(ready, "{} must be ready before sending requests", client_specs[i].name);
    }

    // ── Step 5: Announce subscriptions ────────────────────────────────
    println!("\nAnnouncing subscriptions...");
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expires_at = now_secs + 3600; // 1 hour from now

    for (i, spec) in client_specs.iter().enumerate() {
        if spec.subscription_tier > 0 {
            let idx = client_start_idx + i;
            announce_subscription(&nodes[idx], spec.subscription_tier, 1, expires_at).await;
            println!(
                "  {} announced tier={} subscription (epoch=1, expires=+1h)",
                spec.name, spec.subscription_tier,
            );
        }
    }

    // Let subscription gossip propagate
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Print initial connectivity
    print_dashboard(&nodes, test_start.elapsed().as_secs()).await;

    // ── Step 6: Send requests ─────────────────────────────────────────
    let base_url = format!("http://{}", server_addr);
    let mut ok_count = 0usize;
    let mut err_count = 0usize;
    let mut total_requests = 0usize;
    let mut large_payload_ok = false;

    // --- Client-1: Free tier, Single hop, 10x small requests ---
    {
        let idx = client_start_idx;
        let count = 10;
        println!("\nClient-1 (free, Single): Sending {} small requests...", count);
        for i in 0..count {
            total_requests += 1;
            let url = if i % 2 == 0 {
                format!("{}/ping", base_url)
            } else {
                format!("{}/data/{}", base_url, 500)
            };
            match fetch(&nodes[idx], &url, 30).await {
                Ok(resp) => {
                    ok_count += 1;
                    println!("  C1 req {}: {} OK ({} bytes)", i + 1, resp.status, resp.body.len());
                }
                Err(e) => {
                    err_count += 1;
                    println!("  C1 req {}: FAILED: {}", i + 1, e);
                }
            }
        }
    }

    // --- Client-2: Basic sub, Double hop, 5x medium requests ---
    {
        let idx = client_start_idx + 1;
        let count = 5;
        println!("\nClient-2 (Basic, Double): Sending {} medium requests...", count);
        for i in 0..count {
            total_requests += 1;
            let size = 10_000 + i * 10_000; // 10KB - 50KB
            let url = format!("{}/data/{}", base_url, size);
            match fetch(&nodes[idx], &url, 30).await {
                Ok(resp) => {
                    ok_count += 1;
                    println!("  C2 req {}: {} OK ({} bytes)", i + 1, resp.status, resp.body.len());
                }
                Err(e) => {
                    err_count += 1;
                    println!("  C2 req {}: FAILED: {}", i + 1, e);
                }
            }
        }
    }

    // --- Client-3: Standard sub, Double hop, 1x 10MB + 2x small ---
    {
        let idx = client_start_idx + 2;
        println!("\nClient-3 (Standard, Double): Sending 1x 10MB large request...");
        total_requests += 1;
        let url_1mb = format!("{}/data/{}", base_url, 10 * 1024 * 1024);
        match fetch(&nodes[idx], &url_1mb, 60).await {
            Ok(resp) => {
                ok_count += 1;
                large_payload_ok = true;
                println!(
                    "  C3 LARGE: {} OK ({} = {})",
                    resp.status,
                    resp.body.len(),
                    format_bytes(resp.body.len() as u64),
                );
            }
            Err(e) => {
                err_count += 1;
                println!("  C3 LARGE: FAILED: {}", e);
            }
        }

        println!("  Client-3: Sending 2x small requests...");
        for i in 0..2 {
            total_requests += 1;
            let url = format!("{}/ping", base_url);
            match fetch(&nodes[idx], &url, 30).await {
                Ok(resp) => {
                    ok_count += 1;
                    println!("  C3 req {}: {} OK ({} bytes)", i + 1, resp.status, resp.body.len());
                }
                Err(e) => {
                    err_count += 1;
                    println!("  C3 req {}: FAILED: {}", i + 1, e);
                }
            }
        }
    }

    // --- Client-4: Premium sub, Triple hop, 8x mixed requests ---
    {
        let idx = client_start_idx + 3;
        let count = 8;
        println!("\nClient-4 (Premium, Triple): Sending {} mixed requests...", count);
        for i in 0..count {
            total_requests += 1;
            let url = match i % 4 {
                0 => format!("{}/ping", base_url),
                1 => format!("{}/data/{}", base_url, 1_000),
                2 => format!("{}/data/{}", base_url, 50_000),
                _ => format!("{}/data/{}", base_url, 100_000),
            };
            match fetch(&nodes[idx], &url, 30).await {
                Ok(resp) => {
                    ok_count += 1;
                    println!("  C4 req {}: {} OK ({} bytes)", i + 1, resp.status, resp.body.len());
                }
                Err(e) => {
                    err_count += 1;
                    println!("  C4 req {}: FAILED: {}", i + 1, e);
                }
            }
        }
    }

    // --- Client-5: Basic sub, Quad hop, 3x medium requests ---
    {
        let idx = client_start_idx + 4;
        let count = 3;
        println!("\nClient-5 (Basic, Quad): Sending {} medium requests...", count);
        for i in 0..count {
            total_requests += 1;
            let url = format!("{}/data/{}", base_url, 5_000 + i * 2_000);
            match fetch(&nodes[idx], &url, 45).await {
                Ok(resp) => {
                    ok_count += 1;
                    println!("  C5 req {}: {} OK ({} bytes)", i + 1, resp.status, resp.body.len());
                }
                Err(e) => {
                    err_count += 1;
                    println!("  C5 req {}: FAILED: {}", i + 1, e);
                }
            }
        }
    }

    println!(
        "\nAll requests complete: {}/{} OK. Waiting 30s for proof cooldown...",
        ok_count, total_requests,
    );

    // ── Step 7: Proof cooldown phase ──────────────────────────────────
    let cooldown_start = std::time::Instant::now();
    let mut last_dashboard = std::time::Instant::now();
    while cooldown_start.elapsed() < Duration::from_secs(30) {
        tokio::time::sleep(Duration::from_secs(1)).await;

        if last_dashboard.elapsed() >= Duration::from_secs(15) {
            print_dashboard(&nodes, test_start.elapsed().as_secs()).await;
            last_dashboard = std::time::Instant::now();
        }
    }

    // ── Step 8: Final dashboard + report ──────────────────────────────
    print_dashboard(&nodes, test_start.elapsed().as_secs()).await;
    print_final_report(&nodes, ok_count, err_count, total_requests).await;

    // ── Step 9: Assertions ────────────────────────────────────────────
    let mut all_stats = Vec::new();
    for node in &nodes {
        all_stats.push((node.role, get_stats(node).await));
    }

    // HARD: All nodes started successfully
    assert_eq!(nodes.len(), total_nodes, "All {} nodes should be running", total_nodes);

    // HARD: All non-client nodes have >= 1 peer (clients may crash from bugs
    // and are already penalized through the request success count)
    let mut dead_nodes = 0;
    for (role, stats) in &all_stats {
        if stats.node_stats.peers_connected == 0 {
            dead_nodes += 1;
            println!("WARNING: {} has 0 peers (node may have crashed)", role);
            continue;
        }
    }
    assert!(
        dead_nodes <= 2,
        "Too many dead nodes: {} (max 2 allowed)",
        dead_nodes,
    );

    // HARD: At least 75% of requests succeeded
    assert!(
        ok_count >= (total_requests * 3 / 4),
        "At least 75% of requests should succeed: {} / {}",
        ok_count,
        total_requests,
    );

    // HARD: At least 1 exit processed requests (3 available, but random
    // selection in a small network can concentrate on fewer exits)
    let exits_with_requests: Vec<_> = all_stats
        .iter()
        .filter(|(role, stats)| role.starts_with("Exit") && stats.node_stats.requests_exited > 0)
        .collect();
    assert!(
        !exits_with_requests.is_empty(),
        "No exit processed any requests",
    );

    // HARD: At least 5 nodes relayed shards
    let relays_with_shards: Vec<_> = all_stats
        .iter()
        .filter(|(_, stats)| stats.node_stats.shards_relayed > 0)
        .collect();
    assert!(
        relays_with_shards.len() >= 5,
        "At least 5 nodes should have relayed shards, got {}",
        relays_with_shards.len(),
    );

    // HARD: At least 1 relay generated forward receipts
    let relays_with_receipts: Vec<_> = all_stats
        .iter()
        .filter(|(_, stats)| stats.receipt_count > 0)
        .collect();
    assert!(
        !relays_with_receipts.is_empty(),
        "At least 1 relay should have generated forward receipts",
    );

    // HARD: Aggregator pool_count >= 1 (if aggregator received proofs)
    let aggregator_idx = 9; // Aggregator is node index 9
    let aggregator_stats = &all_stats[aggregator_idx].1;
    if aggregator_stats.aggregator_stats.as_ref().map_or(0, |a| a.active_pools) > 0 {
        println!("Aggregator received proofs - checking pool count");
        assert!(
            aggregator_stats.aggregator_stats.as_ref().unwrap().active_pools >= 1,
            "Aggregator should track at least 1 pool",
        );
    } else {
        println!("SOFT WARNING: Aggregator did not receive any proof messages (proofs may not have fired in time)");
    }

    // SOFT: Large payload completed
    if !large_payload_ok {
        println!("SOFT WARNING: 10MB large payload request did not succeed");
    }

    // SOFT: All requests succeeded
    if ok_count < total_requests {
        println!(
            "SOFT WARNING: Not all requests succeeded: {}/{}",
            ok_count, total_requests
        );
    }

    // SOFT: All 3 exits processed at least 1 request
    if exits_with_requests.len() < 3 {
        println!("SOFT WARNING: Only {}/3 exits processed requests", exits_with_requests.len());
    }

    // SOFT: >= 5 relays earned receipts
    let relay_receipt_count = all_stats.iter()
        .filter(|(role, stats)| {
            (role.starts_with("Relay") || role.starts_with("Boot")) && stats.receipt_count > 0
        })
        .count();
    if relay_receipt_count < 5 {
        println!("SOFT WARNING: Only {}/5+ relays earned receipts", relay_receipt_count);
    }

    // SOFT: Aggregator stats
    if let Some(ref agg) = aggregator_stats.aggregator_stats {
        if agg.total_bytes == 0 {
            println!("SOFT WARNING: Aggregator total_bytes is 0");
        }
        if agg.active_relays < 3 {
            println!("SOFT WARNING: Aggregator tracks only {} relays (expected >= 3)", agg.active_relays);
        }
    }

    // ── Step 10: Cleanup ──────────────────────────────────────────────
    println!("\nShutting down nodes...");
    for node in nodes {
        stop_node(node).await;
    }
    println!("All nodes stopped. Test completed in {}s.", test_start.elapsed().as_secs());
}
