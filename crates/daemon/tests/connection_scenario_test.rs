
//! Full connection scenario tests covering:
//!   1. Single-node relay announce — secsAgo becomes Some
//!   2. Two-node exit discovery — client sees exit node from DHT
//!   3. Two-node relay peer discovery

use craftnet_daemon::{ConnectParams, DaemonService};
use craftnet_client::{Capabilities, NodeConfig};
use std::time::Duration;
use tokio::time::timeout;

fn make_secret(seed: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = seed; s[1] = 0xCA; s[2] = 0xFE;
    s
}

async fn wait_for_tcp(addr: &str, retries: u32) -> bool {
    for i in 0..retries {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            eprintln!("[tcp] {} is listening (attempt {})", addr, i + 1);
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    eprintln!("[tcp] {} never became reachable", addr);
    false
}

// ── Test 1: Single-node relay announce ───────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn test_01_single_node_relay_announce() {
    let svc = DaemonService::new_with_keypair(&make_secret(1)).unwrap();
    svc.set_mode("relay").await.unwrap();
    svc.init_with_node_config(NodeConfig {
        capabilities: Capabilities::CLIENT | Capabilities::RELAY,
        listen_addr: "/ip4/127.0.0.1/tcp/44201".parse().unwrap(),
        bootstrap_peers: vec![],
        ..Default::default()
    }).await.unwrap();

    let found = timeout(Duration::from_secs(15), async {
        loop {
            let s = svc.status().await;
            eprintln!("[t01] relay_secs={:?}", s.relay_announced_secs_ago);
            if s.relay_announced_secs_ago.is_some() { return; }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }).await;
    assert!(found.is_ok(), "Timeout: relay_announced_secs_ago never became Some");
    eprintln!("[t01] PASS");
}

// ── Test 2: Two-node exit discovery ─────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn test_02_two_node_exit_discovery() {
    // ── Node A (exit) ──
    let svc_a = DaemonService::new_with_keypair(&make_secret(10)).unwrap();
    svc_a.set_mode("exit").await.unwrap();
    svc_a.init_with_node_config(NodeConfig {
        capabilities: Capabilities::CLIENT | Capabilities::EXIT,
        listen_addr: "/ip4/127.0.0.1/tcp/44210".parse().unwrap(),
        bootstrap_peers: vec![],
        ..Default::default()
    }).await.unwrap();

    // Wait for A to announce its exit and TCP listener to be ready
    let peer_id_a_str = timeout(Duration::from_secs(20), async {
        loop {
            let s = svc_a.status().await;
            eprintln!("[t02] A: state={:?} exit_secs={:?}", s.state, s.exit_announced_secs_ago);
            if s.exit_announced_secs_ago.is_some() {
                if let Some(id) = svc_a.local_peer_id_str().await { return id; }
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }).await.expect("Timeout: A never announced as exit");
    eprintln!("[t02] Node A peer_id={}", peer_id_a_str);

    // Make sure A's TCP listener is actually ready before B dials
    assert!(
        wait_for_tcp("127.0.0.1:44210", 20).await,
        "Node A TCP listener not ready"
    );

    let peer_id_a: libp2p::PeerId = peer_id_a_str.parse().unwrap();

    // ── Node B (client → A as bootstrap) ──
    let svc_b = DaemonService::new_with_keypair(&make_secret(20)).unwrap();
    svc_b.init_with_node_config(NodeConfig {
        capabilities: Capabilities::CLIENT,
        listen_addr: "/ip4/127.0.0.1/tcp/44211".parse().unwrap(),
        bootstrap_peers: vec![(peer_id_a, "/ip4/127.0.0.1/tcp/44210".parse().unwrap())],
        ..Default::default()
    }).await.unwrap();

    // Give B time to connect and bootstrap DHT
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Connect B (triggers wait_for_exit + discover_exits)
    let connect_result = svc_b.connect(ConnectParams { hops: None }).await;
    eprintln!("[t02] B connect result: {:?}", connect_result.is_ok());

    let exits = timeout(Duration::from_secs(30), async {
        loop {
            let avail = svc_b.get_available_exits().await;
            eprintln!("[t02] B exits={}", avail.len());
            if !avail.is_empty() { return avail; }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }).await.expect("Timeout: B never discovered A as exit");

    assert!(!exits.is_empty(), "No exits found by B");
    eprintln!("[t02] PASS: {} exit(s)", exits.len());
}

// ── Test 3: Two-node relay peer discovery ────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn test_03_two_node_relay_discovery() {
    let svc_relay = DaemonService::new_with_keypair(&make_secret(30)).unwrap();
    svc_relay.set_mode("relay").await.unwrap();
    svc_relay.init_with_node_config(NodeConfig {
        capabilities: Capabilities::CLIENT | Capabilities::RELAY,
        listen_addr: "/ip4/127.0.0.1/tcp/44220".parse().unwrap(),
        bootstrap_peers: vec![],
        ..Default::default()
    }).await.unwrap();

    let relay_peer_id_str = timeout(Duration::from_secs(20), async {
        loop {
            let s = svc_relay.status().await;
            if s.relay_announced_secs_ago.is_some() {
                if let Some(id) = svc_relay.local_peer_id_str().await { return id; }
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }).await.expect("Relay announce timeout");
    eprintln!("[t03] Relay peer_id={}", relay_peer_id_str);

    assert!(wait_for_tcp("127.0.0.1:44220", 20).await, "Relay TCP not ready");

    let relay_peer_id: libp2p::PeerId = relay_peer_id_str.parse().unwrap();

    let svc_client = DaemonService::new_with_keypair(&make_secret(31)).unwrap();
    svc_client.init_with_node_config(NodeConfig {
        capabilities: Capabilities::CLIENT,
        listen_addr: "/ip4/127.0.0.1/tcp/44221".parse().unwrap(),
        bootstrap_peers: vec![(relay_peer_id, "/ip4/127.0.0.1/tcp/44220".parse().unwrap())],
        ..Default::default()
    }).await.unwrap();

    tokio::time::sleep(Duration::from_secs(2)).await;
    let _ = svc_client.connect(ConnectParams { hops: None }).await;

    let peers = timeout(Duration::from_secs(20), async {
        loop {
            let p = svc_client.get_peers().await;
            eprintln!("[t03] peers={}", p.len());
            if !p.is_empty() { return p; }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }).await.expect("Peer discovery timeout");

    assert!(!peers.is_empty());
    eprintln!("[t03] PASS: {} peers", peers.len());
}
