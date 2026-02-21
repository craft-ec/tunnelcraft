
//! Integration test for the announce timing flow.
//!
//! Asserts that after connect() + set_mode("relay"):
//!   relay_announced_secs_ago transitions from None -> Some
//!
//! Two scenarios:
//!   1. Enable relay BEFORE connect (common UI flow — enable caps then click connect)
//!   2. Enable relay AFTER connect (enable caps while already connected)

use craftnet_daemon::{ConnectParams, DaemonService};
use std::time::Duration;

fn random_secret() -> [u8; 32] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .hash(&mut h);
    let seed = h.finish();
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = ((seed >> (i % 8)) ^ (seed.wrapping_mul(i as u64 + 1))) as u8;
    }
    key
}

/// Poll status until relay_announced_secs_ago is Some, or give up.
async fn wait_for_relay_announce(svc: &DaemonService, timeout: Duration) -> Option<u64> {
    let start = std::time::Instant::now();
    loop {
        let status = svc.status().await;
        eprintln!(
            "[test] state={:?}  relay_secs={:?}",
            status.state, status.relay_announced_secs_ago
        );
        if let Some(secs) = status.relay_announced_secs_ago {
            return Some(secs);
        }
        if start.elapsed() > timeout {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

// ── Scenario 1: relay enabled BEFORE connect ─────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn test_relay_announce_when_enabled_before_connect() {
    let secret = random_secret();
    let svc = DaemonService::new_with_keypair(&secret).expect("DaemonService::new_with_keypair");

    // Enable relay before the node is started
    svc.set_mode("relay").await.expect("set_mode");

    let before = svc.status().await;
    eprintln!("[test] before connect: relay_secs={:?}", before.relay_announced_secs_ago);
    assert!(
        before.relay_announced_secs_ago.is_none(),
        "Expected None before connect (no swarm yet), got {:?}",
        before.relay_announced_secs_ago
    );

    // Connect — node.start() builds a standalone swarm, sets peer_id, then announces
    eprintln!("[test] connecting...");
    svc.connect(ConnectParams { hops: None }).await.expect("connect");
    eprintln!("[test] connected, polling for announce...");

    let result = wait_for_relay_announce(&svc, Duration::from_secs(10)).await;
    assert!(
        result.is_some(),
        "relay_announced_secs_ago is STILL None after connect — peer_id not set or status not updated. \
         Check [announce_as_relay] and [announce] log lines."
    );
    eprintln!("[test] PASS scenario 1: relay_announced_secs_ago={:?}", result);
}

// ── Scenario 2: relay enabled AFTER connect ─────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn test_relay_announce_when_enabled_after_connect() {
    let secret = random_secret();
    let svc = DaemonService::new_with_keypair(&secret).expect("DaemonService::new_with_keypair");

    // Connect as client first
    svc.connect(ConnectParams { hops: None }).await.expect("connect");

    let before = svc.status().await;
    eprintln!("[test] connected (client only): relay_secs={:?}", before.relay_announced_secs_ago);

    // Now enable relay — peer_id is already set so announce should fire immediately
    svc.set_mode("relay").await.expect("set_mode");

    let result = wait_for_relay_announce(&svc, Duration::from_secs(5)).await;
    assert!(
        result.is_some(),
        "relay_announced_secs_ago is None after enabling relay while connected. \
         Check [announce] log lines."
    );
    eprintln!("[test] PASS scenario 2: relay_announced_secs_ago={:?}", result);
}
