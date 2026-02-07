//! Integration tests for shard exchange between network nodes
//!
//! These tests verify that two nodes can connect and exchange shards.

use std::time::Duration;

use libp2p::identity::Keypair;
use libp2p::swarm::SwarmEvent;
use tokio::time::timeout;
use futures::StreamExt;

use tunnelcraft_core::Shard;
use tunnelcraft_network::{
    ShardResponse, ShardRequest,
    TunnelCraftBehaviour, TunnelCraftBehaviourEvent, PeerId,
};

/// Create a test shard
fn create_test_shard() -> Shard {
    let user_pubkey = [4u8; 32];
    Shard::new_request(
        [1u8; 32],  // shard_id
        [2u8; 32],  // request_id
        user_pubkey, // user_pubkey
        [5u8; 32],  // destination
        2,          // hops_remaining
        b"test payload".to_vec(),
        0,          // shard_index
        5,          // total_shards
    )
}

/// Create a test swarm
async fn create_test_swarm() -> (libp2p::Swarm<TunnelCraftBehaviour>, PeerId) {
    use libp2p::{noise, tcp, yamux, SwarmBuilder};
    use tunnelcraft_network::new_shard_behaviour;

    let keypair = Keypair::generate_ed25519();
    let peer_id = PeerId::from(keypair.public());

    let (behaviour, _relay_transport) = TunnelCraftBehaviour::new(peer_id, &keypair);

    let swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap()
        .with_relay_client(noise::Config::new, yamux::Config::default)
        .unwrap()
        .with_behaviour(|_key, relay_behaviour| {
            Ok(TunnelCraftBehaviour {
                kademlia: behaviour.kademlia,
                identify: behaviour.identify,
                mdns: behaviour.mdns,
                gossipsub: behaviour.gossipsub,
                rendezvous_client: behaviour.rendezvous_client,
                rendezvous_server: behaviour.rendezvous_server,
                relay_client: relay_behaviour,
                dcutr: behaviour.dcutr,
                shard: new_shard_behaviour(),
            })
        })
        .unwrap()
        .build();

    (swarm, peer_id)
}

#[tokio::test]
async fn test_two_nodes_can_connect() {
    let (mut swarm1, peer1) = create_test_swarm().await;
    let (mut swarm2, peer2) = create_test_swarm().await;

    // Start listening
    swarm1.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
    swarm2.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();

    // Get listen address from swarm1
    let addr1 = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm1.select_next_some().await {
            break address;
        }
    };

    // Get listen address from swarm2
    let addr2 = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm2.select_next_some().await {
            break address;
        }
    };

    // Add addresses to each other
    swarm1.behaviour_mut().add_address(&peer2, addr2);
    swarm2.behaviour_mut().add_address(&peer1, addr1);

    // Dial from swarm1 to swarm2
    swarm1.dial(peer2).unwrap();

    // Run both swarms until connected
    let connected = timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = swarm1.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
                        if peer_id == peer2 {
                            return true;
                        }
                    }
                }
                event = swarm2.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
                        if peer_id == peer1 {
                            return true;
                        }
                    }
                }
            }
        }
    })
    .await
    .expect("Should connect within timeout");

    assert!(connected);
}

#[tokio::test]
async fn test_shard_send_and_receive() {
    let (mut swarm1, peer1) = create_test_swarm().await;
    let (mut swarm2, peer2) = create_test_swarm().await;

    // Start listening
    swarm1.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
    swarm2.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();

    // Get addresses
    let addr1 = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm1.select_next_some().await {
            break address;
        }
    };

    let addr2 = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm2.select_next_some().await {
            break address;
        }
    };

    // Connect
    swarm1.behaviour_mut().add_address(&peer2, addr2);
    swarm2.behaviour_mut().add_address(&peer1, addr1);
    swarm1.dial(peer2).unwrap();

    // Wait for connection on BOTH sides
    timeout(Duration::from_secs(10), async {
        let mut swarm1_connected = false;
        let mut swarm2_connected = false;
        loop {
            tokio::select! {
                event = swarm1.select_next_some() => {
                    if matches!(event, SwarmEvent::ConnectionEstablished { .. }) {
                        swarm1_connected = true;
                        if swarm2_connected { return; }
                    }
                }
                event = swarm2.select_next_some() => {
                    if matches!(event, SwarmEvent::ConnectionEstablished { .. }) {
                        swarm2_connected = true;
                        if swarm1_connected { return; }
                    }
                }
            }
        }
    })
    .await
    .expect("Should connect");

    // Give protocols time to negotiate after connection
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Send a shard from node1 to node2
    let shard = create_test_shard();
    let request = ShardRequest { shard: shard.clone() };
    let _request_id = swarm1.behaviour_mut().send_shard(peer2, request);

    // Process events until shard is received and response is sent
    let result = timeout(Duration::from_secs(10), async {
        let mut received_shard: Option<Shard> = None;
        let mut got_response = false;

        loop {
            tokio::select! {
                event = swarm1.select_next_some() => {
                    if let SwarmEvent::Behaviour(TunnelCraftBehaviourEvent::Shard(shard_event)) = event {
                        use libp2p::request_response::Event;
                        if let Event::Message { message: libp2p::request_response::Message::Response { response, .. }, .. } = shard_event {
                            assert!(matches!(response, ShardResponse::Accepted(_)));
                            got_response = true;
                            if received_shard.is_some() {
                                return (received_shard.unwrap(), true);
                            }
                        }
                    }
                }
                event = swarm2.select_next_some() => {
                    if let SwarmEvent::Behaviour(TunnelCraftBehaviourEvent::Shard(shard_event)) = event {
                        use libp2p::request_response::Event;
                        if let Event::Message { message: libp2p::request_response::Message::Request { request, channel, .. }, .. } = shard_event {
                            received_shard = Some(request.shard);
                            // Accept the shard
                            swarm2.behaviour_mut().send_shard_response(channel, ShardResponse::Accepted(None)).ok();
                            if got_response {
                                return (received_shard.unwrap(), true);
                            }
                        }
                    }
                }
            }
        }
    })
    .await
    .expect("Should exchange shard");

    let (received, success) = result;
    assert!(success);
    assert_eq!(received.shard_id, shard.shard_id);
    assert_eq!(received.request_id, shard.request_id);
    assert_eq!(received.payload, shard.payload);
}

#[tokio::test]
async fn test_shard_rejection() {
    let (mut swarm1, peer1) = create_test_swarm().await;
    let (mut swarm2, peer2) = create_test_swarm().await;

    // Start listening and connect
    swarm1.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
    swarm2.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();

    let addr1 = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm1.select_next_some().await {
            break address;
        }
    };

    let addr2 = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm2.select_next_some().await {
            break address;
        }
    };

    swarm1.behaviour_mut().add_address(&peer2, addr2);
    swarm2.behaviour_mut().add_address(&peer1, addr1);
    swarm1.dial(peer2).unwrap();

    // Wait for connection
    timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = swarm1.select_next_some() => {
                    if matches!(event, SwarmEvent::ConnectionEstablished { .. }) {
                        return;
                    }
                }
                _ = swarm2.select_next_some() => {}
            }
        }
    })
    .await
    .unwrap();

    // Send shard
    let shard = create_test_shard();
    let request = ShardRequest { shard };
    swarm1.behaviour_mut().send_shard(peer2, request);

    // Node2 rejects, node1 receives rejection
    let rejection_reason = timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = swarm1.select_next_some() => {
                    if let SwarmEvent::Behaviour(TunnelCraftBehaviourEvent::Shard(shard_event)) = event {
                        use libp2p::request_response::Event;
                        if let Event::Message { message: libp2p::request_response::Message::Response { response, .. }, .. } = shard_event {
                            if let ShardResponse::Rejected(reason) = response {
                                return reason;
                            }
                        }
                    }
                }
                event = swarm2.select_next_some() => {
                    if let SwarmEvent::Behaviour(TunnelCraftBehaviourEvent::Shard(shard_event)) = event {
                        use libp2p::request_response::Event;
                        if let Event::Message { message: libp2p::request_response::Message::Request { channel, .. }, .. } = shard_event {
                            // Reject with reason
                            swarm2.behaviour_mut().send_shard_response(
                                channel,
                                ShardResponse::Rejected("Invalid destination".to_string())
                            ).ok();
                        }
                    }
                }
            }
        }
    })
    .await
    .expect("Should receive rejection");

    assert_eq!(rejection_reason, "Invalid destination");
}

#[tokio::test]
async fn test_multiple_shards_erasure_coding() {
    let (mut swarm1, peer1) = create_test_swarm().await;
    let (mut swarm2, peer2) = create_test_swarm().await;

    // Setup and connect
    swarm1.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();
    swarm2.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();

    let addr1 = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm1.select_next_some().await {
            break address;
        }
    };

    let addr2 = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm2.select_next_some().await {
            break address;
        }
    };

    swarm1.behaviour_mut().add_address(&peer2, addr2);
    swarm2.behaviour_mut().add_address(&peer1, addr1);
    swarm1.dial(peer2).unwrap();

    timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = swarm1.select_next_some() => {
                    if matches!(event, SwarmEvent::ConnectionEstablished { .. }) {
                        return;
                    }
                }
                _ = swarm2.select_next_some() => {}
            }
        }
    })
    .await
    .unwrap();

    // Send 5 shards (simulating 5/3 erasure coding)
    for i in 0..5u8 {
        let mut shard = create_test_shard();
        shard.shard_id = [i + 10; 32];
        shard.shard_index = i;
        let request = ShardRequest { shard };
        swarm1.behaviour_mut().send_shard(peer2, request);
    }

    // Receive all 5 shards and respond
    let mut received_count = 0;
    let mut response_count = 0;

    timeout(Duration::from_secs(15), async {
        loop {
            tokio::select! {
                event = swarm1.select_next_some() => {
                    if let SwarmEvent::Behaviour(TunnelCraftBehaviourEvent::Shard(shard_event)) = event {
                        use libp2p::request_response::Event;
                        if let Event::Message { message: libp2p::request_response::Message::Response { response, .. }, .. } = shard_event {
                            if matches!(response, ShardResponse::Accepted(_)) {
                                response_count += 1;
                                if response_count >= 5 && received_count >= 5 {
                                    return;
                                }
                            }
                        }
                    }
                }
                event = swarm2.select_next_some() => {
                    if let SwarmEvent::Behaviour(TunnelCraftBehaviourEvent::Shard(shard_event)) = event {
                        use libp2p::request_response::Event;
                        if let Event::Message { message: libp2p::request_response::Message::Request { channel, request: _, .. }, .. } = shard_event {
                            received_count += 1;
                            swarm2.behaviour_mut().send_shard_response(channel, ShardResponse::Accepted(None)).ok();
                            if response_count >= 5 && received_count >= 5 {
                                return;
                            }
                        }
                    }
                }
            }
        }
    })
    .await
    .expect("Should exchange all 5 shards");

    assert_eq!(received_count, 5);
    assert_eq!(response_count, 5);
}
