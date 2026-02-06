//! Bootstrap node configuration
//!
//! Default bootstrap nodes for joining the TunnelCraft network.
//! These are public nodes that act as entry points for peer discovery.

use libp2p::{Multiaddr, PeerId};

/// Default bootstrap nodes for the TunnelCraft network
///
/// These nodes run on public VPS and provide:
/// - Initial peer discovery (DHT bootstrap)
/// - Relay services for NAT traversal
/// - Rendezvous for peer registration
///
/// Format: /ip4/<IP>/tcp/<PORT>/p2p/<PEER_ID>
///
/// To add your own bootstrap node:
/// 1. Run `tunnelcraft-node` on a VPS with public IP
/// 2. Note the peer ID from startup logs
/// 3. Add the multiaddr below
pub const DEFAULT_BOOTSTRAP_NODES: &[&str] = &[
    // TODO: Replace with actual bootstrap node addresses once VPS is set up
    // Example format:
    // "/ip4/123.45.67.89/tcp/9000/p2p/12D3KooWxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    // "/ip4/98.76.54.32/tcp/9000/p2p/12D3KooWyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy",
];

/// Default port for TunnelCraft nodes
pub const DEFAULT_PORT: u16 = 9000;

/// Parse bootstrap nodes from the default list
pub fn default_bootstrap_peers() -> Vec<(PeerId, Multiaddr)> {
    let peers = parse_bootstrap_nodes(DEFAULT_BOOTSTRAP_NODES);
    if peers.is_empty() {
        tracing::warn!("No bootstrap nodes configured, using local-only mode");
    }
    peers
}

/// Parse bootstrap nodes from a list of multiaddr strings
pub fn parse_bootstrap_nodes(addrs: &[&str]) -> Vec<(PeerId, Multiaddr)> {
    addrs
        .iter()
        .filter_map(|addr_str| parse_bootstrap_addr(addr_str))
        .collect()
}

/// Parse a single bootstrap address
///
/// Expected format: /ip4/<IP>/tcp/<PORT>/p2p/<PEER_ID>
pub fn parse_bootstrap_addr(addr_str: &str) -> Option<(PeerId, Multiaddr)> {
    let addr: Multiaddr = addr_str.parse().ok()?;

    // Extract peer ID from the multiaddr
    let peer_id = addr.iter().find_map(|proto| {
        if let libp2p::multiaddr::Protocol::P2p(peer_id) = proto {
            Some(peer_id)
        } else {
            None
        }
    })?;

    // Remove /p2p/<peer_id> from the address for dialing
    let dial_addr: Multiaddr = addr
        .iter()
        .filter(|proto| !matches!(proto, libp2p::multiaddr::Protocol::P2p(_)))
        .collect();

    Some((peer_id, dial_addr))
}

/// Create a bootstrap multiaddr string from components
pub fn make_bootstrap_addr(ip: &str, port: u16, peer_id: &str) -> String {
    format!("/ip4/{}/tcp/{}/p2p/{}", ip, port, peer_id)
}

/// Check if we have any bootstrap nodes configured
pub fn has_bootstrap_nodes() -> bool {
    !DEFAULT_BOOTSTRAP_NODES.is_empty() &&
    DEFAULT_BOOTSTRAP_NODES.iter().any(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bootstrap_addr() {
        // Valid address
        let addr = "/ip4/127.0.0.1/tcp/9000/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN";
        let result = parse_bootstrap_addr(addr);
        assert!(result.is_some());

        let (peer_id, dial_addr) = result.unwrap();
        assert_eq!(dial_addr.to_string(), "/ip4/127.0.0.1/tcp/9000");
        assert!(peer_id.to_string().starts_with("12D3KooW"));
    }

    #[test]
    fn test_parse_invalid_addr() {
        assert!(parse_bootstrap_addr("invalid").is_none());
        assert!(parse_bootstrap_addr("/ip4/127.0.0.1/tcp/9000").is_none()); // No peer ID
    }

    #[test]
    fn test_make_bootstrap_addr() {
        let addr = make_bootstrap_addr(
            "123.45.67.89",
            9000,
            "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
        );
        assert_eq!(
            addr,
            "/ip4/123.45.67.89/tcp/9000/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
        );
    }

    #[test]
    fn test_parse_bootstrap_nodes() {
        let addrs = &[
            "/ip4/127.0.0.1/tcp/9000/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN",
        ];
        let peers = parse_bootstrap_nodes(addrs);
        assert_eq!(peers.len(), 1);
    }

    #[test]
    fn test_empty_bootstrap() {
        let peers = parse_bootstrap_nodes(&[]);
        assert!(peers.is_empty());
    }

    #[test]
    fn test_has_bootstrap_nodes() {
        // Currently empty, so should be false
        // Will be true once we add actual addresses
        assert!(!has_bootstrap_nodes());
    }
}
