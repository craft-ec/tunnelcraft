# TunnelCraft Architecture — Applicable Domains

## What TunnelCraft Actually Is

TunnelCraft is a **private communication layer** — a transient pipe. Data goes in one end, traverses multi-hop erasure-coded paths, gets reconstructed at the other end, and is gone. There is no storage, no persistence, no computation delegation.

Core primitives:

- **Erasure-coded sharding** (no single node sees full data)
- **Multi-hop random-path routing** (traffic analysis resistance)
- **Trustless relay verification** (destination checks, ForwardReceipts)
- **On-chain incentive layer** (nodes earn for forwarding, settled via proofs)
- **P2P DHT discovery** (no central coordinator)

## Applications That Fit (no new layers required)

These use the communication layer as-is — payloads in, payloads out, nothing persisted.

**VPN (current)** — HTTP requests/responses sharded and routed through the network, reconstructed and fetched at exit nodes.

**Private Messaging** — Messages instead of HTTP payloads. Each message gets erasure-coded, multi-hop routed, and reconstructed at the recipient. The ForwardReceipt settlement model works identically. Essentially Signal without servers — metadata is hidden because no relay sees the full message or both endpoints.

**Private Transaction Relay (Mixnet)** — Replace the exit node's HTTP fetch with transaction broadcast. Cryptocurrency transactions are sharded, routed through multiple hops, and reconstructed at a broadcasting node. Prevents transaction graph analysis (similar to Dandelion++ but with economic incentives and erasure coding).

**Private DNS Resolution** — DNS queries sharded and routed through the network, reconstructed at an exit that performs the lookup. Prevents ISP/network-level DNS surveillance. The existing request/response flow maps directly — just swap the payload format.

## Applications That Don't Fit (without a new layer)

These require a **distributed data/storage layer** or **computation layer** that TunnelCraft does not provide. They would be a different project built on top of or alongside the communication layer.

- Decentralized CDN (needs persistent distributed storage)
- Censorship-resistant publishing (needs content hosting/retrieval)
- Anonymous whistleblowing platform (needs document persistence)
- Decentralized data marketplace (needs storage + access control)
- Distributed computation relay (needs task scheduling + compute delegation)
- Private telemetry collection (needs aggregation + storage)

## The Common Thread

The fitting applications all share one property: **transient, point-to-point data transfer where privacy of the payload and metadata matters.** Put data in, get data out, nothing stored. That's the pipe.
