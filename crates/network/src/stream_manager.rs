//! Persistent stream manager for shard transport.
//!
//! Manages one persistent bidirectional stream per peer, replacing per-shard
//! request-response with length-prefixed frames on a single yamux sub-stream.
//! TCP backpressure replaces hard yamux sub-stream limits.
//!
//! Stream opening is asynchronous: `ensure_opening()` spawns a background task
//! that calls `control.open_stream()`. The swarm's Handler processes the request
//! during `swarm.poll()`, so background tasks naturally complete as the event loop
//! progresses. `poll_open_streams()` collects completed opens.
//!
//! Two-layer subscription priority:
//! - Layer 1: per-peer stream reading routes shards to high/low priority channels
//! - Layer 2: after onion peel, free-tier shards are deferred (handled in client node)

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

use futures::AsyncReadExt;
use libp2p::PeerId;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use tunnelcraft_core::{ForwardReceipt, Shard};

use crate::protocol::{
    read_frame, write_ack_frame, write_nack_frame, write_shard_frame, StreamFrame,
    SHARD_STREAM_PROTOCOL,
};

/// Result of an ack/nack for a sent shard
#[derive(Debug)]
pub enum AckResult {
    /// Shard was accepted, optionally with a ForwardReceipt
    Accepted(Option<Box<ForwardReceipt>>),
    /// Shard was rejected with reason
    Rejected(String),
}

/// An inbound shard received from a peer stream
#[derive(Debug)]
pub struct InboundShard {
    pub peer: PeerId,
    pub seq_id: u64,
    pub shard: Shard,
}

/// Manages one persistent stream per peer.
pub struct StreamManager {
    control: libp2p_stream::Control,
    streams: HashMap<PeerId, PeerStream>,
    /// High-priority inbound channel sender (subscribed peers)
    inbound_high_tx: mpsc::Sender<InboundShard>,
    /// Low-priority inbound channel sender (free-tier peers)
    inbound_low_tx: mpsc::Sender<InboundShard>,
    /// Channel for receipts from ack frames that arrive for fire-and-forget sends
    receipt_tx: mpsc::Sender<ForwardReceipt>,
    /// Our own PeerId for duplicate stream tiebreaking
    local_peer_id: PeerId,
    /// Channel for receiving streams opened by background tasks
    open_result_rx: mpsc::UnboundedReceiver<(PeerId, Result<libp2p::Stream, std::io::Error>)>,
    /// Sender clone given to background tasks
    open_result_tx: mpsc::UnboundedSender<(PeerId, Result<libp2p::Stream, std::io::Error>)>,
    /// Peers with a background open in flight (prevents duplicate spawns)
    opening: HashSet<PeerId>,
}

struct PeerStream {
    /// Writer half of the stream, protected by async mutex for concurrent sends
    writer: Arc<Mutex<futures::io::WriteHalf<libp2p::Stream>>>,
    /// Monotonically increasing sequence ID
    next_seq: Arc<AtomicU64>,
    /// Pending ack channels: seq_id → oneshot sender
    pending_acks: Arc<std::sync::Mutex<HashMap<u64, oneshot::Sender<AckResult>>>>,
    /// Reader task handle
    reader_handle: JoinHandle<()>,
    /// Peer's subscription tier: 0 = free, 1+ = subscribed
    tier: Arc<AtomicU8>,
}

impl StreamManager {
    /// Create a new stream manager.
    ///
    /// Returns (StreamManager, high_priority_rx, low_priority_rx, receipt_rx).
    pub fn new(
        control: libp2p_stream::Control,
        local_peer_id: PeerId,
    ) -> (
        Self,
        mpsc::Receiver<InboundShard>,
        mpsc::Receiver<InboundShard>,
        mpsc::Receiver<ForwardReceipt>,
    ) {
        let (inbound_high_tx, inbound_high_rx) = mpsc::channel(4096);
        let (inbound_low_tx, inbound_low_rx) = mpsc::channel(2048);
        let (receipt_tx, receipt_rx) = mpsc::channel(4096);
        let (open_result_tx, open_result_rx) = mpsc::unbounded_channel();

        let mgr = Self {
            control,
            streams: HashMap::new(),
            inbound_high_tx,
            inbound_low_tx,
            receipt_tx,
            local_peer_id,
            open_result_rx,
            open_result_tx,
            opening: HashSet::new(),
        };

        (mgr, inbound_high_rx, inbound_low_rx, receipt_rx)
    }

    /// Send a shard to a peer on an existing stream.
    ///
    /// If no stream exists, initiates a background open and returns `WouldBlock`.
    /// The caller should re-queue the shard and call `poll_open_streams()` after
    /// the next swarm poll to pick up the newly opened stream.
    ///
    /// If `await_ack` is true, blocks until ack/nack is received.
    /// If false, the send is fire-and-forget (receipts delivered via receipt channel).
    pub async fn send_shard(
        &mut self,
        peer: PeerId,
        shard: &Shard,
        await_ack: bool,
    ) -> Result<Option<AckResult>, std::io::Error> {
        // If no stream, initiate background open and tell caller to retry
        if !self.streams.contains_key(&peer) {
            self.ensure_opening(peer);
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                format!("Stream to {} opening in background", peer),
            ));
        }

        let ps = self.streams.get(&peer).unwrap();
        let seq_id = ps.next_seq.fetch_add(1, Ordering::Relaxed);

        // Set up ack waiter if needed
        let ack_rx = if await_ack {
            let (tx, rx) = oneshot::channel();
            ps.pending_acks.lock().unwrap().insert(seq_id, tx);
            Some(rx)
        } else {
            None
        };

        // Write the shard frame
        let write_result = {
            let mut writer = ps.writer.lock().await;
            write_shard_frame(&mut *writer, shard, seq_id).await
        };

        match write_result {
            Ok(()) => {
                // Write succeeded
                if let Some(rx) = ack_rx {
                    match rx.await {
                        Ok(result) => Ok(Some(result)),
                        Err(_) => Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionReset,
                            "Ack channel closed (stream dropped)",
                        )),
                    }
                } else {
                    Ok(None)
                }
            }
            Err(e) => {
                // InvalidData means shard too large — not retryable
                if e.kind() == std::io::ErrorKind::InvalidData {
                    warn!("Shard too large for peer {} — not retryable: {}", peer, e);
                    return Err(e);
                }
                // Connection/IO error — close stream, kick off background reopen
                warn!("Stream write to {} failed: {}", peer, e);
                self.close_stream(&peer);
                self.ensure_opening(peer);
                Err(e)
            }
        }
    }

    /// Send an ack frame back to a peer.
    pub async fn send_ack(
        &mut self,
        peer: PeerId,
        seq_id: u64,
        receipt: Option<&ForwardReceipt>,
    ) -> Result<(), std::io::Error> {
        if let Some(ps) = self.streams.get(&peer) {
            let mut writer = ps.writer.lock().await;
            if let Err(e) = write_ack_frame(&mut *writer, seq_id, receipt).await {
                warn!("Ack write to {} failed: {}", peer, e);
                drop(writer);
                self.close_stream(&peer);
                return Err(e);
            }
        } else {
            debug!("No stream to peer {} for ack (seq={})", peer, seq_id);
        }
        Ok(())
    }

    /// Send a nack frame back to a peer.
    pub async fn send_nack(
        &mut self,
        peer: PeerId,
        seq_id: u64,
        reason: &str,
    ) -> Result<(), std::io::Error> {
        if let Some(ps) = self.streams.get(&peer) {
            let mut writer = ps.writer.lock().await;
            if let Err(e) = write_nack_frame(&mut *writer, seq_id, reason).await {
                warn!("Nack write to {} failed: {}", peer, e);
                drop(writer);
                self.close_stream(&peer);
                return Err(e);
            }
        } else {
            debug!("No stream to peer {} for nack (seq={})", peer, seq_id);
        }
        Ok(())
    }

    /// Accept an inbound stream from a peer.
    pub fn accept_stream(&mut self, peer: PeerId, stream: libp2p::Stream, tier: u8) {
        // Cancel any in-flight background open since we now have a stream
        self.opening.remove(&peer);

        // Duplicate stream tiebreak: lower PeerId keeps outbound (its opened stream),
        // higher PeerId accepts inbound.
        if self.streams.contains_key(&peer) {
            if self.local_peer_id < peer {
                // We have lower PeerId: keep our outbound, reject this inbound
                debug!(
                    "Duplicate stream tiebreak: keeping outbound to {} (we have lower PeerId)",
                    peer
                );
                return;
            } else {
                // We have higher PeerId: accept inbound, close outbound
                debug!(
                    "Duplicate stream tiebreak: accepting inbound from {} (we have higher PeerId)",
                    peer
                );
                self.close_stream(&peer);
            }
        }

        self.register_stream(peer, stream, tier);
        info!("Accepted inbound stream from peer {} (tier={})", peer, tier);
    }

    /// Ensure a background stream-open task is running for this peer.
    ///
    /// If we already have a stream or a background open in flight, this is a no-op.
    /// The spawned task calls `control.open_stream()` which requires the swarm's
    /// Handler to be polled — since this runs as a separate tokio task, it naturally
    /// completes once `swarm.poll()` processes the request in the main event loop.
    pub fn ensure_opening(&mut self, peer: PeerId) {
        if self.streams.contains_key(&peer) || self.opening.contains(&peer) {
            return;
        }
        self.opening.insert(peer);
        let mut control = self.control.clone();
        let tx = self.open_result_tx.clone();
        tokio::spawn(async move {
            debug!("Background: opening stream to {} ...", peer);
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                control.open_stream(peer, SHARD_STREAM_PROTOCOL),
            )
            .await
            {
                Ok(Ok(stream)) => {
                    let _ = tx.send((peer, Ok(stream)));
                }
                Ok(Err(e)) => {
                    warn!("Background: stream open to {} failed: {}", peer, e);
                    let _ = tx.send((
                        peer,
                        Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionRefused,
                            format!("open_stream failed: {}", e),
                        )),
                    ));
                }
                Err(_) => {
                    warn!("Background: stream open to {} timed out (5s)", peer);
                    let _ = tx.send((
                        peer,
                        Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "open_stream timed out",
                        )),
                    ));
                }
            }
        });
        debug!("Initiated background stream open to {}", peer);
    }

    /// Collect completed background stream opens.
    ///
    /// Call this after every `swarm.poll()` cycle to register newly opened streams.
    pub fn poll_open_streams(&mut self) {
        while let Ok((peer, result)) = self.open_result_rx.try_recv() {
            self.opening.remove(&peer);
            match result {
                Ok(stream) => {
                    if self.streams.contains_key(&peer) {
                        // Stream already exists (e.g., accepted inbound in the meantime)
                        debug!(
                            "Background stream to {} ready but stream already exists, dropping",
                            peer
                        );
                        continue;
                    }
                    self.register_stream(peer, stream, 0);
                    info!("Opened outbound stream to peer {}", peer);
                }
                Err(e) => {
                    debug!("Background stream open to {} failed: {}", peer, e);
                }
            }
        }
    }

    /// Update a peer's subscription tier.
    pub fn update_peer_tier(&mut self, peer: &PeerId, tier: u8) {
        if let Some(ps) = self.streams.get(peer) {
            ps.tier.store(tier, Ordering::Relaxed);
            debug!("Updated peer {} tier to {}", peer, tier);
        }
    }

    /// Check if we have an active stream to a peer.
    pub fn has_stream(&self, peer: &PeerId) -> bool {
        self.streams.contains_key(peer)
    }

    /// Close and remove a stream to a peer.
    fn close_stream(&mut self, peer: &PeerId) {
        if let Some(ps) = self.streams.remove(peer) {
            ps.reader_handle.abort();
            debug!("Closed stream to peer {}", peer);
        }
    }

    /// Remove a disconnected peer's stream.
    pub fn on_peer_disconnected(&mut self, peer: &PeerId) {
        self.opening.remove(peer);
        self.close_stream(peer);
    }

    /// Register a raw stream: split into reader/writer, spawn reader task, insert.
    fn register_stream(&mut self, peer: PeerId, stream: libp2p::Stream, tier: u8) {
        let tier_atomic = Arc::new(AtomicU8::new(tier));
        let (reader, writer) = AsyncReadExt::split(stream);
        let pending_acks: Arc<std::sync::Mutex<HashMap<u64, oneshot::Sender<AckResult>>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));

        let reader_handle = tokio::spawn(Self::reader_loop(
            peer,
            reader,
            pending_acks.clone(),
            self.inbound_high_tx.clone(),
            self.inbound_low_tx.clone(),
            self.receipt_tx.clone(),
            tier_atomic.clone(),
        ));

        self.streams.insert(
            peer,
            PeerStream {
                writer: Arc::new(Mutex::new(writer)),
                next_seq: Arc::new(AtomicU64::new(0)),
                pending_acks,
                reader_handle,
                tier: tier_atomic,
            },
        );
    }

    /// Reader loop for a single peer stream.
    ///
    /// Reads frames in a loop. Shard frames are dispatched to high/low priority
    /// channels based on peer tier. Ack/nack frames resolve pending_acks oneshots.
    async fn reader_loop(
        peer: PeerId,
        mut reader: futures::io::ReadHalf<libp2p::Stream>,
        pending_acks: Arc<std::sync::Mutex<HashMap<u64, oneshot::Sender<AckResult>>>>,
        inbound_high_tx: mpsc::Sender<InboundShard>,
        inbound_low_tx: mpsc::Sender<InboundShard>,
        receipt_tx: mpsc::Sender<ForwardReceipt>,
        tier: Arc<AtomicU8>,
    ) {
        loop {
            match read_frame(&mut reader).await {
                Ok(StreamFrame::Shard { seq_id, shard }) => {
                    let inbound = InboundShard {
                        peer,
                        seq_id,
                        shard,
                    };
                    // Route to high or low priority based on peer tier
                    if tier.load(Ordering::Relaxed) > 0 {
                        if inbound_high_tx.send(inbound).await.is_err() {
                            debug!("High-priority inbound channel closed for {}", peer);
                            break;
                        }
                    } else if inbound_low_tx.send(inbound).await.is_err() {
                        debug!("Low-priority inbound channel closed for {}", peer);
                        break;
                    }
                }
                Ok(StreamFrame::Ack { seq_id, receipt }) => {
                    // Resolve pending ack
                    let sender = pending_acks.lock().unwrap().remove(&seq_id);
                    if let Some(tx) = sender {
                        let _ = tx.send(AckResult::Accepted(receipt.clone().map(Box::new)));
                    }
                    // Also forward receipt to the receipt channel for fire-and-forget sends
                    if let Some(r) = receipt {
                        let _ = receipt_tx.send(r).await;
                    }
                }
                Ok(StreamFrame::Nack { seq_id, reason }) => {
                    let sender = pending_acks.lock().unwrap().remove(&seq_id);
                    if let Some(tx) = sender {
                        let _ = tx.send(AckResult::Rejected(reason.clone()));
                    }
                    debug!(
                        "Received nack from {} (seq={}): {}",
                        peer, seq_id, reason
                    );
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        debug!("Stream from {} closed (EOF)", peer);
                    } else {
                        warn!("Stream read error from {}: {}", peer, e);
                    }
                    break;
                }
            }
        }

        debug!("Reader loop ended for peer {}", peer);
    }
}
