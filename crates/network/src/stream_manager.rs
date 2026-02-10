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

/// Outbound shard queued for writing by the writer task.
pub struct OutboundShard {
    pub peer: PeerId,
    pub shard: Shard,
}

/// Raw writer type: writes go directly to TCP, no buffering layer.
type StreamWriter = futures::io::WriteHalf<libp2p::Stream>;

/// Per-peer writer handle: cloneable Arcs for the writer task to use.
struct PeerWriterHandle {
    writer: Arc<Mutex<StreamWriter>>,
    next_seq: Arc<AtomicU64>,
}

/// Registry mapping peers to their writer handles.
/// The writer task briefly holds a read lock to clone Arcs, then releases
/// before any async work. poll_once's register/close use write lock (sync).
type WriterRegistry = Arc<std::sync::RwLock<HashMap<PeerId, PeerWriterHandle>>>;

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
    local_peer_id: PeerId,
    streams: HashMap<PeerId, PeerStream>,
    /// High-priority inbound channel sender (subscribed peers)
    inbound_high_tx: mpsc::Sender<InboundShard>,
    /// Low-priority inbound channel sender (free-tier peers)
    inbound_low_tx: mpsc::Sender<InboundShard>,
    /// Channel for receipts from ack frames that arrive for fire-and-forget sends
    receipt_tx: mpsc::Sender<ForwardReceipt>,
    /// Channel for receiving streams opened by background tasks
    open_result_rx: mpsc::UnboundedReceiver<(PeerId, Result<libp2p::Stream, std::io::Error>)>,
    /// Sender clone given to background tasks
    open_result_tx: mpsc::UnboundedSender<(PeerId, Result<libp2p::Stream, std::io::Error>)>,
    /// Peers with a background open in flight (prevents duplicate spawns)
    opening: HashSet<PeerId>,
    /// Peers whose stream open failed (protocol unsupported, etc.) — skip future opens
    failed_peers: HashSet<PeerId>,
    /// Shared registry of peer writers (accessible from the outbound writer task)
    writer_registry: WriterRegistry,
}

struct PeerStream {
    writer: Arc<Mutex<StreamWriter>>,
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
    /// Returns (StreamManager, high_priority_rx, low_priority_rx, receipt_rx, outbound_tx).
    /// The outbound_tx channel is the data plane: all shard writes go through it
    /// to a background writer task, keeping poll_once non-blocking.
    pub fn new(
        control: libp2p_stream::Control,
        local_peer_id: PeerId,
    ) -> (
        Self,
        mpsc::Receiver<InboundShard>,
        mpsc::Receiver<InboundShard>,
        mpsc::Receiver<ForwardReceipt>,
        mpsc::Sender<OutboundShard>,
    ) {
        let (inbound_high_tx, inbound_high_rx) = mpsc::channel(16384);
        let (inbound_low_tx, inbound_low_rx) = mpsc::channel(8192);
        let (receipt_tx, receipt_rx) = mpsc::channel(8192);
        let (open_result_tx, open_result_rx) = mpsc::unbounded_channel();
        let (outbound_tx, outbound_rx) = mpsc::channel::<OutboundShard>(8192);

        let writer_registry: WriterRegistry = Arc::new(std::sync::RwLock::new(HashMap::new()));

        // Spawn the background writer task — owns the outbound_rx and writer registry.
        // This task is the data plane: it writes shards to TCP without blocking poll_once.
        tokio::spawn(Self::outbound_writer_loop(
            writer_registry.clone(),
            outbound_rx,
        ));

        let mgr = Self {
            control,
            local_peer_id,
            streams: HashMap::new(),
            inbound_high_tx,
            inbound_low_tx,
            receipt_tx,
            open_result_rx,
            open_result_tx,
            opening: HashSet::new(),
            failed_peers: HashSet::new(),
            writer_registry,
        };

        (mgr, inbound_high_rx, inbound_low_rx, receipt_rx, outbound_tx)
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

        // Write the shard frame directly to TCP
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
    ///
    /// Never replace a healthy stream — dropping a writer kills the remote
    /// reader, cascading into churn. Only register if no stream exists or
    /// the existing reader is dead.
    pub fn accept_stream(&mut self, peer: PeerId, stream: libp2p::Stream, tier: u8) {
        self.opening.remove(&peer);
        self.failed_peers.remove(&peer);

        if let Some(existing) = self.streams.get(&peer) {
            if !existing.reader_handle.is_finished() {
                debug!("Already have healthy stream to {} — dropping inbound", peer);
                drop(stream);
                return;
            }
            debug!("Existing stream to {} has dead reader — replacing", peer);
            self.close_stream(&peer);
        }

        self.register_stream(peer, stream, tier);
        debug!("Accepted inbound stream from peer {} (tier={})", peer, tier);
    }

    /// Ensure a stream open is in flight for this peer.
    ///
    /// Only the lower PeerId opens — this guarantees at most one stream per
    /// peer pair, avoiding the two-stream race where close_stream on one
    /// kills the remote reader on the other.
    pub fn ensure_opening(&mut self, peer: PeerId) {
        if self.local_peer_id > peer {
            return;
        }
        if self.streams.contains_key(&peer)
            || self.opening.contains(&peer)
            || self.failed_peers.contains(&peer)
        {
            return;
        }
        self.spawn_open(peer);
    }

    /// Spawn a background open_stream task for a peer.
    fn spawn_open(&mut self, peer: PeerId) {
        self.opening.insert(peer);
        let mut control = self.control.clone();
        let tx = self.open_result_tx.clone();
        tokio::spawn(async move {
            debug!("Background: opening stream to {} ...", peer);
            match tokio::time::timeout(
                std::time::Duration::from_secs(10),
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
                    warn!("Background: stream open to {} timed out (10s)", peer);
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
    }

    /// Collect completed background stream opens.
    ///
    /// Call this after every `swarm.poll()` cycle to register newly opened streams.
    /// Returns the number of newly registered streams.
    pub fn poll_open_streams(&mut self) -> usize {
        let mut opened = 0;
        while let Ok((peer, result)) = self.open_result_rx.try_recv() {
            self.opening.remove(&peer);
            match result {
                Ok(stream) => {
                    if self.streams.contains_key(&peer) {
                        debug!(
                            "Background stream to {} ready but stream already exists, dropping",
                            peer
                        );
                        continue;
                    }
                    self.register_stream(peer, stream, 0);
                    warn!("Opened outbound stream to peer {}", peer);
                    opened += 1;
                }
                Err(e) => {
                    let msg = e.to_string();
                    // Only blacklist permanent failures (protocol not supported).
                    // "receiver is gone" = connection closed (transient), will retry on reconnect.
                    if msg.contains("does not support") {
                        warn!("Blacklisting peer {} — protocol unsupported", peer);
                        self.failed_peers.insert(peer);
                    }
                    debug!("Background stream open to {} failed: {}", peer, e);
                }
            }
        }
        opened
    }

    /// Number of streams established.
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Number of opens in flight.
    pub fn pending_count(&self) -> usize {
        self.opening.len()
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

    /// Return all peers with active streams.
    pub fn stream_peers(&self) -> Vec<PeerId> {
        self.streams.keys().copied().collect()
    }

    /// Close and remove a stream to a peer.
    fn close_stream(&mut self, peer: &PeerId) {
        if let Some(ps) = self.streams.remove(peer) {
            ps.reader_handle.abort();
            // Remove from writer registry (writer task will stop writing to this peer)
            self.writer_registry.write().unwrap().remove(peer);
            debug!("Closed stream to peer {}", peer);
        }
    }

    /// Remove a disconnected peer's stream.
    ///
    /// Does NOT clear failed_peers — if a peer was blacklisted (e.g. protocol
    /// unsupported), it stays blacklisted across reconnects. Only accept_stream
    /// clears the blacklist (proving the peer now supports the protocol).
    pub fn on_peer_disconnected(&mut self, peer: &PeerId) {
        self.opening.remove(peer);
        self.close_stream(peer);
    }

    /// Remove streams whose reader task has terminated (EOF or error).
    ///
    /// When a reader_loop exits, the stream is half-dead: writes go to TCP but
    /// the peer has disconnected. This detects dead readers and cleans up, but
    /// does NOT auto-reopen to avoid churn storms during bootstrap.
    /// The next send_shard() call will trigger ensure_opening() lazily.
    pub fn cleanup_dead_streams(&mut self) {
        let dead_peers: Vec<PeerId> = self
            .streams
            .iter()
            .filter(|(_, ps)| ps.reader_handle.is_finished())
            .map(|(peer, _)| *peer)
            .collect();

        for peer in dead_peers {
            warn!("Stream to {} has dead reader — removing and re-opening", peer);
            self.close_stream(&peer);
            // Proactively re-establish the stream (respects PeerId guard + failed_peers)
            self.ensure_opening(peer);
        }
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

        let writer_arc = Arc::new(Mutex::new(writer));
        let seq_arc = Arc::new(AtomicU64::new(0));

        // Register writer in the shared registry (accessible by the writer task)
        self.writer_registry.write().unwrap().insert(peer, PeerWriterHandle {
            writer: writer_arc.clone(),
            next_seq: seq_arc.clone(),
        });

        self.streams.insert(
            peer,
            PeerStream {
                writer: writer_arc,
                next_seq: seq_arc,
                pending_acks,
                reader_handle,
                tier: tier_atomic,
            },
        );
    }

    /// Background writer task: reads outbound shards from the channel and writes
    /// directly to peer streams. Runs as a separate tokio task so data writes
    /// never block poll_once (the control plane).
    async fn outbound_writer_loop(
        registry: WriterRegistry,
        mut rx: mpsc::Receiver<OutboundShard>,
    ) {
        loop {
            let Some(outbound) = rx.recv().await else {
                debug!("Outbound writer channel closed, exiting");
                break;
            };

            // Briefly hold std RwLock to clone Arcs — released before any async work
            let handle = {
                let reg = registry.read().unwrap();
                reg.get(&outbound.peer).map(|h| (h.writer.clone(), h.next_seq.clone()))
            };
            if let Some((writer, next_seq)) = handle {
                let seq_id = next_seq.fetch_add(1, Ordering::Relaxed);
                let mut w = writer.lock().await;
                if let Err(e) = write_shard_frame(&mut *w, &outbound.shard, seq_id).await {
                    warn!("Outbound write to {} failed: {}", outbound.peer, e);
                }
            } else {
                warn!("No stream in writer_registry for peer {} — dropping outbound shard", outbound.peer);
            }
        }
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
                    // Route to high or low priority based on peer tier.
                    // Use try_send to avoid blocking the reader loop when the
                    // channel is full (backpressure from slow drain). Blocking
                    // here would stall TCP reads, causing upstream writers to
                    // block on TCP send, cascading into a full pipeline stall.
                    // Dropped shards are recoverable via erasure coding (3-of-5).
                    if tier.load(Ordering::Relaxed) > 0 {
                        match inbound_high_tx.try_send(inbound) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                warn!("High-priority inbound channel full for {} — dropping shard to prevent backpressure stall", peer);
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                debug!("High-priority inbound channel closed for {}", peer);
                                break;
                            }
                        }
                    } else {
                        match inbound_low_tx.try_send(inbound) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                warn!("Low-priority inbound channel full for {} — dropping shard to prevent backpressure stall", peer);
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                debug!("Low-priority inbound channel closed for {}", peer);
                                break;
                            }
                        }
                    }
                }
                Ok(StreamFrame::Ack { seq_id, receipt }) => {
                    // Resolve pending ack
                    let sender = pending_acks.lock().unwrap().remove(&seq_id);
                    if let Some(tx) = sender {
                        let _ = tx.send(AckResult::Accepted(receipt.clone().map(Box::new)));
                    }
                    // Also forward receipt to the receipt channel for fire-and-forget sends.
                    // Use try_send to avoid blocking the reader loop.
                    if let Some(r) = receipt {
                        let _ = receipt_tx.try_send(r);
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
