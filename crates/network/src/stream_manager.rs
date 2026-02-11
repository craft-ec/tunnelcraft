//! Two-unidirectional-stream transport per peer.
//!
//! Each peer pair uses two independent streams:
//! - **Outbound**: we open → we write shards/acks/nacks, peer reads.
//! - **Inbound**: peer opens → peer writes shards/acks/nacks, we read.
//!
//! Closing one direction never affects the other — no cascading reader deaths.
//! Either side opens its own outbound independently (no PeerId tiebreak).
//!
//! Acks for shards received on our inbound are sent on our outbound.
//! The peer reads acks from their inbound (our outbound) and matches by seq_id.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Instant;

use libp2p::PeerId;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

/// Cooldown after a failed outbound open before retrying (seconds).
const OPEN_RETRY_COOLDOWN_SECS: u64 = 1;

use tunnelcraft_core::{ForwardReceipt, Shard};

use crate::protocol::{
    read_frame, write_ack_frame, write_nack_frame, write_shard_frame, StreamFrame,
    SHARD_STREAM_PROTOCOL,
};

/// Outbound shard queued for writing by the background writer task.
pub struct OutboundShard {
    pub peer: PeerId,
    pub shard: Shard,
}

/// Per-peer writer handle for the background writer task.
struct PeerWriterHandle {
    writer: Arc<Mutex<libp2p::Stream>>,
    next_seq: Arc<AtomicU64>,
    /// Set to true on first write failure — prevents cascade of doomed writes.
    poisoned: Arc<AtomicBool>,
}

/// Registry mapping peers to their outbound writer handles.
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

/// Per-peer connection with separate outbound and inbound streams.
struct PeerConnection {
    /// Our outbound stream (we write, peer reads). None until we open it.
    outbound: Option<OutboundHandle>,
    /// Peer's outbound stream (peer writes, we read). None until peer opens it.
    inbound: Option<InboundHandle>,
    /// Pending ack channels: created by send_shard, resolved by inbound reader.
    pending_acks: Arc<std::sync::Mutex<HashMap<u64, oneshot::Sender<AckResult>>>>,
    /// Peer's subscription tier: 0 = free, 1+ = subscribed.
    tier: Arc<AtomicU8>,
}

struct OutboundHandle {
    writer: Arc<Mutex<libp2p::Stream>>,
    next_seq: Arc<AtomicU64>,
}

struct InboundHandle {
    reader_handle: JoinHandle<()>,
}

/// Manages two unidirectional streams per peer.
pub struct StreamManager {
    control: libp2p_stream::Control,
    peers: HashMap<PeerId, PeerConnection>,
    /// High-priority inbound channel sender (subscribed peers)
    inbound_high_tx: mpsc::Sender<InboundShard>,
    /// Low-priority inbound channel sender (free-tier peers)
    inbound_low_tx: mpsc::Sender<InboundShard>,
    /// Channel for receipts from ack frames
    receipt_tx: mpsc::Sender<ForwardReceipt>,
    /// Channel for receiving streams opened by background tasks
    open_result_rx: mpsc::UnboundedReceiver<(PeerId, Result<libp2p::Stream, std::io::Error>)>,
    /// Sender clone given to background tasks
    open_result_tx: mpsc::UnboundedSender<(PeerId, Result<libp2p::Stream, std::io::Error>)>,
    /// Outbound opens in flight (prevents duplicate spawns)
    opening: HashSet<PeerId>,
    /// Cooldown after failed opens — don't retry until Instant passes
    open_cooldown: HashMap<PeerId, Instant>,
    /// Shared registry of outbound writers (for background writer task)
    writer_registry: WriterRegistry,
    /// Channel for writer loop to signal dead outbound streams
    write_fail_rx: mpsc::UnboundedReceiver<PeerId>,
    /// Channel for writer loop to request stream opens for buffered peers
    need_stream_rx: mpsc::UnboundedReceiver<PeerId>,
}

impl StreamManager {
    /// Create a new stream manager.
    ///
    /// Returns (StreamManager, high_priority_rx, low_priority_rx, receipt_rx, outbound_tx).
    pub fn new(
        control: libp2p_stream::Control,
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
        let (write_fail_tx, write_fail_rx) = mpsc::unbounded_channel();
        let (need_stream_tx, need_stream_rx) = mpsc::unbounded_channel();

        let writer_registry: WriterRegistry = Arc::new(std::sync::RwLock::new(HashMap::new()));

        tokio::spawn(Self::outbound_writer_loop(
            writer_registry.clone(),
            outbound_rx,
            write_fail_tx,
            need_stream_tx,
        ));

        let mgr = Self {
            control,
            peers: HashMap::new(),
            inbound_high_tx,
            inbound_low_tx,
            receipt_tx,
            open_result_rx,
            open_result_tx,
            opening: HashSet::new(),
            open_cooldown: HashMap::new(),
            writer_registry,
            write_fail_rx,
            need_stream_rx,
        };

        (mgr, inbound_high_rx, inbound_low_rx, receipt_rx, outbound_tx)
    }

    /// Send a shard to a peer on our outbound stream.
    ///
    /// If no outbound exists, initiates a background open and returns `WouldBlock`.
    pub async fn send_shard(
        &mut self,
        peer: PeerId,
        shard: &Shard,
        await_ack: bool,
    ) -> Result<Option<AckResult>, std::io::Error> {
        let pc = match self.peers.get(&peer) {
            Some(pc) if pc.outbound.is_some() => pc,
            _ => {
                self.ensure_opening(peer);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    format!("No outbound to {} (opening in background)", peer),
                ));
            }
        };

        let out = pc.outbound.as_ref().unwrap();
        let seq_id = out.next_seq.fetch_add(1, Ordering::Relaxed);

        let ack_rx = if await_ack {
            let (tx, rx) = oneshot::channel();
            pc.pending_acks.lock().unwrap().insert(seq_id, tx);
            Some(rx)
        } else {
            None
        };

        let write_result = {
            let mut writer = out.writer.lock().await;
            write_shard_frame(&mut *writer, shard, seq_id).await
        };

        match write_result {
            Ok(()) => {
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
                if e.kind() == std::io::ErrorKind::InvalidData {
                    warn!("Shard too large for peer {} — not retryable: {}", peer, e);
                    return Err(e);
                }
                warn!("Outbound write to {} failed: {}", peer, e);
                self.close_outbound(&peer);
                self.ensure_opening(peer);
                Err(e)
            }
        }
    }

    /// Send an ack frame to a peer on our outbound stream (fire-and-forget).
    ///
    /// Spawns the write in a background task to avoid blocking the drain loop
    /// with writer mutex contention under high shard throughput.
    pub fn send_ack(&self, peer: PeerId, seq_id: u64, receipt: Option<ForwardReceipt>) {
        if let Some(pc) = self.peers.get(&peer) {
            if let Some(ref out) = pc.outbound {
                let writer = out.writer.clone();
                tokio::spawn(async move {
                    let mut w = writer.lock().await;
                    if let Err(e) = write_ack_frame(&mut *w, seq_id, receipt.as_ref()).await {
                        warn!("Ack write to {} failed: {}", peer, e);
                    }
                });
            } else {
                debug!("No outbound to peer {} for ack (seq={})", peer, seq_id);
            }
        } else {
            debug!("No connection to peer {} for ack (seq={})", peer, seq_id);
        }
    }

    /// Send a nack frame to a peer on our outbound stream (fire-and-forget).
    ///
    /// Spawns the write in a background task to avoid blocking the drain loop.
    pub fn send_nack(&self, peer: PeerId, seq_id: u64, reason: &str) {
        if let Some(pc) = self.peers.get(&peer) {
            if let Some(ref out) = pc.outbound {
                let writer = out.writer.clone();
                let reason = reason.to_owned();
                tokio::spawn(async move {
                    let mut w = writer.lock().await;
                    if let Err(e) = write_nack_frame(&mut *w, seq_id, &reason).await {
                        warn!("Nack write to {} failed: {}", peer, e);
                    }
                });
            } else {
                debug!("No outbound to peer {} for nack (seq={})", peer, seq_id);
            }
        } else {
            debug!("No connection to peer {} for nack (seq={})", peer, seq_id);
        }
    }

    /// Accept an inbound stream from a peer (peer's outbound to us).
    ///
    /// If we already have a healthy inbound from this peer, drop the new one.
    /// Independent of our outbound — closing inbound never kills outbound.
    pub fn accept_stream(&mut self, peer: PeerId, stream: libp2p::Stream, tier: u8) {
        let pc = self.get_or_create_peer(peer);
        pc.tier.store(tier, Ordering::Relaxed);

        if let Some(ref inbound) = pc.inbound {
            if !inbound.reader_handle.is_finished() {
                debug!("Already have healthy inbound from {} — dropping", peer);
                drop(stream);
                return;
            }
        }

        // Clear cooldown — peer clearly supports the protocol
        self.open_cooldown.remove(&peer);

        self.register_inbound(peer, stream);
        debug!("Accepted inbound from peer {} (tier={})", peer, tier);

        // Peer can reach us — ensure we can reach them too.
        self.ensure_opening(peer);
    }

    /// Clear the open cooldown for a peer, allowing immediate retry.
    /// Call this when a new connection is established to avoid stale cooldowns
    /// blocking stream opens.
    pub fn clear_open_cooldown(&mut self, peer: &PeerId) {
        self.open_cooldown.remove(peer);
    }

    /// Ensure our outbound stream to this peer is opening.
    ///
    /// No PeerId tiebreak — each side opens its own outbound independently.
    /// Two streams per pair is intentional (one per direction).
    pub fn ensure_opening(&mut self, peer: PeerId) {
        if self.peers.get(&peer).map_or(false, |pc| pc.outbound.is_some()) {
            return;
        }
        if self.opening.contains(&peer) {
            return;
        }
        // Respect cooldown after failed opens
        if let Some(&deadline) = self.open_cooldown.get(&peer) {
            if Instant::now() < deadline {
                return;
            }
            self.open_cooldown.remove(&peer);
        }
        self.spawn_open(peer);
    }

    /// Spawn a background open_stream task for a peer.
    fn spawn_open(&mut self, peer: PeerId) {
        self.opening.insert(peer);
        let mut control = self.control.clone();
        let tx = self.open_result_tx.clone();
        tokio::spawn(async move {
            debug!("Background: opening outbound to {} ...", peer);
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
                    warn!("Background: outbound open to {} failed: {}", peer, e);
                    let _ = tx.send((
                        peer,
                        Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionRefused,
                            format!("open_stream failed: {}", e),
                        )),
                    ));
                }
                Err(_) => {
                    warn!("Background: outbound open to {} timed out (10s)", peer);
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

    /// Collect completed background outbound opens and drain write failures.
    pub fn poll_open_streams(&mut self) -> usize {
        let mut opened = 0;
        while let Ok((peer, result)) = self.open_result_rx.try_recv() {
            self.opening.remove(&peer);
            match result {
                Ok(stream) => {
                    if self.peers.get(&peer).map_or(false, |pc| pc.outbound.is_some()) {
                        debug!("Outbound to {} ready but already have one — dropping", peer);
                        continue;
                    }
                    self.register_outbound(peer, stream);
                    debug!("Opened outbound to peer {}", peer);
                    opened += 1;
                }
                Err(e) => {
                    debug!("Background outbound open to {} failed: {}", peer, e);
                    self.open_cooldown.insert(
                        peer,
                        Instant::now() + std::time::Duration::from_secs(OPEN_RETRY_COOLDOWN_SECS),
                    );
                }
            }
        }

        // Drain write failures from the background writer task.
        // The writer task already removed the dead stream from the registry;
        // we close the outbound handle and re-open.
        while let Ok(peer) = self.write_fail_rx.try_recv() {
            self.close_outbound(&peer);
            self.ensure_opening(peer);
        }

        // Drain stream-needed signals from the writer loop's retry buffer.
        // Deduplicate to avoid redundant ensure_opening calls when many
        // buffered shards target the same unreachable peer.
        {
            let mut need_peers = HashSet::new();
            while let Ok(peer) = self.need_stream_rx.try_recv() {
                need_peers.insert(peer);
            }
            for peer in need_peers {
                self.ensure_opening(peer);
            }
        }

        opened
    }

    /// Number of peers with outbound streams (can send to).
    pub fn stream_count(&self) -> usize {
        self.peers.values().filter(|pc| pc.outbound.is_some()).count()
    }

    /// Number of outbound opens in flight.
    pub fn pending_count(&self) -> usize {
        self.opening.len()
    }

    /// Update a peer's subscription tier.
    pub fn update_peer_tier(&mut self, peer: &PeerId, tier: u8) {
        if let Some(pc) = self.peers.get(peer) {
            pc.tier.store(tier, Ordering::Relaxed);
        }
    }

    /// Check if we have an outbound stream to a peer (can send).
    pub fn has_stream(&self, peer: &PeerId) -> bool {
        self.peers.get(peer).map_or(false, |pc| pc.outbound.is_some())
    }

    /// Return all peers we have outbound streams to.
    pub fn stream_peers(&self) -> Vec<PeerId> {
        self.peers
            .iter()
            .filter(|(_, pc)| pc.outbound.is_some())
            .map(|(id, _)| *id)
            .collect()
    }

    /// Close our outbound to a peer. Does not affect inbound.
    fn close_outbound(&mut self, peer: &PeerId) {
        if let Some(pc) = self.peers.get_mut(peer) {
            if pc.outbound.take().is_some() {
                self.writer_registry.write().unwrap().remove(peer);
                debug!("Closed outbound to {}", peer);
            }
        }
        self.maybe_remove_peer(peer);
    }

    /// Close inbound from a peer. Does not affect outbound.
    fn close_inbound(&mut self, peer: &PeerId) {
        if let Some(pc) = self.peers.get_mut(peer) {
            if let Some(inbound) = pc.inbound.take() {
                inbound.reader_handle.abort();
                debug!("Closed inbound from {}", peer);
            }
        }
        self.maybe_remove_peer(peer);
    }

    /// Remove PeerConnection entry if both directions are gone.
    fn maybe_remove_peer(&mut self, peer: &PeerId) {
        if let Some(pc) = self.peers.get(peer) {
            if pc.outbound.is_none() && pc.inbound.is_none() {
                self.peers.remove(peer);
            }
        }
    }

    /// Remove a disconnected peer's streams (both directions).
    pub fn on_peer_disconnected(&mut self, peer: &PeerId) {
        self.opening.remove(peer);
        self.open_cooldown.remove(peer);
        // Close both directions independently
        if let Some(pc) = self.peers.remove(peer) {
            if pc.outbound.is_some() {
                self.writer_registry.write().unwrap().remove(peer);
            }
            if let Some(inbound) = pc.inbound {
                inbound.reader_handle.abort();
            }
            debug!("Disconnected peer {} — closed both directions", peer);
        }
    }

    /// Clean up dead inbound readers.
    ///
    /// Only handles inbound — outbound failures are detected on write.
    /// Does not re-open: the peer re-establishes their outbound to us.
    pub fn cleanup_dead_streams(&mut self) {
        let dead: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(_, pc)| {
                pc.inbound
                    .as_ref()
                    .map_or(false, |i| i.reader_handle.is_finished())
            })
            .map(|(peer, _)| *peer)
            .collect();

        for peer in dead {
            debug!("Inbound from {} has dead reader — removing", peer);
            self.close_inbound(&peer);
        }
    }

    /// Get or create a PeerConnection entry.
    fn get_or_create_peer(&mut self, peer: PeerId) -> &mut PeerConnection {
        self.peers.entry(peer).or_insert_with(|| PeerConnection {
            outbound: None,
            inbound: None,
            pending_acks: Arc::new(std::sync::Mutex::new(HashMap::new())),
            tier: Arc::new(AtomicU8::new(0)),
        })
    }

    /// Register a newly opened stream as our outbound to a peer.
    fn register_outbound(&mut self, peer: PeerId, stream: libp2p::Stream) {
        let writer_arc = Arc::new(Mutex::new(stream));
        let seq_arc = Arc::new(AtomicU64::new(0));
        let poisoned_arc = Arc::new(AtomicBool::new(false));

        self.writer_registry
            .write()
            .unwrap()
            .insert(peer, PeerWriterHandle {
                writer: writer_arc.clone(),
                next_seq: seq_arc.clone(),
                poisoned: poisoned_arc,
            });

        let pc = self.get_or_create_peer(peer);
        pc.outbound = Some(OutboundHandle {
            writer: writer_arc,
            next_seq: seq_arc,
        });
    }

    /// Register a peer's stream as our inbound (spawn reader task).
    fn register_inbound(&mut self, peer: PeerId, stream: libp2p::Stream) {
        // Grab shared state from the PeerConnection before spawning
        let pc = self.get_or_create_peer(peer);
        let tier = pc.tier.clone();
        let pending_acks = pc.pending_acks.clone();

        // Abort old reader if replacing a dead one
        if let Some(old) = pc.inbound.take() {
            old.reader_handle.abort();
        }

        let reader_handle = tokio::spawn(Self::reader_loop(
            peer,
            stream,
            pending_acks,
            self.inbound_high_tx.clone(),
            self.inbound_low_tx.clone(),
            self.receipt_tx.clone(),
            tier,
        ));

        self.peers.get_mut(&peer).unwrap().inbound = Some(InboundHandle { reader_handle });
    }

    /// Background writer task for fire-and-forget outbound shards.
    ///
    /// Single-threaded: processes one shard at a time from the channel.
    /// If no writer exists for a peer, the shard is buffered for retry.
    /// A periodic flush drains the retry buffer so shards aren't lost
    /// when stream opens complete asynchronously.
    async fn outbound_writer_loop(
        registry: WriterRegistry,
        mut rx: mpsc::Receiver<OutboundShard>,
        write_fail_tx: mpsc::UnboundedSender<PeerId>,
        need_stream_tx: mpsc::UnboundedSender<PeerId>,
    ) {
        let mut retry_buf: VecDeque<OutboundShard> = VecDeque::new();
        let mut flush_interval = tokio::time::interval(std::time::Duration::from_millis(100));
        flush_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Channel for spawned write tasks to return failed shards for retry.
        let (write_retry_tx, mut write_retry_rx) = mpsc::unbounded_channel::<OutboundShard>();

        loop {
            tokio::select! {
                biased;
                msg = rx.recv() => {
                    let Some(outbound) = msg else {
                        debug!("Outbound writer channel closed, exiting");
                        break;
                    };
                    Self::try_write_or_buffer(&registry, &write_fail_tx, &need_stream_tx, &write_retry_tx, outbound, &mut retry_buf);
                }
                // Reclaim shards from failed writes for retry on fresh streams.
                retry_msg = write_retry_rx.recv() => {
                    if let Some(outbound) = retry_msg {
                        if retry_buf.len() < 1024 {
                            retry_buf.push_back(outbound);
                        }
                    }
                }
                _ = flush_interval.tick() => {
                    Self::flush_retry_buffer(&registry, &write_fail_tx, &need_stream_tx, &write_retry_tx, &mut retry_buf);
                }
            }
        }
    }

    /// Try to write a shard; if no writer exists, buffer for retry.
    fn try_write_or_buffer(
        registry: &WriterRegistry,
        write_fail_tx: &mpsc::UnboundedSender<PeerId>,
        need_stream_tx: &mpsc::UnboundedSender<PeerId>,
        write_retry_tx: &mpsc::UnboundedSender<OutboundShard>,
        outbound: OutboundShard,
        retry_buf: &mut VecDeque<OutboundShard>,
    ) {
        let handle = {
            let reg = registry.read().unwrap();
            reg.get(&outbound.peer)
                .map(|h| (h.writer.clone(), h.next_seq.clone(), h.poisoned.clone()))
        };

        if let Some((writer, next_seq, poisoned)) = handle {
            // If the stream is already known-dead, skip the write and buffer for retry.
            if poisoned.load(Ordering::Relaxed) {
                if retry_buf.len() < 1024 {
                    retry_buf.push_back(outbound);
                }
                return;
            }
            let peer = outbound.peer;
            let seq_id = next_seq.fetch_add(1, Ordering::Relaxed);
            let wf_tx = write_fail_tx.clone();
            let retry_tx = write_retry_tx.clone();
            let reg = registry.clone();
            tokio::spawn(async move {
                // Double-check poison after acquiring mutex (another task may have failed first).
                if poisoned.load(Ordering::Relaxed) {
                    let _ = retry_tx.send(outbound);
                    return;
                }
                let mut w = writer.lock().await;
                if let Err(e) = write_shard_frame(&mut *w, &outbound.shard, seq_id).await {
                    warn!("Outbound write to {} failed: {}", peer, e);
                    // Poison the handle so other in-flight tasks skip immediately.
                    poisoned.store(true, Ordering::Relaxed);
                    drop(w);
                    reg.write().unwrap().remove(&peer);
                    let _ = wf_tx.send(peer);
                    // Return the shard for retry on a fresh stream.
                    let _ = retry_tx.send(outbound);
                }
            });
        } else {
            // No writer yet — buffer for retry (stream may be opening).
            // Signal StreamManager to ensure a stream is being opened.
            let _ = need_stream_tx.send(outbound.peer);
            if retry_buf.len() < 1024 {
                retry_buf.push_back(outbound);
            } else {
                warn!("Retry buffer full — dropping shard for {}", outbound.peer);
            }
        }
    }

    /// Flush buffered shards that now have writers available.
    fn flush_retry_buffer(
        registry: &WriterRegistry,
        write_fail_tx: &mpsc::UnboundedSender<PeerId>,
        need_stream_tx: &mpsc::UnboundedSender<PeerId>,
        write_retry_tx: &mpsc::UnboundedSender<OutboundShard>,
        retry_buf: &mut VecDeque<OutboundShard>,
    ) {
        let mut remaining = VecDeque::new();
        let mut need_stream: HashSet<PeerId> = HashSet::new();
        while let Some(outbound) = retry_buf.pop_front() {
            let handle = {
                let reg = registry.read().unwrap();
                reg.get(&outbound.peer)
                    .map(|h| (h.writer.clone(), h.next_seq.clone(), h.poisoned.clone()))
            };
            if let Some((writer, next_seq, poisoned)) = handle {
                // Skip poisoned streams — they'll be cleaned up and re-opened.
                if poisoned.load(Ordering::Relaxed) {
                    remaining.push_back(outbound);
                    continue;
                }
                let peer = outbound.peer;
                let seq_id = next_seq.fetch_add(1, Ordering::Relaxed);
                let wf_tx = write_fail_tx.clone();
                let retry_tx = write_retry_tx.clone();
                let reg = registry.clone();
                tokio::spawn(async move {
                    if poisoned.load(Ordering::Relaxed) {
                        let _ = retry_tx.send(outbound);
                        return;
                    }
                    let mut w = writer.lock().await;
                    if let Err(e) = write_shard_frame(&mut *w, &outbound.shard, seq_id).await {
                        warn!("Outbound write to {} failed: {}", peer, e);
                        poisoned.store(true, Ordering::Relaxed);
                        drop(w);
                        reg.write().unwrap().remove(&peer);
                        let _ = wf_tx.send(peer);
                        let _ = retry_tx.send(outbound);
                    }
                });
            } else {
                need_stream.insert(outbound.peer);
                remaining.push_back(outbound);
            }
        }
        *retry_buf = remaining;
        for peer in need_stream {
            let _ = need_stream_tx.send(peer);
        }
    }

    /// Reader loop for a peer's inbound stream.
    ///
    /// Reads frames in a loop. Shard frames dispatch to priority channels.
    /// Ack/nack frames resolve pending_acks (from shards we sent on our outbound).
    async fn reader_loop(
        peer: PeerId,
        mut stream: libp2p::Stream,
        pending_acks: Arc<std::sync::Mutex<HashMap<u64, oneshot::Sender<AckResult>>>>,
        inbound_high_tx: mpsc::Sender<InboundShard>,
        inbound_low_tx: mpsc::Sender<InboundShard>,
        receipt_tx: mpsc::Sender<ForwardReceipt>,
        tier: Arc<AtomicU8>,
    ) {
        loop {
            match read_frame(&mut stream).await {
                Ok(StreamFrame::Shard { seq_id, shard }) => {
                    let inbound = InboundShard {
                        peer,
                        seq_id,
                        shard,
                    };
                    if tier.load(Ordering::Relaxed) > 0 {
                        match inbound_high_tx.try_send(inbound) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                warn!("High-priority inbound full for {} — dropping shard", peer);
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                break;
                            }
                        }
                    } else {
                        match inbound_low_tx.try_send(inbound) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                warn!("Low-priority inbound full for {} — dropping shard", peer);
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                break;
                            }
                        }
                    }
                }
                Ok(StreamFrame::Ack { seq_id, receipt }) => {
                    let sender = pending_acks.lock().unwrap().remove(&seq_id);
                    if let Some(tx) = sender {
                        let _ = tx.send(AckResult::Accepted(receipt.clone().map(Box::new)));
                    }
                    if let Some(r) = receipt {
                        let _ = receipt_tx.try_send(r);
                    }
                }
                Ok(StreamFrame::Nack { seq_id, reason }) => {
                    let sender = pending_acks.lock().unwrap().remove(&seq_id);
                    if let Some(tx) = sender {
                        let _ = tx.send(AckResult::Rejected(reason.clone()));
                    }
                    debug!("Nack from {} (seq={}): {}", peer, seq_id, reason);
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        debug!("Inbound from {} closed (EOF)", peer);
                    } else {
                        warn!("Inbound read error from {}: {}", peer, e);
                    }
                    break;
                }
            }
        }

        debug!("Reader loop ended for peer {}", peer);
    }
}
