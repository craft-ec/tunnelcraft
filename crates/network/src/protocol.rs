//! Shard protocol for TunnelCraft
//!
//! Custom libp2p request-response protocol for sending and receiving shards between peers.

use std::io;

use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
#[allow(unused_imports)]
use libp2p::request_response::{self, Codec};
use libp2p::StreamProtocol;
use tunnelcraft_core::{ForwardReceipt, Shard, SHARD_MAGIC, SHARD_VERSION};

/// Protocol identifier for shard messages
pub const SHARD_PROTOCOL_ID: StreamProtocol = StreamProtocol::new("/tunnelcraft/shard/2.0.0");

/// Maximum shard message size (10KB — onion header + payload per shard)
pub const MAX_SHARD_SIZE: usize = 10 * 1024;

/// Shard protocol handler (marker type for request-response behaviour)
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct ShardProtocol;

#[allow(dead_code)]
impl ShardProtocol {
    pub fn new() -> Self {
        Self
    }
}

/// A shard request sent to a peer
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ShardRequest {
    pub shard: Shard,
}

/// A shard response from a peer
#[derive(Debug, Clone)]
pub enum ShardResponse {
    /// Shard was accepted and forwarded/processed.
    /// Contains an optional ForwardReceipt — a cryptographic proof that
    /// the receiver got the shard. The sender uses this for settlement.
    Accepted(Option<Box<ForwardReceipt>>),
    /// Shard was rejected with reason
    Rejected(String),
}

/// Codec for encoding/decoding shard messages
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ShardCodec {
    max_size: usize,
}

impl Default for ShardCodec {
    fn default() -> Self {
        Self {
            max_size: MAX_SHARD_SIZE,
        }
    }
}

#[allow(dead_code)]
impl ShardCodec {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_size(max_size: usize) -> Self {
        Self { max_size }
    }
}

#[async_trait]
impl Codec for ShardCodec {
    type Protocol = StreamProtocol;
    type Request = ShardRequest;
    type Response = ShardResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        // Read and validate magic bytes
        let mut magic = [0u8; 4];
        io.read_exact(&mut magic).await?;
        if magic != SHARD_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid shard magic bytes",
            ));
        }

        // Read version
        let mut version = [0u8; 1];
        io.read_exact(&mut version).await?;
        if version[0] != SHARD_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported shard version: {}", version[0]),
            ));
        }

        // Read length (4 bytes, big-endian)
        let mut len_bytes = [0u8; 4];
        io.read_exact(&mut len_bytes).await?;
        let len = u32::from_be_bytes(len_bytes) as usize;

        if len > self.max_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Shard too large: {} > {}", len, self.max_size),
            ));
        }

        // Read shard data
        let mut data = vec![0u8; len];
        io.read_exact(&mut data).await?;

        // Deserialize shard
        let shard = Shard::from_bytes(&data).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("Invalid shard: {}", e))
        })?;

        Ok(ShardRequest { shard })
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        // Read response type (1 byte)
        let mut response_type = [0u8; 1];
        io.read_exact(&mut response_type).await?;

        match response_type[0] {
            0 => {
                // Accepted without receipt
                Ok(ShardResponse::Accepted(None))
            }
            1 => {
                // Read rejection reason length
                let mut len_bytes = [0u8; 2];
                io.read_exact(&mut len_bytes).await?;
                let len = u16::from_be_bytes(len_bytes) as usize;

                if len > 1024 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Rejection reason too long",
                    ));
                }

                // Read reason string
                let mut reason_bytes = vec![0u8; len];
                io.read_exact(&mut reason_bytes).await?;
                let reason = String::from_utf8(reason_bytes).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8 in rejection reason")
                })?;

                Ok(ShardResponse::Rejected(reason))
            }
            2 => {
                // Accepted with ForwardReceipt
                let mut receipt_len_bytes = [0u8; 4];
                io.read_exact(&mut receipt_len_bytes).await?;
                let receipt_len = u32::from_be_bytes(receipt_len_bytes) as usize;

                if receipt_len > 4096 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Receipt too large",
                    ));
                }

                let mut receipt_bytes = vec![0u8; receipt_len];
                io.read_exact(&mut receipt_bytes).await?;

                let receipt: ForwardReceipt = bincode::deserialize(&receipt_bytes).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("Invalid receipt: {}", e))
                })?;

                Ok(ShardResponse::Accepted(Some(Box::new(receipt))))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unknown response type: {}", response_type[0]),
            )),
        }
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        // Serialize shard
        let data = request.shard.to_bytes().map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("Failed to serialize shard: {}", e))
        })?;

        if data.len() > self.max_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Shard too large: {} > {}", data.len(), self.max_size),
            ));
        }

        // Write magic bytes
        io.write_all(&SHARD_MAGIC).await?;

        // Write version
        io.write_all(&[SHARD_VERSION]).await?;

        // Write length
        let len = data.len() as u32;
        io.write_all(&len.to_be_bytes()).await?;

        // Write shard data
        io.write_all(&data).await?;

        io.flush().await?;

        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        match response {
            ShardResponse::Accepted(None) => {
                io.write_all(&[0]).await?;
            }
            ShardResponse::Accepted(Some(receipt)) => {
                io.write_all(&[2]).await?;

                let receipt_bytes = bincode::serialize(&receipt).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("Failed to serialize receipt: {}", e))
                })?;
                let len = receipt_bytes.len() as u32;
                io.write_all(&len.to_be_bytes()).await?;
                io.write_all(&receipt_bytes).await?;
            }
            ShardResponse::Rejected(reason) => {
                io.write_all(&[1]).await?;

                // Truncate reason if too long
                let reason_bytes = reason.as_bytes();
                let len = reason_bytes.len().min(1024) as u16;
                io.write_all(&len.to_be_bytes()).await?;
                io.write_all(&reason_bytes[..len as usize]).await?;
            }
        }

        io.flush().await?;

        Ok(())
    }
}

// ============================================================================
// Persistent stream protocol (replaces per-shard request-response)
// ============================================================================

/// Protocol identifier for persistent shard streams
pub const SHARD_STREAM_PROTOCOL: libp2p::StreamProtocol =
    libp2p::StreamProtocol::new("/tunnelcraft/shard-stream/1.0.0");

/// Frame type bytes
const FRAME_TYPE_SHARD: u8 = 0x01;
const FRAME_TYPE_ACK: u8 = 0x02;
const FRAME_TYPE_NACK: u8 = 0x03;

/// Maximum frame payload size (64KB — generous for onion-wrapped shards)
const MAX_FRAME_PAYLOAD: usize = 64 * 1024;

/// A frame on a persistent shard stream.
///
/// Wire format: `[type: u8] [length: u32 BE] [payload: length bytes]`
#[derive(Debug, Clone)]
pub enum StreamFrame {
    /// A shard with a sequence ID for ack correlation
    Shard {
        seq_id: u64,
        shard: Shard,
    },
    /// Acknowledgment of a shard, optionally carrying a ForwardReceipt
    Ack {
        seq_id: u64,
        receipt: Option<ForwardReceipt>,
    },
    /// Negative acknowledgment with a reason string
    Nack {
        seq_id: u64,
        reason: String,
    },
}

/// Read a single frame from an async stream (futures::io).
pub async fn read_frame<T: AsyncRead + Unpin>(io: &mut T) -> io::Result<StreamFrame> {
    // Read type byte
    let mut ty = [0u8; 1];
    io.read_exact(&mut ty).await?;

    // Read length
    let mut len_bytes = [0u8; 4];
    io.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;

    if len > MAX_FRAME_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Frame payload too large: {} > {}", len, MAX_FRAME_PAYLOAD),
        ));
    }

    // Read payload
    let mut payload = vec![0u8; len];
    io.read_exact(&mut payload).await?;

    match ty[0] {
        FRAME_TYPE_SHARD => {
            if payload.len() < 8 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Shard frame too short for seq_id",
                ));
            }
            let seq_id = u64::from_be_bytes(payload[..8].try_into().unwrap());
            let shard_bytes = &payload[8..];
            let shard = Shard::from_bytes(shard_bytes).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("Invalid shard: {}", e))
            })?;
            Ok(StreamFrame::Shard { seq_id, shard })
        }
        FRAME_TYPE_ACK => {
            if payload.len() < 9 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Ack frame too short",
                ));
            }
            let seq_id = u64::from_be_bytes(payload[..8].try_into().unwrap());
            let has_receipt = payload[8];
            let receipt = if has_receipt == 1 && payload.len() > 9 {
                let receipt: ForwardReceipt =
                    bincode::deserialize(&payload[9..]).map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Invalid receipt: {}", e),
                        )
                    })?;
                Some(receipt)
            } else {
                None
            };
            Ok(StreamFrame::Ack { seq_id, receipt })
        }
        FRAME_TYPE_NACK => {
            if payload.len() < 10 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Nack frame too short",
                ));
            }
            let seq_id = u64::from_be_bytes(payload[..8].try_into().unwrap());
            let reason_len =
                u16::from_be_bytes(payload[8..10].try_into().unwrap()) as usize;
            if payload.len() < 10 + reason_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Nack reason truncated",
                ));
            }
            let reason = String::from_utf8(payload[10..10 + reason_len].to_vec())
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8 in nack reason")
                })?;
            Ok(StreamFrame::Nack { seq_id, reason })
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Unknown frame type: 0x{:02x}", ty[0]),
        )),
    }
}

/// Write a shard frame to an async stream.
///
/// Builds the entire frame in memory first, then writes it in a single
/// `write_all` call. This prevents stream desync if the connection dies
/// mid-frame (partial header would leave the reader misaligned).
pub async fn write_shard_frame<T: AsyncWrite + Unpin>(
    io: &mut T,
    shard: &Shard,
    seq_id: u64,
) -> io::Result<()> {
    let shard_bytes = shard.to_bytes().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to serialize shard: {}", e),
        )
    })?;
    let payload_len = 8 + shard_bytes.len();

    // Enforce the same limit the reader enforces — fail fast, don't desync
    if payload_len > MAX_FRAME_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Shard frame payload too large: {} > {} (shard_bytes={})",
                payload_len, MAX_FRAME_PAYLOAD, shard_bytes.len()
            ),
        ));
    }

    // Build complete frame in one buffer: [type:1][length:4][seq_id:8][shard_bytes:N]
    let frame_len = 1 + 4 + payload_len;
    let mut buf = Vec::with_capacity(frame_len);
    buf.push(FRAME_TYPE_SHARD);
    buf.extend_from_slice(&(payload_len as u32).to_be_bytes());
    buf.extend_from_slice(&seq_id.to_be_bytes());
    buf.extend_from_slice(&shard_bytes);

    io.write_all(&buf).await?;
    io.flush().await?;

    Ok(())
}

/// Write an ack frame to an async stream (atomic single write).
pub async fn write_ack_frame<T: AsyncWrite + Unpin>(
    io: &mut T,
    seq_id: u64,
    receipt: Option<&ForwardReceipt>,
) -> io::Result<()> {
    let receipt_bytes = match receipt {
        Some(r) => bincode::serialize(r).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to serialize receipt: {}", e),
            )
        })?,
        None => Vec::new(),
    };
    let has_receipt: u8 = if receipt.is_some() { 1 } else { 0 };
    let payload_len = 8 + 1 + receipt_bytes.len();

    if payload_len > MAX_FRAME_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Ack frame payload too large: {} > {}", payload_len, MAX_FRAME_PAYLOAD),
        ));
    }

    let frame_len = 1 + 4 + payload_len;
    let mut buf = Vec::with_capacity(frame_len);
    buf.push(FRAME_TYPE_ACK);
    buf.extend_from_slice(&(payload_len as u32).to_be_bytes());
    buf.extend_from_slice(&seq_id.to_be_bytes());
    buf.push(has_receipt);
    buf.extend_from_slice(&receipt_bytes);

    io.write_all(&buf).await?;
    io.flush().await?;

    Ok(())
}

/// Write a nack frame to an async stream (atomic single write).
pub async fn write_nack_frame<T: AsyncWrite + Unpin>(
    io: &mut T,
    seq_id: u64,
    reason: &str,
) -> io::Result<()> {
    let reason_bytes = reason.as_bytes();
    let reason_len = reason_bytes.len().min(1024);
    let payload_len = 8 + 2 + reason_len;

    let frame_len = 1 + 4 + payload_len;
    let mut buf = Vec::with_capacity(frame_len);
    buf.push(FRAME_TYPE_NACK);
    buf.extend_from_slice(&(payload_len as u32).to_be_bytes());
    buf.extend_from_slice(&seq_id.to_be_bytes());
    buf.extend_from_slice(&(reason_len as u16).to_be_bytes());
    buf.extend_from_slice(&reason_bytes[..reason_len]);

    io.write_all(&buf).await?;
    io.flush().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_protocol_id() {
        assert_eq!(
            SHARD_PROTOCOL_ID.as_ref(),
            "/tunnelcraft/shard/2.0.0"
        );
    }

    #[test]
    fn test_shard_protocol_new() {
        let _protocol = ShardProtocol::new();
    }

    #[test]
    fn test_shard_protocol_default() {
        let _protocol = ShardProtocol;
    }

    #[test]
    fn test_max_shard_size() {
        assert_eq!(MAX_SHARD_SIZE, 10 * 1024);
    }

    #[test]
    fn test_shard_codec_default() {
        let codec = ShardCodec::new();
        assert_eq!(codec.max_size, MAX_SHARD_SIZE);
    }

    #[test]
    fn test_shard_codec_with_max_size() {
        let codec = ShardCodec::with_max_size(1024);
        assert_eq!(codec.max_size, 1024);
    }

    #[test]
    fn test_shard_request_clone() {
        let shard = Shard::new(
            [1u8; 32], vec![2, 3], vec![4, 5, 6],
            vec![0; 92],
        );
        let request = ShardRequest { shard };
        let _cloned = request.clone();
    }

    #[test]
    fn test_shard_response_variants() {
        let accepted = ShardResponse::Accepted(None);
        let rejected = ShardResponse::Rejected("test reason".to_string());

        match accepted {
            ShardResponse::Accepted(None) => {}
            _ => panic!("Expected Accepted(None)"),
        }

        match rejected {
            ShardResponse::Rejected(reason) => assert_eq!(reason, "test reason"),
            _ => panic!("Expected Rejected"),
        }
    }

    #[tokio::test]
    async fn test_codec_request_roundtrip() {
        let shard = Shard::new(
            [1u8; 32], vec![2, 3], vec![0xAB, 0xCD, 0xEF],
            vec![0; 92],
        );
        let request = ShardRequest { shard };

        let mut codec = ShardCodec::new();
        let mut buffer = Vec::new();

        // Write request
        {
            let mut cursor = futures::io::Cursor::new(&mut buffer);
            codec.write_request(&SHARD_PROTOCOL_ID, &mut cursor, request.clone())
                .await
                .unwrap();
        }

        // Read request back
        let mut cursor = futures::io::Cursor::new(&buffer);
        let decoded = codec.read_request(&SHARD_PROTOCOL_ID, &mut cursor)
            .await
            .unwrap();

        assert_eq!(decoded.shard.ephemeral_pubkey, [1u8; 32]);
        assert_eq!(decoded.shard.payload, vec![0xAB, 0xCD, 0xEF]);
    }

    #[tokio::test]
    async fn test_codec_response_accepted_roundtrip() {
        let response = ShardResponse::Accepted(None);

        let mut codec = ShardCodec::new();
        let mut buffer = Vec::new();

        {
            let mut cursor = futures::io::Cursor::new(&mut buffer);
            codec.write_response(&SHARD_PROTOCOL_ID, &mut cursor, response)
                .await
                .unwrap();
        }

        let mut cursor = futures::io::Cursor::new(&buffer);
        let decoded = codec.read_response(&SHARD_PROTOCOL_ID, &mut cursor)
            .await
            .unwrap();

        match decoded {
            ShardResponse::Accepted(None) => {}
            _ => panic!("Expected Accepted(None)"),
        }
    }

    #[tokio::test]
    async fn test_codec_response_rejected_roundtrip() {
        let response = ShardResponse::Rejected("destination mismatch".to_string());

        let mut codec = ShardCodec::new();
        let mut buffer = Vec::new();

        {
            let mut cursor = futures::io::Cursor::new(&mut buffer);
            codec.write_response(&SHARD_PROTOCOL_ID, &mut cursor, response)
                .await
                .unwrap();
        }

        let mut cursor = futures::io::Cursor::new(&buffer);
        let decoded = codec.read_response(&SHARD_PROTOCOL_ID, &mut cursor)
            .await
            .unwrap();

        match decoded {
            ShardResponse::Rejected(reason) => assert_eq!(reason, "destination mismatch"),
            _ => panic!("Expected Rejected"),
        }
    }

    #[tokio::test]
    async fn test_codec_invalid_magic() {
        let mut codec = ShardCodec::new();
        let buffer = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x02, 0x00, 0x00, 0x00, 0x10];

        let mut cursor = futures::io::Cursor::new(&buffer);
        let result = codec.read_request(&SHARD_PROTOCOL_ID, &mut cursor).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("magic"));
    }

    #[tokio::test]
    async fn test_codec_invalid_version() {
        let mut codec = ShardCodec::new();
        let mut buffer = SHARD_MAGIC.to_vec();
        buffer.push(99); // wrong version

        let mut cursor = futures::io::Cursor::new(&buffer);
        let result = codec.read_request(&SHARD_PROTOCOL_ID, &mut cursor).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("version"));
    }

    #[tokio::test]
    async fn test_codec_shard_too_large() {
        let mut codec = ShardCodec::with_max_size(100);
        let mut buffer = SHARD_MAGIC.to_vec();
        buffer.push(SHARD_VERSION);
        buffer.extend_from_slice(&1000u32.to_be_bytes());

        let mut cursor = futures::io::Cursor::new(&buffer);
        let result = codec.read_request(&SHARD_PROTOCOL_ID, &mut cursor).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }

    #[tokio::test]
    async fn test_codec_unknown_response_type() {
        let mut codec = ShardCodec::new();
        let buffer = vec![99];

        let mut cursor = futures::io::Cursor::new(&buffer);
        let result = codec.read_response(&SHARD_PROTOCOL_ID, &mut cursor).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown response type"));
    }

    // ====================================================================
    // Stream frame protocol tests
    // ====================================================================

    #[test]
    fn test_stream_protocol_id() {
        assert_eq!(
            SHARD_STREAM_PROTOCOL.as_ref(),
            "/tunnelcraft/shard-stream/1.0.0"
        );
    }

    #[tokio::test]
    async fn test_stream_shard_frame_roundtrip() {
        let shard = Shard::new(
            [1u8; 32],
            vec![2u8; 64],
            b"stream payload".to_vec(),
            vec![3u8; 92],
        );

        let mut buffer = Vec::new();
        {
            let mut cursor = futures::io::Cursor::new(&mut buffer);
            write_shard_frame(&mut cursor, &shard, 42).await.unwrap();
        }

        let mut cursor = futures::io::Cursor::new(&buffer);
        let frame = read_frame(&mut cursor).await.unwrap();

        match frame {
            StreamFrame::Shard { seq_id, shard: decoded } => {
                assert_eq!(seq_id, 42);
                assert_eq!(decoded.ephemeral_pubkey, [1u8; 32]);
                assert_eq!(decoded.payload, b"stream payload");
            }
            _ => panic!("Expected Shard frame"),
        }
    }

    #[tokio::test]
    async fn test_stream_ack_frame_no_receipt() {
        let mut buffer = Vec::new();
        {
            let mut cursor = futures::io::Cursor::new(&mut buffer);
            write_ack_frame(&mut cursor, 99, None).await.unwrap();
        }

        let mut cursor = futures::io::Cursor::new(&buffer);
        let frame = read_frame(&mut cursor).await.unwrap();

        match frame {
            StreamFrame::Ack { seq_id, receipt } => {
                assert_eq!(seq_id, 99);
                assert!(receipt.is_none());
            }
            _ => panic!("Expected Ack frame"),
        }
    }

    #[tokio::test]
    async fn test_stream_ack_frame_with_receipt() {
        let receipt = ForwardReceipt {
            request_id: [10u8; 32],
            shard_id: [11u8; 32],
            sender_pubkey: [12u8; 32],
            receiver_pubkey: [13u8; 32],
            blind_token: [15u8; 32],
            payload_size: 1234,
            epoch: 1,
            timestamp: 1700000000,
            signature: [14u8; 64],
        };

        let mut buffer = Vec::new();
        {
            let mut cursor = futures::io::Cursor::new(&mut buffer);
            write_ack_frame(&mut cursor, 7, Some(&receipt)).await.unwrap();
        }

        let mut cursor = futures::io::Cursor::new(&buffer);
        let frame = read_frame(&mut cursor).await.unwrap();

        match frame {
            StreamFrame::Ack { seq_id, receipt: decoded } => {
                assert_eq!(seq_id, 7);
                let r = decoded.unwrap();
                assert_eq!(r.request_id, [10u8; 32]);
                assert_eq!(r.payload_size, 1234);
            }
            _ => panic!("Expected Ack frame"),
        }
    }

    #[tokio::test]
    async fn test_stream_nack_frame_roundtrip() {
        let mut buffer = Vec::new();
        {
            let mut cursor = futures::io::Cursor::new(&mut buffer);
            write_nack_frame(&mut cursor, 123, "not in relay mode").await.unwrap();
        }

        let mut cursor = futures::io::Cursor::new(&buffer);
        let frame = read_frame(&mut cursor).await.unwrap();

        match frame {
            StreamFrame::Nack { seq_id, reason } => {
                assert_eq!(seq_id, 123);
                assert_eq!(reason, "not in relay mode");
            }
            _ => panic!("Expected Nack frame"),
        }
    }

    #[tokio::test]
    async fn test_stream_unknown_frame_type() {
        let mut buffer = Vec::new();
        buffer.push(0xFF); // unknown type
        buffer.extend_from_slice(&4u32.to_be_bytes()); // length
        buffer.extend_from_slice(&[0, 0, 0, 0]); // dummy payload

        let mut cursor = futures::io::Cursor::new(&buffer);
        let result = read_frame(&mut cursor).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown frame type"));
    }

    #[tokio::test]
    async fn test_stream_frame_too_large() {
        let mut buffer = Vec::new();
        buffer.push(FRAME_TYPE_SHARD);
        buffer.extend_from_slice(&(100_000u32).to_be_bytes()); // > MAX_FRAME_PAYLOAD

        let mut cursor = futures::io::Cursor::new(&buffer);
        let result = read_frame(&mut cursor).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }
}
