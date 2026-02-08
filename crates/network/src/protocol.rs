//! Shard protocol for TunnelCraft
//!
//! Custom libp2p request-response protocol for sending and receiving shards between peers.

use std::io;

use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use libp2p::request_response::{self, Codec};
use libp2p::StreamProtocol;
use tunnelcraft_core::{ForwardReceipt, Shard, SHARD_MAGIC, SHARD_VERSION};

/// Protocol identifier for shard messages
pub const SHARD_PROTOCOL_ID: StreamProtocol = StreamProtocol::new("/tunnelcraft/shard/1.0.0");

/// Maximum shard message size (8KB — header + 6KB payload per shard)
pub const MAX_SHARD_SIZE: usize = 8 * 1024;

/// Shard protocol handler (marker type for request-response behaviour)
#[derive(Debug, Clone, Default)]
pub struct ShardProtocol;

impl ShardProtocol {
    pub fn new() -> Self {
        Self
    }
}

/// A shard request sent to a peer
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
    Accepted(Option<ForwardReceipt>),
    /// Shard was rejected with reason
    Rejected(String),
}

/// Codec for encoding/decoding shard messages
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
                // Accepted without receipt (legacy / client endpoints)
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

                Ok(ShardResponse::Accepted(Some(receipt)))
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

/// Type alias for the shard request-response behaviour
pub type ShardBehaviour = request_response::Behaviour<ShardCodec>;

/// Create a new shard behaviour
pub fn new_shard_behaviour() -> ShardBehaviour {
    request_response::Behaviour::new(
        [(SHARD_PROTOCOL_ID, request_response::ProtocolSupport::Full)],
        request_response::Config::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_protocol_id() {
        assert_eq!(
            SHARD_PROTOCOL_ID.as_ref(),
            "/tunnelcraft/shard/1.0.0"
        );
    }

    #[test]
    fn test_shard_protocol_new() {
        let _protocol = ShardProtocol::new();
    }

    #[test]
    fn test_shard_protocol_default() {
        let _protocol = ShardProtocol::default();
    }

    #[test]
    fn test_max_shard_size() {
        assert_eq!(MAX_SHARD_SIZE, 8 * 1024);
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
        let user_pubkey = [4u8; 32];
        let shard = Shard::new_request(
            [1u8; 32], [2u8; 32], user_pubkey, [5u8; 32],
            3, vec![0u8; 100], 0, 5, 3, 0, 1,
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
        let user_pubkey = [4u8; 32];
        let shard = Shard::new_request(
            [1u8; 32], [2u8; 32], user_pubkey, [5u8; 32],
            3, vec![0xAB, 0xCD, 0xEF], 0, 5, 3, 0, 1,
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

        assert_eq!(decoded.shard.shard_id, [1u8; 32]);
        assert_eq!(decoded.shard.payload, vec![0xAB, 0xCD, 0xEF]);
    }

    #[tokio::test]
    async fn test_codec_response_accepted_roundtrip() {
        let response = ShardResponse::Accepted(None);

        let mut codec = ShardCodec::new();
        let mut buffer = Vec::new();

        // Write response
        {
            let mut cursor = futures::io::Cursor::new(&mut buffer);
            codec.write_response(&SHARD_PROTOCOL_ID, &mut cursor, response)
                .await
                .unwrap();
        }

        // Read response back
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

        // Write response
        {
            let mut cursor = futures::io::Cursor::new(&mut buffer);
            codec.write_response(&SHARD_PROTOCOL_ID, &mut cursor, response)
                .await
                .unwrap();
        }

        // Read response back
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
        let buffer = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0x00, 0x10];

        let mut cursor = futures::io::Cursor::new(&buffer);
        let result = codec.read_request(&SHARD_PROTOCOL_ID, &mut cursor).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("magic"));
    }

    #[tokio::test]
    async fn test_codec_invalid_version() {
        let mut codec = ShardCodec::new();
        // Valid magic, but wrong version (99)
        let mut buffer = SHARD_MAGIC.to_vec();
        buffer.push(99);

        let mut cursor = futures::io::Cursor::new(&buffer);
        let result = codec.read_request(&SHARD_PROTOCOL_ID, &mut cursor).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("version"));
    }

    #[tokio::test]
    async fn test_codec_shard_too_large() {
        let mut codec = ShardCodec::with_max_size(100);
        // Valid header claiming 1000 bytes
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
        let buffer = vec![99]; // Unknown response type

        let mut cursor = futures::io::Cursor::new(&buffer);
        let result = codec.read_response(&SHARD_PROTOCOL_ID, &mut cursor).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown response type"));
    }

    #[test]
    fn test_new_shard_behaviour() {
        let _behaviour = new_shard_behaviour();
    }
}
