//! TunnelCraft Erasure Coding
//!
//! Reed-Solomon encoding (5/3) for request/response fragmentation.
//! Requests/responses are split into 5 shards; only 3 needed for reconstruction.

use reed_solomon_erasure::galois_8::ReedSolomon;
use thiserror::Error;

/// Number of data shards (minimum needed for reconstruction)
pub const DATA_SHARDS: usize = 3;

/// Number of parity shards (redundancy)
pub const PARITY_SHARDS: usize = 2;

/// Total number of shards
pub const TOTAL_SHARDS: usize = DATA_SHARDS + PARITY_SHARDS;

#[derive(Error, Debug)]
pub enum ErasureError {
    #[error("Failed to create Reed-Solomon encoder: {0}")]
    EncoderCreationFailed(String),

    #[error("Encoding failed: {0}")]
    EncodingFailed(String),

    #[error("Decoding failed: {0}")]
    DecodingFailed(String),

    #[error("Insufficient shards: need {DATA_SHARDS}, got {0}")]
    InsufficientShards(usize),

    #[error("Invalid shard size: all shards must have equal length")]
    InvalidShardSize,

    #[error("Empty data")]
    EmptyData,
}

pub type Result<T> = std::result::Result<T, ErasureError>;

/// Erasure encoder/decoder using Reed-Solomon 5/3
pub struct ErasureCoder {
    rs: ReedSolomon,
}

impl ErasureCoder {
    /// Create a new erasure coder with 3 data shards and 2 parity shards
    pub fn new() -> Result<Self> {
        let rs = ReedSolomon::new(DATA_SHARDS, PARITY_SHARDS)
            .map_err(|e| ErasureError::EncoderCreationFailed(e.to_string()))?;
        Ok(Self { rs })
    }

    /// Encode data into 5 shards (3 data + 2 parity)
    ///
    /// Returns a vector of 5 shard buffers, each of equal size.
    /// The data is padded to be evenly divisible by DATA_SHARDS.
    pub fn encode(&self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        if data.is_empty() {
            return Err(ErasureError::EmptyData);
        }

        // Calculate shard size (pad data to be divisible by DATA_SHARDS)
        let shard_size = data.len().div_ceil(DATA_SHARDS);

        // Create data shards with padding
        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(TOTAL_SHARDS);

        for i in 0..DATA_SHARDS {
            let start = i * shard_size;
            let end = std::cmp::min(start + shard_size, data.len());

            let mut shard = vec![0u8; shard_size];
            if start < data.len() {
                let copy_len = end - start;
                shard[..copy_len].copy_from_slice(&data[start..end]);
            }
            shards.push(shard);
        }

        // Add empty parity shards
        for _ in 0..PARITY_SHARDS {
            shards.push(vec![0u8; shard_size]);
        }

        // Encode parity shards
        self.rs
            .encode(&mut shards)
            .map_err(|e| ErasureError::EncodingFailed(e.to_string()))?;

        Ok(shards)
    }

    /// Decode shards back into original data
    ///
    /// Takes a vector of Option<Vec<u8>> where None represents a missing shard.
    /// At least 3 shards must be present.
    /// Returns the original data (with padding removed based on original_len).
    pub fn decode(&self, shards: &mut [Option<Vec<u8>>], original_len: usize) -> Result<Vec<u8>> {
        if shards.len() != TOTAL_SHARDS {
            return Err(ErasureError::InvalidShardSize);
        }

        // Count available shards
        let available = shards.iter().filter(|s| s.is_some()).count();
        if available < DATA_SHARDS {
            return Err(ErasureError::InsufficientShards(available));
        }

        // Verify all present shards have the same size
        let shard_size = shards
            .iter()
            .filter_map(|s| s.as_ref())
            .next()
            .map(|s| s.len())
            .ok_or(ErasureError::InsufficientShards(0))?;

        for shard in shards.iter().flatten() {
            if shard.len() != shard_size {
                return Err(ErasureError::InvalidShardSize);
            }
        }

        // Reconstruct missing shards
        self.rs
            .reconstruct(shards)
            .map_err(|e| ErasureError::DecodingFailed(e.to_string()))?;

        // Combine data shards
        let mut data = Vec::with_capacity(DATA_SHARDS * shard_size);
        for s in shards.iter().take(DATA_SHARDS).flatten() {
            data.extend_from_slice(s);
        }

        // Trim to original length
        data.truncate(original_len);

        Ok(data)
    }

    /// Verify that shards can be reconstructed (without actually reconstructing)
    pub fn verify(&self, shards: &[Option<Vec<u8>>]) -> bool {
        let available = shards.iter().filter(|s| s.is_some()).count();
        available >= DATA_SHARDS
    }
}

impl Default for ErasureCoder {
    fn default() -> Self {
        Self::new().expect("Failed to create default ErasureCoder")
    }
}

/// Convenience function to encode data
pub fn encode(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    ErasureCoder::new()?.encode(data)
}

/// Convenience function to decode shards
pub fn decode(shards: &mut [Option<Vec<u8>>], original_len: usize) -> Result<Vec<u8>> {
    ErasureCoder::new()?.decode(shards, original_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_basic() {
        let coder = ErasureCoder::new().unwrap();
        let data = b"Hello, TunnelCraft! This is a test message for erasure coding.";

        let shards = coder.encode(data).unwrap();
        assert_eq!(shards.len(), TOTAL_SHARDS);

        // Convert to Option<Vec<u8>> for decoding
        let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        let decoded = coder.decode(&mut shard_opts, data.len()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_with_missing_shards() {
        let coder = ErasureCoder::new().unwrap();
        let data = b"Testing reconstruction with missing shards!";

        let shards = coder.encode(data).unwrap();
        let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        // Remove 2 shards (we can lose up to PARITY_SHARDS)
        shard_opts[0] = None;
        shard_opts[3] = None;

        let decoded = coder.decode(&mut shard_opts, data.len()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_with_max_missing() {
        let coder = ErasureCoder::new().unwrap();
        let data = b"Maximum loss test - losing exactly 2 shards";

        let shards = coder.encode(data).unwrap();
        let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        // Remove exactly PARITY_SHARDS (2) shards
        shard_opts[1] = None;
        shard_opts[4] = None;

        let decoded = coder.decode(&mut shard_opts, data.len()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_insufficient_shards() {
        let coder = ErasureCoder::new().unwrap();
        let data = b"This will fail";

        let shards = coder.encode(data).unwrap();
        let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        // Remove 3 shards (more than PARITY_SHARDS)
        shard_opts[0] = None;
        shard_opts[1] = None;
        shard_opts[2] = None;

        let result = coder.decode(&mut shard_opts, data.len());
        assert!(matches!(result, Err(ErasureError::InsufficientShards(_))));
    }

    #[test]
    fn test_verify() {
        let coder = ErasureCoder::new().unwrap();
        let data = b"Verify test";

        let shards = coder.encode(data).unwrap();
        let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        // All shards present
        assert!(coder.verify(&shard_opts));

        // Remove 2 shards - still verifiable
        shard_opts[0] = None;
        shard_opts[1] = None;
        assert!(coder.verify(&shard_opts));

        // Remove 3rd shard - not verifiable
        shard_opts[2] = None;
        assert!(!coder.verify(&shard_opts));
    }

    #[test]
    fn test_empty_data() {
        let coder = ErasureCoder::new().unwrap();
        let result = coder.encode(b"");
        assert!(matches!(result, Err(ErasureError::EmptyData)));
    }

    #[test]
    fn test_small_data() {
        let coder = ErasureCoder::new().unwrap();
        let data = b"Hi";

        let shards = coder.encode(data).unwrap();
        let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        let decoded = coder.decode(&mut shard_opts, data.len()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_large_data() {
        let coder = ErasureCoder::new().unwrap();
        let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();

        let shards = coder.encode(&data).unwrap();
        let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        // Lose 2 random shards
        shard_opts[2] = None;
        shard_opts[4] = None;

        let decoded = coder.decode(&mut shard_opts, data.len()).unwrap();
        assert_eq!(decoded, data);
    }

    // ==================== NEGATIVE TESTS ====================

    #[test]
    fn test_decode_wrong_shard_count() {
        let coder = ErasureCoder::new().unwrap();

        // Wrong number of shards (4 instead of 5)
        let mut shards: Vec<Option<Vec<u8>>> = vec![
            Some(vec![0u8; 10]),
            Some(vec![0u8; 10]),
            Some(vec![0u8; 10]),
            Some(vec![0u8; 10]),
        ];

        let result = coder.decode(&mut shards, 30);
        assert!(matches!(result, Err(ErasureError::InvalidShardSize)));
    }

    #[test]
    fn test_decode_mismatched_shard_sizes() {
        let coder = ErasureCoder::new().unwrap();

        // Shards with different sizes
        let mut shards: Vec<Option<Vec<u8>>> = vec![
            Some(vec![0u8; 10]),
            Some(vec![0u8; 15]), // Different size!
            Some(vec![0u8; 10]),
            None,
            None,
        ];

        let result = coder.decode(&mut shards, 30);
        assert!(matches!(result, Err(ErasureError::InvalidShardSize)));
    }

    #[test]
    fn test_decode_all_shards_missing() {
        let coder = ErasureCoder::new().unwrap();

        let mut shards: Vec<Option<Vec<u8>>> = vec![None, None, None, None, None];

        let result = coder.decode(&mut shards, 30);
        assert!(matches!(result, Err(ErasureError::InsufficientShards(0))));
    }

    #[test]
    fn test_decode_only_one_shard() {
        let coder = ErasureCoder::new().unwrap();
        let data = b"Test data";

        let shards = coder.encode(data).unwrap();
        let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        // Keep only one shard
        shard_opts[0] = None;
        shard_opts[1] = None;
        shard_opts[3] = None;
        shard_opts[4] = None;

        let result = coder.decode(&mut shard_opts, data.len());
        assert!(matches!(result, Err(ErasureError::InsufficientShards(1))));
    }

    #[test]
    fn test_decode_only_two_shards() {
        let coder = ErasureCoder::new().unwrap();
        let data = b"Test data";

        let shards = coder.encode(data).unwrap();
        let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        // Keep only two shards
        shard_opts[0] = None;
        shard_opts[2] = None;
        shard_opts[4] = None;

        let result = coder.decode(&mut shard_opts, data.len());
        assert!(matches!(result, Err(ErasureError::InsufficientShards(2))));
    }

    #[test]
    fn test_verify_with_no_shards() {
        let coder = ErasureCoder::new().unwrap();
        let shards: Vec<Option<Vec<u8>>> = vec![None, None, None, None, None];

        assert!(!coder.verify(&shards));
    }

    #[test]
    fn test_verify_with_insufficient_shards() {
        let coder = ErasureCoder::new().unwrap();
        let shards: Vec<Option<Vec<u8>>> = vec![
            Some(vec![0u8; 10]),
            Some(vec![0u8; 10]),
            None,
            None,
            None,
        ];

        assert!(!coder.verify(&shards));
    }

    #[test]
    fn test_decode_with_corrupted_original_length() {
        let coder = ErasureCoder::new().unwrap();
        let data = b"Short";

        let shards = coder.encode(data).unwrap();
        let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        // Decode with wrong original length (too large)
        let decoded = coder.decode(&mut shard_opts, 1000).unwrap();
        // Should be padded, but the actual data portion is correct
        assert!(decoded.starts_with(data));
    }

    #[test]
    fn test_decode_with_zero_original_length() {
        let coder = ErasureCoder::new().unwrap();
        let data = b"Some data";

        let shards = coder.encode(data).unwrap();
        let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        // Decode with zero length - should return empty
        let decoded = coder.decode(&mut shard_opts, 0).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_encode_single_byte() {
        let coder = ErasureCoder::new().unwrap();
        let data = b"X";

        let shards = coder.encode(data).unwrap();
        assert_eq!(shards.len(), TOTAL_SHARDS);

        // All shards should have same size
        let shard_size = shards[0].len();
        for shard in &shards {
            assert_eq!(shard.len(), shard_size);
        }

        let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        let decoded = coder.decode(&mut shard_opts, data.len()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_loses_all_data_shards() {
        let coder = ErasureCoder::new().unwrap();
        let data = b"Testing when all data shards are lost";

        let shards = coder.encode(data).unwrap();
        let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        // Lose all 3 data shards, keep only parity
        shard_opts[0] = None;
        shard_opts[1] = None;
        shard_opts[2] = None;

        // Only 2 parity shards remain - insufficient
        let result = coder.decode(&mut shard_opts, data.len());
        assert!(matches!(result, Err(ErasureError::InsufficientShards(2))));
    }

    #[test]
    fn test_decode_loses_all_parity_shards() {
        let coder = ErasureCoder::new().unwrap();
        let data = b"Testing when all parity shards are lost";

        let shards = coder.encode(data).unwrap();
        let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        // Lose all parity shards - should still work with 3 data shards
        shard_opts[3] = None;
        shard_opts[4] = None;

        let decoded = coder.decode(&mut shard_opts, data.len()).unwrap();
        assert_eq!(decoded, data);
    }
}
