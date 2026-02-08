//! Fixed-size chunking for shard payloads
//!
//! Data is split into 3KB chunks before erasure coding. Each chunk is independently
//! erasure coded into 5 shards of ~1KB payload. This enables:
//! - Parallel multi-path distribution
//! - Device inclusivity (any phone can relay small shards)
//! - Clean bandwidth accounting (1 receipt = 1 KB forwarded)

use std::collections::BTreeMap;

use crate::{ErasureCoder, ErasureError, Result};

/// Fixed chunk size in bytes (3 KB).
/// Each chunk erasure coded into 5 shards → ~1KB payload per shard.
pub const CHUNK_SIZE: usize = 3072;

/// Split data into chunks and erasure code each independently.
///
/// Returns `Vec<(chunk_index, shard_payloads)>` where each `shard_payloads`
/// contains exactly `TOTAL_SHARDS` (5) payload buffers.
///
/// For data smaller than `CHUNK_SIZE`, returns a single chunk (index 0).
pub fn chunk_and_encode(data: &[u8]) -> Result<Vec<(u16, Vec<Vec<u8>>)>> {
    if data.is_empty() {
        return Err(ErasureError::EmptyData);
    }

    let coder = ErasureCoder::new()?;
    let num_chunks = data.len().div_ceil(CHUNK_SIZE);
    let mut result = Vec::with_capacity(num_chunks);

    for i in 0..num_chunks {
        let start = i * CHUNK_SIZE;
        let end = std::cmp::min(start + CHUNK_SIZE, data.len());
        let chunk = &data[start..end];

        let shard_payloads = coder.encode(chunk)?;
        result.push((i as u16, shard_payloads));
    }

    Ok(result)
}

/// Reassemble reconstructed chunks into original data.
///
/// `chunks` maps `chunk_index → reconstructed chunk data`.
/// `total_chunks` is the expected number of chunks.
/// `original_len` is the total original data length (for trimming the last chunk's padding).
pub fn reassemble(
    chunks: &BTreeMap<u16, Vec<u8>>,
    total_chunks: u16,
    original_len: usize,
) -> Result<Vec<u8>> {
    if chunks.len() < total_chunks as usize {
        return Err(ErasureError::DecodingFailed(format!(
            "Missing chunks: have {}, need {}",
            chunks.len(),
            total_chunks
        )));
    }

    let mut data = Vec::with_capacity(original_len);
    for i in 0..total_chunks {
        let chunk = chunks.get(&i).ok_or_else(|| {
            ErasureError::DecodingFailed(format!("Missing chunk {}", i))
        })?;
        data.extend_from_slice(chunk);
    }

    // Trim to original length (last chunk may have padding from erasure coding)
    data.truncate(original_len);

    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DATA_SHARDS, TOTAL_SHARDS};

    #[test]
    fn test_chunk_size() {
        assert_eq!(CHUNK_SIZE, 3072);
    }

    #[test]
    fn test_small_data_single_chunk() {
        let data = b"Hello, TunnelCraft!";
        let chunks = chunk_and_encode(data).unwrap();

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].0, 0); // chunk_index = 0
        assert_eq!(chunks[0].1.len(), TOTAL_SHARDS); // 5 shard payloads
    }

    #[test]
    fn test_exact_chunk_size() {
        let data = vec![0xAB; CHUNK_SIZE];
        let chunks = chunk_and_encode(&data).unwrap();

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].0, 0);
    }

    #[test]
    fn test_two_chunks() {
        let data = vec![0xCD; CHUNK_SIZE + 1];
        let chunks = chunk_and_encode(&data).unwrap();

        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].0, 0);
        assert_eq!(chunks[1].0, 1);
    }

    #[test]
    fn test_multiple_chunks() {
        // 10KB → ceil(10240 / 3072) = 4 chunks
        let data = vec![0xEF; 10240];
        let chunks = chunk_and_encode(&data).unwrap();

        assert_eq!(chunks.len(), 4);
        for (i, (idx, payloads)) in chunks.iter().enumerate() {
            assert_eq!(*idx, i as u16);
            assert_eq!(payloads.len(), TOTAL_SHARDS);
        }
    }

    #[test]
    fn test_shard_payload_size() {
        // Each chunk is 3KB, split into 3 data shards → ~1KB per shard
        let data = vec![0xAB; CHUNK_SIZE];
        let chunks = chunk_and_encode(&data).unwrap();

        let payload_size = chunks[0].1[0].len();
        // shard_size = ceil(3072 / 3) = 1024
        assert_eq!(payload_size, 1024);
    }

    #[test]
    fn test_roundtrip_small() {
        let data = b"Small payload under 3KB";
        let encoded = chunk_and_encode(data).unwrap();

        // Decode each chunk
        let coder = ErasureCoder::new().unwrap();
        let mut chunks_map = BTreeMap::new();

        for (chunk_idx, shard_payloads) in &encoded {
            let mut opts: Vec<Option<Vec<u8>>> =
                shard_payloads.iter().map(|p| Some(p.clone())).collect();
            let shard_size = shard_payloads[0].len();
            let max_len = shard_size * DATA_SHARDS;
            let chunk_data = coder.decode(&mut opts, max_len).unwrap();
            chunks_map.insert(*chunk_idx, chunk_data);
        }

        let total_chunks = encoded.len() as u16;
        let result = reassemble(&chunks_map, total_chunks, data.len()).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_roundtrip_large() {
        // 50KB payload → 17 chunks
        let data: Vec<u8> = (0..50_000).map(|i| (i % 256) as u8).collect();
        let encoded = chunk_and_encode(&data).unwrap();

        assert_eq!(encoded.len(), 50_000usize.div_ceil(CHUNK_SIZE)); // 17 chunks

        let coder = ErasureCoder::new().unwrap();
        let mut chunks_map = BTreeMap::new();

        for (chunk_idx, shard_payloads) in &encoded {
            let mut opts: Vec<Option<Vec<u8>>> =
                shard_payloads.iter().map(|p| Some(p.clone())).collect();
            let shard_size = shard_payloads[0].len();
            let max_len = shard_size * DATA_SHARDS;
            let chunk_data = coder.decode(&mut opts, max_len).unwrap();
            chunks_map.insert(*chunk_idx, chunk_data);
        }

        let total_chunks = encoded.len() as u16;
        let result = reassemble(&chunks_map, total_chunks, data.len()).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_roundtrip_with_missing_shards() {
        // Verify that per-chunk reconstruction works with 2 missing shards per chunk
        let data: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
        let encoded = chunk_and_encode(&data).unwrap();

        let coder = ErasureCoder::new().unwrap();
        let mut chunks_map = BTreeMap::new();

        for (chunk_idx, shard_payloads) in &encoded {
            let mut opts: Vec<Option<Vec<u8>>> =
                shard_payloads.iter().map(|p| Some(p.clone())).collect();
            // Drop 2 shards per chunk (max tolerable loss)
            opts[0] = None;
            opts[3] = None;

            let shard_size = shard_payloads[0].len();
            let max_len = shard_size * DATA_SHARDS;
            let chunk_data = coder.decode(&mut opts, max_len).unwrap();
            chunks_map.insert(*chunk_idx, chunk_data);
        }

        let total_chunks = encoded.len() as u16;
        let result = reassemble(&chunks_map, total_chunks, data.len()).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_empty_data_error() {
        let result = chunk_and_encode(b"");
        assert!(matches!(result, Err(ErasureError::EmptyData)));
    }

    #[test]
    fn test_reassemble_missing_chunk() {
        let mut chunks = BTreeMap::new();
        chunks.insert(0u16, vec![0u8; 100]);
        // Missing chunk 1

        let result = reassemble(&chunks, 2, 200);
        assert!(result.is_err());
    }

    #[test]
    fn test_single_byte() {
        let data = b"X";
        let encoded = chunk_and_encode(data).unwrap();
        assert_eq!(encoded.len(), 1);

        let coder = ErasureCoder::new().unwrap();
        let mut chunks_map = BTreeMap::new();

        let (chunk_idx, shard_payloads) = &encoded[0];
        let mut opts: Vec<Option<Vec<u8>>> =
            shard_payloads.iter().map(|p| Some(p.clone())).collect();
        let shard_size = shard_payloads[0].len();
        let max_len = shard_size * DATA_SHARDS;
        let chunk_data = coder.decode(&mut opts, max_len).unwrap();
        chunks_map.insert(*chunk_idx, chunk_data);

        let result = reassemble(&chunks_map, 1, data.len()).unwrap();
        assert_eq!(result, data);
    }
}
