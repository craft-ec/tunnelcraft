//! Binary Merkle tree for distribution proofs.
//!
//! Leaf formula: `SHA256(relay_pubkey || count_le_bytes)`.
//! Internal nodes: `SHA256(left || right)`.
//! If the leaf count is not a power of 2, pad with `[0u8; 32]`.

use sha2::{Digest, Sha256};

/// A Merkle proof consisting of sibling hashes along the path to the root.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// Sibling hashes from leaf level to root (bottom-up).
    pub siblings: Vec<[u8; 32]>,
    /// Index of the leaf in the tree (determines left/right at each level).
    pub leaf_index: usize,
}

/// A binary Merkle tree.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// All nodes stored level by level, bottom-up. `layers[0]` = leaves.
    layers: Vec<Vec<[u8; 32]>>,
}

/// Compute a leaf hash from a relay pubkey and cumulative bytes.
///
/// `SHA256(pubkey || bytes.to_le_bytes())`
///
/// This formula MUST match the on-chain `verify_merkle_proof()` in the
/// Anchor program (which uses `solana_program::hash::hashv`). Both are
/// standard SHA-256 on identical input bytes.
pub fn merkle_leaf(relay_pubkey: &[u8; 32], relay_bytes: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(relay_pubkey);
    hasher.update(&relay_bytes.to_le_bytes());
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Hash two child nodes to produce a parent.
pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Round up to the next power of 2 (returns n if already a power of 2).
fn next_power_of_two(n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    n.next_power_of_two()
}

impl MerkleTree {
    /// Build a Merkle tree from distribution entries `(relay_pubkey, receipt_count)`.
    ///
    /// Entries are hashed into leaves using `merkle_leaf()`, then the tree
    /// is built bottom-up. If the number of entries is not a power of 2,
    /// the leaf layer is padded with `[0u8; 32]`.
    pub fn from_entries(entries: &[([u8; 32], u64)]) -> Self {
        let leaves: Vec<[u8; 32]> = entries
            .iter()
            .map(|(pubkey, count)| merkle_leaf(pubkey, *count))
            .collect();
        Self::from_leaves(leaves)
    }

    /// Build a Merkle tree from pre-hashed leaves.
    pub fn from_leaves(leaves: Vec<[u8; 32]>) -> Self {
        if leaves.is_empty() {
            return Self {
                layers: vec![vec![[0u8; 32]]],
            };
        }

        // Pad to power of 2
        let padded_len = next_power_of_two(leaves.len());
        let mut padded = leaves;
        padded.resize(padded_len, [0u8; 32]);

        let mut layers = vec![padded];

        // Build tree bottom-up
        while layers.last().unwrap().len() > 1 {
            let prev = layers.last().unwrap();
            let mut next_layer = Vec::with_capacity(prev.len() / 2);
            for pair in prev.chunks(2) {
                next_layer.push(hash_pair(&pair[0], &pair[1]));
            }
            layers.push(next_layer);
        }

        Self { layers }
    }

    /// Get the Merkle root.
    pub fn root(&self) -> [u8; 32] {
        *self.layers.last().unwrap().first().unwrap()
    }

    /// Generate a proof for the leaf at the given index.
    ///
    /// Returns `None` if the index is out of range (beyond the original
    /// leaf count including padding).
    pub fn proof(&self, leaf_index: usize) -> Option<MerkleProof> {
        if leaf_index >= self.layers[0].len() {
            return None;
        }

        let mut siblings = Vec::with_capacity(self.layers.len() - 1);
        let mut idx = leaf_index;

        for layer in &self.layers[..self.layers.len() - 1] {
            // Sibling is the other child of the same parent
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            siblings.push(layer[sibling_idx]);
            idx /= 2;
        }

        Some(MerkleProof {
            siblings,
            leaf_index,
        })
    }

    /// Verify a Merkle proof against a given root and leaf hash.
    pub fn verify(root: &[u8; 32], leaf: &[u8; 32], proof: &MerkleProof) -> bool {
        let mut current = *leaf;
        let mut idx = proof.leaf_index;

        for sibling in &proof.siblings {
            current = if idx % 2 == 0 {
                hash_pair(&current, sibling)
            } else {
                hash_pair(sibling, &current)
            };
            idx /= 2;
        }

        current == *root
    }

    /// Number of leaves (including padding).
    pub fn leaf_count(&self) -> usize {
        self.layers[0].len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_leaf() {
        let entries = vec![([1u8; 32], 100u64)];
        let tree = MerkleTree::from_entries(&entries);

        // Single leaf: 1 is already a power of 2 → no padding, root == leaf
        assert_eq!(tree.leaf_count(), 1);
        let leaf = merkle_leaf(&[1u8; 32], 100);
        assert_eq!(tree.root(), leaf);
    }

    #[test]
    fn test_power_of_two() {
        let entries = vec![
            ([1u8; 32], 10),
            ([2u8; 32], 20),
            ([3u8; 32], 30),
            ([4u8; 32], 40),
        ];
        let tree = MerkleTree::from_entries(&entries);
        assert_eq!(tree.leaf_count(), 4);

        // Manually compute expected root
        let l0 = merkle_leaf(&[1u8; 32], 10);
        let l1 = merkle_leaf(&[2u8; 32], 20);
        let l2 = merkle_leaf(&[3u8; 32], 30);
        let l3 = merkle_leaf(&[4u8; 32], 40);
        let h01 = hash_pair(&l0, &l1);
        let h23 = hash_pair(&l2, &l3);
        let expected = hash_pair(&h01, &h23);
        assert_eq!(tree.root(), expected);
    }

    #[test]
    fn test_non_power_of_two() {
        // 3 entries → padded to 4
        let entries = vec![([1u8; 32], 10), ([2u8; 32], 20), ([3u8; 32], 30)];
        let tree = MerkleTree::from_entries(&entries);
        assert_eq!(tree.leaf_count(), 4);

        let l0 = merkle_leaf(&[1u8; 32], 10);
        let l1 = merkle_leaf(&[2u8; 32], 20);
        let l2 = merkle_leaf(&[3u8; 32], 30);
        let pad = [0u8; 32];
        let h01 = hash_pair(&l0, &l1);
        let h23 = hash_pair(&l2, &pad);
        let expected = hash_pair(&h01, &h23);
        assert_eq!(tree.root(), expected);
    }

    #[test]
    fn test_proof_verify_roundtrip() {
        let entries = vec![
            ([1u8; 32], 10),
            ([2u8; 32], 20),
            ([3u8; 32], 30),
            ([4u8; 32], 40),
        ];
        let tree = MerkleTree::from_entries(&entries);
        let root = tree.root();

        for (i, (pubkey, count)) in entries.iter().enumerate() {
            let leaf = merkle_leaf(pubkey, *count);
            let proof = tree.proof(i).expect("proof should exist");
            assert!(
                MerkleTree::verify(&root, &leaf, &proof),
                "proof for leaf {} should verify",
                i
            );
        }
    }

    #[test]
    fn test_wrong_leaf_fails() {
        let entries = vec![([1u8; 32], 10), ([2u8; 32], 20)];
        let tree = MerkleTree::from_entries(&entries);
        let root = tree.root();

        let wrong_leaf = merkle_leaf(&[99u8; 32], 999);
        let proof = tree.proof(0).unwrap();
        assert!(!MerkleTree::verify(&root, &wrong_leaf, &proof));
    }

    #[test]
    fn test_wrong_root_fails() {
        let entries = vec![([1u8; 32], 10), ([2u8; 32], 20)];
        let tree = MerkleTree::from_entries(&entries);

        let leaf = merkle_leaf(&[1u8; 32], 10);
        let proof = tree.proof(0).unwrap();
        let wrong_root = [0xFFu8; 32];
        assert!(!MerkleTree::verify(&wrong_root, &leaf, &proof));
    }

    #[test]
    fn test_empty_entries() {
        let tree = MerkleTree::from_entries(&[]);
        assert_eq!(tree.root(), [0u8; 32]);
    }

    #[test]
    fn test_proof_out_of_range() {
        let entries = vec![([1u8; 32], 10), ([2u8; 32], 20)];
        let tree = MerkleTree::from_entries(&entries);
        assert!(tree.proof(5).is_none());
    }

    #[test]
    fn test_deterministic() {
        let entries = vec![([1u8; 32], 10), ([2u8; 32], 20), ([3u8; 32], 30)];
        let tree1 = MerkleTree::from_entries(&entries);
        let tree2 = MerkleTree::from_entries(&entries);
        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_large_tree() {
        let entries: Vec<_> = (0..17u8).map(|i| ([i; 32], i as u64 * 100)).collect();
        let tree = MerkleTree::from_entries(&entries);
        // 17 entries → padded to 32
        assert_eq!(tree.leaf_count(), 32);

        // Verify all 17 original entries
        let root = tree.root();
        for (i, (pubkey, count)) in entries.iter().enumerate() {
            let leaf = merkle_leaf(pubkey, *count);
            let proof = tree.proof(i).unwrap();
            assert!(MerkleTree::verify(&root, &leaf, &proof));
        }
    }
}
