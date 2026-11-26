//! Merkle tree hash over event hashes (RFC 9162 section 2.1.1).
//!
//! Mirrors `merkle.py` in the Python supplementary. A leaf is
//! `SHA-256(0x00 || event_hash)`, an interior node
//! `SHA-256(0x01 || left || right)`; a tree of n > 1 leaves splits at the
//! largest power of two below n, so no node is duplicated. The root of an
//! empty log is `SHA-256("")`. The shared known answers are in
//! `../vectors/bytes_kat.json` (`merkle`).

use sha2::{Digest, Sha256};

fn leaf_hash(event_hash: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(event_hash);
    h.finalize().to_vec()
}

fn node_hash(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update([1u8]);
    h.update(left);
    h.update(right);
    h.finalize().to_vec()
}

/// Compute the tree hash over a list of event hashes, in one pass with a
/// stack of the complete subtrees met so far.
pub fn merkle_root(hashes: &[Vec<u8>]) -> Vec<u8> {
    if hashes.is_empty() {
        return Sha256::digest(b"").to_vec();
    }
    let mut stack: Vec<(Vec<u8>, usize)> = Vec::new();
    for event_hash in hashes {
        let (mut node, mut size) = (leaf_hash(event_hash), 1usize);
        while stack.last().is_some_and(|(_, s)| *s == size) {
            node = node_hash(&stack.pop().unwrap().0, &node);
            size *= 2;
        }
        stack.push((node, size));
    }
    let mut node = stack.pop().unwrap().0;
    while let Some((left, _)) = stack.pop() {
        node = node_hash(&left, &node);
    }
    node
}

/// Convenience: take hex-encoded hashes, return hex root.
pub fn merkle_root_hex(hashes_hex: &[String]) -> String {
    let hashes: Vec<Vec<u8>> = hashes_hex
        .iter()
        .map(|h| hex::decode(h).unwrap_or_default())
        .collect();
    hex::encode(merkle_root(&hashes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha(data: &[u8]) -> Vec<u8> {
        Sha256::digest(data).to_vec()
    }

    #[test]
    fn empty_log_is_the_hash_of_the_empty_string() {
        assert_eq!(merkle_root(&[]), sha(b""));
    }

    #[test]
    fn single_leaf_is_its_leaf_hash_not_the_event_hash() {
        let h0 = sha(b"event0");
        assert_eq!(merkle_root(&[h0.clone()]), leaf_hash(&h0));
        assert_ne!(merkle_root(&[h0.clone()]), h0);
    }

    #[test]
    fn three_leaves_split_two_and_one_without_duplication() {
        let (h0, h1, h2) = (sha(b"e0"), sha(b"e1"), sha(b"e2"));
        let left = node_hash(&leaf_hash(&h0), &leaf_hash(&h1));
        let expected = node_hash(&left, &leaf_hash(&h2));
        assert_eq!(merkle_root(&[h0, h1, h2]), expected);
    }
}
