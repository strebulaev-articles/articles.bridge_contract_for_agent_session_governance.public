//! Merkle tree over event hashes for O(log n) verification.
//!
//! Mirrors `merkle.py` in the Python supplementary.

use sha2::{Digest, Sha256};

/// Compute the Merkle root over a list of 32-byte event hashes.
///
/// For an empty list, returns SHA-256 of the empty string.
/// For a single leaf, returns that leaf.
/// For n >= 2, if n is odd, the last leaf is duplicated.
pub fn merkle_root(hashes: &[Vec<u8>]) -> Vec<u8> {
    if hashes.is_empty() {
        return Sha256::digest(b"").to_vec();
    }
    if hashes.len() == 1 {
        return hashes[0].clone();
    }
    let mut level = hashes.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(level[level.len() - 1].clone());
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for i in (0..level.len()).step_by(2) {
            let mut hasher = Sha256::new();
            hasher.update(&level[i]);
            hasher.update(&level[i + 1]);
            next.push(hasher.finalize().to_vec());
        }
        level = next;
    }
    level.into_iter().next().unwrap()
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
    fn test_empty() {
        let r = merkle_root(&[]);
        assert_eq!(r, sha(b""));
    }

    #[test]
    fn test_single() {
        let h0 = sha(b"event0");
        assert_eq!(merkle_root(&[h0.clone()]), h0);
    }

    #[test]
    fn test_two() {
        let h0 = sha(b"event0");
        let h1 = sha(b"event1");
        let mut hasher = Sha256::new();
        hasher.update(&h0);
        hasher.update(&h1);
        assert_eq!(merkle_root(&[h0, h1]), hasher.finalize().to_vec());
    }

    #[test]
    fn test_three() {
        let h0 = sha(b"e0");
        let h1 = sha(b"e1");
        let h2 = sha(b"e2");
        let a = { let mut h = Sha256::new(); h.update(&h0); h.update(&h1); h.finalize().to_vec() };
        let b = { let mut h = Sha256::new(); h.update(&h2); h.update(&h2); h.finalize().to_vec() };
        let expected = { let mut h = Sha256::new(); h.update(&a); h.update(&b); h.finalize().to_vec() };
        assert_eq!(merkle_root(&[h0, h1, h2]), expected);
    }
}
