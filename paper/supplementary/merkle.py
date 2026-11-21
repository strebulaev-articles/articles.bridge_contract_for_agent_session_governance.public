"""Merkle tree over event hashes for O(log n) verification.

Used by I-CHECKPOINT (SHOULD): the bridge computes a Merkle root over
the event_hash values of all preceding events and includes it in the
CHECKPOINT event payload.

Construction (Appendix A.4 of the paper):
- Leaves are the event_hash values (SHA-256 of canonical JSON) of
  events 0, 1, ..., n-1.
- Internal nodes are SHA-256(left || right), where left and right are
  the raw 32-byte digests (not hex-encoded).
- If n is odd, the last leaf is duplicated to make it even.
- The root is the hash of the topmost node.
- For n=0 (empty tree), the root is SHA-256("") = the hash of the
  empty string, matching the genesis event's prev_hash convention.
"""
from __future__ import annotations

import hashlib
from typing import List


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def merkle_root(hashes: List[bytes]) -> bytes:
    """Compute the Merkle root over a list of 32-byte event hashes.

    For an empty list, returns SHA-256 of the empty string (32 zero
    bytes followed by their hash is NOT used; we follow the genesis
    convention: prev_hash = empty string, so the root of an empty
    tree is SHA-256(b"")).

    For a single leaf, the root is that leaf.

    For n >= 2 leaves, if n is odd, the last leaf is duplicated.
    """
    if not hashes:
        return _sha256(b"")
    if len(hashes) == 1:
        return hashes[0]

    level = list(hashes)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])  # duplicate last
        level = [
            _sha256(level[i] + level[i + 1])
            for i in range(0, len(level), 2)
        ]
    return level[0]


def merkle_root_hex(hashes_hex: List[str]) -> str:
    """Convenience: take hex-encoded hashes, return hex root."""
    hashes = [bytes.fromhex(h) for h in hashes_hex]
    return merkle_root(hashes).hex()
