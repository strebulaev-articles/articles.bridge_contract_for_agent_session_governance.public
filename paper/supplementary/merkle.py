"""Merkle tree hash over event hashes, as RFC 9162, Section 2.1.1.

Used by I-CHECKPOINT (SHOULD): the bridge computes the tree hash over the
event hashes of all preceding events of a session and records it, with the
tree size, in the CHECKPOINT event.

The input is the ordered list d(0), ..., d(n-1) of event hashes: the raw
32-byte SHA-256 digests of the events' canonical JSON (not their hex form).
With HASH = SHA-256 and || concatenation, the tree hash MTH is

    MTH({})      = HASH()                                  the empty string
    MTH({d(0)})  = HASH(0x00 || d(0))                      a leaf
    MTH(D[n])    = HASH(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
                   for n > 1, k the largest power of two smaller than n

The prefix byte separates the domains: a leaf hash is never an interior
hash, so an interior node cannot be passed off as an event.  A tree whose
size is not a power of two is split, never padded by repeating its last
node, so logs of different lengths do not share a root by construction.

``inclusion_proof`` and ``verify_inclusion`` are the audit path of
Section 2.1.3 of the same RFC: the proof that one event hash is the leaf
at a given position of a tree with a given size and root.
"""
from __future__ import annotations

import hashlib
from typing import List

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(event_hash: bytes) -> bytes:
    """The hash of a leaf: HASH(0x00 || event_hash)."""
    return _sha256(LEAF_PREFIX + event_hash)


def node_hash(left: bytes, right: bytes) -> bytes:
    """The hash of an interior node: HASH(0x01 || left || right)."""
    return _sha256(NODE_PREFIX + left + right)


def split_point(n: int) -> int:
    """The largest power of two smaller than ``n`` (n > 1)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(hashes: List[bytes]) -> bytes:
    """MTH over a list of 32-byte event hashes.

    Computed in one pass with a stack of the complete subtrees met so far
    (their sizes are the powers of two in the binary form of the count,
    largest first); joining them from the right gives the tree that the
    recursive definition splits at the largest power of two."""
    if not hashes:
        return _sha256(b"")
    stack: list[tuple[bytes, int]] = []
    for event_hash in hashes:
        node, size = leaf_hash(event_hash), 1
        while stack and stack[-1][1] == size:
            node, size = node_hash(stack.pop()[0], node), size * 2
        stack.append((node, size))
    node = stack.pop()[0]
    while stack:
        node = node_hash(stack.pop()[0], node)
    return node


def merkle_root_hex(hashes_hex: List[str]) -> str:
    """Convenience: take hex-encoded hashes, return hex root."""
    hashes = [bytes.fromhex(h) for h in hashes_hex]
    return merkle_root(hashes).hex()


def inclusion_proof(hashes: List[bytes], index: int) -> List[bytes]:
    """PATH(index, D[n]) of RFC 9162, Section 2.1.3.1: the sibling hashes
    from the leaf at ``index`` up to the root, lowest first."""
    n = len(hashes)
    if not 0 <= index < n:
        raise ValueError("index outside the tree")
    lo, hi = 0, n                      # the subtree D[lo:hi] holding the leaf
    siblings: List[bytes] = []         # from the root down
    while hi - lo > 1:
        k = split_point(hi - lo)
        if index - lo < k:
            siblings.append(merkle_root(hashes[lo + k:hi]))
            hi = lo + k
        else:
            siblings.append(merkle_root(hashes[lo:lo + k]))
            lo = lo + k
    return siblings[::-1]


def verify_inclusion(event_hash: bytes, index: int, tree_size: int,
                     proof: List[bytes], root: bytes) -> bool:
    """RFC 9162, Section 2.1.3.2: whether ``proof`` shows that
    ``event_hash`` is the leaf at ``index`` of the tree of ``tree_size``
    leaves whose hash is ``root``."""
    if not 0 <= index < tree_size:
        return False
    fn, sn = index, tree_size - 1
    r = leaf_hash(event_hash)
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root
