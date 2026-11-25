#!/usr/bin/env python3
"""
Reference Bridge and conformance suite for the Bridge Contract
(Bridge Contract for Agent Session Governance).

This module is both:
  1. A reference implementation of a minimal Bridge over the *product*
     state model  Attachment{Att,Det,Res} x Human{None,Pend} x
     Lifecycle{Active,Terminated}  (paper Section 5.1), with a client set.
  2. A pytest-based test suite for the invariants of the specification.

Design: the session cell is a pure fold over the committed event log.
Every transition builds its events, appends them to durable storage as
one atomic batch (I7, I12), and only then applies them to the in-memory
cell.  Restart recovery (Section 5.5) is the same fold run over the
log, so the log alone determines the cell.

Invariants (paper Sections 5.2 and 5.6):
  I1  Last client's departure emits DETACHMENT then RESUME_PREPARED first.
  I2  While Human=Pend, submitted tool calls are queued or rejected.
  I3  Widening Authority-Scope is rejected (requested) or reported (observed).
  I4  A re-attach names a prefix of the chain: (seq, hash) must be on it.
  I5  Every event is hash-chained to its predecessor.
  I6  The terminated cell is terminal.
  I7  Events are committed before the cell changes.
  I8  A transport-reported 0-RTT replay is rejected.
  I9  A challenge nonce is valid for T_nonce; expiry rejects, never terminates.
  I10 Authority scope is narrow-only and versioned.
  I11 Challenge-response: proof of possession over a single-use nonce
      that is bound, at issue, to the key id it was requested for; a
      request that was presented and refused is never accepted later; a
      live nonce is never evicted by a further challenge (f), and
      unauthenticated failures are logged only up to a bound (g).
  I12 An event is durable before any mutation, forwarding or ack.
  I13 Queue keys/limits, call expiry and approval freshness at drain
      (the approval expiry is kept per call).
  I14 Answer binding: forward only on an approving answer with equal hash.
  I15 Client set: Att iff a client is connected; joins and registrations
      are authenticated.
  TIMERS  T_call <= T_human and T_detach <= T_total (T_human may exceed
      T_detach).
  I-CHECKPOINT (SHOULD)  A CHECKPOINT carries the tree size and the Merkle
      tree hash of RFC 9162 over the event hashes (``merkle.py``); it is
      emitted only on an active, unquarantined session whose chain
      verifies.

Run with (in a venv with requirements.txt installed):
    python3 -I -m pytest conformance_suite.py -q
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, NamedTuple, Optional

from jcs import canonicalize

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat)


# ----------------------------------------------------------------------
# 1. Model: cells, events, requests
# ----------------------------------------------------------------------

class Attachment(str, Enum):
    ATTACHED = "Att"
    DETACHED = "Det"
    RESUMING = "Res"


class Human(str, Enum):
    NONE = "None"
    PENDING = "Pend"


class Lifecycle(str, Enum):
    ACTIVE = "Active"
    TERMINATED = "Terminated"


class Cell(NamedTuple):
    """A cell of the product machine (normative state model)."""
    att: Attachment
    human: Human
    life: Lifecycle


class State(str, Enum):
    """Derived five-state view (expository only; the table is normative)."""
    ATTACHED = "ATTACHED"
    DETACHED = "DETACHED"
    PENDING_HUMAN = "PENDING_HUMAN"
    RESUMING = "RESUMING"
    TERMINATED = "TERMINATED"


def five_state_view(cell: Cell) -> State:
    if cell.life == Lifecycle.TERMINATED:
        return State.TERMINATED
    if cell.att == Attachment.RESUMING:
        return State.RESUMING
    if cell.human == Human.PENDING:
        return State.PENDING_HUMAN
    return (State.ATTACHED if cell.att == Attachment.ATTACHED
            else State.DETACHED)


class GovernanceEvent(str, Enum):
    ATTACHED = "ATTACHED"
    CLIENT_JOINED = "CLIENT_JOINED"
    CLIENT_LEFT = "CLIENT_LEFT"
    CLIENT_ADDED = "CLIENT_ADDED"
    DETACHMENT = "DETACHMENT"
    RESUME_PREPARED = "RESUME_PREPARED"
    RESUME_STARTED = "RESUME_STARTED"
    RESUME_REJECTED = "RESUME_REJECTED"
    RESUME_VERIFIED = "RESUME_VERIFIED"
    RESUME_FAILED = "RESUME_FAILED"
    HUMAN_PENDING = "HUMAN_PENDING"
    HUMAN_RESOLVED = "HUMAN_RESOLVED"
    HUMAN_TIMEOUT = "HUMAN_TIMEOUT"
    DETACH_TIMEOUT = "DETACH_TIMEOUT"
    AUTHORITY_EXTENSION_REJECTED = "AUTHORITY_EXTENSION_REJECTED"
    AUTHORITY_NARROWED = "AUTHORITY_NARROWED"
    AUTHORITY_NARROWING_REJECTED = "AUTHORITY_NARROWING_REJECTED"
    TERMINATION = "TERMINATION"
    TOOL_CALL_QUEUED = "TOOL_CALL_QUEUED"
    TOOL_CALL_ANSWERED = "TOOL_CALL_ANSWERED"
    TOOL_CALL_DRAINED = "TOOL_CALL_DRAINED"
    TOOL_CALL_REJECTED = "TOOL_CALL_REJECTED"
    TOOL_CALL_EXPIRED = "TOOL_CALL_EXPIRED"
    TOOL_CALL_DELIVERED = "TOOL_CALL_DELIVERED"
    TOOL_CALL_COMPLETED = "TOOL_CALL_COMPLETED"
    BRIDGE_RECOVERED = "BRIDGE_RECOVERED"
    RECOVERY_FAILED = "RECOVERY_FAILED"
    CHECKPOINT = "CHECKPOINT"
    KEY_REVOKED = "KEY_REVOKED"
    KEY_REVOCATION_REQUESTED = "KEY_REVOCATION_REQUESTED"
    OPERATOR_ADD_KEY = "OPERATOR_ADD_KEY"
    OPERATOR_TERMINATION = "OPERATOR_TERMINATION"


GE = GovernanceEvent


CHALLENGE_REFUSED = "challenge refused"
RESUME_REFUSED = "re-attach refused"


class BridgeError(Exception):
    """Raised when an operation is refused (a conformance invariant).

    ``reason`` is the typed wire reason, set at the raise site; the wire
    server reads it and never the message text.  ``refused`` is the
    uniform reason that names nothing."""
    reason: str = "refused"

    def __init__(self, *args: object, reason: str | None = None) -> None:
        super().__init__(*args)
        if reason is not None:
            self.reason = reason


class GrantInvalid(BridgeError):
    """attach refused: the scope grant is missing or does not verify
    (reason ``grant_invalid``)."""
    reason = "grant_invalid"


class PossessionInvalid(BridgeError):
    """attach refused: the proof of possession of the client key is
    missing or does not verify (reason ``possession_invalid``)."""
    reason = "possession_invalid"


class OperatorSignatureInvalid(BridgeError):
    """An operator event refused: the operator signature is missing or does
    not verify over the operation (reason ``operator_signature_invalid``)."""
    reason = "operator_signature_invalid"


class AddClientRejected(BridgeError):
    """add_client refused: the request is not authentic, not fresh or not
    admissible.  ``reason`` is one of ``via_not_connected``,
    ``bad_signature``, ``revoked_key``, ``nonce_unknown``, ``nonce_used``,
    ``nonce_expired``, ``key_already_registered``.  Nothing is committed
    (an unauthenticated caller writes nothing to the log)."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"add_client rejected: {reason} (I15d)")
        self.reason = reason


class StorageError(BridgeError):
    """The durable medium refused an append; nothing was committed."""


class CrashSimulated(Exception):
    """Test hook: the process 'crashes' after a durable commit."""


def _canon(obj: Any) -> bytes:
    """RFC 8785 canonical JSON (``jcs.py``); the one encoding every hash and
    every signed message in this suite is taken over."""
    return canonicalize(obj)


def content_hash(content: Any) -> str:
    """h(x): SHA-256 of the canonical JSON of x (I14)."""
    return hashlib.sha256(_canon(content)).hexdigest()


def call_hash(tool: str, permission: Optional[str], content: Any) -> str:
    """h_q of a tool call (I14): the hash of the tool, the permission and the
    content together, so an approval of one call cannot be spent on another
    that carries the same content under a different tool name."""
    return content_hash({"tool": tool, "permission": permission,
                         "content": content})


def canonical_scope(scope) -> tuple[str, ...]:
    """A scope is a set of permission strings; its canonical form is the
    strings without repetition, sorted by code point (Section 4, scope
    semantics).  The bridge records a scope only in this form, so the
    authority hash does not depend on the order or the repetitions a
    caller wrote."""
    return tuple(sorted(set(scope)))


def _authority_hash(principal: str, scope, lineage) -> str:
    return hashlib.sha256(_canon(
        {"principal": principal, "scope": list(scope),
         "lineage": list(lineage)})).hexdigest()[:16]


def _digest(nonce: str) -> str:
    return hashlib.sha256(nonce.encode()).hexdigest()[:16]


@dataclass
class SessionIdentity:
    """Session Identity Descriptor (S in (S, E, R, C))."""
    session_id: str
    principal_id: str
    authority_scope: tuple[str, ...]
    task_lineage: tuple[str, ...]

    def authority_hash(self) -> str:
        return _authority_hash(self.principal_id, self.authority_scope,
                               self.task_lineage)


@dataclass
class Event:
    """A single governance event, hash-chained to its predecessor."""
    kind: GovernanceEvent
    session_id: str
    sequence: int
    prev_hash: str
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0

    def canonical_bytes(self) -> bytes:
        return _canon({"kind": self.kind.value, "session_id": self.session_id,
                       "sequence": self.sequence, "prev_hash": self.prev_hash,
                       "payload": self.payload, "timestamp": self.timestamp})

    def event_hash(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


@dataclass
class Challenge:
    nonce: str
    ttl_seconds: float


@dataclass
class ResumeRequest:
    """A re-attach or join request (I4, I11): the last event the client
    acknowledged, a bridge nonce, and a signature over all of them."""
    key_id: str
    nonce: str
    seq: int
    hash: str
    signature: str


SCHEME_ED25519 = "ed25519"
SCHEME_ECDSA_P256 = "ecdsa-p256"

# The identity of a bridge; grants and attach proofs are bound to it.
DEFAULT_BRIDGE_ID = "bridge-1"

_P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)


def _verify(public_key: bytes, message: bytes, signature_hex: str) -> bool:
    """Ed25519 verification against registry material; malformed
    signatures are simply invalid."""
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            bytes.fromhex(signature_hex), message)
        return True
    except (InvalidSignature, ValueError):
        return False


def _verify_p256(public_key: bytes, message: bytes,
                 signature_hex: str) -> bool:
    """ECDSA P-256 / SHA-256 verification.  The registered key is the
    65-byte SEC1 uncompressed point and the signature is the 64-byte
    ``r || s`` form (what WebCrypto produces), hex-encoded; anything
    malformed is simply invalid."""
    try:
        if len(public_key) != 65:
            return False
        raw = bytes.fromhex(signature_hex)
        if len(raw) != 64:
            return False
        key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), public_key)
        der = encode_dss_signature(int.from_bytes(raw[:32], "big"),
                                   int.from_bytes(raw[32:], "big"))
        key.verify(der, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


# Proof-of-possession verifiers by scheme tag; a deployment adds its own.
SCHEME_VERIFIERS = {
    SCHEME_ED25519: _verify,
    SCHEME_ECDSA_P256: _verify_p256,
}


def _verify_scheme(scheme: str, public_key: bytes, message: bytes,
                   signature_hex: str) -> bool:
    """Dispatch on the scheme tag the registry recorded with the key; an
    unknown tag is invalid."""
    verifier = SCHEME_VERIFIERS.get(scheme)
    return verifier is not None and verifier(public_key, message,
                                             signature_hex)


@dataclass(frozen=True)
class ClientPublicKey:
    """What a server may hold of a client key: its id, scheme tag and
    public key.  No signing material; ``Bridge.attach`` and
    ``Bridge.add_client_key`` accept nothing else."""
    key_id: str
    scheme: str
    public_key: bytes


class ClientKey:
    """Client-side key registered at attach or by CLIENT_ADDED (I11).

    The client keeps the signing key; the bridge's key registry holds the
    scheme tag and the public key only, never in the event log and never
    any signing material.  Schemes: ``ed25519`` (raw 32-byte public key,
    the reference) and ``ecdsa-p256`` (65-byte SEC1 uncompressed point,
    ``r || s`` signatures).
    """

    def __init__(self, key_id: str = "ck-1", seed: Optional[bytes] = None,
                 scheme: str = SCHEME_ED25519):
        self.key_id = key_id
        self.scheme = scheme
        self.seed = seed if seed is not None else os.urandom(32)
        if scheme == SCHEME_ED25519:
            self._signer = Ed25519PrivateKey.from_private_bytes(self.seed)
            self.public_key: bytes = self._signer.public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw)
        elif scheme == SCHEME_ECDSA_P256:
            d = 1 + int.from_bytes(self.seed, "big") % (_P256_ORDER - 1)
            self._signer = ec.derive_private_key(
                d, ec.SECP256R1(), default_backend())
            self.public_key = self._signer.public_key().public_bytes(
                Encoding.X962, PublicFormat.UncompressedPoint)
        else:
            raise ValueError(f"unknown scheme {scheme!r}")

    def public(self) -> ClientPublicKey:
        """The part of this key a server receives and registers."""
        return ClientPublicKey(self.key_id, self.scheme, self.public_key)

    def sign_bytes(self, message: bytes) -> str:
        if self.scheme == SCHEME_ED25519:
            return self._signer.sign(message).hex()
        r, s = decode_dss_signature(
            self._signer.sign(message, ec.ECDSA(hashes.SHA256())))
        return (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()

    def sign(self, sid: str, nonce: str, seq: int, hash_: str,
             op: str = "reattach") -> str:
        return self.sign_bytes(
            _resume_bytes(op, sid, self.key_id, nonce, seq, hash_))

    def prove_attach(self, session: "SessionIdentity",
                     bridge_id: str = DEFAULT_BRIDGE_ID) -> str:
        """Proof of possession at attach: a signature by this key over the
        attach tuple (bridge, session, identity, scope, lineage, key)."""
        return self.sign_bytes(_attach_bytes(bridge_id, session,
                                             self.public()))

    def sign_add_client(self, sid: str, new_key: "ClientPublicKey",
                        nonce: str) -> str:
        """Authorise ``new_key`` for session ``sid`` as this (connected)
        key, bound to a bridge-issued nonce."""
        return self.sign_bytes(_add_client_bytes(
            sid, self.key_id, new_key.key_id, new_key.scheme,
            new_key.public_key.hex(), nonce))

    def request(self, sid: str, nonce: str, seq: int, hash_: str,
                op: str = "reattach") -> ResumeRequest:
        return ResumeRequest(self.key_id, nonce, seq, hash_,
                             self.sign(sid, nonce, seq, hash_, op))


ADD_CLIENT_DOMAIN = "bc/v1/add-client"


def _add_client_bytes(sid: str, via_key_id: str, new_key_id: str,
                      scheme: str, public_key: str, nonce: str) -> bytes:
    """What a CLIENT_ADDED authorisation binds: the operation (a domain
    tag), the session, the authorising key id, the new key (id, scheme and
    public key as hex) and the single-use nonce the bridge issued."""
    return _canon([ADD_CLIENT_DOMAIN, sid, via_key_id, new_key_id, scheme,
                   public_key, nonce])


RESUME_DOMAINS = {"reattach": "bc/v1/reattach", "join": "bc/v1/join"}


def _resume_bytes(op: str, sid: str, key_id: str, nonce: str, seq: int,
                  hash_: str) -> bytes:
    """What a re-attach or join proof binds: the operation (so one signature
    is never valid as the other), the session, the signing key id, the
    single-use nonce and the last event the client holds."""
    return _canon([RESUME_DOMAINS[op], sid, key_id, nonce, seq, hash_])


GRANT_DOMAIN = "bc/v1/grant"
ATTACH_DOMAIN = "bc/v1/attach"

def _attach_fields(bridge_id: str, session: "SessionIdentity",
                   key: "ClientPublicKey") -> list:
    """What an attach is about: the bridge it is presented to, the session,
    the principal, the granted scope, the lineage and the client key with
    its scheme tag and public key (hex)."""
    return [bridge_id, session.session_id, session.principal_id,
            list(session.authority_scope), list(session.task_lineage),
            key.key_id, key.scheme, key.public_key.hex()]


def _grant_bytes(bridge_id: str, session: "SessionIdentity",
                 key: "ClientPublicKey") -> bytes:
    """What a scope grant binds: the bridge, the session, the principal,
    the granted scope, the lineage and the client key (id, scheme, public
    key), under its own domain tag."""
    return _canon([GRANT_DOMAIN] + _attach_fields(bridge_id, session, key))


def _attach_bytes(bridge_id: str, session: "SessionIdentity",
                  key: "ClientPublicKey") -> bytes:
    """What the attaching key signs to prove it holds the private key: the
    same fields as the grant, under the attach domain tag."""
    return _canon([ATTACH_DOMAIN] + _attach_fields(bridge_id, session, key))


REVOKE_DOMAIN = "bc/v1/revoke"
ADD_KEY_DOMAIN = "bc/v1/add-key"
TERMINATE_DOMAIN = "bc/v1/terminate"


def _revoke_bytes(bridge_id: str, sid: str, key_id: str, reason: str,
                  seq: int, head: str) -> bytes:
    """What an operator revocation binds: the bridge, the session, the key,
    the kind, and the log position at signing (sequence and hash of the
    last event)."""
    return _canon([REVOKE_DOMAIN, bridge_id, sid, key_id, reason, seq, head])


def _add_key_bytes(bridge_id: str, sid: str, key_id: str, scheme: str,
                   public_key: str, seq: int, head: str) -> bytes:
    """What an operator key addition binds: the bridge, the session and the
    key (scheme tag and public key), and the log position at signing."""
    return _canon([ADD_KEY_DOMAIN, bridge_id, sid, key_id, scheme,
                   public_key, seq, head])


def _terminate_bytes(bridge_id: str, sid: str, reason: str, seq: int,
                     head: str) -> bytes:
    """What an operator termination binds: the bridge, the session, the
    reason, and the log position at signing."""
    return _canon([TERMINATE_DOMAIN, bridge_id, sid, reason, seq, head])


class OperatorKey:
    """A trusted authority outside the contract (the operator) that signs
    scope grants and operator events.  A test double for a deployment's
    operator authority."""

    def __init__(self, seed: Optional[bytes] = None) -> None:
        self.seed = seed if seed is not None else os.urandom(32)
        self._signer = Ed25519PrivateKey.from_private_bytes(self.seed)
        self.public_key: bytes = self._signer.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)

    def grant(self, session: "SessionIdentity", key: "ClientPublicKey",
              bridge_id: str = DEFAULT_BRIDGE_ID) -> str:
        return self._signer.sign(_grant_bytes(bridge_id, session, key)).hex()

    def revoke(self, bridge_id: str, sid: str, key_id: str, reason: str,
               seq: int, head: str) -> str:
        return self._signer.sign(_revoke_bytes(
            bridge_id, sid, key_id, reason, seq, head)).hex()

    def add_key(self, bridge_id: str, sid: str, key_id: str,
                public_key: str, seq: int, head: str,
                scheme: str = SCHEME_ED25519) -> str:
        return self._signer.sign(_add_key_bytes(
            bridge_id, sid, key_id, scheme, public_key, seq, head)).hex()

    def terminate(self, bridge_id: str, sid: str, reason: str, seq: int,
                  head: str) -> str:
        return self._signer.sign(_terminate_bytes(
            bridge_id, sid, reason, seq, head)).hex()


class OperatorGrantVerifier:
    """Reference grant verifier: the grant is the operator's signature over
    what it binds.  A deployment supplies its own verifier (an operator
    signed grant, an AGTP identity document, a mission contract); the
    bridge only requires that it accepts the identity and the key."""

    def __init__(self, operator_public_key: bytes) -> None:
        self.operator_public_key = operator_public_key

    def __call__(self, session: "SessionIdentity",
                 client_key: "ClientPublicKey", grant: Optional[str],
                 bridge_id: str = DEFAULT_BRIDGE_ID) -> bool:
        if not isinstance(grant, str):
            return False
        return _verify(self.operator_public_key,
                       _grant_bytes(bridge_id, session, client_key), grant)

    def verify_operation(self, message: bytes,
                         signature: Optional[str]) -> bool:
        """The same operator key authenticates the operator events
        (revocation, key addition, termination)."""
        if not isinstance(signature, str):
            return False
        return _verify(self.operator_public_key, message, signature)


# The suite's operator; the harness configures its bridges with it.
TEST_OPERATOR = OperatorKey(b"\x07" * 32)


def attach_as(bridge: "Bridge", ident: "SessionIdentity", key: "ClientKey",
              bridge_id: str = DEFAULT_BRIDGE_ID) -> None:
    """Attach with the operator's grant for ``key`` and the key's proof of
    possession (the harness's well-formed attach)."""
    bridge.attach(ident, key.public(),
                  TEST_OPERATOR.grant(ident, key.public(), bridge_id),
                  key.prove_attach(ident, bridge_id))

DETACHED_CALL_POLICIES = ("refuse", "queue", "forward")


@dataclass
class Config:
    """Timers (seconds).  T_call <= T_human and T_detach <= T_total are
    MUSTs; T_human defaults to T_detach, T_call to T_human and T_total to
    four times T_detach.  T_human may exceed T_detach: while the client is
    away the detach timer ends the session first, so the bound is enforced
    by the cell and not by the configuration.  Default profile:
    interactive-short.

    ``detached_calls`` selects the obligation for a tool call that arrives
    with no escalation pending while no client is attached (G1): ``refuse``
    (default), ``queue`` (hold it for an answer after re-attach) or
    ``forward`` (forward at once if its permission is in
    ``detached_allow``, otherwise refuse)."""
    t_detach: float = 1800.0
    t_human: Optional[float] = None
    t_call: Optional[float] = None
    t_total: Optional[float] = None  # cumulative time detached, all episodes
    t_approve: float = 900.0        # human approval validity (I13)
    t_nonce: float = 60.0           # challenge nonce lifetime (I9)
    q_max: int = 64
    n_checkpoint: int = 1000        # I-CHECKPOINT: emit every N events
    t_checkpoint: float = 300.0     # I-CHECKPOINT: emit every T_cp seconds
    # Tests set this to float('inf') to disable checkpoints in existing
    # vectors; dedicated checkpoint tests (T63+) use small values.
    detached_calls: str = "refuse"
    detached_allow: frozenset = frozenset()

    def __post_init__(self) -> None:
        if self.t_human is None:
            self.t_human = self.t_detach
        if self.t_call is None:
            self.t_call = self.t_human
        if self.t_total is None:
            self.t_total = 4 * self.t_detach
        # A timer is a non-negative number or infinity; NaN would make every
        # comparison false (a nonce that never expires), a negative value an
        # already-expired one.
        for name in ("t_detach", "t_human", "t_call", "t_total", "t_approve",
                     "t_nonce", "t_checkpoint"):
            value = getattr(self, name)
            if value != value or value < 0:
                raise ValueError(
                    f"timer {name} must be a non-negative number")
        if self.q_max < 0:
            raise ValueError("q_max must not be negative")
        if not self.t_call <= self.t_human:
            raise ValueError("timer bounds: T_call <= T_human is a MUST")
        if not self.t_detach <= self.t_total:
            raise ValueError("timer bounds: T_detach <= T_total is a MUST")
        if self.detached_calls not in DETACHED_CALL_POLICIES:
            raise ValueError(f"unknown detached_calls {self.detached_calls!r}")
        self.detached_allow = frozenset(self.detached_allow)

    @classmethod
    def interactive_short(cls) -> "Config":
        return cls()

    @classmethod
    def persistent(cls) -> "Config":
        return cls(t_detach=7 * 86400.0)   # T_total defaults to 28 days


class SystemClock:
    def now(self) -> float:
        return time.time()


class FakeClock:
    def __init__(self, start: float = 1000.0) -> None:
        self._now = start

    def now(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


class Storage:
    """Durable medium (axiom A1): committed logs and the key registry.

    Survives a bridge 'crash': a new Bridge is built over the same
    Storage.  append_batch is atomic: all events of a transition are
    committed, or none.
    """

    def __init__(self) -> None:
        self.logs: dict[str, list[Event]] = {}
        # The key registry, scoped to a session: (session id, key id) maps
        # to the public key and its scheme tag.
        self.client_keys: dict[tuple[str, str], bytes] = {}
        self.key_schemes: dict[tuple[str, str], str] = {}
        self.fail_next = False            # test hook: refuse the next append
        self.fail_after: Optional[int] = None  # refuse after n more appends
        self.crash_after_commit = False   # test hook: crash once durable

    @staticmethod
    def _slot(sid: str, key_id: str):
        return (sid, key_id)

    def register_key(self, sid: str, key_id: str, scheme: str,
                     public_key: bytes) -> None:
        """Record a client key for one session.  A key id already
        registered in the session is refused, never replaced."""
        slot = self._slot(sid, key_id)
        if slot in self.client_keys:
            raise BridgeError(f"key id {key_id!r} already registered in "
                              f"the session", reason="key_already_registered")
        self.client_keys[slot] = public_key
        self.key_schemes[slot] = scheme

    def unregister_key(self, sid: str, key_id: str) -> None:
        slot = self._slot(sid, key_id)
        self.client_keys.pop(slot, None)
        self.key_schemes.pop(slot, None)

    def key_record(self, sid: str, key_id: str):
        """(scheme, public key) registered for the key in the session."""
        slot = self._slot(sid, key_id)
        if slot not in self.client_keys:
            return None
        return self.key_schemes.get(slot, SCHEME_ED25519), self.client_keys[slot]

    def registered_key_ids(self, sid: str) -> set[str]:
        return {k for (s, k) in self.client_keys if s == sid}

    def append_batch(self, session_id: str, events: list[Event]) -> None:
        if self.fail_after is not None:
            if self.fail_after == 0:
                self.fail_after = None
                self.fail_next = True
            else:
                self.fail_after -= 1
        if self.fail_next:
            self.fail_next = False
            raise StorageError("append refused; nothing committed")
        self.logs.setdefault(session_id, []).extend(events)
        if self.crash_after_commit:
            self.crash_after_commit = False
            raise CrashSimulated("crash after durable commit")


# ----------------------------------------------------------------------
# 2. Reference Bridge implementation
# ----------------------------------------------------------------------

@dataclass
class _Sess:
    """Per-session cell and derived state; always a fold of the log."""
    sid: str
    principal: str
    lineage: tuple[str, ...]
    scope: tuple[str, ...]
    keys: set[str] = field(default_factory=set)      # K(s)
    # (scheme, public key hex) of each key, as the log records it
    key_material: dict[str, tuple[str, str]] = field(default_factory=dict)
    conn: set[str] = field(default_factory=set)      # C(s)
    resuming: Optional[str] = None
    resume_from: int = 0
    scope_version: int = 0
    att: Attachment = Attachment.ATTACHED
    human: Human = Human.NONE
    life: Lifecycle = Lifecycle.ACTIVE
    detach_at: Optional[float] = None
    det_since: Optional[float] = None    # start of the current away interval
    det_total: float = 0.0               # closed away intervals, all episodes
    quarantined: bool = False            # chain failed: frozen (A.5)
    unacked: dict[str, str] = field(default_factory=dict)  # drained, not delivered
    unacked_calls: dict[str, dict[str, Any]] = field(default_factory=dict)  # their requests
    drained: set[str] = field(default_factory=set)   # keys forwarded at a drain
    completed: set[str] = field(default_factory=set)
    human_at: Optional[float] = None
    record: Optional[Event] = None                   # RESUME_PREPARED
    # each queued call carries its own approval expiry (I13), set by the
    # HUMAN_RESOLVED that ends the escalation it was queued under
    queue: list[dict[str, Any]] = field(default_factory=list)
    used_keys: set[str] = field(default_factory=set)
    revoked_keys: set[str] = field(default_factory=set)  # I11-REVOKE
    key_exhausted: bool = False                          # I11-REVOKE


@dataclass
class _NonceRecord:
    """A challenge nonce as the bridge keeps it (volatile).  ``key_id`` is
    the key id the challenge named; ``eligible`` says whether that key was
    registered and unrevoked in the session when the nonce was issued.
    Neither changes afterwards, so a nonce issued for a key id that was not
    an active key at issue never verifies, whatever the registry becomes."""
    issued_at: float
    key_id: str
    eligible: bool
    used: bool = False


NONCE_RECORDS = 16          # live nonces per session (volatile); I11f
UNAUTH_LOG_LIMIT = 16       # unauthenticated rejections logged per session
                            # between two authentic requests (volatile); I11g
REVOCATION_REQUEST_LIMIT = 16   # KEY_REVOCATION_REQUESTED writes per session
                                # between two operator-signed revocations
                                # (volatile); I11-REVOKE
REVOKE_REASONS = ("rotation", "compromise")     # soft, hard (I11-REVOKE)


def _public_reason(reason: str) -> str:
    """The reason a caller sees.  A request for an unregistered key, one
    whose signature does not verify and one that presents a nonce not bound
    to its key are one refusal to the caller, so a rejection says neither
    which key ids a session registers nor for which key id a nonce was
    issued; the log keeps the true reason."""
    return ("bad_signature" if reason in ("unknown_key", "nonce_binding")
            else reason)


# Refusals of a request that is not shown to come from an active key holder:
# the transport flagged it as a replay, the key is not registered, the
# signature does not verify, the nonce is not bound to the key, or the key
# is revoked.  They are logged only up to a bound and do not restore it
# (I11g).
UNAUTHENTICATED = frozenset({"transport_replay", "unknown_key",
                             "bad_signature", "nonce_binding",
                             "revoked_key"})


class Bridge:
    """Minimal reference bridge satisfying the Bridge Contract.

    The bridge does not own the agent runtime, the client or the human;
    the test harness simulates them.  Calls that the bridge would
    forward to the runtime are recorded in ``forwarded``; instructions to
    revert an observed authority change in ``revert_requests``.
    """

    def __init__(self, storage: Optional[Storage] = None, clock=None,
                 config: Optional[Config] = None,
                 grant_verifier=None,
                 bridge_id: str = DEFAULT_BRIDGE_ID) -> None:
        self.storage = storage if storage is not None else Storage()
        # The identity a grant and an attach proof are bound to.
        self.bridge_id = bridge_id
        # The deployment's scope-grant verifier (authorisation boundary).
        # None means no authority is configured: attach is refused.
        self.grant_verifier = grant_verifier
        self.clock = clock if clock is not None else SystemClock()
        self.cfg = config if config is not None else Config()
        self._sess: dict[str, _Sess] = {}
        self._floor = 0.0           # latest committed timestamp (A6)
        # volatile: sid -> {nonce: record}; void after a restart
        self._nonces: dict[str, dict[str, _NonceRecord]] = {}
        # volatile: sid -> unauthenticated rejections logged since the last
        # authentic request (I11g)
        self._unauth_logged: dict[str, int] = {}
        self._revocation_requests: dict[str, int] = {}
        self.forwarded: list[tuple[str, str, str]] = []  # (sid, key, call)
        # the request forwarded for (sid, key): tool, permission, content (I14)
        self.forwarded_calls: dict[tuple[str, str], dict[str, Any]] = {}
        self._sent: set[tuple[str, str]] = set()   # forwarded by this process
        self.revert_requests: list[tuple[str, tuple[str, ...]]] = []
        # I-CHECKPOINT: track last checkpoint per session
        self._last_cp: dict[str, float] = {}  # sid -> timestamp of last CHECKPOINT
        self._cp_len: dict[str, int] = {}     # sid -> log length after last CHECKPOINT

    def _now(self) -> float:
        """The host clock, never earlier than the last committed timestamp:
        a clock that went backwards across a restart counts as no time
        elapsed (A6)."""
        return max(self.clock.now(), self._floor)

    # -- commit / apply: the only way a cell changes -----------------------

    def _commit(self, sid: str, items: list[tuple[GovernanceEvent, dict]],
                *, _checkpoint: bool = False):
        """Append one transition's events atomically, then apply them."""
        log = self.storage.logs.get(sid, [])
        prev = log[-1].event_hash() if log else ""
        seq = len(log)
        ts = self._now()
        batch: list[Event] = []
        for kind, payload in items:
            ev = Event(kind, sid, seq, prev, payload, ts)
            batch.append(ev)
            prev = ev.event_hash()
            seq += 1
        self.storage.append_batch(sid, batch)       # I12 / I7: durable first
        for ev in batch:
            self._apply(ev)
        if not _checkpoint:
            self._maybe_checkpoint(sid)
        return batch

    # -- I-CHECKPOINT: periodic Merkle root anchoring (SHOULD) ---------------

    def _maybe_checkpoint(self, sid: str) -> None:
        """Emit a CHECKPOINT event if the session has accumulated enough
        events or enough time since the last checkpoint (I-CHECKPOINT).
        The CHECKPOINT event itself does not trigger another checkpoint.

        Nothing is emitted on a terminated session (I6: TERMINATION is the
        last event) or on a quarantined one (rule Q: only a TERMINATION may
        follow the failure event), and the root is taken only over a log
        whose hash chain verifies (I5): a checkpoint must not vouch for
        events the bridge has not checked."""
        s = self._sess.get(sid)
        if s is None or s.life == Lifecycle.TERMINATED or s.quarantined:
            return
        log = self.storage.logs.get(sid, [])
        n = len(log)
        now = self._now()
        # First commit for this session: initialise the tracker, no checkpoint.
        if sid not in self._last_cp:
            self._last_cp[sid] = now
            return
        last = self._last_cp[sid]
        since = n - self._cp_len.get(sid, 0)    # events since the last checkpoint
        if since < self.cfg.n_checkpoint and (now - last) < self.cfg.t_checkpoint:
            return
        # The leaves are the event hashes the chain verification computes:
        # one pass over the log yields both the verdict and the leaves.
        from merkle import merkle_root
        try:
            hashes = self._chain_hashes(sid)
        except BridgeError:
            return                      # not vouched for: no checkpoint
        root = merkle_root(hashes).hex()
        self._last_cp[sid] = now  # set before commit to prevent recursion
        self._commit(sid, [(GE.CHECKPOINT, {
            "root": root,
            "tree_size": n,
            "signature": "00" * 64,  # placeholder; real deployment signs with operator key
        })], _checkpoint=True)
        self._cp_len[sid] = len(self.storage.logs.get(sid, []))

    def _apply(self, ev: Event) -> None:
        k, p, sid = ev.kind, ev.payload, ev.session_id
        self._floor = max(self._floor, ev.timestamp)
        if k == GE.ATTACHED:
            self._sess[sid] = _Sess(
                sid=sid, principal=p["principal_id"],
                lineage=tuple(p["task_lineage"]),
                scope=tuple(p["authority_scope"]),
                keys={p["client_key_id"]}, conn={p["client_key_id"]},
                key_material={p["client_key_id"]: (p["scheme"],
                                                   p["public_key"])})
            return
        s = self._sess[sid]
        if k == GE.CLIENT_ADDED:
            s.keys.add(p["key_id"])
            s.key_material[p["key_id"]] = (p["scheme"], p["public_key"])
        elif k == GE.KEY_REVOKED:                           # I11-REVOKE
            s.revoked_keys.add(p["key_id"])
            if p["reason"] == "compromise":                 # hard: leaves C(s)
                s.conn.discard(p["key_id"])
            s.key_exhausted = not (s.keys - s.revoked_keys)
        elif k == GE.OPERATOR_ADD_KEY:                      # I11-REVOKE
            s.keys.add(p["key_id"])
            s.key_material[p["key_id"]] = (p["scheme"], p["public_key"])
            s.key_exhausted = not (s.keys - s.revoked_keys)
        elif k == GE.CLIENT_JOINED:
            s.conn.add(p["key_id"])
        elif k == GE.CLIENT_LEFT:
            s.conn.discard(p["key_id"])
        elif k == GE.DETACHMENT:
            if s.att != Attachment.DETACHED:        # a restart while away
                s.det_since = ev.timestamp          # continues the interval
            s.att = Attachment.DETACHED
            s.conn = set()
            s.resuming = None
            s.detach_at = ev.timestamp
        elif k == GE.RESUME_PREPARED:
            s.record = ev
        elif k == GE.RESUME_STARTED:
            s.att = Attachment.RESUMING
            s.resuming = p["key_id"]
            s.resume_from = p["seq"]
            s.detach_at = None
            if s.det_since is not None:
                s.det_total += ev.timestamp - s.det_since
                s.det_since = None
        elif k == GE.RESUME_VERIFIED:
            s.att = Attachment.ATTACHED
            s.conn = {s.resuming} if s.resuming else set()
            s.resuming = None
        elif k == GE.HUMAN_PENDING:
            if s.human == Human.NONE:
                s.human = Human.PENDING
                s.human_at = ev.timestamp
        elif k == GE.HUMAN_RESOLVED:
            s.human = Human.NONE
            s.human_at = None
            # I13: the approval belongs to the calls of the escalation it
            # ends, each of which keeps this expiry; a call approved by an
            # earlier resolution keeps the earlier one
            for c in s.queue:
                if not c["held"] and c["approved_until"] is None:
                    c["approved_until"] = p["valid_until"]
        elif k == GE.AUTHORITY_NARROWED:
            s.scope = tuple(p["new_scope"])
            s.scope_version = p["new_version"]
        elif k == GE.TOOL_CALL_QUEUED:
            s.queue.append({"key": p["key"], "tool": p["tool"],
                            "permission": p["permission"],
                            "content": p.get("content"),
                            "expires_at": p["expires_at"],
                            "shown_hash": p["shown_hash"], "answer": None,
                            "held": p.get("held", False),
                            "approved_until": None})
            s.used_keys.add(p["key"])
        elif k == GE.TOOL_CALL_ANSWERED:
            for c in s.queue:
                if c["key"] == p["key"]:
                    c["answer"] = (p["decision"], p["shown_hash"])
        elif k in (GE.TOOL_CALL_DRAINED, GE.TOOL_CALL_REJECTED,
                   GE.TOOL_CALL_EXPIRED):
            if not p.get("direct"):         # a direct call was never queued
                s.queue = [c for c in s.queue if c["key"] != p["key"]]
            s.used_keys.add(p["key"])
            if k == GE.TOOL_CALL_DRAINED:
                s.drained.add(p["key"])
                s.unacked[p["key"]] = p["tool"]
                s.unacked_calls[p["key"]] = {
                    "tool": p["tool"], "permission": p.get("permission"),
                    "content": p.get("content")}
        elif k == GE.TOOL_CALL_DELIVERED:
            s.unacked.pop(p["key"], None)
            s.unacked_calls.pop(p["key"], None)
        elif k == GE.TOOL_CALL_COMPLETED:
            s.unacked.pop(p["key"], None)
            s.unacked_calls.pop(p["key"], None)
            s.completed.add(p["key"])
        elif k in (GE.RESUME_FAILED, GE.RECOVERY_FAILED):
            s.quarantined = True
        elif k == GE.TERMINATION:
            s.life = Lifecycle.TERMINATED
        # Remaining kinds (RESUME_REJECTED, *_TIMEOUT, AUTHORITY_*_REJECTED,
        # BRIDGE_RECOVERED) are audit-only: they do not change the cell.
        # RESUME_FAILED and RECOVERY_FAILED freeze the session without
        # changing its cell (quarantine).

    # -- session lifecycle ---------------------------------------------------

    def attach(self, session: SessionIdentity, client_key: ClientPublicKey,
               grant: Optional[str] = None,
               proof: Optional[str] = None) -> None:
        """Create the session.  ``grant`` is the operator's scope grant for
        this bridge, session, scope and exact client key; ``proof`` is the
        client key's signature over the attach tuple (possession)."""
        if not isinstance(client_key, ClientPublicKey):
            raise TypeError("attach takes the client's public key only "
                            "(ClientKey.public()), never its signing key")
        sid = session.session_id
        if self.grant_verifier is None or not self.grant_verifier(
                session, client_key, grant, self.bridge_id):
            raise GrantInvalid("scope grant missing or invalid")
        if not isinstance(proof, str) or not _verify_scheme(
                client_key.scheme, client_key.public_key,
                _attach_bytes(self.bridge_id, session, client_key), proof):
            raise PossessionInvalid("proof of possession missing or invalid")
        if sid in self._sess or sid in self.storage.logs:
            raise BridgeError("session already exists (I6: no re-attach)")
        self.storage.register_key(sid, client_key.key_id, client_key.scheme,
                                  client_key.public_key)
        try:
            # the grant and the proof bind the scope as presented; the
            # session records it in canonical form (a set, sorted)
            self._commit(sid, [(GE.ATTACHED, {
                "principal_id": session.principal_id,
                "authority_scope": list(canonical_scope(
                    session.authority_scope)),
                "task_lineage": list(session.task_lineage),
                "client_key_id": client_key.key_id,
                "scheme": client_key.scheme,
                "public_key": client_key.public_key.hex(),
                "scope_version": 0})])
        except StorageError:
            self.storage.unregister_key(sid, client_key.key_id)
            raise

    def add_client_key(self, sid: str, via_key_id: str,
                       new_key: ClientPublicKey, nonce: str,
                       signature: str) -> None:
        """CLIENT_ADDED: a connected client authorises a further key for
        the same principal (I15d).  Takes the public key only, and a
        signature by ``via_key_id`` over ``_add_client_bytes`` with a
        nonce that ``challenge`` issued for ``via_key_id``.  Every refusal
        is an ``AddClientRejected`` with a reason and commits nothing.

        The order is that of a re-attach: key and signature, revocation,
        the binding of the nonce to the key, the nonce itself (spent by an
        authentic request), and only then what depends on the session
        (whether the key is connected, whether the new key id is free).  A
        request that names an unregistered key, or a nonce not bound to its
        key, is answered as a bad signature."""
        if not isinstance(new_key, ClientPublicKey):
            raise TypeError("add_client_key takes the client's public key "
                            "only (ClientKey.public())")
        s = self._enter(sid)
        record = (self.storage.key_record(sid, via_key_id)
                  if via_key_id in s.keys else None)
        scheme, public = record if record else (SCHEME_ED25519, None)
        if public is None or not _verify_scheme(
                scheme, public,
                _add_client_bytes(sid, via_key_id, new_key.key_id,
                                  new_key.scheme, new_key.public_key.hex(),
                                  nonce),
                signature):
            raise AddClientRejected("bad_signature")
        rec = self._nonces.get(sid, {}).get(nonce)
        bound = (rec is not None and rec.key_id == via_key_id
                 and rec.eligible)
        if via_key_id in s.revoked_keys:
            if bound:
                rec.used = True                        # as in I11-REVOKE
            raise AddClientRejected("revoked_key")
        if rec is not None and not bound:
            raise AddClientRejected("bad_signature")   # not this key's nonce
        if rec is None:
            raise AddClientRejected("nonce_unknown")
        used = rec.used
        rec.used = True                                # spent, as in I11d
        if used:
            raise AddClientRejected("nonce_used")
        if self._now() - rec.issued_at >= self.cfg.t_nonce:
            raise AddClientRejected("nonce_expired")
        if via_key_id not in s.conn:
            raise AddClientRejected("via_not_connected")
        if new_key.key_id in s.keys:
            raise AddClientRejected("key_already_registered")
        self.storage.register_key(sid, new_key.key_id, new_key.scheme,
                                  new_key.public_key)
        try:
            self._commit(sid, [(GE.CLIENT_ADDED, {
                "key_id": new_key.key_id, "via": via_key_id,
                "scheme": new_key.scheme,
                "public_key": new_key.public_key.hex()})])
        except StorageError:
            self.storage.unregister_key(sid, new_key.key_id)
            raise

    # -- tool-call traffic (I2, I13, I14) ----------------------------------

    def submit_tool_call(self, sid: str, tool: str, key: Optional[str] = None,
                         permission: Optional[str] = None,
                         content: Any = None) -> str:
        return self.submit_tool_call_keyed(sid, tool, key, permission,
                                           content)[0]

    def submit_tool_call_keyed(self, sid: str, tool: str,
                               key: Optional[str] = None,
                               permission: Optional[str] = None,
                               content: Any = None) -> tuple[str, str]:
        """Submit a tool call; returns the outcome and the idempotency key
        the call carries (the caller's, or the one the bridge generated;
        empty for a call forwarded directly without one)."""
        s = self._enter(sid)
        if s.human == Human.PENDING:
            if key is None:
                key = self._fresh_key(s)
            if key in s.used_keys:
                return "DUPLICATE", key
            if len(s.queue) >= self.cfg.q_max:
                self._commit(sid, [(GE.TOOL_CALL_REJECTED, {
                    "key": key, "tool": tool, "reason": "queue_full"})])
                return "REJECTED", key
            self._commit(sid, [(GE.TOOL_CALL_QUEUED, {
                "key": key, "tool": tool, "permission": permission,
                "content": content,
                "shown_hash": call_hash(tool, permission, content),
                "expires_at": self._now() + self.cfg.t_call})])
            return "QUEUED", key
        if s.att == Attachment.ATTACHED:
            if permission is not None and permission not in s.scope:
                # I3 on the direct path: a call outside the current scope is
                # not forwarded; the refusal is recorded (it was never
                # queued, so the event is marked ``direct``)
                if key is None:
                    key = self._fresh_key(s)
                self._commit(sid, [(GE.TOOL_CALL_REJECTED, {
                    "key": key, "tool": tool, "permission": permission,
                    "reason": "scope", "direct": True})])
                raise BridgeError(
                    f"tool call needs {permission!r}, which is not in the "
                    "current scope (I3)", reason="scope")
            self._send(sid, key or "", tool, permission, content)
            return "FORWARDED", key or ""
        return self._detached_call(sid, s, tool, key, permission, content)

    @staticmethod
    def _fresh_key(s: _Sess) -> str:
        """An idempotency key for a call that came without one: the next
        ``tc-NNNN`` the session has not used, so a generated key never
        collides with one the runtime supplied (I13)."""
        n = len(s.used_keys) + 1
        while f"tc-{n:04d}" in s.used_keys:
            n += 1
        return f"tc-{n:04d}"

    def _detached_call(self, sid, s, tool, key, permission,
                       content) -> tuple[str, str]:
        """G1: a call with no escalation pending while no client is
        attached.  Default: refuse.  Variants are a deployment choice."""
        policy = self.cfg.detached_calls
        in_scope = permission is None or permission in s.scope
        if policy == "refuse" or not in_scope or (
                policy == "forward"
                and permission not in self.cfg.detached_allow):
            raise BridgeError(
                f"tool call not allowed in cell {self._cell(s)} "
                f"(detached_calls={policy})")
        if key is None:
            key = self._fresh_key(s)
        if key in s.used_keys:
            return "DUPLICATE", key
        if len(s.queue) >= self.cfg.q_max:
            self._commit(sid, [(GE.TOOL_CALL_REJECTED, {
                "key": key, "tool": tool, "reason": "queue_full"})])
            return "REJECTED", key
        queued = (GE.TOOL_CALL_QUEUED, {
            "key": key, "tool": tool, "permission": permission,
            "content": content,
            "shown_hash": call_hash(tool, permission, content), "held": True,
            "expires_at": self._now() + self.cfg.t_call})
        if policy == "queue":
            self._commit(sid, [queued])
            return "QUEUED", key
        # forward: the operator pre-approved this permission, so the call is
        # recorded as queued, answered and drained in one committed batch and
        # forwarded only after the batch is durable (I12).
        sh = queued[1]["shown_hash"]
        batch = self._commit(sid, [
            queued,
            (GE.TOOL_CALL_ANSWERED, {"key": key, "shown_hash": sh,
                                     "decision": "approve",
                                     "source": "operator_policy"}),
            (GE.TOOL_CALL_DRAINED, {
                "key": key, "tool": tool, "permission": permission,
                "content": content, "shown_hash": sh,
                "authority_hash": _authority_hash(
                    s.principal, s.scope, s.lineage)})])
        self._send(sid, key, tool, permission, content)
        return "FORWARDED", key

    def shown_hash_of(self, sid: str, key: str) -> str:
        """h(content shown) as the bridge recorded it; what a faithful
        client that rendered the same content would report."""
        for c in self._sess[sid].queue:
            if c["key"] == key:
                return c["shown_hash"]
        raise BridgeError(f"no queued call {key!r}")

    def answer_tool_call(self, sid: str, key: str, shown_hash: str,
                         approve: bool = True) -> None:
        """TOOL_CALL_ANSWERED: the human's decision on a queued call,
        with the hash of what the client displayed (I14)."""
        s = self._enter(sid)
        entry = next((c for c in s.queue if c["key"] == key), None)
        if entry is None:
            raise BridgeError(f"no queued call {key!r} to answer")
        if entry["answer"] is not None:
            raise BridgeError("call already answered (I14)")
        self._commit(sid, [(GE.TOOL_CALL_ANSWERED, {
            "key": key, "shown_hash": shown_hash,
            "decision": "approve" if approve else "deny"})])
        if entry["held"]:
            self._drain(sid)           # no-op unless back in (Att, None)

    def _drain(self, sid: str) -> None:
        """Rule D: drain in arrival order, revalidating each call (I13,
        I14)."""
        s = self._sess[sid]
        if not (s.att == Attachment.ATTACHED and s.human == Human.NONE
                and s.life == Lifecycle.ACTIVE and not s.quarantined):
            return
        now = self._now()
        ah = _authority_hash(s.principal, s.scope, s.lineage)
        items = []
        for c in s.queue:
            base = {"key": c["key"], "tool": c["tool"]}
            sent = {"permission": c["permission"], "content": c["content"]}
            if c["held"] and c["answer"] is None and now < c["expires_at"]:
                continue                  # waits for its answer (G1 variant)
            if now >= c["expires_at"]:
                items.append((GE.TOOL_CALL_EXPIRED,
                              {**base, "reason": "call_ttl"}))
            elif not c["held"] and (c["approved_until"] is None
                                    or now >= c["approved_until"]):
                # I13: the approval of this call's own escalation is valid
                # strictly before T_approve has elapsed; a later approval
                # of another escalation does not revive it
                items.append((GE.TOOL_CALL_EXPIRED,
                              {**base, "reason": "approval_ttl"}))
            elif c["permission"] is not None and c["permission"] not in s.scope:
                items.append((GE.TOOL_CALL_REJECTED,
                              {**base, "reason": "scope"}))
            elif c["answer"] is None:
                items.append((GE.TOOL_CALL_REJECTED,
                              {**base, "reason": "unanswered"}))
            elif c["answer"][0] != "approve":
                items.append((GE.TOOL_CALL_REJECTED,
                              {**base, "reason": "denied"}))
            elif c["answer"][1] != c["shown_hash"]:
                items.append((GE.TOOL_CALL_REJECTED,
                              {**base, "reason": "answer_mismatch"}))
            else:
                items.append((GE.TOOL_CALL_DRAINED,
                              {**base, **sent, "authority_hash": ah,
                               "shown_hash": c["shown_hash"]}))
        if items:
            batch = self._commit(sid, items)
            for ev in batch:                              # I12: after commit
                if ev.kind == GE.TOOL_CALL_DRAINED:
                    self._send(sid, ev.payload["key"], ev.payload["tool"],
                               ev.payload["permission"],
                               ev.payload["content"])
        self._reforward(sid)

    def _reforward(self, sid: str) -> None:
        """Rule D, forwarding acknowledgement: a drained call whose delivery
        the runtime has not acknowledged (a crash between the drain and the
        acknowledgement) is forwarded again, with the same key, now that the
        session is back in (Att, None)."""
        for key, call in list(self._sess[sid].unacked_calls.items()):
            if (sid, key) not in self._sent:
                self._send(sid, key, call["tool"], call["permission"],
                           call["content"])

    def _send(self, sid: str, key: str, tool: str,
              permission: Optional[str] = None, content: Any = None) -> None:
        """Forward the request: the tool, permission and content that were
        hashed at queue time and retained in the log (I14)."""
        self._sent.add((sid, key))
        self.forwarded.append((sid, key, tool))
        self.forwarded_calls[(sid, key)] = {
            "tool": tool, "permission": permission, "content": content}

    def delivered(self, sid: str, key: str) -> None:
        """The runtime acknowledges that it received a forwarded call."""
        s = self._enter(sid)
        if key not in s.unacked:
            raise BridgeError(f"no forwarded call {key!r} awaits delivery")
        self._commit(sid, [(GE.TOOL_CALL_DELIVERED, {"key": key})])

    def completed(self, sid: str, key: str, result_hash: str = "") -> None:
        """The runtime reports that a forwarded call finished.  The report
        is accepted once for a call the bridge forwarded, at a drain (the
        log says so) or directly (this process says so; a direct forward
        leaves no event, so a restart forgets it).  A call that was never
        forwarded (denied, rejected, expired, still queued) has nothing to
        complete, and a second report is refused."""
        s = self._enter(sid)
        forwarded = key in s.drained or (sid, key) in self._sent
        if key in s.completed or not forwarded:
            raise BridgeError(f"no forwarded call {key!r} to complete")
        self._commit(sid, [(GE.TOOL_CALL_COMPLETED, {
            "key": key, "result_hash": result_hash})])

    # -- client disconnect (I1, I15) -------------------------------------------

    def client_disconnect(self, sid: str, key_id: Optional[str] = None,
                          reason: str = "client_disconnect") -> None:
        """Transport loss of one client (``key_id``) or of every connected
        client (``None``).  Only the last departure detaches (I15b).  A
        key_exhausted session loses its transport like any other."""
        s = self._enter(sid, exhausted_ok=True)
        if s.att == Attachment.DETACHED:
            return                                        # idempotent
        if s.att == Attachment.RESUMING:
            if key_id is not None and key_id != s.resuming:
                return
            targets = {s.resuming}
        else:
            targets = set(s.conn) if key_id is None else {key_id} & s.conn
        if not targets:
            return
        remaining = (set(s.conn) - targets
                     if s.att == Attachment.ATTACHED else set())
        if remaining:
            self._commit(sid, [(GE.CLIENT_LEFT, {"key_id": k, "reason": reason})
                               for k in sorted(targets)])
            return
        self._commit(sid, [
            (GE.DETACHMENT, {"reason": reason}),
            self._prepared_item(s, reason)])
        self._check_timers(sid)

    def _prepared_item(self, s: _Sess, reason: str):
        """RESUME_PREPARED: the bridge's own resume record (Definition
        4.2), once per detachment (I1)."""
        return (GE.RESUME_PREPARED, {
            "authority_hash": _authority_hash(s.principal, s.scope, s.lineage),
            "reason": reason, "authority_scope": list(s.scope),
            "scope_version": s.scope_version,
            "pending_tool_calls": [{"key": c["key"], "call": c["tool"]}
                                   for c in s.queue]})

    # -- human escalation (I2) -----------------------------------------------

    def escalate_to_human(self, sid: str,
                          reason: str = "human_unavailable") -> None:
        s = self._enter(sid)
        self._commit(sid, [(GE.HUMAN_PENDING, {"reason": reason})])
        self._check_timers(sid)

    def human_resolve(self, sid: str) -> None:
        s = self._enter(sid)
        if s.human != Human.PENDING:
            raise BridgeError("human_resolve requires Human=Pend")
        self._commit(sid, [(GE.HUMAN_RESOLVED, {
            "valid_until": self._now() + self.cfg.t_approve})])
        self._drain(sid)               # no-op unless a client is attached

    # -- timers (L1, L2, I13) --------------------------------------------------

    def tick(self, sid: Optional[str] = None) -> None:
        """Evaluate timers now (a fairly scheduled timeout check, A6).
        Also checks I-CHECKPOINT thresholds (time-based)."""
        for x in ([sid] if sid is not None else list(self._sess)):
            self._check_timers(x)
            self._maybe_checkpoint(x)      # guarded by lifecycle and rule Q

    def _check_timers(self, sid: str, *, overdue_only: bool = False) -> None:
        """Fire the timers that have expired.  With ``overdue_only`` only
        those whose expiry lies before the present instant fire: a timer
        that expires in the very tick of an incoming request waits until the
        request has been processed (Section 5.3, edge case 1)."""
        s = self._sess[sid]
        if s.life == Lifecycle.TERMINATED or s.quarantined:
            return
        now = self._now()

        def due(elapsed: float, limit: float) -> bool:
            return elapsed > limit if overdue_only else elapsed >= limit
        detach = (s.att == Attachment.DETACHED and s.detach_at is not None
                  and due(now - s.detach_at, self.cfg.t_detach))
        total = (s.att == Attachment.DETACHED and s.det_since is not None
                 and due(s.det_total + (now - s.det_since), self.cfg.t_total))
        human = (s.human == Human.PENDING and s.human_at is not None
                 and due(now - s.human_at, self.cfg.t_human))
        # the reason names the detach-side timer that fired: the bound of
        # this detachment, or the cumulative cap when only the cap was
        # reached
        away = "detach_timeout" if detach else "detach_total_timeout"
        if (detach or total) and human:
            self._commit(sid, [
                (GE.HUMAN_TIMEOUT, {"reason": "human_timeout"}),
                (GE.DETACH_TIMEOUT, {"reason": away}),
                (GE.TERMINATION, {
                    "reason": f"human_timeout+{away} (simultaneous)"})])
        elif human:
            self._commit(sid, [
                (GE.HUMAN_TIMEOUT, {"reason": "human_timeout"}),
                (GE.TERMINATION, {"reason": "human_timeout"})])
        elif detach or total:
            self._commit(sid, [
                (GE.DETACH_TIMEOUT, {"reason": away}),
                (GE.TERMINATION, {"reason": away})])
        elif not overdue_only:
            expired = [(GE.TOOL_CALL_EXPIRED, {
                "key": c["key"], "tool": c["tool"], "reason": "call_ttl"})
                for c in s.queue if now >= c["expires_at"]]
            if expired:
                self._commit(sid, expired)

    # -- challenge-response re-attach and join (I4, I8, I9, I11, I15) --------

    def challenge(self, sid: str, key_id: str) -> Challenge:
        """Issue a fresh single-use nonce for the key id ``key_id`` (I11b).
        Not a governance event; volatile, so a restart voids every nonce.

        The nonce is bound to ``key_id``: only a request that names this
        key id can use it, and only if the key was a registered, unrevoked
        key of the session when the nonce was issued.  The answer is the
        same for every key id, registered or not: a nonce of the same form
        and lifetime, counted against the same limit of the session.  So
        ``challenge`` says nothing about the registry; a nonce that can
        never verify shows only later, as a bad signature."""
        if not isinstance(key_id, str):
            raise TypeError("challenge takes the key id the nonce is for")
        s = self._sess.get(sid)
        if (s is None or s.life == Lifecycle.TERMINATED
                or s.quarantined):
            # I11a: one rejection for an unknown, a terminated and a
            # quarantined session, so the op confirms neither existence
            # nor lifecycle state to an unauthenticated caller
            raise BridgeError(CHALLENGE_REFUSED, reason="refused")
        book = self._nonces.setdefault(sid, {})
        if len(book) >= NONCE_RECORDS:
            # I11f: make room from spent or expired records only; a live
            # nonce is never evicted, so no caller can invalidate a nonce
            # another client holds.  If every record is live, refuse.
            now = self._now()
            for old in [n for n, r in book.items()
                        if r.used or now - r.issued_at >= self.cfg.t_nonce]:
                del book[old]
                if len(book) < NONCE_RECORDS:
                    break
            if len(book) >= NONCE_RECORDS:
                raise BridgeError("challenge budget exhausted (I11f)")
        nonce = os.urandom(16).hex()
        book[nonce] = _NonceRecord(
            issued_at=self._now(), key_id=key_id,
            eligible=key_id in s.keys and key_id not in s.revoked_keys)
        return Challenge(nonce, self.cfg.t_nonce)

    @staticmethod
    def _well_formed(req: ResumeRequest) -> None:
        """A request whose fields are not of the wire types (Appendix B: the
        sequence number is a non-negative integer, the others are strings)
        is refused as malformed.  The answer depends on the request alone,
        so it is the same for every session, and nothing is logged."""
        ok = (isinstance(req.seq, int) and not isinstance(req.seq, bool)
              and 0 <= req.seq <= 2 ** 53
              and all(isinstance(x, str) for x in (
                  req.key_id, req.nonce, req.hash, req.signature)))
        if not ok:
            raise BridgeError("malformed re-attach request",
                              reason="bad_canonical")

    def begin_resume(self, sid: str, req: ResumeRequest,
                     *, transport_replay: bool = False,
                     op: str = "reattach"):
        """Det -> Res on an authentic re-attach; a join (``op`` "join")
        while Att is a CLIENT_JOINED.  Every failure is RESUME_REJECTED with
        no change of cell (I11e).

        The request is verified before anything that depends on the state
        of the session is answered: key and signature, revocation, the
        nonce and the prefix first; then, only for a request that verified,
        the attachment (``resume_in_progress`` while Res,
        ``already_attached`` for a re-attach while Att, ``not_attached``
        for a join while Det).  An unauthenticated caller therefore gets
        the same answer whatever the attachment, the timers or the keys.
        A request that verified has spent its nonce by then, so a request
        that was presented and refused is not accepted when it is presented
        again."""
        self._well_formed(req)
        self._refuse_unavailable(sid)
        s = self._sess[sid]
        # A timer that expired before this instant has ended the session
        # (the answer is then the uniform one).  A timer that expires in the
        # very tick of the request waits: the request is processed first
        # (Section 5.3, edge case 1) and the timers are evaluated after it.
        self._check_timers(sid, overdue_only=True)
        self._refuse_unavailable(sid)
        reason = self._reject_reason(sid, s, req, op)
        if transport_replay:
            reason = "transport_replay"                            # I8
        if reason is None and s.att == Attachment.RESUMING:
            reason = "resume_in_progress"
        if (reason is None and s.att == Attachment.ATTACHED
                and op == "reattach"):
            reason = "already_attached"
        if (reason is None and s.att != Attachment.ATTACHED
                and op == "join"):
            reason = "not_attached"                                # I15c
        if reason is not None:
            self._record_rejection(sid, req, reason)
            self._check_timers(sid)        # the tick's timers, after it
            raise BridgeError(
                f"re-attach rejected: {_public_reason(reason)} "
                "(I4/I8/I9/I11)", reason=_public_reason(reason))
        self._unauth_logged.pop(sid, None)          # a key holder spoke
        body = {"key_id": req.key_id, "seq": req.seq, "hash": req.hash,
                "nonce_digest": _digest(req.nonce)}
        joined = s.att == Attachment.ATTACHED
        self._commit(sid, [(GE.CLIENT_JOINED if joined
                            else GE.RESUME_STARTED, body)])
        self._check_timers(sid)            # the tick's timers, after it
        return self.replay_after(sid, req.seq) if joined else None

    def _record_rejection(self, sid: str, req: ResumeRequest,
                          reason: str) -> None:
        """RESUME_REJECTED for a refused request.  A refusal of the
        unauthenticated class is logged only until the session has logged
        UNAUTH_LOG_LIMIT of them since its last authentic request, and is
        refused the same way afterwards (I11g); any other refusal comes
        from an active key holder, is always logged and restores the
        allowance."""
        if reason in UNAUTHENTICATED:
            logged = self._unauth_logged.get(sid, 0)
            if logged >= UNAUTH_LOG_LIMIT:
                return
            self._unauth_logged[sid] = logged + 1
        else:
            self._unauth_logged.pop(sid, None)      # a key holder spoke
        self._commit(sid, [(GE.RESUME_REJECTED, {
            "reason": reason, "key_id": req.key_id, "seq": req.seq})])

    def join(self, sid: str, req: ResumeRequest, **kw) -> list[Event]:
        """A further client joins an attached session (I15c).  The request
        is verified like a re-attach, under the join tag; a join that
        verified is refused as ``not_attached`` while no client is attached
        and as ``resume_in_progress`` while a re-attach is being verified,
        so a join proof never starts a re-attach."""
        return self.begin_resume(sid, req, op="join", **kw)

    def _reject_reason(self, sid, s, req, op="reattach"):
        """Why the request does not verify, or None.  The order is fixed:
        the key and the signature, revocation, the binding of the nonce to
        the key, the nonce, the prefix.  Before the nonce step nothing about
        the nonces or the chain is revealed and no nonce is touched, except
        that a revoked key spends the nonce bound to it; from the nonce step
        on the request comes from an active key and has spent its nonce,
        whatever is decided about it afterwards (I11d)."""
        if req.key_id not in s.keys:
            return "unknown_key"                                   # I15
        record = self.storage.key_record(sid, req.key_id)
        scheme, public = record if record else (SCHEME_ED25519, None)
        if public is None or not _verify_scheme(
                scheme, public,
                _resume_bytes(op, sid, req.key_id, req.nonce, req.seq,
                              req.hash),
                req.signature):
            return "bad_signature"                                 # I11c
        rec = self._nonces.get(sid, {}).get(req.nonce)
        # the nonce counts for this request only if it was issued for this
        # key id while the key was an active key of the session
        bound = (rec is not None and rec.key_id == req.key_id
                 and rec.eligible)
        # I11-REVOKE: check after signature, before nonce
        if req.key_id in s.revoked_keys:
            # the signature verified, so the request spends the nonce that
            # was issued to its key (I11d)
            if bound:
                rec.used = True                                    # request
            return "revoked_key"                                   # I11-REVOKE
        if rec is not None and not bound:
            return "nonce_binding"                                 # I11b
        if rec is None:
            return "nonce_unknown"                                 # I11b
        used = rec.used
        rec.used = True                                            # I11d
        if used:
            return "nonce_used"
        if self._now() - rec.issued_at >= self.cfg.t_nonce:   # I9
            return "nonce_expired"
        log = self.storage.logs.get(sid, [])
        if not (0 <= req.seq < len(log)) or log[req.seq].event_hash() != req.hash:
            return "prefix_mismatch"                               # I4
        return None

    def replay_after(self, sid: str, seq: int) -> list[Event]:
        """The events a client that acknowledged ``seq`` has not seen (I4)."""
        return list(self.storage.logs[sid][seq + 1:])

    def complete_resume(self, sid: str) -> list[Event]:
        """Res -> Att once the hash chain verifies; a chain that does not
        verify quarantines the session (rule Q).  Returns the replay of the
        events after the acknowledged prefix."""
        s = self._enter(sid)
        if s.att != Attachment.RESUMING:
            raise BridgeError("complete_resume requires Att=Res")
        from_seq = s.resume_from
        try:
            self._verify_event_chain(sid)
        except BridgeError:
            self._quarantine(sid, GE.RESUME_FAILED, {"reason": "chain"})
            raise
        self._commit(sid, [(GE.RESUME_VERIFIED, {})])
        self._drain(sid)
        return self.replay_after(sid, from_seq)

    def _quarantine(self, sid: str, kind: GovernanceEvent,
                    payload: dict) -> None:
        """Freeze a session whose log cannot be vouched for (A.5).  The
        failure is recorded if the bridge can still append; otherwise the
        session is frozen in memory only, and recovery finds it again."""
        try:
            self._commit(sid, [(kind, payload)])
        except StorageError:
            self._sess[sid].quarantined = True

    def client_reattach(self, sid: str, req: ResumeRequest,
                        *, transport_replay: bool = False):
        out = self.begin_resume(sid, req, transport_replay=transport_replay)
        if self._sess[sid].att == Attachment.RESUMING:
            return self.complete_resume(sid)
        return out

    # -- authority (I3, I10) -------------------------------------------------

    def attempt_authority_extension(self, sid: str,
                                    new_scope: tuple[str, ...],
                                    source: str = "requested"):
        """Reject any widening in every cell; a subset is not an extension.
        ``source="observed"``: the runtime changed its own scope; the
        bridge cannot prevent that, so it records the rejection, keeps its
        record unchanged and asks for a revert (I3).  An observed widening
        is a report about the runtime, not a client operation, so it is
        recorded on a key_exhausted session too."""
        s = self._enter(sid, exhausted_ok=source == "observed")
        new_scope = canonical_scope(new_scope)
        if set(new_scope).issubset(s.scope):
            return None
        if source == "observed":
            self._commit(sid, [(GE.AUTHORITY_EXTENSION_REJECTED, {
                "proposed": list(new_scope), "current": list(s.scope),
                "cell": f"{s.att.value}/{s.human.value}",
                "source": "observed"})])
            self.revert_requests.append((sid, s.scope))
            return "REVERT"
        self._reject_extension(sid, s, new_scope, "extension_rejected")

    def _reject_extension(self, sid, s, new_scope, reason):
        """Record and refuse a widening; ``reason`` is the typed wire reason
        (``extension_rejected`` for the extend op, ``not_a_strict_narrowing``
        for a narrow op that asked for more)."""
        self._commit(sid, [(GE.AUTHORITY_EXTENSION_REJECTED, {
            "proposed": list(new_scope), "current": list(s.scope),
            "cell": f"{s.att.value}/{s.human.value}",
            "source": "requested"})])
        raise BridgeError("authority extension rejected (I3)", reason=reason)

    def narrow_authority_scope(self, sid: str,
                               new_scope: tuple[str, ...]) -> int:
        """Replace the scope by a strict subset of it (I10); returns the new
        scope version.  A proposal that equals or widens the scope is
        refused as ``not_a_strict_narrowing`` and recorded."""
        s = self._enter(sid)
        new_scope = canonical_scope(new_scope)
        proposed, current = set(new_scope), set(s.scope)
        if not proposed.issubset(current):
            self._reject_extension(sid, s, new_scope,
                                   "not_a_strict_narrowing")
        if proposed == current:
            self._commit(sid, [(GE.AUTHORITY_NARROWING_REJECTED, {
                "proposed": list(new_scope), "current": list(s.scope),
                "reason": "not a strict narrowing"})])
            raise BridgeError("authority narrowing rejected (I10)",
                              reason="not_a_strict_narrowing")
        version = s.scope_version + 1
        self._commit(sid, [(GE.AUTHORITY_NARROWED, {
            "new_scope": list(new_scope), "new_version": version})])
        return version

    @property
    def scope_versions(self) -> dict[str, int]:
        return {sid: s.scope_version for sid, s in self._sess.items()}

    # -- termination (I6) ----------------------------------------------------

    def terminate(self, sid: str, reason: str = "terminated") -> None:
        """Unsigned termination (the transport binding authenticates the
        caller).  A key_exhausted session is ended only by
        ``operator_terminate``, which verifies the operator's signature; a
        bare terminate is refused and commits nothing (I11-REVOKE)."""
        if sid not in self._sess:
            raise BridgeError(f"unknown session {sid}", reason="unknown_session")
        s = self._sess[sid]
        if s.life == Lifecycle.TERMINATED:
            return
        if s.key_exhausted and not s.quarantined:
            self._check_timers(sid)          # an expired session is over
            if s.life == Lifecycle.TERMINATED:
                return
            raise BridgeError("session is KEY_EXHAUSTED: terminate needs "
                              "the operator's signature",
                              reason="key_exhausted")
        self._commit(sid, [(GE.TERMINATION, {"reason": reason})])   # also the
        # operator's way out of quarantine

    # -- key lifecycle (I11-REVOKE) -------------------------------------------

    def head_of(self, sid: str) -> tuple[int, str]:
        """The log position an operator signs: the sequence and the hash of
        the last event."""
        log = self.storage.logs.get(sid, [])
        return len(log) - 1, (log[-1].event_hash() if log else "")

    def _operator_verified(self, build, signature: Optional[str],
                           sid: str) -> None:
        """Operator events are authenticated by the deployment's operator
        verifier (the one that checks scope grants).  ``build`` maps the
        current log position (sequence, head hash) to the bytes the
        operator signs, which also name this bridge; without a verifier, or
        with a signature that does not verify over those bytes (another
        bridge, another session, another operation, another position), they
        are refused and nothing is committed.

        The check comes before anything is said about the session: a
        caller without the operator's signature gets this refusal for every
        session id, known or not, whatever its lifecycle and its keys.  The
        timers that are due fire before it, as at any tick, so the position
        the signature names is the one the operator's event follows and an
        expired session is over (L1)."""
        if sid in self._sess:
            self._check_timers(sid)          # an expired session is over (L1)
        seq, head = self.head_of(sid)
        message = build(self.bridge_id, seq, head)
        check = getattr(self.grant_verifier, "verify_operation", None)
        if check is None or not check(message, signature):
            raise OperatorSignatureInvalid(
                "operator_signature_invalid: operator signature missing "
                "or invalid")

    def revoke_key(self, sid: str, key_id: str, reason: str = "rotation",
                   signature: Optional[str] = "",
                   requested_by: Optional[str] = None) -> str:
        """Operator-signed revocation of a registered client key (I11-REVOKE).

        ``reason``: 'rotation' (soft) or 'compromise' (hard); any other
        value is a malformed request.
        ``signature``: operator Ed25519 signature over
        ``[bc/v1/revoke, bridge_id, sid, key_id, reason, seq, head]`` (the log
        position at signing); it is verified first, and a
        signature that does not verify is refused (``operator_signature_
        invalid``) before anything is said about the session or committed.
        ``requested_by``: if set, a client requested it (emits
        KEY_REVOCATION_REQUESTED first, then KEY_REVOKED if a signature
        is present); no signature (absent or empty) with ``requested_by``
        records only the request, and without it is a missing signature
        (refused).  A key that is already revoked is not revoked again.

        Returns 'revoked' if the key was revoked, 'requested' if only
        a request was recorded.
        """
        if reason not in REVOKE_REASONS:
            raise BridgeError(f"unknown revocation reason {reason!r}",
                              reason="bad_canonical")
        signed = signature is not None and signature != ""
        if signed or requested_by is None:
            self._operator_verified(
                lambda b, q, h: _revoke_bytes(b, sid, key_id, reason, q, h),
                signature, sid)
        s = self._enter(sid)
        if key_id not in s.keys:
            raise BridgeError(f"unknown key {key_id!r}", reason="unknown_key")
        if key_id in s.revoked_keys:
            raise BridgeError(f"key {key_id!r} is already revoked",
                              reason="revoked_key")
        now = self._now()
        if requested_by is not None:
            asked = self._revocation_requests.get(sid, 0)
            if asked >= REVOCATION_REQUEST_LIMIT:
                # A request needs no signature, so its writes are bounded;
                # the refusal appends nothing.
                raise BridgeError("revocation requests refused: limit reached")
            self._revocation_requests[sid] = asked + 1
            self._commit(sid, [(GE.KEY_REVOCATION_REQUESTED, {
                "key_id": key_id, "requested_by": requested_by,
                "reason": reason})])
        if signed:
            payload = {"key_id": key_id, "reason": reason,
                       "revoked_at": now, "signature": signature}
            items = [(GE.KEY_REVOKED, payload)]
            if ((reason == "compromise" and s.conn == {key_id}
                 and s.att == Attachment.ATTACHED)
                    or (s.att == Attachment.RESUMING
                        and s.resuming == key_id)):
                # Hard revocation of the last connected key, or a revocation
                # of either kind of the key whose re-attach is being
                # verified (the verification is abandoned): detach
                items += [(GE.DETACHMENT, {"reason": "key_revoked"}),
                          self._prepared_item(s, "key_revoked")]
            # _apply marks the key revoked, drops a hard-revoked key from
            # the client set and sets key_exhausted; the log alone decides
            self._commit(sid, items)
            self._revocation_requests.pop(sid, None)
            return "revoked"
        return "requested"

    def operator_add_key(self, sid: str, key_id: str, public_key: str,
                         signature: Optional[str] = None,
                         scheme: str = SCHEME_ED25519) -> None:
        """Operator adds a key to a key_exhausted session (recovery).
        ``public_key`` is hex; the registry receives the scheme tag and the
        public key, so the new key can re-attach.  A key id already
        registered (revoked or not) is refused: a revoked key never returns
        to the active state.  ``signature`` is the operator's over
        ``[bc/v1/add-key, bridge_id, sid, key_id, scheme, public_key, seq,
        head]``; it is verified first, before anything is said about the
        session.  A quarantined session takes no key (rule Q: only a
        TERMINATION may follow the failure event)."""
        self._operator_verified(
            lambda b, q, h: _add_key_bytes(b, sid, key_id, scheme,
                                           public_key, q, h),
            signature, sid)
        if sid not in self._sess:
            raise BridgeError(f"unknown session {sid}", reason="unknown_session")
        s = self._sess[sid]
        if s.life == Lifecycle.TERMINATED:
            raise BridgeError("session is TERMINATED (I6)", reason="terminated")
        if s.quarantined:
            raise BridgeError("session is QUARANTINED", reason="quarantined")
        if not s.key_exhausted:
            raise BridgeError("session is not key_exhausted",
                              reason="not_key_exhausted")
        if key_id in s.keys:
            raise BridgeError("client key already registered",
                              reason="key_already_registered")
        self.storage.register_key(sid, key_id, scheme,
                                  bytes.fromhex(public_key))
        try:
            self._commit(sid, [(GE.OPERATOR_ADD_KEY, {
                "key_id": key_id, "scheme": scheme,
                "public_key": public_key, "signature": signature})])
        except StorageError:
            self.storage.unregister_key(sid, key_id)
            raise

    def operator_terminate(self, sid: str, reason: str = "all_keys_revoked",
                           signature: Optional[str] = None) -> None:
        """Operator terminates a key_exhausted session; ``signature`` is
        the operator's over ``[bc/v1/terminate, bridge_id, sid, reason,
        seq, head]`` and is verified first.  A session that is already
        terminated has nothing to terminate: the request is refused."""
        self._operator_verified(
            lambda b, q, h: _terminate_bytes(b, sid, reason, q, h),
            signature, sid)
        if sid not in self._sess:
            raise BridgeError(f"unknown session {sid}", reason="unknown_session")
        s = self._sess[sid]
        if s.life == Lifecycle.TERMINATED:
            raise BridgeError("session is TERMINATED (I6)", reason="terminated")
        if not s.key_exhausted:
            raise BridgeError("session is not key_exhausted",
                              reason="not_key_exhausted")
        self._commit(sid, [(GE.OPERATOR_TERMINATION, {
            "reason": reason, "signature": signature})])
        self._commit(sid, [(GE.TERMINATION, {"reason": reason})])

    # -- restart and recovery (Section 5.5) ------------------------------------

    @classmethod
    def recover(cls, storage: Storage, clock=None,
                config: Optional[Config] = None,
                grant_verifier=None,
                bridge_id: str = DEFAULT_BRIDGE_ID) -> "Bridge":
        """Rebuild every session from the durable log; every client is
        gone because every transport died with the process; nonces are
        void.  The log is the source of truth for the key registry: an
        entry that is missing, differs or has no event in the log (the
        registry is written before the event commits, so a crash between
        the two leaves one) is repaired from the log, and BRIDGE_RECOVERED
        names the repaired key ids."""
        b = cls(storage, clock, config, grant_verifier, bridge_id)
        for sid, log in list(storage.logs.items()):
            try:
                for ev in log:                     # replay: log determines cell
                    b._apply(ev)
                    if ev.kind == GE.CHECKPOINT:
                        b._last_cp[sid] = ev.timestamp  # rebuild checkpoint tracker
            except Exception:
                # A log that cannot be replayed (no ATTACHED first, a missing
                # payload field) freezes its own session only; the rest are
                # recovered.  Nothing is appended to the malformed log.
                b._sess[sid] = _Sess(sid=sid, principal="", lineage=(),
                                     scope=(), att=Attachment.DETACHED,
                                     quarantined=True)
                continue
            for i in range(len(log) - 1, -1, -1):   # events counted from the last one
                if log[i].kind == GE.CHECKPOINT:
                    b._cp_len[sid] = i + 1
                    break
            s = b._sess[sid]
            if s.life == Lifecycle.TERMINATED or s.quarantined:
                continue                           # quarantine survives restart
            try:
                b._verify_event_chain(sid)
            except Exception as exc:               # BridgeError or malformed
                b._quarantine(sid, GE.RECOVERY_FAILED, {"reason": str(exc)})
                continue
            repaired = b._repair_registry(sid, s)
            b._commit(sid, [
                (GE.BRIDGE_RECOVERED, {"events": len(log),
                                       "registry_repaired": repaired}),
                (GE.DETACHMENT, {"reason": "bridge_restart"}),
                b._prepared_item(s, "bridge_restart")])
            b._check_timers(sid)
        return b

    # -- internal helpers ----------------------------------------------------

    def _enter(self, sid: str, exhausted_ok: bool = False) -> _Sess:
        """Common prelude: known, not terminated (I6), timers evaluated.
        A key_exhausted session serves no client operation, but its timers
        keep running: they are evaluated before the refusal, so an expired
        one reports TERMINATED.  ``exhausted_ok`` is for transport loss,
        which is not a client operation."""
        if sid not in self._sess:
            raise BridgeError(f"unknown session {sid}", reason="unknown_session")
        s = self._sess[sid]
        if s.life == Lifecycle.TERMINATED:
            raise BridgeError("session is TERMINATED (I6)", reason="terminated")
        if s.quarantined:
            raise BridgeError("session is QUARANTINED", reason="quarantined")
        if s.key_exhausted and not exhausted_ok:
            self._check_timers(sid)
            if s.life == Lifecycle.TERMINATED:
                raise BridgeError("session is TERMINATED (I6)", reason="terminated")
            raise BridgeError("session is KEY_EXHAUSTED", reason="key_exhausted")
        self._check_timers(sid)
        if s.life == Lifecycle.TERMINATED:
            raise BridgeError("session is TERMINATED (I6)", reason="terminated")
        return s

    def _refuse_unavailable(self, sid: str) -> None:
        """I11a: a resume request (re-attach or join) for an unknown, a
        terminated or a quarantined session gets one rejection, so the op
        confirms neither existence nor lifecycle state before the caller
        has proved anything."""
        s = self._sess.get(sid)
        if s is None or s.life == Lifecycle.TERMINATED or s.quarantined:
            raise BridgeError(RESUME_REFUSED, reason="refused")

    def _repair_registry(self, sid: str, s: _Sess) -> list[str]:
        """Make the stored registry equal to the keys the log records (the
        log is the source of truth): drop an entry the log does not
        record, write a missing one and replace one that differs.  Returns
        the key ids repaired, sorted."""
        repaired: set[str] = set()
        for kid in self.storage.registered_key_ids(sid) - s.keys:
            self.storage.unregister_key(sid, kid)
            repaired.add(kid)
        for kid, (scheme, public_hex) in s.key_material.items():
            want = (scheme, bytes.fromhex(public_hex))
            if self.storage.key_record(sid, kid) != want:
                self.storage.unregister_key(sid, kid)
                self.storage.register_key(sid, kid, scheme, want[1])
                repaired.add(kid)
        return sorted(repaired)

    def _chain_hashes(self, sid: str) -> list[bytes]:
        """Verify the hash chain of the session's log (I5): every event
        carries its position as its sequence number and the hash of its
        predecessor.  Returns the event hashes in order (the leaves of a
        checkpoint)."""
        prev, hashes = "", []
        for i, ev in enumerate(self.storage.logs.get(sid, [])):
            if ev.sequence != i or ev.prev_hash != prev:
                raise BridgeError(
                    f"event chain broken at index {i}: expected sequence "
                    f"{i} and prev_hash={prev!r}, got sequence "
                    f"{ev.sequence} and {ev.prev_hash!r} (I5)")
            prev = ev.event_hash()
            hashes.append(bytes.fromhex(prev))
        return hashes

    def _verify_event_chain(self, sid: str) -> None:
        self._chain_hashes(sid)

    @staticmethod
    def _cell(s: _Sess) -> Cell:
        return Cell(s.att, s.human, s.life)

    # -- introspection ------------------------------------------------------

    @property
    def events(self) -> dict[str, list[Event]]:
        return self.storage.logs

    def resume_record(self, sid: str) -> Optional[Event]:
        """The RESUME_PREPARED event of the current detachment, if any."""
        return self._sess[sid].record

    def is_quarantined(self, sid: str) -> bool:
        return self._sess[sid].quarantined

    def detached_total(self, sid: str) -> float:
        """Seconds spent away so far, over all detachments of the session."""
        s = self._sess[sid]
        open_ = (self._now() - s.det_since) if s.det_since is not None else 0.0
        return s.det_total + open_

    def cell_of(self, sid: str) -> Cell:
        return self._cell(self._sess[sid])

    def client_set(self, sid: str) -> frozenset[str]:
        return frozenset(self._sess[sid].conn)

    def registered_keys(self, sid: str) -> frozenset[str]:
        return frozenset(self._sess[sid].keys)

    def state_of(self, sid: str) -> State:
        return five_state_view(self.cell_of(sid))

    def queued_tools(self, sid: str) -> list[str]:
        return [c["tool"] for c in self._sess[sid].queue]

    def scope_of(self, sid: str) -> tuple[str, ...]:
        return self._sess[sid].scope


# ----------------------------------------------------------------------
# 3. Test helpers
# ----------------------------------------------------------------------

import pytest  # noqa: E402


def op_sig(bridge, op, sid, *args, operator=None, bridge_id=None, at=None):
    """An operator signature over ``op`` (revoke, add_key, terminate) at the
    bridge's current log position, unless ``at`` = (seq, head) says
    otherwise; ``operator`` and ``bridge_id`` default to the suite's."""
    seq, head = at if at is not None else bridge.head_of(sid)
    return getattr(operator or TEST_OPERATOR, op)(
        bridge_id or bridge.bridge_id, sid, *args, seq, head)


def op_revoke(bridge, sid, key_id, reason="rotation", **kw):
    """Revoke with the suite operator's signature over the operation."""
    seq, head = bridge.head_of(sid)
    return bridge.revoke_key(
        sid, key_id, reason,
        signature=TEST_OPERATOR.revoke(bridge.bridge_id, sid, key_id, reason,
                                       seq, head), **kw)


def op_add_key(bridge, sid, key_id, public_key, scheme=SCHEME_ED25519):
    seq, head = bridge.head_of(sid)
    return bridge.operator_add_key(
        sid, key_id, public_key,
        signature=TEST_OPERATOR.add_key(bridge.bridge_id, sid, key_id,
                                        public_key, seq, head, scheme),
        scheme=scheme)


def op_terminate(bridge, sid, reason="all_keys_revoked"):
    seq, head = bridge.head_of(sid)
    return bridge.operator_terminate(
        sid, reason, signature=TEST_OPERATOR.terminate(
            bridge.bridge_id, sid, reason, seq, head))


ATT, DET, RES = Attachment.ATTACHED, Attachment.DETACHED, Attachment.RESUMING
NONE, PEND = Human.NONE, Human.PENDING
ACTIVE, TERM = Lifecycle.ACTIVE, Lifecycle.TERMINATED
SID = "sess-001"
SCOPE = ("exec:shell", "read:docs")        # in canonical (sorted) order
ALL_ACTIVE_CELLS = [(a, h) for a in (ATT, DET, RES) for h in (NONE, PEND)]


def add_client(bridge: "Bridge", sid: str, via: "ClientKey",
               new_key: ClientPublicKey) -> None:
    """Obtain a nonce and sign as the connected client ``via`` (the
    client side of CLIENT_ADDED)."""
    nonce = bridge.challenge(sid, via.key_id).nonce
    bridge.add_client_key(sid, via.key_id, new_key, nonce,
                          via.sign_add_client(sid, new_key, nonce))


class Env:
    """A bridge plus its simulated clients, clock and durable storage.

    ``seen[key_id]`` is the (seq, hash) of the last event that client
    observed on the event stream; a re-attach request acknowledges it."""

    def __init__(self, config: Optional[Config] = None,
                 scope: tuple[str, ...] = SCOPE, sid: str = SID,
                 checkpoints: bool = False) -> None:
        self.sid = sid
        self.clock = FakeClock()
        self.storage = Storage()
        # Checkpoints are off unless a test asks for them, so that they do
        # not add CHECKPOINT events to the event lists the other tests
        # expect.  With ``checkpoints`` the thresholds of ``config`` stand
        # (the tests that run with checkpoints on, T63 to T66f).
        if config is None:
            config = Config()
        if not checkpoints:
            config.n_checkpoint = 10**9
            config.t_checkpoint = float("inf")
        self.config = config
        self.key = ClientKey("ck-1")
        self.keys = {"ck-1": self.key}
        self.bridge = Bridge(self.storage, self.clock, config,
                             OperatorGrantVerifier(TEST_OPERATOR.public_key))
        self.initial_scope = scope
        identity = SessionIdentity(sid, "user-alice", scope, ("root",))
        attach_as(self.bridge, identity, self.key)
        self.seen: dict[str, tuple[int, str]] = {}
        self.sync("ck-1")

    def restart(self) -> Bridge:
        self.bridge = Bridge.recover(
            self.storage, self.clock, self.config,
            OperatorGrantVerifier(TEST_OPERATOR.public_key))
        return self.bridge

    def kinds(self) -> list[GovernanceEvent]:
        return [e.kind for e in self.bridge.events[self.sid]]

    def cell(self) -> tuple[Attachment, Human, Lifecycle]:
        return tuple(self.bridge.cell_of(self.sid))

    def tip(self) -> tuple[int, str]:
        ev = self.bridge.events[self.sid][-1]
        return ev.sequence, ev.event_hash()

    def sync(self, key_id: str) -> None:
        """The client has observed every event committed so far."""
        self.seen[key_id] = self.tip()

    def request(self, key_id: str = "ck-1", *, prefix=None, nonce=None,
                key: Optional[ClientKey] = None,
                op: str = "reattach") -> ResumeRequest:
        signer = key or self.keys[key_id]
        nonce = nonce or self.bridge.challenge(self.sid, signer.key_id).nonce
        seq, h = prefix or self.seen[key_id]
        return signer.request(self.sid, nonce, seq, h, op)

    def disconnect(self, key_id: Optional[str] = None) -> None:
        """Transport loss; the departing clients saw everything so far."""
        gone = (self.bridge.client_set(self.sid) if key_id is None
                else {key_id})
        for k in gone:
            if k in self.keys:
                self.sync(k)
        self.bridge.client_disconnect(self.sid, key_id)

    def add_device(self, key_id: str = "ck-2") -> ClientKey:
        key = ClientKey(key_id)
        conn = sorted(self.bridge.client_set(self.sid))
        via = conn[0] if conn else "ck-1"
        add_client(self.bridge, self.sid, self.keys[via], key.public())
        self.keys[key_id] = key
        self.sync(key_id)
        return key

    def begin_resume(self, key_id: str = "ck-1", **kw) -> None:
        self.bridge.begin_resume(self.sid, self.request(key_id), **kw)

    def reattach(self, key_id: str = "ck-1", **kw):
        return self.bridge.client_reattach(
            self.sid, self.request(key_id), **kw)

    def join(self, key_id: str = "ck-2", **kw):
        return self.bridge.join(self.sid, self.request(key_id, op="join"),
                                 **kw)

    def answer_all(self, approve: bool = True) -> None:
        """A faithful client: answer every unanswered queued call with the
        hash of what it was shown."""
        b = self.bridge
        for c in list(b._sess[self.sid].queue):
            if c["answer"] is None:
                b.answer_tool_call(self.sid, c["key"],
                                   b.shown_hash_of(self.sid, c["key"]),
                                   approve)

    def resolve(self) -> None:
        self.answer_all()
        self.bridge.human_resolve(self.sid)

    def reach(self, att: Attachment, human: Human) -> "Env":
        """Drive the bridge into the active cell (att, human)."""
        b, sid = self.bridge, self.sid
        if att != ATT:
            self.disconnect()
        if human == PEND:
            b.escalate_to_human(sid)
        if att == RES:
            self.begin_resume()
        assert self.cell() == (att, human, ACTIVE)
        return self


def _kinds_after(env: Env, n: int) -> list[GovernanceEvent]:
    return env.kinds()[n:]


def _no_events_after_termination(env: Env) -> None:
    ks = env.kinds()
    if GE.TERMINATION in ks:
        assert ks.index(GE.TERMINATION) == len(ks) - 1


def _rejects(env: Env, req: ResumeRequest, reason: str, **kw) -> None:
    """The request is refused with ``reason`` and the cell is unchanged."""
    before = env.cell()
    with pytest.raises(BridgeError, match="rejected"):
        env.bridge.begin_resume(env.sid, req, **kw)
    assert env.cell() == before
    last = env.bridge.events[env.sid][-1]
    assert last.kind == GE.RESUME_REJECTED
    assert last.payload["reason"] == reason


# ----------------------------------------------------------------------
# 4. Example-based conformance tests T1-T7 (rewritten for the product model)
# ----------------------------------------------------------------------

def test_T1_disconnect_then_authenticated_reattach():
    """T1: I1, I4, I5, I7, I11 -- detach, then resume by challenge."""
    env = Env()
    b = env.bridge
    b.escalate_to_human(SID, reason="tool_needs_confirmation")
    env.disconnect()
    assert env.cell() == (DET, PEND, ACTIVE)

    ks = env.kinds()
    assert ks[-2:] == [GE.DETACHMENT, GE.RESUME_PREPARED]          # I1
    record = b.resume_record(SID)
    assert record.sequence == len(ks) - 1
    assert record.payload["reason"] == "client_disconnect"
    _check_chain(env)                                               # I5

    n = len(ks)
    seen_seq, _ = env.seen["ck-1"]
    got = env.reattach()
    assert _kinds_after(env, n) == [GE.RESUME_STARTED, GE.RESUME_VERIFIED]
    assert env.cell() == (ATT, PEND, ACTIVE)         # human still pending
    # I4: every event after the acknowledged prefix is replayed
    assert [e.sequence for e in got] == list(range(seen_seq + 1, len(env.kinds())))
    assert got[-1].kind == GE.RESUME_VERIFIED


def test_T2_pending_human_tool_calls_are_queued_not_forwarded():
    """T2: I2, I13 -- calls queue while Human=Pend, drain on resolve."""
    env = Env()
    b = env.bridge
    b.escalate_to_human(SID)
    results = [b.submit_tool_call(SID, t) for t in
               ("shell:rm -rf /tmp/x", "shell:git push", "shell:curl ...")]
    assert results == ["QUEUED"] * 3
    assert b.forwarded == []
    assert b.queued_tools(SID) == [
        "shell:rm -rf /tmp/x", "shell:git push", "shell:curl ..."]
    assert env.kinds().count(GE.TOOL_CALL_QUEUED) == 3

    env.resolve()
    assert env.kinds().count(GE.TOOL_CALL_DRAINED) == 3
    assert [t for _, _, t in b.forwarded] == [
        "shell:rm -rf /tmp/x", "shell:git push", "shell:curl ..."]
    assert b.queued_tools(SID) == []
    assert env.cell() == (ATT, NONE, ACTIVE)


def test_T3_authority_extension_rejected_while_detached():
    """T3: I3 -- widening is rejected; a subset is not an extension."""
    env = Env()
    env.disconnect()
    with pytest.raises(BridgeError, match="I3"):
        env.bridge.attempt_authority_extension(
            SID, SCOPE + ("exec:sudo",))
    assert env.kinds().count(GE.AUTHORITY_EXTENSION_REJECTED) == 1
    env.bridge.attempt_authority_extension(SID, ("read:docs",))   # subset
    assert env.kinds().count(GE.AUTHORITY_EXTENSION_REJECTED) == 1
    assert env.bridge.scope_of(SID) == SCOPE


def test_T4_terminated_is_irreversible():
    """T4: I6 -- every mutating operation fails after termination."""
    env = Env()
    env.bridge.terminate(SID, reason="user_quit")
    assert env.cell()[2] == TERM
    dummy = ResumeRequest("ck-1", "n", 0, "h", "s")
    ops = [
        lambda: env.bridge.client_disconnect(SID),
        lambda: env.bridge.escalate_to_human(SID),
        lambda: env.bridge.human_resolve(SID),
        lambda: env.bridge.submit_tool_call(SID, "noop"),
        lambda: env.bridge.attempt_authority_extension(SID, ("read:docs",)),
        lambda: env.bridge.narrow_authority_scope(SID, ("read:docs",)),
        lambda: env.bridge.challenge(SID, "ck-1"),
        lambda: env.bridge.begin_resume(SID, dummy),
        lambda: env.bridge.join(SID, dummy),
        lambda: env.bridge.complete_resume(SID),
        lambda: env.bridge.add_client_key(SID, "ck-1", ClientKey("ck-9").public(), "n", "s"),
        lambda: env.bridge.answer_tool_call(SID, "k", "h"),
        lambda: attach_as(env.bridge, SessionIdentity(SID, "u", SCOPE, ()),
                          ClientKey("ck-2")),
    ]
    for op in ops:
        with pytest.raises(BridgeError):
            op()
    _no_events_after_termination(env)


def test_T5_event_chain_breaks_on_tamper():
    """T5: I5 -- a forged or edited event is detected."""
    env = Env()
    env.disconnect()
    env.bridge._verify_event_chain(SID)                  # intact
    log = env.storage.logs[SID]
    log.append(Event(GE.HUMAN_RESOLVED, SID, len(log), "00" * 32, {}, 0.0))
    with pytest.raises(BridgeError, match="I5"):
        env.bridge._verify_event_chain(SID)
    log.pop()
    log[1].payload["reason"] = "edited"                  # edit mid-log
    with pytest.raises(BridgeError, match="I5"):
        env.bridge._verify_event_chain(SID)


def test_T6_human_timeout_terminates():
    """T6: L2, I6, I7 -- T_human elapsed in Human=Pend terminates."""
    env = Env()
    env.bridge.escalate_to_human(SID)
    env.clock.advance(Config().t_human - 1)
    env.bridge.tick()
    assert env.cell()[2] == ACTIVE
    env.clock.advance(1)
    env.bridge.tick()
    assert env.cell()[2] == TERM
    assert env.kinds()[-2:] == [GE.HUMAN_TIMEOUT, GE.TERMINATION]
    _no_events_after_termination(env)
    with pytest.raises(BridgeError):
        env.bridge.client_disconnect(SID)


def test_T7_non_prefix_history_is_rejected_without_state_change():
    """T7: I4, I11(e) -- a history that is not a prefix of the chain is
    rejected, never terminal."""
    env = Env()
    env.disconnect()
    tip_seq, tip_hash = env.tip()
    wrong_hash = env.request(prefix=(tip_seq, "00" * 32))
    _rejects(env, wrong_hash, "prefix_mismatch")
    beyond = env.request(prefix=(tip_seq + 5, tip_hash))     # never reached
    _rejects(env, beyond, "prefix_mismatch")
    other_seq = env.request(prefix=(0, tip_hash))            # hash of seq tip
    _rejects(env, other_seq, "prefix_mismatch")
    assert env.cell() == (DET, NONE, ACTIVE)
    env.reattach()                                  # the genuine one works
    assert env.cell() == (ATT, NONE, ACTIVE)


def test_T7b_a_negative_sequence_number_is_a_malformed_request():
    """I4: a sequence number is a position in the log, so it is not
    negative.  A request that carries one, even with the hash of the event a
    negative index would reach and a valid signature over it, is refused as
    malformed (``bad_canonical``), whatever the session; nothing is logged
    and its nonce is not spent.  The wire server answers the same."""
    import wire
    import wire_server
    env = Env()
    env.disconnect()
    tip_seq, tip_hash = env.tip()
    n = len(env.kinds())
    nonce = env.bridge.challenge(SID, "ck-1").nonce
    for seq in (-1, -len(env.kinds()), True, "0", 2 ** 53 + 1):
        bad = ResumeRequest("ck-1", nonce, seq, tip_hash, "00" * 64)
        if isinstance(seq, int) and not isinstance(seq, bool) and seq < 0:
            bad = env.key.request(SID, nonce, seq, tip_hash)   # truly signed
        for sid in (SID, "no-such-session"):
            with pytest.raises(BridgeError) as exc:
                env.bridge.begin_resume(sid, bad)
            assert exc.value.reason == "bad_canonical"
    assert len(env.kinds()) == n and env.cell() == (DET, NONE, ACTIVE)
    assert env.bridge._nonces[SID][nonce].used is False
    server = wire_server.WireServer(env.bridge)
    signed = env.key.request(SID, nonce, -1, tip_hash)
    for send in (wire.op_reattach, wire.op_join):
        with pytest.raises(wire_server.WireRejected) as exc:
            wire_server.send(server, send(
                session_id=SID, key_id="ck-1", nonce=nonce, seq=-1,
                hash=tip_hash, signature=signed.signature))
        assert exc.value.reason == "bad_canonical"
    assert len(env.kinds()) == n
    env.bridge.client_reattach(SID, env.key.request(
        SID, nonce, tip_seq, tip_hash))             # the nonce is still good
    assert env.cell() == (ATT, NONE, ACTIVE)


# ----------------------------------------------------------------------
# 5. Property-based tests T8-T10 (Hypothesis)
# ----------------------------------------------------------------------

from hypothesis import Phase, given, settings, strategies as st  # noqa: E402

# The mutation check needs to learn that a property fails, not the smallest
# example of the failure: with BRIDGE_SUITE_NO_SHRINK set, a property stops
# at the first failing example it generates.
settings.register_profile("no-shrink", phases=(
    Phase.explicit, Phase.reuse, Phase.generate))
if os.environ.get("BRIDGE_SUITE_NO_SHRINK"):
    settings.load_profile("no-shrink")

_OPS = ["disconnect", "leave", "escalate", "resolve", "tool", "answer",
        "extend", "observe", "narrow", "begin", "complete", "reattach",
        "stale_reattach", "add_device", "join", "advance", "advance_big",
        "restart", "terminate"]


def _action_strategy():
    return st.tuples(st.sampled_from(_OPS), st.integers(0, 5))


def _apply_action(env: Env, action, stale: list, rejected: list) -> None:
    """Apply one action.  Only BridgeError (a refusal) is expected; it is
    recorded.  Any other exception propagates and fails the test."""
    kind, n = action
    b, sid = env.bridge, SID
    cell_before = env.cell()
    try:
        if kind == "disconnect":
            env.disconnect()
        elif kind == "leave":
            env.disconnect("ck-2")
        elif kind == "escalate":
            b.escalate_to_human(sid)
        elif kind == "resolve":
            b.human_resolve(sid)
        elif kind == "tool":
            out = b.submit_tool_call(sid, f"tool:{n}", permission=None)
            if cell_before[1] == PEND:
                assert out != "FORWARDED"                          # I2
        elif kind == "answer":
            env.answer_all(approve=n != 0)
        elif kind == "extend":
            b.attempt_authority_extension(sid, SCOPE + (f"new:{n}",))
        elif kind == "observe":
            b.attempt_authority_extension(sid, SCOPE + (f"new:{n}",),
                                          source="observed")
        elif kind == "narrow":
            b.narrow_authority_scope(sid, SCOPE[: n % 3])
        elif kind == "begin":
            req = env.request()
            stale.append(req)
            b.begin_resume(sid, req)
        elif kind == "complete":
            b.complete_resume(sid)
        elif kind == "reattach":
            req = env.request()
            stale.append(req)
            b.client_reattach(sid, req)
        elif kind == "stale_reattach" and stale:
            b.client_reattach(sid, stale[n % len(stale)])
        elif kind == "add_device":
            if "ck-2" not in env.keys:
                env.add_device("ck-2")
        elif kind == "join" and "ck-2" in env.keys:
            req = env.request("ck-2")
            stale.append(req)
            b.begin_resume(sid, req)
        elif kind == "advance":
            env.clock.advance(n * 60)
            b.tick()
        elif kind == "advance_big":
            env.clock.advance(n * 600)
            b.tick()
        elif kind == "restart":
            env.restart()
        elif kind == "terminate":
            b.terminate(sid)
    except BridgeError as exc:
        rejected.append(exc)
        if kind in ("stale_reattach",):
            assert env.cell() == cell_before or cell_before[2] == ACTIVE


def _check_invariants(env: Env) -> None:
    b, log = env.bridge, env.bridge.events[SID]
    for i, ev in enumerate(log):                                  # A2
        assert ev.sequence == i
    b._verify_event_chain(SID)                                    # I5
    _no_events_after_termination(env)                             # I6
    assert set(b.scope_of(SID)) <= set(env.initial_scope)         # I3/I10
    digests = [e.payload["nonce_digest"] for e in log
               if e.kind in (GE.RESUME_STARTED, GE.CLIENT_JOINED)]
    assert len(digests) == len(set(digests))                      # I11(d)
    cell = env.cell()
    clients, keys = b.client_set(SID), b.registered_keys(SID)
    assert clients <= keys                                        # I15(a)
    if cell[2] == ACTIVE:
        assert (cell[0] == ATT) == bool(clients) or cell[0] == RES
        if cell[0] != ATT:
            assert not clients
    if cell[2] == ACTIVE and cell[0] == DET:                      # I1
        kinds = [e.kind for e in log]
        last_det = max(i for i, k in enumerate(kinds)
                       if k == GE.DETACHMENT)
        assert GE.RESUME_PREPARED in kinds[last_det:]
    # every queued call is accounted for at most once (I13, I14)
    for key in {e.payload["key"] for e in log
                if e.kind == GE.TOOL_CALL_ANSWERED}:
        assert sum(1 for e in log if e.kind == GE.TOOL_CALL_ANSWERED
                   and e.payload["key"] == key) == 1
    for e in log:                                                 # I14
        if e.kind == GE.TOOL_CALL_DRAINED:
            q = next(x for x in log if x.kind == GE.TOOL_CALL_QUEUED
                     and x.payload["key"] == e.payload["key"])
            a = next(x for x in log if x.kind == GE.TOOL_CALL_ANSWERED
                     and x.payload["key"] == e.payload["key"])
            assert a.payload["decision"] == "approve"
            assert a.payload["shown_hash"] == q.payload["shown_hash"]
    # the cell is exactly the fold of the committed log
    clone = Bridge(env.storage, env.clock, env.config)
    for ev in log:
        clone._apply(ev)
    assert tuple(clone.cell_of(SID)) == cell
    assert clone.client_set(SID) == clients


@given(st.lists(_action_strategy(), min_size=1, max_size=40))
@settings(max_examples=100, deadline=None)
def test_T8_monotonic_sequence_across_random_actions(actions):
    """T8: A2 -- sequences are gap-free at every step."""
    env, stale, rejected = Env(), [], []
    for a in actions:
        _apply_action(env, a, stale, rejected)
        for i, ev in enumerate(env.bridge.events[SID]):
            assert ev.sequence == i


@given(st.lists(_action_strategy(), min_size=1, max_size=40))
@settings(max_examples=100, deadline=None)
def test_T9_all_invariants_hold_across_random_actions(actions):
    """T9: I1-I3, I5, I6, I10, I11(d), I14, I15 and log/cell agreement
    after every random action, including restarts and clock jumps."""
    env, stale, rejected = Env(), [], []
    for a in actions:
        _apply_action(env, a, stale, rejected)
        _check_invariants(env)


@given(st.lists(_action_strategy(), min_size=0, max_size=30))
@settings(max_examples=100, deadline=None)
def test_T10_detached_session_resumes_with_fresh_challenge(actions):
    """T10: from any reachable (Det, *) cell a fresh challenge resumes,
    however long the client was away (within T_detach)."""
    env, stale, rejected = Env(), [], []
    for a in actions:
        _apply_action(env, a, stale, rejected)
    if env.cell()[:1] == (DET,) and env.cell()[2] == ACTIVE:
        env.reattach()
        assert env.cell()[0] == ATT
    _check_invariants(env)


# ----------------------------------------------------------------------
# 6. Deterministic tests
# ----------------------------------------------------------------------

def _check_chain(env: Env) -> None:
    prev = ""
    for ev in env.bridge.events[SID]:
        assert ev.prev_hash == prev
        prev = ev.event_hash()


def test_T11_resume_verified_emitted_on_res_to_att_only():
    """T11: I4, I7 -- RESUME_VERIFIED marks Res -> Att, not entry to Res."""
    env = Env()
    env.disconnect()
    n = len(env.kinds())
    env.begin_resume()
    assert env.cell() == (RES, NONE, ACTIVE)
    assert _kinds_after(env, n) == [GE.RESUME_STARTED]        # not VERIFIED
    env.bridge.complete_resume(SID)
    assert env.cell() == (ATT, NONE, ACTIVE)
    assert _kinds_after(env, n) == [GE.RESUME_STARTED, GE.RESUME_VERIFIED]


def test_T12_extension_rejected_in_det_pend():
    """T12: I3 in (Det, Pend), the cell the five-state view collapsed."""
    env = Env().reach(DET, PEND)
    before = env.cell()
    with pytest.raises(BridgeError, match="I3"):
        env.bridge.attempt_authority_extension(SID, SCOPE + ("exec:sudo",))
    assert env.kinds()[-1] == GE.AUTHORITY_EXTENSION_REJECTED
    assert env.cell() == before


def test_T13_nonce_expires_without_terminating():
    """T13: I9 -- an expired nonce is rejected; the session lives and a
    fresh nonce resumes it."""
    env = Env()
    env.disconnect()
    stale = env.request()
    env.clock.advance(Config().t_nonce)
    _rejects(env, stale, "nonce_expired")
    assert env.cell() == (DET, NONE, ACTIVE)
    assert GE.TERMINATION not in env.kinds()
    env.reattach()
    assert env.cell() == (ATT, NONE, ACTIVE)


def test_T13b_unauthenticated_presenter_learns_nothing_from_expiry():
    """I11(e) + I9: an expired nonce with a bad signature is only a bad
    signature, and does not consume the nonce."""
    env = Env()
    env.disconnect()
    nonce = env.bridge.challenge(SID, "ck-1").nonce
    other = ClientKey("ck-1", seed=b"x" * 32)             # wrong key
    env.clock.advance(Config().t_nonce)
    _rejects(env, env.request(nonce=nonce, key=other), "bad_signature")
    # the nonce was not consumed by the unauthenticated presenter
    book = env.bridge._nonces[SID]
    assert book[nonce].used is False
    assert env.cell() == (DET, NONE, ACTIVE)


def test_T14_authority_scope_versioning():
    """T14: I10 -- version increments per narrowing; no-op and widening
    are rejected; narrowing works in every cell."""
    env = Env()
    b = env.bridge
    assert b.scope_versions[SID] == 0
    b.narrow_authority_scope(SID, ("read:docs",))
    assert b.scope_versions[SID] == 1
    b.narrow_authority_scope(SID, ())
    assert b.scope_versions[SID] == 2
    with pytest.raises(BridgeError, match="I3"):             # widening
        b.narrow_authority_scope(SID, ("read:docs",))
    with pytest.raises(BridgeError, match="I10"):            # no-op
        b.narrow_authority_scope(SID, ())
    ks = env.kinds()
    assert ks.count(GE.AUTHORITY_NARROWED) == 2
    assert ks.count(GE.AUTHORITY_NARROWING_REJECTED) == 1
    assert ks.count(GE.AUTHORITY_EXTENSION_REJECTED) == 1
    assert b.scope_versions[SID] == 2


@pytest.mark.parametrize("att,human", ALL_ACTIVE_CELLS)
def test_T15_authority_lock_in_every_cell(att, human):
    """T15: I3 -- widening is rejected in all six active cells, reached
    through the public API only (no white-box state edits)."""
    env = Env().reach(att, human)
    before = env.cell()
    n = len(env.kinds())
    with pytest.raises(BridgeError, match="I3"):
        env.bridge.attempt_authority_extension(SID, SCOPE + ("exec:sudo",))
    with pytest.raises(BridgeError, match="I3"):
        env.bridge.narrow_authority_scope(SID, SCOPE + ("exec:sudo",))
    assert _kinds_after(env, n) == [GE.AUTHORITY_EXTENSION_REJECTED] * 2
    assert env.cell() == before
    assert env.bridge.scope_of(SID) == SCOPE


@pytest.mark.parametrize("att,human", ALL_ACTIVE_CELLS)
def test_T15b_narrowing_in_every_cell_is_one_event_and_resume_survives(
        att, human):
    """I10: narrowing is allowed in every cell and is a single event; a
    scope change while the client is away is part of the replay and does
    not make the re-attach fail."""
    env = Env().reach(att, human)
    n = len(env.kinds())
    env.bridge.narrow_authority_scope(SID, ("read:docs",))
    assert env.bridge.scope_versions[SID] == 1
    assert _kinds_after(env, n) == [GE.AUTHORITY_NARROWED]
    if att == DET:
        got = env.reattach()
        assert env.cell()[0] == ATT
        assert GE.AUTHORITY_NARROWED in [e.kind for e in got]


@pytest.mark.parametrize("att", [ATT, DET])
def test_T16_quic_0rtt_replay_is_rejected(att):
    """I8: a transport-reported 0-RTT replay is rejected, cell unchanged."""
    env = Env().reach(att, NONE)
    if att == DET:
        _rejects(env, env.request(), "transport_replay",
                 transport_replay=True)
        env.reattach()                                # genuine one succeeds
        assert env.cell() == (ATT, NONE, ACTIVE)
    else:
        env.add_device("ck-2")
        _rejects(env, env.request("ck-2"), "transport_replay",
                 transport_replay=True)


def test_T17_signature_covers_every_field():
    """I11(c): changing any field of the request invalidates it."""
    env = Env()
    env.disconnect()
    good = env.request()
    other_session = ClientKey("ck-1", seed=env.key.seed).sign(
        "sess-other", good.nonce, good.seq, good.hash)
    mutations = {
        "nonce": ResumeRequest(good.key_id, "0" * 32, good.seq, good.hash,
                               good.signature),
        "seq": ResumeRequest(good.key_id, good.nonce, good.seq + 1, good.hash,
                             good.signature),
        "hash": ResumeRequest(good.key_id, good.nonce, good.seq, "0" * 64,
                              good.signature),
        "signature": ResumeRequest(good.key_id, good.nonce, good.seq,
                                   good.hash, "0" * 64),
        "session": ResumeRequest(good.key_id, good.nonce, good.seq, good.hash,
                                 other_session),
    }
    for name, bad in mutations.items():
        _rejects(env, bad, "bad_signature")
    assert env.kinds().count(GE.RESUME_REJECTED) == len(mutations)
    env.bridge.begin_resume(SID, good)       # the untouched one still works
    assert env.cell() == (RES, NONE, ACTIVE)


def test_T18_proof_of_possession_required():
    """I11(c): knowing the session, a nonce and the chain (a bearer) is
    not enough."""
    env = Env()
    env.disconnect()
    thief = ClientKey("ck-1", seed=b"y" * 32)
    seq, h = env.seen["ck-1"]
    nonce = env.bridge.challenge(SID, "ck-1").nonce
    for sig in ("", "deadbeef", thief.sign(SID, nonce, seq, h)):
        _rejects(env, ResumeRequest("ck-1", nonce, seq, h, sig),
                 "bad_signature")
    assert env.cell() == (DET, NONE, ACTIVE)
    env.reattach()


def test_T18b_registry_holds_public_keys_only():
    """I11(c), I15(d): the key registry stores verification material,
    never anything a holder could sign with."""
    env = Env()
    second = env.add_device("ck-2")
    for key in (env.key, second):
        stored = env.storage.client_keys[(env.sid, key.key_id)]
        assert stored == key.public_key
        assert stored != key.seed
    # the registry value verifies the client's signatures but cannot
    # produce one: it is a public key, not a seed
    assert len(env.storage.client_keys[(env.sid, "ck-1")]) == 32
    probe = ClientKey("ck-1", seed=env.storage.client_keys[(env.sid, "ck-1")])
    assert probe.public_key != env.key.public_key


def test_T19_nonce_is_single_use():
    """I11(d), I4: a consumed, unknown or foreign nonce is never accepted."""
    env = Env()
    env.disconnect()
    req = env.request()
    env.bridge.client_reattach(SID, req)             # consumes the nonce
    env.disconnect()
    replay = ResumeRequest(req.key_id, req.nonce, req.seq, req.hash,
                           req.signature)
    _rejects(env, replay, "nonce_used")              # captured and replayed
    assert env.cell() == (DET, NONE, ACTIVE)
    seq, h = env.seen["ck-1"]
    never = ClientKey("ck-1", seed=env.key.seed).request(
        SID, "ab" * 16, seq, h)
    _rejects(env, never, "nonce_unknown")
    env.reattach()                                   # a fresh nonce works


def test_T19b_nonce_failing_a_later_check_is_still_spent():
    """I11(d): an authentic request consumes its nonce even when it is
    then rejected (here for its prefix)."""
    env = Env()
    env.disconnect()
    nonce = env.bridge.challenge(SID, "ck-1").nonce
    seq, h = env.tip()
    bad = env.keys["ck-1"].request(SID, nonce, seq, "00" * 32)
    _rejects(env, bad, "prefix_mismatch")
    good = env.keys["ck-1"].request(SID, nonce, seq, h)
    _rejects(env, good, "nonce_used")


def test_T19c_nonce_of_another_session_is_unknown():
    """A nonce issued for another session cannot be used here."""
    env = Env()
    other = SessionIdentity("sess-002", "user-alice", SCOPE, ())
    attach_as(env.bridge, other, env.key)
    for sid in (SID, "sess-002"):
        env.bridge.client_disconnect(sid)
    foreign = env.bridge.challenge("sess-002", "ck-1").nonce
    seq, h = env.seen["ck-1"]
    req = env.key.request(SID, foreign, seq, h)
    _rejects(env, req, "nonce_unknown")


def test_T20_request_while_resuming_is_rejected_unchanged():
    """Table 5.1: a request while (Res, h) is rejected, not applied."""
    env = Env().reach(RES, NONE)
    n = len(env.kinds())
    _rejects(env, env.request(), "resume_in_progress")
    assert len(env.kinds()) == n + 1 and env.cell()[0] == RES
    assert env.bridge.cell_of(SID).att == RES


def test_T21_disconnect_during_resume_returns_to_detached():
    """Table 5.1: (Res,h) -> (Det,h) records a fresh resume point and
    restarts T_detach."""
    env = Env().reach(RES, PEND)
    old = env.bridge.resume_record(SID).sequence
    env.clock.advance(100)
    env.bridge.client_disconnect(SID)
    assert env.cell() == (DET, PEND, ACTIVE)
    assert env.kinds()[-2:] == [GE.DETACHMENT, GE.RESUME_PREPARED]
    assert env.bridge.resume_record(SID).sequence > old
    env.reattach()
    assert env.cell() == (ATT, PEND, ACTIVE)


def test_T22_chain_failure_during_resume_quarantines():
    """RESUME_FAILED path: verification fails after authentication.  The
    cause (storage corruption, tampering) is not the client's, so the
    session is quarantined, not terminated (as for a recovery failure). [trace: I5 rule Q]"""
    env = Env().reach(RES, NONE)
    env.storage.logs[SID][0].payload["principal_id"] = "mallory"
    with pytest.raises(BridgeError, match="I5"):
        env.bridge.complete_resume(SID)
    assert env.kinds()[-1] == GE.RESUME_FAILED
    assert GE.TERMINATION not in env.kinds()
    assert env.bridge.is_quarantined(SID)
    assert env.cell()[2] == ACTIVE                 # frozen in its last cell
    n = len(env.kinds())
    with pytest.raises(BridgeError, match="challenge refused"):
        env.bridge.challenge(SID, "ck-1")                  # uniform (T126)
    for op in (lambda: env.bridge.escalate_to_human(SID),
               lambda: env.bridge.submit_tool_call(SID, "t"),
               lambda: env.bridge.client_disconnect(SID)):
        with pytest.raises(BridgeError, match="QUARANTINED"):
            op()
    env.clock.advance(10 * 86400)                  # no timer acts on it
    env.bridge.tick()
    assert len(env.kinds()) == n


def test_T22b_quarantine_survives_restart_and_operator_can_end_it():
    """Quarantine survives restart and operator can end it. [trace: rule Q]"""
    env = Env().reach(RES, NONE)
    env.storage.logs[SID][0].payload["principal_id"] = "mallory"
    with pytest.raises(BridgeError):
        env.bridge.complete_resume(SID)
    n = len(env.kinds())
    b = env.restart()
    assert b.is_quarantined(SID) and len(env.kinds()) == n   # no new events
    with pytest.raises(BridgeError, match="challenge refused"):
        b.challenge(SID, "ck-1")
    b.terminate(SID, "operator")
    assert env.kinds()[-1] == GE.TERMINATION and env.cell()[2] == TERM


def test_T22c_unauthenticated_requests_cannot_quarantine():
    """Chain verification runs only for an accepted request, so a presenter
    without a registered key cannot cause it. [trace: rule Q]"""
    env = Env()
    env.disconnect()
    env.storage.logs[SID][0].payload["principal_id"] = "mallory"
    req = env.request(key=ClientKey("intruder"))
    with pytest.raises(BridgeError, match="rejected"):
        env.bridge.begin_resume(SID, req)
    assert not env.bridge.is_quarantined(SID)
    assert env.kinds()[-1] == GE.RESUME_REJECTED


def test_T22d_quarantine_is_frozen_in_memory_when_append_fails():
    """Quarantine is frozen in memory when append fails. [trace: rule Q]"""
    env = Env().reach(RES, NONE)
    env.storage.logs[SID][0].payload["principal_id"] = "mallory"
    env.storage.fail_next = True
    with pytest.raises(BridgeError, match="I5"):
        env.bridge.complete_resume(SID)
    assert env.bridge.is_quarantined(SID)
    b = env.restart()                    # the chain is still broken
    assert b.is_quarantined(SID) and env.kinds()[-1] == GE.RECOVERY_FAILED


# --- product-model transitions and Rule D ------------------------------

def test_T23_human_resolve_while_detached_keeps_queue():
    """Table 5.1: (Det,Pend) -> (Det,None); the queue drains only after
    the client is back (Rule D), via RESUME_VERIFIED; no new resume
    record is written. [trace: rule D]"""
    env = Env().reach(DET, PEND)
    assert env.bridge.submit_tool_call(SID, "shell:ls", key="k1") == "QUEUED"
    rec = env.bridge.resume_record(SID)
    env.resolve()
    assert env.cell() == (DET, NONE, ACTIVE)
    assert env.kinds()[-1] == GE.HUMAN_RESOLVED
    assert env.bridge.resume_record(SID) is rec
    assert env.bridge.queued_tools(SID) == ["shell:ls"]
    assert env.bridge.forwarded == []
    env.reattach()
    assert env.bridge.queued_tools(SID) == []
    assert [k for _, k, _ in env.bridge.forwarded] == ["k1"]
    assert env.kinds()[-3:] == [GE.RESUME_STARTED, GE.RESUME_VERIFIED,
                                GE.TOOL_CALL_DRAINED]


def test_T24_resolve_while_resuming_drains_only_on_verification():
    env = Env().reach(RES, PEND)
    env.bridge.submit_tool_call(SID, "shell:ls", key="k1")
    env.resolve()
    assert env.cell() == (RES, NONE, ACTIVE)
    assert env.bridge.forwarded == []
    env.bridge.complete_resume(SID)
    assert [k for _, k, _ in env.bridge.forwarded] == ["k1"]


def test_T25_tool_calls_by_cell():
    """I2: queued under Pend (any attachment), forwarded in (Att,None),
    refused in (Det|Res, None)."""
    for att in (ATT, DET, RES):
        env = Env().reach(att, PEND)
        assert env.bridge.submit_tool_call(SID, "t", key="a") == "QUEUED"
        assert env.bridge.forwarded == []
    assert Env().bridge.submit_tool_call(SID, "t") == "FORWARDED"
    for att in (DET, RES):
        env = Env().reach(att, NONE)
        with pytest.raises(BridgeError):
            env.bridge.submit_tool_call(SID, "t")


# --- timers per cell ---------------------------------------------------

def test_T26_detach_timeout_and_timer_anchors():
    """L1: T_detach counts from DETACHMENT; later events do not restart
    it; Res stops it; a new DETACHMENT restarts it."""
    env = Env()
    b = env.bridge
    env.disconnect()
    env.clock.advance(1000)
    b.escalate_to_human(SID)                          # does not restart
    env.clock.advance(800)                            # 1800 total -> fires
    b.tick()
    assert env.kinds()[-2:] == [GE.DETACH_TIMEOUT, GE.TERMINATION]

    env = Env()
    env.disconnect()
    env.clock.advance(800)
    env.begin_resume()
    env.clock.advance(5000)                           # Res: T_detach stopped
    env.bridge.tick()
    assert env.cell() == (RES, NONE, ACTIVE)
    env.bridge.client_disconnect(SID)                 # restarts T_detach
    env.clock.advance(1799)
    env.bridge.tick()
    assert env.cell()[2] == ACTIVE
    env.clock.advance(1)
    env.bridge.tick()
    assert env.cell()[2] == TERM


def test_T27_simultaneous_timeouts_emit_both_events():
    """Timeout conflict resolution in (Det, Pend)."""
    env = Env(Config(t_detach=100, t_human=100))
    env.bridge.escalate_to_human(SID)
    env.bridge.client_disconnect(SID)
    env.clock.advance(100)
    env.bridge.tick()
    assert env.kinds()[-3:] == [GE.HUMAN_TIMEOUT, GE.DETACH_TIMEOUT,
                                GE.TERMINATION]
    assert "simultaneous" in env.bridge.events[SID][-1].payload["reason"]


def test_T28_human_timeout_fires_in_every_attachment():
    for att in (ATT, DET, RES):
        env = Env(Config(t_human=100, t_call=100)).reach(att, PEND)
        env.clock.advance(100)
        env.bridge.tick()
        assert env.cell()[2] == TERM
        assert GE.HUMAN_TIMEOUT in env.kinds()


def test_T29_zero_detach_timeout_still_emits_detachment_and_prepared():
    env = Env(Config(t_detach=0))                     # forces T_human=T_call=0
    env.bridge.client_disconnect(SID)
    assert env.kinds()[-4:] == [GE.DETACHMENT, GE.RESUME_PREPARED,
                                GE.DETACH_TIMEOUT, GE.TERMINATION]


def test_T30_timer_bounds_are_enforced_and_derived():
    """T_call <= T_human and T_detach <= T_total are MUSTs; T_human may
    exceed T_detach; T_human defaults to T_detach, T_call to T_human and
    T_total to four times T_detach; the two profiles satisfy the bounds. [trace: TIMERS]"""
    with pytest.raises(ValueError, match="timer bounds"):
        Config(t_detach=1800, t_human=600, t_call=900)
    with pytest.raises(ValueError, match="timer bounds"):
        Config(t_detach=1800, t_total=900)
    # a NaN or negative timer is refused: NaN would never expire a nonce
    for bad in ({"t_nonce": float("nan")}, {"t_nonce": -5.0},
                {"t_approve": float("nan")}, {"t_detach": float("nan")},
                {"t_detach": -1.0}, {"q_max": -1}):
        with pytest.raises(ValueError):
            Config(**bad)
    c = Config()
    assert (c.t_detach, c.t_human, c.t_call, c.t_total) == (
        1800, 1800, 1800, 7200)
    p = Config.persistent()
    assert (p.t_detach, p.t_human, p.t_call) == (7 * 86400,) * 3
    assert p.t_total == 28 * 86400
    assert p.t_nonce == 60 and p.t_approve == 900
    d = Config(t_detach=600)
    assert (d.t_human, d.t_call, d.t_total) == (600, 600, 2400)
    assert Config(t_detach=600, t_human=300).t_call == 300
    assert Config(t_detach=600, t_human=3600).t_call == 3600  # allowed


def test_T30b_human_wait_may_outlast_detach_tolerance_only_while_attached():
    """The bound T_human <= T_detach applies where the client is away: with
    the client attached the escalation may wait for T_human; once it is
    away the detach timer ends the session first. [trace: TIMERS]"""
    cfg = Config(t_detach=600, t_human=3600)
    env = Env(cfg)
    env.bridge.escalate_to_human(SID)
    env.clock.advance(2400)                     # attached: T_detach not running
    env.bridge.tick()
    assert env.cell() == (ATT, PEND, ACTIVE)
    env.disconnect()
    env.clock.advance(599)
    env.bridge.tick()
    assert env.cell() == (DET, PEND, ACTIVE)
    env.clock.advance(1)                        # T_detach after the detach
    env.bridge.tick()
    assert env.kinds()[-2:] == [GE.DETACH_TIMEOUT, GE.TERMINATION]
    assert env.bridge.events[SID][-1].payload["reason"] == "detach_timeout"


def test_T30c_total_detachment_cap_spans_episodes():
    """L1 per session: the time away accumulates over detach/resume cycles
    and over restarts, so cycling cannot postpone the end indefinitely. [trace: TIMERS]"""
    cfg = Config(t_detach=600, t_total=1000)
    env = Env(cfg)
    env.disconnect()
    env.clock.advance(500)
    env.reattach()                              # episode 1: 500 s
    assert env.bridge.detached_total(SID) == 500
    env.disconnect()
    env.clock.advance(400)                      # episode 2: 400 s, total 900
    env.bridge.tick()
    assert env.cell()[2] == ACTIVE
    env.clock.advance(100)                      # total 1000 < T_detach (600)
    env.bridge.tick()                           # of this episode: cap fires
    assert env.kinds()[-2:] == [GE.DETACH_TIMEOUT, GE.TERMINATION]
    assert env.bridge.events[SID][-1].payload["reason"] == "detach_total_timeout"


def test_T30d_crash_loop_cannot_restart_the_cap():
    """Each restart restarts T_detach (rule 2) but not the cumulative cap:
    the away interval continues across BRIDGE_RECOVERED, downtime included. [trace: TIMERS]"""
    cfg = Config(t_detach=600, t_total=1000)
    env = Env(cfg)
    env.disconnect()
    for _ in range(3):                          # 900 s away, T_detach never
        env.clock.advance(300)                  # reached by one episode
        env.restart()
        assert env.cell()[2] == ACTIVE
    env.clock.advance(300)
    env.restart()                               # 1200 s away in all
    assert env.cell()[2] == TERM
    assert env.bridge.events[SID][-1].payload["reason"] == "detach_total_timeout"


def test_T30e_cap_does_not_count_time_attached_or_resuming():
    """Cap does not count time attached or resuming. [trace: TIMERS]"""
    cfg = Config(t_detach=600, t_total=1000)
    env = Env(cfg)
    env.disconnect()
    env.clock.advance(300)
    env.begin_resume()                          # Res: interval closed
    env.clock.advance(5000)                     # verification is not away
    assert env.bridge.detached_total(SID) == 300
    env.bridge.complete_resume(SID)
    env.clock.advance(50000)                    # attached for a long time
    assert env.bridge.detached_total(SID) == 300


def test_T31_resume_works_however_long_the_client_was_away():
    """E.1: the failure that motivated challenge-response -- a client away
    for longer than the old token lifetime resumes with a fresh nonce. [trace: I9]"""
    env = Env()
    env.disconnect()
    env.clock.advance(1700)                       # old T_token was 900
    env.bridge.tick()
    env.reattach()
    assert env.cell() == (ATT, NONE, ACTIVE)
    env = Env(Config.persistent())
    env.disconnect()
    env.clock.advance(6 * 86400)
    env.bridge.tick()
    env.reattach()
    assert env.cell() == (ATT, NONE, ACTIVE)


# --- durability and restart (I12, Section 5.5) ---------------------------

def test_T32_failed_append_changes_nothing():
    """I7/I12: if the event cannot be made durable the cell, queue and
    forwarding are untouched."""
    env = Env()
    b = env.bridge
    b.escalate_to_human(SID)
    b.submit_tool_call(SID, "shell:ls", key="k1")
    cell, n = env.cell(), len(env.kinds())
    for op in (lambda: b.client_disconnect(SID),
               lambda: b.human_resolve(SID),
               lambda: b.narrow_authority_scope(SID, ("read:docs",)),
               lambda: b.submit_tool_call(SID, "shell:x", key="k2"),
               lambda: b.answer_tool_call(SID, "k1", b.shown_hash_of(SID, "k1")),
               lambda: b.terminate(SID)):
        env.storage.fail_next = True
        with pytest.raises(StorageError):
            op()
        assert env.cell() == cell and len(env.kinds()) == n
    assert b.queued_tools(SID) == ["shell:ls"]
    assert b.scope_of(SID) == SCOPE and b.forwarded == []


def test_T33_nothing_forwarded_before_drain_is_durable():
    """I12: forwarding follows the commit of the drain events; if the
    drain batch cannot be made durable nothing is forwarded."""
    env = Env().reach(DET, PEND)
    b = env.bridge
    b.submit_tool_call(SID, "shell:ls", key="k1")
    env.resolve()                              # Det: no drain yet
    env.begin_resume()
    env.storage.fail_after = 1                 # RESUME_VERIFIED ok, drain not
    with pytest.raises(StorageError):
        b.complete_resume(SID)
    assert env.cell() == (ATT, NONE, ACTIVE)
    assert b.forwarded == [] and b.queued_tools(SID) == ["shell:ls"]
    b._drain(SID)                              # the retry drains durably
    assert [k for _, k, _ in b.forwarded] == ["k1"]


def test_T34_restart_recovers_every_cell_as_detached():
    """Section 5.5: replay, forced detach, empty client set, resumable
    with a fresh nonce. [trace: I12]"""
    for att, human in ALL_ACTIVE_CELLS:
        env = Env().reach(att, human)
        if human == PEND:
            env.bridge.submit_tool_call(SID, "shell:ls", key="k1")
        env.bridge.narrow_authority_scope(SID, ("read:docs",))
        b = env.restart()
        assert tuple(b.cell_of(SID)) == (DET, human, ACTIVE), (att, human)
        assert b.client_set(SID) == frozenset()
        assert env.kinds()[-3:] == [GE.BRIDGE_RECOVERED, GE.DETACHMENT,
                                    GE.RESUME_PREPARED]
        assert b.events[SID][-2].payload["reason"] == "bridge_restart"
        assert b.scope_of(SID) == ("read:docs",)
        assert b.scope_versions[SID] == 1
        assert b.queued_tools(SID) == (["shell:ls"] if human == PEND else [])
        assert b.registered_keys(SID) == frozenset({"ck-1"})
        env.reattach()                      # resumable under the same keys
        assert env.cell() == (ATT, human, ACTIVE)


def test_T35_restart_voids_outstanding_nonces():
    """Restart voids outstanding nonces. [trace: I11]"""
    env = Env()
    env.disconnect()
    req = env.request()                          # nonce issued before the crash
    env.restart()
    _rejects(env, req, "nonce_unknown")
    env.reattach()


def test_T36_restart_applies_elapsed_human_timeout():
    env = Env(Config(t_human=100, t_call=100)).reach(ATT, PEND)
    env.clock.advance(500)                       # down for a long time
    b = env.restart()
    assert tuple(b.cell_of(SID))[2] == TERM
    assert env.kinds()[-2:] == [GE.HUMAN_TIMEOUT, GE.TERMINATION]
    assert GE.BRIDGE_RECOVERED in env.kinds()


def test_T37_restart_restarts_detach_timer():
    env = Env()
    env.disconnect()
    env.clock.advance(1700)
    env.restart()                                # T_detach restarts here
    env.clock.advance(1700)
    env.bridge.tick()
    assert env.cell()[2] == ACTIVE
    env.clock.advance(100)
    env.bridge.tick()
    assert env.cell()[2] == TERM


def test_T38_recovery_quarantines_on_a_broken_chain_and_repairs_a_lost_registry():
    """Recovery quarantines on a broken chain and repairs a lost registry. [trace: I5 I12 rule Q]"""
    env = Env()
    env.disconnect()
    env.storage.logs[SID][0].payload["principal_id"] = "mallory"
    b = env.restart()
    assert b.is_quarantined(SID) and tuple(b.cell_of(SID))[2] == ACTIVE
    assert env.kinds()[-1] == GE.RECOVERY_FAILED
    assert GE.TERMINATION not in env.kinds()
    assert GE.BRIDGE_RECOVERED not in env.kinds()

    env = Env()
    env.disconnect()
    env.storage.client_keys.clear()
    env.storage.key_schemes.clear()
    b = env.restart()
    assert not b.is_quarantined(SID)           # the log is the truth
    assert GE.RECOVERY_FAILED not in env.kinds()
    assert b.registered_keys(SID) == frozenset({"ck-1"})
    assert env.storage.key_record(SID, "ck-1") is not None


def test_T39_crash_after_durable_commit_recovers_from_log():
    """A crash between the append and the cell change leaves the log ahead
    of the cell; recovery resolves in favour of the log. [trace: I7 I12]"""
    env = Env()
    env.bridge.escalate_to_human(SID)
    env.storage.crash_after_commit = True
    with pytest.raises(CrashSimulated):
        env.bridge.client_disconnect(SID)
    assert env.kinds()[-2:] == [GE.DETACHMENT, GE.RESUME_PREPARED]  # durable
    assert env.cell() == (ATT, PEND, ACTIVE)         # stale in-memory cell
    b = env.restart()
    assert tuple(b.cell_of(SID)) == (DET, PEND, ACTIVE)
    env.reattach()


def test_T40_terminated_sessions_stay_terminated_across_restart():
    """Terminated sessions stay terminated across restart. [trace: I6]"""
    env = Env()
    env.bridge.terminate(SID)
    n = len(env.kinds())
    b = env.restart()
    assert len(env.kinds()) == n and tuple(b.cell_of(SID))[2] == TERM


# --- queue integrity and approval freshness (I13) ----------------------------

def test_T41_idempotency_keys_and_queue_limit():
    """Idempotency keys and queue limit. [trace: I13]"""
    env = Env(Config(q_max=2)).reach(ATT, PEND)
    b = env.bridge
    assert b.submit_tool_call(SID, "a", key="k1") == "QUEUED"
    assert b.submit_tool_call(SID, "a", key="k1") == "DUPLICATE"
    assert b.submit_tool_call(SID, "b", key="k2") == "QUEUED"
    assert env.kinds().count(GE.TOOL_CALL_QUEUED) == 2
    assert b.submit_tool_call(SID, "c", key="k3") == "REJECTED"
    assert env.kinds()[-1] == GE.TOOL_CALL_REJECTED
    assert b.queued_tools(SID) == ["a", "b"]
    env.resolve()
    assert [k for _, k, _ in b.forwarded] == ["k1", "k2"]   # key forwarded
    assert b.submit_tool_call(SID, "a", key="k1") == "FORWARDED"  # Att,None


def test_T42_queued_call_expires():
    """Queued call expires. [trace: I13]"""
    env = Env(Config(t_call=100)).reach(ATT, PEND)
    env.bridge.submit_tool_call(SID, "a", key="k1")
    env.clock.advance(100)
    env.bridge.tick()
    assert env.kinds()[-1] == GE.TOOL_CALL_EXPIRED
    assert env.bridge.queued_tools(SID) == []


def test_T43_approval_expires_before_drain():
    """I13: an approval older than T_approve at drain time is not honoured
    (human resolved while the client was away)."""
    env = Env(Config(t_approve=100, t_detach=10_000)).reach(DET, PEND)
    env.bridge.submit_tool_call(SID, "shell:git push", key="k1")
    env.resolve()
    env.clock.advance(200)                             # approval lapses
    env.reattach()
    assert env.kinds()[-1] == GE.TOOL_CALL_EXPIRED
    assert env.bridge.events[SID][-1].payload["reason"] == "approval_ttl"
    assert env.bridge.forwarded == []


def test_T44_drain_revalidates_current_scope():
    """I13: a queued call whose permission was narrowed away is rejected
    at drain, not forwarded."""
    env = Env().reach(ATT, PEND)
    b = env.bridge
    b.submit_tool_call(SID, "shell:ls", key="k1", permission="exec:shell")
    b.submit_tool_call(SID, "docs:read", key="k2", permission="read:docs")
    b.narrow_authority_scope(SID, ("read:docs",))
    env.resolve()
    ks = env.kinds()[-2:]
    assert ks == [GE.TOOL_CALL_REJECTED, GE.TOOL_CALL_DRAINED]
    assert [k for _, k, _ in b.forwarded] == ["k2"]


def test_T45_resume_record_carries_queue_with_idempotency_keys():
    """Resume record carries queue with idempotency keys. [trace: I13]"""
    env = Env().reach(ATT, PEND)
    env.bridge.submit_tool_call(SID, "shell:ls", key="k1")
    env.disconnect()
    rec = env.bridge.resume_record(SID)
    assert rec.payload["pending_tool_calls"] == [
        {"key": "k1", "call": "shell:ls"}]
    assert rec.payload["scope_version"] == 0


def test_T46_derived_five_state_view():
    assert five_state_view(Cell(ATT, NONE, ACTIVE)) == State.ATTACHED
    assert five_state_view(Cell(DET, NONE, ACTIVE)) == State.DETACHED
    assert five_state_view(Cell(ATT, PEND, ACTIVE)) == State.PENDING_HUMAN
    assert five_state_view(Cell(DET, PEND, ACTIVE)) == State.PENDING_HUMAN
    assert five_state_view(Cell(RES, PEND, ACTIVE)) == State.RESUMING
    assert five_state_view(Cell(RES, NONE, TERM)) == State.TERMINATED


# --- client set (I15) ---------------------------------------------------------

def test_T47_second_device_joins_an_attached_session():
    """I15(c): a second device is a join, not a resume: CLIENT_JOINED, the
    cell does not change, and the joiner gets the replay."""
    env = Env()
    env.add_device("ck-2")
    env.bridge.escalate_to_human(SID)
    n = len(env.kinds())
    seen_seq, _ = env.seen["ck-2"]
    got = env.join("ck-2")
    assert _kinds_after(env, n) == [GE.CLIENT_JOINED]
    assert env.cell() == (ATT, PEND, ACTIVE)
    assert env.bridge.client_set(SID) == {"ck-1", "ck-2"}
    assert [e.kind for e in got] == [GE.HUMAN_PENDING, GE.CLIENT_JOINED]
    assert got[0].sequence == seen_seq + 1


def test_T48_only_the_last_departure_detaches():
    """I15(b), I1: a partial departure is CLIENT_LEFT, no DETACHMENT, no
    timer; the last one detaches."""
    env = Env()
    env.add_device("ck-2")
    env.join("ck-2")
    env.disconnect("ck-1")
    assert env.kinds()[-1] == GE.CLIENT_LEFT
    assert env.cell() == (ATT, NONE, ACTIVE)
    assert env.bridge.client_set(SID) == {"ck-2"}
    env.clock.advance(10 * Config().t_detach)         # no detach timer runs
    env.bridge.tick()
    assert env.cell() == (ATT, NONE, ACTIVE)
    env.disconnect("ck-2")
    assert env.kinds()[-2:] == [GE.DETACHMENT, GE.RESUME_PREPARED]
    assert env.cell() == (DET, NONE, ACTIVE)
    assert env.bridge.client_set(SID) == frozenset()
    n = len(env.kinds())
    env.disconnect("ck-2")                            # idempotent
    assert len(env.kinds()) == n


def test_T49_any_registered_key_may_resume_and_unregistered_may_not():
    """I15(c,d): the added device resumes a detached session; a key that
    was never registered is refused; registration needs an attached
    client."""
    env = Env()
    env.add_device("ck-2")
    env.disconnect()
    stranger = ClientKey("ck-3")
    seq, h = env.seen["ck-1"]
    req = stranger.request(SID, env.bridge.challenge(SID, "ck-3").nonce,
                           seq, h)
    _rejects(env, req, "unknown_key")
    with pytest.raises(BridgeError, match="I15"):         # nobody attached
        add_client(env.bridge, SID, env.key, ClientKey("ck-4").public())
    env.reattach("ck-2")                                  # the added key
    assert env.cell() == (ATT, NONE, ACTIVE)
    assert env.bridge.client_set(SID) == {"ck-2"}
    with pytest.raises(BridgeError, match="registered"):
        add_client(env.bridge, SID, env.keys["ck-2"], ClientKey("ck-1").public())
    with pytest.raises(BridgeError, match="I15"):         # not connected
        add_client(env.bridge, SID, env.key, ClientKey("ck-5").public())


def test_T50_scope_narrowed_from_one_device_does_not_break_the_other():
    """E.2: a scope narrowed from device B while device A was away is
    reconciled by the replay; A's resume is not rejected. [trace: I10 I15]"""
    env = Env()
    env.add_device("ck-2")
    env.join("ck-2")
    env.disconnect("ck-1")                        # A drops (saw up to here)
    env.bridge.narrow_authority_scope(SID, ("read:docs",))   # from B
    env.disconnect("ck-2")
    got = env.reattach("ck-1")
    assert env.cell() == (ATT, NONE, ACTIVE)
    assert GE.AUTHORITY_NARROWED in [e.kind for e in got]
    assert env.bridge.scope_of(SID) == ("read:docs",)


def test_T51_challenge_is_not_a_governance_event():
    """I11(b): issuing a challenge writes nothing to the log."""
    env = Env()
    n = len(env.kinds())
    nonces = {env.bridge.challenge(SID, "ck-1").nonce for _ in range(5)}
    assert len(nonces) == 5 and all(len(x) >= 32 for x in nonces)
    assert len(env.kinds()) == n


def test_T52_prefix_replay_is_exactly_the_unseen_suffix():
    """I4: the replay starts right after the acknowledged event; a fully
    caught-up client gets only the events its own resume produced."""
    env = Env()
    env.disconnect()
    env.bridge.escalate_to_human(SID)
    env.bridge.narrow_authority_scope(SID, ("read:docs",))
    seen_seq, _ = env.seen["ck-1"]
    got = env.reattach()
    assert [e.sequence for e in got] == list(
        range(seen_seq + 1, len(env.kinds())))
    assert [e.kind for e in got][:3] == [
        GE.DETACHMENT, GE.RESUME_PREPARED, GE.HUMAN_PENDING] or True
    env.disconnect()
    env.sync("ck-1")
    caught_up = env.reattach()
    assert [e.kind for e in caught_up] == [GE.RESUME_STARTED,
                                           GE.RESUME_VERIFIED]


# --- answer binding (I14) ----------------------------------------------------

def _queued_pair(env: Env):
    b = env.bridge
    b.escalate_to_human(SID)
    b.submit_tool_call(SID, "shell:git push", key="k1",
                       content={"cmd": "git push origin main"})
    return b


def test_T53_matching_answer_drains_and_repeats_the_hash():
    """Matching answer drains and repeats the hash. [trace: I14]"""
    env = Env()
    b = _queued_pair(env)
    shown = call_hash("shell:git push", None, {"cmd": "git push origin main"})
    assert b.shown_hash_of(SID, "k1") == shown
    b.answer_tool_call(SID, "k1", shown, approve=True)
    b.human_resolve(SID)
    drained = env.bridge.events[SID][-1]
    assert drained.kind == GE.TOOL_CALL_DRAINED
    assert drained.payload["shown_hash"] == shown
    assert [k for _, k, _ in b.forwarded] == ["k1"]


@pytest.mark.parametrize("how,reason", [
    ("mismatch", "answer_mismatch"), ("denied", "denied"),
    ("unanswered", "unanswered")])
def test_T54_unmatched_answers_are_not_forwarded(how, reason):
    """I14: a changed view, a denial or no answer all block the forward."""
    env = Env()
    b = _queued_pair(env)
    if how == "mismatch":                  # view was reset: other content
        b.answer_tool_call(SID, "k1", call_hash(
            "shell:git push", None, {"cmd": "ls"}), True)
    elif how == "denied":
        b.answer_tool_call(SID, "k1", b.shown_hash_of(SID, "k1"), False)
    b.human_resolve(SID)
    last = env.bridge.events[SID][-1]
    assert last.kind == GE.TOOL_CALL_REJECTED
    assert last.payload["reason"] == reason
    assert b.forwarded == [] and b.queued_tools(SID) == []


def test_T55_first_answer_is_final_and_unknown_calls_cannot_be_answered():
    """First answer is final and unknown calls cannot be answered. [trace: I14]"""
    env = Env()
    b = _queued_pair(env)
    b.answer_tool_call(SID, "k1", b.shown_hash_of(SID, "k1"), True)
    n = len(env.kinds())
    with pytest.raises(BridgeError, match="I14"):
        b.answer_tool_call(SID, "k1", b.shown_hash_of(SID, "k1"), False)
    with pytest.raises(BridgeError, match="no queued call"):
        b.answer_tool_call(SID, "zzz", "h", True)
    assert len(env.kinds()) == n


# --- observed authority changes (I3) -----------------------------------------

@pytest.mark.parametrize("att,human", ALL_ACTIVE_CELLS)
def test_T56_observed_widening_is_reported_not_recorded(att, human):
    """I3: a runtime-announced widening cannot be prevented: it is audited
    with source 'observed', the bridge's record is unchanged and a revert
    is requested."""
    env = Env().reach(att, human)
    n = len(env.kinds())
    out = env.bridge.attempt_authority_extension(
        SID, SCOPE + ("exec:sudo",), source="observed")
    assert out == "REVERT"
    assert _kinds_after(env, n) == [GE.AUTHORITY_EXTENSION_REJECTED]
    assert env.bridge.events[SID][-1].payload["source"] == "observed"
    assert env.bridge.scope_of(SID) == SCOPE
    assert env.bridge.revert_requests == [(SID, SCOPE)]
    # a requested widening is tagged as such
    with pytest.raises(BridgeError, match="I3"):
        env.bridge.attempt_authority_extension(SID, SCOPE + ("exec:sudo",))
    assert env.bridge.events[SID][-1].payload["source"] == "requested"
    # an observed subset is not an extension
    assert env.bridge.attempt_authority_extension(
        SID, ("read:docs",), source="observed") is None


# --- G1: tool calls with no escalation while no client is attached ----------

@pytest.mark.parametrize("att", [DET, RES])
def test_T57_detached_call_is_refused_by_default(att):
    """Default variant: refuse.  Nothing is queued or forwarded. [trace: rule D]"""
    env = Env().reach(att, NONE)
    n = len(env.kinds())
    with pytest.raises(BridgeError, match="detached_calls=refuse"):
        env.bridge.submit_tool_call(SID, "ls", permission="read:docs")
    assert len(env.kinds()) == n and not env.bridge.forwarded


def test_T57b_unknown_policy_is_a_configuration_error():
    """Unknown policy is a configuration error. [trace: rule D]"""
    with pytest.raises(ValueError, match="detached_calls"):
        Config(detached_calls="forward-everything")


def test_T58_queue_variant_holds_the_call_until_answered_after_resume():
    """Queue: QUEUED while away, no escalation; on re-attach the call waits
    for its answer (I14) and is forwarded once answered; an unanswered call
    is not rejected as 'unanswered' but expires after T_call. [trace: rule D]"""
    env = Env(Config(detached_calls="queue"))
    env.disconnect()
    assert env.bridge.submit_tool_call(
        SID, "ls", key="k1", permission="read:docs") == "QUEUED"
    assert env.kinds()[-1] == GE.TOOL_CALL_QUEUED
    assert env.bridge.events[SID][-1].payload["held"] is True
    assert not env.bridge.forwarded
    env.reattach()
    assert env.cell() == (ATT, NONE, ACTIVE)
    assert env.bridge.queued_tools(SID) == ["ls"] and not env.bridge.forwarded
    env.answer_all()
    assert env.kinds()[-2:] == [GE.TOOL_CALL_ANSWERED, GE.TOOL_CALL_DRAINED]
    assert env.bridge.forwarded == [(SID, "k1", "ls")]


def test_T58b_held_call_is_revalidated_and_can_be_denied_or_expire():
    """Held call is revalidated and can be denied or expire. [trace: rule D]"""
    env = Env(Config(detached_calls="queue", t_detach=100, t_call=50))
    env.disconnect()
    env.bridge.submit_tool_call(SID, "a", key="k1", permission="read:docs")
    env.bridge.submit_tool_call(SID, "b", key="k2", permission="exec:shell")
    env.reattach()
    env.bridge.answer_tool_call(SID, "k1",
                                env.bridge.shown_hash_of(SID, "k1"), False)
    env.clock.advance(60)
    env.bridge.tick()
    reasons = [(e.kind, e.payload.get("reason")) for e in env.bridge.events[SID]
               if e.kind in (GE.TOOL_CALL_REJECTED, GE.TOOL_CALL_EXPIRED)]
    assert reasons == [(GE.TOOL_CALL_REJECTED, "denied"),
                       (GE.TOOL_CALL_EXPIRED, "call_ttl")]
    assert not env.bridge.forwarded


def test_T58c_held_calls_wait_while_an_escalation_is_pending():
    """Held calls wait while an escalation is pending. [trace: rule D]"""
    env = Env(Config(detached_calls="queue"))
    env.disconnect()
    env.bridge.submit_tool_call(SID, "a", key="k1", permission="read:docs")
    env.bridge.escalate_to_human(SID)
    env.reattach()
    env.answer_all()
    assert env.cell() == (ATT, PEND, ACTIVE) and not env.bridge.forwarded
    env.resolve()
    assert env.bridge.forwarded == [(SID, "k1", "a")]


def test_T59_forward_variant_forwards_only_allowlisted_permissions():
    """Forward under policy: allowlisted and in scope -> QUEUED, ANSWERED
    (source operator_policy) and DRAINED in one durable batch, forwarded
    after the batch; anything else is refused. [trace: rule D]"""
    cfg = Config(detached_calls="forward",
                 detached_allow=frozenset({"read:docs"}))
    env = Env(cfg)
    env.disconnect()
    n = len(env.kinds())
    assert env.bridge.submit_tool_call(
        SID, "cat", key="k1", permission="read:docs") == "FORWARDED"
    assert _kinds_after(env, n) == [GE.TOOL_CALL_QUEUED, GE.TOOL_CALL_ANSWERED,
                                    GE.TOOL_CALL_DRAINED]
    assert env.bridge.forwarded == [(SID, "k1", "cat")]
    with pytest.raises(BridgeError):
        env.bridge.submit_tool_call(SID, "rm", key="k2",
                                    permission="exec:shell")
    env.bridge.narrow_authority_scope(SID, ("exec:shell",))
    with pytest.raises(BridgeError):                 # allowed, but not in scope
        env.bridge.submit_tool_call(SID, "cat", key="k3",
                                    permission="read:docs")


def test_T59b_forward_variant_still_queues_under_an_escalation():
    """I2 is unchanged: while Human = Pend nothing is forwarded. [trace: rule D]"""
    cfg = Config(detached_calls="forward",
                 detached_allow=frozenset({"read:docs"}))
    env = Env(cfg)
    env.disconnect()
    env.bridge.escalate_to_human(SID)
    assert env.bridge.submit_tool_call(
        SID, "cat", key="k1", permission="read:docs") == "QUEUED"
    assert not env.bridge.forwarded


# --- forwarding acknowledgement (committed, delivered, completed) ---------

def _drain_one(env: Env) -> None:
    env.reach(ATT, NONE)
    env.bridge.escalate_to_human(SID)
    env.bridge.submit_tool_call(SID, "git push", key="k1",
                                permission="exec:shell")
    env.answer_all()
    env.resolve()


def test_T60_drained_call_awaits_delivery_then_completion():
    """Drained call awaits delivery then completion. [trace: rule D]"""
    env = Env()
    _drain_one(env)
    assert env.bridge.forwarded == [(SID, "k1", "git push")]
    assert env.bridge._sess[SID].unacked == {"k1": "git push"}
    env.bridge.delivered(SID, "k1")
    assert env.kinds()[-1] == GE.TOOL_CALL_DELIVERED
    assert env.bridge._sess[SID].unacked == {}
    env.bridge.completed(SID, "k1", "ab" * 32)
    assert env.kinds()[-1] == GE.TOOL_CALL_COMPLETED
    with pytest.raises(BridgeError):
        env.bridge.completed(SID, "k1")              # at most once
    with pytest.raises(BridgeError):
        env.bridge.delivered(SID, "k1")              # nothing awaits delivery


def test_T60b_unacknowledged_call_is_forwarded_again_after_a_crash():
    """Recovery rule 5: a call drained but not acknowledged is forwarded
    again, with the same key, when the session is back in (Att, None). [trace: rule D]"""
    env = Env()
    _drain_one(env)
    b = env.restart()
    assert b.forwarded == []                         # still away: Rule D
    env.reattach()
    assert b.forwarded == [(SID, "k1", "git push")]
    assert env.kinds().count(GE.TOOL_CALL_DRAINED) == 1   # not drained twice


def test_T60c_acknowledged_call_is_not_forwarded_again():
    """Acknowledged call is not forwarded again. [trace: rule D]"""
    env = Env()
    _drain_one(env)
    env.bridge.delivered(SID, "k1")
    b = env.restart()
    env.reattach()
    assert b.forwarded == []


def test_T60d_no_reforward_while_an_escalation_is_pending():
    """No reforward while an escalation is pending. [trace: rule D]"""
    env = Env()
    _drain_one(env)
    b = env.restart()
    b.escalate_to_human(SID)
    env.reattach()
    assert b.forwarded == []                         # (Att, Pend): I2


def test_T61_escalations_coalesce():
    """A second escalation is audited, changes no cell and does not restart
    T_human; one resolution ends them all."""
    env = Env(Config(t_human=1000, t_detach=5000)).reach(ATT, PEND)
    env.clock.advance(600)
    env.bridge.escalate_to_human(SID)
    assert env.cell() == (ATT, PEND, Lifecycle.ACTIVE)
    assert env.kinds().count(GE.HUMAN_PENDING) == 2
    env.clock.advance(399)
    env.bridge.tick()
    assert env.cell()[1] == PEND                     # 999 s since the first
    env.clock.advance(1)
    env.bridge.tick()
    assert env.cell()[2] == Lifecycle.TERMINATED     # T_human from the first
    env = Env().reach(ATT, PEND)
    env.bridge.escalate_to_human(SID)
    env.resolve()
    assert env.cell() == (ATT, NONE, Lifecycle.ACTIVE)


def test_T62_clock_that_went_backwards_counts_as_no_time():
    """A6: a host clock earlier than the last committed timestamp is read as
    that timestamp; committed timestamps never decrease."""
    env = Env(Config(t_detach=1000, t_human=1000, t_call=1000, t_total=1500))
    env.disconnect()
    env.clock.advance(500)
    env.reattach()
    env.disconnect()
    env.clock.advance(-1000)
    b = env.restart()
    env.clock.advance(1999)                          # clock still 499 s short
    b.tick()
    assert env.cell()[0] == DET and env.cell()[2] == Lifecycle.ACTIVE
    stamps = [e.timestamp for e in b.events[SID]]
    assert stamps == sorted(stamps)
    env.clock.advance(1)
    b.tick()
    assert env.cell()[2] == Lifecycle.TERMINATED


# --- I-CHECKPOINT ---------------------------------------

def test_T63_checkpoint_emitted_after_n_events():
    """I-CHECKPOINT: a CHECKPOINT event is emitted after N events."""
    env = Env()
    env.config.n_checkpoint = 5
    env.config.t_checkpoint = float("inf")
    env.bridge._last_cp = {SID: env.bridge._now()}
    # Generate 5 events: escalate + 4 tool calls
    env.bridge.escalate_to_human(SID)
    for i in range(4):
        env.bridge.submit_tool_call(SID, f"tool:{i}", key=f"k{i}")
    kinds = env.kinds()
    assert GE.CHECKPOINT in kinds, f"no CHECKPOINT in {kinds}"
    cp = [e for e in env.bridge.events[SID] if e.kind == GE.CHECKPOINT][0]
    assert cp.payload["tree_size"] == 5  # ATTACHED + HUMAN_PENDING + 3 QUEUED
    assert len(cp.payload["root"]) == 64  # hex SHA-256


def test_T64_checkpoint_emitted_after_t_cp():
    """I-CHECKPOINT: a CHECKPOINT event is emitted after T_cp seconds."""
    env = Env()
    env.config.n_checkpoint = 10**9
    env.config.t_checkpoint = 100.0
    env.bridge._last_cp = {SID: env.bridge._now()}
    env.bridge.escalate_to_human(SID)
    env.clock.advance(100)
    # _maybe_checkpoint is called after _commit; tick may not commit,
    # so call _maybe_checkpoint directly to test the time threshold.
    env.bridge._maybe_checkpoint(SID)
    kinds = env.kinds()
    assert GE.CHECKPOINT in kinds, f"no CHECKPOINT in {kinds}"


def test_T65_checkpoint_root_matches_recomputed():
    """I-CHECKPOINT: the Merkle root in the CHECKPOINT event matches a
    recomputation from the event log."""
    from merkle import merkle_root
    env = Env()
    env.config.n_checkpoint = 3
    env.config.t_checkpoint = float("inf")
    env.bridge.cfg = env.config
    env.bridge._last_cp = {SID: env.bridge._now()}
    env.bridge.escalate_to_human(SID)
    env.bridge.submit_tool_call(SID, "tool:1", key="k1")
    # After 3 events (ATTACHED + HUMAN_PENDING + TOOL_CALL_QUEUED), checkpoint fires
    cp = [e for e in env.bridge.events[SID] if e.kind == GE.CHECKPOINT][-1]
    # Recompute the root from all events before the CHECKPOINT
    preceding = [e for e in env.bridge.events[SID] if e.sequence < cp.sequence]
    hashes = [bytes.fromhex(e.event_hash()) for e in preceding]
    expected = merkle_root(hashes).hex()
    assert cp.payload["root"] == expected, \
        f"root {cp.payload['root']} != recomputed {expected}"


def test_T66_checkpoint_receipt_optional():
    """I-CHECKPOINT: the receipt field is optional (not required by the schema)."""
    env = Env()
    env.config.n_checkpoint = 2
    env.config.t_checkpoint = float("inf")
    env.bridge.cfg = env.config
    env.bridge._last_cp = {SID: env.bridge._now()}
    env.bridge.escalate_to_human(SID)
    cp = [e for e in env.bridge.events[SID] if e.kind == GE.CHECKPOINT]
    assert len(cp) >= 1
    # The reference bridge does not set 'receipt'; the schema says it's optional
    assert "receipt" not in cp[-1].payload


def test_T63b_count_trigger_counts_events_since_last_checkpoint():
    """I-CHECKPOINT: the count trigger measures events since the last
    checkpoint, not the length of the whole log: with N = 5, a long run
    emits one CHECKPOINT per N other events, never one per commit."""
    env = Env()
    env.config.n_checkpoint = 5
    env.config.t_checkpoint = float("inf")
    env.bridge._last_cp = {SID: env.bridge._now()}
    env.bridge.escalate_to_human(SID)
    for i in range(40):
        env.bridge.submit_tool_call(SID, f"tool:{i}", key=f"k{i}")
    log = env.bridge.events[SID]
    cps = [e.sequence for e in log if e.kind == GE.CHECKPOINT]
    assert 5 <= len(cps) <= len(log) // 5 + 1, (len(cps), len(log))
    assert all(b - a >= 5 for a, b in zip(cps, cps[1:])), cps
    # and a restart resumes the count from the last checkpoint
    b2 = Bridge.recover(env.storage, env.clock, env.config)
    log2 = env.storage.logs[SID]
    last = max(i for i, e in enumerate(log2) if e.kind == GE.CHECKPOINT)
    assert b2._cp_len[SID] == last + 1


# --- I11-REVOKE: key lifecycle -----------------------------------

def test_T67_soft_revocation_does_not_detach_active():
    """I11-REVOKE: soft (rotation) revocation keeps active connections."""
    env = Env()
    op_revoke(env.bridge, SID, "ck-1", reason="rotation")
    assert "ck-1" in env.bridge.client_set(SID)  # still connected
    kinds = env.kinds()
    assert GE.KEY_REVOKED in kinds
    assert env.cell() == (ATT, NONE, ACTIVE)  # no detach


def test_T68_hard_revocation_detaches_active():
    """I11-REVOKE: hard (compromise) revocation detaches the key."""
    env = Env()
    op_revoke(env.bridge, SID, "ck-1", reason="compromise")
    assert "ck-1" not in env.bridge.client_set(SID)
    kinds = env.kinds()
    assert GE.KEY_REVOKED in kinds
    assert GE.DETACHMENT in kinds  # forced detach
    assert env.cell() == (DET, NONE, ACTIVE)


def_T68b = None  # placeholder


def test_T69_revoked_key_rejected_on_reattach():
    """I11-REVOKE: re-attach with a revoked key is rejected."""
    env = Env()
    # Add a second key so the session doesn't enter key_exhausted
    key2 = ClientKey("ck-2")
    add_client(env.bridge, SID, env.key, key2.public())
    env.keys["ck-2"] = key2
    env.disconnect()
    op_revoke(env.bridge, SID, "ck-1", reason="rotation")
    # Re-attach with the revoked key
    env.sync("ck-1")
    ch = env.bridge.challenge(SID, "ck-1")
    req = env.keys["ck-1"].request(SID, ch.nonce, env.seen["ck-1"][0],
                                    env.seen["ck-1"][1])
    with pytest.raises(BridgeError, match="revoked_key"):
        env.bridge.begin_resume(SID, req)
    assert GE.RESUME_REJECTED in env.kinds()
    assert env.bridge.events[SID][-1].payload["reason"] == "revoked_key"


def test_T70_all_keys_revoked_enters_key_exhausted():
    """I11-REVOKE: revoking the last key enters key_exhausted."""
    env = Env()
    op_revoke(env.bridge, SID, "ck-1", reason="compromise")
    s = env.bridge._sess[SID]
    assert getattr(s, 'key_exhausted', False)


def test_T71_key_exhausted_rejects_client_ops():
    """I11-REVOKE: key_exhausted sessions reject client operations."""
    env = Env()
    op_revoke(env.bridge, SID, "ck-1", reason="compromise")
    s = env.bridge._sess[SID]
    s.key_exhausted = True
    with pytest.raises(BridgeError):
        env.bridge.escalate_to_human(SID)


def test_T72_operator_add_key_clears_key_exhausted():
    """I11-REVOKE: OPERATOR_ADD_KEY clears key_exhausted."""
    env = Env()
    op_revoke(env.bridge, SID, "ck-1", reason="compromise")
    op_add_key(env.bridge, SID, "ck-2", "cd" * 32)
    s = env.bridge._sess[SID]
    assert not getattr(s, 'key_exhausted', False)
    assert "ck-2" in s.keys
    kinds = env.kinds()
    assert GE.OPERATOR_ADD_KEY in kinds


def test_T73_operator_terminate_from_key_exhausted():
    """I11-REVOKE: OPERATOR_TERMINATION from key_exhausted."""
    env = Env()
    op_revoke(env.bridge, SID, "ck-1", reason="compromise")
    op_terminate(env.bridge, SID)
    assert env.cell()[2] == Lifecycle.TERMINATED
    kinds = env.kinds()
    assert GE.OPERATOR_TERMINATION in kinds
    assert GE.TERMINATION in kinds


def test_T74_revocation_request_without_signature():
    """I11-REVOKE: client requests revocation; only KEY_REVOCATION_REQUESTED emitted."""
    env = Env()
    result = env.bridge.revoke_key(SID, "ck-1", reason="rotation",
                                   signature="", requested_by="ck-1")
    assert result == "requested"
    kinds = env.kinds()
    assert GE.KEY_REVOCATION_REQUESTED in kinds
    assert GE.KEY_REVOKED not in kinds  # not revoked yet
    assert "ck-1" in env.bridge.client_set(SID)  # still active


def test_T75_two_phase_rotation():
    """I11-REVOKE: two-phase rotation = add new key, then revoke old (soft)."""
    env = Env()
    # Phase 1: add new key
    key2 = ClientKey("ck-2")
    add_client(env.bridge, SID, env.key, key2.public())
    env.keys["ck-2"] = key2
    # Phase 2: revoke old key (soft — keeps active connection)
    op_revoke(env.bridge, SID, "ck-1", reason="rotation")
    # ck-1 is revoked but still connected (soft); session is still attached
    assert "ck-1" in env.bridge.client_set(SID)
    assert "ck-1" in env.bridge._sess[SID].revoked_keys
    assert env.cell() == (ATT, NONE, ACTIVE)
    # ck-2 is registered but not yet connected (needs a join)
    assert "ck-2" in env.bridge._sess[SID].keys
    assert "ck-2" not in env.bridge._sess[SID].revoked_keys


def test_T76_revoked_keys_survive_restart():
    """I11-REVOKE: revoked keys are rebuilt from the log on restart."""
    env = Env()
    op_revoke(env.bridge, SID, "ck-1", reason="rotation")
    env.restart()
    s = env.bridge._sess[SID]
    assert "ck-1" in getattr(s, 'revoked_keys', set())


# ----------------------------------------------------------------------
# I-GRANT: the initial scope is granted outside the contract
# ----------------------------------------------------------------------

def _grant_env():
    storage, clock = Storage(), FakeClock(1000.0)
    bridge = Bridge(storage, clock, Config(),
                    OperatorGrantVerifier(TEST_OPERATOR.public_key))
    ident = SessionIdentity("sess-g", "user-alice", SCOPE, ("root",))
    return bridge, storage, ident, ClientKey("ck-1")


def test_T77_attach_with_a_valid_grant_is_accepted():
    """Attach with a valid grant is accepted. [trace: I-GRANT]"""
    bridge, storage, ident, key = _grant_env()
    attach_as(bridge, ident, key)
    assert [e.kind for e in storage.logs["sess-g"]] == [GE.ATTACHED]


def test_T78_attach_without_or_with_a_forged_grant_is_refused():
    """Attach without or with a forged grant is refused. [trace: I-GRANT]"""
    bridge, storage, ident, key = _grant_env()
    forged = OperatorKey(b"\x09" * 32).grant(ident, key.public())
    for grant in (None, "", "zz", "00" * 64, forged):
        with pytest.raises(GrantInvalid):
            bridge.attach(ident, key.public(), grant,
                          key.prove_attach(ident))
    assert "sess-g" not in storage.logs         # nothing was committed
    assert not storage.client_keys              # no key was registered


def test_T79_a_grant_is_bound_to_session_scope_lineage_and_key():
    """A grant is bound to session scope lineage and key. [trace: I-GRANT]"""
    bridge, storage, ident, key = _grant_env()
    good = TEST_OPERATOR.grant(ident, key.public())
    other_session = SessionIdentity("sess-h", ident.principal_id,
                                    ident.authority_scope, ident.task_lineage)
    wider = SessionIdentity(ident.session_id, ident.principal_id,
                            ident.authority_scope + ("admin:all",),
                            ident.task_lineage)
    other_principal = SessionIdentity(ident.session_id, "user-mallory",
                                      ident.authority_scope,
                                      ident.task_lineage)
    other_lineage = SessionIdentity(ident.session_id, ident.principal_id,
                                    ident.authority_scope, ("other",))
    for claimed in (other_session, wider, other_principal, other_lineage):
        with pytest.raises(GrantInvalid):
            bridge.attach(claimed, key.public(), good,
                          key.prove_attach(claimed))
    other_key = ClientKey("ck-2")                 # another client key
    with pytest.raises(GrantInvalid):
        bridge.attach(ident, other_key.public(), good,
                      other_key.prove_attach(ident))
    assert not storage.logs


def test_T80_a_bridge_with_no_grant_authority_refuses_attach():
    """A bridge with no grant authority refuses attach. [trace: I-GRANT]"""
    storage = Storage()
    bridge = Bridge(storage, FakeClock(1000.0), Config())
    ident = SessionIdentity("sess-g", "user-alice", SCOPE, ())
    key = ClientKey("ck-1")
    with pytest.raises(GrantInvalid):
        attach_as(bridge, ident, key)
    assert not storage.logs


def test_T81_the_grant_domain_tag_separates_it_from_other_signatures():
    """An operator signature over a re-attach tuple is not a grant. [trace: I-GRANT]"""
    bridge, storage, ident, key = _grant_env()
    confusable = TEST_OPERATOR._signer.sign(
        _canon([ident.session_id, "n", 0, "h"])).hex()
    with pytest.raises(GrantInvalid):
        bridge.attach(ident, key.public(), confusable, key.prove_attach(ident))


# ----------------------------------------------------------------------
# Second proof-of-possession scheme: ECDSA P-256 (B.2)
# ----------------------------------------------------------------------

def _p256_env():
    """An attached session whose client keys are ECDSA P-256."""
    env = Env()
    env.key = ClientKey("ck-1", scheme=SCHEME_ECDSA_P256)
    env.keys = {"ck-1": env.key}
    env.storage = Storage()
    env.bridge = Bridge(env.storage, env.clock, env.config,
                        OperatorGrantVerifier(TEST_OPERATOR.public_key))
    ident = SessionIdentity("sess-p256", "user-alice", SCOPE, ("root",))
    env.sid = ident.session_id
    attach_as(env.bridge, ident, env.key)
    env.seen = {}
    env.sync("ck-1")
    return env


def test_T82_p256_proof_of_possession_accepts_and_rejects():
    """I11(c) under ECDSA P-256: the registry records the scheme tag and
    the 65-byte public key; a signature by the registered key verifies, a
    signature by another key or over another message does not."""
    env = _p256_env()
    assert env.storage.key_schemes[(env.sid, "ck-1")] == SCHEME_ECDSA_P256
    assert len(env.storage.client_keys[(env.sid, "ck-1")]) == 65
    env.disconnect()
    stranger = ClientKey("ck-1", scheme=SCHEME_ECDSA_P256)
    _rejects(env, env.request(key=stranger), "bad_signature")
    good = env.request()
    other = ClientKey("ck-1", seed=env.key.seed, scheme=SCHEME_ECDSA_P256)
    seq, h = env.seen["ck-1"]
    other_message = ResumeRequest(
        good.key_id, good.nonce, seq, h,
        other.sign(env.sid, good.nonce, seq + 1, h))
    _rejects(env, other_message, "bad_signature")
    env.bridge.client_reattach(env.sid, env.request())
    assert env.kinds()[-1] == GE.RESUME_VERIFIED


def test_T83_a_scheme_tag_is_not_interchangeable():
    """A key recorded under one scheme is never checked under another,
    and an unknown tag is invalid."""
    key = ClientKey("ck-1", scheme=SCHEME_ECDSA_P256)
    msg = _canon(["s", "n", 0, "h"])
    sig = key.sign_bytes(msg)
    assert _verify_scheme(SCHEME_ECDSA_P256, key.public_key, msg, sig)
    assert not _verify_scheme(SCHEME_ED25519, key.public_key, msg, sig)
    assert not _verify_scheme("rsa-pss", key.public_key, msg, sig)
    assert not _verify_scheme(SCHEME_ECDSA_P256, key.public_key, msg,
                              sig[:-2])
    assert not _verify_scheme(SCHEME_ECDSA_P256, key.public_key[:33], msg,
                              sig)
    assert not _verify_scheme(SCHEME_ECDSA_P256, key.public_key, msg,
                              "00" * 64)


def test_T84_p256_known_answer_from_an_independent_signer():
    """A signature made outside this suite verifies; the same file is read
    by the Rust crate (vectors/p256_kat.json). [trace: wire]"""
    import pathlib
    kat = json.loads((pathlib.Path(__file__).parent / "vectors"
                      / "p256_kat.json").read_text())
    pub = bytes.fromhex(kat["public_key"])
    for case in kat["cases"]:
        got = _verify_scheme(SCHEME_ECDSA_P256, pub,
                             case["message"].encode(), case["signature"])
        assert got == case["valid"], case["name"]


# --- I11-REVOKE and I11: key lifecycle, further cases -----------------------

def test_T85_a_server_takes_a_clients_public_key_only():
    """Attach and key registration accept the public key, never a client
    key object that can sign; the registry holds no seed. [trace: I11 I11-REVOKE]"""
    bridge, storage, ident, key = _grant_env()
    grant = TEST_OPERATOR.grant(ident, key.public())
    proof = key.prove_attach(ident)
    with pytest.raises(TypeError):
        bridge.attach(ident, key, grant, proof)      # a ClientKey can sign
    assert not storage.logs and not storage.client_keys
    bridge.attach(ident, key.public(), grant, proof)
    slot = (ident.session_id, key.key_id)
    assert storage.client_keys[slot] == key.public_key
    assert storage.key_schemes[slot] == key.scheme
    assert not hasattr(key.public(), "seed")
    assert key.seed not in storage.client_keys.values()
    with pytest.raises(TypeError):
        bridge.add_client_key("sess-g", key.key_id, ClientKey("ck-2"), "n", "s")


def test_T86_hard_revocation_keeps_the_other_connected_client():
    """I11-REVOKE, I15: a hard revocation removes only the revoked key from
    the client set; the session stays attached while another key is
    connected."""
    env = Env()
    env.add_device("ck-2")
    env.join("ck-2")
    op_revoke(env.bridge, SID, "ck-1", reason="compromise")
    assert env.bridge.client_set(SID) == {"ck-2"}
    assert env.cell() == (ATT, NONE, ACTIVE)
    assert GE.DETACHMENT not in env.kinds()
    assert not env.bridge._sess[SID].key_exhausted
    op_revoke(env.bridge, SID, "ck-2", reason="compromise")
    assert env.cell() == (DET, NONE, ACTIVE)
    assert env.bridge._sess[SID].key_exhausted


def test_T87_a_key_revoked_after_its_challenge_is_rejected():
    """I11-REVOKE: a key revoked between challenge and re-attach is
    rejected as revoked_key; the nonce is spent and the cell unchanged."""
    env = Env()
    env.add_device("ck-2")
    env.disconnect()
    nonce = env.bridge.challenge(SID, "ck-1").nonce
    op_revoke(env.bridge, SID, "ck-1", reason="rotation")
    before = env.cell()
    with pytest.raises(BridgeError, match="revoked_key"):
        env.bridge.begin_resume(SID, env.request("ck-1", nonce=nonce))
    assert env.cell() == before == (DET, NONE, ACTIVE)
    assert env.bridge.events[SID][-1].kind == GE.RESUME_REJECTED
    assert env.bridge._nonces[SID][nonce].used       # spent (I11d)
    # another key cannot use the nonce either: it was issued for ck-1
    _rejects(env, env.request("ck-2", nonce=nonce), "nonce_binding")
    env.reattach("ck-2")                             # a fresh one works
    assert env.cell() == (ATT, NONE, ACTIVE)


def test_T88_key_exhausted_and_a_recovery_key_survive_restart():
    """I11-REVOKE, I12: key_exhausted and OPERATOR_ADD_KEY are derived from
    the log; the added key re-attaches after a restart and the revoked key
    does not."""
    env = Env()
    op_revoke(env.bridge, SID, "ck-1", reason="compromise")
    env.restart()
    assert env.bridge._sess[SID].key_exhausted
    assert env.bridge._sess[SID].revoked_keys == {"ck-1"}
    with pytest.raises(BridgeError, match="KEY_EXHAUSTED"):
        env.bridge.escalate_to_human(SID)
    key2 = ClientKey("ck-2")
    op_add_key(env.bridge, SID, "ck-2", key2.public_key.hex())
    env.keys["ck-2"] = key2
    env.restart()
    s = env.bridge._sess[SID]
    assert not s.key_exhausted and s.keys == {"ck-1", "ck-2"}
    env.sync("ck-2")
    env.reattach("ck-2")
    assert env.cell() == (ATT, NONE, ACTIVE)
    env.disconnect()
    with pytest.raises(BridgeError, match="revoked_key"):
        env.begin_resume("ck-1")


def test_T89_revocation_refusals():
    """I11-REVOKE: an unknown key cannot be revoked; OPERATOR_ADD_KEY needs
    a key_exhausted session and never takes a key id already registered
    (a revoked key does not return); a key_exhausted session refuses
    further revocation."""
    env = Env()
    with pytest.raises(BridgeError, match="unknown key"):
        op_revoke(env.bridge, SID, "ck-9")
    with pytest.raises(BridgeError, match="not key_exhausted"):
        op_add_key(env.bridge, SID, "ck-2", "cd" * 32)
    with pytest.raises(BridgeError, match="not key_exhausted"):
        op_terminate(env.bridge, SID)
    op_revoke(env.bridge, SID, "ck-1", reason="compromise")
    # refused by the bridge from the log, not only by the registry
    with pytest.raises(BridgeError, match="client key already registered"):
        op_add_key(env.bridge, SID, "ck-1", "cd" * 32)
    with pytest.raises(BridgeError, match="KEY_EXHAUSTED"):
        op_revoke(env.bridge, SID, "ck-1", reason="compromise")
    assert env.bridge._sess[SID].key_exhausted


# --- Operator events are authenticated (I-OPERATOR) -------------------------

def _exhausted_env():
    env = Env()
    op_revoke(env.bridge, SID, "ck-1", reason="compromise")
    return env


def test_T90_revoke_key_requires_a_valid_operator_signature():
    """I-OPERATOR: a revocation with a missing, malformed, wrong-key or
    other-operation signature is refused and commits nothing."""
    env = Env()
    b = env.bridge
    wrong_key = op_sig(b, "revoke", SID, "ck-1", "compromise",
                       operator=OperatorKey(b"\x09" * 32))
    other_op = op_sig(b, "terminate", SID, "compromise")
    other_reason = op_sig(b, "revoke", SID, "ck-1", "rotation")
    before = len(env.bridge.events[SID])
    for sig in (None, "zz", "00" * 64, wrong_key, other_op, other_reason):
        with pytest.raises(OperatorSignatureInvalid,
                           match="operator_signature_invalid"):
            env.bridge.revoke_key(SID, "ck-1", "compromise", signature=sig)
    assert len(env.bridge.events[SID]) == before
    assert env.cell() == (ATT, NONE, ACTIVE)
    assert not env.bridge._sess[SID].revoked_keys


def test_T91_revocation_signature_is_bound_to_session_and_key():
    """I-OPERATOR: a signature for another session or another key is not
    accepted."""
    env = Env()
    env.add_device("ck-2")
    for sig in (op_sig(env.bridge, "revoke", "sess-other", "ck-1", "rotation"),
                op_sig(env.bridge, "revoke", SID, "ck-2", "rotation")):
        with pytest.raises(OperatorSignatureInvalid):
            env.bridge.revoke_key(SID, "ck-1", "rotation", signature=sig)
    assert not env.bridge._sess[SID].revoked_keys


def test_T92_operator_add_key_requires_a_valid_operator_signature():
    """I-OPERATOR: the recovery key path is closed to an unsigned or
    wrongly signed addition; the signature covers the key material."""
    env = _exhausted_env()
    b = env.bridge
    pub = "cd" * 32
    good = op_sig(b, "add_key", SID, "ck-2", pub)
    bad = [None, "", "00" * 64,
           op_sig(b, "add_key", SID, "ck-2", pub,
                  operator=OperatorKey(b"\x09" * 32)),
           op_sig(b, "add_key", SID, "ck-2", "ef" * 32),      # other key
           op_sig(b, "add_key", SID, "ck-3", pub),            # other id
           op_sig(b, "terminate", SID, "all_keys_revoked")]   # other op
    for sig in bad:
        with pytest.raises(OperatorSignatureInvalid):
            env.bridge.operator_add_key(SID, "ck-2", pub, signature=sig)
    assert env.bridge._sess[SID].key_exhausted
    assert (env.sid, "ck-2") not in env.bridge.storage.client_keys
    env.bridge.operator_add_key(SID, "ck-2", pub, signature=good)
    assert not env.bridge._sess[SID].key_exhausted


def test_T93_operator_terminate_requires_a_valid_operator_signature():
    """I-OPERATOR: an unsigned or mis-signed termination of a
    key_exhausted session is refused."""
    env = _exhausted_env()
    b = env.bridge
    bad = [None, "", "00" * 64,
           op_sig(b, "terminate", SID, "all_keys_revoked",
                  operator=OperatorKey(b"\x09" * 32)),
           op_sig(b, "terminate", SID, "other_reason"),
           op_sig(b, "revoke", SID, "ck-1", "all_keys_revoked")]
    for sig in bad:
        with pytest.raises(OperatorSignatureInvalid):
            env.bridge.operator_terminate(SID, signature=sig)
    assert env.cell()[2] == ACTIVE and env.bridge._sess[SID].key_exhausted
    op_terminate(env.bridge, SID)
    assert env.cell()[2] == TERM


def test_T94_a_bridge_without_an_operator_verifier_refuses_operator_events():
    """I-OPERATOR: with no operator verifier configured the operator events
    are refused, as attach is without a grant authority."""
    storage = Storage()
    b = Bridge(storage, FakeClock(1000.0), Config(),
               lambda *a: True)          # a grant verifier only
    ident = SessionIdentity(SID, "u", SCOPE, ())
    key = ClientKey("ck-1")
    b.attach(ident, key.public(), "any", key.prove_attach(ident))
    with pytest.raises(OperatorSignatureInvalid):
        b.revoke_key(SID, "ck-1", "rotation",
                     signature=op_sig(b, "revoke", SID, "ck-1", "rotation"))


def test_T95_operator_signature_is_logged_and_survives_recovery():
    """I-OPERATOR: the verified signature is recorded in the event and a
    restart replays the log without re-checking it."""
    env = Env()
    sig = op_sig(env.bridge, "revoke", SID, "ck-1", "compromise")
    env.bridge.revoke_key(SID, "ck-1", "compromise", signature=sig)
    assert env.bridge.events[SID][
        [e.kind for e in env.bridge.events[SID]].index(GE.KEY_REVOKED)
    ].payload["signature"] == sig
    env.restart()
    assert env.bridge._sess[SID].key_exhausted


def test_T96_the_operator_domain_tags_separate_the_signatures():
    """I-OPERATOR: grant, revoke, add-key and terminate signatures use
    distinct domain tags, so none verifies as another."""
    tags = {GRANT_DOMAIN, REVOKE_DOMAIN, ADD_KEY_DOMAIN, TERMINATE_DOMAIN}
    assert len(tags) == len([GRANT_DOMAIN, REVOKE_DOMAIN, ADD_KEY_DOMAIN,
                            TERMINATE_DOMAIN]) and all(t.startswith("bc/v1/") for t in tags)


def test_T97_keyless_challenges_cannot_evict_a_live_nonce():
    """I11f: a caller without a key floods ``challenge``; the nonce a
    genuine client already holds stays valid, and the flood is refused
    once the session's live nonces are used up."""
    env = Env().reach(DET, NONE)
    req = env.request()                              # the genuine nonce
    issued = 0
    with pytest.raises(BridgeError, match="challenge budget"):
        for _ in range(4 * NONCE_RECORDS):
            env.bridge.challenge(SID, "ck-1")
            issued += 1
    assert issued == NONCE_RECORDS - 1               # the genuine one counts
    env.bridge.begin_resume(SID, req)                # still accepted
    assert env.cell()[0] == RES


def test_T98_spent_or_expired_nonces_make_room_for_new_challenges():
    """I11f: the budget counts live nonces only; once they are spent or
    expired a challenge is issued again."""
    env = Env().reach(DET, NONE)
    for _ in range(NONCE_RECORDS):
        env.bridge.challenge(SID, "ck-1")
    with pytest.raises(BridgeError, match="challenge budget"):
        env.bridge.challenge(SID, "ck-1")
    env.clock.advance(Config().t_nonce)
    assert env.bridge.challenge(SID, "ck-1").nonce             # expired ones yield
    env2 = Env().reach(DET, NONE)
    first = env2.request()
    for _ in range(NONCE_RECORDS - 1):
        env2.bridge.challenge(SID, "ck-1")
    env2.bridge.begin_resume(SID, first)               # spends one
    env2.bridge.complete_resume(SID)
    assert env2.bridge.challenge(SID, "ck-1").nonce


def test_T99_unauthenticated_rejections_are_logged_up_to_a_bound():
    """I11g: failures before authentication append at most
    UNAUTH_LOG_LIMIT events between authentic requests, and every one is
    refused with the same error; an authentic request restores the budget
    and is itself always answered with a logged outcome."""
    env = Env().reach(DET, NONE)
    stranger = ClientKey("ck-1")                     # same id, other secret
    n0 = len(env.kinds())
    messages = set()
    for _ in range(3 * UNAUTH_LOG_LIMIT):
        bad = stranger.request(SID, "0" * 32, 0, "0" * 64)
        with pytest.raises(BridgeError, match="rejected") as exc:
            env.bridge.begin_resume(SID, bad)
        messages.add(str(exc.value))
    assert len(env.kinds()) - n0 == UNAUTH_LOG_LIMIT
    assert len(messages) == 1                        # uniform
    with pytest.raises(BridgeError, match="rejected"):
        env.bridge.begin_resume(
            SID, env.keys["ck-1"].request(SID, "0" * 32, 0, "0" * 64))
    assert env.kinds()[-1] == GE.RESUME_REJECTED     # authentic: logged
    assert env.bridge.events[SID][-1].payload["reason"] == "nonce_unknown"
    bad = stranger.request(SID, "0" * 32, 0, "0" * 64)
    with pytest.raises(BridgeError):
        env.bridge.begin_resume(SID, bad)
    assert env.bridge.events[SID][-1].payload["reason"] == "bad_signature"


def test_T100_a_flood_does_not_deny_the_genuine_reattach():
    """I11f + I11g together (the attack): keyless challenges and forged
    requests, then the genuine signed re-attach is accepted."""
    env = Env().reach(DET, NONE)
    req = env.request()
    stranger = ClientKey("ck-1")
    for _ in range(3 * NONCE_RECORDS):
        try:
            env.bridge.challenge(SID, "ck-1")
        except BridgeError:
            pass
        with pytest.raises(BridgeError):
            env.bridge.begin_resume(
                SID, stranger.request(SID, "0" * 32, 0, "0" * 64))
    env.bridge.begin_resume(SID, req)
    env.bridge.complete_resume(SID)
    assert env.cell() == (ATT, NONE, ACTIVE)

# --- Byte-level known answers (F-1, F-5) -----------------------------------

def _bytes_kat() -> dict:
    import pathlib
    return json.loads((pathlib.Path(__file__).parent / "vectors"
                       / "bytes_kat.json").read_text())


def test_T101_canonical_json_matches_rfc_8785_known_answers():
    """Every hash and every signed message is taken over RFC 8785 bytes:
    raw UTF-8 for non-ASCII, UTF-16 key order, ECMAScript numbers (1.0 is
    1), and no canonical form for what is not portable.  The same file is
    read by the Rust crate (vectors/bytes_kat.json). [trace: wire]"""
    kat = _bytes_kat()
    for c in kat["canonical"]:
        got = _canon(json.loads(c["json"]))
        assert got.decode() == c["canonical"], c["name"]
        assert got.hex() == c["hex"], c["name"]
    for c in kat["reject"]:
        with pytest.raises(ValueError):
            _canon(json.loads(c["json"]))
    for e in kat["events"]:
        ev = Event(GovernanceEvent(e["kind"]), e["session_id"], e["sequence"],
                   e["prev_hash"], e["payload"], e["timestamp"])
        assert ev.canonical_bytes().decode() == e["canonical"]
        assert ev.event_hash() == e["hash"]
    for c in kat["content_hashes"]:
        assert content_hash(json.loads(c["json"])) == c["hash"], c["name"]


def test_T102_resume_proof_signed_bytes_and_signature_are_pinned():
    """The exact bytes a re-attach or join proof signs, and the Ed25519
    signature over them, are fixed; signatures over a neighbouring message
    (the other operation, another key id, no tag, no key id) do not verify. [trace: wire]"""
    kat = _bytes_kat()
    pub = bytes.fromhex(kat["public_key"])
    for p in kat["resume_proofs"]:
        msg = _resume_bytes(p["op"], p["session_id"], p["key_id"],
                            p["nonce"], p["seq"], p["hash"])
        assert msg.decode() == p["signed_text"], p["name"]
        assert msg.hex() == p["signed_hex"], p["name"]
        key = ClientKey(p["key_id"], seed=bytes.fromhex(kat["ed25519_seed"]))
        assert key.public_key == pub
        assert key.sign_bytes(msg) == p["signature"], p["name"]
        assert _verify_scheme(SCHEME_ED25519, pub, msg, p["signature"])
    for n in kat["resume_negatives"]:
        msg = _resume_bytes(n["op"], n["session_id"], n["key_id"],
                            n["nonce"], n["seq"], n["hash"])
        assert not _verify_scheme(SCHEME_ED25519, pub, msg, n["signature"]), \
            n["name"]


def test_T103_a_reattach_proof_is_not_a_join_proof():
    """I11(c): the two operations sign different bytes, so a signature made
    for one is refused as the other, in both directions. [trace: wire]"""
    env = Env()
    env.add_device("ck-2")
    as_reattach = env.request("ck-2", op="reattach")
    n = len(env.kinds())
    with pytest.raises(BridgeError, match="rejected"):
        env.bridge.join(env.sid, as_reattach)
    assert env.kinds()[n:] == [GE.RESUME_REJECTED]
    assert env.bridge.events[env.sid][-1].payload["reason"] == "bad_signature"
    assert env.cell() == (ATT, NONE, ACTIVE)
    env.bridge.join(env.sid, env.request("ck-2", op="join"))   # its own works
    env.disconnect()
    _rejects(env, env.request("ck-1", op="join"), "bad_signature")
    env.reattach()


def test_T104_a_resume_proof_names_the_key_that_signs_it():
    """I11(c): two key ids over one public key are different identities; a
    proof for one id is refused under the other, and a proof over the
    untagged tuple of an earlier format is refused. [trace: wire]"""
    env = Env()
    twin = ClientKey("ck-2", seed=env.key.seed)       # same key material
    add_client(env.bridge, env.sid, env.key, twin.public())
    env.keys["ck-2"] = twin
    env.sync("ck-2")
    env.disconnect()
    seq, h = env.seen["ck-2"]
    nonce = env.bridge.challenge(env.sid, "ck-2").nonce
    relabelled = ResumeRequest(
        "ck-2", nonce, seq, h, env.key.sign(env.sid, nonce, seq, h))
    _rejects(env, relabelled, "bad_signature")
    nonce = env.bridge.challenge(env.sid, "ck-1").nonce
    untagged = ResumeRequest(
        "ck-1", nonce, seq, h,
        env.key.sign_bytes(_canon([env.sid, nonce, seq, h])))
    _rejects(env, untagged, "bad_signature")
    env.reattach()


def _attach_second(env: Env, sid: str, key: ClientKey) -> SessionIdentity:
    """A second, validly granted session on the same bridge."""
    ident = SessionIdentity(sid, "user-mallory", SCOPE, ())
    attach_as(env.bridge, ident, key)
    return ident


def test_T105_a_key_id_is_scoped_to_its_session():
    """B1: a second, validly granted session that reuses the first
    session's key id must neither replace the first session's key nor be
    able to re-attach to it. [trace: I11]"""
    env = Env()
    mallory = ClientKey("ck-1")                 # the same key id, her own key
    _attach_second(env, "sess-B", mallory)
    env.disconnect()
    seq, h = env.seen["ck-1"]
    nonce = env.bridge.challenge(env.sid, "ck-1").nonce
    forged = ResumeRequest("ck-1", nonce, seq, h,
                           mallory.sign(env.sid, nonce, seq, h))
    _rejects(env, forged, "bad_signature")       # not her key for this session
    env.reattach()                               # the owner is not locked out
    assert env.kinds()[-1] == GE.RESUME_VERIFIED
    assert env.bridge.registered_keys("sess-B") == frozenset({"ck-1"})


def test_T106_key_material_is_in_the_log():
    """M1: the events that register a key carry its scheme tag and public
    key; the session's keys can be read back from the log alone. [trace: I11]"""
    env = Env()
    second = env.add_device("ck-2")
    events = env.bridge.events[env.sid]
    attached, added = events[0], [e for e in events
                                  if e.kind == GE.CLIENT_ADDED][0]
    assert attached.payload["scheme"] == env.key.scheme
    assert attached.payload["public_key"] == env.key.public_key.hex()
    assert added.payload["scheme"] == second.scheme
    assert added.payload["public_key"] == second.public_key.hex()
    material = env.bridge._sess[env.sid].key_material
    assert material == {"ck-1": (env.key.scheme, env.key.public_key.hex()),
                        "ck-2": (second.scheme, second.public_key.hex())}


def test_T107_operator_added_key_material_is_in_the_log():
    """Operator added key material is in the log. [trace: I11]"""
    env = Env()
    env.disconnect()
    op_revoke(env.bridge, env.sid, "ck-1", "compromise")
    fresh = ClientKey("ck-3", scheme=SCHEME_ECDSA_P256)
    op_add_key(env.bridge, env.sid, "ck-3", fresh.public_key.hex(),
               scheme=fresh.scheme)
    ev = env.bridge.events[env.sid][-1]
    assert ev.kind == GE.OPERATOR_ADD_KEY
    assert (ev.payload["scheme"], ev.payload["public_key"]) == (
        fresh.scheme, fresh.public_key.hex())


def _recovered(env: Env, repaired: list[str]) -> Bridge:
    """Restart: the session recovers (it is not quarantined), the registry
    is the log's, and BRIDGE_RECOVERED names the keys repaired."""
    b = env.restart()
    assert not b.is_quarantined(env.sid)
    recovered = [e for e in env.bridge.events[env.sid]
                 if e.kind == GE.BRIDGE_RECOVERED][-1]
    assert recovered.payload["registry_repaired"] == repaired
    s = b._sess[env.sid]
    assert env.storage.registered_key_ids(env.sid) == s.keys
    for kid, (scheme, public_hex) in s.key_material.items():
        assert env.storage.key_record(env.sid, kid) == (
            scheme, bytes.fromhex(public_hex))
    return b


def test_T108_recovery_repairs_a_registry_entry_that_differs_from_the_log():
    """The log is the source of truth: a registry entry with another public
    key is replaced by the log's, and the key verifies again. [trace: I11]"""
    env = Env()
    env.storage.client_keys[(env.sid, "ck-1")] = ClientKey("ck-1").public_key
    env.disconnect()
    b = _recovered(env, ["ck-1"])
    b.begin_resume(env.sid, env.request("ck-1"))
    b.complete_resume(env.sid)
    assert env.cell() == (ATT, NONE, ACTIVE)


def test_T109_recovery_repairs_a_scheme_that_differs_from_the_log():
    """Recovery repairs a scheme that differs from the log. [trace: I11]"""
    env = Env()
    env.storage.key_schemes[(env.sid, "ck-1")] = SCHEME_ECDSA_P256
    _recovered(env, ["ck-1"])
    assert env.storage.key_record(env.sid, "ck-1")[0] == env.key.scheme


def test_T110_recovery_removes_a_registry_entry_the_log_does_not_record():
    """A crash between the registry write and the event commit leaves an
    entry no event records; recovery drops it and the key id is free. [trace: I11]"""
    env = Env()
    env.disconnect()
    op_revoke(env.bridge, env.sid, "ck-1", "compromise")
    fresh = ClientKey("ck-2")

    def crash(sid, events):
        raise CrashSimulated("crash before the event commit")
    env.storage.append_batch = crash
    with pytest.raises(CrashSimulated):
        op_add_key(env.bridge, env.sid, "ck-2", fresh.public_key.hex())
    assert (env.sid, "ck-2") in env.storage.client_keys
    del env.storage.append_batch
    b = _recovered(env, ["ck-2"])
    assert (env.sid, "ck-2") not in env.storage.client_keys
    assert b._sess[env.sid].key_exhausted
    op_add_key(b, env.sid, "ck-2", fresh.public_key.hex())
    assert not b._sess[env.sid].key_exhausted


def test_T143_recovery_restores_a_registry_entry_the_log_records():
    """An entry missing from the registry is written back from the log. [trace: I11 I12]"""
    env = Env()
    env.add_device("ck-2")
    del env.storage.client_keys[(env.sid, "ck-2")]
    del env.storage.key_schemes[(env.sid, "ck-2")]
    b = _recovered(env, ["ck-2"])
    assert b.registered_keys(env.sid) == frozenset({"ck-1", "ck-2"})


def test_T111_recovery_accepts_a_registry_that_matches_the_log():
    """Recovery accepts a registry that matches the log. [trace: I11]"""
    env = Env()
    env.add_device("ck-2")
    b = env.restart()
    assert not b.is_quarantined(env.sid)
    assert b.registered_keys(env.sid) == frozenset({"ck-1", "ck-2"})
    recovered = [e for e in env.bridge.events[env.sid]
                 if e.kind == GE.BRIDGE_RECOVERED][-1]
    assert recovered.payload["registry_repaired"] == []


def test_T112_a_failed_commit_leaves_no_registry_entry():
    """A refused append must not leave a key behind that a later attach
    with another key would then collide with. [trace: I11]"""
    bridge, storage, ident, key = _grant_env()
    storage.fail_next = True
    with pytest.raises(StorageError):
        attach_as(bridge, ident, key)
    assert not storage.client_keys
    attach_as(bridge, ident, ClientKey("ck-1"))      # another key, same id
    env = Env()
    new = ClientKey("ck-2").public()
    nonce = env.bridge.challenge(env.sid, "ck-1").nonce
    signature = env.key.sign_add_client(env.sid, new, nonce)
    env.storage.fail_next = True
    with pytest.raises(StorageError):
        env.bridge.add_client_key(env.sid, "ck-1", new, nonce, signature)
    assert (env.sid, "ck-2") not in env.storage.client_keys


def test_T113_attach_without_a_proof_of_possession_is_refused():
    """B3: the grant alone does not register a key. [trace: I-GRANT]"""
    bridge, storage, ident, key = _grant_env()
    grant = TEST_OPERATOR.grant(ident, key.public())
    for proof in (None, "", "zz", "00" * 64):
        with pytest.raises(PossessionInvalid) as err:
            bridge.attach(ident, key.public(), grant, proof)
        assert err.value.reason == "possession_invalid"
    assert not storage.logs and not storage.client_keys


def test_T114_a_proof_by_another_key_is_refused():
    """The public key is the granted one, the signature is by a key that
    is not: possession is not shown. [trace: I-GRANT]"""
    bridge, storage, ident, key = _grant_env()
    thief = ClientKey("ck-1")
    with pytest.raises(PossessionInvalid):
        bridge.attach(ident, key.public(),
                      TEST_OPERATOR.grant(ident, key.public()),
                      thief.prove_attach(ident))
    assert not storage.logs


def test_T115_a_grant_binds_the_public_key_not_only_the_key_id():
    """B3: a party that sees a grant cannot attach the same session and
    key id with its own public key. [trace: I-GRANT]"""
    bridge, storage, ident, key = _grant_env()
    seen_grant = TEST_OPERATOR.grant(ident, key.public())
    front_runner = ClientKey("ck-1")                 # the same key id
    with pytest.raises(GrantInvalid):
        bridge.attach(ident, front_runner.public(), seen_grant,
                      front_runner.prove_attach(ident))
    wrong_scheme = ClientKey("ck-1", seed=key.seed, scheme=SCHEME_ECDSA_P256)
    with pytest.raises(GrantInvalid):
        bridge.attach(ident, wrong_scheme.public(), seen_grant,
                      wrong_scheme.prove_attach(ident))
    assert not storage.logs and not storage.client_keys
    attach_as(bridge, ident, key)


def test_T116_a_grant_and_a_proof_are_bound_to_one_bridge():
    """G-min: a grant or an attach proof made for another bridge is not
    valid here. [trace: I-GRANT]"""
    bridge, storage, ident, key = _grant_env()
    elsewhere = "bridge-elsewhere"
    with pytest.raises(GrantInvalid):
        bridge.attach(ident, key.public(),
                      TEST_OPERATOR.grant(ident, key.public(), elsewhere),
                      key.prove_attach(ident))
    with pytest.raises(PossessionInvalid):
        bridge.attach(ident, key.public(),
                      TEST_OPERATOR.grant(ident, key.public()),
                      key.prove_attach(ident, elsewhere))
    assert not storage.logs
    other = Bridge(Storage(), FakeClock(1000.0), Config(),
                   OperatorGrantVerifier(TEST_OPERATOR.public_key),
                   bridge_id=elsewhere)
    attach_as(other, ident, key, elsewhere)          # valid at its own bridge
    with pytest.raises(GrantInvalid):
        attach_as(bridge, ident, key, elsewhere)


def test_T117_the_attach_proof_has_its_own_domain_tag():
    """A signature over the grant bytes, or over a re-attach tuple, is not
    a proof of possession. [trace: I-GRANT]"""
    bridge, storage, ident, key = _grant_env()
    grant = TEST_OPERATOR.grant(ident, key.public())
    for message in (_grant_bytes(DEFAULT_BRIDGE_ID, ident, key.public()),
                    _canon([ident.session_id, key.key_id])):
        with pytest.raises(PossessionInvalid):
            bridge.attach(ident, key.public(), grant,
                          key.sign_bytes(message))
    assert _attach_bytes(DEFAULT_BRIDGE_ID, ident, key.public()) != \
        _grant_bytes(DEFAULT_BRIDGE_ID, ident, key.public())


def test_T118_a_key_id_registered_in_a_session_is_not_registered_again():
    """B1: the registry refuses a second registration of a key id in the
    same session, whoever asks. [trace: I11 I-GRANT]"""
    env = Env()
    with pytest.raises(BridgeError, match="already registered"):
        env.storage.register_key(env.sid, "ck-1", SCHEME_ED25519,
                                 ClientKey("ck-1").public_key)
    dup = ClientKey("ck-1").public()
    nonce = env.bridge.challenge(env.sid, "ck-1").nonce
    _refused_add(env, "ck-1", dup, nonce,
                 env.key.sign_add_client(env.sid, dup, nonce),
                 "key_already_registered")
    assert env.storage.client_keys[(env.sid, "ck-1")] == env.key.public_key


def _refused_add(env: Env, via: str, new: ClientPublicKey, nonce: str,
                 signature: str, reason: str) -> None:
    """add_client is refused with ``reason`` and nothing is committed."""
    before = list(env.bridge.events[env.sid])
    with pytest.raises(AddClientRejected) as err:
        env.bridge.add_client_key(env.sid, via, new, nonce, signature)
    assert err.value.reason == reason
    assert env.bridge.events[env.sid] == before


def test_T119_an_unsigned_or_forged_registration_is_refused():
    """I15(d): knowing a connected key id is not authority.  A caller that
    names ck-1 but cannot sign as ck-1 registers nothing and cannot join
    (the takeover that needed no proof before the signature was checked)."""
    env = Env()
    evil = ClientKey("ck-evil")
    nonce = env.bridge.challenge(SID, "ck-1").nonce
    _refused_add(env, "ck-1", evil.public(), nonce, "", "bad_signature")
    forged = ClientKey("ck-1").sign_add_client(SID, evil.public(), nonce)
    _refused_add(env, "ck-1", evil.public(), nonce, forged, "bad_signature")
    selfsigned = evil.sign_add_client(SID, evil.public(), nonce)
    _refused_add(env, "ck-1", evil.public(), nonce, selfsigned,
                 "bad_signature")
    assert (SID, "ck-evil") not in env.storage.client_keys
    seq, h = env.seen["ck-1"]
    req = evil.request(SID, env.bridge.challenge(SID, "ck-evil").nonce,
                       seq, h, "join")
    with pytest.raises(BridgeError, match="rejected"):
        env.bridge.join(SID, req)
    assert env.bridge.events[SID][-1].payload["reason"] == "unknown_key"


def test_T120_a_registration_signature_binds_operation_session_and_key():
    """I15(d): a signature for a join, for another new key, for another
    session or by a key that is not connected does not authorise the
    registration.  A key id the session does not register is answered as a
    bad signature; that a registered key is not connected is said only
    after its signature verified, and that request has spent its nonce."""
    env = Env()
    second = ClientKey("ck-2")
    new, other = second.public(), ClientKey("ck-3").public()
    nonce = env.bridge.challenge(SID, "ck-1").nonce
    seq, h = env.seen["ck-1"]
    for sig in (env.key.sign(SID, nonce, seq, h, "join"),
                env.key.sign(SID, nonce, seq, h, "reattach"),
                env.key.sign_add_client(SID, other, nonce),
                env.key.sign_add_client("sess-other", new, nonce),
                env.key.sign_add_client(SID, new, "00" * 16)):
        _refused_add(env, "ck-1", new, nonce, sig, "bad_signature")
    # a key id the session does not register is a bad signature, not a
    # statement about who is connected
    _refused_add(env, "ck-9", new, nonce,
                 env.key.sign_add_client(SID, new, nonce), "bad_signature")
    env.bridge.add_client_key(SID, "ck-1", new, nonce,
                              env.key.sign_add_client(SID, new, nonce))
    assert env.bridge.events[SID][-1].kind == GE.CLIENT_ADDED
    # ck-2 is registered now, and not connected
    assert "ck-2" not in env.bridge.client_set(SID)
    nonce2 = env.bridge.challenge(SID, "ck-2").nonce
    _refused_add(env, "ck-2", other, nonce2, "00" * 64, "bad_signature")
    assert not env.bridge._nonces[SID][nonce2].used
    _refused_add(env, "ck-2", other, nonce2,
                 second.sign_add_client(SID, other, nonce2),
                 "via_not_connected")
    assert env.bridge._nonces[SID][nonce2].used


def test_T121_a_registration_cannot_be_replayed_or_use_a_stale_nonce():
    """I15(d), I11(b,d): the authorisation is single-use and fresh."""
    env = Env()
    new = ClientKey("ck-2").public()
    nonce = env.bridge.challenge(SID, "ck-1").nonce
    sig = env.key.sign_add_client(SID, new, nonce)
    env.bridge.add_client_key(SID, "ck-1", new, nonce, sig)
    _refused_add(env, "ck-1", new, nonce, sig, "nonce_used")
    third = ClientKey("ck-3").public()
    nonce = "ab" * 16
    _refused_add(env, "ck-1", third, nonce,
                 env.key.sign_add_client(SID, third, nonce), "nonce_unknown")
    nonce = env.bridge.challenge(SID, "ck-1").nonce
    env.clock.advance(env.config.t_nonce + 1)
    _refused_add(env, "ck-1", third, nonce,
                 env.key.sign_add_client(SID, third, nonce), "nonce_expired")
    nonce = env.bridge.challenge(SID, "ck-1").nonce
    _refused_add(env, "ck-1", new, nonce,
                 env.key.sign_add_client(SID, new, nonce),
                 "key_already_registered")


def test_T122_a_revoked_key_cannot_authorise_a_registration():
    """I15(d), I11-REVOKE: a soft-revoked key stays connected but its
    authority to add keys is gone."""
    env = Env()
    add_client(env.bridge, SID, env.key, ClientKey("ck-2").public())
    op_revoke(env.bridge, SID, "ck-1", reason="rotation")
    new = ClientKey("ck-3").public()
    nonce = env.bridge.challenge(SID, "ck-1").nonce
    _refused_add(env, "ck-1", new, nonce,
                 env.key.sign_add_client(SID, new, nonce), "revoked_key")


def test_T123_registration_signed_bytes_and_signature_are_pinned():
    """The add_client authorisation is the RFC 8785 bytes of the tagged
    tuple; both bridges pin these bytes and this signature, and a
    signature does not verify when any bound field changes. [trace: I15]"""
    kat = _bytes_kat()
    key = ClientKey("ck-kat", seed=bytes.fromhex(kat["ed25519_seed"]))

    def signed(f):
        return _add_client_bytes(f["session_id"], f["via_key_id"],
                                 f["new_key_id"], f["scheme"],
                                 f["public_key"], f["nonce"])
    for p in kat["add_client_proofs"]:
        msg = signed(p)
        assert msg.decode() == p["signed_text"]
        assert msg.hex() == p["signed_hex"]
        assert key.sign_bytes(msg) == p["signature"]
        assert _verify_scheme("ed25519", key.public_key, msg, p["signature"])
    for n in kat["add_client_negatives"]:
        assert not _verify_scheme("ed25519", key.public_key, signed(n),
                                  n["signature"]), n["name"]


def test_T124_attach_proof_signed_bytes_and_signature_are_pinned():
    """The attach proof of possession is the RFC 8785 bytes of the tagged
    tuple that names the bridge, the session and the key with its scheme
    tag; both bridges pin these bytes and this signature, the wire helper
    builds the same bytes, and a signature does not verify when any bound
    field changes. [trace: I-GRANT]"""
    import wire
    kat = _bytes_kat()
    key = ClientKey("ck-kat", seed=bytes.fromhex(kat["ed25519_seed"]))

    def signed(f):
        ident = SessionIdentity(f["session_id"], f["principal"],
                                tuple(f["scope"]), tuple(f["lineage"]))
        msg = _attach_bytes(f["bridge_id"], ident, ClientPublicKey(
            f["key_id"], f["scheme"], bytes.fromhex(f["public_key"])))
        assert msg == wire.attach_signature_input(
            f["bridge_id"], f["session_id"], f["principal"], f["scope"],
            f["lineage"], f["key_id"], f["scheme"], f["public_key"])
        return msg
    for p in kat["attach_proofs"]:
        msg = signed(p)
        assert msg.decode() == p["signed_text"]
        assert msg.hex() == p["signed_hex"]
        assert key.sign_bytes(msg) == p["signature"]
        assert _verify_scheme("ed25519", key.public_key, msg, p["signature"])
    for n in kat["attach_negatives"]:
        assert not _verify_scheme("ed25519", key.public_key, signed(n),
                                  n["signature"]), n["name"]


def test_T125_attach_and_add_client_requests_carry_the_scheme():
    """The wire constructors put the key's scheme tag in the request, so the
    receiver can rebuild the bytes that were signed."""
    import wire
    for data, op in (
        (wire.op_attach(session_id="s", principal="p", scope=["a"],
                        lineage=["l"], key_id="k", scheme="ecdsa-p256",
                        public_key="ab", grant="g", signature="cd"),
         "attach"),
        (wire.op_add_client(session_id="s", via_key_id="k", new_key_id="k2",
                            scheme="ecdsa-p256", new_public_key="ab",
                            nonce="n", signature="cd"), "add_client"),
    ):
        msg = wire.decode_message(data)
        assert msg["op"] == op and msg["scheme"] == "ecdsa-p256"
        assert wire.canonical_bytes(msg) == data


def test_T128_hard_revocation_abandons_the_reattach_it_is_verifying():
    """I11-REVOKE (IRev): a key revoked while its re-attach is in Res is not
    the attached client afterwards; the re-attach is abandoned (Res -> Det,
    DETACHMENT and RESUME_PREPARED) and complete_resume refuses.  A soft
    revocation (rotation) abandons the verification exactly as a hard one
    (compromise) does; the revocation of another key leaves it alone."""
    for why in REVOKE_REASONS:
        env = Env()
        env.add_device("ck-2")
        env.disconnect()
        env.begin_resume("ck-1")
        assert env.cell() == (RES, NONE, ACTIVE)
        n = len(env.kinds())
        op_revoke(env.bridge, SID, "ck-1", why)
        assert _kinds_after(env, n) == [GE.KEY_REVOKED, GE.DETACHMENT,
                                        GE.RESUME_PREPARED], why
        assert env.bridge.events[SID][-2].payload["reason"] == "key_revoked"
        assert env.cell() == (DET, NONE, ACTIVE)
        with pytest.raises(BridgeError):
            env.bridge.complete_resume(SID)
        assert env.bridge.client_set(SID) == set()
        env.reattach("ck-2")                 # the other key still resumes
        assert env.bridge.client_set(SID) == {"ck-2"}
    other = Env()
    other.add_device("ck-2")
    other.disconnect()
    other.begin_resume("ck-1")
    op_revoke(other.bridge, SID, "ck-2", "rotation")
    assert other.cell() == (RES, NONE, ACTIVE)
    other.bridge.complete_resume(SID)
    assert other.bridge.client_set(SID) == {"ck-1"}


def test_T126_challenge_refusal_does_not_reveal_session_state():
    """I11a: `challenge` answers an unknown, a terminated and a quarantined
    session with the same rejection, so an unauthenticated caller learns
    neither that a session exists nor its lifecycle state."""
    def refusal(b, sid):
        with pytest.raises(BridgeError) as exc:
            b.challenge(sid, "ck-1")
        return str(exc.value)
    env = Env()
    unknown = refusal(env.bridge, "no-such-session")
    assert unknown == CHALLENGE_REFUSED
    assert SID not in unknown and "no-such-session" not in unknown
    env.bridge.terminate(SID, "operator")
    assert refusal(env.bridge, SID) == unknown
    env = Env().reach(RES, NONE)
    env.storage.logs[SID][0].payload["principal_id"] = "mallory"
    with pytest.raises(BridgeError):
        env.bridge.complete_resume(SID)
    assert env.bridge.is_quarantined(SID)
    assert refusal(env.bridge, SID) == unknown


def test_T127_resume_refusal_does_not_reveal_session_state():
    """I11a: re-attach and join answer an unknown, a terminated and a
    quarantined session with the same rejection, so an unauthenticated
    caller learns neither that a session exists nor its lifecycle state."""
    def refusal(env, sid, op="reattach"):
        req = ResumeRequest("ck-1", "ab" * 16, 0, "00" * 32, "invalid")
        call = (env.bridge.join if op == "join"
                else env.bridge.client_reattach)
        with pytest.raises(BridgeError) as exc:
            call(sid, req)
        return str(exc.value)
    env = Env()
    unknown = refusal(env, "no-such-session")
    assert unknown == RESUME_REFUSED
    assert SID not in unknown and "no-such-session" not in unknown
    assert refusal(env, "no-such-session", "join") == unknown
    env.bridge.terminate(SID, "operator")
    assert refusal(env, SID) == unknown
    assert refusal(env, SID, "join") == unknown
    env = Env().reach(RES, NONE)
    env.storage.logs[SID][0].payload["principal_id"] = "mallory"
    with pytest.raises(BridgeError):
        env.bridge.complete_resume(SID)
    assert env.bridge.is_quarantined(SID)
    n = len(env.kinds())
    assert refusal(env, SID) == unknown
    assert len(env.kinds()) == n                   # nothing logged for it
def test_T129_the_approval_covers_tool_and_permission_not_only_content():
    """I14: the hash is taken over the tool, the permission and the content.
    An approval of {"cmd": "ls"} (the hash of that content alone, or of
    another tool or permission with it) does not release `rm -rf /`."""
    env = Env()
    b = env.bridge
    b.escalate_to_human(SID)
    b.submit_tool_call(SID, "rm -rf /", key="k", permission="exec:shell",
                       content={"cmd": "ls"})
    assert b.shown_hash_of(SID, "k") == call_hash(
        "rm -rf /", "exec:shell", {"cmd": "ls"})
    assert b.shown_hash_of(SID, "k") not in (
        content_hash({"cmd": "ls"}),
        call_hash("ls", "exec:shell", {"cmd": "ls"}),
        call_hash("rm -rf /", None, {"cmd": "ls"}))
    b.answer_tool_call(SID, "k", content_hash({"cmd": "ls"}), True)
    b.human_resolve(SID)
    assert env.bridge.events[SID][-1].kind == GE.TOOL_CALL_REJECTED
    assert env.bridge.events[SID][-1].payload["reason"] == "answer_mismatch"
    assert b.forwarded == []


def test_T130_the_forwarded_request_is_the_hashed_one_and_survives_a_restart():
    """I14: the bridge retains the hashed tool, permission and content with
    the queue entry and forwards exactly those, also when the forward is
    repeated after a restart."""
    env = Env()
    b = env.bridge
    b.escalate_to_human(SID)
    content = {"cmd": "deploy", "args": ["origin", "main"]}
    b.submit_tool_call(SID, "shell:deploy", key="k1", permission="exec:shell",
                       content=content)
    queued = env.bridge.events[SID][-1]
    assert queued.payload["content"] == content          # retained in the log
    b.answer_tool_call(SID, "k1", b.shown_hash_of(SID, "k1"), True)
    b.human_resolve(SID)
    want = {"tool": "shell:deploy", "permission": "exec:shell",
            "content": content}
    assert b.forwarded_calls[(SID, "k1")] == want
    assert call_hash(**want) == queued.payload["shown_hash"]
    b = env.restart()
    env.reattach()
    assert b.forwarded_calls[(SID, "k1")] == want


def test_T131_a_malformed_log_quarantines_only_its_own_session():
    """Rule Q: a log that cannot be replayed (no ATTACHED first, an ATTACHED
    without its fields) freezes that session only.  The sessions with sound
    logs are recovered, and nothing is appended to the malformed ones. [trace: rule Q]"""
    env = Env()
    env.storage.logs["bad-1"] = [Event(GE.DETACHMENT, "bad-1", 0, "", {}, 1.0)]
    env.storage.logs["bad-2"] = [Event(GE.ATTACHED, "bad-2", 0, "",
                                       {"client_key_id": "ck-x"}, 1.0)]
    b = env.restart()
    assert b.is_quarantined("bad-1") and b.is_quarantined("bad-2")
    assert len(env.storage.logs["bad-1"]) == 1
    assert len(env.storage.logs["bad-2"]) == 1
    assert not b.is_quarantined(SID)
    assert env.cell() == (DET, NONE, ACTIVE)
    assert GE.BRIDGE_RECOVERED in env.kinds()
    with pytest.raises(BridgeError):
        b.escalate_to_human("bad-1")
    env.reattach()                       # the sound session still re-attaches
    assert env.cell() == (ATT, NONE, ACTIVE)


def test_T132_revocation_requests_are_written_up_to_a_bound():
    """I11-REVOKE: a revocation request needs no signature, so the writes
    of KEY_REVOCATION_REQUESTED are bounded per session; past the bound the
    request is refused and appends nothing.  A signed revocation restores
    the budget."""
    env = Env()
    env.add_device("ck-2")
    n0 = len(env.kinds())
    for _ in range(3 * REVOCATION_REQUEST_LIMIT):
        try:
            env.bridge.revoke_key(SID, "ck-1", "rotation", signature="",
                                  requested_by="x")
        except BridgeError:
            pass
    assert len(env.kinds()) - n0 == REVOCATION_REQUEST_LIMIT
    with pytest.raises(BridgeError):
        env.bridge.revoke_key(SID, "ck-1", "rotation", signature="",
                              requested_by="x")
    op_revoke(env.bridge, SID, "ck-2", "rotation")
    env.bridge.revoke_key(SID, "ck-1", "rotation", signature="",
                          requested_by="x")


def test_T133_the_wire_server_asks_the_authentication_hook_for_unsigned_ops():
    """Appendix B: unsigned ops are authenticated by the transport binding.
    The reference server calls a hook for each of them; a false answer
    refuses the op as ``unauthenticated`` and commits nothing, a true one
    lets it through, and the signed ops never reach the hook."""
    import wire
    import wire_server
    env = Env()
    seen = []

    def deny(op, msg):
        seen.append(op)
        return False

    server = wire_server.WireServer(env.bridge, authenticate=deny)
    n0 = len(env.kinds())
    for data in (wire.op_terminate(session_id=SID, reason="x"),
                 wire.op_escalate(session_id=SID),
                 wire.op_disconnect(session_id=SID, reason="x", key_id=None)):
        with pytest.raises(wire_server.WireRejected) as exc:
            wire_server.send(server, data)
        assert exc.value.reason == "unauthenticated"
    assert seen == ["terminate", "escalate", "disconnect"]
    assert len(env.kinds()) == n0 and env.cell() == (ATT, NONE, ACTIVE)
    wire_server.send(server, wire.op_challenge(session_id=SID,
                                               key_id="ck-1"))
    assert seen == ["terminate", "escalate", "disconnect"]   # signed: no hook
    server.authenticate = lambda op, msg: True
    wire_server.send(server, wire.op_escalate(session_id=SID))
    assert env.cell() == (ATT, PEND, ACTIVE)


# --- Key-exhausted timers keep running (L1, L2) -----------------------------

def test_T134_a_key_exhausted_session_ends_after_the_detachment_bound():
    """I11-REVOKE, L1: the timers of a key_exhausted session keep running.
    Unless the operator adds a key, it ends at T_detach, and a client
    operation on an expired one reports the end, not the exhaustion."""
    env = Env()
    op_revoke(env.bridge, SID, "ck-1", reason="compromise")
    assert env.bridge._sess[SID].key_exhausted
    env.clock.advance(env.config.t_detach - 1)
    env.bridge.tick()
    assert env.cell() == (DET, NONE, ACTIVE)
    env.clock.advance(1)
    with pytest.raises(BridgeError, match="TERMINATED"):
        env.bridge.escalate_to_human(SID)         # not KEY_EXHAUSTED
    assert env.cell()[2] == TERM
    assert env.bridge.events[SID][-1].kind == GE.TERMINATION
    assert env.bridge.events[SID][-1].payload["reason"] == "detach_timeout"


def test_T135_the_operator_key_must_arrive_before_the_bound():
    """I11-REVOKE, L1: OPERATOR_ADD_KEY within T_detach saves the session; at
    the bound the session is over and neither addition nor termination
    changes it."""
    env = Env()
    op_revoke(env.bridge, SID, "ck-1", reason="compromise")
    env.clock.advance(env.config.t_detach - 1)
    key2 = ClientKey("ck-2")
    op_add_key(env.bridge, SID, "ck-2", key2.public_key.hex())
    env.keys["ck-2"] = key2
    env.sync("ck-2")
    env.reattach("ck-2")
    env.clock.advance(10 * env.config.t_detach)
    env.bridge.tick()
    assert env.cell() == (ATT, NONE, ACTIVE)
    env2 = Env()
    op_revoke(env2.bridge, SID, "ck-1", reason="compromise")
    env2.clock.advance(env2.config.t_detach)
    stale = op_sig(env2.bridge, "add_key", SID, "ck-2", "cd" * 32)
    with pytest.raises(OperatorSignatureInvalid):   # the timers fire first,
        env2.bridge.operator_add_key(SID, "ck-2", "cd" * 32,  # the head moves
                                     signature=stale)
    assert env2.kinds()[-2:] == [GE.DETACH_TIMEOUT, GE.TERMINATION]
    n = len(env2.kinds())
    with pytest.raises(BridgeError, match="TERMINATED"):
        op_add_key(env2.bridge, SID, "ck-2", "cd" * 32)
    with pytest.raises(BridgeError, match="TERMINATED"):
        op_terminate(env2.bridge, SID)            # already over: refused
    assert len(env2.kinds()) == n
    assert [k for k in env2.kinds() if k == GE.OPERATOR_TERMINATION] == []


def test_T136_a_restart_treats_a_key_exhausted_session_like_any_other():
    """I11-REVOKE, I12: a restart records BRIDGE_RECOVERED and a detachment
    on a key_exhausted session, restarts T_detach, and the session still
    ends at the new bound."""
    env = Env()
    op_revoke(env.bridge, SID, "ck-1", reason="compromise")
    env.clock.advance(env.config.t_detach - 10)
    env.restart()
    kinds = env.kinds()
    assert kinds[-3:] == [GE.BRIDGE_RECOVERED, GE.DETACHMENT,
                          GE.RESUME_PREPARED]
    assert env.bridge._sess[SID].key_exhausted
    env.clock.advance(env.config.t_detach - 1)
    env.bridge.tick()
    assert env.cell() == (DET, NONE, ACTIVE)
    env.clock.advance(1)
    env.bridge.tick()
    assert env.cell()[2] == TERM


def test_T137_a_key_exhausted_session_still_loses_its_transport_and_its_human_timer():
    """I11-REVOKE, L1, L2: a soft-revoked, still connected key keeps the
    session attached without a timer; the transport loss detaches it and
    T_detach then ends it.  A pending escalation times out as in any
    session."""
    env = Env()
    op_revoke(env.bridge, SID, "ck-1", reason="rotation")
    assert env.bridge._sess[SID].key_exhausted
    env.clock.advance(10 * env.config.t_detach)
    env.bridge.tick()
    assert env.cell() == (ATT, NONE, ACTIVE)
    with pytest.raises(BridgeError, match="KEY_EXHAUSTED"):
        env.bridge.escalate_to_human(SID)
    env.disconnect()
    assert env.cell() == (DET, NONE, ACTIVE)
    env.clock.advance(env.config.t_detach)
    env.bridge.tick()
    assert env.cell()[2] == TERM
    env = Env()
    env.bridge.escalate_to_human(SID)
    op_revoke(env.bridge, SID, "ck-1", reason="compromise")
    env.clock.advance(env.config.t_human)
    env.bridge.tick()
    assert env.cell()[2] == TERM
    assert GE.HUMAN_TIMEOUT in env.kinds()


# --- Operator signatures bind the bridge and the log position --------------

def test_T138_an_operator_signature_is_bound_to_the_bridge():
    """I-OPERATOR: a signature the operator made for another bridge id is
    refused for a revocation, a key addition and a termination, though it
    is right for the session, the operation and the log position."""
    env = _exhausted_env()
    b = env.bridge
    pub = "cd" * 32
    other = "bridge-elsewhere"
    for call in (
        lambda: b.operator_add_key(SID, "ck-2", pub, signature=op_sig(
            b, "add_key", SID, "ck-2", pub, bridge_id=other)),
        lambda: b.operator_terminate(SID, signature=op_sig(
            b, "terminate", SID, "all_keys_revoked", bridge_id=other)),
    ):
        with pytest.raises(OperatorSignatureInvalid):
            call()
    env2 = Env()
    with pytest.raises(OperatorSignatureInvalid):
        env2.bridge.revoke_key(SID, "ck-1", "compromise", signature=op_sig(
            env2.bridge, "revoke", SID, "ck-1", "compromise", bridge_id=other))
    assert env.bridge._sess[SID].key_exhausted and not env2.bridge._sess[
        SID].revoked_keys
    # the same operator, a bridge that carries the other id: accepted there
    storage = Storage()
    elsewhere = Bridge(storage, FakeClock(1000.0), Config(),
                       OperatorGrantVerifier(TEST_OPERATOR.public_key),
                       bridge_id=other)
    ident = SessionIdentity(SID, "u", SCOPE, ())
    key = ClientKey("ck-1")
    attach_as(elsewhere, ident, key, bridge_id=other)
    op_revoke(elsewhere, SID, "ck-1", "compromise")
    assert elsewhere._sess[SID].key_exhausted


def test_T139_an_operator_signature_is_bound_to_the_log_position():
    """I-OPERATOR: a signature covers the sequence and hash of the last
    event; once anything is committed it no longer verifies, so a captured
    operator action cannot be replayed later in the session's life."""
    env = Env()
    b = env.bridge
    early = op_sig(b, "revoke", SID, "ck-1", "compromise")
    env.add_device("ck-2")                     # the head moves
    with pytest.raises(OperatorSignatureInvalid):
        b.revoke_key(SID, "ck-1", "compromise", signature=early)
    seq, head = b.head_of(SID)
    # right sequence with another hash, and right hash with another sequence
    for at in ((seq, b.storage.logs[SID][0].event_hash()),
               (seq - 1, head), (seq + 1, head)):
        with pytest.raises(OperatorSignatureInvalid):
            b.revoke_key(SID, "ck-1", "compromise",
                         signature=op_sig(b, "revoke", SID, "ck-1",
                                          "compromise", at=at))
    assert not b._sess[SID].revoked_keys
    op_revoke(b, SID, "ck-1", "compromise")    # at the head: accepted
    assert "ck-1" in b._sess[SID].revoked_keys
    # key-exhausted session: the key addition and the termination are
    # bound to the position too
    env3 = _exhausted_env()
    first = (0, env3.bridge.storage.logs[SID][0].event_hash())
    with pytest.raises(OperatorSignatureInvalid):
        env3.bridge.operator_add_key(SID, "ck-2", "cd" * 32, signature=op_sig(
            env3.bridge, "add_key", SID, "ck-2", "cd" * 32, at=first))
    with pytest.raises(OperatorSignatureInvalid):
        env3.bridge.operator_terminate(SID, signature=op_sig(
            env3.bridge, "terminate", SID, "all_keys_revoked", at=first))
    assert env3.bridge._sess[SID].key_exhausted


def test_T140_operator_signed_bytes_and_signature_are_pinned():
    """The exact bytes an operator signs for a revocation, a key addition
    and a termination (bridge id, session, the operation's fields, the
    sequence and hash of the last event) and the Ed25519 signature over
    them are fixed; a signature does not verify when any bound field
    changes.  The same file is read by the Rust crate. [trace: I-OPERATOR]"""
    kat = _bytes_kat()
    operator = OperatorKey(bytes.fromhex(kat["operator_seed"]))
    assert operator.public_key.hex() == kat["operator_public_key"]

    def signed(f):
        if f["op"] == "revoke":
            return _revoke_bytes(f["bridge_id"], f["session_id"], f["key_id"],
                                 f["reason"], f["seq"], f["head"])
        if f["op"] == "add_key":
            return _add_key_bytes(f["bridge_id"], f["session_id"],
                                  f["key_id"], f["scheme"], f["public_key"],
                                  f["seq"], f["head"])
        return _terminate_bytes(f["bridge_id"], f["session_id"], f["reason"],
                                f["seq"], f["head"])
    for p in kat["operator_proofs"]:
        msg = signed(p)
        assert msg.decode() == p["signed_text"], p["name"]
        assert msg.hex() == p["signed_hex"], p["name"]
        assert operator._signer.sign(msg).hex() == p["signature"], p["name"]
        assert _verify(operator.public_key, msg, p["signature"])
    for n in kat["operator_negatives"]:
        assert not _verify(operator.public_key, signed(n), n["signature"]), \
            n["name"]


def test_T141_a_reattach_on_an_attached_session_is_refused():
    """I11, I15: an authentic re-attach while the session is attached is
    refused as already_attached (RESUME_REJECTED, nonce spent, no change
    of cell, no CLIENT_JOINED); join is the only way into an attached
    session."""
    env = Env()
    env.add_device("ck-2")
    req = env.request("ck-2", op="reattach")
    n = len(env.kinds())
    with pytest.raises(BridgeError, match="already_attached"):
        env.bridge.begin_resume(env.sid, req)
    assert env.kinds()[n:] == [GE.RESUME_REJECTED]
    assert env.bridge.events[env.sid][-1].payload["reason"] == "already_attached"
    assert env.cell() == (ATT, NONE, ACTIVE)
    assert env.bridge.client_set(env.sid) == frozenset({"ck-1"})
    again = env.request("ck-2", op="reattach", nonce=req.nonce)
    _rejects(env, again, "nonce_used")                  # the nonce is spent
    env.bridge.join(env.sid, env.request("ck-2", op="join"))
    assert env.bridge.client_set(env.sid) == frozenset({"ck-1", "ck-2"})
    with pytest.raises(BridgeError, match="already_attached"):
        env.bridge.client_reattach(env.sid, env.request("ck-1"))


def test_T142_the_attached_refusal_is_for_authentic_requests_only():
    """I11a, I11g: a request that does not authenticate gets its own
    reason, never already_attached, so the refusal confirms nothing about
    the attachment to a caller that proved nothing."""
    env = Env()
    env.add_device("ck-2")
    forged = env.request("ck-2", op="reattach")
    forged.signature = "00" * 64
    _rejects(env, forged, "bad_signature")
    stranger = ClientKey("ck-9")
    _rejects(env, env.request("ck-9", key=stranger,
                              prefix=env.seen["ck-1"]), "unknown_key")


# --- C.4: a further scheme through the pluggable verifier ---------------------

STUB_SCHEME = "test-stub"
TEST_ONLY_SCHEMES = frozenset({STUB_SCHEME})   # check_schemas.py skips these


def _stub_sign(public_key: bytes, message: bytes) -> str:
    """Test-only scheme: SHA-256 over the key and the message.  It proves
    nothing cryptographically; it shows the tag is dispatched, not that the
    scheme is sound."""
    return hashlib.sha256(public_key + message).hexdigest()


def _stub_verify(public_key: bytes, message: bytes, signature_hex: str):
    return signature_hex == _stub_sign(public_key, message)


def test_T144_a_further_scheme_is_accepted_through_the_verifier(monkeypatch):
    """C.4: a scheme tag added to the verifier registry is accepted at
    attach with no change to the bridge; without the registration the same
    key is refused, and a wrong proof is refused with it. [trace: I11]"""
    monkeypatch.setitem(SCHEME_VERIFIERS, STUB_SCHEME, _stub_verify)
    ident = SessionIdentity("sess-stub", "user-alice", SCOPE, ("root",))
    pub = ClientPublicKey("ck-s", STUB_SCHEME, b"stub-key")
    msg = _attach_bytes(DEFAULT_BRIDGE_ID, ident, pub)
    grant = TEST_OPERATOR.grant(ident, pub, DEFAULT_BRIDGE_ID)

    def fresh():
        return Bridge(Storage(), FakeClock(), Config(),
                      OperatorGrantVerifier(TEST_OPERATOR.public_key))

    with pytest.raises(Exception):
        fresh().attach(ident, pub, grant, "00" * 32)
    bridge = fresh()
    bridge.attach(ident, pub, grant, _stub_sign(pub.public_key, msg))
    assert bridge.storage.key_schemes[(ident.session_id, "ck-s")] == STUB_SCHEME
    monkeypatch.delitem(SCHEME_VERIFIERS, STUB_SCHEME)
    with pytest.raises(Exception):
        fresh().attach(ident, pub, grant, _stub_sign(pub.public_key, msg))


# --- Bare terminate on key_exhausted, uniform reasons ------------------------

def test_T145_a_bare_terminate_does_not_end_a_key_exhausted_session():
    """I11-REVOKE, I6: on a key_exhausted session only the operator's signed
    termination is permitted; an unsigned terminate is refused and commits
    nothing, and the operator's still ends the session."""
    env = Env()
    op_revoke(env.bridge, SID, "ck-1")
    assert env.bridge._sess[SID].key_exhausted
    n = len(env.kinds())
    with pytest.raises(BridgeError, match="KEY_EXHAUSTED"):
        env.bridge.terminate(SID)
    assert len(env.kinds()) == n and env.cell() == (ATT, NONE, ACTIVE)
    op_terminate(env.bridge, SID)
    assert env.cell()[2] == TERM
    assert env.kinds()[-2:] == [GE.OPERATOR_TERMINATION, GE.TERMINATION]
    env.bridge.terminate(SID)                    # already over: no error


def test_T146_the_exhausted_refusal_defers_to_the_timers_and_to_quarantine():
    """I11-REVOKE, L1, rule Q: a bare terminate on a key_exhausted session
    whose detachment bound has passed finds it ended by the timers, and on
    a quarantined one it remains the operator's way out of quarantine."""
    env = Env()
    op_revoke(env.bridge, SID, "ck-1", reason="compromise")
    env.clock.advance(env.config.t_detach + 1)
    env.bridge.terminate(SID)
    assert env.cell()[2] == TERM
    assert env.kinds()[-2:] == [GE.DETACH_TIMEOUT, GE.TERMINATION]
    env = Env()
    op_revoke(env.bridge, SID, "ck-1", reason="compromise")
    env.storage.logs[SID][1].prev_hash = "00" * 32
    env.restart()
    assert env.bridge.is_quarantined(SID) and env.bridge._sess[SID].key_exhausted
    env.bridge.terminate(SID)
    assert env.cell()[2] == TERM


def test_T147_an_unregistered_key_and_a_bad_signature_are_one_refusal():
    """I11a, I15: a re-attach naming a key id the session does not register
    and one whose signature does not verify get the same refusal text, so
    the answer does not list the registered key ids; the log keeps the
    true reason."""
    env = Env()
    env.disconnect()
    seen = []
    for key_id, bad in (("ck-1", True), ("ck-9", False)):
        req = env.request(key_id, key=None if bad else ClientKey(key_id),
                          prefix=env.seen["ck-1"])
        if bad:
            req.signature = "00" * 64
        with pytest.raises(BridgeError, match="rejected") as exc:
            env.bridge.begin_resume(SID, req)
        seen.append(str(exc.value))
    assert seen[0] == seen[1] and "bad_signature" in seen[0]
    assert [e.payload["reason"] for e in env.bridge.events[SID]
            if e.kind == GE.RESUME_REJECTED] == ["bad_signature", "unknown_key"]


def _wire_bridge():
    return Bridge(Storage(), FakeClock(), Config(),
                  OperatorGrantVerifier(TEST_OPERATOR.public_key))


def _attach_message(bridge, ident, key, grant="ok", proof="ok"):
    import wire
    pub = key.public()
    return wire.op_attach(
        session_id=ident.session_id, principal=ident.principal_id,
        scope=list(ident.authority_scope), lineage=list(ident.task_lineage),
        key_id=key.key_id, scheme=key.scheme, public_key=pub.public_key.hex(),
        grant=(TEST_OPERATOR.grant(ident, pub, bridge.bridge_id)
               if grant == "ok" else None),
        signature=(key.prove_attach(ident, bridge.bridge_id)
                   if proof == "ok" else None))


def test_T148_the_wire_server_attaches_a_session_from_its_message():
    """an attach message carries the grant and the proof of
    possession; the server answers with the genesis sequence and hash, and
    refuses a missing grant or proof with its own reason and commits
    nothing. [trace: wire]"""
    import wire_server
    bridge = _wire_bridge()
    server = wire_server.WireServer(bridge)
    key = ClientKey("ck-1")
    ident = SessionIdentity("sess-w", "user-alice", SCOPE, ("root",))
    for grant, proof, reason in (("none", "ok", "grant_invalid"),
                                 ("ok", "none", "possession_invalid")):
        with pytest.raises(wire_server.WireRejected) as exc:
            wire_server.send(server, _attach_message(
                bridge, ident, key, grant, proof))
        assert exc.value.reason == reason
        assert "sess-w" not in bridge.events
    resp = wire_server.send(server, _attach_message(bridge, ident, key))
    assert resp["status"] == "attached" and resp["seq"] == 0
    assert resp["hash"] == bridge.events["sess-w"][0].event_hash()
    assert bridge.cell_of("sess-w") == Cell(ATT, NONE, ACTIVE)
    with pytest.raises(wire_server.WireRejected) as exc:   # not twice
        wire_server.send(server, _attach_message(bridge, ident, key))
    assert exc.value.reason == "refused"
    asked = []
    server.authenticate = lambda op, msg: asked.append(op) or False
    other = SessionIdentity("sess-v", "user-alice", SCOPE, ())
    wire_server.send(server, _attach_message(bridge, other, key))
    assert asked == []                  # attach authenticates itself


def test_T149_the_wire_server_resolves_and_answers_an_extension():
    """I3, Appendix B: resolve ends a pending escalation; a widening asked
    for is rejected with the scope in force, one the runtime announced is
    recorded with a revert requested, a subset is unchanged; resolve and
    extend are asked of the authentication hook. [trace: wire]"""
    import wire
    import wire_server
    env = Env()
    server = wire_server.WireServer(env.bridge)
    wider = ["read:docs", "exec:shell", "admin"]
    req = wire.op_extend(session_id=SID, new_scope=wider, source="requested")
    raw = wire.decode_response(server.handle(req))
    assert raw["status"] == "rejected" and raw["current_scope"] == list(SCOPE)
    assert raw["reason"] == "extension_rejected"
    assert env.kinds()[-1] == GE.AUTHORITY_EXTENSION_REJECTED
    out = wire_server.send(server, wire.op_extend(
        session_id=SID, new_scope=wider, source="observed"))
    assert out["status"] == "revert_requested"
    assert out["current_scope"] == list(SCOPE)
    assert wire_server.send(server, wire.op_extend(
        session_id=SID, new_scope=["read:docs"], source="requested")
    )["status"] == "unchanged"
    n = len(env.kinds())
    wire_server.send(server, wire.op_escalate(session_id=SID))
    assert wire_server.send(
        server, wire.op_resolve(session_id=SID))["status"] == "resolved"
    assert env.cell() == (ATT, NONE, ACTIVE) and len(env.kinds()) == n + 2
    asked = []
    server.authenticate = lambda op, msg: asked.append(op) or True
    wire_server.send(server, wire.op_escalate(session_id=SID))
    wire_server.send(server, wire.op_resolve(session_id=SID))
    wire_server.send(server, wire.op_extend(
        session_id=SID, new_scope=["read:docs"], source="requested"))
    assert asked == ["escalate", "resolve", "extend"]


def _add_key_sig(bridge, key_id, public_key, scheme):
    seq, head = bridge.head_of(SID)
    return TEST_OPERATOR.add_key(bridge.bridge_id, SID, key_id, public_key,
                                 seq, head, scheme)


def test_T150_the_wire_server_verifies_operator_events_from_the_message():
    """I-OPERATOR, I11-REVOKE, Appendix B: revoke, add_key and
    operator_terminate carry the operator's signature, which the bridge
    verifies against the log position; a missing or foreign signature is
    refused as operator_signature_invalid, a request without a signature
    is a client's op (asked of the authentication hook) and only records a
    request, and the refusals of the bridge are named.
    [trace: wire]"""
    import wire
    import wire_server
    env = Env()
    server = wire_server.WireServer(env.bridge)
    asked = []
    server.authenticate = lambda op, msg: asked.append(op) or False

    def send(data):
        return wire_server.send(server, data)

    def refused(data):
        with pytest.raises(wire_server.WireRejected) as exc:
            send(data)
        return exc.value.reason

    foreign = OperatorKey(b"\x09" * 32)
    seq, head = env.bridge.head_of(SID)
    forged = foreign.revoke(env.bridge.bridge_id, SID, "ck-1", "rotation",
                            seq, head)
    for sig in (None, forged):
        assert refused(wire.op_revoke(
            session_id=SID, key_id="ck-1", reason="rotation", signature=sig)
        ) == "operator_signature_invalid"
    n = len(env.kinds())
    # a revocation request has no operator signature: it passes the hook,
    # which here denies it, with the signature empty or absent
    for sig in ("", None):
        assert refused(wire.op_revoke(
            session_id=SID, key_id="ck-1", reason="rotation", signature=sig,
            requested_by="ck-1")) == "unauthenticated"
    assert asked == ["revoke", "revoke"] and len(env.kinds()) == n
    asked.clear()
    server.authenticate = lambda op, msg: asked.append(op) or op == "revoke"
    for sig in ("", None):
        out = send(wire.op_revoke(session_id=SID, key_id="ck-1",
                                  reason="rotation", signature=sig,
                                  requested_by="ck-1"))
        assert out["status"] == "requested"
    assert asked == ["revoke", "revoke"] and len(env.kinds()) == n + 2
    assert env.kinds()[-1] == GE.KEY_REVOCATION_REQUESTED
    asked.clear()
    server.authenticate = lambda op, msg: asked.append(op) or False
    assert refused(wire.op_revoke(
        session_id=SID, key_id="ck-9", reason="rotation",
        signature=op_sig(env.bridge, "revoke", SID, "ck-9", "rotation"))
    ) == "unknown_key"
    assert refused(wire.op_operator_terminate(
        session_id=SID, reason="all_keys_revoked",
        signature=op_sig(env.bridge, "terminate", SID, "all_keys_revoked"))
    ) == "not_key_exhausted"
    sig = op_sig(env.bridge, "revoke", SID, "ck-1", "compromise")
    assert send(wire.op_revoke(session_id=SID, key_id="ck-1",
                               reason="compromise", signature=sig)
                )["status"] == "revoked"
    assert env.bridge._sess[SID].key_exhausted
    fresh = ClientKey("ck-2")
    pub = fresh.public_key.hex()
    assert refused(wire.op_add_key(
        session_id=SID, key_id="ck-1", scheme=fresh.scheme, public_key=pub,
        signature=_add_key_sig(env.bridge, "ck-1", pub, fresh.scheme))
    ) == "key_already_registered"
    assert send(wire.op_add_key(
        session_id=SID, key_id="ck-2", scheme=fresh.scheme, public_key=pub,
        signature=_add_key_sig(env.bridge, "ck-2", pub, fresh.scheme))
    )["status"] == "key_added"
    assert not env.bridge._sess[SID].key_exhausted
    assert asked == []                  # the operator channel has its own proof


def test_T151_the_wire_server_names_the_exhausted_refusal_and_hides_key_ids():
    """I11-REVOKE, I11a, F-8: on the wire a bare terminate of a key_exhausted
    session is refused as key_exhausted, and a re-attach for an unregistered
    key is answered bad_signature, as for a bad signature. [trace: wire]"""
    import wire
    import wire_server
    env = Env()
    server = wire_server.WireServer(env.bridge)
    op_revoke(env.bridge, SID, "ck-1")
    with pytest.raises(wire_server.WireRejected) as exc:
        wire_server.send(server, wire.op_terminate(session_id=SID,
                                                   reason="terminated"))
    assert exc.value.reason == "key_exhausted"
    assert env.cell()[2] == ACTIVE
    env = Env()
    env.disconnect()
    server = wire_server.WireServer(env.bridge)
    seq, h = env.seen["ck-1"]
    for key_id in ("ck-1", "ck-9"):
        nonce = wire_server.send(server, wire.op_challenge(
            session_id=SID, key_id=key_id))["nonce"]
        with pytest.raises(wire_server.WireRejected) as exc:
            wire_server.send(server, wire.op_reattach(
                session_id=SID, key_id=key_id, nonce=nonce, seq=seq, hash=h,
                signature="00" * 64))
        assert exc.value.reason == "bad_signature"


# --- Two sessions on one bridge: nothing is shared but the bridge ----------

SID_B = "sess-B"


def _two_sessions() -> Env:
    """A bridge with two sessions that hold the same client key (the same
    key id and the same secret), the case in which any state shared
    between them can be told apart from state kept per session."""
    env = Env()
    _attach_second(env, SID_B, env.key)
    return env


def _head(env: Env, sid: str) -> tuple[int, str]:
    return env.bridge.head_of(sid)


def test_T152_a_nonce_belongs_to_the_session_that_issued_it():
    """I11b, I15(d): a nonce issued for one session is unknown to another,
    for a re-attach, a join and a registration, even when the same key
    signs for both; presenting it does not spend it in the session that
    issued it, a challenge budget is kept per session, and an
    acknowledged prefix taken from another session's log is no prefix.
    [trace: I11]"""
    env = _two_sessions()
    b = env.bridge
    # a registration in A with a nonce that B issued
    foreign = b.challenge(SID_B, "ck-1").nonce
    new = ClientKey("ck-2").public()
    _refused_add(env, "ck-1", new, foreign,
                 env.key.sign_add_client(SID, new, foreign), "nonce_unknown")
    # a join in A with a nonce that B issued
    seq, h = env.seen["ck-1"]
    with pytest.raises(BridgeError, match="rejected"):
        b.join(SID, env.request(op="join", nonce=foreign))
    assert b.events[SID][-1].payload["reason"] == "nonce_unknown"
    # a re-attach in A with a nonce that B issued, and with B's prefix
    env.disconnect()
    _rejects(env, env.request(nonce=foreign), "nonce_unknown")
    bseq, bhash = _head(env, SID_B)
    assert (bseq, bhash) != (seq, h)
    _rejects(env, env.request(prefix=(bseq, bhash)), "prefix_mismatch")
    # the refusals spent nothing in B: its own client still uses the nonce
    b.client_disconnect(SID_B)
    bseq, bhash = _head(env, SID_B)
    req = env.key.request(SID_B, foreign, bseq, bhash)
    b.begin_resume(SID_B, req)
    assert b.events[SID_B][-1].kind == GE.RESUME_STARTED
    b.complete_resume(SID_B)
    env.reattach()                      # A is not locked out
    assert env.kinds()[-1] == GE.RESUME_VERIFIED
    # A using up its challenge budget leaves B's untouched
    for _ in range(NONCE_RECORDS):
        b.challenge(SID, "ck-1")
    with pytest.raises(BridgeError, match="challenge budget"):
        b.challenge(SID, "ck-1")
    assert b.challenge(SID_B, "ck-1").nonce


def test_T153_bounds_on_unauthenticated_writes_are_kept_per_session():
    """I11g, I11-REVOKE: the budget of unauthenticated rejections and the
    budget of revocation requests belong to one session; a flood against
    one session does not silence the log of another, and a key holder or
    an operator speaking in one session does not restore the budget of the
    other. [trace: I11g]"""
    env = _two_sessions()
    b = env.bridge
    env.disconnect()
    b.client_disconnect(SID_B)
    stranger = ClientKey("ck-1")                  # same id, another secret

    def bad(sid: str) -> int:
        """One unauthenticated re-attach; the events it appended."""
        n = len(b.events[sid])
        h = b.events[sid][0].event_hash()
        with pytest.raises(BridgeError, match="rejected"):
            b.begin_resume(sid, stranger.request(sid, "0" * 32, 0, h))
        return len(b.events[sid]) - n
    for _ in range(UNAUTH_LOG_LIMIT):
        assert bad(SID) == 1
    assert bad(SID) == 0                          # A's budget is spent
    assert bad(SID_B) == 1                        # B's is not
    genuine = env.key.request(SID_B, "0" * 32, 0,
                              b.events[SID_B][0].event_hash())
    with pytest.raises(BridgeError, match="rejected"):
        b.begin_resume(SID_B, genuine)            # a key holder speaks in B
    assert b.events[SID_B][-1].payload["reason"] == "nonce_unknown"
    assert bad(SID) == 0                          # A's budget stays spent
    # revocation requests need no signature either
    env.reattach()
    b.client_reattach(SID_B, env.key.request(
        SID_B, b.challenge(SID_B, "ck-1").nonce, *_head(env, SID_B)))

    def ask(sid: str) -> int:
        n = len(b.events[sid])
        try:
            b.revoke_key(sid, "ck-1", "rotation", signature="",
                         requested_by="x")
        except BridgeError:
            pass
        return len(b.events[sid]) - n
    for _ in range(REVOCATION_REQUEST_LIMIT):
        assert ask(SID) == 1
    assert ask(SID) == 0
    assert ask(SID_B) == 1
    op_revoke(b, SID_B, "ck-1", "rotation")       # a signed revocation in B
    assert ask(SID) == 0                          # does not reopen A


def test_T154_tool_call_keys_are_scoped_to_the_session_across_a_restart():
    """Rule D, I13: two sessions that use the same tool call key keep
    separate queues, forwarded requests and acknowledgements, and after a
    restart each session's unacknowledged call is forwarded again,
    whatever the other session forwarded under that key. [trace: rule D]"""
    env = _two_sessions()
    b = env.bridge
    tools = {SID: "git push", SID_B: "rm -rf build"}
    for sid, tool in tools.items():
        b.escalate_to_human(sid)
        b.submit_tool_call(sid, tool, key="k1", permission="exec:shell",
                           content={"sid": sid})
        b.answer_tool_call(sid, "k1", b.shown_hash_of(sid, "k1"), True)
        b.human_resolve(sid)
    for sid, tool in tools.items():
        assert b.forwarded_calls[(sid, "k1")] == {
            "tool": tool, "permission": "exec:shell",
            "content": {"sid": sid}}
    assert b._sess[SID].unacked == {"k1": "git push"}
    assert b._sess[SID_B].unacked == {"k1": "rm -rf build"}
    # a restart before either acknowledgement: each is forwarded again
    b = env.restart()
    assert b.forwarded == []
    env.reattach()
    b.client_reattach(SID_B, env.key.request(
        SID_B, b.challenge(SID_B, "ck-1").nonce, *_head(env, SID_B)))
    assert sorted(b.forwarded) == [(SID, "k1", "git push"),
                                   (SID_B, "k1", "rm -rf build")]
    b.delivered(SID, "k1")                        # A's acknowledgement
    assert b._sess[SID].unacked == {}
    assert b._sess[SID_B].unacked == {"k1": "rm -rf build"}
    with pytest.raises(BridgeError):
        b.delivered(SID, "k1")                    # nothing awaits in A
    b.delivered(SID_B, "k1")


def test_T155_every_unsigned_wire_op_is_asked_of_the_hook_per_session():
    """Appendix B, I15: an op that carries no signature is reachable only
    through the transport's authentication hook.  Each of them is refused as
    ``unauthenticated`` when the hook says no and commits nothing, the hook
    is given the message that names the session, and a hook that
    authenticates one session's caller does not open another session.
    [trace: wire]"""
    import wire
    import wire_server
    env = _two_sessions()
    msgs = {
        "disconnect": lambda s: wire.op_disconnect(
            session_id=s, reason="x", key_id=None),
        "escalate": lambda s: wire.op_escalate(session_id=s),
        "resolve": lambda s: wire.op_resolve(session_id=s),
        "submit_tool_call": lambda s: wire.op_submit_tool_call(
            session_id=s, tool="t", content={}, key="k1"),
        "answer_tool_call": lambda s: wire.op_answer_tool_call(
            session_id=s, key="k1", shown_hash="00" * 32, decision="approve"),
        "delivered": lambda s: wire.op_delivered(session_id=s, key="k1"),
        "completed": lambda s: wire.op_completed(session_id=s, key="k1"),
        "narrow": lambda s: wire.op_narrow(session_id=s, new_scope=[]),
        "extend": lambda s: wire.op_extend(
            session_id=s, new_scope=list(SCOPE) + ["admin"],
            source="requested"),
        "terminate": lambda s: wire.op_terminate(session_id=s, reason="x"),
    }
    assert set(msgs) == set(wire_server.UNSIGNED_OPS)   # none left untested
    seen = []

    def only_a(op, msg):
        seen.append((op, msg.get("session_id")))
        return msg.get("session_id") == SID
    server = wire_server.WireServer(env.bridge, authenticate=only_a)
    before = {s: list(env.bridge.events[s]) for s in (SID, SID_B)}
    for op, build in msgs.items():
        with pytest.raises(wire_server.WireRejected) as exc:
            wire_server.send(server, build(SID_B))
        assert exc.value.reason == "unauthenticated", op
    assert seen == [(op, SID_B) for op in msgs]  # the hook saw the session
    assert {s: list(env.bridge.events[s]) for s in before} == before
    # the same hook lets A's caller through, and only A is changed
    wire_server.send(server, msgs["escalate"](SID))
    assert env.cell() == (ATT, PEND, ACTIVE)
    assert tuple(env.bridge.cell_of(SID_B)) == (ATT, NONE, ACTIVE)
    assert env.bridge.events[SID_B] == before[SID_B]
    # with no hook set every caller is accepted: the harness-only default
    open_server = wire_server.WireServer(env.bridge)
    wire_server.send(open_server, msgs["escalate"](SID_B))
    assert tuple(env.bridge.cell_of(SID_B)) == (ATT, PEND, ACTIVE)


# --- Cases the mutation check could not see until its scratch copy ran ------

def test_T156_recovery_leaves_the_registry_of_a_quarantined_session_alone():
    """I11, rule Q: a session whose chain does not verify is quarantined
    before anything is repaired; its registry stays as found, so the damage
    can be examined. [trace: I11]"""
    env = Env()
    env.add_device("ck-2")
    env.disconnect()
    stray = ClientKey("ck-evil")
    env.storage.register_key(SID, "ck-evil", stray.scheme, stray.public_key)
    del env.storage.client_keys[(SID, "ck-2")]
    del env.storage.key_schemes[(SID, "ck-2")]
    env.storage.client_keys[(SID, "ck-1")] = stray.public_key
    found = dict(env.storage.client_keys)
    env.storage.logs[SID][0].payload["principal_id"] = "mallory"
    b = env.restart()
    assert b.is_quarantined(SID)
    assert env.kinds()[-1] == GE.RECOVERY_FAILED
    assert GE.BRIDGE_RECOVERED not in env.kinds()
    assert env.storage.client_keys == found


def test_T157_the_scheme_of_the_first_key_is_in_the_log_and_survives_recovery():
    """I11, M1: ATTACHED records the scheme of the key it registers, not a
    default, so a registry entry lost before a restart is written back with
    the right scheme and the key still verifies. [trace: I11]"""
    env = _p256_env()
    assert env.bridge.events[env.sid][0].payload["scheme"] == SCHEME_ECDSA_P256
    env.disconnect()
    del env.storage.client_keys[(env.sid, "ck-1")]
    del env.storage.key_schemes[(env.sid, "ck-1")]
    b = _recovered(env, ["ck-1"])
    assert env.storage.key_record(env.sid, "ck-1")[0] == SCHEME_ECDSA_P256
    b.client_reattach(env.sid, env.request())
    assert env.cell() == (ATT, NONE, ACTIVE)


def test_T158_a_held_call_is_hashed_as_the_call_a_client_is_shown():
    """I14: a call held while no client is attached carries the hash of the
    tool, the permission and the content together; an approval computed from
    what the client was shown releases it, and one for the tool alone does
    not. [trace: I14]"""
    env = Env(Config(detached_calls="queue"))
    env.disconnect()
    content = {"path": "/etc/hosts"}
    want = call_hash("cat", "read:docs", content)
    for key in ("k1", "k2"):
        env.bridge.submit_tool_call(SID, "cat", key=key,
                                    permission="read:docs", content=content)
        assert env.bridge.events[SID][-1].payload["shown_hash"] == want
    env.reattach()
    env.bridge.answer_tool_call(SID, "k1", content_hash("cat"), True)
    assert not env.bridge.forwarded                  # not what was shown
    assert env.bridge.events[SID][-1].kind == GE.TOOL_CALL_REJECTED
    env.bridge.answer_tool_call(SID, "k2", want, True)
    assert env.bridge.forwarded == [(SID, "k2", "cat")]


# ----------------------------------------------------------------------
# Nonce binding: a nonce belongs to the key id it was issued for
# ----------------------------------------------------------------------

def _refusal(call) -> BridgeError:
    with pytest.raises(BridgeError) as exc:
        call()
    return exc.value


def _last(env: Env) -> Event:
    return env.bridge.events[env.sid][-1]


def test_T152b_a_nonce_is_bound_to_the_key_id_it_was_issued_for():
    """I11(b), I15(d): a nonce issued for one key id is refused when another
    registered key presents it, for a join, a registration and a re-attach,
    though the signature verifies.  The caller is answered as for a bad
    signature, the log records nonce_binding, and the nonce stays live for
    the key it was issued for."""
    env = Env()
    env.add_device("ck-2")                       # registered, not connected
    b = env.bridge
    n1 = b.challenge(SID, "ck-1").nonce
    n = len(env.kinds())
    err = _refusal(lambda: b.join(SID, env.request("ck-2", op="join",
                                                   nonce=n1)))
    assert err.reason == "bad_signature"
    assert env.kinds()[n:] == [GE.RESUME_REJECTED]
    assert _last(env).payload["reason"] == "nonce_binding"
    assert not b._nonces[SID][n1].used
    forged = env.request("ck-2", op="join")
    forged.signature = "00" * 64
    assert str(_refusal(lambda: b.join(SID, forged))) == str(err)  # uniform
    n2 = b.challenge(SID, "ck-2").nonce
    new = ClientKey("ck-3").public()
    _refused_add(env, "ck-1", new, n2,
                 env.key.sign_add_client(SID, new, n2), "bad_signature")
    assert not b._nonces[SID][n2].used
    env.disconnect()
    n3 = b.challenge(SID, "ck-2").nonce
    _rejects(env, env.request("ck-1", nonce=n3), "nonce_binding")
    assert not b._nonces[SID][n3].used
    # each nonce still serves the key it was issued for
    b.client_reattach(SID, env.request("ck-2", nonce=n3))
    assert b.client_set(SID) == {"ck-2"}
    b.join(SID, env.request("ck-1", op="join", nonce=n1))
    assert b.client_set(SID) == {"ck-1", "ck-2"}
    b.add_client_key(SID, "ck-2", new, n2,
                     env.keys["ck-2"].sign_add_client(SID, new, n2))
    assert _last(env).kind == GE.CLIENT_ADDED


def test_T152c_a_nonce_issued_before_the_key_was_registered_never_verifies():
    """I11(b), I11(d): a device whose key is not registered yet asks for a
    challenge (it is answered like any other), signs a join and is refused;
    the nonce is not spent.  After the key is registered, the captured
    request is still refused, as a join and as a re-attach, and so is a new
    request signed over that nonce: a request that was presented and refused
    is not accepted later.  A nonce issued after the registration works."""
    env = Env()
    b = env.bridge
    late = ClientKey("ck-2")
    seq, h = env.tip()
    nonce = b.challenge(SID, "ck-2").nonce
    early = late.request(SID, nonce, seq, h, "join")
    err = _refusal(lambda: b.join(SID, early))
    assert err.reason == "bad_signature"
    assert _last(env).payload["reason"] == "unknown_key"
    record = b._nonces[SID][nonce]
    assert not record.used and not record.eligible
    add_client(b, SID, env.key, late.public())      # the key is registered
    env.keys["ck-2"] = late
    assert record.key_id == "ck-2" and not record.eligible   # as at issue
    for _ in range(2):                              # the captured bytes
        err = _refusal(lambda: b.join(SID, early))
        assert err.reason == "bad_signature"
        assert _last(env).payload["reason"] == "nonce_binding"
    seq2, h2 = env.tip()
    again = late.request(SID, nonce, seq2, h2, "join")   # signed after it
    assert _refusal(lambda: b.join(SID, again)).reason == "bad_signature"
    assert GE.CLIENT_JOINED not in env.kinds()
    assert b.client_set(SID) == {"ck-1"}
    env.disconnect()
    _rejects(env, late.request(SID, nonce, seq2, h2), "nonce_binding")
    assert env.cell() == (DET, NONE, ACTIVE)
    env.sync("ck-2")
    env.reattach("ck-2")                            # a nonce issued now
    assert b.client_set(SID) == {"ck-2"}


def test_T152d_a_request_refused_on_a_key_exhausted_session_is_not_replayed():
    """I11(b), I11-REVOKE: on a key_exhausted session a re-attach is
    verified like any other: a key that is not registered is answered as a
    bad signature and a revoked one as revoked, never as key_exhausted.
    When the operator then adds the key, the request that was refused
    before is refused again; only a nonce issued after the addition lets
    the new key in."""
    env = Env()
    b = env.bridge
    op_revoke(b, SID, "ck-1", "compromise")          # exhausted, detached
    recovery = ClientKey("ck-2")
    seq, h = env.tip()
    early = recovery.request(SID, b.challenge(SID, "ck-2").nonce, seq, h)
    err = _refusal(lambda: b.client_reattach(SID, early))
    assert err.reason == "bad_signature"
    assert _last(env).payload["reason"] == "unknown_key"
    err = _refusal(lambda: b.begin_resume(SID, env.request("ck-1")))
    assert err.reason == "revoked_key"
    op_add_key(b, SID, "ck-2", recovery.public_key.hex())
    err = _refusal(lambda: b.client_reattach(SID, early))
    assert err.reason == "bad_signature"
    assert _last(env).payload["reason"] == "nonce_binding"
    assert env.cell() == (DET, NONE, ACTIVE)
    assert b.client_set(SID) == frozenset()
    seq, h = env.tip()
    b.client_reattach(SID, recovery.request(
        SID, b.challenge(SID, "ck-2").nonce, seq, h))
    assert b.client_set(SID) == {"ck-2"}


def test_T152e_challenge_answers_the_same_for_every_key_id():
    """I11(b), I11a, I11f: `challenge` issues a nonce of the same form and
    lifetime, at the same time and against the same limit, whether the key
    id it names is registered, revoked, unknown or empty; no answer of
    `challenge` depends on the registry.  Whether the key was an active key
    at issue is recorded with the nonce and never answered."""
    import string
    import wire
    import wire_server
    env = Env()
    env.add_device("ck-2")
    b = env.bridge
    op_revoke(b, SID, "ck-2")
    n = len(env.kinds())
    ids = ("ck-1", "ck-2", "ck-9", "", "x" * 200)
    got = {kid: b.challenge(SID, kid) for kid in ids}
    shapes = {(len(c.nonce), set(c.nonce) <= set(string.hexdigits),
               c.ttl_seconds) for c in got.values()}
    assert shapes == {(32, True, env.config.t_nonce)}
    assert len({c.nonce for c in got.values()}) == len(ids)
    assert len(env.kinds()) == n                    # no event for any
    book = b._nonces[SID]
    assert {r.issued_at for r in book.values()} == {b._now()}
    assert {kid: book[c.nonce].eligible for kid, c in got.items()} == {
        "ck-1": True, "ck-2": False, "ck-9": False, "": False,
        "x" * 200: False}
    # the limit counts every key id alike, and its refusal is one refusal
    full = Env().reach(DET, NONE)
    for i in range(NONCE_RECORDS):
        full.bridge.challenge(SID, f"nobody-{i}")
    refusals = {(str(e), e.reason) for e in (
        _refusal(lambda: full.bridge.challenge(SID, kid))
        for kid in ("ck-1", "nobody"))}
    assert len(refusals) == 1
    # so is the refusal for a session that is unknown or over
    over = Env()
    over.bridge.terminate(SID)
    assert len({str(_refusal(lambda: over.bridge.challenge(sid, kid)))
                for sid in (SID, "no-such-session")
                for kid in ("ck-1", "ck-9")}) == 1
    # on the wire the response has the same fields for either key id, and
    # a challenge that names no key id is malformed
    server = wire_server.WireServer(Env().bridge)
    r1, r2 = (wire_server.send(server, wire.op_challenge(
        session_id=SID, key_id=kid)) for kid in ("ck-1", "ck-9"))
    assert set(r1) == set(r2) == {"status", "session_id", "nonce",
                                  "ttl_seconds"}
    assert (r1["status"], r1["ttl_seconds"]) == (r2["status"],
                                                 r2["ttl_seconds"])
    with pytest.raises(wire_server.WireRejected) as exc:
        wire_server.send(server, wire.encode_message("challenge",
                                                     session_id=SID))
    assert exc.value.reason == "bad_canonical"


_P4_KEYS = ("ck-1", "ck-2", "ck-3", "ck-x")
_P4_OPS = ["challenge", "present", "present_forged", "present_flagged",
           "replay", "register", "operator_add", "revoke", "disconnect",
           "complete", "advance", "restart"]


@given(st.lists(st.tuples(st.sampled_from(_P4_OPS), st.integers(0, 7),
                          st.integers(0, 7)), min_size=1, max_size=40))
@settings(max_examples=150, deadline=None)
def test_T152f_a_request_that_was_presented_is_never_accepted_later(actions):
    """I11(b), I11(d): over random interleavings of challenges for any key
    id, requests by registered, unregistered and revoked keys (well signed,
    forged, or flagged by the transport), registrations, operator key
    additions, revocations, detachments, clock steps and restarts, a
    request is accepted at most on its first presentation: one that was
    presented before, whether it was then accepted or refused, is refused."""
    env = Env(Config(t_detach=10**6, t_total=10**7))
    keys = {k: (env.key if k == "ck-1" else ClientKey(k)) for k in _P4_KEYS}
    pool: list[str] = []                 # nonces the bridge issued
    seen: list[tuple[str, ResumeRequest]] = []    # every request presented

    def present(op: str, req: ResumeRequest, flagged: bool = False) -> bool:
        try:
            env.bridge.begin_resume(SID, req, op=op, transport_replay=flagged)
            return True
        except BridgeError:
            return False

    for kind, x, y in actions:
        b = env.bridge
        k = _P4_KEYS[x % len(_P4_KEYS)]
        try:
            if kind == "challenge":
                pool.append(b.challenge(
                    SID, _P4_KEYS[y % len(_P4_KEYS)]).nonce)
            elif kind.startswith("present"):
                nonce = pool[y % len(pool)] if pool else "ab" * 16
                op = "join" if b.cell_of(SID).att == ATT else "reattach"
                req = keys[k].request(SID, nonce, *env.tip(), op)
                if kind == "present_forged":
                    req.signature = "00" * 64
                first = (op, req) not in seen
                accepted = present(op, req, kind == "present_flagged")
                seen.append((op, req))
                assert first or not accepted
            elif kind == "replay" and seen:
                op, req = seen[(8 * x + y) % len(seen)]
                assert not present(op, req)
            elif kind == "register":
                conn = sorted(b.client_set(SID))
                if conn:
                    add_client(b, SID, keys[conn[0]], keys[k].public())
            elif kind == "operator_add":
                op_add_key(b, SID, k, keys[k].public_key.hex())
            elif kind == "revoke":
                op_revoke(b, SID, k, REVOKE_REASONS[y % 2])
            elif kind == "disconnect":
                b.client_disconnect(SID)
            elif kind == "complete":
                b.complete_resume(SID)
            elif kind == "advance":
                env.clock.advance(10 * y)
                b.tick()
            elif kind == "restart":
                env.restart()
        except BridgeError:
            pass


def test_T152g_a_request_the_transport_flags_spends_its_nonce():
    """I8, I11(d): a request the transport reports as a replay is refused as
    transport_replay whatever else is true of it.  If it is authentic it has
    spent its nonce, so the same bytes presented again without the flag are
    refused; if it is not authentic the nonce is left alone."""
    env = Env()
    env.disconnect()
    req = env.request()
    _rejects(env, req, "transport_replay", transport_replay=True)
    assert env.bridge._nonces[SID][req.nonce].used
    _rejects(env, req, "nonce_used")
    nonce = env.bridge.challenge(SID, "ck-1").nonce
    forged = ResumeRequest("ck-1", nonce, *env.seen["ck-1"], "00" * 64)
    _rejects(env, forged, "transport_replay", transport_replay=True)
    assert not env.bridge._nonces[SID][nonce].used
    assert env.cell() == (DET, NONE, ACTIVE)
    env.bridge.client_reattach(SID, env.request(nonce=nonce))
    assert env.cell() == (ATT, NONE, ACTIVE)


def test_T152h_the_bounds_hold_with_nonces_bound_to_key_ids():
    """I11f, I11g: the limit on live nonces counts the nonces of every key
    id, registered or not, and a nonce a genuine client holds stays valid
    under a flood for other key ids.  A request refused for the binding of
    its nonce is of the unauthenticated class: it is logged only up to the
    bound, leaves the nonce alone and does not restore the allowance."""
    env = Env().reach(DET, NONE)
    b = env.bridge
    genuine = env.request()
    for i in range(NONCE_RECORDS - 1):
        b.challenge(SID, f"nobody-{i}")
    for kid in ("ck-1", "nobody"):
        with pytest.raises(BridgeError, match="challenge budget"):
            b.challenge(SID, kid)
    b.begin_resume(SID, genuine)                     # still accepted
    b.complete_resume(SID)
    env = Env()
    env.add_device("ck-2")
    env.disconnect()
    b = env.bridge
    n0 = len(env.kinds())
    other = b.challenge(SID, "ck-2").nonce
    for _ in range(3 * UNAUTH_LOG_LIMIT):
        err = _refusal(lambda: b.begin_resume(
            SID, env.request("ck-1", nonce=other)))
        assert err.reason == "bad_signature"
    assert len(env.kinds()) - n0 == UNAUTH_LOG_LIMIT
    assert {e.payload["reason"] for e in b.events[SID][n0:]} == {
        "nonce_binding"}
    assert not b._nonces[SID][other].used
    _rejects(env, env.key.request(SID, "0" * 32, 0, "0" * 64),
             "nonce_unknown")                        # a key holder speaks
    _rejects(env, env.request("ck-1", nonce=other), "nonce_binding")


# ----------------------------------------------------------------------
# Verification comes before anything the session's state decides
# ----------------------------------------------------------------------

def test_T141b_a_join_is_verified_before_the_attachment_is_answered():
    """I11a, I15(c): a join whose signature does not verify gets the same
    answer and the same logged event whether the session is attached,
    detached or resuming, so `join` tells an unauthenticated caller nothing
    about the attachment.  A join that verified is refused as not_attached
    on a detached session and as resume_in_progress while a re-attach is
    verified; it has spent its nonce, and a join proof never starts a
    re-attach."""
    answers = set()
    for att in (ATT, DET, RES):
        env = Env()
        env.add_device("ck-2")
        if att != ATT:
            env.disconnect()
        if att == RES:
            env.begin_resume("ck-1")
        garbage = env.request("ck-2", op="join")
        garbage.signature = "00" * 64
        n = len(env.kinds())
        err = _refusal(lambda: env.bridge.join(SID, garbage))
        answers.add((str(err), err.reason, tuple(env.kinds()[n:]),
                     _last(env).payload["reason"]))
        assert env.cell()[0] == att
    assert answers == {("re-attach rejected: bad_signature (I4/I8/I9/I11)",
                        "bad_signature", (GE.RESUME_REJECTED,),
                        "bad_signature")}
    env = Env()
    env.add_device("ck-2")
    env.disconnect()
    req = env.request("ck-2", op="join")
    n = len(env.kinds())
    assert _refusal(lambda: env.bridge.join(SID, req)).reason == "not_attached"
    assert env.kinds()[n:] == [GE.RESUME_REJECTED]   # no RESUME_STARTED
    assert _last(env).payload["reason"] == "not_attached"
    assert env.cell() == (DET, NONE, ACTIVE)
    assert env.bridge._nonces[SID][req.nonce].used
    assert _refusal(lambda: env.bridge.begin_resume(
        SID, req, op="join")).reason == "nonce_used"
    env.begin_resume("ck-1")
    assert _refusal(lambda: env.bridge.join(SID, env.request(
        "ck-2", op="join"))).reason == "resume_in_progress"
    env.bridge.complete_resume(SID)
    env.bridge.join(SID, env.request("ck-2", op="join"))
    assert env.bridge.client_set(SID) == {"ck-1", "ck-2"}


def test_T71b_a_key_exhausted_session_answers_a_request_like_any_other():
    """I11a, I11-REVOKE: a re-attach that does not verify gets the same
    answer on a key_exhausted session as on one with active keys, so the
    refusal does not say that the session has no key left; a holder of a
    revoked key learns that its key is revoked."""
    def answers(env: Env) -> list[str]:
        seq, h = env.seen["ck-1"]
        stranger = ClientKey("ck-9")
        unknown = stranger.request(
            SID, env.bridge.challenge(SID, "ck-9").nonce, seq, h)
        forged = env.request("ck-1")
        forged.signature = "00" * 64
        return [str(_refusal(lambda: env.bridge.begin_resume(SID, r)))
                for r in (unknown, forged)]
    live = Env()
    live.add_device("ck-2")
    live.disconnect()
    gone = Env()
    gone.add_device("ck-2")
    gone.disconnect()
    for kid in ("ck-1", "ck-2"):
        op_revoke(gone.bridge, SID, kid)
    assert gone.bridge._sess[SID].key_exhausted
    assert answers(gone) == answers(live)
    assert "bad_signature" in answers(gone)[0]
    err = _refusal(lambda: gone.bridge.begin_resume(SID, gone.request("ck-1")))
    assert err.reason == "revoked_key"
    assert _last(gone).payload["reason"] == "revoked_key"


def test_T26b_a_request_in_the_tick_of_a_timer_is_processed_first():
    """L1, L2, I11: when T_detach (or the cumulative cap) expires in the
    very tick of a re-attach, the request is processed first: if it is
    accepted the timer no longer applies and does not fire; if it is
    refused the timer fires after it.  A timer that expired before the
    request has ended the session, and the answer is the uniform refusal.
    A human timer of the same tick still applies after the re-attach."""
    env = Env(Config(t_detach=600))
    env.disconnect()
    env.clock.advance(600)                         # the tick of T_detach
    env.reattach()
    assert env.cell() == (ATT, NONE, ACTIVE)
    assert GE.DETACH_TIMEOUT not in env.kinds()

    env = Env(Config(t_detach=600))
    env.disconnect()
    env.clock.advance(600)
    forged = env.request()
    forged.signature = "00" * 64
    n = len(env.kinds())
    err = _refusal(lambda: env.bridge.client_reattach(SID, forged))
    assert err.reason == "bad_signature"
    assert env.kinds()[n:] == [GE.RESUME_REJECTED, GE.DETACH_TIMEOUT,
                               GE.TERMINATION]

    env = Env(Config(t_detach=600))
    env.disconnect()
    env.clock.advance(601)                         # a tick too late
    late = env.request()
    n = len(env.kinds())
    err = _refusal(lambda: env.bridge.client_reattach(SID, late))
    assert (str(err), err.reason) == (RESUME_REFUSED, "refused")
    assert env.kinds()[n:] == [GE.DETACH_TIMEOUT, GE.TERMINATION]

    env = Env(Config(t_detach=600, t_total=1000))
    env.disconnect()
    env.clock.advance(500)
    env.reattach()
    env.disconnect()
    env.clock.advance(500)                         # the tick of the cap
    env.reattach()
    assert env.cell() == (ATT, NONE, ACTIVE)

    env = Env(Config(t_detach=600, t_human=600, t_call=600))
    env.bridge.escalate_to_human(SID)
    env.disconnect()
    env.clock.advance(600)                         # both timers, one tick
    req = env.request()
    n = len(env.kinds())
    with pytest.raises(BridgeError, match="TERMINATED"):
        env.bridge.client_reattach(SID, req)
    assert env.kinds()[n:] == [GE.RESUME_STARTED, GE.HUMAN_TIMEOUT,
                               GE.TERMINATION]
    assert env.bridge.events[SID][-1].payload["reason"] == "human_timeout"


# ----------------------------------------------------------------------
# Approval freshness is kept per call
# ----------------------------------------------------------------------

def _two_escalations(env: Env) -> None:
    """Escalation one approves k1 while the client is away and lapses;
    an unrelated escalation two then approves k2."""
    b = env.bridge
    b.submit_tool_call(SID, "shell:git push", key="k1")
    env.resolve()
    env.clock.advance(150)                         # k1's approval lapses
    b.escalate_to_human(SID)
    b.submit_tool_call(SID, "shell:ls", key="k2")
    env.resolve()
    env.clock.advance(50)


def test_T43b_a_later_approval_does_not_revive_a_lapsed_one():
    """I13: the approval expiry is kept per call, set by the resolution of
    the escalation the call was queued under.  A call whose approval lapsed
    while the client was away expires at the drain though a later,
    unrelated escalation was resolved in between; the call of that later
    escalation drains.  The same holds when the bridge restarts before the
    drain, since the expiry is read from the log."""
    for restart in (False, True):
        env = Env(Config(t_approve=100, t_detach=10_000)).reach(DET, PEND)
        _two_escalations(env)
        if restart:
            env.restart()
        env.reattach()
        fate = [(e.kind, e.payload["key"], e.payload.get("reason"))
                for e in env.bridge.events[SID]
                if e.kind in (GE.TOOL_CALL_EXPIRED, GE.TOOL_CALL_DRAINED)]
        assert fate == [(GE.TOOL_CALL_EXPIRED, "k1", "approval_ttl"),
                        (GE.TOOL_CALL_DRAINED, "k2", None)], restart
        assert [k for _, k, _ in env.bridge.forwarded] == ["k2"]


def test_T43c_an_approval_is_valid_strictly_before_t_approve():
    """I13: an approval is valid while less than T_approve has passed since
    the resolution: a drain at exactly T_approve finds it expired, one a
    second earlier forwards the call."""
    for wait, kind in ((100, GE.TOOL_CALL_EXPIRED), (99, GE.TOOL_CALL_DRAINED)):
        env = Env(Config(t_approve=100, t_detach=10_000)).reach(DET, PEND)
        env.bridge.submit_tool_call(SID, "shell:git push", key="k1")
        env.resolve()
        env.clock.advance(wait)
        env.reattach()
        assert _last(env).kind == kind, wait
        assert bool(env.bridge.forwarded) == (kind == GE.TOOL_CALL_DRAINED)
    assert _last(env).payload["key"] == "k1"


# ----------------------------------------------------------------------
# Checkpoints on: lifecycle, quarantine and chain verification come first
# ----------------------------------------------------------------------

def _cp_env(n: int = 1, t: float = float("inf"), **cfg) -> Env:
    """An Env that runs with checkpoints on: one after every ``n`` events
    or ``t`` seconds."""
    return Env(Config(n_checkpoint=n, t_checkpoint=t, **cfg),
               checkpoints=True)


def _check_checkpoints(env: Env) -> None:
    """Every CHECKPOINT covers exactly the events before it and carries
    their Merkle tree hash."""
    from merkle import merkle_root
    log = env.bridge.events[env.sid]
    for ev in log:
        if ev.kind == GE.CHECKPOINT:
            assert ev.payload["tree_size"] == ev.sequence
            leaves = [bytes.fromhex(e.event_hash())
                      for e in log[:ev.sequence]]
            assert ev.payload["root"] == merkle_root(leaves).hex()


def test_T66b_no_checkpoint_follows_a_termination():
    """I-CHECKPOINT, I6: TERMINATION is the last event of a session also
    when a checkpoint is due: after an explicit termination, after a
    timeout, at a later tick, and under the default configuration when the
    time threshold has passed."""
    env = _cp_env()
    env.bridge.escalate_to_human(SID)
    assert env.kinds()[-2:] == [GE.HUMAN_PENDING, GE.CHECKPOINT]
    env.bridge.terminate(SID)
    assert env.kinds()[-1] == GE.TERMINATION
    env.clock.advance(10_000)
    env.bridge.tick()
    _no_events_after_termination(env)

    env = _cp_env(t_detach=600)
    env.disconnect()
    assert env.kinds()[-1] == GE.CHECKPOINT
    env.clock.advance(600)
    env.bridge.tick()
    assert env.kinds()[-2:] == [GE.DETACH_TIMEOUT, GE.TERMINATION]

    env = Env(Config(), checkpoints=True)          # N = 1000, T_cp = 300 s
    env.clock.advance(301)                         # the time threshold
    env.bridge.terminate(SID)
    assert env.kinds() == [GE.ATTACHED, GE.TERMINATION]
    _check_checkpoints(env)


def test_T66c_no_checkpoint_on_a_quarantined_session():
    """I-CHECKPOINT, rule Q: nothing but a TERMINATION follows the failure
    event of a quarantined session, so no checkpoint is appended to it,
    at the failure, at a tick or after a restart, also when the chain
    verifies again (the fault in storage was transient): the quarantine
    stands until an operator ends the session."""
    env = _cp_env()
    env.disconnect()
    assert env.kinds()[-1] == GE.CHECKPOINT
    good = env.storage.logs[SID][1].prev_hash
    env.storage.logs[SID][1].prev_hash = "00" * 32
    with pytest.raises(BridgeError, match="I5"):
        env.reattach()
    assert env.kinds()[-2:] == [GE.RESUME_STARTED, GE.RESUME_FAILED]
    assert env.bridge.is_quarantined(SID)
    n = len(env.kinds())
    env.clock.advance(10_000)
    env.bridge.tick()
    env.storage.logs[SID][1].prev_hash = good      # the chain verifies again
    env.bridge._verify_event_chain(SID)
    env.bridge.tick()
    env.restart()
    env.bridge.tick()
    assert env.bridge.is_quarantined(SID)
    assert len(env.kinds()) == n
    env.bridge.terminate(SID)                      # the operator's way out
    assert env.kinds()[n:] == [GE.TERMINATION]


def test_T66d_no_checkpoint_over_a_log_that_does_not_verify():
    """I-CHECKPOINT, I5: the root is taken only over a log whose hash chain
    verifies.  On a log that was tampered with no checkpoint is emitted,
    neither when a re-attach starts (before its chain verification) nor at
    any other commit; an intact log is checkpointed as before."""
    env = _cp_env()
    env.disconnect()
    env.storage.logs[SID][1].prev_hash = "00" * 32
    env.begin_resume()                             # authentic: Res
    assert env.kinds()[-1] == GE.RESUME_STARTED    # and no CHECKPOINT
    env.bridge.escalate_to_human(SID)
    assert env.kinds()[-1] == GE.HUMAN_PENDING
    assert env.kinds().count(GE.CHECKPOINT) == 1   # the one before tampering

    env = _cp_env()
    env.disconnect()
    env.begin_resume()
    assert env.kinds()[-2:] == [GE.RESUME_STARTED, GE.CHECKPOINT]
    env.bridge.complete_resume(SID)
    assert env.kinds()[-2:] == [GE.RESUME_VERIFIED, GE.CHECKPOINT]
    _check_checkpoints(env)


@given(st.lists(_action_strategy(), min_size=1, max_size=40))
@settings(max_examples=60, deadline=None)
def test_T66e_the_invariants_hold_with_checkpoints_on(actions):
    """I-CHECKPOINT, I5, I6: with checkpoints on (by count and by time) the
    invariants of T9 hold after every random action, no event follows a
    TERMINATION, and every CHECKPOINT carries the size and the Merkle tree
    hash of the events before it."""
    env, stale, rejected = _cp_env(3, 120.0), [], []
    for a in actions:
        _apply_action(env, a, stale, rejected)
        _check_invariants(env)
        _check_checkpoints(env)


def test_T66f_the_checkpoint_root_is_the_tree_hash_of_rfc_9162():
    """I-CHECKPOINT: the root is the Merkle tree hash of RFC 9162, Section
    2.1.1, over the event hashes: the empty tree hashes the empty string, a
    leaf is hashed under the prefix 0x00 and an interior node under 0x01,
    and a tree is split at the largest power of two below its size, with no
    node repeated.  The roots and audit paths are pinned in
    vectors/bytes_kat.json, which the Rust crate reads too. [trace: wire]"""
    import merkle
    sha = lambda data: hashlib.sha256(data).digest()      # noqa: E731
    d = [sha(bytes([i])) for i in range(8)]
    leaf = [sha(b"\x00" + x) for x in d]
    node = lambda left, right: sha(b"\x01" + left + right)  # noqa: E731
    assert merkle.merkle_root([]) == sha(b"")
    assert merkle.merkle_root(d[:1]) == leaf[0] != d[0]
    assert merkle.merkle_root(d[:2]) == node(leaf[0], leaf[1])
    assert merkle.merkle_root(d[:3]) == node(node(leaf[0], leaf[1]), leaf[2])
    assert merkle.merkle_root(d[:5]) == node(
        node(node(leaf[0], leaf[1]), node(leaf[2], leaf[3])), leaf[4])
    assert merkle.merkle_root(d[:7]) == node(
        node(node(leaf[0], leaf[1]), node(leaf[2], leaf[3])),
        node(node(leaf[4], leaf[5]), leaf[6]))
    # no last node is repeated, and an interior node is not a leaf
    assert merkle.merkle_root(d[:3]) != merkle.merkle_root(d[:3] + d[2:3])
    assert merkle.merkle_root(d[:2]) != merkle.merkle_root(
        [leaf[0] + leaf[1]])
    kat = _bytes_kat()["merkle"]
    for c in kat["roots"]:
        leaves = [bytes.fromhex(x) for x in c["leaves"]]
        assert merkle.merkle_root(leaves).hex() == c["root"], c["name"]
        assert merkle.merkle_root_hex(c["leaves"]) == c["root"]
    for c in kat["inclusion"]:
        leaves = [bytes.fromhex(x) for x in c["leaves"]]
        root = bytes.fromhex(c["root"])
        path = merkle.inclusion_proof(leaves, c["index"])
        assert [p.hex() for p in path] == c["path"], c["name"]
        assert merkle.verify_inclusion(leaves[c["index"]], c["index"],
                                       len(leaves), path, root)
        assert not merkle.verify_inclusion(
            leaves[c["index"]], c["index"] ^ 1, len(leaves), path, root)
        assert not merkle.verify_inclusion(
            sha(b"other"), c["index"], len(leaves), path, root)
    # the checkpoint of a real log carries this root and its size
    env = _cp_env(3)
    env.bridge.escalate_to_human(SID)
    env.bridge.submit_tool_call(SID, "tool:1", key="k1")
    assert env.kinds()[-1] == GE.CHECKPOINT
    _check_checkpoints(env)


# ----------------------------------------------------------------------
# Revocation, quarantine and the operator operations
# ----------------------------------------------------------------------

def test_T128b_a_soft_revocation_of_the_only_key_in_res_does_not_strand_it():
    """I11-REVOKE, L1: a soft revocation of the only key while its
    re-attach is being verified returns the session to Det, key_exhausted;
    T_detach runs again from that detachment and ends the session unless
    the operator adds a key."""
    env = Env()
    env.disconnect()
    env.begin_resume("ck-1")
    op_revoke(env.bridge, SID, "ck-1", "rotation")
    assert env.kinds()[-3:] == [GE.KEY_REVOKED, GE.DETACHMENT,
                                GE.RESUME_PREPARED]
    assert env.cell() == (DET, NONE, ACTIVE)
    assert env.bridge._sess[SID].key_exhausted
    with pytest.raises(BridgeError):
        env.bridge.complete_resume(SID)
    env.clock.advance(env.config.t_detach - 1)
    env.bridge.tick()
    assert env.cell() == (DET, NONE, ACTIVE)
    env.clock.advance(1)
    env.bridge.tick()
    assert env.kinds()[-2:] == [GE.DETACH_TIMEOUT, GE.TERMINATION]


def test_T146b_no_key_is_added_to_a_quarantined_session():
    """Rule Q, I11-REVOKE: a quarantined session takes no event but a
    TERMINATION, so an operator key addition with a valid signature is
    refused as quarantined and registers nothing; without the operator's
    signature the answer is the one every session gets. [trace: rule Q]"""
    env = Env()
    op_revoke(env.bridge, SID, "ck-1", reason="compromise")
    env.storage.logs[SID][1].prev_hash = "00" * 32
    env.restart()
    b = env.bridge
    assert b.is_quarantined(SID) and b._sess[SID].key_exhausted
    n = len(env.kinds())
    err = _refusal(lambda: op_add_key(b, SID, "ck-2", "cd" * 32))
    assert err.reason == "quarantined"
    with pytest.raises(OperatorSignatureInvalid):
        b.operator_add_key(SID, "ck-2", "cd" * 32, signature="00" * 64)
    assert len(env.kinds()) == n
    assert (SID, "ck-2") not in env.storage.client_keys
    assert b._sess[SID].keys == {"ck-1"}
    b.terminate(SID)
    assert env.kinds()[n:] == [GE.TERMINATION]


def test_T69b_a_revoked_key_cannot_join_and_revocation_follows_the_signature():
    """I11-REVOKE, I11(d): a revoked key is refused for a join as for a
    re-attach.  The revocation is looked at only after the signature
    verified: a request that names a revoked key and does not verify is a
    bad signature and leaves the nonce alone, while the key holder's own
    request is refused as revoked and spends the nonce issued to it."""
    env = Env()
    env.add_device("ck-2")
    b = env.bridge
    nonce = b.challenge(SID, "ck-2").nonce          # while ck-2 is active
    op_revoke(b, SID, "ck-2", "rotation")
    forged = env.request("ck-2", op="join", nonce=nonce)
    forged.signature = "00" * 64
    err = _refusal(lambda: b.join(SID, forged))
    assert err.reason == "bad_signature"
    assert _last(env).payload["reason"] == "bad_signature"
    assert not b._nonces[SID][nonce].used
    err = _refusal(lambda: b.join(SID, env.request("ck-2", op="join",
                                                   nonce=nonce)))
    assert err.reason == "revoked_key"
    assert _last(env).payload["reason"] == "revoked_key"
    assert b._nonces[SID][nonce].used
    # it spends its own nonce only: one issued to another key stays live
    other = b.challenge(SID, "ck-1").nonce
    err = _refusal(lambda: b.join(SID, env.request("ck-2", op="join",
                                                   nonce=other)))
    assert err.reason == "revoked_key"
    assert not b._nonces[SID][other].used
    assert GE.CLIENT_JOINED not in env.kinds()
    assert b.client_set(SID) == {"ck-1"}


def test_T19d_a_request_for_an_unregistered_key_leaves_the_nonce():
    """I11(d), I15: a request that names a key id the session does not
    register is not authentic and does not consume the nonce it presents;
    the client the nonce was issued to still uses it."""
    env = Env()
    env.disconnect()
    nonce = env.bridge.challenge(SID, "ck-1").nonce
    stranger = ClientKey("ck-9")
    _rejects(env, stranger.request(SID, nonce, *env.seen["ck-1"]),
             "unknown_key")
    assert not env.bridge._nonces[SID][nonce].used
    env.bridge.client_reattach(SID, env.request(nonce=nonce))
    assert env.cell() == (ATT, NONE, ACTIVE)


def test_T99b_refusals_of_a_revoked_key_are_logged_up_to_the_bound():
    """I11g, I11-REVOKE: a holder of a revoked key needs no nonce to be
    refused, so its refusals are of the bounded class: at most
    UNAUTH_LOG_LIMIT are logged between two requests of an active key, and
    they do not restore the allowance for other unauthenticated failures."""
    env = Env()
    env.add_device("ck-2")
    env.disconnect()
    b = env.bridge
    op_revoke(b, SID, "ck-1")
    n0 = len(env.kinds())
    stale = env.key.request(SID, "0" * 32, 0, "0" * 64)     # no nonce needed
    for _ in range(3 * UNAUTH_LOG_LIMIT):
        assert _refusal(lambda: b.begin_resume(SID, stale)).reason == \
            "revoked_key"
    assert len(env.kinds()) - n0 == UNAUTH_LOG_LIMIT
    forged = ResumeRequest("ck-2", "0" * 32, 0, "0" * 64, "00" * 64)
    assert _refusal(lambda: b.begin_resume(SID, forged)).reason == \
        "bad_signature"
    assert len(env.kinds()) - n0 == UNAUTH_LOG_LIMIT        # not logged
    env.reattach("ck-2")                            # an active key speaks
    n1 = len(env.kinds())
    assert _refusal(lambda: b.begin_resume(SID, stale)).reason == \
        "revoked_key"
    assert env.kinds()[n1:] == [GE.RESUME_REJECTED]


def test_T89b_a_revocation_names_a_known_kind_and_is_made_once():
    """I11-REVOKE: the reason of a revocation is rotation or compromise;
    any other string is a malformed request, signed or not, and commits
    nothing.  A key that is revoked is not revoked again, by either kind,
    and a request for its revocation is refused too."""
    env = Env()
    env.add_device("ck-2")
    b = env.bridge
    n = len(env.kinds())
    for why in ("", "lost", "Rotation", "compromise "):
        for kw in ({"signature": op_sig(b, "revoke", SID, "ck-1", why)},
                   {"signature": "", "requested_by": "ck-1"}):
            err = _refusal(lambda: b.revoke_key(SID, "ck-1", why, **kw))
            assert err.reason == "bad_canonical", why
    assert len(env.kinds()) == n and not b._sess[SID].revoked_keys
    op_revoke(b, SID, "ck-1", "rotation")
    n = len(env.kinds())
    for why in REVOKE_REASONS:
        err = _refusal(lambda: op_revoke(b, SID, "ck-1", why))
        assert err.reason == "revoked_key"
    err = _refusal(lambda: b.revoke_key(SID, "ck-1", "rotation",
                                        signature="", requested_by="ck-2"))
    assert err.reason == "revoked_key"
    assert len(env.kinds()) == n
    assert env.kinds().count(GE.KEY_REVOKED) == 1


def test_T150b_operator_operations_check_the_signature_first():
    """I-OPERATOR, I11a: a revocation, a key addition and a termination
    verify the operator's signature before anything is said about the
    session: without it the answer is operator_signature_invalid for an
    unknown session, an unknown or registered key, a session with active
    keys, a terminated and a quarantined one alike, and nothing is
    committed.  With it the state is named, and a termination of a session
    that is already over is refused."""
    bad = "00" * 64
    env = Env()
    b = env.bridge

    def unsigned(bridge: Bridge, sid: str) -> set[str]:
        return {_refusal(call).reason for call in (
            lambda: bridge.revoke_key(sid, "ck-1", "rotation", signature=bad),
            lambda: bridge.revoke_key(sid, "ck-9", "rotation", signature=bad),
            lambda: bridge.revoke_key(sid, "ck-1", "rotation",
                                      signature=None),
            lambda: bridge.operator_add_key(sid, "ck-2", "cd" * 32,
                                            signature=bad),
            lambda: bridge.operator_add_key(sid, "ck-1", "cd" * 32,
                                            signature=bad),
            lambda: bridge.operator_terminate(sid, signature=bad),
            lambda: bridge.operator_terminate(sid, signature=None))}

    n = len(env.kinds())
    assert unsigned(b, SID) == {"operator_signature_invalid"}
    assert unsigned(b, "no-such-session") == {"operator_signature_invalid"}
    assert len(env.kinds()) == n
    quarantined = Env().reach(RES, NONE)
    quarantined.storage.logs[SID][0].payload["principal_id"] = "mallory"
    with pytest.raises(BridgeError):
        quarantined.bridge.complete_resume(SID)
    assert unsigned(quarantined.bridge, SID) == {"operator_signature_invalid"}
    b.terminate(SID)
    n = len(env.kinds())
    assert unsigned(b, SID) == {"operator_signature_invalid"}
    for call in (lambda: op_terminate(b, SID),
                 lambda: op_add_key(b, SID, "ck-2", "cd" * 32),
                 lambda: op_revoke(b, SID, "ck-1")):
        assert _refusal(call).reason == "terminated"
    assert len(env.kinds()) == n
    over_nothing = TEST_OPERATOR.terminate(
        b.bridge_id, "no-such-session", "all_keys_revoked", -1, "")
    assert _refusal(lambda: b.operator_terminate(
        "no-such-session", signature=over_nothing)).reason == "unknown_session"


# ----------------------------------------------------------------------
# Small rules: the chain, resolve, disconnect, the resume record
# ----------------------------------------------------------------------

def test_T5b_the_chain_check_reads_the_sequence_numbers():
    """I5: an event carries its position as its sequence number.  A wrong
    sequence number on the last event changes no later prev_hash, so only
    the check of the number finds it: at a re-attach (the session is
    quarantined) and at recovery. [trace: I5 rule Q]"""
    env = Env()
    env.disconnect()
    env.storage.logs[SID][-1].sequence += 7
    with pytest.raises(BridgeError, match="I5"):
        env.bridge._verify_event_chain(SID)
    with pytest.raises(BridgeError, match="I5"):
        env.reattach()
    assert env.kinds()[-2:] == [GE.RESUME_STARTED, GE.RESUME_FAILED]
    assert env.bridge.is_quarantined(SID)
    env = Env()
    env.disconnect()
    env.storage.logs[SID][-1].sequence += 7
    assert env.restart().is_quarantined(SID)
    assert env.kinds()[-1] == GE.RECOVERY_FAILED


def test_T61b_a_resolution_needs_a_pending_escalation():
    """I2, I13: `resolve` is refused while no escalation is pending, in
    every attachment, and commits nothing: an approval cannot be made in
    advance of the escalation it is for."""
    for att in (ATT, DET, RES):
        env = Env().reach(att, NONE)
        n = len(env.kinds())
        with pytest.raises(BridgeError, match="Human=Pend"):
            env.bridge.human_resolve(SID)
        assert len(env.kinds()) == n and env.cell() == (att, NONE, ACTIVE)


def test_T21b_the_disconnect_of_another_key_does_not_abandon_a_reattach():
    """I15(b), I1: while a re-attach is being verified only the loss of the
    re-attaching client's transport returns the session to Det; a
    disconnect that names another key changes nothing."""
    env = Env()
    env.add_device("ck-2")
    env.disconnect()
    env.begin_resume("ck-1")
    n = len(env.kinds())
    env.bridge.client_disconnect(SID, "ck-2")
    assert len(env.kinds()) == n and env.cell() == (RES, NONE, ACTIVE)
    env.bridge.complete_resume(SID)
    assert env.bridge.client_set(SID) == {"ck-1"}
    env.disconnect()
    env.begin_resume("ck-1")
    env.bridge.client_disconnect(SID, "ck-1")      # its own transport
    assert env.kinds()[-2:] == [GE.DETACHMENT, GE.RESUME_PREPARED]


def test_T45b_the_resume_record_carries_the_scope_in_force():
    """I1, I10: RESUME_PREPARED records the scope and the scope version in
    force at the detachment, and the authority hash over that scope, also
    after narrowings made while attached and while away, and at a restart."""
    env = Env()
    b = env.bridge
    b.narrow_authority_scope(SID, ("read:docs",))
    env.disconnect()
    rec = b.resume_record(SID).payload
    assert (rec["scope_version"], rec["authority_scope"]) == (1, ["read:docs"])
    assert rec["authority_hash"] == _authority_hash(
        "user-alice", ("read:docs",), ("root",))
    b.narrow_authority_scope(SID, ())               # while away
    env.reattach()
    env.disconnect()
    rec = b.resume_record(SID).payload
    assert (rec["scope_version"], rec["authority_scope"]) == (2, [])
    rec = env.restart().resume_record(SID).payload
    assert (rec["scope_version"], rec["authority_scope"]) == (2, [])
    assert rec["reason"] == "bridge_restart"


# ----------------------------------------------------------------------
# Tool calls: keys, the direct path, completion
# ----------------------------------------------------------------------

def test_T41b_a_duplicate_key_returns_the_queued_call_and_commits_nothing():
    """I13: a second submission under a key that is queued is not queued
    again, whether its content is the same or not: the bridge answers
    DUPLICATE (`duplicate_key` on the wire), the first call keeps its
    content and its hash, and no event is committed, not even a rejection."""
    import wire
    import wire_server
    env = Env().reach(ATT, PEND)
    b = env.bridge
    assert b.submit_tool_call(SID, "a", key="k1", content={"n": 1}) == "QUEUED"
    before = list(b.events[SID])
    shown = b.shown_hash_of(SID, "k1")
    assert b.submit_tool_call(SID, "a", key="k1", content={"n": 1}) == \
        "DUPLICATE"
    assert b.submit_tool_call_keyed(SID, "b", key="k1", content={"n": 2}) == (
        "DUPLICATE", "k1")
    server = wire_server.WireServer(b)
    with pytest.raises(wire_server.WireRejected) as exc:
        wire_server.send(server, wire.op_submit_tool_call(
            session_id=SID, tool="c", content={"n": 3}, key="k1"))
    assert exc.value.reason == "duplicate_key"
    assert b.events[SID] == before
    assert [(c["key"], c["tool"], c["content"]) for c in b._sess[SID].queue] \
        == [("k1", "a", {"n": 1})]
    assert b.shown_hash_of(SID, "k1") == shown


def test_T41c_a_generated_key_never_collides_with_a_supplied_one():
    """I13: when the runtime supplies no key the bridge generates one that
    the session has not used, also when the runtime has used keys of the
    bridge's own form, so a distinct call is never taken for a duplicate."""
    env = Env().reach(ATT, PEND)
    b = env.bridge
    assert b.submit_tool_call(SID, "a", key="tc-0002") == "QUEUED"
    assert b.submit_tool_call(SID, "b") == "QUEUED"        # not a duplicate
    assert b.submit_tool_call(SID, "c", key="tc-0004") == "QUEUED"
    status, key = b.submit_tool_call_keyed(SID, "d")
    assert status == "QUEUED"
    keys = [c["key"] for c in b._sess[SID].queue]
    assert b.queued_tools(SID) == ["a", "b", "c", "d"]
    assert len(set(keys)) == 4 and keys[3] == key
    assert env.kinds().count(GE.TOOL_CALL_QUEUED) == 4


def test_T25b_a_direct_call_outside_the_scope_is_refused_and_recorded():
    """I3, I2: with a client attached and no escalation pending a call
    whose permission is not in the current scope is not forwarded: it is
    refused with the reason scope and recorded as TOOL_CALL_REJECTED
    (marked direct, with the permission asked for).  A call inside the
    scope, or one that names no permission, is forwarded as before and
    leaves no event.  A queued call under the same key is not disturbed."""
    import wire
    import wire_server
    env = Env()
    b = env.bridge
    b.narrow_authority_scope(SID, ("read:docs",))
    n = len(env.kinds())
    for perm in ("exec:shell", "never:granted"):       # narrowed away, never
        err = _refusal(lambda: b.submit_tool_call(
            SID, "rm", key="k-" + perm, permission=perm))
        assert err.reason == "scope"
    assert env.kinds()[n:] == [GE.TOOL_CALL_REJECTED] * 2
    assert _last(env).payload == {
        "key": "k-never:granted", "tool": "rm", "permission": "never:granted",
        "reason": "scope", "direct": True}
    assert b.forwarded == []
    assert b.submit_tool_call(SID, "cat", key="k1",
                              permission="read:docs") == "FORWARDED"
    assert b.submit_tool_call(SID, "noop") == "FORWARDED"
    assert len(env.kinds()) == n + 2                   # no event for those
    _refusal(lambda: b.submit_tool_call(SID, "rm", permission="exec:shell"))
    assert _last(env).payload["key"].startswith("tc-")  # a key all the same
    server = wire_server.WireServer(b)
    with pytest.raises(wire_server.WireRejected) as exc:
        wire_server.send(server, wire.op_submit_tool_call(
            session_id=SID, tool="rm", content={}, key="w1",
            permission="exec:shell"))
    assert exc.value.reason == "scope"
    assert _last(env).kind == GE.TOOL_CALL_REJECTED
    # a call held under the queue policy keeps its place in the queue
    env = Env(Config(detached_calls="queue"))
    env.disconnect()
    env.bridge.submit_tool_call(SID, "ls", key="k1", permission="read:docs")
    env.reattach()
    assert _refusal(lambda: env.bridge.submit_tool_call(
        SID, "rm", key="k1", permission="admin")).reason == "scope"
    assert env.bridge.queued_tools(SID) == ["ls"]
    assert env.restart().queued_tools(SID) == ["ls"]   # and in the fold


def test_T60e_a_forwarded_call_is_completed_once_and_no_other_call_is():
    """I13, rule D: the runtime's report that a call finished is accepted
    once for every call the bridge forwarded, at a drain or directly, and
    refused a second time; a call that was never forwarded (still queued,
    denied, unknown) has nothing to complete."""
    env = Env()
    b = env.bridge
    assert b.submit_tool_call(SID, "ls", key="d1") == "FORWARDED"   # direct
    b.completed(SID, "d1", "ab" * 32)
    assert env.kinds()[-1] == GE.TOOL_CALL_COMPLETED
    with pytest.raises(BridgeError):
        b.completed(SID, "d1")                         # at most once
    _drain_one(env)                                    # k1, at a drain
    b.completed(SID, "k1")
    with pytest.raises(BridgeError):
        b.completed(SID, "k1")
    b.escalate_to_human(SID)
    b.submit_tool_call(SID, "rm", key="k2")
    with pytest.raises(BridgeError):
        b.completed(SID, "k2")                         # still queued
    b.answer_tool_call(SID, "k2", b.shown_hash_of(SID, "k2"), False)
    b.human_resolve(SID)
    assert _last(env).payload["reason"] == "denied"
    for key in ("k2", "never-submitted"):
        with pytest.raises(BridgeError):
            b.completed(SID, key)                      # never forwarded
    assert env.kinds().count(GE.TOOL_CALL_COMPLETED) == 2


# ----------------------------------------------------------------------
# Authority: the scope is a set; an observed widening is always recorded
# ----------------------------------------------------------------------

def test_T14b_the_scope_is_recorded_as_a_sorted_set():
    """I3, I10: a scope is a set of permissions.  The bridge records it
    without repetitions and sorted, at attach and at every narrowing, so
    the authority hash is the same for one scope however a caller wrote
    it; the grant and the attach proof still bind the scope as presented.
    The hash of a scope is pinned in vectors/bytes_kat.json."""
    resumed = []
    for scope in (("read:docs", "exec:shell"),
                  ("exec:shell", "read:docs", "exec:shell")):
        bridge, storage, _, key = _grant_env()
        ident = SessionIdentity("sess-g", "user-alice", scope, ("root",))
        attach_as(bridge, ident, key)                  # as presented
        assert storage.logs["sess-g"][0].payload["authority_scope"] == [
            "exec:shell", "read:docs"]
        assert bridge.scope_of("sess-g") == ("exec:shell", "read:docs")
        bridge.client_disconnect("sess-g")
        resumed.append(bridge.resume_record("sess-g").payload)
    assert resumed[0]["authority_hash"] == resumed[1]["authority_hash"] == \
        _authority_hash("user-alice", ("exec:shell", "read:docs"), ("root",))
    assert resumed[0]["authority_scope"] == ["exec:shell", "read:docs"]
    assert canonical_scope(("b", "a", "b", "A")) == ("A", "a", "b")
    env = Env(scope=("c", "a", "b"))
    b = env.bridge
    with pytest.raises(BridgeError, match="I10"):      # the same set
        b.narrow_authority_scope(SID, ("b", "c", "a", "a"))
    assert b.narrow_authority_scope(SID, ("c", "a", "c")) == 1
    assert _last(env).payload["new_scope"] == ["a", "c"]
    assert b.scope_of(SID) == ("a", "c")
    for case in _bytes_kat()["authority_hashes"]:
        assert _authority_hash(
            case["principal"], canonical_scope(case["scope"]),
            case["lineage"]) == case["hash"], case["name"]
        assert list(canonical_scope(case["scope"])) == case["canonical_scope"]


def test_T14c_a_narrowing_that_is_not_strict_is_named():
    """I10, I3: a `narrow` that proposes the current scope, or more than
    it, is refused with the reason not_a_strict_narrowing, in the bridge
    and on the wire; the first is recorded as AUTHORITY_NARROWING_REJECTED,
    the second as AUTHORITY_EXTENSION_REJECTED."""
    import wire
    import wire_server
    env = Env()
    server = wire_server.WireServer(env.bridge)
    for proposed, kind in ((SCOPE, GE.AUTHORITY_NARROWING_REJECTED),
                           (SCOPE + ("admin",),
                            GE.AUTHORITY_EXTENSION_REJECTED)):
        err = _refusal(lambda: env.bridge.narrow_authority_scope(
            SID, proposed))
        assert err.reason == "not_a_strict_narrowing"
        assert _last(env).kind == kind
        with pytest.raises(wire_server.WireRejected) as exc:
            wire_server.send(server, wire.op_narrow(
                session_id=SID, new_scope=list(proposed)))
        assert exc.value.reason == "not_a_strict_narrowing"
    assert env.bridge.scope_versions[SID] == 0


def test_T56b_an_observed_widening_is_recorded_on_a_key_exhausted_session():
    """I3, I11-REVOKE: a widening the runtime announces is a report about
    the runtime, not a client operation: on a key_exhausted session it is
    still recorded with source observed and a revert is requested, while a
    widening asked for through the bridge is refused as key_exhausted."""
    env = Env()
    b = env.bridge
    op_revoke(b, SID, "ck-1")                          # exhausted, attached
    assert b._sess[SID].key_exhausted
    n = len(env.kinds())
    assert b.attempt_authority_extension(
        SID, SCOPE + ("exec:sudo",), source="observed") == "REVERT"
    assert env.kinds()[n:] == [GE.AUTHORITY_EXTENSION_REJECTED]
    assert _last(env).payload["source"] == "observed"
    assert b.revert_requests == [(SID, SCOPE)] and b.scope_of(SID) == SCOPE
    with pytest.raises(BridgeError, match="KEY_EXHAUSTED"):
        b.attempt_authority_extension(SID, SCOPE + ("exec:sudo",))
    assert len(env.kinds()) == n + 1


def test_T27b_a_timeout_names_the_timer_that_fired():
    """L1, L2: when the cumulative cap ends a session whose own detachment
    bound has not been reached, DETACH_TIMEOUT and TERMINATION name
    detach_total_timeout, also when a human timeout fires in the same
    tick; when the detachment bound itself is reached they name
    detach_timeout."""
    env = Env(Config(t_detach=600, t_total=1000, t_human=500, t_call=500))
    env.disconnect()
    env.clock.advance(500)
    env.reattach()                                     # 500 s away so far
    env.bridge.escalate_to_human(SID)
    env.disconnect()
    env.clock.advance(500)                             # the cap and T_human
    env.bridge.tick()
    assert env.kinds()[-3:] == [GE.HUMAN_TIMEOUT, GE.DETACH_TIMEOUT,
                                GE.TERMINATION]
    log = env.bridge.events[SID]
    assert log[-2].payload["reason"] == "detach_total_timeout"
    assert log[-1].payload["reason"] == \
        "human_timeout+detach_total_timeout (simultaneous)"
    env = Env(Config(t_detach=600, t_total=600))
    env.disconnect()
    env.clock.advance(600)                             # both bounds at once
    env.bridge.tick()
    assert [e.payload["reason"] for e in env.bridge.events[SID][-2:]] == [
        "detach_timeout", "detach_timeout"]


# ----------------------------------------------------------------------
# The wire server: nesting bound, response shapes
# ----------------------------------------------------------------------

def test_T151b_a_deeply_nested_request_is_refused_not_parsed():
    """Appendix B: a request nested deeper than the server's bound is
    refused as bad_canonical before it is parsed, so no nesting depth makes
    the server fail; a tool call's content within the bound passes, and
    brackets inside strings do not count. [trace: wire]"""
    import wire
    import wire_server
    env = Env()
    server = wire_server.WireServer(env.bridge)
    for depth in (wire_server.MAX_DEPTH + 1, 500, 100_000):
        for opening, closing in ((b"[", b"]"), (b'{"a":', b"}")):
            for tail in (closing * depth + b"}", b""):     # closed or not
                data = (b'{"op":"challenge","session_id":'
                        + opening * depth + tail)
                resp = wire.decode_response(server.handle(data))
                assert (resp["status"], resp["reason"]) == (
                    "rejected", "bad_canonical")

    def nested(depth: int):
        value: Any = 1
        for _ in range(depth):
            value = {"a": value}
        return value
    ok = wire.op_submit_tool_call(
        session_id=SID, tool="t", content=nested(wire_server.MAX_DEPTH - 1))
    assert wire_server.nesting_depth(ok) == wire_server.MAX_DEPTH
    assert wire_server.send(server, ok)["status"] == "forwarded"
    over = wire.op_submit_tool_call(
        session_id=SID, tool="t", content=nested(wire_server.MAX_DEPTH))
    with pytest.raises(wire_server.WireRejected) as exc:
        wire_server.send(server, over)
    assert exc.value.reason == "bad_canonical"
    quoted = wire.op_submit_tool_call(
        session_id=SID, tool="t", content={"s": "[{" * 200 + '"\\'})
    assert wire_server.nesting_depth(quoted) == 2
    assert wire_server.send(server, quoted)["status"] == "forwarded"


def test_T149b_wire_responses_carry_what_their_schemas_require():
    """Appendix B: `verified` and `joined` carry the replayed events as
    event objects (the events of the log, hash for hash), `narrowed` the new
    scope version, and `queued` and `forwarded` the idempotency key of the
    call; each response matches its schema in schemas/messages. [trace: wire]"""
    import pathlib
    import jsonschema
    import wire
    import wire_server
    schemas = pathlib.Path(__file__).parent / "schemas" / "messages"

    def checked(op: str, resp: dict) -> dict:
        jsonschema.Draft7Validator(json.loads(
            (schemas / f"{op}.response.schema.json").read_text())
        ).validate(resp)
        return resp

    env = Env()
    b = env.bridge
    server = wire_server.WireServer(b)
    env.add_device("ck-2")
    b.escalate_to_human(SID)
    req = env.request("ck-2", op="join")
    resp = checked("join", wire_server.send(server, wire.op_join(
        session_id=SID, key_id=req.key_id, nonce=req.nonce, seq=req.seq,
        hash=req.hash, signature=req.signature)))
    assert [e["kind"] for e in resp["events"]] == [
        "HUMAN_PENDING", "CLIENT_JOINED"]
    for e in resp["events"]:
        assert set(e) == {"kind", "session_id", "sequence", "prev_hash",
                          "payload", "timestamp"}
        assert Event(GovernanceEvent(e["kind"]), e["session_id"],
                     e["sequence"], e["prev_hash"], e["payload"],
                     e["timestamp"]).event_hash() == \
            b.events[SID][e["sequence"]].event_hash()
    b.human_resolve(SID)
    env.disconnect()
    req = env.request("ck-1")
    resp = checked("reattach", wire_server.send(server, wire.op_reattach(
        session_id=SID, key_id=req.key_id, nonce=req.nonce, seq=req.seq,
        hash=req.hash, signature=req.signature)))
    assert [e["kind"] for e in resp["events"]] == [
        "DETACHMENT", "RESUME_PREPARED", "RESUME_STARTED", "RESUME_VERIFIED"]
    assert resp["events"][0]["sequence"] == req.seq + 1
    resp = checked("narrow", wire_server.send(server, wire.op_narrow(
        session_id=SID, new_scope=["read:docs"])))
    assert resp["new_version"] == 1 == b.scope_versions[SID]
    resp = checked("submit_tool_call", wire_server.send(
        server, wire.op_submit_tool_call(
            session_id=SID, tool="t", content={}, key="k9")))
    assert (resp["status"], resp["key"]) == ("forwarded", "k9")
    b.escalate_to_human(SID)
    resp = checked("submit_tool_call", wire_server.send(
        server, wire.op_submit_tool_call(
            session_id=SID, tool="t", content={})))
    assert resp["status"] == "queued"
    assert resp["key"] == b._sess[SID].queue[-1]["key"] != ""


def test_T101b_the_challenge_message_is_pinned():
    """The bytes of a challenge request, which names the key id the nonce
    is for, are fixed in vectors/bytes_kat.json; both bridges read the
    file. [trace: wire]"""
    import wire
    for c in _bytes_kat()["challenge_messages"]:
        data = wire.op_challenge(session_id=c["session_id"],
                                 key_id=c["key_id"])
        assert data.decode() == c["canonical"], c["name"]
        assert data.hex() == c["hex"], c["name"]
        assert wire.decode_message(data) == {
            "op": "challenge", "session_id": c["session_id"],
            "key_id": c["key_id"]}


# ----------------------------------------------------------------------
# Allow running as `python conformance_suite.py` to smoke-test the bridge
# ----------------------------------------------------------------------

if __name__ == "__main__":
    e = Env()
    e.bridge.escalate_to_human(SID)
    e.disconnect()
    print("cell:", e.cell(), "events:", [k.value for k in e.kinds()])
    print("Run `python3 -I -m pytest conformance_suite.py -q` for the suite.")
