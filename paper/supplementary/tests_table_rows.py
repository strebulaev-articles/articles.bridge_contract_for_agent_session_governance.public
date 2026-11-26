"""Rows of the paper's tests table (tab:tests): which tests, which invariants,
what they check. tests_table.py checks these against conformance_suite.py and
generates ../sections/generated_tests.tex. Edit prose here, not in the paper."""

ROWS = [
    (r"""T1, T7, T10, T11, T19c--T22, T52""",
     r"""I1, I4, I5, I7, I11""",
     r"""Detach emits \texttt{RESUME\_PREPARED} before the cell changes; an
authentic re-attach goes through RESUMING, emits \texttt{RESUME\_VERIFIED}
only on RESUMING $\to$ ATTACHED, and replays exactly the events after the
acknowledged prefix; a history that is not a prefix of the chain is
refused without changing state; a request while RESUMING is refused;
disconnect during resume returns to DETACHED; a broken chain during
resume quarantines the session (T22--T22d); a client resumes however long it was away (T10, T31),
which a held token of limited lifetime could not guarantee."""),
    (r"""T2, T25""",
     r"""I2, I13""",
     r"""Calls queue under $\textsc{Pend}$ in every attachment, are forwarded only
in $(\textsc{Att},\textsc{None})$, and drain with one
\texttt{TOOL\_CALL\_DRAINED} each."""),
    (r"""T3, T12, T15, T15b, T56""",
     r"""I3, I10""",
     r"""Widening is rejected in every active cell and emits
\texttt{AUTHORITY\_EXTENSION\_REJECTED}; a widening the runtime announces
itself is reported with source \texttt{observed}, the bridge's record is
unchanged and a revert is requested; narrowing is allowed everywhere as
one event, and a narrowing made while the client was away does not fail
its re-attach."""),
    (r"""T4, T40""",
     r"""I6""",
     r"""Every mutating operation fails after termination, including across a
restart."""),
    (r"""T5""",
     r"""I5""",
     r"""A tampered or forged event is detected by chain verification."""),
    (r"""T6, T6b, T26--T29, T30b--T30e""",
     r"""L1, L2, I6""",
     r"""Detach and human timeouts, their anchors, simultaneous expiry, and the
zero-timeout edge case; a resolve in the tick of $T_{\text{human}}$ that loses to
the timeout; a human wait that outlasts $T_{\text{detach}}$
only while the client is attached; the cumulative cap across episodes,
across restarts and not counting time attached or resuming."""),
    (r"""T8, T9""",
     r"""A2, I1--I3, I5, I6, I10, I11, I14, I15""",
     r"""Property-based: gap-free sequences, and the invariants hold after every
action of a random sequence, with the cell and the client set equal to
the fold of the log."""),
    (r"""T13, T13b, T30, T31""",
     r"""I9, I11""",
     r"""An expired nonce is rejected without terminating and without revealing
more than a bad signature; the timer bounds are enforced and derived."""),
    (r"""T22--T22d, T38""",
     r"""I5, I12""",
     r"""A chain failure after an accepted re-attach, and a recovery failure,
quarantine the session: the failure is recorded, nothing terminates, no
operation or timer acts on it, a restart does not lift it, and a
presenter without a registered key cannot cause it."""),
    (r"""T57--T59b (vectors V33--V37)""",
     r"""I2, I14""",
     r"""A call outside an escalation is refused by default; under the queue
variant it is held until answered after re-attach; under the forward
variant only allowlisted, in-scope permissions are forwarded; while an
escalation is pending nothing is forwarded under any variant."""),
    (r"""T60--T60d (vectors V38--V40)""",
     r"""I12, I13""",
     r"""A drained call awaits delivery and completion; an unacknowledged call is
forwarded again after a restart, with the same key and without a second
drain, only in $(\textsc{Att},\textsc{None})$."""),
    (r"""T61""",
     r"""A6, I2""",
     r"""Escalations coalesce: a second one is audited, changes no cell and does
not restart $T_{\text{human}}$; one resolution ends them all."""),
    (r"""T62 (vector V43)""",
     r"""A6""",
     r"""A host clock that went backwards across a restart counts as no time
elapsed, and committed timestamps never decrease."""),
    (r"""T43 (vector V41)""",
     r"""I13, I14""",
     r"""An approval given while the client is away lapses after
$T_{\text{approve}}$: the call expires on re-attach and is not
forwarded."""),
    (r"""T19 (vector V42)""",
     r"""I11""",
     r"""A request refused as \texttt{resume\_in\_progress} spends its nonce."""),
    (r"""T14""",
     r"""I10""",
     r"""\texttt{scope\_version} increments on each strict narrowing; no-op
narrowing is rejected."""),
    (r"""T16""",
     r"""I8""",
     r"""A transport-reported 0-RTT replay is rejected, cell unchanged."""),
    (r"""T17--T19b, T51""",
     r"""I11""",
     r"""The signature covers every field; the session, a nonce and the chain (a
bearer) are not enough; a consumed, unknown or foreign-session nonce is
never accepted, and an authentic request spends its nonce even when
rejected later; issuing a challenge writes nothing to the log."""),
    (r"""T23, T24""",
     r"""I2, I13""",
     r"""Human resolution while detached keeps the queue and drains only after
verification."""),
    (r"""T32--T40""",
     r"""I7, I12""",
     r"""A failed append changes nothing; nothing is forwarded before its drain
event is durable; restart recovers every cell as detached with an empty
client set, voids outstanding nonces, restarts timers, applies elapsed
timeouts, and fails on a broken chain or a lost key registry."""),
    (r"""T41--T45""",
     r"""I13""",
     r"""Idempotency keys, queue limit, call expiry, approval expiry, and
revalidation of the current scope at drain; the resume record carries the
queue."""),
    (r"""T47--T50""",
     r"""I15""",
     r"""A second device joins an attached session; only the last departure
detaches; an added key resumes, an unregistered one is refused, and
registration needs a connected client; a scope narrowed from one device
reaches the other through the replay."""),
    (r"""T119--T123 (vectors V105--V108b)""",
     r"""I15""",
     r"""A client registration needs a fresh signature by a connected, unrevoked
key over the operation, session, new key and nonce: unsigned, forged,
other-operation, replayed, expired and revoked-key requests are refused with
a named reason and commit nothing; an authorising key the session does not
register is answered as a bad signature, and that a registered key is not
connected is said only after its signature verified; the signed bytes are
pinned by known answers."""),
    (r"""T124--T125""",
     r"""I11""",
     r"""The attach proof of possession is the bytes of the tagged tuple that names
the bridge, the session and the key with its scheme tag, pinned by known
answers that a changed field does not verify against; the wire constructors
for attach and client registration carry the scheme."""),
    (r"""T126 (vector V109)""",
     r"""I11 (a)""",
     r"""\texttt{challenge} refuses an unknown, a terminated and a quarantined
session with one text that names neither the session nor its state."""),
    (r"""T127 (vector V110)""",
     r"""I11 (a)""",
     r"""\texttt{reattach} and \texttt{join} refuse an unknown, a terminated and a
quarantined session with one text that names neither the session nor its
state."""),
    (r"""T128, T128b (vectors V111, V111b, V111c)""",
     r"""I11-REVOKE, L1""",
     r"""A key revoked while its re-attach is verified is not the attached
client afterwards: the re-attach is abandoned (detached, resume record
rewritten) and \texttt{complete\_resume} refuses, for a soft revocation
exactly as for a hard one; the revocation of another key leaves the
verification alone. When the key was the only one the session is detached
and \texttt{key\_exhausted}, and $T_{\text{detach}}$ ends it."""),
    (r"""T138--T140 (vectors V121--V126; \texttt{vectors/bytes\_kat.json})""",
     r"""I-OPERATOR""",
     r"""An operator signature is bound to the bridge identity and to the log
position (sequence and hash of the last event) at signing: one made for
another bridge, or at an earlier or other position, is refused for a
revocation, a key addition and a termination, and the signed bytes and
signatures are pinned by known answers that a changed field does not verify
against."""),
    (r"""T141--T142 (vectors V127, V128)""",
     r"""I11, I15""",
     r"""A re-attach on an attached session is refused as
\texttt{already\_attached} (rejected, nonce spent, no change of cell) and join
is the way in; the reason is given only to an authentic request, so an
unauthenticated one still gets its own reason."""),
    (r"""T129--T130 (vectors V112, V113)""",
     r"""I14""",
     r"""The approval hash covers the tool and the permission as well as the
content, so approving the arguments of one call does not release another
under a different tool name; the bridge retains the hashed request in the
log and forwards exactly that request, also when it forwards it again after
a restart."""),
    (r"""T131 (vector V114)""",
     r"""rule Q""",
     r"""A log that cannot be replayed (no \texttt{ATTACHED} first, or one
without its fields) quarantines its own session only; the other sessions are
recovered and nothing is appended to the malformed log."""),
    (r"""T132""",
     r"""I11-REVOKE""",
     r"""Unsigned revocation requests are written up to a bound per session and
refused past it without a log entry; a signed revocation restores the
budget."""),
    (r"""T133""",
     r"""Appendix B""",
     r"""The reference wire server calls an authentication hook for each unsigned
op and refuses it as \texttt{unauthenticated} on a false answer; signed ops
do not reach the hook."""),
    (r"""T53--T55""",
     r"""I14""",
     r"""A matching answer drains and the event repeats the hash; a changed view,
a denial or no answer block the forward; the first answer is final."""),
    (r"""T63--T66, T63b (vectors V52--V54, V88, V89; Python only)""",
     r"""I-CHECKPOINT""",
     r"""A \texttt{CHECKPOINT} is emitted after the configured number of events
since the last checkpoint and after $T_{\text{cp}}$; its root matches the
recomputed Merkle root; the receipt is optional. The vectors expect the
\texttt{CHECKPOINT} event in the log."""),
    (r"""T97--T100 (vectors V86, V87)""",
     r"""I11 (f), (g)""",
     r"""Keyless challenges cannot evict a live nonce and are refused once the
limit is reached; spent and expired nonces make room; unauthenticated
rejections are recorded only up to the bound and are refused uniformly;
the genuine re-attach is accepted after both floods."""),
    (r"""T101--T104 (vectors V90--V94; \texttt{vectors/bytes\_kat.json})""",
     r"""I11, I5""",
     r"""RFC~8785 known answers (non-ASCII strings, escapes, UTF-16 key order,
numbers, inputs with no canonical form); pinned event and content
hashes; the exact bytes and Ed25519 signature of a re-attach and a join
proof; a proof made for the other operation, for another key id, over
the untagged tuple or without the key id is refused as
\texttt{bad\_signature}."""),
    (r"""T105--T112, T143 (vectors V95, V96, V102--V104, V129)""",
     r"""I11, I12""",
     r"""A key identifier is scoped to its session: a second, validly granted
session that reuses it neither replaces the first session's key nor can
re-attach to the first session, and the owner is not locked out;
\texttt{ATTACHED}, \texttt{CLIENT\_ADDED} and \texttt{OPERATOR\_ADD\_KEY}
carry the scheme tag and public key; recovery repairs the registry from
the log, which is the source of truth: an entry that differs is replaced, one
the log does not record (a crash between the registry write and the event
commit) is dropped, a missing one is written back, and
\texttt{BRIDGE\_RECOVERED} names the keys repaired; a refused append leaves
no registry entry."""),
    (r"""T113--T118 (vectors V97--V101)""",
     r"""I-GRANT, I11""",
     r"""Attach needs a proof of possession by the registered key, under its own
domain tag and bound to the bridge, the session and the key; a missing
proof, a proof by another key and a proof made for another bridge are
refused as \texttt{possession\_invalid}; the grant binds the public key
and the bridge, so a grant seen in transit cannot be used with another
public key under the same key identifier or at another bridge
(\texttt{grant\_invalid})."""),
    (r"""T67--T69, T75, T76, T86, T87""",
     r"""I11-REVOKE, I11""",
     r"""A soft revocation does not detach an active client; a hard revocation
detaches the revoked key's client and keeps the others connected; a
revoked key is refused on re-attach, also when revoked after its
challenge; two-phase rotation; revoked keys survive a restart."""),
    (r"""T70--T74, T88, T89""",
     r"""I11-REVOKE, I6""",
     r"""Revoking the last key enters \texttt{key\_exhausted}; client operations are
refused there; the operator adds a recovery key or terminates; the state
and the recovery key survive a restart; refused revocations commit
nothing."""),
    (r"""T134--T137 (vectors V115--V120)""",
     r"""I11-REVOKE, L1, L2""",
     r"""The timers of a \texttt{key\_exhausted} session keep running: it ends
after $T_{\text{detach}}$ (a client operation on an expired session reports
the end, not the exhaustion), an operator key must arrive before the bound,
a restart treats the session like any other and restarts $T_{\text{detach}}$,
a pending escalation times out, and a session whose revoked key is still
connected detaches on transport loss and then ends."""),
    (r"""T77--T81""",
     r"""I-GRANT""",
     r"""An attach is accepted only with a valid grant, which is bound to the
session, scope lineage and key and carries its own domain tag; without
a grant verifier every attach is refused."""),
    (r"""T82--T85""",
     r"""I11""",
     r"""P-256 proof of possession is accepted and forged proofs are rejected; a
scheme tag is not interchangeable; a known-answer signature from an
independent signer verifies; a server takes only a client's public key."""),
    (r"""T144""",
     r"""I11""",
     r"""A test-only further scheme tag is accepted at attach through the
pluggable verifier, with no change to the bridge, and refused where the
verifier lacks the tag (extension, Section~\ref{sec:ext-schemes})."""),
    (r"""T145, T146 (vector V130)""",
     r"""I11-REVOKE, I6""",
     r"""An unsigned terminate of a key-exhausted session is refused and commits
nothing; only the operator's signed termination ends it. The refusal
defers to the timers (an expired session is found ended) and to
quarantine (the operator's way out of quarantine stays open)."""),
    (r"""T147 (vector V131)""",
     r"""I11, I15""",
     r"""A re-attach naming an unregistered key and one with a bad signature get
the same refusal, so the answer does not list the registered key ids;
the log keeps the true reason."""),
    (r"""T148--T151 (vector V132)""",
     r"""wire, I-OPERATOR""",
     r"""The wire server creates a session from an \texttt{attach} message
(refusing a missing grant or proof by name), answers \texttt{resolve} and
\texttt{extend} (the scope in force, a requested revert), verifies the
operator events from the message and names their refusals, and names the
key-exhausted refusal of a bare terminate."""),
    (r"""T152--T155 (vectors V133, V134)""",
     r"""I11, I11g, I15, wire""",
     r"""Two sessions on one bridge that hold the same client key share
nothing but the bridge: a nonce issued for one session is unknown to the
other for a re-attach, a join and a registration, and spent by neither
refusal; the budgets of challenges, unauthenticated rejections and
revocation requests are kept per session and are not restored by a
request in another; a tool call key means a call only in its session,
across a restart; every unsigned wire op is asked of the authentication
hook with the message that names its session, and a hook that accepts one
session's caller does not open another."""),
    (r"""T156--T158""",
     r"""I11, I14""",
     r"""Cases the mutation check could not see while its scratch copies failed
on their own: recovery leaves the registry of a quarantined session as
found; ATTACHED records the scheme of the first key, so a lost entry is
written back with it; a call held while no client is attached carries the
hash of the call a client is shown."""),
    (r"""T90--T96 (vectors V75--V85)""",
     r"""I-OPERATOR""",
     r"""Revocation, key addition and termination require a valid operator
signature bound to the session, key and operation; a bridge without an
operator verifier refuses them; the signature is logged and survives
recovery; the operator domain tags separate the signatures."""),
    (r"""T46""",
     r"""---""",
     r"""The derived view of named states."""),
    (r"""T152b--T152i (vectors V62--V62f, V09b, V136)""",
     r"""I11, I8, I15""",
     r"""A nonce is bound to the key id its challenge named. One issued for
another key id is refused for a join, a registration and a re-attach though
the signature verifies; one issued for a key id before the key was
registered never verifies, after a \texttt{CLIENT\_ADDED} and after an
\texttt{OPERATOR\_ADD\_KEY} alike; both are answered as a bad signature,
recorded as \texttt{nonce\_binding}, and leave the nonce to the key it was
issued for. \texttt{challenge} answers every key id in the same way and
against the same limit. Over random interleavings a request is accepted at
most on its first presentation (T152f). A request the transport flags as a
replay has spent its nonce if it was authentic. The limits of I11 (f) and
(g) hold with bound nonces. A registration is verified before the lifecycle is
named: an unauthentic caller is answered as a bad signature whether the
session is unknown or terminated (T152i)."""),
    (r"""T141b, T71b, T7b (vectors V90b--V90d)""",
     r"""I11 (a), I15, I4""",
     r"""A join is verified before the attachment is answered: one that does
not verify gets the same answer and the same record on an attached, a
detached and a resuming session; one that verifies is refused as
\texttt{not\_attached} or \texttt{resume\_in\_progress}, has spent its
nonce, and never starts a re-attach. A key-exhausted session answers a
request that does not verify like any other session. A negative sequence
number is a malformed request and is not logged."""),
    (r"""T26b (vectors V16b--V16d)""",
     r"""L1, L2, I11""",
     r"""A re-attach in the tick in which $T_{\text{detach}}$ or the cumulative
cap expires is processed first: accepted, the timer does not fire; refused,
it fires after the rejection. A timer that expired earlier has ended the
session, and the request gets the uniform refusal. A human timer of the same
tick still applies after the re-attach."""),
    (r"""T43b, T43c (vectors V41b--V41d)""",
     r"""I13""",
     r"""The approval expiry is kept per call: a call whose approval lapsed is
expired at the drain though a later escalation was resolved in between, also
across a restart; an approval is valid strictly before
$T_{\text{approve}}$."""),
    (r"""T66b--T66f (vectors V54b, V54c; Python only; \texttt{vectors/bytes\_kat.json})""",
     r"""I-CHECKPOINT, I5, I6""",
     r"""With checkpoints on, no \texttt{CHECKPOINT} follows a
\texttt{TERMINATION}, none is appended to a quarantined session and none is
taken over a log whose chain does not verify; the invariants of T9 hold with
checkpoints on. The root over the event hashes is the Merkle tree hash of
RFC~9162, with known answers for roots and audit paths."""),
    (r"""T146b, T146c (vectors V114b, V137)""",
     r"""rule Q""",
     r"""An operator key addition is refused on a quarantined session and
registers nothing. The operator's signed termination of a session that is
quarantined and key-exhausted is recorded as \texttt{OPERATOR\_TERMINATION},
then \texttt{TERMINATION}."""),
    (r"""T69b, T19d, T99b (vectors V90c, V70b)""",
     r"""I11-REVOKE, I11""",
     r"""A revoked key cannot join; the revocation is looked at only after the
signature verified, and a revoked key spends only the nonce issued to it; a
request for an unregistered key leaves the nonce; refusals of a revoked key
are recorded only up to the bound of I11 (g)."""),
    (r"""T89b, T150b (vectors V73b, V132b)""",
     r"""I11-REVOKE, I-OPERATOR""",
     r"""A revocation names rotation or compromise and is made once per key.
The operator operations verify the signature before anything is said about
the session, so a caller without it gets one answer for every session, key
and state; a termination of a session that is over is refused."""),
    (r"""T5b, T61b, T21b, T45b (vectors V12b, V23b, V21b)""",
     r"""I5, I2, I15, I1""",
     r"""The chain check reads the sequence numbers; a resolution needs a
pending escalation; the disconnect of another key does not abandon a
re-attach in verification; the resume record carries the scope and the
scope version in force."""),
    (r"""T41b, T41c, T25b, T60e (vectors V13b, V15b, V38b)""",
     r"""I13, I3""",
     r"""A duplicate key returns the queued call and commits nothing; a
generated key never collides with a supplied one; a direct call outside the
current scope is refused with the reason \texttt{scope} and recorded, and
leaves a queued call under the same key alone; completion is accepted once
for a forwarded call and refused for a call that was never forwarded."""),
    (r"""T14b, T14c, T56b, T27b (vectors V06b, V06c, V27b, V31b)""",
     r"""I3, I10, L1""",
     r"""The scope is recorded as a sorted set, so the authority hash does not
depend on how a caller wrote it; a narrowing that is not strict is refused
as \texttt{not\_a\_strict\_narrowing}; a widening the runtime announces is
recorded on a key-exhausted session; a timeout names the timer that
fired."""),
    (r"""T151b, T149b, T101b (\texttt{vectors/bytes\_kat.json})""",
     r"""Appendix B""",
     r"""The wire server refuses a request nested beyond its bound before
parsing it; \texttt{verified} and \texttt{joined} carry event objects,
\texttt{narrowed} the new version, \texttt{queued} and \texttt{forwarded}
the key, each matching its schema; the bytes of a challenge request, which
names the key id, are pinned."""),
]
