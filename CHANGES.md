# Version History

<!-- CHANGES:CURRENT:START -->
## v0.10.4 - 2026-11-25 (current)

### Changes in this release
- **Breaking wire change.** `challenge` takes a `key_id`, and the nonce is bound to it at issue. The answer to `challenge` is the same for any key identifier, registered or not. A nonce issued for a key that was not registered at issue never verifies, however the registry changes later, and a request that presents a nonce with another `key_id` is answered as any non-authentic request. A request that was presented and refused is never accepted later. The known-answer files, vectors, schemas and wire-format text are regenerated.
- Merkle checkpoints use the RFC 9162 tree hash (domain-separated leaves and interior nodes, no duplication of a last node); the checkpoint event carries the tree size and the root.
- A direct call outside the current scope is refused with reason `scope` and recorded as `TOOL_CALL_REJECTED`.
- Soft revocation of the key being verified abandons the verification, as a hard revocation does. Operator events verify the signature first. The approval expiry is recorded per call, and an approval is valid strictly before it. A timer that expires in the tick of a request waits for the request.
- Closed limitations: pre-registration replay of a nonce, join before signature, approval revival, timer tick, soft revocation while re-attaching, key addition on a quarantined session, direct calls outside the scope, and checkpoints after the end of a session.
- Formal evidence: the TLA+ model and the Python transcription follow the changes; TLC was rerun in Docker for every configuration with no error and every model mutant killed, the Apalache base and inductive checks were rerun, and the coverage of cells and actions per configuration was measured again. The Python and Rust mutation checks kill every mutant.
- The Internet-Draft source is brought to the same text and rebuilt.
<!-- CHANGES:CURRENT:END -->

## v0.10.3 - 2026-11-21

### Changes in this release
- Republished so that the Zenodo archive of the public companion is created for this version; the paper text and the code are unchanged from the previous version.
- Review pass: every objection in the argument map now has a stated defense, and the costs the defenses concede are in the text: the model is not linked to the code by a refinement proof, and the invariant set has no operator-side hazard analysis behind it.
- Layout and publication: appendix tables that ran into the margin are narrowed, and the paper sources are published as pointers and hashes only.
- Signatures and wire format: re-attach, join, attach, client registration and operator proofs are signed under domain tags over RFC 8785 canonical bytes, pinned by known-answer files; operator signatures are bound to the bridge and the log position; the wire layer is served by both reference runners, with typed reasons.
- Key lifecycle and registry: revocation, key exhaustion (timers keep running), operator key addition and termination; the registry is scoped per session, recorded in the log and repaired from it on recovery; attach needs a grant that binds the public key and a proof of possession; a second signature scheme (ECDSA P-256) beside Ed25519.
- Hardening: a challenge never evicts a live nonce, unauthenticated failures are bounded, rejections for unknown, terminated and quarantined sessions are uniform, the I14 approval binds the tool, permission and content, a malformed log quarantines only its session, and NaN or negative timers are refused.
- Formal evidence: the TLA+ model has the key lifecycle and an explicit attacker with a bounded nonce book; TLC was rerun with every model mutant killed; an Apalache inductive check of a typed single-session model covers the state invariants and step properties; a names-level check compares the inventories of the two models (constants, variables, operators, conjunct names), not their bodies.
- Evidence tooling: the tests table, vector table, comparison matrix and invariant traceability matrix are generated and checked; mutant kills are attributed to tests and the mutation checks run with controls on both runners; fault-injection and verification-cost measurements; a standalone comparison section and a signature-scheme extension section.
- Limits stated as limits: truncation of the last log events, unsigned approvals, the live-nonce budget residual, reattach enumeration of live sessions, and the same-author caveat.

Initial scaffolded version. No substantive changes yet recorded.

<!--
Template for subsequent versions:

## vX.Y - DD Month YYYY
Changes from vW.Z:
- (a) Short description of the change, written as a reader-facing note.
- (b) Reference the section or paragraph affected (e.g. "compressed Section 5.2
      by approximately 30 percent").
- (c) ... etc.
-->
