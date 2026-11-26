# Version History

<!-- CHANGES:CURRENT:START -->
## v0.10.5 - 2026-11-26 (current)

### Changes in this release
- **Timers.** A resolve that arrives in the tick in which `T_human` expires loses to the timeout: the bridge ends the session with `HUMAN_TIMEOUT` and `TERMINATION`, refuses the resolve and answers it `terminated`. The model, the vectors, both bridges and the text state it, and a model mutant and a test cover it.
- **Registration of a further key.** `add_client` verifies the signature first; the state of the session (unknown, terminated, quarantined, key exhausted) is named only to a caller whose signature verified, and any other caller is answered `bad_signature`.
- **End of a session.** The order of the end events is fixed, and an operator termination of a quarantined, key-exhausted session is recorded.
- Formal evidence: TLC was rerun in Docker for every configuration with no error, every TLC and Apalache mutant is killed, and the traceability table and the TLC table are regenerated from the new logs.
- Publication: the arXiv source package is built by `make arxiv` from a clean directory and test-compiled without BibTeX; the status text names the posted Internet-Draft and the back matter says where code, vectors and model are.
- The Internet-Draft source carries the changed rules and is rebuilt as a new revision.
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
