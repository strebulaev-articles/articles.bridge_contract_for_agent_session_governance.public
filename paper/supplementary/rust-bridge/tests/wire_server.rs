//! The wire front-end (`bridge_contract::wire_server`): the envelope, the
//! reasons, the authentication hook and the signed ops, sent as bytes to a
//! bridge. The vectors run through the same server in `vectors.rs`
//! (`all_vectors_pass_through_the_wire_server`); these tests are the
//! front-end rules the vectors do not name, so that the Rust mutation check
//! (`../mutation_check_rust.py`) is killed by `cargo test` on them.

#[allow(dead_code)]
mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::sync::Arc;

use bridge_contract::wire_server::{send, WireServer};
use bridge_contract::*;
use serde_json::{json, Value};

struct Fixture {
    bridge: Bridge,
    key: ClientKey,
}

fn fixture() -> Fixture {
    let operator = OperatorKey::new(&[7u8; 32]);
    let mut bridge = Bridge::new(MemStorage::new(), FakeClock::new(1000.0), Arc::new(SchemeVerifier), Config::default())
        .expect("bridge")
        .with_grant_verifier(Arc::new(OperatorGrantVerifier::new(operator.public_key())));
    let key = ClientKey::new("ck-1", &[1u8; 32]);
    let id = SessionIdentity {
        session_id: "s".into(),
        principal_id: "user-alice".into(),
        authority_scope: vec!["read".into(), "write".into()],
        task_lineage: vec![],
    };
    common::attach_ok(&mut bridge, &id, &key).expect("attach");
    Fixture { bridge, key }
}

fn reason(server: &WireServer, b: &mut Bridge, data: Vec<u8>) -> String {
    send(server, b, &data).expect_err("a refusal")
}

fn nonce(server: &WireServer, b: &mut Bridge) -> String {
    send(server, b, &wire::op_challenge("s", "ck-1")).expect("challenge")["nonce"].as_str().unwrap().to_string()
}

fn tip(b: &Bridge) -> (i64, String) {
    let ev = b.events("s").pop().unwrap();
    (ev.sequence as i64, ev.hash())
}

fn reattach_bytes(key: &ClientKey, n: &str, seq: i64, hash: &str) -> Vec<u8> {
    let r = key.request_for(ResumeOp::Reattach, "s", n, seq, hash);
    wire::op_reattach("s", &r.key_id, &r.nonce, r.seq as u64, &r.hash, &r.signature)
}

#[test]
fn a_request_that_is_not_canonical_json_is_refused() {
    let server = WireServer::new();
    let mut f = fixture();
    let before = f.bridge.events("s").len();
    for data in [
        // members out of order
        br#"{"session_id":"s","op":"challenge","key_id":"ck-1"}"#.to_vec(),
        // a challenge that names no key id
        wire::encode_message("challenge", Some("s"), &serde_json::Map::new()),
        // nested beyond the bound
        [br#"{"op":"challenge","session_id":"#.as_slice(), &[b'['; 500], &[b']'; 500], b"}"].concat(),
        // truncated
        br#"{"op":"challenge","session_id":"s""#.to_vec(),
        // not an object, and no op
        b"[]".to_vec(),
        br#"{"session_id":"s"}"#.to_vec(),
    ] {
        assert_eq!(reason(&server, &mut f.bridge, data), "bad_canonical");
    }
    assert_eq!(f.bridge.events("s").len(), before);
}

#[test]
fn a_request_with_a_missing_or_mistyped_field_is_refused_as_bad_canonical() {
    let server = WireServer::new();
    let mut f = fixture();
    let missing = wire::canonical_bytes(&json!({"op": "delivered", "session_id": "s"}));
    assert_eq!(reason(&server, &mut f.bridge, missing), "bad_canonical");
    let mistyped = wire::canonical_bytes(&json!({"op": "narrow", "session_id": "s", "new_scope": "read"}));
    assert_eq!(reason(&server, &mut f.bridge, mistyped), "bad_canonical");
    let bad_hex = wire::canonical_bytes(&json!({
        "op": "add_client", "session_id": "s", "via_key_id": "ck-1", "new_key_id": "ck-2",
        "scheme": "ed25519", "new_public_key": "zz", "nonce": "n", "signature": "s"}));
    assert_eq!(reason(&server, &mut f.bridge, bad_hex), "bad_canonical");
}

#[test]
fn ops_the_front_end_does_not_serve_are_unsupported() {
    let server = WireServer::new();
    let mut f = fixture();
    let before = f.bridge.events("s").len();
    for data in [
        wire::op_restart(),
        wire::op_tick(Some("s")),
        wire::encode_message("operator_revoke", Some("s"), &serde_json::Map::new()),
    ] {
        assert_eq!(reason(&server, &mut f.bridge, data), "unsupported_op");
    }
    assert_eq!(f.bridge.events("s").len(), before);
}

#[test]
fn an_unknown_session_gets_the_uniform_refusal() {
    let server = WireServer::new();
    let mut f = fixture();
    assert_eq!(reason(&server, &mut f.bridge, wire::op_challenge("nobody", "ck-1")), "refused");
    let req = f.key.request_for(ResumeOp::Reattach, "nobody", &"ab".repeat(16), 0, &"00".repeat(32));
    let data = wire::op_reattach("nobody", &req.key_id, &req.nonce, 0, &req.hash, &req.signature);
    assert_eq!(reason(&server, &mut f.bridge, data), "refused");
    assert_eq!(reason(&server, &mut f.bridge, wire::op_terminate("nobody", "terminated")), "unknown_session");
}

#[test]
fn the_authentication_hook_guards_the_unsigned_ops_only() {
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let server = WireServer::new().with_authenticate(Box::new(move |op, msg| {
        seen.fetch_add(1, Ordering::SeqCst);
        assert_eq!(msg["op"], op);
        false
    }));
    let mut f = fixture();
    let before = f.bridge.events("s").len();
    // a refused caller changes nothing
    for data in [
        wire::op_disconnect("s", "client_disconnect", Some("ck-1")),
        wire::op_escalate("s", None),
        wire::op_submit_tool_call("s", "shell", &json!({"cmd": "ls"}), Some("k1"), None),
        wire::op_answer_tool_call("s", "k1", "h", "approve"),
        wire::op_delivered("s", "k1"),
        wire::op_completed("s", "k1", None),
        wire::op_narrow("s", &["read"]),
        wire::op_terminate("s", "terminated"),
    ] {
        assert_eq!(reason(&server, &mut f.bridge, data), "unauthenticated");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 8);
    assert_eq!(f.bridge.events("s").len(), before);
    assert_eq!(f.bridge.cell_of("s").names(), vec!["Att", "None"]);
    // the signed ops and the challenge carry their own proof: the hook is
    // not asked, and an op the server does not serve is not asked either
    nonce(&server, &mut f.bridge);
    assert_eq!(reason(&server, &mut f.bridge, wire::op_restart()), "unsupported_op");
    assert_eq!(calls.load(Ordering::SeqCst), 8);
}

#[test]
fn a_hook_that_accepts_lets_the_op_through() {
    let server = WireServer::new().with_authenticate(Box::new(|_, _| true));
    let mut f = fixture();
    send(&server, &mut f.bridge, &wire::op_disconnect("s", "client_disconnect", Some("ck-1"))).expect("disconnected");
    assert_eq!(f.bridge.cell_of("s").names(), vec!["Det", "None"]);
}

#[test]
fn a_signed_reattach_is_verified_from_the_envelope() {
    let server = WireServer::new();
    let mut f = fixture();
    let (seq, hash) = tip(&f.bridge);
    send(&server, &mut f.bridge, &wire::op_disconnect("s", "client_disconnect", Some("ck-1"))).expect("disconnected");

    // a forged signature is refused and the session stays detached
    let n = nonce(&server, &mut f.bridge);
    let other = ClientKey::new("ck-1", &[9u8; 32]);
    assert_eq!(reason(&server, &mut f.bridge, reattach_bytes(&other, &n, seq, &hash)), "bad_signature");
    assert_eq!(f.bridge.cell_of("s").names(), vec!["Det", "None"]);

    // the real signature with a fresh nonce is accepted
    let n = nonce(&server, &mut f.bridge);
    let ok = send(&server, &mut f.bridge, &reattach_bytes(&f.key, &n, seq, &hash)).expect("verified");
    assert_eq!(ok["status"], "verified");
    assert_eq!(ok["session_id"], "s");
    assert!(ok["events"].is_array());
    assert_eq!(f.bridge.cell_of("s").names(), vec!["Att", "None"]);

    // the nonce is spent; a re-attach on an attached session is refused
    let (seq, hash) = tip(&f.bridge);
    assert_eq!(reason(&server, &mut f.bridge, reattach_bytes(&f.key, &n, seq, &hash)), "nonce_used");
    let n = nonce(&server, &mut f.bridge);
    assert_eq!(reason(&server, &mut f.bridge, reattach_bytes(&f.key, &n, seq, &hash)), "already_attached");
}

#[test]
fn add_client_and_join_carry_their_own_proofs() {
    let server = WireServer::new();
    let mut f = fixture();
    let second = ClientKey::new("ck-2", &[2u8; 32]);
    let public = second.public();
    let add = |n: &str, sig: &str, via: &str| {
        wire::op_add_client("s", via, "ck-2", &public.scheme, &hex::encode(&public.material), n, sig)
    };

    // a signature by another key, then by a key that is not connected
    let n = nonce(&server, &mut f.bridge);
    let forged = ClientKey::new("ck-1", &[9u8; 32]).sign_add_client("s", &public, &n);
    assert_eq!(reason(&server, &mut f.bridge, add(&n, &forged, "ck-1")), "bad_signature");
    let n = nonce(&server, &mut f.bridge);
    let sig = f.key.sign_add_client("s", &public, &n);
    assert_eq!(reason(&server, &mut f.bridge, add(&n, &sig, "ck-0")), "bad_signature"); // an unregistered key is a bad signature

    // the connected key's signature is accepted once; the nonce cannot be replayed
    let n = nonce(&server, &mut f.bridge);
    let sig = f.key.sign_add_client("s", &public, &n);
    let ok = send(&server, &mut f.bridge, &add(&n, &sig, "ck-1")).expect("added");
    assert_eq!(ok["status"], "added");
    assert_eq!(reason(&server, &mut f.bridge, add(&n, &sig, "ck-1")), "nonce_used");

    // the new key joins the attached session, with a nonce issued for it
    let n = send(&server, &mut f.bridge, &wire::op_challenge("s", "ck-2")).expect("challenge")["nonce"].as_str().unwrap().to_string();
    let (seq, hash) = tip(&f.bridge);
    let r = second.request_for(ResumeOp::Join, "s", &n, seq, &hash);
    let joined = send(&server, &mut f.bridge, &wire::op_join("s", &r.key_id, &r.nonce, seq as u64, &hash, &r.signature)).expect("joined");
    assert_eq!(joined["status"], "joined");
    assert_eq!(f.bridge.client_set("s"), vec!["ck-1", "ck-2"]);
}

#[test]
fn tool_call_outcomes_and_refusal_reasons_are_named() {
    let server = WireServer::new();
    let mut f = fixture();
    let call = |key: &str| wire::op_submit_tool_call("s", "shell", &json!({"cmd": "ls"}), Some(key), None);
    // an attached session forwards
    let first = send(&server, &mut f.bridge, &call("k1")).expect("forwarded");
    assert_eq!(first["status"], "forwarded");
    // delivery and completion of a call nobody awaits are refused
    assert_eq!(reason(&server, &mut f.bridge, wire::op_delivered("s", "nope")), "refused");
    assert_eq!(reason(&server, &mut f.bridge, wire::op_completed("s", "nope", Some("r"))), "refused");
    send(&server, &mut f.bridge, &wire::op_narrow("s", &["read"])).expect("narrowed");
    assert_eq!(f.bridge.scope_of("s"), vec!["read"]);
    // a widening is refused
    assert_eq!(reason(&server, &mut f.bridge, wire::op_narrow("s", &["read", "admin"])), "not_a_strict_narrowing");

    // detached with no escalation pending, the default policy refuses
    send(&server, &mut f.bridge, &wire::op_disconnect("s", "client_disconnect", Some("ck-1"))).expect("disconnected");
    assert_eq!(reason(&server, &mut f.bridge, call("early")), "refused");

    // the human is pending: calls queue, a duplicate key is rejected as such,
    // and a full queue is rejected as such
    send(&server, &mut f.bridge, &wire::op_escalate("s", None)).expect("escalated");
    let mut statuses = vec![];
    for i in 0..Config::default().q_max + 1 {
        match send(&server, &mut f.bridge, &call(&format!("q{i}"))) {
            Ok(v) => statuses.push(v["status"].as_str().unwrap().to_string()),
            Err(r) => statuses.push(r),
        }
    }
    assert_eq!(statuses[0], "queued");
    assert_eq!(reason(&server, &mut f.bridge, call("q0")), "duplicate_key");
    assert_eq!(statuses.last().unwrap(), "queue_full");

    // the end of the session is named for every later op
    send(&server, &mut f.bridge, &wire::op_terminate("s", "terminated")).expect("terminated");
    assert_eq!(reason(&server, &mut f.bridge, call("late")), "terminated");
    assert_eq!(reason(&server, &mut f.bridge, wire::op_challenge("s", "ck-1")), "refused");
}

#[test]
fn a_response_is_canonical_json_with_the_session_id() {
    let server = WireServer::new();
    let mut f = fixture();
    let bytes = server.handle(&mut f.bridge, &wire::op_challenge("s", "ck-1"));
    let v: Value = wire::decode_response(&bytes).unwrap();
    assert_eq!(wire::canonical_bytes(&v), bytes);
    assert_eq!(v["status"], "nonce");
    assert_eq!(v["session_id"], "s");
    assert!(v["ttl_seconds"].is_number());
}

fn operator() -> OperatorKey {
    OperatorKey::new(&[7u8; 32])
}

fn identity(sid: &str) -> SessionIdentity {
    SessionIdentity {
        session_id: sid.into(),
        principal_id: "user-alice".into(),
        authority_scope: vec!["read".into(), "write".into()],
        task_lineage: vec![],
    }
}

fn attach_bytes(b: &Bridge, id: &SessionIdentity, key: &ClientKey, with_grant: bool, with_proof: bool) -> Vec<u8> {
    let public = key.public();
    let scope: Vec<&str> = id.authority_scope.iter().map(String::as_str).collect();
    let grant = operator().grant(id, &public, b.bridge_id());
    let proof = key.prove_attach(id, b.bridge_id());
    wire::op_attach(
        &id.session_id, &id.principal_id, &scope, &[], &public.key_id, &public.scheme,
        &hex::encode(&public.material), with_grant.then_some(grant.as_str()), with_proof.then_some(proof.as_str()),
    )
}

#[test]
fn an_attach_message_creates_the_session_and_its_refusals_are_named() {
    let server = WireServer::new().with_authenticate(Box::new(|_, _| false));
    let mut bridge = Bridge::new(MemStorage::new(), FakeClock::new(1000.0), Arc::new(SchemeVerifier), Config::default())
        .expect("bridge")
        .with_grant_verifier(Arc::new(OperatorGrantVerifier::new(operator().public_key())));
    let key = ClientKey::new("ck-1", &[1u8; 32]);
    let id = identity("s");
    let msg = |g: bool, p: bool, b: &Bridge| attach_bytes(b, &id, &key, g, p);
    let m = msg(false, true, &bridge);
    assert_eq!(reason(&server, &mut bridge, m), "grant_invalid");
    let m = msg(true, false, &bridge);
    assert_eq!(reason(&server, &mut bridge, m), "possession_invalid");
    assert!(bridge.events("s").is_empty());
    // attach carries its own grant and proof: the transport hook is not asked
    let m = msg(true, true, &bridge);
    let ok = send(&server, &mut bridge, &m).expect("attached");
    assert_eq!(ok["status"], "attached");
    assert_eq!(ok["seq"], 0);
    assert_eq!(ok["hash"], bridge.events("s")[0].hash());
    assert_eq!(bridge.cell_of("s").names(), vec!["Att", "None"]);
    let m = msg(true, true, &bridge);
    assert_eq!(reason(&server, &mut bridge, m), "refused");
}

#[test]
fn resolve_and_extend_are_served_and_asked_of_the_hook() {
    let server = WireServer::new();
    let mut f = fixture();
    let wider = ["read", "write", "admin"];
    let raw = wire::decode_response(&server.handle(&mut f.bridge, &wire::op_extend("s", &wider, "requested"))).unwrap();
    assert_eq!(raw["status"], "rejected");
    assert_eq!(raw["reason"], "extension_rejected");
    assert_eq!(raw["current_scope"], json!(["read", "write"]));
    assert_eq!(f.bridge.events("s").last().unwrap().kind, Kind::AUTHORITY_EXTENSION_REJECTED);
    let out = send(&server, &mut f.bridge, &wire::op_extend("s", &wider, "observed")).expect("a revert is requested");
    assert_eq!(out["status"], "revert_requested");
    assert_eq!(out["current_scope"], json!(["read", "write"]));
    let out = send(&server, &mut f.bridge, &wire::op_extend("s", &["read"], "requested")).expect("a subset");
    assert_eq!(out["status"], "unchanged");

    send(&server, &mut f.bridge, &wire::op_escalate("s", None)).expect("escalated");
    assert_eq!(f.bridge.cell_of("s").names(), vec!["Att", "Pend"]);
    let out = send(&server, &mut f.bridge, &wire::op_resolve("s")).expect("resolved");
    assert_eq!(out["status"], "resolved");
    assert_eq!(f.bridge.cell_of("s").names(), vec!["Att", "None"]);

    let asked = Arc::new(AtomicUsize::new(0));
    let counter = asked.clone();
    let server = WireServer::new().with_authenticate(Box::new(move |_, _| {
        counter.fetch_add(1, Ordering::SeqCst);
        false
    }));
    let n = f.bridge.events("s").len();
    assert_eq!(reason(&server, &mut f.bridge, wire::op_resolve("s")), "unauthenticated");
    assert_eq!(reason(&server, &mut f.bridge, wire::op_extend("s", &wider, "requested")), "unauthenticated");
    assert_eq!(asked.load(Ordering::SeqCst), 2);
    assert_eq!(f.bridge.events("s").len(), n);
}

#[test]
fn operator_events_are_verified_from_the_message_and_their_refusals_are_named() {
    let hook_calls = Arc::new(AtomicUsize::new(0));
    let counter = hook_calls.clone();
    let server = WireServer::new().with_authenticate(Box::new(move |_, _| {
        counter.fetch_add(1, Ordering::SeqCst);
        false
    }));
    let mut f = fixture();
    let (seq, head) = f.bridge.head_of("s");
    let foreign = OperatorKey::new(&[9u8; 32]).revoke(f.bridge.bridge_id(), "s", "ck-1", "rotation", seq, &head);
    for sig in [None, Some(foreign.as_str())] {
        assert_eq!(
            reason(&server, &mut f.bridge, wire::op_revoke("s", "ck-1", "rotation", sig, None)),
            "operator_signature_invalid"
        );
    }
    let n = f.bridge.events("s").len();
    // a client's request for a revocation appends an event on the caller's
    // word alone, so it goes through the transport check like an unsigned op
    let asked = hook_calls.load(Ordering::SeqCst);
    assert_eq!(
        reason(&server, &mut f.bridge, wire::op_revoke("s", "ck-1", "rotation", Some(""), Some("ck-1"))),
        "unauthenticated"
    );
    assert_eq!(hook_calls.load(Ordering::SeqCst), asked + 1);
    assert_eq!(f.bridge.events("s").len(), n);
    let server = WireServer::new();
    let out = send(&server, &mut f.bridge, &wire::op_revoke("s", "ck-1", "rotation", Some(""), Some("ck-1"))).expect("a request");
    assert_eq!(out["status"], "requested");
    assert_eq!(f.bridge.events("s").len(), n + 1);
    let sign = |b: &Bridge, key: &str, reason: &str| {
        let (seq, head) = b.head_of("s");
        operator().revoke(b.bridge_id(), "s", key, reason, seq, &head)
    };
    let s = sign(&f.bridge, "ck-9", "rotation");
    assert_eq!(reason(&server, &mut f.bridge, wire::op_revoke("s", "ck-9", "rotation", Some(&s), None)), "unknown_key");
    let (seq, head) = f.bridge.head_of("s");
    let t = operator().terminate(f.bridge.bridge_id(), "s", "all_keys_revoked", seq, &head);
    assert_eq!(
        reason(&server, &mut f.bridge, wire::op_operator_terminate("s", "all_keys_revoked", Some(&t))),
        "not_key_exhausted"
    );
    let s = sign(&f.bridge, "ck-1", "compromise");
    let out = send(&server, &mut f.bridge, &wire::op_revoke("s", "ck-1", "compromise", Some(&s), None)).expect("revoked");
    assert_eq!(out["status"], "revoked");
    assert!(f.bridge.is_key_exhausted("s"));
    let fresh = ClientKey::new("ck-2", &[2u8; 32]);
    let public = fresh.public();
    let pub_hex = hex::encode(&public.material);
    let add = |b: &Bridge, id: &str| {
        let (seq, head) = b.head_of("s");
        operator().add_key(b.bridge_id(), "s", id, &public.scheme, &pub_hex, seq, &head)
    };
    let a = add(&f.bridge, "ck-1");
    assert_eq!(
        reason(&server, &mut f.bridge, wire::op_add_key("s", "ck-1", &public.scheme, &pub_hex, Some(&a))),
        "key_already_registered"
    );
    let a = add(&f.bridge, "ck-2");
    let out = send(&server, &mut f.bridge, &wire::op_add_key("s", "ck-2", &public.scheme, &pub_hex, Some(&a))).expect("added");
    assert_eq!(out["status"], "key_added");
    assert!(!f.bridge.is_key_exhausted("s"));
    // the operator channel has its own proof: the transport hook was asked
    // only for the client's unsigned request for a revocation
    assert_eq!(hook_calls.load(Ordering::SeqCst), asked + 1);
}

/// One message of each unsigned op, naming `sid`; an op added to
/// `UNSIGNED_OPS` without a message here fails the test that uses it.
fn unsigned_message(op: &str, sid: &str) -> Vec<u8> {
    match op {
        "disconnect" => wire::op_disconnect(sid, "client_disconnect", None),
        "escalate" => wire::op_escalate(sid, None),
        "resolve" => wire::op_resolve(sid),
        "submit_tool_call" => wire::op_submit_tool_call(sid, "shell", &json!({}), Some("k1"), None),
        "answer_tool_call" => wire::op_answer_tool_call(sid, "k1", "h", "approve"),
        "delivered" => wire::op_delivered(sid, "k1"),
        "completed" => wire::op_completed(sid, "k1", None),
        "narrow" => wire::op_narrow(sid, &["read"]),
        "extend" => wire::op_extend(sid, &["read", "write", "admin"], "requested"),
        "terminate" => wire::op_terminate(sid, "terminated"),
        other => panic!("no test message for the unsigned op {other}"),
    }
}

#[test]
fn a_hook_that_authenticates_one_session_does_not_open_another() {
    let mut f = fixture();
    let second = SessionIdentity {
        session_id: "s2".into(),
        principal_id: "user-bob".into(),
        authority_scope: vec!["read".into(), "write".into()],
        task_lineage: vec![],
    };
    common::attach_ok(&mut f.bridge, &second, &f.key).expect("second session");
    let seen: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(vec![]));
    let log = seen.clone();
    let server = WireServer::new().with_authenticate(Box::new(move |op, msg| {
        let sid = msg["session_id"].as_str().unwrap_or("").to_string();
        log.lock().unwrap().push((op.to_string(), sid.clone()));
        sid == "s"
    }));
    let before = (f.bridge.events("s"), f.bridge.events("s2"));
    for op in bridge_contract::wire_server::UNSIGNED_OPS {
        assert_eq!(reason(&server, &mut f.bridge, unsigned_message(op, "s2")), "unauthenticated", "{op}");
    }
    let asked: Vec<(String, String)> =
        bridge_contract::wire_server::UNSIGNED_OPS.iter().map(|op| (op.to_string(), "s2".to_string())).collect();
    assert_eq!(*seen.lock().unwrap(), asked, "the hook was not given the message that names the session");
    assert_eq!((f.bridge.events("s"), f.bridge.events("s2")), before);
    // the same hook lets the caller of "s" through, and only "s" changes
    send(&server, &mut f.bridge, &unsigned_message("escalate", "s")).expect("escalated");
    assert_eq!(f.bridge.cell_of("s").names(), vec!["Att", "Pend"]);
    assert_eq!(f.bridge.cell_of("s2").names(), vec!["Att", "None"]);
    assert_eq!(f.bridge.events("s2"), before.1);
}

#[test]
fn a_bare_terminate_of_an_exhausted_session_and_an_unregistered_key_are_named_on_the_wire() {
    let server = WireServer::new();
    let mut f = fixture();
    let (seq, head) = f.bridge.head_of("s");
    let sig = operator().revoke(f.bridge.bridge_id(), "s", "ck-1", "rotation", seq, &head);
    send(&server, &mut f.bridge, &wire::op_revoke("s", "ck-1", "rotation", Some(&sig), None)).expect("revoked");
    assert_eq!(reason(&server, &mut f.bridge, wire::op_terminate("s", "terminated")), "key_exhausted");
    assert_ne!(f.bridge.cell_of("s").names(), vec!["Terminated"]);

    let mut f = fixture();
    send(&server, &mut f.bridge, &wire::op_disconnect("s", "client_disconnect", Some("ck-1"))).expect("disconnected");
    let (seq, hash) = tip(&f.bridge);
    for key in [ClientKey::new("ck-1", &[9u8; 32]), ClientKey::new("ck-9", &[9u8; 32])] {
        let n = nonce(&server, &mut f.bridge);
        assert_eq!(reason(&server, &mut f.bridge, reattach_bytes(&key, &n, seq, &hash)), "bad_signature");
    }
}

#[test]
fn a_request_nested_beyond_the_bound_is_refused_before_it_is_parsed() {
    // below the parser's own recursion limit, so only the bound refuses it
    let server = WireServer::new();
    let mut f = fixture();
    let deep = 100;
    let body = [br#"{"content":"#.as_slice(), "[".repeat(deep).as_bytes(), "]".repeat(deep).as_bytes(),
                br#","op":"submit_tool_call","session_id":"s","tool":"t"}"#.as_slice()].concat();
    let before = f.bridge.events("s").len();
    assert_eq!(reason(&server, &mut f.bridge, body), "bad_canonical");
    assert_eq!(f.bridge.events("s").len(), before);
}
