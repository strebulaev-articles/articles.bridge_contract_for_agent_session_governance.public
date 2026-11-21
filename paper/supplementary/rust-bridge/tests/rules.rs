//! Rules the language-neutral vectors do not reach, kept as plain tests so
//! that the Rust mutation check (`../mutation_check_rust.py`) is killed by
//! `cargo test` on them: a resume request with a nonce the bridge never
//! issued (I11b) and a stored event whose sequence number is wrong but
//! whose hash links are intact (I5).

use std::sync::Arc;

use bridge_contract::*;

fn session() -> (Arc<MemStorage>, Arc<FakeClock>, Bridge, ClientKey, String) {
    let storage = MemStorage::new();
    let clock = FakeClock::new(1000.0);
    let operator = OperatorKey::new(&[7u8; 32]);
    let mut bridge = Bridge::new(storage.clone(), clock.clone(), Arc::new(SchemeVerifier), Config::default())
        .expect("bridge")
        .with_grant_verifier(Arc::new(OperatorGrantVerifier::new(operator.public_key())));
    let key = ClientKey::new("ck-1", &[1u8; 32]);
    let sid = "s-rules".to_string();
    let identity = SessionIdentity {
        session_id: sid.clone(),
        principal_id: "p".into(),
        authority_scope: vec!["fs:read".into()],
        task_lineage: vec![],
    };
    let grant = operator.grant(&identity, &key.public(), DEFAULT_BRIDGE_ID);
    bridge
        .attach(&identity, &key.public(), Some(&grant), Some(&key.prove_attach(&identity, DEFAULT_BRIDGE_ID)))
        .expect("attach");
    (storage, clock, bridge, key, sid)
}

#[test]
fn unknown_nonce_is_refused() {
    let (_storage, _clock, mut bridge, key, sid) = session();
    bridge.client_disconnect(&sid, None, "test").expect("detach");
    let genesis = bridge.events(&sid)[0].hash();
    let req = key.request(&sid, &"ab".repeat(16), 0, &genesis);
    assert!(bridge.begin_resume(&sid, &req, false).is_err(), "a nonce the bridge never issued was accepted");
    assert_eq!(bridge.cell_of(&sid).names()[0], "Det");
}

#[test]
fn wrong_sequence_number_fails_recovery() {
    let (storage, clock, mut bridge, _key, sid) = session();
    bridge.client_disconnect(&sid, None, "test").expect("detach");
    let last = bridge.events(&sid).len() - 1;
    storage.tamper(&sid, last, |e| e.sequence += 7);
    let recovered = Bridge::recover(storage, clock, Arc::new(SchemeVerifier), Config::default()).expect("recover");
    assert!(
        recovered.events(&sid).iter().any(|e| e.kind == Kind::RECOVERY_FAILED),
        "a stored event with the wrong sequence number verified"
    );
}

#[test]
fn keyless_challenges_cannot_evict_a_live_nonce() {
    let (_storage, _clock, mut bridge, key, sid) = session();
    bridge.client_disconnect(&sid, None, "test").expect("detach");
    let genesis = bridge.events(&sid)[0].hash();
    let nonce = bridge.challenge(&sid).expect("genuine nonce").nonce;
    let mut issued = 0;
    for _ in 0..4 * NONCE_RECORDS {
        match bridge.challenge(&sid) {
            Ok(_) => issued += 1,
            Err(e) => {
                assert!(e.0.contains("challenge budget"), "{e:?}");
                break;
            }
        }
    }
    assert_eq!(issued, NONCE_RECORDS - 1, "the budget did not refuse");
    let req = key.request(&sid, &nonce, 0, &genesis);
    bridge.begin_resume(&sid, &req, false).expect("the genuine nonce was evicted");
}

#[test]
fn expired_nonces_make_room_for_new_challenges() {
    let (_storage, clock, mut bridge, _key, sid) = session();
    bridge.client_disconnect(&sid, None, "test").expect("detach");
    for _ in 0..NONCE_RECORDS {
        bridge.challenge(&sid).expect("within budget");
    }
    assert!(bridge.challenge(&sid).is_err());
    clock.advance(Config::default().t_nonce);
    assert!(bridge.challenge(&sid).is_ok());
}

#[test]
fn unauthenticated_rejections_are_logged_up_to_a_bound() {
    let (_storage, _clock, mut bridge, key, sid) = session();
    bridge.client_disconnect(&sid, None, "test").expect("detach");
    let genesis = bridge.events(&sid)[0].hash();
    let stranger = ClientKey::new("ck-1", &[2u8; 32]);
    let n0 = bridge.events(&sid).len();
    let mut messages = std::collections::BTreeSet::new();
    for _ in 0..3 * UNAUTH_LOG_LIMIT {
        let bad = stranger.request(&sid, &"00".repeat(16), 0, &genesis);
        messages.insert(bridge.begin_resume(&sid, &bad, false).unwrap_err().0);
    }
    assert_eq!(bridge.events(&sid).len() - n0, UNAUTH_LOG_LIMIT, "unbounded log growth");
    assert_eq!(messages.len(), 1, "the refusal is not uniform");
    // an authentic request is always logged and restores the budget
    let authentic = key.request(&sid, &"00".repeat(16), 0, &genesis);
    assert!(bridge.begin_resume(&sid, &authentic, false).is_err());
    assert_eq!(bridge.events(&sid).last().unwrap().payload["reason"], "nonce_unknown");
    let bad = stranger.request(&sid, &"00".repeat(16), 0, &genesis);
    assert!(bridge.begin_resume(&sid, &bad, false).is_err());
    assert_eq!(bridge.events(&sid).last().unwrap().payload["reason"], "bad_signature");
}

#[test]
fn revocation_requests_are_written_up_to_a_bound() {
    let (_storage, _clock, mut bridge, _key, sid) = session();
    let n0 = bridge.events(&sid).len();
    for _ in 0..3 * REVOCATION_REQUEST_LIMIT {
        let _ = bridge.revoke_key(&sid, "ck-1", "rotation", "", Some("x"));
    }
    assert_eq!(bridge.events(&sid).len() - n0, REVOCATION_REQUEST_LIMIT, "unbounded request writes");
    assert!(bridge.revoke_key(&sid, "ck-1", "rotation", "", Some("x")).is_err());
}

fn add_client(bridge: &mut Bridge, sid: &str, via: &ClientKey, new: &ClientKey, nonce: &str) -> Result<()> {
    bridge.add_client_key(sid, &via.key_id, &new.key_id, new.scheme(), &new.public_key(), nonce,
        &via.sign_add_client(sid, &new.public(), nonce))
}

#[test]
fn add_client_needs_a_fresh_signature_by_a_connected_unrevoked_key() {
    let (_storage, clock, mut bridge, key, sid) = session();
    let (k2, evil) = (ClientKey::new("ck-2", &[2u8; 32]), ClientKey::new("ck-evil", &[6u8; 32]));
    let reason = |r: Result<()>| r.unwrap_err().0;
    let n = bridge.challenge(&sid).unwrap().nonce;
    // a stranger naming the connected key id, signing as itself
    let forged = reason(bridge.add_client_key(&sid, "ck-1", "ck-evil", evil.scheme(), &evil.public_key(), &n,
        &evil.sign_add_client(&sid, &evil.public(), &n)));
    assert!(forged.contains("rejected: bad_signature "), "{forged}");
    let missing = reason(bridge.add_client_key(&sid, "ck-1", "ck-evil", evil.scheme(), &evil.public_key(), &n, ""));
    assert!(missing.contains("rejected: bad_signature "), "{missing}");
    let unconnected = reason(add_client(&mut bridge, &sid, &ClientKey::new("ck-9", &[9u8; 32]), &k2, &n));
    assert!(unconnected.contains("rejected: via_not_connected "), "{unconnected}");
    let unknown = "ab".repeat(16);
    assert!(reason(add_client(&mut bridge, &sid, &key, &k2, &unknown)).contains("rejected: nonce_unknown "));
    assert_eq!(bridge.events(&sid).len(), 1, "a refused registration committed events");
    add_client(&mut bridge, &sid, &key, &k2, &n).expect("authentic registration");
    assert!(reason(add_client(&mut bridge, &sid, &key, &k2, &n)).contains("rejected: nonce_used "));
    let stale = bridge.challenge(&sid).unwrap().nonce;
    clock.advance(Config::default().t_nonce + 1.0);
    assert!(reason(add_client(&mut bridge, &sid, &key, &evil, &stale)).contains("rejected: nonce_expired "));
    let again = bridge.challenge(&sid).unwrap().nonce;
    assert!(reason(add_client(&mut bridge, &sid, &key, &k2, &again)).contains("rejected: key_already_registered "));
    // a soft-revoked key stays connected but no longer authorises keys
    let (seq, head) = bridge.head_of(&sid);
    let sig = OperatorKey::new(&[7u8; 32]).revoke(bridge.bridge_id(), &sid, "ck-1", "rotation", seq, &head);
    bridge.revoke_key(&sid, "ck-1", "rotation", &sig, None).expect("soft revocation");
    let third = ClientKey::new("ck-3", &[3u8; 32]);
    let fresh = bridge.challenge(&sid).unwrap().nonce;
    assert!(reason(add_client(&mut bridge, &sid, &key, &third, &fresh)).contains("rejected: revoked_key "));
}

/// C.4: a further scheme through the pluggable verifier. The stub scheme is
/// test-only (SHA-256 over key and message); the bridge needs no change to
/// accept its tag, and a bridge without the verifier refuses the same key.
struct StubVerifier;

fn stub_sign(material: &[u8], message: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest([material, message].concat()))
}

impl Verifier for StubVerifier {
    fn verify(&self, scheme: &str, key_material: &[u8], message: &[u8], signature: &str) -> bool {
        if scheme == "test-stub" {
            signature == stub_sign(key_material, message)
        } else {
            SchemeVerifier.verify(scheme, key_material, message, signature)
        }
    }
}

#[test]
fn a_further_scheme_is_accepted_through_the_verifier() {
    let operator = OperatorKey::new(&[7u8; 32]);
    let identity = SessionIdentity {
        session_id: "s-stub".into(),
        principal_id: "p".into(),
        authority_scope: vec!["fs:read".into()],
        task_lineage: vec![],
    };
    let key = ClientPublicKey { key_id: "ck-s".into(), scheme: "test-stub".into(), material: b"stub-key".to_vec() };
    let grant = operator.grant(&identity, &key, DEFAULT_BRIDGE_ID);
    let proof = stub_sign(&key.material, &attach_message(DEFAULT_BRIDGE_ID, &identity, &key));
    let build = |v: Arc<dyn Verifier>| {
        Bridge::new(MemStorage::new(), FakeClock::new(1000.0), v, Config::default())
            .expect("bridge")
            .with_grant_verifier(Arc::new(OperatorGrantVerifier::new(operator.public_key())))
    };
    assert!(build(Arc::new(StubVerifier)).attach(&identity, &key, Some(&grant), Some(&"00".repeat(32))).is_err());
    build(Arc::new(StubVerifier)).attach(&identity, &key, Some(&grant), Some(&proof)).expect("stub scheme attach");
    assert!(build(Arc::new(SchemeVerifier)).attach(&identity, &key, Some(&grant), Some(&proof)).is_err());
}

// ---- two sessions on one bridge: nothing is shared but the bridge -------

/// A second, validly granted session that holds the same client key (the same
/// key id and secret) as the first, so that any state shared between the two
/// can be told apart from state kept per session.
fn attach_second(bridge: &mut Bridge, key: &ClientKey) -> String {
    let sid = "s-two".to_string();
    let identity = SessionIdentity {
        session_id: sid.clone(),
        principal_id: "q".into(),
        authority_scope: vec!["fs:read".into()],
        task_lineage: vec![],
    };
    let operator = OperatorKey::new(&[7u8; 32]);
    let grant = operator.grant(&identity, &key.public(), DEFAULT_BRIDGE_ID);
    bridge
        .attach(&identity, &key.public(), Some(&grant), Some(&key.prove_attach(&identity, DEFAULT_BRIDGE_ID)))
        .expect("second attach");
    sid
}

fn last_reason(bridge: &Bridge, sid: &str) -> String {
    bridge.events(sid).last().unwrap().payload["reason"].as_str().unwrap_or("").to_string()
}

#[test]
fn a_nonce_belongs_to_the_session_that_issued_it() {
    let (_storage, _clock, mut bridge, key, a) = session();
    let b = attach_second(&mut bridge, &key);
    let foreign = bridge.challenge(&b).expect("B's nonce").nonce;
    let genesis = bridge.events(&a)[0].hash();
    // a registration in A with a nonce that B issued
    let k2 = ClientKey::new("ck-2", &[2u8; 32]);
    let err = add_client(&mut bridge, &a, &key, &k2, &foreign).unwrap_err().0;
    assert!(err.contains("rejected: nonce_unknown "), "{err}");
    // a join in A with a nonce that B issued
    let join = key.request_for(ResumeOp::Join, &a, &foreign, 0, &genesis);
    assert!(bridge.join(&a, &join, false).is_err());
    assert_eq!(last_reason(&bridge, &a), "nonce_unknown");
    // a re-attach in A with a nonce that B issued, and with B's prefix
    bridge.client_disconnect(&a, None, "test").expect("detach");
    let req = key.request(&a, &foreign, 0, &genesis);
    assert!(bridge.begin_resume(&a, &req, false).is_err());
    assert_eq!(last_reason(&bridge, &a), "nonce_unknown");
    let b_genesis = bridge.events(&b)[0].hash();
    assert_ne!(b_genesis, genesis);
    let own = bridge.challenge(&a).unwrap().nonce;
    let req = key.request(&a, &own, 0, &b_genesis);
    assert!(bridge.begin_resume(&a, &req, false).is_err());
    assert_eq!(last_reason(&bridge, &a), "prefix_mismatch");
    // the refusals spent nothing in B: its own client still uses the nonce
    bridge.client_disconnect(&b, None, "test").expect("detach B");
    let req = key.request(&b, &foreign, 0, &b_genesis);
    bridge.begin_resume(&b, &req, false).expect("B's nonce was spent by A's refusals");
    bridge.complete_resume(&b).expect("B resumes");
    let fresh = bridge.challenge(&a).unwrap().nonce;
    bridge.begin_resume(&a, &key.request(&a, &fresh, 0, &genesis), false).expect("A is not locked out");
    bridge.complete_resume(&a).expect("A resumes");
    // A using up its challenge budget leaves B's untouched
    bridge.client_disconnect(&a, None, "test").expect("detach");
    let mut refused = false;
    for _ in 0..4 * NONCE_RECORDS {
        if bridge.challenge(&a).is_err() {
            refused = true;
            break;
        }
    }
    assert!(refused, "the budget did not refuse");
    for _ in 0..NONCE_RECORDS {
        assert!(bridge.challenge(&b).is_ok(), "A's budget was charged to B");
    }
}

#[test]
fn bounds_on_unauthenticated_writes_are_kept_per_session() {
    let (_storage, _clock, mut bridge, key, a) = session();
    let b = attach_second(&mut bridge, &key);
    bridge.client_disconnect(&a, None, "test").expect("detach A");
    bridge.client_disconnect(&b, None, "test").expect("detach B");
    let stranger = ClientKey::new("ck-1", &[2u8; 32]);
    let bad = |bridge: &mut Bridge, sid: &str| -> usize {
        let n = bridge.events(sid).len();
        let h = bridge.events(sid)[0].hash();
        let req = stranger.request(sid, &"00".repeat(16), 0, &h);
        assert!(bridge.begin_resume(sid, &req, false).is_err());
        bridge.events(sid).len() - n
    };
    for _ in 0..UNAUTH_LOG_LIMIT {
        assert_eq!(bad(&mut bridge, &a), 1);
    }
    assert_eq!(bad(&mut bridge, &a), 0, "A's budget is spent");
    assert_eq!(bad(&mut bridge, &b), 1, "B's budget is its own");
    // a key holder speaking in B does not restore A's budget
    let h = bridge.events(&b)[0].hash();
    assert!(bridge.begin_resume(&b, &key.request(&b, &"00".repeat(16), 0, &h), false).is_err());
    assert_eq!(last_reason(&bridge, &b), "nonce_unknown");
    assert_eq!(bad(&mut bridge, &a), 0, "A's budget stays spent");
    // revocation requests need no signature either
    let ask = |bridge: &mut Bridge, sid: &str| -> usize {
        let n = bridge.events(sid).len();
        let _ = bridge.revoke_key(sid, "ck-1", "rotation", "", Some("x"));
        bridge.events(sid).len() - n
    };
    for _ in 0..REVOCATION_REQUEST_LIMIT {
        assert_eq!(ask(&mut bridge, &a), 1);
    }
    assert_eq!(ask(&mut bridge, &a), 0);
    assert_eq!(ask(&mut bridge, &b), 1);
    // and a signed revocation in B does not reopen A
    let (seq, head) = bridge.head_of(&b);
    let sig = OperatorKey::new(&[7u8; 32]).revoke(bridge.bridge_id(), &b, "ck-1", "rotation", seq, &head);
    bridge.revoke_key(&b, "ck-1", "rotation", &sig, None).expect("signed revocation in B");
    assert_eq!(ask(&mut bridge, &a), 0, "A's request budget was restored by B");
}

#[test]
fn tool_call_keys_are_scoped_to_the_session_across_a_restart() {
    let (storage, clock, mut bridge, key, a) = session();
    let b = attach_second(&mut bridge, &key);
    for (sid, tool) in [(&a, "git push"), (&b, "rm -rf build")] {
        bridge.escalate_to_human(sid, "test").expect("escalate");
        let content = serde_json::json!({"sid": sid});
        bridge.submit_tool_call(sid, tool, Some("k1"), Some("fs:read"), Some(&content)).expect("queued");
        let shown = bridge.shown_hash_of(sid, "k1").expect("shown");
        bridge.answer_tool_call(sid, "k1", &shown, true).expect("answered");
        bridge.human_resolve(sid).expect("resolved");
    }
    for (sid, tool) in [(&a, "git push"), (&b, "rm -rf build")] {
        let call = &bridge.forwarded_calls[&(sid.to_string(), "k1".to_string())];
        assert_eq!(call.tool, tool);
        assert_eq!(call.content, serde_json::json!({"sid": sid}));
    }
    // a restart before either acknowledgement: each is forwarded again
    let mut bridge = Bridge::recover(storage, clock, Arc::new(SchemeVerifier), Config::default()).expect("recover");
    assert!(bridge.forwarded.is_empty());
    for sid in [&a, &b] {
        let genesis = bridge.events(sid)[0].hash();
        let nonce = bridge.challenge(sid).unwrap().nonce;
        bridge.begin_resume(sid, &key.request(sid, &nonce, 0, &genesis), false).expect("resume");
        bridge.complete_resume(sid).expect("verified");
    }
    let mut got = bridge.forwarded.clone();
    got.sort();
    let want = |sid: &String, tool: &str| (sid.clone(), "k1".to_string(), tool.to_string());
    let mut expected = vec![want(&a, "git push"), want(&b, "rm -rf build")];
    expected.sort();
    assert_eq!(got, expected, "a session's call was not forwarded again");
    bridge.delivered(&a, "k1").expect("A's acknowledgement");
    assert!(bridge.delivered(&a, "k1").is_err(), "nothing awaits in A");
    bridge.delivered(&b, "k1").expect("B's is still awaited");
}
