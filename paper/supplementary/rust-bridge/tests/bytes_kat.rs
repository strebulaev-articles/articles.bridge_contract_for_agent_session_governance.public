//! Byte-level known answers shared with the Python runner
//! (`../vectors/bytes_kat.json`): RFC 8785 canonical bytes, event and
//! content hashes, and the exact bytes and Ed25519 signature of re-attach
//! and join proofs. A third-party implementation can read the same file.

use std::path::PathBuf;

use bridge_contract::wire::{canonical_bytes, try_canonical_bytes};
use bridge_contract::*;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn kat() -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vectors/bytes_kat.json");
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

fn op_of(s: &str) -> ResumeOp {
    match s {
        "reattach" => ResumeOp::Reattach,
        "join" => ResumeOp::Join,
        other => panic!("unknown op {other}"),
    }
}

#[test]
fn canonical_json_matches_rfc_8785_known_answers() {
    let k = kat();
    for c in k["canonical"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let v: Value = serde_json::from_str(c["json"].as_str().unwrap()).unwrap();
        let got = canonical_bytes(&v);
        assert_eq!(String::from_utf8(got.clone()).unwrap(), c["canonical"].as_str().unwrap(), "{name}");
        assert_eq!(hex::encode(&got), c["hex"].as_str().unwrap(), "{name}");
    }
    for c in k["reject"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        // either the text does not parse to a finite number, or it has no canonical form
        if let Ok(v) = serde_json::from_str::<Value>(c["json"].as_str().unwrap()) {
            assert!(try_canonical_bytes(&v).is_err(), "{name}");
        }
    }
}

#[test]
fn event_and_content_hashes_match_the_known_answers() {
    let k = kat();
    for e in k["events"].as_array().unwrap() {
        let ev = Event {
            kind: Kind::parse(e["kind"].as_str().unwrap()).unwrap(),
            session_id: e["session_id"].as_str().unwrap().to_string(),
            sequence: e["sequence"].as_u64().unwrap(),
            prev_hash: e["prev_hash"].as_str().unwrap().to_string(),
            payload: e["payload"].clone(),
            timestamp: e["timestamp"].as_f64().unwrap(),
        };
        assert_eq!(String::from_utf8(ev.canonical()).unwrap(), e["canonical"].as_str().unwrap());
        assert_eq!(hex::encode(ev.canonical()), e["hex"].as_str().unwrap());
        assert_eq!(ev.hash(), e["hash"].as_str().unwrap());
        assert_eq!(sha(&ev.canonical()), e["hash"].as_str().unwrap());
    }
    for c in k["content_hashes"].as_array().unwrap() {
        let v: Value = serde_json::from_str(c["json"].as_str().unwrap()).unwrap();
        assert_eq!(String::from_utf8(canonical_bytes(&v)).unwrap(), c["canonical"].as_str().unwrap());
        assert_eq!(content_hash(&v), c["hash"].as_str().unwrap(), "{}", c["name"]);
    }
}

#[test]
fn resume_proof_signed_bytes_and_signature_are_pinned() {
    let k = kat();
    let seed: [u8; 32] = hex::decode(k["ed25519_seed"].as_str().unwrap()).unwrap().try_into().unwrap();
    let public = hex::decode(k["public_key"].as_str().unwrap()).unwrap();
    for p in k["resume_proofs"].as_array().unwrap() {
        let name = p["name"].as_str().unwrap();
        let key = ClientKey::new(p["key_id"].as_str().unwrap(), &seed);
        assert_eq!(key.public_key(), public);
        let msg = resume_message(
            op_of(p["op"].as_str().unwrap()),
            p["session_id"].as_str().unwrap(),
            p["key_id"].as_str().unwrap(),
            p["nonce"].as_str().unwrap(),
            p["seq"].as_i64().unwrap(),
            p["hash"].as_str().unwrap(),
        );
        assert_eq!(String::from_utf8(msg.clone()).unwrap(), p["signed_text"].as_str().unwrap(), "{name}");
        assert_eq!(hex::encode(&msg), p["signed_hex"].as_str().unwrap(), "{name}");
        assert_eq!(key.sign_bytes(&msg), p["signature"].as_str().unwrap(), "{name}");
        assert!(SchemeVerifier.verify("ed25519", &public, &msg, p["signature"].as_str().unwrap()), "{name}");
    }
    for n in k["resume_negatives"].as_array().unwrap() {
        let msg = resume_message(
            op_of(n["op"].as_str().unwrap()),
            n["session_id"].as_str().unwrap(),
            n["key_id"].as_str().unwrap(),
            n["nonce"].as_str().unwrap(),
            n["seq"].as_i64().unwrap(),
            n["hash"].as_str().unwrap(),
        );
        assert!(!SchemeVerifier.verify("ed25519", &public, &msg, n["signature"].as_str().unwrap()), "{}", n["name"]);
    }
}

#[test]
fn add_client_signed_bytes_and_signature_are_pinned() {
    let k = kat();
    let seed: [u8; 32] = hex::decode(k["ed25519_seed"].as_str().unwrap()).unwrap().try_into().unwrap();
    let public = hex::decode(k["public_key"].as_str().unwrap()).unwrap();
    let msg_of = |p: &Value| {
        add_client_message(
            p["session_id"].as_str().unwrap(),
            p["via_key_id"].as_str().unwrap(),
            p["new_key_id"].as_str().unwrap(),
            p["scheme"].as_str().unwrap(),
            p["public_key"].as_str().unwrap(),
            p["nonce"].as_str().unwrap(),
        )
    };
    for p in k["add_client_proofs"].as_array().unwrap() {
        let key = ClientKey::new(p["via_key_id"].as_str().unwrap(), &seed);
        let msg = msg_of(p);
        assert_eq!(String::from_utf8(msg.clone()).unwrap(), p["signed_text"].as_str().unwrap());
        assert_eq!(hex::encode(&msg), p["signed_hex"].as_str().unwrap());
        assert_eq!(key.sign_bytes(&msg), p["signature"].as_str().unwrap());
        assert!(SchemeVerifier.verify("ed25519", &public, &msg, p["signature"].as_str().unwrap()));
    }
    for n in k["add_client_negatives"].as_array().unwrap() {
        assert!(!SchemeVerifier.verify("ed25519", &public, &msg_of(n), n["signature"].as_str().unwrap()), "{}", n["name"]);
    }
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect()
}

#[test]
fn attach_proof_signed_bytes_and_signature_are_pinned() {
    let k = kat();
    let seed: [u8; 32] = hex::decode(k["ed25519_seed"].as_str().unwrap()).unwrap().try_into().unwrap();
    let public = hex::decode(k["public_key"].as_str().unwrap()).unwrap();
    let msg_of = |p: &Value| {
        let identity = SessionIdentity {
            session_id: p["session_id"].as_str().unwrap().to_string(),
            principal_id: p["principal"].as_str().unwrap().to_string(),
            authority_scope: strings(&p["scope"]),
            task_lineage: strings(&p["lineage"]),
        };
        let key = ClientPublicKey {
            key_id: p["key_id"].as_str().unwrap().to_string(),
            scheme: p["scheme"].as_str().unwrap().to_string(),
            material: hex::decode(p["public_key"].as_str().unwrap()).unwrap(),
        };
        attach_message(p["bridge_id"].as_str().unwrap(), &identity, &key)
    };
    for p in k["attach_proofs"].as_array().unwrap() {
        let key = ClientKey::new(p["key_id"].as_str().unwrap(), &seed);
        let msg = msg_of(p);
        assert_eq!(String::from_utf8(msg.clone()).unwrap(), p["signed_text"].as_str().unwrap());
        assert_eq!(hex::encode(&msg), p["signed_hex"].as_str().unwrap());
        assert_eq!(key.sign_bytes(&msg), p["signature"].as_str().unwrap());
        assert!(SchemeVerifier.verify("ed25519", &public, &msg, p["signature"].as_str().unwrap()));
    }
    for n in k["attach_negatives"].as_array().unwrap() {
        assert!(!SchemeVerifier.verify("ed25519", &public, &msg_of(n), n["signature"].as_str().unwrap()), "{}", n["name"]);
    }
}

#[test]
fn operator_signed_bytes_and_signature_are_pinned() {
    let k = kat();
    let seed: [u8; 32] = hex::decode(k["operator_seed"].as_str().unwrap()).unwrap().try_into().unwrap();
    let operator = OperatorKey::new(&seed);
    let public = hex::decode(k["operator_public_key"].as_str().unwrap()).unwrap();
    assert_eq!(operator.public_key(), public);
    let msg_of = |p: &Value| {
        let (bridge, sid) = (p["bridge_id"].as_str().unwrap(), p["session_id"].as_str().unwrap());
        let (seq, head) = (p["seq"].as_u64().unwrap(), p["head"].as_str().unwrap());
        match p["op"].as_str().unwrap() {
            "revoke" => revoke_message(bridge, sid, p["key_id"].as_str().unwrap(), p["reason"].as_str().unwrap(), seq, head),
            "add_key" => add_key_message(
                bridge,
                sid,
                p["key_id"].as_str().unwrap(),
                p["scheme"].as_str().unwrap(),
                p["public_key"].as_str().unwrap(),
                seq,
                head,
            ),
            _ => terminate_message(bridge, sid, p["reason"].as_str().unwrap(), seq, head),
        }
    };
    for p in k["operator_proofs"].as_array().unwrap() {
        let msg = msg_of(p);
        assert_eq!(String::from_utf8(msg.clone()).unwrap(), p["signed_text"].as_str().unwrap());
        assert_eq!(hex::encode(&msg), p["signed_hex"].as_str().unwrap());
        let (bridge, sid) = (p["bridge_id"].as_str().unwrap(), p["session_id"].as_str().unwrap());
        let (seq, head) = (p["seq"].as_u64().unwrap(), p["head"].as_str().unwrap());
        let signed = match p["op"].as_str().unwrap() {
            "revoke" => operator.revoke(bridge, sid, p["key_id"].as_str().unwrap(), p["reason"].as_str().unwrap(), seq, head),
            "add_key" => operator.add_key(
                bridge,
                sid,
                p["key_id"].as_str().unwrap(),
                p["scheme"].as_str().unwrap(),
                p["public_key"].as_str().unwrap(),
                seq,
                head,
            ),
            _ => operator.terminate(bridge, sid, p["reason"].as_str().unwrap(), seq, head),
        };
        assert_eq!(signed, p["signature"].as_str().unwrap());
        assert!(SchemeVerifier.verify("ed25519", &public, &msg, p["signature"].as_str().unwrap()));
    }
    for n in k["operator_negatives"].as_array().unwrap() {
        assert!(!SchemeVerifier.verify("ed25519", &public, &msg_of(n), n["signature"].as_str().unwrap()), "{}", n["name"]);
    }
}
