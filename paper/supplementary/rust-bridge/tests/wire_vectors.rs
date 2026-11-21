//! Byte-level wire-format tests for V44–V51.
//!
//! These tests encode each wire op-type using the Rust `wire` module,
//! decode the result, and confirm the roundtrip is lossless. They
//! mirror the Python `run_vector_wire()` smoke test.

use bridge_contract::wire::*;
use serde_json::{json, Value};

fn decode(data: &[u8]) -> Value {
    serde_json::from_slice(data).expect("valid JSON")
}

#[test]
fn test_v44_simplest_detach_reattach() {
    // V44: simplest detach and reattach (no escalation)
    let challenge = op_challenge("sess-44");
    let d = decode(&challenge);
    assert_eq!(d["op"], "challenge");
    assert_eq!(d["session_id"], "sess-44");

    let reattach = op_reattach("sess-44", "ck-1", "n1", 0, "h", "sig");
    let d = decode(&reattach);
    assert_eq!(d["op"], "reattach");
    assert_eq!(d["key_id"], "ck-1");
    assert_eq!(d["nonce"], "n1");
    assert_eq!(d["seq"], 0);
    assert_eq!(d["hash"], "h");
    assert_eq!(d["signature"], "sig");
}

#[test]
fn test_v45_add_client_join() {
    // V45: add_client then join with the new key
    let add = op_add_client("sess-45", "ck-1", "ck-2", "ed25519", "cdcdcd", "n0", "sig");
    let d = decode(&add);
    assert_eq!(d["op"], "add_client");
    assert_eq!(d["via_key_id"], "ck-1");
    assert_eq!(d["new_key_id"], "ck-2");

    let join = op_join("sess-45", "ck-2", "n1", 0, "h", "sig");
    let d = decode(&join);
    assert_eq!(d["op"], "join");
    assert_eq!(d["key_id"], "ck-2");
}

#[test]
fn test_v46_tool_call_answer_drain() {
    // V46: tool_call with explicit content, answer, drain
    let tc = op_submit_tool_call(
        "sess-46", "shell:git",
        &json!({"cmd": "git push"}),
        Some("k1"), Some("exec:shell"));
    let d = decode(&tc);
    assert_eq!(d["op"], "submit_tool_call");
    assert_eq!(d["tool"], "shell:git");
    assert_eq!(d["key"], "k1");
    assert_eq!(d["permission"], "exec:shell");
    assert_eq!(d["content"]["cmd"], "git push");

    let ans = op_answer_tool_call("sess-46", "k1", "00ab", "approve");
    let d = decode(&ans);
    assert_eq!(d["op"], "answer_tool_call");
    assert_eq!(d["decision"], "approve");
}

#[test]
fn test_v47_narrow_extend() {
    // V47: narrow then extend (observed)
    let narrow = op_narrow("sess-47", &["read:docs"]);
    let d = decode(&narrow);
    assert_eq!(d["op"], "narrow");
    assert_eq!(d["new_scope"], json!(["read:docs"]));

    let extend = op_extend(
        "sess-47",
        &["read:docs", "exec:shell", "exec:sudo"],
        "observed");
    let d = decode(&extend);
    assert_eq!(d["op"], "extend");
    assert_eq!(d["source"], "observed");
}

#[test]
fn test_v48_delivered_completed() {
    // V48: delivered then completed — forwarding ack chain
    let del = op_delivered("sess-48", "k1");
    let d = decode(&del);
    assert_eq!(d["op"], "delivered");
    assert_eq!(d["key"], "k1");

    let comp = op_completed("sess-48", "k1", Some("result_hash_123"));
    let d = decode(&comp);
    assert_eq!(d["op"], "completed");
    assert_eq!(d["result_hash"], "result_hash_123");
}

#[test]
fn test_v49_terminate() {
    // V49: terminate from (Att, None)
    let term = op_terminate("sess-49", "clean_end");
    let d = decode(&term);
    assert_eq!(d["op"], "terminate");
    assert_eq!(d["reason"], "clean_end");
}

#[test]
fn test_v50_tick() {
    // V50: tick fires detach timeout
    let tick = op_tick(Some("sess-50"));
    let d = decode(&tick);
    assert_eq!(d["op"], "tick");
    assert_eq!(d["session_id"], "sess-50");

    // tick without session_id (all sessions)
    let tick_all = op_tick(None);
    let d = decode(&tick_all);
    assert_eq!(d["op"], "tick");
    assert!(d.get("session_id").is_none());
}

#[test]
fn test_v51_partial_disconnect() {
    // V51: disconnect specific key, then disconnect all
    let disc1 = op_disconnect("sess-51", "client_disconnect", Some("ck-1"));
    let d = decode(&disc1);
    assert_eq!(d["op"], "disconnect");
    assert_eq!(d["key_id"], "ck-1");

    let disc2 = op_disconnect("sess-51", "client_disconnect", None);
    let d = decode(&disc2);
    assert_eq!(d["op"], "disconnect");
    assert!(d.get("key_id").is_none());
}

#[test]
fn test_restart_and_error() {
    // restart has no session_id
    let restart = op_restart();
    let d = decode(&restart);
    assert_eq!(d["op"], "restart");
    assert!(d.get("session_id").is_none());

    // error encoding
    let err = encode_error("sess-44", "prefix_mismatch");
    let d = decode(&err);
    assert_eq!(d["status"], "rejected");
    assert_eq!(d["session_id"], "sess-44");
    assert_eq!(d["reason"], "prefix_mismatch");
}

#[test]
fn test_canonical_bytes_deterministic() {
    let a = json!({"b": 1, "a": 2});
    let b = json!({"a": 2, "b": 1});
    assert_eq!(canonical_bytes(&a), canonical_bytes(&b));
}

#[test]
fn test_signature_scope_reattach() {
    let values = vec![
        json!("sess-001"),
        json!("n1"),
        json!(6),
        json!("h1"),
    ];
    let sig = canonical_for_signature(&values);
    assert_eq!(
        String::from_utf8(sig).unwrap(),
        r#"["sess-001","n1",6,"h1"]"#
    );
}
