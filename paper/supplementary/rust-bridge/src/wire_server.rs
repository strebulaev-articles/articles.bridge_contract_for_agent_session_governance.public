//! A wire front-end for the Rust bridge, mirroring `wire_server.py`.
//!
//! [`WireServer::handle`] takes the bytes of one client request (Appendix B),
//! decodes them, dispatches the op to a [`Bridge`] and returns the bytes of
//! the response. Signed ops are verified by the bridge itself, from the
//! fields of the message and the registry of client keys, so a request is
//! accepted or refused as the envelope states it, not as a harness
//! constructs it.
//!
//! Ops handled: `attach`, `challenge`, `add_client`, `reattach`, `join`,
//! `disconnect`, `escalate`, `resolve`, `submit_tool_call`,
//! `answer_tool_call`, `delivered`, `completed`, `narrow`, `extend` and
//! `terminate`, and the operator events `revoke`, `add_key` and
//! `operator_terminate`, which carry the operator's signature. `attach`
//! carries the scope grant and the client's proof of possession, so it needs
//! no transport check; the operator events are verified by the bridge
//! against the operator key. Any other op is refused as `unsupported_op`. A
//! request that is not canonical JSON is refused as `bad_canonical`.

use serde_json::{json, Map, Value};

use crate::bridge::{AuthorityOutcome, Bridge, Revocation, Source, ToolOutcome};
use crate::types::{
    Attachment, BridgeError, ClientPublicKey, Event, ResumeRequest, SessionIdentity,
};
use crate::wire;

/// Ops that carry no signature of their own (Appendix B, "Authentication of
/// unsigned ops"): the transport binding authenticates their caller.
pub const UNSIGNED_OPS: [&str; 10] = [
    "disconnect", "escalate", "resolve", "submit_tool_call", "answer_tool_call",
    "delivered", "completed", "narrow", "extend", "terminate",
];

/// Ops that carry their own proof or need none.
const OTHER_SERVED_OPS: [&str; 8] =
    ["attach", "challenge", "add_client", "reattach", "join", "revoke", "add_key", "operator_terminate"];

/// The transport-level caller check: `(op, message) -> accepted`.
pub type Authenticate = Box<dyn Fn(&str, &Value) -> bool + Send + Sync>;

/// The reason name of a refusal: the typed reason the raise site set
/// (`refused` when it names nothing). The message text is never read.
pub fn reason_of(err: &BridgeError) -> String {
    err.1.to_string()
}

/// `authenticate(op, message)` is the hook where a deployment puts its
/// transport-level caller check (a client certificate, a session token). It
/// is called for every op in [`UNSIGNED_OPS`] before the bridge sees it; a
/// false answer refuses the op as `unauthenticated` and nothing is
/// committed. With no hook every caller is accepted, which is only
/// acceptable for the reference harness.
#[derive(Default)]
pub struct WireServer {
    authenticate: Option<Authenticate>,
}

struct Malformed;

enum HandleError {
    Bridge(BridgeError),
    Malformed,
}

impl From<BridgeError> for HandleError {
    fn from(e: BridgeError) -> Self {
        HandleError::Bridge(e)
    }
}

impl From<Malformed> for HandleError {
    fn from(_: Malformed) -> Self {
        HandleError::Malformed
    }
}

type Handled = std::result::Result<Vec<u8>, HandleError>;

fn text<'a>(m: &'a Value, k: &str) -> std::result::Result<&'a str, Malformed> {
    m.get(k).and_then(Value::as_str).ok_or(Malformed)
}

fn strings(m: &Value, k: &str) -> std::result::Result<Vec<String>, Malformed> {
    m.get(k)
        .and_then(Value::as_array)
        .ok_or(Malformed)?
        .iter()
        .map(|x| x.as_str().map(String::from).ok_or(Malformed))
        .collect()
}

fn ack(status: &str, sid: &str) -> Vec<u8> {
    wire::encode_response(status, Some(sid), &Map::new())
}

fn with_events(status: &str, sid: &str, events: &[Event]) -> Vec<u8> {
    let mut f = Map::new();
    f.insert("events".into(), json!(events.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>()));
    wire::encode_response(status, Some(sid), &f)
}

fn resume_request(m: &Value) -> std::result::Result<ResumeRequest, Malformed> {
    Ok(ResumeRequest {
        key_id: text(m, "key_id")?.to_string(),
        nonce: text(m, "nonce")?.to_string(),
        seq: m.get("seq").and_then(Value::as_i64).ok_or(Malformed)?,
        hash: text(m, "hash")?.to_string(),
        signature: text(m, "signature")?.to_string(),
    })
}

impl WireServer {
    pub fn new() -> Self {
        WireServer { authenticate: None }
    }

    pub fn with_authenticate(mut self, hook: Authenticate) -> Self {
        self.authenticate = Some(hook);
        self
    }

    /// Serve one request against `bridge`; the response is the bytes to send.
    pub fn handle(&self, bridge: &mut Bridge, data: &[u8]) -> Vec<u8> {
        let Ok(msg) = wire::decode_message(data) else {
            return wire::encode_error("", "bad_canonical");
        };
        match wire::try_canonical_bytes(&msg) {
            Ok(c) if c == data => {}
            _ => return wire::encode_error("", "bad_canonical"),
        }
        let sid = msg.get("session_id").and_then(Value::as_str).unwrap_or("").to_string();
        let op = msg.get("op").and_then(Value::as_str).unwrap_or("").to_string();
        let unsigned = UNSIGNED_OPS.contains(&op.as_str());
        if !unsigned && !OTHER_SERVED_OPS.contains(&op.as_str()) {
            return wire::encode_error(&sid, "unsupported_op");
        }
        if unsigned {
            if let Some(auth) = &self.authenticate {
                if !auth(&op, &msg) {
                    return wire::encode_error(&sid, "unauthenticated");
                }
            }
        }
        match self.dispatch(bridge, &op, &sid, &msg) {
            Ok(bytes) => bytes,
            Err(HandleError::Bridge(e)) => wire::encode_error(&sid, &reason_of(&e)),
            Err(HandleError::Malformed) => wire::encode_error(&sid, "bad_canonical"),
        }
    }

    fn dispatch(&self, b: &mut Bridge, op: &str, sid: &str, m: &Value) -> Handled {
        match op {
            "challenge" => {
                let ch = b.challenge(sid)?;
                let mut f = Map::new();
                f.insert("nonce".into(), json!(ch.nonce));
                f.insert("ttl_seconds".into(), json!(ch.ttl_seconds));
                Ok(wire::encode_response("nonce", Some(sid), &f))
            }
            "attach" => {
                let id = SessionIdentity {
                    session_id: sid.to_string(),
                    principal_id: text(m, "principal")?.to_string(),
                    authority_scope: strings(m, "scope")?,
                    task_lineage: strings(m, "lineage")?,
                };
                let key = ClientPublicKey {
                    key_id: text(m, "key_id")?.to_string(),
                    scheme: text(m, "scheme")?.to_string(),
                    material: hex::decode(text(m, "public_key")?).map_err(|_| Malformed)?,
                };
                b.attach(
                    &id,
                    &key,
                    m.get("grant").and_then(Value::as_str),
                    m.get("signature").and_then(Value::as_str),
                )?;
                let mut f = Map::new();
                f.insert("seq".into(), json!(0));
                f.insert("hash".into(), json!(b.events(sid)[0].hash()));
                Ok(wire::encode_response("attached", Some(sid), &f))
            }
            "add_client" => {
                let material = hex::decode(text(m, "new_public_key")?).map_err(|_| Malformed)?;
                b.add_client_key(
                    sid, text(m, "via_key_id")?, text(m, "new_key_id")?, text(m, "scheme")?,
                    &material, text(m, "nonce")?, text(m, "signature")?,
                )?;
                Ok(ack("added", sid))
            }
            "reattach" => {
                let req = resume_request(m)?;
                b.begin_resume(sid, &req, false)?;
                let events = if b.cell_of(sid).att == Attachment::Res {
                    b.complete_resume(sid)?
                } else {
                    vec![]
                };
                Ok(with_events("verified", sid, &events))
            }
            "join" => {
                let req = resume_request(m)?;
                let events = b.join(sid, &req, false)?;
                Ok(with_events("joined", sid, &events))
            }
            "disconnect" => {
                b.client_disconnect(sid, m.get("key_id").and_then(Value::as_str), text(m, "reason")?)?;
                Ok(ack("disconnected", sid))
            }
            "escalate" => {
                let trigger = m.get("trigger").and_then(Value::as_str).unwrap_or("human_unavailable");
                b.escalate_to_human(sid, trigger)?;
                Ok(ack("escalated", sid))
            }
            "resolve" => {
                b.human_resolve(sid)?;
                Ok(ack("resolved", sid))
            }
            "extend" => {
                let source = match text(m, "source")? {
                    "observed" => Source::Observed,
                    "requested" => Source::Requested,
                    _ => return Err(Malformed.into()),
                };
                let outcome = b.attempt_authority_extension(sid, &strings(m, "new_scope")?, source);
                let mut f = Map::new();
                match outcome {
                    Err(e) if e.1 == "extension_rejected" => {
                        f.insert("reason".into(), json!("extension_rejected"));
                        f.insert("current_scope".into(), json!(b.scope_of(sid)));
                        Ok(wire::encode_response("rejected", Some(sid), &f))
                    }
                    Err(e) => Err(e.into()),
                    Ok(out) => {
                        f.insert("current_scope".into(), json!(b.scope_of(sid)));
                        let status = match out {
                            AuthorityOutcome::Revert => "revert_requested",
                            AuthorityOutcome::NoChange => "unchanged",
                        };
                        Ok(wire::encode_response(status, Some(sid), &f))
                    }
                }
            }
            "revoke" => {
                let out = b.revoke_key(
                    sid,
                    text(m, "key_id")?,
                    text(m, "reason")?,
                    m.get("signature").and_then(Value::as_str).unwrap_or(""),
                    m.get("requested_by").and_then(Value::as_str),
                )?;
                Ok(ack(
                    match out {
                        Revocation::Revoked => "revoked",
                        Revocation::Requested => "requested",
                    },
                    sid,
                ))
            }
            "add_key" => {
                let key = ClientPublicKey {
                    key_id: text(m, "key_id")?.to_string(),
                    scheme: text(m, "scheme")?.to_string(),
                    material: hex::decode(text(m, "public_key")?).map_err(|_| Malformed)?,
                };
                b.operator_add_key(sid, &key, m.get("signature").and_then(Value::as_str).unwrap_or(""))?;
                Ok(ack("key_added", sid))
            }
            "operator_terminate" => {
                b.operator_terminate(
                    sid,
                    text(m, "reason")?,
                    m.get("signature").and_then(Value::as_str).unwrap_or(""),
                )?;
                Ok(ack("terminated", sid))
            }
            "submit_tool_call" => {
                let content = m.get("content").filter(|c| !c.is_null());
                let out = b.submit_tool_call(
                    sid,
                    text(m, "tool")?,
                    m.get("key").and_then(Value::as_str),
                    m.get("permission").and_then(Value::as_str),
                    content,
                )?;
                Ok(match out {
                    ToolOutcome::Duplicate => wire::encode_error(sid, "duplicate_key"),
                    ToolOutcome::Rejected => wire::encode_error(sid, "queue_full"),
                    ToolOutcome::Queued => ack("queued", sid),
                    ToolOutcome::Forwarded => ack("forwarded", sid),
                })
            }
            "answer_tool_call" => {
                b.answer_tool_call(sid, text(m, "key")?, text(m, "shown_hash")?, text(m, "decision")? == "approve")?;
                Ok(ack("answered", sid))
            }
            "delivered" => {
                b.delivered(sid, text(m, "key")?)?;
                Ok(ack("delivered", sid))
            }
            "completed" => {
                b.completed(sid, text(m, "key")?, m.get("result_hash").and_then(Value::as_str).unwrap_or(""))?;
                Ok(ack("completed", sid))
            }
            "narrow" => {
                b.narrow_authority_scope(sid, &strings(m, "new_scope")?)?;
                Ok(ack("narrowed", sid))
            }
            "terminate" => {
                b.terminate(sid, text(m, "reason")?)?;
                Ok(ack("terminated", sid))
            }
            _ => Ok(wire::encode_error(sid, "unsupported_op")),
        }
    }
}

/// Send a request; the decoded response, or `Err(reason)` for
/// `status: "rejected"`.
pub fn send(server: &WireServer, bridge: &mut Bridge, data: &[u8]) -> std::result::Result<Value, String> {
    let resp = wire::decode_response(&server.handle(bridge, data)).expect("the server answers in canonical JSON");
    if resp["status"] == "rejected" {
        return Err(resp["reason"].as_str().unwrap_or("").to_string());
    }
    Ok(resp)
}
