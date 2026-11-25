//! Runs the language-neutral vectors in `../vectors/*.json` (schema in
//! `../vectors/README.md`) against this crate.

mod common;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use bridge_contract::wire_server::{send, WireServer};
use bridge_contract::*;
use serde_json::{json, Value};

/// A [`Storage`] plus the hooks the vectors need to damage it.
trait TestStorage: Storage {
    fn tamper_prev_hash(&self, sid: &str, index: usize);
    fn fail_next(&self);
    fn tamper_key(&self, sid: &str, key_id: &str, material: &[u8]);
}

impl TestStorage for MemStorage {
    fn tamper_prev_hash(&self, sid: &str, index: usize) {
        self.tamper(sid, index, |e| e.prev_hash = "00".repeat(32));
    }
    fn fail_next(&self) {
        self.fail_next.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    fn tamper_key(&self, sid: &str, key_id: &str, material: &[u8]) {
        MemStorage::tamper_key(self, sid, key_id, material);
    }
}

impl TestStorage for common::FileStorage {
    fn tamper_prev_hash(&self, sid: &str, index: usize) {
        common::FileStorage::tamper_prev_hash(self, sid, index);
    }
    fn fail_next(&self) {
        common::FileStorage::fail_next(self);
    }
    fn tamper_key(&self, sid: &str, key_id: &str, material: &[u8]) {
        common::FileStorage::tamper_key(self, sid, key_id, material);
    }
}

fn operator() -> OperatorKey {
    OperatorKey::new(&[7u8; 32])
}

/// The operator signs at the bridge's current log position, under its id.
fn sig_revoke(b: &Bridge, sid: &str, key_id: &str, reason: &str) -> String {
    let (seq, head) = b.head_of(sid);
    operator().revoke(b.bridge_id(), sid, key_id, reason, seq, &head)
}

fn sig_terminate(b: &Bridge, sid: &str, reason: &str) -> String {
    let (seq, head) = b.head_of(sid);
    operator().terminate(b.bridge_id(), sid, reason, seq, &head)
}

fn add_key_sig(b: &Bridge, k: &ClientPublicKey) -> String {
    let (seq, head) = b.head_of("s");
    operator().add_key(b.bridge_id(), "s", &k.key_id, &k.scheme, &hex::encode(&k.material), seq, &head)
}

fn grant_verifier() -> Arc<dyn GrantVerifier> {
    Arc::new(OperatorGrantVerifier::new(operator().public_key()))
}

struct Runner {
    attach_refused: bool,
    attach_reason: Option<String>,
    /// Keys of second sessions attached by `attach_other`, by (session, key id).
    others: HashMap<(String, String), ClientKey>,
    storage: Arc<dyn TestStorage>,
    clock: Arc<FakeClock>,
    cfg: Config,
    bridge: Bridge,
    sid: String,
    first: String,
    scheme: String,
    scope: Value,
    keys: HashMap<String, ClientKey>,
    seen: HashMap<String, (i64, String)>,
    nonces: HashMap<String, String>,
    /// Requests kept under a name by `as`, for `replay_of`.
    requests: HashMap<String, ResumeRequest>,
    last_add: (String, String, String),
    /// Wire mode: the actions of `WIRE_ROUTED` are sent as Appendix B
    /// messages to this server, over the same bridge.
    server: Option<WireServer>,
}

fn config_of(v: &Value) -> Result<Config> {
    let mut c = (Config::default().t_detach, None, None, None, 900.0, 60.0, 64usize);
    let (mut policy, mut allow) = (DetachedCalls::Refuse, Vec::<String>::new());
    // The Rust bridge does not implement I-CHECKPOINT emission yet;
    // always disable checkpoints so V52-V54 (which set small thresholds)
    // don't expect CHECKPOINT events that the Rust bridge won't emit.
    let (n_cp, t_cp) = (1_000_000_000usize, 1.0e18);
    if let Some(m) = v.as_object() {
        for (k, x) in m {
            match k.as_str() {
                "t_detach" => c.0 = x.as_f64().unwrap(),
                "t_human" => c.1 = Some(x.as_f64().unwrap()),
                "t_call" => c.2 = Some(x.as_f64().unwrap()),
                "t_total" => c.3 = Some(x.as_f64().unwrap()),
                "t_approve" => c.4 = x.as_f64().unwrap(),
                "t_nonce" => c.5 = x.as_f64().unwrap(),
                "q_max" => c.6 = x.as_u64().unwrap() as usize,
                "n_checkpoint" => { /* parsed but ignored; Rust bridge doesn't emit CHECKPOINT */ }
                "t_checkpoint" => { /* parsed but ignored; Rust bridge doesn't emit CHECKPOINT */ }
                "detached_calls" => {
                    policy = match x.as_str().unwrap() {
                        "refuse" => DetachedCalls::Refuse,
                        "queue" => DetachedCalls::Queue,
                        "forward" => DetachedCalls::Forward,
                        other => panic!("unknown detached_calls {other}"),
                    }
                }
                "detached_allow" => allow = strings(x),
                other => panic!("unknown config key {other}"),
            }
        }
    }
    let mut cfg = Config::new(c.0, c.1, c.2, c.3, c.4, c.5, c.6)?.with_detached_calls(policy, allow);
    cfg.n_checkpoint = n_cp;
    cfg.t_checkpoint = t_cp;
    Ok(cfg)
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect()
}

/// A client key of the scheme a vector names (`ed25519` by default).
fn make_key(scheme: &str, key_id: &str, seed: &[u8; 32]) -> ClientKey {
    match scheme {
        "ed25519" => ClientKey::new(key_id, seed),
        "ecdsa-p256" => ClientKey::new_p256(key_id, seed),
        other => panic!("unknown scheme {other}"),
    }
}

fn secret_of(key_id: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(format!("client-seed-{key_id}")).into()
}

impl Runner {
    fn new(vec: &Value, storage: Arc<dyn TestStorage>, wire: bool) -> Result<Runner> {
        let cfg = config_of(&vec["config"])?;
        let clock = FakeClock::new(1000.0);
        let s = &vec["session"];
        let first = s["client_key_id"].as_str().unwrap().to_string();
        let scheme = s["scheme"].as_str().unwrap_or("ed25519").to_string();
        let key = make_key(&scheme, &first, &secret_of(&first));
        let mut bridge = Bridge::new(storage.clone(), clock.clone(), Arc::new(SchemeVerifier), cfg.clone())?
            .with_grant_verifier(grant_verifier());
        let sid = s["session_id"].as_str().unwrap().to_string();
        let identity = SessionIdentity {
            session_id: sid.clone(),
            principal_id: s["principal_id"].as_str().unwrap().to_string(),
            authority_scope: strings(&s["authority_scope"]),
            task_lineage: vec![],
        };
        let public = key.public();
        let grant: Option<String> = match s["grant"].as_str().unwrap_or("ok") {
            "ok" => Some(operator().grant(&identity, &public, DEFAULT_BRIDGE_ID)),
            "none" => None,
            "forged" => Some(OperatorKey::new(&[9u8; 32]).grant(&identity, &public, DEFAULT_BRIDGE_ID)),
            "other-session" => {
                let other = SessionIdentity { session_id: format!("{sid}-x"), ..identity.clone() };
                Some(operator().grant(&other, &public, DEFAULT_BRIDGE_ID))
            }
            "wider-scope" => {
                let narrower = SessionIdentity {
                    authority_scope: identity.authority_scope[..1].to_vec(),
                    ..identity.clone()
                };
                Some(operator().grant(&narrower, &public, DEFAULT_BRIDGE_ID))
            }
            // another public key under the same key id
            "other-key" => {
                let other = make_key(&scheme, &first, &secret_of(&format!("wrong-{first}")));
                Some(operator().grant(&identity, &other.public(), DEFAULT_BRIDGE_ID))
            }
            "other-bridge" => Some(operator().grant(&identity, &public, "bridge-elsewhere")),
            other => return Err(BridgeError::new(format!("unknown grant kind {other}"))),
        };
        let proof: Option<String> = match s["possession"].as_str().unwrap_or("ok") {
            "ok" => Some(key.prove_attach(&identity, DEFAULT_BRIDGE_ID)),
            "none" => None,
            "wrong-key" => {
                let other = make_key(&scheme, &first, &secret_of(&format!("wrong-{first}")));
                Some(other.prove_attach(&identity, DEFAULT_BRIDGE_ID))
            }
            "other-bridge" => Some(key.prove_attach(&identity, "bridge-elsewhere")),
            other => return Err(BridgeError::new(format!("unknown possession kind {other}"))),
        };
        let server = wire.then(WireServer::new);
        let attached = match &server {
            // session creation is an `attach` message in wire mode
            Some(server) => {
                let scope: Vec<&str> = identity.authority_scope.iter().map(String::as_str).collect();
                let msg = wire::op_attach(
                    &sid, &identity.principal_id, &scope, &[], &public.key_id, &public.scheme,
                    &hex::encode(&public.material), grant.as_deref(), proof.as_deref(),
                );
                send(server, &mut bridge, &msg).map(|_| ()).map_err(|reason| BridgeError::new(format!("{reason}: attach (wire)")))
            }
            None => bridge.attach(&identity, &public, grant.as_deref(), proof.as_deref()),
        };
        let (attach_refused, attach_reason) = match attached {
            Ok(()) => (false, None),
            Err(e) if e.0.starts_with("grant_invalid") => (true, Some("grant_invalid".to_string())),
            Err(e) if e.0.starts_with("possession_invalid") => (true, Some("possession_invalid".to_string())),
            Err(e) => return Err(e),
        };
        let mut r = Runner {
            attach_refused,
            attach_reason,
            others: HashMap::new(),
            storage,
            clock,
            cfg,
            bridge,
            sid,
            first: first.clone(),
            scheme,
            scope: s["authority_scope"].clone(),
            keys: HashMap::from([(first.clone(), key)]),
            seen: HashMap::new(),
            nonces: HashMap::new(),
            requests: HashMap::new(),
            last_add: Default::default(),
            server,
        };
        if !attach_refused {
            r.sync(&first);
        }
        Ok(r)
    }

    /// The operator signature an action presents: `ok` (at the bridge's
    /// current log position, under its id), `none` (absent), `forged`
    /// (another key's), `other-operation` (the operator's, over a different
    /// operation of the same session), `other-bridge` (bound to another
    /// bridge id) or `stale` (bound to the position of the first event).
    fn operator_sig(&self, a: &Value, op: &str, args: &[&str]) -> Result<String> {
        let sid = self.sid.as_str();
        let mut signer = operator();
        let mut bid = self.bridge.bridge_id().to_string();
        let (mut seq, mut head) = self.bridge.head_of(sid);
        match a["sig"].as_str().unwrap_or("ok") {
            "ok" => {}
            "none" => return Ok(String::new()),
            "forged" => signer = OperatorKey::new(&[9u8; 32]),
            "other-bridge" => bid = "bridge-elsewhere".to_string(),
            "stale" => {
                seq = 0;
                head = self.storage.read_log(sid)?[0].hash();
            }
            "other-operation" => {
                return Ok(match op {
                    "revoke" => signer.terminate(&bid, sid, "other", seq, &head),
                    "add_key" => signer.revoke(&bid, sid, args[0], "compromise", seq, &head),
                    _ => signer.revoke(&bid, sid, &self.first, "compromise", seq, &head),
                })
            }
            other => return Err(BridgeError::new(format!("unknown signature kind {other}"))),
        }
        Ok(match op {
            "revoke" => signer.revoke(&bid, sid, args[0], args[1], seq, &head),
            "add_key" => signer.add_key(&bid, sid, args[0], args[1], args[2], seq, &head),
            _ => signer.terminate(&bid, sid, args[0], seq, &head),
        })
    }

    /// Send one request to the wire server; a rejection is an error whose
    /// text names the wire reason (`rejected: <reason> (wire)`).
    fn send(&mut self, data: Vec<u8>) -> Result<Value> {
        let server = self.server.as_ref().expect("wire mode");
        send(server, &mut self.bridge, &data).map_err(|reason| BridgeError::new(format!("rejected: {reason} (wire)")))
    }

    /// A challenge for `key_id`: the nonce is bound to that key id.
    fn fresh_nonce(&mut self, key_id: &str) -> Result<String> {
        if self.server.is_none() {
            return Ok(self.bridge.challenge(&self.sid, key_id)?.nonce);
        }
        let resp = self.send(wire::op_challenge(&self.sid, key_id))?;
        Ok(resp["nonce"].as_str().expect("a nonce").to_string())
    }

    /// The hash an `answer` action reports.
    fn answer_hash(&self, a: &Value) -> Result<String> {
        let key = a["key"].as_str().unwrap();
        Ok(match a["hash"].as_str().unwrap_or("shown") {
            "shown" => self.bridge.shown_hash_of(&self.sid, key)?,
            // what a client that approved only the arguments reports
            "content-only" => content_hash(&a["content"]),
            _ => content_hash(&serde_json::json!({"other": true})),
        })
    }

    /// Wire mode: send the action as a wire message, or `None` for an action
    /// with no wire form here (clock and restart hooks, log and registry
    /// tampering, a re-attach left incomplete or flagged as a transport
    /// replay), which the bridge takes directly.
    fn act_wire(&mut self, a: &Value) -> Option<Result<()>> {
        let sid = self.sid.clone();
        let kind = a["do"].as_str().unwrap();
        let sent = match kind {
            "challenge" => self.fresh_nonce(&a["client"].as_str().unwrap_or(&self.first).to_string()).map(|n| {
                if let Some(name) = a["as"].as_str() {
                    self.nonces.insert(name.to_string(), n);
                }
            }),
            "add_client" => (|| {
                let c = a["client"].as_str().unwrap().to_string();
                let key = self.key(&c);
                let (via, nonce, sig) = self.add_client_request(a, &key)?;
                let msg = wire::op_add_client(&sid, &via, &c, key.scheme(), &hex::encode(key.public_key()), &nonce, &sig);
                self.send(msg)?;
                self.sync(&c);
                Ok(())
            })(),
            "reattach" | "join" => {
                if kind == "reattach"
                    && (a["transport_replay"].as_bool().unwrap_or(false) || !a["complete"].as_bool().unwrap_or(true))
                {
                    return None;
                }
                let op = if kind == "join" { ResumeOp::Join } else { ResumeOp::Reattach };
                self.request(a, op).and_then(|req| {
                    let build = if kind == "join" { wire::op_join } else { wire::op_reattach };
                    self.send(build(&sid, &req.key_id, &req.nonce, req.seq as u64, &req.hash, &req.signature)).map(|_| ())
                })
            }
            "disconnect" => {
                let gone: Vec<String> = match a["client"].as_str() {
                    Some(c) => vec![c.to_string()],
                    None => self.bridge.client_set(&sid),
                };
                for c in &gone {
                    self.sync(c);
                }
                self.send(wire::op_disconnect(&sid, "client_disconnect", a["client"].as_str())).map(|_| ())
            }
            "escalate" => self.send(wire::op_escalate(&sid, None)).map(|_| ()),
            "tool_call" => {
                let content = a.get("content").cloned().unwrap_or(Value::Null);
                let msg = wire::op_submit_tool_call(&sid, a["tool"].as_str().unwrap(), &content, a["key"].as_str(), a["permission"].as_str());
                match self.send(msg) {
                    // a duplicate key or a full queue is answered "rejected"
                    // on the wire; the bridge returns normally, as in plain mode
                    Err(e) if e.0.contains("rejected: duplicate_key ") || e.0.contains("rejected: queue_full ") => Ok(()),
                    other => other.map(|_| ()),
                }
            }
            "answer" => self.answer_hash(a).and_then(|h| {
                let decision = if a["approve"].as_bool().unwrap_or(true) { "approve" } else { "deny" };
                self.send(wire::op_answer_tool_call(&sid, a["key"].as_str().unwrap(), &h, decision)).map(|_| ())
            }),
            "narrow" => {
                let scope = strings(&a["scope"]);
                let scope: Vec<&str> = scope.iter().map(String::as_str).collect();
                self.send(wire::op_narrow(&sid, &scope)).map(|_| ())
            }
            "resolve" => (|| {
                if a["answer"].as_str().unwrap_or("all") == "all" {
                    for k in self.bridge.unanswered_keys(&sid) {
                        let h = self.bridge.shown_hash_of(&sid, &k)?;
                        self.send(wire::op_answer_tool_call(&sid, &k, &h, "approve"))?;
                    }
                }
                self.send(wire::op_resolve(&sid)).map(|_| ())
            })(),
            "extend" => {
                let scope = strings(&a["scope"]);
                let scope: Vec<&str> = scope.iter().map(String::as_str).collect();
                let source = a["source"].as_str().unwrap_or("requested");
                self.send(wire::op_extend(&sid, &scope, source)).map(|resp| {
                    assert_eq!(strings(&resp["current_scope"]), self.bridge.scope_of(&sid));
                })
            }
            "revoke" => (|| {
                let client = a["client"].as_str().unwrap();
                let reason = a["reason"].as_str().unwrap_or("rotation");
                let signature = if a["signed"].as_bool().unwrap_or(true) {
                    self.operator_sig(a, "revoke", &[client, reason])?
                } else {
                    String::new()
                };
                let sig = (!signature.is_empty()).then_some(signature.as_str());
                self.send(wire::op_revoke(&sid, client, reason, sig, a["requested_by"].as_str())).map(|_| ())
            })(),
            "operator_add_key" => (|| {
                let c = a["client"].as_str().unwrap().to_string();
                let key = make_key(&self.scheme, &c, &secret_of(&c));
                let public = key.public();
                let pub_hex = hex::encode(&public.material);
                let signature = self.operator_sig(a, "add_key", &[&c, &public.scheme, &pub_hex])?;
                let sig = (!signature.is_empty()).then_some(signature.as_str());
                self.send(wire::op_add_key(&sid, &c, &public.scheme, &pub_hex, sig))?;
                self.keys.insert(c.clone(), key);
                self.sync(&c);
                Ok(())
            })(),
            "operator_terminate" => (|| {
                let signature = self.operator_sig(a, "terminate", &["all_keys_revoked"])?;
                let sig = (!signature.is_empty()).then_some(signature.as_str());
                self.send(wire::op_operator_terminate(&sid, "all_keys_revoked", sig)).map(|_| ())
            })(),
            "terminate" => self.send(wire::op_terminate(&sid, "terminated")).map(|_| ()),
            "delivered" => self.send(wire::op_delivered(&sid, a["key"].as_str().unwrap())).map(|_| ()),
            "completed" => {
                let rh = a["result_hash"].as_str().unwrap_or("");
                self.send(wire::op_completed(&sid, a["key"].as_str().unwrap(), Some(rh))).map(|_| ())
            }
            _ => return None,
        };
        Some(sent)
    }

    fn cell(&self) -> Vec<&'static str> {
        self.bridge.cell_of(&self.sid).names()
    }

    fn tip(&self) -> (i64, String) {
        let ev = self.bridge.events(&self.sid).pop().unwrap();
        (ev.sequence as i64, ev.hash())
    }

    fn sync(&mut self, client: &str) {
        let t = self.tip();
        self.seen.insert(client.to_string(), t);
    }

    fn key(&mut self, client: &str) -> ClientKey {
        let scheme = self.scheme.clone();
        self.keys
            .entry(client.to_string())
            .or_insert_with(|| make_key(&scheme, client, &secret_of(client)))
            .clone()
    }

    fn request(&mut self, a: &Value, op: ResumeOp) -> Result<ResumeRequest> {
        if let Some(name) = a["replay_of"].as_str() {
            return Ok(self.requests[name].clone()); // an earlier request, byte for byte
        }
        let req = self.new_request(a, op)?;
        if let Some(name) = a["as"].as_str() {
            self.requests.insert(name.to_string(), req.clone());
        }
        Ok(req)
    }

    fn new_request(&mut self, a: &Value, op: ResumeOp) -> Result<ResumeRequest> {
        let client = a["client"].as_str().unwrap_or(&self.first).to_string();
        let key = self.key(&client);
        let nonce = match a["nonce"].as_str().unwrap_or("fresh") {
            "fresh" => self.fresh_nonce(&client)?,
            "unknown" => "ab".repeat(16),
            // issued for a second session
            "other-session" => self.bridge.challenge(a["from_session"].as_str().unwrap(), &client)?.nonce,
            name => self.nonces[name].clone(),
        };
        if let Some(n) = a["as"].as_str() {
            self.nonces.insert(n.to_string(), nonce.clone());
        }
        let (tip_seq, tip_hash) = self.tip();
        let genesis = self.bridge.events(&self.sid)[0].hash();
        let (mut seq, mut h) = self.seen.get(&client).cloned().unwrap_or((0, genesis));
        match a["prefix"].as_str().unwrap_or("seen") {
            "seen" => {}
            "tip" => (seq, h) = (tip_seq, tip_hash),
            "hash-mismatch" => h = "00".repeat(32),
            "beyond" => seq = tip_seq + 5,
            other => panic!("unknown prefix {other}"),
        }
        let mut req = key.request_for(op, &self.sid, &nonce, seq, &h);
        match a["proof"].as_str().unwrap_or("valid") {
            "valid" => {}
            "invalid" => req.signature = "invalid".into(),
            // a real signature by another key of the same scheme
            "wrong-key" => {
                let other = make_key(&self.scheme, &client, &secret_of(&format!("wrong-{client}")));
                req.signature = other.sign_for(op, &self.sid, &nonce, seq, &h);
            }
            // a real signature by the registered key over a different message
            "other-message" => req.signature = key.sign_for(op, &self.sid, &nonce, seq + 1, &h),
            // a real signature by the registered key for the other operation
            "other-operation" => {
                let other = if op == ResumeOp::Reattach { ResumeOp::Join } else { ResumeOp::Reattach };
                req.signature = key.sign_for(other, &self.sid, &nonce, seq, &h);
            }
            // a signature by the key a second session registered under this key id
            "other-session-key" => {
                let from = a["from_session"].as_str().unwrap().to_string();
                let other = self.others[&(from, client.clone())].clone();
                req.signature = other.sign_for(op, &self.sid, &nonce, seq, &h);
            }
            // the tagged tuple without the key id
            "no-key-id" => {
                req.signature = key.sign_bytes(&wire::canonical_bytes(&serde_json::json!([op.tag(), self.sid, nonce, seq, h])));
            }
            // the tuple without the domain tag
            "untagged" => {
                req.signature = key.sign_bytes(&wire::canonical_bytes(&serde_json::json!([self.sid, nonce, seq, h])));
            }
            other => panic!("unknown proof {other}"),
        }
        Ok(req)
    }

    /// (via key id, nonce, signature) an `add_client` action presents; see
    /// `vectors/README.md` for the `proof` values.
    fn add_client_request(&mut self, a: &Value, new: &ClientKey) -> Result<(String, String, String)> {
        let conn = self.bridge.client_set(&self.sid);
        let via = a["via"].as_str().map(String::from).or_else(|| conn.first().cloned()).unwrap_or_else(|| self.first.clone());
        let proof = a["proof"].as_str().unwrap_or("valid").to_string();
        if proof == "replay" {
            return Ok(self.last_add.clone());
        }
        let signer = self.key(&via);
        let nonce = match a["nonce"].as_str() {
            // issued for a second session
            Some("other-session") => self.bridge.challenge(a["from_session"].as_str().unwrap(), &via)?.nonce,
            Some(name) => self.nonces[name].clone(),
            None => self.fresh_nonce(&via)?,
        };
        let public = new.public();
        let sig = match proof.as_str() {
            "valid" => signer.sign_add_client(&self.sid, &public, &nonce),
            "none" => String::new(),
            "forged" => make_key(&self.scheme, &via, &secret_of(&format!("wrong-{via}"))).sign_add_client(&self.sid, &public, &nonce),
            "other-operation" => {
                let (seq, h) = self.seen.get(&via).cloned().unwrap_or_else(|| (0, self.bridge.events(&self.sid)[0].hash()));
                signer.sign_for(ResumeOp::Join, &self.sid, &nonce, seq, &h)
            }
            other => panic!("unknown proof {other}"),
        };
        self.last_add = (via, nonce, sig);
        Ok(self.last_add.clone())
    }

    fn act(&mut self, a: &Value) -> Result<()> {
        if self.server.is_some() {
            if let Some(done) = self.act_wire(a) {
                return done;
            }
        }
        let sid = self.sid.clone();
        match a["do"].as_str().unwrap() {
            "disconnect" => {
                let gone: Vec<String> = match a["client"].as_str() {
                    Some(c) => vec![c.to_string()],
                    None => self.bridge.client_set(&sid),
                };
                for c in &gone {
                    self.sync(c);
                }
                self.bridge.client_disconnect(&sid, a["client"].as_str(), "client_disconnect")
            }
            "sync" => {
                self.sync(a["client"].as_str().unwrap());
                Ok(())
            }
            "escalate" => self.bridge.escalate_to_human(&sid, "human_unavailable"),
            "resolve" => {
                if a["answer"].as_str().unwrap_or("all") == "all" {
                    for k in self.bridge.unanswered_keys(&sid) {
                        let h = self.bridge.shown_hash_of(&sid, &k)?;
                        self.bridge.answer_tool_call(&sid, &k, &h, true)?;
                    }
                }
                self.bridge.human_resolve(&sid)
            }
            "answer" => {
                let key = a["key"].as_str().unwrap();
                let h = self.answer_hash(a)?;
                self.bridge.answer_tool_call(&sid, key, &h, a["approve"].as_bool().unwrap_or(true))
            }
            "tool_call" => self
                .bridge
                .submit_tool_call(
                    &sid,
                    a["tool"].as_str().unwrap(),
                    a["key"].as_str(),
                    a["permission"].as_str(),
                    a.get("content"),
                )
                .map(|_| ()),
            "delivered" => self.bridge.delivered(&sid, a["key"].as_str().unwrap()),
            "completed" => self.bridge.completed(&sid, a["key"].as_str().unwrap(), a["result_hash"].as_str().unwrap_or("")),
            "narrow" => self.bridge.narrow_authority_scope(&sid, &strings(&a["scope"])).map(|_| ()),
            "extend" => {
                let source = match a["source"].as_str().unwrap_or("requested") {
                    "observed" => Source::Observed,
                    _ => Source::Requested,
                };
                self.bridge.attempt_authority_extension(&sid, &strings(&a["scope"]), source).map(|_| ())
            }
            "attach_other" => {
                // a second, validly granted session on the same bridge whose
                // client key carries the given key id
                let c = a["client"].as_str().unwrap().to_string();
                let other_sid = a["session_id"].as_str().unwrap().to_string();
                let key = make_key(&self.scheme, &c, &secret_of(&format!("other-{other_sid}-{c}")));
                let id = SessionIdentity {
                    session_id: other_sid.clone(),
                    principal_id: a["principal_id"].as_str().unwrap_or("user-mallory").to_string(),
                    authority_scope: strings(&self.scope),
                    task_lineage: vec![],
                };
                common::attach_ok(&mut self.bridge, &id, &key)?;
                self.others.insert((other_sid, c), key);
                Ok(())
            }
            "tamper_registry" => {
                let c = a["client"].as_str().unwrap();
                match a["how"].as_str().unwrap() {
                    "other-key" => {
                        let stray = make_key(&self.scheme, c, &secret_of(&format!("wrong-{c}")));
                        self.storage.tamper_key(&sid, c, &stray.public_key());
                    }
                    "extra" => {
                        let stray = make_key(&self.scheme, c, &secret_of(&format!("wrong-{c}")));
                        self.storage.register_key(&sid, c, stray.scheme(), &stray.public_key())?;
                    }
                    "missing" => self.storage.unregister_key(&sid, c)?,
                    other => panic!("unknown registry tampering {other}"),
                }
                Ok(())
            }
            "add_client" => {
                let c = a["client"].as_str().unwrap().to_string();
                let key = self.key(&c);
                let (via, nonce, sig) = self.add_client_request(a, &key)?;
                self.bridge.add_client_key(&sid, &via, &c, key.scheme(), &key.public_key(), &nonce, &sig)?;
                self.sync(&c);
                Ok(())
            }
            "revoke" => {
                let client = a["client"].as_str().unwrap();
                let reason = a["reason"].as_str().unwrap_or("rotation");
                let signature = if a["signed"].as_bool().unwrap_or(true) {
                    self.operator_sig(a, "revoke", &[client, reason])?
                } else {
                    String::new()
                };
                self.bridge.revoke_key(&sid, client, reason, &signature, a["requested_by"].as_str()).map(|_| ())
            }
            "operator_add_key" => {
                let c = a["client"].as_str().unwrap().to_string();
                let key = make_key(&self.scheme, &c, &secret_of(&c));
                let public = key.public();
                let pub_hex = hex::encode(&public.material);
                let signature = self.operator_sig(a, "add_key", &[&c, &public.scheme, &pub_hex])?;
                self.bridge.operator_add_key(&sid, &public, &signature)?;
                self.keys.insert(c.clone(), key);
                self.sync(&c);
                Ok(())
            }
            "operator_terminate" => {
                let signature = self.operator_sig(a, "terminate", &["all_keys_revoked"])?;
                self.bridge.operator_terminate(&sid, "all_keys_revoked", &signature)
            }
            "challenge" => {
                let who = a["client"].as_str().unwrap_or(&self.first).to_string();
                let n = self.bridge.challenge(&sid, &who)?.nonce;
                if let Some(name) = a["as"].as_str() {
                    self.nonces.insert(name.to_string(), n);
                }
                Ok(())
            }
            "challenge_uniform" => {
                // I11a: the session and a session the bridge never saw are
                // refused with the same text
                let who = a["client"].as_str().unwrap_or(&self.first).to_string();
                let own = self.bridge.challenge(&sid, &who).err().map(|e| e.0);
                let other = self.bridge.challenge("no-such-session", &who).err().map(|e| e.0);
                assert!(own.is_some() && own == other, "{own:?} vs {other:?}");
                Ok(())
            }
            "reattach_uniform" => {
                // I11a: a re-attach request for the session and for a
                // session the bridge never saw are refused with the same text
                let req = self.request(a, ResumeOp::Reattach)?;
                let own = self.bridge.begin_resume(&sid, &req, false).err().map(|e| e.0);
                let other = self.bridge.begin_resume("no-such-session", &req, false).err().map(|e| e.0);
                assert!(own.is_some() && own == other, "{own:?} vs {other:?}");
                Ok(())
            }
            "reattach_key_uniform" => {
                // a request that names an unregistered key and one whose
                // signature does not verify are refused with the same text
                let bad = json!({"client": self.first.clone(), "proof": "invalid"});
                let stranger = json!({"client": a["client"].clone()});
                let mut texts = vec![];
                for variant in [&bad, &stranger] {
                    let req = self.request(variant, ResumeOp::Reattach)?;
                    texts.push(self.bridge.begin_resume(&sid, &req, false).err().map(|e| e.0));
                }
                assert!(texts[0].is_some() && texts[0] == texts[1], "{texts:?}");
                Ok(())
            }
            kind @ ("reattach" | "join") => {
                let op = if kind == "join" { ResumeOp::Join } else { ResumeOp::Reattach };
                let req = self.request(a, op)?;
                let replay = a["transport_replay"].as_bool().unwrap_or(false);
                if kind == "join" {
                    return self.bridge.join(&sid, &req, replay).map(|_| ());
                }
                self.bridge.begin_resume(&sid, &req, replay)?;
                if a["complete"].as_bool().unwrap_or(true) && self.bridge.cell_of(&sid).att == Attachment::Res {
                    self.bridge.complete_resume(&sid)?;
                }
                Ok(())
            }
            "complete_resume" => self.bridge.complete_resume(&sid).map(|_| ()),
            "advance" => {
                self.clock.advance(a["seconds"].as_f64().unwrap());
                if a["tick"].as_bool() == Some(false) {
                    return Ok(()); // the clock moves and no timer is evaluated yet
                }
                self.bridge.tick(None)
            }
            "tick" => self.bridge.tick(None),
            "restart" => {
                self.clock.advance(a["downtime"].as_f64().unwrap_or(0.0));
                self.bridge = Bridge::recover_with(
                    self.storage.clone(),
                    self.clock.clone(),
                    Arc::new(SchemeVerifier),
                    self.cfg.clone(),
                    Some(grant_verifier()),
                )?;
                Ok(())
            }
            "plant_malformed_log" => {
                // a second session whose durable log cannot be replayed
                let other = a["session_id"].as_str().unwrap().to_string();
                let ev = match a["how"].as_str().unwrap() {
                    "no-genesis" => Event {
                        kind: Kind::DETACHMENT,
                        session_id: other.clone(),
                        sequence: 0,
                        prev_hash: String::new(),
                        payload: json!({}),
                        timestamp: 1.0,
                    },
                    "missing-field" => Event {
                        kind: Kind::ATTACHED,
                        session_id: other.clone(),
                        sequence: 0,
                        prev_hash: String::new(),
                        payload: json!({"client_key_id": "ck-x"}),
                        timestamp: 1.0,
                    },
                    how => panic!("unknown malformed log {how}"),
                };
                self.storage.append_batch(&other, vec![ev])
            }
            "other_quarantined" => {
                assert!(self.bridge.is_quarantined(a["session_id"].as_str().unwrap()));
                Ok(())
            }
            "tamper_log" => {
                self.storage.tamper_prev_hash(&sid, a["index"].as_u64().unwrap() as usize);
                Ok(())
            }
            "terminate" => self.bridge.terminate(&sid, "terminated"),
            other => panic!("unknown action {other}"),
        }
    }
}

fn run_vector(vec: &Value, storage: Arc<dyn TestStorage>, wire: bool) -> Vec<String> {
    let expect = &vec["expect"];
    if expect["config_error"].as_bool().unwrap_or(false) {
        return match Runner::new(vec, storage, wire) {
            Err(_) => vec![],
            Ok(_) => vec!["expected a configuration error".into()],
        };
    }
    let mut r = Runner::new(vec, storage, wire).expect("bridge builds");
    let mut fails = vec![];
    let want_refused = expect["attach_refused"].as_bool().unwrap_or(false);
    if r.attach_refused || want_refused {
        if r.attach_refused != want_refused {
            fails.push(format!(
                "attach {}, expected {}",
                if r.attach_refused { "refused" } else { "accepted" },
                if want_refused { "refusal" } else { "success" }
            ));
        }
        if want_refused && r.attach_refused {
            let want = expect["attach_reason"].as_str().unwrap_or("grant_invalid");
            if r.attach_reason.as_deref() != Some(want) {
                fails.push(format!("attach refused as {:?}, expected {want}", r.attach_reason));
            }
        }
        if !r.storage.read_log(&r.sid).map(|l| l.is_empty()).unwrap_or(false) {
            fails.push("a refused attach committed events".into());
        }
        return fails;
    }
    // an action with `times: n` is applied n times
    let actions: Vec<&Value> = vec["actions"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|a| std::iter::repeat(a).take(a["times"].as_u64().unwrap_or(1) as usize))
        .collect();
    for (i, a) in actions.into_iter().enumerate() {
        let outcome = r.act(a);
        let refused = outcome.is_err();
        if let Err(e) = &outcome {
            if a["sig"].as_str().unwrap_or("ok") != "ok"
                && !e.0.starts_with("operator_signature_invalid")
                && !e.0.starts_with("rejected: operator_signature_invalid ")
            {
                fails.push(format!("action {i} {}: refused as {}, expected operator_signature_invalid", a["do"], e.0));
            }
        }
        if let (Err(e), Some(want)) = (&outcome, a["wire_reason"].as_str()) {
            if e.0.starts_with("rejected: ") && !e.0.starts_with(&format!("rejected: {want} ")) {
                fails.push(format!("action {i} {}: refused on the wire as {}, expected {want}", a["do"], e.0));
            }
        }
        if let (Err(e), Some(reason), "add_client") = (&outcome, a["reason"].as_str(), a["do"].as_str().unwrap()) {
            if !e.0.contains(&format!("rejected: {reason} ")) {
                fails.push(format!("action {i} add_client: refused as {}, expected {reason}", e.0));
            }
        }
        let want_err = a["error"].as_bool().unwrap_or(false);
        if refused != want_err {
            fails.push(format!(
                "action {i} {}: {}, expected {}",
                a["do"],
                if refused { "refused" } else { "accepted" },
                if want_err { "refusal" } else { "success" }
            ));
        }
        if let Some(c) = a.get("then_cell") {
            let want: Vec<String> = strings(c);
            if r.cell() != want {
                fails.push(format!("action {i}: cell {:?} != {:?}", r.cell(), want));
            }
        }
    }
    let log = r.bridge.events(&r.sid);
    let got: Vec<&str> = log.iter().map(|e| e.kind.as_str()).collect();
    let want = strings(&expect["events"]);
    if got != want.iter().map(String::as_str).collect::<Vec<_>>() {
        fails.push(format!("events\n  got  {got:?}\n  want {want:?}"));
    }
    if r.cell() != strings(&expect["cell"]) {
        fails.push(format!("cell {:?} != {}", r.cell(), expect["cell"]));
    }
    if r.bridge.scope_version(&r.sid) != expect["scope_version"].as_u64().unwrap() {
        fails.push(format!("scope_version {} != {}", r.bridge.scope_version(&r.sid), expect["scope_version"]));
    }
    if let Some(m) = expect.get("other_events").and_then(Value::as_object) {
        for (other, want) in m {
            let got: Vec<String> = r.bridge.events(other).iter().map(|e| e.kind.as_str().to_string()).collect();
            if got != strings(want) {
                fails.push(format!("events of {other}\n  got  {got:?}\n  want {want}"));
            }
        }
    }
    if let Some(q) = expect.get("queue") {
        if r.bridge.queue_keys(&r.sid) != strings(q) {
            fails.push(format!("queue {:?} != {}", r.bridge.queue_keys(&r.sid), q));
        }
    }
    if let Some(f) = expect.get("forwarded") {
        let got: Vec<String> = r.bridge.forwarded.iter().map(|(_, k, _)| k.clone()).collect();
        if got != strings(f) {
            fails.push(format!("forwarded {got:?} != {f}"));
        }
    }
    if let Some(f) = expect.get("forwarded_calls") {
        let got: serde_json::Map<String, Value> = r
            .bridge
            .forwarded_calls
            .iter()
            .filter(|((s, _), _)| *s == r.sid)
            .map(|((_, k), c)| {
                (k.clone(), serde_json::json!({"tool": c.tool, "permission": c.permission, "content": c.content}))
            })
            .collect();
        if Value::Object(got.clone()) != *f {
            fails.push(format!("forwarded calls {got:?} != {f}"));
        }
    }
    if let Some(c) = expect.get("clients") {
        let mut got = r.bridge.client_set(&r.sid);
        got.sort();
        if got != strings(c) {
            fails.push(format!("clients {got:?} != {c}"));
        }
    }
    if let Some(x) = expect.get("key_exhausted") {
        if r.bridge.is_key_exhausted(&r.sid) != x.as_bool().unwrap() {
            fails.push(format!("key_exhausted {} != {x}", r.bridge.is_key_exhausted(&r.sid)));
        }
    }
    if let Some(x) = expect.get("revoked") {
        if r.bridge.revoked_keys(&r.sid) != strings(x) {
            fails.push(format!("revoked {:?} != {x}", r.bridge.revoked_keys(&r.sid)));
        }
    }
    if let Some(q) = expect.get("quarantined") {
        if r.bridge.is_quarantined(&r.sid) != q.as_bool().unwrap() {
            fails.push(format!("quarantined {} != {q}", r.bridge.is_quarantined(&r.sid)));
        }
    }
    if let Some(x) = expect.get("registry") {
        let mut got = r.storage.key_ids(&r.sid).unwrap();
        got.sort();
        if got != strings(x) {
            fails.push(format!("registry {got:?} != {x}"));
        }
    }
    if let Some(n) = expect.get("reverts") {
        if r.bridge.revert_requests.len() as u64 != n.as_u64().unwrap() {
            fails.push(format!("reverts {} != {n}", r.bridge.revert_requests.len()));
        }
    }
    if let Some(m) = expect.get("last_event_payload").and_then(Value::as_object) {
        let last = log.last().unwrap();
        for (k, v) in m {
            if &last.payload[k] != v {
                fails.push(format!("last event payload[{k}] = {} != {v}", last.payload[k]));
            }
        }
    }
    fails
}

fn vector_files() -> Vec<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vectors");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .expect("vectors directory")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with('V')))
        .collect();
    files.sort();
    files
}

fn run_all(label: &str, wire: bool, make: impl Fn() -> Arc<dyn TestStorage>) {
    let files = vector_files();
    assert!(files.len() >= 28, "expected at least 28 vectors, found {}", files.len());
    let mut bad = 0;
    let mut skipped: Vec<String> = Vec::new();
    for f in &files {
        let v: Value = serde_json::from_str(&std::fs::read_to_string(f).unwrap()).unwrap();
        // `requires` names optional features; this crate has no CHECKPOINT
        // emission, so a vector that needs it is Python-only.
        if v["requires"].as_array().is_some_and(|r| r.iter().any(|x| x == "checkpoint")) {
            println!("{label} skip {} {} (requires checkpoint)", v["id"], v["title"]);
            skipped.push(v["id"].as_str().unwrap_or("?").to_string());
            continue;
        }
        let fails = run_vector(&v, make(), wire);
        println!("{label} {} {} {}", if fails.is_empty() { "ok  " } else { "FAIL" }, v["id"], v["title"]);
        for m in &fails {
            println!("    {m}");
        }
        bad += !fails.is_empty() as usize;
    }
    assert_eq!(bad, 0, "{bad} vector(s) failed on {label}");
    // The paper names exactly these as the vectors the crate does not run.
    assert_eq!(skipped, ["V52", "V53", "V54", "V54b", "V54c", "V88", "V89"], "skipped vectors on {label}");
}

#[test]
fn all_vectors_pass_on_memory_storage() {
    run_all("mem", false, || MemStorage::new());
}

/// The wire mode of `run_vectors.py --wire`: the actions the front-end
/// serves are sent as Appendix B messages with real signatures, and the same
/// expectations are checked.
#[test]
fn all_vectors_pass_through_the_wire_server() {
    run_all("wire", true, || MemStorage::new());
}

#[test]
fn all_vectors_pass_on_file_storage() {
    // a fresh directory made for this run and removed on every exit, a
    // failing run included
    let root = common::TempDir::new("vectors");
    let n = std::sync::atomic::AtomicUsize::new(0);
    run_all("file", false, || {
        let dir = root.path().join(format!("v{}", n.fetch_add(1, std::sync::atomic::Ordering::SeqCst)));
        common::FileStorage::new(dir)
    });
}

#[test]
fn a_torn_trailing_record_is_discarded_on_file_storage() {
    use std::io::Write;
    let root = common::TempDir::new("torn");
    let storage = common::FileStorage::new(root.path().to_path_buf());
    let clock = FakeClock::new(0.0);
    let key = ClientKey::new("ck-1", &[1u8; 32]);
    let mut b = Bridge::new(storage.clone(), clock.clone(), Arc::new(SchemeVerifier), Config::default())
        .unwrap()
        .with_grant_verifier(grant_verifier());
    let id = SessionIdentity {
        session_id: "s".into(),
        principal_id: "p".into(),
        authority_scope: vec!["a".into()],
        task_lineage: vec![],
    };
    common::attach_ok(&mut b, &id, &key).unwrap();
    let whole = storage.read_log("s").unwrap();
    assert_eq!(whole.len(), 1);
    // a crash in the middle of the next append: half a record, no newline
    let log = std::fs::read_dir(root.path().join("logs")).unwrap().next().unwrap().unwrap().path();
    std::fs::OpenOptions::new().append(true).open(&log).unwrap().write_all(br#"{"kind":"HUMAN_PEN"#).unwrap();
    assert_eq!(storage.read_log("s").unwrap(), whole, "the torn record is discarded");
    // the same record cut at a newline is discarded too
    std::fs::OpenOptions::new().append(true).open(&log).unwrap().write_all(b"\n").unwrap();
    assert_eq!(storage.read_log("s").unwrap(), whole);
    // a damaged record that is not the last is an error, not silently dropped
    std::fs::OpenOptions::new().append(true).open(&log).unwrap().write_all(whole_line(&whole[0]).as_bytes()).unwrap();
    assert!(storage.read_log("s").is_err());
}

fn whole_line(e: &Event) -> String {
    format!("{}\n", String::from_utf8(e.canonical()).unwrap())
}

#[test]
fn bridge_and_collaborators_are_send_and_sync() {
    fn send<T: Send>() {}
    fn send_sync<T: Send + Sync>() {}
    send::<Bridge>();
    send_sync::<MemStorage>();
    send_sync::<common::FileStorage>();
    send_sync::<FakeClock>();
    send_sync::<SystemClock>();
    send_sync::<Ed25519Verifier>();
    send_sync::<EcdsaP256Verifier>();
    send_sync::<SchemeVerifier>();
    send_sync::<Config>();
}

#[test]
fn a_shared_bridge_serves_sessions_from_several_threads() {
    use std::sync::Mutex;
    let storage = MemStorage::new();
    let bridge = Arc::new(Mutex::new(
        Bridge::new(storage.clone(), FakeClock::new(0.0), Arc::new(SchemeVerifier), Config::default())
            .unwrap()
            .with_grant_verifier(grant_verifier()),
    ));
    let handles: Vec<_> = (0..8)
        .map(|i| {
            let bridge = bridge.clone();
            std::thread::spawn(move || {
                let sid = format!("s{i}");
                let key = ClientKey::new("ck", &[i as u8; 32]);
                let id = SessionIdentity {
                    session_id: sid.clone(),
                    principal_id: "p".into(),
                    authority_scope: vec!["a".into()],
                    task_lineage: vec![],
                };
                let mut b = bridge.lock().unwrap();
                common::attach_ok(&mut b, &id, &key).unwrap();
                b.escalate_to_human(&sid, "x").unwrap();
                b.client_disconnect(&sid, None, "x").unwrap();
                let genesis = b.events(&sid)[0].hash();
                let nonce = b.challenge(&sid, "ck").unwrap().nonce;
                let req = key.request(&sid, &nonce, 0, &genesis);
                b.begin_resume(&sid, &req, false).unwrap();
                b.complete_resume(&sid).unwrap();
                assert_eq!(b.cell_of(&sid).names(), vec!["Att", "Pend"]);
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(storage.sessions().unwrap().len(), 8);
}

#[test]
fn default_config_satisfies_the_timer_bounds() {
    let c = Config::default();
    assert!(c.t_call <= c.t_human && c.t_detach <= c.t_total);
    assert_eq!((c.t_detach, c.t_human, c.t_call, c.t_total), (1800.0, 1800.0, 1800.0, 7200.0));
    let p = Config::persistent();
    assert_eq!((p.t_detach, p.t_human, p.t_call), (604_800.0, 604_800.0, 604_800.0));
    assert_eq!(p.t_total, 28.0 * 86_400.0);
    // T_human may exceed T_detach; T_call may not exceed T_human; T_total >= T_detach.
    assert!(Config::new(1800.0, Some(3600.0), None, None, 900.0, 60.0, 64).is_ok());
    assert!(Config::new(1800.0, Some(600.0), Some(900.0), None, 900.0, 60.0, 64).is_err());
    assert!(Config::new(1800.0, None, None, Some(900.0), 900.0, 60.0, 64).is_err());
    // A NaN or negative timer is refused, as in the Python bridge.
    assert!(Config::new(1800.0, None, None, None, 900.0, f64::NAN, 64).is_err());
    assert!(Config::new(1800.0, None, None, None, 900.0, -5.0, 64).is_err());
    assert!(Config::new(1800.0, None, None, None, f64::NAN, 60.0, 64).is_err());
    assert!(Config::new(f64::NAN, None, None, None, 900.0, 60.0, 64).is_err());
    assert!(Config::new(-1.0, None, None, None, 900.0, 60.0, 64).is_err());
    // an infinite timer never fires and has no canonical form in a log
    assert!(Config::new(1800.0, None, None, None, 900.0, f64::INFINITY, 64).is_err());
    assert!(Config::new(f64::INFINITY, None, None, Some(f64::INFINITY), 900.0, 60.0, 64).is_err());
}

#[test]
fn a_call_whose_content_has_no_canonical_form_is_refused_not_a_panic() {
    let (mut b, _, _, _, _) = two_key_bridge();
    b.escalate_to_human("s", "x").unwrap();
    let before = b.events("s").len();
    for content in [json!({"n": 9_007_199_254_740_993u64}), json!({"n": u64::MAX})] {
        let r = b.submit_tool_call("s", "t", Some("k"), None, Some(&content));
        assert_eq!(r.unwrap_err().1, "bad_canonical");
    }
    assert_eq!(b.events("s").len(), before, "a refused call commits nothing");
}

#[test]
fn failed_append_changes_nothing() {
    let clock = FakeClock::new(0.0);
    let storage = MemStorage::new();
    let key = ClientKey::new("ck", &[7u8; 32]);
    let mut b = Bridge::new(storage.clone(), clock, Arc::new(SchemeVerifier), Config::default())
        .unwrap()
        .with_grant_verifier(grant_verifier());
    let id = SessionIdentity {
        session_id: "s".into(),
        principal_id: "p".into(),
        authority_scope: vec!["a".into()],
        task_lineage: vec![],
    };
    common::attach_ok(&mut b, &id, &key).unwrap();
    let cell = b.cell_of("s");
    storage.fail_next();
    assert!(b.client_disconnect("s", None, "x").is_err());
    assert_eq!(b.cell_of("s"), cell);
    assert_eq!(b.events("s").len(), 1);
}

#[test]
fn registry_holds_public_keys_only() {
    let seed = [9u8; 32];
    let key = ClientKey::new("ck", &seed);
    let storage = MemStorage::new();
    let mut b = Bridge::new(storage.clone(), FakeClock::new(0.0), Arc::new(SchemeVerifier), Config::default())
        .unwrap()
        .with_grant_verifier(grant_verifier());
    let id = SessionIdentity {
        session_id: "s".into(),
        principal_id: "p".into(),
        authority_scope: vec!["a".into()],
        task_lineage: vec![],
    };
    common::attach_ok(&mut b, &id, &key).unwrap();
    let record = storage.key_record("s", "ck").unwrap().unwrap();
    assert_eq!(record.scheme, "ed25519");
    let stored = record.material;
    assert_eq!(stored, key.public_key());
    assert_ne!(stored, seed.to_vec());
}

#[test]
fn attach_is_refused_without_a_valid_grant() {
    let key = ClientKey::new("ck", &[7u8; 32]);
    let id = SessionIdentity {
        session_id: "s".into(),
        principal_id: "p".into(),
        authority_scope: vec!["a".into()],
        task_lineage: vec![],
    };
    let good = operator().grant(&id, &key.public(), DEFAULT_BRIDGE_ID);
    let proof = key.prove_attach(&id, DEFAULT_BRIDGE_ID);
    let forged = OperatorKey::new(&[9u8; 32]).grant(&id, &key.public(), DEFAULT_BRIDGE_ID);
    let wider = SessionIdentity { authority_scope: vec!["a".into(), "b".into()], ..id.clone() };
    let storage = MemStorage::new();
    // a bridge with no grant authority refuses every attach
    let mut bare = Bridge::new(storage.clone(), FakeClock::new(0.0), Arc::new(SchemeVerifier), Config::default()).unwrap();
    assert!(bare.attach(&id, &key.public(), Some(good.as_str()), Some(proof.as_str())).is_err());
    let mut b = Bridge::new(storage.clone(), FakeClock::new(0.0), Arc::new(SchemeVerifier), Config::default())
        .unwrap()
        .with_grant_verifier(grant_verifier());
    for grant in [None, Some(""), Some("zz"), Some(forged.as_str())] {
        assert!(b.attach(&id, &key.public(), grant, Some(proof.as_str())).is_err());
    }
    // a grant is bound to the claimed scope and to the client key
    let other = ClientKey::new("other", &[8u8; 32]);
    assert!(b.attach(&wider, &key.public(), Some(good.as_str()), Some(key.prove_attach(&wider, DEFAULT_BRIDGE_ID).as_str())).is_err());
    assert!(b.attach(&id, &other.public(), Some(good.as_str()), Some(other.prove_attach(&id, DEFAULT_BRIDGE_ID).as_str())).is_err());
    assert!(storage.read_log("s").unwrap().is_empty());
    b.attach(&id, &key.public(), Some(good.as_str()), Some(proof.as_str())).unwrap();
}

fn identity(sid: &str) -> SessionIdentity {
    SessionIdentity {
        session_id: sid.into(),
        principal_id: "p".into(),
        authority_scope: vec!["a".into()],
        task_lineage: vec![],
    }
}

fn two_key_bridge() -> (Bridge, Arc<MemStorage>, Arc<FakeClock>, ClientKey, ClientKey) {
    let storage = MemStorage::new();
    let clock = FakeClock::new(1000.0);
    let mut b = Bridge::new(storage.clone(), clock.clone(), Arc::new(SchemeVerifier), Config::default())
        .unwrap()
        .with_grant_verifier(grant_verifier());
    let (k1, k2) = (ClientKey::new("ck-1", &[1u8; 32]), ClientKey::new("ck-2", &[2u8; 32]));
    let id = identity("s");
    common::attach_ok(&mut b, &id, &k1).unwrap();
    let nonce = b.challenge("s", "ck-1").unwrap().nonce;
    b.add_client_key("s", "ck-1", "ck-2", k2.scheme(), &k2.public_key(), &nonce, &k1.sign_add_client("s", &k2.public(), &nonce)).unwrap();
    (b, storage, clock, k1, k2)
}

fn resume(b: &mut Bridge, key: &ClientKey, seq: i64, nonce: Option<String>) -> Result<Vec<Event>> {
    let nonce = match nonce {
        Some(n) => n,
        None => b.challenge("s", &key.key_id)?.nonce,
    };
    let hash = b.events("s")[seq as usize].hash();
    b.begin_resume("s", &key.request("s", &nonce, seq, &hash), false)
}

fn last_reason(b: &Bridge) -> String {
    b.events("s").last().unwrap().payload["reason"].as_str().unwrap_or("").to_string()
}

#[test]
fn attach_takes_the_public_key_only() {
    // The type of the argument is the guarantee: ClientPublicKey has no
    // signing material, and ClientKey (which has) is not accepted.
    let key = ClientKey::new("ck", &[5u8; 32]);
    let public = key.public();
    assert_eq!(public, ClientPublicKey { key_id: "ck".into(), scheme: "ed25519".into(), material: key.public_key() });
    let storage = MemStorage::new();
    let mut b = Bridge::new(storage.clone(), FakeClock::new(0.0), Arc::new(SchemeVerifier), Config::default())
        .unwrap()
        .with_grant_verifier(grant_verifier());
    let id = identity("s");
    common::attach_ok(&mut b, &id, &key).unwrap();
    let seed_hex = hex::encode([5u8; 32]);
    for e in storage.read_log("s").unwrap() {
        assert!(!String::from_utf8_lossy(&e.canonical()).contains(&seed_hex));
    }
    let record = storage.key_record("s", "ck").unwrap().unwrap();
    assert_eq!(record.material, key.public_key());
    assert_ne!(record.material, vec![5u8; 32]);
}

#[test]
fn soft_revocation_keeps_the_connected_client() {
    let (mut b, _, _, _, _) = two_key_bridge();
    assert_eq!(b.revoke_key("s", "ck-1", "rotation", &sig_revoke(&b, "s", "ck-1", "rotation"), None).unwrap(), Revocation::Revoked);
    assert_eq!(b.client_set("s"), vec!["ck-1"]);
    assert_eq!(b.cell_of("s").names(), vec!["Att", "None"]);
    assert_eq!(b.revoked_keys("s"), vec!["ck-1"]);
    assert!(!b.is_key_exhausted("s"));
    assert_eq!(b.events("s").last().unwrap().kind, Kind::KEY_REVOKED);
}

#[test]
fn hard_revocation_detaches_only_when_it_removes_the_last_connected_client() {
    let (mut b, _, _, k1, k2) = two_key_bridge();
    resume_second_client(&mut b, &k1, &k2);
    b.revoke_key("s", "ck-1", "compromise", &sig_revoke(&b, "s", "ck-1", "compromise"), None).unwrap();
    assert_eq!(b.client_set("s"), vec!["ck-2"]);
    assert_eq!(b.cell_of("s").names(), vec!["Att", "None"]);
    b.revoke_key("s", "ck-2", "compromise", &sig_revoke(&b, "s", "ck-2", "compromise"), None).unwrap();
    assert_eq!(b.cell_of("s").names(), vec!["Det", "None"]);
    let kinds: Vec<_> = b.events("s").iter().rev().take(3).map(|e| e.kind).collect();
    assert_eq!(kinds, vec![Kind::RESUME_PREPARED, Kind::DETACHMENT, Kind::KEY_REVOKED]);
    assert!(b.is_key_exhausted("s"));
}

fn resume_second_client(b: &mut Bridge, _k1: &ClientKey, k2: &ClientKey) {
    let tip = b.events("s").len() as i64 - 1;
    let nonce = b.challenge("s", &k2.key_id).unwrap().nonce;
    let hash = b.events("s")[tip as usize].hash();
    b.join("s", &k2.request_for(ResumeOp::Join, "s", &nonce, tip, &hash), false).unwrap();
    assert_eq!(b.client_set("s"), vec!["ck-1", "ck-2"]);
}

#[test]
fn two_phase_rotation_leaves_only_the_new_key_able_to_re_attach() {
    let (mut b, _, _, k1, k2) = two_key_bridge();
    b.revoke_key("s", "ck-1", "rotation", &sig_revoke(&b, "s", "ck-1", "rotation"), None).unwrap();
    b.client_disconnect("s", None, "x").unwrap();
    assert!(resume(&mut b, &k1, 1, None).is_err());
    assert_eq!(last_reason(&b), "revoked_key");
    assert_eq!(b.cell_of("s").names(), vec!["Det", "None"]);
    resume(&mut b, &k2, 1, None).unwrap();
    b.complete_resume("s").unwrap();
    assert_eq!(b.client_set("s"), vec!["ck-2"]);
}

#[test]
fn hard_revocation_abandons_the_re_attach_it_is_verifying() {
    // I11-REVOKE (IRev): a key revoked for compromise while its re-attach is
    // in Res is not the attached client afterwards.
    let (mut b, _, _, k1, _) = two_key_bridge();
    b.client_disconnect("s", None, "x").unwrap();
    resume(&mut b, &k1, 1, None).unwrap();
    assert_eq!(b.cell_of("s").names(), vec!["Res", "None"]);
    let n = b.events("s").len();
    b.revoke_key("s", "ck-1", "compromise", &sig_revoke(&b, "s", "ck-1", "compromise"), None).unwrap();
    let kinds: Vec<_> = b.events("s")[n..].iter().map(|e| e.kind).collect();
    assert_eq!(kinds, vec![Kind::KEY_REVOKED, Kind::DETACHMENT, Kind::RESUME_PREPARED]);
    assert_eq!(b.cell_of("s").names(), vec!["Det", "None"]);
    assert!(b.complete_resume("s").is_err());
    assert!(b.client_set("s").is_empty());
}

#[test]
fn soft_revocation_abandons_the_re_attach_it_is_verifying() {
    let (mut b, _, _, k1, _) = two_key_bridge();
    b.client_disconnect("s", None, "x").unwrap();
    resume(&mut b, &k1, 1, None).unwrap();
    b.revoke_key("s", "ck-1", "rotation", &sig_revoke(&b, "s", "ck-1", "rotation"), None).unwrap();
    // the verification is abandoned, as for a hard revocation
    assert_eq!(b.cell_of("s").names(), vec!["Det", "None"]);
}

#[test]
fn a_key_revoked_after_its_challenge_is_rejected_and_the_nonce_is_spent() {
    let (mut b, _, _, k1, k2) = two_key_bridge();
    b.client_disconnect("s", None, "x").unwrap();
    let nonce = b.challenge("s", "ck-1").unwrap().nonce;
    b.revoke_key("s", "ck-1", "rotation", &sig_revoke(&b, "s", "ck-1", "rotation"), None).unwrap();
    assert!(resume(&mut b, &k1, 1, Some(nonce.clone())).is_err());
    assert_eq!(last_reason(&b), "revoked_key");
    // the nonce was issued for ck-1: it is not ck-2's, and it stays spent
    assert!(resume(&mut b, &k2, 1, Some(nonce)).is_err());
    assert_eq!(last_reason(&b), "nonce_binding");
    assert_eq!(b.cell_of("s").names(), vec!["Det", "None"]);
    resume(&mut b, &k2, 1, None).unwrap();
}

#[test]
fn the_last_revoked_key_exhausts_the_session_until_the_operator_acts() {
    let (mut b, storage, clock, k1, _) = two_key_bridge();
    b.revoke_key("s", "ck-1", "compromise", &sig_revoke(&b, "s", "ck-1", "compromise"), None).unwrap();
    assert!(!b.is_key_exhausted("s"));
    b.revoke_key("s", "ck-2", "rotation", &sig_revoke(&b, "s", "ck-2", "rotation"), None).unwrap();
    assert!(b.is_key_exhausted("s"));
    // client operations are refused; so is a further revocation
    assert!(b.escalate_to_human("s", "x").is_err());
    // transport loss is not a client operation: nothing left to detach here
    assert!(b.client_disconnect("s", None, "x").is_ok());
    assert!(b.revoke_key("s", "ck-1", "compromise", &sig_revoke(&b, "s", "ck-1", "compromise"), None).is_err());
    assert!(resume(&mut b, &k1, 1, None).is_err());
    // a restart rebuilds the state from the log
    let mut b = Bridge::recover_with(storage.clone(), clock.clone(), Arc::new(SchemeVerifier), Config::default(), Some(grant_verifier())).unwrap();
    assert!(b.is_key_exhausted("s"));
    assert_eq!(b.revoked_keys("s"), vec!["ck-1", "ck-2"]);
    // recovery: a new key; a registered key id, revoked or not, is refused
    let k3 = ClientKey::new_p256("ck-3", &[3u8; 32]);
    assert!(b.operator_add_key("s", &k1.public(), &add_key_sig(&b, &k1.public())).is_err());
    b.operator_add_key("s", &k3.public(), &add_key_sig(&b, &k3.public())).unwrap();
    assert!(!b.is_key_exhausted("s"));
    assert_eq!(b.revoked_keys("s"), vec!["ck-1", "ck-2"]);
    let mut b = Bridge::recover_with(storage, clock, Arc::new(SchemeVerifier), Config::default(), Some(grant_verifier())).unwrap();
    assert!(!b.is_key_exhausted("s"));
    let tip = b.events("s").len() as i64 - 1;
    let nonce = b.challenge("s", "ck-3").unwrap().nonce;
    let hash = b.events("s")[tip as usize].hash();
    b.begin_resume("s", &k3.request("s", &nonce, tip, &hash), false).unwrap();
    b.complete_resume("s").unwrap();
    assert_eq!(b.client_set("s"), vec!["ck-3"]);
}

#[test]
fn a_key_exhausted_session_keeps_its_timers_and_ends_unless_a_key_is_added() {
    let (mut b, _, clock, _, _) = two_key_bridge();
    b.revoke_key("s", "ck-1", "compromise", &sig_revoke(&b, "s", "ck-1", "compromise"), None).unwrap();
    b.revoke_key("s", "ck-2", "compromise", &sig_revoke(&b, "s", "ck-2", "compromise"), None).unwrap();
    assert!(b.is_key_exhausted("s"));
    let t_detach = Config::default().t_detach;
    clock.advance(t_detach - 1.0);
    b.tick(None).unwrap();
    assert_eq!(b.cell_of("s").names(), vec!["Det", "None"]);
    clock.advance(1.0);
    // a client operation on an expired session reports the end, not the exhaustion
    assert!(b.escalate_to_human("s", "x").unwrap_err().to_string().contains("TERMINATED"));
    assert_eq!(b.cell_of("s").names(), vec!["Terminated"]);
    // the operator's key arrives too late, also when it is the first call after the bound
    let (mut b, _, clock, _, _) = two_key_bridge();
    b.revoke_key("s", "ck-1", "compromise", &sig_revoke(&b, "s", "ck-1", "compromise"), None).unwrap();
    b.revoke_key("s", "ck-2", "compromise", &sig_revoke(&b, "s", "ck-2", "compromise"), None).unwrap();
    clock.advance(t_detach);
    let k3 = ClientKey::new("ck-3", &[3u8; 32]);
    assert!(b.operator_add_key("s", &k3.public(), &add_key_sig(&b, &k3.public())).is_err());
    assert_eq!(b.cell_of("s").names(), vec!["Terminated"]);
}

#[test]
fn a_key_exhausted_session_that_is_still_connected_detaches_on_transport_loss() {
    let (mut b, _, clock, _, _) = two_key_bridge();
    b.revoke_key("s", "ck-1", "rotation", &sig_revoke(&b, "s", "ck-1", "rotation"), None).unwrap();
    b.revoke_key("s", "ck-2", "rotation", &sig_revoke(&b, "s", "ck-2", "rotation"), None).unwrap();
    assert!(b.is_key_exhausted("s"));
    clock.advance(Config::default().t_detach * 2.0);
    b.tick(None).unwrap();
    assert_eq!(b.cell_of("s").names(), vec!["Att", "None"]);
    b.client_disconnect("s", None, "x").unwrap();
    assert_eq!(b.cell_of("s").names(), vec!["Det", "None"]);
    clock.advance(Config::default().t_detach);
    b.tick(None).unwrap();
    assert_eq!(b.cell_of("s").names(), vec!["Terminated"]);
}

#[test]
fn operator_termination_ends_only_a_key_exhausted_session() {
    let (mut b, _, _, _, _) = two_key_bridge();
    assert!(b.operator_terminate("s", "all_keys_revoked", &sig_terminate(&b, "s", "all_keys_revoked")).is_err());
    assert!(b.operator_add_key("s", &ClientKey::new("ck-9", &[9u8; 32]).public(), &add_key_sig(&b, &ClientKey::new("ck-9", &[9u8; 32]).public())).is_err());
    b.revoke_key("s", "ck-1", "compromise", &sig_revoke(&b, "s", "ck-1", "compromise"), None).unwrap();
    b.revoke_key("s", "ck-2", "compromise", &sig_revoke(&b, "s", "ck-2", "compromise"), None).unwrap();
    b.operator_terminate("s", "all_keys_revoked", &sig_terminate(&b, "s", "all_keys_revoked")).unwrap();
    assert_eq!(b.cell_of("s").names(), vec!["Terminated"]);
    let kinds: Vec<_> = b.events("s").iter().rev().take(2).map(|e| e.kind).collect();
    assert_eq!(kinds, vec![Kind::TERMINATION, Kind::OPERATOR_TERMINATION]);
    assert!(b.operator_add_key("s", &ClientKey::new("ck-9", &[9u8; 32]).public(), &add_key_sig(&b, &ClientKey::new("ck-9", &[9u8; 32]).public())).is_err());
}

#[test]
fn a_revocation_request_without_the_operator_signature_revokes_nothing() {
    let (mut b, _, _, _, _) = two_key_bridge();
    assert_eq!(b.revoke_key("s", "ck-1", "rotation", "", Some("ck-1")).unwrap(), Revocation::Requested);
    assert_eq!(b.events("s").last().unwrap().kind, Kind::KEY_REVOCATION_REQUESTED);
    assert!(b.revoked_keys("s").is_empty());
    assert!(b.revoke_key("s", "ck-9", "rotation", &sig_revoke(&b, "s", "ck-9", "rotation"), None).is_err());
}

#[test]
fn revoked_keys_survive_a_restart() {
    let (mut b, storage, clock, k1, k2) = two_key_bridge();
    b.revoke_key("s", "ck-1", "rotation", &sig_revoke(&b, "s", "ck-1", "rotation"), None).unwrap();
    let mut b = Bridge::recover_with(storage, clock, Arc::new(SchemeVerifier), Config::default(), Some(grant_verifier())).unwrap();
    assert_eq!(b.revoked_keys("s"), vec!["ck-1"]);
    let tip = b.events("s").len() as i64 - 1;
    assert!(resume(&mut b, &k1, tip, None).is_err());
    assert_eq!(last_reason(&b), "revoked_key");
    resume(&mut b, &k2, tip, None).unwrap();
}

#[test]
fn operator_events_need_a_valid_operator_signature() {
    let (mut b, _, _, _, _) = two_key_bridge();
    let forged = OperatorKey::new(&[9u8; 32]);
    let (seq, head) = b.head_of("s");
    let bid = b.bridge_id().to_string();
    let before = b.events("s").len();
    // revocation: missing, malformed, wrong key, other reason, other key, other operation
    for sig in [
        String::new(),
        "zz".to_string(),
        "00".repeat(64),
        forged.revoke(&bid, "s", "ck-1", "compromise", seq, &head),
        operator().revoke(&bid, "s", "ck-1", "rotation", seq, &head),
        operator().revoke(&bid, "s", "ck-2", "compromise", seq, &head),
        operator().terminate(&bid, "s", "compromise", seq, &head),
    ] {
        let e = b.revoke_key("s", "ck-1", "compromise", &sig, None).unwrap_err();
        assert!(e.0.starts_with("operator_signature_invalid"), "{}", e.0);
    }
    assert_eq!(b.events("s").len(), before);
    assert!(b.revoked_keys("s").is_empty());
    // a request without a signature is still only a request
    assert_eq!(b.revoke_key("s", "ck-1", "rotation", "", Some("ck-1")).unwrap(), Revocation::Requested);
    b.revoke_key("s", "ck-1", "compromise", &sig_revoke(&b, "s", "ck-1", "compromise"), None).unwrap();
    b.revoke_key("s", "ck-2", "compromise", &sig_revoke(&b, "s", "ck-2", "compromise"), None).unwrap();
    assert!(b.is_key_exhausted("s"));

    // key addition: bound to the key id, scheme and public key
    let k3 = ClientKey::new_p256("ck-3", &[3u8; 32]);
    let other = ClientKey::new_p256("ck-4", &[4u8; 32]);
    let good = add_key_sig(&b, &k3.public());
    let (seq, head) = b.head_of("s");
    for sig in [
        String::new(),
        "00".repeat(64),
        forged.add_key(&bid, "s", "ck-3", &k3.public().scheme, &hex::encode(&k3.public().material), seq, &head),
        add_key_sig(&b, &other.public()),
        operator().terminate(&bid, "s", "all_keys_revoked", seq, &head),
    ] {
        let e = b.operator_add_key("s", &k3.public(), &sig).unwrap_err();
        assert!(e.0.starts_with("operator_signature_invalid"), "{}", e.0);
    }
    assert!(b.is_key_exhausted("s"));

    // termination
    for sig in [
        String::new(),
        "00".repeat(64),
        forged.terminate(&bid, "s", "all_keys_revoked", seq, &head),
        operator().terminate(&bid, "s", "other", seq, &head),
        good.clone(),
    ] {
        let e = b.operator_terminate("s", "all_keys_revoked", &sig).unwrap_err();
        assert!(e.0.starts_with("operator_signature_invalid"), "{}", e.0);
    }
    assert_eq!(b.cell_of("s").names(), vec!["Det", "None"]);
    b.operator_add_key("s", &k3.public(), &good).unwrap();
    assert!(!b.is_key_exhausted("s"));
}

#[test]
fn a_verifier_without_operator_support_refuses_operator_events() {
    struct GrantOnly;
    impl GrantVerifier for GrantOnly {
        fn verify(&self, _: &str, _: &SessionIdentity, _: &ClientPublicKey, _: Option<&str>) -> bool {
            true
        }
    }
    let k1 = ClientKey::new("ck-1", &[1u8; 32]);
    let id = identity("s");
    let storage = MemStorage::new();
    let mut c = Bridge::new(storage.clone(), FakeClock::new(1000.0), Arc::new(SchemeVerifier), Config::default())
        .unwrap()
        .with_grant_verifier(Arc::new(GrantOnly));
    c.attach(&id, &k1.public(), Some("any"), Some(k1.prove_attach(&id, DEFAULT_BRIDGE_ID).as_str())).unwrap();
    let e = c.revoke_key("s", "ck-1", "rotation", &sig_revoke(&c, "s", "ck-1", "rotation"), None).unwrap_err();
    assert!(e.0.starts_with("operator_signature_invalid"));
    // a bridge with no verifier at all refuses too: it is the same session,
    // recovered from the same log, so the refusal is not the unknown session's
    let mut d = Bridge::recover_with(storage, FakeClock::new(1000.0), Arc::new(SchemeVerifier), Config::default(), None).unwrap();
    assert_eq!(d.registered_keys("s"), vec!["ck-1".to_string()]);
    let e = d.revoke_key("s", "ck-1", "rotation", &sig_revoke(&d, "s", "ck-1", "rotation"), None).unwrap_err();
    assert_eq!(e.1, "operator_signature_invalid");
    assert!(d.revoked_keys("s").is_empty());
}

#[test]
fn a_reattach_proof_is_not_a_join_proof() {
    let (mut b, _, _, _k1, k2) = two_key_bridge();
    let tip = b.events("s").len() as i64 - 1;
    let hash = b.events("s")[tip as usize].hash();
    let nonce = b.challenge("s", "ck-2").unwrap().nonce;
    assert!(b.join("s", &k2.request_for(ResumeOp::Reattach, "s", &nonce, tip, &hash), false).is_err());
    assert_eq!(last_reason(&b), "bad_signature");
    assert_eq!(b.cell_of("s").names(), vec!["Att", "None"]);
    let nonce = b.challenge("s", "ck-2").unwrap().nonce;
    b.join("s", &k2.request_for(ResumeOp::Join, "s", &nonce, tip, &hash), false).unwrap();
    // and the other way round, on a detached session
    b.client_disconnect("s", None, "x").unwrap();
    let nonce = b.challenge("s", "ck-2").unwrap().nonce;
    let tip = b.events("s").len() as i64 - 1;
    let hash = b.events("s")[tip as usize].hash();
    let k1 = ClientKey::new("ck-1", &[1u8; 32]);
    assert!(b.begin_resume("s", &k1.request_for(ResumeOp::Join, "s", &nonce, tip, &hash), false).is_err());
    assert_eq!(last_reason(&b), "bad_signature");
}

#[test]
fn a_resume_proof_names_the_key_that_signs_it() {
    let (mut b, _, _, k1, _k2) = two_key_bridge();
    b.client_disconnect("s", None, "x").unwrap();
    let tip = b.events("s").len() as i64 - 1;
    let hash = b.events("s")[tip as usize].hash();
    // a proof ck-1 made for itself, presented under ck-2 (the byte-level
    // separation of the key id is pinned in bytes_kat.rs)
    let nonce = b.challenge("s", "ck-1").unwrap().nonce;
    let mut req = k1.request("s", &nonce, tip, &hash);
    req.key_id = "ck-2".into();
    assert!(b.begin_resume("s", &req, false).is_err());
    assert_eq!(last_reason(&b), "bad_signature");
    // the untagged tuple of an earlier format is refused
    let nonce = b.challenge("s", "ck-1").unwrap().nonce;
    let mut req = k1.request("s", &nonce, tip, &hash);
    req.signature = k1.sign_bytes(&wire::canonical_bytes(&serde_json::json!(["s", nonce, tip, hash])));
    assert!(b.begin_resume("s", &req, false).is_err());
    assert_eq!(last_reason(&b), "bad_signature");
}

#[test]
fn a_key_id_is_scoped_to_its_session() {
    // B1: a second, validly granted session reusing the key id replaces
    // nothing and cannot re-attach to the first.
    let (mut b, storage, _, k1, _) = two_key_bridge();
    let mallory = ClientKey::new("ck-1", &[66u8; 32]);
    common::attach_ok(&mut b, &identity("s2"), &mallory).unwrap();
    assert_eq!(storage.key_record("s", "ck-1").unwrap().unwrap().material, k1.public_key());
    assert_eq!(storage.key_record("s2", "ck-1").unwrap().unwrap().material, mallory.public_key());
    b.client_disconnect("s", None, "x").unwrap();
    let nonce = b.challenge("s", "ck-1").unwrap().nonce;
    let hash = b.events("s")[0].hash();
    assert!(b.begin_resume("s", &mallory.request("s", &nonce, 0, &hash), false).is_err());
    assert_eq!(last_reason(&b), "bad_signature");
    let nonce = b.challenge("s", "ck-1").unwrap().nonce;
    b.begin_resume("s", &k1.request("s", &nonce, 0, &hash), false).unwrap(); // the owner is not locked out
}

#[test]
fn a_key_id_registered_in_a_session_is_not_registered_again() {
    let (mut b, storage, _, k1, _) = two_key_bridge();
    let stray = ClientKey::new("ck-1", &[67u8; 32]);
    assert!(storage.register_key("s", "ck-1", stray.scheme(), &stray.public_key()).is_err());
    let nonce = b.challenge("s", "ck-1").unwrap().nonce;
    let err = b
        .add_client_key("s", "ck-1", "ck-1", stray.scheme(), &stray.public_key(), &nonce, &k1.sign_add_client("s", &stray.public(), &nonce))
        .unwrap_err();
    assert!(err.0.contains("rejected: key_already_registered "), "{}", err.0);
    assert_eq!(storage.key_ids("s").unwrap().len(), 2);
}

#[test]
fn a_failed_commit_leaves_no_registry_entry() {
    let storage = MemStorage::new();
    let mut b = Bridge::new(storage.clone(), FakeClock::new(0.0), Arc::new(SchemeVerifier), Config::default())
        .unwrap()
        .with_grant_verifier(grant_verifier());
    let key = ClientKey::new("ck", &[3u8; 32]);
    storage.fail_next.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(common::attach_ok(&mut b, &identity("s"), &key).is_err());
    assert!(storage.key_ids("s").unwrap().is_empty());
    common::attach_ok(&mut b, &identity("s"), &ClientKey::new("ck", &[4u8; 32])).unwrap();
}

#[test]
fn key_material_is_in_the_log() {
    let (b, _, _, k1, k2) = two_key_bridge();
    let events = b.events("s");
    assert_eq!(events[0].payload["scheme"], k1.scheme());
    assert_eq!(events[0].payload["public_key"], hex::encode(k1.public_key()));
    assert_eq!(events[1].payload["scheme"], k2.scheme());
    assert_eq!(events[1].payload["public_key"], hex::encode(k2.public_key()));
}

#[test]
fn recovery_repairs_the_registry_from_the_log() {
    let recover = |storage: &Arc<MemStorage>| {
        Bridge::recover_with(storage.clone(), FakeClock::new(2000.0), Arc::new(SchemeVerifier), Config::default(), Some(grant_verifier())).unwrap()
    };
    let repaired = |b: &Bridge| -> Vec<String> {
        let ev = b.events("s").into_iter().rev().find(|e| e.kind == Kind::BRIDGE_RECOVERED).unwrap();
        ev.payload["registry_repaired"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect()
    };
    // a matching registry needs no repair
    let (_, storage, _, _, _) = two_key_bridge();
    let b = recover(&storage);
    assert!(!b.is_quarantined("s") && repaired(&b).is_empty());
    // an entry with other material is replaced by the log's, and the key verifies again
    let (_, storage, _, _, k2) = two_key_bridge();
    storage.tamper_key("s", "ck-2", &ClientKey::new("ck-2", &[99u8; 32]).public_key());
    let mut b = recover(&storage);
    assert!(!b.is_quarantined("s"));
    assert_eq!(repaired(&b), vec!["ck-2".to_string()]);
    assert_eq!(storage.key_record("s", "ck-2").unwrap().unwrap().material, k2.public_key());
    resume(&mut b, &k2, 0, None).unwrap();
    // an entry no event records (a crash between the registry write and the
    // event commit) is dropped
    let (_, storage, _, _, _) = two_key_bridge();
    let stray = ClientKey::new("ck-9", &[98u8; 32]);
    storage.register_key("s", "ck-9", stray.scheme(), &stray.public_key()).unwrap();
    let b = recover(&storage);
    assert!(!b.is_quarantined("s"));
    assert_eq!(repaired(&b), vec!["ck-9".to_string()]);
    assert_eq!(storage.key_ids("s").unwrap().len(), 2);
    // a missing entry is written back
    let (_, storage, _, _, _) = two_key_bridge();
    storage.forget_keys();
    let b = recover(&storage);
    assert!(!b.is_quarantined("s"));
    assert_eq!(repaired(&b), vec!["ck-1".to_string(), "ck-2".to_string()]);
    assert_eq!(storage.key_ids("s").unwrap().len(), 2);
    // a broken chain still quarantines, and the registry is left alone
    let (_, storage, _, _, _) = two_key_bridge();
    storage.tamper("s", 0, |e| e.prev_hash = "00".repeat(32));
    storage.forget_keys();
    let b = recover(&storage);
    assert!(b.is_quarantined("s"));
    assert!(storage.key_ids("s").unwrap().is_empty());
}

#[test]
fn a_reattach_on_an_attached_session_is_refused_and_join_is_the_way_in() {
    let (mut b, _, _, _, k2) = two_key_bridge();
    // the other key's re-attach is authentic but the session is attached
    let e = resume(&mut b, &k2, 0, None).unwrap_err();
    assert!(e.0.contains("already_attached"), "{}", e.0);
    assert_eq!(last_reason(&b), "already_attached");
    assert_eq!(b.events("s").last().unwrap().kind, Kind::RESUME_REJECTED);
    assert_eq!(b.cell_of("s").names(), vec!["Att", "None"]);
    assert_eq!(b.client_set("s"), vec!["ck-1".to_string()]);
    // an unauthentic one still gets the unauthenticated reason
    let nonce = b.challenge("s", "ck-2").unwrap().nonce;
    let hash = b.events("s")[0].hash();
    let mut forged = k2.request("s", &nonce, 0, &hash);
    forged.signature = "00".repeat(64);
    assert!(b.begin_resume("s", &forged, false).unwrap_err().0.contains("bad_signature"));
    // join is the way in
    let nonce = b.challenge("s", "ck-2").unwrap().nonce;
    let req = k2.request_for(ResumeOp::Join, "s", &nonce, 0, &hash);
    b.join("s", &req, false).unwrap();
    assert_eq!(b.client_set("s"), vec!["ck-1".to_string(), "ck-2".to_string()]);
}

#[test]
fn operator_signatures_are_bound_to_the_bridge_and_the_log_position() {
    let (mut b, _, _, _, _) = two_key_bridge();
    let (seq, head) = b.head_of("s");
    assert_eq!(seq, 1);
    let at_head = operator().revoke(b.bridge_id(), "s", "ck-2", "rotation", seq, &head);
    let elsewhere = operator().revoke("bridge-elsewhere", "s", "ck-2", "rotation", seq, &head);
    let first = b.events("s")[0].hash();
    let stale = operator().revoke(b.bridge_id(), "s", "ck-2", "rotation", 0, &first);
    let wrong_hash = operator().revoke(b.bridge_id(), "s", "ck-2", "rotation", seq, &first);
    for sig in [&elsewhere, &stale, &wrong_hash] {
        let e = b.revoke_key("s", "ck-2", "rotation", sig, None).unwrap_err();
        assert!(e.0.starts_with("operator_signature_invalid"), "{}", e.0);
    }
    assert!(b.revoked_keys("s").is_empty());
    // a request is recorded, so the head moves: the signature made at the old
    // head no longer verifies for anything committed after it
    b.revoke_key("s", "ck-2", "rotation", "", Some("ck-2")).unwrap();
    let e = b.revoke_key("s", "ck-2", "rotation", &at_head, None).unwrap_err();
    assert!(e.0.starts_with("operator_signature_invalid"), "{}", e.0);
    b.revoke_key("s", "ck-2", "rotation", &sig_revoke(&b, "s", "ck-2", "rotation"), None).unwrap();
    assert_eq!(b.revoked_keys("s"), vec!["ck-2".to_string()]);
}

#[test]
fn attach_needs_a_proof_of_possession() {
    let key = ClientKey::new("ck", &[7u8; 32]);
    let id = identity("s");
    let grant = operator().grant(&id, &key.public(), DEFAULT_BRIDGE_ID);
    let storage = MemStorage::new();
    let mut b = Bridge::new(storage.clone(), FakeClock::new(0.0), Arc::new(SchemeVerifier), Config::default())
        .unwrap()
        .with_grant_verifier(grant_verifier());
    let thief = ClientKey::new("ck", &[8u8; 32]);
    let grant_bytes = grant_message(DEFAULT_BRIDGE_ID, &id, &key.public());
    for proof in [
        None,
        Some(String::new()),
        Some("zz".to_string()),
        Some(thief.prove_attach(&id, DEFAULT_BRIDGE_ID)),
        Some(key.sign_bytes(&grant_bytes)),
        Some(key.prove_attach(&id, "bridge-elsewhere")),
    ] {
        let e = b.attach(&id, &key.public(), Some(&grant), proof.as_deref()).unwrap_err();
        assert!(e.0.starts_with("possession_invalid"), "{}", e.0);
    }
    assert!(storage.read_log("s").unwrap().is_empty() && storage.key_ids("s").unwrap().is_empty());
    assert_ne!(attach_message(DEFAULT_BRIDGE_ID, &id, &key.public()), grant_bytes);
}

#[test]
fn a_grant_binds_the_public_key_and_the_bridge() {
    let key = ClientKey::new("ck", &[7u8; 32]);
    let id = identity("s");
    let seen = operator().grant(&id, &key.public(), DEFAULT_BRIDGE_ID);
    let storage = MemStorage::new();
    let mut b = Bridge::new(storage.clone(), FakeClock::new(0.0), Arc::new(SchemeVerifier), Config::default())
        .unwrap()
        .with_grant_verifier(grant_verifier());
    // a front-runner with the same key id and its own public key
    let front = ClientKey::new("ck", &[9u8; 32]);
    let e = b.attach(&id, &front.public(), Some(&seen), Some(&front.prove_attach(&id, DEFAULT_BRIDGE_ID))).unwrap_err();
    assert!(e.0.starts_with("grant_invalid"));
    // a grant made for another bridge
    let elsewhere = operator().grant(&id, &key.public(), "bridge-elsewhere");
    let e = b.attach(&id, &key.public(), Some(&elsewhere), Some(&key.prove_attach(&id, DEFAULT_BRIDGE_ID))).unwrap_err();
    assert!(e.0.starts_with("grant_invalid"));
    assert!(storage.read_log("s").unwrap().is_empty());
    // valid at the bridge it names
    let mut other = Bridge::new(MemStorage::new(), FakeClock::new(0.0), Arc::new(SchemeVerifier), Config::default())
        .unwrap()
        .with_grant_verifier(grant_verifier())
        .with_bridge_id("bridge-elsewhere");
    other.attach(&id, &key.public(), Some(&elsewhere), Some(&key.prove_attach(&id, "bridge-elsewhere"))).unwrap();
    b.attach(&id, &key.public(), Some(&seen), Some(&key.prove_attach(&id, DEFAULT_BRIDGE_ID))).unwrap();
}

#[test]
fn challenge_refusal_does_not_reveal_session_state() {
    let refusal = |b: &mut Bridge, sid: &str| b.challenge(sid, "ck-1").unwrap_err().0;
    let (mut b, storage, _, _, _) = two_key_bridge();
    let unknown = refusal(&mut b, "no-such-session");
    assert_eq!(unknown, CHALLENGE_REFUSED);
    assert!(!unknown.contains("no-such-session"));
    // quarantined: a recovery that finds the event chain broken
    storage.tamper("s", 0, |e| e.prev_hash = "00".repeat(32));
    let mut q = Bridge::recover_with(storage.clone(), FakeClock::new(2000.0), Arc::new(SchemeVerifier), Config::default(), Some(grant_verifier())).unwrap();
    assert!(q.is_quarantined("s"));
    assert_eq!(refusal(&mut q, "s"), unknown);
    // terminated
    let (mut b, _, _, _, _) = two_key_bridge();
    b.terminate("s", "operator").unwrap();
    assert_eq!(refusal(&mut b, "s"), unknown);
}

#[test]
fn resume_refusal_does_not_reveal_session_state() {
    let (mut b, storage, _, _, _) = two_key_bridge();
    let req = ResumeRequest { key_id: "ck-1".into(), nonce: "ab".repeat(16), seq: 0, hash: "00".repeat(32), signature: "invalid".into() };
    let refusal = |b: &mut Bridge, sid: &str| b.begin_resume(sid, &req, false).unwrap_err().0;
    let unknown = refusal(&mut b, "no-such-session");
    assert_eq!(unknown, RESUME_REFUSED);
    assert!(!unknown.contains("no-such-session"));
    // quarantined: a recovery that finds the event chain broken
    storage.tamper("s", 0, |e| e.prev_hash = "00".repeat(32));
    let mut q = Bridge::recover_with(storage.clone(), FakeClock::new(2000.0), Arc::new(SchemeVerifier), Config::default(), Some(grant_verifier())).unwrap();
    assert!(q.is_quarantined("s"));
    assert_eq!(refusal(&mut q, "s"), unknown);
    assert_eq!(q.join("s", &req, false).unwrap_err().0, unknown);
    // terminated
    let (mut b, _, _, _, _) = two_key_bridge();
    b.terminate("s", "operator").unwrap();
    assert_eq!(refusal(&mut b, "s"), unknown);
}

#[test]
fn an_approval_covers_tool_and_permission_not_only_content() {
    let (mut b, _, _, _, _) = two_key_bridge();
    let content = serde_json::json!({"cmd": "ls"});
    b.escalate_to_human("s", "human_unavailable").unwrap();
    b.submit_tool_call("s", "shell:wipe", Some("k"), Some("a"), Some(&content)).unwrap();
    let h = b.shown_hash_of("s", "k").unwrap();
    assert_eq!(h, call_hash("shell:wipe", Some("a"), &content));
    assert_ne!(h, content_hash(&content));
    assert_ne!(h, call_hash("shell:ls", Some("a"), &content));
    assert_ne!(h, call_hash("shell:wipe", None, &content));
    b.answer_tool_call("s", "k", &content_hash(&content), true).unwrap();
    b.human_resolve("s").unwrap();
    assert_eq!(last_reason(&b), "answer_mismatch");
    assert!(b.forwarded.is_empty());
}

#[test]
fn the_forwarded_request_is_the_hashed_one() {
    let (mut b, _, _, _, _) = two_key_bridge();
    let content = serde_json::json!({"cmd": "deploy", "args": ["origin", "main"]});
    b.escalate_to_human("s", "human_unavailable").unwrap();
    b.submit_tool_call("s", "shell:deploy", Some("k1"), Some("a"), Some(&content)).unwrap();
    assert_eq!(b.events("s").last().unwrap().payload["content"], content); // retained in the log
    let h = b.shown_hash_of("s", "k1").unwrap();
    b.answer_tool_call("s", "k1", &h, true).unwrap();
    b.human_resolve("s").unwrap();
    let sent = &b.forwarded_calls[&("s".to_string(), "k1".to_string())];
    assert_eq!(sent.tool, "shell:deploy");
    assert_eq!(sent.permission.as_deref(), Some("a"));
    assert_eq!(sent.content, content);
    assert_eq!(call_hash(&sent.tool, sent.permission.as_deref(), &sent.content), h);
}

#[test]
fn a_bare_terminate_does_not_end_a_key_exhausted_session() {
    let (mut b, _, _, _, _) = two_key_bridge();
    b.revoke_key("s", "ck-1", "rotation", &sig_revoke(&b, "s", "ck-1", "rotation"), None).unwrap();
    b.revoke_key("s", "ck-2", "rotation", &sig_revoke(&b, "s", "ck-2", "rotation"), None).unwrap();
    assert!(b.is_key_exhausted("s"));
    let n = b.events("s").len();
    let err = b.terminate("s", "terminated").unwrap_err();
    assert!(err.0.contains("KEY_EXHAUSTED"), "{}", err.0);
    assert_eq!(b.events("s").len(), n);
    assert_ne!(b.cell_of("s").names(), vec!["Terminated"]);
    b.operator_terminate("s", "all_keys_revoked", &sig_terminate(&b, "s", "all_keys_revoked")).unwrap();
    assert_eq!(b.cell_of("s").names(), vec!["Terminated"]);
    b.terminate("s", "terminated").unwrap(); // already over: no error
}

#[test]
fn the_exhausted_refusal_defers_to_the_timers_and_to_quarantine() {
    // an expired key_exhausted session is found ended
    let (mut b, _, clock, _, _) = two_key_bridge();
    b.revoke_key("s", "ck-1", "compromise", &sig_revoke(&b, "s", "ck-1", "compromise"), None).unwrap();
    b.revoke_key("s", "ck-2", "compromise", &sig_revoke(&b, "s", "ck-2", "compromise"), None).unwrap();
    clock.advance(Config::default().t_detach + 1.0);
    b.terminate("s", "terminated").unwrap();
    assert_eq!(b.cell_of("s").names(), vec!["Terminated"]);
    // a quarantined one: the operator's way out stays open
    let (mut b, storage, _, _, _) = two_key_bridge();
    b.revoke_key("s", "ck-1", "compromise", &sig_revoke(&b, "s", "ck-1", "compromise"), None).unwrap();
    b.revoke_key("s", "ck-2", "compromise", &sig_revoke(&b, "s", "ck-2", "compromise"), None).unwrap();
    storage.tamper("s", 1, |e| e.prev_hash = "00".repeat(32));
    let mut q = Bridge::recover_with(storage, FakeClock::new(2000.0), Arc::new(SchemeVerifier), Config::default(), Some(grant_verifier())).unwrap();
    assert!(q.is_quarantined("s") && q.is_key_exhausted("s"));
    q.terminate("s", "operator").unwrap();
    assert_eq!(q.cell_of("s").names(), vec!["Terminated"]);
}

#[test]
fn an_unregistered_key_and_a_bad_signature_are_one_refusal() {
    let (mut b, _, _, k1, _) = two_key_bridge();
    b.client_disconnect("s", None, "client_disconnect").unwrap();
    let hash = b.events("s")[0].hash();
    let mut bad = k1.request("s", &b.challenge("s", "ck-1").unwrap().nonce, 0, &hash);
    bad.signature = "00".repeat(64);
    let stranger = ClientKey::new("ck-9", &[9u8; 32]);
    let unknown = stranger.request("s", &b.challenge("s", "ck-9").unwrap().nonce, 0, &hash);
    let first = b.begin_resume("s", &bad, false).unwrap_err().0;
    let second = b.begin_resume("s", &unknown, false).unwrap_err().0;
    assert_eq!(first, second);
    assert!(first.contains("bad_signature"), "{first}");
    let reasons: Vec<String> = b
        .events("s")
        .iter()
        .filter(|e| e.kind == Kind::RESUME_REJECTED)
        .map(|e| e.payload["reason"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(reasons, vec!["bad_signature", "unknown_key"]); // the log keeps the true reason
}

#[test]
fn a_revoked_key_request_spends_the_nonce_bound_to_it() {
    // I11d with I11-REVOKE: the refused request is authentic, so its nonce is
    // spent. Observable through I11f: a spent record can make room in a full
    // book, a live one cannot.
    let (mut b, _, _, _, k2) = two_key_bridge();
    let held = b.challenge("s", "ck-2").unwrap().nonce;
    b.revoke_key("s", "ck-2", "rotation", &sig_revoke(&b, "s", "ck-2", "rotation"), None).unwrap();
    let mut issued = 1;
    while b.challenge("s", "ck-1").is_ok() {
        issued += 1;
        assert!(issued < 100_000, "the book never fills");
    }
    let hash = b.events("s")[0].hash();
    let e = b.begin_resume("s", &k2.request("s", &held, 0, &hash), false).unwrap_err();
    assert!(e.0.contains("revoked_key"), "{}", e.0);
    assert!(b.challenge("s", "ck-1").is_ok(), "the spent nonce must make room");
}

#[test]
fn a_negative_or_oversized_seq_is_malformed_and_not_logged() {
    let (mut b, _, _, k1, _) = two_key_bridge();
    let before = b.events("s").len();
    let nonce = b.challenge("s", "ck-1").unwrap().nonce;
    let hash = b.events("s")[0].hash();
    for seq in [-1i64, (1i64 << 53) + 1] {
        let mut req = k1.request("s", &nonce, 0, &hash);
        req.seq = seq;
        let e = b.begin_resume("s", &req, false).unwrap_err();
        assert!(e.0.contains("malformed"), "{}", e.0);
        assert_eq!(b.events("s").len(), before);
    }
}
