use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::sync::Arc;

use serde_json::{json, Value};

use crate::types::*;

/// Live (unspent, unexpired) nonces per session (volatile); I11f.
pub const NONCE_RECORDS: usize = 16;
/// The one error text of a refused `challenge` (I11a).
pub const CHALLENGE_REFUSED: &str = "challenge refused";
/// The one error text of a refused re-attach or join request (I11a).
pub const RESUME_REFUSED: &str = "re-attach refused";
/// Unauthenticated rejections logged per session between two authentic
/// requests (volatile); I11g.
pub const UNAUTH_LOG_LIMIT: usize = 16;
/// KEY_REVOCATION_REQUESTED writes per session between two operator-signed
/// revocations (volatile); I11-REVOKE.
pub const REVOCATION_REQUEST_LIMIT: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolOutcome {
    Queued,
    Duplicate,
    Rejected,
    Forwarded,
}

/// Where an authority change came from (I3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Requested through the bridge: enforced.
    Requested,
    /// Announced by the runtime itself: observed, reported, revert requested.
    Observed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityOutcome {
    /// A subset of the current scope: nothing to do.
    NoChange,
    /// An observed widening was reported; the runtime should revert.
    Revert,
}

/// The request the bridge hands to the runtime: the tool, permission and
/// content that were hashed at queue time (I14).
#[derive(Debug, Clone, PartialEq)]
pub struct ForwardedCall {
    pub tool: String,
    pub permission: Option<String>,
    pub content: Value,
}

#[derive(Debug, Clone)]
struct Queued {
    key: String,
    tool: String,
    permission: Option<String>,
    /// The content hashed into `shown_hash`, retained to be forwarded (I14).
    content: Value,
    expires_at: f64,
    shown_hash: String,
    /// (approve, hash the client displayed)
    answer: Option<(bool, String)>,
    /// Queued with no escalation pending (G1 `Queue`): waits for its answer.
    held: bool,
    /// The expiry of the approval of the escalation this call was queued
    /// under, set by the HUMAN_RESOLVED that ends it (I13).
    approved_until: Option<f64>,
}

/// Per-session state. It is derived from the log only (see `apply`).
#[derive(Debug, Clone)]
struct Session {
    principal: String,
    lineage: Vec<String>,
    scope: Vec<String>,
    scope_version: u64,
    keys: BTreeSet<String>,
    /// (scheme, public key hex) of each key, as the log records it.
    key_material: BTreeMap<String, (String, String)>,
    conn: BTreeSet<String>,
    resuming: Option<String>,
    resume_from: i64,
    cell: Cell,
    detach_deadline: Option<f64>,
    human_deadline: Option<f64>,
    /// Start of the current away interval, and the closed intervals so far.
    det_since: Option<f64>,
    det_total: f64,
    /// A failed chain verification froze the session (cell unchanged).
    quarantined: bool,
    record: Option<Event>,
    queue: Vec<Queued>,
    used_keys: HashSet<String>,
    /// Keys forwarded at a drain, and keys whose completion was reported.
    drained: HashSet<String>,
    completed: HashSet<String>,
    /// Drained calls whose delivery the runtime has not acknowledged: key -> tool.
    unacked: BTreeMap<String, ForwardedCall>,
    /// Keys revoked by KEY_REVOKED; they stay in `keys` (I11-REVOKE).
    revoked: BTreeSet<String>,
    /// Every key in `keys` is revoked, and no OPERATOR_ADD_KEY followed.
    key_exhausted: bool,
}

/// What `revoke_key` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revocation {
    /// KEY_REVOKED was committed.
    Revoked,
    /// Only KEY_REVOCATION_REQUESTED was committed (no operator signature).
    Requested,
}

#[derive(Debug, Clone)]
struct NonceRec {
    nonce: String,
    issued: f64,
    used: bool,
    /// The key id the challenge named, and whether that key was registered
    /// and unrevoked when the nonce was issued. Neither changes afterwards:
    /// a nonce issued for a key that was not an active key never verifies.
    key_id: String,
    eligible: bool,
}

pub struct Bridge {
    storage: Arc<dyn Storage>,
    clock: Arc<dyn Clock>,
    verifier: Arc<dyn Verifier>,
    /// The deployment's scope-grant verifier; without one, attach is refused.
    grant_verifier: Option<Arc<dyn GrantVerifier>>,
    /// The identity a grant and an attach proof are bound to.
    bridge_id: String,
    cfg: Config,
    /// Latest committed timestamp (A6).
    floor: f64,
    sessions: BTreeMap<String, Session>,
    /// Volatile: void after a restart.
    nonces: BTreeMap<String, VecDeque<NonceRec>>,
    /// Volatile: unauthenticated rejections logged since the last authentic
    /// request, per session (I11g).
    unauth_logged: BTreeMap<String, usize>,
    revocation_requests: BTreeMap<String, usize>,
    /// Calls handed to the agent runtime: (session, key, call).
    pub forwarded: Vec<(String, String, String)>,
    /// The request forwarded for (session, key), as retained at queue time (I14).
    pub forwarded_calls: BTreeMap<(String, String), ForwardedCall>,
    /// Calls this instance has forwarded: (session, key).
    sent: HashSet<(String, String)>,
    /// Instructions to revert an observed widening: (session, scope to revert to).
    pub revert_requests: Vec<(String, Vec<String>)>,
    /// I-CHECKPOINT: time of the last checkpoint (or first commit) per session.
    last_cp: BTreeMap<String, f64>,
    /// I-CHECKPOINT: log length after the last CHECKPOINT per session.
    cp_len: BTreeMap<String, usize>,
}

type Item = (Kind, Value);

impl Session {
    /// The placeholder for a session whose log cannot be replayed: detached,
    /// quarantined, with no keys, so that every operation refuses it.
    fn frozen() -> Session {
        Session {
            principal: String::new(),
            lineage: vec![],
            scope: vec![],
            scope_version: 0,
            keys: BTreeSet::new(),
            key_material: BTreeMap::new(),
            conn: BTreeSet::new(),
            resuming: None,
            resume_from: 0,
            cell: Cell { att: Attachment::Det, human: Human::None, life: Life::Active },
            detach_deadline: None,
            human_deadline: None,
            det_since: None,
            det_total: 0.0,
            quarantined: true,
            record: None,
            queue: vec![],
            used_keys: HashSet::new(),
            drained: HashSet::new(),
            completed: HashSet::new(),
            unacked: BTreeMap::new(),
            revoked: BTreeSet::new(),
            key_exhausted: false,
        }
    }
}

/// A log can be replayed when it starts with an ATTACHED event that carries
/// the fields the session is built from.
/// The reason a caller sees. A request for an unregistered key and a request
/// whose signature does not verify are one refusal to the caller, so a
/// rejection does not say which key ids a session registers; the log keeps
/// the true reason.
fn public_reason(reason: &'static str) -> &'static str {
    if reason == "unknown_key" || reason == "nonce_binding" {
        "bad_signature"
    } else {
        reason
    }
}

fn replayable(log: &[Event]) -> bool {
    match log.first() {
        Some(ev) if ev.kind == Kind::ATTACHED => {
            let p = &ev.payload;
            ["principal_id", "client_key_id", "scheme", "public_key"]
                .iter()
                .all(|k| p[*k].is_string())
                && p["task_lineage"].is_array()
                && p["authority_scope"].is_array()
        }
        _ => false,
    }
}

fn strs(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

impl Bridge {
    /// Configure the deployment's scope-grant verifier (authorisation
    /// boundary). A bridge without one refuses every attach.
    pub fn with_grant_verifier(mut self, verifier: Arc<dyn GrantVerifier>) -> Self {
        self.grant_verifier = Some(verifier);
        self
    }

    /// Set the identity grants and attach proofs are bound to (default
    /// [`DEFAULT_BRIDGE_ID`]).
    pub fn with_bridge_id(mut self, bridge_id: &str) -> Self {
        self.bridge_id = bridge_id.to_string();
        self
    }

    pub fn new(
        storage: Arc<dyn Storage>,
        clock: Arc<dyn Clock>,
        verifier: Arc<dyn Verifier>,
        cfg: Config,
    ) -> Result<Bridge> {
        cfg.validate()?;
        Ok(Bridge {
            storage,
            clock,
            verifier,
            grant_verifier: None,
            bridge_id: DEFAULT_BRIDGE_ID.to_string(),
            cfg,
            floor: 0.0,
            sessions: BTreeMap::new(),
            nonces: BTreeMap::new(),
            unauth_logged: BTreeMap::new(),
            revocation_requests: BTreeMap::new(),
            forwarded: vec![],
            forwarded_calls: BTreeMap::new(),
            sent: HashSet::new(),
            revert_requests: vec![],
            last_cp: BTreeMap::new(),
            cp_len: BTreeMap::new(),
        })
    }

    /// The host clock, never earlier than the last committed timestamp: a
    /// clock that went backwards across a restart counts as no time
    /// elapsed (A6).
    fn now(&self) -> f64 {
        self.clock.now().max(self.floor)
    }

    // ---- commit / apply: the only way a cell changes ---------------------

    fn commit(&mut self, sid: &str, items: Vec<Item>) -> Result<Vec<Event>> {
        let batch = self.commit_events(sid, items)?;
        self.maybe_checkpoint(sid)?;
        Ok(batch)
    }

    fn commit_events(&mut self, sid: &str, items: Vec<Item>) -> Result<Vec<Event>> {
        let ts = self.now();
        let log = self.storage.read_log(sid)?;
        let mut prev = log.last().map(Event::hash).unwrap_or_default();
        let mut seq = log.len() as u64;
        let mut batch: Vec<Event> = Vec::with_capacity(items.len());
        for (kind, payload) in items {
            let ev = Event {
                kind,
                session_id: sid.to_string(),
                sequence: seq,
                prev_hash: prev,
                payload,
                timestamp: ts,
            };
            prev = ev.hash();
            seq += 1;
            batch.push(ev);
        }
        self.storage.append_batch(sid, batch.clone())?; // durable first
        for ev in &batch {
            self.apply(ev);
        }
        Ok(batch)
    }

    // ---- I-CHECKPOINT: periodic Merkle root anchoring (SHOULD) ------------

    /// Emit a CHECKPOINT when the session has accumulated N events or T_cp
    /// seconds since the last one. A CHECKPOINT does not trigger another.
    /// Nothing is emitted on a terminated or quarantined session, and the
    /// root is taken only over a log whose chain verifies (I5).
    fn maybe_checkpoint(&mut self, sid: &str) -> Result<()> {
        let Some(s) = self.sessions.get(sid) else { return Ok(()) };
        if s.cell.life == Life::Terminated || s.quarantined {
            return Ok(());
        }
        let n = self.storage.read_log(sid)?.len();
        let now = self.now();
        let Some(&last) = self.last_cp.get(sid) else {
            self.last_cp.insert(sid.to_string(), now); // first commit: no checkpoint
            return Ok(());
        };
        let since = n - self.cp_len.get(sid).copied().unwrap_or(0);
        if since < self.cfg.n_checkpoint && (now - last) < self.cfg.t_checkpoint {
            return Ok(());
        }
        let Ok(hashes) = self.chain_hashes(sid) else { return Ok(()) }; // not vouched for
        let root = crate::merkle::merkle_root_hex(&hashes);
        self.last_cp.insert(sid.to_string(), now);
        self.commit_events(
            sid,
            vec![(Kind::CHECKPOINT, json!({"root": root, "tree_size": n, "signature": "00".repeat(64)}))],
        )?;
        let len = self.storage.read_log(sid)?.len();
        self.cp_len.insert(sid.to_string(), len);
        Ok(())
    }

    /// Verify the hash chain (I5) and return the event hashes in order.
    fn chain_hashes(&self, sid: &str) -> Result<Vec<String>> {
        let mut prev = String::new();
        let mut hashes = Vec::new();
        for (i, ev) in self.storage.read_log(sid)?.iter().enumerate() {
            if ev.sequence != i as u64 || ev.prev_hash != prev {
                return Err(BridgeError::new(format!("event chain broken at index {i} (I5)")));
            }
            prev = ev.hash();
            hashes.push(prev.clone());
        }
        Ok(hashes)
    }

    fn apply(&mut self, ev: &Event) {
        self.floor = self.floor.max(ev.timestamp);
        let p = &ev.payload;
        if ev.kind == Kind::ATTACHED {
            let key = p["client_key_id"].as_str().unwrap_or("").to_string();
            self.sessions.insert(
                ev.session_id.clone(),
                Session {
                    principal: p["principal_id"].as_str().unwrap_or("").to_string(),
                    lineage: strs(&p["task_lineage"]),
                    scope: strs(&p["authority_scope"]),
                    scope_version: 0,
                    keys: BTreeSet::from([key.clone()]),
                    key_material: BTreeMap::from([(
                        key.clone(),
                        (
                            p["scheme"].as_str().unwrap_or("").to_string(),
                            p["public_key"].as_str().unwrap_or("").to_string(),
                        ),
                    )]),
                    conn: BTreeSet::from([key]),
                    resuming: None,
                    resume_from: 0,
                    cell: Cell { att: Attachment::Att, human: Human::None, life: Life::Active },
                    detach_deadline: None,
                    human_deadline: None,
                    det_since: None,
                    det_total: 0.0,
                    quarantined: false,
                    record: None,
                    queue: vec![],
                    used_keys: HashSet::new(),
                    drained: HashSet::new(),
            completed: HashSet::new(),
                    unacked: BTreeMap::new(),
                    revoked: BTreeSet::new(),
                    key_exhausted: false,
                },
            );
            return;
        }
        let (t_detach, t_human) = (self.cfg.t_detach, self.cfg.t_human);
        let Some(s) = self.sessions.get_mut(&ev.session_id) else { return };
        let key_id = p["key_id"].as_str().unwrap_or("").to_string();
        match ev.kind {
            Kind::CLIENT_ADDED => {
                s.key_material.insert(
                    key_id.clone(),
                    (p["scheme"].as_str().unwrap_or("").to_string(), p["public_key"].as_str().unwrap_or("").to_string()),
                );
                s.keys.insert(key_id);
            }
            Kind::KEY_REVOKED => {
                // I11-REVOKE: the key stays in K(s), marked revoked; a hard
                // revocation also takes it out of the client set
                if p["reason"].as_str() == Some("compromise") {
                    s.conn.remove(&key_id);
                }
                s.revoked.insert(key_id);
                s.key_exhausted = s.keys.is_subset(&s.revoked);
            }
            Kind::OPERATOR_ADD_KEY => {
                s.key_material.insert(
                    key_id.clone(),
                    (p["scheme"].as_str().unwrap_or("").to_string(), p["public_key"].as_str().unwrap_or("").to_string()),
                );
                s.keys.insert(key_id);
                s.key_exhausted = s.keys.is_subset(&s.revoked);
            }
            Kind::CLIENT_JOINED => {
                s.conn.insert(key_id);
            }
            Kind::CLIENT_LEFT => {
                s.conn.remove(&key_id);
            }
            Kind::DETACHMENT => {
                if s.cell.att != Attachment::Det {
                    s.det_since = Some(ev.timestamp); // a restart while away continues the interval
                }
                s.cell.att = Attachment::Det;
                s.conn.clear();
                s.resuming = None;
                s.detach_deadline = Some(ev.timestamp + t_detach);
            }
            Kind::RESUME_PREPARED => s.record = Some(ev.clone()),
            Kind::RESUME_STARTED => {
                s.cell.att = Attachment::Res;
                s.resuming = Some(key_id);
                s.resume_from = p["seq"].as_i64().unwrap_or(0);
                s.detach_deadline = None;
                if let Some(since) = s.det_since.take() {
                    s.det_total += ev.timestamp - since;
                }
            }
            Kind::RESUME_FAILED | Kind::RECOVERY_FAILED => s.quarantined = true,
            Kind::RESUME_VERIFIED => {
                s.cell.att = Attachment::Att;
                s.conn = s.resuming.take().into_iter().collect();
            }
            Kind::HUMAN_PENDING => {
                if s.cell.human == Human::None {
                    s.cell.human = Human::Pend;
                    s.human_deadline = Some(ev.timestamp + t_human);
                }
            }
            Kind::HUMAN_RESOLVED => {
                s.cell.human = Human::None;
                s.human_deadline = None;
                // I13: the approval belongs to the calls of the escalation
                // it ends; a call approved earlier keeps the earlier expiry
                let until = p["valid_until"].as_f64().unwrap_or(0.0);
                for c in s.queue.iter_mut().filter(|c| !c.held && c.approved_until.is_none()) {
                    c.approved_until = Some(until);
                }
            }
            Kind::AUTHORITY_NARROWED => {
                s.scope = strs(&p["new_scope"]);
                s.scope_version = p["new_version"].as_u64().unwrap_or(s.scope_version);
            }
            Kind::TOOL_CALL_QUEUED => {
                let key = p["key"].as_str().unwrap_or("").to_string();
                s.used_keys.insert(key.clone());
                s.queue.push(Queued {
                    key,
                    tool: p["tool"].as_str().unwrap_or("").to_string(),
                    permission: p["permission"].as_str().map(String::from),
                    content: p["content"].clone(),
                    expires_at: p["expires_at"].as_f64().unwrap_or(0.0),
                    shown_hash: p["shown_hash"].as_str().unwrap_or("").to_string(),
                    answer: None,
                    held: p["held"].as_bool().unwrap_or(false),
                    approved_until: None,
                });
            }
            Kind::TOOL_CALL_ANSWERED => {
                let key = p["key"].as_str().unwrap_or("");
                for c in s.queue.iter_mut().filter(|c| c.key == key) {
                    c.answer = Some((
                        p["decision"].as_str() == Some("approve"),
                        p["shown_hash"].as_str().unwrap_or("").to_string(),
                    ));
                }
            }
            Kind::TOOL_CALL_DRAINED | Kind::TOOL_CALL_REJECTED | Kind::TOOL_CALL_EXPIRED => {
                let key = p["key"].as_str().unwrap_or("");
                if p["direct"].as_bool() != Some(true) {
                    s.queue.retain(|c| c.key != key); // a direct call was never queued
                }
                s.used_keys.insert(key.to_string());
                if ev.kind == Kind::TOOL_CALL_DRAINED {
                    s.drained.insert(key.to_string());
                    s.unacked.insert(
                        key.to_string(),
                        ForwardedCall {
                            tool: p["tool"].as_str().unwrap_or("").to_string(),
                            permission: p["permission"].as_str().map(String::from),
                            content: p["content"].clone(),
                        },
                    );
                }
            }
            Kind::TOOL_CALL_DELIVERED | Kind::TOOL_CALL_COMPLETED => {
                let key = p["key"].as_str().unwrap_or("");
                s.unacked.remove(key);
                if ev.kind == Kind::TOOL_CALL_COMPLETED {
                    s.completed.insert(key.to_string());
                }
            }
            Kind::TERMINATION => s.cell.life = Life::Terminated,
            // Audit-only events do not move the cell.
            _ => {}
        }
    }

    // ---- sessions -----------------------------------------------------------

    /// Create the session. Takes the client's public key only: the server
    /// registers a scheme tag and verification material and never holds a
    /// signing key. `grant` is the operator's grant for this bridge,
    /// session, scope and exact key; `proof` is the key's signature over
    /// [`attach_message`] (possession).
    pub fn attach(&mut self, id: &SessionIdentity, key: &ClientPublicKey, grant: Option<&str>, proof: Option<&str>) -> Result<()> {
        let granted = match &self.grant_verifier {
            Some(v) => v.verify(&self.bridge_id, id, key, grant),
            None => false,
        };
        if !granted {
            return Err(BridgeError::with_reason("grant_invalid: scope grant missing or invalid", "grant_invalid"));
        }
        let possessed = match proof {
            Some(p) => self.verifier.verify(&key.scheme, &key.material, &attach_message(&self.bridge_id, id, key), p),
            None => false,
        };
        if !possessed {
            return Err(BridgeError::with_reason(
                "possession_invalid: proof of possession missing or invalid",
                "possession_invalid",
            ));
        }
        let sid = id.session_id.as_str();
        if self.sessions.contains_key(sid) || !self.storage.read_log(sid)?.is_empty() {
            return Err(BridgeError::new("session already exists (I6)"));
        }
        self.storage.register_key(sid, &key.key_id, &key.scheme, &key.material)?;
        let committed = self.commit(
            sid,
            vec![(
                Kind::ATTACHED,
                json!({
                    "principal_id": id.principal_id,
                    "authority_scope": canonical_scope(&id.authority_scope),
                    "task_lineage": id.task_lineage,
                    "client_key_id": key.key_id,
                    "scheme": key.scheme,
                    "public_key": hex::encode(&key.material),
                    "scope_version": 0,
                }),
            )],
        );
        if let Err(e) = committed {
            self.storage.unregister_key(sid, &key.key_id)?;
            return Err(e);
        }
        Ok(())
    }

    /// CLIENT_ADDED: a connected client authorises a further key for the
    /// same principal (I15d). `scheme` and `material` are what the [`Verifier`] needs.
    /// `signature` is by `via_key_id` over [`add_client_message`] with a
    /// nonce issued by [`Bridge::challenge`]. Every refusal names a reason
    /// (`via_not_connected`, `bad_signature`, `revoked_key`, `nonce_unknown`,
    /// `nonce_used`, `nonce_expired`, `key_already_registered`) and commits
    /// nothing.
    pub fn add_client_key(
        &mut self,
        sid: &str,
        via_key_id: &str,
        new_key_id: &str,
        scheme: &str,
        material: &[u8],
        nonce: &str,
        signature: &str,
    ) -> Result<()> {
        let refuse = |reason: &'static str| {
            Err(BridgeError::with_reason(format!("add_client rejected: {reason} (I15d)"), reason))
        };
        // The signature comes first: a caller that has not proved a key of the
        // session is answered as a bad signature whether the session is
        // unknown, terminated, quarantined or key-exhausted (I11 (c)); the
        // lifecycle is named only to an authentic caller.
        let msg = add_client_message(sid, via_key_id, new_key_id, scheme, &hex::encode(material), nonce);
        let known = self.sessions.get(sid).is_some_and(|s| s.keys.contains(via_key_id));
        let record = if known { self.storage.key_record(sid, via_key_id)? } else { None };
        let ok = match record {
            Some(m) => self.verifier.verify(&m.scheme, &m.material, &msg, signature),
            None => false,
        };
        if !ok {
            return refuse("bad_signature");
        }
        let s = self.enter(sid)?;
        let now = self.now();
        let t_nonce = self.cfg.t_nonce;
        let rec = self.nonces.get_mut(sid).and_then(|b| b.iter_mut().find(|r| r.nonce == nonce));
        let bound = rec.as_ref().is_some_and(|r| r.key_id == via_key_id && r.eligible);
        if s.revoked.contains(via_key_id) {
            if let (Some(rec), true) = (rec, bound) {
                rec.used = true; // as in I11-REVOKE
            }
            return refuse("revoked_key");
        }
        let Some(rec) = rec else {
            return refuse("nonce_unknown");
        };
        if !bound {
            return refuse("bad_signature"); // not this key's nonce
        }
        let was_used = rec.used;
        rec.used = true; // spent by the first authentic presentation, as in I11d
        if was_used {
            return refuse("nonce_used");
        }
        if now - rec.issued >= t_nonce {
            return refuse("nonce_expired");
        }
        if !s.conn.contains(via_key_id) {
            return refuse("via_not_connected");
        }
        if s.keys.contains(new_key_id) {
            return refuse("key_already_registered");
        }
        self.storage.register_key(sid, new_key_id, scheme, material)?;
        let committed = self.commit(
            sid,
            vec![(
                Kind::CLIENT_ADDED,
                json!({"key_id": new_key_id, "via": via_key_id, "scheme": scheme, "public_key": hex::encode(material)}),
            )],
        );
        if let Err(e) = committed {
            self.storage.unregister_key(sid, new_key_id)?;
            return Err(e);
        }
        Ok(())
    }

    /// Known, not terminated (I6); timers evaluated first.
    fn enter(&mut self, sid: &str) -> Result<Session> {
        self.enter_with(sid, false)
    }

    /// A key_exhausted session serves no client operation, but its timers
    /// keep running: they are evaluated before the refusal, so an expired
    /// one reports TERMINATED. `exhausted_ok` is for transport loss, which is
    /// not a client operation.
    fn enter_with(&mut self, sid: &str, exhausted_ok: bool) -> Result<Session> {
        let terminated = |b: &Bridge| {
            b.sessions.get(sid).map(|s| s.cell.life == Life::Terminated).unwrap_or(false)
        };
        if !self.sessions.contains_key(sid) {
            return Err(BridgeError::with_reason(format!("unknown session {sid}"), "unknown_session"));
        }
        if terminated(self) {
            return Err(BridgeError::with_reason("session is TERMINATED (I6)", "terminated"));
        }
        if self.sessions[sid].quarantined {
            return Err(BridgeError::with_reason("session is QUARANTINED", "quarantined"));
        }
        if self.sessions[sid].key_exhausted && !exhausted_ok {
            self.check_timers(sid)?;
            if terminated(self) {
                return Err(BridgeError::with_reason("session is TERMINATED (I6)", "terminated"));
            }
            return Err(BridgeError::with_reason("session is KEY_EXHAUSTED", "key_exhausted"));
        }
        self.check_timers(sid)?;
        if terminated(self) {
            return Err(BridgeError::with_reason("session is TERMINATED (I6)", "terminated"));
        }
        Ok(self.sessions[sid].clone())
    }

    // ---- tool calls (I2, I13, I14) ----------------------------------------

    pub fn submit_tool_call(
        &mut self,
        sid: &str,
        tool: &str,
        key: Option<&str>,
        permission: Option<&str>,
        content: Option<&Value>,
    ) -> Result<ToolOutcome> {
        self.submit_tool_call_keyed(sid, tool, key, permission, content).map(|(o, _)| o)
    }

    /// An idempotency key for a call that came without one: the next
    /// `tc-NNNN` the session has not used, so a generated key never
    /// collides with one the runtime supplied (I13).
    fn fresh_key(s: &Session) -> String {
        let mut n = s.used_keys.len() + 1;
        while s.used_keys.contains(&format!("tc-{n:04}")) {
            n += 1;
        }
        format!("tc-{n:04}")
    }

    /// Submit a tool call; returns the outcome and the idempotency key the
    /// call carries (the caller's, or the one the bridge generated; empty
    /// for a call forwarded directly without one).
    pub fn submit_tool_call_keyed(
        &mut self,
        sid: &str,
        tool: &str,
        key: Option<&str>,
        permission: Option<&str>,
        content: Option<&Value>,
    ) -> Result<(ToolOutcome, String)> {
        // the content is hashed and logged, so it must have a canonical form
        // (no integer beyond 2^53, no NaN or infinity); the answer depends on
        // the call alone
        if let Some(c) = content {
            if crate::wire::try_canonical_bytes(c).is_err() {
                return Err(BridgeError::with_reason("tool call content has no canonical form", "bad_canonical"));
            }
        }
        let s = self.enter(sid)?;
        if s.cell.human == Human::Pend {
            let key = key.map(String::from).unwrap_or_else(|| Self::fresh_key(&s));
            if s.used_keys.contains(&key) {
                return Ok((ToolOutcome::Duplicate, key));
            }
            if s.queue.len() >= self.cfg.q_max {
                self.commit(
                    sid,
                    vec![(
                        Kind::TOOL_CALL_REJECTED,
                        json!({"key": key, "tool": tool, "reason": "queue_full"}),
                    )],
                )?;
                return Ok((ToolOutcome::Rejected, key));
            }
            let content = content.cloned().unwrap_or(Value::Null);
            let shown_hash = call_hash(tool, permission, &content);
            let expires_at = self.now() + self.cfg.t_call;
            self.commit(
                sid,
                vec![(
                    Kind::TOOL_CALL_QUEUED,
                    json!({"key": key, "tool": tool, "permission": permission, "content": content,
                           "shown_hash": shown_hash, "expires_at": expires_at}),
                )],
            )?;
            return Ok((ToolOutcome::Queued, key));
        }
        if s.cell.att == Attachment::Att {
            if permission.is_some_and(|p| !s.scope.iter().any(|x| x == p)) {
                // I3 on the direct path: a call outside the current scope is
                // not forwarded; the refusal is recorded (it was never
                // queued, so the event is marked `direct`)
                let key = key.map(String::from).unwrap_or_else(|| Self::fresh_key(&s));
                self.commit(
                    sid,
                    vec![(
                        Kind::TOOL_CALL_REJECTED,
                        json!({"key": key, "tool": tool, "permission": permission,
                               "reason": "scope", "direct": true}),
                    )],
                )?;
                return Err(BridgeError::with_reason(
                    format!("tool call needs {:?}, which is not in the current scope (I3)", permission.unwrap_or("")),
                    "scope",
                ));
            }
            let call = ForwardedCall {
                tool: tool.to_string(),
                permission: permission.map(String::from),
                content: content.cloned().unwrap_or(Value::Null),
            };
            self.send(sid, key.unwrap_or(""), call);
            return Ok((ToolOutcome::Forwarded, key.unwrap_or("").to_string()));
        }
        self.detached_call(sid, &s, tool, key, permission, content)
    }

    /// G1: a call with no escalation pending while no client is attached.
    /// `Refuse` (default) errors; `Queue` holds the call for an answer after
    /// re-attach; `Forward` forwards an allowlisted, in-scope call at once,
    /// recorded as queued, answered and drained in one durable batch.
    fn detached_call(
        &mut self,
        sid: &str,
        s: &Session,
        tool: &str,
        key: Option<&str>,
        permission: Option<&str>,
        content: Option<&Value>,
    ) -> Result<(ToolOutcome, String)> {
        let policy = self.cfg.detached_calls;
        let in_scope = permission.is_none_or(|p| s.scope.iter().any(|x| x == p));
        let allowed = permission.is_some_and(|p| self.cfg.detached_allow.contains(p));
        if policy == DetachedCalls::Refuse || !in_scope || (policy == DetachedCalls::Forward && !allowed) {
            return Err(BridgeError::new("tool call not allowed in this cell (detached_calls policy)"));
        }
        let key = key.map(String::from).unwrap_or_else(|| Self::fresh_key(s));
        if s.used_keys.contains(&key) {
            return Ok((ToolOutcome::Duplicate, key));
        }
        if s.queue.len() >= self.cfg.q_max {
            self.commit(
                sid,
                vec![(Kind::TOOL_CALL_REJECTED, json!({"key": key, "tool": tool, "reason": "queue_full"}))],
            )?;
            return Ok((ToolOutcome::Rejected, key));
        }
        let content = content.cloned().unwrap_or(Value::Null);
        let shown_hash = call_hash(tool, permission, &content);
        let expires_at = self.now() + self.cfg.t_call;
        let queued = (
            Kind::TOOL_CALL_QUEUED,
            json!({"key": key, "tool": tool, "permission": permission, "content": content,
                   "shown_hash": shown_hash, "held": true, "expires_at": expires_at}),
        );
        if policy == DetachedCalls::Queue {
            self.commit(sid, vec![queued])?;
            return Ok((ToolOutcome::Queued, key));
        }
        self.commit(
            sid,
            vec![
                queued,
                (
                    Kind::TOOL_CALL_ANSWERED,
                    json!({"key": key, "shown_hash": shown_hash, "decision": "approve",
                           "source": "operator_policy"}),
                ),
                (
                    Kind::TOOL_CALL_DRAINED,
                    json!({"key": key, "tool": tool, "permission": permission, "content": content,
                           "shown_hash": shown_hash,
                           "authority_hash": authority_hash(&s.principal, &s.scope, &s.lineage)}),
                ),
            ],
        )?;
        let call = ForwardedCall { tool: tool.to_string(), permission: permission.map(String::from), content };
        self.send(sid, &key, call); // only after the batch is durable (I12)
        Ok((ToolOutcome::Forwarded, key))
    }

    /// Hand the request to the runtime: the tool, permission and content
    /// that were hashed at queue time and retained in the log (I14).
    fn send(&mut self, sid: &str, key: &str, call: ForwardedCall) {
        self.sent.insert((sid.to_string(), key.to_string()));
        self.forwarded.push((sid.to_string(), key.to_string(), call.tool.clone()));
        self.forwarded_calls.insert((sid.to_string(), key.to_string()), call);
    }

    /// The runtime acknowledges that it received a forwarded call
    /// (`TOOL_CALL_DELIVERED`). Until then a restart forwards it again.
    pub fn delivered(&mut self, sid: &str, key: &str) -> Result<()> {
        let s = self.enter(sid)?;
        if !s.unacked.contains_key(key) {
            return Err(BridgeError::new(format!("no forwarded call {key:?} awaits delivery")));
        }
        self.commit(sid, vec![(Kind::TOOL_CALL_DELIVERED, json!({"key": key}))]).map(|_| ())
    }

    /// The runtime reports that a call finished (`TOOL_CALL_COMPLETED`).
    pub fn completed(&mut self, sid: &str, key: &str, result_hash: &str) -> Result<()> {
        let s = self.enter(sid)?;
        // accepted once for a call the bridge forwarded, at a drain (the log
        // says so) or directly (this process says so); a call that was never
        // forwarded has nothing to complete
        let forwarded = s.drained.contains(key) || self.sent.contains(&(sid.to_string(), key.to_string()));
        if s.completed.contains(key) || !forwarded {
            return Err(BridgeError::new(format!("no call {key:?} to complete")));
        }
        self.commit(sid, vec![(Kind::TOOL_CALL_COMPLETED, json!({"key": key, "result_hash": result_hash}))])
            .map(|_| ())
    }

    /// h(content shown) as the bridge recorded it: what a faithful client
    /// that rendered the same content reports.
    pub fn shown_hash_of(&self, sid: &str, key: &str) -> Result<String> {
        self.sessions
            .get(sid)
            .and_then(|s| s.queue.iter().find(|c| c.key == key))
            .map(|c| c.shown_hash.clone())
            .ok_or_else(|| BridgeError::new(format!("no queued call {key:?}")))
    }

    /// Keys of queued calls that have no answer yet.
    pub fn unanswered_keys(&self, sid: &str) -> Vec<String> {
        self.sessions[sid].queue.iter().filter(|c| c.answer.is_none()).map(|c| c.key.clone()).collect()
    }

    /// TOOL_CALL_ANSWERED: the human's decision on a queued call, with the
    /// hash of what the client displayed (I14). The first answer is final.
    pub fn answer_tool_call(&mut self, sid: &str, key: &str, shown_hash: &str, approve: bool) -> Result<()> {
        let s = self.enter(sid)?;
        let Some(entry) = s.queue.iter().find(|c| c.key == key) else {
            return Err(BridgeError::new(format!("no queued call {key:?} to answer")));
        };
        if entry.answer.is_some() {
            return Err(BridgeError::new("call already answered (I14)"));
        }
        let held = entry.held;
        self.commit(
            sid,
            vec![(
                Kind::TOOL_CALL_ANSWERED,
                json!({"key": key, "shown_hash": shown_hash,
                       "decision": if approve { "approve" } else { "deny" }}),
            )],
        )?;
        if held {
            self.drain(sid)?; // no-op unless back in (Att, None)
        }
        Ok(())
    }

    /// Rule D: drain in arrival order, revalidating every call (I13, I14).
    fn drain(&mut self, sid: &str) -> Result<()> {
        let s = self.sessions[sid].clone();
        if !(s.cell.att == Attachment::Att
            && s.cell.human == Human::None
            && s.cell.life == Life::Active
            && !s.quarantined)
        {
            return Ok(());
        }
        let now = self.now();
        let ah = authority_hash(&s.principal, &s.scope, &s.lineage);
        let items: Vec<Item> = s
            .queue
            .iter()
            .filter(|c| !(c.held && c.answer.is_none() && now < c.expires_at)) // a held call waits for its answer
            .map(|c| {
                let base = |reason: &str| json!({"key": c.key, "tool": c.tool, "reason": reason});
                if now >= c.expires_at {
                    (Kind::TOOL_CALL_EXPIRED, base("call_ttl"))
                } else if !c.held && c.approved_until.is_none_or(|u| now >= u) {
                    (Kind::TOOL_CALL_EXPIRED, base("approval_ttl"))
                } else if c.permission.as_ref().is_some_and(|p| !s.scope.contains(p)) {
                    (Kind::TOOL_CALL_REJECTED, base("scope"))
                } else {
                    match &c.answer {
                        None => (Kind::TOOL_CALL_REJECTED, base("unanswered")),
                        Some((false, _)) => (Kind::TOOL_CALL_REJECTED, base("denied")),
                        Some((true, h)) if *h != c.shown_hash => {
                            (Kind::TOOL_CALL_REJECTED, base("answer_mismatch"))
                        }
                        Some(_) => (
                            Kind::TOOL_CALL_DRAINED,
                            json!({"key": c.key, "tool": c.tool, "permission": c.permission,
                                   "content": c.content, "authority_hash": ah,
                                   "shown_hash": c.shown_hash}),
                        ),
                    }
                }
            })
            .collect();
        if !items.is_empty() {
            let batch = self.commit(sid, items)?;
            for ev in batch.iter().filter(|e| e.kind == Kind::TOOL_CALL_DRAINED) {
                // forwarded only after the DRAINED events are durable (I12)
                let key = ev.str_field("key").unwrap_or("").to_string();
                let call = ForwardedCall {
                    tool: ev.str_field("tool").unwrap_or("").to_string(),
                    permission: ev.str_field("permission").map(String::from),
                    content: ev.payload["content"].clone(),
                };
                self.send(sid, &key, call);
            }
        }
        // A drained call whose delivery was never acknowledged (a crash in
        // between) is forwarded again, with the same key, by this instance.
        let again: Vec<(String, ForwardedCall)> = self.sessions[sid]
            .unacked
            .iter()
            .filter(|(k, _)| !self.sent.contains(&(sid.to_string(), (*k).clone())))
            .map(|(k, c)| (k.clone(), c.clone()))
            .collect();
        for (key, call) in again {
            self.send(sid, &key, call);
        }
        Ok(())
    }

    // ---- detach, escalate, resolve ----------------------------------------

    /// RESUME_PREPARED: the bridge's own resume record, once per detachment (I1).
    fn prepared(&self, s: &Session, reason: &str) -> Item {
        let calls: Vec<Value> =
            s.queue.iter().map(|c| json!({"key": c.key, "call": c.tool})).collect();
        (
            Kind::RESUME_PREPARED,
            json!({
                "authority_hash": authority_hash(&s.principal, &s.scope, &s.lineage),
                "reason": reason,
                "authority_scope": s.scope,
                "scope_version": s.scope_version,
                "pending_tool_calls": calls,
            }),
        )
    }

    /// Transport loss of one client (`key_id`) or of every connected client
    /// (`None`). Only the last departure detaches (I15b). A key_exhausted
    /// session loses its transport like any other.
    pub fn client_disconnect(&mut self, sid: &str, key_id: Option<&str>, reason: &str) -> Result<()> {
        let s = self.enter_with(sid, true)?;
        if s.cell.att == Attachment::Det {
            return Ok(());
        }
        let targets: BTreeSet<String> = if s.cell.att == Attachment::Res {
            match (key_id, &s.resuming) {
                (Some(k), Some(r)) if k != r => return Ok(()),
                (_, Some(r)) => BTreeSet::from([r.clone()]),
                _ => return Ok(()),
            }
        } else {
            match key_id {
                None => s.conn.clone(),
                Some(k) => s.conn.iter().filter(|c| c.as_str() == k).cloned().collect(),
            }
        };
        if targets.is_empty() {
            return Ok(());
        }
        let remaining: BTreeSet<_> = if s.cell.att == Attachment::Att {
            s.conn.difference(&targets).cloned().collect()
        } else {
            BTreeSet::new()
        };
        if !remaining.is_empty() {
            let items = targets
                .iter()
                .map(|k| (Kind::CLIENT_LEFT, json!({"key_id": k, "reason": reason})))
                .collect();
            self.commit(sid, items)?;
            return Ok(());
        }
        let items = vec![(Kind::DETACHMENT, json!({"reason": reason})), self.prepared(&s, reason)];
        self.commit(sid, items)?;
        self.check_timers(sid)
    }

    pub fn escalate_to_human(&mut self, sid: &str, reason: &str) -> Result<()> {
        self.enter(sid)?;
        self.commit(sid, vec![(Kind::HUMAN_PENDING, json!({"reason": reason}))])?;
        self.check_timers(sid)
    }

    pub fn human_resolve(&mut self, sid: &str) -> Result<()> {
        let s = self.enter(sid)?;
        if s.cell.human != Human::Pend {
            return Err(BridgeError::new("human_resolve requires Human=Pend"));
        }
        self.commit(
            sid,
            vec![(Kind::HUMAN_RESOLVED, json!({"valid_until": self.now() + self.cfg.t_approve}))],
        )?;
        self.drain(sid)
    }

    // ---- timers (L1, L2, I13) ------------------------------------------------

    pub fn tick(&mut self, sid: Option<&str>) -> Result<()> {
        let ids: Vec<String> = match sid {
            Some(x) => vec![x.to_string()],
            None => self.sessions.keys().cloned().collect(),
        };
        for id in ids {
            self.check_timers(&id)?;
            self.maybe_checkpoint(&id)?;
        }
        Ok(())
    }

    fn check_timers(&mut self, sid: &str) -> Result<()> {
        self.check_timers_mode(sid, false)
    }

    /// With `overdue_only` only the timers whose expiry lies before the
    /// present instant fire: one that expires in the very tick of an
    /// incoming request waits until the request has been processed.
    fn check_timers_mode(&mut self, sid: &str, overdue_only: bool) -> Result<()> {
        let s = self.sessions[sid].clone();
        if s.cell.life == Life::Terminated || s.quarantined {
            return Ok(());
        }
        let now = self.now();
        let due = |elapsed: f64, limit: f64| if overdue_only { elapsed > limit } else { elapsed >= limit };
        let detach = s.cell.att == Attachment::Det && s.detach_deadline.is_some_and(|d| due(now - d, 0.0));
        let total = s.cell.att == Attachment::Det
            && s.det_since.is_some_and(|since| due(s.det_total + (now - since), self.cfg.t_total));
        let human = s.cell.human == Human::Pend && s.human_deadline.is_some_and(|d| due(now - d, 0.0));
        // the reason names the detach-side timer that fired
        let away = if detach { "detach_timeout" } else { "detach_total_timeout" };
        let items: Vec<Item> = match (detach || total, human) {
            (true, true) => vec![
                (Kind::HUMAN_TIMEOUT, json!({"reason": "human_timeout"})),
                (Kind::DETACH_TIMEOUT, json!({"reason": away})),
                (Kind::TERMINATION, json!({"reason": format!("human_timeout+{away} (simultaneous)")})),
            ],
            (false, true) => vec![
                (Kind::HUMAN_TIMEOUT, json!({"reason": "human_timeout"})),
                (Kind::TERMINATION, json!({"reason": "human_timeout"})),
            ],
            (true, false) => vec![
                (Kind::DETACH_TIMEOUT, json!({"reason": away})),
                (Kind::TERMINATION, json!({"reason": away})),
            ],
            (false, false) if overdue_only => vec![],
            (false, false) => s
                .queue
                .iter()
                .filter(|c| now >= c.expires_at)
                .map(|c| {
                    (
                        Kind::TOOL_CALL_EXPIRED,
                        json!({"key": c.key, "tool": c.tool, "reason": "call_ttl"}),
                    )
                })
                .collect(),
        };
        if items.is_empty() {
            return Ok(());
        }
        self.commit(sid, items).map(|_| ())
    }

    // ---- challenge-response re-attach and join (I4, I8, I9, I11, I15) --------

    /// Issue a fresh single-use nonce (I11b). Not a governance event;
    /// volatile, so a restart voids every nonce.
    pub fn challenge(&mut self, sid: &str, key_id: &str) -> Result<Challenge> {
        // I11a: one rejection for an unknown, a terminated and a quarantined
        // session, so the op confirms neither existence nor lifecycle state
        // to an unauthenticated caller.
        let eligible = match self.sessions.get(sid) {
            Some(s) if s.cell.life != Life::Terminated && !s.quarantined => {
                s.keys.contains(key_id) && !s.revoked.contains(key_id)
            }
            _ => return Err(BridgeError::with_reason(CHALLENGE_REFUSED, "refused")),
        };
        let mut raw = [0u8; 16];
        getrandom::getrandom(&mut raw).map_err(|e| BridgeError::new(format!("no randomness: {e}")))?;
        let nonce = hex::encode(raw);
        let issued = self.now();
        let t_nonce = self.cfg.t_nonce;
        let book = self.nonces.entry(sid.to_string()).or_default();
        if book.len() >= NONCE_RECORDS {
            // I11f: make room from spent or expired records only; a live
            // nonce is never evicted, so no caller can invalidate a nonce
            // another client holds. If every record is live, refuse.
            book.retain(|r| !r.used && issued - r.issued < t_nonce);
            if book.len() >= NONCE_RECORDS {
                return Err(BridgeError::new("challenge budget exhausted (I11f)"));
            }
        }
        book.push_back(NonceRec { nonce: nonce.clone(), issued, used: false, key_id: key_id.to_string(), eligible });
        Ok(Challenge { nonce, ttl_seconds: self.cfg.t_nonce })
    }

    /// Det -> Res on an authentic re-attach. A re-attach while Att is
    /// refused as `already_attached` (join is the only way into an attached
    /// session), and any request while Res as `resume_in_progress`. Every
    /// failure is RESUME_REJECTED with no change of cell (I11e). A join
    /// while Att is a CLIENT_JOINED (the replay is returned).
    pub fn begin_resume(&mut self, sid: &str, req: &ResumeRequest, transport_replay: bool) -> Result<Vec<Event>> {
        self.begin_resume_as(ResumeOp::Reattach, sid, req, transport_replay)
    }

    fn begin_resume_as(&mut self, op: ResumeOp, sid: &str, req: &ResumeRequest, transport_replay: bool) -> Result<Vec<Event>> {
        // A sequence number is a non-negative integer; another value is
        // malformed, answered the same for every session and not logged.
        if req.seq < 0 || req.seq > (1i64 << 53) {
            return Err(BridgeError::with_reason("malformed re-attach request", "bad_canonical"));
        }
        self.refuse_unavailable(sid)?;
        // A timer that expired before this instant has ended the session;
        // one that expires in the very tick of the request waits for it.
        self.check_timers_mode(sid, true)?;
        self.refuse_unavailable(sid)?;
        let s = self.sessions[sid].clone();
        let mut reason = self.reject_reason(op, sid, &s, req)?;
        if transport_replay {
            reason = Some("transport_replay"); // I8
        }
        if reason.is_none() && s.cell.att == Attachment::Res {
            reason = Some("resume_in_progress");
        }
        if reason.is_none() && s.cell.att == Attachment::Att && op == ResumeOp::Reattach {
            reason = Some("already_attached");
        }
        if reason.is_none() && s.cell.att != Attachment::Att && op == ResumeOp::Join {
            reason = Some("not_attached"); // I15c
        }
        if let Some(reason) = reason {
            let shown = public_reason(reason);
            let unauthenticated = matches!(
                reason,
                "transport_replay" | "unknown_key" | "bad_signature" | "nonce_binding" | "revoked_key"
            );
            let mut write = true;
            if unauthenticated {
                // I11g: the caller is not shown to hold an active key; bound what it can write
                let logged = self.unauth_logged.entry(sid.to_string()).or_insert(0);
                if *logged >= UNAUTH_LOG_LIMIT {
                    write = false;
                } else {
                    *logged += 1;
                }
            } else {
                self.unauth_logged.remove(sid); // a key holder spoke
            }
            if write {
                self.commit(
                    sid,
                    vec![(
                        Kind::RESUME_REJECTED,
                        json!({"reason": reason, "key_id": req.key_id, "seq": req.seq}),
                    )],
                )?;
            }
            self.check_timers(sid)?; // the tick's timers, after the request
            return Err(BridgeError::with_reason(
                format!("re-attach rejected: {shown} (I4/I8/I9/I11)"),
                shown,
            ));
        }
        self.unauth_logged.remove(sid); // a key holder spoke
        let body = json!({"key_id": req.key_id, "seq": req.seq, "hash": req.hash,
                          "nonce_digest": digest(&req.nonce)});
        let joined = s.cell.att == Attachment::Att;
        self.commit(sid, vec![(if joined { Kind::CLIENT_JOINED } else { Kind::RESUME_STARTED }, body)])?;
        self.check_timers(sid)?;
        if joined {
            return self.replay_after(sid, req.seq);
        }
        Ok(vec![])
    }

    /// A further client joins an attached session (I15c).
    /// I11a: a resume request for an unknown, a terminated or a quarantined
    /// session gets one rejection, so the op confirms neither existence nor
    /// lifecycle state before the caller has proved anything.
    fn refuse_unavailable(&self, sid: &str) -> Result<()> {
        match self.sessions.get(sid) {
            Some(s) if s.cell.life != Life::Terminated && !s.quarantined => Ok(()),
            _ => Err(BridgeError::with_reason(RESUME_REFUSED, "refused")),
        }
    }

    pub fn join(&mut self, sid: &str, req: &ResumeRequest, transport_replay: bool) -> Result<Vec<Event>> {
        self.begin_resume_as(ResumeOp::Join, sid, req, transport_replay)
    }

    /// Why the request does not verify, or None. The order is fixed: the
    /// key and the signature, revocation, the binding of the nonce to the
    /// key, the nonce, the prefix. Before the nonce step no nonce is touched,
    /// except that a revoked key spends the nonce bound to it; from the nonce
    /// step on the request has spent its nonce (I11d).
    fn reject_reason(
        &mut self,
        op: ResumeOp,
        sid: &str,
        s: &Session,
        req: &ResumeRequest,
    ) -> Result<Option<&'static str>> {
        if !s.keys.contains(&req.key_id) {
            return Ok(Some("unknown_key")); // I15
        }
        let ok = match self.storage.key_record(sid, &req.key_id)? {
            Some(m) => self.verifier.verify(&m.scheme, &m.material, &resume_message(op, sid, &req.key_id, &req.nonce, req.seq, &req.hash), &req.signature),
            None => false,
        };
        if !ok {
            return Ok(Some("bad_signature")); // I11c
        }
        let now = self.now();
        let t_nonce = self.cfg.t_nonce;
        let rec = self.nonces.get_mut(sid).and_then(|b| b.iter_mut().find(|r| r.nonce == req.nonce));
        let bound = rec.as_ref().is_some_and(|r| r.key_id == req.key_id && r.eligible);
        // I11-REVOKE: after the signature, before the nonce; the request is
        // authentic, so it spends the nonce bound to its key (I11d)
        if s.revoked.contains(&req.key_id) {
            if let (Some(rec), true) = (rec, bound) {
                rec.used = true;
            }
            return Ok(Some("revoked_key"));
        }
        let Some(rec) = rec else {
            return Ok(Some("nonce_unknown")); // I11b
        };
        if !bound {
            return Ok(Some("nonce_binding")); // I11b
        }
        let was_used = rec.used;
        rec.used = true; // I11d: spent by the first authentic presentation
        if was_used {
            return Ok(Some("nonce_used"));
        }
        if now - rec.issued >= t_nonce {
            return Ok(Some("nonce_expired")); // I9
        }
        let log = self.storage.read_log(sid)?;
        let on_chain = req.seq >= 0
            && log.get(req.seq as usize).is_some_and(|e| e.hash() == req.hash);
        if !on_chain {
            return Ok(Some("prefix_mismatch")); // I4
        }
        Ok(None)
    }

    /// The events a client that acknowledged `seq` has not seen (I4).
    pub fn replay_after(&self, sid: &str, seq: i64) -> Result<Vec<Event>> {
        Ok(self.storage.read_log(sid)?.into_iter().skip((seq + 1).max(0) as usize).collect())
    }

    /// Res -> Att once the hash chain verifies; otherwise terminate. Returns
    /// the replay of the events after the acknowledged prefix.
    pub fn complete_resume(&mut self, sid: &str) -> Result<Vec<Event>> {
        let s = self.enter(sid)?;
        if s.cell.att != Attachment::Res {
            return Err(BridgeError::new("complete_resume requires Att=Res"));
        }
        if let Err(e) = self.verify_chain(sid) {
            self.quarantine(sid, Kind::RESUME_FAILED, json!({"reason": "chain"}));
            return Err(e);
        }
        self.commit(sid, vec![(Kind::RESUME_VERIFIED, json!({}))])?;
        self.drain(sid)?;
        self.replay_after(sid, s.resume_from)
    }

    // ---- authority (I3, I10) -----------------------------------------------

    fn reject_extension(&mut self, sid: &str, s: &Session, proposed: &[String], source: &str) -> Result<()> {
        let cell = format!("{:?}/{:?}", s.cell.att, s.cell.human);
        self.commit(
            sid,
            vec![(
                Kind::AUTHORITY_EXTENSION_REJECTED,
                json!({"proposed": proposed, "current": s.scope, "cell": cell, "source": source}),
            )],
        )?;
        Ok(())
    }

    /// Reject any widening in every cell; a subset is not an extension.
    /// `Observed`: the runtime changed its own scope; the bridge cannot
    /// prevent that, so it records the rejection, keeps its record and asks
    /// for a revert (I3).
    pub fn attempt_authority_extension(
        &mut self,
        sid: &str,
        proposed: &[String],
        source: Source,
    ) -> Result<AuthorityOutcome> {
        // an observed widening is a report about the runtime, not a client
        // operation: it is recorded on a key-exhausted session too
        let s = self.enter_with(sid, source == Source::Observed)?;
        let proposed = canonical_scope(proposed);
        if proposed.iter().all(|p| s.scope.contains(p)) {
            return Ok(AuthorityOutcome::NoChange);
        }
        match source {
            Source::Observed => {
                self.reject_extension(sid, &s, &proposed, "observed")?;
                self.revert_requests.push((sid.to_string(), s.scope.clone()));
                Ok(AuthorityOutcome::Revert)
            }
            Source::Requested => {
                self.reject_extension(sid, &s, &proposed, "requested")?;
                Err(BridgeError::with_reason("authority extension rejected (I3)", "extension_rejected"))
            }
        }
    }

    /// Replace the scope by a strict subset of it (I10); returns the new
    /// scope version. A proposal that equals or widens the scope is refused
    /// as `not_a_strict_narrowing` and recorded.
    pub fn narrow_authority_scope(&mut self, sid: &str, proposed: &[String]) -> Result<u64> {
        let s = self.enter(sid)?;
        let proposed = canonical_scope(proposed);
        if !proposed.iter().all(|p| s.scope.contains(p)) {
            self.reject_extension(sid, &s, &proposed, "requested")?;
            return Err(BridgeError::with_reason("authority extension rejected (I3)", "not_a_strict_narrowing"));
        }
        if s.scope.iter().all(|c| proposed.contains(c)) {
            self.commit(
                sid,
                vec![(
                    Kind::AUTHORITY_NARROWING_REJECTED,
                    json!({"proposed": proposed, "current": s.scope,
                           "reason": "not a strict narrowing"}),
                )],
            )?;
            return Err(BridgeError::with_reason("authority narrowing rejected (I10)", "not_a_strict_narrowing"));
        }
        let version = s.scope_version + 1;
        self.commit(
            sid,
            vec![(Kind::AUTHORITY_NARROWED, json!({"new_scope": proposed, "new_version": version}))],
        )?;
        Ok(version)
    }

    // ---- key lifecycle (I11-REVOKE) -----------------------------------------

    /// Revocation of a registered client key. `reason` is `rotation` (soft:
    /// connected clients stay) or `compromise` (hard: the key leaves the
    /// client set, and the session detaches if it was the last connected
    /// one, or the key whose re-attach is being verified: that re-attach is
    /// abandoned). `signature` is the operator's over
    /// `["bc/v1/revoke", bridge_id, sid, key_id, reason, seq, head]` (the log
    /// position at signing) and is verified (refused as
    /// `operator_signature_invalid`, nothing committed); an empty one with
    /// `requested_by` records only KEY_REVOCATION_REQUESTED; without
    /// `requested_by` it is a missing signature and refused. With both, the
    /// request is recorded first.
    pub fn revoke_key(
        &mut self,
        sid: &str,
        key_id: &str,
        reason: &str,
        signature: &str,
        requested_by: Option<&str>,
    ) -> Result<Revocation> {
        if reason != "rotation" && reason != "compromise" {
            return Err(BridgeError::with_reason(format!("unknown revocation reason {reason:?}"), "bad_canonical"));
        }
        if !signature.is_empty() || requested_by.is_none() {
            self.operator_checked(sid, signature, |b, seq, head| revoke_message(b, sid, key_id, reason, seq, head))?;
        }
        let s = self.enter(sid)?;
        if !s.keys.contains(key_id) {
            return Err(BridgeError::with_reason(format!("unknown key {key_id:?}"), "unknown_key"));
        }
        if s.revoked.contains(key_id) {
            return Err(BridgeError::with_reason(format!("key {key_id:?} is already revoked"), "revoked_key"));
        }
        let now = self.now();
        if let Some(by) = requested_by {
            // A request needs no signature, so its writes are bounded; the
            // refusal appends nothing.
            let asked = self.revocation_requests.get(sid).copied().unwrap_or(0);
            if asked >= REVOCATION_REQUEST_LIMIT {
                return Err(BridgeError::new("revocation requests refused: limit reached"));
            }
            self.revocation_requests.insert(sid.to_string(), asked + 1);
            self.commit(
                sid,
                vec![(
                    Kind::KEY_REVOCATION_REQUESTED,
                    json!({"key_id": key_id, "requested_by": by, "reason": reason}),
                )],
            )?;
        }
        if signature.is_empty() {
            return Ok(Revocation::Requested);
        }
        let mut items: Vec<Item> = vec![(
            Kind::KEY_REVOKED,
            json!({"key_id": key_id, "reason": reason, "revoked_at": now, "signature": signature}),
        )];
        // a hard revocation of the last connected key, or a revocation of
        // either kind of the key whose re-attach is being verified (the
        // verification is abandoned): detach
        let last_connected = s.cell.att == Attachment::Att && s.conn.len() == 1 && s.conn.contains(key_id);
        let verifying = s.cell.att == Attachment::Res && s.resuming.as_deref() == Some(key_id);
        if (reason == "compromise" && last_connected) || verifying {
            items.push((Kind::DETACHMENT, json!({"reason": "key_revoked"})));
            items.push(self.prepared(&s, "key_revoked"));
        }
        self.commit(sid, items)?;
        self.revocation_requests.remove(sid);
        Ok(Revocation::Revoked)
    }

    /// The identity operator signatures, grants and attach proofs are bound to.
    pub fn bridge_id(&self) -> &str {
        &self.bridge_id
    }

    /// The log position an operator signs: the sequence and the hash of the
    /// last event of the session.
    pub fn head_of(&self, sid: &str) -> (u64, String) {
        match self.storage.read_log(sid).ok().and_then(|l| l.last().cloned()) {
            Some(ev) => (ev.sequence, ev.hash()),
            None => (0, String::new()),
        }
    }

    /// The operator events are authenticated by the deployment's verifier
    /// (the one that checks scope grants); without one, or with a signature
    /// that does not verify over the message (which names this bridge and
    /// the current log position), they are refused. The check comes before
    /// anything is said about the session. The timers that are due fire
    /// first, as at any tick, so the position the signature names is the one
    /// the operator's event follows and an expired session is over.
    fn operator_checked(
        &mut self,
        sid: &str,
        signature: &str,
        build: impl FnOnce(&str, u64, &str) -> Vec<u8>,
    ) -> Result<()> {
        if self.sessions.contains_key(sid) {
            self.check_timers(sid)?;
        }
        let (seq, head) = self.head_of(sid);
        let message = build(&self.bridge_id, seq, &head);
        let ok = match &self.grant_verifier {
            Some(v) => v.verify_operation(&message, Some(signature)),
            None => false,
        };
        if ok {
            Ok(())
        } else {
            Err(BridgeError::with_reason(
                "operator_signature_invalid: operator signature missing or invalid",
                "operator_signature_invalid",
            ))
        }
    }

    /// OPERATOR_ADD_KEY: the recovery from key_exhausted. Registers the
    /// key's scheme tag and public key. A key id already registered, revoked
    /// or not, is refused: a revoked key never returns.
    pub fn operator_add_key(&mut self, sid: &str, key: &ClientPublicKey, signature: &str) -> Result<()> {
        let public_hex = hex::encode(&key.material);
        self.operator_checked(sid, signature, |b, seq, head| {
            add_key_message(b, sid, &key.key_id, &key.scheme, &public_hex, seq, head)
        })?;
        let Some(s) = self.sessions.get(sid) else {
            return Err(BridgeError::with_reason(format!("unknown session {sid}"), "unknown_session"));
        };
        if s.cell.life == Life::Terminated {
            return Err(BridgeError::with_reason("session is TERMINATED (I6)", "terminated"));
        }
        if s.quarantined {
            // rule Q: only a TERMINATION may follow the failure event
            return Err(BridgeError::with_reason("session is QUARANTINED", "quarantined"));
        }
        if !s.key_exhausted {
            return Err(BridgeError::with_reason("session is not key_exhausted", "not_key_exhausted"));
        }
        if s.keys.contains(&key.key_id) {
            return Err(BridgeError::with_reason("client key already registered", "key_already_registered"));
        }
        self.storage.register_key(sid, &key.key_id, &key.scheme, &key.material)?;
        let committed = self.commit(
            sid,
            vec![(
                Kind::OPERATOR_ADD_KEY,
                json!({
                    "key_id": key.key_id,
                    "scheme": key.scheme,
                    "public_key": hex::encode(&key.material),
                    "signature": signature,
                }),
            )],
        );
        if let Err(e) = committed {
            self.storage.unregister_key(sid, &key.key_id)?;
            return Err(e);
        }
        Ok(())
    }

    /// OPERATOR_TERMINATION: the operator's way out of key_exhausted.
    pub fn operator_terminate(&mut self, sid: &str, reason: &str, signature: &str) -> Result<()> {
        self.operator_checked(sid, signature, |b, seq, head| terminate_message(b, sid, reason, seq, head))?;
        let Some(s) = self.sessions.get(sid) else {
            return Err(BridgeError::with_reason(format!("unknown session {sid}"), "unknown_session"));
        };
        if s.cell.life == Life::Terminated {
            return Err(BridgeError::with_reason("session is TERMINATED (I6)", "terminated"));
        }
        if !s.key_exhausted {
            return Err(BridgeError::with_reason("session is not key_exhausted", "not_key_exhausted"));
        }
        self.commit(
            sid,
            vec![
                (Kind::OPERATOR_TERMINATION, json!({"reason": reason, "signature": signature})),
                (Kind::TERMINATION, json!({"reason": reason})),
            ],
        )?;
        Ok(())
    }

    /// Keys revoked so far.
    pub fn revoked_keys(&self, sid: &str) -> Vec<String> {
        self.sessions[sid].revoked.iter().cloned().collect()
    }

    /// Every registered key is revoked and no OPERATOR_ADD_KEY followed.
    pub fn is_key_exhausted(&self, sid: &str) -> bool {
        self.sessions[sid].key_exhausted
    }

    /// Unsigned termination. A key_exhausted session is ended only by
    /// `operator_terminate`, which verifies the operator's signature; a bare
    /// terminate is refused and commits nothing (I11-REVOKE).
    pub fn terminate(&mut self, sid: &str, reason: &str) -> Result<()> {
        let Some(s) = self.sessions.get(sid) else {
            return Err(BridgeError::with_reason(format!("unknown session {sid}"), "unknown_session"));
        };
        if s.cell.life == Life::Terminated {
            return Ok(());
        }
        if s.key_exhausted && !s.quarantined {
            self.check_timers(sid)?; // an expired session is over
            if self.sessions[sid].cell.life == Life::Terminated {
                return Ok(());
            }
            return Err(BridgeError::with_reason(
                "session is KEY_EXHAUSTED: terminate needs the operator's signature",
                "key_exhausted",
            ));
        }
        self.commit(sid, vec![(Kind::TERMINATION, json!({"reason": reason}))]).map(|_| ())
    }

    /// Freeze a session whose log cannot be vouched for. The failure is
    /// recorded if the bridge can still append; otherwise the session is
    /// frozen in memory only and recovery finds it again.
    fn quarantine(&mut self, sid: &str, kind: Kind, payload: Value) {
        if self.commit(sid, vec![(kind, payload)]).is_err() {
            if let Some(s) = self.sessions.get_mut(sid) {
                s.quarantined = true;
            }
        }
    }

    pub fn is_quarantined(&self, sid: &str) -> bool {
        self.sessions[sid].quarantined
    }

    // ---- restart and recovery (Section 5.5) ---------------------------------

    /// Rebuild every session from the durable log. All transports died with
    /// the process, so each active session comes back detached with an empty
    /// client set and a fresh resume record; nonces are void. A session
    /// whose chain does not verify, or whose key registry is missing a key
    /// the log refers to, is quarantined with RECOVERY_FAILED.
    pub fn recover(
        storage: Arc<dyn Storage>,
        clock: Arc<dyn Clock>,
        verifier: Arc<dyn Verifier>,
        cfg: Config,
    ) -> Result<Bridge> {
        Bridge::recover_with(storage, clock, verifier, cfg, None)
    }

    /// Like [`Bridge::recover`], keeping the deployment's grant and
    /// operator verifier across the restart.
    pub fn recover_with(
        storage: Arc<dyn Storage>,
        clock: Arc<dyn Clock>,
        verifier: Arc<dyn Verifier>,
        cfg: Config,
        grant_verifier: Option<Arc<dyn GrantVerifier>>,
    ) -> Result<Bridge> {
        let mut b = Bridge::new(storage.clone(), clock, verifier, cfg)?;
        b.grant_verifier = grant_verifier;
        let mut ids = storage.sessions()?;
        ids.sort();
        for sid in ids {
            let log: Vec<Event> = storage.read_log(&sid)?;
            if !replayable(&log) {
                // A log that cannot be replayed freezes its own session only;
                // nothing is appended to it and the other sessions recover.
                b.sessions.insert(sid.clone(), Session::frozen());
                continue;
            }
            for ev in &log {
                b.apply(ev);
                if ev.kind == Kind::CHECKPOINT {
                    b.last_cp.insert(sid.clone(), ev.timestamp);
                }
            }
            if let Some(i) = log.iter().rposition(|e| e.kind == Kind::CHECKPOINT) {
                b.cp_len.insert(sid.clone(), i + 1);
            }
            if b.sessions[&sid].cell.life == Life::Terminated || b.sessions[&sid].quarantined {
                continue; // quarantine survives a restart
            }
            let ok = b.verify_chain(&sid).and_then(|_| b.repair_registry(&sid));
            let repaired = match ok {
                Ok(r) => r,
                Err(e) => {
                    b.quarantine(&sid, Kind::RECOVERY_FAILED, json!({"reason": e.to_string()}));
                    continue;
                }
            };
            let s = b.sessions[&sid].clone();
            let items = vec![
                (Kind::BRIDGE_RECOVERED, json!({"events": log.len(), "registry_repaired": repaired})),
                (Kind::DETACHMENT, json!({"reason": "bridge_restart"})),
                b.prepared(&s, "bridge_restart"),
            ];
            b.commit(&sid, items)?;
            b.check_timers(&sid)?;
        }
        Ok(b)
    }

    // ---- introspection --------------------------------------------------------

    /// The log is the source of truth for the key registry: drop an entry
    /// the log does not record (a crash between the registry write and the
    /// event commit leaves one), write back a missing one and replace one
    /// with other material. Returns the key ids repaired, sorted.
    fn repair_registry(&self, sid: &str) -> Result<Vec<String>> {
        let s = &self.sessions[sid];
        let mut repaired: BTreeSet<String> = BTreeSet::new();
        for k in self.storage.key_ids(sid)? {
            if !s.keys.contains(&k) {
                self.storage.unregister_key(sid, &k)?;
                repaired.insert(k);
            }
        }
        for (k, (scheme, public_hex)) in &s.key_material {
            let same = match self.storage.key_record(sid, k)? {
                Some(r) => r.scheme == *scheme && hex::encode(&r.material) == *public_hex,
                None => false,
            };
            if !same {
                let material = hex::decode(public_hex)
                    .map_err(|_| BridgeError::new(format!("log holds malformed key material for {k}")))?;
                self.storage.unregister_key(sid, k)?;
                self.storage.register_key(sid, k, scheme, &material)?;
                repaired.insert(k.clone());
            }
        }
        Ok(repaired.into_iter().collect())
    }

    fn verify_chain(&self, sid: &str) -> Result<()> {
        self.chain_hashes(sid).map(|_| ())
    }

    pub fn events(&self, sid: &str) -> Vec<Event> {
        self.storage.read_log(sid).unwrap_or_default()
    }

    pub fn cell_of(&self, sid: &str) -> Cell {
        self.sessions[sid].cell
    }

    pub fn client_set(&self, sid: &str) -> Vec<String> {
        self.sessions[sid].conn.iter().cloned().collect()
    }

    pub fn registered_keys(&self, sid: &str) -> Vec<String> {
        self.sessions[sid].keys.iter().cloned().collect()
    }

    /// The RESUME_PREPARED event of the current detachment, if any.
    pub fn resume_record(&self, sid: &str) -> Option<Event> {
        self.sessions[sid].record.clone()
    }

    pub fn scope_version(&self, sid: &str) -> u64 {
        self.sessions[sid].scope_version
    }

    pub fn scope_of(&self, sid: &str) -> Vec<String> {
        self.sessions[sid].scope.clone()
    }

    pub fn queue_keys(&self, sid: &str) -> Vec<String> {
        self.sessions[sid].queue.iter().map(|c| c.key.clone()).collect()
    }
}
