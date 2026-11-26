use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::wire::canonical_bytes;

#[derive(Debug, Clone, PartialEq, Eq)]
/// A refusal: the message, and the typed wire reason set at the raise site
/// (`"refused"` when the refusal names nothing). The wire server reads the
/// reason, never the message.
pub struct BridgeError(pub String, pub &'static str);

impl BridgeError {
    /// A refusal that names nothing on the wire (reason `refused`).
    pub fn new(msg: impl Into<String>) -> Self {
        BridgeError(msg.into(), "refused")
    }

    /// A refusal with its typed wire reason.
    pub fn with_reason(msg: impl Into<String>, reason: &'static str) -> Self {
        BridgeError(msg.into(), reason)
    }
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for BridgeError {}

pub type Result<T> = std::result::Result<T, BridgeError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attachment {
    Att,
    Det,
    Res,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Human {
    None,
    Pend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Life {
    Active,
    Terminated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cell {
    pub att: Attachment,
    pub human: Human,
    pub life: Life,
}

impl Cell {
    /// The names used by the test vectors: `["Att","None"]` or `["Terminated"]`.
    pub fn names(&self) -> Vec<&'static str> {
        if self.life == Life::Terminated {
            return vec!["Terminated"];
        }
        vec![
            match self.att {
                Attachment::Att => "Att",
                Attachment::Det => "Det",
                Attachment::Res => "Res",
            },
            match self.human {
                Human::None => "None",
                Human::Pend => "Pend",
            },
        ]
    }
}

macro_rules! kinds {
    ($($v:ident),+ $(,)?) => {
        #[allow(non_camel_case_types)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Kind { $($v),+ }
        impl Kind {
            pub fn as_str(&self) -> &'static str {
                match self { $(Kind::$v => stringify!($v)),+ }
            }
            pub fn parse(s: &str) -> Option<Kind> {
                match s { $(stringify!($v) => Some(Kind::$v),)+ _ => None }
            }
        }
    };
}

kinds!(
    ATTACHED, CLIENT_JOINED, CLIENT_LEFT, CLIENT_ADDED, DETACHMENT, RESUME_PREPARED,
    RESUME_STARTED, RESUME_REJECTED, RESUME_VERIFIED, RESUME_FAILED, HUMAN_PENDING,
    HUMAN_RESOLVED, HUMAN_TIMEOUT, DETACH_TIMEOUT, AUTHORITY_EXTENSION_REJECTED,
    AUTHORITY_NARROWED, AUTHORITY_NARROWING_REJECTED, TERMINATION, TOOL_CALL_QUEUED,
    TOOL_CALL_ANSWERED, TOOL_CALL_DRAINED, TOOL_CALL_REJECTED, TOOL_CALL_EXPIRED,
    TOOL_CALL_DELIVERED, TOOL_CALL_COMPLETED, BRIDGE_RECOVERED, RECOVERY_FAILED,
    KEY_REVOKED, KEY_REVOCATION_REQUESTED, OPERATOR_ADD_KEY, OPERATOR_TERMINATION, CHECKPOINT,
);

/// A governance event, hash-chained to its predecessor (I5).
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub kind: Kind,
    pub session_id: String,
    pub sequence: u64,
    pub prev_hash: String,
    pub payload: Value,
    pub timestamp: f64,
}

impl Event {
    /// Canonical JSON: sorted keys, no whitespace (serde_json maps are ordered).
    pub fn canonical(&self) -> Vec<u8> {
        let v = json!({
            "kind": self.kind.as_str(),
            "session_id": self.session_id,
            "sequence": self.sequence,
            "prev_hash": self.prev_hash,
            "payload": self.payload,
            "timestamp": self.timestamp,
        });
        canonical_bytes(&v)
    }

    pub fn hash(&self) -> String {
        hex::encode(Sha256::digest(self.canonical()))
    }

    pub fn str_field(&self, name: &str) -> Option<&str> {
        self.payload.get(name).and_then(Value::as_str)
    }
}

#[derive(Debug, Clone)]
pub struct SessionIdentity {
    pub session_id: String,
    pub principal_id: String,
    pub authority_scope: Vec<String>,
    pub task_lineage: Vec<String>,
}

/// A fresh single-use nonce (I11b).
#[derive(Debug, Clone, PartialEq)]
pub struct Challenge {
    pub nonce: String,
    pub ttl_seconds: f64,
}

/// A re-attach or join request (I4, I11): the last event the client
/// acknowledged, a bridge nonce, and a signature over all of them.
#[derive(Debug, Clone, PartialEq)]
pub struct ResumeRequest {
    pub key_id: String,
    pub nonce: String,
    pub seq: i64,
    pub hash: String,
    pub signature: String,
}

/// The operation a resume proof is for. A re-attach and a join sign different
/// bytes, so one signature is never valid as the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeOp {
    Reattach,
    Join,
}

impl ResumeOp {
    /// The domain tag the proof binds.
    pub fn tag(self) -> &'static str {
        match self {
            ResumeOp::Reattach => "bc/v1/reattach",
            ResumeOp::Join => "bc/v1/join",
        }
    }
}

/// The message a client signs to re-attach or join: canonical JSON of
/// `[tag, sid, key_id, nonce, seq, hash]`, the tag naming the operation.
pub fn resume_message(op: ResumeOp, sid: &str, key_id: &str, nonce: &str, seq: i64, hash: &str) -> Vec<u8> {
    canonical_bytes(&json!([op.tag(), sid, key_id, nonce, seq, hash]))
}

/// Domain tag of the add_client authorisation.
pub const ADD_CLIENT_DOMAIN: &str = "bc/v1/add-client";

/// What a connected client signs to authorise a further key: canonical JSON
/// of `[tag, sid, via_key_id, new_key_id, scheme, public_key_hex, nonce]`.
pub fn add_client_message(sid: &str, via_key_id: &str, new_key_id: &str, scheme: &str, public_key_hex: &str, nonce: &str) -> Vec<u8> {
    canonical_bytes(&json!([ADD_CLIENT_DOMAIN, sid, via_key_id, new_key_id, scheme, public_key_hex, nonce]))
}

/// Scheme tag of the reference proof-of-possession scheme.
pub const SCHEME_ED25519: &str = "ed25519";
/// Scheme tag of ECDSA over P-256 with SHA-256 (the WebCrypto scheme): the
/// registered key is the 65-byte SEC1 uncompressed point, the signature the
/// 64-byte `r || s` (IEEE P1363) hex-encoded.
pub const SCHEME_ECDSA_P256: &str = "ecdsa-p256";

#[derive(Clone)]
enum KeySigner {
    Ed25519(SigningKey),
    P256(P256SigningKey),
}

/// What a server may hold of a client key: its id, scheme tag and public key.
/// It has no signing material, and [`crate::Bridge::attach`] accepts nothing
/// else, so a server never holds a client's signing key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientPublicKey {
    pub key_id: String,
    pub scheme: String,
    pub material: Vec<u8>,
}

/// Client key (I11): a signing key held by the client, with its scheme tag.
/// The bridge's registry receives only [`ClientKey::public`].
#[derive(Clone)]
pub struct ClientKey {
    pub key_id: String,
    signer: KeySigner,
}

impl fmt::Debug for ClientKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClientKey({})", self.key_id)
    }
}

impl ClientKey {
    /// An Ed25519 key from a 32-byte seed.
    pub fn new(key_id: &str, seed: &[u8; 32]) -> Self {
        ClientKey { key_id: key_id.to_string(), signer: KeySigner::Ed25519(SigningKey::from_bytes(seed)) }
    }

    /// An ECDSA P-256 key. The scalar is `1 + seed mod (n - 1)`, so every
    /// seed yields a valid key.
    pub fn new_p256(key_id: &str, seed: &[u8; 32]) -> Self {
        // n - 1 of the P-256 group order, big-endian
        const N_MINUS_1: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x50,
        ];
        let mut d = *seed;
        // seed < 2^256 < 2 (n - 1), so one conditional subtraction reduces it
        if d >= N_MINUS_1 {
            let mut borrow = 0i16;
            for i in (0..32).rev() {
                let v = d[i] as i16 - N_MINUS_1[i] as i16 - borrow;
                borrow = if v < 0 { 1 } else { 0 };
                d[i] = (if v < 0 { v + 256 } else { v }) as u8;
            }
        }
        for i in (0..32).rev() {
            let (v, carry) = d[i].overflowing_add(1);
            d[i] = v;
            if !carry {
                break;
            }
        }
        let sk = P256SigningKey::from_slice(&d).expect("scalar in range");
        ClientKey { key_id: key_id.to_string(), signer: KeySigner::P256(sk) }
    }

    /// The scheme tag the registry records with the key.
    pub fn scheme(&self) -> &'static str {
        match self.signer {
            KeySigner::Ed25519(_) => SCHEME_ED25519,
            KeySigner::P256(_) => SCHEME_ECDSA_P256,
        }
    }

    /// The verification key to register: raw 32 bytes (Ed25519) or the
    /// 65-byte SEC1 uncompressed point (P-256); no signing material.
    pub fn public_key(&self) -> Vec<u8> {
        match &self.signer {
            KeySigner::Ed25519(k) => k.verifying_key().to_bytes().to_vec(),
            KeySigner::P256(k) => k.verifying_key().to_encoded_point(false).as_bytes().to_vec(),
        }
    }

    /// The part of this key a server receives and registers.
    pub fn public(&self) -> ClientPublicKey {
        ClientPublicKey { key_id: self.key_id.clone(), scheme: self.scheme().to_string(), material: self.public_key() }
    }

    /// Sign arbitrary bytes under this key (hex).
    pub fn sign_bytes(&self, message: &[u8]) -> String {
        match &self.signer {
            KeySigner::Ed25519(k) => hex::encode(k.sign(message).to_bytes()),
            KeySigner::P256(k) => {
                let sig: P256Signature = k.sign(message);
                hex::encode(sig.to_bytes())
            }
        }
    }

    /// Proof of possession at attach: this key's signature over the attach
    /// tuple (bridge, session, identity, scope, lineage, key).
    pub fn prove_attach(&self, identity: &SessionIdentity, bridge_id: &str) -> String {
        self.sign_bytes(&attach_message(bridge_id, identity, &self.public()))
    }

    /// An add_client authorisation for `new`, signed by this (connected) key.
    pub fn sign_add_client(&self, sid: &str, new: &ClientPublicKey, nonce: &str) -> String {
        self.sign_bytes(&add_client_message(sid, &self.key_id, &new.key_id, &new.scheme, &hex::encode(&new.material), nonce))
    }

    /// A proof for `op`, signed by this key under its own key id.
    pub fn sign_for(&self, op: ResumeOp, sid: &str, nonce: &str, seq: i64, hash: &str) -> String {
        self.sign_bytes(&resume_message(op, sid, &self.key_id, nonce, seq, hash))
    }

    /// A re-attach proof.
    pub fn sign(&self, sid: &str, nonce: &str, seq: i64, hash: &str) -> String {
        self.sign_for(ResumeOp::Reattach, sid, nonce, seq, hash)
    }

    pub fn request_for(&self, op: ResumeOp, sid: &str, nonce: &str, seq: i64, hash: &str) -> ResumeRequest {
        ResumeRequest {
            key_id: self.key_id.clone(),
            nonce: nonce.to_string(),
            seq,
            hash: hash.to_string(),
            signature: self.sign_for(op, sid, nonce, seq, hash),
        }
    }

    /// A re-attach request.
    pub fn request(&self, sid: &str, nonce: &str, seq: i64, hash: &str) -> ResumeRequest {
        self.request_for(ResumeOp::Reattach, sid, nonce, seq, hash)
    }
}

/// Proof-of-possession check (I11c). `scheme` is the tag the registry
/// recorded with the key; `key_material` is the key's public key. A verifier
/// returns false for a scheme it does not implement.
pub trait Verifier: Send + Sync {
    fn verify(&self, scheme: &str, key_material: &[u8], message: &[u8], signature: &str) -> bool;
}

/// Ed25519 verification of a hex-encoded signature; malformed key material
/// or signatures are simply invalid.
#[derive(Debug, Default, Clone, Copy)]
pub struct Ed25519Verifier;

impl Verifier for Ed25519Verifier {
    fn verify(&self, scheme: &str, key_material: &[u8], message: &[u8], signature: &str) -> bool {
        if scheme != SCHEME_ED25519 {
            return false;
        }
        let Ok(pk) = <[u8; 32]>::try_from(key_material) else { return false };
        let Ok(vk) = VerifyingKey::from_bytes(&pk) else { return false };
        let Ok(raw) = hex::decode(signature) else { return false };
        let Ok(sig) = Signature::from_slice(&raw) else { return false };
        vk.verify(message, &sig).is_ok()
    }
}

/// ECDSA P-256 / SHA-256 verification: key material is a 65-byte SEC1
/// uncompressed point, the signature is 64-byte `r || s` in hex. Malformed
/// input is simply invalid.
#[derive(Debug, Default, Clone, Copy)]
pub struct EcdsaP256Verifier;

impl Verifier for EcdsaP256Verifier {
    fn verify(&self, scheme: &str, key_material: &[u8], message: &[u8], signature: &str) -> bool {
        if scheme != SCHEME_ECDSA_P256 || key_material.len() != 65 {
            return false;
        }
        let Ok(vk) = P256VerifyingKey::from_sec1_bytes(key_material) else { return false };
        let Ok(raw) = hex::decode(signature) else { return false };
        let Ok(sig) = P256Signature::from_slice(&raw) else { return false };
        // WebCrypto does not normalise s; accept either form of a valid pair.
        let sig = sig.normalize_s().unwrap_or(sig);
        vk.verify(message, &sig).is_ok()
    }
}

/// Dispatches on the scheme tag to the reference verifiers: Ed25519 and
/// ECDSA P-256. An unknown tag is invalid.
#[derive(Debug, Default, Clone, Copy)]
pub struct SchemeVerifier;

impl Verifier for SchemeVerifier {
    fn verify(&self, scheme: &str, key_material: &[u8], message: &[u8], signature: &str) -> bool {
        match scheme {
            SCHEME_ED25519 => Ed25519Verifier.verify(scheme, key_material, message, signature),
            SCHEME_ECDSA_P256 => EcdsaP256Verifier.verify(scheme, key_material, message, signature),
            _ => false,
        }
    }
}

/// Domain tag of a scope grant; it separates a grant from every other
/// signed tuple.
pub const GRANT_DOMAIN: &str = "bc/v1/grant";

/// Domain tag of the attach proof of possession.
pub const ATTACH_DOMAIN: &str = "bc/v1/attach";

/// The identity a grant and an attach proof are bound to by default.
pub const DEFAULT_BRIDGE_ID: &str = "bridge-1";

fn attach_fields(bridge_id: &str, identity: &SessionIdentity, key: &ClientPublicKey) -> Vec<Value> {
    vec![
        json!(bridge_id),
        json!(identity.session_id),
        json!(identity.principal_id),
        json!(identity.authority_scope),
        json!(identity.task_lineage),
        json!(key.key_id),
        json!(key.scheme),
        json!(hex::encode(&key.material)),
    ]
}

/// What a scope grant binds: canonical JSON of
/// `[GRANT_DOMAIN, bridge_id, sid, principal, scope, lineage, key_id,
/// scheme, public_key_hex]`.
pub fn grant_message(bridge_id: &str, identity: &SessionIdentity, key: &ClientPublicKey) -> Vec<u8> {
    let mut v = vec![json!(GRANT_DOMAIN)];
    v.extend(attach_fields(bridge_id, identity, key));
    canonical_bytes(&Value::Array(v))
}

/// What the attaching key signs to show it holds the private key: the same
/// fields as the grant under [`ATTACH_DOMAIN`].
pub fn attach_message(bridge_id: &str, identity: &SessionIdentity, key: &ClientPublicKey) -> Vec<u8> {
    let mut v = vec![json!(ATTACH_DOMAIN)];
    v.extend(attach_fields(bridge_id, identity, key));
    canonical_bytes(&Value::Array(v))
}

/// Domain tags of the operator events; each separates its signature from
/// every other signed tuple.
pub const REVOKE_DOMAIN: &str = "bc/v1/revoke";
pub const ADD_KEY_DOMAIN: &str = "bc/v1/add-key";
pub const TERMINATE_DOMAIN: &str = "bc/v1/terminate";

/// What an operator revocation binds:
/// `[REVOKE_DOMAIN, bridge_id, sid, key_id, reason, seq, head]`, where
/// `seq` and `head` are the sequence and hash of the last event at signing.
pub fn revoke_message(bridge_id: &str, sid: &str, key_id: &str, reason: &str, seq: u64, head: &str) -> Vec<u8> {
    canonical_bytes(&json!([REVOKE_DOMAIN, bridge_id, sid, key_id, reason, seq, head]))
}

/// What an operator key addition binds:
/// `[ADD_KEY_DOMAIN, bridge_id, sid, key_id, scheme, public_key_hex, seq, head]`.
pub fn add_key_message(
    bridge_id: &str,
    sid: &str,
    key_id: &str,
    scheme: &str,
    public_key_hex: &str,
    seq: u64,
    head: &str,
) -> Vec<u8> {
    canonical_bytes(&json!([ADD_KEY_DOMAIN, bridge_id, sid, key_id, scheme, public_key_hex, seq, head]))
}

/// What an operator termination binds:
/// `[TERMINATE_DOMAIN, bridge_id, sid, reason, seq, head]`.
pub fn terminate_message(bridge_id: &str, sid: &str, reason: &str, seq: u64, head: &str) -> Vec<u8> {
    canonical_bytes(&json!([TERMINATE_DOMAIN, bridge_id, sid, reason, seq, head]))
}

/// Authorisation boundary: the deployment's check that the identity and the
/// key presented at attach carry a scope grant from a trusted authority
/// outside the contract. The grant is opaque to the bridge. The same
/// authority authenticates the operator events: `verify_operation` checks
/// the operator's signature over the bytes of one operation; the default
/// refuses, so a verifier that does not implement it closes those paths.
pub trait GrantVerifier: Send + Sync {
    fn verify(&self, bridge_id: &str, identity: &SessionIdentity, key: &ClientPublicKey, grant: Option<&str>) -> bool;

    fn verify_operation(&self, _message: &[u8], _signature: Option<&str>) -> bool {
        false
    }
}

/// A trusted authority that signs scope grants (a test double for the
/// deployment's grant authority).
#[derive(Clone)]
pub struct OperatorKey {
    signing: SigningKey,
}

impl OperatorKey {
    pub fn new(seed: &[u8; 32]) -> Self {
        OperatorKey { signing: SigningKey::from_bytes(seed) }
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.signing.verifying_key().to_bytes().to_vec()
    }

    pub fn grant(&self, identity: &SessionIdentity, key: &ClientPublicKey, bridge_id: &str) -> String {
        hex::encode(self.signing.sign(&grant_message(bridge_id, identity, key)).to_bytes())
    }

    pub fn revoke(&self, bridge_id: &str, sid: &str, key_id: &str, reason: &str, seq: u64, head: &str) -> String {
        hex::encode(self.signing.sign(&revoke_message(bridge_id, sid, key_id, reason, seq, head)).to_bytes())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_key(
        &self,
        bridge_id: &str,
        sid: &str,
        key_id: &str,
        scheme: &str,
        public_key_hex: &str,
        seq: u64,
        head: &str,
    ) -> String {
        hex::encode(
            self.signing
                .sign(&add_key_message(bridge_id, sid, key_id, scheme, public_key_hex, seq, head))
                .to_bytes(),
        )
    }

    pub fn terminate(&self, bridge_id: &str, sid: &str, reason: &str, seq: u64, head: &str) -> String {
        hex::encode(self.signing.sign(&terminate_message(bridge_id, sid, reason, seq, head)).to_bytes())
    }
}

/// Reference grant verifier: the grant is the operator's hex Ed25519
/// signature over [`grant_message`].
#[derive(Debug, Clone)]
pub struct OperatorGrantVerifier {
    operator_public_key: Vec<u8>,
}

impl OperatorGrantVerifier {
    pub fn new(operator_public_key: Vec<u8>) -> Self {
        OperatorGrantVerifier { operator_public_key }
    }
}

impl GrantVerifier for OperatorGrantVerifier {
    fn verify(&self, bridge_id: &str, identity: &SessionIdentity, key: &ClientPublicKey, grant: Option<&str>) -> bool {
        match grant {
            Some(g) => Ed25519Verifier.verify(SCHEME_ED25519, &self.operator_public_key, &grant_message(bridge_id, identity, key), g),
            None => false,
        }
    }

    fn verify_operation(&self, message: &[u8], signature: Option<&str>) -> bool {
        match signature {
            Some(s) => Ed25519Verifier.verify(SCHEME_ED25519, &self.operator_public_key, message, s),
            None => false,
        }
    }
}

/// Timers in seconds. `T_call <= T_human` and `T_detach <= T_total` are MUSTs
/// (`T_human <= T_detach` is the default, not a requirement); a timer is a
/// non-negative number or infinity, never NaN. Construct through
/// [`Config::new`] or a profile so the bounds are checked, and
/// [`crate::Bridge::new`] re-checks them.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub t_detach: f64,
    pub t_human: f64,
    pub t_call: f64,
    /// Cumulative time a session may spend detached, over all episodes.
    pub t_total: f64,
    pub t_approve: f64,
    pub t_nonce: f64,
    pub q_max: usize,
    /// I-CHECKPOINT: emit a checkpoint every N events (default 1000).
    pub n_checkpoint: usize,
    /// I-CHECKPOINT: emit a checkpoint every T_cp seconds (default 300).
    pub t_checkpoint: f64,
    /// What a call that arrives with no escalation pending while no client
    /// is attached gets (G1); see [`DetachedCalls`].
    pub detached_calls: DetachedCalls,
    /// Permissions that [`DetachedCalls::Forward`] may run without the client.
    pub detached_allow: std::collections::BTreeSet<String>,
}

/// The deployment's choice for a tool call with no escalation pending while
/// no client is attached (G1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DetachedCalls {
    /// Refuse the call (default).
    #[default]
    Refuse,
    /// Queue it as a held call: it waits for an answer after re-attach.
    Queue,
    /// Forward it at once if its permission is allowlisted and in scope.
    Forward,
}

impl Config {
    /// `t_human` defaults to `t_detach`, `t_call` to `t_human` and `t_total`
    /// to four times `t_detach`. `t_human` may exceed `t_detach`: while the
    /// client is away the detach timer ends the session first.
    pub fn new(
        t_detach: f64,
        t_human: Option<f64>,
        t_call: Option<f64>,
        t_total: Option<f64>,
        t_approve: f64,
        t_nonce: f64,
        q_max: usize,
    ) -> Result<Config> {
        let human = t_human.unwrap_or(t_detach);
        let c = Config {
            t_detach,
            t_human: human,
            t_call: t_call.unwrap_or(human),
            t_total: t_total.unwrap_or(4.0 * t_detach),
            t_approve,
            t_nonce,
            q_max,
            n_checkpoint: 1000,
            t_checkpoint: 300.0,
            detached_calls: DetachedCalls::Refuse,
            detached_allow: Default::default(),
        };
        c.validate()?;
        Ok(c)
    }

    /// Choose the detached-call policy and, for `Forward`, the allowlist.
    pub fn with_detached_calls(mut self, policy: DetachedCalls, allow: impl IntoIterator<Item = String>) -> Config {
        self.detached_calls = policy;
        self.detached_allow = allow.into_iter().collect();
        self
    }

    pub fn validate(&self) -> Result<()> {
        // NaN would make every comparison false (a nonce that never expires),
        // an infinity is a timer that never fires and has no canonical form in
        // a log, a negative value an already-expired one.
        let timers = [
            ("t_detach", self.t_detach),
            ("t_human", self.t_human),
            ("t_call", self.t_call),
            ("t_total", self.t_total),
            ("t_approve", self.t_approve),
            ("t_nonce", self.t_nonce),
            ("t_checkpoint", self.t_checkpoint),
        ];
        for (name, value) in timers {
            if !value.is_finite() || value < 0.0 {
                return Err(BridgeError::new(format!("timer {name} must be a finite non-negative number")));
            }
        }
        if self.t_call > self.t_human {
            Err(BridgeError::new("timer bounds: T_call <= T_human is a MUST"))
        } else if self.t_detach > self.t_total {
            Err(BridgeError::new("timer bounds: T_detach <= T_total is a MUST"))
        } else {
            Ok(())
        }
    }

    /// 30 minutes everywhere, 2 hours in all (the default profile).
    pub fn interactive_short() -> Config {
        Config {
            t_detach: 1800.0,
            t_human: 1800.0,
            t_call: 1800.0,
            t_total: 7200.0,
            t_approve: 900.0,
            t_nonce: 60.0,
            q_max: 64,
            n_checkpoint: 1000,
            t_checkpoint: 300.0,
            detached_calls: DetachedCalls::Refuse,
            detached_allow: Default::default(),
        }
    }

    /// 7 days everywhere, 28 days in all; approvals still expire after 15 minutes.
    pub fn persistent() -> Config {
        let d = 7.0 * 86_400.0;
        Config { t_detach: d, t_human: d, t_call: d, t_total: 4.0 * d, ..Config::interactive_short() }
    }
}

impl Default for Config {
    fn default() -> Self {
        Config::interactive_short()
    }
}

pub trait Clock: Send + Sync {
    fn now(&self) -> f64;
}

/// Wall clock for production use.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> f64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
    }
}

/// Manually advanced clock for deterministic tests.
#[derive(Debug, Default)]
pub struct FakeClock {
    bits: AtomicU64,
}

impl FakeClock {
    pub fn new(start: f64) -> Arc<FakeClock> {
        Arc::new(FakeClock { bits: AtomicU64::new(start.to_bits()) })
    }

    pub fn advance(&self, seconds: f64) {
        let t = f64::from_bits(self.bits.load(Ordering::SeqCst)) + seconds;
        self.bits.store(t.to_bits(), Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn now(&self) -> f64 {
        f64::from_bits(self.bits.load(Ordering::SeqCst))
    }
}

/// Durable medium (axiom A1). It outlives a bridge instance; a new
/// [`crate::Bridge`] over the same storage is a restart. All methods take
/// `&self`: an implementation synchronises internally.
pub trait Storage: Send + Sync {
    /// Atomic: all events of a transition are committed, or none (I12).
    /// Returns only once they are durable.
    fn append_batch(&self, sid: &str, events: Vec<Event>) -> Result<()>;
    /// The whole committed log of a session, in order (empty if unknown).
    fn read_log(&self, sid: &str) -> Result<Vec<Event>>;
    /// Every session that has a log.
    fn sessions(&self) -> Result<Vec<String>>;
    /// Register the scheme tag and verification material of a client key
    /// in one session (I15d). The registry is scoped to the session: a key
    /// id means a key only inside the session that registered it. A key id
    /// already registered in the session is refused, never replaced.
    fn register_key(&self, sid: &str, key_id: &str, scheme: &str, material: &[u8]) -> Result<()>;
    /// Remove a registration made for a commit that then failed.
    fn unregister_key(&self, sid: &str, key_id: &str) -> Result<()>;
    /// The scheme tag and verification material registered for a key in a session.
    fn key_record(&self, sid: &str, key_id: &str) -> Result<Option<KeyRecord>>;
    /// Every key id registered in a session.
    fn key_ids(&self, sid: &str) -> Result<Vec<String>>;
}

/// What the registry holds for a client key: its scheme tag and public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRecord {
    pub scheme: String,
    pub material: Vec<u8>,
}

/// In-memory storage: the reference implementation of [`Storage`].
#[derive(Debug, Default)]
pub struct MemStorage {
    logs: Mutex<HashMap<String, Vec<Event>>>,
    keys: Mutex<HashMap<(String, String), KeyRecord>>,
    /// Test hook: refuse the next append.
    pub fail_next: AtomicBool,
}

impl MemStorage {
    pub fn new() -> Arc<MemStorage> {
        Arc::new(MemStorage::default())
    }

    /// Test hook: edit a stored event in place.
    pub fn tamper(&self, sid: &str, index: usize, f: impl FnOnce(&mut Event)) {
        f(&mut self.logs.lock().unwrap().get_mut(sid).unwrap()[index]);
    }

    /// Test hook: forget every registered key.
    pub fn forget_keys(&self) {
        self.keys.lock().unwrap().clear();
    }

    /// Test hook: replace the registered material of a key in a session.
    pub fn tamper_key(&self, sid: &str, key_id: &str, material: &[u8]) {
        let slot = Self::slot(sid, key_id);
        self.keys.lock().unwrap().get_mut(&slot).unwrap().material = material.to_vec();
    }

    fn slot(sid: &str, key_id: &str) -> (String, String) {
        (sid.to_string(), key_id.to_string())
    }
}

impl Storage for MemStorage {
    fn append_batch(&self, sid: &str, events: Vec<Event>) -> Result<()> {
        if self.fail_next.swap(false, Ordering::SeqCst) {
            return Err(BridgeError::new("storage: append refused"));
        }
        self.logs.lock().unwrap().entry(sid.to_string()).or_default().extend(events);
        Ok(())
    }

    fn read_log(&self, sid: &str) -> Result<Vec<Event>> {
        Ok(self.logs.lock().unwrap().get(sid).cloned().unwrap_or_default())
    }

    fn sessions(&self) -> Result<Vec<String>> {
        Ok(self.logs.lock().unwrap().keys().cloned().collect())
    }

    fn register_key(&self, sid: &str, key_id: &str, scheme: &str, material: &[u8]) -> Result<()> {
        let mut keys = self.keys.lock().unwrap();
        let slot = Self::slot(sid, key_id);
        if keys.contains_key(&slot) {
            return Err(BridgeError::with_reason(
                format!("key id {key_id} already registered in the session"),
                "key_already_registered",
            ));
        }
        keys.insert(slot, KeyRecord { scheme: scheme.to_string(), material: material.to_vec() });
        Ok(())
    }

    fn unregister_key(&self, sid: &str, key_id: &str) -> Result<()> {
        self.keys.lock().unwrap().remove(&Self::slot(sid, key_id));
        Ok(())
    }

    fn key_record(&self, sid: &str, key_id: &str) -> Result<Option<KeyRecord>> {
        Ok(self.keys.lock().unwrap().get(&Self::slot(sid, key_id)).cloned())
    }

    fn key_ids(&self, sid: &str) -> Result<Vec<String>> {
        Ok(self.keys.lock().unwrap().keys().filter(|(s, _)| s == sid).map(|(_, k)| k.clone()).collect())
    }
}

pub(crate) fn canon(v: &Value) -> Vec<u8> {
    canonical_bytes(v)
}

/// h(x): SHA-256 of the canonical JSON of `x` (I14).
pub fn content_hash(v: &Value) -> String {
    hex::encode(Sha256::digest(canon(v)))
}

/// h_q of a tool call (I14): the hash of the tool, the permission and the
/// content together, so an approval of one call cannot be spent on another
/// that carries the same content under a different tool name.
pub fn call_hash(tool: &str, permission: Option<&str>, content: &Value) -> String {
    content_hash(&json!({"tool": tool, "permission": permission, "content": content}))
}

pub(crate) fn digest(nonce: &str) -> String {
    hex::encode(Sha256::digest(nonce.as_bytes()))[..16].to_string()
}

pub(crate) fn authority_hash(principal: &str, scope: &[String], lineage: &[String]) -> String {
    let mut m = Map::new();
    m.insert("principal".into(), json!(principal));
    m.insert("scope".into(), json!(scope));
    m.insert("lineage".into(), json!(lineage));
    hex::encode(Sha256::digest(canon(&Value::Object(m))))[..16].to_string()
}

/// A scope is a set of permission strings; its canonical form is the strings
/// without repetition, sorted by code point. The bridge records a scope only
/// in this form, so the authority hash does not depend on the order or the
/// repetitions a caller wrote.
pub fn canonical_scope(scope: &[String]) -> Vec<String> {
    let set: std::collections::BTreeSet<&String> = scope.iter().collect();
    set.into_iter().cloned().collect()
}
