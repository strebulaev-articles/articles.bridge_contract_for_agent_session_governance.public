//! A file-backed [`Storage`] for tests: one JSON-lines log per session, the
//! key registry in one file, `sync_all` after every append. It proves the
//! [`Storage`] trait is implementable over a real medium; it is not meant
//! for production (no locking across processes, no compaction).

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use bridge_contract::*;
use serde_json::{json, Value};

/// A directory made for one test run, removed when the guard is dropped:
/// on every exit, a panic included. The name is unique per run (process id,
/// a counter and the clock), and the directory is created, not reused, so
/// a leftover of an earlier run is never read.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(label: &str) -> TempDir {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        loop {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!("bridge-contract-{label}-{}-{n}-{nanos}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return TempDir { path },
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("cannot create a test directory: {e}"),
            }
        }
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Make the creation or the replacement of a file in `dir` durable.
fn sync_dir(dir: &std::path::Path) -> Result<()> {
    File::open(dir).map_err(io)?.sync_all().map_err(io)
}

pub struct FileStorage {
    dir: PathBuf,
    lock: Mutex<()>,
    fail_next: AtomicBool,
}

fn io(e: impl std::fmt::Display) -> BridgeError {
    BridgeError::new(format!("file storage: {e}"))
}

fn encode(ev: &Event) -> String {
    json!({
        "kind": ev.kind.as_str(), "session_id": ev.session_id, "sequence": ev.sequence,
        "prev_hash": ev.prev_hash, "payload": ev.payload, "timestamp": ev.timestamp,
    })
    .to_string()
}

fn decode(line: &str) -> Result<Event> {
    let v: Value = serde_json::from_str(line).map_err(io)?;
    Ok(Event {
        kind: Kind::parse(v["kind"].as_str().unwrap_or("")).ok_or_else(|| io("unknown event kind"))?,
        session_id: v["session_id"].as_str().unwrap_or("").to_string(),
        sequence: v["sequence"].as_u64().unwrap_or(0),
        prev_hash: v["prev_hash"].as_str().unwrap_or("").to_string(),
        payload: v["payload"].clone(),
        timestamp: v["timestamp"].as_f64().unwrap_or(0.0),
    })
}

impl FileStorage {
    pub fn new(dir: PathBuf) -> Arc<FileStorage> {
        fs::create_dir_all(dir.join("logs")).expect("storage directory");
        Arc::new(FileStorage { dir, lock: Mutex::new(()), fail_next: AtomicBool::new(false) })
    }

    fn log_path(&self, sid: &str) -> PathBuf {
        self.dir.join("logs").join(format!("{}.jsonl", hex::encode(sid)))
    }

    fn keys_path(&self) -> PathBuf {
        self.dir.join("keys.json")
    }

    /// Replace the registry atomically: write a new file, sync it, rename it
    /// over the old one and sync the directory.
    fn write_keys(&self, keys: &HashMap<String, String>) -> Result<()> {
        let tmp = self.dir.join("keys.json.tmp");
        let mut f = File::create(&tmp).map_err(io)?;
        f.write_all(serde_json::to_string(keys).map_err(io)?.as_bytes()).map_err(io)?;
        f.sync_all().map_err(io)?;
        fs::rename(&tmp, self.keys_path()).map_err(io)?;
        sync_dir(&self.dir)
    }

    /// Test hook: replace the stored material of a key in a session.
    pub fn tamper_key(&self, sid: &str, key_id: &str, material: &[u8]) {
        let _g = self.lock.lock().unwrap();
        let mut keys = self.read_keys();
        let v = keys.get_mut(&slot(sid, key_id)).unwrap();
        let scheme = v.split_once(':').unwrap().0.to_string();
        *v = format!("{scheme}:{}", hex::encode(material));
        self.write_keys(&keys).unwrap();
    }

    fn read_keys(&self) -> HashMap<String, String> {
        fs::read_to_string(self.keys_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Test hook: rewrite the stored `prev_hash` of one event.
    pub fn tamper_prev_hash(&self, sid: &str, index: usize) {
        let mut log = self.read_log(sid).unwrap();
        log[index].prev_hash = "00".repeat(32);
        let body: String = log.iter().map(|e| encode(e) + "\n").collect();
        fs::write(self.log_path(sid), body).unwrap();
    }

    pub fn fail_next(&self) {
        self.fail_next.store(true, Ordering::SeqCst);
    }
}

impl Storage for FileStorage {
    fn append_batch(&self, sid: &str, events: Vec<Event>) -> Result<()> {
        if self.fail_next.swap(false, Ordering::SeqCst) {
            return Err(io("append refused"));
        }
        let _g = self.lock.lock().unwrap();
        // one write of the whole batch, then fsync: the batch is committed
        // when `sync_all` returns
        let body: String = events.iter().map(|e| encode(e) + "\n").collect();
        let path = self.log_path(sid);
        let created = !path.exists();
        let mut f = OpenOptions::new().create(true).append(true).open(&path).map_err(io)?;
        f.write_all(body.as_bytes()).map_err(io)?;
        f.sync_all().map_err(io)?;
        if created {
            sync_dir(&self.dir.join("logs"))?; // the new file's directory entry is durable too
        }
        Ok(())
    }

    fn read_log(&self, sid: &str) -> Result<Vec<Event>> {
        let _g = self.lock.lock().unwrap();
        let Ok(text) = fs::read_to_string(self.log_path(sid)) else { return Ok(vec![]) };
        // A trailing record that is not fully durable (no newline, or a line
        // that does not decode) is discarded: by I12 it had no externally
        // visible effect. A damaged record anywhere else is an error.
        let mut lines: Vec<&str> = text.split('\n').collect();
        let tail = lines.pop().unwrap_or(""); // after the last newline: empty if the log ends cleanly
        let mut out = Vec::with_capacity(lines.len());
        for (i, l) in lines.iter().enumerate() {
            match decode(l) {
                Ok(ev) => out.push(ev),
                Err(_) if i + 1 == lines.len() && tail.is_empty() => {} // a torn record that ends in a newline
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    fn sessions(&self) -> Result<Vec<String>> {
        let mut out = vec![];
        for e in fs::read_dir(self.dir.join("logs")).map_err(io)? {
            let name = e.map_err(io)?.file_name().to_string_lossy().to_string();
            if let Some(h) = name.strip_suffix(".jsonl") {
                out.push(String::from_utf8(hex::decode(h).map_err(io)?).map_err(io)?);
            }
        }
        Ok(out)
    }

    fn register_key(&self, sid: &str, key_id: &str, scheme: &str, material: &[u8]) -> Result<()> {
        let _g = self.lock.lock().unwrap();
        let mut keys = self.read_keys();
        let slot = slot(sid, key_id);
        if keys.contains_key(&slot) {
            return Err(BridgeError::new(format!("key id {key_id} already registered in the session")));
        }
        keys.insert(slot, format!("{scheme}:{}", hex::encode(material)));
        self.write_keys(&keys)
    }

    fn unregister_key(&self, sid: &str, key_id: &str) -> Result<()> {
        let _g = self.lock.lock().unwrap();
        let mut keys = self.read_keys();
        keys.remove(&slot(sid, key_id));
        self.write_keys(&keys)
    }

    fn key_record(&self, sid: &str, key_id: &str) -> Result<Option<KeyRecord>> {
        let _g = self.lock.lock().unwrap();
        Ok(self.read_keys().get(&slot(sid, key_id)).and_then(|v| {
            let (scheme, h) = v.split_once(':')?;
            Some(KeyRecord { scheme: scheme.to_string(), material: hex::decode(h).ok()? })
        }))
    }

    fn key_ids(&self, sid: &str) -> Result<Vec<String>> {
        let _g = self.lock.lock().unwrap();
        Ok(self
            .read_keys()
            .keys()
            .filter_map(|k| {
                let (s, id): (String, String) = serde_json::from_str(k).ok()?;
                (s == sid).then_some(id)
            })
            .collect())
    }
}

/// The file registry's map key: a key id means a key only in its session.
fn slot(sid: &str, key_id: &str) -> String {
    serde_json::to_string(&[sid, key_id]).unwrap()
}

/// Attach with the test operator's grant for `key` and the key's proof of
/// possession.
#[allow(dead_code)]
pub fn attach_ok(bridge: &mut Bridge, id: &SessionIdentity, key: &ClientKey) -> Result<()> {
    let operator = OperatorKey::new(&[7u8; 32]);
    let grant = operator.grant(id, &key.public(), DEFAULT_BRIDGE_ID);
    bridge.attach(id, &key.public(), Some(&grant), Some(&key.prove_attach(id, DEFAULT_BRIDGE_ID)))
}
