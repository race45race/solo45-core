//! One Stratum V1 connection (a miner). Mirrors the Worker class in Solo45's pool.py: the same methods, the same
//! share checks in the same order with the same error codes, the same vardiff, remembered difficulties and
//! per-miner overrides.

use crate::job::{Job, EN2_SIZE};
use crate::log;
use crate::pool::{Ctl, Payout, Pool, WorkerHandle, WorkerInfo, AUTH_WINDOW_S, MAX_AUTHORIZE, MAX_DIFF, VERSION_MASK};
use crate::util::{fmt_diff, g3, hash_diff, hash_meets, now_f, sha256d, sig3};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc;

const MAX_LINE: u64 = 64 * 1024;

pub struct StratumError {
    pub code: i64,
    pub msg: &'static str,
}

fn err(code: i64, msg: &'static str) -> StratumError {
    StratumError { code, msg }
}

/// What a job went out to this miner with: its difficulty and the payout its coinbase carries. A share is checked
/// against these, not against the miner's current ones: after a payout address change the miner is still hashing
/// the older job's coinbase until the new job reaches it, and such a share (or a block) must still count. A block
/// found on the older job pays the address that job carried, as on Stratum V2.
struct Sent {
    diff: f64,
    spk: Vec<u8>,
    address: String,
}

struct Worker {
    pool: Arc<Pool>,
    id: u64,
    info: Arc<Mutex<WorkerInfo>>,
    ctl_tx: mpsc::UnboundedSender<Ctl>,
    ip: String,
    en1: [u8; 4],
    diff: f64,
    remembered: bool,
    switches_at_once: bool,
    vd_pending: Option<(i32, f64)>,
    job_sent: HashMap<String, Sent>,
    authorized: bool,
    auth_tries: u32,
    name: String,
    agent: String,
    connected: f64,
    vd_start: f64,
    vd_count: u32,
    vd_work: f64,
    w: OwnedWriteHalf,
}

/// What to send after the reply to a request.
enum After {
    None,
    Difficulty,
    FirstJob,
}

pub async fn serve(pool: Arc<Pool>, stream: TcpStream, peer: SocketAddr) {
    let _ = stream.set_nodelay(true);
    let (r, w) = stream.into_split();
    let mut reader = BufReader::new(r);
    let (ctl_tx, mut ctl_rx) = mpsc::unbounded_channel();
    let ip = peer.ip().to_string();
    let now = now_f();
    let mut wk = Worker {
        id: pool.next_worker_id(),
        info: Arc::new(Mutex::new(WorkerInfo::new(&ip, now))),
        ctl_tx,
        en1: pool.next_en1(),
        diff: pool.cfg.start_diff,
        pool: pool.clone(),
        ip,
        remembered: false,
        switches_at_once: false,
        vd_pending: None,
        job_sent: HashMap::new(),
        authorized: false,
        auth_tries: 0,
        name: String::new(),
        agent: String::new(),
        connected: now,
        vd_start: now,
        vd_count: 0,
        vd_work: 0.0,
        w,
    };
    let mut jobs = pool.job_tx.subscribe();
    let mut tick = tokio::time::interval(Duration::from_secs(15));
    let mut junk = 0u32;
    let mut line = Vec::with_capacity(1024);
    loop {
        // 15 minutes of silence ends a miner's connection; one that never authorizes gets 2 minutes
        let wait = if wk.authorized { 900.0 } else { (wk.connected + AUTH_WINDOW_S - now_f()).max(0.1) };
        // read_until keeps partly read bytes in `line` when another branch wins, so `line` is cleared only after a
        // whole line has been handled, and the limit counts what is already there
        let mut limited = (&mut reader).take(MAX_LINE + 1 - (line.len() as u64).min(MAX_LINE));
        tokio::select! {
            r = tokio::time::timeout(Duration::from_secs_f64(wait), limited.read_until(b'\n', &mut line)) => {
                match r {
                    Err(_) | Ok(Err(_)) | Ok(Ok(0)) => break,
                    Ok(Ok(_)) => {}
                }
                if line.last() != Some(&b'\n') {
                    if line.len() as u64 > MAX_LINE {
                        log!("WARNING", "disconnected {} {}: it sent a line over 64 KB", wk.ip, wk.name);
                    }
                    break;
                }
                let parsed = serde_json::from_slice::<Value>(&line);
                line.clear();
                match parsed {
                    Ok(msg) if msg.is_object() => {
                        if wk.handle(&msg).await.is_err() {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(_) => {
                        junk += 1;
                        if junk >= 20 && !wk.authorized {
                            log!("WARNING", "disconnected {}: it sent {} lines that aren't Stratum", wk.ip, junk);
                            break;
                        }
                    }
                }
            }
            j = jobs.recv(), if wk.authorized => {
                let nj = match j {
                    Ok(nj) => Some((nj.job, nj.clean)),
                    Err(RecvError::Lagged(_)) => pool.current().map(|job| (job, true)),
                    Err(RecvError::Closed) => break,
                };
                if let Some((job, clean)) = nj {
                    if wk.send_job(&job, clean).await.is_err() {
                        break;
                    }
                }
            }
            Some(c) = ctl_rx.recv() => {
                match c {
                    Ctl::SetDiff(d) => {
                        wk.set_diff(d);
                        if wk.send_difficulty().await.is_err() {
                            break;
                        }
                    }
                }
            }
            _ = tick.tick() => {
                let old = wk.diff;
                if let Some(new) = wk.vardiff(now_f()) {
                    log!("INFO", "{} difficulty {} -> {} (1 share / {} s)", wk.name, fmt_diff(old), fmt_diff(new), g3(wk.share_seconds()));
                    if wk.send_difficulty().await.is_err() {
                        break;
                    }
                }
            }
        }
    }
    pool.workers.lock().unwrap().remove(&wk.id);
    pool.conn_close(peer.ip());
    log!("INFO", "disconnected {} {}", wk.ip, wk.name);
}

impl Worker {
    async fn send(&mut self, v: &Value) -> std::io::Result<()> {
        let mut s = v.to_string();
        s.push('\n');
        tokio::time::timeout(Duration::from_secs(10), self.w.write_all(s.as_bytes()))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "send timeout"))?
    }

    async fn send_difficulty(&mut self) -> std::io::Result<()> {
        let d = self.diff;
        self.send(&json!({"id": null, "method": "mining.set_difficulty", "params": [d]})).await
    }

    /// The (script, address) this miner pays right now.
    fn payout(&self) -> (Vec<u8>, String) {
        let i = self.info.lock().unwrap();
        (i.spk.clone(), i.address.clone())
    }

    async fn send_job(&mut self, job: &Arc<Job>, clean: bool) -> std::io::Result<()> {
        let (spk, address) = self.payout();
        let params = job.notify_params(&spk, clean);
        self.job_sent.insert(job.id.clone(), Sent { diff: self.diff, spk, address });
        let pool = self.pool.clone();
        self.job_sent.retain(|id, _| pool.job(id).is_some());
        self.send(&json!({"id": null, "method": "mining.notify", "params": params})).await
    }

    async fn handle(&mut self, msg: &Value) -> std::io::Result<()> {
        let id = msg.get("id").cloned().unwrap_or(Value::Null);
        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("").to_string();
        let params = msg.get("params").cloned().unwrap_or(json!([]));
        let params = if params.is_array() { params } else { json!([]) };
        let (reply, after) = match self.dispatch(&method, &params).await {
            Ok((result, after)) => (json!({"id": id, "result": result, "error": null}), after),
            Err(e) => (json!({"id": id, "result": null, "error": [e.code, e.msg, null]}), After::None),
        };
        self.send(&reply).await?;
        match after {
            After::None => Ok(()),
            After::Difficulty => self.send_difficulty().await,
            After::FirstJob => {
                self.send_difficulty().await?;
                if let Some(job) = self.pool.current() {
                    self.send_job(&job, true).await?;
                }
                Ok(())
            }
        }
    }

    async fn dispatch(&mut self, method: &str, p: &Value) -> Result<(Value, After), StratumError> {
        let bad = || err(20, "Bad request");
        match method {
            "mining.subscribe" => {
                self.agent = p.get(0).and_then(|a| a.as_str()).unwrap_or("").chars().take(60).collect();
                self.info.lock().unwrap().agent = self.agent.clone();
                let sid = hex::encode(self.en1);
                Ok((json!([[["mining.set_difficulty", sid], ["mining.notify", sid]], sid, EN2_SIZE]), After::None))
            }
            "mining.configure" => {
                let exts = p.get(0).and_then(|e| e.as_array()).cloned().unwrap_or_default();
                let opts = p.get(1).cloned().unwrap_or(json!({}));
                let mut result = serde_json::Map::new();
                for ext in exts {
                    let ext = ext.as_str().unwrap_or("").to_string();
                    if ext == "version-rolling" {
                        let asked = opts.get("version-rolling.mask").and_then(|m| m.as_str()).unwrap_or("ffffffff");
                        let asked = u32::from_str_radix(asked, 16).map_err(|_| bad())?;
                        result.insert("version-rolling".into(), json!(true));
                        result.insert("version-rolling.mask".into(), json!(format!("{:08x}", VERSION_MASK & asked)));
                    } else {
                        result.insert(ext, json!(false));
                    }
                }
                Ok((Value::Object(result), After::None))
            }
            "mining.authorize" => self.authorize(p).await,
            "mining.suggest_difficulty" => {
                let d = p.get(0).and_then(|d| d.as_f64()).ok_or_else(bad)?;
                // a fixed difficulty set by the user wins, and so does the difficulty remembered for this miner
                if self.override_diff().is_none() && !self.remembered {
                    self.set_diff(d);
                }
                Ok((json!(true), if self.authorized { After::Difficulty } else { After::None }))
            }
            "mining.submit" => Ok((json!(self.submit(p).await?), After::None)),
            "mining.extranonce.subscribe" => Ok((json!(true), After::None)),
            "mining.get_transactions" => Ok((json!([]), After::None)),
            _ => Err(err(20, "Unknown method")),
        }
    }

    fn override_diff(&self) -> Option<f64> {
        if self.name.is_empty() {
            return None;
        }
        self.pool.override_for(&self.name).get("diff").and_then(|d| d.as_f64())
    }

    fn share_seconds(&self) -> f64 {
        self.pool.override_for(&self.name).get("share_seconds").and_then(|d| d.as_f64()).unwrap_or(self.pool.cfg.share_seconds)
    }

    async fn authorize(&mut self, p: &Value) -> Result<(Value, After), StratumError> {
        self.auth_tries += 1;
        if self.auth_tries > MAX_AUTHORIZE {
            return Err(err(24, "Too many authorize attempts"));
        }
        let user: String = match p.get(0) {
            Some(Value::String(s)) => s.chars().take(120).collect(),
            Some(v) => v.to_string().chars().take(120).collect(),
            None => return Err(err(20, "Bad request")),
        };
        let name = user.split_once('.').map(|(_, n)| n.to_string()).unwrap_or_default();
        let (address, spk) = match self.pool.payout_for(&user).await {
            Payout::To(address, spk) => (address, spk),
            Payout::NoAddress => {
                log!("INFO", "refused {} {}: no payout address yet (set one, or put an address in the miner's username)", self.ip, user);
                return Ok((json!(false), After::None));
            }
            Payout::NoAnswer => {
                log!("INFO", "refused {} {} for now: the node can't check the address in its username (down, starting or \
                              slow); the miner will try again", self.ip, user);
                return Ok((json!(false), After::None));
            }
        };
        self.name = if name.is_empty() { self.ip.clone() } else { name };
        if let Some(d) = self.pool.remembered_diff(&self.name) {
            self.set_diff(d); // start where this miner left off
            self.remembered = true;
        }
        let password = p.get(1).and_then(|v| v.as_str()).unwrap_or("");
        for part in password.split(',') {
            if let Some(d) = part.trim().strip_prefix("d=") {
                if let Ok(d) = d.parse::<f64>() {
                    self.set_diff(d);
                }
            }
        }
        if let Some(d) = self.override_diff() {
            self.set_diff(d);
        }
        {
            let mut i = self.info.lock().unwrap();
            i.user = user;
            i.name = self.name.clone();
            i.address = address.clone();
            i.spk = spk;
            i.diff = self.diff;
        }
        self.authorized = true;
        self.pool.workers.lock().unwrap()
            .insert(self.id, WorkerHandle { info: self.info.clone(), ctl: self.ctl_tx.clone() });
        log!("INFO", "authorized {} {} ({}) pays {}", self.ip, self.name, self.agent, address);
        Ok((json!(true), After::FirstJob))
    }

    fn set_diff(&mut self, d: f64) {
        self.diff = d.max(self.pool.cfg.min_diff).min(MAX_DIFF);
        self.info.lock().unwrap().diff = self.diff;
        self.vd_start = now_f();
        self.vd_count = 0;
        self.vd_work = 0.0;
        self.vd_pending = None;
    }

    /// A share that fails a check: counted, logged, and the miner gets the error.
    fn reject(&self, reason: &'static str, code: i64, msg: &'static str) -> StratumError {
        log!("WARNING", "share rejected from {} ({}): {}", self.name, self.ip, reason);
        *self.info.lock().unwrap().rejected.entry(reason.to_string()).or_insert(0) += 1;
        self.pool.share_rejected(&self.name, reason);
        err(code, msg)
    }

    async fn submit(&mut self, p: &Value) -> Result<bool, StratumError> {
        if !self.authorized {
            return Err(err(24, "Unauthorized worker"));
        }
        let s = |i: usize| p.get(i).and_then(|v| v.as_str()).ok_or_else(|| err(20, "Bad request"));
        let (job_id, en2_hex, ntime_hex, nonce_hex) = (s(1)?, s(2)?, s(3)?, s(4)?);
        let Some(job) = self.pool.job(job_id) else {
            return Err(self.reject("old-job", 21, "Job not found"));
        };
        let parsed = (|| {
            let en2 = hex::decode(en2_hex).ok()?;
            let ntime = u32::from_str_radix(ntime_hex, 16).ok()?;
            let nonce = u64::from_str_radix(nonce_hex, 16).ok()?;
            let vbits = match p.get(5).and_then(|v| v.as_str()) {
                Some(v) if !v.is_empty() => Some(u64::from_str_radix(v, 16).ok()?),
                _ => None,
            };
            Some((en2, ntime, nonce, vbits))
        })();
        let Some((en2v, ntime, nonce, vbits)) = parsed else {
            return Err(self.reject("malformed", 20, "Malformed share"));
        };
        if en2v.len() != EN2_SIZE || nonce >= 1 << 32 {
            return Err(self.reject("malformed", 20, "Malformed share"));
        }
        let en2: [u8; EN2_SIZE] = en2v.try_into().unwrap();
        let nonce = nonce as u32;
        let version = match vbits {
            None => job.version,
            Some(v) if v & !(VERSION_MASK as u64) != 0 => return Err(self.reject("bad-version", 20, "Invalid version bits")),
            Some(v) => (job.version & !VERSION_MASK) | v as u32,
        };
        if !((job.mintime as f64) <= ntime as f64 && ntime as f64 <= now_f() + 7000.0) {
            return Err(self.reject("ntime", 20, "ntime out of range"));
        }
        let key = (self.en1, en2, ntime, nonce, version);
        if job.seen.lock().unwrap().contains(&key) {
            return Err(self.reject("duplicate", 22, "Duplicate share"));
        }
        // the payout this job went out with (see Sent), not the miner's current one
        let (spk, address) = match self.job_sent.get(&job.id) {
            Some(s) => (s.spk.clone(), s.address.clone()),
            None => self.payout(),
        };
        let mut coinbase = job.coinb1.clone();
        coinbase.extend_from_slice(&self.en1);
        coinbase.extend_from_slice(&en2);
        coinbase.extend(job.coinb2(&spk));
        let header = job.header(&coinbase, version, ntime, nonce);
        let h = sha256d(&header);
        let share_diff = hash_diff(&h);
        let is_block = hash_meets(&h, &job.target);
        if is_block {
            job.seen.lock().unwrap().insert(key); // before the submission, so a resend counts as a duplicate
            let pool = self.pool.clone();
            tokio::spawn(pool.found_block(self.name.clone(), self.ip.clone(), address, job.clone(), header, coinbase, share_diff));
        }
        let required = self.job_sent.get(&job.id).map_or(self.diff, |s| s.diff).min(self.diff);
        if share_diff < required * (1.0 - 1e-9) {
            return Err(self.reject("low-diff", 23, "Low difficulty share"));
        }
        job.seen.lock().unwrap().insert(key); // only shares that pass the difficulty check
        if job.prev_hex != self.pool.tip() && !is_block {
            return Err(self.reject("stale", 21, "Stale share")); // work on a block someone else just found
        }
        let now = now_f();
        let credit = self.share_credit(&job.id, share_diff);
        self.vd_count += 1;
        self.vd_work += credit;
        {
            let mut i = self.info.lock().unwrap();
            i.accepted += 1;
            i.last_share = now;
            i.last_height = Some(job.height);
            i.switches_at_once = self.switches_at_once;
            i.shares.push_back((now, credit));
            while i.shares.front().map_or(false, |s| s.0 < now - 3600.0) {
                i.shares.pop_front();
            }
            if share_diff > i.best {
                i.best = share_diff;
            }
        }
        self.pool.share_accepted(&self.name, credit, share_diff, now, is_block);
        Ok(true)
    }

    /// The difficulty an accepted share counts at (see pool.py's share_credit).
    fn share_credit(&mut self, job_id: &str, share_diff: f64) -> f64 {
        let job_diff = self.job_sent.get(job_id).map_or(self.diff, |s| s.diff);
        if share_diff < job_diff * (1.0 - 1e-9) {
            self.switches_at_once = true;
        }
        if self.switches_at_once { self.diff } else { job_diff }
    }

    /// pool.py's vardiff: 40 shares or 10 minutes; changes under x1.5 ignored; two windows must agree unless x4.
    fn vardiff(&mut self, now: f64) -> Option<f64> {
        if !self.authorized || self.override_diff().is_some() {
            return None;
        }
        let target = self.share_seconds();
        let elapsed = now - self.vd_start;
        let far_too_high = self.vd_count == 0 && elapsed >= (12.0 * target).max(180.0);
        if self.vd_count < 40 && elapsed < 600.0 && !far_too_high {
            return None;
        }
        let mut ideal = if self.vd_count > 0 { self.vd_work * target / elapsed } else { self.diff / 4.0 };
        ideal = ideal.max(self.diff / 8.0).min(self.diff * 16.0);
        ideal = sig3(ideal).max(self.pool.cfg.min_diff).min(MAX_DIFF);
        self.vd_start = now;
        self.vd_count = 0;
        self.vd_work = 0.0;
        let ratio = ideal / self.diff;
        if 1.0 / 1.5 < ratio && ratio < 1.5 {
            self.vd_pending = None;
            return None;
        }
        let direction = if ideal > self.diff { 1 } else { -1 };
        if !(far_too_high || ideal >= self.diff * 4.0 || ideal <= self.diff / 4.0) {
            match self.vd_pending {
                Some((d, prev)) if d == direction => ideal = sig3((ideal * prev).sqrt()),
                _ => {
                    self.vd_pending = Some((direction, ideal));
                    return None;
                }
            }
        }
        self.vd_pending = None;
        self.diff = ideal;
        self.info.lock().unwrap().diff = ideal;
        Some(ideal)
    }
}
