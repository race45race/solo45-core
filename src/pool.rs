//! Pool-wide state: configuration, jobs, new-block detection (ZMQ signal, long-poll, tip poll), empty block
//! first, the node's block check, payouts, found blocks, statistics and saved state.
//! Mirrors the Pool class in Solo45's pool.py; the template policy and the stall guard are not ported yet.

use crate::job::{Job, TxCache, EN1_SIZE, EN2_SIZE};
use crate::log;
use crate::rpc::{shellexpand, Rpc};
use crate::util::{address_plausible, commas, fmt_diff, g3, hashrate, median, now_f, sha256d, target_diff};
use crate::zmq::ZmqSub;
use anyhow::Result;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::future::Future;
use std::io::Write;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc};

pub const VERSION_MASK: u32 = 0x1FFF_E000;
pub const MAX_DIFF: f64 = 1e9;
pub const MAX_CONNS: usize = 2000;
pub const AUTH_WINDOW_S: f64 = 120.0;
pub const SPK_CACHE_MAX: usize = 5000;
pub const MAX_AUTHORIZE: u32 = 10;
pub const SUBMIT_TRIES: u32 = 6;
pub const SUBMIT_RETRY_S: f64 = 2.0;
pub const MAX_JOBS: usize = 40;

/// Stand-in payout script for block checks before any payout address is known.
fn check_spk() -> Vec<u8> {
    let mut v = vec![0x00, 0x20];
    v.extend([0u8; 32]);
    v
}

#[derive(Clone, Debug)]
pub struct Config {
    pub stratum_port: u16,
    pub api_port: u16,
    pub web_port: u16,
    pub api_token: String,
    pub rpc_url: String,
    pub rpc_cookie: String,
    pub rpc_user: String,
    pub rpc_pass: String,
    pub zmq_hashblock: String,
    pub default_address: String,
    pub force_default_address: bool,
    pub coinbase_tag: String,
    pub max_conns_per_ip: usize,
    pub start_diff: f64,
    pub min_diff: f64,
    pub share_seconds: f64,
    pub block_poll_ms: u64,
    pub empty_first: bool,
    pub empty_hold_s: f64,
    pub template_refresh_s: f64,
    pub data_dir: String,
}

fn env<T: std::str::FromStr>(k: &str, d: T) -> T {
    std::env::var(k).ok().filter(|v| !v.is_empty()).and_then(|v| v.parse().ok()).unwrap_or(d)
}

impl Config {
    /// Settings from the environment (the Umbrel app sets these), with pool.py's defaults.
    pub fn from_env() -> Config {
        Config {
            stratum_port: env("SOLO45_STRATUM_PORT", 3346),
            api_port: env("SOLO45_API_PORT", 3386),
            web_port: env("SOLO45_WEB_PORT", 0), // the status page; 0 = off (the Umbrel app sets 8346)
            api_token: env("SOLO45_API_TOKEN", String::new()),
            rpc_url: env("BITCOIN_RPC_URL", "http://127.0.0.1:8332/".to_string()),
            rpc_cookie: env("BITCOIN_RPC_COOKIE", "~/umbrel/app-data/bitcoin/data/bitcoin/.cookie".to_string()),
            rpc_user: env("BITCOIN_RPC_USER", String::new()),
            rpc_pass: env("BITCOIN_RPC_PASS", String::new()),
            zmq_hashblock: env("BITCOIN_ZMQ_HASHBLOCK", String::new()),
            default_address: env("SOLO45_DEFAULT_ADDRESS", String::new()),
            force_default_address: env("SOLO45_FORCE_DEFAULT_ADDRESS", false),
            coinbase_tag: env("SOLO45_COINBASE_TAG", "Solo45".to_string()),
            max_conns_per_ip: env("SOLO45_MAX_CONNS_PER_IP", 64),
            start_diff: env("SOLO45_START_DIFF", 10000.0),
            min_diff: env("SOLO45_MIN_DIFF", 256.0),
            share_seconds: env("SOLO45_SHARE_SECONDS", 10.0), // the Solo45 app's setting (pool.py's own default is 5)
            block_poll_ms: env("SOLO45_BLOCK_POLL_MS", 100),
            empty_first: env("SOLO45_EMPTY_FIRST", true),
            empty_hold_s: env("SOLO45_EMPTY_HOLD_S", 10.0),
            template_refresh_s: env("SOLO45_TEMPLATE_REFRESH_S", 30.0),
            data_dir: shellexpand(&env("SOLO45_DATA_DIR", ".".to_string())),
        }
    }
}

#[derive(Clone)]
pub struct NewJob {
    pub job: Arc<Job>,
    pub clean: bool,
}

/// What a connected miner shows on the API (shared between its connection task and the pool).
pub struct WorkerInfo {
    pub name: String,
    pub ip: String,
    pub agent: String,
    pub user: String,
    pub address: String,
    pub spk: Vec<u8>,
    pub diff: f64,
    pub switches_at_once: bool,
    pub accepted: u64,
    pub rejected: BTreeMap<String, u64>,
    pub best: f64,
    pub last_share: f64,
    pub last_height: Option<u64>,
    pub connected: f64,
    pub shares: VecDeque<(f64, f64)>,
}

impl WorkerInfo {
    pub fn new(ip: &str, now: f64) -> WorkerInfo {
        WorkerInfo {
            name: String::new(), ip: ip.to_string(), agent: String::new(), user: String::new(), address: String::new(),
            spk: Vec::new(), diff: 0.0, switches_at_once: false, accepted: 0, rejected: BTreeMap::new(), best: 0.0,
            last_share: 0.0, last_height: None, connected: now, shares: VecDeque::new(),
        }
    }
}

/// Messages from the pool to one miner's connection task.
pub enum Ctl {
    /// set this difficulty (an override from the dashboard) and tell the miner
    SetDiff(f64),
}

pub struct WorkerHandle {
    pub info: Arc<Mutex<WorkerInfo>>,
    pub ctl: mpsc::UnboundedSender<Ctl>,
}

#[derive(Default)]
pub struct Stats {
    pub accepted: u64,
    pub rejected: BTreeMap<String, u64>,
    pub shares: VecDeque<(f64, f64)>,
    pub best: Value,
    window_best: (f64, String),
    stats_mark: (u64, u64),
    pub share_log: VecDeque<Value>,
    share_seq: u64,
    pub last_switch: Value,
    pub proposal: Value,
    pub build_times: VecDeque<u64>,
    pub check_times: VecDeque<u64>,
    last_proposal: f64,
    proposal_checked: HashSet<Vec<u8>>,
}

fn push_capped(q: &mut VecDeque<u64>, v: u64) {
    q.push_back(v);
    while q.len() > 50 {
        q.pop_front();
    }
}

/// Guarded by the template lock: the full template saved during an empty job's hold.
#[derive(Default)]
pub struct TplState {
    held: Option<Value>,
    held_at: f64,
}

/// One request for a new job (pool.py's update_template arguments).
#[derive(Default)]
pub struct Upd {
    pub clean: bool,
    /// a template the node already built (the long-poll's reply)
    pub tpl: Option<Value>,
    /// the block that prompted this; nothing to do if another path already made its job
    pub new_tip: Option<String>,
    pub source: Option<String>,
    /// the empty hold just ended (or the empty job failed its check): send the full template now
    pub fill: bool,
}

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

fn prev_of(t: &Value) -> String {
    t["previousblockhash"].as_str().unwrap_or("").to_string()
}

/// A coinbase-only template for the block on top of `hdr` (a getblockheader reply), built without asking the node
/// for a template. None when the next block starts a new difficulty period (its bits can't be copied).
pub fn empty_template(hdr: &Value, version: u32, now: f64) -> Option<Value> {
    let height = hdr["height"].as_u64()? + 1;
    if height % 2016 == 0 {
        return None;
    }
    let mintime = hdr["mediantime"].as_u64()? + 1;
    Some(json!({
        "height": height, "previousblockhash": hdr["hash"], "version": version, "bits": hdr["bits"],
        "curtime": (now as u64).max(mintime), "mintime": mintime,
        "coinbasevalue": 5_000_000_000u64.checked_shr((height / 210_000) as u32).unwrap_or(0),
        "transactions": []
    }))
}

pub struct Pool {
    pub cfg: Config,
    pub rpc: Rpc,
    jobs: RwLock<VecDeque<Arc<Job>>>,
    current: RwLock<Option<Arc<Job>>>,
    tip: RwLock<String>,
    tx_cache: Mutex<TxCache>,
    pub job_tx: broadcast::Sender<NewJob>,
    en1_next: AtomicU32,
    job_seq: AtomicU64,
    worker_seq: AtomicU64,
    spk_cache: Mutex<(HashMap<String, Option<Vec<u8>>>, VecDeque<String>)>,
    default: RwLock<(String, Option<Vec<u8>>)>,
    conns: Mutex<HashMap<IpAddr, usize>>,
    pub workers: Mutex<HashMap<u64, WorkerHandle>>,
    pub stats: Mutex<Stats>,
    pub state: Mutex<Value>,
    state_path: String,
    pub submitting: AtomicUsize,
    tpl: tokio::sync::Mutex<TplState>,
    chain: RwLock<Option<String>>,
    pub zmq_up: AtomicBool,
    longpoll_waiting: AtomicBool,
    pub started: f64,
}

impl Pool {
    pub fn new(cfg: Config) -> Result<Arc<Pool>> {
        let rpc = Rpc::new(&cfg.rpc_url, Some(cfg.rpc_cookie.clone()), &cfg.rpc_user, &cfg.rpc_pass)?;
        let (job_tx, _) = broadcast::channel(16);
        let seed = (now_f() * 1e6) as u64;
        std::fs::create_dir_all(&cfg.data_dir).ok();
        let state_path = format!("{}/state.json", cfg.data_dir);
        let new_install = !std::path::Path::new(&state_path).exists();
        let mut state: Value = std::fs::read_to_string(&state_path).ok()
            .and_then(|s| serde_json::from_str(&s).ok()).filter(|v: &Value| v.is_object()).unwrap_or(json!({}));
        for (k, d) in [("best_ever", json!({"diff": 0.0})), ("blocks", json!([])), ("accepted_total", json!(0)),
                       ("overrides", json!({})), ("settings", json!({})), ("last_diff", json!({}))] {
            if state.get(k).is_none() {
                state[k] = d;
            }
        }
        if new_install {
            // a new install pays every miner to the payout address; older ones keep what they had
            state["settings"]["force_default_address"] = json!(true);
        }
        let default = (cfg.default_address.clone(), None);
        Ok(Arc::new(Pool {
            rpc,
            jobs: RwLock::new(VecDeque::new()),
            current: RwLock::new(None),
            tip: RwLock::new(String::new()),
            tx_cache: Mutex::new(TxCache::new()),
            job_tx,
            en1_next: AtomicU32::new((seed as u32) & 0x3fff_ffff),
            job_seq: AtomicU64::new(seed & 0xffff),
            worker_seq: AtomicU64::new(1),
            spk_cache: Mutex::new((HashMap::new(), VecDeque::new())),
            default: RwLock::new(default),
            conns: Mutex::new(HashMap::new()),
            workers: Mutex::new(HashMap::new()),
            stats: Mutex::new(Stats { best: json!({"diff": 0.0}), proposal: json!({"ok": null}), ..Default::default() }),
            state: Mutex::new(state),
            state_path,
            submitting: AtomicUsize::new(0),
            tpl: tokio::sync::Mutex::new(TplState::default()),
            chain: RwLock::new(None),
            zmq_up: AtomicBool::new(false),
            longpoll_waiting: AtomicBool::new(false),
            started: now_f(),
            cfg,
        }))
    }

    // ------------------------------------------------------------------ small accessors

    pub fn next_en1(&self) -> [u8; 4] {
        self.en1_next.fetch_add(1, Ordering::Relaxed).to_be_bytes()
    }

    pub fn next_worker_id(&self) -> u64 {
        self.worker_seq.fetch_add(1, Ordering::Relaxed)
    }

    fn next_job_id(&self) -> String {
        format!("{:x}", self.job_seq.fetch_add(1, Ordering::Relaxed))
    }

    pub fn job(&self, id: &str) -> Option<Arc<Job>> {
        self.jobs.read().unwrap().iter().find(|j| j.id == id).cloned()
    }

    pub fn current(&self) -> Option<Arc<Job>> {
        self.current.read().unwrap().clone()
    }

    fn is_current(&self, job: &Arc<Job>) -> bool {
        self.current().map_or(false, |c| Arc::ptr_eq(&c, job))
    }

    pub fn tip(&self) -> String {
        self.tip.read().unwrap().clone()
    }

    pub fn worker_count(&self) -> usize {
        self.workers.lock().unwrap().len()
    }

    fn setting(&self, k: &str) -> Option<Value> {
        self.state.lock().unwrap()["settings"].get(k).cloned()
    }

    pub fn refresh_s(&self) -> f64 {
        self.setting("template_refresh_s").and_then(|v| v.as_f64()).unwrap_or(self.cfg.template_refresh_s)
    }

    pub fn empty_first_on(&self) -> bool {
        self.setting("empty_first").and_then(|v| v.as_bool()).unwrap_or(self.cfg.empty_first)
    }

    pub fn empty_hold_s(&self) -> f64 {
        self.setting("empty_hold_s").and_then(|v| v.as_f64()).unwrap_or(self.cfg.empty_hold_s).clamp(0.0, 40.0)
    }

    /// The dashboard's "Always pay my address" switch.
    pub fn force_default(&self) -> bool {
        self.setting("force_default_address").and_then(|v| v.as_bool()).unwrap_or(self.cfg.force_default_address)
    }

    /// Every miner pays the payout address: the switch is on and an address is set.
    pub fn pays_default(&self) -> bool {
        self.force_default() && self.default.read().unwrap().1.is_some()
    }

    pub fn default_address(&self) -> String {
        self.default.read().unwrap().0.clone()
    }

    /// User settings for this miner name: {"diff": fixed} or {"share_seconds": target}, else {}.
    pub fn override_for(&self, name: &str) -> Value {
        self.state.lock().unwrap()["overrides"].get(name).cloned().unwrap_or(json!({}))
    }

    pub fn remembered_diff(&self, name: &str) -> Option<f64> {
        let st = self.state.lock().unwrap();
        let e = st["last_diff"].get(name)?;
        let (d, at) = (e.get(0)?.as_f64()?, e.get(1)?.as_f64()?);
        (now_f() - at < 7.0 * 86400.0).then_some(d)
    }

    /// Count a new connection; false if this address or the pool is full.
    pub fn conn_open(&self, ip: IpAddr) -> bool {
        let mut c = self.conns.lock().unwrap();
        let total: usize = c.values().sum();
        let n = c.entry(ip).or_insert(0);
        if *n >= self.cfg.max_conns_per_ip || total >= MAX_CONNS {
            if *n == 0 {
                c.remove(&ip);
            }
            return false;
        }
        *n += 1;
        true
    }

    pub fn conn_close(&self, ip: IpAddr) {
        let mut c = self.conns.lock().unwrap();
        if let Some(n) = c.get_mut(&ip) {
            *n -= 1;
            if *n == 0 {
                c.remove(&ip);
            }
        }
    }

    // ------------------------------------------------------------------ payouts

    /// The node's output script for an address, or None (not an address, invalid, or the node can't be asked).
    /// Junk usernames cost nothing and the cache keeps at most SPK_CACHE_MAX entries (v0.1.65 hardening).
    pub async fn script_for(&self, address: &str) -> Option<Vec<u8>> {
        if !address_plausible(address) {
            return None;
        }
        if let Some(v) = self.spk_cache.lock().unwrap().0.get(address) {
            return v.clone();
        }
        let r = self.rpc.call("validateaddress", json!([address])).await.ok()?;
        let spk = if r["isvalid"].as_bool() == Some(true) {
            r["scriptPubKey"].as_str().and_then(|s| hex::decode(s).ok())
        } else {
            None
        };
        let mut c = self.spk_cache.lock().unwrap();
        if c.0.len() >= SPK_CACHE_MAX {
            if let Some(old) = c.1.pop_front() {
                c.0.remove(&old);
            }
        }
        if c.0.insert(address.to_string(), spk.clone()).is_none() {
            c.1.push_back(address.to_string());
        }
        spk
    }

    /// (address, script) a miner with this username pays: the payout address when "Always pay my address" is on,
    /// else a valid address at the start of the username, else the payout address. None if neither works.
    pub async fn payout_for(&self, user: &str) -> Option<(String, Vec<u8>)> {
        let address = user.split('.').next().unwrap_or("");
        let spk = if self.pays_default() { None } else { self.script_for(address).await };
        match spk {
            Some(s) => Some((address.to_string(), s)),
            None => {
                let d = self.default.read().unwrap().clone();
                d.1.map(|s| (d.0, s))
            }
        }
    }

    // ------------------------------------------------------------------ work

    /// Make the job live: kept for share lookups, current, and the tip it builds on.
    fn install(&self, job: &Arc<Job>) {
        let mut jobs = self.jobs.write().unwrap();
        jobs.push_back(job.clone());
        // a job two or more blocks back can never make a valid block or share
        jobs.retain(|j| j.height + 1 >= job.height);
        while jobs.len() > MAX_JOBS {
            jobs.pop_front();
        }
        *self.current.write().unwrap() = Some(job.clone());
        *self.tip.write().unwrap() = job.prev_hex.clone();
    }

    fn note_switch(&self, job: &Job, ms: u64, workers: usize) {
        let mut s = self.stats.lock().unwrap();
        s.last_switch = json!({"height": job.height, "ms": ms, "at": now_f(), "workers": workers});
        if workers > 0 {
            push_capped(&mut s.build_times, ms); // not the first job after a start
        }
    }

    /// A new job from a fresh template (or u.tpl), sent to every miner: a port of pool.py's update_template,
    /// including the empty-block hold. Boxed because the hold's end calls it again from a spawned task.
    pub fn update_template<'a>(self: &'a Arc<Self>, u: Upd) -> BoxFut<'a, Result<()>> {
        Box::pin(async move {
            let job;
            let (new_block, filled);
            {
                let mut st = self.tpl.lock().await;
                let cur = self.current();
                let empty = cur.as_ref().map_or(false, |j| j.empty);
                let holding = match &cur {
                    Some(j) if j.empty && !u.fill => j.created.elapsed().as_secs_f64() < self.empty_hold_s(),
                    _ => false,
                };
                let tip = self.tip();
                let same_tip = u.tpl.as_ref().map_or(false, |t| prev_of(t) == tip)
                    || u.new_tip.as_deref().map_or(false, |n| n == tip);
                if holding && same_tip {
                    // stay on the coinbase-only job, but keep the node's template for the end of the hold
                    if let Some(t) = u.tpl {
                        st.held = Some(t);
                        st.held_at = now_f();
                    }
                    return Ok(());
                }
                if holding && u.tpl.is_none() && u.new_tip.is_none() {
                    return Ok(()); // a routine refresh during the hold
                }
                if same_tip && !empty {
                    return Ok(()); // the other block watcher got there first
                }
                let mut clean = u.clean;
                let mut tpl = u.tpl;
                if u.fill {
                    if let Some(c) = &cur {
                        clean = true; // the hold is over: every miner leaves the empty job now
                        if tpl.is_none() && st.held.as_ref().map_or(false, |h| prev_of(h) == c.prev_hex) {
                            tpl = st.held.take();
                        }
                    }
                }
                st.held = None;
                st.held_at = 0.0;
                let t0 = Instant::now();
                if tpl.is_none() || (same_tip && !u.fill) {
                    tpl = Some(self.rpc.call("getblocktemplate", json!([{"rules": ["segwit"]}])).await?);
                }
                let tpl = tpl.unwrap();
                let prev = prev_of(&tpl);
                new_block = prev != tip;
                if new_block && self.empty_first_on() {
                    // this path saw the new block before the node's block signal did: empty job first all the same
                    let src = u.source.clone().unwrap_or_else(|| "template refresh".to_string());
                    if let Some(ejob) = self.send_empty(&mut st, &prev, &src).await? {
                        if prev == ejob.prev_hex {
                            st.held = Some(tpl); // so the end of the hold does not build it again
                            st.held_at = now_f();
                        }
                        drop(st);
                        self.after_empty(ejob);
                        return Ok(());
                    }
                }
                filled = empty && !new_block; // the full template for the block the miners got empty work for
                if filled {
                    clean = true;
                }
                let j = {
                    let mut cache = self.tx_cache.lock().unwrap();
                    Arc::new(Job::new(&self.next_job_id(), &tpl, self.cfg.coinbase_tag.as_bytes(), &mut cache)?)
                };
                self.install(&j);
                let workers = self.worker_count();
                let _ = self.job_tx.send(NewJob { job: j.clone(), clean: clean || new_block });
                let ms = t0.elapsed().as_millis() as u64;
                if new_block {
                    self.note_switch(&j, ms, workers);
                    log!("INFO", "new network block {} ({}), now mining {}{}", j.height - 1, j.prev_hex, j.height,
                        u.source.as_ref().map(|s| format!(" (spotted by the {})", s)).unwrap_or_default());
                }
                let bytes: usize = j.tx_data.iter().map(|t| t.len()).sum();
                log!("INFO", "{} job {} for block {}: {:.8} BTC, {} txs, {} bytes, fees {:.4} BTC (sent to {} workers in {} ms)",
                    if new_block { "new-block" } else if filled { "full" } else { "updated" }, j.id, j.height,
                    j.value as f64 / 1e8, j.tx_data.len(), commas(bytes as u64), j.fees as f64 / 1e8, workers, ms);
                job = j;
            }
            // the node fully checks every new block's work; routine refreshes less often
            let due = {
                let mut s = self.stats.lock().unwrap();
                let due = new_block || filled || now_f() - s.last_proposal >= check_every_s(&s);
                if due {
                    s.last_proposal = now_f();
                }
                due
            };
            if due {
                tokio::spawn(self.clone().check_proposal(job));
            }
            Ok(())
        })
    }

    /// The empty job for the block after `prev`, sent to every miner (caller holds the template lock).
    /// None when it can't be used: not mainnet, a reorg or skipped block, or a new difficulty period.
    async fn send_empty(&self, st: &mut TplState, prev: &str, source: &str) -> Result<Option<Arc<Job>>> {
        let Some(cur) = self.current() else { return Ok(None) };
        if self.chain.read().unwrap().as_deref() != Some("main") {
            return Ok(None);
        }
        let t0 = Instant::now();
        let hdr = self.rpc.call_t("getblockheader", json!([prev]), 5).await?;
        if hdr["previousblockhash"].as_str() != Some(self.tip().as_str()) {
            return Ok(None); // not the next block on top of ours: use the node's template
        }
        let Some(tpl) = empty_template(&hdr, cur.version, now_f()) else { return Ok(None) };
        let mut j = {
            let mut cache = self.tx_cache.lock().unwrap();
            Job::new(&self.next_job_id(), &tpl, self.cfg.coinbase_tag.as_bytes(), &mut cache)?
        };
        j.empty = true;
        let j = Arc::new(j);
        st.held = None; // a template for the previous block must not fill this one
        st.held_at = 0.0;
        self.install(&j);
        let workers = self.worker_count();
        let _ = self.job_tx.send(NewJob { job: j.clone(), clean: true });
        let ms = t0.elapsed().as_millis() as u64;
        self.note_switch(&j, ms, workers);
        log!("INFO", "new network block {} ({}), now mining {} (spotted by the {})", j.height - 1, j.prev_hex, j.height, source);
        log!("INFO", "new-block job {} for block {}: empty (coinbase only, {:.8} BTC), sent to {} workers in {} ms; \
                      the full template follows in {} s", j.id, j.height, j.value as f64 / 1e8, workers, ms, g3(self.empty_hold_s()));
        Ok(Some(j))
    }

    /// The node's check of the empty job, and the full template once the hold ends.
    fn after_empty(self: &Arc<Self>, job: Arc<Job>) {
        self.stats.lock().unwrap().last_proposal = now_f();
        tokio::spawn(self.clone().check_proposal(job.clone()));
        tokio::spawn(self.clone().fill_after_hold(job));
    }

    /// Empty work on top of a block the node just accepted. Ok(false) when it can't be used.
    async fn empty_first(self: &Arc<Self>, prev: &str, source: &str) -> Result<bool> {
        let job = {
            let mut st = self.tpl.lock().await;
            if prev == self.tip() {
                return Ok(true);
            }
            self.send_empty(&mut st, prev, source).await?
        };
        match job {
            None => Ok(false),
            Some(j) => {
                self.after_empty(j);
                Ok(true)
            }
        }
    }

    /// The full template once this empty job has been mined for empty_hold_s; a template is fetched again in the
    /// last 2 s so the job at the deadline has the transactions that arrived during the hold.
    async fn fill_after_hold(self: Arc<Self>, job: Arc<Job>) {
        loop {
            if !self.is_current(&job) {
                break;
            }
            let left = self.empty_hold_s() - job.created.elapsed().as_secs_f64();
            if left <= 0.0 {
                break;
            }
            if left > 2.0 {
                if tokio::time::timeout(Duration::from_secs_f64(left - 2.0), job.hold_done.notified()).await.is_ok() {
                    break; // the empty job failed its check: leave it now
                }
                continue;
            }
            if !job.refreshed.swap(true, Ordering::SeqCst) {
                let need = {
                    let st = self.tpl.lock().await;
                    st.held.is_none() || now_f() - st.held_at >= 2.0
                };
                if need {
                    match self.rpc.call("getblocktemplate", json!([{"rules": ["segwit"]}])).await {
                        Ok(tpl) if prev_of(&tpl) == job.prev_hex && self.is_current(&job) => {
                            let mut st = self.tpl.lock().await;
                            if self.is_current(&job) {
                                st.held = Some(tpl);
                                st.held_at = now_f();
                            }
                        }
                        Ok(_) => {}
                        Err(e) => log!("WARNING", "template before the end of the empty hold: {}", e),
                    }
                }
            }
            let left = self.empty_hold_s() - job.created.elapsed().as_secs_f64();
            if left <= 0.0 || !self.is_current(&job) {
                break;
            }
            if tokio::time::timeout(Duration::from_secs_f64(left), job.hold_done.notified()).await.is_ok() {
                break;
            }
        }
        if !self.is_current(&job) {
            return; // a newer block already replaced it
        }
        let u = Upd { new_tip: Some(job.prev_hex.clone()), fill: true, ..Default::default() };
        if let Err(e) = self.update_template(u).await {
            log!("WARNING", "full template after the empty one: {}", e);
        }
    }

    /// The node's ZMQ new-block signal: the first sign of a new block, before its template exists.
    async fn on_block_signal(self: Arc<Self>, bhash: String) {
        if bhash == self.tip() {
            return;
        }
        let src = "node's block signal";
        let r = async {
            if self.empty_first_on() && self.empty_first(&bhash, src).await? {
                return Ok(());
            }
            self.update_template(Upd { clean: true, new_tip: Some(bhash.clone()), source: Some(src.into()), ..Default::default() }).await
        }
        .await;
        if let Err(e) = r {
            log!("WARNING", "new block {}: {}", &bhash[..16.min(bhash.len())], e);
        }
    }

    /// The payout address every block; a miner's own address only the first time it shows up.
    fn proposal_script(&self) -> Vec<u8> {
        let current: Vec<Vec<u8>> = {
            let w = self.workers.lock().unwrap();
            let mut seen = HashSet::new();
            w.values().map(|h| h.info.lock().unwrap().spk.clone()).filter(|s| !s.is_empty() && seen.insert(s.clone())).collect()
        };
        let default = self.default.read().unwrap().1.clone();
        let fresh: Option<Vec<u8>> = {
            let s = self.stats.lock().unwrap();
            current.iter().find(|spk| !s.proposal_checked.contains(*spk)).cloned()
        };
        match fresh {
            Some(f) if !self.pays_default() => f,
            _ => default.or_else(|| current.first().cloned()).unwrap_or_else(check_spk),
        }
    }

    /// Have the node validate a complete block built from this job (everything except proof of work).
    async fn check_proposal(self: Arc<Self>, job: Arc<Job>) {
        let spk = self.proposal_script();
        let t0 = Instant::now();
        let mut coinbase = job.coinb1.clone();
        coinbase.extend([0u8; EN1_SIZE + EN2_SIZE]);
        coinbase.extend(job.coinb2(&spk));
        let header = job.header(&coinbase, job.version, job.curtime, 0);
        let data = hex::encode(job.block(&header, &coinbase));
        let res = match self.rpc.call_t("getblocktemplate", json!([{"mode": "proposal", "data": data}]), 60).await {
            Ok(v) => v,
            Err(e) => json!(format!("rpc error: {}", e)),
        };
        if res == json!("inconclusive-not-best-prevblk") {
            return; // a newer block arrived meanwhile; the next job gets checked
        }
        let ms = t0.elapsed().as_millis() as u64;
        let ok = res.is_null();
        {
            let mut s = self.stats.lock().unwrap();
            push_capped(&mut s.check_times, ms);
            s.proposal = json!({"ok": ok, "result": res, "height": job.height, "at": now_f(), "outputs": 1});
            if ok {
                s.proposal_checked.insert(spk);
            }
        }
        if ok {
            log!("INFO", "block check OK for {} (job {}, {} txs) in {} ms", job.height, job.id, job.tx_data.len(), ms);
            return;
        }
        log!("ERROR", "BLOCK PROPOSAL REJECTED at height {}: {}", job.height, res);
        if job.empty {
            log!("ERROR", "the empty template for block {} failed the block check; ending the hold", job.height);
            job.hold_done.notify_one();
        }
    }

    // ------------------------------------------------------------------ found blocks

    fn save_found(&self, entry: &Value) {
        let path = format!("{}/blocks_found.jsonl", self.cfg.data_dir);
        let r = std::fs::OpenOptions::new().create(true).append(true).open(&path)
            .and_then(|mut f| writeln!(f, "{}", entry));
        if let Err(e) = r {
            log!("CRITICAL", "couldn't save block {} to {}: {}", entry["hash"], path, e);
        }
    }

    /// Save, then submit a found block: up to SUBMIT_TRIES tries while the node can't be reached or is starting;
    /// the node's own verdict ends it. "duplicate" after a resend means an earlier try got through.
    pub async fn found_block(self: Arc<Self>, worker: String, ip: String, address: String, job: Arc<Job>,
                             header: [u8; 80], coinbase: Vec<u8>, share_diff: f64) {
        let block_hex = hex::encode(job.block(&header, &coinbase));
        let mut h = sha256d(&header);
        h.reverse();
        let hash = hex::encode(h);
        log!("CRITICAL", "BLOCK FOUND by {} ({}) at height {}: {}", worker, ip, job.height, hash);
        let mut record = json!({"height": job.height, "hash": hash, "worker": worker, "ip": ip, "address": address,
                                "diff": share_diff, "value": job.value, "at": now_f()});
        let mut sending = record.clone();
        sending["result"] = json!("sending");
        sending["hex"] = json!(block_hex);
        self.save_found(&sending); // on disk before it goes to the node
        self.submitting.fetch_add(1, Ordering::SeqCst);
        let mut resent = false;
        let mut result = Value::Null;
        for attempt in 1..=SUBMIT_TRIES {
            match self.rpc.call_t("submitblock", json!([block_hex]), 60).await {
                Ok(v) => {
                    result = v;
                    break;
                }
                Err(e) => {
                    let msg = e.to_string();
                    result = json!(format!("error: {}", msg));
                    let warming = msg.contains("-28");
                    if msg.contains("RPC submitblock error") && !warming {
                        break; // the node's own answer: sending it again won't change it
                    }
                    resent = true;
                    log!("CRITICAL", "submitblock {}, try {} of {} failed: {}{}", hash, attempt, SUBMIT_TRIES, msg,
                        if attempt < SUBMIT_TRIES { "; trying again" } else { "" });
                    if attempt < SUBMIT_TRIES {
                        tokio::time::sleep(Duration::from_secs_f64(SUBMIT_RETRY_S)).await;
                    }
                }
            }
        }
        self.submitting.fetch_sub(1, Ordering::SeqCst);
        if result == json!("duplicate") && resent {
            log!("CRITICAL", "submitblock {}: the node already had it from an earlier try", hash);
            result = Value::Null;
        }
        if result.is_null() {
            log!("CRITICAL", "submitblock {}: accepted by the node", hash);
        } else {
            log!("CRITICAL", "submitblock {}: the node said {}", hash, result);
        }
        record["result"] = result;
        let mut full = record.clone();
        full["hex"] = json!(block_hex);
        self.save_found(&full);
        self.state.lock().unwrap()["blocks"].as_array_mut().map(|b| b.push(record));
        if let Err(e) = self.save_state() {
            log!("CRITICAL", "couldn't save the state after block {}: {}", hash, e);
        }
        let me = self.clone();
        tokio::spawn(async move {
            if let Err(e) = me.update_template(Upd { clean: true, ..Default::default() }).await {
                log!("WARNING", "template after our block: {}", e);
            }
        });
    }

    // ------------------------------------------------------------------ share statistics

    fn log_share(s: &mut Stats, name: &str, diff: Option<f64>, share: Option<f64>, rejected: Option<&str>, block: bool) {
        s.share_seq += 1;
        let seq = s.share_seq;
        s.share_log.push_back(json!({"seq": seq, "t": now_f(), "worker": name, "diff": diff, "share": share,
                                     "rejected": rejected, "block": block}));
        while s.share_log.len() > 300 {
            s.share_log.pop_front();
        }
    }

    pub fn share_accepted(&self, name: &str, credit: f64, share_diff: f64, now: f64, block: bool) {
        {
            let mut s = self.stats.lock().unwrap();
            Self::log_share(&mut s, name, Some(credit), Some(share_diff), None, block);
            s.accepted += 1;
            s.shares.push_back((now, credit));
            while s.shares.front().map_or(false, |x| x.0 < now - 3600.0) {
                s.shares.pop_front();
            }
            if share_diff > s.best["diff"].as_f64().unwrap_or(0.0) {
                s.best = json!({"diff": share_diff, "worker": name, "at": now});
            }
            if share_diff > s.window_best.0 {
                s.window_best = (share_diff, name.to_string());
            }
        }
        let mut st = self.state.lock().unwrap();
        st["accepted_total"] = json!(st["accepted_total"].as_u64().unwrap_or(0) + 1);
        if share_diff > st["best_ever"]["diff"].as_f64().unwrap_or(0.0) {
            st["best_ever"] = json!({"diff": share_diff, "worker": name, "at": now});
        }
    }

    pub fn share_rejected(&self, name: &str, reason: &str) {
        let mut s = self.stats.lock().unwrap();
        *s.rejected.entry(reason.to_string()).or_insert(0) += 1;
        Self::log_share(&mut s, name, None, None, Some(reason), false);
    }

    // ------------------------------------------------------------------ loops

    /// The backstop: the best block every block_poll_ms, or every 2 s while the node's block signal is connected.
    async fn watch_blocks(self: Arc<Self>) {
        loop {
            match self.rpc.call_t("getbestblockhash", json!([]), 5).await {
                Ok(Value::String(best)) => {
                    if best != self.tip() && self.longpoll_waiting.load(Ordering::Relaxed) {
                        // the long-poll brings this block's template sooner: give it a moment
                        for _ in 0..30 {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            if self.tip() == best {
                                break;
                            }
                        }
                    }
                    if best != self.tip() {
                        let u = Upd { clean: true, new_tip: Some(best), source: Some("block poll".into()), ..Default::default() };
                        if let Err(e) = self.update_template(u).await {
                            log!("WARNING", "block watch: {}", e);
                            tokio::time::sleep(Duration::from_secs(2)).await;
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    log!("WARNING", "block watch: {}", e);
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
            let ms = if self.zmq_up.load(Ordering::Relaxed) { 2000 } else { self.cfg.block_poll_ms };
            tokio::time::sleep(Duration::from_millis(ms)).await;
        }
    }

    /// getblocktemplate long-polling: the node answers the moment its tip changes, with the template built.
    async fn longpoll_blocks(self: Arc<Self>) {
        let mut lpid: Option<String> = None;
        loop {
            let req = match &lpid {
                Some(id) => json!([{"rules": ["segwit"], "longpollid": id}]),
                None => json!([{"rules": ["segwit"]}]),
            };
            let t0 = Instant::now();
            self.longpoll_waiting.store(lpid.is_some(), Ordering::Relaxed);
            match self.rpc.call_t("getblocktemplate", req, 900).await {
                Err(e) => {
                    self.longpoll_waiting.store(false, Ordering::Relaxed);
                    if t0.elapsed() < Duration::from_secs(20) {
                        // a real failure; a long wait cut off by the node's HTTP timeout is not
                        log!("WARNING", "block long-poll: {}", e);
                        lpid = None;
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
                Ok(tpl) => {
                    lpid = tpl["longpollid"].as_str().map(String::from);
                    if prev_of(&tpl) != self.tip() {
                        let u = Upd { clean: true, tpl: Some(tpl), source: Some("long-poll".into()), ..Default::default() };
                        if let Err(e) = self.update_template(u).await {
                            log!("WARNING", "block long-poll: {}", e);
                        }
                    }
                }
            }
        }
    }

    async fn refresh_templates(self: Arc<Self>) {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let due = self.current().map_or(false, |j| j.created.elapsed().as_secs_f64() >= self.refresh_s());
            if due {
                if let Err(e) = self.update_template(Upd::default()).await {
                    log!("WARNING", "template refresh: {}", e);
                }
            }
        }
    }

    async fn zmq_loop(self: Arc<Self>) {
        let url = self.cfg.zmq_hashblock.clone();
        let addr = url.trim_start_matches("tcp://").to_string();
        loop {
            match ZmqSub::connect(&addr, b"hashblock").await {
                Ok(mut sub) => {
                    self.zmq_up.store(true, Ordering::Relaxed);
                    log!("INFO", "listening for new blocks on {}", url);
                    loop {
                        match sub.recv().await {
                            Ok(parts) => {
                                if parts.len() >= 2 && parts[0] == b"hashblock" {
                                    tokio::spawn(self.clone().on_block_signal(hex::encode(&parts[1])));
                                }
                            }
                            Err(e) => {
                                log!("WARNING", "block signal {}: {}; retrying in 5 s", url, e);
                                break;
                            }
                        }
                    }
                    self.zmq_up.store(false, Ordering::Relaxed);
                }
                Err(e) => log!("WARNING", "block signal {}: {}; retrying in 5 s", url, e),
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }

    async fn housekeeping(self: Arc<Self>) {
        let mut n = 0u64;
        loop {
            tokio::time::sleep(Duration::from_secs(15)).await;
            n += 1;
            let now = now_f();
            if n % 4 == 0 {
                trim_memory();
                self.remember_diffs(now);
                if let Err(e) = self.save_state() {
                    log!("WARNING", "couldn't save the state: {}", e);
                }
            }
            if n % 20 == 0 {
                self.log_stats(now);
            }
        }
    }

    /// Keep each settled miner's automatic difficulty, so it starts there after a restart.
    fn remember_diffs(&self, now: f64) {
        let settled: Vec<(String, f64)> = self.workers.lock().unwrap().values()
            .map(|h| {
                let i = h.info.lock().unwrap();
                (i.name.clone(), i.diff, now - i.connected > 180.0 && now - i.last_share < 60.0)
            })
            .filter(|x| x.2).map(|x| (x.0, x.1)).collect();
        let mut st = self.state.lock().unwrap();
        for (name, diff) in settled {
            if st["overrides"].get(&name).and_then(|o| o.get("diff")).is_none() {
                st["last_diff"][name] = json!([diff, now]);
            }
        }
    }

    fn log_stats(&self, now: f64) {
        let workers = self.worker_count();
        let mut s = self.stats.lock().unwrap();
        let rejected_total: u64 = s.rejected.values().sum();
        let accepted = s.accepted - s.stats_mark.0;
        let rejected = rejected_total - s.stats_mark.1;
        let th = hashrate(s.shares.iter(), 300f64.min((now - self.started).max(60.0)), now) / 1e12;
        let best = if s.window_best.0 > 0.0 { format!(", best {} ({})", fmt_diff(s.window_best.0), s.window_best.1) } else { String::new() };
        log!("INFO", "stats: {} workers, {:.1} TH/s (5 min), {} shares accepted, {} rejected in 5 min{}",
            workers, th, commas(accepted), rejected, best);
        s.stats_mark = (s.accepted, rejected_total);
        s.window_best = (0.0, String::new());
    }

    pub fn save_state(&self) -> std::io::Result<()> {
        let body = self.state.lock().unwrap().to_string();
        let tmp = format!("{}.tmp", self.state_path);
        std::fs::write(&tmp, body)?;
        std::fs::rename(&tmp, &self.state_path)
    }

    // ------------------------------------------------------------------ start and stop

    pub async fn start(self: &Arc<Self>) -> Result<()> {
        if let Some(saved) = self.setting("default_address").and_then(|v| v.as_str().map(String::from)) {
            self.default.write().unwrap().0 = saved; // set on the dashboard; wins over the environment
        }
        let address = self.default_address();
        let spk = if address.is_empty() { None } else { self.script_for(&address).await };
        if spk.is_none() {
            log!("WARNING", "no payout address set yet ({}): until one is, only miners with a Bitcoin address in \
                             their username can connect", if address.is_empty() { "none given" } else { "the node says it isn't valid" });
        }
        self.default.write().unwrap().1 = spk;
        *self.chain.write().unwrap() = self.rpc.call("getblockchaininfo", json!([])).await.ok()
            .and_then(|i| i["chain"].as_str().map(String::from)); // empty block first only once we know it's mainnet
        self.update_template(Upd { clean: true, ..Default::default() }).await?;
        if !self.cfg.zmq_hashblock.is_empty() {
            tokio::spawn(self.clone().zmq_loop());
        }
        tokio::spawn(self.clone().watch_blocks());
        tokio::spawn(self.clone().longpoll_blocks());
        tokio::spawn(self.clone().refresh_templates());
        tokio::spawn(self.clone().housekeeping());
        Ok(())
    }

    /// The stop signal: let a block on its way to the node get there, keep the state, then exit.
    pub async fn stop(&self) {
        log!("INFO", "stopping");
        for _ in 0..250 {
            if self.submitting.load(Ordering::SeqCst) == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        self.remember_diffs(now_f());
        if let Err(e) = self.save_state() {
            log!("WARNING", "couldn't save the state: {}", e);
        }
        log!("INFO", "stopped");
    }

    // ------------------------------------------------------------------ API

    pub fn snapshot(&self) -> Value {
        let now = now_f();
        let up = now - self.started;
        let job = self.current();
        let (s5, s1h) = (300f64.min(up.max(60.0)), 3600f64.min(up.max(60.0)));
        let workers: Vec<Value> = {
            let w = self.workers.lock().unwrap();
            let mut v: Vec<Value> = w.values().map(|h| {
                let i = h.info.lock().unwrap();
                let since = (now - i.connected).max(60.0);
                json!({
                    "name": i.name, "ip": i.ip, "agent": i.agent, "address": i.address, "diff": i.diff,
                    "switches_at_once": i.switches_at_once, "accepted": i.accepted, "rejected": i.rejected,
                    "best": i.best, "last_share": i.last_share, "last_height": i.last_height, "connected": i.connected,
                    "hashrate_5m": hashrate(i.shares.iter(), 300f64.min(since), now),
                    "hashrate_1h": hashrate(i.shares.iter(), 3600f64.min(since), now),
                })
            }).collect();
            v.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
            v
        };
        let mut workers = workers;
        for w in workers.iter_mut() {
            w["override"] = self.override_for(w["name"].as_str().unwrap_or(""));
        }
        let s = self.stats.lock().unwrap();
        let st = self.state.lock().unwrap();
        let settings = st["settings"].clone();
        let get_f = |k: &str, d: f64| settings.get(k).and_then(|v| v.as_f64()).unwrap_or(d);
        json!({
            "now": now, "uptime": up, "engine": "solo45-core", "version": env!("CARGO_PKG_VERSION"),
            "pool": {
                "height": job.as_ref().map(|j| j.height),
                "prev": self.tip(),
                "txs": job.as_ref().map_or(0, |j| j.tx_data.len()),
                "fees": job.as_ref().map_or(0, |j| j.fees),
                "reward": job.as_ref().map_or(0, |j| j.value),
                "network_diff": job.as_ref().map_or(0.0, |j| target_diff(&j.target)),
                "template_age": job.as_ref().map(|j| j.created.elapsed().as_secs_f64()),
                "empty_job": job.as_ref().map_or(false, |j| j.empty),
                "hashrate_5m": hashrate(s.shares.iter(), s5, now),
                "hashrate_1h": hashrate(s.shares.iter(), s1h, now),
                "accepted": s.accepted,
                "rejected": s.rejected,
                "best": s.best,
                "policy": {"mode": "off", "available": false},
                "best_ever": st["best_ever"],
                "blocks": st["blocks"],
                "last_switch": s.last_switch,
                "proposal": s.proposal,
                "timing": {"build_ms": median(s.build_times.iter()), "blocks": s.build_times.len(),
                           "check_ms": median(s.check_times.iter()), "checks": s.check_times.len(),
                           "check_every_s": (check_every_s(&s) * 10.0).round() / 10.0},
                "default_address": self.default_address(),
                "force_default_address": settings.get("force_default_address").and_then(|v| v.as_bool()).unwrap_or(self.cfg.force_default_address),
                "empty_first": settings.get("empty_first").and_then(|v| v.as_bool()).unwrap_or(self.cfg.empty_first),
                "empty_hold_s": get_f("empty_hold_s", self.cfg.empty_hold_s).clamp(0.0, 40.0),
                "needs_setup": self.default.read().unwrap().1.is_none(),
                "tag": self.cfg.coinbase_tag,
                "stratum_port": self.cfg.stratum_port,
                "template_refresh_s": get_f("template_refresh_s", self.cfg.template_refresh_s),
                "zmq": self.zmq_up.load(Ordering::Relaxed),
                "stall_guard": {"seconds": 0, "events": []},
            },
            "workers": workers,
        })
    }

    pub fn shares_since(&self, since: u64) -> Value {
        let s = self.stats.lock().unwrap();
        json!({"shares": s.share_log.iter().filter(|x| x["seq"].as_u64().unwrap_or(0) > since).collect::<Vec<_>>()})
    }

    pub fn export_settings(&self) -> Value {
        let st = self.state.lock().unwrap();
        json!({"settings": st["settings"], "overrides": st["overrides"], "policy": null, "last_diff": st["last_diff"]})
    }

    /// Per-miner difficulty settings. Only share difficulty changes, never block odds.
    pub fn set_override(&self, data: &Value) -> (u16, Value) {
        let name: String = match &data["name"] {
            Value::String(s) => s.chars().take(64).collect(),
            _ => String::new(),
        };
        if name.is_empty() {
            return (400, json!({"error": "name is required"}));
        }
        let num = |k: &str| data.get(k).filter(|v| !v.is_null()).map(|v| v.as_f64());
        let ov = match (num("diff"), num("share_seconds")) {
            (Some(None), _) | (None, Some(None)) => return (400, json!({"error": "bad request"})),
            (Some(Some(d)), _) => {
                if !(self.cfg.min_diff <= d && d <= MAX_DIFF) {
                    return (400, json!({"error": format!("diff must be between {} and 1e9", g3(self.cfg.min_diff))}));
                }
                json!({"diff": d})
            }
            (None, Some(Some(s))) => {
                if !(1.0..=300.0).contains(&s) {
                    return (400, json!({"error": "share_seconds must be between 1 and 300"}));
                }
                json!({"share_seconds": s})
            }
            (None, None) => json!({}), // back to automatic
        };
        {
            let mut st = self.state.lock().unwrap();
            if ov.as_object().map_or(true, |o| o.is_empty()) {
                st["overrides"].as_object_mut().map(|o| o.remove(&name));
            } else {
                st["overrides"][&name] = ov.clone();
            }
        }
        let _ = self.save_state();
        for h in self.workers.lock().unwrap().values() {
            let (same, diff) = {
                let i = h.info.lock().unwrap();
                (i.name == name, i.diff)
            };
            if same {
                let _ = h.ctl.send(Ctl::SetDiff(ov.get("diff").and_then(|d| d.as_f64()).unwrap_or(diff)));
            }
        }
        log!("INFO", "settings for {}: {}", name, if ov.as_object().map_or(true, |o| o.is_empty()) { "automatic".to_string() } else { ov.to_string() });
        (200, json!({"ok": true, "name": name, "override": ov}))
    }

    /// Pool-wide settings from the dashboard; they take effect at once.
    pub async fn set_settings(self: &Arc<Self>, data: &Value) -> (u16, Value) {
        let keys = ["template_refresh_s", "stall_guard_s", "force_default_address", "empty_first", "empty_hold_s"];
        if !keys.iter().any(|k| data.get(*k).is_some()) {
            return (400, json!({"error": "nothing to change"}));
        }
        for k in ["force_default_address", "empty_first"] {
            if data.get(k).map_or(false, |v| !v.is_boolean()) {
                return (400, json!({"error": format!("{} must be true or false", k)}));
            }
        }
        let num = |k: &str| data.get(k).map(|v| v.as_f64());
        if let Some(h) = num("empty_hold_s") {
            match h {
                Some(h) if (1.0..=40.0).contains(&h) => {}
                _ => return (400, json!({"error": "the empty template hold must be 1 to 40 seconds"})),
            }
        }
        if let Some(r) = num("template_refresh_s") {
            match r {
                Some(r) if (1.0..=120.0).contains(&r) => {}
                _ => return (400, json!({"error": "the job update interval must be between 1 and 120 seconds"})),
            }
        }
        if let Some(g) = num("stall_guard_s") {
            match g {
                Some(g) if g == 0.0 || (20.0..=600.0).contains(&g) => {}
                _ => return (400, json!({"error": "the stall guard must be 20 to 600 seconds, or 0 for off"})),
            }
        }
        let repay = data.get("force_default_address").and_then(|v| v.as_bool()).map_or(false, |f| f != self.force_default());
        {
            let mut st = self.state.lock().unwrap();
            for k in keys {
                if let Some(v) = data.get(k) {
                    st["settings"][k] = v.clone();
                    log!("INFO", "setting {} = {}", k, v);
                }
            }
        }
        if repay {
            self.repay_workers().await;
        }
        let _ = self.save_state();
        (200, json!({"ok": true, "template_refresh_s": self.refresh_s(), "force_default_address": self.force_default(),
                     "empty_first": self.empty_first_on(), "empty_hold_s": self.empty_hold_s(),
                     "stall_guard_s": self.setting("stall_guard_s").unwrap_or(json!(60))}))
    }

    /// Point connected miners at the address they should pay now; they get it with a fresh job.
    async fn repay_workers(self: &Arc<Self>) {
        let list: Vec<(Arc<Mutex<WorkerInfo>>, String)> = self.workers.lock().unwrap().values()
            .map(|h| (h.info.clone(), h.info.lock().unwrap().user.clone())).collect();
        let mut changed = 0;
        for (info, user) in list {
            if let Some((address, spk)) = self.payout_for(&user).await {
                let mut i = info.lock().unwrap();
                if spk != i.spk {
                    i.address = address;
                    i.spk = spk;
                    changed += 1;
                }
            }
        }
        if changed > 0 {
            log!("INFO", "{} miner{} now pay a different address", changed, if changed == 1 { "" } else { "s" });
            let me = self.clone();
            tokio::spawn(async move {
                let _ = me.update_template(Upd { clean: true, ..Default::default() }).await;
            });
        }
    }

    /// The payout address for miners that don't put their own address in the username.
    pub async fn set_payout(self: &Arc<Self>, data: &Value) -> (u16, Value) {
        let address = data["address"].as_str().unwrap_or("").trim().to_string();
        let spk = if address.is_empty() { None } else { self.script_for(&address).await };
        let Some(spk) = spk else {
            return (400, json!({"error": "your node says that isn't a valid Bitcoin address"}));
        };
        let old = std::mem::replace(&mut *self.default.write().unwrap(), (address.clone(), Some(spk.clone()))).0;
        self.state.lock().unwrap()["settings"]["default_address"] = json!(address);
        let _ = self.save_state();
        let all = self.pays_default();
        for h in self.workers.lock().unwrap().values() {
            let mut i = h.info.lock().unwrap();
            if i.address == old || all {
                i.address = address.clone();
                i.spk = spk.clone();
            }
        }
        log!("INFO", "payout address set to {}", address);
        let me = self.clone();
        tokio::spawn(async move {
            let _ = me.update_template(Upd { clean: true, ..Default::default() }).await;
        });
        (200, json!({"ok": true, "address": address}))
    }
}

/// glibc keeps memory the pool freed (each template's JSON is several MB); hand it back to the system, like
/// pool.py's malloc_trim. Does nothing on other C libraries.
fn trim_memory() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        extern "C" {
            fn malloc_trim(pad: usize) -> i32;
        }
        unsafe {
            malloc_trim(0);
        }
    }
}

/// How often a job refresh (same block) gets the node's check: every 10 s at most, and never more than 1/60 of
/// the time (the node holds its main lock while it checks). New-block jobs are always checked.
fn check_every_s(s: &Stats) -> f64 {
    10f64.max(60.0 * median(s.check_times.iter()).unwrap_or(0) as f64 / 1000.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_template_like_pool_py() {
        let hdr = json!({"height": 976754, "hash": "00ab", "bits": "17023a04", "mediantime": 1_800_000_000u64});
        let t = empty_template(&hdr, 0x20000000, 1_700_000_000.0).unwrap();
        assert_eq!(t["height"], 976755);
        assert_eq!(t["coinbasevalue"], 312_500_000u64);
        assert_eq!(t["curtime"], 1_800_000_001u64); // never before mintime
        assert_eq!(t["transactions"], json!([]));
        // the first block of a difficulty period can't copy the bits
        let hdr2 = json!({"height": 2016 * 485 - 1, "hash": "00", "bits": "17023a04", "mediantime": 1});
        assert!(empty_template(&hdr2, 0x20000000, 0.0).is_none());
    }
}
