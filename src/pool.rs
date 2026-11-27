//! Pool-wide state: configuration, jobs, new-block detection (ZMQ signal, long-poll, tip poll), empty block
//! first, the node's block check, payouts, found blocks, statistics and saved state.
//! Mirrors the Pool class in Solo45's pool.py, with its stall guard and template policy.

use crate::job::{Job, TxCache, EN1_SIZE, EN2_SIZE};
use crate::log;
use crate::policy;
use crate::rpc::{shellexpand, Rpc};
use crate::stallguard::StallGuard;
use crate::util::{address_plausible, commas, fmt_diff, g3, hashrate, median, now_f, sha256d, target_diff};
use crate::zmq::ZmqSub;
use anyhow::Result;
use serde_json::{json, Map, Value};
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
/// A found block goes to the node again while it can't be reached or is still starting: every SUBMIT_RETRY_S for the
/// first SUBMIT_TRIES tries, then every SUBMIT_SLOW_S, and after SUBMIT_SLOWER_AFTER_S every SUBMIT_IDLE_S for as long
/// as it takes (a node restart can take many minutes, and about one time in three the network has not found the next
/// block 10 minutes later, so the block can still count). Only the node's own verdict ends it; until then the block
/// stays saved as "sending", so a restart of the pool sends it again too.
pub const SUBMIT_TRIES: u32 = 6;
pub const SUBMIT_RETRY_S: f64 = 2.0;
pub const SUBMIT_SLOW_S: f64 = 5.0;
pub const SUBMIT_SLOWER_AFTER_S: f64 = 600.0;
pub const SUBMIT_IDLE_S: f64 = 30.0;
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
    pub sv2_port: u16,
    /// SOLO45_WEB_READERS: addresses or container names (resolved every minute: an app without a fixed IP)
    pub web_readers: Vec<String>,
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
    /// Bitcoin Core's IPC socket (node.sock, with the node's -ipcbind=unix): templates over IPC; "" = getblocktemplate only
    pub ipc_socket: String,
    pub stall_guard_s: f64,
    /// how long a found block is resent every SUBMIT_SLOW_S before the tries drop to every SUBMIT_IDLE_S
    pub submit_slower_after_s: f64,
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
            sv2_port: env("SOLO45_SV2_PORT", 0), // Stratum V2 (encrypted); 0 = off
            web_readers: std::env::var("SOLO45_WEB_READERS").unwrap_or_default().split(',')
                .map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(), // e.g. the Solo45 dashboard's container
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
            ipc_socket: env("SOLO45_IPC_SOCKET", String::new()),
            stall_guard_s: env("SOLO45_STALL_GUARD_S", 60.0), // 0 = off
            submit_slower_after_s: env("SOLO45_SUBMIT_SLOWER_AFTER_S", SUBMIT_SLOWER_AFTER_S), // tests shorten it
            data_dir: shellexpand(&env("SOLO45_DATA_DIR", ".".to_string())),
        }
    }
}

/// The node's answer about an address (Pool::lookup_script).
pub enum Lookup {
    Script(Vec<u8>),
    Invalid,
    /// the node couldn't be asked (down, starting, too slow)
    NoAnswer,
}

/// Where a miner's blocks are paid (Pool::payout_for).
pub enum Payout {
    To(String, Vec<u8>),
    /// no payout address is set and the username has none
    NoAddress,
    /// the username may hold the miner's own address, but the node can't check it right now
    NoAnswer,
}

/// state.json as last saved. When it can't be read: the unreadable file is kept as state.json.bad-<time>, and its
/// backup state.json.bak (written every 10 minutes) is used. Returns (state, new install); with neither file readable
/// the pool starts like a new install, loudly.
fn load_state(path: &str) -> (Value, bool) {
    let bak = format!("{}.bak", path);
    let exists = |p: &str| std::path::Path::new(p).exists();
    let read = |p: &str| -> std::result::Result<Value, String> {
        let text = std::fs::read_to_string(p).map_err(|e| e.to_string())?;
        match serde_json::from_str::<Value>(&text) {
            Ok(v) if v.is_object() => Ok(v),
            Ok(_) => Err("it doesn't hold the pool's settings".to_string()),
            Err(e) => Err(e.to_string()),
        }
    };
    if !exists(path) && !exists(&bak) {
        return (json!({}), true);
    }
    let why = match read(path) {
        Ok(v) => return (v, false),
        Err(e) => if exists(path) { e } else { "it is missing".to_string() },
    };
    let mut kept = String::new();
    if exists(path) {
        let aside = format!("{}.bad-{}", path, now_f() as u64);
        if std::fs::rename(path, &aside).is_ok() {
            kept = format!("; the unreadable file is kept as {}", aside);
        }
    }
    match read(&bak) {
        Ok(v) => {
            log!("ERROR", "state.json can't be read ({}): using its backup state.json.bak (a setting changed in the last \
                           10 minutes may be missing: check the Settings tab){}", why, kept);
            (v, false)
        }
        Err(e) => {
            log!("ERROR", "state.json can't be read ({}) and neither can its backup ({}): starting like a new install. \
                           Enter the payout address again; per-miner settings and best shares are gone{}", why, e, kept);
            (json!({}), true)
        }
    }
}

/// Write a file so that a crash or power cut leaves either the old or the new contents: a temporary file, flushed to
/// the disk, then renamed over the old one.
fn write_synced(path: &str, body: &str) -> std::io::Result<()> {
    let tmp = format!("{}.tmp", path);
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(body.as_bytes())?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

#[derive(Clone)]
pub struct NewJob {
    pub job: Arc<Job>,
    pub clean: bool,
    /// the miners' earlier work for this block must not be used any more (the node refused that job): Stratum V2
    /// channels then get the new job the way a new block's work goes out, so older jobs go stale at once
    pub flush: bool,
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
    /// "V1", "SV2 extended" or "SV2 standard"
    pub protocol: &'static str,
}

impl WorkerInfo {
    pub fn new(ip: &str, now: f64) -> WorkerInfo {
        WorkerInfo {
            name: String::new(), ip: ip.to_string(), agent: String::new(), user: String::new(), address: String::new(),
            spk: Vec::new(), diff: 0.0, switches_at_once: false, accepted: 0, rejected: BTreeMap::new(), best: 0.0,
            last_share: 0.0, last_height: None, connected: now, shares: VecDeque::new(), protocol: "V1",
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
    /// Stratum V2: the last new block's work reaching SV2 channels (job made -> sent), and recent times
    pub sv2_switch: Value,
    pub sv2_times: VecDeque<u64>,
    /// one reading a minute for the last 24 h: [time, pool TH/s over 5 min, miners]
    pub history: VecDeque<(u64, f64, usize)>,
    /// the last 30 new blocks: how fast their work went out (V1, SV2), when the full template followed, the node's check
    pub recent: VecDeque<Value>,
    /// one reading a minute per miner name for the last 24 h: (time, TH/s over 5 min); for the per-miner chart
    pub worker_history: HashMap<String, VecDeque<(u64, f64)>>,
}

const RECENT_BLOCKS: usize = 30;

impl Stats {
    fn recent_for(&mut self, height: u64) -> Option<&mut Value> {
        self.recent.iter_mut().rev().find(|r| r["height"].as_u64() == Some(height))
    }
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
    /// see NewJob::flush
    pub flush: bool,
    /// have the node check this job now, not at the next routine check (a policy or payout change: a new kind of job)
    pub check: bool,
    /// a template the node already built (the long-poll's reply)
    pub tpl: Option<Value>,
    /// the block that prompted this; nothing to do if another path already made its job
    pub new_tip: Option<String>,
    pub source: Option<String>,
    /// the empty hold just ended (or the empty job failed its check): send the full template now
    pub fill: bool,
    /// a routine refresh whose template (in tpl) was fetched before taking the template lock, so a slow node
    /// never makes a new block's work wait behind it
    pub refresh: bool,
}

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The template policy's settings and what it did to recent blocks (pool.py's policy_* attributes).
pub struct PolicyState {
    pub cfg: Value,
    heights: VecDeque<Value>, // the last ~144 blocks' entries, oldest first (one per height)
    pub fallback_height: Option<u64>, // a filtered job failed the node's block check at this height
    history: Vec<Value>,      // finished blocks, last 30 days (policy-blocks.jsonl)
    file_lines: usize,
    path: String,
}

const POLICY_KEEP: [&str; 13] = ["height", "at", "mode", "filtered", "txs", "fees", "skipped", "fees_skipped",
                                 "weight_skipped", "by_rule", "watched", "fees_watched", "watch_by_rule"];
const DAY: f64 = 86400.0;

impl PolicyState {
    fn load(cfg: Value, path: String) -> PolicyState {
        let mut p = PolicyState { cfg, heights: VecDeque::new(), fallback_height: None, history: vec![], file_lines: 0, path };
        let cutoff = now_f() - 30.0 * DAY;
        let mut keep: BTreeMap<u64, Value> = BTreeMap::new();
        if let Ok(text) = std::fs::read_to_string(&p.path) {
            for line in text.lines() {
                p.file_lines += 1;
                if let Ok(e) = serde_json::from_str::<Value>(line) {
                    if e["at"].as_f64().unwrap_or(0.0) >= cutoff {
                        if let Some(h) = e["height"].as_u64() {
                            keep.insert(h, e); // a later line for the same height (after a reorg) wins
                        }
                    }
                }
            }
        }
        p.history = keep.into_values().collect();
        if p.file_lines > p.history.len() {
            p.write_history();
        }
        for e in p.history.iter().rev().take(144).rev() {
            let mut e = e.clone();
            e["saved"] = json!(true);
            p.heights.push_back(e);
        }
        p
    }

    fn write_history(&mut self) {
        let tmp = format!("{}.tmp", self.path);
        let body: String = self.history.iter().map(|e| format!("{}\n", e)).collect();
        match std::fs::write(&tmp, body).and_then(|_| std::fs::rename(&tmp, &self.path)) {
            Ok(()) => self.file_lines = self.history.len(),
            Err(e) => log!("WARNING", "couldn't save the policy history: {}", e),
        }
    }

    /// Keep a finished block's numbers, so the policy totals survive restarts and updates.
    fn save_block(&mut self, entry: &mut Value) {
        entry["saved"] = json!(true);
        let mut e = Map::new();
        for k in POLICY_KEEP {
            e.insert(k.to_string(), entry.get(k).cloned().unwrap_or(Value::Null));
        }
        let cutoff = now_f() - 30.0 * DAY;
        self.history.retain(|x| x["at"].as_f64().unwrap_or(0.0) >= cutoff);
        let e = Value::Object(e);
        self.history.push(e.clone());
        if self.file_lines > self.history.len() + 144 {
            self.write_history(); // about once a day, drop old lines from the file
            return;
        }
        let r = std::fs::OpenOptions::new().create(true).append(true).open(&self.path)
            .and_then(|mut f| writeln!(f, "{}", e));
        match r {
            Ok(()) => self.file_lines += 1,
            Err(err) => log!("WARNING", "couldn't save the policy history: {}", err),
        }
    }

    fn view(&self) -> Value {
        let done: Vec<&Value> = self.heights.iter().filter(|e| e["saved"] == true).collect(); // found by the network
        let current = self.heights.back().filter(|e| e["saved"] != true).cloned(); // the block being mined
        let now = now_f();
        let sum = |es: &[&Value], k: &str| es.iter().map(|e| e[k].as_u64().unwrap_or(0)).sum::<u64>();
        let periods: Vec<Value> = [("24 hours", DAY), ("7 days", 7.0 * DAY), ("30 days", 30.0 * DAY)].iter().map(|(label, secs)| {
            let es: Vec<&Value> = self.history.iter().filter(|e| e["at"].as_f64().unwrap_or(0.0) >= now - secs).collect();
            let mut v = json!({"label": label, "seconds": secs, "blocks": es.len()});
            for k in ["txs", "fees", "skipped", "fees_skipped", "watched", "fees_watched"] {
                v[k] = json!(sum(&es, k));
            }
            v
        }).collect();
        let mut totals = json!({"blocks": done.len(), "skipped": sum(&done, "skipped"), "fees_skipped": sum(&done, "fees_skipped"),
                                "by_rule": {}, "watched": sum(&done, "watched"), "fees_watched": sum(&done, "fees_watched"),
                                "watch_by_rule": {}});
        for e in &done {
            for key in ["by_rule", "watch_by_rule"] {
                for (k, v) in e[key].as_object().into_iter().flatten() {
                    let t = &mut totals[key][k];
                    let (txs, fees) = (t["txs"].as_u64().unwrap_or(0), t["fees"].as_u64().unwrap_or(0));
                    *t = json!({"txs": txs + v["txs"].as_u64().unwrap_or(0), "fees": fees + v["fees"].as_u64().unwrap_or(0)});
                }
            }
        }
        json!({"mode": self.cfg["mode"], "rules": self.cfg["rules"], "names": policy::rule_names(), "current": current,
               "recent": done.iter().rev().take(12).collect::<Vec<_>>(), "totals": totals, "periods": periods,
               "history_since": self.history.first().map(|e| e["at"].clone()), "fallback_height": self.fallback_height})
    }
}

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
    /// one save at a time (they share a temporary file); holds when state.json.bak was last written
    save: Mutex<Option<Instant>>,
    pub submitting: AtomicUsize,
    tpl: tokio::sync::Mutex<TplState>,
    chain: RwLock<Option<String>>,
    /// the IPC template source, when SOLO45_IPC_SOCKET is set
    pub ipc: std::sync::OnceLock<Arc<crate::ipc::Ipc>>,
    /// templates used from IPC / from getblocktemplate
    tpl_ipc: AtomicU64,
    tpl_rpc: AtomicU64,
    /// why the last template came from getblocktemplate although IPC is set up, and when (for the API)
    tpl_fallback: Mutex<Option<(&'static str, Instant)>>,
    pub zmq_up: AtomicBool,
    longpoll_waiting: AtomicBool,
    guard: Mutex<StallGuard>,
    policy: Mutex<PolicyState>,
    /// the Stratum V2 port and authority key, for the API (set at start when SV2 is on)
    pub sv2_info: RwLock<Value>,
    /// the readers' current addresses (SOLO45_WEB_READERS: IPs as given, names looked up every minute)
    pub readers: RwLock<Vec<std::net::Ipv4Addr>>,
    /// the latest hardware readings (temperature, fan, watts) of each connected miner, by IP (devices.rs)
    pub devices: RwLock<HashMap<String, Value>>,
    pub started: f64,
}

impl Pool {
    pub fn new(cfg: Config) -> Result<Arc<Pool>> {
        let rpc = Rpc::new(&cfg.rpc_url, Some(cfg.rpc_cookie.clone()), &cfg.rpc_user, &cfg.rpc_pass)?;
        let (job_tx, _) = broadcast::channel(16);
        let seed = (now_f() * 1e6) as u64;
        std::fs::create_dir_all(&cfg.data_dir).ok();
        let state_path = format!("{}/state.json", cfg.data_dir);
        let (mut state, new_install) = load_state(&state_path);
        for (k, d) in [("best_ever", json!({"diff": 0.0})), ("blocks", json!([])), ("accepted_total", json!(0)),
                       ("overrides", json!({})), ("settings", json!({})), ("last_diff", json!({}))] {
            if state.get(k).is_none() {
                state[k] = d;
            }
        }
        if new_install {
            // a new install (or one whose saved state is lost) pays every miner to the payout address; older ones keep
            // what they had
            state["settings"]["force_default_address"] = json!(true);
        }
        let default = (cfg.default_address.clone(), None);
        let events = state["stall_events"].as_array().cloned().unwrap_or_default();
        let pcfg = policy::load_config(&state["policy"]);
        let pstate = PolicyState::load(pcfg, format!("{}/policy-blocks.jsonl", cfg.data_dir));
        Ok(Arc::new(Pool {
            guard: Mutex::new(StallGuard::new(events)),
            policy: Mutex::new(pstate),
            sv2_info: RwLock::new(Value::Null),
            readers: RwLock::new(Vec::new()), // filled by resolve_readers
            devices: RwLock::new(HashMap::new()), // filled by devices::poll_loop
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
            save: Mutex::new(None),
            submitting: AtomicUsize::new(0),
            tpl: tokio::sync::Mutex::new(TplState::default()),
            chain: RwLock::new(None),
            ipc: std::sync::OnceLock::new(),
            tpl_ipc: AtomicU64::new(0),
            tpl_rpc: AtomicU64::new(0),
            tpl_fallback: Mutex::new(None),
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

    pub fn stall_guard_s(&self) -> f64 {
        self.setting("stall_guard_s").and_then(|v| v.as_f64()).unwrap_or(self.cfg.stall_guard_s)
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
    pub async fn script_for(&self, address: &str) -> Option<Vec<u8>> {
        match self.lookup_script(address).await {
            Lookup::Script(s) => Some(s),
            Lookup::Invalid | Lookup::NoAnswer => None,
        }
    }

    /// What the node says about an address: its output script, not a valid address, or no answer (the node is down,
    /// starting or too slow), which is kept apart so "couldn't ask" is never taken for "isn't an address".
    /// Junk usernames cost nothing and the cache keeps at most SPK_CACHE_MAX entries (v0.1.65 hardening).
    pub async fn lookup_script(&self, address: &str) -> Lookup {
        let known = |v: Option<Vec<u8>>| v.map_or(Lookup::Invalid, Lookup::Script);
        if !address_plausible(address) {
            return Lookup::Invalid;
        }
        if let Some(v) = self.spk_cache.lock().unwrap().0.get(address) {
            return known(v.clone());
        }
        let Ok(r) = self.rpc.call("validateaddress", json!([address])).await else { return Lookup::NoAnswer };
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
        known(spk)
    }

    /// The (address, script) a miner with this username pays: the payout address when "Always pay my address" is on,
    /// else a valid address at the start of the username, else the payout address. NoAddress if neither works.
    /// NoAnswer when the username starts with what may be the miner's own address but the node can't say right now:
    /// the miner is then refused (it tries again) instead of being paid to the payout address by mistake.
    pub async fn payout_for(&self, user: &str) -> Payout {
        let address = user.split('.').next().unwrap_or("");
        if !self.pays_default() {
            match self.lookup_script(address).await {
                Lookup::Script(s) => return Payout::To(address.to_string(), s),
                Lookup::NoAnswer => return Payout::NoAnswer,
                Lookup::Invalid => {}
            }
        }
        let d = self.default.read().unwrap().clone();
        match d.1 {
            Some(s) => Payout::To(d.0, s),
            None => Payout::NoAddress,
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

    fn note_switch(&self, job: &Job, ms: u64, workers: usize, source: &str) {
        let mut s = self.stats.lock().unwrap();
        let at = now_f();
        s.last_switch = json!({"height": job.height, "ms": ms, "at": at, "workers": workers});
        if workers > 0 {
            push_capped(&mut s.build_times, ms); // not the first job after a start
        }
        s.recent.push_back(json!({"height": job.height, "at": at, "source": source, "v1_ms": ms, "workers": workers,
                                  "empty": job.empty, "txs": job.tx_data.len(), "fees": job.fees}));
        while s.recent.len() > RECENT_BLOCKS {
            s.recent.pop_front();
        }
    }

    /// The full template that followed a new block's empty job.
    fn note_filled(&self, job: &Job) {
        let mut s = self.stats.lock().unwrap();
        if let Some(r) = s.recent_for(job.height) {
            if r["full_after_s"].is_null() {
                r["full_after_s"] = json!(((now_f() - r["at"].as_f64().unwrap_or(0.0)) * 10.0).round() / 10.0);
                r["txs"] = json!(job.tx_data.len());
                r["fees"] = json!(job.fees);
            }
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
                if u.refresh && holding {
                    return Ok(()); // a routine refresh during the hold: the hold's end fetches its own template
                }
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
                if same_tip && !empty && !u.refresh {
                    return Ok(()); // the other block watcher got there first
                }
                let mut clean = u.clean;
                let mut tpl = u.tpl;
                if u.refresh && !same_tip {
                    // the tip moved while the node built this refresh: never mine on an old tip, build it again here
                    tpl = None;
                }
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
                if tpl.is_none() || (same_tip && !u.fill && !u.refresh) {
                    tpl = Some(self.fetch_template().await?);
                }
                let mut tpl = tpl.unwrap();
                if tpl.get("_ipc").is_some() && self.policy.lock().unwrap().cfg["mode"] == "filter" {
                    tpl = self.rpc.call("getblocktemplate", json!([{"rules": ["segwit"]}])).await?;
                }
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
                // template policy: in filter mode work out now what the job leaves out; the counting for watch
                // rules waits until the miners have their work (below)
                let (pcfg, fallback) = {
                    let p = self.policy.lock().unwrap();
                    (p.cfg.clone(), p.fallback_height)
                };
                let mode = pcfg["mode"].as_str().unwrap_or("off").to_string();
                let (mut report, mut filtered_tpl) = (None, None);
                if mode == "filter" {
                    let r = policy::evaluate(&tpl, &pcfg, false);
                    if r.skipped() > 0 && fallback != tpl["height"].as_u64() {
                        filtered_tpl = Some(policy::apply(&tpl, &r));
                    }
                    report = Some(r);
                }
                let filtered = filtered_tpl.is_some();
                let j = {
                    let mut cache = self.tx_cache.lock().unwrap();
                    let mut j = Job::new(&self.next_job_id(), filtered_tpl.as_ref().unwrap_or(&tpl),
                                         self.cfg.coinbase_tag.as_bytes(), &mut cache)?;
                    j.filtered = filtered;
                    Arc::new(j)
                };
                drop(filtered_tpl);
                self.install(&j);
                let workers = self.worker_count();
                let _ = self.job_tx.send(NewJob { job: j.clone(), clean: clean || new_block, flush: u.flush });
                let ms = t0.elapsed().as_millis() as u64;
                if new_block {
                    self.note_switch(&j, ms, workers, u.source.as_deref().unwrap_or("node"));
                } else if filled {
                    self.note_filled(&j);
                }
                if new_block {
                    log!("INFO", "new network block {} ({}), now mining {}{}", j.height - 1, j.prev_hex, j.height,
                        u.source.as_ref().map(|s| format!(" (spotted by the {})", s)).unwrap_or_default());
                }
                let bytes: usize = j.tx_data.iter().map(|t| t.len()).sum();
                log!("INFO", "{} job {} for block {}: {:.8} BTC, {} txs, {} bytes, fees {:.4} BTC (sent to {} workers in {} ms)",
                    if new_block { "new-block" } else if filled { "full" } else { "updated" }, j.id, j.height,
                    j.value as f64 / 1e8, j.tx_data.len(), commas(bytes as u64), j.fees as f64 / 1e8, workers, ms);
                // only counting, so it runs after the miners already have the job
                if mode == "watch" && tpl.get("_ipc").is_some() {
                    // an IPC template has no per-transaction fees: count from the node's getblocktemplate instead
                    let (me, prev, m2, cfg2) = (self.clone(), j.prev_hex.clone(), mode.clone(), pcfg.clone());
                    tokio::spawn(async move {
                        if let Ok(t) = me.rpc.call("getblocktemplate", json!([{"rules": ["segwit"]}])).await {
                            if prev_of(&t) == prev {
                                me.record_policy(policy::evaluate(&t, &cfg2, true), &m2, false);
                            }
                        }
                    });
                } else if mode == "watch" {
                    report = Some(policy::evaluate(&tpl, &pcfg, true));
                } else if let Some(r) = report.as_mut() {
                    policy::add_watch(r, &tpl, &pcfg);
                }
                if let Some(r) = report {
                    self.record_policy(r, &mode, filtered);
                }
                job = j;
            }
            // the node fully checks every new block's work; routine refreshes less often
            let due = {
                let mut s = self.stats.lock().unwrap();
                let due = new_block || filled || u.check || now_f() - s.last_proposal >= check_every_s(&s);
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
        let _ = self.job_tx.send(NewJob { job: j.clone(), clean: true, flush: false });
        let ms = t0.elapsed().as_millis() as u64;
        self.note_switch(&j, ms, workers, source);
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
                    match self.fetch_template().await {
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
        let mut tries = 0u32;
        loop {
            let u = Upd { new_tip: Some(job.prev_hex.clone()), fill: true, ..Default::default() };
            match self.update_template(u).await {
                Ok(()) => break,
                Err(e) => {
                    tries += 1;
                    if tries <= 3 || tries % 30 == 0 {
                        log!("WARNING", "full template after the empty one (try {}): {}; trying again in 2 s", tries, e);
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            if !self.is_current(&job) {
                break; // a newer job (another block, or a refresh) replaced the empty one
            }
        }
    }

    /// The node's ZMQ new-block signal: the first sign of a new block, before its template exists.
    async fn on_block_signal(self: Arc<Self>, bhash: String) {
        self.on_block_signal_from(bhash, "node's block signal").await
    }

    async fn on_block_signal_from(self: Arc<Self>, bhash: String, src: &'static str) {
        if bhash == self.tip() {
            return;
        }
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
            // the block's row shows the check of its newest job (the full template once it is out)
            if let Some(r) = s.recent_for(job.height) {
                r["check_ok"] = json!(ok);
                r["check_ms"] = json!(ms);
            }
            if ok {
                s.proposal_checked.insert(spk);
            }
        }
        if ok {
            log!("INFO", "block check OK for {} (job {}, {} txs) in {} ms", job.height, job.id, job.tx_data.len(), ms);
            return;
        }
        log!("ERROR", "BLOCK PROPOSAL REJECTED at height {}: {}", job.height, res);
        if job.filtered {
            log!("ERROR", "the filtered template for block {} failed the block check; mining the node's own template \
                           for this block instead", job.height);
            self.policy.lock().unwrap().fallback_height = Some(job.height);
            let me = self.clone();
            tokio::spawn(async move {
                let _ = me.update_template(Upd { clean: true, flush: true, check: true, ..Default::default() }).await;
            });
        } else if job.empty {
            log!("ERROR", "the empty template for block {} failed the block check; ending the hold", job.height);
            job.hold_done.notify_one();
        }
    }

    // ------------------------------------------------------------------ found blocks

    /// Append a found block's entry to blocks_found.jsonl. `sync`: wait until it is on the disk; otherwise the
    /// returned file is synced by the caller (in the background, so the block never waits for the disk).
    fn save_found(&self, entry: &Value, sync: bool) -> Option<std::fs::File> {
        let path = format!("{}/blocks_found.jsonl", self.cfg.data_dir);
        let r = std::fs::OpenOptions::new().create(true).append(true).open(&path)
            .and_then(|mut f| {
                writeln!(f, "{}", entry)?;
                if sync {
                    f.sync_all()?;
                }
                Ok(f)
            });
        match r {
            Ok(f) => Some(f),
            Err(e) => {
                log!("CRITICAL", "couldn't save block {} to {}: {}", entry["hash"], path, e);
                None
            }
        }
    }

    /// Save, then submit a found block: tries again for as long as the node can't be reached or is starting (see
    /// SUBMIT_TRIES); the node's own verdict ends it. "duplicate" after a resend means an earlier try got through.
    pub async fn found_block(self: Arc<Self>, worker: String, ip: String, address: String, job: Arc<Job>,
                             header: [u8; 80], coinbase: Vec<u8>, share_diff: f64) {
        let block_hex = hex::encode(job.block(&header, &coinbase));
        let mut h = sha256d(&header);
        h.reverse();
        let hash = hex::encode(h);
        log!("CRITICAL", "BLOCK FOUND by {} ({}) at height {}: {}", worker, ip, job.height, hash);
        let record = json!({"height": job.height, "hash": hash, "worker": worker, "ip": ip, "address": address,
                            "diff": share_diff, "value": job.value, "at": now_f()});
        let mut sending = record.clone();
        sending["result"] = json!("sending");
        sending["hex"] = json!(block_hex);
        // written before it goes to the node (a pool restart resends it); the disk sync runs while it is sent, so
        // a power cut can't lose it either and the block doesn't wait for the disk
        if let Some(f) = self.save_found(&sending, false) {
            tokio::task::spawn_blocking(move || {
                if let Err(e) = f.sync_all() {
                    log!("CRITICAL", "couldn't sync blocks_found.jsonl to the disk: {}", e);
                }
            });
        }
        self.submit_and_record(record, block_hex, false).await;
    }

    /// Send a saved block to the node until it answers (however long that takes, see SUBMIT_TRIES), then record the
    /// answer: in blocks_found.jsonl, the API's block list, and a fresh job. `resent`: it may have reached the node
    /// before (a block resumed after a restart), so "duplicate" means it got there.
    async fn submit_and_record(self: Arc<Self>, mut record: Value, block_hex: String, mut resent: bool) {
        let hash = record["hash"].as_str().unwrap_or("").to_string();
        self.submitting.fetch_add(1, Ordering::SeqCst);
        let t0 = Instant::now();
        let mut last_log = Instant::now();
        let mut attempt = 0u32;
        let mut result: Value = loop {
            attempt += 1;
            match self.rpc.call_t("submitblock", json!([block_hex]), 60).await {
                Ok(v) => break v,
                Err(e) => {
                    let msg = e.to_string();
                    let warming = msg.contains("-28");
                    if msg.contains("RPC submitblock error") && !warming {
                        break json!(format!("error: {}", msg)); // the node's own answer: sending it again won't change it
                    }
                    // the node can't be reached or is still starting: never give up on a block (it stays "sending" in
                    // blocks_found.jsonl, so a restart of the pool resends it as well)
                    resent = true;
                    let slow = t0.elapsed().as_secs_f64() >= self.cfg.submit_slower_after_s;
                    // every try at first, then about once a minute, later every 10 minutes
                    if attempt <= SUBMIT_TRIES || last_log.elapsed().as_secs_f64() >= if slow { 600.0 } else { 60.0 } {
                        last_log = Instant::now();
                        log!("CRITICAL", "submitblock {}, try {} failed: {}; trying again until the node answers", hash, attempt, msg);
                    }
                    let gap = if attempt < SUBMIT_TRIES { SUBMIT_RETRY_S } else if slow { SUBMIT_IDLE_S } else { SUBMIT_SLOW_S };
                    tokio::time::sleep(Duration::from_secs_f64(gap)).await;
                }
            }
        };
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
        self.save_found(&full, true);
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

    /// Every minute: look up the readers given by name (another app's container, which has no fixed IP on umbrelOS
    /// and may get a new one after a restart). Addresses given as IPs stay as they are.
    async fn resolve_readers(self: Arc<Self>) {
        let mut last: Vec<std::net::Ipv4Addr> = Vec::new();
        loop {
            let mut now: Vec<std::net::Ipv4Addr> = Vec::new();
            for r in &self.cfg.web_readers {
                if let Ok(ip) = r.parse::<std::net::Ipv4Addr>() {
                    now.push(ip);
                    continue;
                }
                match tokio::net::lookup_host(format!("{}:0", r)).await {
                    Ok(addrs) => now.extend(addrs.filter_map(|a| match a.ip() {
                        std::net::IpAddr::V4(v) => Some(v),
                        _ => None,
                    })),
                    Err(_) => {} // not running right now: nothing to let in
                }
            }
            now.sort();
            now.dedup();
            if now != last {
                log!("INFO", "status page readers ({}): {}", self.cfg.web_readers.join(", "),
                     if now.is_empty() { "none found".to_string() } else { now.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ") });
                *self.readers.write().unwrap() = now.clone();
                last = now;
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    }
    /// At start: a block saved as "sending" whose answer never came (the pool stopped while it was still sending it,
    /// for example during a long node restart) goes to the node again if it can still count: it is for the next block, or the node's
    /// newest block (it may already have it: then "duplicate" = it got there). Older ones are recorded as stale, so
    /// they aren't looked at again.
    async fn resume_unsent(self: Arc<Self>) {
        let path = format!("{}/blocks_found.jsonl", self.cfg.data_dir);
        let Ok(text) = std::fs::read_to_string(&path) else { return };
        let mut last: Vec<(String, Value)> = Vec::new(); // the latest entry per block hash, in file order
        for line in text.lines() {
            let Ok(v) = serde_json::from_str::<Value>(line) else { continue };
            let Some(h) = v["hash"].as_str().map(String::from) else { continue };
            last.retain(|(k, _)| *k != h);
            last.push((h, v));
        }
        let unsent: Vec<Value> = last.into_iter().map(|(_, v)| v).filter(|v| v["result"] == json!("sending") && v["hex"].is_string()).collect();
        if unsent.is_empty() {
            return;
        }
        let tip = match self.rpc.call_t("getblockcount", json!([]), 10).await {
            Ok(v) => v.as_u64().unwrap_or(0),
            Err(e) => {
                log!("CRITICAL", "{} saved block(s) were never answered by the node, and it can't be asked now: {}", unsent.len(), e);
                return;
            }
        };
        for v in unsent {
            let height = v["height"].as_u64().unwrap_or(0);
            let hash = v["hash"].as_str().unwrap_or("").to_string();
            let hex = v["hex"].as_str().unwrap_or("").to_string();
            let mut record = v.clone();
            record.as_object_mut().map(|o| {
                o.remove("hex");
                o.remove("result");
            });
            if height + 1 >= tip && height <= tip + 1 {
                log!("CRITICAL", "block {} at height {} was saved but never answered (Core stopped while sending it): sending it again", hash, height);
                tokio::spawn(self.clone().submit_and_record(record, hex, true));
            } else {
                log!("WARNING", "block {} at height {} was saved but never answered; the chain is at {} now, so it can't count: recorded as stale", hash, height, tip);
                record["result"] = json!("stale: never answered (Core stopped while sending it)");
                let mut full = record.clone();
                full["hex"] = json!(hex);
                self.save_found(&full, true);
            }
        }
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

    /// A new block's work has reached a connection's SV2 channels `ms` after Core made the job.
    pub fn note_sv2_switch(&self, height: u64, ms: u64, channels: usize) {
        let mut s = self.stats.lock().unwrap();
        let same = s.sv2_switch["height"].as_u64() == Some(height);
        let ms = if same { ms.max(s.sv2_switch["ms"].as_u64().unwrap_or(0)) } else { ms };
        if same {
            s.sv2_times.pop_back();
        }
        push_capped(&mut s.sv2_times, ms);
        let n = if same { s.sv2_switch["channels"].as_u64().unwrap_or(0) as usize + channels } else { channels };
        s.sv2_switch = json!({"height": height, "ms": ms, "at": now_f(), "channels": n});
        if let Some(r) = s.recent_for(height) {
            r["sv2_ms"] = json!(ms);
            r["channels"] = json!(n);
        }
    }

    fn history_path(&self) -> String {
        format!("{}/history.json", self.cfg.data_dir)
    }

    /// Readings from the last 24 h saved by an earlier run (so the chart survives restarts and updates).
    fn load_history(&self) {
        let Ok(text) = std::fs::read_to_string(self.history_path()) else { return };
        let Ok(Value::Array(rows)) = serde_json::from_str::<Value>(&text) else { return };
        let cutoff = now_f() as u64 - 86400;
        let mut s = self.stats.lock().unwrap();
        for r in rows {
            if let (Some(t), Some(ths), Some(n)) = (r[0].as_u64(), r[1].as_f64(), r[2].as_u64()) {
                if t >= cutoff {
                    s.history.push_back((t, ths, n as usize));
                }
            }
        }
    }

    fn save_history(&self) {
        let (body, wbody) = {
            let s = self.stats.lock().unwrap();
            (json!(s.history.iter().map(|(t, h, n)| json!([t, (h * 1000.0).round() / 1000.0, n])).collect::<Vec<_>>()).to_string(),
             json!(s.worker_history.iter().map(|(k, q)| (k.clone(), json!(q.iter().map(|(t, h)| json!([t, (h * 10000.0).round() / 10000.0]))
                 .collect::<Vec<_>>()))).collect::<Map<String, Value>>()).to_string())
        };
        for (path, body) in [(self.history_path(), body), (self.worker_history_path(), wbody)] {
            let tmp = format!("{}.tmp", path);
            if let Err(e) = std::fs::write(&tmp, body).and_then(|_| std::fs::rename(&tmp, &path)) {
                log!("WARNING", "couldn't save the hashrate history: {}", e);
            }
        }
    }

    fn worker_history_path(&self) -> String {
        format!("{}/history-miners.json", self.cfg.data_dir)
    }

    /// Per-miner readings from the last 24 h saved by an earlier run.
    fn load_worker_history(&self) {
        let Ok(text) = std::fs::read_to_string(self.worker_history_path()) else { return };
        let Ok(Value::Object(m)) = serde_json::from_str::<Value>(&text) else { return };
        let cutoff = now_f() as u64 - 86400;
        let mut s = self.stats.lock().unwrap();
        for (name, rows) in m.into_iter().take(200) {
            let q: VecDeque<(u64, f64)> = rows.as_array().into_iter().flatten()
                .filter_map(|r| Some((r[0].as_u64()?, r[1].as_f64()?))).filter(|x| x.0 >= cutoff).collect();
            if !q.is_empty() {
                s.worker_history.insert(name, q);
            }
        }
    }

    /// The 24 h chart: the pool's, or one miner's (`worker`) as [time, TH/s].
    pub fn history(&self, worker: Option<&str>) -> Value {
        let s = self.stats.lock().unwrap();
        match worker {
            Some(w) => json!({"worker": w, "history": s.worker_history.get(w).map(|q| q.iter().map(|(t, h)| json!([t, h])).collect::<Vec<_>>()).unwrap_or_default()}),
            None => json!({"history": s.history.iter().map(|(t, h, n)| json!([t, h, n])).collect::<Vec<_>>()}),
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
        // each miner's best share ever on this pool (kept in state.json across restarts and updates)
        if share_diff > st["miner_best"][name]["diff"].as_f64().unwrap_or(0.0) {
            st["miner_best"][name] = json!({"diff": share_diff, "at": now});
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

    /// The payout address's script and the chain are looked up once at start; when the node didn't answer then
    /// (not when the address is invalid), ask again every 30 s until it does.
    async fn retry_start_lookups(self: Arc<Self>) {
        loop {
            let (address, have) = {
                let d = self.default.read().unwrap();
                (d.0.clone(), d.1.is_some())
            };
            let mut pending = false;
            if !address.is_empty() && !have {
                match self.lookup_script(&address).await {
                    Lookup::Script(s) => {
                        let mut d = self.default.write().unwrap();
                        if d.0 == address && d.1.is_none() {
                            d.1 = Some(s);
                            log!("INFO", "the node answered: the payout address is set");
                        }
                    }
                    Lookup::NoAnswer => pending = true,
                    Lookup::Invalid => {}
                }
            }
            if self.chain.read().unwrap().is_none() {
                match self.rpc.call_t("getblockchaininfo", json!([]), 10).await {
                    Ok(i) => {
                        if let Some(c) = i["chain"].as_str() {
                            *self.chain.write().unwrap() = Some(c.to_string());
                            log!("INFO", "the node answered: chain {}", c);
                        }
                    }
                    Err(_) => pending = true,
                }
            }
            if !pending {
                return;
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    }

    /// A block template: from IPC when it is connected, current (built on the node's best block) and the template
    /// policy isn't filtering (that needs each transaction's fee, which IPC doesn't give); otherwise getblocktemplate.
    /// A new block's IPC template is usually a few ms away, so this waits up to 500 ms for one before falling back.
    pub async fn fetch_template(&self) -> Result<Value> {
        if let Some(ipc) = self.ipc.get() {
            let filter = self.policy.lock().unwrap().cfg["mode"] == "filter";
            let mut why = if filter { "the template policy filters (that needs each transaction's fee)" } else { "IPC isn't connected" };
            if !filter && ipc.up.load(Ordering::Relaxed) {
                why = "the node didn't answer getbestblockhash";
                if let Ok(best) = self.rpc.call_t("getbestblockhash", json!([]), 5).await {
                    why = "no IPC template for the node's best block within 500 ms";
                    let best = best.as_str().unwrap_or("").to_string();
                    let deadline = Instant::now() + Duration::from_millis(500);
                    loop {
                        let t = ipc.latest.lock().unwrap().clone();
                        if let Some(t) = t.filter(|t| t.prev_hex == best) {
                            let mut tpl = t.tpl.clone();
                            let now = now_f() as u64;
                            let mintime = tpl["mintime"].as_u64().unwrap_or(0);
                            tpl["curtime"] = json!(now.max(mintime));
                            self.tpl_ipc.fetch_add(1, Ordering::Relaxed);
                            return Ok(tpl);
                        }
                        if Instant::now() >= deadline {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            }
            *self.tpl_fallback.lock().unwrap() = Some((why, Instant::now()));
        }
        self.tpl_rpc.fetch_add(1, Ordering::Relaxed);
        self.rpc.call("getblocktemplate", json!([{"rules": ["segwit"]}])).await
    }

    async fn refresh_templates(self: Arc<Self>) {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let due = self.current().map_or(false, |j| j.created.elapsed().as_secs_f64() >= self.refresh_s());
            if !due {
                continue;
            }
            // during the empty hold the hold itself decides (no fetch); otherwise the node builds the template
            // first and the lock is only taken to send it out
            let holding = self.current().map_or(false, |j| j.empty);
            let r = if holding {
                self.update_template(Upd::default()).await
            } else {
                match self.fetch_template().await {
                    Ok(t) => {
                        let stale = self.current().map_or(true, |j| j.created.elapsed().as_secs_f64() < self.refresh_s());
                        if stale {
                            continue; // a newer job went out while the node was building this one
                        }
                        self.update_template(Upd { tpl: Some(t), refresh: true, ..Default::default() }).await
                    }
                    Err(e) => Err(e),
                }
            };
            if let Err(e) = r {
                log!("WARNING", "template refresh: {}", e);
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
                {
                    let workers = self.worker_count();
                    // each miner's 5-minute hashrate (connections with the same name add up)
                    let mut per: HashMap<String, f64> = HashMap::new();
                    for h in self.workers.lock().unwrap().values() {
                        let i = h.info.lock().unwrap();
                        if i.name.is_empty() {
                            continue;
                        }
                        let since = (now - i.connected).max(60.0);
                        *per.entry(i.name.clone()).or_default() += hashrate(i.shares.iter(), 300f64.min(since), now) / 1e12;
                    }
                    let mut s = self.stats.lock().unwrap();
                    let th = hashrate(s.shares.iter(), 300f64.min((now - self.started).max(60.0)), now) / 1e12;
                    s.history.push_back((now as u64, th, workers));
                    while s.history.front().map_or(false, |x| x.0 + 86400 < now as u64) {
                        s.history.pop_front();
                    }
                    for (name, th) in per {
                        if s.worker_history.len() < 200 || s.worker_history.contains_key(&name) {
                            s.worker_history.entry(name).or_default().push_back((now as u64, th));
                        }
                    }
                    for q in s.worker_history.values_mut() {
                        while q.front().map_or(false, |x| x.0 + 86400 < now as u64) {
                            q.pop_front();
                        }
                    }
                    s.worker_history.retain(|_, q| !q.is_empty());
                }
                if n % 40 == 0 {
                    self.save_history(); // every 10 minutes
                }
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

    /// Save state.json (one save at a time, flushed to the disk before it replaces the old file), and every 10 minutes
    /// the same contents as state.json.bak, which load_state falls back on.
    pub fn save_state(&self) -> std::io::Result<()> {
        let mut last_bak = self.save.lock().unwrap_or_else(|e| e.into_inner());
        let body = self.state.lock().unwrap().to_string();
        write_synced(&self.state_path, &body)?;
        if last_bak.map_or(true, |t| t.elapsed() >= Duration::from_secs(600)) {
            write_synced(&format!("{}.bak", self.state_path), &body)?;
            *last_bak = Some(Instant::now());
        }
        Ok(())
    }

    // ------------------------------------------------------------------ start and stop

    /// Before starting: wait while the node can't be reached or is still loading (after a reboot both apps start at
    /// once, and the node takes a while). A WARNING when it starts waiting and every 5 minutes, an ERROR only once
    /// it has waited 15 minutes. Returns how long it waited.
    pub async fn wait_for_node(&self) -> f64 {
        let t0 = Instant::now();
        let mut said = -1.0f64;
        loop {
            let err = match self.rpc.call_t("getblockchaininfo", json!([]), 10).await {
                Ok(_) => return t0.elapsed().as_secs_f64(),
                Err(e) => format!("{:#}", e),
            };
            let waited = t0.elapsed().as_secs_f64();
            if said < 0.0 || waited - said >= 300.0 {
                said = waited;
                let why = if err.contains("\"code\":-28") { "the node is still starting".to_string() } else { err.chars().take(120).collect() };
                if waited >= 900.0 {
                    log!("ERROR", "still waiting for the node after {} min: {}", (waited / 60.0).round(), why);
                } else {
                    log!("WARNING", "waiting for the node: {}", why);
                }
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

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
        if !self.cfg.ipc_socket.is_empty() {
            let chain = self.chain.read().unwrap().clone().unwrap_or_else(|| "main".to_string());
            let ipc = crate::ipc::start(self.cfg.ipc_socket.clone().into(), chain);
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
            *ipc.tip_tx.lock().unwrap() = Some(tx);
            let _ = self.ipc.set(ipc.clone());
            let me = self.clone();
            tokio::spawn(async move {
                while let Some(h) = rx.recv().await {
                    tokio::spawn(me.clone().on_block_signal_from(h, "node's IPC"));
                }
            });
            for _ in 0..30 {  // up to 3 s for the first IPC template, so the first job can use it
                if ipc.latest.lock().unwrap().is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        self.update_template(Upd { clean: true, ..Default::default() }).await?;
        if !self.cfg.zmq_hashblock.is_empty() {
            tokio::spawn(self.clone().zmq_loop());
        }
        tokio::spawn(self.clone().watch_blocks());
        tokio::spawn(self.clone().longpoll_blocks());
        tokio::spawn(self.clone().refresh_templates());
        tokio::spawn(self.clone().resume_unsent()); // a found block Core stopped sending, if any
        tokio::spawn(self.clone().retry_start_lookups()); // the payout address and chain, if the node didn't answer
        if !self.cfg.web_readers.is_empty() {
            tokio::spawn(self.clone().resolve_readers()); // IPs as given, names looked up every minute
        }
        self.load_history();
        self.load_worker_history();
        tokio::spawn(self.clone().housekeeping());
        tokio::spawn(self.clone().stall_guard_loop());
        if std::env::var("SOLO45_MINER_READINGS").map_or(true, |v| v != "0") {
            tokio::spawn(crate::devices::poll_loop(self.clone())); // temperature, fan, watts from each miner
        }
        Ok(())
    }

    /// The IP addresses of the miners connected right now.
    pub fn worker_ips(&self) -> Vec<String> {
        self.workers.lock().unwrap().values().map(|h| h.info.lock().unwrap().ip.clone()).collect()
    }

    /// Every 5 s: is the node stuck on a block one peer won't send? Then drop that peer (pool.py's stall_guard_loop).
    /// Solo45 on the same node runs the same guard; whichever acts first wins and the other's disconnect just
    /// finds the peer already gone.
    async fn stall_guard_loop(self: Arc<Self>) {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let limit = self.stall_guard_s();
            if limit <= 0.0 {
                continue;
            }
            let info = match self.rpc.call_t("getblockchaininfo", json!([]), 10).await {
                Ok(i) => i,
                Err(e) => {
                    if !e.to_string().contains("\"code\":-28") { // -28: the node is still starting up
                        log!("WARNING", "stall guard: {}", e);
                    }
                    continue;
                }
            };
            let (blocks, headers) = (info["blocks"].as_u64().unwrap_or(0), info["headers"].as_u64().unwrap_or(0));
            let ibd = info["initialblockdownload"].as_bool().unwrap_or(false);
            let peers = if headers > blocks {
                match self.rpc.call_t("getpeerinfo", json!([]), 10).await {
                    Ok(Value::Array(p)) => p,
                    Ok(_) => vec![],
                    Err(e) => {
                        log!("WARNING", "stall guard: {}", e);
                        continue;
                    }
                }
            } else {
                vec![]
            };
            let (targets, note) = self.guard.lock().unwrap().check(blocks, headers, ibd, &peers, now_f(), limit);
            if let Some(n) = note {
                log!("WARNING", "stall guard: {}", n);
            }
            for (id, desc) in &targets {
                match self.rpc.call_t("disconnectnode", json!(["", id]), 10).await {
                    Ok(_) => log!("WARNING", "stall guard: block {} was announced over {:.0} s ago but {} still hasn't sent it; \
                                              disconnected it so the node gets the block from another peer", blocks + 1, limit, desc),
                    Err(e) if e.to_string().contains("\"code\":-29") =>
                        log!("INFO", "stall guard: {} was already disconnected (Solo45's guard on the same node, or it left)", desc),
                    Err(e) => log!("WARNING", "stall guard: couldn't disconnect {}: {}", desc, e),
                }
            }
            if !targets.is_empty() {
                let events = self.guard.lock().unwrap().events.clone();
                self.state.lock().unwrap()["stall_events"] = json!(events);
                let _ = self.save_state();
            }
        }
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
        self.save_history();
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
                    "protocol": i.protocol,
                    "hashrate_5m": hashrate(i.shares.iter(), 300f64.min(since), now),
                    "hashrate_1h": hashrate(i.shares.iter(), 3600f64.min(since), now),
                })
            }).collect();
            v.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
            v
        };
        let mut workers = workers;
        let miner_best = self.state.lock().unwrap()["miner_best"].clone();
        for w in workers.iter_mut() {
            w["best_ever"] = miner_best[w["name"].as_str().unwrap_or("")]["diff"].clone();
        }
        {
            let dev = self.devices.read().unwrap();
            let mut per_ip: HashMap<String, usize> = HashMap::new();
            for w in workers.iter() {
                *per_ip.entry(w["ip"].as_str().unwrap_or("").to_string()).or_default() += 1;
            }
            for w in workers.iter_mut() {
                w["override"] = self.override_for(w["name"].as_str().unwrap_or(""));
                // several miners behind one address (a proxy): its readings would be the proxy's, so show none
                let ip = w["ip"].as_str().unwrap_or("").to_string();
                w["device"] = if per_ip.get(&ip) == Some(&1) { dev.get(&ip).cloned().unwrap_or(Value::Null) } else { Value::Null };
            }
        }
        let s = self.stats.lock().unwrap();
        let st = self.state.lock().unwrap();
        let settings = st["settings"].clone();
        let get_f = |k: &str, d: f64| settings.get(k).and_then(|v| v.as_f64()).unwrap_or(d);
        let stall_events: Vec<Value> = {
            let g = self.guard.lock().unwrap();
            g.events[g.events.len().saturating_sub(10)..].to_vec()
        };
        let stall_s = settings.get("stall_guard_s").and_then(|v| v.as_f64()).unwrap_or(self.cfg.stall_guard_s);
        let policy_view = self.policy_view();
        let sv2_info = self.sv2_info.read().unwrap().clone();
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
                "policy": policy_view,
                "best_ever": st["best_ever"],
                "blocks": st["blocks"],
                "last_switch": s.last_switch,
                "sv2_switch": {"last": s.sv2_switch, "ms_median": median(s.sv2_times.iter()), "blocks": s.sv2_times.len()},
                "recent_blocks": s.recent.iter().collect::<Vec<_>>(),
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
                "sv2": sv2_info,
                "template_refresh_s": get_f("template_refresh_s", self.cfg.template_refresh_s),
                "electricity_usd_kwh": settings.get("electricity_usd_kwh").cloned().unwrap_or(Value::Null),
                "share_seconds": self.cfg.share_seconds,
                "min_diff": self.cfg.min_diff,
                "zmq": self.zmq_up.load(Ordering::Relaxed),
                "ipc": self.ipc.get().map(|i| {
                    let mut s = i.status();
                    s["used"] = json!(self.tpl_ipc.load(Ordering::Relaxed));
                    s["rpc_used"] = json!(self.tpl_rpc.load(Ordering::Relaxed));
                    s["fallback"] = json!(self.tpl_fallback.lock().unwrap().as_ref()
                        .map(|(r, at)| json!({"reason": r, "age_s": at.elapsed().as_secs_f64()})));
                    s
                }),
                "stall_guard": {"seconds": stall_s, "events": stall_events},
            },
            "workers": workers,
        })
    }

    pub fn shares_since(&self, since: u64) -> Value {
        let s = self.stats.lock().unwrap();
        json!({"shares": s.share_log.iter().filter(|x| x["seq"].as_u64().unwrap_or(0) > since).collect::<Vec<_>>()})
    }

    pub fn export_settings(&self) -> Value {
        let pcfg = self.policy.lock().unwrap().cfg.clone();
        let st = self.state.lock().unwrap();
        json!({"settings": st["settings"], "overrides": st["overrides"], "policy": pcfg, "last_diff": st["last_diff"]})
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
        let keys = ["template_refresh_s", "stall_guard_s", "force_default_address", "empty_first", "empty_hold_s", "electricity_usd_kwh"];
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
        if let Some(e) = num("electricity_usd_kwh") {
            match e {
                Some(e) if (0.0..=2.0).contains(&e) => {}
                _ => return (400, json!({"error": "the electricity price must be 0 to 2 dollars per kWh"})),
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
                     "stall_guard_s": self.stall_guard_s(), "electricity_usd_kwh": self.setting("electricity_usd_kwh")}))
    }

    /// Keep what the policy did to this template (the latest per block), and log it (pool.py's record_policy).
    fn record_policy(&self, r: policy::Report, mode: &str, filtered: bool) {
        let mut p = self.policy.lock().unwrap();
        if let Some(last) = p.heights.back().cloned() {
            if r.height > last["height"].as_u64().unwrap_or(0) && last["saved"] != true {
                let mut last = last;
                p.save_block(&mut last); // a new block arrived, so the previous one's numbers are final
                *p.heights.back_mut().unwrap() = last;
            }
        }
        let entry = json!({"height": r.height, "mode": mode, "filtered": filtered, "txs": r.txs, "skipped": r.skipped(),
                           "fees": r.fees, "fees_skipped": r.fees_skipped, "weight_skipped": r.weight_skipped,
                           "by_rule": r.by_rule, "examples": r.examples, "watched": r.watched, "fees_watched": r.fees_watched,
                           "watch_by_rule": r.watch_by_rule, "at": now_f()});
        p.heights.retain(|e| e["height"].as_u64() != Some(r.height));
        p.heights.push_back(entry);
        while p.heights.len() > 144 {
            p.heights.pop_front(); // about a day of blocks
        }
        drop(p);
        let why = |by: &Value| by.as_object().into_iter().flatten()
            .map(|(k, v)| format!("{} {}", k, v["txs"])).collect::<Vec<_>>().join(", ");
        let text = if r.skipped() > 0 {
            let mut t = format!("{} {} of {} txs for block {}, {} sats in fees ({})",
                                if filtered { "skipped" } else { "would skip" }, r.skipped(), r.txs, r.height,
                                commas(r.fees_skipped), why(&r.by_rule));
            if r.watched > 0 {
                t += &format!("; watch rules would also skip {} txs, {} sats ({})", r.watched, commas(r.fees_watched), why(&r.watch_by_rule));
            }
            t
        } else if r.watched > 0 {
            format!("would skip {} of {} txs for block {}, {} sats in fees ({})", r.watched, r.txs, r.height,
                    commas(r.fees_watched), why(&r.watch_by_rule))
        } else {
            return;
        };
        log!("INFO", "policy ({}): {}", if filtered { "filtering" } else if mode == "watch" { "watch-only" }
                                        else if r.skipped() > 0 { "fallback" } else { "watch rules" }, text);
    }

    pub fn policy_view(&self) -> Value {
        self.policy.lock().unwrap().view()
    }

    /// A policy change from the dashboard; the next job uses it right away.
    pub async fn set_policy(self: &Arc<Self>, data: &Value) -> (u16, Value) {
        let cfg = {
            let cur = self.policy.lock().unwrap().cfg.clone();
            match policy::check_config(data, &cur) {
                Ok(c) => c,
                Err(e) => return (400, json!({"error": e})),
            }
        };
        self.policy.lock().unwrap().cfg = cfg.clone();
        self.state.lock().unwrap()["policy"] = cfg.clone();
        let _ = self.save_state();
        let states: Vec<(String, &str)> = cfg["rules"].as_object().into_iter().flatten()
            .map(|(k, v)| (k.clone(), policy::rule_state(v))).collect();
        let list = |s: &str| {
            let v: Vec<&str> = states.iter().filter(|x| x.1 == s).map(|x| x.0.as_str()).collect();
            if v.is_empty() { "none".to_string() } else { v.join(", ") }
        };
        log!("INFO", "template policy: mode {}, filter: {}, watch only: {}", cfg["mode"].as_str().unwrap_or("?"),
             list("filter"), list("watch"));
        let me = self.clone();
        tokio::spawn(async move {
            let _ = me.update_template(Upd { check: true, ..Default::default() }).await; // apply it to the next job right away, checked
        });
        let mut v = self.policy_view();
        v["ok"] = json!(true);
        (200, v)
    }

    /// Load a backup made by export_settings (pool.py's restore_settings). Each part goes through the same checks as
    /// a change on the dashboard; a part that fails is reported and skipped. Miners not in the backup keep theirs.
    pub async fn restore_settings(self: &Arc<Self>, data: &Value) -> (u16, Value) {
        let (mut done, mut errors): (Vec<String>, Vec<String>) = (vec![], vec![]);
        let mut step = |label: String, (code, reply): (u16, Value)| {
            if code == 200 {
                done.push(label);
            } else {
                errors.push(format!("{}: {}", label, reply["error"].as_str().map(String::from).unwrap_or(code.to_string())));
            }
        };
        let s = &data["settings"];
        if let Some(a) = s["default_address"].as_str().filter(|a| !a.is_empty()) {
            step("payout address".into(), self.set_payout(&json!({"address": a})).await);
        }
        let mut ps = Map::new();
        for k in ["template_refresh_s", "stall_guard_s", "force_default_address", "empty_first", "empty_hold_s", "electricity_usd_kwh"] {
            if let Some(v) = s.get(k) {
                ps.insert(k.into(), v.clone());
            }
        }
        if !ps.is_empty() {
            step("job timing, stall guard, payout switch and empty block first".into(), self.set_settings(&Value::Object(ps)).await);
        }
        let mut miners = 0;
        for (name, o) in data["overrides"].as_object().into_iter().flatten() {
            if let Some(o) = o.as_object() {
                let mut o = o.clone();
                o.insert("name".into(), json!(name));
                let r = self.set_override(&Value::Object(o));
                if r.0 == 200 {
                    miners += 1;
                } else {
                    step(format!("difficulty for {}", name), r);
                }
            }
        }
        if miners > 0 {
            step(format!("difficulty settings for {} miner{}", miners, if miners == 1 { "" } else { "s" }), (200, json!({})));
        }
        if data["policy"].is_object() {
            step("template policy".into(), self.set_policy(&data["policy"]).await);
        }
        let mut kept = 0;
        {
            let mut st = self.state.lock().unwrap();
            for (name, v) in data["last_diff"].as_object().into_iter().flatten() {
                let (Some(diff), Some(at)) = (v[0].as_f64(), v[1].as_f64()) else { continue };
                if (self.cfg.min_diff..=MAX_DIFF).contains(&diff) {
                    let name: String = name.chars().take(64).collect();
                    st["last_diff"][name] = json!([diff, at]);
                    kept += 1;
                }
            }
        }
        if kept > 0 {
            done.push(format!("remembered difficulty for {} miner{}", kept, if kept == 1 { "" } else { "s" }));
        }
        let _ = self.save_state();
        log!("INFO", "settings restored from a backup: {}{}", if done.is_empty() { "nothing".into() } else { done.join(", ") },
             if errors.is_empty() { String::new() } else { format!("; problems: {}", errors.join("; ")) });
        (200, json!({"ok": errors.is_empty(), "restored": done, "errors": errors}))
    }

    /// Point connected miners at the address they should pay now; they get it with a fresh job.
    async fn repay_workers(self: &Arc<Self>) {
        let list: Vec<(Arc<Mutex<WorkerInfo>>, String)> = self.workers.lock().unwrap().values()
            .map(|h| (h.info.clone(), h.info.lock().unwrap().user.clone())).collect();
        let mut changed = 0;
        for (info, user) in list {
            // a miner whose own address the node can't check right now keeps what it pays
            if let Payout::To(address, spk) = self.payout_for(&user).await {
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
                let _ = me.update_template(Upd { clean: true, check: true, ..Default::default() }).await;
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
            let _ = me.update_template(Upd { clean: true, check: true, ..Default::default() }).await;
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

    #[test]
    fn state_file_falls_back_on_its_backup() {
        let dir = std::env::temp_dir().join(format!("s45-state-test-{}-{}", std::process::id(), (now_f() * 1e6) as u64));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json").to_string_lossy().into_owned();
        let bad_copies = || std::fs::read_dir(&dir).unwrap().filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().contains(".bad-")).count();
        // nothing saved yet: a new install
        let (v, new) = load_state(&path);
        assert!(new && v == json!({}));
        // a good file is used as it is
        write_synced(&path, r#"{"settings":{"default_address":"a"}}"#).unwrap();
        let (v, new) = load_state(&path);
        assert!(!new && v["settings"]["default_address"] == "a");
        // an unreadable file (cut short, empty, or not an object): the backup is used and the bad file is kept
        write_synced(&format!("{}.bak", path), r#"{"settings":{"default_address":"b"}}"#).unwrap();
        for (n, bad) in [r#"{"settings":{"defau"#, "", "[1,2]"].iter().enumerate() {
            std::fs::write(&path, bad).unwrap();
            let (v, new) = load_state(&path);
            assert!(!new && v["settings"]["default_address"] == "b", "{:?}", bad);
            assert!(!std::path::Path::new(&path).exists());
            assert!(bad_copies() >= 1, "kept copy {}", n);
        }
        // the file is missing but the backup is there: not a new install
        let (v, new) = load_state(&path);
        assert!(!new && v["settings"]["default_address"] == "b");
        // neither can be read: like a new install (which turns "always pay my address" on)
        std::fs::write(&path, "garbage").unwrap();
        std::fs::write(format!("{}.bak", path), "garbage").unwrap();
        let (v, new) = load_state(&path);
        assert!(new && v == json!({}));
        std::fs::remove_dir_all(&dir).ok();
    }
}
