//! Stratum V2 for Solo45 Core: an encrypted (Noise) mining port with extended channels, built on the Stratum V2
//! reference implementation's crates (stratum-core / stratum-apps from crates.io): their Noise handshake and framing,
//! their message types, and their pool-side extended channel (`channels_sv2`), which builds each channel's jobs,
//! checks shares, catches duplicates and stale work, and spots blocks.
//!
//! Core feeds every job it makes (the same work its Stratum V1 miners get, after the template policy) into each
//! channel as a Template Distribution `NewTemplate`: a new block's job as a future template followed by
//! `SetNewPrevHash`, later jobs for the same block as immediate templates. Found blocks are rebuilt from Core's own
//! job (its transactions) and go through the same save-first, resend-while-the-node-is-down path as V1 blocks.
//! SV2 miners show on the API and status page like V1 miners, with "sv2" in their agent.
//!
//! SV1 miners (Bitaxes) reach this port through the reference Translator Proxy (tProxy). Standard channels
//! (header-only mining) are not offered yet: connections are told to use extended channels.

use crate::job::Job;
use crate::log;
use crate::pool::{Ctl, NewJob, Payout, Pool, WorkerHandle, WorkerInfo};
use crate::util::{fmt_diff, now_f, push, script_num, target_diff};
use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use stratum_apps::key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};
use stratum_apps::network_helpers::noise_stream::{NoiseTcpStream, NoiseTcpWriteHalf};
use stratum_apps::stratum_core::bitcoin::{Amount, ScriptBuf, Target, TxOut};
use stratum_apps::stratum_core::channels_sv2::{
    extranonce_manager::ExtranonceAllocator,
    server::{
        extended::ExtendedChannel,
        standard::StandardChannel,
        share_accounting::{ShareValidationError, ShareValidationResult},
    },
    Vardiff, VardiffState,
};
use stratum_apps::stratum_core::common_messages_sv2::{Protocol, SetupConnectionErrorOwned, SetupConnectionSuccess};
use stratum_apps::stratum_core::mining_sv2::{
    OpenExtendedMiningChannelSuccessOwned, OpenMiningChannelErrorOwned, OpenStandardMiningChannelSuccessOwned,
    SetNewPrevHashOwned as SetNewPrevHashMp, SetTargetOwned, SubmitSharesErrorOwned, SubmitSharesExtendedOwned,
    SubmitSharesStandardOwned, SubmitSharesSuccessOwned,
};
use stratum_apps::stratum_core::noise_sv2::Responder;
use stratum_apps::stratum_core::parsers_sv2::{parse_message_frame_with_tlvs, AnyMessageOwned, CommonMessagesOwned, MiningOwned};
use stratum_apps::stratum_core::template_distribution_sv2::{NewTemplateOwned, SetNewPrevHashOwned as SetNewPrevHashTdp};
use stratum_apps::utils::types::OutboundFrame;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};

const SV2_VERSION: u16 = 2;
const SERVER_TAG: u8 = 0x45; // first extranonce byte on this pool ("45")
const MAX_CHANNELS: u32 = 65_536; // 2 bytes of channel index
const CLIENT_EXTRANONCE: u8 = 16; // the space each channel rolls itself (what the reference pool gives)
const SHARE_BATCH: usize = 1; // acknowledge every share (small fleets: no reason to batch)
const CERT_VALIDITY_S: u64 = 365 * 24 * 3600;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CHANNELS_PER_CONN: usize = 256;

/// The pool's Stratum V2 authority key (kept in the data folder), whose public half miners and proxies can pin.
pub struct Authority {
    pub public: Secp256k1PublicKey,
    secret: String, // base58check, as the reference tools write it
}

/// Base58Check (payload + the first 4 bytes of its double SHA-256), the reference tools' key format.
fn base58check(payload: &[u8]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut data = payload.to_vec();
    data.extend_from_slice(&crate::util::sha256d(payload)[..4]);
    let mut digits: Vec<u8> = Vec::new(); // base 58, least significant first
    for &byte in &data {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let zeros = data.iter().take_while(|b| **b == 0).count();
    std::iter::repeat(b'1').take(zeros).chain(digits.iter().rev().map(|d| ALPHABET[*d as usize]))
        .map(|c| c as char).collect()
}

impl Authority {
    /// Load sv2-authority.json from the data folder, or make a new key the first time.
    pub fn load_or_create(data_dir: &str) -> Result<Authority> {
        let path = format!("{}/sv2-authority.json", data_dir);
        let parse = |s: &str| s.parse::<Secp256k1SecretKey>().map_err(|e| anyhow!("authority secret: {:?}", e));
        if let Ok(text) = std::fs::read_to_string(&path) {
            let v: serde_json::Value = serde_json::from_str(&text).context("sv2-authority.json")?;
            let secret = v["secret"].as_str().unwrap_or("").to_string();
            let public = Secp256k1PublicKey::from(parse(&secret)?);
            return Ok(Authority { public, secret });
        }
        // 32 random bytes from the operating system (a valid secret key unless astronomically unlucky: try again)
        let secret = loop {
            let mut b = [0u8; 32];
            std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom").context("/dev/urandom")?, &mut b)?;
            let s = base58check(&b);
            if parse(&s).is_ok() {
                break s;
            }
        };
        let public = Secp256k1PublicKey::from(parse(&secret)?);
        let body = serde_json::json!({"secret": secret, "public": public.to_string()}).to_string();
        let tmp = format!("{}.tmp", path);
        std::fs::write(&tmp, body).and_then(|_| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
            }
            std::fs::rename(&tmp, &path)
        }).context("saving sv2-authority.json")?;
        log!("INFO", "Stratum V2: made a new authority key (public {})", public);
        Ok(Authority { public, secret })
    }

    fn responder(&self) -> Result<Box<Responder>> {
        let secret = self.secret.parse::<Secp256k1SecretKey>().map_err(|e| anyhow!("authority secret: {:?}", e))?;
        Responder::from_authority_kp(&self.public.into_bytes(), &secret.into_bytes(), Duration::from_secs(CERT_VALIDITY_S))
            .map_err(|e| anyhow!("noise responder: {:?}", e))
    }
}

pub struct Sv2 {
    pub authority: Authority,
    allocator: Mutex<ExtranonceAllocator>,
}

impl Sv2 {
    pub fn new(data_dir: &str) -> Result<Arc<Sv2>> {
        let allocator = ExtranonceAllocator::new(vec![SERVER_TAG], 1 + 2 + CLIENT_EXTRANONCE, MAX_CHANNELS)
            .map_err(|e| anyhow!("extranonce allocator: {:?}", e))?;
        Ok(Arc::new(Sv2 { authority: Authority::load_or_create(data_dir)?, allocator: Mutex::new(allocator) }))
    }
}

pub async fn serve(pool: Arc<Pool>, sv2: Arc<Sv2>, listener: TcpListener) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                if !pool.conn_open(peer.ip()) {
                    continue; // same per-address limit as the V1 port
                }
                let (pool, sv2) = (pool.clone(), sv2.clone());
                tokio::spawn(async move {
                    if let Err(e) = connection(pool.clone(), sv2, stream, peer).await {
                        log!("INFO", "Stratum V2 {}: {:#}", peer.ip(), e);
                    }
                    pool.conn_close(peer.ip());
                });
            }
            Err(e) => {
                log!("WARNING", "Stratum V2 accept failed: {}", e);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// A channel's reference state: extended (the miner builds its own coinbase/merkle root: proxies, AxeOS
/// "extended") or standard (header-only mining: Braiins OS, AxeOS "standard").
enum Ch {
    Ext(ExtendedChannel),
    Std(StandardChannel),
}

/// Run the same expression on either kind of channel (their APIs match).
macro_rules! on {
    ($ch:expr, $x:ident => $e:expr) => {
        match $ch {
            Ch::Ext($x) => $e,
            Ch::Std($x) => $e,
        }
    };
}

enum Sub {
    Ext(SubmitSharesExtendedOwned),
    Std(SubmitSharesStandardOwned),
}

/// Shares the reference vardiff needs before it may change a channel's difficulty (see Conn::vardiff).
const VARDIFF_MIN_SHARES: u32 = 12;

/// One channel on a connection: the reference channel state plus the miner as the pool shows it.
struct Chan {
    ch: Ch,
    vardiff: VardiffState,
    worker_id: u64,
    info: Arc<Mutex<WorkerInfo>>,
    name: String,
    address: String,
    spk: Vec<u8>,
    tip: String, // the block this channel's jobs build on (prev hash, display hex)
    fixed: bool, // a fixed difficulty set for this miner (API override): no vardiff
    /// the difficulty each job went out at: a share counts at its job's difficulty, never more (V1's job_diff), so
    /// shares a miner still sends on older jobs after a difficulty rise don't count at the new one
    job_diff: HashMap<u32, f64>,
    /// a new channel's first shares (when, count, work): if they flood in, the difficulty goes up at once instead of
    /// waiting for the next minute's vardiff (Braiins OS reports a tiny hashrate when it connects)
    early: (f64, u32, f64),
}

struct Conn {
    pool: Arc<Pool>,
    sv2: Arc<Sv2>,
    w: NoiseTcpWriteHalf,
    ip: String,
    agent: String,
    chans: HashMap<u32, Chan>,
    next_channel: u32,
    /// difficulty changes from the API (per-miner overrides), tagged with the channel they are for
    ctl_tx: mpsc::UnboundedSender<(u32, f64)>,
}

impl Drop for Conn {
    fn drop(&mut self) {
        let mut ws = self.pool.workers.lock().unwrap();
        for c in self.chans.values() {
            ws.remove(&c.worker_id);
        }
    }
}

async fn connection(pool: Arc<Pool>, sv2: Arc<Sv2>, stream: TcpStream, peer: SocketAddr) -> Result<()> {
    stream.set_nodelay(true).ok();
    let noise = NoiseTcpStream::accept(stream, sv2.authority.responder()?, HANDSHAKE_TIMEOUT).await
        .map_err(|e| anyhow!("noise handshake failed: {:?}", e))?;
    let (mut r, w) = noise.into_split();
    // the reader is not cancel-safe inside select!, so it runs on its own and hands over whole frames
    let (ftx, mut frx) = mpsc::channel(64);
    let reader = tokio::spawn(async move {
        while let Ok(f) = r.read_frame().await {
            if ftx.send(f).await.is_err() {
                break;
            }
        }
    });
    let (ctl_tx, mut ctl_rx) = mpsc::unbounded_channel();
    let mut c = Conn { pool: pool.clone(), sv2, w, ip: peer.ip().to_string(), agent: "sv2".into(), chans: HashMap::new(),
                       next_channel: 1, ctl_tx };
    let result = c.run(&mut frx, &mut ctl_rx).await;
    reader.abort();
    if !c.chans.is_empty() {
        let names: Vec<&str> = c.chans.values().map(|ch| ch.name.as_str()).collect();
        log!("INFO", "disconnected {} (Stratum V2: {})", c.ip, names.join(", "));
    }
    result
}

impl Conn {
    async fn send(&mut self, m: AnyMessageOwned) -> Result<()> {
        let f = OutboundFrame::from_message(m).map_err(|e| anyhow!("encode: {:?}", e))?;
        tokio::time::timeout(Duration::from_secs(10), self.w.write_frame(f)).await
            .map_err(|_| anyhow!("send timed out"))?
            .map_err(|e| anyhow!("send: {:?}", e))
    }

    async fn send_mining(&mut self, m: MiningOwned) -> Result<()> {
        self.send(AnyMessageOwned::Mining(m)).await
    }

    async fn run(&mut self, frx: &mut mpsc::Receiver<stratum_apps::utils::types::InboundFrame>,
                 ctl_rx: &mut mpsc::UnboundedReceiver<(u32, f64)>) -> Result<()> {
        // 1. SetupConnection, within 10 s
        let mut f = tokio::time::timeout(Duration::from_secs(10), frx.recv()).await
            .map_err(|_| anyhow!("no SetupConnection"))?.ok_or_else(|| anyhow!("closed before SetupConnection"))?;
        let header = f.header();
        let (msg, _) = parse_message_frame_with_tlvs(header, f.payload(), &[]).map_err(|e| anyhow!("parse: {:?}", e))?;
        let msg = msg.into_owned();
        let AnyMessageOwned::Common(CommonMessagesOwned::SetupConnection(s)) = msg else {
            return Err(anyhow!("the first message wasn't SetupConnection"));
        };
        if s.protocol != Protocol::MiningProtocol || s.min_version > SV2_VERSION || s.max_version < SV2_VERSION {
            let code = if s.protocol != Protocol::MiningProtocol { "unsupported-protocol" } else { "protocol-version-mismatch" };
            let e = SetupConnectionErrorOwned { flags: 0, error_code: code.to_string().try_into().unwrap() };
            let _ = self.send(AnyMessageOwned::Common(e.into())).await;
            return Err(anyhow!("SetupConnection refused: {}", code));
        }
        let clean = |s: &str| s.chars().filter(|c| !c.is_control()).take(40).collect::<String>();
        self.agent = format!("sv2/{}/{}", clean(&s.vendor.as_utf8_or_hex()), clean(&s.firmware.as_utf8_or_hex()));
        let ok = SetupConnectionSuccess { used_version: SV2_VERSION, flags: 0 }; // standard and extended channels
        self.send(AnyMessageOwned::Common(ok.into())).await?;

        // 2. channels, shares, jobs and vardiff
        let mut jobs = self.pool.job_tx.subscribe();
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.tick().await;
        loop {
            tokio::select! {
                f = frx.recv() => {
                    let Some(mut f) = f else { return Ok(()) };
                    let header = f.header();
                    let msg = match parse_message_frame_with_tlvs(header, f.payload(), &[]) {
                        Ok((m, _)) => m.into_owned(),
                        Err(e) => return Err(anyhow!("parse: {:?}", e)),
                    };
                    self.handle(msg).await?;
                }
                j = jobs.recv() => {
                    let (job, flush) = match j {
                        Ok(NewJob { job, flush, .. }) => (job, flush),
                        Err(broadcast::error::RecvError::Lagged(_)) => match self.pool.current() { Some(j) => (j, false), None => continue },
                        Err(broadcast::error::RecvError::Closed) => return Ok(()),
                    };
                    let ids: Vec<u32> = self.chans.keys().copied().collect();
                    let new_block = self.chans.values().any(|c| c.tip != job.prev_hex);
                    for id in &ids {
                        self.push_job(*id, &job, flush).await?;
                    }
                    if new_block && !ids.is_empty() {
                        // the new block's work is out on every SV2 channel of this connection
                        self.pool.note_sv2_switch(job.height, job.created.elapsed().as_millis() as u64, ids.len());
                    }
                }
                Some((id, diff)) = ctl_rx.recv() => self.set_difficulty(id, diff).await?,
                _ = tick.tick() => self.vardiff().await?,
            }
        }
    }

    async fn handle(&mut self, msg: AnyMessageOwned) -> Result<()> {
        match msg {
            AnyMessageOwned::Mining(MiningOwned::OpenExtendedMiningChannel(m)) => {
                let user = m.user_identity.as_utf8_or_hex();
                let max_target = Target::from_le_bytes(m.max_target.to_array());
                self.open_channel(true, m.request_id, user, m.nominal_hash_rate, max_target, m.min_extranonce_size as usize).await
            }
            AnyMessageOwned::Mining(MiningOwned::OpenStandardMiningChannel(m)) => {
                let user = m.user_identity.as_utf8_or_hex();
                let max_target = Target::from_le_bytes(m.max_target.to_array());
                self.open_channel(false, m.get_request_id_as_u32(), user, m.nominal_hash_rate, max_target, 0).await
            }
            AnyMessageOwned::Mining(MiningOwned::SubmitSharesExtended(s)) => self.share(Sub::Ext(s)).await,
            AnyMessageOwned::Mining(MiningOwned::SubmitSharesStandard(s)) => self.share(Sub::Std(s)).await,
            AnyMessageOwned::Mining(MiningOwned::UpdateChannel(u)) => {
                let Some(c) = self.chans.get_mut(&u.channel_id) else { return Ok(()) };
                let max = Target::from_le_bytes(u.max_target.to_array());
                if on!(&mut c.ch, x => x.update_channel(u.nominal_hash_rate, Some(max)).is_ok()) {
                    let t = *on!(&c.ch, x => x.get_target());
                    c.info.lock().unwrap().diff = t.difficulty_float();
                    let id = u.channel_id;
                    self.send_mining(MiningOwned::SetTarget(SetTargetOwned { channel_id: id, target: t.to_le_bytes().into() })).await?;
                }
                Ok(())
            }
            AnyMessageOwned::Mining(MiningOwned::CloseChannel(c)) => {
                if let Some(ch) = self.chans.remove(&c.channel_id) {
                    self.pool.workers.lock().unwrap().remove(&ch.worker_id);
                    log!("INFO", "{} {} closed its Stratum V2 channel {}", self.ip, ch.name, c.channel_id);
                }
                Ok(())
            }
            _ => Ok(()), // nothing else is expected from a miner; ignore rather than drop the connection
        }
    }

    /// OpenExtendedMiningChannel / OpenStandardMiningChannel: payout, extranonce prefix, the reference channel, the
    /// reply, the miner on the API, and its first job.
    async fn open_channel(&mut self, extended: bool, request_id: u32, user: String, nominal: f32, max_target: Target,
                          min_extranonce: usize) -> Result<()> {
        let user: String = user.chars().filter(|c| !c.is_control()).take(120).collect();
        let refuse = |code: &str| MiningOwned::OpenMiningChannelError(OpenMiningChannelErrorOwned {
            request_id, error_code: code.to_string().try_into().unwrap() });
        if self.chans.len() >= MAX_CHANNELS_PER_CONN {
            return self.send_mining(refuse("max-channels-reached")).await;
        }
        let (address, spk) = match self.pool.payout_for(&user).await {
            Payout::To(address, spk) => (address, spk),
            Payout::NoAddress => {
                log!("INFO", "refused {} {} (Stratum V2): no payout address yet", self.ip, user);
                return self.send_mining(refuse("unknown-user")).await;
            }
            Payout::NoAnswer => {
                log!("INFO", "refused {} {} (Stratum V2) for now: the node can't check the address in its username (down, \
                              starting or slow); the miner will try again", self.ip, user);
                return self.send_mining(refuse("unknown-user")).await;
            }
        };
        let allocated = {
            let mut a = self.sv2.allocator.lock().unwrap();
            if extended { a.allocate_extended(min_extranonce) } else { a.allocate_standard() }
        };
        let prefix = match allocated {
            Ok(p) => p,
            Err(e) => {
                log!("WARNING", "Stratum V2 {}: extranonce: {:?}", self.ip, e);
                return self.send_mining(refuse("min-extranonce-size-too-large")).await;
            }
        };
        let channel_id = self.next_channel;
        self.next_channel += 1;
        // the miner as the API shows it: name after the first dot, like V1 usernames
        let name = user.split_once('.').map(|(_, n)| n.to_string()).filter(|n| !n.is_empty())
            .unwrap_or_else(|| if user.is_empty() { self.ip.clone() } else { user.clone() });
        // per-miner settings, like V1: a share time (shares per minute) and a fixed difficulty
        let ov = self.pool.override_for(&name);
        let share_s = ov["share_seconds"].as_f64().unwrap_or(self.pool.cfg.share_seconds).clamp(1.0, 300.0);
        let spm = (60.0 / share_s) as f32;
        let fixed_diff = ov["diff"].as_f64();
        let tag = self.pool.cfg.coinbase_tag.clone();
        let made = if extended {
            ExtendedChannel::new_for_pool(channel_id, user.clone(), prefix, max_target, nominal, true, CLIENT_EXTRANONCE as u16,
                                          SHARE_BATCH, spm, tag, None).map(Ch::Ext).map_err(|e| format!("{:?}", e))
        } else {
            StandardChannel::new_for_pool(channel_id, user.clone(), prefix, max_target, nominal, SHARE_BATCH, spm,
                                          tag, None).map(Ch::Std).map_err(|e| format!("{:?}", e))
        };
        let mut ch = match made {
            Ok(ch) => ch,
            Err(e) => {
                log!("INFO", "refused {} {} (Stratum V2): {}", self.ip, user, e);
                return self.send_mining(refuse(if e.contains("Target") { "max-target-out-of-range" } else { "invalid-nominal-hashrate" })).await;
            }
        };
        // start at the fixed difficulty, or where this miner left off (like V1's remembered difficulty), instead of the
        // miner's own guess: a difficulty is a hashrate at this channel's share rate, which the channel turns into a target
        let start = fixed_diff.or_else(|| self.pool.remembered_diff(&name));
        // a miner new to this pool: its own hashrate guess, but never under the V1 port's start difficulty
        let floor = self.pool.cfg.start_diff;
        let guess = on!(&ch, x => x.get_target().difficulty_float());
        let start = start.or(if guess < floor { Some(floor) } else { None });
        if let Some(d) = start {
            let h = (d * 4_294_967_296.0 * spm as f64 / 60.0) as f32;
            if on!(&mut ch, x => x.update_channel(h, None).is_err()) {
                log!("INFO", "{} (Stratum V2): couldn't start at difficulty {} (outside what the miner allows)", name, fmt_diff(d));
            }
        }
        let ok = match &ch {
            Ch::Ext(c) => MiningOwned::OpenExtendedMiningChannelSuccess(OpenExtendedMiningChannelSuccessOwned {
                request_id, channel_id,
                target: c.get_target().to_le_bytes().into(),
                extranonce_size: c.get_rollable_extranonce_size(),
                extranonce_prefix: c.get_extranonce_prefix().to_vec().try_into().map_err(|e| anyhow!("{:?}", e))?,
                group_channel_id: 0,
            }),
            Ch::Std(c) => MiningOwned::OpenStandardMiningChannelSuccess(OpenStandardMiningChannelSuccessOwned {
                request_id: request_id.into(), channel_id,
                target: c.get_target().to_le_bytes().into(),
                extranonce_prefix: c.get_extranonce_prefix().to_vec().try_into().map_err(|e| anyhow!("{:?}", e))?,
                group_channel_id: 0,
            }),
        };
        self.send_mining(ok).await?;
        let diff = on!(&ch, x => x.get_target().difficulty_float());
        let kind = if extended { "extended" } else { "standard" };
        {
                let mut info = WorkerInfo::new(&self.ip, now_f());
                info.name = name.clone();
                info.user = user.clone();
                info.agent = self.agent.clone();
                info.address = address.clone();
                info.spk = spk.clone();
                info.diff = diff;
                info.protocol = if extended { "SV2 extended" } else { "SV2 standard" };
                let info = Arc::new(Mutex::new(info));
                let worker_id = self.pool.next_worker_id();
                // difficulty changes from the API reach this connection tagged with the channel
                let (ctl_tx, mut ctl_rx) = mpsc::unbounded_channel::<Ctl>();
                let conn_tx = self.ctl_tx.clone();
                tokio::spawn(async move {
                    while let Some(Ctl::SetDiff(d)) = ctl_rx.recv().await {
                        if conn_tx.send((channel_id, d)).is_err() {
                            break;
                        }
                    }
                });
                self.pool.workers.lock().unwrap().insert(worker_id, WorkerHandle { info: info.clone(), ctl: ctl_tx });
                let vardiff = VardiffState::new().map_err(|e| anyhow!("vardiff: {:?}", e))?;
                self.chans.insert(channel_id, Chan { ch, vardiff, worker_id, info, name: name.clone(), address: address.clone(), spk,
                                                     tip: String::new(), fixed: fixed_diff.is_some(), job_diff: HashMap::new(),
                                                     early: (now_f(), 0, 0.0) });
                log!("INFO", "authorized {} {} ({}, Stratum V2 {} channel {}) pays {}, difficulty {}{}", self.ip, name, self.agent, kind,
                     channel_id, address, fmt_diff(diff), if fixed_diff.is_some() { " (fixed)" } else if start.is_some() { " (remembered)" } else { "" });
        }
        if let Some(job) = self.pool.current() {
            self.push_job(channel_id, &job, false).await?;
        }
        Ok(())
    }

    /// Give one channel a Core job: a new block's job as a future template plus SetNewPrevHash, otherwise as an
    /// immediate job for the block it is already on. When the earlier work must not be used any more (`flush`: the
    /// node refused that job), the job goes out like a new block's, with SetNewPrevHash for the same block: the miner
    /// drops its old jobs, and shares on them are refused as stale (V1's clean_jobs). A payout change does NOT flush:
    /// the new job (new address) becomes the active one at once, but a late share on an older job is still accepted,
    /// and if it is a block it is still submitted (it pays the old address), as on V1. Flushing there would refuse a
    /// real block found in the moment of the change.
    async fn push_job(&mut self, channel_id: u32, job: &Arc<Job>, flush: bool) -> Result<()> {
        let Some(c) = self.chans.get_mut(&channel_id) else { return Ok(()) };
        let (spk, address) = {
            let i = c.info.lock().unwrap();
            (i.spk.clone(), i.address.clone())
        };
        // a new payout address (set on the page, or the default address now enforced) reaches this channel's next job
        let repay = !spk.is_empty() && spk != c.spk;
        if repay {
            log!("INFO", "{} {}: Stratum V2 work now pays {}", self.ip, c.name, address);
            c.spk = spk;
            c.address = address;
        }
        let template_id = u64::from_str_radix(&job.id, 16).unwrap_or(0);
        let new_block = c.tip != job.prev_hex || flush;
        let template = new_template(job, template_id, new_block)?;
        let outputs = vec![TxOut { value: Amount::from_sat(job.value), script_pubkey: ScriptBuf::from(c.spk.clone()) }];
        on!(&mut c.ch, x => x.on_new_template(template, outputs).map_err(|e| anyhow!("job for channel {}: {:?}", channel_id, e)))?;
        let mut out: Vec<MiningOwned> = Vec::new();
        if new_block {
            let job_id = on!(&c.ch, x => x.get_future_job_id_from_template_id(template_id)).ok_or_else(|| anyhow!("no future job"))?;
            out.push(match &c.ch {
                Ch::Ext(x) => MiningOwned::NewExtendedMiningJob(x.get_future_job(job_id).ok_or_else(|| anyhow!("no future job"))?.get_job_message().clone()),
                Ch::Std(x) => MiningOwned::NewMiningJob(x.get_future_job(job_id).ok_or_else(|| anyhow!("no future job"))?.get_job_message().clone()),
            });
            let mut target = job.target;
            target.reverse(); // big-endian -> the little-endian bytes SV2 uses
            let snph = SetNewPrevHashTdp { template_id, prev_hash: job.prev.into(), ntime_start: job.curtime,
                                           n_bits: job.bits, target: target.into() };
            on!(&mut c.ch, x => x.on_set_new_prev_hash(snph).map_err(|e| anyhow!("new block for channel {}: {:?}", channel_id, e)))?;
            out.push(MiningOwned::SetNewPrevHash(SetNewPrevHashMp { channel_id, job_id, prev_hash: job.prev.into(),
                                                               ntime_start: job.curtime, nbits: job.bits }));
            c.tip = job.prev_hex.clone();
        } else {
            out.push(match &c.ch {
                Ch::Ext(x) => MiningOwned::NewExtendedMiningJob(x.get_active_job().ok_or_else(|| anyhow!("no active job"))?.get_job_message().clone()),
                Ch::Std(x) => MiningOwned::NewMiningJob(x.get_active_job().ok_or_else(|| anyhow!("no active job"))?.get_job_message().clone()),
            });
        }
        let c = self.chans.get_mut(&channel_id).expect("channel");
        let d = on!(&c.ch, x => x.get_target().difficulty_float());
        for m in &out {
            let id = match m {
                MiningOwned::NewExtendedMiningJob(j) => j.job_id,
                MiningOwned::NewMiningJob(j) => j.job_id,
                _ => continue,
            };
            if new_block {
                c.job_diff.clear(); // older jobs are stale now
            }
            c.job_diff.insert(id, d);
        }
        if c.job_diff.len() > 200 {
            let keep: Vec<u32> = { let mut k: Vec<u32> = c.job_diff.keys().copied().collect(); k.sort_unstable(); k.split_off(k.len() - 100) };
            c.job_diff.retain(|k, _| keep.contains(k));
        }
        for m in out {
            self.send_mining(m).await?;
        }
        Ok(())
    }

    async fn share(&mut self, sub: Sub) -> Result<()> {
        let (channel_id, seq, job_id, version, ntime, nonce) = match &sub {
            Sub::Ext(s) => (s.channel_id, s.sequence_number, s.job_id, s.version, s.ntime, s.nonce),
            Sub::Std(s) => (s.channel_id, s.sequence_number, s.job_id, s.version, s.ntime, s.nonce),
        };
        let bad_channel = SubmitSharesErrorOwned { channel_id, sequence_number: seq,
                                                   error_code: "invalid-channel-id".to_string().try_into().unwrap() };
        let Some(c) = self.chans.get_mut(&channel_id) else {
            return self.send_mining(MiningOwned::SubmitSharesError(bad_channel)).await;
        };
        c.vardiff.increment_shares_since_last_update();
        let now_diff = on!(&c.ch, x => x.get_target().difficulty_float());
        let credit = c.job_diff.get(&job_id).map_or(now_diff, |d| d.min(now_diff));
        let res = match (&mut c.ch, sub) {
            (Ch::Ext(x), Sub::Ext(s)) => x.validate_share(s),
            (Ch::Std(x), Sub::Std(s)) => x.validate_share(s),
            _ => return self.send_mining(MiningOwned::SubmitSharesError(bad_channel)).await, // wrong kind for this channel
        };
        let now = now_f();
        let ok = |c: &Chan| {
            let a = on!(&c.ch, x => x.get_share_accounting());
            SubmitSharesSuccessOwned { channel_id, last_sequence_number: a.get_last_share_sequence_number(),
                                  new_submits_accepted_count: a.get_last_batch_accepted(), new_shares_sum: a.get_last_batch_work_sum() }
        };
        match res {
            Ok(ShareValidationResult::Valid(hash)) => {
                let share_diff = hash_diff(hash.as_ref());
                self.credit(channel_id, credit, share_diff, now, false);
                let m = ok(&self.chans[&channel_id]);
                self.send_mining(MiningOwned::SubmitSharesSuccess(m)).await?;
                self.early_retarget(channel_id, credit, now).await
            }
            Ok(ShareValidationResult::BlockFound(hash, template_id, coinbase)) => {
                let share_diff = hash_diff(hash.as_ref());
                self.credit(channel_id, credit, share_diff, now, true);
                let c = &self.chans[&channel_id];
                let (name, address) = (c.name.clone(), c.address.clone());
                let job = template_id.and_then(|t| self.pool.job(&format!("{:x}", t)));
                match (job, legacy_coinbase(&coinbase)) {
                    (Some(job), Some(cb)) => {
                        let header = job.header(&cb, version, ntime, nonce);
                        tokio::spawn(self.pool.clone().found_block(name, self.ip.clone(), address, job, header, cb, share_diff));
                    }
                    _ => log!("CRITICAL", "Stratum V2 block from {} {} could not be rebuilt (job {} / template {:?} gone)",
                              self.ip, name, job_id, template_id),
                }
                let m = ok(&self.chans[&channel_id]);
                self.send_mining(MiningOwned::SubmitSharesSuccess(m)).await
            }
            Err(e) => {
                let (code, reason) = match &e {
                    ShareValidationError::Invalid(c) => (*c, "invalid"),
                    ShareValidationError::Stale(c) => (*c, "stale"),
                    ShareValidationError::InvalidJobId(c) => (*c, "job not found"),
                    ShareValidationError::DoesNotMeetTarget(c) => (*c, "low difficulty"),
                    ShareValidationError::DuplicateShare(c) => (*c, "duplicate"),
                    ShareValidationError::BadExtranonceSize(c) => (*c, "bad extranonce"),
                    ShareValidationError::VersionRollingNotAllowed(c) => (*c, "bad version"),
                    ShareValidationError::SeenSharesBudgetExhausted => return Err(anyhow!("share budget exhausted")),
                    other => return Err(anyhow!("share check: {:?}", other)),
                };
                let name = self.chans[&channel_id].name.clone();
                log!("WARNING", "share rejected from {} ({}, Stratum V2): {}", name, self.ip, reason);
                *self.chans[&channel_id].info.lock().unwrap().rejected.entry(reason.to_string()).or_insert(0) += 1;
                self.pool.share_rejected(&name, reason);
                let m = SubmitSharesErrorOwned { channel_id, sequence_number: seq, error_code: code.to_string().try_into().unwrap() };
                self.send_mining(MiningOwned::SubmitSharesError(m)).await
            }
        }
    }

    fn credit(&self, channel_id: u32, credit: f64, share_diff: f64, now: f64, block: bool) {
        let c = &self.chans[&channel_id];
        {
            let mut i = c.info.lock().unwrap();
            i.accepted += 1;
            i.last_share = now;
            i.shares.push_back((now, credit));
            while i.shares.front().map_or(false, |s| s.0 < now - 3600.0) {
                i.shares.pop_front();
            }
            if share_diff > i.best {
                i.best = share_diff;
            }
            if let Some(j) = self.pool.current() {
                i.last_height = Some(j.height);
            }
            if i.accepted == 1 {
                // how long a miner takes to send its first share after connecting (a Bitaxe returning after a Core
                // update once took ~90 s at its remembered difficulty: this shows whether that repeats)
                log!("INFO", "{} {}: first share {:.1} s after connecting (difficulty {})", self.ip, c.name, now - i.connected,
                     fmt_diff(i.diff));
            }
        }
        self.pool.share_accepted(&c.name, credit, share_diff, now, block);
    }

    /// Every minute: the reference vardiff per channel; a new target goes to the miner with SetTarget.
    /// A difficulty from the API (a per-miner override set, or removed: then the miner's current difficulty comes back
    /// and vardiff takes over again). Sent to the miner with SetTarget.
    async fn set_difficulty(&mut self, channel_id: u32, diff: f64) -> Result<()> {
        let Some(c) = self.chans.get_mut(&channel_id) else { return Ok(()) };
        c.fixed = self.pool.override_for(&c.name)["diff"].as_f64().is_some();
        let spm = on!(&c.ch, x => x.get_shares_per_minute()) as f64;
        let h = (diff * 4_294_967_296.0 * spm / 60.0) as f32;
        if on!(&mut c.ch, x => x.update_channel(h, None).is_err()) {
            log!("WARNING", "{} (Stratum V2): difficulty {} is outside what the miner allows", c.name, fmt_diff(diff));
            return Ok(());
        }
        let t = *on!(&c.ch, x => x.get_target());
        c.info.lock().unwrap().diff = t.difficulty_float();
        log!("INFO", "{} difficulty set to {} (Stratum V2{})", c.name, fmt_diff(t.difficulty_float()), if c.fixed { ", fixed" } else { "" });
        self.send_mining(MiningOwned::SetTarget(SetTargetOwned { channel_id, target: t.to_le_bytes().into() })).await
    }

    /// A new channel's first minutes: after 20 shares, if they came in at least 4x faster than this channel's share
    /// rate, set the difficulty from the measured rate right away (the minute vardiff would otherwise let a miner that
    /// guessed its hashrate far too low flood the pool, and the reference share-budget check drops it).
    async fn early_retarget(&mut self, channel_id: u32, credit: f64, now: f64) -> Result<()> {
        let Some(c) = self.chans.get_mut(&channel_id) else { return Ok(()) };
        if c.fixed || now - c.early.0 > 120.0 {
            return Ok(());
        }
        c.early.1 += 1;
        c.early.2 += credit;
        if c.early.1 < 20 {
            return Ok(());
        }
        let spm = on!(&c.ch, x => x.get_shares_per_minute()) as f64;
        let rate = c.early.2 * 4_294_967_296.0 / (now - c.early.0).max(1.0); // hashes per second
        let want = rate * 60.0 / spm.max(0.1) / 4_294_967_296.0;
        let cur = on!(&c.ch, x => x.get_target().difficulty_float());
        c.early = (now, 0, 0.0);
        if want > cur * 4.0 {
            log!("INFO", "{} (Stratum V2): shares came in {:.0}x too fast, difficulty {} -> {}", c.name, want / cur, fmt_diff(cur), fmt_diff(want));
            return self.set_difficulty(channel_id, want).await;
        }
        Ok(())
    }

    async fn vardiff(&mut self) -> Result<()> {
        let mut out = Vec::new();
        let now_s = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
        for (id, c) in self.chans.iter_mut() {
            if c.fixed {
                continue; // a fixed difficulty from the API
            }
            // the reference vardiff judges every minute; at one share per ~10 s a single quiet minute (0 shares,
            // about 1 minute in 400) divides the difficulty by 3 and the next ones overshoot. Let it judge only once
            // there are VARDIFF_MIN_SHARES shares to go on, after 5 minutes, or after 2 minutes with no share at all (a
            // difficulty far too hard: by chance that's about 1 in 160,000 at one share per 10 s, so it steps down
            // every 2 minutes instead of every 5). A flood of shares is handled at once by early_retarget.
            let since = now_s.saturating_sub(c.vardiff.timestamp_of_last_update);
            let shares = c.vardiff.shares_since_last_update;
            if shares < VARDIFF_MIN_SHARES && since < 300 && !(shares == 0 && since >= 120) {
                continue;
            }
            let (h, t, spm) = on!(&c.ch, x => (x.get_nominal_hashrate(), *x.get_target(), x.get_shares_per_minute()));
            let Ok(Some(new_h)) = c.vardiff.try_vardiff(h, &t, spm) else {
                on!(&mut c.ch, x => x.set_stable_hashrate(true));
                continue;
            };
            on!(&mut c.ch, x => x.set_stable_hashrate(false));
            if on!(&mut c.ch, x => x.update_channel(new_h, None).is_ok()) {
                let t = *on!(&c.ch, x => x.get_target());
                let d = t.difficulty_float();
                let old = c.info.lock().unwrap().diff;
                c.info.lock().unwrap().diff = d;
                log!("INFO", "{} difficulty {} -> {} (Stratum V2)", c.name, crate::util::fmt_diff(old), crate::util::fmt_diff(d));
                out.push(SetTargetOwned { channel_id: *id, target: t.to_le_bytes().into() });
            }
        }
        for m in out {
            self.send_mining(MiningOwned::SetTarget(m)).await?;
        }
        Ok(())
    }
}

/// Test miner for standard channels (header-only mining, like Braiins OS): connects over encrypted SV2, opens a
/// standard channel, mines `shares` shares on the CPU and prints each result. On regtest every share is a block.
///   solo45-core sv2-miner <host:port> <authority pubkey> <user identity> <shares>
pub async fn test_miner(addr: &str, pubkey: &str, user: &str, shares: u32, pause_s: f64) -> Result<()> {
    use stratum_apps::stratum_core::common_messages_sv2::SetupConnectionOwned;
    use stratum_apps::stratum_core::mining_sv2::OpenStandardMiningChannelOwned;
    use stratum_apps::stratum_core::noise_sv2::Initiator;
    let key: Secp256k1PublicKey = pubkey.parse().map_err(|e| anyhow!("authority key: {:?}", e))?;
    let init = Initiator::from_raw_k(key.into_bytes()).map_err(|e| anyhow!("initiator: {:?}", e))?;
    let stream = TcpStream::connect(addr).await?;
    let noise = NoiseTcpStream::connect(stream, init, HANDSHAKE_TIMEOUT).await.map_err(|e| anyhow!("handshake: {:?}", e))?;
    let (mut r, mut w) = noise.into_split();
    // frames are read in their own task (read_frame is not cancel-safe), so the miner keeps taking new work while it
    // pauses between shares, like a real miner
    let (msg_tx, mut msg_rx) = mpsc::unbounded_channel::<Result<AnyMessageOwned>>();
    tokio::spawn(async move {
        loop {
            let res = match r.read_frame().await {
                Ok(mut f) => {
                    let header = f.header();
                    parse_message_frame_with_tlvs(header, f.payload(), &[]).map(|x| x.0.into_owned()).map_err(|e| anyhow!("{:?}", e))
                }
                Err(e) => Err(anyhow!("{:?}", e)),
            };
            let stop = res.is_err();
            if msg_tx.send(res).is_err() || stop {
                break;
            }
        }
    });
    let mut resume_at: Option<tokio::time::Instant> = None;
    let sticky = std::env::var("SOLO45_TEST_STICKY").map_or(false, |v| v == "1");
    let send = |m: AnyMessageOwned| -> Result<OutboundFrame> { OutboundFrame::from_message(m).map_err(|e| anyhow!("{:?}", e)) };
    let s = |t: &str| -> Result<_> { t.to_string().try_into().map_err(|e| anyhow!("{:?}", e)) };
    let setup = SetupConnectionOwned { protocol: Protocol::MiningProtocol, min_version: 2, max_version: 2, flags: 0,
        endpoint_host: s("")?, endpoint_port: 0, vendor: s("solo45-test")?, hardware_version: s("cpu")?,
        firmware: s("solo45-core-test")?, device_id: s("1")? };
    w.write_frame(send(AnyMessageOwned::Common(setup.into()))?).await.map_err(|e| anyhow!("{:?}", e))?;
    // SOLO45_TEST_NOMINAL: the hashrate it claims (default 1e5 H/s); a tiny one acts like Braiins OS at connect
    let nominal: f32 = std::env::var("SOLO45_TEST_NOMINAL").ok().and_then(|v| v.parse().ok()).unwrap_or(1e5);
    let open = OpenStandardMiningChannelOwned { request_id: 7u32.into(), user_identity: s(user)?, nominal_hash_rate: nominal,
                                                max_target: [0xffu8; 32].into() };
    let mut opened = false;
    let (mut channel, mut target, mut job): (u32, [u8; 32], Option<(u32, u32, [u8; 32])>) = (0, [0xff; 32], None);
    let (mut prev, mut ntime, mut nbits): (Option<[u8; 32]>, u32, u32) = (None, 0, 0);
    let mut jobs: HashMap<u32, (u32, [u8; 32])> = HashMap::new(); // job_id -> (version, merkle root)
    let (mut sent, mut seq) = (0u32, 0u32);
    let mut nonce_base = 0u32;
    loop {
        let wait = resume_at.map_or(Duration::from_secs(30), |t| t.saturating_duration_since(tokio::time::Instant::now()));
        let msg = match tokio::time::timeout(wait, msg_rx.recv()).await {
            Ok(Some(m)) => Some(m?),
            Ok(None) => return Err(anyhow!("connection closed")),
            Err(_) if resume_at.is_some() => None, // the pause is over: mine the next share
            Err(_) => return Err(anyhow!("no message for 30 s")),
        };
        if let Some(msg) = msg {
        match msg {
            AnyMessageOwned::Common(CommonMessagesOwned::SetupConnectionSuccess(m)) => {
                println!("SetupConnectionSuccess version {} flags {:#x}", m.used_version, m.flags);
                w.write_frame(send(AnyMessageOwned::Mining(MiningOwned::OpenStandardMiningChannel(open.clone())))?).await.map_err(|e| anyhow!("{:?}", e))?;
            }
            AnyMessageOwned::Mining(MiningOwned::OpenStandardMiningChannelSuccess(m)) => {
                channel = m.channel_id;
                target = m.target.to_array();
                opened = true;
                println!("OpenStandardMiningChannelSuccess channel {} extranonce_prefix {}", channel, hex::encode(m.extranonce_prefix.as_ref()));
            }
            AnyMessageOwned::Mining(MiningOwned::OpenMiningChannelError(m)) => {
                return Err(anyhow!("channel refused: {}", m.error_code.as_utf8_or_hex()));
            }
            AnyMessageOwned::Mining(MiningOwned::SetTarget(m)) => target = m.target.to_array(),
            AnyMessageOwned::Mining(MiningOwned::NewMiningJob(m)) => {
                jobs.insert(m.job_id, (m.version, m.merkle_root.to_array()));
                // SOLO45_TEST_STICKY=1: keep mining the job it has (tests: a late share on an older job of the same block)
                if m.ntime_start.clone().into_inner().is_some() && !(sticky && job.is_some()) {
                    job = Some((m.job_id, m.version, m.merkle_root.to_array())); // for the current block: mine it now
                }
            }
            AnyMessageOwned::Mining(MiningOwned::SetNewPrevHash(m)) => {
                println!("SetNewPrevHash job {} prev {}", m.job_id, hex::encode(m.prev_hash.to_array()));
                prev = Some(m.prev_hash.to_array());
                ntime = m.ntime_start;
                nbits = m.nbits;
                job = jobs.get(&m.job_id).map(|(v, root)| (m.job_id, *v, *root));
            }
            AnyMessageOwned::Mining(MiningOwned::SubmitSharesSuccess(m)) => {
                println!("SubmitSharesSuccess last seq {} accepted {}", m.last_sequence_number, m.new_submits_accepted_count);
                if sent >= shares {
                    return Ok(());
                }
            }
            AnyMessageOwned::Mining(MiningOwned::SubmitSharesError(m)) => {
                println!("SubmitSharesError seq {}: {}", m.sequence_number, m.error_code.as_utf8_or_hex());
                if sent >= shares {
                    return Ok(());
                }
            }
            _ => {}
        }
        }
        // mine one share on the current job, then wait for the answer (and new work, on regtest)
        if let (true, Some((job_id, version, root)), Some(p)) = (opened, job, prev) {
            if sent < shares && seq == sent {
                if pause_s > 0.0 && sent > 0 {
                    // load tests: one share every pause_s, still taking new work meanwhile
                    match resume_at {
                        None => {
                            resume_at = Some(tokio::time::Instant::now() + Duration::from_secs_f64(pause_s));
                            continue;
                        }
                        Some(t) if tokio::time::Instant::now() < t => continue,
                        _ => resume_at = None,
                    }
                }
                let mut hdr = Vec::with_capacity(80);
                hdr.extend(version.to_le_bytes());
                hdr.extend(p);
                hdr.extend(root);
                hdr.extend(ntime.to_le_bytes());
                hdr.extend(nbits.to_le_bytes());
                let mut tgt = target;
                tgt.reverse(); // compare as big-endian numbers
                for n in nonce_base.. {
                    let mut h = hdr.clone();
                    h.extend(n.to_le_bytes());
                    let mut d = crate::util::sha256d(&h);
                    d.reverse();
                    if d <= tgt {
                        let sub = stratum_apps::stratum_core::mining_sv2::SubmitSharesStandardOwned {
                            channel_id: channel, sequence_number: seq, job_id, nonce: n, ntime, version };
                        w.write_frame(send(AnyMessageOwned::Mining(MiningOwned::SubmitSharesStandard(sub)))?).await.map_err(|e| anyhow!("{:?}", e))?;
                        println!("share {} on job {}: nonce {} hash {}", seq, job_id, n, hex::encode(d));
                        nonce_base = n.wrapping_add(1);
                        seq += 1;
                        sent += 1;
                        // a block (every share on regtest): wait for the next block's work; otherwise keep mining this job
                        let exp = (nbits >> 24) as usize;
                        let mut net = [0u8; 32]; // the network target, big-endian
                        for (i, b) in (nbits & 0x00ff_ffff).to_be_bytes()[1..].iter().enumerate() {
                            if let Some(p) = (32 + i).checked_sub(exp) {
                                if p < 32 {
                                    net[p] = *b;
                                }
                            }
                        }
                        if d <= net {
                            job = None;
                        }
                        break;
                    }
                }
            }
        }
    }
}

/// A Core job as a Template Distribution NewTemplate (template_id = the job's number).
fn new_template(job: &Job, template_id: u64, future: bool) -> Result<NewTemplateOwned> {
    let mut outputs = Vec::new();
    let mut count = 0u32;
    if let Some(wc) = &job.witness_commitment {
        outputs.extend(0u64.to_le_bytes());
        outputs.extend(crate::util::varint(wc.len() as u64));
        outputs.extend(wc);
        count = 1;
    }
    let path: Vec<_> = job.branch.iter().map(|h| (*h).into()).collect();
    Ok(NewTemplateOwned {
        template_id,
        future_template: future,
        version: job.version,
        coinbase_tx_version: 2,
        coinbase_prefix: push(&script_num(job.height)).try_into().map_err(|e| anyhow!("coinbase prefix: {:?}", e))?,
        coinbase_tx_input_sequence: 0xffff_ffff,
        coinbase_tx_value_remaining: job.value,
        coinbase_tx_outputs_count: count,
        coinbase_tx_outputs: outputs.try_into().map_err(|e| anyhow!("coinbase outputs: {:?}", e))?,
        coinbase_tx_locktime: 0,
        merkle_path: path.try_into().map_err(|e| anyhow!("merkle path: {:?}", e))?,
    })
}

/// A share hash (internal byte order) as a difficulty.
fn hash_diff(h: &[u8]) -> f64 {
    let mut be = [0u8; 32];
    be.copy_from_slice(&h[..32]);
    be.reverse();
    target_diff(&be)
}

/// The found block's coinbase without its segwit marker and witness (Core's Job::block puts those back): the
/// reference channel returns it with the BIP141 parts.
pub fn legacy_coinbase(cb: &[u8]) -> Option<Vec<u8>> {
    if cb.len() < 4 + 2 + 4 || cb[4] != 0 || cb[5] != 1 {
        return Some(cb.to_vec()); // already without witness
    }
    let n = cb.len();
    let wit = n.checked_sub(4 + 34)?; // one witness item: 0x01 0x20 + 32 zero bytes, then the locktime
    if cb[wit] != 0x01 || cb[wit + 1] != 0x20 || cb[wit + 2..n - 4].iter().any(|b| *b != 0) {
        return None;
    }
    let mut v = cb[..4].to_vec();
    v.extend_from_slice(&cb[6..wit]);
    v.extend_from_slice(&cb[n - 4..]);
    Some(v)
}

#[cfg(test)]
mod tests {
    #[test]
    fn base58check_matches_the_reference_key_format() {
        // vectors checked with an independent (Python) Base58Check; the reference key_utils reads ours back
        let s = super::base58check(&[1u8; 32]);
        assert_eq!(s, "SeLqn3UAUoRymWmwW7axrzJK7JfNaBR2cHCryA6cFsgFkHEF");
        let k: stratum_apps::key_utils::Secp256k1SecretKey = s.parse().unwrap();
        assert_eq!(k.to_string(), s);
        assert_eq!(super::base58check(&[0, 0, 1]), "11BwW2qR"); // leading zeros become '1's
    }

    #[test]
    fn legacy_coinbase_drops_the_witness() {
        let legacy = [vec![2, 0, 0, 0], vec![1, 9, 9, 9], vec![0, 0, 0, 0]].concat();
        let mut segwit = vec![2, 0, 0, 0, 0, 1, 1, 9, 9, 9, 1, 0x20];
        segwit.extend([0u8; 32]);
        segwit.extend([0, 0, 0, 0]);
        assert_eq!(super::legacy_coinbase(&segwit).unwrap(), legacy);
        assert_eq!(super::legacy_coinbase(&legacy).unwrap(), legacy);
        let mut bad = segwit.clone();
        bad[20] = 7; // a witness item that isn't the zero reserved value
        assert!(super::legacy_coinbase(&bad).is_none());
    }
}
