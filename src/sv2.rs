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
use crate::pool::{Ctl, NewJob, Pool, WorkerHandle, WorkerInfo};
use crate::util::{now_f, push, script_num, target_diff};
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
        share_accounting::{ShareValidationError, ShareValidationResult},
    },
    Vardiff, VardiffState,
};
use stratum_apps::stratum_core::common_messages_sv2::{Protocol, SetupConnectionErrorOwned, SetupConnectionSuccess};
use stratum_apps::stratum_core::mining_sv2::{
    OpenExtendedMiningChannelSuccessOwned, OpenMiningChannelErrorOwned, SetNewPrevHashOwned as SetNewPrevHashMp,
    SetTargetOwned, SubmitSharesErrorOwned, SubmitSharesExtendedOwned, SubmitSharesSuccessOwned,
};
use stratum_apps::stratum_core::noise_sv2::Responder;
use stratum_apps::stratum_core::parsers_sv2::{parse_message_frame_with_tlvs, AnyMessageOwned, CommonMessagesOwned, MiningOwned};
use stratum_apps::stratum_core::template_distribution_sv2::{NewTemplateOwned, SetNewPrevHashOwned as SetNewPrevHashTdp};
use stratum_apps::utils::types::OutboundFrame;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};

const SV2_VERSION: u16 = 2;
const REQUIRES_EXTENDED_CHANNELS: u32 = 0x02;
const SERVER_TAG: u8 = 0x45; // first extranonce byte on this pool ("45")
const MAX_CHANNELS: u32 = 65_536; // 2 bytes of channel index
const CLIENT_EXTRANONCE: u8 = 16; // the space each channel rolls itself (what the reference pool gives)
const SHARES_PER_MINUTE: f32 = 6.0; // a share every 10 s, like Core's V1 default
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

/// One extended channel on a connection: the reference channel state plus the miner as the pool shows it.
struct Chan {
    ch: ExtendedChannel,
    vardiff: VardiffState,
    worker_id: u64,
    info: Arc<Mutex<WorkerInfo>>,
    name: String,
    address: String,
    spk: Vec<u8>,
    tip: String, // the block this channel's jobs build on (prev hash, display hex)
}

struct Conn {
    pool: Arc<Pool>,
    sv2: Arc<Sv2>,
    w: NoiseTcpWriteHalf,
    ip: String,
    agent: String,
    chans: HashMap<u32, Chan>,
    next_channel: u32,
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
    let mut c = Conn { pool: pool.clone(), sv2, w, ip: peer.ip().to_string(), agent: "sv2".into(), chans: HashMap::new(), next_channel: 1 };
    let result = c.run(&mut frx).await;
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

    async fn run(&mut self, frx: &mut mpsc::Receiver<stratum_apps::utils::types::InboundFrame>) -> Result<()> {
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
        let ok = SetupConnectionSuccess { used_version: SV2_VERSION, flags: REQUIRES_EXTENDED_CHANNELS };
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
                    let job = match j {
                        Ok(NewJob { job, .. }) => job,
                        Err(broadcast::error::RecvError::Lagged(_)) => match self.pool.current() { Some(j) => j, None => continue },
                        Err(broadcast::error::RecvError::Closed) => return Ok(()),
                    };
                    let ids: Vec<u32> = self.chans.keys().copied().collect();
                    for id in ids {
                        self.push_job(id, &job).await?;
                    }
                }
                _ = tick.tick() => self.vardiff().await?,
            }
        }
    }

    async fn handle(&mut self, msg: AnyMessageOwned) -> Result<()> {
        match msg {
            AnyMessageOwned::Mining(MiningOwned::OpenExtendedMiningChannel(m)) => {
                let user: String = m.user_identity.as_utf8_or_hex().chars().filter(|c| !c.is_control()).take(120).collect();
                let request_id = m.request_id;
                let refuse = |code: &str| MiningOwned::OpenMiningChannelError(OpenMiningChannelErrorOwned {
                    request_id, error_code: code.to_string().try_into().unwrap() });
                if self.chans.len() >= MAX_CHANNELS_PER_CONN {
                    return self.send_mining(refuse("max-channels-reached")).await;
                }
                let Some((address, spk)) = self.pool.payout_for(&user).await else {
                    log!("INFO", "refused {} {} (Stratum V2): no payout address yet", self.ip, user);
                    return self.send_mining(refuse("unknown-user")).await;
                };
                let allocated = self.sv2.allocator.lock().unwrap().allocate_extended(m.min_extranonce_size as usize);
                let prefix = match allocated {
                    Ok(p) => p,
                    Err(e) => {
                        log!("WARNING", "Stratum V2 {}: extranonce: {:?}", self.ip, e);
                        return self.send_mining(refuse("min-extranonce-size-too-large")).await;
                    }
                };
                let channel_id = self.next_channel;
                self.next_channel += 1;
                let max_target = Target::from_le_bytes(m.max_target.to_array());
                let ch = ExtendedChannel::new_for_pool(channel_id, user.clone(), prefix, max_target, m.nominal_hash_rate, true,
                                                       CLIENT_EXTRANONCE as u16, SHARE_BATCH, SHARES_PER_MINUTE,
                                                       self.pool.cfg.coinbase_tag.clone(), None);
                let ch = match ch {
                    Ok(ch) => ch,
                    Err(e) => {
                        log!("INFO", "refused {} {} (Stratum V2): {:?}", self.ip, user, e);
                        return self.send_mining(refuse("invalid-nominal-hashrate")).await;
                    }
                };
                let ok = OpenExtendedMiningChannelSuccessOwned {
                    request_id, channel_id,
                    target: ch.get_target().to_le_bytes().into(),
                    extranonce_size: ch.get_rollable_extranonce_size(),
                    extranonce_prefix: ch.get_extranonce_prefix().to_vec().try_into().map_err(|e| anyhow!("{:?}", e))?,
                    group_channel_id: 0,
                };
                self.send_mining(MiningOwned::OpenExtendedMiningChannelSuccess(ok)).await?;
                // the miner as the API shows it: name after the first dot, like V1 usernames
                let name = user.split_once('.').map(|(_, n)| n.to_string()).filter(|n| !n.is_empty())
                    .unwrap_or_else(|| if user.is_empty() { self.ip.clone() } else { user.clone() });
                let mut info = WorkerInfo::new(&self.ip, now_f());
                info.name = name.clone();
                info.user = user.clone();
                info.agent = self.agent.clone();
                info.address = address.clone();
                info.spk = spk.clone();
                info.diff = ch.get_target().difficulty_float();
                let info = Arc::new(Mutex::new(info));
                let worker_id = self.pool.next_worker_id();
                let (ctl_tx, _ctl_rx) = mpsc::unbounded_channel::<Ctl>();
                self.pool.workers.lock().unwrap().insert(worker_id, WorkerHandle { info: info.clone(), ctl: ctl_tx });
                let vardiff = VardiffState::new().map_err(|e| anyhow!("vardiff: {:?}", e))?;
                self.chans.insert(channel_id, Chan { ch, vardiff, worker_id, info, name: name.clone(), address: address.clone(), spk, tip: String::new() });
                log!("INFO", "authorized {} {} ({}, Stratum V2 channel {}) pays {}", self.ip, name, self.agent, channel_id, address);
                if let Some(job) = self.pool.current() {
                    self.push_job(channel_id, &job).await?;
                }
                Ok(())
            }
            AnyMessageOwned::Mining(MiningOwned::OpenStandardMiningChannel(m)) => {
                let e = OpenMiningChannelErrorOwned { request_id: m.get_request_id_as_u32(),
                                                 error_code: "standard-channels-not-supported".to_string().try_into().unwrap() };
                self.send_mining(MiningOwned::OpenMiningChannelError(e)).await
            }
            AnyMessageOwned::Mining(MiningOwned::SubmitSharesExtended(s)) => self.share(s).await,
            AnyMessageOwned::Mining(MiningOwned::UpdateChannel(u)) => {
                let Some(c) = self.chans.get_mut(&u.channel_id) else { return Ok(()) };
                let max = Target::from_le_bytes(u.max_target.to_array());
                if c.ch.update_channel(u.nominal_hash_rate, Some(max)).is_ok() {
                    let t = c.ch.get_target().to_le_bytes();
                    c.info.lock().unwrap().diff = c.ch.get_target().difficulty_float();
                    let id = u.channel_id;
                    self.send_mining(MiningOwned::SetTarget(SetTargetOwned { channel_id: id, target: t.into() })).await?;
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

    /// Give one channel a Core job: a new block's job as a future template plus SetNewPrevHash, otherwise as an
    /// immediate job for the block it is already on.
    async fn push_job(&mut self, channel_id: u32, job: &Arc<Job>) -> Result<()> {
        let Some(c) = self.chans.get_mut(&channel_id) else { return Ok(()) };
        let template_id = u64::from_str_radix(&job.id, 16).unwrap_or(0);
        let new_block = c.tip != job.prev_hex;
        let template = new_template(job, template_id, new_block)?;
        let outputs = vec![TxOut { value: Amount::from_sat(job.value), script_pubkey: ScriptBuf::from(c.spk.clone()) }];
        c.ch.on_new_template(template, outputs).map_err(|e| anyhow!("job for channel {}: {:?}", channel_id, e))?;
        let mut out: Vec<MiningOwned> = Vec::new();
        if new_block {
            let job_id = c.ch.get_future_job_id_from_template_id(template_id).ok_or_else(|| anyhow!("no future job"))?;
            let msg = c.ch.get_future_job(job_id).ok_or_else(|| anyhow!("no future job"))?.get_job_message().clone();
            out.push(MiningOwned::NewExtendedMiningJob(msg));
            let mut target = job.target;
            target.reverse(); // big-endian -> the little-endian bytes SV2 uses
            let snph = SetNewPrevHashTdp { template_id, prev_hash: job.prev.into(), ntime_start: job.curtime,
                                           n_bits: job.bits, target: target.into() };
            c.ch.on_set_new_prev_hash(snph).map_err(|e| anyhow!("new block for channel {}: {:?}", channel_id, e))?;
            out.push(MiningOwned::SetNewPrevHash(SetNewPrevHashMp { channel_id, job_id, prev_hash: job.prev.into(),
                                                               ntime_start: job.curtime, nbits: job.bits }));
            c.tip = job.prev_hex.clone();
        } else {
            let msg = c.ch.get_active_job().ok_or_else(|| anyhow!("no active job"))?.get_job_message().clone();
            out.push(MiningOwned::NewExtendedMiningJob(msg));
        }
        for m in out {
            self.send_mining(m).await?;
        }
        Ok(())
    }

    async fn share(&mut self, s: SubmitSharesExtendedOwned) -> Result<()> {
        let (channel_id, seq) = (s.channel_id, s.sequence_number);
        let Some(c) = self.chans.get_mut(&channel_id) else {
            let e = SubmitSharesErrorOwned { channel_id, sequence_number: seq, error_code: "invalid-channel-id".to_string().try_into().unwrap() };
            return self.send_mining(MiningOwned::SubmitSharesError(e)).await;
        };
        c.vardiff.increment_shares_since_last_update();
        let credit = c.ch.get_target().difficulty_float();
        let (version, ntime, nonce) = (s.version, s.ntime, s.nonce);
        let job_id = s.job_id;
        let res = c.ch.validate_share(s);
        let now = now_f();
        let ok = |c: &Chan| {
            let a = c.ch.get_share_accounting();
            SubmitSharesSuccessOwned { channel_id, last_sequence_number: a.get_last_share_sequence_number(),
                                  new_submits_accepted_count: a.get_last_batch_accepted(), new_shares_sum: a.get_last_batch_work_sum() }
        };
        match res {
            Ok(ShareValidationResult::Valid(hash)) => {
                let share_diff = hash_diff(hash.as_ref());
                self.credit(channel_id, credit, share_diff, now, false);
                let m = ok(&self.chans[&channel_id]);
                self.send_mining(MiningOwned::SubmitSharesSuccess(m)).await
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
        }
        self.pool.share_accepted(&c.name, credit, share_diff, now, block);
    }

    /// Every minute: the reference vardiff per channel; a new target goes to the miner with SetTarget.
    async fn vardiff(&mut self) -> Result<()> {
        let mut out = Vec::new();
        for (id, c) in self.chans.iter_mut() {
            let (h, t, spm) = (c.ch.get_nominal_hashrate(), *c.ch.get_target(), c.ch.get_shares_per_minute());
            let Ok(Some(new_h)) = c.vardiff.try_vardiff(h, &t, spm) else {
                c.ch.set_stable_hashrate(true);
                continue;
            };
            c.ch.set_stable_hashrate(false);
            if c.ch.update_channel(new_h, None).is_ok() {
                let d = c.ch.get_target().difficulty_float();
                let old = c.info.lock().unwrap().diff;
                c.info.lock().unwrap().diff = d;
                log!("INFO", "{} difficulty {} -> {} (Stratum V2)", c.name, crate::util::fmt_diff(old), crate::util::fmt_diff(d));
                out.push(SetTargetOwned { channel_id: *id, target: c.ch.get_target().to_le_bytes().into() });
            }
        }
        for m in out {
            self.send_mining(MiningOwned::SetTarget(m)).await?;
        }
        Ok(())
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
