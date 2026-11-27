//! Templates straight from Bitcoin Core 32+ over its IPC mining interface (`-ipcbind=unix`), through the Stratum V2
//! reference crate `bitcoin_core_sv2` (Template Distribution Protocol). Optional (SOLO45_IPC_SOCKET): the pool keeps
//! using getblocktemplate whenever IPC isn't connected, isn't current, or the template policy filters.
//!
//! Core pushes a template the moment a block arrives (prepared in advance) and again when fees rise, so a new
//! block's full work is ready in milliseconds instead of a getblocktemplate call. Each template is turned into the
//! same shape getblocktemplate returns (height, previousblockhash, version, bits, times, coinbasevalue,
//! default_witness_commitment, transactions with txid/hash/data), so the pool builds jobs exactly as before. What
//! IPC doesn't give is each transaction's fee: the template's total fees are known (coinbase value minus subsidy).
//!
//! capnp-rpc isn't Send, so the IPC session runs on its own thread with its own runtime and LocalSet; it reconnects
//! by itself (node restart, socket not there yet) and hands finished templates to the pool through `Ipc`.

use crate::util::sha256d;
use bitcoin_core_sv2::runtime_api::{template_distribution_protocol, BitcoinCoreVersion};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use stratum_apps::stratum_core::parsers_sv2::TemplateDistributionOwned;
use stratum_apps::stratum_core::template_distribution_sv2::{CoinbaseOutputConstraintsOwned, RequestTransactionDataOwned};
use tokio_util::sync::CancellationToken;

/// A template from IPC, in getblocktemplate's shape.
pub struct IpcTemplate {
    pub tpl: Value,
    pub prev_hex: String,
    pub at: Instant,
}

#[derive(Default)]
pub struct Ipc {
    pub latest: Mutex<Option<Arc<IpcTemplate>>>,
    /// woken whenever a new template is ready
    pub ready: tokio::sync::Notify,
    pub up: AtomicBool,
    pub templates: AtomicU64,
    pub reconnects: AtomicU64,
    pub last_error: Mutex<Option<String>>,
    /// templates Core sent that the pool couldn't use, and why the last one was left out (and when)
    pub skipped: AtomicU64,
    pub last_skip: Mutex<Option<(String, Instant)>>,
    /// the last skip that went to the log: the same reason is logged again only after 10 minutes
    skip_logged: Mutex<Option<(String, Instant)>>,
    /// the chain tip Core announced last (display hex): an extra new-block signal for the pool
    pub tip_tx: Mutex<Option<tokio::sync::mpsc::UnboundedSender<String>>>,
    /// the newest block Core announced, with what an empty job on top of it needs
    pub tip: Mutex<Option<IpcTip>>,
}

/// A new block as Core announced it (SetNewPrevHash + the pre-built template it points to): everything an empty
/// job for the next block needs, so the pool doesn't have to ask the node for the block header.
#[derive(Clone)]
pub struct IpcTip {
    pub prev_hex: String,
    pub height: u64,
    pub bits: u32,
    pub ntime: u32,
    pub version: u32,
}

/// What a NewTemplate gives that the pool needs (kept until its transactions arrive).
struct Pending {
    version: u32,
    height: u64,
    value: u64,
    witness_commitment: Option<String>,
}

impl Ipc {
    pub fn status(&self) -> Value {
        json!({
            "up": self.up.load(Ordering::Relaxed),
            "templates": self.templates.load(Ordering::Relaxed),
            "reconnects": self.reconnects.load(Ordering::Relaxed),
            "error": self.last_error.lock().unwrap().clone(),
            "age_s": self.latest.lock().unwrap().as_ref().map(|t| t.at.elapsed().as_secs_f64()),
            "skipped": self.skipped.load(Ordering::Relaxed),
            "last_skip": self.last_skip.lock().unwrap().as_ref()
                .map(|(r, at)| json!({"reason": r, "age_s": at.elapsed().as_secs_f64()})),
        })
    }

    /// A template from Core that the pool can't use: counted and kept as the last skip reason for the API. The log
    /// gets it once per reason every 10 minutes (and at most one line every 10 s), so a change in Core that hits
    /// every template doesn't flood it. The pool keeps mining on the last good template or getblocktemplate.
    pub fn skip(&self, template_id: u64, reason: &str) {
        self.skipped.fetch_add(1, Ordering::Relaxed);
        *self.last_skip.lock().unwrap() = Some((reason.to_string(), Instant::now()));
        let mut logged = self.skip_logged.lock().unwrap();
        let quiet = logged.as_ref().map_or(false, |(r, at)| {
            at.elapsed() < Duration::from_secs(10) || (r == reason && at.elapsed() < Duration::from_secs(600))
        });
        if !quiet {
            crate::log!("WARNING", "IPC: template {} skipped: {} ({} skipped so far)", template_id, reason,
                        self.skipped.load(Ordering::Relaxed));
            *logged = Some((reason.to_string(), Instant::now()));
        }
    }
}

/// Start the IPC session thread for the socket at `sock`. `chain` picks the block subsidy schedule.
pub fn start(sock: PathBuf, chain: String) -> Arc<Ipc> {
    let ipc = Arc::new(Ipc::default());
    let me = ipc.clone();
    std::thread::Builder::new().name("ipc".into()).spawn(move || {
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                crate::log!("ERROR", "IPC: no runtime: {}", e);
                return;
            }
        };
        let mut first = true;
        loop {
            if !first {
                me.reconnects.fetch_add(1, Ordering::Relaxed);
            }
            first = false;
            let local = tokio::task::LocalSet::new();
            let r = local.block_on(&rt, session(me.clone(), sock.clone(), &chain));
            me.up.store(false, Ordering::Relaxed);
            if let Err(e) = r {
                let was = me.last_error.lock().unwrap().replace(e.clone());
                if was.as_deref() != Some(e.as_str()) {
                    crate::log!("WARNING", "IPC: {} (templates come from getblocktemplate; trying again every 15 s)", e);
                }
            }
            std::thread::sleep(Duration::from_secs(15));
        }
    }).expect("ipc thread");
    ipc
}

async fn session(ipc: Arc<Ipc>, sock: PathBuf, chain: &str) -> Result<(), String> {
    if !sock.exists() {
        return Err(format!("no IPC socket at {} (is the node's IPC mining interface on?)", sock.display()));
    }
    let cancel = CancellationToken::new();
    let (to_core, to_core_rx) = async_channel::unbounded();
    let (from_core_tx, from_core) = async_channel::unbounded();
    // a new template when the block's fees rise by 1,000 sats, at most once a second; a new block: at once
    let mut tdp = template_distribution_protocol::new(BitcoinCoreVersion::V32X, &sock, 1000, 1, None,
                                                      to_core_rx, from_core_tx, cancel.clone())
        .await
        .map_err(|e| format!("can't connect to {}: {:?}", sock.display(), e))?;
    let runner = tokio::task::spawn_local(async move { tdp.run().await });
    // Solo45's coinbase: the payout output (up to a 34-byte P2WSH/P2TR script) plus our tag in the scriptSig
    to_core.send(TemplateDistributionOwned::CoinbaseOutputConstraints(CoinbaseOutputConstraintsOwned {
        coinbase_output_max_additional_size: 64,
        coinbase_output_max_additional_sigops: 4,
    })).await.map_err(|_| "IPC session closed at once".to_string())?;
    ipc.up.store(true, Ordering::Relaxed);
    *ipc.last_error.lock().unwrap() = None;
    crate::log!("INFO", "IPC: connected to Bitcoin Core at {} (templates over the IPC mining interface)", sock.display());
    let mut pending: HashMap<u64, Pending> = HashMap::new();
    let mut futures: HashMap<u64, Pending> = HashMap::new(); // future templates wait for their SetNewPrevHash
    let mut prev: Option<String> = None; // the tip the current templates build on (display hex)
    let mut bits = 0u32;
    let mut ntime = 0u32;
    let result = loop {
        let msg = tokio::select! {
            m = from_core.recv() => m,
            _ = cancel.cancelled() => break Err("IPC session ended".to_string()),
        };
        let Ok(msg) = msg else { break Err("IPC session ended".to_string()) };
        match msg {
            TemplateDistributionOwned::NewTemplate(t) => {
                let p = match pending_from(&t) {
                    Ok(p) => p,
                    Err(e) => {
                        ipc.skip(t.template_id, &e);
                        continue;
                    }
                };
                if t.future_template {
                    futures.insert(t.template_id, p);
                } else if prev.is_some() {
                    pending.insert(t.template_id, p);
                    let _ = to_core.send(TemplateDistributionOwned::RequestTransactionData(
                        RequestTransactionDataOwned { template_id: t.template_id })).await;
                }
            }
            TemplateDistributionOwned::SetNewPrevHash(s) => {
                let mut h = s.prev_hash.to_array();
                h.reverse();
                let hex = hex::encode(h);
                prev = Some(hex.clone());
                bits = s.n_bits;
                ntime = s.ntime_start;
                pending.clear();
                let fut = futures.remove(&s.template_id);
                // the new block's height (from its pre-built template), bits and earliest time: an empty job's header
                *ipc.tip.lock().unwrap() = fut.as_ref().map(|p| IpcTip {
                    prev_hex: hex.clone(), height: p.height, bits: s.n_bits, ntime: s.ntime_start, version: p.version });
                if let Some(p) = fut {
                    pending.insert(s.template_id, p);
                    let _ = to_core.send(TemplateDistributionOwned::RequestTransactionData(
                        RequestTransactionDataOwned { template_id: s.template_id })).await;
                }
                futures.clear();
                if let Some(tx) = ipc.tip_tx.lock().unwrap().as_ref() {
                    let _ = tx.send(hex);
                }
            }
            TemplateDistributionOwned::RequestTransactionDataSuccess(d) => {
                let Some(p) = pending.remove(&d.template_id) else { continue };
                let Some(prev_hex) = prev.clone() else { continue };
                if !d.excess_data.as_ref().iter().all(|b| *b == 0) {
                    // the coinbase witness the commitment was made for isn't the all-zero one the pool uses
                    ipc.skip(d.template_id, "its witness commitment is for a non-zero coinbase witness");
                    continue;
                }
                let txs: Vec<Vec<u8>> = d.transaction_list.into_inner().into_iter().map(|t| t.as_ref().to_vec()).collect();
                match to_gbt(&p, &prev_hex, bits, ntime, &txs, chain) {
                    Ok(tpl) => {
                        *ipc.latest.lock().unwrap() = Some(Arc::new(IpcTemplate { tpl, prev_hex, at: Instant::now() }));
                        ipc.templates.fetch_add(1, Ordering::Relaxed);
                        ipc.ready.notify_waiters();
                    }
                    Err(e) => ipc.skip(d.template_id, &e),
                }
            }
            TemplateDistributionOwned::RequestTransactionDataError(e) => {
                // only a template still wanted counts: a new block clears the requests it made stale
                if pending.remove(&e.template_id).is_some() {
                    let code = String::from_utf8_lossy(e.error_code.as_ref()).to_string();
                    ipc.skip(e.template_id, &format!("the node sent no transactions for it ({})", code));
                }
            }
            _ => {}
        }
    };
    cancel.cancel();
    let _ = runner.await;
    result
}

fn pending_from(t: &stratum_apps::stratum_core::template_distribution_sv2::NewTemplateOwned) -> Result<Pending, String> {
    let height = bip34_height(t.coinbase_prefix.as_ref()).ok_or("no block height in the coinbase prefix")?;
    Ok(Pending {
        version: t.version,
        height,
        value: t.coinbase_tx_value_remaining,
        witness_commitment: witness_commitment(t.coinbase_tx_outputs.as_ref(), t.coinbase_tx_outputs_count),
    })
}

/// The block height from the start of the coinbase scriptSig (BIP 34: a number push, or OP_1..OP_16).
pub fn bip34_height(prefix: &[u8]) -> Option<u64> {
    let n = *prefix.first()?;
    match n {
        0x51..=0x60 => Some((n - 0x50) as u64),
        0x01..=0x08 => {
            let b = prefix.get(1..1 + n as usize)?;
            let mut v = 0u64;
            for (i, x) in b.iter().enumerate() {
                v |= (*x as u64) << (8 * i);
            }
            Some(v)
        }
        _ => None,
    }
}

/// The witness commitment script (OP_RETURN aa21a9ed...) among the coinbase outputs Core requires, as hex.
pub fn witness_commitment(outs: &[u8], count: u32) -> Option<String> {
    let mut i = 0;
    for _ in 0..count {
        i += 8;
        let (len, j) = varint(outs, i)?;
        let s = outs.get(j..j + len as usize)?;
        if s.len() >= 38 && s.starts_with(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]) {
            return Some(hex::encode(s));
        }
        i = j + len as usize;
    }
    None
}

fn varint(b: &[u8], i: usize) -> Option<(u64, usize)> {
    let n = *b.get(i)?;
    let size = match n {
        0xFD => 2,
        0xFE => 4,
        0xFF => 8,
        _ => return Some((n as u64, i + 1)),
    };
    let s = b.get(i + 1..i + 1 + size)?;
    let mut v = [0u8; 8];
    v[..size].copy_from_slice(s);
    Some((u64::from_le_bytes(v), i + 1 + size))
}

/// (txid, wtxid) in display hex for a raw transaction; the txid hashes it without the witness.
pub fn tx_ids(raw: &[u8]) -> Option<(String, String)> {
    let mut wtxid = sha256d(raw);
    wtxid.reverse();
    let segwit = raw.len() > 6 && raw[4] == 0 && raw[5] == 1;
    let mut txid = if segwit {
        let mut i = 6;
        let (n_in, j) = varint(raw, i)?;
        i = j;
        for _ in 0..n_in {
            i += 36;
            let (l, j) = varint(raw, i)?;
            i = j + l as usize + 4;
        }
        let (n_out, j) = varint(raw, i)?;
        i = j;
        for _ in 0..n_out {
            i += 8;
            let (l, j) = varint(raw, i)?;
            i = j + l as usize;
        }
        let mut stripped = raw.get(0..4)?.to_vec();
        stripped.extend_from_slice(raw.get(6..i)?);
        stripped.extend_from_slice(raw.get(raw.len().checked_sub(4)?..)?);
        sha256d(&stripped)
    } else {
        sha256d(raw)
    };
    txid.reverse();
    Some((hex::encode(txid), hex::encode(wtxid)))
}

/// A coinbase-only template for the block Core announced in `t`, in getblocktemplate's shape. Height, bits and the
/// earliest time are Core's own for that block, so (unlike a copy of the previous header's bits) it is right for the
/// first block of a difficulty period too.
pub fn empty_template(t: &IpcTip, now: f64, chain: &str) -> Value {
    json!({
        "height": t.height, "previousblockhash": t.prev_hex, "version": t.version, "bits": format!("{:08x}", t.bits),
        "curtime": (now as u64).max(t.ntime as u64), "mintime": t.ntime, "coinbasevalue": subsidy(t.height, chain),
        "transactions": []
    })
}

/// The block subsidy at `height` on this chain (regtest halves every 150 blocks, the others every 210,000).
pub fn subsidy(height: u64, chain: &str) -> u64 {
    let interval = if chain == "regtest" { 150 } else { 210_000 };
    let halvings = height / interval;
    if halvings >= 64 { 0 } else { 5_000_000_000u64 >> halvings }
}

fn to_gbt(p: &Pending, prev_hex: &str, bits: u32, ntime: u32, txs: &[Vec<u8>], chain: &str) -> Result<Value, String> {
    let mut list = Vec::with_capacity(txs.len());
    for raw in txs {
        let (txid, hash) = tx_ids(raw).ok_or("a transaction couldn't be read")?;
        list.push(json!({"txid": txid, "hash": hash, "data": hex::encode(raw)}));
    }
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as u32).unwrap_or(0);
    let mut tpl = json!({
        "height": p.height,
        "previousblockhash": prev_hex,
        "version": p.version as i64,
        "bits": format!("{:08x}", bits),
        "curtime": now.max(ntime),
        "mintime": ntime,
        "coinbasevalue": p.value,
        "transactions": list,
        "_ipc": true,
        "total_fees": p.value.saturating_sub(subsidy(p.height, chain)),
    });
    if let Some(wc) = &p.witness_commitment {
        tpl["default_witness_commitment"] = json!(wc);
    }
    Ok(tpl)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_template_from_cores_new_block() {
        let t = IpcTip { prev_hex: "00ab".into(), height: 977_760, bits: 0x17023a04, ntime: 1_800_000_000, version: 0x20000000 };
        let e = empty_template(&t, 1_700_000_000.0, "main");
        assert_eq!(e["height"], 977_760);
        assert_eq!(e["previousblockhash"], "00ab");
        assert_eq!(e["bits"], "17023a04");
        assert_eq!(e["curtime"], 1_800_000_000u64); // never before Core's earliest time
        assert_eq!(e["coinbasevalue"], 312_500_000u64);
        assert_eq!(e["transactions"], json!([]));
        assert_eq!(empty_template(&t, 1_900_000_000.0, "main")["curtime"], 1_900_000_000u64);
        // the first block of a difficulty period works too (Core's bits are already the new ones)
        let t2 = IpcTip { height: 2016 * 485, ..t.clone() };
        assert_eq!(empty_template(&t2, 0.0, "main")["height"], 2016 * 485);
        assert_eq!(empty_template(&IpcTip { height: 300, ..t }, 0.0, "regtest")["coinbasevalue"], 1_250_000_000u64);
    }

    #[test]
    fn skipped_templates_are_counted_with_the_last_reason() {
        let ipc = Ipc::default();
        assert_eq!(ipc.status()["skipped"], 0);
        assert!(ipc.status()["last_skip"].is_null());
        ipc.skip(1, "no block height in the coinbase prefix");
        ipc.skip(2, "the node sent no transactions for it (template-id-not-found)");
        let s = ipc.status();
        assert_eq!(s["skipped"], 2);
        assert_eq!(s["last_skip"]["reason"], "the node sent no transactions for it (template-id-not-found)");
        assert!(s["last_skip"]["age_s"].as_f64().unwrap() < 5.0);
    }

    #[test]
    fn heights_from_the_coinbase_prefix() {
        assert_eq!(bip34_height(&[0x03, 0x01, 0xe9, 0x0e]), Some(977_153));
        assert_eq!(bip34_height(&[0x52]), Some(2));
        assert_eq!(bip34_height(&[0x02, 0xc8, 0x00, 0x00]), Some(200));
        assert_eq!(bip34_height(&[]), None);
    }

    #[test]
    fn txids_with_and_without_witness() {
        // a segwit transaction: the txid skips marker, flag and witness; the wtxid hashes everything
        let mut legacy = vec![1, 0, 0, 0, 1]; // version 1, one input
        legacy.extend([0xaa; 32]);
        legacy.extend([0, 0, 0, 0, 0, 0, 0, 0, 0]); // prevout index, empty scriptSig, sequence
        legacy.push(1); // one output
        legacy.extend([0u8; 8]);
        legacy.extend([1, 0x6a]); // OP_RETURN
        legacy.extend([0, 0, 0, 0]); // locktime
        let (txid, wtxid) = tx_ids(&legacy).unwrap();
        assert_eq!(txid, wtxid);
        let mut seg = legacy[..4].to_vec();
        seg.extend([0x00, 0x01]);
        seg.extend(&legacy[4..legacy.len() - 4]);
        seg.extend([0x01, 0x02, 0xab, 0xcd]); // one witness item of 2 bytes for the one input
        seg.extend(&legacy[legacy.len() - 4..]);
        let (t2, w2) = tx_ids(&seg).unwrap();
        assert_eq!(t2, txid);
        assert_ne!(w2, t2);
    }

    #[test]
    fn subsidy_schedule() {
        assert_eq!(subsidy(0, "main"), 5_000_000_000);
        assert_eq!(subsidy(977_700, "main"), 312_500_000);
        assert_eq!(subsidy(150, "regtest"), 2_500_000_000);
    }

    #[test]
    fn finds_the_witness_commitment() {
        let mut outs = Vec::new();
        outs.extend(0u64.to_le_bytes());
        let script = hex::decode(format!("6a24aa21a9ed{}", "11".repeat(32))).unwrap();
        outs.push(script.len() as u8);
        outs.extend(&script);
        assert_eq!(witness_commitment(&outs, 1).unwrap(), hex::encode(&script));
        assert_eq!(witness_commitment(&outs[..10], 1), None);
    }
}
