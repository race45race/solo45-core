//! One mining job built from a getblocktemplate reply: coinbase halves, merkle branch and header assembly.
//! A line-for-line port of the Job class in Solo45's pool.py, so the two pools hand miners identical work.

use crate::util::{bits_to_target, merkle_branch, push, script_num, sha256d, stratum_prevhash, varint};
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

/// Raw transactions by wtxid, shared by the jobs (pool.py's tx_cache): a transaction that stays in the mempool
/// is decoded once and held once, however many jobs include it.
pub type TxCache = HashMap<String, Arc<Vec<u8>>>;

/// Everything that makes a share unique: extranonce1, extranonce2, ntime, nonce, version.
pub type ShareKey = ([u8; 4], [u8; EN2_SIZE], u32, u32, u32);

pub const EN1_SIZE: usize = 4;
pub const EN2_SIZE: usize = 8;

pub struct Job {
    pub id: String,
    pub height: u64,
    pub prev_hex: String,
    pub prev: [u8; 32],
    pub version: u32,
    pub bits: u32,
    pub target: [u8; 32],
    pub curtime: u32,
    pub mintime: u32,
    pub value: u64,
    pub witness_commitment: Option<Vec<u8>>,
    pub tx_data: Vec<Arc<Vec<u8>>>,
    pub fees: u64,
    pub branch: Vec<[u8; 32]>,
    pub coinb1: Vec<u8>,
    pub created: std::time::Instant,
    /// coinbase-only work sent the moment a block arrives (empty block first)
    pub empty: bool,
    /// set when the node's block check rejects this empty job: the hold ends at once
    pub hold_done: tokio::sync::Notify,
    /// the template was fetched again near the end of this empty job's hold
    pub refreshed: std::sync::atomic::AtomicBool,
    /// built from a template the policy filtered (if the node's check rejects it, mine the node's own template)
    pub filtered: bool,
    coinb2_cache: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
    /// shares already seen for this job (only ones that passed the difficulty check, or block candidates)
    pub seen: Mutex<HashSet<ShareKey>>,
}

fn field<'a>(tpl: &'a Value, k: &str) -> Result<&'a Value> {
    tpl.get(k).ok_or_else(|| anyhow!("template has no '{}'", k))
}

fn hex32_rev(s: &str) -> Result<[u8; 32]> {
    let mut b: [u8; 32] = hex::decode(s)?.try_into().map_err(|_| anyhow!("not 32 bytes: {}", s))?;
    b.reverse();
    Ok(b)
}

impl Job {
    /// `cache` is reused for transactions already seen and, when the template has any, replaced by exactly this
    /// template's transactions (so it never holds more than the latest template).
    pub fn new(id: &str, tpl: &Value, tag: &[u8], cache: &mut TxCache) -> Result<Job> {
        let height = field(tpl, "height")?.as_u64().ok_or_else(|| anyhow!("height"))?;
        let prev_hex = field(tpl, "previousblockhash")?.as_str().ok_or_else(|| anyhow!("prev"))?.to_string();
        let prev = hex32_rev(&prev_hex)?;
        let version = (field(tpl, "version")?.as_i64().ok_or_else(|| anyhow!("version"))? as u64 & 0xffff_ffff) as u32;
        let bits = u32::from_str_radix(field(tpl, "bits")?.as_str().ok_or_else(|| anyhow!("bits"))?, 16)?;
        let curtime = field(tpl, "curtime")?.as_u64().ok_or_else(|| anyhow!("curtime"))? as u32;
        let mintime = field(tpl, "mintime")?.as_u64().ok_or_else(|| anyhow!("mintime"))? as u32;
        let value = field(tpl, "coinbasevalue")?.as_u64().ok_or_else(|| anyhow!("coinbasevalue"))?;
        let witness_commitment = match tpl.get("default_witness_commitment").and_then(|v| v.as_str()) {
            Some(s) => Some(hex::decode(s)?),
            None => None,
        };
        let txs = field(tpl, "transactions")?.as_array().ok_or_else(|| anyhow!("transactions"))?;
        let mut tx_data = Vec::with_capacity(txs.len());
        let mut txids = Vec::with_capacity(txs.len());
        let mut fees = 0u64;
        let mut next: TxCache = HashMap::with_capacity(txs.len());
        for t in txs {
            let txid = t["txid"].as_str().ok_or_else(|| anyhow!("txid"))?;
            let key = t.get("hash").and_then(|h| h.as_str()).unwrap_or(txid);
            let data = match cache.get(key) {
                Some(d) => d.clone(),
                None => Arc::new(t["data"].as_str().and_then(crate::util::unhex).ok_or_else(|| anyhow!("tx data"))?),
            };
            next.insert(key.to_string(), data.clone());
            tx_data.push(data);
            txids.push(hex32_rev(txid)?);
            fees += t.get("fee").and_then(|f| f.as_u64()).unwrap_or(0);
        }
        if let Some(f) = tpl.get("total_fees").and_then(|f| f.as_u64()) {
            fees = f; // an IPC template knows the block's fees, not each transaction's
        }
        if !txs.is_empty() {
            *cache = next; // an empty (coinbase-only) template leaves the cache for the full one that follows
        }
        let branch = merkle_branch(&txids);
        let mut script = push(&script_num(height));
        script.extend(push(tag));
        let mut coinb1 = Vec::new();
        coinb1.extend_from_slice(&2u32.to_le_bytes());
        coinb1.push(1);
        coinb1.extend_from_slice(&[0u8; 32]);
        coinb1.extend_from_slice(&[0xff; 4]);
        coinb1.extend(varint((script.len() + 1 + EN1_SIZE + EN2_SIZE) as u64));
        coinb1.extend(&script);
        coinb1.push((EN1_SIZE + EN2_SIZE) as u8);
        Ok(Job {
            id: id.to_string(),
            height,
            prev_hex,
            prev,
            version,
            bits,
            target: bits_to_target(bits),
            curtime,
            mintime,
            value,
            witness_commitment,
            tx_data,
            fees,
            branch,
            coinb1,
            created: std::time::Instant::now(),
            empty: false,
            hold_done: tokio::sync::Notify::new(),
            refreshed: std::sync::atomic::AtomicBool::new(false),
            filtered: false,
            coinb2_cache: Mutex::new(HashMap::new()),
            seen: Mutex::new(HashSet::new()),
        })
    }

    /// Second coinbase half paying `spk` (cached per payout script, like pool.py).
    pub fn coinb2(&self, spk: &[u8]) -> Vec<u8> {
        if let Some(c) = self.coinb2_cache.lock().unwrap().get(spk) {
            return c.clone();
        }
        let mut outs: Vec<Vec<u8>> = Vec::new();
        let mut o = (self.value as i64).to_le_bytes().to_vec();
        o.extend(varint(spk.len() as u64));
        o.extend_from_slice(spk);
        outs.push(o);
        if let Some(wc) = &self.witness_commitment {
            let mut o = 0i64.to_le_bytes().to_vec();
            o.extend(varint(wc.len() as u64));
            o.extend_from_slice(wc);
            outs.push(o);
        }
        let mut c = vec![0xff; 4];
        c.extend(varint(outs.len() as u64));
        for o in outs {
            c.extend(o);
        }
        c.extend_from_slice(&[0u8; 4]);
        self.coinb2_cache.lock().unwrap().insert(spk.to_vec(), c.clone());
        c
    }

    pub fn stratum_prev(&self) -> String {
        stratum_prevhash(&self.prev)
    }

    /// mining.notify params for a miner paying `spk`.
    pub fn notify_params(&self, spk: &[u8], clean: bool) -> Value {
        json!([
            self.id,
            self.stratum_prev(),
            hex::encode(&self.coinb1),
            hex::encode(self.coinb2(spk)),
            self.branch.iter().map(hex::encode).collect::<Vec<_>>(),
            format!("{:08x}", self.version),
            format!("{:08x}", self.bits),
            format!("{:08x}", self.curtime),
            clean
        ])
    }

    /// 80-byte header for a share.
    pub fn header(&self, coinbase: &[u8], version: u32, ntime: u32, nonce: u32) -> [u8; 80] {
        let mut root = sha256d(coinbase);
        for h in &self.branch {
            let mut cat = [0u8; 64];
            cat[..32].copy_from_slice(&root);
            cat[32..].copy_from_slice(h);
            root = sha256d(&cat);
        }
        let mut hdr = [0u8; 80];
        hdr[0..4].copy_from_slice(&version.to_le_bytes());
        hdr[4..36].copy_from_slice(&self.prev);
        hdr[36..68].copy_from_slice(&root);
        hdr[68..72].copy_from_slice(&ntime.to_le_bytes());
        hdr[72..76].copy_from_slice(&self.bits.to_le_bytes());
        hdr[76..80].copy_from_slice(&nonce.to_le_bytes());
        hdr
    }

    /// Full serialised block for submitblock.
    pub fn block(&self, header: &[u8; 80], coinbase: &[u8]) -> Vec<u8> {
        let cb: Vec<u8> = if self.witness_commitment.is_some() {
            // a segwit coinbase carries one witness item: the 32-byte zero reserved value
            let mut v = coinbase[..4].to_vec();
            v.extend_from_slice(&[0x00, 0x01]);
            v.extend_from_slice(&coinbase[4..coinbase.len() - 4]);
            v.extend_from_slice(&[0x01, 0x20]);
            v.extend_from_slice(&[0u8; 32]);
            v.extend_from_slice(&coinbase[coinbase.len() - 4..]);
            v
        } else {
            coinbase.to_vec()
        };
        let mut out = header.to_vec();
        out.extend(varint(1 + self.tx_data.len() as u64));
        out.extend(cb);
        for t in &self.tx_data {
            out.extend_from_slice(t.as_slice());
        }
        out
    }
}
