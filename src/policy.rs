//! Template policy (port of Solo45's policy.py): leave chosen kinds of transactions out of the blocks this pool
//! builds. It only ever removes transactions from the node's block template (plus anything that spends them),
//! then recomputes the reward and the witness commitment. It never touches consensus rules, and the pool still
//! has the node check every job with getblocktemplate "proposal" mode.
//!
//! The config is kept as JSON in pool.py's shape, so the API, backups and the dashboard stay compatible:
//! {"mode": "off"|"watch"|"filter", "rules": {name: {"on": bool, "watch": bool, ...}}}.

use crate::util::{sha256d, unhex};
use serde_json::{json, Map, Value};
use std::collections::{BTreeSet, HashMap, HashSet};

pub const RULES: [&str; 5] = ["inscriptions", "opreturn", "baremultisig", "runes", "minfee"];

pub fn rule_names() -> Value {
    json!({
        "inscriptions": "Inscriptions / Ordinals",
        "opreturn": "Large OP_RETURN data",
        "baremultisig": "Bare multisig (Stamps)",
        "runes": "Runes",
        "minfee": "Below minimum fee rate",
        "child": "Spends a skipped transaction",
    })
}

pub fn defaults() -> Value {
    json!({
        "mode": "watch", // "off", "watch" (every rule only counts) or "filter" (each rule as set below)
        "rules": {       // "on": the rule is used; "watch": it only counts what it would skip, even in filter mode
            "inscriptions": {"on": true, "watch": false},
            "opreturn": {"on": true, "watch": false, "max_bytes": 83},
            "baremultisig": {"on": true, "watch": false},
            "runes": {"on": true, "watch": false},
            "minfee": {"on": false, "watch": false, "sat_vb": 1.0},
        }
    })
}

const OP_0: u8 = 0x00;
const OP_IF: u8 = 0x63;
const OP_RETURN: u8 = 0x6A;
const OP_13: u8 = 0x5D;
const OP_CHECKMULTISIG: u8 = 0xAE;
const WITNESS_COMMITMENT_HEADER: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

// ------------------------------------------------------------------ parsing

fn read_varint(b: &[u8], i: usize) -> Option<(u64, usize)> {
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

fn take<'a>(b: &'a [u8], i: usize, len: u64) -> Option<(&'a [u8], usize)> {
    let end = i.checked_add(usize::try_from(len).ok()?)?;
    Some((b.get(i..end)?, end))
}

/// (output scripts, witness stacks). None for malformed data. With read_witness false it stops after the
/// outputs and returns no witness stacks (reading the signatures is most of the work).
pub fn parse_tx(raw: &[u8], read_witness: bool) -> Option<(Vec<&[u8]>, Vec<Vec<&[u8]>>)> {
    let mut i = 4;
    let segwit = *raw.get(i)? == 0 && *raw.get(i + 1)? == 1;
    if segwit {
        i += 2;
    }
    let (n_in, j) = read_varint(raw, i)?;
    i = j;
    for _ in 0..n_in {
        i += 36;
        let (slen, j) = read_varint(raw, i)?;
        i = take(raw, j, slen)?.1 + 4;
    }
    let (n_out, j) = read_varint(raw, i)?;
    i = j;
    let mut outputs = Vec::new();
    for _ in 0..n_out {
        i += 8;
        let (slen, j) = read_varint(raw, i)?;
        let (s, j) = take(raw, j, slen)?;
        outputs.push(s);
        i = j;
    }
    let mut witnesses = Vec::new();
    if !read_witness {
        return Some((outputs, witnesses));
    }
    if segwit {
        for _ in 0..n_in {
            let (n_items, j) = read_varint(raw, i)?;
            i = j;
            let mut items = Vec::new();
            for _ in 0..n_items {
                let (ilen, j) = read_varint(raw, i)?;
                let (item, j) = take(raw, j, ilen)?;
                items.push(item);
                i = j;
            }
            witnesses.push(items);
        }
    }
    if i + 4 != raw.len() {
        return None; // unexpected transaction length
    }
    Some((outputs, witnesses))
}

/// (opcode, pushed data or None) for a script; stops quietly at a truncated push.
pub fn script_ops(script: &[u8]) -> Vec<(u8, Option<&[u8]>)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < script.len() {
        let op = script[i];
        i += 1;
        let size = match op {
            0x01..=0x4B => op as usize,
            0x4C => match script.get(i) {
                Some(&s) => {
                    i += 1;
                    s as usize
                }
                None => return out,
            },
            0x4D => match script.get(i..i + 2) {
                Some(s) => {
                    i += 2;
                    u16::from_le_bytes([s[0], s[1]]) as usize
                }
                None => return out,
            },
            0x4E => match script.get(i..i + 4) {
                Some(s) => {
                    i += 4;
                    u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize
                }
                None => return out,
            },
            _ => {
                out.push((op, None));
                continue;
            }
        };
        match script.get(i..i + size) {
            Some(d) => out.push((op, Some(d))),
            None => return out,
        }
        i += size;
    }
    out
}

// ------------------------------------------------------------------ classifiers

/// The leaf script of a taproot script-path spend, or None.
pub fn tapscript<'a>(stack: &[&'a [u8]]) -> Option<&'a [u8]> {
    let mut items: &[&[u8]] = stack;
    if items.len() >= 2 && items[items.len() - 1].first() == Some(&0x50) {
        items = &items[..items.len() - 1]; // annex
    }
    if items.len() < 2 {
        return None;
    }
    let control = items[items.len() - 1];
    // (len - 33) % 32 the way Python computes it (a floored modulo), so both pools judge the same bytes alike
    if control.is_empty() || (control[0] & 0xFE) != 0xC0 || (control.len() as i64 - 33).rem_euclid(32) != 0 {
        return None;
    }
    Some(items[items.len() - 2])
}

/// True for the OP_FALSE OP_IF ... data envelope that inscriptions (and similar) use.
pub fn has_envelope(script: &[u8]) -> bool {
    let mut prev = None;
    for (op, _) in script_ops(script) {
        if prev == Some(OP_0) && op == OP_IF {
            return true;
        }
        prev = Some(op);
    }
    false
}

/// OP_m <pubkey>... OP_n OP_CHECKMULTISIG, read opcode by opcode (a taproot output also starts with OP_1, and its
/// 32-byte key can end in the byte 0xae).
pub fn is_bare_multisig(spk: &[u8]) -> bool {
    // the shortest one (1-of-1, compressed key) is 37 bytes; almost every output fails this quick look
    if spk.len() < 37 || spk[spk.len() - 1] != OP_CHECKMULTISIG || !(0x51..=0x60).contains(&spk[0]) {
        return false;
    }
    let ops = script_ops(spk);
    if ops.len() < 4 || ops[ops.len() - 1] != (OP_CHECKMULTISIG, None) {
        return false;
    }
    let (m, n) = (ops[0].0, ops[ops.len() - 2].0);
    let keys = &ops[1..ops.len() - 2];
    (0x51..=0x60).contains(&m) && (0x51..=0x60).contains(&n) && keys.len() == (n - 0x50) as usize
        && keys.iter().all(|(_, d)| d.map_or(false, |d| d.len() == 33 || d.len() == 65))
}

fn on(rules: &Value, name: &str) -> bool {
    truthy(&rules[name]["on"])
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map_or(false, |f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
        Value::Null => false,
    }
}

/// The content rules that are on, read once per template.
struct Prepared {
    runes: bool,
    op_limit: Option<usize>,
    multisig: bool,
    inscriptions: bool,
}

fn content_rules(rules: &Value) -> Prepared {
    Prepared {
        runes: on(rules, "runes"),
        op_limit: if on(rules, "opreturn") {
            Some(rules["opreturn"]["max_bytes"].as_f64().map_or(83, |v| v.max(0.0) as usize))
        } else {
            None
        },
        multisig: on(rules, "baremultisig"),
        inscriptions: on(rules, "inscriptions"),
    }
}

/// The content rules this template transaction breaks (empty = keep it). The fee rule is judged on whole packages.
fn classify(tx: &Value, p: &Prepared) -> Vec<&'static str> {
    let mut reasons = Vec::new();
    let Some(raw) = tx["data"].as_str().and_then(unhex) else {
        return reasons; // can't read it: leave the decision to the node
    };
    // an envelope starts with the bytes 00 63 (OP_FALSE OP_IF), so without them there's no witness to read
    let read_witness = p.inscriptions && raw.windows(2).any(|w| w == [0x00, 0x63]);
    let Some((outputs, witnesses)) = parse_tx(&raw, read_witness) else {
        return reasons;
    };
    let (mut rune, mut big, mut bare) = (false, false, false);
    for o in &outputs {
        if o.first() == Some(&OP_RETURN) {
            rune = rune || (p.runes && o.len() > 1 && o[1] == OP_13);
            big = big || p.op_limit.map_or(false, |l| o.len() > l);
        } else if p.multisig && !bare {
            bare = is_bare_multisig(o);
        }
    }
    for (name, hit) in [("runes", rune), ("opreturn", big), ("baremultisig", bare)] {
        if hit {
            reasons.push(name);
        }
    }
    if p.inscriptions && witnesses.iter().any(|s| tapscript(s).map_or(false, has_envelope)) {
        reasons.push("inscriptions");
    }
    reasons
}

// ------------------------------------------------------------------ templates

/// "off", "watch" (only counts) or "filter" for one rule's settings.
pub fn rule_state(rule: &Value) -> &'static str {
    if !truthy(&rule["on"]) {
        "off"
    } else if truthy(&rule["watch"]) {
        "watch"
    } else {
        "filter"
    }
}

/// The size the node uses for fee rates: weight / 4, or more for transactions heavy in signature checks.
fn vsize(tx: &Value) -> u64 {
    let w = tx["weight"].as_u64().unwrap_or(0).max(tx["sigops"].as_u64().unwrap_or(0) * 20);
    ((w + 3) / 4).max(1)
}

/// The candidates that don't pay sat_vb, judged by package the way the node builds blocks: keep taking the
/// transaction whose not-yet-taken ancestors plus itself pay the best rate, until the best one left pays less than
/// sat_vb. So a low-fee parent stays when its child pays enough for both (child pays for parent), and a low-fee child
/// can't ride along on a parent that pays well.
fn low_fee(txs: &[Value], candidates: &BTreeSet<usize>, sat_vb: f64) -> BTreeSet<usize> {
    let mut parents: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut children: HashMap<usize, Vec<usize>> = candidates.iter().map(|&n| (n, vec![])).collect();
    for &n in candidates {
        let ps: Vec<usize> = txs[n]["depends"].as_array().map_or(vec![], |d| {
            d.iter().filter_map(|x| x.as_u64()).filter(|&x| x >= 1).map(|x| x as usize - 1)
                .filter(|p| candidates.contains(p)).collect()
        });
        for &p in &ps {
            children.get_mut(&p).unwrap().push(n);
        }
        parents.insert(n, ps);
    }
    let fee = |n: usize| txs[n]["fee"].as_u64().unwrap_or(0) as f64;
    let size = |n: usize| vsize(&txs[n]) as f64;
    let (mut low, mut seen) = (BTreeSet::new(), HashSet::new());
    for &start in candidates {
        if seen.contains(&start) {
            continue;
        }
        if parents[&start].is_empty() && children[&start].is_empty() {
            // most transactions stand alone: their own rate decides
            seen.insert(start);
            if fee(start) / size(start) < sat_vb {
                low.insert(start);
            }
            continue;
        }
        let (mut cluster, mut stack) = (BTreeSet::new(), vec![start]); // everything linked to it by spending
        while let Some(n) = stack.pop() {
            if cluster.insert(n) {
                stack.extend(&parents[&n]);
                stack.extend(&children[&n]);
            }
        }
        seen.extend(cluster.iter().copied());
        let mut anc: HashMap<usize, BTreeSet<usize>> = HashMap::new();
        for &n in &cluster {
            // the template lists parents before children
            let mut a = BTreeSet::from([n]);
            for p in &parents[&n] {
                if let Some(pa) = anc.get(p) {
                    a.extend(pa.iter().copied());
                }
            }
            anc.insert(n, a);
        }
        let mut left = cluster.clone();
        while !left.is_empty() {
            let (mut best, mut best_rate): (Option<Vec<usize>>, f64) = (None, -1.0);
            for &n in &left {
                let pkg: Vec<usize> = anc[&n].iter().copied().filter(|m| left.contains(m)).collect();
                let rate = pkg.iter().map(|&m| fee(m)).sum::<f64>() / pkg.iter().map(|&m| size(m)).sum::<f64>();
                if rate > best_rate {
                    best = Some(pkg);
                    best_rate = rate;
                }
            }
            if best_rate < sat_vb {
                break;
            }
            for m in best.unwrap() {
                left.remove(&m);
            }
        }
        low.extend(left);
    }
    low
}

/// Which transactions applying the rules in `names` leaves out, in pool.py's order: [(index, reasons)]. A
/// transaction that spends a left-out one goes too, because a block can't contain a child without its parent.
fn select(txs: &[Value], found: &[Vec<&'static str>], rules: &Value, names: &HashSet<String>)
          -> Vec<(usize, Vec<&'static str>)> {
    let mut skip: Vec<(usize, Vec<&'static str>)> = Vec::new();
    let mut skipped: HashSet<usize> = HashSet::new();
    for (n, tx) in txs.iter().enumerate() {
        let mut reasons: Vec<&'static str> = found[n].iter().copied().filter(|r| names.contains(*r)).collect();
        if reasons.is_empty() && tx["depends"].as_array().map_or(false, |d| {
            d.iter().filter_map(|x| x.as_u64()).any(|x| x >= 1 && skipped.contains(&(x as usize - 1)))
        }) {
            reasons = vec!["child"];
        }
        if !reasons.is_empty() {
            skip.push((n, reasons));
            skipped.insert(n);
        }
    }
    if names.contains("minfee") {
        let rest: BTreeSet<usize> = (0..txs.len()).filter(|n| !skipped.contains(n)).collect();
        let sat_vb = rules["minfee"]["sat_vb"].as_f64().unwrap_or(1.0);
        for n in low_fee(txs, &rest, sat_vb) {
            skip.push((n, vec!["minfee"]));
        }
    }
    skip
}

/// (rules that count, rules applied to the template) for this config.
fn rule_sets(cfg: &Value) -> (HashSet<String>, HashSet<String>) {
    let mut counted = HashSet::new();
    let mut applied = HashSet::new();
    let filter_mode = cfg["mode"] == "filter";
    if let Some(rules) = cfg["rules"].as_object() {
        for (name, rule) in rules {
            match rule_state(rule) {
                "off" => {}
                s => {
                    counted.insert(name.clone());
                    if s == "filter" && filter_mode {
                        applied.insert(name.clone());
                    }
                }
            }
        }
    }
    (counted, applied)
}

fn tally(txs: &[Value], part: &[(usize, Vec<&'static str>)]) -> Value {
    let mut by_rule = Map::new();
    for (n, reasons) in part {
        // count each transaction once, under its first reason
        let e = by_rule.entry(reasons[0].to_string()).or_insert_with(|| json!({"txs": 0, "fees": 0}));
        e["txs"] = json!(e["txs"].as_u64().unwrap_or(0) + 1);
        e["fees"] = json!(e["fees"].as_u64().unwrap_or(0) + txs[*n]["fee"].as_u64().unwrap_or(0));
    }
    Value::Object(by_rule)
}

fn examples(txs: &[Value], part: &[(usize, Vec<&'static str>)]) -> Value {
    json!(part.iter().take(5).map(|(n, r)| json!({"txid": txs[*n]["txid"], "rule": r[0]})).collect::<Vec<_>>())
}

fn sum_of(txs: &[Value], part: &[(usize, Vec<&'static str>)], k: &str) -> u64 {
    part.iter().map(|(n, _)| txs[*n][k].as_u64().unwrap_or(0)).sum()
}

/// What the rules do to one template (pool.py's report dict).
pub struct Report {
    pub height: u64,
    pub txs: usize,
    pub fees: u64,
    pub skip: Vec<(usize, Vec<&'static str>)>,
    pub fees_skipped: u64,
    pub weight_skipped: u64,
    pub by_rule: Value,
    pub examples: Value,
    found: Vec<Vec<&'static str>>,
    pub watched: usize,
    pub fees_watched: u64,
    pub weight_watched: u64,
    pub watch_by_rule: Value,
    pub watch_examples: Value,
}

impl Report {
    pub fn skipped(&self) -> usize {
        self.skip.len()
    }
}

fn txs_of(tpl: &Value) -> &[Value] {
    tpl["transactions"].as_array().map_or(&[], |a| a.as_slice())
}

/// What the rules take out of this template (skip, used in filter mode), and with watch=true what the rules set
/// to watch would take out on top of that (only counted). With watch=false add_watch() does the rest later, once
/// the miners have their work.
pub fn evaluate(tpl: &Value, cfg: &Value, watch: bool) -> Report {
    let rules = &cfg["rules"];
    let (_, applied) = rule_sets(cfg);
    let txs = txs_of(tpl);
    let p = content_rules(rules);
    let found: Vec<Vec<&'static str>> = txs.iter().map(|t| classify(t, &p)).collect();
    let skip = select(txs, &found, rules, &applied);
    let mut r = Report {
        height: tpl["height"].as_u64().unwrap_or(0),
        txs: txs.len(),
        fees: txs.iter().map(|t| t["fee"].as_u64().unwrap_or(0)).sum(),
        fees_skipped: sum_of(txs, &skip, "fee"),
        weight_skipped: sum_of(txs, &skip, "weight"),
        by_rule: tally(txs, &skip),
        examples: examples(txs, &skip),
        skip,
        found,
        watched: 0,
        fees_watched: 0,
        weight_watched: 0,
        watch_by_rule: json!({}),
        watch_examples: json!([]),
    };
    if watch {
        add_watch(&mut r, tpl, cfg);
    }
    r
}

/// The watch part of evaluate(): what the rules set to watch would skip on top of what was skipped. tpl is the
/// template evaluate() was given (before apply()).
pub fn add_watch(r: &mut Report, tpl: &Value, cfg: &Value) {
    let (counted, applied) = rule_sets(cfg);
    let txs = txs_of(tpl);
    let found = std::mem::take(&mut r.found);
    let skipped: HashSet<usize> = r.skip.iter().map(|(n, _)| *n).collect();
    let watch: Vec<(usize, Vec<&'static str>)> = if counted != applied {
        select(txs, &found, &cfg["rules"], &counted).into_iter().filter(|(n, _)| !skipped.contains(n)).collect()
    } else {
        vec![]
    };
    r.watched = watch.len();
    r.fees_watched = sum_of(txs, &watch, "fee");
    r.weight_watched = sum_of(txs, &watch, "weight");
    r.watch_by_rule = tally(txs, &watch);
    r.watch_examples = examples(txs, &watch);
}

fn merkle_root(hashes: Vec<[u8; 32]>) -> [u8; 32] {
    let mut level = hashes;
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().unwrap());
        }
        level = level.chunks(2).map(|c| {
            let mut b = [0u8; 64];
            b[..32].copy_from_slice(&c[0]);
            b[32..].copy_from_slice(&c[1]);
            sha256d(&b)
        }).collect();
    }
    level[0]
}

/// The coinbase's witness commitment output script for these template transactions.
pub fn witness_commitment(txs: &[Value]) -> Vec<u8> {
    let mut wtxids = vec![[0u8; 32]];
    for t in txs {
        let mut h = [0u8; 32];
        if let Some(Ok(b)) = t["hash"].as_str().map(hex::decode) {
            if b.len() == 32 {
                h.copy_from_slice(&b);
                h.reverse();
            }
        }
        wtxids.push(h);
    }
    let mut b = merkle_root(wtxids).to_vec();
    b.extend([0u8; 32]);
    let mut out = WITNESS_COMMITMENT_HEADER.to_vec();
    out.extend(sha256d(&b));
    out
}

/// A copy of the template without the skipped transactions, with the reward and witness commitment recomputed and
/// the remaining 'depends' indexes renumbered.
pub fn apply(tpl: &Value, r: &Report) -> Value {
    let skipped: HashSet<usize> = r.skip.iter().map(|(n, _)| *n).collect();
    let mut renumber: HashMap<u64, u64> = HashMap::new();
    let mut kept: Vec<Value> = Vec::new();
    for (n, tx) in txs_of(tpl).iter().enumerate() {
        if skipped.contains(&n) {
            continue;
        }
        renumber.insert(n as u64 + 1, kept.len() as u64 + 1);
        let mut t = tx.clone();
        let deps: Vec<u64> = tx["depends"].as_array().map_or(vec![], |d| {
            d.iter().filter_map(|x| x.as_u64()).filter_map(|x| renumber.get(&x).copied()).collect()
        });
        t["depends"] = json!(deps);
        kept.push(t);
    }
    let mut new = Map::new();
    for (k, v) in tpl.as_object().into_iter().flatten() {
        if k != "transactions" {
            new.insert(k.clone(), v.clone());
        }
    }
    new.insert("coinbasevalue".into(), json!(tpl["coinbasevalue"].as_u64().unwrap_or(0).saturating_sub(r.fees_skipped)));
    if tpl["default_witness_commitment"].as_str().map_or(false, |s| !s.is_empty()) {
        new.insert("default_witness_commitment".into(), json!(hex::encode(witness_commitment(&kept))));
    }
    new.insert("transactions".into(), Value::Array(kept));
    Value::Object(new)
}

/// Validate a policy change from the dashboard; returns the new config or an error.
pub fn check_config(data: &Value, current: &Value) -> Result<Value, String> {
    let mut cfg = current.clone();
    if let Some(m) = data.get("mode") {
        match m.as_str() {
            Some(s @ ("off" | "watch" | "filter")) => cfg["mode"] = json!(s),
            _ => return Err("mode must be off, watch or filter".into()),
        }
    }
    if let Some(rules) = data.get("rules").filter(|r| !r.is_null()) {
        let Some(rules) = rules.as_object() else { return Err("bad value in rules".into()) };
        let d = defaults();
        for (name, change) in rules {
            if !RULES.contains(&name.as_str()) || !change.is_object() {
                return Err(format!("unknown rule: {}", name));
            }
            if cfg["rules"].get(name).is_none() {
                cfg["rules"][name] = d["rules"][name].clone();
            }
            let rule = &mut cfg["rules"][name];
            if let Some(v) = change.get("on") {
                rule["on"] = json!(truthy(v));
            }
            if let Some(v) = change.get("watch") {
                rule["watch"] = json!(truthy(v));
            }
            if name == "opreturn" {
                if let Some(v) = change.get("max_bytes") {
                    let val = num(v).ok_or("bad value for the OP_RETURN limit")?.trunc();
                    if !(0.0..=100000.0).contains(&val) {
                        return Err("the OP_RETURN limit must be 0 to 100,000 bytes".into());
                    }
                    rule["max_bytes"] = json!(val as u64);
                }
            }
            if name == "minfee" {
                if let Some(v) = change.get("sat_vb") {
                    let val = num(v).ok_or("bad value for the minimum fee rate")?;
                    if !(0.0..=1000.0).contains(&val) {
                        return Err("the minimum fee rate must be 0 to 1,000 sat/vB".into());
                    }
                    rule["sat_vb"] = json!((val * 1000.0).round() / 1000.0);
                }
            }
        }
    }
    Ok(cfg)
}

fn num(v: &Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok())).filter(|f: &f64| f.is_finite())
}

/// The saved policy merged over the defaults, so new rules appear with their default setting.
pub fn load_config(saved: &Value) -> Value {
    let mut cfg = defaults();
    if let Some(m) = saved["mode"].as_str().filter(|m| ["off", "watch", "filter"].contains(m)) {
        cfg["mode"] = json!(m);
    }
    if let Some(rules) = saved["rules"].as_object() {
        for (name, rule) in rules {
            if let (Some(cur), Some(r)) = (cfg["rules"].get_mut(name).and_then(|c| c.as_object_mut()), rule.as_object()) {
                for (k, v) in r {
                    cur.insert(k.clone(), v.clone());
                }
            }
        }
    }
    cfg
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal transaction: one input (optionally with a witness stack), the given output scripts.
    fn tx_hex(outputs: &[Vec<u8>], witness: Option<Vec<Vec<u8>>>) -> String {
        let mut t = 2u32.to_le_bytes().to_vec();
        if witness.is_some() {
            t.extend([0, 1]);
        }
        t.push(1);
        t.extend([0x11; 32]);
        t.extend(0u32.to_le_bytes());
        t.push(0);
        t.extend([0xff; 4]);
        t.push(outputs.len() as u8);
        for o in outputs {
            t.extend(1000u64.to_le_bytes());
            t.extend(crate::util::varint(o.len() as u64));
            t.extend(o);
        }
        if let Some(w) = witness {
            t.push(w.len() as u8);
            for item in w {
                t.extend(crate::util::varint(item.len() as u64));
                t.extend(item);
            }
        }
        t.extend(0u32.to_le_bytes());
        hex::encode(t)
    }

    fn tx(data: String, fee: u64, weight: u64, depends: &[u64]) -> Value {
        json!({"data": data, "txid": format!("{:064x}", fee + weight), "hash": format!("{:064x}", fee + weight + 1),
               "fee": fee, "weight": weight, "sigops": 1, "depends": depends})
    }

    fn p2wpkh() -> Vec<u8> {
        let mut s = vec![0x00, 0x14];
        s.extend([7u8; 20]);
        s
    }

    fn cfg(mode: &str) -> Value {
        let mut c = defaults();
        c["mode"] = json!(mode);
        c
    }

    #[test]
    fn classifies_each_kind() {
        let p = content_rules(&defaults()["rules"]);
        let plain = tx(tx_hex(&[p2wpkh()], None), 500, 400, &[]);
        assert!(classify(&plain, &p).is_empty());
        let rune = tx(tx_hex(&[vec![OP_RETURN, OP_13, 0x01, 0x02]], None), 500, 400, &[]);
        assert_eq!(classify(&rune, &p), vec!["runes"]);
        let mut big = vec![OP_RETURN, 0x4c, 90];
        big.extend([9u8; 90]);
        assert_eq!(classify(&tx(tx_hex(&[big], None), 1, 1, &[]), &p), vec!["opreturn"]);
        let mut ms = vec![0x51, 33];
        ms.extend([2u8; 33]);
        ms.extend([0x51, OP_CHECKMULTISIG]);
        assert_eq!(classify(&tx(tx_hex(&[ms], None), 1, 1, &[]), &p), vec!["baremultisig"]);
        // taproot output: OP_1 <32 bytes ending in 0xae> is NOT bare multisig
        let mut tr = vec![0x51, 0x20];
        tr.extend([0xaeu8; 32]);
        assert!(classify(&tx(tx_hex(&[tr], None), 1, 1, &[]), &p).is_empty());
        // inscription: script-path spend whose leaf has OP_FALSE OP_IF
        let mut leaf = vec![0x20];
        leaf.extend([1u8; 32]);
        leaf.extend([0xac, OP_0, OP_IF, 0x03, b'o', b'r', b'd', 0x68]);
        let mut control = vec![0xc0];
        control.extend([5u8; 32]);
        let insc = tx(tx_hex(&[p2wpkh()], Some(vec![vec![1u8; 64], leaf, control])), 1, 1, &[]);
        assert_eq!(classify(&insc, &p), vec!["inscriptions"]);
        // unreadable data is kept (the node decides)
        assert!(classify(&json!({"data": "zz"}), &p).is_empty());
    }

    #[test]
    fn script_ops_stop_at_a_truncated_push() {
        assert_eq!(script_ops(&[0x00, 0x63, 0x05, 1, 2]), vec![(0x00, None), (0x63, None)]);
        assert_eq!(script_ops(&[0x4c]), vec![]);
        assert_eq!(script_ops(&[0x02, 7, 8, 0x6a]), vec![(0x02, Some(&[7u8, 8][..])), (0x6a, None)]);
    }

    #[test]
    fn filter_skips_children_and_fixes_the_template() {
        let rune = tx_hex(&[vec![OP_RETURN, OP_13, 1]], None);
        let txs = vec![
            tx(tx_hex(&[p2wpkh()], None), 1000, 400, &[]), // 1: kept
            tx(rune, 2000, 400, &[]),                       // 2: runes
            tx(tx_hex(&[p2wpkh()], None), 3000, 400, &[2]), // 3: spends 2 -> child
            tx(tx_hex(&[p2wpkh()], None), 4000, 400, &[1]), // 4: spends 1 -> kept, renumbered depends
        ];
        let tpl = json!({"height": 900000, "coinbasevalue": 312_510_000u64, "transactions": txs,
                         "default_witness_commitment": "6a24aa21a9ed00"});
        let r = evaluate(&tpl, &cfg("filter"), true);
        assert_eq!(r.skip, vec![(1, vec!["runes"]), (2, vec!["child"])]);
        assert_eq!((r.fees_skipped, r.weight_skipped), (5000, 800));
        assert_eq!(r.by_rule["runes"]["txs"], 1);
        assert_eq!(r.by_rule["child"]["fees"], 3000);
        let t = apply(&tpl, &r);
        assert_eq!(t["transactions"].as_array().unwrap().len(), 2);
        assert_eq!(t["transactions"][1]["depends"], json!([1]));
        assert_eq!(t["coinbasevalue"], 312_505_000u64);
        assert_eq!(t["default_witness_commitment"].as_str().unwrap().len(), 76);
        assert!(t["default_witness_commitment"].as_str().unwrap().starts_with("6a24aa21a9ed"));
        // watch mode never skips, only counts
        let w = evaluate(&tpl, &cfg("watch"), true);
        assert_eq!((w.skipped(), w.watched, w.fees_watched), (0, 2, 5000));
        // filter mode with the runes rule on watch: nothing skipped, the rune and its child only counted
        let mut fw = cfg("filter");
        fw["rules"]["runes"]["watch"] = json!(true);
        let r2 = evaluate(&tpl, &fw, true);
        assert_eq!((r2.skipped(), r2.watched), (0, 2));
        // (mode "off" is never evaluated: the pool skips the policy entirely, like pool.py)
    }

    #[test]
    fn min_fee_judges_packages_like_the_node() {
        let mut c = cfg("filter");
        c["rules"]["minfee"] = json!({"on": true, "watch": false, "sat_vb": 10.0});
        let d = tx_hex(&[p2wpkh()], None);
        let txs = vec![
            tx(d.clone(), 100, 400, &[]),    // 1: 1 sat/vB parent ...
            tx(d.clone(), 3000, 400, &[1]),  // 2: ... whose child pays for both (15.5 sat/vB together)
            tx(d.clone(), 5000, 400, &[]),   // 3: 50 sat/vB, alone
            tx(d.clone(), 100, 400, &[3]),   // 4: 1 sat/vB child of a good parent: can't ride along
            tx(d, 500, 400, &[]),            // 5: 5 sat/vB alone
        ];
        let tpl = json!({"height": 1, "coinbasevalue": 10_000u64, "transactions": txs});
        let r = evaluate(&tpl, &c, false);
        let skipped: Vec<usize> = r.skip.iter().map(|(n, _)| *n).collect();
        assert_eq!(skipped, vec![3, 4]);
        assert!(r.skip.iter().all(|(_, why)| why == &vec!["minfee"]));
    }

    #[test]
    fn config_checks_and_merges() {
        let cur = load_config(&json!({"mode": "filter", "rules": {"runes": {"on": false}}}));
        assert_eq!(cur["mode"], "filter");
        assert_eq!(cur["rules"]["runes"]["on"], false);
        assert_eq!(cur["rules"]["inscriptions"]["on"], true); // default filled in
        let c = check_config(&json!({"mode": "off", "rules": {"minfee": {"on": true, "sat_vb": 2.34567}}}), &cur).unwrap();
        assert_eq!((c["mode"].as_str(), c["rules"]["minfee"]["sat_vb"].as_f64()), (Some("off"), Some(2.346)));
        assert!(check_config(&json!({"mode": "loud"}), &cur).is_err());
        assert!(check_config(&json!({"rules": {"nope": {}}}), &cur).is_err());
        assert!(check_config(&json!({"rules": {"opreturn": {"max_bytes": 100001}}}), &cur).is_err());
        assert_eq!(rule_state(&json!({"on": true, "watch": true})), "watch");
    }
}
