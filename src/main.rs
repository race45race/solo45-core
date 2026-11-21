//! Solo45 Core: a fast solo Bitcoin mining pool in Rust.
//!
//! Commands:
//!   solo45-core serve                        run the pool (settings from SOLO45_* / BITCOIN_* environment)
//!   solo45-core node                         ask the node for chain info and a block template
//!   solo45-core job <template.json> <tag> <spk_hex>
//!                                            print the job built from a saved template (for the pool.py cross-check)

mod api;
mod job;
mod pool;
mod rpc;
mod stratum;
mod util;
mod zmq;

use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("serve") => serve().await,
        Some("version") => {
            println!("solo45-core {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("node") => node().await,
        Some("job") if args.len() == 5 => job_dump(&args[2], &args[3], &args[4]),
        _ => bail!("usage: solo45-core serve | version | node | job <template.json> <tag> <spk_hex>"),
    }
}

async fn serve() -> Result<()> {
    if let Some(f) = std::env::var("SOLO45_LOG_FILE").ok().filter(|f| !f.is_empty()) {
        util::log_to_file(&f);
    }
    let cfg = pool::Config::from_env();
    let pool = match pool::Pool::new(cfg.clone()) {
        Ok(p) => p,
        Err(e) => {
            log!("ERROR", "can't start: {:#}", e);
            return Err(e);
        }
    };
    if let Err(e) = pool.start().await {
        log!("ERROR", "can't start: {:#} (the app restarts and tries again)", e);
        return Err(e);
    }
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", cfg.stratum_port)).await?;
    let api_listener = tokio::net::TcpListener::bind(("0.0.0.0", cfg.api_port)).await?;
    tokio::spawn(api::serve(pool.clone(), api_listener, api::Kind::Api));
    if cfg.web_port != 0 {
        let web = tokio::net::TcpListener::bind(("0.0.0.0", cfg.web_port)).await?;
        tokio::spawn(api::serve(pool.clone(), web, api::Kind::Web));
    }
    log!("INFO", "Solo45 Core {}: stratum on :{}, api on :{}{}, height {}, pays {} by default{}",
        env!("CARGO_PKG_VERSION"), cfg.stratum_port, cfg.api_port,
        if cfg.web_port != 0 { format!(", status page on :{}", cfg.web_port) } else { String::new() },
        pool.current().map_or(0, |j| j.height),
        pool.default_address(), if pool.pays_default() { " (every miner)" } else { "" });
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut warned: std::collections::HashMap<std::net::IpAddr, f64> = std::collections::HashMap::new();
    loop {
        tokio::select! {
            a = listener.accept() => match a {
                Ok((stream, peer)) => {
                    if !pool.conn_open(peer.ip()) {
                        let last = warned.entry(peer.ip()).or_insert(0.0);
                        if util::now_f() - *last > 300.0 { // at most every 5 minutes per address
                            *last = util::now_f();
                            log!("WARNING", "refused a connection from {}: too many open from there (limit {})", peer.ip(), cfg.max_conns_per_ip);
                        }
                        continue;
                    }
                    tokio::spawn(stratum::serve(Arc::clone(&pool), stream, peer));
                }
                Err(e) => {
                    // out of file descriptors or memory must not end the pool (ckpool 72aff21 class): wait and go on
                    log!("WARNING", "accept failed: {}", e);
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            },
            _ = term.recv() => break,
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    pool.stop().await;
    Ok(())
}

fn rpc_from_env() -> Result<rpc::Rpc> {
    let c = pool::Config::from_env();
    rpc::Rpc::new(&c.rpc_url, Some(c.rpc_cookie), &c.rpc_user, &c.rpc_pass)
}

async fn node() -> Result<()> {
    let rpc = rpc_from_env()?;
    let t0 = std::time::Instant::now();
    let info = rpc.call("getblockchaininfo", json!([])).await?;
    let t1 = t0.elapsed();
    let tpl = rpc.call("getblocktemplate", json!([{"rules": ["segwit"]}])).await?;
    let t2 = t0.elapsed();
    let j = job::Job::new("1", &tpl, b"Solo45", &mut job::TxCache::new())?;
    let spk = hex::decode("0014751e76e8199196d454941c45d1b3a323f1433bd6")?; // BIP 173's example address (timing only)
    let cb2 = j.coinb2(&spk);
    let t3 = t0.elapsed();
    println!(
        "chain {} height {} | template height {} with {} txs, fees {} sat, {} merkle branches | coinb1 {} B, coinb2 {} B",
        info["chain"], info["blocks"], j.height, j.tx_data.len(), j.fees, j.branch.len(), j.coinb1.len(), cb2.len()
    );
    println!("timing: chain info {:?}, template {:?}, job built {:?}", t1, t2 - t1, t3 - t2);
    Ok(())
}

fn job_dump(path: &str, tag: &str, spk_hex: &str) -> Result<()> {
    let tpl: Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    let j = job::Job::new("1", &tpl, tag.as_bytes(), &mut job::TxCache::new())?;
    let spk = hex::decode(spk_hex)?;
    let cb2 = j.coinb2(&spk);
    // a fixed test share: en1 = 01020304, en2 = 8 x 0xaa, ntime = curtime, nonce = 0x12345678, version rolled
    let mut coinbase = j.coinb1.clone();
    coinbase.extend_from_slice(&[1, 2, 3, 4]);
    coinbase.extend_from_slice(&[0xaa; 8]);
    coinbase.extend(&cb2);
    let version = (j.version & !0x1fffe000) | 0x00a4e000;
    let hdr = j.header(&coinbase, version, j.curtime, 0x12345678);
    let block = j.block(&hdr, &coinbase);
    let out = json!({
        "height": j.height,
        "coinb1": hex::encode(&j.coinb1),
        "coinb2": hex::encode(&cb2),
        "branch": j.branch.iter().map(hex::encode).collect::<Vec<_>>(),
        "stratum_prev": j.stratum_prev(),
        "version": format!("{:08x}", j.version),
        "header": hex::encode(hdr),
        "block_sha256d": hex::encode(util::sha256d(&block)),
        "block_len": block.len(),
    });
    println!("{}", out);
    Ok(())
}
