//! Async JSON-RPC client for bitcoind (HTTP/1.1, cookie or user/pass auth), re-reading the cookie on a 401
//! (bitcoind writes a new one on every restart).
//!
//! Connections are kept open and reused (keep-alive), so a call doesn't pay for a new TCP connection: that was
//! most of the time between the node's block signal and the miners' empty job. Two kinds of call never reuse
//! one: submitblock (a found block must not depend on an old socket) and long waits (the long-poll).
//! A reused connection the node has meanwhile closed fails at once; the call is then sent again on a fresh one.

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

const MAX_IDLE: usize = 4;
/// bitcoind drops an idle connection after rpcservertimeout (30 s by default); don't reuse one near that.
const IDLE_MAX_AGE: Duration = Duration::from_secs(15);
const MAX_REPLY: usize = 64 << 20;

pub struct Rpc {
    host: String,
    port: u16,
    path: String,
    cookie_path: Option<String>,
    userpass: Option<String>,
    auth: Mutex<Option<String>>,
    idle: std::sync::Mutex<Vec<(TcpStream, Instant)>>,
}

impl Rpc {
    /// url like "http://127.0.0.1:8332/"
    pub fn new(url: &str, cookie_path: Option<String>, user: &str, pass: &str) -> Result<Rpc> {
        let rest = url.strip_prefix("http://").ok_or_else(|| anyhow!("only http:// RPC urls: {}", url))?;
        let (hostport, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (host, port) = match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse()?),
            None => (hostport.to_string(), 8332),
        };
        Ok(Rpc {
            host,
            port,
            path: path.to_string(),
            cookie_path,
            userpass: if user.is_empty() { None } else { Some(format!("{}:{}", user, pass)) },
            auth: Mutex::new(None),
            idle: std::sync::Mutex::new(Vec::new()),
        })
    }

    fn load_auth(&self) -> Result<String> {
        let creds = match &self.userpass {
            Some(up) => up.clone(),
            None => {
                let p = self.cookie_path.as_ref().ok_or_else(|| anyhow!("no RPC user and no cookie file"))?;
                std::fs::read_to_string(shellexpand(p)).with_context(|| format!("reading cookie {}", p))?.trim().to_string()
            }
        };
        Ok(format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(creds)))
    }

    /// A call with pool.py's default 15 s timeout.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        self.call_t(method, params, 15).await
    }

    /// A call that gives up after `secs` (submitblock and block checks 60 s, the long-poll 900 s).
    pub async fn call_t(&self, method: &str, params: Value, secs: u64) -> Result<Value> {
        let body = json!({"jsonrpc": "1.0", "id": method, "method": method, "params": params}).to_string();
        let reuse = method != "submitblock" && secs <= 60;
        for attempt in 0..2 {
            let auth = {
                let mut a = self.auth.lock().await;
                if a.is_none() || attempt == 1 {
                    *a = Some(self.load_auth()?);
                }
                a.clone().unwrap()
            };
            let (status, reply) = tokio::time::timeout(Duration::from_secs(secs), self.exchange(&auth, &body, reuse))
                .await
                .map_err(|_| anyhow!("RPC {} timed out", method))??;
            if status == 401 && attempt == 0 {
                continue; // bitcoind writes a new cookie on every restart
            }
            let v: Value = serde_json::from_slice(&reply).with_context(|| format!("RPC {} HTTP {}", method, status))?;
            if !v["error"].is_null() {
                bail!("RPC {} error: {}", method, v["error"]);
            }
            return Ok(v["result"].clone());
        }
        bail!("RPC {}: unauthorised", method)
    }

    fn take_idle(&self) -> Option<TcpStream> {
        let mut idle = self.idle.lock().unwrap();
        idle.retain(|(_, at)| at.elapsed() < IDLE_MAX_AGE);
        idle.pop().map(|(s, _)| s)
    }

    fn put_idle(&self, s: TcpStream) {
        let mut idle = self.idle.lock().unwrap();
        if idle.len() < MAX_IDLE {
            idle.push((s, Instant::now()));
        }
    }

    async fn exchange(&self, auth: &str, body: &str, reuse: bool) -> Result<(u16, Vec<u8>)> {
        if reuse {
            if let Some(s) = self.take_idle() {
                // a connection the node closed meanwhile fails here; then use a fresh one (only for calls that
                // are safe to send twice: submitblock never comes this way)
                if let Ok((status, reply, back)) = self.post_on(s, auth, body, true).await {
                    if let Some(s) = back {
                        self.put_idle(s);
                    }
                    return Ok((status, reply));
                }
            }
        }
        let s = TcpStream::connect((self.host.as_str(), self.port)).await?;
        s.set_nodelay(true)?;
        let (status, reply, back) = self.post_on(s, auth, body, reuse).await?;
        if let Some(s) = back {
            self.put_idle(s);
        }
        Ok((status, reply))
    }

    /// One request on `s`; returns the connection when it may be used again.
    async fn post_on(&self, mut s: TcpStream, auth: &str, body: &str, keep: bool)
                     -> Result<(u16, Vec<u8>, Option<TcpStream>)> {
        let req = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nAuthorization: {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n{}",
            self.path, self.host, auth, body.len(), if keep { "keep-alive" } else { "close" }, body
        );
        s.write_all(req.as_bytes()).await?;
        let mut r = BufReader::new(&mut s);
        let mut line = String::new();
        if r.read_line(&mut line).await? == 0 {
            bail!("the node closed the connection");
        }
        let status: u16 = line.split_whitespace().nth(1).and_then(|x| x.parse().ok()).ok_or_else(|| anyhow!("bad status line"))?;
        let (mut length, mut chunked, mut close) = (None, false, !keep);
        loop {
            line.clear();
            if r.read_line(&mut line).await? == 0 {
                bail!("the node closed the connection in the headers");
            }
            let h = line.trim_end().to_ascii_lowercase();
            if h.is_empty() {
                break;
            }
            if let Some(v) = h.strip_prefix("content-length:") {
                length = v.trim().parse::<usize>().ok();
            } else if h.starts_with("transfer-encoding:") && h.contains("chunked") {
                chunked = true;
            } else if h.starts_with("connection:") && h.contains("close") {
                close = true;
            }
        }
        let mut reply = Vec::new();
        if chunked {
            loop {
                line.clear();
                r.read_line(&mut line).await?;
                let size = usize::from_str_radix(line.trim().split(';').next().unwrap_or("").trim(), 16)
                    .map_err(|_| anyhow!("bad chunk size"))?;
                if size == 0 {
                    loop {
                        // trailer lines, then the blank line that ends the reply
                        line.clear();
                        if r.read_line(&mut line).await? == 0 || line.trim().is_empty() {
                            break;
                        }
                    }
                    break;
                }
                if reply.len() + size > MAX_REPLY {
                    bail!("RPC reply over {} bytes", MAX_REPLY);
                }
                let start = reply.len();
                reply.resize(start + size, 0);
                r.read_exact(&mut reply[start..]).await?;
                let mut crlf = [0u8; 2];
                r.read_exact(&mut crlf).await?;
            }
        } else if let Some(n) = length {
            if n > MAX_REPLY {
                bail!("RPC reply over {} bytes", MAX_REPLY);
            }
            reply.resize(n, 0);
            r.read_exact(&mut reply).await?;
        } else {
            (&mut r).take(MAX_REPLY as u64).read_to_end(&mut reply).await?;
            close = true; // the end of the reply was the end of the connection
        }
        // no pipelining, so nothing of a next reply can be sitting in the buffer
        drop(r);
        Ok((status, reply, if close { None } else { Some(s) }))
    }
}

pub fn shellexpand(p: &str) -> String {
    match p.strip_prefix("~/") {
        Some(rest) => format!("{}/{}", std::env::var("HOME").unwrap_or_default(), rest),
        None => p.to_string(),
    }
}
