//! The pool's HTTP side, in two listeners.
//!
//! The API (SOLO45_API_PORT), compatible with pool.py's: GET the snapshot, /api/shares?since=N, /api/export; POST
//! /api/worker, /api/settings, /api/payout, /api/policy, /api/restore. Only the machine itself, or a caller with the app's shared secret
//! (X-Solo45-Token), may use it, for reading too: it shows payout addresses and miner names and addresses.
//!
//! The status page (SOLO45_WEB_PORT, the Umbrel app's web port): the page itself, the snapshot and the same three
//! settings routes. It answers only the machine itself and the container's default gateway, which is where
//! umbrelOS's login-checking app gateway (and the Umbrel host) connect from; other apps get 403. Changes also need
//! a same-origin request (Sec-Fetch-Site, or an Origin matching Host), so another website open in the owner's
//! browser can't change the payout address.

use crate::log;
use crate::pool::Pool;
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

const PAGE: &str = include_str!("../web/index.html");

#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    Api,
    Web,
}

pub async fn serve(pool: Arc<Pool>, listener: TcpListener, kind: Kind) {
    loop {
        match listener.accept().await {
            Ok((s, peer)) => {
                tokio::spawn(handle(pool.clone(), s, peer, kind));
            }
            Err(e) => {
                log!("WARNING", "{} accept failed: {}", if kind == Kind::Api { "API" } else { "status page" }, e);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn read_line<R: AsyncBufReadExt + Unpin>(r: &mut R) -> Option<String> {
    let mut buf = Vec::new();
    match tokio::time::timeout(Duration::from_secs(5), r.read_until(b'\n', &mut buf)).await {
        Ok(Ok(_)) => Some(String::from_utf8_lossy(&buf).into_owned()),
        _ => None,
    }
}

/// "%20" etc. in a query value back to text (invalid sequences are kept as they are).
fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("zz"), 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.to_ipv4_mapped().map_or(false, |v4| v4.is_loopback()),
    }
}

/// The container's default gateway from /proc/net/route (the Destination 00000000 line; addresses are little-endian hex).
fn default_gateway() -> Option<Ipv4Addr> {
    let table = std::fs::read_to_string("/proc/net/route").ok()?;
    table.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() > 2 && f[1] == "00000000" {
            u32::from_str_radix(f[2], 16).ok().filter(|g| *g != 0).map(|g| Ipv4Addr::from(g.swap_bytes()))
        } else {
            None
        }
    })
}

/// Addresses allowed to read the status, share feed and history on the status page's port, and to pass on per-miner
/// difficulty (SOLO45_WEB_READERS, comma separated): the Solo45 dashboard's container, which only accepts those
/// changes through the Umbrel login. Never pool settings, the payout address, the policy, backups or restores.
fn is_reader(pool: &Pool, ip: IpAddr) -> bool {
    let Some(ip) = v4(ip) else { return false };
    pool.readers.read().unwrap().iter().any(|r| *r == ip)
}

fn v4(ip: IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(a) => Some(a),
        IpAddr::V6(a) => a.to_ipv4_mapped(),
    }
}

#[derive(Default)]
struct Req {
    length: usize,
    token: String,
    fetch_site: String,
    origin: String,
    host: String,
    fwd_host: String,
}

impl Req {
    /// A browser request from the page itself (not from another website).
    fn same_origin(&self) -> bool {
        if !self.fetch_site.is_empty() {
            return self.fetch_site == "same-origin";
        }
        let o = self.origin.split("://").nth(1).unwrap_or("");
        !o.is_empty() && (o == self.host || o == self.fwd_host)
    }
}

enum Body {
    Json(Value),
    Html(&'static str),
}

async fn handle(pool: Arc<Pool>, stream: TcpStream, peer: SocketAddr, kind: Kind) {
    let (r, mut w) = stream.into_split();
    let mut r = BufReader::new(r.take(300_000));
    let Some(first) = read_line(&mut r).await else { return };
    let mut it = first.split_whitespace();
    let (method, path) = match (it.next(), it.next()) {
        (Some(m), Some(p)) => (m.to_string(), p.to_string()),
        _ => return reply(&mut w, 400, Body::Json(json!({"error": "bad request"}))).await,
    };
    let mut q = Req::default();
    loop {
        let Some(l) = read_line(&mut r).await else { return };
        let t = l.trim_end();
        if t.is_empty() {
            break;
        }
        let Some((k, v)) = t.split_once(':') else { continue };
        let v = v.trim();
        match k.trim().to_ascii_lowercase().as_str() {
            "content-length" => q.length = v.parse().unwrap_or(0),
            "x-solo45-token" => q.token = v.to_string(),
            "sec-fetch-site" => q.fetch_site = v.to_ascii_lowercase(),
            "origin" => q.origin = v.to_ascii_lowercase(),
            "host" => q.host = v.to_ascii_lowercase(),
            "x-forwarded-host" => q.fwd_host = v.to_ascii_lowercase(),
            _ => {}
        }
    }
    let (status, body) = match kind {
        Kind::Api => {
            let secret = &pool.cfg.api_token;
            if is_local(peer.ip()) || (!secret.is_empty() && ct_eq(q.token.as_bytes(), secret.as_bytes())) {
                let (s, v) = route(&pool, &method, &path, q.length, &mut r).await;
                (s, Body::Json(v))
            } else {
                (403, Body::Json(json!({"error": if secret.is_empty() {
                    "set SOLO45_API_TOKEN (the same on the pool and the dashboard) to use the pool's API from another machine or container"
                } else {
                    "the pool's API needs the app's token"
                }})))
            }
        }
        Kind::Web => {
            let trusted = is_local(peer.ip()) || (v4(peer.ip()).is_some() && v4(peer.ip()) == default_gateway());
            let p = path.split('?').next().unwrap_or("");
            let reader_ok = match method.as_str() {
                "GET" => matches!(p, "/api/state" | "/api/shares" | "/api/history"),
                // the dashboard passes on per-miner difficulty it took through the Umbrel login (pool settings, the
                // payout address, the policy and restores stay on Core's own page)
                "POST" => p == "/api/worker",
                _ => false,
            };
            if !trusted && reader_ok && is_reader(&pool, peer.ip()) {
                // the Solo45 dashboard (SOLO45_WEB_READERS): status, share feed, history; per-miner difficulty
                let (s, v) = route(&pool, &method, &path, q.length, &mut r).await;
                reply(&mut w, s, Body::Json(v)).await;
                return;
            }
            if !trusted {
                log!("WARNING", "status page: refused a request from {} (open Solo45 SV2 from the Umbrel home screen)", peer.ip());
                (403, Body::Json(json!({"error": "open Solo45 SV2 from your Umbrel's home screen"})))
            } else if method == "GET" && (path == "/" || path.starts_with("/?")) {
                (200, Body::Html(PAGE))
            } else if method == "POST" && !q.same_origin() {
                (403, Body::Json(json!({"error": "changes are only accepted from the Solo45 SV2 page itself"})))
            } else {
                if matches!((method.as_str(), p), ("GET", "/api/state" | "/api/export" | "/api/shares" | "/api/history")
                    | ("POST", "/api/worker" | "/api/settings" | "/api/payout" | "/api/policy" | "/api/restore")) {
                    let (s, v) = route(&pool, &method, &path, q.length, &mut r).await;
                    (s, Body::Json(v))
                } else if method == "GET" {
                    (404, Body::Json(json!({"error": "not found"})))
                } else {
                    (405, Body::Json(json!({"error": "method not allowed"})))
                }
            }
        }
    };
    reply(&mut w, status, body).await;
}

async fn route<R: AsyncRead + Unpin>(pool: &Arc<Pool>, method: &str, path: &str, length: usize, r: &mut R) -> (u16, Value) {
    let (p, query) = path.split_once('?').unwrap_or((path, ""));
    match (method, p) {
        ("POST", "/api/worker" | "/api/settings" | "/api/payout" | "/api/policy" | "/api/restore") => {
            let mut body = vec![0u8; length.min(if p == "/api/restore" { 200_000 } else { 4096 })];
            match tokio::time::timeout(Duration::from_secs(5), r.read_exact(&mut body)).await {
                Ok(Ok(_)) => {}
                _ => return (400, json!({"error": "bad request"})),
            }
            let data: Value = match serde_json::from_slice(&body) {
                Ok(v @ Value::Object(_)) => v,
                _ => return (400, json!({"error": "bad request"})),
            };
            match p {
                "/api/worker" => pool.set_override(&data),
                "/api/settings" => pool.set_settings(&data).await,
                "/api/policy" => pool.set_policy(&data).await,
                "/api/restore" => pool.restore_settings(&data).await,
                _ => pool.set_payout(&data).await,
            }
        }
        ("GET", "/api/export") => (200, pool.export_settings()),
        ("GET", "/api/history") => {
            // ?worker=NAME: that miner's own 24 h readings (names are percent-encoded by the page)
            let w = query.split('&').find_map(|kv| kv.strip_prefix("worker=")).map(pct_decode);
            (200, pool.history(w.as_deref()))
        }
        ("GET", "/api/shares") => {
            let since = query.split('&').find_map(|kv| kv.strip_prefix("since=")).and_then(|v| v.parse().ok()).unwrap_or(0);
            (200, pool.shares_since(since))
        }
        ("GET", "/" | "/api" | "/api/" | "/api/state") => (200, pool.snapshot()),
        ("GET", _) => (404, json!({"error": "not found"})),
        _ => (405, json!({"error": "method not allowed"})),
    }
}

async fn reply<W: AsyncWriteExt + Unpin>(w: &mut W, status: u16, body: Body) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Not Implemented",
    };
    let (ctype, body) = match body {
        Body::Json(v) => ("application/json", v.to_string()),
        Body::Html(h) => ("text/html; charset=utf-8", h.to_string()),
    };
    let msg = format!("HTTP/1.1 {} {}\r\nContent-Type: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\
                       Referrer-Policy: no-referrer\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                      status, reason, ctype, body.len(), body);
    let _ = tokio::time::timeout(Duration::from_secs(10), w.write_all(msg.as_bytes())).await;
    let _ = w.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::Req;

    #[test]
    fn same_origin_rules() {
        let mut q = Req { fetch_site: "same-origin".into(), ..Default::default() };
        assert!(q.same_origin());
        q.fetch_site = "cross-site".into();
        q.origin = "http://umbrel.local:4546".into();
        q.host = "umbrel.local:4546".into();
        assert!(!q.same_origin()); // the browser's own verdict wins
        q.fetch_site.clear();
        assert!(q.same_origin()); // old browser: Origin matches Host
        q.origin = "https://evil.example".into();
        assert!(!q.same_origin());
        q.origin.clear();
        assert!(!q.same_origin()); // no Origin, no Sec-Fetch-Site: refused
    }
}
