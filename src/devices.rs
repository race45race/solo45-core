//! Miner hardware readings for the status page: temperature, fan and watts, read straight from each connected
//! miner on the home network, the way the Solo45 dashboard reads them (no logins, read only):
//!  - AxeOS (Bitaxe): HTTP GET /api/system/info on port 80;
//!  - Braiins OS and other CGMiner-API miners: the JSON API on port 4028 ("temps", "fans", "tunerstatus").
//! Only private IPv4 addresses of miners that are connected right now are asked, every 30 s, with short timeouts.
use crate::pool::Pool;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const POLL_S: u64 = 30;
const TIMEOUT: Duration = Duration::from_secs(3);
const MAX_REPLY: usize = 512 * 1024;

fn private_v4(ip: &str) -> bool {
    ip.parse::<std::net::Ipv4Addr>().map_or(false, |a| a.is_private())
}

async fn read_reply(mut s: TcpStream) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = s.read(&mut chunk).await.ok()?;
        if n == 0 {
            return Some(buf);
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_REPLY {
            return None;
        }
    }
}

/// A body sent with Transfer-Encoding: chunked, put back together.
fn dechunk(mut b: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = b.windows(2).position(|w| w == b"\r\n")?;
        let size = usize::from_str_radix(std::str::from_utf8(&b[..eol]).ok()?.split(';').next()?.trim(), 16).ok()?;
        b = &b[eol + 2..];
        if size == 0 {
            return Some(out);
        }
        if b.len() < size {
            return None;
        }
        out.extend_from_slice(&b[..size]);
        b = b.get(size + 2..).unwrap_or(&[]);
    }
}

pub fn parse_http_json(buf: &[u8]) -> Option<Value> {
    let pos = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&buf[..pos]).to_ascii_lowercase();
    if head.split_whitespace().nth(1) != Some("200") {
        return None;
    }
    let body = &buf[pos + 4..];
    if head.contains("transfer-encoding: chunked") {
        serde_json::from_slice(&dechunk(body)?).ok()
    } else {
        serde_json::from_slice(body).ok()
    }
}

/// True once `buf` holds a whole HTTP reply (AxeOS keeps the connection open after it, so don't wait for a close).
pub fn http_complete(buf: &[u8]) -> bool {
    let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") else { return false };
    let head = String::from_utf8_lossy(&buf[..pos]).to_ascii_lowercase();
    let body = &buf[pos + 4..];
    if let Some(len) = head.lines().find_map(|l| l.strip_prefix("content-length:")).and_then(|v| v.trim().parse::<usize>().ok()) {
        return body.len() >= len;
    }
    head.contains("transfer-encoding: chunked") && body.ends_with(b"0\r\n\r\n")
}

async fn http_json(ip: &str, path: &str) -> Option<Value> {
    let fut = async {
        let mut s = TcpStream::connect((ip, 80)).await.ok()?;
        let req = format!("GET {} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nConnection: close\r\n\r\n", path, ip);
        s.write_all(req.as_bytes()).await.ok()?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        while !http_complete(&buf) {
            let n = s.read(&mut chunk).await.ok()?;
            if n == 0 || buf.len() > MAX_REPLY {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        parse_http_json(&buf)
    };
    tokio::time::timeout(TIMEOUT, fut).await.ok().flatten()
}

async fn cgminer(ip: &str, cmd: &str) -> Option<Value> {
    let fut = async {
        let mut s = TcpStream::connect((ip, 4028)).await.ok()?;
        s.write_all(json!({ "command": cmd }).to_string().as_bytes()).await.ok()?;
        let buf = read_reply(s).await?;
        let text = String::from_utf8_lossy(&buf);
        serde_json::from_str(text.trim_matches(|c: char| c == '\0' || c.is_whitespace())).ok()
    };
    tokio::time::timeout(TIMEOUT, fut).await.ok().flatten()
}

fn num(v: &Value) -> Option<f64> {
    v.as_f64().filter(|x| x.is_finite())
}

/// AxeOS /api/system/info -> the readings shown on the page.
pub fn from_axeos(i: &Value) -> Value {
    // a Bitaxe Hex has two chip sensors (temp, temp2): show the hotter one, like its own page
    let chip_temp = [num(&i["temp"]), num(&i["temp2"])].into_iter().flatten().filter(|t| *t > 0.0)
        .fold(None, |m: Option<f64>, t| Some(m.map_or(t, |m| m.max(t))));
    json!({
        "kind": "bitaxe",
        "model": i["ASICModel"].as_str().map(|m| format!("Bitaxe {}", m)),
        "temp": chip_temp,
        "vr_temp": num(&i["vrTemp"]).filter(|t| *t > 0.0),
        "fan": num(&i["fanspeed"]),
        "watts": num(&i["power"]),
        "freq": num(&i["frequency"]),
        "mv": num(&i["coreVoltage"]),
    })
}

/// CGMiner-API replies (Braiins OS) -> the readings shown on the page.
pub fn from_cgminer(temps: &Value, fans: &Value, tuner: &Value) -> Value {
    let list = |v: &Value, k: &str| v[k].as_array().cloned().unwrap_or_default();
    let max_of = |rows: &[Value], k: &str| rows.iter().filter_map(|r| num(&r[k])).filter(|x| *x > 0.0).fold(None, |m: Option<f64>, x| Some(m.map_or(x, |m| m.max(x))));
    let t = list(temps, "TEMPS");
    let f: Vec<f64> = list(fans, "FANS").iter().filter_map(|r| num(&r["Speed"])).collect();
    json!({
        "kind": "braiins",
        "model": "Braiins OS",
        "temp": max_of(&t, "Chip"),
        "vr_temp": max_of(&t, "Board"),
        "fan": if f.is_empty() { None } else { Some(f.iter().sum::<f64>() / f.len() as f64) },
        "watts": num(&tuner["TUNERSTATUS"][0]["ApproximateMinerPowerConsumption"]),
    })
}

/// Canaan packs an Avalon's readings into one "estats" string: 'TAvg[71] OTemp[52] FanR[40%] MPO[133] ...'.
pub fn avalon_fields(text: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let b = text.as_bytes();
    let mut i = 0;
    while let Some(open) = text[i..].find('[').map(|p| p + i) {
        let mut k = open;
        while k > 0 && (b[k - 1].is_ascii_alphanumeric() || b[k - 1] == b'_') {
            k -= 1;
        }
        let Some(close) = text[open..].find(']').map(|p| p + open) else { break };
        if k < open {
            out.insert(text[k..open].to_string(), text[open + 1..close].to_string());
        }
        i = close + 1;
    }
    out
}

/// An Avalon's estats ("MM ID0" string) -> the readings shown on the page (the same fields the Solo45 dashboard uses).
pub fn from_avalon(mm: &str) -> Value {
    let f = avalon_fields(mm);
    let n = |k: &str, idx: isize| -> Option<f64> {
        let parts: Vec<&str> = f.get(k)?.split_whitespace().collect();
        let i = if idx < 0 { parts.len().checked_sub(1)? } else { idx as usize };
        parts.get(i)?.trim_end_matches('%').parse::<f64>().ok().filter(|x| x.is_finite())
    };
    let watts = n("MPO", 0).filter(|w| *w > 0.0).or_else(|| n("PS", -1).filter(|w| *w > 0.0));
    json!({
        "kind": "avalon",
        "model": "Avalon",
        "temp": n("TAvg", 0).filter(|t| *t > -40.0 && *t < 150.0),
        "temp_max": n("TMax", 0),
        "vr_temp": n("OTemp", 0).filter(|t| *t > -40.0 && *t < 150.0),
        "fan": n("FanR", 0),
        "watts": watts,
    })
}

async fn read_device(ip: &str, kind: Option<&str>) -> Option<Value> {
    if kind != Some("braiins") {
        if let Some(i) = http_json(ip, "/api/system/info").await {
            if i.get("ASICModel").is_some() || i.get("hashRate").is_some() {
                return Some(from_axeos(&i));
            }
        }
    }
    if kind != Some("bitaxe") {
        let temps = cgminer(ip, "temps").await;
        let fans = cgminer(ip, "fans").await;
        if temps.is_some() || fans.is_some() {
            let tuner = cgminer(ip, "tunerstatus").await.unwrap_or(Value::Null);
            let d = from_cgminer(&temps.unwrap_or(Value::Null), &fans.unwrap_or(Value::Null), &tuner);
            // other CGMiner-API miners (an Avalon Nano, say) answer but report none of these: show nothing
            if ["temp", "fan", "watts"].iter().any(|k| !d[*k].is_null()) {
                return Some(d);
            }
        }
        // a Canaan Avalon (Nano 3S): its readings are only in the estats string
        if let Some(st) = cgminer(ip, "estats").await {
            let mm = st["STATS"].as_array().into_iter().flatten()
                .flat_map(|s| s.as_object().into_iter().flatten())
                .find(|(k, v)| k.starts_with("MM ID") && v.is_string())
                .and_then(|(_, v)| v.as_str().map(String::from));
            if let Some(mm) = mm {
                let d = from_avalon(&mm);
                if ["temp", "fan", "watts"].iter().any(|k| !d[*k].is_null()) {
                    return Some(d);
                }
            }
        }
    }
    None
}

/// One miner's readings, as the status page would show them (`solo45-core read-miner <ip>`).
pub async fn read_once(ip: &str) -> Value {
    read_device(ip, None).await.unwrap_or(Value::Null)
}

/// Every 30 s: read each connected miner (private IPv4 only) and keep the latest readings by IP.
pub async fn poll_loop(pool: Arc<Pool>) {
    let mut kinds: HashMap<String, String> = HashMap::new();
    loop {
        let ips: Vec<String> = {
            let mut v: Vec<String> = pool.worker_ips().into_iter().filter(|ip| private_v4(ip)).collect();
            v.sort();
            v.dedup();
            v
        };
        // all miners at once, so one that doesn't answer (timeouts) doesn't hold up the others
        let mut set = tokio::task::JoinSet::new();
        for ip in &ips {
            let (ip, known) = (ip.clone(), kinds.get(ip).cloned());
            set.spawn(async move {
                let mut d = read_device(&ip, known.as_deref()).await;
                if d.is_none() && known.is_some() {
                    d = read_device(&ip, None).await; // firmware changed, or the miner was swapped
                }
                (ip, d)
            });
        }
        let now = crate::util::now_f();
        let mut found: HashMap<String, Value> = HashMap::new();
        while let Some(Ok((ip, d))) = set.join_next().await {
            if let Some(mut d) = d {
                kinds.insert(ip.clone(), d["kind"].as_str().unwrap_or("").to_string());
                d["at"] = json!(now);
                found.insert(ip, d);
            }
        }
        // one missed reading keeps the last one for up to 90 s instead of blanking the row
        {
            let old = pool.devices.read().unwrap();
            for ip in &ips {
                if let Some(o) = old.get(ip) {
                    if !found.contains_key(ip) && now - o["at"].as_f64().unwrap_or(0.0) < 90.0 {
                        found.insert(ip.clone(), o.clone());
                    }
                }
            }
        }
        kinds.retain(|ip, _| ips.contains(ip));
        *pool.devices.write().unwrap() = found;
        tokio::time::sleep(Duration::from_secs(POLL_S)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn axeos_reply_plain_and_chunked() {
        let body = r#"{"ASICModel":"BM1368","temp":55.5,"vrTemp":61,"fanspeed":40,"power":87.2,"frequency":600,"coreVoltage":1215,"hashRate":4500}"#;
        let plain = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
        assert!(http_complete(plain.as_bytes()) && !http_complete(&plain.as_bytes()[..plain.len() - 1]));
        let d = from_axeos(&parse_http_json(plain.as_bytes()).unwrap());
        assert_eq!(d["model"], "Bitaxe BM1368");
        assert_eq!(d["temp"], 55.5);
        assert_eq!(d["fan"], 40.0);
        let hex = from_axeos(&json!({"ASICModel": "BM1368", "temp": 24.7, "temp2": 37.4}));
        assert_eq!(hex["temp"], 37.4);
        let gamma = from_axeos(&json!({"ASICModel": "BM1370", "temp": 58.0, "temp2": -1}));
        assert_eq!(gamma["temp"], 58.0);
        let (a, b) = body.split_at(20);
        let chunked = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n{:x}\r\n{}\r\n0\r\n\r\n", a.len(), a, b.len(), b);
        assert!(http_complete(chunked.as_bytes()));
        assert_eq!(parse_http_json(chunked.as_bytes()).unwrap()["power"], 87.2);
        assert!(parse_http_json(b"HTTP/1.1 404 Not Found\r\n\r\n{}").is_none());
    }

    #[test]
    fn braiins_readings() {
        let temps = json!({"TEMPS": [{"Board": 50.0, "Chip": 65.0}, {"Board": 52.0, "Chip": 68.5}, {"Board": 0, "Chip": 0}]});
        let fans = json!({"FANS": [{"RPM": 3000, "Speed": 40}, {"RPM": 3100, "Speed": 50}]});
        let tuner = json!({"TUNERSTATUS": [{"ApproximateMinerPowerConsumption": 2142}]});
        let d = from_cgminer(&temps, &fans, &tuner);
        assert_eq!(d["temp"], 68.5);
        assert_eq!(d["vr_temp"], 52.0);
        assert_eq!(d["fan"], 45.0);
        assert_eq!(d["watts"], 2142.0);
        assert!(!private_v4("8.8.8.8") && private_v4("192.168.4.28") && !private_v4("nonsense"));
    }

    #[test]
    fn avalon_readings() {
        let mm = "Ver[Nano3s] OTemp[52] TMax[76] TAvg[71] TarT[90] Fan1[1700] FanR[40%] PS[0 0 27471 4 0 3782 131] MPO[133] WORKMODE[2]";
        let d = from_avalon(mm);
        assert_eq!(d["temp"], 71.0);
        assert_eq!(d["vr_temp"], 52.0);
        assert_eq!(d["fan"], 40.0);
        assert_eq!(d["watts"], 133.0);
        let no_mpo = from_avalon("TAvg[60] PS[0 0 27471 4 0 3782 131]");
        assert_eq!(no_mpo["watts"], 131.0);
        assert!(from_avalon("garbage [ no ] fields")["temp"].is_null());
    }
}
