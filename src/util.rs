//! Byte-level helpers shared by the pool: hashing, Bitcoin serialisation and Stratum encodings.
//! Each one mirrors the function of the same name in Solo45's pool.py, so both pools build identical work.

use sha2::{Digest, Sha256};

const fn hex_lut() -> [u8; 256] {
    let mut t = [0xffu8; 256];
    let mut i = 0;
    while i < 10 {
        t[b'0' as usize + i] = i as u8;
        i += 1;
    }
    let mut i = 0;
    while i < 6 {
        t[b'a' as usize + i] = 10 + i as u8;
        t[b'A' as usize + i] = 10 + i as u8;
        i += 1;
    }
    t
}
static HEX_LUT: [u8; 256] = hex_lut();

/// Hex to bytes with a lookup table: the `hex` crate's decoder took 35 ms for a full template's transactions,
/// this one about 2 ms. None for odd lengths or non-hex characters.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut bad = 0u8;
    for p in b.chunks_exact(2) {
        let (h, l) = (HEX_LUT[p[0] as usize], HEX_LUT[p[1] as usize]);
        bad |= h | l;
        out.push((h << 4) | (l & 0x0f));
    }
    if bad & 0xf0 != 0 {
        return None;
    }
    Some(out)
}

/// Double SHA-256.
pub fn sha256d(b: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(b);
    Sha256::digest(first).into()
}

/// Bitcoin CompactSize integer.
pub fn varint(n: u64) -> Vec<u8> {
    if n < 0xfd {
        vec![n as u8]
    } else if n <= 0xffff {
        let mut v = vec![0xfd];
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v
    } else if n <= 0xffff_ffff {
        let mut v = vec![0xfe];
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xff];
        v.extend_from_slice(&n.to_le_bytes());
        v
    }
}

/// CScriptNum encoding, used for the BIP34 height in the coinbase.
pub fn script_num(mut n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    while n > 0 {
        out.push((n & 0xff) as u8);
        n >>= 8;
    }
    if let Some(&last) = out.last() {
        if last & 0x80 != 0 {
            out.push(0);
        }
    }
    out
}

/// A direct push of up to 75 bytes.
pub fn push(data: &[u8]) -> Vec<u8> {
    assert!(data.len() < 76, "push of {} bytes", data.len());
    let mut v = vec![data.len() as u8];
    v.extend_from_slice(data);
    v
}

/// Target from compact bits as a 256-bit big-endian byte array (the node never sends a negative target).
pub fn bits_to_target(bits: u32) -> [u8; 32] {
    let exp = (bits >> 24) as usize;
    let mant = bits & 0x00ff_ffff;
    let mut t = [0u8; 32];
    // value = mant << (8 * (exp - 3)); place the 3 mantissa bytes so the lowest sits at byte (32 - exp + 2)
    let m = [(mant >> 16) as u8, (mant >> 8) as u8, mant as u8];
    for (i, b) in m.iter().enumerate() {
        let pos = 32i64 - exp as i64 + i as i64;
        if (0..32).contains(&pos) {
            t[pos as usize] = *b;
        }
    }
    t
}

/// Stratum merkle branch for the coinbase (index 0). txids in internal byte order.
pub fn merkle_branch(txids: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut branch = Vec::new();
    // level[0] stands for the coinbase, which we don't know yet
    let mut level: Vec<Option<[u8; 32]>> = std::iter::once(None).chain(txids.iter().map(|t| Some(*t))).collect();
    while level.len() > 1 {
        branch.push(level[1].expect("level[1] is a known hash"));
        if level.len() % 2 == 1 {
            let last = *level.last().unwrap();
            level.push(last);
        }
        let mut next = vec![None];
        let mut i = 2;
        while i < level.len() {
            let mut cat = [0u8; 64];
            cat[..32].copy_from_slice(&level[i].unwrap());
            cat[32..].copy_from_slice(&level[i + 1].unwrap());
            next.push(Some(sha256d(&cat)));
            i += 2;
        }
        level = next;
    }
    branch
}

/// The previous-block hash the way Stratum sends it: internal order with each 4-byte word reversed.
pub fn stratum_prevhash(prev_internal: &[u8; 32]) -> String {
    let mut out = [0u8; 32];
    for w in 0..8 {
        for b in 0..4 {
            out[4 * w + b] = prev_internal[4 * w + 3 - b];
        }
    }
    hex::encode(out)
}

/// A hash (internal byte order, as sha256d returns it) compared with a big-endian target: true if hash <= target.
pub fn hash_meets(hash_le: &[u8; 32], target_be: &[u8; 32]) -> bool {
    for i in 0..32 {
        let h = hash_le[31 - i];
        if h != target_be[i] {
            return h < target_be[i];
        }
    }
    true
}

/// Difficulty of a hash (internal byte order): difficulty-1 target / hash, as pool.py's DIFF1 / h.
pub fn hash_diff(hash_le: &[u8; 32]) -> f64 {
    let mut v = 0f64;
    for i in (0..32).rev() {
        v = v * 256.0 + hash_le[i] as f64;
    }
    if v == 0.0 {
        f64::INFINITY
    } else {
        65535.0 * 2f64.powi(208) / v
    }
}

/// Difficulty of a big-endian target (pool.py's DIFF1 / job.target): the network difficulty.
pub fn target_diff(target_be: &[u8; 32]) -> f64 {
    let v = target_be.iter().fold(0f64, |v, &b| v * 256.0 + b as f64);
    if v == 0.0 { 0.0 } else { 65535.0 * 2f64.powi(208) / v }
}

/// Hashes per second from (time, difficulty) shares in the last `window` seconds.
pub fn hashrate<'a>(shares: impl Iterator<Item = &'a (f64, f64)>, window: f64, now: f64) -> f64 {
    let total: f64 = shares.filter(|s| s.0 > now - window).map(|s| s.1).sum();
    total * 2f64.powi(32) / window
}

/// pool.py's median: the upper middle value, None when empty.
pub fn median<'a>(values: impl Iterator<Item = &'a u64>) -> Option<u64> {
    let mut v: Vec<u64> = values.copied().collect();
    v.sort_unstable();
    v.get(v.len() / 2).copied()
}

/// float("%.3g" % x)
pub fn sig3(x: f64) -> f64 {
    if x == 0.0 || !x.is_finite() {
        return x;
    }
    format!("{:.2e}", x).parse().unwrap_or(x)
}

/// pool.py's fmt_diff: 3 significant digits with K/M/G/T.
pub fn fmt_diff(d: f64) -> String {
    for (unit, size) in [("T", 1e12), ("G", 1e9), ("M", 1e6), ("K", 1e3)] {
        if d >= size {
            return format!("{}{}", g3(d / size), unit);
        }
    }
    g3(d)
}

/// Python's "%.3g" as text (no trailing zeros).
pub fn g3(x: f64) -> String {
    let v = sig3(x);
    if v != 0.0 && (v.abs() >= 1e3 || v.abs() < 1e-4) {
        return format!("{:e}", v);
    }
    let s = format!("{}", v);
    s
}

/// 1234567 -> "1,234,567"
pub fn commas(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Seconds since 1970 as a float.
pub fn now_f() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// "2026-11-20 15:04:05,123" (UTC), the same timestamp shape as pool.py's log.
pub fn stamp() -> String {
    let t = now_f();
    let secs = t as i64;
    let ms = ((t - secs as f64) * 1000.0) as i64;
    let days = secs.div_euclid(86400);
    let sod = secs.rem_euclid(86400);
    // civil-from-days (Howard Hinnant)
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02},{:03}", y, m, d, sod / 3600, sod / 60 % 60, sod % 60, ms)
}

/// Log a line to stdout in pool.py's format.
#[macro_export]
macro_rules! log {
    ($lvl:expr, $($arg:tt)*) => {
        $crate::util::log_line(&format!("{} {} {}", $crate::util::stamp(), $lvl, format!($($arg)*)))
    };
}

/// Where log lines go: always stdout (the container log, which umbrelOS shows as the app's logs), and also the file
/// named by SOLO45_LOG_FILE (the Umbrel app's data folder), which is rotated at 20 MB keeping three old copies
/// (pool.log.1 .. pool.log.3), like pool.py's log.
struct LogFile {
    path: String,
    file: Option<std::fs::File>,
    size: u64,
}

static LOG: std::sync::Mutex<Option<LogFile>> = std::sync::Mutex::new(None);
const LOG_MAX: u64 = 20 << 20;

pub fn log_to_file(path: &str) {
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    *LOG.lock().unwrap() = Some(LogFile { path: path.to_string(), file: None, size });
}

pub fn log_line(line: &str) {
    use std::io::Write;
    let mut g = LOG.lock().unwrap_or_else(|e| e.into_inner());
    // every line goes to stdout too (under the lock, so lines stay in order); a closed stdout is ignored, never fatal
    let _ = writeln!(std::io::stdout(), "{}", line);
    let Some(l) = g.as_mut() else { return };
    if l.size + line.len() as u64 + 1 > LOG_MAX {
        l.file = None;
        for i in (1..3).rev() {
            let _ = std::fs::rename(format!("{}.{}", l.path, i), format!("{}.{}", l.path, i + 1));
        }
        let _ = std::fs::rename(&l.path, format!("{}.1", l.path));
        l.size = 0;
    }
    if l.file.is_none() {
        l.file = std::fs::OpenOptions::new().create(true).append(true).open(&l.path).ok();
    }
    match l.file.as_mut().map(|f| writeln!(f, "{}", line)) {
        Some(Ok(())) => l.size += line.len() as u64 + 1,
        _ => l.file = None, // the data folder is unwritable: the line is still in the container log
    }
}

/// Bitcoin addresses are 25-90 plain ASCII letters and digits (cheap check before asking the node).
pub fn address_plausible(a: &str) -> bool {
    (25..=90).contains(&a.len()) && a.chars().all(|c| c.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    #[test]
    fn hash_diff_genesis_and_diff1() {
        // a hash exactly at the difficulty-1 target has difficulty 1
        let mut h = [0u8; 32];
        h[26] = 0xff;
        h[27] = 0xff;
        assert!((super::hash_diff(&h) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn unhex_matches_the_hex_crate() {
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(super::unhex(&hex::encode(&all)).unwrap(), all);
        assert_eq!(super::unhex("ABcd0f").unwrap(), vec![0xab, 0xcd, 0x0f]);
        assert_eq!(super::unhex("").unwrap(), Vec::<u8>::new());
        assert!(super::unhex("abc").is_none());
        assert!(super::unhex("zz").is_none());
        assert!(super::unhex("0g").is_none());
    }

    #[test]
    fn stamp_shape() {
        let s = super::stamp();
        assert_eq!(s.len(), 23);
        assert!(s.starts_with("20"));
    }

    #[test]
    fn plausible_addresses() {
        assert!(super::address_plausible("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
        assert!(!super::address_plausible("Bitaxe1"));
        assert!(!super::address_plausible("bc1q-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    }

    use super::*;

    #[test]
    fn formatting_matches_python() {
        assert_eq!(sig3(123456.0), 123000.0);
        assert_eq!(sig3(0.0012345), 0.00123);
        assert_eq!(fmt_diff(5200.0), "5.2K");
        assert_eq!(fmt_diff(3.142e12), "3.14T");
        assert_eq!(fmt_diff(256.0), "256");
        assert_eq!(commas(1234567), "1,234,567");
        assert_eq!(commas(12), "12");
        assert_eq!(median([5u64, 1, 9, 3].iter()), Some(5));
        assert!((target_diff(&bits_to_target(0x1d00ffff)) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn script_num_edges() {
        let got: Vec<String> = [1u64, 127, 128, 255, 256, 32768].iter().map(|&x| hex::encode(script_num(x))).collect();
        assert_eq!(got, ["01", "7f", "8000", "ff00", "0001", "008000"]);
    }

    #[test]
    fn varint_sizes() {
        assert_eq!(varint(0xfc), vec![0xfc]);
        assert_eq!(varint(0xfd), vec![0xfd, 0xfd, 0x00]);
        assert_eq!(varint(0x1_0000), vec![0xfe, 0, 0, 1, 0]);
    }

    #[test]
    fn genesis_header_meets_its_target() {
        let hdr = hex::decode(concat!(
            "01000000", "0000000000000000000000000000000000000000000000000000000000000000",
            "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
            "29ab5f49", "ffff001d", "1dac2b7c")).unwrap();
        let h = sha256d(&hdr);
        let mut disp = h;
        disp.reverse();
        assert_eq!(hex::encode(disp), "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
        assert!(hash_meets(&h, &bits_to_target(0x1d00ffff)));
    }
}
