#!/usr/bin/env python3
"""Load test: many fake miners on a spare Solo45 Core, on mainnet templates.

Start Core on spare ports with a tiny difficulty and a high per-address limit, e.g.
  SOLO45_STRATUM_PORT=3347 SOLO45_API_PORT=3387 SOLO45_SV2_PORT=34264 SOLO45_MAX_CONNS_PER_IP=500
  SOLO45_START_DIFF=0.000001 SOLO45_MIN_DIFF=0.000001 ... solo45-core serve
then: python3 tools/load_test.py <minutes> <v1 miners> <sv2 miners> <core pid> <core log> <sv2 authority key>

V1 miners are threads that subscribe, authorize, keep up with every job and send a share about every 10 s; SV2
miners are `solo45-core sv2-miner` processes (standard channels) sending a share about every 10 s. Every 10 s the
test samples Core's memory and CPU; at the end it reports those, how long Core took to get each job out to everyone
(its own log lines), the Stratum V2 new-block timing, accepted and rejected shares, and whether every miner was
still connected and sending.
"""
import json, os, random, socket, subprocess, sys, threading, time, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
MINUTES, N1, N2, PID, LOG, KEY = float(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5], sys.argv[6]
sys.argv = [sys.argv[0], "127.0.0.1", "3347"]
import test_miner as tm  # noqa: E402

ADDR = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
API = "http://127.0.0.1:3387/api"
stop = threading.Event()
stats = {"ok": 0, "bad": 0, "errors": 0}
lock = threading.Lock()


def v1_miner(i):
    try:
        c = tm.Client()
        en1 = bytes.fromhex(c.call("mining.subscribe", [f"load/{i}"])["result"][1])
        user = f"{ADDR}.load{i:03d}"
        c.call("mining.authorize", [user, "x"])
        time.sleep(random.uniform(0, 10))  # spread the shares out
        n = 0
        while not stop.is_set():
            job = c.job or (c.wait_note("mining.notify", 5) and c.job)
            if not job or not c.diff:
                c.wait_note("mining.set_difficulty", 1)
                continue
            n += 1
            en2 = (i * 1_000_000 + n).to_bytes(8, "big")
            ntime, nonce = tm.mine(job, en1, en2, int(job[5], 16), c.diff)
            r = c.call("mining.submit", [user, job[0], en2.hex(), "%08x" % ntime, "%08x" % nonce])
            with lock:
                stats["ok" if r.get("result") is True else "bad"] += 1
            end = time.time() + 10
            while time.time() < end and not stop.is_set():
                c.wait_note("mining.notify", 1)  # keep reading the pool's messages
    except Exception as e:
        with lock:
            stats["errors"] += 1
        print("V1 miner", i, "stopped:", e, flush=True)


def proc_stat():
    """Core's resident memory (MB) and CPU seconds so far."""
    with open(f"/proc/{PID}/status") as f:
        rss = next(int(l.split()[1]) for l in f if l.startswith("VmRSS")) / 1024
    with open(f"/proc/{PID}/stat") as f:
        parts = f.read().rsplit(")", 1)[1].split()
    cpu = (int(parts[11]) + int(parts[12])) / os.sysconf("SC_CLK_TCK")
    return rss, cpu


def main():
    log_start = os.path.getsize(LOG)
    rss0, cpu0 = proc_stat()
    t0 = time.time()
    threads = [threading.Thread(target=v1_miner, args=(i,), daemon=True) for i in range(N1)]
    for t in threads:
        t.start()
        time.sleep(0.02)
    core = os.path.expanduser("~/solo45-core/target/release/solo45-core")
    shares_each = int(MINUTES * 6) + 5
    procs = [subprocess.Popen([core, "sv2-miner", "127.0.0.1:34264", KEY, f"{ADDR}.sv2load{i:02d}", str(shares_each), "10"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for i in range(N2)]
    samples = []
    end = t0 + MINUTES * 60
    while time.time() < end:
        time.sleep(10)
        rss, cpu = proc_stat()
        samples.append((time.time() - t0, rss, cpu))
    d = json.load(urllib.request.urlopen(API, timeout=10))
    stop.set()
    for p in procs:
        p.terminate()
    workers = d["workers"]
    v1 = [w for w in workers if not w["agent"].startswith("sv2")]
    sv2 = [w for w in workers if w["agent"].startswith("sv2")]
    now = d["now"]
    quiet = [w["name"] for w in workers if now - (w["last_share"] or 0) > 60]
    with open(LOG) as f:
        f.seek(log_start)
        lines = f.read().splitlines()
    sends = []
    for l in lines:
        if "sent to " in l and " workers in " in l:
            try:
                n = int(l.split("sent to ")[1].split()[0])
                ms = int(l.split(" workers in ")[1].split()[0])
                sends.append((n, ms, "new-block" in l))
            except (ValueError, IndexError):
                pass
    warn = [l for l in lines if " WARNING " in l or " ERROR " in l]
    dur = samples[-1][0]
    cpu_pct = 100 * (samples[-1][2] - cpu0) / dur
    print(f"\n== {N1} V1 + {N2} SV2 miners for {dur / 60:.1f} min")
    print(f"connected at the end: {len(v1)} V1, {len(sv2)} SV2; quiet for over 60 s: {len(quiet)} {quiet[:5]}")
    print(f"shares from the V1 test miners: {stats['ok']} accepted, {stats['bad']} refused, {stats['errors']} miners stopped")
    print(f"Core counted: {d['pool']['accepted']} accepted, rejected {d['pool']['rejected']}")
    print(f"Core memory: {rss0:.0f} MB before, {min(s[1] for s in samples):.0f}-{max(s[1] for s in samples):.0f} MB during")
    print(f"Core CPU: {cpu_pct:.1f}% of one core on average ({samples[-1][2] - cpu0:.1f} s over {dur:.0f} s)")
    if sends:
        full = [ms for n, ms, nb in sends if n >= N1]
        print(f"jobs sent to everyone: {len(full)} times, {min(full) if full else '-'}-{max(full) if full else '-'} ms "
              f"(median {sorted(full)[len(full) // 2] if full else '-'} ms); new blocks: {[ms for n, ms, nb in sends if nb]}")
    print("Stratum V2 new-block timing:", d["pool"].get("sv2_switch"))
    print(f"warnings/errors in Core's log: {len(warn)}", warn[:3])


if __name__ == "__main__":
    main()
