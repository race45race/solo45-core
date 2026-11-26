#!/usr/bin/env python3
"""Soak test: Solo45 SV2 under an hour of reconnect storms, bad shares and junk, on the private regtest chain.

  python3 tools/soak_test.py <minutes>        (needs the regtest node: bash tools/regtest.sh start)

Starts its own Core on spare ports (V1 3357, API 3397, SV2 34267; data ~/solo45-test/core-soak) and runs:
  steady miners  8 SV2 standard channels and 4 V1 miners, a share every ~20 s each (on regtest every share is a block)
  SV2 storm      ~12 short connections at a time: open a channel and drop the TCP connection 1-8 s later (some mine 1 share)
  V1 storm       connections that send a bad job id, a duplicate, a low-difficulty share and a junk line, then drop
  junk           random bytes on the SV2 port; silent sockets that never finish the encrypted handshake
  no channel     3 SV2 connections that set up but never open a channel: the pool must close them after ~2 min
  silent channel 2 SV2 channels that never send a share: the pool must close them after ~15 min (runs >= 20 min only)
Every 10 s: Core's memory (RSS), open files and threads. At the end the storm stops and the test checks that Core is
still up, memory settled, every steady miner is still connected and sending, the connections went back to the steady
ones, the closures above happened in time, and the log has no ERROR/CRITICAL other than found blocks.
"""
import json, os, random, signal, socket, subprocess, sys, threading, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
MINUTES = float(sys.argv[1]) if len(sys.argv) > 1 else 60
# SOAK_NO_BLOCKS=1: nothing mines (on regtest every share is a block), storm names from a pool of 50: isolates the
# connection storm itself from the per-block and per-name records the pool keeps on purpose
NO_BLOCKS = os.environ.get("SOAK_NO_BLOCKS") == "1"
NAMES = 50 if NO_BLOCKS else 1000
# SOAK_PORTS="v1,api,sv2" and SOAK_TAG let two runs go side by side; SOAK_SERVER_BIN: the pool binary to test
V1, API, SV2 = (int(x) for x in os.environ.get("SOAK_PORTS", "3357,3397,34267").split(","))
sys.argv = [sys.argv[0], "127.0.0.1", str(V1)]
import test_miner as tm  # noqa: E402

HOME = os.path.expanduser("~")
CORE = os.path.join(HOME, "solo45-core/target/release/solo45-core")
DATA = os.path.join(HOME, "solo45-test/core-soak" + os.environ.get("SOAK_TAG", ""))
SERVER = os.environ.get("SOAK_SERVER_BIN") or CORE
NODE = os.path.join(HOME, "solo45-test/regtest-node")
ADDR = open(os.path.join(HOME, "solo45-test/core-regtest/address.txt")).read().strip()
stop_storm, stop_all = threading.Event(), threading.Event()
lock = threading.Lock()
count = {"sv2_storm": 0, "v1_storm": 0, "junk": 0, "v1_shares": 0, "v1_errors": 0}
results = []


def check(name, ok, detail=""):
    results.append(ok)
    print("%s  %s %s" % ("PASS" if ok else "FAIL", name, detail), flush=True)


def bump(k, n=1):
    with lock:
        count[k] += n


def api_state():
    with urllib.request.urlopen(f"http://127.0.0.1:{API}/api/state", timeout=10) as r:
        return json.load(r)


def sv2_proc(user, shares, pause, secs, env=None, out=subprocess.DEVNULL):
    return subprocess.Popen(["timeout", str(secs), CORE, "sv2-miner", f"127.0.0.1:{SV2}", PUB, user, str(shares), str(pause)],
                            stdout=out, stderr=subprocess.STDOUT, env=dict(os.environ, **(env or {})), start_new_session=True)


def kill(p):
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def v1_steady(i):
    while not stop_all.is_set():
        try:
            c = tm.Client()
            sub = c.call("mining.subscribe", [f"soak/{i}"])["result"]
            en1, size = bytes.fromhex(sub[1]), int(sub[2])
            c.call("mining.authorize", [f"{ADDR}.v1steady{i}", "x"])
            n = 0
            while NO_BLOCKS and not stop_all.is_set():
                c.wait_note("mining.notify", 5)  # stay connected, never mine
            while not stop_all.is_set():
                job = c.job or (c.wait_note("mining.notify", 5) and c.job)
                if not job or not c.diff:
                    c.wait_note("mining.set_difficulty", 1)
                    continue
                n += 1
                en2 = n.to_bytes(size, "big")
                ntime, nonce = tm.mine(job, en1, en2, int(job[5], 16), c.diff)
                r = tm.submit(c, job, en2, ntime, nonce)
                bump("v1_shares" if r.get("result") else "v1_errors")
                end = time.time() + random.uniform(15, 25)
                while time.time() < end and not stop_all.is_set():
                    c.wait_note("mining.notify", 1)
        except Exception:
            bump("v1_errors")
            time.sleep(2)


def not_a_block(job, en1, en2, ntime):
    """A nonce whose hash misses even regtest's block target (about half of all hashes beat it): a plain bad share."""
    ver = int(job[5], 16)
    while True:
        n = random.getrandbits(32)
        h = tm.sha256d(tm.header_for(job, en1, en2, ntime, n, ver))
        if int.from_bytes(h, "little") >= 1 << 255:
            return n


def v1_storm():
    while not stop_storm.is_set():
        try:
            c = tm.Client()
            sub = c.call("mining.subscribe", ["storm"])["result"]
            en1, size = bytes.fromhex(sub[1]), int(sub[2])
            c.call("mining.authorize", [f"{ADDR}.storm{random.randrange(NAMES)}", "x"])
            job = c.job or (c.wait_note("mining.notify", 5) and c.job)
            if job:
                en2 = (1).to_bytes(size, "big")
                nt = int(job[7], 16)
                tm.submit(c, job, en2, nt, 0, job_id="deadbeef")                        # unknown job
                tm.submit(c, job, en2, nt, not_a_block(job, en1, en2, nt))               # low difficulty, never a block
            if job and not NO_BLOCKS:
                ntime, nonce = tm.mine(job, en1, en2, int(job[5], 16), c.diff or 1e-5)
                tm.submit(c, job, en2, ntime, nonce)
                tm.submit(c, job, en2, ntime, nonce)                                    # duplicate
            c.send_raw(b"{not json at all\n" + os.urandom(64) + b"\n")
            c.s.close()  # drop without a goodbye
            bump("v1_storm")
        except Exception:
            pass
        time.sleep(random.uniform(0.2, 1.0))


def junk():
    while not stop_storm.is_set():
        try:
            s = socket.create_connection(("127.0.0.1", SV2), timeout=5)
            if random.random() < 0.5:
                s.sendall(os.urandom(random.randint(1, 4000)))
            else:
                time.sleep(random.uniform(1, 15))  # never finishes the handshake
            s.close()
            bump("junk")
        except Exception:
            pass
        time.sleep(random.uniform(0.5, 2))


def sv2_storm():
    live = []
    while not stop_storm.is_set():
        live = [p for p in live if p.poll() is None]
        while len(live) < 12:
            shares = 1 if random.random() < 0.15 and not NO_BLOCKS else 0
            live.append(sv2_proc(f"storm{random.randrange(NAMES)}", shares, 0, random.randint(1, 8)))
            bump("sv2_storm")
        time.sleep(0.3)
    for p in live:
        kill(p)


def rss_fds_threads(pid):
    rss = thr = 0
    for line in open(f"/proc/{pid}/status"):
        if line.startswith("VmRSS:"):
            rss = int(line.split()[1]) // 1024
        if line.startswith("Threads:"):
            thr = int(line.split()[1])
    return rss, len(os.listdir(f"/proc/{pid}/fd")), thr


def closed_after(p, started):
    """Seconds until the process ended (None if still running)."""
    return p.ended - started if getattr(p, "ended", None) else None


def main():
    global PUB
    for port in (V1, API, SV2):
        s = socket.socket()
        if s.connect_ex(("127.0.0.1", port)) == 0:
            sys.exit(f"port {port} is busy: a soak test or another stand is already running")
        s.close()
    os.makedirs(DATA, exist_ok=True)
    for f in ("state.json", "state.json.bak", "pool.log", "blocks_found.jsonl", "history.json"):
        p = os.path.join(DATA, f)
        if os.path.exists(p):
            os.replace(p, p + ".old")
    env = dict(os.environ, SOLO45_STRATUM_PORT=str(V1), SOLO45_API_PORT=str(API), SOLO45_SV2_PORT=str(SV2),
               SOLO45_DATA_DIR=DATA, SOLO45_LOG_FILE=os.path.join(DATA, "pool.log"), SOLO45_DEFAULT_ADDRESS=ADDR,
               SOLO45_START_DIFF="0.00001", SOLO45_MIN_DIFF="0.00001", SOLO45_MAX_CONNS_PER_IP="500",
               SOLO45_MINER_READINGS="0",
               BITCOIN_RPC_URL="http://127.0.0.1:18543/", BITCOIN_RPC_COOKIE=os.path.join(NODE, "regtest/.cookie"),
               BITCOIN_ZMQ_HASHBLOCK="tcp://127.0.0.1:28544")
    core = subprocess.Popen([SERVER, "serve"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(60):
        if os.path.exists(os.path.join(DATA, "sv2-authority.json")):
            try:
                api_state()
                break
            except Exception:
                pass
        time.sleep(0.5)
    PUB = json.load(open(os.path.join(DATA, "sv2-authority.json")))["public"]
    t0 = time.time()
    print(f"soak test {MINUTES:g} min, Core pid {core.pid}, started {time.strftime('%H:%M:%S', time.gmtime(t0))} UTC", flush=True)
    # no steady miners without blocks: a channel that never sends a share is closed after 15 min (on purpose)
    NS, NV = (0, 0) if NO_BLOCKS else (8, 4)
    steady = [sv2_proc(f"steady{i}", 1_000_000, 20, int(MINUTES * 60 + 300)) for i in range(NS)]
    threads = [threading.Thread(target=v1_steady, args=(i,), daemon=True) for i in range(NV)]
    threads += [threading.Thread(target=f, daemon=True) for f in (v1_storm, v1_storm, junk, junk, sv2_storm)]
    for t in threads:
        t.start()
    no_chan = [sv2_proc(f"nochan{i}", 1, 0, 600, {"SOLO45_TEST_NO_CHANNEL": "1"}) for i in range(3)]
    nc_start = time.time()
    silent, sl_start = [], None
    if MINUTES >= 20:
        silent = [sv2_proc(f"silent{i}", 0, 0, 1500) for i in range(2)]
        sl_start = time.time()
    samples = []  # (t, rss MB, fds, threads, workers)
    storm_end = t0 + MINUTES * 60
    while time.time() < storm_end:
        time.sleep(10)
        for p in no_chan + silent:
            if p.poll() is not None and not getattr(p, "ended", None):
                p.ended = time.time()
        if core.poll() is not None:
            break
        try:
            w = len(api_state().get("workers") or [])
        except Exception:
            w = -1
        samples.append((time.time() - t0,) + rss_fds_threads(core.pid) + (w,))
        if len(samples) % 30 == 0:
            s = samples[-1]
            with lock:
                c = dict(count)
            print(f"{s[0] / 60:5.1f} min: RSS {s[1]} MB, files {s[2]}, threads {s[3]}, workers {s[4]}, {c}", flush=True)
    stop_storm.set()
    alive = core.poll() is None
    time.sleep(45)  # storm connections close; give the pool a moment
    for p in no_chan + silent:
        if p.poll() is not None and not getattr(p, "ended", None):
            p.ended = time.time()
    end = rss_fds_threads(core.pid) if alive else (0, 0, 0)
    st = api_state() if alive else {}
    names = sorted(str(w.get("name", "")).split(".")[-1] for w in st.get("workers") or [])
    log = open(os.path.join(DATA, "pool.log"), errors="replace").read().splitlines()
    bad = [l for l in log if (" ERROR " in l or " CRITICAL " in l)
           and "BLOCK FOUND" not in l and "submitblock" not in l]
    # memory: average of minutes 5-10 against the last 5 minutes of the storm
    early = [s[1] for s in samples if 300 <= s[0] <= 600] or [s[1] for s in samples[:30]]
    late = [s[1] for s in samples if s[0] >= MINUTES * 60 - 300] or [s[1] for s in samples[-30:]]
    e_avg, l_avg = sum(early) / max(1, len(early)), sum(late) / max(1, len(late))
    with lock:
        c = dict(count)
    print(f"storm totals: {c}; RSS early {e_avg:.0f} MB, late {l_avg:.0f} MB, max {max(s[1] for s in samples)} MB; "
          f"after: RSS {end[0]} MB, files {end[1]}, threads {end[2]}", flush=True)
    check("Core ran through the whole storm", alive)
    check("memory settled (last 5 min within 15% + 10 MB of minutes 5-10)", l_avg <= e_avg * 1.15 + 10, f"({e_avg:.0f} -> {l_avg:.0f} MB)")
    want = sorted([f"steady{i}" for i in range(NS)] + [f"v1steady{i}" for i in range(NV)])
    have = [n for n in names if n in want]
    check("every steady miner is still connected", have == want, f"({len(have)}/{len(want)}; workers now: {len(names)})")
    check("the storm's connections are gone: only the steady miners (and silent ones still in time) remain",
          set(names) <= set(want) | {f"silent{i}" for i in range(2)}, f"({[n for n in names if n not in want]})")
    v1_ok = NO_BLOCKS or c["v1_shares"] > 4 * MINUTES * 60 / 30
    check("steady V1 miners kept getting shares accepted", v1_ok, f"({c['v1_shares']} accepted, {c['v1_errors']} errors)")
    nc = [closed_after(p, nc_start) for p in no_chan]
    check("SV2 connections without a channel closed after ~2 min", all(x is not None and 100 <= x <= 200 for x in nc), f"({nc})")
    if silent:
        sl = [closed_after(p, sl_start) for p in silent]
        check("SV2 channels that never send closed after ~15 min", all(x is not None and 880 <= x <= 990 for x in sl), f"({sl})")
    check("no ERROR/CRITICAL in the log other than found blocks", not bad, f"({len(bad)}: {bad[:3]})")
    stop_all.set()
    for p in steady + no_chan + silent:
        if p.poll() is None:
            kill(p)
    core.terminate()
    core.wait(15)
    print(f"\n{sum(results)}/{len(results)} checks passed", flush=True)
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
