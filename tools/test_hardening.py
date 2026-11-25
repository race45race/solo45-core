#!/usr/bin/env python3
"""Four hardening fixes, against the private regtest node (tools/regtest.sh start). The pool runs on its own ports
behind a stand-in that can make chosen node calls fail the way a node that is down, starting or too busy does.

A. Stratum V1 payout change: a block found on the job the miner already had still counts and pays the address that
   job carried; the next job pays the new address.
B. A miner with its own address in the username is refused while the node can't check that address (it is not
   quietly paid to the payout address); once the node answers it is accepted and pays its own address.
C. A found block the node can't take is sent again for as long as it takes: after SOLO45_SUBMIT_SLOWER_AFTER_S the
   tries drop to one every 30 s, and it stays "sending" in blocks_found.jsonl until the node answers.
D. state.json: a backup copy (state.json.bak) is kept; an unreadable state.json is set aside and the backup used;
   with neither readable the pool starts like a new install and says so.
  python3 tools/test_hardening.py
"""
import glob, http.server, json, os, signal, struct, subprocess, sys, threading, time, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
NODE_PORT, PROXY_PORT, STRATUM, API = 18543, 18551, 3354, 3394
sys.argv = [sys.argv[0], "127.0.0.1", str(STRATUM)]
import test_miner as tm  # noqa: E402

CORE = os.path.expanduser("~/solo45-core/target/release/solo45-core")
DATA = os.path.expanduser("~/solo45-test/core-hardening")
BIN = os.path.expanduser("~/solo45-test/bitcoin-32.1/bin")
NODE_DIR = os.path.expanduser("~/solo45-test/regtest-node")
check = tm.check
failing = set()   # node calls the stand-in answers with "503 busy" instead of passing on
submits = []      # when each submitblock call arrived


class Proxy(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        req = json.loads(body)
        if req.get("method") == "submitblock":
            submits.append(time.time())
        if req.get("method") in failing:
            status, out = 503, b"Work queue depth exceeded"
        else:
            r = urllib.request.Request(f"http://127.0.0.1:{NODE_PORT}/", body,
                                       {"Authorization": self.headers["Authorization"], "Content-Type": "text/plain"})
            try:
                with urllib.request.urlopen(r, timeout=60) as resp:
                    status, out = resp.status, resp.read()
            except urllib.error.HTTPError as e:
                status, out = e.code, e.read()
            except Exception as e:  # the node itself can't be reached
                status, out = 503, str(e).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


def cli(*a):
    return subprocess.run([f"{BIN}/bitcoin-cli", "-regtest", f"-datadir={NODE_DIR}", "-rpcport=18543", *a],
                          capture_output=True, text=True, timeout=30).stdout.strip()


def spk_of(addr):
    return json.loads(cli("getaddressinfo", addr))["scriptPubKey"]


def api(path="/api", data=None):
    r = urllib.request.Request(f"http://127.0.0.1:{API}{path}", None if data is None else json.dumps(data).encode())
    return json.load(urllib.request.urlopen(r, timeout=15))


def target_of(nbits_hex):
    b = int(nbits_hex, 16)
    return (b & 0xFFFFFF) << (8 * ((b >> 24) - 3))


def find_block(c, job, en1, n):
    target = min(target_of(job[6]), int(tm.DIFF1 / c.diff))
    en2 = n.to_bytes(8, "big")
    ntime = int(job[7], 16)
    pre = tm.header_for(job, en1, en2, ntime, 0, int(job[5], 16))[:76]
    for nonce in range(1 << 32):
        h = tm.sha256d(pre + struct.pack("<I", nonce))
        if int.from_bytes(h, "little") <= target:
            return en2, ntime, nonce, h[::-1].hex()


def job_height(job):
    cb1 = bytes.fromhex(job[2])
    return int.from_bytes(cb1[43:43 + cb1[42]], "little")


def next_job(c, after_height, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        if c.job and job_height(c.job) > after_height:
            return c.job
        c.wait_note("mining.notify", 1)
    return None


def wait_tip(bhash, timeout):
    end = time.time() + timeout
    while time.time() < end:
        if cli("getbestblockhash") == bhash:
            return True
        time.sleep(0.3)
    return False


def coinbase_pays(block_hash, spk):
    out = cli("getblock", block_hash, "2")
    if not out:
        return False  # the node doesn't have that block
    return any(o["scriptPubKey"]["hex"] == spk for o in json.loads(out)["tx"][0]["vout"])


def saved_address(name):
    """The payout address in a saved state file, or None when the file is missing or unreadable."""
    try:
        return json.load(open(os.path.join(DATA, name)))["settings"]["default_address"]
    except Exception:
        return None


def entries():
    p = os.path.join(DATA, "blocks_found.jsonl")
    return [json.loads(l) for l in open(p)] if os.path.exists(p) else []


def log_text():
    return open(os.path.join(DATA, "pool.log")).read()


def start_core(env):
    p = subprocess.Popen([CORE, "serve"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(40):  # until its API answers
        time.sleep(0.25)
        try:
            api()
            break
        except Exception:
            pass
    return p


def stop_core(core):
    core.send_signal(signal.SIGTERM)
    core.wait(40)


def main():
    os.makedirs(DATA, exist_ok=True)
    for f in ("state.json", "state.json.bak", "pool.log", "blocks_found.jsonl", "history.json", "history-miners.json"):
        p = os.path.join(DATA, f)
        if os.path.exists(p):
            os.replace(p, p + ".old")
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), Proxy)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    addr_a = open(os.path.expanduser("~/solo45-test/core-regtest/address.txt")).read().strip()
    cli("loadwallet", "core-test")  # an earlier test may have restarted the node, which starts without its wallet
    addr_b, addr_c, addr_d = (cli("getnewaddress", "", "bech32") for _ in range(3))
    if not (addr_b and addr_c and addr_d):
        print("FAIL the test node's wallet gave no new addresses (run: bash tools/regtest.sh start)")
        return 1
    spk_a, spk_b, spk_c = spk_of(addr_a), spk_of(addr_b), spk_of(addr_c)
    env = dict(os.environ, SOLO45_STRATUM_PORT=str(STRATUM), SOLO45_API_PORT=str(API), SOLO45_DATA_DIR=DATA,
               SOLO45_LOG_FILE=os.path.join(DATA, "pool.log"), SOLO45_DEFAULT_ADDRESS=addr_a,
               SOLO45_START_DIFF="0.00001", SOLO45_MIN_DIFF="0.00001", SOLO45_SUBMIT_SLOWER_AFTER_S="8",
               BITCOIN_RPC_URL=f"http://127.0.0.1:{PROXY_PORT}/", BITCOIN_RPC_COOKIE=os.path.join(NODE_DIR, "regtest/.cookie"))
    core = start_core(env)
    try:
        # ---- A: a payout change while a V1 miner is on an older job
        c = tm.Client()
        en1 = bytes.fromhex(c.call("mining.subscribe", ["hardening-test/1.0"])["result"][1])
        c.call("mining.authorize", ["plain.w1", "x"])
        height = int(cli("getblockcount"))
        j1 = next_job(c, height - 1)
        check("A: the miner's job pays the payout address", j1 is not None and spk_a in j1[3])
        r = api("/api/payout", {"address": addr_b})
        check("A: payout address changed on the pool", r.get("ok") is True and api()["pool"]["default_address"] == addr_b, r)
        en2, ntime, nonce, bhash = find_block(c, j1, en1, 1)  # still hashing the job it had: its coinbase pays the old address
        r = tm.submit(c, j1, en2, ntime, nonce)
        check("A: a block on the job the miner already had is accepted (not 'low difficulty')", r["result"] is True, r)
        check("A: ... and the node took it", wait_tip(bhash, 10), bhash[:16])
        check("A: ... and it pays the address that job carried", coinbase_pays(bhash, spk_a))
        time.sleep(1)
        rec = [e for e in entries() if e["hash"] == bhash]
        check("A: the block's record names that address", rec and rec[-1]["address"] == addr_a and rec[-1]["result"] is None,
              [(e["address"][-8:], e["result"]) for e in rec])
        j2 = next_job(c, height + 1)
        check("A: the next job pays the new address", j2 is not None and spk_b in j2[3] and spk_a not in j2[3])
        en2, ntime, nonce, bhash2 = find_block(c, j2, en1, 2)
        r = tm.submit(c, j2, en2, ntime, nonce)
        check("A: a block on the new job pays the new address", r["result"] is True and wait_tip(bhash2, 10) and coinbase_pays(bhash2, spk_b))
        check("A: state.json and its backup state.json.bak are both saved",
              saved_address("state.json") == addr_b and saved_address("state.json.bak") == addr_b)

        # ---- B: the node can't check a miner's own address
        r = api("/api/settings", {"force_default_address": False})
        check("B: 'always pay my address' switched off", r.get("force_default_address") is False, r)
        failing.add("validateaddress")
        c2 = tm.Client()
        c2.call("mining.subscribe", ["hardening-test/1.0"])
        r = c2.call("mining.authorize", [addr_c + ".w2", "x"])
        check("B: a miner with its own address is refused while the node can't check it", r["result"] is False, r)
        check("B: ... and the log says why", "the node can't check the address in its username" in log_text())
        c3 = tm.Client()
        c3.call("mining.subscribe", ["hardening-test/1.0"])
        r = c3.call("mining.authorize", ["w3", "x"])
        j = c3.job or c3.wait_note("mining.notify", 5) and c3.job
        check("B: a miner with a plain name still connects and pays the payout address", r["result"] is True and j and spk_b in j[3], r)
        failing.clear()
        r = c2.call("mining.authorize", [addr_c + ".w2", "x"])
        j = c2.job or c2.wait_note("mining.notify", 5) and c2.job
        check("B: once the node answers, the same miner is accepted and pays its own address",
              r["result"] is True and j and spk_c in j[3] and spk_b not in j[3], r)
        r = api("/api/settings", {"force_default_address": True})
        failing.add("validateaddress")
        c4 = tm.Client()
        c4.call("mining.subscribe", ["hardening-test/1.0"])
        r = c4.call("mining.authorize", [addr_d + ".w4", "x"])
        j = c4.job or c4.wait_note("mining.notify", 5) and c4.job
        check("B: with 'always pay my address' on, no check is needed: the miner connects and pays the payout address",
              r["result"] is True and j and spk_b in j[3], r)
        failing.clear()

        # ---- C: the node can't take a found block for a long time
        height = int(cli("getblockcount"))
        job = next_job(c, height)
        en2, ntime, nonce, bhash3 = find_block(c, job, en1, 3)
        failing.add("submitblock")
        del submits[:]
        r = tm.submit(c, job, en2, ntime, nonce)
        check("C: the block share is accepted while the node can't take blocks", r["result"] is True, r)
        t0 = time.time()
        time.sleep(44)  # past the 6 quick tries and past SOLO45_SUBMIT_SLOWER_AFTER_S (8 s here, 10 minutes normally)
        mine = [e for e in entries() if e["hash"] == bhash3]
        check("C: long after the quick tries the block is still 'sending' (never given up)",
              [e["result"] for e in mine] == ["sending"] and cli("getbestblockhash") != bhash3, [e["result"] for e in mine])
        gaps = [b - a for a, b in zip(submits, submits[1:])]
        check("C: 6 quick tries, then one about every 30 s", len(submits) >= 7 and max(gaps) > 25 and min(gaps) < 4,
              [round(g) for g in gaps])
        failing.clear()
        check("C: once the node takes blocks again, ours becomes its tip", wait_tip(bhash3, 45), f"{time.time() - t0:.0f} s after the find")
        time.sleep(1)
        mine = [e for e in entries() if e["hash"] == bhash3]
        log = log_text()
        check("C: recorded as accepted, and nothing in the log about giving up",
              [e["result"] for e in mine] == ["sending", None] and f"submitblock {bhash3}: accepted by the node" in log
              and "giving up" not in log, [e["result"] for e in mine])
        check("C: the pool is still running", core.poll() is None)

        # ---- D: state.json can't be read at start
        stop_core(core)
        path = os.path.join(DATA, "state.json")
        good = open(path).read()
        check("D: a clean stop leaves a readable state.json", saved_address("state.json") == addr_b)
        bad_before = set(glob.glob(path + ".bad-*"))
        open(path, "w").write(good[:len(good) // 2])  # cut short, as after a power cut
        core = start_core(env)
        s = api()["pool"]
        check("D: an unreadable state.json: the backup's payout address and switch are used",
              s["default_address"] == addr_b and s["force_default_address"] is True and s["needs_setup"] is False,
              (s["default_address"][-8:], s["force_default_address"]))
        log = log_text()
        check("D: ... an ERROR in the log says so", " ERROR state.json can't be read" in log and "using its backup state.json.bak" in log)
        check("D: ... and the unreadable file is kept aside", len(set(glob.glob(path + ".bad-*")) - bad_before) == 1)
        stop_core(core)
        check("D: the next save writes a readable state.json again", saved_address("state.json") == addr_b)
        for f in (path, path + ".bak"):
            open(f, "w").write("not json")
        core = start_core(env)
        s = api()["pool"]
        check("D: neither file readable: starts like a new install (the environment's address, 'always pay my address' on)",
              s["default_address"] == addr_a and s["force_default_address"] is True, (s["default_address"][-8:], s["force_default_address"]))
        check("D: ... with an ERROR that names it", "and neither can its backup" in log_text() and "starting like a new install" in log_text())
        c5 = tm.Client()
        c5.call("mining.subscribe", ["hardening-test/1.0"])
        r = c5.call("mining.authorize", ["w5", "x"])
        check("D: the pool gives miners work after that start", r["result"] is True and (c5.job or c5.wait_note("mining.notify", 10)))
        check("D: the pool is still running", core.poll() is None)
    finally:
        failing.clear()
        if core.poll() is None:
            core.terminate()
            core.wait(40)
        srv.shutdown()
    passed = sum(1 for _, ok in tm.results if ok)
    print(f"\n{passed}/{len(tm.results)} checks passed")
    return 0 if passed == len(tm.results) else 1


if __name__ == "__main__":
    sys.exit(main())
