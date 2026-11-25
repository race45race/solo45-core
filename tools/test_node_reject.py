#!/usr/bin/env python3
"""Solo45 Core when the node REJECTS a found block, against the private regtest node (tools/regtest.sh start).

A stand-in between Core and the node forwards every call but answers submitblock with the node's own kind of
verdict ("bad-txnmrklroot") instead of passing the block on. Expected: Core sends the block once (a verdict is
final: no retries), saves it as "sending" and then with the verdict, shows it in the API, keeps the node's chain
unchanged, and goes on giving miners work.
  python3 tools/test_node_reject.py
"""
import http.server, json, os, struct, subprocess, sys, threading, time, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
NODE_PORT, PROXY_PORT, STRATUM, API = 18543, 18550, 3349, 3389
sys.argv = [sys.argv[0], "127.0.0.1", str(STRATUM)]
import test_miner as tm  # noqa: E402

CORE = os.path.expanduser("~/solo45-core/target/release/solo45-core")
DATA = os.path.expanduser("~/solo45-test/core-reject")
NODE_DIR = os.path.expanduser("~/solo45-test/regtest-node")
VERDICT = "bad-txnmrklroot"
submits = []
check = tm.check


class Proxy(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        req = json.loads(body)
        if req.get("method") == "submitblock":
            submits.append(time.time())
            status, out = 200, json.dumps({"result": VERDICT, "error": None, "id": req.get("id")}).encode()
        else:
            r = urllib.request.Request(f"http://127.0.0.1:{NODE_PORT}/", body,
                                       {"Authorization": self.headers["Authorization"], "Content-Type": "text/plain"})
            try:
                with urllib.request.urlopen(r, timeout=60) as resp:
                    status, out = resp.status, resp.read()
            except urllib.error.HTTPError as e:
                status, out = e.code, e.read()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


def cli(*a):
    return subprocess.run([os.path.expanduser("~/solo45-test/bitcoin-32.1/bin/bitcoin-cli"), "-regtest",
                           f"-datadir={NODE_DIR}", "-rpcport=18543", *a], capture_output=True, text=True).stdout.strip()


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


def main():
    os.makedirs(DATA, exist_ok=True)
    for f in ("state.json", "state.json.bak", "pool.log", "blocks_found.jsonl"):
        p = os.path.join(DATA, f)
        if os.path.exists(p):
            os.replace(p, p + ".old")
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), Proxy)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    addr = open(os.path.expanduser("~/solo45-test/core-regtest/address.txt")).read().strip()
    env = dict(os.environ, SOLO45_STRATUM_PORT=str(STRATUM), SOLO45_API_PORT=str(API), SOLO45_DATA_DIR=DATA,
               SOLO45_LOG_FILE=os.path.join(DATA, "pool.log"), SOLO45_DEFAULT_ADDRESS=addr,
               SOLO45_START_DIFF="0.00001", SOLO45_MIN_DIFF="0.00001",
               BITCOIN_RPC_URL=f"http://127.0.0.1:{PROXY_PORT}/", BITCOIN_RPC_COOKIE=os.path.join(NODE_DIR, "regtest/.cookie"))
    core = subprocess.Popen([CORE, "serve"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(2)
        tip_before, height_before = cli("getbestblockhash"), int(cli("getblockcount"))
        c = tm.Client()
        en1 = bytes.fromhex(c.call("mining.subscribe", ["reject-test/1.0"])["result"][1])
        c.call("mining.authorize", [addr + ".reject1", "x"])
        job = c.job or c.wait_note("mining.notify", 5) and c.job
        en2, ntime, nonce, bhash = find_block(c, job, en1, 7)
        r = tm.submit(c, job, en2, ntime, nonce)
        check("the block share itself is accepted from the miner", r["result"] is True, r)
        time.sleep(8)  # long enough for several retries if Core (wrongly) retried a verdict
        check("Core sent it to the node exactly once (a verdict is final)", len(submits) == 1, f"{len(submits)} submitblock calls")
        log = open(os.path.join(DATA, "pool.log")).read()
        check("the log says the node refused it, with the reason",
              f'submitblock {bhash}: the node said "{VERDICT}"' in log and f"submitblock {bhash}, try" not in log)
        lines = [json.loads(l) for l in open(os.path.join(DATA, "blocks_found.jsonl"))]
        check("blocks_found.jsonl: saved as 'sending' first, then with the verdict, full block hex kept",
              [l["result"] for l in lines] == ["sending", VERDICT] and all(l.get("hex") for l in lines), [l["result"] for l in lines])
        s = json.load(urllib.request.urlopen(f"http://127.0.0.1:{API}/api", timeout=10))
        b = [x for x in s["pool"]["blocks"] if x["hash"] == bhash]
        check("the API lists the block with the node's verdict", len(b) == 1 and b[0]["result"] == VERDICT, b)
        check("the node's chain is unchanged", cli("getbestblockhash") == tip_before and int(cli("getblockcount")) == height_before)
        r = tm.submit(c, job, en2, ntime, nonce)
        check("sending the same share again is a duplicate (never re-sent to the node)", tm.err_code(r) == 22 and len(submits) == 1)
        en2b = (99).to_bytes(8, "big")
        nt, nn = tm.mine(job, en1, en2b, int(job[5], 16), c.diff)
        r = tm.submit(c, job, en2b, nt, nn)
        check("Core keeps taking shares after the refusal", r["result"] is True, r)
        check("Core is still running", core.poll() is None)
    finally:
        core.terminate()
        core.wait(10)
        srv.shutdown()
    passed = sum(1 for _, ok in tm.results if ok)
    print(f"\n{passed}/{len(tm.results)} checks passed")
    return 0 if passed == len(tm.results) else 1


if __name__ == "__main__":
    sys.exit(main())
