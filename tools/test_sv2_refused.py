#!/usr/bin/env python3
"""Stratum V2 when the node REFUSES a filtered job, on the private regtest chain (tools/regtest.sh start first).

A stand-in between Core and the node forwards every call, but answers the first block check (getblocktemplate
proposal) of a coinbase-only block with a refusal, 3 s late, so an SV2 miner is already working on that job. With
transactions waiting, a coinbase-only block can only be Core's filtered template (template policy: minimum fee rate
500 sat/vB leaves them all out; regtest has no empty-block-first). Expected:
  - Core logs the refusal and falls back to the node's own template for that block;
  - the SV2 miner gets the replacement as a new block's work (SetNewPrevHash for the SAME block), so it drops the
    refused job at once (V1's clean_jobs);
  - the next block, mined over SV2, carries the transactions (the node's template) and pays the payout address.
  python3 tools/test_sv2_refused.py
"""
import http.server, json, os, subprocess, sys, threading, time, urllib.request

NODE_PORT, PROXY_PORT, STRATUM, API, SV2 = 18543, 18552, 3352, 3392, 34263
CORE = os.path.expanduser("~/solo45-core/target/release/solo45-core")
DATA = os.path.expanduser("~/solo45-test/core-sv2-refused")
NODE_DIR = os.path.expanduser("~/solo45-test/regtest-node")
CLI = [os.path.expanduser("~/solo45-test/bitcoin-32.1/bin/bitcoin-cli"), "-regtest", f"-datadir={NODE_DIR}", "-rpcport=18543"]
refused = []
armed = []  # refuse only once the test has set the policy (the node may hand out a template without the new txs at first)
results = []


def check(name, ok, detail=""):
    results.append(bool(ok))
    print(("PASS  " if ok else "FAIL  ") + name + (f" ({detail})" if detail and not ok else ""))


def cli(*a):
    return subprocess.run(CLI + list(a), capture_output=True, text=True).stdout.strip()


class Proxy(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        req = json.loads(body)
        params = req.get("params") or [{}]
        data = params[0].get("data", "") if req.get("method") == "getblocktemplate" and isinstance(params[0], dict) else ""
        # tx count: the varint right after the 80-byte header; 01 = coinbase only
        if data and params[0].get("mode") == "proposal" and data[160:162] == "01" and armed and not refused:
            refused.append(time.time())
            time.sleep(3)  # the miner is already on this job when the refusal comes
            out = json.dumps({"result": "bad-txns-test-refusal", "error": None, "id": req.get("id")}).encode()
            status = 200
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


def miner(user, shares, secs, out):
    pub = json.load(open(os.path.join(DATA, "sv2-authority.json")))["public"]
    with open(out, "w") as f:
        return subprocess.Popen(["timeout", str(secs), CORE, "sv2-miner", f"127.0.0.1:{SV2}", pub, user, str(shares)],
                                stdout=f, stderr=subprocess.STDOUT)


def main():
    os.makedirs(DATA, exist_ok=True)
    for f in ("state.json", "state.json.bak", "pool.log", "blocks_found.jsonl", "history.json"):
        p = os.path.join(DATA, f)
        if os.path.exists(p):
            os.replace(p, p + ".old")
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), Proxy)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    addr = open(os.path.expanduser("~/solo45-test/core-regtest/address.txt")).read().strip()
    for _ in range(6):
        cli("-rpcwallet=core-test", "sendtoaddress", addr, "0.01")
    for _ in range(40):  # until the node's block template carries them (it reuses a template for a few seconds)
        if len(json.loads(cli("getblocktemplate", '{"rules": ["segwit"]}')).get("transactions", [])) >= 6:
            break
        time.sleep(0.5)
    env = dict(os.environ, SOLO45_STRATUM_PORT=str(STRATUM), SOLO45_API_PORT=str(API), SOLO45_SV2_PORT=str(SV2),
               SOLO45_DATA_DIR=DATA, SOLO45_LOG_FILE=os.path.join(DATA, "pool.log"), SOLO45_DEFAULT_ADDRESS=addr,
               SOLO45_START_DIFF="0.00001", SOLO45_MIN_DIFF="0.00001", SOLO45_TEMPLATE_REFRESH_S="120",
               BITCOIN_RPC_URL=f"http://127.0.0.1:{PROXY_PORT}/", BITCOIN_RPC_COOKIE=os.path.join(NODE_DIR, "regtest/.cookie"))
    core = subprocess.Popen([CORE, "serve"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    a_out, b_out = os.path.join(DATA, "miner-a.out"), os.path.join(DATA, "miner-b.out")
    try:
        time.sleep(3)
        h0 = int(cli("getblockcount"))
        a = miner("watcher", 0, 14, a_out)  # only listens: never mines, so the refused job can't become a block
        time.sleep(3)
        armed.append(1)
        req = urllib.request.Request(f"http://127.0.0.1:{API}/api/policy", json.dumps(
            {"mode": "filter", "rules": {"minfee": {"on": True, "sat_vb": 500}}}).encode(), {"Content-Type": "application/json"})
        pol = json.load(urllib.request.urlopen(req, timeout=10))
        check("policy set to filter (minimum fee 500 sat/vB)", pol.get("ok") is True, pol)
        a.wait()
        log = open(os.path.join(DATA, "pool.log")).read()
        check("the stand-in refused one coinbase-only (filtered) job", len(refused) == 1, refused)
        check("Core logged the refusal and fell back to the node's own template",
              "BLOCK PROPOSAL REJECTED" in log and "failed the block check; mining the node's own template" in log)
        snph = [l.split()[-1] for l in open(a_out) if l.startswith("SetNewPrevHash")]
        check("the SV2 miner got the replacement as SetNewPrevHash for the same block (drops the refused job)",
              len(snph) >= 2 and snph[-1] == snph[0], snph)
        b = miner("refusedminer", 1, 30, b_out)
        b.wait()
        for _ in range(50):  # the miner quits right after its share; the block reaches the node a few ms later
            h1 = int(cli("getblockcount"))
            if h1 > h0:
                break
            time.sleep(0.1)
        check("the next SV2 share made a block", h1 == h0 + 1, f"{h0} -> {h1}")
        blk = json.loads(cli("getblock", cli("getblockhash", str(h1)), "2")) if h1 > h0 else {"tx": []}
        spk = json.loads(cli("getaddressinfo", addr))["scriptPubKey"]
        check("that block is the node's template: it carries the waiting transactions", len(blk["tx"]) > 1, len(blk["tx"]))
        check("and pays the payout address", blk["tx"] and any(o["scriptPubKey"]["hex"] == spk for o in blk["tx"][0]["vout"]))
        check("Core is still running", core.poll() is None)
    finally:
        core.terminate()
        core.wait(10)
        srv.shutdown()
    print(f"\n{sum(results)}/{len(results)} checks passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
