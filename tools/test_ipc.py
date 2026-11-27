#!/usr/bin/env python3
"""Templates over Bitcoin Core's IPC mining interface, on a private regtest node (bitcoin-node -ipcbind=unix).

  python3 tools/test_ipc.py        (needs ~/solo45-test/bitcoin-32.1 with libexec/bitcoin-node)

Its own node (datadir ~/solo45-test/core-ipc-node, RPC 18653, ZMQ 28654) and Core (V1 3360, API 3400, SV2 34270,
data ~/solo45-test/core-ipc). With ~300 transactions waiting, an SV2 test miner finds blocks (on regtest every share
is one) and the test checks that Core connected over IPC, built its jobs from IPC templates, that the node accepted
every block, that the blocks carry the waiting transactions and pay the payout address; that with the template
policy filtering Core uses getblocktemplate instead (blocks still accepted, the API says why) and goes back to IPC
when it stops; that no template was skipped; that with empty-block-first a new block's empty job takes its header
from IPC (no getblockheader call) and a block found on that empty job is accepted (coinbase only, pays the payout); that when the node restarts right after a new block (a template
request in flight) Core notices, mines on getblocktemplate meanwhile and reconnects to IPC by itself; and that a
Core pointed at a socket that isn't there mines through getblocktemplate as before.
"""
import json, os, subprocess, sys, time, urllib.request

HOME = os.path.expanduser("~")
BIN = os.path.join(HOME, "solo45-test/bitcoin-32.1")
NODE = os.path.join(HOME, "solo45-test/core-ipc-node")
DATA = os.path.join(HOME, "solo45-test/core-ipc")
CORE = os.path.join(HOME, "solo45-core/target/release/solo45-core")
V1, API, SV2, RPC, ZMQ = 3360, 3400, 34270, 18653, 28654
SOCK = os.path.join(NODE, "regtest/node.sock")
results = []


def check(name, ok, detail=""):
    results.append(bool(ok))
    print("%s  %s %s" % ("PASS" if ok else "FAIL", name, detail), flush=True)


def cli(*a, wallet=False):
    cmd = [BIN + "/bin/bitcoin-cli", "-regtest", "-datadir=" + NODE, "-rpcport=%d" % RPC] + (["-rpcwallet=ipc"] if wallet else []) + list(a)
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.strip()


def api():
    with urllib.request.urlopen("http://127.0.0.1:%d/api/state" % API, timeout=10) as r:
        return json.load(r)


def post(path, body):
    req = urllib.request.Request("http://127.0.0.1:%d%s" % (API, path), json.dumps(body).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)


def start_node():
    os.makedirs(NODE, exist_ok=True)
    try:
        cli("getblockcount")
        return
    except Exception:
        pass
    subprocess.run([BIN + "/libexec/bitcoin-node", "-regtest", "-datadir=" + NODE, "-ipcbind=unix", "-rpcport=%d" % RPC,
                    "-port=18654", "-listen=0", "-server", "-fallbackfee=0.0002", "-spendzeroconfchange=0",
                    "-zmqpubhashblock=tcp://127.0.0.1:%d" % ZMQ, "-daemon"], check=True)
    for _ in range(60):
        try:
            cli("getblockcount")
            return
        except Exception:
            time.sleep(0.5)
    sys.exit("the IPC test node didn't start")


def fill_mempool(n=300):
    try:
        cli("createwallet", "ipc")
    except subprocess.CalledProcessError:
        try:
            cli("loadwallet", "ipc")
        except subprocess.CalledProcessError:
            pass
    addr = cli("getnewaddress", wallet=True)
    if int(cli("getblockcount")) < 200:
        cli("generatetoaddress", "200", addr, wallet=True)
    have = json.loads(cli("getmempoolinfo"))["size"]
    if have < n:
        outs = {cli("getnewaddress", wallet=True): 0.01 for _ in range(n)}
        cli("sendmany", "", json.dumps(outs), wallet=True)
        cli("generatetoaddress", "1", addr, wallet=True)
        for _ in range(n):
            try:
                cli("sendtoaddress", cli("getnewaddress", wallet=True), "0.005", wallet=True)
            except subprocess.CalledProcessError:
                break
    return addr


def start_core(sock, payout, extra=None):
    os.makedirs(DATA, exist_ok=True)
    for f in ("state.json", "state.json.bak", "pool.log", "blocks_found.jsonl", "history.json"):
        p = os.path.join(DATA, f)
        if os.path.exists(p):
            os.replace(p, p + ".old")
    env = dict(os.environ, SOLO45_STRATUM_PORT=str(V1), SOLO45_API_PORT=str(API), SOLO45_SV2_PORT=str(SV2),
               SOLO45_DATA_DIR=DATA, SOLO45_LOG_FILE=os.path.join(DATA, "pool.log"), SOLO45_DEFAULT_ADDRESS=payout,
               SOLO45_START_DIFF="0.00001", SOLO45_MIN_DIFF="0.00001", SOLO45_MINER_READINGS="0",
               SOLO45_IPC_SOCKET=sock, BITCOIN_RPC_URL="http://127.0.0.1:%d/" % RPC,
               BITCOIN_RPC_COOKIE=os.path.join(NODE, "regtest/.cookie"), BITCOIN_ZMQ_HASHBLOCK="tcp://127.0.0.1:%d" % ZMQ)
    env.update(extra or {})
    core = subprocess.Popen([CORE, "serve"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(80):
        try:
            api()
            if os.path.exists(os.path.join(DATA, "sv2-authority.json")):
                return core
        except Exception:
            pass
        time.sleep(0.25)
    return core


def mine(shares):
    pub = json.load(open(os.path.join(DATA, "sv2-authority.json")))["public"]
    subprocess.run(["timeout", "60", CORE, "sv2-miner", "127.0.0.1:%d" % SV2, pub, "ipctest", str(shares), "2"],
                   capture_output=True, text=True)


def ipc_state():
    return (api().get("pool") or {}).get("ipc") or {}


def wait_for(cond, seconds):
    end = time.time() + seconds
    while time.time() < end:
        try:
            s = ipc_state()
            if cond(s):
                return s
        except Exception:
            pass
        time.sleep(0.5)
    try:
        return ipc_state()
    except Exception:
        return {}


def log():
    return open(os.path.join(DATA, "pool.log"), errors="replace").read()


def main():
    start_node()
    payout = fill_mempool()
    spk = json.loads(cli("getaddressinfo", payout, wallet=True))["scriptPubKey"]
    waiting = json.loads(cli("getmempoolinfo"))["size"]
    print("mempool: %d transactions" % waiting, flush=True)

    # 1. IPC on
    core = start_core(SOCK, payout)
    try:
        time.sleep(4)
        ipc = (api().get("pool") or {}).get("ipc") or {}
        check("Core connected to the node over IPC", ipc.get("up") is True and "IPC: connected" in log(), ipc)
        check("its first job came from an IPC template", (ipc.get("used") or 0) >= 1, ipc)
        h0 = int(cli("getblockcount"))
        used0 = ipc.get("used") or 0
        mine(3)
        time.sleep(3)
        h1 = int(cli("getblockcount"))
        check("3 blocks mined on IPC templates, all accepted by the node", h1 == h0 + 3, "%d -> %d" % (h0, h1))
        blk = json.loads(cli("getblock", cli("getblockhash", str(h0 + 1)), "2"))
        check("the first block carries the waiting transactions", len(blk["tx"]) > 100, "%d txs" % len(blk["tx"]))
        check("and pays the payout address", any(o["scriptPubKey"]["hex"] == spk for o in blk["tx"][0]["vout"]))
        ipc = (api().get("pool") or {}).get("ipc") or {}
        check("the jobs after each block came from IPC too", (ipc.get("used") or 0) >= used0 + 3, ipc)
        # 2. a filtering policy needs each transaction's fee: getblocktemplate
        rpc0 = ipc.get("rpc_used") or 0
        post("/api/policy", {"mode": "filter", "rules": {"minfee": {"on": True, "sat_vb": 1}}})
        h2 = int(cli("getblockcount"))
        mine(1)
        time.sleep(3)
        ipc = (api().get("pool") or {}).get("ipc") or {}
        check("with the policy filtering, templates come from getblocktemplate", (ipc.get("rpc_used") or 0) > rpc0, ipc)
        check("and the block is accepted", int(cli("getblockcount")) == h2 + 1)
        fb = ipc.get("fallback") or {}
        check("the API says why: the policy filters", "policy filters" in (fb.get("reason") or ""), fb)
        post("/api/policy", {"mode": "watch"})
        used1, h4 = ipc.get("used") or 0, int(cli("getblockcount"))
        mine(1)
        time.sleep(3)
        ipc = ipc_state()
        check("back on Watch, the next block's jobs come from IPC again",
              (ipc.get("used") or 0) > used1 and int(cli("getblockcount")) == h4 + 1, ipc)
        check("no template from the node was skipped", ipc.get("skipped") == 0 and ipc.get("last_skip") is None, ipc)
        bad = [l for l in log().splitlines() if (" ERROR " in l or " CRITICAL " in l) and "BLOCK FOUND" not in l and "submitblock" not in l]
        check("no ERROR/CRITICAL in the log other than found blocks", not bad, bad[:3])

        # 2b. the node restarts right after a new block (Core has just asked for that template's transactions)
        rec0 = ipc.get("reconnects") or 0
        cli("generatetoaddress", "1", payout)
        cli("stop")
        down = wait_for(lambda s: s.get("up") is False, 30)
        check("with the node gone, Core sees IPC down", down.get("up") is False, down)
        for _ in range(120):  # wait until the node process has really exited before starting it again
            if subprocess.run(["pgrep", "-f", "datadir=" + NODE], capture_output=True).returncode != 0:
                break
            time.sleep(0.5)
        time.sleep(1)
        start_node()
        up = wait_for(lambda s: s.get("up") is True and (s.get("reconnects") or 0) > rec0, 60)
        check("after the node is back Core reconnects to IPC by itself", up.get("up") is True and (up.get("reconnects") or 0) > rec0, up)
        time.sleep(3)
        used2, h5 = up.get("used") or 0, int(cli("getblockcount"))
        mine(1)
        time.sleep(3)
        ipc = ipc_state()
        check("and mines on IPC templates again (block accepted)",
              (ipc.get("used") or 0) > used2 and int(cli("getblockcount")) == h5 + 1, ipc)
        alive = core.poll() is None
        check("Core kept running through the node restart", alive)
    finally:
        core.terminate()
        core.wait(15)

    # 4. empty block first (mainnet only, let in here by the test switch): a new block's empty job takes its header from
    #    IPC, and a block found on that empty job (coinbase only) is accepted
    core = start_core(SOCK, payout, {"SOLO45_TEST_EMPTY_ANY_CHAIN": "1", "SOLO45_EMPTY_HOLD_S": "20"})
    try:
        time.sleep(4)
        tries, got = 0, False
        while tries < 3 and not got:  # IPC usually beats the 30 ms wait; allow the odd block where it doesn't
            tries += 1
            n0 = log().count("(block header from IPC)")
            cli("generatetoaddress", "1", payout)  # someone else's block
            time.sleep(1.5)
            got = log().count("(block header from IPC)") > n0
        empties = [l for l in log().splitlines() if "empty (coinbase only" in l]
        check("a new block: the empty job goes out first, its header from IPC (no node call)", got,
              "%d tries; %s" % (tries, empties[-1:] if empties else "no empty job"))
        h6 = int(cli("getblockcount"))
        mine(1)  # inside the 20 s hold: the share (on regtest also a block) is on the empty job
        time.sleep(3)
        blk = json.loads(cli("getblock", cli("getbestblockhash"), "2"))
        check("a block found on the empty job is accepted: coinbase only, pays the payout address",
              int(cli("getblockcount")) == h6 + 1 and len(blk["tx"]) == 1
              and any(o["scriptPubKey"]["hex"] == spk for o in blk["tx"][0]["vout"]), "%d txs" % len(blk["tx"]))
        bad = [l for l in log().splitlines() if (" ERROR " in l or " CRITICAL " in l) and "BLOCK FOUND" not in l and "submitblock" not in l]
        check("no ERROR/CRITICAL in the log with empty jobs", not bad, bad[:3])
    finally:
        core.terminate()
        core.wait(15)

    # 3. a socket that isn't there: getblocktemplate as before
    core = start_core(SOCK + ".missing", payout)
    try:
        time.sleep(3)
        ipc = (api().get("pool") or {}).get("ipc") or {}
        h3 = int(cli("getblockcount"))
        mine(1)
        time.sleep(3)
        check("without the socket Core mines through getblocktemplate (block accepted)",
              int(cli("getblockcount")) == h3 + 1 and ipc.get("up") is False and "no IPC socket" in log(), ipc)
    finally:
        core.terminate()
        core.wait(15)
        cli("stop")
    print("\n%d/%d checks passed" % (sum(results), len(results)), flush=True)
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
