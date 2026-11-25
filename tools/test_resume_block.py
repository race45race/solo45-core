#!/usr/bin/env python3
"""A found block survives Core stopping while it sends it, on the private regtest chain (tools/regtest.sh start).

The node is stopped, a miner finds a block, Core starts trying to send it, and Core is killed (no clean stop) so
the block's last entry in blocks_found.jsonl is "sending". An old unsent block from long ago is added to the file
too. Then the node comes back and Core starts again. Expected: Core sends the saved block again and the node
takes it (it becomes the tip), the old one is recorded as stale without being sent, and Core gives miners work.
  python3 tools/test_resume_block.py
"""
import json, os, signal, struct, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
STRATUM, API = 3353, 3393
sys.argv = [sys.argv[0], "127.0.0.1", str(STRATUM)]
import test_miner as tm  # noqa: E402

CORE = os.path.expanduser("~/solo45-core/target/release/solo45-core")
DATA = os.path.expanduser("~/solo45-test/core-resume")
BIN = os.path.expanduser("~/solo45-test/bitcoin-32.1/bin")
NODE_DIR = os.path.expanduser("~/solo45-test/regtest-node")
CLI = [f"{BIN}/bitcoin-cli", "-regtest", f"-datadir={NODE_DIR}", "-rpcport=18543"]
check = tm.check
OLD_HASH = "11" * 32


def cli(*a):
    r = subprocess.run(CLI + list(a), capture_output=True, text=True, timeout=30)
    return r.stdout.strip() if not r.returncode else None


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


def entries():
    p = os.path.join(DATA, "blocks_found.jsonl")
    return [json.loads(l) for l in open(p)] if os.path.exists(p) else []


def start_core(env):
    return subprocess.Popen([CORE, "serve"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    os.makedirs(DATA, exist_ok=True)
    for f in ("state.json", "state.json.bak", "pool.log", "blocks_found.jsonl", "history.json"):
        p = os.path.join(DATA, f)
        if os.path.exists(p):
            os.replace(p, p + ".old")
    addr = open(os.path.expanduser("~/solo45-test/core-regtest/address.txt")).read().strip()
    env = dict(os.environ, SOLO45_STRATUM_PORT=str(STRATUM), SOLO45_API_PORT=str(API), SOLO45_DATA_DIR=DATA,
               SOLO45_LOG_FILE=os.path.join(DATA, "pool.log"), SOLO45_DEFAULT_ADDRESS=addr,
               SOLO45_START_DIFF="0.00001", SOLO45_MIN_DIFF="0.00001",
               BITCOIN_RPC_URL="http://127.0.0.1:18543/", BITCOIN_RPC_COOKIE=os.path.join(NODE_DIR, "regtest/.cookie"))
    core = start_core(env)
    try:
        time.sleep(3)
        c = tm.Client()
        en1 = bytes.fromhex(c.call("mining.subscribe", ["resume-test/1.0"])["result"][1])
        c.call("mining.authorize", [addr + ".resume1", "x"])
        job = c.job or c.wait_note("mining.notify", 5) and c.job
        en2, ntime, nonce, bhash = find_block(c, job, en1, 5)
        cli("stop")
        t0 = time.time()
        while cli("getblockcount") is not None and time.time() - t0 < 30:
            time.sleep(0.2)
        check("test node stopped", cli("getblockcount") is None)
        r = tm.submit(c, job, en2, ntime, nonce)
        check("the block share is accepted while the node is down", r["result"] is True, r)
        time.sleep(3)
        core.send_signal(signal.SIGKILL)  # stops mid-send: no clean shutdown
        core.wait(10)
        last = [e for e in entries() if e["hash"] == bhash]
        check("Core was killed while the block's last entry is still 'sending'",
              last and last[-1]["result"] == "sending" and last[-1].get("hex"), [e["result"] for e in last])
        # an unsent block from long ago (height 1): must be recorded stale, never sent
        with open(os.path.join(DATA, "blocks_found.jsonl"), "a") as f:
            f.write(json.dumps({"height": 1, "hash": OLD_HASH, "worker": "old", "ip": "", "address": addr, "diff": 1,
                                "value": 0, "at": 0, "result": "sending", "hex": "00"}) + "\n")
        subprocess.Popen([f"{BIN}/bitcoind", "-regtest", f"-datadir={NODE_DIR}", "-daemon"], stdout=subprocess.DEVNULL)
        core = start_core(env)  # starts while the node is still coming up: it waits for it
        t0 = time.time()
        tip = None
        while time.time() - t0 < 60:
            tip = cli("getbestblockhash")
            if tip == bhash:
                break
            time.sleep(0.5)
        check("after Core and the node restarted, the saved block is the node's tip", tip == bhash, f"{time.time() - t0:.1f} s")
        time.sleep(2)
        log = open(os.path.join(DATA, "pool.log")).read()
        check("Core logged that it sent the unanswered block again, and the node accepted it",
              f"block {bhash} at height" in log and "sending it again" in log and f"submitblock {bhash}: accepted by the node" in log)
        mine = [e for e in entries() if e["hash"] == bhash]
        check("blocks_found.jsonl now ends with the node's answer for it", mine and mine[-1]["result"] is None, [e["result"] for e in mine])
        old = [e for e in entries() if e["hash"] == OLD_HASH]
        check("the old unsent block was recorded as stale, not sent",
              len(old) == 2 and str(old[-1]["result"]).startswith("stale") and f"submitblock {OLD_HASH}" not in log,
              [e["result"] for e in old])
        c2 = tm.Client()
        c2.call("mining.subscribe", ["resume-test/1.0"])
        c2.call("mining.authorize", [addr + ".resume2", "x"])
        check("Core gives miners work after the restart", c2.job or c2.wait_note("mining.notify", 10))
        check("Core is still running", core.poll() is None)
    finally:
        core.terminate()
        core.wait(30)
    passed = sum(1 for _, ok in tm.results if ok)
    print(f"\n{passed}/{len(tm.results)} checks passed")
    return 0 if passed == len(tm.results) else 1


if __name__ == "__main__":
    sys.exit(main())
