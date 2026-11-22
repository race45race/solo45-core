#!/usr/bin/env python3
"""Solo45 Core found-block test on a private regtest chain.

Needs a regtest bitcoind (see tools/regtest.sh) and Solo45 Core pointed at it on port 3348 / API 3388.
  python3 tools/test_regtest_blocks.py <payout address> <core data dir> <api token>

Part A: 5 real blocks, one after another: the share is accepted, the node's tip becomes our block hash, the
coinbase pays the payout address, the miners get the next block's work, the block is in Core's API and in
blocks_found.jsonl (saved "sending" first, then the node's answer). A resend of the same share is a duplicate.
Part B: the node is stopped when the block is found: Core must keep trying (node down, then starting up) and
the block must be in the chain once the node is back.
"""
import json, os, struct, subprocess, sys, time, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
ADDR, CORE_DIR, TOKEN = sys.argv[1], sys.argv[2], sys.argv[3]
sys.argv = [sys.argv[0], "127.0.0.1", "3348"]
import test_miner as tm  # noqa: E402

BIN = os.path.expanduser("~/solo45-test/bitcoin-32.1/bin")
NODE_DIR = os.path.expanduser("~/solo45-test/regtest-node")
CLI = [f"{BIN}/bitcoin-cli", "-regtest", f"-datadir={NODE_DIR}", "-rpcport=18543"]
check = tm.check


def cli(*a, ok_fail=False):
    r = subprocess.run(CLI + list(a), capture_output=True, text=True, timeout=30)
    if r.returncode and not ok_fail:
        raise RuntimeError(r.stderr.strip())
    return r.stdout.strip() if not r.returncode else None


def api():
    r = urllib.request.Request("http://127.0.0.1:3388/api", headers={"X-Solo45-Token": TOKEN})
    return json.load(urllib.request.urlopen(r, timeout=10))


def target_of(nbits_hex):
    b = int(nbits_hex, 16)
    return (b & 0xFFFFFF) << (8 * ((b >> 24) - 3))


def find_block(c, job, en1, n):
    """A share whose hash also meets the job's block target; returns (en2, ntime, nonce, block hash hex)."""
    target = min(target_of(job[6]), int(tm.DIFF1 / c.diff))
    en2 = n.to_bytes(8, "big")
    ntime = int(job[7], 16)
    pre = tm.header_for(job, en1, en2, ntime, 0, int(job[5], 16))[:76]
    for nonce in range(1 << 32):
        h = tm.sha256d(pre + struct.pack("<I", nonce))
        if int.from_bytes(h, "little") <= target:
            return en2, ntime, nonce, h[::-1].hex()


def next_job(c, after_height, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        if c.job and int.from_bytes(bytes.fromhex(c.job[2])[43:43 + bytes.fromhex(c.job[2])[42]], "little") > after_height:
            return c.job
        c.wait_note("mining.notify", 1)
    return None


def main():
    spk = json.loads(cli("getaddressinfo", ADDR))["scriptPubKey"]
    c = tm.Client()
    en1 = bytes.fromhex(c.call("mining.subscribe", ["regtest-test/1.0"])["result"][1])
    c.call("mining.authorize", [ADDR + ".regtest1", "x"])
    job = c.job or c.wait_note("mining.notify", 5) and c.job
    blocks = []
    # ---- Part A: five blocks in a row
    for n in range(1, 6):
        height_before = int(cli("getblockcount"))
        job = next_job(c, height_before)
        if not job:
            check(f"block {n}: work for height {height_before + 1} arrived", False)
            break
        en2, ntime, nonce, bhash = find_block(c, job, en1, n)
        r = tm.submit(c, job, en2, ntime, nonce)
        t0 = time.time()
        while time.time() - t0 < 10 and int(cli("getblockcount")) == height_before:
            time.sleep(0.1)
        tip = cli("getbestblockhash")
        blk = json.loads(cli("getblock", tip, "2"))
        pays = any(o["scriptPubKey"]["hex"] == spk for o in blk["tx"][0]["vout"])
        check(f"block {n}: share accepted and the node's tip is our block at height {height_before + 1}",
              r["result"] is True and tip == bhash and blk["height"] == height_before + 1,
              f"{bhash[:16]}... in {(time.time() - t0) * 1000:.0f} ms")
        check(f"block {n}: coinbase pays the payout address", pays)
        blocks.append(bhash)
        last = (job, en2, ntime, nonce)
    nj = next_job(c, int(cli("getblockcount")) - 1, 10)
    check("after a block the miner gets clean work for the next height", nj is not None and nj[8] is True)
    job, en2, ntime, nonce = last
    r = tm.submit(c, job, en2, ntime, nonce)
    check("the same block share again = error 22 duplicate (never sent twice)", tm.err_code(r) == 22, r["error"])
    time.sleep(1)
    s = api()
    got = [b for b in s["pool"]["blocks"] if b["hash"] in blocks]
    check("Core's API lists the 5 blocks, each accepted by the node",
          len(got) == 5 and all(b["result"] is None for b in got), [(b["height"], b["result"]) for b in got])
    lines = [json.loads(l) for l in open(os.path.join(CORE_DIR, "blocks_found.jsonl"))]
    mine = [l for l in lines if l["hash"] in blocks]
    check("blocks_found.jsonl: each block saved as 'sending' first, then with the node's answer, full block hex",
          len(mine) == 10 and all(m.get("hex") for m in mine)
          and all([m["result"] for m in mine if m["hash"] == b] == ["sending", None] for b in blocks))

    # ---- Part B: the node is down when the block is found
    height_before = int(cli("getblockcount"))
    job = next_job(c, height_before - 1)
    en2, ntime, nonce, bhash = find_block(c, job, en1, 99)
    cli("stop")
    t0 = time.time()
    while cli("getblockcount", ok_fail=True) is not None and time.time() - t0 < 30:
        time.sleep(0.2)
    down = cli("getblockcount", ok_fail=True) is None
    check("test node stopped", down, f"after {time.time() - t0:.1f} s")
    r = tm.submit(c, job, en2, ntime, nonce)
    check("the block share is accepted while the node is down", r["result"] is True, r)
    time.sleep(15)  # down longer than Core's first 6 quick tries (~10 s): it must keep trying (0.0.14)
    subprocess.Popen([f"{BIN}/bitcoind", "-regtest", f"-datadir={NODE_DIR}", "-daemon"], stdout=subprocess.DEVNULL)
    t0 = time.time()
    tip = None
    while time.time() - t0 < 40:
        tip = cli("getbestblockhash", ok_fail=True)
        if tip == bhash:
            break
        time.sleep(0.5)
    check("after the node came back, our block is its tip", tip == bhash, f"{(time.time() - t0):.1f} s after restart")
    time.sleep(1)
    log = open(os.path.join(CORE_DIR, "pool.log")).read()
    tries = log.count(f"submitblock {bhash}, try")
    check("Core kept trying while the node was down (past the first 6 quick tries), then the node accepted it",
          tries >= 6 and f"submitblock {bhash}: accepted by the node" in log, f"{tries} failed tries logged")
    passed = sum(1 for _, ok in tm.results if ok)
    print(f"\n{passed}/{len(tm.results)} checks passed")
    return 0 if passed == len(tm.results) else 1


if __name__ == "__main__":
    sys.exit(main())
