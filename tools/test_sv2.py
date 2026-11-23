#!/usr/bin/env python3
"""Stratum V2 end to end on the private regtest chain (start the stand with: bash tools/sv2_regtest.sh start).

An SV1 test miner (tools/test_miner.py's client) mines through the reference Translator Proxy, which speaks
encrypted Stratum V2 to Solo45 Core. On regtest the network target is easier than any share target, so every share
is a block: the test mines three blocks in a row over SV2 and checks each at the node (new tip, coinbase pays the
payout address, height), on Core's API (the block, the share counted under an "sv2" agent) and in Core's log, that
the next block's work arrives each time, that a share for the old block is refused, and that the node's check of
Core's own V1 jobs still passes.
  python3 tools/test_sv2.py
"""
import json, os, struct, subprocess, sys, time, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.argv = [sys.argv[0], "127.0.0.1", "34261"]
import test_miner as tm  # noqa: E402

BIN = os.path.expanduser("~/solo45-test/bitcoin-32.1/bin")
NODE_DIR = os.path.expanduser("~/solo45-test/regtest-node")
CORE_DIR = os.path.expanduser("~/solo45-test/core-sv2")
API = "http://127.0.0.1:3389/api"
check = tm.check
USER = None  # the username the miner authorized with (tProxy only takes shares under that name)


def cli(*a):
    return subprocess.run([f"{BIN}/bitcoin-cli", "-regtest", f"-datadir={NODE_DIR}", "-rpcport=18543", *a],
                          capture_output=True, text=True).stdout.strip()


def api():
    return json.load(urllib.request.urlopen(API, timeout=10))


def submit(c, job, en2, ntime, nonce):
    return c.call("mining.submit", [USER, job[0], en2.hex(), "%08x" % ntime, "%08x" % nonce])


def target_of(nbits_hex):
    b = int(nbits_hex, 16)
    return (b & 0xFFFFFF) << (8 * ((b >> 24) - 3))


def solve(c, job, en1, en2):
    """A nonce meeting both the share and the network target (on regtest: the first valid share)."""
    target = min(target_of(job[6]), int(tm.DIFF1 / c.diff))
    ntime = int(job[7], 16)
    pre = tm.header_for(job, en1, en2, ntime, 0, int(job[5], 16))[:76]
    for nonce in range(1 << 32):
        h = tm.sha256d(pre + struct.pack("<I", nonce))
        if int.from_bytes(h, "little") <= target:
            return ntime, nonce, h[::-1].hex()


def new_job(c, old_id, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        if c.job and c.job[0] != old_id:
            return c.job
        c.wait_note("mining.notify", 1)
    return None


def sv2_accepted():
    return sum(w["accepted"] for w in api()["workers"] if w["agent"].startswith("sv2"))


def main():
    global USER
    addr = open(os.path.expanduser("~/solo45-test/core-regtest/address.txt")).read().strip()
    spk = json.loads(cli("getaddressinfo", addr))["scriptPubKey"]
    s = api()
    check("Core reports its Stratum V2 port and authority key", (s["pool"].get("sv2") or {}).get("port") == 34260
          and len((s["pool"]["sv2"] or {}).get("authority_pubkey", "")) > 40, s["pool"].get("sv2"))

    for i in range(30):  # tProxy may still be starting on a slow CI runner
        try:
            c = tm.Client()
            break
        except OSError:
            time.sleep(1)
    else:
        c = tm.Client()
    sub = c.call("mining.subscribe", ["sv2-test/1.0"])["result"]
    en1 = bytes.fromhex(sub[1])
    check("tProxy hands out extranonce2 of 8 bytes", sub[2] == 8, sub[1:])
    USER = addr + ".sv2miner"
    r = c.call("mining.authorize", [USER, "x"])
    check("authorize through tProxy", r.get("result") is True, r)
    job = c.job or (c.wait_note("mining.notify", 30) and c.job)  # tProxy opens its SV2 channel first
    check("work arrives through tProxy (from Core over Stratum V2)", job is not None)
    if not job:
        return finish()
    for _ in range(10):
        if c.diff:
            break
        c.wait_note("mining.set_difficulty", 1)
    check("a share difficulty is set", (c.diff or 0) > 0, c.diff)

    # real (segwit) transactions in the mempool, so blocks 2 and 3 carry them: the merkle path and the witness
    # commitment Core gives over SV2 then have to be right for the node to accept the blocks
    sent = [cli("-rpcwallet=core-test", "sendtoaddress", addr, "0.01") for _ in range(12)]
    check("12 test transactions in the node's mempool", all(len(t) == 64 for t in sent), sent[:1])

    blocks, accepted0, with_txs = [], sv2_accepted(), 0
    for n in range(1, 4):
        height_before = int(cli("getblockcount"))
        en2 = (100 + n).to_bytes(8, "big")
        ntime, nonce, bhash = solve(c, job, en1, en2)
        r = submit(c, job, en2, ntime, nonce)
        t0, tip = time.time(), None
        while time.time() - t0 < 15:
            tip = cli("getbestblockhash")
            if tip == bhash:
                break
            time.sleep(0.1)
        ok = r.get("result") is True and tip == bhash
        detail = "%s... in %.0f ms" % (bhash[:16], (time.time() - t0) * 1000) if ok else (r, tip)
        check(f"block {n}: share accepted, the node's tip is our block (Stratum V2 all the way)", ok, detail)
        if not ok:
            break
        blk = json.loads(cli("getblock", tip, "2"))
        check(f"block {n}: coinbase pays the payout address, height {height_before + 1}, {len(blk['tx'])} txs",
              any(o["scriptPubKey"]["hex"] == spk for o in blk["tx"][0]["vout"]) and blk["height"] == height_before + 1)
        with_txs += len(blk["tx"]) > 1
        blocks.append(bhash)
        old, job = job, new_job(c, job[0])
        check(f"block {n}: work for the next block arrives over SV2", job is not None)
        if not job:
            break
    if blocks:
        r = submit(c, old, (999).to_bytes(8, "big"), *solve(c, old, en1, (999).to_bytes(8, "big"))[:2])
        check("a share for an old block is refused", r.get("result") is not True, r.get("error"))
    check("blocks with transactions (merkle path + witness commitment over SV2) were accepted", with_txs >= 1,
          f"{with_txs} of {len(blocks)}")
    time.sleep(1)
    listed = [b for b in api()["pool"]["blocks"] if b["hash"] in blocks]
    check("Core's API lists the 3 blocks, each accepted by the node",
          len(blocks) == 3 and len(listed) == 3 and all(b["result"] is None for b in listed), [b["result"] for b in listed])
    log = open(os.path.join(CORE_DIR, "pool.log")).read()
    check("Core logged each one as accepted by the node", all(f"submitblock {h}: accepted by the node" in log for h in blocks))
    check("Core counted the shares on its SV2 channel", sv2_accepted() >= accepted0 + len(blocks), (accepted0, sv2_accepted()))
    lines = [json.loads(l) for l in open(os.path.join(CORE_DIR, "blocks_found.jsonl"))]
    check("blocks_found.jsonl: saved 'sending' first, then the node's answer, full hex",
          all([l["result"] for l in lines if l["hash"] == h] == ["sending", None] for h in blocks)
          and all(l.get("hex") for l in lines if l["hash"] in blocks))
    check("Core's own V1 job still passes the node's block check", api()["pool"]["proposal"].get("ok") is True)
    return finish()


def finish():
    passed = sum(1 for _, ok in tm.results if ok)
    print(f"\n{passed}/{len(tm.results)} checks passed")
    return 0 if passed == len(tm.results) else 1


if __name__ == "__main__":
    sys.exit(main())
