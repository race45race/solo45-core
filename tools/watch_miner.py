#!/usr/bin/env python3
"""Stays connected to the pool for a while, logs every job (time, id, clean, transactions in the merkle branch,
coinbase value) and mines one share on each new job, to watch empty-block-first through real network blocks.

  python3 tools/watch_miner.py <seconds> [host] [port]
"""
import os, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
SECONDS = float(sys.argv[1])
sys.argv = [sys.argv[0]] + sys.argv[2:]
import test_miner as tm  # noqa: E402


def stamp():
    t = time.time()
    return time.strftime("%H:%M:%S", time.gmtime(t)) + ",%03d" % (t % 1 * 1000)


def main():
    c = tm.Client()
    en1 = bytes.fromhex(c.call("mining.subscribe", ["watch-miner/1.0"])["result"][1])
    c.call("mining.authorize", ["Bitaxe-test.watcher", "x"])
    end = time.time() + SECONDS
    seen, n = set(), 0
    while time.time() < end:
        job = c.job
        if job and job[0] not in seen:
            seen.add(job[0])
            cb2 = bytes.fromhex(job[3])
            value = int.from_bytes(cb2[5:13], "little")  # first output's value (after sequence + output count)
            height = int.from_bytes(bytes.fromhex(job[2])[43:43 + bytes.fromhex(job[2])[42]], "little")
            n += 1
            en2 = n.to_bytes(8, "big")
            t0 = time.time()
            ntime, nonce = tm.mine(job, en1, en2, int(job[5], 16), c.diff)
            r = tm.submit(c, job, en2, ntime, nonce)
            print(f"{stamp()} job {job[0]} height {height} clean={job[8]} branch={len(job[4])} value={value / 1e8:.8f} "
                  f"share={'ok' if r['result'] else r['error']} ({(time.time() - t0) * 1000:.0f} ms)", flush=True)
        c.wait_note("mining.notify", 1)
    print("done", flush=True)


if __name__ == "__main__":
    main()
