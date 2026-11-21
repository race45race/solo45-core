"""Cross-check Solo45 Core's job builder against Solo45's pool.py on the same block templates.

Saves fresh templates from the node (a full one, and an empty coinbase-only one), runs both builders with the
same tag, payout script and test share, and compares every field. Exit 0 only if everything matches.
usage: python3 crosscheck_job.py  (env SOLO45_DATA_DIR for pool.py's config; run from ~/solo45-core)
"""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.expanduser("~/solo45-app/src"))
import pool as P  # noqa: E402

TAG = "Solo45"
SPK = "0014751e76e8199196d454941c45d1b3a323f1433bd6"  # BIP 173's example address (any script works here)

cfg = P.load_config()
rpc = P.RPC(cfg["rpc_url"], cfg["rpc_cookie"], cfg["rpc_user"], cfg["rpc_pass"])
full = rpc.call("getblocktemplate", {"rules": ["segwit"]})
tip = rpc.call("getblockheader", rpc.call("getbestblockhash"))
empty = P.empty_template(tip, full["version"]) or dict(full, transactions=[])

ok_all = True
for name, tpl in (("full template", full), ("empty template", empty)):
    path = "/tmp/xc-%s.json" % name.split()[0]
    with open(path, "w") as f:
        json.dump(tpl, f)
    rust = json.loads(subprocess.check_output(["./target/release/solo45-core", "job", path, TAG, SPK]))
    j = P.Job("1", tpl, TAG.encode())
    spk = bytes.fromhex(SPK)
    cb = j.coinb1 + bytes([1, 2, 3, 4]) + b"\xaa" * 8 + j.coinb2(spk)
    version = (j.version & ~0x1FFFE000) | 0x00A4E000
    hdr = j.header(cb, version, j.curtime, 0x12345678)
    blk = j.block(hdr, cb)
    py = {
        "height": j.height,
        "coinb1": j.coinb1.hex(),
        "coinb2": j.coinb2(spk).hex(),
        "branch": [b.hex() for b in j.branch],
        "stratum_prev": P.stratum_prevhash(j.prev),
        "version": "%08x" % j.version,
        "header": hdr.hex(),
        "block_sha256d": P.sha256d(blk).hex(),
        "block_len": len(blk),
    }
    bad = [k for k in py if py[k] != rust.get(k)]
    ok_all &= not bad
    print("%-15s height %d, %d txs, %d branches, block %d bytes: %s" % (
        name, py["height"], len(tpl["transactions"]), len(py["branch"]), py["block_len"],
        "ALL MATCH" if not bad else "MISMATCH in " + ", ".join(bad)))
    for k in bad:
        print("   %s\n     py   %s\n     rust %s" % (k, str(py[k])[:120], str(rust.get(k))[:120]))
print("RESULT:", "PASS" if ok_all else "FAIL")
sys.exit(0 if ok_all else 1)
