"""Cross-check Solo45 Core's template policy against Solo45's policy.py on the same live block template.

Runs both on a fresh template under several configs (filter, watch, mixed, fee rules at several rates) and compares
which transactions are left out and why (in order), the fee/weight totals, the watch counts, and the template that
filtering produces (reward, witness commitment, renumbered depends). Exit 0 only if everything matches.
usage: python3 tools/crosscheck_policy.py  (env SOLO45_DATA_DIR for pool.py's config; run from ~/solo45-core)
"""
import copy
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.expanduser("~/solo45-app/src"))
import pool as P  # noqa: E402
import policy  # noqa: E402

cfg = P.load_config()
rpc = P.RPC(cfg["rpc_url"], cfg["rpc_cookie"], cfg["rpc_user"], cfg["rpc_pass"])
tpl = rpc.call("getblocktemplate", {"rules": ["segwit"]})
path = "/tmp/xp-template.json"
with open(path, "w") as f:
    json.dump(tpl, f)


def config(mode, **rules):
    c = copy.deepcopy(policy.DEFAULTS)
    c["mode"] = mode
    for name, change in rules.items():
        c["rules"][name].update(change)
    return c


CASES = [
    ("filter, defaults", config("filter")),
    ("watch, defaults", config("watch")),
    ("filter, OP_RETURN 42, fee 2 sat/vB", config("filter", opreturn={"max_bytes": 42}, minfee={"on": True, "sat_vb": 2})),
    ("filter, fee 5 sat/vB only", config("filter", inscriptions={"on": False}, opreturn={"on": False},
                                         baremultisig={"on": False}, runes={"on": False}, minfee={"on": True, "sat_vb": 5})),
    ("filter, fee 20 sat/vB, runes watch", config("filter", runes={"watch": True}, minfee={"on": True, "sat_vb": 20})),
    ("filter, all on, fee 1.5 watch", config("filter", minfee={"on": True, "watch": True, "sat_vb": 1.5})),
]

ok_all = True
print("template height %d, %d txs" % (tpl["height"], len(tpl["transactions"])))
for name, c in CASES:
    cpath = "/tmp/xp-config.json"
    with open(cpath, "w") as f:
        json.dump(c, f)
    rust = json.loads(subprocess.check_output(["./target/release/solo45-core", "policy", path, cpath]))
    t0 = time.time()
    rep = policy.evaluate(tpl, c)
    py_ms = (time.time() - t0) * 1000
    new = policy.apply(tpl, rep)
    py = {
        "skip": [[n, r] for n, r in rep["skip"].items()],
        "fees_skipped": rep["fees_skipped"], "weight_skipped": rep["weight_skipped"], "by_rule": rep["by_rule"],
        "watched": rep["watched"], "fees_watched": rep["fees_watched"], "watch_by_rule": rep["watch_by_rule"],
        "coinbasevalue": new["coinbasevalue"], "default_witness_commitment": new.get("default_witness_commitment"),
        "depends": [t.get("depends", []) for t in new["transactions"]],
    }
    bad = [k for k in py if py[k] != rust.get(k)]
    ok_all &= not bad
    print("%-38s skip %4d (%s), watch %4d: %s  [python %.0f ms, rust %.1f ms]" % (
        name, len(py["skip"]), ", ".join("%s %d" % (k, v["txs"]) for k, v in py["by_rule"].items()) or "-",
        py["watched"], "MATCH" if not bad else "MISMATCH in " + ", ".join(bad), py_ms, rust["ms"]))
    for k in bad:
        print("   %s\n     py   %s\n     rust %s" % (k, str(py[k])[:160], str(rust.get(k))[:160]))
print("RESULT:", "PASS" if ok_all else "FAIL")
sys.exit(0 if ok_all else 1)
