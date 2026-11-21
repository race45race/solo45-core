#!/usr/bin/env python3
"""Milestone 3 live test: the HTTP API, settings, per-miner overrides and the node's block check.

Run the pool as for test_miner.py, plus SOLO45_API_PORT=3386 SOLO45_API_TOKEN=<token> and BITCOIN_ZMQ_HASHBLOCK, then:
  python3 tools/test_m3.py <lan-ip-of-this-machine> <token>
"""
import json, os, sys, time, urllib.request, urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.argv = [sys.argv[0]] + sys.argv[1:]
LAN_IP, TOKEN = sys.argv[1], sys.argv[2]
sys.argv = [sys.argv[0]]  # test_miner reads host/port from argv: use its defaults (127.0.0.1:3346)
import test_miner as tm  # noqa: E402

tm.PORT = int(os.environ.get("S45_PORT", "3346"))
API_PORT = int(os.environ.get("S45_API_PORT", "3386"))
API = f"http://127.0.0.1:{API_PORT}"
OWNER = tm.OWNER
check = tm.check


def req(method, path, body=None, base=API, token=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(base + path, data=data, method=method)
    if token:
        r.add_header("X-Solo45-Token", token)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def snap():
    return req("GET", "/api")[1]


def main():
    s = snap()
    p = s["pool"]
    check("snapshot has the template", p["height"] and p["txs"] >= 0 and p["network_diff"] > 1e13,
          f"height {p['height']}, {p['txs']} txs, network diff {p['network_diff']:.4g}")
    check("block signal (ZMQ) connected", p.get("zmq") is True)
    for _ in range(30):
        if s["pool"]["proposal"].get("ok") is not None:
            break
        time.sleep(1)
        s = snap()
    pr = s["pool"]["proposal"]
    check("the node's block check passed", pr.get("ok") is True, pr)
    check("timing has the check time", s["pool"]["timing"]["check_ms"] is not None, s["pool"]["timing"])

    c = tm.Client()
    c.call("mining.subscribe", ["m3-test/1.0"])
    c.call("mining.authorize", ["Bitaxe-test.m3test", "x"])
    job = c.job or c.wait_note("mining.notify", 5) and c.job
    en1 = None
    # the en1 is in the subscribe reply; ask again on a fresh id
    en1 = bytes.fromhex(c.call("mining.subscribe", ["m3-test/1.0"])["result"][1])
    names = [w["name"] for w in snap()["workers"]]
    check("the miner shows in the worker list by name", "m3test" in names, names)

    en2 = bytes(range(8))
    ntime, nonce = tm.mine(job, en1, en2, int(job[5], 16), c.diff)
    r = tm.submit(c, job, en2, ntime, nonce)
    check("a share is accepted", r["result"] is True, r)
    s = snap()
    w = next(w for w in s["workers"] if w["name"] == "m3test")
    check("the worker's accepted count and best show it", w["accepted"] == 1 and w["best"] > 0, (w["accepted"], w["best"]))
    check("the pool's accepted count and best show it", s["pool"]["accepted"] >= 1 and s["pool"]["best"]["diff"] > 0)
    sh = req("GET", "/api/shares?since=0")[1]["shares"]
    check("the live share feed has it", any(x["worker"] == "m3test" and x["rejected"] is None for x in sh), len(sh))
    last = max(x["seq"] for x in sh)
    dups = snap()["pool"]["rejected"].get("duplicate", 0)
    r = tm.submit(c, job, en2, ntime, nonce)  # duplicate: rejected and shown in the feed
    sh2 = req("GET", f"/api/shares?since={last}")[1]["shares"]
    check("a rejected share shows in the feed (since=)", [x["rejected"] for x in sh2] == ["duplicate"], sh2)
    check("the pool's reject counter has it", snap()["pool"]["rejected"].get("duplicate") == dups + 1)

    st, rep = req("POST", "/api/worker", {"name": "m3test", "diff": 0.00005})
    got = c.wait_note("mining.set_difficulty", 3)
    check("a fixed difficulty from the API reaches the miner", st == 200 and got == [0.00005], (st, rep, got))
    w = next(w for w in snap()["workers"] if w["name"] == "m3test")
    check("the snapshot shows the override", w["override"] == {"diff": 0.00005} and w["diff"] == 0.00005, w["override"])
    r = c.call("mining.suggest_difficulty", [0.00001])
    c.wait_note("mining.set_difficulty", 2)
    check("suggest_difficulty can't undo a fixed difficulty", c.diff == 0.00005, c.diff)
    st, _ = req("POST", "/api/worker", {"name": "m3test", "diff": 5e12})
    check("a difficulty over 1e9 is refused", st == 400)
    st, rep = req("POST", "/api/worker", {"name": "m3test"})
    check("the override can be removed (automatic)", st == 200 and rep["override"] == {}, rep)
    st, _ = req("POST", "/api/worker", {"diff": 1})
    check("an override without a name is refused", st == 400)

    st, _ = req("POST", "/api/settings", {"empty_hold_s": 99})
    check("an empty hold over 40 s is refused", st == 400)
    st, rep = req("POST", "/api/settings", {"empty_hold_s": 8, "template_refresh_s": 10})
    check("settings change at once", st == 200 and rep["empty_hold_s"] == 8 and rep["template_refresh_s"] == 10, rep)
    st, _ = req("POST", "/api/settings", {"empty_first": "yes"})
    check("empty_first must be true or false", st == 400)
    st, _ = req("POST", "/api/settings", {"nothing": 1})
    check("a settings call with nothing to change is refused", st == 400)
    st, _ = req("POST", "/api/payout", {"address": "notanaddress"})
    check("an invalid payout address is refused", st == 400)
    st, rep = req("POST", "/api/payout", {"address": OWNER})
    check("a valid payout address is accepted", st == 200 and rep["address"] == OWNER, rep)
    ex = req("GET", "/api/export")[1]
    check("the export has the settings", ex["settings"].get("empty_hold_s") == 8 and ex["settings"].get("default_address") == OWNER, ex["settings"])
    check("an unknown path is 404", req("GET", "/api/nope")[0] == 404)
    check("an unknown method is 405", req("DELETE", "/api")[0] == 405)

    # stall guard settings (the guard itself: tools/test_stallguard.py)
    check("the stall guard is on by default (60 s)", snap()["pool"]["stall_guard"]["seconds"] == 60, snap()["pool"]["stall_guard"])
    st, _ = req("POST", "/api/settings", {"stall_guard_s": 15})
    check("a stall guard under 20 s is refused", st == 400)
    st, rep = req("POST", "/api/settings", {"stall_guard_s": 0})
    check("the stall guard can be turned off", st == 200 and rep["stall_guard_s"] == 0 and snap()["pool"]["stall_guard"]["seconds"] == 0)
    req("POST", "/api/settings", {"stall_guard_s": 60})

    # template policy: watch counts, filter leaves transactions out and the node still accepts the block
    pol = snap()["pool"]["policy"]
    check("the policy starts in watch mode with pool.py's rules", pol["mode"] == "watch" and set(pol["rules"]) ==
          {"inscriptions", "opreturn", "baremultisig", "runes", "minfee"}, pol["mode"])
    st, _ = req("POST", "/api/policy", {"mode": "loud"})
    check("an unknown policy mode is refused", st == 400)
    st, _ = req("POST", "/api/policy", {"rules": {"minfee": {"sat_vb": 5000}}})
    check("a fee rule over 1,000 sat/vB is refused", st == 400)
    node_txs = snap()["pool"]["txs"]
    t_change = time.time()
    st, rep = req("POST", "/api/policy", {"mode": "filter"})
    check("filter mode is accepted", st == 200 and rep["mode"] == "filter", st)
    cur = None
    for _ in range(40):
        time.sleep(1)
        s = snap()
        cur = s["pool"]["policy"]["current"]
        if cur and cur.get("filtered") and cur["at"] > t_change:
            break
    check("the next job leaves the counted transactions out", cur and cur.get("filtered") and cur["skipped"] > 0
          and s["pool"]["txs"] < max(node_txs, cur["txs"]), cur and (cur["skipped"], cur["txs"], s["pool"]["txs"]))
    ok = None
    for _ in range(120):
        pr = snap()["pool"]["proposal"]
        if pr.get("at", 0) > cur["at"] if cur else 0:
            ok = pr.get("ok")
            break
        time.sleep(1)
    check("the node's block check accepts the filtered job", ok is True, snap()["pool"]["proposal"])
    st, rep = req("POST", "/api/policy", {"mode": "watch"})
    check("back to watch mode", st == 200 and rep["mode"] == "watch")

    # backup and restore
    ex = req("GET", "/api/export")[1]
    check("the export has the policy", ex["policy"]["mode"] == "watch" and "rules" in ex["policy"])
    ex["overrides"]["restored-miner"] = {"share_seconds": 7}
    ex["last_diff"]["restored-miner"] = [1234.5, time.time()]
    ex["policy"]["rules"]["opreturn"]["max_bytes"] = 80
    st, rep = req("POST", "/api/restore", ex)
    check("a backup restores every part", st == 200 and rep["ok"] and not rep["errors"], rep)
    e2 = req("GET", "/api/export")[1]
    check("restored values are in effect", e2["overrides"].get("restored-miner") == {"share_seconds": 7}
          and e2["last_diff"]["restored-miner"][0] == 1234.5 and e2["policy"]["rules"]["opreturn"]["max_bytes"] == 80)
    st, rep = req("POST", "/api/restore", {"settings": {"default_address": "notanaddress", "empty_hold_s": 9}})
    check("a bad part is reported and the rest restored", st == 200 and not rep["ok"] and len(rep["errors"]) == 1
          and any("job timing" in d for d in rep["restored"]), rep)
    ex["policy"]["rules"]["opreturn"]["max_bytes"] = 83
    req("POST", "/api/restore", {"policy": ex["policy"]})

    base = f"http://{LAN_IP}:{API_PORT}"
    check("another machine without the token gets 403", req("GET", "/api", base=base)[0] == 403)
    check("a wrong token gets 403", req("GET", "/api", base=base, token="wrong")[0] == 403)
    st, body = req("GET", "/api", base=base, token=TOKEN)
    check("the right token gets the snapshot", st == 200 and "pool" in body)

    passed = sum(1 for _, ok in tm.results if ok)
    print(f"\n{passed}/{len(tm.results)} checks passed")
    return 0 if passed == len(tm.results) else 1


if __name__ == "__main__":
    sys.exit(main())
