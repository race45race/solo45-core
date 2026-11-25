#!/usr/bin/env python3
"""Solo45 Core stall guard, end to end, against the private regtest node (start it with tools/regtest.sh start).

A stand-in sits between Core and the node and forwards every call, except that while a "stall" is switched on it
reports the node one block behind the announced chain (headers = blocks + 1) with three made-up peers: one has the
missing block in flight, one has nothing in flight, one has an older block. disconnectnode is answered by the
stand-in and recorded. Core runs on spare ports with a 20 s guard.
  python3 tools/test_stallguard.py
Checks: nothing happens before 20 s; then only the peer holding the block is dropped; the event is in the API and
state.json; the next round (after the 30 s cooldown) treats "already gone" (-29) calmly; with no peer holding the
block it logs one note and drops nobody; a caught-up node resets the clock.
"""
import http.server, json, os, subprocess, sys, threading, time, urllib.request

NODE_PORT, PROXY_PORT, STRATUM, API = 18543, 18549, 3349, 3389
CORE = os.path.expanduser("~/solo45-core/target/release/solo45-core")
DATA = os.path.expanduser("~/solo45-test/core-stallguard")
NODE_DIR = os.path.expanduser("~/solo45-test/regtest-node")
state = {"stall": False, "holder": True, "gone": False, "disconnects": [], "since": None}
results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + name + (f"  ({detail})" if detail != "" else ""), flush=True)


class Proxy(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def reply(self, status, obj):
        out = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def forward(self, body):
        r = urllib.request.Request(f"http://127.0.0.1:{NODE_PORT}/", body,
                                   {"Authorization": self.headers["Authorization"], "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(r, timeout=60) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        req = json.loads(body)
        m, rid = req.get("method"), req.get("id")
        if m == "disconnectnode":
            state["disconnects"].append((time.time(), req["params"]))
            if state["gone"]:
                return self.reply(500, {"result": None, "id": rid, "error": {"code": -29, "message": "Node not found in connected nodes"}})
            return self.reply(200, {"result": None, "id": rid, "error": None})
        status, out = self.forward(body)
        if state["stall"] and m == "getblockchaininfo" and out.get("result"):
            out["result"]["headers"] = out["result"]["blocks"] + 1
        if state["stall"] and m == "getpeerinfo" and out.get("result") is not None:
            b = state["blocks"]
            fake = [{"id": 9002, "network": "ipv4", "inbound": True, "inflight": []},
                    {"id": 9003, "network": "onion", "inbound": False, "inflight": [b - 5]}]
            if state["holder"]:
                fake.insert(0, {"id": 9001, "network": "ipv4", "inbound": False, "inflight": [b + 1]})
            out["result"] = out["result"] + fake
        self.reply(status, out)


def cli(*a):
    return subprocess.run([os.path.expanduser("~/solo45-test/bitcoin-32.1/bin/bitcoin-cli"), "-regtest",
                           f"-datadir={NODE_DIR}", "-rpcport=18543", *a], capture_output=True, text=True).stdout.strip()


def api():
    return json.load(urllib.request.urlopen(f"http://127.0.0.1:{API}/api", timeout=10))


def log_text():
    try:
        return open(os.path.join(DATA, "pool.log")).read()
    except FileNotFoundError:
        return ""  # Core hasn't written its first line yet


def wait_for(pred, secs):
    end = time.time() + secs
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.5)
    return False


def main():
    os.makedirs(DATA, exist_ok=True)
    for f in ("state.json", "state.json.bak", "pool.log"):
        p = os.path.join(DATA, f)
        if os.path.exists(p):
            os.replace(p, p + ".old")
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", PROXY_PORT), Proxy)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    addr = open(os.path.expanduser("~/solo45-test/core-regtest/address.txt")).read().strip()
    env = dict(os.environ, SOLO45_STRATUM_PORT=str(STRATUM), SOLO45_API_PORT=str(API), SOLO45_DATA_DIR=DATA,
               SOLO45_LOG_FILE=os.path.join(DATA, "pool.log"), SOLO45_STALL_GUARD_S="20", SOLO45_DEFAULT_ADDRESS=addr,
               BITCOIN_RPC_URL=f"http://127.0.0.1:{PROXY_PORT}/", BITCOIN_RPC_COOKIE=os.path.join(NODE_DIR, "regtest/.cookie"))
    core = subprocess.Popen([CORE, "serve"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        check("Core started through the stand-in", wait_for(lambda: "Solo45 SV2" in log_text(), 15))
        check("the guard is set to 20 s", api()["pool"]["stall_guard"]["seconds"] == 20)

        # 1. a peer holds up the next block
        state["blocks"] = int(cli("getblockcount"))
        t0 = time.time()
        state["stall"] = True
        time.sleep(15)
        check("nothing happens before the limit", not state["disconnects"], state["disconnects"])
        got = wait_for(lambda: state["disconnects"], 25)
        waited = (state["disconnects"][0][0] - t0) if got else None
        check("after ~20 s the peer holding the block is dropped", got and 19 <= waited <= 32, f"{waited and round(waited, 1)} s")
        time.sleep(1)
        ids = [p[1] for _, p in state["disconnects"]]
        check("only that peer (not the idle one, not the one with an old block)", ids == [9001], state["disconnects"])
        check("the log says why", "stall guard: block %d was announced over 20 s ago but peer 9001 (ipv4, outbound)"
              % (state["blocks"] + 1) in log_text())
        ev = api()["pool"]["stall_guard"]["events"]
        check("the event is in the API", len(ev) == 1 and ev[0]["height"] == state["blocks"] + 1
              and ev[0]["peers"] == ["peer 9001 (ipv4, outbound)"], ev)
        st = json.load(open(os.path.join(DATA, "state.json")))
        check("and saved in state.json", len(st.get("stall_events", [])) == 1)

        # 2. still stuck after the 30 s cooldown; this time the peer is already gone (Solo45's guard got it first)
        state["gone"] = True
        got = wait_for(lambda: len(state["disconnects"]) >= 2, 40)
        gap = state["disconnects"][1][0] - state["disconnects"][0][0] if got else None
        check("the next round waits for the 30 s cooldown", got and 29 <= gap <= 40, f"{gap and round(gap, 1)} s")
        time.sleep(1)
        check("an already-gone peer is logged calmly, not as a failure",
              "peer 9001 (ipv4, outbound) was already disconnected" in log_text() and "couldn't disconnect" not in log_text())

        # 3. the block arrives: the clock resets
        state["stall"] = False
        time.sleep(7)
        n = len(state["disconnects"])
        state["holder"], state["gone"] = False, False
        state["stall"] = True
        t1 = time.time()
        time.sleep(17)
        check("a caught-up node resets the clock (no action 17 s into a new stall)", len(state["disconnects"]) == n)
        # 4. nobody has the block in flight: one note, nobody dropped
        got = wait_for(lambda: "no peer has the block in flight" in log_text(), 20)
        check("with no peer holding the block it only notes it", got and len(state["disconnects"]) == n,
              f"after {round(time.time() - t1)} s")
        time.sleep(12)
        check("... once", log_text().count("no peer has the block in flight") == 1)
        state["stall"] = False
        check("Core kept mining throughout", api()["pool"]["height"] == state["blocks"] + 1)
    finally:
        core.terminate()
        core.wait(10)
        srv.shutdown()
    print(f"\n{sum(results)}/{len(results)} checks passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
