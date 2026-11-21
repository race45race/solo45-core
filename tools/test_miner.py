#!/usr/bin/env python3
"""Live test for Solo45 Core's Stratum V1 server.

Run the pool with a tiny difficulty first, e.g.
  SOLO45_STRATUM_PORT=3346 SOLO45_START_DIFF=0.00001 SOLO45_MIN_DIFF=0.00001 SOLO45_TEMPLATE_REFRESH_S=10 \
  SOLO45_DEFAULT_ADDRESS=bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 SOLO45_DATA_DIR=/tmp/s45core target/release/solo45-core serve
then: python3 tools/test_miner.py [host] [port]
(the address is BIP 173's example address; set S45_PAYOUT_ADDR and S45_PAYOUT_SPK to test with another one)

The miner decodes mining.notify on its own (no pool code), mines real shares in Python and checks every reply,
including the bad-share cases. Exit code 0 = all checks passed.
"""
import hashlib, json, os, socket, struct, sys, time

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 3346
OWNER = os.environ.get("S45_PAYOUT_ADDR", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")  # the pool's default address
OWNER_SPK = os.environ.get("S45_PAYOUT_SPK", "0014751e76e8199196d454941c45d1b3a323f1433bd6")  # ... and its script
DIFF1 = 0xFFFF << 208
results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(("PASS " if ok else "FAIL ") + name + (f"  ({detail})" if detail else ""), flush=True)


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


class Client:
    def __init__(self):
        self.s = socket.create_connection((HOST, PORT), timeout=15)
        self.buf = b""
        self.next_id = 1
        self.notes = []  # notifications received (method, params)
        self.diff = None
        self.job = None

    def send_raw(self, data):
        self.s.sendall(data)

    def _line(self, timeout):
        self.s.settimeout(timeout)
        while b"\n" not in self.buf:
            chunk = self.s.recv(65536)
            if not chunk:
                raise ConnectionError("closed")
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return json.loads(line)

    def _note(self, m):
        self.notes.append((m["method"], m["params"]))
        if m["method"] == "mining.set_difficulty":
            self.diff = m["params"][0]
        elif m["method"] == "mining.notify":
            self.job = m["params"]

    def call(self, method, params, timeout=15):
        i = self.next_id
        self.next_id += 1
        self.send_raw((json.dumps({"id": i, "method": method, "params": params}) + "\n").encode())
        while True:
            m = self._line(timeout)
            if m.get("id") == i and "method" not in m:
                return m
            if m.get("method"):
                self._note(m)

    def wait_note(self, method, timeout):
        end = time.time() + timeout
        while time.time() < end:
            try:
                m = self._line(max(0.1, end - time.time()))
            except socket.timeout:
                break
            if m.get("method"):
                self._note(m)
                if m["method"] == method:
                    return m["params"]
        return None

    def closed_within(self, timeout):
        self.s.settimeout(timeout)
        try:
            while True:
                if not self.s.recv(65536):
                    return True
        except socket.timeout:
            return False
        except OSError:
            return True


def header_for(job, en1, en2, ntime, nonce, version):
    jid, prev, cb1, cb2, branch, ver, nbits, curtime, clean = job
    coinbase = bytes.fromhex(cb1) + en1 + en2 + bytes.fromhex(cb2)
    root = sha256d(coinbase)
    for h in branch:
        root = sha256d(root + bytes.fromhex(h))
    p = bytes.fromhex(prev)
    prev_internal = b"".join(p[i:i + 4][::-1] for i in range(0, 32, 4))
    return struct.pack("<I", version) + prev_internal + root + struct.pack("<I", ntime) + \
        struct.pack("<I", int(nbits, 16)) + struct.pack("<I", nonce)


def share_diff(hdr):
    v = int.from_bytes(sha256d(hdr), "little")
    return DIFF1 / v if v else float("inf")


def mine(job, en1, en2, version, diff, start=0):
    ntime = int(job[7], 16)
    pre = header_for(job, en1, en2, ntime, 0, version)[:76]
    target = int(DIFF1 / diff)
    for nonce in range(start, start + 50_000_000):
        h = sha256d(pre + struct.pack("<I", nonce))
        if int.from_bytes(h, "little") <= target:
            return ntime, nonce
    raise RuntimeError("no share found")


def submit(c, job, en2, ntime, nonce, version_bits=None, job_id=None):
    p = ["test." + "miner", job_id or job[0], en2.hex(), "%08x" % ntime, "%08x" % nonce]
    if version_bits is not None:
        p.append("%08x" % version_bits)
    return c.call("mining.submit", p)


def err_code(r):
    return r["error"][0] if r.get("error") else None


def main():
    t0 = time.time()
    # --- a normal miner ---
    c = Client()
    r = c.call("mining.subscribe", ["solo45-test-miner/1.0"])
    en1 = bytes.fromhex(r["result"][1])
    check("subscribe gives a 4-byte extranonce1 and extranonce2 size 8", len(en1) == 4 and r["result"][2] == 8, r["result"][1:])
    r = c.call("mining.configure", [["version-rolling"], {"version-rolling.mask": "ffffffff"}])
    check("configure grants version rolling with mask 1fffe000",
          r["result"].get("version-rolling") is True and r["result"].get("version-rolling.mask") == "1fffe000", r["result"])
    r = c.call("mining.submit", ["x", "1", "00" * 8, "00000000", "00000000"])
    check("submit before authorize = error 24", err_code(r) == 24, r["error"])
    r = c.call("mining.authorize", ["Bitaxe-test.miner", "x"])
    check("authorize with a plain name falls back to the default address", r["result"] is True, r)
    job = c.job or c.wait_note("mining.notify", 5) and c.job
    check("set_difficulty and a clean job follow authorize", c.diff is not None and job is not None and job[8] is True,
          f"diff {c.diff}")
    check("coinbase pays the default address", OWNER_SPK in job[3])
    height = int.from_bytes(bytes.fromhex(job[2])[43:43 + bytes.fromhex(job[2])[42]], "little")
    check("coinbase holds a plausible BIP34 height", 900_000 < height < 2_000_000, height)
    d = c.diff
    base = int(job[5], 16)

    # a real share with rolled version bits
    en2 = bytes(range(1, 9))
    vbits = 0x00004000
    version = (base & ~0x1fffe000) | vbits
    t = time.time()
    ntime, nonce = mine(job, en1, en2, version, d)
    hd = share_diff(header_for(job, en1, en2, ntime, nonce, version))
    r = submit(c, job, en2, ntime, nonce, vbits)
    check("a valid share with rolled version bits is accepted", r["result"] is True and r["error"] is None,
          f"share diff {hd:.6g} vs {d}, mined in {time.time() - t:.2f} s")
    r = submit(c, job, en2, ntime, nonce, vbits)
    check("the same share again = error 22 duplicate", err_code(r) == 22, r["error"])

    # a second valid share without version rolling (en2 differs)
    en2b = bytes(8)
    ntime2, nonce2 = mine(job, en1, en2b, base, d)
    r = submit(c, job, en2b, ntime2, nonce2)
    check("a valid share without version bits is accepted", r["result"] is True, r)

    # low difficulty: find a nonce that does NOT meet the difficulty
    en2c = b"\x11" * 8
    ntime3 = int(job[7], 16)
    pre = header_for(job, en1, en2c, ntime3, 0, base)[:76]
    target = int(DIFF1 / d)
    low = next(n for n in range(10**6) if int.from_bytes(sha256d(pre + struct.pack("<I", n)), "little") > target)
    r = submit(c, job, en2c, ntime3, low)
    check("a share under the difficulty = error 23", err_code(r) == 23, r["error"])
    r = submit(c, job, en2c, ntime3, low)
    check("a low share is not remembered (resubmit is still 23, not 22)", err_code(r) == 23, r["error"])

    r = submit(c, job, en2, ntime, nonce, 0xe0000000)
    check("version bits outside the mask = error 20 Invalid version bits",
          err_code(r) == 20 and "version" in r["error"][1].lower(), r["error"])
    r = submit(c, job, en2, 1, nonce)
    check("ntime far in the past = error 20", err_code(r) == 20 and "ntime" in r["error"][1].lower(), r["error"])
    r = submit(c, job, en2, int(time.time()) + 8000, nonce)
    check("ntime over 7000 s ahead = error 20", err_code(r) == 20, r["error"])
    r = submit(c, job, en2, ntime, nonce, job_id="nosuchjob")
    check("unknown job id = error 21", err_code(r) == 21, r["error"])
    r = c.call("mining.submit", ["t", job[0], "00" * 6, "%08x" % ntime, "%08x" % nonce])
    check("extranonce2 of the wrong size = error 20", err_code(r) == 20, r["error"])
    r = c.call("mining.submit", ["t", job[0], "zz" * 8, "%08x" % ntime, "%08x" % nonce])
    check("non-hex extranonce2 = error 20", err_code(r) == 20, r["error"])
    r = c.call("mining.submit", ["t", job[0], "00" * 8, "%08x" % ntime, "1%08x" % nonce])
    check("nonce over 32 bits = error 20", err_code(r) == 20, r["error"])
    r = c.call("mining.submit", ["t"])
    check("submit with missing params = error 20", err_code(r) == 20, r["error"])
    r = c.call("mining.no_such_method", [])
    check("unknown method = error 20", err_code(r) == 20, r["error"])
    r = c.call("mining.extranonce.subscribe", [])
    check("extranonce.subscribe answers true", r["result"] is True)
    n_before = len(c.notes)
    r = c.call("mining.suggest_difficulty", [0.00002])
    got = c.wait_note("mining.set_difficulty", 3)
    check("suggest_difficulty after authorize sends a new set_difficulty", r["result"] is True and got is not None, got)

    # template refresh (SOLO45_TEMPLATE_REFRESH_S=10 in the test): a new job arrives on its own
    t = time.time()
    nj = c.wait_note("mining.notify", 40)
    check("a new job is pushed without asking", nj is not None and nj[0] != job[0],
          f"after {time.time() - t:.1f} s, clean={nj[8] if nj else None}")
    if nj:
        r = submit(c, job, en2b, ntime2, nonce2 ^ 1)  # old job is still known (same block): low/dup handling, not 21
        check("the previous job of the same block is still known", err_code(r) in (None, 23), r)

    # --- payout address in the username ---
    c2 = Client()
    c2.call("mining.subscribe", [])
    r = c2.call("mining.authorize", [OWNER + ".rig2", ""])
    j2 = c2.job or c2.wait_note("mining.notify", 5)
    check("authorize with an address in the username pays that address", r["result"] is True and OWNER_SPK in c2.job[3])
    r = c2.call("mining.authorize", ["bc1qjunkjunkjunkjunkjunkjunkjunkjunkjunk.x", "d=5000"])
    check("a junk address that looks plausible still authorizes (falls back to default)", r["result"] is True, r)

    # --- too many authorize attempts ---
    c3 = Client()
    c3.call("mining.subscribe", [])
    codes = [err_code(c3.call("mining.authorize", ["w%d" % i, "x"])) for i in range(11)]
    check("the 11th authorize = error 24", codes[:10] == [None] * 10 and codes[10] == 24, codes)

    # --- junk lines before authorize ---
    c4 = Client()
    c4.send_raw(b"this is not json\n" * 25)
    check("20+ junk lines before authorize closes the connection", c4.closed_within(5))

    # --- a line over 64 KB ---
    c5 = Client()
    c5.send_raw(b"{" + b"a" * 70_000)
    check("a line over 64 KB closes the connection", c5.closed_within(5))

    # --- a line split across packets still works ---
    c6 = Client()
    msg = (json.dumps({"id": 7, "method": "mining.subscribe", "params": []}) + "\n").encode()
    c6.send_raw(msg[:10]); time.sleep(0.3); c6.send_raw(msg[10:])
    m = c6._line(5)
    check("a request split across two packets is answered", m.get("id") == 7 and m.get("result"), m)

    # --- many connections at once ---
    many = [Client() for _ in range(50)]
    ok = 0
    for cl in many:
        if cl.call("mining.subscribe", [])["result"]:
            ok += 1
    subs = {cl.call("mining.subscribe", [])["result"][1] for cl in many}
    check("50 connections at once all subscribe with unique extranonce1", ok == 50 and len(subs) == 50, f"{ok}, {len(subs)} unique")

    passed = sum(1 for _, ok in results if ok)
    print(f"\n{passed}/{len(results)} checks passed in {time.time() - t0:.1f} s")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
