#!/usr/bin/env python3
"""Test stand-in between Solo45 Core and the regtest node: answers the first N submitblock calls with bitcoind's
"still starting up" error (RPC code -28), then forwards everything to the real node.
  python3 tools/rpc_warmup_proxy.py <listen port> <node port> <how many -28 answers>
"""
import http.server, json, sys, urllib.request

LISTEN, NODE, FAILS = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
left = [FAILS]


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        req = json.loads(body)
        if req.get("method") == "submitblock" and left[0] > 0:
            left[0] -= 1
            out = json.dumps({"result": None, "id": req.get("id"),
                              "error": {"code": -28, "message": "Loading block index..."}}).encode()
            print("answered submitblock with -28", flush=True)
            status = 500
        else:
            r = urllib.request.Request(f"http://127.0.0.1:{NODE}/", body,
                                       {"Authorization": self.headers["Authorization"], "Content-Type": "text/plain"})
            try:
                with urllib.request.urlopen(r, timeout=60) as resp:
                    status, out = resp.status, resp.read()
            except urllib.error.HTTPError as e:
                status, out = e.code, e.read()
            if req.get("method") == "submitblock":
                print("forwarded submitblock:", out[:80], flush=True)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


http.server.ThreadingHTTPServer(("127.0.0.1", LISTEN), H).serve_forever()
