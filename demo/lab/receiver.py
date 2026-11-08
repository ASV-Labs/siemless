#!/usr/bin/env python3
"""The demo lab's one local server. Three jobs, all on 127.0.0.1:

* ``GET /page``       serves the injection page (demo/lab/injection_page.html) with the demo home
                      path substituted in, so the injected instruction names a real fixture file;
* ``POST /collect``   the "attacker's" endpoint: records that something was posted (size and a
                      SHA-256 of the body, never the body) to ``collect.log`` under ``$SIEMLESS_DEMO_OUT`` (default ``$TMPDIR/siemless-demo``);
* ``POST /ingest``    a stand-in for The Summit: accepts SIEMless's receiver contract
                      (``Authorization: Bearer <token>``; ``{"events": [...], "findings": [...]}``)
                      and appends to ``summit.log`` so the demo can show "the same finding on the wall".

Nothing here leaves the machine, and nothing here stores what was sent to /collect.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOKEN = os.environ.get("SIEMLESS_DEMO_TOKEN", "siemless-demo-token")


class Handler(BaseHTTPRequestHandler):
    server_version = "siemless-demo/0.1"
    demo_home = str(HERE / "fake_home")
    demo_port = 8787
    # Logs live outside the plugin tree, so a packaged copy that ran the demo never ships them.
    logs = Path(os.environ.get("SIEMLESS_DEMO_OUT") or (Path(tempfile.gettempdir()) / "siemless-demo"))
    timeout = 10  # seconds per connection: a client that stalls cannot hold a handler thread

    def log_message(self, fmt, *args):  # quieter
        sys.stderr.write("[receiver] %s\n" % (fmt % args))

    def _send(self, code: int, body: bytes, ctype: str = "application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/page"):
            html = (HERE / "injection_page.html").read_text(encoding="utf-8").replace("SIEMLESS_DEMO_HOME", self.demo_home).replace("SIEMLESS_DEMO_PORT", str(self.demo_port))
            return self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
        if self.path.startswith("/summit"):
            lines = (self.logs / "summit.log").read_text().splitlines() if (self.logs / "summit.log").exists() else []
            return self._send(200, ("\n".join(lines[-50:]) + "\n").encode(), "text/plain")
        if self.path.startswith("/collect"):
            lines = (self.logs / "collect.log").read_text().splitlines() if (self.logs / "collect.log").exists() else []
            return self._send(200, ("\n".join(lines[-50:]) + "\n").encode(), "text/plain")
        return self._send(404, b'{"error":"not found"}')

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self._send(400, b'{"error":"bad content-length"}')
        if n < 0 or n > 5 * 1024 * 1024:
            return self._send(413 if n > 0 else 400, b'{"error":"bad content-length"}')
        body = self.rfile.read(n) if n else b""
        self.logs.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.startswith("/collect"):
            rec = {"t": int(time.time() * 1000), "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()[:16],
                   "ua": self.headers.get("User-Agent", "")[:60]}
            with open(self.logs / "collect.log", "a") as fh:
                fh.write(json.dumps(rec) + "\n")
            sys.stderr.write(f"[receiver] /collect received {len(body)} bytes (not stored)\n")
            return self._send(200, b'{"ok":true}')
        if self.path.startswith("/ingest"):
            if self.headers.get("Authorization") != f"Bearer {TOKEN}":
                return self._send(401, b'{"error":"bad token"}')
            try:
                payload = json.loads(body.decode("utf-8"))
            except ValueError:
                return self._send(400, b'{"error":"bad json"}')
            if not isinstance(payload, dict):
                return self._send(400, b'{"error":"body must be a JSON object"}')
            findings = [f for f in (payload.get("findings") or []) if isinstance(f, dict)] if isinstance(payload.get("findings"), list) else []
            events = payload.get("events") if isinstance(payload.get("events"), list) else []
            with open(self.logs / "summit.log", "a") as fh:
                for f in findings:
                    attack = [a.get("id") for a in (f.get("attack") or []) if isinstance(a, dict)] if isinstance(f.get("attack"), list) else []
                    fh.write(json.dumps({"t": int(time.time() * 1000), "rule": f.get("rule_id"), "severity": f.get("severity"),
                                         "confidence": f.get("confidence"), "title": f.get("title"), "session": f.get("session_id"),
                                         "replay": bool(f.get("replay")), "attack": attack}) + "\n")
                    sev = str(f.get("severity") or "?").upper()
                    tag = " [REPLAY]" if f.get("replay") else ""
                    sys.stderr.write(f"[summit] {sev:8} {f.get('rule_id')} {f.get('title')}{tag}\n")
                fh.write(json.dumps({"t": int(time.time() * 1000), "events": len(events)}) + "\n")
            return self._send(202, b'{"accepted":true}')
        return self._send(404, b'{"error":"not found"}')


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--home", default=str(HERE / "fake_home"), help="the fixture home the injection names")
    a = ap.parse_args()
    Handler.demo_home = str(Path(a.home).resolve())
    Handler.demo_port = a.port
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    print(f"siemless demo receiver on http://127.0.0.1:{a.port}  (page: /page, collector: /collect, summit stand-in: /ingest)")
    print(f"fixture home: {Handler.demo_home}")
    print(f"logs: {Handler.logs}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
