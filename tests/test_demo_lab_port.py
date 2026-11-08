"""Regression test from the Nov 8, 2026 live run on the MacBook.

Another app held 127.0.0.1:8787, so the receiver had to move with ``--port``. The injection page
still told the agent to POST to port 8787, which is someone else's server, so the demo's "attacker"
endpoint was never the receiver that served the page.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

RECEIVER = Path(__file__).resolve().parents[1] / "demo" / "lab" / "receiver.py"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _get_page(port: int) -> str:
    last = None
    for _ in range(50):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/page", timeout=1) as resp:
                return resp.read().decode("utf-8")
        except OSError as exc:
            last = exc
            time.sleep(0.1)
    raise AssertionError(f"receiver never answered: {last}")


def test_page_names_the_collector_on_the_receivers_own_port(tmp_path):
    port = _free_port()
    env = {"SIEMLESS_DEMO_OUT": str(tmp_path / "out"), "PATH": "/usr/bin:/bin"}
    proc = subprocess.Popen([sys.executable, "-I", str(RECEIVER), "--port", str(port)],
                            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        page = _get_page(port)
    finally:
        proc.terminate()
        proc.wait(timeout=5)
    assert f"http://127.0.0.1:{port}/collect" in page
    assert "SIEMLESS_DEMO_PORT" not in page
    if port != 8787:
        assert "8787" not in page
