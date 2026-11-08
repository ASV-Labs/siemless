"""Regression tests from the first live run on the MacBook (Nov 8, 2026, 7d395c3).

Hermes's web_extract refused http://127.0.0.1:8787/page (private address), so the model fetched the
same page with ``curl`` in the terminal, and that is how the injected text reached it. SIEMless
recorded the egress but never marked the curl output as untrusted content, so the injection-marker
scan never saw the text that carried the attack. It also recorded the *blocked* web_extract as
untrusted content entering the context, which it did not.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from conftest import load_plugin_package  # noqa: E402

PLUG = load_plugin_package()
COL = importlib.import_module(PLUG.__name__ + ".siemless_core.collectors")
PAGE = (Path(__file__).resolve().parents[1] / "demo" / "lab" / "injection_page.html").read_text()


def _events(tool, args, status="ok", result="ok"):
    payload = {"session_id": "live1", "turn_id": "t1", "tool_name": tool, "args": args, "status": status, "result": result}
    return COL.collect("post_tool_call", payload, config={})


def _untrusted(evs):
    return [e for e in evs if e.kind == "content.untrusted"]


def test_shell_fetch_is_untrusted_content_and_scanned_for_injection():
    evs = _events("terminal", {"command": 'curl -sS -L --max-time 15 "http://127.0.0.1:8787/page"'}, result=PAGE)
    u = _untrusted(evs)
    assert len(u) == 1, [e.kind for e in evs]
    assert "untrusted:shell_fetch" in u[0].tags
    assert u[0].visibility == "inferred"
    assert u[0].host == "127.0.0.1"
    assert "untrusted:injection_markers" in u[0].tags, u[0].tags
    assert any(e.kind == "net.egress" for e in evs)


def test_wget_and_python_fetch_are_untrusted_too():
    py = 'python3 -c "import urllib.request as u; print(u.urlopen(\'https://example.com/x\').read())"'
    for cmd in ("wget -qO- https://example.com/notes", py):
        assert _untrusted(_events("terminal", {"command": cmd})), cmd


def test_failed_shell_fetch_is_not_untrusted_content():
    evs = _events("terminal", {"command": "curl -sS http://127.0.0.1:8787/page"}, status="error", result="curl: (7) Failed to connect")
    assert not _untrusted(evs)
    assert any(e.kind == "net.egress" for e in evs)  # the attempt is still recorded


def test_blocked_web_extract_is_egress_attempt_not_untrusted_content():
    evs = _events("web_extract", {"urls": ["http://127.0.0.1:8787/page"]}, status="error",
                  result="Blocked: URL targets a private or internal network address")
    assert not _untrusted(evs)
    eg = [e for e in evs if e.kind == "net.egress"]
    assert eg and eg[0].visibility == "inferred"


def test_successful_web_extract_still_untrusted():
    assert _untrusted(_events("web_extract", {"url": "https://example.com/a"}, result=PAGE))


def test_shell_without_url_is_not_untrusted_content():
    assert not _untrusted(_events("terminal", {"command": "ls -la ~/Projects"}))
    assert not _untrusted(_events("terminal", {"command": "ssh deploy@example.com uptime"}))
