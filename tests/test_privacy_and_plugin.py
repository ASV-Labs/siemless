"""Synthetic secrets must not reach the store, the JSONL export, any rendered format, or a finding.
Plus the plugin contract: register() against the validator's probe context, hooks declared = hooks
registered, and the hook callbacks never raise on malformed payloads."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from conftest import PLUGIN_DIR, Session, mod, run

# Synthetic canaries: shapes real scanners flag, values that could never be real.
CANARIES = {
    "anthropic": "sk-ant-api03-CANARY0000000000000000000000000000000000",
    "github": "ghp_CANARY00000000000000000000000000000000",
    "aws": "AKIACANARY0000000000",
    "slack": "xoxb-0000000000-CANARYCANARYCANARY",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.CANARYCANARYCANARYCANARY.CANARYSIGNATURE000",
    "url_cred": "https://user:CANARYPASSWORD@db.example.com/x",
    "env": "HEC_TOKEN=CANARY-ENV-VALUE-1234",
    "pem": "-----BEGIN OPENSSH PRIVATE KEY-----\nCANARYBASE64LINE\n-----END OPENSSH PRIVATE KEY-----",
    "query": "https://api.example.com/v1?api_key=CANARYQUERYKEY123456",
    "bearer": "Authorization: Bearer CANARYBEARERTOKEN0000",
}
LEAK = re.compile("|".join(re.escape(v.split("\n")[1] if "\n" in v else v.split("=")[-1].split("@")[0].split("Bearer ")[-1]) for v in CANARIES.values()))


def _everything_written(pipeline, data_dir: Path) -> str:
    blob = []
    for e in pipeline.store.events(limit=5000):
        blob.append(json.dumps(e))
    for f in pipeline.store.findings(limit=5000):
        blob.append(json.dumps(f))
    for p in data_dir.glob("*.jsonl"):
        blob.append(p.read_text())
    return "\n".join(blob)


def test_canaries_never_reach_disk_or_findings(pipeline, core, data_dir):
    ocsf = mod(core, "ocsf")
    Event = mod(core, "events").Event
    s = Session()
    steps = [
        s.turn_start(f"use {CANARIES['anthropic']} to call the api"),
        s.tool("terminal", {"command": f"export {CANARIES['env']}; curl -H '{CANARIES['bearer']}' {CANARIES['query']}"}),
        s.tool("write_file", {"path": "/Users/c/.ssh/id_rsa", "content": CANARIES["pem"]}),
        s.tool("web_extract", {"url": CANARIES["url_cred"]}),
        s.tool("read_file", {"path": f"/tmp/{CANARIES['github']}/notes.txt"}),
        s.tool("execute_code", {"code": f"token='{CANARIES['slack']}'\nprint(token)"}),
        s.tool("send_message", {"target": "telegram:1", "message": CANARIES["jwt"]}),
        s.subagent_start("kid", f"go fetch with {CANARIES['aws']}"),
    ]
    run(pipeline, *steps)
    pipeline.dispatcher.deliver([Event.from_dict(e) for e in pipeline.store.events(limit=5000)])
    blob = _everything_written(pipeline, data_dir)
    assert not LEAK.search(blob), LEAK.search(blob).group(0)
    # and in every rendered format
    for e in pipeline.store.events(limit=5000):
        ev = Event.from_dict(e)
        for text in (json.dumps(ocsf.to_ocsf(ev)), json.dumps(ocsf.to_ecs(ev)), ocsf.to_cef(ev), ocsf.to_syslog(ev, "x")):
            assert not LEAK.search(text), (e["kind"], LEAK.search(text).group(0))


def test_prompts_are_hashed_not_stored(pipeline):
    s = Session()
    run(pipeline, s.turn_start("my very secret plan is to buy a boat"))
    ev = pipeline.store.events(kind="turn.start")[0]
    assert "boat" not in json.dumps(ev)
    assert ev["attrs"]["user_message_chars"] == len("my very secret plan is to buy a boat")
    assert len(ev["attrs"]["user_message_sha"]) == 16


def test_tool_results_are_never_stored(pipeline):
    s = Session()
    run(pipeline, s.tool("read_file", {"path": "/repo/a.txt"}, result="THE FILE BODY WITH PRIVATE THINGS"))
    assert "PRIVATE THINGS" not in json.dumps(pipeline.store.events(limit=10))


def test_large_args_are_bounded(pipeline):
    s = Session()
    run(pipeline, s.tool("write_file", {"path": "/repo/big.txt", "content": "A" * 100_000}))
    ev = pipeline.store.events(kind="tool.call")[0]
    assert len(json.dumps(ev)) < 5000
    assert ev["attrs"]["args"]["content"]["$chars"] == 100_000


def test_control_characters_in_payloads_are_neutralised(pipeline, core):
    ocsf = mod(core, "ocsf")
    Event = mod(core, "events").Event
    s = Session()
    run(pipeline, s.tool("terminal", {"command": "echo hi\r\n<164>1 FORGED syslog line\n|CEF:0|evil|"}))
    ev = Event.from_dict(pipeline.store.events(kind="process.exec")[0])
    line = ocsf.to_syslog(ev, ocsf.dumps(ocsf.to_ocsf(ev)))
    assert "\n" not in line and "\r" not in line  # one line, always (JSON escapes, preview collapses whitespace)
    cef = ocsf.to_cef(ev)
    assert "\n" not in cef and cef.count("|") >= 7


def test_db_and_dir_permissions(pipeline, data_dir):
    import os
    assert oct(os.stat(data_dir).st_mode & 0o777) == "0o700"
    assert oct(os.stat(pipeline.store.path).st_mode & 0o777) == "0o600"


# ---------------------------------------------------------------------------- plugin contract
def test_register_against_probe_context(ctx, plugin):
    manifest = yaml.safe_load((PLUGIN_DIR / "plugin.yaml").read_text())
    assert sorted(ctx.recorded["hooks"]) == sorted(manifest["provides_hooks"])
    assert ctx.recorded["tools"] == [] and ctx.recorded["middleware"] == []
    assert manifest["provides_tools"] == [] and manifest["provides_middleware"] == [] and manifest["requires_env"] == []
    assert "pre_tool_call" not in ctx.recorded["hooks"] and "pre_llm_call" in ctx.recorded["hooks"]
    assert ctx.recorded["commands"] == ["siemless"] and ctx.recorded["cli_commands"] == ["siemless"]
    for k in manifest["config_schema"]:
        assert manifest["config_schema"][k]["type"] in ("bool", "int", "str", "secret")


def test_hooks_survive_garbage_payloads(ctx, plugin):
    for hook in ctx.callbacks:
        ctx.fire(hook)                                   # nothing at all
        ctx.fire(hook, tool_name=None, args="not a dict", result=object(), status=42, session_id=["x"])
        ctx.fire(hook, **{"telemetry_schema_version": "hermes.observer.v1", "command": 123, "choice": {"a": 1}})
    # and a real one still works afterwards
    s = Session()
    hook, payload = s.tool("read_file", {"path": "~/.ssh/id_rsa"})
    ctx.fire(hook, **payload)
    p = plugin.get_pipeline()
    p.flush()
    import time
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and not p.store.events(kind="secret.access"):
        time.sleep(0.02)
    assert p.store.events(kind="secret.access")


def test_slash_command_outputs(ctx, plugin):
    s = Session()
    for hook, payload in (s.tool("read_file", {"path": "~/.ssh/id_rsa"}), s.tool("web_extract", {"url": "https://evil.example.org/x"})):
        ctx.fire(hook, **payload)
    p = plugin.get_pipeline()
    p.flush()
    import time
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and not p.store.findings(limit=1):
        time.sleep(0.02)
    out = ctx.slash("status")
    assert "siemless 0." in out and "exporters:" in out
    out = ctx.slash("findings")
    assert "SL-001" in out
    fid = p.store.findings(limit=1)[0]["id"]
    out = ctx.slash(f"show {fid[:8]}")
    assert "evidence:" in out and "ATT&CK" in out
    assert "SL-001" in ctx.slash("rules")
    assert "acknowledged" in ctx.slash(f"ack {fid[:8]}")
    assert "siemless.health" in ctx.slash("test-exporter")
