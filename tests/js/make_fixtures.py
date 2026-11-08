#!/usr/bin/env python3
"""Regenerate tests/js/fixtures/*.json from a real replay, so the Desktop render test sees exactly
what dashboard/plugin_api.py returns. Run: python tests/js/make_fixtures.py"""
from __future__ import annotations

import importlib
import importlib.util
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("siemless_jsfix", ROOT / "__init__.py", submodule_search_locations=[str(ROOT)])
m = importlib.util.module_from_spec(spec)
m.__path__ = [str(ROOT)]
sys.modules["siemless_jsfix"] = m
spec.loader.exec_module(m)
P = importlib.import_module("siemless_jsfix.siemless_core.pipeline").Pipeline
C = importlib.import_module("siemless_jsfix.siemless_core.config")
S = importlib.import_module("siemless_jsfix.siemless_core.store").Store
cmds = importlib.import_module("siemless_jsfix.siemless_core.commands")

d = Path(tempfile.mkdtemp())
p = P(C.load(overrides={"finding_cooldown_s": 0, "watch_private_hosts": True}), data_dir=d, worker=False, store=S(d / "x.db"), profile="demo")
cmds.replay(p, ROOT / "demo" / "fixtures" / "6_subagent_carries_chain.jsonl")
out = Path(__file__).resolve().parent / "fixtures"
out.mkdir(exist_ok=True)
json.dump(p.status(), open(out / "status.json", "w"), indent=1, default=str)
fs = p.store.findings(limit=50)
json.dump({"findings": fs}, open(out / "findings.json", "w"), indent=1)
f = next(x for x in fs if x["rule_id"] == "SL-001")
ids = [e["id"] for e in f["evidence"]]
full = {e["id"]: e for e in p.store.events(ids=ids, limit=len(ids))}
json.dump({"finding": f, "chain": [full.get(i) or e for i, e in zip(ids, f["evidence"])],
           "context": p.store.events(session_id=f["session_id"], limit=60)}, open(out / "finding.json", "w"), indent=1)
json.dump({"events": p.store.events(limit=100)}, open(out / "events.json", "w"), indent=1)
json.dump({"exporters": p.dispatcher.health(), "queue": p.dispatcher.queue_health(), "remote_export": False}, open(out / "exporters.json", "w"), indent=1)
json.dump({"rules": p.engine.rule_table(), "attack_version": "20.1"}, open(out / "rules.json", "w"), indent=1)
p.close()
print("wrote", sorted(x.name for x in out.glob("*.json")))
