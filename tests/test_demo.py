"""Replay every recorded demo fixture and check the expectations the brief asks for."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import mod

FIX = Path(__file__).resolve().parents[1] / "demo" / "fixtures"
EXPECTED = json.loads((FIX / "expected.json").read_text())
ORDER = ["info", "low", "medium", "high", "critical"]


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_fixture(name, core, data_dir):
    Pipeline = mod(core, "pipeline").Pipeline
    cfg = mod(core, "config").load(overrides={"finding_cooldown_s": 0, "watch_private_hosts": True})
    p = Pipeline(cfg, data_dir=data_dir, worker=False, store=mod(core, "store").Store(data_dir / f"{name}.db"))
    try:
        r = mod(core, "commands").replay(p, FIX / f"{name}.jsonl")
        exp = EXPECTED[name]
        got = {f["rule_id"] for f in r["findings"]}
        for rid in exp.get("rules", []):
            assert rid in got, f"{name}: expected {rid}, got {sorted(got)}"
        for rid in exp.get("not_rules", []):
            assert rid not in got, f"{name}: {rid} must not fire; got {sorted(got)}"
        for rid, sev in exp.get("min_severity", {}).items():
            assert ORDER.index(max((f["severity"] for f in r["findings"] if f["rule_id"] == rid), key=ORDER.index)) >= ORDER.index(sev)
        for rid, sev in exp.get("max_severity", {}).items():
            assert all(ORDER.index(f["severity"]) <= ORDER.index(sev) for f in r["findings"] if f["rule_id"] == rid)
        if exp.get("canaries"):
            Event = mod(core, "events").Event
            p.dispatcher.deliver([Event.from_dict(e) for e in p.store.events(limit=5000)])
            blob = "\n".join(json.dumps(e) for e in p.store.events(limit=5000)) + "\n".join(json.dumps(f) for f in p.store.findings(limit=100))
            for f in data_dir.glob("*.jsonl"):
                blob += f.read_text()
            for c in exp["canaries"]:
                assert c not in blob, f"{name}: canary {c} leaked"
        assert r["replay"] is True and r["records"] > 0
        # replayed payloads are marked so nobody mistakes them for live telemetry
        assert all(json.loads(l)["payload"].get("_replay") is None for l in (FIX / f"{name}.jsonl").read_text().splitlines())
    finally:
        p.close()


def test_exporter_down_during_detection(core, data_dir):
    """Variant 7: the destination dies mid-run; findings still land locally, the batch spools, health says so."""
    Pipeline = mod(core, "pipeline").Pipeline
    ExportError = mod(core, "exporters").ExportError
    cfg = mod(core, "config").load(overrides={"finding_cooldown_s": 0, "watch_private_hosts": True})
    p = Pipeline(cfg, data_dir=data_dir, worker=False, store=mod(core, "store").Store(data_dir / "v7.db"))

    class Dead:
        name, remote = "dead", False
        calls = 0

        def send(self, batch):
            self.calls += 1
            raise ExportError("connection refused")

        def close(self):
            pass

        def describe(self):
            return {"name": "dead", "remote": False, "format": "ocsf"}

    slot = p.dispatcher.add(Dead())
    r = mod(core, "commands").replay(p, FIX / "7_exporter_down.jsonl")
    assert any(f["rule_id"] == "SL-001" for f in r["findings"])
    Event = mod(core, "events").Event
    p.dispatcher.deliver([Event.from_dict(e) for e in p.store.events(limit=100)])
    assert slot.state == "retrying" and slot.spooled > 0 and slot.last_error
    assert p.store.findings(limit=5)  # local truth is intact
    health = {h["name"]: h for h in p.dispatcher.health()}
    assert health["dead"]["state"] == "retrying" and health["jsonl"]["state"] == "ok"
    p.close()
