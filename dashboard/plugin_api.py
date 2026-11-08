"""Backend for the SIEMless Desktop page. Mounted by Hermes at ``/api/plugins/siemless/``.

Read-mostly: status, findings, one finding with its evidence chain, events, rules, hosts, exporter
health. Writes are three explicit clicks: ack a finding, send one test event through the exporters,
replay a fixture. Nothing here reads prompts or secrets; it serves what the store already holds.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

router = APIRouter()

_CORE_NAME = "hermes_plugin_siemless_core_api"


def _core():
    """Load ../siemless_core as a package of our own name (plugin_api.py is imported standalone)."""
    mod = sys.modules.get(_CORE_NAME)
    if mod is not None:
        return mod
    root = Path(__file__).resolve().parent.parent / "siemless_core"
    spec = importlib.util.spec_from_file_location(_CORE_NAME, root / "__init__.py", submodule_search_locations=[str(root)])
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_CORE_NAME] = mod
    spec.loader.exec_module(mod)
    return mod


_RO: dict = {}  # one read-mostly pipeline per profile data dir
_RO_MAX = 16


def _pipeline():
    """A read-mostly pipeline over the same store as the agent half (its own process may differ).

    Keyed by the *current* profile's data directory: one dashboard process can serve several
    profiles (Hermes binds each request to its profile's home), and a cached instance must never
    show one profile's findings to another. Status and health come from the store, which the agent
    half keeps current; test-exporter and replay run through this instance's own dispatcher and
    engine, against that profile's configuration."""
    _core()
    store_mod = importlib.import_module(f"{_CORE_NAME}.store")
    data_dir = store_mod.default_data_dir().resolve()
    key = str(data_dir)
    p = _RO.get(key)
    if p is None:
        pipeline_mod = importlib.import_module(f"{_CORE_NAME}.pipeline")
        config_mod = importlib.import_module(f"{_CORE_NAME}.config")
        p = pipeline_mod.Pipeline(config_mod.load(_hermes_ctx()), data_dir=data_dir, worker=False)
        if len(_RO) >= _RO_MAX:
            _RO.pop(next(iter(_RO))).close()
        _RO[key] = p
    return p


def _hermes_ctx():
    """Plugin config through Hermes's own loader when available (the dashboard half has no ctx)."""
    try:
        from hermes_cli.config import load_config  # type: ignore  # documented config reader

        entries = ((load_config() or {}).get("plugins") or {}).get("entries") or {}
        entry = entries.get("siemless") or {}
        cfg = dict(entry.get("config") or {})
        cfg.update(entry.get("settings") or {})

        class _Ctx:
            def get_config(self, key, default=None):
                return cfg.get(key, default)

        return _Ctx()
    except Exception:
        return None


def _store():
    return _pipeline().store


@router.get("/health")
def health():
    core = _core()
    return {"ok": True, "plugin": core.PLUGIN_ID, "version": core.__version__}


@router.get("/status")
def status():
    return _pipeline().status()


@router.get("/findings")
def findings(limit: int = Query(50, ge=1, le=500), rule_id: Optional[str] = None, session_id: Optional[str] = None,
             since: Optional[int] = None, include_acked: bool = True):
    return {"findings": _store().findings(limit=limit, rule_id=rule_id, session_id=session_id, since=since, include_acked=include_acked)}


@router.get("/finding")
def finding(id: str = Query(...)):
    f = _store().finding(id)
    if not f:
        for cand in _store().findings(limit=500):
            if cand["id"].startswith(id):
                f = cand
                break
    if not f:
        raise HTTPException(status_code=404, detail=f"no finding {id!r}")
    ids = [e["id"] for e in f.get("evidence", [])]
    full = {e["id"]: e for e in _store().events(ids=ids, limit=len(ids) or 1)} if ids else {}
    chain = [full.get(i) or e for i, e in zip(ids, f.get("evidence", []))]
    # context: the session's events around the finding
    ctx_events = _store().events(session_id=f.get("session_id"), limit=60) if f.get("session_id") else []
    return {"finding": f, "chain": chain, "context": ctx_events}


class AckBody(BaseModel):
    id: str
    acked: bool = True


@router.post("/finding/ack")
def ack(body: AckBody):
    ok = _store().ack_finding(body.id, body.acked)
    if not ok:
        raise HTTPException(status_code=404, detail=f"no finding {body.id!r}")
    return {"ok": True}


@router.get("/events")
def events(limit: int = Query(100, ge=1, le=2000), kind: Optional[str] = None, session_id: Optional[str] = None, since: Optional[int] = None):
    return {"events": _store().events(limit=limit, kind=kind, session_id=session_id, since=since)}


@router.get("/rules")
def rules():
    return {"rules": _pipeline().engine.rule_table(), "attack_version": importlib.import_module(f"{_CORE_NAME}.attack").version()}


@router.get("/hosts")
def hosts(limit: int = Query(200, ge=1, le=5000)):
    return {"hosts": _store().hosts(limit)}


@router.get("/exporters")
def exporters():
    p = _pipeline()
    return {"exporters": p.exporter_health(), "queue": p.dispatcher.queue_health(), "remote_export": bool(p.config.get("remote_export"))}


@router.post("/exporters/test")
def test_exporters():
    p = _pipeline()
    commands = importlib.import_module(f"{_CORE_NAME}.commands")
    text = commands.dispatch(p, ["test-exporter"])
    return {"ok": True, "text": text, "exporters": p.dispatcher.health()}


class ReplayBody(BaseModel):
    path: str


@router.post("/replay")
def replay(body: ReplayBody):
    p = _pipeline()
    path = Path(body.path).expanduser()
    allowed_roots = [Path(__file__).resolve().parent.parent / "demo", p.data_dir]
    try:
        rp = path.resolve()
    except OSError:
        raise HTTPException(status_code=400, detail="bad path")
    if not any(rp.is_relative_to(r.resolve()) for r in allowed_roots) or not rp.is_file():
        raise HTTPException(status_code=400, detail="replay fixtures must live under the plugin's demo/ folder or its data dir")
    commands = importlib.import_module(f"{_CORE_NAME}.commands")
    r = commands.replay(p, rp)
    r["findings"] = r["findings"][:50]
    return r


@router.get("/fixtures")
def fixtures():
    demo = Path(__file__).resolve().parent.parent / "demo"
    out = []
    for f in sorted(demo.glob("**/*.jsonl")):
        out.append({"name": f.name, "path": str(f), "bytes": f.stat().st_size})
    return {"fixtures": out}
