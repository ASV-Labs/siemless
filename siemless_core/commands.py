"""``/siemless`` slash command and ``hermes siemless`` CLI. Read-mostly; the only writes are
``ack`` (mark a finding seen), ``test-exporter`` (send one synthetic health event) and ``replay``
(run a recorded fixture through the pipeline, labelled as a replay).
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Callable, Optional

from . import __version__
from .events import Event

HELP = """siemless {v} — agent security telemetry
  /siemless status                 pipeline, queue and exporter health
  /siemless findings [N] [rule]    latest findings (default 10)
  /siemless show <finding-id>      one finding with its evidence chain
  /siemless tail [N] [kind]        latest events
  /siemless rules                  the baseline ruleset
  /siemless hosts                  destinations seen (baseline)
  /siemless ack <finding-id>       mark a finding as reviewed
  /siemless test-exporter          send one synthetic siemless.health event through every exporter
  /siemless replay <fixture.jsonl> run a recorded session through the detections (labelled replay)
"""


def _fmt_time(ms: Optional[int]) -> str:
    if not ms:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ms / 1000))


def status_text(st: dict) -> str:
    lines = [f"siemless {st['version']} · profile {st.get('profile') or 'default'} · host {st.get('hostname')}",
             f"events processed {st['processed']} (24h: {st['events_24h']}), dropped before queue {st['dropped_in']}",
             f"findings {st['findings_total']} total; 24h by severity: {st['findings_24h'] or {}}",
             f"rules enabled {st['rules']['enabled']} · evaluations {st['rules']['evaluations']} · suppressed {st['rules']['suppressed']}",
             f"correlator sessions {st['correlator']['sessions']} · window {st['correlator']['window_ms'] // 60000} min · hosts known {st['hosts_known']}",
             f"queue {st['queue']['size']}/{st['queue']['capacity']} · dropped {st['queue']['dropped']} · worker {'alive' if st['queue']['worker_alive'] else 'STOPPED'}",
             f"export scope {st['export_scope']} · remote export {'ON' if st['remote_export'] else 'off (consent not given)'}",
             f"detection latency p50 {st['latency_ms']['p50']} ms · p95 {st['latency_ms']['p95']} ms (n={st['latency_ms']['n']})",
             "exporters:"]
    for ex in st["exporters"]:
        extra = ex.get("target") or ex.get("url") or ex.get("events_path") or ""
        lines.append(f"  {ex['name']:8} {ex['state']:13} sent {ex['sent']:>6} failed {ex['failed']:>4} dropped {ex['dropped']:>4} "
                     f"spooled {ex['spooled']:>4}  {extra}" + (f"  last error: {ex['last_error']}" if ex.get("last_error") else ""))
    return "\n".join(lines)


def findings_text(items: list[dict]) -> str:
    if not items:
        return "no findings"
    out = []
    for f in items:
        out.append(f"{_fmt_time(f['time'])}  {f['severity']:8} {f['confidence']:6} {f['rule_id']}  {f['title']}  [{f['id'][:8]}]"
                   + ("  ✓" if f.get("acked") else ""))
    return "\n".join(out)


def finding_text(f: dict) -> str:
    lines = [f"{f['rule_id']} {f['rule_name']} — {f['severity']} / confidence {f['confidence']}  id {f['id']}",
             f"when: {_fmt_time(f['time'])}   session {f.get('session_id')}   turn {f.get('turn_id')}",
             f"title: {f['title']}", f"observed: {f['observed']}", f"why: {f['why']}",
             f"ATT&CK: {', '.join(a['id'] + ' ' + a['name'] for a in f['attack']) or 'none (see note)'}"]
    if f.get("attack_note"):
        lines.append(f"note: {f['attack_note']}")
    lines.append(f"visibility: {f['visibility'].get('observed', 0)} observed, {f['visibility'].get('inferred', 0)} inferred")
    lines.append("evidence:")
    for e in f["evidence"]:
        lines.append(f"  {_fmt_time(e['time'])}  {e['visibility']:8} {e['kind']:18} {e.get('tool') or '':14} {e.get('target') or e.get('host') or ''}")
    if f.get("missing_evidence"):
        lines.append("not visible: " + " ".join(f["missing_evidence"]))
    lines.append(f"recommendation: {f['recommendation']}")
    return "\n".join(lines)


def tail_text(items: list[dict]) -> str:
    if not items:
        return "no events"
    out = []
    for e in items:
        out.append(f"{_fmt_time(e['time'])}  {e['visibility'][:3]} {e['severity']:6} {e['kind']:18} {e.get('tool') or '':14} "
                   f"{(e.get('target') or e.get('host') or '')[:80]}  {' '.join(e.get('tags') or [])[:60]}")
    return "\n".join(out)


def rules_text(table: list[dict]) -> str:
    out = []
    for r in table:
        if not r.get("enabled", True):
            out.append(f"{r['id']}  (disabled)")
            continue
        out.append(f"{r['id']}  {r['severity']:8} {r['name']}\n      on {', '.join(r['triggers'])}; ATT&CK {', '.join(r['attack']) or 'none'}")
    return "\n".join(out)


def replay(pipeline, path: Path) -> dict:
    """Run a recorded fixture (JSONL of {"hook":..., "payload":...}) through the full pipeline."""
    n = 0
    findings: list[dict] = []
    t0 = time.monotonic()
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            payload = dict(rec.get("payload") or {})
            payload.setdefault("_replay", True)
            _, fds = pipeline.process_now(rec["hook"], payload)
            n += 1
            findings += fds
    return {"records": n, "findings": findings, "elapsed_ms": int((time.monotonic() - t0) * 1000), "replay": True}


def dispatch(pipeline, args: list[str], *, cwd: Optional[str] = None) -> str:
    cmd = (args[0] if args else "status").lower()
    rest = args[1:]
    store = pipeline.store
    if cmd in ("help", "-h", "--help"):
        return HELP.format(v=__version__)
    if cmd == "status":
        return status_text(pipeline.status())
    if cmd == "findings":
        n = int(rest[0]) if rest and rest[0].isdigit() else 10
        rule = next((r for r in rest if r.upper().startswith("SL-")), None)
        return findings_text(store.findings(limit=n, rule_id=rule.upper() if rule else None))
    if cmd == "show" and rest:
        f = _find(store, rest[0])
        return finding_text(f) if f else f"no finding matching {rest[0]!r}"
    if cmd == "tail":
        n = int(rest[0]) if rest and rest[0].isdigit() else 20
        kind = next((r for r in rest if "." in r), None)
        return tail_text(store.events(limit=n, kind=kind))
    if cmd == "rules":
        return rules_text(pipeline.engine.rule_table())
    if cmd == "hosts":
        hs = store.hosts(50)
        return "\n".join(f"{_fmt_time(h['first_seen'])}  {h['count']:>5}  {h['host']}" for h in hs) or "no destinations recorded"
    if cmd == "ack" and rest:
        f = _find(store, rest[0])
        if not f:
            return f"no finding matching {rest[0]!r}"
        store.ack_finding(f["id"], True)
        _audit(pipeline, "ack", f"{f['rule_id']} {f['id']}")
        return f"acknowledged {f['rule_id']} {f['title']}"
    if cmd == "test-exporter":
        ev = Event(kind="siemless.health", visibility="observed", severity="info", target="test-exporter",
                   attrs={"note": "synthetic event from /siemless test-exporter", **pipeline.dispatcher.queue_health()},
                   profile=pipeline.profile)
        store.add_events([ev])
        pipeline.dispatcher.deliver([ev])
        return "sent one siemless.health event\n" + status_text(pipeline.status())
    if cmd == "replay" and rest:
        p = Path(rest[0])
        if not p.is_absolute() and cwd:
            p = Path(cwd) / p
        if not p.exists():
            return f"no such fixture: {p}"
        _audit(pipeline, "replay", str(p)[-200:])
        r = replay(pipeline, p)
        head = f"replayed {r['records']} records in {r['elapsed_ms']} ms → {len(r['findings'])} finding(s)  [REPLAY, not live]"
        return head + ("\n" + findings_text(r["findings"]) if r["findings"] else "")
    return HELP.format(v=__version__)


def _audit(pipeline, action: str, target: str) -> None:
    """Every ack and replay leaves an audit event in the store and the export stream, whoever ran it:
    the agent can reach this CLI through its terminal, so these are never silent."""
    try:
        ev = Event(kind="command", visibility="observed", severity="low", action=f"siemless_{action}", target=target,
                   tags=["siemless:audit", f"siemless:{action}"], profile=pipeline.profile)
        pipeline.process_event(ev)
    except Exception:
        pass


def _find(store, ref: str) -> Optional[dict]:
    f = store.finding(ref)
    if f:
        return f
    for cand in store.findings(limit=500):
        if cand["id"].startswith(ref):
            return cand
    return None


# ----------------------------------------------------------------------------- CLI plumbing
def cli_setup(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("words", nargs="*", help="status | findings [N] [rule] | show <id> | tail [N] [kind] | rules | hosts | ack <id> | test-exporter | replay <file>")
    parser.add_argument("--json", action="store_true", help="machine-readable output where available")


def cli_handler(args: argparse.Namespace, *, pipeline_factory: Callable[[], Any]) -> int:
    pipeline = pipeline_factory()
    words = list(getattr(args, "words", []) or [])
    if getattr(args, "json", False):
        cmd = (words[0] if words else "status").lower()
        if cmd == "status":
            print(json.dumps(pipeline.status(), indent=2, default=str))
        elif cmd == "findings":
            print(json.dumps(pipeline.store.findings(limit=int(words[1]) if len(words) > 1 and words[1].isdigit() else 10), indent=2))
        elif cmd == "rules":
            print(json.dumps(pipeline.engine.rule_table(), indent=2))
        elif cmd == "replay" and len(words) > 1:
            print(json.dumps(replay(pipeline, Path(words[1])), indent=2, default=str))
        else:
            print(json.dumps({"error": "no json form for this command"}))
        return 0
    print(dispatch(pipeline, words))
    return 0


__all__ = ["dispatch", "cli_setup", "cli_handler", "replay", "HELP"]
