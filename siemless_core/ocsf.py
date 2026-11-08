"""Canonical event → OCSF, ECS, CEF and RFC 5424 syslog.

OCSF class choices are a table (``_CLASS``) so a correction from docs/RESEARCH.md is a one-line
change. The rules of the road:

* ``type_uid = class_uid * 100 + activity_id``;
* vendor attributes live under ``unmapped.siemless`` — never invented top-level fields;
* ``severity_id`` follows OCSF (1 Informational … 5 Critical), ``status_id`` 1 Success / 2 Failure;
* ``metadata.product`` names SIEMless and its version; ``metadata.version`` is the OCSF version
  the shape follows.
"""

from __future__ import annotations

import json
import re
import socket
import time
from datetime import datetime, timezone
from typing import Any, Optional

from . import PRODUCT, VENDOR, __version__
from .events import Event

OCSF_VERSION = "1.4.0"   # the schema version these shapes are validated against (see docs/RESEARCH.md)

# kind → (class_uid, class_name, category_uid, activity_id, activity_name)
# Activity ids follow each class's own enum; 99 = Other.
_CLASS: dict[str, tuple[int, str, int, int, str]] = {
    "session.start":    (6003, "API Activity", 6, 99, "Other"),
    "session.end":      (6003, "API Activity", 6, 99, "Other"),
    "session.reset":    (6003, "API Activity", 6, 99, "Other"),
    "session.delete":   (6003, "API Activity", 6, 4, "Delete"),
    "turn.start":       (6003, "API Activity", 6, 1, "Create"),
    "turn.end":         (6003, "API Activity", 6, 3, "Update"),
    "llm.request":      (6003, "API Activity", 6, 1, "Create"),
    "llm.response":     (6003, "API Activity", 6, 1, "Create"),
    "llm.error":        (6003, "API Activity", 6, 1, "Create"),
    "aux.call":         (6003, "API Activity", 6, 1, "Create"),
    "tool.call":        (6003, "API Activity", 6, 99, "Other"),
    "file.read":        (1001, "File System Activity", 1, 2, "Read"),
    "file.write":       (1001, "File System Activity", 1, 3, "Update"),
    "secret.access":    (1001, "File System Activity", 1, 2, "Read"),
    "process.exec":     (1007, "Process Activity", 1, 1, "Launch"),
    "net.egress":       (4001, "Network Activity", 4, 6, "Traffic"),
    "content.untrusted": (4002, "HTTP Activity", 4, 3, "Get"),
    "approval.request": (6003, "API Activity", 6, 99, "Other"),
    "approval.response": (6003, "API Activity", 6, 99, "Other"),
    "human_input":      (6003, "API Activity", 6, 99, "Other"),
    "subagent.start":   (1007, "Process Activity", 1, 1, "Launch"),
    "subagent.stop":    (1007, "Process Activity", 1, 2, "Terminate"),
    "cron.change":      (1006, "Scheduled Job Activity", 1, 1, "Create"),
    "plugin.change":    (6002, "Application Lifecycle", 6, 1, "Install"),
    "skill.change":     (6002, "Application Lifecycle", 6, 8, "Update"),
    "config.change":    (6003, "API Activity", 6, 3, "Update"),
    "command":          (6003, "API Activity", 6, 99, "Other"),
    "kanban.event":     (6003, "API Activity", 6, 99, "Other"),
    "finding":          (2004, "Detection Finding", 2, 1, "Create"),
    "siemless.health":  (6003, "API Activity", 6, 99, "Other"),
}
_CATEGORY_NAME = {1: "System Activity", 2: "Findings", 4: "Network Activity", 5: "Discovery", 6: "Application Activity"}
_SEVERITY_ID = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
_SEVERITY_NAME = {"info": "Informational", "low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"}

_CRON_ACTIVITY = {"create": 1, "add": 1, "update": 2, "edit": 2, "delete": 3, "remove": 3, "enable": 4, "resume": 4,
                  "disable": 5, "pause": 5, "run": 6, "start": 6}
_PLUGIN_ACTIVITY = {"install": 1, "remove": 2, "uninstall": 2, "start": 3, "stop": 4, "enable": 6, "disable": 7, "update": 8}


def _status(e: Event) -> tuple[int, str]:
    o = (e.outcome or "").lower()
    if o in ("ok", "allowed", "success", "completed"):
        return 1, "Success"
    if o in ("error", "denied", "blocked", "failed", "timeout", "cancelled"):
        return 2, "Failure"
    if not o:
        return 0, "Unknown"
    return 99, "Other"


def _iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _metadata(e: Event, *, hostname: Optional[str]) -> dict:
    md: dict[str, Any] = {
        "version": OCSF_VERSION,
        "product": {"name": PRODUCT, "vendor_name": VENDOR, "version": __version__, "feature": {"name": "observer-hooks"}},
        "uid": e.id,
        "logged_time": int(time.time() * 1000),
        "log_name": "hermes.observer.v1",
        "labels": list(e.tags)[:16],
    }
    if hostname:
        md["log_provider"] = hostname
    cid = {k: v for k, v in {"session_id": e.session_id, "turn_id": e.turn_id, "task_id": e.task_id,
                             "tool_call_id": e.tool_call_id, "api_request_id": e.api_request_id}.items() if v}
    if cid:
        md["correlation_uid"] = e.turn_id or e.session_id or e.id
    return md


def _actor(e: Event) -> dict:
    actor: dict[str, Any] = {"app_name": "hermes-agent"}
    if e.profile or e.session_id:
        actor["session"] = {k: v for k, v in {"uid": e.session_id, "uid_alt": e.turn_id}.items() if v}
    if e.subagent_id or e.child_session_id:
        actor["process"] = {"name": "hermes-subagent", "uid": e.subagent_id or e.child_session_id}
    if e.profile:
        actor["user"] = {"name": e.profile, "type": "Service"}
    return actor


def to_ocsf(e: Event, *, hostname: Optional[str] = None) -> dict:
    class_uid, class_name, cat_uid, act_id, act_name = _CLASS.get(e.kind, (6003, "API Activity", 6, 99, "Other"))
    if e.kind == "cron.change" and e.action:
        act_id = _CRON_ACTIVITY.get(e.action.lower(), 99)
        act_name = {1: "Create", 2: "Update", 3: "Delete", 4: "Enable", 5: "Disable", 6: "Start", 99: "Other"}[act_id]
    if e.kind == "plugin.change" and e.action:
        act_id = _PLUGIN_ACTIVITY.get(e.action.lower(), 99)
        act_name = {1: "Install", 2: "Remove", 3: "Start", 4: "Stop", 6: "Enable", 7: "Disable", 8: "Update", 99: "Other"}[act_id]
    status_id, status = _status(e)
    sev_id = _SEVERITY_ID.get(e.severity, 1)
    out: dict[str, Any] = {
        "class_uid": class_uid, "class_name": class_name,
        "category_uid": cat_uid, "category_name": _CATEGORY_NAME.get(cat_uid, "Other"),
        "activity_id": act_id, "activity_name": act_name,
        "type_uid": class_uid * 100 + act_id, "type_name": f"{class_name}: {act_name}",
        "time": e.time, "time_dt": _iso(e.time),
        "severity_id": sev_id, "severity": _SEVERITY_NAME.get(e.severity, "Informational"),
        "status_id": status_id, "status": status,
        "message": _message(e),
        "metadata": _metadata(e, hostname=hostname),
        "actor": _actor(e),
        "observables": _observables(e),
        "unmapped": {"siemless": {k: v for k, v in e.to_dict().items() if k not in ("id", "time", "schema")}},
    }
    if e.outcome:
        out["status_detail"] = e.outcome
    if hostname:
        out["device"] = {"hostname": hostname, "type_id": 0, "type": "Unknown"}

    # class-specific objects
    if class_uid == 6003:
        out["api"] = {"operation": e.action or e.kind, "service": {"name": e.tool or e.kind}}
        if e.kind in ("llm.response", "llm.error", "aux.call") and e.host:
            out["dst_endpoint"] = {"hostname": e.host}
    elif class_uid == 1001:
        out["file"] = {"path": e.target or "", "name": (e.target or "").rsplit("/", 1)[-1], "type_id": 1, "type": "Regular File"}
    elif class_uid == 1007:
        proc: dict[str, Any] = {"name": e.tool or "hermes", "cmd_line": e.target or ""} if e.kind == "process.exec" else \
            {"name": "hermes-subagent", "uid": e.subagent_id or e.child_session_id or ""}
        out["process"] = proc
    elif class_uid == 4001:
        out["dst_endpoint"] = {k: v for k, v in {"hostname": e.host, "port": (e.attrs.get("port") if isinstance(e.attrs.get("port"), int) else None)}.items() if v}
        out["connection_info"] = {"direction_id": 2, "direction": "Outbound", "protocol_name": "tcp"}
        if e.target and "://" in (e.target or ""):
            out["url"] = {"url_string": e.target, "hostname": e.host}
    elif class_uid == 4002:
        out["http_request"] = {"url": {"url_string": e.target or "", "hostname": e.host}, "http_method": "GET"}
        out["dst_endpoint"] = {"hostname": e.host} if e.host else {}
    elif class_uid == 1006:
        out["job"] = {"name": e.target or "scheduled job", "cmd_line": (e.attrs.get("schedule") or "")}
    elif class_uid == 6002:
        out["app"] = {"name": e.target or "plugin"}
    elif class_uid == 2004:
        attack = [{"technique": {"uid": a}} for a in (e.attrs.get("attack") or [])]
        out["finding_info"] = {"uid": e.attrs.get("finding_id") or e.id, "title": e.target or "finding",
                               "analytic": {"type_id": 1, "type": "Rule", "name": (e.rule_ids or ["?"])[0], "uid": (e.rule_ids or ["?"])[0]},
                               "related_events": [{"uid": x} for x in e.evidence[:32]]}
        if attack:
            out["finding_info"]["attacks"] = attack
        out["confidence"] = str(e.attrs.get("confidence") or "")
        out["confidence_id"] = {"low": 1, "medium": 2, "high": 3}.get(str(e.attrs.get("confidence")), 0)
    return out


def _message(e: Event) -> str:
    bits = [e.kind]
    if e.tool:
        bits.append(e.tool)
    if e.action:
        bits.append(e.action)
    if e.target:
        bits.append(e.target[:120])
    elif e.host:
        bits.append(e.host)
    if e.outcome:
        bits.append(f"[{e.outcome}]")
    return " ".join(bits)


def _observables(e: Event) -> list[dict]:
    obs: list[dict] = []
    if e.host:
        obs.append({"name": "dst_endpoint.hostname", "type_id": 1, "type": "Hostname", "value": e.host})
    if e.kind in ("file.read", "file.write", "secret.access") and e.target:
        obs.append({"name": "file.path", "type_id": 9, "type": "File Name", "value": e.target})
    if e.kind == "process.exec" and e.target:
        obs.append({"name": "process.cmd_line", "type_id": 13, "type": "Command Line", "value": e.target})
    if e.target and e.kind in ("net.egress", "content.untrusted") and "://" in e.target:
        obs.append({"name": "url.url_string", "type_id": 6, "type": "URL String", "value": e.target})
    return obs[:8]


# ------------------------------------------------------------------------------------------ ECS
ECS_VERSION = "8.17.0"

_ECS_CAT = {
    "file.read": (["file"], ["access"]), "file.write": (["file"], ["change"]), "secret.access": (["file"], ["access"]),
    "process.exec": (["process"], ["start"]), "net.egress": (["network"], ["connection"]),
    "content.untrusted": (["web"], ["access"]), "approval.request": (["iam"], ["info"]), "approval.response": (["iam"], ["change"]),
    "subagent.start": (["process"], ["start"]), "subagent.stop": (["process"], ["end"]), "cron.change": (["configuration"], ["creation"]),
    "plugin.change": (["package"], ["installation"]), "skill.change": (["package"], ["change"]), "config.change": (["configuration"], ["change"]),
    "finding": (["intrusion_detection"], ["indicator"]), "llm.response": (["api"], ["info"]), "aux.call": (["api"], ["info"]),
}


def to_ecs(e: Event, *, hostname: Optional[str] = None) -> dict:
    cat, typ = _ECS_CAT.get(e.kind, (["process"], ["info"]))
    status_id, _ = _status(e)
    doc: dict[str, Any] = {
        "@timestamp": _iso(e.time),
        "ecs": {"version": ECS_VERSION},
        "event": {
            "kind": "alert" if e.kind == "finding" else "event",
            "category": cat, "type": typ,
            "action": e.kind, "id": e.id, "dataset": "siemless.hermes", "module": "siemless",
            "severity": _SEVERITY_ID.get(e.severity, 1),
            "outcome": "success" if status_id == 1 else ("failure" if status_id == 2 else "unknown"),
            "provider": "hermes-agent",
        },
        "observer": {"vendor": VENDOR, "product": PRODUCT, "version": __version__, "type": "agent-telemetry"},
        "agent": {"name": "hermes-agent", "type": "ai-agent", "id": e.profile or "default"},
        "labels": {"visibility": e.visibility, "kind": e.kind},
        "tags": list(e.tags),
        "siemless": {k: v for k, v in e.to_dict().items() if k not in ("id", "time", "schema", "tags")},
    }
    if hostname:
        doc["host"] = {"name": hostname}
    if e.session_id or e.turn_id:
        doc["trace"] = {"id": e.session_id}
        doc["transaction"] = {"id": e.turn_id}
    if e.kind in ("file.read", "file.write", "secret.access") and e.target:
        doc["file"] = {"path": e.target, "name": e.target.rsplit("/", 1)[-1]}
    if e.kind == "process.exec" and e.target:
        doc["process"] = {"command_line": e.target, "name": e.tool}
    if e.host:
        doc["destination"] = {"domain": e.host}
        if isinstance(e.attrs.get("port"), int):
            doc["destination"]["port"] = e.attrs["port"]
        doc.setdefault("related", {})["hosts"] = [e.host]
    if e.target and "://" in (e.target or ""):
        doc["url"] = {"full": e.target, "domain": e.host}
    if e.kind == "finding":
        doc["rule"] = {"id": (e.rule_ids or [""])[0], "name": e.target, "ruleset": "siemless-baseline"}
        ids = e.attrs.get("attack") or []
        if ids:
            doc["threat"] = {"framework": "MITRE ATT&CK", "technique": {"id": ids}}
        doc["event"]["risk_score"] = {"info": 10, "low": 25, "medium": 50, "high": 75, "critical": 95}.get(e.severity, 10)
    return doc


# ------------------------------------------------------------------------------------------ CEF
_CEF_SEV = {"info": 1, "low": 3, "medium": 5, "high": 8, "critical": 10}


def _cef_header(s: Any) -> str:
    return str(s).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _cef_ext(s: Any) -> str:
    return str(s).replace("\\", "\\\\").replace("=", "\\=").replace("\r", "\\r").replace("\n", "\\n")


def to_cef(e: Event) -> str:
    sig = (e.rule_ids[0] if e.rule_ids else e.kind)
    name = e.target if e.kind == "finding" else _message(e)
    ext: dict[str, Any] = {"rt": e.time, "act": e.action or e.kind, "cat": e.kind, "outcome": e.outcome or "",
                           "cs1Label": "sessionId", "cs1": e.session_id or "", "cs2Label": "turnId", "cs2": e.turn_id or "",
                           "cs3Label": "visibility", "cs3": e.visibility, "cs4Label": "tags", "cs4": ",".join(e.tags)[:1000],
                           "cs5Label": "tool", "cs5": e.tool or "", "externalId": e.id}
    if e.host:
        ext["dhost"] = e.host
    if e.kind in ("file.read", "file.write", "secret.access") and e.target:
        ext["filePath"] = e.target
    if e.kind == "process.exec" and e.target:
        ext["cs6Label"] = "commandLine"
        ext["cs6"] = e.target[:1000]
    if e.target and "://" in (e.target or ""):
        ext["request"] = e.target[:1000]
    if e.kind == "finding":
        ext["cn1Label"] = "confidence"
        ext["cn1"] = {"low": 1, "medium": 2, "high": 3}.get(str(e.attrs.get("confidence")), 0)
        if e.attrs.get("attack"):
            ext["cs6Label"] = "attack"
            ext["cs6"] = ",".join(e.attrs["attack"])
    header = "|".join(["CEF:0", _cef_header(VENDOR), _cef_header(PRODUCT), _cef_header(__version__), _cef_header(sig),
                       _cef_header(name)[:200], str(_CEF_SEV.get(e.severity, 1))])
    return header + "|" + " ".join(f"{k}={_cef_ext(v)}" for k, v in ext.items() if v != "" and v is not None)


# --------------------------------------------------------------------------------------- syslog
SD_ID = "siemless@32473"  # 32473 is the IANA example enterprise number (RFC 5612) until ASV Labs registers one
_SYSLOG_SEV = {"info": 6, "low": 5, "medium": 4, "high": 3, "critical": 2}
FACILITY_AUDIT = 13


def _sd_escape(s: Any) -> str:
    return str(s).replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def to_syslog(e: Event, msg: str, *, hostname: Optional[str] = None, app: str = "siemless", facility: int = FACILITY_AUDIT) -> str:
    pri = facility * 8 + _SYSLOG_SEV.get(e.severity, 6)
    host = hostname or socket.gethostname() or "-"
    host = re.sub(r"[^\x21-\x7e]", "", host)[:255] or "-"
    msgid = re.sub(r"[^\x21-\x7e]", "", e.kind.replace(".", "_"))[:32] or "-"
    sd_params = {"id": e.id, "kind": e.kind, "visibility": e.visibility, "severity": e.severity}
    if e.session_id:
        sd_params["session"] = e.session_id
    if e.turn_id:
        sd_params["turn"] = e.turn_id
    if e.rule_ids:
        sd_params["rule"] = e.rule_ids[0]
    sd = f"[{SD_ID} " + " ".join(f'{k}="{_sd_escape(v)}"' for k, v in sd_params.items()) + "]"
    return f"<{pri}>1 {_iso(e.time)} {host} {app} - {msgid} {sd} {msg}"


def dumps(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False, default=str)


__all__ = ["to_ocsf", "to_ecs", "to_cef", "to_syslog", "dumps", "OCSF_VERSION", "ECS_VERSION", "SD_ID"]
