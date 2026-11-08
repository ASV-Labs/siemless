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

OCSF_VERSION = "1.9.0"   # schema version the shapes follow (docs/RESEARCH.md §1); 1.9.0 adds ai_agent, delegation
ATTACK_VERSION = "20.1"

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
    "config.change":    (1001, "File System Activity", 1, 3, "Update"),  # a path; command-only changes fall back to 6003 below
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
    if o in ("error", "failed"):
        return 2, "Failure"
    if o in ("blocked", "cancelled", "denied", "timeout"):
        return 99, o.capitalize()  # the call did not run; OCSF status 1/2 are for ran-and-succeeded/failed
    if not o:
        return 0, "Unknown"
    return 99, "Other"


# security_control profile (approvals and blocked tool calls): action_id / disposition_id
def _security_control(e: Event) -> Optional[dict]:
    choice = str(e.attrs.get("choice") or "").lower()
    if e.kind == "approval.response":
        if choice in ("once", "session", "always"):
            return {"action_id": 1, "action": "Allowed", "disposition_id": 8, "disposition": "Approved"}
        if choice == "deny":
            return {"action_id": 2, "action": "Denied", "disposition_id": 2, "disposition": "Blocked"}
        if choice == "timeout":
            return {"action_id": 2, "action": "Denied", "disposition_id": 14, "disposition": "Delayed"}
        if choice == "cancelled":
            return {"action_id": 2, "action": "Denied", "disposition_id": 25, "disposition": "Rejected"}
        return {"action_id": 0, "action": "Unknown", "disposition_id": 0, "disposition": "Unknown"}
    if e.kind == "approval.request":
        return {"action_id": 3, "action": "Observed", "disposition_id": 14, "disposition": "Delayed"}
    if e.kind == "tool.call" and (e.outcome or "") == "blocked":
        return {"action_id": 2, "action": "Denied", "disposition_id": 2, "disposition": "Blocked"}
    return None


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
        "profiles": ["ai_operation"],
        "extensions": [{"name": "siemless", "uid": 999, "version": __version__}],  # 999 = OCSF dev uid, unregistered
    }
    if hostname:
        md["log_provider"] = hostname
    cid = {k: v for k, v in {"session_id": e.session_id, "turn_id": e.turn_id, "task_id": e.task_id,
                             "tool_call_id": e.tool_call_id, "api_request_id": e.api_request_id}.items() if v}
    if cid:
        md["correlation_uid"] = e.turn_id or e.session_id or e.id
    return md


def _ai_agent(e: Event) -> dict:
    agent = {"name": "hermes-agent", "uid": e.profile or "default", "type_id": 99, "type": "hermes"}
    if e.session_id:
        agent["instance_uid"] = e.session_id
    return agent


def _actor(e: Event) -> dict:
    actor: dict[str, Any] = {"app_name": "hermes-agent", "application": {"name": "hermes-agent"}}
    if e.session_id:
        actor["session"] = {k: v for k, v in {"uid": e.session_id, "uid_alt": e.turn_id}.items() if v}
    if e.subagent_id or e.child_session_id:
        actor["process"] = {"name": "hermes-subagent", "uid": e.subagent_id or e.child_session_id, "ai_agent": _ai_agent(e)}
    if e.profile:
        actor["user"] = {"name": e.profile, "type_id": 3, "type": "System"}
    return actor


def _flat_unmapped(e: Event) -> dict:
    """Scalars only (Wazuh's JSON decoder does not read arrays of objects): tags and ids as strings."""
    d = e.to_dict()
    out: dict[str, Any] = {}
    for k, v in d.items():
        if k in ("id", "time", "schema", "attrs", "tags", "rule_ids", "evidence"):
            continue
        out[k] = v
    out["tags"] = ",".join(e.tags)
    if e.rule_ids:
        out["rule_id"] = e.rule_ids[0]
    if e.evidence:
        out["evidence_ids"] = ",".join(e.evidence[:32])
    for k, v in e.attrs.items():
        if isinstance(v, (str, int, float, bool)) or v is None:
            out[f"attr_{k}"] = v
        elif isinstance(v, list) and all(isinstance(x, (str, int, float)) for x in v):
            out[f"attr_{k}"] = ",".join(str(x) for x in v)
        elif isinstance(v, dict) and k == "args":
            out["args_json"] = json.dumps(v, separators=(",", ":"), ensure_ascii=False)[:4000]
    if e.attrs.get("attack"):
        out["attack_ids"] = ",".join(e.attrs["attack"])
    if "replay" in e.tags:
        out["replay"] = True  # replayed recording, not live telemetry
    return out


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
        "unmapped": {"siemless": _flat_unmapped(e)},
        "ai_agent": _ai_agent(e),
    }
    if e.kind == "config.change" and not (e.target or "").startswith(("/", "~", ".")):
        class_uid, class_name, cat_uid, act_id, act_name = 6003, "API Activity", 6, 3, "Update"  # a command, not a path
        out.update({"class_uid": class_uid, "class_name": class_name, "category_uid": cat_uid, "category_name": "Application Activity",
                    "activity_id": act_id, "activity_name": act_name, "type_uid": class_uid * 100 + act_id, "type_name": f"{class_name}: {act_name}"})
    if e.outcome:
        out["status_detail"] = e.outcome
    # system classes (1xxx) require device; we add it everywhere for a stable shape
    out["device"] = {"hostname": hostname or "unknown", "type_id": 0, "type": "Unknown"}
    sc = _security_control(e)
    if sc:
        out.update(sc)
        out["metadata"]["profiles"].append("security_control")
    if e.kind in ("llm.response", "llm.error", "aux.call") and (e.attrs.get("model") or e.attrs.get("provider")):
        out["ai_model"] = {"name": str(e.attrs.get("model") or "unknown"), "ai_provider": str(e.attrs.get("provider") or e.host or "unknown")}
        usage = e.attrs.get("usage") if isinstance(e.attrs.get("usage"), dict) else {}
        mc = {"ai_role_id": 2, "ai_role": "Assistant"}
        for src, dst in (("prompt_tokens", "prompt_tokens"), ("input_tokens", "prompt_tokens"), ("completion_tokens", "completion_tokens"),
                         ("output_tokens", "completion_tokens"), ("total_tokens", "total_tokens")):
            if isinstance(usage.get(src), (int, float)):
                mc[dst] = int(usage[src])
        out["message_context"] = mc
    if e.kind in ("subagent.start", "subagent.stop") and (e.child_session_id or e.subagent_id):
        out["delegation"] = {k: v for k, v in {"uid": e.child_session_id or e.subagent_id, "issuer_uid": e.parent_session_id,
                                               "parent_uid": e.turn_id, "created_time": e.time}.items() if v}

    # class-specific objects
    if class_uid == 6003:
        out["api"] = {"operation": e.action or e.kind, "service": {"name": e.tool or e.kind}}
        out["src_endpoint"] = {"svc_name": "hermes-agent"}
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
        cron = "via:terminal" in e.tags
        out["job"] = {"name": e.target or "scheduled job", "cmd_line": (e.attrs.get("schedule") or ""),
                      "type_id": 2 if cron else 99, "type": "Cron" if cron else "Hermes cron"}
    elif class_uid == 6002:
        out["app"] = {"name": e.target or "plugin"}
    elif class_uid == 2004:
        from .attack import is_known, technique

        attacks = []
        for a in e.attrs.get("attack") or []:
            if is_known(a):
                t = technique(a)
                attacks.append({"technique": {"uid": t["id"], "name": t["name"], "src_url": t["url"]},
                                "tactic": {"uid": t["tactic"]["id"], "name": t["tactic"]["name"]}, "version": ATTACK_VERSION})
            else:
                attacks.append({"technique": {"uid": a}, "version": ATTACK_VERSION})
        out["finding_info"] = {"uid": e.attrs.get("finding_id") or e.id, "title": e.target or "finding",
                               "analytic": {"type_id": 1, "type": "Rule", "name": (e.rule_ids or ["?"])[0], "uid": (e.rule_ids or ["?"])[0],
                                            "version": __version__},
                               "related_events": [{"uid": x} for x in e.evidence[:32]], "types": ["Agent Behavior"]}
        if attacks:
            out["finding_info"]["attacks"] = attacks
        out["is_alert"] = e.severity in ("high", "critical")
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
        obs.append({"name": "dst_endpoint", "type_id": 20, "type": "Endpoint", "value": e.host})
    if e.kind in ("file.read", "file.write", "secret.access", "config.change") and e.target and e.target.startswith(("/", "~", ".")):
        obs.append({"name": "file", "type_id": 24, "type": "File", "value": e.target})
    if e.kind == "process.exec" and e.target:
        obs.append({"name": "process.cmd_line", "type_id": 13, "type": "Command Line", "value": e.target})
    if e.target and e.kind in ("net.egress", "content.untrusted") and "://" in e.target:
        obs.append({"name": "url", "type_id": 23, "type": "URL", "value": e.target})
    return obs[:8]


# ------------------------------------------------------------------------------------------ ECS
ECS_VERSION = "9.5.0"

_ECS_CAT = {
    "file.read": (["file"], ["access"]), "file.write": (["file"], ["change"]), "secret.access": (["file"], ["access"]),
    "process.exec": (["process"], ["start"]), "net.egress": (["network"], ["connection"]),
    "content.untrusted": (["web"], ["access"]), "approval.request": (["api"], ["info"]), "approval.response": (["api"], ["info"]),
    "subagent.start": (["process"], ["start"]), "subagent.stop": (["process"], ["end"]), "cron.change": (["configuration"], ["creation"]),
    "plugin.change": (["package"], ["installation"]), "skill.change": (["package"], ["change"]), "config.change": (["configuration"], ["change"]),
    "finding": (["intrusion_detection"], ["info"]), "llm.response": (["api"], ["info"]), "aux.call": (["api"], ["info"]),
    "command": (["api"], ["info"]), "human_input": (["api"], ["info"]), "session.start": (["session"], ["start"]), "session.end": (["session"], ["end"]),
}


def to_ecs(e: Event, *, hostname: Optional[str] = None) -> dict:
    cat, typ = _ECS_CAT.get(e.kind, (["process"], ["info"]))
    if e.kind == "approval.response":
        typ = ["allowed"] if e.outcome == "allowed" else ["denied"]
    status_id, _ = _status(e)
    doc: dict[str, Any] = {
        "@timestamp": _iso(e.time),
        "ecs": {"version": ECS_VERSION},
        "event": {
            "kind": "alert" if e.kind == "finding" else "event",
            "category": cat, "type": typ,
            "action": e.kind, "id": e.id, "dataset": "siemless.hermes", "module": "siemless",
            "severity": {"info": 10, "low": 30, "medium": 50, "high": 70, "critical": 90}.get(e.severity, 10),
            "outcome": "success" if status_id == 1 else ("failure" if status_id == 2 else "unknown"),
            "provider": "hermes-agent",
        },
        "observer": {"vendor": VENDOR, "product": PRODUCT, "version": __version__, "type": "agent-telemetry"},
        "agent": {"name": "hermes-agent", "type": "ai-agent", "id": e.profile or "default"},
        "labels": {"visibility": e.visibility, "kind": e.kind, **({"replay": "true"} if "replay" in e.tags else {})},
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
            from .attack import is_known, technique

            known = [technique(i) for i in ids if is_known(i)]
            doc["threat"] = {"framework": "MITRE ATT&CK",
                             "technique": {"id": ids, "name": [t["name"] for t in known], "reference": [t["url"] for t in known]},
                             "tactic": {"id": sorted({t["tactic"]["id"] for t in known if t["tactic"]["id"]}),
                                        "name": sorted({t["tactic"]["name"] for t in known if t["tactic"]["name"]})}}
        doc["event"]["risk_score"] = {"info": 10, "low": 25, "medium": 50, "high": 75, "critical": 95}.get(e.severity, 10)
    return doc


# ------------------------------------------------------------------------------------------ CEF
_CEF_SEV = {"info": 1, "low": 3, "medium": 5, "high": 7, "critical": 9}  # 1-3 Low, 4-6 Medium, 7-8 High, 9-10 Very-High


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
    if "replay" in e.tags:
        ext["flexString1Label"] = "mode"
        ext["flexString1"] = "replay"
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
    # Truncate *before* escaping: cutting an escaped string can leave a lone "\" that escapes the next "|".
    header = "|".join(["CEF:0", _cef_header(VENDOR), _cef_header(PRODUCT), _cef_header(__version__), _cef_header(str(sig)[:100]),
                       _cef_header(str(name or "")[:200]), str(_CEF_SEV.get(e.severity, 1))])
    return header + "|" + " ".join(f"{k}={_cef_ext(v)}" for k, v in ext.items() if v != "" and v is not None)


# --------------------------------------------------------------------------------------- syslog
SD_ID = "siemless@32473"  # 32473 is the IANA example enterprise number (RFC 5612) until ASV Labs registers one
_SYSLOG_SEV = {"info": 6, "low": 5, "medium": 4, "high": 3, "critical": 2}
FACILITY_LOCAL4 = 20
BOM = "\ufeff"  # RFC 5424: a UTF-8 MSG must start with the BOM


def _sd_escape(s: Any) -> str:
    return str(s).replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def to_syslog(e: Event, msg: str, *, hostname: Optional[str] = None, app: str = "siemless", facility: int = FACILITY_LOCAL4) -> str:
    pri = facility * 8 + _SYSLOG_SEV.get(e.severity, 6)
    host = hostname or socket.gethostname() or "-"
    host = re.sub(r"[^\x21-\x7e]", "", host)[:255] or "-"
    msgid = re.sub(r"[^\x21-\x7e]", "", e.kind.replace(".", "_"))[:32] or "-"
    class_uid, _cn, _cat, act_id, _an = _CLASS.get(e.kind, (6003, "", 6, 99, ""))
    sd_params = {"id": e.id, "kind": e.kind, "class_uid": class_uid, "type_uid": class_uid * 100 + act_id,
                 "visibility": e.visibility, "severity": e.severity}
    if e.session_id:
        sd_params["session"] = e.session_id
    if e.turn_id:
        sd_params["turn"] = e.turn_id
    if e.rule_ids:
        sd_params["rule"] = e.rule_ids[0]
    if "replay" in e.tags:
        sd_params["replay"] = "true"
    sd = f"[{SD_ID} " + " ".join(f'{k}="{_sd_escape(v)}"' for k, v in sd_params.items()) + "]"
    body = msg if msg.isascii() else BOM + msg
    return f"<{pri}>1 {_iso(e.time)} {host} {app} - {msgid} {sd} {body}"


def dumps(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False, default=str)


__all__ = ["to_ocsf", "to_ecs", "to_cef", "to_syslog", "dumps", "OCSF_VERSION", "ECS_VERSION", "ATTACK_VERSION", "SD_ID", "BOM"]
