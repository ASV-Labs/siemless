"""Hook payload → canonical events.

``collect(hook, payload)`` is a pure function: it never touches the network, the filesystem or
the store, so a hook callback can run it in microseconds and hand the result to the pipeline.
Everything that leaves here has been through ``redact`` and is size-bounded.

Visibility rules (see events.py):
* a dedicated tool that reported ``status == "ok"`` is *observed* (Hermes read that file,
  fetched that URL);
* anything derived from command text or argument shape is *inferred*;
* the derived ``secret.access`` / ``config.change`` / ``cron.change`` / ``plugin.change`` events
  inherit the visibility of the event they were derived from.
"""

from __future__ import annotations

import hashlib
from typing import Any, Optional

from . import sensitive as S
from .events import Event, INFERRED, OBSERVED
from .redact import bound_args, preview, redact_text

# Slash commands that change how the agent is governed.
SECURITY_COMMANDS = {"yolo", "approve", "approvals", "plugins", "plugin", "config", "hooks", "trust", "auth", "mcp",
                     "skills", "skill", "cron", "schedule", "memory", "profile", "model"}

MUTATING_CRON_ACTIONS = {"create", "add", "update", "edit", "enable", "resume", "pause", "disable", "delete", "remove", "run"}
MUTATING_SKILL_ACTIONS = {"create", "install", "update", "edit", "remove", "delete", "enable", "disable", "patch", "write"}


def _h(text: Any) -> str:
    """Short, stable hash of a text we deliberately do not store."""
    try:
        b = str(text).encode("utf-8", "replace")
    except Exception:
        return ""
    return hashlib.sha256(b).hexdigest()[:16]


def _ids(p: dict) -> dict:
    return {
        "session_id": _s(p.get("session_id")),
        "turn_id": _s(p.get("turn_id")),
        "task_id": _s(p.get("task_id")),
        "tool_call_id": _s(p.get("tool_call_id")),
        "api_request_id": _s(p.get("api_request_id")),
        "platform": _s(p.get("platform")),
    }


def _s(v: Any) -> Optional[str]:
    if v is None:
        return None
    try:
        s = str(v)
    except Exception:
        return None
    return s[:200] if s else None


def collect(hook: str, payload: dict, *, config: Optional[dict] = None) -> list[Event]:
    cfg = config or {}
    fn = _HANDLERS.get(hook)
    if fn is None:
        return []
    try:
        events = fn(payload, cfg) or []
    except Exception:
        # Never let a malformed payload break the agent; record that we saw something.
        events = [Event(kind="tool.call", hook=hook, outcome="collector_error", severity="info", **_ids(payload))]
    for e in events:
        e.hook = e.hook or hook
    return events


# ----------------------------------------------------------------------------- sessions / turns
def _session(kind: str):
    def fn(p: dict, cfg: dict) -> list[Event]:
        attrs = {}
        for k in ("completed", "interrupted", "reason", "old_session_id", "new_session_id"):
            if k in p and p[k] is not None:
                attrs[k] = _s(p[k]) if not isinstance(p[k], bool) else p[k]
        return [Event(kind=kind, severity="info", attrs=attrs, **_ids(p))]
    return fn


def _turn_start(p: dict, cfg: dict) -> list[Event]:
    attrs = {"model": _s(p.get("model")), "is_first_turn": bool(p.get("is_first_turn", False))}
    msg = p.get("user_message")
    if isinstance(msg, str):
        attrs["user_message_sha"] = _h(msg)
        attrs["user_message_chars"] = len(msg)
        if cfg.get("record_prompts"):
            attrs["user_message_preview"] = preview(msg, 200)
    if p.get("sender_id") is not None:
        attrs["sender_sha"] = _h(p.get("sender_id"))
    return [Event(kind="turn.start", attrs=attrs, **_ids(p))]


def _turn_end(p: dict, cfg: dict) -> list[Event]:
    attrs = {"model": _s(p.get("model"))}
    resp = p.get("assistant_response")
    if isinstance(resp, str):
        attrs["assistant_chars"] = len(resp)
        attrs["assistant_sha"] = _h(resp)
    return [Event(kind="turn.end", attrs=attrs, **_ids(p))]


def _llm_response(p: dict, cfg: dict) -> list[Event]:
    host = S.host_of(_s(p.get("base_url")))
    attrs = {k: _s(p.get(k)) for k in ("model", "provider", "response_model", "finish_reason", "api_mode") if p.get(k) is not None}
    for k in ("api_call_count", "message_count", "assistant_tool_call_count", "assistant_content_chars"):
        if isinstance(p.get(k), int):
            attrs[k] = p[k]
    if isinstance(p.get("api_duration"), (int, float)):
        attrs["duration_ms"] = int(p["api_duration"] * 1000)
    usage = p.get("usage")
    if isinstance(usage, dict):
        attrs["usage"] = {k: v for k, v in usage.items() if isinstance(v, (int, float))}
    tags = ["egress:provider"] + S.classify_host(host)
    return [Event(kind="llm.response", host=host, target=host, outcome="ok", attrs=attrs, tags=tags, **_ids(p))]


def _llm_error(p: dict, cfg: dict) -> list[Event]:
    host = S.host_of(_s(p.get("base_url")))
    err = p.get("error") if isinstance(p.get("error"), dict) else {}
    attrs = {"model": _s(p.get("model")), "provider": _s(p.get("provider")), "status_code": p.get("status_code"),
             "retry_count": p.get("retry_count"), "retryable": p.get("retryable"), "reason": _s(p.get("reason")),
             "error_type": _s(err.get("type")), "error": preview(err.get("message"), 160)}
    return [Event(kind="llm.error", host=host, target=host, outcome="error", severity="low",
                  attrs={k: v for k, v in attrs.items() if v is not None}, tags=["egress:provider"], **_ids(p))]


def _aux_call(p: dict, cfg: dict) -> list[Event]:
    if not cfg.get("record_aux_calls", True):
        return []
    host = S.host_of(_s(p.get("base_url")))
    attrs = {"aux_task": _s(p.get("aux_task")), "model": _s(p.get("model")), "provider": _s(p.get("provider"))}
    outcome = "error" if p.get("error") else "ok"
    if p.get("error"):
        attrs["error"] = preview(p.get("error"), 160)
    return [Event(kind="aux.call", host=host, target=host, outcome=outcome,
                  attrs={k: v for k, v in attrs.items() if v is not None}, tags=["egress:provider"], **_ids(p))]


# ------------------------------------------------------------------------------------ tools
def _tool_call(p: dict, cfg: dict) -> list[Event]:
    tool = _s(p.get("tool_name")) or "unknown"
    args = p.get("args") if isinstance(p.get("args"), dict) else {}
    status = _s(p.get("status")) or "ok"
    ids = _ids(p)
    ok = status == "ok"
    attrs: dict[str, Any] = {"status": status}
    if isinstance(p.get("duration_ms"), (int, float)):
        attrs["duration_ms"] = int(p["duration_ms"])
    if p.get("error_type"):
        attrs["error_type"] = _s(p.get("error_type"))
    if p.get("error_message"):
        attrs["error"] = preview(p.get("error_message"), 160)
    result = p.get("result")
    if isinstance(result, (str, bytes)):
        attrs["result_chars"] = len(result)
    if cfg.get("record_args", True):
        attrs["args"] = bound_args(args, per_value=200, total=1500)
    else:
        attrs["arg_names"] = sorted(str(k) for k in args.keys())[:32]

    base = Event(kind="tool.call", tool=tool, outcome=status, attrs=attrs, **ids)
    out = [base]
    derived_vis = OBSERVED if ok else INFERRED  # a failed call proves intent, not effect
    path = S.first_str(args, "path", "file_path", "filename", "file", "target")
    url = S.first_str(args, "url", "uri", "href")
    cmd = S.first_str(args, "command", "cmd", "code", "script")

    # --- file tools
    if tool in S.FILE_READ_TOOLS and path:
        out += _file_event("file.read", "read", path, derived_vis, tool, ids)
    elif tool in S.FILE_WRITE_TOOLS and path:
        out += _file_event("file.write", "write", path, derived_vis, tool, ids)
    # --- shell / code
    elif tool in S.EXEC_TOOLS and cmd:
        out += _exec_events(cmd, tool, ids, derived_vis)
    # --- web
    elif tool == "web_search":
        q = S.first_str(args, "query", "q")
        out.append(Event(kind="content.untrusted", visibility=derived_vis, tool=tool, action="search", outcome=status,
                         attrs={"query_sha": _h(q), "query_chars": len(q or "")}, tags=["untrusted:web_search"], **ids))
    elif tool == "web_extract" or tool == "x_search":
        urls = []
        if url:
            urls = [url]
        elif isinstance(args.get("urls"), list):
            urls = [u for u in args["urls"] if isinstance(u, str)][:16]
        for u in urls:
            host = S.host_of(u)
            out.append(Event(kind="net.egress", visibility=derived_vis, tool=tool, action="fetch", outcome=status, host=host,
                             target=redact_text(u)[:300], tags=["egress:fetch"] + S.classify_host(host), **ids))
        out.append(Event(kind="content.untrusted", visibility=derived_vis, tool=tool, action="fetch", outcome=status,
                         host=S.host_of(urls[0]) if urls else None, attrs={"urls": len(urls)}, tags=["untrusted:web_fetch"], **ids))
    # --- browser
    elif tool.startswith(S.BROWSER_TOOLS_PREFIX):
        action = S.browser_action(tool, args)
        if action == "navigate" and url:
            host = S.host_of(url)
            out.append(Event(kind="net.egress", visibility=derived_vis, tool=tool, action="navigate", outcome=status, host=host,
                             target=redact_text(url)[:300], tags=["egress:browser"] + S.classify_host(host), **ids))
            out.append(Event(kind="content.untrusted", visibility=derived_vis, tool=tool, action="navigate", outcome=status,
                             host=host, tags=["untrusted:browser"], **ids))
        elif action == "read":
            out.append(Event(kind="content.untrusted", visibility=derived_vis, tool=tool, action="read", outcome=status,
                             tags=["untrusted:browser"], **ids))
        else:
            base.tags.append("browser:act")
    # --- messaging / delegation
    elif tool in S.SEND_TOOLS:
        target = S.first_str(args, "target", "channel", "chat_id", "to", "recipient", "platform", "task_id")
        body = S.first_str(args, "message", "text", "content", "body", "comment")
        out.append(Event(kind="net.egress", visibility=derived_vis, tool=tool, action="send", outcome=status,
                         target=preview(target, 80) if target else None,
                         attrs={"message_chars": len(body or ""), "message_sha": _h(body) if body else None},
                         tags=["egress:message"], **ids))
    elif tool in S.DELEGATE_TOOLS:
        base.tags.append("delegate")
    # --- cron / skills / memory
    elif tool in S.CRON_TOOLS:
        action = (S.first_str(args, "action", "operation", "op") or "create").lower()
        if action in MUTATING_CRON_ACTIONS:
            out.append(Event(kind="cron.change", visibility=derived_vis, tool=tool, action=action, outcome=status,
                             target=preview(S.first_str(args, "name", "job_id", "id", "schedule"), 80),
                             attrs={"schedule": preview(S.first_str(args, "schedule", "cron", "interval"), 60)},
                             tags=["persistence:cron"], **ids))
    elif tool in S.SKILL_TOOLS:
        action = (S.first_str(args, "action", "operation") or "").lower()
        if action in MUTATING_SKILL_ACTIONS:
            out.append(Event(kind="skill.change", visibility=derived_vis, tool=tool, action=action, outcome=status,
                             target=preview(S.first_str(args, "name", "skill", "skill_name"), 80), tags=["config:hermes_skills"], **ids))
    elif path:  # an unknown tool with a path argument still gets a path classification
        tags = S.classify_path(path)
        if tags:
            base.tags += tags
            base.target = redact_text(path)[:300]
    return out


def _file_event(kind: str, action: str, path: str, vis: str, tool: str, ids: dict) -> list[Event]:
    tags = S.classify_path(path)
    target = redact_text(path)[:300]
    ev = Event(kind=kind, visibility=vis, tool=tool, action=action, target=target, tags=list(tags), **ids)
    out = [ev]
    if any(t.startswith("sensitive:") for t in tags):
        ev.severity = "medium"
        out.append(Event(kind="secret.access", visibility=vis, tool=tool, action=action, target=target, severity="medium",
                         tags=[t for t in tags if t.startswith("sensitive:")], **ids))
    if action == "write" and any(t.startswith("config:") for t in tags):
        ev.severity = "medium"
        out.append(Event(kind="config.change", visibility=vis, tool=tool, action="write", target=target, severity="medium",
                         tags=[t for t in tags if t.startswith("config:")], **ids))
    if action == "read" and S.is_untrusted_path(path):
        out.append(Event(kind="content.untrusted", visibility=vis, tool=tool, action="read_file", target=target,
                         tags=["untrusted:downloaded_file"], **ids))
    return out


_WRITE_HINT = ("> ", ">>", " tee ", "sed -i", " cp ", " mv ", "install ", "ln -s", "cat >", "echo ", "printf ")


def _exec_events(cmd: str, tool: str, ids: dict, vis_ok: str) -> list[Event]:
    """A terminal/execute_code call: one process.exec plus whatever the command text implies."""
    red = redact_text(cmd)
    cmd_tags = S.classify_command(cmd)
    tags = [t for t, _ in cmd_tags]
    sev = "info"
    if any(t in tags for t in ("cmd:reverse_shell", "cmd:decode_exec", "cmd:download_exec", "cmd:inline_exec",
                               "cmd:keychain", "cmd:token_fetch", "cmd:browser_creds", "cmd:credential_archive", "cmd:log_tamper")):
        sev = "high"
    elif tags:
        sev = "medium"
    ev = Event(kind="process.exec", visibility=INFERRED, tool=tool, action="exec", target=S.command_preview(red, 200),
               severity=sev, attrs={"command_sha": _h(cmd), "command_chars": len(cmd), "reasons": [r for _, r in cmd_tags][:8]},
               tags=tags, **ids)
    out = [ev]

    # Paths the command touches
    sensitive_hit = False
    for p in S.paths_in_text(cmd):
        ptags = S.classify_path(p)
        if not ptags:
            continue
        tgt = redact_text(p)[:300]
        if any(t.startswith("sensitive:") for t in ptags) and not sensitive_hit:
            sensitive_hit = True
            out.append(Event(kind="secret.access", visibility=INFERRED, tool=tool, action="exec", target=tgt, severity="medium",
                             tags=[t for t in ptags if t.startswith("sensitive:")] + ["via:terminal"], **ids))
        if any(t.startswith("config:") for t in ptags) and any(h in f" {cmd} " for h in _WRITE_HINT):
            out.append(Event(kind="config.change", visibility=INFERRED, tool=tool, action="exec", target=tgt, severity="medium",
                             tags=[t for t in ptags if t.startswith("config:")] + ["via:terminal"], **ids))
    if "cmd:credential_read" in tags and not sensitive_hit:
        out.append(Event(kind="secret.access", visibility=INFERRED, tool=tool, action="exec", target=ev.target, severity="medium",
                         tags=["sensitive:command", "via:terminal"], **ids))
    if "cmd:env_dump" in tags or "cmd:keychain" in tags or "cmd:token_fetch" in tags or "cmd:browser_creds" in tags:
        out.append(Event(kind="secret.access", visibility=INFERRED, tool=tool, action="exec", target=ev.target, severity="high",
                         tags=[t for t in tags if t in ("cmd:env_dump", "cmd:keychain", "cmd:token_fetch", "cmd:browser_creds")] + ["via:terminal"], **ids))

    # Network destinations
    for dest in S.egress_from_command(cmd):
        host = dest.get("host")
        out.append(Event(kind="net.egress", visibility=INFERRED, tool=tool, action="exec", host=host,
                         target=redact_text(dest.get("url") or host or "")[:300],
                         attrs={"client": dest.get("client"), "port": dest.get("port")},
                         tags=["egress:shell"] + S.classify_host(host), **ids))
    if "cmd:git_push" in tags or "cmd:gh_publish" in tags:
        out.append(Event(kind="net.egress", visibility=INFERRED, tool=tool, action="publish", target=ev.target, severity="low",
                         tags=["egress:publish"] + [t for t in tags if t in ("cmd:git_push", "cmd:gh_publish", "cmd:git_remote_change")], **ids))

    # Governance changes expressed as commands
    if "cmd:persistence" in tags or "cmd:hermes_cron" in tags:
        out.append(Event(kind="cron.change", visibility=INFERRED, tool=tool, action="exec", target=ev.target, severity="medium",
                         tags=["persistence:cron", "via:terminal"], **ids))
    if "cmd:hermes_plugin" in tags:
        out.append(Event(kind="plugin.change", visibility=INFERRED, tool=tool, action="exec", target=ev.target, severity="medium",
                         tags=["config:hermes_plugins", "via:terminal"], **ids))
    if "cmd:hermes_security_config" in tags:
        out.append(Event(kind="config.change", visibility=INFERRED, tool=tool, action="exec", target=ev.target, severity="high",
                         tags=["config:hermes_config", "via:terminal"], **ids))
    return out


# -------------------------------------------------------------------------- approvals / humans
def _approval_request(p: dict, cfg: dict) -> list[Event]:
    cmd = _s(p.get("command"))
    attrs = {"pattern_key": _s(p.get("pattern_key")), "surface": _s(p.get("surface")),
             "description": preview(p.get("description"), 160), "command_sha": _h(cmd) if cmd else None}
    pk = p.get("pattern_keys")
    if isinstance(pk, (list, tuple)):
        attrs["pattern_keys"] = [str(x)[:64] for x in pk][:16]
    ids = _ids(p)
    ids["session_id"] = ids["session_id"] or _s(p.get("session_key"))
    return [Event(kind="approval.request", action="request", target=S.command_preview(redact_text(cmd or ""), 200),
                  attrs={k: v for k, v in attrs.items() if v is not None}, **ids)]


def _approval_response(p: dict, cfg: dict) -> list[Event]:
    cmd = _s(p.get("command"))
    choice = _s(p.get("choice")) or "unknown"
    outcome = {"once": "allowed", "session": "allowed", "always": "allowed", "deny": "denied", "timeout": "timeout",
               "cancelled": "cancelled"}.get(choice, choice)
    attrs = {"choice": choice, "decided_by": _s(p.get("decided_by")), "pattern_key": _s(p.get("pattern_key")),
             "surface": _s(p.get("surface")), "command_sha": _h(cmd) if cmd else None}
    ids = _ids(p)
    ids["session_id"] = ids["session_id"] or _s(p.get("session_key"))
    sev = "low" if outcome == "denied" else "info"
    if choice == "always":
        sev = "low"
    return [Event(kind="approval.response", action="decide", outcome=outcome, severity=sev,
                  target=S.command_preview(redact_text(cmd or ""), 200), attrs={k: v for k, v in attrs.items() if v is not None}, **ids)]


def _human_input(action: str):
    def fn(p: dict, cfg: dict) -> list[Event]:
        ids = _ids(p)
        ids["session_id"] = ids["session_id"] or _s(p.get("session_key"))
        attrs = {"kind": _s(p.get("kind")), "request_id": _s(p.get("request_id"))}
        return [Event(kind="human_input", action=action, outcome=_s(p.get("outcome")), attrs={k: v for k, v in attrs.items() if v}, **ids)]
    return fn


# -------------------------------------------------------------------------------- subagents
def _subagent_start(p: dict, cfg: dict) -> list[Event]:
    goal = p.get("child_goal")
    attrs = {"child_role": _s(p.get("child_role")), "goal_sha": _h(goal) if goal else None,
             "goal_chars": len(goal) if isinstance(goal, str) else None,
             "parent_turn_id": _s(p.get("parent_turn_id")), "parent_subagent_id": _s(p.get("parent_subagent_id"))}
    if cfg.get("record_prompts") and isinstance(goal, str):
        attrs["goal_preview"] = preview(goal, 200)
    return [Event(kind="subagent.start", action="spawn", parent_session_id=_s(p.get("parent_session_id")),
                  child_session_id=_s(p.get("child_session_id")), subagent_id=_s(p.get("child_subagent_id")),
                  session_id=_s(p.get("parent_session_id")), turn_id=_s(p.get("parent_turn_id")),
                  attrs={k: v for k, v in attrs.items() if v is not None}, tags=["delegation"])]


def _subagent_stop(p: dict, cfg: dict) -> list[Event]:
    hist = p.get("tool_call_history") if isinstance(p.get("tool_call_history"), list) else []
    tools: dict[str, int] = {}
    targets: list[str] = []
    for h in hist[:500]:
        if not isinstance(h, dict):
            continue
        name = _s(h.get("tool") or h.get("tool_name") or h.get("name")) or "?"
        tools[name] = tools.get(name, 0) + 1
        for key in ("targets", "side_effect_targets", "side_effects"):
            v = h.get(key)
            if isinstance(v, (list, tuple)):
                targets += [str(x)[:200] for x in v if x]
    tags = ["delegation"]
    sens = [t for t in targets if any(x.startswith("sensitive:") for x in S.classify_path(t))]
    if sens:
        tags.append("sensitive:subagent_targets")
    attrs = {"child_role": _s(p.get("child_role")), "status": _s(p.get("status") or p.get("child_status")),
             "duration_ms": p.get("duration_ms") if isinstance(p.get("duration_ms"), (int, float)) else None,
             "tool_counts": dict(sorted(tools.items())[:32]), "targets": [redact_text(t) for t in targets[:16]],
             "summary_chars": len(p["child_summary"]) if isinstance(p.get("child_summary"), str) else None}
    outcome = _s(p.get("status") or p.get("child_status")) or "ok"
    sev = "medium" if sens else "info"
    return [Event(kind="subagent.stop", action="return", outcome=outcome, severity=sev,
                  parent_session_id=_s(p.get("parent_session_id")), child_session_id=_s(p.get("child_session_id")),
                  subagent_id=_s(p.get("child_subagent_id")), session_id=_s(p.get("parent_session_id")),
                  turn_id=_s(p.get("parent_turn_id")), attrs={k: v for k, v in attrs.items() if v is not None}, tags=tags)]


# ---------------------------------------------------------------------- commands / skills / kanban
def _command(p: dict, cfg: dict) -> list[Event]:
    name = (_s(p.get("command")) or "").lstrip("/").lower()
    ids = _ids(p)
    ids["session_id"] = ids["session_id"] or _s(p.get("session_key"))
    tags = []
    sev = "info"
    if name in SECURITY_COMMANDS:
        tags.append("command:security")
        sev = "low"
    args_raw = p.get("args_raw")
    attrs = {"surface": _s(p.get("surface")), "alias_used": _s(p.get("alias_used")),
             "args_preview": preview(args_raw, 120) if isinstance(args_raw, str) and args_raw else None}
    ev = Event(kind="command", action=name or "unknown", target=name, severity=sev, tags=tags,
               attrs={k: v for k, v in attrs.items() if v is not None}, **ids)
    out = [ev]
    if name in ("yolo",) or (name in ("approvals", "approve", "config") and isinstance(args_raw, str)
                             and any(w in args_raw.lower() for w in ("off", "yolo", "never", "auto"))):
        out.append(Event(kind="config.change", visibility=INFERRED, action="command", target=f"/{name} {preview(args_raw, 60)}".strip(),
                         severity="high", tags=["config:approvals", "via:command"], **ids))
    if name in ("plugins", "plugin") and isinstance(args_raw, str) and any(w in args_raw.lower() for w in ("install", "enable", "disable", "remove")):
        out.append(Event(kind="plugin.change", visibility=INFERRED, action="command", target=f"/{name} {preview(args_raw, 60)}",
                         severity="medium", tags=["config:hermes_plugins", "via:command"], **ids))
    return out


def _skill_lifecycle(p: dict, cfg: dict) -> list[Event]:
    action = _s(p.get("action") or p.get("event") or p.get("lifecycle")) or "change"
    return [Event(kind="skill.change", action=action, target=preview(p.get("skill") or p.get("name") or p.get("skill_name"), 80),
                  attrs={"source": preview(p.get("source"), 80)} if p.get("source") else {}, tags=["config:hermes_skills"], **_ids(p))]


def _kanban(name: str):
    def fn(p: dict, cfg: dict) -> list[Event]:
        attrs = {k: _s(p.get(k)) for k in ("task_id", "board", "assignee", "run_id", "profile_name", "exit_kind", "exit_code") if p.get(k) is not None}
        return [Event(kind="kanban.event", action=name, attrs=attrs, task_id=_s(p.get("task_id")), profile=_s(p.get("profile_name")))]
    return fn


_HANDLERS = {
    "on_session_start": _session("session.start"),
    "on_session_end": _session("session.end"),
    "on_session_reset": _session("session.reset"),
    "on_session_delete": _session("session.delete"),
    "pre_llm_call": _turn_start,
    "post_llm_call": _turn_end,
    "post_api_request": _llm_response,
    "api_request_error": _llm_error,
    "post_auxiliary_call": _aux_call,
    "post_tool_call": _tool_call,
    "pre_approval_request": _approval_request,
    "post_approval_response": _approval_response,
    "on_human_input_request": _human_input("request"),
    "on_human_input_resolved": _human_input("resolved"),
    "subagent_start": _subagent_start,
    "subagent_stop": _subagent_stop,
    "pre_command": _command,
    "on_skill_lifecycle": _skill_lifecycle,
    "kanban_task_claimed": _kanban("claimed"),
    "kanban_task_completed": _kanban("completed"),
    "kanban_task_blocked": _kanban("blocked"),
    "on_kanban_worker_spawned": _kanban("worker_spawned"),
    "on_kanban_worker_exited": _kanban("worker_exited"),
}

HOOKS = tuple(_HANDLERS.keys())

__all__ = ["collect", "HOOKS", "SECURITY_COMMANDS"]
