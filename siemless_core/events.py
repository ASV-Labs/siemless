"""The canonical event: what every hook payload is reduced to before anything else sees it.

Every event carries a *visibility* so no consumer can mistake an intention for a fact:

* ``observed`` — Hermes told us this happened (a tool call completed with this status, an
  approval was answered, a subagent stopped).
* ``inferred`` — derived from arguments or text (a ``read_file`` with a path under ``~/.ssh`` is
  an inferred secret read: the call was made, whether the OS served the bytes is not visible;
  a ``curl`` in a terminal command is inferred egress: the shell ran, the socket is not visible).
* ``unavailable`` — reserved for capability-matrix rows; never attached to a stored event.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

from . import SCHEMA_VERSION

OBSERVED = "observed"
INFERRED = "inferred"
REPLAY_TAG = "replay"  # events and findings from `siemless replay`, never from a live agent
UNAVAILABLE = "unavailable"

# Event kinds. Dotted, stable, documented in docs/EVENTS.md. New kinds are additive.
KINDS = (
    "session.start", "session.end", "session.reset", "session.delete",
    "turn.start", "turn.end",
    "llm.request", "llm.response", "llm.error", "aux.call",
    "tool.call",            # a tool completed (post_tool_call), any tool
    "file.read", "file.write",   # derived from file tools and terminal commands
    "process.exec",         # terminal / execute_code command
    "net.egress",           # web_extract, browser navigation, terminal network clients, send_message
    "content.untrusted",    # untrusted content entered the context (web result, fetched page, downloaded file)
    "secret.access",        # a sensitive path or credential store was targeted
    "approval.request", "approval.response", "human_input",
    "subagent.start", "subagent.stop",
    "cron.change", "plugin.change", "config.change", "skill.change",
    "command",              # a slash command (pre_command)
    "kanban.event",
    "finding",              # a detection
    "siemless.health",      # exporter / queue health snapshots
)

SEVERITY = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def now_ms() -> int:
    return int(time.time() * 1000)


def new_id() -> str:
    return uuid.uuid4().hex


@dataclass
class Event:
    kind: str
    visibility: str = OBSERVED
    id: str = field(default_factory=new_id)
    time: int = field(default_factory=now_ms)          # epoch ms
    schema: str = SCHEMA_VERSION

    # correlation (all optional; copied verbatim from the hook payload when present)
    session_id: Optional[str] = None
    turn_id: Optional[str] = None
    task_id: Optional[str] = None
    tool_call_id: Optional[str] = None
    api_request_id: Optional[str] = None
    parent_session_id: Optional[str] = None
    child_session_id: Optional[str] = None
    subagent_id: Optional[str] = None
    profile: Optional[str] = None
    platform: Optional[str] = None
    hook: Optional[str] = None                          # the Hermes hook this came from

    # what
    tool: Optional[str] = None
    action: Optional[str] = None                        # read / write / exec / fetch / send / create / ...
    outcome: Optional[str] = None                       # ok / error / blocked / cancelled / denied / allowed / timeout
    severity: str = "info"
    target: Optional[str] = None                        # path, host, command preview, job name ...
    host: Optional[str] = None                          # destination host when known
    attrs: dict[str, Any] = field(default_factory=dict) # bounded, redacted, JSON-safe
    tags: list[str] = field(default_factory=list)       # sensitivity / trust tags
    rule_ids: list[str] = field(default_factory=list)   # findings only
    evidence: list[str] = field(default_factory=list)   # findings only: event ids

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # keep output stable and small
        for k in ("attrs", "tags", "rule_ids", "evidence"):
            if not d.get(k):
                d.pop(k, None)
        return {k: v for k, v in d.items() if v is not None}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Event":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in known})


__all__ = ["REPLAY_TAG", "Event", "KINDS", "SEVERITY", "OBSERVED", "INFERRED", "UNAVAILABLE", "now_ms", "new_id"]
