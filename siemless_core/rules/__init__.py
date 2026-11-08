"""The baseline ruleset.

A rule is a small object: an id, the event kinds that trigger it, and ``evaluate(event, ctx)``
returning a ``Finding`` or ``None``. Rules are deterministic, read the correlation window only,
and never block anything. Confidence is derived from what the evidence is made of: all observed →
high, mixed → medium, all inferred → low (a rule may cap it lower).

ATT&CK ids are only attached where the behaviour matches the technique as MITRE defines it. Where
it does not, the rule says so in ``attack_note`` rather than borrowing an id.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional, Protocol

from ..correlate import Correlator, SessionState
from ..events import Event, INFERRED, OBSERVED, new_id


@dataclass
class Finding:
    rule_id: str
    name: str
    severity: str                   # info | low | medium | high | critical
    title: str                      # one line, human
    observed: str                   # what was observed (facts, not conclusions)
    why: str                        # why it is suspicious
    evidence: list[Event]           # the events the conclusion rests on (oldest first)
    attack: list[dict] = field(default_factory=list)      # [{"id": "T1552.001", "name": ...}]
    attack_note: Optional[str] = None
    recommendation: str = ""
    missing_evidence: list[str] = field(default_factory=list)
    dedupe_key: str = ""            # same key within the cooldown → one finding
    confidence_cap: Optional[str] = None  # a rule can cap confidence (e.g. "medium")
    id: str = field(default_factory=new_id)

    @property
    def session_id(self) -> Optional[str]:
        return self.evidence[-1].session_id if self.evidence else None

    @property
    def turn_id(self) -> Optional[str]:
        return self.evidence[-1].turn_id if self.evidence else None

    def confidence(self) -> str:
        vis = {e.visibility for e in self.evidence}
        if vis == {OBSERVED}:
            c = "high"
        elif INFERRED in vis and OBSERVED in vis:
            c = "medium"
        else:
            c = "low"
        order = ["low", "medium", "high"]
        if self.confidence_cap and order.index(self.confidence_cap) < order.index(c):
            c = self.confidence_cap
        return c

    def visibility_summary(self) -> dict[str, int]:
        out = {OBSERVED: 0, INFERRED: 0}
        for e in self.evidence:
            out[e.visibility] = out.get(e.visibility, 0) + 1
        return out


def _norm(p: str) -> str:
    from ..sensitive import _norm_path

    return _norm_path(p)


class RuleContext:
    """What a rule may look at. A thin, read-only view over the correlator."""

    def __init__(self, corr: Correlator, state: SessionState, config: dict):
        self.corr = corr
        self.state = state
        self.config = config

    def recent(self, kinds: Iterable[str], before: Event, within_ms: Optional[int] = None,
               include_parents: bool = False, predicate: Optional[Callable[[Event], bool]] = None) -> list[Event]:
        return self.corr.recent(self.state, kinds, before=before, within_ms=within_ms,
                                include_parents=include_parents, predicate=predicate)

    def tainted(self, before: Event, within_ms: Optional[int] = None) -> list[Event]:
        return self.corr.tainted(self.state, before=before, within_ms=within_ms)

    def parent(self) -> Optional[SessionState]:
        return self.corr.parent(self.state)

    def first_seen_host(self, host: Optional[str], when: int, event_id: Optional[str] = None) -> bool:
        return self.corr.is_first_seen_host(host, when, event_id)

    def denies_within(self, before: Event, within_ms: int) -> int:
        return self.corr.denies_within(self.state, before, within_ms)

    def allowlisted_host(self, host: Optional[str]) -> bool:
        if not host:
            return False
        allow = self.config.get("allow_hosts") or []
        h = host.lower()
        return any(h == a.lower() or h.endswith("." + a.lower().lstrip("*.")) for a in allow if a)

    def allowlisted_path(self, path: Optional[str]) -> bool:
        if not path:
            return False
        allow = self.config.get("allow_paths") or []
        norm = _norm(path)
        for a in allow:
            if not a:
                continue
            if a.startswith(("/", "~", "$")):
                # A prefix: containment on the *normalised* path at a segment boundary, so
                # /home/u/proj/../.ssh/id_rsa is not "inside" /home/u/proj and /home/u/project is not either.
                base = _norm(a).rstrip("/") or "/"
                if norm == base or norm.startswith(base.rstrip("/") + "/"):
                    return True
            elif norm.endswith(a) and ".." not in a:
                return True  # a suffix such as .env.example
        return False

    @property
    def window_ms(self) -> int:
        return self.corr.window_ms


class Rule(Protocol):
    id: str
    name: str
    description: str
    severity: str
    triggers: tuple[str, ...]
    attack: list[dict]
    attack_note: Optional[str]
    false_positives: str
    required_fields: tuple[str, ...]

    def evaluate(self, event: Event, ctx: RuleContext) -> Optional[Finding]: ...


def all_rules() -> list:
    from . import baseline

    return list(baseline.RULES)


def rule_index() -> dict[str, object]:
    return {r.id: r for r in all_rules()}


__all__ = ["Finding", "RuleContext", "Rule", "all_rules", "rule_index"]
