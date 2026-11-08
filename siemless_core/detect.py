"""Detection engine: runs the ruleset over each correlated event and shapes findings.

Suppression happens here, in three layers, all configurable:
* disabled rules (``disable_rules``);
* allow-lists for hosts and paths (applied inside rules through ``RuleContext``);
* a dedupe cooldown: the same rule with the same ``dedupe_key`` fires at most once per
  ``finding_cooldown_s`` (default 600 s), so a loop does not produce a hundred findings.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Optional

from . import PRODUCT, VENDOR, __version__
from .correlate import Correlator, SessionState
from .events import Event, now_ms
from .rules import Finding, RuleContext, all_rules


_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class Engine:
    def __init__(self, corr: Correlator, config: Optional[dict] = None):
        self.corr = corr
        self.config = dict(config or {})
        self.rules = [r for r in all_rules() if r.id not in set(self.config.get("disable_rules") or [])]
        self._by_trigger: dict[str, list] = {}
        for r in self.rules:
            for k in r.triggers:
                self._by_trigger.setdefault(k, []).append(r)
        self._recent: OrderedDict[str, tuple[int, int]] = OrderedDict()
        self.cooldown_ms = int(float(self.config.get("finding_cooldown_s", 600)) * 1000)
        self.evaluations = 0
        self.suppressed = 0

    def evaluate(self, event: Event, state: SessionState) -> list[Finding]:
        rules = self._by_trigger.get(event.kind)
        if not rules:
            return []
        ctx = RuleContext(self.corr, state, self.config)
        out: list[Finding] = []
        for rule in rules:
            self.evaluations += 1
            try:
                f = rule.evaluate(event, ctx)
            except Exception:
                continue  # a broken rule must never break telemetry
            if f is None:
                continue
            if self._suppressed(f, event.time):
                self.suppressed += 1
                continue
            out.append(f)
        return out

    def _suppressed(self, f: Finding, when: int) -> bool:
        """Same rule + dedupe key inside the cooldown is one finding, unless the new one is more severe:
        an escalation (a small owner message, then a 5 kB one to a stranger) is never masked."""
        key = f"{f.rule_id}|{f.dedupe_key}"
        rank = _SEV_RANK.get(f.severity, 0)
        last = self._recent.get(key)
        if last is not None and when - last[0] < self.cooldown_ms and rank <= last[1]:
            return True
        self._recent[key] = (when, rank)
        self._recent.move_to_end(key)
        while len(self._recent) > 4096:
            self._recent.popitem(last=False)
        return False

    def rule_table(self) -> list[dict]:
        return [{"id": r.id, "name": r.name, "severity": r.severity, "triggers": list(r.triggers),
                 "attack": [a["id"] for a in r.attack], "attack_note": r.attack_note,
                 "description": r.description, "false_positives": r.false_positives,
                 "required_fields": list(r.required_fields), "enabled": True} for r in self.rules] + [
            {"id": rid, "enabled": False} for rid in (self.config.get("disable_rules") or [])]


def finding_to_dict(f: Finding, *, profile: Optional[str] = None, replay: bool = False) -> dict:
    """The stored / exported form of a finding. Evidence is summarised; full events are in the store."""
    conf = f.confidence()
    vis = f.visibility_summary()
    return {
        "id": f.id,
        "time": f.evidence[-1].time if f.evidence else now_ms(),
        "detected_at": now_ms(),
        "schema": "siemless.finding.v1",
        "replay": bool(replay),
        "rule_id": f.rule_id,
        "rule_name": f.name,
        "severity": f.severity,
        "confidence": conf,
        "title": ("[REPLAY] " + f.title) if replay else f.title,
        "observed": f.observed,
        "why": f.why,
        "recommendation": f.recommendation,
        "missing_evidence": list(f.missing_evidence),
        "attack": list(f.attack),
        "attack_note": f.attack_note,
        "session_id": f.session_id,
        "turn_id": f.turn_id,
        "profile": profile,
        "visibility": vis,
        "evidence": [{"id": e.id, "time": e.time, "kind": e.kind, "visibility": e.visibility, "tool": e.tool,
                      "action": e.action, "target": e.target, "host": e.host, "tags": list(e.tags)} for e in f.evidence],
        "product": {"vendor": VENDOR, "name": PRODUCT, "version": __version__},
    }


def finding_event(fd: dict) -> Event:
    """A finding as an event, so it flows through the same store and exporters as everything else."""
    return Event(kind="finding", visibility="observed", id="f-" + fd["id"], time=fd["time"], session_id=fd.get("session_id"),
                 turn_id=fd.get("turn_id"), profile=fd.get("profile"), severity=fd["severity"], target=fd["title"],
                 rule_ids=[fd["rule_id"]], evidence=[e["id"] for e in fd["evidence"]],
                 attrs={"confidence": fd["confidence"], "attack": [a["id"] for a in fd["attack"]], "finding_id": fd["id"],
                        **({"replay": True} if fd.get("replay") else {})},
                 tags=(["replay", "finding"] if fd.get("replay") else ["finding"]))


__all__ = ["Engine", "finding_to_dict", "finding_event"]
