"""Correlation state: what has happened recently in a session, a turn, and across a delegation tree.

Bounded on every axis: at most ``max_sessions`` live sessions, at most ``max_events`` events per
session, and rules only look back ``window_ms``. Events are keyed by id so a duplicate callback is
ignored, and windows are computed on event *time*, not arrival order, so a late event still
correlates with what preceded it in the agent's own timeline.

Sessions are never merged: a child subagent session is linked to its parent (so a rule can ask
"did the parent do this too?") but keeps its own timeline.
"""

from __future__ import annotations

import time
from collections import OrderedDict, deque
from typing import Callable, Iterable, Optional

from .events import Event

UNKNOWN_SESSION = "_unknown"


class SessionState:
    __slots__ = ("session_id", "events", "seen", "parent_session_id", "children", "last_activity", "profile",
                 "turn_ids", "hosts", "denies")

    def __init__(self, session_id: str, max_events: int):
        self.session_id = session_id
        self.events: deque[Event] = deque(maxlen=max_events)
        self.seen: OrderedDict[str, None] = OrderedDict()
        self.parent_session_id: Optional[str] = None
        self.children: set[str] = set()
        self.last_activity = 0
        self.profile: Optional[str] = None
        self.turn_ids: deque[str] = deque(maxlen=64)
        self.hosts: dict[str, int] = {}
        self.denies: deque[int] = deque(maxlen=64)

    def add(self, e: Event) -> bool:
        if e.id in self.seen:
            return False
        self.seen[e.id] = None
        while len(self.seen) > self.events.maxlen * 2:
            self.seen.popitem(last=False)
        self.events.append(e)
        self.last_activity = max(self.last_activity, e.time)
        if e.turn_id and (not self.turn_ids or self.turn_ids[-1] != e.turn_id):
            self.turn_ids.append(e.turn_id)
        if e.host and e.kind == "net.egress":
            self.hosts[e.host] = self.hosts.get(e.host, 0) + 1
        if e.kind == "approval.response" and e.outcome == "denied":
            self.denies.append(e.time)
        return True


class Correlator:
    def __init__(self, *, window_ms: int = 10 * 60 * 1000, max_sessions: int = 256, max_events: int = 1000,
                 first_seen_host: Optional[Callable[[str, int], bool]] = None):
        self.window_ms = int(window_ms)
        self.max_sessions = int(max_sessions)
        self.max_events = int(max_events)
        self._sessions: OrderedDict[str, SessionState] = OrderedDict()
        self._first_seen_host = first_seen_host or (lambda host, when: False)
        self._host_cache: dict[str, tuple[Optional[str], bool]] = {}

    # ------------------------------------------------------------------ state
    def session(self, session_id: Optional[str]) -> SessionState:
        sid = session_id or UNKNOWN_SESSION
        st = self._sessions.get(sid)
        if st is None:
            st = SessionState(sid, self.max_events)
            self._sessions[sid] = st
            while len(self._sessions) > self.max_sessions:
                self._sessions.popitem(last=False)
        else:
            self._sessions.move_to_end(sid)
        return st

    def add(self, e: Event) -> Optional[SessionState]:
        """Record *e*; returns the owning state, or None when it was a duplicate."""
        sid = e.session_id or e.parent_session_id or UNKNOWN_SESSION
        st = self.session(sid)
        if e.profile and not st.profile:
            st.profile = e.profile
        if e.kind == "subagent.start" and e.child_session_id:
            child = self.session(e.child_session_id)
            child.parent_session_id = sid
            st.children.add(e.child_session_id)
        if not st.add(e):
            return None
        return st

    def parent(self, st: SessionState) -> Optional[SessionState]:
        if st.parent_session_id:
            return self._sessions.get(st.parent_session_id)
        return None

    def lineage(self, st: SessionState, depth: int = 4) -> list[SessionState]:
        """This session and its ancestors, nearest first."""
        out = [st]
        cur = st
        while cur.parent_session_id and len(out) <= depth:
            p = self._sessions.get(cur.parent_session_id)
            if not p:
                break
            out.append(p)
            cur = p
        return out

    # ---------------------------------------------------------------- queries
    def recent(self, st: SessionState, kinds: Iterable[str], *, before: Event, within_ms: Optional[int] = None,
               include_parents: bool = False, predicate: Optional[Callable[[Event], bool]] = None) -> list[Event]:
        """Events of *kinds* in the window ending at *before* (exclusive), newest first."""
        kinds = set(kinds)
        win = self.window_ms if within_ms is None else int(within_ms)
        lo = before.time - win
        states = self.lineage(st) if include_parents else [st]
        out: list[Event] = []
        for s in states:
            for e in reversed(s.events):
                if e.id == before.id:
                    continue
                if e.time > before.time:
                    continue  # arrived early relative to the agent timeline
                if e.time < lo:
                    break
                if e.kind in kinds and (predicate is None or predicate(e)):
                    out.append(e)
        out.sort(key=lambda x: x.time, reverse=True)
        return out

    def tainted(self, st: SessionState, *, before: Event, within_ms: Optional[int] = None) -> list[Event]:
        """Untrusted-content events that precede *before* in the window (this turn's taint source)."""
        return self.recent(st, ["content.untrusted"], before=before, within_ms=within_ms)

    def is_first_seen_host(self, host: Optional[str], when: int, event_id: Optional[str] = None) -> bool:
        """True the first time *host* is seen by this profile. Every rule asking about the same event gets
        the same answer; a later event asking about the host gets False."""
        if not host:
            return False
        cached = self._host_cache.get(host)
        if cached is not None:
            return cached[1] if cached[0] == event_id else False
        first = bool(self._first_seen_host(host, when))
        self._host_cache[host] = (event_id, first)
        if len(self._host_cache) > 5000:
            self._host_cache.pop(next(iter(self._host_cache)))
        return first

    def denies_within(self, st: SessionState, before: Event, within_ms: int) -> int:
        lo = before.time - within_ms
        return sum(1 for t in st.denies if lo <= t <= before.time)

    def stats(self) -> dict:
        return {"sessions": len(self._sessions), "events": sum(len(s.events) for s in self._sessions.values()),
                "window_ms": self.window_ms}


__all__ = ["Correlator", "SessionState", "UNKNOWN_SESSION"]
