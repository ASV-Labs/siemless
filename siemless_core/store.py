"""Local store: events, findings, exporter health, first-seen hosts.

One SQLite database per Hermes profile at ``<HERMES_HOME>/plugin-data/siemless/siemless.db``,
created 0600 inside a 0700 directory. Retention is by age and by row count, both configurable.
The store never holds a secret on purpose: everything written has been through ``redact``.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import threading
import time
from pathlib import Path
from typing import Any, Iterable, Optional

from . import PLUGIN_ID
from .events import Event

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    time INTEGER NOT NULL,
    kind TEXT NOT NULL,
    visibility TEXT NOT NULL,
    severity TEXT NOT NULL,
    session_id TEXT,
    turn_id TEXT,
    task_id TEXT,
    tool TEXT,
    host TEXT,
    target TEXT,
    body TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_events_time ON events(time);
CREATE INDEX IF NOT EXISTS ix_events_session ON events(session_id, time);
CREATE INDEX IF NOT EXISTS ix_events_kind ON events(kind, time);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    time INTEGER NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    session_id TEXT,
    turn_id TEXT,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    acked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_findings_time ON findings(time);
CREATE INDEX IF NOT EXISTS ix_findings_rule ON findings(rule_id, time);

CREATE TABLE IF NOT EXISTS hosts_seen (
    host TEXT PRIMARY KEY,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    count INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS exporter_health (
    name TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL,
    sent INTEGER NOT NULL DEFAULT 0,
    failed INTEGER NOT NULL DEFAULT 0,
    dropped INTEGER NOT NULL DEFAULT 0,
    spooled INTEGER NOT NULL DEFAULT 0,
    last_ok INTEGER,
    last_error_at INTEGER,
    last_error TEXT,
    state TEXT NOT NULL DEFAULT 'idle'
);

CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
"""


def default_data_dir() -> Path:
    """``<HERMES_HOME>/plugin-data/siemless``, through Hermes's own helper when available."""
    try:  # inside Hermes: the documented per-plugin storage helper
        from plugins.plugin_storage import plugin_data_dir  # type: ignore

        path = Path(plugin_data_dir(PLUGIN_ID))
    except Exception:
        try:
            from hermes_constants import get_hermes_home  # type: ignore

            root = Path(get_hermes_home())
        except Exception:
            root = Path(os.getenv("HERMES_HOME") or (Path.home() / ".hermes"))
        path = root / "plugin-data" / PLUGIN_ID
    path.mkdir(parents=True, exist_ok=True)
    _tighten(path, 0o700)
    return path


def _tighten(path: Path, mode: int) -> None:
    try:
        if os.name == "posix":
            os.chmod(path, mode)
    except OSError:
        pass


class Store:
    """Thread-safe local store. One instance per database path (``Store.shared``)."""

    _instances: dict[str, "Store"] = {}
    _instances_lock = threading.Lock()

    @classmethod
    def shared(cls, path: Optional[Path] = None) -> "Store":
        p = Path(path) if path else default_data_dir() / "siemless.db"
        key = str(p)
        with cls._instances_lock:
            inst = cls._instances.get(key)
            if inst is None:
                inst = cls(p)
                cls._instances[key] = inst
            return inst

    @classmethod
    def reset_shared(cls) -> None:
        with cls._instances_lock:
            for inst in cls._instances.values():
                inst.close()
            cls._instances.clear()

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        _tighten(self.path.parent, 0o700)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False, timeout=5.0)
        self._conn.row_factory = sqlite3.Row
        try:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
        except sqlite3.DatabaseError:
            pass
        with self._lock:
            self._conn.executescript(_SCHEMA)
        for suffix in ("", "-wal", "-shm"):
            p = Path(str(self.path) + suffix)
            if p.exists():
                _tighten(p, 0o600)

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass

    # ------------------------------------------------------------------ events
    def add_events(self, events: Iterable[Event]) -> int:
        rows = []
        for e in events:
            rows.append((e.id, e.time, e.kind, e.visibility, e.severity, e.session_id, e.turn_id, e.task_id,
                         e.tool, e.host, e.target, json.dumps(e.to_dict(), separators=(",", ":"), ensure_ascii=False)))
        if not rows:
            return 0
        with self._lock:
            self._conn.executemany(
                "INSERT OR IGNORE INTO events(id,time,kind,visibility,severity,session_id,turn_id,task_id,tool,host,target,body)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)
            self._conn.commit()
        return len(rows)

    def events(self, *, since: Optional[int] = None, kind: Optional[str] = None, session_id: Optional[str] = None,
               limit: int = 200, ids: Optional[Iterable[str]] = None) -> list[dict]:
        q = "SELECT body FROM events WHERE 1=1"
        args: list[Any] = []
        if ids is not None:
            idl = list(ids)
            if not idl:
                return []
            q += f" AND id IN ({','.join('?' * len(idl))})"
            args += idl
        if since is not None:
            q += " AND time >= ?"
            args.append(since)
        if kind:
            q += " AND kind = ?"
            args.append(kind)
        if session_id:
            q += " AND session_id = ?"
            args.append(session_id)
        q += " ORDER BY time DESC LIMIT ?"
        args.append(max(1, min(int(limit), 5000)))
        with self._lock:
            rows = self._conn.execute(q, args).fetchall()
        return [json.loads(r["body"]) for r in rows]

    def count_events(self, since: Optional[int] = None) -> int:
        with self._lock:
            if since is None:
                return int(self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])
            return int(self._conn.execute("SELECT COUNT(*) FROM events WHERE time >= ?", (since,)).fetchone()[0])

    def kind_counts(self, since: Optional[int] = None) -> dict[str, int]:
        with self._lock:
            if since is None:
                rows = self._conn.execute("SELECT kind, COUNT(*) c FROM events GROUP BY kind").fetchall()
            else:
                rows = self._conn.execute("SELECT kind, COUNT(*) c FROM events WHERE time >= ? GROUP BY kind", (since,)).fetchall()
        return {r["kind"]: int(r["c"]) for r in rows}

    # ---------------------------------------------------------------- findings
    def add_finding(self, finding: dict) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO findings(id,time,rule_id,severity,confidence,session_id,turn_id,title,body)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (finding["id"], finding["time"], finding["rule_id"], finding["severity"], finding["confidence"],
                 finding.get("session_id"), finding.get("turn_id"), finding["title"],
                 json.dumps(finding, separators=(",", ":"), ensure_ascii=False)))
            self._conn.commit()

    def findings(self, *, since: Optional[int] = None, rule_id: Optional[str] = None, session_id: Optional[str] = None,
                 limit: int = 100, include_acked: bool = True) -> list[dict]:
        q = "SELECT body, acked FROM findings WHERE 1=1"
        args: list[Any] = []
        if since is not None:
            q += " AND time >= ?"
            args.append(since)
        if rule_id:
            q += " AND rule_id = ?"
            args.append(rule_id)
        if session_id:
            q += " AND session_id = ?"
            args.append(session_id)
        if not include_acked:
            q += " AND acked = 0"
        q += " ORDER BY time DESC LIMIT ?"
        args.append(max(1, min(int(limit), 2000)))
        with self._lock:
            rows = self._conn.execute(q, args).fetchall()
        out = []
        for r in rows:
            d = json.loads(r["body"])
            d["acked"] = bool(r["acked"])
            out.append(d)
        return out

    def finding(self, finding_id: str) -> Optional[dict]:
        with self._lock:
            r = self._conn.execute("SELECT body, acked FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if not r:
            return None
        d = json.loads(r["body"])
        d["acked"] = bool(r["acked"])
        return d

    def ack_finding(self, finding_id: str, acked: bool = True) -> bool:
        with self._lock:
            cur = self._conn.execute("UPDATE findings SET acked = ? WHERE id = ?", (1 if acked else 0, finding_id))
            self._conn.commit()
        return cur.rowcount > 0

    def finding_counts(self, since: Optional[int] = None) -> dict[str, int]:
        with self._lock:
            if since is None:
                rows = self._conn.execute("SELECT severity, COUNT(*) c FROM findings GROUP BY severity").fetchall()
            else:
                rows = self._conn.execute("SELECT severity, COUNT(*) c FROM findings WHERE time >= ? GROUP BY severity", (since,)).fetchall()
        return {r["severity"]: int(r["c"]) for r in rows}

    def rule_counts(self, since: Optional[int] = None) -> dict[str, int]:
        with self._lock:
            if since is None:
                rows = self._conn.execute("SELECT rule_id, COUNT(*) c FROM findings GROUP BY rule_id").fetchall()
            else:
                rows = self._conn.execute("SELECT rule_id, COUNT(*) c FROM findings WHERE time >= ? GROUP BY rule_id", (since,)).fetchall()
        return {r["rule_id"]: int(r["c"]) for r in rows}

    # ------------------------------------------------------------------- hosts
    def note_host(self, host: str, when: int) -> bool:
        """Record a destination host. Returns True when this is the first time it was seen."""
        if not host:
            return False
        with self._lock:
            row = self._conn.execute("SELECT 1 FROM hosts_seen WHERE host = ?", (host,)).fetchone()
            if row:
                self._conn.execute("UPDATE hosts_seen SET last_seen = ?, count = count + 1 WHERE host = ?", (when, host))
                first = False
            else:
                self._conn.execute("INSERT INTO hosts_seen(host, first_seen, last_seen) VALUES (?,?,?)", (host, when, when))
                first = True
            self._conn.commit()
        return first

    def hosts(self, limit: int = 500) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM hosts_seen ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    # -------------------------------------------------------------- exporters
    def exporter_health(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM exporter_health ORDER BY name").fetchall()
        return [dict(r) for r in rows]

    def set_exporter_health(self, name: str, **fields: Any) -> None:
        cols = ["enabled", "sent", "failed", "dropped", "spooled", "last_ok", "last_error_at", "last_error", "state"]
        with self._lock:
            exists = self._conn.execute("SELECT 1 FROM exporter_health WHERE name = ?", (name,)).fetchone()
            if not exists:
                self._conn.execute("INSERT INTO exporter_health(name, enabled) VALUES (?, ?)", (name, int(bool(fields.get("enabled", True)))))
            sets = [f"{c} = ?" for c in cols if c in fields]
            if sets:
                vals = [fields[c] if c not in ("enabled",) else int(bool(fields[c])) for c in cols if c in fields]
                self._conn.execute(f"UPDATE exporter_health SET {', '.join(sets)} WHERE name = ?", (*vals, name))
            self._conn.commit()

    def bump_exporter(self, name: str, **deltas: int) -> None:
        with self._lock:
            exists = self._conn.execute("SELECT 1 FROM exporter_health WHERE name = ?", (name,)).fetchone()
            if not exists:
                self._conn.execute("INSERT INTO exporter_health(name, enabled) VALUES (?, 1)", (name,))
            for col, d in deltas.items():
                if col in ("sent", "failed", "dropped", "spooled") and d:
                    self._conn.execute(f"UPDATE exporter_health SET {col} = {col} + ? WHERE name = ?", (int(d), name))
            self._conn.commit()

    # -------------------------------------------------------------------- meta
    def get_meta(self, key: str, default: Optional[str] = None) -> Optional[str]:
        with self._lock:
            r = self._conn.execute("SELECT v FROM meta WHERE k = ?", (key,)).fetchone()
        return r["v"] if r else default

    def set_meta(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute("INSERT INTO meta(k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", (key, value))
            self._conn.commit()

    # --------------------------------------------------------------- retention
    def prune(self, *, max_age_days: int = 30, max_events: int = 200_000, max_findings: int = 20_000) -> dict[str, int]:
        cutoff = int((time.time() - max_age_days * 86400) * 1000)
        with self._lock:
            a = self._conn.execute("DELETE FROM events WHERE time < ?", (cutoff,)).rowcount
            b = self._conn.execute(
                "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY time DESC LIMIT -1 OFFSET ?)", (max_events,)).rowcount
            c = self._conn.execute("DELETE FROM findings WHERE time < ?", (cutoff,)).rowcount
            d = self._conn.execute(
                "DELETE FROM findings WHERE id IN (SELECT id FROM findings ORDER BY time DESC LIMIT -1 OFFSET ?)", (max_findings,)).rowcount
            self._conn.commit()
        return {"events_by_age": a, "events_by_count": b, "findings_by_age": c, "findings_by_count": d}

    def db_size(self) -> int:
        try:
            return self.path.stat().st_size
        except OSError:
            return 0


__all__ = ["Store", "default_data_dir"]
