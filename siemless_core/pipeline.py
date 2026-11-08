"""The pipeline: hook payload → events → store → correlation → findings → dispatch.

``Pipeline.ingest(hook, payload)`` is what the hook callbacks call. It does the cheap part on the
agent thread (collect + enqueue) and everything else on its own worker. ``Pipeline.process_now``
runs the whole chain synchronously for tests and for ``replay``.
"""

from __future__ import annotations

import logging
import queue
import socket
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from . import PLUGIN_ID, __version__
from .collectors import collect
from .config import in_scope, load as load_config
from .correlate import Correlator
from .detect import Engine, finding_event, finding_to_dict
from .dispatch import Dispatcher
from .events import REPLAY_TAG, Event
from .exporters.http import ElasticExporter, HecExporter, SummitExporter
from .exporters.jsonl import JsonlExporter
from .exporters.syslog import SyslogExporter
from .store import Store, default_data_dir

log = logging.getLogger("hermes.plugins.siemless")


# Which setting names each remote destination. Clearing one stops that exporter in a running agent.
DESTINATION_SETTINGS = {"syslog": "syslog_target", "hec": "hec_url", "elastic": "elastic_url", "summit": "summit_url"}
SETTINGS_POLL_S = 5.0


class Pipeline:
    def __init__(self, config: Optional[dict] = None, *, store: Optional[Store] = None, data_dir: Optional[Path] = None,
                 emit: Optional[Callable[[str, dict], None]] = None, worker: bool = True, profile: Optional[str] = None,
                 reload_config: Optional[Callable[[], dict]] = None):
        self.config = config or load_config()
        self._reload_config = reload_config
        self.data_dir = Path(data_dir) if data_dir else default_data_dir()
        self.store = store or Store.shared(self.data_dir / "siemless.db")
        self.profile = profile
        self.hostname = self.config.get("hostname") or socket.gethostname()
        self.emit = emit or (lambda name, payload: None)
        self.corr = Correlator(window_ms=int(self.config["window_minutes"]) * 60 * 1000,
                               first_seen_host=self._first_seen_host)
        self.engine = Engine(self.corr, self.config)
        # Replays (fixtures, recordings) run in their own namespace: their own correlation state and an
        # in-memory host history, so a forged recording can neither correlate with live sessions nor
        # mark a destination as "already known" for live first-seen checks.
        self._replay_hosts: set[str] = set()
        self.replay_corr = Correlator(window_ms=int(self.config["window_minutes"]) * 60 * 1000,
                                      first_seen_host=self._replay_first_seen)
        self.replay_engine = Engine(self.replay_corr, self.config)
        self._in: "queue.Queue[Event]" = queue.Queue(maxsize=max(1000, int(self.config["queue_size"])))
        self.dropped_in = 0
        self.processed = 0
        self.findings_total = 0
        self.owns_hooks = True  # False in a one-shot CLI process: it has a worker but is not the agent
        self.last_event_at: Optional[int] = None
        self.last_finding_at: Optional[int] = None
        self.started_at = int(time.time() * 1000)
        self.dispatcher = Dispatcher(spool_dir=self.data_dir / "spool", queue_size=int(self.config["queue_size"]),
                                     spool_max_mb=float(self.config["spool_max_mb"]), on_health=self._save_health, worker=worker)
        self._build_exporters()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_prune = 0.0
        self._process_lock = threading.RLock()  # replay/test paths run on other threads than the worker
        if worker:
            self._thread = threading.Thread(target=self._run, name="siemless-pipeline", daemon=True)
            self._thread.start()
            if reload_config is not None:  # its own thread: reading settings can block, and events must not wait on it
                threading.Thread(target=self._watch_settings, name="siemless-settings", daemon=True).start()

    # ------------------------------------------------------------------ exporters
    def _build_exporters(self) -> None:
        cfg = self.config
        consent = bool(cfg.get("remote_export"))
        if cfg.get("jsonl_enabled", True):
            self.dispatcher.add(JsonlExporter({"path": cfg.get("jsonl_path") or None, "format": cfg.get("jsonl_format"),
                                               "max_mb": cfg.get("jsonl_max_mb", 50), "hostname": self.hostname}, data_dir=self.data_dir))
        remote_state = "idle" if consent else "needs_consent"
        if cfg.get("syslog_target"):
            try:
                self.dispatcher.add(SyslogExporter({"target": cfg["syslog_target"], "format": cfg.get("syslog_format"),
                                                    "ca_file": cfg.get("syslog_ca_file") or None, "hostname": self.hostname}), state=remote_state)
            except ValueError as exc:
                log.warning("siemless: syslog exporter not started: %s", exc)
        if cfg.get("hec_url"):
            try:
                self.dispatcher.add(HecExporter({"url": cfg["hec_url"], "index": cfg.get("hec_index") or None,
                                                 "sourcetype": cfg.get("hec_sourcetype"), "format": cfg.get("hec_format"),
                                                 "ca_file": cfg.get("http_ca_file") or None, "hostname": self.hostname}), state=remote_state)
            except ValueError as exc:
                log.warning("siemless: hec exporter not started: %s", exc)
        if cfg.get("elastic_url"):
            try:
                self.dispatcher.add(ElasticExporter({"url": cfg["elastic_url"], "data_stream": cfg.get("elastic_data_stream"),
                                                     "ca_file": cfg.get("http_ca_file") or None, "hostname": self.hostname}), state=remote_state)
            except ValueError as exc:
                log.warning("siemless: elastic exporter not started: %s", exc)
        if cfg.get("summit_url"):
            try:
                self.dispatcher.add(SummitExporter({"url": cfg["summit_url"], "ca_file": cfg.get("http_ca_file") or None,
                                                    "hostname": self.hostname, "agent": self.profile or "hermes",
                                                    "allow_loopback_http": bool(cfg.get("allow_loopback_http"))},
                                                   finding_lookup=self.store.finding), state=remote_state)
            except ValueError as exc:
                log.warning("siemless: summit exporter not started: %s", exc)
        for slot in self.dispatcher.slots.values():
            self.store.set_exporter_health(slot.exporter.name, enabled=slot.enabled, state=slot.state)

    def _watch_settings(self) -> None:
        while not self._stop.wait(SETTINGS_POLL_S):
            self.refresh_delivery_settings()

    def refresh_delivery_settings(self) -> None:
        """Honour a withdrawn or restored consent, or a cleared destination, without a restart.

        Consent is a promise about what leaves the machine, so it cannot wait for the gateway to restart.
        A destination that is added or changed still needs a restart, because that builds a new exporter."""
        if self._reload_config is None:
            return
        try:
            cfg = self._reload_config()
        except Exception as exc:  # unreadable settings change nothing
            log.debug("siemless settings reload: %s", exc)
            return
        consent = bool(cfg.get("remote_export"))
        self.config["remote_export"] = consent
        self.dispatcher.set_consent(consent)
        for name, key in DESTINATION_SETTINGS.items():
            if key in cfg and not cfg[key]:
                self.config[key] = cfg[key]
                self.dispatcher.remove(name)

    def _save_health(self, health: list[dict]) -> None:
        for h in health:
            self.store.set_exporter_health(h["name"], enabled=h["enabled"], state=h["state"], sent=h["sent"], failed=h["failed"],
                                           dropped=h["dropped"], spooled=h["spooled"], last_ok=h["last_ok"],
                                           last_error=h["last_error"], last_error_at=h["last_error_at"])
        self.emit("health", {"exporters": health, "queue": self.dispatcher.queue_health()})

    def _first_seen_host(self, host: str, when: int) -> bool:
        return self.store.note_host(host, when)

    def _replay_first_seen(self, host: str, when: int) -> bool:
        if host in self._replay_hosts:
            return False
        if len(self._replay_hosts) > 10_000:
            self._replay_hosts.clear()
        self._replay_hosts.add(host)
        return True

    @staticmethod
    def _mark_replay(e: Event) -> None:
        if REPLAY_TAG not in e.tags:
            e.tags.insert(0, REPLAY_TAG)
        e.attrs["replay"] = True

    # ------------------------------------------------------------------ ingress
    def ingest(self, hook: str, payload: dict) -> list[Event]:
        """Agent-thread entry point: collect, enqueue, return. Microseconds."""
        events = collect(hook, payload, config=self.config)
        replay = bool(isinstance(payload, dict) and payload.get("_replay"))
        for e in events:
            e.profile = e.profile or self.profile
            if replay:
                self._mark_replay(e)
            try:
                self._in.put_nowait(e)
            except queue.Full:
                self.dropped_in += 1
        return events

    def process_now(self, hook: str, payload: dict) -> tuple[list[Event], list[dict]]:
        """Synchronous: collect and run the full chain on the caller's thread (tests, replay)."""
        events = collect(hook, payload, config=self.config)
        replay = bool(isinstance(payload, dict) and payload.get("_replay"))
        findings: list[dict] = []
        for e in events:
            e.profile = e.profile or self.profile
            if replay:
                self._mark_replay(e)
            findings += self._process(e)
        return events, findings

    def process_event(self, e: Event) -> list[dict]:
        return self._process(e)

    # ------------------------------------------------------------------ worker
    def _run(self) -> None:
        while not self._stop.is_set():
            self._housekeeping()  # wall-clock check every iteration: a busy agent must still get pruned
            try:
                e = self._in.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._process(e)
            except Exception as exc:  # never die
                log.debug("siemless pipeline: %s", exc)

    def _process(self, e: Event) -> list[dict]:
        with self._process_lock:
            return self._process_locked(e)

    def _process_locked(self, e: Event) -> list[dict]:
        t0 = time.monotonic()
        self.store.add_events([e])
        self.processed += 1
        self.last_event_at = e.time
        out: list[dict] = []
        replay = REPLAY_TAG in e.tags
        corr, engine = (self.replay_corr, self.replay_engine) if replay else (self.corr, self.engine)
        st = corr.add(e)
        to_export: list[Event] = []
        if in_scope(e.kind, e.tags, self.config["export_scope"]):
            to_export.append(e)
        if st is not None:
            for f in engine.evaluate(e, st):
                fd = finding_to_dict(f, profile=self.profile, replay=replay)
                # Stored with the finding, not exported: the Desktop page and the CLI read from another process.
                self.store.add_finding({**fd, "latency_ms": round((time.monotonic() - t0) * 1000, 2)})
                fe = finding_event(fd)
                self.store.add_events([fe])
                corr.add(fe)
                to_export.append(fe)
                out.append(fd)
                self.findings_total += 1
                self.last_finding_at = fd["detected_at"]
                self.emit("finding", fd)
        if to_export:
            self.dispatcher.offer(to_export)
        return out

    def _housekeeping(self) -> None:
        now = time.monotonic()
        if now - self._last_prune > 3600:
            self._last_prune = now
            try:
                self.store.prune(max_age_days=int(self.config["retention_days"]), max_events=int(self.config["max_events"]))
            except Exception:
                pass

    # ------------------------------------------------------------------ status
    @property
    def live(self) -> bool:
        """True in the process that owns the hooks; False for a read-only instance over the same store."""
        return self._thread is not None and self.owns_hooks

    def status(self) -> dict:
        since_day = int(time.time() * 1000) - 86_400_000
        exporters = self.exporter_health()
        latency = self.store.finding_latencies()
        return {
            "plugin": PLUGIN_ID, "version": __version__, "profile": self.profile, "hostname": self.hostname,
            "started_at": self.started_at, "processed": self.processed, "dropped_in": self.dropped_in,
            # Totals come from the store: the Desktop page and the CLI read through their own process, whose
            # in-memory counter is always 0 (it raised nothing itself). The counter stays as since_start.
            "findings_total": sum(self.store.finding_counts().values()), "findings_since_start": self.findings_total,
            "last_event_at": self.last_event_at, "last_finding_at": self.last_finding_at,
            "events_24h": self.store.count_events(since_day), "kinds_24h": self.store.kind_counts(since_day),
            "findings_24h": self.store.finding_counts(since_day), "rules_24h": self.store.rule_counts(since_day),
            "rules": {"enabled": len(self.engine.rules), "evaluations": self.engine.evaluations, "suppressed": self.engine.suppressed},
            "correlator": self.corr.stats(), "queue": self.dispatcher.queue_health(), "exporters": exporters, "live": self.live,
            "export_scope": self.config["export_scope"], "remote_export": bool(self.config.get("remote_export")),
            "db_bytes": self.store.db_size(), "hosts_known": self.store.host_count(), "sessions_24h": self.store.session_count(since_day),
            "latency_ms": {"p50": _pct(latency, 50), "p95": _pct(latency, 95), "n": len(latency)},
        }

    def exporter_health(self) -> list[dict]:
        return self.dispatcher.health() if self.live else self._stored_exporters()

    def _stored_exporters(self) -> list[dict]:
        out = []
        for r in self.store.exporter_health():
            slot = self.dispatcher.slots.get(r["name"])
            if slot is None:  # its destination has been cleared; the old row says nothing about the settings now
                continue
            d = dict(r)
            d["enabled"] = bool(d.get("enabled"))
            d.update(slot.exporter.describe())
            if slot.state == "needs_consent":  # a failure from before consent was withdrawn is not a failure now
                d["state"] = "needs_consent"
            out.append(d)
        return out

    def flush(self, timeout: float = 3.0) -> None:
        """Tests: wait for the input queue and dispatcher to drain."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and (not self._in.empty() or not self.dispatcher.q.empty()):
            time.sleep(0.02)

    def close(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(2.0)
        self.dispatcher.stop()


def _pct(xs: list[float], p: int) -> Optional[float]:
    if not xs:
        return None
    s = sorted(xs)
    return s[min(len(s) - 1, int(len(s) * p / 100))]


__all__ = ["Pipeline"]
