"""Bounded, non-blocking dispatch from the agent thread to the exporters.

The agent thread only does ``offer()``: a non-blocking put on a bounded queue. Everything slow
(formatting, sockets, HTTPS, disk) happens on one daemon worker thread. Guarantees, as tested:

* **Never blocks the agent.** A full queue drops the oldest event and counts the drop.
* **A dead destination never breaks the session.** Failures are counted, retried with capped
  exponential backoff, and the batch goes to a per-exporter on-disk spool (bounded by
  ``spool_max_mb``; beyond that, dropped and counted). When the exporter recovers the spool is
  replayed first, in order.
* **Delivery is at-least-once per destination**, not exactly-once: a batch that was written but
  whose acknowledgement was lost is sent again. Every event carries its id, so receivers dedupe.
* **A refused destination (401/403) is not abandoned**: its events spool and it is retried every
  ``BACKOFF_MAX_S``; health says ``refused`` with the reason until a send succeeds.
* **Best-effort only when the spool is full or the process dies with a non-empty queue**: those
  events are lost and the loss is visible in ``dropped``.
"""

from __future__ import annotations

import json
import os
import queue
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from .events import Event
from .exporters import Exporter, ExportError, ExportRefused

BATCH_MAX = 200
BATCH_WAIT_S = 0.5
BACKOFF_BASE_S = 2.0
BACKOFF_MAX_S = 300.0


class _Slot:
    """Per-exporter runtime state."""

    def __init__(self, exporter: Exporter, spool_dir: Path, spool_max_bytes: int, enabled: bool, state: str):
        self.exporter = exporter
        self.enabled = enabled
        self.state = state                # idle | ok | retrying | refused | needs_consent | disabled
        self.failures = 0
        self.next_retry = 0.0
        self.sent = 0
        self.failed = 0
        self.dropped = 0
        self.spooled = 0
        self.last_ok: Optional[int] = None
        self.last_error: Optional[str] = None
        self.last_error_at: Optional[int] = None
        self.spool = spool_dir / f"{exporter.name}.spool.jsonl"
        self.spool_max = spool_max_bytes
        self.dirty = True

    def health(self) -> dict:
        return {"name": self.exporter.name, "enabled": self.enabled, "state": self.state, "sent": self.sent, "failed": self.failed,
                "dropped": self.dropped, "spooled": self.spooled, "last_ok": self.last_ok, "last_error": self.last_error,
                "last_error_at": self.last_error_at, "spool_bytes": self._spool_size(), **self.exporter.describe()}

    def _spool_size(self) -> int:
        try:
            return self.spool.stat().st_size
        except OSError:
            return 0

    # ------------------------------------------------------------ spool
    def spool_batch(self, batch: list[Event]) -> None:
        # ensure_ascii: U+2028/U+0085 etc. stay escaped, so a record is always exactly one "\n"-terminated line.
        lines = [json.dumps(e.to_dict(), separators=(",", ":"), ensure_ascii=True) for e in batch]
        incoming = sum(len(l) + 1 for l in lines)
        if self._spool_size() + incoming > self.spool_max:
            self.dropped += len(batch)
            self.dirty = True
            return
        fd = os.open(str(self.spool), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        self.spooled += len(batch)
        self.dirty = True

    def drain_spool(self) -> bool:
        """Replay the spool. Returns True when it is empty afterwards."""
        if not self.spool.exists():
            return True
        try:
            with open(self.spool, "r", encoding="utf-8") as fh:
                lines = [l for l in fh.read().split("\n") if l.strip()]
        except OSError:
            return True
        batch: list[Event] = []
        done = 0
        for line in lines:
            try:
                batch.append(Event.from_dict(json.loads(line)))
            except Exception:
                done += 1
                continue
            if len(batch) >= BATCH_MAX:
                self.exporter.send(batch)
                self.sent += len(batch)
                done += len(batch)
                batch = []
                self._truncate_spool(lines[done:])
        if batch:
            self.exporter.send(batch)
            self.sent += len(batch)
            done += len(batch)
        self._truncate_spool(lines[done:])
        return done >= len(lines)

    def _truncate_spool(self, remaining: list[str]) -> None:
        if not remaining:
            try:
                self.spool.unlink()
            except OSError:
                pass
            return
        tmp = self.spool.with_suffix(".tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(remaining) + "\n")
        os.replace(tmp, self.spool)


class Dispatcher:
    def __init__(self, *, spool_dir: Path, queue_size: int = 10_000, spool_max_mb: float = 20.0,
                 on_health: Optional[Callable[[list[dict]], None]] = None, worker: bool = True):
        self.q: "queue.Queue[Event]" = queue.Queue(maxsize=max(100, int(queue_size)))
        self.spool_dir = Path(spool_dir)
        self.spool_dir.mkdir(parents=True, exist_ok=True)
        self.spool_max = int(spool_max_mb * 1024 * 1024)
        self.slots: dict[str, _Slot] = {}
        self.dropped_queue = 0
        self.received = 0
        self._on_health = on_health
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._deliver_lock = threading.Lock()  # test-exporter and replay deliver from other threads
        self._thread: Optional[threading.Thread] = None
        self._last_health = 0.0
        if worker:
            self.start()

    # ------------------------------------------------------------ exporters
    def add(self, exporter: Exporter, *, enabled: bool = True, state: str = "idle") -> _Slot:
        slot = _Slot(exporter, self.spool_dir, self.spool_max, enabled, state)
        with self._lock:
            self.slots[exporter.name] = slot
        return slot

    def remove(self, name: str) -> None:
        with self._lock:
            slot = self.slots.pop(name, None)
        if slot is not None:
            try:
                slot.exporter.close()
            except Exception:  # the slot is gone either way; a socket that will not close must not stop the watcher
                pass

    def set_consent(self, granted: bool) -> None:
        """Apply the remote_export setting to every remote exporter, in either direction."""
        with self._lock:
            slots = [s for s in self.slots.values() if s.exporter.remote]
        for slot in slots:
            if not granted and slot.state != "needs_consent":
                slot.state = "needs_consent"
                slot.dirty = True
            elif granted and slot.state == "needs_consent":
                slot.state = "idle"
                slot.next_retry = 0.0
                slot.dirty = True

    # ------------------------------------------------------------ producer
    def offer(self, events: list[Event]) -> None:
        """Agent-thread side. Never blocks: on a full queue the oldest event is dropped."""
        for e in events:
            self.received += 1
            try:
                self.q.put_nowait(e)
            except queue.Full:
                try:
                    self.q.get_nowait()
                    self.dropped_queue += 1
                    self.q.put_nowait(e)
                except (queue.Empty, queue.Full):
                    self.dropped_queue += 1

    # ------------------------------------------------------------ worker
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="siemless-dispatch", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout)
        for s in self.slots.values():
            s.exporter.close()

    def _run(self) -> None:
        while not self._stop.is_set():
            batch = self._next_batch()
            if batch:
                self.deliver(batch)
            self._maybe_health()
        # final flush
        batch = self._next_batch(wait=False)
        if batch:
            self.deliver(batch)
        self._maybe_health(force=True)

    def _next_batch(self, wait: bool = True) -> list[Event]:
        batch: list[Event] = []
        try:
            first = self.q.get(timeout=BATCH_WAIT_S) if wait else self.q.get_nowait()
        except queue.Empty:
            return batch
        batch.append(first)
        deadline = time.monotonic() + 0.05
        while len(batch) < BATCH_MAX and time.monotonic() < deadline:
            try:
                batch.append(self.q.get_nowait())
            except queue.Empty:
                break
        return batch

    def deliver(self, batch: list[Event]) -> None:
        """Synchronous delivery of one batch to every enabled exporter (also used directly by tests)."""
        with self._deliver_lock:
            self._deliver(batch)

    def _deliver(self, batch: list[Event]) -> None:
        now = time.monotonic()
        with self._lock:
            slots = list(self.slots.values())
        local_batch = batch
        for slot in slots:
            if not slot.enabled or slot.state in ("needs_consent", "disabled"):
                continue
            batch = local_batch
            if slot.exporter.remote:
                # Replayed recordings never leave the machine: a fixture is not evidence about a live agent,
                # and remote consent was given for the agent's telemetry, not for files someone fed in.
                batch = [e for e in local_batch if "replay" not in e.tags]
                if not batch:
                    continue
            if now < slot.next_retry:
                slot.spool_batch(batch)
                continue
            try:
                if not slot.drain_spool():
                    slot.spool_batch(batch)
                    raise ExportError("spool not fully drained")
                slot.exporter.send(batch)
            except ExportRefused as exc:
                # The destination rejected us (401/403/400): usually a token or index problem the owner fixes.
                # Keep the events in the bounded spool and retry on the long backoff rather than dropping
                # everything forever; the state stays "refused" until a send succeeds.
                slot.state = "refused"
                slot.failures += 1
                slot.failed += 1
                slot.last_error = str(exc)[:300]
                slot.last_error_at = int(time.time() * 1000)
                slot.next_retry = time.monotonic() + BACKOFF_MAX_S
                slot.spool_batch(batch)
                slot.dirty = True
                continue
            except ExportError as exc:
                slot.failures += 1
                slot.failed += 1
                slot.state = "retrying"
                slot.last_error = str(exc)[:300]
                slot.last_error_at = int(time.time() * 1000)
                slot.next_retry = time.monotonic() + min(BACKOFF_MAX_S, BACKOFF_BASE_S * (2 ** min(slot.failures, 8)))
                if str(exc) != "spool not fully drained":
                    slot.spool_batch(batch)
                slot.dirty = True
                continue
            except Exception as exc:  # an exporter bug is a failure, not a crash
                slot.failures += 1
                slot.failed += 1
                slot.state = "retrying"
                slot.last_error = f"{exc.__class__.__name__}: {str(exc)[:200]}"
                slot.last_error_at = int(time.time() * 1000)
                slot.next_retry = time.monotonic() + min(BACKOFF_MAX_S, BACKOFF_BASE_S * (2 ** min(slot.failures, 8)))
                slot.spool_batch(batch)
                slot.dirty = True
                continue
            slot.sent += len(batch)
            slot.failures = 0
            slot.state = "ok"
            slot.last_ok = int(time.time() * 1000)
            slot.dirty = True

    def _maybe_health(self, force: bool = False) -> None:
        if not self._on_health:
            return
        now = time.monotonic()
        dirty = any(s.dirty for s in self.slots.values())
        if force or (dirty and now - self._last_health > 2.0):
            self._last_health = now
            for s in self.slots.values():
                s.dirty = False
            try:
                self._on_health(self.health())
            except Exception:
                pass

    def health(self) -> list[dict]:
        return [s.health() for s in self.slots.values()]

    def queue_health(self) -> dict:
        return {"size": self.q.qsize(), "capacity": self.q.maxsize, "received": self.received, "dropped": self.dropped_queue,
                "worker_alive": bool(self._thread and self._thread.is_alive())}


__all__ = ["Dispatcher", "BATCH_MAX"]
