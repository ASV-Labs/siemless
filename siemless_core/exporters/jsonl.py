"""Local JSON Lines exporter: one file for events, one for findings, rotated by size, 0600.

This is the exporter that is on by default and the one Wazuh's ``<localfile>`` reads.
"""

from __future__ import annotations

import os
from pathlib import Path

from ..events import Event
from . import Exporter, ExportError, render

_LINE_SEPS = {c: f"\\u{c:04x}" for c in (0x0B, 0x0C, 0x1C, 0x1D, 0x1E, 0x85, 0x2028, 0x2029)}


class JsonlExporter(Exporter):
    name = "jsonl"
    remote = False

    def __init__(self, config: dict, *, data_dir: Path):
        super().__init__(config)
        self.dir = Path(config.get("path") or data_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.max_bytes = int(float(config.get("max_mb", 50)) * 1024 * 1024)
        self.backups = int(config.get("backups", 5))
        self.events_path = self.dir / "events.jsonl"
        self.findings_path = self.dir / "findings.jsonl"

    def send(self, batch: list[Event]) -> None:
        ev_lines, f_lines = [], []
        for e in batch:
            line = render(e, self.fmt, hostname=self.hostname)
            # One record per "\n" for every reader: escape the characters str.splitlines() also breaks on.
            line = line.translate(_LINE_SEPS)
            (f_lines if e.kind == "finding" else ev_lines).append(line)
        try:
            if ev_lines:
                self._append(self.events_path, ev_lines)
            if f_lines:
                self._append(self.findings_path, f_lines)
        except OSError as exc:
            raise ExportError(f"jsonl write failed: {exc}") from exc

    def _append(self, path: Path, lines: list[str]) -> None:
        self._rotate(path, sum(len(l) + 1 for l in lines))
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")

    def _rotate(self, path: Path, incoming: int) -> None:
        try:
            size = path.stat().st_size
        except OSError:
            return
        if size + incoming <= self.max_bytes:
            return
        for i in range(self.backups - 1, 0, -1):
            src = Path(f"{path}.{i}")
            if src.exists():
                os.replace(src, f"{path}.{i + 1}")
        os.replace(path, f"{path}.1")

    def describe(self) -> dict:
        d = super().describe()
        d.update({"events_path": str(self.events_path), "findings_path": str(self.findings_path), "max_mb": self.max_bytes // (1024 * 1024)})
        return d


__all__ = ["JsonlExporter"]
