"""Syslog exporter: RFC 5424 messages over UDP, TCP (RFC 6587 octet-counting) or TLS (RFC 5425).

MSG is either the JSON rendering (``format: ocsf|ecs|canonical``) or a CEF line (``format: cef``).
Target syntax: ``udp://host:514``, ``tcp://host:6514``, ``tls://host:6514``; a ``ca_file`` may
name a private CA. TLS verification is always on.
"""

from __future__ import annotations

import socket
from typing import Optional
from urllib.parse import urlsplit

from ..events import Event
from ..ocsf import to_syslog
from . import Exporter, ExportError, render, tls_context


class SyslogExporter(Exporter):
    name = "syslog"
    remote = True

    def __init__(self, config: dict):
        super().__init__(config)
        target = str(config.get("target") or "")
        parts = urlsplit(target if "://" in target else "udp://" + target)
        self.scheme = (parts.scheme or "udp").lower()
        if self.scheme not in ("udp", "tcp", "tls"):
            raise ValueError(f"syslog target scheme must be udp, tcp or tls (got {self.scheme})")
        self.host = parts.hostname or "127.0.0.1"
        self.port = parts.port or (514 if self.scheme == "udp" else 6514)
        self.ca_file = config.get("ca_file") or None
        self.app = config.get("app") or "siemless"
        self.timeout = float(config.get("timeout_s", 5))
        self._sock: Optional[socket.socket] = None

    # ------------------------------------------------------------ transport
    def _connect(self) -> socket.socket:
        if self._sock is not None:
            return self._sock
        if self.scheme == "udp":
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.timeout)
            self._sock = s
            return s
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.scheme == "tls":
            raw = tls_context(self.ca_file).wrap_socket(raw, server_hostname=self.host)
        self._sock = raw
        return raw

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def frame(self, msg: str) -> bytes:
        data = msg.encode("utf-8")
        if self.scheme == "udp":
            return data[:65000]
        return f"{len(data)} ".encode("ascii") + data  # RFC 6587 octet counting

    def send(self, batch: list[Event]) -> None:
        try:
            sock = self._connect()
            for e in batch:
                body = render(e, self.fmt, hostname=self.hostname)
                line = to_syslog(e, body, hostname=self.hostname, app=self.app)
                payload = self.frame(line)
                if self.scheme == "udp":
                    sock.sendto(payload, (self.host, self.port))
                else:
                    sock.sendall(payload)
        except (OSError, ValueError) as exc:
            self.close()
            raise ExportError(f"syslog {self.scheme}://{self.host}:{self.port}: {exc}") from exc

    def describe(self) -> dict:
        d = super().describe()
        d.update({"target": f"{self.scheme}://{self.host}:{self.port}", "tls": self.scheme == "tls"})
        return d


__all__ = ["SyslogExporter"]
