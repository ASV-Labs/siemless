"""Exporters: where events go. Every exporter has the same tiny contract.

``send(batch: list[Event]) -> None`` delivers a batch or raises. The dispatcher owns retries, the
spool and health; an exporter only formats and writes. Remote exporters are created in state
``needs_consent`` unless the operator set ``remote_export: true`` — nothing leaves the machine by
default. TLS verification is never disabled; there is no option for it.
"""

from __future__ import annotations

import ssl
from typing import Optional

from ..events import Event
from ..ocsf import dumps, to_cef, to_ecs, to_ocsf

FORMATS = ("ocsf", "ecs", "canonical", "cef")


def render(e: Event, fmt: str, *, hostname: Optional[str] = None) -> str:
    if fmt == "ocsf":
        return dumps(to_ocsf(e, hostname=hostname))
    if fmt == "ecs":
        return dumps(to_ecs(e, hostname=hostname))
    if fmt == "cef":
        return to_cef(e)
    return dumps(e.to_dict())


class Exporter:
    name = "base"
    remote = False          # True → needs remote_export consent

    def __init__(self, config: dict):
        self.config = config
        self.fmt = config.get("format") or "ocsf"
        if self.fmt not in FORMATS:
            self.fmt = "ocsf"
        self.hostname = config.get("hostname")

    def send(self, batch: list[Event]) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def close(self) -> None:
        pass

    def describe(self) -> dict:
        return {"name": self.name, "remote": self.remote, "format": self.fmt}


def tls_context(ca_file: Optional[str] = None) -> ssl.SSLContext:
    """A verifying TLS context. A private CA may be added; verification cannot be turned off."""
    ctx = ssl.create_default_context(cafile=ca_file or None)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


class ExportError(RuntimeError):
    """Raised by an exporter when a batch could not be delivered (retryable)."""


class ExportRefused(RuntimeError):
    """Raised when the destination rejected the data for good (bad token, 4xx): not retried."""


__all__ = ["Exporter", "ExportError", "ExportRefused", "render", "tls_context", "FORMATS"]
