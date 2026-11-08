"""HTTPS exporters: Splunk HEC, Elastic bulk, and a generic JSON webhook used for The Summit.

All three share one verifying HTTPS client (stdlib ``urllib`` + ``ssl``): https only, certificate
and hostname verification always on, bounded body size, a timeout, and a clear split between
retryable failures (network, 5xx, 429) and refusals (401/403/400, redirects → spooled, retried on the
long backoff, surfaced in health). Redirects are never followed, so a token never moves to another host.
Tokens come from Hermes's secret route (``agent.secret_scope.get_secret``) when inside Hermes, so
the plugin never reads ``.env`` itself.
"""

from __future__ import annotations

import gzip
import json
import time
import urllib.error
import urllib.request
from typing import Callable, Optional
from urllib.parse import urlsplit

from ..events import Event
from ..ocsf import dumps
from . import Exporter, ExportError, ExportRefused, render, tls_context

MAX_BODY = 5 * 1024 * 1024  # bytes per request; HEC's default max_content_length is far higher, Elastic's 100 MB
MAX_RESPONSE = 4 * 1024 * 1024  # a _bulk response for a full batch is far larger than a status line


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: the Authorization header would go wherever the Location points."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        raise ExportRefused(f"redirect {code} to {urlsplit(newurl).netloc or newurl[:80]} refused; set the final URL")


def secret(name: str, config: dict) -> Optional[str]:
    """A secret through Hermes's route when available; a config value only in tests/dev."""
    try:
        from agent.secret_scope import get_secret  # type: ignore

        v = get_secret(name)
        if v:
            return str(v)
    except Exception:
        pass
    v = config.get("_test_secret")  # tests only; never read from .env here
    return str(v) if v else None


class _Https(Exporter):
    remote = True
    token_env = ""

    def __init__(self, config: dict):
        super().__init__(config)
        self.url = str(config.get("url") or "")
        parts = urlsplit(self.url)
        if parts.scheme != "https" and not (parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost") and config.get("allow_loopback_http")):
            raise ValueError(f"{self.name}: url must be https:// (got {parts.scheme or 'none'})")
        self.timeout = float(config.get("timeout_s", 10))
        self.ca_file = config.get("ca_file") or None
        self.gzip = bool(config.get("gzip", False))
        self._ctx = tls_context(self.ca_file) if parts.scheme == "https" else None
        self._token = secret(self.token_env, config) if self.token_env else None
        handlers = [_NoRedirect()]
        if self._ctx is not None:
            handlers.append(urllib.request.HTTPSHandler(context=self._ctx))
        self._opener = urllib.request.build_opener(*handlers)

    def _post(self, body: bytes, headers: dict[str, str]) -> tuple[int, bytes]:
        if len(body) > MAX_BODY:
            raise ExportRefused(f"{self.name}: batch body {len(body)} bytes exceeds {MAX_BODY}")
        if self.gzip:
            body = gzip.compress(body)
            headers = {**headers, "Content-Encoding": "gzip"}
        req = urllib.request.Request(self.url, data=body, method="POST", headers={"User-Agent": "siemless/0.1", **headers})
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:  # noqa: S310 - https enforced above
                if 300 <= resp.status < 400:
                    raise ExportRefused(f"{self.name}: HTTP {resp.status} redirect refused")
                return resp.status, resp.read(MAX_RESPONSE)
        except ExportRefused:
            raise
        except urllib.error.HTTPError as exc:
            status = exc.code
            detail = exc.read(512).decode("utf-8", "replace") if exc.fp else ""
            if status in (400, 401, 403, 404, 413):
                raise ExportRefused(f"{self.name}: HTTP {status} {detail[:200]}") from exc
            raise ExportError(f"{self.name}: HTTP {status} {detail[:200]}") from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise ExportError(f"{self.name}: {exc}") from exc

    def _resolve_token(self) -> Optional[str]:
        """Resolve lazily: the first hook may run outside a profile's secret scope, and an owner may set the
        token after start. A missing token is a refusal (spooled, retried on the long backoff), not a crash."""
        if not self._token and self.token_env:
            self._token = secret(self.token_env, self.config)
        return self._token

    def describe(self) -> dict:
        d = super().describe()
        d.update({"url": self.url, "token_env": self.token_env, "token_present": bool(self._token)})
        return d


class HecExporter(_Https):
    """Splunk HTTP Event Collector, ``/services/collector/event`` JSON envelope."""

    name = "hec"
    token_env = "SIEMLESS_HEC_TOKEN"

    def __init__(self, config: dict):
        super().__init__(config)
        self.index = config.get("index") or None
        self.sourcetype = config.get("sourcetype") or "siemless:ocsf"
        self.source = config.get("source") or "hermes-agent"

    def send(self, batch: list[Event]) -> None:
        if not self._resolve_token():
            raise ExportRefused("hec: SIEMLESS_HEC_TOKEN is not set")
        lines = []
        for e in batch:
            env = {"time": e.time / 1000.0, "source": self.source, "sourcetype": self.sourcetype,
                   "event": json.loads(render(e, self.fmt, hostname=self.hostname)) if self.fmt != "cef" else render(e, "cef")}
            if self.hostname:
                env["host"] = self.hostname
            if self.index:
                env["index"] = self.index
            lines.append(dumps(env))
        body = "\n".join(lines).encode("utf-8")
        status, _ = self._post(body, {"Authorization": f"Splunk {self._token}", "Content-Type": "application/json"})
        if status not in (200, 201, 202):
            raise ExportError(f"hec: unexpected status {status}")


class ElasticExporter(_Https):
    """Elasticsearch ``_bulk`` into a data stream (``logs-siemless.hermes-default`` by default), ECS documents."""

    name = "elastic"
    token_env = "SIEMLESS_ELASTIC_API_KEY"

    def __init__(self, config: dict):
        config = {**config, "format": config.get("format") or "ecs"}
        super().__init__(config)
        self.data_stream = config.get("data_stream") or "logs-siemless.hermes-default"
        if not self.url.rstrip("/").endswith("/_bulk"):
            self.url = self.url.rstrip("/") + "/_bulk"
        self.rejected = 0               # documents Elastic refused for good (mapping errors etc.)
        self.last_item_error: Optional[str] = None

    def send(self, batch: list[Event]) -> None:
        if not self._resolve_token():
            raise ExportRefused("elastic: SIEMLESS_ELASTIC_API_KEY is not set")
        lines = []
        for e in batch:
            # _id = the event id: a retried batch cannot duplicate documents (Elastic answers 409 instead).
            lines.append(dumps({"create": {"_index": self.data_stream, "_id": e.id}}))
            lines.append(render(e, "ecs", hostname=self.hostname))
        body = ("\n".join(lines) + "\n").encode("utf-8")
        status, resp = self._post(body, {"Authorization": f"ApiKey {self._token}", "Content-Type": "application/x-ndjson"})
        if status not in (200, 201):
            raise ExportError(f"elastic: unexpected status {status}")
        try:
            doc = json.loads(resp.decode("utf-8", "replace"))
        except ValueError:
            return
        if not isinstance(doc, dict) or not doc.get("errors"):
            return
        retry, bad = 0, 0
        items = doc.get("items") if isinstance(doc.get("items"), list) else []
        for it in items:
            r = (it or {}).get("create") or (it or {}).get("index") or {}
            st = int(r.get("status") or 0)
            if st < 300 or st == 409:   # stored now, or stored by an earlier attempt
                continue
            if st == 429 or st >= 500:
                retry += 1
            else:
                bad += 1
                err = r.get("error")
                self.last_item_error = (json.dumps(err)[:300] if err else f"status {st}")
        if not items:
            bad = len(batch)  # errors with no item detail: count the batch as rejected rather than wedge on it
            self.last_item_error = "bulk reported errors without item detail"
        if retry:
            raise ExportError(f"elastic: {retry} item(s) throttled or failed server-side; retrying (ids dedupe)")
        # Permanent per-document errors are not retried: one bad document must not stop every later event.
        self.rejected += bad

    def describe(self) -> dict:
        d = super().describe()
        d.update({"rejected": self.rejected, "last_item_error": self.last_item_error})
        return d


class SummitExporter(_Https):
    """The Summit (ASV Labs' monitoring wall), or any JSON receiver with the same contract.

    Contract (``docs/integrations/summit.md``): ``POST {url}`` with ``Authorization: Bearer <token>``
    and body ``{"source": "siemless", "version": ..., "agent": ..., "events": [canonical events],
    "findings": [finding dicts]}``. The local demo receiver in ``demo/`` speaks exactly this.
    """

    name = "summit"
    token_env = "SIEMLESS_SUMMIT_TOKEN"

    def __init__(self, config: dict, *, finding_lookup: Optional[Callable[[str], Optional[dict]]] = None):
        config = {**config, "format": "canonical"}
        super().__init__(config)
        self.agent = config.get("agent") or "hermes"
        self._lookup = finding_lookup

    def send(self, batch: list[Event]) -> None:
        if not self._resolve_token():
            raise ExportRefused("summit: SIEMLESS_SUMMIT_TOKEN is not set")
        findings = []
        events = []
        for e in batch:
            if e.kind == "finding":
                fd = self._lookup(e.attrs.get("finding_id") or "") if self._lookup else None
                findings.append(fd or e.to_dict())
            else:
                events.append(e.to_dict())
        from .. import __version__

        body = dumps({"source": "siemless", "version": __version__, "agent": self.agent, "sent_at": int(time.time() * 1000),
                      "events": events, "findings": findings}).encode("utf-8")
        status, _ = self._post(body, {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"})
        if status not in (200, 201, 202, 204):
            raise ExportError(f"summit: unexpected status {status}")


__all__ = ["HecExporter", "ElasticExporter", "SummitExporter", "secret", "MAX_BODY"]
