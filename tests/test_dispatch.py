"""Reliability contracts: a dead destination never breaks the session, the queue never blocks,
spooling is bounded, refused tokens stop retries, and nothing leaves without consent."""

from __future__ import annotations

import json
import os
import time

import pytest

from conftest import mod


def _events(core, n, kind="secret.access"):
    Event = mod(core, "events").Event
    return [Event(kind=kind, target=f"/x/{i}", session_id="s") for i in range(n)]


class Flaky:
    """An exporter that fails N times then succeeds."""
    name = "flaky"
    remote = False

    def __init__(self, core, fail_times):
        self.ExportError = mod(core, "exporters").ExportError
        self.fail_times = fail_times
        self.calls = 0
        self.got: list = []

    def send(self, batch):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise self.ExportError("down")
        self.got += batch

    def close(self):
        pass

    def describe(self):
        return {"name": self.name, "remote": False, "format": "canonical"}


class Refuser(Flaky):
    name = "refuser"

    def send(self, batch):
        raise mod(self._core, "exporters").ExportRefused("401 bad token")


def test_dead_exporter_spools_then_replays_in_order(core, data_dir):
    Dispatcher = mod(core, "dispatch").Dispatcher
    d = Dispatcher(spool_dir=data_dir / "spool", worker=False)
    ex = Flaky(core, fail_times=1)
    slot = d.add(ex)
    first = _events(core, 3)
    d.deliver(first)                      # fails → spooled
    assert slot.state == "retrying" and slot.spooled == 3 and slot.failed == 1
    assert slot.spool.exists() and oct(os.stat(slot.spool).st_mode & 0o777) == "0o600"
    slot.next_retry = 0                   # pretend the backoff elapsed
    second = _events(core, 2)
    d.deliver(second)                     # drains spool first, then sends the new batch
    assert slot.state == "ok"
    assert [e.target for e in ex.got] == [e.target for e in first + second]
    assert not slot.spool.exists()
    assert slot.sent == 5


def test_spool_is_bounded_and_drops_are_counted(core, data_dir):
    Dispatcher = mod(core, "dispatch").Dispatcher
    d = Dispatcher(spool_dir=data_dir / "spool", worker=False, spool_max_mb=0.001)  # ~1 KB
    ex = Flaky(core, fail_times=10**6)
    slot = d.add(ex)
    for _ in range(5):
        d.deliver(_events(core, 20))
        slot.next_retry = 0
    assert slot.dropped > 0
    size = slot.spool.stat().st_size if slot.spool.exists() else 0
    assert size <= 1024  # never over the cap: a batch that would cross it is dropped whole and counted


def test_queue_never_blocks_and_drops_oldest(core, data_dir):
    Dispatcher = mod(core, "dispatch").Dispatcher
    d = Dispatcher(spool_dir=data_dir / "spool", worker=False, queue_size=100)
    t0 = time.monotonic()
    d.offer(_events(core, 1000))
    assert time.monotonic() - t0 < 0.5
    assert d.q.qsize() == 100 and d.dropped_queue == 900
    assert d.queue_health()["dropped"] == 900


def test_refused_destination_stops_retrying(core, data_dir):
    Dispatcher = mod(core, "dispatch").Dispatcher
    d = Dispatcher(spool_dir=data_dir / "spool", worker=False)
    ex = Refuser(core, 0)
    ex._core = core
    slot = d.add(ex)
    d.deliver(_events(core, 2))
    assert slot.state == "refused" and "401" in slot.last_error
    d.deliver(_events(core, 2))
    assert slot.failed == 1 and slot.dropped == 4  # not retried; later batches counted as dropped


def test_remote_exporters_need_consent(core, data_dir):
    Pipeline = mod(core, "pipeline").Pipeline
    cfg = mod(core, "config").load(overrides={"syslog_target": "udp://127.0.0.1:1", "hec_url": "https://splunk.invalid:8088/services/collector/event",
                                             "elastic_url": "https://es.invalid:9200", "summit_url": "https://summit.invalid/ingest"})
    p = Pipeline(cfg, data_dir=data_dir, worker=False, store=mod(core, "store").Store(data_dir / "c.db"))
    states = {h["name"]: h["state"] for h in p.dispatcher.health()}
    assert states["jsonl"] == "idle"
    assert {states["syslog"], states["hec"], states["elastic"], states["summit"]} == {"needs_consent"}
    p.dispatcher.deliver(_events(core, 1))
    for h in p.dispatcher.health():
        if h["name"] != "jsonl":
            assert h["sent"] == 0 and h["failed"] == 0
    p.close()


def test_https_exporter_refuses_plain_http(core):
    http = mod(core, "exporters.http")
    with pytest.raises(ValueError):
        http.HecExporter({"url": "http://splunk.example.com:8088/services/collector/event"})


def test_hec_envelope_and_token_from_config_only_in_tests(core, data_dir, monkeypatch):
    http = mod(core, "exporters.http")
    ex = http.HecExporter({"url": "https://splunk.example.com:8088/services/collector/event", "_test_secret": "tok", "index": "sec"})
    captured = {}

    def fake_post(body, headers):
        captured["body"] = body
        captured["headers"] = headers
        return 200, b"{}"

    ex._post = fake_post
    ex.send(_events(core, 2))
    lines = captured["body"].decode().splitlines()
    assert len(lines) == 2
    env = json.loads(lines[0])
    assert env["sourcetype"] == "siemless:ocsf" and env["index"] == "sec" and env["event"]["class_uid"] == 1001
    assert captured["headers"]["Authorization"] == "Splunk tok"


def test_elastic_bulk_is_ndjson_create(core):
    http = mod(core, "exporters.http")
    ex = http.ElasticExporter({"url": "https://es.example.com:9200", "_test_secret": "k"})
    captured = {}
    ex._post = lambda body, headers: captured.update(body=body, headers=headers) or (200, b'{"errors":false}')
    ex.send(_events(core, 1))
    lines = captured["body"].decode().splitlines()
    assert json.loads(lines[0]) == {"create": {"_index": "logs-siemless.hermes-default"}}
    assert json.loads(lines[1])["event"]["category"] == ["file"]
    assert captured["headers"]["Content-Type"] == "application/x-ndjson"
    assert ex.url.endswith("/_bulk")


def test_syslog_udp_frames_and_tcp_octet_counting(core):
    sl = mod(core, "exporters.syslog")
    udp = sl.SyslogExporter({"target": "udp://127.0.0.1:514"})
    tcp = sl.SyslogExporter({"target": "tcp://127.0.0.1:6514"})
    assert udp.frame("abc") == b"abc"
    assert tcp.frame("abc") == b"3 abc"
    with pytest.raises(ValueError):
        sl.SyslogExporter({"target": "http://x"})


def test_jsonl_rotation_and_permissions(core, data_dir):
    J = mod(core, "exporters.jsonl").JsonlExporter
    ex = J({"max_mb": 0.001, "backups": 2, "format": "canonical"}, data_dir=data_dir)
    for _ in range(30):
        ex.send(_events(core, 10))
    assert ex.events_path.exists() and (data_dir / "events.jsonl.1").exists()
    assert not (data_dir / "events.jsonl.3").exists()
    assert oct(os.stat(ex.events_path).st_mode & 0o777) == "0o600"


def test_pipeline_threads_end_to_end(core, data_dir):
    """The real asynchronous path: hooks → queue → worker → store/exporter, nothing blocking."""
    Pipeline = mod(core, "pipeline").Pipeline
    cfg = mod(core, "config").load(overrides={"finding_cooldown_s": 0})
    p = Pipeline(cfg, data_dir=data_dir, worker=True, store=mod(core, "store").Store(data_dir / "t.db"))
    from conftest import Session
    s = Session()
    t0 = time.monotonic()
    for hook, payload in (s.tool("read_file", {"path": "~/.ssh/id_rsa"}), s.tool("web_extract", {"url": "https://evil.example.org/"})):
        p.ingest(hook, payload)
    assert time.monotonic() - t0 < 0.05  # agent-thread cost
    p.flush()
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline and not p.store.findings(limit=1):
        time.sleep(0.02)
    fds = p.store.findings(limit=10)
    assert any(f["rule_id"] == "SL-001" for f in fds)
    time.sleep(0.7)
    assert (data_dir / "findings.jsonl").exists()
    st = p.status()
    assert st["queue"]["worker_alive"] and st["findings_total"] >= 1
    p.close()
