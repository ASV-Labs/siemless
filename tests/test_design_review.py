"""Regression tests from the design team's Desktop review (Nov 8, 2026).

The security-relevant one: turning remote_export off in Settings did nothing to a running gateway
until it restarted, while `status`, reading the file, already said "off". The others are stale
exporter rows shown as failing after consent was withdrawn or a destination was cleared, and a
curl upload recorded as untrusted content coming in.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from conftest import load_plugin_package  # noqa: E402

PLUG = load_plugin_package()
PIPE = importlib.import_module(PLUG.__name__ + ".siemless_core.pipeline")
CFG = importlib.import_module(PLUG.__name__ + ".siemless_core.config")
COL = importlib.import_module(PLUG.__name__ + ".siemless_core.collectors")
EV = importlib.import_module(PLUG.__name__ + ".siemless_core.events")

SUMMIT = {"summit_url": "https://summit.example/ingest", "remote_export": True}


def _pipe(tmp_path, overrides=None, **kw):
    return PIPE.Pipeline(CFG.load(None, overrides=overrides or {}), data_dir=tmp_path, worker=False, **kw)


def _event():
    return EV.Event(kind="net.egress", visibility="inferred", tool="terminal", action="exec", host="example.com", session_id="s1")


class _Stub:
    name = "summit"
    remote = True

    def __init__(self):
        self.sent = []

    def send(self, batch):
        self.sent.append(batch)

    def describe(self):
        return {}

    def close(self):
        self.closed = True


def _with_stub(p):
    p.dispatcher.slots.pop("summit", None)
    stub = _Stub()
    p.dispatcher.add(stub, state="idle")
    return stub


def _settings(**over):
    return {"remote_export": True, "syslog_target": "", "hec_url": "", "elastic_url": "",
            "summit_url": "https://summit.example/ingest", **over}


def test_running_agent_stops_sending_when_consent_is_withdrawn(tmp_path):
    settings = _settings()
    p = _pipe(tmp_path, SUMMIT, reload_config=lambda: settings)
    try:
        stub = _with_stub(p)
        p.dispatcher.deliver([_event()])
        assert len(stub.sent) == 1
        settings["remote_export"] = False
        p.refresh_delivery_settings()
        p.dispatcher.deliver([_event()])
        assert len(stub.sent) == 1
        assert p.dispatcher.slots["summit"].state == "needs_consent"
        assert p.config["remote_export"] is False
    finally:
        p.close()


def test_running_agent_resumes_when_consent_is_given_again(tmp_path):
    settings = _settings(remote_export=False)
    p = _pipe(tmp_path, {**SUMMIT, "remote_export": False}, reload_config=lambda: settings)
    try:
        stub = _with_stub(p)
        p.dispatcher.slots["summit"].state = "needs_consent"
        settings["remote_export"] = True
        p.refresh_delivery_settings()
        p.dispatcher.deliver([_event()])
        assert len(stub.sent) == 1
    finally:
        p.close()


def test_clearing_a_destination_stops_a_running_agent(tmp_path):
    settings = _settings()
    p = _pipe(tmp_path, SUMMIT, reload_config=lambda: settings)
    try:
        stub = _with_stub(p)
        settings["summit_url"] = ""
        p.refresh_delivery_settings()
        p.dispatcher.deliver([_event()])
        assert not stub.sent and "summit" not in p.dispatcher.slots and stub.closed
    finally:
        p.close()


def test_unreadable_settings_change_nothing(tmp_path):
    def broken():
        raise OSError("config busy")

    p = _pipe(tmp_path, SUMMIT, reload_config=broken)
    try:
        stub = _with_stub(p)
        p.refresh_delivery_settings()
        p.dispatcher.deliver([_event()])
        assert len(stub.sent) == 1
    finally:
        p.close()


def test_reader_hides_a_destination_that_was_cleared(tmp_path):
    writer = _pipe(tmp_path, SUMMIT)
    try:
        writer.store.set_exporter_health("summit", enabled=True, state="refused", spooled=6, last_error="no token")
        reader = _pipe(tmp_path, {"remote_export": False})
        try:
            assert "summit" not in {x["name"] for x in reader.status()["exporters"]}
        finally:
            reader.close()
    finally:
        writer.close()


def test_reader_shows_needs_consent_instead_of_a_stale_failure(tmp_path):
    writer = _pipe(tmp_path, SUMMIT)
    try:
        reader = _pipe(tmp_path, {**SUMMIT, "remote_export": False})
        try:
            writer.store.set_exporter_health("summit", enabled=True, state="refused", failed=1, last_error="no token")
            rows = {x["name"]: x for x in reader.exporter_health()}
            assert rows["summit"]["state"] == "needs_consent"
        finally:
            reader.close()
    finally:
        writer.close()


def _shell(cmd):
    payload = {"session_id": "s", "turn_id": "t", "tool_name": "terminal", "args": {"command": cmd}, "status": "ok", "result": "ok"}
    return COL.collect("post_tool_call", payload, config={})


def _untrusted(evs):
    return [e for e in evs if e.kind == "content.untrusted"]


def test_upload_only_commands_bring_nothing_in():
    for cmd in ("curl -s -X POST --data-binary @/tmp/k http://127.0.0.1:8787/collect",
                "curl -d @/tmp/k https://example.com/x",
                "curl --data-binary=@/tmp/k https://example.com/x",
                "curl -F file=@/tmp/k https://example.com/x",
                "curl -T /tmp/k https://example.com/x",
                "wget --post-file=/tmp/k https://example.com/x"):
        evs = _shell(cmd)
        assert not _untrusted(evs), cmd
        assert any(e.kind == "net.egress" for e in evs), cmd


def test_a_fetch_beside_an_upload_is_still_untrusted():
    assert _untrusted(_shell("curl -s https://example.com/page; curl -d @/tmp/k https://example.com/x"))
    assert _untrusted(_shell("curl -d @/tmp/k https://example.com/x && wget https://example.com/next"))


def test_plain_fetch_and_inline_post_stay_untrusted():
    assert _untrusted(_shell("curl -s https://example.com/page"))
    assert _untrusted(_shell("curl -d q=hello https://example.com/search"))
