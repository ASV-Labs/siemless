"""Regression tests from the Nov 8, 2026 Desktop check on the MacBook.

The Desktop page and ``hermes siemless status`` read through their own process, which never raised
a finding. Detection latency came from that process's memory, so it was always empty there even
though the README and the page both promise it, and the CLI printed per-process counters as if they
described the agent ("events processed 0" next to "24h: 996").
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
CMD = importlib.import_module(PLUG.__name__ + ".siemless_core.commands")
EV = importlib.import_module(PLUG.__name__ + ".siemless_core.events")


def _pipelines(tmp_path):
    cfg = CFG.load(None)
    return PIPE.Pipeline(cfg, data_dir=tmp_path, worker=False), PIPE.Pipeline(cfg, data_dir=tmp_path, worker=False)


def _raise_finding(p):
    ids = {"session_id": "s1", "turn_id": "t1"}
    p._process(EV.Event(kind="secret.access", visibility="observed", tool="read_file", action="read",
                        target="/Users/demo/siemless-lab/.ssh/id_rsa", tags=["sensitive:ssh"], **ids))
    p._process(EV.Event(kind="net.egress", visibility="inferred", tool="terminal", action="exec",
                        host="evil.example.com", target="https://evil.example.com/x", tags=["egress:shell"], **ids))


def test_latency_reaches_a_process_that_raised_nothing(tmp_path):
    writer, reader = _pipelines(tmp_path)
    try:
        _raise_finding(writer)
        assert writer.status()["findings_total"] >= 1
        lat = reader.status()["latency_ms"]
        assert lat["n"] >= 1 and lat["p50"] is not None and lat["p95"] is not None
    finally:
        writer.close()
        reader.close()


def test_latency_is_kept_out_of_what_is_exported(tmp_path):
    writer, reader = _pipelines(tmp_path)
    try:
        ids = {"session_id": "s1", "turn_id": "t1"}
        out = writer._process(EV.Event(kind="secret.access", visibility="observed", tool="read_file", action="read",
                                       target="/Users/demo/siemless-lab/.ssh/id_rsa", tags=["sensitive:ssh"], **ids))
        assert out and all("latency_ms" not in f for f in out)
    finally:
        writer.close()
        reader.close()


def test_status_text_does_not_present_per_process_counters_as_the_agents(tmp_path):
    _, reader = _pipelines(tmp_path)
    try:
        text = CMD.status_text(reader.status())
        assert "events processed" not in text
        assert "evaluations" not in text
        assert "correlator sessions" not in text
        assert "queue 0/" not in text
        assert "None ms" not in text
        assert "events 24h" in text
    finally:
        reader.close()


def test_status_text_keeps_live_counters_in_the_agent_process(tmp_path):
    _, reader = _pipelines(tmp_path)
    try:
        st = dict(reader.status(), live=True)
        text = CMD.status_text(st)
        assert "events processed" in text and "queue 0/" in text
    finally:
        reader.close()
