"""Test fixtures: load the plugin the way Hermes does (a package built from __init__.py), stand up
an isolated HERMES_HOME, and drive hooks with the documented payload shapes (observer-hooks.md)."""

from __future__ import annotations

import importlib
import importlib.util
import sys
import time
import uuid
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parents[1]
PKG = "hermes_plugin_siemless_under_test"


def load_plugin_package(name: str = PKG):
    """Mirror hermes_cli/plugins_loader: spec from __init__.py with the plugin dir as package path."""
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, PLUGIN_DIR / "__init__.py", submodule_search_locations=[str(PLUGIN_DIR)])
    module = importlib.util.module_from_spec(spec)
    module.__path__ = [str(PLUGIN_DIR)]
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def plugin():
    return load_plugin_package()


@pytest.fixture
def core(plugin):
    return importlib.import_module(plugin.__name__ + ".siemless_core")


def mod(core, name: str):
    return importlib.import_module(core.__name__ + "." + name)


@pytest.fixture
def hermes_home(tmp_path, monkeypatch):
    home = tmp_path / "hermes-home"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    return home


@pytest.fixture
def data_dir(hermes_home):
    d = hermes_home / "plugin-data" / "siemless"
    d.mkdir(parents=True)
    return d


@pytest.fixture
def pipeline(core, data_dir):
    """A synchronous pipeline (no worker threads): process_now() runs the full chain inline."""
    Pipeline = mod(core, "pipeline").Pipeline
    Store = mod(core, "store").Store
    cfg = mod(core, "config").load(overrides={"finding_cooldown_s": 0, "jsonl_enabled": True})
    store = Store(data_dir / "siemless.db")
    p = Pipeline(cfg, store=store, data_dir=data_dir, worker=False, profile="test")
    yield p
    p.close()
    store.close()


class RecordingContext:
    """The validator's probe context, reproduced: register() must work against exactly this."""

    plugin_config: dict = {}
    profile_name = "default"
    plugin_id = "hermes_validate_probe_plugin"

    def __init__(self, config: dict | None = None):
        self.recorded = {"tools": [], "hooks": [], "middleware": [], "commands": [], "cli_commands": []}
        self.callbacks: dict[str, list] = {}
        self.slash = None
        self.cli = None
        self._config = config or {}

    def register_tool(self, name, *args, **kwargs):
        self.recorded["tools"].append(str(name))

    def register_hook(self, hook_name, callback, *, hold_stream=False):
        self.recorded["hooks"].append(str(hook_name))
        self.callbacks.setdefault(hook_name, []).append(callback)

    def register_middleware(self, kind, callback):
        self.recorded["middleware"].append(str(kind))

    def register_command(self, name, handler, *args, **kwargs):
        self.recorded["commands"].append(str(name))
        self.slash = handler

    def register_cli_command(self, name, help, setup_fn, handler_fn=None, **kwargs):
        self.recorded["cli_commands"].append(str(name))
        self.cli = (setup_fn, handler_fn)

    def get_config(self, key, default=None):
        return self._config.get(key, default)

    def fire(self, hook_name, **payload):
        payload.setdefault("telemetry_schema_version", "hermes.observer.v1")
        for cb in self.callbacks.get(hook_name, []):
            cb(**payload)


@pytest.fixture
def ctx(plugin, hermes_home, monkeypatch):
    monkeypatch.setattr(plugin, "_pipeline", None)
    monkeypatch.setattr(plugin, "_config", None)
    c = RecordingContext({"finding_cooldown_s": 0})
    plugin.register(c)
    yield c
    p = getattr(plugin, "_pipeline", None)
    if p is not None:
        p.close()


# ------------------------------------------------------------------------------ payload builders
class Session:
    """Builds documented hook payloads for one session with monotonically increasing ids/time."""

    def __init__(self, session_id: str | None = None, t0: int | None = None):
        self.session_id = session_id or f"s-{uuid.uuid4().hex[:8]}"
        self.turn_id = f"t-{uuid.uuid4().hex[:8]}"
        self.t = t0 or int(time.time() * 1000)
        self.n = 0

    def _ids(self):
        self.n += 1
        return {"session_id": self.session_id, "turn_id": self.turn_id, "task_id": "default",
                "tool_call_id": f"call_{self.n}", "api_request_id": f"req-{self.n}", "platform": "cli"}

    def tool(self, name: str, args: dict, *, status: str = "ok", result: str = "ok", duration_ms: int = 12) -> tuple[str, dict]:
        return "post_tool_call", {"tool_name": name, "args": args, "result": result, "status": status, "duration_ms": duration_ms,
                                  "error_type": None, "error_message": None, **self._ids()}

    def turn_start(self, message: str = "hello") -> tuple[str, dict]:
        return "pre_llm_call", {"user_message": message, "conversation_history": [], "is_first_turn": True, "model": "test-model",
                                "sender_id": "owner", **self._ids()}

    def approval(self, command: str, choice: str) -> list[tuple[str, dict]]:
        base = {"command": command, "description": "run", "pattern_key": command.split()[0], "pattern_keys": [command.split()[0]],
                "session_key": self.session_id, "surface": "cli", **self._ids()}
        return [("pre_approval_request", dict(base)), ("post_approval_response", {**base, "choice": choice, "decided_by": "user"})]

    def subagent_start(self, child_session: str, goal: str = "do a thing") -> tuple[str, dict]:
        return "subagent_start", {"parent_session_id": self.session_id, "parent_turn_id": self.turn_id, "parent_subagent_id": None,
                                  "child_session_id": child_session, "child_subagent_id": f"sub-{child_session}",
                                  "child_role": "worker", "child_goal": goal}

    def command(self, name: str, args_raw: str = "") -> tuple[str, dict]:
        return "pre_command", {"surface": "cli", "command": name, "alias_used": None, "args_raw": args_raw,
                               "session_key": self.session_id, "platform": "cli", **self._ids()}


def run(pipeline, *steps):
    """Feed (hook, payload) steps synchronously; return all findings."""
    out = []
    for hook, payload in steps:
        _, fds = pipeline.process_now(hook, payload)
        out += fds
    return out


def rule_ids(findings):
    return [f["rule_id"] for f in findings]
