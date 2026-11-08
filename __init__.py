"""SIEMless — agent security telemetry and detection for Hermes Agent.

Observer hooks only: no tools, no middleware, no ``pre_tool_call`` (that hook can block the agent),
no ``pre_llm_call`` injection. Each callback reduces its payload to redacted, bounded events and
hands them to a worker thread; the agent thread never waits on a disk or a socket. Nothing leaves
the machine unless ``remote_export`` is true and a destination is configured. See README.md.
"""

from __future__ import annotations

import logging
from typing import Optional

from .siemless_core import PLUGIN_ID, __version__
from .siemless_core.collectors import HOOKS
from .siemless_core.config import delivery_settings, load as load_config

log = logging.getLogger("hermes.plugins.siemless")

_pipeline = None
_config: Optional[dict] = None
_ctx = None


def _emit(event: str, payload: dict) -> None:
    """Push to the Desktop half through Hermes's public event bridge, when it exists."""
    try:
        from hermes_cli.plugin_events import broadcast_plugin_event  # documented public bridge
    except Exception:
        return
    try:
        broadcast_plugin_event(PLUGIN_ID, event, payload)
    except Exception:
        pass


def _profile_name(ctx) -> Optional[str]:
    for attr in ("profile_name", "profile"):
        v = getattr(ctx, attr, None)
        if isinstance(v, str) and v:
            return v
    return None


def get_pipeline(config: Optional[dict] = None, profile: Optional[str] = None):
    """The process-wide pipeline, created on first use so register() stays instant."""
    global _pipeline
    if _pipeline is None:
        from .siemless_core.pipeline import Pipeline

        reload_config = (lambda: delivery_settings(_ctx)) if _ctx is not None else None
        _pipeline = Pipeline(config or _config or load_config(), emit=_emit, profile=profile, reload_config=reload_config)
    return _pipeline


def register(ctx) -> None:
    global _config, _ctx
    _ctx = ctx
    _config = load_config(ctx)
    profile = _profile_name(ctx)

    def hook(name: str):
        def _cb(**kwargs):
            try:
                get_pipeline(_config, profile).ingest(name, kwargs)
            except Exception as exc:  # the pipeline already guards; this guards the pipeline
                log.debug("siemless hook %s: %s", name, exc)

        _cb.__name__ = f"siemless_{name}"
        return _cb

    for name in HOOKS:
        ctx.register_hook(name, hook(name))

    def slash(raw_args: str = "", session_id: Optional[str] = None, **_kw) -> str:
        from .siemless_core.commands import dispatch

        try:
            return dispatch(get_pipeline(_config, profile), raw_args.split())
        except Exception as exc:
            return f"siemless: {exc.__class__.__name__}: {exc}"

    ctx.register_command(
        "siemless", slash,
        description="Agent security telemetry: status, findings, rules, exporter health.",
        args_hint="[status | findings [N] | show <id> | tail [N] | rules | hosts | ack <id> | test-exporter | replay <file>]",
    )

    def cli_setup(parser):
        from .siemless_core.commands import cli_setup as _setup

        _setup(parser)

    def cli_handler(args):
        from .siemless_core.commands import cli_handler as _handler

        return _handler(args, pipeline_factory=lambda: get_pipeline(_config, profile))

    ctx.register_cli_command(
        "siemless", "Agent security telemetry: status, findings, rules, exporters, replay",
        cli_setup, cli_handler,
        description=f"siemless {__version__}: security events and detections for everything the agent does.",
    )


__all__ = ["register", "get_pipeline", "HOOKS", "__version__"]
