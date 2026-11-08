"""Configuration: flat keys from Hermes's plugin config (``ctx.get_config``), with defaults and types.

Everything an operator can set is here, in one table, which also generates ``plugin.yaml``'s
``config_schema`` (``python -m siemless_core.config --schema``) so the two cannot drift.
"""

from __future__ import annotations

import json
import sys
from typing import Any

# key: (type, default, description)
SCHEMA: dict[str, tuple[str, Any, str]] = {
    # what is recorded
    "record_args": ("bool", True, "Keep bounded, redacted tool arguments on tool.call events (default true). false keeps argument names only."),
    "record_prompts": ("bool", False, "Keep a short redacted preview of user messages and subagent goals (default false: hashes and lengths only)."),
    "record_aux_calls": ("bool", True, "Record auxiliary model calls (titles, compression, vision) as aux.call events (default true)."),
    # correlation / detection
    "window_minutes": ("int", 10, "Correlation window: how far back a rule looks for the first half of a sequence (default 10)."),
    "finding_cooldown_s": ("int", 600, "The same rule with the same key fires at most once per this many seconds (default 600)."),
    "approval_denies": ("int", 3, "SL-007: denials within five minutes that make a finding (default 3)."),
    "approval_burst": ("int", 6, "SL-007: approval prompts within one minute that make a finding (default 6)."),
    "allow_hosts": ("str", "", "Comma-separated hosts (or .suffixes) that are expected destinations; egress to them is not reported."),
    "watch_private_hosts": ("bool", False, "Treat loopback and RFC 1918 destinations as egress for the rules (default false). The demo lab needs true."),
    "allow_paths": ("str", "", "Comma-separated path prefixes or suffixes your workflow legitimately touches (e.g. .env.example)."),
    "disable_rules": ("str", "", "Comma-separated rule ids to turn off (e.g. SL-004,SL-011)."),
    # local storage
    "retention_days": ("int", 30, "Delete stored events and findings older than this (default 30)."),
    "max_events": ("int", 200000, "Keep at most this many events in the local database (default 200000)."),
    "queue_size": ("int", 10000, "In-memory dispatch queue; when full the oldest event is dropped and counted (default 10000)."),
    "spool_max_mb": ("int", 20, "Per-exporter on-disk spool while a destination is down; beyond this events are dropped and counted (default 20)."),
    # exporters
    "export_scope": ("str", "security", "What leaves the local store: findings | security | all (default security = findings plus security-relevant events)."),
    "jsonl_enabled": ("bool", True, "Write events.jsonl and findings.jsonl under plugin-data/siemless (default true). Wazuh reads these."),
    "jsonl_format": ("str", "ocsf", "Shape of the JSONL lines: ocsf | ecs | canonical (default ocsf)."),
    "jsonl_path": ("str", "", "Directory for the JSONL files (default: plugin-data/siemless)."),
    "jsonl_max_mb": ("int", 50, "Rotate each JSONL file at this size; 5 backups are kept (default 50)."),
    "remote_export": ("bool", False, "Consent gate: nothing is sent off this machine until this is true (default false)."),
    "syslog_target": ("str", "", "udp://host:514, tcp://host:6514 or tls://host:6514. Empty = off."),
    "syslog_format": ("str", "ocsf", "Syslog MSG body: ocsf | ecs | canonical | cef (default ocsf)."),
    "syslog_ca_file": ("str", "", "PEM bundle for a private CA on the TLS syslog receiver (verification is always on)."),
    "hec_url": ("str", "", "Splunk HEC endpoint, e.g. https://splunk.example.com:8088/services/collector/event. Token: SIEMLESS_HEC_TOKEN."),
    "hec_index": ("str", "", "Splunk index to write to (default: the token's default index)."),
    "hec_sourcetype": ("str", "siemless:ocsf", "Splunk sourcetype (default siemless:ocsf)."),
    "hec_format": ("str", "ocsf", "Event body sent to HEC: ocsf | ecs | canonical (default ocsf)."),
    "elastic_url": ("str", "", "Elasticsearch base URL, e.g. https://es.example.com:9200. Documents are ECS. Key: SIEMLESS_ELASTIC_API_KEY."),
    "elastic_data_stream": ("str", "logs-siemless.hermes-default", "Elastic data stream name (default logs-siemless.hermes-default)."),
    "summit_url": ("str", "", "The Summit (or any receiver with the documented contract) endpoint. Token: SIEMLESS_SUMMIT_TOKEN."),
    "allow_loopback_http": ("bool", False, "Lab switch: let summit_url be plain http:// on 127.0.0.1/localhost only (default false; https everywhere else)."),
    "http_ca_file": ("str", "", "PEM bundle for a private CA on the HEC / Elastic / Summit endpoints."),
    "hostname": ("str", "", "Host name to stamp on exported events (default: the machine's)."),
}

SECRETS = {
    "SIEMLESS_HEC_TOKEN": "Splunk HEC token (only when hec_url is set).",
    "SIEMLESS_ELASTIC_API_KEY": "Elasticsearch API key (only when elastic_url is set).",
    "SIEMLESS_SUMMIT_TOKEN": "Bearer token for the Summit receiver (only when summit_url is set).",
}

SECURITY_KINDS = {
    "finding", "secret.access", "net.egress", "process.exec", "config.change", "cron.change", "plugin.change", "skill.change",
    "approval.request", "approval.response", "human_input", "subagent.start", "subagent.stop", "content.untrusted", "command",
    "session.start", "session.end", "file.write",
}


def _coerce(typ: str, value: Any, default: Any) -> Any:
    if value is None:
        return default
    try:
        if typ == "bool":
            if isinstance(value, str):
                return value.strip().lower() in ("1", "true", "yes", "on")
            return bool(value)
        if typ == "int":
            return int(value)
        return str(value)
    except (TypeError, ValueError):
        return default


def load(ctx: Any = None, overrides: dict | None = None) -> dict:
    """Resolve the configuration from a Hermes plugin context (or a plain dict in tests)."""
    cfg: dict[str, Any] = {}
    for key, (typ, default, _desc) in SCHEMA.items():
        raw = None
        if overrides and key in overrides:
            raw = overrides[key]
        elif ctx is not None:
            try:
                raw = ctx.get_config(key, None)
            except Exception:
                raw = None
        cfg[key] = _coerce(typ, raw, default)
    for list_key in ("allow_hosts", "allow_paths", "disable_rules"):
        v = cfg[list_key]
        cfg[list_key] = [x.strip() for x in str(v).split(",") if x.strip()] if isinstance(v, str) else list(v or [])
    if cfg["export_scope"] not in ("findings", "security", "all"):
        cfg["export_scope"] = "security"
    return cfg


def in_scope(kind: str, tags: list[str], scope: str) -> bool:
    if scope == "all":
        return True
    if scope == "findings":
        return kind == "finding"
    if kind in SECURITY_KINDS:
        return True
    return kind == "tool.call" and any(t.startswith(("sensitive:", "config:", "browser:act", "delegate")) for t in tags)


SECRET_FIELDS = {
    "hec_token": ("SIEMLESS_HEC_TOKEN", "Splunk HEC token (only when hec_url is set)."),
    "elastic_api_key": ("SIEMLESS_ELASTIC_API_KEY", "Elasticsearch API key (only when elastic_url is set)."),
    "summit_token": ("SIEMLESS_SUMMIT_TOKEN", "Bearer token for the Summit receiver (only when summit_url is set)."),
}
CHOICES = {"export_scope": ["findings", "security", "all"], "jsonl_format": ["ocsf", "ecs", "canonical"],
           "syslog_format": ["ocsf", "ecs", "canonical", "cef"], "hec_format": ["ocsf", "ecs", "canonical"]}


def plugin_yaml_schema() -> dict:
    """``config_schema`` for plugin.yaml. Secrets are ``type: secret`` fields that name their env var, so
    Hermes stores them through its credential route and the plugin reads them with ``get_secret``; they are
    never ``requires_env`` (that would gate loading on optional exporters)."""
    out: dict = {}
    for k, (t, d, desc) in SCHEMA.items():
        entry: dict = {"type": t, "default": d, "description": desc}
        if k in CHOICES:
            entry["choices"] = CHOICES[k]
        out[k] = entry
    for k, (env, desc) in SECRET_FIELDS.items():
        out[k] = {"type": "secret", "env": env, "description": desc}
    return out


if __name__ == "__main__" and "--schema" in sys.argv:
    import yaml  # type: ignore

    print(yaml.safe_dump({"config_schema": plugin_yaml_schema()}, sort_keys=False, width=100))
elif __name__ == "__main__":
    print(json.dumps(load(), indent=2))

__all__ = ["SCHEMA", "SECRETS", "SECRET_FIELDS", "CHOICES", "SECURITY_KINDS", "load", "in_scope", "plugin_yaml_schema"]
