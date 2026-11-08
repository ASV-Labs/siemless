"""siemless — agent security telemetry and detection for Hermes Agent.

Observer hooks only. Every Hermes lifecycle event becomes a bounded, redacted canonical event;
events are correlated by session, turn, task and subagent; deterministic rules turn suspicious
sequences into findings; everything is written locally and, when configured, exported to a SIEM.
Nothing in here changes what the agent does.
"""

from __future__ import annotations

__version__ = "0.1.0"
PLUGIN_ID = "siemless"
SCHEMA_VERSION = "siemless.event.v1"
VENDOR = "ASV Labs"
PRODUCT = "SIEMless"

__all__ = ["__version__", "PLUGIN_ID", "SCHEMA_VERSION", "VENDOR", "PRODUCT"]
