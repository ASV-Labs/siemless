# Changelog

## 0.1.0 — 2026-11-08

First release, built for the Nous Research Hermes Agent Plugin Hackathon.

- Observer-only collectors for 23 Hermes hooks → ~20 canonical event kinds with observed/inferred visibility.
- Correlation by session, turn and delegation tree; taint follows subagents; windows keyed on event time.
- 14 baseline rules (SL-001 … SL-014) with ATT&CK Enterprise 20.1 mapping from a bundled, verified excerpt.
- OCSF 1.9.0 output validated against the schema for every event kind; `ai_operation` and `security_control` profiles; Wazuh-safe scalar mirrors under `unmapped.siemless`.
- Exporters: JSONL (rotating, 0600), RFC 5424 syslog over UDP/TCP/TLS (octet counting, BOM), CEF, Splunk HEC, Elastic `_bulk` (ECS 9.x), JSON receiver (The Summit contract).
- Bounded non-blocking dispatch with per-exporter spool, backoff, refusal handling and health counters; consent gate for anything remote.
- Desktop page (findings + evidence chains, events, exporter health, rules), status-bar chip, palette command; FastAPI backend.
- `/siemless` slash command and `hermes siemless` CLI incl. `replay`.
- Packs: Wazuh rules, Splunk guide, Elastic template, 22 generated Sigma rules (2 correlations), Summit contract.
- Demo lab with eight recorded variants and a local receiver.
