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

### Hardened after independent audit round 1 (audit/round1.md: 5 high, 14 medium, 9 low — all fixed)

- Redaction: CLI credential flags, more vendor prefixes, webhook paths, PEM of any length, quoted KV values, argument
  names, free-text fields; redaction before any cut; one shared budget for strings, dicts and lists. 23 canaries.
- Coverage: tools without a dedicated collector (MCP, other plugins), globs, `..` paths, interpreter sockets,
  `$(curl …)`, `crontab <file>`, quote/backslash obfuscation, trailing-dot and numeric hosts; bounded `subagent_stop`.
- Tamper: writes to SIEMless's own data, `hermes siemless ack|replay`, and `plugins.entries.siemless` edits are SL-010
  "SIEMless itself was changed" (critical for deletes/sqlite edits); ack and replay leave audit events.
- Replay: tagged `replay` in every format, `[REPLAY]` titles, separate correlation namespace, never sent remote.
- Rules: injection-marker scan of fetched content (names only) gates *critical*; escalations are never masked by the
  cooldown; own profile is not "another profile"; `allow_paths` normalised and segment-bounded; salient-event ring
  so floods cannot evict a secret read; out-of-order events no longer hide in-window ones; T1528 for token fetches.
- Delivery: refusals spool and retry on the long backoff; Elastic `_id` = event id and per-item error handling;
  redirects never followed; spool records are one line whatever the content; lazy token resolution.
- Store: retention runs on busy agents; `hosts_seen` pruned; Wazuh named rules ordered before severity fallbacks;
  Sigma correlations group by session; demo receiver hardened and logs outside the plugin tree.

### Hardened after independent audit round 2 (audit/round2.md: 2 high, 2 medium — all fixed)

- Telemetry tamper through an interpreter (`os.remove`, `shutil.rmtree`, `os.rename`, `Path.unlink`, `open(…, "w")`)
  on SIEMless's own data is critical SL-010; `events.jsonl`/`findings.jsonl` count only inside SIEMless's directory.
- Redaction: `redis-cli -a`, npm `_authToken`/`_auth`/`_password`, `.netrc` `password <value>`, `*_AUTH`/`*_PASS` env
  assignments. 27 canaries.
- Unknown tools: every path- or URL-shaped string argument is classified, whatever its name (bounded).
- SL-001 capped at medium for a reply on the agent's own channel (no external host).
- JSONL lines escape U+2028/U+2029/U+0085 and other `splitlines()` breakers.
- Dashboard: the cached read pipeline is per profile data directory, so one dashboard process serving several
  profiles never shows one profile's findings to another (found while reviewing the Mac live test).

### Fixed after the first live run on a Mac (Hermes 0.23.0, grok-4.7; tests/test_live_mac_run.py)

- A URL fetched from the shell (`curl`, `wget`, `python -c urllib …`) is now untrusted content, inferred, tagged `untrusted:shell_fetch`, and its output is scanned for injection markers. In the live run Hermes's `web_extract` refused 127.0.0.1, the model fetched the page with `curl`, and that was the path the injected text took.
- A blocked or failed `web_extract`/`x_search` is recorded as an egress attempt only, no longer as untrusted content entering the context.
