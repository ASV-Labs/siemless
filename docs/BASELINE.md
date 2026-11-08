# Baseline (2026-11-07, 9:40 PM PT)

Starting state recorded before any siemless code was written.

| Thing | Value |
|---|---|
| Upstream NousResearch/hermes-agent main | 21ae0e1238 (committed 2026-11-07T19:38:20-08:00) |
| Observer-hook contract | `website/docs/developer-guide/observer-hooks.md`, `telemetry_schema_version = "hermes.observer.v1"` |
| VALID_HOOKS source | `hermes_cli/plugins.py` lines 111–206 |
| Catalog rules | `plugin-catalog/README.md` (18 rules), lint `hermes_cli/plugin_validate_desktop.py` |
| lineage (reuse source) | P0GL0L/hermes-lineage @ 14ae9e9db62350f1c207b2e383cc9e9ea8cd0205 (v0.1.5 at 5d90271) |
| helm | ASV-Labs/hermes-helm @ d0cf5200147b2d224dbd6d97546c71b29d78e9d5 (1.2.0) |
| Catalog JSON | 1,200 entries, generated 2026-11-08T03:20Z |
| Name check | `siemless` absent from the catalog (also `sentinel`, `watchtower`, `siem`, `ocsf`) |

Hooks Hermes does NOT have (so these are inferred from tool calls, never observed): cron job
creation (→ `cronjob` tool args), plugin install/enable (→ `terminal` args / `pre_command`),
config edits (→ `write_file`/`patch` path args), network egress from the shell (→ `terminal` args).
