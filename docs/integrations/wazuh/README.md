# SIEMless → Wazuh

Wazuh reads SIEMless's local JSONL with its built-in JSON decoder. No custom decoder, no network
exporter: the file is the integration. Tested against the decoder and rule syntax in Wazuh's
documentation (docs/RESEARCH.md §7); the exact XML for `frequency`/`same_field` was not
re-verified on the fetched pages, so run `wazuh-logtest` once before trusting rule 100550.

## 1. Point the agent at the files

SIEMless writes two files under `<HERMES_HOME>/plugin-data/siemless/`:

| File | Contents |
|---|---|
| `events.jsonl` | every exported event, one OCSF 1.9 object per line (`export_scope` decides which kinds) |
| `findings.jsonl` | OCSF Detection Findings (class 2004) only |

The files are `0600`; the Wazuh agent runs as `wazuh` and needs read access. Either run the agent
as the Hermes user, or set `jsonl_path` to a directory you own jointly and loosen it yourself.

```xml
<!-- /var/ossec/etc/ossec.conf on the machine that runs Hermes -->
<localfile>
  <log_format>json</log_format>
  <location>/Users/you/.hermes/plugin-data/siemless/events.jsonl</location>
  <label key="siemless.file">events</label>
</localfile>
<localfile>
  <log_format>json</log_format>
  <location>/Users/you/.hermes/plugin-data/siemless/findings.jsonl</location>
  <label key="siemless.file">findings</label>
</localfile>
```

Both files rotate at `jsonl_max_mb` (default 50 MB) with five backups; Wazuh follows the active file.

## 2. Install the rules

Copy `local_rules.xml` to `/var/ossec/etc/rules/siemless_rules.xml` on the manager and restart it.
Rule ids 100500–100599. Levels: findings 5/7/10/13 by SIEMless severity; named rules 7–12.

## 3. Test

```
/var/ossec/bin/wazuh-logtest
# paste one line from findings.jsonl
```

You should see the JSON decoder's dynamic fields (`class_uid`, `finding_info.title`,
`unmapped.siemless.rule_id`, `unmapped.siemless.attack_ids`, …) and a match on 100510 plus the
severity and named rule. A demo line is in `sample_finding.jsonl` here.

## What Wazuh cannot read

Wazuh's JSON decoder flattens nested objects but **not arrays of objects**. OCSF puts the ATT&CK
mapping in `finding_info.attacks[]` and observables in `observables[]`; those are invisible to Wazuh
rules. SIEMless mirrors them as plain strings for exactly this reason:

| OCSF (array) | Wazuh-readable mirror |
|---|---|
| `finding_info.attacks[].technique.uid` | `unmapped.siemless.attack_ids` = `"T1552.001,T1567,T1700"` |
| `metadata.labels[]` (tags) | `unmapped.siemless.tags` = `"sensitive:ssh,via:terminal"` |
| `finding_info.related_events[].uid` | `unmapped.siemless.evidence_ids` |

`<mitre><id>` entries that Wazuh's ATT&CK database does not know yet (T1698, T1700, T1685 are ATT&CK
v20, Sept 2026) produce a warning at manager start, not an error.
