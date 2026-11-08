# SIEMless adversarial review, round 2

Reviewer: independent (second-round auditor; did not trust round 1's fixes or the README). Date: 2026-11-08.
Tree: `/home/claude/siemless` at `09e812d` ("audit round 1: fix all 28 findings"). Nothing outside `audit/` was
modified.

Evidence: `audit/test_audit_round2.py`. Each test asserts the *claimed* (correct) behaviour, so **a failing test is a
confirmed finding**; `test_held_*` tests assert what held up and pass. Run:

```
cd /home/claude/siemless && python3 -m pytest -q audit/test_audit_round2.py -p no:cacheprovider
```

Current result: **8 failed, 3 passed**. Scratch probes used for discovery live only under `/tmp/audit2_scratch` and
were not added to the tree (they would add install-scanner hits). Every finding below names its test.

Severity scale: critical / high / medium / low / note (same as round 1). All work was done with synthetic/fake
credentials; no real secret was read.

---

## Axis 1 — Secret leakage

### R2-L1 (high): Everyday CLI/registry/netrc credential shapes reach the store and every export in clear
- **What:** `redact_text` (`siemless_core/redact.py`) misses several credential forms that are routine in real agent
  sessions. Verified to pass through unchanged and to land in the stored event body, the OCSF `process.cmd_line`
  and the CEF `commandLine` (`cs6`) field:
  - **`redis-cli -a <password>`** — the Redis auth flag. `-a` is not in `_CLI_SECRET_FLAG_RE` and not special-cased
    like `mysql -p`.
  - **npm registry tokens: `//registry.npmjs.org/:_authToken=…`, `:_auth=…`, `:_password=…`** — the credential CI
    pipelines write most often (`.npmrc`). The `_`-prefix defeats the `\b` anchor in `_KV_RE` (`_` is a word char, so
    there is no word boundary before `auth`/`token`/`password`), and there is no `_authToken` fragment in the list.
  - **`.netrc` inline: `machine h login u password <value>`** — `.netrc` separates key and value with a *space*, not
    `=`/`:`, so `_KV_RE` never matches. (SIEMless already classifies `.netrc` as a credential store in
    `sensitive.py`, which makes leaking its contents inline the more jarring.)
- **Repro:** `test_redis_cli_password_flag_redacted`, `test_npmrc_authtoken_redacted`, `test_netrc_password_word_redacted`,
  `test_cli_password_leak_does_not_reach_store_ocsf_cef`.
- **Why it matters:** the README promises "no secrets in storage or exports". These are everyday shell/CI shapes; with
  `remote_export` on they go to Splunk/Elastic/syslog in clear, and the finding titles/`process.cmd_line` carry them.
- **Fix:** add a `redis-cli? … -a <pass>` pattern (scoped to the redis client to avoid `-a`=append false positives);
  make `_KV_RE` match credential key fragments preceded by `_`/`:` (drop the leading `\b`, or add an
  `[:_]`-prefixed alternative, and add `authtoken`/`_auth`/`_password` fragments); add a `netrc`-style
  `\bpassword\s+<value>` pattern. Put each shape in the canary fixture.

---

## Axis 2 — Detection evasion & false positives

### R2-E1 (high): The agent can delete SIEMless's own database through an interpreter with no finding at all
- **What:** round 1's H-2 fix added `cmd:telemetry_tamper`, but the regex (`sensitive.py:378`) only recognises the
  shell verbs `rm|shred|truncate|unlink|mv|sqlite3|dd` next to the path, plus a `> …siemless.db` redirect. An agent
  that has `execute_code` (Python) deletes the store with calls that carry **none** of those verbs and **no**
  `_WRITE_HINT`, so neither `cmd:telemetry_tamper` nor the path-derived `config.change` fires:
  - `os.remove(os.path.expanduser('…/siemless.db'))`
  - `shutil.rmtree(os.path.expanduser('…/plugin-data/siemless'))`
  - `os.rename('…/siemless.db', '/tmp/x')` / `os.replace(…)` (move the DB aside)

  Each produces **zero** events-with-findings. When `remote_export` is off (the default), the local DB is the only
  copy, so the SIEM simply goes dark. (Note: `pathlib …unlink()` and `open(path,'w')` *are* caught — but only as
  SL-010 *high*, not the *critical* `cmd:telemetry_tamper`/`config:siemless` tamper label — which is itself an
  inconsistency.)
- **Repro:** `test_telemetry_delete_via_interpreter_is_detected` (os.remove / shutil.rmtree / os.rename all miss);
  `test_held_pathlib_unlink_and_open_w_detected` shows the hint-bearing variants are caught.
- **Fix:** derive `config:siemless` / `cmd:telemetry_tamper` from *any* command whose `paths_in_text` classify as
  `config:siemless`, regardless of the verb — delete, move and truncate of the telemetry path are all tamper. Add
  `remove|rmtree|rename|replace|unlink|rmdir` and the `Path(...).unlink`/`open(...,'w')` shapes to `_WRITE_HINT` and
  treat a write/delete to the siemless path as critical.

### R2-E2 (medium): Secret reads and egress through an MCP/other tool are invisible unless the arg uses a listed name
- **What:** round 1's H-3 fix derives file/secret/egress events from "any other tool that names a path", but the
  implementation keys on a fixed argument-name set only. `_tool_call` picks the path with
  `S.first_str(args, "path","file_path","filepath","filename","file","target","source","src","destination","dest")`
  and the URL with `first_str(args, "url","uri","href")` (`collectors.py:177-179`, `:255`). An MCP server or plugin
  that names its argument differently defeats the whole chain:
  - secret read with arg `location` / `input` / `object` / `source_path` / `uri-but-for-a-file` → **no**
    `secret.access` → SL-001 / SL-003 / SL-014 blind.
  - egress with arg `endpoint` / `target_url` / `callback` → **no** `net.egress` → SL-012 (webhook) and SL-001's
    egress half blind.
- **Repro:** `test_secret_read_via_other_tool_nonstandard_argname`, `test_egress_via_other_tool_nonstandard_argname`.
- **Why it matters:** MCP tool schemas are not standardised; `location`, `endpoint`, `callback` are common. The canary
  set and round 1 only exercised `path`/`url`. A single non-standard arg name turns off exfil detection for that tool.
- **Fix:** for an unknown tool, scan *all* string-valued args (bounded) for the first that `host_of` resolves to a
  host or `classify_path` tags as sensitive/config, rather than a fixed key list. Keep visibility `inferred`.

### R2-FP1 (medium, false positive): `.env` read then any reply to the owner fires SL-001 *high*
- **What:** `_is_external_egress` returns `True` for `action=="send"` "whatever the host" (`baseline.py:43-44`), and
  SL-001 keeps its default `high`. Reading a `.env` (routine: agents edit `.env` constantly) and then sending *any*
  message to the session owner on the agent's own channel yields **SL-001 high "Sensitive access then egress to
  owner"** (plus SL-013). round 1's FP-1 explicitly recommended "do not let a send to the session's own platform or
  chat raise SL-001 above medium"; that recommendation was never implemented (only the own-profile, docs-fetch and
  `env|grep` parts of FP-1 were).
- **Repro:** `test_fp_env_read_then_owner_reply_not_high`.
- **Fix:** when the egress is a `send` whose target is the session's own owner/platform (no external host), cap SL-001
  at medium (or require a webhook/first-seen host for high), as FP-1 asked.

---

## What held up

**Axis 1 (leakage).** The round-1 shapes stay masked: `mysql -uroot -p…`, `--password`/`--token` flags, `sshpass -p`,
`curl -u user:pass`, `Authorization: Bearer …`, URL userinfo (`postgres://u:pass@`), Slack/Discord webhook path
secrets, Stripe/STS/SendGrid prefixes, query-param secrets, PEM blocks (incl. the >1600-char preview case), KV pairs
with quoted spaces, and GCP `private_key_id`. Dict keys and list budgets are bounded. (`test_held_mysql_and_bearer_still_redacted`.)

**Axis 2 (evasion).** The evasions round 1 closed stay closed: globs (`~/.ss?/id_*`), interpreter socket/pty reverse
shells, `crontab <file>`, `$(curl…)`, decode-then-run, env dumps, `HERMES_YOLO`, `..` path-allowlist bypass,
trailing-dot/numeric-IP host canonicalisation. Deleting the DB with a shell verb (`rm`, `sqlite3`, `dd`) or a
hint-bearing interpreter call (`Path(...).unlink()`, `open(...,'w')`) is still caught (`test_held_pathlib_unlink_and_open_w_detected`).

**Axis 3 (agent-thread safety).** `collect()` stays bounded: `bound_args` budget, `MAX_COMMAND_SCAN`=16 KB,
`MAX_SUBAGENT_TARGETS`=64 (round-1 fix), `MAX_CONTENT_SCAN`=64 KB. No catastrophic-backtracking regex was found in the
classifier set within those bounds. Hooks still swallow every exception (`__init__.py`, `collectors.collect`).

**Axis 4 (delivery/reliability).** round 1's fixes verify: `_NoRedirect` refuses redirects so the bearer token never
moves; 401/403/404/413 become a recoverable `refused` with long-backoff retry rather than permanent drop; Elastic sets
`_id=e.id` and parses per-item results (no duplicate storm, no single-doc wedge); the spool is written `ensure_ascii`
and split on `"\n"` only (U+2028/U+0085 safe); retention runs on a wall-clock check, not only when idle; `hosts_seen`
is pruned. (Residual note: the **jsonl** exporter still renders with `ensure_ascii=False`, so a consumer that uses
Python `str.splitlines()` on `events.jsonl` can still mis-split a line containing U+2028/U+2029/U+0085 — Wazuh's
byte-`\n` reader is unaffected. Low.)

**Axis 5 (replay/namespace).** Replays run in a separate correlator/engine and an in-memory host set, carry the
`replay` tag through the store and OCSF `unmapped.siemless.replay`, and are filtered out of every *remote* exporter in
`dispatch._deliver`. A forged replay cannot correlate with or seed first-seen state for live detection.
(`test_held_replay_is_labelled_and_not_remote`.)

**Axis 6 (formats/standards).** 18 OCSF renderings (file/secret/exec/egress/webhook/send/api/subagent/approval/
command/kanban) pass `tools/ocsf_check.py --schema /tmp/std-src/ocsf-schema` (1.9.0) with 0 invalid; `type_uid =
class_uid*100 + activity_id` holds. All ATT&CK ids the rules use (incl. the AI techniques T1700/T1698/T1685.007/
T1567.004 and T1528/T1552.003) exist and are unrevoked in `/tmp/std-src/enterprise-attack.json`; the revoked
T1562.001 is correctly avoided for T1685. CEF header truncate-before-escape (round-1 M-12) holds; CEF extension values
escape `=` so a crafted file path cannot forge a key. RFC 5424 SD escaping and framing hold.

**Axis 7 (catalog admission).** `/tmp/valvenv/bin/python tools/admission_lint.py /home/claude/hermes-agent <clean
git-archive copy>` → **16/16 PASS**, security scan **caution** (not dangerous), isolation `host`. Re-run with
`audit/test_audit_round2.py` added to the tree: still 16/16, still caution (the test file assembles every
credential-shaped literal from parts and contains no bytecode or `authorized_keys` prose, so it adds no scanner hits).

---

## Summary ranking

| id | sev | one line | test |
|---|---|---|---|
| R2-E1 | high | `os.remove`/`shutil.rmtree`/`os.rename` on siemless.db via execute_code → no finding; SIEM goes dark | `test_telemetry_delete_via_interpreter_is_detected` |
| R2-L1 | high | `redis-cli -a PASS`, npmrc `:_authToken=/_auth=/_password=`, `.netrc` `password <val>` reach store + OCSF + CEF in clear | `test_redis_cli_password_flag_redacted`, `test_npmrc_authtoken_redacted`, `test_netrc_password_word_redacted`, `test_cli_password_leak_does_not_reach_store_ocsf_cef` |
| R2-E2 | medium | secret read / egress through an MCP/other tool is invisible unless the arg is in a fixed name list | `test_secret_read_via_other_tool_nonstandard_argname`, `test_egress_via_other_tool_nonstandard_argname` |
| R2-FP1 | medium | `.env` read + any reply to the owner → SL-001 *high* ("egress to owner"); FP-1's own-channel cap was never implemented | `test_fp_env_read_then_owner_reply_not_high` |

Counts by severity: **high 2, medium 2** (4 findings; 8 failing assertions across them). 3 held-up checks pass.

Pytest: `8 failed, 3 passed`.
