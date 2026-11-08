# Events, visibility and the capability matrix

## Visibility

Every SIEMless event says how it knows what it knows:

| visibility | meaning | example |
|---|---|---|
| `observed` | Hermes reported it through an observer hook | `read_file` on `~/.ssh/id_rsa` returned `status: ok`; an approval was denied; a subagent stopped |
| `inferred` | derived from arguments or command text; the effect is not visible | `curl … https://x` in a `terminal` command (the shell ran, the socket is not seen); a `read_file` that returned an error (intent, not effect) |
| `unavailable` | the matrix row below; never attached to a stored event | whether the OS actually served the bytes of a file |

A finding's **confidence** is derived from its evidence: all observed → high, mixed → medium, all
inferred → low, and a rule may cap it lower (SL-002's causality is temporal, so it caps at medium).

## Event kinds (siemless.event.v1)

| kind | from | visibility | fields that matter |
|---|---|---|---|
| session.start / end / reset / delete | on_session_* | observed | session_id, attrs.completed/interrupted/reason |
| turn.start / turn.end | pre/post_llm_call | observed | attrs.model, user_message_sha/chars (never the text unless `record_prompts`) |
| llm.response / llm.error | post_api_request / api_request_error | observed | host (provider), attrs.model, provider, usage, duration_ms; tagged `egress:provider` |
| aux.call | post_auxiliary_call | observed | attrs.aux_task, model; tagged `egress:provider` |
| tool.call | post_tool_call | observed | tool, outcome (ok/error/blocked/cancelled), attrs.args (bounded, redacted), result_chars |
| file.read / file.write | file tools | observed when status ok, else inferred | target (path), tags `sensitive:*` / `config:*` |
| process.exec | terminal / execute_code | inferred | target (redacted first line), tags `cmd:*`, attrs.reasons, command_sha |
| net.egress | web_extract, browser navigate, send_message, command text | observed for dedicated tools, inferred from commands | host, target (url), action fetch/navigate/send/exec/publish, tags `egress:*` |
| content.untrusted | web_search/extract, browser, downloaded-file reads | as above | tags `untrusted:*` — the taint source for SL-002 |
| secret.access | derived | inherits | target, tags `sensitive:<store>` |
| config.change | derived | inherits | target, tags `config:<control>` |
| cron.change / plugin.change / skill.change | cron/skill tools, command text, /commands, on_skill_lifecycle | inherits | action, target |
| approval.request / approval.response | pre_approval_request / post_approval_response | observed | target (redacted command), outcome allowed/denied/timeout/cancelled, attrs.choice, pattern_key, surface |
| human_input | on_human_input_* | observed | attrs.kind (sudo/clarify/approval), outcome |
| subagent.start / subagent.stop | subagent_start / stop | observed | child_session_id, subagent_id, attrs.child_role, goal_sha, tool_counts, targets (bounded) |
| command | pre_command | observed | action (the slash command), tags `command:security` |
| kanban.event | kanban hooks | observed | attrs.task_id, board, assignee |
| finding | the engine | observed | rule_ids, evidence (event ids), attrs.confidence/attack/finding_id |
| siemless.health | /siemless test-exporter | observed | queue and exporter counters |

## Capability matrix (Hermes observer-hooks.md, upstream main 21ae0e1, 2026-11-07)

| Security question | Visibility | How |
|---|---|---|
| Which tool ran, with what arguments, and did it succeed | **observed** | `post_tool_call` (`status`, `args`, `duration_ms`) |
| A file read or written by the file tools | **observed** | `read_file` / `write_file` / `patch` args + status |
| A file or URL named by a tool SIEMless has no collector for (MCP servers, other plugins) | **inferred** | `path`/`file_path`/`url`-style args through the same classifiers, tagged `via:other_tool` |
| A file touched by a shell command | **inferred** | path tokens in the command text; the OS call is not visible |
| A credential store targeted | observed or inferred | path classifier over either of the above; the bytes are never seen |
| An HTTP fetch by `web_extract` / browser navigation | **observed** | url arg + status |
| Network egress from a shell command (`curl`, `ssh`, `scp`, `nc`, `/dev/tcp`) | **inferred** | parsed from command text; the connection is not visible |
| Where the model request went (provider host) | **observed** | `post_api_request.base_url` |
| Auxiliary model calls (titles, compression, vision) | **observed** | `post_auxiliary_call` |
| What text left in a message | metadata only | `send_message` arg length and hash; text never stored |
| Approval prompt raised and the user's answer | **observed** | `pre_approval_request` / `post_approval_response` |
| A tool blocked by another plugin | **observed** | `post_tool_call.status == "blocked"` |
| Subagent spawned, its goal, its tool history | **observed, metadata-only** | `subagent_start/stop`; history carries tool names and bounded targets by Hermes design, no arguments |
| A Hermes cron job created | **inferred** | `cronjob` tool arguments or `hermes cron` in a command; there is no cron hook |
| OS persistence (crontab, launchctl, systemd) | **inferred** | command text |
| A plugin installed/enabled/removed | **inferred** | `hermes plugins …` in a command, `/plugins` slash command, writes under `.hermes/plugins`; there is no plugin-lifecycle hook |
| A skill created/installed | **observed** | `on_skill_lifecycle` |
| Hermes config / .env / hooks / SOUL.md edited | observed (file tools) or inferred (commands) | path classifier |
| Approval mode changed | **inferred** | `/yolo`, `/approvals …`, `hermes config set approvals…` in a command |
| Slash commands | **observed** (name + bounded args) | `pre_command` |
| Untrusted content entering the context | **observed for the fetch**; the content is scanned, not kept | `web_*`, browser, downloaded-file reads; the first 64 KB of the result are matched against a few injection-marker shapes and only the marker *names* are recorded |
| Prompt text, tool results, file bodies | **not recorded** by default | hashes and lengths only; `record_prompts` adds a 200-char redacted preview of user messages |
| Whether the OS served a file's bytes, whether a socket opened, what a decoded payload did | **unavailable** | application-level hooks only; pair with host telemetry (auditd, EDR) for that |
| Network calls made by a plugin or MCP server directly (not via a tool) | **unavailable** | no hook covers provider-side plugin traffic |
| Prompt injection *content* | **unavailable** | SIEMless records which marker shapes matched, never the injected text; the transcript has it. No marker match proves nothing |
| SIEMless's own integrity | **inferred** | writes/deletes of its data, `sqlite3` on its DB, `hermes siemless ack` / `replay`, `plugins.entries.siemless` edits → SL-010 "SIEMless itself was changed"; a process with root on the host can still erase it silently — export remotely if that matters |
