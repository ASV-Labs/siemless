# Launch checklist (hackathon deadline Nov 11, 2026 — confirm the hour on the official thread)

## Charles, in order

1. **Create `ASV-Labs/siemless`** (public, MIT) and push `main` from the sandbox repo. CI runs three
   jobs; the `admission` job is upstream's own `hermes plugins validate` and is the one that matters.
2. **Read the audit** (`audit/round1.md`) and the fixes commit; re-run `python -m pytest -q tests`.
3. **Install on the Mac mini Hermes** (`hermes plugins install ASV-Labs/siemless --enable`, gateway
   restart) and run the eight replays plus one live session. lineage's lesson: a second machine
   finds what the container cannot. Check the Desktop page renders and the chip appears.
4. **Record the demo** (storyboard below), ≤ 90 s, 1080p. Attach as `docs/media/siemless-demo.mp4`
   and to the release.
5. **Release v0.1.0** (tag on the commit, not an annotated tag object for the pin). Set `sha:` in
   `catalog/siemless.yaml` to that commit, re-pin `image:` to it, and open the catalog PR from the
   ASV fork of hermes-agent (`plugin-catalog/add-siemless`, title `feat(plugin-catalog): add siemless`).
6. **Confirm a third entry per person is allowed** on the hackathon thread; then X post + form
   (Grokbot can run the same handoff as lineage's, text below).

## Demo storyboard (≤ 90 s)

| t | shot | words on screen / said |
|---|---|---|
| 0–8 | Hermes Desktop, SIEMless page empty, chip reads `0 findings` | "Hermes does a lot while you're not looking. SIEMless turns all of it into security events your SIEM already understands." |
| 8–20 | Terminal: `python3 demo/lab/receiver.py`; browser: the injection page (looks like meeting notes) | "This page is a trap: hidden text tells the agent to read an SSH key and post it to a collector. Everything here is synthetic." |
| 20–40 | Hermes chat: "Summarise http://127.0.0.1:8787/page". **If the model refuses**, show the refusal, say so, and cut to the replay: `hermes siemless replay demo/fixtures/1_injection_succeeds.jsonl` | "A well-aligned model refuses. So here is the same sequence replayed from a recording — labelled replay, nothing hidden." |
| 40–62 | SIEMless page: SL-002 / SL-003 / SL-001 appear; click SL-001; evidence chain with `observed` / `inferred` badges; ATT&CK T1552.001 · T1567 · T1700; "not visible to SIEMless" lines | "Three findings. Click one: what was observed, why it matters, the ATT&CK techniques, and — the part I care about — what SIEMless could not see, labelled inferred." |
| 62–78 | Terminal: `tail -f ~/.hermes/plugin-data/siemless/findings.jsonl` (OCSF 2004 line) and the receiver's `[summit] HIGH SL-001 …` log line | "The same finding is an OCSF Detection Finding on disk for Wazuh, and already on the wall through the receiver contract." |
| 78–90 | README packs section; `/siemless status` with `remote export off` | "Wazuh, Splunk, Elastic, Sigma, syslog, CEF. Off by default; nothing leaves until you say so. SIEMless, from ASV Labs." |

Detection latency: read it off `/siemless status` on camera; do not state a number you did not see.

## X post (≤ 280, URLs count as 23)

```
SIEMless: agent security telemetry for Hermes. Tool calls, file reads, commands, requests, approvals, subagents → OCSF events; 14 ATT&CK-mapped rules; Wazuh, Splunk, Elastic, syslog, CEF. Evidence labelled observed or inferred.

hermes plugins install siemless
@NousResearch
```

Reply:

```
Nothing leaves your machine until you set remote_export. Observer hooks only; it never blocks the agent.

Code: https://github.com/ASV-Labs/siemless
Built for the Hermes Agent Plugin Hackathon. #HermesAgent
```

## Form answers

- Plugin name: siemless
- Repo: https://github.com/ASV-Labs/siemless
- One line: Agent security telemetry for SIEMs — OCSF events, 14 ATT&CK-mapped correlation rules, exports to Wazuh/Splunk/Elastic/syslog/CEF, evidence labelled observed or inferred.
- Longer: SIEMless records what a Hermes agent does — tool calls, file reads, shell commands, outbound requests, approvals, subagents, scheduled jobs, configuration changes — as OCSF 1.9 security events, correlates them by session and delegation tree with fourteen deterministic rules mapped to MITRE ATT&CK 20.1 (indirect prompt injection, AI-enabled exfiltration, credential discovery, persistence, governance tampering), and exports to Wazuh, Splunk HEC, Elastic, syslog and CEF with a pack and 22 Sigma rules for each. Every finding says what was observed, what was inferred and what is not visible. Observer hooks only: it never blocks, and nothing leaves the machine until remote export is enabled. Built by ASV Labs.
- Image: docs/banner.png (1200×600).
