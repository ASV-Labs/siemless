# SIEMless → The Summit (or any JSON receiver)

The Summit is ASV Labs' monitoring wall. SIEMless does not assume an API there: this is the
contract SIEMless *sends*, and `demo/lab/receiver.py` implements the receiving side so the demo
can show a finding land on "the wall" without The Summit itself. Wiring the real Summit means
giving it a route that accepts this body; nothing in SIEMless depends on it existing.

## Request

```
POST {summit_url}
Authorization: Bearer <SIEMLESS_SUMMIT_TOKEN>
Content-Type: application/json
User-Agent: siemless/<version>
```

```json
{
  "source": "siemless",
  "version": "0.1.0",
  "agent": "<hermes profile name>",
  "sent_at": 1794200000000,
  "events": [ { ...canonical event... } ],
  "findings": [ { ...finding dict (siemless.finding.v1)... } ]
}
```

* `events` are canonical SIEMless events (`siemless.event.v1`): `kind`, `visibility`, `time`,
  `session_id`, `turn_id`, `tool`, `action`, `outcome`, `severity`, `target`, `host`, `tags`,
  bounded `attrs`. Which kinds arrive follows `export_scope`.
* `findings` are full finding dicts: `rule_id`, `rule_name`, `severity`, `confidence`, `title`,
  `observed`, `why`, `recommendation`, `missing_evidence`, `attack[] {id, name, tactic{id,name}, url}`,
  `visibility {observed, inferred}`, `evidence[] {id, time, kind, visibility, tool, action, target, host, tags}`,
  `session_id`, `turn_id`, `profile`, `detected_at`.

## Response

`200`/`201`/`202`/`204` = accepted. `401`/`403`/`400`/`404`/`413` = refused: SIEMless stops
sending to this destination and shows `refused` with the status in `/siemless status` until the
plugin is restarted with a fixed configuration. Anything else (5xx, timeout, connection error) is
retried with capped exponential backoff; batches wait in the on-disk spool meanwhile.

## What The Summit should show

Per finding: agent (`profile`), severity, rule id and title, confidence, the evidence chain in
time order with its observed/inferred labels, the ATT&CK ids, and the Hermes `session_id` so an
operator can open the transcript. The demo receiver prints exactly that to its log.
