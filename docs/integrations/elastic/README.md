# SIEMless → Elastic

SIEMless ships ECS 9.x documents straight into a data stream with `_bulk` `create` actions
(`application/x-ndjson`, `Authorization: ApiKey …`). Default data stream:
`logs-siemless.hermes-default`. Mapping notes are in docs/RESEARCH.md §8.

## 1. Index template

`index_template.json` here maps the fields SIEMless uses (`event.*`, `file.path`,
`process.command_line`, `destination.domain`, `url.full`, `rule.*`, `threat.*`, `trace.id`,
`transaction.id`, `agent.*`, `observer.*`, `siemless.*` as flattened). Install it:

```
curl -X PUT "https://es.example.com:9200/_index_template/logs-siemless.hermes" \
  -H "Authorization: ApiKey $KEY" -H "Content-Type: application/json" \
  --data-binary @index_template.json
```

The data stream is created on first write.

## 2. API key

Create a key with `create_doc` and `auto_configure` on `logs-siemless.hermes-*`:

```json
{"name": "siemless", "role_descriptors": {"siemless_writer": {"indices": [{"names": ["logs-siemless.hermes-*"], "privileges": ["create_doc", "auto_configure"]}]}}}
```

Store the encoded key through Hermes (Settings → Plugins → SIEMless → Elastic API key →
`SIEMLESS_ELASTIC_API_KEY`).

## 3. Configure SIEMless

```
hermes config set plugins.entries.siemless.settings.remote_export true
hermes config set plugins.entries.siemless.settings.elastic_url https://es.example.com:9200
```

`/siemless test-exporter`, then in Discover: `data_stream.dataset : "siemless.hermes"`.

## 4. KQL

Findings: `event.kind : "alert" and observer.product : "SIEMless"`

High and critical: `event.kind : "alert" and event.severity >= 70`

Credential access then egress, by session: filter `event.action : ("secret.access" or "net.egress")`,
then break down by `trace.id` (the Hermes session id) and sort by `@timestamp`.

ATT&CK: `threat.technique.id : "T1700"` — the Security app's MITRE view reads
`threat.framework`, `threat.tactic.*`, `threat.technique.*`, which every finding carries.

## Detection rules in Kibana

`event.kind` is `alert` (an external detection), never `signal`. If you want Kibana's own rule
engine to raise signals from SIEMless findings, point a custom query rule at
`observer.product : "SIEMless" and event.kind : "alert"` with severity mapped from `event.severity`.
