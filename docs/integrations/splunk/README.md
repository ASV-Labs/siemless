# SIEMless → Splunk (HTTP Event Collector)

SIEMless posts batches to `/services/collector/event` with the standard JSON envelope
(`time`, `host`, `source`, `sourcetype`, `index`, `event`). The `event` is the OCSF object by
default (`hec_format: ocsf`), or ECS / canonical if you prefer. Details verified against Splunk's
HEC documentation (docs/RESEARCH.md §6).

## 1. Create a token

Settings → Data Inputs → HTTP Event Collector → New Token. Name it `siemless`, pick an allowed
index (e.g. `agent_security`), set the default sourcetype to `siemless:ocsf`. Make sure HEC is
enabled in Global Settings (default port 8088, HTTPS on).

`inputs.conf` equivalent:

```
[http://siemless]
token = <GUID>
index = agent_security
sourcetype = siemless:ocsf
disabled = 0
```

## 2. Configure SIEMless

```
hermes config set plugins.entries.siemless.settings.remote_export true
hermes config set plugins.entries.siemless.settings.hec_url https://splunk.example.com:8088/services/collector/event
hermes config set plugins.entries.siemless.settings.hec_index agent_security
```

Store the token through Hermes's secret route (Desktop → Settings → Plugins → SIEMless → HEC token),
which saves it as `SIEMLESS_HEC_TOKEN`; the plugin reads it with `get_secret`, never from `.env`.
Then `/siemless test-exporter` sends one `siemless.health` event; `/siemless status` shows
`hec ok · sent 1`.

A private CA: set `http_ca_file` to its PEM bundle. Certificate verification cannot be turned off.

## 3. Props for the sourcetype

`props.conf`:

```
[siemless:ocsf]
KV_MODE = json
TIME_PREFIX = \"time\":
TIME_FORMAT = %s%3N
MAX_TIMESTAMP_LOOKAHEAD = 16
TRUNCATE = 100000
```

HEC already stamps `time` from the envelope, so the props are only needed if you also index the
JSONL files with a universal forwarder.

## 4. Searches

Findings, newest first:

```spl
index=agent_security sourcetype="siemless:ocsf" class_uid=2004
| eval rule=unmapped.siemless.rule_id, attack=unmapped.siemless.attack_ids
| table _time severity confidence rule finding_info.title attack metadata.correlation_uid
| sort - _time
```

Secret access followed by egress within 10 minutes, reconstructed in Splunk (independent of SL-001):

```spl
index=agent_security sourcetype="siemless:ocsf" (unmapped.siemless.kind="secret.access" OR unmapped.siemless.kind="net.egress")
| eval sess='metadata.correlation_uid', kind='unmapped.siemless.kind'
| transaction sess startswith=eval(kind=="secret.access") endswith=eval(kind=="net.egress") maxspan=10m
| table _time sess duration eventcount file.path dst_endpoint.hostname
```

ATT&CK coverage over 7 days:

```spl
index=agent_security sourcetype="siemless:ocsf" class_uid=2004 earliest=-7d
| makemv delim="," unmapped.siemless.attack_ids
| stats count by unmapped.siemless.attack_ids
```

Exporter health never reaches Splunk by design (it would be circular); read it on the Desktop page
or with `/siemless status`.

## Delivery semantics

At-least-once per destination. A batch whose acknowledgement is lost is re-sent after the
backoff, so dedupe on `metadata.uid` (the event id) if exact counts matter. Indexer acknowledgment
(`useACK`) is not used; a 2xx is treated as delivered.
