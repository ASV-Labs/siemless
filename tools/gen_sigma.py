#!/usr/bin/env python3
"""Generate the Sigma rule pack (docs/integrations/sigma/) from the baseline ruleset.

Two kinds of rule come out:
* one *finding* rule per SIEMless rule — matches the OCSF Detection Finding SIEMless itself emits
  (so any SIEM that ingests the JSONL can alert on SL-xxx with the right ATT&CK tags);
* a handful of *raw event* rules and *correlation* rules that re-derive the most important
  sequences from the raw OCSF events, independent of SIEMless's engine (for people who want the
  SIEM, not the plugin, to be the judge).

Logsource: product `hermes`, service `siemless`; field names are OCSF paths as flattened by a
JSON decoder (`unmapped.siemless.rule_id`). Tags carry the ATT&CK technique and BOTH tactic
spellings (v20 `stealth`/`defense-impairment` and the legacy names Sigma's tag appendix still
lists), as docs/RESEARCH.md §2.1/§3 recommends.

Run: python tools/gen_sigma.py   (writes YAML; validates against docs/standards/*.json when
`jsonschema` is installed).
"""

from __future__ import annotations

import importlib.util
import json
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "integrations" / "sigma"
NS = uuid.UUID("6d2d9a62-3c3b-4b5a-9f2f-5a1b7c2d8e01")  # stable ids: uuid5(NS, rule id)

LEGACY_TACTIC = {"stealth": "defense-evasion", "defense-impairment": "defense-evasion"}


def load_core():
    spec = importlib.util.spec_from_file_location("siemless_gen_pkg", ROOT / "__init__.py", submodule_search_locations=[str(ROOT)])
    m = importlib.util.module_from_spec(spec)
    m.__path__ = [str(ROOT)]
    sys.modules["siemless_gen_pkg"] = m
    spec.loader.exec_module(m)
    import importlib as il

    return il.import_module("siemless_gen_pkg.siemless_core.rules").all_rules(), il.import_module("siemless_gen_pkg.siemless_core.attack")


def yaml_dump(d: dict) -> str:
    import yaml

    return yaml.safe_dump(d, sort_keys=False, allow_unicode=True, width=100, indent=4, default_flow_style=False)


def tags_for(attack: list[dict]) -> list[str]:
    tags = []
    for a in attack:
        tags.append(f"attack.{a['id'].lower()}")
        sn = (a.get("tactic") or {}).get("shortname")
        if sn:
            tags.append(f"attack.{sn}")
            if sn in LEGACY_TACTIC:
                tags.append(f"attack.{LEGACY_TACTIC[sn]}")
    seen, out = set(), []
    for t in tags:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def finding_rule(r) -> dict:
    sev = {"info": "informational", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}[r.severity]
    return {
        "title": f"SIEMless {r.id}: {r.name}",
        "id": str(uuid.uuid5(NS, f"finding:{r.id}")),
        "name": f"siemless_finding_{r.id.lower().replace('-', '_')}",
        "status": "experimental",
        "description": r.description,
        "references": ["https://github.com/ASV-Labs/siemless"],
        "author": "ASV Labs (SIEMless)",
        "date": "2026-11-08",
        "logsource": {"product": "hermes", "service": "siemless", "definition": "SIEMless OCSF JSONL; field names are OCSF paths flattened with dots"},
        "detection": {"selection": {"class_uid": 2004, "metadata.product.name": "SIEMless", "unmapped.siemless.rule_id": r.id}, "condition": "selection"},
        "falsepositives": [r.false_positives] if r.false_positives else ["Unknown"],
        "level": sev,
        "tags": tags_for(r.attack) + ["detection.threat-hunting"] if not r.attack else tags_for(r.attack),
    }


def raw_rules(attack) -> list[dict]:
    T = attack.technique
    base = {"status": "experimental", "references": ["https://github.com/ASV-Labs/siemless"], "author": "ASV Labs (SIEMless)", "date": "2026-11-08",
            "logsource": {"product": "hermes", "service": "siemless", "definition": "SIEMless OCSF JSONL; field names are OCSF paths flattened with dots"}}
    return [
        {**base, "title": "Hermes agent read a credential store", "id": str(uuid.uuid5(NS, "raw:secret_access")), "name": "siemless_raw_secret_access",
         "description": "A SIEMless secret.access event: a tool call or command targeted an SSH key, cloud credentials, .env, keychain or browser store.",
         "detection": {"selection": {"metadata.product.name": "SIEMless", "unmapped.siemless.kind": "secret.access"}, "condition": "selection"},
         "falsepositives": ["Developers asking the agent to edit their own .env or ssh config"], "level": "medium",
         "tags": tags_for([T("T1552"), T("T1555")])},
        {**base, "title": "Hermes agent shell command reaches the network", "id": str(uuid.uuid5(NS, "raw:shell_egress")), "name": "siemless_raw_shell_egress",
         "description": "A net.egress event derived from a terminal command (curl, wget, ssh, scp, nc …). Inferred from command text.",
         "detection": {"selection": {"metadata.product.name": "SIEMless", "unmapped.siemless.kind": "net.egress", "unmapped.siemless.tags|contains": "egress:shell"},
                       "filter_dev": {"unmapped.siemless.tags|contains": "egress:dev"}, "condition": "selection and not filter_dev"},
         "falsepositives": ["Package installs and git operations to registries (filtered by egress:dev)"], "level": "low",
         "tags": tags_for([T("T1071.001")])},
        {**base, "title": "Hermes agent reached a webhook or paste service", "id": str(uuid.uuid5(NS, "raw:webhook")), "name": "siemless_raw_webhook_egress",
         "description": "Destination host is a known webhook, tunnel, paste or OOB-interaction service.",
         "detection": {"selection": {"metadata.product.name": "SIEMless", "unmapped.siemless.kind": "net.egress", "unmapped.siemless.tags|contains": "egress:webhook"}, "condition": "selection"},
         "falsepositives": ["Teams that notify Slack or Discord from scripts"], "level": "medium", "tags": tags_for([T("T1567.004")])},
        {**base, "title": "Hermes agent changed its own security configuration", "id": str(uuid.uuid5(NS, "raw:config")), "name": "siemless_raw_security_config_change",
         "description": "config.change on Hermes config, .env, hooks, plugins, approval mode or an agent instruction file.",
         "detection": {"selection": {"metadata.product.name": "SIEMless", "unmapped.siemless.kind": "config.change"}, "condition": "selection"},
         "falsepositives": ["The owner editing config through the agent"], "level": "high", "tags": tags_for([T("T1685")])},
        {**base, "title": "Hermes approval denied", "id": str(uuid.uuid5(NS, "raw:denied")), "name": "siemless_raw_approval_denied",
         "description": "The user denied a dangerous-command approval prompt.",
         "detection": {"selection": {"metadata.product.name": "SIEMless", "unmapped.siemless.kind": "approval.response", "unmapped.siemless.outcome": "denied"}, "condition": "selection"},
         "falsepositives": ["Normal use"], "level": "informational", "tags": []},
        {**base, "title": "Hermes agent spawned a subagent", "id": str(uuid.uuid5(NS, "raw:subagent")), "name": "siemless_raw_subagent_start",
         "description": "subagent.start: delegated work began. Used by the correlation rules.",
         "detection": {"selection": {"metadata.product.name": "SIEMless", "unmapped.siemless.kind": "subagent.start"}, "condition": "selection"},
         "falsepositives": ["Normal use"], "level": "informational", "tags": []},
    ]


def correlation_rules(attack) -> list[dict]:
    T = attack.technique
    return [
        {"title": "Credential read followed by shell egress in one Hermes session", "id": str(uuid.uuid5(NS, "corr:secret_then_egress")),
         "name": "siemless_corr_secret_then_egress", "status": "experimental", "author": "ASV Labs (SIEMless)", "date": "2026-11-08",
         "description": "SIEM-side reconstruction of SL-001: a secret.access then a shell net.egress from the same session within ten minutes.",
         "correlation": {"type": "temporal_ordered", "rules": ["siemless_raw_secret_access", "siemless_raw_shell_egress"],
                         "group-by": ["metadata.correlation_uid"], "timespan": "10m"},
         "level": "high", "tags": tags_for([T("T1552.001"), T("T1567"), T("T1700")])},
        {"title": "Three denied approvals in one Hermes session", "id": str(uuid.uuid5(NS, "corr:denies")),
         "name": "siemless_corr_repeated_denials", "status": "experimental", "author": "ASV Labs (SIEMless)", "date": "2026-11-08",
         "description": "SIEM-side reconstruction of SL-007: the user denied three prompts within five minutes.",
         "correlation": {"type": "event_count", "rules": ["siemless_raw_approval_denied"], "group-by": ["metadata.correlation_uid"],
                         "timespan": "5m", "condition": {"gte": 3}},
         "level": "medium", "tags": []},
    ]


def validate(docs: list[dict]) -> list[str]:
    try:
        import jsonschema  # type: ignore
    except ImportError:
        return ["jsonschema not installed; schema validation skipped"]
    det = json.loads((ROOT / "docs" / "standards" / "sigma-detection-rule-schema.json").read_text())
    cor = json.loads((ROOT / "docs" / "standards" / "sigma-correlation-rules-schema.json").read_text())
    problems = []
    for d in docs:
        schema = cor if "correlation" in d else det
        try:
            jsonschema.validate(d, schema)
        except jsonschema.ValidationError as exc:
            problems.append(f"{d.get('title')}: {exc.message[:160]}")
    return problems


def main() -> int:
    rules, attack = load_core()
    OUT.mkdir(parents=True, exist_ok=True)
    for old in OUT.glob("*.yml"):
        old.unlink()
    docs = []
    for r in rules:
        d = finding_rule(r)
        docs.append(d)
        (OUT / f"{d['name']}.yml").write_text(yaml_dump(d))
    for d in raw_rules(attack):
        docs.append(d)
        (OUT / f"{d['name']}.yml").write_text(yaml_dump(d))
    for d in correlation_rules(attack):
        docs.append(d)
        (OUT / f"mr_{d['name']}.yml").write_text(yaml_dump(d))
    problems = validate(docs)
    for p in problems:
        print("schema:", p)
    print(f"wrote {len(docs)} Sigma rules to {OUT} (ATT&CK {attack.version()})")
    return 1 if any(not p.startswith("jsonschema not installed") for p in problems) else 0


if __name__ == "__main__":
    sys.exit(main())
