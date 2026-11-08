"""The integration packs stay in step with the code: Sigma rules regenerate identically and validate;
every ATT&CK id a rule uses exists and is not revoked; the Wazuh XML parses; the config schema in
plugin.yaml equals the one the code generates."""

from __future__ import annotations

import json
import subprocess
import sys
import xml.dom.minidom
from pathlib import Path

import yaml

from conftest import PLUGIN_DIR, mod

SIGMA = PLUGIN_DIR / "docs" / "integrations" / "sigma"


def test_attack_ids_are_known_and_current(core):
    attack = mod(core, "attack")
    rules = mod(core, "rules").all_rules()
    assert attack.version() == "20.1"
    for r in rules:
        for a in r.attack:
            assert attack.is_known(a["id"]), (r.id, a["id"])
            assert attack.is_revoked(a["id"]) is False, (r.id, a["id"])
            assert a["name"] == attack.technique(a["id"])["name"]
    assert attack.is_revoked("T1562.001") is True  # the brief's id; we must never emit it


def test_sigma_pack_is_fresh_and_valid(tmp_path):
    before = {p.name: p.read_text() for p in SIGMA.glob("*.yml")}
    r = subprocess.run([sys.executable, str(PLUGIN_DIR / "tools" / "gen_sigma.py")], capture_output=True, text=True, cwd=PLUGIN_DIR)
    assert r.returncode == 0, r.stdout + r.stderr
    after = {p.name: p.read_text() for p in SIGMA.glob("*.yml")}
    assert before == after, "docs/integrations/sigma is stale: run tools/gen_sigma.py and commit"
    assert len(after) >= 20
    for name, text in after.items():
        d = yaml.safe_load(text)
        assert d["title"] and d.get("id") and d.get("level")
        if "correlation" in d:
            assert d["correlation"]["type"] in ("event_count", "value_count", "temporal", "temporal_ordered")
        else:
            assert d["logsource"]["product"] == "hermes" and "condition" in d["detection"]
        for t in d.get("tags", []):
            assert t == t.lower()
            if t.startswith("attack.t"):
                assert t.upper()[7:] != "T1562.001"


def test_wazuh_rules_parse_and_reference_real_fields():
    text = (PLUGIN_DIR / "docs" / "integrations" / "wazuh" / "local_rules.xml").read_text()
    xml.dom.minidom.parseString("<root>" + text.split("-->", 1)[1] + "</root>")
    sample = json.loads((PLUGIN_DIR / "docs" / "integrations" / "wazuh" / "sample_finding.jsonl").read_text().splitlines()[0])
    for field in ("metadata.product.name", "class_uid", "severity_id", "unmapped.siemless.rule_id", "unmapped.siemless.attack_ids", "finding_info.title"):
        cur = sample
        for part in field.split("."):
            assert part in cur, f"sample finding lacks {field}"
            cur = cur[part]
        assert not isinstance(cur, (list, dict)) or field == "finding_info.title"
    assert "<mitre><id>T1562.001" not in text


def test_plugin_yaml_schema_matches_code(core):
    cfg = mod(core, "config")
    manifest = yaml.safe_load((PLUGIN_DIR / "plugin.yaml").read_text())
    assert manifest["config_schema"] == cfg.plugin_yaml_schema()
    assert manifest["provides_hooks"] == list(mod(core, "collectors").HOOKS)
    assert manifest["version"] == core.__version__
    assert manifest["requires_env"] == []


def test_elastic_template_is_json():
    json.loads((PLUGIN_DIR / "docs" / "integrations" / "elastic" / "index_template.json").read_text())
