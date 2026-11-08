#!/usr/bin/env python3
"""Minimal offline OCSF validator built from a checkout of github.com/ocsf/ocsf-schema.

Resolves each class's ``extends`` chain, merges attribute requirements, then checks an event for:
required attributes present (walking into required object leaves one level), ``type_uid ==
class_uid*100 + activity_id``, ``class_uid`` and ``category_uid`` consistent with the class file,
and enum membership for ``activity_id`` / ``severity_id`` / ``status_id`` where the class defines
them. It also compiles a compact ``required.json`` so tests can run without the schema checkout.

Usage:
  python tools/ocsf_check.py --schema /path/to/ocsf-schema --compile siemless_core/data/ocsf_required.json
  python tools/ocsf_check.py --schema /path/to/ocsf-schema events.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

SKIP_ATTRS = {"$include"}


class Schema:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.classes: dict[str, dict] = {}
        self.objects: dict[str, dict] = {}
        self.dictionary = json.loads((self.root / "dictionary.json").read_text())
        self.categories = json.loads((self.root / "categories.json").read_text())["attributes"]
        for p in (self.root / "events").rglob("*.json"):
            d = json.loads(p.read_text())
            if "name" in d:
                self.classes[d["name"]] = d
        for p in (self.root / "objects").rglob("*.json"):
            d = json.loads(p.read_text())
            if "name" in d:
                self.objects[d["name"]] = d

    def merged(self, name: str, table: dict[str, dict]) -> dict:
        """Attributes with inheritance applied (child overrides parent)."""
        chain = []
        cur = table.get(name)
        seen = set()
        while cur and cur.get("name") not in seen:
            chain.append(cur)
            seen.add(cur.get("name"))
            parent = cur.get("extends")
            cur = table.get(parent) if parent else None
        attrs: dict[str, dict] = {}
        for d in reversed(chain):
            for k, v in (d.get("attributes") or {}).items():
                if k in SKIP_ATTRS:
                    continue
                cur_attr = attrs.setdefault(k, {})
                v = dict(v or {})
                if "enum" in v and "enum" in cur_attr:
                    merged_enum = dict(cur_attr["enum"])
                    merged_enum.update(v["enum"])  # a class adds values; base_event's 0/99 stay valid
                    v["enum"] = merged_enum
                cur_attr.update(v)
        return attrs

    def _inherited(self, name: str, key: str):
        cur = self.classes.get(name)
        seen = set()
        while cur and cur.get("name") not in seen:
            if cur.get(key) is not None:
                return cur[key]
            seen.add(cur.get("name"))
            cur = self.classes.get(cur.get("extends") or "")
        return None

    def class_info(self, name: str) -> dict:
        d = self.classes[name]
        attrs = self.merged(name, self.classes)
        cat = self._inherited(name, "category")
        cat_uid = self.categories[cat]["uid"] if cat in self.categories else None
        class_uid = (cat_uid * 1000 + d["uid"]) if cat_uid is not None and "uid" in d else d.get("uid")
        enums = {}
        for k in ("activity_id", "severity_id", "status_id"):
            e = dict((self.dictionary["attributes"].get(k) or {}).get("enum") or {})
            e.update((attrs.get(k) or {}).get("enum") or {})
            if e:
                enums[k] = sorted(int(x) for x in e.keys())
        required = sorted(k for k, v in attrs.items() if v.get("requirement") == "required")
        recommended = sorted(k for k, v in attrs.items() if v.get("requirement") == "recommended")
        obj_required = {}
        for k in required + recommended:
            otype = (attrs.get(k) or {}).get("type") or (self.dictionary["attributes"].get(k) or {}).get("type")
            if otype and otype in self.objects and otype != "object":
                oattrs = self.merged(otype, self.objects)
                req = sorted(a for a, v in oattrs.items() if v.get("requirement") == "required")
                if req:
                    obj_required[k] = req
        return {"name": name, "caption": d.get("caption"), "class_uid": class_uid, "category_uid": cat_uid,
                "required": required, "recommended": recommended, "enums": enums, "object_required": obj_required}

    def by_uid(self) -> dict[int, dict]:
        out = {}
        for name in self.classes:
            info = self.class_info(name)
            if isinstance(info["class_uid"], int) and info["class_uid"] > 0:
                out[info["class_uid"]] = info
        return out


def validate(event: dict, table: dict[int, dict]) -> list[str]:
    errs: list[str] = []
    cu = event.get("class_uid")
    info = table.get(cu)
    if info is None:
        return [f"unknown class_uid {cu}"]
    if event.get("category_uid") != info["category_uid"]:
        errs.append(f"category_uid {event.get('category_uid')} != {info['category_uid']} for {info['name']}")
    act = event.get("activity_id")
    if event.get("type_uid") != cu * 100 + (act if isinstance(act, int) else -1):
        errs.append(f"type_uid {event.get('type_uid')} != class_uid*100+activity_id")
    for k in info["required"]:
        if k not in event or event[k] in (None, "", [], {}):
            errs.append(f"missing required {k}")
    for k, allowed in info["enums"].items():
        v = event.get(k)
        if v is not None and v not in allowed:
            errs.append(f"{k}={v} not in enum {allowed}")
    for k, req in info["object_required"].items():
        v = event.get(k)
        if isinstance(v, dict):
            for a in req:
                if a not in v or v[a] in (None, "", [], {}):
                    errs.append(f"{k}.{a} required by object schema")
        elif isinstance(v, list):
            for i, item in enumerate(v):
                if isinstance(item, dict):
                    for a in req:
                        if a not in item or item[a] in (None, "", [], {}):
                            errs.append(f"{k}[{i}].{a} required by object schema")
    return errs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--schema", required=True)
    ap.add_argument("--compile", help="write the compact required-attributes table here")
    ap.add_argument("files", nargs="*")
    a = ap.parse_args()
    s = Schema(Path(a.schema))
    table = s.by_uid()
    if a.compile:
        Path(a.compile).write_text(json.dumps({"ocsf_version": json.loads((Path(a.schema) / "version.json").read_text())["version"],
                                              "classes": {str(k): v for k, v in sorted(table.items())}}, indent=1))
        print(f"wrote {a.compile}: {len(table)} classes")
    bad = 0
    for f in a.files:
        for n, line in enumerate(Path(f).read_text().splitlines(), 1):
            if not line.strip():
                continue
            errs = validate(json.loads(line), table)
            if errs:
                bad += 1
                print(f"{f}:{n}: {'; '.join(errs)}")
    if a.files:
        print(f"{bad} invalid line(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
