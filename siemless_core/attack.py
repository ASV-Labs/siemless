"""MITRE ATT&CK lookups from the bundled, verified excerpt (``data/attack.json``, Enterprise 20.1).

A rule never types a technique name by hand: ``technique("T1700")`` returns the name, tactic and
URL from the bundle, and a test fails if a rule references an id that is missing or revoked.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Optional

_DATA = Path(__file__).resolve().parent / "data" / "attack.json"


@lru_cache(maxsize=1)
def bundle() -> dict:
    with open(_DATA, "r", encoding="utf-8") as fh:
        return json.load(fh)


def version() -> str:
    return str(bundle().get("attack_version") or "")


def technique(tid: str) -> dict:
    """``{"id", "name", "tactic": {"id", "name", "shortname"}, "url", "version"}`` or raise KeyError."""
    t = bundle()["techniques"][tid]
    if t.get("revoked"):
        raise KeyError(f"{tid} is revoked in ATT&CK {version()}")
    shortname = (t.get("tactics") or [None])[0]
    tac = bundle()["tactics"].get(shortname or "", {})
    return {"id": tid, "name": t["name"], "url": t.get("url"), "version": t.get("version"),
            "tactic": {"id": tac.get("id"), "name": tac.get("name"), "shortname": shortname}}


def techniques(*tids: str) -> list[dict]:
    return [technique(t) for t in tids]


def is_known(tid: str) -> bool:
    return tid in bundle()["techniques"]


def is_revoked(tid: str) -> Optional[bool]:
    t = bundle()["techniques"].get(tid)
    return None if t is None else bool(t.get("revoked"))


__all__ = ["bundle", "version", "technique", "techniques", "is_known", "is_revoked"]
