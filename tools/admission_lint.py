#!/usr/bin/env python3
"""Run the static halves of upstream's `hermes plugins validate` against a plugin tree, using a
checkout of NousResearch/hermes-agent (no install needed): core-override, private-import,
desktop-surface and security-scan checks. The capability probe and dependency resolution still
need the real `hermes plugins validate` (CI's `admission` job runs it).

Usage: python tools/admission_lint.py /path/to/hermes-agent [/path/to/plugin]
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path


class Report:
    def __init__(self):
        self.rows, self.warnings = [], []

    def add(self, name, ok, detail=""):
        self.rows.append((name, ok, detail))

    def warn(self, message):
        self.warnings.append(message)


def main() -> int:
    ha = Path(sys.argv[1]).resolve()
    plugin = Path(sys.argv[2] if len(sys.argv) > 2 else Path(__file__).resolve().parents[1]).resolve()
    sys.path.insert(0, str(ha))
    r = Report()
    for mod, fn in (("hermes_cli.plugin_validate_core_override", "check_core_override"),
                    ("hermes_cli.plugin_validate_private_imports", "check_private_imports"),
                    ("hermes_cli.plugin_validate_desktop", "check_desktop_surface")):
        try:
            getattr(importlib.import_module(mod), fn)(r, plugin)
        except Exception as exc:  # a check that cannot import standalone is reported, not hidden
            r.add(fn, None, f"could not run standalone: {exc.__class__.__name__}: {exc}")
    try:
        from tools.plugin_guard import scan_plugin  # type: ignore

        res = scan_plugin(plugin)
        r.add("security scan", res.verdict != "dangerous", res.verdict)
        for f in getattr(res, "findings", []) or []:
            r.warn(f"scan: {f}")
    except Exception as exc:
        r.add("security scan", None, f"could not run standalone: {exc.__class__.__name__}: {exc}")
    bad = 0
    for name, ok, detail in r.rows:
        mark = "PASS" if ok else ("SKIP" if ok is None else "FAIL")
        bad += ok is False
        print(f"{mark:4} {name}: {detail}")
    for w in r.warnings:
        print(f"warn {w}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
