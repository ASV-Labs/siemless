#!/usr/bin/env python3
"""Run upstream's `hermes plugins validate` logic (hermes_cli.plugin_validate.validate_plugin_dir)
from a NousResearch/hermes-agent checkout, without installing Hermes. Dev tool only: it is never
imported by the plugin, which is why the catalog's rule-9 "private core import" warning points here.

Needs `ruamel.yaml==0.18.17` and `packaging` in the interpreter (a throwaway venv is enough).

Usage: python tools/admission_lint.py /path/to/hermes-agent [/path/to/plugin]
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path


def main() -> int:
    ha = Path(sys.argv[1]).resolve()
    plugin = Path(sys.argv[2] if len(sys.argv) > 2 else Path(__file__).resolve().parents[1]).resolve()
    sys.path.insert(0, str(ha))
    validate = importlib.import_module("hermes_cli.plugin_validate").validate_plugin_dir
    report = validate(plugin)
    bad = 0
    for name, ok, detail in report.checks:
        bad += not ok
        print(f"{'PASS' if ok else 'FAIL'} {name}: {detail}")
    for w in report.warnings:
        print(f"warn {w}")
    print(f"isolation: {getattr(report, 'isolation', {}).get('verdict')}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
