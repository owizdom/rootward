#!/usr/bin/env python3
"""Print the README's rule table from the catalog.

    .venv/bin/python catalog/table.py

The table used to be maintained by hand and drifted: it claimed 42 rules when there were
46, and a rule shipped without ever appearing in it. Generating it from the YAML means the
only way to add a rule to the README is to add it to the catalog.
"""

from __future__ import annotations

import pathlib
import re
import sys

import yaml

RULES = pathlib.Path(__file__).resolve().parent / "rules"

# Reading order: threats first, then build config, then per-platform, then the scorecard.
FAMILY_ORDER = ["T", "CFG", "DS", "CS", "EC", "OS", "LYR"]


def sort_key(rule: dict) -> tuple:
    m = re.match(r"^BT-([A-Z]+)(\d+)([A-Z]?)-", rule["id"])
    family, num, suffix = m.group(1), int(m.group(2)), m.group(3)
    return (FAMILY_ORDER.index(family), num, suffix)


def main() -> int:
    rules = sorted(
        (yaml.safe_load(p.read_text(encoding="utf-8")) for p in RULES.glob("BT-*.yaml")),
        key=sort_key,
    )
    print("| # | Rule | What it detects | Threat | Layer | Severity | Confidence |")
    print("|---|---|---|---|---|---|---|")
    for i, r in enumerate(rules, 1):
        short = r["id"].split("-")[1]
        link = f"[`{short}`](catalog/rules/{r['id']}.yaml)"
        print(
            f"| {i} | {link} | {r['title']} | {r.get('threat', '—')} | "
            f"{r.get('layer_required', '—')} | {r['severity']} | {r['confidence']} |"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
