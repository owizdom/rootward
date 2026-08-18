#!/usr/bin/env python3
"""Cross-reference the catalog against detectors that actually exist.

Run: uv run --with pyyaml catalog/coverage.py

A catalogued rule with no working detector is a rule the tool does not check. Keeping that
gap measured and printed is the difference between "42 rules" meaning coverage and meaning
intent — and a security tool that overstates its coverage is worse than one with an honest
hole, because someone will rely on it.

Exit code is always 0: at this stage an uncovered rule is expected, not a failure.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent
RULES = ROOT / "catalog" / "rules"
SEMGREP = ROOT / "detectors" / "semgrep" / "tee"
DETECTORS = ROOT / "detectors"


def semgrep_catalog_ids() -> dict[str, list[str]]:
    """catalog-id -> semgrep rule ids implementing it."""
    out: dict[str, list[str]] = {}
    for path in SEMGREP.glob("*.yaml"):
        doc = yaml.safe_load(path.read_text()) or {}
        for rule in doc.get("rules", []):
            cid = (rule.get("metadata") or {}).get("catalog-id")
            if cid:
                out.setdefault(cid, []).append(rule["id"])
    return out


def python_rule_ids() -> dict[str, list[str]]:
    """catalog-id -> python detector modules referencing it."""
    out: dict[str, list[str]] = {}
    for path in DETECTORS.glob("*.py"):
        text = path.read_text()
        for cid in set(re.findall(r'rule_id="(BT-[A-Z0-9-]+-[a-z0-9-]+)"', text)):
            out.setdefault(cid, []).append(path.name)
    return out


def agent_rule_ids() -> dict[str, list[str]]:
    """Rules implemented by the semantic layer.

    Read from agent/prompts.py rather than hardcoded, so adding a pass without a catalog
    entry (or vice versa) shows up as an orphan rather than passing silently.
    """
    out: dict[str, list[str]] = {}
    prompts = ROOT / "agent" / "prompts.py"
    if not prompts.exists():
        return out
    text = prompts.read_text()
    block = re.search(r"PASSES\s*=\s*\{(.*?)\n\}", text, re.S)
    if not block:
        return out
    for cid in re.findall(r'"(BT-[A-Z0-9]+-[a-z0-9-]+)"\s*:', block.group(1)):
        out.setdefault(cid, []).append("agent:semantic")
    return out


def rust_rule_ids() -> dict[str, list[str]]:
    """Rules implemented in the Rust core, which does not emit catalog ids itself —
    the mapping lives here so it stays visible rather than implicit."""
    return {
        "BT-T09A-eif-embedded-secret": ["core:eif-secret-scan"],
    }


def main() -> int:
    rules = []
    for path in sorted(RULES.glob("*.yaml")):
        rules.append(yaml.safe_load(path.read_text()))

    impl: dict[str, list[str]] = {}
    for source in (semgrep_catalog_ids(), python_rule_ids(), rust_rule_ids(), agent_rule_ids()):
        for cid, who in source.items():
            impl.setdefault(cid, []).extend(who)

    covered, uncovered = [], []
    for rule in rules:
        (covered if rule["id"] in impl else uncovered).append(rule)

    print(f"catalog: {len(rules)} rules   implemented: {len(covered)}   not yet: {len(uncovered)}\n")

    print("IMPLEMENTED")
    for rule in sorted(covered, key=lambda r: r["id"]):
        who = ", ".join(sorted(set(impl[rule["id"]])))
        print(f"  {rule['id']:38} {rule['detection']:14} {who}")

    print("\nNOT YET IMPLEMENTED")
    by_kind: dict[str, list[str]] = {}
    for rule in uncovered:
        by_kind.setdefault(rule["detection"], []).append(rule["id"])
    for kind in ("deterministic", "hybrid", "semantic"):
        for rid in sorted(by_kind.get(kind, [])):
            print(f"  {rid:38} {kind}")

    # Any catalog-id referenced by a detector but absent from the catalog is a broken
    # reference — a finding would be emitted that no rule explains.
    known = {r["id"] for r in rules}
    orphans = sorted(set(impl) - known)
    if orphans:
        print("\nORPHANED DETECTOR REFERENCES (no such catalog rule):")
        for o in orphans:
            print(f"  {o}  <- {', '.join(sorted(set(impl[o])))}")
        return 1

    det_total = sum(1 for r in rules if r["detection"] == "deterministic")
    det_done = sum(1 for r in covered if r["detection"] == "deterministic")
    print(f"\ndeterministic coverage: {det_done}/{det_total}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
