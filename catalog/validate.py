#!/usr/bin/env python3
"""Validate the rule catalog against schema.json.

Run: uv run --with pyyaml --with jsonschema catalog/validate.py

This is the P0 gate. A rule without a source citation, without a stated
false-positive mode, or whose filename disagrees with its id does not ship.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

CATALOG = Path(__file__).parent
RULES = CATALOG / "rules"


def _status_errors(rules: list[dict]) -> list[str]:
    """Check each rule's `status` against what actually exists.

    Three claims, three checks:
      implemented  → a detector references this rule id
      benchmarked  → also appears in docs/benchmark-results.md
      draft        → must NOT have a detector, or the field is understating the work

    The benchmark file is optional: on a fresh checkout it does not exist yet, and failing
    then would make the gate impossible to satisfy rather than informative.
    """
    import re as _re

    sys.path.insert(0, str(CATALOG))
    try:
        import coverage as cov  # type: ignore
    except Exception as exc:  # noqa: BLE001 - report, don't crash the validator
        return [f"could not compute coverage for status check: {exc}"]

    implemented: set[str] = set()
    for source in (
        cov.semgrep_catalog_ids(),
        cov.python_rule_ids(),
        cov.rust_rule_ids(),
        cov.agent_rule_ids(),
    ):
        implemented |= set(source)

    results = CATALOG.parent / "docs" / "benchmark-results.md"
    measured: set[str] = set()
    have_results = results.exists()
    if have_results:
        measured = set(_re.findall(r"^\| `([A-Z0-9]+)` \|", results.read_text(), _re.M))

    out: list[str] = []
    for rule in rules:
        rid = rule.get("id")
        status = rule.get("status", "draft")
        if not isinstance(rid, str):
            continue
        family = rid.split("-")[1] if "-" in rid else ""

        if status in ("implemented", "benchmarked") and rid not in implemented:
            out.append(f"{rid}.yaml: status is {status!r} but no detector references it")
        if status == "benchmarked" and have_results and family not in measured:
            out.append(
                f"{rid}.yaml: status is 'benchmarked' but {family} has no row in "
                f"docs/benchmark-results.md"
            )
        if status == "draft" and rid in implemented:
            out.append(
                f"{rid}.yaml: status is 'draft' but a detector implements it "
                f"(set 'implemented' or 'benchmarked')"
            )
    return out


def main() -> int:
    schema = json.loads((CATALOG / "schema.json").read_text())
    validator = Draft202012Validator(schema)

    errors: list[str] = []
    seen_ids: dict[str, str] = {}
    rules: list[dict] = []

    paths = sorted(RULES.glob("*.yaml"))
    if not paths:
        print("no rules found", file=sys.stderr)
        return 1

    for path in paths:
        try:
            rule = yaml.safe_load(path.read_text())
        except yaml.YAMLError as exc:
            errors.append(f"{path.name}: unparseable YAML: {exc}")
            continue

        if not isinstance(rule, dict):
            errors.append(f"{path.name}: top level is not a mapping")
            continue

        for err in sorted(validator.iter_errors(rule), key=lambda e: list(e.path)):
            loc = ".".join(str(p) for p in err.path) or "(root)"
            errors.append(f"{path.name}: {loc}: {err.message}")

        rule_id = rule.get("id")
        if isinstance(rule_id, str):
            # Filename must match id, so a rule is greppable by id alone.
            if path.stem != rule_id:
                errors.append(f"{path.name}: filename does not match id {rule_id!r}")
            if rule_id in seen_ids:
                errors.append(f"{path.name}: duplicate id {rule_id!r} (also {seen_ids[rule_id]})")
            seen_ids[rule_id] = path.name

        rules.append(rule)

    # A `status` field nobody checks drifts. Every rule in this catalog claimed `draft` for
    # weeks while 24 of them were implemented and 15 had measured numbers, exactly the
    # stale-metadata rot this tool exists to catch in other people's repositories.
    errors.extend(_status_errors(rules))

    if errors:
        print(f"FAIL: {len(errors)} problem(s) in {len(paths)} rule(s):\n", file=sys.stderr)
        for err in errors:
            print(f"  {err}", file=sys.stderr)
        return 1

    by_detection: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for rule in rules:
        by_detection[rule["detection"]] = by_detection.get(rule["detection"], 0) + 1
        by_severity[rule["severity"]] = by_severity.get(rule["severity"], 0) + 1
        by_status[rule.get("status", "draft")] = by_status.get(rule.get("status", "draft"), 0) + 1

    def fmt(d: dict[str, int], order: list[str]) -> str:
        return "  ".join(f"{k}={d[k]}" for k in order if k in d)

    print(f"OK: {len(rules)} rules, all with source citations")
    print(f"  detection:  {fmt(by_detection, ['deterministic', 'hybrid', 'semantic'])}")
    print(f"  severity:   {fmt(by_severity, ['critical', 'high', 'medium', 'low', 'info'])}")
    print(f"  status:     {fmt(by_status, ['draft', 'implemented', 'benchmarked'])}")

    # Every rule needs a detector before P2/P3 can claim coverage. Report, don't fail:
    # at P0 a catalogued rule with no detector yet is the expected state.
    missing = [r["id"] for r in rules if not r.get("detector")]
    if missing:
        print(f"  note: {len(missing)} rule(s) have no detector assigned yet")
    return 0


if __name__ == "__main__":
    sys.exit(main())
