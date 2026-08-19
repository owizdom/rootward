#!/usr/bin/env python3
"""Diff a real repository's findings against what is expected of it.

    .venv/bin/python bench/check_expectations.py <path-to-repo> --name dstack

The fixture suite proves the rules find defects planted for them. It cannot prove they stay
quiet on code that is merely complicated, which is where every false positive in this
catalog has come from. `bench/corpus_expectations.yaml` pins the adjudicated answer per
repository; this diffs against it and fails on a rule that appears when it should not, or
disappears when it should be there.

Not in CI: the corpus is fetched, not vendored. Run it before a release, and after any
change to a detector.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
EXPECTATIONS = ROOT / "bench" / "corpus_expectations.yaml"


def audit(path: Path) -> set[str]:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "cli" / "audit.py"), str(path), "--format", "json"],
        capture_output=True, text=True, timeout=1800,
    )
    if proc.returncode not in (0, 2) or not proc.stdout.strip():
        raise SystemExit(f"audit failed on {path}:\n{proc.stderr[-2000:]}")
    return {f["rule_id"] for f in json.loads(proc.stdout)["findings"]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--name", required=True, help="key in corpus_expectations.yaml")
    args = ap.parse_args()

    spec = (yaml.safe_load(EXPECTATIONS.read_text()) or {}).get(args.name)
    if spec is None:
        print(f"no expectations recorded for {args.name!r}", file=sys.stderr)
        return 1

    actual = audit(Path(args.path))
    expect = set(spec.get("expect") or {})
    forbid = set(spec.get("forbid") or {})

    missing = expect - actual
    returned = forbid & actual
    unexpected = actual - expect - forbid

    print(f"{args.name}: {len(actual)} rule(s) fired")
    for rid in sorted(actual):
        print(f"  {rid}")

    problems = []
    for rid in sorted(missing):
        problems.append(f"MISSING  {rid}: expected here and did not fire. {spec['expect'][rid].strip()}")
    for rid in sorted(returned):
        problems.append(f"REGRESSED {rid}: this was a fixed false positive. {spec['forbid'][rid].strip()}")
    for rid in sorted(unexpected):
        problems.append(f"NEW      {rid}: not adjudicated. Read it, then add it to expect or forbid.")

    if problems:
        print(f"\nFAIL: {len(problems)} problem(s)\n")
        for p in problems:
            print(f"  {p}")
        return 1
    print("\nOK: matches the adjudicated expectations")
    return 0


if __name__ == "__main__":
    sys.exit(main())
