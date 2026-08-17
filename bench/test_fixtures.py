#!/usr/bin/env python3
"""End-to-end regression test over the fixture corpora.

    uv run --with pyyaml bench/test_fixtures.py

Two assertions per fixture set, and the second matters more than the first:

  * every defect planted in a `vulnerable` tree is found   (recall)
  * the matching `clean` tree produces nothing at all      (precision)

The clean trees have already caught three rules that fired on *correct* code — a
digest-pinned Docker base image read as a private key, yum-style `pkg-version` pins read as
unpinned, and `subtle.ConstantTimeCompare(...) == 1` read as a timing oracle. All three
would have made the tool noisiest on the best-maintained repositories, and none was visible
from the vulnerable side. That is the whole argument for negative fixtures.

Exits non-zero on any mismatch, so it works as a CI gate.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "bench" / "fixtures"

# Rule families each vulnerable tree must produce. Keyed by the middle segment of the
# catalog id so the expectation survives a rename of the descriptive suffix.
EXPECTED: dict[str, dict] = {
    "vulnerable": {
        "platform": "nitro",
        "must_find": {
            "T01", "T02",       # KMS policy: no attestation condition, PCR0-only
            "T03", "T03B",      # secret logged, traceback egress
            "T04B",             # host-supplied time
            "T06", "T06B",      # no chain validation, TLS verification disabled
            "T07A", "T07B", "T07C",  # vsock timeout, padding oracle, timing oracle
            "T09A", "T09B",     # secret in ramdisk, secret in Dockerfile
            "T00A",             # host path followed through a symlink
            "T03C",             # whole output stream exposed by configuration
            "T07D", "T10",      # no replay protection, unauthenticated relayed data
            "CFG01", "CFG02", "CFG03", "CFG04",
        },
        "max_layer": 0,
    },
    "clean": {"platform": "nitro", "must_find": set(), "expect_zero": True},
    "dstack-vulnerable": {
        "platform": "dstack",
        "must_find": {"DS01", "DS02", "DS03", "DS04", "DS05"},
    },
    "dstack-clean": {"platform": "dstack", "must_find": set(), "expect_zero": True},
}


def audit(path: Path) -> dict:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "cli" / "audit.py"), str(path), "--format", "json"],
        capture_output=True, text=True, timeout=900,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        raise SystemExit(f"audit failed on {path}:\n{proc.stderr[-2000:]}")
    return json.loads(proc.stdout)


def family(rule_id: str) -> str:
    return rule_id.split("-")[1]


def main() -> int:
    failures: list[str] = []

    for name, spec in EXPECTED.items():
        target = FIXTURES / name
        if not target.is_dir():
            failures.append(f"{name}: fixture directory missing")
            continue

        result = audit(target)
        found = {family(f["rule_id"]) for f in result["findings"]}
        platform = result["platform"]["summary"]
        layer = result["scorecard"]["effective_layer"]
        ceiling = result["scorecard"]["verifiable_ceiling"]

        print(f"{name}")
        print(f"  platform  {platform}")
        print(f"  layer     {layer}/{ceiling}")
        print(f"  findings  {len(result['findings'])}  ({', '.join(sorted(found)) or 'none'})")

        if spec["platform"] not in platform:
            failures.append(f"{name}: expected platform {spec['platform']}, got {platform}")

        missing = spec["must_find"] - found
        if missing:
            failures.append(f"{name}: MISSED {sorted(missing)}")

        if spec.get("expect_zero") and result["findings"]:
            for f in result["findings"]:
                failures.append(
                    f"{name}: FALSE POSITIVE {f['rule_id']} at {f['file']}:{f['line']} "
                    f"— {f['evidence'][:80]}"
                )

        if "max_layer" in spec and layer > spec["max_layer"]:
            failures.append(f"{name}: layer {layer} exceeds expected max {spec['max_layer']}")

        # Every finding must carry evidence. A finding without the offending line is an
        # assertion, which is the thing this whole project is against.
        for f in result["findings"]:
            if not f["evidence"].strip():
                failures.append(f"{name}: {f['rule_id']} at {f['file']}:{f['line']} has no evidence")

        # A report that claims nothing was missed is itself a defect.
        if not result["not_verified"]:
            failures.append(f"{name}: NOT-VERIFIED section is empty")
        print()

    if failures:
        print(f"FAIL — {len(failures)} problem(s):\n")
        for f in failures:
            print(f"  {f}")
        return 1

    print("OK — all fixture expectations met")
    return 0


if __name__ == "__main__":
    sys.exit(main())
