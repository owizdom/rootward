#!/usr/bin/env python3
"""Corpus A runner, the auditor against real repositories.

    .venv/bin/python bench/corpus.py [--only NAME] [--json] [--keep]

Clones each repository in `corpus.yaml` at its pinned ref into a scratch directory, runs
the full deterministic audit, and prints what came back.

There is no pass/fail here on purpose. Fixtures and mutants have ground truth; a real
repository does not, and inventing an expected result then tuning until it matches turns a
benchmark into a mirror. What this produces is a finding list a human reads, the number
that matters is how many of them survive that reading.

The one real assertion is `attestation-doc-validation`: it is a correct attestation
validator, so BT-T06 firing there means the chain-walk detection is broken. That is a
negative control, not an expectation about the repository.

Clones are shallow and go to a scratch directory that is gitignored; nothing is vendored,
so the audited bytes are always verifiable from the pinned ref.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "bench" / "corpus.yaml"
CACHE = ROOT / "bench" / "corpus"
PYTHON = str(ROOT / ".venv" / "bin" / "python")

# Repositories where a specific rule firing means the detector is wrong, not the repo.
NEGATIVE_CONTROLS = {
    "attestation-doc-validation": {"T06"},
    # vanta is the EigenCompute negative control. It TLS-SPKI-pins its price feed, reads
    # MNEMONIC once and zeroes it, rejects HKDF salt/info reuse, keeps the signer as a
    # non-exported KeyObject, and refuses to start on an app-id mismatch. Each of these
    # rules firing there would mean the detector is wrong, and three of them did during
    # development: EC01 on a generic sha256 helper, CS01 on delegation to the platform SDK,
    # and EC03 on a token *budget* that happened to contain the word TOKEN.
    "vanta": {"EC01", "EC02", "EC03", "CS01"},
}


def clone(url: str, ref: str, dest: Path, attempts: int = 3) -> bool:
    """Shallow clone, retried. Large repositories over a slow link fail mid-transfer with
    RPC/sideband errors often enough that a single attempt makes the corpus look broken
    when the network is merely slow."""
    if dest.exists() and (dest / ".git").exists():
        return True
    dest.parent.mkdir(parents=True, exist_ok=True)

    import os

    # A full 40-char SHA cannot be reached with `clone --branch`; fetch it directly so the
    # corpus can pin the exact commit an external audit covered rather than drifting with
    # the default branch.
    is_sha = bool(ref) and len(ref) == 40 and all(c in "0123456789abcdef" for c in ref.lower())

    for attempt in range(1, attempts + 1):
        shutil.rmtree(dest, ignore_errors=True)
        if is_sha:
            dest.mkdir(parents=True, exist_ok=True)
            steps = [
                ["git", "init", "--quiet", str(dest)],
                ["git", "-C", str(dest), "remote", "add", "origin", url],
                ["git", "-C", str(dest), "fetch", "--depth", "1", "--quiet", "origin", ref],
                ["git", "-C", str(dest), "checkout", "--quiet", "FETCH_HEAD"],
            ]
            failed = None
            for step in steps:
                r = subprocess.run(step, capture_output=True, text=True, timeout=3600)
                if r.returncode != 0:
                    failed = r
                    break
            if failed is None:
                return True
            print(f"  fetch attempt {attempt}/{attempts} failed: "
                  f"{(failed.stderr or '').strip().splitlines()[0][:160] if failed.stderr else '?'}",
                  file=sys.stderr)
            time.sleep(3 * attempt)
            continue

        cmd = ["git", "clone", "--depth", "1", "--quiet"]
        if ref and ref != "main":
            cmd += ["--branch", ref]
        cmd += [url, str(dest)]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=3600,
            # Fail fast on a stalled transfer rather than hanging the whole corpus run.
            env={**os.environ,
                 "GIT_HTTP_LOW_SPEED_LIMIT": "1000",
                 "GIT_HTTP_LOW_SPEED_TIME": "120"},
        )
        if proc.returncode == 0:
            return True
        print(f"  clone attempt {attempt}/{attempts} failed: "
              f"{proc.stderr.strip().splitlines()[0][:160] if proc.stderr.strip() else '?'}",
              file=sys.stderr)
        time.sleep(3 * attempt)

    shutil.rmtree(dest, ignore_errors=True)
    return False


def head_sha(path: Path) -> str:
    proc = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True
    )
    return proc.stdout.strip()[:12] if proc.returncode == 0 else "unknown"


def audit(path: Path) -> dict:
    proc = subprocess.run(
        [PYTHON, str(ROOT / "cli" / "audit.py"), str(path), "--format", "json"],
        capture_output=True, text=True, timeout=3600,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        raise RuntimeError(proc.stderr[-800:] or "no output")
    return json.loads(proc.stdout)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="run a single repo by name")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--keep", action="store_true", help="keep clones for inspection")
    args = ap.parse_args()

    manifest = yaml.safe_load(MANIFEST.read_text())
    repos = manifest["repos"]
    if args.only:
        repos = [r for r in repos if r["name"] == args.only]
        if not repos:
            print(f"no repo named {args.only}", file=sys.stderr)
            return 1

    results = []
    control_failures: list[str] = []

    for repo in repos:
        name = repo["name"]
        dest = CACHE / name
        print(f"== {name}", file=sys.stderr)

        if not clone(repo["url"], repo.get("ref", "main"), dest):
            results.append({"name": name, "status": "clone-failed"})
            continue

        sha = head_sha(dest)
        started = time.monotonic()
        try:
            result = audit(dest)
        except Exception as exc:  # noqa: BLE001 - a failed audit is data, not a crash
            print(f"  audit failed: {exc}", file=sys.stderr)
            results.append({"name": name, "status": "audit-failed", "sha": sha,
                            "error": str(exc)[:300]})
            continue
        elapsed = time.monotonic() - started

        by_rule: dict[str, int] = {}
        for f in result["findings"]:
            fam = f["rule_id"].split("-")[1]
            by_rule[fam] = by_rule.get(fam, 0) + 1

        for banned in NEGATIVE_CONTROLS.get(name, set()):
            if banned in by_rule:
                control_failures.append(
                    f"{name}: {banned} fired on a negative control "
                    f"({by_rule[banned]} finding(s)), the detector is wrong, not the repo"
                )

        entry = {
            "name": name,
            "status": "ok",
            "sha": sha,
            "platform": result["platform"]["summary"],
            "layer": result["scorecard"]["effective_layer"],
            "ceiling": result["scorecard"]["verifiable_ceiling"],
            "findings": len(result["findings"]),
            "by_rule": dict(sorted(by_rule.items())),
            "seconds": round(elapsed, 1),
            "top": [
                {"rule": f["rule_id"], "at": f"{f['file']}:{f['line']}",
                 "severity": f["severity"], "evidence": f["evidence"][:120]}
                for f in result["findings"][:10]
            ],
        }
        results.append(entry)
        print(f"  {sha}  platform={entry['platform']}  layer={entry['layer']}/"
              f"{entry['ceiling']}  findings={entry['findings']}  {entry['seconds']}s",
              file=sys.stderr)

        if not args.keep:
            shutil.rmtree(dest, ignore_errors=True)

    if args.json:
        print(json.dumps({"results": results, "control_failures": control_failures}, indent=2))
    else:
        print()
        print(f"{'repo':32} {'platform':10} {'layer':>6} {'findings':>9}  rules")
        print("-" * 100)
        for r in results:
            if r["status"] != "ok":
                print(f"{r['name']:32} {r['status']}")
                continue
            rules = ", ".join(f"{k}x{v}" for k, v in r["by_rule"].items()) or "none"
            print(f"{r['name']:32} {r['platform']:10} "
                  f"{r['layer']}/{r['ceiling']:>4} {r['findings']:>9}  {rules}")
        print()
        print("No pass/fail: real repositories have no ground truth. These findings are for")
        print("a human to read, and how many survive that reading is the real result.")

    if control_failures:
        print("\nNEGATIVE CONTROL FAILURES:", file=sys.stderr)
        for c in control_failures:
            print(f"  {c}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
