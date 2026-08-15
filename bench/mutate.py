#!/usr/bin/env python3
"""Mutation harness — measured recall instead of estimated recall.

    .venv/bin/python bench/mutate.py [--repo PATH] [--json]

Takes a clean tree, injects exactly one catalogued defect, runs the full auditor, and asks
whether that specific rule fired. Ground truth is exact by construction: the harness planted
the bug, so it knows precisely what should be found and where.

Why this and not just the hand-written fixtures: a fixture I wrote to demonstrate a rule is
code shaped like the rule. Real code is not. Mutating a *clean* tree means the surrounding
context is whatever the tree already was, and the rule has to find the defect in it rather
than in a sentence written to be found.

Two numbers come out, and the second is the one that decides whether anyone runs this twice:

  recall     did the planted defect fire its rule?
  collateral did the mutant produce findings the clean baseline did not, other than the
             planted one? Those are false positives caused by the mutation.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BASE = ROOT / "bench" / "fixtures" / "clean"
PYTHON = str(ROOT / ".venv" / "bin" / "python") if (ROOT / ".venv" / "bin" / "python").exists() else sys.executable


@dataclass
class Mutation:
    """One planted defect.

    `find` and `replace` are literal strings, not regexes, so a mutation either applies
    cleanly or is reported as inapplicable. A mutation that silently matched nothing would
    show up as a recall failure and send someone debugging the wrong thing.
    """

    rule_family: str
    target: str
    find: str
    replace: str
    note: str

    def apply(self, root: Path) -> bool:
        path = root / self.target
        if not path.is_file():
            return False
        text = path.read_text(encoding="utf-8")
        if self.find not in text:
            return False
        path.write_text(text.replace(self.find, self.replace, 1), encoding="utf-8")
        return True


MUTATIONS: list[Mutation] = [
    Mutation(
        "T07C", "enclave.rs",
        "hmac_tag.ct_eq(expected).into()",
        "hmac_tag == expected",
        "constant-time compare replaced with ==",
    ),
    Mutation(
        "T07C", "handler.py",
        "hmac.compare_digest(api_key, expected)",
        "api_key == expected",
        "compare_digest replaced with ==",
    ),
    Mutation(
        "T07C", "relay.go",
        "subtle.ConstantTimeCompare(signature, expected) == 1",
        "bytes.Equal(signature, expected)",
        "ConstantTimeCompare replaced with bytes.Equal",
    ),
    Mutation(
        "T06B", "handler.py",
        "requests.get(url)",
        "requests.get(url, verify=False)",
        "TLS verification disabled",
    ),
    Mutation(
        "T06B", "relay.go",
        "&tls.Config{MinVersion: tls.VersionTLS13}",
        "&tls.Config{InsecureSkipVerify: true}",
        "TLS verification disabled",
    ),
    Mutation(
        "T06B", "api.ts",
        "new https.Agent({})",
        "new https.Agent({ rejectUnauthorized: false })",
        "TLS verification disabled",
    ),
    Mutation(
        "T03", "relay.go",
        'log.Printf("loaded keyFingerprint=%s", keyFingerprint)',
        'log.Printf("loaded privateKey=%s", privateKey)',
        "secret written to a log sink",
    ),
    Mutation(
        "T04B", "handler.py",
        "def expired(expires_at, attested_now):\n    return expires_at < attested_now",
        "def expired(expires_at):\n    import time\n    return expires_at < time.time()",
        "expiry checked against the parent-controlled clock",
    ),
    Mutation(
        "T03B", "handler.py",
        '    _ = traceback\n    raise RuntimeError("E_INTERNAL")',
        "    traceback.print_exc()",
        "traceback printed across the boundary",
    ),
    Mutation(
        "T07A", "handler.py",
        "    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)\n    s.settimeout(30)",
        "    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)",
        "vsock timeout removed",
    ),
    Mutation(
        "T07B", "handler.py",
        'raise ValueError("decryption failed")',
        'raise ValueError("invalid padding")',
        "error message distinguishes padding failure",
    ),
    Mutation(
        "CFG01", "run-enclave.sh",
        "--eif-path app.eif",
        "--eif-path app.eif --debug-mode",
        "enclave launched in debug mode",
    ),
    Mutation(
        "CFG04", "Dockerfile",
        "FROM public.ecr.aws/amazonlinux/amazonlinux@sha256:1f2e3d4c5b6a798877665544332211ffeeddccbbaa99887766554433221100ff",
        "FROM public.ecr.aws/amazonlinux/amazonlinux:latest",
        "base image unpinned",
    ),
    Mutation(
        "T09B", "Dockerfile",
        "COPY . /app",
        "ENV SIGNER_PRIVATE_KEY=0x4d1f8a2b93c7e05fa6b8d34c19e7205fb83c6a4d9e1720f5c8b3a6d4e9f10275\nCOPY . /app",
        "private key baked into the image",
    ),
    Mutation(
        "T06", "attest.py",
        "    root = x509.load_pem_x509_certificate(AWS_NITRO_ROOT_CERT)\n"
        "    chain = [x509.load_der_x509_certificate(c) for c in doc[\"cabundle\"]]\n"
        "    verify_cert_chain(chain, root)\n"
        "    if not sign1.verify(chain[-1].public_key()):",
        "    if not sign1.verify(sign1.certificate):",
        "chain validation to the pinned root removed",
    ),
    Mutation(
        "CFG02", "attest.py",
        '    if all(b == 0 for v in pcrs.values() for b in v):\n'
        '        raise ValueError("debug-mode attestation rejected")\n',
        "",
        "all-zero PCR rejection removed",
    ),
    Mutation(
        "T01", "kms-key-policy.json",
        '"Condition": {',
        '"_Condition": {',
        "attestation condition removed from the KMS policy",
    ),
]


def audit(path: Path) -> dict:
    proc = subprocess.run(
        [PYTHON, str(ROOT / "cli" / "audit.py"), str(path), "--format", "json"],
        capture_output=True, text=True, timeout=900,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        raise RuntimeError(f"audit failed on {path}: {proc.stderr[-800:]}")
    return json.loads(proc.stdout)


def families(result: dict) -> set[str]:
    return {f["rule_id"].split("-")[1] for f in result["findings"]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=str(DEFAULT_BASE), help="clean tree to mutate")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    base = Path(args.repo).resolve()
    if not base.is_dir():
        print(f"no such directory: {base}", file=sys.stderr)
        return 1

    baseline = audit(base)
    baseline_families = families(baseline)
    if baseline_families:
        print(
            f"warning: baseline is not clean, it reports {sorted(baseline_families)}. "
            "Collateral counts are measured against it, not against zero.\n",
            file=sys.stderr,
        )

    rows = []
    for i, mut in enumerate(MUTATIONS):
        with tempfile.TemporaryDirectory(prefix="tee-audit-mutant-") as tmp:
            work = Path(tmp) / "repo"
            shutil.copytree(base, work)

            if not mut.apply(work):
                rows.append({
                    "rule": mut.rule_family, "target": mut.target, "note": mut.note,
                    "status": "inapplicable", "detected": False, "collateral": [],
                })
                continue

            result = audit(work)
            found = families(result)
            collateral = sorted(found - baseline_families - {mut.rule_family})
            rows.append({
                "rule": mut.rule_family,
                "target": mut.target,
                "note": mut.note,
                "status": "ok",
                "detected": mut.rule_family in found,
                "collateral": collateral,
                "layer": result["scorecard"]["effective_layer"],
            })

    applied = [r for r in rows if r["status"] == "ok"]
    detected = [r for r in applied if r["detected"]]
    with_collateral = [r for r in applied if r["collateral"]]

    if args.json:
        print(json.dumps({
            "baseline_findings": len(baseline["findings"]),
            "mutations": rows,
            "recall": len(detected) / len(applied) if applied else 0.0,
        }, indent=2))
        return 0 if len(detected) == len(applied) else 1

    print(f"base tree: {base}")
    print(f"baseline findings: {len(baseline['findings'])}\n")
    print(f"{'rule':8} {'target':22} {'detected':9} {'collateral':>10}  note")
    print("-" * 92)
    for r in rows:
        mark = "-" if r["status"] == "inapplicable" else ("yes" if r["detected"] else "NO")
        coll = "" if r["status"] == "inapplicable" else str(len(r["collateral"]))
        print(f"{r['rule']:8} {r['target']:22} {mark:9} {coll:>10}  {r['note']}")

    print()
    print(f"applied      {len(applied)}/{len(rows)}")
    print(f"recall       {len(detected)}/{len(applied)}"
          + (f"  ({100 * len(detected) / len(applied):.0f}%)" if applied else ""))
    print(f"collateral   {len(with_collateral)} mutant(s) produced unrelated findings")

    for r in applied:
        if not r["detected"]:
            print(f"  MISS  {r['rule']:8} {r['target']:22} {r['note']}")
        if r["collateral"]:
            print(f"  EXTRA {r['rule']:8} {r['target']:22} -> {r['collateral']}")

    return 0 if len(detected) == len(applied) else 1


if __name__ == "__main__":
    sys.exit(main())
