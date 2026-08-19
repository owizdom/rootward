"""KMS key policy analysis. BT-T01 (no measurement pinning) and BT-T02 (PCR0-only).

This is the detector semgrep cannot be: both rules turn on something being *absent*. A
policy that grants `kms:Decrypt` and carries no `RecipientAttestation` condition is a
critical finding precisely because nothing is there to match.

What makes these rules worth having is that KMS enforces the constraint server-side. An
enclave that checks PCRs in its own application code can be bypassed by an operator running
different application code; a KMS key policy condition cannot. So the policy file is the
strongest available static evidence about whether measurement pinning is real.

The condition keys, per the handbook's Nitro Enclaves page and AWS's attestation docs:

    kms:RecipientAttestation:ImageSha384    PCR0 by another name
    kms:RecipientAttestation:PCR0..PCR8     individual registers
"""

from __future__ import annotations

import json
from pathlib import Path

from model import Confidence, Finding, Severity, read_lines

# Operations that release plaintext or key material to the caller. A policy granting these
# without attestation conditions is the finding; granting Describe/List is not.
SENSITIVE_ACTIONS = {
    "kms:decrypt",
    "kms:generatedatakey",
    "kms:generatedatakeypair",
    "kms:generatedatakeywithoutplaintext",
    "kms:generaterandom",
    "kms:sign",
    "kms:*",
    "*",
}

ATTESTATION_PREFIX = "kms:recipientattestation:"

# PCR0 alone is insufficient (BT-T02): it moves on any change to kernel, bootstrap, or
# application together, so it cannot express "this kernel, any of these app versions".
PCR0_KEYS = {"pcr0", "imagesha384"}


def _iter_statements(policy: dict):
    stmt = policy.get("Statement")
    if isinstance(stmt, dict):
        yield stmt
    elif isinstance(stmt, list):
        for s in stmt:
            if isinstance(s, dict):
                yield s


def _as_list(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    if isinstance(v, list):
        return [x for x in v if isinstance(x, str)]
    return []


def _attestation_keys(statement: dict) -> set[str]:
    """Every RecipientAttestation register named anywhere in this statement's conditions,
    lowercased and stripped of the key prefix ({'pcr0', 'pcr1', ...})."""
    found: set[str] = set()
    condition = statement.get("Condition")
    if not isinstance(condition, dict):
        return found
    # Condition := {operator: {key: value}}
    for operand in condition.values():
        if not isinstance(operand, dict):
            continue
        for key in operand:
            k = key.lower()
            if k.startswith(ATTESTATION_PREFIX):
                found.add(k[len(ATTESTATION_PREFIX) :])
    return found


def _looks_like_policy(doc) -> bool:
    return isinstance(doc, dict) and "Statement" in doc and (
        "Version" in doc or any(isinstance(s, dict) and "Effect" in s for s in _iter_statements(doc))
    )


def _find_line(lines: list[str], needle: str) -> int:
    for i, line in enumerate(lines, start=1):
        if needle in line:
            return i
    return 0


def analyze_policy(path: Path, doc: dict, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = read_lines(path)

    for idx, stmt in enumerate(_iter_statements(doc)):
        if str(stmt.get("Effect", "")).lower() != "allow":
            continue

        actions = {a.lower() for a in _as_list(stmt.get("Action")) + _as_list(stmt.get("Actions"))}
        sensitive = actions & SENSITIVE_ACTIONS
        if not sensitive:
            continue

        registers = _attestation_keys(stmt)
        sid = stmt.get("Sid") or f"statement[{idx}]"
        line = _find_line(lines, str(stmt.get("Sid"))) if stmt.get("Sid") else 0

        if not registers:
            findings.append(
                Finding(
                    rule_id="BT-T01-no-measurement-pinning",
                    file=rel,
                    line=line,
                    evidence=(
                        f"{sid}: Allow {sorted(sensitive)} with no "
                        f"kms:RecipientAttestation condition"
                    ),
                    message=(
                        "KMS key policy releases key material without any attestation "
                        "condition. A correctly signed attestation from any enclave, "
                        "including one running replaced code, satisfies this policy, so "
                        "the measurement guarantee is not enforced anywhere KMS can see."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=Confidence.MEDIUM,
                    detector="kms_policy.no_attestation_condition",
                    metadata={"statement": sid, "actions": sorted(sensitive)},
                )
            )
            continue

        if registers <= PCR0_KEYS:
            findings.append(
                Finding(
                    rule_id="BT-T02-pcr0-only",
                    file=rel,
                    line=line,
                    evidence=f"{sid}: pins only {sorted(registers)}",
                    message=(
                        "Policy pins PCR0 (or ImageSha384) alone. PCR0 covers kernel, "
                        "bootstrap and application together, so a routine kernel patch "
                        "forces a policy rotation, and the usual resolution is to loosen "
                        "the pin. Pin PCR1 and PCR2 separately, and PCR8 when images are "
                        "signed."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    detector="kms_policy.pcr_coverage",
                    metadata={"statement": sid, "pinned": sorted(registers)},
                )
            )

    return findings


def run(root: Path) -> list[Finding]:
    """Scan a repository for KMS/IAM policy documents and analyze each.

    Coverage gap worth stating: this reads JSON policy documents. Policies expressed in
    Terraform HCL, CDK, CloudFormation YAML, or generated at deploy time are not parsed,
    so a clean result here means "no unattested policy in a JSON file", not "measurement
    pinning is enforced". The report's NOT-VERIFIED section carries that distinction.
    """
    findings: list[Finding] = []
    skip = {".git", "node_modules", "target", "venv", ".venv", "dist", "build", "__pycache__"}

    for path in root.rglob("*.json"):
        if any(part in skip for part in path.parts):
            continue
        try:
            if path.stat().st_size > 2_000_000:
                continue
            doc = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue

        if not _looks_like_policy(doc):
            continue
        findings.extend(analyze_policy(path, doc, str(path.relative_to(root))))

    return findings


if __name__ == "__main__":
    import sys

    from model import to_json

    target = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    print(to_json(run(target), root=str(target)))
