"""dstack-specific rules — BT-DS01 (code governance), BT-DS03 (KMS mode),
BT-DS04 (measured-boot policy).

Only runs when platform detection says the repo uses dstack. On a Nitro repo every one of
these would fire and every one would be wrong, and a report padded with inapplicable
findings teaches the reader to skim past the real ones.

dstack's security argument is that it assumes the TEE hardware will eventually be broken and
puts the guarantees elsewhere: on-chain governance of which code may hold keys, threshold
sharing of the root key, and measured boot compared against policy. These three rules check
that each of those is actually wired up rather than merely available.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from model import Confidence, Finding, Severity, code_only, quote_line, read_lines
from platform_detect import Platform

SKIP_DIRS = {".git", "node_modules", "target", "venv", ".venv", "dist", "build", "__pycache__"}
TEXTY = {".rs", ".go", ".py", ".ts", ".js", ".mjs", ".json", ".yaml", ".yml", ".toml", ".sh", ".sol"}

GOVERNANCE = re.compile(r"\b(KmsAuth|AppAuth)\b")
# Registering an app / allowlisting a code hash — the operations that make the contracts
# load-bearing rather than merely referenced.
GOVERNANCE_USE = re.compile(
    r"(?i)\b(register_?app|addApp|allowedCodeHash|compose_?hash|app_?id|isAppAllowed|"
    r"deploy(ed)?_?to_?chain|upgrade_?logic)\b"
)

KMS_DUPLICATION = re.compile(r"(?i)\b(simple[_-]?duplication|duplicate[_-]?root[_-]?key|single[_-]?node[_-]?kms)\b")
KMS_THRESHOLD = re.compile(r"(?i)\b(shamir|threshold|secret[_-]?shar\w*|mpc|t_?of_?n|k_?of_?n)\b")

MEASURED_BOOT = re.compile(r"(?i)\b(rtmr\d?|mrtd|measured[_-]?boot|quote|tdx[_-]?report)\b")
POLICY_COMPARE = re.compile(
    r"(?i)\b(expected[_-]?(rtmr|mrtd|measurement)|"
    r"verify[_-]?(quote|measurement|rtmr)|compare[_-]?measurement|"
    r"allowed[_-]?measurements?|measurement[_-]?policy|dstack[_-]?verifier)\b"
)


def _iter_text(root: Path):
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in TEXTY:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
            raw = path.read_text(encoding="utf-8", errors="replace")
            # Absence checks match live code only — see model.code_only.
            yield path, code_only(raw, path.suffix)
        except OSError:
            continue


def _first_line(text: str, pattern: re.Pattern) -> int:
    m = pattern.search(text)
    return text.count("\n", 0, m.start()) + 1 if m else 0


def check_governance(root: Path) -> list[Finding]:
    """BT-DS01 — no KmsAuth/AppAuth registration, so 'code is law' is not enforced."""
    any_governance = False
    any_use = False
    for _path, text in _iter_text(root):
        if GOVERNANCE.search(text):
            any_governance = True
        if GOVERNANCE_USE.search(text):
            any_use = True

    if any_governance and any_use:
        return []

    return [
        Finding(
            rule_id="BT-DS01-no-onchain-code-governance",
            file=".",
            line=0,
            evidence=(
                "no KmsAuth/AppAuth reference found in repository"
                if not any_governance
                else "KmsAuth/AppAuth referenced but no app registration or code-hash allowlisting found"
            ),
            message=(
                "dstack's code-is-law property comes from two contracts: KmsAuth holds the "
                "global allowlist of authorised applications, AppAuth holds per-application "
                "authorised code hashes and upgrade rules. Enforcement happens at the KMS "
                "layer, so unauthorised code still executes but cannot obtain decryption "
                "keys and is functionally inert. Without registration the deployment looks "
                "like it works while the governance guarantee is simply absent."
            ),
            severity=Severity.HIGH,
            confidence=Confidence.LOW,
            detector="dstack.governance_contracts",
            metadata={"note": "governance may live in a separate deployment repo"},
        )
    ]


def check_kms_mode(root: Path) -> list[Finding]:
    """BT-DS03 — root key duplicated across nodes rather than threshold-shared."""
    findings: list[Finding] = []
    for path, text in _iter_text(root):
        if not KMS_DUPLICATION.search(text):
            continue
        if KMS_THRESHOLD.search(text):
            continue
        lines = text.splitlines()
        line = _first_line(text, KMS_DUPLICATION)
        findings.append(
            Finding(
                rule_id="BT-DS03-kms-simple-duplication",
                file=str(path.relative_to(root)),
                line=line,
                evidence=quote_line(lines, line),
                message=(
                    "dstack-KMS appears configured for simple duplication: one node "
                    "generates the root key and shares it with peers after verifying "
                    "attestation. That is highly available and leaves a single point of "
                    "total compromise — one compromised node yields every derived key in "
                    "the system, which is the exact failure Layer 4 exists to prevent. "
                    "Shamir-based MPC requires a threshold of nodes to collaborate."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                detector="dstack.kms_mode",
            )
        )
    return findings


def check_rtmr_policy(root: Path) -> list[Finding]:
    """BT-DS04 — measurements collected but never compared against expected policy."""
    collectors: list[tuple[Path, str]] = []
    compares = False
    for path, text in _iter_text(root):
        if MEASURED_BOOT.search(text):
            collectors.append((path, text))
        if POLICY_COMPARE.search(text):
            compares = True

    if compares or not collectors:
        return []

    path, text = collectors[0]
    lines = text.splitlines()
    line = _first_line(text, MEASURED_BOOT)
    return [
        Finding(
            rule_id="BT-DS04-no-rtmr-policy-check",
            file=str(path.relative_to(root)),
            line=line,
            evidence=quote_line(lines, line),
            message=(
                "Measured-boot values are handled but no comparison against an expected "
                "policy was found. dstack's verification chain runs hardware to OS to "
                "containers, compared against expected measurements; collecting them "
                "without comparing them is the dstack analogue of accepting an attestation "
                "without pinning it — the quote verifies, and it attests to nothing in "
                "particular."
            ),
            severity=Severity.CRITICAL,
            confidence=Confidence.LOW,
            detector="dstack.rtmr_policy",
            metadata={"note": "comparison may be delegated to dstack-KMS key release"},
        )
    ]


def run(root: Path, platform: Platform | None = None) -> list[Finding]:
    """No-ops unless the repo actually uses dstack."""
    if platform is not None and not platform.dstack:
        return []
    return [
        *check_governance(root),
        *check_kms_mode(root),
        *check_rtmr_policy(root),
    ]


if __name__ == "__main__":
    import sys

    import platform_detect
    from model import to_json

    target = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    p = platform_detect.detect(target)
    print(to_json(run(target, p), root=str(target), platform=p.summary()))
