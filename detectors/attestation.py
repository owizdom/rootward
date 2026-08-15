"""Attestation verification analysis — BT-T06, BT-CFG02, BT-CFG03.

All three are absence checks, which is why they are here rather than in semgrep: the defect
is that something required is missing, and a pattern matcher can only find what is present.

The approach for the two code-level rules is two-phase. First establish that the file
*does* attestation work at all (otherwise every file in the repo trivially "lacks" a root
certificate check and the rule is noise). Only then look for the safeguard. That gating is
what keeps the false-positive rate survivable on a real repository.

BT-CFG03 is different and much stronger: both sides are computable. It recomputes PCR0 from
a built EIF and compares it against the value pinned in a KMS key policy, so the output is
two concrete hashes rather than an inference.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from model import (
    Confidence,
    Finding,
    Severity,
    code_only,
    quote_line,
    read_lines,
    strip_definitions,
)

SKIP_DIRS = {".git", "node_modules", "target", "venv", ".venv", "dist", "build", "__pycache__"}
CODE_SUFFIXES = {".rs", ".go", ".py", ".ts", ".js", ".mjs"}

# Tests, type declarations, and FFI shims name attestation types without performing
# verification. Corpus A found all seven false positives on Evervault's *correct* validator
# living in exactly these: a `.d.ts` with no implementation, `__test__/index.spec.mjs`, and
# binding structs whose only crime was a field called `pcr0`.
TEST_PATH = re.compile(
    r"(?i)(^|/)(tests?|__tests?__|spec|specs|testdata|fixtures?|examples?|benches)(/|$)"
    r"|(^|/)(test_[^/]+|[^/]+_test|[^/]+\.(test|spec))\.[a-z]+$"
)
DECLARATION_ONLY = re.compile(r"\.d\.ts$")

# --- phase 1: does this file handle attestation documents at all? ---------------
#
# Split into a noun and a verb. Naming an attestation type is not doing attestation work —
# an FFI binding that passes a document through, or a struct with a `pcr0` field, mentions
# every noun and performs no verification. Requiring both halves is what keeps this rule
# off the shims and on the code that actually decides whether to trust a document.
ATTESTATION_NOUN = re.compile(
    r"(?i)\b("
    r"attestation_?doc|attestationdoc|attestation_document|"
    r"cose_?sign1|coseSign1|"
    r"nsm_?api|nsm_?process_?request|NsmRequest|"
    r"describe_?nsm|GetAttestationDoc|get_attestation"
    r")\b"
)
ATTESTATION_VERB = re.compile(
    r"(?i)\b("
    r"verify|validate|authenticate|check_?signature|"
    r"from_slice|decode|deserialize|parse|loads?\b"
    r")\b"
)


def _does_attestation(text: str) -> bool:
    return bool(ATTESTATION_NOUN.search(text) and ATTESTATION_VERB.search(text))


def _is_auditable(rel: str) -> bool:
    """Exclude tests and declaration-only files from absence checks.

    A missing safeguard in a test file is not a vulnerability, and a `.d.ts` cannot contain
    a safeguard at all. Both were sources of confident-looking false positives.
    """
    return not (TEST_PATH.search(rel) or DECLARATION_ONLY.search(rel))

# --- BT-T06: is the chain actually walked to a pinned root? --------------------
#
# Split into two signals rather than one, because the mutation benchmark showed a single
# OR-of-everything pattern is defeated by a leftover constant: deleting the chain-walking
# code while leaving `AWS_NITRO_ROOT_CERT` defined still looked safe. Possessing a root
# certificate is not the same as using it, and the realistic regression is exactly that —
# verification gets refactored away and the constant stays behind.
#
# Audited implementations that own verification themselves. A file that delegates to one
# of these is not missing a safeguard — the safeguard is in the library. Corpus A surfaced
# this: Evervault's own Kotlin and wasm bindings import `validate_expected_pcrs` from the
# core crate and were flagged for not re-implementing checks the crate already performs.
KNOWN_VALIDATOR = re.compile(
    r"(?i)\b("
    r"attestation_?doc_?validation|nitro_enclave_attestation_document|"
    r"aws_nitro_enclaves_nsm_api|validate_expected_pcrs|"
    r"validate_attestation_doc_against_cert"
    r")\b"
)

# CHAIN_WALK is the load-bearing signal: evidence the cabundle is actually traversed.
CHAIN_WALK = re.compile(
    r"(?i)\b("
    r"cabundle|ca_?bundle|"
    r"X509Store|X509StoreContext|add_cert|set_trust|verify_cert_chain|"
    r"build_chain|validate_chain|verify_chain"
    r")\b"
)
# ROOT_MATERIAL alone proves only that a root is available, not that it is consulted.
ROOT_MATERIAL = re.compile(r"(?i)\b(root_?cert|root_?ca|aws_?root|nitro_?root|trust_?anchor)\b")

# --- BT-CFG02: is an all-zero PCR map rejected? --------------------------------
#
# Naming a PCR is not consuming one. Corpus A flagged `pcr0: Option<String>` in a Kotlin
# binding struct and a wasm getter attribute — files that carry PCR values across an FFI
# boundary and verify nothing. The rule needs evidence the values are actually *compared*.
HANDLES_PCRS = re.compile(r"(?i)\b(pcr0|pcr_?map|pcrs?\[|recipientattestation|imagesha384)\b")
COMPARES_PCRS = re.compile(
    r"(?i)(expected_?pcrs?|pcr_?(match|mismatch|check|compare|verify)|"
    r"\bpcrs?\b[^\n]{0,40}(==|!=|\.eq\(|equals|compare)|"
    r"(==|!=)[^\n]{0,40}\bpcrs?\b)"
)
REJECTS_ZERO = re.compile(
    r"(?i)("
    r"all\(\s*\|?\w*\|?\s*\*?\w+\s*==\s*0|"          # rust: iter().all(|b| *b == 0)
    r"\ball\(\s*b\s*==\s*0|"                          # python: all(b == 0 ...)
    r"[\"']0{32,}[\"']|"                              # literal all-zero hex string
    r"\[\s*0\s*(?:u8\s*)?;\s*(?:48|32|64)\s*\]|"      # [0u8; 48]
    r"\bis_?zero\b|\bZERO_?PCR\b|\ball_?zero\b|"
    r"\bdebug_?mode\b"
    r")"
)
# A hardcoded non-zero PCR pin rejects all-zero implicitly, so it counts as a safeguard.
HARDCODED_PCR = re.compile(r"[\"'][0-9a-fA-F]{96}[\"']")


def _iter_code(root: Path):
    for path in root.rglob("*"):
        if path.suffix not in CODE_SUFFIXES or not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if not _is_auditable(str(path.relative_to(root))):
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
        except OSError:
            continue
        yield path


def _first_match_line(lines: list[str], pattern: re.Pattern) -> int:
    for i, line in enumerate(lines, start=1):
        if pattern.search(line):
            return i
    return 0


def check_chain_validation(root: Path) -> list[Finding]:
    """BT-T06 — attestation parsed without walking the chain to a pinned AWS root."""
    findings: list[Finding] = []
    for path in _iter_code(root):
        text = path.read_text(encoding="utf-8", errors="replace")
        # Match safeguards against live code only. A comment saying the cabundle is walked
        # and an uncalled helper that walks it are both text, not verification.
        live = strip_definitions(code_only(text, path.suffix))
        if not _does_attestation(live):
            continue
        if CHAIN_WALK.search(live) or KNOWN_VALIDATOR.search(live):
            continue

        # A root constant with no chain walk is a stronger signal than nothing at all: it
        # usually means the verification was removed and the constant was left behind.
        orphaned_root = bool(ROOT_MATERIAL.search(live))

        lines = text.splitlines()
        line = _first_match_line(lines, ATTESTATION_NOUN)
        findings.append(
            Finding(
                rule_id="BT-T06-no-root-cert-validation",
                file=str(path.relative_to(root)),
                line=line,
                evidence=quote_line(lines, line),
                message=(
                    (
                        "File parses attestation documents and defines root certificate "
                        "material, but never walks a certificate bundle — the root is "
                        "present and unused. This is the shape left behind when chain "
                        "validation is refactored away and the constant survives. "
                        if orphaned_root
                        else "File parses attestation documents but contains no reference "
                        "to a certificate bundle, a pinned root, or a known validating "
                        "library. "
                    )
                    + "Verifying a document against the certificate embedded in that same "
                    "document proves nothing: an attacker generates a keypair, signs a "
                    "document asserting any PCR values they like, embeds their own "
                    "certificate, and it verifies. The security of the scheme is entirely "
                    "in walking the cabundle to an out-of-band pinned AWS Nitro root."
                ),
                severity=Severity.CRITICAL,
                # A dangling root constant is more specific evidence than plain absence.
                confidence=Confidence.HIGH if orphaned_root else Confidence.MEDIUM,
                detector="attestation.chain_validation",
                metadata={"orphaned_root_material": orphaned_root},
            )
        )
    return findings


def check_zero_pcr_rejected(root: Path) -> list[Finding]:
    """BT-CFG02 — verifier does not reject the all-zero PCR map a debug enclave emits."""
    findings: list[Finding] = []
    for path in _iter_code(root):
        text = path.read_text(encoding="utf-8", errors="replace")
        live = code_only(text, path.suffix)
        if not (HANDLES_PCRS.search(live) and _does_attestation(live)):
            continue
        # Declaring a PCR field is not verifying against one, and delegating to an
        # audited validator means the check lives there rather than here.
        if not COMPARES_PCRS.search(live) or KNOWN_VALIDATOR.search(live):
            continue
        # A hardcoded 96-hex-char pin already excludes all-zero.
        if REJECTS_ZERO.search(live) or HARDCODED_PCR.search(live):
            continue

        lines = text.splitlines()
        line = _first_match_line(lines, HANDLES_PCRS)
        findings.append(
            Finding(
                rule_id="BT-CFG02-zero-pcr-accepted",
                file=str(path.relative_to(root)),
                line=line,
                evidence=quote_line(lines, line),
                message=(
                    "PCR values are consumed with no explicit rejection of an all-zero map "
                    "and no hardcoded pin. Debug-mode enclaves report PCRs that are "
                    "entirely zeros, so a verifier that does not reject them accepts any "
                    "debug enclave as genuine — and a debug enclave is exactly what a "
                    "developer runs locally, so this passes every test."
                ),
                severity=Severity.CRITICAL,
                confidence=Confidence.LOW,
                detector="attestation.zero_pcr",
            )
        )
    return findings


# --------------------------------------------------------------------------- CFG03
PCR_CONDITION = re.compile(r"(?i)kms:RecipientAttestation:(PCR\d|ImageSha384)")


def _policy_pins(root: Path) -> dict[str, list[tuple[str, str]]]:
    """register -> [(file, pinned hex)] across every JSON policy in the repo."""
    pins: dict[str, list[tuple[str, str]]] = {}
    for path in root.rglob("*.json"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            if path.stat().st_size > 2_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "RecipientAttestation" not in text:
            continue
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            continue

        stmts = doc.get("Statement")
        stmts = [stmts] if isinstance(stmts, dict) else (stmts or [])
        for stmt in stmts:
            if not isinstance(stmt, dict):
                continue
            cond = stmt.get("Condition")
            if not isinstance(cond, dict):
                continue
            for operand in cond.values():
                if not isinstance(operand, dict):
                    continue
                for key, value in operand.items():
                    m = PCR_CONDITION.search(key)
                    if not m:
                        continue
                    reg = m.group(1).upper()
                    reg = "PCR0" if reg == "IMAGESHA384" else reg
                    for v in value if isinstance(value, list) else [value]:
                        if isinstance(v, str):
                            pins.setdefault(reg, []).append(
                                (str(path.relative_to(root)), v.lower())
                            )
    return pins


def check_pcr_policy_matches_eif(root: Path, core_bin: Path | None) -> list[Finding]:
    """BT-CFG03 — recomputed PCR does not match the value pinned in a KMS policy.

    The strongest check available statically, because neither side is inferred. Requires a
    built .eif to be present; when there is none the check simply does not run, and the
    report's NOT-VERIFIED section says so.
    """
    findings: list[Finding] = []
    if core_bin is None or not core_bin.exists():
        return findings

    pins = _policy_pins(root)
    if not pins:
        return findings

    eifs = [p for p in root.rglob("*.eif") if not any(x in SKIP_DIRS for x in p.parts)]
    for eif in eifs:
        try:
            proc = subprocess.run(
                [str(core_bin), "measure", str(eif)],
                capture_output=True, text=True, timeout=300,
            )
            payload = json.loads(proc.stdout or "{}")
        except (OSError, subprocess.SubprocessError, ValueError):
            continue
        measured = payload.get("measurements")
        if not measured:
            continue

        for reg, entries in sorted(pins.items()):
            if reg not in measured:
                continue  # PCR3/PCR4/PCR8 are not statically derivable
            actual = measured[reg].lower()
            for policy_file, pinned in entries:
                if pinned == actual:
                    continue
                findings.append(
                    Finding(
                        rule_id="BT-CFG03-pcr-policy-eif-mismatch",
                        file=policy_file,
                        line=0,
                        evidence=(
                            f"{reg}: policy pins {pinned[:24]}… but "
                            f"{eif.relative_to(root)} measures {actual[:24]}…"
                        ),
                        message=(
                            f"The {reg} pinned in this KMS policy does not match the {reg} "
                            f"recomputed from {eif.relative_to(root)}. Either the policy "
                            "authorises an image nobody can account for, or the built image "
                            "cannot obtain its keys. Note that a non-reproducible build "
                            "(BT-CFG04) makes a mismatch expected rather than suspicious, "
                            "and the nitro-cli and hypervisor parsers have been observed to "
                            "disagree — treat this as a lead to investigate."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        detector="attestation.pcr_policy_diff",
                        metadata={
                            "register": reg,
                            "pinned": pinned,
                            "measured": actual,
                            "eif": str(eif.relative_to(root)),
                        },
                    )
                )
    return findings


def run(root: Path, core_bin: Path | None = None) -> list[Finding]:
    return [
        *check_chain_validation(root),
        *check_zero_pcr_rejected(root),
        *check_pcr_policy_matches_eif(root, core_bin),
    ]


if __name__ == "__main__":
    import sys

    from model import to_json

    target = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    core = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else None
    print(to_json(run(target, core), root=str(target)))
