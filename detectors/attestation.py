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

# Split into material and verification, because the mutation benchmark showed that touching
# the bundle was being read as validating it: neutering the `verify_cert_chain(chain, root)`
# call left `chain = [... for c in doc["cabundle"]]` behind, the old combined pattern still
# matched on "cabundle", and the rule went quiet on a genuinely broken verifier.
#
# CHAIN_MATERIAL — the bundle is accessed. Necessary, nowhere near sufficient.
CHAIN_MATERIAL = re.compile(r"(?i)\b(cabundle|ca_?bundle|cert_?chain)\b")

# CHAIN_VERIFY — the chain is actually checked against something. This is the load-bearing
# signal; the rule stays quiet only when one of these (or a KNOWN_VALIDATOR) is present.
CHAIN_VERIFY = re.compile(
    r"(?i)\b("
    r"X509Store|X509StoreContext|add_cert|set_trust|"
    r"verify_cert_chain|build_chain|validate_chain|verify_chain|"
    r"verify_directly_issued_by|check_chain|chain_verify"
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
        if CHAIN_VERIFY.search(live) or KNOWN_VALIDATOR.search(live):
            continue

        # Two shapes of leftover, both meaning "the pieces are here and nothing checks them":
        # a pinned root constant that is never consulted, or a chain assembled from the
        # cabundle and then discarded. Either is stronger evidence than plain absence.
        orphaned_root = bool(ROOT_MATERIAL.search(live))
        unused_chain = bool(CHAIN_MATERIAL.search(live))

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
                        "File assembles a certificate chain from the attestation document's "
                        "cabundle and never verifies it against anything — the chain is "
                        "built and discarded. This is the shape left behind when the "
                        "verification call is removed and the plumbing around it survives. "
                        if unused_chain
                        else "File parses attestation documents and defines root certificate "
                        "material, but never verifies a certificate chain — the root is "
                        "present and unused. "
                        if orphaned_root
                        else "File parses attestation documents but contains no certificate "
                        "chain verification, no pinned root, and no known validating "
                        "library. "
                    )
                    + "Verifying a document against the certificate embedded in that same "
                    "document proves nothing: an attacker generates a keypair, signs a "
                    "document asserting any PCR values they like, embeds their own "
                    "certificate, and it verifies. The security of the scheme is entirely "
                    "in walking the cabundle to an out-of-band pinned AWS Nitro root."
                ),
                severity=Severity.CRITICAL,
                # Leftover plumbing is more specific evidence than plain absence.
                confidence=(
                    Confidence.HIGH if (unused_chain or orphaned_root) else Confidence.MEDIUM
                ),
                detector="attestation.chain_validation",
                metadata={
                    "orphaned_root_material": orphaned_root,
                    "unverified_chain_material": unused_chain,
                },
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



# --- BT-CS04: attestation vocabulary with no hardware root ------------------------

# The words. Used heavily by anything that genuinely attests, and equally heavily by
# something that signs a response and calls the signature an attestation.
ATTESTATION_VOCAB = re.compile(r"(?i)\battest\w*")

# Any actual root of trust. One of these anywhere in the repository is enough to say the
# project has a hardware anchor somewhere, even if a given file delegates to it.
HARDWARE_ROOT = re.compile(
    r"(?i)("
    # Confidential Space / GCP
    r"metadata\.google\.internal|computeMetadata/v1/instance/attestation"
    r"|confidentialcomputing\.googleapis\.com|\bAttestClient\b|\bJwtProvider\b"
    # the SDK's attest entry point specifically -- importing the package for its API
    # client is not attestation, and matching the bare package name made this rule
    # suppress itself on the repository it was written for.
    r"|ecloud-sdk/attest"
    # Intel TDX / SGX
    r"|/dev/tdx[-_]guest|/sys/kernel/config/tsm/report|\bDCAP\b|quote3?_?verify"
    r"|\bsgx_?(?:quote|report|ra)\b"
    # AWS Nitro
    r"|nsm_?api|/dev/nsm|nitro_enclaves_nsm|cose_?sign1|attestation_?doc"
    r"|aws[-_]nitro[-_]enclaves"
    # dstack
    r"|\btappd\b|dstack[-_](?:kms|gateway|sdk)|\bRTMR\d?\b"
    # generic JOSE verification of a platform token
    r"|createRemoteJWKSet|\bjwtVerify\b|PyJWKClient"
    r")"
)

# Evidence the project produces something it presents as attestation, rather than merely
# discussing the concept. Without this a design document that says "attestation" a lot
# would qualify.
PRODUCES_ATTESTATION = re.compile(
    r"(?i)("
    r"attestation[_-]?(?:version|header|payload|response|token|report|doc)"
    r"|X-\w+-(?:Signature|Attestation)"
    r"|\bbuildAttestation\b|\battestationFor\w*|\bgetAttestation\b|/attestation\b"
    r"|verifyAttestation|attested\s*[:=]"
    r")"
)

MIN_VOCAB_HITS = 8


def check_attestation_without_root(root: Path) -> list[Finding]:
    """BT-CS04 — the repository presents attestation it does not have.

    A repository-level question, not a file-level one, and the only rule here that is.
    The failure is not a missing check inside a verification routine: it is that no
    verification routine exists anywhere, while the surrounding project is built and
    documented as though one does.

    The shape that motivated it: a TEE-side gateway that signs every response with a
    secp256k1 key, emits `X-Eigen-Signature`, ships a `verify` package, and uses the word
    "attestation" eighty times — with no metadata-server call, no quote, no JWT, and no
    certificate chain anywhere in the tree. The signature is real. What it proves is that
    whoever holds the key signed the bytes, which is what any web server can say. It does
    not bind the response to a measured workload on attested hardware, which is the entire
    property the word is doing work for.

    This reported zero findings before the rule existed, which is worse than a false
    positive: a reader sees a clean report on a project whose central claim is unbacked.
    """
    vocab_hits = 0
    produces_at: tuple[str, int] | None = None
    saw_root = False

    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in CODE_SUFFIXES | {".md", ".json", ".toml"}:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        # A root of trust is implemented in code. The same hostname sitting in an egress
        # allowlist or a README is a declaration, not a verification -- the clean fixture
        # names confidentialcomputing.googleapis.com in its ecloud.toml, and reading that as
        # an implementation made this rule suppress itself on its own mutants.
        if path.suffix in CODE_SUFFIXES and HARDWARE_ROOT.search(text):
            saw_root = True
            break

        rel = str(path.relative_to(root))
        vocab_hits += len(ATTESTATION_VOCAB.findall(text))
        if produces_at is None and path.suffix in CODE_SUFFIXES:
            m = PRODUCES_ATTESTATION.search(text)
            if m:
                produces_at = (rel, text.count("\n", 0, m.start()) + 1)

    if saw_root or produces_at is None or vocab_hits < MIN_VOCAB_HITS:
        return []

    rel, line = produces_at
    return [
        Finding(
            rule_id="BT-CS04-attestation-without-hardware-root",
            file=rel,
            line=line,
            evidence=(
                f"{vocab_hits} uses of 'attest*' across the repository, and no hardware "
                f"root of trust anywhere in it"
            ),
            message=(
                "This project presents attestation it does not perform. It produces and "
                "verifies something it calls an attestation, and the word appears throughout "
                "— but there is no attestation token fetch, no TDX or SGX quote, no NSM "
                "document, no certificate chain to a hardware root, and no platform SDK that "
                "would do any of that on its behalf. What the signature proves is that "
                "whoever holds the signing key signed the bytes. It does not prove the code "
                "that signed them is the code you published, running on hardware that says "
                "so, which is the property the word attestation is carrying here. A consumer "
                "checking the signature and seeing it pass will believe otherwise."
            ),
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            detector="detectors:attestation.check_attestation_without_root",
            metadata={"attestation_mentions": vocab_hits},
        )
    ]


def run(root: Path, core_bin: Path | None = None) -> list[Finding]:
    return [
        *check_chain_validation(root),
        *check_zero_pcr_rejected(root),
        *check_pcr_policy_matches_eif(root, core_bin),
        *check_attestation_without_root(root),
    ]


if __name__ == "__main__":
    import sys

    from model import to_json

    target = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    core = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else None
    print(to_json(run(target, core), root=str(target)))
