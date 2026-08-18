"""Confidential Space rules — BT-CS01 (token never verified), BT-CS02 (platform claims
unchecked), BT-CS03 (attestation failure is not fatal), plus a Confidential Space emitter
for BT-T01 (measurement not pinned).

Runs on any Google Cloud Confidential Space workload, which includes every EigenCompute
app. The substrate is worth its own tier because the failure it enables is identical
regardless of who deploys on it.

The shape of that failure is specific and worth stating, because it is what every rule here
keys on. A Confidential Space attestation is a JWT: three base64 segments, the middle one
holding claims about the hardware, the boot state, and the image digest. Decoding it takes
one line and proves *nothing* — the payload is not authenticated by being readable. The
security comes entirely from checking the signature against Google's published keys and
then reading the claims. Code that decodes and reports is extremely common, looks like
verification in a code review, and is worth exactly zero.

BT-T01 is reused rather than duplicated. Pinning an image digest from the `submods` claim
is the same act as pinning a PCR in a KMS policy: it is what binds "some enclave" to "the
code I published". Only the remediation differs, so the rule stays one rule.
"""

from __future__ import annotations

import re
from pathlib import Path

from model import (
    Confidence,
    Finding,
    Severity,
    code_only,
    quote_line,
    read_lines,
    strip_string_literals,
)
from platform_detect import Platform

SKIP_DIRS = {".git", "node_modules", "target", "venv", ".venv", "dist", "build", "__pycache__"}
CODE = {".ts", ".js", ".mjs", ".cjs", ".py", ".go", ".rs", ".java"}

# --- scoping: which files are actually doing attestation ---------------------------

# A file only qualifies if it obtains a Confidential Space token. Absence checks that are
# not scoped this tightly report every file that fails to verify something it never had.
TOKEN_SOURCE = re.compile(
    r"(?i)("
    r"computeMetadata/v1/instance/attestation/token"
    r"|attestation[_/]?verifier[_-]?claims[_-]?token"
    r"|\bAttestClient\b|\bJwtProvider\b"
    r"|\.attest\s*\(\s*\)"
    r"|/sys/kernel/config/tsm/report|/dev/tdx[-_]guest"
    r"|localhost:29343/attest"
    r")"
)

# Libraries whose job is to verify. Delegating to one is how this is supposed to be done,
# so a file that uses the platform SDK has not skipped verification -- it has performed it
# somewhere this detector cannot see, which is a different thing. The Nitro side of this
# catalog already learned the lesson: `attestation.py` keeps a KNOWN_VALIDATOR allowlist
# because flagging Evervault's validator for delegating to its own audited crate was one of
# the nine false positives on that negative control.
KNOWN_VALIDATOR = re.compile(
    r"(?i)("
    r"@layr-labs/ecloud-sdk|\bAttestClient\b|\bJwtProvider\b"
    r"|go-tpm-tools/verifier|confidential-space/.*verifier"
    r")"
)

# Verification against a key. Any one of these means the signature is actually checked.
TOKEN_VERIFIED = re.compile(
    r"(?i)("
    r"\bjwtVerify\s*\(|\bjwt\.verify\s*\(|\bjws\.verify\s*\("
    r"|createRemoteJWKSet|\bJWKS?\b\s*[,)]|PyJWKClient|get_signing_key_from_jwt"
    r"|\bjwt\.decode\s*\([^)]*verify\s*=\s*True"
    r"|\bVerifyWithKeySet\b|\bjwt\.Parse\s*\("
    r"|verify_?(token|jwt|attestation|quote)\s*\("
    r"|dcap|\bQuoteVerif|verify_?quote"
    r")"
)

# Decoding without verifying. These are the shapes that look like verification and are not.
TOKEN_DECODED_ONLY = re.compile(
    r"(?i)("
    r"\bjwt_?decode\s*\(|\bjwtDecode\s*\(|\bdecodeJwt\w*\s*\(|\bdecode_?jwt\w*\s*\("
    r"|\bjwt\.decode\s*\((?![^)]*verify\s*=\s*True)"
    r"|split\s*\(\s*[\"']\\.[\"']\s*\)"
    r"|\.split\s*\(\s*[\"']\.[\"']\s*\)"
    r")"
)

# --- BT-CS02: the claims that carry the guarantee ----------------------------------

# Each of these is a distinct assertion that a valid signature does NOT imply. A token can
# be perfectly signed and still say "this is a debug VM with secure boot off".
PLATFORM_CLAIMS = {
    "hwmodel": re.compile(r"(?i)\bhw_?model\b"),
    "swname": re.compile(r"(?i)\bsw_?name\b"),
    "secboot": re.compile(r"(?i)\bsec_?boot\b"),
    "tcbstatus": re.compile(r"(?i)\btcb_?status\b"),
}
# Reading a claim is not checking it. A comparison has to happen somewhere in the file.
CLAIM_COMPARED = re.compile(
    r"(?i)(==|!=|===|!==|\.eq\b|\bassert|\bexpect|throw|raise|panic|return\s+false"
    r"|refus|reject|mismatch|!==?\s*true|not\s+in\b)"
)

AUDIENCE_CHECKED = re.compile(r"(?i)\b(audience|\baud\b)\b\s*[:=]|audience\s*[,)]")
ISSUER_CHECKED = re.compile(r"(?i)\b(issuer|\biss\b)\b\s*[:=]|issuer\s*[,)]")

# --- BT-T01 on this platform: is the workload identity pinned ----------------------

# The two identities a Confidential Space token carries, checked independently: pinning
# the app id says *which application*, pinning the image digest says *which build of it*.
# A repo that pins one and reads the other unchecked is the common case, and collapsing
# them into a single "is anything pinned" test lets the unpinned half through.
IDENTITY_CHECKS = {
    "image digest": (
        re.compile(r"(?i)(\bsubmods\b|image_?digest)"),
        re.compile(
            r"(?i)(EXPECTED_(IMAGE_)?DIGEST|PINNED_?DIGEST|allowed_?digests?"
            r"|image_?digest\s*(===?|!==?)|(===?|!==?)\s*\w*image_?digest)"
        ),
    ),
    "app id": (
        re.compile(r"(?i)\bapp_?id\b"),
        re.compile(
            r"(?i)(EXPECTED_APP_ID|PINNED_?APP_ID"
            r"|app_?id\s*(===?|!==?)|(===?|!==?)\s*\w*app_?id)"
        ),
    ),
}

# --- BT-CS03: is an attestation failure fatal -------------------------------------

FATAL = re.compile(
    r"(?i)(throw\b|process\.exit|os\.Exit|panic!|\braise\b|sys\.exit|return\s+Err|\bexit\s*\(\s*1)"
)
# The tell-tale of a fail-open path: a warning, then execution continues.
SOFT_FAILURE = re.compile(
    r"(?i)(console\.(warn|error|log)|logger?\.(warn|warning|error)|print\s*\(|fmt\.Print|log\.Print)"
)
DEGRADED = re.compile(
    r"(?i)\b(degraded|unavailable|fall_?back|non-?blocking|best[_-]?effort)\b"
)
# Fabricating an attestation-shaped result out of nothing, so callers cannot tell the
# difference between "attested" and "we gave up".
FABRICATED = re.compile(
    r"(?i)(=\s*\{[^}]{0,200}(unavailable|\"\"|''|null|undefined|false)"
    r"|return\s*\{[^}]{0,200}(unavailable|\"\"|''|null|undefined|false))"
)
# Returning the value from before is a cache-refresh policy: the attestation that is served
# was verified when it was fetched. Serving it stale forever is worth knowing about, but it
# is not the failure this rule describes, and reporting it here buries the one that is.
SERVES_CACHED = re.compile(r"(?i)return\s+(cached\w*|prev\w*|existing\w*|last\w*|current\w*)\s*;")


def _iter_code(root: Path):
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in CODE:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        # A test that decodes a token without verifying is a test, not a deployment.
        low = str(path).lower()
        if "/test" in low or "test/" in low or low.endswith((".spec.ts", ".test.ts", ".d.ts")):
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # Absence checks read live code only: a commented-out verify call is not a verify
        # call, and a docstring describing one is not one either.
        code = code_only(raw, path.suffix)
        # `impl` is what absence checks read: comments AND string literals removed, so a
        # verification chain written as prose cannot pass for a verification chain.
        yield path, raw, code, strip_string_literals(code)


def _line_of(text: str, pattern: re.Pattern) -> int:
    m = pattern.search(text)
    return text.count("\n", 0, m.start()) + 1 if m else 0


def check_token_verification(root: Path) -> list[Finding]:
    """BT-CS01 — a Confidential Space token is obtained and never cryptographically verified."""
    out: list[Finding] = []
    for path, raw, code, impl in _iter_code(root):
        if not TOKEN_SOURCE.search(code):
            continue
        if TOKEN_VERIFIED.search(impl) or KNOWN_VALIDATOR.search(impl):
            continue
        rel = str(path.relative_to(root))
        lines = read_lines(path)
        line = _line_of(code, TOKEN_DECODED_ONLY) or _line_of(code, TOKEN_SOURCE)
        decoded = bool(TOKEN_DECODED_ONLY.search(code))
        out.append(
            Finding(
                rule_id="BT-CS01-attestation-token-unverified",
                file=rel,
                line=line,
                evidence=quote_line(lines, line),
                message=(
                    "A Confidential Space attestation token is fetched but its signature is "
                    "never verified against Google's published keys. "
                    + (
                        "The payload is base64-decoded and read directly. Decoding proves "
                        "nothing: any party can mint a token with whatever claims they like, "
                        "because nothing here distinguishes a Google signature from no "
                        "signature at all."
                        if decoded
                        else "No JWKS fetch, no jwtVerify, and no quote verification appears "
                        "in this file."
                    )
                ),
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH if decoded else Confidence.MEDIUM,
                detector="detectors:confspace.check_token_verification",
            )
        )
    return out


def check_platform_claims(root: Path) -> list[Finding]:
    """BT-CS02 — the claims that carry the platform guarantee are never compared."""
    out: list[Finding] = []
    for path, raw, code, impl in _iter_code(root):
        if not TOKEN_SOURCE.search(code):
            continue
        missing = [name for name, pat in PLATFORM_CLAIMS.items() if not pat.search(impl)]
        # A file that reads some claims but compares none is the interesting case; a file
        # that reads none is already covered by CS01's "never verified".
        read_any = len(missing) < len(PLATFORM_CLAIMS)
        compared = bool(CLAIM_COMPARED.search(impl))
        aud = bool(AUDIENCE_CHECKED.search(impl))
        iss = bool(ISSUER_CHECKED.search(impl))

        gaps = list(missing)
        if not aud:
            gaps.append("aud")
        if not iss:
            gaps.append("iss")
        if not gaps:
            continue
        # If nothing at all is read and nothing is compared, CS01 says it better.
        if not read_any and not compared:
            continue

        rel = str(path.relative_to(root))
        lines = read_lines(path)
        line = _line_of(code, TOKEN_SOURCE)
        out.append(
            Finding(
                rule_id="BT-CS02-platform-claims-unchecked",
                file=rel,
                line=line,
                evidence=quote_line(lines, line) or f"token obtained in {rel}",
                message=(
                    "Confidential Space attestation claims are not checked: "
                    f"{', '.join(sorted(set(gaps)))}. A valid signature says Google issued "
                    "the token; it does not say the workload runs on Intel TDX, that secure "
                    "boot was on, that the TCB is current, or that the token was minted for "
                    "this audience. Each of those is a separate claim and each has to be "
                    "compared against an expected value."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                detector="detectors:confspace.check_platform_claims",
                metadata={"unchecked_claims": sorted(set(gaps))},
            )
        )
    return out


def check_digest_pinning(root: Path) -> list[Finding]:
    """BT-T01 on Confidential Space — a workload identity is read but pinned to nothing.

    Deliberately emits the handbook's own measurement-pinning rule rather than a new id.
    Pinning `submods.container.image_digest` is the same act as pinning PCR1/PCR2 in a KMS
    policy: it binds "an enclave" to "the code I published". Only the remediation differs.
    """
    out: list[Finding] = []
    for path, raw, code, impl in _iter_code(root):
        if not TOKEN_SOURCE.search(code):
            continue
        for label, (read_pat, pinned_pat) in IDENTITY_CHECKS.items():
            if not read_pat.search(code):
                continue
            if pinned_pat.search(impl):
                continue
            rel = str(path.relative_to(root))
            lines = read_lines(path)
            line = _line_of(code, read_pat)
            out.append(
                Finding(
                    rule_id="BT-T01-no-measurement-pinning",
                    file=rel,
                    line=line,
                    evidence=quote_line(lines, line),
                    message=(
                        f"The workload's {label} is read out of the attestation token and "
                        "never compared against an expected value. On this platform the "
                        "image digest is the measurement: it is what KMS releases secrets "
                        "to and what is recorded on chain. Reading it and reporting it, "
                        "without an equality check against a pinned value, leaves the code "
                        "identity unenforced."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    detector="detectors:confspace.check_digest_pinning",
                    metadata={"identity": label},
                )
            )
    return out


def check_fail_open(root: Path) -> list[Finding]:
    """BT-CS03 — attestation fails and the workload starts anyway."""
    out: list[Finding] = []
    for path, raw, code, impl in _iter_code(root):
        if not TOKEN_SOURCE.search(code):
            continue
        # Look at catch/except blocks that mention the soft-failure shape.
        for m in re.finditer(
            r"(?is)(catch\s*(\([^)]*\))?\s*\{|except[^\n:]*:|if\s+err\s*!=\s*nil\s*\{)(.{0,400})",
            code,
        ):
            body = m.group(3)
            if not SOFT_FAILURE.search(body):
                continue
            if FATAL.search(body):
                continue
            fabricates = bool(DEGRADED.search(body) or FABRICATED.search(body))
            # Order matters. A block that builds an empty attestation object and then
            # returns the variable it just assigned is fabricating, not serving a cache --
            # checking "returns something cached" first swallows exactly that shape.
            if not fabricates:
                continue
            if SERVES_CACHED.search(body) and not FABRICATED.search(body):
                continue
            line = code.count("\n", 0, m.start()) + 1
            rel = str(path.relative_to(root))
            lines = read_lines(path)
            out.append(
                Finding(
                    rule_id="BT-CS03-attestation-fail-open",
                    file=rel,
                    line=line,
                    evidence=quote_line(lines, line),
                    message=(
                        "Attestation failure is caught, logged, and execution continues. "
                        "An enclave that cannot prove what it is running is indistinguishable "
                        "from one that is running something else, so this path starts the "
                        "workload — and releases whatever the workload holds — in exactly the "
                        "case the attestation existed to rule out. Failure here has to be fatal."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    detector="detectors:confspace.check_fail_open",
                )
            )
            break  # one per file is enough to act on
    return out


def run(root: Path, platform: Platform | None = None) -> list[Finding]:
    """No-ops unless the repo runs on Confidential Space (which includes EigenCompute)."""
    if platform is not None and not platform.confidential_space:
        return []
    return [
        *check_token_verification(root),
        *check_platform_claims(root),
        *check_digest_pinning(root),
        *check_fail_open(root),
    ]


if __name__ == "__main__":
    import sys

    import platform_detect
    from model import to_json

    target = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    p = platform_detect.detect(target)
    print(to_json(run(target, p), root=str(target), platform=p.summary()))
