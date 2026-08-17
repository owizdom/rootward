"""vsock boundary rules — BT-T07D (replay protection), BT-T10 (unauthenticated relayed data).

Both are absence checks scoped to a specific place, which is the design that keeps them
usable. Asking "does this repository have replay protection?" produces noise on every file;
asking "this function handles vsock messages, does *its* schema carry a freshness token?"
produces a short list.

So the shape is: find the handlers first, then check only those. Scoping is doing the heavy
lifting for precision — the same move that keeps the attestation rules off FFI shims.

BT-T10 is the handbook's Threat 10, the one with a worked dollar figure attached: an oracle
fetching price data through the parent, acting on it without verifying a signature, and an
operator injecting a fabricated price to trigger liquidations of healthy positions.
"""

from __future__ import annotations

import re
from pathlib import Path

from model import Confidence, Finding, Severity, code_only, quote_line, read_lines

SKIP_DIRS = {".git", "node_modules", "target", "venv", ".venv", "dist", "build", "__pycache__"}
CODE_SUFFIXES = {".rs", ".go", ".py", ".ts", ".js", ".mjs"}

TEST_PATH = re.compile(
    r"(?i)(^|/)(tests?|__tests?__|spec|specs|testdata|fixtures?|examples?|benches)(/|$)"
    r"|(^|/)(test_[^/]+|[^/]+_test|[^/]+\.(test|spec))\.[a-z]+$"
)

# --- where the boundary actually is -------------------------------------------------
VSOCK_SURFACE = re.compile(
    r"(?i)\b("
    r"AF_VSOCK|VsockStream|VsockListener|VsockAddr|vsock_?(proxy|listener|stream|addr|conn)|"
    r"SOCK_VSOCK|virtio_?vsock"
    r")\b"
)

# Reading a message off that surface. Without one of these the file merely mentions vsock.
MESSAGE_READ = re.compile(
    r"(?i)\b("
    r"recv|read_to_end|read_exact|read_line|readMessage|read_message|"
    r"from_slice|from_reader|deserialize|loads?|parse|JSON\.parse|unmarshal"
    r")\b"
)

# --- BT-T07D: is there anything that makes a message single-use? --------------------
FRESHNESS = re.compile(
    r"(?i)\b("
    r"nonce|counter|sequence_?(no|num|number)|seq_?(no|num)|"
    r"replay|freshness|monotonic|"
    r"issued_?at|not_?before|not_?after|expires_?at|timestamp"
    r")\b"
)

# Consuming the token, not merely carrying it. A struct field called `nonce` that nobody
# checks is the same class of mistake as a root certificate nobody consults.
FRESHNESS_ENFORCED = re.compile(
    r"(?i)("
    r"\b(seen|used|consumed|replay)_?(nonces?|ids?|tokens?)\b|"
    r"\bnonce\b[^\n]{0,60}(contains|insert|check|verify|match|==|!=)|"
    r"(contains|insert|check|verify)[^\n]{0,40}\bnonce\b|"
    r"\b(counter|seq(_?no|uence)?)\b[^\n]{0,40}(>|<|>=|<=|\+= *1|increment)|"
    r"\breplay[_ ]?(protect|check|guard|window)\b"
    r")"
)

# --- BT-T10: data relayed by the parent, consumed without verification --------------
RELAYED_SOURCE = re.compile(
    r"(?i)\b("
    r"kms_?(client|proxy|response)|kmstool|"
    r"oracle|price_?(feed|response|data)|quote_?response|"
    r"http_?(get|post|response)|reqwest|axios|fetch\(|requests\.(get|post)|"
    r"proxy_?(request|response)|relay"
    r")\b"
)

# Acting on it in a way that carries authority.
AUTHORITY_USE = re.compile(
    r"(?i)\b("
    r"price|amount|balance|collateral|liquidat\w*|withdraw\w*|transfer|"
    r"authoriz\w*|permit|allow(ed)?|grant|approve|"
    r"state_?(root|transition)|settle\w*"
    r")\b"
)

# Something that would make the relayed payload trustworthy end to end.
#
# Deliberately generous, including a bare `.verify(...)` method call. This rule has already
# been gated twice by the time it gets here (the file relays parent data AND uses it for
# something with authority), so the cost of accepting a weak verification signal is a missed
# finding, while the cost of rejecting a real one is flagging correctly-written code — and
# the clean fixture caught exactly that: `ORACLE_KEY.verify(body)` on a `VerifyKey` did not
# match a pattern list built around `verify_signature`-style names.
PAYLOAD_VERIFIED = re.compile(
    r"(?i)("
    r"\b(verify|check)_?(signature|sig|payload|response|attestation)\b|"
    r"\b(ed25519|secp256k1|ecdsa|schnorr|recover_?signer)\b|"
    r"\bverify_?key\b|\bverifying_?key\b|\bsigning_?key\b|"
    r"\bpublic_?key\b[^\n]{0,40}verify|"
    r"\b(merkle|inclusion_?proof|attestation_?doc)\b|"
    # A method call named verify on any object: nacl VerifyKey, ring, openssl, web3.
    r"\.\s*verify\w*\s*\("
    r")"
)


def _iter_code(root: Path):
    for path in root.rglob("*"):
        if path.suffix not in CODE_SUFFIXES or not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        rel = str(path.relative_to(root))
        if TEST_PATH.search(rel):
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
        except OSError:
            continue
        yield path, rel


def _line_of(text: str, pattern: re.Pattern) -> int:
    m = pattern.search(text)
    return text.count("\n", 0, m.start()) + 1 if m else 0


def check_replay_protection(root: Path) -> list[Finding]:
    """BT-T07D — a vsock message handler whose schema carries no freshness token."""
    findings: list[Finding] = []
    for path, rel in _iter_code(root):
        raw = path.read_text(encoding="utf-8", errors="replace")
        live = code_only(raw, path.suffix)

        # Scope: this file must actually read messages off a vsock surface.
        if not (VSOCK_SURFACE.search(live) and MESSAGE_READ.search(live)):
            continue
        if FRESHNESS_ENFORCED.search(live):
            continue

        carries_token = bool(FRESHNESS.search(live))
        lines = raw.splitlines()
        line = _line_of(raw, VSOCK_SURFACE)

        findings.append(
            Finding(
                rule_id="BT-T07D-no-replay-protection",
                file=rel,
                line=line,
                evidence=quote_line(lines, line),
                message=(
                    (
                        "Messages read off vsock carry a freshness field, but nothing in this "
                        "file consumes it — no seen-nonce set, no counter comparison, no "
                        "replay window. Carrying a nonce is not checking one. "
                        if carries_token
                        else "Messages are read off vsock with no nonce, counter, or signed "
                        "timestamp in the schema at all. "
                    )
                    + "The parent sees every message the enclave receives and can send any of "
                    "them again; a correctly signed message is still correctly signed the "
                    "second time, so authentication alone does not prevent re-execution of a "
                    "withdrawal or a state transition."
                ),
                severity=Severity.HIGH,
                # Carrying an unused token is specific evidence; total absence is weaker,
                # because an idempotent read-only handler legitimately needs neither.
                confidence=Confidence.MEDIUM if carries_token else Confidence.LOW,
                detector="vsock.replay_protection",
                metadata={"carries_unused_freshness_field": carries_token},
            )
        )
    return findings


def check_relayed_authority(root: Path) -> list[Finding]:
    """BT-T10 — parent-relayed data used for a decision without verifying its origin."""
    findings: list[Finding] = []
    for path, rel in _iter_code(root):
        raw = path.read_text(encoding="utf-8", errors="replace")
        live = code_only(raw, path.suffix)

        if not RELAYED_SOURCE.search(live):
            continue
        if not AUTHORITY_USE.search(live):
            continue
        if PAYLOAD_VERIFIED.search(live):
            continue

        lines = raw.splitlines()
        line = _line_of(raw, RELAYED_SOURCE)

        findings.append(
            Finding(
                rule_id="BT-T10-unauthenticated-parent-response",
                file=rel,
                line=line,
                evidence=quote_line(lines, line),
                message=(
                    "Data relayed through the parent is consumed in a decision that carries "
                    "authority, with no signature check, attestation, or proof verification "
                    "anywhere in this file. The enclave has no network stack, so every "
                    "external response arrives via a parent-side proxy — without end-to-end "
                    "authentication that proxy is not a blind transport but a trusted "
                    "oracle, and the operator chooses what it says."
                ),
                severity=Severity.CRITICAL,
                # Deciding which relayed value carries authority is a judgment call, which is
                # why the catalog marks this hybrid: this is the prefilter, and the semantic
                # pass adjudicates.
                confidence=Confidence.LOW,
                detector="vsock.relayed_authority",
            )
        )
    return findings


def run(root: Path) -> list[Finding]:
    return [*check_replay_protection(root), *check_relayed_authority(root)]


if __name__ == "__main__":
    import sys

    from model import to_json

    target = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    print(to_json(run(target), root=str(target)))
