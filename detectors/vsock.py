"""vsock boundary rules. BT-T07D (replay protection), BT-T10 (unauthenticated relayed data).

Both are absence checks scoped to a specific place, which is the design that keeps them
usable. Asking "does this repository have replay protection?" produces noise on every file;
asking "this function handles vsock messages, does *its* schema carry a freshness token?"
produces a short list.

So the shape is: find the handlers first, then check only those. Scoping is doing the heavy
lifting for precision, the same move that keeps the attestation rules off FFI shims.

BT-T10 is the handbook's Threat 10, the one with a worked dollar figure attached: an oracle
fetching price data through the parent, acting on it without verifying a signature, and an
operator injecting a fabricated price to trigger liquidations of healthy positions.
"""

from __future__ import annotations

import re
from pathlib import Path

from model import (
    DEFINITION_SITE,
    Confidence,
    Finding,
    Severity,
    code_only,
    quote_line,
    strip_definitions,
    strip_imports,
)

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
# Call-shaped, not vocabulary-shaped. A bare `reqwest` matches every file that builds an
# HTTP client, and a bare `relay` matches `let relay = async {`. Both produced criticals on
# dstack whose evidence line was a variable binding. What this rule is about is a *fetch*,
# so the pattern has to be the fetch and not the crate name.
RELAYED_SOURCE = re.compile(
    r"(?i)("
    r"\bkms_?(client|proxy|response)\b|\bkmstool\b|"
    r"\boracle\b|\bprice_?(feed|response|data)\b|\bquote_?response\b|"
    r"\bhttp_?(get|post|response)\b|"
    r"\brelay(ed)?_?(request|response|payload|data)\b|"
    r"\bproxy_?(request|response)\b|"
    # An actual call: reqwest::get(...), client.get(...).send(), axios.get(...),
    # requests.post(...), fetch(...).
    r"\breqwest::(blocking::)?(get|post)\s*\(|"
    r"\baxios\.(get|post)\s*\(|\brequests\.(get|post)\s*\(|"
    r"\bfetch\s*\(|"
    r"\.(get|post)\s*\([^)]*\)\s*\.\s*(send|await|json|text)\b"
    r")"
)

# A line that only names or binds a thing. `let client = Client::builder().build()?;` and
# `let kms = self.kms_client()?;` are plumbing, and anchoring a finding on one points the
# reader at the wrong place even when the finding itself is real.
BINDING_ONLY = re.compile(
    r"^\s*(let|const|var|pub\s+let)?\s*\w[\w:<>, ]*\s*=\s*"
    r"[\w:.]*(builder|new|default|client|connect|config)\s*\([^;]*\)[?;.]?\s*$"
    r"|^\s*let\s+\w+\s*=\s*self\.\w+\(\)\??;\s*$"
    r"|^\s*(let|const)\s+\w+\s*=\s*async\s*[{|]"
)

# How far apart a fetch and an authority use may sit and still be the same thought. Tuned
# against dstack and the fixtures: the clean tree stays silent and the vulnerable tree still
# fires at 25, and the six dstack false positives were all hundreds of lines apart.
PROXIMITY_LINES = 25

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
# finding, while the cost of rejecting a real one is flagging correctly-written code, and
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


def _colocated_anchor(text: str) -> int | None:
    """The line of a fetch that has an authority use within PROXIMITY_LINES of it.

    Returns the 1-indexed line to anchor the finding on, or None when no fetch in this file
    is near anything that carries authority. Binding-only lines are skipped as anchors: they
    are where the client was made, not where the response was trusted.
    """
    lines = text.splitlines()
    authority = [i for i, ln in enumerate(lines) if AUTHORITY_USE.search(ln)]
    if not authority:
        return None
    for i, ln in enumerate(lines):
        if not RELAYED_SOURCE.search(ln):
            continue
        if BINDING_ONLY.match(ln):
            continue
        if any(abs(a - i) <= PROXIMITY_LINES for a in authority):
            return i + 1
    return None


# A payload that carries its own binding does not need the transport to provide freshness.
# An attestation quote echoes the caller's report_data and is signed over it, so replaying
# an old one fails at verification rather than at the socket. dstack's tdx-attest writes a
# QGS request and reads the quote back; the rule reported the read as having no replay
# protection, and dstack's replay protection is in the quote.
SELF_BINDING_PAYLOAD = re.compile(
    r"(?i)\b(quote|attestation_?(doc|report)|report_?data|qgs|nsm_?(request|response))\b"
)


def _read_anchor(text: str) -> int | None:
    """Line of a message read that sits within PROXIMITY_LINES of a vsock surface."""
    lines = text.splitlines()
    surfaces = [i for i, ln in enumerate(lines) if VSOCK_SURFACE.search(ln)]
    if not surfaces:
        return None
    for i, ln in enumerate(lines):
        if not MESSAGE_READ.search(ln):
            continue
        if BINDING_ONLY.match(ln) or DEFINITION_SITE.match(ln):
            continue
        if any(abs(a - i) <= PROXIMITY_LINES for a in surfaces):
            return i + 1
    return None


def check_replay_protection(root: Path) -> list[Finding]:
    """BT-T07D: a vsock message handler whose schema carries no freshness token."""
    findings: list[Finding] = []
    for path, rel in _iter_code(root):
        raw = path.read_text(encoding="utf-8", errors="replace")
        live = strip_definitions(code_only(raw, path.suffix))
        # An import is not a listener: `use tokio_vsock::VsockAddr;` was enough to report a
        # file as relaying unauthenticated parent data. Trigger on the import-stripped view,
        # keep suppression on the fuller one.
        trigger = strip_imports(live)

        # Scope: this file must actually read messages off a vsock surface, and the read has
        # to be near the surface rather than merely in the same file.
        if not (VSOCK_SURFACE.search(trigger) and MESSAGE_READ.search(trigger)):
            continue
        if FRESHNESS_ENFORCED.search(live):
            continue
        if SELF_BINDING_PAYLOAD.search(live):
            continue

        # Anchor on the read, not the surface. The surface's first mention is typically a
        # struct field (`listener: vsock::VsockListener,`) or a connect call, and citing one
        # of those says the defect is the existence of vsock. The claim is about a message
        # arriving with nothing that makes it single-use, so the citation is the read.
        anchor = _read_anchor(trigger)
        if anchor is None:
            continue

        carries_token = bool(FRESHNESS.search(live))
        lines = raw.splitlines()
        line = anchor

        findings.append(
            Finding(
                rule_id="BT-T07D-no-replay-protection",
                file=rel,
                line=line,
                evidence=quote_line(lines, line),
                message=(
                    (
                        "Messages read off vsock carry a freshness field, but nothing in this "
                        "file consumes it, no seen-nonce set, no counter comparison, no "
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
                confidence=Confidence.LOW if carries_token else Confidence.LOW,
                detector="vsock.replay_protection",
                metadata={"carries_unused_freshness_field": carries_token},
            )
        )
    return findings


# Files that declare shapes rather than make decisions. An ABI entry naming an "oracle"
# field, or a generated type module, matched the authority vocabulary while containing no
# control flow at all.
DECLARATION_ONLY = re.compile(r"(?i)(^|/)(abi|abis|types?|generated|__generated__)(/|\.)")


def check_relayed_authority(root: Path) -> list[Finding]:
    """BT-T10: relayed data used for a decision without verifying its origin."""
    findings: list[Finding] = []
    for path, rel in _iter_code(root):
        if DECLARATION_ONLY.search(rel):
            continue
        raw = path.read_text(encoding="utf-8", errors="replace")
        live = strip_definitions(code_only(raw, path.suffix))
        # An import is not a listener: `use tokio_vsock::VsockAddr;` was enough to report a
        # file as relaying unauthenticated parent data. Trigger on the import-stripped view,
        # keep suppression on the fuller one.
        trigger = strip_imports(live)

        if PAYLOAD_VERIFIED.search(live):
            continue

        # Co-location, not co-occurrence. The old check asked whether a fetch and an
        # authority word both appeared anywhere in the file, which on a 900-line module is
        # barely a question. It has to be the same piece of code doing both.
        anchor = _colocated_anchor(trigger)
        if anchor is None:
            continue

        lines = raw.splitlines()
        line = anchor

        findings.append(
            Finding(
                rule_id="BT-T10-unauthenticated-parent-response",
                file=rel,
                line=line,
                evidence=quote_line(lines, line),
                message=(
                    "Data fetched from outside the enclave is consumed in a decision that "
                    "carries authority, with no signature check, attestation, or proof "
                    "verification anywhere in this file. Whoever controls the transport, a "
                    "parent-side proxy on Nitro, the network path on Confidential Space, "
                    "chooses what that response says. Without end-to-end authentication the "
                    "enclave is not deciding; it is relaying someone else's decision."
                ),
                severity=Severity.CRITICAL,
                # Deciding which relayed value carries authority is a judgment call, which is
                # why the catalog marks this hybrid: this is the prefilter, and the semantic
                # pass adjudicates.
                confidence=Confidence.MEDIUM,
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
