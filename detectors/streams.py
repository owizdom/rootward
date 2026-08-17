"""BT-T03C — an output stream exposed across the enclave boundary by configuration.

BT-T03 catches a secret-named value passed to a log call. This catches the case with no
offending line at all: a relay or a config flag that exposes an entire stdout/stderr stream
to the host, so every future log statement inside the enclave becomes an egress channel no
matter what it prints.

The distinction is not academic. On dstack the tool found the right file — the guest agent's
container-log relay — and classified it as trusted-computing-base bloat, because the value
that leaks is never named in the code. zkSecurity called the same code an unrestricted
stdout/stderr exposure. Same surface, and only one of those framings tells a reader what to
fix.
"""

from __future__ import annotations

import re
from pathlib import Path

from model import Confidence, Finding, Severity, code_only, quote_line, read_lines

SKIP_DIRS = {".git", "node_modules", "target", "venv", ".venv", "dist", "build", "__pycache__"}
TEXTY = {".rs", ".go", ".py", ".ts", ".js", ".mjs", ".json", ".yaml", ".yml", ".toml"}

TEST_PATH = re.compile(
    r"(?i)(^|/)(tests?|__tests?__|spec|specs|testdata|fixtures?|examples?|benches)(/|$)"
)

# A relay that hands a whole stream to a caller. Reading logs *within* the enclave is fine;
# serving them out of it is the finding.
LOG_RELAY = re.compile(
    r"(?i)\b("
    r"logs?_?(stream|relay|endpoint|handler|route)|"
    r"container_?logs?|docker_?logs?|"
    r"attach_?(stdout|stderr)|follow_?logs?|"
    r"journalctl|docker\.logs|bollard|"
    r"tail_?logs?|stream_?logs?"
    r")\b"
)

# Configuration that publishes them outright.
PUBLIC_FLAG = re.compile(
    r"(?i)(\"|')?\b(public_?logs?|logs?_?public|expose_?logs?|public_?sysinfo)\b(\"|')?"
    r"\s*[:=]\s*(true|1|yes|on)"
)

# The stream itself being wired somewhere it can leave.
STREAM_WIRED = re.compile(
    r"(?i)\b("
    r"stdout|stderr|Stdio::inherit|subprocess\.PIPE|"
    r"CombinedOutput|StdoutPipe|StderrPipe"
    r")\b"
)

# Anything suggesting the endpoint is not simply open.
GATED = re.compile(
    r"(?i)\b("
    r"require_?auth|authenticate|authoriz\w*|bearer|api_?key|"
    r"attestation_?required|verify_?token|check_?permission|"
    r"is_?admin|admin_?only|localhost_?only|internal_?only"
    r")\b"
)


def _iter_text(root: Path):
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in TEXTY:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        rel = str(path.relative_to(root))
        if TEST_PATH.search(rel):
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
            yield path, rel, path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue


def _line_of(text: str, pattern: re.Pattern) -> int:
    m = pattern.search(text)
    return text.count("\n", 0, m.start()) + 1 if m else 0


def run(root: Path) -> list[Finding]:
    findings: list[Finding] = []

    for path, rel, raw in _iter_text(root):
        live = code_only(raw, path.suffix) if path.suffix in {
            ".rs", ".go", ".py", ".ts", ".js", ".mjs", ".yaml", ".yml", ".toml"
        } else raw

        flag = PUBLIC_FLAG.search(live)
        relay = LOG_RELAY.search(live) and STREAM_WIRED.search(live)

        if not (flag or relay):
            continue
        # A gated endpoint is a different risk profile; the handbook's concern is the
        # unrestricted case, and reporting an authenticated one trains readers to skim.
        if not flag and GATED.search(live):
            continue

        lines = raw.splitlines()
        line = _line_of(raw, PUBLIC_FLAG if flag else LOG_RELAY)

        findings.append(
            Finding(
                rule_id="BT-T03C-stream-exposure",
                file=rel,
                line=line,
                evidence=quote_line(lines, line),
                message=(
                    (
                        "Configuration publishes an output stream outright. "
                        if flag
                        else "An output stream is relayed out of the enclave with no "
                        "authentication or attestation gate on the path. "
                    )
                    + "Unlike a single leaked value, this exposes every future log statement "
                    "inside the boundary — the defect is the channel, not the line, so no "
                    "amount of care about what individual statements print will close it. "
                    "Anything written to stdout or stderr from here should be treated as "
                    "public."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM if flag else Confidence.LOW,
                detector="streams.stream_exposure",
                metadata={"explicit_public_flag": bool(flag)},
            )
        )

    return findings


if __name__ == "__main__":
    import sys

    from model import to_json

    target = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    print(to_json(run(target), root=str(target)))
