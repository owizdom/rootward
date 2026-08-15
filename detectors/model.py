"""Shared finding model.

Every detector — semgrep, the Rust core, and the Python analyzers — normalises into this
one shape, so the report renderer and the adversarial verifier have a single contract to
work against.

The evidence field is not optional and not decorative. A finding without a quoted line of
source is an assertion, and this tool exists because unverified assertions are what get TEE
protocols rekt. The one exception is a finding whose evidence is structural (a PCR digest
pair, an absent condition key); those set `evidence` to the structural fact itself.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Iterable


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[self.value]


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Verdict(str, Enum):
    """Set by the adversarial pass in verify/. Deterministic detector hits are CONFIRMED
    on arrival — their evidence is a literal pattern match, and there is nothing for a
    model to adjudicate."""

    CONFIRMED = "confirmed"
    PLAUSIBLE = "plausible"
    REFUTED = "refuted"
    UNVERIFIED = "unverified"


@dataclass
class Finding:
    rule_id: str
    """Catalog id, e.g. BT-T07C-timing-oracle-compare. Must exist in catalog/rules/."""

    file: str
    """Path relative to the audit root."""

    line: int
    """1-indexed. 0 means the finding is about the file as a whole."""

    evidence: str
    """Quoted source, or the structural fact for findings with no single line."""

    message: str
    severity: Severity
    confidence: Confidence
    detector: str
    """Which detector produced this, e.g. semgrep:tee-timing-oracle-compare-rust."""

    verdict: Verdict = Verdict.UNVERIFIED
    refutation: str | None = None
    """Why the adversarial pass could not confirm it, when it could not."""

    metadata: dict = field(default_factory=dict)

    def key(self) -> tuple:
        """Dedup key. Two detectors finding the same defect on the same line is one
        finding, not two — semgrep and a Python analyzer overlap on several rules."""
        return (self.rule_id, self.file, self.line)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        d["verdict"] = self.verdict.value
        return d


def dedupe(findings: Iterable[Finding]) -> list[Finding]:
    """Collapse duplicates, keeping the highest-confidence instance of each.

    Order matters for the report, so this is stable: ties keep first-seen order.
    """
    best: dict[tuple, Finding] = {}
    order: list[tuple] = []
    ranks = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}
    for f in findings:
        k = f.key()
        if k not in best:
            best[k] = f
            order.append(k)
        elif ranks[f.confidence] < ranks[best[k].confidence]:
            best[k] = f
    return [best[k] for k in order]


def sort_for_report(findings: Iterable[Finding]) -> list[Finding]:
    """Severity first, then confidence, then location — so the reader hits the thing that
    matters most before anything else."""
    ranks = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}
    return sorted(
        findings,
        key=lambda f: (f.severity.rank, ranks[f.confidence], f.file, f.line),
    )


def to_json(findings: Iterable[Finding], **extra) -> str:
    return json.dumps({"findings": [f.to_dict() for f in findings], **extra}, indent=2)


def read_lines(path: Path) -> list[str]:
    """Read a file for evidence extraction, tolerating the encoding zoo found in
    vendored dependencies and build artifacts."""
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, UnicodeDecodeError):
        return []


_LINE_COMMENT = {
    ".py": "#", ".sh": "#", ".bash": "#", ".yaml": "#", ".yml": "#", ".toml": "#",
    ".rs": "//", ".go": "//", ".ts": "//", ".js": "//", ".mjs": "//", ".sol": "//",
}


def code_only(text: str, suffix: str) -> str:
    """Strip comments so absence checks cannot be satisfied by prose.

    This exists because the mutation benchmark caught the detectors reading
    ``# Walk the cabundle to the pinned AWS Nitro root`` as evidence that the cabundle was
    walked. Every "is the safeguard present?" rule has that hole: a comment describing
    security is not security, and comments describing what code *used to* do outlive the
    code constantly.

    Blank lines are preserved so line numbers stay correct for evidence quoting — a
    detector that reports the wrong line is worse than one that reports nothing.
    """
    marker = _LINE_COMMENT.get(suffix)
    out: list[str] = []
    in_block = False

    for line in text.splitlines():
        stripped = line

        if marker == "//":
            # Block comments, tracked across lines.
            if in_block:
                end = stripped.find("*/")
                if end == -1:
                    out.append("")
                    continue
                stripped = stripped[end + 2 :]
                in_block = False
            while "/*" in stripped:
                start = stripped.find("/*")
                end = stripped.find("*/", start + 2)
                if end == -1:
                    stripped = stripped[:start]
                    in_block = True
                    break
                stripped = stripped[:start] + stripped[end + 2 :]

        if marker:
            idx = 0
            while True:
                idx = stripped.find(marker, idx)
                if idx == -1:
                    break
                # Don't cut a URL scheme ("https://") or a string quote boundary.
                if marker == "//" and idx > 0 and stripped[idx - 1] == ":":
                    idx += 2
                    continue
                before = stripped[:idx]
                # Crude but effective: an odd number of quotes means we are inside a
                # string literal, so this marker is content rather than a comment.
                if before.count('"') % 2 == 1 or before.count("'") % 2 == 1:
                    idx += len(marker)
                    continue
                stripped = before
                break

        out.append(stripped)

    return "\n".join(out)


# Definition sites, which are not evidence that the thing is ever called.
DEFINITION_SITE = re.compile(r"^\s*(?:async\s+)?(?:def|fn|func|function|pub\s+fn)\s+\w+")


def strip_definitions(text: str) -> str:
    """Blank out function *definition* lines.

    Companion to `code_only`, for the same reason: the benchmark showed a dead
    ``def verify_cert_chain(chain, root)`` counting as proof that chain validation happens,
    when the only call to it had been deleted. Keeping the line as blank preserves numbering.
    """
    return "\n".join(
        "" if DEFINITION_SITE.match(line) else line for line in text.splitlines()
    )


def quote_line(lines: list[str], line_no: int, limit: int = 200) -> str:
    """One line of evidence, trimmed. Truncated rather than omitted: a minified bundle
    should still show *something* at the match site."""
    if not (1 <= line_no <= len(lines)):
        return ""
    text = lines[line_no - 1].strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"
