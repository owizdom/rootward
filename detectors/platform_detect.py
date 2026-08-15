"""Platform detection — is this repo Nitro Enclaves, dstack, both, or neither?

Without this, every dstack rule fires on every Nitro repo and vice versa, and a report full
of inapplicable findings is worse than no report: it trains the reader to skim. Detection is
evidence-based and reported alongside the result, so a reader can see *why* the tool decided
a repo was dstack and overrule it when the guess is wrong.

Deliberately conservative. When nothing indicates a TEE platform at all, that is itself
worth saying — auditing a repo that turns out not to use enclaves should produce "no TEE
platform detected", not a clean bill of health.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", "target", "venv", ".venv", "dist", "build", "__pycache__"}

NITRO_SIGNALS: list[tuple[str, re.Pattern]] = [
    ("nitro-cli invocation", re.compile(r"\bnitro-cli\b")),
    ("EIF reference", re.compile(r"(?i)\b(\.eif\b|enclave[_-]?image[_-]?file)")),
    ("NSM API", re.compile(r"(?i)\b(nsm_?api|/dev/nsm|nitro_enclaves_nsm)")),
    ("vsock/AF_VSOCK", re.compile(r"(?i)\b(AF_VSOCK|VsockStream|VsockListener|vsock_?proxy)")),
    ("KMS attestation condition", re.compile(r"kms:RecipientAttestation")),
    ("nitro enclaves SDK", re.compile(r"(?i)aws[-_]nitro[-_]enclaves")),
]

DSTACK_SIGNALS: list[tuple[str, re.Pattern]] = [
    ("dstack reference", re.compile(r"(?i)\bdstack[-_]?(kms|gateway|vmm|os)?\b")),
    ("app-compose manifest", re.compile(r"(?i)app[-_]compose\.(json|ya?ml)")),
    ("tappd socket", re.compile(r"(?i)\btappd\b")),
    ("governance contracts", re.compile(r"\b(KmsAuth|AppAuth)\b")),
    ("Phala cloud", re.compile(r"(?i)\bphala\b")),
    ("RTMR", re.compile(r"\bRTMR\d?\b")),
]

SCAN_SUFFIXES = {
    ".rs", ".go", ".py", ".ts", ".js", ".mjs", ".json", ".yaml", ".yml",
    ".toml", ".sh", ".bash", ".tf", ".md", ".txt", "",
}
SCAN_NAMES = {"Dockerfile", "Makefile", "docker-compose.yml", "docker-compose.yaml"}


@dataclass
class Platform:
    nitro: bool = False
    dstack: bool = False
    evidence: dict[str, list[str]] = field(default_factory=dict)
    """signal name -> up to a few 'file:line' locations that produced it."""

    @property
    def any(self) -> bool:
        return self.nitro or self.dstack

    def names(self) -> list[str]:
        out = []
        if self.nitro:
            out.append("nitro")
        if self.dstack:
            out.append("dstack")
        return out or ["none"]

    def summary(self) -> str:
        if not self.any:
            return "no TEE platform detected"
        return ", ".join(self.names())


def detect(root: Path, max_files: int = 4000) -> Platform:
    result = Platform()
    seen = 0

    for path in root.rglob("*"):
        if seen >= max_files:
            break
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix not in SCAN_SUFFIXES and path.name not in SCAN_NAMES:
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        seen += 1

        rel = str(path.relative_to(root))
        for label, pattern in NITRO_SIGNALS:
            m = pattern.search(text)
            if m:
                result.nitro = True
                _record(result, label, text, m, rel)
        for label, pattern in DSTACK_SIGNALS:
            m = pattern.search(text)
            if m:
                result.dstack = True
                _record(result, label, text, m, rel)

    return result


def _record(result: Platform, label: str, text: str, match: re.Match, rel: str) -> None:
    locations = result.evidence.setdefault(label, [])
    if len(locations) >= 3:
        return
    line = text.count("\n", 0, match.start()) + 1
    locations.append(f"{rel}:{line}")
