"""Build and launch configuration — BT-CFG01 (debug mode), BT-CFG04 (build determinism),
BT-T09B (secrets in the Dockerfile).

BT-CFG01 is the highest value-per-line check in the whole tool. A debug-mode enclave
reports PCRs that are entirely zeros, and the handbook states plainly that those
attestation documents cannot be used for cryptographic attestation. So a single
`--debug-mode` on a production launch path silently disables the guarantee the entire
architecture rests on, with no error at runtime and no visible symptom. It is one flag, in
one shell script, and it is findable with a regex.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from model import Confidence, Finding, Severity, quote_line, read_lines

SKIP_DIRS = {".git", "node_modules", "target", "venv", ".venv", "dist", "build", "__pycache__"}

# Paths that look like local development rather than deployment. Debug mode there is
# expected, so the finding is downgraded rather than dropped — "it's only in a dev script"
# is exactly what someone says about the script that turns out to be wired into CI.
DEV_HINTS = re.compile(r"(?i)(^|/)(test|tests|dev|devel|local|example|examples|sample|samples|fixture)s?(/|$|[._-])")

DEBUG_MODE = re.compile(r"--debug-mode\b")
RUN_ENCLAVE = re.compile(r"\bnitro-cli\s+run-enclave\b")

# Floating references make a build unreproducible, so a third party cannot rebuild the
# image and confirm it measures to the published PCR0 (BT-CFG04).
FROM_LINE = re.compile(r"(?i)^\s*FROM\s+(?P<ref>\S+)")
PINNED_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}")
FLOATING_TAG = re.compile(r"(?i):(latest|main|master|edge|stable|nightly)\s*$|^[^:@]+$")

PKG_INSTALL = re.compile(r"(?i)\b(apt-get|apt|apk|yum|dnf|pip3?)\s+(install|add)\b")

# Package managers disagree about how a version is pinned:
#   apt/apk   pkg=1.2.3
#   pip       pkg==1.2.3
#   yum/dnf   pkg-1.2.3          <- hyphen, which is also how package names are spelled
# so "contains =" alone under-detects and flags correctly pinned yum installs.
PINNED_PKG = re.compile(r"^[A-Za-z0-9._+-]+(==?|-)\d[\w.+-]*$")


def _install_targets(line: str) -> list[str]:
    """Package arguments on an install line, with flags and shell noise removed."""
    after = PKG_INSTALL.split(line, maxsplit=1)
    if len(after) < 4:
        return []
    tokens = after[-1].replace("&&", " ").replace("\\", " ").split()
    out = []
    for tok in tokens:
        if tok.startswith("-"):
            continue
        # Stop at a shell operator; anything past it is a different command.
        if tok in {";", "|", "&"}:
            break
        out.append(tok)
    return out


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _is_dev_path(rel: str) -> bool:
    return bool(DEV_HINTS.search(rel))


def _walk(root: Path, patterns: list[str]):
    for pat in patterns:
        for path in root.rglob(pat):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if path.is_file():
                yield path


def check_debug_mode(root: Path) -> list[Finding]:
    """BT-CFG01 — enclave launched with attestation disabled."""
    findings: list[Finding] = []
    targets = ["*.sh", "*.bash", "Makefile", "*.mk", "*.yml", "*.yaml", "*.tf", "*.py", "*.js", "*.ts"]

    for path in _walk(root, targets):
        lines = read_lines(path)
        rel = _rel(path, root)
        dev = _is_dev_path(rel)

        for i, line in enumerate(lines, start=1):
            if not DEBUG_MODE.search(line):
                continue
            # Only meaningful on a launch; --debug-mode elsewhere is noise.
            context = "\n".join(lines[max(0, i - 4) : i + 2])
            if not RUN_ENCLAVE.search(context) and "enclave" not in context.lower():
                continue

            findings.append(
                Finding(
                    rule_id="BT-CFG01-debug-mode-launch",
                    file=rel,
                    line=i,
                    evidence=quote_line(lines, i),
                    message=(
                        "Enclave launched with --debug-mode. Debug enclaves emit "
                        "attestation documents whose PCRs are entirely zeros, which cannot "
                        "be used for cryptographic attestation, and expose the enclave "
                        "console to the parent."
                        + (
                            " Path looks development-only, so this may be intended — "
                            "confirm it is not reachable from a deployment path."
                            if dev
                            else ""
                        )
                    ),
                    severity=Severity.MEDIUM if dev else Severity.CRITICAL,
                    confidence=Confidence.MEDIUM if dev else Confidence.HIGH,
                    detector="buildconfig.debug_mode",
                    metadata={"dev_path": dev},
                )
            )
    return findings


def check_build_determinism(root: Path) -> list[Finding]:
    """BT-CFG04 — image cannot be independently rebuilt to the same PCR0."""
    findings: list[Finding] = []

    for path in _walk(root, ["Dockerfile", "Dockerfile.*", "*.dockerfile"]):
        lines = read_lines(path)
        rel = _rel(path, root)

        for i, line in enumerate(lines, start=1):
            m = FROM_LINE.match(line)
            if m:
                ref = m.group("ref")
                if not PINNED_DIGEST.search(ref) and FLOATING_TAG.search(ref):
                    findings.append(
                        Finding(
                            rule_id="BT-CFG04-nondeterministic-build",
                            file=rel,
                            line=i,
                            evidence=quote_line(lines, i),
                            message=(
                                f"Base image '{ref}' is referenced by a floating tag rather "
                                "than a digest. The image cannot be rebuilt reproducibly, so "
                                "nobody can independently confirm that the published PCR0 "
                                "corresponds to the published source. Pin with @sha256:."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            detector="buildconfig.build_determinism",
                        )
                    )
                continue

            if PKG_INSTALL.search(line):
                targets = _install_targets(line)
                unpinned = [t for t in targets if not PINNED_PKG.match(t)]
                if targets and unpinned:
                    findings.append(
                        Finding(
                            rule_id="BT-CFG04-nondeterministic-build",
                            file=rel,
                            line=i,
                            evidence=quote_line(lines, i),
                            message=(
                                f"Package install without pinned versions ({', '.join(unpinned[:5])}). "
                                "Two builds of the same source will measure differently, which "
                                "breaks independent verification of PCR values."
                            ),
                            severity=Severity.LOW,
                            confidence=Confidence.MEDIUM,
                            detector="buildconfig.build_determinism",
                            metadata={"unpinned": unpinned},
                        )
                    )

    return findings


def check_dockerfile_secrets(root: Path, core_bin: Path | None = None) -> list[Finding]:
    """BT-T09B — secrets introduced via ENV, ARG, or a copied build context.

    Delegates the actual matching to the Rust core so build-context scanning and ramdisk
    scanning use one implementation, and so a Dockerfile secret and the same secret found
    later inside the EIF are classified identically.
    """
    findings: list[Finding] = []
    if core_bin is None or not core_bin.exists():
        return findings

    targets = list(_walk(root, ["Dockerfile", "Dockerfile.*", "*.dockerfile", ".env", ".env.*", "*.env"]))
    if not targets:
        return findings

    try:
        proc = subprocess.run(
            [str(core_bin), "scan", *[str(p) for p in targets]],
            capture_output=True,
            text=True,
            timeout=120,
        )
        import json

        payload = json.loads(proc.stdout or "{}")
    except (OSError, subprocess.SubprocessError, ValueError):
        return findings

    for raw in payload.get("findings", []):
        path = Path(raw["path"])
        rel = _rel(path, root)
        lines = read_lines(path)
        findings.append(
            Finding(
                rule_id="BT-T09B-dockerfile-secret",
                file=rel,
                line=raw["line"],
                # The core never returns the secret, only its digest — so evidence here is
                # the line with the value elided, not the raw source.
                evidence=f"{raw['kind']} (sha256:{raw['digest']}, {raw['value_len']} chars, entropy {raw['entropy']:.2f})",
                message=(
                    "Secret material in the build context. A build ARG persists in image "
                    "history, an ENV persists in the running filesystem, and a copied .env "
                    "lands in the ramdisk verbatim — where anyone with access to the parent "
                    "can extract it from the EIF. Provision secrets at runtime after "
                    "attestation instead."
                ),
                severity=Severity.INFO if raw.get("known_test_vector") else Severity.CRITICAL,
                confidence=Confidence.HIGH,
                detector="buildconfig.dockerfile_secrets",
                metadata={"kind": raw["kind"], "digest": raw["digest"]},
            )
        )
        _ = lines
    return findings


def run(root: Path, core_bin: Path | None = None) -> list[Finding]:
    return [
        *check_debug_mode(root),
        *check_build_determinism(root),
        *check_dockerfile_secrets(root, core_bin),
    ]


if __name__ == "__main__":
    import sys

    from model import to_json

    target = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    core = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    print(to_json(run(target, core), root=str(target)))
