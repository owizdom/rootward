"""OS image and firmware build rules. BT-OS01 (guest firmware built without the TDX
target), BT-OS02 (secure boot off by default), BT-OS03 (development image features in a
production TEE image).

The rule class this catalog did not have, and the reason `meta-dstack` returned one finding
against zkSecurity's five, including the only High in their report. Everything else here
audits what an application does; this audits what the machine it runs on was built from.

Why that is a different question. A TEE's guarantee is a chain: hardware measures firmware,
firmware measures the kernel, the kernel measures the workload. Every rule elsewhere in this
catalog starts at the last link. If the firmware was built with the wrong target, or secure
boot was never enabled, or the image ships a debug shell, the application code can be
flawless and the chain still does not hold, and none of the application-level rules can see
it, because the defect is in a BitBake recipe.

Scoped narrowly on purpose. These fire only on files that are recognisably an OS or firmware
build (BitBake recipes, Yocto configuration, EDK II build invocations), which is a small and
well-signposted set. A repository that does not build an image never reaches them.
"""

from __future__ import annotations

import re
from pathlib import Path

from model import Confidence, Finding, Severity, code_only, quote_line, read_lines
from platform_detect import Platform

SKIP_DIRS = {".git", "node_modules", "target", "venv", ".venv", "dist", "build", "__pycache__"}

# The files that describe how an image is built. `.bb`/`.bbappend`/`.inc` are BitBake
# recipes; `.conf` covers Yocto distro and local configuration.
RECIPE_SUFFIXES = {".bb", ".bbappend", ".inc", ".conf"}
RECIPE_NAMES = {"local.conf", "layer.conf", "Makefile"}

# --- BT-OS01: which firmware target -------------------------------------------------

# An EDK II / OVMF build of any kind.
FIRMWARE_BUILD = re.compile(r"(?i)(OvmfPkg|edk2|\bOVMF\b|\.dsc\b)")

# Config-B: the Intel TDX firmware target, which keeps the VMM outside the TCB.
TDX_FIRMWARE_TARGET = re.compile(r"(?i)(IntelTdx(Pkg|X64)|IntelTdx\w*\.dsc|-p\s+IntelTdx)")

# Config-A: the general-purpose OVMF build.
GENERIC_FIRMWARE_TARGET = re.compile(
    r"(?i)(OvmfPkg/build\.sh|OvmfPkgX64\.dsc|OvmfPkgIa32X64\.dsc|-p\s+OvmfPkg)"
)

# Evidence the project is a TDX guest at all, so the target choice matters.
TDX_CONTEXT = re.compile(r"(?i)(\btdx\b|\bRTMR\d?\b|tdx[-_]guest|dstack|confidential)")

# --- BT-OS02: secure boot ------------------------------------------------------------

SECUREBOOT_OPTION = re.compile(r"(?i)PACKAGECONFIG\[secureboot\]|SECURE_BOOT_ENABLE")
# `PACKAGECONFIG ??= ""` is the weak default: the option exists and is not taken.
#
# [ \t] and not \s throughout, for the reason spelled out at the invocation filter below:
# `\s` matches a newline, so `^\s*` starts the match at the top of whatever blank-and-
# comment run precedes the offending line -- `code_only` blanks comments but keeps the
# lines, so a rule with a two-line comment above it reported the comment's line number and
# quoted an empty string as its evidence. Two of the three rules here did exactly that the
# first time they fired on a tree that had comments in it.
SECUREBOOT_DEFAULT_OFF = re.compile(r'(?m)^[ \t]*PACKAGECONFIG[ \t]*\?\?=[ \t]*""[ \t]*$')
# What counts as "and it is taken". Only two things do: secureboot named in the value of a
# PACKAGECONFIG assignment, or in MACHINE_FEATURES.
#
# `SECURE_BOOT_ENABLE=TRUE` appearing anywhere used to count too, and that was a false
# negative on the one repository this rule exists for. meta-dstack defines
# `OVMF_SECURE_BOOT_FLAGS = "-DSECURE_BOOT_ENABLE=TRUE"` at line 67 and passes it only on a
# second build guarded by `contains('PACKAGECONFIG', 'secureboot', ...)` -- which line 12's
# `PACKAGECONFIG ??= ""` does not satisfy. The recipe says so itself at line 206:
# `bbnote "Building without Secure Boot."`. Defining the flag is not passing it, the same
# distinction the invocation filter draws for BT-OS01.
#
# `(?::append|_append)?` and not a general suffix: `PACKAGECONFIG[secureboot] = ",,,"` is the
# option's *declaration*, and accepting it here would suppress the rule on every recipe that
# offers secure boot, which is every recipe the rule can fire on.
SECUREBOOT_ENABLED = re.compile(
    r"(?i)(PACKAGECONFIG(?::append|_append)?[ \t]*[?+:]*=[ \t]*[\"'][^\"']*secureboot"
    r"|MACHINE_FEATURES[^\n]*secureboot)"
)

# --- BT-OS03: development features in a production image -----------------------------

DEV_IMAGE_FEATURE = re.compile(
    r"(?im)^[ \t]*EXTRA_IMAGE_FEATURES[ \t]*[?+:]*=[ \t]*[\"'][^\"']*"
    r"(debug-tweaks|allow-empty-password|allow-root-login|empty-root-password|tools-debug)"
)
DEBUG_CMDLINE = re.compile(
    r"(?i)(APPEND[^\n]*\b(init=/bin/(sh|bash)|single|nokaslr|noapic)\b"
    r"|CMDLINE[^\n]*\b(init=/bin/(sh|bash)|nokaslr)\b)"
)


def _iter_recipes(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix not in RECIPE_SUFFIXES and path.name not in RECIPE_NAMES:
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # BitBake uses `#` comments, same as shell.
        yield path, code_only(raw, ".sh")


def _line(text: str, pattern: re.Pattern) -> int:
    m = pattern.search(text)
    return text.count("\n", 0, m.start()) + 1 if m else 1


def check_firmware_target(root: Path) -> list[Finding]:
    """BT-OS01: a TDX guest whose firmware is built from the general-purpose OVMF target.

    zkSecurity's only High on dstack. `OvmfPkg/build.sh` produces Config-A firmware, which
    leaves the virtual machine monitor inside the trusted computing base, so the host that
    the entire threat model treats as adversarial is, at the firmware level, trusted. The
    fix is a different build target, and nothing above the firmware layer can compensate.
    """
    out: list[Finding] = []
    tdx_project = False
    candidates: list[tuple[Path, str]] = []

    for path, code in _iter_recipes(root):
        if TDX_CONTEXT.search(code):
            tdx_project = True
        if FIRMWARE_BUILD.search(code):
            candidates.append((path, code))

    if not tdx_project:
        return out

    for path, code in candidates:
        if TDX_FIRMWARE_TARGET.search(code):
            continue
        # Prefer the line that actually invokes the build over one that merely names the
        # path -- the recipe rewrites `OvmfPkg/build.sh` in a sed long before it runs it,
        # and pointing a reader at the sed makes the finding look wrong.
        invocations = [
            mm for mm in GENERIC_FIRMWARE_TARGET.finditer(code)
            # [ \t] not \s: \s matches a newline, so `build.sh` at the end of a sed
            # followed by `}` on the next line looked like an invocation with an argument.
            if re.search(r"build\.sh[ \t]+\S|-p[ \t]+OvmfPkg|\.dsc\b",
                         code[mm.start(): mm.start() + 80])
        ]
        m = invocations[0] if invocations else GENERIC_FIRMWARE_TARGET.search(code)
        if not m:
            continue
        rel = str(path.relative_to(root))
        line = code.count("\n", 0, m.start()) + 1
        out.append(
            Finding(
                rule_id="BT-OS01-firmware-not-tdx-target",
                file=rel,
                line=line,
                evidence=quote_line(read_lines(path), line),
                message=(
                    "Guest firmware for a TDX project is built from the general-purpose OVMF "
                    "target rather than the Intel TDX one. That is EDK II's Config-A, which "
                    "leaves the virtual machine monitor inside the trusted computing base, "
                    "so the host this threat model treats as adversarial is trusted by the "
                    "firmware the enclave boots from. No application-level control "
                    "compensates for it, and no measurement above this layer detects it. "
                    "Build the IntelTdx target instead."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                detector="detectors:osimage.check_firmware_target",
            )
        )
    return out


def check_secure_boot(root: Path) -> list[Finding]:
    """BT-OS02: the firmware recipe offers secure boot and does not take it."""
    out: list[Finding] = []
    for path, code in _iter_recipes(root):
        if not SECUREBOOT_OPTION.search(code):
            continue
        if SECUREBOOT_ENABLED.search(code):
            continue
        if not SECUREBOOT_DEFAULT_OFF.search(code):
            continue
        rel = str(path.relative_to(root))
        line = _line(code, SECUREBOOT_DEFAULT_OFF)
        out.append(
            Finding(
                rule_id="BT-OS02-secure-boot-not-enabled",
                file=rel,
                line=line,
                evidence=quote_line(read_lines(path), line),
                message=(
                    "The firmware recipe defines a secure-boot option and leaves it out of "
                    "the default configuration. Without it the firmware will load an unsigned "
                    "bootloader, so the measured-boot chain starts from something the host "
                    "can replace, which is the assumption every later measurement depends "
                    "on. Enable it in PACKAGECONFIG, or state in the deployment "
                    "documentation which layer is expected to provide the equivalent."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                detector="detectors:osimage.check_secure_boot",
            )
        )
    return out


DEV_NAMED = re.compile(r"(?i)(^|[-_/])dev([-_.]|$)")
INCLUDE = re.compile(r"(?m)^\s*(?:include|require)\s+(\S+)")


def _reachable_from_production(root: Path, target: Path, recipes: dict[str, tuple[Path, str]]) -> bool:
    """Is this recipe pulled in by an image that is not itself a development image?

    A file named `dstack-rootfs-dev.inc` is allowed to contain debug-tweaks; that is what it
    is for. The finding is the same feature reaching production. Walking `include`/`require`
    upward answers which one this is, and without it the rule reports every development
    image in every Yocto layer -- which is how a rule teaches people to ignore it.
    """
    name = target.name
    includers = [
        (p, c) for p, c in recipes.values()
        if any(Path(inc).name == name for inc in INCLUDE.findall(c))
    ]
    if not includers:
        # Nothing includes it: judge it on its own name.
        return not DEV_NAMED.search(target.stem)
    seen: set[str] = set()
    frontier = list(includers)
    while frontier:
        p, c = frontier.pop()
        if str(p) in seen:
            continue
        seen.add(str(p))
        if DEV_NAMED.search(p.stem):
            continue  # a development image including it is expected
        parents = [
            (pp, cc) for pp, cc in recipes.values()
            if any(Path(inc).name == p.name for inc in INCLUDE.findall(cc))
        ]
        if not parents:
            return True  # a non-dev image at the top of the chain
        frontier.extend(parents)
    return False


def check_dev_image_features(root: Path) -> list[Finding]:
    """BT-OS03: development conveniences reaching a production TEE image."""
    out: list[Finding] = []
    recipes = {str(p): (p, c) for p, c in _iter_recipes(root)}
    for path, code in _iter_recipes(root):
        for pattern, what in ((DEV_IMAGE_FEATURE, "image feature"), (DEBUG_CMDLINE, "kernel command line")):
            m = pattern.search(code)
            if not m:
                continue
            if not _reachable_from_production(root, path, recipes):
                continue
            rel = str(path.relative_to(root))
            line = code.count("\n", 0, m.start()) + 1
            out.append(
                Finding(
                    rule_id="BT-OS03-development-image-features",
                    file=rel,
                    line=line,
                    evidence=quote_line(read_lines(path), line),
                    message=(
                        f"A development convenience is compiled into the image through the "
                        f"{what}. debug-tweaks, an empty root password, or a shell on the "
                        "kernel command line each hand interactive access to whoever can "
                        "reach the guest console, and the operator can always reach it. "
                        "These belong in a development image only, and the measurement will "
                        "not tell them apart from the production one unless you compare it "
                        "against a known-good value."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    detector="detectors:osimage.check_dev_image_features",
                )
            )
    return out


def run(root: Path, platform: Platform | None = None) -> list[Finding]:
    """Runs everywhere. An OS image build is its own signal, a repository that does not
    contain one never matches, so there is nothing to gate on."""
    return [
        *check_firmware_target(root),
        *check_secure_boot(root),
        *check_dev_image_features(root),
    ]


if __name__ == "__main__":
    import sys

    import platform_detect
    from model import to_json

    target = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    p = platform_detect.detect(target)
    print(to_json(run(target, p), root=str(target), platform=p.summary()))
