#!/usr/bin/env python3
"""tee-audit — static auditor for Web3 protocols on cloud TEEs.

    python3 cli/audit.py <path> [--format md|json] [--semgrep <bin>]

Order of operations matters. Platform detection runs first so platform-specific rules are
gated rather than fired blindly; deterministic detectors run next because they are cheap
and precise; and the report is assembled last so that what was *not* checked can be
computed from what was.

The three report sections are deliberate:

  1. Layer scorecard   where the protocol actually sits on the handbook's 0-6 ladder
  2. Findings          ranked, each with file:line evidence
  3. NOT VERIFIED      what this audit structurally could not check

Section 3 is not a disclaimer. Static analysis cannot see the KMS policy deployed in AWS,
the PCRs a running enclave reports, or whether --debug-mode was used on the real launch. A
report that omits that reads as a clean bill of health, which is a worse outcome than no
report at all.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "detectors"))

import attestation  # noqa: E402
import buildconfig  # noqa: E402
import confspace as confspace_rules  # noqa: E402
import dstack as dstack_rules  # noqa: E402
import eigencompute as eigencompute_rules  # noqa: E402
import kms_policy  # noqa: E402
import platform_detect  # noqa: E402
import streams as stream_rules  # noqa: E402
import vsock as vsock_rules  # noqa: E402
from model import (  # noqa: E402
    Confidence,
    Finding,
    Severity,
    Verdict,
    dedupe,
    sort_for_report,
)

SEMGREP_RULES = ROOT / "detectors" / "semgrep" / "tee"
CORE_BIN_CANDIDATES = [
    ROOT / "core" / "target" / "release" / "tee-audit-core",
    ROOT / "core" / "target" / "debug" / "tee-audit-core",
]

def _source_line(path: Path, line_no: int) -> str:
    """One line of source for evidence."""
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh, start=1):
                if i == line_no:
                    return line.strip()
    except OSError:
        pass
    return ""


SEVERITY_MAP = {
    "ERROR": Severity.CRITICAL,
    "WARNING": Severity.HIGH,
    "INFO": Severity.MEDIUM,
}
CONFIDENCE_MAP = {"HIGH": Confidence.HIGH, "MEDIUM": Confidence.MEDIUM, "LOW": Confidence.LOW}


# ---------------------------------------------------------------- catalog ---
def load_catalog() -> dict[str, dict]:
    import yaml

    out = {}
    for path in sorted((ROOT / "catalog" / "rules").glob("*.yaml")):
        rule = yaml.safe_load(path.read_text())
        out[rule["id"]] = rule
    return out


def find_core() -> Path | None:
    for c in CORE_BIN_CANDIDATES:
        if c.exists():
            return c
    return None


# --------------------------------------------------------------- semgrep ---
def run_semgrep(root: Path, semgrep_bin: str) -> tuple[list[Finding], list[str]]:
    """Returns (findings, warnings). A semgrep failure degrades the audit rather than
    aborting it — a partial audit that says which part is missing beats no audit."""
    if not shutil.which(semgrep_bin):
        return [], [f"semgrep not found ({semgrep_bin}); code-pattern rules did not run"]

    try:
        proc = subprocess.run(
            [semgrep_bin, "--config", str(SEMGREP_RULES), "--json",
             "--metrics=off", "--quiet", "--no-git-ignore", str(root)],
            capture_output=True, text=True, timeout=900,
        )
        payload = json.loads(proc.stdout or "{}")
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        return [], [f"semgrep failed to run ({exc}); code-pattern rules did not run"]

    findings, warnings = [], []
    for err in payload.get("errors", []):
        msg = err.get("long_msg") or err.get("message") or str(err)
        warnings.append(f"semgrep: {msg[:200]}")

    for r in payload.get("results", []):
        meta = r["extra"].get("metadata", {})
        cid = meta.get("catalog-id")
        if not cid:
            continue
        abs_path = Path(r["path"]).resolve()
        try:
            rel = str(abs_path.relative_to(root))
        except ValueError:
            rel = r["path"]

        # semgrep's extra.lines is "requires login" on the unauthenticated tier, so the
        # evidence is read from disk instead. Evidence is not optional in this tool — a
        # finding without the offending line is an assertion.
        evidence = (r["extra"].get("lines") or "").strip()
        if not evidence or evidence == "requires login":
            evidence = _source_line(abs_path, r["start"]["line"])

        findings.append(
            Finding(
                rule_id=cid,
                file=rel,
                line=r["start"]["line"],
                evidence=evidence[:200],
                message=" ".join((r["extra"].get("message") or "").split()),
                severity=SEVERITY_MAP.get(r["extra"].get("severity", "WARNING"), Severity.HIGH),
                confidence=CONFIDENCE_MAP.get(str(meta.get("confidence", "MEDIUM")).upper(), Confidence.MEDIUM),
                detector=f"semgrep:{r['check_id'].split('.')[-1]}",
                # A literal pattern match is its own evidence; there is nothing for the
                # adversarial pass to adjudicate.
                verdict=Verdict.CONFIRMED,
            )
        )
    return findings, warnings


# ------------------------------------------------------------- eif scan ---
def run_eif_scan(root: Path, core: Path | None) -> tuple[list[Finding], list[str], list[dict]]:
    findings: list[Finding] = []
    warnings: list[str] = []
    reports: list[dict] = []

    if core is None:
        return findings, ["core binary not built; EIF and ramdisk scanning did not run"], reports

    eifs = [p for p in root.rglob("*.eif") if ".git" not in p.parts]
    for eif in eifs:
        try:
            proc = subprocess.run(
                [str(core), "inspect", str(eif)],
                capture_output=True, text=True, timeout=600,
            )
            payload = json.loads(proc.stdout or "{}")
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            warnings.append(f"{eif.name}: core inspect failed ({exc})")
            continue

        if "error" in payload:
            warnings.append(f"{eif.name}: {payload['error']}")
            continue

        rel_eif = str(eif.relative_to(root))
        reports.append({"eif": rel_eif, **{k: payload[k] for k in
                        ("measurements", "signature_present", "ramdisk_entries") if k in payload}})
        for w in payload.get("warnings", []):
            warnings.append(f"{rel_eif}: {w}")

        for f in payload.get("findings", []):
            findings.append(
                Finding(
                    rule_id="BT-T09A-eif-embedded-secret",
                    file=f"{rel_eif}!{f['path']}",
                    line=f["line"],
                    evidence=(
                        f"{f['kind']} (sha256:{f['digest']}, {f['value_len']} chars, "
                        f"entropy {f['entropy']:.2f})"
                    ),
                    message=(
                        "Secret material recoverable from the EIF ramdisk. The image is a "
                        "build artifact on the parent's filesystem, and the parent is "
                        "hostile: anyone with EC2 access can copy the EIF, decompress the "
                        "cpio ramdisk, and read this. It was never protected by the enclave."
                    ),
                    severity=Severity.INFO if f.get("known_test_vector") else Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    detector="core:eif-secret-scan",
                    verdict=Verdict.CONFIRMED,
                    metadata={"kind": f["kind"], "digest": f["digest"]},
                )
            )
    return findings, warnings, reports


# --------------------------------------------------------- semantic scope ---
ENCLAVE_HINTS = re.compile(
    r"(?i)(enclave|vsock|attest|nsm|kms|tee|nitro|dstack|tappd|seal|secure|crypt)"
)
SCOPE_SUFFIXES = {".rs", ".go", ".py", ".ts", ".js", ".mjs", ".md"}


def semantic_scope(root: Path, findings: list[Finding], limit: int = 60) -> list[str]:
    """Files worth spending a model call on.

    Handing an agent a whole repository wastes context on vendored dependencies and lets it
    wander. The scope is: files the deterministic layer already flagged, plus files whose
    path suggests they sit on the enclave boundary, plus the README (which BT-LYR01 needs
    to compare claims against reality).
    """
    picked: list[str] = []
    seen: set[str] = set()

    def add(rel: str) -> None:
        if rel not in seen:
            seen.add(rel)
            picked.append(rel)

    for f in findings:
        rel = f.file.split("!", 1)[0]
        if (root / rel).is_file():
            add(rel)

    for name in ("README.md", "readme.md", "README", "docs/README.md"):
        if (root / name).is_file():
            add(name)

    for path in sorted(root.rglob("*")):
        if len(picked) >= limit:
            break
        if not path.is_file() or path.suffix not in SCOPE_SUFFIXES:
            continue
        if any(part in {".git", "node_modules", "target", "venv", ".venv", "dist", "build"}
               for part in path.parts):
            continue
        rel = str(path.relative_to(root))
        if ENCLAVE_HINTS.search(rel):
            add(rel)

    return picked[:limit]


# ------------------------------------------------------------ scorecard ---
def layer_scorecard(
    catalog: dict[str, dict],
    findings: list[Finding],
    platform: platform_detect.Platform | None = None,
) -> dict:
    """Effective layer = highest L such that every rule required at or below L passes.

    A single failing prerequisite caps the protocol there, which is the point: the
    handbook's layers are cumulative, so Layer 4 with broken attestation is not Layer 4.
    """
    failed = {f.rule_id for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)}

    # Only rules that could apply to this deployment count toward the layer requirements.
    # Without this, adding a platform inflates every other platform's verifiable ceiling:
    # the EigenCompute rules sit at layers 1-2, so a Nitro repo would suddenly "reach" a
    # layer on the strength of rules that can never fire on it. That is the overclaiming
    # the ceiling exists to prevent, arriving through the back door.
    applicable = set(platform.names()) if platform is not None else None

    def _applies(rule: dict) -> bool:
        if applicable is None:
            return True
        platforms = set(rule.get("platform") or ["generic"])
        return bool(platforms & applicable) or "generic" in platforms

    per_layer: dict[int, dict] = {}
    for level in range(0, 7):
        required = [
            rid for rid, r in catalog.items()
            if r.get("layer_required") == level and r["severity"] != "info" and _applies(r)
        ]
        broken = sorted(set(required) & failed)
        per_layer[level] = {
            "required_rules": len(required),
            "failing": broken,
            "passes": not broken,
        }

    # A layer with no rules in the catalog cannot be passed, only unassessed. Reporting
    # "Layer 6" because nothing checks layers 5 and 6 would be precisely the overclaiming
    # this tool exists to catch — so the score is capped at the highest layer we can
    # actually speak to, and the gap is reported rather than silently rounded up.
    ceiling = max((l for l in range(1, 7) if per_layer[l]["required_rules"] > 0), default=0)

    effective = 0
    for level in range(1, ceiling + 1):
        if all(per_layer[l]["passes"] for l in range(1, level + 1)):
            effective = level
        else:
            break

    blockers = []
    for level in range(1, 7):
        if per_layer[level]["failing"]:
            blockers = per_layer[level]["failing"]
            break

    return {
        "effective_layer": effective,
        "verifiable_ceiling": ceiling,
        "per_layer": per_layer,
        "blocking_rules": blockers,
    }


# --------------------------------------------------------- not verified ---
def not_verified(
    root: Path,
    catalog: dict[str, dict],
    platform: platform_detect.Platform,
    core: Path | None,
    eif_reports: list[dict],
    warnings: list[str],
    semantic_ran: bool = False,
) -> list[str]:
    """What this audit structurally could not check. Computed, not hand-written, so it
    cannot drift away from what the tool actually did."""
    items: list[str] = []

    # Rules in the catalog with no implementation yet.
    sys.path.insert(0, str(ROOT / "catalog"))
    try:
        import coverage as cov  # type: ignore

        impl: dict[str, list[str]] = {}
        sources = [cov.semgrep_catalog_ids(), cov.python_rule_ids(), cov.rust_rule_ids()]
        # The semantic rules count as covered only on a run that actually invoked them.
        if semantic_ran:
            sources.append(cov.agent_rule_ids())
        for src in sources:
            for cid, who in src.items():
                impl.setdefault(cid, []).extend(who)
        missing = sorted(set(catalog) - set(impl))
        if missing:
            items.append(
                f"{len(missing)} catalogued rules have no detector yet and were not "
                f"checked: {', '.join(m.split('-', 2)[1] for m in missing)}"
            )
    except Exception:
        items.append("catalog coverage could not be computed")

    # Deployment reality is out of reach by design.
    items.append(
        "Deployed configuration was not inspected. The KMS key policy in this repository "
        "is not necessarily the policy attached to the live key, and --debug-mode absent "
        "from a script is not proof of how the enclave was actually launched."
    )
    items.append(
        "Runtime behaviour was not observed: no attestation document was fetched from a "
        "running enclave, no PCR values were read live, and no timing or response-size "
        "distributions were measured (which is why BT-T08 metadata leakage has low recall)."
    )

    if platform.nitro:
        items.append(
            "PCR3 (parent IAM role) and PCR4 (parent instance ID) are runtime values not "
            "present in an EIF and cannot be derived statically by any tool."
        )
    if any(r.get("signature_present") for r in eif_reports):
        items.append(
            "An EIF is signed, so a PCR8 exists. Computing it requires X.509 parsing that "
            "this tool deliberately omits, so PCR8 was not verified."
        )
    if not eif_reports:
        items.append(
            "No built .eif was found, so ramdisk secret scanning (BT-T09A) and the "
            "PCR-to-policy comparison (BT-CFG03) did not run. Build the image and re-run "
            "to cover them."
        )
    if core is None:
        items.append("The Rust core was not built, so no binary-format analysis ran at all.")
    if not platform.any:
        items.append(
            "No TEE platform indicators were found in this repository. Either it does not "
            "use enclaves, or the enclave code lives elsewhere — a clean result here is "
            "not evidence of a secure enclave deployment."
        )

    items.append(
        "Hardware attacks are out of scope: speculative execution, Rowhammer, voltage and "
        "EM fault injection, and the 2025 memory-bus attacks (WireTap, Battering RAM, "
        "TEE.fail) are not statically detectable and were not assessed."
    )
    items.extend(f"Detector limitation: {w}" for w in warnings)
    return items


# ------------------------------------------------------------- rendering ---
def render_markdown(result: dict) -> str:
    sc = result["scorecard"]
    lines = [
        "# TEE audit report",
        "",
        f"**Target:** `{result['root']}`  ",
        f"**Platform detected:** {result['platform']['summary']}  ",
        f"**Findings:** {len(result['findings'])}",
        "",
        "## 1. Layer scorecard",
        "",
        f"**Effective layer: {sc['effective_layer']}** "
        f"of a verifiable ceiling of {sc['verifiable_ceiling']} "
        f"(the handbook's ladder runs to 6 — see "
        f"[security layers](https://bluethroatlabs.com/docs/layers-of-security-for-tees))",
        "",
    ]
    if sc["verifiable_ceiling"] < 6:
        lines += [
            f"> Layers {sc['verifiable_ceiling'] + 1}-6 carry no rules in this catalog, so "
            f"they are unassessed rather than passed. A score of "
            f"{sc['verifiable_ceiling']} is the maximum this tool can currently award and "
            f"is not a claim about Layer 6.",
            "",
        ]
    if sc["blocking_rules"]:
        lines += [
            "Capped by:",
            "",
            *[f"- `{r}`" for r in sc["blocking_rules"]],
            "",
        ]
    if sc["effective_layer"] <= 1:
        lines += [
            "> The handbook states Layer 1 — TEE with no verified attestation — must not "
            "be used in production.",
            "",
        ]

    lines += ["| Layer | Required rules | Status |", "|---|---|---|"]
    for level in range(1, 7):
        info = sc["per_layer"][level]
        if info["required_rules"] == 0:
            status = "unassessed (no rules)"
        elif info["passes"]:
            status = "pass"
        else:
            status = f"fails ({len(info['failing'])})"
        lines.append(f"| {level} | {info['required_rules']} | {status} |")

    lines += ["", "## 2. Findings", ""]
    if not result["findings"]:
        lines.append("None from the detectors that ran. See section 3 for what did not run.")
    for f in result["findings"]:
        lines += [
            f"### `{f['rule_id']}` — {f['severity']}",
            "",
            f"**{f['file']}:{f['line']}** · confidence {f['confidence']} · {f['detector']} · {f['verdict']}",
            "",
            f"```\n{f['evidence']}\n```",
            "",
            f["message"],
            "",
        ]

    lines += ["## 3. NOT VERIFIED", "",
              "What this audit structurally could not check.", ""]
    lines += [f"- {item}" for item in result["not_verified"]]
    lines.append("")
    return "\n".join(lines)


# ------------------------------------------------------------------ main ---
def main() -> int:
    ap = argparse.ArgumentParser(description="Static auditor for cloud TEE protocols")
    ap.add_argument("path")
    ap.add_argument("--format", choices=["md", "json"], default="md")
    ap.add_argument("--semgrep", default="semgrep")
    ap.add_argument(
        "--semantic",
        action="store_true",
        help="run the four judgment rules (BT-T00/T05/T08/LYR01) through the Claude Agent "
             "SDK, each finding adversarially verified. Costs model calls and minutes; the "
             "deterministic layer is complete without it.",
    )
    ap.add_argument(
        "--no-verify",
        action="store_true",
        help="skip the adversarial refutation pass. Semantic findings then ship unverified "
             "and are labelled as such — not recommended outside debugging.",
    )
    args = ap.parse_args()

    root = Path(args.path).resolve()
    if not root.is_dir():
        print(json.dumps({"error": f"{root} is not a directory"}))
        return 1

    catalog = load_catalog()
    core = find_core()
    platform = platform_detect.detect(root)

    warnings: list[str] = []
    findings: list[Finding] = []

    sg_findings, sg_warnings = run_semgrep(root, args.semgrep)
    findings += sg_findings
    warnings += sg_warnings

    eif_findings, eif_warnings, eif_reports = run_eif_scan(root, core)
    findings += eif_findings
    warnings += eif_warnings

    findings += kms_policy.run(root)
    findings += buildconfig.run(root, core)
    findings += attestation.run(root, core)
    findings += vsock_rules.run(root)
    findings += stream_rules.run(root)
    findings += dstack_rules.run(root, platform)
    findings += confspace_rules.run(root, platform)
    findings += eigencompute_rules.run(root, platform)

    refuted: list[Finding] = []
    if args.semantic:
        import asyncio

        sys.path.insert(0, str(ROOT / "agent"))
        from semantic import run_semantic

        scope = semantic_scope(root, findings)
        kept, refuted, sem_warnings = asyncio.run(
            run_semantic(root, scope, verify=not args.no_verify)
        )
        findings += kept
        warnings += sem_warnings
    else:
        warnings.append(
            "semantic rules (BT-T00 trust boundary, BT-T05 TCB bloat, BT-T08 metadata "
            "leakage, BT-LYR01 layer claims) did not run; pass --semantic to enable them"
        )

    findings = sort_for_report(dedupe(findings))
    scorecard = layer_scorecard(catalog, findings, platform)

    result = {
        "root": str(root),
        "platform": {"summary": platform.summary(), "evidence": platform.evidence},
        "scorecard": scorecard,
        "eif": eif_reports,
        "findings": [f.to_dict() for f in findings],
        # Refuted findings are kept out of the report but recorded. A refutation rate of
        # zero means the adversarial pass is rubber-stamping and should be distrusted.
        "refuted": [f.to_dict() for f in refuted],
        "not_verified": not_verified(
            root, catalog, platform, core, eif_reports, warnings, semantic_ran=args.semantic
        ),
    }

    print(json.dumps(result, indent=2) if args.format == "json" else render_markdown(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
