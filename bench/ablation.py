#!/usr/bin/env python3
"""Ablation: does the model layer earn its cost?

    .venv/bin/python bench/ablation.py [--only NAME] [--markdown PATH]

Runs each corpus repository twice, deterministic-only and `--semantic`, and diffs the
findings by threat class.

The question is not "is the LLM good". It is narrower and answerable: **for each threat
class, does the model layer surface anything the deterministic layer does not, and what did
that cost?** Where the answer is no, the honest move is to say so and stop paying for the
model call on that class, which is the finding this project committed to publishing before
it knew what the number would be.

The comparison is deliberately unfair to the model layer in one respect: deterministic runs
take seconds and cost nothing, so anything the model finds has to be worth minutes and
dollars. That is the real decision a user makes.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "bench" / "corpus.yaml"
CACHE = ROOT / "bench" / "corpus"
PYTHON = str(ROOT / ".venv" / "bin" / "python")

# Threat classes only the semantic layer implements. Deterministic-only cannot produce these
# by construction, so their appearance is the ablation's whole point rather than a surprise.
SEMANTIC_ONLY = {"T00", "T05", "T08", "LYR01"}


def run_audit(path: Path, semantic: bool) -> tuple[dict, float]:
    cmd = [PYTHON, str(ROOT / "cli" / "audit.py"), str(path), "--format", "json"]
    if semantic:
        cmd.append("--semantic")
    started = time.monotonic()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
    elapsed = time.monotonic() - started
    if proc.returncode != 0 or not proc.stdout.strip():
        raise RuntimeError(proc.stderr[-600:] or "no output")
    return json.loads(proc.stdout), elapsed


def by_class(result: dict) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for f in result["findings"]:
        out.setdefault(f["rule_id"].split("-")[1], []).append(f)
    return out


def compare(name: str, path: Path) -> dict:
    det, det_secs = run_audit(path, semantic=False)
    sem, sem_secs = run_audit(path, semantic=True)

    det_classes, sem_classes = by_class(det), by_class(sem)
    all_classes = sorted(set(det_classes) | set(sem_classes))

    rows = []
    for cls in all_classes:
        d, s = det_classes.get(cls, []), sem_classes.get(cls, [])
        # Same rule at the same location counts as the same finding.
        d_at = {(f["file"], f["line"]) for f in d}
        s_at = {(f["file"], f["line"]) for f in s}
        rows.append({
            "class": cls,
            "deterministic": len(d),
            "semantic": len(s),
            "only_semantic": sorted(s_at - d_at),
            "only_deterministic": sorted(d_at - s_at),
            "semantic_only_by_design": cls in SEMANTIC_ONLY,
        })

    # Refuted findings never reach the report but are the clearest evidence the verification
    # layer is doing work rather than rubber-stamping. A refutation rate of zero is ambiguous
    # on its own. it means either "the verifier checked and agreed" or "the verifier never
    # ran", and those were confused by hand once already, so the two are counted separately.
    refuted = sem.get("refuted", [])
    kept = [f for f in sem["findings"] if f["detector"].startswith("agent:")]
    refuter_errors = sum(
        1 for f in kept
        if "failed after" in (f.get("refutation") or "") or "errored" in (f.get("refutation") or "")
    )

    return {
        "repo": name,
        "deterministic_seconds": round(det_secs, 1),
        "semantic_seconds": round(sem_secs, 1),
        "deterministic_findings": len(det["findings"]),
        "semantic_findings": len(sem["findings"]),
        "refuted": len(refuted),
        "refuter_errors": refuter_errors,
        "semantic_kept": len(kept),
        "verdicts": _verdict_counts(sem["findings"]),
        "classes": rows,
        "failed_passes": [
            n for n in sem.get("not_verified", []) if "Detector limitation" in n
        ],
    }


def _verdict_counts(findings: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        if f["detector"].startswith("agent:"):
            out[f["verdict"]] = out.get(f["verdict"], 0) + 1
    return out


def render(results: list[dict]) -> str:
    lines = [
        "# Ablation: model layer vs deterministic-only",
        "",
        # Emitted here rather than hand-written into the markdown. A scope note added by
        # hand to a generated file survives exactly until the next run deletes it, and this
        # one is load-bearing: without it the conclusion reads as covering every platform.
        "> **Scope.** Covers the repositories listed below only. The EigenCompute rules are",
        "> all deterministic, so there is nothing for the model layer to add or miss on",
        "> them, and they have not been ablated.",
        "",
        "Generated by `bench/ablation.py`. Each repository is audited twice, once with the",
        "deterministic detectors alone and once with `--semantic`, and the findings are",
        "diffed by threat class.",
        "",
        "The deterministic layer runs in seconds and costs nothing. Anything the model layer",
        "adds has to be worth minutes and dollars, which is the actual decision a user makes.",
        "",
        "| repo | deterministic | semantic | refuted | wall-clock |",
        "|---|---|---|---|---|",
    ]
    for r in results:
        lines.append(
            f"| {r['repo']} | {r['deterministic_findings']} | {r['semantic_findings']} | "
            f"{r['refuted']} | {r['deterministic_seconds']}s → {r['semantic_seconds']}s |"
        )
    lines.append("")

    for r in results:
        lines += [
            f"## {r['repo']}",
            "",
            f"- deterministic: {r['deterministic_findings']} findings in "
            f"{r['deterministic_seconds']}s",
            f"- with semantic: {r['semantic_findings']} findings in {r['semantic_seconds']}s",
            f"- refuted and dropped by the adversarial pass: {r['refuted']}",
        ]
        if r["verdicts"]:
            verdicts = ", ".join(f"{k} {v}" for k, v in sorted(r["verdicts"].items()))
            lines.append(f"- semantic verdicts: {verdicts}")
        if r.get("refuter_errors"):
            lines.append(
                f"- **{r['refuter_errors']} of {r['semantic_kept']} refutations failed to "
                f"run.** Those findings ship as PLAUSIBLE without having been checked, a "
                f"refutation rate of zero here means the verifier was unavailable, not that "
                f"it agreed."
            )
        elif r["refuted"] == 0 and r["semantic_kept"]:
            lines.append(
                f"- every refutation ran and none succeeded: the verifier checked all "
                f"{r['semantic_kept']} findings and let them stand"
            )
        if r["failed_passes"]:
            lines += ["", "Passes that did not complete (reported, not silently empty):", ""]
            lines += [f"  - {p.replace('Detector limitation: ', '')}" for p in r["failed_passes"]]
        lines += ["", "| threat class | deterministic | semantic | unique to semantic |",
                  "|---|---|---|---|"]
        for row in r["classes"]:
            uniq = len(row["only_semantic"])
            marker = " *(semantic-only rule)*" if row["semantic_only_by_design"] else ""
            lines.append(
                f"| `{row['class']}`{marker} | {row['deterministic']} | {row['semantic']} | {uniq} |"
            )
        lines.append("")

    # The verdict the plan asked for, stated plainly.
    lines += ["## Reading", ""]
    shared = [
        row for r in results for row in r["classes"]
        if not row["semantic_only_by_design"]
    ]
    added = [row for row in shared if row["only_semantic"]]
    if not added:
        lines += [
            "On every threat class that **both** layers implement, the model layer found",
            f"nothing the deterministic layer missed, across {len(results)} repositories. "
            f"That is the honest result: for those",
            "classes the model call is not buying detection, and `--semantic` should be",
            "reserved for the four rules only it can implement (T00 trust boundary, T05 TCB",
            "bloat, T08 metadata leakage, LYR01 claim-vs-code).",
            "",
        ]
    else:
        lines += [
            "Classes where the model layer added findings the deterministic layer missed:",
            "",
        ]
        lines += [
            f"- `{row['class']}`, {len(row['only_semantic'])} additional at "
            + ", ".join(f"`{f}:{ln}`" for f, ln in row["only_semantic"][:4])
            for row in added
        ]
        lines.append("")

    lines += [
        "The semantic-only rules are the layer's actual justification. On dstack at the",
        "zkSecurity-audited commit, `T00` produced the finding that matched their #03 with a",
        "data-flow trace the published report does not contain, and the deterministic layer",
        "produced nothing in that class; see `docs/dstack-vs-zksecurity.md`.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="run a single repo by name")
    ap.add_argument("--markdown", metavar="PATH", default="docs/ablation.md")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    repos = yaml.safe_load(MANIFEST.read_text())["repos"]
    if args.only:
        repos = [r for r in repos if r["name"] == args.only]
        if not repos:
            print(f"no repo named {args.only}", file=sys.stderr)
            return 1

    results = []
    for repo in repos:
        dest = CACHE / repo["name"]
        if not dest.is_dir():
            print(f"skip {repo['name']}: not cloned "
                  f"(run: bench/corpus.py --only {repo['name']} --keep)", file=sys.stderr)
            continue
        print(f"== {repo['name']}", file=sys.stderr)
        try:
            results.append(compare(repo["name"], dest))
        except Exception as exc:  # noqa: BLE001 - a failed run is data
            print(f"  failed: {exc}", file=sys.stderr)
            continue
        r = results[-1]
        print(f"  deterministic {r['deterministic_findings']} in {r['deterministic_seconds']}s"
              f" | semantic {r['semantic_findings']} in {r['semantic_seconds']}s"
              f" | refuted {r['refuted']}", file=sys.stderr)

    if not results:
        print("no repositories were audited", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(results, indent=2))
        return 0

    out = Path(args.markdown)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(results), encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
