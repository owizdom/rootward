"""Semantic passes and adversarial verification, on the Claude Agent SDK.

Four rules in the catalog need judgment rather than pattern matching: BT-T00 (trust
boundary), BT-T05 (TCB bloat), BT-T08 (metadata leakage), and BT-LYR01 (layer claims vs
reality). This module runs those, then hands every resulting finding to an independent agent
whose only job is to refute it.

Two design commitments:

**Opt-in.** The deterministic layer is the tool; this is an addition to it. Model calls cost
money and take minutes, and 19 of 29 rules never need one. `audit.py` runs without this
unless asked.

**Nothing ships unverified.** A semantic finding arrives as a claim. It becomes CONFIRMED
only after a separate agent, given the same codebase and no access to the finder's
reasoning, tries to refute it and fails. Findings that survive as uncertain ship as
PLAUSIBLE and are labelled that way in the report; refuted ones are dropped and kept in the
run log. Deterministic findings skip this entirely — a literal pattern match is its own
evidence.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "detectors"))
sys.path.insert(0, str(ROOT / "agent"))

from model import Confidence, Finding, Severity, Verdict  # noqa: E402
import prompts  # noqa: E402

# Read-only tools. The auditor has no business editing the code it is auditing, and a
# semantic pass that can write is a semantic pass that can "fix" a finding out of existence.
READ_ONLY_TOOLS = ["Read", "Grep", "Glob"]

FINDER_MODEL = "claude-opus-5"
# Hard ceiling per agent invocation. An auditor that spawns a dozen agents over an
# unfamiliar repository should not be able to run up an unbounded bill because one of them
# decided to read every file in node_modules. Verified present on ClaudeAgentOptions in
# claude-agent-sdk 0.2.139.
# $2 was too low: on dstack the BT-T08 pass died with "Reached maximum budget ($2)" and
# was reported as a failed pass rather than a clean one. A real repository needs room to
# read. Override with TEE_AUDIT_MAX_USD when auditing something large.
MAX_USD_PER_AGENT = float(__import__("os").environ.get("TEE_AUDIT_MAX_USD", "8.00"))
# The refuter is the check on the finder, so it needs comparable capability — a weaker
# refuter rubber-stamps, which is worse than no refutation because it launders claims.
REFUTER_MODEL = "claude-opus-5"

SEVERITY_BY_RULE = {
    "BT-CFG05-no-key-rotation": Severity.MEDIUM,
    "BT-T00-parent-instance-trusted": Severity.HIGH,
    "BT-T05-tcb-bloat": Severity.MEDIUM,
    "BT-T08-metadata-leakage": Severity.CRITICAL,
    "BT-LYR01-layer-scorecard": Severity.INFO,
}

CONFIDENCE = {"high": Confidence.HIGH, "medium": Confidence.MEDIUM, "low": Confidence.LOW}


class AgentUnavailable(RuntimeError):
    """The SDK is missing or unauthenticated. Callers degrade rather than abort."""


def _require_sdk():
    try:
        from claude_agent_sdk import ClaudeAgentOptions, query  # noqa: F401
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise AgentUnavailable(
            "claude-agent-sdk not installed; run: pip install claude-agent-sdk"
        ) from exc
    return query, ClaudeAgentOptions


async def _run_json(system_prompt: str, user_prompt: str, cwd: Path, schema: dict,
                    model: str, max_turns: int = 60) -> dict:
    """Run one agent to completion and return its structured output.

    Returns {} when the agent produced nothing parseable, which the callers treat as "no
    findings" rather than an error — a semantic pass failing should degrade the audit, not
    abort it.
    """
    query, ClaudeAgentOptions = _require_sdk()

    options = ClaudeAgentOptions(
        system_prompt=system_prompt,
        allowed_tools=READ_ONLY_TOOLS,
        # Read-only tools only, so nothing here can edit the audited repository. The
        # permission mode governs prompting, not capability — the tool list is the guard.
        permission_mode="bypassPermissions",
        cwd=str(cwd),
        model=model,
        max_turns=max_turns,
        max_budget_usd=MAX_USD_PER_AGENT,
        output_format={"type": "json_schema", "schema": schema},
    )

    # Where the structured result actually lands, verified against sdk 0.2.139: the model
    # emits a `StructuredOutput` tool call, and the parsed value appears on the terminal
    # ResultMessage as `structured_output` (with `result` carrying the same thing as a JSON
    # string). It is NOT in an AssistantMessage text block — those hold the model's prose
    # preamble ("I'll produce the finding."), which is why reading text blocks yielded
    # unparseable output and silently produced zero findings on every pass.
    structured: dict | None = None
    raw_result: str | None = None
    chunks: list[str] = []

    async for message in query(prompt=user_prompt, options=options):
        so = getattr(message, "structured_output", None)
        if isinstance(so, dict):
            structured = so
        res = getattr(message, "result", None)
        if isinstance(res, str) and res.strip():
            raw_result = res
        # Kept as a fallback for a run where structured output did not engage.
        for block in getattr(message, "content", []) or []:
            text = getattr(block, "text", None)
            if text:
                chunks.append(text)

    if structured is not None:
        return structured

    for candidate in (raw_result, "".join(chunks).strip()):
        if not candidate:
            continue
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            start, end = candidate.find("{"), candidate.rfind("}")
            if start >= 0 and end > start:
                try:
                    return json.loads(candidate[start : end + 1])
                except json.JSONDecodeError:
                    pass
    return {}


async def run_pass(
    rule_id: str,
    root: Path,
    scope: list[str],
    attempts: int = 3,
    platform=None,
) -> list[Finding]:
    """One semantic rule over a scoped file list.

    Retried, for the same reason `refute` is: a transient SDK error is not a result. A full
    ablation across five repositories had 5 of 20 passes die with "Claude Code returned an
    error result", including the BT-T00 pass on dstack — the one rule that re-found an
    external auditor's finding. Those passes were correctly reported as failed rather than
    empty, but a failed pass still costs the run its coverage, and retrying is cheap next to
    re-running the whole audit.
    """
    instruction = prompts.PASSES[rule_id]
    # The threat model has to match the platform. Telling a Confidential Space audit that
    # every byte crosses a vsock channel the parent controls produces fluent, confident,
    # wrong findings -- the exact failure mode this project documented in
    # docs/when-the-verifier-is-wrong.md, arriving through the system prompt instead.
    system = f"{prompts.threat_model(platform)}\n\n{instruction}"

    listing = "\n".join(f"- {p}" for p in scope[:200])
    user = (
        f"Audit the code in this repository against the rule in your instructions.\n\n"
        f"Start with these files, which other detectors flagged as enclave-relevant or "
        f"security-relevant. Read more if you need to, but stay inside the repository:\n\n"
        f"{listing}\n\n"
        f"Return findings in the required schema. An empty list is a valid and common result."
    )

    payload: dict = {}
    last_error: str | None = None
    for attempt in range(1, attempts + 1):
        try:
            payload = await _run_json(system, user, root, prompts.FINDING_SCHEMA, FINDER_MODEL)
        except Exception as exc:  # noqa: BLE001 - retry, then let the caller report it
            last_error = f"{type(exc).__name__}: {exc}"
            payload = {}
        # An empty findings list is a legitimate result, so only a hard failure retries.
        if payload:
            break
        if attempt < attempts:
            await asyncio.sleep(3 * attempt)

    if not payload and last_error:
        raise RuntimeError(f"{rule_id} failed after {attempts} attempts: {last_error}")

    out: list[Finding] = []
    for raw in payload.get("findings", []):
        try:
            out.append(
                Finding(
                    rule_id=rule_id,
                    file=str(raw["file"]),
                    line=int(raw["line"]),
                    evidence=str(raw["evidence"])[:200],
                    message=str(raw["reasoning"]),
                    severity=SEVERITY_BY_RULE.get(rule_id, Severity.MEDIUM),
                    confidence=CONFIDENCE.get(str(raw.get("confidence", "low")), Confidence.LOW),
                    detector=f"agent:{rule_id.split('-')[1].lower()}",
                    verdict=Verdict.UNVERIFIED,
                )
            )
        except (KeyError, TypeError, ValueError):
            continue
    return out


async def refute(finding: Finding, root: Path, attempts: int = 3, platform=None) -> Finding:
    """Adversarial pass. Mutates verdict in place on a copy and returns it.

    Retried, because a transient SDK error is not a verdict. On one dstack run every one of
    16 refutations errored at once (a credential refresh mid-run) and all 16 findings shipped
    as PLAUSIBLE — unverified output wearing a label that suggests it was checked.
    """
    user = (
        f"Finding to refute:\n\n"
        f"  rule:      {finding.rule_id}\n"
        f"  location:  {finding.file}:{finding.line}\n"
        f"  evidence:  {finding.evidence}\n"
        f"  claim:     {finding.message}\n\n"
        f"Read the cited location and the surrounding code, then decide."
    )
    payload: dict = {}
    last_error: str | None = None
    for attempt in range(1, attempts + 1):
        try:
            payload = await _run_json(
                prompts.REFUTE, user, root, prompts.REFUTE_SCHEMA, REFUTER_MODEL, max_turns=30
            )
        except Exception as exc:  # noqa: BLE001 - retry, then degrade with the reason
            last_error = f"{type(exc).__name__}: {exc}"
            payload = {}
        if payload:
            break
        if attempt < attempts:
            await asyncio.sleep(2 * attempt)

    if not payload:
        finding.verdict = Verdict.PLAUSIBLE
        finding.refutation = (
            f"adversarial pass failed after {attempts} attempts"
            + (f": {last_error}" if last_error else "")
        )
        return finding


    if payload.get("refuted"):
        finding.verdict = Verdict.REFUTED
    elif finding.confidence == Confidence.LOW:
        finding.verdict = Verdict.PLAUSIBLE
    else:
        finding.verdict = Verdict.CONFIRMED

    finding.refutation = str(payload.get("reason", ""))[:400]
    finding.metadata["refuter_checked"] = str(payload.get("checked", ""))
    return finding


async def run_semantic(root: Path, scope: list[str], rules: list[str] | None = None,
                       verify: bool = True,
                       platform=None) -> tuple[list[Finding], list[Finding], list[str]]:
    """Run the semantic passes and the adversarial check.

    Returns (kept, dropped, warnings). `dropped` holds refuted findings so the run log can
    show what the verifier removed — a refutation rate near zero means the verifier is
    rubber-stamping and should itself be distrusted.
    """
    warnings: list[str] = []
    selected = rules or list(prompts.PASSES)

    try:
        _require_sdk()
    except AgentUnavailable as exc:
        return [], [], [str(exc)]

    results = await asyncio.gather(
        *(run_pass(rule, root, scope, platform=platform) for rule in selected), return_exceptions=True
    )

    candidates: list[Finding] = []
    for rule, result in zip(selected, results):
        if isinstance(result, BaseException):
            warnings.append(f"semantic pass {rule} failed: {result}")
            continue
        candidates.extend(result)

    if not verify or not candidates:
        return candidates, [], warnings

    verified = await asyncio.gather(
        *(refute(f, root, platform=platform) for f in candidates), return_exceptions=True
    )

    kept, dropped = [], []
    for original, result in zip(candidates, verified):
        if isinstance(result, BaseException):
            original.verdict = Verdict.PLAUSIBLE
            original.refutation = f"adversarial pass errored: {result}"
            kept.append(original)
        elif result.verdict == Verdict.REFUTED:
            dropped.append(result)
        else:
            kept.append(result)

    return kept, dropped, warnings
