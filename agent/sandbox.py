"""A PreToolUse hook that confines the semantic passes to the audited repository.

Until this existed, the boundary was a sentence in a system prompt. `cwd` was set to the
audited repository and the tool list was read-only, so the worst case was a read rather
than a write, but "please stay inside the repository" is an instruction, and the audited
repository's own files are in scope by construction. A repository written to attack the
auditor can put instructions in its README, and the model reads that README.

This makes the boundary enforced rather than requested. Every Read, Grep, and Glob is
checked against the audit root before it runs, and anything resolving outside is denied
with a reason the model sees.

Two properties it deliberately has:

**Fail closed.** A tool call whose path cannot be resolved is denied, not allowed. The
alternative (allow what we do not understand) makes the guard decorative the moment a
tool grows an argument this file has not heard of.

**Symlinks resolved on both sides.** `realpath` before comparing, so a symlink planted in
the audited tree cannot point at `/Users/you/.ssh` and be read as an in-scope relative
path. That is BT-T00A, the rule this tool ships, applied to the tool itself.

**It matches every tool, not the three we grant.** This is the whole reason the guard is
not a narrower one. `allowed_tools` is not a capability boundary under
`permission_mode="bypassPermissions"` -- measured, not assumed: with
`allowed_tools=["Read", "Grep", "Glob"]` and that permission mode, an agent asked for a
file outside its `cwd` called **Bash** and ran `cat` on it, and the contents came back.
A hook registered only for `Read|Grep|Glob` never sees that call. So the matcher is `None`
(every tool), the tool allow-list is enforced here rather than trusted from options, and
anything not on it is denied whatever it is.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

# The tools the semantic passes are given. Each names the path it will touch differently.
GUARDED_TOOLS = ("Read", "Grep", "Glob")

# Where each tool carries a filesystem path. Checked in order; every key present is
# checked, not just the first, because Grep takes both a search root and a glob.
PATH_KEYS = ("file_path", "path", "notebook_path")


def _resolve(root: Path, value: str) -> Path:
    """Resolve a tool-supplied path the way the tool will, including symlinks.

    Relative paths resolve against the audit root because that is the agent's `cwd`.
    """
    p = Path(value)
    if not p.is_absolute():
        p = root / p
    return Path(os.path.realpath(p))


def _inside(root: Path, candidate: Path) -> bool:
    return candidate == root or candidate.is_relative_to(root)


def check(root: Path, tool_name: str, tool_input: dict[str, Any]) -> str | None:
    """Return a denial reason, or None to allow.

    Pure and synchronous so it can be tested without an SDK, an event loop, or a model.
    The hook below is a thin adapter over it; this is the part that has to be right.
    """
    if tool_name not in GUARDED_TOOLS:
        # Nothing else is in `allowed_tools`, so reaching here means the tool list and
        # this guard have drifted apart. Deny rather than wave it through.
        return (
            f"{tool_name} is not one of the read-only tools this audit grants "
            f"({', '.join(GUARDED_TOOLS)})."
        )

    root = Path(os.path.realpath(root))

    for key in PATH_KEYS:
        value = tool_input.get(key)
        if value is None:
            continue
        if not isinstance(value, str):
            return f"{tool_name}.{key} is not a path."
        try:
            target = _resolve(root, value)
        except (OSError, ValueError) as exc:
            return f"{tool_name}.{key} could not be resolved ({exc})."
        if not _inside(root, target):
            return (
                f"{tool_name} was denied: {key}={value!r} resolves to {target}, which is "
                f"outside the audit root {root}. This audit may only read the repository "
                f"it was pointed at. If the finding needs a file outside it, report that "
                f"you could not verify it instead."
            )
    return None


def make_hooks(root: Path) -> dict:
    """Build the `hooks` mapping for ClaudeAgentOptions.

    Shape verified against claude-agent-sdk 0.2.139: `hooks` is
    {event: [HookMatcher]}, a matcher's `matcher` is a tool-name pattern, and a
    PreToolUse callback denies by returning
    {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                            "permissionDecision": "deny",
                            "permissionDecisionReason": ...}}.

    `matcher=None` means every tool. Do not narrow it to GUARDED_TOOLS -- see the module
    docstring for the measurement that says why.
    """
    from claude_agent_sdk import HookMatcher

    async def guard(input_data: dict, tool_use_id: str | None, context: Any) -> dict:
        reason = check(root, input_data.get("tool_name", ""), input_data.get("tool_input") or {})
        if reason is None:
            return {}
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }

    return {"PreToolUse": [HookMatcher(matcher=None, hooks=[guard])]}
