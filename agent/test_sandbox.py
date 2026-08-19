#!/usr/bin/env python3
"""Tests for the audit-root sandbox.

    .venv/bin/python agent/test_sandbox.py

`check()` is pure, so the boundary can be tested without a model, an API key, or a
network. The escape attempts below are the ones worth having a regression for: `..`
traversal, an absolute path, and a symlink planted inside the tree that points out of it.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sandbox import check  # noqa: E402


def main() -> int:
    failures: list[str] = []

    def expect_allowed(tool: str, ti: dict, why: str, root: Path) -> None:
        reason = check(root, tool, ti)
        if reason is not None:
            failures.append(f"{why}: expected allowed, denied with {reason!r}")

    def expect_denied(tool: str, ti: dict, why: str, root: Path) -> None:
        if check(root, tool, ti) is None:
            failures.append(f"{why}: expected DENIED, was allowed")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(os.path.realpath(Path(tmp) / "repo"))
        (root / "src").mkdir(parents=True)
        (root / "src" / "main.py").write_text("x = 1\n")

        outside = Path(os.path.realpath(tmp)) / "secrets"
        outside.mkdir()
        (outside / "id_rsa").write_text("PRIVATE KEY\n")

        # A symlink inside the tree pointing out of it — BT-T00A applied to ourselves.
        (root / "escape").symlink_to(outside)

        expect_allowed("Read", {"file_path": "src/main.py"}, "relative in-tree read", root)
        expect_allowed("Read", {"file_path": str(root / "src" / "main.py")}, "absolute in-tree read", root)
        expect_allowed("Grep", {"pattern": "x"}, "grep with no path defaults to cwd", root)
        expect_allowed("Glob", {"pattern": "**/*.py", "path": "src"}, "glob in-tree", root)
        expect_allowed("Read", {"file_path": str(root)}, "the root itself", root)

        expect_denied("Read", {"file_path": "../secrets/id_rsa"}, "dotdot traversal", root)
        expect_denied("Read", {"file_path": str(outside / "id_rsa")}, "absolute out-of-tree", root)
        expect_denied("Read", {"file_path": "escape/id_rsa"}, "symlink out of the tree", root)
        expect_denied("Grep", {"pattern": "KEY", "path": "/etc"}, "grep outside the tree", root)
        expect_denied("Read", {"file_path": "/etc/hosts"}, "absolute system path", root)
        expect_denied("Bash", {"command": "cat /etc/hosts"}, "a tool that was never granted", root)
        expect_denied("Read", {"file_path": 42}, "a path that is not a string", root)
        expect_denied("Read", {"file_path": "src/../../secrets/id_rsa"}, "traversal through the tree", root)

    if failures:
        print(f"FAIL — {len(failures)} problem(s):\n")
        for f in failures:
            print(f"  {f}")
        return 1
    print("OK — sandbox holds on 13 cases")
    return 0


if __name__ == "__main__":
    sys.exit(main())
