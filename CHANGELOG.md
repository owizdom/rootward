# Changelog

Notable changes per release. Dates are the tag date.

The version this matters most for is the Action: pin `owizdom/rootward@v0.2.0` rather than
`@main`, because `@main` moves under you — which is the defect this tool reports as
`BT-CFG04`.

## v0.2.0 — 2026-08-19

First tagged release. Renamed from `tee-audit`; GitHub keeps a redirect from the old URL,
but the Rust crate (`rootward_core`), its binary (`rootward-core`), and the
`ROOTWARD_MAX_USD` environment variable all changed name.

### Added

- **`BT-OS01`–`BT-OS03`, OS image and firmware rules.** The rule class an external audit
  proved was missing: guest firmware built from the general-purpose OVMF target rather than
  the Intel TDX one, secure boot offered by a recipe and never taken, and development image
  features reaching a production image. They read BitBake recipes and EDK II build
  invocations, which is the far end of the measurement chain every other rule starts at.
- **`BT-CS04`, attestation presented but never performed.** Fires on a project that signs
  every response with a real key, ships a verification library, uses the word throughout its
  documentation, and performs no quote fetch, token verification, or chain walk anywhere.
- **An enforced sandbox on the semantic layer** (`agent/sandbox.py`). Every tool call goes
  through a `PreToolUse` hook that resolves each path — symlinks included — and denies
  anything outside the audit root, plus any tool that is not `Read`, `Grep`, or `Glob`.
- **Fuzzing** (`core/fuzz/`). Four cargo-fuzz targets over the EIF, CPIO, decompression and
  secret-scanning paths, seeded from the built fixtures, run nightly by
  `.github/workflows/fuzz.yml`.
- **`catalog/table.py`** generates the README's rule table, and CI fails if the README is
  stale against the catalog.
- Two fixture trees, `osimage-clean` and `osimage-vulnerable`, and nine mutants.

### Fixed

- **The semantic layer could read outside the audit root, and the documentation said it
  could not.** `allowed_tools` is not a capability boundary under
  `permission_mode="bypassPermissions"` — measured, not assumed: an agent configured that
  way and asked for a file outside its `cwd` called `Bash`, ran `cat`, and returned the
  contents. The hook above closes it; `SECURITY.md` now describes what is actually enforced.
- **`BT-OS02` missed the repository it was written for.** Defining
  `OVMF_SECURE_BOOT_FLAGS = "-DSECURE_BOOT_ENABLE=TRUE"` counted as secure boot being
  enabled, even where the flag is only passed on a branch that is not taken. `meta-dstack`
  has exactly that shape and says so itself: `bbnote "Building without Secure Boot."`.
- **`BT-OS02` and `BT-OS03` reported the wrong line and quoted nothing.** `^\s*` let a match
  start in the blank-and-comment run above the offending line, so the finding pointed at a
  comment and its evidence was the empty string.
- **`BT-T03` fired nine times on `vanta` where two were real**, fixed at the cause with a
  post-filter plus multi-line evidence capture.
- The mutation harness labelled any base tree that was not `eigencompute-clean` as `nitro`.
- Ruff was configured and had never run; 58 violations, including a closure over a loop
  variable and two zips that would silently truncate.
- The README claimed 42 rules when there were 46, reported 55/55 mutation recall when it was
  74/74, and listed two gaps that had already been closed.

### Changed

- **External validation goes from 1 of 14 re-found to 2 of 14.** `BT-OS01` finds
  zkSecurity's only High on `meta-dstack` at `dstack-ovmf_git.bb:208`, at the commit their
  report names. It is a re-find rather than a blind find — the gap was documented first and
  the rule written against a known answer — and `docs/dstack-vs-zksecurity.md` says so.
- Mutation recall 74/74 → **83/83**, still zero false positives, now across 30 rules and
  four clean fixture trees.
- README restructured; the rule table is generated rather than maintained.

## v0.1.0 — untagged

The 44 commits before this: the rule catalog and its validator, the Rust core with its
differential check against AWS's own EIF implementation, the semgrep ruleset, the
deterministic detectors for Nitro, dstack, and EigenCompute, the semantic layer and its
adversarial refutation pass, the mutation harness, the real-repository corpus, the ablation,
and the GitHub Action.
