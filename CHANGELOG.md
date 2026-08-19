# Changelog

Notable changes per release. Dates are the tag date.

The version this matters most for is the Action: pin `owizdom/rootward@v0.2.0` rather than
`@main`, because `@main` moves under you, which is the defect this tool reports as
`BT-CFG04`.

## Unreleased

### Changed

- **Reported severity is now per-instance.** A finding's severity is its rule's impact
  lowered by the detector's confidence (`high` 0 steps, `medium` 1, `low` 2), floored at
  `low` and never raised above what the rule declares. The original is kept on the finding
  and printed in the report, so the adjustment is visible rather than trusted.
  **This changes what `--fail-on` gates on**: a pipeline set to `--fail-on critical` will
  trip less often than before. That is the correction, not a side effect. On the dstack
  monorepo it takes 13 criticals to 3.
- The catalog's `confidence` is now a ceiling that detectors may not exceed, checked on
  every fixture tree by `bench/test_fixtures.py`. Turning that check on found ten detectors
  whose emitted confidence had drifted from their catalog entry in one direction or the
  other, silently moving severities.

### Fixed

- **BT-T10 required only that a fetch and an authority-carrying word appear somewhere in
  the same file.** On a 900-line module that is barely a question, and it produced six
  criticals on dstack whose evidence lines were variable bindings
  (`let relay = async {`, `Client::builder().build()?`). It now requires the two within 25
  lines of each other, will not anchor on a binding-only line, and matches fetch calls
  rather than crate names. Six findings to zero, none of them real.
- **BT-T03 flagged PRNG seeds.** `print(f"FAIL seed={args.seed:#x} ...")` in a differential
  test harness was reported as a critical secret egress; the value traces to `argparse` and
  `random.Random`. Values reached through a CLI namespace or named for a PRNG are excluded.
  `instance_id_seed = secrets.token_hex(20)` written to a logger still fires, which is the
  split that matters.
- **BT-T06B fired on RA-TLS.** `InsecureSkipVerify: true` paired with a
  `VerifyPeerCertificate` callback is how attestation-based verification is done.
- Directories named `mock-*` are suppressed alongside `*-mock`.

## v0.2.1: 2026-08-19

### Changed

- Removed every em dash from what the tool emits and ships: source, docs, rule prose, and
  the report template. The finding header was the visible one, rendering as
  `### BT-T09B-dockerfile-secret [em dash] critical` on every finding in every report. The
  four that remain are in `bench/fixtures/`, which is synthetic code under audit rather than
  our own prose.

### Fixed

- `CONTRIBUTING.md` still told contributors to hand-edit the README rule table, which
  `catalog/table.py` generates and CI gates.
- The fuzz workflow could not run on a fresh checkout: `fuzz/corpus/<target>` is gitignored,
  and libFuzzer requires the writable corpus directory to exist.

## v0.2.0: 2026-08-19

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
  through a `PreToolUse` hook that resolves each path (symlinks included) and denies
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
  `permission_mode="bypassPermissions"`, measured, not assumed: an agent configured that
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
  report names. It is a re-find rather than a blind find, the gap was documented first and
  the rule written against a known answer, and `docs/dstack-vs-zksecurity.md` says so.
- Mutation recall 74/74 → **83/83**, still zero false positives, now across 30 rules and
  four clean fixture trees.
- README restructured; the rule table is generated rather than maintained.

## v0.1.0: untagged

The 44 commits before this: the rule catalog and its validator, the Rust core with its
differential check against AWS's own EIF implementation, the semgrep ruleset, the
deterministic detectors for Nitro, dstack, and EigenCompute, the semantic layer and its
adversarial refutation pass, the mutation harness, the real-repository corpus, the ablation,
and the GitHub Action.
