# Contributing

Rules, bug reports, and false-positive reports are all welcome. **A false-positive report is
the most valuable thing you can send.** Five separate false-positive classes have been fixed
because someone ran this against correct code and it fired, each one made the tool better in
a way no amount of adding rules would have.

## Setup

```sh
git clone https://github.com/owizdom/rootward && cd rootward
uv venv                                          # or: python3 -m venv .venv
uv pip install pyyaml jsonschema semgrep
(cd core && cargo build --release --bins)
.venv/bin/python bench/fixtures/build.py
```

Order matters, `bench/fixtures/build.py` measures the built EIF, so the Rust core has to
exist first. It exits loudly if you get that wrong.

**Put `.venv/bin` on your `PATH` before running the benchmarks.** The audit subprocess finds
semgrep via `PATH`, and without it ~10 rule families silently do not run and the fixture gate
fails for the wrong reason:

```sh
export PATH="$PWD/.venv/bin:$PATH"
```

## The gates

Run these before opening a PR. The first five are what CI enforces.

```sh
(cd core && cargo test && cargo clippy --all-targets -- -D warnings)
.venv/bin/python catalog/validate.py     # schema, citations, status accuracy
.venv/bin/python catalog/coverage.py     # exits 1 on a detector citing a rule that doesn't exist
.venv/bin/python bench/test_fixtures.py  # recall, and zero findings on every clean tree
.venv/bin/python bench/mutate.py         # per-rule precision and recall
```

`bench/corpus.py` clones eleven repositories and `bench/ablation.py` spends real money, so
neither runs in CI. You do not need to run them for a normal change.

## Adding a rule

Six steps, in this order. The validator enforces most of it, so out-of-order work fails the
build rather than shipping wrong.

### 1. Catalog entry, `catalog/rules/BT-XXNN-short-slug.yaml`

The filename must equal the `id`. The schema sets `additionalProperties: false`, so an
unrecognised field fails the build.

Required: `id`, `title`, `source` (an `https://` URI), `platform`, `severity`, `detection`,
`rationale`, `remediation`, `false_positives`.

**`false_positives` is required and is not a formality.** It must state a real condition under
which your rule is wrong. A rule whose author cannot say when it misfires has not been thought
through, and the 20-character minimum exists because that gets tested rather than asserted.

Two constraints that will stop you cold if you don't know them:

- **New rule *families* need a schema change.** The `id` pattern in `catalog/schema.json`
  allows `T##`, `CFG##`, `DS##`, `CS##`, `EC##`, `LYR##` and nothing else.
- **New `platform` values need one too**, and detection has to actually exist. `sgx`, `tdx`
  and `sev-snp` are legal in the schema but `detectors/platform_detect.py` cannot detect them,
  so a rule gated only on those can never fire.

Start at `status: draft`. Copy `catalog/rules/BT-EC01-key-from-public-input.yaml`; it is the
most complete example.

### 2. The detector

Four backends. Whichever you pick, `catalog/coverage.py` has to be able to *see* it, or step 5
fails.

**semgrep**, a rule in `detectors/semgrep/tee/*.yaml` carrying `metadata.catalog-id: <your
id>`. A semgrep result without a `catalog-id` is silently dropped. Convention is one rule per
language, `tee-<name>-{rust,go,python,js}`.

**Python**, a function in `detectors/*.py` returning `Finding` from `detectors/model.py`.
Coverage detection is a literal regex: write `rule_id="BT-..."` with **double quotes, on one
line, as a literal**. `rule_id=SOME_CONST` is invisible to it.

Reuse the helpers rather than writing new ones, each exists because a rule was fooled:

| helper | exists because |
|---|---|
| `code_only(text, suffix)` | a commented-out check read as an implemented check |
| `strip_definitions(text)` | a dead function definition read as a live call |
| `strip_string_literals(text)` | a `VERIFICATION_CHAIN` array of prose steps satisfied an "is verification present" test |
| `quote_line`, `read_lines` | evidence has to be the real source line |

A **new module** also needs wiring into `cli/audit.py` in two places: the import block and the
call list. Match one of the three existing `run()` shapes, `run(root)`, `run(root, core_bin)`,
or `run(root, platform)` for platform-gated rules.

**Rust core**, add the id to the hardcoded map in `catalog/coverage.py`.

**Semantic**, add a prompt and an entry to `PASSES` in `agent/prompts.py`, plus a severity in
`agent/semantic.py`. Coverage regex-parses that `PASSES` block, so keep its formatting.

### 3. Both fixtures, the step that catches the most bugs

Add your defect to the matching `*-vulnerable/` tree, **and make sure the paired `*-clean/`
tree stays silent.** Trees are `clean`/`vulnerable` (Nitro), `dstack-*`, `eigencompute-*`.

The clean trees are asserted to produce **zero** findings. This is where three rules that fired
on correct code were caught before shipping, and where the fix for four more started. If you
are adding a platform-specific rule, write the clean fixture *first* and confirm it audits to
zero before you write the detector, you will find out immediately whether an existing rule
misfires on your idiom.

Then edit `bench/test_fixtures.py`:

- add your rule **family** to `EXPECTED[<tree>]["must_find"]`
- add it to every **other** tree's `FOREIGN` set, so platform gating is asserted in both
  directions. A rule that fires everywhere passes `must_find` and is still wrong.

### 4. Mutants

Append a `Mutation(...)` to `MUTATIONS` in `bench/mutate.py`. `base=` must name a fixture tree
of your rule's platform.

**Convention is ≥3 mutants per rule, varying the *shape* of the defect rather than the file.**
This is not bureaucracy: shape variation dropped a flattering 17/17 to 32/35 the first time it
was applied, and later caught three detector bugs that single mutants had missed. A rule that
only recognises its author's idiom scores 100% against one mutant and then misses the same bug
in real code.

`find` is literal by default. A mutation that matches nothing reports `inapplicable` and is
dropped from scoring (a silent recall hole) so only set `regex=True` for generated text. Use
`also_expects=(...)` for defects that genuinely cannot be planted in isolation.

### 5. Run the gates

See above. `catalog/coverage.py` exits 0 for an uncovered rule but **exits 1 for an orphan**
a detector citing a catalog id that does not exist.

### 6. Promote the status

`draft` → `implemented` → `benchmarked`, and the validator enforces each:

| status | requires |
|---|---|
| `draft` | **no** detector may implement it |
| `implemented` | a detector references it |
| `benchmarked` | a detector **and** a row for its family in `docs/benchmark-results.md` |

So land as `implemented`, then regenerate the results file and promote:

```sh
PATH="$PWD/.venv/bin:$PATH" .venv/bin/python bench/mutate.py --markdown docs/benchmark-results.md
```

The rule table in `README.md` is generated by `catalog/table.py` and gated in CI, so there
is nothing to add by hand. Regenerate it and paste the output over the existing table.

## House style

**Every finding carries evidence.** A `file:line` with the quoted source line, or a structural
fact (two hashes, an absent condition key). A finding without evidence is an assertion, and
unverified assertions are the thing this tool exists to catch.

**Comments explain why, not what.** The valuable comments in this codebase record the incident
that produced the code, which false positive, which repository, which wrong assumption. If you
fix a misfire, say what it fired on.

**Prefer the gap to the fabrication.** A missed finding is a gap. A false positive wastes a
security engineer's time and discredits every other finding in the report.

## Reporting a false positive

Open an issue with the rule id, the `file:line` it fired on, and the source it fired on. If the
code is public, a link is enough. These get priority.

## Fuzzing the Rust core

Anything that reads bytes someone else produced is fuzzed. `cargo-fuzz` needs nightly, so
it is not part of the per-pull-request gate, `.github/workflows/fuzz.yml` runs it nightly
and on demand.

```sh
cargo install cargo-fuzz
cd core
cargo +nightly fuzz run <target> fuzz/corpus/<target> fuzz/seeds/<target> -- -max_total_time=300
```

Targets are `eif`, `cpio`, `decompress`, and `secrets`.

Two things to know before you touch it:

**The first corpus directory is writable, the second is read-only.** `cargo fuzz run eif
fuzz/seeds/eif` writes libFuzzer's evolved corpus *into* the seed directory. That turned a
curated 8-file corpus into 1985 files the first time it was run that way.

**Seeds are carved from the built fixtures, not invented.** `bench/fixtures/build.py`
produces real EIFs; the seeds are those files and the ramdisk sections carved out of them.
Seeded, the EIF target reaches coverage 6655. Unseeded it reaches 88, random bytes almost
never produce the `.eif` magic, so an unseeded run tests the magic check and nothing behind
it, while looking exactly like a passing run.

A new crash arrives as a file in `core/fuzz/artifacts/<target>/`. Reproduce it with
`cargo +nightly fuzz run <target> <that file>`, then add it to `fuzz/seeds/<target>/` with
the fix so it stays covered.
