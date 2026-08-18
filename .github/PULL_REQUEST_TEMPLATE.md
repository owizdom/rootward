## What this changes

<!-- One or two sentences. -->

## Checklist

If this adds or changes a rule (see [CONTRIBUTING.md](../CONTRIBUTING.md)):

- [ ] Catalog entry with a `source` URI and a real `false_positives` note
- [ ] Detector wired in, and visible to `catalog/coverage.py`
- [ ] **Vulnerable fixture** — the rule fires on it
- [ ] **Clean fixture** — the rule is silent, and the tree audits to **zero**
- [ ] Added to `must_find` for its tree, and to `FOREIGN` for every other tree
- [ ] Mutants in `bench/mutate.py`, ideally three shapes, with `base=` naming the tree
- [ ] `status` reflects reality (`benchmarked` only once it has a benchmark row)
- [ ] Coverage table in `README.md` updated

Always:

- [ ] `catalog/validate.py` and `catalog/coverage.py` pass
- [ ] `bench/test_fixtures.py` passes — **zero findings on every clean tree**
- [ ] `bench/mutate.py` passes at 100% recall
- [ ] `cargo test` and `cargo clippy -- -D warnings` pass, if Rust changed

## If this fixes a false positive

What did it fire on, and why was that code correct? That belongs in the commit message and
usually in the rule's `false_positives` field.
