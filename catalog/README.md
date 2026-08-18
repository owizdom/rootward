# Rule catalog

42 rules. Each is one YAML file whose name equals its `id`, so any finding in a report can be traced
to its rule with `cat catalog/rules/<id>.yaml`.

Validate with:

```
uv run --with pyyaml --with jsonschema catalog/validate.py
```

The validator is the gate. It fails on a missing `source`, a missing `false_positives`, a filename
that disagrees with the `id`, or a duplicate id.

## Fields that carry weight

**`source`** — required, must be an https URL. The handbook section the rule derives from. A rule
nobody can trace to a source is an opinion, and this project's whole premise is that opinions are
what get TEE protocols rekt.

**`source_secondary`** — present on every rule that would still ship if the handbook did not exist.
`BT-T07C` (constant-time comparison) cites CWE-208 and the `subtle` crate; `BT-T06` cites the AWS
attestation process docs and Evervault's validator. Rules with only a handbook citation are the ones
resting on one firm's framework, and that distinction should stay visible.

**`layer_required`** — the lowest [handbook layer](https://bluethroatlabs.com/docs/layers-of-security-for-tees)
(0–6) that requires this rule to pass. This is what drives the scorecard: the effective layer is the
highest one whose prerequisites all hold. It is why `BT-T07C` sits at layer 3 (constant-time crypto
is what Layer 3 *is*) while `BT-T01` sits at layer 2 (attestation).

**`false_positives`** — required, minimum 20 characters, and not a formality. A rule whose author
cannot name its failure mode has not been thought through, and unreviewed rules inflate exactly the
false-positive rate the benchmark exists to measure.

**`confidence`** — expected precision, set *before* benchmarking. P4 measures the real number.
Divergence between the two is itself a result worth publishing.

**`detection`** — `deterministic` (parse/AST/grep, no model call), `semantic` (needs judgment), or
`hybrid` (deterministic prefilter, semantic adjudication). Current split: 32 deterministic / 6 hybrid / 4 semantic.

## Deliberately not encoded

The handbook's implementation-overhead scores (7/10, 9/10, 9.8/10) and cost figures
(~$250K/month for a hybrid architecture) are editorial judgments, not measurable properties. Turning
them into checks would be precisely the theorizing this tool exists to catch.

Hardware attacks — the entire attack-categorisation table — are out of scope. Not because they do
not matter, but because no static analyzer can see them, and a tool that implies coverage it does
not have is worse than one with an honest gap.

## Adding a rule

1. Copy the closest existing rule; keep the id scheme (`BT-T##`, `BT-CFG##`, `BT-DS##`, `BT-LYR##`).
2. Cite a real source. If it is defensible outside the handbook, cite that too.
3. Write `false_positives` honestly, before writing the detector.
4. Add a positive and a negative fixture under `bench/fixtures/`. A rule that fires on its own
   negative fixture does not ship.
5. Run the validator.
