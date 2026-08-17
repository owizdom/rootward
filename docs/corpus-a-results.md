# Corpus A — real repositories

Deterministic layer only (no model calls). Reproduce with:

```
.venv/bin/python bench/corpus.py
```

| repo | ref | platform | layer | findings | rules |
|---|---|---|---|---|---|
| dstack | `be9d0476a63e` | dstack | 0/4 | 14 | T07D×4, T03C×3, T07A×2, T10×2, DS04×1, T00A×1, T07C×1 |
| meta-dstack | `5b63aec337f1` | dstack | 1/4 | 1 | DS01×1 |
| aws-nitro-enclaves-workshop | `93b0851e44d7` | nitro | 0/4 | 19 | CFG04×7, T07D×5, T07A×4, T01×2, T03×1 |
| aws-nitro-enclaves-sdk-c | `cd61b6187c8b` | nitro | 4/4 | 9 | CFG04×7, CFG01×2 |
| attestation-doc-validation | `494131dcbe48` | nitro | 4/4 | **0** | — |

Audit time is 2–8 seconds per repository. `layer` is capped at a verifiable ceiling of 4
because the catalog carries no rules for layers 5–6 — see the scorecard note in the report.

## Verified by hand

Two findings on the AWS workshop samples were checked against source rather than taken on
trust. Both are true positives.

### BT-T01 — KMS policy releases key material with no attestation condition

`resources/code/my-first-enclave/cryptographic-attestation/key_policy_template.json`

```json
{
    "Sid": "Enable Development Environment to Decrypt",
    "Effect": "Allow",
    "Principal": { "AWS": "AWS_PRINCIPAL" },
    "Action": "kms:Decrypt",
    "Resource": "*"
}
```

No `kms:RecipientAttestation:*` condition anywhere in the document, and a second statement
grants `kms:*`. A correctly signed attestation from *any* enclave satisfies this policy,
including one running replaced code — which is the entire failure BT-T01 describes.

**Caveat worth stating:** this is a workshop *template*, and teaching material legitimately
starts from a working baseline and hardens it in later steps. The finding is accurate about
what the file contains; whether it is a defect depends on whether the workshop ever adds the
condition. Sample code is disproportionately worth auditing precisely because it gets copied
into production by people who skip the later steps.

### BT-T03 — decrypted plaintext printed inside the enclave

`resources/code/my-first-enclave/cryptographic-attestation/server.py:75`

```python
plaintext = get_plaintext(credentials)
print(plaintext)
```

`get_plaintext` returns KMS-decrypted content. Inside a Nitro enclave stdout crosses the
trust boundary to the parent — which the threat model treats as hostile — so this is the
handbook's Threat 3 verbatim, in code written to be copied.

## The negative control

`attestation-doc-validation` (Evervault) is a correct attestation validator, so `BT-T06`
firing there means the detector is wrong, not the repository. **It now reports zero findings
at layer 4/4.** Getting there took five distinct fixes, every one of them a rule firing on
correct code:

| cause | example |
|---|---|
| TypeScript declaration files | `index.d.ts`, which contains no implementation at all |
| test files | `__test__/index.spec.mjs`, `tests/test_attestation.py` |
| FFI binding shims | a struct field `pcr0: Option<String>`, a `wasm_bindgen` getter |
| enum comparison | `attestation_document.digest == Digest::SHA384` — matched because "digest" was in the secret-name regex, but this compares an algorithm identifier |
| delegation to an audited library | bindings importing `validate_expected_pcrs` from the core crate, flagged for not re-implementing checks the crate performs |

The tool went from 9 findings to 0 on this repository across those fixes, while mutation
recall stayed at 100% — the precision was not bought with recall.

## Corpus findings by rule, and what they are worth

**`CFG04` (build determinism) dominates by count** — 14 of 43 findings across two repos. It
is the lowest-severity rule in the catalog and fires on any floating base image or unpinned
package. Accurate, and worth reading last.

**`T07D` (replay protection) is new and untriaged** — 9 findings across dstack and the AWS
samples. It is a `hybrid` rule shipping at LOW confidence when a handler carries no freshness
token at all, precisely because an idempotent read-only handler legitimately needs none.
These need a human before any of them counts.

**`T00A` on dstack** is the rule written *because* the zkSecurity comparison showed the tool
missing their finding #02. It now fires on that repository. Whether it lands on the same call
site they identified has not been verified line-for-line and should not be claimed.

**meta-dstack returns almost nothing (1 finding), and that is the expected result.** Five of
zkSecurity's fourteen findings live in that repository — including the only High, OVMF built
with Config-A leaving the VMM inside the TCB — and every one is about Yocto recipes and
firmware build configuration. The catalog has no rule class for that. Auditing the repo makes
the gap measurable instead of assumed, which is the only reason it is in the corpus.

## What this run does not show

- **No precision or recall figure for real repositories.** Ground truth does not exist for
  them; that is what the mutation corpus (`docs/benchmark-results.md`) and the external
  comparison (`docs/dstack-vs-zksecurity.md`) are for. Of 43 findings here, 2 are verified
  true positives, 0 are known false positives, and 41 are unreviewed.
- **The semantic rules did not run.** This is the deterministic layer only — see
  `docs/ablation.md` for what the model layer adds.
- Everything in the report's NOT VERIFIED section applies: no deployed configuration, no
  runtime behaviour, no hardware attacks.
