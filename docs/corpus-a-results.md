# Corpus A — first run against real repositories

Deterministic layer only (no model calls). Reproduce with:

```
.venv/bin/python bench/corpus.py
```

| repo | ref | platform | layer | findings | rules |
|---|---|---|---|---|---|
| aws-nitro-enclaves-workshop | `93b0851e44d7` | nitro | 0/4 | 14 | CFG04×7, T07A×4, T01×2, T03×1 |
| aws-nitro-enclaves-sdk-c | `cd61b6187c8b` | nitro | 4/4 | 9 | CFG04×7, CFG01×2 |
| attestation-doc-validation | `494131dcbe48` | nitro | 2/4 | 1 | T07C×1 |
| dstack | — | — | — | — | clone failed (network) |

Audit time was ~2s per repository. `layer` is capped at a verifiable ceiling of 4 because
the catalog carries no rules for layers 5–6 — see the scorecard note in the report.

## Verified by hand

Two findings on the AWS workshop samples were checked against the source rather than taken
on trust. Both are true positives.

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

`attestation-doc-validation` (Evervault) is a correct attestation validator, so BT-T06
firing there means the detector is wrong, not the repository. On the first run it fired
three times, alongside four other false positives.

All five distinct false-positive causes came from the same mistake — treating text that
mentions security as evidence of security:

| cause | example |
|---|---|
| TypeScript declaration files | `index.d.ts`, which contains no implementation at all |
| test files | `__test__/index.spec.mjs`, `tests/test_attestation.py` |
| FFI binding shims | a struct field `pcr0: Option<String>`, a `wasm_bindgen` getter |
| enum comparison | `attestation_document.digest == Digest::SHA384` — matched because "digest" is in the secret-name regex, but this compares an algorithm identifier |
| delegation to an audited library | bindings importing `validate_expected_pcrs` from the core crate, flagged for not re-implementing checks the crate performs |

After the fixes: **9 findings → 1**, and the layer score rose from 1/4 to 2/4 as the
spurious caps dropped away. Recall on the mutation benchmark stayed at 17/17 and the fixture
suite stayed clean, so none of this was bought with precision-for-recall trades.

The one remaining finding is `matching_nonce == expected_nonce` in
`attestation_doc.rs:141`. A nonce is chosen by the verifier and is not secret, so timing
leakage there reveals nothing an attacker does not already know. This is the documented
false-positive class in the rule's own `false_positives` field: BT-T07C is deliberately
tuned toward recall, because constant-time comparison of a public value costs nothing while
a missed timing oracle is recoverable byte by byte.

## What this run does not show

- **No precision or recall number for real repositories.** Only two findings were verified
  by hand. The honest summary is "24 findings across three repos, 2 confirmed true
  positives, 1 known-class false positive, 21 unreviewed".
- **dstack did not run.** Its clone failed on a transient network error; retry logic has
  since been added. dstack is the external-validation target, since zkSecurity published an
  independent audit of it — that comparison is still outstanding.
- **The semantic rules did not run.** This was the deterministic layer only.
- Everything in the report's NOT VERIFIED section applies: no deployed configuration, no
  runtime behaviour, no hardware attacks.
