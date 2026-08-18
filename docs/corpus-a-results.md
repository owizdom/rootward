# Corpus A — real repositories

Deterministic layer only (no model calls). Reproduce with:

```
.venv/bin/python bench/corpus.py
```

| repo | ref | platform | layer | findings | rules |
|---|---|---|---|---|---|
| dstack | `be9d0476a63e` | dstack | 0/4 | 14 | T07D×4, T03C×3, T07A×2, T10×2, DS04×1, T00A×1, T07C×1 |
| meta-dstack | `5b63aec337f1` | dstack | 1/4 | 1 | DS01×1 |
| aws-nitro-enclaves-samples | `93b0851e44d7` | nitro | 0/3 | 19 | CFG04×7, T07D×5, T07A×4, T01×2, T03×1 |
| aws-nitro-enclaves-sdk-c | `cd61b6187c8b` | nitro | 3/3 | 9 | CFG04×7, CFG01×2 |
| attestation-doc-validation | `494131dcbe48` | nitro | 3/3 | **0** | — |
| vanta | `e8d274f60526` | eigencompute | 0/3 | 23 | T03×9, T10×6, T07C×5, CS02×2, T04B×1 |
| bobIsAlive | `7de5b965e95a` | eigencompute | 0/3 | 13 | EC02×2, T03×3, EC01×1, EC04×1, EC07×1, EC08×1, CS01×1, CS02×1, T07C×1, CFG04×1 |
| eigenbox | `cefb8782a1fc` | eigencompute | 3/3 | **0** | — |
| swarm-mindv2 | `709241b0f721` | eigencompute | 0/3 | 15 | T03×4, CFG04×3, EC05×3, EC02×2, CS01×1, CS02×1, T01×1 |
| eigen-hotcold-lotto | `e87da7bbdaa6` | eigencompute | 0/3 | 5 | CFG04×2, EC03×1, EC07×1, T09B×1 |
| eigencompute-secure-DB | `95e8bf34c9d1` | eigencompute | 2/3 | 3 | CFG04×1, T07C×1, T10×1 |

Audit time is 2–8 seconds per repository. `layer` is capped at a **per-platform**
verifiable ceiling: only rules that could apply to the detected platform count toward a
layer's requirements. Nitro reaches 3, dstack 4, EigenCompute 3, and no platform reaches
5–6 because the catalog has no rules there. Nitro previously showed 4, which was wrong —
it was borrowing dstack's layer-4 rules, which can never fire on a Nitro repository.

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
at layer 3/3.** Getting there took five distinct fixes, every one of them a rule firing on
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

**`CFG04` (build determinism) dominates by count** — 21 of 102 findings across six repos. It
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

## EigenCompute — verified by hand

Six deployed applications. They are the author's own repositories, which is worth saying
plainly: it makes the corpus easy to assemble and it means these findings were not
adversarially selected. It does not make them softer. The EC01 finding below was checked
against source before it was written down, and three of the four EC01 findings the first
version of the rule produced were false positives that were fixed rather than published.

### BT-EC01 — signing key derived from a public value

`bobIsAlive/agents/tee.ts:394-410`, at the audited commit:

```ts
export function deriveTEEWalletKey(): string | null {
  if (!teeActive || !kmsPublicKey) return null;
  const ikm = crypto.createHash("sha256").update(kmsPublicKey).digest();
  const salt = Buffer.from("bob-is-alive-starknet-wallet-v1");
  const info = Buffer.from("starknet-signing-key");
  const prk = crypto.createHmac("sha256", salt).update(ikm).digest();
  const derivedKey = crypto.createHmac("sha256", prk)
    .update(Buffer.concat([info, Buffer.from([1])]))
    .digest();
  return "0x" + derivedKey.toString("hex");
}
```

The keying material is `kmsPublicKey` — a **public** key. And in fallback mode, `tee.ts:184`:

```ts
if (!teeActive && process.env.EIGENCOMPUTE_INSTANCE_ID) {
  teeActive = true;
  kmsPublicKey = `eigencompute-instance:${process.env.EIGENCOMPUTE_INSTANCE_ID}`;
}
```

…the keying material is a literal string built from the instance id, which `getTEEState()`
at `tee.ts:454` publishes unauthenticated on `GET /api/tee`. Both salt and info constants are
in the repository. So every input to the derivation is public, and anyone who reads that
endpoint can recompute the key.

`agents/nft.ts:42-51` substitutes this key for `STARKNET_PRIVATE_KEY` whenever
`isTEEActive()` — and `isTEEActive()` is true whenever an environment variable is set, which
is `BT-EC02` on the same file.

**Severity in context:** `ecloud.toml` sets `environment = "sepolia"`, the RPC is
`free-rpc.nethermind.io/sepolia-juno`, and swaps use AVNU's `SEPOLIA_BASE_URL`. The funds at
risk are testnet. This is a fix-before-mainnet, not a live incident — and the pattern would
be catastrophic unchanged on a mainnet deployment.

### BT-EC05 — deployer key on the command line

`swarm-mindv2/scripts/deploy-hub.sh:63` and `scripts/deploy-eigen-agents.sh:83,93`:

```sh
ecloud compute app upgrade "$HUB_APP_ID" --image-ref "$IMAGE" \
  --env-file "$TMP_ENV" --private-key "$ECLOUD_PRIVATE_KEY" --rpc-url "$ECLOUD_RPC_URL"
```

Three true positives. The same scripts hardcode `--log-visibility public`.

### BT-EC03 — sealing key defaults to zero

`eigen-hotcold-lotto/enclave/src/crypto.ts:130`:

```ts
const SEAL_KEY_HEX = process.env.SEAL_KEY || "0".repeat(64); // 32 bytes hex — dev default
```

AES-256-CBC keyed with 32 zero bytes whenever the environment does not provide one — which
on this platform is precisely the case where KMS did not release the environment.

### The negative control

`vanta` is the EigenCompute counterpart to `attestation-doc-validation`. It TLS-SPKI-pins its
price feed against `getPeerCertificate(true)`, reads `MNEMONIC` exactly once and deletes it
from `process.env`, rejects HKDF salt/info reuse, keeps its signer as a non-exported
`KeyObject` that throws on re-init, and refuses to start on an app-id mismatch. **`EC01`,
`EC02`, `EC03` and `CS01` firing there means the detector is wrong**, and `bench/corpus.py`
asserts it.

All four fired during development, and all four were detector bugs:

| rule | what it flagged | why it was wrong |
|---|---|---|
| `EC01` | `sha256Hex(bytes)`, a generic helper | public identifiers were matched in a character window near the call rather than in its arguments |
| `CS01` | `tee/src/attest.ts` | verification is delegated to the platform SDK's `AttestClient`, which is the correct path |
| `CS03` | a `JwtProvider` cache refresh | it serves the previously verified bundle on a failed refresh; not a boot-time fail-open |
| `EC03` | `TOKEN_BUDGET_PER_AGENT \|\| "50000"` | a token *budget* is a number, and `KEY`/`TOKEN` as substrings match far more than credentials |

`CS02` still fires on vanta, twice, and that one is real as far as this tool can see: it pins
the app id and the KMS public key hash but never compares `hwmodel`, `swname`, `secboot` or
`tcbstatus`. Whether the SDK checks them internally is not visible from the repository, which
is what the rule's `false_positives` field says and why it ships at medium confidence.

### Gaps this corpus makes measurable

**`eigenbox` reports zero findings, and that is not a clean bill of health.** It is a
TEE-side gateway that signs every response with a secp256k1 key derived from `MNEMONIC` and
emits `X-Eigen-Signature` headers. There is no hardware attestation anywhere in it: no
metadata-server call, no JWT, no quote. The signature is real and what it proves is only
that whoever holds the key signed it. The catalog has no rule for *"this presents itself as
attestation and is not"*, so the repository is structurally unreachable — the same shape as
`meta-dstack` being quiet because there are no OS-image rules.

**`eigen-hotcold-lotto` holds a defect no pattern will find.** The enclave seals a 12-digit
target and returns the exact numeric distance to each guess, so two guesses determine it —
the repository's own `STEPS.md` documents the three-guess win. Information disclosure through
an intended API is a design property, not a code pattern.

**`T07D` and `T10` remain untriaged.** Six `T10` findings on vanta and one on
`eigencompute-secure-DB` have not been read line by line and should not be counted as true
positives on the strength of this table.

## What this run does not show

- **No precision or recall figure for real repositories.** Ground truth does not exist for
  them; that is what the mutation corpus (`docs/benchmark-results.md`) and the external
  comparison (`docs/dstack-vs-zksecurity.md`) are for. Of 102 findings across eleven
  repositories, 7 are verified true positives, 0 are known false positives that survived,
  and the rest are unreviewed.
- **The semantic rules did not run.** This is the deterministic layer only — see
  `docs/ablation.md` for what the model layer adds.
- Everything in the report's NOT VERIFIED section applies: no deployed configuration, no
  runtime behaviour, no hardware attacks.
