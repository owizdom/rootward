# tee-audit

Static auditor for Web3 protocols built on cloud TEEs — AWS Nitro Enclaves and dstack.

```
python3 cli/audit.py ./repo                 # deterministic rules, seconds, no model calls
python3 cli/audit.py ./repo --semantic      # + four judgment rules, adversarially verified
```

Reports a security-layer scorecard, ranked findings with `file:line` evidence, and a
mandatory list of what the audit could not check.

## Why

The [Bluethroat Labs TEE Security Handbook](https://bluethroatlabs.com/docs/executive-summary)
makes one argument throughout: Web3 TEE protocols do not get rekt by hardware attacks. Its
scope page says so directly — hardware attack research is out of scope because "hardware
attacks are not what actually causes Web3 TEE protocols to get rekt." The real failures are
attestation verification gaps, trusting the parent instance, metadata leakage, timing
oracles, hardcoded credentials, and KMS misconfiguration. The handbook estimates most active
Web3 TEE projects carry three to five of these at once.

Nearly all of them are visible in a repository — in source, Dockerfiles, KMS key policies,
and the built EIF image. That is what this tool looks for.

## Measured

| | result | how |
|---|---|---|
| Mutation recall | **35/35** across 15 rules | [`docs/benchmark-results.md`](docs/benchmark-results.md) |
| False positives on mutants | **0** | same |
| Clean-fixture false positives | **0** on both clean trees | `bench/test_fixtures.py` |
| Negative control (a correct validator) | **0 findings**, was 9 | [`docs/corpus-a-results.md`](docs/corpus-a-results.md) |
| PCR measurement | matches AWS's own implementation | `cargo test --features differential` |
| External validation | 1 re-find + 1 partial of 14 | [`docs/dstack-vs-zksecurity.md`](docs/dstack-vs-zksecurity.md) |
| Model layer vs deterministic | **0 added findings** on shared classes | [`docs/ablation.md`](docs/ablation.md) |

Mutants vary the *shape* of each defect, not just the file, because a rule that recognises
only its author's idiom scores full recall against one mutant and then misses the same bug in
real code. Adding shape variation dropped recall from a flattering 17/17 to 32/35 and exposed
a genuine gap in the certificate-chain rule.

**The most useful thing this project produced is not a detection rate.** It is
[`docs/when-the-verifier-is-wrong.md`](docs/when-the-verifier-is-wrong.md): the adversarial
verification layer confidently deleted a true positive with a fluent, well-cited, and
completely invalid cryptographic argument. It was caught only because an independent audit
existed to grade against.

## Design

**Deterministic detectors first, model second.** Of 31 catalogued rules, 21 need no model
call — they are parse, AST, or binary-format checks. Six are hybrid, four require genuine
judgment.

The [ablation](docs/ablation.md) measured that split across five real repositories, and the
result is blunt: **on every threat class both layers implement, the model layer found nothing
the deterministic layer missed.** Zero, across all 20 passes. Deterministic runs finish in
2–4 seconds; the same audits with `--semantic` take 6–14 minutes and cost real money.

So `--semantic` is worth paying for exactly four rules — the ones no pattern matcher can
implement (T00 trust boundary, T05 TCB bloat, T08 metadata leakage, LYR01 claim-vs-code) —
and is wasted everywhere else. That is the recommendation the tool makes about itself.

**Every finding carries evidence.** A `file:line` with quoted source, or two hashes. Semantic
findings go through an adversarial pass — an independent agent that tries to *refute* them.
Survivors are `CONFIRMED`; findings that cannot be confirmed or refuted ship as `PLAUSIBLE`,
labelled; refuted ones are dropped and kept in the run log.

**Every report says what it could not check.** Static analysis cannot see the KMS policy
actually deployed in AWS, the runtime PCR values, or whether `--debug-mode` was used on the
real launch. That list is a mandatory report section, computed from what the run actually
did rather than hand-written.

```
catalog/    31 YAML rules, each citing its source        ← the domain knowledge
core/       Rust: EIF parse, CPIO ramdisk walk, PCR recompute, secret scan
detectors/  semgrep TEE ruleset + KMS policy, build config, vsock, streams, dstack
agent/      Claude Agent SDK: the four semantic passes + adversarial refutation
cli/        orchestration and the report
bench/      fixtures, mutation harness, real-repo corpus, ablation
```

## Coverage

Mapped to the handbook's own threat numbering. `layer` is the lowest
[security layer](https://bluethroatlabs.com/docs/layers-of-security-for-tees) that requires
the rule to pass; failing one caps the protocol below it.

| Rule | Threat | Layer | Detection |
|---|---|---|---|
| `BT-T00` parent instance trusted | 0 | 1 | semantic |
| `BT-T00A` host path followed through a symlink | 0 | 1 | deterministic |
| `BT-T01` no measurement pinning | 1 | 2 | deterministic |
| `BT-T02` PCR0-only pin | 2 | 2 | deterministic |
| `BT-T03` secret reaches log sink | 3 | 1 | hybrid |
| `BT-T03B` crash dump egress | 3 | 3 | deterministic |
| `BT-T03C` output stream exposed by configuration | 3 | 1 | deterministic |
| `BT-T04A` host-supplied entropy | 4 | 1 | deterministic |
| `BT-T04B` host-supplied time | 4 | 1 | deterministic |
| `BT-T05` TCB bloat | 5 | 1 | semantic |
| `BT-T06` no cert chain to AWS root | 6 | 2 | deterministic |
| `BT-T06B` TLS verification disabled | 6 | 2 | deterministic |
| `BT-T07A` vsock without timeout | 7 | 1 | deterministic |
| `BT-T07B` error differential oracle | 7 | 1 | deterministic |
| `BT-T07C` non-constant-time compare | 7 | 3 | deterministic |
| `BT-T07D` no replay protection | 7 | 1 | hybrid |
| `BT-T08` metadata leakage | 8 | 3 | semantic |
| `BT-T09A` secret in EIF ramdisk | 9 | 1 | deterministic |
| `BT-T09B` secret in Dockerfile | 9 | 1 | deterministic |
| `BT-T10` unauthenticated relayed data | 10 | 1 | hybrid |
| `BT-CFG01`–`CFG05` | — | 2 | debug mode, zero PCRs, PCR/policy diff, build determinism, key rotation |
| `BT-DS01`–`DS05` | — | 2–4 | dstack: code governance, key derivation, KMS mode, RTMR policy, gateway binding |
| `BT-LYR01` layer scorecard | — | — | semantic |

Every rule cites its source, states when it is wrong (`false_positives` is a required field),
and carries a status the validator checks against reality — a rule claiming `benchmarked`
with no row in the benchmark results fails the build.

**Out of scope, deliberately.** The handbook's attack-categorisation table — Spectre,
Rowhammer, Plundervolt, EMFI, and the 2025 memory-bus attacks (WireTap, Battering RAM,
TEE.fail) — is real and matters for architecture decisions, but none of it is statically
detectable. It informs the layer scorecard as context and is never reported as a finding.

Also out of scope by design: live enclaves. No AWS credentials, no attestation fetched from a
running instance, no active probing. Repository in, report out.

## Known gaps

- **No OS-image or firmware build rules.** Five of zkSecurity's fourteen dstack findings live
  in `meta-dstack` and concern Yocto recipes and OVMF configuration, including the only High.
  The corpus audits that repository specifically so the gap is measured rather than assumed.
- **`BT-T08` (metadata leakage) has low static recall by construction.** Response-size and
  timing correlation is a runtime distribution; static analysis sees the encoder.
- **Deployment configuration is unreachable.** The KMS policy in a repository is not
  necessarily the policy attached to the live key.
- **`BT-T07D` and `BT-T10` are new and largely untriaged** on real code — they ship at LOW
  confidence for exactly that reason.

## Setup

```
uv venv && uv pip install -e '.[all]'     # semgrep + claude-agent-sdk are optional extras
cd core && cargo build --release --bins    # the Rust core
.venv/bin/python bench/fixtures/build.py   # generate the binary fixtures
```

The tool degrades rather than fails when an optional piece is missing: no semgrep means the
code-pattern rules do not run, and the report says so in its NOT VERIFIED section.

## Verification

```
cd core && cargo test                        # 34 tests
cargo test --features differential           # PCRs vs AWS's own implementation
.venv/bin/python catalog/validate.py         # citations, false-positive notes, status accuracy
.venv/bin/python bench/test_fixtures.py      # recall + zero FP on clean trees
.venv/bin/python bench/mutate.py             # per-rule precision and recall
.venv/bin/python bench/corpus.py             # real repos + negative control
.venv/bin/python bench/ablation.py           # model layer vs deterministic-only
```

## License

Apache-2.0.

The rule catalog is derived from the Bluethroat Labs TEE Security Handbook, cited per rule in
each rule's `source` field. This is an independent implementation, not affiliated with or
endorsed by Bluethroat Labs. The dstack comparison uses
[zkSecurity's published audit](https://phala.com/dstack/dstack-audit.pdf) as external ground
truth; that work is theirs.
