# tee-audit

Static auditor for Web3 protocols built on cloud TEEs — AWS Nitro Enclaves and dstack.

> **Status: detection works, benchmark does not exist yet.** All 19 deterministic rules are
> implemented and pass against fixtures (16 rule families found on the vulnerable trees, 0
> false positives on the clean ones). That is a fixture result, not a benchmark — no
> precision/recall number over real repositories has been measured, so no detection-rate
> claim is made. See [Build status](#build-status).

## Why

The [Bluethroat Labs TEE Security Handbook](https://bluethroatlabs.com/docs/executive-summary) makes
one argument throughout: Web3 TEE protocols do not get rekt by hardware attacks. Its scope page says
so directly — hardware attack research is out of scope because "hardware attacks are not what
actually causes Web3 TEE protocols to get rekt." The real failures are attestation verification
gaps, trusting the parent instance, metadata leakage, timing oracles, hardcoded credentials, and KMS
misconfiguration. The handbook estimates most active Web3 TEE projects carry three to five of these
at once.

Nearly all of them are visible in a repository — in source, Dockerfiles, KMS key policies, and the
built EIF image. That is what this tool looks for.

## Design

**Deterministic detectors first, model second.** Of the 29 catalogued rules, 19 need no model call:
they are parse, AST, or binary-format checks. Six are hybrid, and four require genuine judgment
(trust-boundary reasoning, TCB bloat, metadata leakage, layer classification). Spending a model call
on something `semgrep` decides correctly is how a tool ends up slow, expensive, and less precise
than the thing it wrapped.

**Every finding carries evidence.** A `file:line` with quoted source, or two hashes. Findings from
the semantic layer go through an adversarial pass — an independent agent that tries to *refute*
them — before reaching the report. Findings that survive are `CONFIRMED`; findings that cannot be
confirmed or refuted ship as `PLAUSIBLE`, labelled as such.

**Every report says what it could not check.** Static analysis cannot see the KMS policy actually
deployed in AWS, the runtime PCR values, or whether `--debug-mode` was used on the real launch. That
list is a mandatory report section, not an omission.

```
catalog/    29 YAML rules, each citing its source        ← the domain knowledge
core/       Rust: EIF parse, CPIO walk, PCR recompute, COSE/cert-chain
detectors/  Python: semgrep TEE ruleset, KMS policy, build config, vsock
agent/      Claude Agent SDK: the four semantic passes
verify/     adversarial refutation
report/     layer scorecard + findings + NOT-VERIFIED
bench/      corpora, mutation harness, scoring
```

## Coverage

Mapped to the handbook's own threat numbering. `layer` is the lowest
[security layer](https://bluethroatlabs.com/docs/layers-of-security-for-tees) that requires the rule
to pass.

| Rule | Threat | Layer | Detection |
|---|---|---|---|
| `BT-T00` parent instance trusted | 0 | 1 | semantic |
| `BT-T01` no measurement pinning | 1 | 2 | deterministic |
| `BT-T02` PCR0-only pin | 2 | 2 | deterministic |
| `BT-T03` secret reaches log sink | 3 | 1 | hybrid |
| `BT-T03B` crash dump egress | 3 | 3 | deterministic |
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

**Out of scope, deliberately.** The handbook's attack-categorisation table — Spectre, Rowhammer,
Plundervolt, EMFI, and the 2025 memory-bus attacks (WireTap, Battering RAM, TEE.fail) — is real and
matters for architecture decisions, but none of it is statically detectable. It informs the layer
scorecard as context and is never reported as a finding.

Also out of scope by design: live enclaves. No AWS credentials, no attestation fetched from a
running instance, no active probing. Repository in, report out.

## Build status

| Phase | | |
|---|---|---|
| P0 | rule catalog + schema + validator | done — 29 rules, validator enforces citations |
| P1 | Rust core: EIF, CPIO, secret scan, PCR recompute | done — 34 tests; PCRs verified against AWS's implementation |
| P2 | semgrep TEE ruleset + Python detectors | done — 19/19 deterministic rules, 0 FP on clean fixtures |
| P3 | Agent SDK harness + semantic passes + adversarial verify | written, not yet run end to end |
| P4 | benchmark: corpora, mutants, precision/recall, ablation | not started |
| P5 | report renderer + release | report done; release pending the benchmark |

```
python3 cli/audit.py <path>              # deterministic only, no model calls
python3 cli/audit.py <path> --semantic   # + the four judgment rules, adversarially verified
uv run --with pyyaml bench/test_fixtures.py   # regression gate
uv run --with pyyaml catalog/coverage.py      # what is catalogued vs implemented
```

## Benchmark

Detection rates get measured, not asserted. Three corpora: real repositories pinned by commit SHA,
synthetic mutants with ground truth by construction (so recall is measured rather than estimated),
and clean baselines for the false-positive rate. Reported per rule, alongside an ablation of the
model layer against deterministic-only — if `semgrep` alone matches the full pipeline on a threat
class, that gets published and the model call gets dropped.

External validation: zkSecurity audited dstack in May–June 2025 and published their findings.
Running against the pre-fix commit gives ground truth this project did not author. What it re-finds
is a result; what it misses gets written up as a gap.

## License

Apache-2.0.

The rule catalog is derived from the Bluethroat Labs TEE Security Handbook, which is cited per rule
in the `source` field. It is an independent implementation, not affiliated with or endorsed by
Bluethroat Labs.
