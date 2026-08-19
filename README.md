# rootward

[![ci](https://github.com/owizdom/rootward/actions/workflows/ci.yml/badge.svg)](https://github.com/owizdom/rootward/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![platforms](https://img.shields.io/badge/platforms-Nitro%20%7C%20dstack%20%7C%20EigenCompute%20%7C%20Confidential%20Space-informational)](#rules)

rootward is a static auditor for Web3 protocols built on cloud TEEs. Point it at a
repository and it reads everything that decides whether the enclave actually holds: source,
Dockerfiles, deployment manifests, KMS key policies, the Yocto and EDK II recipes the image
was built from, and the built enclave image itself. It reports a security-layer scorecard,
ranked findings with `file:line` evidence, and a mandatory list of what it could not check.

Most of its 46 rules are deterministic and finish in seconds with no model calls. The
handful that need genuine judgment run behind `--semantic`, and every one of those is put
through an agent that tries to refute it before it reaches the report.

```sh
.venv/bin/python cli/audit.py ./repo              # deterministic rules, seconds, no model calls
.venv/bin/python cli/audit.py ./repo --semantic   # + five judgment passes, adversarially verified
```

## Table of Contents

- [Why](#why)
- [Features](#features)
- [Usage](#usage)
- [How to Install](#how-to-install)
  - [Using uv (recommended)](#using-uv-recommended)
  - [Using pip](#using-pip)
  - [Using Git (development)](#using-git-development)
  - [Integration](#integration)
- [Rules](#rules)
  - [Out of scope, deliberately](#out-of-scope-deliberately)
- [Measured](#measured)
- [Design](#design)
- [Known gaps](#known-gaps)
- [Verification](#verification)
- [FAQ](#faq)
- [Getting help](#getting-help)
- [License](#license)
- [References](#references)

## Why

The [Bluethroat Labs TEE Security Handbook](https://bluethroatlabs.com/docs/executive-summary)
makes one argument throughout: Web3 TEE protocols do not get rekt by hardware attacks. Its
scope page says so directly. Hardware attack research is out of scope because "hardware
attacks are not what actually causes Web3 TEE protocols to get rekt." The real failures are
attestation gaps, trusting the parent instance, metadata leakage, timing oracles, hardcoded
credentials, and KMS misconfiguration, and it estimates most active projects carry three to
five at once.

The attention goes to the attacks with names and logos. The things that break real
deployments are ordinary defects in plain sight: a Dockerfile that pins nothing, a KMS
policy that checks PCR0. Almost all of them are visible in the repository.

So the handbook is a good threat model that gets read once. rootward exists to make it
something you run.

**For an auditor**, it does the mechanical first pass in seconds: which PCRs the policy
pins, where the attestation document is verified, whether the vsock listener has a timeout.
Every answer arrives with a `file:line` and the quoted source, every rule declares in its
own YAML when it is wrong, and every report ends with what it structurally could not check,
so a clean result never quietly means "did not look."

**For a team shipping one**, it catches the slow failure: audited once, and eleven months
later the base image is unpinned again and a debug flag came back for an incident and
stayed. In CI those are pull-request comments via SARIF, on the offending line.

It is not a replacement for an audit. It finds catalogued defects and does not reason about
your protocol. It clears the floor so a human starts above it.

## Features

- **46 catalogued rules**, each citing its handbook section, each with a required
  `false_positives` field saying when it is wrong.
- **Four platforms**: AWS Nitro Enclaves, dstack, EigenCompute, and Google Cloud
  Confidential Space, gated in both directions so a Nitro report never carries dstack noise.
- **Binary image analysis** in Rust: EIF parse, CPIO ramdisk walk, PCR recomputation, and a
  secret scan of the image contents, checked against AWS's own implementation.
- **Firmware and OS-image rules** that read BitBake recipes and EDK II build targets, not
  just application code.
- **Evidence on every finding**: `file:line` with the quoted source, or two hashes.
- **A mandatory NOT VERIFIED section**, computed from what the run actually did, so a report
  can never imply it checked something it skipped.
- **A security-layer scorecard** mapped to the handbook's own layer model; failing one rule
  caps the protocol below that layer.
- **An optional semantic layer** for the five rules no pattern matcher can implement, with an
  adversarial pass that tries to refute each finding before it ships.
- **Measured, not asserted**: 83/83 mutation recall, zero false positives on four clean
  fixture trees, and an external comparison against a published third-party audit.
- **CI-ready**: a GitHub Action, SARIF output that lands findings on the pull-request diff,
  and exit codes that distinguish a clean repository from a broken scanner.
- **An enforced sandbox on the semantic layer**: every tool call is checked against the
  audit root by a `PreToolUse` hook before it runs, symlinks resolved, unknown tools denied.
- **Fuzzed binary parsers**: four cargo-fuzz targets over the EIF, CPIO, decompression and
  secret-scanning paths, seeded from the real fixtures.

## Usage

```sh
.venv/bin/python cli/audit.py ./repo
```

Deterministic rules only: parse, AST, semgrep, and binary-format checks. No model calls, no
network, 2–4 seconds on a typical repository.

```sh
.venv/bin/python cli/audit.py ./repo --semantic
```

Adds the five judgment passes (trust boundary, TCB bloat, metadata leakage, claim-vs-code,
and key rotation), each of which is put through an independent agent that tries to refute it.
Survivors are `CONFIRMED`, findings that can be neither confirmed nor refuted ship as
`PLAUSIBLE` and are labelled, and refuted ones are dropped and kept in the run log. This takes
6–14 minutes and costs money; [the ablation](docs/ablation.md) explains when it is worth it.

```sh
.venv/bin/python cli/audit.py ./repo --format json      # machine-readable
.venv/bin/python cli/audit.py ./repo --fail-on high     # exit 2 on a High or above
```

Run it from a clone. There is no `pip install`: the tool resolves its rule catalog, its
semgrep ruleset and its Rust binary relative to its own location.

## How to Install

**Requirements:** Python 3.11+, Rust 1.88+ (1.94.1+ only for the optional differential test).

### Using uv (recommended)

```sh
git clone https://github.com/owizdom/rootward && cd rootward

uv venv
uv pip install pyyaml jsonschema semgrep         # semgrep is optional but recommended

(cd core && cargo build --release --bins)        # the Rust core
.venv/bin/python bench/fixtures/build.py         # generate the binary fixtures
```

Order matters: `bench/fixtures/build.py` measures the built EIF to derive the clean fixture's
KMS policy, so the Rust core has to exist first. It exits loudly rather than silently
skipping if you get that wrong.

### Using pip

```sh
git clone https://github.com/owizdom/rootward && cd rootward
python3 -m venv .venv
.venv/bin/pip install pyyaml jsonschema semgrep
(cd core && cargo build --release --bins)
.venv/bin/python bench/fixtures/build.py
```

### Using Git (development)

Add `claude-agent-sdk` only if you want `--semantic`; 36 of 46 rules never make a model call.

The tool degrades rather than fails when an optional piece is missing: no semgrep means the
code-pattern rules do not run, and the report says so in its NOT VERIFIED section.

See [CONTRIBUTING.md](CONTRIBUTING.md) for what a new rule has to carry before it is accepted.

### Integration

```yaml
- uses: owizdom/rootward@v0.2.1
  with:
    path: .
    fail-on: high
```

Pin the tag, not `@main`. `@main` moves under you, which is the defect this tool reports
as `BT-CFG04`.

Findings land inline on the pull-request diff via SARIF, so a hardcoded mnemonic shows up as
a review comment on the offending line rather than in a log nobody opens:

```yaml
permissions:
  security-events: write
steps:
  - uses: actions/checkout@v4
  - uses: owizdom/rootward@v0.2.1
    id: audit
    with: { path: ., fail-on: high }
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with: { sarif_file: ${{ steps.audit.outputs.sarif }} }
```

**Exit codes**, because a gate that cannot tell a broken scanner from a clean repository is
worse than no gate:

| exit | meaning |
|---|---|
| 0 | the audit ran and found nothing at or above `--fail-on` |
| 1 | the audit **could not run**: bad path, missing dependency. Never a pass. |
| 2 | the audit ran and found something at or above `--fail-on` |

`--fail-on` defaults to `never` on the CLI (so interactive use stays exit 0) and to `high` in
the Action.

## Rules

Mapped to the handbook's own threat numbering. `Layer` is the lowest
[security layer](https://bluethroatlabs.com/docs/layers-of-security-for-tees) that requires
the rule to pass; failing one caps the protocol below it. This table is generated from the
catalog by `catalog/table.py`. A rule that is not in the catalog cannot be in this list.

| # | Rule | What it detects | Threat | Layer | Severity | Confidence |
|---|---|---|---|---|---|---|
| 1 | [`T00`](catalog/rules/BT-T00-parent-instance-trusted.yaml) | Parent instance treated as trusted rather than adversarial | 0 | 1 | high | low |
| 2 | [`T00A`](catalog/rules/BT-T00A-host-path-symlink.yaml) | Host-supplied filesystem path used without rejecting symbolic links | 0 | 1 | high | medium |
| 3 | [`T01`](catalog/rules/BT-T01-no-measurement-pinning.yaml) | Attestation accepted without pinning measurements to an allowlist | 1 | 2 | critical | medium |
| 4 | [`T02`](catalog/rules/BT-T02-pcr0-only.yaml) | Policy pins PCR0 only, leaving kernel and application changes indistinguishable | 2 | 2 | high | high |
| 5 | [`T03`](catalog/rules/BT-T03-secret-egress-logging.yaml) | Decrypted data or key material reaches a log sink outside the enclave | 3 | 1 | critical | medium |
| 6 | [`T03B`](catalog/rules/BT-T03B-crash-dump-egress.yaml) | Panic, crash dump, or backtrace path can emit enclave memory to the parent | 3 | 3 | high | medium |
| 7 | [`T03C`](catalog/rules/BT-T03C-stream-exposure.yaml) | Container or process output stream exposed across the enclave boundary by configuration | 3 | 1 | high | medium |
| 8 | [`T04A`](catalog/rules/BT-T04A-host-randomness.yaml) | Entropy sourced from the parent instead of the enclave RNG | 4 | 1 | critical | medium |
| 9 | [`T04B`](catalog/rules/BT-T04B-host-time.yaml) | Security-relevant time obtained from the parent instance | 4 | 1 | high | low |
| 10 | [`T05`](catalog/rules/BT-T05-tcb-bloat.yaml) | Trusted computing base carries logic that is not confidentiality-critical | 5 | 1 | medium | low |
| 11 | [`T06`](catalog/rules/BT-T06-no-root-cert-validation.yaml) | Attestation signature checked without validating the chain to the AWS Nitro root | 6 | 2 | critical | medium |
| 12 | [`T06B`](catalog/rules/BT-T06B-tls-verification-disabled.yaml) | Certificate verification explicitly disabled on a trust-bearing connection | 6 | 2 | high | high |
| 13 | [`T07A`](catalog/rules/BT-T07A-vsock-no-timeout.yaml) | Blocking vsock read with no timeout | 7 | 1 | medium | medium |
| 14 | [`T07B`](catalog/rules/BT-T07B-error-differential.yaml) | Distinct error messages returned across the enclave boundary form a decryption oracle | 7 | 1 | high | medium |
| 15 | [`T07C`](catalog/rules/BT-T07C-timing-oracle-compare.yaml) | Non-constant-time comparison of a secret-derived value | 7 | 3 | high | high |
| 16 | [`T07D`](catalog/rules/BT-T07D-no-replay-protection.yaml) | vsock message schema carries no nonce, counter, or signed timestamp | 7 | 1 | high | low |
| 17 | [`T08`](catalog/rules/BT-T08-metadata-leakage.yaml) | Observable request metadata correlates with confidential payload contents | 8 | 3 | critical | low |
| 18 | [`T09A`](catalog/rules/BT-T09A-eif-embedded-secret.yaml) | Secret material recoverable from the built EIF ramdisk | 9 | 1 | critical | high |
| 19 | [`T09B`](catalog/rules/BT-T09B-dockerfile-secret.yaml) | Secret introduced through Dockerfile ENV, ARG, or copied build context | 9 | 1 | critical | high |
| 20 | [`T10`](catalog/rules/BT-T10-unauthenticated-parent-response.yaml) | Data relayed by the parent consumed without verifying its signature | 10 | 1 | critical | medium |
| 21 | [`CFG01`](catalog/rules/BT-CFG01-debug-mode-launch.yaml) | Enclave launched in debug mode, voiding cryptographic attestation | n/a | 2 | critical | high |
| 22 | [`CFG02`](catalog/rules/BT-CFG02-zero-pcr-accepted.yaml) | Verifier accepts an all-zero PCR map | n/a | 2 | critical | high |
| 23 | [`CFG03`](catalog/rules/BT-CFG03-pcr-policy-eif-mismatch.yaml) | PCR value pinned in KMS policy does not match the PCR recomputed from the EIF | n/a | 2 | high | high |
| 24 | [`CFG04`](catalog/rules/BT-CFG04-nondeterministic-build.yaml) | Enclave image build is not reproducible, so PCR values cannot be independently confirmed | n/a | 2 | medium | medium |
| 25 | [`CFG05`](catalog/rules/BT-CFG05-no-key-rotation.yaml) | No key rotation path, so a single compromise is permanent | n/a | 2 | medium | low |
| 26 | [`DS01`](catalog/rules/BT-DS01-no-onchain-code-governance.yaml) | dstack deployment without KmsAuth or AppAuth code governance | n/a | 2 | high | medium |
| 27 | [`DS02`](catalog/rules/BT-DS02-hardware-bound-sealing.yaml) | Keys sealed to hardware rather than derived from application identity | n/a | 4 | medium | low |
| 28 | [`DS03`](catalog/rules/BT-DS03-kms-simple-duplication.yaml) | dstack-KMS configured for simple duplication rather than threshold sharing | n/a | 4 | high | high |
| 29 | [`DS04`](catalog/rules/BT-DS04-no-rtmr-policy-check.yaml) | Measured boot values not compared against an expected policy | n/a | 2 | critical | medium |
| 30 | [`DS05`](catalog/rules/BT-DS05-gateway-no-domain-binding.yaml) | Zero Trust TLS domain binding not established for the workload | n/a | 2 | medium | low |
| 31 | [`CS01`](catalog/rules/BT-CS01-attestation-token-unverified.yaml) | Confidential Space attestation token decoded but never verified | 6 | 2 | critical | high |
| 32 | [`CS02`](catalog/rules/BT-CS02-platform-claims-unchecked.yaml) | Attestation verified but the platform claims are never compared | 1 | 2 | high | medium |
| 33 | [`CS03`](catalog/rules/BT-CS03-attestation-fail-open.yaml) | Attestation failure is caught and the workload starts anyway | 0 | 2 | high | medium |
| 34 | [`CS04`](catalog/rules/BT-CS04-attestation-without-hardware-root.yaml) | Project presents attestation with no hardware root of trust | 1 | 2 | high | medium |
| 35 | [`EC01`](catalog/rules/BT-EC01-key-from-public-input.yaml) | Signing key derived from material an observer can read | 4 | 1 | critical | high |
| 36 | [`EC02`](catalog/rules/BT-EC02-env-presence-as-attestation.yaml) | Enclave state asserted from the presence of an environment variable | 0 | 1 | high | high |
| 37 | [`EC03`](catalog/rules/BT-EC03-dev-key-fallback.yaml) | Development key or weak default reachable when the environment is unset | 9 | 1 | critical | high |
| 38 | [`EC04`](catalog/rules/BT-EC04-check-silently-disabled.yaml) | Security check disables itself or degrades to a weaker one | 1 | 2 | high | medium |
| 39 | [`EC05`](catalog/rules/BT-EC05-deploy-secret-in-argv.yaml) | Deploy secret passed as a command-line argument | 3 | 1 | high | high |
| 40 | [`EC06`](catalog/rules/BT-EC06-unauthenticated-env-dump.yaml) | Unauthenticated HTTP route enumerates the process environment | 3 | 1 | critical | medium |
| 41 | [`EC07`](catalog/rules/BT-EC07-container-runs-as-root.yaml) | EigenCompute image overrides the platform privilege drop | 5 | 1 | medium | high |
| 42 | [`EC08`](catalog/rules/BT-EC08-egress-unrestricted.yaml) | Deployment manifest does not restrict outbound traffic | 3 | 3 | medium | medium |
| 43 | [`OS01`](catalog/rules/BT-OS01-firmware-not-tdx-target.yaml) | TDX guest firmware built from the general-purpose OVMF target | 5 | 2 | high | medium |
| 44 | [`OS02`](catalog/rules/BT-OS02-secure-boot-not-enabled.yaml) | Firmware recipe defines a secure-boot option and leaves it off | 5 | 2 | medium | medium |
| 45 | [`OS03`](catalog/rules/BT-OS03-development-image-features.yaml) | Development image features reachable from a production TEE image | 5 | 1 | high | medium |
| 46 | [`LYR01`](catalog/rules/BT-LYR01-layer-scorecard.yaml) | Effective security layer versus claimed security layer | n/a | 0 | info | medium |

`BT-CS*` applies to any Google Cloud Confidential Space workload; `BT-EC*` is gated on
EigenCompute specifically; `BT-OS*` carries no platform gate at all, because an OS image
build is its own signal and a repository that does not contain one never reaches those rules.
Rules are gated by platform in both directions and the fixture suite asserts it, because a
report padded with another platform's inapplicable findings teaches the reader to skim past
the real ones. The EigenCompute security model is written up in
[`docs/eigencompute-model.md`](docs/eigencompute-model.md), read out of the `eigenx-cli`
source rather than from a docs page.

Every rule cites its source, states when it is wrong (`false_positives` is a required field),
and carries a status the validator checks against reality. A rule claiming `benchmarked`
with no row in the benchmark results fails the build.

### Out of scope, deliberately

The handbook's attack-categorisation table (Spectre, Rowhammer, Plundervolt, EMFI, and the
2025 memory-bus attacks WireTap, Battering RAM and TEE.fail) is real and matters for
architecture decisions, but none of it is statically detectable. It informs the layer
scorecard as context and is never reported as a finding.

Also out of scope by design: live enclaves. No AWS credentials, no attestation fetched from a
running instance, no active probing. Repository in, report out.

## Measured

| | result | how |
|---|---|---|
| Mutation recall | **83/83** across 30 rules | [`docs/benchmark-results.md`](docs/benchmark-results.md) |
| False positives on mutants | **0** | same |
| Clean-fixture false positives | **0** on all four clean trees | `bench/test_fixtures.py` |
| Negative control (Nitro) | **0 findings**, was 9 | [`docs/corpus-a-results.md`](docs/corpus-a-results.md) |
| Negative control (EigenCompute) | **4 rules asserted silent**, all 4 once fired | same |
| Corpus | 11 pinned repositories, 3 platforms | [`docs/corpus-a-results.md`](docs/corpus-a-results.md) |
| PCR measurement | matches AWS's own implementation | `cargo test --features differential` |
| External validation | 2 re-finds + 1 partial of 14 | [`docs/dstack-vs-zksecurity.md`](docs/dstack-vs-zksecurity.md) |
| Model layer vs deterministic | **0 added findings** on shared classes | [`docs/ablation.md`](docs/ablation.md) |

Mutants vary the *shape* of each defect, not just the file, because a rule that recognises
only its author's idiom scores full recall against one mutant and then misses the same bug in
real code. That has paid for itself twice: introducing shape variation dropped an early
17/17 to 32/35 and exposed a gap in the certificate-chain rule, and taking the newer rules
from one shape to three found three more detector bugs, including that `BT-CS02` missed
the commonest form of its own defect, claims read and logged but never compared.

**The most useful thing this project produced is not a detection rate.** It is
[`docs/when-the-verifier-is-wrong.md`](docs/when-the-verifier-is-wrong.md): the adversarial
verification layer confidently deleted a true positive with a fluent, well-cited, and
completely invalid cryptographic argument. It was caught only because an independent audit
existed to grade against.

## Design

**Deterministic detectors first, model second.** Of 46 catalogued rules, 36 need no model
call. They are parse, AST, or binary-format checks. Six are hybrid, four require genuine
judgment.

The [ablation](docs/ablation.md) measured that split across five real repositories, and the
result is blunt: **on every threat class both layers implement, the model layer found nothing
the deterministic layer missed.** Zero, across all 20 passes. Deterministic runs finish in
2–4 seconds; the same audits with `--semantic` take 6–14 minutes and cost real money.

So `--semantic` is worth paying for exactly the rules no pattern matcher can implement:
T00 trust boundary, T05 TCB bloat, T08 metadata leakage, LYR01 claim-vs-code, plus a
semantic pass for the hybrid CFG05 key rotation, five passes in all. It is wasted
everywhere else. That is the recommendation the tool makes about itself.

**Every finding carries evidence.** A `file:line` with quoted source, or two hashes. Semantic
findings go through an adversarial pass, an independent agent that tries to *refute* them.
Survivors are `CONFIRMED`; findings that cannot be confirmed or refuted ship as `PLAUSIBLE`,
labelled; refuted ones are dropped and kept in the run log.

**Every report says what it could not check.** Static analysis cannot see the KMS policy
actually deployed in AWS, the runtime PCR values, or whether `--debug-mode` was used on the
real launch. That list is a mandatory report section, computed from what the run actually
did rather than hand-written.

```
catalog/    46 YAML rules, each citing its source        ← the domain knowledge
core/       Rust: EIF parse, CPIO ramdisk walk, PCR recompute, secret scan
detectors/  semgrep TEE ruleset + KMS policy, build config, vsock, streams,
            dstack, confidential-space, eigencompute, OS image / firmware
agent/      Claude Agent SDK: the five judgment passes + adversarial refutation
cli/        orchestration and the report
bench/      fixtures, mutation harness, real-repo corpus, ablation
```

## Known gaps

- **OS-image and firmware rules are new and thin.** `BT-OS01`–`OS03` closed the gap that
  five of zkSecurity's fourteen dstack findings sat in, and `BT-OS01` re-finds the report's
  only High. Three rules do not cover Yocto; they cover the three defects there was an
  external answer for. They read BitBake and EDK II specifically, so a project that builds
  its image any other way is unreached and the report will not say a rule was skipped.
- **`BT-T08` (metadata leakage) has low static recall by construction.** Response-size and
  timing correlation is a runtime distribution; static analysis sees the encoder.
- **Deployment configuration is unreachable.** The KMS policy in a repository is not
  necessarily the policy attached to the live key.
- **`BT-T07D` and `BT-T10` are new and largely untriaged** on real code, so they ship at LOW
  confidence for exactly that reason.
- **No image measurement on EigenCompute.** There is no EIF and there are no PCRs, so the
  Rust core does not run there. Workload identity is the image digest in the attestation
  token, and comparing it to the digest recorded on chain needs the network.

## Verification

```sh
(cd core && cargo test)                      # 35 tests
(cd core && cargo test --features differential)   # PCRs vs AWS's own implementation
.venv/bin/python catalog/validate.py         # citations, false-positive notes, status accuracy
.venv/bin/python catalog/coverage.py         # every detector maps to a catalogued rule
.venv/bin/python catalog/table.py            # regenerates the rule table above
.venv/bin/python agent/test_sandbox.py       # the semantic layer cannot read outside the audit root
.venv/bin/python bench/test_fixtures.py      # recall + zero FP on all clean trees
.venv/bin/python bench/mutate.py             # per-rule precision and recall
.venv/bin/python bench/corpus.py             # real repos + negative controls (clones, needs network)
.venv/bin/python bench/ablation.py           # model layer vs deterministic-only (costs money)
```

Those are what CI gates on, except the last two: `corpus.py` clones eleven repositories and
`ablation.py` makes model calls.

**Fuzzing** the binary parsers needs a nightly toolchain, so it runs on its own schedule
rather than per pull request:

```sh
cargo install cargo-fuzz
cd core
# first dir is the writable corpus, second is the read-only seeds; passing only seeds/
# makes libFuzzer write its evolved corpus into your curated one
cargo +nightly fuzz run eif fuzz/corpus/eif fuzz/seeds/eif -- -max_total_time=300
```

Four targets: `eif`, `cpio`, `decompress`, `secrets`. The seeds are carved from the built
fixtures rather than random, which matters more than it sounds: seeded, the EIF target
reaches coverage 6655; unseeded it reaches 88, because it never gets past the magic check.

## FAQ

**Does it need a running enclave, or AWS credentials?**
No. Repository in, report out. Nothing is fetched from a live instance and nothing is probed.
The cost is that a repository's KMS policy is not necessarily the policy attached to the live
key, which is why that limit is printed in every report's NOT VERIFIED section.

**Why is there no `pip install`?**
The tool resolves its rule catalog, its semgrep ruleset and its Rust binary relative to its
own location, so it runs from a clone. That also means the rules you are running are the
rules you can read in `catalog/`.

**Do I need `--semantic`?**
Usually not. The [ablation](docs/ablation.md) found the model layer added zero findings on
every threat class the deterministic layer also implements. It is worth paying for the five
rules no pattern matcher can implement, and wasted everywhere else.

**A rule fired on correct code. Is that a bug?**
Possibly, and every rule declares its own false-positive modes in its `false_positives`
field, and read that first. If it is a genuine miss of that description, it is a bug: the clean
fixture trees exist precisely to catch rules that fire on correct code, and three rules have
already been caught that way.

## Getting help

- Open an issue at [github.com/owizdom/rootward/issues](https://github.com/owizdom/rootward/issues).
- Security-relevant reports: see [SECURITY.md](SECURITY.md).
- Adding or changing a rule: see [CONTRIBUTING.md](CONTRIBUTING.md).
- What changed between releases: see [CHANGELOG.md](CHANGELOG.md).

## License

Apache-2.0.

The rule catalog is derived from the Bluethroat Labs TEE Security Handbook, cited per rule in
each rule's `source` field. This is an independent implementation, not affiliated with or
endorsed by Bluethroat Labs. The dstack comparison uses
[zkSecurity's published audit](https://phala.com/dstack/dstack-audit.pdf) as external ground
truth; that work is theirs.

## References

| Source | Used for |
|---|---|
| [Bluethroat Labs, TEE Security Handbook](https://bluethroatlabs.com/docs/executive-summary) | The threat model the whole catalog is derived from; cited per rule |
| [Bluethroat Labs, Layers of Security for TEEs](https://bluethroatlabs.com/docs/layers-of-security-for-tees) | The layer scorecard and each rule's `layer_required` |
| [zkSecurity, dstack audit](https://phala.com/dstack/dstack-audit.pdf) | External ground truth for [`docs/dstack-vs-zksecurity.md`](docs/dstack-vs-zksecurity.md) |
| [`aws-nitro-enclaves-image-format`](https://github.com/aws/aws-nitro-enclaves-image-format) | Differential check that the Rust core's PCRs match AWS's own implementation |
| [Google Cloud, validating Confidential Space attestation tokens](https://cloud.google.com/confidential-computing/confidential-space/docs/validate-attestation-tokens) | `BT-CS01`–`CS04` |
| [EDK II / tianocore](https://github.com/tianocore/edk2) | `BT-OS01`: the Config-A vs Config-B firmware targets |
