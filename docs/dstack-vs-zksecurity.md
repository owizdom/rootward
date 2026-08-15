# External validation: dstack vs the zkSecurity audit

The point of this comparison is ground truth this project did not author. zkSecurity audited
dstack between 26 May and 13 June 2025 and published
[the report](https://phala.com/dstack/dstack-audit.pdf). Running against the same commit
gives a number that cannot be tuned into existence.

**Result: 0 of 14 overlap.** Details and reasons below, because the reasons are the useful
part.

## Setup

Both sides at the same commit, taken from the report's introduction: *"The audit focused on
parts of two public codebases: dstack at commit `be9d0476`, and meta-dstack at commit
`5b63aec3`."* The short SHA resolves to `be9d0476a63e937eda4c13659547a25088393394`
(committed 2025-05-29, inside the audit window).

```
.venv/bin/python bench/corpus.py --only dstack
```

Deterministic layer only — the four semantic rules did not run.

## What zkSecurity found

| ID | Component | Finding | Risk |
|---|---|---|---|
| #00 | meta-dstack/ovmf | VMM is Currently Trusted in OVMF Build | High |
| #01 | meta-dstack recipes | Terminal Binaries Present in Production Dstack Image | Medium |
| #02 | dstack-util system setup | Host Can Pass Symbolic Links To Shared Folder With Guest | Medium |
| #03 | dstack-util | Env Injection via Unauthenticated Shared Files | Medium |
| #04 | app-compose service | Pre-Launcher Code Can Be Used To Leak Secrets on Default KMS | Medium |
| #05 | meta-dstack | qemu-guest-agent is Present in Production | Medium |
| #06 | dcap-qvl | Incomplete TD Under Debug Checks | Medium |
| #07 | app-compose service | Unchecked Container Image Digest | Medium |
| #08 | guest-agent | Unrestricted Exposure of stdout/stderr From CVM Docker Containers | Low |
| #09 | dstack-util | Incomplete Measurement of CVM Configuration Files | Low |
| #0a | * | Underdocumented Root of Trust and Vendored Attestation Code | Low |
| #0b | dcap-qvl | Lack of Revocation Checks in Quote Verification Library | Low |
| #0c | meta-dstack | Lack of Documentation on Design and Hardening Decisions | Informational |
| #0d | * | Insufficient Guidance for Secure Production Deployment of CVMs | Informational |

## What this tool found

Four findings, none of them zkSecurity's.

| Rule | Location | Assessment |
|---|---|---|
| `BT-T07C` | `kms/src/main_service.rs:183` | **Real, and not in the report.** `if token_hash.as_slice() != self.state.config.admin_token_hash.as_slice()` — a non-constant-time comparison on admin authentication material. |
| `BT-T07A` | `http-client/src/hyper_vsock.rs:127` | Plausible. `VsockStream::connect(cid, port)` with no deadline set at the call site. |
| `BT-T07A` | `rocket-vsock-listener/src/lib.rs:259` | Plausible. Same, for `VsockListener::bind`. |
| `BT-DS04` | `kms/src/onboard_service.rs:303` | Plausible, after a fix. It originally pointed at `guest-agent/dstack.toml:17` (`quote_file = "quote.hex"`) — a TOML key matching the measured-boot pattern on the bare word "quote", reported as critical. Tightening the pattern to qualified forms (`get_quote`, `verify_quote`, `rtmr`, `mrtd`, `td_report`) and excluding configuration moved it onto real quote-handling code. |

## Why the overlap is zero

Not one explanation, four — and only the last is a defect in this tool.

**1. Different repository (5 findings: #00, #01, #05, #0c, and part of #0a).** These are in
`meta-dstack`, the Yocto layer that builds the OS image. The corpus audits `dstack` only.
The highest-severity finding in the entire report — OVMF built with Config-A, which keeps
the VMM inside the TCB — lives in a BitBake recipe selecting `OvmfPkgX64.dsc` over
`IntelTdxX64.dsc`. Nothing in this catalog models firmware build configuration.

**2. Components absent at this commit (4 findings: #04, #06, #07, #0b).** `dcap-qvl` and
`app-compose` are not directories in the dstack repository at `be9d0476` — verified, not
assumed. Findings about a quote-verification library and a container-launch service cannot
be found in a tree that does not contain them.

**3. Out of catalog scope by construction (#0a, #0d).** Documentation quality and deployment
guidance are not statically detectable, and the catalog deliberately encodes no rule for
them.

**4. In scope and genuinely missed (3 findings: #02, #03, #08).** This is the part that
matters:

- **#02 Host can pass symbolic links to the shared folder** is `BT-T00` exactly — the parent
  supplying input that the guest trusts. Semantic rule; the run was deterministic-only.
- **#03 Env injection via unauthenticated shared files** is `BT-T10`/`BT-T00` — parent-supplied
  data consumed without authentication.
- **#08 Unrestricted exposure of stdout/stderr from CVM containers** is `BT-T03` almost
  verbatim: content crossing the enclave boundary into somewhere the operator reads. The
  semgrep rule looks for a *secret-named value* passed to a log call. This finding is
  architectural — the whole stream is exposed by configuration, with no offending line to
  match. A pattern matcher cannot see it.

## What this says

**The honest headline is that scopes barely intersect.** zkSecurity audited OS image
generation and low-level libraries; this catalog targets application-level TEE misuse. The
`corpus.yaml` note predicted partial overlap at best. Zero is worse than predicted, and
three of their findings were in scope and missed.

**Three concrete gaps to close**, in priority order:

1. **Run the semantic layer on this comparison.** #02 and #03 are precisely what `BT-T00`
   exists for, and they were never given a chance. This is the cheapest fix and the honest
   next step before drawing any conclusion about semantic recall.
2. **Add meta-dstack to the corpus.** Five findings including the only High are unreachable
   without it. That also argues for a catalog rule class this project does not have: OS
   image and firmware build configuration.
3. **`BT-T03` is too narrow.** It matches a secret-named value reaching a log sink, and
   misses configuration that exposes an entire output stream. Worth a companion rule for
   stream-level exposure.

**One finding in the other direction.** `kms/src/main_service.rs:183` compares admin token
hashes with `!=`, which is a documented timing weakness on authentication material and is
not in the report. One unreported finding against fourteen missed is not a favourable
trade, but it is evidence the deterministic layer sees things a manual audit did not
prioritise.

**And one precision bug found and fixed.** `BT-DS04` reported a critical finding on a TOML
config key because its pattern matched the bare word "quote". Restricting it to qualified
forms and excluding build configuration moved it onto real code. Both the fixture suite and
the mutation benchmark stayed green through the change, and the negative control stayed at
zero — the fix cost no recall.
