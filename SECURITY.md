# Security

`tee-audit` reads untrusted third-party repositories, and optionally sends parts of them to a
model API. This document says what it does with your code, and what it does not.

## Reporting a vulnerability in this tool

Open a [GitHub security advisory](https://github.com/owizdom/tee-audit/security/advisories/new),
or email the maintainer. Please do not open a public issue for anything that would let a
malicious repository read files outside its own tree, or exfiltrate anything.

Findings **produced by** the tool about someone else's code are not vulnerabilities in the tool
— those go to whoever owns the code. A rule that fires on correct code is a bug, and belongs in
a normal issue.

## What the tool does with the repository you point it at

**It never executes or imports anything from the audited repository.** No build step, no
`eval`, no dynamic import, no test run. Every access is a file read. `semgrep` and the Rust
core are invoked as subprocesses with fixed argument vectors and no shell.

**By default, nothing leaves your machine.** The deterministic layer — 32 of 42 rules — is
entirely local. There is no telemetry (`semgrep` is invoked with `--metrics=off`).

## `--semantic` sends source code to the Anthropic API

Off by default. When you pass it, a bounded scope of files is sent to Claude:

- files the deterministic layer already flagged
- the repository's `README.md`
- files whose *path* matches enclave-related terms
- capped at **60 files**, suffix-limited, and skipping `.git`, `node_modules`, `target`,
  `venv`, `dist`, `build`

### The scope is a suggestion, not a sandbox — read this before auditing hostile code

The agent runs with read-only tools (`Read`, `Grep`, `Glob`) so **it cannot modify anything**,
and `cwd` is set to the audited repository. But `permission_mode` is `bypassPermissions`, and
the instruction to stay inside the repository is exactly that — an instruction in the system
prompt, not an enforced boundary.

The audited repository's `README.md` is **always** in scope by construction. A repository
written to attack you can put instructions there. We have not seen this happen, and the tool
list means the worst case is a read rather than a write — but the honest statement is:

> **Do not run `--semantic` against a repository you actively distrust, on a machine holding
> secrets you care about.** Run it in a container or a scratch checkout. The deterministic
> layer has no such caveat and finds the large majority of what the tool finds.

Closing this properly needs filesystem-level sandboxing rather than a better prompt. It is a
known limitation, not a solved problem.

## Reports can contain secrets from the audited repository

Two different policies apply, and the difference matters:

| producer | behaviour |
|---|---|
| Rust core (`BT-T09A`, `BT-T09B`) | **redacts.** Emits kind, a 12-hex SHA-256 prefix, length and entropy — never the value. |
| Python detectors and semgrep | **quote the raw source line**, truncated to 200 characters. |

So a report may contain a plaintext key, mnemonic, or token — and the rules most likely to
match a line *containing* a live secret are exactly the ones that quote it verbatim.

**Treat `tee-audit` output as sensitive as the repository it audited.** Do not paste a report
into a public issue without reading it first. When filing a false positive, the offending
*pattern* is what is useful; redact the value.

## Parsing untrusted binaries

The Rust core parses attacker-influenceable input — EIF images, gzip streams, cpio archives.
It is bounds-checked deliberately and contains no `unsafe`:

- EIF: magic and header length checked, section count capped, per-section size capped, and a
  past-EOF check before any allocation
- gzip: 4 GiB inflate ceiling, so a decompression bomb is bounded
- cpio: hand-written newc reader, `checked_add` on every length field, every slice preceded by
  a bounds check; oversized entries are recorded rather than buffered

**There is no fuzzing harness.** That is the main known gap in this area.

## Cost

`--semantic` spends money. `TEE_AUDIT_MAX_USD` (default `8.00`) caps **each agent invocation**,
not the run: five finder passes plus one refuter per finding means aggregate spend scales with
findings. A repository that induces many findings costs more. Set the variable lower, or run
without `--semantic`, if that matters.

## Scope of the tool's claims

`tee-audit` is a static analyser. It cannot see your deployed KMS policy, your running
enclave's measurements, or how your image was actually launched — and every report ends with a
computed list of what it could not check. **A clean report is not a security guarantee**, and a
report on a repository with no detected TEE platform is not assessed at all rather than passed.
