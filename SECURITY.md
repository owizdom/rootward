# Security

`rootward` reads untrusted third-party repositories, and optionally sends parts of them to a
model API. This document says what it does with your code, and what it does not.

## Reporting a vulnerability in this tool

Open a [GitHub security advisory](https://github.com/owizdom/rootward/security/advisories/new),
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

### The scope is enforced by a hook, and here is exactly how far that goes

Every tool call the semantic passes make goes through a `PreToolUse` hook
(`agent/sandbox.py`) before it runs. The hook resolves each path argument — `realpath`, so
symlinks are followed — and denies anything that lands outside the audit root, along with
any tool that is not `Read`, `Grep`, or `Glob`. `agent/test_sandbox.py` covers `..`
traversal, absolute paths, a symlink planted inside the tree pointing out of it, and an
ungranted tool.

**This replaced a boundary that did not exist, and the reason it did not exist is worth
stating plainly.** The previous version relied on `allowed_tools=["Read", "Grep", "Glob"]`
and a system-prompt instruction. `allowed_tools` is not a capability boundary under
`permission_mode="bypassPermissions"` — measured, not assumed: an agent configured that way
and asked for a file outside its `cwd` called **Bash**, ran `cat`, and returned the
contents. Any assertion elsewhere in this repository's history that the tool list was the
guard was wrong. With the hook in place the same request produces two denied `Bash` calls
and one denied `Read`, and the file is not read.

What the hook still does not do: it governs the tools, not the process. The auditor is
ordinary Python running as you, and a rule, a dependency, or semgrep is not confined by it.
The hook is a boundary on what the *model* can reach, not a container.

The audited repository's `README.md` is **always** in scope by construction, so a repository
written to attack you can still put instructions there — the hook bounds what those
instructions can reach, it does not stop them being read.

> For genuinely hostile code, still prefer a container or a scratch checkout. The
> deterministic layer has no such caveat and finds the large majority of what the tool finds.

## Reports can contain secrets from the audited repository

Two different policies apply, and the difference matters:

| producer | behaviour |
|---|---|
| Rust core (`BT-T09A`, `BT-T09B`) | **redacts.** Emits kind, a 12-hex SHA-256 prefix, length and entropy — never the value. |
| Python detectors and semgrep | **quote the raw source line**, truncated to 200 characters. |

So a report may contain a plaintext key, mnemonic, or token — and the rules most likely to
match a line *containing* a live secret are exactly the ones that quote it verbatim.

**Treat `rootward` output as sensitive as the repository it audited.** Do not paste a report
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

`--semantic` spends money. `ROOTWARD_MAX_USD` (default `8.00`) caps **each agent invocation**,
not the run: five finder passes plus one refuter per finding means aggregate spend scales with
findings. A repository that induces many findings costs more. Set the variable lower, or run
without `--semantic`, if that matters.

## Scope of the tool's claims

`rootward` is a static analyser. It cannot see your deployed KMS policy, your running
enclave's measurements, or how your image was actually launched — and every report ends with a
computed list of what it could not check. **A clean report is not a security guarantee**, and a
report on a repository with no detected TEE platform is not assessed at all rather than passed.
