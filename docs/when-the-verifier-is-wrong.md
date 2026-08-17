# When the verifier is wrong

A note on the failure mode nobody benchmarks, found by accident, and what fixed it.

## The design

The semantic layer of this tool has four rules that need judgment rather than pattern
matching. Because an LLM producing confident security findings with no evidence is worse
than no tool at all, every semantic finding goes through an adversarial pass: a second agent,
given the same codebase and no access to the finder's reasoning, whose only instruction is
to **refute** the finding. Survivors ship as `CONFIRMED`; findings that cannot be confirmed
or refuted ship as `PLAUSIBLE`, labelled; refuted ones are dropped from the report and kept
in the run log.

This is a sound design and it works. On one dstack run the refuter killed 6 of 10 findings,
each with a specific line citation — including one it dropped because the *clean control
fixture* contained the identical line, so the line could not be the defect.

Then it deleted a true positive.

## What happened

Auditing dstack at the commit zkSecurity audited, `BT-T00` produced this:

> `dstack-util/src/system_setup.rs:140` — the env ciphertext is read straight from the
> host-shared 9p directory (mounted at line 173) and flows to `decrypt_env_vars` (line 626)
> → `dh_decrypt` (line 595).

The refuter returned **refuted**:

> The claim of "decrypted without authentication" is contradicted by the callee: `dh_decrypt`
> at `crypto.rs:31-37` uses AES-256-GCM (an AEAD) whose tag check returns `Err` on any
> tampering, and that error propagates via the `?` operator.

Read that again, because it is the interesting part. It is fluent. It cites a real file at
real line numbers. It names the right primitive. Everything it says about the code is true.

And the conclusion is wrong.

AEAD gives **integrity**, not **authenticity of origin**. zkSecurity's finding #03 turns on
exactly that distinction: the attacker fetches the application's public key — trivially
available from the KMS — encrypts a payload of their own, and every tag validates perfectly
because the attacker computed it. The tag proves the ciphertext was not corrupted in transit.
It proves nothing about who wrote it.

The finding was correct. The refutation was confident, well-cited, and it deleted it.

## Why this is the worst case

A false positive costs a security engineer an afternoon. They read the finding, check the
code, disagree, move on. It is visible, annoying, and self-correcting.

A false **refutation** costs them the vulnerability. The finding never appears in the report.
There is no line item saying "we considered this and dismissed it", because the whole point
of dropping refuted findings is to keep the report readable. The tool's confidence is
indistinguishable from the case where the code was genuinely fine.

Worse: the verification layer is the component that makes the semantic layer trustworthy
enough to ship. Every argument for including an LLM in an audit pipeline routes through
"but it gets checked". If the checker can be wrong in this direction, the argument weakens
considerably.

## How it was caught

Not by a benchmark. Not by review. By **external ground truth** — zkSecurity had published
their findings, so there was an answer sheet to grade against.

That is not a satisfying answer, because most audits do not have one. But it is the honest
one, and it is the strongest available argument for keeping an external validation target in
the benchmark rather than only synthetic mutants. Mutants measure whether the finder works.
Only an independent auditor measures whether the *verifier* works, because only they can
tell you a dropped finding should have stayed.

## The fix

The refuter prompt now names the class explicitly rather than trusting general reasoning:

> Do NOT refute on any of these grounds. Each is a plausible-sounding argument that has
> deleted a real finding:
>
> - *"The data is encrypted, so the host cannot tamper with it."* Encryption is not
>   authentication of origin. Where the encryption key is public — an ECIES-style scheme
>   whose recipient public key the host can fetch — the host encrypts its own payload and
>   every AEAD tag validates correctly.
> - *"An AEAD tag, checksum, or hash is verified."* Ask which key that check is under and who
>   holds it. Integrity against corruption is not authenticity against an attacker who can
>   choose the input.
> - *"The value is measured or hashed somewhere."* Ask whether anything ever *compares* that
>   measurement against an expected value and fails closed on mismatch. Recording a
>   measurement is not enforcing one.
> - *"Something later would catch it."* Trace that later check and cite its file:line, or do
>   not claim it exists.

Plus an asymmetry instruction, which matters as much as the specific guards:

> Default to refuted when you are uncertain about a FACT you can check: whether the cited
> line says what is claimed, whether the path is reachable, whether a validating call exists
> elsewhere. Do not refute on a cryptographic argument you have not traced to a specific key
> held by a specific party.
>
> Confirming a finding asserts a security engineer should spend time on it. Refuting one
> asserts they should not, and that mistake is made silently — the finding simply disappears
> from the report.

## The result

With the guards in place the same finding returns **confirmed**, and the refuter's reasoning
is now better than the original finding's — and better than the published report's:

> Line 140 reads the env ciphertext from the host-writable 9p share (copied at
> `system_setup.rs:180`; host writes it at `vmm/src/main_service.rs:258`), and `dh_decrypt`
> at `crypto.rs:15-38` derives the AES-GCM key from an ephemeral pubkey taken from the
> attacker-controlled first 32 bytes of that file.

That last clause is the mechanism, and zkSecurity's report does not spell it out. The key is
derived from bytes the attacker supplies, so of course the tag validates — the attacker chose
the key.

## What transfers

Three things, for anyone building LLM-assisted audit or review tooling:

1. **An adversarial verification pass is not automatically a safety net.** It is another
   model call with its own failure modes, and its failures are quieter than the thing it is
   checking. Measure it separately.

2. **Name the specific wrong arguments.** General instructions to be rigorous did not prevent
   this; an explicit list of plausible-but-invalid moves did. The failure was not sloppiness,
   it was a *sophisticated* argument that happened to be inapplicable — and you cannot
   prompt your way out of that with "be careful".

3. **Make the cost asymmetry explicit in the prompt.** A verifier that does not know which
   direction of error is more expensive will treat them as equivalent. They are not: one
   wastes an afternoon, the other loses the vulnerability.

Two harness bugs surfaced alongside this and are worth listing, because both produce
silently degraded output:

- A `max_budget_usd` cap of $2 killed two of four semantic passes on a real repository. They
  were reported as *failed*, correctly, in the NOT-VERIFIED section — and were still misread
  as clean results on first pass. Reporting a failure is not the same as making it hard to
  ignore.
- One run had all 16 refutations error simultaneously during a credential refresh. Every
  finding shipped as `PLAUSIBLE` — unverified output wearing a label that implies it was
  checked. Refutations now retry, and a run that cannot verify says so per finding.
