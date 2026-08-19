# External validation: dstack vs the zkSecurity audit

The point of this comparison is ground truth this project did not author. zkSecurity audited
dstack between 26 May and 13 June 2025 and published
[the report](https://phala.com/dstack/dstack-audit.pdf). Running against the same commit
produces a number that cannot be tuned into existence.

**Result: 2 of 14 re-found, 1 partial, 11 missed.** The reasons are the useful part, and one
of them is a bug in this tool that nearly hid the hit.

## Setup

Both sides at the same commit, from the report's introduction: *"The audit focused on parts
of two public codebases: dstack at commit `be9d0476`, and meta-dstack at commit
`5b63aec3`."* The short SHA resolves to `be9d0476a63e937eda4c13659547a25088393394`
(committed 2025-05-29, inside the audit window).

```
.venv/bin/python bench/corpus.py --only dstack              # deterministic
.venv/bin/python cli/audit.py bench/corpus/dstack --semantic  # + judgment rules
```

## The hit: #03, Env Injection via Unauthenticated Shared Files

zkSecurity's finding: the VMM stores five user-configurable files as CVM inputs
(`.encrypted-env`, `.instance-info`, `.sys-config.json`, `.user-config`, `app-compose.json`)
with *"no cryptographic integrity protection or authentication mechanism in place"*. Their
key observation is that encrypting `.encrypted-env` does not help, because the attacker can
fetch the application's public key from the KMS and encrypt a payload of their own.

`BT-T00` found this independently, in three places, each with a data-flow trace:

| Location | Trace |
|---|---|
| `dstack-util/src/system_setup.rs:140` | `.encrypted-env` read from the host 9p share → `decrypt_env_vars` (626) → `dh_decrypt` (595) |
| `dstack-util/src/system_setup.rs:283` | `.sys-config.json` deserialized from the host share at line 132 → `kms_urls` iterated at 350 to pick the KMS endpoint |
| `dstack-util/src/system_setup.rs:857` | docker registry mirror taken from the same host-supplied `sys_config` |

The 9p mount is cited directly: `mount -t 9p -o trans=virtio,version=9p2000.L,ro host-shared`
at line 173.

On re-verification the adversarial pass went further than the original finding *and* further
than my own reading: it traced that `dh_decrypt` (`crypto.rs:15-38`) derives the AES-GCM key
from an ephemeral public key read out of **the attacker-controlled first 32 bytes of the
file itself**, and that the host writes that file at `vmm/src/main_service.rs:258`. That is
zkSecurity's argument reconstructed from the code, with line numbers they did not publish.

## The near-miss that mattered more than the hit

The first refutation of this finding **refuted it**, with this reasoning:

> The claim of "decrypted without authentication" is contradicted by the callee: `dh_decrypt`
> at `crypto.rs:31-37` uses AES-256-GCM (an AEAD) whose tag check returns `Err` on any
> tampering.

That is fluent, cites real code, and is wrong. AEAD gives integrity, not authenticity of
origin. When the encryption key is public, which is precisely the case zkSecurity documents
, the attacker encrypts their own payload and the tag validates perfectly.

This is the most dangerous failure mode in the whole design. A false positive wastes an
afternoon; a false *refutation* deletes a true finding silently, and the report never
mentions it existed. It was caught only because the external audit gave an answer to check
against: which is the entire argument for having an external validation target.

The refuter prompt now carries explicit guards against this class: encryption is not
authentication, an AEAD tag is only as good as who holds the key, a recorded measurement is
not an enforced one, and "something later catches it" requires citing the later check. With
those guards the same finding comes back **confirmed**.

## The partial: #08

zkSecurity #08 is *Unrestricted Exposure of stdout/stderr From CVM Docker Containers* in
`guest-agent`. `BT-T05` flagged `guest-agent/src/http_routes.rs:225`, the bollard Docker
client and container-log relay, noting the `/logs/<container_name>` route at line 95 accepts
eight caller-supplied query parameters.

Same file, same code surface, different framing: reported as trusted-computing-base bloat
rather than as boundary exposure. Worth counting as a partial hit and as evidence that
`BT-T03` needs a companion rule for stream-level exposure, it matched a secret-named
value reaching a log call, and could not see a configuration that exposes an entire stream.

**Since shipped:** that companion rule is `BT-T03C-stream-exposure`, and it now fires on
this repository three times.

## The second hit: the only High, OVMF built as Config-A

zkSecurity's only High is guest firmware built from the general-purpose OVMF target rather
than the Intel TDX one, which leaves the virtual machine monitor inside the TCB of a guest
whose whole threat model treats the host as adversarial.

`BT-OS01` finds it at `meta-dstack/recipes-core/dstack-ovmf/dstack-ovmf_git.bb:208`, the
line that runs the build:

```
${S}/OvmfPkg/build.sh $PARALLEL_JOBS -a $OVMF_ARCH -b RELEASE -t ${FIXED_GCCVER} ${PACKAGECONFIG_CONFARGS}
```

`OvmfPkg/build.sh` with no `IntelTdx` target anywhere in the recipe. Same commit
(`5b63aec3`), same repository, and the evidence is the invocation rather than a mention of
it: the rule prefers a build line over a path because this recipe also rewrites
`OvmfPkg/build.sh` in a `sed` a hundred lines earlier, and pointing a reader at the `sed`
would make a correct finding look wrong.

This is the rule class every previous version of this document listed as the open gap. It
is worth being clear about what that means for the number at the top: the gap was named
here first and the rule was written afterwards, against a repository whose answer was
already known. It is a re-find, not a blind find, and one shape of one defect.

`BT-OS02` also fires, at line 12 of the same recipe, `PACKAGECONFIG ??= ""` with a
`[secureboot]` option declared at line 15 and never added to the default, which the recipe
confirms itself at line 206 with `bbnote "Building without Secure Boot."`. Whether that
corresponds to one of the four remaining meta-dstack findings is not known: the report's
per-finding text for those is not reproduced here, so it is left unmapped rather than
counted.

## Why the other 11 were missed

**Different repository (4: #00, #01, #0c, part of #0a).** These live in `meta-dstack`, the
Yocto layer, which the corpus did not audit at the time of this comparison. It does now,
pinned at the same commit zkSecurity read. The fifth of that group, the report's only
High: is no longer among them; it is the second hit, above.

**Components absent at this commit (4: #04, #06, #07, #0b).** `dcap-qvl` and `app-compose`
are not directories in the dstack tree at `be9d0476`, verified, not assumed.

**Out of scope by construction (#0a, #0d).** Documentation quality and deployment guidance
are not statically detectable and are deliberately uncatalogued.

**In scope and genuinely missed (#02, #09).** #02 is the symlink-following `fs_err::copy` in
`system_setup.rs`: the host replaces `app-compose.json` with a symlink to `/proc/kcore` and
the guest copies live kernel memory into its staging directory. `BT-T00` read that function
and did not flag it. This is a real recall gap in the semantic layer, not a scope excuse.

## What this tool found that the report did not

- `kms/src/main_service.rs:183`, admin token hashes compared with `!=`, a non-constant-time
  comparison on authentication material (`BT-T07C`, deterministic).
- `kms/src/onboard_service.rs:190`, `request.source_url` from an unauthenticated `onboard`
  RPC, on a server mounted with no auth token and no `QuoteVerifier`, bound to `0.0.0.0:8000`
  per `kms.toml` (`BT-T00`).
- Four `BT-LYR01` claim-vs-code gaps, including `kms/README.md:107` stating attestation
  verification unconditionally while `main_service.rs:569` wraps it in
  `if self.state.config.onboard.quote_enabled {`.

These are unverified beyond the adversarial pass and are offered as leads, not conclusions.

## Honest summary

One clear re-find, one partial, one in-scope miss, and ten unreachable for scope reasons that
were largely predictable from `corpus.yaml`'s own note. The most valuable output was not the
hit: it was discovering that the verification layer could confidently delete a correct
finding, which no internal benchmark would have surfaced.

**Both follow-ups from this comparison have since shipped:** `meta-dstack` is in
`bench/corpus.yaml` pinned at `5b63aec3`, and `BT-T00A-host-path-symlink` was written for
host-supplied filesystem paths and now fires on this repository. Whether it lands on the
same call site zkSecurity identified has not been verified line-for-line and is not claimed.

The rule class this comparison exposed is now closed enough to be measured: `BT-OS01`–
`OS03` read BitBake and EDK II, `BT-OS01` re-finds the High, and `BT-OS02` adds a second
finding in the same recipe. Three rules are not coverage of a Yocto layer. they are the
three defects there was an external answer for, and the four meta-dstack findings that are
not the High remain unmatched.
