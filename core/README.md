# core — EIF parsing, ramdisk inspection, secret scanning

The Rust half of the auditor: the parts that are binary-format or cryptographic work rather
than pattern matching. Everything here is offline. Nothing dials AWS, and no attestation is
fetched from a running enclave.

```
tee-audit-core inspect <file.eif>     # measurements + sections + ramdisk secret scan
tee-audit-core measure <file.eif>     # measurements only
tee-audit-core scan <file>...         # secret-scan build context (Dockerfile, .env, scripts)
```

Always emits one JSON object on stdout. Errors are `{"error": "..."}` with exit 1, so the
caller parses one shape either way.

## Three decisions worth knowing about

### 1. The measurement algorithm is reimplemented, not imported

`src/measure.rs` computes PCR0/1/2 locally. Normally importing the vendor's implementation
is the right call — and it was the original plan — but `aws-nitro-enclaves-image-format` has
no feature flags and lists `aws-config`, `aws-sdk-kms`, `tokio`, `hyper`, `rustls`, and
`openssl` as **mandatory** dependencies, because the same crate also does KMS-backed
*signing*. That is 545 transitive crates. This tool only ever reads.

Shipping a network stack and a KMS client inside an auditor whose own threat model is
"parse a file handed to us by a hostile host" is a bad trade. The local implementation
builds in ~13 seconds against ~28 crates.

The correctness risk that creates is handled by not trusting it:

```
cargo test --features differential
```

pulls the official crate as an optional dependency and asserts both implementations agree
across several image shapes. **This passes** — PCR0/1/2 match AWS's implementation exactly
for one-ramdisk, two-ramdisk, and three-ramdisk-plus-metadata images. AWS's code is the oracle; it just is not a runtime dependency.
`nitro-cli` would be the more direct oracle but only runs on an EC2 Nitro host.

The algorithm, transcribed from `defs/eif_hasher.rs` and `utils/eif_reader.rs` at 0.6.0:

```
PCR = SHA384( 0x00 * 48 || SHA384(section bytes) )

PCR0  kernel + cmdline + every ramdisk
PCR1  kernel + cmdline + ramdisk[0]
PCR2  ramdisk[1..]
```

`EifReader` builds its hashers with `new_without_cache`, so `EifHasher`'s block-chaining
never runs for EIF measurement and the accumulated value is a plain hash over concatenated
bytes. Sections are walked **sequentially** from the end of the header, not via
`section_offsets`, because that is what the reference implementation does — and a different
walk order yields a different PCR0 for identical bytes.

### 2. It is a subprocess, not a PyO3 module

The Python side calls this a handful of times per audit, never in a loop, so the binding
overhead PyO3 would save is not measurable. The costs are: an ABI pinned to a CPython
version, a maturin step in every install, and a native crash taking the whole auditor down.
A subprocess is one JSON contract, debuggable with `cat`, and survives the child dying on a
malformed image.

### 3. Findings never carry the secret

A finding reports a classification, a location, a length, an entropy score, and the first 12
hex chars of SHA-256 over the matched value — never the value. Audit reports get pasted into
issues and, for this project, published. A report that quotes the key it found has moved the
key somewhere new. The digest is enough for an operator to confirm *which* key was hit.

`eif::tests::finds_a_planted_key_in_the_ramdisk` asserts this directly: it serializes the
whole report and fails if the planted key appears anywhere in it.

## Known gaps

**PCR8 is not computed.** Deriving it requires CBOR-decoding the signature section,
PEM-parsing the signing certificate, and re-encoding to DER — an X.509 stack, which means
openssl, which is the dependency this module exists to avoid. When an image is signed the
report sets `signature_present: true` and emits a warning, and the audit's NOT-VERIFIED
section records that PCR8 was not checked. Reporting a wrong PCR8 would be worse than
reporting none.

**The CRC is not verified.** `eif_crc32` is parsed and reported but not recomputed. It is an
integrity check, not a security one, and getting its exact coverage subtly wrong would
produce a misleading "corrupt image" signal.

**PCR3 and PCR4 are structurally out of reach.** They are runtime values — parent IAM role
and parent instance ID — that do not exist in the EIF. No static tool can produce them.

**Static PCRs can legitimately differ from the hypervisor's.** Trail of Bits
([notes on Nitro Enclaves](https://blog.trailofbits.com/2024/02/16/a-few-notes-on-aws-nitro-enclaves-images-and-attestation/))
observed that the `nitro-cli` parser and the hypervisor parser can disagree on the same
image. A mismatch found by `BT-CFG03` is therefore a lead to investigate, not proof of a
substituted image.

## Tests

```
cargo test                          # 35 tests, ~13s cold
cargo test --features differential  # 36 tests, + cross-check against the official AWS crate
```

The differential feature needs rustc 1.94.1 (an AWS SDK transitive requirement) even though
the crate itself builds on 1.88+.
