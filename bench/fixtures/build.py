#!/usr/bin/env python3
"""Generate the binary fixtures (EIF images) that cannot be committed as text.

Run: python3 bench/fixtures/build.py

EIFs are gitignored — they are build artifacts, and committing megabytes of binary to a
security repo invites exactly the "what is actually in this file" question the tool exists
to answer. Generating them keeps every fixture inspectable as source.

Produces:
  vulnerable/app.eif   ramdisk containing a planted private key (BT-T09A), and a PCR0 that
                       deliberately disagrees with the PCR0 pinned in the vulnerable KMS
                       policy (BT-CFG03)
  clean/app.eif        same structure, no secret
"""

from __future__ import annotations

import gzip
import struct
import sys
from pathlib import Path

HERE = Path(__file__).parent

EIF_HEADER_SIZE = 548
SECTION_KERNEL, SECTION_CMDLINE, SECTION_RAMDISK = 1, 2, 3


def newc(name: str, mode: int, body: bytes) -> bytes:
    """One cpio newc entry: 110-byte ASCII header, NUL-terminated name, body, both
    padded to a 4-byte boundary."""
    namesize = len(name) + 1
    fields = [1, mode, 0, 0, 1, 0, len(body), 0, 0, 0, 0, namesize, 0]
    out = b"070701" + b"".join(b"%08X" % f for f in fields)
    assert len(out) == 110, len(out)
    out += name.encode() + b"\0"
    out += b"\0" * ((4 - (110 + namesize) % 4) % 4)
    out += body
    out += b"\0" * ((4 - len(body) % 4) % 4)
    return out


def ramdisk(entries: list[tuple[str, int, bytes]]) -> bytes:
    blob = b"".join(newc(n, m, b) for n, m, b in entries)
    blob += newc("TRAILER!!!", 0, b"")
    # mtime=0: gzip writes a timestamp into its header by default, so the compressed
    # bytes -- and therefore PCR1, which measures the ramdisk -- changed on every build.
    # Following the README then left a tracked file modified.
    return gzip.compress(blob, mtime=0)


def section(kind: int, data: bytes) -> bytes:
    return struct.pack(">HHQ", kind, 0, len(data)) + data


def eif(sections: list[bytes]) -> bytes:
    hdr = bytearray(EIF_HEADER_SIZE)
    hdr[0:4] = b".eif"
    hdr[4:6] = struct.pack(">H", 4)       # version
    hdr[8:16] = struct.pack(">Q", 512)    # default_mem
    hdr[16:24] = struct.pack(">Q", 2)     # default_cpus
    hdr[26:28] = struct.pack(">H", len(sections))
    return bytes(hdr) + b"".join(sections)


def main() -> None:
    # A planted key: high entropy, not a placeholder, not a known test vector, so it must
    # survive every filter in the scanner and be reported.
    planted = (
        b"# runtime config\n"
        b"RPC_URL=https://example.invalid\n"
        b"SIGNER_PRIVATE_KEY=0x8f2a559490d1b7c3e0a2b41d6c95a7e3f18b204c7d6e9a1350f4c8b2d7e6a903\n"
    )
    vulnerable = eif([
        section(SECTION_KERNEL, b"KERNELBYTES-vulnerable"),
        section(SECTION_CMDLINE, b"console=ttyS0 reboot=k panic=30"),
        section(SECTION_RAMDISK, ramdisk([
            ("app/.env", 0o100600, planted),
            ("app/server.py", 0o100644, b"print('serving')\n"),
        ])),
    ])
    (HERE / "vulnerable" / "app.eif").write_bytes(vulnerable)

    clean = eif([
        section(SECTION_KERNEL, b"KERNELBYTES-clean"),
        section(SECTION_CMDLINE, b"console=ttyS0 reboot=k panic=30"),
        section(SECTION_RAMDISK, ramdisk([
            # Same shape, but the secret is provisioned at runtime rather than baked in.
            ("app/.env", 0o100600, b"# runtime config\nRPC_URL=https://example.invalid\n"),
            ("app/server.py", 0o100644, b"print('serving')\n"),
        ])),
    ])
    (HERE / "clean" / "app.eif").write_bytes(clean)

    for name in ("vulnerable/app.eif", "clean/app.eif"):
        p = HERE / name
        print(f"{name}: {p.stat().st_size} bytes")

    _write_clean_policy()


def _write_clean_policy() -> None:
    """Regenerate the clean fixture's KMS policy so its pinned PCRs match its own EIF.

    This is not fixture bookkeeping — it is what a correct deployment does. The policy has
    to be derived from the build output, or the two drift and BT-CFG03 fires. Hardcoding
    placeholder PCRs in the "clean" fixture made it fail its own check, which is the same
    mistake a real team makes when the policy is maintained by hand.
    """
    import json
    import subprocess

    # Release first, then debug — the same order audit.py uses. Hardcoding `debug` meant CI,
    # which builds `--release`, silently skipped this step: the clean fixture kept its
    # placeholder PCRs, they did not match the generated EIF, BT-CFG03 fired on the clean
    # tree, and the fixture gate failed with a false positive that never reproduced locally.
    root = HERE.parent.parent / "core" / "target"
    core = next(
        (p for p in (root / "release" / "tee-audit-core", root / "debug" / "tee-audit-core")
         if p.exists()),
        None,
    )
    if core is None:
        # Loud, because a silent skip here produces a fixture tree that fails its own gate.
        print(
            "ERROR: core binary not found in target/release or target/debug.\n"
            "       Build it first (cd core && cargo build --release --bins), or the clean\n"
            "       fixture's KMS policy will not match its EIF and BT-CFG03 will fire on\n"
            "       the clean tree.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    out = subprocess.run(
        [str(core), "measure", str(HERE / "clean" / "app.eif")],
        capture_output=True, text=True, check=True,
    )
    measured = json.loads(out.stdout)["measurements"]

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEnclaveDecryptAttested",
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:role/enclave-parent"},
                "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
                "Resource": "*",
                "Condition": {
                    "StringEqualsIgnoreCase": {
                        # PCR1 (kernel+bootstrap) and PCR2 (application) pinned separately,
                        # rather than PCR0 alone — see BT-T02.
                        "kms:RecipientAttestation:PCR1": measured["PCR1"],
                        "kms:RecipientAttestation:PCR2": measured["PCR2"],
                    }
                },
            },
            {
                "Sid": "AllowDescribeUnconditional",
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:role/ops"},
                "Action": ["kms:DescribeKey", "kms:ListAliases"],
                "Resource": "*",
            },
        ],
    }
    path = HERE / "clean" / "kms-key-policy.json"
    path.write_text(json.dumps(policy, indent=2) + "\n")
    print(f"clean/kms-key-policy.json: pins PCR1/PCR2 from clean/app.eif")


if __name__ == "__main__":
    main()
