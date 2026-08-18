#!/usr/bin/env python3
"""Mutation harness — measured recall instead of estimated recall.

    .venv/bin/python bench/mutate.py [--repo PATH] [--json]

Takes a clean tree, injects exactly one catalogued defect, runs the full auditor, and asks
whether that specific rule fired. Ground truth is exact by construction: the harness planted
the bug, so it knows precisely what should be found and where.

Why this and not just the hand-written fixtures: a fixture I wrote to demonstrate a rule is
code shaped like the rule. Real code is not. Mutating a *clean* tree means the surrounding
context is whatever the tree already was, and the rule has to find the defect in it rather
than in a sentence written to be found.

Two numbers come out per rule, and the second is the one that decides whether anyone runs
this twice:

  recall     of the mutants planting rule R, how many did R detect?
  precision  of every finding of rule R across the whole run, how many were the planted
             defect rather than noise? The denominator is deliberately harsh: it counts R
             firing on a mutant that planted a *different* rule, and R firing on the
             untouched clean baseline. Both are false positives.

Each rule gets several mutants that vary the *shape* of the defect, not just the file it
sits in. A rule that only recognises the one idiom its author had in mind will show full
recall against a single mutant and fail on real code; three shapes is the cheapest defence
against measuring the fixture instead of the rule.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BASE = ROOT / "bench" / "fixtures" / "clean"
PYTHON = str(ROOT / ".venv" / "bin" / "python") if (ROOT / ".venv" / "bin" / "python").exists() else sys.executable


@dataclass
class Mutation:
    """One planted defect.

    `find` and `replace` are literal by default, so a mutation either applies cleanly or is
    reported as inapplicable. A mutation that silently matched nothing would show up as a
    recall failure and send someone debugging the wrong thing. Set `regex=True` only where
    the target text is generated rather than checked in.
    """

    rule_family: str
    target: str
    find: str
    replace: str
    note: str

    also_expects: tuple[str, ...] = ()
    """Other rule families this mutant legitimately trips.

    Some defects cannot be planted in isolation. Replacing a `jwtVerify(token, JWKS,
    {issuer, audience})` call with a bare base64 decode removes the signature check (CS01)
    *and* the audience and issuer checks (CS02), because they were arguments to the call
    that was deleted. Both findings are correct. Counting the second as collateral would
    report a precision loss for a rule that behaved exactly right, so the co-occurrence is
    declared here and excluded from the false-positive tally rather than tuned away.
    """

    base: str = "clean"
    """Which fixture tree under bench/fixtures/ this defect is planted in.

    Platform-specific rules can only be planted in a tree of that platform: an EigenCompute
    mutant applied to the Nitro tree finds none of its target text, reports `inapplicable`,
    and is then dropped from scoring — a permanent recall hole that looks like a clean run.
    Every mutant names its tree so that cannot happen silently.
    """

    extra_edits: tuple[tuple[str, str], ...] = ()
    """Further (find, replace) pairs applied in order after the first.

    Some defects take more than one edit to plant. The KMS policy pins PCR1 *and* PCR2, so
    a single swap leaves the other pin standing and the rule is correct to stay quiet — the
    first version of those two mutants made exactly that mistake and read as rule misses.
    """

    regex: bool = False
    """Treat `find` (and `extra_edits` finds) as regexes.

    Off by default and used sparingly: a literal either applies or is reported inapplicable,
    which is the property that keeps a silently-matching-nothing mutation from looking like
    a recall failure. It is switched on only where the target text is *generated* — the KMS
    fixture's PCR values come from the built EIF, so they cannot be written out literally.
    """

    def apply(self, root: Path) -> bool:
        path = root / self.target
        if not path.is_file():
            return False
        text = path.read_text(encoding="utf-8")

        for find, replace in ((self.find, self.replace), *self.extra_edits):
            if self.regex:
                text, n = re.subn(find, replace, text, count=1)
                if n == 0:
                    return False
            else:
                if find not in text:
                    return False
                text = text.replace(find, replace, 1)

        path.write_text(text, encoding="utf-8")
        return True


MUTATIONS: list[Mutation] = [
    Mutation(
        "T07C", "enclave.rs",
        "hmac_tag.ct_eq(expected).into()",
        "hmac_tag == expected",
        "constant-time compare replaced with ==",
    ),
    Mutation(
        "T07C", "handler.py",
        "hmac.compare_digest(api_key, expected)",
        "api_key == expected",
        "compare_digest replaced with ==",
    ),
    Mutation(
        "T07C", "relay.go",
        "subtle.ConstantTimeCompare(signature, expected) == 1",
        "bytes.Equal(signature, expected)",
        "ConstantTimeCompare replaced with bytes.Equal",
    ),
    Mutation(
        "T06B", "handler.py",
        "requests.get(url)",
        "requests.get(url, verify=False)",
        "TLS verification disabled",
    ),
    Mutation(
        "T06B", "relay.go",
        "&tls.Config{MinVersion: tls.VersionTLS13}",
        "&tls.Config{InsecureSkipVerify: true}",
        "TLS verification disabled",
    ),
    Mutation(
        "T06B", "api.ts",
        "new https.Agent({})",
        "new https.Agent({ rejectUnauthorized: false })",
        "TLS verification disabled",
    ),
    Mutation(
        "T03", "relay.go",
        'log.Printf("loaded keyFingerprint=%s", keyFingerprint)',
        'log.Printf("loaded privateKey=%s", privateKey)',
        "secret written to a log sink",
    ),
    Mutation(
        "T04B", "handler.py",
        "def expired(expires_at, attested_now):\n    return expires_at < attested_now",
        "def expired(expires_at):\n    import time\n    return expires_at < time.time()",
        "expiry checked against the parent-controlled clock",
    ),
    Mutation(
        "T03B", "handler.py",
        '    _ = traceback\n    raise RuntimeError("E_INTERNAL")',
        "    traceback.print_exc()",
        "traceback printed across the boundary",
    ),
    Mutation(
        "T07A", "handler.py",
        "    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)\n    s.settimeout(30)",
        "    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)",
        "vsock timeout removed",
    ),
    Mutation(
        "T07B", "handler.py",
        'raise ValueError("decryption failed")',
        'raise ValueError("invalid padding")',
        "error message distinguishes padding failure",
    ),
    Mutation(
        "CFG01", "run-enclave.sh",
        "--eif-path app.eif",
        "--eif-path app.eif --debug-mode",
        "enclave launched in debug mode",
    ),
    Mutation(
        "CFG04", "Dockerfile",
        "FROM public.ecr.aws/amazonlinux/amazonlinux@sha256:1f2e3d4c5b6a798877665544332211ffeeddccbbaa99887766554433221100ff",
        "FROM public.ecr.aws/amazonlinux/amazonlinux:latest",
        "base image unpinned",
    ),
    Mutation(
        "T09B", "Dockerfile",
        "COPY . /app",
        "ENV SIGNER_PRIVATE_KEY=0x4d1f8a2b93c7e05fa6b8d34c19e7205fb83c6a4d9e1720f5c8b3a6d4e9f10275\nCOPY . /app",
        "private key baked into the image",
    ),
    Mutation(
        "T06", "attest.py",
        "    root = x509.load_pem_x509_certificate(AWS_NITRO_ROOT_CERT)\n"
        "    chain = [x509.load_der_x509_certificate(c) for c in doc[\"cabundle\"]]\n"
        "    verify_cert_chain(chain, root)\n"
        "    if not sign1.verify(chain[-1].public_key()):",
        "    if not sign1.verify(sign1.certificate):",
        "chain validation to the pinned root removed",
    ),
    Mutation(
        "CFG02", "attest.py",
        '    if all(b == 0 for v in pcrs.values() for b in v):\n'
        '        raise ValueError("debug-mode attestation rejected")\n',
        "",
        "all-zero PCR rejection removed",
    ),
    Mutation(
        "T01", "kms-key-policy.json",
        '"Condition": {',
        '"_Condition": {',
        "attestation condition removed from the KMS policy",
    ),

    # ---- additional shapes -------------------------------------------------------
    # Everything below varies HOW the defect is written rather than where it lives. A
    # rule that recognises only its author's idiom scores full recall on one mutant and
    # then misses the same bug in real code, which is precisely what the zkSecurity
    # comparison caught for BT-T00 (it read the vulnerable function and said nothing).

    # T07C — the recommended fix removed in three different dialects.
    Mutation(
        "T07C", "enclave.rs",
        "hmac_tag.ct_eq(expected).into()",
        "hmac_tag.as_slice() == expected.as_slice()",
        "constant-time compare replaced with slice ==",
    ),
    Mutation(
        "T07C", "api.ts",
        "  return a.length === b.length && crypto.timingSafeEqual(a, b);",
        "  return token === expected;",
        "timingSafeEqual replaced with ===",
    ),

    # T03 — secret reaching a sink, in each language's idiom.
    Mutation(
        "T03", "enclave.rs",
        'eprintln!("derived session key fingerprint={}", fingerprint(session_key));',
        'eprintln!("derived session_key={}", session_key);',
        "secret interpolated into eprintln",
    ),
    Mutation(
        "T03", "api.ts",
        '  console.log("sessionFingerprint", sessionFingerprint);',
        '  console.log("sessionKey", sessionKey);',
        "secret passed to console.log",
    ),

    # T06B — verification disabled, three libraries.
    Mutation(
        "T06B", "handler.py",
        "def fetch(url):\n    return requests.get(url)",
        "def fetch(url):\n    import ssl\n    ctx = ssl._create_unverified_context()\n    return requests.get(url)",
        "unverified ssl context constructed",
    ),

    # T04B — host clock reached through different call shapes.
    Mutation(
        "T04B", "enclave.rs",
        "pub fn check_lease(valid_until: u64, attested_now: u64) -> bool {\n    valid_until < attested_now\n}",
        "pub fn check_lease(valid_until: std::time::SystemTime) -> bool {\n    valid_until < SystemTime::now()\n}",
        "expiry compared against SystemTime::now",
    ),
    Mutation(
        "T04B", "api.ts",
        "export const agent = new https.Agent({});",
        "export function expired(expiresAt: number): boolean {\n  return expiresAt < Date.now();\n}\nexport const agent = new https.Agent({});",
        "expiry compared against Date.now",
    ),

    # T07A — the timeout removed from a listener as well as a client socket.
    Mutation(
        "T07A", "enclave.rs",
        "use subtle::ConstantTimeEq;",
        "use subtle::ConstantTimeEq;\nuse vsock::VsockListener;\n\npub fn serve() -> std::io::Result<VsockListener> {\n    VsockListener::bind(&addr())\n}\nfn addr() -> vsock::VsockAddr { unimplemented!() }",
        "vsock listener bound with no timeout",
    ),

    # T07B — the oracle phrased differently.
    Mutation(
        "T07B", "handler.py",
        'raise ValueError("decryption failed")',
        'raise ValueError("Bad padding on ciphertext")',
        "padding named in a differently-worded error",
    ),

    # T03B — backtrace egress in two languages.
    Mutation(
        "T03B", "relay.go",
        'func audit(keyFingerprint string) {',
        'func dumpOnPanic() {\n\tdebug.PrintStack()\n}\n\nfunc audit(keyFingerprint string) {',
        "stack dump added to a panic path",
    ),

    # T02 — the policy loosened to a single register rather than stripped entirely.
    # Both pins must go: the clean policy pins PCR1 AND PCR2, so swapping one leaves the
    # other and the policy is still not PCR0-only. The first version of this mutant made
    # that mistake and read as a rule miss when the rule was right.
    Mutation(
        "T02", "kms-key-policy.json",
        r',\s*"kms:RecipientAttestation:PCR2": "[0-9a-fA-F]+"', "",
        "pins collapsed onto PCR0 only",
        extra_edits=(
            (r'"kms:RecipientAttestation:PCR1"', '"kms:RecipientAttestation:PCR0"'),
        ),
        regex=True,
    ),

    # T04A — entropy taken from across the boundary.
    Mutation(
        "T04A", "handler.py",
        "def listen():",
        "def seed_from(msg):\n    import random\n    random.seed(msg)\n\ndef listen():",
        "RNG seeded from a message",
    ),

    # CFG01 — debug mode reached through a variable rather than a literal flag.
    Mutation(
        "CFG01", "run-enclave.sh",
        "nitro-cli run-enclave --cpu-count 2 --memory 512 --eif-path app.eif",
        'FLAGS="--debug-mode"\nnitro-cli run-enclave --cpu-count 2 --memory 512 --eif-path app.eif $FLAGS',
        "debug mode passed through a shell variable",
    ),

    # CFG04 — determinism broken by an unpinned install rather than the base image.
    Mutation(
        "CFG04", "Dockerfile",
        "RUN yum install -y python3-3.9.16 openssl-3.0.8",
        "RUN yum install -y python3 openssl",
        "package versions unpinned",
    ),

    # T09B — a secret in ARG rather than ENV.
    Mutation(
        "T09B", "Dockerfile",
        "COPY . /app",
        "ARG DEPLOY_KEY=0x7c3e0a2b41d6c95a7e3f18b204c7d6e9a1350f4c8b2d7e6a9038f2a559490d1b\nCOPY . /app",
        "private key passed as a build ARG",
    ),

    # T06 — chain validation replaced by a bare signature check on a different shape.
    Mutation(
        "T06", "attest.py",
        "    verify_cert_chain(chain, root)",
        "    pass  # chain check disabled",
        "chain validation call neutered but constant left behind",
    ),

    # CFG02 — the zero check weakened rather than deleted.
    Mutation(
        "CFG02", "attest.py",
        '    if all(b == 0 for v in pcrs.values() for b in v):\n'
        '        raise ValueError("debug-mode attestation rejected")',
        '    if False:\n'
        '        raise ValueError("debug-mode attestation rejected")',
        "zero-PCR check made unreachable",
    ),

    # T01 — conditions kept but pointed at non-attestation keys. Same trap as T02: both
    # pins have to be replaced or an attestation condition survives and the rule is
    # correct to stay quiet.
    Mutation(
        "T01", "kms-key-policy.json",
        r',\s*"kms:RecipientAttestation:PCR2": "[0-9a-fA-F]+"', "",
        "attestation conditions swapped for unrelated keys",
        extra_edits=(
            (r'"kms:RecipientAttestation:PCR1"', '"aws:SourceVpc"'),
        ),
        regex=True,
    ),
    # ---------------------------------------------------------------- EigenCompute ---
    # Planted in the eigencompute-clean tree. Shapes vary the *form* of each defect rather
    # than the file, because a rule that only recognises the idiom its author wrote scores
    # full recall against one mutant and then misses the same bug in real code.

    Mutation(
        "EC01", "src/wallet.ts",
        'hkdfSync("sha256", ikm, Buffer.from(salt, "utf8"), Buffer.from(info, "utf8"), length)',
        'hkdfSync("sha256", Buffer.from(kmsPublicKey), Buffer.from(salt, "utf8"), Buffer.from(info, "utf8"), length)',
        "hkdf keyed on the KMS public key",
        base="eigencompute-clean",
        extra_edits=(("export function deriveKey(",
                      "const kmsPublicKey = process.env.KMS_PUBLIC_KEY ?? \"\";\nexport function deriveKey("),),
    ),
    Mutation(
        "EC01", "src/wallet.ts",
        'const seed = deriveKey(ikm, "example-clean/v1/signing", "ed25519-seed", 32);',
        'const seed = Buffer.from(createHmac("sha256", "v1").update(String(process.env.EIGENCOMPUTE_INSTANCE_ID)).digest());',
        "signing seed derived from the instance id",
        base="eigencompute-clean",
    ),
    Mutation(
        "EC01", "src/wallet.ts",
        "export function initSigning(ikm: Buffer): void {",
        'export function deriveWalletKey(imageDigest: string): string {\n'
        '  return "0x" + createHmac("sha256", "wallet-v1").update(imageDigest).digest("hex");\n}\n\n'
        "export function initSigning(ikm: Buffer): void {",
        "wallet key derived from the image digest",
        base="eigencompute-clean",
    ),

    Mutation(
        "EC02", "src/attest.ts",
        "export async function requireAttestation(nonce: string): Promise<Verified> {",
        "export const teeActive = !!process.env.EIGENCOMPUTE_INSTANCE_ID;\n\n"
        "export async function requireAttestation(nonce: string): Promise<Verified> {",
        "enclave state read off an environment variable",
        base="eigencompute-clean",
    ),
    Mutation(
        "EC02", "src/attest.ts",
        "  if (!EXPECTED_IMAGE_DIGEST || !EXPECTED_APP_ID) {",
        "  if (process.env.KMS_SERVER_URL) {\n    return { imageDigest: \"\", appId: \"\", issuedAt: 0 };\n  }\n"
        "  if (!EXPECTED_IMAGE_DIGEST || !EXPECTED_APP_ID) {",
        "attestation skipped when a platform variable is present",
        base="eigencompute-clean",
    ),

    Mutation(
        "EC03", "src/wallet.ts",
        'const raw = process.env["MNEMONIC"];',
        'const raw = process.env["MNEMONIC"] || "abandon abandon abandon abandon abandon abandon";',
        "mnemonic falls back to a published test phrase",
        base="eigencompute-clean",
    ),
    Mutation(
        "EC03", "src/wallet.ts",
        "const usedPairs = new Set<string>();",
        'const SEAL_KEY = process.env.SEAL_KEY || "0".repeat(64);\nconst usedPairs = new Set<string>();',
        "sealing key defaults to all zeroes",
        base="eigencompute-clean",
    ),
    Mutation(
        "EC03", "src/routes.ts",
        'const ADMIN_TOKEN = process.env["ADMIN_TOKEN"] ?? "";',
        'const ADMIN_TOKEN = process.env["ADMIN_TOKEN"] ?? "changeme-admin-token";',
        "admin token defaults to a hardcoded literal",
        base="eigencompute-clean",
    ),

    Mutation(
        "EC04", "src/attest.ts",
        "  if (!EXPECTED_IMAGE_DIGEST || !EXPECTED_APP_ID) {\n"
        "    throw new Error(\"refusing to start: expected image digest and app id are not pinned\");\n  }",
        "  if (!EXPECTED_IMAGE_DIGEST) {\n    return { imageDigest: \"\", appId: \"\", issuedAt: 0 };\n  }",
        "missing pin turns the check into a pass",
        base="eigencompute-clean",
    ),
    Mutation(
        "EC04", "src/kms.ts",
        "  if (!verifier(payload.value, payload.signature)) {\n    throw new Error(\"signature did not verify\");\n  }",
        "  try {\n    if (!verifier(payload.value, payload.signature)) {\n"
        "      throw new Error(\"signature did not verify\");\n    }\n"
        "  } catch {\n    return createHash(\"sha256\").update(payload.value).digest(\"hex\");\n  }",
        "signature check degrades to a hash on error",
        base="eigencompute-clean",
    ),

    Mutation(
        "EC05", "deploy.sh",
        "  --env-file .env.tee \\",
        '  --private-key "$ECLOUD_PRIVATE_KEY" \\\n  --env-file .env.tee \\',
        "deployer key moved onto the command line",
        base="eigencompute-clean",
    ),
    Mutation(
        "EC05", "deploy.sh",
        "  --log-visibility off",
        '  --log-visibility off --api-key "$SOME_API_KEY"',
        "api key passed as an argument",
        base="eigencompute-clean",
    ),

    Mutation(
        "EC06", "src/routes.ts",
        'app.get("/healthz", (_req, res) => {\n  res.json({ ok: true });\n});',
        'app.get("/debug/env", (_req, res) => {\n'
        "  const out: Record<string, string> = {};\n"
        "  for (const [k, v] of Object.entries(process.env)) {\n"
        "    if (k.startsWith(\"KMS\") || k.startsWith(\"TEE\")) out[k] = String(v);\n  }\n"
        "  res.json(out);\n});",
        "unauthenticated route enumerating the environment",
        base="eigencompute-clean",
    ),

    Mutation(
        "EC07", "Dockerfile", "USER node", "USER root",
        "privilege drop overridden to root",
        base="eigencompute-clean",
    ),

    Mutation(
        "EC08", "ecloud.toml",
        '[egress]\nallow = [\n  "confidentialcomputing.googleapis.com",\n  "example-price-feed.invalid",\n]',
        '[egress]\nallow = ["*"]',
        "egress allowlist widened to a wildcard",
        base="eigencompute-clean",
    ),

    Mutation(
        "CS01", "src/attest.ts",
        "  const { payload } = await jwtVerify(token, JWKS, {\n"
        "    issuer: \"https://confidentialcomputing.googleapis.com\",\n"
        "    audience: AUDIENCE,\n    clockTolerance: 30,\n  });",
        "  const payload = JSON.parse(Buffer.from(token.split(\".\")[1], \"base64\").toString());",
        "signature verification replaced by a base64 decode",
        base="eigencompute-clean",
        also_expects=("CS02",),
    ),
    Mutation(
        "CS01", "src/attest.ts",
        "import { createRemoteJWKSet, jwtVerify } from \"jose\";",
        "import { decodeJwt } from \"jose\";",
        "jwks verification swapped for decodeJwt",
        base="eigencompute-clean",
        also_expects=("CS02",),
        extra_edits=(
            ("  const { payload } = await jwtVerify(token, JWKS, {\n"
             "    issuer: \"https://confidentialcomputing.googleapis.com\",\n"
             "    audience: AUDIENCE,\n    clockTolerance: 30,\n  });",
             "  const payload = decodeJwt(token);"),
            ("const JWKS = createRemoteJWKSet(\n"
             "  new URL(\"https://confidentialcomputing.googleapis.com/.well-known/jwks.json\"),\n);",
             ""),
        ),
    ),

    Mutation(
        "CS02", "src/attest.ts",
        '  if (payload.hwmodel !== "INTEL_TDX") {\n'
        "    throw new Error(`unexpected hardware model: ${String(payload.hwmodel)}`);\n  }",
        "",
        "hardware model check removed",
        base="eigencompute-clean",
        extra_edits=(
            ('  if (payload.swname !== "CONFIDENTIAL_SPACE") {\n'
             "    throw new Error(`unexpected software stack: ${String(payload.swname)}`);\n  }", ""),
            ("  if (payload.secboot !== true) {\n"
             "    throw new Error(\"secure boot was not asserted\");\n  }", ""),
            ('  const tcb = String(payload.tcbstatus ?? payload.tcb_status ?? "");\n'
             '  if (tcb !== "OK" && tcb !== "UpToDate") {\n'
             "    throw new Error(`TCB is not up to date: ${tcb}`);\n  }", ""),
        ),
    ),

    Mutation(
        "CS03", "src/attest.ts",
        "export async function requireAttestation(nonce: string): Promise<Verified> {\n"
        "  const verified = await verifyAttestationToken(nonce);",
        "export async function requireAttestation(nonce: string): Promise<Verified> {\n"
        "  let verified: Verified;\n  try {\n    verified = await verifyAttestationToken(nonce);\n"
        "  } catch (err) {\n    console.warn(\"attestation unavailable, continuing\");\n"
        "    verified = { imageDigest: \"\", appId: \"\", issuedAt: 0 };\n    return verified;\n  }",
        "attestation failure caught and boot continues",
        base="eigencompute-clean",
    ),

    Mutation(
        "T01", "src/attest.ts",
        "  if (imageDigest !== EXPECTED_IMAGE_DIGEST) {\n"
        "    throw new Error(\"image digest does not match the pinned digest; refusing to start\");\n  }",
        "",
        "image digest read but never compared",
        base="eigencompute-clean",
        extra_edits=(
            ('const EXPECTED_IMAGE_DIGEST = process.env.EXPECTED_IMAGE_DIGEST ?? "";',
             'const EXPECTED_IMAGE_DIGEST = "";'),
        ),
    ),

]


def audit(path: Path) -> dict:
    proc = subprocess.run(
        [PYTHON, str(ROOT / "cli" / "audit.py"), str(path), "--format", "json"],
        capture_output=True, text=True, timeout=900,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        raise RuntimeError(f"audit failed on {path}: {proc.stderr[-800:]}")
    return json.loads(proc.stdout)


def families(result: dict) -> set[str]:
    return {f["rule_id"].split("-")[1] for f in result["findings"]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=None,
                    help="run only mutants for this fixture tree (default: all)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--markdown", metavar="PATH",
                    help="also write the per-rule table to a markdown file")
    args = ap.parse_args()

    mutations = [m for m in MUTATIONS if args.base is None or m.base == args.base]
    if not mutations:
        print(f"no mutants for base {args.base!r}", file=sys.stderr)
        return 1

    # One baseline per tree, computed once. Collateral is measured against the tree a
    # mutant was actually planted in, never against another platform's tree.
    bases: dict[str, Path] = {}
    baselines: dict[str, set[str]] = {}
    for name in sorted({m.base for m in mutations}):
        tree = (ROOT / "bench" / "fixtures" / name).resolve()
        if not tree.is_dir():
            print(f"no such fixture tree: {tree}", file=sys.stderr)
            return 1
        bases[name] = tree
        fams = families(audit(tree))
        baselines[name] = fams
        if fams:
            print(
                f"warning: baseline {name} is not clean, it reports {sorted(fams)}. "
                "Collateral counts are measured against it, not against zero.\n",
                file=sys.stderr,
            )

    rows = []
    for i, mut in enumerate(mutations):
        base = bases[mut.base]
        baseline_families = baselines[mut.base]
        with tempfile.TemporaryDirectory(prefix="tee-audit-mutant-") as tmp:
            work = Path(tmp) / "repo"
            shutil.copytree(base, work)

            if not mut.apply(work):
                rows.append({
                    "rule": mut.rule_family, "target": mut.target, "note": mut.note,
                    "base": mut.base,
                    "status": "inapplicable", "detected": False, "collateral": [],
                })
                continue

            result = audit(work)
            found = families(result)
            collateral = sorted(
                found - baseline_families - {mut.rule_family} - set(mut.also_expects)
            )
            rows.append({
                "rule": mut.rule_family,
                "target": mut.target,
                "note": mut.note,
                "status": "ok",
                "detected": mut.rule_family in found,
                "collateral": collateral,
                "base": mut.base,
                "layer": result["scorecard"]["effective_layer"],
            })

    applied = [r for r in rows if r["status"] == "ok"]
    scores = score(rows, set())

    if args.json:
        print(json.dumps({
            "bases": {name: sorted(fams) for name, fams in baselines.items()},
            "mutations": rows,
            "per_rule": scores,
            "recall": (sum(s["tp"] for s in scores.values())
                       / max(1, sum(s["planted"] for s in scores.values()))),
        }, indent=2))
        return 0 if all(s["tp"] == s["planted"] for s in scores.values()) else 1

    for name in sorted(bases):
        n = len([r for r in rows if r.get("base") == name])
        print(f"base tree: {name}  ({n} mutants, baseline "
              f"{sorted(baselines[name]) or 'clean'})")
    print()

    print(f"{'rule':8} {'recall':>10} {'precision':>11} {'planted':>8} {'fp':>4}  shapes")
    print("-" * 96)
    for rule in sorted(scores):
        s = scores[rule]
        rec = f"{s['tp']}/{s['planted']}"
        prec = "n/a" if (s["tp"] + s["fp"]) == 0 else f"{100 * s['precision']:.0f}%"
        print(f"{rule:8} {rec:>10} {prec:>11} {s['planted']:>8} {s['fp']:>4}  "
              f"{', '.join(s['shapes'][:3])}")

    total_tp = sum(s["tp"] for s in scores.values())
    total_planted = sum(s["planted"] for s in scores.values())
    total_fp = sum(s["fp"] for s in scores.values())

    print()
    print(f"applied      {len(applied)}/{len(rows)} mutants")
    print(f"recall       {total_tp}/{total_planted}"
          + (f"  ({100 * total_tp / total_planted:.0f}%)" if total_planted else ""))
    print(f"false pos    {total_fp} finding(s) attributable to no planted defect")

    for r in applied:
        if not r["detected"]:
            print(f"  MISS  {r['rule']:8} {r['target']:22} {r['note']}")
        if r["collateral"]:
            print(f"  EXTRA {r['rule']:8} {r['target']:22} -> {r['collateral']}")
    for r in rows:
        if r["status"] == "inapplicable":
            print(f"  SKIP  {r['rule']:8} {r['target']:22} {r['note']}")

    if args.markdown:
        out = Path(args.markdown)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(render_markdown(scores, rows, bases), encoding="utf-8")
        print(f"\nwrote {out}")

    return 0 if total_tp == total_planted else 1


def score(rows: list[dict], _unused: set[str] | None = None) -> dict[str, dict]:
    """Per-rule precision and recall.

    recall    = detections ÷ mutants planting that rule
    precision = detections ÷ (detections + firings attributable to no planted defect)

    The precision denominator counts a rule firing on a mutant that planted something else,
    which is the harsh reading on purpose: on the clean tree that finding did not exist, so
    the mutation caused it and the rule owns it. Baseline findings are excluded because the
    clean tree is asserted to be empty elsewhere; if it ever is not, main() warns.
    """
    planted: dict[str, int] = {}
    tp: dict[str, int] = {}
    fp: dict[str, int] = {}
    shapes: dict[str, list[str]] = {}

    for r in rows:
        if r["status"] != "ok":
            continue
        rule = r["rule"]
        planted[rule] = planted.get(rule, 0) + 1
        shapes.setdefault(rule, []).append(r["note"])
        if r["detected"]:
            tp[rule] = tp.get(rule, 0) + 1
        for other in r["collateral"]:
            fp[other] = fp.get(other, 0) + 1

    out: dict[str, dict] = {}
    for rule in sorted(set(planted) | set(fp)):
        t, f = tp.get(rule, 0), fp.get(rule, 0)
        out[rule] = {
            "planted": planted.get(rule, 0),
            "tp": t,
            "fp": f,
            "recall": t / planted[rule] if planted.get(rule) else 0.0,
            "precision": t / (t + f) if (t + f) else 0.0,
            "shapes": shapes.get(rule, []),
        }
    return out


def render_markdown(scores: dict[str, dict], rows: list[dict], bases: dict) -> str:
    total_tp = sum(s["tp"] for s in scores.values())
    total_planted = sum(s["planted"] for s in scores.values())
    total_fp = sum(s["fp"] for s in scores.values())

    lines = [
        "# Benchmark results — mutation corpus",
        "",
        "Generated by `bench/mutate.py`. Ground truth is exact by construction: the harness",
        "plants one catalogued defect in a clean tree and asks whether that rule fires.",
        "",
        "Mutants are planted per platform: a rule gated on EigenCompute cannot be exercised",
        "in a Nitro tree, and a mutant that finds none of its target text reports",
        "`inapplicable` and is then dropped from scoring — a recall hole that reads as a",
        "clean run. Every mutant names the tree it belongs to.",
        "",
    ] + [
        f"- base tree `bench/fixtures/{name}`: "
        f"{len([r for r in rows if r.get('base') == name])} mutants"
        for name in sorted(bases)
    ] + [
        f"- mutants: {len([r for r in rows if r['status'] == 'ok'])} applied, "
        f"{len([r for r in rows if r['status'] != 'ok'])} inapplicable",
        f"- **recall {total_tp}/{total_planted}"
        + (f" ({100 * total_tp / total_planted:.0f}%)**" if total_planted else "**"),
        f"- **false positives: {total_fp}**",
        "",
        "`precision` counts a rule firing on a mutant that planted a *different* defect as a",
        "false positive — that finding did not exist on the clean tree, so the rule owns it.",
        "",
        "| rule | platform | recall | precision | mutants | FP | defect shapes tested |",
        "|---|---|---|---|---|---|---|",
    ]
    rule_base = {}
    for r in rows:
        rule_base.setdefault(r["rule"], set()).add(
            "eigencompute" if r.get("base", "clean").startswith("eigencompute") else "nitro"
        )
    for rule in sorted(scores):
        s = scores[rule]
        rec = f"{s['tp']}/{s['planted']}"
        prec = "n/a" if (s["tp"] + s["fp"]) == 0 else f"{100 * s['precision']:.0f}%"
        plat = ", ".join(sorted(rule_base.get(rule, {"nitro"})))
        lines.append(
            f"| `{rule}` | {plat} | {rec} | {prec} | {s['planted']} | {s['fp']} | "
            f"{'; '.join(s['shapes'])} |"
        )

    misses = [r for r in rows if r["status"] == "ok" and not r["detected"]]
    if misses:
        lines += ["", "## Misses", ""]
        lines += [f"- `{r['rule']}` — {r['note']} (`{r['target']}`)" for r in misses]

    skipped = [r for r in rows if r["status"] != "ok"]
    if skipped:
        lines += ["", "## Inapplicable mutants", "",
                  "These did not apply against the current fixture tree and are reported",
                  "rather than silently dropped — a mutation that matches nothing would",
                  "otherwise look like a recall failure.", ""]
        lines += [f"- `{r['rule']}` — {r['note']} (`{r['target']}`)" for r in skipped]

    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
