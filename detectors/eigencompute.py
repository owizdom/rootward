"""EigenCompute rules — BT-EC01 (key derived from public material), BT-EC02 (enclave state
asserted from an environment variable), BT-EC03 (dev-key fallback reachable in production),
BT-EC04 (security check silently disabled), BT-EC05 (deploy secret in argv), BT-EC06
(unauthenticated environment dump), BT-EC07 (container runs as root), BT-EC08 (egress
allowlist absent or wildcard).

Gated on EigenCompute, because most of these only mean something given how that platform
works. Worth stating once, since every rule below refers back to it:

Secrets are never baked into an EigenCompute image. At container start the platform's
`compute-source-env.sh` runs `kms-client`, which fetches the app's environment from KMS,
verifies the response against a signing public key pinned into the image at
`/usr/local/bin/kms-signing-public-key.pem`, writes `/tmp/.env`, sources it, deletes it, and
drops privileges. KMS releases that environment only to an attested Docker image digest,
recorded on chain. The wallet the app spends from derives from `MNEMONIC`, delivered by
exactly that path.

So the interesting failures here are not "a secret leaked". They are "the app rebuilt, by
hand, a weaker version of a guarantee the platform already provides" — deriving its own key
from something public, deciding it is in a TEE because an environment variable is set, or
committing the mnemonic the KMS exists to deliver.
"""

from __future__ import annotations

import re
from pathlib import Path

from model import (
    Confidence,
    Finding,
    Severity,
    code_only,
    quote_line,
    read_lines,
    strip_string_literals,
)
from platform_detect import Platform

SKIP_DIRS = {".git", "node_modules", "target", "venv", ".venv", "dist", "build", "__pycache__"}
CODE = {".ts", ".js", ".mjs", ".cjs", ".py", ".go", ".rs"}
SHELLY = {".sh", ".bash", ".zsh", ".yml", ".yaml", ".mk", ""}

# --------------------------------------------------------------- BT-EC01 ---

# A key-derivation or digest call, with its argument list captured.
KDF_CALL = re.compile(
    r"(?i)\b("
    r"createHmac|createHash|hkdfSync|hkdf|pbkdf2(Sync)?|scrypt(Sync)?"
    r"|hmac\.new|HMAC\.new|PBKDF2|derive_?key|deriveKey"
    r"|Hmac::new(_from_slice)?|Sha256::(new|digest)"
    r")\s*\(([^;\n]{0,200})",
)

# Values an observer can read. A key derived from any of these is a key the observer can
# also derive. `kmsPublicKey` is the live case: a *public* key used as keying material.
PUBLIC_INPUT = re.compile(
    r"(?i)\b("
    r"\w*public_?key\w*|\w*pub_?key\w*|\w*spki\w*"
    r"|\w*instance_?id\w*|EIGENCOMPUTE_INSTANCE_ID|EIGENCLOUD_INSTANCE_ID"
    r"|\w*image_?digest\w*|\w*app_?id\w*|\w*chain_?id\w*"
    r"|\w*hostname\w*|\w*domain\w*|\w*account_?address\w*"
    r")\b"
)

# Genuinely secret keying material. Named separately rather than as "not public" because a
# correct HKDF and a broken one are the same call with a different second argument, and the
# whole precision of this rule is in telling those apart.
SECRET_INPUT = re.compile(
    r"(?i)\b("
    r"mnemonic|seed|master|\bikm\b|entropy|private_?key|priv_?key|secret|passphrase"
    r"|password|randomBytes|randomUUID|urandom|getrandom|KeyObject"
    r")\b"
)

# Evidence that what comes out of the derivation is used as a key, rather than as a
# fingerprint or a pin. Without this, computing sha256 of a peer certificate for TLS
# pinning — which is correct and desirable — reads as a violation.
KEY_PRODUCED = re.compile(
    r"(?i)("
    r"private_?key|priv_?key|signing_?key|signer|wallet|\bsk\b|secret_?key"
    r"|\"0x\"\s*\+|'0x'\s*\+|`0x\$\{"
    r"|new\s+Wallet|Wallet\.from|privateKeyToAccount|from_?phrase|Account\s*\("
    r"|createPrivateKey|generateKeyPair"
    r")"
)

# --------------------------------------------------------------- BT-EC02 ---

# "We are in a TEE because an environment variable is set." The variable is supplied by the
# host, so this is the host asserting its own trustworthiness.
ENV_AS_PROOF = re.compile(
    r"(?i)("
    r"(?:if|elif)\s*\(?\s*(?:process\.env|os\.environ(?:\.get)?)[\.\[]\s*[\"']?"
    r"(EIGENCOMPUTE_INSTANCE_ID|EIGENCLOUD_INSTANCE_ID|KMS_SERVER_URL|KMS_PUBLIC_KEY)"
    r"|(?:tee_?active|in_?tee|is_?tee|tee_?mode|teeMode|teeActive)\s*[:=]+\s*"
    r"(?:!!)?\s*(?:Boolean\s*\()?\s*(?:process\.env|os\.environ)"
    r")"
)

# --------------------------------------------------------------- BT-EC03 ---

# Published keys everyone has. The Rust core already classifies these as known test vectors
# and downgrades them to info, which is correct when they sit in a fixture. The finding here
# is different: the key is a *fallback*, so it is what the process runs on when the
# environment is not provisioned.
WELL_KNOWN_KEY = re.compile(
    r"(?i)("
    r"0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    r"|0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
    r"|test test test test test test test test test test test junk"
    r"|abandon abandon abandon abandon"
    r")"
)
# A key-shaped default reached with ||, ??, or `or`.
WEAK_DEFAULT = re.compile(
    r"(?i)(process\.env[\.\[][\"']?(\w*(?:KEY|MNEMONIC|SEED|SECRET|TOKEN)\w*)[\"']?\]?"
    r"|os\.environ(?:\.get)?[\.\(\[][\"'](\w*(?:KEY|MNEMONIC|SEED|SECRET|TOKEN)\w*)[\"'])"
    r"\s*(?:\|\||\?\?|,|\bor\b)\s*"
    r"([\"'`][^\"'`\n]{4,}[\"'`]|[\"']0[\"']\s*\.\s*repeat|Buffer\.alloc)",
)
PROD_GUARD = re.compile(r"(?i)(NODE_ENV|ECLOUD_ENVIRONMENT|APP_ENV|is_?prod|production)")

# A default that is a path, a URL, or a filename is configuration. `KMS_SIGNING_KEY_FILE`
# contains "KEY" and defaults to the .pem the platform ships at a fixed location, which
# is both correct and required — flagging it would train the reader to skip EC03.
NOT_A_SECRET_DEFAULT = re.compile(
    r"(?i)(^[\"\'`]?(/|\./|~|[a-z]+://)|\.(pem|json|toml|ya?ml|txt|key|crt|sock)[\"\'`]?$"
    r"|localhost|127\.0\.0\.1|0\.0\.0\.0)"
)
# ...and neither is the *name* of a path-shaped variable.
PATHY_NAME = re.compile(r"(?i)_(FILE|PATH|DIR|URL|URI|ENDPOINT|HOST|SERVER)$")

# --------------------------------------------------------------- BT-EC04 ---

# A pin that is optional is a pin that is off. `if (!expected) return;` inside a function
# whose whole job is to check something reads as defensive and disables the check.
OPTIONAL_PIN = re.compile(
    r"(?is)\b(?:function|def|fn)\s+(\w*(?:verify|check|assert|validate|enforce|require|pin)\w*)"
    r"\s*\([^)]*\)[^{:]*[{:](.{0,300})"
)
EARLY_RETURN_ON_MISSING = re.compile(
    r"(?i)if\s*\(?\s*!\s*(\w*(?:expected|pin|allow|trusted|known)\w*)\s*\)?\s*(?:\{\s*)?"
    r"(?:return\b|pass\b)"
)

# A signer whose catch block returns a hash is a signer anyone can forge.
SIGN_FALLBACK = re.compile(
    r"(?is)(?:catch\s*(?:\([^)]*\))?\s*\{|except[^\n:]*:)\s*"
    r"(?:return\s+)?[^}]{0,160}?(createHash|sha256|md5|hashlib\.)"
)

# --------------------------------------------------------------- BT-EC05 ---

SECRET_ARGV = re.compile(
    r"(?i)--(private-key|priv-key|api-key|secret|mnemonic|token)[= ]+"
    r"[\"']?(?!\s*$)(\$\{?\w+\}?|0x[0-9a-f]{16,}|[A-Za-z0-9_\-]{16,})"
)

# --------------------------------------------------------------- BT-EC06 ---

ROUTE_HANDLER = re.compile(
    r"(?i)(app|router|server)\.(get|post|all)\s*\(\s*[\"'`]([^\"'`]+)[\"'`]"
    r"|@(?:app|router)\.(?:route|get|post)\s*\(\s*[\"']([^\"']+)[\"']"
    r"|http\.HandleFunc\s*\(\s*[\"']([^\"']+)[\"']"
)
ENV_ENUMERATION = re.compile(
    r"(?i)(Object\.(keys|entries|assign)\s*\(\s*process\.env"
    r"|for\s+\w+\s+in\s+os\.environ|dict\s*\(\s*os\.environ|os\.environ\.items"
    r"|process\.env\s*\)|\bos\.Environ\s*\(\s*\))"
)
AUTH_PRESENT = re.compile(
    r"(?i)(requireAuth|requireAdmin|authenticate|authorize|isAuthed|@login_required"
    r"|verify_?(token|admin|api_?key)|checkAdmin|middleware|Depends\s*\(|guard)"
)

# --------------------------------------------------------------- BT-EC07 ---

USER_ROOT = re.compile(r"(?im)^\s*USER\s+(root|0)\s*$")
USER_ANY = re.compile(r"(?im)^\s*USER\s+\S+")


def _iter(root: Path, suffixes: set[str]):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix not in suffixes and path.name not in {"Dockerfile", "Makefile"}:
            continue
        low = str(path).lower()
        if low.endswith((".spec.ts", ".test.ts", ".d.ts")) or "/test" in low or "/__tests__" in low:
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        yield path, raw


def _iter_code(root: Path):
    for path, raw in _iter(root, CODE):
        code = code_only(raw, path.suffix)
        yield path, raw, code, strip_string_literals(code)


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


ENCLOSING_FN = re.compile(r"(?i)\b(?:function|def|fn)\s+(\w+)|\b(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(")


def _enclosing_name(text: str, pos: int) -> str | None:
    """Name of the nearest function definition above `pos`."""
    best = None
    for m in ENCLOSING_FN.finditer(text, 0, pos):
        best = m.group(1) or m.group(2)
    return best


def _enclosing_span(text: str, pos: int) -> str:
    start = text.rfind("\n\n", 0, pos)
    return text[max(0, start): pos + 200]


def check_public_key_derivation(root: Path) -> list[Finding]:
    """BT-EC01 — a key is derived from material an observer can read.

    The headline rule. A KDF is only as secret as its input: HKDF over a public key is a
    deterministic public function, so every party who can read that public key computes the
    same "private" key. This is worse than a hardcoded secret, because it looks like key
    derivation in review and carries the vocabulary of one — salt, info, HMAC, extract-and-
    expand — while providing none of the property.
    """
    out: list[Finding] = []
    for path, raw, code, impl in _iter_code(root):
        lines = read_lines(path)
        rel = str(path.relative_to(root))
        for m in KDF_CALL.finditer(impl):
            args = m.group(m.lastindex) or ""
            # The call chain matters: `createHash(alg).update(x)` puts the input after the
            # closing paren, so read a little past the call too.
            window = impl[m.start(): m.start() + 260]
            if not PUBLIC_INPUT.search(window):
                continue
            if SECRET_INPUT.search(window.split("(", 1)[-1][:160]):
                continue
            # Is the output actually used as a key? Computing sha256 of a peer certificate
            # for TLS pinning hits every pattern above and is correct.
            context = impl[max(0, m.start() - 200): m.start() + 700]
            if not KEY_PRODUCED.search(context):
                continue
            line = _line(impl, m.start())
            public_bit = PUBLIC_INPUT.search(window)
            out.append(
                Finding(
                    rule_id="BT-EC01-key-from-public-input",
                    file=rel,
                    line=line,
                    evidence=quote_line(lines, line),
                    message=(
                        f"A signing key is derived from `{public_bit.group(0)}`, a value that "
                        "is not secret. Key derivation does not create secrecy; it only "
                        "preserves it. Every party who can read this input runs the same "
                        "function with the same salt and info constants — both of which are "
                        "in this repository — and obtains the same private key. If the input "
                        "is reachable over the network or recorded on chain, the wallet this "
                        "key controls is spendable by anyone who looks."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    detector="detectors:eigencompute.check_public_key_derivation",
                    metadata={"derived_from": public_bit.group(0)},
                )
            )
    return out


def check_env_as_attestation(root: Path) -> list[Finding]:
    """BT-EC02 — enclave state is asserted from an environment variable."""
    out: list[Finding] = []
    for path, raw, code, impl in _iter_code(root):
        m = ENV_AS_PROOF.search(impl)
        if not m:
            continue
        rel = str(path.relative_to(root))
        lines = read_lines(path)
        line = _line(impl, m.start())
        out.append(
            Finding(
                rule_id="BT-EC02-env-presence-as-attestation",
                file=rel,
                line=line,
                evidence=quote_line(lines, line),
                message=(
                    "Whether the workload is running in a TEE is decided by the presence of "
                    "an environment variable. The environment is supplied by the platform "
                    "the enclave is supposed to be proving itself to, so this is the host "
                    "vouching for itself. Anyone who can set the variable — including on an "
                    "ordinary VM — gets the same answer, and every downstream branch guarded "
                    "by it inherits the mistake. Enclave state comes from a verified "
                    "attestation or it is not known."
                ),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                detector="detectors:eigencompute.check_env_as_attestation",
            )
        )
    return out


def check_dev_key_fallback(root: Path) -> list[Finding]:
    """BT-EC03 — a development key or weak default is what runs when the env is unset."""
    out: list[Finding] = []
    for path, raw in _iter(root, CODE | SHELLY):
        code = code_only(raw, path.suffix)
        rel = str(path.relative_to(root))
        lines = read_lines(path)
        seen: set[int] = set()

        for m in WEAK_DEFAULT.finditer(code):
            line = _line(code, m.start())
            if line in seen:
                continue
            var_name = m.group(2) or m.group(3) or ""
            default = (m.group(4) or "").strip()
            if PATHY_NAME.search(var_name) or NOT_A_SECRET_DEFAULT.search(default):
                continue
            block = code[max(0, m.start() - 300): m.start() + 300]
            if PROD_GUARD.search(block):
                continue
            seen.add(line)
            well_known = bool(WELL_KNOWN_KEY.search(m.group(0)))
            out.append(
                Finding(
                    rule_id="BT-EC03-dev-key-fallback",
                    file=rel,
                    line=line,
                    evidence=quote_line(lines, line),
                    message=(
                        "A key or seed falls back to a hardcoded default when its environment "
                        "variable is unset, with no environment guard. On EigenCompute the "
                        "environment is delivered by KMS after attestation, so the case this "
                        "branch handles is exactly the case where attestation did not happen "
                        "— and it handles it by running on a key that is in the source tree."
                        + (
                            " The default here is a published test key that everyone has."
                            if well_known
                            else ""
                        )
                    ),
                    severity=Severity.CRITICAL if well_known else Severity.HIGH,
                    confidence=Confidence.HIGH,
                    detector="detectors:eigencompute.check_dev_key_fallback",
                    metadata={"well_known_key": well_known},
                )
            )
    return out


def check_disabled_checks(root: Path) -> list[Finding]:
    """BT-EC04 — a security check that turns itself off, or degrades to something weaker."""
    out: list[Finding] = []
    for path, raw, code, impl in _iter_code(root):
        rel = str(path.relative_to(root))
        lines = read_lines(path)

        for m in OPTIONAL_PIN.finditer(impl):
            fn_name, body = m.group(1), m.group(2)
            hit = EARLY_RETURN_ON_MISSING.search(body)
            if not hit:
                continue
            line = _line(impl, m.start(2) + hit.start())
            out.append(
                Finding(
                    rule_id="BT-EC04-check-silently-disabled",
                    file=rel,
                    line=line,
                    evidence=quote_line(lines, line),
                    message=(
                        f"`{fn_name}` returns successfully when its expected value is unset, "
                        "so the check it exists to perform is skipped rather than failed. A "
                        "pin that is absent should stop the process: a deployment that forgot "
                        "to configure one is indistinguishable here from a deployment that "
                        "passed, and it reports the same result."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    detector="detectors:eigencompute.check_disabled_checks",
                )
            )

        for m in SIGN_FALLBACK.finditer(impl):
            block = impl[max(0, m.start() - 400): m.start()]
            if not re.search(r"(?i)(sign|signature|attest)", block):
                continue
            line = _line(impl, m.start())
            out.append(
                Finding(
                    rule_id="BT-EC04-check-silently-disabled",
                    file=rel,
                    line=line,
                    evidence=quote_line(lines, line),
                    message=(
                        "Signing falls back to a plain hash when it throws. A hash is not a "
                        "signature: it takes no key, so anyone can compute it over any "
                        "content. Every consumer that checks this value sees something "
                        "well-formed and accepts forged input, and the failure is silent "
                        "because the fallback returns the same shape as success."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    detector="detectors:eigencompute.check_disabled_checks",
                )
            )
    return out


def check_secret_in_argv(root: Path) -> list[Finding]:
    """BT-EC05 — a deploy secret passed as a command-line argument."""
    out: list[Finding] = []
    for path, raw in _iter(root, SHELLY | {".md"}):
        code = code_only(raw, path.suffix)
        if not re.search(r"(?i)\b(ecloud|eigenx)\b", code):
            continue
        rel = str(path.relative_to(root))
        lines = read_lines(path)
        for m in SECRET_ARGV.finditer(code):
            line = _line(code, m.start())
            out.append(
                Finding(
                    rule_id="BT-EC05-deploy-secret-in-argv",
                    file=rel,
                    line=line,
                    evidence=quote_line(lines, line),
                    message=(
                        f"`--{m.group(1)}` is passed as a command-line argument. Argument "
                        "vectors are world-readable in `ps`, land in shell history, and are "
                        "echoed into CI logs — three places this key was never meant to be. "
                        "The CLI reads the same value from the environment, which none of "
                        "those capture."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    detector="detectors:eigencompute.check_secret_in_argv",
                )
            )
    return out


def check_env_dump_route(root: Path) -> list[Finding]:
    """BT-EC06 — an unauthenticated HTTP route that enumerates the environment."""
    out: list[Finding] = []
    for path, raw, code, impl in _iter_code(root):
        if not ENV_ENUMERATION.search(impl):
            continue
        routes = list(ROUTE_HANDLER.finditer(impl))
        if not routes:
            continue
        m = ENV_ENUMERATION.search(impl)

        # Which route reaches the enumeration matters. A file with one authenticated route
        # and one open debug route has auth "present", and checking file-wide would let the
        # open one through -- which is the arrangement this rule exists to find.
        enumerating_fn = _enclosing_span(impl, m.start())
        reachable_unguarded = False
        for r in routes:
            span = impl[r.start(): r.start() + 600]
            if AUTH_PRESENT.search(span):
                continue
            # The handler either enumerates inline or calls the helper that does.
            helper = _enclosing_name(impl, m.start())
            if ENV_ENUMERATION.search(span) or (helper and helper in span):
                reachable_unguarded = True
                break
        if not reachable_unguarded:
            continue
        rel = str(path.relative_to(root))
        lines = read_lines(path)
        line = _line(impl, m.start())
        out.append(
            Finding(
                rule_id="BT-EC06-unauthenticated-env-dump",
                file=rel,
                line=line,
                evidence=quote_line(lines, line),
                message=(
                    "An HTTP route in this file enumerates the process environment, and no "
                    "authentication appears anywhere in the file. On EigenCompute the "
                    "environment is where KMS puts the app's secrets, so this publishes the "
                    "material the enclave exists to protect. Even truncated values are enough "
                    "when they are the inputs to a key derivation."
                ),
                severity=Severity.CRITICAL,
                confidence=Confidence.MEDIUM,
                detector="detectors:eigencompute.check_env_dump_route",
            )
        )
    return out


def check_container_user(root: Path) -> list[Finding]:
    """BT-EC07 — the container overrides the platform's privilege drop."""
    out: list[Finding] = []
    for path, raw in _iter(root, {""}):
        if path.name != "Dockerfile" and not path.name.startswith("Dockerfile"):
            continue
        code = code_only(raw, "")
        m = USER_ROOT.search(code)
        if not m:
            continue
        rel = str(path.relative_to(root))
        lines = read_lines(path)
        line = _line(code, m.start())
        out.append(
            Finding(
                rule_id="BT-EC07-container-runs-as-root",
                file=rel,
                line=line,
                evidence=quote_line(lines, line),
                message=(
                    "The image runs as root. The EigenCompute entrypoint sources the "
                    "KMS-delivered environment, deletes it from disk, and then deliberately "
                    "drops privileges to the image's original user before starting the "
                    "workload. Declaring root removes the second half of that: the "
                    "application process keeps full capability over the container it shares "
                    "with the KMS client and the signing key material."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                detector="detectors:eigencompute.check_container_user",
            )
        )
    return out


# --------------------------------------------------------- manifest ---


def parse_ecloud_toml(path: Path) -> dict:
    """Normalise both observed `ecloud.toml` schemas into one flat dict.

    Two shapes are in the wild: a flat one (`instance_type`, `log_visibility`, `[wallet]
    source`) and a nested one (`[app]`, `[runtime] shape`, `[attestation] mode`, `[egress]
    allow`). Reading only one of them silently skips every app that uses the other, so the
    normalisation lives here and every manifest rule reads the result.
    """
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - py<3.11
        return {}
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return {}

    runtime = data.get("runtime") or {}
    app = data.get("app") or {}
    egress = data.get("egress") or {}
    return {
        "name": data.get("name") or app.get("name"),
        "log_visibility": data.get("log_visibility") or runtime.get("log_visibility"),
        "instance_type": data.get("instance_type") or runtime.get("shape"),
        "wallet_source": (data.get("wallet") or {}).get("source"),
        "attestation_mode": (data.get("attestation") or {}).get("mode"),
        "egress_allow": egress.get("allow"),
        "has_egress_block": "egress" in data,
        "raw": data,
    }


def check_egress(root: Path) -> list[Finding]:
    """BT-EC08 — no egress allowlist, or one that allows everything."""
    out: list[Finding] = []
    for path in root.rglob("ecloud.toml"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        manifest = parse_ecloud_toml(path)
        if not manifest:
            continue
        allow = manifest.get("egress_allow")
        wildcard = isinstance(allow, list) and any(a in ("*", "0.0.0.0/0", "::/0") for a in allow)
        if manifest.get("has_egress_block") and allow and not wildcard:
            continue
        rel = str(path.relative_to(root))
        lines = read_lines(path)
        out.append(
            Finding(
                rule_id="BT-EC08-egress-unrestricted",
                file=rel,
                line=1,
                evidence=(
                    f"egress allow = {allow!r}" if manifest.get("has_egress_block")
                    else "no [egress] block in the manifest"
                ),
                message=(
                    "The deployment manifest does not restrict outbound traffic. A "
                    "Confidential Space workload has an ordinary network stack, so an "
                    "unrestricted enclave can send anything it holds anywhere — which turns "
                    "any code-execution or dependency-compromise issue into direct "
                    "exfiltration of the wallet seed. An allowlist naming the hosts the app "
                    "genuinely needs bounds that blast radius."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                detector="detectors:eigencompute.check_egress",
                metadata={"allow": allow},
            )
        )
    return out


def run(root: Path, platform: Platform | None = None) -> list[Finding]:
    """No-ops unless the repo deploys to EigenCompute."""
    if platform is not None and not platform.eigencompute:
        return []
    return [
        *check_public_key_derivation(root),
        *check_env_as_attestation(root),
        *check_dev_key_fallback(root),
        *check_disabled_checks(root),
        *check_secret_in_argv(root),
        *check_env_dump_route(root),
        *check_container_user(root),
        *check_egress(root),
    ]


if __name__ == "__main__":
    import sys

    import platform_detect
    from model import to_json

    target = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    p = platform_detect.detect(target)
    print(to_json(run(target, p), root=str(target), platform=p.summary()))
