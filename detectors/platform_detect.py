"""Platform detection. Nitro Enclaves, dstack, Confidential Space, EigenCompute, or none.

Four tiers, two of them layered: EigenCompute runs on Google Cloud Confidential Space, so
detecting the deployment layer implies the substrate. The generic Confidential Space rules
then apply to any TDX workload there, while the EigenCloud-specific rules stay gated.

Without this, every dstack rule fires on every Nitro repo and vice versa, and a report full
of inapplicable findings is worse than no report: it trains the reader to skim. Detection is
evidence-based and reported alongside the result, so a reader can see *why* the tool decided
a repo was dstack and overrule it when the guess is wrong.

Deliberately conservative. When nothing indicates a TEE platform at all. that is itself
worth saying, auditing a repo that turns out not to use enclaves should produce "no TEE
platform detected", not a clean bill of health.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", "target", "venv", ".venv", "dist", "build", "__pycache__"}

# Signals are weighted, because a single weak one must not unlock a whole platform's rules.
# A lone mention of "app-compose.json" in a path string inside a Nitro fixture flipped the
# platform to dstack and fired all five dstack rules on a repository that does not use it.
# Weight 2 = unmistakable (a tool, an API, a contract name that exists nowhere else).
# Weight 1 = suggestive but coincidental in isolation (a filename, a vendor name, a
# transport used by more than one platform).
STRONG, WEAK = 2, 1
DETECT_THRESHOLD = 2  # one strong signal, or two independent weak ones

NITRO_SIGNALS: list[tuple[str, re.Pattern, int]] = [
    ("nitro-cli invocation", re.compile(r"\bnitro-cli\b"), STRONG),
    # The leading \b applied to the whole group, and there is no word boundary before the
    # "/" in "/dev/nsm", so that alternative never matched anything a real repo contains --
    # a STRONG signal (enough on its own to identify Nitro) that was silently dead. Each
    # alternative now carries its own anchoring.
    ("NSM API", re.compile(r"(?i)(\bnsm_?api\b|/dev/nsm\b|\bnitro_enclaves_nsm\b)"), STRONG),
    ("KMS attestation condition", re.compile(r"kms:RecipientAttestation"), STRONG),
    ("nitro enclaves SDK", re.compile(r"(?i)aws[-_]nitro[-_]enclaves"), STRONG),
    ("EIF reference", re.compile(r"(?i)\b(\.eif\b|enclave[_-]?image[_-]?file)"), WEAK),
    # vsock is the Nitro transport but is not exclusive to it.
    ("vsock/AF_VSOCK", re.compile(r"(?i)\b(AF_VSOCK|VsockStream|VsockListener|vsock_?proxy)"), WEAK),
]

DSTACK_SIGNALS: list[tuple[str, re.Pattern, int]] = [
    ("dstack tooling", re.compile(r"(?i)\bdstack[-_](kms|gateway|vmm|os|util|types)\b"), STRONG),
    ("tappd socket", re.compile(r"(?i)\btappd\b"), STRONG),
    ("governance contracts", re.compile(r"\b(KmsAuth|AppAuth)\b"), STRONG),
    ("RTMR", re.compile(r"\bRTMR\d?\b"), STRONG),
    ("dstack reference", re.compile(r"(?i)\bdstack\b"), WEAK),
    ("app-compose manifest", re.compile(r"(?i)app[-_]compose\.(json|ya?ml)"), WEAK),
    ("Phala cloud", re.compile(r"(?i)\bphala\b"), WEAK),
]

# Google Cloud Confidential Space is the substrate EigenCompute runs on, and it is not
# EigenCloud-specific: anyone deploying a TDX workload there fetches the same attestation
# token from the same metadata endpoint. Keeping this tier separate means the token-handling
# rules (CS01-CS03) apply to any Confidential Space deployment, while the EigenCloud-specific
# rules stay gated behind the tier below.
CONFIDENTIAL_SPACE_SIGNALS: list[tuple[str, re.Pattern, int]] = [
    ("Confidential Space attestation token", re.compile(
        r"computeMetadata/v1/instance/attestation/token"), STRONG),
    ("GCP metadata attestation call", re.compile(
        r"(?i)Metadata-Flavor\s*:\s*Google"), STRONG),
    # The EAT claim names Confidential Space puts in the token. Distinctive as a set;
    # `submods` and `eat_nonce` in particular appear nowhere else.
    # `eat_nonce` and `submods` are EAT claims Google Confidential Space emits; nothing
    # else produces them. `tcb_status` deliberately is NOT here; it is generic Intel DCAP
    # vocabulary that dstack's KMS also uses, and including it flipped a pure-TDX project
    # into Confidential Space on one match.
    ("Confidential Space EAT claims", re.compile(r"\b(eat_nonce|submods)\b"), STRONG),
    ("TDX TCB status", re.compile(r"\b(tcbstatus|tcb_status)\b"), WEAK),
    ("Confidential Space image reference", re.compile(
        r"(?i)\bconfidential[-_]space\b"), STRONG),
    ("TDX guest device", re.compile(
        r"(?i)(/dev/tdx[-_]guest|/sys/kernel/config/tsm/report)"), WEAK),
    ("TDX hardware model claim", re.compile(r"\b(INTEL_TDX|hwmodel|secboot)\b"), WEAK),
]

# EigenCompute (EigenCloud), `ecloud` is the current CLI; `eigenx` is the deprecated one
# and is kept as a weak signal so older repos still resolve.
EIGENCOMPUTE_SIGNALS: list[tuple[str, re.Pattern, int]] = [
    ("ecloud CLI deploy", re.compile(
        r"\becloud\s+compute\s+app\s+(deploy|upgrade|list|logs)\b"), STRONG),
    ("ecloud SDK", re.compile(r"@layr-labs/ecloud-sdk"), STRONG),
    ("ecloud.toml manifest", re.compile(r"(?i)(^|/)ecloud\.toml\b"), STRONG),
    # The platform ships these into every image; their presence means the KMS secret-delivery
    # path is wired up, which is unique to EigenCompute.
    ("EigenCompute KMS client", re.compile(
        r"(?i)(kms-signing-public-key\.pem|\bkms-client\b|compute-source-env\.sh)"), STRONG),
    ("EigenCompute instance id", re.compile(
        r"\b(EIGENCOMPUTE_INSTANCE_ID|EIGENCLOUD_INSTANCE_ID)\b"), STRONG),
    ("ecloud deploy environment", re.compile(
        r"\bECLOUD_(PRIVATE_KEY|RPC_URL|ENVIRONMENT|INSTANCE_TYPE|LOG_VISIBILITY)\b"), WEAK),
    ("EigenCompute by name", re.compile(r"(?i)\beigencompute\b"), STRONG),
    ("EigenCloud reference", re.compile(
        r"(?i)\b(eigencloud\.xyz|eigenlabs\.org|eigencloud)\b"), WEAK),
    ("EigenCompute instance shape", re.compile(
        r"\b(g1-standard-\d+t|tdx-\d*x?large)\b"), WEAK),
    ("eigenx CLI (deprecated)", re.compile(r"\beigenx\s+app\s+\w+"), WEAK),
]

SCAN_SUFFIXES = {
    ".rs", ".go", ".py", ".ts", ".js", ".mjs", ".json", ".yaml", ".yml",
    ".toml", ".sh", ".bash", ".tf", ".md", ".txt", "",
}
SCAN_NAMES = {"Dockerfile", "Makefile", "docker-compose.yml", "docker-compose.yaml"}


@dataclass
class Platform:
    nitro: bool = False
    dstack: bool = False
    confidential_space: bool = False
    eigencompute: bool = False
    evidence: dict[str, list[str]] = field(default_factory=dict)
    """signal name -> up to a few 'file:line' locations that produced it."""

    scores: dict[str, int] = field(default_factory=dict)
    """Accumulated weight per platform, so a reader can see how close a call it was."""

    truncated: bool = False
    """True when the file cap was hit before the tree was fully walked.

    This has to be reported. Detection drives rule gating, so a signal missed past the
    cap disables most of the rule set -- and the report then shows a clean result with a
    high layer score, which is the most dangerous output this tool can produce. A
    monorepo or a tree with a large generated directory reaches the cap easily.
    """

    @property
    def any(self) -> bool:
        return self.nitro or self.dstack or self.confidential_space or self.eigencompute

    def names(self) -> list[str]:
        out = []
        if self.nitro:
            out.append("nitro")
        if self.dstack:
            out.append("dstack")
        # eigencompute implies confidential-space, so naming both would be noise. The base
        # tier is only worth reporting on its own when no known deployment layer sits on it.
        if self.eigencompute:
            out.append("eigencompute")
        elif self.confidential_space:
            out.append("confidential-space")
        return out or ["none"]

    def summary(self) -> str:
        if not self.any:
            return "no TEE platform detected"
        return ", ".join(self.names())


def detect(root: Path, max_files: int = 4000) -> Platform:
    result = Platform()
    nitro_hits: dict[str, int] = {}
    nitro_files: dict[str, set[str]] = {}
    dstack_hits: dict[str, int] = {}
    dstack_files: dict[str, set[str]] = {}
    cs_hits: dict[str, int] = {}
    cs_files: dict[str, set[str]] = {}
    ec_hits: dict[str, int] = {}
    ec_files: dict[str, set[str]] = {}
    seen = 0

    for path in root.rglob("*"):
        if seen >= max_files:
            result.truncated = True
            break
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix not in SCAN_SUFFIXES and path.name not in SCAN_NAMES:
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        seen += 1

        rel = str(path.relative_to(root))
        for label, pattern, weight in NITRO_SIGNALS:
            m = pattern.search(text)
            if m:
                nitro_hits[label] = weight
                nitro_files.setdefault(label, set()).add(rel)
                _record(result, label, text, m, rel)
        for label, pattern, weight in DSTACK_SIGNALS:
            m = pattern.search(text)
            if m:
                dstack_hits[label] = weight
                dstack_files.setdefault(label, set()).add(rel)
                _record(result, label, text, m, rel)
        for label, pattern, weight in CONFIDENTIAL_SPACE_SIGNALS:
            m = pattern.search(text)
            if m:
                cs_hits[label] = weight
                cs_files.setdefault(label, set()).add(rel)
                _record(result, label, text, m, rel)
        for label, pattern, weight in EIGENCOMPUTE_SIGNALS:
            m = pattern.search(text)
            if m:
                ec_hits[label] = weight
                ec_files.setdefault(label, set()).add(rel)
                _record(result, label, text, m, rel)
        # ecloud.toml is a manifest, not a mention: the filename alone is the evidence, and
        # a repo can carry one without the string "ecloud.toml" appearing in any file.
        if path.name == "ecloud.toml":
            ec_hits["ecloud.toml manifest"] = STRONG
            ec_files.setdefault("ecloud.toml manifest", set()).add(rel)
            result.evidence.setdefault("ecloud.toml manifest", [])
            if rel not in result.evidence["ecloud.toml manifest"]:
                result.evidence["ecloud.toml manifest"].append(rel)

    # Each distinct signal counts once no matter how many files carry it: a filename
    # repeated across twenty files is still one piece of evidence, not twenty.
    def _score(hits: dict[str, int], files: dict[str, set[str]]) -> int:
        """Sum the signal weights, but refuse to reach the threshold on weak signals that
        all came from a single file.

        A TEE app commonly probes several platforms' endpoints and falls back between them.
        bobIsAlive is deployed on EigenCompute and carries an `ecloud.toml`, yet one
        fallback block in `agents/tee.ts` mentions both a dstack endpoint and Phala, two
        distinct weak signals, one file, and dstack was reported as a detected platform.
        Two hints in the same file are one piece of evidence about that file, not two
        independent corroborations, which is the same reasoning that already stops a single
        signal from counting once per file it appears in.
        """
        if any(w >= STRONG for w in hits.values()):
            return sum(hits.values())
        distinct = set().union(*files.values()) if files else set()
        return sum(hits.values()) if len(distinct) > 1 else min(sum(hits.values()), DETECT_THRESHOLD - 1)

    nitro_score = _score(nitro_hits, nitro_files)
    dstack_score = _score(dstack_hits, dstack_files)
    cs_score = _score(cs_hits, cs_files)
    ec_score = _score(ec_hits, ec_files)
    result.scores = {
        "nitro": nitro_score,
        "dstack": dstack_score,
        "confidential-space": cs_score,
        "eigencompute": ec_score,
    }
    result.nitro = nitro_score >= DETECT_THRESHOLD
    result.dstack = dstack_score >= DETECT_THRESHOLD
    result.confidential_space = cs_score >= DETECT_THRESHOLD
    result.eigencompute = ec_score >= DETECT_THRESHOLD

    # EigenCompute runs on Confidential Space, so detecting the deployment layer implies the
    # substrate even when the app never touches the metadata endpoint itself. Most apps do
    # not: they let the platform hold the attestation and never fetch a token, which is
    # exactly the case CS01-CS03 need to be live for.
    if result.eigencompute:
        result.confidential_space = True

    return result


def _record(result: Platform, label: str, text: str, match: re.Match, rel: str) -> None:
    locations = result.evidence.setdefault(label, [])
    if len(locations) >= 3:
        return
    line = text.count("\n", 0, match.start()) + 1
    locations.append(f"{rel}:{line}")
