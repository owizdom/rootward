"""Prompts for the semantic passes.

These four rules are the ones no pattern matcher can decide. Each prompt does three things:
establishes the TEE threat model the judgment depends on, states exactly what would count as
evidence, and forbids the failure mode that makes an LLM auditor worse than no auditor —
plausible findings with no citation.

The shared preamble is deliberately blunt about the cost asymmetry. A missed finding is a
gap; a fabricated finding wastes a security engineer's afternoon and teaches them to
distrust the whole report. When the evidence is not in the files provided, the correct
output is an empty list.
"""

from __future__ import annotations

# The threat model is platform-specific and getting it wrong is worse than omitting it: a
# semantic pass told that "the enclave has no network stack" will reason confidently and
# wrongly about a Confidential Space workload, which has an ordinary one. The vsock framing
# below is accurate for Nitro and false for EigenCompute, so the two are kept apart.

_EVIDENCE_RULES = """\
Scope rule, absolute:
- Read ONLY files inside the repository you were pointed at. Never read a parent directory, a sibling directory, or anything outside it. You are auditing a third party's code, and reading outside the target is out of bounds no matter how useful it looks.

Evidence rules, which override any instinct to be helpful:
- Every finding MUST cite a real file path and a real 1-indexed line number you actually \
read, and quote the line.
- If you cannot point at a specific line, the finding does not exist. Return an empty list.
- Do not infer a defect from a file's name, a function's name, or the absence of code you \
did not go looking for.
- A missed finding is a gap. A fabricated finding wastes a security engineer's time and \
discredits every other finding in the report. Prefer the gap.
"""

_NITRO_MODEL = """\
You are auditing a Web3 protocol that runs inside a cloud Trusted Execution Environment \
(AWS Nitro Enclaves or dstack). Work from this threat model:

- The parent EC2 instance, its operating system, and the hypervisor are ADVERSARIAL. The \
enclave operator is the attacker.
- The enclave has no network stack. Every byte in or out crosses a vsock channel the parent \
controls, and every external response is relayed by a parent-side proxy.
- The parent can: read anything logged, observe the size and timing of every message, \
replay any message, delay or reorder messages, supply the clock, and supply entropy if the \
enclave accepts it.
- The parent CANNOT read enclave memory. Do not report findings that require that.
- Hardware attacks (speculative execution, Rowhammer, voltage/EM fault injection, memory-bus \
interposition) are OUT OF SCOPE. Never report them.
"""

_CONFIDENTIAL_SPACE_MODEL = """\
You are auditing a Web3 protocol that runs inside a Google Cloud Confidential Space \
workload on Intel TDX, deployed via EigenCompute. Work from this threat model:

- The cloud operator and anyone who can reach the deployment API are ADVERSARIAL.
- The workload is an ordinary container with a NORMAL network stack. There is no vsock and \
no parent-side proxy: it makes outbound connections directly, bounded only by an egress \
allowlist in `ecloud.toml` if one is declared. Do not reason about vsock on this platform.
- Secrets are NOT baked into the image. At container start the platform runs `kms-client`, \
which fetches the app's environment from KMS, verifies the response against a signing key \
pinned into the image, writes /tmp/.env, sources it, deletes it, and drops privileges. KMS \
releases that environment only to an attested Docker image digest, recorded on chain. The \
wallet the app spends from derives from the MNEMONIC delivered this way.
- Workload identity is the Docker image digest, carried in the attestation token's `submods` \
claim. There is no EIF and there are no PCRs.
- Attestation is a JWT from Google's attestation verifier. Decoding it proves nothing; only \
checking its signature against Google's JWKS does.
- The operator CAN read anything the app logs when `log_visibility` is `public`, and can \
observe message sizes and timing.
- The operator CANNOT read enclave memory, and CANNOT obtain MNEMONIC for an image digest \
they cannot reproduce. Do not report findings that require either.
- Hardware attacks (speculative execution, Rowhammer, voltage/EM fault injection, memory-bus \
interposition) are OUT OF SCOPE. Never report them.
"""


def threat_model(platform=None) -> str:
    """The threat model for the platform actually detected.

    `platform` is a detectors.platform_detect.Platform, or None for the Nitro default.
    """
    if platform is not None and getattr(platform, "confidential_space", False):
        return _CONFIDENTIAL_SPACE_MODEL + "\n" + _EVIDENCE_RULES
    return _NITRO_MODEL + "\n" + _EVIDENCE_RULES


# Backwards-compatible default for callers that have no platform to hand.
THREAT_MODEL = threat_model()

FINDING_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "file": {"type": "string", "description": "Path relative to the audit root"},
                    "line": {"type": "integer", "description": "1-indexed line you read"},
                    "evidence": {"type": "string", "description": "The exact source line, quoted"},
                    "reasoning": {
                        "type": "string",
                        "description": "How the parent exploits this, concretely. Name the step.",
                    },
                    "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                },
                "required": ["file", "line", "evidence", "reasoning", "confidence"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["findings"],
    "additionalProperties": False,
}

TRUST_BOUNDARY = """\
Rule BT-T00 — the parent instance is treated as trusted rather than adversarial.

Find places where data arriving from the parent (over vsock, from a relayed HTTP response, \
from a KMS proxy response, or as a process argument or environment variable) is used to make \
a security decision WITHOUT being validated or authenticated.

Report only when you can point at both halves: where the data enters, and where it is used \
unchecked. Examples that qualify: an amount or address parsed from a vsock message and acted \
on; a price used for a liquidation decision with no signature check; an identity claim taken \
at face value.

Does NOT qualify: unvalidated input on a health check, a metrics endpoint, a log level, or \
anything that cannot change a security outcome. Validation performed in a helper the caller \
invokes still counts as validation — follow the call before reporting.
"""

TCB_BLOAT = """\
Rule BT-T05 — the trusted computing base carries logic that does not need confidentiality.

Assess what runs INSIDE the enclave boundary. Only operations that must see plaintext, or \
that hold key material, need to be there. Everything else can run outside with its results \
verified cryptographically.

Report subsystems inside the boundary that do not need to be, citing the file and line where \
each is set up: HTTP routing frameworks, template engines, ORMs and database drivers, \
metrics/telemetry agents, admin interfaces, general business logic.

This is a judgment call reported as evidence, not a defect. Use confidence "low" unless the \
component is both clearly inside the enclave and clearly unnecessary there. If the enclave is \
already minimal, return an empty list — that is the expected result for a well-built one.
"""

METADATA_LEAKAGE = """\
Rule BT-T08 — observable request metadata correlates with confidential payload contents.

Encryption hides payload contents, not payload shape. Look for places where an observer on \
the parent could infer something about a secret from what they CAN see: the byte length of a \
response, how long a handler took, how many messages were exchanged, or the order of \
operations.

Concretely, report: responses whose serialized length varies with a secret value (a \
variable-length JSON body over vsock with no padding is the classic case); branches on secret \
data where the paths have visibly different cost; loops whose iteration count depends on a \
secret.

Be honest about the limit of static analysis here. You can see the encoder; you cannot see the \
distribution. Report what is structurally visible, mark it confidence "low" unless the \
correlation is direct and obvious, and do not speculate about exploitability you cannot \
demonstrate from the code.
"""

LAYER_CLASSIFIER = """\
Rule BT-LYR01 — classify this codebase against the handbook's security layers, and compare \
that to what the project claims.

The ladder is cumulative — each layer requires everything below it:

  Layer 0  no TEE at all
  Layer 1  TEE only, no verified attestation (the handbook says: never use in production)
  Layer 2  + attestation correctly verified, measurements pinned to an allowlist
  Layer 3  + constant-time cryptography and no metadata leakage
  Layer 4  + MPC or threshold keys, so one compromised TEE is not total loss
  Layer 5  + zero-knowledge proofs giving independent verification of computation
  Layer 6  + economic incentives for detecting compromise (bounties, slashing)

Read the README and any documentation, and record what security level the project CLAIMS, \
quoting the sentence and its location. Then determine what the code actually implements, \
citing evidence for each layer you credit.

Report the gap as findings only where the claim exceeds the implementation, citing the claim's \
location as the file/line. A hybrid architecture, where different operations sit at different \
layers, is legitimate — say so rather than scoring it down, as long as the boundaries are \
explicit.
"""

KEY_LIFECYCLE = """\
Rule BT-CFG05 — no key rotation path, so a single compromise is permanent.

Determine whether this system can rotate the keys it holds, quarantine a compromised \
enclave, or re-provision after a breach — as a routine operation rather than as incident \
improvisation.

Look for and cite: a rotation function or endpoint; a key version or epoch carried in \
storage or on chain; a revocation or quarantine path; governance able to replace an \
authorised measurement. Any one of these, cited with file:line, means the capability exists \
and you should return an empty list.

Report a finding only when key material is clearly long-lived and nothing you can find \
replaces it. Cite where the key is created or loaded, since that is the evidence a reader \
needs.

Be careful with absence here, because absence of evidence is weak evidence. Rotation is \
frequently operational, lives in a deployment repository, or is a runbook rather than code. \
Use confidence "low" and phrase the finding as an open question unless the repository \
clearly owns its own key lifecycle. The 2025 memory-bus attacks (WireTap, Battering RAM, \
TEE.fail) are why this matters — a design whose keys never change assumes the hardware \
guarantee holds forever, and that assumption now has published counterexamples — but do \
NOT report those attacks themselves. They are out of scope.
"""

PASSES = {
    "BT-CFG05-no-key-rotation": KEY_LIFECYCLE,
    "BT-T00-parent-instance-trusted": TRUST_BOUNDARY,
    "BT-T05-tcb-bloat": TCB_BLOAT,
    "BT-T08-metadata-leakage": METADATA_LEAKAGE,
    "BT-LYR01-layer-scorecard": LAYER_CLASSIFIER,
}

REFUTE = """\
You are the adversarial check on a security finding another agent produced. Your job is to \
REFUTE it. A finding that survives you is worth reporting; one that does not must be dropped.

You have the codebase. Read the cited file and the code around it before deciding anything.
Read ONLY files inside the repository under audit — never a parent or sibling directory.

The finding is refuted if ANY of these hold:
- The cited line does not exist, or does not say what the finding claims it says.
- The data in question does not actually cross the enclave trust boundary.
- Validation, authentication, or a constant-time primitive is applied elsewhere on the path — \
check the callers and callees before concluding it is absent.
- The code is unreachable, is test-only, or is behind a disabled feature flag.
- The claimed attack requires a capability the threat model does not grant the parent, such \
as reading enclave memory.
- The reasoning describes a hardware attack, which is out of scope.

Do NOT refute on any of these grounds. Each is a plausible-sounding argument that has \
deleted a real finding:

- "The data is encrypted, so the host cannot tamper with it." Encryption is not \
authentication of origin. Where the encryption key is public — an ECIES-style scheme whose \
recipient public key the host can fetch — the host encrypts its own payload and every AEAD \
tag validates correctly. This exact reasoning wrongly refuted a finding that an independent \
audit had separately confirmed.
- "An AEAD tag, checksum, or hash is verified." Ask which key that check is under and who \
holds it. Integrity against corruption is not authenticity against an attacker who can \
choose the input.
- "The value is measured or hashed somewhere." Ask whether anything ever *compares* that \
measurement against an expected value and fails closed on mismatch. Recording a measurement \
is not enforcing one.
- "Something later would catch it." Trace that later check and cite its file:line, or do not \
claim it exists.

Default to refuted when you are uncertain about a FACT you can check: whether the cited line \
says what is claimed, whether the path is reachable, whether a validating call exists \
elsewhere. Do not refute on a cryptographic argument you have not traced to a specific key \
held by a specific party.

Confirming a finding asserts a security engineer should spend time on it. Refuting one \
asserts they should not, and that mistake is made silently — the finding simply disappears \
from the report. Weigh them accordingly.

Return: refuted (bool), reason (one or two sentences), and the file:line you checked to \
decide. The reason must reference what you actually read, not restate the finding.
"""

REFUTE_SCHEMA = {
    "type": "object",
    "properties": {
        "refuted": {"type": "boolean"},
        "reason": {"type": "string"},
        "checked": {"type": "string", "description": "file:line you read to decide"},
    },
    "required": ["refuted", "reason", "checked"],
    "additionalProperties": False,
}
