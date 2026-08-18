# The EigenCompute security model

Read out of [`Layr-Labs/eigenx-cli`](https://github.com/Layr-Labs/eigenx-cli) and six
deployed applications, because the rules in this catalog have to key on what the platform
actually does rather than on what a docs page says it does.

Everything below is either a quoted file from that repository or a pattern observed across
those deployments. Where something is inferred rather than read, it says so.

## What it is

EigenCompute runs a Docker image inside a **Google Cloud Confidential Space** VM on **Intel
TDX**. That matters more than it sounds: it is not AWS Nitro, so almost none of this
tool's Nitro machinery transfers.

| | Nitro Enclaves | EigenCompute |
|---|---|---|
| Artifact | EIF, built by `nitro-cli` | Docker image |
| Identity | PCR0/1/2, measured from the EIF | image digest, recorded on chain |
| Secret delivery | KMS releases to an attested PCR set | KMS releases to an attested digest |
| Network | none; every byte crosses vsock | ordinary network stack |
| Host boundary | parent EC2 instance | cloud operator + deployment API |

The consequence for this tool is that the Rust core — EIF parsing, cpio ramdisk walking, PCR
recomputation — has **no analogue here and does not run**. An EigenCompute audit is source
and configuration only, and the report says so in its NOT VERIFIED section rather than
leaving the reader to notice the absence.

## The CLI

`ecloud` is current; `eigenx` is deprecated but still appears in older repositories.

```
ecloud compute app deploy|upgrade|list|logs
  --image-ref --env-file --instance-type --log-visibility
  --resource-usage-monitoring --verifiable --repo --commit
  --private-key --rpc-url --app-id
```

`--log-visibility` takes `public|private|off`. Public logs on an application holding a
wallet is a first-class finding (`BT-T03C`), and it is the default in several of the
deployments audited here.

`--private-key` on the command line is `BT-EC05`: argv is readable from `ps`, lands in shell
history, and is echoed into CI logs. The CLI reads `ECLOUD_PRIVATE_KEY` from the environment
instead.

## The manifest

`ecloud.toml`, in two schemas that both occur in the wild. `parse_ecloud_toml` in
`detectors/eigencompute.py` normalises them, because reading only one silently skips every
app using the other.

```toml
# flat                          # nested
name = "app"                    [app]
instance_type = "g1-standard-4t"  name = "app"
log_visibility = "public"       [runtime]
dockerfile = "Dockerfile"         shape = "g1-standard-4t"
[wallet]                        [attestation]
source = "TEE_GENERATED"          mode = "kms-jwt"
                                [egress]
                                  allow = ["host.example", ...]
```

**A manifest is not a deployment.** Every field here can be overridden by a flag on
`ecloud compute app deploy`, so `log_visibility = "off"` in the repository is not evidence
that the running app has logs off. That cuts both ways and both rules' `false_positives`
fields say so.

## How secrets actually arrive

This is the part worth reading carefully, because it is what makes several findings severe
that would otherwise be routine.

**Secrets are never baked into the image.** From
`internal/templates/docker/Dockerfile.layered.tmpl` and
`internal/templates/scripts/compute-source-env.sh.tmpl`:

```sh
if /usr/local/bin/kms-client \
  --kms-server-url "{{.KMSServerURL}}" \
  --kms-signing-key-file /usr/local/bin/kms-signing-public-key.pem \
  --userapi-url "{{.UserAPIURL}}" \
  --output /tmp/.env; then
    set -a && . /tmp/.env && set +a
    rm -f /tmp/.env
else
    echo "ERROR - Failed to fetch environment variables from KMS"
    exit 1
fi
...
if [ -n "$__EIGENX_ORIGINAL_USER" ] && [ "$(id -u)" = "0" ]; then
    exec su -s /bin/sh "$__EIGENX_ORIGINAL_USER" -c 'exec "$@"' -- sh "$@"
fi
```

So at container start the platform:

1. runs `kms-client`, which fetches the app's environment from KMS,
2. **verifies the KMS response against a signing public key pinned into the image** at
   `/usr/local/bin/kms-signing-public-key.pem`,
3. writes `/tmp/.env`, sources it, and deletes it,
4. **drops privileges** to the image's original user.

KMS releases that environment only to an attested image digest. The wallet the application
spends from derives from the `MNEMONIC` delivered this way.

Three rules follow directly:

- A committed `MNEMONIC` (`BT-T09B`) does not merely leak a secret. It defeats the entire
  design, and that mnemonic controls a wallet.
- A dev-key fallback (`BT-EC03`) is reached exactly when KMS did **not** release the
  environment — which is to say, exactly when attestation did not happen. The branch handling
  that case handles it by running on a key in the source tree.
- `USER root` (`BT-EC07`) discards step 4. This is why it is a rule here and not general
  container lint: the mitigation being overridden is one the platform went out of its way to
  provide.

## Attestation

A JWT from Google's attestation verifier, fetched from the metadata server:

```
http://metadata.google.internal/computeMetadata/v1/instance/attestation/token
  ?audience=...&nonce=...&format=full
Metadata-Flavor: Google
```

Claims that carry the guarantee: `hwmodel` (expect `INTEL_TDX`), `swname` (expect
`CONFIDENTIAL_SPACE`), `secboot`, `tcbstatus`, `eat_nonce`, `aud`, `iss`, `exp`, and
`submods` — which carries the container image digest.

**Decoding the token proves nothing.** The payload is base64, not ciphertext. Three of the
six audited deployments read claims out of a decoded token with no signature check, one of
them with a docstring saying so outright. That is `BT-CS01`, and it is the single most
common failure on this platform.

Verifying the signature is also not enough. A correctly signed token from a debug VM with
secure boot off asserts, in plain text, that it is a debug VM with secure boot off — so the
claims have to be compared, which is `BT-CS02`. And the image digest has to be compared
against a pinned value, which is `BT-T01`: pinning `submods.container.image_digest` is the
same act as pinning PCR1/PCR2 in a KMS key policy, so it reuses the handbook's rule rather
than minting a new one.

Verification is normally **delegated** to `@layr-labs/ecloud-sdk/attest` (`AttestClient`,
`JwtProvider`). That is the correct path, so the SDK is on a known-validator allowlist — the
same accommodation `detectors/attestation.py` already makes for Nitro validators that
delegate to an audited crate.

## What this audit still cannot see

Stated positively in every EigenCompute report, because a reader who knows the Nitro output
will otherwise wonder where the EIF and PCR rules went, and silence reads as a pass:

- No EIF, no PCRs, no image measurement — structurally inapplicable, not skipped.
- The image digest recorded on chain was not fetched. Whether the digest KMS releases
  `MNEMONIC` to matches the image this repository builds is checkable at
  `verify.eigencloud.xyz`, and it is a deployment fact rather than a repository one.
- `kms-signing-public-key.pem` ships in the platform base image, not in the app repository,
  so this tool cannot confirm the running `kms-client` pins the right KMS.
- The wallet derived from `MNEMONIC` was not inspected on chain. Whether it holds funds is
  what decides the severity of every key-handling finding.
- Whether the app was deployed `--verifiable` is a deploy-time flag, absent from the source.
