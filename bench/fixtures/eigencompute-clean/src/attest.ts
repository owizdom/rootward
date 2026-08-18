// Confidential Space attestation, verified rather than merely decoded.
//
// The token is a JWT signed by Google's attestation verifier. Decoding it proves nothing:
// the payload is base64, not a signature. Everything below the fetch is the part that
// actually establishes what is running.

import { createRemoteJWKSet, jwtVerify } from "jose";

const JWKS = createRemoteJWKSet(
  new URL("https://confidentialcomputing.googleapis.com/.well-known/jwks.json"),
);

const METADATA =
  "http://metadata.google.internal/computeMetadata/v1/instance/attestation/token";

// The digest this app is allowed to be. Deployment writes it; a mismatch is fatal.
const EXPECTED_IMAGE_DIGEST = process.env.EXPECTED_IMAGE_DIGEST ?? "";
const EXPECTED_APP_ID = process.env.EXPECTED_APP_ID ?? "";
const AUDIENCE = "https://example-clean.invalid";
const MAX_TOKEN_AGE_SECONDS = 300;

export interface Verified {
  imageDigest: string;
  appId: string;
  issuedAt: number;
}

/**
 * Fetch a token bound to a caller-supplied nonce and verify it end to end.
 *
 * The nonce is an argument, not something generated here. A nonce the signer picks makes
 * each token unique but proves nothing about freshness to a remote verifier — only a
 * challenge the verifier chose can do that.
 */
export async function verifyAttestationToken(nonce: string): Promise<Verified> {
  if (!EXPECTED_IMAGE_DIGEST || !EXPECTED_APP_ID) {
    throw new Error("refusing to start: expected image digest and app id are not pinned");
  }

  const params = new URLSearchParams({ audience: AUDIENCE, nonce, format: "full" });
  const res = await fetch(`${METADATA}?${params}`, {
    headers: { "Metadata-Flavor": "Google" },
    signal: AbortSignal.timeout(6_000),
  });
  if (!res.ok) {
    throw new Error(`attestation fetch failed with ${res.status}`);
  }
  const token = (await res.text()).trim();

  // Signature, issuer and audience, checked against Google's published keys.
  const { payload } = await jwtVerify(token, JWKS, {
    issuer: "https://confidentialcomputing.googleapis.com",
    audience: AUDIENCE,
    clockTolerance: 30,
  });

  // Freshness: a signed timestamp with no skew window is a token that replays forever.
  const issuedAt = Number(payload.iat ?? 0);
  const ageSeconds = Math.floor(Date.now() / 1000) - issuedAt;
  if (!issuedAt || ageSeconds > MAX_TOKEN_AGE_SECONDS || ageSeconds < -30) {
    throw new Error(`attestation token outside the freshness window: ${ageSeconds}s`);
  }

  // The nonce we asked for must be the nonce that came back.
  const echoed = payload.eat_nonce;
  const echoedOne = Array.isArray(echoed) ? echoed[0] : echoed;
  if (echoedOne !== nonce) {
    throw new Error("attestation nonce did not match the challenge");
  }

  // Platform integrity claims. Each one is a distinct guarantee and none is implied by
  // the signature being valid.
  if (payload.hwmodel !== "INTEL_TDX") {
    throw new Error(`unexpected hardware model: ${String(payload.hwmodel)}`);
  }
  if (payload.swname !== "CONFIDENTIAL_SPACE") {
    throw new Error(`unexpected software stack: ${String(payload.swname)}`);
  }
  if (payload.secboot !== true) {
    throw new Error("secure boot was not asserted");
  }
  const tcb = String(payload.tcbstatus ?? payload.tcb_status ?? "");
  if (tcb !== "OK" && tcb !== "UpToDate") {
    throw new Error(`TCB is not up to date: ${tcb}`);
  }

  // Workload identity: which image is actually running.
  const submods = (payload.submods ?? {}) as Record<string, any>;
  const imageDigest = String(submods?.container?.image_digest ?? "");
  if (imageDigest !== EXPECTED_IMAGE_DIGEST) {
    throw new Error("image digest does not match the pinned digest; refusing to start");
  }

  const appId = String(payload.app_id ?? "");
  if (appId !== EXPECTED_APP_ID) {
    throw new Error("app id does not match the pinned app id; refusing to start");
  }

  return { imageDigest, appId, issuedAt };
}

/**
 * Startup gate. Attestation failure is fatal here on purpose: continuing to boot with a
 * wallet after failing to prove what is running is the whole failure this guards against.
 */
export async function requireAttestation(nonce: string): Promise<Verified> {
  const verified = await verifyAttestationToken(nonce);
  console.log(`[attest] running image ${verified.imageDigest.slice(0, 19)}...`);
  return verified;
}
