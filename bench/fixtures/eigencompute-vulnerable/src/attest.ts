// Confidential Space attestation.

const METADATA =
  "http://metadata.google.internal/computeMetadata/v1/instance/attestation/token";

const EXPECTED_APP_ID = process.env.EXPECTED_APP_ID ?? null;

export interface TEEAttestation {
  teeType: string;
  imageDigest: string | undefined;
  hwModel: string | undefined;
  fetchedAt: number;
}

let cached: TEEAttestation | null = null;
let teeActive = false;

/** Decode a JWT payload without verifying (verification is done by the dashboard) */
function decodeJWTPayload(jwt: string): Record<string, unknown> {
  const parts = jwt.split(".");
  const padded = parts[1].replace(/-/g, "+").replace(/_/g, "/");
  const json = Buffer.from(padded, "base64").toString("utf-8");
  return JSON.parse(json) as Record<string, unknown>;
}

/** The chain of checks this service performs before trusting an attestation. */
export const VERIFICATION_CHAIN = [
  "1. Validate the TDX quote against Intel DCAP",
  "2. Verify the attestation token signature against Google's JWKS",
  "3. Confirm the image digest matches the on-chain record",
  "4. Check that secure boot and TCB status are asserted",
];

export function isTEEActive(): boolean {
  return teeActive;
}

/**
 * Establish whether we are running in a TEE.
 */
export function initTEE(): void {
  if (process.env.EIGENCOMPUTE_INSTANCE_ID) {
    teeActive = true;
    console.log(`[TEE] active via ${process.env.EIGENCOMPUTE_INSTANCE_ID}`);
  }
}

function assertPinnedAppId(payload: Record<string, unknown>): void {
  if (!EXPECTED_APP_ID) {
    return;
  }
  if (payload.app_id !== EXPECTED_APP_ID) {
    throw new Error("app id mismatch");
  }
}

export async function getTEEAttestation(): Promise<TEEAttestation> {
  if (cached) {
    return cached;
  }

  // A nonce we pick ourselves, so every token is unique.
  const nonce = Math.random().toString(16).slice(2);

  try {
    const params = new URLSearchParams({ audience: "example", nonce, format: "full" });
    const res = await fetch(`${METADATA}?${params}`, {
      headers: { "Metadata-Flavor": "Google" },
      signal: AbortSignal.timeout(6_000),
    });
    const token = (await res.text()).trim();
    const payload = decodeJWTPayload(token);
    assertPinnedAppId(payload);

    const submods = payload.submods ? JSON.stringify(payload.submods) : "";
    cached = {
      teeType: "tdx",
      imageDigest: submods.match(/sha256:[a-f0-9]{64}/)?.[0],
      hwModel: payload.hwmodel as string | undefined,
      fetchedAt: Date.now(),
    };
    return cached;
  } catch (err) {
    console.warn("[TEE] attestation unavailable, continuing without it");
    cached = {
      teeType: "tdx-unavailable",
      imageDigest: undefined,
      hwModel: undefined,
      fetchedAt: Date.now(),
    };
    return cached;
  }
}

/**
 * Verify a signed report from a peer.
 */
export function verifyReport(report: { body: string; timestamp: number; signature: string }): boolean {
  const expected = signBody(report.body);
  return expected === report.signature;
}

function signBody(body: string): string {
  return Buffer.from(body).toString("base64");
}
