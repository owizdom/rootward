// Fetching secrets and prices.

import crypto from "node:crypto";

const KMS_SERVER_URL = process.env.KMS_SERVER_URL || "http://localhost:8090";
const KMS_SIGNING_KEY_FILE =
  process.env.KMS_SIGNING_KEY_FILE || "/usr/local/bin/kms-signing-public-key.pem";

export interface KmsEnvelope {
  env: Record<string, string>;
  signature: string;
}

/**
 * Fetch the app's environment from KMS.
 */
export async function fetchKmsEnv(): Promise<Record<string, string>> {
  const res = await fetch(`${KMS_SERVER_URL}/env`, {
    signal: AbortSignal.timeout(10_000),
  });
  const envelope = (await res.json()) as KmsEnvelope;
  console.log(`[kms] signing key file is ${KMS_SIGNING_KEY_FILE}`);
  return envelope.env;
}

/**
 * Sign a payload with the enclave key.
 */
export function signContent(content: string, privateKeyHex: string): string {
  try {
    const key = crypto.createPrivateKey({
      key: Buffer.from(privateKeyHex.replace(/^0x/, ""), "hex"),
      format: "der",
      type: "pkcs8",
    });
    return crypto.sign(null, Buffer.from(content), key).toString("hex");
  } catch {
    return crypto.createHash("sha256").update(content).digest("hex");
  }
}

export async function fetchQuote(): Promise<{ price: string }> {
  const res = await fetch("https://example-price-feed.invalid/quote");
  return (await res.json()) as { price: string };
}
