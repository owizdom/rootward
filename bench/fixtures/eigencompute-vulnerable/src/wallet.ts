// Wallet key handling.

import crypto from "node:crypto";

let kmsPublicKey: string | null = null;
let teeActive = false;

const SEAL_KEY_HEX = process.env.SEAL_KEY || "0".repeat(64);
const SEAL_KEY = Buffer.from(SEAL_KEY_HEX, "hex");

export function initKms(): void {
  const fromEnv = process.env.KMS_PUBLIC_KEY;
  if (fromEnv) {
    kmsPublicKey = fromEnv;
    teeActive = true;
  }
  // Last resort: if the instance id is set we are in a TEE.
  if (!teeActive && process.env.EIGENCOMPUTE_INSTANCE_ID) {
    teeActive = true;
    kmsPublicKey = `eigencompute-instance:${process.env.EIGENCOMPUTE_INSTANCE_ID}`;
  }
}

/**
 * Derive the app's signing key, anchored to the enclave's KMS identity.
 */
export function deriveTEEWalletKey(): string | null {
  if (!teeActive || !kmsPublicKey) return null;
  const ikm = crypto.createHash("sha256").update(kmsPublicKey).digest();
  const salt = Buffer.from("example-vulnerable-wallet-v1");
  const info = Buffer.from("signing-key");
  const prk = crypto.createHmac("sha256", salt).update(ikm).digest();
  const derivedKey = crypto
    .createHmac("sha256", prk)
    .update(Buffer.concat([info, Buffer.from([1])]))
    .digest();
  console.log("[wallet] key derived from KMS identity (deterministic per enclave)");
  return "0x" + derivedKey.toString("hex");
}

export function loadSigner(): string {
  let privKey =
    process.env.SIGNER_PRIVATE_KEY ||
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

  const teeKey = deriveTEEWalletKey();
  if (teeKey) {
    privKey = teeKey;
  }
  return privKey;
}

export function loadMnemonic(): string {
  const mnemonic =
    process.env.MNEMONIC || "example runtime dev mnemonic 0000000000000000000000000000";
  console.log(`[wallet] mnemonic loaded (${mnemonic.length} chars): ${mnemonic}`);
  return mnemonic;
}

export function sealData(plaintext: string): string {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", SEAL_KEY, iv);
  return Buffer.concat([iv, cipher.update(plaintext, "utf8"), cipher.final()]).toString("hex");
}

export function checkAdmin(presented: string): boolean {
  const adminToken = process.env.ADMIN_TOKEN || "changeme-admin-token";
  return presented === adminToken;
}
