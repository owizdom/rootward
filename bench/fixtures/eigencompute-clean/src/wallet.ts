// Wallet key handling.
//
// On EigenCompute the mnemonic arrives in the environment from KMS, which released it only
// to an attested image digest. It is the single most sensitive value in the process, so it
// is read exactly once, used to derive, and then erased from the environment.

import { createHmac, hkdfSync, createPrivateKey, KeyObject, timingSafeEqual } from "node:crypto";

let mnemonicConsumed = false;

/**
 * Read MNEMONIC once and remove it from the environment.
 *
 * Reading it more than once means more copies live longer than they need to, and leaving it
 * in process.env means every child process and every accidental env dump carries it.
 */
export function readMnemonicOnce(): Buffer {
  if (mnemonicConsumed) {
    throw new Error("mnemonic already consumed; it is readable exactly once per process");
  }
  const raw = process.env["MNEMONIC"];
  if (raw === undefined || raw.length === 0) {
    // No fallback. A default here would be a key an attacker also knows.
    throw new Error("MNEMONIC was not provisioned by KMS; refusing to start");
  }
  const buf = Buffer.from(raw, "utf8");
  if (buf.length < 32) {
    throw new Error("MNEMONIC is too short to be a real seed");
  }
  mnemonicConsumed = true;
  zeroAndDropMnemonicEnv();
  return buf;
}

function zeroAndDropMnemonicEnv(): void {
  delete process.env["MNEMONIC"];
}

// HKDF (salt, info) pairs must be unique per derived key. Reusing a pair silently derives
// the same key for two different purposes, which turns one compromise into two.
const usedPairs = new Set<string>();

/**
 * Derive a key from the mnemonic.
 *
 * The keying material is the secret seed. Deriving from anything an observer can read --
 * a public key, an instance id, an image digest -- produces a key the observer can also
 * compute, which is not a key at all.
 */
export function deriveKey(ikm: Buffer, salt: string, info: string, length = 32): Buffer {
  const pair = `${salt} ${info}`;
  if (usedPairs.has(pair)) {
    throw new Error(`hkdf salt/info pair reused: ${pair}`);
  }
  usedPairs.add(pair);
  return Buffer.from(
    hkdfSync("sha256", ikm, Buffer.from(salt, "utf8"), Buffer.from(info, "utf8"), length),
  );
}

// The signing key never leaves this module and is never exported as bytes.
let signingKey: KeyObject | null = null;

const PKCS8_ED25519_PREFIX = "302e020100300506032b657004220420";

export function initSigning(ikm: Buffer): void {
  if (signingKey !== null) {
    throw new Error("signing already initialised");
  }
  const seed = deriveKey(ikm, "example-clean/v1/signing", "ed25519-seed", 32);
  signingKey = createPrivateKey({
    key: Buffer.concat([Buffer.from(PKCS8_ED25519_PREFIX, "hex"), seed]),
    format: "der",
    type: "pkcs8",
  });
  seed.fill(0);
}

/** A non-secret fingerprint, safe to log. The mnemonic itself is never logged. */
export function mnemonicFingerprint(ikm: Buffer): string {
  return createHmac("sha256", "example-clean/fingerprint").update(ikm).digest("hex").slice(0, 12);
}

export function constantTimeEquals(a: string, b: string): boolean {
  const left = Buffer.from(a, "utf8");
  const right = Buffer.from(b, "utf8");
  if (left.length !== right.length) {
    return false;
  }
  return timingSafeEqual(left, right);
}

export function bootstrap(): void {
  const ikm = readMnemonicOnce();
  initSigning(ikm);
  console.log(`[wallet] signing key ready, seed fingerprint ${mnemonicFingerprint(ikm)}`);
  ikm.fill(0);
}
