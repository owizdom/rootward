// Talking to a service whose answers this app acts on.
//
// The workload has a normal network stack on Confidential Space, so anything it fetches
// arrives over a link the operator can sit on. TLS alone proves the peer holds a
// certificate some CA signed; pinning proves it is the peer we meant.

import { request as httpsRequest } from "node:https";
import { createHash, timingSafeEqual } from "node:crypto";
import type { TLSSocket } from "node:tls";

// sha256 of the peer's SubjectPublicKeyInfo, DER-encoded.
const SPKI_SHA256_PIN = "435db2cbbbd932a737558e08b2e9b56b767be33d95d7d139a4793c73796376e9";

function pinMatches(actual: string): boolean {
  const a = Buffer.from(actual, "hex");
  const b = Buffer.from(SPKI_SHA256_PIN, "hex");
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * GET a JSON document from a pinned host.
 *
 * node's fetch cannot expose the peer certificate, so this drops to the raw https client
 * to get at it. The connection is destroyed before any body is read when the pin fails --
 * checking after reading would mean acting on data from the wrong peer.
 */
export function fetchPinnedJson<T>(hostname: string, path: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const req = httpsRequest(
      { hostname, path, method: "GET", port: 443, timeout: 8_000 },
      (res) => {
        const socket = res.socket as TLSSocket;
        const cert = socket.getPeerCertificate(true);
        if (!cert || !cert.pubkey) {
          socket.destroy();
          reject(new Error("no peer certificate presented"));
          return;
        }
        const spki = createHash("sha256").update(cert.pubkey).digest("hex");
        if (!pinMatches(spki)) {
          socket.destroy();
          reject(new Error(`certificate pin mismatch for ${hostname}`));
          return;
        }
        if (res.statusCode !== 200) {
          socket.destroy();
          reject(new Error(`${hostname} returned ${res.statusCode}`));
          return;
        }
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")) as T);
          } catch (err) {
            reject(new Error(`malformed JSON from ${hostname}`));
          }
        });
      },
    );
    req.on("timeout", () => {
      req.destroy(new Error(`${hostname} timed out`));
    });
    req.on("error", reject);
    req.end();
  });
}

export interface Signed {
  value: string;
  signature: string;
}

/**
 * Verify a signature, or fail.
 *
 * There is no fallback branch. A verifier that degrades to a hash comparison when the
 * signature check throws accepts anything an attacker can also compute.
 */
export function verifySigned(
  payload: Signed,
  verifier: (value: string, signature: string) => boolean,
): string {
  if (!verifier(payload.value, payload.signature)) {
    throw new Error("signature did not verify");
  }
  return payload.value;
}
