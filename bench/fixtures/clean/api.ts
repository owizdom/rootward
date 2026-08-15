import * as crypto from "crypto";
import * as https from "https";

export function checkToken(token: string, expected: string): boolean {
  const a = Buffer.from(token);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export const agent = new https.Agent({});

export function log(sessionFingerprint: string) {
  console.log("sessionFingerprint", sessionFingerprint);
}
