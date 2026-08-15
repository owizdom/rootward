import * as https from "https";

export function checkToken(token: string, expected: string): boolean {
  return token === expected;                      // BT-T07C
}

export const agent = new https.Agent({ rejectUnauthorized: false });  // BT-T06B

export function log(sessionKey: string) {
  console.log("sessionKey", sessionKey);          // BT-T03
}
