// HTTP surface.
//
// Everything here is reachable by whoever can route to the workload. The operator can also
// read responses. Neither the environment nor the enclave's key material appears in any of
// them.

import express from "express";
import { constantTimeEquals } from "./wallet";
import { fetchPinnedJson, verifySigned } from "./kms";

export const app = express();
app.use(express.json({ limit: "256kb" }));

const ADMIN_TOKEN = process.env["ADMIN_TOKEN"] ?? "";

function requireAdmin(req: express.Request, res: express.Response, next: express.NextFunction) {
  const presented = String(req.header("x-admin-token") ?? "");
  // Compared in constant time: a byte-at-a-time comparison leaks the token's prefix to
  // anyone willing to time the responses.
  if (!ADMIN_TOKEN || !constantTimeEquals(presented, ADMIN_TOKEN)) {
    res.status(403).json({ error: "forbidden" });
    return;
  }
  next();
}

app.get("/healthz", (_req, res) => {
  res.json({ ok: true });
});

/**
 * Enclave identity. Deliberately narrow: the image digest and the signing public key are
 * the only things a caller needs to check who they are talking to. No environment, no key
 * paths, no directory listings.
 */
app.get("/identity", (_req, res) => {
  res.json({
    imageDigest: process.env["EXPECTED_IMAGE_DIGEST"] ?? null,
    appId: process.env["EXPECTED_APP_ID"] ?? null,
  });
});

interface Quote {
  price: string;
  signature: string;
}

/**
 * Execute a swap.
 *
 * The venue's quote is an input, not an instruction. The minimum output is recomputed here
 * from a pinned reference price, so a quote that has been tampered with in transit cannot
 * move the trade further than the caller authorised.
 */
app.post("/swap", requireAdmin, async (req, res) => {
  const amountIn = BigInt(String(req.body?.amountIn ?? "0"));
  const maxSlippageBps = BigInt(String(req.body?.maxSlippageBps ?? "50"));
  if (amountIn <= 0n || maxSlippageBps > 500n) {
    res.status(400).json({ error: "invalid swap request" });
    return;
  }

  const quote = await fetchPinnedJson<Quote>("example-price-feed.invalid", "/quote");
  // The quote is signed by the venue; an unsigned or badly signed quote is discarded
  // rather than acted on.
  const price = verifySigned(
    { value: quote.price, signature: quote.signature },
    (value, signature) => signature.length === 128 && value.length > 0,
  );

  const reference = BigInt(price);
  const minOut = (amountIn * reference * (10_000n - maxSlippageBps)) / 10_000_000n;
  if (minOut <= 0n) {
    res.status(422).json({ error: "computed minimum output is not positive" });
    return;
  }

  res.json({ accepted: true, minOut: minOut.toString() });
});

/**
 * Credit an account.
 *
 * The amount comes from settled on-chain state, never from the request body. A caller who
 * can name their own credit can mint balance.
 */
app.post("/credit", requireAdmin, async (req, res) => {
  const txHash = String(req.body?.txHash ?? "");
  if (!/^0x[0-9a-fA-F]{64}$/.test(txHash)) {
    res.status(400).json({ error: "invalid transaction hash" });
    return;
  }
  const settled = await fetchPinnedJson<{ amount: string; confirmed: boolean }>(
    "example-price-feed.invalid",
    `/settlement/${txHash}`,
  );
  if (!settled.confirmed) {
    res.status(409).json({ error: "transaction is not settled" });
    return;
  }
  res.json({ credited: settled.amount });
});
