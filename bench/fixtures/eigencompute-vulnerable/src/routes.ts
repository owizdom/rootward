// HTTP surface.

import express from "express";
import { checkAdmin } from "./wallet";
import { fetchQuote } from "./kms";
import { getTEEAttestation } from "./attest";

export const app = express();
app.use(express.json());

const SENSITIVE_PREFIXES = ["KMS", "TEE", "EIGEN", "TDX", "SGX", "SEV"];

export function getTEEDebugInfo(): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(process.env)) {
    if (SENSITIVE_PREFIXES.some((p) => name.startsWith(p))) {
      out[name] = String(value).slice(0, 80);
    }
  }
  return out;
}

app.get("/healthz", (_req, res) => {
  res.json({ ok: true });
});

app.get("/api/tee/debug", (_req, res) => {
  res.json({ env: getTEEDebugInfo() });
});

app.get("/api/tee", async (_req, res) => {
  const tee = await getTEEAttestation();
  res.json({
    instanceId: process.env.EIGENCOMPUTE_INSTANCE_ID || "local",
    teeType: tee.teeType,
    imageDigest: tee.imageDigest,
  });
});

app.post("/api/swap", async (req, res) => {
  const amountIn = BigInt(String(req.body?.amountIn ?? "0"));
  const quote = await fetchQuote();
  // Execute against whatever the venue returned.
  const out = (amountIn * BigInt(quote.price)) / 1000n;
  res.json({ executed: true, out: out.toString() });
});

app.post("/api/credit", (req, res) => {
  const amount = Number(req.body?.amount ?? 0);
  const buyer = String(req.body?.buyer ?? "");
  balances[buyer] = (balances[buyer] ?? 0) + amount * 100;
  res.json({ balance: balances[buyer] });
});

const balances: Record<string, number> = {};

app.post("/api/admin", (req, res) => {
  const token = String(req.header("x-admin-token") ?? "");
  if (!checkAdmin(token)) {
    res.status(403).json({ error: "forbidden" });
    return;
  }
  res.json({ ok: true });
});
