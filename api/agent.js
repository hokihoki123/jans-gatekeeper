"use strict";
/*
 * Vercel serverless entry (deployment alternative — see STATUS.md).
 *
 * Deploy: connect this project to Vercel under the owner's own account,
 * set AGENT_GAMES_HMAC_SECRET (and optionally KURIER_API_KEY,
 * KURIER_POLL_BUDGET_MS=5000) in the Vercel project env, deploy, and
 * register https://<project>.vercel.app/agent as the agent endpoint.
 *
 * State note: on serverless the seen-set/response cache lives in /tmp and
 * can reset on cold starts. Within a round this is a small PROOF_REUSED
 * risk; the VM + named-tunnel deployment keeps state on disk instead.
 */
const path = require("path");
const { loadConfig } = require("../src/config");
const { GatekeeperHandler } = require("../src/handler");
const { AgentState } = require("../src/store");
const { SIGNATURE_HEADER } = require("../src/signing");

process.env.ARTIFACTS_DIR =
  process.env.ARTIFACTS_DIR || path.join(process.cwd(), "artifacts");
process.env.STATE_PATH =
  process.env.STATE_PATH || "/tmp/agentgames-state.json";

const cfg = loadConfig();
const handler = new GatekeeperHandler(cfg, new AgentState(cfg.statePath));

module.exports = async (req, res) => {
  if (req.method === "GET") {
    const r = handler.health();
    res.status(r.status).setHeader("content-type", "application/json");
    res.send(r.body);
    return;
  }
  if (req.method !== "POST") {
    res.status(404).json({ error: "not_found" });
    return;
  }
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const rawBody = Buffer.concat(chunks);
  const headerValue = req.headers[SIGNATURE_HEADER];
  const result = await handler.handlePost(
    rawBody,
    Array.isArray(headerValue) ? headerValue[0] : headerValue
  );
  res.status(result.status).setHeader("content-type", "application/json");
  if (result.signature) res.setHeader(SIGNATURE_HEADER, result.signature);
  res.send(result.body);
};

module.exports.config = { api: { bodyParser: false } };
