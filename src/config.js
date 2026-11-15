"use strict";
/*
 * Runtime configuration for the Gatekeeper agent.
 *
 * Everything sensitive comes from the environment (or a local .env file that
 * is never committed). There are deliberately NO default secrets: without
 * AGENT_GAMES_HMAC_SECRET the agent refuses to answer task POSTs, because a
 * placeholder secret would fail the platform preflight anyway and could mask
 * a misconfiguration.
 */
const fs = require("fs");
const path = require("path");

const PROJECT_ROOT = path.resolve(__dirname, "..");

/** Minimal .env reader (KEY=VALUE lines, # comments). Real env wins. */
function loadDotEnv(file) {
  try {
    const raw = fs.readFileSync(file, "utf8");
    for (const line of raw.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eq = trimmed.indexOf("=");
      if (eq <= 0) continue;
      const key = trimmed.slice(0, eq).trim();
      let value = trimmed.slice(eq + 1).trim();
      if (
        (value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))
      ) {
        value = value.slice(1, -1);
      }
      if (process.env[key] === undefined) process.env[key] = value;
    }
  } catch {
    /* no .env file is fine */
  }
}

function intFromEnv(name, fallback) {
  const v = Number(process.env[name]);
  return Number.isFinite(v) && v > 0 ? Math.floor(v) : fallback;
}

function loadConfig() {
  loadDotEnv(path.join(PROJECT_ROOT, ".env"));
  const env = process.env;
  return {
    // Platform-issued HMAC secret (dashboard -> Rotate Secret). Required.
    hmacSecret: env.AGENT_GAMES_HMAC_SECRET || "",
    // Kurier (zkVerify) — optional. Without a key the agent still answers
    // with the locally generated proof + public_signals.
    kurierApiKey: env.KURIER_API_KEY || null,
    kurierApiUrl: env.KURIER_API_URL || "https://api.kurier.xyz/api/v1",
    // Registered gatekeeper vk_hash on zkVerify mainnet (/api/circuit-info).
    gatekeeperVkHash:
      env.GATEKEEPER_VK_HASH ||
      "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
    artifactsDir: env.ARTIFACTS_DIR || path.join(PROJECT_ROOT, "artifacts"),
    statePath: env.STATE_PATH || path.join(PROJECT_ROOT, "data", "state.json"),
    // Time budgets: the platform hard deadline is 60 s. Proving takes ~1 s;
    // Kurier polling is capped so the response always leaves in time.
    kurierPollBudgetMs: intFromEnv("KURIER_POLL_BUDGET_MS", 20000),
    kurierPollIntervalMs: intFromEnv("KURIER_POLL_INTERVAL_MS", 3000),
    taskSoftDeadlineMs: intFromEnv("TASK_SOFT_DEADLINE_MS", 50000),
    port: intFromEnv("PORT", 8791),
    host: env.HOST || "0.0.0.0",
  };
}

module.exports = { loadConfig, PROJECT_ROOT };
