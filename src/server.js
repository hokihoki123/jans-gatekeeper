"use strict";
/*
 * HTTP entrypoint for the Gatekeeper agent.
 *
 * Routes:
 *   POST /agent   — registered agent endpoint (preflight + tasks)
 *   GET  /agent   — health check { ok: true, protocolVersion: "v1" }
 *   GET  /health  — same health payload
 *
 * The raw request body is preserved byte-for-byte for HMAC verification;
 * nothing parses JSON before the handler has authenticated it.
 */
const http = require("http");
const { loadConfig } = require("./config");
const { GatekeeperHandler } = require("./handler");
const { AgentState } = require("./store");
const { SIGNATURE_HEADER } = require("./signing");

const MAX_BODY_BYTES = 1024 * 1024;

function createServer() {
  const cfg = loadConfig();
  if (!cfg.hmacSecret) {
    console.warn(
      "[agent] WARNING: AGENT_GAMES_HMAC_SECRET is not set — task POSTs will return 500 until it is configured."
    );
  }
  const handler = new GatekeeperHandler(cfg, new AgentState(cfg.statePath));

  return http.createServer((req, res) => {
    let url;
    try {
      url = new URL(req.url || "/", "http://localhost");
    } catch {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "bad_url" }));
      return;
    }
    const isAgentPath = url.pathname === "/agent" || url.pathname === "/";

    if (req.method === "GET" && (isAgentPath || url.pathname === "/health")) {
      const r = handler.health();
      res.writeHead(r.status, { "content-type": "application/json" });
      res.end(r.body);
      return;
    }

    if (req.method === "POST" && isAgentPath) {
      const chunks = [];
      let size = 0;
      let tooLarge = false;
      req.on("data", (chunk) => {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) {
          tooLarge = true;
          res.writeHead(413, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "payload_too_large" }));
          req.destroy();
          return;
        }
        chunks.push(chunk);
      });
      req.on("end", async () => {
        if (tooLarge) return;
        const rawBody = Buffer.concat(chunks);
        const headerValue = req.headers[SIGNATURE_HEADER];
        const result = await handler.handlePost(
          rawBody,
          Array.isArray(headerValue) ? headerValue[0] : headerValue
        );
        const headers = { "content-type": "application/json" };
        if (result.signature) headers[SIGNATURE_HEADER] = result.signature;
        res.writeHead(result.status, headers);
        res.end(result.body);
      });
      req.on("error", () => {
        if (!res.headersSent) res.writeHead(400);
        res.end();
      });
      return;
    }

    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not_found" }));
  });
}

if (require.main === module) {
  const cfg = loadConfig();
  const server = createServer();
  server.listen(cfg.port, cfg.host, () => {
    console.log(`[agent] Gatekeeper agent listening on ${cfg.host}:${cfg.port} (POST /agent)`);
  });
}

module.exports = { createServer };
