"use strict";
/*
 * Request pipeline for the Gatekeeper agent endpoint.
 *
 * Order of operations (per the platform build guide):
 *   1. Verify x-agent-games-signature over the RAW body — before any parsing.
 *      Mismatch -> HTTP 401, unsigned error body.
 *   2. Preflight envelopes -> signed { ok: true, protocolVersion: "v1" }.
 *   3. Task envelopes -> idempotency cache, timestamp sanity, deterministic
 *      policy, local Groth16 proof (every provable case), optional Kurier
 *      submission, signed response.
 *   4. Fail closed everywhere: malformed input, expired deadline, internal
 *      errors and proving failures all resolve to REJECT — never an
 *      unproven APPROVE. "INVALID_TASK" is a defensive code outside the
 *      documented 7-code taxonomy, reachable only off the scored paths.
 */
const { signBody, verifyBodySignature, deriveTaskSalt } = require("./signing");
const { parseTaskInput, evaluatePolicy, buildCircuitInputs } = require("./policy");
const { GatekeeperProver } = require("./prover");
const { submitAndTrack } = require("./kurier");

const TASK_TYPE = "agent-games.proof-gatekeeper.v1";
const PREFLIGHT_TYPE = "agent-games.preflight.v1";
const PROTOCOL_VERSION = "v1";

/** Tolerant timestamp parse: ISO string, epoch seconds, or epoch ms. */
function parseTimestampMs(v) {
  if (typeof v === "number" && Number.isFinite(v)) {
    return v < 1e12 ? v * 1000 : v;
  }
  if (typeof v === "string") {
    const s = v.trim();
    if (/^[0-9]+$/.test(s)) {
      const n = Number(s);
      return n < 1e12 ? n * 1000 : n;
    }
    const t = Date.parse(s);
    return Number.isNaN(t) ? null : t;
  }
  return null;
}

class GatekeeperHandler {
  constructor(cfg, state) {
    this.cfg = cfg;
    this.state = state;
    this.prover = new GatekeeperProver(cfg.artifactsDir);
  }

  health() {
    return {
      status: 200,
      body: JSON.stringify({ ok: true, protocolVersion: PROTOCOL_VERSION }),
      signature: null,
    };
  }

  _signed(status, obj) {
    const body = JSON.stringify(obj);
    return { status, body, signature: signBody(this.cfg.hmacSecret, body) };
  }

  _signedRaw(status, body) {
    return { status, body, signature: signBody(this.cfg.hmacSecret, body) };
  }

  async handlePost(rawBody, signatureHeader) {
    if (!this.cfg.hmacSecret) {
      return {
        status: 500,
        body: JSON.stringify({
          error: "server_misconfigured",
          detail: "AGENT_GAMES_HMAC_SECRET is not set",
        }),
        signature: null,
      };
    }

    // 1. Authenticate the raw bytes before parsing anything.
    if (!verifyBodySignature(this.cfg.hmacSecret, rawBody, signatureHeader)) {
      return {
        status: 401,
        body: JSON.stringify({ error: "invalid_signature" }),
        signature: null,
      };
    }

    let envelope;
    try {
      envelope = JSON.parse(rawBody.toString("utf8"));
    } catch {
      return this._signed(400, { decision: "REJECT", reason_code: "INVALID_TASK" });
    }
    if (!envelope || typeof envelope !== "object") {
      return this._signed(400, { decision: "REJECT", reason_code: "INVALID_TASK" });
    }

    // 2. Preflight handshake.
    if (envelope.type === PREFLIGHT_TYPE) {
      return this._signed(200, { ok: true, protocolVersion: PROTOCOL_VERSION });
    }

    if (envelope.type !== TASK_TYPE) {
      return this._signed(400, { decision: "REJECT", reason_code: "INVALID_TASK" });
    }

    // 3. Task.
    try {
      return await this._handleTask(envelope);
    } catch (err) {
      console.error("[agent] task handling error:", err.message);
      return this._signed(200, { decision: "REJECT", reason_code: "INVALID_TASK" });
    }
  }

  async _handleTask(task) {
    const startedAt = Date.now();

    // Idempotent redelivery: the platform may retry after a network
    // failure; answer with the original response, never re-evaluate (a
    // redelivery must not be mistaken for proof reuse).
    if (typeof task.task_id === "string" && task.task_id) {
      const cached = this.state.cachedResponse(task.task_id);
      if (cached) return this._signedRaw(200, cached);
    }

    // Timestamp sanity. The HMAC already authenticates the sender; this is
    // anti-replay hygiene. Only a clearly past deadline fails the task.
    const now = Date.now();
    const deadlineMs = parseTimestampMs(task.deadline_at);
    if (deadlineMs !== null && now > deadlineMs) {
      return this._signed(200, { decision: "REJECT", reason_code: "INVALID_TASK" });
    }
    const issuedMs = parseTimestampMs(task.issued_at);
    if (issuedMs !== null && issuedMs > now + 5 * 60 * 1000) {
      return this._signed(200, { decision: "REJECT", reason_code: "INVALID_TASK" });
    }

    const parsed = parseTaskInput(task.input);
    if (!parsed || typeof task.task_id !== "string" || !task.task_id) {
      return this._signed(200, { decision: "REJECT", reason_code: "INVALID_TASK" });
    }

    const evaluation = evaluatePolicy(parsed, (tx) => this.state.hasSeenProof(tx));

    const response = {
      decision: evaluation.decision,
      reason_code: evaluation.reason_code,
    };

    if (!evaluation.provable) {
      // PROOF_REUSED: documented as having no proof to submit. Echo the
      // reference, matching the sample response shape in the docs.
      response.proof_tx = parsed.proofTx;
    } else {
      const salt = deriveTaskSalt(this.cfg.hmacSecret, task.task_id);
      const circuitInputs = buildCircuitInputs(
        task.task_id,
        parsed,
        evaluation.decision,
        salt
      );
      let proved;
      try {
        proved = await this.prover.prove(circuitInputs);
      } catch (err) {
        // Proving failed (includes a decision the circuit refuses to
        // witness). Fail closed: never send an APPROVE without its proof.
        console.error("[agent] proof generation failed:", err.message);
        if (evaluation.decision === "APPROVE") {
          return this._signed(200, {
            decision: "REJECT",
            reason_code: "INVALID_TASK",
            proof_tx: parsed.proofTx,
          });
        }
        return this._signed(200, {
          decision: "REJECT",
          reason_code: evaluation.reason_code,
          proof_tx: parsed.proofTx,
        });
      }
      response.proof = proved.proof;
      response.public_signals = proved.publicSignals;

      // zkVerify submission via Kurier, bounded so the answer stays inside
      // the deadline. Absent key / any failure: still answer with the
      // locally generated proof + public_signals.
      const remainingMs = this.cfg.taskSoftDeadlineMs - (Date.now() - startedAt);
      const budgetMs = Math.min(this.cfg.kurierPollBudgetMs, Math.max(0, remainingMs));
      const kurier = await submitAndTrack(
        this.cfg,
        proved.proof,
        proved.publicSignals,
        budgetMs
      );
      response.proof_tx = kurier && kurier.txHash ? kurier.txHash : parsed.proofTx;
    }

    const result = this._signed(200, response);
    // Record only after a completed evaluation, so a task never flags
    // its own proof reference as reused.
    this.state.recordProof(parsed.proofTx);
    this.state.recordResponse(task.task_id, result.body);
    return result;
  }
}

module.exports = { GatekeeperHandler, TASK_TYPE, PREFLIGHT_TYPE, PROTOCOL_VERSION };
