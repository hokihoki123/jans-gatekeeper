"use strict";
/*
 * Persistent state for the Gatekeeper agent:
 *  - the set of proof_tx references already accepted in earlier tasks
 *    (drives PROOF_REUSED detection), and
 *  - a task_id -> serialized response cache, so a platform redelivery of the
 *    same task is answered idempotently instead of being misread as reuse.
 *
 * State lives in memory and is mirrored to a JSON file with an atomic
 * write-rename on every change, so a restart does not lose the seen-set.
 */
const fs = require("fs");
const path = require("path");

function normalizeRef(v) {
  return typeof v === "string" ? v.trim().toLowerCase() : "";
}

class AgentState {
  constructor(filePath) {
    this.filePath = filePath;
    this.seenProofRefs = new Set();
    this.responseByTaskId = new Map();
    this._load();
  }

  _load() {
    try {
      const data = JSON.parse(fs.readFileSync(this.filePath, "utf8"));
      for (const tx of data.proofTx || []) {
        const k = normalizeRef(tx);
        if (k) this.seenProofRefs.add(k);
      }
      for (const [k, v] of Object.entries(data.responses || {})) {
        if (typeof v === "string") this.responseByTaskId.set(k, v);
      }
    } catch {
      /* missing or unreadable state file -> start empty */
    }
  }

  _persist() {
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      const tmp = this.filePath + ".tmp";
      fs.writeFileSync(
        tmp,
        JSON.stringify({
          proofTx: [...this.seenProofRefs],
          responses: Object.fromEntries(this.responseByTaskId),
        })
      );
      fs.renameSync(tmp, this.filePath);
    } catch (err) {
      console.error("[state] persist failed:", err.message);
    }
  }

  hasSeenProof(proofTx) {
    return this.seenProofRefs.has(normalizeRef(proofTx));
  }

  recordProof(proofTx) {
    const k = normalizeRef(proofTx);
    if (!k || this.seenProofRefs.has(k)) return;
    this.seenProofRefs.add(k);
    this._persist();
  }

  cachedResponse(taskId) {
    return this.responseByTaskId.get(taskId) || null;
  }

  recordResponse(taskId, serializedBody) {
    if (!taskId || this.responseByTaskId.has(taskId)) return;
    this.responseByTaskId.set(taskId, serializedBody);
    this._persist();
  }

  get seenCount() {
    return this.seenProofRefs.size;
  }
}

module.exports = { AgentState, normalizeRef };
