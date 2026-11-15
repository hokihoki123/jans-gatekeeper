"use strict";
/*
 * Local Groth16 proving with snarkjs against the official gatekeeper
 * artifacts (gatekeeper.wasm + gatekeeper_final.zkey, downloaded from the
 * platform's /api/circuit-info links). The circuit is small (647 witnesses);
 * a proof takes well under a second on this VM, far inside the 60 s task
 * deadline.
 *
 * Serverless fallback (Vercel): the binary artifacts are too large to ship
 * through the deployment channel we use, so when they are absent locally
 * they are fetched once from the OFFICIAL circuit-info URLs, verified
 * against pinned SHA-256 hashes, and cached in the OS temp dir. A hash
 * mismatch aborts the proof (fail closed) — never prove with unverified
 * artifacts.
 */
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const snarkjs = require("snarkjs");

const OFFICIAL_ARTIFACTS = {
  "gatekeeper.wasm": {
    url: "https://agentgames.zkverify.io/circuits/gatekeeper.wasm",
    sha256:
      "be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f",
  },
  "gatekeeper_final.zkey": {
    url: "https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey",
    sha256:
      "adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d",
  },
};

function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

class GatekeeperProver {
  constructor(artifactsDir) {
    this.wasmPath = path.join(artifactsDir, "gatekeeper.wasm");
    this.zkeyPath = path.join(artifactsDir, "gatekeeper_final.zkey");
    this._ready = null;
  }

  async _ensureArtifacts() {
    const missing = [];
    if (!fs.existsSync(this.wasmPath)) missing.push("gatekeeper.wasm");
    if (!fs.existsSync(this.zkeyPath)) missing.push("gatekeeper_final.zkey");
    if (missing.length === 0) return;
    const cacheDir = path.join(os.tmpdir(), "agentgames-artifacts");
    fs.mkdirSync(cacheDir, { recursive: true });
    for (const name of missing) {
      const spec = OFFICIAL_ARTIFACTS[name];
      const cached = path.join(cacheDir, name);
      if (fs.existsSync(cached)) {
        const buf = fs.readFileSync(cached);
        if (sha256Hex(buf) !== spec.sha256) {
          throw new Error(`cached artifact hash mismatch: ${name}`);
        }
      } else {
        const res = await fetch(spec.url);
        if (!res.ok) throw new Error(`artifact download failed: ${name} HTTP ${res.status}`);
        const buf = Buffer.from(await res.arrayBuffer());
        if (sha256Hex(buf) !== spec.sha256) {
          throw new Error(`downloaded artifact hash mismatch: ${name}`);
        }
        fs.writeFileSync(cached, buf);
      }
      if (name === "gatekeeper.wasm") this.wasmPath = cached;
      if (name === "gatekeeper_final.zkey") this.zkeyPath = cached;
    }
  }

  /** Returns { proof, publicSignals } exactly as snarkjs produces them. */
  async prove(circuitInputs) {
    if (!this._ready) this._ready = this._ensureArtifacts();
    await this._ready;
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      circuitInputs,
      this.wasmPath,
      this.zkeyPath
    );
    return { proof, publicSignals };
  }
}

module.exports = { GatekeeperProver };
