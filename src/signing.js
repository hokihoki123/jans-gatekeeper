"use strict";
/*
 * HMAC signing for the Agent Games protocol.
 *
 * The platform signs every request with the agent's secret in the
 * x-agent-games-signature header, computed over the RAW request body, and
 * expects the same signature over the raw response body. The docs mandate
 * HMAC over the raw body without pinning an encoding, so:
 *  - we SIGN with HMAC-SHA256, lowercase hex digest;
 *  - we VERIFY against the raw MAC bytes, accepting the hex or base64
 *    spelling of those bytes (and an optional "sha256=" prefix), compared
 *    in constant time. Accepting two spellings of the same MAC does not
 *    weaken authentication — the caller must still know the secret.
 */
const crypto = require("crypto");

const SIGNATURE_HEADER = "x-agent-games-signature";

/** BN128 scalar field prime; circuit values are reduced modulo this. */
const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function signBody(secret, rawBody) {
  return crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
}

function macBytes(secret, rawBody) {
  return crypto.createHmac("sha256", secret).update(rawBody).digest();
}

function decodeSignatureHeader(headerValue) {
  if (typeof headerValue !== "string") return null;
  let v = headerValue.trim();
  if (v.toLowerCase().startsWith("sha256=")) v = v.slice("sha256=".length).trim();
  if (/^[0-9a-fA-F]{64}$/.test(v)) return Buffer.from(v, "hex");
  try {
    const b = Buffer.from(v, "base64");
    if (b.length === 32) return b;
  } catch {
    /* not base64 either */
  }
  return null;
}

function verifyBodySignature(secret, rawBody, headerValue) {
  if (!secret || !headerValue) return false;
  const candidate = decodeSignatureHeader(headerValue);
  if (!candidate) return false;
  const expected = macBytes(secret, rawBody);
  return (
    candidate.length === expected.length &&
    crypto.timingSafeEqual(candidate, expected)
  );
}

/**
 * Per-task circuit salt. Deterministic (HMAC of the task id under our
 * secret, reduced into the field) so that a platform redelivery of the same
 * task reproduces identical proof inputs, while staying unpredictable to
 * anyone who does not hold the secret.
 */
function deriveTaskSalt(secret, taskId) {
  const digest = crypto
    .createHmac("sha256", secret || "gatekeeper-unconfigured")
    .update("gatekeeper-salt:" + taskId)
    .digest();
  return BigInt("0x" + digest.toString("hex")) % FIELD_PRIME;
}

module.exports = {
  SIGNATURE_HEADER,
  FIELD_PRIME,
  signBody,
  verifyBodySignature,
  deriveTaskSalt,
};
