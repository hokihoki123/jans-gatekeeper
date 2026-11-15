"use strict";
/*
 * Deterministic decision policy for Proof Gatekeeper.
 *
 * No model is involved in the final call. The checks mirror the platform's
 * Security checklist and the trap taxonomy on the event page, and they must
 * mirror the gatekeeper circuit exactly: the circuit asserts that its
 * `decision` input equals the AND of the five field checks, so any
 * disagreement between this code and the circuit makes witness generation
 * fail (which we treat as fail-closed REJECT).
 *
 * Check order (first failure decides the reason_code):
 *   proof_vk != registered_vk        -> VK_SUBSTITUTION
 *   proof_tx already seen            -> PROOF_REUSED   (carries no proof)
 *   public_balance < minimum         -> THRESHOLD_MISMATCH
 *   current_block >= expiry_block    -> EXPIRED_CONDITION
 *   recipient != condition_recipient -> RECIPIENT_MISMATCH
 *   amount > max_transfer            -> AMOUNT_OVERFLOW
 *   otherwise                        -> APPROVE / VALID_CONDITION
 *
 * Boundary semantics: balance == minimum passes, amount == max_transfer
 * passes, current_block == expiry_block is already expired.
 */
const crypto = require("crypto");
const { FIELD_PRIME } = require("./signing");

function normalizeHexString(v) {
  return typeof v === "string" ? v.trim().toLowerCase() : "";
}

/** Parse a non-negative integer from a decimal string, hex string, or number. */
function parseUint(v) {
  if (typeof v === "number") {
    return Number.isSafeInteger(v) && v >= 0 ? BigInt(v) : null;
  }
  if (typeof v !== "string") return null;
  const s = v.trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  if (/^[0-9]+$/.test(s)) return BigInt(s);
  return null;
}

/**
 * Validate and normalize the envelope `input` object.
 * Returns null when any field is missing or malformed (caller fails closed).
 */
function parseTaskInput(input) {
  if (!input || typeof input !== "object") return null;
  const minimum = parseUint(input.minimum);
  const publicBalance = parseUint(input.public_balance);
  const amount = parseUint(input.amount);
  const maxTransfer = parseUint(input.max_transfer);
  const expiryBlock = parseUint(input.expiry_block);
  const currentBlock = parseUint(input.current_block);
  if (
    minimum === null ||
    publicBalance === null ||
    amount === null ||
    maxTransfer === null ||
    expiryBlock === null ||
    currentBlock === null
  ) {
    return null;
  }
  for (const field of [
    "registered_vk",
    "proof_vk",
    "recipient",
    "condition_recipient",
    "proof_tx",
  ]) {
    if (typeof input[field] !== "string" || input[field].trim() === "") {
      return null;
    }
  }
  return {
    registeredVk: input.registered_vk,
    proofVk: input.proof_vk,
    minimum,
    publicBalance,
    expiryBlock,
    currentBlock,
    recipient: input.recipient,
    conditionRecipient: input.condition_recipient,
    amount,
    maxTransfer,
    proofTx: input.proof_tx,
  };
}

/**
 * Evaluate the policy. `alreadySeen(proofTx)` reports whether the proof
 * reference was recorded by an earlier task.
 * Returns { decision, reason_code, provable } — provable is false only for
 * PROOF_REUSED, which the event page documents as having no proof to submit.
 */
function evaluatePolicy(parsed, alreadySeen) {
  if (normalizeHexString(parsed.proofVk) !== normalizeHexString(parsed.registeredVk)) {
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION", provable: true };
  }
  if (alreadySeen(parsed.proofTx)) {
    return { decision: "REJECT", reason_code: "PROOF_REUSED", provable: false };
  }
  if (parsed.publicBalance < parsed.minimum) {
    return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH", provable: true };
  }
  if (parsed.currentBlock >= parsed.expiryBlock) {
    return { decision: "REJECT", reason_code: "EXPIRED_CONDITION", provable: true };
  }
  if (normalizeHexString(parsed.recipient) !== normalizeHexString(parsed.conditionRecipient)) {
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH", provable: true };
  }
  if (parsed.amount > parsed.maxTransfer) {
    return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW", provable: true };
  }
  return { decision: "APPROVE", reason_code: "VALID_CONDITION", provable: true };
}

/**
 * Reduce an envelope value to a BN128 field element (decimal string).
 * Hex and decimal values are taken numerically mod p (reduction preserves
 * the equality comparisons the circuit performs); anything else (e.g. a
 * free-form task id like "gk_8d31_x") is hashed into the field with SHA-256.
 */
function toFieldElement(v) {
  let n;
  if (typeof v === "bigint") {
    n = v;
  } else {
    const s = String(v).trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) n = BigInt(s);
    else if (/^[0-9]+$/.test(s)) n = BigInt(s);
    else n = BigInt("0x" + crypto.createHash("sha256").update(s).digest("hex"));
  }
  return (((n % FIELD_PRIME) + FIELD_PRIME) % FIELD_PRIME).toString(10);
}

/**
 * Circuit inputs for gatekeeper.wasm. Signal layout (recovered from the
 * official artifacts and confirmed by proving):
 *   inputs:  taskId, registeredVkHash, proofVkHash, minimum, publicBalance,
 *            expiryBlock, currentBlock, recipient, conditionRecipient,
 *            amount, maxTransfer, decision, salt (private)
 *   outputs/public signals: [commitment=Poseidon(taskId, salt), then the 12
 *            public inputs in the same order, ending with taskId]
 */
function buildCircuitInputs(taskId, parsed, decision, salt) {
  return {
    taskId: toFieldElement(taskId),
    registeredVkHash: toFieldElement(parsed.registeredVk),
    proofVkHash: toFieldElement(parsed.proofVk),
    minimum: parsed.minimum.toString(10),
    publicBalance: parsed.publicBalance.toString(10),
    expiryBlock: parsed.expiryBlock.toString(10),
    currentBlock: parsed.currentBlock.toString(10),
    recipient: toFieldElement(parsed.recipient),
    conditionRecipient: toFieldElement(parsed.conditionRecipient),
    amount: parsed.amount.toString(10),
    maxTransfer: parsed.maxTransfer.toString(10),
    decision: decision === "APPROVE" ? "1" : "0",
    salt: salt.toString(10),
  };
}

module.exports = {
  parseUint,
  parseTaskInput,
  evaluatePolicy,
  toFieldElement,
  buildCircuitInputs,
  normalizeHexString,
};
