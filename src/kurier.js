"use strict";
/*
 * Kurier (zkVerify mainnet) proof submission.
 *
 *   POST {apiUrl}/submit-proof/{apiKey}
 *     { proofType: "groth16", vkRegistered: true,
 *       proofOptions: { library: "snarkjs", curve: "bn128" },
 *       proofData: { proof, publicSignals, vk: <gatekeeper vk_hash> } }
 *     -> { jobId, optimisticVerify }
 *   GET  {apiUrl}/job-status/{apiKey}/{jobId}
 *     lifecycle: Queued -> Valid -> Submitted -> IncludedInBlock ->
 *     Finalized | Failed. The on-chain txHash exists from "Submitted"
 *     onward; we return as soon as a txHash exists (see the polling loop
 *     for why waiting for Finalized is the wrong trade inside a 60 s
 *     task window), bounded by a budget that keeps the response timely.
 *
 * The gatekeeper verification key is already registered on zkVerify
 * mainnet, so no register-vk call is needed.
 *
 * This module NEVER throws: any failure returns null / partial outcome and
 * the caller still answers the task with the local proof + public_signals.
 */

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function submitAndTrack(cfg, proof, publicSignals, budgetMs) {
  if (!cfg.kurierApiKey) return null; // not configured — caller proceeds without it
  const key = cfg.kurierApiKey;
  const deadline = Date.now() + Math.max(0, budgetMs);
  try {
    const submitRes = await fetch(`${cfg.kurierApiUrl}/submit-proof/${key}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        proofType: "groth16",
        vkRegistered: true,
        proofOptions: { library: "snarkjs", curve: "bn128" },
        proofData: { proof, publicSignals, vk: cfg.gatekeeperVkHash },
      }),
    });
    if (!submitRes.ok) {
      console.error(`[kurier] submit-proof HTTP ${submitRes.status}`);
      return null;
    }
    const job = await submitRes.json();
    if (!job || !job.jobId) {
      console.error("[kurier] submit-proof response missing jobId");
      return null;
    }
    console.log(
      `[kurier] job ${job.jobId} accepted (optimisticVerify=${job.optimisticVerify ?? "n/a"})`
    );

    let status = "Submitted";
    let txHash;
    while (Date.now() < deadline) {
      const wait = Math.min(cfg.kurierPollIntervalMs, Math.max(0, deadline - Date.now()));
      if (wait > 0) await sleep(wait);
      let s;
      try {
        const statusRes = await fetch(
          `${cfg.kurierApiUrl}/job-status/${key}/${job.jobId}`
        );
        if (!statusRes.ok) {
          console.error(`[kurier] job-status HTTP ${statusRes.status}`);
          continue;
        }
        s = await statusRes.json();
      } catch (err) {
        console.error("[kurier] job-status error:", err.message);
        continue;
      }
      if (s.status) status = s.status;
      const hash = s.txHash || (s.transactionInfo && s.transactionInfo.txHash);
      if (hash) txHash = hash;
      if (status === "Failed") {
        return { jobId: job.jobId, status, txHash, finalized: false };
      }
      if (txHash) {
        // The verification transaction exists on-chain from the Submitted
        // stage onward (~4 s in live measurements), while full finalization
        // takes ~27 s and has exceeded 35 s. Waiting for Finalized inside a
        // 60 s task window risks turning a correct answer into a timeout,
        // so we return the txHash as soon as it exists; the job keeps
        // finalizing server-side at Kurier. This exact pattern was
        // practice-verified against the platform (proofs marked verified).
        return { jobId: job.jobId, status, txHash, finalized: status === "Finalized" };
      }
    }
    console.log(
      `[kurier] job ${job.jobId} not finalized within budget (last status=${status}, txHash=${txHash || "none"})`
    );
    return { jobId: job.jobId, status, txHash, finalized: false };
  } catch (err) {
    console.error("[kurier] submission error:", err.message);
    return null;
  }
}

module.exports = { submitAndTrack };
