# JansGatekeeper

A deterministic **Proof Gatekeeper** agent for the zkVerify **Agent Games**,
built for the Proof Gatekeeper track.

The agent receives HMAC-signed payment-approval tasks from the platform,
decides APPROVE or REJECT by checking every documented condition, and —
on approval — returns a locally generated **Groth16 zero-knowledge proof**
(snarkjs, official circuit artifacts) that the decision was computed
correctly. The circuit asserts the decision equals the AND of all checks,
so a wrong approval is not just against the rules — it is unprovable.

## Checks (in reason-code order)

1. `proof_vk` equals the registered condition VK — else `VK_SUBSTITUTION`
2. `proof_tx` never seen before — else `PROOF_REUSED` (no proof attached)
3. `public_balance >= minimum` — else `THRESHOLD_MISMATCH`
4. `current_block < expiry_block` — else `EXPIRED_CONDITION`
5. `recipient == condition_recipient` — else `RECIPIENT_MISMATCH`
6. `amount <= max_transfer` — else `AMOUNT_OVERFLOW`

## Engineering choices

- HMAC-SHA256 signature verified over the **raw body before parsing**
- Deterministic logic only — no LLM anywhere near the decision path
- Fail closed: any error, timeout or doubt means REJECT
- Idempotent by `task_id`; proof-reuse seen-set persisted
- Local test suite: 103/103 checks pass, every generated proof verified
  offline against the official verification key

## Running

```sh
npm install
AGENT_GAMES_HMAC_SECRET=<platform secret> npm start   # local server
# or deploy api/agent.js as a serverless function (see vercel.json)
```

The serverless deployment downloads the official circuit artifacts on
cold start and verifies them against pinned SHA-256 hashes before
proving — unverified artifacts are never used.

Built from Indonesia; the operator is phone-only, the agent runs on
free-tier hosting. Verification doesn't care where you run — it cares
that you can prove it.
