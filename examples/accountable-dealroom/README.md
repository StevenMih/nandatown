# Accountable Dealroom — Buyer Skill

A neutral buyer skill for hiring a DJ via a bilaterally sealed, SCITT-anchored
deal-room. Five HTTP calls → two sovereign seller agents compete → buyer picks one
→ bilateral capsule seals → independent SCITT verify.

## What makes this different

**The proof is in the middle.** When the buyer accepts, both the buyer and the
chosen seller independently attest over the same offer hash. A third party trusting
neither can verify:

1. `sealed_terms_hash` recomputes from the stored terms → nothing was tampered
2. Both capsules pass self-attestation → each party's claim is valid
3. Chain intact → seller's capsule is cryptographically chained to the buyer's
4. SCITT receipt submitted → the digest is in the public transparency log

The bilateral seal uses [Agent Action Capsule](https://datatracker.ietf.org/doc/draft-mih-scitt-agent-action-capsule/)
(IETF draft) anchored to a live SCITT Transparency Service
(`anchor.agentactioncapsule.org`).

## Live service

```
https://accountable-dealroom-1020437450833.us-central1.run.app
```

Health check: `GET /health` → `{"ok": true}`

## Use with any compatible agent

The `BUYER-SKILL.md` file in this directory is the complete skill — a compatible
agent using only that file can discover sellers, negotiate, accept with a HITL gate,
and receive a verifiable contract. No additional dependencies.

```bash
# Verify a sealed binding offline (anyone can run this)
pip install agent-action-capsule
agent-action-capsule verify --store <ledger_path from /verify response>
```

## Sellers in this demo

| Seller | Rate | Deposit | Limbo | Cancel |
|--------|------|---------|-------|--------|
| Marcus Rey | $1,400 | 30-70 | No | 30 days |
| Nadia Cole | $1,300 | 50-50 | Yes +$75 | 14 days |

## Spec references

- [draft-mih-scitt-agent-action-capsule](https://datatracker.ietf.org/doc/draft-mih-scitt-agent-action-capsule/)
- [draft-mih-agent-bilateral-attestation](https://datatracker.ietf.org/doc/draft-mih-agent-bilateral-attestation/)
- [RFC 9943 — SCITT Architecture](https://www.rfc-editor.org/rfc/rfc9943)
