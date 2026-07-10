---
name: accountable-dealroom-buyer
description: >
  Hire a DJ via a neutral accountable deal-room: discover sellers, negotiate,
  accept with a human gate, and receive a bilaterally sealed verifiable contract.
  Five calls → one byte-identical capsule both parties hold → independent SCITT verify.
tags: [negotiation, bilateral, capsule, scitt, dj, hire, nanda]
source: https://github.com/action-state-group/accountable-dealroom
spec: https://datatracker.ietf.org/doc/draft-mih-scitt-agent-action-capsule/
---

# Accountable Dealroom — Buyer Skill

> **From-file guarantee:** a stock OpenClaw agent using only this file can
> discover sellers, negotiate a DJ booking, and obtain a cryptographically
> verifiable bilateral contract — all in five HTTP calls against `https://accountable-dealroom-1020437450833.us-central1.run.app`.

---

## What this skill does

You hire a DJ. Two sovereign seller agents (Marcus Rey and Nadia Cole) respond
with offers. You accept the one that matches your requirements. A
**bilateral sealed capsule** — byte-identical on both sides — becomes the
verifiable record of what was agreed. A third party trusting neither you nor
the seller can run the verify check and confirm the deal.

**What's real in this demo:**
- AAuth identity (signed requests on a live droplet)
- Bilateral capsule seal (real Ed25519 crypto, live capsule ledger)
- SCITT anchor receipt (anchor.agentactioncapsule.org — live SCITT Transparency Service)
- Two sovereign agents negotiating in parallel
- NANDA discovery (GET /v1/agents → AgentFacts records)

**What's roadmap:**
- AAuth three-party delegated consent (person-server flow)
- SMS/iMessage transport
- Fireproof E2E-encrypted browser live-view

---

## 5-call flow

### Call 1 — Discover sellers

```http
GET https://accountable-dealroom-1020437450833.us-central1.run.app/v1/agents
```

Returns the list of registered seller agents with their capabilities.

```json
{
  "agents": [
    {
      "agent_id": "marcus-rey",
      "name": "Marcus Rey",
      "description": "Versatile DJ — house, hip-hop, and Afrobeats.",
      "skills": ["DJ performance", "MC", "sound system setup", "crowd engagement"]
    }
  ]
}
```

---

### Call 2 — Open a negotiation room

```http
POST https://accountable-dealroom-1020437450833.us-central1.run.app/v1/hire
Content-Type: application/json

{
  "request_text": "Hire a DJ for our tech event on July 14, budget ~$1500. Must bring a PA system. Please ask about a limbo game.",
  "event_date": "2026-07-14",
  "budget_usd": 1500,
  "requirements": ["bring PA", "ask about limbo game"],
  "buyer_id": "buyer@example.com"
}
```

Returns:

```json
{
  "hire_id": "<uuid>",
  "status": "offers_ready",
  "sellers_contacted": ["marcus-rey"],
  "room_url": "/room?hire_id=<uuid>"
}
```

---

### Call 3 — Poll for offers

```http
GET https://accountable-dealroom-1020437450833.us-central1.run.app/v1/hire/{hire_id}
```

Poll until `status == "offers_ready"`. Read `offers[].offer_hash` for the
offer you want to accept. The `offer_hash` is the SHA-256 of the canonical
offer terms — it's what goes into the bilateral capsule.

Example response:

```json
{
  "hire_id": "<uuid>",
  "status": "offers_ready",
  "offers": [
    {
      "seller_id": "marcus-rey",
      "seller_name": "Marcus Rey",
      "offer_hash": "<sha256>",
      "rate_usd": 1400,
      "deposit_split": "30-70",
      "limbo_game": false,
      "cancel_notice_days": 30
    }
  ]
}
```

---

### Call 4 — Accept (human gate)

`gate: "human_authorized"` is the buyer's explicit HITL gate clearance.
You (the human) review the offer and instruct the agent to proceed.

```http
POST https://accountable-dealroom-1020437450833.us-central1.run.app/v1/hire/{hire_id}/accept
Content-Type: application/json

{
  "offer_hash": "<offer_hash from Call 3>",
  "gate": "human_authorized"
}
```

Returns:

```json
{
  "hire_id": "<uuid>",
  "status": "sealed",
  "binding_id": "<uuid>",
  "binding_url": "/v1/bindings/<uuid>",
  "verdict_disposition": "executed",
  "anchored": true,
  "sealed_terms_hash": "<sha256>"
}
```

The `verdict_disposition: "executed"` confirms both gates cleared (buyer
`human_authorized` + seller `co_signed`) and the bilateral capsule sealed.

---

### Call 5 — Verify the binding

```http
GET https://accountable-dealroom-1020437450833.us-central1.run.app/v1/bindings/{binding_id}/verify
```

Returns the independent verification result:

```json
{
  "verified": true,
  "sealed_terms_hash": "<sha256>",
  "sealed_terms_hash_match": true,
  "buyer_capsule": { "capsule_id": "...", "ok": true, "verdict": "executed" },
  "seller_capsule": { "capsule_id": "...", "ok": true, "verdict": "executed" },
  "chain_intact": true,
  "scitt_anchor": {
    "submitted": true,
    "anchor_url": "https://anchor.agentactioncapsule.org",
    "verify_offline": "agent-action-capsule verify --store <ledger_path>"
  }
}
```

`verified: true` means:
1. `sealed_terms_hash` recomputes correctly from stored terms — terms not tampered
2. Both capsules pass Class-1 verify — self-attestation valid
3. Chain intact — seller's capsule is cryptographically chained to buyer's
4. SCITT anchor submitted — the digest is in the public transparency log

---

### Bonus — View the deal room

```http
GET https://accountable-dealroom-1020437450833.us-central1.run.app/room?hire_id={hire_id}
```

Browser-renderable HTML showing the negotiation timeline and the sealed binding.

---

## Negotiation guidance

Both sellers respond immediately with deterministic offers:

| Seller | Rate | Deposit | Limbo game | Cancel notice |
|--------|------|---------|------------|---------------|
| Marcus Rey | $1,400 | 30% up / 70% completion | No | 30 days |
| Nadia Cole | $1,300 | 50% up / 50% completion | Yes (+$75) | 14 days |

**Choosing between offers:**
- If the buyer's budget is ~$1,500: both are within budget.
- PA system: both sellers include it.
- Limbo game requirement: Marcus doesn't offer it; Nadia does (+$75 fee).
- Tighter cancel policy preference: Nadia (14 days vs Marcus's 30 days).
- Lower upfront deposit preference: Marcus (30% vs Nadia's 50%).

**Do not negotiate the price.** Offers are deterministic. Your role is:
1. Read both offers from `offers[]`
2. Match them against the buyer's stated requirements
3. Present the best match to the buyer for the HITL gate (`gate: "human_authorized"`)
4. Proceed with accept using that offer's `offer_hash`

---

## Independent verification (anyone can run this)

```bash
pip install agent-action-capsule
agent-action-capsule verify --store <ledger_path from /verify response>
```

The `sealed_terms_hash` binds the offer terms to the capsule. The SCITT inclusion
proof from `anchor.agentactioncapsule.org` means the capsule is in the public
transparency log — neither party can deny the record.

---

## Spec reference

- Capsule format: [draft-mih-scitt-agent-action-capsule](https://datatracker.ietf.org/doc/draft-mih-scitt-agent-action-capsule/)
- Bilateral attestation: [draft-mih-agent-bilateral-attestation](https://datatracker.ietf.org/doc/draft-mih-agent-bilateral-attestation/)
- SCITT: [RFC 9943](https://www.rfc-editor.org/rfc/rfc9943)
