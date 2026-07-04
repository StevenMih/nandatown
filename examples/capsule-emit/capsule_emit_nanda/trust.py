# SPDX-License-Identifier: Apache-2.0
"""CapsuleEmitTrust — NANDA Town Trust layer plugin backed by capsule-emit.

Drop-in replacement for ``agent_receipts``: every interaction a NANDA agent
already reports via ``ctx.plugins.get("trust").report(...)`` is anchored to
an Agent Action Capsule ledger — zero agent-code changes required.

Three gates for a receipt to build reputation (same as ``agent_receipts``):

1. **Valid** — Ed25519 issuer signature verifies.
2. **Corroborated** — distinct counterparty co-signed the same interaction.
3. **Anchored** — a capsule was emitted and is present in the capsule ledger.

Gate 3 is the additive contribution: an agent whose interactions are never
anchored gets no reputation score even if their receipts are individually
valid and corroborated. The capsule ledger is the authoritative record,
independently verifiable by any party who ran none of the agents.

Plain-string ``evidence.detail`` (stock NANDA scenarios with no receipt)
falls back to the ``score_average`` heuristic so this plugin is a drop-in
in any scenario.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from pathlib import Path
from typing import Any, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import capsule_emit
from nest_core.types import AgentId, Attestation, Claim, Evidence, ReputationScore

# Private helpers from nest-plugins-reference — couples to NANDA internals.
# agent_receipts is not present in the published nest-plugins-reference package
# (v0.1.1); it lives only in a source checkout of the nandatown repo.  We
# defer the error to instantiation so that importing this module (and the
# StripeCapsuledPayments sibling) still works in a bare pip install.
_TRUST_BACKEND_AVAILABLE = True
try:
    from nest_plugins_reference.trust.agent_receipts import (
        NORMALIZATION_K,
        DEFAULT_CATEGORY_WEIGHTS,
        _action_field,
        _counterparty,
        _effective_receipts,
        _normalize,
        _raw_reputation,
        _verify_receipt,
        did_for_pubkey,
        is_corroborated,
    )
except ImportError:
    _TRUST_BACKEND_AVAILABLE = False

logger = logging.getLogger(__name__)

ALGORITHM = "ed25519"
_DEFAULT_CAPSULE_ACTION = "message_sent"


class CapsuleEmitTrust:
    """Anchored, collusion-resistant reputation implementing the ``Trust`` Protocol.

    Mirrors ``AgentReceiptsTrust`` with one addition: every corroborated receipt
    triggers a ``capsule_emit.emit()`` call, so the reputation history is sealed
    to an Agent Action Capsule ledger that any third party can verify with::

        agent-action-capsule verify --store capsule_ledger.jsonl

    Args:
        identity: Agent identity (passed by the NANDA runtime; may be None).
        anchor: Whether to anchor capsules to the public log (default False for
            deterministic replay; set True for the live-anchor pass).
        ledger: Path for the capsule ledger JSONL file.
    """

    _SYSTEM_AGENT = AgentId("trust:capsule_emit")

    def __init__(
        self,
        identity: Any = None,
        *,
        anchor: bool = False,
        ledger: str | Path = "capsule_ledger.jsonl",
    ) -> None:
        if not _TRUST_BACKEND_AVAILABLE:
            raise ImportError(
                "CapsuleEmitTrust requires nest_plugins_reference.trust.agent_receipts, "
                "which is not present in the published nest-plugins-reference package. "
                "Install from a source checkout of nandatown that includes the trust backend."
            )
        self._identity = identity
        self._anchor = anchor
        self._ledger_path = Path(ledger)
        self._system_seed = hashlib.sha256(b"trust:capsule_emit").digest()[:32]
        self._receipts: list[dict[str, Any]] = []
        self._anchored: dict[tuple[str, str, str], str] = {}
        self._fallback_scores: dict[AgentId, list[float]] = {}
        self._stakes: dict[AgentId, int] = {}

    def _did_of(self, agent: AgentId) -> str:
        seed = hashlib.sha256(str(agent).encode()).digest()[:32]
        pub = (
            Ed25519PrivateKey.from_private_bytes(seed)
            .public_key()
            .public_bytes(Encoding.Raw, PublicFormat.Raw)
        )
        return did_for_pubkey(pub)

    def _receipt_key(self, receipt: dict[str, Any]) -> tuple[str, str, str]:
        issuer = str(receipt.get("issuer_did", ""))
        cp = _counterparty(receipt) or ""
        action_id = str(_action_field(receipt, "action_id") or _action_field(receipt, "category") or "")
        return (issuer, cp, action_id)

    async def report(self, agent: AgentId, evidence: Evidence) -> None:
        """Report evidence; anchor to capsule ledger if it's a valid receipt."""
        try:
            parsed: object = json.loads(evidence.detail)
        except (json.JSONDecodeError, TypeError):
            self._record_fallback(agent, evidence)
            return

        if not isinstance(parsed, dict):
            self._record_fallback(agent, evidence)
            return

        receipt = cast("dict[str, Any]", parsed)
        if not _verify_receipt(receipt):
            self._record_fallback(agent, evidence)
            return

        self._receipts.append(receipt)
        await asyncio.to_thread(self._emit_capsule, agent, receipt)

    def _emit_capsule(self, agent: AgentId, receipt: dict[str, Any]) -> None:
        issuer_did = str(receipt.get("issuer_did", ""))
        category = str(_action_field(receipt, "category") or _DEFAULT_CAPSULE_ACTION)
        cp_did = _counterparty(receipt) or ""
        corroborated = is_corroborated(receipt)

        try:
            result = capsule_emit.emit(
                action=category,
                operator=issuer_did,
                developer=str(agent),
                agent_input=receipt,
                agent_output={"corroborated": corroborated, "counterparty_did": cp_did},
                anchor=self._anchor,
                ledger=str(self._ledger_path),
            )
            self._anchored[self._receipt_key(receipt)] = result.capsule_id
        except Exception:
            logger.exception("capsule emit failed for agent=%s", agent)

    async def score(self, agent: AgentId) -> ReputationScore:
        """Reputation from corroborated, ring-severed, anchored receipts."""
        did = self._did_of(agent)
        effective = _effective_receipts(self._receipts)
        mine_eff = [r for r in effective if str(r.get("issuer_did", "")) == did]
        mine_anchored = [r for r in mine_eff if self._receipt_key(r) in self._anchored]
        mine_all = [r for r in self._receipts if str(r.get("issuer_did", "")) == did]

        if mine_all:
            raw = _raw_reputation(mine_anchored, DEFAULT_CATEGORY_WEIGHTS)
            confidence = len(mine_anchored) / len(mine_all)
            return ReputationScore(
                agent_id=agent,
                score=_normalize(raw),
                confidence=confidence,
                sample_count=len(mine_all),
            )

        fallback = self._fallback_scores.get(agent)
        if fallback:
            avg = sum(fallback) / len(fallback)
            return ReputationScore(
                agent_id=agent,
                score=avg,
                confidence=min(1.0, len(fallback) / 100.0),
                sample_count=len(fallback),
            )
        return ReputationScore(agent_id=agent, score=0.5, confidence=0.0, sample_count=0)

    async def attest(self, agent: AgentId, claim: Claim) -> Attestation:
        """Issue an Ed25519-signed attestation (same as agent_receipts)."""
        from nest_core.types import Signature

        sk = Ed25519PrivateKey.from_private_bytes(self._system_seed)
        raw = sk.sign(claim.model_dump_json().encode())
        sig = Signature(signer=self._SYSTEM_AGENT, value=raw, algorithm=ALGORITHM)
        return Attestation(issuer=self._SYSTEM_AGENT, claim=claim, signature=sig)

    async def stake(self, agent: AgentId, amount: int) -> None:
        self._stakes[agent] = self._stakes.get(agent, 0) + amount

    def _record_fallback(self, agent: AgentId, evidence: Evidence) -> None:
        score_val = 0.5
        if evidence.kind == "positive":
            score_val = 1.0
        elif evidence.kind in ("negative", "byzantine"):
            score_val = 0.0
        self._fallback_scores.setdefault(agent, []).append(score_val)
