# SPDX-License-Identifier: Apache-2.0
"""Smoke tests: instantiate both plugins and exercise one happy path each.

CapsuleEmitTrust depends on nest_plugins_reference.trust.agent_receipts which
is not shipped in the published nest-plugins-reference package (v0.1.1); it
lives only in a nandatown source checkout.  The trust test therefore skips
gracefully in a bare pip-install environment while the payments test always
runs.
"""

import os

import pytest

from nest_core.types import AgentId, Evidence

from capsule_emit_nanda.trust import CapsuleEmitTrust
from capsule_emit_nanda.payments import StripeCapsuledPayments


@pytest.fixture(autouse=True)
def no_real_stripe(monkeypatch):
    """Ensure sandbox mode regardless of the host environment."""
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)


@pytest.mark.asyncio
async def test_trust_report_and_score(tmp_path):
    try:
        plugin = CapsuleEmitTrust(ledger=tmp_path / "ledger.jsonl")
    except ImportError as exc:
        pytest.skip(f"trust backend not available: {exc}")

    agent = AgentId("agent-a")
    reporter = AgentId("agent-b")

    # Plain-string evidence triggers the fallback reputation path.
    ev = Evidence(reporter=reporter, subject=agent, kind="positive", detail="good work")
    await plugin.report(agent, ev)

    score = await plugin.score(agent)
    assert score.agent_id == agent
    assert 0.0 <= score.score <= 1.0


@pytest.mark.asyncio
async def test_sandbox_pay(tmp_path):
    plugin = StripeCapsuledPayments(ledger=str(tmp_path / "ledger.jsonl"))
    payer = AgentId("payer-1")
    payee = AgentId("payee-1")

    result = await plugin.pay(payer, payee, 19.99)
    assert result["status"] == "succeeded"
    assert result["payment_intent_id"].startswith("pi_sandbox_")
    assert result["amount_received"] == pytest.approx(19.99)
