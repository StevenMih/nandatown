# SPDX-License-Identifier: Apache-2.0
"""capsule-emit-nanda — verifiable, anchored records for NANDA agents.

Two plugins:

- ``CapsuleEmitTrust`` (``trust: capsule_emit``) — anchored trust layer that
  seals every corroborated receipt into an Agent Action Capsule ledger. Third-party
  verifiable via ``agent-action-capsule verify --store``.

- ``StripeCapsuledPayments`` (``payments: stripe_capsule``) — standalone demo:
  Stripe (or sandbox) payments sealed into a capsule. Not a conforming NANDA
  Payments protocol implementation; see module docstring for caveats. Sandbox
  by default (set ``STRIPE_SECRET_KEY`` for real payments).
"""
from capsule_emit_nanda.trust import CapsuleEmitTrust
from capsule_emit_nanda.payments import StripeCapsuledPayments

__all__ = ["CapsuleEmitTrust", "StripeCapsuledPayments"]
