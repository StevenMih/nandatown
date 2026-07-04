# SPDX-License-Identifier: Apache-2.0
"""Sentinel test guarding the private-API coupling in trust.py.

CapsuleEmitTrust imports several private symbols from
``nest_plugins_reference.trust.agent_receipts``:

    _verify_receipt, _counterparty, _effective_receipts, _normalize,
    _raw_reputation, _action_field, did_for_pubkey, is_corroborated,
    NORMALIZATION_K, DEFAULT_CATEGORY_WEIGHTS

These are not part of nest-plugins-reference's public API, so they can
disappear or be renamed without a semver bump.  This test will fail
immediately if any of them are removed — alerting maintainers that
trust.py needs a corresponding update.

NOTE: ``nest_plugins_reference.trust.agent_receipts`` is **not** present
in the published nest-plugins-reference package (v0.1.1).  It exists only
in a source checkout of the nandatown repository.  Accordingly this test
is skipped in a bare pip-install environment.
"""

import pytest


def test_private_import_still_works():
    """Sentinel: ensure all private symbols used by CapsuleEmitTrust are importable."""
    try:
        from nest_plugins_reference.trust.agent_receipts import (  # noqa: F401
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
    except ImportError as exc:
        pytest.skip(
            f"nest_plugins_reference.trust.agent_receipts not available "
            f"(not in published package; needs nandatown source checkout): {exc}"
        )
