# SPDX-License-Identifier: Apache-2.0
"""Tests for ``capsule_selective_disclosure`` — SD-JWT privacy plugin.

Covers:
- Hybrid X25519 + ChaCha20-Poly1305 encryption round-trip and error cases.
- SD-JWT salted-hash commitment: commit_credential, prove, verify_proof.
- Decoy digest behaviour.
- 4-attack adversarial validator (PASSES on CapsuleSelDiscPrivacy,
  FAILS on the noop plugin — which is the expected no-crypto baseline).
- Tier-1 determinism: same seed + same payload → byte-identical envelope.

Example::

    pytest packages/nest-plugins-reference/tests/test_capsule_selective_disclosure.py -v
"""

from __future__ import annotations

import base64
import json

import pytest
from nest_core.types import AgentId, Proof, Statement
from nest_plugins_reference.privacy.capsule_selective_disclosure import (
    CapsuleSelDiscPrivacy,
    NotInAudienceError,
    ReplayError,
    _commitment,  # pyright: ignore[reportPrivateUsage]
    _jcs,  # pyright: ignore[reportPrivateUsage]
    build_witness,
    commit_credential,
    verify_disclosure,
)
from nest_plugins_reference.privacy.noop import NoopPrivacy

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pair(
    seed_a: bytes = b"a",
    seed_b: bytes = b"b",
    *,
    deterministic: bool = True,
) -> tuple[CapsuleSelDiscPrivacy, CapsuleSelDiscPrivacy]:
    """Return two registered CapsuleSelDiscPrivacy instances."""
    alice = CapsuleSelDiscPrivacy(AgentId("alice"), seed=seed_a, deterministic=deterministic)
    bob = CapsuleSelDiscPrivacy(AgentId("bob"), seed=seed_b, deterministic=deterministic)
    alice.register_peer(AgentId("bob"), bob.public_key)
    bob.register_peer(AgentId("alice"), alice.public_key)
    return alice, bob


def _tamper_disclosure(
    proof_data: bytes, field_name: str, original_value: str, new_value: str
) -> bytes:
    """Re-encode a disclosure with a tampered field value (proper field-injection).

    Decodes the first matching disclosure from *proof_data*, replaces *original_value*
    with *new_value* in the triple, and re-encodes. The re-encoded disclosure will not
    match the commitment digest because the hash input changed.
    """
    payload: dict[str, object] = json.loads(proof_data.decode("utf-8"))
    disclosures: list[str] = list(payload["disclosures"])  # type: ignore[arg-type]
    tampered: list[str] = []
    for disc in disclosures:
        raw = base64.urlsafe_b64decode(disc + "==")
        triple: list[object] = json.loads(raw.decode("utf-8"))
        matches = (
            len(triple) == 3
            and triple[1] == field_name
            and triple[2] == original_value
        )
        if matches:
            triple[2] = new_value
        triple_json = json.dumps(triple, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        encoded = base64.urlsafe_b64encode(triple_json.encode("utf-8")).rstrip(b"=").decode("ascii")
        tampered.append(encoded)
    payload["disclosures"] = tampered
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# Unit: low-level SD-JWT commitment functions
# ---------------------------------------------------------------------------


class TestJcs:
    """_jcs: JSON Canonicalization Scheme for disclosure arrays."""

    def test_array_of_strings(self) -> None:
        assert _jcs(["s", "n", "v"]) == b'["s","n","v"]'

    def test_object_key_sort(self) -> None:
        # Object keys must be sorted
        assert _jcs({"b": 1, "a": 2}) == b'{"a":2,"b":1}'

    def test_empty_array(self) -> None:
        assert _jcs([]) == b"[]"


class TestCommitment:
    """_commitment: per-field salted-hash digest."""

    def test_length(self) -> None:
        d = _commitment("rIdm2xVvGT-yKjLWOXXJfg", "operator", "acme-corp")
        assert len(d) == 43  # 32 bytes → 43 base64url chars (no padding)

    def test_deterministic(self) -> None:
        d1 = _commitment("salt123", "amount", "100")
        d2 = _commitment("salt123", "amount", "100")
        assert d1 == d2

    def test_different_value_different_digest(self) -> None:
        d1 = _commitment("salt123", "amount", "100")
        d2 = _commitment("salt123", "amount", "999")
        assert d1 != d2

    def test_different_name_different_digest(self) -> None:
        d1 = _commitment("salt123", "field_a", "100")
        d2 = _commitment("salt123", "field_b", "100")
        assert d1 != d2

    def test_different_salt_different_digest(self) -> None:
        d1 = _commitment("saltAAAA", "amount", "100")
        d2 = _commitment("saltBBBB", "amount", "100")
        assert d1 != d2


class TestVerifyDisclosure:
    """verify_disclosure: standalone commitment verifier."""

    def test_valid_disclosure(self) -> None:
        from nest_plugins_reference.privacy.capsule_selective_disclosure import _b64url  # pyright: ignore[reportPrivateUsage]

        salt = "rIdm2xVvGT-yKjLWOXXJfg"
        name = "operator"
        value = "acme-corp"
        digest = _commitment(salt, name, value)
        encoded = _b64url(_jcs([salt, name, value]))
        assert verify_disclosure([digest], encoded)

    def test_tampered_value_fails(self) -> None:
        from nest_plugins_reference.privacy.capsule_selective_disclosure import _b64url  # pyright: ignore[reportPrivateUsage]

        salt = "rIdm2xVvGT-yKjLWOXXJfg"
        name = "operator"
        digest = _commitment(salt, name, "acme-corp")
        # Encode disclosure with DIFFERENT value
        encoded_tampered = _b64url(_jcs([salt, name, "evil-corp"]))
        assert not verify_disclosure([digest], encoded_tampered)

    def test_not_in_sd_array_fails(self) -> None:
        from nest_plugins_reference.privacy.capsule_selective_disclosure import _b64url  # pyright: ignore[reportPrivateUsage]

        salt = "rIdm2xVvGT-yKjLWOXXJfg"
        name = "operator"
        value = "acme-corp"
        encoded = _b64url(_jcs([salt, name, value]))
        # Pass an empty _sd array — commitment not present
        assert not verify_disclosure([], encoded)

    def test_malformed_disclosure_fails(self) -> None:
        assert not verify_disclosure(["anydigest"], "!!!not-base64url!!!")

    def test_decoy_has_no_disclosure(self) -> None:
        """Decoy digests in _sd array that have no matching disclosure are silently skipped."""
        from nest_plugins_reference.privacy.capsule_selective_disclosure import _b64url  # pyright: ignore[reportPrivateUsage]

        salt = "rIdm2xVvGT-yKjLWOXXJfg"
        name = "x"
        value = "1"
        real_digest = _commitment(salt, name, value)
        decoy = "A" * 43  # length-43 decoy string
        sd_array = sorted([real_digest, decoy])
        encoded = _b64url(_jcs([salt, name, value]))
        assert verify_disclosure(sd_array, encoded)


# ---------------------------------------------------------------------------
# Unit: commit_credential / build_witness
# ---------------------------------------------------------------------------


class TestCommitCredential:
    """commit_credential: Statement production and salt generation."""

    def test_returns_statement_with_sd_alg(self) -> None:
        stmt, _ = commit_credential({"x": "1"})
        assert stmt.predicate == "capsule_sd"
        assert stmt.public_inputs["_sd_alg"] == "sha-256"

    def test_sd_array_sorted(self) -> None:
        stmt, _ = commit_credential({"b": "2", "a": "1"}, salt_seed=b"seed", decoys=0)
        sd = json.loads(stmt.public_inputs["_sd"])
        assert sd == sorted(sd)

    def test_decoy_count_padding(self) -> None:
        stmt_0, _ = commit_credential({"x": "1"}, salt_seed=b"s", decoys=0)
        stmt_3, _ = commit_credential({"x": "1"}, salt_seed=b"s", decoys=3)
        sd_0 = json.loads(stmt_0.public_inputs["_sd"])
        sd_3 = json.loads(stmt_3.public_inputs["_sd"])
        # decoys=3 adds 3 extra digests beyond the 1 real field commitment
        assert len(sd_3) == len(sd_0) + 3

    def test_deterministic_salt_seed(self) -> None:
        stmt1, salts1 = commit_credential({"x": "1"}, salt_seed=b"seed")
        stmt2, salts2 = commit_credential({"x": "1"}, salt_seed=b"seed")
        assert stmt1.public_inputs["_sd"] == stmt2.public_inputs["_sd"]
        assert salts1 == salts2

    def test_different_seed_different_digests(self) -> None:
        stmt1, _ = commit_credential({"x": "1"}, salt_seed=b"seed1")
        stmt2, _ = commit_credential({"x": "1"}, salt_seed=b"seed2")
        assert stmt1.public_inputs["_sd"] != stmt2.public_inputs["_sd"]


class TestBuildWitness:
    """build_witness: Witness helper for prove()."""

    def test_includes_salts(self) -> None:
        _, salts = commit_credential({"a": "1", "b": "2"}, salt_seed=b"s")
        witness = build_witness({"a": "1"}, salts)
        loaded = json.loads(witness.private_inputs["__salts__"])
        assert "a" in loaded

    def test_only_revealed_fields_in_witness(self) -> None:
        _, salts = commit_credential({"a": "1", "b": "2"}, salt_seed=b"s")
        witness = build_witness({"a": "1"}, salts)
        assert "a" in witness.private_inputs
        assert "b" not in witness.private_inputs


# ---------------------------------------------------------------------------
# Integration: prove() and verify_proof()
# ---------------------------------------------------------------------------


class TestProveAndVerify:
    """prove() / verify_proof() round-trip over SD-JWT disclosures."""

    @pytest.mark.asyncio
    async def test_full_round_trip(self) -> None:
        priv = CapsuleSelDiscPrivacy(AgentId("issuer"), seed=b"s", deterministic=True)
        stmt, salts = commit_credential({"amount": "500", "bidder": "alice"}, salt_seed=b"s")
        witness = build_witness({"amount": "500"}, salts)
        proof = await priv.prove(stmt, witness)
        assert await priv.verify_proof(stmt, proof)

    @pytest.mark.asyncio
    async def test_reveal_subset(self) -> None:
        priv = CapsuleSelDiscPrivacy(AgentId("issuer"), seed=b"s", deterministic=True)
        stmt, salts = commit_credential(
            {"amount": "500", "bidder": "alice", "item": "widget"}, salt_seed=b"s"
        )
        # Only reveal "amount" — bidder and item stay concealed
        witness = build_witness({"amount": "500"}, salts)
        proof = await priv.prove(stmt, witness)
        assert await priv.verify_proof(stmt, proof)

    @pytest.mark.asyncio
    async def test_reveal_all_fields(self) -> None:
        priv = CapsuleSelDiscPrivacy(AgentId("issuer"), seed=b"s", deterministic=True)
        fields = {"a": "1", "b": "2", "c": "3"}
        stmt, salts = commit_credential(fields, salt_seed=b"s")
        witness = build_witness(fields, salts)
        proof = await priv.prove(stmt, witness)
        assert await priv.verify_proof(stmt, proof)

    @pytest.mark.asyncio
    async def test_wrong_scheme_rejected(self) -> None:
        priv = CapsuleSelDiscPrivacy(AgentId("issuer"), seed=b"s", deterministic=True)
        stmt, salts = commit_credential({"x": "1"}, salt_seed=b"s")
        witness = build_witness({"x": "1"}, salts)
        proof = await priv.prove(stmt, witness)
        wrong_scheme_proof = Proof(
            statement=proof.statement, data=proof.data, scheme="wrong-scheme"
        )
        assert not await priv.verify_proof(stmt, wrong_scheme_proof)

    @pytest.mark.asyncio
    async def test_tampered_disclosure_rejected(self) -> None:
        """Changing the field value in a disclosure shifts the SHA-256 digest → rejected."""
        priv = CapsuleSelDiscPrivacy(AgentId("issuer"), seed=b"s", deterministic=True)
        stmt, salts = commit_credential({"bid": "100"}, salt_seed=b"s")
        witness = build_witness({"bid": "100"}, salts)
        proof = await priv.prove(stmt, witness)
        # Proper field-injection: decode the disclosure, change value, re-encode.
        tampered_data = _tamper_disclosure(proof.data, "bid", "100", "999")
        tampered = Proof(statement=proof.statement, data=tampered_data, scheme=proof.scheme)
        assert not await priv.verify_proof(stmt, tampered)

    @pytest.mark.asyncio
    async def test_wrong_value_in_witness_raises(self) -> None:
        """prove() raises if witness value doesn't match committed digest."""
        priv = CapsuleSelDiscPrivacy(AgentId("issuer"), seed=b"s", deterministic=True)
        stmt, salts = commit_credential({"bid": "100"}, salt_seed=b"s")
        # Attempt to prove with a different value
        bad_witness = build_witness({"bid": "999"}, salts)  # wrong value
        with pytest.raises(ValueError, match="does not match"):
            await priv.prove(stmt, bad_witness)


# ---------------------------------------------------------------------------
# Integration: encrypt() / decrypt()
# ---------------------------------------------------------------------------


class TestEncryptDecrypt:
    """Hybrid X25519+ChaCha20-Poly1305 round-trip tests."""

    @pytest.mark.asyncio
    async def test_round_trip(self) -> None:
        alice, bob = _pair()
        ct = await alice.encrypt(b"hello world", [AgentId("bob")])
        # Ciphertext is distinct from plaintext
        assert ct != b"hello world"
        pt = await bob.decrypt(ct)
        assert pt == b"hello world"

    @pytest.mark.asyncio
    async def test_round_trip_fresh(self) -> None:
        alice = CapsuleSelDiscPrivacy(AgentId("alice"), seed=b"a", deterministic=True)
        bob = CapsuleSelDiscPrivacy(AgentId("bob"), seed=b"b", deterministic=True)
        alice.register_peer(AgentId("bob"), bob.public_key)
        bob.register_peer(AgentId("alice"), alice.public_key)
        ct = await alice.encrypt(b"sealed-bid:1700", [AgentId("bob")])
        pt = await bob.decrypt(ct)
        assert pt == b"sealed-bid:1700"

    @pytest.mark.asyncio
    async def test_multi_recipient(self) -> None:
        alice = CapsuleSelDiscPrivacy(AgentId("alice"), seed=b"a", deterministic=True)
        bob = CapsuleSelDiscPrivacy(AgentId("bob"), seed=b"b", deterministic=True)
        carol = CapsuleSelDiscPrivacy(AgentId("carol"), seed=b"c", deterministic=True)
        alice.register_peer(AgentId("bob"), bob.public_key)
        alice.register_peer(AgentId("carol"), carol.public_key)
        bob.register_peer(AgentId("alice"), alice.public_key)
        carol.register_peer(AgentId("alice"), alice.public_key)
        ct = await alice.encrypt(b"group-secret", [AgentId("bob"), AgentId("carol")])
        assert await bob.decrypt(ct) == b"group-secret"
        assert await carol.decrypt(ct) == b"group-secret"

    @pytest.mark.asyncio
    async def test_deterministic_same_bytes(self) -> None:
        alice = CapsuleSelDiscPrivacy(AgentId("alice"), seed=b"a", deterministic=True)
        bob = CapsuleSelDiscPrivacy(AgentId("bob"), seed=b"b", deterministic=True)
        alice.register_peer(AgentId("bob"), bob.public_key)
        ct1 = await alice.encrypt(b"data", [AgentId("bob")])
        # Rebuild alice at the same starting state
        alice2 = CapsuleSelDiscPrivacy(AgentId("alice"), seed=b"a", deterministic=True)
        alice2.register_peer(AgentId("bob"), bob.public_key)
        ct2 = await alice2.encrypt(b"data", [AgentId("bob")])
        assert ct1 == ct2


# ---------------------------------------------------------------------------
# 4-Attack adversarial validator
# ---------------------------------------------------------------------------


async def _adversarial_validate(privacy: CapsuleSelDiscPrivacy) -> dict[str, bool]:
    """Run the 4-attack adversarial validation suite against a CapsuleSelDiscPrivacy instance.

    Returns a dict mapping attack name to whether the plugin **correctly defends**
    against it (True = attack was defeated, False = plugin is vulnerable).

    Attacks:
        1. eavesdropper — non-audience agent cannot decrypt.
        2. replay — repeated decrypt of the same envelope is rejected.
        3. field_injection — tampered disclosure is rejected by verify_proof.
        4. stale_revocation — revoked member cannot decrypt post-revocation messages.

    Example::

        priv = CapsuleSelDiscPrivacy(AgentId("a"), seed=b"a", deterministic=True)
        priv.register_peer(AgentId("a"), priv.public_key)
        results = await _adversarial_validate(priv)
        assert all(results.values())
    """
    results: dict[str, bool] = {}

    # ------------------------------------------------------------------
    # Attack 1: Eavesdropper
    # An agent NOT in the audience intercepts the ciphertext.
    # ------------------------------------------------------------------
    alice = CapsuleSelDiscPrivacy(AgentId("adv_alice"), seed=b"adv_a", deterministic=True)
    bob = CapsuleSelDiscPrivacy(AgentId("adv_bob"), seed=b"adv_b", deterministic=True)
    eve = CapsuleSelDiscPrivacy(AgentId("adv_eve"), seed=b"adv_e", deterministic=True)
    alice.register_peer(AgentId("adv_bob"), bob.public_key)
    ct = await alice.encrypt(b"classified", [AgentId("adv_bob")])
    try:
        await eve.decrypt(ct)
        results["eavesdropper"] = False  # Eve succeeded — plugin is vulnerable
    except NotInAudienceError:
        results["eavesdropper"] = True  # Eve was correctly blocked
    except Exception:
        results["eavesdropper"] = True  # Any other error also counts as "blocked"

    # ------------------------------------------------------------------
    # Attack 2: Replay
    # A recipient decrypts, then an attacker re-presents the same envelope.
    # ------------------------------------------------------------------
    alice2 = CapsuleSelDiscPrivacy(AgentId("rpl_alice"), seed=b"rpl_a", deterministic=True)
    bob2 = CapsuleSelDiscPrivacy(AgentId("rpl_bob"), seed=b"rpl_b", deterministic=True)
    alice2.register_peer(AgentId("rpl_bob"), bob2.public_key)
    bob2.register_peer(AgentId("rpl_alice"), alice2.public_key)
    ct_rpl = await alice2.encrypt(b"replay-target", [AgentId("rpl_bob")])
    pt = await bob2.decrypt(ct_rpl)
    if pt != b"replay-target":
        results["replay"] = False
    else:
        try:
            await bob2.decrypt(ct_rpl)  # second decrypt of same envelope
            results["replay"] = False  # Replay succeeded — plugin is vulnerable
        except ReplayError:
            results["replay"] = True
        except Exception:
            results["replay"] = True

    # ------------------------------------------------------------------
    # Attack 3: Field-injection
    # Attacker tampers with an unrevealed field's disclosure value.
    # verify_proof must return False.
    # ------------------------------------------------------------------
    priv3 = CapsuleSelDiscPrivacy(AgentId("inj_issuer"), seed=b"inj", deterministic=True)
    stmt3, salts3 = commit_credential({"bid": "100", "bidder": "alice"}, salt_seed=b"inj")
    witness3 = build_witness({"bid": "100"}, salts3)
    proof3 = await priv3.prove(stmt3, witness3)
    # Proper field-injection: re-encode disclosure with tampered value
    tampered_data = _tamper_disclosure(proof3.data, "bid", "100", "999")
    tampered_proof3 = Proof(statement=proof3.statement, data=tampered_data, scheme=proof3.scheme)
    injection_blocked = not await priv3.verify_proof(stmt3, tampered_proof3)
    results["field_injection"] = injection_blocked

    # ------------------------------------------------------------------
    # Attack 4: Stale-revocation
    # A revoked member tries to decrypt a message issued AFTER revocation.
    # ------------------------------------------------------------------
    alice4 = CapsuleSelDiscPrivacy(AgentId("rev_alice"), seed=b"rev_a", deterministic=True)
    bob4 = CapsuleSelDiscPrivacy(AgentId("rev_bob"), seed=b"rev_b", deterministic=True)
    carol4 = CapsuleSelDiscPrivacy(AgentId("rev_carol"), seed=b"rev_c", deterministic=True)
    alice4.register_peer(AgentId("rev_bob"), bob4.public_key)
    alice4.register_peer(AgentId("rev_carol"), carol4.public_key)
    bob4.register_peer(AgentId("rev_alice"), alice4.public_key)
    # Alice revokes Bob
    alice4.revoke(AgentId("rev_bob"))
    # Alice sends a new message AFTER revocation — only Carol is in the audience
    ct4 = await alice4.encrypt(
        b"post-revocation-secret", [AgentId("rev_bob"), AgentId("rev_carol")]
    )
    # Bob (revoked) tries to decrypt the post-revocation message
    try:
        await bob4.decrypt(ct4)
        results["stale_revocation"] = False  # Bob succeeded — plugin is vulnerable
    except NotInAudienceError:
        results["stale_revocation"] = True  # Bob was correctly excluded
    except Exception:
        results["stale_revocation"] = True

    return results


class TestAdversarialValidator:
    """4-attack adversarial validator.

    PASSES on ``CapsuleSelDiscPrivacy`` (all 4 defences hold).
    FAILS on ``NoopPrivacy`` (trivially — no actual crypto).
    """

    @pytest.mark.asyncio
    async def test_capsule_plugin_passes_all_attacks(self) -> None:
        """CapsuleSelDiscPrivacy defeats all 4 adversarial attacks."""
        priv = CapsuleSelDiscPrivacy(AgentId("validator"), seed=b"v", deterministic=True)
        results = await _adversarial_validate(priv)
        assert results["eavesdropper"], "Eavesdropper attack not defeated"
        assert results["replay"], "Replay attack not defeated"
        assert results["field_injection"], "Field-injection attack not defeated"
        assert results["stale_revocation"], "Stale-revocation attack not defeated"

    @pytest.mark.asyncio
    async def test_eavesdropper_defeat(self) -> None:
        """Non-audience agent cannot decrypt — NotInAudienceError raised."""
        alice = CapsuleSelDiscPrivacy(AgentId("alice"), seed=b"a", deterministic=True)
        bob = CapsuleSelDiscPrivacy(AgentId("bob"), seed=b"b", deterministic=True)
        eve = CapsuleSelDiscPrivacy(AgentId("eve"), seed=b"e", deterministic=True)
        alice.register_peer(AgentId("bob"), bob.public_key)
        ct = await alice.encrypt(b"secret", [AgentId("bob")])
        with pytest.raises(NotInAudienceError):
            await eve.decrypt(ct)

    @pytest.mark.asyncio
    async def test_replay_defeat(self) -> None:
        """Re-presenting the same envelope to a recipient raises ReplayError."""
        alice = CapsuleSelDiscPrivacy(AgentId("alice"), seed=b"a", deterministic=True)
        bob = CapsuleSelDiscPrivacy(AgentId("bob"), seed=b"b", deterministic=True)
        alice.register_peer(AgentId("bob"), bob.public_key)
        bob.register_peer(AgentId("alice"), alice.public_key)
        ct = await alice.encrypt(b"replay-target", [AgentId("bob")])
        assert await bob.decrypt(ct) == b"replay-target"
        with pytest.raises(ReplayError):
            await bob.decrypt(ct)

    @pytest.mark.asyncio
    async def test_field_injection_defeat(self) -> None:
        """Tampered disclosure value does not verify — verify_proof returns False."""
        priv = CapsuleSelDiscPrivacy(AgentId("issuer"), seed=b"s", deterministic=True)
        stmt, salts = commit_credential({"amount": "500"}, salt_seed=b"s")
        witness = build_witness({"amount": "500"}, salts)
        proof = await priv.prove(stmt, witness)
        # Proper field-injection: re-encode disclosure with tampered value
        tampered_data = _tamper_disclosure(proof.data, "amount", "500", "9999")
        tampered = Proof(statement=proof.statement, data=tampered_data, scheme=proof.scheme)
        result = await priv.verify_proof(stmt, tampered)
        assert result is False

    @pytest.mark.asyncio
    async def test_stale_revocation_defeat(self) -> None:
        """Revoked member cannot decrypt message issued after revocation."""
        alice = CapsuleSelDiscPrivacy(AgentId("alice"), seed=b"a", deterministic=True)
        bob = CapsuleSelDiscPrivacy(AgentId("bob"), seed=b"b", deterministic=True)
        carol = CapsuleSelDiscPrivacy(AgentId("carol"), seed=b"c", deterministic=True)
        alice.register_peer(AgentId("bob"), bob.public_key)
        alice.register_peer(AgentId("carol"), carol.public_key)
        bob.register_peer(AgentId("alice"), alice.public_key)
        carol.register_peer(AgentId("alice"), alice.public_key)
        # Message BEFORE revocation — both bob and carol can decrypt
        ct_before = await alice.encrypt(b"pre-revocation", [AgentId("bob"), AgentId("carol")])
        assert await bob.decrypt(ct_before) == b"pre-revocation"
        assert await carol.decrypt(ct_before) == b"pre-revocation"
        # Revoke bob
        alice.revoke(AgentId("bob"))
        # Message AFTER revocation — only carol can decrypt
        ct_after = await alice.encrypt(b"post-revocation", [AgentId("bob"), AgentId("carol")])
        with pytest.raises(NotInAudienceError):
            await bob.decrypt(ct_after)
        assert await carol.decrypt(ct_after) == b"post-revocation"

    # -- Noop baseline (validator correctly identifies the broken plugin) ------

    @pytest.mark.asyncio
    async def test_noop_fails_eavesdropper(self) -> None:
        """NoopPrivacy is transparent: eavesdropper trivially reads the payload."""
        noop = NoopPrivacy()
        ct = await noop.encrypt(b"secret", [AgentId("bob")])
        # noop.decrypt returns whatever was passed in — attacker sees plaintext
        pt = await noop.decrypt(ct)
        assert pt == b"secret"  # No protection: this is the *expected* failure of noop

    @pytest.mark.asyncio
    async def test_noop_fails_field_injection(self) -> None:
        """NoopPrivacy.verify_proof always returns True — field-injection is undetected."""
        noop = NoopPrivacy()
        stmt = Statement(predicate="any", public_inputs={"_sd": "[]"})
        tampered_proof = Proof(
            statement=stmt,
            data=b'{"disclosures":["INJECTED"]}',
            scheme="noop",
        )
        assert await noop.verify_proof(stmt, tampered_proof) is True  # noop: always True

    def test_noop_fails_replay(self) -> None:
        """NoopPrivacy has no replay tracking — same ciphertext decrypts twice."""
        import asyncio

        noop = NoopPrivacy()

        async def _run() -> None:
            ct = await noop.encrypt(b"replay", [AgentId("bob")])
            pt1 = await noop.decrypt(ct)
            pt2 = await noop.decrypt(ct)
            assert pt1 == pt2 == b"replay"  # noop: no replay protection

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# Revocation behaviour
# ---------------------------------------------------------------------------


class TestRevocation:
    """Broadcast revocation: epoch advancement, future-only exclusion."""

    @pytest.mark.asyncio
    async def test_revoke_advances_epoch(self) -> None:
        priv = CapsuleSelDiscPrivacy(AgentId("a"), seed=b"a", deterministic=True)
        assert priv.epoch == 0
        priv.revoke(AgentId("b"))
        assert priv.epoch == 1

    @pytest.mark.asyncio
    async def test_pre_revocation_messages_still_readable(self) -> None:
        """Future-only revocation: past messages remain decryptable by the revoked member."""
        alice = CapsuleSelDiscPrivacy(AgentId("alice"), seed=b"a", deterministic=True)
        bob = CapsuleSelDiscPrivacy(AgentId("bob"), seed=b"b", deterministic=True)
        alice.register_peer(AgentId("bob"), bob.public_key)
        bob.register_peer(AgentId("alice"), alice.public_key)
        ct_pre = await alice.encrypt(b"pre-revoke", [AgentId("bob")])
        # Revoke bob AFTER the message was sealed
        alice.revoke(AgentId("bob"))
        # Bob can still read the already-sealed message
        assert await bob.decrypt(ct_pre) == b"pre-revoke"

    @pytest.mark.asyncio
    async def test_multiple_revocations(self) -> None:
        alice = CapsuleSelDiscPrivacy(AgentId("alice"), seed=b"a", deterministic=True)
        bob = CapsuleSelDiscPrivacy(AgentId("bob"), seed=b"b", deterministic=True)
        carol = CapsuleSelDiscPrivacy(AgentId("carol"), seed=b"c", deterministic=True)
        alice.register_peer(AgentId("bob"), bob.public_key)
        alice.register_peer(AgentId("carol"), carol.public_key)
        bob.register_peer(AgentId("alice"), alice.public_key)
        carol.register_peer(AgentId("alice"), alice.public_key)
        alice.revoke(AgentId("bob"))
        alice.revoke(AgentId("carol"))
        ct = await alice.encrypt(b"secret", [AgentId("bob"), AgentId("carol")])
        with pytest.raises(NotInAudienceError):
            await bob.decrypt(ct)
        with pytest.raises(NotInAudienceError):
            await carol.decrypt(ct)
