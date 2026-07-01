# SPDX-License-Identifier: Apache-2.0
"""Capsule selective-disclosure privacy plugin.

Unlike :mod:`nest_plugins_reference.privacy.hybrid_x25519` — which uses a Merkle
authentication-path construction for selective disclosure — this plugin implements
the **SD-JWT salted-hash commitment model** from the Agent Action Capsule
selective-disclosure profile (``draft-mih-scitt-agent-action-capsule-sel-disc``):

* **Hybrid encryption (HPKE-shaped).** X25519 ephemeral-static ECDH + HKDF-SHA256
  key-agreement, ChaCha20-Poly1305 AEAD per message, one symmetric content-key
  wrap per recipient.  Identical broadcast cost model to the Merkle-path plugin.
* **Selective disclosure — SD-JWT salted-hash model.**  :meth:`commit_credential`
  commits each field as ``digest = BASE64URL(SHA-256(UTF8(JCS([salt, name, value]))))``,
  inserts the digest into a per-object ``_sd`` array, and optionally adds **decoy
  digests** to hide the count of concealed fields.  A holder reveals a subset by
  sharing the ``[salt, name, value]`` triple; a verifier checks
  ``BASE64URL(SHA-256(UTF8(JCS(triple))))`` is present in the ``_sd`` commitment
  set.  No authentication path is required — the commitment is per-field.
* **Broadcast revocation.** :meth:`revoke` advances an epoch and excludes the
  revoked agent from future key-wrap sets without touching any live member's key.

Differences from the Merkle-path approach (``hybrid_x25519``)
--------------------------------------------------------------

``hybrid_x25519`` commits all fields to a single Merkle root and proves individual
fields via their authentication paths (sibling hashes up the tree).  **This plugin
uses per-field salted-hash commitments** — the same construction the AAC sel-disc
I-D (``draft-mih-scitt-agent-action-capsule-sel-disc``) applies to Capsule payloads:

* **No tree traversal.** Verifying a disclosure is one SHA-256 comparison; there
  is no ``_root_from_path`` computation.
* **Decoy digests.** Extra commitment digests with no associated disclosure hide
  the count of concealed fields, providing ``k``-anonymity over field count.
* **Algorithm-agile.**  The ``_sd_alg`` member (``"sha-256"``) permits future
  algorithm upgrades without wire-format changes.
* **Capsule-portable.**  An SD-Capsule produced by the capsule-emit library is
  verifiable by this plugin's :func:`verify_disclosure` helper without modification.

Threat model
------------

1. **Eavesdropper.**  A non-audience agent holds no per-recipient wrap entry and
   cannot recover the content key.  :meth:`decrypt` raises
   :class:`NotInAudienceError`.
2. **Replay.**  Every envelope carries a unique ``msg_id`` bound into the AEAD
   associated data.  :meth:`decrypt` raises :class:`ReplayError` on a second
   presentation of the same ``(sender, msg_id)``.
3. **Field-injection.**  Tampering a disclosed ``[salt, name, value]`` triple
   changes its SHA-256 digest, which no longer appears in the ``_sd`` commitment
   set.  :meth:`verify_proof` returns ``False``.
4. **Stale-revocation.**  A member revoked at epoch ``E`` is excluded from all
   wrap sets at epoch ``>= E``.  :meth:`decrypt` raises :class:`NotInAudienceError`
   for any post-revocation envelope.

Forward-secrecy note: revocation is future-only.  Past envelopes already delivered
to the revoked member remain decryptable from the stored content key.

Deterministic traces (Tier 1)
------------------------------

Constructed with ``deterministic=True``, all ephemeral keys and nonces are derived
via HKDF from the agent's private key and a per-message ``msg_id`` counter.
Salts for :func:`commit_credential` are derived from the ``salt_seed`` argument.
Pass ``salt_seed=None`` for production (system CSPRNG); use a fixed seed only for
Tier-1 test reproducibility.

Example::

    alice = CapsuleSelDiscPrivacy(AgentId("alice"), seed=b"a", deterministic=True)
    bob = CapsuleSelDiscPrivacy(AgentId("bob"), seed=b"b", deterministic=True)
    alice.register_peer(AgentId("bob"), bob.public_key)
    bob.register_peer(AgentId("alice"), alice.public_key)
    ct = await alice.encrypt(b"bid:1700", [AgentId("bob")])
    assert await bob.decrypt(ct) == b"bid:1700"
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from nest_core.types import AgentId, Proof, Statement, Witness

SCHEME = "capsule-sd/1"
"""Wire-format tag stamped into every envelope and bound into the AEAD AAD."""

PROOF_SCHEME = "capsule-sd-v1"
"""Scheme tag on selective-disclosure :class:`~nest_core.types.Proof` objects."""

_KEY_BYTES = 32
_NONCE_BYTES = 12


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PrivacyError(Exception):
    """Base class for capsule-sd plugin failures.

    Example::

        try:
            await priv.decrypt(env)
        except PrivacyError:
            ...
    """


class NotInAudienceError(PrivacyError):
    """Raised when this agent has no wrap entry in the envelope.

    Covers the eavesdropper attack (never in audience) and the
    stale-revocation attack (excluded from this epoch's wrap set).

    Example::

        raise NotInAudienceError("eve not in audience")
    """


class ReplayError(PrivacyError):
    """Raised when an already-seen (sender, msg_id) envelope is re-presented.

    Example::

        raise ReplayError("duplicate alice:0:1")
    """


class MalformedEnvelopeError(PrivacyError):
    """Raised when envelope bytes are not a well-formed SCHEME envelope.

    Example::

        raise MalformedEnvelopeError("missing field 'ct'")
    """


class TamperError(PrivacyError):
    """Raised when AEAD authentication fails (ciphertext or AAD tampered).

    Example::

        raise TamperError("AEAD tag mismatch")
    """


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------


def _b64(raw: bytes) -> str:
    """Standard base64 for embedding raw bytes as ASCII in the JSON envelope."""
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    """Inverse of :func:`_b64`; raises on malformed input."""
    return base64.b64decode(text.encode("ascii"))


def _b64url(raw: bytes) -> str:
    """Base64url encoding without padding (for SD-JWT disclosures and digests).

    Example::

        assert len(_b64url(bytes(16))) == 22
    """
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64url(text: str) -> bytes:
    """Inverse of :func:`_b64url`.

    Example::

        raw = _unb64url(_b64url(b"hello"))
        assert raw == b"hello"
    """
    padding = 4 - len(text) % 4
    if padding < 4:
        text = text + "=" * padding
    return base64.urlsafe_b64decode(text.encode("ascii"))


def _jcs(obj: Any) -> bytes:
    """JSON Canonicalization Scheme (RFC 8785) for strings and arrays of strings.

    For our disclosure arrays ``[salt, name, value]`` all elements are strings;
    JCS output equals ``json.dumps`` with sorted object keys, no extra whitespace,
    and ``ensure_ascii=False``.

    Example::

        assert _jcs(["s", "n", "v"]) == b'["s","n","v"]'
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _commitment(salt_b64url: str, name: str, value: str) -> str:
    """Compute the SD-JWT commitment digest for a ``[salt, name, value]`` triple.

    ``digest = BASE64URL(SHA-256(UTF-8(JCS([salt, name, value]))))``

    Example::

        d = _commitment("rIdm2xVvGT-yKjLWOXXJfg", "operator", "acme-corp")
        assert len(d) == 43  # 32 bytes → 43 base64url chars (no padding)
    """
    disclosure_array = [salt_b64url, name, value]
    return _b64url(hashlib.sha256(_jcs(disclosure_array)).digest())


def _decoy_digest(seed: bytes | None = None) -> str:
    """Generate a commitment digest with no associated disclosure.

    The decoy hides the count of concealed fields by padding the ``_sd`` array.

    Example::

        d = _decoy_digest()
        assert len(d) == 43
    """
    raw = seed if seed is not None else os.urandom(32)
    return _b64url(hashlib.sha256(b"capsule-sd-decoy\x00" + raw).digest())


def _hkdf(ikm: bytes, info: bytes, *, length: int = _KEY_BYTES) -> bytes:
    """HKDF-SHA256 with a fixed empty salt and explicit info separation."""
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(ikm)


def _x25519_private_from_seed(seed: bytes, agent_id: AgentId) -> X25519PrivateKey:
    """Derive a deterministic X25519 private key for *agent_id* from *seed*.

    Example::

        k = _x25519_private_from_seed(b"root", AgentId("a1"))
        assert isinstance(k, X25519PrivateKey)
    """
    material = _hkdf(seed, b"capsule-sd-x25519|" + str(agent_id).encode("utf-8"))
    return X25519PrivateKey.from_private_bytes(material)


def _raw_public(key: X25519PublicKey) -> bytes:
    """Raw 32-byte X25519 public key."""
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _raw_private(key: X25519PrivateKey) -> bytes:
    """Raw 32-byte X25519 private scalar."""
    return key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def _key_id(public_key: bytes) -> str:
    """Short stable identifier for a public key (first 16 hex chars of SHA-256)."""
    return hashlib.sha256(public_key).hexdigest()[:16]


def _canon(obj: dict[str, Any]) -> bytes:
    """Sorted-key, compact JSON bytes for AAD construction."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# Selective-disclosure commitment (SD-JWT model per AAC sel-disc I-D)
# ---------------------------------------------------------------------------


def commit_credential(
    fields: dict[str, str],
    *,
    salt_seed: bytes | None = None,
    decoys: int = 1,
) -> tuple[Statement, dict[str, str]]:
    """Commit a multi-field credential using SD-JWT salted-hash commitments.

    Each field is committed as::

        digest = BASE64URL(SHA-256(UTF-8(JCS([salt_b64url, name, value]))))

    ``decoys`` additional digests (no associated disclosures) are inserted to
    hide the count of concealed fields.  The ``_sd`` array is sorted
    lexicographically before embedding in the :class:`~nest_core.types.Statement`.

    Args:
        fields: Mapping of field name → value (both strings).
        salt_seed: If given, derive salts deterministically (Tier-1 replay);
            otherwise use ``os.urandom(16)`` per field.
        decoys: Number of decoy digests to insert.  Defaults to 1.

    Returns:
        ``(statement, salts)`` where *salts* maps each field name to its
        base64url-encoded 16-byte salt.  Retain *salts* to call
        :func:`build_witness` later.

    Example::

        stmt, salts = commit_credential({"amount": "100", "currency": "USD"})
        witness = build_witness({"amount": "100"}, salts)
        proof = await priv.prove(stmt, witness)
        assert await priv.verify_proof(stmt, proof)
    """
    sd_array: list[str] = []
    salts: dict[str, str] = {}
    for name in sorted(fields):
        value = fields[name]
        if salt_seed is None:
            raw_salt = os.urandom(16)
        else:
            raw_salt = _hkdf(salt_seed, b"capsule-sd-salt|" + name.encode("utf-8"), length=16)
        salt_b64url = _b64url(raw_salt)
        salts[name] = salt_b64url
        sd_array.append(_commitment(salt_b64url, name, value))
    # Decoy digests — one unique decoy per requested count
    for i in range(decoys):
        if salt_seed is None:
            decoy_seed = None
        else:
            decoy_seed = _hkdf(salt_seed, b"capsule-sd-decoy|" + str(i).encode("ascii"))
        sd_array.append(_decoy_digest(decoy_seed))
    # Sort lexicographically (per I-D §4.2)
    sd_array.sort()
    stmt = Statement(
        predicate="capsule_sd",
        public_inputs={
            "_sd_alg": "sha-256",
            "_sd": json.dumps(sd_array, separators=(",", ":")),
        },
    )
    return stmt, salts


def build_witness(reveal: dict[str, str], salts: dict[str, str]) -> Witness:
    """Build a :class:`~nest_core.types.Witness` for :meth:`CapsuleSelDiscPrivacy.prove`.

    Args:
        reveal: ``{field_name: value}`` for every field to disclose.
        salts: The salts returned by :func:`commit_credential`.

    Returns:
        A :class:`~nest_core.types.Witness` whose ``private_inputs`` embeds the
        field values and their salts in the format expected by
        :meth:`CapsuleSelDiscPrivacy.prove`.

    Example::

        stmt, salts = commit_credential({"bid": "500", "bidder": "alice"})
        witness = build_witness({"bid": "500"}, salts)
    """
    private_inputs: dict[str, str] = {}
    reveal_salts: dict[str, str] = {}
    for name, value in reveal.items():
        private_inputs[name] = value
        if name in salts:
            reveal_salts[name] = salts[name]
    private_inputs["__salts__"] = json.dumps(reveal_salts, separators=(",", ":"))
    return Witness(private_inputs=private_inputs)


def verify_disclosure(sd_array: list[str], encoded_disclosure: str) -> bool:
    """Verify one encoded disclosure against an ``_sd`` commitment array.

    Computes ``digest = BASE64URL(SHA-256(UTF-8(JCS(decoded_triple))))`` and
    checks membership in *sd_array*.  Returns ``True`` on a match.

    This is the standalone verifier helper: it is identical to Phase 1 of the
    AAC sel-disc I-D (SD-4: Commitment Verification and Reconstruction).

    Example::

        stmt, salts = commit_credential({"x": "1"}, salt_seed=b"seed")
        salt = salts["x"]
        disc = _b64url(_jcs([salt, "x", "1"]))
        assert verify_disclosure(json.loads(stmt.public_inputs["_sd"]), disc)
    """
    try:
        decoded = _unb64url(encoded_disclosure)
        triple: list[Any] = json.loads(decoded.decode("utf-8"))
    except Exception:
        return False
    if not isinstance(triple, list) or len(triple) not in (2, 3):  # pyright: ignore[reportUnnecessaryIsInstance]
        return False
    computed = _b64url(hashlib.sha256(_jcs(triple)).digest())
    return computed in sd_array


# ---------------------------------------------------------------------------
# Envelope model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Wrap:
    """One per-recipient key-wrap entry inside an envelope."""

    key_id: str
    """SHA-256-prefix identifier of the recipient's public key."""
    wrapped_cek: str
    """Base64-encoded ChaCha20-Poly1305 encryption of the content key."""


@dataclass
class _Envelope:
    """Parsed, validated SCHEME envelope."""

    scheme: str
    msg_id: str
    sender: str
    epoch: int
    eph_pub: bytes
    ct: bytes
    nonce: bytes
    wraps: list[_Wrap]

    @classmethod
    def decode(cls, data: bytes) -> _Envelope:
        """Parse and validate envelope bytes."""
        try:
            obj: dict[str, Any] = json.loads(data.decode("utf-8"))
        except Exception as exc:
            msg = f"not valid JSON: {exc}"
            raise MalformedEnvelopeError(msg) from exc
        missing = {"scheme", "msg_id", "sender", "epoch", "eph_pub", "ct", "nonce", "wraps"} - set(
            obj
        )
        if missing:
            msg = f"missing envelope fields: {sorted(missing)}"
            raise MalformedEnvelopeError(msg)
        if obj["scheme"] != SCHEME:
            msg = f"expected scheme {SCHEME!r}, got {obj['scheme']!r}"
            raise MalformedEnvelopeError(msg)
        wraps = [_Wrap(key_id=w["key_id"], wrapped_cek=w["wrapped_cek"]) for w in obj["wraps"]]
        return cls(
            scheme=obj["scheme"],
            msg_id=obj["msg_id"],
            sender=obj["sender"],
            epoch=int(obj["epoch"]),
            eph_pub=_unb64(obj["eph_pub"]),
            ct=_unb64(obj["ct"]),
            nonce=_unb64(obj["nonce"]),
            wraps=wraps,
        )

    def encode(self) -> bytes:
        """Serialise this envelope to bytes."""
        obj: dict[str, Any] = {
            "scheme": self.scheme,
            "msg_id": self.msg_id,
            "sender": self.sender,
            "epoch": self.epoch,
            "eph_pub": _b64(self.eph_pub),
            "ct": _b64(self.ct),
            "nonce": _b64(self.nonce),
            "wraps": [{"key_id": w.key_id, "wrapped_cek": w.wrapped_cek} for w in self.wraps],
        }
        return json.dumps(obj, separators=(",", ":")).encode("utf-8")

    @property
    def aad(self) -> bytes:
        """AEAD associated data: scheme + msg_id + sender + epoch + recipient key-ids."""
        return _canon(
            {
                "scheme": self.scheme,
                "msg_id": self.msg_id,
                "sender": self.sender,
                "epoch": self.epoch,
                "recipients": sorted(w.key_id for w in self.wraps),
            }
        )


# ---------------------------------------------------------------------------
# Main plugin class
# ---------------------------------------------------------------------------


class CapsuleSelDiscPrivacy:
    """Capsule SD privacy: X25519+ChaCha20-Poly1305 + SD-JWT selective disclosure.

    Implements the :class:`~nest_core.layers.privacy.Privacy` protocol.
    Encryption uses a per-message HPKE-shaped broadcast construction.
    Selective disclosure follows the SD-JWT salted-hash commitment model
    per ``draft-mih-scitt-agent-action-capsule-sel-disc``.

    Args:
        agent_id: This agent's identity.
        seed: Byte seed for deterministic X25519 key derivation.  The same seed
            always produces the same long-term key, so callers can register
            their peer's key without out-of-band exchange.
        deterministic: If ``True``, derive ephemeral keys and nonces via HKDF
            (Tier-1 replay mode).  If ``False`` (default), use system CSPRNG.

    Example::

        alice = CapsuleSelDiscPrivacy(AgentId("alice"), seed=b"a", deterministic=True)
        bob = CapsuleSelDiscPrivacy(AgentId("bob"), seed=b"b", deterministic=True)
        alice.register_peer(AgentId("bob"), bob.public_key)
        bob.register_peer(AgentId("alice"), alice.public_key)
        ct = await alice.encrypt(b"sealed-bid:1700", [AgentId("bob")])
        assert await bob.decrypt(ct) == b"sealed-bid:1700"
    """

    def __init__(
        self,
        agent_id: AgentId,
        seed: bytes = b"",
        *,
        deterministic: bool = False,
    ) -> None:
        self._agent_id = agent_id
        self._deterministic = deterministic
        self._private = _x25519_private_from_seed(seed, agent_id)
        self._public = _raw_public(self._private.public_key())
        self._key_id = _key_id(self._public)
        self._directory: dict[AgentId, bytes] = {agent_id: self._public}
        self._revoked: dict[AgentId, int] = {}
        self._epoch = 0
        self._seq = 0
        self._seen: set[tuple[str, str]] = set()

    # -- public identity -------------------------------------------------------

    @property
    def public_key(self) -> bytes:
        """This agent's raw 32-byte X25519 public key.

        Example::

            pk = priv.public_key
            assert len(pk) == 32
        """
        return self._public

    @property
    def key_id(self) -> str:
        """Short id of this agent's public key (matches envelope wrap entries).

        Example::

            kid = priv.key_id
            assert len(kid) == 16
        """
        return self._key_id

    @property
    def epoch(self) -> int:
        """Current revocation epoch (advances on :meth:`revoke`).

        Example::

            assert priv.epoch == 0
        """
        return self._epoch

    def register_peer(self, agent_id: AgentId, public_key: bytes) -> None:
        """Register a peer's X25519 public key so messages can be wrapped for it.

        Example::

            priv.register_peer(AgentId("bob"), bob_public_key)
        """
        self._directory[agent_id] = public_key

    def revoke(self, agent_id: AgentId) -> int:
        """Revoke *agent_id*: advance the epoch and exclude from future wrap sets.

        Returns the new epoch.  Messages already issued remain decryptable by
        the revoked member (future-only revocation; no backward secrecy).

        Example::

            new_epoch = priv.revoke(AgentId("carol"))
            assert new_epoch == 1
        """
        self._epoch += 1
        self._revoked[agent_id] = self._epoch
        return self._epoch

    def _is_revoked(self, agent_id: AgentId, epoch: int) -> bool:
        revoked_at = self._revoked.get(agent_id)
        return revoked_at is not None and epoch >= revoked_at

    # -- randomness (deterministic or system) ----------------------------------

    def _make_ephemeral(self, msg_id: str) -> X25519PrivateKey:
        if self._deterministic:
            material = _hkdf(
                _raw_private(self._private), b"capsule-sd-eph|" + msg_id.encode("utf-8")
            )
            return X25519PrivateKey.from_private_bytes(material)
        return X25519PrivateKey.generate()

    def _make_nonce(self, msg_id: str, index: int) -> bytes:
        if self._deterministic:
            return _hkdf(
                _raw_private(self._private),
                b"capsule-sd-nonce|" + msg_id.encode("utf-8") + b"|" + str(index).encode("ascii"),
                length=_NONCE_BYTES,
            )
        return os.urandom(_NONCE_BYTES)

    def _make_cek(self, msg_id: str) -> bytes:
        if self._deterministic:
            return _hkdf(_raw_private(self._private), b"capsule-sd-cek|" + msg_id.encode("utf-8"))
        return os.urandom(_KEY_BYTES)

    # -- wrap / unwrap helpers -------------------------------------------------

    def _derive_wrap_key(self, shared: bytes, eph_pub: bytes, recipient_kid: str) -> bytes:
        """HPKE-style per-recipient key-wrap key from ECDH shared secret."""
        info = b"capsule-sd-wrap|" + eph_pub + b"|" + recipient_kid.encode("ascii")
        return _hkdf(shared, info)

    def _wrap_cek(
        self,
        cek: bytes,
        recipient_pub: bytes,
        eph_priv: X25519PrivateKey,
        eph_pub: bytes,
        msg_id: str,
        index: int,
    ) -> tuple[str, str]:
        """ECDH + HKDF key agreement, then wrap the CEK with ChaCha20-Poly1305.

        Returns ``(key_id, wrapped_cek_b64)``.
        """
        shared = eph_priv.exchange(X25519PublicKey.from_public_bytes(recipient_pub))
        wrap_key = self._derive_wrap_key(shared, eph_pub, _key_id(recipient_pub))
        nonce = self._make_nonce(msg_id, index)
        aad = b"capsule-sd-cek-wrap|" + msg_id.encode("utf-8")
        wrapped = ChaCha20Poly1305(wrap_key).encrypt(nonce, cek, aad)
        return _key_id(recipient_pub), _b64(nonce + wrapped)

    def _unwrap_cek(self, wrapped_b64: str, shared: bytes, eph_pub: bytes, msg_id: str) -> bytes:
        """Recover the content key using this agent's wrap entry."""
        raw = _unb64(wrapped_b64)
        nonce = raw[:_NONCE_BYTES]
        ciphertext = raw[_NONCE_BYTES:]
        wrap_key = self._derive_wrap_key(shared, eph_pub, self._key_id)
        aad = b"capsule-sd-cek-wrap|" + msg_id.encode("utf-8")
        try:
            return ChaCha20Poly1305(wrap_key).decrypt(nonce, ciphertext, aad)
        except InvalidTag as exc:
            msg_str = "wrap key mismatch or tampered ciphertext"
            raise TamperError(msg_str) from exc

    # -- Privacy Protocol: encrypt / decrypt ----------------------------------

    async def encrypt(self, data: bytes, audience: list[AgentId]) -> bytes:
        """Encrypt *data* to non-revoked members of *audience*.

        Produces a self-describing envelope: one ChaCha20-Poly1305 encryption
        of the payload plus one X25519+HKDF key-wrap per recipient.  The
        sender, epoch, and recipient key-ids are bound into the AEAD AAD so
        the envelope is tamper-evident and recipient-bound.

        Raises:
            KeyError: If a recipient's public key has not been registered.

        Example::

            ct = await alice.encrypt(b"bid:500", [AgentId("bob")])
            assert len(ct) > 0
        """
        msg_id = f"{self._agent_id}:{self._epoch}:{self._seq}"
        self._seq += 1
        eph_priv = self._make_ephemeral(msg_id)
        eph_pub = _raw_public(eph_priv.public_key())
        cek = self._make_cek(msg_id)
        wraps: list[_Wrap] = []
        for i, recipient in enumerate(audience):
            if self._is_revoked(recipient, self._epoch):
                continue
            recipient_pub = self._directory[recipient]
            kid, wrapped_b64 = self._wrap_cek(cek, recipient_pub, eph_priv, eph_pub, msg_id, i)
            wraps.append(_Wrap(key_id=kid, wrapped_cek=wrapped_b64))
        env = _Envelope(
            scheme=SCHEME,
            msg_id=msg_id,
            sender=str(self._agent_id),
            epoch=self._epoch,
            eph_pub=eph_pub,
            ct=b"",
            nonce=b"",
            wraps=wraps,
        )
        nonce = self._make_nonce(msg_id, len(audience))
        ct = ChaCha20Poly1305(cek).encrypt(nonce, data, env.aad)
        env = _Envelope(
            scheme=env.scheme,
            msg_id=env.msg_id,
            sender=env.sender,
            epoch=env.epoch,
            eph_pub=env.eph_pub,
            ct=ct,
            nonce=nonce,
            wraps=env.wraps,
        )
        return env.encode()

    async def decrypt(self, data: bytes) -> bytes:
        """Decrypt an envelope produced by :meth:`encrypt`.

        Raises:
            NotInAudienceError: If this agent has no wrap entry (eavesdropper
                or stale-revocation attack).
            ReplayError: If this ``(sender, msg_id)`` has already been decrypted.
            TamperError: If the AEAD authentication tag does not verify.
            MalformedEnvelopeError: If the envelope bytes are not well-formed.

        Example::

            pt = await bob.decrypt(ct)
            assert pt == b"bid:500"
        """
        env = _Envelope.decode(data)
        replay_key = (env.sender, env.msg_id)
        if replay_key in self._seen:
            msg = f"duplicate envelope {env.sender}:{env.msg_id}"
            raise ReplayError(msg)
        my_wrap = next((w for w in env.wraps if w.key_id == self._key_id), None)
        if my_wrap is None:
            msg = f"{self._agent_id!r} has no wrap entry in envelope {env.msg_id!r}"
            raise NotInAudienceError(msg)
        eph_pub = env.eph_pub
        shared = self._private.exchange(X25519PublicKey.from_public_bytes(eph_pub))
        cek = self._unwrap_cek(my_wrap.wrapped_cek, shared, eph_pub, env.msg_id)
        try:
            plaintext = ChaCha20Poly1305(cek).decrypt(env.nonce, env.ct, env.aad)
        except InvalidTag as exc:
            msg_str = "AEAD authentication failed — envelope tampered"
            raise TamperError(msg_str) from exc
        self._seen.add(replay_key)
        return plaintext

    # -- Privacy Protocol: selective disclosure --------------------------------

    async def prove(self, statement: Statement, witness: Witness) -> Proof:
        """Generate SD-JWT disclosures for fields named in *witness*.

        ``statement.public_inputs`` must carry ``_sd_alg`` and ``_sd`` (the
        commitment array).  ``witness.private_inputs`` must carry the field
        values to reveal (keyed by name) plus ``__salts__`` (a JSON object
        mapping field names to their base64url salts).

        Each output disclosure is ``BASE64URL(UTF-8(JCS([salt, name, value])))``.
        The returned :class:`~nest_core.types.Proof` embeds the disclosure list
        in ``data`` as ``{"disclosures": [...]}``.

        Raises:
            ValueError: If the witness salts don't match the statement
                commitments, or ``_sd_alg`` is unsupported.

        Example::

            stmt, salts = commit_credential({"bid": "500"}, salt_seed=b"s")
            witness = build_witness({"bid": "500"}, salts)
            proof = await priv.prove(stmt, witness)
            assert await priv.verify_proof(stmt, proof)
        """
        if statement.predicate != "capsule_sd":
            msg = f"expected predicate 'capsule_sd', got {statement.predicate!r}"
            raise ValueError(msg)
        sd_alg = statement.public_inputs.get("_sd_alg", "")
        if sd_alg != "sha-256":
            msg = f"unsupported _sd_alg {sd_alg!r}"
            raise ValueError(msg)
        sd_raw = statement.public_inputs.get("_sd", "[]")
        sd_array: list[str] = json.loads(sd_raw)
        sd_set = set(sd_array)
        # Parse witness
        private = dict(witness.private_inputs)
        salts_json = private.pop("__salts__", "{}")
        salts: dict[str, str] = json.loads(salts_json)
        fields: dict[str, str] = {k: v for k, v in private.items()}
        # Build disclosures and verify against commitments
        disclosures: list[str] = []
        missing_salt: list[str] = []
        for name, value in sorted(fields.items()):
            salt_b64url = salts.get(name)
            if salt_b64url is None:
                missing_salt.append(name)
                continue
            digest = _commitment(salt_b64url, name, value)
            if digest not in sd_set:
                msg = f"witness field {name!r} does not match any commitment in _sd"
                raise ValueError(msg)
            encoded = _b64url(_jcs([salt_b64url, name, value]))
            disclosures.append(encoded)
        if missing_salt:
            msg = f"missing salt(s) in __salts__ for field(s): {', '.join(missing_salt)}"
            raise ValueError(msg)
        payload = json.dumps({"disclosures": disclosures}, separators=(",", ":")).encode("utf-8")
        return Proof(statement=statement, data=payload, scheme=PROOF_SCHEME)

    async def verify_proof(self, statement: Statement, proof: Proof) -> bool:
        """Verify SD-JWT disclosures in *proof* against *statement*'s commitments.

        For each disclosure in ``proof.data["disclosures"]``, this method:

        1. Base64url-decodes the disclosure string.
        2. Parses it as a JSON array ``[salt, name, value]``.
        3. Computes ``digest = BASE64URL(SHA-256(UTF-8(JCS(array))))``.
        4. Checks *digest* is present in the ``_sd`` commitment array.

        Returns ``True`` if and only if *all* disclosures verify and the scheme
        tag matches.  A tampered salt, name, or value shifts the digest and
        yields ``False`` (the field-injection defence).

        Example::

            ok = await priv.verify_proof(stmt, proof)
            assert ok
        """
        if proof.scheme != PROOF_SCHEME:
            return False
        if statement.predicate != "capsule_sd":
            return False
        sd_alg = statement.public_inputs.get("_sd_alg", "")
        if sd_alg != "sha-256":
            return False
        sd_raw = statement.public_inputs.get("_sd", "[]")
        try:
            sd_array: list[str] = json.loads(sd_raw)
        except Exception:
            return False
        try:
            payload: dict[str, Any] = json.loads(proof.data.decode("utf-8"))
            disclosures: list[str] = payload["disclosures"]
        except Exception:
            return False
        if not isinstance(disclosures, list):  # pyright: ignore[reportUnnecessaryIsInstance]
            return False
        consumed: set[str] = set()
        for encoded in disclosures:
            if not verify_disclosure(sd_array, encoded):
                return False
            # Duplicate-disclosure guard (SD-4 step 4 of the I-D)
            if encoded in consumed:
                return False
            consumed.add(encoded)
        return True
