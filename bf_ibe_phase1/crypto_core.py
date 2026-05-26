"""Educational BasicIdent and FullIdent implementation for local demos.

This module follows the algebraic shape of the Boneh-Franklin paper, but it is
not a production pairing implementation. Group elements are represented by
exponents in a prime-order toy group so the demo can run without native crypto
dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import secrets

from bf_ibe_phase1.encoding import b64decode, b64encode, int_from_b64, int_to_b64
from bf_ibe_phase1.models import PrivateKey, PublicParameters, RecipientCiphertext


DEMO_Q = 2**127 - 1
DEFAULT_MESSAGE_SIZE_BYTES = 32


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def _hash_bytes(label: bytes, *parts: bytes, length: int = DEFAULT_MESSAGE_SIZE_BYTES) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        digest = hashlib.sha256(label + counter.to_bytes(4, "big") + b"".join(parts)).digest()
        output.extend(digest)
        counter += 1
    return bytes(output[:length])


def _scalar_hash(label: bytes, *parts: bytes, q: int = DEMO_Q) -> int:
    digest = hashlib.sha256(label + b"".join(parts)).digest()
    return int.from_bytes(digest, "big") % (q - 1) + 1


def _int_bytes(value: int) -> bytes:
    return value.to_bytes(32, "big")


@dataclass(frozen=True)
class ToyBFIBE:
    q: int
    master_secret: int
    message_size_bytes: int = DEFAULT_MESSAGE_SIZE_BYTES

    @classmethod
    def setup_demo(cls) -> ToyBFIBE:
        return cls(q=DEMO_Q, master_secret=secrets.randbelow(DEMO_Q - 1) + 1)

    @property
    def public_parameters(self) -> PublicParameters:
        return PublicParameters(
            scheme="BF-IBE-DIRECT-TOY",
            curve="toy-prime-order-exponent-group",
            pairing="e(aP,bP)=g_T^(ab)",
            generator_g1_b64=int_to_b64(1),
            public_point_b64=int_to_b64(self.master_secret),
            hash_to_point="SHA256-to-scalar-demo",
            hash_h2="SHA256-mask-demo",
            hash_h3="SHA256-to-Zq-demo",
            hash_h4="SHA256-mask-demo",
            message_size_bits=self.message_size_bytes * 8,
            version="toy-demo-v1",
        )

    def identity_point(self, identity: str) -> int:
        return _scalar_hash(b"H1", identity.encode("utf-8"), q=self.q)

    def extract_private_key(self, identity: str, recipient_email: str) -> PrivateKey:
        q_id = self.identity_point(identity)
        private_scalar = (self.master_secret * q_id) % self.q
        hour = identity.split("||", 1)[1]
        issued_at = datetime.now(timezone.utc)
        return PrivateKey(
            time_bound_id=identity,
            recipient_email=recipient_email,
            valid_hour=hour,
            private_key_b64=int_to_b64(private_scalar),
            issued_at=issued_at,
            expires_at=issued_at + timedelta(hours=1),
            public_parameters_version=self.public_parameters.version,
        )

    def encrypt_block(
        self,
        identity: str,
        message: bytes,
        scheme_mode: str,
        chunk_index: int,
    ) -> RecipientCiphertext:
        if len(message) != self.message_size_bytes:
            message = message.ljust(self.message_size_bytes, b"\0")
        if len(message) != self.message_size_bytes:
            raise ValueError("message block is too large")
        if scheme_mode == "BasicIdent":
            return self._encrypt_basic(identity, message, chunk_index)
        if scheme_mode == "FullIdent":
            return self._encrypt_full(identity, message, chunk_index)
        raise ValueError("scheme_mode must be BasicIdent or FullIdent")

    def decrypt_block(self, ciphertext: RecipientCiphertext, private_key: PrivateKey) -> bytes:
        if ciphertext.time_bound_id != private_key.time_bound_id:
            raise ValueError("ciphertext identity does not match private key identity")
        if ciphertext.scheme_mode == "BasicIdent":
            return self._decrypt_basic(ciphertext, private_key)
        if ciphertext.scheme_mode == "FullIdent":
            return self._decrypt_full(ciphertext, private_key)
        raise ValueError("unsupported ciphertext scheme mode")

    def _encrypt_basic(self, identity: str, message: bytes, chunk_index: int) -> RecipientCiphertext:
        r = secrets.randbelow(self.q - 1) + 1
        q_id = self.identity_point(identity)
        shared = (q_id * self.master_secret * r) % self.q
        mask = _hash_bytes(b"H2", _int_bytes(shared), length=self.message_size_bytes)
        return RecipientCiphertext(
            recipient_email=identity.split("||", 1)[0],
            time_bound_id=identity,
            scheme_mode="BasicIdent",
            chunk_index=chunk_index,
            u_b64=int_to_b64(r),
            v_b64=b64encode(_xor(message, mask)),
        )

    def _encrypt_full(self, identity: str, message: bytes, chunk_index: int) -> RecipientCiphertext:
        sigma = secrets.token_bytes(self.message_size_bytes)
        r = _scalar_hash(b"H3", sigma, message, q=self.q)
        q_id = self.identity_point(identity)
        shared = (q_id * self.master_secret * r) % self.q
        v_mask = _hash_bytes(b"H2", _int_bytes(shared), length=self.message_size_bytes)
        w_mask = _hash_bytes(b"H4", sigma, length=self.message_size_bytes)
        return RecipientCiphertext(
            recipient_email=identity.split("||", 1)[0],
            time_bound_id=identity,
            scheme_mode="FullIdent",
            chunk_index=chunk_index,
            u_b64=int_to_b64(r),
            v_b64=b64encode(_xor(sigma, v_mask)),
            w_b64=b64encode(_xor(message, w_mask)),
        )

    def _decrypt_basic(self, ciphertext: RecipientCiphertext, private_key: PrivateKey) -> bytes:
        u = int_from_b64(ciphertext.u_b64)
        private_scalar = int_from_b64(private_key.private_key_b64)
        shared = (private_scalar * u) % self.q
        mask = _hash_bytes(b"H2", _int_bytes(shared), length=self.message_size_bytes)
        return _xor(b64decode(ciphertext.v_b64), mask)

    def _decrypt_full(self, ciphertext: RecipientCiphertext, private_key: PrivateKey) -> bytes:
        if ciphertext.w_b64 is None:
            raise ValueError("FullIdent ciphertext is missing W")
        u = int_from_b64(ciphertext.u_b64)
        private_scalar = int_from_b64(private_key.private_key_b64)
        shared = (private_scalar * u) % self.q
        v_mask = _hash_bytes(b"H2", _int_bytes(shared), length=self.message_size_bytes)
        sigma = _xor(b64decode(ciphertext.v_b64), v_mask)
        w_mask = _hash_bytes(b"H4", sigma, length=self.message_size_bytes)
        message = _xor(b64decode(ciphertext.w_b64), w_mask)
        expected_u = _scalar_hash(b"H3", sigma, message, q=self.q)
        if expected_u != u:
            raise ValueError("FullIdent integrity check failed")
        return message
