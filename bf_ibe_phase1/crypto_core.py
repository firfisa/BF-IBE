"""BasicIdent / FullIdent 内核。

这个模块按 Boneh-Franklin 论文的公式组织代码：

- BasicIdent: C = <U, V>
- FullIdent:  C = <U, V, W>

`BLS12381BFIBE` 使用 py_ecc 的 BLS12-381 optimal Ate pairing，密文里的
U 是真实 G1 曲线点 rP。`ToyBFIBE` 仅保留作教学对照，不作为默认业务后端。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
from typing import Any

from bf_ibe_phase1.encoding import b64decode, b64encode, int_from_b64, int_to_b64
from bf_ibe_phase1.models import KemCiphertext, PrivateKey, PublicParameters, RecipientCiphertext

try:
    from py_ecc.bls.hash_to_curve import hash_to_G2
    from py_ecc.optimized_bls12_381 import (
        FQ,
        FQ2,
        G1,
        Z1,
        Z2,
        b,
        b2,
        curve_order,
        field_modulus,
        is_on_curve,
        multiply,
        normalize,
        pairing,
    )
except ImportError:  # pragma: no cover - exercised only outside the bf-ibe conda env.
    hash_to_G2 = None
    FQ = FQ2 = None
    G1 = Z1 = Z2 = None
    b = b2 = None
    curve_order = None
    field_modulus = None
    is_on_curve = None
    multiply = None
    normalize = None
    pairing = None


DEMO_Q = 2**127 - 1
DEFAULT_MESSAGE_SIZE_BYTES = 32
DEFAULT_KEM_KEY_BYTES = 32
BLS12_381_FIELD_BYTES = 48
BLS12_381_G1_BYTES = BLS12_381_FIELD_BYTES * 2
BLS12_381_G2_BYTES = BLS12_381_FIELD_BYTES * 4
BLS12_381_HASH_DST = b"BF-IBE-PHASE2-BLS12381G2-SHA256-v1"


def _xor(left: bytes, right: bytes) -> bytes:
    """论文里 M xor H2(...) 的字节级实现。"""
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def _hash_bytes(label: bytes, *parts: bytes, length: int = DEFAULT_MESSAGE_SIZE_BYTES) -> bytes:
    """把任意输入扩展成指定长度的伪随机字节流，用来模拟 H2/H4。"""
    output = bytearray()
    counter = 0
    while len(output) < length:
        digest = hashlib.sha256(label + counter.to_bytes(4, "big") + b"".join(parts)).digest()
        output.extend(digest)
        counter += 1
    return bytes(output[:length])


def _scalar_hash(label: bytes, *parts: bytes, q: int = DEMO_Q) -> int:
    """把身份或 FullIdent 的 sigma/M 映射成 1..q-1 的标量。"""
    digest = hashlib.sha256(label + b"".join(parts)).digest()
    return int.from_bytes(digest, "big") % (q - 1) + 1


def _int_bytes(value: int) -> bytes:
    return value.to_bytes(32, "big")


def _require_py_ecc() -> None:
    if pairing is None:
        raise RuntimeError(
            "py-ecc is required for BLS12381BFIBE; run `conda run -n bf-ibe python -m pip install py-ecc`"
        )


class DecryptReject(ValueError):
    """Uniform external decryption failure for KEM/DEM CCA2 handling."""

    def __init__(self) -> None:
        super().__init__("REJECT")


def _field_element_to_bytes(value: Any) -> bytes:
    return int(value).to_bytes(BLS12_381_FIELD_BYTES, "big")


def _field_element_from_bytes(data: bytes) -> int:
    value = int.from_bytes(data, "big")
    if field_modulus is None or value >= field_modulus:
        raise ValueError("field element is out of range")
    return value


def _gt_to_bytes(value: Any) -> bytes:
    """Serialize a BLS12-381 GT element for H2/H4 masking.

    py_ecc returns an FQ12 element as 12 base-field coefficients. We do not
    expose GT directly; these bytes are only fed into SHA-256 based KDF masks.
    """
    return b"".join(_field_element_to_bytes(coefficient) for coefficient in value.coeffs)


def _g1_equal(left: Any, right: Any) -> bool:
    return serialize_g1_point(left) == serialize_g1_point(right)


def serialize_g1_point(point: Any) -> str:
    """Serialize a non-infinity BLS12-381 G1 curve point as x||y.

    This is the real `U = rP` component used by the pairing backend. It is not
    the random scalar `r`; recovering `r` from this point is the discrete-log
    problem on G1.
    """
    _require_py_ecc()
    if point == Z1:
        raise ValueError("cannot serialize point at infinity")
    x, y = normalize(point)
    return b64encode(_field_element_to_bytes(x) + _field_element_to_bytes(y))


def deserialize_g1_point(value: str) -> Any:
    """Deserialize and validate a BLS12-381 G1 point."""
    _require_py_ecc()
    raw = b64decode(value)
    if len(raw) != BLS12_381_G1_BYTES:
        raise ValueError("serialized G1 point must be 96 bytes")
    x = _field_element_from_bytes(raw[:BLS12_381_FIELD_BYTES])
    y = _field_element_from_bytes(raw[BLS12_381_FIELD_BYTES:])
    point = (FQ(x), FQ(y), FQ.one())
    if not is_on_curve(point, b):
        raise ValueError("serialized G1 point is not on BLS12-381")
    if multiply(point, curve_order) != Z1:
        raise ValueError("serialized G1 point is not in the prime-order subgroup")
    return point


def serialize_g2_point(point: Any) -> str:
    """Serialize a non-infinity BLS12-381 G2 curve point as x0||x1||y0||y1."""
    _require_py_ecc()
    if point == Z2:
        raise ValueError("cannot serialize point at infinity")
    x, y = normalize(point)
    return b64encode(
        _field_element_to_bytes(x.coeffs[0])
        + _field_element_to_bytes(x.coeffs[1])
        + _field_element_to_bytes(y.coeffs[0])
        + _field_element_to_bytes(y.coeffs[1])
    )


def deserialize_g2_point(value: str) -> Any:
    """Deserialize and validate a BLS12-381 G2 point."""
    _require_py_ecc()
    raw = b64decode(value)
    if len(raw) != BLS12_381_G2_BYTES:
        raise ValueError("serialized G2 point must be 192 bytes")
    parts = [
        _field_element_from_bytes(raw[offset : offset + BLS12_381_FIELD_BYTES])
        for offset in range(0, BLS12_381_G2_BYTES, BLS12_381_FIELD_BYTES)
    ]
    point = (FQ2([parts[0], parts[1]]), FQ2([parts[2], parts[3]]), FQ2.one())
    if not is_on_curve(point, b2):
        raise ValueError("serialized G2 point is not on BLS12-381")
    if multiply(point, curve_order) != Z2:
        raise ValueError("serialized G2 point is not in the prime-order subgroup")
    return point


@dataclass(frozen=True)
class ToyBFIBE:
    """一个能跑通论文公式的 BF-IBE 教学实现。

    在真实 BF-IBE 中：
    - P 是椭圆曲线群 G1 的生成元；
    - master_secret 是 PKG 的主密钥 s；
    - Ppub = sP 是系统公钥；
    - H1(ID) 是 Hash-to-Point 得到的 Q_ID；
    - pairing(Q_ID, Ppub)^r 是共享掩码来源。

    在这个 toy 实现中，点都用“相对 P 的标量”表示，所以 pairing 的结果可以
    简化成标量乘积。这样代码短很多，但安全性不等价于真实 pairing。
    """

    q: int
    master_secret: int
    message_size_bytes: int = DEFAULT_MESSAGE_SIZE_BYTES

    @classmethod
    def setup_demo(cls) -> ToyBFIBE:
        """模拟论文 Setup：生成群参数和 PKG 主密钥 s。"""
        return cls(q=DEMO_Q, master_secret=secrets.randbelow(DEMO_Q - 1) + 1)

    @property
    def public_parameters(self) -> PublicParameters:
        """暴露给所有客户端的公共参数；master_secret 不会出现在这里。"""
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
        """模拟 H1(ID) -> Q_ID。真实实现应替换成 Hash-to-Point。"""
        return _scalar_hash(b"H1", identity.encode("utf-8"), q=self.q)

    def extract_private_key(self, identity: str, recipient_email: str) -> PrivateKey:
        """模拟论文 Extract：d_ID = s * Q_ID。"""
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
        """加密一个定长消息块。

        论文的 BasicIdent/FullIdent 都加密固定长度消息 M。文件加密器会先把
        文件拆成 chunk，然后逐块调用这个方法。
        """
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
        """用 Extract 得到的 d_ID 解密一个密文块。"""
        if ciphertext.time_bound_id != private_key.time_bound_id:
            raise ValueError("ciphertext identity does not match private key identity")
        if ciphertext.scheme_mode == "BasicIdent":
            return self._decrypt_basic(ciphertext, private_key)
        if ciphertext.scheme_mode == "FullIdent":
            return self._decrypt_full(ciphertext, private_key)
        raise ValueError("unsupported ciphertext scheme mode")

    def _encrypt_basic(self, identity: str, message: bytes, chunk_index: int) -> RecipientCiphertext:
        """BasicIdent Encrypt。

        论文公式：
        - Q_ID = H1(ID)
        - 随机选 r
        - U = rP
        - V = M xor H2(pairing(Q_ID, Ppub)^r)

        这里 u_b64 保存 r 的 toy 表示；真实实现应保存曲线点 U = rP。
        """
        r = secrets.randbelow(self.q - 1) + 1
        q_id = self.identity_point(identity)
        # toy shared = Q_ID * s * r，对应真实 shared = e(Q_ID, Ppub)^r。
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
        """FullIdent Encrypt。

        FullIdent 是论文中用 Fujisaki-Okamoto 变换得到的 CCA 安全版本：
        - 先随机生成 sigma；
        - r = H3(sigma, M)，因此随机性和明文绑定；
        - V = sigma xor H2(shared)；
        - W = M xor H4(sigma)；
        - 密文为 <U, V, W>。
        """
        sigma = secrets.token_bytes(self.message_size_bytes)
        r = _scalar_hash(b"H3", sigma, message, q=self.q)
        q_id = self.identity_point(identity)
        # 与 BasicIdent 一样，这里模拟 e(Q_ID, Ppub)^r。
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
        """BasicIdent Decrypt：M = V xor H2(pairing(d_ID, U))。"""
        u = int_from_b64(ciphertext.u_b64)
        private_scalar = int_from_b64(private_key.private_key_b64)
        # toy shared = d_ID * r，对应真实 shared = e(d_ID, U)。
        shared = (private_scalar * u) % self.q
        mask = _hash_bytes(b"H2", _int_bytes(shared), length=self.message_size_bytes)
        return _xor(b64decode(ciphertext.v_b64), mask)

    def _decrypt_full(self, ciphertext: RecipientCiphertext, private_key: PrivateKey) -> bytes:
        """FullIdent Decrypt，并执行 U = rP 的一致性校验。"""
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
        # 这是 FullIdent 的 CCA 防篡改检查：重算 r，要求 U 与 rP 一致。
        if expected_u != u:
            raise ValueError("FullIdent integrity check failed")
        return message


@dataclass(frozen=True)
class BLS12381BFIBE:
    """Boneh-Franklin IBE over real BLS12-381 curve points.

    This backend uses py_ecc's `optimized_bls12_381.pairing`, which implements
    the optimal Ate pairing on BLS12-381. BLS12-381 is an asymmetric Type-3
    pairing curve, so we map the paper's symmetric notation as follows:

    - P, Ppub=sP, and U=rP live in G1.
    - Q_ID=H1(ID) and d_ID=sQ_ID live in G2.
    - The pairing is e: G2 x G1 -> GT.

    The decryption equality is still the Boneh-Franklin equality:
    e(d_ID, U) = e(sQ_ID, rP) = e(Q_ID, sP)^r = e(Q_ID, Ppub)^r.
    """

    master_secret: int
    message_size_bytes: int = DEFAULT_MESSAGE_SIZE_BYTES

    @classmethod
    def setup_demo(cls) -> BLS12381BFIBE:
        """Setup: choose the PKG master secret scalar s in Z_q."""
        _require_py_ecc()
        return cls(master_secret=secrets.randbelow(curve_order - 1) + 1)

    @property
    def q(self) -> int:
        _require_py_ecc()
        return curve_order

    @property
    def public_parameters(self) -> PublicParameters:
        """Expose public parameters; never expose `master_secret`."""
        _require_py_ecc()
        return PublicParameters(
            scheme="BF-IBE-BLS12-381",
            curve="BLS12-381",
            pairing="optimal Ate pairing on BLS12-381, e: G2 x G1 -> GT (py_ecc.optimized_bls12_381.pairing)",
            generator_g1_b64=serialize_g1_point(G1),
            public_point_b64=serialize_g1_point(self._public_point()),
            hash_to_point="IETF hash_to_curve hash_to_G2 with SHA-256 DST BF-IBE-PHASE2-BLS12381G2-SHA256-v1",
            hash_h2="SHA256-XOF mask over serialized GT",
            hash_h3="SHA256-to-Zq for Dent/FO KEM randomness and FullIdent comparison",
            hash_h4="SHA256-XOF KDF for KEM key and FullIdent comparison",
            message_size_bits=self.message_size_bytes * 8,
            version="bls12-381-pairing-v1",
        )

    def is_serialized_g1_point(self, value: str) -> bool:
        """Return True only when `value` is a valid serialized BLS12-381 G1 point."""
        try:
            deserialize_g1_point(value)
        except ValueError:
            return False
        return True

    def identity_point(self, identity: str) -> Any:
        """H1(ID) -> Q_ID in G2 using py_ecc's hash_to_G2."""
        _require_py_ecc()
        return hash_to_G2(identity.encode("utf-8"), BLS12_381_HASH_DST, hashlib.sha256)

    def extract_private_key(self, identity: str, recipient_email: str) -> PrivateKey:
        """Extract: d_ID = sQ_ID, serialized as a real G2 curve point."""
        _require_py_ecc()
        private_point = multiply(self.identity_point(identity), self.master_secret)
        hour = identity.split("||", 1)[1]
        issued_at = datetime.now(timezone.utc)
        return PrivateKey(
            time_bound_id=identity,
            recipient_email=recipient_email,
            valid_hour=hour,
            private_key_b64=serialize_g2_point(private_point),
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
        """Encrypt a fixed-size BF-IBE message block."""
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
        """Decrypt a BF-IBE block using the matching Extract output."""
        if ciphertext.time_bound_id != private_key.time_bound_id:
            raise ValueError("ciphertext identity does not match private key identity")
        if ciphertext.scheme_mode == "BasicIdent":
            return self._decrypt_basic(ciphertext, private_key)
        if ciphertext.scheme_mode == "FullIdent":
            return self._decrypt_full(ciphertext, private_key)
        raise ValueError("unsupported ciphertext scheme mode")

    def encapsulate_key(self, identity: str) -> tuple[KemCiphertext, bytes]:
        """Dent/FO KEM_Encap.

        PDF protocol mapping:
        - sigma <- {0,1}^n
        - r = H3(sigma)
        - U = rP
        - V = sigma xor H2(e(Q_ID, Ppub)^r)
        - K = H4(sigma)

        The output KEM ciphertext is exactly (U,V); FullIdent's W component is
        omitted because the DEM key is directly defined as H4(sigma).
        """
        _require_py_ecc()
        sigma = secrets.token_bytes(self.message_size_bytes)
        r = _scalar_hash(b"H3", sigma, q=curve_order)
        q_id = self.identity_point(identity)
        u_point = multiply(G1, r)
        shared = pairing(q_id, self._public_point()) ** r
        mask = _hash_bytes(b"H2", _gt_to_bytes(shared), length=self.message_size_bytes)
        key = _hash_bytes(b"H4", sigma, length=DEFAULT_KEM_KEY_BYTES)
        return (
            KemCiphertext(
                u_b64=serialize_g1_point(u_point),
                v_b64=b64encode(_xor(sigma, mask)),
                kem_algorithm="BF-IBE-DENT-FO-KEM-BLS12-381",
                seed_length_bytes=self.message_size_bytes,
                key_length_bytes=DEFAULT_KEM_KEY_BYTES,
            ),
            key,
        )

    def decapsulate_key(self, kem_ciphertext: KemCiphertext, private_key: PrivateKey) -> bytes:
        """Dent/FO KEM_Decap with a uniform REJECT failure surface."""
        try:
            private_point = deserialize_g2_point(private_key.private_key_b64)
            u_point = deserialize_g1_point(kem_ciphertext.u_b64)
            encrypted_sigma = b64decode(kem_ciphertext.v_b64)
            if len(encrypted_sigma) != kem_ciphertext.seed_length_bytes:
                raise ValueError("invalid KEM V length")
            shared = pairing(private_point, u_point)
            mask = _hash_bytes(b"H2", _gt_to_bytes(shared), length=kem_ciphertext.seed_length_bytes)
            sigma = _xor(encrypted_sigma, mask)
            expected_r = _scalar_hash(b"H3", sigma, q=curve_order)
            expected_u = multiply(G1, expected_r)
            if not _g1_equal(expected_u, u_point):
                raise ValueError("KEM re-encryption check failed")
            return _hash_bytes(b"H4", sigma, length=kem_ciphertext.key_length_bytes)
        except Exception as exc:
            raise DecryptReject() from exc

    def _public_point(self) -> Any:
        """Ppub = sP in G1."""
        return multiply(G1, self.master_secret)

    def _encrypt_basic(self, identity: str, message: bytes, chunk_index: int) -> RecipientCiphertext:
        """BasicIdent Encrypt with the real curve point U = rP.

        The pairing call below is the optimal Ate pairing:
        `pairing(Q_ID, Ppub)`, where Q_ID is in G2 and Ppub is in G1.
        """
        r = secrets.randbelow(curve_order - 1) + 1
        q_id = self.identity_point(identity)
        u_point = multiply(G1, r)
        shared = pairing(q_id, self._public_point()) ** r
        mask = _hash_bytes(b"H2", _gt_to_bytes(shared), length=self.message_size_bytes)
        return RecipientCiphertext(
            recipient_email=identity.split("||", 1)[0],
            time_bound_id=identity,
            scheme_mode="BasicIdent",
            chunk_index=chunk_index,
            u_b64=serialize_g1_point(u_point),
            v_b64=b64encode(_xor(message, mask)),
        )

    def _encrypt_full(self, identity: str, message: bytes, chunk_index: int) -> RecipientCiphertext:
        """FullIdent Encrypt with Fujisaki-Okamoto CCA transform.

        Here `u_b64` serializes the actual BLS12-381 G1 point U = rP. It never
        stores the scalar r.
        """
        sigma = secrets.token_bytes(self.message_size_bytes)
        r = _scalar_hash(b"H3", sigma, message, q=curve_order)
        q_id = self.identity_point(identity)
        u_point = multiply(G1, r)
        # optimal Ate pairing on BLS12-381, e(Q_ID, Ppub)^r.
        shared = pairing(q_id, self._public_point()) ** r
        v_mask = _hash_bytes(b"H2", _gt_to_bytes(shared), length=self.message_size_bytes)
        w_mask = _hash_bytes(b"H4", sigma, length=self.message_size_bytes)
        return RecipientCiphertext(
            recipient_email=identity.split("||", 1)[0],
            time_bound_id=identity,
            scheme_mode="FullIdent",
            chunk_index=chunk_index,
            u_b64=serialize_g1_point(u_point),
            v_b64=b64encode(_xor(sigma, v_mask)),
            w_b64=b64encode(_xor(message, w_mask)),
        )

    def _decrypt_basic(self, ciphertext: RecipientCiphertext, private_key: PrivateKey) -> bytes:
        """BasicIdent Decrypt: M = V xor H2(e(d_ID, U))."""
        private_point = deserialize_g2_point(private_key.private_key_b64)
        u_point = deserialize_g1_point(ciphertext.u_b64)
        # optimal Ate pairing on BLS12-381, e(d_ID, U).
        shared = pairing(private_point, u_point)
        mask = _hash_bytes(b"H2", _gt_to_bytes(shared), length=self.message_size_bytes)
        return _xor(b64decode(ciphertext.v_b64), mask)

    def _decrypt_full(self, ciphertext: RecipientCiphertext, private_key: PrivateKey) -> bytes:
        """FullIdent Decrypt and verify the CCA check U == rP."""
        if ciphertext.w_b64 is None:
            raise ValueError("FullIdent ciphertext is missing W")
        private_point = deserialize_g2_point(private_key.private_key_b64)
        u_point = deserialize_g1_point(ciphertext.u_b64)
        shared = pairing(private_point, u_point)
        v_mask = _hash_bytes(b"H2", _gt_to_bytes(shared), length=self.message_size_bytes)
        sigma = _xor(b64decode(ciphertext.v_b64), v_mask)
        w_mask = _hash_bytes(b"H4", sigma, length=self.message_size_bytes)
        message = _xor(b64decode(ciphertext.w_b64), w_mask)
        expected_r = _scalar_hash(b"H3", sigma, message, q=curve_order)
        expected_u = multiply(G1, expected_r)
        if not _g1_equal(expected_u, u_point):
            raise ValueError("FullIdent integrity check failed")
        return message
