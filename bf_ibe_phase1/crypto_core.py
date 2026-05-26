"""教学版 BasicIdent / FullIdent 内核。

这个模块按 Boneh-Franklin 论文的公式组织代码：

- BasicIdent: C = <U, V>
- FullIdent:  C = <U, V, W>

为了让课程演示不依赖原生 pairing 库，这里没有实现真正的椭圆曲线
Weil/Tate pairing，而是用“指数玩具群”模拟 pairing 的双线性关系。
因此它适合演示流程和测试接口，不适合作为生产密码学实现。
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
