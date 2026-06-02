"""系统中的数据结构。

这里的 dataclass 相当于“接口文档里的 JSON schema”：

- PKG 返回什么；
- 文件服务保存什么；
- 客户端解密需要从 header 里读什么。

这些类尽量只表达数据，不写复杂业务逻辑，方便后续替换成 Pydantic /
FastAPI schema。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
from typing import Any


TIME_BOUND_ID_SEPARATOR = "||"
HOUR_FORMAT = "%Y-%m-%d-%H"
HOUR_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}-\d{2}$")


@dataclass(frozen=True)
class PublicParameters:
    """BF-IBE 公共参数。

    客户端加密只需要这些公共参数和接收者 ID，不需要接收者提前生成证书。
    `public_point_b64` 对应论文里的 Ppub = sP。
    """

    scheme: str
    curve: str
    pairing: str
    generator_g1_b64: str
    public_point_b64: str
    hash_to_point: str
    hash_h2: str
    hash_h3: str | None
    hash_h4: str | None
    message_size_bits: int
    version: str


@dataclass(frozen=True)
class MasterSecret:
    """PKG 主密钥引用。

    真实系统中这里应该接 HSM/KMS/密钥保险箱。它绝不能出现在客户端、
    文件服务或日志里。
    """

    secret_scalar_ref: str
    storage_backend: str
    created_at: datetime
    version: str


@dataclass(frozen=True)
class PrivateKey:
    """PKG 为某个 `email||hour` 身份派生出的用户私钥 d_ID。"""

    time_bound_id: str
    recipient_email: str
    valid_hour: str
    private_key_b64: str
    issued_at: datetime
    expires_at: datetime
    public_parameters_version: str


@dataclass(frozen=True)
class TimeBoundIdentity:
    """IBE 公钥身份：`email||YYYY-MM-DD-HH`。

    这就是论文里的 ID。发送者用这个字符串加密；接收者向 PKG 申请同一
    字符串对应的私钥。
    """

    email: str
    hour: str

    @property
    def identity(self) -> str:
        return f"{self.email}{TIME_BOUND_ID_SEPARATOR}{self.hour}"

    @classmethod
    def for_hour(cls, email: str, moment: datetime) -> TimeBoundIdentity:
        """根据具体时间自动取整到 UTC 小时。"""
        if moment.tzinfo is None:
            raise ValueError("moment must include timezone information")
        normalized = moment.astimezone(timezone.utc)
        return cls(email=email.strip().lower(), hour=normalized.strftime(HOUR_FORMAT))

    @classmethod
    def for_requested_hour(cls, email: str, requested_hour: str) -> TimeBoundIdentity:
        """根据客户端显式请求的小时构造 ID。"""
        if not HOUR_PATTERN.match(requested_hour):
            raise ValueError("requested_hour must use YYYY-MM-DD-HH")
        return cls(email=email.strip().lower(), hour=requested_hour)

    @classmethod
    def parse(cls, value: str) -> TimeBoundIdentity:
        """从 header 或 API 字符串中解析 `email||hour`。"""
        parts = value.split(TIME_BOUND_ID_SEPARATOR)
        if len(parts) != 2 or not parts[0] or not HOUR_PATTERN.match(parts[1]):
            raise ValueError("time-bound identity must use email||YYYY-MM-DD-HH")
        return cls(email=parts[0].strip().lower(), hour=parts[1])


@dataclass(frozen=True)
class KeyPackage:
    """PKG 给客户端的私钥响应包。"""

    subject_email: str
    server_hour: str
    private_key: PrivateKey
    public_parameters: PublicParameters
    ntp_policy: str


@dataclass(frozen=True)
class KemCiphertext:
    """Dent/FO KEM 封装密文 C_KEM = (U, V)。

    KEM 只封装随机种子 sigma 并派生会话密钥，不包含 FullIdent PKE 的 W 分量。
    """

    u_b64: str
    v_b64: str
    kem_algorithm: str
    seed_length_bytes: int
    key_length_bytes: int


@dataclass(frozen=True)
class RecipientKeyEnvelope:
    """面向某个接收者的 KEM key envelope。

    文件正文只用一个 file_key 加密一次；每个接收者用自己的 BF-IBE KEM key
    封装同一个 file_key。
    """

    recipient_email: str
    time_bound_id: str
    kem_ciphertext: KemCiphertext
    wrap_iv_b64: str
    wrapped_file_key_b64: str


@dataclass(frozen=True)
class RecipientCiphertext:
    """某个接收者、某个 chunk 的 IBE 密文。

    BasicIdent 使用 U/V 两个分量；FullIdent 使用 U/V/W 三个分量。
    同一文件发给多个人时，每个接收者都会有自己的 RecipientCiphertext。
    """

    recipient_email: str
    time_bound_id: str
    scheme_mode: str
    chunk_index: int
    u_b64: str
    v_b64: str
    w_b64: str | None = None

    @property
    def is_full_ident(self) -> bool:
        """方便测试和业务代码判断当前条目是否是 FullIdent。"""
        return self.scheme_mode == "FullIdent"

    def with_v_b64(self, value: str) -> RecipientCiphertext:
        """生成一个篡改 V 分量后的副本，用于 FullIdent 防篡改测试。"""
        return RecipientCiphertext(
            recipient_email=self.recipient_email,
            time_bound_id=self.time_bound_id,
            scheme_mode=self.scheme_mode,
            chunk_index=self.chunk_index,
            u_b64=self.u_b64,
            v_b64=value,
            w_b64=self.w_b64,
        )


@dataclass(frozen=True)
class EncryptedFileHeader:
    """密文文件头。

    文件服务保存密文文件本体，同时保存/返回这个 header。客户端靠 header
    找到自己的 time_bound_id、chunk 列表和算法模式。
    """

    file_id: str
    algorithm: str
    encryption_hour: str
    ciphertext_sha256: str
    recipients: list[RecipientCiphertext]
    schema_version: str = "phase1.v1"
    chunk_size_bytes: int = 32
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def recipient_count(self) -> int:
        return len(self.recipients)

    @property
    def recipient_ids(self) -> list[str]:
        return [recipient.time_bound_id for recipient in self.recipients]


@dataclass(frozen=True)
class HybridEncryptedFileHeader:
    """KEM/DEM 混合加密文件头。"""

    file_id: str
    algorithm: str
    encryption_hour: str
    dem_algorithm: str
    dem_iv_b64: str
    dem_tag_b64: str
    recipient_envelopes: list[RecipientKeyEnvelope]
    ciphertext_sha256: str
    schema_version: str = "phase2.hybrid.v1"
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def recipients(self) -> list[RecipientKeyEnvelope]:
        """兼容文件服务现有 owner/recipient 元数据逻辑。"""
        return self.recipient_envelopes

    @property
    def recipient_count(self) -> int:
        return len(self.recipient_envelopes)

    @property
    def recipient_ids(self) -> list[str]:
        return [recipient.time_bound_id for recipient in self.recipient_envelopes]


@dataclass(frozen=True)
class UserPrincipal:
    """从模拟 JWT 解析出的员工身份。"""

    subject: str
    email: str
    roles: list[str]
    active: bool


@dataclass(frozen=True)
class FileMetadata:
    """文件服务给列表/详情接口返回的元数据。"""

    file_id: str
    owner_email: str
    original_filename: str
    size_bytes: int
    encryption_hour: str
    recipients: list[str]
    ciphertext_sha256: str
    created_at: datetime


@dataclass(frozen=True)
class AuditEvent:
    """审计事件：记录下载、拒绝、私钥发放等安全相关动作。"""

    event_id: str
    actor_email: str
    action: str
    target: str
    occurred_at: datetime
    client_time: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
