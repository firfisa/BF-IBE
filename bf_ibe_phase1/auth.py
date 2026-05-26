"""演示用模拟 SSO/JWT 服务。

真实企业系统里，这一层会替换成 LDAP、OAuth2/OIDC、企业微信/飞书 SSO 等。
这里用 HMAC 签名的简化 token 模拟 JWT，重点展示：

- 登录后拿到 token；
- 文件服务和 PKG 都用 token 识别用户；
- 用户离职时把 active 改为 False，后续下载和私钥申请都会失败。
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import time

from bf_ibe_phase1.encoding import b64decode, b64encode
from bf_ibe_phase1.models import UserPrincipal


class AuthError(Exception):
    """认证或员工状态校验失败。"""

    pass


@dataclass
class _UserRecord:
    """内存用户表中的一条记录。"""

    email: str
    password_hash: str
    roles: list[str]
    active: bool = True


class AuthService:
    """模拟企业身份系统。"""

    def __init__(self, secret: bytes = b"bf-ibe-demo-secret"):
        self._secret = secret
        self._users: dict[str, _UserRecord] = {}

    @classmethod
    def demo(cls) -> AuthService:
        """创建演示账号：Alice 发送文件，Bob 接收文件。"""
        service = cls()
        service.register("alice@company.com", "demo-password", ["employee", "sender"])
        service.register("bob@company.com", "demo-password", ["employee"])
        service.register("admin@company.com", "demo-password", ["admin"])
        return service

    def register(self, email: str, password: str, roles: list[str]) -> None:
        """注册用户到内存用户表。"""
        normalized = email.strip().lower()
        self._users[normalized] = _UserRecord(
            email=normalized,
            password_hash=self._password_hash(password),
            roles=roles,
        )

    def login(self, email: str, password: str) -> str:
        """登录并返回简化 JWT。

        token 结构是 `base64(payload).base64(hmac)`，足够演示签名校验；
        正式系统应使用标准 JWT/OIDC 库。
        """
        normalized = email.strip().lower()
        record = self._users.get(normalized)
        if record is None or record.password_hash != self._password_hash(password):
            raise AuthError("invalid email or password")
        if not record.active:
            raise AuthError("user is inactive")
        payload = {
            "sub": f"user-{normalized}",
            "email": normalized,
            "roles": record.roles,
            "iat": int(time.time()),
        }
        body = b64encode(json.dumps(payload, sort_keys=True).encode("utf-8"))
        signature = b64encode(hmac.new(self._secret, body.encode("ascii"), hashlib.sha256).digest())
        return f"{body}.{signature}"

    def authenticate(self, token: str) -> UserPrincipal:
        """验证 token 签名，并返回当前用户状态。

        注意：active 状态每次都从内存用户表读取，所以用户离职后，即使用旧
        token 调用文件服务或 PKG，也会被识别为 inactive。
        """
        try:
            body, signature = token.split(".", 1)
        except ValueError as exc:
            raise AuthError("invalid token") from exc
        expected = b64encode(hmac.new(self._secret, body.encode("ascii"), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            raise AuthError("invalid token signature")
        payload = json.loads(b64decode(body).decode("utf-8"))
        email = payload["email"].strip().lower()
        record = self._users.get(email)
        if record is None:
            raise AuthError("unknown user")
        return UserPrincipal(
            subject=payload["sub"],
            email=email,
            roles=list(record.roles),
            active=record.active,
        )

    def ensure_active(self, token: str) -> UserPrincipal:
        """既要 token 有效，也要员工仍是 active。"""
        principal = self.authenticate(token)
        if not principal.active:
            raise AuthError("user is inactive")
        return principal

    def set_active(self, email: str, active: bool) -> None:
        """模拟 HR/管理员把员工设置为在职或离职。"""
        normalized = email.strip().lower()
        if normalized not in self._users:
            raise AuthError("unknown user")
        self._users[normalized].active = active

    def _password_hash(self, password: str) -> str:
        """演示用密码哈希；生产系统不要自己写密码存储。"""
        return hashlib.sha256((password + ":bf-ibe-demo").encode("utf-8")).hexdigest()
