"""Mock SSO/JWT service for the local demo."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import time

from bf_ibe_phase1.encoding import b64decode, b64encode
from bf_ibe_phase1.models import UserPrincipal


class AuthError(Exception):
    pass


@dataclass
class _UserRecord:
    email: str
    password_hash: str
    roles: list[str]
    active: bool = True


class AuthService:
    def __init__(self, secret: bytes = b"bf-ibe-demo-secret"):
        self._secret = secret
        self._users: dict[str, _UserRecord] = {}

    @classmethod
    def demo(cls) -> AuthService:
        service = cls()
        service.register("alice@company.com", "demo-password", ["employee", "sender"])
        service.register("bob@company.com", "demo-password", ["employee"])
        service.register("admin@company.com", "demo-password", ["admin"])
        return service

    def register(self, email: str, password: str, roles: list[str]) -> None:
        normalized = email.strip().lower()
        self._users[normalized] = _UserRecord(
            email=normalized,
            password_hash=self._password_hash(password),
            roles=roles,
        )

    def login(self, email: str, password: str) -> str:
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
        principal = self.authenticate(token)
        if not principal.active:
            raise AuthError("user is inactive")
        return principal

    def set_active(self, email: str, active: bool) -> None:
        normalized = email.strip().lower()
        if normalized not in self._users:
            raise AuthError("unknown user")
        self._users[normalized].active = active

    def _password_hash(self, password: str) -> str:
        return hashlib.sha256((password + ":bf-ibe-demo").encode("utf-8")).hexdigest()
