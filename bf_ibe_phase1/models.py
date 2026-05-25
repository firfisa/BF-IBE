"""Data contracts for phase one of the BF-IBE file distribution system.

The classes in this module are intentionally lightweight. They model the
interfaces and payloads that later phases will wire to BasicIdent and
FullIdent from the Boneh-Franklin IBE paper.
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
    """Public BF-IBE parameters distributed to every client."""

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
    """PKG-only master secret material.

    This object must never be serialized into client or file-service payloads.
    It exists in phase one to document the boundary of the PKG.
    """

    secret_scalar_ref: str
    storage_backend: str
    created_at: datetime
    version: str


@dataclass(frozen=True)
class PrivateKey:
    """A user private key extracted for one time-bound identity."""

    time_bound_id: str
    recipient_email: str
    valid_hour: str
    private_key_b64: str
    issued_at: datetime
    expires_at: datetime
    public_parameters_version: str


@dataclass(frozen=True)
class TimeBoundIdentity:
    """Canonical `email||YYYY-MM-DD-HH` identity used as an IBE public key."""

    email: str
    hour: str

    @property
    def identity(self) -> str:
        return f"{self.email}{TIME_BOUND_ID_SEPARATOR}{self.hour}"

    @classmethod
    def for_hour(cls, email: str, moment: datetime) -> TimeBoundIdentity:
        if moment.tzinfo is None:
            raise ValueError("moment must include timezone information")
        normalized = moment.astimezone(timezone.utc)
        return cls(email=email.strip().lower(), hour=normalized.strftime(HOUR_FORMAT))

    @classmethod
    def for_requested_hour(cls, email: str, requested_hour: str) -> TimeBoundIdentity:
        if not HOUR_PATTERN.match(requested_hour):
            raise ValueError("requested_hour must use YYYY-MM-DD-HH")
        return cls(email=email.strip().lower(), hour=requested_hour)

    @classmethod
    def parse(cls, value: str) -> TimeBoundIdentity:
        parts = value.split(TIME_BOUND_ID_SEPARATOR)
        if len(parts) != 2 or not parts[0] or not HOUR_PATTERN.match(parts[1]):
            raise ValueError("time-bound identity must use email||YYYY-MM-DD-HH")
        return cls(email=parts[0].strip().lower(), hour=parts[1])


@dataclass(frozen=True)
class KeyPackage:
    """Private-key response returned by the PKG to an authenticated client."""

    subject_email: str
    server_hour: str
    private_key: PrivateKey
    public_parameters: PublicParameters
    ntp_policy: str


@dataclass(frozen=True)
class RecipientCiphertext:
    """Direct BasicIdent or FullIdent ciphertext for one recipient and chunk."""

    recipient_email: str
    time_bound_id: str
    scheme_mode: str
    chunk_index: int
    u_b64: str
    v_b64: str
    w_b64: str | None = None

    @property
    def is_full_ident(self) -> bool:
        return self.scheme_mode == "FullIdent"


@dataclass(frozen=True)
class EncryptedFileHeader:
    """Metadata needed by the client to decrypt direct IBE ciphertext chunks."""

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
class UserPrincipal:
    """Authenticated employee identity extracted from a mock SSO JWT."""

    subject: str
    email: str
    roles: list[str]
    active: bool


@dataclass(frozen=True)
class FileMetadata:
    """File-service metadata for a stored ciphertext object."""

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
    """Append-only event used for PKG and file-service audit trails."""

    event_id: str
    actor_email: str
    action: str
    target: str
    occurred_at: datetime
    client_time: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
