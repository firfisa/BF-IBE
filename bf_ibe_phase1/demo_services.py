"""In-memory Auth/PKG/File service implementations for the demo."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import shutil

from bf_ibe_phase1.auth import AuthError, AuthService
from bf_ibe_phase1.crypto_core import ToyBFIBE
from bf_ibe_phase1.models import EncryptedFileHeader, FileMetadata, KeyPackage, TimeBoundIdentity


class ServiceError(Exception):
    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.message = message


def _service_error(exc: AuthError) -> ServiceError:
    text = str(exc)
    status = 403 if "inactive" in text else 401
    return ServiceError(status, text)


class PKGService:
    def __init__(self, auth: AuthService, ibe: ToyBFIBE):
        self.auth = auth
        self.ibe = ibe

    def get_public_parameters(self, jwt: str):
        try:
            self.auth.ensure_active(jwt)
        except AuthError as exc:
            raise _service_error(exc) from exc
        return self.ibe.public_parameters

    def get_private_key(
        self,
        jwt: str,
        requested_hour: str,
        client_time_iso: str | None = None,
    ) -> KeyPackage:
        del client_time_iso
        try:
            principal = self.auth.ensure_active(jwt)
        except AuthError as exc:
            raise _service_error(exc) from exc
        identity = TimeBoundIdentity.for_requested_hour(principal.email, requested_hour).identity
        private_key = self.ibe.extract_private_key(identity, principal.email)
        return KeyPackage(
            subject_email=principal.email,
            server_hour=datetime.now(timezone.utc).strftime("%Y-%m-%d-%H"),
            private_key=private_key,
            public_parameters=self.ibe.public_parameters,
            ntp_policy="PKG server time is authoritative for audit and employee-state checks",
        )

    def get_private_keys(
        self,
        jwt: str,
        requested_hours: list[str],
        client_time_iso: str | None = None,
    ) -> list[KeyPackage]:
        return [
            self.get_private_key(jwt, requested_hour, client_time_iso)
            for requested_hour in requested_hours
        ]


class FileService:
    def __init__(self, auth: AuthService, storage_dir: Path):
        self.auth = auth
        self.storage_dir = storage_dir
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self._headers: dict[str, EncryptedFileHeader] = {}
        self._metadata: dict[str, FileMetadata] = {}
        self._paths: dict[str, Path] = {}

    def upload_file(
        self,
        jwt: str,
        ciphertext_path: Path,
        header: EncryptedFileHeader,
    ) -> FileMetadata:
        principal = self._active_principal(jwt)
        stored_path = self.storage_dir / f"{header.file_id}.bfibe"
        shutil.copyfile(ciphertext_path, stored_path)
        recipients = sorted({item.recipient_email for item in header.recipients})
        metadata = FileMetadata(
            file_id=header.file_id,
            owner_email=principal.email,
            original_filename=str(header.metadata.get("original_filename", header.file_id)),
            size_bytes=stored_path.stat().st_size,
            encryption_hour=header.encryption_hour,
            recipients=recipients,
            ciphertext_sha256=header.ciphertext_sha256,
            created_at=datetime.now(timezone.utc),
        )
        self._headers[header.file_id] = header
        self._metadata[header.file_id] = metadata
        self._paths[header.file_id] = stored_path
        return metadata

    def list_files(self, jwt: str) -> list[FileMetadata]:
        principal = self._active_principal(jwt)
        return [
            metadata
            for metadata in self._metadata.values()
            if self._can_access(principal.email, metadata)
        ]

    def get_file_metadata(self, jwt: str, file_id: str) -> FileMetadata:
        principal = self._active_principal(jwt)
        metadata = self._require_metadata(file_id)
        if not self._can_access(principal.email, metadata):
            raise ServiceError(403, "user is not allowed to access this file")
        return metadata

    def download_file(self, jwt: str, file_id: str, destination_path: Path) -> EncryptedFileHeader:
        principal = self._active_principal(jwt)
        metadata = self._require_metadata(file_id)
        if not self._can_access(principal.email, metadata):
            raise ServiceError(403, "user is not allowed to download this file")
        shutil.copyfile(self._paths[file_id], destination_path)
        return self._headers[file_id]

    def _active_principal(self, jwt: str):
        try:
            return self.auth.ensure_active(jwt)
        except AuthError as exc:
            raise _service_error(exc) from exc

    def _require_metadata(self, file_id: str) -> FileMetadata:
        metadata = self._metadata.get(file_id)
        if metadata is None:
            raise ServiceError(404, "file not found")
        return metadata

    def _can_access(self, email: str, metadata: FileMetadata) -> bool:
        return email == metadata.owner_email or email in metadata.recipients
