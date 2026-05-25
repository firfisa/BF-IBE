"""Client-side service contracts for PKG and file-server APIs."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from bf_ibe_phase1.models import (
    EncryptedFileHeader,
    FileMetadata,
    KeyPackage,
    PublicParameters,
)


class PKGClient(ABC):
    """Pull public parameters and current-hour private keys from the PKG."""

    @abstractmethod
    def get_public_parameters(self, jwt: str) -> PublicParameters:
        """Return the active BF-IBE public parameters."""
        raise NotImplementedError

    @abstractmethod
    def get_current_private_key(self, jwt: str, client_time_iso: str | None = None) -> KeyPackage:
        """Return the private key for the authenticated user's server-side hour."""
        raise NotImplementedError


class FileServerClient(ABC):
    """Upload, list, inspect, and download encrypted files."""

    @abstractmethod
    def upload_file(
        self,
        jwt: str,
        ciphertext_path: Path,
        header: EncryptedFileHeader,
    ) -> FileMetadata:
        """Upload ciphertext plus its encrypted file header."""
        raise NotImplementedError

    @abstractmethod
    def list_files(self, jwt: str) -> list[FileMetadata]:
        """List ciphertext objects visible to the authenticated user."""
        raise NotImplementedError

    @abstractmethod
    def get_file_metadata(self, jwt: str, file_id: str) -> FileMetadata:
        """Return metadata for one ciphertext object."""
        raise NotImplementedError

    @abstractmethod
    def download_file(self, jwt: str, file_id: str, destination_path: Path) -> EncryptedFileHeader:
        """Download ciphertext to `destination_path` and return its header."""
        raise NotImplementedError
