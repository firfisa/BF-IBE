"""Business-facing encryption and decryption interfaces."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterable

from bf_ibe_phase1.models import EncryptedFileHeader, HybridEncryptedFileHeader, KeyPackage, PublicParameters


FileHeader = EncryptedFileHeader | HybridEncryptedFileHeader


class FileEncryptor(ABC):
    """Encrypt a local file for one or more time-bound recipient identities."""

    @abstractmethod
    def encrypt_file(
        self,
        source_path: Path,
        recipients: Iterable[str],
        public_parameters: PublicParameters,
        output_path: Path,
        scheme_mode: str = "KEMDEM",
    ) -> FileHeader:
        """Encrypt `source_path` into ciphertext and return the matching header."""
        raise NotImplementedError


class FileDecryptor(ABC):
    """Decrypt a ciphertext file using the matching requested-hour key package."""

    @abstractmethod
    def decrypt_file(
        self,
        ciphertext_path: Path,
        header: FileHeader,
        key_package: KeyPackage,
        output_path: Path,
    ) -> Path:
        """Decrypt ciphertext from `ciphertext_path` into `output_path`."""
        raise NotImplementedError
