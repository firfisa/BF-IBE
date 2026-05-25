"""Business-facing encryption and decryption interfaces.

Real cryptographic operations are deferred to phase two. These abstractions
document how the client code will call into direct BasicIdent and FullIdent
implementations from the Boneh-Franklin IBE paper.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterable

from bf_ibe_phase1.models import EncryptedFileHeader, KeyPackage, PublicParameters


class FileEncryptor(ABC):
    """Encrypt a local file for one or more time-bound recipient identities."""

    @abstractmethod
    def encrypt_file(
        self,
        source_path: Path,
        recipients: Iterable[str],
        public_parameters: PublicParameters,
        output_path: Path,
        scheme_mode: str,
    ) -> EncryptedFileHeader:
        """Encrypt `source_path` into direct IBE ciphertext chunks at `output_path`."""
        raise NotImplementedError


class FileDecryptor(ABC):
    """Decrypt a ciphertext file using the matching requested-hour key package."""

    @abstractmethod
    def decrypt_file(
        self,
        ciphertext_path: Path,
        header: EncryptedFileHeader,
        key_package: KeyPackage,
        output_path: Path,
    ) -> Path:
        """Decrypt direct IBE ciphertext chunks from `ciphertext_path` into `output_path`."""
        raise NotImplementedError
