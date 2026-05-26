"""Concrete file encryptor/decryptor for the local direct-IBE demo."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import uuid

from bf_ibe_phase1.crypto_core import ToyBFIBE
from bf_ibe_phase1.crypto_interfaces import FileDecryptor, FileEncryptor
from bf_ibe_phase1.models import EncryptedFileHeader, KeyPackage, PublicParameters, TimeBoundIdentity


class DirectIBEFileEncryptor(FileEncryptor):
    def __init__(self, ibe: ToyBFIBE):
        self.ibe = ibe

    def encrypt_file(
        self,
        source_path: Path,
        recipients: list[str],
        public_parameters: PublicParameters,
        output_path: Path,
        scheme_mode: str,
        encryption_hour: str | None = None,
    ) -> EncryptedFileHeader:
        chunk_size = public_parameters.message_size_bits // 8
        if chunk_size <= 0:
            raise ValueError("message_size_bits must be positive")
        hour = encryption_hour or TimeBoundIdentity.for_hour(
            recipients[0],
            _source_mtime_as_utc(source_path),
        ).hour
        plaintext = source_path.read_bytes()
        chunks = [plaintext[i : i + chunk_size] for i in range(0, len(plaintext), chunk_size)]
        if not chunks:
            chunks = [b""]

        ciphertexts = []
        for chunk_index, chunk in enumerate(chunks):
            for recipient in recipients:
                identity = TimeBoundIdentity.for_requested_hour(recipient, hour).identity
                ciphertexts.append(self.ibe.encrypt_block(identity, chunk, scheme_mode, chunk_index))

        payload = {
            "ciphertexts": [asdict(ciphertext) for ciphertext in ciphertexts],
        }
        encoded_payload = json.dumps(payload, sort_keys=True).encode("utf-8")
        output_path.write_bytes(encoded_payload)

        return EncryptedFileHeader(
            file_id=f"file-{uuid.uuid4().hex[:12]}",
            algorithm=f"BF-IBE-{scheme_mode.upper()}-DIRECT-TOY",
            encryption_hour=hour,
            ciphertext_sha256=hashlib.sha256(encoded_payload).hexdigest(),
            recipients=ciphertexts,
            chunk_size_bytes=chunk_size,
            metadata={
                "original_filename": source_path.name,
                "original_size": len(plaintext),
                "demo_notice": "Educational direct IBE ciphertext, not production crypto",
            },
        )


class DirectIBEFileDecryptor(FileDecryptor):
    def __init__(self, ibe: ToyBFIBE):
        self.ibe = ibe

    def decrypt_file(
        self,
        ciphertext_path: Path,
        header: EncryptedFileHeader,
        key_package: KeyPackage,
        output_path: Path,
    ) -> Path:
        actual_digest = hashlib.sha256(ciphertext_path.read_bytes()).hexdigest()
        if actual_digest != header.ciphertext_sha256:
            raise ValueError("ciphertext digest does not match header")
        matching = [
            item
            for item in header.recipients
            if item.time_bound_id == key_package.private_key.time_bound_id
        ]
        if not matching:
            raise ValueError("no ciphertext entries match the provided private key")
        chunks = []
        for item in sorted(matching, key=lambda entry: entry.chunk_index):
            chunks.append(self.ibe.decrypt_block(item, key_package.private_key))
        original_size = int(header.metadata.get("original_size", sum(len(chunk) for chunk in chunks)))
        output_path.write_bytes(b"".join(chunks)[:original_size])
        return output_path


def _source_mtime_as_utc(source_path: Path):
    from datetime import datetime, timezone

    return datetime.fromtimestamp(source_path.stat().st_mtime, tz=timezone.utc)
