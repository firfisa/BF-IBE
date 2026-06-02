"""BF-IBE Dent/FO KEM + AES-GCM DEM 文件加解密器。"""

from __future__ import annotations

import hashlib
from pathlib import Path
import secrets
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from bf_ibe_phase1.crypto_core import BLS12381BFIBE, DecryptReject
from bf_ibe_phase1.crypto_interfaces import FileDecryptor, FileEncryptor
from bf_ibe_phase1.encoding import b64decode, b64encode
from bf_ibe_phase1.models import (
    HybridEncryptedFileHeader,
    KeyPackage,
    PublicParameters,
    RecipientKeyEnvelope,
    TimeBoundIdentity,
)


HYBRID_ALGORITHM = "BF-IBE-DENT-FO-KEMDEM-BLS12-381-AES-256-GCM"
DEM_ALGORITHM = "AES-256-GCM"
AES_GCM_KEY_BYTES = 32
AES_GCM_IV_BYTES = 12
AES_GCM_TAG_BYTES = 16


class HybridKEMDEMFileEncryptor(FileEncryptor):
    """Encrypt a file once with AES-GCM and wrap its file key per recipient."""

    def __init__(self, ibe: BLS12381BFIBE):
        self.ibe = ibe

    def encrypt_file(
        self,
        source_path: Path,
        recipients: list[str],
        public_parameters: PublicParameters,
        output_path: Path,
        scheme_mode: str = "KEMDEM",
        encryption_hour: str | None = None,
    ) -> HybridEncryptedFileHeader:
        del scheme_mode
        if not recipients:
            raise ValueError("at least one recipient is required")
        hour = encryption_hour or TimeBoundIdentity.for_hour(
            recipients[0],
            _source_mtime_as_utc(source_path),
        ).hour

        plaintext = source_path.read_bytes()
        file_key = secrets.token_bytes(AES_GCM_KEY_BYTES)
        dem_iv = secrets.token_bytes(AES_GCM_IV_BYTES)
        dem_aad = _dem_aad(hour)
        dem_combined = AESGCM(file_key).encrypt(dem_iv, plaintext, dem_aad)
        dem_ciphertext = dem_combined[:-AES_GCM_TAG_BYTES]
        dem_tag = dem_combined[-AES_GCM_TAG_BYTES:]
        output_path.write_bytes(dem_ciphertext)

        envelopes = []
        for recipient in recipients:
            identity = TimeBoundIdentity.for_requested_hour(recipient, hour).identity
            kem_ciphertext, kem_key = self.ibe.encapsulate_key(identity)
            wrap_iv = secrets.token_bytes(AES_GCM_IV_BYTES)
            wrapped_file_key = AESGCM(kem_key).encrypt(
                wrap_iv,
                file_key,
                _wrap_aad(identity, kem_ciphertext.u_b64, kem_ciphertext.v_b64),
            )
            envelopes.append(
                RecipientKeyEnvelope(
                    recipient_email=recipient.strip().lower(),
                    time_bound_id=identity,
                    kem_ciphertext=kem_ciphertext,
                    wrap_iv_b64=b64encode(wrap_iv),
                    wrapped_file_key_b64=b64encode(wrapped_file_key),
                )
            )

        return HybridEncryptedFileHeader(
            file_id=f"file-{uuid.uuid4().hex[:12]}",
            algorithm=HYBRID_ALGORITHM,
            encryption_hour=hour,
            dem_algorithm=DEM_ALGORITHM,
            dem_iv_b64=b64encode(dem_iv),
            dem_tag_b64=b64encode(dem_tag),
            recipient_envelopes=envelopes,
            ciphertext_sha256=hashlib.sha256(dem_ciphertext).hexdigest(),
            metadata={
                "original_filename": source_path.name,
                "original_size": len(plaintext),
                "public_parameters_version": public_parameters.version,
            },
        )


class HybridKEMDEMFileDecryptor(FileDecryptor):
    """Decrypt a KEM/DEM ciphertext using the matching requested-hour key."""

    def __init__(self, ibe: BLS12381BFIBE):
        self.ibe = ibe

    def decrypt_file(
        self,
        ciphertext_path: Path,
        header: HybridEncryptedFileHeader,
        key_package: KeyPackage,
        output_path: Path,
    ) -> Path:
        try:
            dem_ciphertext = ciphertext_path.read_bytes()
            if hashlib.sha256(dem_ciphertext).hexdigest() != header.ciphertext_sha256:
                raise DecryptReject()

            envelope = _matching_envelope(header, key_package)
            kem_key = self.ibe.decapsulate_key(envelope.kem_ciphertext, key_package.private_key)
            file_key = AESGCM(kem_key).decrypt(
                b64decode(envelope.wrap_iv_b64),
                b64decode(envelope.wrapped_file_key_b64),
                _wrap_aad(envelope.time_bound_id, envelope.kem_ciphertext.u_b64, envelope.kem_ciphertext.v_b64),
            )
            plaintext = AESGCM(file_key).decrypt(
                b64decode(header.dem_iv_b64),
                dem_ciphertext + b64decode(header.dem_tag_b64),
                _dem_aad(header.encryption_hour),
            )
            output_path.write_bytes(plaintext)
            return output_path
        except DecryptReject:
            raise
        except Exception as exc:
            raise DecryptReject() from exc


def _matching_envelope(header: HybridEncryptedFileHeader, key_package: KeyPackage) -> RecipientKeyEnvelope:
    for envelope in header.recipient_envelopes:
        if envelope.time_bound_id == key_package.private_key.time_bound_id:
            return envelope
    raise DecryptReject()


def _dem_aad(encryption_hour: str) -> bytes:
    return f"{HYBRID_ALGORITHM}|{DEM_ALGORITHM}|{encryption_hour}".encode("utf-8")


def _wrap_aad(time_bound_id: str, u_b64: str, v_b64: str) -> bytes:
    return f"{HYBRID_ALGORITHM}|{time_bound_id}|{u_b64}|{v_b64}".encode("utf-8")


def _source_mtime_as_utc(source_path: Path):
    from datetime import datetime, timezone

    return datetime.fromtimestamp(source_path.stat().st_mtime, tz=timezone.utc)
