"""文件加解密器。

这里把“论文只能加密固定长度消息 M”的限制适配到文件场景：

1. 读取文件明文；
2. 按 `message_size_bits` 切成固定大小 chunk；
3. 对每个接收者、每个 chunk 调用 BasicIdent 或 FullIdent；
4. 生成 `EncryptedFileHeader`，里面记录每个 chunk 的 U/V/W。

注意：这是当前“直接 IBE 加密 chunk”的演示路径；后续如果改成
KEM-DEM/AES-GCM，大文件正文会改由 AES-GCM 加密，IBE 只封装会话密钥。
"""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import uuid

from bf_ibe_phase1.crypto_core import BLS12381BFIBE, ToyBFIBE
from bf_ibe_phase1.crypto_interfaces import FileDecryptor, FileEncryptor
from bf_ibe_phase1.models import EncryptedFileHeader, KeyPackage, PublicParameters, TimeBoundIdentity


class DirectIBEFileEncryptor(FileEncryptor):
    """把普通文件转换成 direct IBE 密文文件和 header。"""

    def __init__(self, ibe: BLS12381BFIBE | ToyBFIBE):
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
        # PublicParameters.message_size_bits 对应论文中 M 的长度 n。
        chunk_size = public_parameters.message_size_bits // 8
        if chunk_size <= 0:
            raise ValueError("message_size_bits must be positive")
        hour = encryption_hour or TimeBoundIdentity.for_hour(
            recipients[0],
            _source_mtime_as_utc(source_path),
        ).hour
        plaintext = source_path.read_bytes()
        # 空文件也要产生一个空 chunk，方便演示上传/下载流程完整执行。
        chunks = [plaintext[i : i + chunk_size] for i in range(0, len(plaintext), chunk_size)]
        if not chunks:
            chunks = [b""]

        ciphertexts = []
        for chunk_index, chunk in enumerate(chunks):
            for recipient in recipients:
                # IBE 的“公钥”就是字符串 ID：邮箱 + 文件加密小时。
                identity = TimeBoundIdentity.for_requested_hour(recipient, hour).identity
                ciphertexts.append(self.ibe.encrypt_block(identity, chunk, scheme_mode, chunk_index))

        # 存储文件本体时只保存密文块；header 会单独交给文件服务保存/返回。
        payload = {
            "ciphertexts": [asdict(ciphertext) for ciphertext in ciphertexts],
        }
        encoded_payload = json.dumps(payload, sort_keys=True).encode("utf-8")
        output_path.write_bytes(encoded_payload)

        return EncryptedFileHeader(
            file_id=f"file-{uuid.uuid4().hex[:12]}",
            algorithm=f"BF-IBE-{scheme_mode.upper()}-DIRECT-{public_parameters.curve}",
            encryption_hour=hour,
            ciphertext_sha256=hashlib.sha256(encoded_payload).hexdigest(),
            recipients=ciphertexts,
            chunk_size_bytes=chunk_size,
            metadata={
                "original_filename": source_path.name,
                # 解密时要把最后一个 chunk 的 padding 去掉，所以保存原始长度。
                "original_size": len(plaintext),
                "demo_notice": "Direct BasicIdent/FullIdent ciphertext for coursework PoC; KEM-DEM remains the large-file production path.",
            },
        )


class DirectIBEFileDecryptor(FileDecryptor):
    """用 PKG 返回的私钥包恢复文件明文。"""

    def __init__(self, ibe: BLS12381BFIBE | ToyBFIBE):
        self.ibe = ibe

    def decrypt_file(
        self,
        ciphertext_path: Path,
        header: EncryptedFileHeader,
        key_package: KeyPackage,
        output_path: Path,
    ) -> Path:
        # 文件服务保存的密文如果被改过，这里先用 header 中的 hash 拦截。
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
        # 同一个接收者会有多个 chunk，必须按 chunk_index 拼回原文件顺序。
        for item in sorted(matching, key=lambda entry: entry.chunk_index):
            chunks.append(self.ibe.decrypt_block(item, key_package.private_key))
        original_size = int(header.metadata.get("original_size", sum(len(chunk) for chunk in chunks)))
        output_path.write_bytes(b"".join(chunks)[:original_size])
        return output_path


def _source_mtime_as_utc(source_path: Path):
    from datetime import datetime, timezone

    return datetime.fromtimestamp(source_path.stat().st_mtime, tz=timezone.utc)
