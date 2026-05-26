"""演示用的 PKG 服务和文件服务。

这里没有启动 HTTP 服务，而是把 FastAPI 将来会调用的核心业务逻辑先做成
普通 Python 类，便于测试和命令行演示。

安全边界：
- PKGService: 校验用户 active 后，按请求小时派生 IBE 私钥。
- FileService: 校验用户 active 且是 owner/recipient 后，才允许列表/下载。
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import shutil

from bf_ibe_phase1.auth import AuthError, AuthService
from bf_ibe_phase1.crypto_core import BLS12381BFIBE, ToyBFIBE
from bf_ibe_phase1.models import EncryptedFileHeader, FileMetadata, KeyPackage, TimeBoundIdentity


class ServiceError(Exception):
    """用类似 HTTP 的 status_code 表达服务层错误。"""

    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.message = message


def _service_error(exc: AuthError) -> ServiceError:
    """把认证层异常转换成服务层异常：未登录 401，离职/禁用 403。"""
    text = str(exc)
    status = 403 if "inactive" in text else 401
    return ServiceError(status, text)


class PKGService:
    """Private Key Generator。

    它唯一持有 BF-IBE master secret 的对象 `ibe`，客户端只能通过这里申请
    指定小时的私钥。是否能申请，不取决于小时是否过期，只取决于用户当前
    是否仍是 active 员工。
    """

    def __init__(self, auth: AuthService, ibe: BLS12381BFIBE | ToyBFIBE):
        self.auth = auth
        self.ibe = ibe

    def get_public_parameters(self, jwt: str):
        """返回公共参数前也检查 active，避免离职用户继续拿系统参数。"""
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
        """按请求小时发放私钥。

        例子：Bob 08:00 访问 02:00 文件时，请求 `2026-05-17-02`，
        PKG 会派生 `bob@company.com||2026-05-17-02` 的私钥。
        """
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
        """批量申请多个小时的私钥，方便客户端一次处理多个旧文件。"""
        return [
            self.get_private_key(jwt, requested_hour, client_time_iso)
            for requested_hour in requested_hours
        ]


class FileService:
    """密文仓库服务。

    文件服务不解密、不持有用户私钥，只做三件事：
    - 保存密文文件和 header；
    - 根据 owner/recipient 控制访问；
    - 在任何文件操作前检查用户是否 active。
    """

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
        """上传密文。上传者会成为 owner。"""
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
        """只列出当前 active 用户拥有或被授权接收的文件。"""
        principal = self._active_principal(jwt)
        return [
            metadata
            for metadata in self._metadata.values()
            if self._can_access(principal.email, metadata)
        ]

    def get_file_metadata(self, jwt: str, file_id: str) -> FileMetadata:
        """读取 header/metadata 前也要做 active + ACL 校验。"""
        principal = self._active_principal(jwt)
        metadata = self._require_metadata(file_id)
        if not self._can_access(principal.email, metadata):
            raise ServiceError(403, "user is not allowed to access this file")
        return metadata

    def download_file(self, jwt: str, file_id: str, destination_path: Path) -> EncryptedFileHeader:
        """下载密文文件。

        离职用户会在这里被第一时间拒绝，拿不到密文和 header；PKG 的
        active 校验是第二道防线。
        """
        principal = self._active_principal(jwt)
        metadata = self._require_metadata(file_id)
        if not self._can_access(principal.email, metadata):
            raise ServiceError(403, "user is not allowed to download this file")
        shutil.copyfile(self._paths[file_id], destination_path)
        return self._headers[file_id]

    def _active_principal(self, jwt: str):
        """所有文件服务入口共用的 active 校验。"""
        try:
            return self.auth.ensure_active(jwt)
        except AuthError as exc:
            raise _service_error(exc) from exc

    def _require_metadata(self, file_id: str) -> FileMetadata:
        """查找文件元数据，不存在时模拟 HTTP 404。"""
        metadata = self._metadata.get(file_id)
        if metadata is None:
            raise ServiceError(404, "file not found")
        return metadata

    def _can_access(self, email: str, metadata: FileMetadata) -> bool:
        """文件 ACL：上传者 owner 或收件人 recipient 可以访问。"""
        return email == metadata.owner_email or email in metadata.recipients
