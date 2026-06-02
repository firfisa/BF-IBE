"""客户端看到的服务接口契约。

这些是抽象接口，不包含具体网络实现。后续接 FastAPI/HTTP 客户端时，只要
实现这些方法，业务层就不用关心底层是本地对象调用还是 REST API。
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from bf_ibe_phase1.models import (
    EncryptedFileHeader,
    FileMetadata,
    HybridEncryptedFileHeader,
    KeyPackage,
    PublicParameters,
)


FileHeader = EncryptedFileHeader | HybridEncryptedFileHeader


class PKGClient(ABC):
    """PKG 客户端接口：获取公共参数、申请指定小时私钥。"""

    @abstractmethod
    def get_public_parameters(self, jwt: str) -> PublicParameters:
        """获取 BF-IBE 公共参数。"""
        raise NotImplementedError

    @abstractmethod
    def get_private_key(
        self,
        jwt: str,
        requested_hour: str,
        client_time_iso: str | None = None,
    ) -> KeyPackage:
        """申请一个小时的私钥；PKG 会校验用户是否 active。"""
        raise NotImplementedError

    @abstractmethod
    def get_private_keys(
        self,
        jwt: str,
        requested_hours: list[str],
        client_time_iso: str | None = None,
    ) -> list[KeyPackage]:
        """批量申请多个小时的私钥。"""
        raise NotImplementedError


class FileServerClient(ABC):
    """文件服务客户端接口：上传、列表、详情、下载密文。"""

    @abstractmethod
    def upload_file(
        self,
        jwt: str,
        ciphertext_path: Path,
        header: FileHeader,
    ) -> FileMetadata:
        """上传密文文件和 header。"""
        raise NotImplementedError

    @abstractmethod
    def list_files(self, jwt: str) -> list[FileMetadata]:
        """列出当前用户可见的密文文件。"""
        raise NotImplementedError

    @abstractmethod
    def get_file_metadata(self, jwt: str, file_id: str) -> FileMetadata:
        """读取单个密文文件的元数据。"""
        raise NotImplementedError

    @abstractmethod
    def download_file(self, jwt: str, file_id: str, destination_path: Path) -> FileHeader:
        """下载密文到本地路径，并返回解密需要的 header。"""
        raise NotImplementedError
