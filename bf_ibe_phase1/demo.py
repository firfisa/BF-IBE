"""Command-line demo for the BF-IBE enterprise file distribution PoC."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter

from bf_ibe_phase1.auth import AuthService
from bf_ibe_phase1.crypto_core import ToyBFIBE
from bf_ibe_phase1.demo_services import FileService, PKGService, ServiceError
from bf_ibe_phase1.direct_file_crypto import DirectIBEFileDecryptor, DirectIBEFileEncryptor


def main() -> None:
    print("BF-IBE 企业文件分发 PoC 演示")
    print("注意：当前 crypto core 是教学用 toy pairing 模型，不是生产级密码库。")
    print()

    with TemporaryDirectory(prefix="bf_ibe_demo_") as tmp:
        workdir = Path(tmp)
        auth = AuthService.demo()
        ibe = ToyBFIBE.setup_demo()
        pkg = PKGService(auth, ibe)
        file_service = FileService(auth, workdir / "storage")
        encryptor = DirectIBEFileEncryptor(ibe)
        decryptor = DirectIBEFileDecryptor(ibe)

        alice_token = auth.login("alice@company.com", "demo-password")
        bob_token = auth.login("bob@company.com", "demo-password")

        plaintext_path = workdir / "finance-report.txt"
        ciphertext_path = workdir / "finance-report.bfibe"
        download_path = workdir / "downloaded.bfibe"
        decrypted_path = workdir / "finance-report.decrypted.txt"
        plaintext = (
            b"Quarterly finance report for Bob. "
            b"This file was encrypted at 02:00 and opened later."
        )
        plaintext_path.write_bytes(plaintext)

        print("1. Alice 登录并获取公共参数")
        params = pkg.get_public_parameters(alice_token)
        print(f"   params.version = {params.version}")

        print("2. Alice 使用 FullIdent 直接加密文件 chunk，发送给 Bob，身份小时=2026-05-17-02")
        header = encryptor.encrypt_file(
            source_path=plaintext_path,
            recipients=["bob@company.com"],
            public_parameters=params,
            output_path=ciphertext_path,
            scheme_mode="FullIdent",
            encryption_hour="2026-05-17-02",
        )
        metadata = file_service.upload_file(alice_token, ciphertext_path, header)
        print(f"   uploaded file_id = {metadata.file_id}")
        print(f"   recipient identity = {header.recipient_ids[0]}")

        print("3. Bob 08:00 访问 02:00 文件：文件服务先校验 Bob 仍 active，再返回密文")
        downloaded_header = file_service.download_file(bob_token, metadata.file_id, download_path)
        key_package = pkg.get_private_key(bob_token, "2026-05-17-02")
        decryptor.decrypt_file(download_path, downloaded_header, key_package, decrypted_path)
        print(f"   decrypted plaintext = {decrypted_path.read_text()}")

        print("4. Bob 离职后再次访问：文件服务拒绝下载，PKG 也拒绝发放任意小时私钥")
        auth.set_active("bob@company.com", False)
        _print_denial("file service", lambda: file_service.download_file(bob_token, metadata.file_id, workdir / "denied.bfibe"))
        _print_denial("pkg service", lambda: pkg.get_private_key(bob_token, "2026-05-17-02"))

        print("5. BasicIdent vs FullIdent 简单性能对比")
        for mode in ("BasicIdent", "FullIdent"):
            encrypt_ms, decrypt_ms = _benchmark_mode(ibe, mode)
            target = "IND-ID-CPA" if mode == "BasicIdent" else "IND-ID-CCA"
            print(f"   {mode:10s} ({target}) encrypt={encrypt_ms:.3f}ms decrypt={decrypt_ms:.3f}ms")


def _print_denial(label: str, action) -> None:
    try:
        action()
    except ServiceError as exc:
        print(f"   {label}: {exc.status_code} {exc.message}")
    else:
        raise RuntimeError(f"{label} unexpectedly allowed resigned user")


def _benchmark_mode(ibe: ToyBFIBE, mode: str, repeat: int = 200) -> tuple[float, float]:
    identity = "bench@company.com||2026-05-17-02"
    private_key = ibe.extract_private_key(identity, "bench@company.com")
    message = b"x" * ibe.message_size_bytes

    encrypted = []
    start = perf_counter()
    for index in range(repeat):
        encrypted.append(ibe.encrypt_block(identity, message, mode, index))
    encrypt_ms = (perf_counter() - start) * 1000 / repeat

    start = perf_counter()
    for item in encrypted:
        ibe.decrypt_block(item, private_key)
    decrypt_ms = (perf_counter() - start) * 1000 / repeat
    return encrypt_ms, decrypt_ms


if __name__ == "__main__":
    main()
