from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from bf_ibe_phase1.auth import AuthService
from bf_ibe_phase1.crypto_core import ToyBFIBE
from bf_ibe_phase1.demo_services import FileService, PKGService, ServiceError
from bf_ibe_phase1.direct_file_crypto import DirectIBEFileDecryptor, DirectIBEFileEncryptor


class ToyBFIBETests(unittest.TestCase):
    def test_basic_ident_round_trip(self):
        ibe = ToyBFIBE.setup_demo()
        identity = "bob@company.com||2026-05-17-02"
        private_key = ibe.extract_private_key(identity, "bob@company.com")

        ciphertext = ibe.encrypt_block(identity, b"hello bf ibe", "BasicIdent", 0)
        plaintext = ibe.decrypt_block(ciphertext, private_key)

        self.assertEqual(plaintext[:12], b"hello bf ibe")
        self.assertIsNone(ciphertext.w_b64)

    def test_full_ident_rejects_tampered_ciphertext(self):
        ibe = ToyBFIBE.setup_demo()
        identity = "bob@company.com||2026-05-17-02"
        private_key = ibe.extract_private_key(identity, "bob@company.com")
        ciphertext = ibe.encrypt_block(identity, b"attack check", "FullIdent", 0)

        tampered = ciphertext.with_v_b64("AAAA")

        with self.assertRaises(ValueError):
            ibe.decrypt_block(tampered, private_key)


class DemoServiceFlowTests(unittest.TestCase):
    def test_active_user_can_decrypt_old_file_and_resigned_user_is_denied(self):
        with TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            auth = AuthService.demo()
            ibe = ToyBFIBE.setup_demo()
            pkg = PKGService(auth, ibe)
            files = FileService(auth, workdir / "storage")
            encryptor = DirectIBEFileEncryptor(ibe)
            decryptor = DirectIBEFileDecryptor(ibe)

            alice_token = auth.login("alice@company.com", "demo-password")
            bob_token = auth.login("bob@company.com", "demo-password")

            plaintext_path = workdir / "report.txt"
            encrypted_path = workdir / "report.bfibe"
            decrypted_path = workdir / "report.out.txt"
            plaintext_path.write_bytes(b"quarterly report for bob")

            header = encryptor.encrypt_file(
                source_path=plaintext_path,
                recipients=["bob@company.com"],
                public_parameters=pkg.get_public_parameters(alice_token),
                output_path=encrypted_path,
                scheme_mode="FullIdent",
                encryption_hour="2026-05-17-02",
            )
            metadata = files.upload_file(alice_token, encrypted_path, header)

            downloaded_path = workdir / "downloaded.bfibe"
            downloaded_header = files.download_file(bob_token, metadata.file_id, downloaded_path)
            key_package = pkg.get_private_key(bob_token, "2026-05-17-02")
            decryptor.decrypt_file(downloaded_path, downloaded_header, key_package, decrypted_path)

            self.assertEqual(decrypted_path.read_bytes(), b"quarterly report for bob")

            auth.set_active("bob@company.com", False)

            with self.assertRaises(ServiceError):
                files.download_file(bob_token, metadata.file_id, workdir / "denied.bfibe")
            with self.assertRaises(ServiceError):
                pkg.get_private_key(bob_token, "2026-05-17-02")


if __name__ == "__main__":
    unittest.main()
