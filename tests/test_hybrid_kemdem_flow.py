from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from bf_ibe_phase1.auth import AuthService
from bf_ibe_phase1.crypto_core import BLS12381BFIBE, DecryptReject
from bf_ibe_phase1.demo_services import FileService, PKGService, ServiceError
from bf_ibe_phase1.encoding import b64decode, b64encode
from bf_ibe_phase1.hybrid_file_crypto import HybridKEMDEMFileDecryptor, HybridKEMDEMFileEncryptor


class HybridKEMDEMFlowTests(unittest.TestCase):
    def test_one_dem_ciphertext_can_be_opened_by_multiple_recipient_envelopes(self):
        with TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            auth = AuthService.demo()
            ibe = BLS12381BFIBE.setup_demo()
            pkg = PKGService(auth, ibe)
            files = FileService(auth, workdir / "storage")
            encryptor = HybridKEMDEMFileEncryptor(ibe)
            decryptor = HybridKEMDEMFileDecryptor(ibe)

            alice_token = auth.login("alice@company.com", "demo-password")
            bob_token = auth.login("bob@company.com", "demo-password")
            admin_token = auth.login("admin@company.com", "demo-password")

            plaintext = b"hybrid kem dem report for two recipients"
            plaintext_path = workdir / "report.txt"
            encrypted_path = workdir / "report.bfibe"
            plaintext_path.write_bytes(plaintext)

            header = encryptor.encrypt_file(
                source_path=plaintext_path,
                recipients=["bob@company.com", "admin@company.com"],
                public_parameters=pkg.get_public_parameters(alice_token),
                output_path=encrypted_path,
                encryption_hour="2026-05-17-02",
            )
            metadata = files.upload_file(alice_token, encrypted_path, header)

            self.assertEqual(header.algorithm, "BF-IBE-DENT-FO-KEMDEM-BLS12-381-AES-256-GCM")
            self.assertEqual(header.dem_algorithm, "AES-256-GCM")
            self.assertEqual(header.recipient_count, 2)
            self.assertEqual(len(header.recipient_envelopes), 2)
            self.assertEqual(len({item.kem_ciphertext.u_b64 for item in header.recipient_envelopes}), 2)
            self.assertNotIn(plaintext, encrypted_path.read_bytes())
            self.assertEqual(metadata.recipients, ["admin@company.com", "bob@company.com"])

            bob_download = workdir / "bob-download.bfibe"
            bob_output = workdir / "bob-output.txt"
            bob_header = files.download_file(bob_token, metadata.file_id, bob_download)
            bob_key = pkg.get_private_key(bob_token, "2026-05-17-02")
            decryptor.decrypt_file(bob_download, bob_header, bob_key, bob_output)
            self.assertEqual(bob_output.read_bytes(), plaintext)

            admin_download = workdir / "admin-download.bfibe"
            admin_output = workdir / "admin-output.txt"
            admin_header = files.download_file(admin_token, metadata.file_id, admin_download)
            admin_key = pkg.get_private_key(admin_token, "2026-05-17-02")
            decryptor.decrypt_file(admin_download, admin_header, admin_key, admin_output)
            self.assertEqual(admin_output.read_bytes(), plaintext)

    def test_hybrid_decrypt_rejects_tampered_dem_ciphertext_with_uniform_error(self):
        with TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            auth = AuthService.demo()
            ibe = BLS12381BFIBE.setup_demo()
            pkg = PKGService(auth, ibe)
            encryptor = HybridKEMDEMFileEncryptor(ibe)
            decryptor = HybridKEMDEMFileDecryptor(ibe)

            alice_token = auth.login("alice@company.com", "demo-password")
            bob_token = auth.login("bob@company.com", "demo-password")
            plaintext_path = workdir / "report.txt"
            encrypted_path = workdir / "report.bfibe"
            tampered_path = workdir / "tampered.bfibe"
            plaintext_path.write_bytes(b"tamper me")
            header = encryptor.encrypt_file(
                source_path=plaintext_path,
                recipients=["bob@company.com"],
                public_parameters=pkg.get_public_parameters(alice_token),
                output_path=encrypted_path,
                encryption_hour="2026-05-17-02",
            )
            raw = bytearray(encrypted_path.read_bytes())
            raw[-1] ^= 1
            tampered_path.write_bytes(bytes(raw))

            key_package = pkg.get_private_key(bob_token, "2026-05-17-02")
            with self.assertRaisesRegex(DecryptReject, "^REJECT$"):
                decryptor.decrypt_file(tampered_path, header, key_package, workdir / "out.txt")

    def test_hybrid_decrypt_rejects_tampered_recipient_envelope_with_uniform_error(self):
        with TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            auth = AuthService.demo()
            ibe = BLS12381BFIBE.setup_demo()
            pkg = PKGService(auth, ibe)
            encryptor = HybridKEMDEMFileEncryptor(ibe)
            decryptor = HybridKEMDEMFileDecryptor(ibe)

            alice_token = auth.login("alice@company.com", "demo-password")
            bob_token = auth.login("bob@company.com", "demo-password")
            plaintext_path = workdir / "report.txt"
            encrypted_path = workdir / "report.bfibe"
            plaintext_path.write_bytes(b"wrapped key tamper")
            header = encryptor.encrypt_file(
                source_path=plaintext_path,
                recipients=["bob@company.com"],
                public_parameters=pkg.get_public_parameters(alice_token),
                output_path=encrypted_path,
                encryption_hour="2026-05-17-02",
            )

            envelope = header.recipient_envelopes[0]
            raw_wrapped_key = bytearray(b64decode(envelope.wrapped_file_key_b64))
            raw_wrapped_key[-1] ^= 1
            tampered_envelope = replace(envelope, wrapped_file_key_b64=b64encode(bytes(raw_wrapped_key)))
            tampered_header = replace(header, recipient_envelopes=[tampered_envelope])

            key_package = pkg.get_private_key(bob_token, "2026-05-17-02")
            with self.assertRaisesRegex(DecryptReject, "^REJECT$"):
                decryptor.decrypt_file(encrypted_path, tampered_header, key_package, workdir / "out.txt")

    def test_resigned_user_is_denied_before_hybrid_decrypt(self):
        with TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            auth = AuthService.demo()
            ibe = BLS12381BFIBE.setup_demo()
            pkg = PKGService(auth, ibe)
            files = FileService(auth, workdir / "storage")
            encryptor = HybridKEMDEMFileEncryptor(ibe)

            alice_token = auth.login("alice@company.com", "demo-password")
            bob_token = auth.login("bob@company.com", "demo-password")
            plaintext_path = workdir / "report.txt"
            encrypted_path = workdir / "report.bfibe"
            plaintext_path.write_bytes(b"resignation test")
            header = encryptor.encrypt_file(
                source_path=plaintext_path,
                recipients=["bob@company.com"],
                public_parameters=pkg.get_public_parameters(alice_token),
                output_path=encrypted_path,
                encryption_hour="2026-05-17-02",
            )
            metadata = files.upload_file(alice_token, encrypted_path, header)

            auth.set_active("bob@company.com", False)

            with self.assertRaises(ServiceError):
                files.download_file(bob_token, metadata.file_id, workdir / "denied.bfibe")
            with self.assertRaises(ServiceError):
                pkg.get_private_key(bob_token, "2026-05-17-02")


if __name__ == "__main__":
    unittest.main()
