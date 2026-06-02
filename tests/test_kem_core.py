import unittest

from bf_ibe_phase1.crypto_core import BLS12381BFIBE, DecryptReject
from bf_ibe_phase1.encoding import b64decode, b64encode
from bf_ibe_phase1.models import KemCiphertext


class DentFOKEMTests(unittest.TestCase):
    def test_encapsulate_and_decapsulate_return_same_32_byte_key(self):
        ibe = BLS12381BFIBE.setup_demo()
        identity = "bob@company.com||2026-05-17-02"
        private_key = ibe.extract_private_key(identity, "bob@company.com")

        kem_ciphertext, encapsulated_key = ibe.encapsulate_key(identity)
        decapsulated_key = ibe.decapsulate_key(kem_ciphertext, private_key)

        self.assertIsInstance(kem_ciphertext, KemCiphertext)
        self.assertEqual(len(encapsulated_key), 32)
        self.assertEqual(encapsulated_key, decapsulated_key)
        self.assertEqual(len(b64decode(kem_ciphertext.u_b64)), 96)
        self.assertEqual(len(b64decode(kem_ciphertext.v_b64)), 32)
        self.assertFalse(hasattr(kem_ciphertext, "w_b64"))

    def test_decapsulate_rejects_tampered_u_with_uniform_error(self):
        ibe = BLS12381BFIBE.setup_demo()
        identity = "bob@company.com||2026-05-17-02"
        private_key = ibe.extract_private_key(identity, "bob@company.com")
        kem_ciphertext, _ = ibe.encapsulate_key(identity)

        raw_u = bytearray(b64decode(kem_ciphertext.u_b64))
        raw_u[-1] ^= 1
        tampered = KemCiphertext(
            u_b64=b64encode(bytes(raw_u)),
            v_b64=kem_ciphertext.v_b64,
            kem_algorithm=kem_ciphertext.kem_algorithm,
            seed_length_bytes=kem_ciphertext.seed_length_bytes,
            key_length_bytes=kem_ciphertext.key_length_bytes,
        )

        with self.assertRaisesRegex(DecryptReject, "^REJECT$"):
            ibe.decapsulate_key(tampered, private_key)

    def test_decapsulate_rejects_tampered_v_with_uniform_error(self):
        ibe = BLS12381BFIBE.setup_demo()
        identity = "bob@company.com||2026-05-17-02"
        private_key = ibe.extract_private_key(identity, "bob@company.com")
        kem_ciphertext, _ = ibe.encapsulate_key(identity)

        raw_v = bytearray(b64decode(kem_ciphertext.v_b64))
        raw_v[-1] ^= 1
        tampered = KemCiphertext(
            u_b64=kem_ciphertext.u_b64,
            v_b64=b64encode(bytes(raw_v)),
            kem_algorithm=kem_ciphertext.kem_algorithm,
            seed_length_bytes=kem_ciphertext.seed_length_bytes,
            key_length_bytes=kem_ciphertext.key_length_bytes,
        )

        with self.assertRaisesRegex(DecryptReject, "^REJECT$"):
            ibe.decapsulate_key(tampered, private_key)


if __name__ == "__main__":
    unittest.main()
