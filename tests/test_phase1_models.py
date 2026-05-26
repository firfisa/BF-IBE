from datetime import datetime, timezone
import unittest

from bf_ibe_phase1.models import EncryptedFileHeader, RecipientCiphertext, TimeBoundIdentity


class PhaseOneModelTests(unittest.TestCase):
    def test_time_bound_identity_formats_email_and_utc_hour(self):
        moment = datetime(2026, 5, 17, 14, 59, tzinfo=timezone.utc)

        identity = TimeBoundIdentity.for_hour("alice@company.com", moment)

        self.assertEqual(identity.identity, "alice@company.com||2026-05-17-14")
        self.assertEqual(identity.email, "alice@company.com")
        self.assertEqual(identity.hour, "2026-05-17-14")

    def test_time_bound_identity_rejects_malformed_value(self):
        with self.assertRaisesRegex(ValueError, "email\\|\\|YYYY-MM-DD-HH"):
            TimeBoundIdentity.parse("alice@company.com|2026-05-17-14")

    def test_time_bound_identity_can_use_requested_hour(self):
        identity = TimeBoundIdentity.for_requested_hour(
            "Alice@Company.com",
            "2026-05-17-02",
        )

        self.assertEqual(identity.identity, "alice@company.com||2026-05-17-02")
        self.assertEqual(identity.hour, "2026-05-17-02")

    def test_encrypted_file_header_supports_multiple_direct_ibe_ciphertexts(self):
        header = EncryptedFileHeader(
            file_id="file-001",
            algorithm="BF-IBE-FULLIDENT-DIRECT-BLS12-381",
            encryption_hour="2026-05-17-14",
            ciphertext_sha256="abc123",
            recipients=[
                RecipientCiphertext(
                    recipient_email="alice@company.com",
                    time_bound_id="alice@company.com||2026-05-17-14",
                    scheme_mode="FullIdent",
                    chunk_index=0,
                    u_b64="u-a",
                    v_b64="v-a",
                    w_b64="w-a",
                ),
                RecipientCiphertext(
                    recipient_email="bob@company.com",
                    time_bound_id="bob@company.com||2026-05-17-14",
                    scheme_mode="BasicIdent",
                    chunk_index=0,
                    u_b64="u-b",
                    v_b64="v-b",
                ),
            ],
        )

        self.assertEqual(header.recipient_count, 2)
        self.assertTrue(header.recipients[0].is_full_ident)
        self.assertFalse(header.recipients[1].is_full_ident)
        self.assertEqual(
            header.recipient_ids,
            [
                "alice@company.com||2026-05-17-14",
                "bob@company.com||2026-05-17-14",
            ],
        )


if __name__ == "__main__":
    unittest.main()
