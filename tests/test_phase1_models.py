from datetime import datetime, timezone
import unittest

from bf_ibe_phase1.models import EncryptedFileHeader, RecipientCapsule, TimeBoundIdentity


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

    def test_encrypted_file_header_supports_multiple_recipient_capsules(self):
        header = EncryptedFileHeader(
            file_id="file-001",
            algorithm="BF-IBE-FULL-KEM+A256GCM",
            encryption_hour="2026-05-17-14",
            nonce_b64="nonce",
            aad_b64="aad",
            ciphertext_sha256="abc123",
            recipients=[
                RecipientCapsule(
                    recipient_email="alice@company.com",
                    time_bound_id="alice@company.com||2026-05-17-14",
                    ibe_capsule_b64="capsule-a",
                    encrypted_file_key_b64="key-a",
                ),
                RecipientCapsule(
                    recipient_email="bob@company.com",
                    time_bound_id="bob@company.com||2026-05-17-14",
                    ibe_capsule_b64="capsule-b",
                    encrypted_file_key_b64="key-b",
                ),
            ],
        )

        self.assertEqual(header.recipient_count, 2)
        self.assertEqual(
            header.recipient_ids,
            [
                "alice@company.com||2026-05-17-14",
                "bob@company.com||2026-05-17-14",
            ],
        )


if __name__ == "__main__":
    unittest.main()
