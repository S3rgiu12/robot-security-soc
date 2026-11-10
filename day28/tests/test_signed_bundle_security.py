"""Day 28 - Signed bundle security tests."""

import shutil
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from day28.secure_signed_bundle_verifier import verify_signed_bundle


ROOT = Path(__file__).resolve().parents[2]
CASE_ID = "INC-CAC40C42F3254074"


class SignedBundleSecurityTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.root = Path(self.temp.name)

        self.export_root = self.root / "exports"
        self.signature_root = self.root / "signatures"

        self.bundle = self.export_root / CASE_ID
        self.signature_dir = self.signature_root / CASE_ID

        self.bundle.parent.mkdir(parents=True)
        self.signature_dir.mkdir(parents=True)

        shutil.copytree(
            ROOT / "day27" / "exports" / CASE_ID,
            self.bundle,
        )

        shutil.copy2(
            ROOT / "day28" / "signatures" / CASE_ID / "manifest.sig",
            self.signature_dir / "manifest.sig",
        )

        self.public_key = (
            ROOT / "day28" / "keys" / "soc_signing_public.pem"
        )

    def verify(self, public_key=None):
        return verify_signed_bundle(
            CASE_ID,
            export_root=self.export_root,
            signature_root=self.signature_root,
            public_key_file=public_key or self.public_key,
        )

    def test_original_bundle_valid(self):
        result = self.verify()

        self.assertEqual(result["signature_status"], "VALID")
        self.assertEqual(result["integrity_status"], "VALID")
        self.assertEqual(result["verified_count"], 3)
        self.assertEqual(result["status"], "SIGNED & VERIFIED")

    def test_modified_csv_rejected(self):
        csv_file = self.bundle / "evidence.csv"

        with csv_file.open("ab") as file:
            file.write(b"\nUNAUTHORIZED,CHANGE\n")

        result = self.verify()

        self.assertEqual(result["signature_status"], "VALID")
        self.assertEqual(result["integrity_status"], "INVALID")
        self.assertFalse(result["files"]["evidence.csv"])
        self.assertEqual(result["status"], "VERIFICATION FAILED")

    def test_modified_signature_rejected(self):
        signature_file = self.signature_dir / "manifest.sig"

        data = bytearray(signature_file.read_bytes())
        data[0] ^= 0x01
        signature_file.write_bytes(data)

        result = self.verify()

        self.assertEqual(result["signature_status"], "INVALID")
        self.assertEqual(result["status"], "VERIFICATION FAILED")

    def test_wrong_public_key_rejected(self):
        other_private_key = Ed25519PrivateKey.generate()

        other_public_pem = other_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        wrong_key_file = self.root / "wrong_public.pem"
        wrong_key_file.write_bytes(other_public_pem)

        from day27.report_integrity import ReportIntegrityError

        with self.assertRaisesRegex(
            ReportIntegrityError,
            "Public key fingerprint mismatch",
        ):
            self.verify(public_key=wrong_key_file)


if __name__ == "__main__":
    unittest.main()
