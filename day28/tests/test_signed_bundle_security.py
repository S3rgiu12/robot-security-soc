"""Day 28 - Self-contained signed bundle security tests."""

import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from day27.report_integrity import ReportIntegrityError
from day28.secure_signed_bundle_verifier import verify_signed_bundle


CASE_ID = "INC-CI-TEST001"


class SignedBundleSecurityTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.root = Path(self.temp.name)
        self.export_root = self.root / "exports"
        self.signature_root = self.root / "signatures"

        self.bundle = self.export_root / CASE_ID
        self.signature_dir = self.signature_root / CASE_ID

        self.bundle.mkdir(parents=True)
        self.signature_dir.mkdir(parents=True)

        contents = {
            "incident-report.json": b'{"case_id":"INC-CI-TEST001"}\n',
            "evidence.csv": b"id,event\n1,TEST_EVENT\n",
            "audit.csv": b"id,action\n1,CREATED\n",
        }

        metadata = {}

        for filename, data in contents.items():
            (self.bundle / filename).write_bytes(data)

            metadata[filename] = {
                "sha256": hashlib.sha256(data).hexdigest(),
                "size_bytes": len(data),
            }

        manifest = {
            "manifest_type": "SOC_REPORT_INTEGRITY",
            "manifest_version": "1.0",
            "case_id": CASE_ID,
            "generated_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "hash_algorithm": "SHA-256",
            "files": metadata,
        }

        manifest_bytes = (
            json.dumps(manifest, indent=2) + "\n"
        ).encode("utf-8")

        (self.bundle / "manifest.json").write_bytes(
            manifest_bytes
        )

        private_key = Ed25519PrivateKey.generate()

        public_key = private_key.public_key()

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        public_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        self.fingerprint = hashlib.sha256(
            public_der
        ).hexdigest()

        self.public_key = self.root / "public.pem"
        self.public_key.write_bytes(public_pem)

        signature = private_key.sign(manifest_bytes)

        (self.signature_dir / "manifest.sig").write_bytes(
            signature
        )

        self.patcher = patch(
            "day28.trusted_public_key.TRUSTED_PUBLIC_KEY_SHA256",
            self.fingerprint,
        )
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def verify(self, public_key=None):
        return verify_signed_bundle(
            CASE_ID,
            export_root=self.export_root,
            signature_root=self.signature_root,
            public_key_file=(
                public_key
                if public_key is not None
                else self.public_key
            ),
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

        other_public_pem = (
            other_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

        wrong_key_file = self.root / "wrong_public.pem"
        wrong_key_file.write_bytes(other_public_pem)

        with self.assertRaisesRegex(
            ReportIntegrityError,
            "Public key fingerprint mismatch",
        ):
            self.verify(public_key=wrong_key_file)


if __name__ == "__main__":
    unittest.main()
