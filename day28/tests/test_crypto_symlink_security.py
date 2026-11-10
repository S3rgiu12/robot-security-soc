"""Day 28 - Symlink protection tests for cryptographic files."""

import tempfile
import unittest
from pathlib import Path

from day27.report_integrity import ReportIntegrityError
from day28.secure_crypto_reader import (
    read_detached_signature,
    read_trusted_public_key,
)

CASE_ID = "INC-CAC40C42F3254074"


class CryptoSymlinkSecurityTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.root = Path(self.temp.name)
        self.signature_root = self.root / "signatures"
        self.signature_root.mkdir()

        self.case_dir = self.signature_root / CASE_ID
        self.case_dir.mkdir()

        self.real_signature = self.root / "real_signature.bin"
        self.real_signature.write_bytes(b"A" * 64)

        self.real_public_key = self.root / "real_public.pem"
        self.real_public_key.write_bytes(
            b"-----BEGIN PUBLIC KEY-----\n"
            b"TEST\n"
            b"-----END PUBLIC KEY-----\n"
        )

    def test_signature_file_symlink_rejected(self):
        link = self.case_dir / "manifest.sig"
        link.symlink_to(self.real_signature)

        with self.assertRaises(ReportIntegrityError):
            read_detached_signature(
                CASE_ID,
                self.signature_root,
            )

    def test_signature_directory_symlink_rejected(self):
        self.case_dir.rmdir()

        target_dir = self.root / "other_case"
        target_dir.mkdir()
        (target_dir / "manifest.sig").write_bytes(b"A" * 64)

        self.case_dir.symlink_to(
            target_dir,
            target_is_directory=True,
        )

        with self.assertRaises(ReportIntegrityError):
            read_detached_signature(
                CASE_ID,
                self.signature_root,
            )

    def test_public_key_symlink_rejected(self):
        link = self.root / "linked_public.pem"
        link.symlink_to(self.real_public_key)

        with self.assertRaises(ReportIntegrityError):
            read_trusted_public_key(link)


if __name__ == "__main__":
    unittest.main()
