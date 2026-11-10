"""Day 27 - SHA-256 integrity tests."""

import hashlib
import tempfile
import unittest
from pathlib import Path

from day27.report_integrity import (
    ReportIntegrityError,
    sha256_bytes,
    sha256_text,
    sha256_file,
    verify_sha256,
    verify_file,
)


class TestReportIntegrity(unittest.TestCase):

    def test_sha256_known_value(self):
        expected = hashlib.sha256(b"abc").hexdigest()
        self.assertEqual(sha256_bytes(b"abc"), expected)

    def test_empty_bytes(self):
        expected = hashlib.sha256(b"").hexdigest()
        self.assertEqual(sha256_bytes(b""), expected)

    def test_unicode_text(self):
        value = "Robot securitate - Braila 🔐"
        expected = hashlib.sha256(
            value.encode("utf-8")
        ).hexdigest()
        self.assertEqual(sha256_text(value), expected)

    def test_original_content_valid(self):
        data = b'{"status":"OPEN"}'
        digest = sha256_bytes(data)
        self.assertTrue(verify_sha256(data, digest))

    def test_modified_content_rejected(self):
        original = b'{"status":"OPEN"}'
        modified = b'{"status":"CLOSED"}'
        digest = sha256_bytes(original)
        self.assertFalse(verify_sha256(modified, digest))

    def test_invalid_hash_rejected(self):
        with self.assertRaises(ReportIntegrityError):
            verify_sha256(b"test", "invalid")

    def test_invalid_input_rejected(self):
        with self.assertRaises(ReportIntegrityError):
            sha256_bytes("not bytes")

    def test_file_integrity(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            path.write_bytes(b'{"incident":"TEST"}')

            digest = sha256_file(path)

            self.assertTrue(verify_file(path, digest))

            path.write_bytes(b'{"incident":"MODIFIED"}')

            self.assertFalse(verify_file(path, digest))

    def test_missing_file_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "missing.json"

            with self.assertRaises(ReportIntegrityError):
                sha256_file(path)


if __name__ == "__main__":
    unittest.main()
