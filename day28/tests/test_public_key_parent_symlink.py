"""Day 28 - Public key parent directory symlink tests."""

import tempfile
import unittest
from pathlib import Path

from day27.report_integrity import ReportIntegrityError
from day28.secure_crypto_reader import read_trusted_public_key


class PublicKeyParentSymlinkTests(unittest.TestCase):

    def test_parent_directory_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            real_directory = root / "real_keys"
            real_directory.mkdir()

            public_key = real_directory / "public.pem"
            public_key.write_bytes(
                b"-----BEGIN PUBLIC KEY-----\n"
                b"TEST\n"
                b"-----END PUBLIC KEY-----\n"
            )

            linked_directory = root / "linked_keys"
            linked_directory.symlink_to(
                real_directory,
                target_is_directory=True,
            )

            linked_public_key = linked_directory / "public.pem"

            with self.assertRaises(ReportIntegrityError):
                read_trusted_public_key(linked_public_key)

    def test_regular_parent_directory_accepted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)

            key_directory = root / "keys"
            key_directory.mkdir()

            public_key = key_directory / "public.pem"
            expected = (
                b"-----BEGIN PUBLIC KEY-----\n"
                b"TEST\n"
                b"-----END PUBLIC KEY-----\n"
            )

            public_key.write_bytes(expected)

            actual = read_trusted_public_key(public_key)

            self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
