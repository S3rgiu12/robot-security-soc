"""Day 27 - Controlled bundle access tests."""

import tempfile
import unittest
from pathlib import Path

from day27.bundle_access import get_bundle_directory
from day27.report_integrity import ReportIntegrityError


class TestBundleAccess(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

        self.root = Path(self.tmp.name) / "exports"
        self.root.mkdir()

        self.case_id = "INC-TEST123"
        self.bundle = self.root / self.case_id
        self.bundle.mkdir()

    def test_valid_incident(self):
        result = get_bundle_directory(
            self.case_id, self.root
        )
        self.assertEqual(result, self.bundle.resolve())

    def test_invalid_case_ids(self):
        invalid_ids = (
            "../etc/passwd",
            "../../secret",
            "INC-../../secret",
            "",
            "INC-TEST/other",
        )

        for case_id in invalid_ids:
            with self.subTest(case_id=case_id):
                with self.assertRaises(ReportIntegrityError):
                    get_bundle_directory(case_id, self.root)

    def test_missing_incident(self):
        with self.assertRaises(ReportIntegrityError):
            get_bundle_directory("INC-MISSING", self.root)

    def test_symlinked_incident(self):
        outside = Path(self.tmp.name) / "outside"
        outside.mkdir()

        link = self.root / "INC-LINK"
        link.symlink_to(
            outside,
            target_is_directory=True,
        )

        with self.assertRaises(ReportIntegrityError):
            get_bundle_directory("INC-LINK", self.root)

    def test_symlinked_export_root(self):
        link = Path(self.tmp.name) / "root-link"
        link.symlink_to(
            self.root,
            target_is_directory=True,
        )

        with self.assertRaises(ReportIntegrityError):
            get_bundle_directory(self.case_id, link)

    def test_file_instead_of_directory(self):
        file_path = self.root / "INC-FILE"
        file_path.write_text("NOT A DIRECTORY")

        with self.assertRaises(ReportIntegrityError):
            get_bundle_directory("INC-FILE", self.root)


if __name__ == "__main__":
    unittest.main()
