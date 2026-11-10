"""Day 27 - Secure bundle path regression tests."""

import shutil
import tempfile
import unittest
from pathlib import Path

from day27.report_integrity import ReportIntegrityError
from day27.report_manifest import verify_incident_bundle
from day27.secure_file_reader import secure_sha256_file


CASE_ID = "INC-CAC40C42F3254074"

ORIGINAL = (
    Path(__file__).resolve().parents[1]
    / "exports"
    / CASE_ID
)


class TestSecureBundlePaths(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

        self.root = Path(self.tmp.name)
        self.bundle = self.root / CASE_ID

        shutil.copytree(ORIGINAL, self.bundle)

    def test_normal_bundle(self):
        results = verify_incident_bundle(self.bundle)
        self.assertTrue(all(results.values()))

    def test_symlinked_export_rejected(self):
        outside = self.root / "outside.txt"
        outside.write_text("EXTERNAL TEST DATA")

        target = self.bundle / "audit.csv"
        target.unlink()
        target.symlink_to(outside)

        with self.assertRaises(ReportIntegrityError):
            secure_sha256_file(self.bundle, "audit.csv")

        results = verify_incident_bundle(self.bundle)
        self.assertFalse(results["audit.csv"])

    def test_symlinked_bundle_rejected(self):
        link = self.root / "linked-bundle"
        link.symlink_to(self.bundle, target_is_directory=True)

        with self.assertRaises(ReportIntegrityError):
            secure_sha256_file(
                link, "incident-report.json"
            )

    def test_directory_instead_of_export(self):
        target = self.bundle / "evidence.csv"
        target.unlink()
        target.mkdir()

        results = verify_incident_bundle(self.bundle)
        self.assertFalse(results["evidence.csv"])


if __name__ == "__main__":
    unittest.main()
