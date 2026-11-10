"""Day 27 - Descriptor-based integrity verification tests."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from day27.report_integrity import ReportIntegrityError
from day27.secure_bundle_verifier import verify_secure_bundle


CASE_ID = "INC-CAC40C42F3254074"

ORIGINAL = (
    Path(__file__).resolve().parents[1]
    / "exports"
    / CASE_ID
)


class TestSecureBundleVerifier(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

        self.root = Path(self.tmp.name) / "exports"
        self.root.mkdir()

        self.bundle = self.root / CASE_ID
        shutil.copytree(ORIGINAL, self.bundle)

    def verify(self):
        return verify_secure_bundle(CASE_ID, self.root)

    def test_original_bundle_valid(self):
        result = self.verify()

        self.assertEqual(result["status"], "VALID")
        self.assertEqual(result["verified_count"], 3)
        self.assertEqual(result["total_files"], 3)
        self.assertTrue(all(result["files"].values()))

    def test_modified_report_detected(self):
        report = self.bundle / "incident-report.json"

        with report.open("ab") as stream:
            stream.write(b"\nTAMPERED")

        result = self.verify()

        self.assertEqual(result["status"], "TAMPERED")
        self.assertFalse(
            result["files"]["incident-report.json"]
        )

    def test_missing_export_detected(self):
        (self.bundle / "audit.csv").unlink()

        result = self.verify()

        self.assertEqual(result["status"], "TAMPERED")
        self.assertFalse(result["files"]["audit.csv"])

    def test_symlinked_export_detected(self):
        outside = Path(self.tmp.name) / "outside.csv"
        outside.write_text("EXTERNAL DATA")

        target = self.bundle / "evidence.csv"
        target.unlink()
        target.symlink_to(outside)

        result = self.verify()

        self.assertEqual(result["status"], "TAMPERED")
        self.assertFalse(result["files"]["evidence.csv"])

    def test_invalid_manifest_rejected(self):
        manifest_path = self.bundle / "manifest.json"

        manifest = json.loads(
            manifest_path.read_text(encoding="utf-8")
        )
        manifest["hash_algorithm"] = "MD5"

        manifest_path.write_text(
            json.dumps(manifest),
            encoding="utf-8",
        )

        with self.assertRaises(ReportIntegrityError):
            self.verify()

    def test_symlinked_manifest_rejected(self):
        manifest_path = self.bundle / "manifest.json"
        outside = Path(self.tmp.name) / "manifest.json"

        shutil.copy2(manifest_path, outside)
        manifest_path.unlink()
        manifest_path.symlink_to(outside)

        with self.assertRaises(ReportIntegrityError):
            self.verify()

    def test_invalid_case_id_rejected(self):
        with self.assertRaises(ReportIntegrityError):
            verify_secure_bundle("../etc/passwd", self.root)


if __name__ == "__main__":
    unittest.main()
