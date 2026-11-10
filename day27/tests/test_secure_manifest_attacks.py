"""Day 27 - Manifest security attack tests."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from day27.report_integrity import ReportIntegrityError
from day27.report_manifest import verify_incident_bundle


CASE_ID = "INC-CAC40C42F3254074"

ORIGINAL = (
    Path(__file__).resolve().parents[1]
    / "exports"
    / CASE_ID
)


class TestSecureManifestAttacks(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

        self.root = Path(self.tmp.name)
        self.bundle = self.root / CASE_ID
        shutil.copytree(ORIGINAL, self.bundle)

    def test_original_manifest(self):
        results = verify_incident_bundle(self.bundle)
        self.assertTrue(all(results.values()))

    def test_manifest_symlink_rejected(self):
        manifest = self.bundle / "manifest.json"
        outside = self.root / "outside.json"

        shutil.copy2(manifest, outside)
        manifest.unlink()
        manifest.symlink_to(outside)

        with self.assertRaises(ReportIntegrityError):
            verify_incident_bundle(self.bundle)

    def test_modified_hash_detected(self):
        manifest_path = self.bundle / "manifest.json"

        manifest = json.loads(
            manifest_path.read_text(encoding="utf-8")
        )

        manifest["files"]["audit.csv"]["sha256"] = "0" * 64

        manifest_path.write_text(
            json.dumps(manifest),
            encoding="utf-8",
        )

        results = verify_incident_bundle(self.bundle)
        self.assertFalse(results["audit.csv"])

    def test_invalid_algorithm_rejected(self):
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
            verify_incident_bundle(self.bundle)

    def test_oversized_manifest_rejected(self):
        manifest_path = self.bundle / "manifest.json"

        manifest_path.write_bytes(b" " * (1024 * 1024 + 1))

        with self.assertRaises(ReportIntegrityError):
            verify_incident_bundle(self.bundle)


if __name__ == "__main__":
    unittest.main()
