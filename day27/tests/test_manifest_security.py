"""Day 27 - SOC manifest security tests."""

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from day27.manifest_security import (
    validate_case_id,
    validate_manifest,
)
from day27.report_integrity import ReportIntegrityError
from day27.report_manifest import verify_incident_bundle


CASE_ID = "INC-CAC40C42F3254074"

BUNDLE = (
    Path(__file__).resolve().parents[1]
    / "exports"
    / CASE_ID
)


class TestManifestSecurity(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(
            (BUNDLE / "manifest.json").read_text(
                encoding="utf-8"
            )
        )

    def test_valid_manifest(self):
        self.assertTrue(
            validate_manifest(
                self.manifest,
                expected_case_id=CASE_ID,
            )
        )

    def test_invalid_case_id(self):
        for value in (
            "../incident",
            "INC-../../secret",
            "INC-",
            "",
            None,
        ):
            with self.subTest(value=value):
                with self.assertRaises(
                    ReportIntegrityError
                ):
                    validate_case_id(value)

    def test_invalid_algorithm(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["hash_algorithm"] = "MD5"

        with self.assertRaises(ReportIntegrityError):
            validate_manifest(manifest)

    def test_missing_export_metadata(self):
        manifest = copy.deepcopy(self.manifest)
        del manifest["files"]["audit.csv"]

        with self.assertRaises(ReportIntegrityError):
            validate_manifest(manifest)

    def test_invalid_sha256(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["files"]["audit.csv"]["sha256"] = "bad"

        with self.assertRaises(ReportIntegrityError):
            validate_manifest(manifest)

    def test_invalid_size(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["files"]["audit.csv"]["size_bytes"] = -1

        with self.assertRaises(ReportIntegrityError):
            validate_manifest(manifest)

    def test_boolean_size_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["files"]["audit.csv"]["size_bytes"] = True

        with self.assertRaises(ReportIntegrityError):
            validate_manifest(manifest)

    def test_incident_mismatch(self):
        with self.assertRaises(ReportIntegrityError):
            validate_manifest(
                self.manifest,
                expected_case_id="INC-OTHER",
            )

    def test_original_bundle_valid(self):
        results = verify_incident_bundle(BUNDLE)
        self.assertTrue(all(results.values()))

    def test_modified_report_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            copied = Path(tmp) / CASE_ID
            shutil.copytree(BUNDLE, copied)

            report_path = copied / "incident-report.json"
            report_path.write_bytes(
                report_path.read_bytes() + b"\nMODIFIED"
            )

            results = verify_incident_bundle(copied)

            self.assertFalse(
                results["incident-report.json"]
            )
            self.assertTrue(results["evidence.csv"])
            self.assertTrue(results["audit.csv"])

    def test_missing_export_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            copied = Path(tmp) / CASE_ID
            shutil.copytree(BUNDLE, copied)

            (copied / "audit.csv").unlink()

            results = verify_incident_bundle(copied)

            self.assertFalse(results["audit.csv"])


if __name__ == "__main__":
    unittest.main()
