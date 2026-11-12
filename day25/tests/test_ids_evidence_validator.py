"""Tests for IDS V3 evidence validation."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from day25.ids_evidence_validator import (
    create_ids_alert_id,
    validate_ids_alert,
)


class TestIDSEvidenceValidator(unittest.TestCase):

    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.log_path = Path(self.temp.name) / "ids.log"

        self.alert = (
            "2026-11-12 11:09:04.347447 | CRITICAL | "
            "Multiple TLS certificate rejections detected! "
            "Events: 3 within 60 seconds"
        )

        self.alert_id = create_ids_alert_id(self.alert)

        self.log_path.write_text(
            self.alert + "\n",
            encoding="utf-8",
        )

    def test_valid_alert(self):
        self.assertTrue(
            validate_ids_alert(
                self.alert_id,
                self.alert_id,
                self.log_path,
            )
        )

    def test_mismatched_incident(self):
        with self.assertRaises(ValueError):
            validate_ids_alert(
                self.alert_id,
                "IDS-OTHER",
                self.log_path,
            )

    def test_missing_log(self):
        with self.assertRaises(ValueError):
            validate_ids_alert(
                self.alert_id,
                self.alert_id,
                Path(self.temp.name) / "missing.log",
            )

    def test_missing_alert(self):
        self.log_path.write_text(
            "Normal operation\n",
            encoding="utf-8",
        )

        with self.assertRaises(ValueError):
            validate_ids_alert(
                self.alert_id,
                self.alert_id,
                self.log_path,
            )

    def test_noncritical_alert(self):
        modified = self.alert.replace(
            " | CRITICAL | ",
            " | INFO | ",
        )

        modified_id = create_ids_alert_id(modified)

        self.log_path.write_text(
            modified + "\n",
            encoding="utf-8",
        )

        with self.assertRaises(ValueError):
            validate_ids_alert(
                modified_id,
                modified_id,
                self.log_path,
            )


if __name__ == "__main__":
    unittest.main()
