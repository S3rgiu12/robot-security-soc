"""Automated tests for IDS V3 TLS event correlation."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from day25.ids_evidence_validator import create_ids_alert_id
from day25.ids_tls_correlation import validate_tls_correlation


class TestIDSTLSCorrelation(unittest.TestCase):

    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        root = Path(self.temp.name)
        self.alert_log = root / "ids_alerts.log"
        self.security_log = root / "robot_security.log"

        self.alert_line = (
            "2026-11-12 11:09:04.347447 | CRITICAL | "
            "Multiple TLS certificate rejections detected! "
            "Events: 3 within 60 seconds"
        )

        self.alert_id = create_ids_alert_id(self.alert_line)
        self.alert_log.write_text(
            self.alert_line + "\n",
            encoding="utf-8",
        )

        self.valid_events = [
            self.event("2026-11-12 11:08:20,100"),
            self.event("2026-11-12 11:08:35,200"),
            self.event("2026-11-12 11:08:50,300"),
        ]

        self.write_events(self.valid_events)

    @staticmethod
    def event(timestamp):
        return (
            f"{timestamp} | WARNING | SECURITY ALERT: "
            "TLS certificate rejected: simulated failure"
        )

    def write_events(self, events):
        self.security_log.write_text(
            "\n".join(events) + "\n",
            encoding="utf-8",
        )

    def validate(self):
        return validate_tls_correlation(
            self.alert_id,
            self.alert_log,
            self.security_log,
        )

    def test_three_valid_events(self):
        result = self.validate()

        self.assertEqual(result["status"], "CORROBORATED")
        self.assertEqual(result["correlated_events"], 3)

    def test_only_two_events(self):
        self.write_events(self.valid_events[:2])

        with self.assertRaises(ValueError):
            self.validate()

    def test_old_events(self):
        self.write_events([
            self.event("2026-11-12 11:05:00,100"),
            self.event("2026-11-12 11:05:10,200"),
            self.event("2026-11-12 11:05:20,300"),
        ])

        with self.assertRaises(ValueError):
            self.validate()

    def test_missing_security_log(self):
        self.security_log.unlink()

        with self.assertRaises(ValueError):
            self.validate()

    def test_declared_count_below_threshold(self):
        invalid_alert = self.alert_line.replace(
            "Events: 3",
            "Events: 2",
        )

        self.alert_id = create_ids_alert_id(invalid_alert)
        self.alert_log.write_text(
            invalid_alert + "\n",
            encoding="utf-8",
        )

        with self.assertRaises(ValueError):
            self.validate()


if __name__ == "__main__":
    unittest.main()
