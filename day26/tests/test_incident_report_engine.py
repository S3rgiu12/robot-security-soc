import json
import unittest
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

from day26.incident_report_engine import (
    IncidentReportError,
    generate_incident_report,
    normalize,
    report_to_json,
)


class TestIncidentReportEngine(unittest.TestCase):

    def setUp(self):
        self.case_id = "INC-TEST-001"
        self.db_path = "/tmp/day26-test-placeholder.db"

        self.incident = {
            "case_id": self.case_id,
            "status": "INVESTIGATING",
            "severity": "HIGH",
            "verdict": None,
        }

        self.evidence = [
            {
                "evidence_type": "IOC_ALERT",
                "reference_id": "ALERT-001",
            }
        ]

        self.audit = [
            {
                "action": "CREATED",
                "analyst": "test_analyst",
            }
        ]

    def test_generate_report(self):
        with (
            patch(
                "day26.incident_report_engine.get_incident",
                return_value=self.incident,
            ),
            patch(
                "day26.incident_report_engine.get_incident_evidence",
                return_value=self.evidence,
            ),
            patch(
                "day26.incident_report_engine.get_incident_audit",
                return_value=self.audit,
            ),
        ):
            report = generate_incident_report(
                self.case_id,
                self.db_path,
            )

        self.assertEqual(
            report["report_type"],
            "SOC_INCIDENT_REPORT",
        )
        self.assertEqual(
            report["incident"]["status"],
            "INVESTIGATING",
        )
        self.assertIsNone(
            report["incident"]["verdict"]
        )
        self.assertEqual(
            report["summary"]["evidence_count"],
            1,
        )
        self.assertEqual(
            report["summary"]["audit_events"],
            1,
        )

    def test_report_json_serialization(self):
        report = {
            "report_type": "SOC_INCIDENT_REPORT",
            "incident": {"case_id": self.case_id},
        }

        output = report_to_json(report)
        decoded = json.loads(output)

        self.assertEqual(
            decoded["incident"]["case_id"],
            self.case_id,
        )

    def test_missing_incident(self):
        with patch(
            "day26.incident_report_engine.get_incident",
            return_value=None,
        ):
            with self.assertRaises(IncidentReportError):
                generate_incident_report(
                    self.case_id,
                    self.db_path,
                )

    def test_invalid_case_id(self):
        with self.assertRaises(IncidentReportError):
            generate_incident_report("", self.db_path)

    def test_missing_database_path(self):
        with self.assertRaises(IncidentReportError):
            generate_incident_report(self.case_id, None)

    def test_normalize_supported_types(self):
        now = datetime(
            2026, 11, 9, 10, 0,
            tzinfo=timezone.utc,
        )

        result = normalize({
            "timestamp": now,
            "amount": Decimal("1.25"),
            "path": Path("reports/test.json"),
        })

        self.assertEqual(
            result["timestamp"],
            now.isoformat(),
        )
        self.assertEqual(result["amount"], "1.25")
        self.assertEqual(
            result["path"],
            "reports/test.json",
        )

    def test_normalize_unsupported_type(self):
        with self.assertRaises(IncidentReportError):
            normalize(object())


if __name__ == "__main__":
    unittest.main()
