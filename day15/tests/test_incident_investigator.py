import sys
import unittest
from pathlib import Path

DAY15_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DAY15_DIR))

from incident_investigator import investigate_incident, build_report


class TestIncidentInvestigator(unittest.TestCase):

    def test_open_without_evidence(self):
        incident = {
            "incident_id": "INC-TEST-1",
            "status": "OPEN",
            "event_keys": [],
            "resolved_at": None
        }

        result = investigate_incident(incident)

        self.assertEqual(result["evidence_status"], "MISSING")
        self.assertEqual(result["investigation_priority"], "HIGH")
        self.assertEqual(result["investigation_status"], "REVIEW_REQUIRED")

    def test_resolved_with_evidence(self):
        incident = {
            "incident_id": "INC-TEST-2",
            "status": "RESOLVED",
            "event_keys": ["OFFLINE", "RECOVERY"],
            "resolved_at": "2026-10-22T12:01:24"
        }

        result = investigate_incident(incident)

        self.assertEqual(result["evidence_status"], "AVAILABLE")
        self.assertEqual(result["investigation_priority"], "LOW")
        self.assertEqual(result["investigation_status"], "EVIDENCE_LINKED")

    def test_partial_evidence(self):
        incident = {
            "incident_id": "INC-TEST-3",
            "status": "RESOLVED",
            "event_keys": ["OFFLINE"],
            "resolved_at": "2026-10-22T12:01:24"
        }

        result = investigate_incident(incident)

        self.assertEqual(result["evidence_status"], "PARTIAL")
        self.assertEqual(result["investigation_status"], "REVIEW_REQUIRED")

    def test_resolved_without_timestamp(self):
        incident = {
            "incident_id": "INC-TEST-4",
            "status": "RESOLVED",
            "event_keys": ["OFFLINE", "RECOVERY"],
            "resolved_at": None
        }

        result = investigate_incident(incident)

        self.assertEqual(result["investigation_priority"], "MEDIUM")
        self.assertIn(
            "Resolved incident lacks resolution timestamp.",
            result["findings"]
        )

    def test_invalid_evidence_type(self):
        incident = {
            "incident_id": "INC-TEST-5",
            "status": "OPEN",
            "event_keys": "INVALID"
        }

        result = investigate_incident(incident)

        self.assertEqual(result["evidence_count"], 0)
        self.assertEqual(result["evidence_status"], "MISSING")

    def test_report_summary(self):
        incidents = [
            {
                "incident_id": "INC-A",
                "status": "OPEN",
                "event_keys": []
            },
            {
                "incident_id": "INC-B",
                "status": "RESOLVED",
                "event_keys": ["OFFLINE", "RECOVERY"],
                "resolved_at": "2026-10-22T12:01:24"
            }
        ]

        report = build_report(incidents)

        self.assertEqual(report["summary"]["total"], 2)
        self.assertEqual(
            report["summary"]["by_investigation_status"]["REVIEW_REQUIRED"],
            1
        )
        self.assertEqual(
            report["summary"]["by_investigation_status"]["EVIDENCE_LINKED"],
            1
        )


if __name__ == "__main__":
    unittest.main()
