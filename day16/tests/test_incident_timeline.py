import sys
import unittest
from pathlib import Path

DAY16_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DAY16_DIR))

from incident_timeline import (
    reconstruct_timeline,
    build_timeline_report
)


def evidence(timestamp, event_type):
    return {
        "status": "VERIFIED",
        "event_key": (
            f"IDS_AVAILABILITY|{timestamp} | "
            f"{event_type} | Test event"
        )
    }


def incident(events, status="VERIFIED"):
    return {
        "incident_id": "INC-TEST",
        "operational_status": "RESOLVED",
        "verification_status": status,
        "evidence": events
    }


class TestIncidentTimeline(unittest.TestCase):

    def test_valid_timeline(self):
        result = reconstruct_timeline(incident([
            evidence("2026-10-21 12:00:00", "OFFLINE"),
            evidence("2026-10-21 12:00:24", "RECOVERY")
        ]))

        self.assertEqual(
            result["timeline_status"], "RECONSTRUCTED"
        )
        self.assertEqual(result["duration_seconds"], 24)

    def test_long_outage(self):
        result = reconstruct_timeline(incident([
            evidence("2026-10-21 12:00:00", "OFFLINE"),
            evidence("2026-10-21 13:00:00", "RECOVERY")
        ]))

        self.assertEqual(result["duration_seconds"], 3600)

    def test_reversed_input_order(self):
        result = reconstruct_timeline(incident([
            evidence("2026-10-21 12:00:24", "RECOVERY"),
            evidence("2026-10-21 12:00:00", "OFFLINE")
        ]))

        self.assertEqual(
            result["timeline_status"], "RECONSTRUCTED"
        )
        self.assertEqual(
            result["events"][0]["event_type"], "OFFLINE"
        )

    def test_recovery_before_offline(self):
        result = reconstruct_timeline(incident([
            evidence("2026-10-21 12:00:24", "OFFLINE"),
            evidence("2026-10-21 12:00:00", "RECOVERY")
        ]))

        self.assertEqual(
            result["timeline_status"], "INCOMPLETE"
        )
        self.assertIsNone(result["duration_seconds"])

    def test_no_evidence(self):
        result = reconstruct_timeline(
            incident([], "UNVERIFIABLE")
        )

        self.assertEqual(
            result["timeline_status"], "INCOMPLETE"
        )
        self.assertIsNone(result["duration_seconds"])

    def test_unverified_evidence(self):
        result = reconstruct_timeline(incident([
            evidence("2026-10-21 12:00:00", "OFFLINE"),
            evidence("2026-10-21 12:00:24", "RECOVERY")
        ], "REVIEW_REQUIRED"))

        self.assertEqual(
            result["timeline_status"], "INCOMPLETE"
        )

    def test_report_summary(self):
        report = build_timeline_report({
            "incidents": [
                incident([
                    evidence("2026-10-21 12:00:00", "OFFLINE"),
                    evidence("2026-10-21 12:00:24", "RECOVERY")
                ]),
                incident([], "UNVERIFIABLE")
            ]
        })

        self.assertEqual(
            report["summary"]["total_incidents"], 2
        )
        self.assertEqual(
            report["summary"]["reconstructed"], 1
        )
        self.assertEqual(
            report["summary"]["incomplete"], 1
        )


if __name__ == "__main__":
    unittest.main()
