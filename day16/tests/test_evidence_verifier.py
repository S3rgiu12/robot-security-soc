import sys
import unittest
from collections import Counter
from pathlib import Path

DAY16_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DAY16_DIR))

from evidence_verifier import verify_incident, build_report


OFFLINE = (
    "IDS_AVAILABILITY|"
    "2026-10-21 12:36:02 | OFFLINE | "
    "IDS v3 unavailable: Heartbeat timeout exceeded"
)

RECOVERY = (
    "IDS_AVAILABILITY|"
    "2026-10-21 12:36:26 | RECOVERY | "
    "IDS v3 heartbeat restored"
)


def incident_with(keys):
    return {
        "incident_id": "INC-TEST",
        "status": "RESOLVED",
        "event_keys": keys
    }


class TestEvidenceVerifier(unittest.TestCase):

    def setUp(self):
        self.logs = Counter({
            OFFLINE: 1,
            RECOVERY: 1
        })

    def test_valid_evidence(self):
        result = verify_incident(
            incident_with([OFFLINE, RECOVERY]),
            self.logs
        )

        self.assertEqual(
            result["verification_status"], "VERIFIED"
        )
        self.assertEqual(result["verified_count"], 2)

    def test_missing_evidence(self):
        missing = (
            "IDS_AVAILABILITY|"
            "2026-10-21 14:00:00 | OFFLINE | Missing"
        )

        result = verify_incident(
            incident_with([missing]),
            self.logs
        )

        self.assertEqual(
            result["evidence"][0]["status"], "MISSING"
        )
        self.assertEqual(
            result["verification_status"], "REVIEW_REQUIRED"
        )

    def test_duplicate_reference(self):
        result = verify_incident(
            incident_with([OFFLINE, OFFLINE]),
            self.logs
        )

        self.assertEqual(
            result["evidence"][1]["status"], "MISMATCH"
        )

    def test_unknown_source(self):
        result = verify_incident(
            incident_with(["UNKNOWN|some-event"]),
            self.logs
        )

        self.assertEqual(
            result["evidence"][0]["status"], "UNVERIFIABLE"
        )

    def test_reversed_timeline(self):
        result = verify_incident(
            incident_with([RECOVERY, OFFLINE]),
            self.logs
        )

        self.assertEqual(
            result["verification_status"], "REVIEW_REQUIRED"
        )
        self.assertTrue(result["findings"])

    def test_incident_without_evidence(self):
        result = verify_incident(
            incident_with([]),
            self.logs
        )

        self.assertEqual(
            result["verification_status"], "UNVERIFIABLE"
        )
        self.assertEqual(result["verified_count"], 0)


if __name__ == "__main__":
    unittest.main()
