import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "day24"))

from threat_hunting_engine import (
    parse_timestamp,
    parse_security_event,
    create_event_id,
    analyze_log,
    SYNTHETIC_LOG,
    REAL_IDS_LOG,
)


class TestThreatHuntingEngine(unittest.TestCase):

    def test_timestamp_seconds(self):
        value = parse_timestamp("2026-10-29 10:00:00")
        self.assertIsNotNone(value)
        self.assertEqual(value.microsecond, 0)

    def test_timestamp_milliseconds(self):
        value = parse_timestamp("2026-10-12 15:55:06,382")
        self.assertIsNotNone(value)
        self.assertEqual(value.microsecond, 382000)

    def test_invalid_timestamp(self):
        self.assertIsNone(parse_timestamp("invalid-date"))

    def test_warning_classification(self):
        event = parse_security_event(
            "2026-10-29 10:00:00 | WARNING | Test alert",
            1,
            "synthetic.log"
        )
        self.assertEqual(
            event["classification"],
            "POTENTIAL_SECURITY_EVENT"
        )

    def test_info_classification(self):
        event = parse_security_event(
            "2026-10-29 10:00:00 | INFO | Normal activity",
            1,
            "synthetic.log"
        )
        self.assertEqual(
            event["classification"],
            "OBSERVATION"
        )

    def test_unknown_timestamp(self):
        event = parse_security_event(
            "invalid | WARNING | Test alert",
            1,
            "synthetic.log"
        )
        self.assertIsNone(event["timestamp"])
        self.assertFalse(event["timestamp_available"])

    def test_event_id_deterministic(self):
        first = create_event_id(
            "test.log", 1, "example"
        )
        second = create_event_id(
            "test.log", 1, "example"
        )
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("EVT-"))

    def test_original_evidence_preserved(self):
        original = (
            "2026-10-29 10:00:00 | CRITICAL | "
            "Suspicious connection"
        )
        event = parse_security_event(
            original, 1, "test.log"
        )
        self.assertEqual(event["evidence"], original)

    def test_chronological_order(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.log"
            path.write_text(
                "2026-10-29 10:00:03 | INFO | Later\n"
                "2026-10-29 10:00:01 | WARNING | Earlier\n",
                encoding="utf-8"
            )
            result = analyze_log(path)
            self.assertEqual(
                result["timeline"][0]["message"],
                "Earlier"
            )

    def test_missing_log_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.log"
            with self.assertRaises(FileNotFoundError):
                analyze_log(missing)

    def test_synthetic_log(self):
        result = analyze_log(SYNTHETIC_LOG)
        self.assertEqual(result["total_events"], 4)
        self.assertEqual(
            result["potential_security_events"], 3
        )
        self.assertEqual(result["unknown_timestamps"], 0)

    def test_existing_ids_log(self):
        result = analyze_log(REAL_IDS_LOG)
        self.assertEqual(result["total_events"], 28)
        self.assertEqual(
            result["potential_security_events"], 18
        )
        self.assertEqual(result["unknown_timestamps"], 0)


if __name__ == "__main__":
    unittest.main()
