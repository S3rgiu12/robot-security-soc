import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "day24"))

import evidence_correlation_engine as engine


class TestEvidenceCorrelationEngine(unittest.TestCase):

    def test_synthetic_alerts_correlated(self):
        path = (
            ROOT /
            "day21/data/simulated_security_events.log"
        )

        result = engine.correlate_evidence(path)

        self.assertEqual(result["total_events"], 4)
        self.assertEqual(result["total_alerts"], 3)
        self.assertEqual(result["correlated_alerts"], 3)
        self.assertEqual(result["unmatched_alerts"], [])

    def test_real_log_has_no_ioc_alerts(self):
        path = ROOT / "day05/logs/robot_security.log"

        result = engine.correlate_evidence(path)

        self.assertEqual(result["total_events"], 28)
        self.assertEqual(result["total_alerts"], 0)
        self.assertEqual(result["correlated_alerts"], 0)

    def test_timeline_chronological(self):
        path = (
            ROOT /
            "day21/data/simulated_security_events.log"
        )

        result = engine.correlate_evidence(path)

        timestamps = [
            item["timestamp"]
            for item in result["timeline"]
        ]

        self.assertEqual(
            timestamps,
            sorted(timestamps)
        )

    def test_original_evidence_preserved(self):
        path = (
            ROOT /
            "day21/data/simulated_security_events.log"
        )

        result = engine.correlate_evidence(path)

        with path.open(encoding="utf-8") as file:
            lines = file.read().splitlines()

        for item in result["timeline"]:
            original = lines[item["line_number"] - 1]
            self.assertEqual(
                item["evidence"],
                original
            )

    def test_alert_event_ids_present(self):
        path = (
            ROOT /
            "day21/data/simulated_security_events.log"
        )

        result = engine.correlate_evidence(path)

        for item in result["timeline"]:
            self.assertTrue(
                item["alert_id"].startswith("ALT-")
            )
            self.assertTrue(
                item["event_id"].startswith("EVT-")
            )

    def test_unmatched_alert_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.log"

            path.write_text(
                "2026-10-29 10:00:00 | INFO | Normal\n",
                encoding="utf-8"
            )

            fake_alert = {
                "alert_id": "ALT-UNMATCHED",
                "line_number": 999,
                "evidence": "Missing event"
            }

            with patch.object(
                engine,
                "generate_alerts",
                return_value={
                    "status": "OK",
                    "alerts": [fake_alert]
                }
            ):
                result = engine.correlate_evidence(path)

            self.assertEqual(
                result["correlated_alerts"],
                0
            )
            self.assertEqual(
                result["unmatched_alerts"],
                ["ALT-UNMATCHED"]
            )

    def test_invalid_alert_generation_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.log"

            path.write_text(
                "2026-10-29 10:00:00 | INFO | Normal\n",
                encoding="utf-8"
            )

            with patch.object(
                engine,
                "generate_alerts",
                return_value={"status": "ERROR"}
            ):
                with self.assertRaises(ValueError):
                    engine.correlate_evidence(path)

    def test_missing_log_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.log"

            with self.assertRaises(FileNotFoundError):
                engine.correlate_evidence(path)


if __name__ == "__main__":
    unittest.main()
