import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "day21"))

from ioc_correlation_engine import (
    load_indicators,
    extract_observables,
    correlate_lines
)


class TestIOCCorrelationEngine(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.indicators = load_indicators()

    def test_exact_ipv4_match(self):
        lines = ["Connection from 192.0.2.10"]

        matches = correlate_lines(
            lines,
            self.indicators
        )

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["ioc_id"], "IOC-0001")

    def test_no_partial_ipv4_match(self):
        lines = ["Connection from 192.0.2.100"]

        matches = correlate_lines(
            lines,
            self.indicators
        )

        self.assertEqual(matches, [])

    def test_case_insensitive_domain(self):
        lines = [
            "DNS request ROBOT-CONTROL-TEST.EXAMPLE"
        ]

        matches = correlate_lines(
            lines,
            self.indicators
        )

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["ioc_id"], "IOC-0002")

    def test_no_partial_domain_match(self):
        lines = [
            "DNS request fake-robot-control-test.example"
        ]

        matches = correlate_lines(
            lines,
            self.indicators
        )

        self.assertEqual(matches, [])

    def test_invalid_ipv4_rejected(self):
        observables = extract_observables(
            "Connection from 999.999.999.999"
        )

        self.assertEqual(
            observables["ipv4"],
            set()
        )

    def test_three_synthetic_ioc_matches(self):
        lines = [
            "Connection from 192.0.2.10",
            "DNS request robot-control-test.example",
            "Connection from 198.51.100.25",
            "Connection from 127.0.0.1"
        ]

        matches = correlate_lines(
            lines,
            self.indicators
        )

        self.assertEqual(len(matches), 3)

        ids = {
            item["ioc_id"]
            for item in matches
        }

        self.assertEqual(
            ids,
            {"IOC-0001", "IOC-0002", "IOC-0003"}
        )


if __name__ == "__main__":
    unittest.main()
