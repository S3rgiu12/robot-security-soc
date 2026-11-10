import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))

from soc_report_generator import (
    build_soc_reports,
    index_records,
)
from soc_pdf_exporter import export_incident


class TestSOCReporting(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.data = build_soc_reports()
        cls.reports = cls.data["reports"]

    def test_total_reports(self):
        self.assertEqual(len(self.reports), 11)

    def test_unique_incident_ids(self):
        ids = [r["incident_id"] for r in self.reports]
        self.assertEqual(len(ids), len(set(ids)))

    def test_verified_incidents(self):
        self.assertEqual(
            self.data["summary"]["verified_incidents"],
            10
        )

    def test_review_required(self):
        self.assertEqual(
            self.data["summary"]["review_required"],
            1
        )

    def test_inc0001_remains_open(self):
        report = next(
            r for r in self.reports
            if r["incident_id"] == "INC-0001"
        )
        self.assertEqual(report["operational_status"], "OPEN")
        self.assertTrue(report["review_required"])
        self.assertEqual(
            report["forensics"]["verification_status"],
            "UNVERIFIABLE"
        )

    def test_duplicate_ids_rejected(self):
        with self.assertRaises(ValueError):
            index_records([
                {"incident_id": "INC-0001"},
                {"incident_id": "INC-0001"},
            ])

    def test_pdf_export(self):
        report = self.reports[0]
        output = export_incident(
            report,
            self.data["generated_at_utc"]
        )
        self.assertTrue(output.exists())
        self.assertEqual(
            output.read_bytes()[:5],
            b"%PDF-"
        )


if __name__ == "__main__":
    unittest.main()
