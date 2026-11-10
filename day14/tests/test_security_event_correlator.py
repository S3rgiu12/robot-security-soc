import sys
import unittest
from pathlib import Path

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1])
)

from security_event_correlator import (
    correlate_availability,
    correlate_recovery,
    correlate_blocked,
)

def event(event_id, timestamp, event_type,
          source="IDS_AVAILABILITY",
          source_file="day12/data/security_alerts.json",
          simulated=False):
    return {
        "event_id": event_id,
        "timestamp_utc": timestamp,
        "event_type": event_type,
        "source": source,
        "source_file": source_file,
        "service": "robot_ids_v3",
        "simulated": simulated,
    }


class TestAvailabilityCorrelation(unittest.TestCase):

    def test_offline_online_pair(self):
        events = [
            event("a", "2026-10-21T09:00:00+00:00", "IDS_OFFLINE"),
            event("b", "2026-10-21T09:00:20+00:00", "IDS_ONLINE"),
        ]

        incidents = correlate_availability(events)

        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["status"], "RESTORED")
        self.assertEqual(incidents[0]["duration_seconds"], 20)

    def test_offline_without_online(self):
        events = [
            event("a", "2026-10-21T09:00:00+00:00", "IDS_OFFLINE"),
        ]

        incidents = correlate_availability(events)

        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["status"], "UNRESOLVED")

    def test_long_outage_is_critical(self):
        events = [
            event("a", "2026-10-21T09:00:00+00:00", "IDS_OFFLINE"),
            event("b", "2026-10-21T10:01:00+00:00", "IDS_ONLINE"),
        ]

        incidents = correlate_availability(events)

        self.assertEqual(incidents[0]["severity"], "CRITICAL")

    def test_simulation_not_mixed_with_real(self):
        events = [
            event("a", "2026-10-21T09:00:00+00:00",
                  "IDS_OFFLINE", simulated=True),
            event("b", "2026-10-21T09:00:05+00:00",
                  "IDS_ONLINE", simulated=False),
        ]

        incidents = correlate_availability(events)

        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["status"], "UNRESOLVED")
        self.assertTrue(incidents[0]["simulated"])


class TestRecoveryCorrelation(unittest.TestCase):

    def recovery_event(self, event_id, timestamp, event_type):
        return event(
            event_id,
            timestamp,
            event_type,
            source="RECOVERY_CONTROLLER",
            source_file="day11/logs/recovery.log",
        )

    def test_complete_recovery(self):
        events = [
            self.recovery_event(
                "a", "2026-10-23T12:00:00+00:00", "STARTING"
            ),
            self.recovery_event(
                "b", "2026-10-23T12:00:01+00:00", "STARTED"
            ),
            self.recovery_event(
                "c", "2026-10-23T12:00:03+00:00", "RECOVERED"
            ),
        ]

        incidents = correlate_recovery(events)

        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["status"], "RECOVERED")
        self.assertEqual(len(incidents[0]["event_ids"]), 3)

    def test_recovery_without_completion(self):
        events = [
            self.recovery_event(
                "a", "2026-10-23T12:00:00+00:00", "STARTING"
            ),
            self.recovery_event(
                "b", "2026-10-23T12:00:01+00:00", "STARTED"
            ),
        ]

        incidents = correlate_recovery(events)

        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["status"], "INCOMPLETE")

    def test_recovery_outside_time_window(self):
        events = [
            self.recovery_event(
                "a", "2026-10-23T12:00:00+00:00", "STARTING"
            ),
            self.recovery_event(
                "b", "2026-10-23T12:02:00+00:00", "STARTED"
            ),
        ]

        incidents = correlate_recovery(events)

        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["status"], "INCOMPLETE")


class TestBlockedRecovery(unittest.TestCase):

    def test_blocked_event(self):
        events = [
            event(
                "blocked1",
                "2026-10-26T12:55:48+00:00",
                "BLOCKED",
                source="RECOVERY_CONTROLLER",
                source_file="day11/logs/recovery.log",
                simulated=True,
            )
        ]

        incidents = correlate_blocked(events)

        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["status"], "BLOCKED")
        self.assertTrue(incidents[0]["simulated"])


class TestCorrelationEdgeCases(unittest.TestCase):

    def test_recovered_before_started(self):
        events = [
            event(
                "a", "2026-10-23T12:00:00+00:00",
                "STARTING",
                source="RECOVERY_CONTROLLER",
                source_file="day11/logs/recovery.log"
            ),
            event(
                "b", "2026-10-23T12:00:01+00:00",
                "RECOVERED",
                source="RECOVERY_CONTROLLER",
                source_file="day11/logs/recovery.log"
            ),
            event(
                "c", "2026-10-23T12:00:02+00:00",
                "STARTED",
                source="RECOVERY_CONTROLLER",
                source_file="day11/logs/recovery.log"
            ),
        ]

        incidents = correlate_recovery(events)

        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["status"], "INCOMPLETE")

    def test_identical_timestamps_are_deterministic(self):
        events = [
            event(
                "a", "2026-10-21T09:00:00+00:00",
                "IDS_OFFLINE"
            ),
            event(
                "b", "2026-10-21T09:00:00+00:00",
                "IDS_ONLINE"
            ),
        ]

        first = correlate_availability(events)
        second = correlate_availability(events)

        self.assertEqual(first, second)
        self.assertEqual(len(first), 1)
        self.assertEqual(first[0]["duration_seconds"], 0)


if __name__ == "__main__":
    unittest.main()
