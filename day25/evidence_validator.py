"""Day 25 - Validate SOC evidence references."""

from day24.evidence_correlation_engine import correlate_evidence
from day24.threat_hunting_engine import analyze_log


VALID_EVIDENCE_TYPES = {
    "IOC_ALERT",
    "LOG_EVENT",
    "INVESTIGATION",
}


def validate_evidence_reference(
    evidence_type,
    reference_id,
    incident_alert_id,
    log_path,
):
    """Validate a reference against the selected SOC log."""

    if evidence_type not in VALID_EVIDENCE_TYPES:
        raise ValueError("Unsupported evidence type")

    if not isinstance(reference_id, str) or not reference_id:
        raise ValueError("Evidence reference is required")

    if not isinstance(incident_alert_id, str) or not incident_alert_id:
        raise ValueError("Incident alert ID is required")

    correlation = correlate_evidence(log_path)

    alerts = {
        event["alert_id"]
        for event in correlation["timeline"]
    }

    if evidence_type == "IOC_ALERT":
        if reference_id != incident_alert_id:
            raise ValueError(
                "Evidence alert does not match incident"
            )

        if reference_id not in alerts:
            raise ValueError(
                "Alert evidence not found in selected log"
            )

        return True

    if evidence_type == "INVESTIGATION":
        if reference_id != incident_alert_id:
            raise ValueError(
                "Investigation alert does not match incident"
            )

        if reference_id not in alerts:
            raise ValueError(
                "Investigation alert not found"
            )

        return True

    if evidence_type == "LOG_EVENT":
        matching_events = [
            event
            for event in correlation["timeline"]
            if event["alert_id"] == incident_alert_id
        ]

        matching_event_ids = {
            event["event_id"]
            for event in matching_events
        }

        if reference_id not in matching_event_ids:
            raise ValueError(
                "Log event is not correlated with incident alert"
            )

        timeline = analyze_log(log_path)

        original_event_ids = {
            event["event_id"]
            for event in timeline["timeline"]
        }

        if reference_id not in original_event_ids:
            raise ValueError(
                "Original log event not found"
            )

        return True

    raise ValueError("Unsupported evidence type")
