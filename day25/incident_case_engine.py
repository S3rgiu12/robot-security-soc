"""Day 25 - SOC Incident Case Engine.

Business rules only. No database or network operations.
"""

from datetime import datetime, timezone
from uuid import uuid4


VALID_STATUSES = frozenset({
    "OPEN",
    "INVESTIGATING",
    "RESOLVED",
    "CLOSED",
})

VALID_SEVERITIES = frozenset({
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
})

VALID_VERDICTS = frozenset({
    "UNDETERMINED",
    "TRUE_POSITIVE",
    "FALSE_POSITIVE",
    "BENIGN_ACTIVITY",
})

ALLOWED_TRANSITIONS = {
    "OPEN": {"INVESTIGATING"},
    "INVESTIGATING": {"RESOLVED"},
    "RESOLVED": {"CLOSED", "INVESTIGATING"},
    "CLOSED": set(),
}


def utc_now():
    """Return a timezone-aware ISO 8601 timestamp."""
    return datetime.now(timezone.utc).isoformat(
        timespec="milliseconds"
    )


def generate_case_id():
    """Generate an unpredictable unique case identifier."""
    return "INC-" + uuid4().hex[:16].upper()


def validate_severity(severity):
    if severity not in VALID_SEVERITIES:
        raise ValueError("Invalid incident severity")
    return severity


def validate_verdict(verdict):
    if verdict not in VALID_VERDICTS:
        raise ValueError("Invalid investigation verdict")
    return verdict


def validate_transition(current_status, new_status):
    if current_status not in VALID_STATUSES:
        raise ValueError("Invalid current incident status")

    if new_status not in VALID_STATUSES:
        raise ValueError("Invalid target incident status")

    if new_status not in ALLOWED_TRANSITIONS[current_status]:
        raise ValueError(
            f"Transition not allowed: "
            f"{current_status} -> {new_status}"
        )

    return True


def create_case_record(
    alert_id,
    severity,
    analyst,
    description,
):
    """Build a new incident case record.

    Creating a case does not confirm an attack.
    """

    if not isinstance(alert_id, str) or not alert_id.strip():
        raise ValueError("Alert ID is required")

    if not isinstance(analyst, str) or not analyst.strip():
        raise ValueError("Analyst identity is required")

    if (
        not isinstance(description, str)
        or not description.strip()
    ):
        raise ValueError("Incident description is required")

    validate_severity(severity)

    timestamp = utc_now()

    return {
        "case_id": generate_case_id(),
        "alert_id": alert_id.strip(),
        "status": "OPEN",
        "severity": severity,
        "verdict": "UNDETERMINED",
        "assigned_analyst": analyst.strip(),
        "description": description.strip(),
        "created_at": timestamp,
        "updated_at": timestamp,
    }


def create_audit_record(
    case_id,
    analyst,
    action,
    previous_status=None,
    new_status=None,
    note=None,
):
    """Build an audit entry for a case operation."""

    if not isinstance(case_id, str) or not case_id.strip():
        raise ValueError("Case ID is required")

    if not isinstance(analyst, str) or not analyst.strip():
        raise ValueError("Analyst identity is required")

    if not isinstance(action, str) or not action.strip():
        raise ValueError("Audit action is required")

    return {
        "case_id": case_id.strip(),
        "analyst": analyst.strip(),
        "action": action.strip(),
        "previous_status": previous_status,
        "new_status": new_status,
        "note": note,
        "created_at": utc_now(),
    }
