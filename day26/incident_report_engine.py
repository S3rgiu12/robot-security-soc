"""Day 26 - SOC Incident Reporting Engine."""

import json
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path

from day25.incident_case_store import (
    get_incident,
    get_incident_evidence,
    get_incident_audit,
)


class IncidentReportError(Exception):
    """Raised when a report cannot be generated."""


def normalize(value):
    """Convert supported database values into JSON-safe data."""

    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, (datetime, date)):
        return value.isoformat()

    if isinstance(value, Decimal):
        return str(value)

    if isinstance(value, Path):
        return str(value)

    if isinstance(value, dict):
        return {
            str(key): normalize(item)
            for key, item in value.items()
        }

    if hasattr(value, "keys"):
        return {
            str(key): normalize(value[key])
            for key in value.keys()
        }

    if isinstance(value, (list, tuple)):
        return [normalize(item) for item in value]

    raise IncidentReportError(
        f"Unsupported report value type: {type(value).__name__}"
    )


def generate_incident_report(case_id, db_path):
    """Generate a read-only report from an existing SOC incident."""

    if not isinstance(case_id, str) or not case_id.strip():
        raise IncidentReportError("Invalid incident case ID")

    if not db_path:
        raise IncidentReportError("Database path is required")

    incident = get_incident(case_id, db_path)

    if incident is None:
        raise IncidentReportError("Incident not found")

    evidence = get_incident_evidence(case_id, db_path)
    audit = get_incident_audit(case_id, db_path)

    incident_data = normalize(incident)
    evidence_data = normalize(evidence or [])
    audit_data = normalize(audit or [])

    if not isinstance(incident_data, dict):
        raise IncidentReportError("Invalid incident record")

    if not isinstance(evidence_data, list):
        raise IncidentReportError("Invalid evidence records")

    if not isinstance(audit_data, list):
        raise IncidentReportError("Invalid audit records")

    report = {
        "report_type": "SOC_INCIDENT_REPORT",
        "report_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "incident": incident_data,
        "evidence": evidence_data,
        "audit_trail": audit_data,
        "summary": {
            "evidence_count": len(evidence_data),
            "audit_events": len(audit_data),
            "incident_status": incident_data.get("status"),
            "incident_verdict": incident_data.get("verdict"),
        },
    }

    return report


def report_to_json(report):
    """Serialize a report as formatted JSON."""

    return json.dumps(
        report,
        indent=2,
        ensure_ascii=False,
        allow_nan=False,
    )
