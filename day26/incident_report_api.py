"""Day 26 - Secure SOC Incident Reporting API."""

import re
from pathlib import Path

from flask import (
    Blueprint,
    Response,
    current_app,
    jsonify,
)

from flask_session_auth import require_analyst, current_analyst

from day25.incident_case_store import DEFAULT_DB
from day26.incident_report_engine import (
    IncidentReportError,
    generate_incident_report,
)
from day26.incident_csv_export import (
    export_evidence_csv,
    export_audit_csv,
)


incident_report_bp = Blueprint(
    "day26_incident_reports",
    __name__,
)

CASE_ID_PATTERN = re.compile(
    r"^INC-[A-Za-z0-9_-]{1,64}$"
)



def require_reporting_role(view):
    """Restrict reporting to the ANALYST role."""
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        analyst = current_analyst()

        if analyst is None:
            return report_error(
                "Authentication required", 401
            )

        if analyst.get("role") != "ANALYST":
            return report_error(
                "Insufficient permissions", 403
            )

        return view(*args, **kwargs)

    return wrapped


def database_path():
    return Path(
        current_app.config.get(
            "DAY25_INCIDENT_DB",
            DEFAULT_DB,
        )
    )


def report_error(message, status):
    response = jsonify({
        "error": message,
    })
    response.status_code = status
    response.headers["Cache-Control"] = "no-store"
    return response


def load_report(case_id):
    if not CASE_ID_PATTERN.fullmatch(case_id):
        raise ValueError("Invalid incident case ID")

    return generate_incident_report(
        case_id,
        database_path(),
    )


def secure_response(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; sandbox"
    )
    return response


def handle_report_error(error):
    if isinstance(error, ValueError):
        return report_error("Invalid incident case ID", 400)

    if isinstance(error, IncidentReportError):
        return report_error("Incident not found", 404)

    current_app.logger.exception(
        "Day26 incident report generation failed"
    )
    return report_error("Report unavailable", 500)


@incident_report_bp.route(
    "/api/day26/incidents/<case_id>/report",
    methods=["GET"],
)
@require_analyst
@require_reporting_role
def incident_report_endpoint(case_id):
    try:
        report = load_report(case_id)
    except Exception as error:
        return handle_report_error(error)

    response = jsonify(report)
    return secure_response(response)


@incident_report_bp.route(
    "/api/day26/incidents/<case_id>/evidence.csv",
    methods=["GET"],
)
@require_analyst
@require_reporting_role
def incident_evidence_export_endpoint(case_id):
    try:
        report = load_report(case_id)
        content = export_evidence_csv(report)
    except Exception as error:
        return handle_report_error(error)

    response = Response(
        content,
        mimetype="text/csv",
    )
    response.headers["Content-Disposition"] = (
        f'attachment; filename="{case_id}-evidence.csv"'
    )
    return secure_response(response)


@incident_report_bp.route(
    "/api/day26/incidents/<case_id>/audit.csv",
    methods=["GET"],
)
@require_analyst
@require_reporting_role
def incident_audit_export_endpoint(case_id):
    try:
        report = load_report(case_id)
        content = export_audit_csv(report)
    except Exception as error:
        return handle_report_error(error)

    response = Response(
        content,
        mimetype="text/csv",
    )
    response.headers["Content-Disposition"] = (
        f'attachment; filename="{case_id}-audit.csv"'
    )
    return secure_response(response)
