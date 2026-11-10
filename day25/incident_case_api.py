import sqlite3
"""Day 25 - SOC Incident Case API."""

from pathlib import Path

from flask import (
    Blueprint,
    current_app,
    jsonify,
    request,
)

from flask_session_auth import (
    require_analyst,
    current_analyst,
)

from threat_alert_engine import generate_alerts

from day25.incident_case_store import (
    DEFAULT_DB,
    connect,
    create_incident,
    get_incident,
)


incident_case_bp = Blueprint(
    "day25_incident_cases",
    __name__,
)


def analyst_identity():
    analyst = current_analyst()

    if not analyst:
        return None

    if analyst.get("role") != "ANALYST":
        return None

    return analyst["username"]


def database_path():
    return current_app.config.get(
        "DAY25_INCIDENT_DB",
        str(DEFAULT_DB),
    )


def alert_log_path():
    return current_app.config.get(
        "DAY25_ALERT_LOG",
    )


def load_alerts():
    results = generate_alerts(
        log_path=alert_log_path()
    )

    return {
        alert["alert_id"]: alert
        for alert in results["alerts"]
    }


def error_response(message, status):
    return jsonify({"error": message}), status


@incident_case_bp.get("/api/day25/incidents")
@require_analyst
def list_incidents():
    if analyst_identity() is None:
        return error_response(
            "Analyst role required", 403
        )

    try:
        with connect(database_path()) as db:
            rows = db.execute(
                """
                SELECT *
                FROM incident_cases
                ORDER BY created_at DESC, case_id DESC
                """
            ).fetchall()

        incidents = [dict(row) for row in rows]

        return jsonify({
            "status": "OK",
            "total": len(incidents),
            "incidents": incidents,
        })

    except (OSError, ValueError, sqlite3.Error):
        current_app.logger.exception(
            "Day25 incident listing failed"
        )
        return error_response(
            "Incident data unavailable", 503
        )


@incident_case_bp.get(
    "/api/day25/incidents/<case_id>"
)
@require_analyst
def incident_details(case_id):
    if analyst_identity() is None:
        return error_response(
            "Analyst role required", 403
        )

    try:
        incident = get_incident(
            case_id,
            database_path(),
        )

        if incident is None:
            return error_response(
                "Incident not found", 404
            )

        return jsonify({
            "status": "OK",
            "incident": incident,
        })

    except (OSError, ValueError, sqlite3.Error):
        current_app.logger.exception(
            "Day25 incident details failed"
        )
        return error_response(
            "Incident data unavailable", 503
        )


@incident_case_bp.post("/api/day25/incidents")
@require_analyst
def create_incident_endpoint():
    analyst = analyst_identity()

    if analyst is None:
        return error_response(
            "Analyst role required", 403
        )

    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return error_response(
            "JSON object required", 400
        )

    alert_id = payload.get("alert_id")
    description = payload.get("description")

    if not isinstance(alert_id, str):
        return error_response(
            "Invalid alert ID", 400
        )

    if (
        not isinstance(description, str)
        or not description.strip()
        or len(description) > 2000
    ):
        return error_response(
            "Description must contain 1-2000 characters",
            400,
        )

    try:
        alerts = load_alerts()

        if alert_id not in alerts:
            return error_response(
                "Unknown alert ID", 404
            )

        alert = alerts[alert_id]

        incident = create_incident(
            alert_id=alert_id,
            severity=alert["severity"],
            analyst=analyst,
            description=description,
            db_path=database_path(),
        )

        return jsonify({
            "status": "OK",
            "incident": incident,
        }), 201

    except ValueError as exc:
        return error_response(str(exc), 400)

    except (OSError, KeyError, TypeError, sqlite3.Error):
        current_app.logger.exception(
            "Day25 incident creation failed"
        )
        return error_response(
            "Incident creation unavailable", 503
        )


# DAY25_INCIDENT_MANAGEMENT_ENDPOINTS

from day25.incident_case_store import (
    change_incident_status,
    change_incident_verdict,
    add_incident_evidence,
    get_incident_evidence,
    get_incident_audit,
)
from day24.threat_hunting_engine import REAL_IDS_LOG


def incident_log_path():
    return current_app.config.get(
        "DAY25_ALERT_LOG",
        str(REAL_IDS_LOG),
    )


def incident_payload():
    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        raise ValueError("JSON object required")

    return payload


def required_text(payload, field, max_length=2000):
    value = payload.get(field)

    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > max_length
    ):
        raise ValueError(
            f"{field} must contain 1-{max_length} characters"
        )

    return value.strip()


def incident_error(exc):
    message = str(exc)

    if message == "Incident case not found":
        return error_response(message, 404)

    return error_response(message, 400)


@incident_case_bp.post(
    "/api/day25/incidents/<case_id>/status"
)
@require_analyst
def update_incident_status_endpoint(case_id):
    analyst = analyst_identity()

    if analyst is None:
        return error_response("Analyst role required", 403)

    try:
        payload = incident_payload()

        new_status = required_text(
            payload, "status", 30
        )
        note = required_text(
            payload, "note"
        )

        incident = change_incident_status(
            case_id=case_id,
            new_status=new_status,
            analyst=analyst,
            note=note,
            db_path=database_path(),
        )

        return jsonify({
            "status": "OK",
            "incident": incident,
        })

    except ValueError as exc:
        return incident_error(exc)

    except (OSError, sqlite3.Error):
        current_app.logger.exception(
            "Day25 status update failed"
        )
        return error_response(
            "Incident update unavailable", 503
        )


@incident_case_bp.post(
    "/api/day25/incidents/<case_id>/verdict"
)
@require_analyst
def update_incident_verdict_endpoint(case_id):
    analyst = analyst_identity()

    if analyst is None:
        return error_response("Analyst role required", 403)

    try:
        payload = incident_payload()

        verdict = required_text(
            payload, "verdict", 30
        )
        note = required_text(
            payload, "note"
        )

        incident = change_incident_verdict(
            case_id=case_id,
            new_verdict=verdict,
            analyst=analyst,
            note=note,
            db_path=database_path(),
        )

        return jsonify({
            "status": "OK",
            "incident": incident,
        })

    except ValueError as exc:
        return incident_error(exc)

    except (OSError, sqlite3.Error):
        current_app.logger.exception(
            "Day25 verdict update failed"
        )
        return error_response(
            "Incident update unavailable", 503
        )


@incident_case_bp.post(
    "/api/day25/incidents/<case_id>/evidence"
)
@require_analyst
def add_incident_evidence_endpoint(case_id):
    analyst = analyst_identity()

    if analyst is None:
        return error_response("Analyst role required", 403)

    try:
        payload = incident_payload()

        evidence_type = required_text(
            payload, "evidence_type", 30
        )
        source = required_text(
            payload, "source", 100
        )
        reference_id = required_text(
            payload, "reference_id", 150
        )
        description = required_text(
            payload, "description"
        )

        add_incident_evidence(
            case_id=case_id,
            evidence_type=evidence_type,
            source=source,
            reference_id=reference_id,
            description=description,
            analyst=analyst,
            db_path=database_path(),
            log_path=incident_log_path(),
        )

        return jsonify({
            "status": "OK",
            "message": "Evidence attached",
        }), 201

    except ValueError as exc:
        return incident_error(exc)

    except sqlite3.IntegrityError:
        return error_response(
            "Evidence already attached", 409
        )

    except (OSError, sqlite3.Error):
        current_app.logger.exception(
            "Day25 evidence attachment failed"
        )
        return error_response(
            "Evidence storage unavailable", 503
        )


@incident_case_bp.get(
    "/api/day25/incidents/<case_id>/evidence"
)
@require_analyst
def list_incident_evidence_endpoint(case_id):
    if analyst_identity() is None:
        return error_response("Analyst role required", 403)

    try:
        if get_incident(case_id, database_path()) is None:
            return error_response(
                "Incident not found", 404
            )

        evidence = get_incident_evidence(
            case_id, database_path()
        )

        return jsonify({
            "status": "OK",
            "total": len(evidence),
            "evidence": evidence,
        })

    except (OSError, sqlite3.Error):
        current_app.logger.exception(
            "Day25 evidence listing failed"
        )
        return error_response(
            "Evidence unavailable", 503
        )


@incident_case_bp.get(
    "/api/day25/incidents/<case_id>/audit"
)
@require_analyst
def list_incident_audit_endpoint(case_id):
    if analyst_identity() is None:
        return error_response("Analyst role required", 403)

    try:
        if get_incident(case_id, database_path()) is None:
            return error_response(
                "Incident not found", 404
            )

        audit = get_incident_audit(
            case_id, database_path()
        )

        return jsonify({
            "status": "OK",
            "total": len(audit),
            "audit": audit,
        })

    except (OSError, sqlite3.Error):
        current_app.logger.exception(
            "Day25 audit listing failed"
        )
        return error_response(
            "Audit unavailable", 503
        )


# END_DAY25_INCIDENT_MANAGEMENT_ENDPOINTS
