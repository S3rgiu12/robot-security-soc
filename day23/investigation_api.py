from flask import Blueprint, jsonify, request, current_app

from flask_session_auth import (
    require_analyst,
    current_analyst,
)

from threat_alert_engine import generate_alerts

from investigation_engine import (
    get_investigation,
    update_investigation,
    add_investigation_note,
    get_audit_trail,
)


investigation_bp = Blueprint(
    "day23_investigations",
    __name__
)


def load_alerts():
    results = generate_alerts()

    alerts = results.get("alerts", [])

    return {
        alert["alert_id"]: alert
        for alert in alerts
    }


def database_path():
    return current_app.config.get(
        "DAY23_INVESTIGATION_DB"
    )


def analyst_identity():
    analyst = current_analyst()

    if analyst is None:
        return None

    if analyst.get("role") != "ANALYST":
        return None

    return analyst["username"]


def error_response(message, status):
    return jsonify({"error": message}), status


@investigation_bp.get("/api/day23/investigations")
@require_analyst
def list_investigations():
    if analyst_identity() is None:
        return error_response("Analyst role required", 403)

    try:
        alerts = load_alerts()

        investigations = []

        for alert_id, alert in alerts.items():
            investigation = get_investigation(
                alert_id,
                database_path()
            )

            investigations.append({
                **alert,
                "investigation": investigation,
            })

        return jsonify({
            "status": "OK",
            "total": len(investigations),
            "investigations": investigations,
        })

    except (OSError, ValueError, KeyError, TypeError):
        current_app.logger.exception(
            "Day23 investigation listing failed"
        )
        return error_response(
            "Investigation data unavailable", 503
        )


@investigation_bp.get(
    "/api/day23/investigations/<alert_id>"
)
@require_analyst
def investigation_details(alert_id):
    if analyst_identity() is None:
        return error_response("Analyst role required", 403)

    try:
        alerts = load_alerts()

        if alert_id not in alerts:
            return error_response("Unknown alert ID", 404)

        return jsonify({
            "alert": alerts[alert_id],
            "investigation": get_investigation(
                alert_id,
                database_path()
            ),
        })

    except (OSError, ValueError, KeyError, TypeError):
        current_app.logger.exception(
            "Day23 investigation details failed"
        )
        return error_response(
            "Investigation data unavailable", 503
        )


@investigation_bp.post(
    "/api/day23/investigations/<alert_id>/status"
)
@require_analyst
def change_investigation_status(alert_id):
    analyst = analyst_identity()

    if analyst is None:
        return error_response("Analyst role required", 403)

    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return error_response("JSON object required", 400)

    try:
        alerts = load_alerts()

        if alert_id not in alerts:
            return error_response("Unknown alert ID", 404)

        result = update_investigation(
            alert_id=alert_id,
            new_status=payload.get("status"),
            analyst=analyst,
            known_alert_ids=set(alerts),
            note=payload.get("note"),
            db_path=database_path(),
        )

        return jsonify({
            "status": "OK",
            "investigation": result,
        })

    except ValueError as exc:
        return error_response(str(exc), 400)

    except (OSError, KeyError, TypeError):
        current_app.logger.exception(
            "Day23 status update failed"
        )
        return error_response(
            "Investigation update unavailable", 503
        )


@investigation_bp.post(
    "/api/day23/investigations/<alert_id>/notes"
)
@require_analyst
def add_note(alert_id):
    analyst = analyst_identity()

    if analyst is None:
        return error_response("Analyst role required", 403)

    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return error_response("JSON object required", 400)

    try:
        alerts = load_alerts()

        if alert_id not in alerts:
            return error_response("Unknown alert ID", 404)

        result = add_investigation_note(
            alert_id=alert_id,
            analyst=analyst,
            note=payload.get("note"),
            known_alert_ids=set(alerts),
            db_path=database_path(),
        )

        return jsonify({
            "status": "OK",
            "investigation": result,
        })

    except ValueError as exc:
        return error_response(str(exc), 400)

    except (OSError, KeyError, TypeError):
        current_app.logger.exception(
            "Day23 note creation failed"
        )
        return error_response(
            "Investigation note unavailable", 503
        )


@investigation_bp.get(
    "/api/day23/investigations/<alert_id>/audit"
)
@require_analyst
def investigation_audit(alert_id):
    if analyst_identity() is None:
        return error_response("Analyst role required", 403)

    try:
        alerts = load_alerts()

        if alert_id not in alerts:
            return error_response("Unknown alert ID", 404)

        events = get_audit_trail(
            alert_id,
            database_path()
        )

        return jsonify({
            "status": "OK",
            "alert_id": alert_id,
            "total": len(events),
            "events": events,
        })

    except (OSError, ValueError, KeyError, TypeError):
        current_app.logger.exception(
            "Day23 audit retrieval failed"
        )
        return error_response(
            "Investigation audit unavailable", 503
        )
