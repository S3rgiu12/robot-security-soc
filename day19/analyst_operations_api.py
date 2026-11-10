from flask import Blueprint, request, jsonify

from flask_session_auth import (
    require_analyst,
    current_analyst
)

from analyst_workflow_engine import (
    assign_case,
    change_status,
    add_note
)

analyst_operations_bp = Blueprint(
    "analyst_operations",
    __name__
)


def error_response(error):
    if isinstance(error, PermissionError):
        return jsonify({
            "status": "FORBIDDEN",
            "error": str(error)
        }), 403

    if isinstance(error, ValueError):
        return jsonify({
            "status": "INVALID_REQUEST",
            "error": str(error)
        }), 400

    raise error


def request_data():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        raise ValueError("JSON object required")

    return data


def analyst_identity():
    user = current_analyst()

    if user is None or user.get("role") != "ANALYST":
        raise PermissionError("Analyst role required")

    return user["username"]


@analyst_operations_bp.route(
    "/api/day19/cases/<incident_id>/assign",
    methods=["POST"]
)
@require_analyst
def assign_incident(incident_id):
    try:
        actor = analyst_identity()
        data = request_data()

        if data:
            raise ValueError(
                "Assignment does not accept additional fields"
            )

        assign_case(
            incident_id=incident_id,
            analyst=actor,
            actor=actor
        )

        return jsonify({
            "status": "OK",
            "incident_id": incident_id,
            "workflow_status": "ASSIGNED",
            "assigned_to": actor
        }), 200

    except (ValueError, PermissionError) as error:
        return error_response(error)


@analyst_operations_bp.route(
    "/api/day19/cases/<incident_id>/status",
    methods=["POST"]
)
@require_analyst
def update_incident_status(incident_id):
    try:
        actor = analyst_identity()
        data = request_data()

        if set(data) - {"new_status", "note"}:
            raise ValueError("Unexpected request fields")

        new_status = data.get("new_status")
        note = data.get("note", "")

        if new_status not in ("IN_REVIEW", "CLOSED"):
            raise ValueError("Invalid target status")

        if new_status == "CLOSED" and (
            not isinstance(note, str) or not note.strip()
        ):
            raise ValueError(
                "Closing a case requires a resolution note"
            )

        change_status(
            incident_id=incident_id,
            new_status=new_status,
            actor=actor,
            note=note
        )

        return jsonify({
            "status": "OK",
            "incident_id": incident_id,
            "workflow_status": new_status
        }), 200

    except (ValueError, PermissionError) as error:
        return error_response(error)


@analyst_operations_bp.route(
    "/api/day19/cases/<incident_id>/notes",
    methods=["POST"]
)
@require_analyst
def add_incident_note(incident_id):
    try:
        actor = analyst_identity()
        data = request_data()

        if set(data) != {"note"}:
            raise ValueError("Only the note field is accepted")

        add_note(
            incident_id=incident_id,
            actor=actor,
            note=data["note"]
        )

        return jsonify({
            "status": "OK",
            "incident_id": incident_id,
            "message": "Investigation note recorded"
        }), 200

    except (ValueError, PermissionError) as error:
        return error_response(error)
