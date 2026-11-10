"""Day 27 - Authenticated SOC incident integrity API."""

from functools import wraps

from flask import Blueprint, jsonify

from flask_session_auth import (
    require_analyst,
    current_analyst,
)

from day27.manifest_security import validate_case_id
from day27.report_integrity import ReportIntegrityError
from day27.secure_bundle_verifier import verify_secure_bundle


integrity_bp = Blueprint(
    "day27_integrity",
    __name__,
)


def secure_response(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def integrity_error(message, status_code):
    response = jsonify({
        "status": "ERROR",
        "error": message,
    })
    return secure_response(response), status_code


def require_integrity_role(view):
    """Allow only authenticated SOC ANALYST users."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        analyst = current_analyst()

        if analyst is None:
            return integrity_error(
                "Authentication required", 401
            )

        if analyst.get("role") != "ANALYST":
            return integrity_error(
                "Insufficient permissions", 403
            )

        return view(*args, **kwargs)

    return wrapped


@integrity_bp.get(
    "/api/day27/incidents/<case_id>/integrity"
)
@require_analyst
@require_integrity_role
def incident_integrity(case_id):
    """Verify an exported SOC incident bundle."""

    try:
        validate_case_id(case_id)
    except ReportIntegrityError:
        return integrity_error(
            "Invalid incident case ID", 400
        )

    try:
        result = verify_secure_bundle(case_id)
    except ReportIntegrityError:
        return integrity_error(
            "Incident bundle unavailable or invalid", 404
        )

    response = jsonify(result)
    return secure_response(response), 200
