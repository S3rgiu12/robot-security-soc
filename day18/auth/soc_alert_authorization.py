import secrets

from flask import request, session

from flask_session_auth import current_analyst


def analyst_can_update_alert():
    user = current_analyst()

    if user is None:
        return False

    if user.get("role") != "ANALYST":
        return False

    expected = session.get("csrf_token")
    provided = request.headers.get("X-CSRF-Token", "")

    if not isinstance(expected, str):
        return False

    if not isinstance(provided, str):
        return False

    if not expected or not provided:
        return False

    return secrets.compare_digest(expected, provided)
