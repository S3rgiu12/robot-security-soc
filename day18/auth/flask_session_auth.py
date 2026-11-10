import secrets
from functools import wraps

from flask import (
    session,
    request,
    jsonify
)

from analyst_auth import (
    authenticate_analyst,
    connect_auth
)


def login_analyst(username, password):
    user = authenticate_analyst(username, password)

    if user is None:
        return None

    session.clear()
    session["analyst_username"] = user["username"]
    session["csrf_token"] = secrets.token_urlsafe(32)

    return user


def current_analyst():
    username = session.get("analyst_username")

    if not username:
        return None

    with connect_auth() as db:
        row = db.execute("""
            SELECT username, role, active
            FROM analyst_users
            WHERE username = ?
        """, (username,)).fetchone()

    if row is None or not row["active"]:
        return None

    return {
        "username": row["username"],
        "role": row["role"]
    }


def logout_analyst():
    session.clear()


def require_analyst(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_analyst()

        if user is None:
            return jsonify({
                "error": "Authentication required"
            }), 401

        if request.method not in (
            "GET", "HEAD", "OPTIONS"
        ):
            expected = session.get("csrf_token")
            provided = request.headers.get(
                "X-CSRF-Token", ""
            )

            if not expected or not secrets.compare_digest(
                expected, provided
            ):
                return jsonify({
                    "error": "Invalid CSRF token"
                }), 403

        return view(*args, **kwargs)

    return wrapped
