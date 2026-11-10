from datetime import datetime, timezone

from investigation_store import (
    connect_db,
    initialize_database,
    VALID_STATUSES,
)


ALLOWED_TRANSITIONS = {
    "UNREVIEWED": {"INVESTIGATING"},
    "INVESTIGATING": {"CONFIRMED", "FALSE_POSITIVE"},
    "CONFIRMED": set(),
    "FALSE_POSITIVE": set(),
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def validate_alert_id(alert_id, known_alert_ids):
    if not isinstance(alert_id, str):
        raise ValueError("Invalid alert ID")

    if alert_id not in known_alert_ids:
        raise ValueError("Unknown alert ID")


def get_investigation(alert_id, db_path=None):
    initialize_database(db_path)

    with connect_db(db_path) as connection:
        row = connection.execute(
            """
            SELECT *
            FROM alert_investigations
            WHERE alert_id = ?
            """,
            (alert_id,)
        ).fetchone()

    if row is None:
        return {
            "alert_id": alert_id,
            "status": "UNREVIEWED",
            "assigned_analyst": None,
            "created_at": None,
            "updated_at": None,
        }

    return dict(row)


def update_investigation(
    alert_id,
    new_status,
    analyst,
    known_alert_ids,
    note=None,
    db_path=None,
):
    validate_alert_id(alert_id, known_alert_ids)

    if new_status not in VALID_STATUSES:
        raise ValueError("Invalid investigation status")

    if not isinstance(analyst, str) or not analyst.strip():
        raise ValueError("Analyst identity required")

    analyst = analyst.strip()

    if note is not None and not isinstance(note, str):
        raise ValueError("Note must be text")

    note = note.strip() if note else None

    if note and len(note) > 4000:
        raise ValueError("Note exceeds 4000 characters")

    if new_status in ("CONFIRMED", "FALSE_POSITIVE") and not note:
        raise ValueError("Final status requires an investigation note")

    initialize_database(db_path)

    with connect_db(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")

        existing = connection.execute(
            """
            SELECT *
            FROM alert_investigations
            WHERE alert_id = ?
            """,
            (alert_id,)
        ).fetchone()

        old_status = (
            existing["status"] if existing else "UNREVIEWED"
        )

        if existing is not None:
            assigned = existing["assigned_analyst"]

            if assigned != analyst:
                raise ValueError(
                    "Only the assigned analyst can change status"
                )

        if new_status not in ALLOWED_TRANSITIONS[old_status]:
            raise ValueError(
                f"Invalid transition: {old_status} -> {new_status}"
            )

        timestamp = utc_now()

        if existing is None:
            connection.execute(
                """
                INSERT INTO alert_investigations (
                    alert_id,
                    status,
                    assigned_analyst,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    alert_id,
                    new_status,
                    analyst,
                    timestamp,
                    timestamp,
                )
            )
        else:
            connection.execute(
                """
                UPDATE alert_investigations
                SET status = ?,
                    assigned_analyst = ?,
                    updated_at = ?
                WHERE alert_id = ?
                """,
                (
                    new_status,
                    analyst,
                    timestamp,
                    alert_id,
                )
            )

        connection.execute(
            """
            INSERT INTO alert_investigation_audit (
                alert_id,
                analyst,
                action,
                previous_status,
                new_status,
                note,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert_id,
                analyst,
                "STATUS_CHANGED",
                old_status,
                new_status,
                note,
                timestamp,
            )
        )

    return get_investigation(alert_id, db_path)


def get_audit_trail(alert_id, db_path=None):
    initialize_database(db_path)

    with connect_db(db_path) as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                alert_id,
                analyst,
                action,
                previous_status,
                new_status,
                note,
                created_at
            FROM alert_investigation_audit
            WHERE alert_id = ?
            ORDER BY id ASC
            """,
            (alert_id,)
        ).fetchall()

    return [dict(row) for row in rows]


def add_investigation_note(
    alert_id,
    analyst,
    note,
    known_alert_ids,
    db_path=None,
):
    validate_alert_id(alert_id, known_alert_ids)

    if not isinstance(analyst, str) or not analyst.strip():
        raise ValueError("Analyst identity required")

    if not isinstance(note, str) or not note.strip():
        raise ValueError("Investigation note required")

    analyst = analyst.strip()
    note = note.strip()

    if len(note) > 4000:
        raise ValueError("Note exceeds 4000 characters")

    initialize_database(db_path)

    with connect_db(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")

        existing = connection.execute(
            """
            SELECT status, assigned_analyst
            FROM alert_investigations
            WHERE alert_id = ?
            """,
            (alert_id,)
        ).fetchone()

        if existing is None:
            raise ValueError("Investigation has not started")

        if existing["status"] != "INVESTIGATING":
            raise ValueError(
                "Notes are allowed only during investigation"
            )

        if existing["assigned_analyst"] != analyst:
            raise ValueError(
                "Only the assigned analyst can add notes"
            )

        timestamp = utc_now()

        connection.execute(
            """
            INSERT INTO alert_investigation_audit (
                alert_id,
                analyst,
                action,
                previous_status,
                new_status,
                note,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert_id,
                analyst,
                "NOTE_ADDED",
                existing["status"],
                existing["status"],
                note,
                timestamp,
            )
        )

        connection.execute(
            """
            UPDATE alert_investigations
            SET updated_at = ?
            WHERE alert_id = ?
            """,
            (timestamp, alert_id)
        )

    return get_investigation(alert_id, db_path)
