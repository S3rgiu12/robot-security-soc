import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
REGISTRY = BASE_DIR / "day09/data/incidents.json"
DATABASE = BASE_DIR / "day18/data/analyst_workflow.db"

ID_PATTERN = re.compile(r"INC-\d{4,}")
ACTOR_PATTERN = re.compile(r"[A-Za-z0-9_.-]{2,64}")

TRANSITIONS = {
    "NEW": {"ASSIGNED"},
    "ASSIGNED": {"IN_REVIEW"},
    "IN_REVIEW": {"CLOSED"},
    "CLOSED": set(),
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def connect(db_path=DATABASE):
    db = sqlite3.connect(db_path, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def registry_ids():
    incidents = json.loads(
        REGISTRY.read_text(encoding="utf-8")
    )
    return {
        item["incident_id"]
        for item in incidents
    }


def validate_incident(incident_id):
    if not isinstance(incident_id, str):
        raise ValueError("Invalid incident ID")

    if not ID_PATTERN.fullmatch(incident_id):
        raise ValueError("Invalid incident ID")

    if incident_id not in registry_ids():
        raise ValueError("Incident not found")


def validate_actor(actor):
    if not isinstance(actor, str):
        raise ValueError("Invalid analyst identity")

    if not ACTOR_PATTERN.fullmatch(actor):
        raise ValueError("Invalid analyst identity")


def initialize(db_path=DATABASE):
    with connect(db_path) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS analyst_cases (
                incident_id TEXT PRIMARY KEY,
                workflow_status TEXT NOT NULL
                    CHECK (
                        workflow_status IN (
                            'NEW',
                            'ASSIGNED',
                            'IN_REVIEW',
                            'CLOSED'
                        )
                    ),
                assigned_to TEXT,
                updated_at TEXT NOT NULL
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS analyst_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                previous_status TEXT,
                new_status TEXT,
                note TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (incident_id)
                    REFERENCES analyst_cases(incident_id)
            )
        """)

        now = utc_now()

        for incident_id in sorted(registry_ids()):
            db.execute("""
                INSERT OR IGNORE INTO analyst_cases (
                    incident_id,
                    workflow_status,
                    assigned_to,
                    updated_at
                )
                VALUES (?, 'NEW', NULL, ?)
            """, (incident_id, now))


def list_cases(db_path=DATABASE):
    with connect(db_path) as db:
        rows = db.execute("""
            SELECT *
            FROM analyst_cases
            ORDER BY incident_id
        """).fetchall()

        return [dict(row) for row in rows]


def get_audit(incident_id, db_path=DATABASE):
    validate_incident(incident_id)

    with connect(db_path) as db:
        rows = db.execute("""
            SELECT *
            FROM analyst_audit
            WHERE incident_id = ?
            ORDER BY id ASC
        """, (incident_id,)).fetchall()

        return [dict(row) for row in rows]


def assign_case(
    incident_id,
    analyst,
    actor,
    db_path=DATABASE
):
    validate_incident(incident_id)
    validate_actor(analyst)
    validate_actor(actor)

    with connect(db_path) as db:
        row = db.execute("""
            SELECT workflow_status
            FROM analyst_cases
            WHERE incident_id = ?
        """, (incident_id,)).fetchone()

        if row is None:
            raise ValueError("Case not initialized")

        if row["workflow_status"] != "NEW":
            raise ValueError("Case is not NEW")

        now = utc_now()

        result = db.execute("""
            UPDATE analyst_cases
            SET workflow_status = 'ASSIGNED',
                assigned_to = ?,
                updated_at = ?
            WHERE incident_id = ?
              AND workflow_status = 'NEW'
        """, (analyst, now, incident_id))

        if result.rowcount != 1:
            raise ValueError(
                "Case was already assigned by another analyst"
            )

        db.execute("""
            INSERT INTO analyst_audit (
                incident_id, actor, action,
                previous_status, new_status,
                note, created_at
            )
            VALUES (?, ?, 'ASSIGN', 'NEW',
                    'ASSIGNED', ?, ?)
        """, (
            incident_id,
            actor,
            f"Assigned to {analyst}",
            now
        ))


def change_status(
    incident_id,
    new_status,
    actor,
    note="",
    db_path=DATABASE
):
    validate_incident(incident_id)
    validate_actor(actor)

    if new_status not in TRANSITIONS:
        raise ValueError("Invalid workflow status")

    if not isinstance(note, str) or len(note) > 2000:
        raise ValueError("Invalid note")

    with connect(db_path) as db:
        row = db.execute("""
            SELECT workflow_status, assigned_to
            FROM analyst_cases
            WHERE incident_id = ?
        """, (incident_id,)).fetchone()

        if row is None:
            raise ValueError("Case not initialized")

        previous = row["workflow_status"]

        if new_status not in TRANSITIONS[previous]:
            raise ValueError(
                f"Invalid transition: {previous} -> {new_status}"
            )

        if new_status == "ASSIGNED":
            raise ValueError("Use assign_case")

        if row["assigned_to"] != actor:
            raise PermissionError(
                "Only the assigned analyst may change status"
            )

        now = utc_now()

        result = db.execute("""
            UPDATE analyst_cases
            SET workflow_status = ?,
                updated_at = ?
            WHERE incident_id = ?
              AND workflow_status = ?
              AND assigned_to = ?
        """, (
            new_status,
            now,
            incident_id,
            previous,
            actor
        ))

        if result.rowcount != 1:
            raise ValueError(
                "Case changed concurrently; retry operation"
            )

        db.execute("""
            INSERT INTO analyst_audit (
                incident_id, actor, action,
                previous_status, new_status,
                note, created_at
            )
            VALUES (?, ?, 'STATUS_CHANGE', ?, ?, ?, ?)
        """, (
            incident_id,
            actor,
            previous,
            new_status,
            note,
            now
        ))


def add_note(
    incident_id,
    actor,
    note,
    db_path=DATABASE
):
    validate_incident(incident_id)
    validate_actor(actor)

    if not isinstance(note, str):
        raise ValueError("Invalid note")

    note = note.strip()

    if not note or len(note) > 2000:
        raise ValueError("Note must contain 1-2000 characters")

    with connect(db_path) as db:
        row = db.execute("""
            SELECT workflow_status, assigned_to
            FROM analyst_cases
            WHERE incident_id = ?
        """, (incident_id,)).fetchone()

        if row is None:
            raise ValueError("Case not initialized")

        if row["workflow_status"] == "CLOSED":
            raise ValueError("Closed case cannot be modified")

        if row["assigned_to"] != actor:
            raise PermissionError(
                "Only the assigned analyst may add notes"
            )

        db.execute("""
            INSERT INTO analyst_audit (
                incident_id, actor, action,
                previous_status, new_status,
                note, created_at
            )
            VALUES (?, ?, 'NOTE', ?, ?, ?, ?)
        """, (
            incident_id,
            actor,
            row["workflow_status"],
            row["workflow_status"],
            note,
            utc_now()
        ))


if __name__ == "__main__":
    initialize()
    print("=== DAY 18 ANALYST WORKFLOW ===")
    print("Database:", DATABASE)
    print("Cases initialized:", len(list_cases()))
