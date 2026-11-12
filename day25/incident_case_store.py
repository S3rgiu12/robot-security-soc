"""Day 25 - SQLite incident case storage."""

import sqlite3
from pathlib import Path

from day25.incident_case_engine import (
    create_case_record,
    create_audit_record,
)

DEFAULT_DB = (
    Path(__file__).resolve().parent
    / "data"
    / "soc_incident_cases.db"
)


def connect(db_path=DEFAULT_DB):
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(
        str(path),
        timeout=10,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    return connection


def initialize_database(db_path=DEFAULT_DB):
    with connect(db_path) as connection:
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS incident_cases (
                case_id TEXT PRIMARY KEY,
                alert_id TEXT NOT NULL,
                status TEXT NOT NULL
                    CHECK(status IN (
                        'OPEN',
                        'INVESTIGATING',
                        'RESOLVED',
                        'CLOSED'
                    )),
                severity TEXT NOT NULL
                    CHECK(severity IN (
                        'LOW',
                        'MEDIUM',
                        'HIGH',
                        'CRITICAL'
                    )),
                verdict TEXT NOT NULL
                    CHECK(verdict IN (
                        'UNDETERMINED',
                        'TRUE_POSITIVE',
                        'FALSE_POSITIVE',
                        'BENIGN_ACTIVITY'
                    )),
                assigned_analyst TEXT NOT NULL,
                description TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS incident_case_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                analyst TEXT NOT NULL,
                action TEXT NOT NULL,
                previous_status TEXT,
                new_status TEXT,
                note TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(case_id)
                    REFERENCES incident_cases(case_id)
            );

            CREATE INDEX IF NOT EXISTS
                idx_incident_cases_alert
                ON incident_cases(alert_id);

            CREATE INDEX IF NOT EXISTS
                idx_incident_audit_case
                ON incident_case_audit(case_id);
        """)


def create_incident(
    alert_id,
    severity,
    analyst,
    description,
    db_path=DEFAULT_DB,
):
    case = create_case_record(
        alert_id=alert_id,
        severity=severity,
        analyst=analyst,
        description=description,
    )

    audit = create_audit_record(
        case_id=case["case_id"],
        analyst=analyst,
        action="CASE_CREATED",
        new_status="OPEN",
        note="Incident case created",
    )

    with connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO incident_cases (
                case_id, alert_id, status,
                severity, verdict,
                assigned_analyst, description,
                created_at, updated_at
            )
            VALUES (
                :case_id, :alert_id, :status,
                :severity, :verdict,
                :assigned_analyst, :description,
                :created_at, :updated_at
            )
            """,
            case,
        )

        connection.execute(
            """
            INSERT INTO incident_case_audit (
                case_id, analyst, action,
                previous_status, new_status,
                note, created_at
            )
            VALUES (
                :case_id, :analyst, :action,
                :previous_status, :new_status,
                :note, :created_at
            )
            """,
            audit,
        )

    return case


def get_incident(case_id, db_path=DEFAULT_DB):
    with connect(db_path) as connection:
        row = connection.execute(
            """
            SELECT *
            FROM incident_cases
            WHERE case_id = ?
            """,
            (case_id,),
        ).fetchone()

        return dict(row) if row else None


def get_incident_audit(case_id, db_path=DEFAULT_DB):
    with connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM incident_case_audit
            WHERE case_id = ?
            ORDER BY id ASC
            """,
            (case_id,),
        ).fetchall()

        return [dict(row) for row in rows]


def change_incident_status(
    case_id,
    new_status,
    analyst,
    note,
    db_path=DEFAULT_DB,
):
    """Change case status and record audit atomically."""

    from day25.incident_case_engine import (
        validate_transition,
        create_audit_record,
        utc_now,
    )

    if not isinstance(case_id, str) or not case_id.strip():
        raise ValueError("Case ID is required")

    if not isinstance(analyst, str) or not analyst.strip():
        raise ValueError("Analyst identity is required")

    if not isinstance(note, str) or not note.strip():
        raise ValueError("Transition note is required")

    with connect(db_path) as connection:
        # Acquire the write lock before reading current status.
        connection.execute("BEGIN IMMEDIATE")

        row = connection.execute(
            """
            SELECT status, verdict
            FROM incident_cases
            WHERE case_id = ?
            """,
            (case_id,),
        ).fetchone()

        if row is None:
            raise ValueError("Incident case not found")

        previous_status = row["status"]

        validate_transition(
            previous_status,
            new_status,
        )

        if new_status in {"RESOLVED", "CLOSED"}:
            if row["verdict"] == "UNDETERMINED":
                raise ValueError(
                    "A documented verdict is required"
                )

        if new_status == "CLOSED":
            evidence_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM incident_evidence
                WHERE case_id = ?
                """,
                (case_id,),
            ).fetchone()[0]

            if evidence_count < 1:
                raise ValueError(
                    "At least one evidence reference is required"
                )

        timestamp = utc_now()

        connection.execute(
            """
            UPDATE incident_cases
            SET status = ?,
                updated_at = ?
            WHERE case_id = ?
            """,
            (
                new_status,
                timestamp,
                case_id,
            ),
        )

        audit = create_audit_record(
            case_id=case_id,
            analyst=analyst,
            action="STATUS_CHANGED",
            previous_status=previous_status,
            new_status=new_status,
            note=note.strip(),
        )

        connection.execute(
            """
            INSERT INTO incident_case_audit (
                case_id,
                analyst,
                action,
                previous_status,
                new_status,
                note,
                created_at
            )
            VALUES (
                :case_id,
                :analyst,
                :action,
                :previous_status,
                :new_status,
                :note,
                :created_at
            )
            """,
            audit,
        )

    return get_incident(case_id, db_path)


def change_incident_verdict(
    case_id,
    new_verdict,
    analyst,
    note,
    db_path=DEFAULT_DB,
):
    """Update an investigation verdict with atomic audit."""

    from day25.incident_case_engine import (
        validate_verdict,
        create_audit_record,
        utc_now,
    )

    if not isinstance(case_id, str) or not case_id.strip():
        raise ValueError("Case ID is required")

    if not isinstance(analyst, str) or not analyst.strip():
        raise ValueError("Analyst identity is required")

    if not isinstance(note, str) or not note.strip():
        raise ValueError("Verdict justification is required")

    validate_verdict(new_verdict)

    with connect(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")

        row = connection.execute(
            """
            SELECT verdict, status
            FROM incident_cases
            WHERE case_id = ?
            """,
            (case_id,),
        ).fetchone()

        if row is None:
            raise ValueError("Incident case not found")

        if row["status"] == "CLOSED":
            raise ValueError(
                "Cannot change verdict of a closed case"
            )

        previous_verdict = row["verdict"]

        if previous_verdict == new_verdict:
            raise ValueError(
                "New verdict must differ from current verdict"
            )

        timestamp = utc_now()

        connection.execute(
            """
            UPDATE incident_cases
            SET verdict = ?,
                updated_at = ?
            WHERE case_id = ?
            """,
            (
                new_verdict,
                timestamp,
                case_id,
            ),
        )

        audit = create_audit_record(
            case_id=case_id,
            analyst=analyst,
            action="VERDICT_CHANGED",
            note=(
                f"{previous_verdict} -> {new_verdict}: "
                f"{note.strip()}"
            ),
        )

        connection.execute(
            """
            INSERT INTO incident_case_audit (
                case_id,
                analyst,
                action,
                previous_status,
                new_status,
                note,
                created_at
            )
            VALUES (
                :case_id,
                :analyst,
                :action,
                :previous_status,
                :new_status,
                :note,
                :created_at
            )
            """,
            audit,
        )

    return get_incident(case_id, db_path)


def initialize_evidence_table(db_path=DEFAULT_DB):
    """Initialize evidence storage without altering existing cases."""

    with connect(db_path) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS incident_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                source TEXT NOT NULL,
                reference_id TEXT NOT NULL,
                description TEXT NOT NULL,
                added_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(case_id)
                    REFERENCES incident_cases(case_id),
                UNIQUE(case_id, evidence_type, source, reference_id)
            )
        """)


def add_incident_evidence(
    case_id,
    evidence_type,
    source,
    reference_id,
    description,
    analyst,
    db_path=DEFAULT_DB,
    *,
    log_path=None,
    security_log_path=None,
):
    """Attach only validated SOC evidence and audit the action."""

    from day25.incident_case_engine import (
        create_audit_record,
        utc_now,
    )

    fields = {
        "case_id": case_id,
        "evidence_type": evidence_type,
        "source": source,
        "reference_id": reference_id,
        "description": description,
        "analyst": analyst,
    }

    for name, value in fields.items():
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} is required")

    if evidence_type not in {
        "IOC_ALERT",
        "LOG_EVENT",
        "IDS_ALERT",
        "INVESTIGATION",
    }:
        raise ValueError("Invalid evidence type")

    expected_sources = {
        "IOC_ALERT": "DAY22",
        "LOG_EVENT": "DAY24",
        "IDS_ALERT": "IDS_V3",
    }

    if evidence_type == "INVESTIGATION":
        raise ValueError(
            "Investigation evidence requires Day23 verification"
        )

    if source.strip() != expected_sources[evidence_type]:
        raise ValueError(
            "Evidence source does not match evidence type"
        )

    if log_path is None:
        raise ValueError(
            "Evidence validation log_path is required"
        )

    from day25.evidence_validator import (
        validate_evidence_reference,
    )

    with connect(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")

        case = connection.execute(
            """
            SELECT status, alert_id
            FROM incident_cases
            WHERE case_id = ?
            """,
            (case_id,),
        ).fetchone()

        if case is None:
            raise ValueError("Incident case not found")

        if case["status"] == "CLOSED":
            raise ValueError(
                "Cannot add evidence to a closed case"
            )

        if evidence_type == "IDS_ALERT":
            from day25.ids_evidence_validator import (
                validate_ids_alert,
            )

            validate_ids_alert(
                reference_id=reference_id.strip(),
                incident_alert_id=case["alert_id"],
                log_path=log_path,
            )

            if security_log_path is None:
                raise ValueError(
                    "TLS security log is required for IDS evidence"
                )

            from day25.ids_tls_correlation import (
                validate_tls_correlation,
            )

            validate_tls_correlation(
                alert_id=reference_id.strip(),
                alert_log_path=log_path,
                security_log_path=security_log_path,
            )
        else:
            validate_evidence_reference(
                evidence_type=evidence_type,
                reference_id=reference_id.strip(),
                incident_alert_id=case["alert_id"],
                log_path=log_path,
            )

        connection.execute(
            """
            INSERT INTO incident_evidence (
                case_id, evidence_type, source,
                reference_id, description,
                added_by, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                evidence_type,
                source.strip(),
                reference_id.strip(),
                description.strip(),
                analyst.strip(),
                utc_now(),
            ),
        )

        audit = create_audit_record(
            case_id=case_id,
            analyst=analyst,
            action="EVIDENCE_ADDED",
            note=(
                f"{evidence_type}: "
                f"{reference_id.strip()}"
            ),
        )

        connection.execute(
            """
            INSERT INTO incident_case_audit (
                case_id, analyst, action,
                previous_status, new_status,
                note, created_at
            )
            VALUES (
                :case_id, :analyst, :action,
                :previous_status, :new_status,
                :note, :created_at
            )
            """,
            audit,
        )


def get_incident_evidence(case_id, db_path=DEFAULT_DB):
    with connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM incident_evidence
            WHERE case_id = ?
            ORDER BY id ASC
            """,
            (case_id,),
        ).fetchall()

        return [dict(row) for row in rows]
