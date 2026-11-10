"""Day 26 - Safe SOC Incident CSV Export."""

import csv
import io
import json


class IncidentCSVExportError(ValueError):
    """Invalid CSV export input."""


DANGEROUS_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")


def safe_csv_value(value):
    """Neutralize spreadsheet formula injection."""

    if value is None:
        return ""

    if isinstance(value, (dict, list, tuple)):
        value = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
        )

    value = str(value)

    # Leading whitespace must not bypass formula detection.
    if value.lstrip().startswith(DANGEROUS_PREFIXES):
        return "'" + value

    return value


def records_to_csv(records, columns):
    """Export structured records using an explicit column list."""

    if not isinstance(records, list):
        raise IncidentCSVExportError(
            "Records must be a list"
        )

    if not isinstance(columns, (list, tuple)) or not columns:
        raise IncidentCSVExportError(
            "Columns must be a non-empty list"
        )

    if not all(isinstance(c, str) and c for c in columns):
        raise IncidentCSVExportError(
            "Invalid column name"
        )

    if len(set(columns)) != len(columns):
        raise IncidentCSVExportError(
            "Duplicate column names"
        )

    output = io.StringIO(newline="")

    writer = csv.writer(
        output,
        quoting=csv.QUOTE_ALL,
        lineterminator="\r\n",
    )

    writer.writerow(columns)

    for record in records:
        if not isinstance(record, dict):
            raise IncidentCSVExportError(
                "Each record must be a dictionary"
            )

        writer.writerow([
            safe_csv_value(record.get(column))
            for column in columns
        ])

    return output.getvalue()


EVIDENCE_COLUMNS = [
    "id",
    "case_id",
    "evidence_type",
    "source",
    "reference_id",
    "description",
    "analyst",
    "created_at",
]

AUDIT_COLUMNS = [
    "id",
    "case_id",
    "analyst",
    "action",
    "previous_status",
    "new_status",
    "note",
    "created_at",
]


def export_evidence_csv(report):
    """Export incident evidence to CSV."""

    if not isinstance(report, dict):
        raise IncidentCSVExportError("Invalid report")

    return records_to_csv(
        report.get("evidence", []),
        EVIDENCE_COLUMNS,
    )


def export_audit_csv(report):
    """Export incident audit history to CSV."""

    if not isinstance(report, dict):
        raise IncidentCSVExportError("Invalid report")

    return records_to_csv(
        report.get("audit_trail", []),
        AUDIT_COLUMNS,
    )
