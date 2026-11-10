"""Day 27 - SOC Report Integrity Manifest."""

import json
from datetime import datetime, timezone
from pathlib import Path

from day26.incident_report_engine import (
    generate_incident_report,
    report_to_json,
)
from day26.incident_csv_export import (
    export_evidence_csv,
    export_audit_csv,
)
from day27.report_integrity import (
    ReportIntegrityError,
    sha256_bytes,
    sha256_file,
)


from day27.manifest_security import validate_case_id, validate_manifest

from day27.secure_file_reader import secure_sha256_file

from day27.secure_manifest_reader import read_secure_manifest

EXPORT_NAMES = (
    "incident-report.json",
    "evidence.csv",
    "audit.csv",
)


def export_incident_bundle(case_id, db_path, output_root):
    """Export incident files and their SHA-256 manifest."""
    validate_case_id(case_id)

    report = generate_incident_report(case_id, db_path)

    output_dir = Path(output_root) / case_id

    # Avoid overwriting an existing evidence bundle.
    output_dir.mkdir(parents=True, exist_ok=False)

    contents = {
        "incident-report.json": (
            report_to_json(report) + "\n"
        ).encode("utf-8"),
        "evidence.csv": export_evidence_csv(
            report
        ).encode("utf-8"),
        "audit.csv": export_audit_csv(
            report
        ).encode("utf-8"),
    }

    files = {}

    for name, data in contents.items():
        target = output_dir / name
        target.write_bytes(data)

        files[name] = {
            "sha256": sha256_bytes(data),
            "size_bytes": len(data),
        }

    manifest = {
        "manifest_type": "SOC_REPORT_INTEGRITY",
        "manifest_version": "1.0",
        "case_id": case_id,
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "hash_algorithm": "SHA-256",
        "files": files,
    }

    validate_manifest(
        manifest,
        expected_case_id=case_id,
    )

    manifest_path = output_dir / "manifest.json"

    manifest_path.write_text(
        json.dumps(
            manifest,
            indent=2,
            ensure_ascii=False,
        ) + "\n",
        encoding="utf-8",
    )

    return output_dir, manifest


def verify_incident_bundle(output_dir):
    """Verify exported files against their manifest."""
    output_dir = Path(output_dir)

    manifest = read_secure_manifest(output_dir)

    validate_manifest(
        manifest,
        expected_case_id=output_dir.name,
    )

    results = {}

    for name in EXPORT_NAMES:
        metadata = manifest["files"][name]
        file_path = output_dir / name

        try:
            actual = secure_sha256_file(
                output_dir,
                name,
            )

            results[name] = (
                actual["size_bytes"]
                == metadata["size_bytes"]
                and actual["sha256"]
                == metadata["sha256"].lower()
            )
        except (OSError, ReportIntegrityError):
            results[name] = False

    return results
