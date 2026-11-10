"""Day 27 - Manifest security validation."""

import re

from day27.report_integrity import ReportIntegrityError


CASE_ID_PATTERN = re.compile(
    r"^INC-[A-Za-z0-9_-]{1,64}$"
)

EXPECTED_FILES = frozenset({
    "incident-report.json",
    "evidence.csv",
    "audit.csv",
})

SHA256_PATTERN = re.compile(
    r"^[0-9a-fA-F]{64}$"
)


def validate_case_id(case_id):
    if (
        not isinstance(case_id, str)
        or not CASE_ID_PATTERN.fullmatch(case_id)
    ):
        raise ReportIntegrityError(
            "Invalid incident case ID"
        )

    return case_id


def validate_manifest(manifest, expected_case_id=None):
    if not isinstance(manifest, dict):
        raise ReportIntegrityError(
            "Manifest must be an object"
        )

    if manifest.get("manifest_type") != "SOC_REPORT_INTEGRITY":
        raise ReportIntegrityError(
            "Invalid manifest type"
        )

    if manifest.get("manifest_version") != "1.0":
        raise ReportIntegrityError(
            "Unsupported manifest version"
        )

    if manifest.get("hash_algorithm") != "SHA-256":
        raise ReportIntegrityError(
            "Unsupported hash algorithm"
        )

    case_id = validate_case_id(
        manifest.get("case_id")
    )

    if (
        expected_case_id is not None
        and case_id != validate_case_id(expected_case_id)
    ):
        raise ReportIntegrityError(
            "Manifest incident ID mismatch"
        )

    files = manifest.get("files")

    if not isinstance(files, dict):
        raise ReportIntegrityError(
            "Invalid manifest files"
        )

    if set(files) != EXPECTED_FILES:
        raise ReportIntegrityError(
            "Unexpected manifest file list"
        )

    for name, metadata in files.items():
        if not isinstance(metadata, dict):
            raise ReportIntegrityError(
                f"Invalid metadata: {name}"
            )

        digest = metadata.get("sha256")
        size = metadata.get("size_bytes")

        if (
            not isinstance(digest, str)
            or not SHA256_PATTERN.fullmatch(digest)
        ):
            raise ReportIntegrityError(
                f"Invalid SHA-256: {name}"
            )

        if (
            type(size) is not int
            or size < 0
        ):
            raise ReportIntegrityError(
                f"Invalid file size: {name}"
            )

    return True
