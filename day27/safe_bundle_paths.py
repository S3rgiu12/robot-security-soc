"""Day 27 - Safe SOC export paths."""

from pathlib import Path
from day27.report_integrity import ReportIntegrityError


def validate_bundle_directory(bundle_dir):
    path = Path(bundle_dir)

    if path.is_symlink():
        raise ReportIntegrityError(
            "Symlinked bundle directory rejected"
        )

    if not path.is_dir():
        raise ReportIntegrityError(
            "Bundle directory not found"
        )

    return path


def validate_bundle_file(bundle_dir, filename):
    bundle_dir = validate_bundle_directory(bundle_dir)

    if (
        not isinstance(filename, str)
        or not filename
        or Path(filename).name != filename
        or filename in (".", "..")
    ):
        raise ReportIntegrityError(
            "Invalid export filename"
        )

    target = bundle_dir / filename

    if target.is_symlink():
        raise ReportIntegrityError(
            "Symlinked export file rejected"
        )

    if not target.is_file():
        raise ReportIntegrityError(
            "Export file missing"
        )

    if target.resolve().parent != bundle_dir.resolve():
        raise ReportIntegrityError(
            "Export path escapes bundle"
        )

    return target
