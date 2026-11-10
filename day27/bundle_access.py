"""Day 27 - Controlled access to SOC export bundles."""

import os
import stat
from pathlib import Path

from day27.manifest_security import validate_case_id
from day27.report_integrity import ReportIntegrityError


EXPORT_ROOT = (
    Path(__file__).resolve().parent / "exports"
)


def get_bundle_directory(case_id, export_root=EXPORT_ROOT):
    """Locate a bundle under a trusted export root."""
    validate_case_id(case_id)

    root = Path(export_root)

    try:
        root_fd = os.open(
            root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
    except OSError as exc:
        raise ReportIntegrityError(
            "Cannot safely open export root"
        ) from exc

    try:
        bundle_fd = os.open(
            case_id,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=root_fd,
        )

        try:
            info = os.fstat(bundle_fd)

            if not stat.S_ISDIR(info.st_mode):
                raise ReportIntegrityError(
                    "Incident bundle is not a directory"
                )

            root_real = root.resolve(strict=True)
            bundle = root_real / case_id

            return bundle

        finally:
            os.close(bundle_fd)

    except OSError as exc:
        raise ReportIntegrityError(
            "Incident bundle unavailable or unsafe"
        ) from exc

    finally:
        os.close(root_fd)
