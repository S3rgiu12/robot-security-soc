"""Day 27 - Directory descriptor based bundle access."""

import os
import stat
from contextlib import contextmanager
from pathlib import Path

from day27.bundle_access import EXPORT_ROOT
from day27.manifest_security import validate_case_id
from day27.report_integrity import ReportIntegrityError


@contextmanager
def open_secure_bundle(case_id, export_root=EXPORT_ROOT):
    """Keep a verified bundle directory descriptor open."""
    validate_case_id(case_id)

    root_fd = None
    bundle_fd = None

    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | os.O_CLOEXEC
    )

    try:
        root_fd = os.open(Path(export_root), flags)

        bundle_fd = os.open(
            case_id,
            flags,
            dir_fd=root_fd,
        )

        info = os.fstat(bundle_fd)

        if not stat.S_ISDIR(info.st_mode):
            raise ReportIntegrityError(
                "Incident bundle is not a directory"
            )

        yield bundle_fd

    except OSError as exc:
        raise ReportIntegrityError(
            "Cannot safely access incident bundle"
        ) from exc

    finally:
        if bundle_fd is not None:
            os.close(bundle_fd)

        if root_fd is not None:
            os.close(root_fd)
