"""Day 27 - Safe file access relative to a bundle descriptor."""

import hashlib
import os
import stat

from day27.report_integrity import ReportIntegrityError

MAX_EXPORT_BYTES = 50 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024

ALLOWED_FILES = frozenset({
    "manifest.json",
    "incident-report.json",
    "evidence.csv",
    "audit.csv",
})


def read_bundle_file(bundle_fd, filename):
    """Read an allowlisted regular file through dir_fd."""
    if filename not in ALLOWED_FILES:
        raise ReportIntegrityError(
            "File is not allowed"
        )

    limit = (
        MAX_MANIFEST_BYTES
        if filename == "manifest.json"
        else MAX_EXPORT_BYTES
    )

    flags = (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | os.O_CLOEXEC
        | os.O_NONBLOCK
    )

    try:
        fd = os.open(
            filename,
            flags,
            dir_fd=bundle_fd,
        )
    except OSError as exc:
        raise ReportIntegrityError(
            "Cannot safely open bundle file"
        ) from exc

    try:
        info = os.fstat(fd)

        if not stat.S_ISREG(info.st_mode):
            raise ReportIntegrityError(
                "Bundle entry is not a regular file"
            )

        if info.st_size > limit:
            raise ReportIntegrityError(
                "Bundle file exceeds size limit"
            )

        data = bytearray()

        while True:
            chunk = os.read(
                fd,
                min(65536, limit + 1 - len(data)),
            )

            if not chunk:
                break

            data.extend(chunk)

            if len(data) > limit:
                raise ReportIntegrityError(
                    "Bundle file exceeds size limit"
                )

        return bytes(data)

    except OSError as exc:
        raise ReportIntegrityError(
            "Cannot safely read bundle file"
        ) from exc

    finally:
        os.close(fd)


def hash_bundle_file(bundle_fd, filename):
    """Calculate SHA-256 from safely opened file bytes."""
    data = read_bundle_file(bundle_fd, filename)

    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
    }
