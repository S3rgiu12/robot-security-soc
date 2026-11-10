"""Day 27 - Secure file hashing for SOC bundles."""

import hashlib
import os
import stat
from pathlib import Path

from day27.report_integrity import ReportIntegrityError
from day27.safe_bundle_paths import validate_bundle_file


def secure_sha256_file(bundle_dir, filename):
    """Hash an export using a no-follow file descriptor."""
    path = validate_bundle_file(bundle_dir, filename)

    flags = os.O_RDONLY | os.O_NOFOLLOW

    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ReportIntegrityError(
            "Cannot safely open export file"
        ) from exc

    try:
        info = os.fstat(fd)

        if not stat.S_ISREG(info.st_mode):
            raise ReportIntegrityError(
                "Export is not a regular file"
            )

        digest = hashlib.sha256()
        size = 0

        with os.fdopen(fd, "rb", closefd=False) as stream:
            while True:
                chunk = stream.read(65536)

                if not chunk:
                    break

                digest.update(chunk)
                size += len(chunk)

        return {
            "sha256": digest.hexdigest(),
            "size_bytes": size,
        }
    finally:
        os.close(fd)
