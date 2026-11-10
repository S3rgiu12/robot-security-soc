"""Day 27 - Secure manifest reader for SOC bundles."""

import json
import os
import stat
from pathlib import Path

from day27.report_integrity import ReportIntegrityError
from day27.manifest_security import validate_manifest

MAX_MANIFEST_BYTES = 1024 * 1024


def read_secure_manifest(bundle_dir):
    """Read manifest using directory-relative no-follow access."""
    bundle = Path(bundle_dir)

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

    try:
        directory_fd = os.open(bundle, flags)
    except OSError as exc:
        raise ReportIntegrityError(
            "Cannot safely open bundle directory"
        ) from exc

    try:
        file_fd = os.open(
            "manifest.json",
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory_fd,
        )

        try:
            info = os.fstat(file_fd)

            if not stat.S_ISREG(info.st_mode):
                raise ReportIntegrityError(
                    "Manifest is not a regular file"
                )

            if info.st_size > MAX_MANIFEST_BYTES:
                raise ReportIntegrityError(
                    "Manifest exceeds size limit"
                )

            with os.fdopen(
                file_fd, "rb", closefd=False
            ) as stream:
                content = stream.read(
                    MAX_MANIFEST_BYTES + 1
                )

            if len(content) > MAX_MANIFEST_BYTES:
                raise ReportIntegrityError(
                    "Manifest exceeds size limit"
                )

            manifest = json.loads(
                content.decode("utf-8")
            )

            validate_manifest(
                manifest,
                expected_case_id=bundle.name,
            )

            return manifest

        finally:
            os.close(file_fd)

    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        raise ReportIntegrityError(
            "Cannot safely read manifest"
        ) from exc

    finally:
        os.close(directory_fd)
