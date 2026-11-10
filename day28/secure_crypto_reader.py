"""Day 28 - Secure access to Ed25519 verification material."""

import os
import stat
from pathlib import Path

from day27.manifest_security import validate_case_id
from day27.report_integrity import ReportIntegrityError

FILE_FLAGS = (
    os.O_RDONLY
    | os.O_NOFOLLOW
    | os.O_CLOEXEC
    | os.O_NONBLOCK
)

DIR_FLAGS = (
    os.O_RDONLY
    | os.O_DIRECTORY
    | os.O_NOFOLLOW
    | os.O_CLOEXEC
)

MAX_PUBLIC_KEY_BYTES = 4096
ED25519_SIGNATURE_BYTES = 64


def read_regular_file(fd, limit):
    """Read a bounded regular file from an existing descriptor."""

    info = os.fstat(fd)

    if not stat.S_ISREG(info.st_mode):
        raise ReportIntegrityError("Not a regular file")

    if info.st_size > limit:
        raise ReportIntegrityError("Cryptographic file too large")

    data = bytearray()

    while len(data) <= limit:
        chunk = os.read(fd, min(4096, limit + 1 - len(data)))

        if not chunk:
            return bytes(data)

        data.extend(chunk)

    raise ReportIntegrityError("Cryptographic file too large")


def read_trusted_public_key(path):
    """Read a public key through verified directory descriptors."""

    path = Path(path).absolute()
    parts = path.parts

    directory_fd = None
    file_fd = None

    try:
        directory_fd = os.open("/", DIR_FLAGS)

        for component in parts[1:-1]:
            next_fd = os.open(
                component,
                DIR_FLAGS,
                dir_fd=directory_fd,
            )

            os.close(directory_fd)
            directory_fd = next_fd

        file_fd = os.open(
            parts[-1],
            FILE_FLAGS,
            dir_fd=directory_fd,
        )

        return read_regular_file(
            file_fd,
            MAX_PUBLIC_KEY_BYTES,
        )

    except OSError as exc:
        raise ReportIntegrityError(
            "Cannot safely read trusted public key"
        ) from exc

    finally:
        if file_fd is not None:
            os.close(file_fd)

        if directory_fd is not None:
            os.close(directory_fd)


def read_detached_signature(case_id, signature_root):
    """Read a signature relative to securely opened directories."""

    validate_case_id(case_id)

    root_fd = None
    case_fd = None
    signature_fd = None

    try:
        root_fd = os.open(Path(signature_root), DIR_FLAGS)

        case_fd = os.open(
            case_id,
            DIR_FLAGS,
            dir_fd=root_fd,
        )

        signature_fd = os.open(
            "manifest.sig",
            FILE_FLAGS,
            dir_fd=case_fd,
        )

        signature = read_regular_file(
            signature_fd,
            ED25519_SIGNATURE_BYTES,
        )

        if len(signature) != ED25519_SIGNATURE_BYTES:
            raise ReportIntegrityError(
                "Invalid Ed25519 signature length"
            )

        return signature

    except OSError as exc:
        raise ReportIntegrityError(
            "Cannot safely read detached signature"
        ) from exc

    finally:
        if signature_fd is not None:
            os.close(signature_fd)

        if case_fd is not None:
            os.close(case_fd)

        if root_fd is not None:
            os.close(root_fd)
