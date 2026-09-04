"""Held, no-follow file references for reusable private service keys."""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from northgate_rmm.errors import ValidationError

MAX_PRIVATE_KEY_BYTES = 65_536


@contextmanager
def regular_file_reference(
    path: Path,
    *,
    label: str,
    maximum_bytes: int,
    private: bool,
) -> Iterator[Path]:
    """Hold one no-follow regular-file inode while a library loads it."""

    if path.is_symlink():
        raise ValidationError(f"{label} could not be opened safely")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum_bytes:
            raise ValidationError(f"{label} is not a bounded regular file")
        if private and os.name == "posix":
            get_effective_user = getattr(os, "geteuid", None)
            effective_user = get_effective_user() if get_effective_user else None
            if (
                type(effective_user) is not int
                or metadata.st_uid not in {0, effective_user}
                or metadata.st_mode & 0o077
            ):
                raise ValidationError(f"{label} permissions are too broad")
        reference = Path(f"/proc/self/fd/{descriptor}") if os.name == "posix" else path
        yield reference
    except ValidationError:
        raise
    except OSError as error:
        raise ValidationError(f"{label} could not be opened safely") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


@contextmanager
def private_key_reference(path: Path, *, label: str) -> Iterator[Path]:
    """Hold a permission-restricted private-key inode for OpenSSL."""

    with regular_file_reference(
        path,
        label=label,
        maximum_bytes=MAX_PRIVATE_KEY_BYTES,
        private=True,
    ) as reference:
        yield reference
