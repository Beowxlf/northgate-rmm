#!/usr/bin/env python3
"""Verify one SFTP-staged file and publish it without overwriting another file."""

import hashlib
import json
import os
import re
import sys

ROOT = "/var/lib/NorthGateRMM-Ops"
LIMIT = 20 * 1024 * 1024


def receive():
    header = sys.stdin.buffer.readline(1025)
    if len(header) > 1024 or not header.endswith(b"\n"):
        raise ValueError("Invalid header")
    value = json.loads(header)
    name, size, expected = value["name"], value["size"], value["sha256"]
    if (
        not isinstance(name, str)
        or not re.fullmatch(r"[a-f0-9]{12}-[A-Za-z0-9][A-Za-z0-9._-]{0,99}", name)
        or name.endswith(".")
    ):
        raise ValueError("Invalid name")
    if (
        type(size) is not int
        or not 0 <= size <= LIMIT
        or not re.fullmatch(r"[a-f0-9]{64}", expected)
    ):
        raise ValueError("Invalid metadata")
    directory = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if os.fstat(directory).st_uid != 0:
            raise ValueError("Invalid directory owner")
        staged = ".upload-" + name
        fd = os.open(staged, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        with os.fdopen(fd, "rb") as source:
            if os.fstat(source.fileno()).st_size != size:
                raise ValueError("Size mismatch")
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        if digest != expected:
            raise ValueError("Checksum mismatch")
        os.link(
            staged,
            name,
            src_dir_fd=directory,
            dst_dir_fd=directory,
            follow_symlinks=False,
        )
        os.unlink(staged, dir_fd=directory)
        print(json.dumps({"name": name, "size": size, "sha256": digest}))
    finally:
        os.close(directory)


if __name__ == "__main__":
    try:
        receive()
    except Exception:
        print("Staged file was not accepted", file=sys.stderr)
        sys.exit(1)
