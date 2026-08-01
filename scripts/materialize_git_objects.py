#!/usr/bin/env python3
"""Materialize an exact reachable-Git-object list for secret scanning."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


class MaterializationError(RuntimeError):
    pass


OBJECT_ID = re.compile(rb"(?:[0-9a-f]{40}|[0-9a-f]{64})")
OBJECT_TYPES = {b"blob", b"commit", b"tag", b"tree"}


def load_object_ids(path: Path) -> list[bytes]:
    if not path.is_file() or path.is_symlink():
        raise MaterializationError("reachable-object index is absent or unsafe")
    object_ids: set[bytes] = set()
    with path.open("rb") as handle:
        for line_number, line in enumerate(handle, 1):
            token = line.rstrip(b"\n").split(b" ", 1)[0]
            if token.startswith(b"?"):
                raise MaterializationError(
                    f"reachable-object index contains a missing object at line {line_number}"
                )
            if not OBJECT_ID.fullmatch(token):
                raise MaterializationError(
                    f"reachable-object index has an invalid ID at line {line_number}"
                )
            object_ids.add(token)
    if not object_ids:
        raise MaterializationError("reachable-object index is empty")
    return sorted(object_ids)


def validate_output_root(path: Path) -> None:
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise MaterializationError("output root must be a real directory")
    if any(path.iterdir()):
        raise MaterializationError("output root must be empty")


def write_object(path: Path, stream: object, size: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            remaining = size
            while remaining:
                chunk = stream.read(min(remaining, 1024 * 1024))  # type: ignore[attr-defined]
                if not chunk:
                    raise MaterializationError("git cat-file truncated an object")
                handle.write(chunk)
                remaining -= len(chunk)
            handle.flush()
    finally:
        os.close(descriptor)


def materialize(repo: Path, object_ids: list[bytes], output: Path) -> dict[str, object]:
    process = subprocess.Popen(
        ["git", "-C", str(repo), "cat-file", "--batch"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.stdin is None or process.stdout is None or process.stderr is None:
        raise MaterializationError("could not open git cat-file pipes")

    type_counts = {kind.decode("ascii"): 0 for kind in sorted(OBJECT_TYPES)}
    total_bytes = 0
    try:
        for index, requested_id in enumerate(object_ids, 1):
            process.stdin.write(requested_id + b"\n")
            process.stdin.flush()
            header = process.stdout.readline().rstrip(b"\n")
            fields = header.split(b" ")
            if (
                len(fields) != 3
                or fields[0] != requested_id
                or fields[1] not in OBJECT_TYPES
                or not fields[2].isdigit()
            ):
                raise MaterializationError(
                    f"git cat-file returned an invalid header for object {index}"
                )
            object_type = fields[1]
            size = int(fields[2])
            destination = output / (
                f"{index:08d}-{requested_id.decode('ascii')}"
                f".{object_type.decode('ascii')}"
            )
            write_object(destination, process.stdout, size)
            if process.stdout.read(1) != b"\n":
                raise MaterializationError(
                    f"git cat-file returned an invalid trailer for object {index}"
                )
            type_counts[object_type.decode("ascii")] += 1
            total_bytes += size
        process.stdin.close()
        stderr = process.stderr.read()
        exit_status = process.wait()
        if exit_status != 0:
            raise MaterializationError(
                "git cat-file failed: " + stderr.decode("utf-8", "replace").strip()
            )
        if stderr:
            raise MaterializationError(
                "git cat-file emitted unexpected diagnostics: "
                + stderr.decode("utf-8", "replace").strip()
            )
    except BaseException:
        process.kill()
        process.wait()
        raise

    observed_count = sum(type_counts.values())
    if observed_count != len(object_ids):
        raise MaterializationError("materialized object count disagrees with index")
    return {
        "schemaVersion": 1,
        "status": "OBJECTS_MATERIALIZED",
        "objectCount": observed_count,
        "contentBytes": total_bytes,
        "types": type_counts,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--objects", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    try:
        repo = args.repo.resolve(strict=True)
        output = Path(os.path.abspath(args.output))
        validate_output_root(output)
        result = materialize(
            repo,
            load_object_ids(Path(os.path.abspath(args.objects))),
            output,
        )
    except (MaterializationError, OSError) as error:
        print(f"object materialization error: {error}", file=sys.stderr)
        return 1

    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
