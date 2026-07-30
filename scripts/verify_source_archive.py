#!/usr/bin/env python3
"""Fail-closed verification of a local source-review archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile

from canonical_gzip import canonical_gzip_bytes

MAX_ARCHIVE_BYTES = 50 * 1024 * 1024


class VerificationError(RuntimeError):
    pass


def git(repo: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise VerificationError(
            f"git {' '.join(args)} failed: {result.stderr.decode('utf-8', 'replace').strip()}"
        )
    return result.stdout


def tree_entries(repo: Path, commit: str) -> dict[str, tuple[str, str]]:
    raw = git(repo, "ls-tree", "-rz", commit)
    entries: dict[str, tuple[str, str]] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, path_bytes = record.split(b"\t", 1)
        mode, kind, object_id = metadata.decode("ascii").split(" ")
        path = path_bytes.decode("utf-8", "surrogateescape")
        if kind != "blob":
            raise VerificationError(f"unsupported non-blob tree entry: {path} ({kind})")
        if mode not in {"100644", "100755"}:
            raise VerificationError(f"symlink or unsupported tree mode: {path} ({mode})")
        entries[path] = (mode, object_id)
    if not entries:
        raise VerificationError("candidate tree scan set is empty")
    return entries


def blob_object_id(data: bytes, algorithm: str) -> str:
    try:
        digest = hashlib.new(algorithm)
    except ValueError as exc:
        raise VerificationError(f"unsupported Git object format: {algorithm}") from exc
    digest.update(f"blob {len(data)}\0".encode("ascii"))
    digest.update(data)
    return digest.hexdigest()


def canonical_product_version(repo: Path, commit: str) -> str:
    manifest = git(repo, "show", f"{commit}:crates/omnis-key-cli/Cargo.toml").decode(
        "utf-8"
    )
    package_match = re.search(r"(?ms)^\[package\]\s*(.*?)(?=^\[|\Z)", manifest)
    if package_match is None:
        raise VerificationError("canonical CLI manifest has no [package] section")
    versions = re.findall(
        r'(?m)^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$',
        package_match.group(1),
    )
    if len(versions) != 1:
        raise VerificationError("canonical CLI manifest has ambiguous product version")
    if versions[0] != "0.1.0":
        raise VerificationError(f"unexpected V1 product version: {versions[0]}")
    return versions[0]


def verify_archive(repo: Path, archive: Path, ref: str) -> dict[str, object]:
    if not archive.is_file() or archive.is_symlink():
        raise VerificationError("archive must be a regular, non-symlink file")
    archive_size = archive.stat().st_size
    if archive_size <= 0:
        raise VerificationError("archive is empty")
    if archive_size >= MAX_ARCHIVE_BYTES:
        raise VerificationError(
            f"archive is {archive_size} bytes; bound is strictly below {MAX_ARCHIVE_BYTES}"
        )

    commit = git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}").decode().strip()
    tree = git(repo, "rev-parse", f"{commit}^{{tree}}").decode().strip()
    object_format = git(repo, "rev-parse", "--show-object-format").decode().strip()
    product_version = canonical_product_version(repo, commit)
    expected_prefix = f"omnis-key-harness-v{product_version}-{commit[:12]}"
    canonical_tar = git(
        repo,
        "archive",
        "--format=tar",
        f"--prefix={expected_prefix}/",
        commit,
    )
    canonical_archive = canonical_gzip_bytes(canonical_tar)
    archive_bytes = archive.read_bytes()
    if archive_bytes != canonical_archive:
        mismatch = next(
            (
                index
                for index, (actual, expected_byte) in enumerate(
                    zip(archive_bytes, canonical_archive)
                )
                if actual != expected_byte
            ),
            min(len(archive_bytes), len(canonical_archive)),
        )
        raise VerificationError(
            "archive compressed byte stream is noncanonical: "
            f"firstMismatchOffset={mismatch} "
            f"actualBytes={len(archive_bytes)} "
            f"expectedBytes={len(canonical_archive)}"
        )
    expected = tree_entries(repo, commit)
    observed: dict[str, tuple[str, str]] = {}
    prefix: str | None = None

    try:
        handle = tarfile.open(archive, mode="r:*")
    except (tarfile.TarError, OSError) as exc:
        raise VerificationError(f"archive could not be opened: {exc}") from exc

    with handle:
        members = handle.getmembers()
        if not members:
            raise VerificationError("archive member scan set is empty")
        for member in members:
            name = member.name
            if "\\" in name or name.startswith("/"):
                raise VerificationError(f"unsafe archive member path: {name!r}")
            pure = PurePosixPath(name)
            if any(part in {"", ".", ".."} for part in pure.parts):
                raise VerificationError(f"unsafe archive member path: {name!r}")
            current_prefix = pure.parts[0]
            if prefix is None:
                prefix = current_prefix
            elif current_prefix != prefix:
                raise VerificationError("archive has more than one top-level prefix")
            if member.isdir():
                continue
            if not member.isfile():
                raise VerificationError(
                    f"archive contains symlink, hardlink, device, or unsupported member: {name}"
                )
            if len(pure.parts) < 2:
                raise VerificationError(f"archive file is outside its top-level prefix: {name}")
            relative = PurePosixPath(*pure.parts[1:]).as_posix()
            if relative in observed:
                raise VerificationError(f"duplicate archive member: {relative}")
            extracted = handle.extractfile(member)
            if extracted is None:
                raise VerificationError(f"archive member is unreadable: {relative}")
            data = extracted.read()
            if len(data) != member.size:
                raise VerificationError(f"archive member is truncated: {relative}")
            mode = "100755" if member.mode & 0o111 else "100644"
            observed[relative] = (mode, blob_object_id(data, object_format))

    missing = sorted(set(expected) - set(observed))
    extra = sorted(set(observed) - set(expected))
    mismatched = sorted(
        path for path in set(expected) & set(observed) if expected[path] != observed[path]
    )
    if missing or extra or mismatched:
        details = {
            "missing": missing[:20],
            "extra": extra[:20],
            "mismatched": mismatched[:20],
        }
        raise VerificationError(f"archive/tree mismatch: {json.dumps(details, sort_keys=True)}")
    if prefix != expected_prefix:
        raise VerificationError(
            f"archive prefix mismatch: {prefix!r} != {expected_prefix!r}"
        )

    archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()
    return {
        "schemaVersion": 1,
        "status": "ARCHIVE_VALID",
        "kind": "local-review-source-archive",
        "commit": commit,
        "tree": tree,
        "prefix": f"{prefix}/",
        "productVersion": product_version,
        "fileCount": len(observed),
        "compressionFormat": "gzip-stored-v1",
        "compressedBytes": archive_size,
        "maxCompressedBytesExclusive": MAX_ARCHIVE_BYTES,
        "sha256": archive_sha256,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--ref", default="HEAD")
    parser.add_argument("--repo", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    repo = (args.repo or Path(__file__).resolve().parent.parent).resolve()
    try:
        result = verify_archive(
            repo, Path(os.path.abspath(args.archive)), args.ref
        )
    except VerificationError as exc:
        print(f"archive verification error: {exc}", file=os.sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        print(
            "source archive verified: "
            f"commit={result['commit']} tree={result['tree']} "
            f"files={result['fileCount']} bytes={result['compressedBytes']} "
            f"sha256={result['sha256']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
