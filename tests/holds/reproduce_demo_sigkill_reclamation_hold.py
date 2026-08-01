#!/usr/bin/env python3
"""Reproduce the frozen-spec SIGKILL reclamation capability HOLD."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from typing import Optional


HOLD_ID = "HOLD-DEMO-SIGKILL-RECLAMATION-CAPABILITY"
ROOT_PATTERN = re.compile(r"^omnis-key-demo-[0-9]+-[A-Za-z0-9]{24}$")
TEMP_ROOT = Path("/tmp")
SOURCE = Path(__file__).with_name("demo_sigkill_after_mkdir.c")
CleanupIdentity = tuple[str, int, int, int, int, Optional[str]]


class ReproductionError(RuntimeError):
    pass


def exact_roots() -> set[Path]:
    return {
        entry
        for entry in TEMP_ROOT.iterdir()
        if ROOT_PATTERN.fullmatch(entry.name) is not None
    }


def private_directory(path: Path) -> None:
    path.mkdir(mode=0o700)
    path.chmod(0o700)


def identity(path: Path) -> tuple[int, int, int, int]:
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ReproductionError(f"unsafe fixture identity: {path.name}")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
    )


def cleanup_identity(path: Path) -> CleanupIdentity:
    if ROOT_PATTERN.fullmatch(path.name) is None:
        raise ReproductionError(f"refusing non-fixture identity: {path.name}")
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        kind = "symlink"
        target: Optional[str] = os.readlink(path)
    elif stat.S_ISDIR(metadata.st_mode):
        kind = "directory"
        target = None
    else:
        raise ReproductionError(f"refusing unsafe fixture type: {path.name}")
    if metadata.st_uid != os.geteuid():
        raise ReproductionError(f"refusing wrong-owner fixture: {path.name}")
    return (
        kind,
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
        target,
    )


def remove_owned_fixture(path: Path, expected: CleanupIdentity) -> None:
    if cleanup_identity(path) != expected:
        raise ReproductionError(f"refusing unsafe fixture cleanup: {path.name}")
    if expected[0] == "symlink":
        path.unlink()
    else:
        shutil.rmtree(path)


def compile_interposer(cc: str, output: Path) -> None:
    if sys.platform == "darwin":
        command = [
            cc,
            "-dynamiclib",
            "-O2",
            "-Wall",
            "-Wextra",
            str(SOURCE),
            "-o",
            str(output),
        ]
    elif sys.platform.startswith("linux"):
        command = [
            cc,
            "-shared",
            "-fPIC",
            "-O2",
            "-Wall",
            "-Wextra",
            str(SOURCE),
            "-ldl",
            "-o",
            str(output),
        ]
    else:
        raise ReproductionError("fixture supports only macOS and Linux")
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise ReproductionError(f"interposer compilation failed: {result.stderr.strip()}")


def injected_environment(library: Path) -> dict[str, str]:
    environment = dict(os.environ)
    environment.pop("LD_PRELOAD", None)
    environment.pop("DYLD_INSERT_LIBRARIES", None)
    environment.pop("DYLD_FORCE_FLAT_NAMESPACE", None)
    if sys.platform == "darwin":
        environment["DYLD_INSERT_LIBRARIES"] = str(library)
        environment["DYLD_FORCE_FLAT_NAMESPACE"] = "1"
    else:
        environment["LD_PRELOAD"] = str(library)
    return environment


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--omnis-key", required=True, type=Path)
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()

    binary = args.omnis_key.resolve()
    if not binary.is_file() or binary.is_symlink():
        raise ReproductionError("omnis-key must be a regular binary")
    cc = shutil.which(args.cc)
    if cc is None:
        raise ReproductionError("C compiler is unavailable")

    suffixes = [secrets.token_hex(12) for _ in range(3)]
    empty_preplant = TEMP_ROOT / f"omnis-key-demo-2147483646-{suffixes[0]}"
    sentinel_preplant = TEMP_ROOT / f"omnis-key-demo-2147483645-{suffixes[1]}"
    symlink_preplant = TEMP_ROOT / f"omnis-key-demo-2147483644-{suffixes[2]}"
    created: list[Path] = []
    cleanup_identities: dict[Path, CleanupIdentity] = {}
    killed_root: Path | None = None
    reproduced = False

    with tempfile.TemporaryDirectory(prefix="omnis-hold-fixture-") as temporary:
        work = Path(temporary)
        victim = work / "symlink-victim"
        private_directory(victim)
        sentinel = sentinel_preplant / "sentinel"
        try:
            private_directory(empty_preplant)
            created.append(empty_preplant)
            cleanup_identities[empty_preplant] = cleanup_identity(empty_preplant)
            private_directory(sentinel_preplant)
            created.append(sentinel_preplant)
            cleanup_identities[sentinel_preplant] = cleanup_identity(
                sentinel_preplant
            )
            sentinel.write_bytes(b"plausible preplant must survive\n")
            sentinel.chmod(0o600)
            cleanup_identities[sentinel_preplant] = cleanup_identity(
                sentinel_preplant
            )
            symlink_preplant.symlink_to(victim, target_is_directory=True)
            created.append(symlink_preplant)
            cleanup_identities[symlink_preplant] = cleanup_identity(
                symlink_preplant
            )

            empty_before = identity(empty_preplant)
            sentinel_before = identity(sentinel_preplant)
            sentinel_bytes = sentinel.read_bytes()
            symlink_target = os.readlink(symlink_preplant)

            library = work / ("hold.dylib" if sys.platform == "darwin" else "hold.so")
            compile_interposer(cc, library)
            process = subprocess.Popen(
                [str(binary), "demo", "integrity", "--json"],
                cwd=work,
                env=injected_environment(library),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            process.communicate(timeout=20)
            if process.returncode != -signal.SIGKILL:
                raise ReproductionError(
                    f"injected run did not exit by SIGKILL: {process.returncode}"
                )
            candidates = [
                path
                for path in exact_roots()
                if path.name.startswith(f"omnis-key-demo-{process.pid}-")
            ]
            for candidate in candidates:
                created.append(candidate)
                cleanup_identities[candidate] = cleanup_identity(candidate)
            if len(candidates) != 1:
                raise ReproductionError(
                    f"expected one killed-run remnant, observed {len(candidates)}"
                )
            killed_root = candidates[0]
            killed_before = identity(killed_root)
            if any(killed_root.iterdir()):
                raise ReproductionError("injected SIGKILL did not land immediately after mkdir")

            next_run = subprocess.run(
                [str(binary), "demo", "integrity", "--json"],
                cwd=work,
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=20,
            )
            if next_run.returncode != 0:
                raise ReproductionError(
                    f"next demo run failed unexpectedly: {next_run.returncode}"
                )
            if identity(killed_root) != killed_before or any(killed_root.iterdir()):
                raise ReproductionError("next run changed the uncatchable-crash remnant")
            if identity(empty_preplant) != empty_before:
                raise ReproductionError("next run changed the empty plausible preplant")
            if (
                identity(sentinel_preplant) != sentinel_before
                or sentinel.read_bytes() != sentinel_bytes
            ):
                raise ReproductionError("next run changed the sentinel preplant")
            if (
                not symlink_preplant.is_symlink()
                or os.readlink(symlink_preplant) != symlink_target
            ):
                raise ReproductionError("next run changed the symlink preplant")

            reproduced = True
        finally:
            cleanup_errors: list[str] = []
            for path in reversed(created):
                try:
                    if path.exists() or path.is_symlink():
                        remove_owned_fixture(path, cleanup_identities[path])
                    else:
                        cleanup_errors.append(f"{path.name}: absent before cleanup")
                except (OSError, ReproductionError, KeyError) as error:
                    cleanup_errors.append(f"{path.name}: {error}")
            if cleanup_errors:
                raise ReproductionError(
                    "fixture cleanup failed: " + "; ".join(cleanup_errors)
                )
            if any(path.exists() or path.is_symlink() for path in created):
                raise ReproductionError("fixture cleanup verification failed")

    if not reproduced:
        raise ReproductionError("HOLD reproduction did not complete")
    print(
        f"HOLD_REPRODUCED: {HOLD_ID} "
        "killedRootPrivate=true nextRunReclaimed=false "
        "plausiblePreplantsPreserved=true"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ReproductionError, subprocess.TimeoutExpired) as error:
        print(f"HOLD_REPRODUCTION_ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
