#!/usr/bin/env python3
"""Execute one builder-evidence command without a shell or ambient PATH lookup."""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import shlex
import stat
import subprocess
import sys


TOOL_ENV = {
    "bash": "OMNIS_BUILDER_TOOL_BASH",
    "cargo": "OMNIS_BUILDER_TOOL_CARGO",
    "cc": "OMNIS_BUILDER_TOOL_CC",
    "git": "OMNIS_BUILDER_TOOL_GIT",
    "python3": "OMNIS_BUILDER_TOOL_PYTHON3",
    "rustc": "OMNIS_BUILDER_TOOL_RUSTC",
    "uname": "OMNIS_BUILDER_TOOL_UNAME",
}

TOOLCHAIN_COMMAND = (
    "uname -a && rustc -Vv && cargo -V && git --version && "
    "python3 --version && cc --version"
)

TOOLCHAIN_INVOCATIONS = (
    ("uname", "-a"),
    ("rustc", "-Vv"),
    ("cargo", "-V"),
    ("git", "--version"),
    ("python3", "--version"),
    ("cc", "--version"),
)


class CommandError(RuntimeError):
    """Raised when a requested evidence command is not direct and unambiguous."""


def trusted_tool(name: str) -> str:
    variable = TOOL_ENV[name]
    value = os.environ.get(variable)
    if (
        not value
        or not os.path.isabs(value)
        or "\0" in value
        or "\n" in value
        or "\r" in value
    ):
        raise CommandError(f"{variable} is absent or unsafe")
    path = Path(value)
    try:
        metadata = path.stat()
    except OSError as exc:
        raise CommandError(f"trusted {name} executable is unreadable") from exc
    if not stat.S_ISREG(metadata.st_mode) or not os.access(path, os.X_OK):
        raise CommandError(f"trusted {name} executable is not executable")
    return value


def repository_program(repo: Path, token: str) -> tuple[str, ...]:
    pure = PurePosixPath(token)
    if (
        pure.is_absolute()
        or not pure.parts
        or pure.parts[0] not in {"scripts", "tests"}
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise CommandError(f"repository program path is unsafe: {token!r}")
    path = repo.joinpath(*pure.parts)
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as exc:
        raise CommandError(f"repository program is absent: {token}") from exc
    if (
        resolved != path.absolute()
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
    ):
        raise CommandError(f"repository program is not a regular tracked file: {token}")
    if path.suffix == ".py":
        return (trusted_tool("python3"), str(path))
    if path.suffix == ".sh":
        return (trusted_tool("bash"), str(path))
    if not os.access(path, os.X_OK):
        raise CommandError(f"repository program is not executable: {token}")
    return (str(path),)


def direct_argv(repo: Path, command: str) -> tuple[str, ...]:
    try:
        arguments = shlex.split(command, posix=True)
    except ValueError as exc:
        raise CommandError("command quoting is invalid") from exc
    if not arguments:
        raise CommandError("command is empty")
    if any(token in {"&&", "||", ";", "|", "&", ">", ">>", "<"} for token in arguments):
        raise CommandError("shell control operators are forbidden")

    program, *rest = arguments
    if program in TOOL_ENV:
        return (trusted_tool(program), *rest)
    if program.startswith("scripts/") or program.startswith("tests/"):
        return (*repository_program(repo, program), *rest)
    if program == "printf":
        return ("/usr/bin/printf", *rest)
    if program in {":", "true"}:
        return ("/usr/bin/true", *rest)
    raise CommandError(f"command program is outside the evidence allowlist: {program!r}")


def run_one(repo: Path, argv: tuple[str, ...]) -> int:
    try:
        result = subprocess.run(
            argv,
            cwd=repo,
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except OSError as exc:
        raise CommandError(f"could not execute trusted command: {argv[0]}") from exc
    return result.returncode


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "usage: run_trusted_builder_command.py REPO COMMAND",
            file=sys.stderr,
        )
        return 2
    repo = Path(sys.argv[1])
    command = sys.argv[2]
    if (
        not repo.is_absolute()
        or repo.resolve() != repo
        or not repo.is_dir()
        or repo.is_symlink()
    ):
        print("trusted builder command error: repository root is unsafe", file=sys.stderr)
        return 2
    try:
        if command == TOOLCHAIN_COMMAND:
            for invocation in TOOLCHAIN_INVOCATIONS:
                status = run_one(
                    repo,
                    (trusted_tool(invocation[0]), *invocation[1:]),
                )
                if status != 0:
                    return status
            return 0
        return run_one(repo, direct_argv(repo, command))
    except CommandError as exc:
        print(f"trusted builder command error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
