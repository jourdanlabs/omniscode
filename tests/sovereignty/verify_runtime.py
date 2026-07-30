#!/usr/bin/env python3
"""Prove V1 zero-attempt networking and exact allowed writes on Unix."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import platform
import pty
import re
import secrets
import select
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import termios
import time
from dataclasses import dataclass
from pathlib import Path
from collections import Counter
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[2]
INTERPOSER_SOURCE = Path(__file__).with_name("network_interposer.c")
PROBE_SOURCE = Path(__file__).with_name("instrumentation_probe.c")
CREDENTIAL_NAMES_SOURCE = Path(__file__).with_name(
    "credential_environment_names.h"
)
NETWORK_EVENTS = {
    "DNS",
    "DNS_GETHOSTBYNAME",
    "DNS_GETHOSTBYNAME2",
    "DNS_GETHOSTBYADDR",
    "DNS_RES_QUERY",
    "AF_INET",
    "AF_INET6",
    "CONNECT_AF_INET",
    "CONNECT_AF_INET6",
    "BIND_AF_INET",
    "BIND_AF_INET6",
}
UNIX_EVENTS = {"AF_UNIX", "CONNECT_AF_UNIX", "BIND_AF_UNIX"}
CREDENTIAL_EVENT_PREFIX = "CREDENTIAL_ENV|"
PROCESS_START_PREFIX = "PROCESS_START|"
EXECUTION_ATTEMPT_PREFIX = "EXEC_ATTEMPT|"
EXECUTION_RESULT_PREFIX = "EXEC_RESULT|"
EVENT_SCHEMA = "EV1"
MUTATING_FILESYSTEM_OPERATIONS = {
    "chmod",
    "fchmod",
    "chown",
    "fchown",
    "lchown",
    "truncate",
    "ftruncate",
    "mkdir",
    "mkdirat",
    "unlink",
    "unlinkat",
    "rmdir",
    "remove",
    "rename-from",
    "rename-to",
    "renameat-from",
    "renameat-to",
    "link-from",
    "link-to",
    "linkat-from",
    "linkat-to",
    "symlink-to",
    "symlinkat-to",
    "utimes",
    "futimes",
    "lutimes",
    "setxattr",
    "lsetxattr",
    "fsetxattr",
    "removexattr",
    "lremovexattr",
    "fremovexattr",
    "fclonefileat-to",
}
DIRECT_ENVIRONMENT_ENUMERATION = re.compile(
    r"(?:\bstd::)?\benv::vars(?:_os)?\s*\("
)
LITERAL_ENVIRONMENT_READ = re.compile(
    r"(?:std::)?env::(?:var|var_os)\(\s*\"([A-Z][A-Z0-9_]*)\""
)
EXPLICIT_ONLY_ENVIRONMENT_ENUMERATION_PATHS = {
    "crates/jcode-base/src/mcp/client.rs",
}
NON_CREDENTIAL_AUTH_CONTROL_ENVIRONMENT = {
    "JCODE_DEFERRED_AUTH_BOOTSTRAP",
}


def load_credential_environment_names() -> set[str]:
    if not CREDENTIAL_NAMES_SOURCE.is_file():
        raise RuntimeError(
            f"missing credential environment inventory: {CREDENTIAL_NAMES_SOURCE}"
        )
    names = set(
        re.findall(
            r'X\("([A-Z][A-Z0-9_]*)"\)',
            CREDENTIAL_NAMES_SOURCE.read_text(encoding="utf-8"),
        )
    )
    if len(names) < 50:
        raise RuntimeError("credential environment inventory is unexpectedly incomplete")
    return names


CREDENTIAL_ENVIRONMENT = load_credential_environment_names()


class GateFailure(RuntimeError):
    pass


@dataclass
class Sandbox:
    root: Path
    roots: dict[str, Path]
    environment: dict[str, str]


@dataclass
class HostilePtyFixtures:
    protected_files: dict[str, Path]
    forbidden_prefixes: dict[str, Path]
    protected_snapshot_keys: set[str]
    replacement_marker: Path


@dataclass(frozen=True)
class InstrumentationEvent:
    pid: int
    payload: str
    raw: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jcode", type=Path, required=True)
    parser.add_argument("--omnis-key", type=Path, required=True)
    parser.add_argument(
        "--receipt",
        type=Path,
        default=REPO_ROOT / "target" / "sovereignty" / "runtime-receipt.json",
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="development-only: permit a dirty worktree (final evidence must omit this)",
    )
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_identity(*, allow_dirty: bool) -> dict[str, object]:
    def query(*arguments: str) -> str:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            raise GateFailure(
                f"git {' '.join(arguments)} failed while binding runtime evidence"
            )
        return completed.stdout.strip()

    commit = query("rev-parse", "HEAD")
    tree = query("rev-parse", "HEAD^{tree}")
    dirty = bool(query("status", "--porcelain=v1", "--untracked-files=all"))
    if dirty and not allow_dirty:
        raise GateFailure(
            "worktree is dirty; final runtime evidence must bind a frozen clean commit/tree"
        )
    return {
        "commit": commit,
        "tree": tree,
        "worktreeClean": not dirty,
        "developmentDirtyOverride": dirty and allow_dirty,
    }


def compile_instrumentation(work: Path) -> tuple[Path, Path, str]:
    if not INTERPOSER_SOURCE.is_file():
        raise GateFailure(f"missing interposer source: {INTERPOSER_SOURCE}")
    if not PROBE_SOURCE.is_file():
        raise GateFailure(f"missing instrumentation probe source: {PROBE_SOURCE}")
    compiler = shutil.which("cc")
    if compiler is None:
        raise GateFailure("C compiler `cc` is required for zero-attempt instrumentation")

    suffix = ".dylib" if sys.platform == "darwin" else ".so"
    output = work / f"sovereignty-interposer{suffix}"
    command = [compiler]
    if sys.platform == "darwin":
        command.extend(["-dynamiclib", "-fPIC"])
    elif sys.platform.startswith("linux"):
        command.extend(["-shared", "-fPIC"])
    else:
        raise GateFailure(f"unsupported instrumentation platform: {sys.platform}")
    command.extend(["-Wall", "-Wextra", "-Werror", str(INTERPOSER_SOURCE), "-o", str(output)])
    if sys.platform.startswith("linux"):
        command.append("-ldl")
    command.append("-lresolv")
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise GateFailure(
            "interposer compilation failed:\n"
            f"{completed.stdout}\n{completed.stderr}"
        )
    probe = work / "sovereignty-instrumentation-probe"
    probe_command = [
        compiler,
        "-Wall",
        "-Wextra",
        "-Werror",
        str(PROBE_SOURCE),
        "-o",
        str(probe),
        "-lresolv",
    ]
    completed = subprocess.run(probe_command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise GateFailure(
            "instrumentation probe compilation failed:\n"
            f"{completed.stdout}\n{completed.stderr}"
        )
    version = subprocess.run(
        [compiler, "--version"], capture_output=True, text=True, check=False
    ).stdout.splitlines()
    return output, probe, version[0] if version else "cc version unavailable"


def private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=False)
    path.chmod(0o700)


def make_sandbox(base: Path, name: str, interposer: Path) -> Sandbox:
    root = base / name
    private_directory(root)
    roots: dict[str, Path] = {}
    for label, directory in [
        ("HOME", "home"),
        ("JCODE_HOME", "jcode-home"),
        ("XDG_CONFIG_HOME", "xdg-config"),
        ("XDG_STATE_HOME", "xdg-state"),
        ("XDG_CACHE_HOME", "xdg-cache"),
        ("TMPDIR", "tmp"),
        ("CWD", "cwd"),
        ("RUNTIME", "runtime"),
        ("OPERATOR", "operator-sentinel"),
        ("HOSTILE_PATH", "hostile-path"),
    ]:
        path = root / directory
        private_directory(path)
        roots[label] = path

    sentinel = roots["OPERATOR"] / "NEVER_READ.txt"
    sentinel.write_bytes(b"synthetic fixture: operator state must remain untouched\n")
    sentinel.chmod(0o600)

    environment = {
        "PATH": str(roots["HOSTILE_PATH"]),
        "TERM": "xterm-256color",
        "LANG": os.environ.get("LANG", "C"),
        "HOME": str(roots["HOME"]),
        "JCODE_HOME": str(roots["JCODE_HOME"]),
        "XDG_CONFIG_HOME": str(roots["XDG_CONFIG_HOME"]),
        "XDG_STATE_HOME": str(roots["XDG_STATE_HOME"]),
        "XDG_CACHE_HOME": str(roots["XDG_CACHE_HOME"]),
        "TMPDIR": str(roots["TMPDIR"]),
        "JCODE_RUNTIME_DIR": str(roots["RUNTIME"]),
        "JCODE_SOCKET": str(roots["RUNTIME"] / "jcode.sock"),
        "NO_BROWSER": "1",
        "JCODE_NO_BROWSER": "1",
        "OMNIS_OPERATOR_STATE_ROOT": str(roots["OPERATOR"]),
        "OMNIS_OPERATOR_SENTINEL": str(roots["OPERATOR"]),
    }
    if sys.platform == "darwin":
        environment["DYLD_INSERT_LIBRARIES"] = str(interposer)
        environment["DYLD_FORCE_FLAT_NAMESPACE"] = "1"
    else:
        environment["LD_PRELOAD"] = str(interposer)
    return Sandbox(root=root, roots=roots, environment=environment)


def install_hostile_demo_fixtures(sandbox: Sandbox) -> None:
    poison = b"fixture-only hostile input: production demo must never read this\n"
    fixture_paths = [
        sandbox.roots["HOME"] / ".jcode" / "config.toml",
        sandbox.roots["HOME"] / ".config" / "jcode" / "config.toml",
        sandbox.roots["JCODE_HOME"] / "config" / "jcode" / "config.toml",
        sandbox.roots["XDG_CONFIG_HOME"] / "jcode" / "config.toml",
        sandbox.roots["JCODE_HOME"] / "hooks" / "fixture-only-hook",
        sandbox.roots["JCODE_HOME"] / "plugins" / "fixture-only-plugin",
    ]
    for path in fixture_paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.parent.chmod(0o700)
        path.write_bytes(poison)
        path.chmod(0o600)

    hostile_tool = sandbox.roots["HOSTILE_PATH"] / "fixture-provider"
    hostile_tool.write_bytes(b"fixture-only executable: must never run\n")
    hostile_tool.chmod(0o700)
    sandbox.environment.update(
        {
            "JCODE_HOOK_TURN_START": str(sandbox.roots["JCODE_HOME"] / "hooks" / "fixture-only-hook"),
            "JCODE_PLUGIN_PATH": str(sandbox.roots["JCODE_HOME"] / "plugins"),
            "OMNIS_HOSTILE_CONFIG_FIXTURE": str(fixture_paths[2]),
            "OPENAI_API_KEY": "fixture-only-not-a-credential",
            "ANTHROPIC_API_KEY": "fixture-only-not-a-credential",
        }
    )


def credential_canary_value(name: str) -> str:
    if any(
        marker in name
        for marker in ("ENDPOINT", "BASE_URL", "_URI", "CREDENTIALS_FULL_URI")
    ):
        return f"https://credential-canary.invalid/{name.lower()}"
    if name == "JCODE_SUBSCRIPTION_ACTIVE":
        return "1"
    return f"credential-canary-{name.lower()}"


def install_hostile_pty_fixtures(sandbox: Sandbox) -> HostilePtyFixtures:
    """Plant account, updater, and restart state that no-arg startup must ignore."""

    fixture_json = b'{"fixtureOnly":true,"token":"not-a-credential"}\n'
    protected_files: dict[str, Path] = {
        "jcode-claude-auth": sandbox.roots["JCODE_HOME"] / "auth.json",
        "jcode-openai-auth": sandbox.roots["JCODE_HOME"] / "openai-auth.json",
        "jcode-gemini-auth": sandbox.roots["JCODE_HOME"] / "gemini_oauth.json",
        "jcode-antigravity-auth": sandbox.roots["JCODE_HOME"]
        / "antigravity_oauth.json",
        "jcode-google-auth": sandbox.roots["JCODE_HOME"] / "google_oauth.json",
        "jcode-subscription-env": sandbox.roots["JCODE_HOME"]
        / "config/jcode/jcode-subscription.env",
        "jcode-config": sandbox.roots["JCODE_HOME"] / "config/jcode/config.toml",
        "jcode-mcp-config": sandbox.roots["JCODE_HOME"] / "mcp.json",
        "jcode-skill": sandbox.roots["JCODE_HOME"] / "skills/fixture/SKILL.md",
        "jcode-hook": sandbox.roots["JCODE_HOME"] / "hooks/fixture-only-hook",
        "jcode-plugin": sandbox.roots["JCODE_HOME"] / "plugins/fixture-only-plugin",
        "external-claude-auth": sandbox.roots["JCODE_HOME"]
        / "external/.claude/.credentials.json",
        "external-codex-auth": sandbox.roots["JCODE_HOME"]
        / "external/.codex/auth.json",
        "external-cursor-auth": sandbox.roots["JCODE_HOME"]
        / "external/.cursor/auth.json",
        "external-cursor-config-auth": sandbox.roots["JCODE_HOME"]
        / "external/.config/cursor/auth.json",
        "external-copilot-auth": sandbox.roots["JCODE_HOME"]
        / "external/.config/github-copilot/hosts.json",
        "external-opencode-auth": sandbox.roots["JCODE_HOME"]
        / "external/.local/share/opencode/auth.json",
        "external-pi-auth": sandbox.roots["JCODE_HOME"]
        / "external/.pi/agent/auth.json",
        "external-openclaw-auth": sandbox.roots["JCODE_HOME"]
        / "external/.openclaw/agent/auth.json",
        "external-hermes-auth": sandbox.roots["JCODE_HOME"]
        / "external/.hermes/auth.json",
        "home-claude-auth": sandbox.roots["HOME"] / ".claude/.credentials.json",
        "home-codex-auth": sandbox.roots["HOME"] / ".codex/auth.json",
        "home-cursor-auth": sandbox.roots["HOME"] / ".cursor/auth.json",
        "home-copilot-auth": sandbox.roots["HOME"]
        / ".config/github-copilot/hosts.json",
        "home-opencode-auth": sandbox.roots["HOME"]
        / ".local/share/opencode/auth.json",
        "home-pi-auth": sandbox.roots["HOME"] / ".pi/agent/auth.json",
        "home-openclaw-auth": sandbox.roots["HOME"]
        / ".openclaw/agent/auth.json",
        "home-hermes-auth": sandbox.roots["HOME"] / ".hermes/auth.json",
        "home-login-keychain": sandbox.roots["HOME"]
        / "Library/Keychains/login.keychain",
        "home-login-keychain-db": sandbox.roots["HOME"]
        / "Library/Keychains/login.keychain-db",
    }
    for path in protected_files.values():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(fixture_json)
        path.chmod(0o600)

    app_config = sandbox.roots["JCODE_HOME"] / "config/jcode"
    app_config.mkdir(parents=True, exist_ok=True)
    for name, payload in {
        "openrouter.env": "OPENROUTER_API_KEY=fixture-only-not-a-credential\n",
        "openai.env": "OPENAI_API_KEY=fixture-only-not-a-credential\n",
        "azure.env": (
            "AZURE_OPENAI_API_KEY=fixture-only-not-a-credential\n"
            "AZURE_OPENAI_ENDPOINT=https://fixture.invalid\n"
        ),
        "bedrock.env": (
            "AWS_ACCESS_KEY_ID=fixture-only\n"
            "AWS_SECRET_ACCESS_KEY=fixture-only-not-a-credential\n"
        ),
    }.items():
        path = app_config / name
        path.write_text(payload, encoding="utf-8")
        path.chmod(0o600)
        protected_files[f"provider-env-{name}"] = path

    restart_snapshot = sandbox.roots["JCODE_HOME"] / "restart-snapshot.json"
    restart_snapshot.write_text(
        json.dumps(
            {
                "version": 1,
                "created_at": "2026-07-28T00:00:00Z",
                "auto_restore_on_next_start": True,
                "sessions": [
                    {
                        "session_id": "fixture-only-session",
                        "display_name": "fixture-only restart decoy",
                        "working_dir": str(sandbox.roots["CWD"]),
                        "is_selfdev": False,
                    }
                ],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    restart_snapshot.chmod(0o600)
    protected_files["restart-snapshot"] = restart_snapshot

    replacement_marker = sandbox.roots["OPERATOR"] / "replacement-attempted"
    replacement_script = (
        "#!/bin/sh\n"
        'printf "%s\\n" "$0 $*" > "$OMNIS_REPLACEMENT_SENTINEL"\n'
        "exit 97\n"
    )
    builds = sandbox.roots["JCODE_HOME"] / "builds"
    for channel in ("current", "stable", "shared-server"):
        candidate = builds / channel / "jcode"
        candidate.parent.mkdir(parents=True, exist_ok=True)
        candidate.write_text(replacement_script, encoding="utf-8")
        candidate.chmod(0o700)
        protected_files[f"replacement-{channel}"] = candidate
        marker = builds / f"{channel}-version"
        marker.write_text("0.61.2\n", encoding="utf-8")
        marker.chmod(0o600)
        protected_files[f"replacement-version-{channel}"] = marker

    for command_name in ("cargo", "curl", "git", "jcode", "open", "xdg-open"):
        candidate = sandbox.roots["HOSTILE_PATH"] / command_name
        candidate.write_text(replacement_script, encoding="utf-8")
        candidate.chmod(0o700)
        protected_files[f"hostile-path-{command_name}"] = candidate

    for path in protected_files.values():
        parent = path.parent
        while parent != sandbox.root and is_within(parent, sandbox.root):
            parent.chmod(0o700)
            parent = parent.parent

    forbidden_prefixes = {
        "jcode-external-auth": sandbox.roots["JCODE_HOME"] / "external",
        "inherited-build-channels": sandbox.roots["JCODE_HOME"] / "builds",
        "hostile-executable-path": sandbox.roots["HOSTILE_PATH"],
        "home-claude": sandbox.roots["HOME"] / ".claude",
        "home-codex": sandbox.roots["HOME"] / ".codex",
        "home-cursor": sandbox.roots["HOME"] / ".cursor",
        "home-copilot": sandbox.roots["HOME"] / ".config/github-copilot",
        "home-opencode": sandbox.roots["HOME"] / ".local/share/opencode",
        "home-pi": sandbox.roots["HOME"] / ".pi",
        "home-openclaw": sandbox.roots["HOME"] / ".openclaw",
        "home-hermes": sandbox.roots["HOME"] / ".hermes",
        "home-keychains": sandbox.roots["HOME"] / "Library/Keychains",
    }

    protected_snapshot_keys: set[str] = set()
    for path in protected_files.values():
        for root_label, root in sandbox.roots.items():
            if is_within(path, root):
                protected_snapshot_keys.add(
                    f"{root_label}:{path.relative_to(root).as_posix()}"
                )
                break

    sandbox.environment.update(
        {
            name: credential_canary_value(name)
            for name in CREDENTIAL_ENVIRONMENT
        }
    )
    sandbox.environment["OMNIS_REPLACEMENT_SENTINEL"] = str(replacement_marker)
    return HostilePtyFixtures(
        protected_files=protected_files,
        forbidden_prefixes=forbidden_prefixes,
        protected_snapshot_keys=protected_snapshot_keys,
        replacement_marker=replacement_marker,
    )


def snapshot_entry(path: Path) -> tuple[object, ...]:
    metadata = path.lstat()
    mode = stat.S_IMODE(metadata.st_mode)
    identity = (
        metadata.st_uid,
        metadata.st_gid,
        getattr(metadata, "st_flags", 0),
    )
    if path.is_symlink():
        return (
            "symlink",
            mode,
            *identity,
            metadata.st_nlink,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
            os.readlink(path),
        )
    if path.is_dir():
        return ("directory", mode, *identity)
    if path.is_file():
        return (
            "file",
            mode,
            *identity,
            metadata.st_nlink,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
            metadata.st_size,
            sha256_file(path),
        )
    return ("other", mode, *identity, stat.S_IFMT(metadata.st_mode))


def snapshot(roots: dict[str, Path]) -> dict[str, tuple[object, ...]]:
    result: dict[str, tuple[object, ...]] = {}
    for label, root in roots.items():
        result[f"{label}:."] = snapshot_entry(root)
        pending = [root]
        while pending:
            directory = pending.pop()
            for entry in sorted(os.scandir(directory), key=lambda item: item.name):
                path = Path(entry.path)
                relative = path.relative_to(root).as_posix()
                result[f"{label}:{relative}"] = snapshot_entry(path)
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
    return result


def changed_paths(
    before: dict[str, tuple[object, ...]],
    after: dict[str, tuple[object, ...]],
) -> set[str]:
    return {
        key
        for key in before.keys() | after.keys()
        if before.get(key) != after.get(key)
    }


def parse_instrumentation_event(line: str) -> InstrumentationEvent:
    fields = line.split("|", 2)
    if len(fields) != 3 or fields[0] != EVENT_SCHEMA:
        raise GateFailure(f"malformed instrumentation event envelope: {line!r}")
    try:
        pid = int(fields[1])
    except ValueError as error:
        raise GateFailure(f"invalid instrumentation event pid: {line!r}") from error
    if pid <= 0 or not fields[2]:
        raise GateFailure(f"invalid instrumentation event envelope: {line!r}")
    return InstrumentationEvent(pid=pid, payload=fields[2], raw=line)


def read_events(log: Path) -> list[InstrumentationEvent]:
    if not log.exists():
        raise GateFailure("instrumentation log was not created")
    return [
        parse_instrumentation_event(line.strip())
        for line in log.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def attributed_filesystem_events(
    events: Iterable[InstrumentationEvent],
) -> list[tuple[int, str, str]]:
    parsed: list[tuple[int, str, str]] = []
    for event in events:
        if not event.payload.startswith("FS|"):
            continue
        fields = event.payload.split("|", 2)
        if len(fields) != 3:
            raise GateFailure(
                f"malformed filesystem instrumentation event: {event.raw!r}"
            )
        parsed.append((event.pid, fields[1], fields[2]))
    return parsed


def filesystem_events(
    events: Iterable[InstrumentationEvent],
) -> list[tuple[str, str]]:
    return [
        (operation, path)
        for _, operation, path in attributed_filesystem_events(events)
    ]


def event_name(event: InstrumentationEvent) -> str:
    return event.payload.split("|", 1)[0]


def canonical_observed_path(path: Path) -> Path:
    normalized = Path(os.path.normpath(str(path)))
    if sys.platform == "darwin" and normalized.is_absolute():
        parts = normalized.parts
        if len(parts) >= 2 and parts[1] in {"tmp", "var", "etc"}:
            normalized = Path("/private").joinpath(*parts[1:])
    return normalized


def trace_sha256(events: Iterable[InstrumentationEvent]) -> str:
    materialized = list(events)
    return hashlib.sha256(
        ("\n".join(event.raw for event in materialized) + "\n").encode("utf-8")
    ).hexdigest()


def normalized_instrumentation_summary(
    events: Iterable[InstrumentationEvent], sandbox: Sandbox
) -> dict[str, object]:
    materialized = list(events)
    operations = Counter(operation for operation, _ in filesystem_events(materialized))
    path_classes: Counter[str] = Counter()
    for _, raw_path in filesystem_events(materialized):
        if not raw_path.startswith("/"):
            path_classes["relative-or-unresolved"] += 1
            continue
        path = canonical_observed_path(Path(raw_path))
        matched = False
        for label, root in sandbox.roots.items():
            if is_within(path, canonical_observed_path(root)):
                path_classes[f"controlled:{label}"] += 1
                matched = True
                break
        if not matched:
            if path.parent in {Path("/tmp"), Path("/private/tmp")} and path.name.startswith(
                "omnis-key-demo-"
            ):
                path_classes["demo-root"] += 1
            elif any(part.startswith("omnis-key-demo-") for part in path.parts):
                path_classes["demo-root-descendant"] += 1
            else:
                path_classes["system-or-other"] += 1
    return {
        "networkEvents": sorted(
            {event_name(event) for event in materialized} & NETWORK_EVENTS
        ),
        "unixSocketEvents": sorted(
            {event_name(event) for event in materialized} & UNIX_EVENTS
        ),
        "credentialEnvironmentAccesses": sorted(
            {
                event.payload.removeprefix(CREDENTIAL_EVENT_PREFIX)
                for event in materialized
                if event.payload.startswith(CREDENTIAL_EVENT_PREFIX)
            }
        ),
        "operatorAccessDetected": any(
            event.payload == "OPERATOR" for event in materialized
        ),
        "instrumentedProcessCount": len({event.pid for event in materialized}),
        "processStartCount": sum(
            event.payload.startswith(PROCESS_START_PREFIX)
            for event in materialized
        ),
        "executionAttemptCount": sum(
            event.payload.startswith(EXECUTION_ATTEMPT_PREFIX)
            for event in materialized
        ),
        "unixSocketAttemptCount": sum(
            event_name(event) in UNIX_EVENTS for event in materialized
        ),
        "filesystemCallCount": sum(operations.values()),
        "filesystemOperations": dict(sorted(operations.items())),
        "filesystemPathClasses": dict(sorted(path_classes.items())),
        "traceEventSchema": EVENT_SCHEMA,
        "traceEventCount": len(materialized),
        "traceSha256": trace_sha256(materialized),
    }


def is_within(path: Path, root: Path) -> bool:
    canonical_path = canonical_observed_path(path)
    canonical_root = canonical_observed_path(root)
    return canonical_path == canonical_root or canonical_root in canonical_path.parents


def assert_no_direct_environment_enumeration() -> int:
    checked = 0
    violations: list[str] = []
    missing_sensitive_names: dict[str, set[str]] = {}
    for source_root in (REPO_ROOT / "src", REPO_ROOT / "crates"):
        for path in source_root.rglob("*.rs"):
            checked += 1
            text = path.read_text(encoding="utf-8")
            relative = path.relative_to(REPO_ROOT).as_posix()
            if (
                DIRECT_ENVIRONMENT_ENUMERATION.search(text)
                and relative not in EXPLICIT_ONLY_ENVIRONMENT_ENUMERATION_PATHS
            ):
                violations.append(relative)
            for name in LITERAL_ENVIRONMENT_READ.findall(text):
                sensitive = (
                    "API_KEY" in name
                    or name.endswith("_TOKEN")
                    or name.endswith("_TOKEN_ID")
                    or "SECRET" in name
                    or "CREDENTIAL" in name
                    or "AUTH" in name
                    or "ACCOUNT" in name
                    or "SUBSCRIPTION" in name
                    or "ENDPOINT" in name
                    or "BASE_URL" in name
                    or "PROVIDER_PROFILE" in name
                    or name == "AWS_PROFILE"
                )
                if (
                    sensitive
                    and name not in NON_CREDENTIAL_AUTH_CONTROL_ENVIRONMENT
                    and name not in CREDENTIAL_ENVIRONMENT
                ):
                    missing_sensitive_names.setdefault(name, set()).add(relative)
    if violations:
        raise GateFailure(
            "direct process-environment enumeration bypasses credential read "
            f"instrumentation: {sorted(violations)}"
        )
    if missing_sensitive_names:
        details = {
            name: sorted(paths)
            for name, paths in sorted(missing_sensitive_names.items())
        }
        raise GateFailure(
            "shipped sensitive environment reads are absent from the "
            f"credential instrumentation inventory: {details}"
        )
    return checked


def run_instrumentation_positive_control(
    base: Path,
    interposer: Path,
    probe: Path,
    evidence: Path,
) -> dict[str, object]:
    sandbox = make_sandbox(base, "instrumentation-positive-control", interposer)
    log = evidence / "instrumentation-positive-control.events"
    log.write_bytes(b"")
    log.chmod(0o600)
    environment = dict(sandbox.environment)
    environment["OMNIS_SOVEREIGNTY_LOG"] = str(log)
    environment["OMNIS_SOVEREIGNTY_FS_TRACE"] = "1"
    sentinel = sandbox.roots["OPERATOR"] / "NEVER_READ.txt"
    write_probe = sandbox.roots["CWD"] / "instrumentation-write-probe"
    completed = subprocess.run(
        [str(probe), str(sentinel), str(write_probe)],
        cwd=sandbox.roots["CWD"],
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=20,
        check=False,
    )
    if completed.returncode != 0:
        raise GateFailure(
            f"instrumentation positive control exited {completed.returncode}"
        )
    events = read_events(log)
    required = {
        "DNS",
        "DNS_GETHOSTBYNAME",
        "DNS_GETHOSTBYNAME2",
        "DNS_GETHOSTBYADDR",
        "DNS_RES_QUERY",
        "AF_INET",
        "AF_INET6",
        "CONNECT_AF_INET",
        "CONNECT_AF_INET6",
        "BIND_AF_INET",
        "BIND_AF_INET6",
        "BIND_AF_UNIX",
        "AF_UNIX",
        "CONNECT_AF_UNIX",
        "OPERATOR",
    }
    observed_names = {event_name(event) for event in events}
    missing = required - observed_names
    if missing:
        raise GateFailure(
            f"instrumentation positive control missed events: {sorted(missing)}"
        )
    sentinel_operations = {
        operation
        for operation, path in filesystem_events(events)
        if Path(path) == sentinel
    }
    missing_operations = {"open", "openat", "stat"} - sentinel_operations
    if missing_operations:
        raise GateFailure(
            "filesystem instrumentation positive control missed operations: "
            f"{sorted(missing_operations)}"
        )
    credential_reads = {
        event.payload.removeprefix(CREDENTIAL_EVENT_PREFIX)
        for event in events
        if event.payload.startswith(CREDENTIAL_EVENT_PREFIX)
    }
    missing_credential_reads = CREDENTIAL_ENVIRONMENT - credential_reads
    unexpected_credential_reads = credential_reads - CREDENTIAL_ENVIRONMENT
    if missing_credential_reads or unexpected_credential_reads:
        raise GateFailure(
            "credential-environment positive control mismatch: "
            f"missing={sorted(missing_credential_reads)} "
            f"unexpected={sorted(unexpected_credential_reads)}"
        )
    process_starts = [
        event
        for event in events
        if event.payload.startswith(PROCESS_START_PREFIX)
        and Path(event.payload.removeprefix(PROCESS_START_PREFIX)).name
        == probe.name
    ]
    if len(process_starts) != 1:
        raise GateFailure(
            "instrumentation positive control did not emit exactly one "
            f"probe process-start event: {len(process_starts)}"
        )
    write_operations = {
        operation
        for operation, path in filesystem_events(events)
        if canonical_observed_path(Path(path))
        == canonical_observed_path(write_probe)
    }
    required_write_operations = {
        "open-write",
        "fchmod",
        "chmod",
        "fchown",
        "chown",
        "lchown",
        "utimes",
        "setxattr",
        "unlink",
    }
    missing_write_operations = required_write_operations - write_operations
    if missing_write_operations:
        raise GateFailure(
            "filesystem mutation positive control missed operations: "
            f"{sorted(missing_write_operations)}"
        )
    execution_attempts = [
        event.payload
        for event in events
        if event.payload.startswith(EXECUTION_ATTEMPT_PREFIX)
    ]
    if not execution_attempts or not all(
        "|trace=1|inject=1|" in payload for payload in execution_attempts
    ):
        raise GateFailure(
            "subprocess instrumentation positive control did not prove "
            "trace/injection propagation"
        )
    source_files_checked = assert_no_direct_environment_enumeration()
    return {
        "result": "PASS",
        "requiredNetworkAndOperatorEvents": sorted(required),
        "requiredFilesystemOperations": ["open", "openat", "stat"],
        "requiredMutationOperations": sorted(required_write_operations),
        "requiredCredentialEnvironmentReads": sorted(CREDENTIAL_ENVIRONMENT),
        "processStartEvents": 1,
        "executionAttemptEvents": len(execution_attempts),
        "directEnvironmentEnumerationSourceFilesChecked": source_files_checked,
        "traceSha256": trace_sha256(events),
    }


def assert_events(
    events: Iterable[InstrumentationEvent],
    *,
    forbid_unix: bool,
    label: str,
    allow_execution: bool = False,
) -> None:
    materialized = list(events)
    observed_names = {event_name(event) for event in materialized}
    forbidden = observed_names & NETWORK_EVENTS
    if forbid_unix:
        forbidden.update(observed_names & UNIX_EVENTS)
    if any(event.payload == "OPERATOR" for event in materialized):
        forbidden.add("OPERATOR")
    forbidden.update(
        event.payload
        for event in materialized
        if event.payload.startswith(CREDENTIAL_EVENT_PREFIX)
    )
    if not allow_execution:
        forbidden.update(
            event.payload
            for event in materialized
            if event.payload.startswith(EXECUTION_ATTEMPT_PREFIX)
        )
    if forbidden:
        raise GateFailure(
            f"{label} recorded forbidden runtime attempts: {sorted(forbidden)}"
        )


def assert_single_process_instrumented(
    events: Iterable[InstrumentationEvent],
    binary: Path,
    label: str,
) -> None:
    materialized = list(events)
    starts = parse_process_starts(materialized)
    if set(starts) != {event.pid for event in materialized} or len(starts) != 1:
        raise GateFailure(
            f"{label} did not bind every event to one instrumented process image"
        )
    images = next(iter(starts.values()))
    if len(images) != 1 or exact_existing_path(images[0]) != exact_existing_path(binary):
        raise GateFailure(f"{label} instrumented process image identity drifted")


def assert_hostile_pty_fixtures_ignored(
    events: Iterable[InstrumentationEvent],
    sandbox: Sandbox,
    fixtures: HostilePtyFixtures,
    changes: set[str],
) -> dict[str, object]:
    credential_environment_accesses = sorted(
        {
            event.payload.removeprefix(CREDENTIAL_EVENT_PREFIX)
            for event in events
            if event.payload.startswith(CREDENTIAL_EVENT_PREFIX)
        }
    )
    if credential_environment_accesses:
        raise GateFailure(
            "no-argument PTY read hostile credential/account environment: "
            f"{credential_environment_accesses}"
        )
    protected_by_path = {
        canonical_observed_path(path): label
        for label, path in fixtures.protected_files.items()
    }
    forbidden_prefixes = {
        label: canonical_observed_path(path)
        for label, path in fixtures.forbidden_prefixes.items()
    }
    accesses: set[str] = set()
    for operation, raw_path in filesystem_events(events):
        if raw_path in {"<null>", "<unresolved-relative-path>"}:
            if raw_path == "<unresolved-relative-path>":
                accesses.add(f"{operation}:unresolved-relative-path")
            continue
        path = Path(raw_path)
        if not path.is_absolute():
            path = sandbox.roots["CWD"] / path
        path = canonical_observed_path(path)
        protected_label = protected_by_path.get(path)
        if protected_label is not None:
            accesses.add(f"{operation}:{protected_label}")
            continue
        for prefix_label, prefix in forbidden_prefixes.items():
            if is_within(path, prefix):
                accesses.add(f"{operation}:{prefix_label}")
                break
    if accesses:
        raise GateFailure(
            "no-argument PTY accessed hostile credential/update/restart fixtures: "
            f"{sorted(accesses)}"
        )

    protected_changes = changes & fixtures.protected_snapshot_keys
    if protected_changes:
        raise GateFailure(
            "no-argument PTY modified hostile credential/update/restart fixtures: "
            f"{sorted(protected_changes)}"
        )
    if fixtures.replacement_marker.exists() or fixtures.replacement_marker.is_symlink():
        raise GateFailure("no-argument PTY executed an inherited replacement candidate")
    return {
        "fixtureOnly": True,
        "credentialAccountAccesses": 0,
        "protectedFixtureChanges": 0,
        "replacementCandidateExecutions": 0,
        "armedRestartRestoreExecutions": 0,
    }


def allowed_pty_write(path: str) -> bool:
    exact = {
        "HOME:.jcode",
        "HOME:.jcode/logs",
        "HOME:Library",
        "HOME:Library/Caches",
        "HOME:Library/Caches/jcode",
        "HOME:Library/Caches/jcode/mermaid",
        "JCODE_HOME:active_pids",
        "JCODE_HOME:ambient",
        "JCODE_HOME:ambient/transcripts",
        "JCODE_HOME:hotkey",
        "JCODE_HOME:hotkey/last_dir",
        "JCODE_HOME:hotkey/last_repo",
        "JCODE_HOME:keymap-snapshot.json",
        "JCODE_HOME:last_focused_client_session",
        "JCODE_HOME:logs",
        "JCODE_HOME:logs/memory",
        "JCODE_HOME:migrations",
        "JCODE_HOME:migrations/swarm-spawn-mode-inline",
        "JCODE_HOME:models",
        "JCODE_HOME:models/all-MiniLM-L6-v2",
        "JCODE_HOME:safety",
        "JCODE_HOME:safety/state.v1.initialized",
        "JCODE_HOME:safety/state.v1.json",
        "JCODE_HOME:safety/state.v1.lock",
        "JCODE_HOME:servers.json",
        "JCODE_HOME:sessions",
        "JCODE_HOME:sessions-bak-prune.stamp",
        "RUNTIME:durable-state",
        "RUNTIME:durable-state/swarm",
        "RUNTIME:jcode-daemon.lock",
        "RUNTIME:jcode.sock.hash",
        "TMPDIR:jcode-bg-tasks",
        "XDG_CACHE_HOME:jcode",
        "XDG_CACHE_HOME:jcode/mermaid",
    }
    if path in exact:
        return True
    patterns = (
        r"^HOME:\.jcode/logs/memory-events-\d{4}-\d{2}-\d{2}\.jsonl$",
        r"^JCODE_HOME:active_pids/.+$",
        r"^JCODE_HOME:logs/jcode-\d{4}-\d{2}-\d{2}\.log$",
        r"^JCODE_HOME:logs/memory/(?:client|server)-runtime-memory-"
        r"\d{4}-\d{2}-\d{2}\.jsonl$",
        r"^JCODE_HOME:sessions/session_[a-z0-9-]+_[0-9]{13}_[0-9a-f]{16}\.(?:bak|json)$",
    )
    return any(re.fullmatch(pattern, path) is not None for pattern in patterns)


def sandbox_manifest_path(path: Path, sandbox: Sandbox) -> str | None:
    canonical = canonical_observed_path(path)
    for label, root in sandbox.roots.items():
        canonical_root = canonical_observed_path(root)
        if is_within(canonical, canonical_root):
            if canonical == canonical_root:
                return f"{label}:."
            return f"{label}:{canonical.relative_to(canonical_root).as_posix()}"
    return None


def allowed_pty_transient_write(path: str) -> bool:
    exact = {
        "JCODE_HOME:.",
        "RUNTIME:.",
        "RUNTIME:jcode.sock",
        "RUNTIME:jcode.sock.spawning",
        "RUNTIME:jcode.sock.server.json",
    }
    if path in exact:
        return True
    patterns = (
        r"^RUNTIME:jcode\.sock\.server\.json\.[A-Za-z0-9_.-]+\.tmp$",
        r"^JCODE_HOME:\.[A-Za-z0-9_.-]+\.[A-Za-z0-9_.-]+\.tmp$",
        r"^JCODE_HOME:safety/\.[A-Za-z0-9_.-]+\.[A-Za-z0-9_.-]+\.tmp$",
        r"^JCODE_HOME:sessions/\.session_pawprint_[A-Za-z0-9_.-]+\.tmp$",
        r"^JCODE_HOME:sessions/session_[a-z0-9-]+_[0-9]{13}_[0-9a-f]{16}"
        r"\.tmp\.[0-9]+\.[0-9]+$",
        r"^JCODE_HOME:(?:active|internal|streaming)_pids/"
        r"session_[a-z0-9-]+_[0-9]{13}_[0-9a-f]{16}$",
        r"^RUNTIME:durable-state/swarm/[A-Za-z0-9_-]+"
        r"\.(?:bak|json|tmp\.[0-9]+\.[0-9]+)$",
    )
    return any(re.fullmatch(pattern, path) is not None for pattern in patterns)


def mutating_filesystem_operation(operation: str) -> bool:
    return (
        operation in MUTATING_FILESYSTEM_OPERATIONS
        or operation.endswith("-write")
    )


def assert_pty_write_attempts(
    events: Iterable[InstrumentationEvent],
    sandbox: Sandbox,
    label: str,
) -> dict[str, object]:
    attempts: list[str] = []
    forbidden: list[str] = []
    for pid, operation, raw_path in attributed_filesystem_events(events):
        if not mutating_filesystem_operation(operation):
            continue
        if raw_path in {"<null>", "<unresolved-relative-path>", "<unresolved-file-descriptor>"}:
            forbidden.append(f"pid={pid}:{operation}:{raw_path}")
            continue
        path = Path(raw_path)
        if not path.is_absolute():
            forbidden.append(f"pid={pid}:{operation}:relative:{raw_path}")
            continue
        canonical_path = canonical_observed_path(path)
        if operation == "open-write" and canonical_path == Path("/dev/null"):
            attempts.append("open-write:SYSTEM:/dev/null")
            continue
        manifest_path = sandbox_manifest_path(path, sandbox)
        if manifest_path is None:
            forbidden.append(f"pid={pid}:{operation}:outside-controlled-roots")
            continue
        attempts.append(f"{operation}:{manifest_path}")
        if not (
            allowed_pty_write(manifest_path)
            or allowed_pty_transient_write(manifest_path)
        ):
            forbidden.append(f"pid={pid}:{operation}:{manifest_path}")
    if forbidden:
        raise GateFailure(
            f"{label} made forbidden transient or metadata write attempts: "
            f"{sorted(forbidden)}"
        )
    return {
        "attemptCount": len(attempts),
        "attemptClasses": sorted(set(attempts)),
        "forbiddenAttemptCount": 0,
    }


def parse_process_starts(
    events: Iterable[InstrumentationEvent],
) -> dict[int, list[Path]]:
    starts: dict[int, list[Path]] = {}
    for event in events:
        if not event.payload.startswith(PROCESS_START_PREFIX):
            continue
        image = event.payload.removeprefix(PROCESS_START_PREFIX)
        if not image.startswith("/"):
            raise GateFailure(f"instrumented process image was not absolute: {image!r}")
        starts.setdefault(event.pid, []).append(canonical_observed_path(Path(image)))
    return starts


def parse_execution_attempt(payload: str) -> tuple[str, bool, bool, str]:
    fields = payload.split("|", 4)
    if (
        len(fields) != 5
        or fields[0] != "EXEC_ATTEMPT"
        or fields[2] not in {"trace=0", "trace=1"}
        or fields[3] not in {"inject=0", "inject=1"}
    ):
        raise GateFailure(f"malformed execution instrumentation event: {payload!r}")
    return (
        fields[1],
        fields[2] == "trace=1",
        fields[3] == "inject=1",
        fields[4],
    )


def parse_execution_result(payload: str) -> tuple[str, int, int, str]:
    fields = payload.split("|", 4)
    if (
        len(fields) != 5
        or fields[0] != "EXEC_RESULT"
        or not fields[2].startswith("result=")
        or not fields[3].startswith("pid=")
    ):
        raise GateFailure(f"malformed execution result event: {payload!r}")
    try:
        result = int(fields[2].removeprefix("result="))
        pid = int(fields[3].removeprefix("pid="))
    except ValueError as error:
        raise GateFailure(f"invalid execution result event: {payload!r}") from error
    return fields[1], result, pid, fields[4]


def exact_existing_path(path: Path) -> Path:
    return canonical_observed_path(Path(os.path.realpath(path)))


def assert_pty_process_instrumentation(
    events: Iterable[InstrumentationEvent],
    *,
    client_pid: int,
    temporary_server_pid: int,
    invoked_binary: Path,
) -> dict[str, object]:
    materialized = list(events)
    if temporary_server_pid == client_pid:
        raise GateFailure("temporary server reused the client pid")
    starts = parse_process_starts(materialized)
    observed_pids = {event.pid for event in materialized}
    expected_pids = {client_pid, temporary_server_pid}
    if observed_pids != expected_pids:
        raise GateFailure(
            "PTY instrumentation process set drifted: "
            f"observed={sorted(observed_pids)} expected={sorted(expected_pids)}"
        )

    expected_jcode = exact_existing_path(invoked_binary.parent / "jcode")
    expected_client = exact_existing_path(invoked_binary)
    client_images = [exact_existing_path(path) for path in starts.get(client_pid, [])]
    server_images = [
        exact_existing_path(path) for path in starts.get(temporary_server_pid, [])
    ]
    required_client_images = {expected_client}
    if invoked_binary.name == "omnis-key":
        required_client_images.add(expected_jcode)
    if not required_client_images.issubset(set(client_images)):
        raise GateFailure(
            "PTY client process-start image chain was incomplete: "
            f"observed={[path.name for path in client_images]} "
            f"required={[path.name for path in sorted(required_client_images)]}"
        )
    if set(server_images) != {expected_jcode}:
        raise GateFailure(
            "temporary server process-start image was not the exact sibling jcode"
        )

    execution_attempts: list[tuple[int, str, str]] = []
    for event in materialized:
        if not event.payload.startswith(EXECUTION_ATTEMPT_PREFIX):
            continue
        operation, trace_present, injection_present, raw_path = (
            parse_execution_attempt(event.payload)
        )
        if not trace_present or not injection_present:
            raise GateFailure(
                f"PTY {operation} stripped runtime instrumentation propagation"
            )
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            raise GateFailure(
                f"PTY launched a PATH-resolved executable via {operation}: {raw_path!r}"
            )
        if exact_existing_path(candidate) != expected_jcode:
            raise GateFailure(
                f"PTY launched a non-sibling executable via {operation}: "
                f"{candidate.name!r}"
            )
        execution_attempts.append((event.pid, operation, candidate.name))

    if invoked_binary.name == "omnis-key" and not any(
        pid == client_pid and operation == "execvp"
        for pid, operation, _ in execution_attempts
    ):
        raise GateFailure("omnis-key did not instrument its exact sibling exec handoff")
    successful_server_spawns = [
        parse_execution_result(event.payload)
        for event in materialized
        if event.payload.startswith(EXECUTION_RESULT_PREFIX)
    ]
    server_exec_observed = any(
        pid == temporary_server_pid
        and operation in {"execve", "execvp"}
        for pid, operation, _ in execution_attempts
    )
    parent_spawn_observed = any(
        result == 0
        and child_pid == temporary_server_pid
        and exact_existing_path(Path(raw_path)) == expected_jcode
        for _, result, child_pid, raw_path in successful_server_spawns
        if Path(raw_path).is_absolute()
    )
    if not server_exec_observed and not parent_spawn_observed:
        raise GateFailure(
            "temporary server pid was not bound to an instrumented exact-sibling spawn"
        )
    return {
        "clientProcessStartObserved": True,
        "clientImageChain": (
            ["omnis-key", "jcode"]
            if invoked_binary.name == "omnis-key"
            else ["jcode"]
        ),
        "temporaryServerProcessStartObserved": True,
        "temporaryServerImage": "jcode",
        "instrumentedProcessCount": 2,
        "executionAttemptCount": len(execution_attempts),
        "instrumentationPropagationStrips": 0,
        "unexpectedExecutableAttempts": 0,
    }


def parse_unix_socket_path(event: InstrumentationEvent) -> Path:
    fields = event.payload.split("|", 1)
    if len(fields) != 2 or fields[1] in {"", "<unnamed>"}:
        raise GateFailure(f"PTY used an unnamed Unix socket via {fields[0]}")
    if fields[1].startswith("@"):
        raise GateFailure(f"PTY used an abstract Unix socket via {fields[0]}")
    path = Path(fields[1])
    if not path.is_absolute():
        raise GateFailure(f"PTY used a relative Unix socket via {fields[0]}")
    return canonical_observed_path(path)


def assert_pty_unix_transport(
    events: Iterable[InstrumentationEvent],
    *,
    sandbox: Sandbox,
    client_pid: int,
    temporary_server_pid: int,
) -> dict[str, object]:
    expected_socket = canonical_observed_path(sandbox.roots["RUNTIME"] / "jcode.sock")
    socket_creations = [
        event for event in events if event_name(event) == "AF_UNIX"
    ]
    connects = [
        event for event in events if event_name(event) == "CONNECT_AF_UNIX"
    ]
    binds = [
        event for event in events if event_name(event) == "BIND_AF_UNIX"
    ]
    if not socket_creations or not connects or not binds:
        raise GateFailure("PTY did not exercise the complete controlled Unix transport")
    if any(
        event.pid not in {client_pid, temporary_server_pid}
        for event in socket_creations
    ):
        raise GateFailure("PTY Unix socket creation came from an unexpected process")
    if any(event.pid != client_pid for event in connects):
        raise GateFailure("PTY Unix socket connection did not come from the client")
    if any(event.pid != temporary_server_pid for event in binds):
        raise GateFailure("PTY Unix socket bind did not come from the temporary server")
    for event in [*connects, *binds]:
        if parse_unix_socket_path(event) != expected_socket:
            raise GateFailure(
                "PTY accessed a Unix socket other than the controlled jcode socket"
            )
    return {
        "socketPathClass": "controlled:JCODE_SOCKET",
        "socketCreateAttempts": len(socket_creations),
        "connectAttempts": len(connects),
        "bindAttempts": len(binds),
        "unexpectedSocketAttempts": 0,
        "clientConnectOnly": True,
        "temporaryServerBindOnly": True,
    }


def assert_no_credential_canary_leak(
    sandbox: Sandbox,
    fixtures: HostilePtyFixtures,
) -> None:
    protected = {
        canonical_observed_path(path) for path in fixtures.protected_files.values()
    }
    needle = b"credential-canary"
    for root in sandbox.roots.values():
        for directory, _, filenames in os.walk(root):
            for filename in filenames:
                path = Path(directory) / filename
                if canonical_observed_path(path) in protected or path.is_symlink():
                    continue
                try:
                    payload = path.read_bytes()
                except (OSError, ValueError):
                    continue
                if needle in payload.lower():
                    raise GateFailure(
                        "no-argument PTY copied a credential canary into "
                        f"{sandbox_manifest_path(path, sandbox)}"
                    )


def sanitized_argv(argv: list[str | bytes]) -> list[str]:
    executable = os.fsdecode(argv[0])
    sanitized = [Path(executable).name]
    for argument in argv[1:]:
        if isinstance(argument, bytes):
            try:
                argument = argument.decode("utf-8")
            except UnicodeDecodeError:
                sanitized.append(f"<NON_UTF8:{argument.hex()}>")
                continue
        if argument.startswith("/"):
            sanitized.append("<ABSOLUTE_PATH_REDACTED>")
        else:
            sanitized.append(argument)
    return sanitized


def run_command(
    sandbox: Sandbox,
    evidence: Path,
    label: str,
    argv: list[str | bytes],
    expected: set[int],
    *,
    forbid_unix: bool = False,
    trace_filesystem: bool = False,
    timeout: float = 20.0,
) -> tuple[dict[str, object], list[str]]:
    log = evidence / f"{label}.events"
    log.write_bytes(b"")
    log.chmod(0o600)
    environment = dict(sandbox.environment)
    environment["OMNIS_SOVEREIGNTY_LOG"] = str(log)
    if trace_filesystem:
        environment["OMNIS_SOVEREIGNTY_FS_TRACE"] = "1"
    try:
        completed = subprocess.run(
            argv,
            cwd=sandbox.roots["CWD"],
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise GateFailure(f"{label} timed out after {timeout}s") from error
    events = read_events(log)
    assert_events(events, forbid_unix=forbid_unix, label=label)
    assert_single_process_instrumented(
        events,
        Path(os.fsdecode(argv[0])),
        label,
    )
    if completed.returncode not in expected:
        raise GateFailure(
            f"{label} exited {completed.returncode}, expected {sorted(expected)}\n"
            f"stdout:\n{completed.stdout.decode(errors='replace')}\n"
            f"stderr:\n{completed.stderr.decode(errors='replace')}"
        )
    try:
        stdout_utf8 = completed.stdout.decode("utf-8")
        stderr_utf8 = completed.stderr.decode("utf-8")
    except UnicodeDecodeError as error:
        raise GateFailure(f"{label} emitted non-UTF-8 public output") from error
    return (
        {
            "name": label,
            "argv": sanitized_argv(argv),
            "exitCode": completed.returncode,
            "instrumentation": normalized_instrumentation_summary(events, sandbox),
            "stdoutSha256": hashlib.sha256(completed.stdout).hexdigest(),
            "stderrSha256": hashlib.sha256(completed.stderr).hexdigest(),
            "stdoutUtf8": stdout_utf8,
            "stderrUtf8": stderr_utf8,
        },
        events,
    )


def run_read_only_case(
    base: Path,
    interposer: Path,
    evidence: Path,
    binary: Path,
    label: str,
    arguments: list[str | bytes],
    expected: set[int],
    *,
    forbid_unix: bool = False,
) -> dict[str, object]:
    sandbox = make_sandbox(base, label, interposer)
    before = snapshot(sandbox.roots)
    result, _ = run_command(
        sandbox,
        evidence,
        label,
        [str(binary), *arguments],
        expected,
        forbid_unix=forbid_unix,
    )
    after = snapshot(sandbox.roots)
    changes = changed_paths(before, after)
    if changes:
        raise GateFailure(f"{label} made forbidden writes: {sorted(changes)}")
    result["writeManifest"] = []
    return result


def assert_private_path(path: Path, kind: str, mode: int) -> None:
    metadata = path.lstat()
    if kind == "directory" and not path.is_dir():
        raise GateFailure(f"expected private directory: {path.name}")
    if kind == "file" and not path.is_file():
        raise GateFailure(f"expected private file: {path.name}")
    actual = stat.S_IMODE(metadata.st_mode)
    if actual != mode:
        raise GateFailure(f"{path.name} mode {actual:o}, expected {mode:o}")


def record_case(
    base: Path,
    interposer: Path,
    evidence: Path,
    binary: Path,
    label: str,
    prefix: list[str],
) -> list[dict[str, object]]:
    sandbox = make_sandbox(base, label, interposer)
    before = snapshot(sandbox.roots)
    arguments = [
        *prefix,
        "record",
        "--event-id",
        "fixture:event/one",
        "test",
        "synthetic-subject",
        "--evidence-sha256",
        "a" * 64,
        "--json",
    ]
    first, _ = run_command(
        sandbox,
        evidence,
        f"{label}-first",
        [str(binary), *arguments],
        {0},
    )
    after_first = snapshot(sandbox.roots)
    changes = changed_paths(before, after_first)
    allowed = {
        "JCODE_HOME:state",
        "JCODE_HOME:state/omnis-key",
        "JCODE_HOME:state/omnis-key/receipts.jsonl",
        "JCODE_HOME:state/omnis-key/receipts.jsonl.lock",
    }
    if changes != allowed:
        raise GateFailure(
            f"{label} record write manifest mismatch: "
            f"observed={sorted(changes)} expected={sorted(allowed)}"
        )
    ledger_root = sandbox.roots["JCODE_HOME"] / "state" / "omnis-key"
    assert_private_path(ledger_root, "directory", 0o700)
    assert_private_path(ledger_root / "receipts.jsonl", "file", 0o600)
    assert_private_path(ledger_root / "receipts.jsonl.lock", "file", 0o600)
    if any(".tmp." in path.name for path in ledger_root.iterdir()):
        raise GateFailure(f"{label} left a receipt temp file behind")
    first["writeManifest"] = sorted(changes)

    replay_before = snapshot(sandbox.roots)
    replay, _ = run_command(
        sandbox,
        evidence,
        f"{label}-replay",
        [str(binary), *arguments],
        {0},
    )
    replay_after = snapshot(sandbox.roots)
    replay_changes = changed_paths(replay_before, replay_after)
    if replay_changes:
        raise GateFailure(f"{label} exact replay changed state: {sorted(replay_changes)}")
    replay["writeManifest"] = []

    for operation, suffix in [("status", "status"), ("verify", "verify")]:
        read_before = snapshot(sandbox.roots)
        read_result, _ = run_command(
            sandbox,
            evidence,
            f"{label}-{suffix}",
            [str(binary), *prefix, operation, "--json"],
            {0},
        )
        read_after = snapshot(sandbox.roots)
        read_changes = changed_paths(read_before, read_after)
        if read_changes:
            raise GateFailure(
                f"{label} {operation} changed existing state: {sorted(read_changes)}"
            )
        read_result["writeManifest"] = []
        if operation == "status":
            status_result = read_result
        else:
            verify_result = read_result
    return [first, replay, status_result, verify_result]


def reconcile_case(
    base: Path,
    interposer: Path,
    evidence: Path,
    binary: Path,
    label: str,
    arguments: list[str],
) -> list[dict[str, object]]:
    sandbox = make_sandbox(base, label, interposer)
    before = snapshot(sandbox.roots)
    first, _ = run_command(
        sandbox,
        evidence,
        f"{label}-first",
        [str(binary), *arguments],
        {0},
    )
    after = snapshot(sandbox.roots)
    changes = changed_paths(before, after)
    allowed = {
        "JCODE_HOME:safety",
        "JCODE_HOME:safety/state.v1.initialized",
        "JCODE_HOME:safety/state.v1.json",
        "JCODE_HOME:safety/state.v1.lock",
    }
    if changes != allowed:
        raise GateFailure(
            f"{label} reconcile write manifest mismatch: "
            f"observed={sorted(changes)} expected={sorted(allowed)}"
        )
    safety = sandbox.roots["JCODE_HOME"] / "safety"
    assert_private_path(safety, "directory", 0o700)
    for name in ["state.v1.initialized", "state.v1.json", "state.v1.lock"]:
        assert_private_path(safety / name, "file", 0o600)
    first["writeManifest"] = sorted(changes)

    second_before = snapshot(sandbox.roots)
    second, _ = run_command(
        sandbox,
        evidence,
        f"{label}-replay",
        [str(binary), *arguments],
        {0},
    )
    second_after = snapshot(sandbox.roots)
    second_changes = changed_paths(second_before, second_after)
    if second_changes:
        raise GateFailure(f"{label} reconcile replay changed state: {sorted(second_changes)}")
    second["writeManifest"] = []
    return [first, second]


def assert_demo_filesystem_access(
    events: list[InstrumentationEvent],
    sandbox: Sandbox,
    planted: Path,
    planted_symlink: Path,
    loader_roots: set[Path],
) -> dict[str, object]:
    accesses = filesystem_events(events)
    if not accesses:
        raise GateFailure("demo produced no filesystem events after a proven interposer load")

    normalized: list[tuple[str, Path]] = []
    for operation, raw_path in accesses:
        if not raw_path.startswith("/"):
            raise GateFailure(
                f"demo used unresolved or cwd-relative filesystem path via {operation}"
            )
        path = canonical_observed_path(Path(raw_path))
        normalized.append((operation, path))
        if is_within(path, sandbox.root):
            raise GateFailure(
                f"demo accessed a controlled harness root via {operation}"
            )
        if is_within(path, planted) or is_within(path, planted_symlink):
            raise GateFailure(
                f"demo accessed a preplanted demo-root adversary via {operation}"
            )

    temp_bases = {Path("/tmp"), Path("/private/tmp")}
    created_roots = {
        path
        for operation, path in normalized
        if operation in {"mkdir", "mkdirat"}
        and path.parent in temp_bases
        and path.name.startswith("omnis-key-demo-")
    }
    if len(created_roots) != 1:
        raise GateFailure(
            "demo instrumentation did not identify exactly one self-created root: "
            f"count={len(created_roots)}"
        )
    demo_root = next(iter(created_roots))

    system_prefixes = (
        Path("/System"),
        Path("/usr"),
        Path("/bin"),
        Path("/sbin"),
        Path("/Library"),
        Path("/etc"),
        Path("/private/etc"),
        Path("/dev"),
        Path("/proc"),
        Path("/sys"),
        Path("/var/db"),
        Path("/private/var/db"),
        Path("/var/folders"),
        Path("/private/var/folders"),
    )
    demo_calls = 0
    system_calls = 0
    for operation, path in normalized:
        if is_within(path, demo_root):
            demo_calls += 1
            continue
        if any(
            path == canonical_observed_path(loader_root)
            or path == canonical_observed_path(loader_root / "Info.plist")
            for loader_root in loader_roots
        ):
            system_calls += 1
            continue
        if sys.platform == "darwin" and path.name == ".CFUserTextEncoding":
            # CoreFoundation consults this Darwin runtime metadata before
            # `main`; it is not an OMNIS/config/operator-state access.
            system_calls += 1
            continue
        if path == Path("/") or path in temp_bases or any(
            is_within(path, prefix) for prefix in system_prefixes
        ):
            system_calls += 1
            continue
        raise GateFailure(
            "demo accessed a path outside system loader/runtime paths and its "
            f"self-created root via {operation}; basename={path.name!r}"
        )
    if demo_calls == 0:
        raise GateFailure("demo never accessed its instrumented self-created root")
    return {
        "result": "PASS",
        "selfCreatedRootCount": 1,
        "selfCreatedRootAccessCalls": demo_calls,
        "allowedSystemAccessCalls": system_calls,
        "controlledRootAccessCalls": 0,
        "preplantedAdversaryAccessCalls": 0,
    }


def demo_case(
    base: Path,
    interposer: Path,
    evidence: Path,
    binary: Path,
    label: str,
    arguments: list[str],
) -> dict[str, object]:
    sandbox = make_sandbox(base, label, interposer)
    install_hostile_demo_fixtures(sandbox)
    suffix = secrets.token_hex(12)
    planted = Path("/tmp") / f"omnis-key-demo-2147483646-{suffix}"
    victim = sandbox.root / "preplanted-victim"
    private_directory(victim)
    victim_file = victim / "preserve.txt"
    victim_file.write_bytes(b"preplanted fixture must survive\n")
    victim_file.chmod(0o600)
    planted.mkdir(mode=0o700)
    symlink_suffix = suffix[:-1] + ("0" if suffix[-1] != "0" else "1")
    symlink = Path("/tmp") / f"omnis-key-demo-2147483646-{symlink_suffix}"
    symlink.symlink_to(victim, target_is_directory=True)
    planted_identity = snapshot_entry(planted)
    symlink_identity = snapshot_entry(symlink)
    victim_digest = sha256_file(victim_file)

    try:
        before = snapshot(sandbox.roots)
        result, events = run_command(
            sandbox,
            evidence,
            label,
            [str(binary), *arguments],
            {0},
            forbid_unix=True,
            trace_filesystem=True,
        )
        after = snapshot(sandbox.roots)
        changes = changed_paths(before, after)
        if changes:
            raise GateFailure(f"{label} left writes outside its removed temp root: {sorted(changes)}")
        if not planted.exists() or snapshot_entry(planted) != planted_identity:
            raise GateFailure(f"{label} mutated a preplanted private demo-root adversary")
        if not symlink.is_symlink() or snapshot_entry(symlink) != symlink_identity:
            raise GateFailure(f"{label} mutated a preplanted symlink demo-root adversary")
        if sha256_file(victim_file) != victim_digest:
            raise GateFailure(f"{label} mutated the preplanted symlink victim")
        result["filesystemProof"] = assert_demo_filesystem_access(
            events,
            sandbox,
            planted,
            symlink,
            {binary.parent, interposer.parent},
        )
        result["writeManifest"] = ["private fixture root created and removed"]
        return result
    finally:
        if symlink.is_symlink():
            symlink.unlink()
        if planted.exists():
            planted.rmdir()


def pty_case(
    base: Path,
    interposer: Path,
    evidence: Path,
    binary: Path,
    label: str,
) -> dict[str, object]:
    sandbox = make_sandbox(base, label, interposer)
    hostile_fixtures = install_hostile_pty_fixtures(sandbox)
    before = snapshot(sandbox.roots)
    log = evidence / f"{label}.events"
    log.write_bytes(b"")
    log.chmod(0o600)
    environment = dict(sandbox.environment)
    environment["OMNIS_SOVEREIGNTY_LOG"] = str(log)
    environment["OMNIS_SOVEREIGNTY_FS_TRACE"] = "1"
    environment["JCODE_TEMP_SERVER"] = "1"
    environment["JCODE_SERVER_SCOPE"] = "temporary"
    environment["JCODE_TEMP_SERVER_IDLE_SECS"] = "1"
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))
    process = subprocess.Popen(
        [str(binary)],
        cwd=sandbox.roots["CWD"],
        env=environment,
        stdin=slave,
        stdout=slave,
        stderr=slave,
        start_new_session=True,
        close_fds=True,
    )
    os.close(slave)
    output = bytearray()
    deadline = time.monotonic() + 20.0
    frame_deadline = time.monotonic() + 10.0
    sent_quit = False
    sent_onboarding_escape = False
    first_frame_printable = 0
    first_frame_at: float | None = None
    temporary_server_pid: int | None = None
    metadata_path = sandbox.roots["RUNTIME"] / "jcode.sock.server.json"
    try:
        while process.poll() is None and time.monotonic() < deadline:
            readable, _, _ = select.select([master], [], [], 0.1)
            if readable:
                try:
                    output.extend(os.read(master, 65536))
                except OSError:
                    break
            if not sent_quit:
                without_ansi = re.sub(
                    rb"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))",
                    b"",
                    bytes(output),
                )
                first_frame_printable = sum(
                    byte in b"\n\r\t" or 0x20 <= byte < 0x7F for byte in without_ansi
                )
                if first_frame_printable >= 40 and first_frame_at is None:
                    if metadata_path.is_symlink() or not metadata_path.is_file():
                        if hostile_fixtures.replacement_marker.exists():
                            attempted = hostile_fixtures.replacement_marker.read_text(
                                encoding="utf-8", errors="replace"
                            ).strip()
                            raise GateFailure(
                                f"{label} executed an inherited replacement or PATH candidate: "
                                f"{attempted}"
                            )
                        raise GateFailure(
                            f"{label} did not expose temporary-server lifecycle metadata"
                        )
                    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                    expected_socket = str(sandbox.roots["RUNTIME"] / "jcode.sock")
                    if (
                        metadata.get("schema_version") != 1
                        or metadata.get("scope") != "temporary"
                        or metadata.get("socket_path") != expected_socket
                        or metadata.get("idle_timeout_secs") != 1
                        or not isinstance(metadata.get("pid"), int)
                        or metadata["pid"] <= 0
                    ):
                        raise GateFailure(
                            f"{label} temporary-server lifecycle metadata was invalid"
                        )
                    temporary_server_pid = metadata["pid"]
                    first_frame_at = time.monotonic()
                if (
                    first_frame_at is not None
                    and not sent_onboarding_escape
                    and time.monotonic() - first_frame_at >= 0.5
                ):
                    os.write(master, b"\x1b")
                    sent_onboarding_escape = True
                if (
                    first_frame_at is not None
                    and sent_onboarding_escape
                    and time.monotonic() - first_frame_at >= 1.5
                ):
                    os.write(master, b"/quit\r")
                    sent_quit = True
                elif first_frame_at is None and time.monotonic() >= frame_deadline:
                    break
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
            if not sent_quit:
                raise GateFailure(f"{label} PTY startup emitted no usable first frame")
            raise GateFailure(f"{label} PTY startup did not exit after onboarding escape and /quit")
    finally:
        os.close(master)
    if hostile_fixtures.replacement_marker.exists():
        attempted = hostile_fixtures.replacement_marker.read_text(
            encoding="utf-8", errors="replace"
        ).strip()
        raise GateFailure(
            f"{label} executed an inherited replacement or PATH candidate: {attempted}"
        )
    if process.returncode != 0:
        raise GateFailure(
            f"{label} PTY startup exited {process.returncode}; output digest "
            f"{hashlib.sha256(output).hexdigest()}"
        )
    if temporary_server_pid is None:
        raise GateFailure(f"{label} did not bind the temporary server process")

    shutdown_started = time.monotonic()
    shutdown_deadline = shutdown_started + 25.0
    while time.monotonic() < shutdown_deadline:
        try:
            os.kill(temporary_server_pid, 0)
            server_alive = True
        except ProcessLookupError:
            server_alive = False
        except PermissionError:
            server_alive = True
        if not server_alive and not metadata_path.exists():
            break
        time.sleep(0.1)
    else:
        raise GateFailure(
            f"{label} temporary server persisted beyond the bounded shutdown window"
        )

    first_quiescent_log = log.read_bytes()
    time.sleep(0.25)
    second_quiescent_log = log.read_bytes()
    if first_quiescent_log != second_quiescent_log:
        raise GateFailure(
            f"{label} instrumentation writer remained active after server shutdown"
        )
    events = read_events(log)
    assert_events(
        events,
        forbid_unix=False,
        label=label,
        allow_execution=True,
    )
    process_instrumentation = assert_pty_process_instrumentation(
        events,
        client_pid=process.pid,
        temporary_server_pid=temporary_server_pid,
        invoked_binary=binary,
    )
    local_transport = assert_pty_unix_transport(
        events,
        sandbox=sandbox,
        client_pid=process.pid,
        temporary_server_pid=temporary_server_pid,
    )
    write_attempt_proof = assert_pty_write_attempts(events, sandbox, label)
    after = snapshot(sandbox.roots)
    changes = changed_paths(before, after)
    hostile_fixture_proof = assert_hostile_pty_fixtures_ignored(
        events, sandbox, hostile_fixtures, changes
    )
    assert_no_credential_canary_leak(sandbox, hostile_fixtures)
    forbidden_changes = {path for path in changes if not allowed_pty_write(path)}
    if forbidden_changes:
        raise GateFailure(
            f"{label} PTY startup wrote outside the explicit compatibility manifest: "
            f"{sorted(forbidden_changes)}"
        )
    return {
        "name": label,
        "argv": [binary.name],
        "exitCode": process.returncode,
        "instrumentation": normalized_instrumentation_summary(events, sandbox),
        "stdoutSha256": hashlib.sha256(output).hexdigest(),
        "stderrSha256": None,
        "usableFirstFrame": True,
        "firstFramePrintableBytes": first_frame_printable,
        "hostileStartupProof": hostile_fixture_proof,
        "processInstrumentation": process_instrumentation,
        "controlledUnixTransport": local_transport,
        "writeAttemptProof": write_attempt_proof,
        "temporaryServerShutdown": {
            "metadataBound": True,
            "processExitObserved": True,
            "metadataRemoved": True,
            "instrumentationLogQuiescent": True,
            "boundedWaitSeconds": 25,
        },
        "writeManifest": sorted(changes),
    }


def run_gate(args: argparse.Namespace) -> dict[str, object]:
    provided_binaries = {"jcode": args.jcode, "omnis-key": args.omnis_key}
    for label, provided in provided_binaries.items():
        if provided.is_symlink():
            raise GateFailure(f"{label} binary must not be a symlink: {provided}")
    binaries = {
        label: provided.resolve() for label, provided in provided_binaries.items()
    }
    for label, binary in binaries.items():
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise GateFailure(f"{label} binary is not executable: {binary}")
    if binaries["jcode"].name != "jcode" or binaries["omnis-key"].name != "omnis-key":
        raise GateFailure("advertised binaries do not have the exact frozen names")
    if binaries["jcode"].parent != binaries["omnis-key"].parent:
        raise GateFailure("omnis-key and jcode must be exact sibling executables")
    if os.path.samefile(binaries["jcode"], binaries["omnis-key"]):
        raise GateFailure("omnis-key and jcode unexpectedly resolve to the same file")
    repository_identity = git_identity(allow_dirty=args.allow_dirty)

    work = Path(tempfile.mkdtemp(prefix="omnis-sovereignty-", dir="/tmp"))
    work.chmod(0o700)
    active_error: BaseException | None = None
    try:
        evidence = work / "instrumentation"
        private_directory(evidence)
        interposer, probe, compiler_version = compile_instrumentation(work)
        control_root = work / "controls"
        private_directory(control_root)
        instrumentation_control = run_instrumentation_positive_control(
            control_root,
            interposer,
            probe,
            evidence,
        )
        cases: list[dict[str, object]] = []

        canonical_help_and_version = [
            ("omnis-help", ["--help"]),
            ("omnis-help-short", ["-h"]),
            ("omnis-version", ["--version"]),
            ("omnis-version-short", ["-V"]),
            ("omnis-version-command", ["version"]),
            ("omnis-version-json", ["version", "--json"]),
            ("omnis-version-help", ["version", "--help"]),
            ("omnis-receipts-help", ["receipts", "--help"]),
            ("omnis-receipts-status-help", ["receipts", "status", "--help"]),
            ("omnis-receipts-verify-help", ["receipts", "verify", "--help"]),
            ("omnis-receipts-record-help", ["receipts", "record", "--help"]),
            (
                "omnis-receipts-reconcile-help",
                ["receipts", "reconcile-safety", "--help"],
            ),
            ("omnis-checkpoint-help", ["checkpoint", "--help"]),
            ("omnis-checkpoint-anchor-help", ["checkpoint", "anchor", "--help"]),
            (
                "omnis-checkpoint-verify-help",
                ["checkpoint", "verify-anchored", "--help"],
            ),
            ("omnis-demo-help", ["demo", "--help"]),
            ("omnis-demo-integrity-help", ["demo", "integrity", "--help"]),
        ]
        compatibility_help_and_version = [
            ("jcode-help", ["--help"]),
            ("jcode-help-short", ["-h"]),
            ("jcode-version", ["--version"]),
            ("jcode-version-short", ["-V"]),
            ("jcode-setup-hotkey-help", ["setup-hotkey", "--help"]),
            ("jcode-setup-launcher-help", ["setup-launcher", "--help"]),
            ("jcode-browser-help", ["browser", "--help"]),
            ("jcode-omnis-help", ["omnis", "--help"]),
            ("jcode-omnis-receipts-help", ["omnis", "receipts", "--help"]),
            (
                "jcode-omnis-receipts-status-help",
                ["omnis", "receipts", "status", "--help"],
            ),
            (
                "jcode-omnis-receipts-verify-help",
                ["omnis", "receipts", "verify", "--help"],
            ),
            (
                "jcode-omnis-receipts-record-help",
                ["omnis", "receipts", "record", "--help"],
            ),
            (
                "jcode-omnis-receipts-reconcile-help",
                ["omnis", "receipts", "reconcile-safety", "--help"],
            ),
            ("jcode-omnis-checkpoint-help", ["omnis", "checkpoint", "--help"]),
            (
                "jcode-omnis-checkpoint-anchor-help",
                ["omnis", "checkpoint", "anchor", "--help"],
            ),
            (
                "jcode-omnis-checkpoint-verify-help",
                ["omnis", "checkpoint", "verify-anchored", "--help"],
            ),
            ("jcode-omnis-demo-help", ["omnis", "demo", "--help"]),
            (
                "jcode-omnis-demo-integrity-help",
                ["omnis", "demo", "integrity", "--help"],
            ),
            ("jcode-omnis-version-command", ["omnis", "version"]),
            ("jcode-omnis-version-json", ["omnis", "version", "--json"]),
            ("jcode-omnis-version-help", ["omnis", "version", "--help"]),
        ]
        read_only = [
            *[
                (label, binaries["omnis-key"], arguments, {0}, False)
                for label, arguments in canonical_help_and_version
            ],
            *[
                (label, binaries["jcode"], arguments, {0}, False)
                for label, arguments in compatibility_help_and_version
            ],
            ("omnis-parse-error", binaries["omnis-key"], ["not-a-command"], {2}, False),
            (
                "omnis-non-utf8-parse-error",
                binaries["omnis-key"],
                [b"\xff"],
                {2},
                False,
            ),
            (
                "omnis-receipts-parse-error",
                binaries["omnis-key"],
                ["receipts", "not-a-command"],
                {2},
                False,
            ),
            (
                "omnis-record-missing-input",
                binaries["omnis-key"],
                ["receipts", "record"],
                {2},
                False,
            ),
            (
                "omnis-checkpoint-parse-error",
                binaries["omnis-key"],
                ["checkpoint", "not-a-command"],
                {2},
                False,
            ),
            (
                "omnis-demo-parse-error",
                binaries["omnis-key"],
                ["demo", "not-a-command"],
                {2},
                False,
            ),
            (
                "omnis-empty-status",
                binaries["omnis-key"],
                ["receipts", "status", "--json"],
                {3},
                False,
            ),
            (
                "omnis-empty-verify",
                binaries["omnis-key"],
                ["receipts", "verify", "--json"],
                {3},
                False,
            ),
            (
                "omnis-checkpoint-anchor",
                binaries["omnis-key"],
                ["checkpoint", "anchor", "--request-id", "fixture:anchor/one", "--json"],
                {4},
                False,
            ),
            (
                "omnis-checkpoint-verify",
                binaries["omnis-key"],
                ["checkpoint", "verify-anchored", "--json"],
                {4},
                False,
            ),
            (
                "omnis-malformed-event-id",
                binaries["omnis-key"],
                [
                    "receipts",
                    "record",
                    "--event-id",
                    "bad id",
                    "test",
                    "synthetic-subject",
                    "--evidence-sha256",
                    "a" * 64,
                    "--json",
                ],
                {2},
                False,
            ),
            (
                "omnis-malformed-checkpoint-request-id",
                binaries["omnis-key"],
                [
                    "checkpoint",
                    "anchor",
                    "--request-id",
                    "bad id",
                    "--json",
                ],
                {3},
                False,
            ),
            ("jcode-parse-error", binaries["jcode"], ["not-a-command"], {2}, False),
            (
                "jcode-non-utf8-parse-error",
                binaries["jcode"],
                [b"\xff"],
                {2},
                False,
            ),
            (
                "jcode-omnis-parse-error",
                binaries["jcode"],
                ["omnis", "not-a-command"],
                {2},
                False,
            ),
            (
                "jcode-omnis-receipts-parse-error",
                binaries["jcode"],
                ["omnis", "receipts", "not-a-command"],
                {2},
                False,
            ),
            (
                "jcode-omnis-record-missing-input",
                binaries["jcode"],
                ["omnis", "receipts", "record"],
                {2},
                False,
            ),
            (
                "jcode-omnis-checkpoint-parse-error",
                binaries["jcode"],
                ["omnis", "checkpoint", "not-a-command"],
                {2},
                False,
            ),
            (
                "jcode-omnis-demo-parse-error",
                binaries["jcode"],
                ["omnis", "demo", "not-a-command"],
                {2},
                False,
            ),
            (
                "jcode-global-omnis-status",
                binaries["jcode"],
                ["--quiet", "omnis", "receipts", "status", "--json"],
                {3},
                False,
            ),
            (
                "jcode-legacy-ledger-refusal",
                binaries["jcode"],
                ["omnis", "status", "--ledger", "/tmp/not-allowed"],
                {2},
                False,
            ),
            (
                "jcode-checkpoint-anchor",
                binaries["jcode"],
                ["omnis", "checkpoint", "anchor", "--request-id", "fixture:anchor/two", "--json"],
                {4},
                False,
            ),
            (
                "jcode-checkpoint-verify",
                binaries["jcode"],
                ["omnis", "checkpoint", "verify-anchored", "--json"],
                {4},
                False,
            ),
            (
                "jcode-malformed-event-id",
                binaries["jcode"],
                [
                    "omnis",
                    "receipts",
                    "record",
                    "--event-id",
                    "bad id",
                    "test",
                    "synthetic-subject",
                    "--evidence-sha256",
                    "a" * 64,
                    "--json",
                ],
                {2},
                False,
            ),
            (
                "jcode-malformed-checkpoint-request-id",
                binaries["jcode"],
                [
                    "omnis",
                    "checkpoint",
                    "anchor",
                    "--request-id",
                    "bad id",
                    "--json",
                ],
                {3},
                False,
            ),
            (
                "jcode-inherited-updater-refusal",
                binaries["jcode"],
                ["update"],
                {1},
                False,
            ),
            (
                "jcode-inherited-setup-hotkey-refusal",
                binaries["jcode"],
                ["setup-hotkey"],
                {1},
                False,
            ),
            (
                "jcode-inherited-setup-launcher-refusal",
                binaries["jcode"],
                ["setup-launcher"],
                {1},
                False,
            ),
            (
                "jcode-inherited-browser-refusal",
                binaries["jcode"],
                ["browser"],
                {1},
                False,
            ),
            (
                "jcode-inherited-pairing-refusal",
                binaries["jcode"],
                ["pair"],
                {1},
                False,
            ),
            (
                "jcode-inherited-pairing-help-refusal",
                binaries["jcode"],
                ["pair", "--help"],
                {2},
                False,
            ),
        ]
        cases_root = work / "cases"
        private_directory(cases_root)
        for label, binary, arguments, expected, forbid_unix in read_only:
            cases.append(
                run_read_only_case(
                    cases_root,
                    interposer,
                    evidence,
                    binary,
                    label,
                    arguments,
                    expected,
                    forbid_unix=forbid_unix,
                )
            )

        cases.extend(
            record_case(
                cases_root,
                interposer,
                evidence,
                binaries["omnis-key"],
                "omnis-record",
                ["receipts"],
            )
        )
        cases.extend(
            record_case(
                cases_root,
                interposer,
                evidence,
                binaries["jcode"],
                "jcode-record",
                ["omnis", "receipts"],
            )
        )
        cases.extend(
            reconcile_case(
                cases_root,
                interposer,
                evidence,
                binaries["omnis-key"],
                "omnis-reconcile",
                ["receipts", "reconcile-safety", "--json"],
            )
        )
        cases.extend(
            reconcile_case(
                cases_root,
                interposer,
                evidence,
                binaries["jcode"],
                "jcode-reconcile",
                ["omnis", "receipts", "reconcile-safety", "--json"],
            )
        )
        cases.append(
            demo_case(
                cases_root,
                interposer,
                evidence,
                binaries["omnis-key"],
                "omnis-demo",
                ["demo", "integrity", "--json"],
            )
        )
        cases.append(
            demo_case(
                cases_root,
                interposer,
                evidence,
                binaries["jcode"],
                "jcode-demo",
                ["omnis", "demo", "integrity", "--json"],
            )
        )
        cases.append(
            pty_case(
                cases_root,
                interposer,
                evidence,
                binaries["jcode"],
                "jcode-pty-no-argument",
            )
        )
        cases.append(
            pty_case(
                cases_root,
                interposer,
                evidence,
                binaries["omnis-key"],
                "omnis-pty-no-argument",
            )
        )

        return {
            "schemaVersion": 1,
            "proposition": "OMNIS KEY Local Integrity V1 fork sovereignty",
            "externalActions": False,
            "gitIdentity": repository_identity,
            "platform": {"system": platform.system(), "machine": platform.machine()},
            "toolchain": {
                "python": platform.python_version(),
                "compiler": compiler_version,
            },
            "instrumentationPositiveControl": instrumentation_control,
            "binaries": {
                label: {
                    "name": binary.name,
                    "sha256": sha256_file(binary),
                }
                for label, binary in binaries.items()
            },
            "cases": cases,
            "result": "PASS",
        }
    except BaseException as error:
        active_error = error
        raise
    finally:
        try:
            shutil.rmtree(work)
        except OSError as cleanup_error:
            if active_error is None:
                raise GateFailure(
                    "harness work root was not quiescent after all cases completed"
                ) from cleanup_error
            raise GateFailure(
                f"{active_error}; harness work root also remained non-quiescent"
            ) from active_error


def write_private_new_receipt(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    parent_metadata = path.parent.lstat()
    if path.parent.is_symlink() or not stat.S_ISDIR(parent_metadata.st_mode):
        raise GateFailure("receipt parent must be a real directory")
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    else:
        raise GateFailure("receipt target already exists or is a symlink")

    temporary = path.parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.link(temporary, path, follow_symlinks=False)
        directory_flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        directory = os.open(path.parent, directory_flags)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    metadata = path.lstat()
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise GateFailure("receipt publication did not produce a private regular file")


def main() -> int:
    args = parse_args()
    try:
        receipt = run_gate(args)
        payload = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8")
        write_private_new_receipt(args.receipt, payload)
        print(f"PASS: runtime sovereignty receipt sha256={sha256_file(args.receipt)}")
        return 0
    except (GateFailure, OSError, subprocess.SubprocessError) as error:
        print(f"REFUSE: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
