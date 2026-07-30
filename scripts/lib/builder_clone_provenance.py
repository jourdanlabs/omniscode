"""Fail-closed primitives for local builder fresh-clone provenance."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any


MARKER_KIND = "jourdanlabs.omnis-builder-fresh-clone.v1"
PLATFORM_SYSTEM = {"linux": "Linux", "macos": "Darwin"}
CLONE_ARGUMENTS = [
    "clone",
    "--no-local",
    "--no-hardlinks",
    "--no-checkout",
    "--",
    "<SOURCE>",
    "<DESTINATION>",
]


class ProvenanceError(RuntimeError):
    """Raised when clone provenance is absent, ambiguous, or unsafe."""


def host_platform() -> str:
    if sys.platform == "darwin":
        return "macos"
    if sys.platform.startswith("linux"):
        return "linux"
    raise ProvenanceError(f"unsupported builder platform: {sys.platform}")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def git_environment() -> dict[str, str]:
    """Return a local-file-only Git environment without ambient config."""

    path = os.environ.get("PATH")
    if not path:
        raise ProvenanceError("PATH is absent")
    environment = {
        "PATH": path,
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_ALLOW_PROTOCOL": "file",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }
    task_tmp = os.environ.get("TMPDIR")
    if task_tmp:
        environment["TMPDIR"] = task_tmp
    return environment


def git(
    repo: Path | None,
    *arguments: str,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    executable = shutil.which("git")
    if executable is None:
        raise ProvenanceError("git executable is absent")
    command = [executable]
    if repo is not None:
        command.extend(["-C", str(repo)])
    command.extend(arguments)
    result = subprocess.run(
        command,
        env=git_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ProvenanceError(
            f"git command failed ({result.returncode}): "
            f"{' '.join(arguments)}: {detail}"
        )
    return result


def git_text(repo: Path | None, *arguments: str) -> str:
    return git(repo, *arguments).stdout.decode("utf-8", errors="strict").strip()


def absolute_without_following_leaf(path: Path) -> Path:
    return Path(os.path.abspath(path))


def require_no_symlink_path(path: Path, label: str) -> Path:
    absolute = absolute_without_following_leaf(path)
    if absolute.is_symlink():
        raise ProvenanceError(f"{label} is a symlink: {path}")
    return absolute.resolve()


def require_private_directory(path: Path, label: str) -> Path:
    path = require_no_symlink_path(path, label)
    if not path.is_dir() or path.is_symlink():
        raise ProvenanceError(f"{label} is not a regular directory: {path}")
    metadata = path.stat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ProvenanceError(f"{label} is not private mode 0700 and owner-bound")
    return path


def require_private_file(path: Path, label: str) -> bytes:
    path = require_no_symlink_path(path, label)
    if not path.is_file() or path.is_symlink():
        raise ProvenanceError(f"{label} is not a regular file: {path}")
    metadata = path.stat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ProvenanceError(f"{label} is not private mode 0600 and owner-bound")
    return path.read_bytes()


def local_config(repo: Path) -> dict[str, list[str]]:
    raw = git(repo, "config", "--local", "--null", "--list").stdout
    values: dict[str, list[str]] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        key, separator, value = record.partition(b"\n")
        if separator != b"\n":
            raise ProvenanceError("local Git config has ambiguous framing")
        decoded_key = key.decode("utf-8", errors="strict").lower()
        decoded_value = value.decode("utf-8", errors="strict")
        values.setdefault(decoded_key, []).append(decoded_value)
    return values


def forbidden_partial_config(config: dict[str, list[str]]) -> tuple[list[str], list[str], list[str]]:
    extensions: list[str] = []
    promisors: list[str] = []
    filters: list[str] = []
    for key in sorted(config):
        if key == "extensions.partialclone":
            extensions.append(key)
        elif re.fullmatch(r"remote\..+\.promisor", key):
            promisors.append(key)
        elif re.fullmatch(r"remote\..+\.partialclonefilter", key):
            filters.append(key)
    return extensions, promisors, filters


def repository_state(
    repo: Path,
    expected_commit: str,
    expected_tree: str,
    *,
    require_detached: bool,
    require_local_origin: bool,
) -> dict[str, Any]:
    repo = require_no_symlink_path(repo, "repository")
    if not repo.is_dir():
        raise ProvenanceError("repository directory is absent")
    top = Path(git_text(repo, "rev-parse", "--show-toplevel")).resolve()
    if top != repo:
        raise ProvenanceError(f"repository root disagrees: {top} != {repo}")
    commit = git_text(repo, "rev-parse", "--verify", "HEAD^{commit}")
    tree = git_text(repo, "rev-parse", "HEAD^{tree}")
    if commit != expected_commit or tree != expected_tree:
        raise ProvenanceError("repository candidate commit/tree identity disagrees")
    if git_text(repo, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ProvenanceError("repository worktree is not clean")

    symbolic = git(repo, "symbolic-ref", "-q", "HEAD", check=False)
    if symbolic.returncode not in {0, 1}:
        raise ProvenanceError("could not determine detached HEAD state")
    detached = symbolic.returncode == 1
    if require_detached and not detached:
        raise ProvenanceError("fresh-clone HEAD is not detached")

    shallow = git_text(repo, "rev-parse", "--is-shallow-repository")
    if shallow not in {"true", "false"}:
        raise ProvenanceError("Git returned an unknown shallow-repository state")
    git_directory = Path(git_text(repo, "rev-parse", "--absolute-git-dir"))
    if not git_directory.is_absolute() or git_directory.is_symlink():
        raise ProvenanceError("Git directory identity is unsafe")
    shallow_file = git_directory / "shallow"
    alternates_file = git_directory / "objects" / "info" / "alternates"
    grafts_file = git_directory / "info" / "grafts"

    config = local_config(repo)
    partial_extensions, promisor_entries, filter_entries = forbidden_partial_config(
        config
    )
    if (
        shallow != "false"
        or shallow_file.exists()
        or shallow_file.is_symlink()
        or partial_extensions
        or promisor_entries
        or filter_entries
        or alternates_file.exists()
        or alternates_file.is_symlink()
        or grafts_file.exists()
        or grafts_file.is_symlink()
    ):
        raise ProvenanceError(
            "repository is shallow, partial, promisor-backed, filtered, "
            "alternate-backed, or grafted"
        )

    replace_refs = git_text(
        repo, "for-each-ref", "--format=%(refname)", "refs/replace"
    ).splitlines()
    if replace_refs:
        raise ProvenanceError("repository has replacement refs")

    if require_local_origin:
        origin_values = config.get("remote.origin.url", [])
        if len(origin_values) != 1:
            raise ProvenanceError("fresh clone lacks exactly one local origin URL")
        origin = origin_values[0]
        if "://" in origin or not Path(origin).is_absolute():
            raise ProvenanceError("fresh clone origin is not a local absolute path")

    git(repo, "fsck", "--full", "--strict", "--connectivity-only")
    return {
        "headCommit": commit,
        "headTree": tree,
        "detachedHead": detached,
        "worktreeClean": True,
        "shallowRepository": False,
        "shallowFilePresent": False,
        "partialCloneExtensionEntries": [],
        "promisorConfigEntries": [],
        "partialCloneFilterConfigEntries": [],
        "alternatesFilePresent": False,
        "graftsFilePresent": False,
        "replaceRefs": [],
        "fsckConnectivity": "PASS",
    }


def validate_marker_object(
    marker: object,
    expected_platform: str,
    expected_commit: str,
    expected_tree: str,
    expected_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(marker, dict) or set(marker) != {
        "schemaVersion",
        "kind",
        "platform",
        "candidate",
        "creation",
        "state",
        "toolchain",
        "externalActions",
    }:
        raise ProvenanceError("clone marker top-level schema drifted")
    if (
        marker["schemaVersion"] != 1
        or marker["kind"] != MARKER_KIND
        or marker["platform"] != expected_platform
        or marker["externalActions"] is not False
    ):
        raise ProvenanceError("clone marker identity or external-action state drifted")
    candidate = marker["candidate"]
    if (
        not isinstance(candidate, dict)
        or set(candidate) != {"commit", "tree"}
        or candidate != {"commit": expected_commit, "tree": expected_tree}
    ):
        raise ProvenanceError("clone marker candidate identity disagrees")
    creation = marker["creation"]
    if (
        not isinstance(creation, dict)
        or set(creation)
        != {
            "sourceKind",
            "allowedProtocols",
            "ambientGitConfigDisabled",
            "cloneArguments",
        }
        or creation["sourceKind"] != "local-absolute-path"
        or creation["allowedProtocols"] != ["file"]
        or creation["ambientGitConfigDisabled"] is not True
        or creation["cloneArguments"] != CLONE_ARGUMENTS
    ):
        raise ProvenanceError("clone marker creation contract drifted")
    state = marker["state"]
    required_state_keys = {
        "headCommit",
        "headTree",
        "detachedHead",
        "worktreeClean",
        "shallowRepository",
        "shallowFilePresent",
        "partialCloneExtensionEntries",
        "promisorConfigEntries",
        "partialCloneFilterConfigEntries",
        "alternatesFilePresent",
        "graftsFilePresent",
        "replaceRefs",
        "fsckConnectivity",
    }
    if (
        not isinstance(state, dict)
        or set(state) != required_state_keys
        or state["headCommit"] != expected_commit
        or state["headTree"] != expected_tree
        or state["detachedHead"] is not True
        or state["worktreeClean"] is not True
        or state["shallowRepository"] is not False
        or state["shallowFilePresent"] is not False
        or state["partialCloneExtensionEntries"] != []
        or state["promisorConfigEntries"] != []
        or state["partialCloneFilterConfigEntries"] != []
        or state["alternatesFilePresent"] is not False
        or state["graftsFilePresent"] is not False
        or state["replaceRefs"] != []
        or state["fsckConnectivity"] != "PASS"
    ):
        raise ProvenanceError("clone marker repository state is not full and clean")
    if expected_state is not None and state != expected_state:
        raise ProvenanceError("clone marker state disagrees with in-clone verification")
    toolchain = marker["toolchain"]
    if (
        not isinstance(toolchain, dict)
        or set(toolchain) != {"git", "python"}
        or not all(isinstance(value, str) and value for value in toolchain.values())
    ):
        raise ProvenanceError("clone marker toolchain identity is incomplete")
    return marker


def read_marker(
    path: Path,
    expected_platform: str,
    expected_commit: str,
    expected_tree: str,
    expected_state: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], bytes, str]:
    payload = require_private_file(path, "clone provenance marker")
    if len(payload) > 128 * 1024 or b"\0" in payload or not payload.endswith(b"\n"):
        raise ProvenanceError("clone provenance marker framing is unsafe")
    try:
        marker = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ProvenanceError("clone provenance marker is not valid JSON") from exc
    validated = validate_marker_object(
        marker,
        expected_platform,
        expected_commit,
        expected_tree,
        expected_state,
    )
    canonical = (
        json.dumps(validated, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    if payload != canonical:
        raise ProvenanceError("clone provenance marker is not canonical JSON")
    return validated, payload, sha256_bytes(payload)


def atomic_private_write(path: Path, payload: bytes) -> None:
    path = absolute_without_following_leaf(path)
    parent = require_private_directory(path.parent, "marker parent")
    if path.exists() or path.is_symlink():
        raise ProvenanceError(f"marker output already exists: {path}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".omnis-clone-marker.", dir=parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists() or temporary.is_symlink():
            temporary.unlink()
