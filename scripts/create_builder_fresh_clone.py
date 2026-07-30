#!/usr/bin/env python3
"""Create one local-file-only full clone and its retained provenance marker."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True

from lib.builder_clone_provenance import (
    CLONE_ARGUMENTS,
    MARKER_KIND,
    ProvenanceError,
    absolute_without_following_leaf,
    atomic_private_write,
    git,
    git_environment,
    git_text,
    host_platform,
    repository_state,
    require_no_symlink_path,
    require_private_directory,
    sha256_bytes,
    validate_marker_object,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", required=True, choices=("linux", "macos"))
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--marker", required=True, type=Path)
    args = parser.parse_args()

    try:
        if args.platform != host_platform():
            raise ProvenanceError("requested platform does not match this host")
        source = require_no_symlink_path(args.source, "clone source")
        if not source.is_dir() or source.is_symlink():
            raise ProvenanceError("clone source is absent or unsafe")
        candidate = git_text(source, "rev-parse", "--verify", f"{args.candidate}^{{commit}}")
        head = git_text(source, "rev-parse", "--verify", "HEAD^{commit}")
        if candidate != head:
            raise ProvenanceError("clone candidate must be the source HEAD")
        tree = git_text(source, "rev-parse", f"{candidate}^{{tree}}")
        repository_state(
            source,
            candidate,
            tree,
            require_detached=False,
            require_local_origin=False,
        )

        destination = absolute_without_following_leaf(args.destination)
        marker = absolute_without_following_leaf(args.marker)
        require_private_directory(destination.parent, "clone destination parent")
        require_private_directory(marker.parent, "clone marker parent")
        if destination.exists() or destination.is_symlink():
            raise ProvenanceError("clone destination already exists")
        if marker.exists() or marker.is_symlink():
            raise ProvenanceError("clone marker already exists")
        if destination == marker or source in destination.parents or source in marker.parents:
            raise ProvenanceError("clone outputs must remain outside the source repository")
        if destination in marker.parents or marker in destination.parents:
            raise ProvenanceError("clone destination and marker must not contain each other")

        executable = shutil.which("git")
        if executable is None:
            raise ProvenanceError("git executable is absent")
        clone = [
            executable,
            "-c",
            "protocol.file.allow=always",
            "clone",
            "--no-local",
            "--no-hardlinks",
            "--no-checkout",
            "--",
            str(source),
            str(destination),
        ]
        result = subprocess.run(
            clone,
            env=git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise ProvenanceError(f"local full clone failed: {detail}")
        os.chmod(destination, 0o700)
        git(destination, "checkout", "--detach", "--force", candidate)
        state = repository_state(
            destination,
            candidate,
            tree,
            require_detached=True,
            require_local_origin=True,
        )
        marker_object = {
            "schemaVersion": 1,
            "kind": MARKER_KIND,
            "platform": args.platform,
            "candidate": {"commit": candidate, "tree": tree},
            "creation": {
                "sourceKind": "local-absolute-path",
                "allowedProtocols": ["file"],
                "ambientGitConfigDisabled": True,
                "cloneArguments": CLONE_ARGUMENTS,
            },
            "state": state,
            "toolchain": {
                "git": git_text(None, "--version"),
                "python": sys.version.splitlines()[0],
            },
            "externalActions": False,
        }
        validate_marker_object(
            marker_object, args.platform, candidate, tree, expected_state=state
        )
        payload = (
            json.dumps(
                marker_object, sort_keys=True, indent=2, ensure_ascii=False
            )
            + "\n"
        ).encode("utf-8")
        atomic_private_write(marker, payload)
        digest = sha256_bytes(payload)
    except (OSError, UnicodeError, ProvenanceError) as exc:
        print(f"fresh clone creation error: {exc}", file=sys.stderr)
        return 1

    print(
        "FRESH_CLONE_CREATED "
        f"schemaVersion=1 platform={args.platform} "
        f"candidateCommit={candidate} candidateTree={tree} "
        f"markerSha256={digest} externalActions=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
