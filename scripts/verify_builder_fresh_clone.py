#!/usr/bin/env python3
"""Verify a clone in place and cross-bind its retained creation marker."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.dont_write_bytecode = True

from lib.builder_clone_provenance import (
    ProvenanceError,
    git_text,
    host_platform,
    read_marker,
    repository_state,
    require_no_symlink_path,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--marker", required=True, type=Path)
    args = parser.parse_args()

    try:
        platform = host_platform()
        repo = require_no_symlink_path(Path.cwd(), "fresh clone")
        commit = git_text(repo, "rev-parse", "--verify", "HEAD^{commit}")
        tree = git_text(repo, "rev-parse", "HEAD^{tree}")
        state = repository_state(
            repo,
            commit,
            tree,
            require_detached=True,
            require_local_origin=True,
        )
        _, _, digest = read_marker(
            args.marker,
            platform,
            commit,
            tree,
            expected_state=state,
        )
    except (OSError, UnicodeError, ProvenanceError) as exc:
        print(f"fresh clone verification error: {exc}", file=sys.stderr)
        return 1

    print(
        "FRESH_CLONE_VERIFIED "
        f"schemaVersion=1 platform={platform} "
        f"candidateCommit={commit} candidateTree={tree} "
        f"markerSha256={digest} detachedHead=true worktreeClean=true "
        "shallow=false partialClone=false promisor=false filter=false "
        "externalActions=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
