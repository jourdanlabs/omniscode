#!/usr/bin/env python3
"""Prove that the OMNIS release diff adds no guardrail regression.

The inherited ratchet files predate the frozen V1 implementation start and are
known to be stale. This checker compares the exact implementation start tree to
the candidate tree directly. It does not update or waive an inherited budget.

Covered release-diff properties:
- no new or grown oversized production/test Rust file;
- no per-file or total increase in production panic-prone patterns;
- no per-file, per-pattern, or total increase in swallowed-error patterns;
- no per-file or total increase in cross-crate wildcard re-exports; and
- no new Rust compiler warning signature when ``--check-warnings`` is used.

The normal release invocation names two committed trees and uses
``--check-warnings``. ``--candidate WORKTREE --skip-warnings`` exists only for
fast, pre-freeze iteration and is identified as non-final in the JSON output.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parent.parent
FROZEN_START = "670955adf1eebb207bc4a4411e5f6083562d167c"
SPEC_PATH = "docs/OPEN_SOURCE_V1_RELEASE_SPEC.md"
SPEC_SHA256 = "5753be2bd2ff7af6d892381c9294a477eb2d7839ec7f5df886f1096e490d2026"
SIZE_THRESHOLD = 1200

PANIC_RE = re.compile(r"\.unwrap\(|\.expect\(|\b(?:panic!|todo!|unimplemented!)")
SWALLOWED_RES = {
    "let_underscore": re.compile(r"\blet\s+_\s*="),
    "dot_ok": re.compile(r"\.ok\(\)"),
    "unwrap_or_default": re.compile(r"\.unwrap_or_default\(\)"),
}
WILDCARD_RE = re.compile(
    r"^\s*pub\s+use\s+(?:::)?jcode_[a-z0-9_]+(?:::[A-Za-z0-9_]+)*::\*\s*;"
)
CFG_TEST_RE = re.compile(r"^\s*#\s*\[\s*cfg\s*\(\s*(?:all\s*\(\s*)?test\s*[,)]")
ITEM_START_RE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:mod|fn)\b")


def run(
    argv: list[str],
    *,
    cwd: Path = REPO_ROOT,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def git_oid(ref: str, kind: str) -> str:
    result = run(["git", "rev-parse", "--verify", f"{ref}^{{{kind}}}"])
    return result.stdout.strip()


class Tree:
    def paths(self) -> Iterable[str]:
        raise NotImplementedError

    def read(self, path: str) -> str:
        raise NotImplementedError


@dataclass(frozen=True)
class GitTree(Tree):
    ref: str

    def paths(self) -> Iterable[str]:
        output = run(["git", "ls-tree", "-r", "--name-only", self.ref]).stdout
        return (line for line in output.splitlines() if line)

    def read(self, path: str) -> str:
        result = subprocess.run(
            ["git", "show", f"{self.ref}:{path}"],
            cwd=REPO_ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return result.stdout.decode("utf-8", errors="ignore")


@dataclass(frozen=True)
class WorkTree(Tree):
    root: Path

    def paths(self) -> Iterable[str]:
        tracked = run(["git", "ls-files", "-co", "--exclude-standard"]).stdout
        return (
            path
            for path in tracked.splitlines()
            if path and (self.root / path).is_file()
        )

    def read(self, path: str) -> str:
        return (self.root / path).read_text(encoding="utf-8", errors="ignore")


def is_rust(path: str) -> bool:
    return path.endswith(".rs") and (
        path.startswith("src/")
        or path.startswith("crates/")
        or path.startswith("tests/")
    )


def is_test_rust(path: str) -> bool:
    if not is_rust(path):
        return False
    parts = path.split("/")
    name = parts[-1]
    return (
        parts[0] == "tests"
        or any(
            part == "tests"
            or part.endswith("_tests")
            or part.endswith("_test")
            or part.startswith("tests_")
            for part in parts
        )
        or name == "tests.rs"
        or name.endswith("_tests.rs")
        or name.endswith("_test.rs")
        or name.startswith("tests_")
    )


def is_production_rust(path: str) -> bool:
    return (
        is_rust(path)
        and not is_test_rust(path)
        and (path.startswith("src/") or path.startswith("crates/"))
    )


def line_count(text: str) -> int:
    return len(text.splitlines())


def production_lines(text: str) -> list[str]:
    """Match the inherited ratchets' lightweight cfg(test) block exclusion."""
    output: list[str] = []
    skip_stack: list[int] = []
    pending_cfg_test = False
    for line in text.splitlines():
        stripped = line.strip()
        if not skip_stack:
            if pending_cfg_test and ITEM_START_RE.match(line):
                delta = line.count("{") - line.count("}")
                if delta > 0:
                    skip_stack.append(delta)
                pending_cfg_test = False
                continue
            if pending_cfg_test and stripped and not stripped.startswith("#"):
                pending_cfg_test = False
            if CFG_TEST_RE.match(line):
                pending_cfg_test = True
                continue
            output.append(line)
        else:
            skip_stack[-1] += line.count("{") - line.count("}")
            if skip_stack[-1] <= 0:
                skip_stack.pop()
    return output


def collect_metrics(tree: Tree) -> dict[str, object]:
    production_size: dict[str, int] = {}
    test_size: dict[str, int] = {}
    panic: dict[str, int] = {}
    swallowed: dict[str, dict[str, int]] = {}
    wildcard: dict[str, int] = {}

    for path in sorted(set(tree.paths())):
        if not is_rust(path):
            continue
        text = tree.read(path)
        lines = text.splitlines()
        count = line_count(text)
        if is_test_rust(path):
            if count > SIZE_THRESHOLD:
                test_size[path] = count
        elif is_production_rust(path):
            if count > SIZE_THRESHOLD:
                production_size[path] = count
            prod = production_lines(text)
            panic_count = sum(1 for line in prod if PANIC_RE.search(line))
            if panic_count:
                panic[path] = panic_count
            pattern_counts = {
                name: sum(1 for line in prod if pattern.search(line))
                for name, pattern in SWALLOWED_RES.items()
            }
            if sum(pattern_counts.values()):
                swallowed[path] = pattern_counts

        wildcard_count = sum(
            1
            for line in lines
            if not line.strip().startswith("//") and WILDCARD_RE.match(line)
        )
        if wildcard_count:
            wildcard[path] = wildcard_count

    return {
        "productionSize": production_size,
        "testSize": test_size,
        "panic": panic,
        "swallowed": swallowed,
        "wildcard": wildcard,
    }


def simple_regressions(
    label: str,
    base: dict[str, int],
    candidate: dict[str, int],
    *,
    compare_total: bool = True,
) -> list[str]:
    findings: list[str] = []
    for path, value in sorted(candidate.items()):
        prior = base.get(path, 0)
        if value > prior:
            findings.append(f"{label}: {path}: {prior} -> {value}")
    if compare_total and sum(candidate.values()) > sum(base.values()):
        findings.append(
            f"{label}: total: {sum(base.values())} -> {sum(candidate.values())}"
        )
    return findings


def swallowed_regressions(
    base: dict[str, dict[str, int]],
    candidate: dict[str, dict[str, int]],
) -> list[str]:
    findings: list[str] = []
    for path, counts in sorted(candidate.items()):
        prior = base.get(path, {})
        for name, value in sorted(counts.items()):
            old = prior.get(name, 0)
            if value > old:
                findings.append(f"swallowed/{name}: {path}: {old} -> {value}")
    for name in SWALLOWED_RES:
        old_total = sum(counts.get(name, 0) for counts in base.values())
        new_total = sum(counts.get(name, 0) for counts in candidate.values())
        if new_total > old_total:
            findings.append(f"swallowed/{name}: total: {old_total} -> {new_total}")
    old_grand = sum(sum(counts.values()) for counts in base.values())
    new_grand = sum(sum(counts.values()) for counts in candidate.values())
    if new_grand > old_grand:
        findings.append(f"swallowed: total: {old_grand} -> {new_grand}")
    return findings


def export_tree(ref: str, destination: Path) -> None:
    archive = subprocess.Popen(
        ["git", "archive", "--format=tar", ref],
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if archive.stdout is None:
        raise RuntimeError("git archive did not expose stdout")
    extracted = subprocess.run(
        ["tar", "-xf", "-", "-C", str(destination)],
        stdin=archive.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    archive.stdout.close()
    stderr = archive.stderr.read().decode("utf-8", errors="replace") if archive.stderr else ""
    status = archive.wait()
    if status != 0:
        raise RuntimeError(f"git archive {ref} failed ({status}): {stderr.strip()}")
    if extracted.returncode != 0:
        detail = extracted.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"tar extraction for {ref} failed ({extracted.returncode}): {detail}")


def warning_signatures(ref: str, target_dir: Path) -> collections.Counter[str]:
    with tempfile.TemporaryDirectory(prefix="omnis-guardrail-tree-") as raw:
        root = Path(raw)
        export_tree(ref, root)
        env = os.environ.copy()
        env["CARGO_TERM_COLOR"] = "never"
        env["CARGO_TARGET_DIR"] = str(target_dir)
        result = run(
            [
                "cargo",
                "check",
                "--locked",
                "--message-format=json",
            ],
            cwd=root,
            env=env,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"cargo check failed for {ref} ({result.returncode}):\n"
                f"{result.stderr[-4000:]}"
            )
        signatures: collections.Counter[str] = collections.Counter()
        for line in result.stdout.splitlines():
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if value.get("reason") != "compiler-message":
                continue
            message = value.get("message", {})
            if message.get("level") != "warning":
                continue
            spans = message.get("spans") or []
            primary_files = sorted(
                {
                    span.get("file_name", "")
                    for span in spans
                    if span.get("is_primary") and span.get("file_name")
                }
            )
            code = (message.get("code") or {}).get("code", "")
            package_fragment = str(value.get("package_id", "")).rsplit("#", 1)[-1]
            package = package_fragment.rsplit("@", 1)[0]
            signature = json.dumps(
                {
                    "package": package,
                    "code": code,
                    "message": message.get("message", ""),
                    "files": primary_files,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            signatures[signature] += 1
        return signatures


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default=FROZEN_START)
    parser.add_argument("--candidate", default="HEAD")
    warning_mode = parser.add_mutually_exclusive_group(required=True)
    warning_mode.add_argument("--check-warnings", action="store_true")
    warning_mode.add_argument("--skip-warnings", action="store_true")
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    base_commit = git_oid(args.base, "commit")
    base_tree_oid = git_oid(args.base, "tree")
    if base_commit != FROZEN_START:
        raise SystemExit(
            f"error: base must resolve to frozen implementation start {FROZEN_START}, "
            f"got {base_commit}"
        )

    worktree_mode = args.candidate == "WORKTREE"
    if worktree_mode:
        candidate_tree: Tree = WorkTree(REPO_ROOT)
        candidate_commit = None
        candidate_tree_oid = None
        if args.check_warnings:
            raise SystemExit("error: --check-warnings requires a committed candidate")
    else:
        candidate_commit = git_oid(args.candidate, "commit")
        candidate_tree_oid = git_oid(args.candidate, "tree")
        candidate_tree = GitTree(args.candidate)

    spec_bytes = candidate_tree.read(SPEC_PATH).encode("utf-8")
    spec_digest = hashlib.sha256(spec_bytes).hexdigest()
    if spec_digest != SPEC_SHA256:
        raise SystemExit(
            f"error: candidate spec digest mismatch: {spec_digest} != {SPEC_SHA256}"
        )

    base_metrics = collect_metrics(GitTree(args.base))
    candidate_metrics = collect_metrics(candidate_tree)
    regressions: list[str] = []
    regressions.extend(
        simple_regressions(
            "oversized-production",
            base_metrics["productionSize"],
            candidate_metrics["productionSize"],
            compare_total=False,
        )
    )
    regressions.extend(
        simple_regressions(
            "oversized-test",
            base_metrics["testSize"],
            candidate_metrics["testSize"],
            compare_total=False,
        )
    )
    regressions.extend(
        simple_regressions("panic", base_metrics["panic"], candidate_metrics["panic"])
    )
    regressions.extend(
        swallowed_regressions(
            base_metrics["swallowed"], candidate_metrics["swallowed"]
        )
    )
    regressions.extend(
        simple_regressions(
            "wildcard", base_metrics["wildcard"], candidate_metrics["wildcard"]
        )
    )

    warning_summary: dict[str, object]
    if args.check_warnings:
        with tempfile.TemporaryDirectory(prefix="omnis-guardrail-target-") as raw:
            target_dir = Path(raw)
            base_warnings = warning_signatures(args.base, target_dir)
            candidate_warnings = warning_signatures(args.candidate, target_dir)
        added_warnings = candidate_warnings - base_warnings
        for signature, count in sorted(added_warnings.items()):
            regressions.append(f"warning: added x{count}: {signature}")
        warning_summary = {
            "checked": True,
            "baseCount": sum(base_warnings.values()),
            "candidateCount": sum(candidate_warnings.values()),
            "addedCount": sum(added_warnings.values()),
        }
    else:
        warning_summary = {
            "checked": False,
            "reason": "explicit pre-freeze iteration mode",
        }

    payload = {
        "schemaVersion": 1,
        "status": "PASS" if not regressions else "FAIL",
        "base": {"commit": base_commit, "tree": base_tree_oid},
        "candidate": {
            "commit": candidate_commit,
            "tree": candidate_tree_oid,
            "worktreeMode": worktree_mode,
        },
        "specSha256": spec_digest,
        "thresholdLoc": SIZE_THRESHOLD,
        "warnings": warning_summary,
        "regressions": regressions,
        "counts": {
            label: {
                "baseFiles": len(base_metrics[key]),
                "candidateFiles": len(candidate_metrics[key]),
            }
            for label, key in (
                ("oversizedProduction", "productionSize"),
                ("oversizedTest", "testSize"),
                ("panic", "panic"),
                ("swallowed", "swallowed"),
                ("wildcard", "wildcard"),
            )
        },
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if not regressions else 1


if __name__ == "__main__":
    raise SystemExit(main())
