#!/usr/bin/env python3
"""Assemble a fail-closed, builder-only verification index from raw receipts.

This tool is deliberately not a release gate.  It derives evidence identity,
digests, command results, toolchains, version output, and acceptance mappings;
it can only record PASS evidence or a named HOLD.  It never emits CLEAR.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import sys
from typing import Callable, Iterable

sys.dont_write_bytecode = True

from generate_builder_manifest import (
    APPROVED_PROPOSITION,
    APPROVED_SPEC_SHA256,
    ARCHIVE_SELF_TEST_COMMAND,
    ASSEMBLER_SELF_TEST_COMMAND,
    BOUNDARY_TEST_COMMAND,
    BUILD_JCODE_COMMAND,
    CLONE_CREATION_PROGRAM,
    CLONE_VERIFICATION_PROGRAM,
    COMMITTED_RANGE_DIFF_CHECK_COMMAND,
    DEPENDENCY_BOUNDARIES_COMMAND,
    DEMO_SIGKILL_HOLD_COMMAND,
    FROZEN_IMPLEMENTATION_START,
    FULL_WORKSPACE_TEST_COMMAND,
    GIT_DIFF_CHECK_COMMAND,
    INFORMATIONAL_WARNINGS_HOLD_ID,
    PROPOSED_EXCEPTIONS_HOLD_ID,
    RELEASE_DIFF_GUARDRAIL_COMMAND,
    RELEASE_HYGIENE_COMMAND,
    REQUIRED_ADVERSARIAL_CASES,
    REQUIRED_ADDITIONAL_COMMANDS,
    REQUIRED_SECTION9_COMMANDS,
    REQUIRED_VERSION_COMMANDS,
    RUNTIME_COMMAND,
    RUNTIME_HARNESS_SELF_TEST_COMMAND,
    SECURITY_EXCEPTION_BINDING_SELF_TEST_COMMAND,
    THIRD_PARTY_INVENTORY_COMMAND,
    TOOLCHAIN_COMMAND,
    WORKSPACE_METADATA_COMMAND,
    atomic_write,
    commit_file,
    product_version,
    sha256_file,
)
from verify_source_archive import VerificationError, git, verify_archive
from lib.builder_clone_provenance import (
    ProvenanceError,
    read_marker as read_clone_marker,
)


VERSION_TEXT_COMMAND = (
    "cargo run --locked -q -p omnis-key-cli --bin omnis-key -- --version"
)
VERSION_JSON_COMMAND = (
    "cargo run --locked -q -p omnis-key-cli --bin omnis-key -- version --json"
)
SECURITY_PREFLIGHT_PROGRAM = "scripts/security_preflight.sh"
SECURITY_FAULT_PROGRAM = "tests/security/verify_preflight_faults.sh"
SECURITY_BASE_COMMIT = "a3a24cdb3aee97ebb43fe84e79bfa63828f3a39a"
SECURITY_ADVISORY_DB_COMMIT = "7003e463338e95aae16b7d97f5712e72a0771d6e"
SECURITY_IDENTITY_POLICY = "host-targeted-exact-sha256-before-execution"
SECURITY_PLATFORM_IDENTITIES: dict[str, dict[str, str]] = {
    "linux": {
        "os": "linux",
        "architecture": "arm64",
        "gitleaksSha256": (
            "4a0dd276c419a59f9b1f7b5ba0d6061466cad15698b2f545b648885f526c8c15"
        ),
        "cargoAuditSha256": (
            "abfee14de536fec79a8654b171273f2bf0f776aaf65577bf6e59c3ecd5b2e222"
        ),
        "cargoDenySha256": (
            "7e10bd91fe9836ee31be480b59ac96f88c58ccda3ad724da4d2b2cb94039b6bf"
        ),
        "sha256Tool": "sha256sum (/usr/bin/sha256sum)",
    },
    "macos": {
        "os": "darwin",
        "architecture": "arm64",
        "gitleaksSha256": (
            "006505fce427cd3b273ddfdb9ca374001bad5b621fe6efd06ac267c4502ffe14"
        ),
        "cargoAuditSha256": (
            "f8117c03d0e849f41db4b3efbc967990f6153c559b259f90d567b1a65cebaf0b"
        ),
        "cargoDenySha256": (
            "6a32f679ecaaeac354357681ec5814235dcd500e679b50c130c2b61180e79f1f"
        ),
        "sha256Tool": "shasum (/usr/bin/shasum)",
    },
}
SECURITY_PROPOSED_EXCEPTIONS: list[dict[str, str]] = []
SECURITY_PROPOSED_EXCEPTION_IDS = {
    exception["id"] for exception in SECURITY_PROPOSED_EXCEPTIONS
}
SECURITY_REPORT_COMMANDS = [
    "gitleaks dir <release-tree>",
    "gitleaks dir <exact-archive>",
    "gitleaks git <repo> --log-opts=<base>..<candidate>",
    "gitleaks git <repo> --log-opts=--all",
    "scripts/materialize_git_objects.py <reachable-object-index>",
    "gitleaks dir <materialized-reachable-git-objects>",
    "gitleaks dir <publication-metadata>",
    "cargo-audit audit --no-fetch --db <pinned-db> --json",
    "scripts/validate_advisory_exception_findings.py <exceptions> <unsuppressed-audit>",
    "cargo-audit audit --no-fetch --db <pinned-db> --json <proposed-ignores>",
    "cargo-deny --config config/security/deny.toml check licenses",
    "scripts/check_third_party_inventory.sh",
    "scripts/check_workspace_metadata.sh",
    "scripts/check_release_hygiene.sh",
    "scripts/verify_source_archive.py",
]
SECURITY_NAMED_SCANS = {
    "release_tree",
    "exact_archive",
    "jourdanlabs_commit_range",
    "reachable_git_history",
    "reachable_git_objects",
    "git_publication_metadata",
}

KNOWN_EXACT_COMMANDS = (
    REQUIRED_SECTION9_COMMANDS
    | REQUIRED_ADDITIONAL_COMMANDS
)

MANDATORY_HOLDS: dict[str, tuple[str, str]] = {
    "HOLD-DEMO-SIGKILL-RECLAMATION-CAPABILITY": (
        "The frozen one-root and zero-access boundaries provide no "
        "authenticated capability for distinguishing a SIGKILL remnant from "
        "a plausible same-UID preplant on the next run.",
        "Captain/specification-amendment-and-independent-review",
    ),
    "HOSTED_CI_NOT_RUN_CAPTAIN_CONTROLLED": (
        "Hosted workflows on the exact candidate have not been run because "
        "push and hosted execution remain Captain-controlled external actions.",
        "Captain",
    ),
    "GITHUB_GENERATED_TAG_ARCHIVE_NOT_AVAILABLE": (
        "The exact GitHub-generated archive for a published tag does not "
        "exist; a local review archive cannot satisfy that hosted condition.",
        "Captain",
    ),
    "SIGNED_RC_AND_AUTHENTICATED_MANIFEST_NOT_CREATED_CAPTAIN_CONTROLLED": (
        "No signed RC tag or separately authenticated manifest has been "
        "created; those promotion actions remain Captain-controlled.",
        "Captain",
    ),
    "HOSTED_SETTINGS_RECEIPT_NOT_CAPTURED_CAPTAIN_CONTROLLED": (
        "No hosted repository-settings receipt has been captured because the "
        "builder performed no hosted mutation.",
        "Captain",
    ),
    "INDEPENDENT_COLD_GATES_PENDING": (
        "The exact builder candidate still requires independent cold gates; "
        "this builder-only index is not a gate verdict.",
        "independent-review",
    ),
}

FIXED_CASE_HOLDS = {
    "offline_fixture_demo": "HOLD-DEMO-SIGKILL-RECLAMATION-CAPABILITY",
    "triggered_workflows": "HOSTED_CI_NOT_RUN_CAPTAIN_CONTROLLED",
    "source_archive_fresh_build_under_50mib": (
        "GITHUB_GENERATED_TAG_ARCHIVE_NOT_AVAILABLE"
    ),
}

_CANONICAL_HELP_AND_VERSION_CASES = [
    ("omnis-help", ["--help"], "help"),
    ("omnis-help-short", ["-h"], "help"),
    ("omnis-version", ["--version"], "omnis-version-text"),
    ("omnis-version-short", ["-V"], "omnis-version-text"),
    ("omnis-version-command", ["version"], "omnis-version-text"),
    ("omnis-version-json", ["version", "--json"], "version-json"),
    ("omnis-version-help", ["version", "--help"], "help"),
    ("omnis-receipts-help", ["receipts", "--help"], "help"),
    ("omnis-receipts-status-help", ["receipts", "status", "--help"], "help"),
    ("omnis-receipts-verify-help", ["receipts", "verify", "--help"], "help"),
    ("omnis-receipts-record-help", ["receipts", "record", "--help"], "help"),
    (
        "omnis-receipts-reconcile-help",
        ["receipts", "reconcile-safety", "--help"],
        "help",
    ),
    ("omnis-checkpoint-help", ["checkpoint", "--help"], "help"),
    ("omnis-checkpoint-anchor-help", ["checkpoint", "anchor", "--help"], "help"),
    (
        "omnis-checkpoint-verify-help",
        ["checkpoint", "verify-anchored", "--help"],
        "help",
    ),
    ("omnis-demo-help", ["demo", "--help"], "help"),
    ("omnis-demo-integrity-help", ["demo", "integrity", "--help"], "help"),
]

_COMPATIBILITY_HELP_AND_VERSION_CASES = [
    ("jcode-help", ["--help"], "help"),
    ("jcode-help-short", ["-h"], "help"),
    ("jcode-version", ["--version"], "jcode-version-text"),
    ("jcode-version-short", ["-V"], "jcode-version-text"),
    ("jcode-setup-hotkey-help", ["setup-hotkey", "--help"], "help"),
    ("jcode-setup-launcher-help", ["setup-launcher", "--help"], "help"),
    ("jcode-browser-help", ["browser", "--help"], "help"),
    ("jcode-omnis-help", ["omnis", "--help"], "help"),
    ("jcode-omnis-receipts-help", ["omnis", "receipts", "--help"], "help"),
    (
        "jcode-omnis-receipts-status-help",
        ["omnis", "receipts", "status", "--help"],
        "help",
    ),
    (
        "jcode-omnis-receipts-verify-help",
        ["omnis", "receipts", "verify", "--help"],
        "help",
    ),
    (
        "jcode-omnis-receipts-record-help",
        ["omnis", "receipts", "record", "--help"],
        "help",
    ),
    (
        "jcode-omnis-receipts-reconcile-help",
        ["omnis", "receipts", "reconcile-safety", "--help"],
        "help",
    ),
    ("jcode-omnis-checkpoint-help", ["omnis", "checkpoint", "--help"], "help"),
    (
        "jcode-omnis-checkpoint-anchor-help",
        ["omnis", "checkpoint", "anchor", "--help"],
        "help",
    ),
    (
        "jcode-omnis-checkpoint-verify-help",
        ["omnis", "checkpoint", "verify-anchored", "--help"],
        "help",
    ),
    ("jcode-omnis-demo-help", ["omnis", "demo", "--help"], "help"),
    (
        "jcode-omnis-demo-integrity-help",
        ["omnis", "demo", "integrity", "--help"],
        "help",
    ),
    ("jcode-omnis-version-command", ["omnis", "version"], "omnis-version-text"),
    ("jcode-omnis-version-json", ["omnis", "version", "--json"], "version-json"),
    ("jcode-omnis-version-help", ["omnis", "version", "--help"], "help"),
]

RUNTIME_CASE_CONTRACTS: dict[str, dict[str, object]] = {}
for _name, _arguments, _output_kind in _CANONICAL_HELP_AND_VERSION_CASES:
    RUNTIME_CASE_CONTRACTS[_name] = {
        "argv": ["omnis-key", *_arguments],
        "exitCode": 0,
        "outputKind": _output_kind,
        "writeManifest": [],
    }
for _name, _arguments, _output_kind in _COMPATIBILITY_HELP_AND_VERSION_CASES:
    RUNTIME_CASE_CONTRACTS[_name] = {
        "argv": ["jcode", *_arguments],
        "exitCode": 0,
        "outputKind": _output_kind,
        "writeManifest": [],
    }

for _name, _binary, _arguments in [
    ("omnis-parse-error", "omnis-key", ["not-a-command"]),
    ("omnis-non-utf8-parse-error", "omnis-key", ["<NON_UTF8:ff>"]),
    ("omnis-receipts-parse-error", "omnis-key", ["receipts", "not-a-command"]),
    ("omnis-record-missing-input", "omnis-key", ["receipts", "record"]),
    ("omnis-checkpoint-parse-error", "omnis-key", ["checkpoint", "not-a-command"]),
    ("omnis-demo-parse-error", "omnis-key", ["demo", "not-a-command"]),
    ("jcode-parse-error", "jcode", ["not-a-command"]),
    ("jcode-non-utf8-parse-error", "jcode", ["<NON_UTF8:ff>"]),
    ("jcode-omnis-parse-error", "jcode", ["omnis", "not-a-command"]),
    (
        "jcode-omnis-receipts-parse-error",
        "jcode",
        ["omnis", "receipts", "not-a-command"],
    ),
    (
        "jcode-omnis-record-missing-input",
        "jcode",
        ["omnis", "receipts", "record"],
    ),
    (
        "jcode-omnis-checkpoint-parse-error",
        "jcode",
        ["omnis", "checkpoint", "not-a-command"],
    ),
    (
        "jcode-omnis-demo-parse-error",
        "jcode",
        ["omnis", "demo", "not-a-command"],
    ),
    (
        "jcode-legacy-ledger-refusal",
        "jcode",
        ["omnis", "status", "--ledger", "<ABSOLUTE_PATH_REDACTED>"],
    ),
]:
    RUNTIME_CASE_CONTRACTS[_name] = {
        "argv": [_binary, *_arguments],
        "exitCode": 2,
        "outputKind": "parser-error",
        "writeManifest": [],
    }

_JSON_READ_ONLY_CASES = [
    (
        "omnis-empty-status",
        ["omnis-key", "receipts", "status", "--json"],
        3,
        "receipts.status",
        {"EMPTY_NOT_YET_EVIDENCED"},
    ),
    (
        "omnis-empty-verify",
        ["omnis-key", "receipts", "verify", "--json"],
        3,
        "receipts.verify",
        {"EMPTY_NOT_YET_EVIDENCED"},
    ),
    (
        "omnis-checkpoint-anchor",
        [
            "omnis-key",
            "checkpoint",
            "anchor",
            "--request-id",
            "fixture:anchor/one",
            "--json",
        ],
        4,
        "checkpoint.anchor",
        {"CHECKPOINT_AUTHORITY_UNAVAILABLE"},
    ),
    (
        "omnis-checkpoint-verify",
        ["omnis-key", "checkpoint", "verify-anchored", "--json"],
        4,
        "checkpoint.verify-anchored",
        {"CHECKPOINT_AUTHORITY_UNAVAILABLE"},
    ),
    (
        "omnis-malformed-event-id",
        [
            "omnis-key",
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
        2,
        "receipts.record",
        {"INVALID_RECEIPT_INPUT"},
    ),
    (
        "omnis-malformed-checkpoint-request-id",
        [
            "omnis-key",
            "checkpoint",
            "anchor",
            "--request-id",
            "bad id",
            "--json",
        ],
        3,
        "checkpoint.anchor",
        {"CHECKPOINT_REFUSED"},
    ),
    (
        "jcode-global-omnis-status",
        ["jcode", "--quiet", "omnis", "receipts", "status", "--json"],
        3,
        "receipts.status",
        {"EMPTY_NOT_YET_EVIDENCED"},
    ),
    (
        "jcode-checkpoint-anchor",
        [
            "jcode",
            "omnis",
            "checkpoint",
            "anchor",
            "--request-id",
            "fixture:anchor/two",
            "--json",
        ],
        4,
        "checkpoint.anchor",
        {"CHECKPOINT_AUTHORITY_UNAVAILABLE"},
    ),
    (
        "jcode-checkpoint-verify",
        ["jcode", "omnis", "checkpoint", "verify-anchored", "--json"],
        4,
        "checkpoint.verify-anchored",
        {"CHECKPOINT_AUTHORITY_UNAVAILABLE"},
    ),
    (
        "jcode-malformed-event-id",
        [
            "jcode",
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
        2,
        "receipts.record",
        {"INVALID_RECEIPT_INPUT"},
    ),
    (
        "jcode-malformed-checkpoint-request-id",
        [
            "jcode",
            "omnis",
            "checkpoint",
            "anchor",
            "--request-id",
            "bad id",
            "--json",
        ],
        3,
        "checkpoint.anchor",
        {"CHECKPOINT_REFUSED"},
    ),
]
for _name, _argv, _exit_code, _command, _codes in _JSON_READ_ONLY_CASES:
    RUNTIME_CASE_CONTRACTS[_name] = {
        "argv": _argv,
        "exitCode": _exit_code,
        "outputKind": "json",
        "jsonCommand": _command,
        "jsonCodes": _codes,
        "writeManifest": [],
    }

RUNTIME_CASE_CONTRACTS["jcode-inherited-updater-refusal"] = {
    "argv": ["jcode", "update"],
    "exitCode": 1,
    "outputKind": "disabled-surface",
    "disabledSurface": "update",
    "writeManifest": [],
}
for _name, _arguments in [
    ("jcode-inherited-setup-hotkey-refusal", ["setup-hotkey"]),
    ("jcode-inherited-setup-launcher-refusal", ["setup-launcher"]),
    ("jcode-inherited-browser-refusal", ["browser"]),
]:
    RUNTIME_CASE_CONTRACTS[_name] = {
        "argv": ["jcode", *_arguments],
        "exitCode": 1,
        "outputKind": "disabled-surface",
        "disabledSurface": "installer",
        "writeManifest": [],
    }
RUNTIME_CASE_CONTRACTS["jcode-inherited-pairing-refusal"] = {
    "argv": ["jcode", "pair"],
    "exitCode": 1,
    "outputKind": "disabled-surface",
    "disabledSurface": "pairing",
    "writeManifest": [],
}
RUNTIME_CASE_CONTRACTS["jcode-inherited-pairing-help-refusal"] = {
    "argv": ["jcode", "pair", "--help"],
    "exitCode": 2,
    "outputKind": "parser-error",
    "writeManifest": [],
}

_RECEIPT_WRITE_MANIFEST = [
    "JCODE_HOME:state",
    "JCODE_HOME:state/omnis-key",
    "JCODE_HOME:state/omnis-key/receipts.jsonl",
    "JCODE_HOME:state/omnis-key/receipts.jsonl.lock",
]
_SAFETY_WRITE_MANIFEST = [
    "JCODE_HOME:safety",
    "JCODE_HOME:safety/state.v1.initialized",
    "JCODE_HOME:safety/state.v1.json",
    "JCODE_HOME:safety/state.v1.lock",
]
for _prefix, _binary, _arguments in [
    ("omnis", "omnis-key", ["receipts"]),
    ("jcode", "jcode", ["omnis", "receipts"]),
]:
    _record_argv = [
        _binary,
        *_arguments,
        "record",
        "--event-id",
        "fixture:event/one",
        "test",
        "synthetic-subject",
        "--evidence-sha256",
        "a" * 64,
        "--json",
    ]
    for _suffix, _argv, _command, _codes, _writes in [
        ("first", _record_argv, "receipts.record", {"RECEIPT_APPENDED"}, _RECEIPT_WRITE_MANIFEST),
        ("replay", _record_argv, "receipts.record", {"RECEIPT_EXISTING"}, []),
        (
            "status",
            [_binary, *_arguments, "status", "--json"],
            "receipts.status",
            {"RECEIPT_CHAIN_VALID"},
            [],
        ),
        (
            "verify",
            [_binary, *_arguments, "verify", "--json"],
            "receipts.verify",
            {"RECEIPT_CHAIN_VALID"},
            [],
        ),
    ]:
        RUNTIME_CASE_CONTRACTS[f"{_prefix}-record-{_suffix}"] = {
            "argv": _argv,
            "exitCode": 0,
            "outputKind": "json",
            "jsonCommand": _command,
            "jsonCodes": _codes,
            "writeManifest": list(_writes),
        }

for _prefix, _binary, _arguments in [
    ("omnis", "omnis-key", ["receipts", "reconcile-safety", "--json"]),
    ("jcode", "jcode", ["omnis", "receipts", "reconcile-safety", "--json"]),
]:
    for _suffix, _writes in [
        ("first", _SAFETY_WRITE_MANIFEST),
        ("replay", []),
    ]:
        RUNTIME_CASE_CONTRACTS[f"{_prefix}-reconcile-{_suffix}"] = {
            "argv": [_binary, *_arguments],
            "exitCode": 0,
            "outputKind": "json",
            "jsonCommand": "receipts.reconcile-safety",
            "jsonCodes": {"SAFETY_RECONCILED", "SAFETY_ALREADY_RECONCILED"},
            "writeManifest": list(_writes),
        }

for _name, _argv in [
    ("omnis-demo", ["omnis-key", "demo", "integrity", "--json"]),
    ("jcode-demo", ["jcode", "omnis", "demo", "integrity", "--json"]),
]:
    RUNTIME_CASE_CONTRACTS[_name] = {
        "argv": _argv,
        "exitCode": 0,
        "outputKind": "demo-json",
        "writeManifest": ["private fixture root created and removed"],
    }
for _name, _binary in [
    ("jcode-pty-no-argument", "jcode"),
    ("omnis-pty-no-argument", "omnis-key"),
]:
    RUNTIME_CASE_CONTRACTS[_name] = {
        "argv": [_binary],
        "exitCode": 0,
        "outputKind": "pty",
    }

EXPECTED_RUNTIME_CASES = set(RUNTIME_CASE_CONTRACTS)

POSITIVE_CONTROL_EVENTS = {
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
    "AF_UNIX",
    "CONNECT_AF_UNIX",
    "BIND_AF_UNIX",
    "OPERATOR",
}
POSITIVE_CONTROL_MUTATIONS = {
    "chmod",
    "chown",
    "fchmod",
    "fchown",
    "lchown",
    "open-write",
    "setxattr",
    "unlink",
    "utimes",
}
RUNTIME_TRACE_EVENT_SCHEMA = "EV1"
RUNTIME_MUTATING_FILESYSTEM_OPERATIONS = {
    "chmod",
    "chown",
    "fchmod",
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
    "open-write",
}


def load_credential_environment_inventory() -> set[str]:
    source = (
        Path(__file__).resolve().parents[1]
        / "tests"
        / "sovereignty"
        / "credential_environment_names.h"
    )
    try:
        text = source.read_text(encoding="utf-8")
    except OSError as error:
        raise VerificationError(
            f"credential environment inventory is unreadable: {source}: {error}"
        ) from error
    names = set(re.findall(r'X\("([A-Z][A-Z0-9_]*)"\)', text))
    if len(names) < 50:
        raise VerificationError(
            "credential environment inventory is unexpectedly incomplete"
        )
    return names


CREDENTIAL_ENVIRONMENT = load_credential_environment_inventory()

PLATFORM_SYSTEM = {"linux": "Linux", "macos": "Darwin"}
TRUSTED_TOOLCHAIN_FORMAT = "absolute-executables-v1"
TRUSTED_TOOL_NAMES = (
    "bash",
    "cargo",
    "cargo-clippy",
    "cargo-fmt",
    "cc",
    "clippy-driver",
    "git",
    "python3",
    "rustc",
    "rustfmt",
    "uname",
)
TRUSTED_SUPPLEMENTAL_TOOL_NAMES = (
    "cargo-audit",
    "cargo-deny",
    "gitleaks",
    "go",
)
PROHIBITED_PLAN_KEYS = {
    "authenticated",
    "builderissuedclear",
    "clear",
    "clearissued",
    "independentgate",
    "verdict",
    "verdictissued",
}


@dataclass(frozen=True)
class RawReceipt:
    receipt_id: str
    platform: str
    candidate_commit: str
    candidate_tree: str
    command: str
    started_utc: str
    finished_utc: str
    exit_status: int
    output: str
    path: Path
    relative_path: str
    sha256: str
    trusted_toolchain_format: str = ""
    trusted_toolchain_fingerprint_sha256: str = ""
    trusted_supplemental_tool_path: str = ""
    trusted_tools: dict[str, dict[str, str]] = field(default_factory=dict)
    trusted_supplemental_tools: dict[str, dict[str, str]] = field(
        default_factory=dict
    )

    def index_entry(self) -> dict[str, object]:
        return {
            "id": self.receipt_id,
            "platform": self.platform,
            "command": self.command,
            "status": "PASS",
            "exitStatus": self.exit_status,
            "startedUtc": self.started_utc,
            "finishedUtc": self.finished_utc,
            "trustedToolchainFingerprintSha256": (
                self.trusted_toolchain_fingerprint_sha256
            ),
            "evidence": {
                "path": self.relative_path,
                "sha256": self.sha256,
            },
        }


@dataclass(frozen=True)
class ProofGroup:
    command: str | None
    markers: tuple[str, ...]
    predicate: Callable[[RawReceipt], bool] | None = None

    def matches(self, receipt: RawReceipt) -> bool:
        command_matches = (
            receipt.command == self.command
            if self.command is not None
            else self.predicate is not None and self.predicate(receipt)
        )
        if not command_matches:
            return False
        if self.command is not None and self.command.startswith("cargo test "):
            return all(
                cargo_test_marker_passed(receipt.output, marker)
                for marker in self.markers
            )
        return all(marker in receipt.output for marker in self.markers)


def cargo_test_marker_passed(output: str, marker: str) -> bool:
    statuses: list[str] = []
    for line in output.splitlines():
        match = re.fullmatch(
            r"test ([^\s]+) \.\.\. (ok|FAILED|ignored(?:,.*)?)",
            line,
        )
        if match is None:
            continue
        qualified_name = match.group(1)
        if qualified_name == marker or qualified_name.endswith(f"::{marker}"):
            statuses.append(match.group(2))
    return bool(statuses) and all(status == "ok" for status in statuses)


def cli_group(*markers: str) -> ProofGroup:
    return ProofGroup("cargo test -p omnis-key-cli", tuple(markers))


def base_omnis_group(*markers: str) -> ProofGroup:
    return ProofGroup("cargo test -p jcode-base omnis::tests", tuple(markers))


def safety_adversarial_group(*markers: str) -> ProofGroup:
    return ProofGroup(
        "cargo test -p jcode-base safety::adversarial_tests", tuple(markers)
    )


CASE_GROUPS: dict[str, tuple[ProofGroup, ...]] = {
    "offline_fixture_demo": (
        cli_group(
            "demo_json_is_exact_and_host_identifier_free",
            "preplanted_matching_root_is_preserved_byte_for_byte",
        ),
    ),
    "exact_replay": (
        cli_group("record_replay_verify_and_conflict_follow_the_frozen_contract"),
        base_omnis_group("idempotent_append_replays_exactly_and_refuses_drift"),
    ),
    "mutated_receipt": (
        base_omnis_group("rejects_partial_tail_and_tampered_hash"),
    ),
    "partial_and_mid_record_truncation_refusal": (
        base_omnis_group(
            "partial_byte_and_mid_record_truncation_are_refused_without_reseed"
        ),
    ),
    "valid_prefix_rollback_ceiling": (
        base_omnis_group(
            "valid_prefix_tail_removal_remains_locally_undetected_without_checkpoint"
        ),
    ),
    "reordered_receipt_refusal": (
        base_omnis_group("reordered_receipts_are_refused"),
    ),
    "orphaned_safety_receipt_refusal": (
        safety_adversarial_group(
            "deleting_acknowledged_history_leaves_a_refused_orphan_receipt"
        ),
    ),
    "decision_receipt_mismatch_refusal": (
        safety_adversarial_group(
            "mutated_outbox_binding_is_refused_before_receipt_append",
            "dropping_a_committed_decisions_outbox_is_refused",
        ),
    ),
    "receipt_write_failure_reconciliation": (
        safety_adversarial_group(
            "receipt_failure_leaves_outbox_and_restart_reconciles_once"
        ),
    ),
    "canonical_boundary_refusals": (
        cli_group(
            "public_parser_rejects_path_and_claim_overrides_without_writes",
            "unsafe_ledger_and_parent_modes_are_refused_without_repair",
            "symlinked_canonical_ledger_is_refused_without_touching_target",
        ),
        ProofGroup(
            BOUNDARY_TEST_COMMAND,
            (
                "concrete_wrong_owned_ledger_is_refused_without_mutation",
                "concrete_extended_acl_is_refused",
            ),
        ),
    ),
    "exact_allowed_write_snapshots": (
        cli_group(
            "read_only_and_demo_commands_preserve_every_controlled_root",
            "canonical_record_writes_only_private_receipt_files_and_ignores_runtime_override",
            "safety_reconciliation_writes_only_its_named_private_state",
        ),
    ),
    "hostile_environment_demo_fixture_preservation": (
        cli_group("preplanted_matching_root_is_preserved_byte_for_byte"),
    ),
    "credential_free_pty_all_advertised_executables": (
        cli_group("no_argument_pty_handoff_uses_only_an_exact_sibling_fixture"),
    ),
    "updater_replacement_refusal": (
        ProofGroup(
            "cargo test -p jcode --lib cli::startup::tests",
            (
                "auto_install_is_disabled_without_live_terminal",
                "auto_install_is_disabled_with_live_terminal_attached",
                "every_omnis_command_takes_the_isolated_no_update_path",
            ),
        ),
    ),
    "empty_chain_not_yet_evidenced": (
        cli_group("empty_chain_is_a_refusal_with_the_exact_shape"),
    ),
    "public_output_redaction": (
        cli_group("demo_json_is_exact_and_host_identifier_free"),
    ),
    "checkpoint_activation_refusal": (
        cli_group(
            "inactive_checkpoint_refuses_with_exit_four_and_one_json_object"
        ),
    ),
    "third_party_inventory": (
        ProofGroup(
            THIRD_PARTY_INVENTORY_COMMAND,
            ("third-party inventory verified:", "unknown_rights=0"),
        ),
    ),
    "workspace_metadata_lockout": (
        ProofGroup(
            WORKSPACE_METADATA_COMMAND,
            (
                "workspace metadata verified:",
                "publishable=0",
                "incomplete=0",
                "product_version=0.1.0",
            ),
        ),
    ),
    "security_preflight_fault_injection": (
        ProofGroup(
            None,
            ("PASS: security preflight failed closed for 11 injected faults",),
            predicate=lambda receipt: is_security_fault_command(receipt.command),
        ),
    ),
}

RUNTIME_REQUIRED_CASES = {
    "offline_fixture_demo",
    "exact_allowed_write_snapshots",
    "zero_attempt_network_omnis_and_jcode",
    "hostile_environment_demo_fixture_preservation",
    "credential_free_pty_all_advertised_executables",
    "updater_replacement_refusal",
    "empty_chain_not_yet_evidenced",
    "public_output_redaction",
    "checkpoint_activation_refusal",
}


def fail(message: str) -> None:
    raise VerificationError(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def absolute_without_following_leaf(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    return absolute.parent.resolve() / absolute.name


def parse_utc(value: str, label: str) -> datetime:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        fail(f"{label} is not canonical UTC: {value!r}")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise VerificationError(f"{label} is not a real UTC instant") from exc


def require_regular_private(path: Path, label: str) -> bytes:
    if path.absolute() != path.resolve() or path.is_symlink() or not path.is_file():
        fail(f"{label} must be a regular non-symlink file: {path}")
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode):
        fail(f"{label} is not a regular file: {path}")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        fail(f"{label} must not grant group or other access: {path}")
    return path.read_bytes()


def safe_relative_path(root: Path, value: object, label: str) -> tuple[Path, str]:
    if not isinstance(value, str) or not value:
        fail(f"{label} path is absent")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        fail(f"{label} path is unsafe: {value!r}")
    path = root.joinpath(*pure.parts)
    if path.absolute() != path.resolve():
        fail(f"{label} path traverses a symlink: {value!r}")
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError as exc:
        raise VerificationError(f"{label} escapes the packet root") from exc
    return path, relative


def parse_raw_receipt(
    path: Path,
    relative_path: str,
    expected_commit: str,
    expected_tree: str,
) -> RawReceipt:
    payload = require_regular_private(path, "raw command receipt")
    if len(payload) > 64 * 1024 * 1024:
        fail(f"raw command receipt exceeds 64 MiB: {relative_path}")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerificationError(
            f"raw command receipt is not UTF-8: {relative_path}"
        ) from exc
    if "\0" in text or "\r" in text or not text.endswith("\n"):
        fail(f"raw command receipt has non-canonical text framing: {relative_path}")

    output_marker = "\n--- command output ---\n"
    result_line = "--- receipt result ---\n"
    if text.count(output_marker) != 1:
        fail(f"raw command receipt has ambiguous framing markers: {relative_path}")
    header_text, remainder = text.split(output_marker, 1)
    if remainder.count(result_line) != 1:
        fail(f"raw command receipt has ambiguous framing markers: {relative_path}")
    if remainder.startswith(result_line):
        output = ""
        result_text = remainder[len(result_line) :]
    else:
        result_marker = "\n" + result_line
        if result_marker not in remainder:
            fail(f"raw command receipt result framing drifted: {relative_path}")
        output, result_text = remainder.split(result_marker, 1)
    header_lines = header_text.splitlines()
    expected_keys = [
        "schemaVersion",
        "receiptId",
        "platform",
        "candidateCommit",
        "candidateTree",
        "command",
        "startedUtc",
        "trustedToolchainFormat",
        "trustedToolchainFingerprintSha256",
        "trustedSupplementalToolPath",
    ]
    for tool_name in TRUSTED_TOOL_NAMES:
        expected_keys.extend(
            [
                f"trustedTool.{tool_name}.path",
                f"trustedTool.{tool_name}.sha256",
                f"trustedTool.{tool_name}.identity",
            ]
        )
    for tool_name in TRUSTED_SUPPLEMENTAL_TOOL_NAMES:
        expected_keys.extend(
            [
                f"trustedSupplementalTool.{tool_name}.path",
                f"trustedSupplementalTool.{tool_name}.sha256",
                f"trustedSupplementalTool.{tool_name}.identity",
            ]
        )
    if len(header_lines) != len(expected_keys):
        fail(f"raw command receipt header length drifted: {relative_path}")
    fields: dict[str, str] = {}
    for expected_key, line in zip(expected_keys, header_lines):
        key, separator, value = line.partition("=")
        if separator != "=" or key != expected_key:
            fail(f"raw command receipt header order drifted: {relative_path}")
        fields[key] = value
    if fields["schemaVersion"] != "2":
        fail(f"raw command receipt schema is unsupported: {relative_path}")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", fields["receiptId"]):
        fail(f"raw command receipt ID is unsafe: {relative_path}")
    if fields["platform"] not in PLATFORM_SYSTEM:
        fail(f"raw command receipt platform is unsupported: {relative_path}")
    if fields["candidateCommit"] != expected_commit:
        fail(f"raw receipt candidate mismatch: {relative_path}")
    if fields["candidateTree"] != expected_tree:
        fail(f"raw receipt tree mismatch: {relative_path}")
    if (
        not fields["command"]
        or "\n" in fields["command"]
        or any(ord(character) < 0x20 for character in fields["command"])
    ):
        fail(f"raw command receipt command is unsafe: {relative_path}")
    if fields["trustedToolchainFormat"] != TRUSTED_TOOLCHAIN_FORMAT:
        fail(f"raw command receipt toolchain format drifted: {relative_path}")
    supplemental_path = fields["trustedSupplementalToolPath"]
    if supplemental_path:
        supplemental_parts = supplemental_path.split(":")
        if (
            any(
                not part
                or not os.path.isabs(part)
                or "\0" in part
                or "\n" in part
                or "\r" in part
                for part in supplemental_parts
            )
            or len(set(supplemental_parts)) != len(supplemental_parts)
        ):
            fail(
                f"raw command receipt supplemental tool path is unsafe: "
                f"{relative_path}"
            )

    trusted_tools: dict[str, dict[str, str]] = {}
    fingerprint_lines = [
        f"trustedSupplementalToolPath={supplemental_path}\n"
    ]
    for tool_name in TRUSTED_TOOL_NAMES:
        path_value = fields[f"trustedTool.{tool_name}.path"]
        digest_value = fields[f"trustedTool.{tool_name}.sha256"]
        identity_value = fields[f"trustedTool.{tool_name}.identity"]
        if (
            not os.path.isabs(path_value)
            or "\0" in path_value
            or "\n" in path_value
            or "\r" in path_value
            or not re.fullmatch(r"[0-9a-f]{64}", digest_value)
            or not identity_value
            or any(ord(character) < 0x20 for character in identity_value)
        ):
            fail(
                f"raw command receipt trusted-tool identity is unsafe: "
                f"{relative_path}: {tool_name}"
            )
        trusted_tools[tool_name] = {
            "path": path_value,
            "sha256": digest_value,
            "identity": identity_value,
        }
        fingerprint_lines.extend(
            [
                f"trustedTool.{tool_name}.path={path_value}\n",
                f"trustedTool.{tool_name}.sha256={digest_value}\n",
                f"trustedTool.{tool_name}.identity={identity_value}\n",
            ]
        )
    trusted_supplemental_tools: dict[str, dict[str, str]] = {}
    for tool_name in TRUSTED_SUPPLEMENTAL_TOOL_NAMES:
        path_value = fields[f"trustedSupplementalTool.{tool_name}.path"]
        digest_value = fields[f"trustedSupplementalTool.{tool_name}.sha256"]
        identity_value = fields[f"trustedSupplementalTool.{tool_name}.identity"]
        fingerprint_lines.extend(
            [
                f"trustedSupplementalTool.{tool_name}.path={path_value}\n",
                f"trustedSupplementalTool.{tool_name}.sha256={digest_value}\n",
                f"trustedSupplementalTool.{tool_name}.identity={identity_value}\n",
            ]
        )
        if supplemental_path:
            if (
                not os.path.isabs(path_value)
                or str(Path(path_value).parent) not in supplemental_parts
                or Path(path_value).name != tool_name
                or not re.fullmatch(r"[0-9a-f]{64}", digest_value)
                or not identity_value
                or any(ord(character) < 0x20 for character in identity_value)
            ):
                fail(
                    f"raw command receipt supplemental-tool identity is unsafe: "
                    f"{relative_path}: {tool_name}"
                )
            trusted_supplemental_tools[tool_name] = {
                "path": path_value,
                "sha256": digest_value,
                "identity": identity_value,
            }
        elif path_value or digest_value or identity_value:
            fail(
                f"raw command receipt has tools without a supplemental path: "
                f"{relative_path}: {tool_name}"
            )
    expected_fingerprint = sha256_bytes("".join(fingerprint_lines).encode("utf-8"))
    fingerprint = fields["trustedToolchainFingerprintSha256"]
    if (
        not re.fullmatch(r"[0-9a-f]{64}", fingerprint)
        or fingerprint != expected_fingerprint
    ):
        fail(f"raw command receipt toolchain fingerprint disagrees: {relative_path}")

    result_match = re.fullmatch(
        r"exitStatus=(0|[1-9][0-9]{0,2})\n"
        r"finishedUtc=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\n",
        result_text,
    )
    if result_match is None:
        fail(f"raw command receipt result framing drifted: {relative_path}")
    started = parse_utc(fields["startedUtc"], f"{relative_path} startedUtc")
    finished = parse_utc(result_match.group(2), f"{relative_path} finishedUtc")
    if finished < started:
        fail(f"raw command receipt finishes before it starts: {relative_path}")
    exit_status = int(result_match.group(1))
    if exit_status != 0:
        fail(
            f"listed raw command receipt did not pass: "
            f"{fields['receiptId']} exit={exit_status}"
        )

    return RawReceipt(
        receipt_id=fields["receiptId"],
        platform=fields["platform"],
        candidate_commit=fields["candidateCommit"],
        candidate_tree=fields["candidateTree"],
        command=fields["command"],
        started_utc=fields["startedUtc"],
        finished_utc=result_match.group(2),
        exit_status=exit_status,
        output=output,
        path=path,
        relative_path=relative_path,
        sha256=sha256_bytes(payload),
        trusted_toolchain_format=fields["trustedToolchainFormat"],
        trusted_toolchain_fingerprint_sha256=fingerprint,
        trusted_supplemental_tool_path=supplemental_path,
        trusted_tools=trusted_tools,
        trusted_supplemental_tools=trusted_supplemental_tools,
    )


def parse_security_preflight_command(command: str) -> dict[str, str] | None:
    try:
        arguments = shlex.split(command, posix=True)
    except ValueError:
        return None
    if (
        len(arguments) != 7
        or arguments[0] != SECURITY_PREFLIGHT_PROGRAM
        or arguments[1] != "--archive"
        or arguments[3] != "--report"
        or arguments[5] != "--advisory-db"
    ):
        return None
    values = {
        "archive": arguments[2],
        "report": arguments[4],
        "advisoryDatabase": arguments[6],
    }
    if any(
        not value
        or not os.path.isabs(value)
        or "\0" in value
        or "\n" in value
        or "\r" in value
        for value in values.values()
    ):
        return None
    return values


def is_security_fault_command(command: str) -> bool:
    try:
        arguments = shlex.split(command, posix=True)
    except ValueError:
        return False
    if len(arguments) != 7 or arguments[0] != SECURITY_FAULT_PROGRAM:
        return False
    return (
        arguments[1] == "--archive"
        and arguments[3] == "--advisory-db"
        and arguments[5] == "--tools-dir"
        and all(
            value
            and "\0" not in value
            and "\n" not in value
            and "\r" not in value
            for value in (arguments[2], arguments[4], arguments[6])
        )
    )


def parse_clone_creation_command(command: str) -> dict[str, str] | None:
    try:
        arguments = shlex.split(command, posix=True)
    except ValueError:
        return None
    if (
        len(arguments) != 11
        or arguments[0] != CLONE_CREATION_PROGRAM
        or arguments[1] != "--platform"
        or arguments[2] not in PLATFORM_SYSTEM
        or arguments[3:7] != ["--source", ".", "--candidate", "HEAD"]
        or arguments[7] != "--destination"
        or arguments[9] != "--marker"
    ):
        return None
    destination = arguments[8]
    marker = arguments[10]
    if (
        not os.path.isabs(destination)
        or not os.path.isabs(marker)
        or destination == marker
        or any(
            not value
            or "\0" in value
            or "\n" in value
            or "\r" in value
            for value in (destination, marker)
        )
    ):
        return None
    return {
        "platform": arguments[2],
        "destination": destination,
        "marker": marker,
    }


def parse_clone_verification_command(command: str) -> dict[str, str] | None:
    try:
        arguments = shlex.split(command, posix=True)
    except ValueError:
        return None
    if (
        len(arguments) != 3
        or arguments[0] != CLONE_VERIFICATION_PROGRAM
        or arguments[1] != "--marker"
        or not os.path.isabs(arguments[2])
        or not arguments[2]
        or "\0" in arguments[2]
        or "\n" in arguments[2]
        or "\r" in arguments[2]
    ):
        return None
    return {"marker": arguments[2]}


def command_is_known(command: str) -> bool:
    return (
        command in KNOWN_EXACT_COMMANDS
        or parse_security_preflight_command(command) is not None
        or is_security_fault_command(command)
        or parse_clone_creation_command(command) is not None
        or parse_clone_verification_command(command) is not None
    )


def security_preflight_receipt_label(
    exception_count: int,
    warning_count: int,
) -> str:
    if exception_count > 0:
        return "HOLD_PENDING_INDEPENDENT_EXCEPTION_REVIEW"
    if warning_count > 0:
        return "HOLD_INFORMATIONAL_WARNINGS_PENDING_REMEDIATION"
    return "complete"


def validate_exact_command_semantics(receipt: RawReceipt) -> None:
    """Bind semantically meaningful output for exact builder-only checks."""

    if parse_security_preflight_command(receipt.command) is not None:
        labels = (
            "HOLD_PENDING_INDEPENDENT_EXCEPTION_REVIEW",
            "HOLD_INFORMATIONAL_WARNINGS_PENDING_REMEDIATION",
            "complete",
        )
        expected_identity = (
            f"commit={receipt.candidate_commit} "
            f"tree={receipt.candidate_tree} report_sha256="
        )
        output_matches = False
        for label in labels:
            prefix = f"security preflight {label}: {expected_identity}"
            if receipt.output.startswith(prefix) and re.fullmatch(
                r"[0-9a-f]{64}", receipt.output[len(prefix) :]
            ):
                output_matches = True
                break
        if not output_matches:
            fail(
                "security-preflight receipt output identity or digest framing "
                f"disagrees: {receipt.receipt_id}"
            )
        return

    if receipt.command in {
        GIT_DIFF_CHECK_COMMAND,
        COMMITTED_RANGE_DIFF_CHECK_COMMAND,
    }:
        if receipt.output != "":
            fail(f"git diff --check receipt is not silent: {receipt.receipt_id}")
        return

    if receipt.command == DEPENDENCY_BOUNDARIES_COMMAND:
        if receipt.output.splitlines()[-1:] != ["dependency boundary check passed"]:
            fail(
                "dependency-boundary receipt lacks its success marker: "
                f"{receipt.receipt_id}"
            )
        return

    if receipt.command in {
        ARCHIVE_SELF_TEST_COMMAND,
        ASSEMBLER_SELF_TEST_COMMAND,
        RUNTIME_HARNESS_SELF_TEST_COMMAND,
        SECURITY_EXCEPTION_BINDING_SELF_TEST_COMMAND,
    }:
        if (
            re.search(r"(?m)^Ran [1-9][0-9]* tests? in ", receipt.output) is None
            or receipt.output.splitlines()[-1:] != ["OK"]
        ):
            fail(
                "Python self-test receipt lacks its unittest completion proof: "
                f"{receipt.receipt_id}"
            )
        return

    if receipt.command == DEMO_SIGKILL_HOLD_COMMAND:
        expected = (
            "HOLD_REPRODUCED: "
            "HOLD-DEMO-SIGKILL-RECLAMATION-CAPABILITY "
            "killedRootPrivate=true nextRunReclaimed=false "
            "plausiblePreplantsPreserved=true"
        )
        if receipt.output != expected:
            fail(
                "demo SIGKILL HOLD receipt lacks its exact reproduction proof: "
                f"{receipt.receipt_id}"
            )
        return

    if receipt.command == FULL_WORKSPACE_TEST_COMMAND:
        if (
            "test result: ok." not in receipt.output
            or "test result: FAILED." in receipt.output
        ):
            fail(
                "full-workspace receipt lacks successful test output: "
                f"{receipt.receipt_id}"
            )
        return

    if receipt.command != RELEASE_DIFF_GUARDRAIL_COMMAND:
        return
    try:
        payload = json.loads(receipt.output)
    except json.JSONDecodeError as exc:
        raise VerificationError(
            f"release-diff guardrail receipt is not JSON: {receipt.receipt_id}"
        ) from exc
    if not isinstance(payload, dict):
        fail(f"release-diff guardrail receipt is malformed: {receipt.receipt_id}")
    base = payload.get("base")
    candidate = payload.get("candidate")
    warnings = payload.get("warnings")
    if (
        payload.get("schemaVersion") != 1
        or payload.get("status") != "PASS"
        or payload.get("specSha256") != APPROVED_SPEC_SHA256
        or payload.get("thresholdLoc") != 1200
        or payload.get("regressions") != []
        or not isinstance(base, dict)
        or base.get("commit") != FROZEN_IMPLEMENTATION_START
        or not isinstance(candidate, dict)
        or candidate.get("commit") != receipt.candidate_commit
        or candidate.get("tree") != receipt.candidate_tree
        or candidate.get("worktreeMode") is not False
        or not isinstance(warnings, dict)
        or warnings.get("checked") is not True
        or warnings.get("addedCount") != 0
    ):
        fail(
            "release-diff guardrail receipt identity or semantics disagree: "
            f"{receipt.receipt_id}"
        )


def trusted_toolchain_binding(receipt: RawReceipt) -> tuple[str, str, str, str]:
    if (
        receipt.trusted_toolchain_format != TRUSTED_TOOLCHAIN_FORMAT
        or not receipt.trusted_toolchain_fingerprint_sha256
        or set(receipt.trusted_tools) != set(TRUSTED_TOOL_NAMES)
        or (
            receipt.trusted_supplemental_tool_path != ""
            and set(receipt.trusted_supplemental_tools)
            != set(TRUSTED_SUPPLEMENTAL_TOOL_NAMES)
        )
        or (
            receipt.trusted_supplemental_tool_path == ""
            and receipt.trusted_supplemental_tools
        )
    ):
        fail(
            f"toolchain receipt lacks its trusted executable binding: "
            f"{receipt.receipt_id}"
        )
    return (
        receipt.trusted_toolchain_format,
        receipt.trusted_toolchain_fingerprint_sha256,
        receipt.trusted_supplemental_tool_path,
        json.dumps(
            {
                "core": receipt.trusted_tools,
                "supplemental": receipt.trusted_supplemental_tools,
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
    )


def validate_platform_toolchain_binding(
    receipts: Iterable[RawReceipt], platform: str
) -> tuple[str, str, str, str]:
    bindings = {trusted_toolchain_binding(receipt) for receipt in receipts}
    if len(bindings) != 1:
        fail(f"{platform} receipts do not share one trusted toolchain binding")
    return next(iter(bindings))


def parse_toolchain(receipt: RawReceipt) -> dict[str, str]:
    if receipt.command != TOOLCHAIN_COMMAND:
        fail(f"toolchain receipt uses a non-canonical command: {receipt.receipt_id}")
    trusted_toolchain_binding(receipt)
    lines = [line.strip() for line in receipt.output.splitlines() if line.strip()]
    if not lines or PLATFORM_SYSTEM[receipt.platform] not in lines[0]:
        fail(f"toolchain uname does not match {receipt.platform}: {receipt.receipt_id}")

    def one(pattern: str, label: str) -> str:
        matches = [
            match.group(1)
            for line in lines
            if (match := re.fullmatch(pattern, line)) is not None
        ]
        if len(matches) != 1 or not matches[0]:
            fail(f"toolchain {label} is absent or ambiguous: {receipt.receipt_id}")
        return matches[0]

    compiler_lines = [
        line
        for line in lines
        if re.match(
            r"^(?:Apple clang version|clang version|gcc |cc |[A-Za-z0-9_.+-]+-gcc )",
            line,
        )
    ]
    if not compiler_lines:
        fail(f"toolchain C compiler identity is absent: {receipt.receipt_id}")
    parsed = {
        "uname": lines[0],
        "rustcVersion": one(r"release: (.+)", "rustc release"),
        "rustcHost": one(r"host: (.+)", "rustc host"),
        "cargoVersion": one(r"cargo ([^ ]+)(?: .*)?", "Cargo version"),
        "gitVersion": one(r"git version (.+)", "Git version"),
        "pythonVersion": one(r"Python ([^ ]+)", "Python version"),
        "cCompiler": compiler_lines[0],
    }
    decoded_identities = {
        name: tool["identity"].replace("\\n", "\n")
        for name, tool in receipt.trusted_tools.items()
    }
    expected_identity_fragments = {
        "uname": parsed["uname"],
        "rustc": f"release: {parsed['rustcVersion']}",
        "cargo": f"cargo {parsed['cargoVersion']}",
        "git": f"git version {parsed['gitVersion']}",
        "python3": f"Python {parsed['pythonVersion']}",
        "cc": parsed["cCompiler"],
    }
    for tool_name, fragment in expected_identity_fragments.items():
        if fragment not in decoded_identities[tool_name]:
            fail(
                f"toolchain command output disagrees with trusted {tool_name} "
                f"identity: {receipt.receipt_id}"
            )
    return parsed


def parse_root_package_version(manifest: bytes) -> str:
    text = manifest.decode("utf-8")
    package = re.search(r"(?ms)^\[package\]\s*(.*?)(?=^\[|\Z)", text)
    if package is None:
        fail("root Cargo.toml has no [package] section")
    matches = re.findall(
        r'(?m)^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$',
        package.group(1),
    )
    if len(matches) != 1:
        fail("root compatibility package version is ambiguous")
    return matches[0]


def validate_version_receipts(
    receipts_by_platform: dict[str, list[RawReceipt]],
    passed_platforms: set[str],
    version: str,
    compatibility_version: str,
) -> list[str]:
    expected_text = (
        f"omnis-key {version}\n"
        f"jcode compatibility base {compatibility_version}"
    )
    expected_json = {
        "schemaVersion": 1,
        "command": "version",
        "ok": True,
        "code": "VERSION",
        "data": {
            "productVersion": version,
            "compatibilityBaseName": "jcode",
            "compatibilityBaseVersion": compatibility_version,
        },
    }
    identifiers: list[str] = []
    for platform in sorted(passed_platforms):
        platform_receipts = receipts_by_platform[platform]
        text_receipts = [
            receipt
            for receipt in platform_receipts
            if receipt.command == VERSION_TEXT_COMMAND
        ]
        json_receipts = [
            receipt
            for receipt in platform_receipts
            if receipt.command == VERSION_JSON_COMMAND
        ]
        if len(text_receipts) != 1 or len(json_receipts) != 1:
            fail(f"{platform} does not have exactly one receipt per version command")
        if text_receipts[0].output != expected_text:
            fail(f"{platform} text version output is not exact")
        try:
            parsed = json.loads(json_receipts[0].output)
        except json.JSONDecodeError as exc:
            raise VerificationError(
                f"{platform} JSON version output is invalid"
            ) from exc
        exact_json_outputs = {
            json.dumps(
                expected_json,
                sort_keys=sort_keys,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            for sort_keys in (False, True)
        }
        if parsed != expected_json or json_receipts[0].output not in exact_json_outputs:
            fail(f"{platform} JSON version envelope is not exact")
        identifiers.extend(
            [text_receipts[0].receipt_id, json_receipts[0].receipt_id]
        )
    return identifiers


def validate_runtime_instrumentation(
    instrumentation: object,
    platform_name: str,
    case_name: str,
    *,
    pty: bool,
) -> None:
    if not isinstance(instrumentation, dict) or set(instrumentation) != {
        "networkEvents",
        "unixSocketEvents",
        "credentialEnvironmentAccesses",
        "operatorAccessDetected",
        "instrumentedProcessCount",
        "processStartCount",
        "executionAttemptCount",
        "unixSocketAttemptCount",
        "filesystemCallCount",
        "filesystemOperations",
        "filesystemPathClasses",
        "traceEventSchema",
        "traceEventCount",
        "traceSha256",
    }:
        fail(f"{platform_name} runtime instrumentation schema drifted: {case_name}")
    unix_events = instrumentation["unixSocketEvents"]
    if (
        instrumentation["networkEvents"] != []
        or instrumentation["credentialEnvironmentAccesses"] != []
        or instrumentation["operatorAccessDetected"] is not False
        or not isinstance(unix_events, list)
        or any(
            event not in {"AF_UNIX", "BIND_AF_UNIX", "CONNECT_AF_UNIX"}
            for event in unix_events
        )
        or unix_events != sorted(set(unix_events))
    ):
        fail(f"{platform_name} runtime case has forbidden attempts: {case_name}")
    if pty:
        if set(unix_events) != {"AF_UNIX", "BIND_AF_UNIX", "CONNECT_AF_UNIX"}:
            fail(f"{platform_name} PTY did not bind its exact local transport: {case_name}")
    elif unix_events:
        fail(f"{platform_name} non-PTY case attempted a local socket: {case_name}")

    instrumented_process_count = instrumentation["instrumentedProcessCount"]
    process_start_count = instrumentation["processStartCount"]
    execution_attempt_count = instrumentation["executionAttemptCount"]
    unix_socket_attempt_count = instrumentation["unixSocketAttemptCount"]
    call_count = instrumentation["filesystemCallCount"]
    operations = instrumentation["filesystemOperations"]
    path_classes = instrumentation["filesystemPathClasses"]
    trace_event_count = instrumentation["traceEventCount"]
    integer_counts = (
        instrumented_process_count,
        process_start_count,
        execution_attempt_count,
        unix_socket_attempt_count,
        call_count,
        trace_event_count,
    )
    if (
        any(
            not isinstance(count, int) or isinstance(count, bool) or count < 0
            for count in integer_counts
        )
        or instrumented_process_count < 1
        or process_start_count < instrumented_process_count
        or not isinstance(operations, dict)
        or any(
            not isinstance(operation, str)
            or not operation
            or not isinstance(count, int)
            or isinstance(count, bool)
            or count <= 0
            for operation, count in operations.items()
        )
        or sum(operations.values()) != call_count
        or not isinstance(path_classes, dict)
        or any(
            not isinstance(path_class, str)
            or not path_class
            or not isinstance(count, int)
            or isinstance(count, bool)
            or count <= 0
            for path_class, count in path_classes.items()
        )
        or sum(path_classes.values()) != call_count
        or instrumentation["traceEventSchema"] != RUNTIME_TRACE_EVENT_SCHEMA
        or trace_event_count
        < (
            call_count
            + process_start_count
            + execution_attempt_count
            + unix_socket_attempt_count
        )
        or not re.fullmatch(
            r"[0-9a-f]{64}", str(instrumentation["traceSha256"])
        )
    ):
        fail(f"{platform_name} runtime instrumentation accounting drifted: {case_name}")
    if pty:
        if (
            instrumented_process_count != 2
            or process_start_count < 2
            or execution_attempt_count < 1
            or unix_socket_attempt_count < 3
        ):
            fail(f"{platform_name} PTY process instrumentation drifted: {case_name}")
    elif (
        instrumented_process_count != 1
        or process_start_count != 1
        or execution_attempt_count != 0
        or unix_socket_attempt_count != 0
    ):
        fail(f"{platform_name} isolated process instrumentation drifted: {case_name}")


def runtime_output_text(
    case: dict[str, object],
    platform_name: str,
    case_name: str,
) -> tuple[str, str]:
    stdout = case.get("stdoutUtf8")
    stderr = case.get("stderrUtf8")
    if not isinstance(stdout, str) or not isinstance(stderr, str):
        fail(f"{platform_name} runtime output text is absent: {case_name}")
    stdout_digest = case.get("stdoutSha256")
    stderr_digest = case.get("stderrSha256")
    if (
        stdout_digest != sha256_bytes(stdout.encode("utf-8"))
        or stderr_digest != sha256_bytes(stderr.encode("utf-8"))
    ):
        fail(f"{platform_name} runtime output digest disagrees: {case_name}")
    return stdout, stderr


def parse_runtime_json(
    stdout: str,
    stderr: str,
    platform_name: str,
    case_name: str,
) -> dict[str, object]:
    if stderr != "" or not stdout.endswith("\n") or stdout.count("\n") != 1:
        fail(f"{platform_name} runtime JSON framing drifted: {case_name}")
    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise VerificationError(
            f"{platform_name} runtime JSON is invalid: {case_name}"
        ) from exc
    if (
        not isinstance(parsed, dict)
        or set(parsed) != {"schemaVersion", "command", "ok", "code", "data"}
        or parsed.get("schemaVersion") != 1
        or not isinstance(parsed.get("command"), str)
        or not isinstance(parsed.get("ok"), bool)
        or not isinstance(parsed.get("code"), str)
    ):
        fail(f"{platform_name} runtime JSON envelope drifted: {case_name}")
    return parsed


def validate_runtime_json_contract(
    parsed: dict[str, object],
    contract: dict[str, object],
    platform_name: str,
    case_name: str,
) -> None:
    expected_command = contract.get("jsonCommand")
    expected_codes = contract.get("jsonCodes")
    if (
        parsed["command"] != expected_command
        or not isinstance(expected_codes, set)
        or parsed["code"] not in expected_codes
        or parsed["ok"] is not (contract["exitCode"] == 0)
    ):
        fail(f"{platform_name} runtime JSON result drifted: {case_name}")
    code = parsed["code"]
    data = parsed["data"]
    if code == "EMPTY_NOT_YET_EVIDENCED":
        if data != {"state": "EMPTY", "entryCount": 0, "headSha256": None}:
            fail(f"{platform_name} empty receipt shape drifted: {case_name}")
    elif code == "RECEIPT_CHAIN_VALID":
        if (
            not isinstance(data, dict)
            or set(data) != {"state", "entryCount", "headSha256"}
            or data.get("state") != "VALID"
            or data.get("entryCount") != 1
            or not re.fullmatch(r"[0-9a-f]{64}", str(data.get("headSha256", "")))
        ):
            fail(f"{platform_name} valid receipt shape drifted: {case_name}")
    elif code in {"RECEIPT_APPENDED", "RECEIPT_EXISTING"}:
        expected_disposition = {
            "RECEIPT_APPENDED": "APPENDED",
            "RECEIPT_EXISTING": "EXISTING",
        }[str(code)]
        if (
            not isinstance(data, dict)
            or set(data)
            != {"disposition", "sequence", "receiptSha256", "claimCeiling"}
            or data.get("disposition") != expected_disposition
            or data.get("sequence") != 1
            or not re.fullmatch(
                r"[0-9a-f]{64}", str(data.get("receiptSha256", ""))
            )
            or data.get("claimCeiling") != "local-record"
        ):
            fail(f"{platform_name} receipt record shape drifted: {case_name}")
    elif code in {"SAFETY_RECONCILED", "SAFETY_ALREADY_RECONCILED"}:
        if (
            not isinstance(data, dict)
            or set(data) != {"pendingBefore", "appended", "existing", "pendingAfter"}
            or any(
                not isinstance(data[key], int)
                or isinstance(data[key], bool)
                or data[key] < 0
                for key in data
            )
            or data["pendingAfter"] != 0
        ):
            fail(f"{platform_name} safety reconciliation shape drifted: {case_name}")
    elif code in {
        "INVALID_RECEIPT_INPUT",
        "CHECKPOINT_AUTHORITY_UNAVAILABLE",
        "CHECKPOINT_REFUSED",
    }:
        if data is not None:
            fail(f"{platform_name} refusal must carry null data: {case_name}")


def validate_pty_write_manifest(
    manifest: object,
    platform_name: str,
    case_name: str,
) -> None:
    if (
        not isinstance(manifest, list)
        or any(not isinstance(path, str) for path in manifest)
        or manifest != sorted(set(manifest))
    ):
        fail(f"{platform_name} PTY write manifest is malformed: {case_name}")
    exact = {
        "HOME:.jcode",
        "HOME:.jcode/logs",
        "HOME:Library",
        "HOME:Library/Caches",
        "HOME:Library/Caches/jcode",
        "HOME:Library/Caches/jcode/mermaid",
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
    patterns = [
        r"^HOME:\.jcode/logs/memory-events-\d{4}-\d{2}-\d{2}\.jsonl$",
        r"^JCODE_HOME:active_pids(?:/.+)?$",
        r"^JCODE_HOME:logs/jcode-\d{4}-\d{2}-\d{2}\.log$",
        r"^JCODE_HOME:logs/memory/(?:client|server)-runtime-memory-"
        r"\d{4}-\d{2}-\d{2}\.jsonl$",
        r"^JCODE_HOME:sessions/session_[a-z0-9-]+_[0-9]{13}_[0-9a-f]{16}\.(?:bak|json)$",
    ]
    invalid = [
        path
        for path in manifest
        if path not in exact
        and not any(re.fullmatch(pattern, path) for pattern in patterns)
    ]
    required = {
        "JCODE_HOME:sessions",
        "RUNTIME:durable-state",
        "RUNTIME:jcode-daemon.lock",
    }
    session_paths = [
        path
        for path in manifest
        if re.fullmatch(patterns[-1], path) is not None
    ]
    session_stems = {
        path.removesuffix(".bak").removesuffix(".json") for path in session_paths
    }
    exact_session_pair = (
        len(session_paths) == 2
        and len(session_stems) == 1
        and {path.rsplit(".", 1)[-1] for path in session_paths} == {"bak", "json"}
    )
    if invalid or not required.issubset(set(manifest)) or not exact_session_pair:
        fail(
            f"{platform_name} PTY exact-write contract drifted: {case_name}; "
            f"invalid={invalid} missing={sorted(required - set(manifest))} "
            f"exactSessionPair={exact_session_pair}"
        )


def validate_runtime_receipt(
    payload: object,
    platform_name: str,
    commit: str,
    tree: str,
) -> set[str]:
    if (
        not isinstance(payload, dict)
        or set(payload)
        != {
            "schemaVersion",
            "proposition",
            "externalActions",
            "gitIdentity",
            "platform",
            "toolchain",
            "instrumentationPositiveControl",
            "binaries",
            "cases",
            "result",
        }
        or payload.get("schemaVersion") != 1
    ):
        fail(f"{platform_name} runtime evidence schema is unsupported")
    if payload.get("proposition") != "OMNIS KEY Local Integrity V1 fork sovereignty":
        fail(f"{platform_name} runtime evidence proposition drifted")
    if payload.get("externalActions") is not False or payload.get("result") != "PASS":
        fail(f"{platform_name} runtime evidence is not a builder-only PASS")
    if payload.get("gitIdentity") != {
        "commit": commit,
        "tree": tree,
        "worktreeClean": True,
        "developmentDirtyOverride": False,
    }:
        fail(f"{platform_name} runtime evidence is not bound to a clean candidate")
    platform = payload.get("platform")
    if (
        not isinstance(platform, dict)
        or set(platform) != {"system", "machine"}
        or platform.get("system") != PLATFORM_SYSTEM[platform_name]
        or not isinstance(platform.get("machine"), str)
        or not platform["machine"]
    ):
        fail(f"{platform_name} runtime platform identity disagrees")
    toolchain = payload.get("toolchain")
    if (
        not isinstance(toolchain, dict)
        or set(toolchain) != {"python", "compiler"}
        or not isinstance(toolchain.get("python"), str)
        or not toolchain["python"]
        or not isinstance(toolchain.get("compiler"), str)
        or not toolchain["compiler"]
    ):
        fail(f"{platform_name} runtime toolchain identity is absent")
    control = payload.get("instrumentationPositiveControl")
    control_events = (
        control.get("requiredNetworkAndOperatorEvents")
        if isinstance(control, dict)
        else None
    )
    if (
        not isinstance(control, dict)
        or set(control)
        != {
            "result",
            "requiredNetworkAndOperatorEvents",
            "requiredFilesystemOperations",
            "requiredMutationOperations",
            "requiredCredentialEnvironmentReads",
            "processStartEvents",
            "executionAttemptEvents",
            "directEnvironmentEnumerationSourceFilesChecked",
            "traceSha256",
        }
        or control.get("result") != "PASS"
        or not isinstance(control_events, list)
        or any(not isinstance(event, str) for event in control_events)
        or set(control_events) != POSITIVE_CONTROL_EVENTS
        or control.get("requiredFilesystemOperations") != ["open", "openat", "stat"]
        or control.get("requiredMutationOperations")
        != sorted(POSITIVE_CONTROL_MUTATIONS)
        or control.get("requiredCredentialEnvironmentReads")
        != sorted(CREDENTIAL_ENVIRONMENT)
        or control.get("processStartEvents") != 1
        or not isinstance(control.get("executionAttemptEvents"), int)
        or isinstance(control.get("executionAttemptEvents"), bool)
        or control["executionAttemptEvents"] < 1
        or not isinstance(
            control.get("directEnvironmentEnumerationSourceFilesChecked"), int
        )
        or isinstance(
            control.get("directEnvironmentEnumerationSourceFilesChecked"), bool
        )
        or control["directEnvironmentEnumerationSourceFilesChecked"] < 1
        or not re.fullmatch(r"[0-9a-f]{64}", str(control.get("traceSha256", "")))
    ):
        fail(f"{platform_name} instrumentation positive control is incomplete")
    binaries = payload.get("binaries")
    if not isinstance(binaries, dict) or set(binaries) != {"jcode", "omnis-key"}:
        fail(f"{platform_name} runtime binary identity is incomplete")
    for name in ("jcode", "omnis-key"):
        binary = binaries[name]
        if (
            not isinstance(binary, dict)
            or set(binary) != {"name", "sha256"}
            or binary.get("name") != name
            or not re.fullmatch(r"[0-9a-f]{64}", str(binary.get("sha256", "")))
        ):
            fail(f"{platform_name} runtime binary identity drifted: {name}")

    cases = payload.get("cases")
    if not isinstance(cases, list):
        fail(f"{platform_name} runtime cases are absent")
    observed: dict[str, dict[str, object]] = {}
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("name"), str):
            fail(f"{platform_name} runtime case is malformed")
        name = case["name"]
        if name in observed:
            fail(f"{platform_name} runtime case is duplicated: {name}")
        contract = RUNTIME_CASE_CONTRACTS.get(name)
        if contract is None:
            fail(f"{platform_name} runtime evidence has an unexpected case: {name}")
        output_kind = contract["outputKind"]
        pty = output_kind == "pty"
        required_keys = {
            "name",
            "argv",
            "exitCode",
            "instrumentation",
            "stdoutSha256",
            "stderrSha256",
            "writeManifest",
        }
        if pty:
            required_keys.update(
                {
                    "usableFirstFrame",
                    "firstFramePrintableBytes",
                    "hostileStartupProof",
                    "temporaryServerShutdown",
                    "processInstrumentation",
                    "controlledUnixTransport",
                    "writeAttemptProof",
                }
            )
        else:
            required_keys.update({"stdoutUtf8", "stderrUtf8"})
        if output_kind == "demo-json":
            required_keys.add("filesystemProof")
        if set(case) != required_keys:
            fail(f"{platform_name} runtime case schema drifted: {name}")
        if case["argv"] != contract["argv"] or case["exitCode"] != contract["exitCode"]:
            fail(f"{platform_name} runtime argv/exit contract drifted: {name}")
        validate_runtime_instrumentation(
            case["instrumentation"], platform_name, name, pty=pty
        )
        if pty:
            if (
                not re.fullmatch(r"[0-9a-f]{64}", str(case["stdoutSha256"]))
                or case["stderrSha256"] is not None
            ):
                fail(f"{platform_name} PTY output identity drifted: {name}")
            validate_pty_write_manifest(case["writeManifest"], platform_name, name)
        else:
            if case["writeManifest"] != contract["writeManifest"]:
                fail(f"{platform_name} runtime exact-write manifest drifted: {name}")
            stdout, stderr = runtime_output_text(case, platform_name, name)
            if output_kind == "help":
                if (
                    stderr != ""
                    or not stdout.endswith("\n")
                    or "Usage:" not in stdout
                    or not stdout.strip()
                ):
                    fail(f"{platform_name} help output drifted: {name}")
            elif output_kind == "omnis-version-text":
                if stdout != "omnis-key 0.1.0\njcode compatibility base 0.61.2\n" or stderr:
                    fail(f"{platform_name} OMNIS version output drifted: {name}")
            elif output_kind == "jcode-version-text":
                expected = (
                    rf"jcode v0\.61\.2-dev "
                    rf"\({re.escape(commit[:8])}, clean\)\n"
                )
                if re.fullmatch(expected, stdout) is None or stderr:
                    fail(f"{platform_name} jcode version output drifted: {name}")
            elif output_kind == "version-json":
                parsed = parse_runtime_json(stdout, stderr, platform_name, name)
                if parsed != {
                    "schemaVersion": 1,
                    "command": "version",
                    "ok": True,
                    "code": "VERSION",
                    "data": {
                        "compatibilityBaseName": "jcode",
                        "compatibilityBaseVersion": "0.61.2",
                        "productVersion": "0.1.0",
                    },
                }:
                    fail(f"{platform_name} version JSON drifted: {name}")
            elif output_kind == "parser-error":
                if (
                    stdout != ""
                    or not stderr.startswith("error:")
                    or "Usage:" not in stderr
                    or "panicked at" in stderr
                    or "stack backtrace:" in stderr
                ):
                    fail(f"{platform_name} parser refusal drifted: {name}")
            elif output_kind == "disabled-surface":
                surface = contract["disabledSurface"]
                if (
                    stdout != ""
                    or stderr
                    != (
                        "Error: OMNIS_KEY_INHERITED_SURFACE_DISABLED: inherited "
                        f"Jcode {surface} behavior is disabled in OMNIS KEY Local "
                        "Integrity V1\n"
                    )
                ):
                    fail(f"{platform_name} inherited-surface refusal drifted: {name}")
            elif output_kind == "json":
                parsed = parse_runtime_json(stdout, stderr, platform_name, name)
                validate_runtime_json_contract(
                    parsed, contract, platform_name, name
                )
            elif output_kind == "demo-json":
                parsed = parse_runtime_json(stdout, stderr, platform_name, name)
                if parsed != {
                    "schemaVersion": 1,
                    "command": "demo.integrity",
                    "ok": True,
                    "code": "DEMO_INTEGRITY_PASSED",
                    "data": {
                        "fixtureOnly": True,
                        "firstAppend": "APPENDED",
                        "exactReplay": "EXISTING",
                        "validChain": True,
                        "tamperedCopyRefused": True,
                        "tamperRefusalCode": "RECEIPT_CHAIN_INVALID",
                        "executionAuthorized": False,
                    },
                }:
                    fail(f"{platform_name} demo JSON drifted: {name}")
        observed[name] = case
    if set(observed) != EXPECTED_RUNTIME_CASES:
        fail(
            f"{platform_name} runtime exact case set drifted: "
            f"missing={sorted(EXPECTED_RUNTIME_CASES - set(observed))} "
            f"extra={sorted(set(observed) - EXPECTED_RUNTIME_CASES)}"
        )

    for name in ("omnis-demo", "jcode-demo"):
        case = observed[name]
        proof = case.get("filesystemProof")
        if (
            not isinstance(proof, dict)
            or set(proof)
            != {
                "result",
                "selfCreatedRootCount",
                "selfCreatedRootAccessCalls",
                "allowedSystemAccessCalls",
                "controlledRootAccessCalls",
                "preplantedAdversaryAccessCalls",
            }
            or proof.get("result") != "PASS"
            or proof.get("selfCreatedRootCount") != 1
            or not isinstance(proof.get("selfCreatedRootAccessCalls"), int)
            or proof["selfCreatedRootAccessCalls"] <= 0
            or not isinstance(proof.get("allowedSystemAccessCalls"), int)
            or proof["allowedSystemAccessCalls"] < 0
            or proof.get("controlledRootAccessCalls") != 0
            or proof.get("preplantedAdversaryAccessCalls") != 0
        ):
            fail(f"{platform_name} demo filesystem proof is incomplete: {name}")
    for name in ("jcode-pty-no-argument", "omnis-pty-no-argument"):
        case = observed[name]
        hostile = case.get("hostileStartupProof")
        shutdown = case.get("temporaryServerShutdown")
        if (
            case.get("usableFirstFrame") is not True
            or not isinstance(case.get("firstFramePrintableBytes"), int)
            or case["firstFramePrintableBytes"] < 40
            or not isinstance(hostile, dict)
            or hostile
            != {
                "fixtureOnly": True,
                "credentialAccountAccesses": 0,
                "protectedFixtureChanges": 0,
                "replacementCandidateExecutions": 0,
                "armedRestartRestoreExecutions": 0,
            }
            or not isinstance(shutdown, dict)
            or set(shutdown)
            != {
                "metadataBound",
                "processExitObserved",
                "metadataRemoved",
                "instrumentationLogQuiescent",
                "boundedWaitSeconds",
            }
            or shutdown.get("metadataBound") is not True
            or shutdown.get("processExitObserved") is not True
            or shutdown.get("metadataRemoved") is not True
            or shutdown.get("instrumentationLogQuiescent") is not True
            or shutdown.get("boundedWaitSeconds") != 25
        ):
            fail(f"{platform_name} PTY sovereignty proof is incomplete: {name}")
        instrumentation = case["instrumentation"]
        process = case.get("processInstrumentation")
        expected_image_chain = (
            ["jcode"] if name == "jcode-pty-no-argument" else ["omnis-key", "jcode"]
        )
        if (
            not isinstance(process, dict)
            or set(process)
            != {
                "clientImageChain",
                "clientProcessStartObserved",
                "executionAttemptCount",
                "instrumentationPropagationStrips",
                "instrumentedProcessCount",
                "temporaryServerImage",
                "temporaryServerProcessStartObserved",
                "unexpectedExecutableAttempts",
            }
            or process.get("clientImageChain") != expected_image_chain
            or process.get("clientProcessStartObserved") is not True
            or process.get("temporaryServerProcessStartObserved") is not True
            or process.get("temporaryServerImage") != "jcode"
            or process.get("instrumentationPropagationStrips") != 0
            or process.get("unexpectedExecutableAttempts") != 0
            or process.get("instrumentedProcessCount")
            != instrumentation["instrumentedProcessCount"]
            or process.get("executionAttemptCount")
            != instrumentation["executionAttemptCount"]
            or instrumentation["processStartCount"] != len(expected_image_chain) + 1
        ):
            fail(f"{platform_name} PTY process/image proof is incomplete: {name}")

        transport = case.get("controlledUnixTransport")
        if (
            not isinstance(transport, dict)
            or set(transport)
            != {
                "bindAttempts",
                "clientConnectOnly",
                "connectAttempts",
                "socketCreateAttempts",
                "socketPathClass",
                "temporaryServerBindOnly",
                "unexpectedSocketAttempts",
            }
            or transport.get("bindAttempts") != 1
            or not isinstance(transport.get("connectAttempts"), int)
            or isinstance(transport.get("connectAttempts"), bool)
            or transport["connectAttempts"] < 1
            or not isinstance(transport.get("socketCreateAttempts"), int)
            or isinstance(transport.get("socketCreateAttempts"), bool)
            or transport["socketCreateAttempts"] < 1
            or transport.get("socketPathClass") != "controlled:JCODE_SOCKET"
            or transport.get("temporaryServerBindOnly") is not True
            or transport.get("clientConnectOnly") is not True
            or transport.get("unexpectedSocketAttempts") != 0
            or instrumentation["unixSocketAttemptCount"]
            != (
                transport["socketCreateAttempts"]
                + transport["bindAttempts"]
                + transport["connectAttempts"]
            )
        ):
            fail(f"{platform_name} PTY exact Unix transport proof is incomplete: {name}")

        attempts = case.get("writeAttemptProof")
        attempt_classes = (
            attempts.get("attemptClasses") if isinstance(attempts, dict) else None
        )
        mutation_attempt_count = sum(
            count
            for operation, count in instrumentation["filesystemOperations"].items()
            if operation in RUNTIME_MUTATING_FILESYSTEM_OPERATIONS
        )
        if (
            not isinstance(attempts, dict)
            or set(attempts)
            != {"attemptClasses", "attemptCount", "forbiddenAttemptCount"}
            or not isinstance(attempt_classes, list)
            or not attempt_classes
            or attempt_classes != sorted(set(attempt_classes))
            or any(
                not isinstance(attempt_class, str)
                or not attempt_class
                or attempt_class.split(":", 1)[0]
                not in RUNTIME_MUTATING_FILESYSTEM_OPERATIONS
                for attempt_class in attempt_classes
            )
            or attempts.get("attemptCount") != mutation_attempt_count
            or mutation_attempt_count < len(attempt_classes)
            or attempts.get("forbiddenAttemptCount") != 0
        ):
            fail(f"{platform_name} PTY write-attempt proof is incomplete: {name}")

    equal_output_groups = [
        ["omnis-version", "omnis-version-short", "omnis-version-command", "jcode-omnis-version-command"],
        ["omnis-version-json", "jcode-omnis-version-json"],
        ["omnis-receipts-help", "jcode-omnis-receipts-help"],
        ["omnis-receipts-status-help", "jcode-omnis-receipts-status-help"],
        ["omnis-receipts-verify-help", "jcode-omnis-receipts-verify-help"],
        ["omnis-receipts-record-help", "jcode-omnis-receipts-record-help"],
        ["omnis-receipts-reconcile-help", "jcode-omnis-receipts-reconcile-help"],
        ["omnis-checkpoint-help", "jcode-omnis-checkpoint-help"],
        ["omnis-checkpoint-anchor-help", "jcode-omnis-checkpoint-anchor-help"],
        ["omnis-checkpoint-verify-help", "jcode-omnis-checkpoint-verify-help"],
        ["omnis-demo-help", "jcode-omnis-demo-help"],
        ["omnis-demo-integrity-help", "jcode-omnis-demo-integrity-help"],
        ["omnis-version-help", "jcode-omnis-version-help"],
        ["omnis-empty-status", "jcode-global-omnis-status"],
        ["omnis-checkpoint-verify", "jcode-checkpoint-verify"],
        ["omnis-malformed-event-id", "jcode-malformed-event-id"],
        [
            "omnis-malformed-checkpoint-request-id",
            "jcode-malformed-checkpoint-request-id",
        ],
    ]
    for group in equal_output_groups:
        identities = {
            (
                observed[name].get("stdoutSha256"),
                observed[name].get("stderrSha256"),
                observed[name].get("stdoutUtf8"),
                observed[name].get("stderrUtf8"),
            )
            for name in group
        }
        if len(identities) != 1:
            fail(
                f"{platform_name} canonical/compatibility output mismatch: {group}"
            )
    return set(observed)


def security_exact_dict(
    value: object, keys: set[str], label: str
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        observed = sorted(value) if isinstance(value, dict) else type(value).__name__
        fail(
            f"{label} keys disagree: "
            f"expected={sorted(keys)} observed={observed}"
        )
    return value


def security_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        fail(f"{label} is not a lowercase SHA-256 digest")
    return value


def security_integer(
    value: object, label: str, *, minimum: int = 0
) -> int:
    if type(value) is not int or value < minimum:
        fail(f"{label} is not an integer >= {minimum}")
    return value


def security_text(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4096
        or any(ord(character) < 0x20 for character in value)
    ):
        fail(f"{label} is absent or contains unsafe control text")
    return value


def security_date(value: object, label: str) -> datetime:
    if not isinstance(value, str) or re.fullmatch(r"\d{4}-\d{2}-\d{2}", value) is None:
        fail(f"{label} is not a canonical date")
    try:
        return datetime.strptime(value, "%Y-%m-%d")
    except ValueError as exc:
        raise VerificationError(f"{label} is not a real date") from exc


def validate_security_tool(
    value: object,
    label: str,
    *,
    name: str,
    version: str,
    executable: str,
    expected_sha256: str,
    target: dict[str, str],
) -> None:
    tool = security_exact_dict(
        value,
        {
            "name",
            "version",
            "target",
            "executable",
            "executableSha256",
            "expectedExecutableSha256",
            "identityPolicy",
        },
        label,
    )
    if (
        tool["name"] != name
        or tool["version"] != version
        or tool["target"] != target
        or tool["executable"] != executable
        or tool["identityPolicy"] != SECURITY_IDENTITY_POLICY
        or tool["executableSha256"] != expected_sha256
        or tool["expectedExecutableSha256"] != expected_sha256
    ):
        fail(f"{label} exact pinned identity disagrees")


def validate_security_report(
    path: Path,
    platform_name: str,
    commit: str,
    tree: str,
    archive_result: dict[str, object],
) -> tuple[str, int, int]:
    if platform_name not in SECURITY_PLATFORM_IDENTITIES:
        fail(f"security report platform is unsupported: {platform_name}")
    payload_bytes = require_regular_private(path, "security report")
    try:
        raw_report = json.loads(payload_bytes)
    except json.JSONDecodeError as exc:
        raise VerificationError("security report is not valid JSON") from exc
    report = security_exact_dict(
        raw_report,
        {
            "schemaVersion",
            "status",
            "candidate",
            "archive",
            "tools",
            "scanSets",
            "legs",
            "commands",
            "observedDateUtc",
            "externalActions",
        },
        "security report",
    )
    if (
        type(report["schemaVersion"]) is not int
        or report["schemaVersion"] != 1
        or report["externalActions"] is not False
    ):
        fail("security report schema or externalActions disagrees")

    candidate = security_exact_dict(
        report["candidate"],
        {"commit", "tree", "baseCommit"},
        "security report candidate",
    )
    if candidate != {
        "commit": commit,
        "tree": tree,
        "baseCommit": SECURITY_BASE_COMMIT,
    }:
        fail("security report candidate/base identity disagrees")

    archive = security_exact_dict(
        report["archive"],
        {
            "kind",
            "prefix",
            "productVersion",
            "sha256",
            "compressedBytes",
            "fileCount",
        },
        "security report archive",
    )
    if (
        archive["kind"] != "local-review-source-archive"
        or archive["sha256"] != archive_result.get("sha256")
        or archive["prefix"] != archive_result.get("prefix")
        or archive["productVersion"] != archive_result.get("productVersion")
        or archive["compressedBytes"] != archive_result.get("compressedBytes")
        or archive["fileCount"] != archive_result.get("fileCount")
        or security_integer(
            archive["compressedBytes"],
            "security report archive compressedBytes",
            minimum=1,
        )
        >= 50 * 1024 * 1024
        or security_integer(
            archive["fileCount"],
            "security report archive fileCount",
            minimum=1,
        )
        < 1
    ):
        fail("security report archive identity or size disagrees")
    security_sha256(archive["sha256"], "security report archive sha256")

    platform_identity = SECURITY_PLATFORM_IDENTITIES[platform_name]
    expected_target = {
        "os": platform_identity["os"],
        "architecture": platform_identity["architecture"],
    }
    tools = security_exact_dict(
        report["tools"],
        {
            "secretScanner",
            "dependencyTool",
            "licenseTool",
            "advisoryDatabase",
            "runtime",
        },
        "security report tools",
    )
    secret_scanner = security_exact_dict(
        tools["secretScanner"],
        {
            "name",
            "version",
            "sourceCommit",
            "buildToolchain",
            "target",
            "executable",
            "executableSha256",
            "expectedExecutableSha256",
            "identityPolicy",
            "goBuildInfoSha256",
            "vcsModified",
            "configurationPolicy",
        },
        "security report secret scanner",
    )
    if (
        secret_scanner["name"] != "gitleaks"
        or secret_scanner["version"] != "8.30.1"
        or secret_scanner["sourceCommit"]
        != "83d9cd684c87d95d656c1458ef04895a7f1cbd8e"
        or secret_scanner["buildToolchain"] != "go1.26.5"
        or secret_scanner["target"] != expected_target
        or secret_scanner["executable"] != "gitleaks"
        or secret_scanner["executableSha256"]
        != platform_identity["gitleaksSha256"]
        or secret_scanner["expectedExecutableSha256"]
        != platform_identity["gitleaksSha256"]
        or secret_scanner["identityPolicy"] != SECURITY_IDENTITY_POLICY
        or secret_scanner["vcsModified"] is not False
    ):
        fail(f"{platform_name} secret-scanner exact pinned identity disagrees")
    security_sha256(
        secret_scanner["goBuildInfoSha256"],
        "security report gitleaks build-info digest",
    )
    configuration = security_exact_dict(
        secret_scanner["configurationPolicy"],
        {"source", "ambientOverridesCleared", "candidateOverrideFiles"},
        "security report secret-scanner configuration policy",
    )
    if (
        configuration["source"] != "pinned-embedded-defaults"
        or configuration["ambientOverridesCleared"] is not True
        or security_integer(
            configuration["candidateOverrideFiles"],
            "security report candidate scanner override files",
        )
        != 0
    ):
        fail("security report secret-scanner configuration policy disagrees")

    validate_security_tool(
        tools["dependencyTool"],
        "security report dependency tool",
        name="cargo-audit",
        version="0.22.2",
        executable="cargo-audit",
        expected_sha256=platform_identity["cargoAuditSha256"],
        target=expected_target,
    )
    validate_security_tool(
        tools["licenseTool"],
        "security report license tool",
        name="cargo-deny",
        version="0.20.2",
        executable="cargo-deny",
        expected_sha256=platform_identity["cargoDenySha256"],
        target=expected_target,
    )
    advisory = security_exact_dict(
        tools["advisoryDatabase"],
        {
            "repository",
            "commit",
            "modifiedFiles",
            "stagedFiles",
            "untrackedFiles",
        },
        "security report advisory database",
    )
    if (
        advisory["repository"]
        not in {
            "https://github.com/RustSec/advisory-db",
            "https://github.com/RustSec/advisory-db.git",
        }
        or advisory["commit"] != SECURITY_ADVISORY_DB_COMMIT
        or security_integer(
            advisory["modifiedFiles"],
            "security report advisory modifiedFiles",
        )
        != 0
        or security_integer(
            advisory["stagedFiles"],
            "security report advisory stagedFiles",
        )
        != 0
        or security_integer(
            advisory["untrackedFiles"],
            "security report advisory untrackedFiles",
        )
        != 0
    ):
        fail("security report advisory-database identity or cleanliness disagrees")

    runtime = security_exact_dict(
        tools["runtime"],
        {"git", "tar", "cargo", "rustc", "go", "python", "jq", "sha256"},
        "security report runtime tools",
    )
    runtime_executables = {
        "git": "git",
        "tar": "tar",
        "cargo": "cargo",
        "rustc": "rustc",
        "go": "go",
        "python": "python3",
        "jq": "jq",
    }
    runtime_versions: dict[str, str] = {}
    for runtime_name, executable in runtime_executables.items():
        runtime_tool = security_exact_dict(
            runtime[runtime_name],
            {"version", "executable"},
            f"security report runtime {runtime_name}",
        )
        if runtime_tool["executable"] != executable:
            fail(
                f"security report runtime {runtime_name} executable disagrees"
            )
        runtime_versions[runtime_name] = security_text(
            runtime_tool["version"],
            f"security report runtime {runtime_name} version",
        )
    if (
        not runtime_versions["git"].startswith("git version ")
        or not runtime_versions["cargo"].startswith("cargo ")
        or not runtime_versions["rustc"].startswith("rustc ")
        or runtime_versions["go"]
        != (
            "go version go1.26.5 "
            f"{platform_identity['os']}/{platform_identity['architecture']}"
        )
        or not runtime_versions["python"].startswith("Python ")
        or not runtime_versions["jq"].startswith("jq-")
        or runtime["sha256"] != platform_identity["sha256Tool"]
    ):
        fail("security report runtime tool identity is incomplete or inconsistent")

    scan_sets = security_exact_dict(
        report["scanSets"],
        {
            "releaseTreeFiles",
            "exactArchiveFiles",
            "jourdanLabsRangeCommits",
            "reachableGitCommits",
            "reachableGitObjects",
            "materializedGitObjects",
            "materializedGitObjectBytes",
            "materializedGitObjectTypes",
            "missingOrPromisorGitObjects",
            "shallowRepository",
            "partialClone",
            "gitObjectFsck",
            "publicationMetadataFiles",
            "submodules",
            "gitReplaceRefs",
            "gitAlternateObjectStores",
            "gitGrafts",
            "gitLfsPointers",
            "gitLfsObjectFiles",
            "inventoriedAssets",
            "workspacePackages",
        },
        "security report scan sets",
    )
    positive_scan_counts = {
        key: security_integer(
            scan_sets[key], f"security report scanSets.{key}", minimum=1
        )
        for key in {
            "releaseTreeFiles",
            "exactArchiveFiles",
            "jourdanLabsRangeCommits",
            "reachableGitCommits",
            "reachableGitObjects",
            "materializedGitObjects",
            "materializedGitObjectBytes",
            "publicationMetadataFiles",
            "inventoriedAssets",
            "workspacePackages",
        }
    }
    if (
        positive_scan_counts["releaseTreeFiles"] != archive["fileCount"]
        or positive_scan_counts["exactArchiveFiles"] != archive["fileCount"]
        or positive_scan_counts["reachableGitObjects"]
        != positive_scan_counts["materializedGitObjects"]
        or positive_scan_counts["reachableGitCommits"]
        > positive_scan_counts["reachableGitObjects"]
        or security_integer(
            scan_sets["missingOrPromisorGitObjects"],
            "security report missing/promisor Git objects",
        )
        != 0
        or scan_sets["shallowRepository"] is not False
        or scan_sets["partialClone"] is not False
        or security_integer(
            scan_sets["submodules"], "security report submodules"
        )
        != 0
        or security_integer(
            scan_sets["gitReplaceRefs"], "security report Git replace refs"
        )
        != 0
        or security_integer(
            scan_sets["gitAlternateObjectStores"],
            "security report Git alternate object stores",
        )
        != 0
        or security_integer(
            scan_sets["gitGrafts"], "security report Git grafts"
        )
        != 0
        or security_integer(
            scan_sets["gitLfsPointers"], "security report Git LFS pointers"
        )
        != 0
        or security_integer(
            scan_sets["gitLfsObjectFiles"],
            "security report Git LFS object files",
        )
        != 0
    ):
        fail("security report scan-set coverage or repository state disagrees")
    object_types = security_exact_dict(
        scan_sets["materializedGitObjectTypes"],
        {"blob", "commit", "tag", "tree"},
        "security report materialized Git object types",
    )
    object_type_counts = {
        key: security_integer(
            object_types[key],
            f"security report materialized Git object type {key}",
        )
        for key in object_types
    }
    if (
        sum(object_type_counts.values())
        != positive_scan_counts["materializedGitObjects"]
        or object_type_counts["blob"] < 1
        or object_type_counts["commit"] < 1
        or object_type_counts["tree"] < 1
    ):
        fail("security report materialized Git object accounting disagrees")
    git_fsck = security_exact_dict(
        scan_sets["gitObjectFsck"],
        {"status", "exitStatus", "evidenceSha256"},
        "security report Git fsck",
    )
    if (
        git_fsck["status"] != "SCAN_CLEAN"
        or security_integer(
            git_fsck["exitStatus"],
            "security report Git fsck exit status",
        )
        != 0
    ):
        fail("security report Git fsck did not prove a clean object database")
    security_sha256(
        git_fsck["evidenceSha256"],
        "security report Git fsck evidence digest",
    )

    legs = security_exact_dict(
        report["legs"],
        {"secret", "dependency", "license", "artifact"},
        "security report legs",
    )
    secret = security_exact_dict(
        legs["secret"],
        {"status", "namedScans", "positiveControl", "scanStatusSha256"},
        "security report secret leg",
    )
    if secret["status"] != "SCAN_CLEAN":
        fail("security report secret leg is not clean")
    security_sha256(
        secret["scanStatusSha256"],
        "security report secret scan-status digest",
    )
    positive_control = security_exact_dict(
        secret["positiveControl"],
        {"status", "exitStatus", "findingCount", "reportSha256"},
        "security report planted-secret positive control",
    )
    if (
        positive_control["status"] != "DETECTED_AS_REQUIRED"
        or security_integer(
            positive_control["exitStatus"],
            "security report planted-secret exit status",
        )
        != 1
        or security_integer(
            positive_control["findingCount"],
            "security report planted-secret finding count",
            minimum=1,
        )
        < 1
    ):
        fail("security report planted-secret positive control disagrees")
    security_sha256(
        positive_control["reportSha256"],
        "security report planted-secret report digest",
    )

    named_scans = secret["namedScans"]
    if not isinstance(named_scans, list) or len(named_scans) != 6:
        fail("security report named secret scans are incomplete")
    expected_scan_counts = {
        "release_tree": positive_scan_counts["releaseTreeFiles"],
        "exact_archive": positive_scan_counts["exactArchiveFiles"],
        "jourdanlabs_commit_range": positive_scan_counts[
            "jourdanLabsRangeCommits"
        ],
        "reachable_git_history": positive_scan_counts[
            "reachableGitCommits"
        ],
        "reachable_git_objects": positive_scan_counts[
            "materializedGitObjects"
        ],
        "git_publication_metadata": positive_scan_counts[
            "publicationMetadataFiles"
        ],
    }
    observed_scan_names: set[str] = set()
    for position, raw_scan in enumerate(named_scans):
        scan = security_exact_dict(
            raw_scan,
            {
                "name",
                "scanSetCount",
                "exitStatus",
                "status",
                "reportSha256",
            },
            f"security report named secret scan {position}",
        )
        name = scan["name"]
        if (
            not isinstance(name, str)
            or name not in SECURITY_NAMED_SCANS
            or name in observed_scan_names
            or security_integer(
                scan["scanSetCount"],
                f"security report named secret scan {name} count",
                minimum=1,
            )
            != expected_scan_counts.get(name)
            or security_integer(
                scan["exitStatus"],
                f"security report named secret scan {name} exit status",
            )
            != 0
            or scan["status"] != "SCAN_CLEAN"
        ):
            fail("security report named secret scan coverage disagrees")
        security_sha256(
            scan["reportSha256"],
            f"security report named secret scan {name} digest",
        )
        observed_scan_names.add(name)
    if observed_scan_names != SECURITY_NAMED_SCANS:
        fail("security report named secret scan set disagrees")

    dependency = security_exact_dict(
        legs["dependency"],
        {
            "status",
            "exitStatus",
            "reportSha256",
            "unsuppressedExitStatus",
            "unsuppressedReportSha256",
            "unreviewedVulnerabilityCount",
            "visibleWarningCount",
            "informationalWarnings",
            "warningCounts",
            "exceptionCount",
            "proposedExceptionFindings",
            "proposedExceptions",
        },
        "security report dependency leg",
    )
    if (
        security_integer(
            dependency["exitStatus"],
            "security report dependency exit status",
        )
        != 0
        or security_integer(
            dependency["unreviewedVulnerabilityCount"],
            "security report unreviewed vulnerability count",
        )
        != 0
    ):
        fail("security report dependency HOLD/status disagrees")
    security_sha256(
        dependency["reportSha256"],
        "security report dependency report digest",
    )
    security_sha256(
        dependency["unsuppressedReportSha256"],
        "security report unsuppressed dependency report digest",
    )
    warnings = dependency["informationalWarnings"]
    warning_count = security_integer(
        dependency["visibleWarningCount"],
        "security report dependency visible warning count",
    )
    if not isinstance(warnings, list) or len(warnings) != warning_count:
        fail("security report informational warnings are incomplete")
    warning_counts = security_exact_dict(
        dependency["warningCounts"],
        {"unmaintained", "unsound", "notice"},
        "security report dependency warning counts",
    )
    expected_warning_counts = {
        key: security_integer(
            warning_counts[key],
            f"security report dependency warning count {key}",
        )
        for key in warning_counts
    }
    observed_warnings: list[dict[str, object]] = []
    observed_warning_counts = {key: 0 for key in expected_warning_counts}
    for position, raw_warning in enumerate(warnings):
        warning = security_exact_dict(
            raw_warning,
            {"kind", "advisoryId", "package", "version"},
            f"security report dependency warning {position}",
        )
        kind = warning["kind"]
        if (
            not isinstance(kind, str)
            or kind not in observed_warning_counts
            or not isinstance(warning["advisoryId"], str)
            or re.fullmatch(
                r"RUSTSEC-[0-9]{4}-[0-9]{4}",
                warning["advisoryId"],
            )
            is None
            or re.fullmatch(
                r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]+)?",
                str(warning["version"]),
            )
            is None
        ):
            fail("security report dependency warning is malformed")
        security_text(
            warning["package"],
            f"security report dependency warning {position} package",
        )
        observed_warning_counts[kind] += 1
        observed_warnings.append(warning)
    if (
        observed_warning_counts != expected_warning_counts
        or sum(expected_warning_counts.values()) != warning_count
        or observed_warnings
        != sorted(
            observed_warnings,
            key=lambda warning: (
                str(warning["advisoryId"]),
                str(warning["package"]),
                str(warning["version"]),
            ),
        )
    ):
        fail("security report dependency warning accounting disagrees")

    observed_date = security_date(
        report["observedDateUtc"], "security report observedDateUtc"
    )
    proposed_exceptions = dependency["proposedExceptions"]
    exception_count = security_integer(
        dependency["exceptionCount"],
        "security report proposed-exception count",
    )
    if (
        not isinstance(proposed_exceptions, list)
        or len(proposed_exceptions) != exception_count
        or exception_count != len(SECURITY_PROPOSED_EXCEPTION_IDS)
    ):
        fail("security report proposed-exception set is incomplete")
    observed_exception_ids: list[str] = []
    for position, raw_exception in enumerate(proposed_exceptions):
        exception = security_exact_dict(
            raw_exception,
            {
                "id",
                "package",
                "version",
                "scope",
                "reason",
                "proposer",
                "proposedOn",
                "expiresOn",
            },
            f"security report proposed exception {position}",
        )
        exception_id = exception["id"]
        if (
            not isinstance(exception_id, str)
            or exception_id not in SECURITY_PROPOSED_EXCEPTION_IDS
            or exception_id in observed_exception_ids
            or exception["proposer"] != "OMNIS V1 builder"
        ):
            fail("security report proposed-exception identity disagrees")
        security_text(
            exception["package"],
            f"security report proposed exception {exception_id} package",
        )
        if (
            re.fullmatch(
                r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]+)?",
                str(exception["version"]),
            )
            is None
        ):
            fail("security report proposed-exception version is malformed")
        security_text(
            exception["scope"],
            f"security report proposed exception {exception_id} scope",
        )
        security_text(
            exception["reason"],
            f"security report proposed exception {exception_id} reason",
        )
        proposed_on = security_date(
            exception["proposedOn"],
            f"security report proposed exception {exception_id} proposedOn",
        )
        expires_on = security_date(
            exception["expiresOn"],
            f"security report proposed exception {exception_id} expiresOn",
        )
        if not proposed_on <= observed_date < expires_on:
            fail("security report proposed-exception date window disagrees")
        observed_exception_ids.append(exception_id)
    if observed_exception_ids != sorted(SECURITY_PROPOSED_EXCEPTION_IDS):
        fail("security report proposed-exception ordering or set disagrees")
    if proposed_exceptions != SECURITY_PROPOSED_EXCEPTIONS:
        fail("security report proposed-exception content disagrees")
    proposed_findings = dependency["proposedExceptionFindings"]
    expected_findings = sorted(
        (
            {
                "advisoryId": exception["id"],
                "package": exception["package"],
                "version": exception["version"],
            }
            for exception in SECURITY_PROPOSED_EXCEPTIONS
        ),
        key=lambda finding: (
            finding["advisoryId"],
            finding["package"],
            finding["version"],
        ),
    )
    if proposed_findings != expected_findings:
        fail(
            "security report proposed exceptions are not bound to exact "
            "unsuppressed findings"
        )
    expected_unsuppressed_status = 1 if exception_count > 0 else 0
    if (
        security_integer(
            dependency["unsuppressedExitStatus"],
            "security report unsuppressed dependency exit status",
        )
        != expected_unsuppressed_status
    ):
        fail("security report unsuppressed dependency status disagrees")
    if exception_count > 0:
        expected_report_status = (
            "SCAN_COMPLETE_WITH_PROPOSED_EXCEPTIONS_HOLD"
        )
        expected_dependency_status = "PENDING_INDEPENDENT_REVIEW"
    elif warning_count > 0:
        expected_report_status = "SCAN_COMPLETE_WITH_INFORMATIONAL_WARNINGS"
        expected_dependency_status = (
            "SCAN_COMPLETE_WITH_INFORMATIONAL_WARNINGS"
        )
    else:
        expected_report_status = "SCAN_COMPLETE"
        expected_dependency_status = "SCAN_CLEAN"
    if (
        report["status"] != expected_report_status
        or dependency["status"] != expected_dependency_status
    ):
        fail("security report dependency/report status disagrees")

    license_leg = security_exact_dict(
        legs["license"],
        {
            "status",
            "exitStatus",
            "evidenceSha256",
            "unknownOrIncompatibleRights",
        },
        "security report license leg",
    )
    if (
        license_leg["status"] != "SCAN_CLEAN"
        or security_integer(
            license_leg["exitStatus"],
            "security report license exit status",
        )
        != 0
        or security_integer(
            license_leg["unknownOrIncompatibleRights"],
            "security report unknown/incompatible rights",
        )
        != 0
    ):
        fail("security report license leg disagrees")
    security_sha256(
        license_leg["evidenceSha256"],
        "security report license evidence digest",
    )

    artifact = security_exact_dict(
        legs["artifact"],
        {
            "status",
            "exitStatus",
            "archiveUnder50MiB",
            "publishableWorkspacePackages",
            "metadataIncompleteWorkspacePackages",
            "activePublicationWorkflows",
            "temporaryPathAdversary",
            "cleanup",
        },
        "security report artifact leg",
    )
    if (
        artifact["status"] != "SCAN_CLEAN"
        or security_integer(
            artifact["exitStatus"],
            "security report artifact exit status",
        )
        != 0
        or artifact["archiveUnder50MiB"] is not True
        or security_integer(
            artifact["publishableWorkspacePackages"],
            "security report publishable workspace packages",
        )
        != 0
        or security_integer(
            artifact["metadataIncompleteWorkspacePackages"],
            "security report incomplete workspace metadata packages",
        )
        != 0
        or security_integer(
            artifact["activePublicationWorkflows"],
            "security report active publication workflows",
        )
        != 0
        or artifact["temporaryPathAdversary"] != "REFUSED"
        or artifact["cleanup"] != "COMPLETED"
    ):
        fail(
            "security report artifact/archive/metadata/hygiene/cleanup "
            "evidence disagrees"
        )
    if report["commands"] != SECURITY_REPORT_COMMANDS:
        fail("security report exact command list or ordering disagrees")

    digest = sha256_bytes(payload_bytes)
    sidecar = Path(str(path) + ".sha256")
    sidecar_bytes = require_regular_private(sidecar, "security report digest sidecar")
    expected_sidecar = f"{digest}  {path.name}\n".encode("ascii")
    if sidecar_bytes != expected_sidecar:
        fail("security report digest sidecar disagrees")
    return digest, warning_count, exception_count


def validate_security_preflight_receipt(
    receipt: RawReceipt,
    platform_name: str,
    report_path: Path,
    report_sha256: str,
    archive_path: Path,
    exception_count: int,
    warning_count: int,
) -> None:
    parsed = parse_security_preflight_command(receipt.command)
    if parsed is None or receipt.platform != platform_name:
        fail(f"{platform_name} security-preflight receipt grammar disagrees")
    if (
        absolute_without_following_leaf(Path(parsed["archive"]))
        != archive_path
        or absolute_without_following_leaf(Path(parsed["report"]))
        != report_path
    ):
        fail(f"{platform_name} security-preflight receipt artifact paths disagree")
    expected_output = (
        "security preflight "
        f"{security_preflight_receipt_label(exception_count, warning_count)}: "
        f"commit={receipt.candidate_commit} tree={receipt.candidate_tree} "
        f"report_sha256={report_sha256}"
    )
    if receipt.output != expected_output:
        fail(
            f"{platform_name} security-preflight receipt/report digest "
            "binding disagrees"
        )


def select_security_preflight_receipts(
    receipts_by_platform: dict[str, list[RawReceipt]],
    passed_platforms: set[str],
) -> dict[str, RawReceipt]:
    selected: dict[str, RawReceipt] = {}
    for platform_name in PLATFORM_SYSTEM:
        matching = [
            receipt
            for receipt in receipts_by_platform[platform_name]
            if parse_security_preflight_command(receipt.command) is not None
        ]
        expected_count = 1 if platform_name in passed_platforms else 0
        if len(matching) != expected_count:
            fail(
                f"{platform_name} requires exactly {expected_count} canonical "
                "security-preflight command receipts"
            )
        if matching:
            selected[platform_name] = matching[0]
    return selected


def reject_prohibited_keys(value: object, location: str = "plan") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if str(key).replace("_", "").lower() in PROHIBITED_PLAN_KEYS:
                fail(f"{location} contains prohibited gate assertion key: {key}")
            reject_prohibited_keys(nested, f"{location}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            reject_prohibited_keys(nested, f"{location}[{index}]")


def exact_keys(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        observed = sorted(value) if isinstance(value, dict) else type(value).__name__
        fail(f"{label} keys disagree: expected={sorted(keys)} observed={observed}")
    return value


def load_plan(path: Path) -> dict[str, object]:
    payload = require_regular_private(path, "verification assembly plan")
    try:
        plan = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise VerificationError("verification assembly plan is not valid JSON") from exc
    reject_prohibited_keys(plan)
    return exact_keys(
        plan,
        {
            "schemaVersion",
            "candidate",
            "externalActions",
            "receiptPaths",
            "runtimeEvidence",
            "platforms",
            "caseHolds",
            "additionalHolds",
        },
        "verification assembly plan",
    )


def select_group_receipts(
    group: ProofGroup,
    receipts: Iterable[RawReceipt],
) -> list[RawReceipt]:
    return [receipt for receipt in receipts if group.matches(receipt)]


def relative_evidence(root: Path, path: Path) -> dict[str, str]:
    if path.absolute() != path.resolve() or path.is_symlink() or not path.is_file():
        fail(f"supplemental evidence path is absent or unsafe: {path}")
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError as exc:
        raise VerificationError(
            f"supplemental evidence is outside packet root: {path}"
        ) from exc
    return {"path": relative, "sha256": sha256_file(path)}


def parse_platform_paths(values: list[str], label: str) -> dict[str, Path]:
    paths: dict[str, Path] = {}
    for value in values:
        platform_name, separator, raw_path = value.partition("=")
        if (
            separator != "="
            or platform_name not in PLATFORM_SYSTEM
            or not raw_path
            or platform_name in paths
        ):
            fail(
                f"{label} must use one unique linux=PATH or macos=PATH value "
                f"per passed platform"
            )
        paths[platform_name] = absolute_without_following_leaf(Path(raw_path))
    return paths


def expected_clone_creation_output(
    platform_name: str, commit: str, tree: str, marker_sha256: str
) -> str:
    return (
        "FRESH_CLONE_CREATED "
        f"schemaVersion=1 platform={platform_name} "
        f"candidateCommit={commit} candidateTree={tree} "
        f"markerSha256={marker_sha256} externalActions=false"
    )


def expected_clone_verification_output(
    platform_name: str, commit: str, tree: str, marker_sha256: str
) -> str:
    return (
        "FRESH_CLONE_VERIFIED "
        f"schemaVersion=1 platform={platform_name} "
        f"candidateCommit={commit} candidateTree={tree} "
        f"markerSha256={marker_sha256} detachedHead=true worktreeClean=true "
        "shallow=false partialClone=false promisor=false filter=false "
        "externalActions=false"
    )


def validate_clone_provenance(
    packet_root: Path,
    platform_name: str,
    config: dict[str, object],
    receipt_by_id: dict[str, RawReceipt],
    commit: str,
    tree: str,
) -> dict[str, object]:
    creation_id = config["cloneCreationReceiptId"]
    verification_id = config["cloneVerificationReceiptId"]
    marker_value = config["cloneMarkerPath"]
    if (
        not isinstance(creation_id, str)
        or not isinstance(verification_id, str)
        or creation_id == verification_id
        or creation_id not in receipt_by_id
        or verification_id not in receipt_by_id
    ):
        fail(f"{platform_name} clone provenance names unknown command receipts")
    marker_path, marker_relative = safe_relative_path(
        packet_root,
        marker_value,
        f"{platform_name} clone marker",
    )
    creation_receipt = receipt_by_id[creation_id]
    verification_receipt = receipt_by_id[verification_id]
    platform_creations = [
        receipt.receipt_id
        for receipt in receipt_by_id.values()
        if receipt.platform == platform_name
        and parse_clone_creation_command(receipt.command) is not None
    ]
    platform_verifications = [
        receipt.receipt_id
        for receipt in receipt_by_id.values()
        if receipt.platform == platform_name
        and parse_clone_verification_command(receipt.command) is not None
    ]
    if platform_creations != [creation_id] or platform_verifications != [
        verification_id
    ]:
        fail(f"{platform_name} requires exactly one clone creation and verifier receipt")
    creation_command = parse_clone_creation_command(creation_receipt.command)
    verification_command = parse_clone_verification_command(
        verification_receipt.command
    )
    if (
        creation_receipt.platform != platform_name
        or verification_receipt.platform != platform_name
        or creation_command is None
        or creation_command["platform"] != platform_name
        or verification_command is None
    ):
        fail(f"{platform_name} clone provenance receipt grammar disagrees")
    command_marker_paths = [
        Path(creation_command["marker"]),
        Path(verification_command["marker"]),
    ]
    if any(
        path.absolute() != path.resolve() or path.resolve() != marker_path
        for path in command_marker_paths
    ):
        fail(f"{platform_name} clone receipts do not cross-bind the marker path")
    try:
        _, _, marker_sha256 = read_clone_marker(
            marker_path,
            platform_name,
            commit,
            tree,
        )
    except ProvenanceError as exc:
        raise VerificationError(
            f"{platform_name} clone provenance marker refused: {exc}"
        ) from exc
    if creation_receipt.output != expected_clone_creation_output(
        platform_name, commit, tree, marker_sha256
    ):
        fail(f"{platform_name} clone creation receipt output disagrees")
    if verification_receipt.output != expected_clone_verification_output(
        platform_name, commit, tree, marker_sha256
    ):
        fail(f"{platform_name} in-clone verification receipt output disagrees")
    evidence = relative_evidence(packet_root, marker_path)
    if evidence["sha256"] != marker_sha256:
        fail(f"{platform_name} clone marker digest binding disagrees")
    return {
        "platform": platform_name,
        "creationReceiptId": creation_id,
        "verificationReceiptId": verification_id,
        "markerSha256": marker_sha256,
        "evidence": evidence,
    }


def assemble_index(
    repo: Path,
    ref: str,
    plan_path: Path,
    archive_path: Path,
    security_report_paths: dict[str, Path],
    output_path: Path,
) -> dict[str, object]:
    repo = repo.resolve()
    packet_root = output_path.parent.resolve()
    if plan_path.parent.resolve() != packet_root:
        fail("assembly plan and output must share the packet root")
    if output_path.exists() or output_path.is_symlink():
        fail(f"verification index output already exists: {output_path}")
    if not packet_root.is_dir() or packet_root.is_symlink():
        fail("verification index output parent is absent or unsafe")

    commit = git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}").decode().strip()
    tree = git(repo, "rev-parse", f"{commit}^{{tree}}").decode().strip()
    plan = load_plan(plan_path)
    if type(plan.get("schemaVersion")) is not int or plan.get(
        "schemaVersion"
    ) != 1 or plan.get("externalActions") is not False:
        fail("assembly plan schema/externalActions is invalid")
    candidate = exact_keys(plan["candidate"], {"commit", "tree"}, "plan candidate")
    if candidate != {"commit": commit, "tree": tree}:
        fail("assembly plan candidate identity disagrees")

    archive_result = verify_archive(repo, archive_path, commit)
    if archive_result["tree"] != tree:
        fail("archive tree identity disagrees")
    version = product_version(
        commit_file(repo, commit, "crates/omnis-key-cli/Cargo.toml")
    )
    if version != "0.1.0":
        fail(f"candidate product version is not V1: {version}")
    compatibility_version = parse_root_package_version(
        commit_file(repo, commit, "Cargo.toml")
    )
    proposition = commit_file(repo, commit, "release/PROPOSITION.txt").decode(
        "utf-8"
    ).rstrip("\n")
    if proposition != APPROVED_PROPOSITION:
        fail("release proposition drifted")
    changelog = commit_file(repo, commit, "CHANGELOG.md").decode("utf-8")
    if len(re.findall(rf"(?m)^## \[{re.escape(version)}\]", changelog)) != 1:
        fail("CHANGELOG does not name the canonical version exactly once")
    receipt_paths = plan["receiptPaths"]
    if not isinstance(receipt_paths, list) or not receipt_paths:
        fail("assembly plan receiptPaths must be a nonempty array")
    receipts: list[RawReceipt] = []
    observed_paths: set[str] = set()
    observed_ids: set[str] = set()
    for position, value in enumerate(receipt_paths):
        path, relative = safe_relative_path(
            packet_root, value, f"receiptPaths[{position}]"
        )
        if relative in observed_paths:
            fail(f"duplicate raw receipt path: {relative}")
        observed_paths.add(relative)
        receipt = parse_raw_receipt(path, relative, commit, tree)
        if receipt.receipt_id in observed_ids:
            fail(f"duplicate raw receipt ID: {receipt.receipt_id}")
        if not command_is_known(receipt.command):
            fail(
                f"raw receipt uses a command outside the frozen evidence catalog: "
                f"{receipt.receipt_id}"
            )
        validate_exact_command_semantics(receipt)
        observed_ids.add(receipt.receipt_id)
        receipts.append(receipt)
    receipt_by_id = {receipt.receipt_id: receipt for receipt in receipts}
    receipts_by_platform = {
        platform: [receipt for receipt in receipts if receipt.platform == platform]
        for platform in PLATFORM_SYSTEM
    }

    platform_plan = plan["platforms"]
    if not isinstance(platform_plan, list) or len(platform_plan) != 2:
        fail("assembly plan must contain exactly two platform entries")
    platforms: dict[str, dict[str, object]] = {}
    for position, raw_platform in enumerate(platform_plan):
        if (
            not isinstance(raw_platform, dict)
            or not isinstance(raw_platform.get("name"), str)
            or raw_platform.get("name") not in {"linux", "macos"}
        ):
            fail(f"platforms[{position}] is malformed")
        name = str(raw_platform["name"])
        if name in platforms:
            fail(f"duplicate platform entry: {name}")
        status = raw_platform.get("status")
        expected_keys = (
            {
                "name",
                "status",
                "cloneCreationReceiptId",
                "cloneVerificationReceiptId",
                "cloneMarkerPath",
                "toolchainReceiptId",
            }
            if status == "PASS"
            else {"name", "status", "holdId"}
            if status == "HOLD"
            else set()
        )
        if not expected_keys:
            fail(f"platform {name} is skipped or incomplete")
        platforms[name] = exact_keys(
            raw_platform, expected_keys, f"platforms[{position}]"
        )
    if set(platforms) != {"linux", "macos"}:
        fail("both linux and macos platform entries are required")
    passed_platforms = {
        name for name, platform in platforms.items() if platform["status"] == "PASS"
    }
    if not passed_platforms:
        fail("at least one fresh-clone platform must pass")
    clone_provenance = [
        validate_clone_provenance(
            packet_root,
            platform_name,
            platforms[platform_name],
            receipt_by_id,
            commit,
            tree,
        )
        for platform_name in sorted(passed_platforms)
    ]
    if set(security_report_paths) != passed_platforms:
        fail(
            "security-report platforms must exactly match passed platforms: "
            f"reports={sorted(security_report_paths)} "
            f"passed={sorted(passed_platforms)}"
        )
    security_receipts = select_security_preflight_receipts(
        receipts_by_platform,
        passed_platforms,
    )
    security_reports: list[dict[str, object]] = []
    informational_warning_count = 0
    has_proposed_exceptions = False
    for platform_name in sorted(passed_platforms):
        path = security_report_paths[platform_name]
        digest, warning_count, exception_count = validate_security_report(
            path, platform_name, commit, tree, archive_result
        )
        security_receipt = security_receipts[platform_name]
        validate_security_preflight_receipt(
            security_receipt,
            platform_name,
            path,
            digest,
            absolute_without_following_leaf(archive_path),
            exception_count,
            warning_count,
        )
        sidecar = Path(str(path) + ".sha256")
        security_reports.append(
            {
                "platform": platform_name,
                "sha256": digest,
                "informationalWarningCount": warning_count,
                "commandReceiptId": security_receipt.receipt_id,
                "evidence": relative_evidence(packet_root, path),
                "sidecarEvidence": relative_evidence(packet_root, sidecar),
            }
        )
        informational_warning_count += warning_count
        has_proposed_exceptions = has_proposed_exceptions or exception_count > 0

    toolchains: list[dict[str, object]] = []
    for platform_name in sorted(passed_platforms):
        config = platforms[platform_name]
        platform_receipts = receipts_by_platform[platform_name]
        validate_platform_toolchain_binding(platform_receipts, platform_name)
        toolchain_id = config["toolchainReceiptId"]
        if (
            not isinstance(toolchain_id, str)
            or toolchain_id not in receipt_by_id
        ):
            fail(f"{platform_name} platform names an unknown setup receipt")
        toolchain = receipt_by_id[str(toolchain_id)]
        if toolchain.platform != platform_name:
            fail(f"{platform_name} toolchain receipt is cross-platform")
        parsed_toolchain = parse_toolchain(toolchain)
        toolchains.append(
            {
                "platform": platform_name,
                "receiptId": toolchain.receipt_id,
                "trustedToolchainFormat": toolchain.trusted_toolchain_format,
                "trustedToolchainFingerprintSha256": (
                    toolchain.trusted_toolchain_fingerprint_sha256
                ),
                "trustedSupplementalToolPath": (
                    toolchain.trusted_supplemental_tool_path
                ),
                "executables": toolchain.trusted_tools,
                "supplementalExecutables": (
                    toolchain.trusted_supplemental_tools
                ),
                **parsed_toolchain,
                "evidence": {
                    "path": toolchain.relative_path,
                    "sha256": toolchain.sha256,
                },
            }
        )
        command_counts: dict[str, int] = {}
        for receipt in platform_receipts:
            command_counts[receipt.command] = command_counts.get(receipt.command, 0) + 1
        required_platform_commands = (
            REQUIRED_SECTION9_COMMANDS | REQUIRED_ADDITIONAL_COMMANDS
        )
        missing = sorted(
            command
            for command in required_platform_commands
            if command_counts.get(command, 0) != 1
        )
        if missing:
            fail(
                f"{platform_name} lacks exactly one required command receipt: {missing}"
            )
        duplicates = sorted(
            command for command, count in command_counts.items() if count > 1
        )
        if duplicates:
            fail(f"{platform_name} has ambiguous duplicate commands: {duplicates}")

    version_receipt_ids = validate_version_receipts(
        receipts_by_platform, passed_platforms, version, compatibility_version
    )

    runtime_plan = plan["runtimeEvidence"]
    if not isinstance(runtime_plan, list):
        fail("runtimeEvidence must be an array")
    runtime_by_platform: dict[str, tuple[RawReceipt, Path, str]] = {}
    supplemental: list[dict[str, object]] = [
        {
            "id": "assembly-plan",
            "kind": "assembly-plan",
            "evidence": relative_evidence(packet_root, plan_path),
        }
    ]
    for position, raw_runtime in enumerate(runtime_plan):
        runtime = exact_keys(
            raw_runtime,
            {"platform", "receiptId", "path"},
            f"runtimeEvidence[{position}]",
        )
        platform_name = runtime["platform"]
        if not isinstance(platform_name, str) or platform_name not in passed_platforms:
            fail("runtime evidence may only target a passed platform")
        if platform_name in runtime_by_platform:
            fail(f"duplicate runtime evidence platform: {platform_name}")
        receipt_id = runtime["receiptId"]
        if not isinstance(receipt_id, str) or receipt_id not in receipt_by_id:
            fail(f"runtime evidence names unknown command receipt: {receipt_id}")
        command_receipt = receipt_by_id[str(receipt_id)]
        if (
            command_receipt.platform != platform_name
            or command_receipt.command != RUNTIME_COMMAND
        ):
            fail(f"runtime evidence command receipt is not canonical: {receipt_id}")
        rich_path, rich_relative = safe_relative_path(
            packet_root, runtime["path"], f"runtimeEvidence[{position}]"
        )
        rich_bytes = require_regular_private(rich_path, "rich runtime evidence")
        rich_sha = sha256_bytes(rich_bytes)
        if (
            command_receipt.output
            != f"PASS: runtime sovereignty receipt sha256={rich_sha}"
        ):
            fail(f"runtime command/digest binding disagrees: {receipt_id}")
        try:
            rich_payload = json.loads(rich_bytes)
        except json.JSONDecodeError as exc:
            raise VerificationError(
                f"rich runtime evidence is invalid JSON: {rich_relative}"
            ) from exc
        validate_runtime_receipt(rich_payload, str(platform_name), commit, tree)
        runtime_by_platform[str(platform_name)] = (
            command_receipt,
            rich_path,
            rich_relative,
        )
        supplemental.append(
            {
                "id": f"runtime-sovereignty-{platform_name}",
                "kind": "runtime-sovereignty",
                "platform": platform_name,
                "commandReceiptId": receipt_id,
                "evidence": {"path": rich_relative, "sha256": rich_sha},
            }
        )
    if set(runtime_by_platform) != passed_platforms:
        fail("every passed platform requires exactly one rich runtime receipt")

    holds: dict[str, dict[str, object]] = {
        hold_id: {
            "id": hold_id,
            "status": "HOLD",
            "description": description,
            "owner": owner,
        }
        for hold_id, (description, owner) in MANDATORY_HOLDS.items()
    }
    if has_proposed_exceptions:
        holds[PROPOSED_EXCEPTIONS_HOLD_ID] = {
            "id": PROPOSED_EXCEPTIONS_HOLD_ID,
            "status": "HOLD",
            "description": (
                "Proposed RustSec exceptions remain pending independent "
                "review; the builder has not approved them."
            ),
            "owner": "independent-review",
        }
    if informational_warning_count > 0:
        holds[INFORMATIONAL_WARNINGS_HOLD_ID] = {
            "id": INFORMATIONAL_WARNINGS_HOLD_ID,
            "status": "HOLD",
            "description": (
                "The pinned dependency scan reports informational advisories "
                "that remain visible and pending remediation."
            ),
            "owner": "builder",
        }
    demo_hold_id = "HOLD-DEMO-SIGKILL-RECLAMATION-CAPABILITY"
    holds[demo_hold_id]["receiptIds"] = sorted(
        receipt.receipt_id
        for receipt in receipts
        if receipt.command == DEMO_SIGKILL_HOLD_COMMAND
    )
    additional_holds = plan["additionalHolds"]
    if not isinstance(additional_holds, list):
        fail("additionalHolds must be an array")
    for position, raw_hold in enumerate(additional_holds):
        hold = exact_keys(
            raw_hold,
            {"id", "description", "owner", "receiptIds"},
            f"additionalHolds[{position}]",
        )
        hold_id = hold["id"]
        if (
            not isinstance(hold_id, str)
            or re.fullmatch(r"[A-Z0-9][A-Z0-9_]{2,127}", hold_id) is None
            or hold_id in holds
            or hold_id in {
                PROPOSED_EXCEPTIONS_HOLD_ID,
                INFORMATIONAL_WARNINGS_HOLD_ID,
            }
        ):
            fail(f"additional HOLD ID is invalid or duplicated: {hold_id!r}")
        if not isinstance(hold["description"], str) or not hold["description"].strip():
            fail(f"additional HOLD description is absent: {hold_id}")
        if not isinstance(hold["owner"], str) or not hold["owner"].strip():
            fail(f"additional HOLD owner is absent: {hold_id}")
        hold_receipts = hold["receiptIds"]
        if (
            not isinstance(hold_receipts, list)
            or any(
                not isinstance(receipt_id, str) or receipt_id not in receipt_by_id
                for receipt_id in hold_receipts
            )
        ):
            fail(f"additional HOLD has unknown receipt IDs: {hold_id}")
        holds[str(hold_id)] = {
            "id": hold_id,
            "status": "HOLD",
            "description": hold["description"].strip(),
            "owner": hold["owner"].strip(),
            "receiptIds": sorted(set(hold_receipts)),
        }

    for platform_name, config in platforms.items():
        if config["status"] == "HOLD":
            hold_id = config["holdId"]
            if not isinstance(hold_id, str) or hold_id not in holds:
                fail(f"platform HOLD is unnamed: {platform_name}")

    case_holds = plan["caseHolds"]
    if not isinstance(case_holds, dict):
        fail("caseHolds must be an object")
    invalid_case_holds = set(case_holds) - (
        REQUIRED_ADVERSARIAL_CASES - set(FIXED_CASE_HOLDS)
    )
    if invalid_case_holds:
        fail(f"caseHolds contains unknown or fixed cases: {sorted(invalid_case_holds)}")
    for case_id, hold_id in case_holds.items():
        if not isinstance(hold_id, str) or hold_id not in holds:
            fail(f"case HOLD is unnamed: {case_id}")

    adversarial: list[dict[str, object]] = []
    for case_id in sorted(REQUIRED_ADVERSARIAL_CASES):
        if case_id in FIXED_CASE_HOLDS:
            hold_id = FIXED_CASE_HOLDS[case_id]
            adversarial.append(
                {
                    "id": case_id,
                    "status": "HOLD",
                    "holdId": hold_id,
                    "receiptIds": holds[hold_id].get("receiptIds", []),
                }
            )
            continue
        if case_id in {"linux_fresh_clone", "macos_fresh_clone"}:
            platform_name = case_id.removesuffix("_fresh_clone")
            config = platforms[platform_name]
            if config["status"] == "PASS":
                adversarial.append(
                    {
                        "id": case_id,
                        "status": "PASS",
                        "holdId": None,
                        "receiptIds": sorted(
                            [
                                config["cloneCreationReceiptId"],
                                config["cloneVerificationReceiptId"],
                            ]
                        ),
                    }
                )
            else:
                adversarial.append(
                    {
                        "id": case_id,
                        "status": "HOLD",
                        "holdId": config["holdId"],
                        "receiptIds": [
                            receipt.receipt_id
                            for receipt in receipts_by_platform[platform_name]
                        ],
                    }
                )
            continue
        if case_id in case_holds:
            hold_id = str(case_holds[case_id])
            adversarial.append(
                {
                    "id": case_id,
                    "status": "HOLD",
                    "holdId": hold_id,
                    "receiptIds": holds[hold_id].get("receiptIds", []),
                }
            )
            continue

        case_receipt_ids: set[str] = set()
        missing_proofs: list[str] = []
        if case_id == "version_identity":
            case_receipt_ids.update(version_receipt_ids)
        for platform_name in sorted(passed_platforms):
            platform_receipts = receipts_by_platform[platform_name]
            for group_index, group in enumerate(CASE_GROUPS.get(case_id, ())):
                matches = select_group_receipts(group, platform_receipts)
                if len(matches) != 1:
                    missing_proofs.append(
                        f"{platform_name}:command-group-{group_index + 1}"
                    )
                else:
                    case_receipt_ids.add(matches[0].receipt_id)
            if case_id in RUNTIME_REQUIRED_CASES:
                case_receipt_ids.add(runtime_by_platform[platform_name][0].receipt_id)
        if not case_receipt_ids or missing_proofs:
            fail(
                f"adversarial case lacks exact proof and must name a HOLD: "
                f"{case_id} missing={missing_proofs}"
            )
        adversarial.append(
            {
                "id": case_id,
                "status": "PASS",
                "holdId": None,
                "receiptIds": sorted(case_receipt_ids),
            }
        )

    section9 = [
        receipt.index_entry()
        for receipt in receipts
        if receipt.command in REQUIRED_SECTION9_COMMANDS
    ]
    additional = [
        receipt.index_entry()
        for receipt in receipts
        if receipt.command not in REQUIRED_SECTION9_COMMANDS
    ]
    platform_entries = []
    for name in ("linux", "macos"):
        config = platforms[name]
        entry: dict[str, object] = {
            "name": name,
            "status": config["status"],
            "freshClone": config["status"] == "PASS",
            "receiptIds": sorted(
                receipt.receipt_id for receipt in receipts_by_platform[name]
            ),
        }
        if config["status"] == "HOLD":
            entry["holdId"] = config["holdId"]
        platform_entries.append(entry)

    return {
        "schemaVersion": 1,
        "status": "VERIFICATION_COMPLETE_WITH_NAMED_HOLDS",
        "assembly": {
            "tool": "scripts/assemble_verification_index.py",
            "mode": "BUILDER_EVIDENCE_ONLY",
            "verdictIssued": False,
            "clearIssued": False,
            "archive": {
                "sha256": archive_result["sha256"],
                "commit": commit,
                "tree": tree,
            },
            "securityReports": security_reports,
        },
        "candidate": {"commit": commit, "tree": tree},
        "externalActions": False,
        "section9": sorted(section9, key=lambda entry: str(entry["id"])),
        "additionalCommands": sorted(additional, key=lambda entry: str(entry["id"])),
        "cloneProvenance": clone_provenance,
        "supplementalEvidence": supplemental,
        "knownHolds": sorted(holds.values(), key=lambda hold: str(hold["id"])),
        "adversarial": adversarial,
        "platforms": platform_entries,
        "toolchains": toolchains,
        "versionIdentity": {
            "canonical": version,
            "binaryText": f"omnis-key {version}",
            "binaryJson": version,
            "changelog": version,
            "releaseProposition": version,
            "packageMetadata": version,
            "archiveMetadata": str(archive_result["productVersion"]),
            "compatibilityBase": compatibility_version,
            "receiptIds": sorted(version_receipt_ids),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument(
        "--security-report",
        required=True,
        action="append",
        metavar="PLATFORM=PATH",
        help="repeat once for each passed platform",
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--ref", default="HEAD")
    parser.add_argument("--repo", type=Path)
    args = parser.parse_args()

    repo = (args.repo or Path(__file__).resolve().parent.parent).resolve()
    plan = absolute_without_following_leaf(args.plan)
    archive = absolute_without_following_leaf(args.archive)
    output = absolute_without_following_leaf(args.output)
    try:
        security_reports = parse_platform_paths(
            args.security_report, "--security-report"
        )
        index = assemble_index(
            repo, args.ref, plan, archive, security_reports, output
        )
        payload = (
            json.dumps(index, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        atomic_write(output, payload)
    except (VerificationError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"verification index assembly error: {exc}", file=os.sys.stderr)
        return 1
    print(
        "verification index assembled: "
        f"candidate={index['candidate']['commit']} "
        f"tree={index['candidate']['tree']} "
        f"adversarial={len(index['adversarial'])} "
        f"holds={len(index['knownHolds'])} "
        "verdict=NOT_ISSUED clear=NOT_ISSUED"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
