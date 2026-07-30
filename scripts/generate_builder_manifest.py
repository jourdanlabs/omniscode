#!/usr/bin/env python3
"""Generate an explicitly unauthenticated builder-candidate manifest."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import sys
import tarfile
import tempfile

sys.dont_write_bytecode = True

from verify_source_archive import VerificationError, git, verify_archive
from lib.builder_clone_provenance import (
    ProvenanceError,
    read_marker as read_clone_marker,
)

APPROVED_SPEC_SHA256 = "5753be2bd2ff7af6d892381c9294a477eb2d7839ec7f5df886f1096e490d2026"
UPSTREAM_LICENSE_SHA256 = "720443eee2efeda8f9f93a7a6a6f62763c17171106f60df58a35b8ea638fdf60"
APPROVED_PROPOSITION = """OMNIS KEY Local Integrity V1 is a transparently attributed fork of jcode
whose inherited upstream code and JourdanLabs-authored modifications are
offered under MIT.
It adds per-record-bounded, idempotent, hash-linked local evidence receipts.
A terminal ambient-permission decision processed by the SafetySystem
atomically commits the decision and a receipt obligation. Receipt failure
leaves that obligation pending; reconciled status requires the exact matching
receipt. Receipt and bound safety state refuse malformed, partial, internally
inconsistent, orphaned, drifted, or mismatched bytes."""
REQUIRED_SECTION9_COMMANDS = {
    "cargo fmt --all -- --check",
    "cargo check --workspace --all-targets",
    "cargo clippy -p jcode-omnis --all-targets -- -D warnings",
    "cargo clippy -p omnis-key-cli --all-targets -- -D warnings",
    "cargo test -p jcode-omnis",
    "cargo test -p omnis-key-cli",
    "cargo build --locked -p omnis-key-cli --bin omnis-key",
    "cargo test -p jcode-base omnis::tests",
    "cargo test -p jcode-base safety::tests",
    "cargo test -p jcode-base safety::adversarial_tests",
    "cargo test -p jcode --lib cli::omnis::tests",
    "cargo test -p jcode --lib cli::startup::tests",
    "cargo test -p jcode --lib cli::args::tests::omnis_checkpoint_commands_expose_no_authority_override",
    "cargo test --test e2e safety -- --test-threads=1",
}
REQUIRED_VERSION_COMMANDS = {
    "cargo run --locked -q -p omnis-key-cli --bin omnis-key -- --version",
    "cargo run --locked -q -p omnis-key-cli --bin omnis-key -- version --json",
}
FROZEN_IMPLEMENTATION_START = "670955adf1eebb207bc4a4411e5f6083562d167c"
BUILD_JCODE_COMMAND = "cargo build --locked -p jcode --bin jcode"
RUNTIME_COMMAND = (
    "python3 tests/sovereignty/verify_runtime.py "
    "--omnis-key target/debug/omnis-key --jcode target/debug/jcode"
)
RUNTIME_HARNESS_SELF_TEST_COMMAND = (
    "python3 tests/sovereignty/test_verify_runtime_adversarial.py"
)
DEMO_SIGKILL_HOLD_COMMAND = (
    "python3 tests/holds/reproduce_demo_sigkill_reclamation_hold.py "
    "--omnis-key target/debug/omnis-key"
)
WORKSPACE_METADATA_COMMAND = "scripts/check_workspace_metadata.sh"
THIRD_PARTY_INVENTORY_COMMAND = "scripts/check_third_party_inventory.sh"
RELEASE_HYGIENE_COMMAND = "scripts/check_release_hygiene.sh"
BOUNDARY_TEST_COMMAND = "cargo test -p jcode-base omnis::boundary::tests"
CLONE_CREATION_PROGRAM = "scripts/create_builder_fresh_clone.py"
CLONE_VERIFICATION_PROGRAM = "scripts/verify_builder_fresh_clone.py"
SECURITY_PREFLIGHT_PROGRAM = "scripts/security_preflight.sh"
TOOLCHAIN_COMMAND = (
    "uname -a && rustc -Vv && cargo -V && git --version && "
    "python3 --version && cc --version"
)
FULL_WORKSPACE_TEST_COMMAND = "cargo test --workspace --all-targets --locked"
RELEASE_DIFF_GUARDRAIL_COMMAND = (
    "python3 scripts/check_release_diff_guardrails.py "
    f"--base {FROZEN_IMPLEMENTATION_START} --candidate HEAD --check-warnings"
)
GIT_DIFF_CHECK_COMMAND = "git diff --check"
COMMITTED_RANGE_DIFF_CHECK_COMMAND = (
    f"git diff --check {FROZEN_IMPLEMENTATION_START}..HEAD"
)
DEPENDENCY_BOUNDARIES_COMMAND = "python3 scripts/check_dependency_boundaries.py"
ASSEMBLER_SELF_TEST_COMMAND = "python3 scripts/test_assemble_verification_index.py"
ARCHIVE_SELF_TEST_COMMAND = "python3 scripts/test_verify_source_archive.py"
SECURITY_EXCEPTION_BINDING_SELF_TEST_COMMAND = (
    "python3 scripts/test_security_exception_binding.py"
)
REQUIRED_ADDITIONAL_COMMANDS = REQUIRED_VERSION_COMMANDS | {
    BUILD_JCODE_COMMAND,
    RUNTIME_COMMAND,
    RUNTIME_HARNESS_SELF_TEST_COMMAND,
    DEMO_SIGKILL_HOLD_COMMAND,
    WORKSPACE_METADATA_COMMAND,
    THIRD_PARTY_INVENTORY_COMMAND,
    RELEASE_HYGIENE_COMMAND,
    BOUNDARY_TEST_COMMAND,
    TOOLCHAIN_COMMAND,
    FULL_WORKSPACE_TEST_COMMAND,
    RELEASE_DIFF_GUARDRAIL_COMMAND,
    GIT_DIFF_CHECK_COMMAND,
    COMMITTED_RANGE_DIFF_CHECK_COMMAND,
    DEPENDENCY_BOUNDARIES_COMMAND,
    ASSEMBLER_SELF_TEST_COMMAND,
    ARCHIVE_SELF_TEST_COMMAND,
    SECURITY_EXCEPTION_BINDING_SELF_TEST_COMMAND,
}
PROPOSED_EXCEPTIONS_HOLD_ID = (
    "RUSTSEC_PROPOSED_EXCEPTIONS_PENDING_INDEPENDENT_REVIEW"
)
INFORMATIONAL_WARNINGS_HOLD_ID = (
    "RUSTSEC_INFORMATIONAL_WARNINGS_PENDING_REMEDIATION"
)
MANDATORY_EXTERNAL_HOLD_IDS = {
    "HOSTED_CI_NOT_RUN_CAPTAIN_CONTROLLED",
    "GITHUB_GENERATED_TAG_ARCHIVE_NOT_AVAILABLE",
    "SIGNED_RC_AND_AUTHENTICATED_MANIFEST_NOT_CREATED_CAPTAIN_CONTROLLED",
    "HOSTED_SETTINGS_RECEIPT_NOT_CAPTURED_CAPTAIN_CONTROLLED",
    "INDEPENDENT_COLD_GATES_PENDING",
}
REQUIRED_ADVERSARIAL_CASES = {
    "version_identity",
    "offline_fixture_demo",
    "exact_replay",
    "mutated_receipt",
    "partial_and_mid_record_truncation_refusal",
    "valid_prefix_rollback_ceiling",
    "reordered_receipt_refusal",
    "orphaned_safety_receipt_refusal",
    "decision_receipt_mismatch_refusal",
    "receipt_write_failure_reconciliation",
    "canonical_boundary_refusals",
    "exact_allowed_write_snapshots",
    "zero_attempt_network_omnis_and_jcode",
    "hostile_environment_demo_fixture_preservation",
    "credential_free_pty_all_advertised_executables",
    "updater_replacement_refusal",
    "empty_chain_not_yet_evidenced",
    "public_output_redaction",
    "checkpoint_activation_refusal",
    "triggered_workflows",
    "source_archive_fresh_build_under_50mib",
    "third_party_inventory",
    "workspace_metadata_lockout",
    "security_preflight_fault_injection",
    "linux_fresh_clone",
    "macos_fresh_clone",
}
TRUSTED_TOOLCHAIN_FORMAT = "absolute-executables-v1"
TRUSTED_TOOL_NAMES = {
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
}
TRUSTED_SUPPLEMENTAL_TOOL_NAMES = {
    "cargo-audit",
    "cargo-deny",
    "gitleaks",
    "go",
}


def parse_clone_creation_command(command: object) -> dict[str, str] | None:
    if not isinstance(command, str):
        return None
    try:
        arguments = shlex.split(command, posix=True)
    except ValueError:
        return None
    if (
        len(arguments) != 11
        or arguments[0] != CLONE_CREATION_PROGRAM
        or arguments[1] != "--platform"
        or arguments[2] not in {"linux", "macos"}
        or arguments[3:7] != ["--source", ".", "--candidate", "HEAD"]
        or arguments[7] != "--destination"
        or arguments[9] != "--marker"
        or not os.path.isabs(arguments[8])
        or not os.path.isabs(arguments[10])
    ):
        return None
    return {
        "platform": arguments[2],
        "destination": arguments[8],
        "marker": arguments[10],
    }


def parse_clone_verification_command(command: object) -> dict[str, str] | None:
    if not isinstance(command, str):
        return None
    try:
        arguments = shlex.split(command, posix=True)
    except ValueError:
        return None
    if (
        len(arguments) != 3
        or arguments[0] != CLONE_VERIFICATION_PROGRAM
        or arguments[1] != "--marker"
        or not os.path.isabs(arguments[2])
    ):
        return None
    return {"marker": arguments[2]}


def parse_security_preflight_command(command: object) -> dict[str, str] | None:
    if not isinstance(command, str):
        return None
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


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def absolute_without_following(path: Path) -> Path:
    return Path(os.path.abspath(path))


def commit_file(repo: Path, commit: str, path: str) -> bytes:
    return git(repo, "show", f"{commit}:{path}")


def product_version(manifest: bytes) -> str:
    text = manifest.decode("utf-8")
    package_match = re.search(r"(?ms)^\[package\]\s*(.*?)(?=^\[|\Z)", text)
    if not package_match:
        raise VerificationError("omnis-key-cli manifest has no [package] section")
    version_match = re.search(
        r'(?m)^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$',
        package_match.group(1),
    )
    if not version_match:
        raise VerificationError("omnis-key-cli package has no literal semantic version")
    return version_match.group(1)


def archive_files(archive: Path, prefix: str) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    with tarfile.open(archive, "r:*") as handle:
        for member in handle.getmembers():
            if not member.isfile():
                continue
            pure = PurePosixPath(member.name)
            if pure.parts[0] + "/" != prefix:
                raise VerificationError("archive prefix drifted after verification")
            relative = PurePosixPath(*pure.parts[1:]).as_posix()
            source = handle.extractfile(member)
            if source is None:
                raise VerificationError(f"could not read archive member: {relative}")
            data = source.read()
            entries.append(
                {
                    "path": relative,
                    "mode": "100755" if member.mode & 0o111 else "100644",
                    "bytes": len(data),
                    "sha256": sha256_bytes(data),
                }
            )
    return sorted(entries, key=lambda entry: str(entry["path"]))


def atomic_write(path: Path, payload: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise VerificationError(f"output already exists: {path}")
    parent = path.parent.resolve()
    if not parent.is_dir() or parent.is_symlink():
        raise VerificationError("output parent must be an existing non-symlink directory")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".omnis-manifest.", dir=parent)
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


def evidence_file(index_path: Path, value: object, label: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise VerificationError(f"{label} evidence reference is not an object")
    relative = value.get("path")
    expected_sha = value.get("sha256")
    if not isinstance(relative, str) or not relative:
        raise VerificationError(f"{label} evidence path is missing")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise VerificationError(f"{label} evidence path is unsafe: {relative!r}")
    if not isinstance(expected_sha, str) or not re.fullmatch(
        r"[0-9a-f]{64}", expected_sha
    ):
        raise VerificationError(f"{label} evidence SHA-256 is invalid")
    base = index_path.parent.resolve()
    path = base.joinpath(*pure.parts)
    if path.resolve() != path or not path.is_file() or path.is_symlink():
        raise VerificationError(f"{label} evidence is absent or unsafe: {relative}")
    actual_sha = sha256_file(path)
    if actual_sha != expected_sha:
        raise VerificationError(
            f"{label} evidence digest mismatch: {actual_sha} != {expected_sha}"
        )
    return {"path": relative, "sha256": actual_sha}


def evidence_path(index_path: Path, value: object, label: str) -> Path:
    validated = evidence_file(index_path, value, label)
    return index_path.parent.resolve().joinpath(
        *PurePosixPath(validated["path"]).parts
    )


def rederive_verification_index(
    index_path: Path,
    index: dict[str, object],
    repo: Path,
    archive_path: Path,
    security_report_paths: dict[str, Path],
    commit: str,
) -> None:
    trusted_assembler = repo.resolve() / "scripts" / "assemble_verification_index.py"
    if (
        not trusted_assembler.is_file()
        or trusted_assembler.is_symlink()
        or trusted_assembler.read_bytes()
        != commit_file(
            repo.resolve(),
            commit,
            "scripts/assemble_verification_index.py",
        )
    ):
        raise VerificationError(
            "trusted verification-index assembler differs from the candidate"
        )
    assembler_module = importlib.import_module("assemble_verification_index")
    module_path = Path(str(assembler_module.__file__)).resolve()
    if module_path != trusted_assembler:
        raise VerificationError(
            "trusted verification-index assembler resolved outside the candidate"
        )

    supplemental = index.get("supplementalEvidence")
    if not isinstance(supplemental, list):
        raise VerificationError(
            "verification index cannot be rederived without supplemental evidence"
        )
    assembly_plans = [
        item
        for item in supplemental
        if isinstance(item, dict)
        and item.get("id") == "assembly-plan"
        and item.get("kind") == "assembly-plan"
    ]
    if len(assembly_plans) != 1:
        raise VerificationError(
            "verification index cannot identify exactly one raw assembly plan"
        )
    plan_path = evidence_path(
        index_path,
        assembly_plans[0].get("evidence"),
        "raw assembly plan",
    )

    assembly = index.get("assembly")
    indexed_reports = (
        assembly.get("securityReports") if isinstance(assembly, dict) else None
    )
    if not isinstance(indexed_reports, list):
        raise VerificationError(
            "verification index cannot identify bound security reports"
        )
    bound_security_paths: dict[str, Path] = {}
    for position, report in enumerate(indexed_reports):
        if not isinstance(report, dict) or report.get("platform") not in {
            "linux",
            "macos",
        }:
            raise VerificationError(
                "verification index has malformed bound security-report identity"
            )
        platform = str(report["platform"])
        if platform in bound_security_paths:
            raise VerificationError(
                f"verification index duplicates a bound security report: {platform}"
            )
        bound_security_paths[platform] = evidence_path(
            index_path,
            report.get("evidence"),
            f"bound security report[{position}]",
        )
    normalized_supplied = {
        platform: path.resolve()
        for platform, path in security_report_paths.items()
    }
    if bound_security_paths != normalized_supplied:
        raise VerificationError(
            "verification index security reports differ from manifest inputs"
        )

    packet_root = index_path.parent.resolve()
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".manifest-reassembly.", dir=packet_root
    )
    os.close(descriptor)
    reassembly_output = Path(temporary_name)
    reassembly_output.unlink()
    try:
        derived = assembler_module.assemble_index(
            repo.resolve(),
            commit,
            plan_path,
            archive_path.resolve(),
            normalized_supplied,
            reassembly_output,
        )
    finally:
        if reassembly_output.exists() or reassembly_output.is_symlink():
            reassembly_output.unlink()
    if derived != index:
        raise VerificationError(
            "verification index differs from deterministic raw-receipt reassembly"
        )


def validate_verification_index(
    index_path: Path,
    commit: str,
    tree: str,
    version: str,
    *,
    repo: Path | None = None,
    archive_path: Path | None = None,
    security_report_paths: dict[str, Path] | None = None,
) -> tuple[dict[str, object], list[dict[str, str]]]:
    if not index_path.is_file() or index_path.is_symlink():
        raise VerificationError(
            "verification index must be a regular non-symlink file"
        )
    index = json.loads(index_path.read_text(encoding="utf-8"))
    if not isinstance(index, dict) or index.get("schemaVersion") != 1:
        raise VerificationError("verification index schema is unsupported")
    if index.get("status") not in {
        "VERIFICATION_COMPLETE",
        "VERIFICATION_COMPLETE_WITH_NAMED_HOLDS",
    }:
        raise VerificationError("verification index is not complete")
    if index.get("candidate") != {"commit": commit, "tree": tree}:
        raise VerificationError("verification index candidate identity mismatch")
    if index.get("externalActions") is not False:
        raise VerificationError("verification index must record externalActions=false")
    prohibited_gate_keys = {
        "authenticated",
        "builderIssuedClear",
        "clear",
        "independentGate",
        "verdict",
    }
    present_gate_keys = sorted(prohibited_gate_keys & set(index))
    if present_gate_keys:
        raise VerificationError(
            f"verification index contains prohibited gate assertions: "
            f"{present_gate_keys}"
        )
    assembly = index.get("assembly")
    if (
        not isinstance(assembly, dict)
        or assembly.get("tool") != "scripts/assemble_verification_index.py"
        or assembly.get("mode") != "BUILDER_EVIDENCE_ONLY"
        or assembly.get("verdictIssued") is not False
        or assembly.get("clearIssued") is not False
    ):
        raise VerificationError(
            "verification index lacks builder-only assembly identity"
        )
    assembly_archive = assembly.get("archive")
    if (
        not isinstance(assembly_archive, dict)
        or assembly_archive.get("commit") != commit
        or assembly_archive.get("tree") != tree
        or not re.fullmatch(
            r"[0-9a-f]{64}", str(assembly_archive.get("sha256", ""))
        )
    ):
        raise VerificationError("verification index assembly archive identity disagrees")
    assembly_security = assembly.get("securityReports")
    if not isinstance(assembly_security, list) or not assembly_security:
        raise VerificationError(
            "verification index assembly security reports are absent"
        )
    assembly_security_platforms: set[str] = set()
    assembly_security_receipt_ids: dict[str, str] = {}
    assembly_security_bound_files: list[dict[str, str]] = []
    for position, report in enumerate(assembly_security):
        if not isinstance(report, dict) or set(report) != {
            "platform",
            "sha256",
            "informationalWarningCount",
            "commandReceiptId",
            "evidence",
            "sidecarEvidence",
        }:
            raise VerificationError(
                "verification index assembly security report is malformed"
            )
        platform = report.get("platform")
        command_receipt_id = report.get("commandReceiptId")
        if (
            platform not in {"linux", "macos"}
            or platform in assembly_security_platforms
            or not re.fullmatch(r"[0-9a-f]{64}", str(report.get("sha256", "")))
            or type(report.get("informationalWarningCount")) is not int
            or report["informationalWarningCount"] < 0
            or not isinstance(command_receipt_id, str)
            or not command_receipt_id
        ):
            raise VerificationError(
                "verification index assembly security identity is malformed"
            )
        report_evidence = evidence_file(
            index_path,
            report.get("evidence"),
            f"assembly.securityReports[{position}]",
        )
        if report_evidence["sha256"] != report["sha256"]:
            raise VerificationError(
                f"assembly security report digest disagrees: {platform}"
            )
        assembly_security_bound_files.extend(
            [
                report_evidence,
                evidence_file(
                    index_path,
                    report.get("sidecarEvidence"),
                    f"assembly.securityReports[{position}].sidecar",
                ),
            ]
        )
        assembly_security_platforms.add(str(platform))
        assembly_security_receipt_ids[str(platform)] = command_receipt_id

    receipts = index.get("section9")
    if not isinstance(receipts, list):
        raise VerificationError("verification index section9 receipts are absent")
    commands: set[str] = set()
    receipt_ids: set[str] = set()
    receipts_by_id: dict[str, dict[str, object]] = {}
    receipt_evidence_by_id: dict[str, dict[str, str]] = {}
    command_platform_pairs: set[tuple[str, str]] = set()
    bound_files: list[dict[str, str]] = list(assembly_security_bound_files)
    for position, receipt in enumerate(receipts):
        if not isinstance(receipt, dict):
            raise VerificationError("section9 receipt is not an object")
        receipt_id = receipt.get("id")
        command = receipt.get("command")
        if not isinstance(receipt_id, str) or not receipt_id:
            raise VerificationError("section9 receipt ID is missing")
        if receipt_id in receipt_ids:
            raise VerificationError(f"duplicate section9 receipt ID: {receipt_id}")
        if not isinstance(command, str) or not command:
            raise VerificationError(f"section9 command is missing for {receipt_id}")
        platform = receipt.get("platform")
        if platform not in {"linux", "macos"}:
            raise VerificationError(
                f"section9 receipt platform is malformed: {receipt_id}"
            )
        command_platform_pair = (str(platform), command)
        if command_platform_pair in command_platform_pairs:
            raise VerificationError(
                f"duplicate section9 command/platform receipt: {command_platform_pair}"
            )
        if receipt.get("status") != "PASS" or receipt.get("exitStatus") != 0:
            raise VerificationError(f"section9 command did not pass: {command}")
        if re.fullmatch(
            r"[0-9a-f]{64}",
            str(receipt.get("trustedToolchainFingerprintSha256", "")),
        ) is None:
            raise VerificationError(
                f"section9 receipt lacks a trusted toolchain binding: {receipt_id}"
            )
        receipt_ids.add(receipt_id)
        receipts_by_id[receipt_id] = receipt
        command_platform_pairs.add(command_platform_pair)
        commands.add(command)
        validated_evidence = evidence_file(
            index_path, receipt.get("evidence"), f"section9[{position}]"
        )
        receipt_evidence_by_id[receipt_id] = validated_evidence
        bound_files.append(validated_evidence)
    missing_commands = sorted(REQUIRED_SECTION9_COMMANDS - commands)
    if missing_commands:
        raise VerificationError(
            f"verification index lacks Section 9 commands: {missing_commands}"
        )

    additional_receipts = index.get("additionalCommands")
    if not isinstance(additional_receipts, list):
        raise VerificationError("verification index additionalCommands are absent")
    additional_commands: set[str] = set()
    for position, receipt in enumerate(additional_receipts):
        if not isinstance(receipt, dict):
            raise VerificationError("additional command receipt is not an object")
        receipt_id = receipt.get("id")
        command = receipt.get("command")
        if not isinstance(receipt_id, str) or not receipt_id:
            raise VerificationError("additional command receipt ID is missing")
        if receipt_id in receipt_ids:
            raise VerificationError(f"duplicate command receipt ID: {receipt_id}")
        if not isinstance(command, str) or not command:
            raise VerificationError(f"additional command is missing for {receipt_id}")
        platform = receipt.get("platform")
        if platform not in {"linux", "macos"}:
            raise VerificationError(
                f"additional command platform is malformed: {receipt_id}"
            )
        command_platform_pair = (str(platform), command)
        if command_platform_pair in command_platform_pairs:
            raise VerificationError(
                f"duplicate additional command/platform receipt: "
                f"{command_platform_pair}"
            )
        if receipt.get("status") != "PASS" or receipt.get("exitStatus") != 0:
            raise VerificationError(f"additional command did not pass: {command}")
        if re.fullmatch(
            r"[0-9a-f]{64}",
            str(receipt.get("trustedToolchainFingerprintSha256", "")),
        ) is None:
            raise VerificationError(
                f"additional receipt lacks a trusted toolchain binding: {receipt_id}"
            )
        receipt_ids.add(receipt_id)
        receipts_by_id[receipt_id] = receipt
        command_platform_pairs.add(command_platform_pair)
        additional_commands.add(command)
        validated_evidence = evidence_file(
            index_path,
            receipt.get("evidence"),
            f"additionalCommands[{position}]",
        )
        receipt_evidence_by_id[receipt_id] = validated_evidence
        bound_files.append(validated_evidence)
    missing_additional_commands = sorted(
        REQUIRED_ADDITIONAL_COMMANDS - additional_commands
    )
    if missing_additional_commands:
        raise VerificationError(
            "verification index lacks required additional commands: "
            f"{missing_additional_commands}"
        )
    for platform, receipt_id in assembly_security_receipt_ids.items():
        receipt = receipts_by_id.get(receipt_id)
        parsed_command = (
            parse_security_preflight_command(receipt.get("command"))
            if isinstance(receipt, dict)
            else None
        )
        if (
            receipt is None
            or receipt.get("platform") != platform
            or parsed_command is None
        ):
            raise VerificationError(
                f"assembly security report command receipt is not canonical: "
                f"{platform}"
            )

    clone_provenance = index.get("cloneProvenance")
    if not isinstance(clone_provenance, list) or not clone_provenance:
        raise VerificationError("verification index clone provenance is absent")
    clone_platforms: set[str] = set()
    clone_receipts_by_platform: dict[str, set[str]] = {}
    for position, entry in enumerate(clone_provenance):
        if not isinstance(entry, dict) or set(entry) != {
            "platform",
            "creationReceiptId",
            "verificationReceiptId",
            "markerSha256",
            "evidence",
        }:
            raise VerificationError("clone provenance entry is malformed")
        platform = entry.get("platform")
        creation_id = entry.get("creationReceiptId")
        verification_id = entry.get("verificationReceiptId")
        marker_sha = entry.get("markerSha256")
        if (
            platform not in {"linux", "macos"}
            or platform in clone_platforms
            or not isinstance(creation_id, str)
            or not isinstance(verification_id, str)
            or creation_id == verification_id
            or creation_id not in receipt_ids
            or verification_id not in receipt_ids
            or not re.fullmatch(r"[0-9a-f]{64}", str(marker_sha))
        ):
            raise VerificationError("clone provenance identity is malformed")
        creation_receipt = receipts_by_id[creation_id]
        verification_receipt = receipts_by_id[verification_id]
        creation_command = parse_clone_creation_command(
            creation_receipt.get("command")
        )
        verification_command = parse_clone_verification_command(
            verification_receipt.get("command")
        )
        if (
            creation_receipt.get("platform") != platform
            or verification_receipt.get("platform") != platform
            or creation_command is None
            or creation_command["platform"] != platform
            or verification_command is None
            or Path(creation_command["marker"]).resolve()
            != Path(verification_command["marker"]).resolve()
        ):
            raise VerificationError(
                f"clone provenance command binding disagrees: {platform}"
            )
        marker_evidence = evidence_file(
            index_path,
            entry.get("evidence"),
            f"cloneProvenance[{position}]",
        )
        if marker_evidence["sha256"] != marker_sha:
            raise VerificationError(
                f"clone provenance marker digest disagrees: {platform}"
            )
        marker_path = index_path.parent.resolve().joinpath(
            *PurePosixPath(marker_evidence["path"]).parts
        )
        if (
            marker_path.resolve() != Path(creation_command["marker"]).resolve()
            or marker_path.resolve()
            != Path(verification_command["marker"]).resolve()
        ):
            raise VerificationError(
                f"clone provenance marker path disagrees: {platform}"
            )
        try:
            _, _, observed_marker_sha = read_clone_marker(
                marker_path,
                str(platform),
                commit,
                tree,
            )
        except ProvenanceError as exc:
            raise VerificationError(
                f"clone provenance marker refused: {platform}: {exc}"
            ) from exc
        if observed_marker_sha != marker_sha:
            raise VerificationError(
                f"clone provenance marker content disagrees: {platform}"
            )
        clone_platforms.add(str(platform))
        clone_receipts_by_platform[str(platform)] = {
            creation_id,
            verification_id,
        }
        bound_files.append(marker_evidence)

    known_holds = index.get("knownHolds")
    if not isinstance(known_holds, list):
        raise VerificationError("knownHolds must be an array")
    hold_ids: set[str] = set()
    for hold in known_holds:
        if (
            not isinstance(hold, dict)
            or hold.get("status") != "HOLD"
            or not isinstance(hold.get("id"), str)
            or not hold["id"]
            or not isinstance(hold.get("description"), str)
            or not hold["description"]
            or not isinstance(hold.get("owner"), str)
            or not hold["owner"]
        ):
            raise VerificationError("known HOLD is malformed or unnamed")
        if hold["id"] in hold_ids:
            raise VerificationError(f"duplicate HOLD ID: {hold['id']}")
        hold_ids.add(hold["id"])
        if "evidence" in hold:
            bound_files.append(
                evidence_file(
                    index_path, hold["evidence"], f"known HOLD {hold['id']}"
                )
            )
        if "receiptIds" in hold and (
            not isinstance(hold["receiptIds"], list)
            or any(
                not isinstance(receipt_id, str) or receipt_id not in receipt_ids
                for receipt_id in hold["receiptIds"]
            )
        ):
            raise VerificationError(
                f"known HOLD has unknown command receipts: {hold['id']}"
            )
    expected_index_status = (
        "VERIFICATION_COMPLETE_WITH_NAMED_HOLDS"
        if known_holds
        else "VERIFICATION_COMPLETE"
    )
    if index.get("status") != expected_index_status:
        raise VerificationError("verification status and known HOLDs disagree")
    missing_external_holds = sorted(MANDATORY_EXTERNAL_HOLD_IDS - hold_ids)
    if missing_external_holds:
        raise VerificationError(
            f"verification index omits external-action HOLDs: "
            f"{missing_external_holds}"
        )

    supplemental = index.get("supplementalEvidence")
    if not isinstance(supplemental, list) or not supplemental:
        raise VerificationError("verification index supplemental evidence is absent")
    supplemental_ids: set[str] = set()
    assembly_plan_count = 0
    runtime_supplemental_platforms: set[str] = set()
    for position, item in enumerate(supplemental):
        if not isinstance(item, dict):
            raise VerificationError("supplemental evidence entry is malformed")
        item_id = item.get("id")
        kind = item.get("kind")
        if (
            not isinstance(item_id, str)
            or not item_id
            or item_id in supplemental_ids
        ):
            raise VerificationError("supplemental evidence ID is absent or duplicated")
        supplemental_ids.add(item_id)
        if kind == "assembly-plan":
            if set(item) != {"id", "kind", "evidence"}:
                raise VerificationError("assembly-plan supplemental evidence drifted")
            assembly_plan_count += 1
        elif kind == "runtime-sovereignty":
            if set(item) != {
                "id",
                "kind",
                "platform",
                "commandReceiptId",
                "evidence",
            }:
                raise VerificationError(
                    "runtime-sovereignty supplemental evidence drifted"
                )
            platform = item.get("platform")
            command_receipt_id = item.get("commandReceiptId")
            if (
                platform not in {"linux", "macos"}
                or platform in runtime_supplemental_platforms
                or not isinstance(command_receipt_id, str)
                or command_receipt_id not in receipt_ids
                or receipts_by_id[command_receipt_id].get("platform") != platform
                or receipts_by_id[command_receipt_id].get("command")
                != (
                    "python3 tests/sovereignty/verify_runtime.py "
                    "--omnis-key target/debug/omnis-key --jcode target/debug/jcode"
                )
            ):
                raise VerificationError(
                    "runtime-sovereignty supplemental binding is invalid"
                )
            runtime_supplemental_platforms.add(str(platform))
        else:
            raise VerificationError(f"unknown supplemental evidence kind: {kind}")
        bound_files.append(
            evidence_file(
                index_path,
                item.get("evidence"),
                f"supplementalEvidence[{position}]",
            )
        )
    if assembly_plan_count != 1:
        raise VerificationError(
            "verification index must bind exactly one assembly plan"
        )

    adversarial = index.get("adversarial")
    if not isinstance(adversarial, list):
        raise VerificationError("adversarial coverage is absent")
    observed_cases: set[str] = set()
    for case in adversarial:
        if not isinstance(case, dict) or not isinstance(case.get("id"), str):
            raise VerificationError("adversarial case is malformed")
        case_id = case["id"]
        if case_id in observed_cases:
            raise VerificationError(f"duplicate adversarial case: {case_id}")
        observed_cases.add(case_id)
        status = case.get("status")
        case_receipts = case.get("receiptIds")
        if not isinstance(case_receipts, list) or any(
            not isinstance(item, str) or item not in receipt_ids
            for item in case_receipts
        ):
            raise VerificationError(
                f"adversarial case has unknown receipt IDs: {case_id}"
            )
        if status == "PASS":
            if not case_receipts:
                raise VerificationError(
                    f"adversarial PASS has no command receipt: {case_id}"
                )
            if case.get("holdId") is not None:
                raise VerificationError(
                    f"adversarial PASS incorrectly names a HOLD: {case_id}"
                )
        elif status == "HOLD":
            if case.get("holdId") not in hold_ids:
                raise VerificationError(
                    f"adversarial HOLD is not named in knownHolds: {case_id}"
                )
        else:
            raise VerificationError(
                f"adversarial case is skipped or incomplete: {case_id}"
            )
    if observed_cases != REQUIRED_ADVERSARIAL_CASES:
        raise VerificationError(
            "verification index adversarial case set disagrees: "
            f"missing={sorted(REQUIRED_ADVERSARIAL_CASES - observed_cases)} "
            f"extra={sorted(observed_cases - REQUIRED_ADVERSARIAL_CASES)}"
        )
    cases_by_id = {str(case["id"]): case for case in adversarial}
    expected_fixed_holds = {
        "offline_fixture_demo": (
            "HOLD-DEMO-SIGKILL-RECLAMATION-CAPABILITY"
        ),
        "triggered_workflows": "HOSTED_CI_NOT_RUN_CAPTAIN_CONTROLLED",
        "source_archive_fresh_build_under_50mib": (
            "GITHUB_GENERATED_TAG_ARCHIVE_NOT_AVAILABLE"
        ),
    }
    for case_id, hold_id in expected_fixed_holds.items():
        case = cases_by_id[case_id]
        if case.get("status") != "HOLD" or case.get("holdId") != hold_id:
            raise VerificationError(
                f"builder-only evidence must preserve external HOLD: {case_id}"
            )

    platforms = index.get("platforms")
    if not isinstance(platforms, list):
        raise VerificationError("platform verification is absent")
    observed_platforms: set[str] = set()
    for platform in platforms:
        if not isinstance(platform, dict) or platform.get("name") not in {
            "linux",
            "macos",
        }:
            raise VerificationError("platform entry is malformed")
        name = str(platform["name"])
        if name in observed_platforms:
            raise VerificationError(f"duplicate platform entry: {name}")
        observed_platforms.add(name)
        status = platform.get("status")
        platform_receipts = platform.get("receiptIds")
        if not isinstance(platform_receipts, list) or any(
            not isinstance(item, str) or item not in receipt_ids
            for item in platform_receipts
        ):
            raise VerificationError(f"platform has unknown receipt IDs: {name}")
        exact_platform_receipts = {
            receipt_id
            for receipt_id, receipt in receipts_by_id.items()
            if receipt.get("platform") == name
        }
        if set(platform_receipts) != exact_platform_receipts:
            raise VerificationError(
                f"platform receipt mapping is incomplete or excessive: {name}"
            )
        if status == "PASS":
            if not platform_receipts:
                raise VerificationError(f"platform PASS has no receipts: {name}")
            if platform.get("freshClone") is not True:
                raise VerificationError(f"platform PASS is not a fresh clone: {name}")
        elif status == "HOLD":
            if platform.get("holdId") not in hold_ids:
                raise VerificationError(f"platform HOLD is unnamed: {name}")
        else:
            raise VerificationError(f"platform is skipped or incomplete: {name}")
    if observed_platforms != {"linux", "macos"}:
        raise VerificationError("both linux and macos platform entries are required")

    toolchains = index.get("toolchains")
    if not isinstance(toolchains, list) or not toolchains:
        raise VerificationError("toolchain receipts are absent")
    toolchain_platforms: set[str] = set()
    for position, toolchain in enumerate(toolchains):
        if (
            not isinstance(toolchain, dict)
            or toolchain.get("platform") not in {"linux", "macos"}
        ):
            raise VerificationError("toolchain entry is malformed")
        platform = str(toolchain["platform"])
        if platform in toolchain_platforms:
            raise VerificationError(f"duplicate toolchain platform: {platform}")
        toolchain_platforms.add(platform)
        receipt_id = toolchain.get("receiptId")
        executables = toolchain.get("executables")
        supplemental_executables = toolchain.get("supplementalExecutables")
        executable_binding_valid = (
            isinstance(executables, dict)
            and set(executables) == TRUSTED_TOOL_NAMES
            and all(
                isinstance(value, dict)
                and set(value) == {"path", "sha256", "identity"}
                and isinstance(value.get("path"), str)
                and os.path.isabs(value["path"])
                and re.fullmatch(r"[0-9a-f]{64}", str(value.get("sha256", "")))
                is not None
                and isinstance(value.get("identity"), str)
                and bool(value["identity"])
                for value in executables.values()
            )
        )
        supplemental_tool_path = toolchain.get("trustedSupplementalToolPath")
        supplemental_parts = (
            supplemental_tool_path.split(":")
            if isinstance(supplemental_tool_path, str)
            and supplemental_tool_path
            else []
        )
        supplemental_binding_valid = (
            isinstance(supplemental_tool_path, str)
            and all(part and os.path.isabs(part) for part in supplemental_parts)
            and len(set(supplemental_parts)) == len(supplemental_parts)
        )
        supplemental_executable_binding_valid = (
            isinstance(supplemental_executables, dict)
            and (
                (
                    not supplemental_parts
                    and supplemental_executables == {}
                )
                or (
                    bool(supplemental_parts)
                    and set(supplemental_executables)
                    == TRUSTED_SUPPLEMENTAL_TOOL_NAMES
                    and all(
                        isinstance(value, dict)
                        and set(value) == {"path", "sha256", "identity"}
                        and isinstance(value.get("path"), str)
                        and os.path.isabs(value["path"])
                        and str(Path(value["path"]).parent)
                        in supplemental_parts
                        and Path(value["path"]).name == name
                        and re.fullmatch(
                            r"[0-9a-f]{64}",
                            str(value.get("sha256", "")),
                        )
                        is not None
                        and isinstance(value.get("identity"), str)
                        and bool(value["identity"])
                        for name, value in supplemental_executables.items()
                    )
                )
            )
        )
        if (
            not isinstance(receipt_id, str)
            or receipt_id not in receipt_ids
            or receipts_by_id[receipt_id].get("platform") != platform
            or receipts_by_id[receipt_id].get("command")
            != (
                "uname -a && rustc -Vv && cargo -V && git --version && "
                "python3 --version && cc --version"
            )
            or any(
                not isinstance(toolchain.get(key), str) or not toolchain[key]
                for key in {
                    "uname",
                    "rustcVersion",
                    "rustcHost",
                    "cargoVersion",
                    "gitVersion",
                    "pythonVersion",
                    "cCompiler",
                }
            )
            or toolchain.get("trustedToolchainFormat")
            != TRUSTED_TOOLCHAIN_FORMAT
            or re.fullmatch(
                r"[0-9a-f]{64}",
                str(toolchain.get("trustedToolchainFingerprintSha256", "")),
            )
            is None
            or not supplemental_binding_valid
            or not supplemental_executable_binding_valid
            or toolchain.get("trustedToolchainFingerprintSha256")
            != receipts_by_id[receipt_id].get(
                "trustedToolchainFingerprintSha256"
            )
            or not executable_binding_valid
        ):
            raise VerificationError(
                f"toolchain identity/command binding is incomplete: {platform}"
            )
        toolchain_evidence = evidence_file(
            index_path, toolchain.get("evidence"), f"toolchain[{position}]"
        )
        if toolchain_evidence != receipt_evidence_by_id[receipt_id]:
            raise VerificationError(
                f"toolchain evidence does not match its command receipt: {platform}"
            )
        bound_files.append(toolchain_evidence)
    passed_platforms = {
        str(platform["name"])
        for platform in platforms
        if platform.get("status") == "PASS"
    }
    if passed_platforms != toolchain_platforms:
        raise VerificationError(
            "passed platforms and toolchain receipt platforms disagree"
        )
    if passed_platforms != assembly_security_platforms:
        raise VerificationError(
            "passed platforms and full security-report platforms disagree"
        )
    if passed_platforms != clone_platforms:
        raise VerificationError(
            "passed platforms and retained clone-provenance platforms disagree"
        )
    if runtime_supplemental_platforms != passed_platforms:
        raise VerificationError(
            "passed platforms and rich runtime evidence platforms disagree"
        )
    for platform in passed_platforms:
        case = cases_by_id[f"{platform}_fresh_clone"]
        if (
            case.get("status") != "PASS"
            or set(case.get("receiptIds", []))
            != clone_receipts_by_platform[platform]
        ):
            raise VerificationError(
                f"{platform} fresh-clone case does not bind both provenance receipts"
            )
    for platform in passed_platforms:
        platform_section9_commands = {
            str(receipt["command"])
            for receipt in receipts
            if receipt.get("platform") == platform
        }
        missing_platform_section9 = sorted(
            REQUIRED_SECTION9_COMMANDS - platform_section9_commands
        )
        if missing_platform_section9:
            raise VerificationError(
                f"{platform} lacks Section 9 commands: "
                f"{missing_platform_section9}"
            )
        platform_additional_commands = {
            str(receipt["command"])
            for receipt in additional_receipts
            if receipt.get("platform") == platform
        }
        missing_platform_additional = sorted(
            REQUIRED_ADDITIONAL_COMMANDS - platform_additional_commands
        )
        if missing_platform_additional:
            raise VerificationError(
                f"{platform} lacks required additional commands: "
                f"{missing_platform_additional}"
            )

    version_identity = index.get("versionIdentity")
    expected_versions = {
        "canonical": version,
        "binaryText": f"omnis-key {version}",
        "binaryJson": version,
        "changelog": version,
        "releaseProposition": version,
        "packageMetadata": version,
        "archiveMetadata": version,
        "compatibilityBase": "0.61.2",
    }
    if not isinstance(version_identity, dict):
        raise VerificationError("verification index version identity is absent")
    observed_versions = {
        key: version_identity.get(key) for key in expected_versions
    }
    if observed_versions != expected_versions:
        raise VerificationError("verification index version identity disagrees")
    version_receipts = version_identity.get("receiptIds")
    if (
        not isinstance(version_receipts, list)
        or not version_receipts
        or any(
            not isinstance(receipt_id, str) or receipt_id not in receipt_ids
            for receipt_id in version_receipts
        )
    ):
        raise VerificationError("version identity lacks valid command receipts")
    version_receipt_commands = {
        str(receipts_by_id[receipt_id]["command"])
        for receipt_id in version_receipts
    }
    if version_receipt_commands != REQUIRED_VERSION_COMMANDS:
        raise VerificationError(
            "version identity receipt mapping does not bind both version commands"
        )

    if repo is None or archive_path is None or security_report_paths is None:
        raise VerificationError(
            "verification index requires independent raw-reassembly context"
        )
    rederive_verification_index(
        index_path,
        index,
        repo,
        archive_path,
        security_report_paths,
        commit,
    )

    unique_bound_files = {
        (entry["path"], entry["sha256"]): entry for entry in bound_files
    }
    return index, sorted(
        unique_bound_files.values(), key=lambda entry: entry["path"]
    )


def parse_platform_paths(values: list[str], label: str) -> dict[str, Path]:
    paths: dict[str, Path] = {}
    for value in values:
        platform, separator, raw_path = value.partition("=")
        if (
            separator != "="
            or platform not in {"linux", "macos"}
            or not raw_path
            or platform in paths
        ):
            raise VerificationError(
                f"{label} must use one unique linux=PATH or macos=PATH value "
                "per passed platform"
            )
        paths[platform] = absolute_without_following(Path(raw_path))
    return paths


def private_packet_evidence(
    path: Path, packet_root: Path, label: str
) -> tuple[str, str]:
    if (
        path.resolve() != path
        or not path.is_file()
        or path.is_symlink()
        or not stat.S_ISREG(path.stat().st_mode)
        or stat.S_IMODE(path.stat().st_mode) & 0o077
    ):
        raise VerificationError(f"{label} must be a private regular packet file")
    try:
        relative = path.relative_to(packet_root).as_posix()
    except ValueError as exc:
        raise VerificationError(f"{label} must remain inside the packet") from exc
    return relative, sha256_file(path)


def validate_security_report_artifact(
    path: Path,
    platform: str,
    packet_root: Path,
    commit: str,
    tree: str,
    archive_result: dict[str, object],
    version: str,
) -> dict[str, object]:
    relative, digest = private_packet_evidence(
        path, packet_root, f"{platform} security report"
    )
    report = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(report, dict)
        or report.get("externalActions") is not False
    ):
        raise VerificationError(
            f"{platform} security report is malformed or claims external actions"
        )
    dependency = (
        report.get("legs", {}).get("dependency", {})
        if isinstance(report.get("legs"), dict)
        else {}
    )
    warnings = dependency.get("informationalWarnings")
    warning_count = dependency.get("visibleWarningCount")
    proposed_exceptions = dependency.get("proposedExceptions")
    proposed_findings = dependency.get("proposedExceptionFindings")
    exception_count = dependency.get("exceptionCount")
    if (
        not isinstance(proposed_exceptions, list)
        or not isinstance(proposed_findings, list)
        or type(exception_count) is not int
        or exception_count < 0
        or len(proposed_exceptions) != exception_count
        or len(proposed_findings) != exception_count
        or not isinstance(dependency.get("unsuppressedReportSha256"), str)
        or not isinstance(warnings, list)
        or type(warning_count) is not int
        or warning_count != len(warnings)
        or dependency.get("exitStatus") != 0
        or dependency.get("unreviewedVulnerabilityCount") != 0
    ):
        raise VerificationError(
            f"{platform} security report dependency evidence is incomplete"
        )
    if exception_count > 0:
        expected_report_status = (
            "SCAN_COMPLETE_WITH_PROPOSED_EXCEPTIONS_HOLD"
        )
        expected_dependency_status = "PENDING_INDEPENDENT_REVIEW"
        expected_unsuppressed_status = 1
    elif warning_count > 0:
        expected_report_status = "SCAN_COMPLETE_WITH_INFORMATIONAL_WARNINGS"
        expected_dependency_status = (
            "SCAN_COMPLETE_WITH_INFORMATIONAL_WARNINGS"
        )
        expected_unsuppressed_status = 0
    else:
        expected_report_status = "SCAN_COMPLETE"
        expected_dependency_status = "SCAN_CLEAN"
        expected_unsuppressed_status = 0
    if (
        report.get("status") != expected_report_status
        or dependency.get("status") != expected_dependency_status
        or dependency.get("unsuppressedExitStatus")
        != expected_unsuppressed_status
    ):
        raise VerificationError(
            f"{platform} security report dependency status disagrees"
        )
    candidate = report.get("candidate")
    archive = report.get("archive")
    tools = report.get("tools")
    secret_scanner = tools.get("secretScanner") if isinstance(tools, dict) else None
    target = (
        secret_scanner.get("target") if isinstance(secret_scanner, dict) else None
    )
    expected_target_os = {"linux": "linux", "macos": "darwin"}[platform]
    if (
        not isinstance(candidate, dict)
        or candidate.get("commit") != commit
        or candidate.get("tree") != tree
        or not isinstance(archive, dict)
        or archive.get("sha256") != archive_result["sha256"]
        or archive.get("productVersion") != version
        or archive.get("prefix") != archive_result["prefix"]
        or not isinstance(target, dict)
        or target.get("os") != expected_target_os
        or not isinstance(target.get("architecture"), str)
        or not target["architecture"]
    ):
        raise VerificationError(
            f"{platform} security report candidate/archive/platform identity disagrees"
        )
    sidecar = Path(str(path) + ".sha256")
    sidecar_relative, sidecar_digest = private_packet_evidence(
        sidecar, packet_root, f"{platform} security report digest sidecar"
    )
    if sidecar.read_bytes() != f"{digest}  {path.name}\n".encode("ascii"):
        raise VerificationError(
            f"{platform} security report SHA-256 sidecar mismatch"
        )
    return {
        "platform": platform,
        "path": relative,
        "sha256": digest,
        "informationalWarningCount": warning_count,
        "proposedExceptionCount": exception_count,
        "sidecar": {
            "path": sidecar_relative,
            "sha256": sidecar_digest,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument(
        "--security-report",
        required=True,
        action="append",
        metavar="PLATFORM=PATH",
        help="repeat once for each passed platform",
    )
    parser.add_argument("--verification-index", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--ref", default="HEAD")
    parser.add_argument("--repo", type=Path)
    args = parser.parse_args()

    repo = (args.repo or Path(__file__).resolve().parent.parent).resolve()
    archive = absolute_without_following(args.archive)
    verification_index_path = absolute_without_following(args.verification_index)
    output = absolute_without_following(args.output)

    try:
        security_report_paths = parse_platform_paths(
            args.security_report, "--security-report"
        )
        archive_result = verify_archive(repo, archive, args.ref)
        commit = str(archive_result["commit"])
        tree = str(archive_result["tree"])

        spec = commit_file(repo, commit, "docs/OPEN_SOURCE_V1_RELEASE_SPEC.md")
        spec_sha = sha256_bytes(spec)
        if spec_sha != APPROVED_SPEC_SHA256:
            raise VerificationError(
                f"release specification digest drift: {spec_sha} != {APPROVED_SPEC_SHA256}"
            )
        license_sha = sha256_bytes(commit_file(repo, commit, "LICENSE"))
        if license_sha != UPSTREAM_LICENSE_SHA256:
            raise VerificationError("upstream LICENSE is not verbatim")

        version = product_version(
            commit_file(repo, commit, "crates/omnis-key-cli/Cargo.toml")
        )
        if version != "0.1.0":
            raise VerificationError(f"unexpected product version: {version}")

        proposition_bytes = commit_file(repo, commit, "release/PROPOSITION.txt")
        proposition = proposition_bytes.decode("utf-8").rstrip("\n")
        if proposition != APPROVED_PROPOSITION:
            raise VerificationError("release proposition drifted from approved text")
        changelog = commit_file(repo, commit, "CHANGELOG.md").decode("utf-8")
        changelog_versions = re.findall(
            r"(?m)^## \[([0-9]+\.[0-9]+\.[0-9]+)\]", changelog
        )
        if changelog_versions.count(version) != 1:
            raise VerificationError("CHANGELOG does not resolve exactly once to 0.1.0")

        verification_index, evidence_files = validate_verification_index(
            verification_index_path,
            commit,
            tree,
            version,
            repo=repo,
            archive_path=archive,
            security_report_paths=security_report_paths,
        )
        assembly = verification_index["assembly"]
        if assembly["archive"]["sha256"] != archive_result["sha256"]:
            raise VerificationError(
                "verification index assembly archive digest does not match"
            )
        passed_platforms = {
            str(platform["name"])
            for platform in verification_index["platforms"]
            if platform.get("status") == "PASS"
        }
        if set(security_report_paths) != passed_platforms:
            raise VerificationError(
                "manifest security-report platforms must exactly match passed "
                f"platforms: reports={sorted(security_report_paths)} "
                f"passed={sorted(passed_platforms)}"
            )
        packet_root = output.parent.resolve()
        retained_security_reports = [
            validate_security_report_artifact(
                security_report_paths[platform],
                platform,
                packet_root,
                commit,
                tree,
                archive_result,
                version,
            )
            for platform in sorted(passed_platforms)
        ]
        indexed_security_reports = {
            str(report["platform"]): report
            for report in assembly["securityReports"]
        }
        for report in retained_security_reports:
            indexed = indexed_security_reports.get(str(report["platform"]))
            if (
                indexed is None
                or indexed.get("sha256") != report["sha256"]
                or indexed.get("informationalWarningCount")
                != report["informationalWarningCount"]
                or indexed.get("evidence", {}).get("path") != report["path"]
                or indexed.get("sidecarEvidence", {}).get("path")
                != report["sidecar"]["path"]
            ):
                raise VerificationError(
                    "verification index assembly security binding disagrees: "
                    f"{report['platform']}"
                )
        verification_hold_ids = {
            str(hold["id"]) for hold in verification_index["knownHolds"]
        }
        has_informational_warnings = any(
            int(report["informationalWarningCount"]) > 0
            for report in retained_security_reports
        )
        if has_informational_warnings != (
            INFORMATIONAL_WARNINGS_HOLD_ID in verification_hold_ids
        ):
            raise VerificationError(
                "verification index informational-warning HOLD disagrees"
            )
        has_proposed_exceptions = any(
            int(report["proposedExceptionCount"]) > 0
            for report in retained_security_reports
        )
        if has_proposed_exceptions != (
            PROPOSED_EXCEPTIONS_HOLD_ID in verification_hold_ids
        ):
            raise VerificationError(
                "verification index proposed-exception HOLD disagrees"
            )
        verification_index_sha = sha256_file(verification_index_path)

        manifest = {
            "schemaVersion": 1,
            "status": "BUILDER_CANDIDATE_READY",
            "verdict": None,
            "builderIssuedClear": False,
            "authenticated": False,
            "candidate": {
                "commit": commit,
                "tree": tree,
                "tag": None,
                "productVersion": version,
            },
            "proposition": {
                "text": proposition,
                "sha256": sha256_bytes(proposition_bytes),
                "productVersion": version,
            },
            "releaseSpecification": {
                "path": "docs/OPEN_SOURCE_V1_RELEASE_SPEC.md",
                "sha256": spec_sha,
            },
            "license": {
                "path": "LICENSE",
                "sha256": license_sha,
                "verbatimUpstream": True,
            },
            "archive": archive_result,
            "securityReports": retained_security_reports,
            "verificationIndex": {
                "path": verification_index_path.name,
                "sha256": verification_index_sha,
                "status": verification_index["status"],
                "evidenceFiles": evidence_files,
            },
            "knownHolds": verification_index["knownHolds"],
            "knownLimits": [
                "No independent evidence-truth validation",
                "No universal model/tool/action receipts",
                "No hostile same-UID or valid-prefix rollback detection without a retained checkpoint",
                "No installed or active checkpoint authority",
                "Plaintext local state",
                "No production-availability claim",
            ],
            "externalActions": {
                "push": False,
                "tagCreated": False,
                "githubSettingsChanged": False,
                "githubReleaseCreated": False,
                "defaultBranchChanged": False,
                "announcementIssued": False,
            },
            "hostedEvidence": None,
            "independentGate": None,
            "files": archive_files(archive, str(archive_result["prefix"])),
        }
        payload = (
            json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        atomic_write(output, payload)
        manifest_sha = sha256_bytes(payload)
        atomic_write(
            Path(str(output) + ".sha256"),
            f"{manifest_sha}  {output.name}\n".encode("ascii"),
        )
    except (VerificationError, json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
        print(f"manifest error: {exc}", file=os.sys.stderr)
        return 1

    print(
        f"builder manifest generated: commit={commit} tree={tree} "
        f"files={len(manifest['files'])} sha256={manifest_sha}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
