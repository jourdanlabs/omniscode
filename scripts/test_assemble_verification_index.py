#!/usr/bin/env python3
"""Focused adversarial tests for verification-index assembly."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import platform
from pathlib import Path
import shutil
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import assemble_verification_index as assembly
import generate_builder_manifest as manifest
from lib import builder_clone_provenance as clone_provenance
from lib import run_trusted_builder_command as trusted_command
from verify_source_archive import VerificationError


COMMIT = "a" * 40
TREE = "b" * 40


def trusted_tools_fixture(platform_name: str) -> dict[str, dict[str, str]]:
    system = assembly.PLATFORM_SYSTEM[platform_name]
    identities = {
        "bash": "GNU bash, version fixture",
        "cargo": "cargo 1.88.0 (fixture)",
        "cargo-clippy": "clippy 0.1.88 (fixture)",
        "cargo-fmt": "rustfmt 1.8.0 (fixture)",
        "cc": "cc (Fixture GCC) 14.2.0",
        "clippy-driver": "clippy 0.1.88 (fixture)",
        "git": "git version 2.50.0",
        "python3": "Python 3.13.5",
        "rustc": (
            "rustc 1.88.0 (fixture)\\n"
            "host: x86_64-unknown-linux-gnu\\n"
            "release: 1.88.0"
        ),
        "rustfmt": "rustfmt 1.8.0 (fixture)",
        "uname": f"{system} fixture 6.1 x86_64",
    }
    return {
        name: {
            "path": f"/trusted/bin/{name}",
            "sha256": hashlib.sha256(name.encode()).hexdigest(),
            "identity": identities[name],
        }
        for name in assembly.TRUSTED_TOOL_NAMES
    }


def trusted_toolchain_fingerprint(
    tools: dict[str, dict[str, str]],
    supplemental_path: str = "",
    supplemental_tools: dict[str, dict[str, str]] | None = None,
) -> str:
    supplemental_tools = supplemental_tools or {}
    lines = [f"trustedSupplementalToolPath={supplemental_path}\n"]
    for name in assembly.TRUSTED_TOOL_NAMES:
        lines.extend(
            [
                f"trustedTool.{name}.path={tools[name]['path']}\n",
                f"trustedTool.{name}.sha256={tools[name]['sha256']}\n",
                f"trustedTool.{name}.identity={tools[name]['identity']}\n",
            ]
        )
    for name in assembly.TRUSTED_SUPPLEMENTAL_TOOL_NAMES:
        tool = supplemental_tools.get(
            name, {"path": "", "sha256": "", "identity": ""}
        )
        lines.extend(
            [
                f"trustedSupplementalTool.{name}.path={tool['path']}\n",
                f"trustedSupplementalTool.{name}.sha256={tool['sha256']}\n",
                f"trustedSupplementalTool.{name}.identity={tool['identity']}\n",
            ]
        )
    return hashlib.sha256("".join(lines).encode()).hexdigest()


def raw_receipt_payload(
    receipt_id: str,
    platform_name: str,
    command: str,
    output: str,
    *,
    exit_status: int = 0,
    duplicate_result_marker: bool = False,
) -> bytes:
    tools = trusted_tools_fixture(platform_name)
    lines = [
        "schemaVersion=2",
        f"receiptId={receipt_id}",
        f"platform={platform_name}",
        f"candidateCommit={COMMIT}",
        f"candidateTree={TREE}",
        f"command={command}",
        "startedUtc=2026-07-29T00:00:00Z",
        f"trustedToolchainFormat={assembly.TRUSTED_TOOLCHAIN_FORMAT}",
        (
            "trustedToolchainFingerprintSha256="
            f"{trusted_toolchain_fingerprint(tools)}"
        ),
        "trustedSupplementalToolPath=",
    ]
    for name in assembly.TRUSTED_TOOL_NAMES:
        lines.extend(
            [
                f"trustedTool.{name}.path={tools[name]['path']}",
                f"trustedTool.{name}.sha256={tools[name]['sha256']}",
                f"trustedTool.{name}.identity={tools[name]['identity']}",
            ]
        )
    for name in assembly.TRUSTED_SUPPLEMENTAL_TOOL_NAMES:
        lines.extend(
            [
                f"trustedSupplementalTool.{name}.path=",
                f"trustedSupplementalTool.{name}.sha256=",
                f"trustedSupplementalTool.{name}.identity=",
            ]
        )
    result = [
        *lines,
        "--- command output ---",
        output,
        "--- receipt result ---",
        f"exitStatus={exit_status}",
    ]
    if duplicate_result_marker:
        result.extend(["--- receipt result ---", f"exitStatus={exit_status}"])
    result.append("finishedUtc=2026-07-29T00:00:01Z")
    return ("\n".join(result) + "\n").encode()


def install_runner_fixture(repo: Path) -> Path:
    scripts = repo / "scripts"
    library = scripts / "lib"
    library.mkdir(parents=True)
    runner = scripts / "run_builder_receipt.sh"
    shutil.copy2(SCRIPT_DIR / "run_builder_receipt.sh", runner)
    shutil.copy2(
        SCRIPT_DIR / "lib" / "run_trusted_builder_command.py",
        library / "run_trusted_builder_command.py",
    )
    return runner


def receipt_object(
    receipt_id: str,
    platform: str,
    command: str,
    output: str,
) -> assembly.RawReceipt:
    tools = trusted_tools_fixture(platform)
    return assembly.RawReceipt(
        receipt_id=receipt_id,
        platform=platform,
        candidate_commit=COMMIT,
        candidate_tree=TREE,
        command=command,
        started_utc="2026-07-29T00:00:00Z",
        finished_utc="2026-07-29T00:00:01Z",
        exit_status=0,
        output=output,
        path=Path(f"/tmp/{receipt_id}.txt"),
        relative_path=f"receipts/{receipt_id}.txt",
        sha256="c" * 64,
        trusted_toolchain_format=assembly.TRUSTED_TOOLCHAIN_FORMAT,
        trusted_toolchain_fingerprint_sha256=trusted_toolchain_fingerprint(
            tools
        ),
        trusted_supplemental_tool_path="",
        trusted_tools=tools,
        trusted_supplemental_tools={},
    )


def runtime_payload(platform_name: str = "linux") -> dict[str, object]:
    def json_line(value: object) -> str:
        return json.dumps(value, separators=(",", ":")) + "\n"

    def json_result(
        command: str, code: str, ok: bool, data: object
    ) -> str:
        return json_line(
            {
                "schemaVersion": 1,
                "command": command,
                "ok": ok,
                "code": code,
                "data": data,
            }
        )

    cases: list[dict[str, object]] = []
    for name, contract in sorted(assembly.RUNTIME_CASE_CONTRACTS.items()):
        output_kind = contract["outputKind"]
        stdout = ""
        stderr = ""
        if output_kind == "help":
            stdout = "Fixture help\n\nUsage: fixture\n"
        elif output_kind == "omnis-version-text":
            stdout = "omnis-key 0.1.0\njcode compatibility base 0.61.2\n"
        elif output_kind == "jcode-version-text":
            stdout = f"jcode v0.61.2-dev ({COMMIT[:8]}, clean)\n"
        elif output_kind == "version-json":
            stdout = json_result(
                "version",
                "VERSION",
                True,
                {
                    "compatibilityBaseName": "jcode",
                    "compatibilityBaseVersion": "0.61.2",
                    "productVersion": "0.1.0",
                },
            )
        elif output_kind == "parser-error":
            stderr = "error: fixture refusal\n\nUsage: fixture\n"
        elif output_kind == "disabled-surface":
            stderr = (
                "Error: OMNIS_KEY_INHERITED_SURFACE_DISABLED: inherited Jcode "
                f"{contract['disabledSurface']} behavior is disabled in "
                "OMNIS KEY Local Integrity V1\n"
            )
        elif output_kind == "json":
            code = sorted(contract["jsonCodes"])[0]
            data: object = None
            if code == "EMPTY_NOT_YET_EVIDENCED":
                data = {"state": "EMPTY", "entryCount": 0, "headSha256": None}
            elif code == "RECEIPT_CHAIN_VALID":
                data = {"state": "VALID", "entryCount": 1, "headSha256": "1" * 64}
            elif code in {"RECEIPT_APPENDED", "RECEIPT_EXISTING"}:
                data = {
                    "disposition": {
                        "RECEIPT_APPENDED": "APPENDED",
                        "RECEIPT_EXISTING": "EXISTING",
                    }[code],
                    "sequence": 1,
                    "receiptSha256": "2" * 64,
                    "claimCeiling": "local-record",
                }
            elif code in {"SAFETY_RECONCILED", "SAFETY_ALREADY_RECONCILED"}:
                data = {
                    "pendingBefore": 0,
                    "appended": 0,
                    "existing": 0,
                    "pendingAfter": 0,
                }
            stdout = json_result(
                str(contract["jsonCommand"]),
                code,
                contract["exitCode"] == 0,
                data,
            )
        elif output_kind == "demo-json":
            stdout = json_result(
                "demo.integrity",
                "DEMO_INTEGRITY_PASSED",
                True,
                {
                    "fixtureOnly": True,
                    "firstAppend": "APPENDED",
                    "exactReplay": "EXISTING",
                    "validChain": True,
                    "tamperedCopyRefused": True,
                    "tamperRefusalCode": "RECEIPT_CHAIN_INVALID",
                    "executionAuthorized": False,
                },
            )

        pty = output_kind == "pty"
        process_start_count = (
            2
            if name == "jcode-pty-no-argument"
            else 3
            if name == "omnis-pty-no-argument"
            else 1
        )
        execution_attempt_count = 1 if pty else 0
        unix_socket_attempt_count = 3 if pty else 0
        filesystem_call_count = 1 if pty else 0
        trace_event_count = (
            process_start_count
            + execution_attempt_count
            + unix_socket_attempt_count
            + filesystem_call_count
        )
        case: dict[str, object] = {
            "name": name,
            "argv": contract["argv"],
            "exitCode": contract["exitCode"],
            "instrumentation": {
                "networkEvents": [],
                "unixSocketEvents": (
                    ["AF_UNIX", "BIND_AF_UNIX", "CONNECT_AF_UNIX"]
                    if pty
                    else []
                ),
                "credentialEnvironmentAccesses": [],
                "operatorAccessDetected": False,
                "instrumentedProcessCount": 2 if pty else 1,
                "processStartCount": process_start_count,
                "executionAttemptCount": execution_attempt_count,
                "unixSocketAttemptCount": unix_socket_attempt_count,
                "filesystemCallCount": filesystem_call_count,
                "filesystemOperations": {"open-write": 1} if pty else {},
                "filesystemPathClasses": (
                    {"controlled:JCODE_HOME": 1} if pty else {}
                ),
                "traceEventSchema": assembly.RUNTIME_TRACE_EVENT_SCHEMA,
                "traceEventCount": trace_event_count,
                "traceSha256": "c" * 64,
            },
            "stdoutSha256": hashlib.sha256(stdout.encode()).hexdigest(),
            "stderrSha256": (
                None if pty else hashlib.sha256(stderr.encode()).hexdigest()
            ),
            "writeManifest": (
                [
                    "JCODE_HOME:sessions",
                    "JCODE_HOME:sessions/session_pawprint_1785299019551_02b11e4348960c32.bak",
                    "JCODE_HOME:sessions/session_pawprint_1785299019551_02b11e4348960c32.json",
                    "RUNTIME:durable-state",
                    "RUNTIME:jcode-daemon.lock",
                ]
                if pty
                else contract["writeManifest"]
            ),
        }
        if not pty:
            case["stdoutUtf8"] = stdout
            case["stderrUtf8"] = stderr
        if output_kind == "demo-json":
            case["filesystemProof"] = {
                "result": "PASS",
                "selfCreatedRootCount": 1,
                "selfCreatedRootAccessCalls": 1,
                "allowedSystemAccessCalls": 0,
                "controlledRootAccessCalls": 0,
                "preplantedAdversaryAccessCalls": 0,
            }
        if pty:
            case["usableFirstFrame"] = True
            case["firstFramePrintableBytes"] = 40
            case["processInstrumentation"] = {
                "clientImageChain": (
                    ["jcode"]
                    if name == "jcode-pty-no-argument"
                    else ["omnis-key", "jcode"]
                ),
                "clientProcessStartObserved": True,
                "executionAttemptCount": execution_attempt_count,
                "instrumentationPropagationStrips": 0,
                "instrumentedProcessCount": 2,
                "temporaryServerImage": "jcode",
                "temporaryServerProcessStartObserved": True,
                "unexpectedExecutableAttempts": 0,
            }
            case["controlledUnixTransport"] = {
                "bindAttempts": 1,
                "clientConnectOnly": True,
                "connectAttempts": 1,
                "socketCreateAttempts": 1,
                "socketPathClass": "controlled:JCODE_SOCKET",
                "temporaryServerBindOnly": True,
                "unexpectedSocketAttempts": 0,
            }
            case["writeAttemptProof"] = {
                "attemptClasses": ["open-write:JCODE_HOME:fixture"],
                "attemptCount": 1,
                "forbiddenAttemptCount": 0,
            }
            case["hostileStartupProof"] = {
                "fixtureOnly": True,
                "credentialAccountAccesses": 0,
                "protectedFixtureChanges": 0,
                "replacementCandidateExecutions": 0,
                "armedRestartRestoreExecutions": 0,
            }
            case["temporaryServerShutdown"] = {
                "metadataBound": True,
                "processExitObserved": True,
                "metadataRemoved": True,
                "instrumentationLogQuiescent": True,
                "boundedWaitSeconds": 25,
            }
        cases.append(case)
    return {
        "schemaVersion": 1,
        "proposition": "OMNIS KEY Local Integrity V1 fork sovereignty",
        "externalActions": False,
        "gitIdentity": {
            "commit": COMMIT,
            "tree": TREE,
            "worktreeClean": True,
            "developmentDirtyOverride": False,
        },
        "platform": {
            "system": assembly.PLATFORM_SYSTEM[platform_name],
            "machine": "fixture-machine",
        },
        "toolchain": {"python": "3.13.0", "compiler": "fixture cc 1.0"},
        "instrumentationPositiveControl": {
            "result": "PASS",
            "requiredNetworkAndOperatorEvents": sorted(
                assembly.POSITIVE_CONTROL_EVENTS
            ),
            "requiredFilesystemOperations": ["open", "openat", "stat"],
            "requiredMutationOperations": sorted(
                assembly.POSITIVE_CONTROL_MUTATIONS
            ),
            "requiredCredentialEnvironmentReads": sorted(
                assembly.CREDENTIAL_ENVIRONMENT
            ),
            "processStartEvents": 1,
            "executionAttemptEvents": 1,
            "directEnvironmentEnumerationSourceFilesChecked": 1,
            "traceSha256": "d" * 64,
        },
        "binaries": {
            "jcode": {"name": "jcode", "sha256": "e" * 64},
            "omnis-key": {"name": "omnis-key", "sha256": "f" * 64},
        },
        "cases": cases,
        "result": "PASS",
    }


def security_report_payload(platform_name: str = "linux") -> dict[str, object]:
    identity = assembly.SECURITY_PLATFORM_IDENTITIES[platform_name]
    target = {
        "os": identity["os"],
        "architecture": identity["architecture"],
    }
    scan_counts = {
        "release_tree": 42,
        "exact_archive": 42,
        "jourdanlabs_commit_range": 3,
        "reachable_git_history": 7,
        "reachable_git_objects": 100,
        "git_publication_metadata": 4,
    }
    proposed_exceptions = copy.deepcopy(
        assembly.SECURITY_PROPOSED_EXCEPTIONS
    )
    return {
        "schemaVersion": 1,
        "status": "SCAN_COMPLETE",
        "candidate": {
            "commit": COMMIT,
            "tree": TREE,
            "baseCommit": assembly.SECURITY_BASE_COMMIT,
        },
        "archive": {
            "kind": "local-review-source-archive",
            "prefix": "omnis-key-0.1.0/",
            "productVersion": "0.1.0",
            "sha256": "e" * 64,
            "compressedBytes": 12345,
            "fileCount": 42,
        },
        "tools": {
            "secretScanner": {
                "name": "gitleaks",
                "version": "8.30.1",
                "sourceCommit": "83d9cd684c87d95d656c1458ef04895a7f1cbd8e",
                "buildToolchain": "go1.26.5",
                "target": target,
                "executable": "gitleaks",
                "executableSha256": identity["gitleaksSha256"],
                "expectedExecutableSha256": identity["gitleaksSha256"],
                "identityPolicy": assembly.SECURITY_IDENTITY_POLICY,
                "goBuildInfoSha256": "1" * 64,
                "vcsModified": False,
                "configurationPolicy": {
                    "source": "pinned-embedded-defaults",
                    "ambientOverridesCleared": True,
                    "candidateOverrideFiles": 0,
                },
            },
            "dependencyTool": {
                "name": "cargo-audit",
                "version": "0.22.2",
                "target": target,
                "executable": "cargo-audit",
                "executableSha256": identity["cargoAuditSha256"],
                "expectedExecutableSha256": identity["cargoAuditSha256"],
                "identityPolicy": assembly.SECURITY_IDENTITY_POLICY,
            },
            "licenseTool": {
                "name": "cargo-deny",
                "version": "0.20.2",
                "target": target,
                "executable": "cargo-deny",
                "executableSha256": identity["cargoDenySha256"],
                "expectedExecutableSha256": identity["cargoDenySha256"],
                "identityPolicy": assembly.SECURITY_IDENTITY_POLICY,
            },
            "advisoryDatabase": {
                "repository": "https://github.com/RustSec/advisory-db",
                "commit": assembly.SECURITY_ADVISORY_DB_COMMIT,
                "modifiedFiles": 0,
                "stagedFiles": 0,
                "untrackedFiles": 0,
            },
            "runtime": {
                "git": {"version": "git version 2.50.0", "executable": "git"},
                "tar": {"version": "tar fixture 1.0", "executable": "tar"},
                "cargo": {"version": "cargo 1.97.1", "executable": "cargo"},
                "rustc": {"version": "rustc 1.97.1", "executable": "rustc"},
                "go": {
                    "version": (
                        "go version go1.26.5 "
                        f"{identity['os']}/{identity['architecture']}"
                    ),
                    "executable": "go",
                },
                "python": {
                    "version": "Python 3.13.0",
                    "executable": "python3",
                },
                "jq": {"version": "jq-1.7.1", "executable": "jq"},
                "sha256": identity["sha256Tool"],
            },
        },
        "scanSets": {
            "releaseTreeFiles": 42,
            "exactArchiveFiles": 42,
            "jourdanLabsRangeCommits": 3,
            "reachableGitCommits": 7,
            "reachableGitObjects": 100,
            "materializedGitObjects": 100,
            "materializedGitObjectBytes": 4096,
            "materializedGitObjectTypes": {
                "blob": 80,
                "commit": 7,
                "tag": 0,
                "tree": 13,
            },
            "missingOrPromisorGitObjects": 0,
            "shallowRepository": False,
            "partialClone": False,
            "gitObjectFsck": {
                "status": "SCAN_CLEAN",
                "exitStatus": 0,
                "evidenceSha256": "2" * 64,
            },
            "publicationMetadataFiles": 4,
            "submodules": 0,
            "gitReplaceRefs": 0,
            "gitAlternateObjectStores": 0,
            "gitGrafts": 0,
            "gitLfsPointers": 0,
            "gitLfsObjectFiles": 0,
            "inventoriedAssets": 44,
            "workspacePackages": 83,
        },
        "legs": {
            "secret": {
                "status": "SCAN_CLEAN",
                "namedScans": [
                    {
                        "name": name,
                        "scanSetCount": count,
                        "exitStatus": 0,
                        "status": "SCAN_CLEAN",
                        "reportSha256": f"{position + 3:x}" * 64,
                    }
                    for position, (name, count) in enumerate(scan_counts.items())
                ],
                "positiveControl": {
                    "status": "DETECTED_AS_REQUIRED",
                    "exitStatus": 1,
                    "findingCount": 1,
                    "reportSha256": "9" * 64,
                },
                "scanStatusSha256": "a" * 64,
            },
            "dependency": {
                "status": "SCAN_CLEAN",
                "exitStatus": 0,
                "reportSha256": "b" * 64,
                "unsuppressedExitStatus": 0,
                "unsuppressedReportSha256": "d" * 64,
                "unreviewedVulnerabilityCount": 0,
                "visibleWarningCount": 0,
                "informationalWarnings": [],
                "warningCounts": {
                    "unmaintained": 0,
                    "unsound": 0,
                    "notice": 0,
                },
                "exceptionCount": len(proposed_exceptions),
                "proposedExceptionFindings": [
                    {
                        "advisoryId": exception["id"],
                        "package": exception["package"],
                        "version": exception["version"],
                    }
                    for exception in proposed_exceptions
                ],
                "proposedExceptions": proposed_exceptions,
            },
            "license": {
                "status": "SCAN_CLEAN",
                "exitStatus": 0,
                "evidenceSha256": "c" * 64,
                "unknownOrIncompatibleRights": 0,
            },
            "artifact": {
                "status": "SCAN_CLEAN",
                "exitStatus": 0,
                "archiveUnder50MiB": True,
                "publishableWorkspacePackages": 0,
                "metadataIncompleteWorkspacePackages": 0,
                "activePublicationWorkflows": 0,
                "temporaryPathAdversary": "REFUSED",
                "cleanup": "COMPLETED",
            },
        },
        "commands": list(assembly.SECURITY_REPORT_COMMANDS),
        "observedDateUtc": "2026-07-29",
        "externalActions": False,
    }


def clone_marker_payload(platform_name: str = "linux") -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "kind": clone_provenance.MARKER_KIND,
        "platform": platform_name,
        "candidate": {"commit": COMMIT, "tree": TREE},
        "creation": {
            "sourceKind": "local-absolute-path",
            "allowedProtocols": ["file"],
            "ambientGitConfigDisabled": True,
            "cloneArguments": clone_provenance.CLONE_ARGUMENTS,
        },
        "state": {
            "headCommit": COMMIT,
            "headTree": TREE,
            "detachedHead": True,
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
        },
        "toolchain": {
            "git": "git version fixture",
            "python": "Python fixture",
        },
        "externalActions": False,
    }


class RawReceiptTests(unittest.TestCase):
    def test_trusted_command_dispatcher_rejects_shell_operators(self) -> None:
        with self.assertRaisesRegex(
            trusted_command.CommandError, "shell control operators"
        ):
            trusted_command.direct_argv(
                SCRIPT_DIR.parent,
                "git --version && /tmp/forged-evidence",
            )

    def test_clone_creation_and_verification_receipts_bind_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            source = root / "source"
            scripts = source / "scripts"
            library = scripts / "lib"
            output = root / "evidence"
            clone = root / "clone"
            marker = output / "fresh-clone-marker.json"
            creation_receipt_path = output / "created.txt"
            verification_receipt_path = output / "verified.txt"
            library.mkdir(parents=True)
            for relative in (
                Path("create_builder_fresh_clone.py"),
                Path("verify_builder_fresh_clone.py"),
                Path("run_builder_receipt.sh"),
                Path("lib/__init__.py"),
                Path("lib/builder_clone_provenance.py"),
                Path("lib/run_trusted_builder_command.py"),
            ):
                destination = scripts / relative
                shutil.copy2(SCRIPT_DIR / relative, destination)
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(source),
                    "add",
                    "scripts",
                ],
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(source),
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "commit",
                    "-q",
                    "-m",
                    "fixture",
                ],
                check=True,
            )
            output.mkdir(mode=0o700)
            platform_name = "macos" if platform.system() == "Darwin" else "linux"
            creation_command = (
                f"{assembly.CLONE_CREATION_PROGRAM} "
                f"--platform {platform_name} --source . --candidate HEAD "
                f"--destination {clone} --marker {marker}"
            )
            subprocess.run(
                [
                    str(scripts / "run_builder_receipt.sh"),
                    str(source),
                    platform_name,
                    f"{platform_name}-created",
                    str(creation_receipt_path),
                    creation_command,
                ],
                check=True,
            )
            verification_command = (
                f"{assembly.CLONE_VERIFICATION_PROGRAM} --marker {marker}"
            )
            subprocess.run(
                [
                    str(clone / "scripts" / "run_builder_receipt.sh"),
                    str(clone),
                    platform_name,
                    f"{platform_name}-verified",
                    str(verification_receipt_path),
                    verification_command,
                ],
                check=True,
            )
            commit = subprocess.run(
                ["git", "-C", str(clone), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            tree = subprocess.run(
                ["git", "-C", str(clone), "rev-parse", "HEAD^{tree}"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            creation_receipt = assembly.parse_raw_receipt(
                creation_receipt_path,
                "created.txt",
                commit,
                tree,
            )
            verification_receipt = assembly.parse_raw_receipt(
                verification_receipt_path,
                "verified.txt",
                commit,
                tree,
            )
            observed = assembly.validate_clone_provenance(
                output,
                platform_name,
                {
                    "cloneCreationReceiptId": creation_receipt.receipt_id,
                    "cloneVerificationReceiptId": verification_receipt.receipt_id,
                    "cloneMarkerPath": marker.name,
                },
                {
                    creation_receipt.receipt_id: creation_receipt,
                    verification_receipt.receipt_id: verification_receipt,
                },
                commit,
                tree,
            )
            self.assertEqual(
                observed["markerSha256"],
                hashlib.sha256(marker.read_bytes()).hexdigest(),
            )

    def test_tracked_runner_emits_the_parser_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repo = root / "repo"
            output_directory = root / "evidence"
            output = output_directory / "runner.txt"
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            runner = install_runner_fixture(repo)
            subprocess.run(["git", "-C", str(repo), "add", "scripts"], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "commit",
                    "-q",
                    "--allow-empty",
                    "-m",
                    "fixture",
                ],
                check=True,
            )
            output_directory.mkdir(mode=0o700)
            platform_name = "macos" if platform.system() == "Darwin" else "linux"
            subprocess.run(
                [
                    str(runner),
                    str(repo),
                    platform_name,
                    f"{platform_name}-runner-contract",
                    str(output),
                    "printf 'runner-ok\\n'",
                ],
                check=True,
            )
            commit = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            tree = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "HEAD^{tree}"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            parsed = assembly.parse_raw_receipt(
                output, "receipts/runner.txt", commit, tree
            )
            self.assertEqual(parsed.output, "runner-ok")
            self.assertEqual(parsed.exit_status, 0)

    def test_tracked_runner_and_parser_support_silent_success(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repo = root / "repo"
            output_directory = root / "evidence"
            output = output_directory / "silent.txt"
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            runner = install_runner_fixture(repo)
            subprocess.run(["git", "-C", str(repo), "add", "scripts"], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "commit",
                    "-q",
                    "--allow-empty",
                    "-m",
                    "fixture",
                ],
                check=True,
            )
            output_directory.mkdir(mode=0o700)
            platform_name = "macos" if platform.system() == "Darwin" else "linux"
            subprocess.run(
                [
                    str(runner),
                    str(repo),
                    platform_name,
                    f"{platform_name}-silent",
                    str(output),
                    ":",
                ],
                check=True,
            )
            commit = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            tree = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "HEAD^{tree}"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            parsed = assembly.parse_raw_receipt(
                output, "receipts/silent.txt", commit, tree
            )
            self.assertEqual(parsed.output, "")

    def test_tracked_runner_ignores_caller_path_shims(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repo = root / "repo"
            evidence = root / "evidence"
            shims = root / "shims"
            marker = root / "shim-executed"
            output = evidence / "receipt.txt"
            subprocess.run(["/usr/bin/git", "init", "-q", str(repo)], check=True)
            runner = install_runner_fixture(repo)
            subprocess.run(
                ["/usr/bin/git", "-C", str(repo), "add", "scripts"],
                check=True,
            )
            subprocess.run(
                [
                    "/usr/bin/git",
                    "-C",
                    str(repo),
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "commit",
                    "-q",
                    "-m",
                    "fixture",
                ],
                check=True,
            )
            evidence.mkdir(mode=0o700)
            shims.mkdir(mode=0o700)
            for name in (
                "bash",
                "cargo",
                "cc",
                "git",
                "python3",
                "rustc",
                "uname",
            ):
                shim = shims / name
                shim.write_text(
                    "#!/bin/bash\n"
                    f"/usr/bin/printf '%s\\n' {name} >> {shlex.quote(str(marker))}\n"
                    "/usr/bin/printf 'forged tool identity\\n'\n",
                    encoding="utf-8",
                )
                shim.chmod(0o700)
            supplemental_identities = {
                "cargo-audit": "cargo-audit 0.22.2",
                "cargo-deny": "cargo-deny 0.20.2",
                "gitleaks": "8.30.1",
                "go": "go version go1.26.5 fixture/arm64",
            }
            for name, identity in supplemental_identities.items():
                shim = shims / name
                shim.write_text(
                    "#!/bin/bash\n"
                    f"/usr/bin/printf '%s\\n' {shlex.quote(identity)}\n",
                    encoding="utf-8",
                )
                shim.chmod(0o700)
            platform_name = "macos" if platform.system() == "Darwin" else "linux"
            subprocess.run(
                [
                    str(runner),
                    str(repo),
                    platform_name,
                    f"{platform_name}-path-shim",
                    str(output),
                    "git --version",
                ],
                check=True,
                env={
                    **os.environ,
                    "PATH": str(shims),
                    "OMNIS_BUILDER_SUPPLEMENTAL_TOOL_PATH": str(shims),
                },
            )
            self.assertFalse(marker.exists())
            receipt_text = output.read_text(encoding="utf-8")
            self.assertNotIn("forged tool identity", receipt_text)
            self.assertIn("trustedTool.git.path=/usr/bin/git\n", receipt_text)
            self.assertIn(
                f"trustedSupplementalToolPath={shims}\n", receipt_text
            )
            commit = subprocess.run(
                ["/usr/bin/git", "-C", str(repo), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            tree = subprocess.run(
                ["/usr/bin/git", "-C", str(repo), "rev-parse", "HEAD^{tree}"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            parsed = assembly.parse_raw_receipt(
                output, "receipts/path-shim.txt", commit, tree
            )
            self.assertEqual(parsed.trusted_tools["git"]["path"], "/usr/bin/git")
            self.assertEqual(
                set(parsed.trusted_supplemental_tools),
                set(assembly.TRUSTED_SUPPLEMENTAL_TOOL_NAMES),
            )
            self.assertTrue(parsed.output.startswith("git version "))

    def test_copied_receipt_runner_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repo = root / "repo"
            evidence = root / "evidence"
            copied_runner = root / "copied-runner.sh"
            subprocess.run(["/usr/bin/git", "init", "-q", str(repo)], check=True)
            install_runner_fixture(repo)
            subprocess.run(
                ["/usr/bin/git", "-C", str(repo), "add", "scripts"],
                check=True,
            )
            subprocess.run(
                [
                    "/usr/bin/git",
                    "-C",
                    str(repo),
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "commit",
                    "-q",
                    "-m",
                    "fixture",
                ],
                check=True,
            )
            evidence.mkdir(mode=0o700)
            shutil.copy2(repo / "scripts" / "run_builder_receipt.sh", copied_runner)
            platform_name = "macos" if platform.system() == "Darwin" else "linux"
            refused = subprocess.run(
                [
                    str(copied_runner),
                    str(repo),
                    platform_name,
                    f"{platform_name}-copied-runner",
                    str(evidence / "receipt.txt"),
                    "git --version",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(refused.returncode, 2)
            self.assertIn("candidate-tracked script", refused.stderr)
            self.assertFalse((evidence / "receipt.txt").exists())

    def test_platform_suite_uses_the_frozen_command_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repo = root / "repo"
            output = root / "evidence"
            runtime = repo / "target" / "sovereignty" / "runtime-receipt.json"
            marker = root / "linux-fresh-clone-marker.json"
            runner = repo / "scripts" / "run_builder_receipt.sh"
            log = root / "commands.tsv"
            shims = root / "shims"
            shim_marker = root / "suite-shim-executed"
            runtime.parent.mkdir(parents=True)
            runtime.write_text("{}\n", encoding="utf-8")
            runner.parent.mkdir()
            runner.write_text(
                "#!/bin/bash\n"
                "printf '%s\\t%s\\n' \"$3\" \"$5\" >> \"$COMMAND_LOG\"\n",
                encoding="utf-8",
            )
            runner.chmod(0o700)
            shims.mkdir(mode=0o700)
            for name in ("bash", "chmod", "cp", "mkdir"):
                shim = shims / name
                shim.write_text(
                    "#!/bin/bash\n"
                    f"/usr/bin/printf '%s\\n' {name} >> "
                    f"{shlex.quote(str(shim_marker))}\n"
                    "exit 97\n",
                    encoding="utf-8",
                )
                shim.chmod(0o700)
            subprocess.run(
                [
                    str(SCRIPT_DIR / "run_builder_platform_suite.sh"),
                    str(repo),
                    "linux",
                    str(output),
                    str(marker),
                ],
                check=True,
                env={
                    **os.environ,
                    "COMMAND_LOG": str(log),
                    "PATH": str(shims),
                },
            )
            self.assertFalse(shim_marker.exists())
            observed = [
                line.split("\t", 1)
                for line in log.read_text(encoding="utf-8").splitlines()
            ]
            commands = {command for _, command in observed}
            verification_commands = {
                command
                for command in commands
                if assembly.parse_clone_verification_command(command) is not None
            }
            self.assertEqual(len(verification_commands), 1)
            self.assertEqual(
                commands - verification_commands,
                assembly.REQUIRED_SECTION9_COMMANDS
                | assembly.REQUIRED_ADDITIONAL_COMMANDS,
            )
            self.assertEqual(len(observed), len(commands))
            self.assertIn(assembly.TOOLCHAIN_COMMAND, commands)
            self.assertTrue(assembly.REQUIRED_SECTION9_COMMANDS.issubset(commands))
            self.assertTrue(assembly.REQUIRED_VERSION_COMMANDS.issubset(commands))
            self.assertTrue(assembly.REQUIRED_ADDITIONAL_COMMANDS.issubset(commands))
            self.assertIn(assembly.RUNTIME_COMMAND, commands)
            self.assertIn(assembly.BOUNDARY_TEST_COMMAND, commands)
            self.assertIn(assembly.FULL_WORKSPACE_TEST_COMMAND, commands)
            self.assertIn(assembly.RELEASE_DIFF_GUARDRAIL_COMMAND, commands)
            self.assertIn(assembly.GIT_DIFF_CHECK_COMMAND, commands)
            self.assertIn(assembly.COMMITTED_RANGE_DIFF_CHECK_COMMAND, commands)
            self.assertIn(assembly.DEPENDENCY_BOUNDARIES_COMMAND, commands)
            self.assertIn(assembly.ASSEMBLER_SELF_TEST_COMMAND, commands)
            self.assertIn(assembly.ARCHIVE_SELF_TEST_COMMAND, commands)
            self.assertIn(assembly.RUNTIME_HARNESS_SELF_TEST_COMMAND, commands)
            self.assertIn(assembly.DEMO_SIGKILL_HOLD_COMMAND, commands)
            self.assertIn(
                assembly.SECURITY_EXCEPTION_BINDING_SELF_TEST_COMMAND,
                commands,
            )

    def test_parser_derives_identity_exit_and_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "receipt.txt"
            payload = raw_receipt_payload(
                "linux-example",
                "linux",
                "cargo fmt --all -- --check",
                "fixture output",
            )
            path.write_bytes(payload)
            path.chmod(0o600)
            parsed = assembly.parse_raw_receipt(
                path, "receipts/receipt.txt", COMMIT, TREE
            )
            self.assertEqual(parsed.receipt_id, "linux-example")
            self.assertEqual(parsed.output, "fixture output")
            self.assertEqual(parsed.exit_status, 0)
            self.assertEqual(parsed.sha256, hashlib.sha256(payload).hexdigest())

    def test_parser_rejects_injected_result_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "receipt.txt"
            path.write_bytes(
                raw_receipt_payload(
                    "linux-example",
                    "linux",
                    "cargo fmt --all -- --check",
                    "forged",
                    duplicate_result_marker=True,
                )
            )
            path.chmod(0o600)
            with self.assertRaisesRegex(VerificationError, "ambiguous framing"):
                assembly.parse_raw_receipt(
                    path, "receipts/receipt.txt", COMMIT, TREE
                )

    def test_parser_rejects_nonzero_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "receipt.txt"
            path.write_bytes(
                raw_receipt_payload(
                    "linux-example",
                    "linux",
                    "cargo fmt --all -- --check",
                    "failed",
                    exit_status=1,
                )
            )
            path.chmod(0o600)
            with self.assertRaisesRegex(VerificationError, "did not pass"):
                assembly.parse_raw_receipt(
                    path, "receipts/receipt.txt", COMMIT, TREE
                )

    def test_parser_rejects_legacy_receipt_without_trusted_toolchain(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "receipt.txt"
            path.write_text(
                "schemaVersion=1\n"
                "receiptId=linux-example\n"
                "platform=linux\n"
                f"candidateCommit={COMMIT}\n"
                f"candidateTree={TREE}\n"
                "command=cargo fmt --all -- --check\n"
                "startedUtc=2026-07-29T00:00:00Z\n"
                "--- command output ---\n"
                "--- receipt result ---\n"
                "exitStatus=0\n"
                "finishedUtc=2026-07-29T00:00:01Z\n",
                encoding="utf-8",
            )
            path.chmod(0o600)
            with self.assertRaisesRegex(VerificationError, "header length"):
                assembly.parse_raw_receipt(
                    path, "receipts/receipt.txt", COMMIT, TREE
                )

    def test_parser_rejects_mutated_toolchain_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "receipt.txt"
            payload = raw_receipt_payload(
                "linux-example",
                "linux",
                "cargo fmt --all -- --check",
                "",
            ).replace(
                b"trustedTool.git.path=/trusted/bin/git\n",
                b"trustedTool.git.path=/forged/bin/git\n",
            )
            path.write_bytes(payload)
            path.chmod(0o600)
            with self.assertRaisesRegex(
                VerificationError, "toolchain fingerprint disagrees"
            ):
                assembly.parse_raw_receipt(
                    path, "receipts/receipt.txt", COMMIT, TREE
                )


class SemanticValidationTests(unittest.TestCase):
    def test_cargo_semantic_markers_require_ok_not_ignored_or_substrings(self) -> None:
        marker = "concrete_wrong_owned_ledger_is_refused_without_mutation"
        self.assertTrue(
            assembly.cargo_test_marker_passed(
                f"test omnis::boundary::tests::{marker} ... ok",
                marker,
            )
        )
        self.assertFalse(
            assembly.cargo_test_marker_passed(
                f"test omnis::boundary::tests::{marker} ... ignored",
                marker,
            )
        )
        self.assertFalse(
            assembly.cargo_test_marker_passed(
                f"diagnostic mentions {marker} but no test status",
                marker,
            )
        )

    def test_clone_command_grammar_rejects_shell_suffixes(self) -> None:
        creation = (
            f"{assembly.CLONE_CREATION_PROGRAM} --platform linux "
            "--source . --candidate HEAD "
            "--destination /private/tmp/clone "
            "--marker /private/tmp/marker.json"
        )
        verification = (
            f"{assembly.CLONE_VERIFICATION_PROGRAM} "
            "--marker /private/tmp/marker.json"
        )
        self.assertIsNotNone(assembly.parse_clone_creation_command(creation))
        self.assertIsNotNone(
            assembly.parse_clone_verification_command(verification)
        )
        self.assertIsNone(
            assembly.parse_clone_creation_command(creation + "; curl invalid")
        )
        self.assertIsNone(
            assembly.parse_clone_verification_command(
                verification + " --extra invalid"
            )
        )

    def test_tracked_clone_creator_and_verifier_cross_bind_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            source = root / "source"
            destination = root / "clone"
            marker = root / "marker.json"
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(source),
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "commit",
                    "-q",
                    "--allow-empty",
                    "-m",
                    "fixture",
                ],
                check=True,
            )
            platform_name = "macos" if platform.system() == "Darwin" else "linux"
            created = subprocess.run(
                [
                    str(SCRIPT_DIR / "create_builder_fresh_clone.py"),
                    "--platform",
                    platform_name,
                    "--source",
                    str(source),
                    "--candidate",
                    "HEAD",
                    "--destination",
                    str(destination),
                    "--marker",
                    str(marker),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            verified = subprocess.run(
                [
                    str(SCRIPT_DIR / "verify_builder_fresh_clone.py"),
                    "--marker",
                    str(marker),
                ],
                cwd=destination,
                check=True,
                capture_output=True,
                text=True,
            )
            digest = hashlib.sha256(marker.read_bytes()).hexdigest()
            self.assertIn(f"markerSha256={digest}", created.stdout)
            self.assertIn(f"markerSha256={digest}", verified.stdout)
            self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o700)

            subprocess.run(
                [
                    "git",
                    "-C",
                    str(destination),
                    "config",
                    "--local",
                    "remote.origin.promisor",
                    "true",
                ],
                check=True,
            )
            refused = subprocess.run(
                [
                    str(SCRIPT_DIR / "verify_builder_fresh_clone.py"),
                    "--marker",
                    str(marker),
                ],
                cwd=destination,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn("promisor-backed", refused.stderr)

    def test_assembler_cross_binds_clone_receipts_and_marker_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            marker = root / "marker.json"
            payload = (
                json.dumps(
                    clone_marker_payload("linux"),
                    sort_keys=True,
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n"
            ).encode()
            marker.write_bytes(payload)
            marker.chmod(0o600)
            digest = hashlib.sha256(payload).hexdigest()
            destination = root / "clone"
            creation_command = (
                f"{assembly.CLONE_CREATION_PROGRAM} --platform linux "
                "--source . --candidate HEAD "
                f"--destination {destination} --marker {marker}"
            )
            verification_command = (
                f"{assembly.CLONE_VERIFICATION_PROGRAM} --marker {marker}"
            )
            creation = receipt_object(
                "linux-created",
                "linux",
                creation_command,
                assembly.expected_clone_creation_output(
                    "linux", COMMIT, TREE, digest
                ),
            )
            verification = receipt_object(
                "linux-verified",
                "linux",
                verification_command,
                assembly.expected_clone_verification_output(
                    "linux", COMMIT, TREE, digest
                ),
            )
            observed = assembly.validate_clone_provenance(
                root,
                "linux",
                {
                    "cloneCreationReceiptId": creation.receipt_id,
                    "cloneVerificationReceiptId": verification.receipt_id,
                    "cloneMarkerPath": marker.name,
                },
                {
                    creation.receipt_id: creation,
                    verification.receipt_id: verification,
                },
                COMMIT,
                TREE,
            )
            self.assertEqual(observed["markerSha256"], digest)
            drifted = receipt_object(
                "linux-verified",
                "linux",
                verification_command,
                verification.output.replace(digest, "0" * 64),
            )
            with self.assertRaisesRegex(
                VerificationError, "verification receipt output disagrees"
            ):
                assembly.validate_clone_provenance(
                    root,
                    "linux",
                    {
                        "cloneCreationReceiptId": creation.receipt_id,
                        "cloneVerificationReceiptId": drifted.receipt_id,
                        "cloneMarkerPath": marker.name,
                    },
                    {
                        creation.receipt_id: creation,
                        drifted.receipt_id: drifted,
                    },
                    COMMIT,
                    TREE,
                )

    def test_exact_builder_command_semantics_are_fail_closed(self) -> None:
        assembly.validate_exact_command_semantics(
            receipt_object(
                "linux-diff",
                "linux",
                assembly.GIT_DIFF_CHECK_COMMAND,
                "",
            )
        )
        assembly.validate_exact_command_semantics(
            receipt_object(
                "linux-range-diff",
                "linux",
                assembly.COMMITTED_RANGE_DIFF_CHECK_COMMAND,
                "",
            )
        )
        assembly.validate_exact_command_semantics(
            receipt_object(
                "linux-boundaries",
                "linux",
                assembly.DEPENDENCY_BOUNDARIES_COMMAND,
                "dependency boundary check passed",
            )
        )
        assembly.validate_exact_command_semantics(
            receipt_object(
                "linux-self-test",
                "linux",
                assembly.ASSEMBLER_SELF_TEST_COMMAND,
                "Ran 17 tests in 0.123s\n\nOK",
            )
        )
        assembly.validate_exact_command_semantics(
            receipt_object(
                "linux-archive-self-test",
                "linux",
                assembly.ARCHIVE_SELF_TEST_COMMAND,
                "Ran 5 tests in 0.123s\n\nOK",
            )
        )
        assembly.validate_exact_command_semantics(
            receipt_object(
                "linux-runtime-harness-self-test",
                "linux",
                assembly.RUNTIME_HARNESS_SELF_TEST_COMMAND,
                "Ran 11 tests in 0.123s\n\nOK",
            )
        )
        assembly.validate_exact_command_semantics(
            receipt_object(
                "linux-security-exception-self-test",
                "linux",
                assembly.SECURITY_EXCEPTION_BINDING_SELF_TEST_COMMAND,
                "Ran 7 tests in 0.123s\n\nOK",
            )
        )
        assembly.validate_exact_command_semantics(
            receipt_object(
                "linux-demo-hold",
                "linux",
                assembly.DEMO_SIGKILL_HOLD_COMMAND,
                "HOLD_REPRODUCED: "
                "HOLD-DEMO-SIGKILL-RECLAMATION-CAPABILITY "
                "killedRootPrivate=true nextRunReclaimed=false "
                "plausiblePreplantsPreserved=true",
            )
        )
        assembly.validate_exact_command_semantics(
            receipt_object(
                "linux-workspace",
                "linux",
                assembly.FULL_WORKSPACE_TEST_COMMAND,
                "test result: ok. 1 passed; 0 failed",
            )
        )
        guardrail = {
            "schemaVersion": 1,
            "status": "PASS",
            "base": {"commit": assembly.FROZEN_IMPLEMENTATION_START},
            "candidate": {
                "commit": COMMIT,
                "tree": TREE,
                "worktreeMode": False,
            },
            "specSha256": assembly.APPROVED_SPEC_SHA256,
            "thresholdLoc": 1200,
            "warnings": {"checked": True, "addedCount": 0},
            "regressions": [],
        }
        assembly.validate_exact_command_semantics(
            receipt_object(
                "linux-guardrail",
                "linux",
                assembly.RELEASE_DIFF_GUARDRAIL_COMMAND,
                json.dumps(guardrail),
            )
        )
        guardrail["warnings"]["addedCount"] = 1
        with self.assertRaisesRegex(VerificationError, "semantics disagree"):
            assembly.validate_exact_command_semantics(
                receipt_object(
                    "linux-bad-guardrail",
                    "linux",
                    assembly.RELEASE_DIFF_GUARDRAIL_COMMAND,
                    json.dumps(guardrail),
                )
            )
        with self.assertRaisesRegex(VerificationError, "not silent"):
            assembly.validate_exact_command_semantics(
                receipt_object(
                    "linux-bad-diff",
                    "linux",
                    assembly.GIT_DIFF_CHECK_COMMAND,
                    "unexpected.patch:1: trailing whitespace",
                )
            )

    def test_security_report_binds_platform_identity_and_exact_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "linux-security.json"
            payload = (
                json.dumps(
                    security_report_payload("linux"),
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode()
            path.write_bytes(payload)
            path.chmod(0o600)
            digest = hashlib.sha256(payload).hexdigest()
            sidecar = Path(str(path) + ".sha256")
            sidecar.write_text(f"{digest}  {path.name}\n", encoding="ascii")
            sidecar.chmod(0o600)
            (
                observed_digest,
                warning_count,
                exception_count,
            ) = assembly.validate_security_report(
                path,
                "linux",
                COMMIT,
                TREE,
                {
                    "sha256": "e" * 64,
                    "prefix": "omnis-key-0.1.0/",
                    "productVersion": "0.1.0",
                    "compressedBytes": 12345,
                    "fileCount": 42,
                },
            )
            self.assertEqual(observed_digest, digest)
            self.assertEqual(warning_count, 0)
            self.assertEqual(exception_count, 0)
            manifest_binding = manifest.validate_security_report_artifact(
                path,
                "linux",
                Path(temporary).resolve(),
                COMMIT,
                TREE,
                {
                    "sha256": "e" * 64,
                    "prefix": "omnis-key-0.1.0/",
                },
                "0.1.0",
            )
            self.assertEqual(manifest_binding["sha256"], digest)
            self.assertEqual(manifest_binding["platform"], "linux")
            self.assertEqual(manifest_binding["proposedExceptionCount"], 0)

            macos_path = Path(temporary).resolve() / "macos-security.json"
            macos_payload = (
                json.dumps(
                    security_report_payload("macos"),
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode()
            macos_path.write_bytes(macos_payload)
            macos_path.chmod(0o600)
            macos_digest = hashlib.sha256(macos_payload).hexdigest()
            macos_sidecar = Path(str(macos_path) + ".sha256")
            macos_sidecar.write_text(
                f"{macos_digest}  {macos_path.name}\n",
                encoding="ascii",
            )
            macos_sidecar.chmod(0o600)
            self.assertEqual(
                assembly.validate_security_report(
                    macos_path,
                    "macos",
                    COMMIT,
                    TREE,
                    {
                        "sha256": "e" * 64,
                        "prefix": "omnis-key-0.1.0/",
                        "productVersion": "0.1.0",
                        "compressedBytes": 12345,
                        "fileCount": 42,
                    },
                ),
                (macos_digest, 0, 0),
            )
            with self.assertRaisesRegex(VerificationError, "identity"):
                assembly.validate_security_report(
                    path,
                    "macos",
                    COMMIT,
                    TREE,
                    {
                        "sha256": "e" * 64,
                        "prefix": "omnis-key-0.1.0/",
                        "productVersion": "0.1.0",
                        "compressedBytes": 12345,
                        "fileCount": 42,
                    },
                )
            sidecar.write_text(
                f"{'0' * 64}  {path.name}\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(VerificationError, "sidecar"):
                assembly.validate_security_report(
                    path,
                    "linux",
                    COMMIT,
                    TREE,
                    {
                        "sha256": "e" * 64,
                        "prefix": "omnis-key-0.1.0/",
                        "productVersion": "0.1.0",
                        "compressedBytes": 12345,
                        "fileCount": 42,
                    },
                )

    def test_security_validator_pins_match_preflight_configuration(self) -> None:
        tools: dict[str, str] = {}
        tools_path = SCRIPT_DIR.parent / "config/security/tools.env"
        for line in tools_path.read_text(encoding="utf-8").splitlines():
            if not line or line.startswith("#"):
                continue
            key, separator, value = line.partition("=")
            self.assertEqual(separator, "=")
            self.assertNotIn(key, tools)
            tools[key] = value
        expected = {
            "GITLEAKS_VERSION": "8.30.1",
            "GITLEAKS_SOURCE_COMMIT": (
                "83d9cd684c87d95d656c1458ef04895a7f1cbd8e"
            ),
            "GITLEAKS_GO_VERSION": "go1.26.5",
            "CARGO_AUDIT_VERSION": "0.22.2",
            "CARGO_DENY_VERSION": "0.20.2",
            "GITLEAKS_SHA256_LINUX_ARM64": (
                assembly.SECURITY_PLATFORM_IDENTITIES["linux"][
                    "gitleaksSha256"
                ]
            ),
            "GITLEAKS_SHA256_DARWIN_ARM64": (
                assembly.SECURITY_PLATFORM_IDENTITIES["macos"][
                    "gitleaksSha256"
                ]
            ),
            "CARGO_AUDIT_SHA256_LINUX_ARM64": (
                assembly.SECURITY_PLATFORM_IDENTITIES["linux"][
                    "cargoAuditSha256"
                ]
            ),
            "CARGO_AUDIT_SHA256_DARWIN_ARM64": (
                assembly.SECURITY_PLATFORM_IDENTITIES["macos"][
                    "cargoAuditSha256"
                ]
            ),
            "CARGO_DENY_SHA256_LINUX_ARM64": (
                assembly.SECURITY_PLATFORM_IDENTITIES["linux"][
                    "cargoDenySha256"
                ]
            ),
            "CARGO_DENY_SHA256_DARWIN_ARM64": (
                assembly.SECURITY_PLATFORM_IDENTITIES["macos"][
                    "cargoDenySha256"
                ]
            ),
            "RUSTSEC_ADVISORY_DB_COMMIT": (
                assembly.SECURITY_ADVISORY_DB_COMMIT
            ),
        }
        for key, value in expected.items():
            self.assertEqual(tools.get(key), value)

    def test_security_report_rejects_tiny_and_semantically_mutated_payloads(
        self,
    ) -> None:
        archive_result = {
            "sha256": "e" * 64,
            "prefix": "omnis-key-0.1.0/",
            "productVersion": "0.1.0",
            "compressedBytes": 12345,
            "fileCount": 42,
        }

        def validate_payload(
            root: Path, payload: dict[str, object]
        ) -> None:
            path = root / "linux-security.json"
            raw = (
                json.dumps(payload, sort_keys=True, separators=(",", ":"))
                + "\n"
            ).encode()
            path.write_bytes(raw)
            path.chmod(0o600)
            digest = hashlib.sha256(raw).hexdigest()
            sidecar = Path(str(path) + ".sha256")
            sidecar.write_text(
                f"{digest}  {path.name}\n",
                encoding="ascii",
            )
            sidecar.chmod(0o600)
            assembly.validate_security_report(
                path,
                "linux",
                COMMIT,
                TREE,
                archive_result,
            )

        def replace_with_tiny_handwritten_report(
            payload: dict[str, object],
        ) -> None:
            payload.clear()
            payload.update(
                {
                    "schemaVersion": 1,
                    "status": "SCAN_COMPLETE",
                    "candidate": {
                        "commit": COMMIT,
                        "tree": TREE,
                        "baseCommit": assembly.SECURITY_BASE_COMMIT,
                    },
                    "archive": {
                        "sha256": "e" * 64,
                        "prefix": "omnis-key-0.1.0/",
                        "productVersion": "0.1.0",
                    },
                    "tools": {
                        "secretScanner": {
                            "target": {
                                "os": "linux",
                                "architecture": "arm64",
                            }
                        }
                    },
                    "legs": {
                        "dependency": {
                            "status": "SCAN_CLEAN",
                            "proposedExceptions": [],
                            "informationalWarnings": [],
                            "visibleWarningCount": 0,
                        }
                    },
                    "externalActions": False,
                }
            )

        mutations = [
            (
                "tiny handwritten report",
                replace_with_tiny_handwritten_report,
            ),
            (
                "candidate base",
                lambda payload: payload["candidate"].__setitem__(
                    "baseCommit", "0" * 40
                ),
            ),
            (
                "boolean substituted for numeric status",
                lambda payload: payload["legs"]["artifact"].__setitem__(
                    "exitStatus", False
                ),
            ),
            (
                "cargo-audit pin",
                lambda payload: payload["tools"]["dependencyTool"].__setitem__(
                    "executableSha256", "0" * 64
                ),
            ),
            (
                "dependency status",
                lambda payload: payload.__setitem__(
                    "status", "SCAN_COMPLETE_WITH_INFORMATIONAL_WARNINGS"
                ),
            ),
            (
                "gitleaks expected pin",
                lambda payload: payload["tools"]["secretScanner"].__setitem__(
                    "expectedExecutableSha256", "0" * 64
                ),
            ),
            (
                "missing named secret scan",
                lambda payload: payload["legs"]["secret"]["namedScans"].pop(),
            ),
            (
                "positive control",
                lambda payload: payload["legs"]["secret"][
                    "positiveControl"
                ].__setitem__("findingCount", 0),
            ),
            (
                "object accounting",
                lambda payload: payload["scanSets"][
                    "materializedGitObjectTypes"
                ].__setitem__("blob", 79),
            ),
            (
                "proposed exception",
                lambda payload: payload["legs"]["dependency"][
                    "proposedExceptions"
                ].append(
                    {
                        "id": "RUSTSEC-2099-0001",
                        "package": "fixture-crate",
                        "version": "1.2.3",
                        "scope": "fixture scope",
                        "reason": "fixture reason",
                        "proposer": "OMNIS V1 builder",
                        "proposedOn": "2026-07-28",
                        "expiresOn": "2026-08-12",
                    }
                ),
            ),
            (
                "unsuppressed proposed-exception binding",
                lambda payload: payload["legs"]["dependency"][
                    "proposedExceptionFindings"
                ].append(
                    {
                        "advisoryId": "RUSTSEC-2099-0001",
                        "package": "wrong-package",
                        "version": "1.2.3",
                    }
                ),
            ),
            (
                "license rights",
                lambda payload: payload["legs"]["license"].__setitem__(
                    "unknownOrIncompatibleRights", 1
                ),
            ),
            (
                "artifact cleanup",
                lambda payload: payload["legs"]["artifact"].__setitem__(
                    "cleanup", "SKIPPED"
                ),
            ),
            (
                "exact command inventory",
                lambda payload: payload["commands"].pop(),
            ),
            (
                "unknown root field",
                lambda payload: payload.__setitem__("builderAssertion", True),
            ),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            warning_payload = security_report_payload("linux")
            warning_payload["legs"]["dependency"]["informationalWarnings"] = [
                {
                    "kind": "unmaintained",
                    "advisoryId": "RUSTSEC-2026-0200",
                    "package": "fixture-package",
                    "version": "1.2.3",
                }
            ]
            warning_payload["legs"]["dependency"]["visibleWarningCount"] = 1
            warning_payload["legs"]["dependency"]["warningCounts"][
                "unmaintained"
            ] = 1
            warning_payload["status"] = (
                "SCAN_COMPLETE_WITH_INFORMATIONAL_WARNINGS"
            )
            warning_payload["legs"]["dependency"]["status"] = (
                "SCAN_COMPLETE_WITH_INFORMATIONAL_WARNINGS"
            )
            validate_payload(root, warning_payload)
            warning_binding = manifest.validate_security_report_artifact(
                root / "linux-security.json",
                "linux",
                root,
                COMMIT,
                TREE,
                {
                    "sha256": "e" * 64,
                    "prefix": "omnis-key-0.1.0/",
                },
                "0.1.0",
            )
            self.assertEqual(
                warning_binding["informationalWarningCount"],
                1,
            )
            self.assertEqual(warning_binding["proposedExceptionCount"], 0)
            for label, mutate in mutations:
                with self.subTest(label=label):
                    payload = copy.deepcopy(security_report_payload("linux"))
                    mutate(payload)
                    with self.assertRaises(VerificationError):
                        validate_payload(root, payload)

    def test_security_preflight_receipt_binds_exact_report_and_sidecar_digest(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            archive = root / "source.tar.gz"
            report = root / "linux-security.json"
            advisory_database = root / "advisory-db"
            command = " ".join(
                [
                    assembly.SECURITY_PREFLIGHT_PROGRAM,
                    "--archive",
                    shlex.quote(str(archive)),
                    "--report",
                    shlex.quote(str(report)),
                    "--advisory-db",
                    shlex.quote(str(advisory_database)),
                ]
            )
            digest = "d" * 64
            output = (
                "security preflight complete: "
                f"commit={COMMIT} tree={TREE} report_sha256={digest}"
            )
            receipt = receipt_object(
                "linux-security-preflight",
                "linux",
                command,
                output,
            )
            self.assertEqual(
                assembly.parse_security_preflight_command(command),
                {
                    "archive": str(archive),
                    "report": str(report),
                    "advisoryDatabase": str(advisory_database),
                },
            )
            assembly.validate_exact_command_semantics(receipt)
            assembly.validate_security_preflight_receipt(
                receipt,
                "linux",
                report,
                digest,
                archive,
                0,
                0,
            )
            selected = assembly.select_security_preflight_receipts(
                {"linux": [receipt], "macos": []},
                {"linux"},
            )
            self.assertEqual(selected, {"linux": receipt})
            with self.assertRaisesRegex(VerificationError, "exactly 1"):
                assembly.select_security_preflight_receipts(
                    {"linux": [], "macos": []},
                    {"linux"},
                )
            with self.assertRaisesRegex(VerificationError, "exactly 1"):
                assembly.select_security_preflight_receipts(
                    {"linux": [receipt, receipt], "macos": []},
                    {"linux"},
                )
            with self.assertRaisesRegex(VerificationError, "exactly 0"):
                assembly.select_security_preflight_receipts(
                    {"linux": [receipt], "macos": []},
                    set(),
                )

            wrong_digest = receipt_object(
                "linux-security-preflight-wrong-digest",
                "linux",
                command,
                output[:-64] + ("0" * 64),
            )
            with self.assertRaisesRegex(VerificationError, "digest binding"):
                assembly.validate_security_preflight_receipt(
                    wrong_digest,
                    "linux",
                    report,
                    digest,
                    archive,
                    0,
                    0,
                )
            wrong_report_command = command.replace(
                str(report),
                str(root / "other-security.json"),
            )
            wrong_report = receipt_object(
                "linux-security-preflight-wrong-report",
                "linux",
                wrong_report_command,
                output,
            )
            with self.assertRaisesRegex(VerificationError, "artifact paths"):
                assembly.validate_security_preflight_receipt(
                    wrong_report,
                    "linux",
                    report,
                    digest,
                    archive,
                    0,
                    0,
                )
            for exception_count, warning_count, label in (
                (
                    1,
                    0,
                    "HOLD_PENDING_INDEPENDENT_EXCEPTION_REVIEW",
                ),
                (
                    0,
                    1,
                    "HOLD_INFORMATIONAL_WARNINGS_PENDING_REMEDIATION",
                ),
            ):
                held_receipt = receipt_object(
                    f"linux-security-preflight-{label.lower()}",
                    "linux",
                    command,
                    (
                        f"security preflight {label}: "
                        f"commit={COMMIT} tree={TREE} "
                        f"report_sha256={digest}"
                    ),
                )
                assembly.validate_exact_command_semantics(held_receipt)
                assembly.validate_security_preflight_receipt(
                    held_receipt,
                    "linux",
                    report,
                    digest,
                    archive,
                    exception_count,
                    warning_count,
                )
            self.assertIsNone(
                assembly.parse_security_preflight_command(
                    f"{command}; curl example.invalid"
                )
            )
            self.assertIsNone(
                assembly.parse_security_preflight_command(
                    "scripts/security_preflight.sh "
                    "--archive relative.tar.gz "
                    "--report /tmp/report.json "
                    "--advisory-db /tmp/advisory-db"
                )
            )

    def test_toolchain_is_parsed_from_canonical_raw_output(self) -> None:
        receipt = receipt_object(
            "linux-toolchain",
            "linux",
            assembly.TOOLCHAIN_COMMAND,
            "Linux fixture 6.1 x86_64\n"
            "rustc 1.88.0 (fixture)\n"
            "binary: rustc\n"
            "commit-hash: 1111111111111111111111111111111111111111\n"
            "commit-date: 2026-06-26\n"
            "host: x86_64-unknown-linux-gnu\n"
            "release: 1.88.0\n"
            "LLVM version: 20.1.5\n"
            "cargo 1.88.0 (fixture)\n"
            "git version 2.50.0\n"
            "Python 3.13.5\n"
            "cc (Fixture GCC) 14.2.0",
        )
        parsed = assembly.parse_toolchain(receipt)
        self.assertEqual(parsed["rustcVersion"], "1.88.0")
        self.assertEqual(parsed["rustcHost"], "x86_64-unknown-linux-gnu")
        self.assertEqual(parsed["cargoVersion"], "1.88.0")
        self.assertEqual(parsed["pythonVersion"], "3.13.5")

    def test_platform_receipts_require_one_exact_toolchain_binding(self) -> None:
        first = receipt_object(
            "linux-first",
            "linux",
            "cargo fmt --all -- --check",
            "",
        )
        second = receipt_object(
            "linux-second",
            "linux",
            "cargo check --workspace --all-targets",
            "",
        )
        assembly.validate_platform_toolchain_binding(
            [first, second], "linux"
        )
        second.trusted_tools["git"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(
            VerificationError, "do not share one trusted toolchain"
        ):
            assembly.validate_platform_toolchain_binding(
                [first, second], "linux"
            )

    def test_version_outputs_are_exact_and_derived(self) -> None:
        envelope = {
            "schemaVersion": 1,
            "command": "version",
            "ok": True,
            "code": "VERSION",
            "data": {
                "productVersion": "0.1.0",
                "compatibilityBaseName": "jcode",
                "compatibilityBaseVersion": "0.61.2",
            },
        }
        receipts = {
            "linux": [
                receipt_object(
                    "linux-version-text",
                    "linux",
                    assembly.VERSION_TEXT_COMMAND,
                    "omnis-key 0.1.0\njcode compatibility base 0.61.2",
                ),
                receipt_object(
                    "linux-version-json",
                    "linux",
                    assembly.VERSION_JSON_COMMAND,
                    json.dumps(envelope, sort_keys=True, separators=(",", ":")),
                ),
            ],
            "macos": [],
        }
        identifiers = assembly.validate_version_receipts(
            receipts, {"linux"}, "0.1.0", "0.61.2"
        )
        self.assertEqual(
            identifiers, ["linux-version-text", "linux-version-json"]
        )
        bad = list(receipts["linux"])
        bad[0] = receipt_object(
            "linux-version-text",
            "linux",
            assembly.VERSION_TEXT_COMMAND,
            "omnis-key 0.1.1\njcode compatibility base 0.61.2",
        )
        with self.assertRaisesRegex(VerificationError, "text version output"):
            assembly.validate_version_receipts(
                {"linux": bad, "macos": []}, {"linux"}, "0.1.0", "0.61.2"
            )

    def test_runtime_receipt_requires_positive_controls_and_zero_attempts(self) -> None:
        payload = runtime_payload()
        observed = assembly.validate_runtime_receipt(
            payload, "linux", COMMIT, TREE
        )
        self.assertTrue(assembly.EXPECTED_RUNTIME_CASES.issubset(observed))
        first_case = payload["cases"][0]
        first_case["instrumentation"]["networkEvents"] = ["DNS"]
        with self.assertRaisesRegex(VerificationError, "forbidden attempts"):
            assembly.validate_runtime_receipt(payload, "linux", COMMIT, TREE)

    def test_runtime_receipt_rejects_case_identity_and_write_mutations(self) -> None:
        mutations = [
            (
                lambda payload: payload["cases"][0].__setitem__(
                    "argv", ["omnis-key", "forged"]
                ),
                "argv/exit contract",
            ),
            (
                lambda payload: payload["cases"][0].__setitem__("exitCode", 99),
                "argv/exit contract",
            ),
            (
                lambda payload: payload["cases"][0].__setitem__(
                    "stdoutSha256", "0" * 64
                ),
                "output digest",
            ),
            (
                lambda payload: next(
                    case
                    for case in payload["cases"]
                    if case["name"] == "omnis-record-first"
                ).__setitem__("writeManifest", []),
                "exact-write manifest",
            ),
            (
                lambda payload: payload["cases"][0]["instrumentation"].__setitem__(
                    "credentialEnvironmentAccesses", ["OPENAI_API_KEY"]
                ),
                "forbidden attempts",
            ),
            (
                lambda payload: payload["instrumentationPositiveControl"].__setitem__(
                    "requiredMutationOperations", []
                ),
                "positive control",
            ),
            (
                lambda payload: payload["cases"][0]["instrumentation"].__setitem__(
                    "traceEventSchema", "EV0"
                ),
                "instrumentation accounting",
            ),
            (
                lambda payload: payload["cases"][0]["instrumentation"].__setitem__(
                    "traceEventCount", 0
                ),
                "instrumentation accounting",
            ),
            (
                lambda payload: next(
                    case
                    for case in payload["cases"]
                    if case["name"] == "jcode-pty-no-argument"
                )["processInstrumentation"].__setitem__(
                    "clientImageChain", ["untrusted-launcher", "jcode"]
                ),
                "process/image proof",
            ),
            (
                lambda payload: next(
                    case
                    for case in payload["cases"]
                    if case["name"] == "jcode-pty-no-argument"
                )["controlledUnixTransport"].__setitem__(
                    "unexpectedSocketAttempts", 1
                ),
                "exact Unix transport proof",
            ),
            (
                lambda payload: next(
                    case
                    for case in payload["cases"]
                    if case["name"] == "jcode-pty-no-argument"
                )["writeAttemptProof"].__setitem__("forbiddenAttemptCount", 1),
                "write-attempt proof",
            ),
            (
                lambda payload: payload["cases"].pop(),
                "exact case set",
            ),
        ]
        for mutate, expected_error in mutations:
            with self.subTest(expected_error=expected_error):
                payload = runtime_payload()
                mutate(payload)
                with self.assertRaisesRegex(VerificationError, expected_error):
                    assembly.validate_runtime_receipt(
                        payload, "linux", COMMIT, TREE
                    )

    def test_security_fault_command_has_frozen_grammar(self) -> None:
        self.assertTrue(
            assembly.is_security_fault_command(
                "tests/security/verify_preflight_faults.sh "
                "--archive packet/source.tar.gz "
                "--advisory-db tools/advisory-db "
                "--tools-dir tools/bin"
            )
        )
        self.assertFalse(
            assembly.is_security_fault_command(
                "tests/security/verify_preflight_faults.sh "
                "--archive packet/source.tar.gz; curl example.invalid "
                "--advisory-db tools/advisory-db "
                "--tools-dir tools/bin"
            )
        )

    def test_all_26_cases_have_a_derivation_route(self) -> None:
        routed = (
            set(assembly.CASE_GROUPS)
            | assembly.RUNTIME_REQUIRED_CASES
            | set(assembly.FIXED_CASE_HOLDS)
            | {
                "version_identity",
                "linux_fresh_clone",
                "macos_fresh_clone",
            }
        )
        self.assertEqual(
            assembly.REQUIRED_ADVERSARIAL_CASES - routed,
            set(),
        )
        self.assertEqual(len(assembly.REQUIRED_ADVERSARIAL_CASES), 26)

    def test_plan_cannot_smuggle_a_gate_verdict(self) -> None:
        with self.assertRaisesRegex(VerificationError, "prohibited gate assertion"):
            assembly.reject_prohibited_keys({"nested": {"clearIssued": True}})

    def test_manifest_rejects_pre_assembler_manual_index(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "verification-index.json"
            path.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "status": "VERIFICATION_COMPLETE_WITH_NAMED_HOLDS",
                        "candidate": {"commit": COMMIT, "tree": TREE},
                        "externalActions": False,
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(VerificationError, "assembly identity"):
                manifest.validate_verification_index(
                    path, COMMIT, TREE, "0.1.0"
                )

    def test_manifest_rejects_command_name_only_assembler_shaped_index(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            evidence_directory = root / "receipts"
            evidence_directory.mkdir()

            def evidence(name: str, payload: bytes) -> dict[str, str]:
                path = evidence_directory / name
                path.write_bytes(payload)
                return {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }

            marker_path = evidence_directory / "linux-fresh-clone-marker.json"
            marker_payload = (
                json.dumps(
                    clone_marker_payload("linux"),
                    sort_keys=True,
                    indent=2,
                    ensure_ascii=False,
                )
                + "\n"
            ).encode()
            marker_evidence = evidence(marker_path.name, marker_payload)
            marker_path.chmod(0o600)
            marker_sha = hashlib.sha256(marker_payload).hexdigest()

            section9: list[dict[str, object]] = []
            additional: list[dict[str, object]] = []
            all_receipt_ids: list[str] = []
            for index, command in enumerate(
                sorted(assembly.REQUIRED_SECTION9_COMMANDS), start=1
            ):
                receipt_id = f"linux-section9-{index:02d}"
                all_receipt_ids.append(receipt_id)
                section9.append(
                    {
                        "id": receipt_id,
                        "platform": "linux",
                        "command": command,
                        "status": "PASS",
                        "exitStatus": 0,
                        "evidence": evidence(
                            f"{receipt_id}.txt", f"{command}\n".encode()
                        ),
                    }
                )
            additional_commands = sorted(assembly.REQUIRED_ADDITIONAL_COMMANDS)
            additional_ids: dict[str, str] = {}
            for index, command in enumerate(additional_commands, start=1):
                receipt_id = f"linux-additional-{index:02d}"
                additional_ids[command] = receipt_id
                all_receipt_ids.append(receipt_id)
                additional.append(
                    {
                        "id": receipt_id,
                        "platform": "linux",
                        "command": command,
                        "status": "PASS",
                        "exitStatus": 0,
                        "evidence": evidence(
                            f"{receipt_id}.txt", f"{command}\n".encode()
                        ),
                    }
                )
            clone_creation_id = "linux-fresh-clone-created"
            clone_verification_id = "linux-fresh-clone-verified"
            clone_creation_command = (
                f"{assembly.CLONE_CREATION_PROGRAM} --platform linux "
                "--source . --candidate HEAD "
                f"--destination {root / 'linux-clone'} "
                f"--marker {marker_path}"
            )
            clone_verification_command = (
                f"{assembly.CLONE_VERIFICATION_PROGRAM} --marker {marker_path}"
            )
            for receipt_id, command in (
                (clone_creation_id, clone_creation_command),
                (clone_verification_id, clone_verification_command),
            ):
                all_receipt_ids.append(receipt_id)
                additional.append(
                    {
                        "id": receipt_id,
                        "platform": "linux",
                        "command": command,
                        "status": "PASS",
                        "exitStatus": 0,
                        "evidence": evidence(
                            f"{receipt_id}.txt", f"{command}\n".encode()
                        ),
                    }
                )

            hold_ids = set(assembly.MANDATORY_HOLDS) | {
                "MACOS_PENDING",
                "LOCAL_CASE_FIXTURE_PENDING",
            }
            known_holds = [
                {
                    "id": hold_id,
                    "status": "HOLD",
                    "description": f"Fixture description for {hold_id}.",
                    "owner": "fixture-owner",
                }
                for hold_id in sorted(hold_ids)
            ]
            adversarial: list[dict[str, object]] = []
            for case_id in sorted(assembly.REQUIRED_ADVERSARIAL_CASES):
                if case_id in assembly.FIXED_CASE_HOLDS:
                    hold_id = assembly.FIXED_CASE_HOLDS[case_id]
                elif case_id == "linux_fresh_clone":
                    adversarial.append(
                        {
                            "id": case_id,
                            "status": "PASS",
                            "holdId": None,
                            "receiptIds": sorted(
                                [clone_creation_id, clone_verification_id]
                            ),
                        }
                    )
                    continue
                else:
                    hold_id = "LOCAL_CASE_FIXTURE_PENDING"
                adversarial.append(
                    {
                        "id": case_id,
                        "status": "HOLD",
                        "holdId": hold_id,
                        "receiptIds": [],
                    }
                )

            plan_evidence = evidence("verification-plan.json", b"{}\n")
            runtime_evidence = evidence("linux-runtime.json", b"{}\n")
            security_evidence = evidence("linux-security.json", b"{}\n")
            security_sidecar_evidence = evidence(
                "linux-security.json.sha256", b"fixture sidecar\n"
            )
            index = {
                "schemaVersion": 1,
                "status": "VERIFICATION_COMPLETE_WITH_NAMED_HOLDS",
                "assembly": {
                    "tool": "scripts/assemble_verification_index.py",
                    "mode": "BUILDER_EVIDENCE_ONLY",
                    "verdictIssued": False,
                    "clearIssued": False,
                    "archive": {
                        "sha256": "1" * 64,
                        "commit": COMMIT,
                        "tree": TREE,
                    },
                    "securityReports": [
                        {
                            "platform": "linux",
                            "sha256": security_evidence["sha256"],
                            "informationalWarningCount": 0,
                            "commandReceiptId": additional_ids[
                                assembly.TOOLCHAIN_COMMAND
                            ],
                            "evidence": security_evidence,
                            "sidecarEvidence": security_sidecar_evidence,
                        }
                    ],
                },
                "candidate": {"commit": COMMIT, "tree": TREE},
                "externalActions": False,
                "section9": section9,
                "additionalCommands": additional,
                "cloneProvenance": [
                    {
                        "platform": "linux",
                        "creationReceiptId": clone_creation_id,
                        "verificationReceiptId": clone_verification_id,
                        "markerSha256": marker_sha,
                        "evidence": marker_evidence,
                    }
                ],
                "supplementalEvidence": [
                    {
                        "id": "assembly-plan",
                        "kind": "assembly-plan",
                        "evidence": plan_evidence,
                    },
                    {
                        "id": "runtime-sovereignty-linux",
                        "kind": "runtime-sovereignty",
                        "platform": "linux",
                        "commandReceiptId": additional_ids[assembly.RUNTIME_COMMAND],
                        "evidence": runtime_evidence,
                    },
                ],
                "knownHolds": known_holds,
                "adversarial": adversarial,
                "platforms": [
                    {
                        "name": "linux",
                        "status": "PASS",
                        "freshClone": True,
                        "receiptIds": all_receipt_ids,
                    },
                    {
                        "name": "macos",
                        "status": "HOLD",
                        "freshClone": False,
                        "holdId": "MACOS_PENDING",
                        "receiptIds": [],
                    },
                ],
                "toolchains": [
                    {
                        "platform": "linux",
                        "receiptId": additional_ids[assembly.TOOLCHAIN_COMMAND],
                        "uname": "Linux fixture",
                        "rustcVersion": "1.88.0",
                        "rustcHost": "x86_64-unknown-linux-gnu",
                        "cargoVersion": "1.88.0",
                        "gitVersion": "2.50.0",
                        "pythonVersion": "3.13.5",
                        "cCompiler": "cc fixture",
                        "evidence": next(
                            receipt["evidence"]
                            for receipt in additional
                            if receipt["command"] == assembly.TOOLCHAIN_COMMAND
                        ),
                    }
                ],
                "versionIdentity": {
                    "canonical": "0.1.0",
                    "binaryText": "omnis-key 0.1.0",
                    "binaryJson": "0.1.0",
                    "changelog": "0.1.0",
                    "releaseProposition": "0.1.0",
                    "packageMetadata": "0.1.0",
                    "archiveMetadata": "0.1.0",
                    "compatibilityBase": "0.61.2",
                    "receiptIds": [
                        additional_ids[assembly.VERSION_TEXT_COMMAND],
                        additional_ids[assembly.VERSION_JSON_COMMAND],
                    ],
                },
            }
            path = root / "verification-index.json"
            path.write_text(json.dumps(index), encoding="utf-8")
            with self.assertRaisesRegex(
                VerificationError, "trusted toolchain binding"
            ):
                manifest.validate_verification_index(
                    path, COMMIT, TREE, "0.1.0"
                )

    def test_manifest_raw_reassembly_refuses_any_index_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            plan = root / "plan.json"
            report = root / "linux-security.json"
            archive = root / "source.tar.gz"
            plan.write_text("{}\n", encoding="utf-8")
            report.write_text("{}\n", encoding="utf-8")
            archive.write_bytes(b"archive fixture")
            for path in (plan, report, archive):
                path.chmod(0o600)

            def evidence(path: Path) -> dict[str, str]:
                return {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }

            index: dict[str, object] = {
                "supplementalEvidence": [
                    {
                        "id": "assembly-plan",
                        "kind": "assembly-plan",
                        "evidence": evidence(plan),
                    }
                ],
                "assembly": {
                    "securityReports": [
                        {
                            "platform": "linux",
                            "evidence": evidence(report),
                        }
                    ]
                },
            }
            assembler_bytes = (
                SCRIPT_DIR / "assemble_verification_index.py"
            ).read_bytes()
            with mock.patch.object(
                manifest, "commit_file", return_value=assembler_bytes
            ):
                with mock.patch.object(
                    assembly,
                    "assemble_index",
                    return_value=copy.deepcopy(index),
                ) as reassembler:
                    manifest.rederive_verification_index(
                        root / "verification-index.json",
                        index,
                        SCRIPT_DIR.parent,
                        archive,
                        {"linux": report},
                        COMMIT,
                    )
                reassembler.assert_called_once()
                rederived = copy.deepcopy(index)
                rederived["candidate"] = {"commit": "0" * 40, "tree": TREE}
                with mock.patch.object(
                    assembly, "assemble_index", return_value=rederived
                ):
                    with self.assertRaisesRegex(
                        VerificationError, "differs from deterministic"
                    ):
                        manifest.rederive_verification_index(
                            root / "verification-index.json",
                            index,
                            SCRIPT_DIR.parent,
                            archive,
                            {"linux": report},
                            COMMIT,
                        )
            with mock.patch.object(
                manifest, "commit_file", return_value=b"forged assembler"
            ):
                with self.assertRaisesRegex(
                    VerificationError, "differs from the candidate"
                ):
                    manifest.rederive_verification_index(
                        root / "verification-index.json",
                        index,
                        SCRIPT_DIR.parent,
                        archive,
                        {"linux": report},
                        COMMIT,
                    )


if __name__ == "__main__":
    unittest.main()
