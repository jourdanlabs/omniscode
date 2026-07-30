#!/usr/bin/env python3
"""Bind every proposed cargo-audit ignore to an unsuppressed exact finding."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


class ExceptionBindingError(RuntimeError):
    pass


def exact_exception_findings(
    exceptions_payload: object,
    audit_payload: object,
) -> list[dict[str, str]]:
    if not isinstance(exceptions_payload, dict):
        raise ExceptionBindingError("exception configuration is not an object")
    exceptions = exceptions_payload.get("proposedExceptions")
    if not isinstance(exceptions, list):
        raise ExceptionBindingError("proposed exception set is malformed")
    if not isinstance(audit_payload, dict):
        raise ExceptionBindingError("unsuppressed audit report is not an object")
    vulnerabilities = audit_payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, dict):
        raise ExceptionBindingError("unsuppressed audit vulnerabilities are absent")
    raw_findings = vulnerabilities.get("list")
    if not isinstance(raw_findings, list):
        raise ExceptionBindingError("unsuppressed audit finding list is absent")
    finding_count = vulnerabilities.get("count")
    if type(finding_count) is not int or finding_count != len(raw_findings):
        raise ExceptionBindingError(
            "unsuppressed audit finding count/list is inconsistent"
        )

    findings: list[dict[str, str]] = []
    for raw_finding in raw_findings:
        if not isinstance(raw_finding, dict):
            raise ExceptionBindingError("unsuppressed audit finding is malformed")
        advisory = raw_finding.get("advisory")
        package = raw_finding.get("package")
        if not isinstance(advisory, dict) or not isinstance(package, dict):
            raise ExceptionBindingError("unsuppressed audit finding identity is absent")
        identity = {
            "advisoryId": advisory.get("id"),
            "package": package.get("name"),
            "version": package.get("version"),
        }
        if not all(isinstance(value, str) and value for value in identity.values()):
            raise ExceptionBindingError("unsuppressed audit finding identity is malformed")
        findings.append(identity)

    expected: list[dict[str, str]] = []
    for raw_exception in exceptions:
        if not isinstance(raw_exception, dict):
            raise ExceptionBindingError("proposed exception is malformed")
        identity = {
            "advisoryId": raw_exception.get("id"),
            "package": raw_exception.get("package"),
            "version": raw_exception.get("version"),
        }
        if not all(isinstance(value, str) and value for value in identity.values()):
            raise ExceptionBindingError("proposed exception identity is incomplete")
        expected.append(identity)
    if len({item["advisoryId"] for item in expected}) != len(expected):
        raise ExceptionBindingError("proposed exception advisory IDs are duplicated")

    expected = sorted(
        expected,
        key=lambda finding: (
            finding["advisoryId"],
            finding["package"],
            finding["version"],
        ),
    )
    findings = sorted(
        findings,
        key=lambda finding: (
            finding["advisoryId"],
            finding["package"],
            finding["version"],
        ),
    )
    if findings != expected:
        raise ExceptionBindingError(
            "complete unsuppressed vulnerability tuple set differs from the "
            "configured exact proposed exceptions"
        )
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exceptions", required=True, type=Path)
    parser.add_argument("--audit-report", required=True, type=Path)
    args = parser.parse_args()
    try:
        exceptions_payload = json.loads(args.exceptions.read_text(encoding="utf-8"))
        audit_payload = json.loads(args.audit_report.read_text(encoding="utf-8"))
        findings = exact_exception_findings(exceptions_payload, audit_payload)
    except (OSError, json.JSONDecodeError, ExceptionBindingError) as error:
        print(f"advisory exception binding error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(findings, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
