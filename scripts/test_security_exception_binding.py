#!/usr/bin/env python3
"""Adversarial tests for exact proposed-advisory binding."""

from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from validate_advisory_exception_findings import (
    ExceptionBindingError,
    exact_exception_findings,
)


EXCEPTIONS = {
    "schemaVersion": 1,
    "proposedExceptions": [
        {
            "id": "RUSTSEC-2099-0001",
            "package": "fixture-crate",
            "version": "1.2.3",
        }
    ],
}
AUDIT = {
    "vulnerabilities": {
        "count": 1,
        "list": [
            {
                "advisory": {"id": "RUSTSEC-2099-0001"},
                "package": {"name": "fixture-crate", "version": "1.2.3"},
            }
        ],
    }
}
EMPTY_EXCEPTIONS = {"schemaVersion": 1, "proposedExceptions": []}
EMPTY_AUDIT = {"vulnerabilities": {"count": 0, "list": []}}


class AdvisoryExceptionBindingTests(unittest.TestCase):
    def test_exact_unsuppressed_finding_is_bound(self) -> None:
        self.assertEqual(
            exact_exception_findings(EXCEPTIONS, AUDIT),
            [
                {
                    "advisoryId": "RUSTSEC-2099-0001",
                    "package": "fixture-crate",
                    "version": "1.2.3",
                }
            ],
        )

    def test_empty_exception_set_binds_exact_zero_findings(self) -> None:
        self.assertEqual(
            exact_exception_findings(EMPTY_EXCEPTIONS, EMPTY_AUDIT),
            [],
        )

    def test_empty_exception_set_refuses_any_vulnerability(self) -> None:
        with self.assertRaisesRegex(ExceptionBindingError, "tuple set differs"):
            exact_exception_findings(EMPTY_EXCEPTIONS, AUDIT)

    def test_empty_exception_set_refuses_nonzero_count_with_empty_list(
        self,
    ) -> None:
        audit = copy.deepcopy(EMPTY_AUDIT)
        audit["vulnerabilities"]["count"] = 1
        with self.assertRaisesRegex(ExceptionBindingError, "inconsistent"):
            exact_exception_findings(EMPTY_EXCEPTIONS, audit)

    def test_stale_advisory_is_refused(self) -> None:
        exceptions = copy.deepcopy(EXCEPTIONS)
        exceptions["proposedExceptions"][0]["id"] = "RUSTSEC-2099-0002"
        with self.assertRaisesRegex(ExceptionBindingError, "tuple set differs"):
            exact_exception_findings(exceptions, AUDIT)

    def test_wrong_package_is_refused(self) -> None:
        exceptions = copy.deepcopy(EXCEPTIONS)
        exceptions["proposedExceptions"][0]["package"] = "lopdf"
        with self.assertRaisesRegex(ExceptionBindingError, "tuple set differs"):
            exact_exception_findings(exceptions, AUDIT)

    def test_wrong_locked_version_is_refused(self) -> None:
        exceptions = copy.deepcopy(EXCEPTIONS)
        exceptions["proposedExceptions"][0]["version"] = "1.2.2"
        with self.assertRaisesRegex(ExceptionBindingError, "tuple set differs"):
            exact_exception_findings(exceptions, AUDIT)

    def test_duplicate_finding_is_refused_as_ambiguous(self) -> None:
        audit = copy.deepcopy(AUDIT)
        audit["vulnerabilities"]["list"].append(
            copy.deepcopy(audit["vulnerabilities"]["list"][0])
        )
        audit["vulnerabilities"]["count"] += 1
        with self.assertRaisesRegex(ExceptionBindingError, "tuple set differs"):
            exact_exception_findings(EXCEPTIONS, audit)

    def test_extra_same_advisory_different_version_is_refused(self) -> None:
        audit = copy.deepcopy(AUDIT)
        audit["vulnerabilities"]["list"].append(
            {
                "advisory": {"id": "RUSTSEC-2099-0001"},
                "package": {"name": "fixture-crate", "version": "1.2.2"},
            }
        )
        audit["vulnerabilities"]["count"] += 1
        with self.assertRaisesRegex(ExceptionBindingError, "tuple set differs"):
            exact_exception_findings(EXCEPTIONS, audit)

    def test_unreviewed_different_advisory_is_refused(self) -> None:
        audit = copy.deepcopy(AUDIT)
        audit["vulnerabilities"]["list"].append(
            {
                "advisory": {"id": "RUSTSEC-2026-9999"},
                "package": {"name": "other", "version": "1.0.0"},
            }
        )
        audit["vulnerabilities"]["count"] += 1
        with self.assertRaisesRegex(ExceptionBindingError, "tuple set differs"):
            exact_exception_findings(EXCEPTIONS, audit)


if __name__ == "__main__":
    unittest.main()
