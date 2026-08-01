#!/usr/bin/env python3
"""Adversarial self-tests for the Unix runtime-sovereignty harness."""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("verify_runtime.py")
SPEC = importlib.util.spec_from_file_location("verify_runtime_under_test", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot import {MODULE_PATH}")
RUNTIME = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNTIME
SPEC.loader.exec_module(RUNTIME)


def event(pid: int, payload: str):
    return RUNTIME.parse_instrumentation_event(f"EV1|{pid}|{payload}")


class RuntimeHarnessAdversarialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="omnis-runtime-harness-selftest-",
            dir="/tmp",
        )
        lexical_root = Path("/tmp") / Path(self.temporary.name).name
        self.root = lexical_root
        self.runtime_root = lexical_root / "runtime"
        self.jcode_home = lexical_root / "jcode-home"
        self.cwd = lexical_root / "cwd"
        self.runtime_root.mkdir()
        self.jcode_home.mkdir()
        self.cwd.mkdir()
        self.sandbox = RUNTIME.Sandbox(
            root=lexical_root,
            roots={
                "JCODE_HOME": self.jcode_home,
                "RUNTIME": self.runtime_root,
                "CWD": self.cwd,
            },
            environment={},
        )
        self.jcode = lexical_root / "jcode"
        self.omnis_key = lexical_root / "omnis-key"
        self.jcode.write_bytes(b"fixture jcode\n")
        self.omnis_key.write_bytes(b"fixture omnis-key\n")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def valid_process_events(self):
        return [
            event(101, f"PROCESS_START|{self.jcode}"),
            event(
                101,
                f"EXEC_ATTEMPT|posix_spawnp|trace=1|inject=1|{self.jcode}",
            ),
            event(
                101,
                f"EXEC_RESULT|posix_spawnp|result=0|pid=202|{self.jcode}",
            ),
            event(202, f"PROCESS_START|{self.jcode}"),
        ]

    @unittest.skipUnless(sys.platform == "darwin", "Darwin /tmp alias test")
    def test_darwin_tmp_alias_cannot_bypass_hostile_fixture_matching(self) -> None:
        fixture = self.root / "secret.json"
        hostile = RUNTIME.HostilePtyFixtures(
            protected_files={"secret": fixture},
            forbidden_prefixes={"root": self.root},
            protected_snapshot_keys=set(),
            replacement_marker=self.root / "replacement-marker",
        )
        canonical_alias = Path("/private/tmp") / self.root.name / "secret.json"
        with self.assertRaisesRegex(RUNTIME.GateFailure, "accessed hostile"):
            RUNTIME.assert_hostile_pty_fixtures_ignored(
                [event(101, f"FS|open|{canonical_alias}")],
                self.sandbox,
                hostile,
                set(),
            )

    def test_both_exact_process_images_are_required(self) -> None:
        proof = RUNTIME.assert_pty_process_instrumentation(
            self.valid_process_events(),
            client_pid=101,
            temporary_server_pid=202,
            invoked_binary=self.jcode,
        )
        self.assertEqual(proof["instrumentedProcessCount"], 2)
        with self.assertRaisesRegex(
            RUNTIME.GateFailure,
            "process set|server process-start",
        ):
            RUNTIME.assert_pty_process_instrumentation(
                self.valid_process_events()[:-1],
                client_pid=101,
                temporary_server_pid=202,
                invoked_binary=self.jcode,
            )

    def test_spawn_must_preserve_instrumentation_and_target_exact_sibling(self) -> None:
        stripped = self.valid_process_events()
        stripped[1] = event(
            101,
            f"EXEC_ATTEMPT|posix_spawnp|trace=1|inject=0|{self.jcode}",
        )
        with self.assertRaisesRegex(RUNTIME.GateFailure, "stripped"):
            RUNTIME.assert_pty_process_instrumentation(
                stripped,
                client_pid=101,
                temporary_server_pid=202,
                invoked_binary=self.jcode,
            )

        wrong = self.root / "other-jcode"
        wrong.write_bytes(b"wrong fixture\n")
        unexpected = self.valid_process_events()
        unexpected[1] = event(
            101,
            f"EXEC_ATTEMPT|posix_spawnp|trace=1|inject=1|{wrong}",
        )
        with self.assertRaisesRegex(RUNTIME.GateFailure, "non-sibling"):
            RUNTIME.assert_pty_process_instrumentation(
                unexpected,
                client_pid=101,
                temporary_server_pid=202,
                invoked_binary=self.jcode,
            )

    def test_unix_transport_is_path_pid_and_count_bound(self) -> None:
        expected = self.runtime_root / "jcode.sock"
        alias = (
            Path("/private/tmp") / self.root.name / "runtime/jcode.sock"
            if sys.platform == "darwin"
            else expected
        )
        valid = [
            event(101, "AF_UNIX"),
            event(202, "AF_UNIX"),
            event(101, f"CONNECT_AF_UNIX|{expected}"),
            event(202, f"BIND_AF_UNIX|{alias}"),
        ]
        proof = RUNTIME.assert_pty_unix_transport(
            valid,
            sandbox=self.sandbox,
            client_pid=101,
            temporary_server_pid=202,
        )
        self.assertEqual(proof["unexpectedSocketAttempts"], 0)
        with self.assertRaisesRegex(RUNTIME.GateFailure, "other than"):
            RUNTIME.assert_pty_unix_transport(
                [
                    *valid,
                    event(101, "CONNECT_AF_UNIX|/tmp/account-agent.sock"),
                ],
                sandbox=self.sandbox,
                client_pid=101,
                temporary_server_pid=202,
            )

    def test_transient_outside_write_is_not_hidden_by_empty_snapshot_diff(self) -> None:
        with self.assertRaisesRegex(RUNTIME.GateFailure, "forbidden transient"):
            RUNTIME.assert_pty_write_attempts(
                [
                    event(101, "FS|open-write|/private/tmp/forbidden-output"),
                    event(101, "FS|unlink|/private/tmp/forbidden-output"),
                ],
                self.sandbox,
                "synthetic-pty",
            )
        proof = RUNTIME.assert_pty_write_attempts(
            [
                event(202, f"FS|open-write|{self.runtime_root / 'jcode.sock'}"),
                event(202, f"FS|unlink|{self.runtime_root / 'jcode.sock'}"),
            ],
            self.sandbox,
            "synthetic-pty",
        )
        self.assertEqual(proof["forbiddenAttemptCount"], 0)

    def test_pty_write_proof_only_exempts_the_exact_null_sink(self) -> None:
        accepted = [
            event(101, "FS|open-write|/dev/null"),
            event(
                101,
                f"FS|open-write|{self.runtime_root / 'jcode.sock.spawning'}",
            ),
            event(
                102,
                f"FS|unlink|{self.runtime_root / 'jcode.sock.spawning'}",
            ),
            event(
                102,
                "FS|open-write|"
                + str(
                    self.jcode_home
                    / "sessions/session_otter_1785300435492_8472e0bf6b2c89a4"
                    ".tmp.102.987654321"
                ),
            ),
            event(
                102,
                "FS|rename-from|"
                + str(
                    self.runtime_root
                    / "durable-state/swarm/_private_fixture_cwd.tmp.102.123456"
                ),
            ),
        ]
        proof = RUNTIME.assert_pty_write_attempts(
            accepted,
            self.sandbox,
            "synthetic-pty",
        )
        self.assertIn("open-write:SYSTEM:/dev/null", proof["attemptClasses"])

        with self.assertRaisesRegex(RUNTIME.GateFailure, "forbidden transient"):
            RUNTIME.assert_pty_write_attempts(
                [
                    event(101, "FS|chmod|/dev/null"),
                    event(101, "FS|open-write|/dev/zero"),
                ],
                self.sandbox,
                "synthetic-pty",
            )

    def test_hostile_user_keychain_prefix_is_credential_state(self) -> None:
        keychain_root = self.root / "home/Library/Keychains"
        fixtures = RUNTIME.HostilePtyFixtures(
            protected_files={},
            forbidden_prefixes={"home-keychains": keychain_root},
            protected_snapshot_keys=set(),
            replacement_marker=self.root / "replacement-marker",
        )
        with self.assertRaisesRegex(RUNTIME.GateFailure, "accessed hostile"):
            RUNTIME.assert_hostile_pty_fixtures_ignored(
                [
                    event(
                        202,
                        f"FS|stat|{keychain_root / 'login.keychain-db'}",
                    )
                ],
                self.sandbox,
                fixtures,
                set(),
            )

    def test_snapshot_detects_same_bytes_metadata_rewrite(self) -> None:
        state = self.cwd / "state"
        state.write_bytes(b"same bytes")
        before = RUNTIME.snapshot({"CWD": self.cwd})
        metadata = state.stat()
        os.utime(
            state,
            ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000_000),
        )
        after = RUNTIME.snapshot({"CWD": self.cwd})
        self.assertEqual(RUNTIME.changed_paths(before, after), {"CWD:state"})

    def test_sensitive_inventory_and_direct_enumeration_guard_are_fail_closed(self) -> None:
        required = {
            "COMPOSIO_GMAIL_CONNECTED_ACCOUNT_ID",
            "COMPOSIO_GMAIL_AUTH_CONFIG_ID",
            "JCODE_NAMED_PROVIDER_PROFILE",
            "JCODE_SAME_PROVIDER_ACCOUNT_FAILOVER",
            "AWS_SESSION_TOKEN",
            "AZURE_OPENAI_API_KEY",
            "CURSOR_REFRESH_TOKEN",
        }
        self.assertTrue(required.issubset(RUNTIME.CREDENTIAL_ENVIRONMENT))
        self.assertGreater(RUNTIME.assert_no_direct_environment_enumeration(), 0)

    def test_unattributed_or_unversioned_events_fail_closed(self) -> None:
        for malformed in ("DNS", "EV1|0|DNS", "EV1|not-a-pid|DNS"):
            with self.subTest(malformed=malformed):
                with self.assertRaises(RUNTIME.GateFailure):
                    RUNTIME.parse_instrumentation_event(malformed)

    def test_non_pty_case_requires_exact_instrumented_image(self) -> None:
        valid = [
            event(101, f"PROCESS_START|{self.jcode}"),
            event(101, f"FS|open|{self.cwd / 'fixture'}"),
        ]
        RUNTIME.assert_single_process_instrumented(
            valid,
            self.jcode,
            "synthetic-read-only",
        )
        with self.assertRaisesRegex(RUNTIME.GateFailure, "every event"):
            RUNTIME.assert_single_process_instrumented(
                [*valid, event(202, f"FS|open|{self.cwd / 'fixture'}")],
                self.jcode,
                "synthetic-read-only",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
