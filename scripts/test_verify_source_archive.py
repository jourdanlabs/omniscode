#!/usr/bin/env python3
"""Adversarial tests for exact source-archive byte verification."""

from __future__ import annotations

import gzip
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from canonical_gzip import canonical_gzip_bytes
from verify_source_archive import VerificationError, verify_archive


class SourceArchiveVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name) / "repo"
        (self.repo / "crates" / "omnis-key-cli").mkdir(parents=True)
        (self.repo / "crates" / "omnis-key-cli" / "Cargo.toml").write_text(
            '[package]\nname = "omnis-key-cli"\nversion = "0.1.0"\n',
            encoding="utf-8",
        )
        (self.repo / "README.md").write_text("OMNIS fixture\n", encoding="utf-8")
        self.git("init", "-q")
        self.git("config", "user.name", "Archive Fixture")
        self.git("config", "user.email", "archive-fixture@example.invalid")
        self.git("add", ".")
        self.git("commit", "-q", "-m", "fixture")
        self.commit = self.git("rev-parse", "HEAD").decode().strip()
        self.prefix = f"omnis-key-harness-v0.1.0-{self.commit[:12]}/"
        self.tar_bytes = self.git(
            "archive",
            "--format=tar",
            f"--prefix={self.prefix}",
            self.commit,
        )
        self.canonical_bytes = canonical_gzip_bytes(self.tar_bytes)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, *args: str) -> bytes:
        result = subprocess.run(
            ["git", "-C", str(self.repo), *args],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(
            result.returncode,
            0,
            result.stderr.decode("utf-8", "replace"),
        )
        return result.stdout

    def write_archive(self, name: str, data: bytes) -> Path:
        archive = Path(self.temporary.name) / name
        archive.write_bytes(data)
        return archive

    def assert_noncanonical(self, data: bytes, name: str) -> None:
        archive = self.write_archive(name, data)
        with self.assertRaisesRegex(
            VerificationError, "compressed byte stream is noncanonical"
        ):
            verify_archive(self.repo, archive, self.commit)

    def test_exact_canonical_archive_is_accepted(self) -> None:
        archive = self.write_archive("canonical.tar.gz", self.canonical_bytes)
        result = verify_archive(self.repo, archive, self.commit)
        self.assertEqual(result["status"], "ARCHIVE_VALID")
        self.assertEqual(result["compressionFormat"], "gzip-stored-v1")
        self.assertEqual(result["commit"], self.commit)

    def test_concatenated_gzip_member_is_rejected(self) -> None:
        tainted = self.canonical_bytes + canonical_gzip_bytes(
            b"OMNIS_SYNTHETIC_PRIVATE_KEY_MARKER"
        )
        self.assertEqual(gzip.decompress(tainted), self.tar_bytes + b"OMNIS_SYNTHETIC_PRIVATE_KEY_MARKER")
        self.assert_noncanonical(tainted, "concatenated.tar.gz")

    def test_gzip_header_name_and_comment_are_rejected(self) -> None:
        named_buffer = io.BytesIO()
        with gzip.GzipFile(
            filename="OMNIS_SYNTHETIC_PRIVATE_KEY_MARKER",
            mode="wb",
            fileobj=named_buffer,
            mtime=0,
        ) as handle:
            handle.write(self.tar_bytes)
        named = named_buffer.getvalue()

        commented = bytearray(self.canonical_bytes)
        commented[3] |= 0x10
        comment = b"OMNIS_SYNTHETIC_PRIVATE_KEY_MARKER\0"
        commented[10:10] = comment

        for name, tainted in (
            ("named.tar.gz", named),
            ("commented.tar.gz", bytes(commented)),
        ):
            with self.subTest(name=name):
                self.assertEqual(gzip.decompress(tainted), self.tar_bytes)
                self.assert_noncanonical(tainted, name)

    def test_noncanonical_deflate_encoding_is_rejected(self) -> None:
        recompressed = gzip.compress(self.tar_bytes, compresslevel=9, mtime=0)
        self.assertEqual(gzip.decompress(recompressed), self.tar_bytes)
        self.assertNotEqual(recompressed, self.canonical_bytes)
        self.assert_noncanonical(recompressed, "recompressed.tar.gz")

    def test_raw_trailing_bytes_are_rejected(self) -> None:
        tainted = self.canonical_bytes + b"OMNIS_SYNTHETIC_TRAILING_BYTES"
        self.assert_noncanonical(tainted, "trailing.tar.gz")


if __name__ == "__main__":
    unittest.main()
