#!/usr/bin/env python3
"""Canonical gzip encoding with deterministic stored DEFLATE blocks."""

from __future__ import annotations

import binascii
import struct
import sys


BLOCK_BYTES = 65_535
HEADER = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff"


def canonical_gzip_bytes(data: bytes) -> bytes:
    """Return one metadata-free gzip member with a unique byte encoding."""
    encoded = bytearray(HEADER)
    if data:
        for offset in range(0, len(data), BLOCK_BYTES):
            block = data[offset : offset + BLOCK_BYTES]
            final = offset + len(block) == len(data)
            # BFINAL occupies bit zero; BTYPE=00 and zero padding consume the
            # rest of this byte. Every stored block therefore starts aligned.
            encoded.append(1 if final else 0)
            length = len(block)
            encoded.extend(struct.pack("<HH", length, length ^ 0xFFFF))
            encoded.extend(block)
    else:
        encoded.extend(b"\x01\x00\x00\xff\xff")
    encoded.extend(
        struct.pack("<II", binascii.crc32(data) & 0xFFFF_FFFF, len(data) & 0xFFFF_FFFF)
    )
    return bytes(encoded)


def main() -> int:
    source = sys.stdin.buffer.read()
    sys.stdout.buffer.write(canonical_gzip_bytes(source))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
