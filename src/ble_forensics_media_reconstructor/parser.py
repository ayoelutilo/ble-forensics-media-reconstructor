"""Simplified btsnoop-like parser."""

from __future__ import annotations

import struct
from pathlib import Path

from .errors import ParseError
from .models import Direction, SnoopRecord

MAGIC = b"BTSN"
VERSION = 1

_FILE_HEADER = struct.Struct("<4sB3s")
_RECORD_HEADER = struct.Struct("<QBH")


def parse_capture_bytes(data: bytes) -> list[SnoopRecord]:
    """Parse capture bytes into snoop records.

    File format:
    - Header: magic (4 bytes), version (1 byte), reserved (3 bytes)
    - Repeated records:
      - timestamp_us (uint64 LE)
      - direction (uint8, 0=outgoing, 1=incoming)
      - payload_len (uint16 LE)
      - payload bytes
    """

    if len(data) < _FILE_HEADER.size:
        raise ParseError("Input shorter than file header")

    magic, version, _reserved = _FILE_HEADER.unpack_from(data, 0)
    if magic != MAGIC:
        raise ParseError(f"Unexpected magic {magic!r}; expected {MAGIC!r}")
    if version != VERSION:
        raise ParseError(f"Unsupported version {version}; expected {VERSION}")

    offset = _FILE_HEADER.size
    records: list[SnoopRecord] = []

    while offset < len(data):
        if len(data) - offset < _RECORD_HEADER.size:
            raise ParseError(f"Incomplete record header at offset {offset}")

        timestamp_us, direction_raw, payload_len = _RECORD_HEADER.unpack_from(data, offset)
        offset += _RECORD_HEADER.size

        if len(data) - offset < payload_len:
            raise ParseError(f"Truncated payload at offset {offset}")

        payload = data[offset : offset + payload_len]
        offset += payload_len

        try:
            direction = Direction(direction_raw)
        except ValueError as exc:
            raise ParseError(
                f"Unsupported direction value {direction_raw} at record {len(records)}"
            ) from exc

        records.append(
            SnoopRecord(
                index=len(records),
                timestamp_us=timestamp_us,
                direction=direction,
                payload=payload,
            )
        )

    return records


def parse_capture_file(path: str | Path) -> list[SnoopRecord]:
    """Read and parse capture file from disk."""

    capture_path = Path(path)
    return parse_capture_bytes(capture_path.read_bytes())

# Refinement.
