"""Domain models for BLE capture parsing and reconstruction."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any


class Direction(IntEnum):
    """Packet direction from the local adapter perspective."""

    OUTGOING = 0
    INCOMING = 1


@dataclass(frozen=True, slots=True)
class SnoopRecord:
    """One parsed record from the simplified btsnoop-like file."""

    index: int
    timestamp_us: int
    direction: Direction
    payload: bytes

    @property
    def payload_len(self) -> int:
        return len(self.payload)


@dataclass(frozen=True, slots=True)
class ATTEvent:
    """One ATT PDU decoded from a snoop record."""

    record_index: int
    timestamp_us: int
    direction: Direction
    opcode: int
    opcode_name: str
    handle: int | None
    value: bytes


@dataclass(frozen=True, slots=True)
class ChunkFragment:
    """Decoded fragment of a reconstructed media chunk."""

    chunk_id: int
    offset: int
    total_length: int
    data: bytes
    record_index: int


@dataclass(frozen=True, slots=True)
class ChunkAssembly:
    """Assembly output for one chunk id."""

    chunk_id: int
    total_length: int
    assembled_bytes: bytes
    covered_bytes: int
    gap_map: list[tuple[int, int]]
    fragment_count: int

    @property
    def completeness_score(self) -> float:
        if self.total_length == 0:
            return 0.0
        return self.covered_bytes / self.total_length

    def as_dict(self) -> dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "total_length": self.total_length,
            "covered_bytes": self.covered_bytes,
            "completeness_score": self.completeness_score,
            "gap_map": self.gap_map,
            "fragment_count": self.fragment_count,
        }
