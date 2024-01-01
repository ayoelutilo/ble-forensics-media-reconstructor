"""ATT event extraction and chunk fragment decoding."""

from __future__ import annotations

from collections.abc import Iterable

from .errors import ATTDecodeError
from .models import ATTEvent, ChunkFragment, SnoopRecord

ATT_OPCODE_NAMES: dict[int, str] = {
    0x12: "write_request",
    0x52: "write_command",
    0x1B: "handle_value_notification",
    0x1D: "handle_value_indication",
}

_HANDLE_BASED_OPCODES = frozenset(ATT_OPCODE_NAMES.keys())
_MIN_FRAGMENT_HEADER_LEN = 6


def extract_att_events(records: Iterable[SnoopRecord]) -> list[ATTEvent]:
    """Extract ATT events from parsed records.

    This parser keeps scope intentionally narrow: only handle-based ATT opcodes
    listed in ``ATT_OPCODE_NAMES`` are decoded.
    """

    events: list[ATTEvent] = []
    for record in records:
        if not record.payload:
            continue

        opcode = record.payload[0]
        if opcode not in _HANDLE_BASED_OPCODES:
            continue

        if len(record.payload) < 3:
            continue

        handle = int.from_bytes(record.payload[1:3], "little")
        value = record.payload[3:]
        events.append(
            ATTEvent(
                record_index=record.index,
                timestamp_us=record.timestamp_us,
                direction=record.direction,
                opcode=opcode,
                opcode_name=ATT_OPCODE_NAMES[opcode],
                handle=handle,
                value=value,
            )
        )

    return events


def decode_chunk_fragment(event: ATTEvent) -> ChunkFragment:
    """Decode one chunk fragment from ATT value bytes.

    Fragment format inside ATT value:
    - chunk_id (uint16 LE)
    - offset (uint16 LE)
    - total_length (uint16 LE)
    - data bytes
    """

    if len(event.value) < _MIN_FRAGMENT_HEADER_LEN:
        raise ATTDecodeError(
            f"Record {event.record_index} value too short for chunk header: {len(event.value)}"
        )

    chunk_id = int.from_bytes(event.value[0:2], "little")
    offset = int.from_bytes(event.value[2:4], "little")
    total_length = int.from_bytes(event.value[4:6], "little")
    if total_length <= 0:
        raise ATTDecodeError(f"Record {event.record_index} has invalid total_length={total_length}")

    return ChunkFragment(
        chunk_id=chunk_id,
        offset=offset,
        total_length=total_length,
        data=event.value[6:],
        record_index=event.record_index,
    )


def extract_chunk_fragments(events: Iterable[ATTEvent], *, strict: bool = False) -> list[ChunkFragment]:
    """Decode chunk fragments from ATT events.

    When ``strict=False`` malformed fragment payloads are skipped.
    """

    fragments: list[ChunkFragment] = []
    for event in events:
        try:
            fragments.append(decode_chunk_fragment(event))
        except ATTDecodeError:
            if strict:
                raise
    return fragments

# Refinement.
