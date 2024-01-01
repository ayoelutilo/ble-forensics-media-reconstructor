"""Chunk assembly and gap-map generation."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from .models import ChunkAssembly, ChunkFragment


def _compute_gap_map(coverage: list[bool]) -> list[tuple[int, int]]:
    gap_map: list[tuple[int, int]] = []
    gap_start: int | None = None

    for index, is_covered in enumerate(coverage):
        if is_covered:
            if gap_start is not None:
                gap_map.append((gap_start, index))
                gap_start = None
            continue

        if gap_start is None:
            gap_start = index

    if gap_start is not None:
        gap_map.append((gap_start, len(coverage)))

    return gap_map


def assemble_fragments(
    fragments: Iterable[ChunkFragment],
    *,
    chunk_id: int | None = None,
) -> ChunkAssembly:
    """Assemble one chunk from one or more fragments.

    Assembly is deterministic:
    - fragments are processed in capture order (record_index)
    - first-write wins when offsets overlap
    """

    fragment_list = list(fragments)
    if not fragment_list:
        raise ValueError("No fragments supplied for assembly")

    resolved_chunk_id = chunk_id if chunk_id is not None else fragment_list[0].chunk_id
    for fragment in fragment_list:
        if fragment.chunk_id != resolved_chunk_id:
            raise ValueError(
                f"Mixed chunk ids in assembly call: expected {resolved_chunk_id}, got {fragment.chunk_id}"
            )

    total_length = fragment_list[0].total_length
    for fragment in fragment_list:
        if fragment.total_length != total_length:
            raise ValueError(
                f"Conflicting total_length values for chunk {resolved_chunk_id}: "
                f"expected {total_length}, got {fragment.total_length}"
            )

    if total_length <= 0:
        raise ValueError("total_length must be positive")

    assembled = bytearray(total_length)
    coverage = [False] * total_length

    for fragment in sorted(fragment_list, key=lambda item: item.record_index):
        if fragment.offset >= total_length:
            continue

        writable = min(len(fragment.data), total_length - fragment.offset)
        for position in range(writable):
            absolute = fragment.offset + position
            if coverage[absolute]:
                continue
            assembled[absolute] = fragment.data[position]
            coverage[absolute] = True

    covered_bytes = sum(1 for covered in coverage if covered)
    gap_map = _compute_gap_map(coverage)

    return ChunkAssembly(
        chunk_id=resolved_chunk_id,
        total_length=total_length,
        assembled_bytes=bytes(assembled),
        covered_bytes=covered_bytes,
        gap_map=gap_map,
        fragment_count=len(fragment_list),
    )


def assemble_chunks(fragments: Iterable[ChunkFragment]) -> dict[int, ChunkAssembly]:
    """Assemble all chunks found in a fragment stream."""

    grouped: dict[int, list[ChunkFragment]] = defaultdict(list)
    for fragment in fragments:
        grouped[fragment.chunk_id].append(fragment)

    return {
        chunk_id: assemble_fragments(chunk_fragments, chunk_id=chunk_id)
        for chunk_id, chunk_fragments in sorted(grouped.items())
    }

# Refinement.
