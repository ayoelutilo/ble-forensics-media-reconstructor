from pathlib import Path

import pytest

from ble_forensics_media_reconstructor.assembler import assemble_fragments
from ble_forensics_media_reconstructor.att import extract_att_events, extract_chunk_fragments
from ble_forensics_media_reconstructor.models import ChunkFragment
from ble_forensics_media_reconstructor.parser import parse_capture_file

FIXTURES = Path(__file__).parent / "fixtures"


def test_out_of_order_chunk_assembly_recovers_original_payload() -> None:
    records = parse_capture_file(FIXTURES / "sample_capture.btsn")
    events = extract_att_events(records)
    fragments = [fragment for fragment in extract_chunk_fragments(events) if fragment.chunk_id == 0]

    # Reverse order to emulate out-of-order arrival in the assembly input.
    assembly = assemble_fragments(list(reversed(fragments)), chunk_id=0)

    assert assembly.assembled_bytes == b"hello world"
    assert assembly.gap_map == []
    assert assembly.completeness_score == pytest.approx(1.0)


def test_completeness_scoring_and_gap_map() -> None:
    fragments = [
        ChunkFragment(chunk_id=9, offset=0, total_length=10, data=b"abc", record_index=0),
        ChunkFragment(chunk_id=9, offset=7, total_length=10, data=b"xy", record_index=1),
    ]

    assembly = assemble_fragments(fragments, chunk_id=9)

    assert assembly.covered_bytes == 5
    assert assembly.total_length == 10
    assert assembly.gap_map == [(3, 7), (9, 10)]
    assert assembly.completeness_score == pytest.approx(0.5)


def test_conflicting_total_length_rejected() -> None:
    fragments = [
        ChunkFragment(chunk_id=9, offset=0, total_length=10, data=b"abc", record_index=0),
        ChunkFragment(chunk_id=9, offset=3, total_length=12, data=b"def", record_index=1),
    ]

    with pytest.raises(ValueError, match="Conflicting total_length"):
        assemble_fragments(fragments, chunk_id=9)
