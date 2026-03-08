from pathlib import Path

import pytest

from ble_forensics_media_reconstructor.att import extract_att_events, extract_chunk_fragments
from ble_forensics_media_reconstructor.errors import ATTDecodeError
from ble_forensics_media_reconstructor.parser import parse_capture_file

FIXTURES = Path(__file__).parent / "fixtures"


def test_chunk_extraction_lenient_mode_skips_malformed_fragment() -> None:
    records = parse_capture_file(FIXTURES / "sample_capture.btsn")
    events = extract_att_events(records)
    fragments = extract_chunk_fragments(events, strict=False)

    assert len(events) == 4
    assert len(fragments) == 3


def test_chunk_extraction_strict_mode_fails_on_malformed_fragment() -> None:
    records = parse_capture_file(FIXTURES / "sample_capture.btsn")
    events = extract_att_events(records)

    with pytest.raises(ATTDecodeError, match="value too short"):
        extract_chunk_fragments(events, strict=True)

# Refinement.
