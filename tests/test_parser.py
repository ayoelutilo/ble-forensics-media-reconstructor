from pathlib import Path

import pytest

from ble_forensics_media_reconstructor.errors import ParseError
from ble_forensics_media_reconstructor.parser import parse_capture_bytes, parse_capture_file

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_valid_capture_file() -> None:
    records = parse_capture_file(FIXTURES / "sample_capture.btsn")

    assert len(records) == 5
    assert records[0].timestamp_us == 1_000_000
    assert records[0].payload[0] == 0x52
    assert records[2].direction.name == "INCOMING"


def test_parse_rejects_bad_magic() -> None:
    with pytest.raises(ParseError, match="Unexpected magic"):
        parse_capture_bytes(b"NOPE" + bytes([1, 0, 0, 0]))


def test_parse_rejects_truncated_payload() -> None:
    with pytest.raises(ParseError, match="Truncated payload"):
        parse_capture_file(FIXTURES / "malformed_truncated_payload.btsn")
