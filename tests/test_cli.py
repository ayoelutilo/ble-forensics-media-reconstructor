from pathlib import Path

from ble_forensics_media_reconstructor.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_cli_assemble_writes_chunk_file(tmp_path: Path) -> None:
    capture = FIXTURES / "sample_capture.btsn"
    output = tmp_path / "chunk0.bin"

    exit_code = main(
        [
            "assemble",
            str(capture),
            "--chunk-id",
            "0",
            "--output",
            str(output),
        ]
    )

    assert exit_code == 0
    assert output.read_bytes() == b"hello world"


def test_cli_reconstruct_writes_manifest(tmp_path: Path) -> None:
    capture = FIXTURES / "sample_capture.btsn"

    exit_code = main(
        [
            "reconstruct",
            str(capture),
            "--output-dir",
            str(tmp_path),
        ]
    )

    assert exit_code == 0
    assert (tmp_path / "reconstruction_report.json").exists()


def test_cli_parse_rejects_negative_limit() -> None:
    capture = FIXTURES / "sample_capture.btsn"

    exit_code = main(
        [
            "parse",
            str(capture),
            "--limit",
            "-1",
        ]
    )

    assert exit_code == 2


def test_cli_missing_input_file_returns_error_code() -> None:
    missing = FIXTURES / "does-not-exist.btsn"

    exit_code = main(
        [
            "summarize",
            str(missing),
        ]
    )

    assert exit_code == 2

# Refinement.
