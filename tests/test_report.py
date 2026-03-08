from pathlib import Path

from ble_forensics_media_reconstructor.assembler import assemble_chunks
from ble_forensics_media_reconstructor.att import extract_att_events, extract_chunk_fragments
from ble_forensics_media_reconstructor.parser import parse_capture_file
from ble_forensics_media_reconstructor.report import write_reconstruction_artifacts

FIXTURES = Path(__file__).parent / "fixtures"


def test_reconstruction_artifacts_are_written(tmp_path: Path) -> None:
    capture_path = FIXTURES / "sample_capture.btsn"
    records = parse_capture_file(capture_path)
    events = extract_att_events(records)
    fragments = extract_chunk_fragments(events)
    assemblies = assemble_chunks(fragments)

    manifest_path, manifest = write_reconstruction_artifacts(
        tmp_path,
        assemblies,
        source_path=capture_path,
    )

    assert manifest_path.exists()
    assert (tmp_path / "chunk_0000.bin").exists()
    assert (tmp_path / "chunk_0001.bin").exists()
    assert (tmp_path / "chunk_0000.report.json").exists()
    assert (tmp_path / "chunk_0001.report.json").exists()
    assert (tmp_path / "reconstructed_media.bin").exists()
    assert manifest["overall_completeness"] == 1.0
