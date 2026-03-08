# ble-forensics-media-reconstructor

Python toolkit for parsing simplified btsnoop-like BLE captures and reconstructing media chunks carried in ATT traffic.

## Features

- Simplified btsnoop-like binary parser.
- ATT event extraction for common handle-based opcodes.
- Chunk fragment model (`chunk_id`, `offset`, `total_length`, `data`) decoded from ATT value bytes.
- Deterministic chunk assembler with:
  - gap map (missing byte ranges)
  - completeness score
  - overlap handling (first-write wins in capture order)
- Reconstruction report artifacts:
  - per-chunk binary + JSON report
  - combined `reconstructed_media.bin`
  - top-level `reconstruction_report.json`
- CLI commands: `parse`, `summarize`, `assemble`, `reconstruct`.

## Install (editable)

```bash
pip install -e .
```

## Simplified Capture Format

Header:

- `magic`: 4 bytes, ASCII `BTSN`
- `version`: 1 byte, currently `1`
- `reserved`: 3 bytes

Records (repeated):

- `timestamp_us`: `uint64` little-endian
- `direction`: `uint8` (`0` outgoing, `1` incoming)
- `payload_len`: `uint16` little-endian
- `payload`: raw bytes

## Chunk Fragment Payload Format

This is decoded from ATT value bytes:

- `chunk_id`: `uint16` LE
- `offset`: `uint16` LE
- `total_length`: `uint16` LE
- `data`: remaining bytes

## CLI

```bash
# Parse records
ble-reconstruct parse tests/fixtures/sample_capture.btsn

# Summarize ATT + fragments
ble-reconstruct summarize tests/fixtures/sample_capture.btsn

# Assemble one chunk and write output
ble-reconstruct assemble tests/fixtures/sample_capture.btsn --chunk-id 0 --output chunk0.bin

# Reconstruct all chunks and write artifacts
ble-reconstruct reconstruct tests/fixtures/sample_capture.btsn --output-dir out
```

## Tests

```bash
pytest
```

- Changelog: minor updates.

- Changelog: minor updates.
