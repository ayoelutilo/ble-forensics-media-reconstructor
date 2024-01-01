# ADR 0001: Simplified BLE Forensics Reconstruction Architecture

- Status: Accepted
- Date: 2024-06-15

## Context

The project needs a pragmatic, testable pipeline for reconstructing media-like payloads from BLE ATT traffic without depending on full protocol stacks or external parsing libraries.

## Decision

Implement the system as a small, composable Python package with four layers:

1. Parser (`parser.py`)
   - Parse a strict, documented btsnoop-like binary format.
   - Fail fast on malformed file headers, record headers, or payload lengths.
2. ATT extraction (`att.py`)
   - Decode a constrained set of handle-based ATT opcodes.
   - Interpret ATT value bytes as chunk fragments.
   - Support strict mode (raise) and lenient mode (skip malformed fragments).
3. Assembly (`assembler.py`)
   - Group by `chunk_id`.
   - Reconstruct chunks deterministically using capture order.
   - Produce gap map and completeness score for forensic confidence.
4. Reporting (`report.py`)
   - Emit per-chunk binary and JSON reports.
   - Emit combined media artifact and top-level reconstruction manifest.

Expose these capabilities through a simple CLI (`parse`, `summarize`, `assemble`, `reconstruct`) built with `argparse` for zero runtime dependencies.

## Consequences

Positive:

- Simple, auditable format and implementation.
- Deterministic assembly behavior supports reproducible results.
- Gap map and completeness scoring make uncertainty explicit.
- CLI and library API share the same core logic.

Trade-offs:

- Parser intentionally supports a simplified capture format, not full btsnoop variants.
- ATT decoding is scoped to a subset of opcodes.
- Combined artifact is a raw concatenation of chunk binaries; container-aware reconstruction is out of scope.
