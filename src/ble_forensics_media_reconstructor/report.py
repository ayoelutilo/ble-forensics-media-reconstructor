"""Reconstruction report artifact helpers."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .models import ChunkAssembly


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def chunk_report_dict(assembly: ChunkAssembly) -> dict[str, Any]:
    """Return a report dictionary for one chunk assembly."""

    return {
        **assembly.as_dict(),
        "sha256": _sha256_hex(assembly.assembled_bytes),
    }


def write_json(path: Path, payload: dict[str, Any]) -> None:
    """Write pretty JSON with stable key ordering."""

    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_reconstruction_artifacts(
    output_dir: str | Path,
    assemblies: dict[int, ChunkAssembly],
    *,
    source_path: str | Path | None = None,
) -> tuple[Path, dict[str, Any]]:
    """Write per-chunk artifacts and a top-level reconstruction report."""

    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)

    chunk_entries: list[dict[str, Any]] = []
    combined = bytearray()

    for chunk_id in sorted(assemblies):
        assembly = assemblies[chunk_id]
        chunk_artifact = destination / f"chunk_{chunk_id:04d}.bin"
        chunk_artifact.write_bytes(assembly.assembled_bytes)

        report = chunk_report_dict(assembly)
        report["artifact_path"] = chunk_artifact.name

        chunk_report_path = destination / f"chunk_{chunk_id:04d}.report.json"
        write_json(chunk_report_path, report)

        chunk_entries.append(
            {
                **report,
                "report_path": chunk_report_path.name,
            }
        )
        combined.extend(assembly.assembled_bytes)

    combined_artifact = destination / "reconstructed_media.bin"
    combined_artifact.write_bytes(bytes(combined))

    total_expected = sum(assembly.total_length for assembly in assemblies.values())
    total_recovered = sum(assembly.covered_bytes for assembly in assemblies.values())

    manifest: dict[str, Any] = {
        "source_path": str(source_path) if source_path is not None else None,
        "chunk_count": len(assemblies),
        "total_expected_bytes": total_expected,
        "total_recovered_bytes": total_recovered,
        "overall_completeness": (total_recovered / total_expected) if total_expected else 0.0,
        "combined_artifact": combined_artifact.name,
        "chunks": chunk_entries,
    }

    manifest_path = destination / "reconstruction_report.json"
    write_json(manifest_path, manifest)
    return manifest_path, manifest

# Refinement.
