"""Command-line interface for BLE forensics reconstruction."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from .assembler import assemble_chunks
from .att import ATT_OPCODE_NAMES, extract_att_events, extract_chunk_fragments
from .errors import ATTDecodeError, ParseError
from .parser import parse_capture_file
from .report import chunk_report_dict, write_reconstruction_artifacts


def _dump_json(payload: dict[str, Any] | list[dict[str, Any]]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def positive_limit(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("--limit must be a positive integer")
    return parsed


def cmd_parse(args: argparse.Namespace) -> int:
    records = parse_capture_file(args.capture)
    if args.limit is not None:
        records = records[: args.limit]

    payload = [
        {
            "index": record.index,
            "timestamp_us": record.timestamp_us,
            "direction": record.direction.name.lower(),
            "payload_len": record.payload_len,
            "payload_hex": record.payload.hex(),
        }
        for record in records
    ]
    _dump_json(payload)
    return 0


def cmd_summarize(args: argparse.Namespace) -> int:
    records = parse_capture_file(args.capture)
    events = extract_att_events(records)
    fragments = extract_chunk_fragments(events, strict=False)

    opcode_counter = Counter(event.opcode_name for event in events)
    chunks = Counter(fragment.chunk_id for fragment in fragments)

    summary: dict[str, Any] = {
        "record_count": len(records),
        "att_event_count": len(events),
        "fragment_count": len(fragments),
        "opcode_counts": dict(sorted(opcode_counter.items())),
        "chunk_fragment_counts": dict(sorted(chunks.items())),
        "known_att_opcodes": {
            f"0x{opcode:02x}": name for opcode, name in sorted(ATT_OPCODE_NAMES.items())
        },
    }
    _dump_json(summary)
    return 0


def cmd_assemble(args: argparse.Namespace) -> int:
    records = parse_capture_file(args.capture)
    events = extract_att_events(records)
    fragments = extract_chunk_fragments(events, strict=args.strict)
    if not fragments:
        raise ValueError("No decodable chunk fragments in capture")

    assemblies = assemble_chunks(fragments)
    chunk_id = args.chunk_id if args.chunk_id is not None else min(assemblies)
    if chunk_id not in assemblies:
        raise ValueError(f"Chunk id {chunk_id} not found in capture")

    assembly = assemblies[chunk_id]
    report = chunk_report_dict(assembly)

    if args.output is not None:
        output_path = Path(args.output)
        output_path.write_bytes(assembly.assembled_bytes)
        report["artifact_path"] = str(output_path)

    _dump_json(report)
    return 0


def cmd_reconstruct(args: argparse.Namespace) -> int:
    records = parse_capture_file(args.capture)
    events = extract_att_events(records)
    fragments = extract_chunk_fragments(events, strict=args.strict)
    if not fragments:
        raise ValueError("No decodable chunk fragments in capture")

    assemblies = assemble_chunks(fragments)
    manifest_path, manifest = write_reconstruction_artifacts(
        args.output_dir,
        assemblies,
        source_path=args.capture,
    )
    manifest["manifest_path"] = str(manifest_path)
    _dump_json(manifest)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ble-reconstruct",
        description="Parse and reconstruct simplified BLE media chunk captures.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    parse_cmd = subparsers.add_parser("parse", help="Parse capture records.")
    parse_cmd.add_argument("capture", help="Path to capture file.")
    parse_cmd.add_argument(
        "--limit",
        type=positive_limit,
        default=None,
        help="Limit record output count (positive integer).",
    )
    parse_cmd.set_defaults(func=cmd_parse)

    summarize_cmd = subparsers.add_parser("summarize", help="Summarize ATT and fragment stats.")
    summarize_cmd.add_argument("capture", help="Path to capture file.")
    summarize_cmd.set_defaults(func=cmd_summarize)

    assemble_cmd = subparsers.add_parser("assemble", help="Assemble one chunk id.")
    assemble_cmd.add_argument("capture", help="Path to capture file.")
    assemble_cmd.add_argument("--chunk-id", type=int, default=None, help="Target chunk id.")
    assemble_cmd.add_argument(
        "--strict",
        action="store_true",
        help="Fail on malformed chunk payloads instead of skipping them.",
    )
    assemble_cmd.add_argument(
        "--output",
        default=None,
        help="Optional path for the assembled chunk bytes.",
    )
    assemble_cmd.set_defaults(func=cmd_assemble)

    reconstruct_cmd = subparsers.add_parser(
        "reconstruct",
        help="Assemble all chunk ids and write reconstruction artifacts.",
    )
    reconstruct_cmd.add_argument("capture", help="Path to capture file.")
    reconstruct_cmd.add_argument(
        "--output-dir",
        default="reconstruction_artifacts",
        help="Directory where artifacts and reports are written.",
    )
    reconstruct_cmd.add_argument(
        "--strict",
        action="store_true",
        help="Fail on malformed chunk payloads instead of skipping them.",
    )
    reconstruct_cmd.set_defaults(func=cmd_reconstruct)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 2
        return code if code != 0 else 2
    try:
        return args.func(args)
    except (ParseError, ATTDecodeError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

# Refinement.
