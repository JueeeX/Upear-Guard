"""Read-only command-line access to a SafeHarness SQLite audit database."""

from __future__ import annotations

import argparse
import asyncio
import json
import sqlite3
import sys
from collections.abc import Sequence
from typing import Any, TextIO

from safeharness.backends.sqlite import SQLiteAuditReader


_TABLE_COLUMNS = (
    "occurred_at",
    "source",
    "action",
    "outcome",
    "tenant_id",
    "agent_id",
    "session_id",
    "tool_name",
    "reason_code",
    "request_id",
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        rows = asyncio.run(
            SQLiteAuditReader(args.database).query(
                tenant_id=args.tenant_id,
                session_id=args.session_id,
                source=args.source,
                action=args.action,
                limit=args.limit,
            )
        )
    except (
        FileNotFoundError,
        OSError,
        RuntimeError,
        ValueError,
        sqlite3.DatabaseError,
    ) as exc:
        parser.exit(2, f"safeharness-audit: {exc}\n")

    _write_rows(rows, output_format=args.format, stream=sys.stdout)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Query an existing SafeHarness SQLite audit database read-only."
    )
    parser.add_argument("database", help="Path to an existing SafeHarness SQLite file.")
    parser.add_argument("--tenant-id")
    parser.add_argument("--session-id")
    parser.add_argument("--source", choices=("agent", "gateway"))
    parser.add_argument("--action")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument(
        "--format",
        choices=("table", "json", "jsonl"),
        default="table",
        help="Output format (default: table). JSON formats include sanitized payloads.",
    )
    return parser


def _write_rows(
    rows: list[dict[str, Any]], *, output_format: str, stream: TextIO
) -> None:
    if output_format == "json":
        json.dump(rows, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")
        return
    if output_format == "jsonl":
        for row in rows:
            stream.write(
                json.dumps(row, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            )
            stream.write("\n")
        return
    _write_table(rows, stream)


def _write_table(rows: list[dict[str, Any]], stream: TextIO) -> None:
    if not rows:
        stream.write("No audit records matched.\n")
        return
    values = [
        [_table_value(row.get(column, "")) for column in _TABLE_COLUMNS]
        for row in rows
    ]
    widths = [
        min(36, max(len(column), *(len(row[index]) for row in values)))
        for index, column in enumerate(_TABLE_COLUMNS)
    ]
    stream.write(_table_line(_TABLE_COLUMNS, widths) + "\n")
    stream.write(_table_line(tuple("-" * width for width in widths), widths) + "\n")
    for row in values:
        stream.write(_table_line(row, widths) + "\n")


def _table_line(values: Sequence[str], widths: Sequence[int]) -> str:
    return "  ".join(
        _truncate(value, width).ljust(width) for value, width in zip(values, widths)
    ).rstrip()


def _table_value(value: Any) -> str:
    return str(value).replace("\r", " ").replace("\n", " ")


def _truncate(value: str, width: int) -> str:
    return value if len(value) <= width else value[: max(0, width - 3)] + "..."


if __name__ == "__main__":
    raise SystemExit(main())
