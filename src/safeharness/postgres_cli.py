"""Initialize the PostgreSQL audit schema with migration credentials."""

from __future__ import annotations

import argparse
import os
from collections.abc import Sequence

from safeharness.backends import PostgreSQLAuditSink


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Initialize the SafeHarness PostgreSQL audit schema."
    )
    parser.add_argument(
        "--table",
        default=os.environ.get(
            "SAFEHARNESS_TOOL_GATEWAY_POSTGRES_TABLE",
            "safeharness_audit_records",
        ),
    )
    parser.add_argument(
        "--runtime-role",
        default=os.environ.get(
            "SAFEHARNESS_TOOL_GATEWAY_POSTGRES_RUNTIME_ROLE",
            "",
        ),
        help="Optional INSERT-only gateway role to grant after migration.",
    )
    parser.add_argument(
        "--reader-role",
        default=os.environ.get(
            "SAFEHARNESS_TOOL_GATEWAY_POSTGRES_READER_ROLE",
            "",
        ),
        help="Optional read-only audit/backup role to grant after migration.",
    )
    args = parser.parse_args(argv)
    dsn = os.environ.get("SAFEHARNESS_TOOL_GATEWAY_POSTGRES_DSN", "")
    if not dsn:
        parser.error(
            "SAFEHARNESS_TOOL_GATEWAY_POSTGRES_DSN must be supplied through the environment"
        )
    try:
        sink = PostgreSQLAuditSink(dsn, table=args.table)
        sink.initialize_schema(
            runtime_role=args.runtime_role or None,
            reader_role=args.reader_role or None,
        )
    except Exception as exc:
        parser.exit(1, f"safeharness-postgres-init: {type(exc).__name__}\n")
    print("SafeHarness PostgreSQL audit schema initialized.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
