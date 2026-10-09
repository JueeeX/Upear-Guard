"""Initialize the shared PostgreSQL Agent communication schema."""

from __future__ import annotations

import argparse
import os
from collections.abc import Sequence

from safeharness.communication.postgres_store import PostgreSQLCommunicationStore


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Initialize the SafeHarness PostgreSQL communication schema."
    )
    parser.add_argument(
        "--runtime-role",
        default=os.environ.get("SAFEHARNESS_COMMUNICATION_RUNTIME_ROLE", ""),
        help="Optional gateway role for mailbox, replay, counters, and audit writes.",
    )
    parser.add_argument(
        "--reader-role",
        default=os.environ.get("SAFEHARNESS_COMMUNICATION_READER_ROLE", ""),
        help="Optional read-only role for audit and mailbox inspection.",
    )
    parser.add_argument(
        "--retention-role",
        default=os.environ.get("SAFEHARNESS_COMMUNICATION_RETENTION_ROLE", ""),
        help="Optional role allowed to purge expired mailbox and replay rows.",
    )
    args = parser.parse_args(argv)
    dsn = os.environ.get("SAFEHARNESS_COMMUNICATION_POSTGRES_DSN", "")
    if not dsn:
        parser.error(
            "SAFEHARNESS_COMMUNICATION_POSTGRES_DSN must be supplied through the environment"
        )
    try:
        store = PostgreSQLCommunicationStore(dsn)
        store.initialize_schema(
            runtime_role=args.runtime_role or None,
            reader_role=args.reader_role or None,
            retention_role=args.retention_role or None,
        )
    except Exception as exc:
        parser.exit(1, f"safeharness-communication-init: {type(exc).__name__}\n")
    print("SafeHarness PostgreSQL communication schema initialized.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
