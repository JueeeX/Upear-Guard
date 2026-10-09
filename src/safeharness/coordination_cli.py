"""Initialize the PostgreSQL coordination-control-plane schema."""

from __future__ import annotations

import argparse
import os
from collections.abc import Sequence

from safeharness.communication.persistence import PostgreSQLCoordinationStore


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Initialize the SafeHarness PostgreSQL coordination schema."
    )
    parser.add_argument(
        "--runtime-role",
        default=os.environ.get("SAFEHARNESS_COORDINATION_RUNTIME_ROLE", ""),
        help="Optional role allowed to read and commit coordination state.",
    )
    parser.add_argument(
        "--reader-role",
        default=os.environ.get("SAFEHARNESS_COORDINATION_READER_ROLE", ""),
        help="Optional read-only role for policy inspection and backup.",
    )
    args = parser.parse_args(argv)
    dsn = os.environ.get("SAFEHARNESS_COORDINATION_POSTGRES_DSN", "")
    if not dsn:
        parser.error(
            "SAFEHARNESS_COORDINATION_POSTGRES_DSN must be supplied through the environment"
        )
    signing_key = os.environ.get("SAFEHARNESS_COORDINATION_SIGNING_KEY", "")
    if len(signing_key.encode("utf-8")) < 32:
        parser.error(
            "SAFEHARNESS_COORDINATION_SIGNING_KEY must contain at least 32 bytes"
        )
    try:
        store = PostgreSQLCoordinationStore(
            signing_key.encode("utf-8"),
            dsn,
        )
        store.initialize_schema(
            runtime_role=args.runtime_role or None,
            reader_role=args.reader_role or None,
        )
    except Exception as exc:
        parser.exit(1, f"safeharness-coordination-init: {type(exc).__name__}\n")
    print("SafeHarness PostgreSQL coordination schema initialized.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
