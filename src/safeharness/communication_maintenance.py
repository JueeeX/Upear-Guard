"""Scheduled communication retention and optional HTTPS audit export."""

from __future__ import annotations

import argparse
import asyncio
import os
import time
from collections.abc import Sequence
from datetime import timedelta

from safeharness.communication.maintenance import (
    AuditCursorFile,
    CommunicationMaintenance,
    HTTPSAuditExporter,
)
from safeharness.communication.postgres_store import PostgreSQLCommunicationStore


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Purge expired communication state and export minimized audit batches."
    )
    parser.add_argument("--once", action="store_true")
    parser.add_argument(
        "--interval-seconds",
        type=int,
        default=int(os.environ.get("SAFEHARNESS_COMMUNICATION_MAINTENANCE_INTERVAL", "300")),
    )
    parser.add_argument(
        "--retention-hours",
        type=int,
        default=int(os.environ.get("SAFEHARNESS_COMMUNICATION_RETENTION_HOURS", "168")),
    )
    args = parser.parse_args(argv)
    if not args.once and not 60 <= args.interval_seconds <= 86_400:
        parser.error("interval-seconds must be between 60 and 86400")

    retention_dsn = os.environ.get("SAFEHARNESS_COMMUNICATION_RETENTION_DSN", "")
    if not retention_dsn:
        parser.error("SAFEHARNESS_COMMUNICATION_RETENTION_DSN is required")
    retention_store = PostgreSQLCommunicationStore(retention_dsn)

    export_url = os.environ.get("SAFEHARNESS_COMMUNICATION_AUDIT_EXPORT_URL", "").strip()
    audit_reader = exporter = cursor_file = None
    if export_url:
        reader_dsn = os.environ.get("SAFEHARNESS_COMMUNICATION_READER_DSN", "")
        if not reader_dsn:
            parser.error("SAFEHARNESS_COMMUNICATION_READER_DSN is required for audit export")
        if reader_dsn == retention_dsn:
            parser.error("audit reader and retention DSNs must use separate identities")
        audit_reader = PostgreSQLCommunicationStore(reader_dsn)
        try:
            exporter = HTTPSAuditExporter(
                export_url,
                os.environ.get("SAFEHARNESS_COMMUNICATION_AUDIT_EXPORT_TOKEN", ""),
                ca_file=os.environ.get("SAFEHARNESS_COMMUNICATION_AUDIT_EXPORT_CA") or None,
            )
        except ValueError as exc:
            parser.error(str(exc))
        cursor_file = AuditCursorFile(
            os.environ.get(
                "SAFEHARNESS_COMMUNICATION_AUDIT_CURSOR_FILE",
                "data/communication-audit-export.cursor.json",
            )
        )

    try:
        maintenance = CommunicationMaintenance(
            retention_store,
            retention=timedelta(hours=args.retention_hours),
            audit_reader=audit_reader,
            exporter=exporter,
            cursor_file=cursor_file,
        )
    except ValueError as exc:
        parser.error(str(exc))

    while True:
        try:
            result = asyncio.run(maintenance.run_once())
        except Exception as exc:
            parser.exit(1, f"safeharness-communication-maintain: {type(exc).__name__}\n")
        print(
            "SafeHarness communication maintenance completed: "
            f"purged={result.purged_rows} exported={result.exported_records}"
        )
        if args.once:
            return 0
        try:
            time.sleep(args.interval_seconds)
        except KeyboardInterrupt:
            return 0


if __name__ == "__main__":
    raise SystemExit(main())
