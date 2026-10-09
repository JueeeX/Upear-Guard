from __future__ import annotations

import asyncio
from contextlib import redirect_stdout
from io import StringIO
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from safeharness.audit_cli import main
from safeharness.backends import SQLiteAuditReader, SQLiteAuditSink
from safeharness.ports import GatewayAuditRecord


class SQLiteAuditReaderTests(unittest.TestCase):
    def test_json_query_filters_sanitized_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.sqlite3"
            sink = SQLiteAuditSink(path)
            asyncio.run(
                sink.write_gateway(
                    GatewayAuditRecord(
                        action="tool_execute",
                        outcome="failed",
                        tenant_id="tenant-a",
                        session_id="session-a",
                        tool_name="lookup",
                        reason_code="tool_execution_failed",
                        details={"password": "must-not-escape"},
                    )
                )
            )
            asyncio.run(
                sink.write_gateway(
                    GatewayAuditRecord(
                        action="capability_issue",
                        outcome="issued",
                        tenant_id="tenant-b",
                    )
                )
            )
            output = StringIO()

            with redirect_stdout(output):
                result = main(
                    [
                        str(path),
                        "--tenant-id",
                        "tenant-a",
                        "--source",
                        "gateway",
                        "--format",
                        "json",
                    ]
                )

            rows = json.loads(output.getvalue())
            serialized = json.dumps(rows)
            self.assertEqual(result, 0)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["action"], "tool_execute")
            self.assertNotIn("must-not-escape", serialized)
            self.assertIn("[REDACTED]", serialized)

    def test_reader_does_not_create_missing_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.sqlite3"

            with self.assertRaises(FileNotFoundError):
                SQLiteAuditReader(path)

            self.assertFalse(path.exists())

    def test_reader_uses_read_only_uri(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.sqlite3"
            sink = SQLiteAuditSink(path)
            asyncio.run(
                sink.write_gateway(GatewayAuditRecord(action="health", outcome="ready"))
            )
            reader = SQLiteAuditReader(path)
            with patch(
                "safeharness.backends.sqlite.sqlite3.connect",
                wraps=sqlite3.connect,
            ) as connect:
                rows = asyncio.run(reader.query())

            self.assertEqual(len(rows), 1)
            uri = connect.call_args.args[0]
            self.assertTrue(uri.endswith("?mode=ro"))
            self.assertTrue(connect.call_args.kwargs["uri"])

    def test_cli_rejects_an_unrelated_sqlite_database_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unrelated.sqlite3"
            connection = sqlite3.connect(path)
            try:
                connection.execute("CREATE TABLE unrelated(value TEXT)")
                connection.commit()
            finally:
                connection.close()

            with self.assertRaises(SystemExit) as rejected:
                main([str(path)])

            self.assertEqual(rejected.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
