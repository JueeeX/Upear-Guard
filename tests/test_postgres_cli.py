from __future__ import annotations

import io
import os
import unittest
from unittest.mock import patch

from safeharness import postgres_cli


class PostgreSQLInitCLITests(unittest.TestCase):
    def test_cli_forwards_validated_runtime_and_reader_roles(self) -> None:
        sink = _RecordingSink()
        environment = {
            "SAFEHARNESS_TOOL_GATEWAY_POSTGRES_DSN": "postgresql://migration/db",
            "SAFEHARNESS_TOOL_GATEWAY_POSTGRES_RUNTIME_ROLE": "safeharness_writer",
            "SAFEHARNESS_TOOL_GATEWAY_POSTGRES_READER_ROLE": "safeharness_reader",
        }
        with patch.dict(os.environ, environment, clear=True), patch(
            "safeharness.postgres_cli.PostgreSQLAuditSink",
            return_value=sink,
        ) as constructor, patch("sys.stdout", new_callable=io.StringIO):
            result = postgres_cli.main([])

        self.assertEqual(result, 0)
        constructor.assert_called_once_with(
            "postgresql://migration/db",
            table="safeharness_audit_records",
        )
        self.assertEqual(
            sink.initialized_with,
            {
                "runtime_role": "safeharness_writer",
                "reader_role": "safeharness_reader",
            },
        )

    def test_cli_reports_only_exception_type_on_migration_failure(self) -> None:
        environment = {
            "SAFEHARNESS_TOOL_GATEWAY_POSTGRES_DSN": (
                "postgresql://user:secret@internal/safeharness"
            )
        }
        with patch.dict(os.environ, environment, clear=True), patch(
            "safeharness.postgres_cli.PostgreSQLAuditSink",
            side_effect=OSError("postgresql://user:secret@internal/safeharness"),
        ), patch("sys.stderr", new_callable=io.StringIO) as stderr:
            with self.assertRaises(SystemExit) as exited:
                postgres_cli.main([])

        self.assertEqual(exited.exception.code, 1)
        self.assertEqual(stderr.getvalue(), "safeharness-postgres-init: OSError\n")


class _RecordingSink:
    def __init__(self) -> None:
        self.initialized_with = None

    def initialize_schema(self, **options) -> None:
        self.initialized_with = options


if __name__ == "__main__":
    unittest.main()
