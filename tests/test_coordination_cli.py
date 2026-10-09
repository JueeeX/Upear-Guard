from __future__ import annotations

import io
import os
import unittest
from unittest.mock import patch

from safeharness import coordination_cli


class CoordinationInitCLITests(unittest.TestCase):
    def test_cli_uses_environment_only_and_forwards_roles(self) -> None:
        store = _RecordingStore()
        environment = {
            "SAFEHARNESS_COORDINATION_POSTGRES_DSN": "postgresql://migration/db",
            "SAFEHARNESS_COORDINATION_SIGNING_KEY": "k" * 32,
            "SAFEHARNESS_COORDINATION_RUNTIME_ROLE": "coordination_writer",
            "SAFEHARNESS_COORDINATION_READER_ROLE": "coordination_reader",
        }
        with patch.dict(os.environ, environment, clear=True), patch(
            "safeharness.coordination_cli.PostgreSQLCoordinationStore",
            return_value=store,
        ) as constructor, patch("sys.stdout", new_callable=io.StringIO):
            result = coordination_cli.main([])

        self.assertEqual(result, 0)
        constructor.assert_called_once_with(b"k" * 32, "postgresql://migration/db")
        self.assertEqual(
            store.options,
            {
                "runtime_role": "coordination_writer",
                "reader_role": "coordination_reader",
            },
        )

    def test_cli_does_not_echo_dsn_or_signing_key_on_failure(self) -> None:
        environment = {
            "SAFEHARNESS_COORDINATION_POSTGRES_DSN": (
                "postgresql://user:secret@internal/safeharness"
            ),
            "SAFEHARNESS_COORDINATION_SIGNING_KEY": "private-coordination-signing-key-123",
        }
        with patch.dict(os.environ, environment, clear=True), patch(
            "safeharness.coordination_cli.PostgreSQLCoordinationStore",
            side_effect=OSError("postgresql://user:secret@internal/safeharness"),
        ), patch("sys.stderr", new_callable=io.StringIO) as stderr:
            with self.assertRaises(SystemExit) as exited:
                coordination_cli.main([])

        self.assertEqual(exited.exception.code, 1)
        self.assertEqual(stderr.getvalue(), "safeharness-coordination-init: OSError\n")


class _RecordingStore:
    def __init__(self) -> None:
        self.options = None

    def initialize_schema(self, **options) -> None:
        self.options = options


if __name__ == "__main__":
    unittest.main()
