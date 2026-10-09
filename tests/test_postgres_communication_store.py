from __future__ import annotations

import hashlib
import io
import json
import os
import threading
import unittest
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from examples.langgraph_noc.communication_gateway import build_communication_gateway

from safeharness import communication_cli
from safeharness.communication import (
    CommunicationAuditRecord,
    InterAgentMessage,
    MessageKind,
    PostgreSQLCommunicationStore,
)


NOW = datetime(2026, 7, 22, 8, 0, tzinfo=timezone.utc)


def _message(
    message_id: str,
    *,
    kind: MessageKind = MessageKind.QUERY,
    delegation_id: str = "",
    created_at: datetime = NOW,
    expires_at: datetime | None = None,
) -> InterAgentMessage:
    return InterAgentMessage(
        tenant_id="fiberhome",
        sender_agent_id="supervisor",
        recipient_agent_id="diagnosis",
        session_id="session-1",
        run_id="run-1",
        trace_id="trace-1",
        kind=kind,
        content="Inspect alarm ALM-1001.",
        delegation_id=delegation_id,
        requested_capabilities=(
            frozenset({"nms:alarm:read"})
            if kind is MessageKind.DELEGATE
            else frozenset()
        ),
        metadata={"safeharness_provenance": {"trust": "medium"}},
        message_id=message_id,
        created_at=created_at,
        expires_at=expires_at or created_at + timedelta(minutes=5),
    )


def _audit(message: InterAgentMessage) -> CommunicationAuditRecord:
    return CommunicationAuditRecord(
        action="message_send",
        outcome="enqueued",
        tenant_id=message.tenant_id,
        sender_agent_id=message.sender_agent_id,
        recipient_agent_id=message.recipient_agent_id,
        message_fingerprint=message.message_fingerprint,
        message_kind=message.kind.value,
        content_sha256=message.content_sha256,
        content_length=len(message.content),
        delegation_fingerprint=(
            hashlib.sha256(message.delegation_id.encode("utf-8")).hexdigest()
            if message.delegation_id
            else ""
        ),
        request_id="request-1",
        details={"password": "must-not-be-stored", "route": "noc"},
    )


class PostgreSQLCommunicationStoreTests(unittest.IsolatedAsyncioTestCase):
    async def test_shared_lifecycle_uses_locked_leases_and_scrubs_content(self) -> None:
        factory = _FakePostgresFactory()
        sender = PostgreSQLCommunicationStore(connect=factory, now=lambda: NOW)
        receiver = PostgreSQLCommunicationStore(connect=factory, now=lambda: NOW)
        message = _message("shared-message-1")

        enqueued = await sender.enqueue(message, _audit(message))
        leases = await receiver.lease_messages(
            "fiberhome",
            "diagnosis",
            limit=1,
            lease_duration=timedelta(seconds=30),
            request_id="receive-1",
        )
        acknowledged = await sender.acknowledge(
            "fiberhome",
            "diagnosis",
            message.message_id,
            leases[0].lease_id,
            request_id="ack-1",
        )
        repeated = await receiver.acknowledge(
            "fiberhome",
            "diagnosis",
            message.message_id,
            leases[0].lease_id,
            request_id="ack-2",
        )

        self.assertTrue(enqueued.allowed)
        self.assertEqual(leases[0].message, message)
        self.assertTrue(acknowledged.allowed)
        self.assertTrue(repeated.idempotent)
        stored = factory.state.messages[message.message_id]
        self.assertEqual(stored["state"], "acknowledged")
        self.assertEqual(stored["content"], "")
        self.assertEqual(stored["metadata_json"], {})
        self.assertEqual(stored["requested_capabilities_json"], [])

        sql = "\n".join(query for query, _ in factory.state.executions)
        self.assertIn("ON CONFLICT(message_fingerprint) DO UPDATE", sql)
        self.assertIn("FOR UPDATE SKIP LOCKED", sql)
        self.assertIn("FOR UPDATE", sql)
        serialized_audit = json.dumps(factory.state.audits)
        self.assertNotIn("must-not-be-stored", serialized_audit)
        self.assertIn("[REDACTED]", serialized_audit)

    async def test_replay_and_delegation_limits_are_shared_between_instances(self) -> None:
        factory = _FakePostgresFactory()
        first = PostgreSQLCommunicationStore(connect=factory, now=lambda: NOW)
        second = PostgreSQLCommunicationStore(connect=factory, now=lambda: NOW)
        initial = _message(
            "delegated-message-1",
            kind=MessageKind.DELEGATE,
            delegation_id="delegation-1",
        )
        next_message = _message(
            "delegated-message-2",
            kind=MessageKind.DELEGATE,
            delegation_id="delegation-1",
        )

        accepted = await first.enqueue(
            initial,
            _audit(initial),
            delegation_max_messages=1,
        )
        replayed = await second.enqueue(
            initial,
            _audit(initial),
            delegation_max_messages=1,
        )
        exhausted = await second.enqueue(
            next_message,
            _audit(next_message),
            delegation_max_messages=1,
        )

        self.assertTrue(accepted.allowed)
        self.assertEqual(replayed.reason_code, "communication_message_replayed")
        self.assertEqual(exhausted.reason_code, "delegation_message_limit_exceeded")
        self.assertEqual(factory.state.delegation_usage[("fiberhome", "delegation-1")], 1)
        self.assertNotIn(next_message.message_id, factory.state.messages)

    async def test_retention_removes_only_old_mailbox_and_replay_rows(self) -> None:
        factory = _FakePostgresFactory()
        old_now = NOW - timedelta(days=10)
        old_store = PostgreSQLCommunicationStore(connect=factory, now=lambda: old_now)
        old_message = _message(
            "old-message",
            created_at=old_now,
            expires_at=old_now + timedelta(hours=1),
        )
        await old_store.enqueue(old_message, _audit(old_message))

        store = PostgreSQLCommunicationStore(connect=factory, now=lambda: NOW)
        deleted = await store.purge_expired(retention=timedelta(days=7))

        self.assertEqual(deleted, 1)
        self.assertEqual(factory.state.messages, {})
        self.assertEqual(factory.state.replay, {})
        self.assertGreaterEqual(len(factory.state.audits), 1)

    async def test_health_fails_closed_on_connection_error(self) -> None:
        store = PostgreSQLCommunicationStore(connect=_raise_postgres)
        self.assertFalse(await store.health())

    async def test_health_checks_schema_tables_and_write_permission(self) -> None:
        factory = _FakePostgresFactory()
        store = PostgreSQLCommunicationStore(connect=factory, now=lambda: NOW)

        self.assertTrue(await store.health())
        sql = "\n".join(query for query, _ in factory.state.executions)
        self.assertIn("to_regclass('safeharness_communication_messages')", sql)
        self.assertIn("INSERT INTO safeharness_communication_health", sql)
        self.assertEqual(factory.connections[-1].rollbacks, 1)

    def test_schema_installs_append_only_audit_and_separate_roles(self) -> None:
        factory = _FakePostgresFactory()
        store = PostgreSQLCommunicationStore(connect=factory)

        store.initialize_schema(
            runtime_role="communication_writer",
            reader_role="communication_reader",
            retention_role="communication_retention",
        )

        sql = "\n".join(query for query, _ in factory.state.executions)
        self.assertIn("SafeHarness communication audit is append-only", sql)
        self.assertIn(
            "GRANT INSERT ON TABLE safeharness_communication_audit TO communication_writer",
            sql,
        )
        self.assertIn(
            "GRANT DELETE ON TABLE safeharness_communication_replay",
            sql,
        )
        self.assertIn(
            "GRANT SELECT ON TABLE safeharness_communication_schema",
            sql,
        )
        with self.assertRaises(ValueError):
            store.initialize_schema(runtime_role="writer; DROP ROLE postgres")
        with self.assertRaises(ValueError):
            store.initialize_schema(
                runtime_role="same_role",
                reader_role="same_role",
            )


class CommunicationInitCLITests(unittest.TestCase):
    def test_cli_forwards_roles_without_echoing_the_dsn(self) -> None:
        recording_store = _RecordingStore()
        environment = {
            "SAFEHARNESS_COMMUNICATION_POSTGRES_DSN": "postgresql://migration/db",
            "SAFEHARNESS_COMMUNICATION_RUNTIME_ROLE": "communication_writer",
            "SAFEHARNESS_COMMUNICATION_READER_ROLE": "communication_reader",
            "SAFEHARNESS_COMMUNICATION_RETENTION_ROLE": "communication_retention",
        }
        with patch.dict(os.environ, environment, clear=True), patch(
            "safeharness.communication_cli.PostgreSQLCommunicationStore",
            return_value=recording_store,
        ) as constructor, patch("sys.stdout", new_callable=io.StringIO):
            result = communication_cli.main([])

        self.assertEqual(result, 0)
        constructor.assert_called_once_with("postgresql://migration/db")
        self.assertEqual(
            recording_store.options,
            {
                "runtime_role": "communication_writer",
                "reader_role": "communication_reader",
                "retention_role": "communication_retention",
            },
        )

    def test_cli_failure_does_not_echo_connection_secrets(self) -> None:
        environment = {
            "SAFEHARNESS_COMMUNICATION_POSTGRES_DSN": (
                "postgresql://user:secret@internal/safeharness"
            )
        }
        with patch.dict(os.environ, environment, clear=True), patch(
            "safeharness.communication_cli.PostgreSQLCommunicationStore",
            side_effect=OSError("postgresql://user:secret@internal/safeharness"),
        ), patch("sys.stderr", new_callable=io.StringIO) as stderr:
            with self.assertRaises(SystemExit) as exited:
                communication_cli.main([])

        self.assertEqual(exited.exception.code, 1)
        self.assertEqual(stderr.getvalue(), "safeharness-communication-init: OSError\n")


class CommunicationGatewayBackendCompositionTests(unittest.TestCase):
    def test_postgres_backend_requires_a_dsn(self) -> None:
        with self.assertRaisesRegex(ValueError, "communication_postgres_dsn"):
            build_communication_gateway(
                database_path="unused.sqlite3",
                communication_backend="postgres",
                now=lambda: NOW,
            )

    def test_builder_selects_the_shared_postgres_backend(self) -> None:
        backend = object()

        def clock() -> datetime:
            return NOW

        with patch(
            "examples.langgraph_noc.communication_gateway.PostgreSQLCommunicationStore",
            return_value=backend,
        ) as constructor:
            application, store = build_communication_gateway(
                database_path="unused.sqlite3",
                communication_backend="postgres",
                communication_postgres_dsn="postgresql://communication/db",
                communication_postgres_initialize=True,
                now=clock,
            )

        self.assertIs(store, backend)
        self.assertIs(application.store, backend)
        constructor.assert_called_once_with(
            "postgresql://communication/db",
            initialize=True,
            now=clock,
        )

    def test_builder_rejects_an_unknown_communication_backend(self) -> None:
        with self.assertRaisesRegex(ValueError, "must be sqlite or postgres"):
            build_communication_gateway(
                database_path="unused.sqlite3",
                communication_backend="unknown",
                now=lambda: NOW,
            )


class _RecordingStore:
    def __init__(self) -> None:
        self.options = None

    def initialize_schema(self, **options) -> None:
        self.options = options


class _FakePostgresState:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.schema_version = 1
        self.replay: dict[str, str] = {}
        self.delegation_usage: dict[tuple[str, str], int] = {}
        self.messages: dict[str, dict[str, object]] = {}
        self.audits: list[tuple[object, ...]] = []
        self.executions: list[tuple[str, object]] = []


class _FakePostgresFactory:
    def __init__(self) -> None:
        self.state = _FakePostgresState()
        self.connections: list[_FakeConnection] = []

    def __call__(self):
        connection = _FakeConnection(self.state)
        self.connections.append(connection)
        return connection


class _FakeConnection:
    def __init__(self, state: _FakePostgresState) -> None:
        self.state = state
        self.commits = 0
        self.rollbacks = 0
        self.closed = False
        self._snapshot = deepcopy(
            (state.replay, state.delegation_usage, state.messages, state.audits)
        )

    def cursor(self):
        return _FakeCursor(self.state)

    def commit(self):
        self.commits += 1
        self._snapshot = deepcopy(
            (
                self.state.replay,
                self.state.delegation_usage,
                self.state.messages,
                self.state.audits,
            )
        )

    def rollback(self):
        self.rollbacks += 1
        replay, usage, messages, audits = deepcopy(self._snapshot)
        self.state.replay = replay
        self.state.delegation_usage = usage
        self.state.messages = messages
        self.state.audits = audits

    def close(self):
        self.closed = True


class _FakeCursor:
    def __init__(self, state: _FakePostgresState) -> None:
        self.state = state
        self._one = None
        self._all = []
        self.rowcount = -1
        self.closed = False

    def execute(self, query, values=None):
        normalized = " ".join(str(query).split())
        with self.state.lock:
            self.state.executions.append((normalized, values))
            self._one = None
            self._all = []
            self.rowcount = -1
            if normalized.startswith("SELECT version") and (
                "FROM safeharness_communication_schema" in normalized
            ):
                self._one = (
                    self.state.schema_version,
                    True,
                    True,
                    True,
                    True,
                    True,
                )
            elif normalized.startswith(
                "INSERT INTO safeharness_communication_replay"
            ):
                fingerprint, _, expires_at, now = values
                current = self.state.replay.get(fingerprint)
                if current is None or datetime.fromisoformat(current) <= datetime.fromisoformat(now):
                    self.state.replay[fingerprint] = expires_at
                    self._one = (fingerprint,)
                    self.rowcount = 1
                else:
                    self.rowcount = 0
            elif normalized.startswith(
                "INSERT INTO safeharness_communication_delegation_usage"
            ):
                tenant_id, delegation_id, _, maximum = values
                key = (tenant_id, delegation_id)
                used = self.state.delegation_usage.get(key, 0)
                if used < maximum:
                    used += 1
                    self.state.delegation_usage[key] = used
                    self._one = (used,)
                    self.rowcount = 1
                else:
                    self.rowcount = 0
            elif normalized.startswith(
                "INSERT INTO safeharness_communication_messages"
            ):
                row = dict(
                    zip(
                        _MESSAGE_INSERT_COLUMNS,
                        values,
                        strict=False,
                    )
                )
                row.update(
                    state="pending",
                    lease_id="",
                    lease_until=None,
                    delivery_attempt=0,
                    acknowledged_at=None,
                )
                self.state.messages[str(row["message_id"])] = row
                self.rowcount = 1
            elif normalized.startswith(
                "INSERT INTO safeharness_communication_audit"
            ):
                self.state.audits.append(tuple(values))
                self.rowcount = 1
            elif normalized.startswith(
                "SELECT message_id, message_fingerprint"
            ) and "FOR UPDATE SKIP LOCKED" in normalized:
                tenant_id, recipient_agent_id, now_text, _, limit = values
                now = datetime.fromisoformat(now_text)
                rows = [
                    row
                    for row in self.state.messages.values()
                    if row["tenant_id"] == tenant_id
                    and row["recipient_agent_id"] == recipient_agent_id
                    and datetime.fromisoformat(str(row["expires_at"])) > now
                    and (
                        row["state"] == "pending"
                        or (
                            row["state"] == "leased"
                            and datetime.fromisoformat(str(row["lease_until"])) <= now
                        )
                    )
                ]
                rows.sort(key=lambda row: (row["created_at"], row["message_id"]))
                self._all = [
                    tuple(row[column] for column in _MESSAGE_SELECT_COLUMNS)
                    for row in rows[:limit]
                ]
            elif normalized.startswith(
                "UPDATE safeharness_communication_messages SET state = 'leased'"
            ):
                lease_id, lease_until, attempt, message_id = values
                row = self.state.messages[message_id]
                row.update(
                    state="leased",
                    lease_id=lease_id,
                    lease_until=lease_until,
                    delivery_attempt=attempt,
                )
                self.rowcount = 1
            elif normalized.startswith(
                "SELECT message_id, message_fingerprint"
            ) and normalized.endswith("FOR UPDATE"):
                tenant_id, recipient_agent_id, message_id = values
                row = self.state.messages.get(message_id)
                if (
                    row is not None
                    and row["tenant_id"] == tenant_id
                    and row["recipient_agent_id"] == recipient_agent_id
                ):
                    self._one = tuple(row[column] for column in _MESSAGE_SELECT_COLUMNS)
            elif normalized.startswith(
                "UPDATE safeharness_communication_messages SET state = 'acknowledged'"
            ):
                acknowledged_at, tenant_id, recipient_agent_id, message_id, lease_id = values
                row = self.state.messages[message_id]
                if (
                    row["tenant_id"] == tenant_id
                    and row["recipient_agent_id"] == recipient_agent_id
                    and row["lease_id"] == lease_id
                ):
                    row.update(
                        state="acknowledged",
                        acknowledged_at=acknowledged_at,
                        content="",
                        metadata_json={},
                        requested_capabilities_json=[],
                    )
                    self.rowcount = 1
            elif normalized.startswith(
                "DELETE FROM safeharness_communication_messages"
            ):
                cutoff = datetime.fromisoformat(values[0])
                expired = [
                    message_id
                    for message_id, row in self.state.messages.items()
                    if datetime.fromisoformat(str(row["expires_at"])) <= cutoff
                ]
                for message_id in expired:
                    del self.state.messages[message_id]
                self.rowcount = len(expired)
            elif normalized.startswith(
                "DELETE FROM safeharness_communication_replay"
            ):
                cutoff = datetime.fromisoformat(values[0])
                expired = [
                    fingerprint
                    for fingerprint, expires_at in self.state.replay.items()
                    if datetime.fromisoformat(expires_at) <= cutoff
                ]
                for fingerprint in expired:
                    del self.state.replay[fingerprint]
                self.rowcount = len(expired)

    def fetchone(self):
        return self._one

    def fetchall(self):
        return self._all

    def close(self):
        self.closed = True


_MESSAGE_INSERT_COLUMNS = (
    "message_id",
    "message_fingerprint",
    "tenant_id",
    "sender_agent_id",
    "recipient_agent_id",
    "session_id",
    "run_id",
    "trace_id",
    "message_kind",
    "content",
    "content_sha256",
    "correlation_id",
    "parent_message_id",
    "delegation_id",
    "requested_capabilities_json",
    "metadata_json",
    "created_at",
    "expires_at",
)

_MESSAGE_SELECT_COLUMNS = _MESSAGE_INSERT_COLUMNS + (
    "state",
    "lease_id",
    "lease_until",
    "delivery_attempt",
    "acknowledged_at",
)


def _raise_postgres():
    raise OSError("postgresql://user:secret@internal/safeharness")


if __name__ == "__main__":
    unittest.main()
