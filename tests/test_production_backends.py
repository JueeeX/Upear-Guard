from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from safeharness import SessionContext, ToolDescriptor, ToolInvocation
from safeharness.backends import (
    PostgreSQLAuditSink,
    RedisCapabilityReplayStore,
    RedisEnforcementReceiptReplayStore,
    SignedCapabilityGateway,
)
from safeharness.gateway import RegisteredTool, ToolGatewayApplication, ToolRegistry
from safeharness.gateway.persistence import build_gateway_persistence
from safeharness.gateway.protocol import request_to_wire
from safeharness.ports import GatewayAuditRecord


class RedisCapabilityReplayStoreTests(unittest.IsolatedAsyncioTestCase):
    async def test_atomic_consume_hashes_token_id_and_uses_absolute_expiry(self) -> None:
        client = _FakeRedis()
        now = datetime(2026, 7, 16, 8, 0, tzinfo=timezone.utc)
        expiry = now + timedelta(minutes=5)
        store = RedisCapabilityReplayStore(client=client, now=lambda: now)

        first = await store.consume("raw-token-id", expiry)
        replay = await store.consume("raw-token-id", expiry)

        expected_key = "safeharness:capability-replay:" + hashlib.sha256(
            b"raw-token-id"
        ).hexdigest()
        self.assertTrue(first)
        self.assertFalse(replay)
        self.assertEqual(client.calls[0][0], expected_key)
        self.assertNotIn("raw-token-id", client.calls[0][0])
        self.assertEqual(client.calls[0][1], b"1")
        self.assertEqual(client.calls[0][2], {"nx": True, "pxat": 1784189100000})

    async def test_expired_token_does_not_reach_redis(self) -> None:
        client = _FakeRedis()
        now = datetime(2026, 7, 16, 8, 0, tzinfo=timezone.utc)
        store = RedisCapabilityReplayStore(client=client, now=lambda: now)

        consumed = await store.consume("expired", now)

        self.assertFalse(consumed)
        self.assertEqual(client.calls, [])

    async def test_health_fails_closed_without_exposing_client_error(self) -> None:
        client = _FakeRedis(set_error=OSError("redis://user:secret@example"))
        store = RedisCapabilityReplayStore(client=client)

        self.assertFalse(await store.health())

    async def test_health_uses_the_same_redis_write_permission_as_replay(self) -> None:
        client = _FakeRedis()
        store = RedisCapabilityReplayStore(client=client)

        self.assertTrue(await store.health())
        self.assertEqual(
            client.calls[0],
            ("safeharness:capability-replay:health", b"1", {"px": 1000}),
        )

    def test_key_prefix_is_bounded_and_safe_for_operational_use(self) -> None:
        with self.assertRaises(ValueError):
            RedisCapabilityReplayStore(client=_FakeRedis(), key_prefix="bad prefix")

    async def test_receipt_replay_uses_an_independent_hashed_namespace(self) -> None:
        client = _FakeRedis()
        now = datetime(2026, 7, 16, 8, 0, tzinfo=timezone.utc)
        store = RedisEnforcementReceiptReplayStore(client=client, now=lambda: now)

        self.assertTrue(
            await store.consume("raw-receipt-id", now + timedelta(minutes=1))
        )
        key = client.calls[0][0]
        self.assertTrue(key.startswith("safeharness:receipt-replay:"))
        self.assertNotIn("raw-receipt-id", key)


class PostgreSQLAuditSinkTests(unittest.IsolatedAsyncioTestCase):
    async def test_gateway_insert_uses_sanitized_shared_audit_row(self) -> None:
        factory = _FakePostgresFactory()
        sink = PostgreSQLAuditSink(connect=factory, initialize=False)
        record = GatewayAuditRecord(
            action="tool_execute",
            outcome="failed",
            tenant_id="tenant-a",
            details={
                "password": "database-password",
                "result": "private-nms-result",
            },
        )

        await sink.write_gateway(record)

        connection = factory.connections[0]
        query, values = connection.cursor_instance.executions[0]
        serialized = json.dumps(values)
        self.assertIn("INSERT INTO safeharness_audit_records", query)
        self.assertIn("CAST(%s AS timestamptz)", query)
        self.assertIn("CAST(%s AS jsonb)", query)
        self.assertNotIn("database-password", serialized)
        self.assertNotIn("private-nms-result", serialized)
        self.assertIn("[REDACTED]", serialized)
        self.assertEqual(connection.commits, 1)
        self.assertEqual(connection.rollbacks, 0)

    async def test_insert_failure_rolls_back_and_propagates(self) -> None:
        factory = _FakePostgresFactory(fail_insert=True)
        sink = PostgreSQLAuditSink(connect=factory, initialize=False)

        with self.assertRaises(OSError):
            await sink.write_gateway(
                GatewayAuditRecord(action="tool_execute", outcome="failed")
            )

        connection = factory.connections[0]
        self.assertEqual(connection.commits, 0)
        self.assertEqual(connection.rollbacks, 1)

    async def test_health_returns_boolean_and_closes_connection(self) -> None:
        factory = _FakePostgresFactory(select_one=(True,))
        sink = PostgreSQLAuditSink(connect=factory, initialize=False)

        self.assertTrue(await sink.health())
        self.assertTrue(factory.connections[0].closed)

    def test_schema_installs_append_only_triggers_and_checks_version(self) -> None:
        factory = _FakePostgresFactory(schema_version=(1,))

        PostgreSQLAuditSink(connect=factory, initialize=True)

        connection = factory.connections[0]
        schema_sql = "\n".join(
            query for query, _ in connection.cursor_instance.executions
        )
        self.assertIn("BEFORE UPDATE", schema_sql)
        self.assertIn("BEFORE DELETE", schema_sql)
        self.assertIn("SafeHarness audit records are append-only", schema_sql)
        self.assertEqual(connection.commits, 1)

    def test_schema_can_install_least_privilege_runtime_and_reader_roles(self) -> None:
        factory = _FakePostgresFactory(schema_version=(1,))
        sink = PostgreSQLAuditSink(connect=factory, initialize=False)

        sink.initialize_schema(
            runtime_role="safeharness_writer",
            reader_role="safeharness_reader",
        )

        schema_sql = "\n".join(
            query for query, _ in factory.connections[0].cursor_instance.executions
        )
        self.assertIn(
            "GRANT INSERT ON TABLE safeharness_audit_records TO safeharness_writer",
            schema_sql,
        )
        self.assertIn(
            "GRANT SELECT ON TABLE safeharness_schema, safeharness_audit_records "
            "TO safeharness_reader",
            schema_sql,
        )
        self.assertIn(
            "REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER",
            schema_sql,
        )
        self.assertNotIn(
            "GRANT SELECT ON TABLE safeharness_audit_records TO safeharness_writer",
            schema_sql,
        )

    def test_postgres_role_names_are_not_an_sql_injection_surface(self) -> None:
        sink = PostgreSQLAuditSink(
            connect=_FakePostgresFactory(),
            initialize=False,
        )
        with self.assertRaises(ValueError):
            sink.initialize_schema(runtime_role="writer; DROP ROLE postgres")
        with self.assertRaises(ValueError):
            sink.initialize_schema(
                runtime_role="safeharness_shared",
                reader_role="safeharness_shared",
            )

    def test_table_name_is_not_an_sql_injection_surface(self) -> None:
        with self.assertRaises(ValueError):
            PostgreSQLAuditSink(
                connect=_FakePostgresFactory(),
                table="audit; DROP TABLE users",
                initialize=False,
            )


class GatewayProductionCompositionTests(unittest.IsolatedAsyncioTestCase):
    async def test_replay_store_failure_returns_503_and_never_dispatches(self) -> None:
        descriptor = ToolDescriptor(
            "lookup", required_capabilities=frozenset({"lookup:read"})
        )
        calls = 0

        def executor(query):
            nonlocal calls
            calls += 1
            return query

        context = SessionContext(tenant_id="tenant-a", agent_id="agent-a")
        invocation = ToolInvocation(
            descriptor.name,
            {"query": "alarm"},
            tool_version=descriptor.version,
        )
        capabilities = SignedCapabilityGateway(
            b"k" * 32,
            {("tenant-a", "agent-a"): {"lookup:read"}},
            replay_store=_FailingReplayStore(),
        )
        application = ToolGatewayApplication(
            registry=ToolRegistry([RegisteredTool(descriptor, executor)]),
            capability_gateway=capabilities,
        )
        grant = await capabilities.issue(context, descriptor, invocation)
        bound = ToolInvocation(
            invocation.tool_name,
            invocation.arguments,
            call_id=invocation.call_id,
            tool_version=invocation.tool_version,
            capability_token=grant.token,
        )

        status, response = await application.execute(request_to_wire(context, bound))

        self.assertEqual(status, 503)
        self.assertEqual(
            response["error"]["code"], "capability_replay_store_unavailable"
        )
        self.assertEqual(calls, 0)

    async def test_health_checks_all_dependencies_without_leaking_errors(self) -> None:
        application = ToolGatewayApplication(
            registry=ToolRegistry(),
            capability_gateway=SignedCapabilityGateway(b"k" * 32, {}),
            readiness_checks=(lambda: True, _raise_dependency_secret),
        )

        with self.assertLogs("safeharness.gateway.service", level="ERROR") as logs:
            status, response = await application.health()
        serialized = json.dumps(response)
        log_output = "\n".join(logs.output)

        self.assertEqual(status, 503)
        self.assertEqual(response["error"]["code"], "gateway_not_ready")
        self.assertNotIn("postgresql://user:password", serialized)
        self.assertNotIn("postgresql://user:password", log_output)
        self.assertIn("OSError", log_output)

    async def test_sqlite_composition_reports_ready(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            persistence = build_gateway_persistence(
                replay_backend="sqlite",
                audit_backend="sqlite",
                sqlite_path=Path(directory) / "gateway.sqlite3",
            )

            results = []
            for check in persistence.readiness_checks:
                results.append(await check())

            self.assertEqual(results, [True, True, True])
            self.assertEqual(len(persistence.readiness_checks), 3)
            self.assertEqual(persistence.replay_backend, "sqlite")
            self.assertEqual(persistence.audit_backend, "sqlite")

    def test_production_composition_selects_redis_and_postgres(self) -> None:
        replay = object()
        receipt_replay = object()
        audit = object()
        with patch(
            "safeharness.gateway.persistence.RedisCapabilityReplayStore",
            return_value=replay,
        ) as redis_backend, patch(
            "safeharness.gateway.persistence.RedisEnforcementReceiptReplayStore",
            return_value=receipt_replay,
        ) as receipt_redis_backend, patch(
            "safeharness.gateway.persistence.PostgreSQLAuditSink",
            return_value=audit,
        ) as postgres_backend:
            persistence = build_gateway_persistence(
                replay_backend="redis",
                audit_backend="postgres",
                redis_url="rediss://redis.internal/0",
                postgres_dsn="postgresql://postgres.internal/safeharness",
            )

        self.assertIs(persistence.replay_store, replay)
        self.assertIs(persistence.receipt_replay_store, receipt_replay)
        self.assertIs(persistence.audit_sink, audit)
        redis_backend.assert_called_once()
        receipt_redis_backend.assert_called_once()
        postgres_backend.assert_called_once()


class _FailingReplayStore:
    async def consume(self, token_id, expires_at):
        raise OSError("redis unavailable")


def _raise_dependency_secret():
    raise OSError("postgresql://user:password@internal/safeharness")


class _FakeRedis:
    def __init__(self, *, set_error: Exception | None = None) -> None:
        self.calls: list[tuple[str, bytes, dict[str, object]]] = []
        self.keys: set[str] = set()
        self.set_error = set_error

    def set(self, key, value, **options):
        if self.set_error is not None:
            raise self.set_error
        self.calls.append((key, value, options))
        if key in self.keys:
            return None
        self.keys.add(key)
        return True

class _FakePostgresFactory:
    def __init__(
        self,
        *,
        fail_insert: bool = False,
        select_one=(1,),
        schema_version=(1,),
    ) -> None:
        self.fail_insert = fail_insert
        self.select_one = select_one
        self.schema_version = schema_version
        self.connections: list[_FakeConnection] = []

    def __call__(self):
        connection = _FakeConnection(
            fail_insert=self.fail_insert,
            select_one=self.select_one,
            schema_version=self.schema_version,
        )
        self.connections.append(connection)
        return connection


class _FakeConnection:
    def __init__(self, *, fail_insert, select_one, schema_version) -> None:
        self.cursor_instance = _FakeCursor(
            fail_insert=fail_insert,
            select_one=select_one,
            schema_version=schema_version,
        )
        self.commits = 0
        self.rollbacks = 0
        self.closed = False

    def cursor(self):
        return self.cursor_instance

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True


class _FakeCursor:
    def __init__(self, *, fail_insert, select_one, schema_version) -> None:
        self.fail_insert = fail_insert
        self.select_one = select_one
        self.schema_version = schema_version
        self.executions: list[tuple[str, object]] = []
        self.last_query = ""
        self.closed = False

    def execute(self, query, values=None):
        self.last_query = query
        self.executions.append((query, values))
        if self.fail_insert and query.lstrip().startswith("INSERT INTO safeharness_audit"):
            raise OSError("postgres unavailable")

    def fetchone(self):
        if "SELECT version FROM safeharness_schema" in self.last_query:
            return self.schema_version
        return self.select_one

    def close(self):
        self.closed = True


if __name__ == "__main__":
    unittest.main()
