from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from safeharness import (
    EventKind,
    EventMeta,
    SafeHarnessRuntime,
    SecurityEvent,
    SessionContext,
    ToolDescriptor,
    ToolInvocation,
)
from safeharness.adapters import execute_tool
from safeharness.backends import (
    CompositeAuditSink,
    InMemoryAuditSink,
    SQLiteAuditSink,
    SQLiteCapabilityReplayStore,
    SignedCapabilityGateway,
    StaticCapabilityAuthority,
    StaticToolCatalog,
)
from safeharness.gateway import RegisteredTool, ToolGatewayApplication, ToolRegistry
from safeharness.ports import AuditRecord, GatewayAuditRecord
from safeharness.runtime import RuntimeServices

class SQLiteReplayStoreTests(unittest.IsolatedAsyncioTestCase):
    async def test_replay_record_survives_store_and_gateway_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gateway.sqlite3"
            context = SessionContext(
                tenant_id="tenant-a",
                agent_id="agent-a",
                session_id="session-a",
                run_id="run-a",
            )
            descriptor = ToolDescriptor(
                "lookup", required_capabilities=frozenset({"lookup:read"})
            )
            invocation = ToolInvocation(
                descriptor.name,
                {"query": "alarm"},
                call_id="restart-call",
                tool_version=descriptor.version,
            )
            first_gateway = SignedCapabilityGateway(
                b"k" * 32,
                {("tenant-a", "agent-a"): {"lookup:read"}},
                replay_store=SQLiteCapabilityReplayStore(path),
            )
            grant = await first_gateway.issue(context, descriptor, invocation)
            bound = ToolInvocation(
                invocation.tool_name,
                invocation.arguments,
                call_id=invocation.call_id,
                tool_version=invocation.tool_version,
                capability_token=grant.token,
            )
            first = await first_gateway.authorize(context, descriptor, bound)

            restarted_gateway = SignedCapabilityGateway(
                b"k" * 32,
                {("tenant-a", "agent-a"): {"lookup:read"}},
                replay_store=SQLiteCapabilityReplayStore(path),
            )
            replayed = await restarted_gateway.authorize(context, descriptor, bound)

            self.assertTrue(first.allowed)
            self.assertFalse(replayed.allowed)
            self.assertEqual(replayed.reason_code, "capability_token_replayed")

    async def test_concurrent_consumers_have_exactly_one_winner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gateway.sqlite3"
            stores = [SQLiteCapabilityReplayStore(path) for _ in range(8)]
            expiry = datetime.now(timezone.utc) + timedelta(minutes=5)
            results = await asyncio.gather(
                *(store.consume("shared-token", expiry) for store in stores)
            )

            self.assertEqual(results.count(True), 1)
            self.assertEqual(results.count(False), 7)

    async def test_expired_records_are_purged_without_allowing_expired_token(self) -> None:
        now = datetime(2026, 7, 16, 8, 0, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gateway.sqlite3"
            clock = [now]
            store = SQLiteCapabilityReplayStore(path, now=lambda: clock[0])
            self.assertTrue(
                await store.consume("soon-expired", now + timedelta(seconds=1))
            )
            clock[0] = now + timedelta(seconds=2)

            self.assertFalse(await store.consume("already-expired", now))
            self.assertEqual(await store.purge_expired(), 1)


class SQLiteAuditSinkTests(unittest.IsolatedAsyncioTestCase):
    async def test_agent_audit_is_persistent_and_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.sqlite3"
            sink = SQLiteAuditSink(path)
            context = SessionContext(
                tenant_id="tenant-a", agent_id="agent-a", session_id="audit-session"
            )
            descriptor = ToolDescriptor(
                "lookup", required_capabilities=frozenset({"lookup:read"})
            )
            runtime = SafeHarnessRuntime(
                services=RuntimeServices(
                    tool_catalog=StaticToolCatalog([descriptor]),
                    capability_authority=StaticCapabilityAuthority(
                        {"agent-a": {"lookup:read"}}
                    ),
                    audit_sink=sink,
                )
            )
            async with runtime.session(context) as session:
                await session.inspect_content("confidential operator request")
                outcome = await execute_tool(
                    session,
                    ToolInvocation(
                        descriptor.name,
                        {"password": "never-store", "query": "alarm"},
                    ),
                    lambda password, query: {
                        "result": "private NMS output",
                        "query": query,
                    },
                )

            restarted_sink = SQLiteAuditSink(path)
            rows = await restarted_sink.query(
                tenant_id="tenant-a", session_id="audit-session", limit=100
            )
            serialized = json.dumps(rows, ensure_ascii=False)

            self.assertFalse(outcome.blocked)
            self.assertGreaterEqual(len(rows), 1)
            self.assertNotIn("confidential operator request", serialized)
            self.assertNotIn("never-store", serialized)
            self.assertNotIn("private NMS output", serialized)
            self.assertIn("[REDACTED]", serialized)

    async def test_gateway_audit_is_queryable_without_raw_arguments_or_results(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gateway.sqlite3"
            audit = SQLiteAuditSink(path)
            descriptor = ToolDescriptor(
                "lookup",
                input_schema={
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                    "additionalProperties": False,
                },
                required_capabilities=frozenset({"lookup:read"}),
            )
            application = ToolGatewayApplication(
                registry=ToolRegistry(
                    [RegisteredTool(descriptor, lambda query: {"result": query})]
                ),
                capability_gateway=SignedCapabilityGateway(
                    b"k" * 32,
                    {("tenant-a", "agent-a"): {"lookup:read"}},
                    replay_store=SQLiteCapabilityReplayStore(path),
                ),
                audit_sink=audit,
            )
            context = SessionContext(
                tenant_id="tenant-a",
                agent_id="agent-a",
                session_id="gateway-session",
                run_id="gateway-run",
            )
            invocation = ToolInvocation(
                descriptor.name,
                {"query": "sensitive alarm text"},
                call_id="gateway-call",
                tool_version=descriptor.version,
            )
            issue_payload = _gateway_request(context, invocation)
            issue_status, issue_response = await application.issue(
                issue_payload, request_id="request-issue"
            )
            grant = issue_response["grant"]
            bound = ToolInvocation(
                invocation.tool_name,
                invocation.arguments,
                call_id=invocation.call_id,
                tool_version=invocation.tool_version,
                capability_token=grant["token"],
            )
            execute_status, _ = await application.execute(
                _gateway_request(context, bound), request_id="request-execute"
            )
            rows = await audit.query(source="gateway", action="tool_execute")
            serialized = json.dumps(rows)

            self.assertEqual(issue_status, 200)
            self.assertEqual(execute_status, 200)
            self.assertEqual(
                {row["outcome"] for row in rows}, {"dispatched", "succeeded"}
            )
            expected_fingerprint = hashlib.sha256(
                grant["token_id"].encode("utf-8")
            ).hexdigest()
            self.assertEqual(
                {row["capability_fingerprint"] for row in rows},
                {expected_fingerprint},
            )
            self.assertNotIn("sensitive alarm text", serialized)
            self.assertNotIn(grant["token"], serialized)
            self.assertNotIn(grant["token_id"], serialized)

    async def test_duplicate_record_is_rejected_instead_of_silently_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sink = SQLiteAuditSink(Path(directory) / "audit.sqlite3")
            event = SecurityEvent(
                EventKind.RUN_STARTED,
                EventMeta(
                    tenant_id="tenant-a",
                    session_id="session-a",
                    run_id="run-a",
                    agent_id="agent-a",
                    sequence=1,
                ),
            )
            record = AuditRecord("decision", event)
            await sink.write(record)
            with self.assertRaises(sqlite3.IntegrityError):
                await sink.write(record)

    async def test_audit_rows_are_append_only_at_database_layer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.sqlite3"
            sink = SQLiteAuditSink(path)
            await sink.write_gateway(
                GatewayAuditRecord(action="health", outcome="ready")
            )
            connection = sqlite3.connect(path)
            try:
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        "UPDATE audit_records SET outcome = 'tampered'"
                    )
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute("DELETE FROM audit_records")
            finally:
                connection.close()

    async def test_gateway_record_details_are_defensively_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sink = SQLiteAuditSink(Path(directory) / "audit.sqlite3")
            await sink.write_gateway(
                GatewayAuditRecord(
                    action="tool_execute",
                    outcome="failed",
                    tenant_id="tenant-a",
                    details={
                        "password": "do-not-store",
                        "result": "private result",
                    },
                )
            )
            rows = await sink.query(source="gateway")
            serialized = json.dumps(rows)

            self.assertNotIn("do-not-store", serialized)
            self.assertNotIn("private result", serialized)
            self.assertIn("[REDACTED]", serialized)

    async def test_gateway_audit_failure_blocks_dispatch_after_token_consumption(self) -> None:
        class FailingAudit:
            async def write_gateway(self, record) -> None:
                raise OSError("audit disk unavailable")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gateway.sqlite3"
            calls = 0

            def executor(query):
                nonlocal calls
                calls += 1
                return query

            descriptor = ToolDescriptor(
                "lookup", required_capabilities=frozenset({"lookup:read"})
            )
            replay_store = SQLiteCapabilityReplayStore(path)
            capabilities = SignedCapabilityGateway(
                b"k" * 32,
                {("tenant-a", "agent-a"): {"lookup:read"}},
                replay_store=replay_store,
            )
            issuing = ToolGatewayApplication(
                registry=ToolRegistry([RegisteredTool(descriptor, executor)]),
                capability_gateway=capabilities,
            )
            context = SessionContext(tenant_id="tenant-a", agent_id="agent-a")
            invocation = ToolInvocation(
                descriptor.name,
                {"query": "alarm"},
                tool_version=descriptor.version,
            )
            _, response = await issuing.issue(_gateway_request(context, invocation))
            bound = ToolInvocation(
                invocation.tool_name,
                invocation.arguments,
                call_id=invocation.call_id,
                tool_version=invocation.tool_version,
                capability_token=response["grant"]["token"],
            )
            failing = ToolGatewayApplication(
                registry=ToolRegistry([RegisteredTool(descriptor, executor)]),
                capability_gateway=capabilities,
                audit_sink=FailingAudit(),
            )

            status, failure = await failing.execute(_gateway_request(context, bound))
            replay_status, replay = await issuing.execute(
                _gateway_request(context, bound)
            )

            self.assertEqual(status, 503)
            self.assertEqual(failure["error"]["code"], "gateway_audit_unavailable")
            self.assertEqual(replay_status, 403)
            self.assertEqual(replay["error"]["code"], "capability_token_replayed")
            self.assertEqual(calls, 0)

    async def test_agent_composite_audit_failure_blocks_tool_dispatch(self) -> None:
        class FailingEnforcementAudit:
            async def write(self, record) -> None:
                if record.record_type == "enforcement":
                    raise OSError("persistent audit unavailable")

        memory_audit = InMemoryAuditSink()
        descriptor = ToolDescriptor(
            "lookup", required_capabilities=frozenset({"lookup:read"})
        )
        runtime = SafeHarnessRuntime(
            services=RuntimeServices(
                tool_catalog=StaticToolCatalog([descriptor]),
                capability_authority=StaticCapabilityAuthority(
                    {"agent-a": {"lookup:read"}}
                ),
                audit_sink=CompositeAuditSink(
                    (memory_audit, FailingEnforcementAudit())
                ),
            )
        )
        session = runtime.session(
            SessionContext(tenant_id="tenant-a", agent_id="agent-a")
        )
        calls = 0

        def executor(query):
            nonlocal calls
            calls += 1
            return query

        await session.start()
        with self.assertRaises(OSError):
            await execute_tool(
                session,
                ToolInvocation(descriptor.name, {"query": "alarm"}),
                executor,
            )
        await session.close()

        self.assertEqual(calls, 0)
        self.assertTrue(
            any(record.event.kind is EventKind.TOOL_CALL_PROPOSED for record in memory_audit.records)
        )

    async def test_pre_execution_audit_failures_return_service_unavailable(self) -> None:
        descriptor = ToolDescriptor(
            "lookup", required_capabilities=frozenset({"lookup:read"})
        )
        capabilities = SignedCapabilityGateway(
            b"k" * 32,
            {("tenant-a", "agent-a"): {"lookup:read"}},
        )
        context = SessionContext(tenant_id="tenant-a", agent_id="agent-a")
        invocation = ToolInvocation(
            descriptor.name,
            {"query": "alarm"},
            tool_version=descriptor.version,
        )
        issuing = ToolGatewayApplication(
            registry=ToolRegistry([RegisteredTool(descriptor, lambda query: query)]),
            capability_gateway=capabilities,
        )
        _, issue_response = await issuing.issue(_gateway_request(context, invocation))
        grant = issue_response["grant"]
        bound = ToolInvocation(
            invocation.tool_name,
            invocation.arguments,
            call_id=invocation.call_id,
            tool_version=invocation.tool_version,
            capability_token=grant["token"],
        )
        failing = ToolGatewayApplication(
            registry=ToolRegistry([RegisteredTool(descriptor, lambda query: query)]),
            capability_gateway=capabilities,
            audit_sink=_FailingGatewayAudit(),
        )

        invalid_status, invalid_response = await failing.issue({})
        inspect_status, inspect_response = await failing.inspect(
            _gateway_request(context, bound)
        )

        self.assertEqual(invalid_status, 503)
        self.assertEqual(
            invalid_response["error"]["code"], "gateway_audit_unavailable"
        )
        self.assertEqual(inspect_status, 503)
        self.assertEqual(
            inspect_response["error"]["code"], "gateway_audit_unavailable"
        )

    async def test_terminal_audit_failure_reports_ambiguous_execution(self) -> None:
        for executor, terminal_outcome in (
            (lambda query: query, "succeeded"),
            (_raise_tool_failure, "failed"),
        ):
            with self.subTest(terminal_outcome=terminal_outcome):
                descriptor = ToolDescriptor(
                    "lookup", required_capabilities=frozenset({"lookup:read"})
                )
                capabilities = SignedCapabilityGateway(
                    b"k" * 32,
                    {("tenant-a", "agent-a"): {"lookup:read"}},
                )
                context = SessionContext(tenant_id="tenant-a", agent_id="agent-a")
                invocation = ToolInvocation(
                    descriptor.name,
                    {"query": "alarm"},
                    tool_version=descriptor.version,
                )
                issuing = ToolGatewayApplication(
                    registry=ToolRegistry([RegisteredTool(descriptor, executor)]),
                    capability_gateway=capabilities,
                )
                _, issue_response = await issuing.issue(
                    _gateway_request(context, invocation)
                )
                bound = ToolInvocation(
                    invocation.tool_name,
                    invocation.arguments,
                    call_id=invocation.call_id,
                    tool_version=invocation.tool_version,
                    capability_token=issue_response["grant"]["token"],
                )
                application = ToolGatewayApplication(
                    registry=ToolRegistry([RegisteredTool(descriptor, executor)]),
                    capability_gateway=capabilities,
                    audit_sink=_FailingGatewayAudit(outcome=terminal_outcome),
                )

                status, response = await application.execute(
                    _gateway_request(context, bound)
                )

                self.assertEqual(status, 500)
                self.assertEqual(
                    response["error"]["code"], "gateway_audit_commit_failed"
                )
                self.assertIn("may have changed external state", response["error"]["message"])
                self.assertIn("must not be retried automatically", response["error"]["message"])

class _FailingGatewayAudit:
    def __init__(self, *, outcome: str | None = None) -> None:
        self.outcome = outcome

    async def write_gateway(self, record) -> None:
        if self.outcome is None or record.outcome == self.outcome:
            raise OSError("audit disk unavailable")


def _raise_tool_failure(query):
    raise RuntimeError("simulated tool failure")


def _gateway_request(
    context: SessionContext, invocation: ToolInvocation
) -> dict[str, object]:
    from safeharness.gateway.protocol import request_to_wire

    return request_to_wire(context, invocation)


if __name__ == "__main__":
    unittest.main()
