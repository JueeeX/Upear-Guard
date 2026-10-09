from __future__ import annotations

import asyncio
from contextlib import contextmanager
import json
import os
from pathlib import Path
import tempfile
from threading import Thread
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from safeharness import (
    Reversibility,
    SafeHarnessRuntime,
    SessionContext,
    ToolDescriptor,
    ToolInvocation,
)
from safeharness.adapters import execute_invocation
from safeharness.backends import (
    SQLiteAuditReader,
    SignedCapabilityGateway,
    StaticToolCatalog,
)
from safeharness.gateway import (
    RegisteredTool,
    RemoteToolGatewayClient,
    ToolGatewayApplication,
    ToolGatewayError,
    ToolRegistry,
    create_gateway_server,
)
from safeharness.runtime import RuntimeServices
from examples.langgraph_noc.app import SecureNocChat
from examples.langgraph_noc.domain import (
    NetworkOperationsEnvironment,
    build_noc_tools,
)
from examples.langgraph_noc.tool_gateway import build_gateway_application


API_KEY = "gateway-test-api-key-32-characters"


def descriptor() -> ToolDescriptor:
    return ToolDescriptor(
        name="lookup",
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
            "additionalProperties": False,
        },
        required_capabilities=frozenset({"lookup:read"}),
    )


@contextmanager
def running_gateway(
    executor=None,
    *,
    max_request_bytes=1024 * 1024,
    telemetry=None,
):
    tool = descriptor()
    calls = []

    def default_executor(query):
        calls.append(query)
        return {"answer": query.upper()}

    registry = ToolRegistry(
        [
            RegisteredTool(
                tool,
                executor or default_executor,
                resource_resolver=lambda arguments: f"query:{arguments['query']}",
            )
        ]
    )
    capabilities = SignedCapabilityGateway(
        b"g" * 32,
        {("tenant-a", "agent-a"): {"lookup:read"}},
    )
    application = ToolGatewayApplication(
        registry=registry,
        capability_gateway=capabilities,
    )
    server = create_gateway_server(
        application,
        host="127.0.0.1",
        port=0,
        api_key=API_KEY,
        tenant_id="tenant-a",
        agent_id="agent-a",
        max_request_bytes=max_request_bytes,
        telemetry=telemetry,
    )
    thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.daemon = True
    thread.start()
    try:
        yield (
            f"http://127.0.0.1:{server.server_address[1]}",
            tool,
            calls,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@contextmanager
def running_application(
    application,
    *,
    api_key="a" * 32,
    tenant_id="fiberhome-demo",
    agent_id="noc-operator-agent",
):
    server = create_gateway_server(
        application,
        host="127.0.0.1",
        port=0,
        api_key=api_key,
        tenant_id=tenant_id,
        agent_id=agent_id,
    )
    thread = Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.01},
        daemon=True,
    )
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class ToolGatewayHTTPTests(unittest.IsolatedAsyncioTestCase):
    async def test_noc_reference_gateway_executes_server_owned_read_tool(self) -> None:
        application, gateway_environment = build_gateway_application(
            signing_key="s" * 32,
            tenant_id="fiberhome-demo",
            agent_id="noc-operator-agent",
        )
        server = create_gateway_server(
            application,
            host="127.0.0.1",
            port=0,
            api_key="a" * 32,
            tenant_id="fiberhome-demo",
            agent_id="noc-operator-agent",
        )
        thread = Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.01},
            daemon=True,
        )
        thread.start()
        try:
            descriptor = next(
                tool.descriptor
                for tool in build_noc_tools(NetworkOperationsEnvironment())
                if tool.descriptor.name == "get_device_snapshot"
            )
            context = SessionContext(
                tenant_id="fiberhome-demo",
                agent_id="noc-operator-agent",
                session_id="noc-smoke",
                run_id="noc-run",
            )
            invocation = ToolInvocation(
                descriptor.name,
                {"device_id": "NE-WH-OLT-01"},
                call_id="noc-call",
                tool_version=descriptor.version,
                resource="NE-WH-OLT-01",
            )
            client = RemoteToolGatewayClient(
                f"http://127.0.0.1:{server.server_address[1]}",
                "a" * 32,
            )
            grant = await client.issue(context, descriptor, invocation)
            bound = ToolInvocation(
                invocation.tool_name,
                invocation.arguments,
                call_id=invocation.call_id,
                tool_version=invocation.tool_version,
                resource=invocation.resource,
                capability_token=grant.token,
            )
            result = await client.execute(context, bound)

            self.assertEqual(result["device_id"], "NE-WH-OLT-01")
            self.assertEqual(result["status"], "degraded")
            self.assertEqual(gateway_environment.operation_log, [])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    async def test_remote_issue_inspect_execute_and_replay_denial(self) -> None:
        with running_gateway() as (url, tool, calls):
            client = RemoteToolGatewayClient(url, API_KEY)
            context = SessionContext(
                tenant_id="tenant-a",
                agent_id="agent-a",
                session_id="session-a",
                run_id="run-a",
            )
            invocation = ToolInvocation(
                tool.name,
                {"query": "alarm"},
                call_id="call-a",
                tool_version=tool.version,
                resource="query:alarm",
            )
            grant = await client.issue(context, tool, invocation)
            authorized = ToolInvocation(
                tool_name=invocation.tool_name,
                arguments=invocation.arguments,
                call_id=invocation.call_id,
                tool_version=invocation.tool_version,
                resource=invocation.resource,
                capability_token=grant.token,
            )

            inspected = await client.authorize(context, tool, authorized)
            inspected_again = await client.authorize(context, tool, authorized)
            result = await client.execute(context, authorized)

            self.assertTrue(inspected.allowed)
            self.assertTrue(inspected_again.allowed)
            self.assertEqual(result, {"answer": "ALARM"})
            self.assertEqual(calls, ["alarm"])
            with self.assertRaises(ToolGatewayError) as replayed:
                await client.execute(context, authorized)
            self.assertEqual(replayed.exception.code, "capability_token_replayed")
            self.assertEqual(calls, ["alarm"])

    async def test_reference_gateway_rejects_replay_after_http_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "tool-gateway.sqlite3"
            context = SessionContext(
                tenant_id="fiberhome-demo",
                agent_id="noc-operator-agent",
                session_id="restart-session",
                run_id="restart-run",
            )
            first, first_environment = build_gateway_application(
                signing_key="s" * 32,
                database_path=database,
            )
            tool = next(
                item.descriptor
                for item in build_noc_tools(first_environment)
                if item.descriptor.name == "get_device_snapshot"
            )
            invocation = ToolInvocation(
                tool.name,
                {"device_id": "NE-WH-OLT-01"},
                call_id="restart-call",
                tool_version=tool.version,
                resource="NE-WH-OLT-01",
            )
            with running_application(first) as url:
                client = RemoteToolGatewayClient(url, "a" * 32)
                grant = await client.issue(context, tool, invocation)
                bound = ToolInvocation(
                    invocation.tool_name,
                    invocation.arguments,
                    call_id=invocation.call_id,
                    tool_version=invocation.tool_version,
                    resource=invocation.resource,
                    capability_token=grant.token,
                )
                result = await client.execute(context, bound)

            restarted, restarted_environment = build_gateway_application(
                signing_key="s" * 32,
                database_path=database,
            )
            with running_application(restarted) as url:
                restarted_client = RemoteToolGatewayClient(url, "a" * 32)
                with self.assertRaises(ToolGatewayError) as replayed:
                    await restarted_client.execute(context, bound)

            rows = await SQLiteAuditReader(database).query(
                source="gateway", action="tool_execute"
            )
            self.assertEqual(result["device_id"], "NE-WH-OLT-01")
            self.assertEqual(replayed.exception.code, "capability_token_replayed")
            self.assertEqual(restarted_environment.operation_log, [])
            self.assertEqual(
                {row["outcome"] for row in rows},
                {"dispatched", "succeeded", "denied"},
            )

    async def test_remote_gateway_runs_through_safeharness_policy_lifecycle(self) -> None:
        with running_gateway() as (url, tool, calls):
            client = RemoteToolGatewayClient(url, API_KEY)
            context = SessionContext(
                tenant_id="tenant-a",
                agent_id="agent-a",
                session_id="session-a",
                run_id="run-a",
            )
            runtime = SafeHarnessRuntime(
                services=RuntimeServices(
                    tool_catalog=StaticToolCatalog([tool]),
                    capability_authority=client,
                )
            )
            invocation = ToolInvocation(
                tool.name,
                {"query": "alarm"},
                call_id="call-safeharness",
                tool_version=tool.version,
                resource="query:alarm",
            )
            grant = await client.issue(context, tool, invocation)

            async with runtime.session(context) as session:
                outcome = await execute_invocation(
                    session,
                    invocation,
                    client.executor_for(context),
                    capability_token=grant.token,
                )

            self.assertFalse(outcome.blocked)
            self.assertEqual(outcome.result, {"answer": "ALARM"})
            self.assertEqual(calls, ["alarm"])

    async def test_argument_context_and_resource_substitution_are_rejected(self) -> None:
        with running_gateway() as (url, tool, calls):
            client = RemoteToolGatewayClient(url, API_KEY)
            context = SessionContext(
                tenant_id="tenant-a",
                agent_id="agent-a",
                session_id="session-a",
                run_id="run-a",
            )
            original = ToolInvocation(
                tool.name,
                {"query": "alarm"},
                call_id="call-a",
                tool_version=tool.version,
                resource="query:alarm",
            )
            grant = await client.issue(context, tool, original)
            changed = ToolInvocation(
                tool.name,
                {"query": "secret"},
                call_id=original.call_id,
                tool_version=tool.version,
                resource="query:secret",
                capability_token=grant.token,
            )
            wrong_context = SessionContext(
                tenant_id="tenant-a",
                agent_id="agent-a",
                session_id="session-b",
                run_id="run-a",
            )

            changed_result = await client.authorize(context, tool, changed)
            context_result = await client.authorize(wrong_context, tool, changed)

            self.assertFalse(changed_result.allowed)
            self.assertEqual(
                changed_result.reason_code,
                "capability_token_invocation_mismatch",
            )
            self.assertFalse(context_result.allowed)
            self.assertEqual(
                context_result.reason_code,
                "capability_token_context_mismatch",
            )
            bad_resource = ToolInvocation(
                tool.name,
                {"query": "alarm"},
                call_id="bad-resource",
                tool_version=tool.version,
                resource="query:other",
            )
            with self.assertRaises(ToolGatewayError) as rejected:
                await client.issue(context, tool, bad_resource)
            self.assertEqual(rejected.exception.code, "invalid_request")
            self.assertEqual(calls, [])

    async def test_local_and_gateway_security_metadata_must_match(self) -> None:
        with running_gateway() as (url, tool, _):
            client = RemoteToolGatewayClient(url, API_KEY)
            context = SessionContext(tenant_id="tenant-a", agent_id="agent-a")
            invocation = ToolInvocation(
                tool.name,
                {"query": "alarm"},
                tool_version=tool.version,
                resource="query:alarm",
            )
            drifted = ToolDescriptor(
                name=tool.name,
                version=tool.version,
                description="Different local security metadata",
                input_schema=tool.input_schema,
                required_capabilities=tool.required_capabilities,
            )

            with self.assertRaises(ToolGatewayError) as rejected:
                await client.issue(context, drifted, invocation)

            self.assertEqual(rejected.exception.code, "invalid_gateway_response")

    async def test_unauthorized_api_key_fails_closed(self) -> None:
        with running_gateway() as (url, tool, _):
            client = RemoteToolGatewayClient(url, "wrong-api-key-but-still-32-chars-long")
            context = SessionContext(tenant_id="tenant-a", agent_id="agent-a")
            invocation = ToolInvocation(
                tool.name,
                {"query": "alarm"},
                tool_version=tool.version,
                resource="query:alarm",
            )
            with self.assertRaises(ToolGatewayError) as denied:
                await client.issue(context, tool, invocation)
            self.assertEqual(denied.exception.code, "unauthorized")

    async def test_api_key_cannot_impersonate_another_tenant_or_agent(self) -> None:
        with running_gateway() as (url, tool, _):
            client = RemoteToolGatewayClient(url, API_KEY)
            context = SessionContext(tenant_id="tenant-a", agent_id="agent-b")
            invocation = ToolInvocation(
                tool.name,
                {"query": "alarm"},
                tool_version=tool.version,
                resource="query:alarm",
            )
            with self.assertRaises(ToolGatewayError) as denied:
                await client.issue(context, tool, invocation)
            self.assertEqual(
                denied.exception.code,
                "authenticated_principal_mismatch",
            )
            wrong_tenant = SessionContext(
                tenant_id="tenant-b", agent_id="agent-a"
            )
            with self.assertRaises(ToolGatewayError) as tenant_denied:
                await client.issue(wrong_tenant, tool, invocation)
            self.assertEqual(
                tenant_denied.exception.code,
                "authenticated_principal_mismatch",
            )

    async def test_execution_failure_consumes_token_and_hides_exception_details(self) -> None:
        def failing_executor(query):
            raise RuntimeError("NMS password must not escape")

        with running_gateway(failing_executor) as (url, tool, _):
            client = RemoteToolGatewayClient(url, API_KEY)
            context = SessionContext(tenant_id="tenant-a", agent_id="agent-a")
            invocation = ToolInvocation(
                tool.name,
                {"query": "alarm"},
                tool_version=tool.version,
                resource="query:alarm",
            )
            grant = await client.issue(context, tool, invocation)
            authorized = ToolInvocation(
                tool.name,
                invocation.arguments,
                call_id=invocation.call_id,
                tool_version=tool.version,
                resource=invocation.resource,
                capability_token=grant.token,
            )

            with self.assertRaises(ToolGatewayError) as failed:
                await client.execute(context, authorized)
            self.assertEqual(failed.exception.code, "tool_execution_failed")
            self.assertNotIn("password", str(failed.exception).lower())
            with self.assertRaises(ToolGatewayError) as replayed:
                await client.execute(context, authorized)
            self.assertEqual(replayed.exception.code, "capability_token_replayed")

    async def test_concurrent_execution_allows_exactly_one_dispatch(self) -> None:
        count = 0

        def executor(query):
            nonlocal count
            count += 1
            return query

        with running_gateway(executor) as (url, tool, _):
            client = RemoteToolGatewayClient(url, API_KEY)
            context = SessionContext(tenant_id="tenant-a", agent_id="agent-a")
            invocation = ToolInvocation(
                tool.name,
                {"query": "alarm"},
                tool_version=tool.version,
                resource="query:alarm",
            )
            grant = await client.issue(context, tool, invocation)
            authorized = ToolInvocation(
                tool.name,
                invocation.arguments,
                call_id=invocation.call_id,
                tool_version=tool.version,
                resource=invocation.resource,
                capability_token=grant.token,
            )

            results = await asyncio.gather(
                client.execute(context, authorized),
                client.execute(context, authorized),
                return_exceptions=True,
            )

            self.assertEqual(count, 1)
            self.assertEqual(sum(not isinstance(item, Exception) for item in results), 1)
            errors = [item for item in results if isinstance(item, ToolGatewayError)]
            self.assertEqual(errors[0].code, "capability_token_replayed")


class ToolGatewayHTTPBoundaryTests(unittest.TestCase):
    def test_remote_noc_mode_advertises_read_only_tools(self) -> None:
        chat = SecureNocChat(model=object(), judge_provider=None)
        context = SessionContext(
            tenant_id=chat.tenant_id,
            agent_id=chat.agent_id,
            session_id=chat.thread_id,
            framework="langgraph",
        )
        client = RemoteToolGatewayClient("http://127.0.0.1:38100", "a" * 32)
        local_tools = build_noc_tools(chat.environment)
        remote_tools = chat._remote_tools(local_tools, client, lambda: context)

        self.assertEqual(
            {tool.descriptor.name for tool in remote_tools},
            {
                "list_active_alarms",
                "get_device_snapshot",
                "query_performance",
                "search_runbook",
            },
        )
        self.assertTrue(all(tool.executor is None for tool in remote_tools))
        self.assertTrue(
            all(
                tool.descriptor.reversibility is Reversibility.READ_ONLY
                and not tool.descriptor.side_effects
                for tool in remote_tools
            )
        )

    def test_remote_noc_mode_requires_agent_api_key(self) -> None:
        chat = SecureNocChat(model=object(), judge_provider=None)
        with patch.dict(
            os.environ,
            {"SAFEHARNESS_TOOL_GATEWAY_URL": "http://127.0.0.1:38100"},
            clear=True,
        ):
            with self.assertRaises(ValueError):
                chat._configured_tool_gateway()

    def test_remote_noc_mtls_requires_client_cert_and_key_together(self) -> None:
        chat = SecureNocChat(model=object(), judge_provider=None)
        with patch.dict(
            os.environ,
            {
                "SAFEHARNESS_TOOL_GATEWAY_URL": "https://gateway.internal",
                "SAFEHARNESS_TOOL_GATEWAY_API_KEY": "a" * 32,
                "SAFEHARNESS_TOOL_GATEWAY_CLIENT_CERT": "client-cert.pem",
            },
            clear=True,
        ):
            with self.assertRaises(ValueError):
                chat._configured_tool_gateway()

    def test_health_requires_authentication(self) -> None:
        with running_gateway() as (url, _, _):
            unauthenticated = Request(f"{url}/health", method="GET")
            denied = self._error_payload(unauthenticated)
            self.assertEqual(denied["error"]["code"], "unauthorized")

            authenticated = Request(
                f"{url}/health",
                method="GET",
                headers={"Authorization": f"Bearer {API_KEY}"},
            )
            with urlopen(authenticated, timeout=2) as response:
                payload = json.loads(response.read())
            self.assertEqual(payload["status"], "ready")

    def test_request_size_limit_and_invalid_json_are_rejected(self) -> None:
        with running_gateway() as (url, _, _):
            invalid = Request(
                f"{url}/v1/capabilities/issue",
                data=b"not-json",
                method="POST",
                headers={
                    "Authorization": f"Bearer {API_KEY}",
                    "Content-Type": "application/json",
                },
            )
            invalid_payload = self._error_payload(invalid)
            self.assertEqual(invalid_payload["error"]["code"], "invalid_json")

        with running_gateway(max_request_bytes=8) as (url, _, _):
            oversized = Request(
                f"{url}/v1/capabilities/issue",
                data=b'{"long":"request"}',
                method="POST",
                headers={
                    "Authorization": f"Bearer {API_KEY}",
                    "Content-Type": "application/json",
                },
            )
            oversized_payload = self._error_payload(oversized)
            self.assertEqual(oversized_payload["error"]["code"], "request_too_large")

    def test_telemetry_contains_only_sanitized_low_cardinality_fields(self) -> None:
        telemetry = _RecordingTelemetry()
        with running_gateway(telemetry=telemetry) as (url, _, _):
            request = Request(
                f"{url}/private/device/NE-SECRET?token=must-not-escape",
                method="GET",
                headers={
                    "Authorization": f"Bearer {API_KEY}",
                    "X-Request-ID": "customer-secret-request-id",
                },
            )
            response = self._error_payload(request)

        observation = telemetry.observations[0]
        serialized = json.dumps(observation.attributes)
        self.assertEqual(response["error"]["code"], "not_found")
        self.assertEqual(observation.route, "unmatched")
        self.assertEqual(observation.error_code, "not_found")
        self.assertNotIn("NE-SECRET", serialized)
        self.assertNotIn("must-not-escape", serialized)
        self.assertNotIn("customer-secret-request-id", serialized)
        self.assertEqual(telemetry.shutdown_count, 1)

    def test_telemetry_failure_never_changes_gateway_response(self) -> None:
        telemetry = _RecordingTelemetry(fail=True)
        with self.assertLogs("safeharness.gateway.service", level="ERROR") as logs:
            with running_gateway(telemetry=telemetry) as (url, _, _):
                request = Request(
                    f"{url}/health",
                    method="GET",
                    headers={"Authorization": f"Bearer {API_KEY}"},
                )
                with urlopen(request, timeout=2) as response:
                    payload = json.loads(response.read())

        self.assertEqual(payload["status"], "ready")
        self.assertNotIn("otel-secret-endpoint", "\n".join(logs.output))

    @staticmethod
    def _error_payload(request: Request) -> dict:
        try:
            urlopen(request, timeout=2)
        except HTTPError as exc:
            try:
                return json.loads(exc.read())
            finally:
                exc.close()
        raise AssertionError("request unexpectedly succeeded")


class _RecordingTelemetry:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.observations = []
        self.shutdown_count = 0

    def record_request(self, observation) -> None:
        if self.fail:
            raise OSError("https://otel-secret-endpoint")
        self.observations.append(observation)

    def shutdown(self) -> None:
        self.shutdown_count += 1


if __name__ == "__main__":
    unittest.main()
