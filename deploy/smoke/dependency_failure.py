"""Prove Redis and PostgreSQL outages fail closed before tool dispatch."""

from __future__ import annotations

import asyncio
import os
import time

from examples.langgraph_noc.domain import NetworkOperationsEnvironment, build_noc_tools
from safeharness import SessionContext, ToolInvocation
from safeharness.backends import SignedCapabilityGateway, SignedEnforcementReceiptAuthority
from safeharness.gateway import RemoteToolGatewayClient, ToolGatewayError


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


async def _wait_for_expected_not_ready(client: RemoteToolGatewayClient) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            await client.health()
        except ToolGatewayError as exc:
            if exc.status == 503 and exc.code == "gateway_not_ready":
                return
        await asyncio.sleep(0.5)
    raise AssertionError("fault-injection gateway did not report a failed dependency")


async def _bound_invocation() -> tuple[SessionContext, ToolInvocation]:
    tool = next(
        item
        for item in build_noc_tools(NetworkOperationsEnvironment())
        if item.descriptor.name == "get_device_snapshot"
    )
    context = SessionContext(
        tenant_id="fiberhome-demo",
        agent_id="noc-operator-agent",
        framework="dependency-failure-smoke",
    )
    invocation = ToolInvocation(
        tool.descriptor.name,
        {"device_id": "NE-WH-OLT-01"},
        tool_version=tool.descriptor.version,
        resource="NE-WH-OLT-01",
    )
    capability_authority = SignedCapabilityGateway(
        _required("SAFEHARNESS_TOOL_GATEWAY_SIGNING_KEY"),
        {("fiberhome-demo", "noc-operator-agent"): {"nms:devices:read"}},
    )
    grant = await capability_authority.issue(context, tool.descriptor, invocation)
    receipt = await SignedEnforcementReceiptAuthority(
        _required("SAFEHARNESS_ENFORCEMENT_RECEIPT_SIGNING_KEY")
    ).issue(
        context,
        tool.descriptor,
        invocation,
        decision_id=f"failure-decision-{context.run_id}",
        event_id=f"failure-event-{context.run_id}",
        policy_version="dependency-failure.v1",
    )
    return context, ToolInvocation(
        invocation.tool_name,
        invocation.arguments,
        call_id=invocation.call_id,
        tool_version=invocation.tool_version,
        resource=invocation.resource,
        capability_token=grant.token,
        enforcement_receipt=receipt,
    )


async def _assert_execute_fails_closed(
    client: RemoteToolGatewayClient,
    *,
    expected_codes: frozenset[str],
) -> None:
    context, invocation = await _bound_invocation()
    try:
        await client.execute(context, invocation)
    except ToolGatewayError as exc:
        if exc.status != 503 or exc.code not in expected_codes:
            raise AssertionError(
                f"expected 503/{sorted(expected_codes)}, received {exc.status}/{exc.code}"
            ) from exc
    else:
        raise AssertionError("a tool result escaped while a mandatory backend was unavailable")


async def main() -> None:
    api_key = _required("SAFEHARNESS_TOOL_GATEWAY_API_KEY")
    redis_failure = RemoteToolGatewayClient(
        _required("SAFEHARNESS_SMOKE_REDIS_FAILURE_GATEWAY_URL"), api_key, timeout=3
    )
    postgres_failure = RemoteToolGatewayClient(
        _required("SAFEHARNESS_SMOKE_POSTGRES_FAILURE_GATEWAY_URL"), api_key, timeout=3
    )
    await asyncio.gather(
        _wait_for_expected_not_ready(redis_failure),
        _wait_for_expected_not_ready(postgres_failure),
    )
    await _assert_execute_fails_closed(
        redis_failure,
        expected_codes=frozenset(
            {
                "capability_replay_store_unavailable",
                "enforcement_receipt_store_unavailable",
            }
        ),
    )
    await _assert_execute_fails_closed(
        postgres_failure,
        expected_codes=frozenset({"gateway_audit_unavailable"}),
    )
    print("SafeHarness dependency failure test passed: Redis and PostgreSQL fail closed.")


if __name__ == "__main__":
    asyncio.run(main())
