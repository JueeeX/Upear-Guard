"""SafeHarness-backed handlers for the offline FSM NOC demo.

The module is intentionally demo-only. It uses the existing simulated NMS
environment and SafeHarness generic tool lifecycle; no real NMS endpoint is
contacted.
"""

from __future__ import annotations

import os
import threading
from typing import Any, Mapping

from safeharness import SafeHarnessRuntime, SessionContext, ToolInvocation
from safeharness.adapters import execute_tool
from safeharness.backends import InMemoryAuditSink, SignedCapabilityGateway, StaticToolCatalog
from safeharness.runtime import RuntimeServices

from examples.langgraph_noc.domain import (
    NetworkOperationsEnvironment,
    build_noc_tools,
)


_CAPABILITY_GRANTS = {
    "alarm.query": frozenset({"nms:alarms:read"}),
    "alarm.diagnose": frozenset({"nms:alarms:read", "nms:devices:read"}),
    "alarm.verify": frozenset({"nms:alarms:read"}),
    "incident.create": frozenset({"noc:tickets:write"}),
    "interface.restart": frozenset({"nms:interface:restart"}),
}
from examples.langgraph_noc.services import DemoApprovalBroker, NocCompensationProvider


_environment = NetworkOperationsEnvironment()
_environment_lock = threading.RLock()


def _tool_map():
    tools = build_noc_tools(_environment)
    return {tool.descriptor.name: tool for tool in tools}


async def _safe_tool_call(tool_name: str, arguments: Mapping[str, Any], context) -> Any:
    tools = _tool_map()
    tool = tools.get(tool_name)
    if tool is None or tool.executor is None:
        raise RuntimeError("simulated NOC capability handler unavailable")
    signing_key = os.environ.get(
        "SAFEHARNESS_DEMO_SIGNING_KEY",
        "local-demo-only-signing-key-change-before-production",
    )
    runtime = SafeHarnessRuntime(
        services=RuntimeServices(
            tool_catalog=StaticToolCatalog([tool.descriptor]),
            capability_authority=SignedCapabilityGateway(
                signing_key,
                {context.agent_id: _CAPABILITY_GRANTS.get(context.capability_id, frozenset())},
            ),
            approval_broker=DemoApprovalBroker(approve_irreversible=True),
            compensation_provider=NocCompensationProvider(_environment),
            audit_sink=InMemoryAuditSink(),
        )
    )
    session = runtime.session(
        SessionContext(
            tenant_id="safeharness-demo",
            agent_id=context.agent_id,
            session_id=context.session_id,
            run_id=context.run_id,
            trace_id=context.delegation_id,
            framework="sumc-fsm-demo",
            metadata={"parent_run_id": context.parent_run_id, "state_id": context.state_id},
        )
    )
    async with session:
        outcome = await execute_tool(
            session,
            ToolInvocation(
                tool_name=tool_name,
                arguments=dict(arguments),
                tool_version=tool.descriptor.version,
                resource=tool.resource_for(arguments),
            ),
            tool.executor,
            adapter_name="sumc-fsm-demo",
            enforced_obligations=tool.enforced_obligations,
        )
    if outcome.blocked or outcome.error is not None:
        raise RuntimeError("SafeHarness denied simulated NOC capability")
    return outcome.result


async def execute_simulated_noc(capability_id: str, arguments: Mapping[str, Any], context) -> dict[str, Any]:
    """Map a fixed AgentCard capability to one SafeHarness-protected handler."""

    device_id = str(arguments.get("device_id") or "")
    # ponytail: one process-wide lock; split per demo tenant if throughput matters.
    with _environment_lock:
        if capability_id == "alarm.query":
            alarms = await _safe_tool_call("list_active_alarms", {"device_id": device_id}, context)
            return {"device_id": device_id, "alarms": alarms, "outcome": "success"}
        if capability_id == "alarm.diagnose":
            alarms = list(arguments.get("alarms") or [])
            outcome = "resolved" if not alarms else "needs_remediation"
            return {
                "outcome": outcome,
                "summary": "No active alarm." if not alarms else "Active alarm requires controlled remediation.",
            }
        if capability_id == "alarm.verify":
            alarms = await _safe_tool_call("list_active_alarms", {"device_id": device_id}, context)
            return {
                "outcome": "resolved" if not alarms else "unresolved",
                "summary": "Alarm cleared." if not alarms else "Alarm remains active.",
                "device_id": device_id,
                "alarms": alarms,
            }
        if capability_id == "incident.create":
            result = await _safe_tool_call(
                "create_incident_ticket",
                {
                    "title": str(arguments.get("title") or "Controlled NOC remediation"),
                    "device_id": device_id,
                    "severity": str(arguments.get("severity") or "major"),
                    "summary": str(arguments.get("summary") or "FSM remediation"),
                },
                context,
            )
            return {**dict(result), "outcome": "success"}
        if capability_id == "interface.restart":
            result = await _safe_tool_call(
                "restart_interface",
                {
                    "device_id": device_id,
                    "interface": str(arguments.get("interface") or arguments.get("interface_id") or "uplink-1"),
                    "reason": str(arguments.get("reason") or "Verified FSM remediation"),
                    "ticket_id": str(arguments.get("ticket_id") or ""),
                },
                context,
            )
            return {**dict(result), "outcome": "success", "summary": "Simulated interface restart completed."}
    raise RuntimeError("unknown simulated NOC capability")
