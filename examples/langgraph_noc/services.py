"""Demo approval and compensation services for simulated NOC operations."""

from __future__ import annotations

from typing import Any

from safeharness.ports import ApprovalResult, CompensationReceipt

from examples.langgraph_noc.domain import NetworkOperationsEnvironment


class DemoApprovalBroker:
    """Explicit opt-in approval broker for the simulated irreversible tool."""

    def __init__(self, *, approve_irreversible: bool = False) -> None:
        self.approve_irreversible = approve_irreversible
        self.requests = 0

    async def request(self, context, event, decision) -> ApprovalResult:
        self.requests += 1
        irreversible = any(
            reason.code == "irreversible_action_requires_approval"
            for reason in decision.reasons
        )
        if not self.approve_irreversible or not irreversible:
            return ApprovalResult(
                False,
                reason=(
                    "Demo operator approval is disabled."
                    if irreversible
                    else "The demo flag approves irreversible actions only."
                ),
            )
        return ApprovalResult(
            True,
            approver="demo-noc-operator",
            reason="Approved explicitly for this simulated demo run.",
            approval_id=f"demo-approval-{self.requests}",
        )


class NocCompensationProvider:
    """Compensate a created demo ticket when post-execution policy rejects it."""

    def __init__(self, environment: NetworkOperationsEnvironment) -> None:
        self.environment = environment

    async def compensate(
        self,
        context,
        invocation,
        result: Any,
        reason: str,
    ) -> CompensationReceipt:
        if invocation.tool_name != "create_incident_ticket" or not isinstance(result, dict):
            return CompensationReceipt("unsupported", False)
        ticket_id = str(result.get("ticket_id", ""))
        if not ticket_id:
            return CompensationReceipt("missing-ticket-id", False)
        self.environment.close_incident_ticket(ticket_id, reason)
        return CompensationReceipt(
            compensation_id=f"close-{ticket_id}",
            compensated=True,
            details={"ticket_id": ticket_id},
        )
