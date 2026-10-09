"""SafeHarness lifecycle inspection for inbound Agent messages."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from safeharness import SafeHarnessRuntime, SessionContext
from safeharness.api.events import ContentSource, EventKind
from safeharness.communication.models import CommunicationInspection, InterAgentMessage


class InterAgentMessageInspector(Protocol):
    async def inspect(self, message: InterAgentMessage) -> CommunicationInspection:
        """Inspect and optionally sanitize one authenticated inter-Agent message."""


class SafeHarnessInterAgentInspector:
    """Apply the configured lifecycle policies at the recipient boundary."""

    def __init__(self, runtime: SafeHarnessRuntime | None = None) -> None:
        self.runtime = runtime or SafeHarnessRuntime()

    async def inspect(self, message: InterAgentMessage) -> CommunicationInspection:
        context = SessionContext(
            tenant_id=message.tenant_id,
            agent_id=message.recipient_agent_id,
            session_id=message.session_id,
            run_id=message.run_id,
            trace_id=message.trace_id,
            framework="agent-communication-gateway",
            metadata={
                "source_agent_id": message.sender_agent_id,
                "message_kind": message.kind.value,
            },
        )
        async with self.runtime.session(context) as session:
            decision = await session.evaluate(
                EventKind.INTER_AGENT,
                {
                    "content": message.content,
                    "source": ContentSource.INTER_AGENT.value,
                    "source_agent_id": message.sender_agent_id,
                    "target_agent_id": message.recipient_agent_id,
                    "message_kind": message.kind.value,
                    "attributes": {
                        "correlation_id": message.correlation_id,
                        "parent_message_id": message.parent_message_id,
                    },
                },
            )
        reason = decision.reasons[-1] if decision.reasons else None
        effective = decision.effective_event.payload
        content = str(effective.get("content", message.content))
        provenance = effective.get("provenance")
        return CommunicationInspection(
            allowed=decision.executable,
            content=content,
            modified=content != message.content,
            reason_code=reason.code if reason else "",
            reason=reason.message if reason else "",
            provenance=provenance if isinstance(provenance, Mapping) else {},
        )
