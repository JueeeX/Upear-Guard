"""In-memory development backends with secure capability defaults."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from safeharness.api.context import SessionContext
from safeharness.api.tools import ToolDescriptor, ToolInvocation
from safeharness.ports import AuditRecord, AuditSink, AuthorizationResult


class InMemoryAuditSink:
    """Collect audit records for tests. Do not use as a production audit store."""

    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    async def write(self, record: AuditRecord) -> None:
        self.records.append(record)


class CompositeAuditSink:
    """Write each record to every configured sink, propagating failures."""

    def __init__(self, sinks: Iterable[AuditSink]) -> None:
        self._sinks = tuple(sinks)
        if not self._sinks:
            raise ValueError("at least one audit sink is required")

    async def write(self, record: AuditRecord) -> None:
        for sink in self._sinks:
            await sink.write(record)


class StaticToolCatalog:
    def __init__(self, descriptors: Iterable[ToolDescriptor] = ()) -> None:
        self._descriptors = {
            (descriptor.name, descriptor.version): descriptor for descriptor in descriptors
        }

    async def resolve(
        self, tool_name: str, version: str | None = None
    ) -> ToolDescriptor | None:
        if version is not None:
            return self._descriptors.get((tool_name, version))
        matches = [
            descriptor
            for (name, _), descriptor in self._descriptors.items()
            if name == tool_name
        ]
        return matches[0] if len(matches) == 1 else None


class StaticCapabilityAuthority:
    """Simple fail-closed grants for examples and adapter conformance tests.

    A grant may be ``*``, ``tool:<name>``, or a capability listed in the tool's
    ``required_capabilities`` set. Production deployments should use signed,
    session-bound, replay-protected claims instead.
    """

    def __init__(self, grants: Mapping[str, Iterable[str]]) -> None:
        self._grants = {
            agent_id: frozenset(agent_grants)
            for agent_id, agent_grants in grants.items()
        }

    async def authorize(
        self,
        context: SessionContext,
        descriptor: ToolDescriptor,
        invocation: ToolInvocation,
    ) -> AuthorizationResult:
        granted = self._grants.get(context.agent_id, frozenset())
        tool_grant = f"tool:{descriptor.name}"
        capability_match = bool(descriptor.required_capabilities) and (
            descriptor.required_capabilities <= granted
        )
        allowed = "*" in granted or tool_grant in granted or capability_match
        if not allowed:
            return AuthorizationResult(
                False,
                "The agent does not hold the required tool capability.",
                "missing_capability",
                claims={"agent_id": context.agent_id, "tool": descriptor.name},
            )
        return AuthorizationResult(
            True,
            claims={"agent_id": context.agent_id, "tool": descriptor.name},
        )
