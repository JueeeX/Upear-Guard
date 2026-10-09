"""Security session identity and tenancy context."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping
from uuid import uuid4

from safeharness.api._mapping import frozen_mapping, plain_mapping


@dataclass(frozen=True, slots=True)
class SessionContext:
    """Identity boundary for one agent run.

    A runtime may be shared globally, but a :class:`SessionContext` and its associated
    ``SecuritySession`` must never be shared across tenants or independent runs.
    """

    tenant_id: str
    agent_id: str
    session_id: str = field(default_factory=lambda: str(uuid4()))
    run_id: str = field(default_factory=lambda: str(uuid4()))
    framework: str = "generic"
    trace_id: str = field(default_factory=lambda: str(uuid4()))
    parent_session_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.tenant_id:
            raise ValueError("tenant_id must not be empty")
        if not self.agent_id:
            raise ValueError("agent_id must not be empty")
        object.__setattr__(self, "metadata", frozen_mapping(self.metadata))

    def child(self, agent_id: str, **metadata: Any) -> "SessionContext":
        """Create an isolated child-agent context linked to this session."""

        merged = plain_mapping(self.metadata)
        merged.update(metadata)
        return SessionContext(
            tenant_id=self.tenant_id,
            agent_id=agent_id,
            framework=self.framework,
            run_id=self.run_id,
            trace_id=self.trace_id,
            parent_session_id=self.session_id,
            metadata=merged,
        )
