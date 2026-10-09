"""Canonical lifecycle events consumed by the SafeHarness policy engine."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping
from uuid import uuid4

from safeharness.api._mapping import frozen_mapping, json_safe


class EventKind(str, Enum):
    RUN_STARTED = "run_started"
    RUN_FINISHED = "run_finished"
    CONTENT_RECEIVED = "content_received"
    MODEL_REQUESTED = "model_requested"
    MODEL_RESPONDED = "model_responded"
    TOOL_CALL_PROPOSED = "tool_call_proposed"
    TOOL_CALL_STARTED = "tool_call_started"
    TOOL_CALL_SUCCEEDED = "tool_call_succeeded"
    TOOL_CALL_FAILED = "tool_call_failed"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE_PROPOSED = "memory_write_proposed"
    MEMORY_READ_RESULT = "memory_read_result"
    AGENT_HANDOFF = "agent_handoff"
    INTER_AGENT = "inter_agent"
    SUBAGENT_CREATION_PROPOSED = "subagent_creation_proposed"
    SUBAGENT_STARTED = "subagent_started"
    SUBAGENT_FINISHED = "subagent_finished"
    FINAL_OUTPUT_PROPOSED = "final_output_proposed"
    CHECKPOINT_CREATED = "checkpoint_created"
    ROLLBACK_REQUESTED = "rollback_requested"
    ROLLBACK_COMPLETED = "rollback_completed"


class ContentSource(str, Enum):
    USER_INPUT = "user_input"
    TOOL_OUTPUT = "tool_output"
    RETRIEVED = "retrieved"
    INTER_AGENT = "inter_agent"
    MEMORY = "memory"
    SYSTEM = "system"
    AGENT_OUTPUT = "agent_output"


@dataclass(frozen=True, slots=True)
class EventMeta:
    tenant_id: str
    session_id: str
    run_id: str
    agent_id: str
    sequence: int
    framework: str = "generic"
    trace_id: str = ""
    span_id: str = field(default_factory=lambda: str(uuid4()))
    parent_span_id: str | None = None
    schema_version: str = "1.0"
    event_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if self.sequence < 1:
            raise ValueError("event sequence must be >= 1")
        if not self.tenant_id or not self.session_id or not self.agent_id:
            raise ValueError("tenant_id, session_id, and agent_id are required")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "tenant_id": self.tenant_id,
            "session_id": self.session_id,
            "run_id": self.run_id,
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "sequence": self.sequence,
            "agent_id": self.agent_id,
            "framework": self.framework,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    kind: EventKind
    meta: EventMeta
    payload: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "payload", frozen_mapping(self.payload))

    def with_payload(self, payload: Mapping[str, Any]) -> "SecurityEvent":
        """Return a policy-modified copy while preserving event identity."""

        return replace(self, payload=frozen_mapping(payload))

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "meta": self.meta.to_dict(),
            "payload": json_safe(self.payload),
        }
