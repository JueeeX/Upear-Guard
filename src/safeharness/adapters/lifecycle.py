"""Framework-neutral wrappers for explicit non-tool lifecycle boundaries."""

from __future__ import annotations

import hashlib
import inspect
import json
import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any

from safeharness.adapters.base import AdapterCapabilities, Coverage
from safeharness.api._mapping import json_safe
from safeharness.api.context import SessionContext
from safeharness.api.decisions import Decision
from safeharness.api.events import ContentSource, EventKind
from safeharness.runtime import SecuritySession


EXPLICIT_LIFECYCLE_CAPABILITIES = AdapterCapabilities(
    input_filter=Coverage.ENFORCE,
    pre_tool_enforcement=Coverage.ENFORCE,
    tool_argument_rewrite=Coverage.ENFORCE,
    post_tool_filter=Coverage.ENFORCE,
    final_output_filter=Coverage.ENFORCE,
    message_interception=Coverage.ENFORCE,
    memory_interception=Coverage.ENFORCE,
    handoff_tracking=Coverage.ENFORCE,
    subagent_creation=Coverage.ENFORCE,
)

_AGENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}\Z")


@dataclass(frozen=True, slots=True)
class GuardedLifecycleValue:
    value: Any
    decision: Decision

    @property
    def blocked(self) -> bool:
        return self.decision.blocked

    @property
    def reason_code(self) -> str:
        reason = self.decision.reasons[-1] if self.decision.reasons else None
        return reason.code if reason is not None else ""


@dataclass(frozen=True, slots=True)
class MemoryOperationOutcome:
    value: Any
    result: Any
    decision: Decision


@dataclass(frozen=True, slots=True)
class SubagentConstraints:
    allowed_agent_ids: frozenset[str] = frozenset()
    delegable_capabilities: frozenset[str] = frozenset()
    max_depth: int = 2

    def __post_init__(self) -> None:
        if not 1 <= self.max_depth <= 32:
            raise ValueError("max_depth must be between 1 and 32")
        if any(_AGENT_ID.fullmatch(agent_id) is None for agent_id in self.allowed_agent_ids):
            raise ValueError("allowed_agent_ids contains an invalid Agent ID")
        if any(not isinstance(item, str) or not item for item in self.delegable_capabilities):
            raise ValueError("delegable_capabilities must contain non-empty strings")

    def denial_reason(
        self,
        agent_id: str,
        requested_capabilities: frozenset[str],
        depth: int,
    ) -> str:
        if agent_id not in self.allowed_agent_ids:
            return "subagent_target_denied"
        if depth > self.max_depth:
            return "subagent_depth_exceeded"
        if not requested_capabilities.issubset(self.delegable_capabilities):
            return "subagent_capability_escalation"
        return ""


@dataclass(frozen=True, slots=True)
class SubagentCreationOutcome:
    child_context: SessionContext
    result: Any
    decision: Decision


class LifecycleOperationDenied(RuntimeError):
    def __init__(self, decision: Decision, *, fallback_code: str = "policy_denied") -> None:
        self.decision = decision
        reason = decision.reasons[-1] if decision.reasons else None
        self.reason_code = reason.code if reason is not None else fallback_code
        message = reason.message if reason is not None else "Lifecycle operation denied."
        super().__init__(message)


class ExplicitLifecycleAdapter:
    """Secure only operations explicitly routed through this adapter instance."""

    capabilities = EXPLICIT_LIFECYCLE_CAPABILITIES

    def __init__(
        self,
        session: SecuritySession,
        *,
        adapter_name: str = "generic-lifecycle",
        subagent_constraints: SubagentConstraints | None = None,
    ) -> None:
        if not adapter_name:
            raise ValueError("adapter_name must not be empty")
        self.session = session
        self.adapter_name = adapter_name
        self.subagent_constraints = subagent_constraints or SubagentConstraints()

    async def inspect_input(self, content: str) -> GuardedLifecycleValue:
        decision = await self.session.inspect_content(
            content,
            source=ContentSource.USER_INPUT,
            attributes={"adapter": self.adapter_name},
        )
        return GuardedLifecycleValue(_effective_value(decision, "content", content), decision)

    async def inspect_message(
        self,
        content: str,
        *,
        target_agent_id: str = "",
        attributes: Mapping[str, Any] | None = None,
    ) -> GuardedLifecycleValue:
        decision = await self.session.evaluate(
            EventKind.INTER_AGENT,
            {
                "content": content,
                "source": ContentSource.INTER_AGENT.value,
                "target_agent_id": target_agent_id,
                "attributes": {
                    "adapter": self.adapter_name,
                    **dict(attributes or {}),
                },
            },
        )
        return GuardedLifecycleValue(_effective_value(decision, "content", content), decision)

    async def inspect_final_output(self, content: str) -> GuardedLifecycleValue:
        decision = await self.session.inspect_final_output(content)
        return GuardedLifecycleValue(_effective_value(decision, "content", content), decision)

    async def read_memory(
        self,
        key: str,
        reader: Callable[[], Any | Awaitable[Any]],
        *,
        namespace: tuple[str, ...] = (),
    ) -> MemoryOperationOutcome:
        key_fingerprint = _memory_key_fingerprint(namespace, key)
        proposed = await self.session.evaluate(
            EventKind.MEMORY_READ,
            {
                "memory_key_fingerprint": key_fingerprint,
                "adapter": self.adapter_name,
            },
        )
        _raise_if_blocked(proposed)
        value = reader()
        value = await value if inspect.isawaitable(value) else value
        decision = await self.session.evaluate(
            EventKind.MEMORY_READ_RESULT,
            {
                "result": json_safe(value),
                "source": ContentSource.MEMORY.value,
                "memory_key_fingerprint": key_fingerprint,
                "attributes": {"adapter": self.adapter_name},
            },
        )
        _raise_if_blocked(decision)
        return MemoryOperationOutcome(
            _effective_value(decision, "result", value),
            value,
            decision,
        )

    async def write_memory(
        self,
        key: str,
        value: Any,
        writer: Callable[[Any], Any | Awaitable[Any]],
        *,
        namespace: tuple[str, ...] = (),
    ) -> MemoryOperationOutcome:
        safe_value = json_safe(value)
        serialized = json.dumps(
            safe_value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        decision = await self.session.evaluate(
            EventKind.MEMORY_WRITE_PROPOSED,
            {
                "content": safe_value,
                "source": ContentSource.MEMORY.value,
                "serialized_bytes": len(serialized),
                "memory_key_fingerprint": _memory_key_fingerprint(namespace, key),
                "attributes": {"adapter": self.adapter_name},
            },
        )
        _raise_if_blocked(decision)
        effective = _effective_value(decision, "content", safe_value)
        result = writer(effective)
        result = await result if inspect.isawaitable(result) else result
        return MemoryOperationOutcome(effective, result, decision)

    async def create_subagent(
        self,
        agent_id: str,
        task: str,
        factory: Callable[[SessionContext, str], Any | Awaitable[Any]],
        *,
        requested_capabilities: frozenset[str] = frozenset(),
        attributes: Mapping[str, Any] | None = None,
    ) -> SubagentCreationOutcome:
        if _AGENT_ID.fullmatch(agent_id) is None:
            raise ValueError("agent_id is invalid")
        if any(not isinstance(item, str) or not item for item in requested_capabilities):
            raise ValueError("requested_capabilities must contain non-empty strings")
        depth = _subagent_depth(self.session.context) + 1
        constraint_reason = self.subagent_constraints.denial_reason(
            agent_id,
            requested_capabilities,
            depth,
        )
        decision = await self.session.evaluate(
            EventKind.SUBAGENT_CREATION_PROPOSED,
            {
                "target_agent_id": agent_id,
                "content": task,
                "source": ContentSource.INTER_AGENT.value,
                "depth": depth,
                "requested_capabilities": sorted(requested_capabilities),
                "delegated_capabilities": sorted(
                    self.subagent_constraints.delegable_capabilities
                ),
                "constraint_allowed": not constraint_reason,
                "constraint_reason": constraint_reason,
                "attributes": {
                    "adapter": self.adapter_name,
                    **dict(attributes or {}),
                },
            },
        )
        if constraint_reason:
            raise LifecycleOperationDenied(decision, fallback_code=constraint_reason)
        _raise_if_blocked(decision)
        effective_task = str(_effective_value(decision, "content", task))
        child_context = self.session.context.child(
            agent_id,
            safeharness_subagent_depth=depth,
            safeharness_requested_capabilities=sorted(requested_capabilities),
            safeharness_adapter=self.adapter_name,
        )
        started = await self.session.evaluate(
            EventKind.SUBAGENT_STARTED,
            {
                "target_agent_id": agent_id,
                "child_session_id": child_context.session_id,
                "depth": depth,
                "adapter": self.adapter_name,
            },
        )
        _raise_if_blocked(started)
        try:
            result = factory(child_context, effective_task)
            result = await result if inspect.isawaitable(result) else result
        except Exception as exc:
            await self.session.evaluate(
                EventKind.SUBAGENT_FINISHED,
                {
                    "target_agent_id": agent_id,
                    "child_session_id": child_context.session_id,
                    "error_type": type(exc).__name__,
                    "adapter": self.adapter_name,
                },
            )
            raise
        await self.session.evaluate(
            EventKind.SUBAGENT_FINISHED,
            {
                "target_agent_id": agent_id,
                "child_session_id": child_context.session_id,
                "error_type": None,
                "adapter": self.adapter_name,
            },
        )
        return SubagentCreationOutcome(child_context, result, decision)


def _raise_if_blocked(decision: Decision) -> None:
    if decision.blocked:
        raise LifecycleOperationDenied(decision)


def _effective_value(decision: Decision, key: str, fallback: Any) -> Any:
    return decision.effective_event.payload.get(key, fallback)


def _memory_key_fingerprint(namespace: tuple[str, ...], key: str) -> str:
    if not isinstance(key, str) or not key:
        raise ValueError("memory key must not be empty")
    if not isinstance(namespace, tuple) or any(
        not isinstance(item, str) or not item for item in namespace
    ):
        raise ValueError("memory namespace must contain non-empty strings")
    canonical = json.dumps([*namespace, key], separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _subagent_depth(context: SessionContext) -> int:
    value = context.metadata.get("safeharness_subagent_depth", 0)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError("safeharness_subagent_depth metadata must be a non-negative integer")
    return value
