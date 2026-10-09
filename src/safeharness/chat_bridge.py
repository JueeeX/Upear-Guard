"""Fail-closed protected chat bridge for SUMC-style callers.

The bridge owns one Guard and one compiled graph per request.  It deliberately
returns buffered, redacted events until a framework-native streaming contract
is wired end to end.
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Awaitable, Callable, Mapping
from uuid import uuid4

from safeharness.adapters.langgraph import LangGraphAgent
from safeharness.guard import Guard
from safeharness.runtime.runtime import SafeHarnessRuntime
from safeharness.ports import AuditRecord, AuditSink


class _TimelineAuditSink:
    """Fan out redacted audit records and retain per-run summaries."""

    def __init__(self, downstream: AuditSink | None) -> None:
        self.downstream = downstream
        self.records: dict[str, list[AuditRecord]] = {}

    async def write(self, record: AuditRecord) -> None:
        if self.downstream is not None:
            await self.downstream.write(record)
        run_id = record.event.meta.run_id
        self.records.setdefault(run_id, []).append(record)

    def take(self, run_id: str) -> list[AuditRecord]:
        return self.records.pop(run_id, [])


class ProtectedChatError(RuntimeError):
    """A protected run was unavailable or failed; no unprotected fallback exists."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        events: tuple[dict[str, Any], ...] = (),
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.events = events


@dataclass(frozen=True, slots=True)
class ProtectedChatRequest:
    tenant_id: str
    user_id: str
    role: str
    conversation_id: str
    agent_id: str
    message: str
    project_id: str = ""
    trace_id: str = ""
    run_id: str = ""
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in (
            "tenant_id",
            "user_id",
            "role",
            "conversation_id",
            "agent_id",
            "message",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must not be empty")
            if value != value.strip():
                raise ValueError(f"{name} must not contain surrounding whitespace")
        for name in ("project_id", "trace_id", "run_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or (value and value != value.strip()):
                raise ValueError(f"{name} must be a trimmed string")


@dataclass(frozen=True, slots=True)
class ProtectedChatResult:
    events: tuple[dict[str, Any], ...]
    final_response: str | None
    blocked: bool
    security_reason: str
    trace_id: str
    run_id: str
    session_id: str
    conversation_id: str


AgentFactory = Callable[[ProtectedChatRequest], LangGraphAgent | Awaitable[LangGraphAgent]]
RuntimeFactory = Callable[
    [ProtectedChatRequest], SafeHarnessRuntime | Awaitable[SafeHarnessRuntime]
]


class ProtectedChatRunner:
    """Run exactly one SafeHarness-protected LangGraph chat turn."""

    def __init__(
        self,
        agent_factory: AgentFactory,
        *,
        runtime: SafeHarnessRuntime | None = None,
        runtime_factory: RuntimeFactory | None = None,
        security_timeline: bool = False,
    ) -> None:
        if not callable(agent_factory):
            raise TypeError("agent_factory must be callable")
        self.agent_factory = agent_factory
        self.runtime = runtime or SafeHarnessRuntime()
        self.runtime_factory = runtime_factory
        self.security_timeline = security_timeline
        self._timeline_sink = _TimelineAuditSink(self.runtime.services.audit_sink) if security_timeline else None
        if self._timeline_sink is not None:
            self.runtime.services = replace(self.runtime.services, audit_sink=self._timeline_sink)

    @staticmethod
    def _timeline_events(records: list[AuditRecord]) -> list[tuple[str, dict[str, Any]]]:
        output: list[tuple[str, dict[str, Any]]] = []
        for record in sorted(records, key=lambda item: item.event.meta.sequence):
            event = record.event
            decision = record.decision
            decision_data = {
                "decision_id": decision.decision_id if decision else "",
                "event_kind": event.kind.value,
                "disposition": decision.disposition.value if decision else "",
                "policy_version": decision.policy_version if decision else "",
                "reason_code": (decision.reasons[0].code if decision and decision.reasons else ""),
            }
            output.append(("policy_decision", decision_data))
            if event.kind.value == "tool_call_proposed":
                output.append(("tool_proposal", {
                    "decision_id": decision_data["decision_id"],
                    "tool_name": str(event.payload.get("tool_name") or ""),
                }))
            details = dict(record.details)
            approval_granted = bool(
                decision
                and any(reason.code == "approval_granted" for reason in decision.reasons)
            )
            if details.get("approval_id") or (
                event.kind.value == "tool_call_proposed"
                and decision
                and (decision.disposition.value == "require_approval" or approval_granted)
            ):
                output.append(("approval", {
                    "approval_id": str(details.get("approval_id") or ""),
                    "status": "approved" if decision and decision.executable else "denied",
                }))
            if event.kind.value in {"tool_call_started", "tool_call_succeeded", "tool_call_failed"}:
                output.append(("execution", {
                    "decision_id": decision_data["decision_id"],
                    "tool_name": str(event.payload.get("tool_name") or ""),
                    "status": event.kind.value.removeprefix("tool_call_"),
                }))
            if record.receipt is not None:
                output.append(("receipt", {
                    "receipt_id": record.receipt.receipt_id,
                    "decision_id": record.receipt.decision_id,
                    "enforced": bool(record.receipt.enforced),
                    "adapter": record.receipt.adapter,
                }))
            output.append(("audit_reference", {
                "record_type": record.record_type,
                "event_id": event.meta.event_id,
                "decision_id": decision_data["decision_id"],
                "receipt_id": record.receipt.receipt_id if record.receipt else "",
            }))
        return output

    async def ainvoke(self, request: ProtectedChatRequest) -> ProtectedChatResult:
        """Execute protected graph and return only safe response fields."""

        events: list[dict[str, Any]] = []
        run_id = request.run_id or str(uuid4())
        trace_id = request.trace_id or str(uuid4())
        session_id = str(request.metadata.get("session_id") or request.conversation_id)
        sequence = 0

        def emit(event_type: str, data: Mapping[str, Any] | None = None) -> None:
            nonlocal sequence
            sequence += 1
            events.append(
                {
                    "schema_version": "1.0",
                    "event_id": str(uuid4()),
                    "type": event_type,
                    "sequence": sequence,
                    "tenant_id": request.tenant_id,
                    "user_id": request.user_id,
                    "agent_id": request.agent_id,
                    "conversation_id": request.conversation_id,
                    "session_id": session_id,
                    "run_id": run_id,
                    "trace_id": trace_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "data": dict(data or {}),
                }
            )

        emit("run_started")
        runtime = self.runtime
        if self.runtime_factory is not None:
            try:
                runtime = self.runtime_factory(request)
                if inspect.isawaitable(runtime):
                    runtime = await runtime
                if not isinstance(runtime, SafeHarnessRuntime):
                    raise TypeError("runtime_factory must return SafeHarnessRuntime")
            except Exception as exc:
                emit(
                    "error",
                    {
                        "code": "protected_backend_unavailable",
                        "message": "Protected chat backend unavailable.",
                    },
                )
                emit("run_finished", {"status": "error"})
                raise ProtectedChatError(
                    "protected_backend_unavailable",
                    f"protected chat runtime unavailable ({type(exc).__name__})",
                    events=tuple(events),
                ) from exc
        if self._timeline_sink is not None and runtime is not self.runtime:
            runtime.services = replace(runtime.services, audit_sink=self._timeline_sink)

        try:
            agent = self.agent_factory(request)
            if inspect.isawaitable(agent):
                agent = await agent
            if not isinstance(agent, LangGraphAgent):
                raise TypeError("agent_factory must return LangGraphAgent")
        except Exception as exc:
            emit(
                "error",
                {
                    "code": "protected_backend_unavailable",
                    "message": "Protected chat backend unavailable.",
                },
            )
            emit("run_finished", {"status": "error"})
            raise ProtectedChatError(
                "protected_backend_unavailable",
                f"protected chat backend unavailable ({type(exc).__name__})",
                events=tuple(events),
            ) from exc

        try:
            from langchain_core.messages import HumanMessage
        except ImportError as exc:
            emit(
                "error",
                {
                    "code": "protected_backend_unavailable",
                    "message": "Protected chat backend unavailable.",
                },
            )
            emit("run_finished", {"status": "error"})
            raise ProtectedChatError(
                "protected_backend_unavailable",
                "LangChain message dependencies are unavailable",
                events=tuple(events),
            ) from exc

        try:
            async with Guard(
                tenant_id=request.tenant_id,
                agent_id=request.agent_id,
                runtime=runtime,
                session_id=session_id,
                run_id=run_id,
                trace_id=trace_id,
                framework="langgraph",
                metadata={
                    "user_id": request.user_id,
                    "role": request.role,
                    "conversation_id": request.conversation_id,
                    **({"project_id": request.project_id} if request.project_id else {}),
                },
            ) as guard:
                # This is the only graph entrypoint allowed by this bridge.
                protected_graph = guard.attach(agent)
                state = await protected_graph.ainvoke(
                    {"messages": [HumanMessage(content=request.message)]},
                    config={"configurable": {"thread_id": session_id}},
                )
                blocked = bool(state.get("halted"))
                reason = str(state.get("security_reason") or "")
                final_response = state.get("final_response")
                if not isinstance(final_response, str):
                    final_response = None
        except Exception as exc:
            if self._timeline_sink is not None:
                self._timeline_sink.take(run_id)
            emit(
                "error",
                {
                    "code": "protected_run_failed",
                    "message": "Protected chat run failed.",
                },
            )
            emit("run_finished", {"status": "error"})
            raise ProtectedChatError(
                "protected_run_failed",
                f"protected chat run failed ({type(exc).__name__})",
                events=tuple(events),
            ) from exc

        if self._timeline_sink is not None:
            for event_type, data in self._timeline_events(self._timeline_sink.take(run_id)):
                emit(event_type, data)

        if blocked:
            emit(
                "blocked",
                {
                    "reason_code": reason or "policy_denied",
                    "message": final_response or "Request blocked by SafeHarness policy.",
                },
            )
        elif final_response is not None:
            emit("message", {"content": final_response})
        emit("run_finished", {"status": "blocked" if blocked else "completed"})
        return ProtectedChatResult(
            events=tuple(events),
            final_response=final_response,
            blocked=blocked,
            security_reason=reason,
            trace_id=trace_id,
            run_id=run_id,
            session_id=session_id,
            conversation_id=request.conversation_id,
        )

    async def astream(self, request: ProtectedChatRequest) -> AsyncIterator[dict[str, Any]]:
        """Yield safe buffered events; raw model/tool payloads stay server-side."""

        try:
            events = (await self.ainvoke(request)).events
        except ProtectedChatError as exc:
            events = exc.events
        for event in events:
            yield event

    async def astream_context(self, context: Mapping[str, str]) -> AsyncIterator[dict[str, Any]]:
        """Adapt a SUMC backend context without exposing framework objects."""

        request = ProtectedChatRequest(
            tenant_id=context["tenant_id"],
            user_id=context["user_id"],
            role=context["role"],
            conversation_id=context["conversation_id"],
            agent_id=context["agent_id"],
            message=context["message"],
            project_id=context.get("project_id", ""),
            trace_id=context["trace_id"],
            run_id=context["run_id"],
            metadata={
                "model_provider_id": context.get("model_provider_id", ""),
                "session_id": context.get("session_id", ""),
                "delegation_id": context.get("delegation_id", ""),
            },
        )
        async for event in self.astream(request):
            yield event
