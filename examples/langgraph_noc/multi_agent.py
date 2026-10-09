"""LangGraph NOC supervisor and diagnosis Agent demo over the communication gateway.

The convenience runner hosts both Agent clients in one process. Production must run
them as separate workloads so each receives only its own communication credential.
"""

from __future__ import annotations

import argparse
import asyncio
import inspect
import os
import ssl
from collections.abc import Awaitable, Callable, Mapping
from datetime import datetime, timedelta, timezone
from typing import Any, TypedDict
from uuid import uuid4

from safeharness import ContentSource, SafeHarnessRuntime, SessionContext
from safeharness.adapters import LangGraphDependencyError
from safeharness.communication import (
    CommunicationGatewayError,
    InterAgentMessage,
    MessageKind,
    RemoteAgentCommunicationClient,
)

from examples.langgraph_noc.app import SecureNocChat
from examples.langgraph_noc.communication_gateway import (
    DEFAULT_DELEGATION_ID,
    DEFAULT_DIAGNOSIS_ID,
    DEFAULT_RUN_ID,
    DEFAULT_SESSION_ID,
    DEFAULT_SUPERVISOR_ID,
    DEFAULT_TENANT_ID,
    DIAGNOSIS_CAPABILITY,
)


DEFAULT_MULTI_AGENT_REQUEST = (
    "Analyze critical alarms and packet-loss risk for NE-WH-OLT-01, then provide "
    "evidence, likely causes, and safe next actions."
)
DiagnosisHandler = Callable[[str], str | Awaitable[str]]


class MultiAgentState(TypedDict, total=False):
    request: str
    safe_input: str
    halted: bool
    security_reason: str
    final_response: str
    correlation_id: str
    delegation_message_id: str
    query_message_id: str
    diagnosis_query: str
    diagnosis_result: str
    result_message_id: str


class SecureNocMultiAgentWorkflow:
    """LangGraph node implementation for one secured supervisor/diagnosis run."""

    def __init__(
        self,
        *,
        supervisor_client: RemoteAgentCommunicationClient,
        diagnosis_client: RemoteAgentCommunicationClient,
        diagnosis_handler: DiagnosisHandler,
        tenant_id: str = DEFAULT_TENANT_ID,
        supervisor_agent_id: str = DEFAULT_SUPERVISOR_ID,
        diagnosis_agent_id: str = DEFAULT_DIAGNOSIS_ID,
        session_id: str = DEFAULT_SESSION_ID,
        run_id: str = DEFAULT_RUN_ID,
        delegation_id: str = DEFAULT_DELEGATION_ID,
        message_ttl: timedelta = timedelta(minutes=5),
        runtime: SafeHarnessRuntime | None = None,
        now=None,
    ) -> None:
        if not timedelta(seconds=1) <= message_ttl <= timedelta(minutes=10):
            raise ValueError("message_ttl must be between 1 and 600 seconds")
        if (supervisor_client.tenant_id, supervisor_client.agent_id) != (
            tenant_id,
            supervisor_agent_id,
        ):
            raise ValueError("the Supervisor client identity does not match the workflow")
        if (diagnosis_client.tenant_id, diagnosis_client.agent_id) != (
            tenant_id,
            diagnosis_agent_id,
        ):
            raise ValueError("the Diagnosis client identity does not match the workflow")
        if not callable(diagnosis_handler):
            raise TypeError("diagnosis_handler must be callable")
        self.supervisor_client = supervisor_client
        self.diagnosis_client = diagnosis_client
        self.diagnosis_handler = diagnosis_handler
        self.tenant_id = tenant_id
        self.supervisor_agent_id = supervisor_agent_id
        self.diagnosis_agent_id = diagnosis_agent_id
        self.session_id = session_id
        self.run_id = run_id
        self.delegation_id = delegation_id
        self.message_ttl = message_ttl
        self.runtime = runtime or SafeHarnessRuntime()
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._session = None
        self._graph = None

    async def __aenter__(self) -> "SecureNocMultiAgentWorkflow":
        if self._session is not None:
            raise RuntimeError("the multi-Agent workflow is already running")
        context = SessionContext(
            tenant_id=self.tenant_id,
            agent_id=self.supervisor_agent_id,
            session_id=self.session_id,
            run_id=self.run_id,
            framework="langgraph-multi-agent",
            metadata={"role": "supervisor", "demo": True},
        )
        self._session = self.runtime.session(context)
        await self._session.start()
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        if self._session is not None:
            await self._session.close(error=type(exc).__name__ if exc else None)
        self._session = None
        self._graph = None

    async def run(self, request: str) -> dict[str, Any]:
        if self._session is None:
            raise RuntimeError("use the multi-Agent workflow as an async context manager")
        if not isinstance(request, str) or not request.strip():
            raise ValueError("request must be a non-empty string")
        if self._graph is None:
            self._graph = build_multi_agent_graph(self)
        return dict(await self._graph.ainvoke({"request": request}))

    async def supervisor_guard(self, state: Mapping[str, Any]) -> MultiAgentState:
        session = self._require_session()
        request = state.get("request")
        if not isinstance(request, str) or not request.strip():
            return _halt("invalid_request", "The NOC request is invalid.")
        decision = await session.inspect_content(
            request,
            source=ContentSource.USER_INPUT,
        )
        if not decision.executable:
            reason = decision.reasons[-1] if decision.reasons else None
            return _halt(
                reason.code if reason else "supervisor_input_denied",
                "The Supervisor input was denied by SafeHarness.",
            )
        return {
            "safe_input": str(decision.effective_event.payload.get("content", request)),
            "halted": False,
        }

    async def supervisor_send(self, state: Mapping[str, Any]) -> MultiAgentState:
        safe_input = state.get("safe_input")
        if not isinstance(safe_input, str) or not safe_input:
            return _halt("trusted_input_required", "No trusted Supervisor input is active.")
        now = self._utc_now()
        expires_at = now + self.message_ttl
        correlation_id = str(uuid4())
        delegation = InterAgentMessage(
            tenant_id=self.tenant_id,
            sender_agent_id=self.supervisor_agent_id,
            recipient_agent_id=self.diagnosis_agent_id,
            session_id=self.session_id,
            run_id=self.run_id,
            trace_id=correlation_id,
            correlation_id=correlation_id,
            kind=MessageKind.DELEGATE,
            content="Delegate read-only NMS alarm diagnosis for this bounded run.",
            delegation_id=self.delegation_id,
            requested_capabilities=frozenset({DIAGNOSIS_CAPABILITY}),
            metadata={"workflow": "langgraph_noc_multi_agent"},
            created_at=now,
            expires_at=expires_at,
        )
        query = InterAgentMessage(
            tenant_id=self.tenant_id,
            sender_agent_id=self.supervisor_agent_id,
            recipient_agent_id=self.diagnosis_agent_id,
            session_id=self.session_id,
            run_id=self.run_id,
            trace_id=correlation_id,
            correlation_id=correlation_id,
            parent_message_id=delegation.message_id,
            kind=MessageKind.QUERY,
            content=safe_input,
            metadata={"workflow": "langgraph_noc_multi_agent"},
            created_at=now,
            expires_at=expires_at,
        )
        try:
            await self.supervisor_client.send(delegation)
            await self.supervisor_client.send(query)
        except (CommunicationGatewayError, ValueError) as exc:
            return _gateway_halt(exc, "supervisor_send_failed")
        return {
            "correlation_id": correlation_id,
            "delegation_message_id": delegation.message_id,
            "query_message_id": query.message_id,
            "halted": False,
        }

    async def diagnosis_receive(self, state: Mapping[str, Any]) -> MultiAgentState:
        correlation_id = _state_string(state, "correlation_id")
        try:
            received = await self.diagnosis_client.receive(limit=10)
        except CommunicationGatewayError as exc:
            return _gateway_halt(exc, "diagnosis_receive_failed")
        matching = [
            lease
            for lease in received.leases
            if lease.message.session_id == self.session_id
            and lease.message.run_id == self.run_id
            and lease.message.correlation_id == correlation_id
        ]
        delegations = [
            lease for lease in matching if lease.message.kind is MessageKind.DELEGATE
        ]
        queries = [lease for lease in matching if lease.message.kind is MessageKind.QUERY]
        if len(delegations) != 1 or len(queries) != 1:
            return _halt(
                "communication_workflow_incomplete",
                "The Diagnosis Agent did not receive one bounded delegation and query.",
            )
        delegation = delegations[0]
        query = queries[0]
        if (
            delegation.message.delegation_id != self.delegation_id
            or delegation.message.requested_capabilities
            != frozenset({DIAGNOSIS_CAPABILITY})
            or query.message.parent_message_id != delegation.message.message_id
        ):
            return _halt(
                "delegation_scope_mismatch",
                "The received diagnosis delegation does not match this workflow.",
            )
        try:
            await self.diagnosis_client.acknowledge(delegation)
            await self.diagnosis_client.acknowledge(query)
        except CommunicationGatewayError as exc:
            return _gateway_halt(exc, "diagnosis_ack_failed")
        return {
            "diagnosis_query": query.message.content,
            "query_message_id": query.message.message_id,
            "halted": False,
        }

    async def diagnosis_execute(self, state: Mapping[str, Any]) -> MultiAgentState:
        query = _state_string(state, "diagnosis_query")
        try:
            result = self.diagnosis_handler(query)
            result = await result if inspect.isawaitable(result) else result
        except Exception:
            return _halt(
                "diagnosis_agent_failed",
                "The Diagnosis Agent could not complete the requested analysis.",
            )
        if not isinstance(result, str) or not result.strip():
            return _halt(
                "diagnosis_agent_invalid_output",
                "The Diagnosis Agent returned no usable result.",
            )
        return {"diagnosis_result": result, "halted": False}

    async def diagnosis_send(self, state: Mapping[str, Any]) -> MultiAgentState:
        result = _state_string(state, "diagnosis_result")
        correlation_id = _state_string(state, "correlation_id")
        query_message_id = _state_string(state, "query_message_id")
        now = self._utc_now()
        message = InterAgentMessage(
            tenant_id=self.tenant_id,
            sender_agent_id=self.diagnosis_agent_id,
            recipient_agent_id=self.supervisor_agent_id,
            session_id=self.session_id,
            run_id=self.run_id,
            trace_id=correlation_id,
            correlation_id=correlation_id,
            parent_message_id=query_message_id,
            kind=MessageKind.RESULT,
            content=result,
            metadata={"workflow": "langgraph_noc_multi_agent"},
            created_at=now,
            expires_at=now + self.message_ttl,
        )
        try:
            await self.diagnosis_client.send(message)
        except (CommunicationGatewayError, ValueError) as exc:
            return _gateway_halt(exc, "diagnosis_send_failed")
        return {"result_message_id": message.message_id, "halted": False}

    async def supervisor_receive(self, state: Mapping[str, Any]) -> MultiAgentState:
        correlation_id = _state_string(state, "correlation_id")
        query_message_id = _state_string(state, "query_message_id")
        try:
            received = await self.supervisor_client.receive(limit=10)
        except CommunicationGatewayError as exc:
            return _gateway_halt(exc, "supervisor_receive_failed")
        results = [
            lease
            for lease in received.leases
            if lease.message.session_id == self.session_id
            and lease.message.run_id == self.run_id
            and lease.message.correlation_id == correlation_id
            and lease.message.parent_message_id == query_message_id
            and lease.message.kind is MessageKind.RESULT
        ]
        if len(results) != 1:
            return _halt(
                "communication_result_missing",
                "The Supervisor did not receive one bounded Diagnosis result.",
            )
        lease = results[0]
        try:
            await self.supervisor_client.acknowledge(lease)
        except CommunicationGatewayError as exc:
            return _gateway_halt(exc, "supervisor_ack_failed")
        decision = await self._require_session().inspect_final_output(
            lease.message.content
        )
        if not decision.executable:
            reason = decision.reasons[-1] if decision.reasons else None
            return _halt(
                reason.code if reason else "supervisor_output_denied",
                "The final multi-Agent result was denied by SafeHarness.",
            )
        return {
            "final_response": str(
                decision.effective_event.payload.get("content", lease.message.content)
            ),
            "halted": False,
        }

    def _require_session(self):
        if self._session is None:
            raise RuntimeError("the multi-Agent workflow is not running")
        return self._session

    def _utc_now(self) -> datetime:
        value = self._now()
        if value.tzinfo is None:
            raise ValueError("the multi-Agent clock must be timezone-aware")
        return value.astimezone(timezone.utc)


def build_multi_agent_graph(workflow: SecureNocMultiAgentWorkflow, *, checkpointer=None):
    """Build the outer LangGraph that routes all cross-Agent data via the gateway."""

    try:
        from langgraph.graph import END, START, StateGraph
    except ImportError as exc:
        raise LangGraphDependencyError(
            "Install the demo dependencies with: pip install -e '.[langgraph]'"
        ) from exc

    graph = StateGraph(MultiAgentState)
    nodes = (
        ("supervisor_guard", workflow.supervisor_guard),
        ("supervisor_send", workflow.supervisor_send),
        ("diagnosis_receive", workflow.diagnosis_receive),
        ("diagnosis_execute", workflow.diagnosis_execute),
        ("diagnosis_send", workflow.diagnosis_send),
        ("supervisor_receive", workflow.supervisor_receive),
    )
    for name, node in nodes:
        graph.add_node(name, node)
    graph.add_edge(START, "supervisor_guard")
    for (name, _), (next_name, _) in zip(nodes, nodes[1:]):
        graph.add_conditional_edges(
            name,
            _continue_or_end,
            {"continue": next_name, "end": END},
        )
    graph.add_edge("supervisor_receive", END)
    return graph.compile(checkpointer=checkpointer)


class SecureNocChatDiagnosisHandler:
    """Adapt the existing guarded NOC specialist graph to a diagnosis callable."""

    def __init__(self, chat: SecureNocChat) -> None:
        self.chat = chat

    async def __call__(self, request: str) -> str:
        result = await self.chat.ask(request)
        if result["blocked"]:
            raise RuntimeError("the Diagnosis Agent rejected the inter-Agent request")
        response = result["final_response"]
        if not isinstance(response, str) or not response.strip():
            raise RuntimeError("the Diagnosis Agent returned an empty response")
        return response


async def run_configured_multi_agent(
    request: str,
    *,
    model: Any | None = None,
    session_id: str | None = None,
    run_id: str | None = None,
    delegation_id: str | None = None,
    judge_provider: Any = None,
) -> dict[str, Any]:
    gateway_url = os.environ.get(
        "SAFEHARNESS_COMMUNICATION_GATEWAY_URL", "http://127.0.0.1:38200"
    ).strip()
    tenant_id = os.environ.get(
        "SAFEHARNESS_COMMUNICATION_TENANT_ID", DEFAULT_TENANT_ID
    )
    supervisor_agent_id = os.environ.get(
        "SAFEHARNESS_COMMUNICATION_SUPERVISOR_AGENT_ID", DEFAULT_SUPERVISOR_ID
    )
    diagnosis_agent_id = os.environ.get(
        "SAFEHARNESS_COMMUNICATION_DIAGNOSIS_AGENT_ID", DEFAULT_DIAGNOSIS_ID
    )
    supervisor_key = os.environ.get(
        "SAFEHARNESS_COMMUNICATION_SUPERVISOR_API_KEY", ""
    )
    diagnosis_key = os.environ.get(
        "SAFEHARNESS_COMMUNICATION_DIAGNOSIS_API_KEY", ""
    )
    if not _valid_api_key(supervisor_key) or not _valid_api_key(diagnosis_key):
        raise ValueError(
            "both communication Agent API keys must be non-placeholder values "
            "with at least 32 characters"
        )
    tls_context = _client_tls_context(gateway_url)
    supervisor_client = RemoteAgentCommunicationClient(
        gateway_url,
        supervisor_key,
        tenant_id=tenant_id,
        agent_id=supervisor_agent_id,
        tls_context=tls_context,
    )
    diagnosis_client = RemoteAgentCommunicationClient(
        gateway_url,
        diagnosis_key,
        tenant_id=tenant_id,
        agent_id=diagnosis_agent_id,
        tls_context=tls_context,
    )
    session_id = session_id or os.environ.get(
        "SAFEHARNESS_COMMUNICATION_SESSION_ID", DEFAULT_SESSION_ID
    )
    run_id = run_id or os.environ.get("SAFEHARNESS_COMMUNICATION_RUN_ID", DEFAULT_RUN_ID)
    delegation_id = delegation_id or os.environ.get(
        "SAFEHARNESS_COMMUNICATION_DELEGATION_ID", DEFAULT_DELEGATION_ID
    )
    async with SecureNocChat(
        tenant_id=tenant_id,
        agent_id=diagnosis_agent_id,
        thread_id=f"{session_id}-diagnosis",
        model=model,
        judge_provider=judge_provider,
    ) as diagnosis_chat:
        workflow = SecureNocMultiAgentWorkflow(
            supervisor_client=supervisor_client,
            diagnosis_client=diagnosis_client,
            diagnosis_handler=SecureNocChatDiagnosisHandler(diagnosis_chat),
            tenant_id=tenant_id,
            supervisor_agent_id=supervisor_agent_id,
            diagnosis_agent_id=diagnosis_agent_id,
            session_id=session_id,
            run_id=run_id,
            delegation_id=delegation_id,
        )
        async with workflow:
            return await workflow.run(request)


def _client_tls_context(gateway_url: str) -> ssl.SSLContext | None:
    if not gateway_url.lower().startswith("https://"):
        return None
    client_ca = os.environ.get("SAFEHARNESS_COMMUNICATION_CA", "").strip()
    certificate = os.environ.get("SAFEHARNESS_COMMUNICATION_CLIENT_CERT", "").strip()
    private_key = os.environ.get("SAFEHARNESS_COMMUNICATION_CLIENT_KEY", "").strip()
    if bool(certificate) != bool(private_key):
        raise ValueError(
            "SAFEHARNESS_COMMUNICATION_CLIENT_CERT and CLIENT_KEY must be configured together"
        )
    context = ssl.create_default_context(cafile=client_ca or None)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if certificate:
        context.load_cert_chain(certificate, private_key)
    return context


def _continue_or_end(state: Mapping[str, Any]) -> str:
    return "end" if state.get("halted") else "continue"


def _halt(code: str, message: str) -> MultiAgentState:
    return {
        "halted": True,
        "security_reason": code,
        "final_response": message,
    }


def _gateway_halt(exc: Exception, fallback: str) -> MultiAgentState:
    code = exc.code if isinstance(exc, CommunicationGatewayError) else fallback
    return _halt(code, "受保护的 Agent 间通信未通过安全检查，已停止本轮处理。")


def _state_string(state: Mapping[str, Any], key: str) -> str:
    value = state.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"multi-Agent state is missing {key}")
    return value


def _valid_api_key(value: str) -> bool:
    return len(value) >= 32 and not value.lower().startswith("replace-")


async def _main() -> None:
    import llm_api

    llm_api.load_env_file()
    communication_env = os.environ.get("SAFEHARNESS_COMMUNICATION_CLIENT_ENV_FILE")
    default_env = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "config",
        "communication.env",
    )
    llm_api.load_env_file(communication_env or default_env)
    parser = argparse.ArgumentParser(description="SafeHarness LangGraph NOC multi-Agent demo")
    parser.add_argument("request", nargs="?", default=DEFAULT_MULTI_AGENT_REQUEST)
    args = parser.parse_args()
    try:
        result = await run_configured_multi_agent(args.request)
    except (CommunicationGatewayError, LangGraphDependencyError, ValueError) as exc:
        parser.error(str(exc))
    if result.get("halted"):
        print(f"SafeHarness blocked the workflow: {result.get('security_reason', '')}")
    print(result.get("final_response", ""))


if __name__ == "__main__":
    asyncio.run(_main())
