"""Secure LangGraph NOC assistant demo.

Run with ``python -m examples.langgraph_noc.app`` after installing the optional
LangGraph dependencies. All tools target an in-memory simulated NMS backend.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import secrets
import ssl
from collections import Counter
from collections.abc import Callable, Mapping
from typing import Any

from safeharness import (
    Guard,
    LangGraphAgent,
    Reversibility,
    SafeHarnessRuntime,
)
from safeharness.adapters import LangGraphDependencyError, LangGraphTool
from safeharness.backends import (
    CompositeAuditSink,
    InMemoryAuditSink,
    OpenAICompatibleJudge,
    PostgreSQLAuditSink,
    SignedCapabilityGateway,
    SQLiteAuditSink,
    StaticToolCatalog,
    build_enforcement_receipt_issuer_from_environment,
)
from safeharness.gateway import RemoteToolGatewayClient
from safeharness.runtime import RuntimeServices

from examples.langgraph_noc.domain import (
    DEFAULT_NOC_GRANTS,
    DEFAULT_NOC_READ_ONLY_GRANTS,
    NetworkOperationsEnvironment,
    build_noc_tools,
)
from examples.langgraph_noc.services import (
    DemoApprovalBroker,
    NocCompensationProvider,
)


SYSTEM_PROMPT = """You are a network-operations assistant for FiberHome Telecommunication
Technologies. Help operators triage alarms, identify hidden risks, and prepare fault
handling plans. Use tools to collect evidence before drawing conclusions. Prefer
read-only diagnosis. Creating a ticket is allowed when evidence justifies it. Never
restart an interface or perform another availability-impacting action unless the
SafeHarness approval path authorizes it. Clearly distinguish observed facts,
hypotheses, and recommended next actions. Reply in Chinese unless asked otherwise."""

DEFAULT_REQUEST = (
    "请排查 NE-WH-OLT-01 当前严重告警和丢包隐患，"
    "给出证据、可能原因和处置建议。"
)
_CONFIGURED_JUDGE = object()
_CHAT_COMMANDS = frozenset(
    {"/audit", "/exit", "/help", "/quit", "/status", "/trace"}
)


def _trace_digest(payload: Mapping[str, Any]) -> str:
    for key in ("content", "result", "arguments"):
        summary = payload.get(key)
        if isinstance(summary, Mapping) and summary.get("sha256"):
            return str(summary["sha256"])
    return ""


def _trace_action(record) -> tuple[str, int]:
    decision = record.decision
    if decision is None:
        return "OBSERVED", 0
    event = record.event.kind.value
    blocked = decision.blocked
    payload = record.event.payload
    attributes = payload.get("attributes")
    if not isinstance(attributes, Mapping):
        attributes = {}
    tool_call_count = int(attributes.get("tool_call_count", 0) or 0)
    source = str(payload.get("source", ""))

    if event == "content_received":
        if blocked and source == "user_input":
            return "INPUT_BLOCKED; MODEL_SKIPPED", 0
        if blocked and source == "agent_output" and tool_call_count:
            return f"MESSAGE_BLOCKED; TOOL_CALLS_STRIPPED={tool_call_count}", tool_call_count
        return ("CONTENT_BLOCKED_AND_REPLACED" if blocked else "CONTENT_ACCEPTED"), 0
    if event == "model_requested":
        return "MODEL_REQUESTED", 0
    if event == "model_responded":
        return "MODEL_CALLED", 0
    if event == "tool_call_proposed":
        return ("TOOL_CALL_BLOCKED" if blocked else "TOOL_CALL_AUTHORIZED"), 0
    if event == "tool_call_started":
        return "TOOL_EXECUTED", 0
    if event == "tool_call_succeeded":
        return ("TOOL_RESULT_BLOCKED" if blocked else "TOOL_RESULT_ACCEPTED"), 0
    if event == "tool_call_failed":
        return "TOOL_FAILED", 0
    if event == "final_output_proposed":
        return ("OUTPUT_BLOCKED" if blocked else "OUTPUT_RELEASED"), 0
    return ("BLOCKED" if blocked else "ALLOWED"), 0


def build_security_trace(records) -> dict[str, Any]:
    """Build a content-free causal trace from already-minimized audit records."""

    records = tuple(records)
    enforced_ids = {
        record.decision.decision_id
        for record in records
        if record.record_type == "enforcement"
        and record.decision is not None
        and record.receipt is not None
        and record.receipt.enforced
    }
    entries: list[dict[str, Any]] = []
    stripped_total = 0
    for record in records:
        if record.record_type != "decision" or record.decision is None:
            continue
        decision = record.decision
        action, stripped = _trace_action(record)
        stripped_total += stripped
        payload = record.event.payload
        entries.append(
            {
                "sequence": record.event.meta.sequence,
                "event": record.event.kind.value,
                "decision": decision.disposition.value.upper(),
                "blocked": decision.blocked,
                "action": action,
                "reason_code": decision.reasons[-1].code if decision.reasons else "",
                "source": str(payload.get("source", "")),
                "tool": str(payload.get("tool_name", "")),
                "digest": _trace_digest(payload),
                "receipt_enforced": decision.decision_id in enforced_ids,
            }
        )

    def count(event: str, *, blocked: bool | None = None) -> int:
        matches = [entry for entry in entries if entry["event"] == event]
        if blocked is None:
            return len(matches)
        return sum(entry["blocked"] is blocked for entry in matches)

    return {
        "redacted": True,
        "entries": entries,
        "summary": {
            "model_requests": count("model_requested"),
            "model_calls": count("model_responded"),
            "tool_calls_proposed": count("tool_call_proposed"),
            "tool_calls_started": count("tool_call_started"),
            "blocked_tool_results": count("tool_call_succeeded", blocked=True),
            "tool_calls_stripped": stripped_total,
            "blocked_decisions": sum(entry["blocked"] for entry in entries),
        },
    }


def format_security_trace(trace: Mapping[str, Any]) -> str:
    """Render one redacted security trace for terminal users."""

    entries = trace.get("entries", ())
    if not entries:
        return "安全轨迹：当前还没有已完成的对话或安全演示。"
    lines = ["安全轨迹（原始内容已脱敏）："]
    for entry in entries:
        details = []
        if entry.get("source"):
            details.append(f"source={entry['source']}")
        if entry.get("tool"):
            details.append(f"tool={entry['tool']}")
        if entry.get("reason_code"):
            details.append(f"reason={entry['reason_code']}")
        if entry.get("digest"):
            details.append(f"sha256={entry['digest'][:12]}")
        if entry.get("receipt_enforced"):
            details.append("receipt=enforced")
        suffix = f" ({', '.join(details)})" if details else ""
        lines.append(
            f"[{entry['sequence']:03d}] {entry['event']:<23} "
            f"{entry['decision']:<6} {entry['action']}{suffix}"
        )
    summary = trace.get("summary", {})
    lines.append(
        "证据汇总："
        f"model_calls={summary.get('model_calls', 0)}, "
        f"tool_calls_proposed={summary.get('tool_calls_proposed', 0)}, "
        f"tool_calls_started={summary.get('tool_calls_started', 0)}, "
        f"blocked_tool_results={summary.get('blocked_tool_results', 0)}, "
        f"tool_calls_stripped={summary.get('tool_calls_stripped', 0)}"
    )
    return "\n".join(lines)


def build_model() -> Any:
    """Build an OpenAI-compatible LangChain model from config/llm.env values."""

    try:
        from langchain_openai import ChatOpenAI
    except ImportError as exc:
        raise LangGraphDependencyError(
            "Install the demo dependencies with: pip install -e '.[langgraph]'"
        ) from exc

    import llm_api

    llm_api.load_env_file()
    base_url, api_key = llm_api._endpoint_settings()
    model_name = llm_api.configured_model(role="agent")
    return ChatOpenAI(
        model=model_name,
        base_url=base_url,
        api_key=api_key,
        temperature=0,
    )


def build_judge_provider() -> OpenAICompatibleJudge | None:
    """Build the optional semantic judge from the shared config/llm.env file."""

    import llm_api

    llm_api.load_env_file()
    if os.environ.get("SAFEHARNESS_ENABLE_SEMANTIC_JUDGE", "true").lower() not in {
        "1",
        "true",
        "yes",
        "on",
    }:
        return None

    try:
        model_name = llm_api.configured_model(role="judge")
        llm_api._endpoint_settings()
    except llm_api.LLMConfigurationError:
        return None
    return OpenAICompatibleJudge(llm_api.call_judge_model, model=model_name)


class SecureNocChat:
    """Keep one latest-SDK Guard and guarded LangGraph thread alive for chat."""

    def __init__(
        self,
        *,
        tenant_id: str = "fiberhome-demo",
        agent_id: str = "noc-operator-agent",
        thread_id: str = "noc-demo-thread",
        approve_irreversible: bool = False,
        model: Any | None = None,
        judge_provider: Any = _CONFIGURED_JUDGE,
        environment: NetworkOperationsEnvironment | None = None,
    ) -> None:
        self.tenant_id = tenant_id
        self.agent_id = agent_id
        self.thread_id = thread_id
        self.approve_irreversible = approve_irreversible
        self._provided_model = model
        self._provided_judge = judge_provider
        self.environment = environment or NetworkOperationsEnvironment()
        self.audit = InMemoryAuditSink()
        self.persistent_audit: SQLiteAuditSink | PostgreSQLAuditSink | None = None
        self.runtime: SafeHarnessRuntime | None = None
        self.guard: Guard | None = None
        self.graph = None
        self.judge_enabled = False
        self.tool_gateway_mode = "local"
        self._human_message_class = None
        self._last_trace = build_security_trace(())

    async def __aenter__(self) -> "SecureNocChat":
        if self.guard is not None:
            raise RuntimeError("SecureNocChat is already running")
        try:
            from langchain_core.messages import HumanMessage
            from langgraph.checkpoint.memory import InMemorySaver
        except ImportError as exc:
            raise LangGraphDependencyError(
                "Install the demo dependencies with: pip install -e '.[langgraph]'"
            ) from exc

        import llm_api

        llm_api.load_env_file()
        local_tools = build_noc_tools(self.environment)
        remote_gateway = self._configured_tool_gateway()
        if remote_gateway is not None:
            gateway = remote_gateway
            tools = self._remote_tools(local_tools, gateway, self._guard_context)
            self.tool_gateway_mode = "remote-read-only"
            receipt_issuer = build_enforcement_receipt_issuer_from_environment()
        else:
            tools = local_tools
            signing_key = os.environ.get("SAFEHARNESS_DEMO_SIGNING_KEY") or (
                "local-demo-only-signing-key-change-before-production"
            )
            gateway = SignedCapabilityGateway(
                signing_key,
                {self.agent_id: DEFAULT_NOC_GRANTS},
            )
            receipt_issuer = None
        catalog = StaticToolCatalog([tool.descriptor for tool in tools])
        audit_sink = self.audit
        audit_backend = os.environ.get("SAFEHARNESS_AUDIT_BACKEND", "sqlite").strip().lower()
        if audit_backend == "postgres":
            audit_dsn = os.environ.get("SAFEHARNESS_AUDIT_POSTGRES_DSN", "").strip()
            if not audit_dsn:
                raise ValueError(
                    "SAFEHARNESS_AUDIT_POSTGRES_DSN is required for PostgreSQL audit"
                )
            self.persistent_audit = PostgreSQLAuditSink(
                audit_dsn,
                table=os.environ.get(
                    "SAFEHARNESS_AUDIT_POSTGRES_TABLE",
                    "safeharness_audit_records",
                ).strip(),
            )
        elif audit_backend == "sqlite":
            audit_path = os.environ.get("SAFEHARNESS_AUDIT_DATABASE", "").strip()
            if audit_path:
                self.persistent_audit = SQLiteAuditSink(audit_path)
        else:
            raise ValueError("SAFEHARNESS_AUDIT_BACKEND must be 'sqlite' or 'postgres'")
        if self.persistent_audit is not None:
            audit_sink = CompositeAuditSink((self.audit, self.persistent_audit))
        judge = (
            build_judge_provider()
            if self._provided_judge is _CONFIGURED_JUDGE
            else self._provided_judge
        )
        self.judge_enabled = judge is not None
        self.runtime = SafeHarnessRuntime(
            services=RuntimeServices(
                tool_catalog=catalog,
                capability_authority=gateway,
                enforcement_receipt_issuer=receipt_issuer,
                judge_provider=judge,
                audit_sink=audit_sink,
                compensation_provider=(
                    None
                    if remote_gateway is not None
                    else NocCompensationProvider(self.environment)
                ),
                approval_broker=DemoApprovalBroker(
                    approve_irreversible=self.approve_irreversible
                ),
            )
        )
        self.guard = Guard(
            tenant_id=self.tenant_id,
            agent_id=self.agent_id,
            runtime=self.runtime,
            session_id=self.thread_id,
            framework="langgraph",
            metadata={"langgraph_thread_id": self.thread_id, "demo": True},
        )
        try:
            self.graph = self.guard.attach(
                LangGraphAgent(
                    model=self._provided_model or build_model(),
                    tools=tuple(tools),
                    system_prompt=SYSTEM_PROMPT,
                    capability_issuer=gateway,
                    checkpointer=InMemorySaver(),
                    checkpoint_integrity_key=secrets.token_bytes(32),
                )
            )
        except BaseException:
            await self.guard.aclose()
            self.guard = None
            raise
        self._human_message_class = HumanMessage
        return self

    @staticmethod
    def _configured_tool_gateway() -> RemoteToolGatewayClient | None:
        gateway_url = os.environ.get("SAFEHARNESS_TOOL_GATEWAY_URL", "").strip()
        if not gateway_url:
            return None
        gateway_api_key = os.environ.get("SAFEHARNESS_TOOL_GATEWAY_API_KEY", "")
        if not gateway_api_key:
            raise ValueError(
                "SAFEHARNESS_TOOL_GATEWAY_API_KEY is required when "
                "SAFEHARNESS_TOOL_GATEWAY_URL is configured"
            )
        tls_context = None
        if gateway_url.lower().startswith("https://"):
            client_ca = os.environ.get("SAFEHARNESS_TOOL_GATEWAY_CA", "").strip()
            client_certificate = os.environ.get(
                "SAFEHARNESS_TOOL_GATEWAY_CLIENT_CERT", ""
            ).strip()
            client_key = os.environ.get(
                "SAFEHARNESS_TOOL_GATEWAY_CLIENT_KEY", ""
            ).strip()
            if bool(client_certificate) != bool(client_key):
                raise ValueError(
                    "SAFEHARNESS_TOOL_GATEWAY_CLIENT_CERT and CLIENT_KEY must be "
                    "configured together"
                )
            tls_context = ssl.create_default_context(cafile=client_ca or None)
            tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
            if client_certificate:
                tls_context.load_cert_chain(client_certificate, client_key)
        return RemoteToolGatewayClient(
            gateway_url,
            gateway_api_key,
            tls_context=tls_context,
        )

    @staticmethod
    def _remote_tools(local_tools, gateway, context_provider):
        async def execute(invocation):
            return await gateway.execute(context_provider(), invocation)

        return [
            LangGraphTool(
                descriptor=tool.descriptor,
                resource_resolver=tool.resource_resolver,
                enforced_obligations=tool.enforced_obligations,
                invocation_executor=execute,
            )
            for tool in local_tools
            if tool.descriptor.reversibility is Reversibility.READ_ONLY
            and not tool.descriptor.side_effects
            and tool.descriptor.required_capabilities <= DEFAULT_NOC_READ_ONLY_GRANTS
        ]

    def _guard_context(self):
        if self.guard is None:
            raise RuntimeError("SafeHarness Guard is not attached")
        return self.guard.context

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        if self.guard is not None:
            await self.guard.aclose()
        self.guard = None
        self.graph = None

    async def ask(self, request: str) -> dict[str, Any]:
        """Run one chat turn through every enforced SafeHarness boundary."""

        if self.graph is None or self._human_message_class is None:
            raise RuntimeError("SecureNocChat must be used as an async context manager")
        if not isinstance(request, str) or not request.strip():
            raise ValueError("request must be a non-empty string")

        audit_before = len(self.audit.records)
        state = await self.graph.ainvoke(
            {"messages": [self._human_message_class(content=request)]},
            config={"configurable": {"thread_id": self.thread_id}},
        )
        self._last_trace = build_security_trace(self.audit.records[audit_before:])
        return {
            "final_response": state.get("final_response", ""),
            "blocked": bool(state.get("halted", False)),
            "security_reason": state.get("security_reason", ""),
            "audit_record_count": len(self.audit.records),
            "audit_record_delta": len(self.audit.records) - audit_before,
            "security_trace": self._last_trace,
            "tickets": dict(self.environment.tickets),
            "operations": list(self.environment.operation_log),
            "attachment_report": self.guard.report.to_dict() if self.guard else {},
        }

    def last_security_trace(self) -> dict[str, Any]:
        """Return the latest turn's redacted causal security trace."""

        return self._last_trace

    def audit_summary(self) -> dict[str, Any]:
        """Return content-free counters that show which security paths ran."""

        decisions = [
            record.decision
            for record in self.audit.records
            if record.record_type == "decision" and record.decision is not None
        ]
        return {
            "records": len(self.audit.records),
            "decisions": len(decisions),
            "blocked_decisions": sum(decision.blocked for decision in decisions),
            "enforcements": sum(
                record.record_type == "enforcement" for record in self.audit.records
            ),
            "events": dict(
                sorted(Counter(record.event.kind.value for record in self.audit.records).items())
            ),
        }


async def run_demo(
    request: str,
    *,
    tenant_id: str = "fiberhome-demo",
    agent_id: str = "noc-operator-agent",
    thread_id: str = "noc-demo-thread",
    approve_irreversible: bool = False,
) -> dict[str, Any]:
    """Run one secured NOC request and return the final state plus audit summary."""

    async with SecureNocChat(
        tenant_id=tenant_id,
        agent_id=agent_id,
        thread_id=thread_id,
        approve_irreversible=approve_irreversible,
    ) as chat:
        result = await chat.ask(request)
    result["audit_record_count"] = len(chat.audit.records)
    result["audit_record_delta"] = len(chat.audit.records)
    return result


def _read_multiline_request(
    reader: Callable[[str], str] = input,
) -> str | None:
    """Read one terminal request; a blank line or ``/send`` submits it."""

    lines: list[str] = []
    while True:
        try:
            line = reader("\n你> " if not lines else "... ")
        except EOFError:
            return "\n".join(lines) if lines else None

        command = line.strip().lower()
        if not lines and command in _CHAT_COMMANDS:
            return command
        if command == "/cancel":
            return ""
        if command == "/send":
            if lines:
                return "\n".join(lines)
            continue
        if not line.strip():
            if lines:
                return "\n".join(lines)
            continue
        lines.append(line)


async def run_interactive_chat(
    *,
    thread_id: str = "noc-demo-thread",
    approve_irreversible: bool = False,
    show_security_events: bool = False,
) -> None:
    """Run an interactive terminal chat backed by one secured Agent session."""

    async with SecureNocChat(
        thread_id=thread_id,
        approve_irreversible=approve_irreversible,
    ) as chat:
        approval_status = "已开启（仅限模拟环境）" if approve_irreversible else "默认拒绝"
        judge_status = "已启用" if chat.judge_enabled else "未启用"
        print("SafeHarness LangGraph NOC Agent 已启动。")
        print(f"会话: {thread_id}")
        print("安全链路: input_guard -> agent -> tools -> output_guard")
        print(f"工具执行: {chat.tool_gateway_mode}")
        print(f"语义 Judge: {judge_status}；不可逆操作审批: {approval_status}")
        print("支持多行输入：回车换行，空行或 /send 发送，/cancel 取消。")
        print("输入 /trace 查看上一轮安全轨迹，输入 /help 查看全部命令。")

        while True:
            try:
                request = await asyncio.to_thread(_read_multiline_request)
            except KeyboardInterrupt:
                print("\n会话已退出。")
                break
            if request is None:
                print("\n会话已退出。")
                break
            if not request.strip():
                continue
            command = request.strip().lower()
            if command in {"/exit", "/quit"}:
                print("会话已退出。")
                break
            if command == "/help":
                print(
                    "回车换行；空行或 /send 发送；/cancel 取消当前输入；"
                    "/status 查看会话状态；/audit 查看安全审计计数；"
                    "/trace 查看上一轮脱敏安全轨迹；/exit 退出。"
                )
                continue
            if command == "/status":
                print(
                    f"Agent={chat.agent_id}，thread={chat.thread_id}，"
                    f"工单={len(chat.environment.tickets)}，"
                    f"模拟操作={len(chat.environment.operation_log)}"
                )
                continue
            if command == "/audit":
                summary = chat.audit_summary()
                print(
                    f"审计记录={summary['records']}，决策={summary['decisions']}，"
                    f"阻断决策={summary['blocked_decisions']}，"
                    f"执行回执={summary['enforcements']}"
                )
                print(f"事件计数: {summary['events']}")
                continue
            if command == "/trace":
                print(format_security_trace(chat.last_security_trace()))
                continue

            try:
                result = await chat.ask(request)
            except Exception as exc:
                print(
                    f"Agent 调用失败（{type(exc).__name__}）。"
                    "请检查 config/llm.env 中的 URL、KEY、MODEL 和服务可用性。"
                )
                continue

            if result["blocked"]:
                print(f"SafeHarness> 已阻断（{result['security_reason']}）")
            print(f"Agent> {result['final_response']}")
            print(
                f"[安全审计] 本轮新增 {result['audit_record_delta']} 条，"
                f"累计 {result['audit_record_count']} 条。"
            )
            if show_security_events:
                print(format_security_trace(result["security_trace"]))


async def _main() -> None:
    parser = argparse.ArgumentParser(description="SafeHarness LangGraph NOC demo")
    parser.add_argument(
        "request",
        nargs="?",
        default=None,
    )
    parser.add_argument(
        "--chat",
        action="store_true",
        help="Start an interactive multi-turn terminal chat.",
    )
    parser.add_argument(
        "--show-security-events",
        action="store_true",
        help="Print the redacted causal security trace after each response.",
    )
    parser.add_argument("--thread-id", default="noc-demo-thread")
    parser.add_argument(
        "--approve-irreversible",
        action="store_true",
        help="Approve simulated availability-impacting operations for this run.",
    )
    args = parser.parse_args()

    if args.chat:
        if args.request:
            parser.error("request cannot be combined with --chat")
        await run_interactive_chat(
            thread_id=args.thread_id,
            approve_irreversible=args.approve_irreversible,
            show_security_events=args.show_security_events,
        )
        return

    result = await run_demo(
        args.request or DEFAULT_REQUEST,
        thread_id=args.thread_id,
        approve_irreversible=args.approve_irreversible,
    )
    print(result["final_response"])
    print(f"\nAudit records: {result['audit_record_count']}")
    print(f"Tickets: {len(result['tickets'])}")
    print(f"Operations: {len(result['operations'])}")
    if args.show_security_events:
        print()
        print(format_security_trace(result["security_trace"]))


if __name__ == "__main__":
    asyncio.run(_main())
