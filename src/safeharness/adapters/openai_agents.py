"""Optional OpenAI Agents SDK adapter built on its public lifecycle contracts."""

from __future__ import annotations

import copy
import dataclasses
import inspect
import json
import threading
from collections.abc import Callable, Mapping
from typing import Any

from safeharness.adapters.base import AdapterCapabilities, Coverage
from safeharness.adapters.generic import (
    CapabilityTokenProvider,
    ToolExecutionDenied,
    ToolExecutionFailed,
    execute_invocation,
)
from safeharness.adapters.lifecycle import (
    ExplicitLifecycleAdapter,
    LifecycleOperationDenied,
    SubagentConstraints,
)
from safeharness.api._mapping import json_safe
from safeharness.api.decisions import ObligationKind
from safeharness.api.events import EventKind
from safeharness.api.tools import ToolDescriptor, ToolInvocation
from safeharness.runtime import SecuritySession


OPENAI_AGENTS_ADAPTER_CAPABILITIES = AdapterCapabilities(
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


class OpenAIAgentsDependencyError(RuntimeError):
    """Raised when an SDK-specific factory is used without openai-agents."""


class OpenAIAgentsLifecycleAdapter:
    """Bind one OpenAI Agents SDK run to an isolated SafeHarness session."""

    adapter_name = "openai-agents"
    capabilities = OPENAI_AGENTS_ADAPTER_CAPABILITIES

    def __init__(
        self,
        session: SecuritySession,
        *,
        subagent_constraints: SubagentConstraints | None = None,
    ) -> None:
        self.session = session
        self._binding = object()
        self.lifecycle = ExplicitLifecycleAdapter(
            session,
            adapter_name=self.adapter_name,
            subagent_constraints=subagent_constraints,
        )

    def input_guardrail(self) -> Any:
        agents = _agents_module()

        async def guardrail(_context, _agent, agent_input):
            content = _content_text(agent_input)
            guarded = await self.lifecycle.inspect_input(content)
            return agents.GuardrailFunctionOutput(
                output_info={"reason_code": guarded.reason_code},
                tripwire_triggered=(guarded.blocked or guarded.value != content),
            )

        setattr(guardrail, "_safeharness_guarded", True)
        guarded = agents.InputGuardrail(
            guardrail_function=guardrail,
            name="safeharness_input",
            run_in_parallel=False,
        )
        setattr(guarded, "_safeharness_guarded", True)
        return guarded

    def output_guardrail(self) -> Any:
        agents = _agents_module()

        async def guardrail(_context, _agent, output):
            content = _content_text(output)
            guarded = await self.lifecycle.inspect_final_output(content)
            return agents.GuardrailFunctionOutput(
                output_info={"reason_code": guarded.reason_code},
                tripwire_triggered=(guarded.blocked or guarded.value != content),
            )

        setattr(guardrail, "_safeharness_guarded", True)
        guarded = agents.OutputGuardrail(
            guardrail_function=guardrail,
            name="safeharness_output",
        )
        setattr(guarded, "_safeharness_guarded", True)
        return guarded

    def agent_hooks(
        self,
        existing_hooks: Any | None = None,
        *,
        scope: "OpenAIAgentsRunScope | None" = None,
    ) -> Any:
        if existing_hooks is not None:
            raise ValueError(
                "caller-defined OpenAI Agent hooks are not supported because the SDK "
                "runs Agent and Run hooks concurrently"
            )
        agents = _agents_module()
        adapter = self

        class SafeHarnessAgentHooks(agents.AgentHooks):
            def __init__(self, run_scope: OpenAIAgentsRunScope | None = None) -> None:
                self._run_scope = run_scope
                self._safeharness_binding = adapter._binding

            async def on_start(self, context, agent) -> None:
                if self._run_scope is not None:
                    self._run_scope.assert_guarded_agent(agent)
                    self._run_scope.assert_run_config()
                return None

            async def on_end(self, context, agent, output) -> None:
                if self._run_scope is not None:
                    self._run_scope.assert_guarded_agent(agent)
                content = _content_text(output)
                guarded = await adapter.lifecycle.inspect_final_output(content)
                if guarded.blocked or guarded.value != content:
                    raise LifecycleOperationDenied(guarded.decision)

            async def on_handoff(self, context, agent, source) -> None:
                if self._run_scope is not None:
                    self._run_scope.assert_guarded_agent(agent)
                    self._run_scope.assert_guarded_agent(source)
                await adapter.session.evaluate(
                    EventKind.AGENT_HANDOFF,
                    {
                        "content": "",
                        "source_agent_id": _agent_name(source),
                        "target_agent_id": _agent_name(agent),
                        "adapter": adapter.adapter_name,
                    },
                )

            async def on_tool_start(self, context, agent, tool) -> None:
                if self._run_scope is not None:
                    self._run_scope.assert_guarded_agent(agent, active_tool=tool)
                    self._run_scope.assert_run_config(
                        getattr(context, "run_config", None)
                    )
                return None

            async def on_tool_end(self, context, agent, tool, result) -> None:
                if self._run_scope is not None:
                    self._run_scope.assert_guarded_agent(agent, active_tool=tool)
                    self._run_scope.assert_run_config(
                        getattr(context, "run_config", None)
                    )
                return None

            async def on_llm_start(
                self,
                context,
                agent,
                system_prompt,
                input_items,
            ) -> None:
                if self._run_scope is not None:
                    self._run_scope.assert_guarded_agent(agent)
                    self._run_scope.assert_run_config()
                content = _content_text(
                    {"system_prompt": system_prompt, "input_items": input_items}
                )
                guarded = await adapter.lifecycle.inspect_message(
                    content,
                    target_agent_id=_agent_name(agent),
                    attributes={"boundary": "llm_input"},
                )
                if guarded.blocked or guarded.value != content:
                    raise LifecycleOperationDenied(guarded.decision)

            async def on_llm_end(self, context, agent, response) -> None:
                if self._run_scope is not None:
                    self._run_scope.assert_guarded_agent(agent)
                await adapter.session.record_model_response(_content_text(response))

        return SafeHarnessAgentHooks(scope)

    def wrap_function_tool(
        self,
        tool: Any,
        descriptor: ToolDescriptor,
        *,
        resource_resolver: Callable[[Mapping[str, Any]], str | None] | None = None,
        enforced_obligations: frozenset[ObligationKind] = frozenset(),
        capability_token: str | None = None,
        capability_token_provider: CapabilityTokenProvider | None = None,
    ) -> Any:
        if getattr(tool, "_safeharness_guarded", False):
            if getattr(tool, "_safeharness_binding", None) is self._binding:
                return tool
            raise ValueError("OpenAI FunctionTool is already bound to another Guard")
        agents = _agents_module()
        if type(tool) is not agents.FunctionTool:
            raise TypeError("only OpenAI Agents SDK FunctionTool objects can be wrapped")
        tool_name = str(getattr(tool, "name", ""))
        if descriptor.name != tool_name:
            raise ValueError("trusted descriptor name must match the FunctionTool name")
        if callable(getattr(tool, "is_enabled", None)):
            raise ValueError("callable OpenAI FunctionTool is_enabled is not supported")
        if callable(getattr(tool, "needs_approval", None)):
            raise ValueError("callable OpenAI FunctionTool needs_approval is not supported")
        _reject_unsafe_function_tool_callbacks(tool)
        original = tool.on_invoke_tool

        async def guarded(context, raw_json: str) -> Any:
            arguments = _strict_json_object(raw_json)
            context_name = str(getattr(context, "tool_name", tool_name))
            if context_name != tool_name:
                raise ValueError("ToolContext name does not match the wrapped FunctionTool")
            resource = resource_resolver(arguments) if resource_resolver else None
            invocation = ToolInvocation(
                tool_name=tool_name,
                arguments=arguments,
                call_id=str(getattr(context, "tool_call_id", "")),
                tool_version=descriptor.version,
                resource=str(resource) if resource is not None else None,
            )

            async def native(effective: ToolInvocation) -> Any:
                effective_json = json.dumps(
                    json_safe(effective.arguments),
                    ensure_ascii=True,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                result = original(context, effective_json)
                return await result if inspect.isawaitable(result) else result

            outcome = await execute_invocation(
                self.session,
                invocation,
                native,
                adapter_name=self.adapter_name,
                enforced_obligations=enforced_obligations,
                capability_token=capability_token,
                capability_token_provider=capability_token_provider,
            )
            if outcome.blocked:
                raise ToolExecutionDenied(outcome.decision)
            if outcome.error is not None:
                raise ToolExecutionFailed(outcome)
            return outcome.result

        setattr(guarded, "_safeharness_guarded", True)
        wrapped = dataclasses.replace(
            tool,
            on_invoke_tool=guarded,
            tool_input_guardrails=None,
            tool_output_guardrails=None,
            custom_data_extractor=None,
            _failure_error_function=None,
            _use_default_failure_error_function=False,
        )
        setattr(wrapped, "_safeharness_guarded", True)
        setattr(wrapped, "_safeharness_binding", self._binding)
        setattr(wrapped, "_safeharness_descriptor", descriptor)
        return wrapped

    def wrap_handoff(
        self,
        handoff: Any,
        target_agent_id: str,
        *,
        requested_capabilities: frozenset[str] = frozenset(),
        target_guard: Callable[[Any, Any], Any] | None = None,
    ) -> Any:
        if getattr(handoff, "_safeharness_guarded", False):
            if getattr(handoff, "_safeharness_binding", None) is self._binding:
                return handoff
            raise ValueError("OpenAI Handoff is already bound to another Guard")
        agents = _agents_module()
        if type(handoff) is not agents.Handoff:
            raise TypeError("handoff must be an OpenAI Agents SDK Handoff object")
        target_ref = getattr(handoff, "_agent_ref", None)
        expected_target = target_ref() if callable(target_ref) else None
        if expected_target is None:
            raise ValueError("OpenAI Handoff target Agent cannot be resolved")
        _validate_sdk_handoff(handoff, expected_target)
        original = handoff.on_invoke_handoff

        async def guarded(context, raw_json: str | None = None) -> Any:
            task = raw_json or "{}"

            async def activate(child_context, effective_task):
                result = original(context, effective_task)
                target = await result if inspect.isawaitable(result) else result
                if target is not expected_target:
                    raise ValueError("OpenAI handoff returned an unexpected target Agent")
                if target_guard is not None:
                    guarded_target = target_guard(target, child_context)
                    guarded_target = (
                        await guarded_target
                        if inspect.isawaitable(guarded_target)
                        else guarded_target
                    )
                else:
                    guarded_target = copy.copy(target)
                setattr(guarded_target, "_safeharness_child_context", child_context)
                return guarded_target

            outcome = await self.lifecycle.create_subagent(
                target_agent_id,
                task,
                activate,
                requested_capabilities=requested_capabilities,
                attributes={"boundary": "openai_agents_handoff"},
            )
            return outcome.result

        setattr(guarded, "_safeharness_guarded", True)
        wrapped = dataclasses.replace(handoff, on_invoke_handoff=guarded)
        wrapped._agent_ref = target_ref
        setattr(wrapped, "_safeharness_guarded", True)
        setattr(wrapped, "_safeharness_binding", self._binding)
        setattr(wrapped, "_safeharness_target_agent_id", target_agent_id)
        setattr(wrapped, "_safeharness_expected_target", expected_target)
        return wrapped

    def guard_agent(
        self,
        agent: Any,
        tool_descriptors: Mapping[str, ToolDescriptor],
        *,
        resource_resolvers: Mapping[
            str, Callable[[Mapping[str, Any]], str | None]
        ] | None = None,
        enforced_obligations: Mapping[str, frozenset[ObligationKind]] | None = None,
        capability_token_providers: Mapping[str, CapabilityTokenProvider] | None = None,
        scope: "OpenAIAgentsRunScope | None" = None,
    ) -> Any:
        if getattr(agent, "_safeharness_guarded", False):
            if getattr(agent, "_safeharness_binding", None) is self._binding:
                return agent
            raise ValueError("OpenAI Agent is already bound to another Guard")
        if getattr(agent, "mcp_servers", None):
            raise ValueError(
                "MCP tools are dynamically loaded and cannot be claimed as FunctionTool-enforced"
            )
        if getattr(agent, "prompt", None) is not None:
            raise ValueError(
                "OpenAI Agent prompt templates are not supported because provider-side prompt "
                "content is not visible to SafeHarness hooks"
            )
        if callable(getattr(agent, "instructions", None)):
            raise ValueError(
                "callable OpenAI Agent instructions are not supported because they run before "
                "SafeHarness model-input inspection"
            )
        if callable(getattr(agent, "tool_use_behavior", None)):
            raise ValueError(
                "callable OpenAI Agent tool_use_behavior is not supported because it can create "
                "a final output outside SafeHarness ordering"
            )
        _reject_unsafe_model_settings(getattr(agent, "model_settings", None), "Agent")
        agents = _agents_module()
        resolvers = resource_resolvers or {}
        obligations = enforced_obligations or {}
        token_providers = capability_token_providers or {}
        guarded_tools = []
        for tool in list(getattr(agent, "tools", ())):
            if getattr(tool, "_is_agent_tool", False):
                raise ValueError("OpenAI Agent.as_tool nested runs are not supported")
            if not isinstance(tool, agents.FunctionTool):
                raise TypeError("only OpenAI Agents SDK FunctionTool objects are supported")
            tool_name = str(getattr(tool, "name", ""))
            descriptor = tool_descriptors.get(tool_name)
            if descriptor is None:
                raise ValueError(
                    f"trusted ToolDescriptor is required for OpenAI tool {tool_name!r}"
                )
            guarded_tools.append(
                self.wrap_function_tool(
                    tool,
                    descriptor,
                    resource_resolver=resolvers.get(tool_name),
                    enforced_obligations=obligations.get(tool_name, frozenset()),
                    capability_token_provider=token_providers.get(tool_name),
                )
            )
        handoffs = list(getattr(agent, "handoffs", ()))
        if any(not getattr(item, "_safeharness_guarded", False) for item in handoffs):
            raise ValueError(
                "all OpenAI Agent handoffs must be wrapped with wrap_handoff first"
            )
        if getattr(agent, "input_guardrails", None) or getattr(agent, "output_guardrails", None):
            raise ValueError(
                "caller-defined OpenAI Agent guardrails are not supported because the SDK "
                "does not guarantee SafeHarness-exclusive ordering"
            )
        input_guardrails = [self.input_guardrail()]
        output_guardrails = [self.output_guardrail()]
        guarded_agent = dataclasses.replace(
            agent,
            tools=guarded_tools,
            handoffs=handoffs,
            input_guardrails=input_guardrails,
            output_guardrails=output_guardrails,
            hooks=self.agent_hooks(getattr(agent, "hooks", None), scope=scope),
        )
        setattr(guarded_agent, "_safeharness_guarded", True)
        setattr(guarded_agent, "_safeharness_binding", self._binding)
        return guarded_agent

    def guard_session(self, session: Any) -> "GuardedOpenAIAgentsSession":
        if isinstance(session, GuardedOpenAIAgentsSession):
            raise ValueError("an OpenAI Session cannot be rebound from another Guard")
        if callable(getattr(session, "run_compaction", None)):
            raise ValueError(
                "OpenAI Responses compaction sessions are not supported because their "
                "internal history rewrite bypasses the Session protocol wrapper"
            )
        module = type(session).__module__
        if module.startswith("agents.memory.openai_conversations"):
            raise ValueError(
                "OpenAI Conversations sessions are server-managed state and are not "
                "supported by the in-process Session wrapper"
            )
        return GuardedOpenAIAgentsSession(self.lifecycle, session)


class GuardedOpenAIAgentsSession:
    """Implement the public Agents SDK Session protocol through guarded memory calls."""

    def __init__(self, lifecycle: ExplicitLifecycleAdapter, session: Any) -> None:
        required = ("get_items", "add_items", "pop_item", "clear_session")
        if any(not callable(getattr(session, name, None)) for name in required):
            raise TypeError("session does not implement the OpenAI Agents Session protocol")
        session_id = str(getattr(session, "session_id", ""))
        if not session_id:
            raise ValueError("OpenAI Agents Session requires a non-empty session_id")
        self.lifecycle = lifecycle
        self._session = session
        self.session_id = session_id
        self.session_settings = getattr(session, "session_settings", None)

    async def get_items(self, limit: int | None = None) -> list[Any]:
        outcome = await self.lifecycle.read_memory(
            f"{self.session_id}:items",
            lambda: self._session.get_items(limit=limit),
            namespace=("openai-agents", "session"),
        )
        items = json_safe(outcome.value)
        if not isinstance(items, list):
            raise TypeError("guarded OpenAI Session get_items must return a list")
        return items

    async def add_items(self, items: list[Any]) -> None:
        if not isinstance(items, list):
            raise TypeError("OpenAI Session items must be supplied as a list")

        async def writer(effective):
            values = json_safe(effective)
            if not isinstance(values, list):
                raise TypeError("policy-effective OpenAI Session items must be a list")
            await self._session.add_items(values)

        await self.lifecycle.write_memory(
            f"{self.session_id}:items",
            items,
            writer,
            namespace=("openai-agents", "session"),
        )

    async def pop_item(self) -> Any | None:
        write = await self.lifecycle.write_memory(
            f"{self.session_id}:pop",
            {"operation": "pop_item"},
            lambda _effective: self._session.pop_item(),
            namespace=("openai-agents", "session"),
        )
        if write.result is None:
            return None
        read = await self.lifecycle.read_memory(
            f"{self.session_id}:popped-item",
            lambda: write.result,
            namespace=("openai-agents", "session"),
        )
        return json_safe(read.value)

    async def clear_session(self) -> None:
        await self.lifecycle.write_memory(
            f"{self.session_id}:clear",
            {"operation": "clear_session"},
            lambda _effective: self._session.clear_session(),
            namespace=("openai-agents", "session"),
        )


class GuardedOpenAIAgentsRunner:
    """Run one protected Agent while fixing all stateful SDK boundaries."""

    def __init__(
        self,
        agent: Any,
        *,
        session: GuardedOpenAIAgentsSession | None,
        scope: "OpenAIAgentsRunScope",
        max_turns: int = 10,
    ) -> None:
        if isinstance(max_turns, bool) or not isinstance(max_turns, int):
            raise TypeError("OpenAI Agents max_turns must be an integer")
        if not 1 <= max_turns <= 100:
            raise ValueError("OpenAI Agents max_turns must be between 1 and 100")
        self._agent = agent
        self._session = session
        self._scope = scope
        self._max_turns = max_turns
        self._run_lock = threading.Lock()

    async def run(
        self,
        agent_input: Any,
        *,
        context: Any = None,
        hooks: Any = None,
        run_config: Any = None,
    ) -> Any:
        agents = _agents_module()
        if isinstance(agent_input, agents.RunState):
            raise ValueError(
                "OpenAI Agents RunState resume is not supported until snapshots are "
                "authenticated and rebound to the guarded Agent tree"
            )
        if hooks is not None:
            raise ValueError(
                "caller-defined OpenAI Run hooks are not supported because the SDK "
                "runs Run and SafeHarness Agent hooks concurrently"
            )
        if not self._run_lock.acquire(blocking=False):
            raise RuntimeError(
                "concurrent calls cannot share one OpenAI Agents Guard session; "
                "create one Guard per concurrent run"
            )
        error: str | None = None
        try:
            safe_run_config = self._scope.prepare_run_config(run_config)
            self._scope.assert_guarded_agent(self._agent)
            return await agents.Runner.run(
                self._agent,
                agent_input,
                context=context,
                max_turns=self._max_turns,
                run_config=safe_run_config,
                session=self._session,
            )
        except Exception as exc:
            error = type(exc).__name__
            raise
        finally:
            try:
                await self._scope.close_children(error=error)
            finally:
                self._scope.finish_run()
                self._run_lock.release()


class OpenAIAgentsRunScope:
    """Validate one Agent tree and own child security sessions created by handoffs."""

    def __init__(
        self,
        adapter: OpenAIAgentsLifecycleAdapter,
        tool_descriptors: Mapping[str, ToolDescriptor],
        *,
        resource_resolvers: Mapping[
            str, Callable[[Mapping[str, Any]], str | None]
        ] | None = None,
        enforced_obligations: Mapping[str, frozenset[ObligationKind]] | None = None,
        capability_token_providers: Mapping[str, CapabilityTokenProvider] | None = None,
        handoff_agent_ids: Mapping[str, str] | None = None,
        handoff_capabilities: Mapping[str, frozenset[str]] | None = None,
        subagent_constraints: SubagentConstraints | None = None,
    ) -> None:
        self.adapter = adapter
        self.tool_descriptors = dict(tool_descriptors)
        self.resource_resolvers = dict(resource_resolvers or {})
        self.enforced_obligations = dict(enforced_obligations or {})
        self.capability_token_providers = dict(capability_token_providers or {})
        self.handoff_agent_ids = dict(handoff_agent_ids or {})
        self.handoff_capabilities = dict(handoff_capabilities or {})
        self.subagent_constraints = subagent_constraints or SubagentConstraints()
        self._child_sessions: list[SecuritySession] = []
        self._guarded_agents: dict[int, tuple[Any, ...]] = {}
        self._active_run_config: Any = None

    def guard_root(self, agent: Any) -> Any:
        self._validate_tree(agent, seen=set(), depth=0)
        return self._guard_agent(agent, self.adapter)

    def prepare_run_config(self, run_config: Any) -> Any:
        agents = _agents_module()
        if run_config is None:
            safe = agents.RunConfig(trace_include_sensitive_data=False)
        elif not isinstance(run_config, agents.RunConfig):
            raise TypeError("run_config must be an OpenAI Agents RunConfig")
        else:
            _reject_unsafe_run_config_callbacks(run_config)
            _reject_unsafe_model_settings(
                getattr(run_config, "model_settings", None), "RunConfig"
            )
            safe = dataclasses.replace(run_config, trace_include_sensitive_data=False)
        setattr(safe, "_safeharness_guarded", True)
        self._active_run_config = safe
        return safe

    def assert_run_config(self, run_config: Any = None) -> None:
        expected = self._active_run_config
        if expected is None or not getattr(expected, "_safeharness_guarded", False):
            raise RuntimeError("OpenAI Agents RunConfig is not bound to SafeHarness")
        if run_config is not None and run_config is not expected:
            raise RuntimeError("OpenAI Agents RunConfig changed during the guarded run")
        if getattr(expected, "trace_include_sensitive_data", True):
            raise RuntimeError("OpenAI Agents tracing was mutated to include sensitive data")
        _reject_unsafe_run_config_callbacks(expected)
        _reject_unsafe_model_settings(getattr(expected, "model_settings", None), "RunConfig")

    def finish_run(self) -> None:
        self._active_run_config = None

    def _bind_guarded_agent(self, agent: Any) -> None:
        self._guarded_agents[id(agent)] = (
            agent,
            tuple(getattr(agent, "tools", ())),
            tuple(getattr(agent, "handoffs", ())),
            tuple(getattr(agent, "input_guardrails", ())),
            tuple(getattr(agent, "output_guardrails", ())),
            getattr(agent, "hooks", None),
        )

    def assert_guarded_agent(self, agent: Any, *, active_tool: Any | None = None) -> None:
        agents = _agents_module()
        if (
            not isinstance(agent, agents.Agent)
            or not getattr(agent, "_safeharness_guarded", False)
            or getattr(agent, "_safeharness_binding", None)
            is not getattr(getattr(agent, "hooks", None), "_safeharness_binding", None)
        ):
            raise RuntimeError("OpenAI Agent is not bound to SafeHarness")
        bound = self._guarded_agents.get(id(agent))
        actual = (
            agent,
            tuple(getattr(agent, "tools", ())),
            tuple(getattr(agent, "handoffs", ())),
            tuple(getattr(agent, "input_guardrails", ())),
            tuple(getattr(agent, "output_guardrails", ())),
            getattr(agent, "hooks", None),
        )
        if bound is None or any(
            len(expected) != len(current)
            or any(left is not right for left, right in zip(expected, current))
            if isinstance(expected, tuple)
            else expected is not current
            for expected, current in zip(bound, actual)
        ):
            raise RuntimeError("OpenAI Agent tree was mutated after Guard.attach()")
        if getattr(agent, "mcp_servers", None):
            raise RuntimeError("guarded OpenAI Agent gained an unsupported MCP server")
        if getattr(agent, "prompt", None) is not None or callable(
            getattr(agent, "instructions", None)
        ):
            raise RuntimeError("guarded OpenAI Agent gained an unsupported prompt callback")
        if callable(getattr(agent, "tool_use_behavior", None)):
            raise RuntimeError("guarded OpenAI Agent gained a tool_use_behavior callback")
        _reject_unsafe_model_settings(getattr(agent, "model_settings", None), "Agent")
        tools = list(getattr(agent, "tools", ()))
        if active_tool is not None and all(active_tool is not tool for tool in tools):
            raise RuntimeError("OpenAI Agent invoked a tool outside its guarded tool set")
        for tool in tools:
            if (
                not isinstance(tool, agents.FunctionTool)
                or not getattr(tool, "_safeharness_guarded", False)
                or getattr(tool, "_safeharness_binding", None)
                is not getattr(agent, "_safeharness_binding", None)
            ):
                raise RuntimeError("OpenAI Agent tool set was mutated after Guard.attach()")
            if not getattr(getattr(tool, "on_invoke_tool", None), "_safeharness_guarded", False):
                raise RuntimeError("OpenAI Agent tool wrapper was mutated after Guard.attach()")
            if callable(getattr(tool, "is_enabled", None)) or callable(
                getattr(tool, "needs_approval", None)
            ):
                raise RuntimeError("OpenAI Agent tool gained an unsupported callback")
            _reject_unsafe_function_tool_callbacks(tool)
        handoffs = list(getattr(agent, "handoffs", ()))
        for handoff in handoffs:
            target_ref = getattr(handoff, "_agent_ref", None)
            target = target_ref() if callable(target_ref) else None
            if (
                not isinstance(handoff, agents.Handoff)
                or not getattr(handoff, "_safeharness_guarded", False)
                or getattr(handoff, "_safeharness_binding", None)
                is not getattr(agent, "_safeharness_binding", None)
                or not getattr(
                    getattr(handoff, "on_invoke_handoff", None),
                    "_safeharness_guarded",
                    False,
                )
                or getattr(handoff, "input_filter", None) is not None
                or target is not getattr(handoff, "_safeharness_expected_target", None)
            ):
                raise RuntimeError("OpenAI Agent handoff set was mutated after Guard.attach()")
        input_guardrails = list(getattr(agent, "input_guardrails", ()))
        output_guardrails = list(getattr(agent, "output_guardrails", ()))
        if (
            len(input_guardrails) != 1
            or getattr(input_guardrails[0], "name", None) != "safeharness_input"
            or not getattr(input_guardrails[0], "_safeharness_guarded", False)
            or not getattr(
                getattr(input_guardrails[0], "guardrail_function", None),
                "_safeharness_guarded",
                False,
            )
            or len(output_guardrails) != 1
            or getattr(output_guardrails[0], "name", None) != "safeharness_output"
            or not getattr(output_guardrails[0], "_safeharness_guarded", False)
            or not getattr(
                getattr(output_guardrails[0], "guardrail_function", None),
                "_safeharness_guarded",
                False,
            )
        ):
            raise RuntimeError("OpenAI Agent guardrails were mutated after Guard.attach()")
        hooks = getattr(agent, "hooks", None)
        if getattr(hooks, "_run_scope", None) is not self:
            raise RuntimeError("OpenAI Agent hooks were mutated after Guard.attach()")

    async def close_children(self, *, error: str | None = None) -> None:
        sessions, self._child_sessions = self._child_sessions, []
        first_error: Exception | None = None
        for session in reversed(sessions):
            try:
                await session.close(error=error)
            except Exception as exc:
                first_error = first_error or exc
        if first_error is not None:
            raise first_error

    def has_handoffs(self, agent: Any) -> bool:
        return bool(getattr(agent, "handoffs", ()))

    def _guard_agent(
        self,
        agent: Any,
        adapter: OpenAIAgentsLifecycleAdapter,
    ) -> Any:
        guarded_handoffs = []
        for configured in list(getattr(agent, "handoffs", ())):
            handoff, expected_target = _openai_handoff(configured)
            target_name = _agent_name(expected_target)
            target_agent_id = self.handoff_agent_ids.get(target_name, target_name)
            requested = self.handoff_capabilities.get(target_name, frozenset())

            async def guard_target(
                actual_target,
                child_context,
                *,
                expected=expected_target,
                parent_adapter=adapter,
            ):
                if actual_target is not expected:
                    raise ValueError("OpenAI handoff returned an unexpected target Agent")
                child_session = parent_adapter.session.runtime.session(child_context)
                await child_session.start()
                child_adapter = OpenAIAgentsLifecycleAdapter(
                    child_session,
                    subagent_constraints=self.subagent_constraints,
                )
                try:
                    guarded = self._guard_agent(actual_target, child_adapter)
                except Exception:
                    await child_session.close(error="AgentAttachmentError")
                    raise
                self._child_sessions.append(child_session)
                return guarded

            guarded_handoffs.append(
                adapter.wrap_handoff(
                    handoff,
                    target_agent_id,
                    requested_capabilities=requested,
                    target_guard=guard_target,
                )
            )
        prepared = dataclasses.replace(agent, handoffs=guarded_handoffs)
        guarded = adapter.guard_agent(
            prepared,
            self.tool_descriptors,
            resource_resolvers=self.resource_resolvers,
            enforced_obligations=self.enforced_obligations,
            capability_token_providers=self.capability_token_providers,
            scope=self,
        )
        self._bind_guarded_agent(guarded)
        return guarded

    def _validate_tree(self, agent: Any, *, seen: set[int], depth: int) -> None:
        agents = _agents_module()
        if type(agent) is not agents.Agent:
            raise TypeError("guarded OpenAI handoffs must target Agent objects")
        if getattr(agent, "_safeharness_guarded", False):
            raise ValueError("an OpenAI Agent cannot be rebound from another Guard")
        marker = id(agent)
        if marker in seen:
            raise ValueError("cyclic OpenAI handoff trees are not supported")
        seen.add(marker)
        try:
            if getattr(agent, "mcp_servers", None):
                raise ValueError("OpenAI MCP servers are not supported by the guarded runner")
            if getattr(agent, "prompt", None) is not None:
                raise ValueError("OpenAI Agent prompt templates are not supported")
            if callable(getattr(agent, "instructions", None)):
                raise ValueError("callable OpenAI Agent instructions are not supported")
            if callable(getattr(agent, "tool_use_behavior", None)):
                raise ValueError("callable OpenAI Agent tool_use_behavior is not supported")
            _reject_unsafe_model_settings(getattr(agent, "model_settings", None), "Agent")
            if getattr(agent, "hooks", None) is not None:
                raise ValueError("caller-defined OpenAI Agent hooks are not supported")
            if getattr(agent, "input_guardrails", None) or getattr(
                agent, "output_guardrails", None
            ):
                raise ValueError("caller-defined OpenAI Agent guardrails are not supported")
            for tool in list(getattr(agent, "tools", ())):
                if getattr(tool, "_safeharness_guarded", False):
                    raise ValueError("an OpenAI FunctionTool cannot be rebound from another Guard")
                if getattr(tool, "_is_agent_tool", False):
                    raise ValueError(
                        "OpenAI Agent.as_tool nested runs are not supported by the guarded runner"
                    )
                tool_name = str(getattr(tool, "name", ""))
                if tool_name not in self.tool_descriptors:
                    raise ValueError(
                        f"trusted ToolDescriptor is required for OpenAI tool {tool_name!r}"
                    )
                if type(tool) is not agents.FunctionTool:
                    raise TypeError("only OpenAI Agents SDK FunctionTool objects are supported")
                if callable(getattr(tool, "is_enabled", None)):
                    raise ValueError("callable OpenAI FunctionTool is_enabled is not supported")
                if callable(getattr(tool, "needs_approval", None)):
                    raise ValueError("callable OpenAI FunctionTool needs_approval is not supported")
                _reject_unsafe_function_tool_callbacks(tool)
            for configured in list(getattr(agent, "handoffs", ())):
                if getattr(configured, "_safeharness_guarded", False):
                    raise ValueError("an OpenAI Handoff cannot be rebound from another Guard")
                handoff, target = _openai_handoff(configured)
                _validate_sdk_handoff(handoff, target)
                target_name = _agent_name(target)
                target_agent_id = self.handoff_agent_ids.get(target_name, target_name)
                requested = self.handoff_capabilities.get(target_name, frozenset())
                reason = self.subagent_constraints.denial_reason(
                    target_agent_id,
                    requested,
                    depth + 1,
                )
                if reason:
                    raise ValueError(
                        f"OpenAI handoff {target_name!r} violates sub-Agent constraints: {reason}"
                    )
                self._validate_tree(target, seen=seen, depth=depth + 1)
        finally:
            seen.remove(marker)


def openai_agents_capabilities(
    agent: Any,
    *,
    session: Any | None,
) -> AdapterCapabilities:
    """Report only surfaces fixed into this concrete guarded runner."""

    has_handoffs = bool(getattr(agent, "handoffs", ()))
    return AdapterCapabilities(
        input_filter=Coverage.ENFORCE,
        pre_tool_enforcement=Coverage.ENFORCE,
        tool_argument_rewrite=Coverage.ENFORCE,
        post_tool_filter=Coverage.ENFORCE,
        final_output_filter=Coverage.ENFORCE,
        message_interception=Coverage.ENFORCE,
        memory_interception=(Coverage.ENFORCE if session is not None else Coverage.NONE),
        handoff_tracking=(Coverage.ENFORCE if has_handoffs else Coverage.NONE),
        subagent_creation=(Coverage.ENFORCE if has_handoffs else Coverage.NONE),
    )


def openai_agents_required_capabilities(
    agent: Any,
    *,
    session: Any | None,
) -> frozenset[str]:
    """Return the contract for OpenAI SDK surfaces enabled by this attachment."""

    required = {
        "input_filter",
        "pre_tool_enforcement",
        "tool_argument_rewrite",
        "post_tool_filter",
        "final_output_filter",
        "message_interception",
    }
    if session is not None:
        required.add("memory_interception")
    if getattr(agent, "handoffs", ()):
        required.update({"handoff_tracking", "subagent_creation"})
    return frozenset(required)


def _agents_module() -> Any:
    try:
        import agents
    except ImportError as exc:
        raise OpenAIAgentsDependencyError(
            "OpenAI Agents integration requires: pip install 'safeharness[agents]'"
        ) from exc
    return agents


def _openai_handoff(configured: Any) -> tuple[Any, Any]:
    agents = _agents_module()
    if isinstance(configured, agents.Agent):
        return agents.handoff(configured), configured
    if type(configured) is not agents.Handoff:
        raise TypeError("OpenAI Agent handoffs must contain Agent or Handoff objects")
    target_ref = getattr(configured, "_agent_ref", None)
    target = target_ref() if callable(target_ref) else None
    if not isinstance(target, agents.Agent):
        raise ValueError("OpenAI Handoff target Agent cannot be resolved")
    if str(getattr(configured, "agent_name", "")) != _agent_name(target):
        raise ValueError("OpenAI Handoff target identity does not match its Agent")
    return configured, target


def _validate_sdk_handoff(handoff: Any, expected_target: Any) -> None:
    if getattr(handoff, "input_filter", None) is not None:
        raise ValueError("caller-defined OpenAI Handoff input_filter is not supported")
    if callable(getattr(handoff, "is_enabled", None)):
        raise ValueError("callable OpenAI Handoff is_enabled is not supported")
    invoke = getattr(handoff, "on_invoke_handoff", None)
    if (
        getattr(invoke, "__module__", "") != "agents.handoffs"
        or getattr(invoke, "__qualname__", "") != "handoff.<locals>._invoke_handoff"
    ):
        raise ValueError("OpenAI Handoff must use the agents.handoff() SDK factory")
    nonlocals = inspect.getclosurevars(invoke).nonlocals
    if nonlocals.get("agent") is not expected_target or nonlocals.get("on_handoff") is not None:
        raise ValueError("caller-defined OpenAI Handoff on_handoff callback is not supported")


def _reject_unsafe_function_tool_callbacks(tool: Any) -> None:
    callbacks = (
        "tool_input_guardrails",
        "tool_output_guardrails",
        "custom_data_extractor",
        "_failure_error_function",
        "timeout_error_function",
    )
    configured = [name for name in callbacks if getattr(tool, name, None)]
    if configured:
        raise ValueError(
            "caller-defined OpenAI FunctionTool callbacks are not supported: "
            + ", ".join(configured)
        )
    if getattr(tool, "timeout_behavior", "raise_exception") != "raise_exception" and getattr(
        tool, "timeout_seconds", None
    ) is not None:
        raise ValueError(
            "OpenAI FunctionTool timeout_behavior must be 'raise_exception' when a timeout is set"
        )


def _reject_unsafe_run_config_callbacks(run_config: Any) -> None:
    callbacks = (
        "handoff_input_filter",
        "handoff_history_mapper",
        "input_guardrails",
        "output_guardrails",
        "session_input_callback",
        "call_model_input_filter",
        "tool_error_formatter",
    )
    configured = [name for name in callbacks if getattr(run_config, name, None)]
    if getattr(run_config, "nest_handoff_history", False):
        configured.append("nest_handoff_history")
    if getattr(run_config, "sandbox", None) is not None:
        configured.append("sandbox")
    if getattr(run_config, "tool_not_found_behavior", "raise_error") != "raise_error":
        configured.append("tool_not_found_behavior")
    if configured:
        raise ValueError(
            "caller-defined OpenAI RunConfig callbacks or rewrite paths are not supported: "
            + ", ".join(configured)
        )


def _reject_unsafe_model_settings(settings: Any, owner: str) -> None:
    if settings is None:
        return
    fields = ("extra_body", "extra_args", "context_management")
    configured = [name for name in fields if getattr(settings, name, None)]
    if configured:
        raise ValueError(
            f"OpenAI {owner} ModelSettings provider rewrite paths are not supported: "
            + ", ".join(configured)
        )


def _strict_json_object(raw_json: str) -> dict[str, Any]:
    if not isinstance(raw_json, str):
        raise TypeError("FunctionTool arguments must be a JSON string")
    if len(raw_json.encode("utf-8")) > 1024 * 1024:
        raise ValueError("FunctionTool arguments exceed the 1 MiB adapter limit")

    def pairs(values):
        output = {}
        for key, value in values:
            if key in output:
                raise ValueError("FunctionTool arguments contain a duplicate key")
            output[key] = value
        return output

    try:
        payload = json.loads(
            raw_json,
            object_pairs_hook=pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"unsupported JSON constant: {value}")
            ),
        )
    except json.JSONDecodeError as exc:
        raise ValueError("FunctionTool arguments must contain valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("FunctionTool arguments must be a JSON object")
    return payload


def _content_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(
        _sdk_json_safe(value),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _sdk_json_safe(value: Any) -> Any:
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return _sdk_json_safe(model_dump(exclude_unset=True))
    if isinstance(value, Mapping):
        return {str(key): _sdk_json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sdk_json_safe(item) for item in value]
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    output = getattr(value, "output", None)
    if output is not None:
        return {"output": _sdk_json_safe(output)}
    return json_safe(value)


def _agent_name(agent: Any) -> str:
    return str(getattr(agent, "name", type(agent).__name__))
