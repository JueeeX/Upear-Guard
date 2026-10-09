"""Simple, capability-reporting attachment facade for Agent frameworks."""

from __future__ import annotations

import asyncio
import functools
import inspect
import json
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from safeharness.adapters.base import (
    BASELINE_REQUIRED_CAPABILITIES,
    PRODUCTION_REQUIRED_CAPABILITIES,
    AdapterCapabilities,
    Coverage,
    DeploymentControls,
)
from safeharness.adapters.lifecycle import (
    ExplicitLifecycleAdapter,
    LifecycleOperationDenied,
    SubagentConstraints,
)
from safeharness.api.context import SessionContext
from safeharness.api.tools import ToolDescriptor
from safeharness.compat.legacy import LegacyPipelineFacade
from safeharness.runtime import SafeHarnessRuntime, SecuritySession


class AgentAttachmentError(RuntimeError):
    """Raised when an Agent cannot be attached without an unsafe blind spot."""


@dataclass(frozen=True, slots=True)
class AgentAttachment:
    """Result returned by a framework adapter to the public Guard facade."""

    agent: Any
    protected_entrypoints: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    capabilities: AdapterCapabilities | None = None
    required_capabilities: frozenset[str] | None = None


@dataclass(frozen=True, slots=True)
class AttachmentReport:
    """Machine-readable evidence for what one attachment actually protects."""

    adapter_name: str
    agent_type: str
    capabilities: AdapterCapabilities
    security_mode: str
    required_capabilities: frozenset[str] = PRODUCTION_REQUIRED_CAPABILITIES
    declared_deployment_controls: DeploymentControls = DeploymentControls()
    protected_entrypoints: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def missing_capabilities(self) -> frozenset[str]:
        return self.capabilities.missing_enforcement(self.required_capabilities)

    @property
    def attachment_contract_satisfied(self) -> bool:
        return not self.missing_capabilities

    @property
    def adapter_lifecycle_complete(self) -> bool:
        return self.capabilities.adapter_lifecycle_complete

    @property
    def production_ready(self) -> bool:
        # Caller declarations are useful inventory, but not deployment evidence.
        return False

    @property
    def deployment_controls(self) -> DeploymentControls:
        """Compatibility alias for caller-declared deployment controls."""

        return self.declared_deployment_controls

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter_name": self.adapter_name,
            "agent_type": self.agent_type,
            "security_mode": self.security_mode,
            "capabilities": self.capabilities.to_dict(),
            "required_capabilities": sorted(self.required_capabilities),
            "missing_capabilities": sorted(self.missing_capabilities),
            "attachment_contract_satisfied": self.attachment_contract_satisfied,
            "adapter_lifecycle_complete": self.adapter_lifecycle_complete,
            "declared_deployment_controls": self.declared_deployment_controls.to_dict(),
            "declared_deployment_controls_complete": (
                self.declared_deployment_controls.declared_complete
            ),
            "deployment_evidence_validated": False,
            "production_ready": self.production_ready,
            "production_readiness_reason": (
                "deployment controls are caller-declared and not independently validated"
            ),
            "protected_entrypoints": list(self.protected_entrypoints),
            "warnings": list(self.warnings),
        }


class AgentAdapter(Protocol):
    """Minimal protocol for adapters discoverable by :class:`Guard`."""

    name: str
    capabilities: AdapterCapabilities
    sync_session: bool

    def can_attach(self, agent: Any) -> bool:
        """Return whether this adapter understands the supplied Agent object."""

    def attach(self, agent: Any, guard: "Guard", **options: Any) -> AgentAttachment:
        """Return an Agent whose declared boundaries route through SafeHarness."""


GENERIC_AGENT_CAPABILITIES = AdapterCapabilities(
    input_filter=Coverage.ENFORCE,
    final_output_filter=Coverage.ENFORCE,
)


_CUSTOM_ADAPTERS: list[AgentAdapter] = []


def register_agent_adapter(adapter: AgentAdapter, *, replace: bool = False) -> None:
    """Register a custom adapter ahead of the built-in auto-detection fallbacks."""

    name = str(getattr(adapter, "name", "")).strip()
    if not name:
        raise ValueError("adapter name must not be empty")
    existing = next(
        (index for index, item in enumerate(_CUSTOM_ADAPTERS) if item.name == name),
        None,
    )
    if existing is not None:
        if not replace:
            raise ValueError(f"adapter {name!r} is already registered")
        _CUSTOM_ADAPTERS.pop(existing)
    _CUSTOM_ADAPTERS.insert(0, adapter)


def unregister_agent_adapter(name: str) -> bool:
    """Remove a custom adapter, primarily for plugin unload and isolated tests."""

    for index, adapter in enumerate(_CUSTOM_ADAPTERS):
        if adapter.name == name:
            _CUSTOM_ADAPTERS.pop(index)
            return True
    return False


class Guard:
    """Attach SafeHarness to a supported Agent through one public entry point.

    A Guard owns exactly one Agent security session. Framework-specific adapters
    may protect deeper boundaries; the generic fallback protects only calls made
    through the returned proxy and reports the remaining gaps.
    """

    def __init__(
        self,
        *,
        tenant_id: str = "local",
        agent_id: str | None = None,
        runtime: SafeHarnessRuntime | None = None,
        session_id: str | None = None,
        run_id: str | None = None,
        trace_id: str | None = None,
        framework: str = "auto",
        metadata: Mapping[str, Any] | None = None,
        adapters: Sequence[AgentAdapter] = (),
        security_mode: str = "production",
        deployment_controls: DeploymentControls | None = None,
    ) -> None:
        if not tenant_id:
            raise ValueError("tenant_id must not be empty")
        if agent_id == "":
            raise ValueError("agent_id must not be empty")
        if trace_id == "":
            raise ValueError("trace_id must not be empty")
        if not framework:
            raise ValueError("framework must not be empty")
        if security_mode not in {"production", "baseline"}:
            raise ValueError("security_mode must be 'production' or 'baseline'")
        if deployment_controls is not None and not isinstance(
            deployment_controls, DeploymentControls
        ):
            raise TypeError("deployment_controls must be DeploymentControls")
        self.runtime = runtime or SafeHarnessRuntime()
        self._tenant_id = tenant_id
        self._configured_agent_id = agent_id
        self._session_id = session_id
        self._run_id = run_id
        self._trace_id = trace_id
        self._framework = framework
        self._metadata = dict(metadata or {})
        self._adapters = tuple(adapters)
        self._security_mode = security_mode
        self._required_capabilities = (
            PRODUCTION_REQUIRED_CAPABILITIES
            if security_mode == "production"
            else BASELINE_REQUIRED_CAPABILITIES
        )
        self._deployment_controls = deployment_controls or DeploymentControls()
        self._context: SessionContext | None = None
        self._session: SecuritySession | None = None
        self._sync_bridge: LegacyPipelineFacade | None = None
        self._lifecycle: ExplicitLifecycleAdapter | None = None
        self._report: AttachmentReport | None = None
        self._attached_agent: Any = None
        self._closed = False

    @property
    def context(self) -> SessionContext:
        if self._context is None:
            raise RuntimeError("no Agent is attached")
        return self._context

    @property
    def session(self) -> SecuritySession:
        if self._session is None:
            raise RuntimeError("no Agent is attached")
        return self._session

    @property
    def lifecycle(self) -> ExplicitLifecycleAdapter:
        if self._lifecycle is None:
            raise RuntimeError("no Agent is attached")
        return self._lifecycle

    @property
    def report(self) -> AttachmentReport:
        if self._report is None:
            raise RuntimeError("no Agent is attached")
        return self._report

    def attach(
        self,
        agent: Any,
        *,
        adapter: str | AgentAdapter = "auto",
        **options: Any,
    ) -> Any:
        """Auto-detect an adapter and return the protected Agent object."""

        if self._closed:
            raise RuntimeError("Guard is closed")
        if self._session is not None:
            raise RuntimeError("one Guard instance can attach exactly one Agent")
        selected = self._select_adapter(agent, adapter)
        inferred_identity = self._configured_agent_id is None
        agent_id = self._configured_agent_id or _inferred_agent_id(agent)
        framework = selected.name if self._framework == "auto" else self._framework
        context_options: dict[str, Any] = {
            "tenant_id": self._tenant_id,
            "agent_id": agent_id,
            "framework": framework,
            "metadata": self._metadata,
        }
        if self._session_id is not None:
            context_options["session_id"] = self._session_id
        if self._run_id is not None:
            context_options["run_id"] = self._run_id
        if self._trace_id is not None:
            context_options["trace_id"] = self._trace_id
        self._context = SessionContext(**context_options)

        if selected.sync_session:
            self._sync_bridge = LegacyPipelineFacade(self.runtime, self._context)
            self._session = self._sync_bridge.session
        else:
            self._session = self.runtime.session(self._context)
        self._lifecycle = ExplicitLifecycleAdapter(
            self._session,
            adapter_name=selected.name,
        )

        try:
            attached = selected.attach(agent, self, **options)
            capabilities = attached.capabilities or selected.capabilities
            required_capabilities = attached.required_capabilities or self._required_capabilities
            self._require_adapter_coverage(
                selected.name,
                capabilities,
                required_capabilities,
            )
        except Exception:
            self._discard_failed_attachment()
            raise

        warnings = list(attached.warnings)
        if inferred_identity:
            warnings.append(
                "agent_id was inferred from the Python type; configure a stable identity "
                "when using shared gateways or production policy."
            )
        self._attached_agent = attached.agent
        self._report = AttachmentReport(
            adapter_name=selected.name,
            agent_type=_qualified_type(agent),
            capabilities=capabilities,
            security_mode=self._security_mode,
            required_capabilities=required_capabilities,
            declared_deployment_controls=self._deployment_controls,
            protected_entrypoints=attached.protected_entrypoints,
            warnings=tuple(warnings),
        )
        return attached.agent

    def run_sync(self, awaitable: Any) -> Any:
        """Run a SafeHarness awaitable on this Guard's dedicated sync loop."""

        if self._sync_bridge is None:
            close = getattr(awaitable, "close", None)
            if callable(close):
                close()
            raise RuntimeError("the selected adapter does not use a synchronous session")
        return self._sync_bridge.run_awaitable(awaitable)

    def close(self) -> None:
        """Close from synchronous code; async applications should use ``aclose``."""

        if self._closed:
            return
        if self._sync_bridge is not None:
            self._sync_bridge.close()
            self._closed = True
            return
        if self._session is None:
            self._closed = True
            return
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            asyncio.run(self._session.close())
            self._closed = True
            return
        raise RuntimeError("an event loop is running; use 'await guard.aclose()'")

    async def aclose(self) -> None:
        """Close the security session from asynchronous code."""

        if self._closed:
            return
        if self._sync_bridge is not None:
            await asyncio.to_thread(self._sync_bridge.close)
        elif self._session is not None:
            await self._session.close()
        self._closed = True

    def __enter__(self) -> "Guard":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    async def __aenter__(self) -> "Guard":
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        await self.aclose()

    def _select_adapter(
        self,
        agent: Any,
        requested: str | AgentAdapter,
    ) -> AgentAdapter:
        candidates = [*self._adapters, *_CUSTOM_ADAPTERS, *_builtin_adapters()]
        if not isinstance(requested, str):
            if not requested.can_attach(agent):
                raise AgentAttachmentError(
                    f"adapter {requested.name!r} does not support {_qualified_type(agent)}"
                )
            return requested
        if requested != "auto":
            selected = next((item for item in candidates if item.name == requested), None)
            if selected is None:
                names = ", ".join(dict.fromkeys(item.name for item in candidates))
                raise AgentAttachmentError(
                    f"unknown adapter {requested!r}; available adapters: {names}"
                )
            if not selected.can_attach(agent):
                raise AgentAttachmentError(
                    f"adapter {requested!r} does not support {_qualified_type(agent)}"
                )
            return selected
        for candidate in candidates:
            if candidate.name == "generic-agent":
                continue
            if candidate.can_attach(agent):
                return candidate
        generic = next(
            (item for item in candidates if item.name == "generic-agent"),
            None,
        )
        if generic is not None and generic.can_attach(agent):
            raise AgentAttachmentError(
                "no framework-specific AgentAdapter supports "
                f"{_qualified_type(agent)}; automatic generic fallback is disabled. "
                "For non-production migration tests only, explicitly request "
                "adapter='generic-agent' and BASELINE_REQUIRED_CAPABILITIES."
            )
        raise AgentAttachmentError(
            f"no callable Agent entrypoint found on {_qualified_type(agent)}"
        )

    def _require_adapter_coverage(
        self,
        adapter_name: str,
        capabilities: AdapterCapabilities,
        required_capabilities: frozenset[str],
    ) -> None:
        missing = capabilities.missing_enforcement(required_capabilities)
        if missing:
            raise AgentAttachmentError(
                f"adapter {adapter_name!r} does not satisfy {self._security_mode} "
                "security capabilities: " + ", ".join(sorted(missing))
            )

    def _discard_failed_attachment(self) -> None:
        if self._sync_bridge is not None:
            self._sync_bridge.close()
        self._context = None
        self._session = None
        self._sync_bridge = None
        self._lifecycle = None


class _GenericAgentAdapter:
    name = "generic-agent"
    capabilities = GENERIC_AGENT_CAPABILITIES
    sync_session = True

    def can_attach(self, agent: Any) -> bool:
        return bool(_entrypoints(agent))

    def attach(self, agent: Any, guard: Guard, **options: Any) -> AgentAttachment:
        requested = options.pop("entrypoints", None)
        if options:
            unknown = ", ".join(sorted(options))
            raise TypeError(f"unsupported generic attachment options: {unknown}")
        available = _entrypoints(agent)
        if requested is not None:
            requested_names = tuple(str(item) for item in requested)
            missing = [name for name in requested_names if name not in available]
            if missing:
                raise AgentAttachmentError(
                    f"generic Agent entrypoints are not callable: {', '.join(missing)}"
                )
            available = requested_names
        proxy = _GuardedAgentProxy(agent, guard, available)
        return AgentAttachment(
            proxy,
            protected_entrypoints=available,
            warnings=(
                "generic attachment protects only calls made through the returned proxy; "
                "the original Agent object remains unguarded.",
                "tool, framework-message, memory, handoff, checkpoint, and arbitrary-code "
                "boundaries require a framework-specific adapter.",
                "one Guard may serve sequential turns only; use a separate Guard for each "
                "concurrent Agent run.",
            ),
        )


class _OpenAIAgentsAdapter:
    name = "openai-agents"
    sync_session = False

    @property
    def capabilities(self) -> AdapterCapabilities:
        from safeharness.adapters.openai_agents import (
            OPENAI_AGENTS_ADAPTER_CAPABILITIES,
        )

        return OPENAI_AGENTS_ADAPTER_CAPABILITIES

    def can_attach(self, agent: Any) -> bool:
        module = type(agent).__module__
        return module == "agents.agent" or module.startswith("agents.agent.")

    def attach(self, agent: Any, guard: Guard, **options: Any) -> AgentAttachment:
        from safeharness.adapters.openai_agents import (
            GuardedOpenAIAgentsRunner,
            OpenAIAgentsLifecycleAdapter,
            OpenAIAgentsRunScope,
            openai_agents_capabilities,
            openai_agents_required_capabilities,
        )

        descriptors = options.pop("tool_descriptors", {})
        if not isinstance(descriptors, Mapping) or any(
            not isinstance(item, ToolDescriptor) for item in descriptors.values()
        ):
            raise TypeError("tool_descriptors must map tool names to ToolDescriptor values")
        subagent_constraints = options.pop("subagent_constraints", None)
        if subagent_constraints is not None and not isinstance(
            subagent_constraints, SubagentConstraints
        ):
            raise TypeError("subagent_constraints must be SubagentConstraints")
        raw_session = options.pop("session", None)
        max_turns = options.pop("max_turns", 10)
        supported = {
            "resource_resolvers",
            "enforced_obligations",
            "capability_token_providers",
            "handoff_agent_ids",
            "handoff_capabilities",
        }
        unknown = set(options) - supported
        if unknown:
            raise TypeError(
                "unsupported OpenAI Agents attachment options: " + ", ".join(sorted(unknown))
            )
        lifecycle = OpenAIAgentsLifecycleAdapter(
            guard.session,
            subagent_constraints=subagent_constraints,
        )
        scope = OpenAIAgentsRunScope(
            lifecycle,
            descriptors,
            resource_resolvers=options.get("resource_resolvers"),
            enforced_obligations=options.get("enforced_obligations"),
            capability_token_providers=options.get("capability_token_providers"),
            handoff_agent_ids=options.get("handoff_agent_ids"),
            handoff_capabilities=options.get("handoff_capabilities"),
            subagent_constraints=subagent_constraints,
        )
        protected_agent = scope.guard_root(agent)
        protected_session = (
            lifecycle.guard_session(raw_session) if raw_session is not None else None
        )
        protected = GuardedOpenAIAgentsRunner(
            protected_agent,
            session=protected_session,
            scope=scope,
            max_turns=max_turns,
        )
        capabilities = openai_agents_capabilities(agent, session=raw_session)
        required_capabilities = openai_agents_required_capabilities(
            agent,
            session=raw_session,
        )
        surfaces = ["input", "tool", "message", "output"]
        if raw_session is not None:
            surfaces.append("memory")
        if scope.has_handoffs(agent):
            surfaces.extend(("handoff", "subagent"))
        return AgentAttachment(
            protected,
            protected_entrypoints=("run",),
            warnings=(
                "use the returned runner; the original OpenAI Agent and Session remain unguarded.",
                "protected OpenAI Agents surfaces: " + ", ".join(surfaces),
                "streaming, RunState resume, server-managed Conversations, Responses "
                "compaction, MCP, Agent.as_tool nested runs, and caller-defined SDK "
                "callbacks are rejected; SDK traces exclude sensitive payloads.",
            ),
            capabilities=capabilities,
            required_capabilities=required_capabilities,
        )


class _LangGraphAdapter:
    name = "langgraph"
    sync_session = False

    @property
    def capabilities(self) -> AdapterCapabilities:
        from safeharness.adapters.langgraph import LANGGRAPH_ADAPTER_CAPABILITIES

        return LANGGRAPH_ADAPTER_CAPABILITIES

    def can_attach(self, agent: Any) -> bool:
        from safeharness.adapters.langgraph import LangGraphAgent

        return isinstance(agent, LangGraphAgent)

    def attach(self, agent: Any, guard: Guard, **options: Any) -> AgentAttachment:
        if options:
            raise TypeError(
                "unsupported LangGraph attachment options: " + ", ".join(sorted(options))
            )
        from safeharness.adapters.langgraph import (
            build_guarded_langgraph,
            langgraph_agent_capabilities,
            langgraph_agent_required_capabilities,
        )

        protected = build_guarded_langgraph(agent, guard.session)
        entrypoints = ("ainvoke", "astream", "invoke", "stream")
        protected_entrypoints = tuple(
            name for name in entrypoints if callable(getattr(protected, name, None))
        )
        surfaces = ["input", "model", "tool", "message", "output"]
        if agent.store is not None:
            surfaces.append("memory")
        if agent.subagents:
            surfaces.extend(("handoff", "subagent"))
        if agent.checkpointer is not None:
            surfaces.append("checkpoint")
        return AgentAttachment(
            protected,
            protected_entrypoints=protected_entrypoints,
            warnings=(
                "use the returned compiled graph; any separately compiled graph remains unguarded.",
                "protected LangGraph surfaces: " + ", ".join(surfaces),
            ),
            capabilities=langgraph_agent_capabilities(agent),
            required_capabilities=langgraph_agent_required_capabilities(agent),
        )


class _GuardedAgentProxy:
    __slots__ = ("_target", "_guard", "_entrypoints", "_wrappers", "_call_lock")

    def __init__(self, target: Any, guard: Guard, entrypoints: tuple[str, ...]) -> None:
        object.__setattr__(self, "_target", target)
        object.__setattr__(self, "_guard", guard)
        object.__setattr__(self, "_entrypoints", entrypoints)
        object.__setattr__(self, "_wrappers", {})
        # Mutable session state must not be shared by concurrent Agent runs.
        object.__setattr__(self, "_call_lock", threading.Lock())

    @property
    def safeharness_report(self) -> AttachmentReport:
        return self._guard.report

    @property
    def safeharness_original(self) -> Any:
        return self._target

    def __getattr__(self, name: str) -> Any:
        value = getattr(self._target, name)
        if name not in self._entrypoints or not callable(value):
            return value
        wrappers: dict[str, Any] = self._wrappers
        if name not in wrappers:
            wrappers[name] = _guard_callable(value, self._guard, self._call_lock)
        return wrappers[name]

    def __setattr__(self, name: str, value: Any) -> None:
        if name in _GuardedAgentProxy.__slots__:
            object.__setattr__(self, name, value)
            return
        setattr(self._target, name, value)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        if "__call__" not in self._entrypoints:
            raise TypeError(f"{_qualified_type(self._target)} is not callable")
        wrapper = self._wrappers.get("__call__")
        if wrapper is None:
            wrapper = _guard_callable(self._target, self._guard, self._call_lock)
            self._wrappers["__call__"] = wrapper
        return wrapper(*args, **kwargs)

    def __dir__(self) -> list[str]:
        return sorted(set(dir(type(self))) | set(dir(self._target)))

    def __repr__(self) -> str:
        return f"GuardedAgentProxy({self._target!r})"


def _guard_callable(fn: Any, guard: Guard, call_lock: threading.Lock) -> Any:
    if inspect.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            _acquire_call(call_lock)
            try:
                await asyncio.to_thread(_inspect_call_input, guard, args, kwargs)
                result = await fn(*args, **kwargs)
                return await asyncio.to_thread(_inspect_call_output, guard, result)
            finally:
                call_lock.release()

        return async_wrapper

    @functools.wraps(fn)
    def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
        _acquire_call(call_lock)
        try:
            _inspect_call_input(guard, args, kwargs)
            result = fn(*args, **kwargs)
            if inspect.isawaitable(result):
                close = getattr(result, "close", None)
                if callable(close):
                    close()
                raise AgentAttachmentError(
                    "a synchronous Agent entrypoint returned an awaitable; expose an "
                    "async entrypoint such as ainvoke so it can be guarded safely"
                )
            return _inspect_call_output(guard, result)
        finally:
            call_lock.release()

    return sync_wrapper


def _acquire_call(call_lock: threading.Lock) -> None:
    if not call_lock.acquire(blocking=False):
        raise AgentAttachmentError(
            "concurrent calls cannot share one generic Guard session; create one Guard "
            "per concurrent Agent run"
        )


def _inspect_call_input(guard: Guard, args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
    content, direct = _call_content(args, kwargs)
    guarded = guard.run_sync(guard.lifecycle.inspect_input(content))
    if guarded.blocked:
        raise LifecycleOperationDenied(guarded.decision)
    if str(guarded.value) != content:
        if direct:
            raise AgentAttachmentError(
                "the generic adapter cannot safely replace call arguments; "
                "use a framework-specific adapter for MODIFY policies"
            )
        raise AgentAttachmentError(
            "SafeHarness modified structured Agent input that the generic adapter "
            "cannot reconstruct safely"
        )


def _inspect_call_output(guard: Guard, result: Any) -> Any:
    content, replace = _output_content(result)
    guarded = guard.run_sync(guard.lifecycle.inspect_final_output(content))
    if guarded.blocked:
        raise LifecycleOperationDenied(guarded.decision)
    effective = str(guarded.value)
    if effective == content:
        return result
    if replace is None:
        raise AgentAttachmentError(
            "SafeHarness modified structured Agent output that the generic adapter "
            "cannot reconstruct safely"
        )
    return replace(effective)


def _call_content(args: tuple[Any, ...], kwargs: Mapping[str, Any]) -> tuple[str, bool]:
    if len(args) == 1 and isinstance(args[0], str) and not kwargs:
        return args[0], True
    for key in ("input", "message", "prompt", "query"):
        if not args and set(kwargs) == {key} and isinstance(kwargs[key], str):
            return str(kwargs[key]), True
    return _serialized_content({"args": args, "kwargs": kwargs}), False


def _output_content(result: Any) -> tuple[str, Any]:
    if isinstance(result, str):
        return result, lambda value: value
    if isinstance(result, dict):
        for key in ("output", "answer", "content", "message"):
            if isinstance(result.get(key), str):
                content = str(result[key])

                def replace(value: str, *, field: str = key) -> dict[str, Any]:
                    updated = dict(result)
                    updated[field] = value
                    return updated

                return content, replace
    for attr in ("content", "message"):
        value = getattr(result, attr, None)
        if isinstance(value, str):

            def replace_attr(replacement: str, *, field: str = attr) -> Any:
                try:
                    setattr(result, field, replacement)
                except Exception as exc:
                    raise AgentAttachmentError(
                        f"the generic adapter cannot replace output attribute {field!r}"
                    ) from exc
                return result

            return value, replace_attr
    return _serialized_content(result), None


def _serialized_content(value: Any) -> str:
    normalized = _strict_json_value(value, seen=set(), depth=0)
    serialized = json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    if len(serialized.encode("utf-8")) > 1_048_576:
        raise AgentAttachmentError("generic Agent input/output exceeds the 1 MiB inspection limit")
    return serialized


def _strict_json_value(value: Any, *, seen: set[int], depth: int) -> Any:
    if depth > 32:
        raise AgentAttachmentError("generic Agent input/output nesting exceeds 32 levels")
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    track = isinstance(value, (Mapping, Sequence)) and not isinstance(
        value, (str, bytes, bytearray)
    )
    if track:
        marker = id(value)
        if marker in seen:
            raise AgentAttachmentError("generic Agent input/output contains a reference cycle")
        seen.add(marker)
    try:
        if isinstance(value, Mapping):
            return {
                str(key): _strict_json_value(item, seen=seen, depth=depth + 1)
                for key, item in value.items()
            }
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return [_strict_json_value(item, seen=seen, depth=depth + 1) for item in value]
        for method_name in ("model_dump", "to_dict", "dict"):
            method = getattr(value, method_name, None)
            if callable(method):
                return _strict_json_value(method(), seen=seen, depth=depth + 1)
    finally:
        if track:
            seen.remove(id(value))
    raise AgentAttachmentError(
        "generic adapter cannot inspect value of type " + _qualified_type(value)
    )


def _entrypoints(agent: Any) -> tuple[str, ...]:
    names = []
    for name in ("ainvoke", "invoke", "arun", "run", "send_message"):
        if callable(getattr(agent, name, None)):
            names.append(name)
    if callable(agent):
        names.append("__call__")
    return tuple(names)


def _builtin_adapters() -> tuple[AgentAdapter, ...]:
    return (_LangGraphAdapter(), _OpenAIAgentsAdapter(), _GenericAgentAdapter())


def _qualified_type(value: Any) -> str:
    value_type = type(value)
    return f"{value_type.__module__}.{value_type.__qualname__}"


def _inferred_agent_id(agent: Any) -> str:
    value_type = type(agent)
    return f"{value_type.__module__}.{value_type.__qualname__}"[:128]


SafeHarnessGuard = Guard


__all__ = [
    "AgentAdapter",
    "AgentAttachment",
    "AgentAttachmentError",
    "AttachmentReport",
    "GENERIC_AGENT_CAPABILITIES",
    "Guard",
    "LifecycleOperationDenied",
    "SafeHarnessGuard",
    "register_agent_adapter",
    "unregister_agent_adapter",
]
