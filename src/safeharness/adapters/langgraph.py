"""LangGraph lifecycle and tool-call integration.

Imports from LangChain are deliberately lazy so the SafeHarness core remains
usable without framework dependencies. Install ``safeharness[langgraph]`` to
construct and run a graph with these nodes.
"""

from __future__ import annotations

import asyncio
import copy
import hmac
import inspect
import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Annotated, Any, Protocol, TypedDict

from safeharness.adapters.base import AdapterCapabilities, Coverage
from safeharness.adapters.generic import execute_invocation, execute_tool
from safeharness.adapters.lifecycle import (
    ExplicitLifecycleAdapter,
    LifecycleOperationDenied,
    MemoryOperationOutcome,
    SubagentConstraints,
    SubagentCreationOutcome,
)
from safeharness.api._mapping import json_safe
from safeharness.api.decisions import ObligationKind
from safeharness.api.events import ContentSource, EventKind
from safeharness.api.tools import Reversibility, ToolDescriptor, ToolInvocation
from safeharness.runtime import SecuritySession


LANGGRAPH_ADAPTER_CAPABILITIES = AdapterCapabilities(
    input_filter=Coverage.ENFORCE,
    pre_tool_enforcement=Coverage.ENFORCE,
    tool_argument_rewrite=Coverage.ENFORCE,
    post_tool_filter=Coverage.ENFORCE,
    final_output_filter=Coverage.ENFORCE,
    message_interception=Coverage.ENFORCE,
    memory_interception=Coverage.ENFORCE,
    handoff_tracking=Coverage.ENFORCE,
    subagent_creation=Coverage.ENFORCE,
    state_checkpoint=Coverage.OBSERVE,
    checkpoint_rehydration=Coverage.ENFORCE,
)


class LangGraphDependencyError(RuntimeError):
    """Raised when a LangGraph adapter is used without its optional packages."""


class CheckpointIntegrityError(ValueError):
    """Raised when authenticated LangGraph checkpoint data fails verification."""


class CapabilityIssuerLike(Protocol):
    async def issue(
        self,
        context,
        descriptor: ToolDescriptor,
        invocation: ToolInvocation,
        *,
        expires_at=None,
    ):
        """Issue a capability grant for one invocation."""


ResourceResolver = Callable[[Mapping[str, Any]], str | None]


@dataclass(frozen=True, slots=True)
class LangGraphTool:
    """Bind trusted tool metadata to an executor exposed to LangGraph."""

    descriptor: ToolDescriptor
    executor: Callable[..., Any] | None = None
    resource_resolver: ResourceResolver | None = None
    enforced_obligations: frozenset[ObligationKind] = frozenset()
    invocation_executor: Callable[[ToolInvocation], Any] | None = None

    def __post_init__(self) -> None:
        if (self.executor is None) == (self.invocation_executor is None):
            raise ValueError(
                "provide exactly one keyword executor or invocation executor"
            )

    @classmethod
    def from_callable(
        cls,
        function: Callable[..., Any],
        *,
        required_capabilities: frozenset[str] | set[str],
        name: str | None = None,
        description: str | None = None,
        resource_parameter: str | None = None,
        version: str = "1",
        side_effects: frozenset[str] = frozenset(),
        data_classifications: frozenset[str] = frozenset(),
        reversibility: Reversibility = Reversibility.READ_ONLY,
        idempotent: bool = True,
        compensator: str | None = None,
        sandbox_required: bool = False,
        tags: frozenset[str] | set[str] = frozenset(),
    ) -> "LangGraphTool":
        """Build a tool from a typed callable without weakening its policy metadata.

        LangChain generates the JSON schema from the callable. Security metadata
        remains explicit because it cannot be inferred safely from Python types.
        """

        if not callable(function):
            raise TypeError("function must be callable")
        tool_name = name or getattr(function, "__name__", type(function).__name__)
        if not tool_name:
            raise ValueError("tool name must not be empty")
        tool_description = description or inspect.getdoc(function) or f"Call {tool_name}."
        is_async = inspect.iscoroutinefunction(function) or inspect.iscoroutinefunction(
            getattr(function, "__call__", None)
        )
        try:
            from langchain_core.tools import StructuredTool
        except ImportError as exc:
            raise LangGraphDependencyError(
                "LangGraphTool.from_callable requires optional LangChain dependencies. "
                "Install with: pip install -e '.[langgraph]'"
            ) from exc

        generated = StructuredTool.from_function(
            func=None if is_async else function,
            coroutine=function if is_async else None,
            name=tool_name,
            description=tool_description,
        )
        schema_model = generated.args_schema
        schema_builder = getattr(schema_model, "model_json_schema", None) or getattr(
            schema_model, "schema", None
        )
        if not callable(schema_builder):
            raise TypeError("LangChain tool schema does not expose a JSON schema method")
        input_schema = schema_builder()
        if not isinstance(input_schema, Mapping):
            raise TypeError("LangChain tool schema must be a JSON object")

        resolver: ResourceResolver | None = None
        if resource_parameter is not None:
            if not resource_parameter:
                raise ValueError("resource_parameter must not be empty")
            try:
                parameters = inspect.signature(function).parameters
            except (TypeError, ValueError) as exc:
                raise TypeError(
                    "resource_parameter requires an inspectable callable signature"
                ) from exc
            if resource_parameter not in parameters:
                raise ValueError(
                    f"resource_parameter {resource_parameter!r} is not a callable parameter"
                )

            def resolve_resource(
                arguments: Mapping[str, Any], parameter: str = resource_parameter
            ) -> str | None:
                value = arguments.get(parameter)
                return None if value is None else str(value)

            resolver = resolve_resource

        return cls(
            ToolDescriptor(
                name=tool_name,
                version=version,
                description=tool_description,
                input_schema=input_schema,
                required_capabilities=frozenset(required_capabilities),
                side_effects=frozenset(side_effects),
                data_classifications=frozenset(data_classifications),
                reversibility=reversibility,
                idempotent=idempotent,
                compensator=compensator,
                sandbox_required=sandbox_required,
                tags=frozenset(tags),
            ),
            executor=function,
            resource_resolver=resolver,
        )

    def resource_for(self, arguments: Mapping[str, Any]) -> str | None:
        if self.resource_resolver is None:
            return None
        resource = self.resource_resolver(arguments)
        return str(resource) if resource is not None else None

    def model_schema(self) -> dict[str, Any]:
        """Return an OpenAI-compatible function schema accepted by bind_tools."""

        return {
            "type": "function",
            "function": {
                "name": self.descriptor.name,
                "description": self.descriptor.description,
                "parameters": json_safe(self.descriptor.input_schema),
            },
        }


@dataclass(frozen=True, slots=True)
class LangGraphSubagent:
    """One explicitly routed sub-Agent in the fixed guarded graph topology."""

    name: str
    agent_id: str
    executor: Callable[[Mapping[str, Any], Any, str], Any]
    task_resolver: Callable[[Mapping[str, Any]], str] | None = None
    requested_capabilities: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not self.name or not self.agent_id:
            raise ValueError("LangGraph sub-Agent name and agent_id must not be empty")
        if not callable(self.executor):
            raise TypeError("LangGraph sub-Agent executor must be callable")
        if self.task_resolver is not None and not callable(self.task_resolver):
            raise TypeError("LangGraph sub-Agent task_resolver must be callable")


@dataclass(frozen=True, slots=True)
class LangGraphAgent:
    """Declarative input for ``Guard.attach`` to build a fixed secure graph."""

    model: Any
    tools: tuple[LangGraphTool, ...] = ()
    system_prompt: str = ""
    capability_issuer: CapabilityIssuerLike | None = None
    store: Any | None = None
    checkpointer: Any | None = None
    checkpoint_integrity_key: bytes | None = None
    subagents: tuple[LangGraphSubagent, ...] = ()
    subagent_router: Callable[[Mapping[str, Any]], Any] | None = None
    subagent_constraints: SubagentConstraints | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "tools", tuple(self.tools))
        object.__setattr__(self, "subagents", tuple(self.subagents))
        if not callable(getattr(self.model, "ainvoke", None)):
            raise TypeError("LangGraph Agent model must provide ainvoke")
        if any(not isinstance(tool, LangGraphTool) for tool in self.tools):
            raise TypeError("LangGraph Agent tools must be LangGraphTool values")
        if any(not isinstance(item, LangGraphSubagent) for item in self.subagents):
            raise TypeError("LangGraph Agent subagents must be LangGraphSubagent values")
        names = [item.name for item in self.subagents]
        if len(names) != len(set(names)) or any(name in {"agent", "end"} for name in names):
            raise ValueError("LangGraph sub-Agent names must be unique and not reserved")
        if bool(self.subagents) != (self.subagent_router is not None):
            raise ValueError("subagents and subagent_router must be configured together")
        if self.subagent_router is not None and not callable(self.subagent_router):
            raise TypeError("LangGraph subagent_router must be callable")
        if self.checkpointer is not None and self.checkpoint_integrity_key is None:
            raise ValueError(
                "checkpoint_integrity_key is required when a checkpointer is configured"
            )
        if self.checkpointer is None and self.checkpoint_integrity_key is not None:
            raise ValueError(
                "checkpoint_integrity_key requires a configured checkpointer"
            )


class HmacIntegrityCipher:
    """LangGraph CipherProtocol implementation providing integrity, not secrecy."""

    cipher_name = "hmac-sha256-v1"

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray, memoryview)):
            raise TypeError("checkpoint integrity key must be bytes")
        if len(key) < 32:
            raise ValueError("checkpoint integrity key must contain at least 32 bytes")
        self._key = bytes(key)

    def encrypt(self, plaintext: bytes) -> tuple[str, bytes]:
        tag = hmac.digest(self._key, plaintext, "sha256")
        return self.cipher_name, tag + plaintext

    def decrypt(self, ciphername: str, ciphertext: bytes) -> bytes:
        tag_size = hashlib.sha256().digest_size
        if ciphername != self.cipher_name or len(ciphertext) < tag_size:
            raise CheckpointIntegrityError("LangGraph checkpoint authentication failed")
        tag, plaintext = ciphertext[:tag_size], ciphertext[tag_size:]
        expected = hmac.digest(self._key, plaintext, "sha256")
        if not hmac.compare_digest(tag, expected):
            raise CheckpointIntegrityError("LangGraph checkpoint authentication failed")
        return plaintext


def authenticated_langgraph_checkpointer(checkpointer: Any, key: bytes) -> Any:
    """Clone a BaseCheckpointSaver with authenticated serialization enabled."""

    try:
        from langgraph.checkpoint.base import BaseCheckpointSaver
        from langgraph.checkpoint.serde.encrypted import EncryptedSerializer
    except ImportError as exc:
        raise LangGraphDependencyError(
            "Authenticated checkpoints require optional LangGraph dependencies. "
            "Install with: pip install -e '.[langgraph]'"
        ) from exc
    if isinstance(checkpointer, bool) or not isinstance(
        checkpointer, BaseCheckpointSaver
    ):
        raise TypeError("checkpointer must be a LangGraph BaseCheckpointSaver")
    serde = getattr(checkpointer, "serde", None)
    if isinstance(serde, EncryptedSerializer):
        raise ValueError(
            "checkpointer already has an encrypted serializer; configure one "
            "authenticated serializer instead of nesting serializers"
        )
    protected = copy.copy(checkpointer)
    protected.serde = _authenticated_serializer(
        EncryptedSerializer,
        HmacIntegrityCipher(key),
        serde,
    )
    return protected


def _authenticated_serializer(serializer_type, cipher, serde):
    class AuthenticatedSerializer(serializer_type):
        _safeharness_authenticated = True
        _envelope_type = "safeharness-checkpoint-v1"
        _envelope_magic = b"SHCP\x01"

        def dumps_typed(self, obj: Any) -> tuple[str, bytes]:
            value_type, value = self.serde.dumps_typed(obj)
            encoded_type = value_type.encode("utf-8")
            if len(encoded_type) > 65_535:
                raise ValueError("LangGraph checkpoint type name is too long")
            plaintext = (
                self._envelope_magic
                + len(encoded_type).to_bytes(2, "big")
                + encoded_type
                + value
            )
            ciphername, ciphertext = self.cipher.encrypt(plaintext)
            return f"{self._envelope_type}+{ciphername}", ciphertext

        def loads_typed(self, data: tuple[str, bytes]) -> Any:
            encrypted_type, ciphertext = data
            prefix = self._envelope_type + "+"
            if not encrypted_type.startswith(prefix):
                raise CheckpointIntegrityError(
                    "unsigned LangGraph checkpoint data is not accepted"
                )
            plaintext = self.cipher.decrypt(encrypted_type[len(prefix) :], ciphertext)
            if not plaintext.startswith(self._envelope_magic):
                raise CheckpointIntegrityError(
                    "LangGraph checkpoint envelope authentication failed"
                )
            offset = len(self._envelope_magic)
            type_size = int.from_bytes(plaintext[offset : offset + 2], "big")
            type_start = offset + 2
            type_end = type_start + type_size
            if type_end > len(plaintext):
                raise CheckpointIntegrityError("LangGraph checkpoint envelope is invalid")
            try:
                value_type = plaintext[type_start:type_end].decode("utf-8")
            except UnicodeDecodeError as exc:
                raise CheckpointIntegrityError(
                    "LangGraph checkpoint envelope is invalid"
                ) from exc
            return self.serde.loads_typed((value_type, plaintext[type_end:]))

    return AuthenticatedSerializer(cipher, serde)


def _restore_authenticated_serializer(checkpointer: Any) -> None:
    try:
        from langgraph.checkpoint.serde.encrypted import EncryptedSerializer
    except ImportError as exc:
        raise LangGraphDependencyError(
            "Authenticated checkpoints require optional LangGraph dependencies."
        ) from exc
    serializer = getattr(checkpointer, "serde", None)
    if getattr(serializer, "_safeharness_authenticated", False):
        return
    if not isinstance(serializer, EncryptedSerializer):
        raise RuntimeError("LangGraph removed the authenticated checkpoint serializer")
    checkpointer.serde = _authenticated_serializer(
        EncryptedSerializer,
        serializer.cipher,
        serializer.serde,
    )


@dataclass(frozen=True, slots=True)
class GuardedContent:
    content: str
    blocked: bool
    reason_code: str = ""
    reason: str = ""


class LangGraphLifecycleAdapter:
    """Map graph lifecycle boundaries onto one isolated security session."""

    adapter_name = "langgraph"
    capabilities = LANGGRAPH_ADAPTER_CAPABILITIES

    def __init__(
        self,
        session: SecuritySession,
        *,
        subagent_constraints: SubagentConstraints | None = None,
    ) -> None:
        self.session = session
        self.lifecycle = ExplicitLifecycleAdapter(
            session,
            adapter_name=self.adapter_name,
            subagent_constraints=subagent_constraints,
        )
        # The cache is process-local and keyed by message IDs. A new process or
        # restored session therefore re-inspects every checkpointed message,
        # while graph edges in one run do not duplicate semantic-judge calls.
        self._inspected_message_fingerprints: dict[str, str] = {}

    async def inspect_input(
        self,
        content: str,
        *,
        attributes: Mapping[str, Any] | None = None,
    ) -> GuardedContent:
        effective_attributes = dict(attributes or {})
        effective_attributes["adapter"] = self.adapter_name
        decision = await self.session.inspect_content(
            content,
            source=ContentSource.USER_INPUT,
            attributes=effective_attributes,
        )
        return _guarded_content(decision, content)

    async def inspect_external_content(
        self,
        content: Any,
        *,
        source: ContentSource,
        upstream_provenance: Mapping[str, Any] | None = None,
        attributes: Mapping[str, Any] | None = None,
    ) -> GuardedContent:
        """Inspect retrieval, memory, tool, or inter-agent content before use."""

        if source in {ContentSource.USER_INPUT, ContentSource.SYSTEM}:
            raise ValueError("use inspect_input for user content; system content is trusted")
        effective_attributes = dict(attributes or {})
        effective_attributes["adapter"] = self.adapter_name
        if upstream_provenance is not None:
            effective_attributes["upstream_provenance"] = dict(upstream_provenance)
        decision = await self.session.inspect_content(
            str(content),
            source=source,
            attributes=effective_attributes,
        )
        return _guarded_content(decision, str(content))

    async def inspect_message(self, message: Any) -> tuple[Any, GuardedContent | None]:
        """Inspect one LangGraph message before it is reused by the model.

        Human messages use the user-input policy. AI and tool messages are
        treated as untrusted external content, which closes the rehydration
        boundary when a checkpointer restores stale or tampered history.
        System messages remain outside this boundary because the adapter does
        not rewrite the application's trusted system prompt.
        """

        role = _message_role(message).lower()
        if role in {"system", "developer"}:
            return message, None
        source_by_role = {
            "human": ContentSource.USER_INPUT,
            "user": ContentSource.USER_INPUT,
            "ai": ContentSource.AGENT_OUTPUT,
            "assistant": ContentSource.AGENT_OUTPUT,
            "tool": ContentSource.TOOL_OUTPUT,
        }
        source = source_by_role.get(role, ContentSource.MEMORY)
        fingerprint = _message_fingerprint(message)
        identity = _message_identity(message)
        if (
            identity is not None
            and self._inspected_message_fingerprints.get(identity) == fingerprint
        ):
            return message, None

        content = _message_text(message)
        message_attributes = {
            "message_role": role,
            "tool_call_count": len(_tool_calls(message)),
        }
        if source is ContentSource.USER_INPUT:
            guarded = await self.inspect_input(content, attributes=message_attributes)
        else:
            guarded = await self.inspect_external_content(
                content,
                source=source,
                upstream_provenance=_message_provenance(message),
                attributes=message_attributes,
            )
        replacement_content = guarded.content
        if guarded.blocked:
            replacement_content = _blocked_message_content(role)
        if guarded.blocked and role in {"ai", "assistant"}:
            # A blocked assistant message must not retain executable tool-call
            # metadata in checkpointed history.
            replacement = _replace_ai_message(message, replacement_content)
        elif replacement_content != content:
            replacement = _replace_message_content(message, replacement_content)
        else:
            replacement = message
        if identity is not None:
            self._inspected_message_fingerprints[identity] = (
                fingerprint if replacement is message else _message_fingerprint(replacement)
            )
        return replacement, guarded

    def remember_message(self, message: Any) -> None:
        """Mark a message whose producing boundary already enforced it."""

        identity = _message_identity(message)
        if identity is not None:
            self._inspected_message_fingerprints[identity] = _message_fingerprint(
                message
            )

    async def before_model(self, messages: Sequence[Any]) -> None:
        await self.session.evaluate(
            EventKind.MODEL_REQUESTED,
            {
                "adapter": self.adapter_name,
                "messages": [_message_audit_view(message) for message in messages],
            },
        )

    async def after_model(self, message: Any) -> None:
        await self.session.record_model_response(_message_text(message))

    async def inspect_output(self, content: str) -> GuardedContent:
        decision = await self.session.inspect_final_output(content)
        return _guarded_content(decision, content)

    async def record_handoff(
        self,
        *,
        target_agent_id: str,
        content: str,
        attributes: Mapping[str, Any] | None = None,
    ) -> GuardedContent:
        """Record and inspect a future supervisor-to-subagent handoff boundary."""

        decision = await self.session.evaluate(
            EventKind.AGENT_HANDOFF,
            {
                "target_agent_id": target_agent_id,
                "content": content,
                "source": ContentSource.INTER_AGENT.value,
                "attributes": dict(attributes or {}),
            },
        )
        return _guarded_content(decision, content)

    async def inspect_inter_agent_message(
        self,
        content: str,
        *,
        target_agent_id: str = "",
        attributes: Mapping[str, Any] | None = None,
    ) -> GuardedContent:
        guarded = await self.lifecycle.inspect_message(
            content,
            target_agent_id=target_agent_id,
            attributes=attributes,
        )
        return _guarded_content(guarded.decision, content)

    async def read_memory(
        self,
        key: str,
        reader: Callable[[], Any],
        *,
        namespace: tuple[str, ...] = (),
    ) -> MemoryOperationOutcome:
        return await self.lifecycle.read_memory(
            key,
            reader,
            namespace=namespace,
        )

    async def write_memory(
        self,
        key: str,
        value: Any,
        writer: Callable[[Any], Any],
        *,
        namespace: tuple[str, ...] = (),
    ) -> MemoryOperationOutcome:
        return await self.lifecycle.write_memory(
            key,
            value,
            writer,
            namespace=namespace,
        )

    async def create_subagent(
        self,
        agent_id: str,
        task: str,
        factory: Callable[[Any, str], Any],
        *,
        requested_capabilities: frozenset[str] = frozenset(),
        attributes: Mapping[str, Any] | None = None,
    ) -> SubagentCreationOutcome:
        return await self.lifecycle.create_subagent(
            agent_id,
            task,
            factory,
            requested_capabilities=requested_capabilities,
            attributes=attributes,
        )


class GuardedLangGraphStore:
    """Guard LangGraph BaseStore memory operations without importing it eagerly."""

    def __init__(self, adapter: LangGraphLifecycleAdapter, store: Any) -> None:
        if store is None or not callable(getattr(store, "abatch", None)):
            raise TypeError("store must provide the LangGraph BaseStore abatch interface")
        self.adapter = adapter
        self._store = store

    @property
    def supports_ttl(self) -> bool:
        return bool(getattr(self._store, "supports_ttl", False))

    @property
    def ttl_config(self) -> Any:
        return getattr(self._store, "ttl_config", None)

    def batch(self, ops) -> list[Any]:
        return _run_store_sync(lambda: self.abatch(ops))

    async def abatch(self, ops) -> list[Any]:
        GetOp, PutOp, SearchOp, ListNamespacesOp = _langgraph_store_types()
        operations = list(ops)
        effective_operations = []
        for operation in operations:
            if isinstance(operation, PutOp):
                outcome = await self.adapter.write_memory(
                    operation.key,
                    operation.value,
                    lambda value: value,
                    namespace=operation.namespace,
                )
                effective_operations.append(
                    PutOp(
                        operation.namespace,
                        operation.key,
                        outcome.value,
                        index=operation.index,
                        ttl=operation.ttl,
                    )
                )
            elif isinstance(operation, (GetOp, SearchOp, ListNamespacesOp)):
                effective_operations.append(operation)
            else:
                raise TypeError(
                    f"unsupported LangGraph store operation: {type(operation).__name__}"
                )
        results = self._store.abatch(effective_operations)
        results = await results if inspect.isawaitable(results) else results
        if len(results) != len(effective_operations):
            raise RuntimeError("LangGraph store returned an invalid batch result count")
        guarded_results = []
        for operation, result in zip(effective_operations, results):
            if isinstance(operation, GetOp):
                guarded_results.append(await self._guard_item(result))
            elif isinstance(operation, SearchOp):
                guarded_results.append(
                    [await self._guard_item(item) for item in list(result or ())]
                )
            else:
                guarded_results.append(result)
        return guarded_results

    def get(self, namespace, key, **kwargs):
        return _run_store_sync(lambda: self.aget(namespace, key, **kwargs))

    async def aget(self, namespace, key, **kwargs):
        result = self._store.aget(namespace, key, **kwargs)
        result = await result if inspect.isawaitable(result) else result
        return await self._guard_item(result)

    def put(self, namespace, key, value, *args, **kwargs) -> None:
        _run_store_sync(lambda: self.aput(namespace, key, value, *args, **kwargs))

    async def aput(self, namespace, key, value, *args, **kwargs) -> None:
        async def writer(effective):
            result = self._store.aput(namespace, key, effective, *args, **kwargs)
            return await result if inspect.isawaitable(result) else result

        await self.adapter.write_memory(
            str(key),
            value,
            writer,
            namespace=tuple(namespace),
        )

    def delete(self, namespace, key) -> None:
        _run_store_sync(lambda: self.adelete(namespace, key))

    async def adelete(self, namespace, key) -> None:
        async def writer(_effective):
            result = self._store.adelete(namespace, key)
            return await result if inspect.isawaitable(result) else result

        await self.adapter.write_memory(
            str(key),
            None,
            writer,
            namespace=tuple(namespace),
        )

    def search(self, namespace_prefix, *args, **kwargs):
        return _run_store_sync(
            lambda: self.asearch(namespace_prefix, *args, **kwargs)
        )

    async def asearch(self, namespace_prefix, *args, **kwargs):
        result = self._store.asearch(namespace_prefix, *args, **kwargs)
        result = await result if inspect.isawaitable(result) else result
        return [await self._guard_item(item) for item in list(result or ())]

    def list_namespaces(self, *args, **kwargs):
        return self._store.list_namespaces(*args, **kwargs)

    async def alist_namespaces(self, *args, **kwargs):
        result = self._store.alist_namespaces(*args, **kwargs)
        return await result if inspect.isawaitable(result) else result

    async def _guard_item(self, item: Any) -> Any:
        if item is None or not hasattr(item, "value"):
            return item
        outcome = await self.adapter.read_memory(
            str(getattr(item, "key", "memory-item")),
            lambda: item.value,
            namespace=tuple(getattr(item, "namespace", ())),
        )
        if outcome.value == item.value:
            return item
        payload = item.dict()
        payload["value"] = outcome.value
        return type(item)(**payload)


class SafeHarnessSubagentNode:
    """Wrap one explicit LangGraph subgraph or Agent call as a guarded node."""

    def __init__(
        self,
        adapter: LangGraphLifecycleAdapter,
        agent_id: str,
        executor: Callable[[Mapping[str, Any], Any, str], Any],
        *,
        task_resolver: Callable[[Mapping[str, Any]], str] | None = None,
        requested_capabilities: frozenset[str] = frozenset(),
        blocked_message: str = "Sub-Agent request blocked by SafeHarness policy.",
    ) -> None:
        self.adapter = adapter
        self.agent_id = agent_id
        self.executor = executor
        self.task_resolver = task_resolver or _default_subagent_task
        self.requested_capabilities = requested_capabilities
        self.blocked_message = blocked_message

    async def __call__(self, state: Mapping[str, Any]) -> dict[str, Any]:
        task = self.task_resolver(state)
        if not isinstance(task, str) or not task:
            raise ValueError("sub-Agent task resolver must return non-empty text")

        async def factory(child_context, effective_task):
            result = self.executor(state, child_context, effective_task)
            result = await result if inspect.isawaitable(result) else result
            if not isinstance(result, Mapping):
                raise TypeError("sub-Agent nodes must return a LangGraph state mapping")
            return dict(result)

        try:
            outcome = await self.adapter.create_subagent(
                self.agent_id,
                task,
                factory,
                requested_capabilities=self.requested_capabilities,
            )
        except LifecycleOperationDenied as exc:
            return {
                "halted": True,
                "final_response": self.blocked_message,
                "security_reason": exc.reason_code,
            }
        return dict(outcome.result)


class SafeHarnessInputNode:
    """Inspect the latest user message before any model node receives it."""

    def __init__(
        self,
        adapter: LangGraphLifecycleAdapter,
        *,
        blocked_message: str = "Request blocked by SafeHarness input policy.",
        input_message_count_key: str = "input_message_count",
    ) -> None:
        self.adapter = adapter
        self.blocked_message = blocked_message
        self.input_message_count_key = input_message_count_key

    async def __call__(self, state: Mapping[str, Any]) -> dict[str, Any]:
        messages = list(state.get("messages", ()))
        if not messages:
            raise ValueError("LangGraph state must contain at least one message")
        already_inspected = int(state.get(self.input_message_count_key, 0) or 0)
        replacements: list[Any] = []
        blocked: GuardedContent | None = None
        safe_input = ""
        safe_input_message_id = ""
        for index, message in enumerate(messages):
            replacement, guarded = await self.adapter.inspect_message(message)
            if replacement is not message:
                replacements.append(replacement)
            if guarded is not None and guarded.blocked and blocked is None:
                blocked = guarded
            if index >= already_inspected and _message_role(message).lower() in {
                "human",
                "user",
            }:
                safe_input = (
                    ""
                    if guarded is not None and guarded.blocked
                    else _message_text(replacement)
                )
                safe_input_message_id = _message_identity(message) or ""

        update: dict[str, Any] = {
            self.input_message_count_key: len(messages),
            "halted": blocked is not None,
            "safe_input": safe_input,
            "safe_input_message_id": safe_input_message_id,
            "security_reason": blocked.reason_code if blocked else "",
        }
        if replacements:
            update["messages"] = replacements
        if blocked is not None:
            update["messages"] = [*replacements, _ai_message(self.blocked_message)]
            update["final_response"] = self.blocked_message
        return update


class SafeHarnessModelNode:
    """Record model lifecycle events around a LangChain-compatible chat model."""

    def __init__(
        self,
        adapter: LangGraphLifecycleAdapter,
        model: Any,
        *,
        system_prompt: str = "",
        blocked_message: str = "Message blocked by SafeHarness state policy.",
    ) -> None:
        self.adapter = adapter
        self.model = model
        self.system_prompt = system_prompt
        self.blocked_message = blocked_message

    async def __call__(self, state: Mapping[str, Any]) -> dict[str, Any]:
        if state.get("halted"):
            # A tool-boundary denial flows through the existing agent edge, so
            # stop before invoking the model and let route_after_model end it.
            return {"halted": True}
        messages = list(state.get("messages", ()))
        effective_messages: list[Any] = []
        replacements: list[Any] = []
        blocked: GuardedContent | None = None
        for message in messages:
            replacement, guarded = await self.adapter.inspect_message(message)
            effective_messages.append(replacement)
            if replacement is not message:
                replacements.append(replacement)
            if guarded is not None and guarded.blocked and blocked is None:
                blocked = guarded
        if blocked is not None:
            return {
                "messages": [*replacements, _ai_message(self.blocked_message)],
                "halted": True,
                "final_response": self.blocked_message,
                "security_reason": blocked.reason_code,
                "safe_input": "",
                "safe_input_message_id": "",
            }
        safe_input = state.get("safe_input")
        safe_input_message_id = str(state.get("safe_input_message_id") or "")
        if isinstance(safe_input, str) and safe_input and safe_input_message_id:
            for index, message in enumerate(effective_messages):
                if _message_identity(message) == safe_input_message_id:
                    effective_messages[index] = _replace_human_message(
                        message, safe_input
                    )
                    if effective_messages[index] is not message:
                        replacements.append(effective_messages[index])
                    break
        model_messages = (
            [_system_message(self.system_prompt), *effective_messages]
            if self.system_prompt
            else effective_messages
        )
        await self.adapter.before_model(model_messages)
        response = self.model.ainvoke(model_messages)
        response = await response if inspect.isawaitable(response) else response
        await self.adapter.after_model(response)
        self.adapter.remember_message(response)
        update: dict[str, Any] = {"messages": [response]}
        if replacements:
            update["messages"] = [*replacements, response]
        return update


class SafeHarnessToolNode:
    """Execute AI tool calls only through SafeHarness authorization and policies."""

    def __init__(
        self,
        adapter: LangGraphLifecycleAdapter,
        tools: Sequence[LangGraphTool],
        *,
        capability_issuer: CapabilityIssuerLike | None = None,
        blocked_message: str = "Tool request blocked by SafeHarness state policy.",
    ) -> None:
        self.adapter = adapter
        self._tools = {tool.descriptor.name: tool for tool in tools}
        if len(self._tools) != len(tools):
            raise ValueError("LangGraph tool names must be unique")
        self.capability_issuer = capability_issuer
        self.blocked_message = blocked_message

    @property
    def model_schemas(self) -> list[dict[str, Any]]:
        return [tool.model_schema() for tool in self._tools.values()]

    async def __call__(self, state: Mapping[str, Any]) -> dict[str, Any]:
        messages = list(state.get("messages", ()))
        if not messages:
            raise ValueError("LangGraph state must contain a model response")
        effective_messages: list[Any] = []
        replacements: list[Any] = []
        blocked: GuardedContent | None = None
        for message in messages:
            replacement, guarded = await self.adapter.inspect_message(message)
            effective_messages.append(replacement)
            if replacement is not message:
                replacements.append(replacement)
            if guarded is not None and guarded.blocked and blocked is None:
                blocked = guarded
        if blocked is not None:
            return {
                "messages": [*replacements, _ai_message(self.blocked_message)],
                "halted": True,
                "final_response": self.blocked_message,
                "security_reason": blocked.reason_code,
                "safe_input": "",
                "safe_input_message_id": "",
            }
        calls = _tool_calls(effective_messages[-1])
        results = [await self._execute_call(call) for call in calls]
        if replacements:
            return {"messages": [*replacements, *results]}
        return {"messages": results}

    async def _execute_call(self, call: Mapping[str, Any]) -> Any:
        tool_name = str(call.get("name", ""))
        call_id = str(call.get("id") or "")
        arguments = call.get("args", {})
        if not isinstance(arguments, Mapping):
            arguments = {"_invalid_arguments": json_safe(arguments)}
        tool = self._tools.get(tool_name)
        invocation = ToolInvocation(
            tool_name=tool_name or "__invalid_tool_name__",
            arguments=arguments,
            call_id=call_id,
            tool_version=tool.descriptor.version if tool else None,
            resource=tool.resource_for(arguments) if tool else None,
        )
        invocation = self.adapter.session.bind_invocation(invocation)

        if tool is None:
            outcome = await self.adapter.session.around_tool(
                invocation,
                lambda _: None,
                adapter=self.adapter.adapter_name,
            )
        else:
            token: str | None = None
            issuance_error: Exception | None = None
            if self.capability_issuer is not None:
                try:
                    grant = await self.capability_issuer.issue(
                        self.adapter.session.context,
                        tool.descriptor,
                        invocation,
                    )
                    token = grant.token
                except Exception as exc:
                    issuance_error = exc
            if issuance_error is not None:
                content = {
                    "status": "blocked",
                    "tool": tool_name,
                    "reason_code": "capability_issuance_failed",
                    "message": "The capability issuer denied or failed the request.",
                }
                await self.adapter.session.evaluate(
                    EventKind.TOOL_CALL_PROPOSED,
                    {
                        "tool_name": tool_name,
                        "tool_version": tool.descriptor.version,
                        "call_id": invocation.call_id,
                        "resource": invocation.resource,
                        "arguments": dict(invocation.arguments),
                        "capability_issuance_error": type(issuance_error).__name__,
                    },
                )
                tool_message = _tool_message(
                    json.dumps(content, ensure_ascii=False, sort_keys=True),
                    call_id or invocation.call_id,
                    tool_name,
                )
                self.adapter.remember_message(tool_message)
                return tool_message
            if tool.invocation_executor is not None:
                outcome = await execute_invocation(
                    self.adapter.session,
                    invocation,
                    tool.invocation_executor,
                    adapter_name=self.adapter.adapter_name,
                    enforced_obligations=tool.enforced_obligations,
                    capability_token=token,
                )
            else:
                outcome = await execute_tool(
                    self.adapter.session,
                    invocation,
                    tool.executor,
                    adapter_name=self.adapter.adapter_name,
                    enforced_obligations=tool.enforced_obligations,
                    capability_token=token,
                )

        if outcome.blocked:
            reason = outcome.decision.reasons[-1] if outcome.decision.reasons else None
            content = {
                "status": "blocked",
                "tool": tool_name,
                "reason_code": reason.code if reason else "policy_denied",
                "message": reason.message if reason else "Tool call denied.",
            }
        elif outcome.error is not None:
            content = {
                "status": "error",
                "tool": tool_name,
                "error_type": outcome.error,
                "external_effect_may_persist": outcome.external_effect_may_persist,
            }
        else:
            provenance = outcome.decision.effective_event.payload.get("provenance")
            content = {
                "status": "ok",
                "tool": tool_name,
                "result": json_safe(outcome.result),
                "provenance": json_safe(provenance) if provenance is not None else {},
            }
        tool_message = _tool_message(
            json.dumps(content, ensure_ascii=False, sort_keys=True),
            call_id or invocation.call_id,
            tool_name or invocation.tool_name,
        )
        self.adapter.remember_message(tool_message)
        return tool_message


class SafeHarnessOutputNode:
    """Inspect the final model response before returning it to the caller."""

    def __init__(
        self,
        adapter: LangGraphLifecycleAdapter,
        *,
        blocked_message: str = "Response blocked by SafeHarness output policy.",
    ) -> None:
        self.adapter = adapter
        self.blocked_message = blocked_message

    async def __call__(self, state: Mapping[str, Any]) -> dict[str, Any]:
        messages = list(state.get("messages", ()))
        if not messages:
            raise ValueError("LangGraph state must contain a final model response")
        final_message = messages[-1]
        original_content = _message_text(final_message)
        guarded = await self.adapter.inspect_output(original_content)
        if guarded.blocked:
            replacement = _replace_ai_message(
                final_message,
                "[Assistant response blocked and removed by SafeHarness.]",
            )
            self.adapter.remember_message(replacement)
            return {
                "messages": [replacement],
                "final_response": self.blocked_message,
                "halted": True,
                "security_reason": guarded.reason_code,
            }
        update = {
            "final_response": guarded.content,
            "halted": False,
            "security_reason": "",
        }
        if guarded.content != original_content:
            replacement = _replace_ai_message(final_message, guarded.content)
            self.adapter.remember_message(replacement)
            update["messages"] = [replacement]
        else:
            self.adapter.remember_message(final_message)
        return update


def build_guarded_langgraph(agent: LangGraphAgent, session: SecuritySession) -> Any:
    """Compile the fixed SafeHarness ReAct topology described by ``agent``."""

    try:
        from langgraph.graph import END, START, StateGraph
        from langgraph.graph.message import add_messages
    except ImportError as exc:
        raise LangGraphDependencyError(
            "LangGraph integration requires optional dependencies. "
            "Install with: pip install -e '.[langgraph]'"
        ) from exc

    GraphState = TypedDict(
        "GraphState",
        {
            "messages": Annotated[list[Any], add_messages],
            "halted": bool,
            "final_response": str,
            "security_reason": str,
            "input_message_count": int,
            "safe_input": str,
            "safe_input_message_id": str,
        },
        total=False,
    )

    adapter = LangGraphLifecycleAdapter(
        session,
        subagent_constraints=agent.subagent_constraints,
    )
    tool_node = SafeHarnessToolNode(
        adapter,
        agent.tools,
        capability_issuer=agent.capability_issuer,
    )
    model = agent.model
    if agent.tools:
        bind_tools = getattr(model, "bind_tools", None)
        if not callable(bind_tools):
            raise TypeError("LangGraph Agent model must provide bind_tools when tools exist")
        model = bind_tools(tool_node.model_schemas)

    graph = StateGraph(GraphState)
    graph.add_node("input_guard", SafeHarnessInputNode(adapter))
    graph.add_node(
        "agent",
        SafeHarnessModelNode(adapter, model, system_prompt=agent.system_prompt),
    )
    graph.add_node("tools", tool_node)
    graph.add_node("output_guard", SafeHarnessOutputNode(adapter))
    graph.add_edge(START, "input_guard")
    graph.add_conditional_edges(
        "input_guard", route_after_input, {"agent": "agent", "end": END}
    )

    route_map = {"tools": "tools", "output": "output_guard", "end": END}
    if agent.subagents:
        for item in agent.subagents:
            graph.add_node(
                item.name,
                SafeHarnessSubagentNode(
                    adapter,
                    item.agent_id,
                    item.executor,
                    task_resolver=item.task_resolver,
                    requested_capabilities=item.requested_capabilities,
                ),
            )
            graph.add_edge(item.name, "output_guard")
            route_map[item.name] = item.name
        graph.add_conditional_edges(
            "agent",
            _guarded_langgraph_route(agent.subagent_router),
            route_map,
        )
    else:
        graph.add_conditional_edges("agent", route_after_model, route_map)
    graph.add_edge("tools", "agent")
    graph.add_edge("output_guard", END)

    checkpointer = agent.checkpointer
    if checkpointer is not None:
        checkpointer = authenticated_langgraph_checkpointer(
            checkpointer,
            agent.checkpoint_integrity_key,
        )
    store = GuardedLangGraphStore(adapter, agent.store) if agent.store is not None else None
    compiled = graph.compile(checkpointer=checkpointer, store=store)
    if checkpointer is not None:
        _restore_authenticated_serializer(compiled.checkpointer)
    return compiled


def langgraph_agent_capabilities(agent: LangGraphAgent) -> AdapterCapabilities:
    """Report only surfaces wired into this concrete guarded graph."""

    return AdapterCapabilities(
        input_filter=Coverage.ENFORCE,
        pre_tool_enforcement=Coverage.ENFORCE,
        tool_argument_rewrite=Coverage.ENFORCE,
        post_tool_filter=Coverage.ENFORCE,
        final_output_filter=Coverage.ENFORCE,
        message_interception=Coverage.ENFORCE,
        memory_interception=(
            Coverage.ENFORCE if agent.store is not None else Coverage.NONE
        ),
        handoff_tracking=(Coverage.ENFORCE if agent.subagents else Coverage.NONE),
        subagent_creation=(Coverage.ENFORCE if agent.subagents else Coverage.NONE),
        state_checkpoint=(
            Coverage.ENFORCE if agent.checkpointer is not None else Coverage.NONE
        ),
        checkpoint_rehydration=(
            Coverage.ENFORCE if agent.checkpointer is not None else Coverage.NONE
        ),
    )


def langgraph_agent_required_capabilities(agent: LangGraphAgent) -> frozenset[str]:
    """Return the security contract for surfaces this spec actually enables."""

    required = {
        "input_filter",
        "pre_tool_enforcement",
        "tool_argument_rewrite",
        "post_tool_filter",
        "final_output_filter",
        "message_interception",
    }
    if agent.store is not None:
        required.add("memory_interception")
    if agent.subagents:
        required.update({"handoff_tracking", "subagent_creation"})
    if agent.checkpointer is not None:
        required.update({"state_checkpoint", "checkpoint_rehydration"})
    return frozenset(required)


def _guarded_langgraph_route(
    subagent_router: Callable[[Mapping[str, Any]], Any] | None,
) -> Callable[[Mapping[str, Any]], str]:
    assert subagent_router is not None

    def route(state: Mapping[str, Any]) -> str:
        default = route_after_model(state)
        if default != "output":
            return default
        selected = subagent_router(state)
        return "output" if selected in {None, "", "output"} else str(selected)

    return route


def route_after_input(state: Mapping[str, Any]) -> str:
    return "end" if state.get("halted") else "agent"


def route_after_model(state: Mapping[str, Any]) -> str:
    if state.get("halted"):
        return "end"
    messages = list(state.get("messages", ()))
    return "tools" if messages and _tool_calls(messages[-1]) else "output"


def _default_subagent_task(state: Mapping[str, Any]) -> str:
    safe_input = state.get("safe_input")
    if isinstance(safe_input, str) and safe_input:
        return safe_input
    messages = list(state.get("messages", ()))
    return _message_text(messages[-1]) if messages else ""


def _langgraph_store_types():
    try:
        from langgraph.store.base import GetOp, ListNamespacesOp, PutOp, SearchOp
    except ImportError as exc:
        raise LangGraphDependencyError(
            "LangGraph memory integration requires optional dependencies. "
            "Install with: pip install -e '.[langgraph]'"
        ) from exc
    return GetOp, PutOp, SearchOp, ListNamespacesOp


def _run_store_sync(factory: Callable[[], Any]) -> Any:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(factory())
    raise RuntimeError(
        "synchronous LangGraph store methods cannot run inside an active event loop; "
        "use the corresponding async method"
    )


def _guarded_content(decision, original: str) -> GuardedContent:
    reason = decision.reasons[-1] if decision.reasons else None
    content = decision.effective_event.payload.get("content", original)
    return GuardedContent(
        content=str(content),
        blocked=decision.blocked,
        reason_code=reason.code if reason else "",
        reason=reason.message if reason else "",
    )


def _message_text(message: Any) -> str:
    content = message.get("content", "") if isinstance(message, Mapping) else getattr(
        message, "content", ""
    )
    if isinstance(content, str):
        return content
    if isinstance(content, Sequence) and not isinstance(content, (bytes, bytearray)):
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, Mapping) and isinstance(block.get("text"), str):
                parts.append(block["text"])
        return "\n".join(parts)
    return str(content)


def _message_identity(message: Any) -> str | None:
    value = (
        message.get("id")
        if isinstance(message, Mapping)
        else getattr(message, "id", None)
    )
    return str(value) if value else None


def _message_fingerprint(message: Any) -> str:
    payload = {
        "role": _message_role(message),
        "content": _message_text(message),
        "tool_calls": _tool_calls(message),
    }
    canonical = json.dumps(
        json_safe(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _message_provenance(message: Any) -> Mapping[str, Any] | None:
    metadata = (
        message.get("response_metadata")
        if isinstance(message, Mapping)
        else getattr(message, "response_metadata", None)
    )
    return metadata if isinstance(metadata, Mapping) else None


def _blocked_message_content(role: str) -> str:
    if role in {"human", "user"}:
        return "[User message blocked and removed by SafeHarness.]"
    if role in {"ai", "assistant"}:
        return "[Assistant message blocked and removed by SafeHarness.]"
    if role == "tool":
        return "[Tool message blocked and removed by SafeHarness.]"
    return "[Message blocked and removed by SafeHarness.]"


def _tool_calls(message: Any) -> list[Mapping[str, Any]]:
    calls = message.get("tool_calls", ()) if isinstance(message, Mapping) else getattr(
        message, "tool_calls", ()
    )
    return [call for call in calls or () if isinstance(call, Mapping)]


def _message_audit_view(message: Any) -> dict[str, Any]:
    message_type = getattr(message, "type", type(message).__name__)
    return {
        "type": str(message_type),
        "content": _message_text(message),
        "tool_call_count": len(_tool_calls(message)),
    }


def _message_role(message: Any) -> str:
    if isinstance(message, Mapping):
        return str(message.get("role") or message.get("type") or "")
    return str(getattr(message, "type", getattr(message, "role", "")))


def _message_class(name: str):
    try:
        from langchain_core import messages
    except ImportError as exc:
        raise LangGraphDependencyError(
            "LangGraph integration requires optional dependencies. "
            "Install with: pip install -e '.[langgraph]'"
        ) from exc
    return getattr(messages, name)


def _human_message(content: str) -> Any:
    return _message_class("HumanMessage")(content=content)


def _replace_human_message(message: Any, content: str) -> Any:
    """Replace a checkpointed human message while preserving its reducer ID."""

    return _replace_message(message, content, "HumanMessage")


def _replace_ai_message(message: Any, content: str) -> Any:
    """Replace a checkpointed AI message while preserving its reducer ID."""

    return _replace_message(message, content, "AIMessage")


def _replace_message_content(message: Any, content: str) -> Any:
    """Replace content while retaining reducer identity and tool metadata."""

    role = _message_role(message).lower()
    if role in {"human", "user"}:
        return _replace_human_message(message, content)
    if role in {"ai", "assistant"}:
        message_id = _message_identity(message)
        kwargs: dict[str, Any] = {"content": content}
        if message_id:
            kwargs["id"] = message_id
        calls = _tool_calls(message)
        if calls:
            kwargs["tool_calls"] = calls
        try:
            return _message_class("AIMessage")(**kwargs)
        except TypeError:
            return _replace_ai_message(message, content)
    if role == "tool":
        message_id = _message_identity(message)
        tool_call_id = (
            message.get("tool_call_id")
            if isinstance(message, Mapping)
            else getattr(message, "tool_call_id", "")
        )
        name = (
            message.get("name")
            if isinstance(message, Mapping)
            else getattr(message, "name", None)
        )
        kwargs = {"content": content, "tool_call_id": str(tool_call_id or "")}
        if name:
            kwargs["name"] = str(name)
        if message_id:
            kwargs["id"] = message_id
        try:
            return _message_class("ToolMessage")(**kwargs)
        except TypeError:
            return _tool_message(content, str(tool_call_id or ""), str(name or ""))
    return message


def _replace_message(message: Any, content: str, message_class_name: str) -> Any:
    message_id = (
        message.get("id")
        if isinstance(message, Mapping)
        else getattr(message, "id", None)
    )
    message_class = _message_class(message_class_name)
    if message_id:
        try:
            return message_class(content=content, id=message_id)
        except TypeError:
            pass
    return message_class(content=content)


def _ai_message(content: str) -> Any:
    return _message_class("AIMessage")(content=content)


def _system_message(content: str) -> Any:
    return _message_class("SystemMessage")(content=content)


def _tool_message(content: str, tool_call_id: str, name: str) -> Any:
    return _message_class("ToolMessage")(
        content=content,
        tool_call_id=tool_call_id,
        name=name,
    )
