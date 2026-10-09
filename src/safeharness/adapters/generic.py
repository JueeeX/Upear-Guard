"""Generic Python callable adapter used as the first conformance target."""

from __future__ import annotations

from functools import wraps
import inspect
from typing import Any, Awaitable, Callable

from safeharness.adapters.base import AdapterCapabilities, Coverage
from safeharness.api.decisions import Decision, ObligationKind
from safeharness.api.tools import ToolExecutionOutcome, ToolInvocation
from safeharness.runtime import SecuritySession


class ToolExecutionDenied(RuntimeError):
    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        reason = decision.reasons[-1].message if decision.reasons else "Tool call denied"
        super().__init__(reason)


class ToolExecutionFailed(RuntimeError):
    def __init__(self, outcome: ToolExecutionOutcome) -> None:
        self.outcome = outcome
        super().__init__(f"Tool execution failed: {outcome.error or 'unknown error'}")


GENERIC_TOOL_CAPABILITIES = AdapterCapabilities(
    pre_tool_enforcement=Coverage.ENFORCE,
    tool_argument_rewrite=Coverage.ENFORCE,
    post_tool_filter=Coverage.ENFORCE,
)

CapabilityTokenProvider = Callable[[ToolInvocation], str | Awaitable[str]]
InvocationExecutor = Callable[[ToolInvocation], Any | Awaitable[Any]]


async def execute_tool(
    session: SecuritySession,
    invocation: ToolInvocation,
    executor: Callable[..., Any],
    *,
    adapter_name: str = "generic-python",
    enforced_obligations: frozenset[ObligationKind] = frozenset(),
    capability_token: str | None = None,
    capability_token_provider: CapabilityTokenProvider | None = None,
) -> ToolExecutionOutcome:
    """Execute a keyword-argument callable through the guarded lifecycle."""

    def native(effective: ToolInvocation) -> Any:
        return executor(**dict(effective.arguments))

    return await execute_invocation(
        session,
        invocation,
        native,
        adapter_name=adapter_name,
        enforced_obligations=enforced_obligations,
        capability_token=capability_token,
        capability_token_provider=capability_token_provider,
    )


async def execute_invocation(
    session: SecuritySession,
    invocation: ToolInvocation,
    executor: InvocationExecutor,
    *,
    adapter_name: str = "generic-python",
    enforced_obligations: frozenset[ObligationKind] = frozenset(),
    capability_token: str | None = None,
    capability_token_provider: CapabilityTokenProvider | None = None,
) -> ToolExecutionOutcome:
    """Execute a callable that needs the complete policy-effective invocation."""

    invocation = session.bind_invocation(invocation)
    if capability_token is not None and capability_token_provider is not None:
        raise ValueError("provide a capability token or token provider, not both")
    if capability_token_provider is not None:
        supplied = capability_token_provider(invocation)
        capability_token = await supplied if inspect.isawaitable(supplied) else supplied
        if not isinstance(capability_token, str):
            raise TypeError("capability token providers must return a string")

    effective_invocation = invocation
    if capability_token is not None:
        effective_invocation = ToolInvocation(
            tool_name=invocation.tool_name,
            arguments=invocation.arguments,
            call_id=invocation.call_id,
            tool_version=invocation.tool_version,
            resource=invocation.resource,
            capability_token=(
                capability_token
                if capability_token is not None
                else invocation.capability_token
            ),
            intent_digest=invocation.intent_digest,
            enforcement_receipt=invocation.enforcement_receipt,
        )
    return await session.around_tool(
        effective_invocation,
        executor,
        adapter=adapter_name,
        enforced_obligations=enforced_obligations,
    )


def wrap_tool(
    session: SecuritySession,
    tool_name: str,
    executor: Callable[..., Any],
    *,
    tool_version: str | None = None,
    adapter_name: str = "generic-python",
    enforced_obligations: frozenset[ObligationKind] = frozenset(),
    capability_token: str | None = None,
    capability_token_provider: CapabilityTokenProvider | None = None,
) -> Callable[..., Any]:
    """Wrap a sync or async keyword-argument callable as an async safe tool."""

    @wraps(executor)
    async def wrapped(**arguments: Any) -> Any:
        outcome = await execute_tool(
            session,
            ToolInvocation(tool_name, arguments, tool_version=tool_version),
            executor,
            adapter_name=adapter_name,
            enforced_obligations=enforced_obligations,
            capability_token=capability_token,
            capability_token_provider=capability_token_provider,
        )
        if outcome.blocked:
            raise ToolExecutionDenied(outcome.decision)
        if outcome.error is not None:
            raise ToolExecutionFailed(outcome)
        return outcome.result

    return wrapped
