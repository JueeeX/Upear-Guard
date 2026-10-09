"""Protect a plain Python tool without depending on an agent framework."""

from __future__ import annotations

import asyncio

from safeharness import (
    Reversibility,
    SafeHarnessRuntime,
    SessionContext,
    ToolDescriptor,
)
from safeharness.adapters import wrap_tool
from safeharness.backends import SignedCapabilityGateway, StaticToolCatalog
from safeharness.runtime import RuntimeServices


async def main() -> None:
    catalog = StaticToolCatalog(
        [
            ToolDescriptor(
                name="weather_lookup",
                description="Look up a city forecast.",
                input_schema={
                    "type": "object",
                    "properties": {"city": {"type": "string"}},
                    "required": ["city"],
                    "additionalProperties": False,
                },
                required_capabilities=frozenset({"weather:read"}),
                reversibility=Reversibility.READ_ONLY,
            )
        ]
    )
    authority = SignedCapabilityGateway(
        # Store this key only in the external gateway in a real deployment.
        b"example-gateway-signing-key-must-be-at-least-32-bytes",
        {"example-agent": {"weather:read"}},
    )
    runtime = SafeHarnessRuntime(
        services=RuntimeServices(
            tool_catalog=catalog,
            capability_authority=authority,
        )
    )

    session_context = SessionContext(
        tenant_id="example-tenant",
        agent_id="example-agent",
        framework="plain-python",
    )
    async with runtime.session(session_context) as session:
        descriptor = await catalog.resolve("weather_lookup")
        assert descriptor is not None

        async def issue_token(invocation):
            grant = await authority.issue(session_context, descriptor, invocation)
            return grant.token

        weather_lookup = wrap_tool(
            session,
            "weather_lookup",
            lambda city: {"city": city, "forecast": "sunny"},
            capability_token_provider=issue_token,
        )
        print(await weather_lookup(city="Shanghai"))


if __name__ == "__main__":
    asyncio.run(main())
