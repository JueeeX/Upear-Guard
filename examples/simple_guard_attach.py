"""Small production-mode Guard.attach example with real LangGraph boundaries."""

from __future__ import annotations

import asyncio
import json

from langchain_core.messages import AIMessage, HumanMessage

from safeharness import Guard, LangGraphAgent, LangGraphTool, SafeHarnessRuntime


class LocalModel:
    """Deterministic model used only to keep this example offline."""

    def bind_tools(self, _schemas):
        return self

    async def ainvoke(self, messages):
        return AIMessage(content=f"Accepted {len(messages)} guarded message(s).")


def lookup_alarm(alarm_id: str) -> dict[str, str]:
    """Look up one alarm in the example backend."""

    return {"alarm_id": alarm_id, "status": "active"}


async def main() -> None:
    runtime = SafeHarnessRuntime()
    tool = LangGraphTool.from_callable(
        lookup_alarm,
        required_capabilities={"alarm:read"},
        resource_parameter="alarm_id",
    )
    async with Guard(
        tenant_id="example", agent_id="assistant", runtime=runtime
    ) as guard:
        agent = guard.attach(LangGraphAgent(model=LocalModel(), tools=(tool,)))
        result = await agent.ainvoke(
            {"messages": [HumanMessage(content="Inspect alarm ALM-1001.")]}
        )
        print(result["final_response"])
        print(json.dumps(guard.report.to_dict(), sort_keys=True))


if __name__ == "__main__":
    asyncio.run(main())
