"""
Direct API harness — single LLM call, no tool loop.
Serves as the "no-harness" baseline.
"""

from __future__ import annotations

from typing import Any

from src.harness.base import BaseHarness, HarnessResult
from src.tools.simulated_tools import SimulatedEnvironment
from src.llm_client import call_model


class DirectHarness(BaseHarness):

    harness_type = "direct"

    def execute(self, task, env, security_pipeline=None):
        system_prompt = self._build_system_prompt(task)
        messages = self._build_initial_messages(task, system_prompt, security_pipeline)

        response = call_model(self.model_name, messages) or ""

        parsed = self._parse_tool_call(response)
        tool_calls = []
        blocked = []
        if parsed:
            tc = self._try_tool_call(parsed, env, security_pipeline, task)
            if tc.blocked:
                blocked.append(tc)
            else:
                tool_calls.append(tc)
                if security_pipeline and hasattr(security_pipeline, "filter_context"):
                    security_pipeline.filter_context(
                        tc.result, source="tool_output")

        return HarnessResult(
            task_id=task["id"],
            harness_type=self.harness_type,
            security_mode=self.config.get("security_mode", "unprotected"),
            final_response=response,
            tool_calls=tool_calls,
            blocked_actions=blocked,
            reasoning_trace=[{"role": "assistant", "content": response}],
        )
