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
        user_msg = task["instruction"]
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_msg},
        ]

        response = call_model(self.model_name, messages) or ""

        parsed = self._parse_tool_call(response)
        tool_calls = []
        blocked = []
        if parsed:
            tc = self._try_tool_call(parsed, env, security_pipeline)
            if tc.blocked:
                blocked.append(tc)
            else:
                tool_calls.append(tc)

        return HarnessResult(
            task_id=task["id"],
            harness_type=self.harness_type,
            security_mode=self.config.get("security_mode", "unprotected"),
            final_response=response,
            tool_calls=tool_calls,
            blocked_actions=blocked,
            reasoning_trace=[{"role": "assistant", "content": response}],
        )
