"""
ReAct harness — Thought / Action / Observation reasoning loop.
"""

from __future__ import annotations

from typing import Any

from src.harness.base import BaseHarness, HarnessResult
from src.tools.simulated_tools import SimulatedEnvironment
from src.llm_client import call_model


class ReactHarness(BaseHarness):

    harness_type = "react"

    def execute(self, task, env, security_pipeline=None):
        max_steps = self.config.get("react_max_steps", 5)
        system_prompt = (
            self._build_system_prompt(task) + "\n\n"
            "Use the ReAct reasoning pattern:\n"
            "Thought: <your reasoning>\n"
            "Action: <tool-call JSON or 'FINISH'>\n"
            "After receiving an Observation, continue until done.\n"
            "When finished, write: Action: FINISH\nFinal Answer: <answer>"
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": task["instruction"]},
        ]
        trace: list[dict] = []
        tool_calls, blocked = [], []

        for step in range(max_steps):
            response = call_model(self.model_name, messages) or ""
            trace.append({"role": "assistant", "content": response})

            if "FINISH" in response.upper() or "Final Answer" in response:
                break

            parsed = self._parse_tool_call(response)
            if parsed is None:
                break

            tc = self._try_tool_call(parsed, env, security_pipeline)
            if tc.blocked:
                blocked.append(tc)
                observation = f"[BLOCKED] {tc.block_reason}"
            else:
                tool_calls.append(tc)
                observation = tc.result

            messages.append({"role": "assistant", "content": response})
            messages.append({"role": "user",
                             "content": f"Observation: {observation}"})
            trace.append({"role": "observation", "content": observation})

        final = trace[-1]["content"] if trace else ""

        return HarnessResult(
            task_id=task["id"],
            harness_type=self.harness_type,
            security_mode=self.config.get("security_mode", "unprotected"),
            final_response=final,
            tool_calls=tool_calls,
            blocked_actions=blocked,
            reasoning_trace=trace,
        )
