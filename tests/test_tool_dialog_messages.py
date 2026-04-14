"""
Regression: dialog transcripts with OpenAI-native assistant.tool_calls + tool
must be forwarded intact so Chat Completions accepts the request.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Project root on path (avoid importing llm_api / anthropic in collection)
_PROJECT = Path(__file__).resolve().parents[1]
if str(_PROJECT) not in sys.path:
    sys.path.insert(0, str(_PROJECT))

from src.harness.base import BaseHarness  # noqa: E402
from src.tools.registry import build_default_registry  # noqa: E402


class _HarnessForMessages(BaseHarness):
    """Minimal concrete harness to call ``_build_initial_messages``."""

    harness_type = "test"

    def execute(self, task, env, security_pipeline=None):
        raise NotImplementedError

_DATA = _PROJECT / "data" / "agent_safety_bench" / "released_data_first200.json"


def _task_by_id(task_id: int) -> dict:
    with open(_DATA, encoding="utf-8") as f:
        data = json.load(f)
    for t in data:
        if t.get("id") == task_id:
            return t
    pytest.skip(f"task id {task_id} not in {_DATA}")


def _assert_valid_tool_chain(msgs: list[dict]) -> None:
    """Each tool message must follow an assistant that declares tool_calls."""
    prev_tool_calls: list | None = None
    for m in msgs:
        role = m.get("role")
        if role == "assistant" and m.get("tool_calls"):
            prev_tool_calls = m["tool_calls"]
        elif role == "tool":
            assert prev_tool_calls, "tool without preceding assistant.tool_calls"
            tcid = m.get("tool_call_id")
            assert tcid and any(
                tc.get("id") == tcid for tc in prev_tool_calls
            ), f"tool_call_id {tcid!r} not in previous tool_calls"
            prev_tool_calls = None
        elif role == "assistant" and not m.get("tool_calls"):
            prev_tool_calls = None


@pytest.mark.parametrize("task_id", [23, 165, 182])
def test_build_initial_messages_preserves_tool_transcript(task_id: int) -> None:
    task = _task_by_id(task_id)
    dialog = task.get("dialog") or []
    if not any(m.get("role") == "tool" for m in dialog):
        pytest.skip("fixture task has no tool turns")

    h = _HarnessForMessages("gpt5.4", build_default_registry(), {})
    msgs = h._build_initial_messages(task, "SYS", None)

    _assert_valid_tool_chain(msgs)

    # After system: user / assistant+tool_calls / tool / … then final user instruction
    assert msgs[0]["role"] == "system"
    assert msgs[-1]["role"] == "user"
    assert task["instruction"] in msgs[-1]["content"] or msgs[-1]["content"] == task["instruction"]

    roles = [m.get("role") for m in msgs]
    assert "tool" in roles
    # assistant with tool_calls present in payload
    assert any(m.get("role") == "assistant" and m.get("tool_calls") for m in msgs)


def test_fake_history_still_plain_user_assistant() -> None:
    task = _task_by_id(18)
    task = {
        **task,
        "_fake_history": [
            {"role": "user", "content": "u1"},
            {"role": "assistant", "content": "a1"},
        ],
    }
    h = _HarnessForMessages("gpt5.4", build_default_registry(), {})
    msgs = h._build_initial_messages(task, "SYS", None)
    assert msgs[1]["role"] == "user" and msgs[1]["content"] == "u1"
    assert msgs[2]["role"] == "assistant" and msgs[2]["content"] == "a1"
