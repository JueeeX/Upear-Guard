"""Compatibility wrapper around the repository's dotenv-configured LLM client."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any


_CODE_ROOT = str(Path(__file__).resolve().parents[1])
if _CODE_ROOT not in sys.path:
    sys.path.insert(0, _CODE_ROOT)

import llm_api  # noqa: E402


def available_models() -> list[str]:
    """Return supported aliases, including ``env`` and ``judge``."""

    return list(llm_api.MODEL_FUNC_MAP)


def call_model(model_name: str, messages: list[dict[str, Any]]) -> str | None:
    """Call a model alias or raw OpenAI-compatible model ID."""

    return llm_api.call_by_name(model_name, messages)


def call_judge(
    messages: list[dict[str, Any]],
    judge_model: str | None = None,
    temperature: float | None = None,
) -> str | None:
    """Call a separately configured judge model when one is provided."""

    params = {"temperature": temperature} if temperature is not None else None
    return llm_api.call_by_name(
        judge_model or "judge",
        messages,
        params=params,
        role="judge",
    )
